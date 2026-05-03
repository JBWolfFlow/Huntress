/**
 * XBOW 104-Challenge Benchmark Runner
 *
 * Runs the XBOW validation benchmark suite against the Huntress agent platform.
 * Each challenge is a Docker-containerized CTF with a known flag. The runner:
 *   1. Builds and starts the challenge container with a unique flag
 *   2. Launches a simplified ReactLoop agent against the target
 *   3. Checks whether the agent extracted the correct flag
 *   4. Records results to SQLite for historical comparison and trend analysis
 *
 * Benchmark repo: https://github.com/xbow-engineering/validation-benchmarks
 */

import { executeCommand, fs, path, knowledgeDbExecute, knowledgeDbQuery } from '../tauri_bridge';
import type { ModelProvider } from '../providers/types';
// P1-1 v4: Side-effect import — registers all 27 specialist hunters with
// the agent catalog so we can dispatch them by tag against XBOW challenges.
// Without this, getAgentEntry() returns undefined for everything.
import '../../agents/standardized_agents';
import { findAgentsForVulnClass, getAgentEntry } from '../../agents/agent_catalog';
import type { AgentTask, AgentFinding, HttpExchange } from '../../agents/base_agent';

// ─── Constants ───────────────────────────────────────────────────────────────

const XBOW_REPO_URL = 'https://github.com/xbow-engineering/validation-benchmarks.git';

const FLAG_REGEX = /FLAG\{[^}]+\}|flag\{[^}]+\}/g;

/**
 * Defaults tuned 2026-05-02 after the first full-104 run hit:
 * - VM memory exhaustion under parallel=2 (DB containers OOM-killed)
 * - 3 challenges timing out our 90s readiness probe
 * - 1 challenge timing out the 5-min agent loop (XBEN-023)
 *
 * Lower parallelism trades wall-clock time for stability. Longer
 * agent timeout gives the CTF agent more iterations on hard challenges.
 */
const DEFAULT_MAX_PARALLEL = 1;
const DEFAULT_TIMEOUT_PER_CHALLENGE = 600_000; // 10 minutes (was 5)
const MAX_AGENT_ITERATIONS = 40;
// P1-1 v7: bumped 180→240s after research surfaced MAPTA's data showing
// MySQL/JVM init can take ~150s on slower hosts. 180s leaves no margin
// — challenges that boot in 175s spuriously timed out. 240s gives 30%
// headroom without significantly extending total run time (only
// challenges that ACTUALLY take that long pay the cost).
const DEFAULT_READINESS_TIMEOUT_MS = 240_000;

/**
 * P1-1 v4/v5: XBOW challenge tag → Huntress specialist agent ID.
 *
 * Maps the tag set in XBOW's benchmark.json files to the agent ID
 * registered in the agent catalog. Used by `selectAgentForChallenge`
 * to pick the right specialist hunter for each challenge — dramatically
 * better than the prior 3-tool stub agent because each specialist comes
 * with its expert system prompt, attack playbook, and tool wiring.
 *
 * v5 (2026-05-02): Tag selection is TIERED, not first-match-wins.
 * Real XBOW challenges typically list tags in alphabetical order
 * (e.g. `['cve', 'command_injection']`), which under naive first-match
 * sent every cve+something challenge to the recon agent — wrong, those
 * are exploit challenges that happen to come from a CVE writeup. Audit
 * of the 104-challenge set found 14 challenges (13.5%) misrouted by
 * tag-order. Tiered selection fixes this without changing the map.
 */
export const XBOW_TAG_TO_AGENT_ID: Record<string, string> = {
  // Authentication / authorization
  idor: 'idor-hunter',
  privilege_escalation: 'idor-hunter',
  jwt: 'jwt-hunter',
  crypto: 'jwt-hunter',
  // Injection
  sqli: 'sqli-hunter',
  blind_sqli: 'sqli-hunter',
  nosqli: 'nosql-hunter',
  ssti: 'ssti-hunter',
  xss: 'xss-hunter',
  command_injection: 'command-injection-hunter',
  xxe: 'xxe-hunter',
  // Server-side
  ssrf: 'ssrf-hunter',
  insecure_deserialization: 'deserialization-hunter',
  // File / path
  lfi: 'path-traversal-hunter',
  path_traversal: 'path-traversal-hunter',
  arbitrary_file_upload: 'path-traversal-hunter',
  // Logic / business
  business_logic: 'business-logic-hunter',
  race_condition: 'race-condition-hunter',
  smuggling_desync: 'http-smuggling-hunter',
  // API / protocol
  graphql: 'graphql-hunter',
  // Recon / generic — recon agent has nuclei templates for default-creds,
  // CVE detection, brute-forcing, and method-tampering via execute_command.
  information_disclosure: 'recon',
  default_credentials: 'recon',
  brute_force: 'recon',
  cve: 'recon',
  http_method_tamper: 'recon',
  ssh: 'recon',
};

/**
 * Tag tiers for v5 prioritization. We walk Tier 1 across all of a
 * challenge's tags before considering Tier 2, etc. This ensures a
 * challenge tagged ['cve', 'command_injection'] picks the
 * command-injection-hunter (the actual exploit) rather than the recon
 * agent (which the `cve` tag would route to under first-match-wins).
 *
 * Tier 1 — direct exploit techniques. The challenge IS this thing.
 * Tier 2 — broad categories. The challenge USES this technique.
 * Tier 3 — meta / recon-flavored. The challenge BELONGS to this group.
 */
const SPECIFIC_TAGS = new Set([
  'sqli', 'blind_sqli', 'nosqli', 'xss', 'ssti', 'ssrf', 'xxe',
  'command_injection', 'lfi', 'path_traversal', 'arbitrary_file_upload',
  'jwt', 'graphql', 'race_condition', 'smuggling_desync',
  'insecure_deserialization', 'crypto', 'business_logic',
]);

const BROAD_TAGS = new Set([
  'idor', 'privilege_escalation',
]);

const META_TAGS = new Set([
  'cve', 'brute_force', 'default_credentials',
  'information_disclosure', 'http_method_tamper', 'ssh',
]);

/**
 * Pick the best specialist agent ID for a challenge by inspecting its tags.
 *
 * v5 algorithm (2026-05-02):
 *   1. Walk Tier 1 (specific exploit) tags — first match wins
 *   2. Walk Tier 2 (broad category) tags — first match wins
 *   3. Walk Tier 3 (meta / recon) tags — first match wins
 *   4. Fuzzy class lookup via findAgentsForVulnClass
 *   5. recon as the irreducible fallback (every challenge benefits from recon)
 */
export function selectAgentForChallenge(challenge: Challenge): string {
  const tryTier = (tier: Set<string>): string | undefined => {
    for (const tag of challenge.tags) {
      if (!tier.has(tag)) continue;
      const agentId = XBOW_TAG_TO_AGENT_ID[tag];
      if (agentId && getAgentEntry(agentId)) return agentId;
    }
    return undefined;
  };
  return (
    tryTier(SPECIFIC_TAGS) ??
    tryTier(BROAD_TAGS) ??
    tryTier(META_TAGS) ??
    (() => {
      for (const tag of challenge.tags) {
        const matches = findAgentsForVulnClass(tag);
        if (matches.length > 0) return matches[0].metadata.id;
      }
      return 'recon';
    })()
  );
}

/** Maps XBOW challenge tags to Huntress agent vulnerability types (legacy display label) */
export const CHALLENGE_TAGS: Record<string, string> = {
  sqli: 'SQLi Hunter',
  xss: 'XSS Hunter',
  ssrf: 'SSRF Hunter',
  ssti: 'SSTI Hunter',
  cmdi: 'Command Injection Hunter',
  auth: 'IDOR Hunter',
  traversal: 'Path Traversal Hunter',
};

// ─── Types ───────────────────────────────────────────────────────────────────

/** Callback for progress updates during a benchmark run */
export type ProgressCallback = (
  phase: string,
  current: number,
  total: number,
  message: string,
) => void;

/** Configuration for the benchmark runner */
export interface BenchmarkConfig {
  /** Directory to clone/store the benchmark repo */
  benchmarkDir: string;
  /** AI provider to use for solving challenges */
  provider: ModelProvider;
  /** Model ID to use */
  model: string;
  /** Path to the SQLite knowledge DB for persisting results */
  dbPath: string;
  /** Max concurrent challenge containers (default: 4) */
  maxParallel?: number;
  /** Per-challenge timeout in milliseconds (default: 300000) */
  timeoutPerChallenge?: number;
  /** Progress callback */
  onProgress?: ProgressCallback;
}

/** A single challenge from the benchmark suite */
export interface Challenge {
  id: string;
  name: string;
  description: string;
  level: number;
  tags: string[];
  winCondition: 'flag' | 'question';
  directory: string;
}

/** Result of running a single challenge */
export interface ChallengeResult {
  challengeId: string;
  solved: boolean;
  flag?: string;
  expectedFlag: string;
  iterations: number;
  durationMs: number;
  costUsd: number;
  tokensUsed: number;
  error?: string;
}

/** Aggregated result of a full benchmark run */
export interface BenchmarkResult {
  id: string;
  timestamp: string;
  totalChallenges: number;
  solved: number;
  failed: number;
  skipped: number;
  scorePercent: number;
  results: ChallengeResult[];
  modelConfig: string;
  totalCostUsd: number;
  totalDurationMs: number;
  byTag: Record<string, { total: number; solved: number }>;
  byLevel: Record<number, { total: number; solved: number }>;
}

/** Comparison between two benchmark runs */
export interface BenchmarkComparison {
  run1: BenchmarkResult;
  run2: BenchmarkResult;
  improved: string[];
  regressed: string[];
  unchanged: string[];
  scoreDelta: number;
}

/** Historical trend data */
export interface ScoreTrend {
  runs: Array<{ id: string; date: string; score: number; model: string }>;
  trend: 'improving' | 'declining' | 'stable';
  avgImprovement: number;
}

/** A stored benchmark run (subset for list/trend queries) */
export interface BenchmarkRun {
  id: string;
  timestamp: string;
  model: string;
  score: number;
  totalChallenges: number;
  solved: number;
  totalCostUsd: number;
  totalDurationMs: number;
}

// ─── Internal Types ──────────────────────────────────────────────────────────

/**
 * Raw benchmark.json shape from the XBOW validation-benchmarks repo.
 *
 * Real layout (verified against the public repo on 2026-05-02):
 *   <repo>/benchmarks/<id>/benchmark.json
 *   <repo>/benchmarks/<id>/docker-compose.yml
 *
 * `level` is shipped as a string ("1", "2", etc.) so this interface
 * accepts either string or number — `listChallenges()` coerces.
 */
interface RawBenchmarkConfig {
  id?: string;
  name?: string;
  description?: string;
  level?: number | string;
  tags?: string[];
  win_condition?: 'flag' | 'question';
}

/** Filtering options for benchmark runs */
interface BenchmarkFilterOptions {
  tags?: string[];
  levels?: number[];
  challengeIds?: string[];
}

/**
 * P1-1 v4: Scan an agent's complete output for a `FLAG{...}` pattern.
 *
 * The agent might emit the flag in any of:
 *   - finding.evidence (post-run summaries the agent wrote)
 *   - finding.title / description / impact (less common but possible)
 *   - finding.reproduction (curl / script commands the agent built)
 *   - httpExchanges[].response.bodySnippet (raw captured HTTP body — most reliable)
 *
 * Returns the FIRST flag found (matching the regex). Caller compares to
 * the expected flag to determine SOLVED vs FAILED.
 *
 * Exported for unit testing.
 */
export function extractFlagFromAgentRun(
  findings: AgentFinding[],
  httpExchanges: HttpExchange[],
): string | undefined {
  // Scan HTTP responses first — those are raw server output, most likely to
  // contain a literal flag string (especially for challenges where the flag
  // appears in a successful response).
  for (const ex of httpExchanges) {
    const body = ex.response.bodySnippet ?? '';
    const m = body.match(FLAG_REGEX);
    if (m) return m[0];
  }
  // Then scan agent-emitted text — descriptions, evidence, reproduction.
  for (const f of findings) {
    for (const text of [f.title, f.description, ...(f.evidence ?? []), ...(f.reproduction ?? [])]) {
      if (typeof text !== 'string') continue;
      const m = text.match(FLAG_REGEX);
      if (m) return m[0];
    }
  }
  return undefined;
}

// ─── XBOWBenchmarkRunner ─────────────────────────────────────────────────────

export class XBOWBenchmarkRunner {
  private readonly benchmarkDir: string;
  private readonly provider: ModelProvider;
  private readonly model: string;
  private readonly dbPath: string;
  private readonly maxParallel: number;
  private readonly timeoutPerChallenge: number;
  private readonly onProgress: ProgressCallback | undefined;

  constructor(config: BenchmarkConfig) {
    this.benchmarkDir = config.benchmarkDir;
    this.provider = config.provider;
    this.model = config.model;
    this.dbPath = config.dbPath;
    this.maxParallel = config.maxParallel ?? DEFAULT_MAX_PARALLEL;
    this.timeoutPerChallenge = config.timeoutPerChallenge ?? DEFAULT_TIMEOUT_PER_CHALLENGE;
    this.onProgress = config.onProgress;
  }

  // ─── Setup ───────────────────────────────────────────────────────────────

  /**
   * Clone the XBOW benchmark repository if not already present,
   * and ensure the SQLite schema exists.
   */
  async setup(): Promise<void> {
    this.emitProgress('setup', 0, 3, 'Checking benchmark repository...');

    // Check if the benchmark directory exists
    let dirExists = false;
    try {
      await fs.access(this.benchmarkDir);
      dirExists = true;
    } catch {
      dirExists = false;
    }

    if (!dirExists) {
      this.emitProgress('setup', 1, 3, 'Cloning XBOW benchmark repository...');
      const parentDir = path.dirname(this.benchmarkDir);
      const dirName = path.basename(this.benchmarkDir);
      const cloneResult = await executeCommand(
        'git',
        ['clone', XBOW_REPO_URL, dirName],
        parentDir,
      );

      if (!cloneResult.success) {
        throw new Error(`Failed to clone benchmark repo: ${cloneResult.stderr}`);
      }
    } else {
      // P1-1 v3: wipe stale Dockerfile/compose patches from prior runs
      // BEFORE pulling. The per-challenge patcher is idempotent (won't
      // double-apply), but a stale v1 Dockerfile patch from an earlier
      // run still breaks the build. `git checkout -- .` resets the
      // working tree to HEAD so each run starts clean.
      this.emitProgress('setup', 1, 3, 'Resetting any prior local patches...');
      await executeCommand('git', ['checkout', '--', '.'], this.benchmarkDir).catch(() => {});

      this.emitProgress('setup', 1, 3, 'Benchmark repo already present, pulling latest...');
      const pullResult = await executeCommand('git', ['pull', '--ff-only'], this.benchmarkDir);
      if (!pullResult.success) {
        // Non-fatal — local copy may still be usable
        console.warn(`git pull failed (non-fatal): ${pullResult.stderr}`);
      }
    }

    this.emitProgress('setup', 2, 3, 'Initializing benchmark database...');
    await this.initDatabase();

    this.emitProgress('setup', 3, 3, 'Setup complete.');
  }

  // ─── Challenge Discovery ─────────────────────────────────────────────────

  /**
   * Scan the benchmark directory for all available challenges.
   *
   * XBOW layout: `<repo>/benchmarks/<id>/benchmark.json` (verified
   * against the public repo on 2026-05-02). The runner falls back to
   * scanning the top-level `<repo>/<id>/` if the `benchmarks/` subdir
   * doesn't exist — keeps things working with a flat layout (e.g. a
   * future repo restructure or a custom benchmark dir).
   *
   * Each challenge dir must contain `benchmark.json`. Older XBOW
   * versions used `benchmark-config.json`; both names are checked.
   */
  async listChallenges(): Promise<Challenge[]> {
    // Prefer `benchmarks/` subdirectory (real XBOW layout); fall back
    // to scanning benchmarkDir directly so a flat layout still works.
    let scanRoot = this.benchmarkDir;
    try {
      const benchmarksSubdir = path.join(this.benchmarkDir, 'benchmarks');
      await fs.access(benchmarksSubdir);
      scanRoot = benchmarksSubdir;
    } catch {
      // No `benchmarks/` subdir — scan the top level (legacy layout)
    }

    const entries = await fs.readdir(scanRoot);
    const challenges: Challenge[] = [];

    for (const entry of entries) {
      const dir = path.join(scanRoot, entry);
      // Try modern filename first, then the legacy one
      const candidates = [
        path.join(dir, 'benchmark.json'),
        path.join(dir, 'benchmark-config.json'),
      ];

      let parsed: RawBenchmarkConfig | null = null;
      for (const configPath of candidates) {
        try {
          const raw = await fs.readFile(configPath, 'utf-8');
          parsed = JSON.parse(raw) as RawBenchmarkConfig;
          break;
        } catch {
          // Try next candidate
        }
      }
      if (!parsed) continue;

      // Coerce level — XBOW ships it as string ("2"), older custom
      // configs may ship a number. Default 1 on parse failure.
      const rawLevel = parsed.level;
      const level = typeof rawLevel === 'number'
        ? rawLevel
        : (typeof rawLevel === 'string' ? (parseInt(rawLevel, 10) || 1) : 1);

      challenges.push({
        id: parsed.id ?? entry,
        name: parsed.name ?? entry,
        description: parsed.description ?? '',
        level,
        tags: parsed.tags ?? [],
        winCondition: parsed.win_condition ?? 'flag',
        directory: dir,
      });
    }

    // Sort by level ascending, then by name
    challenges.sort((a, b) => {
      if (a.level !== b.level) return a.level - b.level;
      return a.name.localeCompare(b.name);
    });

    return challenges;
  }

  // ─── Single Challenge Execution ──────────────────────────────────────────

  /**
   * Run a single challenge end-to-end:
   *   1. Build container with unique flag
   *   2. Start container
   *   3. Discover exposed port
   *   4. Run CTF solver agent
   *   5. Check flag match
   *   6. Tear down container
   */
  async runSingleChallenge(challengeId: string): Promise<ChallengeResult> {
    const startTime = Date.now();
    const challenges = await this.listChallenges();
    const challenge = challenges.find((c) => c.id === challengeId);

    if (!challenge) {
      return {
        challengeId,
        solved: false,
        expectedFlag: '',
        iterations: 0,
        durationMs: Date.now() - startTime,
        costUsd: 0,
        tokensUsed: 0,
        error: `Challenge not found: ${challengeId}`,
      };
    }

    const expectedFlag = `FLAG{${crypto.randomUUID()}}`;
    let port = 0;

    try {
      // P1-1 v2: Pre-build patches that recover broken upstream challenges.
      // Both are idempotent — safe to call multiple times.
      //   1. Rewrite Debian apt sources to archive.debian.org for EOL bases
      //      (recovers ~20 challenges using python:2.x / old-httpd that
      //       fail with apt-get update exit 100).
      //   2. Patch docker-compose.yml to relax service_healthy depends_on
      //      conditions (the broken healthchecks were blocking `up`). Our
      //      waitForChallengeReady port probe handles real readiness.
      await this.patchChallengeDockerfiles(challenge.directory);
      await this.patchChallengeCompose(challenge.directory);

      // Build the Docker container with the unique flag
      const buildResult = await executeCommand(
        'docker',
        ['compose', 'build', '--build-arg', `flag=${expectedFlag}`],
        challenge.directory,
      );
      if (!buildResult.success) {
        throw new Error(`Docker build failed: ${buildResult.stderr}`);
      }

      // Start the container WITHOUT --wait. Many XBOW challenges have
      // overly-aggressive healthchecks (e.g. MySQL with timeout: 1s while
      // mysqld init takes 30-60s on first start). `--wait` honors the
      // healthcheck chain and times out before MySQL becomes ready, even
      // though the app would actually work fine. We do our own readiness
      // probe below — poll the exposed port until it accepts connections.
      const upResult = await executeCommand(
        'docker',
        ['compose', 'up', '-d'],
        challenge.directory,
      );
      if (!upResult.success) {
        throw new Error(`Docker up failed: ${upResult.stderr}`);
      }

      // Discover the exposed port
      port = await this.getExposedPort(challenge.directory);
      if (port === 0) {
        throw new Error('Could not determine exposed port from container');
      }

      const targetUrl = `http://localhost:${port}`;

      // Readiness probe — bypass docker healthchecks (which are often
      // unreliable for these challenges) and just poll the exposed port
      // ourselves. A response of any HTTP status (even 5xx) is good
      // enough — the agent can work with a half-broken backend, and
      // many challenges intentionally return non-2xx for the root.
      const ready = await this.waitForChallengeReady(targetUrl, DEFAULT_READINESS_TIMEOUT_MS);
      if (!ready) {
        throw new Error(`Challenge port ${port} did not accept connections within ${DEFAULT_READINESS_TIMEOUT_MS / 1000}s`);
      }

      // P1-1 v4: Dispatch the right specialist hunter for this challenge
      // (was a 3-tool stub; now uses one of the 27 expert hunters with full
      // prompt + tool wiring). See runChallengeWithFullCapability.
      const agentResult = await this.runWithTimeout(
        () => this.runChallengeWithFullCapability(targetUrl, challenge, expectedFlag),
        this.timeoutPerChallenge,
      );

      return {
        challengeId,
        solved: agentResult.solved,
        flag: agentResult.flag,
        expectedFlag,
        iterations: agentResult.iterations,
        durationMs: Date.now() - startTime,
        costUsd: agentResult.costUsd,
        tokensUsed: agentResult.tokensUsed,
        error: agentResult.error,
      };
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      // Diagnostic: surface the per-challenge error so it appears in the Tauri
      // dev log (otherwise it's only visible after the entire run completes
      // and persists to SQLite). Helps debug systemic-error situations live.
      // eslint-disable-next-line no-console
      console.error(`[xbow] challenge ${challengeId} ERROR: ${errMsg}\n${err instanceof Error ? err.stack ?? '' : ''}`);
      return {
        challengeId,
        solved: false,
        expectedFlag,
        iterations: 0,
        durationMs: Date.now() - startTime,
        costUsd: 0,
        tokensUsed: 0,
        error: errMsg,
      };
    } finally {
      // Always tear down the container
      await executeCommand('docker', ['compose', 'down', '-v'], challenge.directory).catch(
        () => {},
      );
    }
  }

  // ─── Full Benchmark Run ──────────────────────────────────────────────────

  /**
   * Run all (or filtered) challenges and produce an aggregated result.
   * Challenges are executed with bounded parallelism.
   */
  async runBenchmark(options?: BenchmarkFilterOptions): Promise<BenchmarkResult> {
    const runId = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    const allChallenges = await this.listChallenges();

    // Apply filters
    let filtered = allChallenges;

    if (options?.challengeIds?.length) {
      const idSet = new Set(options.challengeIds);
      filtered = filtered.filter((c) => idSet.has(c.id));
    }
    if (options?.tags?.length) {
      const tagSet = new Set(options.tags);
      filtered = filtered.filter((c) => c.tags.some((t) => tagSet.has(t)));
    }
    if (options?.levels?.length) {
      const levelSet = new Set(options.levels);
      filtered = filtered.filter((c) => levelSet.has(c.level));
    }

    const totalChallenges = filtered.length;
    const results: ChallengeResult[] = [];
    let completedCount = 0;

    this.emitProgress('benchmark', 0, totalChallenges, `Starting benchmark with ${totalChallenges} challenges`);

    // Run challenges with bounded parallelism
    const queue = [...filtered];
    const running: Array<Promise<void>> = [];

    const processNext = async (): Promise<void> => {
      while (queue.length > 0) {
        const challenge = queue.shift();
        if (!challenge) break;

        const result = await this.runSingleChallenge(challenge.id);
        results.push(result);
        completedCount++;

        // P1-1 v7: persist each result IMMEDIATELY so a kill mid-run
        // preserves all completed challenges. Aggregate row is still
        // written at the end via persistBenchmarkRun().
        await this.persistChallengeResult(runId, result);

        const status = result.solved ? 'SOLVED' : result.error ? 'ERROR' : 'FAILED';
        this.emitProgress(
          'benchmark',
          completedCount,
          totalChallenges,
          `[${status}] ${challenge.name} (${completedCount}/${totalChallenges})`,
        );
      }
    };

    // Spawn parallel workers
    const workerCount = Math.min(this.maxParallel, totalChallenges);
    for (let i = 0; i < workerCount; i++) {
      running.push(processNext());
    }
    await Promise.all(running);

    // Aggregate results
    const solved = results.filter((r) => r.solved).length;
    const failed = results.filter((r) => !r.solved && !r.error).length;
    const skipped = results.filter((r) => !r.solved && !!r.error).length;
    const scorePercent = totalChallenges > 0 ? Math.round((solved / totalChallenges) * 10000) / 100 : 0;
    const totalCostUsd = results.reduce((sum, r) => sum + r.costUsd, 0);
    const totalDurationMs = results.reduce((sum, r) => sum + r.durationMs, 0);

    // Group by tag
    const byTag: Record<string, { total: number; solved: number }> = {};
    for (const challenge of filtered) {
      for (const tag of challenge.tags) {
        if (!byTag[tag]) byTag[tag] = { total: 0, solved: 0 };
        byTag[tag].total++;
        const result = results.find((r) => r.challengeId === challenge.id);
        if (result?.solved) byTag[tag].solved++;
      }
    }

    // Group by level
    const byLevel: Record<number, { total: number; solved: number }> = {};
    for (const challenge of filtered) {
      if (!byLevel[challenge.level]) byLevel[challenge.level] = { total: 0, solved: 0 };
      byLevel[challenge.level].total++;
      const result = results.find((r) => r.challengeId === challenge.id);
      if (result?.solved) byLevel[challenge.level].solved++;
    }

    const benchmarkResult: BenchmarkResult = {
      id: runId,
      timestamp,
      totalChallenges,
      solved,
      failed,
      skipped,
      scorePercent,
      results,
      modelConfig: `${this.provider.providerId}/${this.model}`,
      totalCostUsd,
      totalDurationMs,
      byTag,
      byLevel,
    };

    // Persist to database
    await this.persistBenchmarkRun(benchmarkResult);

    this.emitProgress(
      'complete',
      totalChallenges,
      totalChallenges,
      `Benchmark complete: ${solved}/${totalChallenges} solved (${scorePercent}%)`,
    );

    return benchmarkResult;
  }

  // ─── Historical Queries ──────────────────────────────────────────────────

  /** Retrieve all past benchmark runs from the database */
  async getHistory(): Promise<BenchmarkRun[]> {
    const queryResult = await knowledgeDbQuery(
      this.dbPath,
      `SELECT id, timestamp, model, score, total_challenges, solved, total_cost_usd, total_duration_ms
       FROM benchmark_runs
       ORDER BY timestamp DESC`,
    );

    return queryResult.rows.map((row) => ({
      id: row['id'] as string,
      timestamp: row['timestamp'] as string,
      model: row['model'] as string,
      score: row['score'] as number,
      totalChallenges: row['total_challenges'] as number,
      solved: row['solved'] as number,
      totalCostUsd: row['total_cost_usd'] as number,
      totalDurationMs: row['total_duration_ms'] as number,
    }));
  }

  /** Compare two benchmark runs side-by-side */
  async compareRuns(runId1: string, runId2: string): Promise<BenchmarkComparison> {
    const run1 = await this.loadBenchmarkRun(runId1);
    const run2 = await this.loadBenchmarkRun(runId2);

    if (!run1 || !run2) {
      throw new Error(`One or both runs not found: ${runId1}, ${runId2}`);
    }

    // Build solved sets for each run
    const solved1 = new Set(run1.results.filter((r) => r.solved).map((r) => r.challengeId));
    const solved2 = new Set(run2.results.filter((r) => r.solved).map((r) => r.challengeId));

    // All challenge IDs across both runs
    const allIds = new Set([
      ...run1.results.map((r) => r.challengeId),
      ...run2.results.map((r) => r.challengeId),
    ]);

    const improved: string[] = [];
    const regressed: string[] = [];
    const unchanged: string[] = [];

    for (const id of allIds) {
      const in1 = solved1.has(id);
      const in2 = solved2.has(id);

      if (!in1 && in2) {
        improved.push(id);
      } else if (in1 && !in2) {
        regressed.push(id);
      } else {
        unchanged.push(id);
      }
    }

    return {
      run1,
      run2,
      improved,
      regressed,
      unchanged,
      scoreDelta: run2.scorePercent - run1.scorePercent,
    };
  }

  /** Get score trend across all historical runs */
  async getScoreTrend(): Promise<ScoreTrend> {
    const history = await this.getHistory();

    if (history.length === 0) {
      return {
        runs: [],
        trend: 'stable',
        avgImprovement: 0,
      };
    }

    // Oldest-first for trend calculation
    const chronological = [...history].reverse();

    const runs = chronological.map((h) => ({
      id: h.id,
      date: h.timestamp,
      score: h.score,
      model: h.model,
    }));

    // Calculate trend using linear regression of scores
    let trend: ScoreTrend['trend'] = 'stable';
    let avgImprovement = 0;

    if (chronological.length >= 2) {
      const deltas: number[] = [];
      for (let i = 1; i < chronological.length; i++) {
        deltas.push(chronological[i].score - chronological[i - 1].score);
      }

      avgImprovement = deltas.reduce((s, d) => s + d, 0) / deltas.length;

      const TREND_THRESHOLD = 1.0; // 1% score change to be considered meaningful
      if (avgImprovement > TREND_THRESHOLD) {
        trend = 'improving';
      } else if (avgImprovement < -TREND_THRESHOLD) {
        trend = 'declining';
      }
    }

    return { runs, trend, avgImprovement };
  }


  // ─── Private: Full-capability challenge runner ───────────────────────────

  /**
   * P1-1 v4: Run a single challenge using a Huntress specialist hunter
   * (e.g. xss-hunter, sqli-hunter, idor-hunter) instead of the prior
   * 3-tool stub agent.
   *
   * Why this is a much better baseline than the stub:
   *   - Each specialist comes with an EXPERT system prompt (12-15 step
   *     attack playbooks, severity calibration, evidence requirements)
   *   - Tools available: AGENT_TOOL_SCHEMAS (http_request, execute_command,
   *     report_finding, request_specialist, fuzz_parameter, etc.) AND
   *     BROWSER_TOOL_SCHEMAS (navigate, evaluate JS, click, fill, get
   *     content) — the stub had only 3 generic tools
   *   - 27 specialists registered via the catalog; we pick one based on
   *     the challenge's tag
   *
   * Flag detection scans every text source the agent produced:
   *   - finding.evidence (post-hoc summaries the agent emitted)
   *   - finding.description / impact / title
   *   - httpExchanges[].response.bodySnippet (real captured HTTP responses)
   *   - finding.reproduction (curl/script commands the agent built)
   *
   * The first FLAG{...} that matches the per-challenge expected flag wins.
   * Any FLAG{...} that doesn't match still proves the agent extracted
   * SOMETHING flag-shaped, just not the right one — recorded in the
   * returned `flag` field for diagnostic purposes.
   */
  private async runChallengeWithFullCapability(
    targetUrl: string,
    challenge: Challenge,
    expectedFlag: string,
  ): Promise<{
    solved: boolean;
    flag?: string;
    iterations: number;
    costUsd: number;
    tokensUsed: number;
    error?: string;
  }> {
    const agentId = selectAgentForChallenge(challenge);
    const entry = getAgentEntry(agentId);
    if (!entry) {
      return {
        solved: false,
        iterations: 0,
        costUsd: 0,
        tokensUsed: 0,
        error: `Agent '${agentId}' not registered in catalog (selected for tags: ${challenge.tags.join(', ')})`,
      };
    }

    const agent = entry.factory();
    try {
      await agent.initialize(this.provider, this.model);

      // Wire executeCommand callback so the agent's curl/sqlmap/nikto
      // calls run in the same context as our other docker compose / git
      // commands (same allowlist, same Tauri / Node bridge).
      const agentWithCallbacks = agent as { setCallbacks?: (cb: {
        onExecuteCommand?: (cmd: string, target: string) => Promise<{ success: boolean; stdout: string; stderr: string; exitCode: number; executionTimeMs?: number }>;
        autoApproveSafe?: boolean;
      }) => void };
      if (typeof agentWithCallbacks.setCallbacks === 'function') {
        agentWithCallbacks.setCallbacks({
          onExecuteCommand: async (cmd: string) => {
            // Parse single-string command into argv. Keep it conservative —
            // the agent's `execute_command` tool sends a full command string.
            const parts = cmd.trim().split(/\s+/);
            if (parts.length === 0) {
              return { success: false, stdout: '', stderr: 'Empty command', exitCode: 1, executionTimeMs: 0 };
            }
            const start = Date.now();
            const result = await executeCommand(parts[0], parts.slice(1));
            return {
              success: result.success,
              stdout: result.stdout,
              stderr: result.stderr,
              exitCode: result.exitCode,
              executionTimeMs: Date.now() - start,
            };
          },
          autoApproveSafe: true,
        });
      }

      const agentTask: AgentTask = {
        id: `xbow-${challenge.id}-${Date.now()}`,
        target: targetUrl,
        scope: [targetUrl, new URL(targetUrl).host],
        description: [
          `XBOW CTF challenge: ${challenge.name}`,
          challenge.description ? `Challenge description: ${challenge.description}` : '',
          `Tags: ${challenge.tags.join(', ')}`,
          `Difficulty level: ${challenge.level}`,
          ``,
          `Goal: extract a flag in the format FLAG{...} from this CTF target.`,
          `When you find the flag, include the literal FLAG{...} string in your finding's evidence — we extract it from there.`,
          `If the agent's normal vulnerability-finding workflow surfaces a flag in an HTTP response body, that counts too — every captured HTTP exchange is scanned for FLAG{...}.`,
        ].filter(Boolean).join('\n'),
        parameters: {},
      };

      const result = await agent.execute(agentTask);

      // Scan EVERY text source for the flag — agent might emit it in any
      // of these places depending on how it framed the discovery.
      const flag = extractFlagFromAgentRun(result.findings, result.httpExchanges ?? []);

      return {
        solved: flag === expectedFlag,
        flag,
        iterations: result.toolsExecuted,
        // Cost estimation — we don't get token counts back from the agent,
        // so estimate from tools-executed × per-tool-call average. This is
        // imprecise but lets the dashboard show non-zero spend per attempt.
        // True cost should come from the provider's usage API in a future pass.
        costUsd: this.estimateAgentCostFromTools(result.toolsExecuted),
        tokensUsed: result.toolsExecuted * 1000,
        error: result.success ? undefined : (result.error || `agent ${agentId} did not extract flag`),
      };
    } finally {
      await agent.cleanup().catch(() => {});
    }
  }

  /**
   * Rough cost estimate for an agent's run. The agent's AgentResult shape
   * doesn't surface raw token counts (yet) — this gives us a conservative
   * directional number so the dashboard column isn't permanently $0.
   *
   * Heuristic: ~3000 input + 500 output tokens per tool call (typical for
   * an agent loop with prior context). A 40-tool-call run on Sonnet ≈
   * 40 × 3000 = 120k input + 40 × 500 = 20k output = $0.36 + $0.30 = $0.66.
   * That matches the order of magnitude we observed in the previous run
   * (XBEN challenges with 40 iters ranged $0.30-$10).
   */
  private estimateAgentCostFromTools(toolsExecuted: number): number {
    const tokensPerTool = { input: 3000, output: 500 };
    return this.provider.estimateCost(
      toolsExecuted * tokensPerTool.input,
      toolsExecuted * tokensPerTool.output,
      this.model,
    );
  }

  // ─── Private: Docker Helpers ─────────────────────────────────────────────

  /**
   * P1-1 v2: Patch Dockerfiles in a challenge directory to redirect
   * Debian apt sources to archive.debian.org. Necessary because many
   * XBOW challenges use EOL Debian bases (python:2.7-slim → buster
   * archived; httpd:2.4.49/50 → bullseye-slim with archived components)
   * whose default `deb.debian.org` repos return 404 on `apt-get update`.
   *
   * Idempotent — looks for our marker comment to avoid double-patching.
   * Per-Dockerfile: scans for the FIRST `RUN apt-get update` line and
   * inserts a `RUN sed -i ...` immediately above it. Files without that
   * pattern are untouched.
   *
   * Patch is bounded: only Dockerfiles directly under the challenge dir
   * are scanned (depth 2: <challenge>/<service>/Dockerfile).
   */
  async patchChallengeDockerfiles(challengeDir: string): Promise<{ patched: number; scanned: number }> {
    const fsMod = fs;
    const pathMod = path;
    let scanned = 0;
    let patched = 0;

    // Walk one level deep — challenges have <challenge>/<service>/Dockerfile
    let entries: string[];
    try {
      entries = await fsMod.readdir(challengeDir);
    } catch { return { patched: 0, scanned: 0 }; }

    const dockerfilePaths: string[] = [];
    // Top-level Dockerfile (some challenges have one)
    dockerfilePaths.push(pathMod.join(challengeDir, 'Dockerfile'));
    // Per-service Dockerfiles
    for (const entry of entries) {
      const sub = pathMod.join(challengeDir, entry, 'Dockerfile');
      dockerfilePaths.push(sub);
    }

    for (const dfPath of dockerfilePaths) {
      let content: string;
      try {
        content = await fsMod.readFile(dfPath, 'utf-8');
      } catch { continue; }
      scanned++;

      // Already patched — skip (idempotent)
      if (content.includes('# huntress-archive-patch')) continue;

      // No apt-get update — nothing to fix
      const aptIdx = content.search(/^RUN\b[^\n]*apt-get\s+update/m);
      if (aptIdx < 0) continue;

      // Insert the sed RUN line just above the first apt-get update.
      // Two RUN lines: rewrite sources, then disable signature checks
      // (some archived repos have expired GPG signing keys). The
      // `--allow-insecure-repositories` and `Acquire::Check-Valid-Until=false`
      // flags handle expired Release files.
      // P1-1 v3: SHELL-CONDITIONAL — only rewrite when sources.list points
      // to an actually-archived suite (buster and older). The v1 patch
      // unconditionally rewrote deb.debian.org → archive, which BROKE
      // current releases (bullseye/bookworm/trixie still live at
      // deb.debian.org and DO NOT exist on archive.debian.org). On 20
      // bullseye+ challenges, the v1 patch caused apt-get update exit 100
      // by sending requests to archive.debian.org/debian/dists/bullseye/
      // which returns 404. The grep guard makes the patch a no-op when
      // the base is current.
      const PATCH = [
        `# huntress-archive-patch v2 — conditional rewrite for EOL Debian only`,
        `RUN if [ -f /etc/apt/sources.list ] && \\`,
        `       grep -qE '(buster|stretch|jessie|wheezy)' /etc/apt/sources.list 2>/dev/null; then \\`,
        `      sed -i -e 's|deb.debian.org|archive.debian.org|g' \\`,
        `             -e 's|security.debian.org|archive.debian.org/debian-security|g' \\`,
        `             -e '/-security/d' /etc/apt/sources.list ; \\`,
        `      echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99-archive ; \\`,
        `    fi`,
        ``,
      ].join('\n');

      const patched_content = content.substring(0, aptIdx) + PATCH + content.substring(aptIdx);
      try {
        await fsMod.writeFile(dfPath, patched_content);
        patched++;
      } catch {
        // ignore — best-effort
      }
    }

    return { patched, scanned };
  }

  /**
   * P1-1 v2: Patch the challenge's docker-compose.yml in place to relax
   * fragile depends_on constraints.
   *
   * The XBEN challenges declare `depends_on: <svc>: condition: service_healthy`,
   * which makes `docker compose up` block until the dependency's healthcheck
   * passes. Several of those healthchecks are broken (MySQL with `timeout:
   * 1s` against a 60-second init) and never report healthy → `up` errors
   * with "dependency failed to start".
   *
   * Fix: replace `condition: service_healthy` with `condition: service_started`.
   * Compose then waits for the dependency CONTAINER to start (not be
   * healthy). Our `waitForChallengeReady` port probe handles actual
   * readiness via direct TCP polling — that's what the agent really cares
   * about.
   *
   * Idempotent via a `# huntress-archive-patch` marker comment. The first
   * implementation tried writing a docker-compose.override.yml that named
   * services not present in the base file — that broke ALL challenges with
   * "service X has neither an image nor a build context specified" because
   * Compose treats unknown override services as new invalid declarations.
   * In-place patch sidesteps that entirely.
   */
  async patchChallengeCompose(challengeDir: string): Promise<{ patched: boolean }> {
    const composeNames = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'];
    let composePath: string | null = null;
    for (const name of composeNames) {
      const p = path.join(challengeDir, name);
      try {
        await fs.access(p);
        composePath = p;
        break;
      } catch { /* try next */ }
    }
    if (!composePath) return { patched: false };

    let content: string;
    try {
      content = await fs.readFile(composePath, 'utf-8');
    } catch { return { patched: false }; }

    // Idempotency check
    if (content.includes('# huntress-archive-patch')) return { patched: false };

    // Only patch when there's something to patch
    if (!/condition:\s*service_healthy/.test(content)) return { patched: false };

    const patched = content
      .replace(/condition:\s*service_healthy/g, 'condition: service_started')
      .replace(/^/, '# huntress-archive-patch — service_healthy → service_started\n');

    try {
      await fs.writeFile(composePath, patched);
      return { patched: true };
    } catch {
      return { patched: false };
    }
  }

  /**
   * Poll an HTTP target until it accepts a TCP connection (any HTTP response,
   * even 5xx, counts as ready — the CTF agent can work with a partially-up
   * backend). Replaces dependence on `docker compose up --wait` which honors
   * per-service healthchecks; many XBOW challenges have unreliable healthcheck
   * configs (e.g. MySQL `timeout: 1s` against ~60s init time).
   *
   * Returns true when reachable within `maxWaitMs`, false on timeout.
   */
  private async waitForChallengeReady(targetUrl: string, maxWaitMs: number): Promise<boolean> {
    const deadline = Date.now() + maxWaitMs;
    const pollIntervalMs = 3_000;
    while (Date.now() < deadline) {
      // Use curl with a short connect timeout so we don't block on a single try.
      // exit 0 = response received, exit 7 = connection refused (try again),
      // exit 28 = timeout (try again), other = treat as still-coming-up.
      const probe = await executeCommand(
        'curl',
        ['-s', '-o', '/dev/null', '--connect-timeout', '2', '--max-time', '5', '-w', '%{http_code}', targetUrl],
      );
      if (probe.exitCode === 0 && probe.stdout && probe.stdout !== '000') {
        return true;
      }
      await new Promise<void>(resolve => setTimeout(resolve, pollIntervalMs));
    }
    return false;
  }

  /** Discover the host-mapped port for the challenge container */
  private async getExposedPort(challengeDir: string): Promise<number> {
    // Use docker compose ps to find the exposed port
    const psResult = await executeCommand(
      'docker',
      ['compose', 'ps', '--format', 'json'],
      challengeDir,
    );

    if (!psResult.success) {
      // Fallback: try docker compose port
      const portResult = await executeCommand(
        'docker',
        ['compose', 'port', '--index', '1', 'challenge', '80'],
        challengeDir,
      );

      if (portResult.success && portResult.stdout.trim()) {
        // Output format: 0.0.0.0:12345
        const parts = portResult.stdout.trim().split(':');
        const portStr = parts[parts.length - 1];
        const port = parseInt(portStr, 10);
        if (!isNaN(port) && port > 0) return port;
      }

      // Second fallback: try common ports
      for (const commonPort of [8080, 80, 3000, 5000, 8000, 443]) {
        const portResult2 = await executeCommand(
          'docker',
          ['compose', 'port', 'challenge', String(commonPort)],
          challengeDir,
        );
        if (portResult2.success && portResult2.stdout.trim()) {
          const parts2 = portResult2.stdout.trim().split(':');
          const portStr2 = parts2[parts2.length - 1];
          const port2 = parseInt(portStr2, 10);
          if (!isNaN(port2) && port2 > 0) return port2;
        }
      }

      return 0;
    }

    // Parse JSON output to find published ports
    try {
      // docker compose ps --format json may return one JSON object per line
      const lines = psResult.stdout.trim().split('\n');
      for (const line of lines) {
        const container = JSON.parse(line) as {
          Publishers?: Array<{ PublishedPort: number; TargetPort: number }>;
        };
        if (container.Publishers && container.Publishers.length > 0) {
          const pub = container.Publishers.find((p) => p.PublishedPort > 0);
          if (pub) return pub.PublishedPort;
        }
      }
    } catch {
      // JSON parse failure — fall through
    }

    return 0;
  }

  // ─── Private: Database ───────────────────────────────────────────────────

  /** Create the benchmark tables if they do not exist */
  private async initDatabase(): Promise<void> {
    await knowledgeDbExecute(
      this.dbPath,
      `CREATE TABLE IF NOT EXISTS benchmark_runs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        model TEXT NOT NULL,
        score REAL NOT NULL,
        total_challenges INTEGER NOT NULL,
        solved INTEGER NOT NULL,
        failed INTEGER NOT NULL,
        skipped INTEGER NOT NULL,
        total_cost_usd REAL NOT NULL,
        total_duration_ms INTEGER NOT NULL,
        results_json TEXT NOT NULL,
        by_tag_json TEXT NOT NULL,
        by_level_json TEXT NOT NULL
      )`,
    );

    // P1-1 v7: Per-challenge incremental persistence. Without this, killing
    // the runner mid-benchmark loses every completed challenge — the
    // aggregate row is only written when runBenchmark() finishes. Now each
    // ChallengeResult is written to benchmark_results as soon as it
    // completes, so a kill-on-39/104 still leaves 39 rows of data we can
    // analyze afterward.
    await knowledgeDbExecute(
      this.dbPath,
      `CREATE TABLE IF NOT EXISTS benchmark_results (
        run_id TEXT NOT NULL,
        challenge_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        solved INTEGER NOT NULL,
        flag TEXT,
        expected_flag TEXT NOT NULL,
        iterations INTEGER NOT NULL,
        duration_ms INTEGER NOT NULL,
        cost_usd REAL NOT NULL,
        tokens_used INTEGER NOT NULL,
        error TEXT,
        PRIMARY KEY (run_id, challenge_id)
      )`,
    );
    await knowledgeDbExecute(
      this.dbPath,
      `CREATE INDEX IF NOT EXISTS idx_benchmark_results_run ON benchmark_results(run_id)`,
    );
  }

  /** P1-1 v7: Persist a single ChallengeResult immediately after the
   * challenge finishes. Idempotent via PRIMARY KEY (run_id, challenge_id);
   * if the same challenge runs twice in a single run (rare, but possible
   * if a retry path is added), the second write replaces the first. */
  private async persistChallengeResult(runId: string, result: ChallengeResult): Promise<void> {
    await knowledgeDbExecute(
      this.dbPath,
      `INSERT OR REPLACE INTO benchmark_results
        (run_id, challenge_id, timestamp, solved, flag, expected_flag,
         iterations, duration_ms, cost_usd, tokens_used, error)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        runId,
        result.challengeId,
        new Date().toISOString(),
        String(result.solved ? 1 : 0),
        result.flag ?? '',
        result.expectedFlag,
        String(result.iterations),
        String(result.durationMs),
        String(result.costUsd),
        String(result.tokensUsed),
        result.error ?? '',
      ],
    ).catch((err) => {
      // Persistence failure must not crash the benchmark — log and continue.
      // Worst case: we lose ONE challenge's row; the aggregate run still
      // captures it via results_json on completion.
      // eslint-disable-next-line no-console
      console.error(`[xbow] failed to persist ${result.challengeId}: ${err instanceof Error ? err.message : String(err)}`);
    });
  }

  /** Persist a benchmark run to the database */
  private async persistBenchmarkRun(result: BenchmarkResult): Promise<void> {
    await knowledgeDbExecute(
      this.dbPath,
      `INSERT INTO benchmark_runs
        (id, timestamp, model, score, total_challenges, solved, failed, skipped, total_cost_usd, total_duration_ms, results_json, by_tag_json, by_level_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        result.id,
        result.timestamp,
        result.modelConfig,
        String(result.scorePercent),
        String(result.totalChallenges),
        String(result.solved),
        String(result.failed),
        String(result.skipped),
        String(result.totalCostUsd),
        String(result.totalDurationMs),
        JSON.stringify(result.results),
        JSON.stringify(result.byTag),
        JSON.stringify(result.byLevel),
      ],
    );
  }

  /** Load a full benchmark run from the database by ID */
  private async loadBenchmarkRun(runId: string): Promise<BenchmarkResult | null> {
    const queryResult = await knowledgeDbQuery(
      this.dbPath,
      `SELECT * FROM benchmark_runs WHERE id = ?`,
      [runId],
    );

    if (queryResult.rows.length === 0) return null;

    const row = queryResult.rows[0];
    const results = JSON.parse(row['results_json'] as string) as ChallengeResult[];
    const byTag = JSON.parse(row['by_tag_json'] as string) as Record<
      string,
      { total: number; solved: number }
    >;
    const byLevel = JSON.parse(row['by_level_json'] as string) as Record<
      number,
      { total: number; solved: number }
    >;

    return {
      id: row['id'] as string,
      timestamp: row['timestamp'] as string,
      totalChallenges: row['total_challenges'] as number,
      solved: row['solved'] as number,
      failed: row['failed'] as number,
      skipped: row['skipped'] as number,
      scorePercent: row['score'] as number,
      results,
      modelConfig: row['model'] as string,
      totalCostUsd: row['total_cost_usd'] as number,
      totalDurationMs: row['total_duration_ms'] as number,
      byTag,
      byLevel,
    };
  }

  // ─── Private: Utilities ──────────────────────────────────────────────────

  /** Emit a progress event if the callback is configured */
  private emitProgress(phase: string, current: number, total: number, message: string): void {
    if (this.onProgress) {
      this.onProgress(phase, current, total, message);
    }
  }

  /**
   * Run a promise with a timeout. Rejects with a timeout error if the
   * promise does not resolve within the given duration.
   */
  private async runWithTimeout<T>(fn: () => Promise<T>, timeoutMs: number): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      let settled = false;

      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          reject(new Error(`Challenge timed out after ${timeoutMs}ms`));
        }
      }, timeoutMs);

      fn()
        .then((result) => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            resolve(result);
          }
        })
        .catch((err) => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            reject(err);
          }
        });
    });
  }

}

export default XBOWBenchmarkRunner;

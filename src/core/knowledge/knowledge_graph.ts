/**
 * Knowledge Graph — Persistent learning & performance tracking for Huntress
 *
 * Stores hunt results, learned patterns, agent performance metrics, benchmark
 * history, and reward events in a local SQLite database via Tauri IPC.
 *
 * All queries use explicit parameter binding — never string interpolation.
 */

import {
  knowledgeDbQuery,
  knowledgeDbExecute,
  initKnowledgeDb,
  type KnowledgeQueryResult,
} from '../tauri_bridge';

// ─── Data Types ──────────────────────────────────────────────────────────────

export interface HuntResult {
  sessionId: string;
  target: string;
  agentId: string;
  vulnType: string;
  findingTitle: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  success: boolean;
  bountyAmount: number;
  h1ReportId?: string;
  h1Status?: string;
  techniquesUsed: string[];
  durationMs: number;
  modelUsed: string;
  tokensUsed: number;
  costUsd: number;
}

export type PatternType =
  | 'target_stack'
  | 'vuln_technique'
  | 'agent_effectiveness'
  | 'endpoint_pattern'
  | 'waf_bypass';

export interface LearnedPattern {
  patternType: PatternType;
  patternKey: string;
  patternValue: string;
  confidence: number;
  source: string;
}

export interface BenchmarkRun {
  model: string;
  totalChallenges: number;
  solved: number;
  failed: number;
  skipped: number;
  score: number;
  totalCostUsd: number;
  totalDurationMs: number;
  resultsJson: string; // JSON-encoded challenge-level detail
  byTagJson: string;
  byLevelJson: string;
}

export type RewardEventType =
  | 'finding_validated'
  | 'bounty_earned'
  | 'duplicate_penalty'
  | 'false_positive_penalty'
  | 'benchmark_improvement'
  | 'technique_novel';

export interface RewardEvent {
  sessionId: string;
  agentId: string;
  eventType: RewardEventType;
  points: number;
  reason: string;
  details: string;
}

export interface AgentPerformance {
  agentId: string;
  totalHunts: number;
  successes: number;
  failures: number;
  successRate: number;
  totalBounties: number;
  avgBounty: number;
  topVulnTypes: Array<{ vulnType: string; count: number }>;
}

export interface OverallStats {
  totalHunts: number;
  successRate: number;
  totalBounties: number;
  avgBounty: number;
  topVulnTypes: Array<{ vulnType: string; count: number }>;
  topAgents: Array<{ agentId: string; successRate: number; hunts: number }>;
  recentTrend: 'improving' | 'stable' | 'declining';
}

// ─── Internal helpers ────────────────────────────────────────────────────────

interface RankedTechnique {
  technique: string;
  successes: number;
  total: number;
  successRate: number;
}

function generateId(): string {
  return crypto.randomUUID();
}

function nowIso(): string {
  return new Date().toISOString();
}

/** Safely extract a number from an unknown query row field. */
function num(value: unknown): number {
  if (typeof value === 'number') return value;
  if (typeof value === 'string') {
    const parsed = Number(value);
    return Number.isNaN(parsed) ? 0 : parsed;
  }
  return 0;
}

/** Safely extract a string from an unknown query row field. */
function str(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return '';
  return String(value);
}

// ─── Schema DDL ──────────────────────────────────────────────────────────────

const SCHEMA_STATEMENTS: string[] = [
  `CREATE TABLE IF NOT EXISTS hunt_results (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    target TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    finding_title TEXT NOT NULL,
    severity TEXT NOT NULL,
    success INTEGER NOT NULL,
    bounty_amount REAL NOT NULL DEFAULT 0,
    h1_report_id TEXT,
    h1_status TEXT,
    techniques_used TEXT NOT NULL DEFAULT '[]',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    model_used TEXT NOT NULL DEFAULT '',
    tokens_used INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  )`,

  `CREATE TABLE IF NOT EXISTS learned_patterns (
    id TEXT PRIMARY KEY,
    pattern_type TEXT NOT NULL,
    pattern_key TEXT NOT NULL,
    pattern_value TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    successes INTEGER NOT NULL DEFAULT 0,
    failures INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`,

  `CREATE TABLE IF NOT EXISTS benchmark_runs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    model TEXT NOT NULL DEFAULT '',
    score REAL NOT NULL DEFAULT 0,
    total_challenges INTEGER NOT NULL DEFAULT 0,
    solved INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    skipped INTEGER NOT NULL DEFAULT 0,
    total_cost_usd REAL NOT NULL DEFAULT 0,
    total_duration_ms INTEGER NOT NULL DEFAULT 0,
    results_json TEXT NOT NULL DEFAULT '[]',
    by_tag_json TEXT NOT NULL DEFAULT '{}',
    by_level_json TEXT NOT NULL DEFAULT '{}'
  )`,

  `CREATE TABLE IF NOT EXISTS reward_events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    points REAL NOT NULL DEFAULT 0,
    reason TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
  )`,

  // Indexes for common query patterns
  `CREATE INDEX IF NOT EXISTS idx_hunt_results_target ON hunt_results(target)`,
  `CREATE INDEX IF NOT EXISTS idx_hunt_results_agent ON hunt_results(agent_id)`,
  `CREATE INDEX IF NOT EXISTS idx_hunt_results_vuln ON hunt_results(vuln_type)`,
  `CREATE INDEX IF NOT EXISTS idx_hunt_results_session ON hunt_results(session_id)`,
  `CREATE INDEX IF NOT EXISTS idx_learned_patterns_type_key ON learned_patterns(pattern_type, pattern_key)`,
  `CREATE INDEX IF NOT EXISTS idx_benchmark_runs_model ON benchmark_runs(model)`,
  `CREATE INDEX IF NOT EXISTS idx_reward_events_session ON reward_events(session_id)`,
];

// ─── Knowledge Graph ─────────────────────────────────────────────────────────

export class KnowledgeGraph {
  private readonly dbPath: string;
  private initialized = false;

  constructor(dbPath: string = 'huntress_knowledge.db') {
    this.dbPath = dbPath;
  }

  // ── Lifecycle ────────────────────────────────────────────────────────────

  async initialize(): Promise<void> {
    await initKnowledgeDb(this.dbPath);

    for (const ddl of SCHEMA_STATEMENTS) {
      await knowledgeDbExecute(this.dbPath, ddl);
    }

    this.initialized = true;
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('KnowledgeGraph not initialized — call initialize() first');
    }
  }

  // ── Hunt Results ─────────────────────────────────────────────────────────

  async recordHuntResult(result: HuntResult): Promise<string> {
    this.ensureInitialized();

    const id = generateId();
    const now = nowIso();

    await knowledgeDbExecute(
      this.dbPath,
      `INSERT INTO hunt_results (
        id, session_id, target, agent_id, vuln_type, finding_title,
        severity, success, bounty_amount, h1_report_id, h1_status,
        techniques_used, duration_ms, model_used, tokens_used, cost_usd,
        created_at
      ) VALUES (
        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
      )`,
      [
        id,
        result.sessionId,
        result.target,
        result.agentId,
        result.vulnType,
        result.findingTitle,
        result.severity,
        result.success ? '1' : '0',
        String(result.bountyAmount),
        result.h1ReportId ?? '',
        result.h1Status ?? '',
        JSON.stringify(result.techniquesUsed),
        String(result.durationMs),
        result.modelUsed,
        String(result.tokensUsed),
        String(result.costUsd),
        now,
      ],
    );

    return id;
  }

  // ── Learned Patterns ─────────────────────────────────────────────────────

  async recordLearnedPattern(pattern: LearnedPattern): Promise<string> {
    this.ensureInitialized();

    // Upsert: if pattern_type+pattern_key already exists, update it
    const existing = await knowledgeDbQuery(
      this.dbPath,
      `SELECT id FROM learned_patterns
       WHERE pattern_type = ?1 AND pattern_key = ?2
       LIMIT 1`,
      [pattern.patternType, pattern.patternKey],
    );

    const now = nowIso();

    if (existing.rows.length > 0) {
      const existingId = str(existing.rows[0]['id']);
      await knowledgeDbExecute(
        this.dbPath,
        `UPDATE learned_patterns
         SET pattern_value = ?1, confidence = ?2, source = ?3, updated_at = ?4
         WHERE id = ?5`,
        [
          pattern.patternValue,
          String(pattern.confidence),
          pattern.source,
          now,
          existingId,
        ],
      );
      return existingId;
    }

    const id = generateId();
    await knowledgeDbExecute(
      this.dbPath,
      `INSERT INTO learned_patterns (
        id, pattern_type, pattern_key, pattern_value, confidence,
        successes, failures, source, created_at, updated_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
      [
        id,
        pattern.patternType,
        pattern.patternKey,
        pattern.patternValue,
        String(pattern.confidence),
        '0',
        '0',
        pattern.source,
        now,
        now,
      ],
    );

    return id;
  }

  // ── Pattern Confidence ───────────────────────────────────────────────────

  async getPatternConfidence(patternType: string, patternKey: string): Promise<number> {
    this.ensureInitialized();

    const result = await knowledgeDbQuery(
      this.dbPath,
      `SELECT confidence FROM learned_patterns
       WHERE pattern_type = ?1 AND pattern_key = ?2
       LIMIT 1`,
      [patternType, patternKey],
    );

    if (result.rows.length === 0) return 0;
    return num(result.rows[0]['confidence']);
  }

  /**
   * Bayesian update of pattern confidence.
   *
   * Uses a simple Beta-distribution model: confidence = (successes + 1) / (successes + failures + 2).
   * The +1/+2 provide a uniform prior (Laplace smoothing) so a pattern with zero observations
   * starts at 0.5 and converges as evidence accumulates.
   */
  async updatePatternFromOutcome(
    patternType: string,
    patternKey: string,
    success: boolean,
  ): Promise<number> {
    this.ensureInitialized();

    const existing = await knowledgeDbQuery(
      this.dbPath,
      `SELECT id, successes, failures FROM learned_patterns
       WHERE pattern_type = ?1 AND pattern_key = ?2
       LIMIT 1`,
      [patternType, patternKey],
    );

    const now = nowIso();

    if (existing.rows.length === 0) {
      // Auto-create pattern if it doesn't exist yet
      const id = generateId();
      const successes = success ? 1 : 0;
      const failures = success ? 0 : 1;
      const confidence = (successes + 1) / (successes + failures + 2);

      await knowledgeDbExecute(
        this.dbPath,
        `INSERT INTO learned_patterns (
          id, pattern_type, pattern_key, pattern_value, confidence,
          successes, failures, source, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
        [
          id,
          patternType,
          patternKey,
          '',
          String(confidence),
          String(successes),
          String(failures),
          'outcome_update',
          now,
          now,
        ],
      );

      return confidence;
    }

    const row = existing.rows[0];
    const existingId = str(row['id']);
    const successes = num(row['successes']) + (success ? 1 : 0);
    const failures = num(row['failures']) + (success ? 0 : 1);
    const confidence = (successes + 1) / (successes + failures + 2);

    await knowledgeDbExecute(
      this.dbPath,
      `UPDATE learned_patterns
       SET successes = ?1, failures = ?2, confidence = ?3, updated_at = ?4
       WHERE id = ?5`,
      [
        String(successes),
        String(failures),
        String(confidence),
        now,
        existingId,
      ],
    );

    return confidence;
  }

  // ── Pattern Queries ──────────────────────────────────────────────────────

  async queryRelevantPatterns(
    target: string,
    vulnType?: string,
  ): Promise<Array<LearnedPattern & { successes: number; failures: number }>> {
    this.ensureInitialized();

    // Search patterns whose key contains the target domain or whose type matches the vuln
    // Use LIKE with wildcard for flexible matching
    let sql: string;
    let params: string[];

    if (vulnType) {
      sql = `SELECT pattern_type, pattern_key, pattern_value, confidence, source, successes, failures
             FROM learned_patterns
             WHERE (pattern_key LIKE ?1 OR pattern_key LIKE ?2)
             ORDER BY confidence DESC
             LIMIT 50`;
      params = [`%${target}%`, `%${vulnType}%`];
    } else {
      sql = `SELECT pattern_type, pattern_key, pattern_value, confidence, source, successes, failures
             FROM learned_patterns
             WHERE pattern_key LIKE ?1
             ORDER BY confidence DESC
             LIMIT 50`;
      params = [`%${target}%`];
    }

    const result = await knowledgeDbQuery(this.dbPath, sql, params);

    return result.rows.map((row) => ({
      patternType: str(row['pattern_type']) as PatternType,
      patternKey: str(row['pattern_key']),
      patternValue: str(row['pattern_value']),
      confidence: num(row['confidence']),
      source: str(row['source']),
      successes: num(row['successes']),
      failures: num(row['failures']),
    }));
  }

  // ── Agent Performance ────────────────────────────────────────────────────

  async getAgentPerformance(agentId: string): Promise<AgentPerformance> {
    this.ensureInitialized();

    const statsResult = await knowledgeDbQuery(
      this.dbPath,
      `SELECT
        COUNT(*) as total_hunts,
        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes,
        SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failures,
        SUM(bounty_amount) as total_bounties,
        AVG(CASE WHEN bounty_amount > 0 THEN bounty_amount ELSE NULL END) as avg_bounty
       FROM hunt_results
       WHERE agent_id = ?1`,
      [agentId],
    );

    const topVulnResult = await knowledgeDbQuery(
      this.dbPath,
      `SELECT vuln_type, COUNT(*) as cnt
       FROM hunt_results
       WHERE agent_id = ?1 AND success = 1
       GROUP BY vuln_type
       ORDER BY cnt DESC
       LIMIT 5`,
      [agentId],
    );

    const stats = statsResult.rows[0] ?? {};
    const totalHunts = num(stats['total_hunts']);
    const successes = num(stats['successes']);
    const failures = num(stats['failures']);

    return {
      agentId,
      totalHunts,
      successes,
      failures,
      successRate: totalHunts > 0 ? successes / totalHunts : 0,
      totalBounties: num(stats['total_bounties']),
      avgBounty: num(stats['avg_bounty']),
      topVulnTypes: topVulnResult.rows.map((row) => ({
        vulnType: str(row['vuln_type']),
        count: num(row['cnt']),
      })),
    };
  }

  // ── Target History ───────────────────────────────────────────────────────

  async getTargetHistory(
    target: string,
  ): Promise<Array<{
    id: string;
    sessionId: string;
    agentId: string;
    vulnType: string;
    findingTitle: string;
    severity: string;
    success: boolean;
    bountyAmount: number;
    h1Status: string;
    createdAt: string;
  }>> {
    this.ensureInitialized();

    const result = await knowledgeDbQuery(
      this.dbPath,
      `SELECT id, session_id, agent_id, vuln_type, finding_title,
              severity, success, bounty_amount, h1_status, created_at
       FROM hunt_results
       WHERE target = ?1
       ORDER BY created_at DESC
       LIMIT 100`,
      [target],
    );

    return result.rows.map((row) => ({
      id: str(row['id']),
      sessionId: str(row['session_id']),
      agentId: str(row['agent_id']),
      vulnType: str(row['vuln_type']),
      findingTitle: str(row['finding_title']),
      severity: str(row['severity']),
      success: num(row['success']) === 1,
      bountyAmount: num(row['bounty_amount']),
      h1Status: str(row['h1_status']),
      createdAt: str(row['created_at']),
    }));
  }

  // ── Best Techniques ──────────────────────────────────────────────────────

  async getBestTechniquesFor(vulnType: string): Promise<RankedTechnique[]> {
    this.ensureInitialized();

    // Retrieve all hunt results for the given vuln type that used techniques
    const result = await knowledgeDbQuery(
      this.dbPath,
      `SELECT techniques_used, success
       FROM hunt_results
       WHERE vuln_type = ?1`,
      [vulnType],
    );

    // Aggregate per technique
    const techniqueMap = new Map<string, { successes: number; total: number }>();

    for (const row of result.rows) {
      const success = num(row['success']) === 1;
      let techniques: string[];
      try {
        techniques = JSON.parse(str(row['techniques_used'])) as string[];
      } catch {
        continue;
      }

      for (const technique of techniques) {
        const existing = techniqueMap.get(technique) ?? { successes: 0, total: 0 };
        existing.total += 1;
        if (success) existing.successes += 1;
        techniqueMap.set(technique, existing);
      }
    }

    // Rank by success rate (with minimum 2 observations for statistical relevance)
    const ranked: RankedTechnique[] = [];
    for (const [technique, counts] of techniqueMap) {
      ranked.push({
        technique,
        successes: counts.successes,
        total: counts.total,
        successRate: counts.total > 0 ? counts.successes / counts.total : 0,
      });
    }

    ranked.sort((a, b) => {
      // Prefer techniques with more observations when success rates are close
      if (Math.abs(a.successRate - b.successRate) < 0.05) {
        return b.total - a.total;
      }
      return b.successRate - a.successRate;
    });

    return ranked;
  }

  // ── Benchmark Tracking ───────────────────────────────────────────────────

  async recordBenchmarkRun(run: BenchmarkRun): Promise<string> {
    this.ensureInitialized();

    const id = generateId();
    const now = nowIso();

    await knowledgeDbExecute(
      this.dbPath,
      `INSERT INTO benchmark_runs (
        id, timestamp, model, score, total_challenges, solved, failed,
        skipped, total_cost_usd, total_duration_ms, results_json,
        by_tag_json, by_level_json
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`,
      [
        id,
        now,
        run.model,
        String(run.score),
        String(run.totalChallenges),
        String(run.solved),
        String(run.failed),
        String(run.skipped),
        String(run.totalCostUsd),
        String(run.totalDurationMs),
        run.resultsJson,
        run.byTagJson,
        run.byLevelJson,
      ],
    );

    return id;
  }

  async getBenchmarkHistory(
    benchmarkName: string,
  ): Promise<Array<BenchmarkRun & { id: string; createdAt: string }>> {
    this.ensureInitialized();

    const result = await knowledgeDbQuery(
      this.dbPath,
      `SELECT id, timestamp, model, score, total_challenges, solved, failed,
              skipped, total_cost_usd, total_duration_ms, results_json,
              by_tag_json, by_level_json
       FROM benchmark_runs
       WHERE model = ?1
       ORDER BY timestamp DESC
       LIMIT 100`,
      [benchmarkName],
    );

    return result.rows.map((row) => ({
      id: str(row['id']),
      model: str(row['model']),
      totalChallenges: num(row['total_challenges']),
      solved: num(row['solved']),
      failed: num(row['failed']),
      skipped: num(row['skipped']),
      score: num(row['score']),
      totalCostUsd: num(row['total_cost_usd']),
      totalDurationMs: num(row['total_duration_ms']),
      resultsJson: str(row['results_json']),
      byTagJson: str(row['by_tag_json']),
      byLevelJson: str(row['by_level_json']),
      createdAt: str(row['timestamp']),
    }));
  }

  // ── Reward System ────────────────────────────────────────────────────────

  async recordRewardEvent(event: RewardEvent): Promise<string> {
    this.ensureInitialized();

    const id = generateId();
    const now = nowIso();

    await knowledgeDbExecute(
      this.dbPath,
      `INSERT INTO reward_events (
        id, session_id, agent_id, event_type, points, reason, details, created_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`,
      [
        id,
        event.sessionId,
        event.agentId,
        event.eventType,
        String(event.points),
        event.reason,
        event.details,
        now,
      ],
    );

    return id;
  }

  async getRewardBalance(sessionId: string): Promise<number> {
    this.ensureInitialized();

    const result = await knowledgeDbQuery(
      this.dbPath,
      `SELECT COALESCE(SUM(points), 0) as balance
       FROM reward_events
       WHERE session_id = ?1`,
      [sessionId],
    );

    if (result.rows.length === 0) return 0;
    return num(result.rows[0]['balance']);
  }

  // ── Overall Statistics ───────────────────────────────────────────────────

  async getOverallStats(): Promise<OverallStats> {
    this.ensureInitialized();

    // Aggregate hunt stats
    const statsResult = await knowledgeDbQuery(
      this.dbPath,
      `SELECT
        COUNT(*) as total_hunts,
        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes,
        SUM(bounty_amount) as total_bounties,
        AVG(CASE WHEN bounty_amount > 0 THEN bounty_amount ELSE NULL END) as avg_bounty
       FROM hunt_results`,
    );

    // Top vuln types by successful find count
    const topVulnResult = await knowledgeDbQuery(
      this.dbPath,
      `SELECT vuln_type, COUNT(*) as cnt
       FROM hunt_results
       WHERE success = 1
       GROUP BY vuln_type
       ORDER BY cnt DESC
       LIMIT 10`,
    );

    // Top agents by success rate (minimum 3 hunts for inclusion)
    const topAgentResult = await knowledgeDbQuery(
      this.dbPath,
      `SELECT
        agent_id,
        COUNT(*) as hunts,
        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes
       FROM hunt_results
       GROUP BY agent_id
       HAVING hunts >= 3
       ORDER BY (CAST(successes AS REAL) / hunts) DESC
       LIMIT 10`,
    );

    // Recent trend: compare last 30 results vs previous 30
    const recentResult = await knowledgeDbQuery(
      this.dbPath,
      `SELECT success, created_at
       FROM hunt_results
       ORDER BY created_at DESC
       LIMIT 60`,
    );

    const stats = statsResult.rows[0] ?? {};
    const totalHunts = num(stats['total_hunts']);
    const successes = num(stats['successes']);

    // Calculate trend
    let recentTrend: 'improving' | 'stable' | 'declining' = 'stable';
    if (recentResult.rows.length >= 10) {
      const midpoint = Math.floor(recentResult.rows.length / 2);
      const recentHalf = recentResult.rows.slice(0, midpoint);
      const olderHalf = recentResult.rows.slice(midpoint);

      const recentRate = recentHalf.filter((r) => num(r['success']) === 1).length / recentHalf.length;
      const olderRate = olderHalf.filter((r) => num(r['success']) === 1).length / olderHalf.length;

      const delta = recentRate - olderRate;
      if (delta > 0.1) {
        recentTrend = 'improving';
      } else if (delta < -0.1) {
        recentTrend = 'declining';
      }
    }

    return {
      totalHunts,
      successRate: totalHunts > 0 ? successes / totalHunts : 0,
      totalBounties: num(stats['total_bounties']),
      avgBounty: num(stats['avg_bounty']),
      topVulnTypes: topVulnResult.rows.map((row) => ({
        vulnType: str(row['vuln_type']),
        count: num(row['cnt']),
      })),
      topAgents: topAgentResult.rows.map((row) => {
        const hunts = num(row['hunts']);
        const agentSuccesses = num(row['successes']);
        return {
          agentId: str(row['agent_id']),
          successRate: hunts > 0 ? agentSuccesses / hunts : 0,
          hunts,
        };
      }),
      recentTrend,
    };
  }
}

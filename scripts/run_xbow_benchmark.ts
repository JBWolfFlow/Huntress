#!/usr/bin/env -S npx tsx
/**
 * Headless XBOW Benchmark Runner — Phase 1.1
 *
 * Run the XBOW 104-challenge validation benchmark from the CLI without
 * launching the Tauri desktop app. Useful for:
 *   - First-time benchmark scoring (no UI button needed)
 *   - Re-running after each P0-3 validator deepening to measure delta
 *   - CI / scheduled measurement (cron the script and capture stdout)
 *
 * Usage:
 *   ANTHROPIC_API_KEY=sk-ant-... npx tsx scripts/run_xbow_benchmark.ts
 *
 * Common options (positional flags, simple parsing — no yargs dependency):
 *   --tags=sqli,xss            Run only challenges with these tags
 *   --levels=1,2               Run only level 1 and 2 challenges
 *   --challenges=id1,id2       Run only the listed challenge IDs
 *   --max-parallel=2           Limit concurrent challenge containers
 *   --timeout-per-challenge=300000   Per-challenge timeout in ms (default 5min)
 *   --model=claude-sonnet-4-6  Override the model (default: opus 4.7)
 *   --benchmark-dir=/path      Where to clone validation-benchmarks
 *   --db=/path/to/sqlite       Where to persist runs (default: ./huntress_benchmark.db)
 *
 * Output: progress lines on stderr, final markdown report on stdout.
 *
 * Prerequisites:
 *   - Docker installed and the user can run docker without sudo
 *   - Anthropic API key (or whatever provider you select via HUNTRESS_PROVIDER)
 *   - ~10 GB disk for the cloned benchmark repo + built containers
 *   - Sufficient API budget — a full 104-challenge run can cost $50–$200
 */

import { XBOWBenchmarkRunner, type BenchmarkConfig, type BenchmarkResult } from '../src/core/benchmark/xbow_runner.js';
import { AnthropicProvider } from '../src/core/providers/anthropic.js';

interface CliFlags {
  tags?: string[];
  levels?: number[];
  challengeIds?: string[];
  maxParallel: number;
  timeoutPerChallenge: number;
  model: string;
  benchmarkDir: string;
  dbPath: string;
}

function parseFlags(argv: string[]): CliFlags {
  const flags: CliFlags = {
    maxParallel: 2,
    timeoutPerChallenge: 300_000,
    model: 'claude-opus-4-7',
    benchmarkDir: '/tmp/huntress-xbow-bench',
    dbPath: 'huntress_benchmark.db',
  };

  for (const arg of argv.slice(2)) {
    const [key, raw] = arg.replace(/^--/, '').split('=');
    if (raw === undefined) continue;
    const csv = (s: string) => s.split(',').map(x => x.trim()).filter(Boolean);
    switch (key) {
      case 'tags': flags.tags = csv(raw); break;
      case 'levels': flags.levels = csv(raw).map(Number).filter(n => !Number.isNaN(n)); break;
      case 'challenges': flags.challengeIds = csv(raw); break;
      case 'max-parallel': flags.maxParallel = Number(raw) || flags.maxParallel; break;
      case 'timeout-per-challenge': flags.timeoutPerChallenge = Number(raw) || flags.timeoutPerChallenge; break;
      case 'model': flags.model = raw; break;
      case 'benchmark-dir': flags.benchmarkDir = raw; break;
      case 'db': flags.dbPath = raw; break;
      default:
        process.stderr.write(`[warn] unknown flag --${key}\n`);
    }
  }

  return flags;
}

function progress(phase: string, current: number, total: number, message: string): void {
  process.stderr.write(`[${phase}] ${current}/${total} — ${message}\n`);
}

/**
 * Render a benchmark result as Markdown for stdout.
 * Format is the same shape we want to publish in PIPELINE.md so the user can
 * paste the relevant lines straight into §1.
 */
function renderMarkdown(result: BenchmarkResult): string {
  const lines: string[] = [];
  lines.push(`# XBOW Benchmark Run — ${result.timestamp}`);
  lines.push('');
  lines.push(`**Score:** ${result.scorePercent.toFixed(2)}%  (${result.solved}/${result.totalChallenges} solved)`);
  lines.push(`**Model:** ${result.modelConfig}`);
  lines.push(`**Total cost:** $${result.totalCostUsd.toFixed(2)}`);
  lines.push(`**Total duration:** ${(result.totalDurationMs / 60_000).toFixed(1)} minutes`);
  lines.push(`**Cost per challenge:** $${(result.totalCostUsd / result.totalChallenges).toFixed(3)}`);
  lines.push('');

  if (Object.keys(result.byTag).length > 0) {
    lines.push('## Score by vulnerability tag');
    lines.push('');
    lines.push('| Tag | Solved | Total | Score |');
    lines.push('|---|---|---|---|');
    const sorted = Object.entries(result.byTag).sort(([, a], [, b]) => (b.solved / b.total) - (a.solved / a.total));
    for (const [tag, stats] of sorted) {
      const pct = stats.total > 0 ? (stats.solved / stats.total) * 100 : 0;
      lines.push(`| ${tag} | ${stats.solved} | ${stats.total} | ${pct.toFixed(0)}% |`);
    }
    lines.push('');
  }

  if (Object.keys(result.byLevel).length > 0) {
    lines.push('## Score by difficulty level');
    lines.push('');
    lines.push('| Level | Solved | Total | Score |');
    lines.push('|---|---|---|---|');
    const sorted = Object.entries(result.byLevel).sort(([a], [b]) => Number(a) - Number(b));
    for (const [level, stats] of sorted) {
      const pct = stats.total > 0 ? (stats.solved / stats.total) * 100 : 0;
      lines.push(`| L${level} | ${stats.solved} | ${stats.total} | ${pct.toFixed(0)}% |`);
    }
    lines.push('');
  }

  lines.push('## Per-challenge results');
  lines.push('');
  lines.push('| Challenge | Status | Iterations | Cost | Duration |');
  lines.push('|---|---|---|---|---|');
  for (const r of result.results) {
    const status = r.solved ? 'SOLVED' : r.error ? 'ERROR' : 'FAILED';
    const dur = (r.durationMs / 1000).toFixed(1) + 's';
    lines.push(`| ${r.challengeId} | ${status} | ${r.iterations} | $${r.costUsd.toFixed(3)} | ${dur} |`);
  }

  return lines.join('\n');
}

async function main(): Promise<void> {
  const flags = parseFlags(process.argv);

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    process.stderr.write('[error] ANTHROPIC_API_KEY env var is required\n');
    process.exit(1);
  }

  const provider = new AnthropicProvider({ apiKey });

  const config: BenchmarkConfig = {
    benchmarkDir: flags.benchmarkDir,
    provider,
    model: flags.model,
    dbPath: flags.dbPath,
    maxParallel: flags.maxParallel,
    timeoutPerChallenge: flags.timeoutPerChallenge,
    onProgress: progress,
  };

  const runner = new XBOWBenchmarkRunner(config);

  process.stderr.write(`[start] XBOW benchmark — model=${flags.model}, parallel=${flags.maxParallel}, timeout=${flags.timeoutPerChallenge}ms\n`);
  if (flags.tags || flags.levels || flags.challengeIds) {
    process.stderr.write(`[filter] tags=${flags.tags?.join(',') ?? 'all'} levels=${flags.levels?.join(',') ?? 'all'} ids=${flags.challengeIds?.length ?? 'all'}\n`);
  }

  await runner.setup();

  const filterOpts: { tags?: string[]; levels?: number[]; challengeIds?: string[] } = {};
  if (flags.tags) filterOpts.tags = flags.tags;
  if (flags.levels) filterOpts.levels = flags.levels;
  if (flags.challengeIds) filterOpts.challengeIds = flags.challengeIds;

  const result = await runner.runBenchmark(
    Object.keys(filterOpts).length > 0 ? filterOpts : undefined,
  );

  process.stderr.write(`\n[done] ${result.solved}/${result.totalChallenges} solved (${result.scorePercent}%) cost=$${result.totalCostUsd.toFixed(2)}\n\n`);
  process.stdout.write(renderMarkdown(result) + '\n');
}

main().catch(err => {
  process.stderr.write(`[fatal] ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});

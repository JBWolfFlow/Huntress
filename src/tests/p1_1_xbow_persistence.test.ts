/**
 * P1-1 v7 — Per-challenge incremental SQLite persistence
 *
 * Bug observed 2026-05-02: user killed the benchmark mid-run at 39/104.
 * The aggregate `benchmark_runs` row only writes when `runBenchmark()`
 * finishes successfully, so a kill loses ALL completed-challenge data.
 *
 * Fix: new `benchmark_results` table + per-challenge write inside the
 * dispatch loop, so a kill preserves N rows of analyzable data.
 *
 * SQLite is wired through Rust (knowledgeDbExecute via tauri_bridge),
 * not directly accessible from Node. These tests mock the bridge and
 * verify the SQL statement shape + parameter binding the runner emits.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the tauri_bridge BEFORE importing xbow_runner so the module's import
// of knowledgeDbExecute resolves to our spy.
const knowledgeDbExecuteSpy = vi.fn(() => Promise.resolve(undefined));
const knowledgeDbQuerySpy = vi.fn(() => Promise.resolve({ rows: [] }));
const executeCommandSpy = vi.fn(() => Promise.resolve({ success: true, stdout: '', stderr: '', exitCode: 0 }));

vi.mock('../core/tauri_bridge', () => ({
  knowledgeDbExecute: (...args: unknown[]) => knowledgeDbExecuteSpy(...args as [string, string, unknown[]?]),
  knowledgeDbQuery: (...args: unknown[]) => knowledgeDbQuerySpy(...args as [string, string, unknown[]?]),
  executeCommand: (...args: unknown[]) => executeCommandSpy(...args as [string, string[], string?]),
  fs: { access: vi.fn(), readdir: vi.fn(() => Promise.resolve([])), readFile: vi.fn() },
  path: { join: (...p: string[]) => p.join('/'), basename: (p: string) => p.split('/').pop() ?? p, dirname: (p: string) => p.split('/').slice(0, -1).join('/') },
}));

// Now safe to import the runner
import { XBOWBenchmarkRunner, type BenchmarkConfig } from '../core/benchmark/xbow_runner';

beforeEach(() => {
  knowledgeDbExecuteSpy.mockClear();
  knowledgeDbQuerySpy.mockClear();
  executeCommandSpy.mockClear();
});

function makeConfig(overrides: Partial<BenchmarkConfig> = {}): BenchmarkConfig {
  return {
    benchmarkDir: '/tmp/test-bench',
    provider: { sendMessage: vi.fn(), streamMessage: vi.fn(), getAvailableModels: () => [], validateApiKey: () => Promise.resolve(true), estimateCost: () => 0, providerId: 'test', displayName: 'Test', supportsToolUse: true } as unknown as BenchmarkConfig['provider'],
    model: 'claude-opus-4-7',
    dbPath: '/tmp/test.db',
    ...overrides,
  };
}

describe('XBOWBenchmarkRunner.initDatabase — schema invariants', () => {
  it('creates the benchmark_runs table', async () => {
    const runner = new XBOWBenchmarkRunner(makeConfig());
    await runner.setup();

    const calls = knowledgeDbExecuteSpy.mock.calls.map(c => c[1] as string);
    const createRuns = calls.find(sql => sql.includes('CREATE TABLE IF NOT EXISTS benchmark_runs'));
    expect(createRuns).toBeDefined();
  });

  it('creates the NEW benchmark_results table for per-challenge persistence', async () => {
    const runner = new XBOWBenchmarkRunner(makeConfig());
    await runner.setup();

    const calls = knowledgeDbExecuteSpy.mock.calls.map(c => c[1] as string);
    const createResults = calls.find(sql => sql.includes('CREATE TABLE IF NOT EXISTS benchmark_results'));
    expect(createResults).toBeDefined();
    // Required columns
    expect(createResults).toContain('run_id TEXT NOT NULL');
    expect(createResults).toContain('challenge_id TEXT NOT NULL');
    expect(createResults).toContain('solved INTEGER NOT NULL');
    expect(createResults).toContain('expected_flag TEXT NOT NULL');
    expect(createResults).toContain('iterations INTEGER NOT NULL');
    expect(createResults).toContain('cost_usd REAL NOT NULL');
    expect(createResults).toContain('PRIMARY KEY (run_id, challenge_id)');
  });

  it('creates the run_id index for mid-run query performance', async () => {
    const runner = new XBOWBenchmarkRunner(makeConfig());
    await runner.setup();

    const calls = knowledgeDbExecuteSpy.mock.calls.map(c => c[1] as string);
    const idx = calls.find(sql => sql.includes('idx_benchmark_results_run'));
    expect(idx).toBeDefined();
    expect(idx).toContain('CREATE INDEX');
    expect(idx).toContain('benchmark_results(run_id)');
  });
});

describe('XBOWBenchmarkRunner.persistChallengeResult — INSERT shape', () => {
  // We exercise the private method by name. Type-cast and call directly.
  it('emits INSERT OR REPLACE so re-running a challenge is idempotent', async () => {
    const runner = new XBOWBenchmarkRunner(makeConfig());
    type Internal = { persistChallengeResult: (runId: string, r: unknown) => Promise<void> };
    await (runner as unknown as Internal).persistChallengeResult('run-x', {
      challengeId: 'XBEN-001-24',
      solved: true,
      flag: 'FLAG{abc}',
      expectedFlag: 'FLAG{abc}',
      iterations: 10,
      durationMs: 5000,
      costUsd: 0.05,
      tokensUsed: 5000,
      error: undefined,
    });

    expect(knowledgeDbExecuteSpy).toHaveBeenCalled();
    const insertCall = knowledgeDbExecuteSpy.mock.calls.find(c => (c[1] as string).includes('INSERT OR REPLACE INTO benchmark_results'));
    expect(insertCall).toBeDefined();
  });

  it('binds all fields (run_id, challenge_id, solved=1 for true, flag, etc.)', async () => {
    const runner = new XBOWBenchmarkRunner(makeConfig());
    type Internal = { persistChallengeResult: (runId: string, r: unknown) => Promise<void> };
    await (runner as unknown as Internal).persistChallengeResult('run-x', {
      challengeId: 'XBEN-001-24',
      solved: true,
      flag: 'FLAG{abc}',
      expectedFlag: 'FLAG{abc}',
      iterations: 10,
      durationMs: 5000,
      costUsd: 0.05,
      tokensUsed: 5000,
      error: undefined,
    });

    const insertCall = knowledgeDbExecuteSpy.mock.calls.find(c => (c[1] as string).includes('INSERT OR REPLACE INTO benchmark_results'));
    const args = insertCall![2] as string[];
    expect(args[0]).toBe('run-x');
    expect(args[1]).toBe('XBEN-001-24');
    // args[2] is timestamp ISO — validate shape only
    expect(args[2]).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(args[3]).toBe('1'); // solved=true
    expect(args[4]).toBe('FLAG{abc}');
    expect(args[5]).toBe('FLAG{abc}');
    expect(args[6]).toBe('10');
    expect(args[10]).toBe(''); // error undefined → empty string
  });

  it('handles failure case (solved=false, error string)', async () => {
    const runner = new XBOWBenchmarkRunner(makeConfig());
    type Internal = { persistChallengeResult: (runId: string, r: unknown) => Promise<void> };
    await (runner as unknown as Internal).persistChallengeResult('run-x', {
      challengeId: 'XBEN-039-24',
      solved: false,
      flag: undefined,
      expectedFlag: 'FLAG{xyz}',
      iterations: 0,
      durationMs: 180000,
      costUsd: 0,
      tokensUsed: 0,
      error: 'Challenge port 32872 did not accept connections within 240s',
    });

    const insertCall = knowledgeDbExecuteSpy.mock.calls.find(c => (c[1] as string).includes('INSERT OR REPLACE INTO benchmark_results'));
    const args = insertCall![2] as string[];
    expect(args[3]).toBe('0'); // solved=false
    expect(args[4]).toBe(''); // flag undefined → empty
    expect(args[10]).toContain('did not accept connections');
  });

  it('persistence failure does NOT crash — silently logs and continues', async () => {
    knowledgeDbExecuteSpy.mockImplementationOnce(() => Promise.resolve(undefined)); // initDatabase #1
    knowledgeDbExecuteSpy.mockImplementationOnce(() => Promise.resolve(undefined)); // initDatabase #2 (results table)
    knowledgeDbExecuteSpy.mockImplementationOnce(() => Promise.resolve(undefined)); // initDatabase #3 (index)
    knowledgeDbExecuteSpy.mockRejectedValueOnce(new Error('disk full'));

    const runner = new XBOWBenchmarkRunner(makeConfig());
    type Internal = { persistChallengeResult: (runId: string, r: unknown) => Promise<void> };

    // Must NOT throw
    await expect((runner as unknown as Internal).persistChallengeResult('run-x', {
      challengeId: 'XBEN-001-24',
      solved: true,
      flag: 'FLAG{x}',
      expectedFlag: 'FLAG{x}',
      iterations: 5,
      durationMs: 3000,
      costUsd: 0.03,
      tokensUsed: 3000,
    })).resolves.toBeUndefined();
  });
});

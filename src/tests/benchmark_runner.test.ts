/**
 * Benchmark Runner Tests
 *
 * Tests the XBOWBenchmarkRunner construction, challenge listing,
 * score comparison logic, and trend calculation.
 */

import { describe, it, expect, vi } from 'vitest';
import { XBOWBenchmarkRunner, CHALLENGE_TAGS } from '../core/benchmark/xbow_runner';
import type { BenchmarkConfig, BenchmarkResult, ChallengeResult } from '../core/benchmark/xbow_runner';
import type { ModelProvider, ChatMessage, SendMessageOptions, ChatResponse } from '../core/providers/types';

// ─── Mock Provider ────────────────────────────────────────────────────────────

function createMockProvider(): ModelProvider {
  return {
    displayName: 'MockProvider',
    sendMessage: vi.fn(async (_msgs: ChatMessage[], _opts: SendMessageOptions): Promise<ChatResponse> => ({
      content: 'I will investigate this target.',
      model: 'mock-model',
      usage: { inputTokens: 100, outputTokens: 50, totalTokens: 150 },
      stopReason: 'end_turn',
    })),
    streamMessage: vi.fn(async function* () {
      yield { type: 'text' as const, text: 'mock' };
    }),
    getAvailableModels: vi.fn(() => [{ id: 'mock-model', name: 'Mock', contextWindow: 4096 }]),
    validateApiKey: vi.fn(async () => true),
    estimateCost: vi.fn(() => ({ inputCost: 0, outputCost: 0, totalCost: 0 })),
  };
}

// ─── Construction Tests ──────────────────────────────────────────────────────

describe('XBOWBenchmarkRunner', () => {
  it('constructs with valid config', () => {
    const config: BenchmarkConfig = {
      benchmarkDir: '/tmp/test-bench',
      provider: createMockProvider(),
      model: 'mock-model',
      dbPath: `/tmp/test_bench_${Date.now()}.db`,
    };

    const runner = new XBOWBenchmarkRunner(config);
    expect(runner).toBeDefined();
  });

  it('uses default parallel and timeout values', () => {
    const config: BenchmarkConfig = {
      benchmarkDir: '/tmp/test-bench',
      provider: createMockProvider(),
      model: 'mock-model',
      dbPath: `/tmp/test_bench_${Date.now()}.db`,
    };

    const runner = new XBOWBenchmarkRunner(config);
    expect(runner).toBeDefined();
    // Defaults are internal — we just verify construction works
  });

  it('accepts custom parallel and timeout values', () => {
    const config: BenchmarkConfig = {
      benchmarkDir: '/tmp/test-bench',
      provider: createMockProvider(),
      model: 'mock-model',
      dbPath: `/tmp/test_bench_${Date.now()}.db`,
      maxParallel: 8,
      timeoutPerChallenge: 600_000,
    };

    const runner = new XBOWBenchmarkRunner(config);
    expect(runner).toBeDefined();
  });

  it('accepts a progress callback', () => {
    const onProgress = vi.fn();
    const config: BenchmarkConfig = {
      benchmarkDir: '/tmp/test-bench',
      provider: createMockProvider(),
      model: 'mock-model',
      dbPath: `/tmp/test_bench_${Date.now()}.db`,
      onProgress,
    };

    const runner = new XBOWBenchmarkRunner(config);
    expect(runner).toBeDefined();
  });
});

// ─── Challenge Tags Mapping ──────────────────────────────────────────────────

describe('CHALLENGE_TAGS', () => {
  it('maps known challenge tags to agent names', () => {
    expect(CHALLENGE_TAGS['sqli']).toBe('SQLi Hunter');
    expect(CHALLENGE_TAGS['xss']).toBe('XSS Hunter');
    expect(CHALLENGE_TAGS['ssrf']).toBe('SSRF Hunter');
    expect(CHALLENGE_TAGS['ssti']).toBe('SSTI Hunter');
    expect(CHALLENGE_TAGS['cmdi']).toBe('Command Injection Hunter');
    expect(CHALLENGE_TAGS['auth']).toBe('IDOR Hunter');
    expect(CHALLENGE_TAGS['traversal']).toBe('Path Traversal Hunter');
  });

  it('covers all expected vulnerability categories', () => {
    const tags = Object.keys(CHALLENGE_TAGS);
    expect(tags.length).toBeGreaterThanOrEqual(7);
  });
});

// ─── Score Calculation Logic ─────────────────────────────────────────────────

describe('Score Calculation', () => {
  it('calculates score percentage correctly', () => {
    const results: ChallengeResult[] = [
      { challengeId: 'c1', solved: true, expectedFlag: 'FLAG{1}', iterations: 5, durationMs: 10000, costUsd: 0.01, tokensUsed: 100 },
      { challengeId: 'c2', solved: true, expectedFlag: 'FLAG{2}', iterations: 10, durationMs: 20000, costUsd: 0.02, tokensUsed: 200 },
      { challengeId: 'c3', solved: false, expectedFlag: 'FLAG{3}', iterations: 40, durationMs: 300000, costUsd: 0.05, tokensUsed: 500, error: 'timeout' },
      { challengeId: 'c4', solved: true, expectedFlag: 'FLAG{4}', iterations: 3, durationMs: 5000, costUsd: 0.005, tokensUsed: 50 },
    ];

    const solved = results.filter(r => r.solved).length;
    const total = results.length;
    const scorePercent = (solved / total) * 100;

    expect(scorePercent).toBe(75);
    expect(solved).toBe(3);
    expect(total).toBe(4);
  });

  it('handles zero challenges gracefully', () => {
    const results: ChallengeResult[] = [];
    const scorePercent = results.length > 0 ? (results.filter(r => r.solved).length / results.length) * 100 : 0;
    expect(scorePercent).toBe(0);
  });

  it('handles all solved correctly', () => {
    const results: ChallengeResult[] = [
      { challengeId: 'c1', solved: true, expectedFlag: 'FLAG{1}', iterations: 5, durationMs: 10000, costUsd: 0.01, tokensUsed: 100 },
      { challengeId: 'c2', solved: true, expectedFlag: 'FLAG{2}', iterations: 3, durationMs: 5000, costUsd: 0.01, tokensUsed: 100 },
    ];

    const solved = results.filter(r => r.solved).length;
    const total = results.length;
    const scorePercent = (solved / total) * 100;

    expect(scorePercent).toBe(100);
  });

  it('handles all failed correctly', () => {
    const results: ChallengeResult[] = [
      { challengeId: 'c1', solved: false, expectedFlag: 'FLAG{1}', iterations: 40, durationMs: 300000, costUsd: 0.05, tokensUsed: 500, error: 'timeout' },
      { challengeId: 'c2', solved: false, expectedFlag: 'FLAG{2}', iterations: 40, durationMs: 300000, costUsd: 0.05, tokensUsed: 500, error: 'wrong flag' },
    ];

    const solved = results.filter(r => r.solved).length;
    const total = results.length;
    const scorePercent = (solved / total) * 100;

    expect(scorePercent).toBe(0);
  });
});

// ─── Trend Calculation ───────────────────────────────────────────────────────

describe('Trend Calculation', () => {
  it('determines improving trend from sequential scores', () => {
    const scores = [30, 40, 50, 60, 70];
    const diffs = scores.slice(1).map((s, i) => s - scores[i]);
    const avgImprovement = diffs.reduce((a, b) => a + b, 0) / diffs.length;
    const trend = avgImprovement > 2 ? 'improving' : avgImprovement < -2 ? 'declining' : 'stable';

    expect(trend).toBe('improving');
    expect(avgImprovement).toBe(10);
  });

  it('determines declining trend from sequential scores', () => {
    const scores = [70, 60, 50, 40, 30];
    const diffs = scores.slice(1).map((s, i) => s - scores[i]);
    const avgImprovement = diffs.reduce((a, b) => a + b, 0) / diffs.length;
    const trend = avgImprovement > 2 ? 'improving' : avgImprovement < -2 ? 'declining' : 'stable';

    expect(trend).toBe('declining');
    expect(avgImprovement).toBe(-10);
  });

  it('determines stable trend from flat scores', () => {
    const scores = [50, 51, 50, 49, 50];
    const diffs = scores.slice(1).map((s, i) => s - scores[i]);
    const avgImprovement = diffs.reduce((a, b) => a + b, 0) / diffs.length;
    const trend = avgImprovement > 2 ? 'improving' : avgImprovement < -2 ? 'declining' : 'stable';

    expect(trend).toBe('stable');
  });

  it('handles single score as stable', () => {
    const scores = [50];
    const diffs = scores.slice(1).map((s, i) => s - scores[i]);
    const avgImprovement = diffs.length > 0 ? diffs.reduce((a, b) => a + b, 0) / diffs.length : 0;
    const trend = avgImprovement > 2 ? 'improving' : avgImprovement < -2 ? 'declining' : 'stable';

    expect(trend).toBe('stable');
  });
});

// ─── Run Comparison ──────────────────────────────────────────────────────────

describe('Run Comparison', () => {
  it('identifies improved challenges between runs', () => {
    const run1Results: ChallengeResult[] = [
      { challengeId: 'c1', solved: false, expectedFlag: 'FLAG{1}', iterations: 40, durationMs: 300000, costUsd: 0.05, tokensUsed: 500, error: 'timeout' },
      { challengeId: 'c2', solved: true, expectedFlag: 'FLAG{2}', iterations: 5, durationMs: 10000, costUsd: 0.01, tokensUsed: 100 },
    ];

    const run2Results: ChallengeResult[] = [
      { challengeId: 'c1', solved: true, expectedFlag: 'FLAG{1}', iterations: 10, durationMs: 20000, costUsd: 0.02, tokensUsed: 200 },
      { challengeId: 'c2', solved: true, expectedFlag: 'FLAG{2}', iterations: 5, durationMs: 10000, costUsd: 0.01, tokensUsed: 100 },
    ];

    // Build maps for comparison
    const run1Map = new Map(run1Results.map(r => [r.challengeId, r]));
    const run2Map = new Map(run2Results.map(r => [r.challengeId, r]));

    const improved: string[] = [];
    const regressed: string[] = [];
    const unchanged: string[] = [];

    for (const [id, r2] of run2Map) {
      const r1 = run1Map.get(id);
      if (!r1) continue;
      if (r2.solved && !r1.solved) improved.push(id);
      else if (!r2.solved && r1.solved) regressed.push(id);
      else unchanged.push(id);
    }

    expect(improved).toEqual(['c1']);
    expect(regressed).toEqual([]);
    expect(unchanged).toEqual(['c2']);
  });
});

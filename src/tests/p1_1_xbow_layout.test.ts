/**
 * P1-1 XBOW listChallenges layout regression tests
 *
 * The first benchmark run on 2026-05-02 returned 0/0 solved in 0s
 * because XBOWBenchmarkRunner.listChallenges() scanned the wrong path:
 *   - Real XBOW layout: <repo>/benchmarks/<id>/benchmark.json
 *   - Runner expected: <repo>/<id>/benchmark-config.json
 *
 * These tests pin the discovery contract against a fake filesystem that
 * mirrors the real XBOW shape so a future repo restructure or filename
 * change surfaces here, not in a 2-hour benchmark run that returns 0%.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  XBOWBenchmarkRunner,
  type BenchmarkConfig,
} from '../core/benchmark/xbow_runner';
import type { ModelProvider } from '../core/providers/types';

// ─── Fake filesystem fixtures ───────────────────────────────────────────────

let testDir: string;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), 'huntress-xbow-test-'));
});

afterEach(() => {
  if (existsSync(testDir)) rmSync(testDir, { recursive: true, force: true });
});

/** Build a real XBOW-shaped tree on disk: <root>/benchmarks/<id>/benchmark.json */
function makeRealXbowLayout(root: string, challenges: Array<{
  id: string;
  config: Record<string, unknown>;
}>): void {
  mkdirSync(join(root, 'benchmarks'), { recursive: true });
  for (const ch of challenges) {
    const dir = join(root, 'benchmarks', ch.id);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'benchmark.json'), JSON.stringify(ch.config));
  }
}

/** Build a flat (legacy) layout: <root>/<id>/benchmark-config.json */
function makeLegacyLayout(root: string, challenges: Array<{
  id: string;
  config: Record<string, unknown>;
}>): void {
  for (const ch of challenges) {
    const dir = join(root, ch.id);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'benchmark-config.json'), JSON.stringify(ch.config));
  }
}

/** Build a runner that points at testDir, with a no-op provider — listChallenges
 * is pure filesystem so the provider isn't called. */
function makeRunner(extraConfig: Partial<BenchmarkConfig> = {}): XBOWBenchmarkRunner {
  const provider: ModelProvider = {
    providerId: 'test',
    displayName: 'Test',
    supportsToolUse: true,
    sendMessage: async () => ({ content: '', toolCalls: [], stopReason: 'end_turn', inputTokens: 0, outputTokens: 0 }),
    sendMessageStream: vi.fn(),
    getProviderInfo: () => ({ id: 'test', name: 'Test', supportsToolUse: true, supportsStreaming: false }),
    getAvailableModels: () => [],
    testConnection: async () => true,
  };

  return new XBOWBenchmarkRunner({
    benchmarkDir: testDir,
    provider,
    model: 'test',
    dbPath: ':memory:',
    ...extraConfig,
  });
}

// ─── Real XBOW layout (the actual repo at github.com/xbow-engineering/validation-benchmarks) ──

describe('P1-1 · listChallenges with real XBOW layout (regression for 0/0 bug)', () => {
  it('discovers challenges under <root>/benchmarks/<id>/benchmark.json', async () => {
    makeRealXbowLayout(testDir, [
      {
        id: 'XBEN-001-24',
        config: {
          name: 'XBEN-001-24 IDOR — Trading Platform',
          description: 'IDOR test',
          level: '2',
          tags: ['idor'],
          win_condition: 'flag',
        },
      },
      {
        id: 'XBEN-002-24',
        config: {
          name: 'XBEN-002-24 SQLi',
          level: '1',
          tags: ['sqli'],
          win_condition: 'flag',
        },
      },
    ]);

    const challenges = await makeRunner().listChallenges();
    expect(challenges).toHaveLength(2);
    const ids = challenges.map(c => c.id);
    expect(ids).toContain('XBEN-001-24');
    expect(ids).toContain('XBEN-002-24');
  });

  it('coerces string level "2" to numeric level 2', async () => {
    makeRealXbowLayout(testDir, [
      { id: 'XBEN-001-24', config: { name: 'a', level: '2', tags: [], win_condition: 'flag' } },
    ]);
    const [c] = await makeRunner().listChallenges();
    expect(c.level).toBe(2);
    expect(typeof c.level).toBe('number');
  });

  it('accepts numeric level (back-compat with custom configs)', async () => {
    makeRealXbowLayout(testDir, [
      { id: 'XBEN-001-24', config: { name: 'a', level: 3, tags: [], win_condition: 'flag' } },
    ]);
    const [c] = await makeRunner().listChallenges();
    expect(c.level).toBe(3);
  });

  it('defaults level to 1 when missing or unparseable', async () => {
    makeRealXbowLayout(testDir, [
      { id: 'A', config: { name: 'a', tags: [], win_condition: 'flag' } },
      { id: 'B', config: { name: 'b', level: 'not-a-number', tags: [], win_condition: 'flag' } },
    ]);
    const challenges = await makeRunner().listChallenges();
    expect(challenges.find(c => c.id === 'A')!.level).toBe(1);
    expect(challenges.find(c => c.id === 'B')!.level).toBe(1);
  });

  it('challenge.directory points at the actual challenge folder (so docker compose finds compose file)', async () => {
    makeRealXbowLayout(testDir, [
      { id: 'XBEN-001-24', config: { name: 'a', level: '1', tags: [], win_condition: 'flag' } },
    ]);
    const [c] = await makeRunner().listChallenges();
    expect(c.directory).toBe(join(testDir, 'benchmarks', 'XBEN-001-24'));
  });

  it('falls back to entry name when id field is absent in config', async () => {
    // The real XBOW configs don't include an `id` field — directory name is the id
    makeRealXbowLayout(testDir, [
      { id: 'XBEN-001-24', config: { name: 'X', level: '1', tags: [], win_condition: 'flag' } },
    ]);
    const [c] = await makeRunner().listChallenges();
    expect(c.id).toBe('XBEN-001-24');
  });

  it('skips entries that do not contain a benchmark.json', async () => {
    makeRealXbowLayout(testDir, [
      { id: 'XBEN-001-24', config: { name: 'a', level: '1', tags: [], win_condition: 'flag' } },
    ]);
    // Add a stray file + a directory without benchmark.json — both should be skipped
    writeFileSync(join(testDir, 'benchmarks', 'README.md'), '# notes');
    mkdirSync(join(testDir, 'benchmarks', 'common'), { recursive: true });
    writeFileSync(join(testDir, 'benchmarks', 'common', 'helper.sh'), '#!/bin/sh');

    const challenges = await makeRunner().listChallenges();
    expect(challenges).toHaveLength(1);
    expect(challenges[0].id).toBe('XBEN-001-24');
  });

  it('sorts by level ascending, then by name', async () => {
    makeRealXbowLayout(testDir, [
      { id: 'C-easy-2', config: { name: 'C-easy-2', level: '1', tags: [], win_condition: 'flag' } },
      { id: 'A-hard',  config: { name: 'A-hard',  level: '3', tags: [], win_condition: 'flag' } },
      { id: 'B-easy-1', config: { name: 'B-easy-1', level: '1', tags: [], win_condition: 'flag' } },
      { id: 'D-med',   config: { name: 'D-med',   level: '2', tags: [], win_condition: 'flag' } },
    ]);

    const ordered = (await makeRunner().listChallenges()).map(c => c.id);
    expect(ordered).toEqual(['B-easy-1', 'C-easy-2', 'D-med', 'A-hard']);
  });
});

// ─── Legacy / flat layout (back-compat) ─────────────────────────────────────

describe('P1-1 · listChallenges back-compat with legacy flat layout', () => {
  it('discovers challenges under <root>/<id>/benchmark-config.json when no benchmarks/ subdir exists', async () => {
    makeLegacyLayout(testDir, [
      { id: 'legacy-1', config: { name: 'legacy 1', level: 2, tags: ['xss'], win_condition: 'flag' } },
      { id: 'legacy-2', config: { name: 'legacy 2', level: 1, tags: ['sqli'], win_condition: 'flag' } },
    ]);
    const challenges = await makeRunner().listChallenges();
    expect(challenges).toHaveLength(2);
    expect(challenges.map(c => c.id).sort()).toEqual(['legacy-1', 'legacy-2']);
  });

  it('legacy layout points directories at the entry under benchmarkDir directly', async () => {
    makeLegacyLayout(testDir, [
      { id: 'legacy-1', config: { name: 'l1', level: 1, tags: [], win_condition: 'flag' } },
    ]);
    const [c] = await makeRunner().listChallenges();
    expect(c.directory).toBe(join(testDir, 'legacy-1'));
  });
});

// ─── Empty / error cases ────────────────────────────────────────────────────

describe('P1-1 · listChallenges error handling', () => {
  it('returns [] when benchmark dir is empty', async () => {
    const challenges = await makeRunner().listChallenges();
    expect(challenges).toEqual([]);
  });

  it('returns [] when benchmarks/ subdir exists but is empty', async () => {
    mkdirSync(join(testDir, 'benchmarks'), { recursive: true });
    const challenges = await makeRunner().listChallenges();
    expect(challenges).toEqual([]);
  });

  it('skips challenges whose benchmark.json is malformed JSON', async () => {
    mkdirSync(join(testDir, 'benchmarks'), { recursive: true });
    const goodDir = join(testDir, 'benchmarks', 'good');
    const badDir = join(testDir, 'benchmarks', 'bad');
    mkdirSync(goodDir, { recursive: true });
    mkdirSync(badDir, { recursive: true });
    writeFileSync(join(goodDir, 'benchmark.json'), JSON.stringify({ name: 'ok', level: '1', tags: [], win_condition: 'flag' }));
    writeFileSync(join(badDir, 'benchmark.json'), '{ this is not json');

    const challenges = await makeRunner().listChallenges();
    expect(challenges).toHaveLength(1);
    expect(challenges[0].id).toBe('good');
  });

  it('prefers benchmark.json over benchmark-config.json when both exist', async () => {
    mkdirSync(join(testDir, 'benchmarks', 'both'), { recursive: true });
    writeFileSync(join(testDir, 'benchmarks', 'both', 'benchmark.json'),
      JSON.stringify({ name: 'modern', level: '1', tags: [], win_condition: 'flag' }));
    writeFileSync(join(testDir, 'benchmarks', 'both', 'benchmark-config.json'),
      JSON.stringify({ name: 'legacy', level: '1', tags: [], win_condition: 'flag' }));

    const [c] = await makeRunner().listChallenges();
    expect(c.name).toBe('modern');
  });
});

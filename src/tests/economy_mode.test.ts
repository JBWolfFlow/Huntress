/**
 * Economy Mode (P1-0-b, 2026-04-23)
 *
 * Covers the cohesive economy-mode config module and its resolver. The
 * orchestrator-side wiring — `maxSpecialistsPerRecon` actually capping the
 * dispatch fan-out, yield-rank ordering selecting the top-N specialists —
 * is exercised separately in `economy_mode_dispatch.test.ts` so this file
 * stays a fast pure-logic unit suite.
 */
import { describe, it, expect } from 'vitest';
import {
  ECONOMY_MODE_OFF,
  ECONOMY_MODE_ON,
  resolveEconomyMode,
  selectSolverAgents,
  specialistYieldRank,
  SPECIALIST_YIELD_RANK,
} from '../core/orchestrator/economy_mode';

// Minimal fake catalog entry for selectSolverAgents tests.
const agent = (id: string) => ({ metadata: { id } });

describe('resolveEconomyMode', () => {
  it('returns the off config when enabled=false (historical defaults preserved)', () => {
    const cfg = resolveEconomyMode(false);
    expect(cfg.enabled).toBe(false);
    expect(cfg.maxConcurrentAgents).toBe(5);
    expect(cfg.maxSpecialistsPerRecon).toBe(Infinity);
    expect(cfg.maxAgentCostFraction).toBe(0.2);
  });

  it('returns the on config when enabled=true (compliant real-program defaults)', () => {
    const cfg = resolveEconomyMode(true);
    expect(cfg.enabled).toBe(true);
    expect(cfg.maxConcurrentAgents).toBe(2);
    expect(cfg.maxSpecialistsPerRecon).toBe(3);
    expect(cfg.maxAgentCostFraction).toBe(0.5);
  });

  it('returns referentially-equal frozen objects (callers must not mutate)', () => {
    expect(resolveEconomyMode(false)).toBe(ECONOMY_MODE_OFF);
    expect(resolveEconomyMode(true)).toBe(ECONOMY_MODE_ON);
    expect(Object.isFrozen(ECONOMY_MODE_OFF)).toBe(true);
    expect(Object.isFrozen(ECONOMY_MODE_ON)).toBe(true);
  });

  it('off config keeps specialist fan-out unlimited', () => {
    // Number.isFinite is the gate in orchestrator_engine; must be false.
    expect(Number.isFinite(ECONOMY_MODE_OFF.maxSpecialistsPerRecon)).toBe(false);
  });

  it('on config keeps specialist fan-out finite', () => {
    expect(Number.isFinite(ECONOMY_MODE_ON.maxSpecialistsPerRecon)).toBe(true);
  });
});

describe('specialistYieldRank', () => {
  it('ranks sqli/xss/idor as top three (the 2026-04-23 Juice Shop winners)', () => {
    const top3 = [...Object.entries(SPECIALIST_YIELD_RANK)]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([id]) => id);
    expect(top3).toEqual(['sqli-hunter', 'xss-hunter', 'idor-hunter']);
  });

  it('returns rank 0 for unknown agent ids (they run last in capped mode)', () => {
    expect(specialistYieldRank('some-unknown-agent')).toBe(0);
    expect(specialistYieldRank('')).toBe(0);
  });

  it('returns the mapped rank for known agents', () => {
    expect(specialistYieldRank('sqli-hunter')).toBe(100);
    expect(specialistYieldRank('xss-hunter')).toBe(95);
    expect(specialistYieldRank('idor-hunter')).toBe(90);
  });

  it('ranks specialist IDs as integers — comparator stable', () => {
    const ranks = Object.values(SPECIALIST_YIELD_RANK);
    expect(ranks.every(r => Number.isInteger(r) && r > 0)).toBe(true);
  });

  it('is internally consistent — higher-ranked agents sort earlier', () => {
    const ids = ['ssrf-hunter', 'sqli-hunter', 'cors-hunter', 'xss-hunter'];
    const sorted = [...ids].sort((a, b) => specialistYieldRank(b) - specialistYieldRank(a));
    expect(sorted).toEqual(['sqli-hunter', 'xss-hunter', 'ssrf-hunter', 'cors-hunter']);
  });
});

describe('ECONOMY_MODE_OFF / ECONOMY_MODE_ON invariants', () => {
  it('on mode is strictly more conservative than off on every axis', () => {
    expect(ECONOMY_MODE_ON.maxConcurrentAgents).toBeLessThan(ECONOMY_MODE_OFF.maxConcurrentAgents);
    expect(ECONOMY_MODE_ON.maxSpecialistsPerRecon).toBeLessThan(ECONOMY_MODE_OFF.maxSpecialistsPerRecon);
    // Per-agent budget fraction is *larger* in economy mode — with fewer
    // agents, each gets more of the pie so hunts still complete.
    expect(ECONOMY_MODE_ON.maxAgentCostFraction).toBeGreaterThan(ECONOMY_MODE_OFF.maxAgentCostFraction);
  });

  it('both configs have valid budget fractions (0 < x ≤ 1)', () => {
    for (const cfg of [ECONOMY_MODE_OFF, ECONOMY_MODE_ON]) {
      expect(cfg.maxAgentCostFraction).toBeGreaterThan(0);
      expect(cfg.maxAgentCostFraction).toBeLessThanOrEqual(1);
    }
  });
});

describe('selectSolverAgents — economy-mode dispatch selection', () => {
  const allAgents = [
    agent('recon'),
    agent('cors-hunter'),       // rank 45
    agent('sqli-hunter'),       // rank 100
    agent('obscure-agent'),     // rank 0 (unknown)
    agent('xss-hunter'),        // rank 95
    agent('idor-hunter'),       // rank 90
    agent('ssti-hunter'),       // rank 85
  ];

  it('drops `recon` itself from the result (recon just completed)', () => {
    const sel = selectSolverAgents(allAgents, new Set(), Infinity);
    expect(sel.map(a => a.metadata.id)).not.toContain('recon');
  });

  it('drops tech-stack-skipped agents', () => {
    const skipped = new Set(['cors-hunter', 'idor-hunter']);
    const sel = selectSolverAgents(allAgents, skipped, Infinity);
    expect(sel.map(a => a.metadata.id)).not.toContain('cors-hunter');
    expect(sel.map(a => a.metadata.id)).not.toContain('idor-hunter');
  });

  it('preserves catalog order when cap is Infinity (non-economy dispatch)', () => {
    const sel = selectSolverAgents(allAgents, new Set(), Infinity);
    expect(sel.map(a => a.metadata.id)).toEqual([
      'cors-hunter', 'sqli-hunter', 'obscure-agent',
      'xss-hunter', 'idor-hunter', 'ssti-hunter',
    ]);
  });

  it('sorts by yield rank when cap is finite (economy dispatch — sqli/xss/idor first)', () => {
    const sel = selectSolverAgents(allAgents, new Set(), 3);
    // Top-3 yield ranks: sqli=100, xss=95, idor=90.
    expect(sel.map(a => a.metadata.id)).toEqual(['sqli-hunter', 'xss-hunter', 'idor-hunter']);
  });

  it('takes the top-N by yield rank — N=2 keeps the two highest', () => {
    const sel = selectSolverAgents(allAgents, new Set(), 2);
    expect(sel.map(a => a.metadata.id)).toEqual(['sqli-hunter', 'xss-hunter']);
  });

  it('applies tech-stack skip before yield-rank sort (skipped agents do not count against cap)', () => {
    const skipped = new Set(['sqli-hunter', 'xss-hunter']); // force top-2 out
    const sel = selectSolverAgents(allAgents, skipped, 3);
    // Remaining ranked: idor=90, ssti=85, cors=45, obscure=0 — take top 3.
    expect(sel.map(a => a.metadata.id)).toEqual(['idor-hunter', 'ssti-hunter', 'cors-hunter']);
  });

  it('returns fewer than N when the filtered pool is smaller than the cap', () => {
    const sel = selectSolverAgents([agent('recon'), agent('sqli-hunter')], new Set(), 5);
    expect(sel.map(a => a.metadata.id)).toEqual(['sqli-hunter']);
  });

  it('returns [] for an empty catalog regardless of cap', () => {
    expect(selectSolverAgents([], new Set(), 5)).toEqual([]);
    expect(selectSolverAgents([], new Set(), Infinity)).toEqual([]);
  });

  it('does not mutate the input catalog array', () => {
    const snapshot = allAgents.map(a => a.metadata.id);
    selectSolverAgents(allAgents, new Set(), 3);
    expect(allAgents.map(a => a.metadata.id)).toEqual(snapshot);
  });
});

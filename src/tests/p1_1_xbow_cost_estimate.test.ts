/**
 * P1-1 estimateCost regression tests
 *
 * The first XBOW smoke test (2026-05-02) reported $0.00 cost despite
 * 23 successful Opus-4-7 iterations. Root cause: the model ID
 * `claude-opus-4-7` was not in `ANTHROPIC_MODELS`, so `estimateCost`
 * returned 0. That silently breaks both the dashboard's cost column
 * and the budget enforcement (90% / 100% caps that depend on real
 * spend tracking — see TracedModelProvider).
 *
 * Fix:
 *   1. Add `claude-opus-4-7` and `claude-sonnet-4-6` to the price table
 *   2. Fall back to Opus-tier rates ($15/$75 per Mtok) when model ID
 *      is unknown — overestimate is safer than underestimate
 *
 * These tests pin both behaviors so a future model addition (Claude 5)
 * doesn't silently break cost tracking again.
 */

import { describe, it, expect } from 'vitest';
import { AnthropicProvider } from '../core/providers/anthropic';

const provider = new AnthropicProvider({ apiKey: 'sk-ant-test-key-for-construction-only' });

describe('AnthropicProvider.estimateCost — known model rates', () => {
  it('claude-opus-4-7 is in the price table (regression for $0 bug)', () => {
    // 1M input + 1M output of Opus = $15 + $75 = $90
    expect(provider.estimateCost(1_000_000, 1_000_000, 'claude-opus-4-7')).toBeCloseTo(90, 4);
  });

  it('claude-opus-4-6 priced at $15/$75 per Mtok', () => {
    expect(provider.estimateCost(1_000_000, 1_000_000, 'claude-opus-4-6')).toBeCloseTo(90, 4);
  });

  it('claude-sonnet-4-6 priced at $3/$15 per Mtok', () => {
    expect(provider.estimateCost(1_000_000, 1_000_000, 'claude-sonnet-4-6')).toBeCloseTo(18, 4);
  });

  it('claude-sonnet-4-5-20250929 priced at $3/$15 per Mtok', () => {
    expect(provider.estimateCost(1_000_000, 1_000_000, 'claude-sonnet-4-5-20250929')).toBeCloseTo(18, 4);
  });

  it('claude-haiku-4-5-20251001 priced at $0.80/$4 per Mtok', () => {
    expect(provider.estimateCost(1_000_000, 1_000_000, 'claude-haiku-4-5-20251001')).toBeCloseTo(4.80, 4);
  });

  it('zero tokens returns zero cost regardless of model', () => {
    expect(provider.estimateCost(0, 0, 'claude-opus-4-7')).toBe(0);
    expect(provider.estimateCost(0, 0, 'claude-sonnet-4-6')).toBe(0);
  });

  it('partial-Mtok inputs scale linearly', () => {
    // 100K input + 50K output of Sonnet = 0.1*$3 + 0.05*$15 = $0.30 + $0.75 = $1.05
    expect(provider.estimateCost(100_000, 50_000, 'claude-sonnet-4-6')).toBeCloseTo(1.05, 4);
  });
});

describe('AnthropicProvider.estimateCost — unknown model fallback', () => {
  it('falls back to Opus-tier rates for unknown model IDs (not $0)', () => {
    // Future model — should NOT silently report $0
    const cost = provider.estimateCost(1_000_000, 1_000_000, 'claude-opus-5-totally-fictional');
    expect(cost).toBeGreaterThan(0);
    expect(cost).toBeCloseTo(90, 4); // Opus-tier defaults: $15 + $75
  });

  it('typo in model ID still produces a meaningful cost estimate', () => {
    // Common typo: missing dash, wrong version, etc.
    expect(provider.estimateCost(1_000, 1_000, 'claude-opus-47')).toBeGreaterThan(0);
    expect(provider.estimateCost(1_000, 1_000, 'opus-4-7')).toBeGreaterThan(0);
    expect(provider.estimateCost(1_000, 1_000, '')).toBeGreaterThan(0);
  });

  it('overestimates rather than underestimates (safer for budget enforcement)', () => {
    // Default rates are Opus-tier ($15/$75). A real Sonnet/Haiku call wouldn't
    // know to use cheaper rates, so it'd see Opus prices — defensive default.
    const fallback = provider.estimateCost(1_000_000, 1_000_000, 'unknown-model');
    const sonnet = provider.estimateCost(1_000_000, 1_000_000, 'claude-sonnet-4-6');
    const haiku = provider.estimateCost(1_000_000, 1_000_000, 'claude-haiku-4-5-20251001');
    expect(fallback).toBeGreaterThanOrEqual(sonnet);
    expect(fallback).toBeGreaterThanOrEqual(haiku);
  });
});

describe('AnthropicProvider.getAvailableModels — opus-4-7 is exposed', () => {
  it('returns claude-opus-4-7 as a selectable model', () => {
    const models = provider.getAvailableModels();
    const ids = models.map(m => m.id);
    expect(ids).toContain('claude-opus-4-7');
  });

  it('returns claude-sonnet-4-6 as a selectable model', () => {
    const models = provider.getAvailableModels();
    const ids = models.map(m => m.id);
    expect(ids).toContain('claude-sonnet-4-6');
  });

  it('keeps older model IDs available for back-compat', () => {
    const models = provider.getAvailableModels();
    const ids = models.map(m => m.id);
    expect(ids).toContain('claude-opus-4-6');
    expect(ids).toContain('claude-sonnet-4-5-20250929');
    expect(ids).toContain('claude-haiku-4-5-20251001');
  });
});

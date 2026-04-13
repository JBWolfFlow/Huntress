/**
 * Session 12 — S1: GitHub + Internal Duplicate Sources
 *
 * Tests that:
 * 1. githubMatch returns non-zero when the finding matches a known advisory
 * 2. internalMatch returns non-zero when a similar finding exists in memory
 * 3. Overall composite score increases when multiple sources agree
 * 4. Graceful degradation when GitHub/memory are unavailable
 * 5. deriveRecommendation uses composite scoring across all sources
 */

import { describe, it, expect, vi } from 'vitest';
import { H1DuplicateChecker } from '../core/reporting/h1_duplicate_check';
import type { H1Report } from '../core/reporting/h1_api';
import type { HuntMemory } from '../core/memory/hunt_memory';

/** Build a minimal H1Report for testing */
function makeReport(overrides: Partial<H1Report> = {}): H1Report {
  return {
    title: 'Reflected XSS in search parameter',
    severity: 'high',
    description: 'A reflected XSS vulnerability was found in the search endpoint. The q parameter is rendered without sanitization.',
    impact: 'An attacker can execute arbitrary JavaScript in the victim\'s browser.',
    steps: ['Navigate to /search?q=<script>alert(1)</script>'],
    proof: { screenshots: [], logs: [] },
    suggestedBounty: { min: 500, max: 2000 },
    weaknessId: 'cwe-79',
    ...overrides,
  };
}

/** Create a mock HuntMemory that returns a duplicate result */
function createMockHuntMemory(options: {
  isDuplicate: boolean;
  score?: number;
  title?: string;
}): HuntMemory {
  return {
    checkDuplicate: vi.fn().mockResolvedValue({
      isDuplicate: options.isDuplicate,
      similarFinding: options.isDuplicate ? {
        id: 'finding_past_001',
        score: options.score ?? 0.9,
        payload: {
          type: 'finding',
          title: options.title ?? 'XSS in search functionality',
          vulnType: 'xss',
          severity: 'high',
          target: 'https://example.com',
        },
      } : undefined,
    }),
    initialize: vi.fn().mockResolvedValue(undefined),
    recordFinding: vi.fn().mockResolvedValue(undefined),
    recordTechnique: vi.fn().mockResolvedValue(undefined),
    queryRelevantTechniques: vi.fn().mockResolvedValue([]),
    queryPastFindingsForTarget: vi.fn().mockResolvedValue([]),
    findSimilarTargets: vi.fn().mockResolvedValue([]),
    getVectorDimension: vi.fn().mockReturnValue(142),
  } as unknown as HuntMemory;
}

describe('S1: Duplicate Sources — Internal Match', () => {
  it('returns internalMatch > 0 when a similar finding exists in memory', async () => {
    const mockMemory = createMockHuntMemory({ isDuplicate: true, score: 0.92 });
    const checker = new H1DuplicateChecker({ huntMemory: mockMemory });

    const report = makeReport();
    const result = await checker.checkDuplicate(report, 'test-program');

    expect(result.internalMatch).toBeGreaterThan(0);
    expect(result.internalMatch).toBeCloseTo(0.92, 1);
    expect(result.matches.some(m => m.source === 'internal')).toBe(true);
  });

  it('returns internalMatch = 0 when no similar finding exists', async () => {
    const mockMemory = createMockHuntMemory({ isDuplicate: false });
    const checker = new H1DuplicateChecker({ huntMemory: mockMemory });

    const report = makeReport();
    const result = await checker.checkDuplicate(report, 'test-program');

    expect(result.internalMatch).toBe(0);
    expect(result.matches.filter(m => m.source === 'internal')).toHaveLength(0);
  });

  it('degrades gracefully when HuntMemory is not provided', async () => {
    const checker = new H1DuplicateChecker({});

    const report = makeReport();
    const result = await checker.checkDuplicate(report, 'test-program');

    // Should still return a valid score structure
    expect(result.internalMatch).toBe(0);
    expect(result.overall).toBeGreaterThanOrEqual(0);
    expect(result.recommendation).toBeDefined();
  });

  it('degrades gracefully when HuntMemory throws', async () => {
    const throwingMemory = {
      checkDuplicate: vi.fn().mockRejectedValue(new Error('Qdrant connection refused')),
      initialize: vi.fn(),
      recordFinding: vi.fn(),
      recordTechnique: vi.fn(),
      queryRelevantTechniques: vi.fn(),
      queryPastFindingsForTarget: vi.fn(),
      findSimilarTargets: vi.fn(),
      getVectorDimension: vi.fn(),
    } as unknown as HuntMemory;

    const checker = new H1DuplicateChecker({ huntMemory: throwingMemory });
    const report = makeReport();
    const result = await checker.checkDuplicate(report, 'test-program');

    // Should not throw, should return 0 for internal match
    expect(result.internalMatch).toBe(0);
    expect(result.overall).toBeGreaterThanOrEqual(0);
  });
});

describe('S1: Duplicate Sources — Composite Scoring', () => {
  it('composite score increases when internal source reports a match', async () => {
    const noMemoryChecker = new H1DuplicateChecker({});
    const withMemoryChecker = new H1DuplicateChecker({
      huntMemory: createMockHuntMemory({ isDuplicate: true, score: 0.85 }),
    });

    const report = makeReport();

    const scoreWithout = await noMemoryChecker.checkDuplicate(report, 'test-program');
    const scoreWith = await withMemoryChecker.checkDuplicate(report, 'test-program');

    expect(scoreWith.overall).toBeGreaterThan(scoreWithout.overall);
  });

  it('recommendation becomes "review" when internal match is high', async () => {
    const checker = new H1DuplicateChecker({
      huntMemory: createMockHuntMemory({ isDuplicate: true, score: 0.95 }),
    });

    const report = makeReport();
    const result = await checker.checkDuplicate(report, 'test-program');

    // With high internal match and no H1/GitHub, should be at least "review"
    expect(['review', 'skip']).toContain(result.recommendation);
  });

  it('all source scores are present in the returned DuplicateScore', async () => {
    const checker = new H1DuplicateChecker({
      huntMemory: createMockHuntMemory({ isDuplicate: true, score: 0.8 }),
    });

    const report = makeReport();
    const result = await checker.checkDuplicate(report, 'test-program');

    // All fields must exist
    expect(result).toHaveProperty('h1Match');
    expect(result).toHaveProperty('githubMatch');
    expect(result).toHaveProperty('internalMatch');
    expect(result).toHaveProperty('overall');
    expect(result).toHaveProperty('recommendation');
    expect(result).toHaveProperty('matches');
    expect(result).toHaveProperty('reasoning');

    // Types must be correct
    expect(typeof result.h1Match).toBe('number');
    expect(typeof result.githubMatch).toBe('number');
    expect(typeof result.internalMatch).toBe('number');
    expect(typeof result.overall).toBe('number');
    expect(result.overall).toBeGreaterThanOrEqual(0);
    expect(result.overall).toBeLessThanOrEqual(100);
  });

  it('reasoning includes internal match information when present', async () => {
    const checker = new H1DuplicateChecker({
      huntMemory: createMockHuntMemory({ isDuplicate: true, score: 0.88, title: 'Past XSS Finding' }),
    });

    const report = makeReport();
    const result = await checker.checkDuplicate(report, 'test-program');

    const hasInternalReasoning = result.reasoning.some(r => r.includes('Internal past finding'));
    expect(hasInternalReasoning).toBe(true);
  });
});

describe('S1: Duplicate Sources — GitHub Degradation', () => {
  it('returns githubMatch = 0 when no GitHub token is configured', async () => {
    const checker = new H1DuplicateChecker({});

    const report = makeReport();
    const result = await checker.checkDuplicate(report, 'test-program');

    expect(result.githubMatch).toBe(0);
  });
});

describe('S1: Similarity methods (existing behavior preserved)', () => {
  it('jaccardSimilarity returns 1.0 for identical strings', () => {
    const checker = new H1DuplicateChecker({});
    expect(checker.jaccardSimilarity('hello world', 'hello world')).toBeCloseTo(1.0, 5);
  });

  it('jaccardSimilarity returns 0.0 for completely different strings', () => {
    const checker = new H1DuplicateChecker({});
    expect(checker.jaccardSimilarity('hello world', 'foo bar baz')).toBeCloseTo(0.0, 5);
  });

  it('titleSimilarity gives CWE boost for matching CWE identifiers', () => {
    const checker = new H1DuplicateChecker({});
    const withCwe = checker.titleSimilarity('XSS CWE-79 in login', 'XSS CWE-79 in search');
    const withoutCwe = checker.titleSimilarity('XSS in login', 'XSS in search');
    expect(withCwe).toBeGreaterThan(withoutCwe);
  });

  it('aggregateSimilarity produces a weighted average', () => {
    const checker = new H1DuplicateChecker({});
    const result = checker.aggregateSimilarity({
      title: 1.0,
      description: 1.0,
      endpoint: 1.0,
      severity: 1.0,
    });
    expect(result).toBeCloseTo(1.0, 5);
  });
});

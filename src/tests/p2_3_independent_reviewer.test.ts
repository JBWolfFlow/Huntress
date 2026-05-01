/**
 * P1-3-f / P0-5-i — Independent Reporter / Reviewer Agent tests
 *
 * Validates the second-pass reviewer that grades a finding's validation
 * evidence and either upgrades, confirms, downgrades, or flags-for-review
 * the validator's verdict. This is the synthetic accept/reject signal that
 * P0-4 (report quality scorer calibration) will use *before* live H1
 * triage data exists.
 *
 * Test coverage strategy:
 *   - Pure functions (parseReviewerResponse, applyReviewVerdict, formatReviewPrompt)
 *     get their own focused tests with full positive/negative case matrix
 *   - The integration path (review() over a mock provider) is covered for
 *     the four verdict outcomes plus error paths (LLM throws, malformed JSON,
 *     missing required fields)
 *   - All assertions check the contract (verdict, recommendedConfidence,
 *     shouldProceedToSubmission), not implementation details (prompt format)
 */

import { describe, it, expect, vi } from 'vitest';
import {
  IndependentReviewer,
  applyReviewVerdict,
  type IndependentReviewResult,
  type ReviewVerdict,
} from '../core/reporting/independent_reviewer';
import type { ValidationResult } from '../core/validation/validator';
import type { ReactFinding } from '../core/engine/react_loop';
import type {
  ChatResponse,
  ModelProvider,
  ProviderInfo,
  ModelInfo,
} from '../core/providers/types';

// ─── Test fixtures ──────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<ReactFinding> = {}): ReactFinding {
  return {
    id: 'f1',
    vulnerabilityType: 'idor',
    severity: 'high',
    title: 'IDOR allows reading other users\' data',
    description: 'GET /api/users/{id} returns any user\'s profile',
    target: 'https://target.com/api/users/42',
    impact: 'PII exfiltration',
    evidence: ['{"email":"victim@target.com","user_id":42}'],
    reproductionSteps: [
      'Authenticate as User A',
      'GET /api/users/42 (User B\'s ID)',
      'Observe User B\'s data returned',
    ],
    confidence: 75,
    discoveredAtIteration: 5,
    ...overrides,
  };
}

function makeValidation(overrides: Partial<ValidationResult> = {}): ValidationResult {
  return {
    findingId: 'f1',
    confirmed: true,
    evidence: [
      {
        type: 'http_response',
        description: 'Cross-user data leaked',
        data: 'HTTP/1.1 200 OK\r\n\r\n{"email":"victim@target.com"}',
        timestamp: Date.now(),
      },
    ],
    reproductionSteps: ['Step 1', 'Step 2'],
    confidence: 80,
    validatorUsed: 'idor',
    validationTime: 1200,
    ...overrides,
  };
}

/**
 * Build a provider stub that returns a single canned reply. `tokenCounts`
 * lets tests verify cost estimation precisely.
 */
function makeMockProvider(reply: string, tokenCounts = { input: 100, output: 50 }): ModelProvider {
  return {
    providerId: 'mock',
    displayName: 'Mock',
    supportsToolUse: true,
    async sendMessage(): Promise<ChatResponse> {
      return {
        content: reply,
        toolCalls: [],
        stopReason: 'end_turn',
        inputTokens: tokenCounts.input,
        outputTokens: tokenCounts.output,
      };
    },
    sendMessageStream: vi.fn(),
    getProviderInfo(): ProviderInfo {
      return { id: 'mock', name: 'Mock', supportsToolUse: true, supportsStreaming: false };
    },
    getAvailableModels(): ModelInfo[] {
      return [{
        id: 'claude-sonnet-4-6',
        name: 'Sonnet',
        contextWindow: 200_000,
        maxOutputTokens: 4096,
        costPerMillionInputTokens: 3,
        costPerMillionOutputTokens: 15,
      }];
    },
    async testConnection() { return true; },
  };
}

function makeThrowingProvider(error: string): ModelProvider {
  return {
    providerId: 'mock',
    displayName: 'Mock',
    supportsToolUse: true,
    async sendMessage(): Promise<ChatResponse> {
      throw new Error(error);
    },
    sendMessageStream: vi.fn(),
    getProviderInfo(): ProviderInfo {
      return { id: 'mock', name: 'Mock', supportsToolUse: true, supportsStreaming: false };
    },
    getAvailableModels(): ModelInfo[] { return []; },
    async testConnection() { return true; },
  };
}

// ─── parseReviewerResponse — pure function, full coverage ───────────────────

describe('IndependentReviewer · parseReviewerResponse', () => {
  // Build a freshly-constructed reviewer to access the public method
  const reviewer = new IndependentReviewer({
    provider: makeMockProvider(''),
    model: 'claude-sonnet-4-6',
  });

  it('parses a clean JSON response', () => {
    const raw = JSON.stringify({
      verdict: 'confirm',
      reasoning: 'Evidence supports the finding',
      recommendedConfidence: 85,
      evidenceGaps: [],
      shouldProceedToSubmission: true,
    });
    const parsed = reviewer.parseReviewerResponse(raw);
    expect(parsed).not.toBeNull();
    expect(parsed!.verdict).toBe('confirm');
    expect(parsed!.recommendedConfidence).toBe(85);
    expect(parsed!.shouldProceedToSubmission).toBe(true);
  });

  it('strips ```json fences', () => {
    const raw = '```json\n{"verdict":"upgrade","reasoning":"strong","recommendedConfidence":95,"evidenceGaps":[],"shouldProceedToSubmission":true}\n```';
    const parsed = reviewer.parseReviewerResponse(raw);
    expect(parsed?.verdict).toBe('upgrade');
  });

  it('strips ``` fences without language tag', () => {
    const raw = '```\n{"verdict":"downgrade","reasoning":"weak","recommendedConfidence":30,"evidenceGaps":["no PoC"],"shouldProceedToSubmission":false}\n```';
    const parsed = reviewer.parseReviewerResponse(raw);
    expect(parsed?.verdict).toBe('downgrade');
    expect(parsed?.evidenceGaps).toEqual(['no PoC']);
  });

  it('extracts JSON when surrounded by leading/trailing prose', () => {
    const raw = 'Here is my judgment:\n{"verdict":"flag_for_review","reasoning":"unclear","recommendedConfidence":50,"evidenceGaps":[],"shouldProceedToSubmission":false}\nLet me know if you need more.';
    const parsed = reviewer.parseReviewerResponse(raw);
    expect(parsed?.verdict).toBe('flag_for_review');
  });

  it('handles all 4 valid verdict values', () => {
    const verdicts: ReviewVerdict[] = ['upgrade', 'confirm', 'downgrade', 'flag_for_review'];
    for (const v of verdicts) {
      const raw = JSON.stringify({
        verdict: v,
        reasoning: 'test',
        recommendedConfidence: 50,
        evidenceGaps: [],
        shouldProceedToSubmission: v === 'confirm' || v === 'upgrade',
      });
      expect(reviewer.parseReviewerResponse(raw)?.verdict).toBe(v);
    }
  });

  it('rejects invalid verdict value', () => {
    const raw = JSON.stringify({
      verdict: 'maybe',
      reasoning: 'x',
      recommendedConfidence: 50,
      evidenceGaps: [],
      shouldProceedToSubmission: true,
    });
    expect(reviewer.parseReviewerResponse(raw)).toBeNull();
  });

  it('rejects missing reasoning', () => {
    const raw = JSON.stringify({
      verdict: 'confirm',
      recommendedConfidence: 50,
      evidenceGaps: [],
      shouldProceedToSubmission: true,
    });
    expect(reviewer.parseReviewerResponse(raw)).toBeNull();
  });

  it('rejects out-of-range confidence (>100)', () => {
    const raw = JSON.stringify({
      verdict: 'confirm',
      reasoning: 'x',
      recommendedConfidence: 150,
      evidenceGaps: [],
      shouldProceedToSubmission: true,
    });
    expect(reviewer.parseReviewerResponse(raw)).toBeNull();
  });

  it('rejects negative confidence', () => {
    const raw = JSON.stringify({
      verdict: 'confirm',
      reasoning: 'x',
      recommendedConfidence: -1,
      evidenceGaps: [],
      shouldProceedToSubmission: true,
    });
    expect(reviewer.parseReviewerResponse(raw)).toBeNull();
  });

  it('rejects non-boolean shouldProceedToSubmission', () => {
    const raw = JSON.stringify({
      verdict: 'confirm',
      reasoning: 'x',
      recommendedConfidence: 50,
      evidenceGaps: [],
      shouldProceedToSubmission: 'yes',
    });
    expect(reviewer.parseReviewerResponse(raw)).toBeNull();
  });

  it('coerces evidenceGaps to empty array when missing', () => {
    const raw = JSON.stringify({
      verdict: 'confirm',
      reasoning: 'x',
      recommendedConfidence: 50,
      shouldProceedToSubmission: true,
    });
    expect(reviewer.parseReviewerResponse(raw)?.evidenceGaps).toEqual([]);
  });

  it('filters non-string entries from evidenceGaps', () => {
    const raw = '{"verdict":"confirm","reasoning":"x","recommendedConfidence":50,"evidenceGaps":["valid",42,null,"also valid"],"shouldProceedToSubmission":true}';
    const parsed = reviewer.parseReviewerResponse(raw);
    expect(parsed?.evidenceGaps).toEqual(['valid', 'also valid']);
  });

  it('returns null on totally unparsable input', () => {
    expect(reviewer.parseReviewerResponse('not json at all')).toBeNull();
    expect(reviewer.parseReviewerResponse('')).toBeNull();
    expect(reviewer.parseReviewerResponse('{ broken')).toBeNull();
  });

  it('returns null when input is array, not object', () => {
    expect(reviewer.parseReviewerResponse('[]')).toBeNull();
  });
});

// ─── formatReviewPrompt — verifies prompt structure ─────────────────────────

describe('IndependentReviewer · formatReviewPrompt', () => {
  const reviewer = new IndependentReviewer({
    provider: makeMockProvider(''),
    model: 'claude-sonnet-4-6',
  });

  it('includes the finding title, target, and vulnerability type', () => {
    const finding = makeFinding({
      title: 'Specific test title',
      target: 'https://x.com/specific/path',
      vulnerabilityType: 'cors_misconfiguration',
    });
    const prompt = reviewer.formatReviewPrompt(finding, makeValidation());
    expect(prompt).toContain('Specific test title');
    expect(prompt).toContain('https://x.com/specific/path');
    expect(prompt).toContain('cors_misconfiguration');
  });

  it('includes the validator output and instructs to ignore the confirmed claim', () => {
    const validation = makeValidation({ confirmed: true, validatorUsed: 'cors_misconfig' });
    const prompt = reviewer.formatReviewPrompt(makeFinding(), validation);
    expect(prompt).toContain('Validator confirmed: true');
    expect(prompt).toMatch(/IGNORE THIS/i);
    expect(prompt).toContain('cors_misconfig');
  });

  it('truncates oversized evidence to keep prompt size bounded', () => {
    const giantData = 'A'.repeat(20_000);
    const validation = makeValidation({
      evidence: Array.from({ length: 20 }, (_, i) => ({
        type: 'http_response' as const,
        description: `evidence ${i}`,
        data: giantData,
        timestamp: Date.now(),
      })),
    });
    const prompt = reviewer.formatReviewPrompt(makeFinding(), validation);
    // Each evidence's `data` is capped at 1500 chars; only first 8 are shown.
    // So total evidence section is at most ~14k chars.
    const evidenceSection = prompt.split('## Validation evidence')[1]?.split('## Reproduction')[0] ?? '';
    expect(evidenceSection.length).toBeLessThan(15_000);
  });

  it('handles empty evidence + empty steps gracefully', () => {
    const validation = makeValidation({ evidence: [], reproductionSteps: [] });
    const finding = makeFinding({ evidence: [] });
    const prompt = reviewer.formatReviewPrompt(finding, validation);
    expect(prompt).toContain('_(none)_'); // placeholder for empty sections
    expect(prompt).toContain('## Validator output');
  });
});

// ─── applyReviewVerdict — pure function for adjusting validation result ─────

describe('applyReviewVerdict · pure function', () => {
  function review(verdict: ReviewVerdict, recConf = 80, gaps: string[] = []): IndependentReviewResult {
    return {
      verdict,
      reasoning: 'test reasoning',
      recommendedConfidence: recConf,
      evidenceGaps: gaps,
      shouldProceedToSubmission: verdict === 'upgrade' || verdict === 'confirm',
      costUsd: 0.001,
      tokensUsed: { input: 100, output: 50 },
      durationMs: 1000,
    };
  }

  it('upgrade takes the higher of validator/reviewer confidence', () => {
    const v = makeValidation({ confidence: 60 });
    const r = review('upgrade', 90);
    const out = applyReviewVerdict(v, r);
    expect(out.effectiveConfidence).toBe(90);
    expect(out.effectiveConfirmed).toBe(true);
  });

  it('upgrade preserves higher validator confidence when reviewer suggests lower', () => {
    const v = makeValidation({ confidence: 95 });
    const r = review('upgrade', 75);
    const out = applyReviewVerdict(v, r);
    expect(out.effectiveConfidence).toBe(95);
  });

  it('confirm passes through validator state unchanged', () => {
    const v = makeValidation({ confidence: 70, confirmed: true });
    const r = review('confirm', 70);
    const out = applyReviewVerdict(v, r);
    expect(out.effectiveConfidence).toBe(70);
    expect(out.effectiveConfirmed).toBe(true);
  });

  it('downgrade takes the lower of the two AND flips confirmed to false', () => {
    const v = makeValidation({ confidence: 80, confirmed: true });
    const r = review('downgrade', 30);
    const out = applyReviewVerdict(v, r);
    expect(out.effectiveConfidence).toBe(30);
    expect(out.effectiveConfirmed).toBe(false);
  });

  it('flag_for_review uses reviewer confidence and blocks (confirmed=false)', () => {
    const v = makeValidation({ confidence: 90, confirmed: true });
    const r = review('flag_for_review', 50);
    const out = applyReviewVerdict(v, r);
    expect(out.effectiveConfidence).toBe(50);
    expect(out.effectiveConfirmed).toBe(false);
  });

  it('reviewNote includes the verdict and reasoning verbatim', () => {
    const v = makeValidation();
    const r = review('downgrade', 20, ['no two-account proof']);
    const out = applyReviewVerdict(v, r);
    expect(out.reviewNote).toContain('downgrade');
    expect(out.reviewNote).toContain('test reasoning');
    expect(out.reviewNote).toContain('no two-account proof');
  });

  it('reviewNote omits the gaps clause when gaps are empty', () => {
    const v = makeValidation();
    const r = review('confirm', 75, []);
    const out = applyReviewVerdict(v, r);
    expect(out.reviewNote).not.toContain('gaps:');
  });
});

// ─── review() integration — happy paths and error paths ────────────────────

describe('IndependentReviewer.review · integration', () => {
  it('returns the parsed verdict on a clean response', async () => {
    const provider = makeMockProvider(JSON.stringify({
      verdict: 'confirm',
      reasoning: 'Strong evidence with HTTP exchange and curl repro',
      recommendedConfidence: 85,
      evidenceGaps: [],
      shouldProceedToSubmission: true,
    }));
    const reviewer = new IndependentReviewer({ provider, model: 'claude-sonnet-4-6' });
    const result = await reviewer.review(makeFinding(), makeValidation());

    expect(result.verdict).toBe('confirm');
    expect(result.recommendedConfidence).toBe(85);
    expect(result.shouldProceedToSubmission).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('returns flag_for_review when LLM throws', async () => {
    const provider = makeThrowingProvider('rate limit exceeded');
    const reviewer = new IndependentReviewer({ provider, model: 'claude-sonnet-4-6' });
    const result = await reviewer.review(makeFinding(), makeValidation());

    expect(result.verdict).toBe('flag_for_review');
    expect(result.shouldProceedToSubmission).toBe(false);
    expect(result.error).toContain('rate limit');
    expect(result.evidenceGaps).toContain('reviewer_error');
  });

  it('returns flag_for_review when LLM returns malformed JSON', async () => {
    const provider = makeMockProvider('hello, here is my analysis: looks great');
    const reviewer = new IndependentReviewer({ provider, model: 'claude-sonnet-4-6' });
    const result = await reviewer.review(makeFinding(), makeValidation());

    expect(result.verdict).toBe('flag_for_review');
    expect(result.shouldProceedToSubmission).toBe(false);
    expect(result.error).toContain('not parsable JSON');
  });

  it('returns flag_for_review when LLM returns valid JSON missing required fields', async () => {
    const provider = makeMockProvider(JSON.stringify({ verdict: 'confirm' }));
    const reviewer = new IndependentReviewer({ provider, model: 'claude-sonnet-4-6' });
    const result = await reviewer.review(makeFinding(), makeValidation());

    expect(result.verdict).toBe('flag_for_review');
    expect(result.error).toContain('not parsable');
  });

  it('preserves validator confidence on error (does not zero it out)', async () => {
    const provider = makeThrowingProvider('boom');
    const reviewer = new IndependentReviewer({ provider, model: 'claude-sonnet-4-6' });
    const validation = makeValidation({ confidence: 75 });
    const result = await reviewer.review(makeFinding(), validation);
    expect(result.recommendedConfidence).toBe(75);
  });

  it('estimates cost from token counts using known rates', async () => {
    // Sonnet 4.6: $3/Mtok input, $15/Mtok output
    const provider = makeMockProvider(JSON.stringify({
      verdict: 'confirm',
      reasoning: 'x',
      recommendedConfidence: 50,
      evidenceGaps: [],
      shouldProceedToSubmission: true,
    }), { input: 1_000_000, output: 1_000_000 });
    const reviewer = new IndependentReviewer({ provider, model: 'claude-sonnet-4-6' });
    const result = await reviewer.review(makeFinding(), makeValidation());
    // 1M input × $3 + 1M output × $15 = $18
    expect(result.costUsd).toBeCloseTo(18, 4);
  });

  it('falls back to default rate for unknown model', async () => {
    const provider = makeMockProvider(JSON.stringify({
      verdict: 'confirm',
      reasoning: 'x',
      recommendedConfidence: 50,
      evidenceGaps: [],
      shouldProceedToSubmission: true,
    }), { input: 1_000_000, output: 0 });
    const reviewer = new IndependentReviewer({ provider, model: 'unknown-future-model' });
    const result = await reviewer.review(makeFinding(), makeValidation());
    // Default fallback is sonnet-tier ($3 input, $15 output) — verify it's positive but realistic
    expect(result.costUsd).toBeGreaterThan(0);
    expect(result.costUsd).toBeLessThan(100); // sanity
  });

  it('records token counts and duration', async () => {
    const provider = makeMockProvider(JSON.stringify({
      verdict: 'confirm',
      reasoning: 'x',
      recommendedConfidence: 50,
      evidenceGaps: [],
      shouldProceedToSubmission: true,
    }), { input: 333, output: 222 });
    const reviewer = new IndependentReviewer({ provider, model: 'claude-sonnet-4-6' });
    const result = await reviewer.review(makeFinding(), makeValidation());
    expect(result.tokensUsed).toEqual({ input: 333, output: 222 });
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('forwards maxTokens and temperature overrides to the provider', async () => {
    const sendSpy = vi.fn(async () => ({
      content: JSON.stringify({
        verdict: 'confirm', reasoning: 'x', recommendedConfidence: 50,
        evidenceGaps: [], shouldProceedToSubmission: true,
      }),
      toolCalls: [],
      stopReason: 'end_turn' as const,
      inputTokens: 0,
      outputTokens: 0,
    }));
    const provider: ModelProvider = {
      providerId: 'spy', displayName: 'Spy', supportsToolUse: true,
      sendMessage: sendSpy,
      sendMessageStream: vi.fn(),
      getProviderInfo: () => ({ id: 'spy', name: 'Spy', supportsToolUse: true, supportsStreaming: false }),
      getAvailableModels: () => [],
      testConnection: async () => true,
    };
    const reviewer = new IndependentReviewer({
      provider,
      model: 'claude-sonnet-4-6',
      maxTokens: 500,
      temperature: 0.3,
    });
    await reviewer.review(makeFinding(), makeValidation());
    expect(sendSpy).toHaveBeenCalledOnce();
    const opts = sendSpy.mock.calls[0][1];
    expect(opts.maxTokens).toBe(500);
    expect(opts.temperature).toBe(0.3);
  });

  it('uses default maxTokens=1024 and temperature=0 when not overridden', async () => {
    const sendSpy = vi.fn(async () => ({
      content: JSON.stringify({
        verdict: 'confirm', reasoning: 'x', recommendedConfidence: 50,
        evidenceGaps: [], shouldProceedToSubmission: true,
      }),
      toolCalls: [],
      stopReason: 'end_turn' as const,
      inputTokens: 0,
      outputTokens: 0,
    }));
    const provider: ModelProvider = {
      providerId: 'spy', displayName: 'Spy', supportsToolUse: true,
      sendMessage: sendSpy,
      sendMessageStream: vi.fn(),
      getProviderInfo: () => ({ id: 'spy', name: 'Spy', supportsToolUse: true, supportsStreaming: false }),
      getAvailableModels: () => [],
      testConnection: async () => true,
    };
    const reviewer = new IndependentReviewer({ provider, model: 'claude-sonnet-4-6' });
    await reviewer.review(makeFinding(), makeValidation());
    const opts = sendSpy.mock.calls[0][1];
    expect(opts.maxTokens).toBe(1024);
    expect(opts.temperature).toBe(0);
  });
});

// ─── Verdict end-to-end matrix — every verdict produces correct downstream effect ──

describe('IndependentReviewer · end-to-end verdict matrix', () => {
  function withReply(reply: object): { reviewer: IndependentReviewer; finding: ReactFinding; validation: ValidationResult } {
    return {
      reviewer: new IndependentReviewer({
        provider: makeMockProvider(JSON.stringify(reply)),
        model: 'claude-sonnet-4-6',
      }),
      finding: makeFinding(),
      validation: makeValidation({ confidence: 70, confirmed: true }),
    };
  }

  it('upgrade verdict → applyReviewVerdict produces effectiveConfirmed=true', async () => {
    const { reviewer, finding, validation } = withReply({
      verdict: 'upgrade', reasoning: 'Stronger than agent claimed',
      recommendedConfidence: 95, evidenceGaps: [], shouldProceedToSubmission: true,
    });
    const review = await reviewer.review(finding, validation);
    const applied = applyReviewVerdict(validation, review);
    expect(applied.effectiveConfirmed).toBe(true);
    expect(applied.effectiveConfidence).toBe(95);
  });

  it('downgrade verdict → applyReviewVerdict flips confirmed to false', async () => {
    const { reviewer, finding, validation } = withReply({
      verdict: 'downgrade', reasoning: 'Evidence too weak',
      recommendedConfidence: 25, evidenceGaps: ['no two-account proof'],
      shouldProceedToSubmission: false,
    });
    const review = await reviewer.review(finding, validation);
    const applied = applyReviewVerdict(validation, review);
    expect(applied.effectiveConfirmed).toBe(false);
    expect(applied.effectiveConfidence).toBe(25);
  });

  it('flag_for_review verdict → blocks submission regardless of original confidence', async () => {
    const { reviewer, finding, validation } = withReply({
      verdict: 'flag_for_review', reasoning: 'Needs human eyes',
      recommendedConfidence: 60, evidenceGaps: [],
      shouldProceedToSubmission: false,
    });
    const review = await reviewer.review(finding, validation);
    expect(review.shouldProceedToSubmission).toBe(false);
    const applied = applyReviewVerdict(validation, review);
    expect(applied.effectiveConfirmed).toBe(false);
  });

  it('confirm verdict on confirmed validation → unchanged downstream state', async () => {
    const { reviewer, finding, validation } = withReply({
      verdict: 'confirm', reasoning: 'Aligned with agent',
      recommendedConfidence: 75, evidenceGaps: [], shouldProceedToSubmission: true,
    });
    const review = await reviewer.review(finding, validation);
    const applied = applyReviewVerdict(validation, review);
    expect(applied.effectiveConfirmed).toBe(true);
    expect(applied.effectiveConfidence).toBe(70); // validator's original
  });
});

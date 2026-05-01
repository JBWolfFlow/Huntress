/**
 * P1-3-f / P0-5-i — Independent Reporter / Reviewer Agent
 *
 * A second-pass quality gate that reads a finding's validation evidence,
 * IGNORES the validator's `confirmed` claim, and forms its own judgment
 * about whether the report would survive HackerOne triage. This produces
 * a synthetic accept/reject signal *before* live H1 triage data exists,
 * which is the missing input for P0-4 (calibrating the report quality
 * scorer against real triage outcomes).
 *
 * Pattern is borrowed from PentAGI's `reporter.tmpl` "Independent Judgment"
 * agent (`docs/research/PENTAGI_DEEP_DIVE.md` §11.9). The reviewer is
 * deliberately a *different model* than the validator (Sonnet by default
 * vs. the Haiku that runs validators) so the signal is a true second
 * opinion rather than the same model reaffirming itself.
 *
 * The reviewer runs over the LLM and is skipped when no provider is
 * supplied — this lets the existing pipeline run in test environments
 * and behind a feature flag without behavioral surprises.
 */

import type { ModelProvider, ChatMessage, SendMessageOptions } from '../providers/types';
import type { ValidationResult } from '../validation/validator';
import type { ReactFinding } from '../engine/react_loop';

// ─── Public types ───────────────────────────────────────────────────────────

/** Reviewer's verdict on a finding's validation evidence. */
export type ReviewVerdict = 'upgrade' | 'confirm' | 'downgrade' | 'flag_for_review';

/**
 * Outcome of a single review pass. The orchestrator should adjust the
 * finding's effective severity / confidence based on `recommendedConfidence`
 * and `verdict`, surfacing the reasoning in the finding's evidence so the
 * user can see why the gate fired.
 */
export interface IndependentReviewResult {
  /** Reviewer's overall judgment on the validation evidence */
  verdict: ReviewVerdict;
  /** 1-3 sentences explaining the verdict */
  reasoning: string;
  /** Recommended confidence (0-100) — supersedes the validator's confidence */
  recommendedConfidence: number;
  /** Specific evidence shapes the report is missing (e.g. "no two-account proof", "no cross-origin fetch PoC") */
  evidenceGaps: string[];
  /**
   * Whether the report should proceed to the submission gate. False ≈
   * the gate would block this report regardless of the validator's claim.
   */
  shouldProceedToSubmission: boolean;
  /** Approximate cost of the review call in USD (best-effort from token counts) */
  costUsd: number;
  /** Token counts for tracing */
  tokensUsed: { input: number; output: number };
  /** Wall-clock duration in ms */
  durationMs: number;
  /** Set when the reviewer call failed; verdict in this case is 'flag_for_review' */
  error?: string;
}

export interface IndependentReviewerConfig {
  provider: ModelProvider;
  /** Model ID — should be a different tier than the validator runs (Sonnet recommended) */
  model: string;
  /** Optional override for max tokens (default 1024) */
  maxTokens?: number;
  /** Optional override for temperature (default 0 for reproducibility) */
  temperature?: number;
}

// ─── Implementation ─────────────────────────────────────────────────────────

/**
 * System prompt for the reviewer. Designed to make the LLM IGNORE the
 * validator's confirmation and form an independent judgment based on the
 * evidence quality alone — exactly what an H1 triager would do.
 */
const REVIEWER_SYSTEM_PROMPT = `You are an independent HackerOne triage simulator. Your job is to judge whether a vulnerability report would be ACCEPTED, TRIAGED, or REJECTED by a real H1 triager based on the evidence quality alone.

You will be given a finding plus the output of an automated validator. The validator may say "confirmed: true" — IGNORE that claim. Form your own judgment based ONLY on the evidence, reproduction steps, and HTTP exchanges. Real triagers do not trust automated tools; they look for proof.

Apply the H1 Decision Matrix:
- CORS reports MUST include cross-origin fetch PoC reading sensitive data — header reflection alone is auto-rejected.
- XSS reports MUST use alert(document.domain) (not alert(1)) — execution-context proof is mandatory.
- Stored XSS MUST show two-session proof (Account A injects, Account B triggers).
- IDOR/BOLA reports MUST show two-account ID swap with both responses captured.
- Open Redirect ALONE is auto-rejected; must chain to OAuth callback hijack or token theft.
- SSRF MUST show internal data accessed (cloud metadata 169.254.169.254, internal services) or OOB callback for blind variants.
- SQLi MUST show actual data extraction — error messages alone are not enough.
- Race condition MUST show HTTP/2 single-packet or N-concurrent-success proof, not theoretical.
- Cache poisoning MUST show 3-step proof: poison → CF-Cache-Status: HIT → clean request returns poisoned response.

Common rejection signals:
- Generic impact statements ("an attacker could...") without specific data accessed
- Tool output dumps without explanation
- "Might be vulnerable" / "potential" / "possible" language — H1 wants demonstrated impact
- Missing raw HTTP request/response pairs
- Missing curl reproduction command
- Self-XSS that cannot target other users
- Missing security headers or version-disclosure findings (Core Ineligible)

Respond with EXACTLY this JSON structure (no markdown fences, no commentary):
{
  "verdict": "upgrade" | "confirm" | "downgrade" | "flag_for_review",
  "reasoning": "1-3 sentences explaining the verdict",
  "recommendedConfidence": 0-100,
  "evidenceGaps": ["specific gap 1", "specific gap 2"],
  "shouldProceedToSubmission": true | false
}

Verdict semantics:
- "upgrade": Evidence is stronger than the validator's confidence suggested — bump confidence up
- "confirm": Validator's verdict matches the evidence — no change needed
- "downgrade": Evidence is weaker than validator claimed — lower confidence; likely false positive
- "flag_for_review": Insufficient evidence to judge; needs human review before submission

Set shouldProceedToSubmission=false for any verdict that would result in rejection by H1 triage.`;

/**
 * Heuristic cost estimation per Anthropic public pricing as of 2026-04.
 * Used for tracing / budget tracking, not billing — actual cost is what
 * the provider's own usage API reports.
 */
const MODEL_COST_PER_MTOK_USD: Record<string, { input: number; output: number }> = {
  'claude-sonnet-4-6': { input: 3, output: 15 },
  'claude-sonnet-4-5-20250929': { input: 3, output: 15 },
  'claude-opus-4-7': { input: 15, output: 75 },
  'claude-opus-4-6': { input: 15, output: 75 },
  'claude-haiku-4-5-20251001': { input: 0.25, output: 1.25 },
};

function estimateCostUsd(model: string, inputTokens: number, outputTokens: number): number {
  const rates = MODEL_COST_PER_MTOK_USD[model] ?? { input: 3, output: 15 };
  return (inputTokens * rates.input + outputTokens * rates.output) / 1_000_000;
}

export class IndependentReviewer {
  constructor(private readonly config: IndependentReviewerConfig) {}

  /**
   * Review a finding's validation evidence and return an independent verdict.
   *
   * Never throws — if the LLM call fails or the response is unparsable,
   * returns `verdict: 'flag_for_review'` with the error captured. This is
   * deliberate: a failing reviewer should NEVER block a finding that the
   * validator already cleared, only flag it for human attention.
   */
  async review(finding: ReactFinding, validation: ValidationResult): Promise<IndependentReviewResult> {
    const startTime = Date.now();

    const userPrompt = this.formatReviewPrompt(finding, validation);
    const messages: ChatMessage[] = [{ role: 'user', content: userPrompt }];

    const options: SendMessageOptions = {
      model: this.config.model,
      systemPrompt: REVIEWER_SYSTEM_PROMPT,
      maxTokens: this.config.maxTokens ?? 1024,
      temperature: this.config.temperature ?? 0,
    };

    let responseText: string;
    let inputTokens = 0;
    let outputTokens = 0;
    try {
      const response = await this.config.provider.sendMessage(messages, options);
      responseText = response.content;
      inputTokens = response.inputTokens;
      outputTokens = response.outputTokens;
    } catch (err) {
      return this.errorResult(finding, validation, startTime, err instanceof Error ? err.message : String(err));
    }

    const parsed = this.parseReviewerResponse(responseText);
    if (!parsed) {
      return this.errorResult(
        finding, validation, startTime,
        `Reviewer response was not parsable JSON: ${responseText.substring(0, 300)}`,
      );
    }

    return {
      verdict: parsed.verdict,
      reasoning: parsed.reasoning,
      recommendedConfidence: parsed.recommendedConfidence,
      evidenceGaps: parsed.evidenceGaps,
      shouldProceedToSubmission: parsed.shouldProceedToSubmission,
      costUsd: estimateCostUsd(this.config.model, inputTokens, outputTokens),
      tokensUsed: { input: inputTokens, output: outputTokens },
      durationMs: Date.now() - startTime,
    };
  }

  /**
   * Build the user message containing the finding + validation summary.
   * Truncates large evidence blocks to keep the review call cheap.
   */
  formatReviewPrompt(finding: ReactFinding, validation: ValidationResult): string {
    const evidenceLines = validation.evidence.slice(0, 8).map((e, i) => {
      const data = (e.data ?? '').substring(0, 1500);
      return `[Evidence ${i + 1}] type=${e.type}\n${e.description}\n${data}`;
    }).join('\n\n');

    const reproSteps = validation.reproductionSteps.slice(0, 20).map((s, i) => `${i + 1}. ${s}`).join('\n');
    const findingEvidence = (finding.evidence ?? []).slice(0, 5).map((e, i) =>
      `[Finding-evidence ${i + 1}] ${typeof e === 'string' ? e.substring(0, 1000) : JSON.stringify(e).substring(0, 1000)}`
    ).join('\n');

    return [
      '## Finding',
      `Title: ${finding.title ?? 'Untitled'}`,
      `Vulnerability type: ${finding.vulnerabilityType}`,
      `Target: ${finding.target}`,
      `Severity (claimed): ${finding.severity ?? 'unknown'}`,
      `Agent confidence: ${finding.confidence}`,
      `Description:\n${(finding.description ?? '').substring(0, 2000)}`,
      `Impact:\n${(finding.impact ?? '').substring(0, 1000)}`,
      '',
      '## Finding evidence (from agent)',
      findingEvidence || '_(none)_',
      '',
      '## Validator output',
      `Validator used: ${validation.validatorUsed}`,
      `Validator confirmed: ${validation.confirmed}  (IGNORE THIS — form your own judgment)`,
      `Validator confidence: ${validation.confidence}`,
      validation.error ? `Validator error: ${validation.error}` : '',
      '',
      '## Validation evidence',
      evidenceLines || '_(none)_',
      '',
      '## Reproduction steps',
      reproSteps || '_(none)_',
      '',
      'Now apply the H1 Decision Matrix and respond with the JSON structure described in your system prompt.',
    ].filter(Boolean).join('\n');
  }

  /**
   * Parse the reviewer's JSON response. Returns null on any structural
   * failure — caller treats null as `verdict: 'flag_for_review'`.
   *
   * Tolerates: ```json fences, leading/trailing whitespace, occasional
   * trailing commas. Does NOT tolerate: missing required fields, invalid
   * verdict values, out-of-range confidence.
   */
  parseReviewerResponse(raw: string): {
    verdict: ReviewVerdict;
    reasoning: string;
    recommendedConfidence: number;
    evidenceGaps: string[];
    shouldProceedToSubmission: boolean;
  } | null {
    let cleaned = raw.trim();
    // Strip markdown code fences if present
    cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
    // Best-effort: extract the first {...} block if there's leading text
    const braceMatch = cleaned.match(/\{[\s\S]*\}/);
    if (braceMatch) cleaned = braceMatch[0];

    let parsed: unknown;
    try {
      parsed = JSON.parse(cleaned);
    } catch {
      return null;
    }

    if (!parsed || typeof parsed !== 'object') return null;
    const obj = parsed as Record<string, unknown>;

    const verdict = obj.verdict;
    if (verdict !== 'upgrade' && verdict !== 'confirm' && verdict !== 'downgrade' && verdict !== 'flag_for_review') {
      return null;
    }
    const reasoning = typeof obj.reasoning === 'string' ? obj.reasoning : null;
    if (!reasoning) return null;
    const recommendedConfidence = typeof obj.recommendedConfidence === 'number' ? obj.recommendedConfidence : null;
    if (recommendedConfidence === null || recommendedConfidence < 0 || recommendedConfidence > 100) return null;
    const evidenceGaps = Array.isArray(obj.evidenceGaps)
      ? obj.evidenceGaps.filter((g): g is string => typeof g === 'string')
      : [];
    const shouldProceedToSubmission = typeof obj.shouldProceedToSubmission === 'boolean'
      ? obj.shouldProceedToSubmission
      : null;
    if (shouldProceedToSubmission === null) return null;

    return { verdict, reasoning, recommendedConfidence, evidenceGaps, shouldProceedToSubmission };
  }

  /** Build the error-path result. */
  private errorResult(
    finding: ReactFinding,
    validation: ValidationResult,
    startTime: number,
    error: string,
  ): IndependentReviewResult {
    return {
      verdict: 'flag_for_review',
      reasoning: `Reviewer failed to produce a verdict: ${error.substring(0, 200)}`,
      // On error, we don't override the validator's confidence — caller
      // can still proceed with the original validation result.
      recommendedConfidence: validation.confidence ?? finding.confidence,
      evidenceGaps: ['reviewer_error'],
      shouldProceedToSubmission: false,
      costUsd: 0,
      tokensUsed: { input: 0, output: 0 },
      durationMs: Date.now() - startTime,
      error,
    };
  }
}

/**
 * Apply a reviewer verdict to a validation result, producing the
 * adjusted finding-level confidence and a human-readable note.
 *
 * Pure function — no I/O. Caller pipes the result into the finding's
 * effective state.
 */
export function applyReviewVerdict(
  validation: ValidationResult,
  review: IndependentReviewResult,
): {
  effectiveConfidence: number;
  effectiveConfirmed: boolean;
  reviewNote: string;
} {
  const reviewNote = `Independent reviewer: ${review.verdict} — ${review.reasoning}` +
    (review.evidenceGaps.length > 0 ? ` (gaps: ${review.evidenceGaps.join(', ')})` : '');

  switch (review.verdict) {
    case 'upgrade':
      // Take the higher of validator and reviewer confidence
      return {
        effectiveConfidence: Math.max(validation.confidence, review.recommendedConfidence),
        effectiveConfirmed: true,
        reviewNote,
      };
    case 'confirm':
      return {
        effectiveConfidence: validation.confidence,
        effectiveConfirmed: validation.confirmed,
        reviewNote,
      };
    case 'downgrade':
      // Take the lower of the two — reviewer is the more conservative voice
      return {
        effectiveConfidence: Math.min(validation.confidence, review.recommendedConfidence),
        effectiveConfirmed: false,
        reviewNote,
      };
    case 'flag_for_review':
      // Block proceeding regardless of confidence
      return {
        effectiveConfidence: review.recommendedConfidence,
        effectiveConfirmed: false,
        reviewNote,
      };
  }
}

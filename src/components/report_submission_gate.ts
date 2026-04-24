/**
 * Pure helpers for the "Approve & Submit" modal — pulled out of
 * `ReportReviewModal.tsx` so the submission-gate logic can be unit-tested
 * without a DOM or React Testing Library.
 *
 * Two functions:
 *   - `computeReportChecklist`: per-field completeness flags + percentage.
 *   - `computeSubmissionGate`: given a report + duplicate score + quality
 *     score, returns `{ blocked, reason }`. This is the authority on
 *     whether the "Approve & Submit" button is enabled.
 *
 * A third invariant — the user must tick the confirmation checkbox — lives
 * in the modal's local state (`confirmChecked`). The checkbox cannot be
 * short-circuited by this helper; both gates must pass in the UI layer.
 */

import type { H1Report } from '../core/reporting/h1_api';

export interface QualityLike {
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
}

export interface DuplicateLike {
  recommendation: 'submit' | 'review' | 'skip';
}

export interface ReportChecklist {
  hasDescription: boolean;
  hasImpact: boolean;
  hasSteps: boolean;
  hasSeverity: boolean;
  hasCvss: boolean;
  hasCwe: boolean;
  hasEvidence: boolean;
  hasSeverityJustification: boolean;
}

export const DESCRIPTION_MIN_CHARS = 50;
export const IMPACT_MIN_CHARS = 20;
export const STEPS_MIN_COUNT = 3;

export function computeReportChecklist(report: H1Report): ReportChecklist {
  return {
    hasDescription: (report.description?.length ?? 0) > DESCRIPTION_MIN_CHARS,
    hasImpact: (report.impact?.length ?? 0) > IMPACT_MIN_CHARS,
    hasSteps: (report.steps?.length ?? 0) >= STEPS_MIN_COUNT,
    hasSeverity: Boolean(report.severity),
    hasCvss: Boolean(report.cvssScore),
    hasCwe: Boolean(report.weaknessId),
    hasEvidence: Boolean(
      report.proof?.screenshots?.length
      || report.proof?.video
      || report.proof?.logs?.length,
    ),
    hasSeverityJustification: Boolean(report.severityJustification?.length),
  };
}

export function computeChecklistScore(checklist: ReportChecklist): number {
  const checks = Object.values(checklist);
  return Math.round((checks.filter(Boolean).length / checks.length) * 100);
}

export interface SubmissionGate {
  blocked: boolean;
  reason: string | null;
}

/**
 * Hard-block rules enforced before the Approve & Submit button is enabled.
 * Order matters — first match wins — because the reason surfaces to the
 * user as the single most important thing to fix.
 *
 * Rules:
 *   1. Duplicate recommendation is `skip` — submitting would damage H1
 *      reputation on an already-known bug.
 *   2. Quality grade is `F` — the scorer ran and found the report
 *      structurally unsendable.
 *   3. The description is missing or too short to be triaged.
 *   4. Fewer than three reproduction steps — standard H1 triage bar.
 *
 * Anything that passes all four is submittable PROVIDED the user also
 * ticks the confirmation checkbox in the modal.
 */
export function computeSubmissionGate(
  report: H1Report,
  duplicateScore: DuplicateLike | null | undefined,
  qualityScore: QualityLike | null | undefined,
): SubmissionGate {
  if (duplicateScore?.recommendation === 'skip') {
    return {
      blocked: true,
      reason: 'High duplicate probability detected. Review and update before submitting.',
    };
  }
  if (qualityScore?.grade === 'F') {
    return {
      blocked: true,
      reason: 'Report quality is too low for submission. Edit the report to improve clarity and completeness.',
    };
  }
  const checklist = computeReportChecklist(report);
  if (!checklist.hasDescription) {
    return { blocked: true, reason: 'Report is missing a description.' };
  }
  if (!checklist.hasSteps) {
    return { blocked: true, reason: `Report needs at least ${STEPS_MIN_COUNT} reproduction steps.` };
  }
  return { blocked: false, reason: null };
}

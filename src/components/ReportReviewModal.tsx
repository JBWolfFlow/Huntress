/**
 * ReportReviewModal — Phase 23D
 *
 * Mandatory human review gate before HackerOne submission.
 * Displays the full report, quality score, duplicate risk, CVSS score,
 * and estimated bounty. User must explicitly click "Approve & Submit"
 * before the report is sent to HackerOne.
 */

import React, { useState, useCallback, useMemo } from 'react';
import type { H1Report } from '../core/reporting/h1_api';
import type { DuplicateScore } from '../utils/duplicate_checker';
import {
  computeReportChecklist,
  computeChecklistScore,
  computeSubmissionGate,
} from './report_submission_gate';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface QualityScore {
  overall: number;
  categories: {
    clarity: number;
    completeness: number;
    evidence: number;
    impact: number;
    reproducibility: number;
  };
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  issues: QualityIssue[];
}

export interface QualityIssue {
  category: string;
  severity: 'critical' | 'major' | 'minor';
  message: string;
  suggestion: string;
}

export interface ReportReviewModalProps {
  report: H1Report;
  programHandle: string;
  qualityScore?: QualityScore;
  duplicateScore?: DuplicateScore;
  onApproveAndSubmit: (report: H1Report, programHandle: string) => Promise<void>;
  onEditReport: (report: H1Report) => void;
  onCancel: () => void;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-900/30', text: 'text-red-400', border: 'border-red-700' },
  high: { bg: 'bg-orange-900/30', text: 'text-orange-400', border: 'border-orange-700' },
  medium: { bg: 'bg-yellow-900/30', text: 'text-yellow-400', border: 'border-yellow-700' },
  low: { bg: 'bg-blue-900/30', text: 'text-blue-400', border: 'border-blue-700' },
};

const GRADE_STYLES: Record<string, string> = {
  A: 'text-green-400 bg-green-900/30',
  B: 'text-blue-400 bg-blue-900/30',
  C: 'text-yellow-400 bg-yellow-900/30',
  D: 'text-orange-400 bg-orange-900/30',
  F: 'text-red-400 bg-red-900/30',
};

function scoreColor(score: number): string {
  if (score >= 80) return 'text-green-400';
  if (score >= 60) return 'text-yellow-400';
  if (score >= 40) return 'text-orange-400';
  return 'text-red-400';
}

function dupRiskColor(recommendation: string): string {
  if (recommendation === 'submit') return 'text-green-400';
  if (recommendation === 'review') return 'text-yellow-400';
  return 'text-red-400';
}

function dupRiskLabel(recommendation: string): string {
  if (recommendation === 'submit') return 'Low Risk';
  if (recommendation === 'review') return 'Medium Risk';
  return 'High Risk';
}

// ─── Sub-components ───────────────────────────────────────────────────────────

const SectionHeader: React.FC<{ title: string }> = ({ title }) => (
  <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">{title}</h3>
);

const ScoreBar: React.FC<{ label: string; score: number }> = ({ label, score }) => (
  <div className="flex items-center space-x-2 mb-1.5">
    <span className="text-xs text-gray-400 w-28 shrink-0">{label}</span>
    <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
      <div
        className={`h-full rounded-full transition-all ${
          score >= 80 ? 'bg-green-500' : score >= 60 ? 'bg-yellow-500' : score >= 40 ? 'bg-orange-500' : 'bg-red-500'
        }`}
        style={{ width: `${Math.min(100, score)}%` }}
      />
    </div>
    <span className={`text-xs font-mono w-8 text-right ${scoreColor(score)}`}>{score}</span>
  </div>
);

const ChecklistItem: React.FC<{ checked: boolean; label: string }> = ({ checked, label }) => (
  <div className="flex items-center space-x-2 text-xs">
    <span className={checked ? 'text-green-400' : 'text-red-400'}>{checked ? '\u2713' : '\u2717'}</span>
    <span className={checked ? 'text-gray-300' : 'text-gray-500'}>{label}</span>
  </div>
);

// ─── Main Component ───────────────────────────────────────────────────────────

export const ReportReviewModal: React.FC<ReportReviewModalProps> = ({
  report,
  programHandle,
  qualityScore,
  duplicateScore,
  onApproveAndSubmit,
  onEditReport,
  onCancel,
}) => {
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [confirmChecked, setConfirmChecked] = useState(false);

  const severity = SEVERITY_STYLES[report.severity] ?? SEVERITY_STYLES.medium;

  // Checklist + submission-gate logic lives in `report_submission_gate.ts`
  // so it can be unit-tested without DOM or React Testing Library.
  const checklist = useMemo(() => computeReportChecklist(report), [report]);
  const checklistScore = useMemo(() => computeChecklistScore(checklist), [checklist]);
  const gate = useMemo(
    () => computeSubmissionGate(report, duplicateScore, qualityScore),
    [report, duplicateScore, qualityScore],
  );
  const isBlocked = gate.blocked;
  const blockReason = gate.reason;

  const handleSubmit = useCallback(async () => {
    if (!confirmChecked || isBlocked) return;
    setSubmitting(true);
    setSubmitError(null);
    try {
      await onApproveAndSubmit(report, programHandle);
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : 'Submission failed');
    } finally {
      setSubmitting(false);
    }
  }, [confirmChecked, isBlocked, onApproveAndSubmit, report, programHandle]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="w-full max-w-4xl max-h-[90vh] bg-gray-900 border border-gray-700 rounded-lg shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className={`px-6 py-4 border-b ${severity.border} ${severity.bg}`}>
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-white">Review Report Before Submission</h2>
              <p className="text-xs text-gray-400 mt-0.5">
                Program: <span className="text-gray-300">{programHandle}</span>
              </p>
            </div>
            <button onClick={onCancel} className="text-gray-400 hover:text-white text-xl leading-none">&times;</button>
          </div>
        </div>

        {/* Body — scrollable */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Report summary */}
          <div>
            <SectionHeader title="Report Summary" />
            <div className={`p-4 rounded-lg border ${severity.border} ${severity.bg}`}>
              <h3 className="text-base font-semibold text-white mb-2">{report.title}</h3>
              <div className="flex items-center space-x-3 text-xs">
                <span className={`px-2 py-0.5 rounded font-bold uppercase ${severity.text} ${severity.bg}`}>
                  {report.severity}
                </span>
                {report.cvssScore && (
                  <span className="text-gray-400">CVSS {report.cvssScore}</span>
                )}
                {report.weaknessId && (
                  <span className="text-gray-400">CWE-{report.weaknessId}</span>
                )}
                <span className="text-green-400">
                  Est. ${report.suggestedBounty.min.toLocaleString()} - ${report.suggestedBounty.max.toLocaleString()}
                </span>
              </div>
            </div>
          </div>

          {/* Description preview */}
          <div>
            <SectionHeader title="Description" />
            <p className="text-sm text-gray-300 whitespace-pre-wrap line-clamp-6">{report.description}</p>
          </div>

          {/* Impact */}
          <div>
            <SectionHeader title="Impact" />
            <p className="text-sm text-gray-300 whitespace-pre-wrap line-clamp-4">{report.impact || 'Not provided'}</p>
          </div>

          {/* Steps */}
          <div>
            <SectionHeader title={`Reproduction Steps (${report.steps.length})`} />
            <ol className="list-decimal list-inside text-sm text-gray-300 space-y-1">
              {report.steps.map((step, i) => (
                <li key={i} className="text-gray-300">{step}</li>
              ))}
            </ol>
          </div>

          {/* Two-column: Quality + Duplicate */}
          <div className="grid grid-cols-2 gap-4">
            {/* Quality Score */}
            <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700">
              <SectionHeader title="Report Quality" />
              {qualityScore ? (
                <>
                  <div className="flex items-center space-x-2 mb-3">
                    <span className={`text-2xl font-bold ${scoreColor(qualityScore.overall)}`}>
                      {qualityScore.overall}
                    </span>
                    <span className="text-gray-500 text-sm">/100</span>
                    <span className={`ml-2 px-2 py-0.5 rounded text-xs font-bold ${GRADE_STYLES[qualityScore.grade] ?? ''}`}>
                      Grade {qualityScore.grade}
                    </span>
                  </div>
                  <ScoreBar label="Clarity" score={qualityScore.categories.clarity} />
                  <ScoreBar label="Completeness" score={qualityScore.categories.completeness} />
                  <ScoreBar label="Evidence" score={qualityScore.categories.evidence} />
                  <ScoreBar label="Impact" score={qualityScore.categories.impact} />
                  <ScoreBar label="Reproducibility" score={qualityScore.categories.reproducibility} />
                  {qualityScore.issues.length > 0 && (
                    <div className="mt-3 space-y-1">
                      {qualityScore.issues.slice(0, 3).map((issue, i) => (
                        <div key={i} className="text-xs text-yellow-400">
                          {issue.severity === 'critical' ? '\u26a0' : '\u2139'} {issue.message}
                        </div>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <div className="text-sm text-gray-500">Quality scoring not available</div>
              )}
            </div>

            {/* Duplicate Risk */}
            <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700">
              <SectionHeader title="Duplicate Risk" />
              {duplicateScore ? (
                <>
                  <div className="flex items-center space-x-2 mb-3">
                    <span className={`text-2xl font-bold ${dupRiskColor(duplicateScore.recommendation)}`}>
                      {duplicateScore.overall}%
                    </span>
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                      duplicateScore.recommendation === 'submit' ? 'bg-green-900/30 text-green-400' :
                      duplicateScore.recommendation === 'review' ? 'bg-yellow-900/30 text-yellow-400' :
                      'bg-red-900/30 text-red-400'
                    }`}>
                      {dupRiskLabel(duplicateScore.recommendation)}
                    </span>
                  </div>
                  <ScoreBar label="H1 Reports" score={Math.round(duplicateScore.h1Match * 100)} />
                  <ScoreBar label="GitHub PoCs" score={Math.round(duplicateScore.githubMatch * 100)} />
                  <ScoreBar label="Internal DB" score={Math.round(duplicateScore.internalMatch * 100)} />
                  {duplicateScore.matches.length > 0 && (
                    <div className="mt-3 space-y-1">
                      {duplicateScore.matches.slice(0, 3).map((match, i) => (
                        <div key={i} className="text-xs text-gray-400 truncate">
                          {match.source}: {match.title} ({Math.round(match.similarity * 100)}%)
                        </div>
                      ))}
                    </div>
                  )}
                  {duplicateScore.reasoning.length > 0 && (
                    <div className="mt-2">
                      {duplicateScore.reasoning.slice(0, 2).map((reason, i) => (
                        <p key={i} className="text-xs text-gray-500 italic">{reason}</p>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <div className="text-sm text-gray-500">Duplicate checking not available</div>
              )}
            </div>
          </div>

          {/* Submission Checklist */}
          <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700">
            <div className="flex items-center justify-between mb-2">
              <SectionHeader title="Submission Checklist" />
              <span className={`text-xs font-mono ${scoreColor(checklistScore)}`}>{checklistScore}%</span>
            </div>
            <div className="grid grid-cols-2 gap-1">
              <ChecklistItem checked={checklist.hasDescription} label="Description (>50 chars)" />
              <ChecklistItem checked={checklist.hasImpact} label="Impact statement" />
              <ChecklistItem checked={checklist.hasSteps} label="3+ reproduction steps" />
              <ChecklistItem checked={checklist.hasSeverity} label="Severity rating" />
              <ChecklistItem checked={checklist.hasCvss} label="CVSS score" />
              <ChecklistItem checked={checklist.hasCwe} label="CWE identifier" />
              <ChecklistItem checked={checklist.hasEvidence} label="Evidence attached" />
              <ChecklistItem checked={checklist.hasSeverityJustification} label="Severity justification" />
            </div>
          </div>
        </div>

        {/* Footer — action buttons */}
        <div className="px-6 py-4 border-t border-gray-700 bg-gray-800">
          {/* Block warning */}
          {isBlocked && blockReason && (
            <div className="mb-3 px-3 py-2 bg-red-900/20 border border-red-800 rounded text-xs text-red-400">
              {blockReason}
            </div>
          )}

          {/* Submit error */}
          {submitError && (
            <div className="mb-3 px-3 py-2 bg-red-900/20 border border-red-800 rounded text-xs text-red-400">
              Submission failed: {submitError}
            </div>
          )}

          <div className="flex items-center justify-between">
            <label className="flex items-center space-x-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={confirmChecked}
                onChange={(e) => setConfirmChecked(e.target.checked)}
                className="rounded border-gray-600 bg-gray-700 text-red-500 focus:ring-red-500 focus:ring-offset-gray-900"
              />
              <span className="text-xs text-gray-400">
                I have reviewed this report and confirm it is accurate and ready for submission.
              </span>
            </label>

            <div className="flex items-center space-x-2">
              <button
                onClick={onCancel}
                className="px-4 py-2 text-xs font-medium text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => onEditReport(report)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white text-xs font-medium rounded transition-colors"
              >
                Edit Report
              </button>
              <button
                onClick={handleSubmit}
                disabled={submitting || !confirmChecked || isBlocked}
                className={`px-5 py-2 text-xs font-bold rounded transition-colors ${
                  submitting || !confirmChecked || isBlocked
                    ? 'bg-gray-600 text-gray-400 cursor-not-allowed'
                    : 'bg-red-600 hover:bg-red-700 text-white'
                }`}
              >
                {submitting ? 'Submitting...' : 'Approve & Submit'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReportReviewModal;

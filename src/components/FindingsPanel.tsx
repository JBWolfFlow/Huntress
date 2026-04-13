/**
 * FindingsPanel
 *
 * Side panel displaying discovered vulnerabilities with severity summary,
 * scrollable list, duplicate status, and report generation trigger.
 */

import React, { useState } from 'react';
import type { AgentFinding, FindingSeverity, ValidationStatus, DuplicateCheckResult } from '../agents/base_agent';

interface FindingsPanelProps {
  findings: AgentFinding[];
  onGenerateReport?: (finding: AgentFinding) => void;
  onViewFinding?: (finding: AgentFinding) => void;
}

const SEVERITY_CONFIG: Record<FindingSeverity, { color: string; bgColor: string; label: string }> = {
  critical: { color: 'text-red-400', bgColor: 'bg-red-500', label: 'Critical' },
  high: { color: 'text-orange-400', bgColor: 'bg-orange-500', label: 'High' },
  medium: { color: 'text-yellow-400', bgColor: 'bg-yellow-500', label: 'Medium' },
  low: { color: 'text-blue-400', bgColor: 'bg-blue-500', label: 'Low' },
  info: { color: 'text-gray-400', bgColor: 'bg-gray-500', label: 'Info' },
};

const SEVERITY_ORDER: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

const VALIDATION_BADGE: Record<ValidationStatus, { color: string; label: string; icon: string }> = {
  pending: { color: 'bg-gray-600 text-gray-200', label: 'Pending', icon: '...' },
  confirmed: { color: 'bg-green-600 text-white', label: 'Verified', icon: '\u2713' },
  unverified: { color: 'bg-yellow-600 text-white', label: 'Unverified', icon: '?' },
  validation_failed: { color: 'bg-gray-500 text-gray-200', label: 'Check Failed', icon: '!' },
};

function getDuplicateLabel(dup?: DuplicateCheckResult): { color: string; label: string } | null {
  if (!dup || dup.status === 'not_checked') return null;
  if (dup.status === 'likely_duplicate') return { color: 'text-red-400', label: 'Likely Duplicate' };
  if (dup.status === 'possible_duplicate') return { color: 'text-yellow-400', label: 'Possible Duplicate' };
  return { color: 'text-green-400', label: 'No Known Duplicates' };
}

export const FindingsPanel: React.FC<FindingsPanelProps> = ({
  findings,
  onGenerateReport,
  onViewFinding,
}) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<FindingSeverity | 'all'>('all');

  // Count findings by severity
  const severityCounts = SEVERITY_ORDER.reduce((acc, sev) => {
    acc[sev] = findings.filter((f) => f.severity === sev).length;
    return acc;
  }, {} as Record<FindingSeverity, number>);

  const totalFindings = findings.length;

  // Apply filter
  const filteredFindings =
    filter === 'all' ? findings : findings.filter((f) => f.severity === filter);

  // Sort by severity then timestamp (newest first)
  const sortedFindings = [...filteredFindings].sort((a, b) => {
    const sevDiff = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (sevDiff !== 0) return sevDiff;
    return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
  });

  if (totalFindings === 0) {
    return (
      <div className="p-4">
        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
          Findings
        </h3>
        <p className="text-sm text-gray-500">No findings yet</p>
      </div>
    );
  }

  return (
    <div className="p-4 flex flex-col h-full">
      <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
        Findings ({totalFindings})
      </h3>

      {/* Severity summary bar */}
      <div className="flex h-2 rounded-full overflow-hidden mb-3">
        {SEVERITY_ORDER.map((sev) => {
          const count = severityCounts[sev];
          if (count === 0) return null;
          const width = (count / totalFindings) * 100;
          return (
            <div
              key={sev}
              className={`${SEVERITY_CONFIG[sev].bgColor} transition-all`}
              style={{ width: `${width}%` }}
              title={`${SEVERITY_CONFIG[sev].label}: ${count}`}
            />
          );
        })}
      </div>

      {/* Severity count chips */}
      <div className="flex flex-wrap gap-1.5 mb-3">
        <button
          onClick={() => setFilter('all')}
          className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
            filter === 'all'
              ? 'bg-gray-600 text-white'
              : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
          }`}
        >
          All {totalFindings}
        </button>
        {SEVERITY_ORDER.map((sev) => {
          const count = severityCounts[sev];
          if (count === 0) return null;
          return (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                filter === sev
                  ? 'bg-gray-600 text-white'
                  : `bg-gray-800 ${SEVERITY_CONFIG[sev].color} hover:bg-gray-700`
              }`}
            >
              {SEVERITY_CONFIG[sev].label} {count}
            </button>
          );
        })}
      </div>

      {/* Findings list */}
      <div className="flex-1 overflow-y-auto space-y-2">
        {sortedFindings.map((finding) => {
          const isExpanded = expandedId === finding.id;
          const config = SEVERITY_CONFIG[finding.severity];

          return (
            <div
              key={finding.id}
              className="bg-gray-900 rounded-lg border border-gray-700 overflow-hidden"
            >
              {/* Header */}
              <button
                onClick={() => {
                  setExpandedId(isExpanded ? null : finding.id);
                  onViewFinding?.(finding);
                }}
                className="w-full text-left p-3 hover:bg-gray-800/50 transition-colors"
              >
                <div className="flex items-start space-x-2">
                  <span
                    className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${config.bgColor} text-white flex-shrink-0 mt-0.5`}
                  >
                    {finding.severity}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5">
                      <p className="text-sm font-medium text-white truncate">{finding.title}</p>
                      {/* Validation status badge */}
                      {finding.validationStatus && (
                        <span
                          className={`inline-block px-1.5 py-0.5 rounded text-[9px] font-bold uppercase flex-shrink-0 ${VALIDATION_BADGE[finding.validationStatus].color}`}
                        >
                          {VALIDATION_BADGE[finding.validationStatus].icon} {VALIDATION_BADGE[finding.validationStatus].label}
                          {finding.validationEvidence && finding.validationEvidence.length > 0
                            ? ` (${finding.validationEvidence.length})`
                            : ''}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-gray-500 mt-0.5 truncate">
                      {finding.agentId} &middot; {finding.target}
                      {/* Duplicate check inline indicator */}
                      {(() => {
                        const dupLabel = getDuplicateLabel(finding.duplicateCheck);
                        return dupLabel ? (
                          <span className={`ml-2 ${dupLabel.color}`}>&middot; {dupLabel.label}</span>
                        ) : null;
                      })()}
                    </p>
                  </div>
                </div>
              </button>

              {/* Expanded details */}
              {isExpanded && (
                <div className="px-3 pb-3 border-t border-gray-800">
                  <p className="text-xs text-gray-300 mt-2 whitespace-pre-wrap">
                    {finding.description}
                  </p>

                  {finding.evidence.length > 0 && (
                    <div className="mt-2">
                      <p className="text-[10px] font-semibold text-gray-500 uppercase mb-1">
                        Evidence
                      </p>
                      {finding.evidence.map((ev, i) => (
                        <p key={i} className="text-xs text-gray-400 font-mono break-all">
                          {ev}
                        </p>
                      ))}
                    </div>
                  )}

                  {finding.reproduction.length > 0 && (
                    <div className="mt-2">
                      <p className="text-[10px] font-semibold text-gray-500 uppercase mb-1">
                        Reproduction Steps
                      </p>
                      <ol className="list-decimal list-inside">
                        {finding.reproduction.map((step, i) => (
                          <li key={i} className="text-xs text-gray-400">
                            {step}
                          </li>
                        ))}
                      </ol>
                    </div>
                  )}

                  {/* Validation evidence (Phase 3) */}
                  {finding.validationEvidence && finding.validationEvidence.length > 0 && (
                    <div className="mt-2">
                      <p className="text-[10px] font-semibold text-green-500 uppercase mb-1">
                        Validation Evidence ({finding.validationEvidence.length})
                      </p>
                      {finding.validationEvidence.map((ev, i) => (
                        <div key={i} className="mb-1">
                          <span className="text-[10px] text-gray-500 uppercase">{ev.type}</span>
                          <p className="text-xs text-gray-400 font-mono break-all">{ev.description}</p>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Duplicate check details (Phase 3) */}
                  {finding.duplicateCheck && finding.duplicateCheck.status !== 'not_checked' && (
                    <div className="mt-2">
                      <p className="text-[10px] font-semibold text-gray-500 uppercase mb-1">
                        Duplicate Check
                      </p>
                      {(() => {
                        const dupLabel = getDuplicateLabel(finding.duplicateCheck);
                        return dupLabel ? (
                          <p className={`text-xs ${dupLabel.color}`}>{dupLabel.label}
                            {finding.duplicateCheck.score ? ` (${finding.duplicateCheck.score.overall}%)` : ''}
                          </p>
                        ) : null;
                      })()}
                      {finding.duplicateCheck.topMatches?.map((match, i) => (
                        <p key={i} className="text-xs text-gray-400">
                          {match.source}: &ldquo;{match.title}&rdquo; ({Math.round(match.similarity * 100)}%)
                        </p>
                      ))}
                    </div>
                  )}

                  {onGenerateReport && (
                    <button
                      onClick={() => onGenerateReport(finding)}
                      className="mt-3 w-full px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-xs font-semibold rounded transition-colors"
                    >
                      Generate Report
                    </button>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Generate report for all findings */}
      {onGenerateReport && totalFindings > 0 && (
        <div className="pt-3 mt-3 border-t border-gray-700">
          <button
            onClick={() => {
              // Report the highest severity finding
              const best = sortedFindings[0];
              if (best) onGenerateReport(best);
            }}
            className="w-full px-3 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-semibold rounded transition-colors"
          >
            Generate Report
          </button>
        </div>
      )}
    </div>
  );
};

export default FindingsPanel;

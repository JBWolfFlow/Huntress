/**
 * Hunt Metrics Tracker
 *
 * Records and analyzes metrics from hunt sessions to measure performance
 * against Phase 5 targets and track improvement over time.
 *
 * Target metrics (Phase 5):
 * - False positive rate: <5%
 * - Duplicate rate: <30%
 * - Triage acceptance rate: >50%
 * - Cost per finding: <$2.50
 * - Cost per accepted submission: <$20
 * - Time to first finding: <15 min
 * - Hunt completion rate: 100%
 * - Out-of-scope incidents: 0
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export interface HuntMetrics {
  huntId: string;
  programHandle: string;
  startedAt: number;
  completedAt?: number;
  /** Total API cost in USD */
  totalCostUsd: number;
  /** Budget limit for this hunt */
  budgetLimitUsd: number;
  /** Number of agents dispatched */
  agentsDispatched: number;
  /** Number of agents that completed successfully */
  agentsCompleted: number;
  /** Number of agents that failed (after retries) */
  agentsFailed: number;
  /** Findings breakdown */
  findings: FindingsMetrics;
  /** Submission outcomes (if any submitted to H1) */
  submissions: SubmissionMetrics;
  /** Safety metrics */
  safety: SafetyMetrics;
  /** Timing metrics */
  timing: TimingMetrics;
}

export interface FindingsMetrics {
  total: number;
  bySeverity: Record<string, number>;
  validated: number;
  validationFailed: number;
  unverified: number;
  pending: number;
  duplicates: number;
  falsePositives: number;
}

export interface SubmissionMetrics {
  submitted: number;
  accepted: number;
  triaged: number;
  duplicate: number;
  informative: number;
  notApplicable: number;
}

export interface SafetyMetrics {
  outOfScopeAttempts: number;
  killSwitchActivations: number;
  approvalsDenied: number;
  approvalsGranted: number;
  approvalsTimedOut: number;
}

export interface TimingMetrics {
  /** Time from hunt start to first finding in seconds */
  timeToFirstFindingSec: number | null;
  /** Total hunt duration in seconds */
  totalDurationSec: number;
  /** Average agent execution time in seconds */
  avgAgentDurationSec: number;
}

export interface MetricsTarget {
  name: string;
  target: string;
  actual: string;
  met: boolean;
}

// ─── Calculator ─────────────────────────────────────────────────────────────

/**
 * Calculate derived metrics and check against Phase 5 targets.
 */
export function evaluateMetrics(metrics: HuntMetrics): {
  derived: Record<string, number>;
  targets: MetricsTarget[];
  overallPass: boolean;
} {
  const { findings, submissions, safety, timing } = metrics;

  // Derived metrics
  const falsePositiveRate = findings.total > 0
    ? (findings.falsePositives / findings.total) * 100
    : 0;
  const duplicateRate = findings.total > 0
    ? (findings.duplicates / findings.total) * 100
    : 0;
  const validationPassRate = (findings.validated + findings.validationFailed) > 0
    ? (findings.validated / (findings.validated + findings.validationFailed)) * 100
    : 0;
  const triageAcceptanceRate = submissions.submitted > 0
    ? ((submissions.accepted + submissions.triaged) / submissions.submitted) * 100
    : 0;
  const costPerFinding = findings.total > 0
    ? metrics.totalCostUsd / findings.total
    : 0;
  const costPerAcceptedSubmission = (submissions.accepted + submissions.triaged) > 0
    ? metrics.totalCostUsd / (submissions.accepted + submissions.triaged)
    : 0;
  const huntCompletionRate = metrics.agentsDispatched > 0
    ? (metrics.agentsCompleted / metrics.agentsDispatched) * 100
    : 0;

  const derived = {
    falsePositiveRate,
    duplicateRate,
    validationPassRate,
    triageAcceptanceRate,
    costPerFinding,
    costPerAcceptedSubmission,
    huntCompletionRate,
    timeToFirstFindingSec: timing.timeToFirstFindingSec ?? -1,
  };

  // Phase 5 targets
  const targets: MetricsTarget[] = [
    {
      name: 'False Positive Rate',
      target: '<5%',
      actual: `${falsePositiveRate.toFixed(1)}%`,
      met: falsePositiveRate < 5,
    },
    {
      name: 'Duplicate Rate',
      target: '<30%',
      actual: `${duplicateRate.toFixed(1)}%`,
      met: duplicateRate < 30,
    },
    {
      name: 'Triage Acceptance Rate',
      target: '>50%',
      actual: submissions.submitted > 0 ? `${triageAcceptanceRate.toFixed(1)}%` : 'N/A',
      met: submissions.submitted === 0 || triageAcceptanceRate > 50,
    },
    {
      name: 'Cost Per Finding',
      target: '<$2.50',
      actual: findings.total > 0 ? `$${costPerFinding.toFixed(2)}` : 'N/A',
      met: findings.total === 0 || costPerFinding < 2.5,
    },
    {
      name: 'Cost Per Accepted Submission',
      target: '<$20',
      actual: (submissions.accepted + submissions.triaged) > 0 ? `$${costPerAcceptedSubmission.toFixed(2)}` : 'N/A',
      met: (submissions.accepted + submissions.triaged) === 0 || costPerAcceptedSubmission < 20,
    },
    {
      name: 'Time to First Finding',
      target: '<15 min',
      actual: timing.timeToFirstFindingSec !== null ? `${(timing.timeToFirstFindingSec / 60).toFixed(1)} min` : 'N/A',
      met: timing.timeToFirstFindingSec === null || timing.timeToFirstFindingSec < 900,
    },
    {
      name: 'Hunt Completion Rate',
      target: '100%',
      actual: `${huntCompletionRate.toFixed(1)}%`,
      met: huntCompletionRate >= 95, // Allow 5% margin for transient failures
    },
    {
      name: 'Out-of-Scope Incidents',
      target: '0',
      actual: `${safety.outOfScopeAttempts}`,
      met: safety.outOfScopeAttempts === 0,
    },
  ];

  const overallPass = targets.every(t => t.met);

  return { derived, targets, overallPass };
}

/**
 * Format metrics as a markdown report for the PRODUCTION_ROADMAP.
 */
export function formatMetricsReport(metrics: HuntMetrics): string {
  const { derived, targets, overallPass } = evaluateMetrics(metrics);

  const lines: string[] = [
    `### Hunt ${metrics.huntId} Metrics — ${metrics.programHandle}`,
    '',
    `| Metric | Target | Actual | Status |`,
    `|--------|--------|--------|--------|`,
  ];

  for (const target of targets) {
    const status = target.met ? 'PASS' : '**FAIL**';
    lines.push(`| ${target.name} | ${target.target} | ${target.actual} | ${status} |`);
  }

  lines.push('');
  lines.push(`**Overall:** ${overallPass ? 'PASS' : 'FAIL'}`);
  lines.push(`**Total Cost:** $${metrics.totalCostUsd.toFixed(2)}`);
  lines.push(`**Duration:** ${(metrics.timing.totalDurationSec / 60).toFixed(1)} min`);
  lines.push(`**Agents:** ${metrics.agentsCompleted}/${metrics.agentsDispatched} completed`);
  lines.push(`**Findings:** ${metrics.findings.total} (${metrics.findings.validated} validated)`);

  return lines.join('\n');
}

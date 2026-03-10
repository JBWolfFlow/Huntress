/**
 * HackerOne Feedback Loop
 *
 * After report submission, monitors HackerOne for triage outcomes and
 * feeds results back into the system for continuous improvement:
 *
 * - When triaged: record severity confirmation/adjustment
 * - When resolved: record bounty amount
 * - When duplicate: record the original report ID
 * - When not applicable / informative: record downgrade reason
 *
 * All outcomes are stored for:
 * - Duplicate detection calibration (fewer dupes over time)
 * - Severity prediction refinement
 * - Agent strategy scoring (which approaches yield bounties)
 * - Training data for LoRA fine-tuning
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type ReportStatus =
  | 'new'
  | 'triaged'
  | 'needs-more-info'
  | 'resolved'
  | 'not-applicable'
  | 'informative'
  | 'duplicate'
  | 'spam';

export interface SubmittedReport {
  /** Internal report ID */
  internalId: string;
  /** HackerOne report ID (after submission) */
  h1ReportId?: string;
  /** Original finding data */
  finding: {
    title: string;
    vulnerabilityType: string;
    severity: string;
    target: string;
    agentId: string;
    cvssScore?: number;
  };
  /** Submission timestamp */
  submittedAt: number;
  /** Current H1 status */
  status: ReportStatus;
  /** H1 assigned severity (may differ from our prediction) */
  h1Severity?: string;
  /** Bounty amount (when resolved) */
  bountyAmount?: number;
  /** Whether it was marked as duplicate */
  isDuplicate?: boolean;
  /** Original report ID if duplicate */
  duplicateOfId?: string;
  /** H1 analyst comments */
  comments: TriageComment[];
  /** Last time we checked the status */
  lastPolledAt: number;
  /** Whether we've finished processing this report */
  finalized: boolean;
}

export interface TriageComment {
  author: string;
  content: string;
  timestamp: number;
}

export interface FeedbackStats {
  totalSubmitted: number;
  triaged: number;
  resolved: number;
  duplicates: number;
  notApplicable: number;
  informative: number;
  pending: number;
  totalBounties: number;
  averageBounty: number;
  duplicateRate: number;
  /** Agent performance: agent_id → { submitted, triaged, resolved, bounties } */
  agentPerformance: Map<string, AgentPerformance>;
  /** Vulnerability type performance */
  vulnTypePerformance: Map<string, VulnTypePerformance>;
}

export interface AgentPerformance {
  submitted: number;
  triaged: number;
  resolved: number;
  totalBounties: number;
  duplicates: number;
}

export interface VulnTypePerformance {
  submitted: number;
  resolved: number;
  totalBounties: number;
  averageBounty: number;
  duplicateRate: number;
}

export interface FeedbackLoopConfig {
  /** Poll interval in milliseconds (default: 1 hour) */
  pollInterval?: number;
  /** HackerOne API fetch function */
  fetchReportStatus?: (h1ReportId: string) => Promise<{
    status: ReportStatus;
    severity?: string;
    bountyAmount?: number;
    duplicateOfId?: string;
    comments: TriageComment[];
  }>;
  /** Callback when a report status changes */
  onStatusChange?: (report: SubmittedReport, oldStatus: ReportStatus) => void;
  /** Callback when feedback stats are updated */
  onStatsUpdate?: (stats: FeedbackStats) => void;
}

// ─── Feedback Loop ───────────────────────────────────────────────────────────

export class FeedbackLoop {
  private reports: Map<string, SubmittedReport> = new Map();
  private config: FeedbackLoopConfig;
  private pollTimer?: ReturnType<typeof setInterval>;
  private running = false;

  constructor(config: FeedbackLoopConfig = {}) {
    this.config = {
      pollInterval: 3_600_000, // 1 hour
      ...config,
    };
  }

  /** Register a submitted report for tracking */
  trackReport(report: SubmittedReport): void {
    this.reports.set(report.internalId, report);
  }

  /** Start polling for status updates */
  startPolling(): void {
    if (this.running) return;
    this.running = true;

    this.pollTimer = setInterval(async () => {
      await this.pollAllReports();
    }, this.config.pollInterval);
  }

  /** Stop polling */
  stopPolling(): void {
    this.running = false;
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = undefined;
    }
  }

  /** Manually poll all active reports */
  async pollAllReports(): Promise<void> {
    const activeReports = Array.from(this.reports.values())
      .filter(r => !r.finalized && r.h1ReportId);

    for (const report of activeReports) {
      await this.pollReport(report);
    }

    this.config.onStatsUpdate?.(this.getStats());
  }

  /** Poll a single report */
  private async pollReport(report: SubmittedReport): Promise<void> {
    if (!this.config.fetchReportStatus || !report.h1ReportId) return;

    try {
      const status = await this.config.fetchReportStatus(report.h1ReportId);
      const oldStatus = report.status;

      report.status = status.status;
      report.lastPolledAt = Date.now();

      if (status.severity) report.h1Severity = status.severity;
      if (status.bountyAmount) report.bountyAmount = status.bountyAmount;
      if (status.duplicateOfId) {
        report.isDuplicate = true;
        report.duplicateOfId = status.duplicateOfId;
      }
      if (status.comments.length > report.comments.length) {
        report.comments = status.comments;
      }

      // Mark as finalized if in a terminal state
      if (['resolved', 'not-applicable', 'informative', 'duplicate', 'spam'].includes(status.status)) {
        report.finalized = true;
      }

      // Notify on status change
      if (oldStatus !== report.status) {
        this.config.onStatusChange?.(report, oldStatus);
      }
    } catch {
      // Poll error — will retry next interval
    }
  }

  /** Get comprehensive feedback statistics */
  getStats(): FeedbackStats {
    const reports = Array.from(this.reports.values());

    const agentPerf = new Map<string, AgentPerformance>();
    const vulnPerf = new Map<string, VulnTypePerformance>();

    for (const report of reports) {
      // Agent performance
      const agentId = report.finding.agentId;
      if (!agentPerf.has(agentId)) {
        agentPerf.set(agentId, { submitted: 0, triaged: 0, resolved: 0, totalBounties: 0, duplicates: 0 });
      }
      const ap = agentPerf.get(agentId)!;
      ap.submitted++;
      if (['triaged', 'resolved'].includes(report.status)) ap.triaged++;
      if (report.status === 'resolved') {
        ap.resolved++;
        ap.totalBounties += report.bountyAmount ?? 0;
      }
      if (report.isDuplicate) ap.duplicates++;

      // Vuln type performance
      const vulnType = report.finding.vulnerabilityType;
      if (!vulnPerf.has(vulnType)) {
        vulnPerf.set(vulnType, { submitted: 0, resolved: 0, totalBounties: 0, averageBounty: 0, duplicateRate: 0 });
      }
      const vp = vulnPerf.get(vulnType)!;
      vp.submitted++;
      if (report.status === 'resolved') {
        vp.resolved++;
        vp.totalBounties += report.bountyAmount ?? 0;
      }
    }

    // Calculate averages
    for (const [, vp] of vulnPerf) {
      vp.averageBounty = vp.resolved > 0 ? vp.totalBounties / vp.resolved : 0;
      vp.duplicateRate = vp.submitted > 0
        ? reports.filter(r => r.finding.vulnerabilityType === r.finding.vulnerabilityType && r.isDuplicate).length / vp.submitted
        : 0;
    }

    const resolved = reports.filter(r => r.status === 'resolved');
    const totalBounties = resolved.reduce((sum, r) => sum + (r.bountyAmount ?? 0), 0);
    const duplicates = reports.filter(r => r.isDuplicate);

    return {
      totalSubmitted: reports.length,
      triaged: reports.filter(r => ['triaged', 'resolved'].includes(r.status)).length,
      resolved: resolved.length,
      duplicates: duplicates.length,
      notApplicable: reports.filter(r => r.status === 'not-applicable').length,
      informative: reports.filter(r => r.status === 'informative').length,
      pending: reports.filter(r => !r.finalized).length,
      totalBounties,
      averageBounty: resolved.length > 0 ? totalBounties / resolved.length : 0,
      duplicateRate: reports.length > 0 ? duplicates.length / reports.length : 0,
      agentPerformance: agentPerf,
      vulnTypePerformance: vulnPerf,
    };
  }

  /** Get all reports */
  getAllReports(): SubmittedReport[] {
    return Array.from(this.reports.values());
  }

  /** Get reports by status */
  getReportsByStatus(status: ReportStatus): SubmittedReport[] {
    return Array.from(this.reports.values()).filter(r => r.status === status);
  }

  /** Export all feedback data for training */
  exportTrainingData(): Array<{
    finding: SubmittedReport['finding'];
    outcome: {
      status: ReportStatus;
      h1Severity?: string;
      bountyAmount?: number;
      isDuplicate: boolean;
    };
  }> {
    return Array.from(this.reports.values())
      .filter(r => r.finalized)
      .map(r => ({
        finding: r.finding,
        outcome: {
          status: r.status,
          h1Severity: r.h1Severity,
          bountyAmount: r.bountyAmount,
          isDuplicate: r.isDuplicate ?? false,
        },
      }));
  }

  /** Get insights and recommendations based on feedback */
  getInsights(): string[] {
    const stats = this.getStats();
    const insights: string[] = [];

    if (stats.duplicateRate > 0.3) {
      insights.push(`High duplicate rate (${Math.round(stats.duplicateRate * 100)}%). Consider improving duplicate detection before submission.`);
    }

    // Find best-performing agent
    let bestAgent = '';
    let bestBounties = 0;
    for (const [agentId, perf] of stats.agentPerformance) {
      if (perf.totalBounties > bestBounties) {
        bestBounties = perf.totalBounties;
        bestAgent = agentId;
      }
    }
    if (bestAgent) {
      insights.push(`Best-performing agent: ${bestAgent} ($${bestBounties} total bounties).`);
    }

    // Find best vulnerability type
    let bestVuln = '';
    let bestAvg = 0;
    for (const [vulnType, perf] of stats.vulnTypePerformance) {
      if (perf.averageBounty > bestAvg && perf.resolved >= 2) {
        bestAvg = perf.averageBounty;
        bestVuln = vulnType;
      }
    }
    if (bestVuln) {
      insights.push(`Highest-paying vulnerability type: ${bestVuln} ($${Math.round(bestAvg)} avg bounty).`);
    }

    if (stats.totalSubmitted > 0 && stats.resolved === 0) {
      insights.push('No reports resolved yet. Review triage feedback to improve submission quality.');
    }

    return insights;
  }
}

export default FeedbackLoop;

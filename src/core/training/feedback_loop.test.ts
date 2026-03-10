/**
 * FeedbackLoop — Unit Tests
 *
 * Tests report tracking, status polling, performance stats,
 * and training data export.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { FeedbackLoop, type SubmittedReport } from './feedback_loop';

function createMockReport(overrides?: Partial<SubmittedReport>): SubmittedReport {
  return {
    internalId: `report_${Date.now()}_${Math.random().toString(36).substring(2)}`,
    finding: {
      title: 'Test XSS',
      vulnerabilityType: 'xss',
      severity: 'high',
      target: 'example.com',
      agentId: 'xss_hunter',
    },
    submittedAt: Date.now(),
    status: 'new',
    comments: [],
    lastPolledAt: Date.now(),
    finalized: false,
    ...overrides,
  };
}

describe('FeedbackLoop', () => {
  let loop: FeedbackLoop;

  beforeEach(() => {
    loop = new FeedbackLoop();
  });

  afterEach(() => {
    loop.stopPolling();
  });

  describe('trackReport', () => {
    it('should register a report for tracking', () => {
      const report = createMockReport();
      loop.trackReport(report);

      const all = loop.getAllReports();
      expect(all).toHaveLength(1);
      expect(all[0].internalId).toBe(report.internalId);
    });
  });

  describe('getStats', () => {
    it('should return correct stats for empty state', () => {
      const stats = loop.getStats();
      expect(stats.totalSubmitted).toBe(0);
      expect(stats.triaged).toBe(0);
      expect(stats.duplicateRate).toBe(0);
    });

    it('should calculate stats correctly with multiple reports', () => {
      loop.trackReport(createMockReport({ status: 'triaged' }));
      loop.trackReport(createMockReport({ status: 'resolved', bountyAmount: 500 }));
      loop.trackReport(createMockReport({ status: 'duplicate', isDuplicate: true, finalized: true }));
      loop.trackReport(createMockReport({ status: 'not-applicable', finalized: true }));

      const stats = loop.getStats();
      expect(stats.totalSubmitted).toBe(4);
      expect(stats.triaged).toBe(2); // triaged + resolved
      expect(stats.resolved).toBe(1);
      expect(stats.duplicates).toBe(1);
      expect(stats.notApplicable).toBe(1);
      expect(stats.totalBounties).toBe(500);
      expect(stats.averageBounty).toBe(500);
      expect(stats.duplicateRate).toBe(0.25);
    });

    it('should track agent performance', () => {
      loop.trackReport(createMockReport({
        finding: { title: 'XSS 1', vulnerabilityType: 'xss', severity: 'high', target: 'a.com', agentId: 'xss_hunter' },
        status: 'resolved',
        bountyAmount: 1000,
      }));
      loop.trackReport(createMockReport({
        finding: { title: 'XSS 2', vulnerabilityType: 'xss', severity: 'medium', target: 'b.com', agentId: 'xss_hunter' },
        status: 'triaged',
      }));
      loop.trackReport(createMockReport({
        finding: { title: 'SQLi 1', vulnerabilityType: 'sqli', severity: 'critical', target: 'c.com', agentId: 'sqli_hunter' },
        status: 'resolved',
        bountyAmount: 5000,
      }));

      const stats = loop.getStats();
      const xssPerf = stats.agentPerformance.get('xss_hunter');
      expect(xssPerf).toBeDefined();
      expect(xssPerf!.submitted).toBe(2);
      expect(xssPerf!.resolved).toBe(1);
      expect(xssPerf!.totalBounties).toBe(1000);

      const sqliPerf = stats.agentPerformance.get('sqli_hunter');
      expect(sqliPerf).toBeDefined();
      expect(sqliPerf!.totalBounties).toBe(5000);
    });
  });

  describe('getReportsByStatus', () => {
    it('should filter reports by status', () => {
      loop.trackReport(createMockReport({ status: 'triaged' }));
      loop.trackReport(createMockReport({ status: 'resolved' }));
      loop.trackReport(createMockReport({ status: 'triaged' }));

      expect(loop.getReportsByStatus('triaged')).toHaveLength(2);
      expect(loop.getReportsByStatus('resolved')).toHaveLength(1);
      expect(loop.getReportsByStatus('duplicate')).toHaveLength(0);
    });
  });

  describe('exportTrainingData', () => {
    it('should only export finalized reports', () => {
      loop.trackReport(createMockReport({ status: 'new', finalized: false }));
      loop.trackReport(createMockReport({ status: 'resolved', finalized: true, bountyAmount: 500 }));
      loop.trackReport(createMockReport({ status: 'duplicate', finalized: true, isDuplicate: true }));

      const training = loop.exportTrainingData();
      expect(training).toHaveLength(2); // Only the 2 finalized ones
      expect(training[0].outcome.status).toBe('resolved');
      expect(training[1].outcome.isDuplicate).toBe(true);
    });
  });

  describe('getInsights', () => {
    it('should flag high duplicate rate', () => {
      // Create 4 reports, 2 duplicates = 50% rate
      loop.trackReport(createMockReport({ status: 'resolved', finalized: true }));
      loop.trackReport(createMockReport({ status: 'resolved', finalized: true }));
      loop.trackReport(createMockReport({ status: 'duplicate', isDuplicate: true, finalized: true }));
      loop.trackReport(createMockReport({ status: 'duplicate', isDuplicate: true, finalized: true }));

      const insights = loop.getInsights();
      expect(insights.some(i => i.includes('duplicate'))).toBe(true);
    });

    it('should identify best-performing agent', () => {
      loop.trackReport(createMockReport({
        finding: { title: 'F1', vulnerabilityType: 'xss', severity: 'high', target: 'a.com', agentId: 'xss_hunter' },
        status: 'resolved',
        bountyAmount: 5000,
      }));

      const insights = loop.getInsights();
      expect(insights.some(i => i.includes('xss_hunter'))).toBe(true);
    });
  });

  describe('pollAllReports', () => {
    it('should poll active reports with fetchReportStatus', async () => {
      const fetchReportStatus = vi.fn().mockResolvedValue({
        status: 'triaged',
        severity: 'high',
        comments: [],
      });

      const loop = new FeedbackLoop({ fetchReportStatus });
      loop.trackReport(createMockReport({
        h1ReportId: 'h1_12345',
        status: 'new',
      }));

      await loop.pollAllReports();

      expect(fetchReportStatus).toHaveBeenCalledWith('h1_12345');
      const reports = loop.getAllReports();
      expect(reports[0].status).toBe('triaged');

      loop.stopPolling();
    });

    it('should call onStatusChange when status changes', async () => {
      const onStatusChange = vi.fn();
      const fetchReportStatus = vi.fn().mockResolvedValue({
        status: 'resolved',
        bountyAmount: 1000,
        comments: [],
      });

      const loop = new FeedbackLoop({ fetchReportStatus, onStatusChange });
      loop.trackReport(createMockReport({
        h1ReportId: 'h1_99999',
        status: 'triaged',
      }));

      await loop.pollAllReports();

      expect(onStatusChange).toHaveBeenCalled();
      expect(onStatusChange.mock.calls[0][1]).toBe('triaged'); // old status

      loop.stopPolling();
    });
  });
});

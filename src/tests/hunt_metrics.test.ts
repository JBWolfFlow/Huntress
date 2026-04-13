/**
 * Tests for Hunt Metrics Tracker
 */

import { describe, it, expect } from 'vitest';
import {
  evaluateMetrics,
  formatMetricsReport,
  type HuntMetrics,
} from '../core/orchestrator/hunt_metrics';

const GOOD_HUNT: HuntMetrics = {
  huntId: '#6',
  programHandle: 'juice-shop',
  startedAt: Date.now() - 600000,
  completedAt: Date.now(),
  totalCostUsd: 12.50,
  budgetLimitUsd: 15,
  agentsDispatched: 20,
  agentsCompleted: 19,
  agentsFailed: 1,
  findings: {
    total: 8,
    bySeverity: { critical: 2, high: 3, medium: 2, low: 1 },
    validated: 6,
    validationFailed: 1,
    unverified: 0,
    pending: 1,
    duplicates: 2,
    falsePositives: 0,
  },
  submissions: {
    submitted: 0,
    accepted: 0,
    triaged: 0,
    duplicate: 0,
    informative: 0,
    notApplicable: 0,
  },
  safety: {
    outOfScopeAttempts: 0,
    killSwitchActivations: 0,
    approvalsDenied: 3,
    approvalsGranted: 15,
    approvalsTimedOut: 0,
  },
  timing: {
    timeToFirstFindingSec: 420,
    totalDurationSec: 600,
    avgAgentDurationSec: 30,
  },
};

const BAD_HUNT: HuntMetrics = {
  huntId: '#bad',
  programHandle: 'test',
  startedAt: Date.now() - 3600000,
  totalCostUsd: 50,
  budgetLimitUsd: 15,
  agentsDispatched: 20,
  agentsCompleted: 10,
  agentsFailed: 10,
  findings: {
    total: 10,
    bySeverity: { medium: 10 },
    validated: 2,
    validationFailed: 5,
    unverified: 3,
    pending: 0,
    duplicates: 4,
    falsePositives: 3,
  },
  submissions: {
    submitted: 3,
    accepted: 0,
    triaged: 0,
    duplicate: 2,
    informative: 1,
    notApplicable: 0,
  },
  safety: {
    outOfScopeAttempts: 2,
    killSwitchActivations: 1,
    approvalsDenied: 5,
    approvalsGranted: 10,
    approvalsTimedOut: 3,
  },
  timing: {
    timeToFirstFindingSec: 1800,
    totalDurationSec: 3600,
    avgAgentDurationSec: 180,
  },
};

describe('Hunt Metrics', () => {
  describe('evaluateMetrics', () => {
    it('good hunt passes all targets', () => {
      const result = evaluateMetrics(GOOD_HUNT);
      expect(result.overallPass).toBe(true);
      expect(result.targets.every(t => t.met)).toBe(true);
    });

    it('bad hunt fails multiple targets', () => {
      const result = evaluateMetrics(BAD_HUNT);
      expect(result.overallPass).toBe(false);
      const failures = result.targets.filter(t => !t.met);
      expect(failures.length).toBeGreaterThan(0);
    });

    it('calculates false positive rate correctly', () => {
      const result = evaluateMetrics(BAD_HUNT);
      expect(result.derived.falsePositiveRate).toBe(30); // 3/10 * 100
    });

    it('calculates duplicate rate correctly', () => {
      const result = evaluateMetrics(BAD_HUNT);
      expect(result.derived.duplicateRate).toBe(40); // 4/10 * 100
    });

    it('calculates cost per finding correctly', () => {
      const result = evaluateMetrics(GOOD_HUNT);
      expect(result.derived.costPerFinding).toBeCloseTo(1.5625); // 12.50/8
    });

    it('detects out-of-scope incidents', () => {
      const result = evaluateMetrics(BAD_HUNT);
      const scopeTarget = result.targets.find(t => t.name === 'Out-of-Scope Incidents');
      expect(scopeTarget!.met).toBe(false);
    });

    it('handles zero findings gracefully', () => {
      const emptyHunt: HuntMetrics = {
        ...GOOD_HUNT,
        findings: { total: 0, bySeverity: {}, validated: 0, validationFailed: 0, unverified: 0, pending: 0, duplicates: 0, falsePositives: 0 },
      };
      const result = evaluateMetrics(emptyHunt);
      expect(result.derived.falsePositiveRate).toBe(0);
      expect(result.derived.costPerFinding).toBe(0);
    });
  });

  describe('formatMetricsReport', () => {
    it('produces valid markdown table', () => {
      const report = formatMetricsReport(GOOD_HUNT);
      expect(report).toContain('| Metric | Target | Actual | Status |');
      expect(report).toContain('PASS');
      expect(report).toContain('juice-shop');
    });

    it('shows FAIL for bad metrics', () => {
      const report = formatMetricsReport(BAD_HUNT);
      expect(report).toContain('**FAIL**');
    });

    it('includes cost and duration', () => {
      const report = formatMetricsReport(GOOD_HUNT);
      expect(report).toContain('$12.50');
      expect(report).toContain('10.0 min');
    });
  });
});

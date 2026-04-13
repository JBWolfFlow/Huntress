/**
 * Tests for HackerOne Program Selector
 *
 * Verifies program scoring, ranking, VDP filtering, and hunt checklist.
 */

import { describe, it, expect } from 'vitest';
import {
  scoreProgram,
  rankPrograms,
  filterVDPs,
  generateHuntChecklist,
  type H1ProgramInfo,
} from '../core/orchestrator/program_selector';

// ─── Fixtures ───────────────────────────────────────────────────────────────

const VDP_PROGRAM: H1ProgramInfo = {
  handle: 'acme-vdp',
  name: 'Acme VDP',
  programType: 'vdp',
  scopeWidth: 15,
  bountyRange: { min: 0, max: 0 },
  avgResponseTimeHours: 48,
  reportsResolved90d: 8,
  acceptingSubmissions: true,
  scope: ['*.acme.com', 'api.acme.com'],
  technologies: ['React', 'Node.js', 'GraphQL'],
  apiTestingInScope: true,
  managedProgram: false,
};

const BBP_HIGH_VALUE: H1ProgramInfo = {
  handle: 'megacorp',
  name: 'MegaCorp BBP',
  programType: 'bbp',
  scopeWidth: 25,
  bountyRange: { min: 500, max: 10000 },
  avgResponseTimeHours: 24,
  reportsResolved90d: 3,
  acceptingSubmissions: true,
  scope: ['*.megacorp.com'],
  technologies: ['REST API', 'OAuth', 'JWT', 'Django'],
  apiTestingInScope: true,
  managedProgram: true,
};

const BBP_LOW_VALUE: H1ProgramInfo = {
  handle: 'smallco',
  name: 'SmallCo BBP',
  programType: 'bbp',
  scopeWidth: 2,
  bountyRange: { min: 50, max: 200 },
  avgResponseTimeHours: 720,
  reportsResolved90d: 60,
  acceptingSubmissions: true,
  scope: ['app.smallco.io'],
  technologies: [],
  apiTestingInScope: false,
  managedProgram: false,
};

const CLOSED_PROGRAM: H1ProgramInfo = {
  handle: 'closed',
  name: 'Closed Program',
  programType: 'bbp',
  scopeWidth: 10,
  bountyRange: { min: 1000, max: 5000 },
  avgResponseTimeHours: 24,
  reportsResolved90d: 5,
  acceptingSubmissions: false,
  scope: ['closed.example.com'],
  technologies: ['PHP'],
  apiTestingInScope: true,
  managedProgram: false,
};

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('Program Selector', () => {
  describe('scoreProgram', () => {
    it('scores VDP programs with reasonable score', () => {
      const score = scoreProgram(VDP_PROGRAM);
      expect(score.totalScore).toBeGreaterThan(40);
      expect(score.recommendation).not.toBe('skip');
    });

    it('scores high-value BBPs highest', () => {
      const score = scoreProgram(BBP_HIGH_VALUE);
      expect(score.totalScore).toBeGreaterThan(70);
      expect(score.recommendation).toBe('hunt');
    });

    it('scores low-value BBPs lower', () => {
      const score = scoreProgram(BBP_LOW_VALUE);
      expect(score.totalScore).toBeLessThan(50);
    });

    it('skips closed programs', () => {
      const score = scoreProgram(CLOSED_PROGRAM);
      expect(score.totalScore).toBe(0);
      expect(score.recommendation).toBe('skip');
      expect(score.reasoning).toContain('not accepting');
    });

    it('returns 6 scoring factors', () => {
      const score = scoreProgram(VDP_PROGRAM);
      expect(score.factors).toHaveLength(6);
    });

    it('all factor scores are 0-100', () => {
      const score = scoreProgram(BBP_HIGH_VALUE);
      for (const factor of score.factors) {
        expect(factor.score).toBeGreaterThanOrEqual(0);
        expect(factor.score).toBeLessThanOrEqual(100);
      }
    });
  });

  describe('rankPrograms', () => {
    it('ranks programs by score descending', () => {
      const ranked = rankPrograms([BBP_LOW_VALUE, VDP_PROGRAM, BBP_HIGH_VALUE, CLOSED_PROGRAM]);
      expect(ranked[0].program.handle).toBe('megacorp');
      expect(ranked[ranked.length - 1].program.handle).toBe('closed');
    });

    it('handles empty input', () => {
      const ranked = rankPrograms([]);
      expect(ranked).toHaveLength(0);
    });
  });

  describe('filterVDPs', () => {
    it('returns only VDP programs', () => {
      const vdps = filterVDPs([BBP_HIGH_VALUE, VDP_PROGRAM, BBP_LOW_VALUE]);
      expect(vdps).toHaveLength(1);
      expect(vdps[0].handle).toBe('acme-vdp');
    });

    it('excludes closed VDPs', () => {
      const closedVdp: H1ProgramInfo = { ...VDP_PROGRAM, acceptingSubmissions: false };
      const vdps = filterVDPs([closedVdp]);
      expect(vdps).toHaveLength(0);
    });
  });

  describe('generateHuntChecklist', () => {
    it('generates checklist with critical items', () => {
      const checklist = generateHuntChecklist(VDP_PROGRAM);
      expect(checklist.length).toBeGreaterThan(8);
      const criticalItems = checklist.filter(c => c.critical);
      expect(criticalItems.length).toBeGreaterThanOrEqual(6);
    });

    it('includes scope validation as critical and manual', () => {
      const checklist = generateHuntChecklist(VDP_PROGRAM);
      const scopeCheck = checklist.find(c => c.item.includes('Scope validated'));
      expect(scopeCheck).toBeDefined();
      expect(scopeCheck!.critical).toBe(true);
      expect(scopeCheck!.automated).toBe(false);
    });

    it('includes approval gates as critical', () => {
      const checklist = generateHuntChecklist(VDP_PROGRAM);
      const approvalCheck = checklist.find(c => c.item.includes('approval gates'));
      expect(approvalCheck).toBeDefined();
      expect(approvalCheck!.critical).toBe(true);
    });
  });

  describe('scoring edge cases', () => {
    it('API testing in scope boosts score', () => {
      const withApi = scoreProgram({ ...VDP_PROGRAM, apiTestingInScope: true });
      const withoutApi = scoreProgram({ ...VDP_PROGRAM, apiTestingInScope: false });
      expect(withApi.totalScore).toBeGreaterThan(withoutApi.totalScore);
    });

    it('GraphQL in tech stack boosts score', () => {
      const withGql = scoreProgram({ ...VDP_PROGRAM, technologies: ['GraphQL'] });
      const withoutGql = scoreProgram({ ...VDP_PROGRAM, technologies: [] });
      expect(withGql.totalScore).toBeGreaterThan(withoutGql.totalScore);
    });

    it('fast response time scores better', () => {
      const fast = scoreProgram({ ...VDP_PROGRAM, avgResponseTimeHours: 12 });
      const slow = scoreProgram({ ...VDP_PROGRAM, avgResponseTimeHours: 1000 });
      expect(fast.totalScore).toBeGreaterThan(slow.totalScore);
    });
  });
});

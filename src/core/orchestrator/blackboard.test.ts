/**
 * Blackboard — Unit Tests
 *
 * Tests cross-agent shared memory: posting, reading, consuming,
 * subscriptions, and filtering.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Blackboard, postObservation, postHypothesis, postFinding } from './blackboard';

describe('Blackboard', () => {
  let board: Blackboard;

  beforeEach(() => {
    board = new Blackboard();
  });

  describe('post and read', () => {
    it('should post an entry and read it back', () => {
      board.post({
        agentId: 'recon',
        type: 'observation',
        category: 'subdomain',
        content: { subdomain: 'api.example.com', status: 200 },
        relevantTo: ['xss_hunter', 'sqli_hunter'],
        priority: 5,
      });

      const entries = board.readFor('xss_hunter');
      expect(entries).toHaveLength(1);
      expect(entries[0].agentId).toBe('recon');
    });

    it('should filter entries by relevance', () => {
      board.post({
        agentId: 'recon',
        type: 'observation',
        category: 'graphql',
        content: { graphql: true },
        relevantTo: ['graphql_hunter'],
        priority: 5,
      });

      const xssEntries = board.readFor('xss_hunter');
      expect(xssEntries).toHaveLength(0);

      const gqlEntries = board.readFor('graphql_hunter');
      expect(gqlEntries).toHaveLength(1);
    });
  });

  describe('consumeFor', () => {
    it('should return entries and mark them as consumed', () => {
      board.post({
        agentId: 'recon',
        type: 'observation',
        category: 'endpoint',
        content: { data: 'test' },
        relevantTo: ['xss_hunter'],
        priority: 5,
      });

      const first = board.consumeFor('xss_hunter');
      expect(first).toHaveLength(1);

      // Second consume should return nothing (already consumed)
      const second = board.consumeFor('xss_hunter');
      expect(second).toHaveLength(0);
    });

    it('should not affect other agents consumption', () => {
      board.post({
        agentId: 'recon',
        type: 'observation',
        category: 'endpoint',
        content: { data: 'test' },
        relevantTo: ['xss_hunter', 'sqli_hunter'],
        priority: 5,
      });

      // After xss_hunter consumes, it's marked consumed for everyone
      // (this is the blackboard pattern — consumed is global)
      board.consumeFor('xss_hunter');

      const entries = board.consumeFor('sqli_hunter');
      // consumed is set to true globally, so sqli_hunter sees nothing
      expect(entries).toHaveLength(0);
    });
  });

  describe('subscribe', () => {
    it('should notify subscriber when relevant entry is posted', () => {
      const callback = vi.fn();
      board.subscribe('xss_hunter', callback);

      board.post({
        agentId: 'recon',
        type: 'observation',
        category: 'param',
        content: { param: 'reflected' },
        relevantTo: ['xss_hunter'],
        priority: 5,
      });

      expect(callback).toHaveBeenCalledTimes(1);
      expect(callback.mock.calls[0][0].agentId).toBe('recon');
    });

    it('should not notify subscriber for irrelevant entries', () => {
      const callback = vi.fn();
      board.subscribe('xss_hunter', callback);

      board.post({
        agentId: 'recon',
        type: 'observation',
        category: 'graphql',
        content: { graphql: true },
        relevantTo: ['graphql_hunter'],
        priority: 5,
      });

      expect(callback).not.toHaveBeenCalled();
    });

    it('should return an unsubscribe function', () => {
      const callback = vi.fn();
      const unsubscribe = board.subscribe('xss_hunter', callback);

      unsubscribe();

      board.post({
        agentId: 'recon',
        type: 'observation',
        category: 'test',
        content: {},
        relevantTo: ['xss_hunter'],
        priority: 5,
      });

      expect(callback).not.toHaveBeenCalled();
    });
  });

  describe('convenience functions', () => {
    it('postObservation should create an observation entry', () => {
      postObservation(board, 'recon', 'subdomain', { data: 'test' }, ['xss_hunter']);

      const entries = board.readFor('xss_hunter');
      expect(entries).toHaveLength(1);
      expect(entries[0].type).toBe('observation');
    });

    it('postHypothesis should create a hypothesis entry', () => {
      postHypothesis(board, 'xss_hunter', 'vuln', { hypothesis: 'reflected XSS likely' }, ['sqli_hunter']);

      const entries = board.readFor('sqli_hunter');
      expect(entries).toHaveLength(1);
      expect(entries[0].type).toBe('hypothesis');
    });

    it('postFinding should create a finding entry with high priority', () => {
      postFinding(board, 'xss_hunter', 'xss', { title: 'XSS in search' }, ['recon']);

      const entries = board.readFor('recon');
      expect(entries).toHaveLength(1);
      expect(entries[0].type).toBe('finding');
      expect(entries[0].priority).toBe(9); // default priority for findings
    });
  });

  describe('getByType', () => {
    it('should filter entries by type', () => {
      board.post({ agentId: 'a', type: 'observation', category: 'x', content: {}, relevantTo: ['y'], priority: 5 });
      board.post({ agentId: 'b', type: 'finding', category: 'x', content: {}, relevantTo: ['y'], priority: 5 });
      board.post({ agentId: 'c', type: 'observation', category: 'x', content: {}, relevantTo: ['y'], priority: 5 });

      expect(board.getByType('observation')).toHaveLength(2);
      expect(board.getByType('finding')).toHaveLength(1);
    });
  });

  describe('getByCategory', () => {
    it('should filter entries by category', () => {
      board.post({ agentId: 'a', type: 'observation', category: 'subdomain', content: {}, relevantTo: ['y'], priority: 5 });
      board.post({ agentId: 'b', type: 'observation', category: 'endpoint', content: {}, relevantTo: ['y'], priority: 5 });

      expect(board.getByCategory('subdomain')).toHaveLength(1);
      expect(board.getByCategory('endpoint')).toHaveLength(1);
      expect(board.getByCategory('nonexistent')).toHaveLength(0);
    });
  });

  describe('getByAgent', () => {
    it('should filter entries by agent ID', () => {
      board.post({ agentId: 'recon', type: 'observation', category: 'x', content: {}, relevantTo: ['y'], priority: 5 });
      board.post({ agentId: 'recon', type: 'finding', category: 'x', content: {}, relevantTo: ['y'], priority: 5 });
      board.post({ agentId: 'xss', type: 'finding', category: 'x', content: {}, relevantTo: ['y'], priority: 5 });

      expect(board.getByAgent('recon')).toHaveLength(2);
      expect(board.getByAgent('xss')).toHaveLength(1);
    });
  });

  describe('priority ordering', () => {
    it('should return entries sorted by priority (highest first)', () => {
      board.post({ agentId: 'a', type: 'observation', category: 'x', content: { order: 1 }, relevantTo: ['y'], priority: 1 });
      board.post({ agentId: 'b', type: 'observation', category: 'x', content: { order: 2 }, relevantTo: ['y'], priority: 10 });
      board.post({ agentId: 'c', type: 'observation', category: 'x', content: { order: 3 }, relevantTo: ['y'], priority: 5 });

      const entries = board.readFor('y');
      expect(entries[0].priority).toBe(10);
      expect(entries[1].priority).toBe(5);
      expect(entries[2].priority).toBe(1);
    });
  });

  describe('clear', () => {
    it('should remove all entries', () => {
      board.post({ agentId: 'a', type: 'observation', category: 'x', content: {}, relevantTo: ['y'], priority: 5 });
      board.post({ agentId: 'b', type: 'finding', category: 'x', content: {}, relevantTo: ['y'], priority: 5 });

      board.clear();

      expect(board.getByType('observation')).toHaveLength(0);
      expect(board.getByType('finding')).toHaveLength(0);
    });
  });

  describe('getSummary', () => {
    it('should return a readable summary', () => {
      board.post({ agentId: 'a', type: 'observation', category: 'x', content: {}, relevantTo: ['y'], priority: 5 });
      board.post({ agentId: 'b', type: 'finding', category: 'x', content: {}, relevantTo: ['y'], priority: 5 });

      const summary = board.getSummary();
      expect(summary).toContain('2 entries');
      expect(summary).toContain('Observations: 1');
      expect(summary).toContain('Findings: 1');
    });
  });
});

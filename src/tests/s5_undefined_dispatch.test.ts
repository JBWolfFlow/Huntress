/**
 * Session 12 — S5: Fix "Blocked dispatch: undefined is not in scope"
 *
 * Tests that:
 * 1. generateFollowUpTasks() inherits the parent target when finding.target is empty
 * 2. generateFollowUpTasks() skips findings when both finding and parent target are missing
 * 3. Follow-up tasks always have a non-empty target string
 */

import { describe, it, expect } from 'vitest';
import { TaskQueue } from '../core/orchestrator/task_queue';
import type { AgentResult, AgentFinding } from '../agents/base_agent';

/** Helper to build a minimal AgentFinding with overrides */
function makeFinding(overrides: Partial<AgentFinding>): AgentFinding {
  return {
    id: 'finding-1',
    agentId: 'xss-hunter',
    type: 'xss_reflected',
    title: 'Reflected XSS in search param',
    severity: 'high',
    description: 'XSS via q parameter',
    target: '',
    evidence: ['<script>alert(1)</script>'],
    reproduction: ['Navigate to /search?q=<script>alert(1)</script>'],
    timestamp: new Date(),
    ...overrides,
  };
}

/** Helper to build a minimal AgentResult */
function makeResult(findings: AgentFinding[]): AgentResult {
  return {
    taskId: 'task_1',
    agentId: 'xss-hunter',
    success: true,
    findings,
    toolsExecuted: 5,
    duration: 10000,
  };
}

describe('S5: generateFollowUpTasks target propagation', () => {
  it('uses finding.target when present', () => {
    const queue = new TaskQueue();
    const finding = makeFinding({
      type: 'xss_reflected',
      target: 'https://target.example.com/search',
    });
    const result = makeResult([finding]);

    const tasks = queue.generateFollowUpTasks(result, 'https://parent.example.com');

    expect(tasks.length).toBeGreaterThan(0);
    // Should use the finding's own target, not the parent
    for (const task of tasks) {
      expect(task.target).toBe('https://target.example.com/search');
    }
  });

  it('falls back to parentTarget when finding.target is empty', () => {
    const queue = new TaskQueue();
    const finding = makeFinding({
      type: 'xss_reflected',
      target: '', // Empty — should fall back
    });
    const result = makeResult([finding]);

    const tasks = queue.generateFollowUpTasks(result, 'https://parent.example.com');

    expect(tasks.length).toBeGreaterThan(0);
    for (const task of tasks) {
      expect(task.target).toBe('https://parent.example.com');
    }
  });

  it('falls back to parentTarget when finding.target is undefined-ish', () => {
    const queue = new TaskQueue();
    // Simulate an LLM agent that didn't set target at all
    const finding = makeFinding({
      type: 'sqli',
      target: undefined as unknown as string,
    });
    const result = makeResult([finding]);

    const tasks = queue.generateFollowUpTasks(result, 'https://parent.example.com');

    expect(tasks.length).toBeGreaterThan(0);
    for (const task of tasks) {
      expect(task.target).toBe('https://parent.example.com');
    }
  });

  it('skips findings when both finding and parent target are missing', () => {
    const queue = new TaskQueue();
    const finding = makeFinding({
      type: 'xss_reflected',
      target: '',
    });
    const result = makeResult([finding]);

    // No parent target either
    const tasks = queue.generateFollowUpTasks(result);

    expect(tasks).toHaveLength(0);
  });

  it('handles mixed findings — some with target, some without', () => {
    const queue = new TaskQueue();
    const findingWithTarget = makeFinding({
      type: 'xss_reflected',
      target: 'https://explicit.example.com',
    });
    const findingWithoutTarget = makeFinding({
      id: 'finding-2',
      type: 'sqli',
      target: '',
    });
    const result = makeResult([findingWithTarget, findingWithoutTarget]);

    const tasks = queue.generateFollowUpTasks(result, 'https://parent.example.com');

    expect(tasks.length).toBe(2);
    // First task from XSS finding — uses its own target
    expect(tasks[0].target).toBe('https://explicit.example.com');
    // Second task from SQLi finding — falls back to parent
    expect(tasks[1].target).toBe('https://parent.example.com');
  });

  it('generates follow-up tasks for redirect findings with parent fallback', () => {
    const queue = new TaskQueue();
    const finding = makeFinding({
      type: 'open_redirect',
      target: '',
    });
    const result = makeResult([finding]);

    const tasks = queue.generateFollowUpTasks(result, 'https://parent.example.com');

    expect(tasks.length).toBeGreaterThan(0);
    const ssrfTask = tasks.find(t => t.agentType === 'ssrf-hunter');
    expect(ssrfTask).toBeDefined();
    expect(ssrfTask!.target).toBe('https://parent.example.com');
  });

  it('generates follow-up tasks for subdomain findings with parent fallback', () => {
    const queue = new TaskQueue();
    const finding = makeFinding({
      type: 'subdomain',
      target: '',
    });
    const result = makeResult([finding]);

    const tasks = queue.generateFollowUpTasks(result, 'https://parent.example.com');

    expect(tasks.length).toBeGreaterThan(0);
    const reconTask = tasks.find(t => t.agentType === 'recon');
    expect(reconTask).toBeDefined();
    expect(reconTask!.target).toBe('https://parent.example.com');
  });
});

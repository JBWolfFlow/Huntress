/**
 * I1 — Specialist Request Routing
 *
 * Verifies that `specialist_request` pseudo-findings produced by the recon
 * agent are filtered OUT of the validation pipeline and routed to the
 * task queue as dispatch tasks instead.
 *
 * Fixes the Hunt #11 log-spam: "No validator available for type: specialist_request"
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { OrchestratorEngine } from '../core/orchestrator/orchestrator_engine';
import type { OrchestratorConfig } from '../core/orchestrator/orchestrator_engine';
import type { AgentFinding, AgentResult } from '../agents/base_agent';
import type { ProgramGuidelines } from '../components/GuidelinesImporter';
import type { HuntTask } from '../core/orchestrator/task_queue';
import { createMockProvider } from './integration/orchestrator_e2e.test';
import * as validator from '../core/validation/validator';

const guidelines: ProgramGuidelines = {
  programHandle: 'test_program',
  programName: 'Test Program',
  url: 'https://hackerone.com/test_program',
  scope: {
    inScope: ['*.test-target.com', 'api.test-target.com'],
    outOfScope: [],
  },
  bountyRange: { min: 100, max: 25000 },
  rules: [],
  severity: {
    critical: '$5,000',
    high: '$2,000',
    medium: '$500',
    low: '$100',
  },
  importedAt: new Date(),
};

function makeSpecialistRequestFinding(agentType: string, target: string, priority = 'high'): AgentFinding {
  return {
    id: `sr_${Math.random().toString(36).slice(2, 8)}`,
    agentId: 'recon',
    type: 'specialist_request',
    title: `Specialist requested: ${agentType}`,
    severity: 'info',
    description: `Discovered surface for ${agentType}`,
    target,
    evidence: [`Agent type: ${agentType}`, `Priority: ${priority}`],
    reproduction: [],
    timestamp: new Date(),
  };
}

function makeRealFinding(type: string, target: string): AgentFinding {
  return {
    id: `f_${Math.random().toString(36).slice(2, 8)}`,
    agentId: 'xss_hunter',
    type,
    title: `Reflected XSS at ${target}`,
    severity: 'high',
    description: 'XSS via q parameter',
    target,
    evidence: ['<script>alert(1)</script>'],
    reproduction: [],
    timestamp: new Date(),
  };
}

describe('I1 — specialist_request routing', () => {
  let validateFindingSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    // Spy on validateFinding to assert it is never invoked for specialist_request
    validateFindingSpy = vi.spyOn(validator, 'validateFinding').mockResolvedValue({
      findingId: 'stub',
      confirmed: false,
      evidence: [],
      reproductionSteps: [],
      confidence: 0,
      validatorUsed: 'stub',
      validationTime: 0,
    });
  });

  async function makeEngine(): Promise<{ engine: OrchestratorEngine }> {
    const { provider } = createMockProvider([]);
    const config: OrchestratorConfig = {
      provider,
      model: 'mock-model',
      maxConcurrentAgents: 1,
    };
    const engine = new OrchestratorEngine(config);
    await engine.initializeHuntSession({ ...guidelines, scope: { ...guidelines.scope } });
    return { engine };
  }

  it('filters specialist_request entries out of the validation pipeline', async () => {
    const { engine } = await makeEngine();
    // Access private handleAgentResult + huntSession via the cast escape hatch
    const anyEngine = engine as unknown as {
      huntSession: {
        taskQueue: {
          enqueue: (t: Omit<HuntTask, 'id' | 'status' | 'createdAt'>) => HuntTask;
          getAllTasks: () => HuntTask[];
          complete: (id: string, r: AgentResult) => void;
        };
        program: ProgramGuidelines;
        activeAgents: number;
        completedDispatches: number;
        allFindings: AgentFinding[];
      };
      handleAgentResult: (task: HuntTask, result: AgentResult) => AgentResult;
    };

    // Pre-seed a task so taskQueue.complete() has something to mark done
    const seedTask = anyEngine.huntSession.taskQueue.enqueue({
      description: 'recon',
      target: 'api.test-target.com',
      agentType: 'recon',
      priority: 50,
      dependencies: [],
      iterationBudget: 30,
      origin: 'initial',
      tags: ['recon'],
    });

    const result: AgentResult = {
      taskId: seedTask.id,
      agentId: 'recon',
      success: true,
      findings: [
        makeSpecialistRequestFinding('xss_hunter', 'api.test-target.com'),
        makeSpecialistRequestFinding('sqli_hunter', 'api.test-target.com', 'medium'),
      ],
      toolsExecuted: 3,
      duration: 1000,
    };

    anyEngine.handleAgentResult(seedTask, result);
    // Let fire-and-forget validators flush — they should NEVER be called anyway
    await new Promise(r => setTimeout(r, 10));

    expect(validateFindingSpy).not.toHaveBeenCalled();
  });

  it('enqueues a specialist_request as a dispatch task', async () => {
    const { engine } = await makeEngine();
    const anyEngine = engine as unknown as {
      huntSession: {
        taskQueue: {
          enqueue: (t: Omit<HuntTask, 'id' | 'status' | 'createdAt'>) => HuntTask;
          getAllTasks: () => HuntTask[];
          complete: (id: string, r: AgentResult) => void;
        };
      };
      handleAgentResult: (task: HuntTask, result: AgentResult) => AgentResult;
    };

    const seedTask = anyEngine.huntSession.taskQueue.enqueue({
      description: 'recon',
      target: 'api.test-target.com',
      agentType: 'recon',
      priority: 50,
      dependencies: [],
      iterationBudget: 30,
      origin: 'initial',
      tags: ['recon'],
    });

    const result: AgentResult = {
      taskId: seedTask.id,
      agentId: 'recon',
      success: true,
      findings: [makeSpecialistRequestFinding('xss_hunter', 'api.test-target.com', 'high')],
      toolsExecuted: 2,
      duration: 500,
    };

    anyEngine.handleAgentResult(seedTask, result);

    const xssTasks = anyEngine.huntSession.taskQueue
      .getAllTasks()
      .filter(t => t.agentType === 'xss_hunter');
    expect(xssTasks.length).toBe(1);
    expect(xssTasks[0].target).toBe('api.test-target.com');
    expect(xssTasks[0].priority).toBe(80); // 'high' → 80
    expect(xssTasks[0].tags).toContain('specialist_request');
  });

  it('does not double-enqueue a specialist_request for the same agent+target', async () => {
    const { engine } = await makeEngine();
    const anyEngine = engine as unknown as {
      huntSession: {
        taskQueue: {
          enqueue: (t: Omit<HuntTask, 'id' | 'status' | 'createdAt'>) => HuntTask;
          getAllTasks: () => HuntTask[];
          complete: (id: string, r: AgentResult) => void;
        };
      };
      handleAgentResult: (task: HuntTask, result: AgentResult) => AgentResult;
    };

    const seedTask = anyEngine.huntSession.taskQueue.enqueue({
      description: 'recon',
      target: 'api.test-target.com',
      agentType: 'recon',
      priority: 50,
      dependencies: [],
      iterationBudget: 30,
      origin: 'initial',
      tags: ['recon'],
    });

    const duplicateRequests: AgentResult = {
      taskId: seedTask.id,
      agentId: 'recon',
      success: true,
      findings: [
        makeSpecialistRequestFinding('xss_hunter', 'api.test-target.com'),
        makeSpecialistRequestFinding('xss_hunter', 'api.test-target.com'), // exact dup
      ],
      toolsExecuted: 1,
      duration: 100,
    };

    anyEngine.handleAgentResult(seedTask, duplicateRequests);

    const xssTasks = anyEngine.huntSession.taskQueue
      .getAllTasks()
      .filter(t => t.agentType === 'xss_hunter');
    expect(xssTasks.length).toBe(1);
  });

  it('still routes real findings through the validation pipeline', async () => {
    const { engine } = await makeEngine();
    const anyEngine = engine as unknown as {
      huntSession: {
        taskQueue: {
          enqueue: (t: Omit<HuntTask, 'id' | 'status' | 'createdAt'>) => HuntTask;
          getAllTasks: () => HuntTask[];
          complete: (id: string, r: AgentResult) => void;
        };
      };
      handleAgentResult: (task: HuntTask, result: AgentResult) => AgentResult;
    };

    const seedTask = anyEngine.huntSession.taskQueue.enqueue({
      description: 'xss',
      target: 'api.test-target.com/search',
      agentType: 'xss_hunter',
      priority: 80,
      dependencies: [],
      iterationBudget: 30,
      origin: 'initial',
      tags: ['xss_hunter'],
    });

    const mixed: AgentResult = {
      taskId: seedTask.id,
      agentId: 'xss_hunter',
      success: true,
      findings: [
        makeRealFinding('xss_reflected', 'api.test-target.com/search'),
        makeSpecialistRequestFinding('sqli_hunter', 'api.test-target.com'),
      ],
      toolsExecuted: 4,
      duration: 2000,
    };

    anyEngine.handleAgentResult(seedTask, mixed);
    // Yield to flush the fire-and-forget runFindingValidation
    await new Promise(r => setTimeout(r, 20));

    // validateFinding was called exactly once — for the real XSS, not the specialist_request
    expect(validateFindingSpy).toHaveBeenCalledTimes(1);
    const calledWith = validateFindingSpy.mock.calls[0][0] as { vulnerabilityType: string };
    expect(calledWith.vulnerabilityType).toBe('xss_reflected');
  });
});

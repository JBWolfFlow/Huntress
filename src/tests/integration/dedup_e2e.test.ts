/**
 * I7 — Cross-subdomain dedup E2E (Integration)
 *
 * Seeds findings on api/www/cdn.example.com with the same vuln type +
 * parameter, drives them through the orchestrator's handleAgentResult()
 * pipeline, and asserts they collapse to a single finding with the
 * highest severity retained.
 *
 * Complements `src/core/orchestrator/finding_dedup.test.ts`, which tests
 * the dedup function in isolation.
 */

import { describe, it, expect } from 'vitest';
import { OrchestratorEngine } from '../../core/orchestrator/orchestrator_engine';
import type { OrchestratorConfig } from '../../core/orchestrator/orchestrator_engine';
import type { AgentFinding, AgentResult } from '../../agents/base_agent';
import type { ProgramGuidelines } from '../../components/GuidelinesImporter';
import type { HuntTask } from '../../core/orchestrator/task_queue';
import { createMockProvider } from './orchestrator_e2e.test';

const guidelines: ProgramGuidelines = {
  programHandle: 'test_program',
  programName: 'Test Program',
  url: 'https://hackerone.com/test_program',
  scope: {
    inScope: ['*.example.com', 'api.example.com', 'www.example.com', 'cdn.example.com'],
    outOfScope: [],
  },
  bountyRange: { min: 100, max: 25000 },
  rules: [],
  severity: { critical: '$5k', high: '$2k', medium: '$500', low: '$100' },
  importedAt: new Date(),
};

type EngineInternals = {
  huntSession: {
    taskQueue: {
      enqueue: (t: Omit<HuntTask, 'id' | 'status' | 'createdAt'>) => HuntTask;
      getAllTasks: () => HuntTask[];
      complete: (id: string, r: AgentResult) => void;
    };
    allFindings: AgentFinding[];
    activeAgents: number;
    completedDispatches: number;
  };
  handleAgentResult: (task: HuntTask, result: AgentResult) => AgentResult;
};

async function makeEngine(): Promise<EngineInternals> {
  const { provider } = createMockProvider([]);
  const config: OrchestratorConfig = { provider, model: 'mock-model' };
  const engine = new OrchestratorEngine(config);
  await engine.initializeHuntSession({ ...guidelines, scope: { ...guidelines.scope } });
  return engine as unknown as EngineInternals;
}

function makeFinding(
  overrides: Partial<AgentFinding> & { target: string; severity: AgentFinding['severity'] }
): AgentFinding {
  return {
    id: `f_${Math.random().toString(36).slice(2, 8)}`,
    agentId: 'xss_hunter',
    type: 'xss_reflected',
    title: 'Reflected XSS in q parameter',
    description: 'XSS via q parameter on /search?q=...',
    evidence: ['<script>alert(1)</script>'],
    reproduction: ['curl ' + overrides.target + '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'],
    timestamp: new Date(),
    ...overrides,
  };
}

async function pumpFinding(engine: EngineInternals, finding: AgentFinding): Promise<void> {
  const seedTask = engine.huntSession.taskQueue.enqueue({
    description: 'test',
    target: finding.target,
    agentType: 'xss_hunter',
    priority: 50,
    dependencies: [],
    iterationBudget: 30,
    origin: 'initial',
    tags: ['xss_hunter'],
  });
  engine.handleAgentResult(seedTask, {
    taskId: seedTask.id,
    agentId: 'xss_hunter',
    success: true,
    findings: [finding],
    toolsExecuted: 5,
    duration: 1000,
  });
  // Yield to let fire-and-forget validators settle.
  await new Promise(r => setTimeout(r, 10));
}

describe('I7: cross-subdomain dedup E2E', () => {
  it('collapses same vuln across api/www/cdn subdomains to 1 finding', async () => {
    const engine = await makeEngine();

    await pumpFinding(engine, makeFinding({
      target: 'https://api.example.com/search?q=x',
      severity: 'medium',
    }));
    await pumpFinding(engine, makeFinding({
      target: 'https://www.example.com/search?q=x',
      severity: 'high',
    }));
    await pumpFinding(engine, makeFinding({
      target: 'https://cdn.example.com/search?q=x',
      severity: 'low',
    }));

    const xssFindings = engine.huntSession.allFindings.filter(
      f => f.type === 'xss_reflected'
    );

    expect(xssFindings).toHaveLength(1);
    // Highest severity across the three inputs was 'high'
    expect(xssFindings[0].severity).toBe('high');
  });

  it('keeps distinct vuln types on the same root domain', async () => {
    const engine = await makeEngine();

    await pumpFinding(engine, makeFinding({
      target: 'https://api.example.com/search?q=x',
      severity: 'high',
    }));
    await pumpFinding(engine, makeFinding({
      target: 'https://www.example.com/login',
      severity: 'critical',
      type: 'sqli',
      title: 'SQLi in username field',
    }));

    // One XSS + one SQLi, even though same root domain
    expect(engine.huntSession.allFindings).toHaveLength(2);
    const types = engine.huntSession.allFindings.map(f => f.type).sort();
    expect(types).toEqual(['sqli', 'xss_reflected']);
  });

  it('retains critical when a later duplicate arrives with lower severity', async () => {
    const engine = await makeEngine();

    await pumpFinding(engine, makeFinding({
      target: 'https://api.example.com/search?q=x',
      severity: 'critical',
    }));
    await pumpFinding(engine, makeFinding({
      target: 'https://www.example.com/search?q=x',
      severity: 'low',
    }));

    const xssFindings = engine.huntSession.allFindings.filter(
      f => f.type === 'xss_reflected'
    );
    expect(xssFindings).toHaveLength(1);
    expect(xssFindings[0].severity).toBe('critical');
  });
});

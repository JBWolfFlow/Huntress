/**
 * Orchestrator End-to-End Tests
 *
 * Tests the full orchestrator flow with a mock model provider that returns
 * scripted tool-use responses. Verifies the task queue lifecycle, agent
 * dispatch, finding collection, and chain detection.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { OrchestratorEngine } from '../../core/orchestrator/orchestrator_engine';
import type {
  OrchestratorConfig,
} from '../../core/orchestrator/orchestrator_engine';
import type {
  ModelProvider,
  ChatMessage,
  ChatResponse,
  SendMessageOptions,
  StreamChunk,
  ModelInfo,
} from '../../core/providers/types';
import type { ConversationMessage, SessionPhase } from '../../core/conversation/types';
import type { ProgramGuidelines } from '../../components/GuidelinesImporter';

// ─── Mock Model Provider ─────────────────────────────────────────────────────

export function createMockProvider(responses: ChatResponse[]): { provider: ModelProvider; callLog: { count: number } } {
  let callIndex = 0;
  const callLog = { count: 0 };

  const provider: ModelProvider = {
    providerId: 'mock',
    displayName: 'Mock Provider',

    async sendMessage(_messages: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
      callLog.count++;

      if (callIndex < responses.length) {
        return responses[callIndex++];
      }

      // Default: return stop_hunting to end the loop
      return {
        content: 'Hunting complete.',
        model: options.model,
        inputTokens: 100,
        outputTokens: 50,
        stopReason: 'tool_use',
        toolCalls: [{
          type: 'tool_use',
          id: `tool_stop_${callIndex++}`,
          name: 'stop_hunting',
          input: { reason: 'All tasks completed' },
        }],
        contentBlocks: [
          { type: 'text', text: 'Hunting complete.' },
          {
            type: 'tool_use',
            id: `tool_stop_${callIndex}`,
            name: 'stop_hunting',
            input: { reason: 'All tasks completed' },
          },
        ],
      };
    },

    async *streamMessage(_messages: ChatMessage[], _options: SendMessageOptions): AsyncGenerator<StreamChunk> {
      yield { type: 'content_delta', content: 'Streaming not used in tests' };
      yield { type: 'message_stop', inputTokens: 50, outputTokens: 25 };
    },

    getAvailableModels(): ModelInfo[] {
      return [{
        id: 'mock-model',
        displayName: 'Mock Model',
        contextWindow: 128000,
        maxOutputTokens: 4096,
        supportsStreaming: true,
        supportsSystemPrompt: true,
        inputCostPer1M: 0,
        outputCostPer1M: 0,
      }];
    },

    async validateApiKey(_key: string): Promise<boolean> {
      return true;
    },

    estimateCost(_input: number, _output: number, _model: string): number {
      return 0;
    },

    supportsToolUse: true,
  };

  return { provider, callLog };
}

// ─── Test Fixtures ───────────────────────────────────────────────────────────

const mockGuidelines: ProgramGuidelines = {
  programHandle: 'test_program',
  programName: 'Test Program',
  url: 'https://hackerone.com/test_program',
  scope: {
    inScope: ['*.test-target.com', 'api.test-target.com'],
    outOfScope: ['status.test-target.com'],
  },
  bountyRange: { min: 100, max: 25000 },
  rules: ['Do not test during business hours.'],
  severity: {
    critical: '$5,000-$25,000',
    high: '$2,000-$10,000',
    medium: '$500-$2,000',
    low: '$100-$500',
  },
  importedAt: new Date(),
};

describe('Orchestrator E2E', () => {
  let messages: ConversationMessage[];
  let phases: SessionPhase[];

  beforeEach(() => {
    messages = [];
    phases = [];
  });

  it('should initialize and load guidelines', () => {
    const { provider } = createMockProvider([]);

    const config: OrchestratorConfig = {
      provider,
      model: 'mock-model',
      maxConcurrentAgents: 2,
    };

    const engine = new OrchestratorEngine(config);
    engine.setMessageCallback((msg) => messages.push(msg));
    engine.setPhaseCallback((phase) => phases.push(phase));

    // Load guidelines
    engine.loadGuidelines(mockGuidelines);

    // Phase should still be idle (loadGuidelines doesn't start hunting)
    expect(engine.getPhase()).toBe('idle');
  });

  it('should handle the hunt lifecycle with stop_hunting', async () => {
    const { provider } = createMockProvider([
      // Model immediately calls stop_hunting
      {
        content: 'No interesting targets found.',
        model: 'mock-model',
        inputTokens: 500,
        outputTokens: 200,
        stopReason: 'tool_use',
        toolCalls: [{
          type: 'tool_use',
          id: 'stop_1',
          name: 'stop_hunting',
          input: { reason: 'No viable attack surface' },
        }],
        contentBlocks: [
          { type: 'text', text: 'No interesting targets found.' },
          {
            type: 'tool_use',
            id: 'stop_1',
            name: 'stop_hunting',
            input: { reason: 'No viable attack surface' },
          },
        ],
      },
    ]);

    const config: OrchestratorConfig = {
      provider,
      model: 'mock-model',
      maxConcurrentAgents: 2,
    };

    const engine = new OrchestratorEngine(config);
    engine.setMessageCallback((msg) => messages.push(msg));
    engine.setPhaseCallback((phase) => phases.push(phase));

    await engine.startHunt(mockGuidelines);

    // Should have gone through phases — normal completion goes hunting -> reporting
    expect(phases).toContain('hunting');
    expect(phases).toContain('reporting');
  });

  it('should stop on abort', async () => {
    const { provider } = createMockProvider([
      // Slow response that never ends — we'll abort before it matters
      {
        content: 'Starting analysis...',
        model: 'mock-model',
        inputTokens: 500,
        outputTokens: 200,
        stopReason: 'end_turn',
        contentBlocks: [{ type: 'text', text: 'Starting analysis...' }],
      },
    ]);

    const config: OrchestratorConfig = {
      provider,
      model: 'mock-model',
    };

    const engine = new OrchestratorEngine(config);
    engine.setMessageCallback((msg) => messages.push(msg));
    engine.setPhaseCallback((phase) => phases.push(phase));

    // Start hunt in background and immediately stop
    const huntPromise = engine.startHunt(mockGuidelines);
    await new Promise(r => setTimeout(r, 100));
    engine.abortHunt();
    await huntPromise;

    // Should have reached complete phase
    expect(phases).toContain('complete');
  });
});

describe('Finding Dedup Integration', () => {
  it('should deduplicate findings with same key', async () => {
    const { deduplicateFindings } = await import('../../core/orchestrator/finding_dedup');

    const findings = [
      {
        id: 'f1',
        agentId: 'xss_hunter',
        type: 'xss_reflected',
        title: 'XSS in search param',
        severity: 'medium' as const,
        description: 'Reflected XSS in the q parameter',
        target: 'https://example.com/search?q=<script>',
        evidence: ['GET /search?q=<script>'],
        reproduction: [],
        timestamp: new Date(),
      },
      {
        id: 'f2',
        agentId: 'recon_agent',
        type: 'xss_reflected',
        title: 'XSS found during recon in search',
        severity: 'high' as const,
        description: 'Reflected XSS in the q parameter',
        target: 'https://example.com/search?q=<img+onerror>',
        evidence: ['GET /search?q=<img+onerror>'],
        reproduction: [],
        timestamp: new Date(),
      },
    ];

    const deduped = deduplicateFindings(findings);
    // Same hostname, same type, same parameter (q) → should collapse to 1
    expect(deduped.length).toBe(1);
    // The higher severity one should win
    expect(deduped[0].severity).toBe('high');
  });

  it('should keep findings with different targets', async () => {
    const { deduplicateFindings } = await import('../../core/orchestrator/finding_dedup');

    const findings = [
      {
        id: 'f1',
        agentId: 'xss_hunter',
        type: 'xss_reflected',
        title: 'XSS on site A',
        severity: 'medium' as const,
        description: 'XSS in q param',
        target: 'https://siteA.com/search?q=test',
        evidence: ['GET /search?q=test'],
        reproduction: [],
        timestamp: new Date(),
      },
      {
        id: 'f2',
        agentId: 'xss_hunter',
        type: 'xss_reflected',
        title: 'XSS on site B',
        severity: 'medium' as const,
        description: 'XSS in q param',
        target: 'https://siteB.com/search?q=test',
        evidence: ['GET /search?q=test'],
        reproduction: [],
        timestamp: new Date(),
      },
    ];

    const deduped = deduplicateFindings(findings);
    expect(deduped.length).toBe(2);
  });
});

describe('SimHash Integration', () => {
  it('should group similar pages together', async () => {
    const { groupBySimHash, computeSimHash, simHashDistance } = await import('../../core/orchestrator/finding_dedup');

    // Two very similar pages
    const html1 = '<html><body><h1>Welcome to Example Corp</h1><p>Our products are great and the team is wonderful.</p></body></html>';
    const html2 = '<html><body><h1>Welcome to Example Corp</h1><p>Our products are amazing and the team is wonderful.</p></body></html>';
    // A very different page
    const html3 = '<html><body><h1>Login</h1><form><input name="user"/><input name="pass" type="password"/></form><button>Submit</button></body></html>';

    const hash1 = computeSimHash(html1);
    const hash2 = computeSimHash(html2);
    const hash3 = computeSimHash(html3);

    // Similar pages should have small distance
    const dist12 = simHashDistance(hash1, hash2);
    expect(dist12).toBeLessThan(20);

    // Different pages should have larger distance
    const dist13 = simHashDistance(hash1, hash3);
    expect(dist13).toBeGreaterThan(dist12);

    const groups = groupBySimHash([
      { url: 'https://a.example.com', html: html1 },
      { url: 'https://b.example.com', html: html2 },
      { url: 'https://c.example.com', html: html3 },
    ], 20);

    // html1 and html2 should be in the same group, html3 separate
    expect(groups.length).toBe(2);
  });

  it('should compute consistent hashes', async () => {
    const { computeSimHash } = await import('../../core/orchestrator/finding_dedup');

    const html = '<html><body>Hello World</body></html>';
    const hash1 = computeSimHash(html);
    const hash2 = computeSimHash(html);

    expect(hash1).toBe(hash2);
  });
});

describe('Cost Router Integration', () => {
  it('should classify agent complexity correctly', async () => {
    const { classifyTaskComplexity } = await import('../../core/orchestrator/cost_router');

    expect(classifyTaskComplexity('recon', 'enumerate subdomains')).toBe('simple');
    expect(classifyTaskComplexity('xss', 'test for reflected XSS')).toBe('moderate');
    expect(classifyTaskComplexity('orchestrator', 'analyze strategy')).toBe('complex');
    // recon is a locked agent — never upgrades regardless of description keywords
    expect(classifyTaskComplexity('recon', 'bypass WAF authentication')).toBe('simple');
  });

  it('should select cheapest model for simple tasks', async () => {
    const { selectModelForTask } = await import('../../core/orchestrator/cost_router');

    const cheapProvider: ModelProvider = {
      providerId: 'cheap', displayName: 'Cheap',
      async sendMessage() { return {} as ChatResponse; },
      async *streamMessage() { /* empty */ },
      getAvailableModels: () => [],
      validateApiKey: async () => true,
      estimateCost: () => 0.001,
    };

    const expensiveProvider: ModelProvider = {
      providerId: 'expensive', displayName: 'Expensive',
      async sendMessage() { return {} as ChatResponse; },
      async *streamMessage() { /* empty */ },
      getAvailableModels: () => [],
      validateApiKey: async () => true,
      estimateCost: () => 1.0,
    };

    const result = selectModelForTask('simple', [
      { provider: expensiveProvider, models: ['claude-opus-4-6'] },
      { provider: cheapProvider, models: ['claude-haiku-4-5-20251001'] },
    ]);

    expect(result).toBeDefined();
    expect(result!.model).toBe('claude-haiku-4-5-20251001');
  });

  it('should select expensive model for complex tasks', async () => {
    const { selectModelForTask } = await import('../../core/orchestrator/cost_router');

    const cheapProvider: ModelProvider = {
      providerId: 'cheap', displayName: 'Cheap',
      async sendMessage() { return {} as ChatResponse; },
      async *streamMessage() { /* empty */ },
      getAvailableModels: () => [],
      validateApiKey: async () => true,
      estimateCost: () => 0.001,
    };

    const expensiveProvider: ModelProvider = {
      providerId: 'expensive', displayName: 'Expensive',
      async sendMessage() { return {} as ChatResponse; },
      async *streamMessage() { /* empty */ },
      getAvailableModels: () => [],
      validateApiKey: async () => true,
      estimateCost: () => 1.0,
    };

    const result = selectModelForTask('complex', [
      { provider: cheapProvider, models: ['claude-haiku-4-5-20251001'] },
      { provider: expensiveProvider, models: ['claude-opus-4-6'] },
    ]);

    expect(result).toBeDefined();
    expect(result!.model).toBe('claude-opus-4-6');
  });

  it('should respect per-agent model overrides', async () => {
    const { selectModelForTask } = await import('../../core/orchestrator/cost_router');

    const provider: ModelProvider = {
      providerId: 'test', displayName: 'Test',
      async sendMessage() { return {} as ChatResponse; },
      async *streamMessage() { /* empty */ },
      getAvailableModels: () => [],
      validateApiKey: async () => true,
      estimateCost: () => 0.5,
    };

    const overrides = {
      recon: { providerId: 'test', modelId: 'gpt-4o' },
    };

    const result = selectModelForTask(
      'simple',
      [{ provider, models: ['gpt-4o', 'gpt-4o-mini'] }],
      overrides,
      'recon',
    );

    expect(result).toBeDefined();
    expect(result!.model).toBe('gpt-4o');
  });
});

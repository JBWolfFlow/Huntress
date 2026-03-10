/**
 * Tests for the LLM Tracing System
 *
 * Covers:
 * - TraceStore CRUD operations and indexing
 * - TracedModelProvider instrumentation
 * - CostTracker budget enforcement
 * - Eviction and memory management
 * - Analytics queries
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TraceStore } from './trace_store';
import { TracedModelProvider, BudgetExceededError } from './traced_provider';
import { CostTracker } from './cost_tracker';
import type {
  LLMCallTrace,
  ToolExecutionTrace,
  SessionId,
  SpanId,
} from './types';
import type {
  ModelProvider,
  ChatMessage,
  ChatResponse,
  StreamChunk,
  SendMessageOptions,
  ModelInfo,
} from '../providers/types';

// ─── Test Fixtures ───────────────────────────────────────────────────────────

function createMockProvider(overrides?: Partial<ChatResponse>): ModelProvider {
  return {
    providerId: 'test-provider',
    displayName: 'Test Provider',
    supportsToolUse: true,

    sendMessage: vi.fn().mockResolvedValue({
      content: 'Test response',
      model: 'test-model',
      inputTokens: 100,
      outputTokens: 50,
      stopReason: 'end_turn',
      toolCalls: undefined,
      contentBlocks: undefined,
      ...overrides,
    } as ChatResponse),

    streamMessage: vi.fn().mockImplementation(async function* (): AsyncGenerator<StreamChunk> {
      yield { type: 'message_start' };
      yield { type: 'content_delta', content: 'Hello' };
      yield { type: 'content_delta', content: ' world' };
      yield { type: 'message_stop', inputTokens: 80, outputTokens: 30 };
    }),

    getAvailableModels: vi.fn().mockReturnValue([
      {
        id: 'test-model',
        displayName: 'Test Model',
        contextWindow: 100000,
        maxOutputTokens: 4096,
        supportsStreaming: true,
        supportsSystemPrompt: true,
        inputCostPer1M: 3,
        outputCostPer1M: 15,
      },
    ] as ModelInfo[]),

    validateApiKey: vi.fn().mockResolvedValue(true),
    estimateCost: vi.fn().mockImplementation((input: number, output: number) => {
      return (input / 1_000_000) * 3 + (output / 1_000_000) * 15;
    }),
  };
}

function createTestTrace(overrides?: Partial<LLMCallTrace>): LLMCallTrace {
  return {
    id: `llm_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    spanId: 'span_test',
    sessionId: 'session_test',
    startedAt: Date.now() - 1000,
    completedAt: Date.now(),
    durationMs: 1000,
    providerId: 'anthropic',
    model: 'claude-sonnet-4-5-20250929',
    inputTokens: 1000,
    outputTokens: 500,
    totalTokens: 1500,
    costUsd: 0.0105,
    streaming: false,
    temperature: 0.7,
    maxTokens: 4096,
    toolCount: 5,
    toolCallCount: 1,
    toolCallNames: ['execute_command'],
    stopReason: 'tool_use',
    callerType: 'agent',
    agentId: 'ssrf-hunter',
    contextMessageCount: 10,
    success: true,
    error: null,
    retryCount: 0,
    systemPrompt: 'You are a security researcher.',
    lastUserMessage: 'Test for SSRF',
    responsePreview: 'I will test the target.',
    ...overrides,
  };
}

function createTestToolTrace(overrides?: Partial<ToolExecutionTrace>): ToolExecutionTrace {
  return {
    id: `tool_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    spanId: 'span_test',
    sessionId: 'session_test',
    startedAt: Date.now() - 500,
    completedAt: Date.now(),
    durationMs: 500,
    toolName: 'execute_command',
    command: 'curl -s https://example.com',
    target: 'example.com',
    approvalStatus: 'approved',
    category: 'recon',
    exitCode: 0,
    success: true,
    error: null,
    blockedBySafety: false,
    agentId: 'ssrf-hunter',
    ...overrides,
  };
}

// ─── TraceStore Tests ────────────────────────────────────────────────────────

describe('TraceStore', () => {
  let store: TraceStore;

  beforeEach(() => {
    store = new TraceStore({
      maxLlmTraces: 100,
      maxToolTraces: 50,
      maxSpans: 50,
      maxSessions: 10,
      persistIntervalMs: 0, // Disable auto-persist in tests
    });
  });

  describe('Session Management', () => {
    it('should create and retrieve a session', () => {
      const session = store.startSession({
        id: 'session_1',
        startedAt: Date.now(),
        status: 'active',
        programName: 'Test Program',
        targets: ['example.com'],
      });

      expect(session.id).toBe('session_1');
      expect(session.status).toBe('active');
      expect(session.totalCostUsd).toBe(0);
      expect(session.totalLlmCalls).toBe(0);

      const retrieved = store.getSession('session_1');
      expect(retrieved).toBeDefined();
      expect(retrieved!.programName).toBe('Test Program');
    });

    it('should end a session and update status', () => {
      store.startSession({
        id: 'session_1',
        startedAt: Date.now(),
        status: 'active',
        programName: 'Test',
        targets: [],
      });

      store.endSession('session_1', 'completed');

      const session = store.getSession('session_1');
      expect(session!.status).toBe('completed');
      expect(session!.completedAt).toBeGreaterThan(0);
    });

    it('should list sessions sorted by most recent', () => {
      store.startSession({ id: 'old', startedAt: 1000, status: 'active', programName: 'Old', targets: [] });
      store.startSession({ id: 'new', startedAt: 2000, status: 'active', programName: 'New', targets: [] });

      const sessions = store.listSessions();
      expect(sessions).toHaveLength(2);
      expect(sessions[0].id).toBe('new');
      expect(sessions[1].id).toBe('old');
    });
  });

  describe('LLM Trace Management', () => {
    beforeEach(() => {
      store.startSession({
        id: 'session_test',
        startedAt: Date.now(),
        status: 'active',
        programName: 'Test',
        targets: [],
      });
      store.startSpan({
        id: 'span_test',
        parentSpanId: null,
        sessionId: 'session_test',
        kind: 'agent_execution',
        name: 'Test Agent',
        startedAt: Date.now(),
        status: 'running',
        metadata: {},
        agentId: 'ssrf-hunter',
        error: null,
      });
    });

    it('should add and retrieve an LLM trace', () => {
      const trace = createTestTrace({ id: 'trace_1' });
      store.addLlmTrace(trace);

      const retrieved = store.getLlmTrace('trace_1');
      expect(retrieved).toBeDefined();
      expect(retrieved!.model).toBe('claude-sonnet-4-5-20250929');
    });

    it('should update session aggregates when adding traces', () => {
      store.addLlmTrace(createTestTrace({ costUsd: 0.01, inputTokens: 100, outputTokens: 50 }));
      store.addLlmTrace(createTestTrace({ costUsd: 0.02, inputTokens: 200, outputTokens: 100 }));

      const session = store.getSession('session_test')!;
      expect(session.totalLlmCalls).toBe(2);
      expect(session.totalCostUsd).toBeCloseTo(0.03);
      expect(session.totalInputTokens).toBe(300);
      expect(session.totalOutputTokens).toBe(150);
    });

    it('should update span aggregates when adding traces', () => {
      store.addLlmTrace(createTestTrace({ costUsd: 0.01 }));
      store.addLlmTrace(createTestTrace({ costUsd: 0.02 }));

      const span = store.getSpan('span_test')!;
      expect(span.llmCallCount).toBe(2);
      expect(span.totalCostUsd).toBeCloseTo(0.03);
    });

    it('should track cost by provider in session', () => {
      store.addLlmTrace(createTestTrace({ providerId: 'anthropic', costUsd: 0.05 }));
      store.addLlmTrace(createTestTrace({ providerId: 'openai', costUsd: 0.03 }));
      store.addLlmTrace(createTestTrace({ providerId: 'anthropic', costUsd: 0.02 }));

      const session = store.getSession('session_test')!;
      expect(session.costByProvider['anthropic']).toBeCloseTo(0.07);
      expect(session.costByProvider['openai']).toBeCloseTo(0.03);
    });

    it('should track cost by agent in session', () => {
      store.addLlmTrace(createTestTrace({ agentId: 'ssrf-hunter', costUsd: 0.05 }));
      store.addLlmTrace(createTestTrace({ agentId: 'xss-hunter', costUsd: 0.03 }));

      const session = store.getSession('session_test')!;
      expect(session.costByAgent['ssrf-hunter']).toBeCloseTo(0.05);
      expect(session.costByAgent['xss-hunter']).toBeCloseTo(0.03);
    });
  });

  describe('Querying', () => {
    beforeEach(() => {
      store.startSession({ id: 'session_test', startedAt: Date.now(), status: 'active', programName: 'Test', targets: [] });
      store.startSpan({ id: 'span_test', parentSpanId: null, sessionId: 'session_test', kind: 'agent_execution', name: 'Test', startedAt: Date.now(), status: 'running', metadata: {}, agentId: 'ssrf-hunter', error: null });

      // Add traces with varying properties
      for (let i = 0; i < 20; i++) {
        store.addLlmTrace(createTestTrace({
          id: `trace_${i}`,
          startedAt: Date.now() - (20 - i) * 1000,
          model: i % 2 === 0 ? 'claude-sonnet-4-5-20250929' : 'gpt-4o',
          providerId: i % 2 === 0 ? 'anthropic' : 'openai',
          costUsd: i * 0.001,
          durationMs: 500 + i * 100,
          success: i !== 5, // trace_5 failed
          agentId: i < 10 ? 'ssrf-hunter' : 'xss-hunter',
        }));
      }
    });

    it('should filter by session ID', () => {
      const results = store.queryLlmTraces({ sessionId: 'session_test' });
      expect(results).toHaveLength(20);
    });

    it('should filter by provider', () => {
      const results = store.queryLlmTraces({ sessionId: 'session_test', providerId: 'anthropic' });
      expect(results).toHaveLength(10);
    });

    it('should filter by model', () => {
      const results = store.queryLlmTraces({ sessionId: 'session_test', model: 'gpt-4o' });
      expect(results).toHaveLength(10);
    });

    it('should filter by success status', () => {
      const failures = store.queryLlmTraces({ sessionId: 'session_test', success: false });
      expect(failures).toHaveLength(1);
      expect(failures[0].id).toBe('trace_5');
    });

    it('should filter by agent', () => {
      const results = store.queryLlmTraces({ agentId: 'xss-hunter' });
      expect(results).toHaveLength(10);
    });

    it('should sort by cost descending', () => {
      const results = store.queryLlmTraces({
        sessionId: 'session_test',
        orderBy: 'costUsd',
        orderDir: 'desc',
        limit: 5,
      });
      expect(results[0].costUsd).toBeGreaterThan(results[4].costUsd);
    });

    it('should paginate results', () => {
      const page1 = store.queryLlmTraces({ sessionId: 'session_test', limit: 5, offset: 0 });
      const page2 = store.queryLlmTraces({ sessionId: 'session_test', limit: 5, offset: 5 });
      expect(page1).toHaveLength(5);
      expect(page2).toHaveLength(5);
      expect(page1[0].id).not.toBe(page2[0].id);
    });

    it('should filter by minimum duration', () => {
      const results = store.queryLlmTraces({
        sessionId: 'session_test',
        minDurationMs: 1500,
      });
      expect(results.every(t => t.durationMs >= 1500)).toBe(true);
    });
  });

  describe('Eviction', () => {
    it('should evict oldest traces when max is reached', () => {
      store.startSession({ id: 'session_test', startedAt: Date.now(), status: 'active', programName: 'Test', targets: [] });
      store.startSpan({ id: 'span_test', parentSpanId: null, sessionId: 'session_test', kind: 'agent_execution', name: 'Test', startedAt: Date.now(), status: 'running', metadata: {}, agentId: null, error: null });

      // Add 150 traces to a store with max 100
      for (let i = 0; i < 150; i++) {
        store.addLlmTrace(createTestTrace({
          id: `trace_${i}`,
          startedAt: Date.now() + i,
        }));
      }

      const stats = store.getStats();
      expect(stats.llmTraceCount).toBeLessThanOrEqual(100);

      // Oldest traces should be evicted
      expect(store.getLlmTrace('trace_0')).toBeUndefined();
      // Newest should still be there
      expect(store.getLlmTrace('trace_149')).toBeDefined();
    });
  });

  describe('Span Hierarchy', () => {
    it('should track parent-child span relationships', () => {
      store.startSession({ id: 's1', startedAt: Date.now(), status: 'active', programName: 'Test', targets: [] });

      store.startSpan({ id: 'root', parentSpanId: null, sessionId: 's1', kind: 'hunt_session', name: 'Root', startedAt: Date.now(), status: 'running', metadata: {}, agentId: null, error: null });
      store.startSpan({ id: 'child1', parentSpanId: 'root', sessionId: 's1', kind: 'agent_execution', name: 'Agent 1', startedAt: Date.now(), status: 'running', metadata: {}, agentId: 'a1', error: null });
      store.startSpan({ id: 'child2', parentSpanId: 'root', sessionId: 's1', kind: 'agent_execution', name: 'Agent 2', startedAt: Date.now(), status: 'running', metadata: {}, agentId: 'a2', error: null });

      const children = store.getChildSpans('root');
      expect(children).toHaveLength(2);
    });

    it('should propagate token aggregates to parent spans', () => {
      store.startSession({ id: 's1', startedAt: Date.now(), status: 'active', programName: 'Test', targets: [] });
      store.startSpan({ id: 'parent', parentSpanId: null, sessionId: 's1', kind: 'hunt_session', name: 'Root', startedAt: Date.now(), status: 'running', metadata: {}, agentId: null, error: null });
      store.startSpan({ id: 'child', parentSpanId: 'parent', sessionId: 's1', kind: 'agent_execution', name: 'Agent', startedAt: Date.now(), status: 'running', metadata: {}, agentId: 'a1', error: null });

      store.addLlmTrace(createTestTrace({
        spanId: 'child',
        sessionId: 's1',
        inputTokens: 500,
        outputTokens: 200,
        costUsd: 0.05,
      }));

      // Child span should have the tokens
      const child = store.getSpan('child')!;
      expect(child.totalInputTokens).toBe(500);

      // Parent span should also have them (propagated)
      const parent = store.getSpan('parent')!;
      expect(parent.totalInputTokens).toBe(500);
      expect(parent.totalCostUsd).toBeCloseTo(0.05);
    });
  });

  describe('Analytics', () => {
    beforeEach(() => {
      store.startSession({ id: 's1', startedAt: Date.now(), status: 'active', programName: 'Test', targets: [] });

      // Create agent spans
      store.startSpan({
        id: 'agent_ssrf', parentSpanId: null, sessionId: 's1',
        kind: 'agent_execution', name: 'SSRF', startedAt: Date.now(),
        status: 'completed', metadata: { findingCount: 2 }, agentId: 'ssrf-hunter', error: null,
      });
      store.endSpan('agent_ssrf', 'completed');

      store.startSpan({
        id: 'agent_xss', parentSpanId: null, sessionId: 's1',
        kind: 'agent_execution', name: 'XSS', startedAt: Date.now(),
        status: 'completed', metadata: { findingCount: 0 }, agentId: 'xss-hunter', error: null,
      });
      store.endSpan('agent_xss', 'completed');

      // Add traces for each agent
      store.addLlmTrace(createTestTrace({ spanId: 'agent_ssrf', sessionId: 's1', agentId: 'ssrf-hunter', costUsd: 0.10, model: 'claude-sonnet-4-5-20250929', providerId: 'anthropic', durationMs: 2000 }));
      store.addLlmTrace(createTestTrace({ spanId: 'agent_xss', sessionId: 's1', agentId: 'xss-hunter', costUsd: 0.05, model: 'gpt-4o', providerId: 'openai', durationMs: 1000 }));
    });

    it('should compute agent performance summaries', () => {
      const performance = store.getAgentPerformance();
      expect(performance).toHaveLength(2);

      const ssrf = performance.find(p => p.agentId === 'ssrf-hunter')!;
      expect(ssrf.totalFindings).toBe(2);
      expect(ssrf.totalCostUsd).toBeCloseTo(0.10);
      expect(ssrf.costEfficiency).toBeGreaterThan(0);
    });

    it('should compute model performance summaries', () => {
      const performance = store.getModelPerformance();
      expect(performance).toHaveLength(2);

      const sonnet = performance.find(p => p.model === 'claude-sonnet-4-5-20250929')!;
      expect(sonnet.totalCalls).toBe(1);
      expect(sonnet.totalCostUsd).toBeCloseTo(0.10);
    });

    it('should compute latency distribution', () => {
      // Add more traces for meaningful percentiles
      for (let i = 0; i < 100; i++) {
        store.addLlmTrace(createTestTrace({
          spanId: 'agent_ssrf',
          sessionId: 's1',
          durationMs: 500 + i * 20,
        }));
      }

      const dist = store.getLatencyDistribution({ sessionId: 's1' });
      expect(dist.p50).toBeGreaterThan(0);
      expect(dist.p95).toBeGreaterThan(dist.p50);
      expect(dist.max).toBeGreaterThan(dist.p95);
    });
  });

  describe('Export/Import', () => {
    it('should export and import data correctly', () => {
      store.startSession({ id: 's1', startedAt: 1000, status: 'active', programName: 'Test', targets: ['a.com'] });
      store.startSpan({ id: 'sp1', parentSpanId: null, sessionId: 's1', kind: 'hunt_session', name: 'Test', startedAt: 1000, status: 'running', metadata: {}, agentId: null, error: null });
      store.addLlmTrace(createTestTrace({ id: 't1', spanId: 'sp1', sessionId: 's1' }));

      const exported = store.exportData();
      expect(exported.version).toBe(1);
      expect(exported.sessions).toHaveLength(1);
      expect(exported.spans).toHaveLength(1);
      expect(exported.llmTraces).toHaveLength(1);

      // Import into a fresh store
      const newStore = new TraceStore({ persistIntervalMs: 0 });
      newStore.importData(exported);

      expect(newStore.getSession('s1')).toBeDefined();
      expect(newStore.getSpan('sp1')).toBeDefined();
      expect(newStore.getLlmTrace('t1')).toBeDefined();
    });
  });

  describe('Event Subscription', () => {
    it('should emit events when traces are added', () => {
      const events: string[] = [];
      store.subscribe((event) => events.push(event.type));

      store.startSession({ id: 's1', startedAt: Date.now(), status: 'active', programName: 'Test', targets: [] });
      store.startSpan({ id: 'sp1', parentSpanId: null, sessionId: 's1', kind: 'hunt_session', name: 'Test', startedAt: Date.now(), status: 'running', metadata: {}, agentId: null, error: null });
      store.addLlmTrace(createTestTrace({ spanId: 'sp1', sessionId: 's1' }));

      expect(events).toContain('session_started');
      expect(events).toContain('span_started');
      expect(events).toContain('llm_trace_added');
    });

    it('should support unsubscribing', () => {
      const events: string[] = [];
      const unsub = store.subscribe((event) => events.push(event.type));

      store.startSession({ id: 's1', startedAt: Date.now(), status: 'active', programName: 'Test', targets: [] });
      expect(events).toHaveLength(1);

      unsub();

      store.startSession({ id: 's2', startedAt: Date.now(), status: 'active', programName: 'Test2', targets: [] });
      expect(events).toHaveLength(1); // No new events after unsubscribe
    });
  });
});

// ─── TracedModelProvider Tests ───────────────────────────────────────────────

describe('TracedModelProvider', () => {
  let store: TraceStore;
  let mockProvider: ModelProvider;

  beforeEach(() => {
    store = new TraceStore({ persistIntervalMs: 0 });
    store.startSession({ id: 'session_1', startedAt: Date.now(), status: 'active', programName: 'Test', targets: [] });
    store.startSpan({ id: 'span_1', parentSpanId: null, sessionId: 'session_1', kind: 'orchestrator_turn', name: 'Test', startedAt: Date.now(), status: 'running', metadata: {}, agentId: null, error: null });
    mockProvider = createMockProvider();
  });

  it('should forward provider identity', () => {
    const traced = new TracedModelProvider(mockProvider, store, {
      sessionId: 'session_1',
      spanId: 'span_1',
      callerType: 'orchestrator',
    });

    expect(traced.providerId).toBe('test-provider');
    expect(traced.displayName).toBe('Test Provider');
    expect(traced.supportsToolUse).toBe(true);
  });

  it('should trace sendMessage calls', async () => {
    const traced = new TracedModelProvider(mockProvider, store, {
      sessionId: 'session_1',
      spanId: 'span_1',
      callerType: 'orchestrator',
    });

    const messages: ChatMessage[] = [{ role: 'user', content: 'Hello' }];
    const response = await traced.sendMessage(messages, { model: 'test-model' });

    // Response should be forwarded unchanged
    expect(response.content).toBe('Test response');
    expect(response.inputTokens).toBe(100);

    // A trace should have been recorded
    const traces = store.queryLlmTraces({ sessionId: 'session_1' });
    expect(traces).toHaveLength(1);
    expect(traces[0].success).toBe(true);
    expect(traces[0].inputTokens).toBe(100);
    expect(traces[0].outputTokens).toBe(50);
    expect(traces[0].callerType).toBe('orchestrator');
    expect(traces[0].durationMs).toBeGreaterThanOrEqual(0);
  });

  it('should trace streaming calls', async () => {
    const traced = new TracedModelProvider(mockProvider, store, {
      sessionId: 'session_1',
      spanId: 'span_1',
      callerType: 'agent',
      agentId: 'ssrf-hunter',
    });

    const messages: ChatMessage[] = [{ role: 'user', content: 'Hello' }];
    const chunks: StreamChunk[] = [];

    for await (const chunk of traced.streamMessage(messages, { model: 'test-model' })) {
      chunks.push(chunk);
    }

    // Chunks should be forwarded
    expect(chunks).toHaveLength(4); // start, 2 deltas, stop

    // A trace should have been recorded
    const traces = store.queryLlmTraces({ sessionId: 'session_1' });
    expect(traces).toHaveLength(1);
    expect(traces[0].streaming).toBe(true);
    expect(traces[0].inputTokens).toBe(80);
    expect(traces[0].outputTokens).toBe(30);
    expect(traces[0].agentId).toBe('ssrf-hunter');
    expect(traces[0].responsePreview).toBe('Hello world');
  });

  it('should trace failed calls', async () => {
    const failingProvider = createMockProvider();
    (failingProvider.sendMessage as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error('API rate limited')
    );

    const traced = new TracedModelProvider(failingProvider, store, {
      sessionId: 'session_1',
      spanId: 'span_1',
      callerType: 'orchestrator',
    });

    await expect(
      traced.sendMessage([{ role: 'user', content: 'test' }], { model: 'test-model' })
    ).rejects.toThrow('API rate limited');

    const traces = store.queryLlmTraces({ sessionId: 'session_1' });
    expect(traces).toHaveLength(1);
    expect(traces[0].success).toBe(false);
    expect(traces[0].error).toBe('API rate limited');
  });

  it('should capture content when configured', async () => {
    const traced = new TracedModelProvider(mockProvider, store, {
      sessionId: 'session_1',
      spanId: 'span_1',
      callerType: 'orchestrator',
      captureContent: true,
    });

    const messages: ChatMessage[] = [
      { role: 'user', content: 'Find SSRF vulnerabilities on example.com' },
    ];

    await traced.sendMessage(messages, {
      model: 'test-model',
      systemPrompt: 'You are a security researcher.',
    });

    const traces = store.queryLlmTraces({ sessionId: 'session_1' });
    expect(traces[0].systemPrompt).toBe('You are a security researcher.');
    expect(traces[0].lastUserMessage).toBe('Find SSRF vulnerabilities on example.com');
    expect(traces[0].responsePreview).toBe('Test response');
  });

  it('should track tool calls in traces', async () => {
    const providerWithTools = createMockProvider({
      toolCalls: [
        { type: 'tool_use', id: 'tc_1', name: 'execute_command', input: { command: 'nmap target.com' } },
        { type: 'tool_use', id: 'tc_2', name: 'analyze_response', input: { data: '...' } },
      ],
      stopReason: 'tool_use',
    });

    const traced = new TracedModelProvider(providerWithTools, store, {
      sessionId: 'session_1',
      spanId: 'span_1',
      callerType: 'agent',
      agentId: 'recon',
    });

    await traced.sendMessage([{ role: 'user', content: 'test' }], { model: 'test-model' });

    const traces = store.queryLlmTraces({ sessionId: 'session_1' });
    expect(traces[0].toolCallCount).toBe(2);
    expect(traces[0].toolCallNames).toEqual(['execute_command', 'analyze_response']);
    expect(traces[0].stopReason).toBe('tool_use');
  });

  it('should enforce budget limits', async () => {
    const traced = new TracedModelProvider(mockProvider, store, {
      sessionId: 'session_1',
      spanId: 'span_1',
      callerType: 'orchestrator',
      budget: {
        maxSessionCostUsd: 0.001, // Very low budget
        maxAgentCostUsd: 0,
        warningThreshold: 0.8,
        hardStop: true,
      },
    });

    // First call should succeed
    await traced.sendMessage([{ role: 'user', content: 'test' }], { model: 'test-model' });

    // Second call should be blocked by budget
    await expect(
      traced.sendMessage([{ role: 'user', content: 'test again' }], { model: 'test-model' })
    ).rejects.toThrow(BudgetExceededError);
  });

  it('should delegate non-tracing methods unchanged', () => {
    const traced = new TracedModelProvider(mockProvider, store, {
      sessionId: 'session_1',
      spanId: 'span_1',
      callerType: 'orchestrator',
    });

    const models = traced.getAvailableModels();
    expect(models).toHaveLength(1);
    expect(models[0].id).toBe('test-model');

    const cost = traced.estimateCost(1000, 500, 'test-model');
    expect(cost).toBeGreaterThan(0);
  });
});

// ─── CostTracker Tests ───────────────────────────────────────────────────────

describe('CostTracker', () => {
  let store: TraceStore;
  let tracker: CostTracker;

  beforeEach(() => {
    store = new TraceStore({ persistIntervalMs: 0 });
    tracker = new CostTracker(store);

    store.startSession({ id: 'session_1', startedAt: Date.now() - 60000, status: 'active', programName: 'Test', targets: [] });
    store.startSpan({
      id: 'span_1', parentSpanId: null, sessionId: 'session_1',
      kind: 'agent_execution', name: 'Agent', startedAt: Date.now() - 60000,
      status: 'running', metadata: { findingCount: 1 }, agentId: 'ssrf-hunter', error: null,
    });
  });

  it('should calculate cost for known models', () => {
    const cost = tracker.calculateCost('claude-sonnet-4-5-20250929', 1_000_000, 500_000);
    // $3/M input + $7.50/M output (500k = $7.50)
    expect(cost).toBeCloseTo(3 + 7.50);
  });

  it('should return 0 for unknown models', () => {
    const cost = tracker.calculateCost('unknown-model', 1000, 500);
    expect(cost).toBe(0);
  });

  it('should support custom pricing', () => {
    tracker.setCustomPricing('my-finetuned-model', 5, 25);
    const cost = tracker.calculateCost('my-finetuned-model', 1_000_000, 1_000_000);
    expect(cost).toBeCloseTo(30); // $5 + $25
  });

  it('should track session budget status', () => {
    tracker.setSessionBudget('session_1', {
      maxSessionCostUsd: 1.00,
      maxAgentCostUsd: 0.50,
      warningThreshold: 0.8,
      hardStop: true,
    });

    // Add some cost
    store.addLlmTrace(createTestTrace({ sessionId: 'session_1', spanId: 'span_1', costUsd: 0.50 }));

    const status = tracker.getSessionBudgetStatus('session_1');
    expect(status.spent).toBeCloseTo(0.50);
    expect(status.limit).toBe(1.00);
    expect(status.remaining).toBeCloseTo(0.50);
    expect(status.percentUsed).toBeCloseTo(0.50);
    expect(status.isWarning).toBe(false);
    expect(status.isExceeded).toBe(false);
  });

  it('should trigger warning when threshold reached', () => {
    tracker.setSessionBudget('session_1', {
      maxSessionCostUsd: 1.00,
      maxAgentCostUsd: 0,
      warningThreshold: 0.8,
      hardStop: false,
    });

    const events: string[] = [];
    tracker.onBudgetEvent('session_1', (event) => events.push(event.type));

    // Add cost that exceeds 80% threshold
    store.addLlmTrace(createTestTrace({ sessionId: 'session_1', spanId: 'span_1', costUsd: 0.85 }));

    expect(events).toContain('session_warning');
  });

  it('should trigger exceeded when budget is blown', () => {
    tracker.setSessionBudget('session_1', {
      maxSessionCostUsd: 0.10,
      maxAgentCostUsd: 0,
      warningThreshold: 0.8,
      hardStop: true,
    });

    const events: string[] = [];
    tracker.onBudgetEvent('session_1', (event) => events.push(event.type));

    store.addLlmTrace(createTestTrace({ sessionId: 'session_1', spanId: 'span_1', costUsd: 0.15 }));

    expect(events).toContain('session_exceeded');
  });

  it('should compute session metrics', () => {
    store.addLlmTrace(createTestTrace({
      sessionId: 'session_1', spanId: 'span_1',
      inputTokens: 1000, outputTokens: 500, costUsd: 0.01, durationMs: 2000,
    }));
    store.addLlmTrace(createTestTrace({
      sessionId: 'session_1', spanId: 'span_1',
      inputTokens: 2000, outputTokens: 1000, costUsd: 0.02, durationMs: 3000,
    }));

    const metrics = tracker.getSessionMetrics('session_1');
    expect(metrics.totalLlmCalls).toBe(2);
    expect(metrics.totalInputTokens).toBe(3000);
    expect(metrics.totalOutputTokens).toBe(1500);
    expect(metrics.totalCostUsd).toBeCloseTo(0.03);
    expect(metrics.tokensPerSecond).toBeGreaterThan(0);
  });

  it('should compute cost breakdown by provider', () => {
    store.addLlmTrace(createTestTrace({ sessionId: 'session_1', spanId: 'span_1', providerId: 'anthropic', costUsd: 0.05 }));
    store.addLlmTrace(createTestTrace({ sessionId: 'session_1', spanId: 'span_1', providerId: 'openai', costUsd: 0.03 }));

    const byProvider = tracker.getCostByProvider('session_1');
    expect(byProvider['anthropic']).toBeCloseTo(0.05);
    expect(byProvider['openai']).toBeCloseTo(0.03);
  });

  it('should compute burn rate', () => {
    // Add recent traces
    const now = Date.now();
    for (let i = 0; i < 10; i++) {
      store.addLlmTrace(createTestTrace({
        sessionId: 'session_1',
        spanId: 'span_1',
        startedAt: now - i * 10000, // Spread over last ~100 seconds
        costUsd: 0.01,
      }));
    }

    const burnRate = tracker.getBurnRate('session_1', 5);
    expect(burnRate).toBeGreaterThan(0);
  });
});

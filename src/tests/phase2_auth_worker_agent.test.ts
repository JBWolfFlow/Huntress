/**
 * Session 25 Part B — AuthWorkerAgent tests
 *
 * Exercises the agent's terminal handling using a scripted ModelProvider.
 * No real browser is launched — browser_* tools error out at the "browserClient
 * not initialized" guard, which is the expected path for these tests.
 *
 * What we verify:
 * 1. Missing-parameter request fails fast without running the loop.
 * 2. capture_failed terminal produces outcome.kind='failed' with propagated reason.
 * 3. capture_complete WITHOUT a prior capturedAuth → agent still reports failure
 *    (LLM skipped browser_finish_auth_capture).
 * 4. Iteration-limit exhaustion without terminal → outcome.kind='failed' with
 *    reason='timeout'.
 */

import { describe, it, expect } from 'vitest';
import { AuthWorkerAgent } from '../agents/auth_worker_agent';
import type {
  ModelProvider,
  ChatMessage,
  ChatResponse,
  SendMessageOptions,
  StreamChunk,
  ModelInfo,
} from '../core/providers/types';

function makeProvider(toolCalls: Array<{ name: string; input: Record<string, unknown> }>): ModelProvider {
  let idx = 0;
  return {
    providerId: 'mock',
    displayName: 'Mock',
    async sendMessage(_m: ChatMessage[], o: SendMessageOptions): Promise<ChatResponse> {
      const i = idx++;
      const tc = toolCalls[i] ?? { name: 'capture_failed', input: { reason: 'other', detail: 'sequence exhausted' } };
      return {
        content: `call ${i}`,
        model: o.model,
        inputTokens: 10,
        outputTokens: 10,
        stopReason: 'tool_use',
        toolCalls: [{ type: 'tool_use', id: `tc_${i}`, name: tc.name, input: tc.input }],
        contentBlocks: [
          { type: 'text', text: `call ${i}` },
          { type: 'tool_use', id: `tc_${i}`, name: tc.name, input: tc.input },
        ],
      };
    },
    async *streamMessage(_m: ChatMessage[], _o: SendMessageOptions): AsyncGenerator<StreamChunk> {
      yield { type: 'message_stop', inputTokens: 0, outputTokens: 0 };
    },
    getAvailableModels(): ModelInfo[] {
      return [{
        id: 'mock-model',
        displayName: 'Mock',
        contextWindow: 128000,
        maxOutputTokens: 4096,
        supportsStreaming: true,
        supportsSystemPrompt: true,
        supportsToolUse: true,
      }];
    },
  };
}

/** Provider that never emits a terminal — forces iteration-limit exit. */
function makeStallingProvider(): ModelProvider {
  let idx = 0;
  return {
    providerId: 'mock',
    displayName: 'Mock',
    async sendMessage(_m: ChatMessage[], o: SendMessageOptions): Promise<ChatResponse> {
      const i = idx++;
      // browser_get_content fails (no page) but keeps the loop iterating
      // without a terminal call, so we eventually hit iteration_limit.
      return {
        content: `stall ${i}`,
        model: o.model,
        inputTokens: 10,
        outputTokens: 10,
        stopReason: 'tool_use',
        toolCalls: [{
          type: 'tool_use',
          id: `tc_${i}`,
          name: 'browser_get_content',
          input: { include_cookies: false },
        }],
        contentBlocks: [
          { type: 'text', text: `stall ${i}` },
          { type: 'tool_use', id: `tc_${i}`, name: 'browser_get_content', input: { include_cookies: false } },
        ],
      };
    },
    async *streamMessage(_m: ChatMessage[], _o: SendMessageOptions): AsyncGenerator<StreamChunk> {
      yield { type: 'message_stop', inputTokens: 0, outputTokens: 0 };
    },
    getAvailableModels(): ModelInfo[] {
      return [{
        id: 'mock-model',
        displayName: 'Mock',
        contextWindow: 128000,
        maxOutputTokens: 4096,
        supportsStreaming: true,
        supportsSystemPrompt: true,
        supportsToolUse: true,
      }];
    },
  };
}

const VALID_INPUTS = {
  loginUrl: 'https://app.example.com/login',
  scopeDomains: ['app.example.com'],
  username: 'alice@example.com',
  password: 'hunter2',
};

describe('AuthWorkerAgent', () => {
  it('has expected metadata', () => {
    const agent = new AuthWorkerAgent();
    expect(agent.metadata.id).toBe('auth-worker');
    expect(agent.metadata.name).toBe('Auth Worker');
    expect(agent.metadata.vulnerabilityClasses).toContain('auth-capture');
  });

  it('fails fast without running the loop when parameters are missing', async () => {
    const agent = new AuthWorkerAgent();
    await agent.initialize(makeProvider([]), 'mock-model');
    const result = await agent.execute({
      id: 't0',
      target: 'app.example.com',
      scope: ['app.example.com'],
      description: 'login',
      parameters: {}, // no inputs
    });
    expect(result.success).toBe(false);
    expect(result.toolsExecuted).toBe(0);
    expect(agent.getLastOutcome()).toEqual({
      kind: 'failed',
      reason: 'bad_request',
      detail: expect.stringContaining('loginUrl'),
    });
  });

  it('capture_failed terminal produces outcome.kind=failed with propagated reason', async () => {
    const provider = makeProvider([
      { name: 'capture_failed', input: { reason: 'wrong_credentials', detail: 'auth returned 401 — password incorrect' } },
    ]);
    const agent = new AuthWorkerAgent();
    await agent.initialize(provider, 'mock-model');
    const result = await agent.execute({
      id: 't1',
      target: 'app.example.com',
      scope: ['app.example.com'],
      description: 'login',
      parameters: VALID_INPUTS as unknown as Record<string, unknown>,
    });
    expect(result.success).toBe(false);
    const outcome = agent.getLastOutcome();
    expect(outcome?.kind).toBe('failed');
    if (outcome?.kind === 'failed') {
      expect(outcome.reason).toBe('wrong_credentials');
      expect(outcome.detail).toMatch(/password incorrect/);
    }
  });

  it('capture_complete without prior finish_auth_capture → reports failure', async () => {
    // LLM jumps straight to capture_complete without calling
    // browser_finish_auth_capture, so capturedAuth is undefined.
    const provider = makeProvider([
      { name: 'capture_complete', input: { summary: 'logged in', login_url: 'https://app.example.com/login', post_login_url: 'https://app.example.com/dashboard' } },
    ]);
    const agent = new AuthWorkerAgent();
    await agent.initialize(provider, 'mock-model');
    const result = await agent.execute({
      id: 't2',
      target: 'app.example.com',
      scope: ['app.example.com'],
      description: 'login',
      parameters: VALID_INPUTS as unknown as Record<string, unknown>,
    });
    expect(result.success).toBe(false);
    const outcome = agent.getLastOutcome();
    expect(outcome?.kind).toBe('failed');
    if (outcome?.kind === 'failed') {
      expect(outcome.detail).toMatch(/browser_finish_auth_capture/);
    }
  });

  it('iteration-limit exhaustion without terminal → outcome.kind=failed, reason=timeout', async () => {
    const agent = new AuthWorkerAgent();
    await agent.initialize(makeStallingProvider(), 'mock-model');
    const result = await agent.execute({
      id: 't3',
      target: 'app.example.com',
      scope: ['app.example.com'],
      description: 'login',
      parameters: VALID_INPUTS as unknown as Record<string, unknown>,
    });
    expect(result.success).toBe(false);
    const outcome = agent.getLastOutcome();
    expect(outcome?.kind).toBe('failed');
    if (outcome?.kind === 'failed') {
      expect(outcome.reason).toBe('timeout');
    }
  });

  it('reportFindings() returns empty — auth worker never emits findings', async () => {
    const agent = new AuthWorkerAgent();
    await agent.initialize(makeProvider([]), 'mock-model');
    expect(agent.reportFindings()).toEqual([]);
  });

  it('validate() accepts reasonable URLs', () => {
    const agent = new AuthWorkerAgent();
    expect(agent.validate('app.example.com')).toBe(true);
    expect(agent.validate('https://app.example.com/login')).toBe(true);
  });
});

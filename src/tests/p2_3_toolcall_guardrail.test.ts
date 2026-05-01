/**
 * P1-3-a + P1-3-b — Tool-call guardrail + per-agent cap tests
 *
 * Validates the two-layered defense against the 2026-04-23 SSTI 90-tool-call
 * burn pattern:
 *   1. Hard guardrail: 3 consecutive identical (toolName, argsHash) calls →
 *      stopReason='identical_toolcall_loop'
 *   2. Per-agent cap from cost_router.getToolCallBudget() → stopReason='tool_call_limit'
 *
 * Tests cover:
 *   - Argument-canonicalization (key order doesn't matter)
 *   - Threshold edge cases (2 identical → no stop, 3 → stop)
 *   - Mixed-call interleaving doesn't fire the guardrail
 *   - Cap is per-complexity (simple/moderate/complex)
 *   - Cap fires before iteration limit when both apply
 *   - System prompt advertises both rules so the LLM self-regulates
 */

import { describe, it, expect, vi } from 'vitest';
import { ReactLoop, type ReactLoopConfig } from '../core/engine/react_loop';
import {
  getToolCallBudget,
  getIterationBudget,
} from '../core/orchestrator/cost_router';
import type {
  ChatResponse,
  ChatMessage,
  ModelProvider,
  ToolUseBlock,
  SendMessageOptions,
  ProviderInfo,
  ModelInfo,
} from '../core/providers/types';

// ─── Mock provider helpers ──────────────────────────────────────────────────

interface ScriptedTurn {
  /** Tool calls the provider should emit for this turn (in order) */
  toolCalls: ToolUseBlock[];
  /** Optional text content alongside the tool calls */
  content?: string;
  /** Whether to mark this as the end-of-turn (terminates loop without tools) */
  endTurn?: boolean;
}

/**
 * Provider stub that scripts a sequence of turns. Each call to sendMessage
 * pops the next turn off the queue. When the queue empties, returns an
 * end_turn response so any test that runs longer than expected fails clean.
 */
function makeScriptedProvider(turns: ScriptedTurn[]): ModelProvider {
  let idx = 0;
  return {
    providerId: 'test',
    displayName: 'Test',
    supportsToolUse: true,
    async sendMessage(_messages: ChatMessage[], _options: SendMessageOptions): Promise<ChatResponse> {
      const turn = turns[idx++] ?? { toolCalls: [], endTurn: true };
      return {
        content: turn.content ?? '',
        toolCalls: turn.toolCalls,
        stopReason: turn.endTurn ? 'end_turn' : 'tool_use',
        inputTokens: 100,
        outputTokens: 50,
      };
    },
    sendMessageStream() { throw new Error('not implemented'); },
    getProviderInfo(): ProviderInfo { return { id: 'test', name: 'Test', supportsToolUse: true, supportsStreaming: false }; },
    getAvailableModels(): ModelInfo[] { return [{ id: 'test-model', name: 'Test', contextWindow: 200_000, maxOutputTokens: 4096, costPerMillionInputTokens: 0, costPerMillionOutputTokens: 0 }]; },
    async testConnection() { return true; },
  };
}

/**
 * Build a minimal ReactLoopConfig that keeps the loop honest but doesn't
 * touch the network. The provider is the only collaborator that matters
 * for guardrail logic — tools are dummies whose output is discarded.
 */
function makeReactLoopConfig(overrides: Partial<ReactLoopConfig> & { provider: ModelProvider }): ReactLoopConfig {
  return {
    model: 'test-model',
    systemPrompt: 'You are a test agent.',
    goal: 'Test guardrails',
    target: 'https://example.com',
    scope: ['example.com'],
    tools: [
      {
        name: 'http_request',
        description: 'fetch a URL',
        input_schema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] },
      },
    ],
    browserEnabled: false,
    autoApproveSafe: true,
    maxIterations: 50,
    ...overrides,
  };
}

function http(url: string, id?: string): ToolUseBlock {
  return { type: 'tool_use', id: id ?? `call_${Math.random().toString(36).slice(2, 9)}`, name: 'http_request', input: { url } };
}

// ─── P1-3-a: 3-identical-toolcall guardrail ─────────────────────────────────

describe('P1-3-a · 3-identical-toolcall guardrail', () => {
  it('does NOT fire after 2 identical calls', async () => {
    const provider = makeScriptedProvider([
      { toolCalls: [http('https://example.com/a')] },
      { toolCalls: [http('https://example.com/a')] },
      // 3rd turn is a different call → guardrail must NOT have fired
      { toolCalls: [http('https://example.com/b')] },
      { endTurn: true },
    ]);
    const loop = new ReactLoop(makeReactLoopConfig({ provider }));
    const result = await loop.execute();
    expect(result.stopReason).not.toBe('identical_toolcall_loop');
    expect(result.toolCallCount).toBe(3);
  });

  it('fires on the 3rd consecutive identical call', async () => {
    const provider = makeScriptedProvider([
      { toolCalls: [http('https://example.com/a')] },
      { toolCalls: [http('https://example.com/a')] },
      { toolCalls: [http('https://example.com/a')] }, // 3rd identical → fires
      { toolCalls: [http('https://example.com/b')] }, // never reached
    ]);
    const loop = new ReactLoop(makeReactLoopConfig({ provider }));
    const result = await loop.execute();
    expect(result.stopReason).toBe('identical_toolcall_loop');
    expect(result.toolCallCount).toBe(3);
    expect(result.summary).toMatch(/3 consecutive identical tool calls/);
    expect(result.summary).toContain('http_request');
  });

  it('treats different argument key-order as identical (canonicalization)', async () => {
    // Same payload, different key order — the canonicalized hash must collapse them.
    const callA = { type: 'tool_use', id: 'a', name: 'http_request', input: { url: 'x', method: 'GET' } } as ToolUseBlock;
    const callB = { type: 'tool_use', id: 'b', name: 'http_request', input: { method: 'GET', url: 'x' } } as ToolUseBlock;
    const callC = { type: 'tool_use', id: 'c', name: 'http_request', input: { url: 'x', method: 'GET' } } as ToolUseBlock;
    const provider = makeScriptedProvider([
      { toolCalls: [callA] },
      { toolCalls: [callB] },
      { toolCalls: [callC] },
    ]);
    const loop = new ReactLoop(makeReactLoopConfig({ provider }));
    const result = await loop.execute();
    expect(result.stopReason).toBe('identical_toolcall_loop');
  });

  it('does NOT fire when identical calls are interleaved with different ones', async () => {
    // A, B, A, B, A → 3 As but not consecutive
    const provider = makeScriptedProvider([
      { toolCalls: [http('https://example.com/a')] },
      { toolCalls: [http('https://example.com/b')] },
      { toolCalls: [http('https://example.com/a')] },
      { toolCalls: [http('https://example.com/b')] },
      { toolCalls: [http('https://example.com/a')] },
      { endTurn: true },
    ]);
    const loop = new ReactLoop(makeReactLoopConfig({ provider }));
    const result = await loop.execute();
    expect(result.stopReason).not.toBe('identical_toolcall_loop');
  });

  it('different tool names with identical args do NOT trigger', async () => {
    // Only the (name, args) tuple as a whole counts — same args under different names is fine
    const provider = makeScriptedProvider([
      { toolCalls: [{ type: 'tool_use', id: 'a', name: 'http_request', input: { url: 'x' } }] },
      { toolCalls: [{ type: 'tool_use', id: 'b', name: 'execute_command', input: { url: 'x' } } as ToolUseBlock] },
      { toolCalls: [{ type: 'tool_use', id: 'c', name: 'http_request', input: { url: 'x' } }] },
      { endTurn: true },
    ]);
    const loop = new ReactLoop(makeReactLoopConfig({ provider }));
    const result = await loop.execute();
    expect(result.stopReason).not.toBe('identical_toolcall_loop');
  });

  it('summary includes the offending tool name', async () => {
    const provider = makeScriptedProvider([
      { toolCalls: [http('https://example.com/loop')] },
      { toolCalls: [http('https://example.com/loop')] },
      { toolCalls: [http('https://example.com/loop')] },
    ]);
    const loop = new ReactLoop(makeReactLoopConfig({ provider }));
    const result = await loop.execute();
    expect(result.summary).toContain("'http_request'");
    expect(result.summary).toContain('appears stuck in a loop');
  });
});

// ─── P1-3-b: Per-agent tool-call cap ────────────────────────────────────────

describe('P1-3-b · per-agent tool-call cap (cost_router.getToolCallBudget)', () => {
  it('returns 45 for a known simple agent (recon)', () => {
    expect(getToolCallBudget('recon')).toBe(45);
  });

  it('returns 120 for a known moderate agent (xss-hunter)', () => {
    expect(getToolCallBudget('xss-hunter')).toBe(120);
  });

  it('returns 180 for a known complex agent (idor-hunter)', () => {
    expect(getToolCallBudget('idor-hunter')).toBe(180);
  });

  it('defaults to moderate (120) for unknown agent types', () => {
    expect(getToolCallBudget('totally-made-up-agent')).toBe(120);
  });

  it('always exceeds the iteration budget (so cap is a true backstop)', () => {
    for (const agent of ['recon', 'xss-hunter', 'idor-hunter', 'unknown']) {
      expect(getToolCallBudget(agent)).toBeGreaterThanOrEqual(getIterationBudget(agent));
    }
  });

  it('is a 1.5× multiplier of iteration budget per complexity tier', () => {
    expect(getToolCallBudget('recon') / getIterationBudget('recon')).toBe(1.5);
    expect(getToolCallBudget('xss-hunter') / getIterationBudget('xss-hunter')).toBe(1.5);
    expect(getToolCallBudget('idor-hunter') / getIterationBudget('idor-hunter')).toBe(1.5);
  });
});

describe('P1-3-b · ReactLoop enforces the cap', () => {
  it('stops with stopReason=tool_call_limit when cap exceeded', async () => {
    // Simple agent → cap is 45. Script 50 distinct turns and verify we stop at the cap.
    const turns: ScriptedTurn[] = Array.from({ length: 60 }, (_, i) => ({
      toolCalls: [http(`https://example.com/path${i}`)],
    }));
    const provider = makeScriptedProvider(turns);
    const loop = new ReactLoop(makeReactLoopConfig({
      provider,
      agentType: 'recon',
      maxIterations: 200, // make sure the iteration limit doesn't fire first
    }));
    const result = await loop.execute();
    expect(result.stopReason).toBe('tool_call_limit');
    // toolCallCount lands at cap+1 because the +1 happens before the check
    expect(result.toolCallCount).toBe(46);
    expect(result.summary).toMatch(/Tool-call cap reached/);
    expect(result.summary).toContain('46/45');
  });

  it('does NOT fire when toolCallCount stays under cap', async () => {
    // Use 30 distinct calls, well under the moderate cap of 120
    const turns: ScriptedTurn[] = Array.from({ length: 30 }, (_, i) => ({
      toolCalls: [http(`https://example.com/path${i}`)],
    }));
    turns.push({ endTurn: true });
    const provider = makeScriptedProvider(turns);
    const loop = new ReactLoop(makeReactLoopConfig({ provider, agentType: 'xss-hunter', maxIterations: 100 }));
    const result = await loop.execute();
    expect(result.stopReason).not.toBe('tool_call_limit');
    expect(result.toolCallCount).toBe(30);
  });

  it('cap fires BEFORE iteration limit when both would apply', async () => {
    // Simple agent, cap 45. 60 distinct turns, maxIterations=60. Cap should
    // fire before iteration limit because every iteration here has 1 tool call.
    const turns: ScriptedTurn[] = Array.from({ length: 60 }, (_, i) => ({
      toolCalls: [http(`https://example.com/p${i}`)],
    }));
    const provider = makeScriptedProvider(turns);
    const loop = new ReactLoop(makeReactLoopConfig({ provider, agentType: 'recon', maxIterations: 60 }));
    const result = await loop.execute();
    expect(result.stopReason).toBe('tool_call_limit');
  });
});

// ─── System prompt advertises the rules ─────────────────────────────────────

describe('P1-3-a/b · system prompt advertises both rules to the LLM', () => {
  it('includes the 3-identical-tool-call rule', async () => {
    // Capture the systemPrompt the loop sends to the provider
    let capturedPrompt: string | undefined;
    const provider: ModelProvider = {
      providerId: 'spy', displayName: 'Spy', supportsToolUse: true,
      async sendMessage(_msgs, opts) {
        capturedPrompt = opts.systemPrompt;
        return { content: 'done', toolCalls: [], stopReason: 'end_turn', inputTokens: 0, outputTokens: 0 };
      },
      sendMessageStream: vi.fn(),
      getProviderInfo: () => ({ id: 'spy', name: 'Spy', supportsToolUse: true, supportsStreaming: false }),
      getAvailableModels: () => [],
      testConnection: async () => true,
    };
    const loop = new ReactLoop(makeReactLoopConfig({ provider, agentType: 'xss-hunter' }));
    await loop.execute();
    expect(capturedPrompt).toBeDefined();
    expect(capturedPrompt!).toMatch(/Maximum 3 attempts of identical tool calls/i);
  });

  it('advertises the per-agent tool-call cap with the actual budget number', async () => {
    let capturedPrompt: string | undefined;
    const provider: ModelProvider = {
      providerId: 'spy', displayName: 'Spy', supportsToolUse: true,
      async sendMessage(_msgs, opts) {
        capturedPrompt = opts.systemPrompt;
        return { content: 'done', toolCalls: [], stopReason: 'end_turn', inputTokens: 0, outputTokens: 0 };
      },
      sendMessageStream: vi.fn(),
      getProviderInfo: () => ({ id: 'spy', name: 'Spy', supportsToolUse: true, supportsStreaming: false }),
      getAvailableModels: () => [],
      testConnection: async () => true,
    };
    // Recon (simple) → cap is 45
    const loop = new ReactLoop(makeReactLoopConfig({ provider, agentType: 'recon' }));
    await loop.execute();
    expect(capturedPrompt!).toMatch(/Hard tool-call cap.*45/);
  });
});

// ─── Behavior under combined load ───────────────────────────────────────────

describe('P1-3-a/b · interaction between guardrail and cap', () => {
  it('guardrail wins when 3 identical calls happen before cap is reached', async () => {
    // Cap is 120 for moderate. Three identical calls happen at calls 1-3.
    const provider = makeScriptedProvider([
      { toolCalls: [http('https://x.com/loop')] },
      { toolCalls: [http('https://x.com/loop')] },
      { toolCalls: [http('https://x.com/loop')] },
    ]);
    const loop = new ReactLoop(makeReactLoopConfig({ provider, agentType: 'xss-hunter' }));
    const result = await loop.execute();
    expect(result.stopReason).toBe('identical_toolcall_loop');
    expect(result.toolCallCount).toBe(3);
  });

  it('cap wins when calls vary enough to never trigger guardrail', async () => {
    const turns: ScriptedTurn[] = Array.from({ length: 130 }, (_, i) => ({
      toolCalls: [http(`https://x.com/p${i}`)],
    }));
    const provider = makeScriptedProvider(turns);
    const loop = new ReactLoop(makeReactLoopConfig({ provider, agentType: 'xss-hunter', maxIterations: 200 }));
    const result = await loop.execute();
    expect(result.stopReason).toBe('tool_call_limit');
    expect(result.toolCallCount).toBe(121); // cap of 120 + 1 (check fires AFTER increment)
  });
});

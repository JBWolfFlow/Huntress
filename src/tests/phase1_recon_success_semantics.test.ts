/**
 * Session 25 — Issue #6: Recon Success Semantics
 *
 * The recon agent's job is to map attack surface; it typically doesn't emit
 * `report_finding`. Before this fix, `ReactLoop.execute()` returned
 * `success: false` whenever stopReason='iteration_limit' and 0 findings were
 * emitted, which blocked `orchestrator_engine.ts:2358` from dispatching
 * specialists. These tests verify the agentType-aware `reconSuccess` branch
 * in react_loop.ts:495.
 *
 * Important: we do NOT mutate stopReason — it stays 'iteration_limit' as
 * accurate log ground truth. Only the success boolean is flipped.
 */

import { describe, it, expect } from 'vitest';
import { ReactLoop } from '../core/engine/react_loop';
import type { ReactLoopConfig } from '../core/engine/react_loop';
import type {
  ModelProvider,
  ChatMessage,
  ChatResponse,
  SendMessageOptions,
  StreamChunk,
  ModelInfo,
} from '../core/providers/types';

// ─── Providers ──────────────────────────────────────────────────────────────

/**
 * Returns `toolCount` execute_command tool calls, then keeps returning
 * execute_command forever — forcing the loop to hit iteration_limit without
 * ever calling stop_hunting or report_finding.
 */
function createIterationLimitProvider(toolCount: number): ModelProvider {
  let callIndex = 0;
  return {
    providerId: 'mock',
    displayName: 'Mock Provider',
    async sendMessage(_messages: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
      const idx = callIndex++;
      // Always return a tool call; we never call stop_hunting so iteration_limit fires.
      // After `toolCount` real commands, return a command that the loop still counts
      // toward toolCallCount — so the test controls tool call volume indirectly via maxIterations.
      const command = idx < toolCount ? `curl -s https://example.com/page${idx}` : 'echo waiting';
      return {
        content: 'Executing command',
        model: options.model,
        inputTokens: 100,
        outputTokens: 50,
        stopReason: 'tool_use',
        toolCalls: [{
          type: 'tool_use',
          id: `tool_${idx}`,
          name: 'execute_command',
          input: { command, target: 'https://example.com', reasoning: 'probe', category: 'recon' },
        }],
        contentBlocks: [
          { type: 'text', text: 'Executing command' },
          {
            type: 'tool_use',
            id: `tool_${idx}`,
            name: 'execute_command',
            input: { command, target: 'https://example.com', reasoning: 'probe', category: 'recon' },
          },
        ],
      };
    },
    async *streamMessage(_m: ChatMessage[], _o: SendMessageOptions): AsyncGenerator<StreamChunk> {
      yield { type: 'content_delta', content: '' };
      yield { type: 'message_stop', inputTokens: 0, outputTokens: 0 };
    },
    getAvailableModels(): ModelInfo[] {
      return [{
        id: 'mock-model',
        displayName: 'Mock Model',
        contextWindow: 128000,
        maxOutputTokens: 4096,
        supportsStreaming: true,
        supportsSystemPrompt: true,
        supportsToolUse: true,
      }];
    },
  };
}

/** Provider that immediately calls stop_hunting with a given reason. */
function createStopHuntingProvider(reason: string): ModelProvider {
  return {
    providerId: 'mock',
    displayName: 'Mock Provider',
    async sendMessage(_m: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
      return {
        content: 'Done.',
        model: options.model,
        inputTokens: 50,
        outputTokens: 25,
        stopReason: 'tool_use',
        toolCalls: [{
          type: 'tool_use',
          id: 'tool_stop',
          name: 'stop_hunting',
          input: { reason, summary: 'done' },
        }],
        contentBlocks: [
          { type: 'text', text: 'Done.' },
          { type: 'tool_use', id: 'tool_stop', name: 'stop_hunting', input: { reason, summary: 'done' } },
        ],
      };
    },
    async *streamMessage(_m: ChatMessage[], _o: SendMessageOptions): AsyncGenerator<StreamChunk> {
      yield { type: 'message_stop', inputTokens: 0, outputTokens: 0 };
    },
    getAvailableModels(): ModelInfo[] {
      return [{
        id: 'mock-model',
        displayName: 'Mock Model',
        contextWindow: 128000,
        maxOutputTokens: 4096,
        supportsStreaming: true,
        supportsSystemPrompt: true,
        supportsToolUse: true,
      }];
    },
  };
}

/**
 * Provider that runs a few commands then emits a valid report_finding — used
 * to verify non-recon agents with findings still succeed (regression safety).
 */
function createFindingProvider(): ModelProvider {
  let idx = 0;
  return {
    providerId: 'mock',
    displayName: 'Mock Provider',
    async sendMessage(_m: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
      const i = idx++;
      if (i < 3) {
        return {
          content: 'probe',
          model: options.model,
          inputTokens: 50,
          outputTokens: 25,
          stopReason: 'tool_use',
          toolCalls: [{
            type: 'tool_use',
            id: `tc_${i}`,
            name: 'execute_command',
            input: { command: `curl -s https://example.com/${i}`, target: 'https://example.com', reasoning: 'r', category: 'recon' },
          }],
          contentBlocks: [
            { type: 'text', text: 'probe' },
            { type: 'tool_use', id: `tc_${i}`, name: 'execute_command', input: { command: `curl -s https://example.com/${i}`, target: 'https://example.com', reasoning: 'r', category: 'recon' } },
          ],
        };
      }
      return {
        content: 'Found',
        model: options.model,
        inputTokens: 50,
        outputTokens: 25,
        stopReason: 'tool_use',
        toolCalls: [{
          type: 'tool_use',
          id: 'tc_report',
          name: 'report_finding',
          input: {
            title: 'Real XSS',
            vulnerability_type: 'xss_reflected',
            severity: 'high',
            target: 'https://example.com',
            description: 'reflected',
            evidence: ['<script>alert(1)</script> reflected'],
            reproduction_steps: ['go', 'inject'],
            impact: 'session theft',
            confidence: 85,
          },
        }],
        contentBlocks: [
          { type: 'text', text: 'Found' },
          { type: 'tool_use', id: 'tc_report', name: 'report_finding', input: {} },
        ],
      };
    },
    async *streamMessage(_m: ChatMessage[], _o: SendMessageOptions): AsyncGenerator<StreamChunk> {
      yield { type: 'message_stop', inputTokens: 0, outputTokens: 0 };
    },
    getAvailableModels(): ModelInfo[] {
      return [{
        id: 'mock-model',
        displayName: 'Mock Model',
        contextWindow: 128000,
        maxOutputTokens: 4096,
        supportsStreaming: true,
        supportsSystemPrompt: true,
        supportsToolUse: true,
      }];
    },
  };
}

// ─── Config helper ──────────────────────────────────────────────────────────

function makeConfig(provider: ModelProvider, agentType: string | undefined, maxIterations: number): ReactLoopConfig {
  return {
    provider,
    model: 'mock-model',
    systemPrompt: 'You are a test agent.',
    goal: 'Map surface',
    tools: [],
    target: 'https://example.com',
    scope: ['example.com'],
    maxIterations,
    agentType,
    onExecuteCommand: async () => ({
      success: true,
      stdout: 'probe ok',
      stderr: '',
      exitCode: 0,
      executionTimeMs: 10,
    }),
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('Session 25 Issue #6 — recon success semantics', () => {
  it('recon + 0 tool calls + iteration_limit → success=false (empty run)', async () => {
    // Loop exits immediately because maxIterations=0 means no iterations run.
    const loop = new ReactLoop(makeConfig(createIterationLimitProvider(5), 'recon', 0));
    const result = await loop.execute();
    expect(result.stopReason).toBe('iteration_limit');
    expect(result.toolCallCount).toBe(0);
    expect(result.success).toBe(false);
  });

  it('recon + 2 tool calls + iteration_limit → success=false (below threshold)', async () => {
    const loop = new ReactLoop(makeConfig(createIterationLimitProvider(10), 'recon', 2));
    const result = await loop.execute();
    expect(result.stopReason).toBe('iteration_limit');
    expect(result.toolCallCount).toBe(2);
    expect(result.success).toBe(false);
  });

  it('recon + 3 tool calls + iteration_limit → success=true (threshold reached)', async () => {
    const loop = new ReactLoop(makeConfig(createIterationLimitProvider(10), 'recon', 3));
    const result = await loop.execute();
    expect(result.stopReason).toBe('iteration_limit');
    expect(result.toolCallCount).toBe(3);
    expect(result.success).toBe(true);
  });

  it('recon + many tool calls + iteration_limit → success=true', async () => {
    const loop = new ReactLoop(makeConfig(createIterationLimitProvider(30), 'recon', 10));
    const result = await loop.execute();
    expect(result.stopReason).toBe('iteration_limit');
    expect(result.toolCallCount).toBe(10);
    expect(result.success).toBe(true);
  });

  it('recon + stop_hunting(task_complete) → success=true (existing path unchanged)', async () => {
    const loop = new ReactLoop(makeConfig(createStopHuntingProvider('task_complete'), 'recon', 10));
    const result = await loop.execute();
    expect(result.stopReason).toBe('task_complete');
    expect(result.success).toBe(true);
  });

  it('recon + stop_hunting(no_vulnerabilities) with 0 findings → success=true (existing path unchanged)', async () => {
    const loop = new ReactLoop(makeConfig(createStopHuntingProvider('no_vulnerabilities'), 'recon', 10));
    const result = await loop.execute();
    expect(result.stopReason).toBe('no_vulnerabilities');
    expect(result.findings).toHaveLength(0);
    expect(result.success).toBe(true);
  });

  it('NON-recon agent + iteration_limit + 10 tool calls + 0 findings → success=false (reconSuccess must NOT apply)', async () => {
    const loop = new ReactLoop(makeConfig(createIterationLimitProvider(30), 'xss-hunter', 10));
    const result = await loop.execute();
    expect(result.stopReason).toBe('iteration_limit');
    expect(result.toolCallCount).toBe(10);
    expect(result.findings).toHaveLength(0);
    expect(result.success).toBe(false);
  });

  it('NON-recon agent with real finding → success=true (regression safety)', async () => {
    const loop = new ReactLoop(makeConfig(createFindingProvider(), 'xss-hunter', 20));
    const result = await loop.execute();
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.success).toBe(true);
  });

  it('recon with undefined agentType → reconSuccess must NOT apply', async () => {
    // Defensive: if the config somehow omits agentType, we shouldn't grant success.
    const loop = new ReactLoop(makeConfig(createIterationLimitProvider(30), undefined, 10));
    const result = await loop.execute();
    expect(result.stopReason).toBe('iteration_limit');
    expect(result.success).toBe(false);
  });

  it('stopReason is preserved as iteration_limit (not mutated) when reconSuccess fires', async () => {
    // Log ground truth: even with success=true via reconSuccess, stopReason must
    // remain 'iteration_limit' so debugging isn't misled.
    const loop = new ReactLoop(makeConfig(createIterationLimitProvider(10), 'recon', 5));
    const result = await loop.execute();
    expect(result.stopReason).toBe('iteration_limit');
    expect(result.success).toBe(true);
  });
});

describe('Session 25 Issue #10 — recon emits endpoint observations', () => {
  it('ReconAgent.execute() surfaces URLs from tool stdout as category:endpoint observations', async () => {
    // Dynamically import to avoid circular-init issues with agent_catalog.
    const { ReconAgent } = await import('../agents/recon_agent');
    const { AnthropicProvider: _AP } = await import('../core/providers/types');
    void _AP;

    // Build a provider that issues two execute_command calls (subfinder, httpx)
    // with stdout containing URLs, then stop_hunting.
    let call = 0;
    const provider: ModelProvider = {
      providerId: 'mock',
      displayName: 'Mock',
      async sendMessage(_m: ChatMessage[], o: SendMessageOptions): Promise<ChatResponse> {
        const i = call++;
        if (i === 0) {
          return {
            content: 'subfinder',
            model: o.model, inputTokens: 10, outputTokens: 10, stopReason: 'tool_use',
            toolCalls: [{ type: 'tool_use', id: 't0', name: 'execute_command', input: { command: 'subfinder -d example.com -json -silent', target: 'example.com', reasoning: 'r', category: 'recon' } }],
            contentBlocks: [
              { type: 'text', text: 'subfinder' },
              { type: 'tool_use', id: 't0', name: 'execute_command', input: { command: 'subfinder -d example.com -json -silent', target: 'example.com', reasoning: 'r', category: 'recon' } },
            ],
          };
        }
        if (i === 1) {
          return {
            content: 'httpx',
            model: o.model, inputTokens: 10, outputTokens: 10, stopReason: 'tool_use',
            toolCalls: [{ type: 'tool_use', id: 't1', name: 'execute_command', input: { command: 'httpx -u https://api.example.com -json -silent', target: 'api.example.com', reasoning: 'r', category: 'recon' } }],
            contentBlocks: [
              { type: 'text', text: 'httpx' },
              { type: 'tool_use', id: 't1', name: 'execute_command', input: { command: 'httpx -u https://api.example.com -json -silent', target: 'api.example.com', reasoning: 'r', category: 'recon' } },
            ],
          };
        }
        return {
          content: 'done', model: o.model, inputTokens: 10, outputTokens: 10, stopReason: 'tool_use',
          toolCalls: [{ type: 'tool_use', id: 't_stop', name: 'stop_hunting', input: { reason: 'task_complete', summary: 'done' } }],
          contentBlocks: [
            { type: 'text', text: 'done' },
            { type: 'tool_use', id: 't_stop', name: 'stop_hunting', input: { reason: 'task_complete', summary: 'done' } },
          ],
        };
      },
      async *streamMessage(_m: ChatMessage[], _o: SendMessageOptions): AsyncGenerator<StreamChunk> {
        yield { type: 'message_stop', inputTokens: 0, outputTokens: 0 };
      },
      getAvailableModels(): ModelInfo[] {
        return [{
          id: 'mock-model', displayName: 'Mock', contextWindow: 128000, maxOutputTokens: 4096,
          supportsStreaming: true, supportsSystemPrompt: true, supportsToolUse: true,
        }];
      },
    };

    const agent = new ReconAgent();
    await agent.initialize(provider, 'mock-model');
    agent.setCallbacks({
      autoApproveSafe: true,
      onExecuteCommand: async (cmd: string) => {
        if (cmd.includes('subfinder')) {
          return {
            success: true,
            stdout: '{"host":"api.example.com"}\n{"host":"admin.example.com"}\nhttps://api.example.com/v1 https://api.example.com/users\n',
            stderr: '',
            exitCode: 0,
            executionTimeMs: 20,
          };
        }
        return {
          success: true,
          stdout: '{"url":"https://api.example.com/v1","status":200}\nhttps://admin.example.com/login\n',
          stderr: '',
          exitCode: 0,
          executionTimeMs: 20,
        };
      },
    });
    const result = await agent.execute({
      id: 'task_test',
      target: 'example.com',
      scope: ['example.com'],
      description: 'Map the attack surface',
      parameters: { availableTools: ['subfinder', 'httpx'] },
    });

    const endpointObs = (result.observations ?? []).filter(o => o.category === 'endpoint');
    expect(endpointObs.length).toBeGreaterThan(0);
    // Must match generateSolverTasks' regex extraction (https?://...).
    expect(endpointObs.every(o => /^https?:\/\//.test(o.detail))).toBe(true);
    const urls = endpointObs.map(o => o.detail);
    expect(urls.some(u => u.includes('api.example.com'))).toBe(true);
  });
});

/**
 * Hunt #7 Bug Fix — H22: Minimum Tool-Call Gate for Findings
 *
 * Tests that the hallucination gate in the ReAct loop rejects findings from
 * agents that haven't performed sufficient HTTP interactions. This prevents
 * the scenario from Hunt #7 where the OAuth Hunter reported 585 findings
 * after only 1 iteration and 0 HTTP requests.
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

// ─── Mock Provider Factory ──────────────────────────────────────────────────

/**
 * Creates a mock provider that returns a scripted sequence of tool calls.
 * Each call to sendMessage returns the next tool call in the sequence.
 * After the sequence is exhausted, it calls stop_hunting.
 */
function createScriptedProvider(
  toolCallSequence: Array<{ name: string; input: Record<string, unknown> }>
): ModelProvider {
  let callIndex = 0;

  return {
    providerId: 'mock',
    displayName: 'Mock Provider',

    async sendMessage(_messages: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
      const idx = callIndex++;

      if (idx < toolCallSequence.length) {
        const tc = toolCallSequence[idx];
        return {
          content: `Executing ${tc.name}`,
          model: options.model,
          inputTokens: 100,
          outputTokens: 50,
          stopReason: 'tool_use',
          toolCalls: [{
            type: 'tool_use',
            id: `tool_${idx}`,
            name: tc.name,
            input: tc.input,
          }],
          contentBlocks: [
            { type: 'text', text: `Executing ${tc.name}` },
            {
              type: 'tool_use',
              id: `tool_${idx}`,
              name: tc.name,
              input: tc.input,
            },
          ],
        };
      }

      // Default: stop hunting
      return {
        content: 'Done.',
        model: options.model,
        inputTokens: 50,
        outputTokens: 25,
        stopReason: 'tool_use',
        toolCalls: [{
          type: 'tool_use',
          id: `tool_stop_${idx}`,
          name: 'stop_hunting',
          input: { reason: 'task_complete', summary: 'Testing complete' },
        }],
        contentBlocks: [
          { type: 'text', text: 'Done.' },
          {
            type: 'tool_use',
            id: `tool_stop_${idx}`,
            name: 'stop_hunting',
            input: { reason: 'task_complete', summary: 'Testing complete' },
          },
        ],
      };
    },

    async *streamMessage(_messages: ChatMessage[], _options: SendMessageOptions): AsyncGenerator<StreamChunk> {
      yield { type: 'content_delta', content: 'Stream test' };
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
        supportsToolUse: true,
      }];
    },
  };
}

/** Standard report_finding input */
function makeReportFindingInput(title: string): Record<string, unknown> {
  return {
    title,
    vulnerability_type: 'oauth_missing_state',
    severity: 'high',
    target: 'https://example.com/oauth',
    description: 'OAuth missing state parameter',
    evidence: ['Evidence line 1'],
    reproduction_steps: ['Step 1', 'Step 2'],
    impact: 'Account takeover',
    confidence: 80,
  };
}

/** Standard execute_command input */
function makeCommandInput(command: string): Record<string, unknown> {
  return {
    command,
    target: 'https://example.com',
    reasoning: 'Testing the target',
    category: 'recon',
  };
}

/** Standard http_request input */
function makeHttpRequestInput(url: string): Record<string, unknown> {
  return {
    url,
    method: 'GET',
  };
}

/** Create a basic ReactLoop config */
function makeConfig(provider: ModelProvider): ReactLoopConfig {
  return {
    provider,
    model: 'mock-model',
    systemPrompt: 'You are a security tester.',
    goal: 'Test the target',
    tools: [], // Tools are built-in to the ReactLoop
    target: 'https://example.com',
    scope: ['example.com'],
    maxIterations: 20,
    // Mock command executor that always succeeds
    onExecuteCommand: async (_command: string, _target: string) => ({
      success: true,
      stdout: 'Command output',
      stderr: '',
      exitCode: 0,
      executionTimeMs: 100,
    }),
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('Hallucination Gate (H22)', () => {
  it('rejects finding at iteration 0 with 0 HTTP requests', async () => {
    // OAuth Hunter scenario: immediately reports a finding with zero work
    const provider = createScriptedProvider([
      { name: 'report_finding', input: makeReportFindingInput('Fake OAuth Finding') },
    ]);

    const loop = new ReactLoop(makeConfig(provider));
    const result = await loop.execute();

    // Finding should be rejected — 0 HTTP requests, iteration 0
    expect(result.findings).toHaveLength(0);
    expect(result.httpRequestCount).toBe(0);
  });

  it('rejects 585 hallucinated findings with 0 HTTP requests (Hunt #7 scenario)', async () => {
    // Exact scenario: OAuth Hunter reported 585 findings in 1 tool call
    // Simulate with multiple report_finding calls, all rejected
    const sequence = Array.from({ length: 10 }, (_, i) => ({
      name: 'report_finding',
      input: makeReportFindingInput(`Hallucinated Finding ${i + 1}`),
    }));

    const provider = createScriptedProvider(sequence);
    const loop = new ReactLoop(makeConfig(provider));
    const result = await loop.execute();

    // ALL findings should be rejected
    expect(result.findings).toHaveLength(0);
    expect(result.httpRequestCount).toBe(0);
  });

  it('accepts finding after >= 3 execute_command calls (iteration >= 3)', async () => {
    const provider = createScriptedProvider([
      { name: 'execute_command', input: makeCommandInput('curl -s https://example.com') },
      { name: 'execute_command', input: makeCommandInput('curl -s https://example.com/api') },
      { name: 'execute_command', input: makeCommandInput('curl -s https://example.com/login') },
      { name: 'report_finding', input: makeReportFindingInput('Real XSS Finding') },
    ]);

    const loop = new ReactLoop(makeConfig(provider));
    const result = await loop.execute();

    // Finding accepted — 3 execute_command calls, iteration 3
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].title).toBe('Real XSS Finding');
    expect(result.httpRequestCount).toBe(3);
  });

  it('accepts finding at iteration 2 with >= 3 HTTP request calls (HTTP count overrides)', async () => {
    // HTTP count is the stronger signal — 3 http_request calls in 2 iterations
    const config = makeConfig(createScriptedProvider([])); // Provider won't be used for this specific test

    // Create provider that returns multiple tool calls per iteration
    let callCount = 0;
    const provider: ModelProvider = {
      providerId: 'mock',
      displayName: 'Mock',
      async sendMessage(_m: ChatMessage[], opts: SendMessageOptions): Promise<ChatResponse> {
        callCount++;
        if (callCount === 1) {
          // First iteration: 2 http_request calls
          return {
            content: 'Testing',
            model: opts.model,
            inputTokens: 100,
            outputTokens: 50,
            stopReason: 'tool_use',
            toolCalls: [
              { type: 'tool_use', id: 'http_1', name: 'execute_command', input: makeCommandInput('curl https://example.com/1') },
              { type: 'tool_use', id: 'http_2', name: 'execute_command', input: makeCommandInput('curl https://example.com/2') },
            ],
            contentBlocks: [
              { type: 'text', text: 'Testing' },
              { type: 'tool_use', id: 'http_1', name: 'execute_command', input: makeCommandInput('curl https://example.com/1') },
              { type: 'tool_use', id: 'http_2', name: 'execute_command', input: makeCommandInput('curl https://example.com/2') },
            ],
          };
        }
        if (callCount === 2) {
          // Second iteration: 1 more http + report
          return {
            content: 'Found vuln',
            model: opts.model,
            inputTokens: 100,
            outputTokens: 50,
            stopReason: 'tool_use',
            toolCalls: [
              { type: 'tool_use', id: 'http_3', name: 'execute_command', input: makeCommandInput('curl https://example.com/3') },
              { type: 'tool_use', id: 'report_1', name: 'report_finding', input: makeReportFindingInput('Real Finding') },
            ],
            contentBlocks: [
              { type: 'text', text: 'Found vuln' },
              { type: 'tool_use', id: 'http_3', name: 'execute_command', input: makeCommandInput('curl https://example.com/3') },
              { type: 'tool_use', id: 'report_1', name: 'report_finding', input: makeReportFindingInput('Real Finding') },
            ],
          };
        }
        return {
          content: 'Done',
          model: opts.model,
          inputTokens: 50,
          outputTokens: 25,
          stopReason: 'tool_use',
          toolCalls: [{ type: 'tool_use', id: 'stop', name: 'stop_hunting', input: { reason: 'task_complete', summary: 'Done' } }],
          contentBlocks: [
            { type: 'text', text: 'Done' },
            { type: 'tool_use', id: 'stop', name: 'stop_hunting', input: { reason: 'task_complete', summary: 'Done' } },
          ],
        };
      },
      async *streamMessage(): AsyncGenerator<StreamChunk> {
        yield { type: 'message_stop', inputTokens: 0, outputTokens: 0 };
      },
      getAvailableModels: () => [{ id: 'mock', displayName: 'Mock', contextWindow: 128000, maxOutputTokens: 4096, supportsStreaming: true, supportsSystemPrompt: true, supportsToolUse: true }],
    };

    const loop = new ReactLoop({
      ...config,
      provider,
    });
    const result = await loop.execute();

    // 3 HTTP requests by iteration 1 (0-indexed), finding reported at iteration 1
    // httpRequestCount >= 3 overrides the iteration < 3 check
    expect(result.findings).toHaveLength(1);
    expect(result.httpRequestCount).toBe(3);
  });

  it('rejects finding at iteration 1 with only 1 HTTP request', async () => {
    const provider = createScriptedProvider([
      { name: 'execute_command', input: makeCommandInput('curl -s https://example.com') },
      { name: 'report_finding', input: makeReportFindingInput('Premature Finding') },
    ]);

    const loop = new ReactLoop(makeConfig(provider));
    const result = await loop.execute();

    // Rejected: only 1 HTTP request and 1 iteration (both < 3)
    expect(result.findings).toHaveLength(0);
    expect(result.httpRequestCount).toBe(1);
  });

  it('legitimate Business Logic Hunter with 91 tool calls works', async () => {
    // Simulates a legitimate agent with many execute_command calls
    const sequence: Array<{ name: string; input: Record<string, unknown> }> = [];
    // 10 command calls (representing the real agent's work)
    for (let i = 0; i < 10; i++) {
      sequence.push({
        name: 'execute_command',
        input: makeCommandInput(`curl -s https://example.com/api/${i}`),
      });
    }
    // Then report a finding
    sequence.push({
      name: 'report_finding',
      input: makeReportFindingInput('Business Logic: Zero Price'),
    });

    const provider = createScriptedProvider(sequence);
    const loop = new ReactLoop(makeConfig(provider));
    const result = await loop.execute();

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].title).toBe('Business Logic: Zero Price');
    expect(result.httpRequestCount).toBe(10);
  });

  it('includes httpRequestCount in ReactLoopResult', async () => {
    const provider = createScriptedProvider([
      { name: 'execute_command', input: makeCommandInput('curl https://example.com') },
      { name: 'execute_command', input: makeCommandInput('curl https://example.com/api') },
    ]);

    const loop = new ReactLoop(makeConfig(provider));
    const result = await loop.execute();

    expect(result.httpRequestCount).toBe(2);
    expect(typeof result.httpRequestCount).toBe('number');
  });

  it('agent continues after finding is rejected (soft gate)', async () => {
    const provider = createScriptedProvider([
      // First report: rejected (no HTTP work yet)
      { name: 'report_finding', input: makeReportFindingInput('Premature Finding') },
      // Agent continues, does real work
      { name: 'execute_command', input: makeCommandInput('curl https://example.com/1') },
      { name: 'execute_command', input: makeCommandInput('curl https://example.com/2') },
      { name: 'execute_command', input: makeCommandInput('curl https://example.com/3') },
      // Second report: accepted (now has 3 HTTP requests)
      { name: 'report_finding', input: makeReportFindingInput('Real Finding After Work') },
    ]);

    const loop = new ReactLoop(makeConfig(provider));
    const result = await loop.execute();

    // First finding rejected, second accepted
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].title).toBe('Real Finding After Work');
    expect(result.httpRequestCount).toBe(3);
  });
});

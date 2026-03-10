/**
 * Kill Switch End-to-End Tests
 *
 * Verifies that the kill switch properly aborts hunts,
 * stops all agents, and marks sessions as complete.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { OrchestratorEngine } from '../../core/orchestrator/orchestrator_engine';
import type { OrchestratorConfig } from '../../core/orchestrator/orchestrator_engine';
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

function createSlowMockProvider(): ModelProvider {
  let callCount = 0;

  return {
    providerId: 'slow-mock',
    displayName: 'Slow Mock Provider',

    async sendMessage(_messages: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
      callCount++;

      // First call: dispatch an agent (simulating work)
      if (callCount <= 2) {
        await new Promise(r => setTimeout(r, 150));
        return {
          content: 'Dispatching recon agent...',
          model: options.model,
          inputTokens: 200,
          outputTokens: 100,
          stopReason: 'tool_use',
          toolCalls: [{
            type: 'tool_use',
            id: `tool_${callCount}`,
            name: 'dispatch_agent',
            input: {
              agent_type: 'recon',
              target: 'test-target.com',
              task_description: 'Enumerate subdomains',
            },
          }],
          contentBlocks: [
            { type: 'text', text: 'Dispatching recon agent...' },
            {
              type: 'tool_use',
              id: `tool_${callCount}`,
              name: 'dispatch_agent',
              input: {
                agent_type: 'recon',
                target: 'test-target.com',
                task_description: 'Enumerate subdomains',
              },
            },
          ],
        };
      }

      // After that, stop
      return {
        content: 'Done.',
        model: options.model,
        inputTokens: 100,
        outputTokens: 50,
        stopReason: 'tool_use',
        toolCalls: [{
          type: 'tool_use',
          id: `stop_${callCount}`,
          name: 'stop_hunting',
          input: { reason: 'Tasks done' },
        }],
        contentBlocks: [
          { type: 'text', text: 'Done.' },
          {
            type: 'tool_use',
            id: `stop_${callCount}`,
            name: 'stop_hunting',
            input: { reason: 'Tasks done' },
          },
        ],
      };
    },

    async *streamMessage(): AsyncGenerator<StreamChunk> {
      yield { type: 'content_delta', content: 'streaming' };
    },

    getAvailableModels(): ModelInfo[] {
      return [{
        id: 'slow-mock-model',
        displayName: 'Slow Mock',
        contextWindow: 128000,
        maxOutputTokens: 4096,
        supportsStreaming: true,
        supportsSystemPrompt: true,
        inputCostPer1M: 0,
        outputCostPer1M: 0,
      }];
    },

    async validateApiKey(): Promise<boolean> { return true; },
    estimateCost(): number { return 0; },
    supportsToolUse: true,
  };
}

const mockGuidelines: ProgramGuidelines = {
  programHandle: 'ks_test',
  programName: 'Kill Switch Test',
  url: 'https://hackerone.com/ks_test',
  scope: {
    inScope: ['*.test-target.com'],
    outOfScope: [],
  },
  bountyRange: { min: 100, max: 25000 },
  rules: [],
  severity: { critical: '$5000-$25000' },
  importedAt: new Date(),
};

describe('Kill Switch E2E', () => {
  let messages: ConversationMessage[];
  let phases: SessionPhase[];

  beforeEach(() => {
    messages = [];
    phases = [];
  });

  it('should abort hunt when abortHunt is called', async () => {
    const provider = createSlowMockProvider();
    const config: OrchestratorConfig = {
      provider,
      model: 'slow-mock-model',
      maxConcurrentAgents: 2,
    };

    const engine = new OrchestratorEngine(config);
    engine.setMessageCallback((msg) => messages.push(msg));
    engine.setPhaseCallback((phase) => phases.push(phase));

    // Start hunt and abort quickly
    const huntPromise = engine.startHunt(mockGuidelines);

    // Wait a bit for the hunt to start processing
    await new Promise(r => setTimeout(r, 200));

    // Trigger stop (simulates kill switch behavior)
    engine.abortHunt();

    // Wait for hunt to finish
    await huntPromise;

    // Verify the hunt reached the complete phase
    expect(phases).toContain('complete');
  });

  it('should handle abortHunt when no hunt is active', () => {
    const provider = createSlowMockProvider();
    const config: OrchestratorConfig = {
      provider,
      model: 'slow-mock-model',
    };

    const engine = new OrchestratorEngine(config);

    // Should not throw
    expect(() => engine.abortHunt()).not.toThrow();
  });

  it('should go through hunting then complete phases', async () => {
    const provider = createSlowMockProvider();
    const config: OrchestratorConfig = {
      provider,
      model: 'slow-mock-model',
    };

    const engine = new OrchestratorEngine(config);
    engine.setPhaseCallback((phase) => phases.push(phase));

    // Start and let it run to completion
    const huntPromise = engine.startHunt(mockGuidelines);

    // Abort after a short time to avoid infinite loops
    setTimeout(() => engine.abortHunt(), 2000);
    await huntPromise;

    // Should have been in hunting phase at some point
    // Normal completion goes to 'reporting'; abort goes to 'complete'
    expect(phases).toContain('hunting');
    const finalPhase = phases[phases.length - 1];
    expect(['complete', 'reporting']).toContain(finalPhase);
  });
});

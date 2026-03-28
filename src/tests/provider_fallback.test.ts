/**
 * Provider Fallback & Resilience Tests (Phase 20K)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ResilientProvider, ResilientProviderError } from '../core/providers/provider_fallback';
import type { FallbackConfig, FallbackProviderEntry, ProviderHealth } from '../core/providers/provider_fallback';
import type { ModelProvider, ChatMessage, ChatResponse, StreamChunk, SendMessageOptions } from '../core/providers/types';

// ─── Mock Provider Factory ───────────────────────────────────────────────────

function createMockProvider(
  overrides?: Partial<{
    sendMessage: ModelProvider['sendMessage'];
    streamMessage: ModelProvider['streamMessage'];
    estimateCost: ModelProvider['estimateCost'];
    label: string;
  }>,
): ModelProvider {
  const label = overrides?.label ?? 'mock';
  return {
    providerId: label,
    displayName: label,
    sendMessage: overrides?.sendMessage ?? vi.fn(async (): Promise<ChatResponse> => ({
      content: `Response from ${label}`,
      model: `${label}-model`,
      inputTokens: 100,
      outputTokens: 50,
      stopReason: 'end_turn',
    })),
    streamMessage: overrides?.streamMessage ?? vi.fn(async function* (): AsyncGenerator<StreamChunk> {
      yield { type: 'content_delta', content: `Stream from ${label}` };
      yield { type: 'message_stop', inputTokens: 100, outputTokens: 50 };
    }),
    getAvailableModels: vi.fn(() => [
      {
        id: `${label}-model`,
        displayName: `${label} Model`,
        contextWindow: 128000,
        maxOutputTokens: 4096,
        supportsStreaming: true,
        supportsSystemPrompt: true,
        inputCostPer1M: 3,
        outputCostPer1M: 15,
      },
    ]),
    validateApiKey: vi.fn(async () => true),
    estimateCost: overrides?.estimateCost ?? vi.fn(() => 0.001),
  } as unknown as ModelProvider;
}

function makeConfig(overrides?: Partial<FallbackConfig>): FallbackConfig {
  return {
    providers: [
      { provider: createMockProvider({ label: 'primary' }), model: 'primary-model', label: 'Primary' },
      { provider: createMockProvider({ label: 'secondary' }), model: 'secondary-model', label: 'Secondary' },
    ],
    maxRetriesPerProvider: 1,
    requestTimeoutMs: 5000,
    circuitBreakerThreshold: 2,
    circuitBreakerCooldownMs: 100, // Short for tests
    ...overrides,
  };
}

const TEST_MESSAGES: ChatMessage[] = [
  { role: 'user', content: 'Hello' },
];

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('ResilientProvider', () => {
  describe('constructor', () => {
    it('requires at least one provider', () => {
      expect(() => new ResilientProvider({ providers: [] })).toThrow();
    });

    it('creates with valid config', () => {
      const rp = new ResilientProvider(makeConfig());
      expect(rp.displayName).toContain('Primary');
      expect(rp.displayName).toContain('Secondary');
    });
  });

  describe('sendMessage — happy path', () => {
    it('sends to primary provider successfully', async () => {
      const config = makeConfig();
      const rp = new ResilientProvider(config);

      const response = await rp.sendMessage(TEST_MESSAGES, { model: 'primary-model', maxTokens: 100 });

      expect(response.content).toContain('primary');
      expect(config.providers[0].provider.sendMessage).toHaveBeenCalled();
      expect(config.providers[1].provider.sendMessage).not.toHaveBeenCalled();
    });
  });

  describe('sendMessage — fallback', () => {
    it('falls back to secondary when primary fails', async () => {
      const primary = createMockProvider({
        label: 'failing',
        sendMessage: vi.fn(async () => { throw new Error('API down'); }),
      });
      const secondary = createMockProvider({ label: 'backup' });

      const onFallback = vi.fn();
      const rp = new ResilientProvider({
        providers: [
          { provider: primary, model: 'failing-model', label: 'Failing' },
          { provider: secondary, model: 'backup-model', label: 'Backup' },
        ],
        maxRetriesPerProvider: 0,
        onFallback,
      });

      const response = await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });

      expect(response.content).toContain('backup');
      expect(onFallback).toHaveBeenCalledWith('Failing', 'Backup', 'API down');
    });

    it('throws when all providers fail', async () => {
      const provider1 = createMockProvider({
        label: 'fail1',
        sendMessage: vi.fn(async () => { throw new Error('fail 1'); }),
      });
      const provider2 = createMockProvider({
        label: 'fail2',
        sendMessage: vi.fn(async () => { throw new Error('fail 2'); }),
      });

      const rp = new ResilientProvider({
        providers: [
          { provider: provider1, model: 'model1', label: 'Provider1' },
          { provider: provider2, model: 'model2', label: 'Provider2' },
        ],
        maxRetriesPerProvider: 0,
      });

      await expect(rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 }))
        .rejects.toThrow(ResilientProviderError);
    });
  });

  describe('sendMessage — retry on rate limit', () => {
    it('retries on 429 error with backoff', async () => {
      let callCount = 0;
      const rateLimitThenSucceed = createMockProvider({
        label: 'ratelimited',
        sendMessage: vi.fn(async (): Promise<ChatResponse> => {
          callCount++;
          if (callCount === 1) {
            throw new Error('429 Too Many Requests');
          }
          return {
            content: 'Success after retry',
            model: 'ratelimited-model',
            inputTokens: 100,
            outputTokens: 50,
            stopReason: 'end_turn',
          };
        }),
      });

      const rp = new ResilientProvider({
        providers: [
          { provider: rateLimitThenSucceed, model: 'model', label: 'RateLimited' },
        ],
        maxRetriesPerProvider: 2,
      });

      const response = await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });
      expect(response.content).toBe('Success after retry');
      expect(callCount).toBe(2);
    });
  });

  describe('circuit breaker', () => {
    it('triggers after N consecutive failures', async () => {
      let primaryCalls = 0;
      const primary = createMockProvider({
        label: 'breaking',
        sendMessage: vi.fn(async () => {
          primaryCalls++;
          throw new Error('persistent failure');
        }),
      });
      const secondary = createMockProvider({ label: 'healthy' });

      const rp = new ResilientProvider({
        providers: [
          { provider: primary, model: 'model', label: 'Breaking' },
          { provider: secondary, model: 'model', label: 'Healthy' },
        ],
        maxRetriesPerProvider: 0,
        circuitBreakerThreshold: 2,
        circuitBreakerCooldownMs: 500,
      });

      // First two calls: primary fails → secondary succeeds
      await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });
      await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });

      // Circuit should be broken now — primary skipped
      primaryCalls = 0;
      await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });
      expect(primaryCalls).toBe(0); // Primary was skipped

      const health = rp.getHealthStatus();
      const brokenProvider = health.find(h => h.label === 'Breaking');
      expect(brokenProvider?.isAvailable).toBe(false);
    });

    it('resets after cooldown', async () => {
      let callCount = 0;
      const primary = createMockProvider({
        label: 'recovering',
        sendMessage: vi.fn(async (): Promise<ChatResponse> => {
          callCount++;
          if (callCount <= 2) throw new Error('failing');
          return {
            content: 'Recovered',
            model: 'model',
            inputTokens: 100,
            outputTokens: 50,
            stopReason: 'end_turn',
          };
        }),
      });
      const secondary = createMockProvider({ label: 'backup2' });

      const rp = new ResilientProvider({
        providers: [
          { provider: primary, model: 'model', label: 'Recovering' },
          { provider: secondary, model: 'model', label: 'Backup' },
        ],
        maxRetriesPerProvider: 0,
        circuitBreakerThreshold: 2,
        circuitBreakerCooldownMs: 100,
      });

      // Trigger circuit breaker
      await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });
      await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });

      // Wait for cooldown
      await new Promise(resolve => setTimeout(resolve, 150));

      // Primary should be available again (probe request)
      const response = await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });
      expect(response.content).toBe('Recovered');
    });
  });

  describe('cost ceiling', () => {
    it('emits warning at 80% of ceiling', async () => {
      const onCostWarning = vi.fn();
      const provider = createMockProvider({
        label: 'costly',
        estimateCost: vi.fn(() => 0.9), // $0.90 per call
      });

      const rp = new ResilientProvider({
        providers: [
          { provider, model: 'model', label: 'Costly' },
        ],
        costCeilingUsd: 1.0,
        onCostWarning,
      });

      await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });

      // $0.90 >= 80% of $1.00 → warning
      expect(onCostWarning).toHaveBeenCalledWith(expect.closeTo(0.9, 1), 1.0);
    });

    it('blocks requests when ceiling reached', async () => {
      const provider = createMockProvider({
        label: 'expensive',
        estimateCost: vi.fn(() => 0.6),
      });

      const rp = new ResilientProvider({
        providers: [
          { provider, model: 'model', label: 'Expensive' },
        ],
        costCeilingUsd: 1.0,
      });

      // First call: $0.60
      await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });
      // Second call: $1.20 total → should succeed but push us over
      await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });

      // Third call should be blocked
      await expect(rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 }))
        .rejects.toThrow(/cost ceiling/i);
    });
  });

  describe('streaming', () => {
    it('streams from primary successfully', async () => {
      const config = makeConfig();
      const rp = new ResilientProvider(config);

      const chunks: StreamChunk[] = [];
      for await (const chunk of rp.streamMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 })) {
        chunks.push(chunk);
      }

      expect(chunks.length).toBeGreaterThan(0);
      expect(chunks.some(c => c.content?.includes('primary'))).toBe(true);
    });

    it('falls back during streaming failure', async () => {
      const failingStream = createMockProvider({
        label: 'stream-fail',
        streamMessage: vi.fn(async function* () {
          throw new Error('stream broken');
        }),
      });
      const workingStream = createMockProvider({ label: 'stream-ok' });

      const rp = new ResilientProvider({
        providers: [
          { provider: failingStream, model: 'model', label: 'Failing' },
          { provider: workingStream, model: 'model', label: 'Working' },
        ],
      });

      const chunks: StreamChunk[] = [];
      for await (const chunk of rp.streamMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 })) {
        chunks.push(chunk);
      }

      expect(chunks.some(c => c.content?.includes('stream-ok'))).toBe(true);
    });
  });

  describe('health status', () => {
    it('reports all providers initially available', () => {
      const rp = new ResilientProvider(makeConfig());
      const health = rp.getHealthStatus();

      expect(health).toHaveLength(2);
      expect(health.every(h => h.isAvailable)).toBe(true);
      expect(health.every(h => h.consecutiveFailures === 0)).toBe(true);
    });

    it('tracks total cost', async () => {
      const provider = createMockProvider({
        label: 'tracked',
        estimateCost: vi.fn(() => 0.05),
      });

      const rp = new ResilientProvider({
        providers: [{ provider, model: 'model', label: 'Tracked' }],
      });

      await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });
      await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });

      expect(rp.getTotalCost()).toBeCloseTo(0.10, 2);
    });
  });

  describe('manual provider management', () => {
    it('disableProvider prevents using that provider', async () => {
      const primary = createMockProvider({ label: 'disabled' });
      const secondary = createMockProvider({ label: 'active' });

      const rp = new ResilientProvider({
        providers: [
          { provider: primary, model: 'model', label: 'Disabled' },
          { provider: secondary, model: 'model', label: 'Active' },
        ],
      });

      rp.disableProvider('Disabled');

      const response = await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });
      expect(response.content).toContain('active');
      expect(primary.sendMessage).not.toHaveBeenCalled();
    });

    it('enableProvider re-enables a disabled provider', async () => {
      const provider = createMockProvider({ label: 're-enabled' });

      const rp = new ResilientProvider({
        providers: [
          { provider, model: 'model', label: 'Toggled' },
        ],
      });

      rp.disableProvider('Toggled');

      // Should fail — no providers available
      await expect(rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 }))
        .rejects.toThrow(ResilientProviderError);

      rp.enableProvider('Toggled');

      // Should work now
      const response = await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });
      expect(response.content).toContain('re-enabled');
    });

    it('resetCircuitBreakers resets all breakers', async () => {
      const primary = createMockProvider({
        label: 'broken',
        sendMessage: vi.fn(async () => { throw new Error('broken'); }),
      });
      const secondary = createMockProvider({ label: 'backup' });

      const rp = new ResilientProvider({
        providers: [
          { provider: primary, model: 'model', label: 'Broken' },
          { provider: secondary, model: 'model', label: 'Backup' },
        ],
        maxRetriesPerProvider: 0,
        circuitBreakerThreshold: 2,
        circuitBreakerCooldownMs: 999999, // Very long cooldown
      });

      // Trigger circuit breaker
      await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });
      await rp.sendMessage(TEST_MESSAGES, { model: 'test', maxTokens: 100 });

      const healthBefore = rp.getHealthStatus();
      expect(healthBefore.find(h => h.label === 'Broken')?.isAvailable).toBe(false);

      rp.resetCircuitBreakers();

      const healthAfter = rp.getHealthStatus();
      expect(healthAfter.find(h => h.label === 'Broken')?.isAvailable).toBe(true);
    });
  });

  describe('getAvailableModels', () => {
    it('returns models from all enabled providers', () => {
      const rp = new ResilientProvider(makeConfig());
      const models = rp.getAvailableModels();
      expect(models.length).toBeGreaterThanOrEqual(2);
    });

    it('excludes models from disabled providers', () => {
      const rp = new ResilientProvider(makeConfig());
      const allModels = rp.getAvailableModels();

      rp.disableProvider('Primary');
      const filteredModels = rp.getAvailableModels();

      expect(filteredModels.length).toBeLessThan(allModels.length);
    });
  });
});

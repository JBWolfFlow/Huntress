/**
 * Resilient Provider with Fallback & Circuit Breaker (Phase 20K)
 *
 * Wraps multiple AI providers with automatic failover, circuit breaker,
 * retry logic, and cost tracking. If the user's primary provider has an
 * outage, rate limit, or error, the entire hunt doesn't die.
 *
 * Circuit breaker pattern:
 * - After N consecutive failures: mark provider as broken
 * - After cooldown: allow one probe request
 * - If probe succeeds: reset breaker
 * - If probe fails: extend cooldown
 */

import type {
  ModelProvider,
  ChatMessage,
  ChatResponse,
  StreamChunk,
  SendMessageOptions,
  ModelInfo,
} from './types';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface FallbackProviderEntry {
  provider: ModelProvider;
  model: string;
  label: string;
}

export interface FallbackConfig {
  /** Ordered list of providers to try (primary first) */
  providers: FallbackProviderEntry[];
  /** Max retries per provider before falling back (default: 2) */
  maxRetriesPerProvider?: number;
  /** Timeout per request in ms (default: 60000) */
  requestTimeoutMs?: number;
  /** Number of consecutive failures to trigger circuit breaker (default: 3) */
  circuitBreakerThreshold?: number;
  /** Circuit breaker cooldown in ms (default: 300000 = 5 min) */
  circuitBreakerCooldownMs?: number;
  /** Per-session spending limit in USD (default: no limit) */
  costCeilingUsd?: number;
  /** Callback when falling back to a different provider */
  onFallback?: (from: string, to: string, reason: string) => void;
  /** Callback when approaching cost ceiling */
  onCostWarning?: (currentCost: number, ceiling: number) => void;
}

export interface ProviderHealth {
  label: string;
  isAvailable: boolean;
  consecutiveFailures: number;
  circuitBrokenUntil?: number;
  totalRequests: number;
  totalFailures: number;
  totalCost: number;
  avgLatencyMs: number;
}

export class ResilientProviderError extends Error {
  constructor(message: string, public readonly attempts: Array<{ label: string; error: string }>) {
    super(message);
    this.name = 'ResilientProviderError';
  }
}

// ─── Internal State ──────────────────────────────────────────────────────────

interface ProviderState {
  entry: FallbackProviderEntry;
  consecutiveFailures: number;
  circuitBrokenUntil: number;
  totalRequests: number;
  totalFailures: number;
  totalCost: number;
  totalLatencyMs: number;
  disabled: boolean;
}

// ─── Default Config ──────────────────────────────────────────────────────────

const DEFAULT_FALLBACK_CONFIG = {
  maxRetriesPerProvider: 2,
  requestTimeoutMs: 60_000,
  circuitBreakerThreshold: 3,
  circuitBreakerCooldownMs: 300_000,
};

// ─── Resilient Provider ──────────────────────────────────────────────────────

export class ResilientProvider implements ModelProvider {
  readonly providerId = 'resilient';
  readonly displayName: string;

  get supportsToolUse(): boolean {
    return this.states[0]?.entry.provider.supportsToolUse ?? false;
  }

  private config: FallbackConfig & typeof DEFAULT_FALLBACK_CONFIG;
  private states: ProviderState[];
  private totalSessionCost = 0;
  private costWarningEmitted = false;

  constructor(config: FallbackConfig) {
    if (config.providers.length === 0) {
      throw new Error('ResilientProvider requires at least one provider');
    }

    this.config = { ...DEFAULT_FALLBACK_CONFIG, ...config };
    this.displayName = `Resilient (${config.providers.map(p => p.label).join(' → ')})`;

    this.states = config.providers.map(entry => ({
      entry,
      consecutiveFailures: 0,
      circuitBrokenUntil: 0,
      totalRequests: 0,
      totalFailures: 0,
      totalCost: 0,
      totalLatencyMs: 0,
      disabled: false,
    }));
  }

  /** Send a complete message — tries each provider in order with retry and fallback */
  async sendMessage(messages: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
    this.checkCostCeiling();

    const attempts: Array<{ label: string; error: string }> = [];

    for (const state of this.getAvailableStates()) {
      const { entry } = state;

      for (let retry = 0; retry <= this.config.maxRetriesPerProvider; retry++) {
        try {
          const startTime = Date.now();

          // Use the provider's model unless overridden in options
          const mergedOptions: SendMessageOptions = {
            ...options,
            model: options.model ?? entry.model,
          };

          const response = await this.withTimeout(
            entry.provider.sendMessage(messages, mergedOptions),
            this.config.requestTimeoutMs,
          );

          // Record success
          const latencyMs = Date.now() - startTime;
          this.recordSuccess(state, latencyMs);

          // Track cost
          const cost = entry.provider.estimateCost(
            response.inputTokens,
            response.outputTokens,
            entry.model,
          );
          this.recordCost(state, cost);

          return response;
        } catch (error) {
          const errorMsg = error instanceof Error ? error.message : String(error);
          attempts.push({ label: entry.label, error: errorMsg });

          // Check if it's a rate limit (429)
          if (this.isRateLimitError(error) && retry < this.config.maxRetriesPerProvider) {
            const waitMs = this.extractRetryAfter(error) ?? (1000 * Math.pow(2, retry));
            await this.sleep(waitMs);
            continue;
          }

          // Check if it's a timeout and worth retrying
          if (this.isTimeoutError(error) && retry < this.config.maxRetriesPerProvider) {
            continue;
          }

          // Record failure
          this.recordFailure(state);

          // If all retries exhausted for this provider, fall back
          if (retry === this.config.maxRetriesPerProvider) {
            const nextState = this.getNextAvailableState(state);
            if (nextState) {
              this.config.onFallback?.(entry.label, nextState.entry.label, errorMsg);
            }
          }

          break; // Move to next provider
        }
      }
    }

    throw new ResilientProviderError(
      `All providers exhausted after ${attempts.length} attempt(s)`,
      attempts,
    );
  }

  /** Stream a response — tries each provider in order with fallback.
   *  If a provider fails mid-stream, we do NOT fall back (partial data already yielded).
   *  Fallback only happens on errors thrown before the first chunk is yielded. */
  async *streamMessage(messages: ChatMessage[], options: SendMessageOptions): AsyncGenerator<StreamChunk> {
    this.checkCostCeiling();

    const attempts: Array<{ label: string; error: string }> = [];

    for (const state of this.getAvailableStates()) {
      const { entry } = state;

      try {
        const startTime = Date.now();
        const mergedOptions: SendMessageOptions = {
          ...options,
          model: options.model ?? entry.model,
        };

        const stream = entry.provider.streamMessage(messages, mergedOptions);

        let lastInputTokens = 0;
        let lastOutputTokens = 0;
        let chunksYielded = 0;

        try {
          for await (const chunk of stream) {
            yield chunk;
            chunksYielded++;

            // Track tokens from message_stop chunks
            if (chunk.inputTokens !== undefined) lastInputTokens = chunk.inputTokens;
            if (chunk.outputTokens !== undefined) lastOutputTokens = chunk.outputTokens;
          }
        } catch (midStreamError) {
          // If we already yielded chunks, do NOT fall back — that would garble output.
          // Re-throw so the consumer knows the stream was interrupted.
          if (chunksYielded > 0) {
            this.recordFailure(state);
            throw midStreamError;
          }
          // No chunks yielded yet — treat as a connection error and try fallback
          throw midStreamError;
        }

        // Record success
        const latencyMs = Date.now() - startTime;
        this.recordSuccess(state, latencyMs);

        // Track cost from accumulated tokens
        if (lastInputTokens > 0 || lastOutputTokens > 0) {
          const cost = entry.provider.estimateCost(lastInputTokens, lastOutputTokens, entry.model);
          this.recordCost(state, cost);
        }

        return; // Stream completed successfully
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        attempts.push({ label: entry.label, error: errorMsg });
        this.recordFailure(state);

        const nextState = this.getNextAvailableState(state);
        if (nextState) {
          this.config.onFallback?.(entry.label, nextState.entry.label, errorMsg);
          continue; // Try next provider
        }
      }
    }

    throw new ResilientProviderError(
      `All providers exhausted during streaming after ${attempts.length} attempt(s)`,
      attempts,
    );
  }

  /** List all models across all providers */
  getAvailableModels(): ModelInfo[] {
    const models: ModelInfo[] = [];
    for (const state of this.states) {
      if (!state.disabled) {
        models.push(...state.entry.provider.getAvailableModels());
      }
    }
    return models;
  }

  /** Validate the primary provider's API key */
  async validateApiKey(key: string): Promise<boolean> {
    if (this.states.length === 0) return false;
    return this.states[0].entry.provider.validateApiKey(key);
  }

  /** Estimate cost using the primary provider's rates */
  estimateCost(inputTokens: number, outputTokens: number, model: string): number {
    if (this.states.length === 0) return 0;
    return this.states[0].entry.provider.estimateCost(inputTokens, outputTokens, model);
  }

  /** Get health status of all configured providers */
  getHealthStatus(): ProviderHealth[] {
    return this.states.map(state => ({
      label: state.entry.label,
      isAvailable: !state.disabled && !this.isCircuitBroken(state),
      consecutiveFailures: state.consecutiveFailures,
      circuitBrokenUntil: state.circuitBrokenUntil > Date.now() ? state.circuitBrokenUntil : undefined,
      totalRequests: state.totalRequests,
      totalFailures: state.totalFailures,
      totalCost: state.totalCost,
      avgLatencyMs: state.totalRequests > 0 ? Math.round(state.totalLatencyMs / state.totalRequests) : 0,
    }));
  }

  /** Get total cost across all providers this session */
  getTotalCost(): number {
    return this.totalSessionCost;
  }

  /** Manually disable a provider */
  disableProvider(label: string): void {
    const state = this.states.find(s => s.entry.label === label);
    if (state) state.disabled = true;
  }

  /** Manually enable a provider */
  enableProvider(label: string): void {
    const state = this.states.find(s => s.entry.label === label);
    if (state) state.disabled = false;
  }

  /** Reset all circuit breakers */
  resetCircuitBreakers(): void {
    for (const state of this.states) {
      state.consecutiveFailures = 0;
      state.circuitBrokenUntil = 0;
    }
  }

  // ─── Private Helpers ─────────────────────────────────────────────────────────

  private getAvailableStates(): ProviderState[] {
    return this.states.filter(s => !s.disabled && !this.isCircuitBroken(s));
  }

  private getNextAvailableState(current: ProviderState): ProviderState | undefined {
    const idx = this.states.indexOf(current);
    for (let i = idx + 1; i < this.states.length; i++) {
      const s = this.states[i];
      if (!s.disabled && !this.isCircuitBroken(s)) {
        return s;
      }
    }
    return undefined;
  }

  private isCircuitBroken(state: ProviderState): boolean {
    if (state.circuitBrokenUntil <= 0) return false;
    if (Date.now() >= state.circuitBrokenUntil) {
      // Cooldown expired — allow probe request
      state.circuitBrokenUntil = 0;
      return false;
    }
    return true;
  }

  private recordSuccess(state: ProviderState, latencyMs: number): void {
    state.totalRequests++;
    state.totalLatencyMs += latencyMs;
    state.consecutiveFailures = 0;
    // Reset circuit breaker on success (probe passed)
    state.circuitBrokenUntil = 0;
  }

  private recordFailure(state: ProviderState): void {
    state.totalRequests++;
    state.totalFailures++;
    state.consecutiveFailures++;

    // Check circuit breaker threshold
    if (state.consecutiveFailures >= this.config.circuitBreakerThreshold) {
      state.circuitBrokenUntil = Date.now() + this.config.circuitBreakerCooldownMs;
    }
  }

  private recordCost(state: ProviderState, cost: number): void {
    state.totalCost += cost;
    this.totalSessionCost += cost;

    // Check cost ceiling warning (80%)
    if (this.config.costCeilingUsd && !this.costWarningEmitted) {
      if (this.totalSessionCost >= this.config.costCeilingUsd * 0.8) {
        this.config.onCostWarning?.(this.totalSessionCost, this.config.costCeilingUsd);
        this.costWarningEmitted = true;
      }
    }
  }

  private checkCostCeiling(): void {
    if (this.config.costCeilingUsd && this.totalSessionCost >= this.config.costCeilingUsd) {
      throw new ResilientProviderError(
        `Cost ceiling of $${this.config.costCeilingUsd} reached (spent: $${this.totalSessionCost.toFixed(4)})`,
        [],
      );
    }
  }

  private isRateLimitError(error: unknown): boolean {
    if (error instanceof Error) {
      return error.message.includes('429') || error.message.toLowerCase().includes('rate limit');
    }
    return false;
  }

  private isTimeoutError(error: unknown): boolean {
    if (error instanceof Error) {
      return error.message.toLowerCase().includes('timeout') || error.message.includes('ETIMEDOUT');
    }
    return false;
  }

  private extractRetryAfter(error: unknown): number | undefined {
    if (error instanceof Error) {
      const match = error.message.match(/retry.after[:\s]*(\d+)/i);
      if (match) {
        return parseInt(match[1], 10) * 1000;
      }
    }
    return undefined;
  }

  private withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`Request timed out after ${timeoutMs}ms`)),
        timeoutMs,
      );

      promise
        .then(result => {
          clearTimeout(timer);
          resolve(result);
        })
        .catch(error => {
          clearTimeout(timer);
          reject(error);
        });
    });
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

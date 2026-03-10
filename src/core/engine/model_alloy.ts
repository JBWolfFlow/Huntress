/**
 * Model Alloy — XBOW's Key Innovation
 *
 * Alternates between different AI models within a single conversation thread.
 * Neither model knows about the other — they share a conversation where each
 * believes all prior assistant messages were their own.
 *
 * Models with lower correlation in solve rates produce better alloys:
 * - Claude Sonnet + Gemini 2.5 Pro (lowest correlation = highest boost)
 * - Claude Opus + GPT-4o (diversity of approach)
 *
 * The alloy can solve problems neither model can solve independently because
 * different models have different blind spots and reasoning patterns.
 */

import type {
  ModelProvider,
  ChatMessage,
  ChatResponse,
  StreamChunk,
  SendMessageOptions,
  ModelInfo,
} from '../providers/types';

// ─── Interfaces ──────────────────────────────────────────────────────────────

export interface AlloyComponent {
  provider: ModelProvider;
  model: string;
  /** Weight in rotation (higher = used more often) */
  weight?: number;
  /** Human-readable label for UI display */
  label?: string;
}

export interface AlloyConfig {
  components: AlloyComponent[];
  /** Rotation strategy */
  strategy: 'round_robin' | 'weighted' | 'random';
  /** Seed for deterministic PRNG (default: Date.now()) */
  seed?: number;
}

/** Per-component usage and performance statistics */
export interface AlloyComponentStats {
  callCount: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  totalCostUsd: number;
  totalLatencyMs: number;
  errorCount: number;
  lastUsedAt: number;
}

/** Aggregate alloy statistics with per-component breakdown */
export interface AlloyStats {
  totalCalls: number;
  totalLatencyMs: number;
  totalCostUsd: number;
  perComponent: Record<string, AlloyComponentStats>;
}

// ─── ModelAlloy ──────────────────────────────────────────────────────────────

export class ModelAlloy implements ModelProvider {
  readonly providerId = 'alloy';
  readonly displayName: string;
  readonly supportsToolUse: boolean;

  private components: AlloyComponent[];
  private strategy: AlloyConfig['strategy'];
  private currentIndex = 0;
  private callCount = 0;

  /** Seeded xorshift32 PRNG state */
  private rngState: number;

  /** Per-component stats keyed by "{providerId}/{model}" */
  private componentStats: Map<string, AlloyComponentStats> = new Map();

  /** The component selected by the most recent sendMessage/streamMessage call */
  private lastSelected: AlloyComponent | null = null;

  constructor(config: AlloyConfig) {
    if (config.components.length < 2) {
      throw new Error('Model alloy requires at least 2 model components');
    }

    this.components = config.components;
    this.strategy = config.strategy;

    // Initialize the seeded PRNG
    const seed = config.seed ?? Date.now();
    // Ensure non-zero initial state (xorshift requires it)
    this.rngState = (seed === 0 ? 1 : seed) >>> 0;

    // Display name shows the alloy composition
    this.displayName = `Alloy: ${config.components
      .map(c => c.label ?? `${c.provider.displayName}/${c.model}`)
      .join(' + ')}`;

    // Support tool use if all components support it
    this.supportsToolUse = config.components.every(c => c.provider.supportsToolUse);

    // Initialize per-component stats
    for (const component of config.components) {
      const key = this.componentKey(component);
      this.componentStats.set(key, {
        callCount: 0,
        totalInputTokens: 0,
        totalOutputTokens: 0,
        totalCostUsd: 0,
        totalLatencyMs: 0,
        errorCount: 0,
        lastUsedAt: 0,
      });
    }
  }

  async sendMessage(messages: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
    const component = this.selectComponent();
    const key = this.componentKey(component);
    const stats = this.componentStats.get(key)!;

    const startMs = performance.now();
    try {
      const response = await component.provider.sendMessage(messages, {
        ...options,
        model: component.model,
      });

      const latencyMs = performance.now() - startMs;
      const cost = component.provider.estimateCost(
        response.inputTokens,
        response.outputTokens,
        component.model
      );

      stats.callCount++;
      stats.totalInputTokens += response.inputTokens;
      stats.totalOutputTokens += response.outputTokens;
      stats.totalCostUsd += cost;
      stats.totalLatencyMs += latencyMs;
      stats.lastUsedAt = Date.now();

      return response;
    } catch (error) {
      stats.errorCount++;
      throw error;
    }
  }

  async *streamMessage(messages: ChatMessage[], options: SendMessageOptions): AsyncGenerator<StreamChunk> {
    const component = this.selectComponent();
    const key = this.componentKey(component);
    const stats = this.componentStats.get(key)!;

    const startMs = performance.now();
    let cumulativeInputTokens = 0;
    let cumulativeOutputTokens = 0;

    try {
      for await (const chunk of component.provider.streamMessage(messages, {
        ...options,
        model: component.model,
      })) {
        // Track cumulative tokens from message_stop chunks
        if (chunk.inputTokens !== undefined) {
          cumulativeInputTokens = chunk.inputTokens;
        }
        if (chunk.outputTokens !== undefined) {
          cumulativeOutputTokens = chunk.outputTokens;
        }

        yield chunk;
      }

      const latencyMs = performance.now() - startMs;
      const cost = component.provider.estimateCost(
        cumulativeInputTokens,
        cumulativeOutputTokens,
        component.model
      );

      stats.callCount++;
      stats.totalInputTokens += cumulativeInputTokens;
      stats.totalOutputTokens += cumulativeOutputTokens;
      stats.totalCostUsd += cost;
      stats.totalLatencyMs += latencyMs;
      stats.lastUsedAt = Date.now();
    } catch (error) {
      stats.errorCount++;
      throw error;
    }
  }

  getAvailableModels(): ModelInfo[] {
    // Return combined models from all components
    return this.components.flatMap(c => c.provider.getAvailableModels());
  }

  async validateApiKey(key: string): Promise<boolean> {
    // Validate all component keys
    const results = await Promise.all(
      this.components.map(c => c.provider.validateApiKey(key))
    );
    return results.every(r => r);
  }

  estimateCost(inputTokens: number, outputTokens: number, _model: string): number {
    // Weighted average based on actual usage distribution
    const totalCalls = this.callCount;

    if (totalCalls === 0) {
      // No usage data yet — fall back to weight-based estimate
      const totalWeight = this.components.reduce((sum, c) => sum + (c.weight ?? 1), 0);
      let weightedCost = 0;
      for (const component of this.components) {
        const proportion = (component.weight ?? 1) / totalWeight;
        weightedCost += proportion * component.provider.estimateCost(
          inputTokens, outputTokens, component.model
        );
      }
      return weightedCost;
    }

    // Use actual call distribution
    let weightedCost = 0;
    for (const component of this.components) {
      const key = this.componentKey(component);
      const stats = this.componentStats.get(key)!;
      const proportion = stats.callCount / totalCalls;
      weightedCost += proportion * component.provider.estimateCost(
        inputTokens, outputTokens, component.model
      );
    }
    return weightedCost;
  }

  /** Get the component selected by the most recent call */
  getLastSelectedComponent(): { providerId: string; model: string; label: string } {
    if (this.lastSelected) {
      return {
        providerId: this.lastSelected.provider.providerId,
        model: this.lastSelected.model,
        label: this.lastSelected.label ?? `${this.lastSelected.provider.displayName}/${this.lastSelected.model}`,
      };
    }
    // Fallback if no call has been made yet
    const first = this.components[0];
    return {
      providerId: first.provider.providerId,
      model: first.model,
      label: first.label ?? `${first.provider.displayName}/${first.model}`,
    };
  }

  /** Get current component info for debugging (legacy compat) */
  getCurrentComponent(): { provider: string; model: string } {
    const last = this.getLastSelectedComponent();
    return { provider: last.providerId, model: last.model };
  }

  /** Get full call statistics with per-component breakdown */
  getStats(): AlloyStats {
    let totalLatencyMs = 0;
    let totalCostUsd = 0;
    const perComponent: Record<string, AlloyComponentStats> = {};

    for (const [key, stats] of this.componentStats) {
      perComponent[key] = { ...stats };
      totalLatencyMs += stats.totalLatencyMs;
      totalCostUsd += stats.totalCostUsd;
    }

    return {
      totalCalls: this.callCount,
      totalLatencyMs,
      totalCostUsd,
      perComponent,
    };
  }

  // ─── Private ─────────────────────────────────────────────────────────────

  /** Seeded xorshift32 for reproducible selection */
  private xorshift32(): number {
    let x = this.rngState;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    this.rngState = x >>> 0;
    return (x >>> 0) / 0xFFFFFFFF;
  }

  /** Build a stable key for a component */
  private componentKey(component: AlloyComponent): string {
    return `${component.provider.providerId}/${component.model}`;
  }

  private selectComponent(): AlloyComponent {
    this.callCount++;
    let selected: AlloyComponent;

    switch (this.strategy) {
      case 'round_robin': {
        selected = this.components[this.currentIndex % this.components.length];
        this.currentIndex++;
        break;
      }
      case 'weighted': {
        const totalWeight = this.components.reduce((sum, c) => sum + (c.weight ?? 1), 0);
        let random = this.xorshift32() * totalWeight;
        selected = this.components[0];
        for (const component of this.components) {
          random -= (component.weight ?? 1);
          if (random <= 0) {
            selected = component;
            break;
          }
        }
        break;
      }
      case 'random': {
        selected = this.components[Math.floor(this.xorshift32() * this.components.length)];
        break;
      }
    }

    this.lastSelected = selected;
    return selected;
  }
}

/** Create a recommended alloy from two providers */
export function createAlloy(
  primary: { provider: ModelProvider; model: string; label?: string },
  secondary: { provider: ModelProvider; model: string; label?: string },
  strategy: AlloyConfig['strategy'] = 'round_robin',
  seed?: number
): ModelAlloy {
  return new ModelAlloy({
    components: [
      {
        provider: primary.provider,
        model: primary.model,
        weight: 1,
        label: primary.label,
      },
      {
        provider: secondary.provider,
        model: secondary.model,
        weight: 1,
        label: secondary.label,
      },
    ],
    strategy,
    seed,
  });
}

export default ModelAlloy;

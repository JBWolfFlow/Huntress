/**
 * TracedModelProvider — Instrumented Provider Wrapper
 *
 * Wraps any ModelProvider to automatically record LLM call traces.
 * This is the primary integration point: wrap a provider once, and
 * every sendMessage/streamMessage call is traced with zero changes
 * to calling code.
 *
 * Usage:
 *   const provider = new AnthropicProvider({ apiKey: '...' });
 *   const traced = new TracedModelProvider(provider, traceStore, {
 *     sessionId: 'session_123',
 *     spanId: 'span_456',
 *     callerType: 'agent',
 *     agentId: 'ssrf-hunter',
 *   });
 *   // Use `traced` exactly like a regular ModelProvider
 *   const response = await traced.sendMessage(messages, options);
 *   // Trace is automatically recorded in the store
 */

import type {
  ModelProvider,
  ChatMessage,
  ChatResponse,
  StreamChunk,
  SendMessageOptions,
  ModelInfo,
} from '../providers/types';
import { getMessageText } from '../providers/types';
import type { TraceStore } from './trace_store';
import type {
  LLMCallTrace,
  SessionId,
  SpanId,
  BudgetConfig,
  BudgetStatus,
} from './types';

// ─── Configuration ───────────────────────────────────────────────────────────

export interface TracedProviderConfig {
  /** Current session ID */
  sessionId: SessionId;
  /** Current span ID (e.g., the agent's execution span) */
  spanId: SpanId;
  /** What kind of caller is making LLM calls */
  callerType: LLMCallTrace['callerType'];
  /** Agent ID if callerType is 'agent' */
  agentId?: string;
  /** Whether to capture prompt/response text (truncated) */
  captureContent?: boolean;
  /** Max chars to capture for prompt/response preview */
  maxContentLength?: number;
  /** Budget configuration */
  budget?: BudgetConfig;
  /** Callback when budget warning threshold is reached */
  onBudgetWarning?: (status: BudgetStatus) => void;
  /** Callback when budget is exceeded */
  onBudgetExceeded?: (status: BudgetStatus) => void;
}

// ─── TracedModelProvider ─────────────────────────────────────────────────────

export class TracedModelProvider implements ModelProvider {
  readonly providerId: string;
  readonly displayName: string;
  readonly supportsToolUse?: boolean;

  private inner: ModelProvider;
  private store: TraceStore;
  private config: TracedProviderConfig;
  private retryCount = 0;

  constructor(inner: ModelProvider, store: TraceStore, config: TracedProviderConfig) {
    this.inner = inner;
    this.store = store;
    this.config = {
      captureContent: true,
      maxContentLength: 2000,
      ...config,
    };

    // Forward provider identity
    this.providerId = inner.providerId;
    this.displayName = inner.displayName;
    this.supportsToolUse = inner.supportsToolUse;
  }

  /** Update the span context (e.g., when moving to a new iteration) */
  updateContext(updates: Partial<Pick<TracedProviderConfig, 'spanId' | 'callerType' | 'agentId'>>): void {
    if (updates.spanId !== undefined) this.config.spanId = updates.spanId;
    if (updates.callerType !== undefined) this.config.callerType = updates.callerType;
    if (updates.agentId !== undefined) this.config.agentId = updates.agentId;
  }

  /** Get the current budget status */
  getBudgetStatus(): BudgetStatus {
    if (!this.config.budget) {
      return { spent: 0, limit: 0, remaining: Infinity, percentUsed: 0, isWarning: false, isExceeded: false };
    }

    const session = this.store.getSession(this.config.sessionId);
    let spent = session?.totalCostUsd ?? 0;

    // If tracking per-agent, use agent-specific cost
    if (this.config.agentId && this.config.budget.maxAgentCostUsd > 0) {
      spent = session?.costByAgent[this.config.agentId] ?? 0;
      const limit = this.config.budget.maxAgentCostUsd;
      return {
        spent,
        limit,
        remaining: Math.max(0, limit - spent),
        percentUsed: limit > 0 ? spent / limit : 0,
        isWarning: limit > 0 && spent / limit >= this.config.budget.warningThreshold,
        isExceeded: limit > 0 && spent >= limit,
      };
    }

    const limit = this.config.budget.maxSessionCostUsd;
    return {
      spent,
      limit,
      remaining: Math.max(0, limit - spent),
      percentUsed: limit > 0 ? spent / limit : 0,
      isWarning: limit > 0 && spent / limit >= this.config.budget.warningThreshold,
      isExceeded: limit > 0 && spent >= limit,
    };
  }

  async sendMessage(messages: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
    // Budget check before calling
    this.checkBudget();

    const traceId = generateTraceId();
    const startedAt = Date.now();

    const trace: LLMCallTrace = this.createBaseTrace(traceId, startedAt, messages, options);

    try {
      const response = await this.inner.sendMessage(messages, options);

      // Fill in response details
      trace.completedAt = Date.now();
      trace.durationMs = trace.completedAt - startedAt;
      trace.inputTokens = response.inputTokens;
      trace.outputTokens = response.outputTokens;
      trace.totalTokens = response.inputTokens + response.outputTokens;
      trace.stopReason = response.stopReason;
      trace.toolCallCount = response.toolCalls?.length ?? 0;
      trace.toolCallNames = response.toolCalls?.map(tc => tc.name) ?? [];
      trace.success = true;
      trace.costUsd = this.inner.estimateCost(response.inputTokens, response.outputTokens, options.model);

      if (this.config.captureContent) {
        trace.responsePreview = truncate(response.content, this.config.maxContentLength!);
      }

      this.store.addLlmTrace(trace);
      this.retryCount = 0;

      // Post-call budget check
      this.checkBudgetWarning();

      return response;
    } catch (error) {
      trace.completedAt = Date.now();
      trace.durationMs = trace.completedAt - startedAt;
      trace.success = false;
      trace.error = error instanceof Error ? error.message : String(error);
      trace.retryCount = this.retryCount;
      this.retryCount++;

      this.store.addLlmTrace(trace);
      throw error;
    }
  }

  async *streamMessage(messages: ChatMessage[], options: SendMessageOptions): AsyncGenerator<StreamChunk> {
    this.checkBudget();

    const traceId = generateTraceId();
    const startedAt = Date.now();
    const trace: LLMCallTrace = this.createBaseTrace(traceId, startedAt, messages, options);
    trace.streaming = true;

    let contentParts: string[] = [];
    let inputTokens = 0;
    let outputTokens = 0;
    let toolCallNames: string[] = [];

    try {
      const stream = this.inner.streamMessage(messages, options);

      for await (const chunk of stream) {
        // Accumulate data from stream
        if (chunk.type === 'content_delta' && chunk.content) {
          contentParts.push(chunk.content);
        }
        if (chunk.type === 'tool_use_delta' && chunk.toolUse?.name) {
          toolCallNames.push(chunk.toolUse.name);
        }
        if (chunk.type === 'message_stop') {
          inputTokens = chunk.inputTokens ?? 0;
          outputTokens = chunk.outputTokens ?? 0;
        }

        yield chunk;
      }

      // Fill in trace
      trace.completedAt = Date.now();
      trace.durationMs = trace.completedAt - startedAt;
      trace.inputTokens = inputTokens;
      trace.outputTokens = outputTokens;
      trace.totalTokens = inputTokens + outputTokens;
      trace.toolCallNames = Array.from(new Set(toolCallNames));
      trace.toolCallCount = trace.toolCallNames.length;
      trace.success = true;
      trace.costUsd = this.inner.estimateCost(inputTokens, outputTokens, options.model);

      if (this.config.captureContent) {
        trace.responsePreview = truncate(contentParts.join(''), this.config.maxContentLength!);
      }

      this.store.addLlmTrace(trace);
      this.retryCount = 0;
      this.checkBudgetWarning();
    } catch (error) {
      trace.completedAt = Date.now();
      trace.durationMs = trace.completedAt - startedAt;
      trace.success = false;
      trace.error = error instanceof Error ? error.message : String(error);
      trace.retryCount = this.retryCount;
      this.retryCount++;

      this.store.addLlmTrace(trace);
      throw error;
    }
  }

  getAvailableModels(): ModelInfo[] {
    return this.inner.getAvailableModels();
  }

  async validateApiKey(key: string): Promise<boolean> {
    return this.inner.validateApiKey(key);
  }

  estimateCost(inputTokens: number, outputTokens: number, model: string): number {
    return this.inner.estimateCost(inputTokens, outputTokens, model);
  }

  // ─── Private Helpers ──────────────────────────────────────────────────────

  private createBaseTrace(
    traceId: string,
    startedAt: number,
    messages: ChatMessage[],
    options: SendMessageOptions
  ): LLMCallTrace {
    const trace: LLMCallTrace = {
      id: traceId,
      spanId: this.config.spanId,
      sessionId: this.config.sessionId,
      startedAt,
      completedAt: 0,
      durationMs: 0,
      providerId: this.providerId,
      model: options.model,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      costUsd: 0,
      streaming: false,
      temperature: options.temperature ?? null,
      maxTokens: options.maxTokens ?? null,
      toolCount: options.tools?.length ?? 0,
      toolCallCount: 0,
      toolCallNames: [],
      stopReason: 'unknown',
      callerType: this.config.callerType,
      agentId: this.config.agentId ?? null,
      contextMessageCount: messages.length,
      success: false,
      error: null,
      retryCount: this.retryCount,
      systemPrompt: null,
      lastUserMessage: null,
      responsePreview: null,
    };

    if (this.config.captureContent) {
      const maxLen = this.config.maxContentLength!;

      if (options.systemPrompt) {
        trace.systemPrompt = truncate(options.systemPrompt, maxLen);
      }

      // Capture last user message
      const lastUserMsg = [...messages].reverse().find(m => m.role === 'user');
      if (lastUserMsg) {
        trace.lastUserMessage = truncate(getMessageText(lastUserMsg.content), maxLen);
      }
    }

    return trace;
  }

  private checkBudget(): void {
    if (!this.config.budget?.hardStop) return;

    const status = this.getBudgetStatus();
    if (status.isExceeded) {
      if (this.config.onBudgetExceeded) {
        this.config.onBudgetExceeded(status);
      }
      throw new BudgetExceededError(
        `Budget exceeded: $${status.spent.toFixed(4)} spent of $${status.limit.toFixed(2)} limit`,
        status
      );
    }
  }

  private checkBudgetWarning(): void {
    if (!this.config.budget || !this.config.onBudgetWarning) return;

    const status = this.getBudgetStatus();
    if (status.isWarning && !status.isExceeded) {
      this.config.onBudgetWarning(status);
    }
  }
}

// ─── Budget Error ────────────────────────────────────────────────────────────

export class BudgetExceededError extends Error {
  readonly budgetStatus: BudgetStatus;

  constructor(message: string, status: BudgetStatus) {
    super(message);
    this.name = 'BudgetExceededError';
    this.budgetStatus = status;
  }
}

// ─── Utility Functions ───────────────────────────────────────────────────────

function generateTraceId(): string {
  return `llm_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
}

function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength) + `... [truncated, ${text.length} total chars]`;
}

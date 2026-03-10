/**
 * CostTracker — Real-Time Cost Calculation Engine
 *
 * Tracks costs across multiple providers and models with real-time
 * aggregation per agent, per session, and per provider. Integrates
 * with the pricing data from each ModelProvider.
 *
 * Features:
 * - Real-time cost accumulation from trace events
 * - Per-agent budget enforcement
 * - Session-level budget limits
 * - Cost projection based on current burn rate
 * - Price overrides for custom/fine-tuned models
 */

import type { TraceStore, TraceStoreEvent } from './trace_store';
import type {
  SessionId,
  BudgetConfig,
  BudgetStatus,
  SessionMetrics,
  AgentMetrics,
} from './types';

// ─── Pricing Database ────────────────────────────────────────────────────────

/** Cost per 1M tokens for known models */
const MODEL_PRICING: Record<string, { inputPer1M: number; outputPer1M: number }> = {
  // Anthropic
  'claude-opus-4-6':                { inputPer1M: 15,   outputPer1M: 75 },
  'claude-sonnet-4-5-20250929':     { inputPer1M: 3,    outputPer1M: 15 },
  'claude-haiku-4-5-20251001':      { inputPer1M: 0.80, outputPer1M: 4 },
  // OpenAI
  'gpt-4o':                         { inputPer1M: 2.50, outputPer1M: 10 },
  'gpt-4o-mini':                    { inputPer1M: 0.15, outputPer1M: 0.60 },
  'o3':                             { inputPer1M: 10,   outputPer1M: 40 },
  'o3-mini':                        { inputPer1M: 1.10, outputPer1M: 4.40 },
  // Google
  'gemini-2.5-pro':                 { inputPer1M: 1.25, outputPer1M: 10 },
  'gemini-2.5-flash':               { inputPer1M: 0.15, outputPer1M: 0.60 },
  // Local models (free)
  'llama-3.1-70b':                  { inputPer1M: 0,    outputPer1M: 0 },
  'llama-3.1-8b':                   { inputPer1M: 0,    outputPer1M: 0 },
  'mistral-nemo':                   { inputPer1M: 0,    outputPer1M: 0 },
};

export class CostTracker {
  private store: TraceStore;
  private budgets: Map<string, BudgetConfig> = new Map();
  private customPricing: Map<string, { inputPer1M: number; outputPer1M: number }> = new Map();
  private unsubscribe: (() => void) | null = null;

  // Real-time accumulators (faster than querying the store)
  private sessionCosts: Map<SessionId, number> = new Map();
  private agentCosts: Map<string, number> = new Map(); // "session:agent" -> cost
  private providerCosts: Map<string, number> = new Map(); // "session:provider" -> cost

  // Callback for budget events
  private budgetListeners: Map<string, (event: BudgetEvent) => void> = new Map();

  constructor(store: TraceStore) {
    this.store = store;

    // Subscribe to trace events for real-time cost tracking
    this.unsubscribe = store.subscribe((event) => {
      if (event.type === 'llm_trace_added') {
        this.handleNewTrace(event.trace);
      }
    });
  }

  // ─── Budget Management ─────────────────────────────────────────────────

  /** Set budget for a session */
  setSessionBudget(sessionId: SessionId, config: BudgetConfig): void {
    this.budgets.set(`session:${sessionId}`, config);
  }

  /** Set budget for a specific agent within a session */
  setAgentBudget(sessionId: SessionId, agentId: string, config: BudgetConfig): void {
    this.budgets.set(`agent:${sessionId}:${agentId}`, config);
  }

  /** Get budget status for a session */
  getSessionBudgetStatus(sessionId: SessionId): BudgetStatus {
    const budget = this.budgets.get(`session:${sessionId}`);
    const spent = this.sessionCosts.get(sessionId) ?? 0;
    return this.computeBudgetStatus(spent, budget);
  }

  /** Get budget status for an agent within a session */
  getAgentBudgetStatus(sessionId: SessionId, agentId: string): BudgetStatus {
    const budget = this.budgets.get(`agent:${sessionId}:${agentId}`)
      ?? this.budgets.get(`session:${sessionId}`); // Fall back to session budget's agent limit
    const key = `${sessionId}:${agentId}`;
    const spent = this.agentCosts.get(key) ?? 0;

    if (budget?.maxAgentCostUsd) {
      return this.computeBudgetStatus(spent, {
        ...budget,
        maxSessionCostUsd: budget.maxAgentCostUsd,
      });
    }
    return this.computeBudgetStatus(spent, undefined);
  }

  /** Subscribe to budget events for a session */
  onBudgetEvent(sessionId: SessionId, listener: (event: BudgetEvent) => void): () => void {
    this.budgetListeners.set(sessionId, listener);
    return () => {
      this.budgetListeners.delete(sessionId);
    };
  }

  // ─── Cost Calculation ──────────────────────────────────────────────────

  /** Calculate cost for a given number of tokens on a specific model */
  calculateCost(model: string, inputTokens: number, outputTokens: number): number {
    const pricing = this.customPricing.get(model) ?? MODEL_PRICING[model];
    if (!pricing) return 0;

    return (inputTokens / 1_000_000) * pricing.inputPer1M +
           (outputTokens / 1_000_000) * pricing.outputPer1M;
  }

  /** Set custom pricing for a model (e.g., fine-tuned models, OpenRouter pricing) */
  setCustomPricing(model: string, inputPer1M: number, outputPer1M: number): void {
    this.customPricing.set(model, { inputPer1M, outputPer1M });
  }

  /** Get pricing info for a model */
  getModelPricing(model: string): { inputPer1M: number; outputPer1M: number } | undefined {
    return this.customPricing.get(model) ?? MODEL_PRICING[model];
  }

  // ─── Real-Time Metrics ─────────────────────────────────────────────────

  /** Get comprehensive session metrics for the dashboard */
  getSessionMetrics(sessionId: SessionId): SessionMetrics {
    const session = this.store.getSession(sessionId);
    if (!session) {
      return this.emptyMetrics(sessionId);
    }

    const elapsedMs = (session.completedAt || Date.now()) - session.startedAt;
    const elapsedSec = Math.max(1, elapsedMs / 1000);
    const elapsedMin = Math.max(1, elapsedMs / 60000);

    // Get latency stats
    const latencyDist = this.store.getLatencyDistribution({ sessionId });

    // Get LLM traces for error rate calculation
    const allTraces = this.store.queryLlmTraces({ sessionId, limit: 100000 });
    const errorCount = allTraces.filter(t => !t.success).length;

    // Build per-agent metrics
    const agentMetrics = this.buildAgentMetrics(sessionId);

    // Budget status
    const budgetStatus = this.getSessionBudgetStatus(sessionId);

    return {
      sessionId,
      elapsedMs,
      totalInputTokens: session.totalInputTokens,
      totalOutputTokens: session.totalOutputTokens,
      tokensPerSecond: (session.totalInputTokens + session.totalOutputTokens) / elapsedSec,
      totalCostUsd: session.totalCostUsd,
      costPerMinute: session.totalCostUsd / elapsedMin,
      totalLlmCalls: session.totalLlmCalls,
      avgLatencyMs: latencyDist.p50,
      p95LatencyMs: latencyDist.p95,
      errorRate: allTraces.length > 0 ? errorCount / allTraces.length : 0,
      activeAgents: agentMetrics.filter(a => a.status === 'running').length,
      completedAgents: agentMetrics.filter(a => a.status === 'completed').length,
      totalFindings: session.totalFindings,
      agentMetrics,
      budgetStatus,
    };
  }

  /** Get cost burn rate (USD per minute) for the last N minutes */
  getBurnRate(sessionId: SessionId, windowMinutes: number = 5): number {
    const now = Date.now();
    const windowStart = now - windowMinutes * 60000;

    const recentTraces = this.store.queryLlmTraces({
      sessionId,
      startAfter: windowStart,
      limit: 100000,
    });

    const recentCost = recentTraces.reduce((sum, t) => sum + t.costUsd, 0);
    return recentCost / windowMinutes;
  }

  /** Project total session cost based on burn rate and estimated remaining time */
  projectCost(sessionId: SessionId, estimatedRemainingMinutes: number): number {
    const session = this.store.getSession(sessionId);
    if (!session) return 0;

    const burnRate = this.getBurnRate(sessionId);
    return session.totalCostUsd + burnRate * estimatedRemainingMinutes;
  }

  // ─── Cost Breakdown ────────────────────────────────────────────────────

  /** Get cost breakdown by provider for a session */
  getCostByProvider(sessionId: SessionId): Record<string, number> {
    const session = this.store.getSession(sessionId);
    return session?.costByProvider ?? {};
  }

  /** Get cost breakdown by agent for a session */
  getCostByAgent(sessionId: SessionId): Record<string, number> {
    const session = this.store.getSession(sessionId);
    return session?.costByAgent ?? {};
  }

  /** Get cost breakdown by model for a session */
  getCostByModel(sessionId: SessionId): Record<string, number> {
    const session = this.store.getSession(sessionId);
    if (!session) return {};

    const result: Record<string, number> = {};
    for (const [model, tokens] of Object.entries(session.tokensByModel)) {
      result[model] = this.calculateCost(model, tokens.input, tokens.output);
    }
    return result;
  }

  /** Clean up */
  destroy(): void {
    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = null;
    }
    this.budgetListeners.clear();
  }

  // ─── Private Helpers ──────────────────────────────────────────────────

  private handleNewTrace(trace: { sessionId: SessionId; agentId: string | null; providerId: string; costUsd: number }): void {
    // Update session cost
    const prevSessionCost = this.sessionCosts.get(trace.sessionId) ?? 0;
    this.sessionCosts.set(trace.sessionId, prevSessionCost + trace.costUsd);

    // Update agent cost
    if (trace.agentId) {
      const agentKey = `${trace.sessionId}:${trace.agentId}`;
      const prevAgentCost = this.agentCosts.get(agentKey) ?? 0;
      this.agentCosts.set(agentKey, prevAgentCost + trace.costUsd);
    }

    // Update provider cost
    const providerKey = `${trace.sessionId}:${trace.providerId}`;
    const prevProviderCost = this.providerCosts.get(providerKey) ?? 0;
    this.providerCosts.set(providerKey, prevProviderCost + trace.costUsd);

    // Check budgets
    this.checkBudgets(trace.sessionId, trace.agentId);
  }

  private checkBudgets(sessionId: SessionId, agentId: string | null): void {
    const listener = this.budgetListeners.get(sessionId);
    if (!listener) return;

    // Check session budget
    const sessionStatus = this.getSessionBudgetStatus(sessionId);
    if (sessionStatus.isExceeded) {
      listener({ type: 'session_exceeded', sessionId, status: sessionStatus });
    } else if (sessionStatus.isWarning) {
      listener({ type: 'session_warning', sessionId, status: sessionStatus });
    }

    // Check agent budget
    if (agentId) {
      const agentStatus = this.getAgentBudgetStatus(sessionId, agentId);
      if (agentStatus.isExceeded) {
        listener({ type: 'agent_exceeded', sessionId, agentId, status: agentStatus });
      } else if (agentStatus.isWarning) {
        listener({ type: 'agent_warning', sessionId, agentId, status: agentStatus });
      }
    }
  }

  private computeBudgetStatus(spent: number, budget?: BudgetConfig): BudgetStatus {
    if (!budget || budget.maxSessionCostUsd <= 0) {
      return {
        spent,
        limit: 0,
        remaining: Infinity,
        percentUsed: 0,
        isWarning: false,
        isExceeded: false,
      };
    }

    const limit = budget.maxSessionCostUsd;
    const remaining = Math.max(0, limit - spent);
    const percentUsed = spent / limit;

    return {
      spent,
      limit,
      remaining,
      percentUsed,
      isWarning: percentUsed >= budget.warningThreshold,
      isExceeded: spent >= limit,
    };
  }

  private buildAgentMetrics(sessionId: SessionId): AgentMetrics[] {
    const agentSpans = this.store.getSessionSpans(sessionId)
      .filter(s => s.kind === 'agent_execution' && s.agentId);

    const agentMap = new Map<string, AgentMetrics>();

    for (const span of agentSpans) {
      const agentId = span.agentId!;
      const existing = agentMap.get(agentId);

      if (existing) {
        // Accumulate across multiple runs of the same agent
        existing.llmCalls += span.llmCallCount;
        existing.toolExecutions += span.toolExecutionCount;
        existing.inputTokens += span.totalInputTokens;
        existing.outputTokens += span.totalOutputTokens;
        existing.costUsd += span.totalCostUsd;
        existing.iterations++;
        existing.elapsedMs += span.durationMs;
        // Update status to most recent
        existing.status = span.status;
      } else {
        // Get traces for latency calculation
        const traces = this.store.queryLlmTraces({ agentId, sessionId, limit: 10000 });
        const avgLatency = traces.length > 0
          ? traces.reduce((sum, t) => sum + t.durationMs, 0) / traces.length
          : 0;

        agentMap.set(agentId, {
          agentId,
          agentName: agentId, // Could be enriched from agent catalog
          status: span.status,
          llmCalls: span.llmCallCount,
          toolExecutions: span.toolExecutionCount,
          inputTokens: span.totalInputTokens,
          outputTokens: span.totalOutputTokens,
          costUsd: span.totalCostUsd,
          findings: (span.metadata?.findingCount as number) ?? 0,
          avgLatencyMs: avgLatency,
          iterations: 1,
          elapsedMs: span.durationMs,
        });
      }
    }

    return Array.from(agentMap.values());
  }

  private emptyMetrics(sessionId: SessionId): SessionMetrics {
    return {
      sessionId,
      elapsedMs: 0,
      totalInputTokens: 0,
      totalOutputTokens: 0,
      tokensPerSecond: 0,
      totalCostUsd: 0,
      costPerMinute: 0,
      totalLlmCalls: 0,
      avgLatencyMs: 0,
      p95LatencyMs: 0,
      errorRate: 0,
      activeAgents: 0,
      completedAgents: 0,
      totalFindings: 0,
      agentMetrics: [],
      budgetStatus: {
        spent: 0,
        limit: 0,
        remaining: Infinity,
        percentUsed: 0,
        isWarning: false,
        isExceeded: false,
      },
    };
  }
}

// ─── Budget Event Types ──────────────────────────────────────────────────────

export type BudgetEvent =
  | { type: 'session_warning'; sessionId: SessionId; status: BudgetStatus }
  | { type: 'session_exceeded'; sessionId: SessionId; status: BudgetStatus }
  | { type: 'agent_warning'; sessionId: SessionId; agentId: string; status: BudgetStatus }
  | { type: 'agent_exceeded'; sessionId: SessionId; agentId: string; status: BudgetStatus };

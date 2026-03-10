/**
 * React Hooks for LLM Tracing Dashboard
 *
 * Provides real-time reactive access to tracing data for the UI.
 * All hooks subscribe to the TraceStore and re-render when relevant data changes.
 *
 * Usage:
 *   function Dashboard() {
 *     const metrics = useSessionMetrics(sessionId);
 *     const costSeries = useCostTimeSeries(sessionId);
 *     return <CostChart data={costSeries} />;
 *   }
 */

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import type { TraceStore, TraceStoreEvent } from './trace_store';
import type { CostTracker } from './cost_tracker';
import type {
  SessionMetrics,
  AgentMetrics,
  SessionId,
  LLMCallTrace,
  AgentPerformanceSummary,
  ModelPerformanceSummary,
  BudgetStatus,
  TraceFilter,
} from './types';

// ─── Context Setup ───────────────────────────────────────────────────────────

/**
 * Tracing context shared across hooks.
 * Initialize once at app startup and pass to TracingProvider.
 */
export interface TracingContext {
  store: TraceStore;
  costTracker: CostTracker;
}

// In a real React app, this would use React.createContext.
// For now, we use a module-level singleton that gets set at startup.
let globalTracingContext: TracingContext | null = null;

/** Initialize the global tracing context. Call once at app startup. */
export function initializeTracing(store: TraceStore, costTracker: CostTracker): TracingContext {
  globalTracingContext = { store, costTracker };
  return globalTracingContext;
}

/** Get the tracing context. Throws if not initialized. */
export function getTracingContext(): TracingContext {
  if (!globalTracingContext) {
    throw new Error(
      'Tracing not initialized. Call initializeTracing() at app startup.'
    );
  }
  return globalTracingContext;
}

// ─── Real-Time Session Metrics Hook ──────────────────────────────────────────

/**
 * Hook that provides real-time session metrics, updating on every LLM call.
 *
 * @param sessionId - The session to monitor
 * @param pollIntervalMs - How often to recalculate metrics (default: 2000ms)
 * @returns Current session metrics, or null if session not found
 */
export function useSessionMetrics(
  sessionId: SessionId | null,
  pollIntervalMs: number = 2000
): SessionMetrics | null {
  const [metrics, setMetrics] = useState<SessionMetrics | null>(null);
  const lastUpdate = useRef(0);

  useEffect(() => {
    if (!sessionId || !globalTracingContext) return;

    const { store, costTracker } = globalTracingContext;

    // Initial load
    setMetrics(costTracker.getSessionMetrics(sessionId));

    // Update on trace events (debounced)
    const unsubscribe = store.subscribe(() => {
      const now = Date.now();
      if (now - lastUpdate.current < pollIntervalMs) return;
      lastUpdate.current = now;
      setMetrics(costTracker.getSessionMetrics(sessionId));
    });

    // Also poll on interval for elapsed time updates
    const timer = setInterval(() => {
      setMetrics(costTracker.getSessionMetrics(sessionId));
    }, pollIntervalMs);

    return () => {
      unsubscribe();
      clearInterval(timer);
    };
  }, [sessionId, pollIntervalMs]);

  return metrics;
}

// ─── Cost Time Series Hook ───────────────────────────────────────────────────

/**
 * Hook for cost-over-time chart data.
 *
 * @param sessionId - The session to chart
 * @param bucketMs - Time bucket size in ms (default: 60000 = 1 minute)
 * @returns Array of { timestamp, cost, tokens } data points
 */
export function useCostTimeSeries(
  sessionId: SessionId | null,
  bucketMs: number = 60000
): Array<{ timestamp: number; cost: number; tokens: number }> {
  const [series, setSeries] = useState<Array<{ timestamp: number; cost: number; tokens: number }>>([]);

  useEffect(() => {
    if (!sessionId || !globalTracingContext) return;

    const { store } = globalTracingContext;

    const update = () => {
      setSeries(store.getCostTimeSeries(sessionId, bucketMs));
    };

    update();

    const unsubscribe = store.subscribe((event) => {
      if (event.type === 'llm_trace_added' && event.trace.sessionId === sessionId) {
        update();
      }
    });

    return unsubscribe;
  }, [sessionId, bucketMs]);

  return series;
}

// ─── Agent Metrics Hook ──────────────────────────────────────────────────────

/**
 * Hook for per-agent metrics within a session.
 *
 * @param sessionId - The session to get agent metrics for
 * @returns Array of agent metrics
 */
export function useAgentMetrics(sessionId: SessionId | null): AgentMetrics[] {
  const [agents, setAgents] = useState<AgentMetrics[]>([]);

  useEffect(() => {
    if (!sessionId || !globalTracingContext) return;

    const { costTracker } = globalTracingContext;

    const update = () => {
      const metrics = costTracker.getSessionMetrics(sessionId);
      setAgents(metrics.agentMetrics);
    };

    update();

    const unsubscribe = globalTracingContext.store.subscribe((event) => {
      if (
        (event.type === 'llm_trace_added' && event.trace.sessionId === sessionId) ||
        (event.type === 'span_started' || event.type === 'span_ended')
      ) {
        update();
      }
    });

    return unsubscribe;
  }, [sessionId]);

  return agents;
}

// ─── Budget Status Hook ─────────────────────────────────────────────────────

/**
 * Hook for real-time budget status.
 *
 * @param sessionId - The session to monitor
 * @returns Current budget status
 */
export function useBudgetStatus(sessionId: SessionId | null): BudgetStatus {
  const defaultStatus: BudgetStatus = {
    spent: 0, limit: 0, remaining: Infinity,
    percentUsed: 0, isWarning: false, isExceeded: false,
  };

  const [status, setStatus] = useState<BudgetStatus>(defaultStatus);

  useEffect(() => {
    if (!sessionId || !globalTracingContext) return;

    const { costTracker, store } = globalTracingContext;

    setStatus(costTracker.getSessionBudgetStatus(sessionId));

    const unsubscribe = store.subscribe((event) => {
      if (event.type === 'llm_trace_added' && event.trace.sessionId === sessionId) {
        setStatus(costTracker.getSessionBudgetStatus(sessionId));
      }
    });

    return unsubscribe;
  }, [sessionId]);

  return status;
}

// ─── LLM Trace List Hook ────────────────────────────────────────────────────

/**
 * Hook for paginated LLM trace list (for trace explorer/debugger).
 *
 * @param filter - Query filter
 * @returns Traces matching the filter
 */
export function useLlmTraces(filter: TraceFilter): LLMCallTrace[] {
  const [traces, setTraces] = useState<LLMCallTrace[]>([]);
  const filterRef = useRef(filter);
  filterRef.current = filter;

  useEffect(() => {
    if (!globalTracingContext) return;

    const { store } = globalTracingContext;

    const update = () => {
      setTraces(store.queryLlmTraces(filterRef.current));
    };

    update();

    const unsubscribe = store.subscribe((event) => {
      if (event.type === 'llm_trace_added') {
        update();
      }
    });

    return unsubscribe;
  }, [
    filter.sessionId,
    filter.agentId,
    filter.providerId,
    filter.model,
    filter.callerType,
    filter.success,
    filter.limit,
    filter.offset,
    filter.orderBy,
    filter.orderDir,
  ]);

  return traces;
}

// ─── Historical Performance Hooks ────────────────────────────────────────────

/**
 * Hook for agent performance summaries across all sessions.
 */
export function useAgentPerformance(): AgentPerformanceSummary[] {
  const [summaries, setSummaries] = useState<AgentPerformanceSummary[]>([]);

  useEffect(() => {
    if (!globalTracingContext) return;

    const { store } = globalTracingContext;

    setSummaries(store.getAgentPerformance());

    const unsubscribe = store.subscribe((event) => {
      if (event.type === 'session_ended') {
        setSummaries(store.getAgentPerformance());
      }
    });

    return unsubscribe;
  }, []);

  return summaries;
}

/**
 * Hook for model performance summaries across all sessions.
 */
export function useModelPerformance(): ModelPerformanceSummary[] {
  const [summaries, setSummaries] = useState<ModelPerformanceSummary[]>([]);

  useEffect(() => {
    if (!globalTracingContext) return;

    const { store } = globalTracingContext;

    setSummaries(store.getModelPerformance());

    const unsubscribe = store.subscribe((event) => {
      if (event.type === 'session_ended') {
        setSummaries(store.getModelPerformance());
      }
    });

    return unsubscribe;
  }, []);

  return summaries;
}

// ─── Latency Distribution Hook ───────────────────────────────────────────────

/**
 * Hook for latency percentile distribution.
 */
export function useLatencyDistribution(
  sessionId?: SessionId
): { p50: number; p75: number; p90: number; p95: number; p99: number; max: number } {
  const defaultDist = { p50: 0, p75: 0, p90: 0, p95: 0, p99: 0, max: 0 };
  const [dist, setDist] = useState(defaultDist);

  useEffect(() => {
    if (!globalTracingContext) return;

    const { store } = globalTracingContext;

    setDist(store.getLatencyDistribution(sessionId ? { sessionId } : undefined));

    const unsubscribe = store.subscribe((event) => {
      if (event.type === 'llm_trace_added') {
        setDist(store.getLatencyDistribution(sessionId ? { sessionId } : undefined));
      }
    });

    return unsubscribe;
  }, [sessionId]);

  return dist;
}

// ─── Store Stats Hook ────────────────────────────────────────────────────────

/**
 * Hook for trace store internal statistics (for debugging).
 */
export function useTraceStoreStats(): {
  llmTraceCount: number;
  toolTraceCount: number;
  spanCount: number;
  sessionCount: number;
} {
  const defaultStats = { llmTraceCount: 0, toolTraceCount: 0, spanCount: 0, sessionCount: 0 };
  const [stats, setStats] = useState(defaultStats);

  useEffect(() => {
    if (!globalTracingContext) return;

    const { store } = globalTracingContext;

    const update = () => {
      const s = store.getStats();
      setStats({
        llmTraceCount: s.llmTraceCount,
        toolTraceCount: s.toolTraceCount,
        spanCount: s.spanCount,
        sessionCount: s.sessionCount,
      });
    };

    update();

    const unsubscribe = store.subscribe(update);
    return unsubscribe;
  }, []);

  return stats;
}

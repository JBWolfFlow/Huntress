/**
 * LLM Observability & Tracing Module — Barrel Export
 *
 * Lightweight, zero-dependency tracing for a Tauri desktop app.
 * No Docker, no external servers, no cloud services required.
 *
 * Quick start:
 *
 *   import { TraceStore, CostTracker, TracedModelProvider, initializeTracing } from './core/tracing';
 *
 *   // 1. Initialize at app startup
 *   const store = new TraceStore();
 *   await store.loadFromDisk();
 *   const costTracker = new CostTracker(store);
 *   initializeTracing(store, costTracker);
 *
 *   // 2. Wrap providers with tracing
 *   const provider = new AnthropicProvider({ apiKey: '...' });
 *   const traced = new TracedModelProvider(provider, store, {
 *     sessionId: 'session_abc',
 *     spanId: 'span_123',
 *     callerType: 'orchestrator',
 *   });
 *
 *   // 3. Use in React components
 *   function Dashboard({ sessionId }) {
 *     const metrics = useSessionMetrics(sessionId);
 *     const budget = useBudgetStatus(sessionId);
 *     const costSeries = useCostTimeSeries(sessionId);
 *     // ... render
 *   }
 */

// Core types
export type {
  TraceId,
  SpanId,
  SessionId,
  LLMCallTrace,
  ToolExecutionTrace,
  Span,
  SpanKind,
  TracingSession,
  BudgetConfig,
  BudgetStatus,
  SessionMetrics,
  AgentMetrics,
  AgentPerformanceSummary,
  ModelPerformanceSummary,
  TraceFilter,
  TimeRange,
} from './types';

// Trace store
export { TraceStore } from './trace_store';
export type { TraceStoreConfig, TraceStoreExport, TraceStoreStats, TraceStoreEvent, PersistAdapter } from './trace_store';

// Traced provider wrapper
export { TracedModelProvider, BudgetExceededError } from './traced_provider';
export type { TracedProviderConfig } from './traced_provider';

// Cost tracker
export { CostTracker } from './cost_tracker';
export type { BudgetEvent } from './cost_tracker';

// React hooks
export {
  initializeTracing,
  getTracingContext,
  useSessionMetrics,
  useCostTimeSeries,
  useAgentMetrics,
  useBudgetStatus,
  useLlmTraces,
  useAgentPerformance,
  useModelPerformance,
  useLatencyDistribution,
  useTraceStoreStats,
} from './hooks';
export type { TracingContext } from './hooks';

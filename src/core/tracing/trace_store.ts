/**
 * TraceStore — Local Trace Storage Engine
 *
 * In-memory trace store with periodic persistence to JSON files via Tauri FS.
 * Designed for a desktop app where:
 * - No external database needed (no Docker, no PostgreSQL)
 * - All data stays local on the user's machine
 * - Queries are fast (in-memory indexes)
 * - Persistence survives app restarts (JSON file export)
 * - Memory bounded (configurable max traces, auto-eviction of old data)
 *
 * For a future version, this can be swapped to use Tauri's SQL plugin
 * (tauri-plugin-sql) with SQLite for larger datasets.
 */

import type {
  LLMCallTrace,
  ToolExecutionTrace,
  Span,
  TracingSession,
  TraceFilter,
  TraceId,
  SpanId,
  SessionId,
  TimeRange,
  AgentPerformanceSummary,
  ModelPerformanceSummary,
} from './types';

// ─── Configuration ───────────────────────────────────────────────────────────

export interface TraceStoreConfig {
  /** Maximum number of LLM call traces to keep in memory */
  maxLlmTraces: number;
  /** Maximum number of tool execution traces */
  maxToolTraces: number;
  /** Maximum number of spans */
  maxSpans: number;
  /** Maximum completed sessions to keep */
  maxSessions: number;
  /** Auto-persist interval in ms (0 = disabled) */
  persistIntervalMs: number;
  /** Directory for persisted trace files (Tauri app data dir) */
  persistDir: string;
}

const DEFAULT_CONFIG: TraceStoreConfig = {
  maxLlmTraces: 10000,
  maxToolTraces: 5000,
  maxSpans: 2000,
  maxSessions: 50,
  persistIntervalMs: 30000, // 30 seconds
  persistDir: '', // Set at runtime from Tauri app data dir
};

// ─── TraceStore ──────────────────────────────────────────────────────────────

/**
 * Pluggable persistence adapter for storing traces.
 * Implement this to use Tauri filesystem, IndexedDB, or any other backend.
 */
export interface PersistAdapter {
  write(json: string): Promise<void>;
  read(): Promise<string | null>;
}

export class TraceStore {
  private config: TraceStoreConfig;
  private persistAdapter: PersistAdapter | null = null;

  // Primary storage
  private llmTraces: Map<TraceId, LLMCallTrace> = new Map();
  private toolTraces: Map<TraceId, ToolExecutionTrace> = new Map();
  private spans: Map<SpanId, Span> = new Map();
  private sessions: Map<SessionId, TracingSession> = new Map();

  // Indexes for fast queries
  private tracesBySession: Map<SessionId, Set<TraceId>> = new Map();
  private tracesBySpan: Map<SpanId, Set<TraceId>> = new Map();
  private tracesByAgent: Map<string, Set<TraceId>> = new Map();
  private spansBySession: Map<SessionId, Set<SpanId>> = new Map();
  private spansByParent: Map<SpanId, Set<SpanId>> = new Map();
  private toolTracesBySession: Map<SessionId, Set<TraceId>> = new Map();

  // Insertion order for eviction
  private llmTraceOrder: TraceId[] = [];
  private toolTraceOrder: TraceId[] = [];

  // Listeners for real-time updates
  private listeners: Set<(event: TraceStoreEvent) => void> = new Set();

  // Persistence timer
  private persistTimer: ReturnType<typeof setInterval> | null = null;
  private dirty = false;

  constructor(config: Partial<TraceStoreConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };

    if (this.config.persistIntervalMs > 0) {
      this.persistTimer = setInterval(() => {
        if (this.dirty) {
          this.persistToDisk().catch(err => {
            console.error('[TraceStore] Persistence error:', err);
          });
        }
      }, this.config.persistIntervalMs);
    }
  }

  // ─── Write Operations ────────────────────────────────────────────────────

  /** Record an LLM call trace */
  addLlmTrace(trace: LLMCallTrace): void {
    this.llmTraces.set(trace.id, trace);
    this.llmTraceOrder.push(trace.id);

    // Update indexes
    this.addToIndex(this.tracesBySession, trace.sessionId, trace.id);
    this.addToIndex(this.tracesBySpan, trace.spanId, trace.id);
    if (trace.agentId) {
      this.addToIndex(this.tracesByAgent, trace.agentId, trace.id);
    }

    // Update parent span aggregates
    this.updateSpanAggregates(trace.spanId, trace);

    // Update session aggregates
    this.updateSessionAggregates(trace.sessionId, trace);

    // Evict if over limit
    this.evictLlmTraces();

    this.dirty = true;
    this.emit({ type: 'llm_trace_added', trace });
  }

  /** Record a tool execution trace */
  addToolTrace(trace: ToolExecutionTrace): void {
    this.toolTraces.set(trace.id, trace);
    this.toolTraceOrder.push(trace.id);

    this.addToIndex(this.toolTracesBySession, trace.sessionId, trace.id);

    // Update parent span
    const span = this.spans.get(trace.spanId);
    if (span) {
      span.toolExecutionCount++;
    }

    // Update session
    const session = this.sessions.get(trace.sessionId);
    if (session) {
      session.totalToolExecutions++;
    }

    this.evictToolTraces();

    this.dirty = true;
    this.emit({ type: 'tool_trace_added', trace });
  }

  /** Start a new span */
  startSpan(span: Omit<Span, 'completedAt' | 'durationMs' | 'totalInputTokens' | 'totalOutputTokens' | 'totalCostUsd' | 'llmCallCount' | 'toolExecutionCount'>): Span {
    const fullSpan: Span = {
      ...span,
      completedAt: 0,
      durationMs: 0,
      totalInputTokens: 0,
      totalOutputTokens: 0,
      totalCostUsd: 0,
      llmCallCount: 0,
      toolExecutionCount: 0,
    };

    this.spans.set(fullSpan.id, fullSpan);
    this.addToIndex(this.spansBySession, fullSpan.sessionId, fullSpan.id);
    if (fullSpan.parentSpanId) {
      this.addToIndex(this.spansByParent, fullSpan.parentSpanId, fullSpan.id);
    }

    this.dirty = true;
    this.emit({ type: 'span_started', span: fullSpan });
    return fullSpan;
  }

  /** Complete a span */
  endSpan(spanId: SpanId, status: 'completed' | 'failed' | 'cancelled' = 'completed', error?: string): void {
    const span = this.spans.get(spanId);
    if (!span) return;

    span.completedAt = Date.now();
    span.durationMs = span.completedAt - span.startedAt;
    span.status = status;
    if (error) span.error = error;

    this.dirty = true;
    this.emit({ type: 'span_ended', span });
  }

  /** Start a new tracing session */
  startSession(session: Omit<TracingSession, 'completedAt' | 'totalInputTokens' | 'totalOutputTokens' | 'totalCostUsd' | 'totalLlmCalls' | 'totalToolExecutions' | 'totalFindings' | 'totalAgentsUsed' | 'costByProvider' | 'costByAgent' | 'tokensByModel'>): TracingSession {
    const fullSession: TracingSession = {
      ...session,
      completedAt: 0,
      totalInputTokens: 0,
      totalOutputTokens: 0,
      totalCostUsd: 0,
      totalLlmCalls: 0,
      totalToolExecutions: 0,
      totalFindings: 0,
      totalAgentsUsed: 0,
      costByProvider: {},
      costByAgent: {},
      tokensByModel: {},
    };

    this.sessions.set(fullSession.id, fullSession);

    this.dirty = true;
    this.emit({ type: 'session_started', session: fullSession });
    return fullSession;
  }

  /** Complete a session */
  endSession(sessionId: SessionId, status: 'completed' | 'failed' | 'cancelled' = 'completed'): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    session.completedAt = Date.now();
    session.status = status;

    // Count unique agents used
    const agentIds = new Set<string>();
    const traceIds = this.tracesBySession.get(sessionId);
    if (traceIds) {
      Array.from(traceIds).forEach(traceId => {
        const trace = this.llmTraces.get(traceId);
        if (trace?.agentId) agentIds.add(trace.agentId);
      });
    }
    session.totalAgentsUsed = agentIds.size;

    this.evictSessions();

    this.dirty = true;
    this.emit({ type: 'session_ended', session });
  }

  /** Increment findings count for a session */
  recordFinding(sessionId: SessionId): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.totalFindings++;
      this.dirty = true;
    }
  }

  // ─── Read Operations ─────────────────────────────────────────────────────

  /** Get a single LLM trace by ID */
  getLlmTrace(id: TraceId): LLMCallTrace | undefined {
    return this.llmTraces.get(id);
  }

  /** Get a single span by ID */
  getSpan(id: SpanId): Span | undefined {
    return this.spans.get(id);
  }

  /** Get a session by ID */
  getSession(id: SessionId): TracingSession | undefined {
    return this.sessions.get(id);
  }

  /** Query LLM traces with filtering */
  queryLlmTraces(filter: TraceFilter): LLMCallTrace[] {
    let results: LLMCallTrace[];

    // Use indexes to narrow down candidates
    if (filter.sessionId) {
      const ids = this.tracesBySession.get(filter.sessionId);
      results = ids ? Array.from(ids).map(id => this.llmTraces.get(id)!).filter(Boolean) : [];
    } else if (filter.spanId) {
      const ids = this.tracesBySpan.get(filter.spanId);
      results = ids ? Array.from(ids).map(id => this.llmTraces.get(id)!).filter(Boolean) : [];
    } else if (filter.agentId) {
      const ids = this.tracesByAgent.get(filter.agentId);
      results = ids ? Array.from(ids).map(id => this.llmTraces.get(id)!).filter(Boolean) : [];
    } else {
      results = Array.from(this.llmTraces.values());
    }

    // Apply filters
    results = results.filter(trace => {
      if (filter.providerId && trace.providerId !== filter.providerId) return false;
      if (filter.model && trace.model !== filter.model) return false;
      if (filter.callerType && trace.callerType !== filter.callerType) return false;
      if (filter.success !== undefined && trace.success !== filter.success) return false;
      if (filter.minCostUsd !== undefined && trace.costUsd < filter.minCostUsd) return false;
      if (filter.maxCostUsd !== undefined && trace.costUsd > filter.maxCostUsd) return false;
      if (filter.startAfter !== undefined && trace.startedAt < filter.startAfter) return false;
      if (filter.startBefore !== undefined && trace.startedAt > filter.startBefore) return false;
      if (filter.minDurationMs !== undefined && trace.durationMs < filter.minDurationMs) return false;
      return true;
    });

    // Sort
    const orderBy = filter.orderBy ?? 'startedAt';
    const dir = filter.orderDir ?? 'desc';
    results.sort((a, b) => {
      const aVal = a[orderBy] as number;
      const bVal = b[orderBy] as number;
      return dir === 'asc' ? aVal - bVal : bVal - aVal;
    });

    // Paginate
    const offset = filter.offset ?? 0;
    const limit = filter.limit ?? 100;
    return results.slice(offset, offset + limit);
  }

  /** Get all spans for a session */
  getSessionSpans(sessionId: SessionId): Span[] {
    const ids = this.spansBySession.get(sessionId);
    if (!ids) return [];
    return Array.from(ids)
      .map(id => this.spans.get(id)!)
      .filter(Boolean)
      .sort((a, b) => a.startedAt - b.startedAt);
  }

  /** Get child spans of a parent */
  getChildSpans(parentSpanId: SpanId): Span[] {
    const ids = this.spansByParent.get(parentSpanId);
    if (!ids) return [];
    return Array.from(ids)
      .map(id => this.spans.get(id)!)
      .filter(Boolean)
      .sort((a, b) => a.startedAt - b.startedAt);
  }

  /** Get all tool traces for a session */
  getSessionToolTraces(sessionId: SessionId): ToolExecutionTrace[] {
    const ids = this.toolTracesBySession.get(sessionId);
    if (!ids) return [];
    return Array.from(ids)
      .map(id => this.toolTraces.get(id)!)
      .filter(Boolean)
      .sort((a, b) => a.startedAt - b.startedAt);
  }

  /** List all sessions, most recent first */
  listSessions(): TracingSession[] {
    return Array.from(this.sessions.values())
      .sort((a, b) => b.startedAt - a.startedAt);
  }

  // ─── Analytics ────────────────────────────────────────────────────────────

  /** Get per-agent performance summary across all sessions */
  getAgentPerformance(timeRange?: TimeRange): AgentPerformanceSummary[] {
    const agentData = new Map<string, {
      sessions: Set<SessionId>;
      findings: number;
      cost: number;
      totalDuration: number;
      successCount: number;
      totalRuns: number;
    }>();

    // Collect data from spans of kind 'agent_execution'
    Array.from(this.spans.values()).forEach(span => {
      if (span.kind !== 'agent_execution' || !span.agentId) return;
      if (timeRange && (span.startedAt < timeRange.start || span.startedAt > timeRange.end)) return;

      let data = agentData.get(span.agentId);
      if (!data) {
        data = { sessions: new Set(), findings: 0, cost: 0, totalDuration: 0, successCount: 0, totalRuns: 0 };
        agentData.set(span.agentId, data);
      }

      data.sessions.add(span.sessionId);
      data.cost += span.totalCostUsd;
      data.totalDuration += span.durationMs;
      data.totalRuns++;
      if (span.status === 'completed') data.successCount++;

      // Count findings from metadata
      const findingCount = (span.metadata?.findingCount as number) ?? 0;
      data.findings += findingCount;
    });

    const results: AgentPerformanceSummary[] = [];
    for (const [agentId, data] of Array.from(agentData)) {
      const avgCostPerFinding = data.findings > 0 ? data.cost / data.findings : 0;
      results.push({
        agentId,
        agentName: agentId, // Could be enriched from agent catalog
        totalSessions: data.sessions.size,
        totalFindings: data.findings,
        totalCostUsd: data.cost,
        avgCostPerFinding,
        avgFindingsPerSession: data.sessions.size > 0 ? data.findings / data.sessions.size : 0,
        avgDurationMs: data.totalRuns > 0 ? data.totalDuration / data.totalRuns : 0,
        successRate: data.totalRuns > 0 ? data.successCount / data.totalRuns : 0,
        costEfficiency: data.cost > 0 ? data.findings / data.cost : 0,
      });
    }

    return results.sort((a, b) => b.costEfficiency - a.costEfficiency);
  }

  /** Get per-model performance summary */
  getModelPerformance(timeRange?: TimeRange): ModelPerformanceSummary[] {
    const modelData = new Map<string, {
      providerId: string;
      calls: number;
      inputTokens: number;
      outputTokens: number;
      cost: number;
      totalLatency: number;
      errors: number;
      productiveCalls: number;
    }>();

    Array.from(this.llmTraces.values()).forEach(trace => {
      if (timeRange && (trace.startedAt < timeRange.start || trace.startedAt > timeRange.end)) return;

      const key = `${trace.providerId}:${trace.model}`;
      let data = modelData.get(key);
      if (!data) {
        data = {
          providerId: trace.providerId,
          calls: 0, inputTokens: 0, outputTokens: 0, cost: 0,
          totalLatency: 0, errors: 0, productiveCalls: 0,
        };
        modelData.set(key, data);
      }

      data.calls++;
      data.inputTokens += trace.inputTokens;
      data.outputTokens += trace.outputTokens;
      data.cost += trace.costUsd;
      data.totalLatency += trace.durationMs;
      if (!trace.success) data.errors++;
      if (trace.toolCallCount > 0 || trace.stopReason === 'end_turn') data.productiveCalls++;
    });

    const results: ModelPerformanceSummary[] = [];
    for (const [key, data] of Array.from(modelData)) {
      const [, model] = key.split(':');
      results.push({
        providerId: data.providerId,
        model,
        totalCalls: data.calls,
        totalInputTokens: data.inputTokens,
        totalOutputTokens: data.outputTokens,
        totalCostUsd: data.cost,
        avgLatencyMs: data.calls > 0 ? data.totalLatency / data.calls : 0,
        errorRate: data.calls > 0 ? data.errors / data.calls : 0,
        productiveCallRate: data.calls > 0 ? data.productiveCalls / data.calls : 0,
      });
    }

    return results.sort((a, b) => b.totalCalls - a.totalCalls);
  }

  /** Get cost over time for charting (bucketed by interval) */
  getCostTimeSeries(sessionId: SessionId, bucketMs: number = 60000): Array<{ timestamp: number; cost: number; tokens: number }> {
    const traceIds = this.tracesBySession.get(sessionId);
    if (!traceIds) return [];

    const session = this.sessions.get(sessionId);
    if (!session) return [];

    const traces = Array.from(traceIds)
      .map(id => this.llmTraces.get(id)!)
      .filter(Boolean)
      .sort((a, b) => a.startedAt - b.startedAt);

    if (traces.length === 0) return [];

    const startTime = session.startedAt;
    const endTime = session.completedAt || Date.now();
    const buckets: Array<{ timestamp: number; cost: number; tokens: number }> = [];

    for (let t = startTime; t <= endTime; t += bucketMs) {
      const bucketTraces = traces.filter(
        tr => tr.startedAt >= t && tr.startedAt < t + bucketMs
      );
      buckets.push({
        timestamp: t,
        cost: bucketTraces.reduce((sum, tr) => sum + tr.costUsd, 0),
        tokens: bucketTraces.reduce((sum, tr) => sum + tr.totalTokens, 0),
      });
    }

    return buckets;
  }

  /** Get latency distribution for a session or globally */
  getLatencyDistribution(filter?: TraceFilter): { p50: number; p75: number; p90: number; p95: number; p99: number; max: number } {
    const traces = this.queryLlmTraces({ ...filter, limit: 100000 });
    if (traces.length === 0) {
      return { p50: 0, p75: 0, p90: 0, p95: 0, p99: 0, max: 0 };
    }

    const latencies = traces.map(t => t.durationMs).sort((a, b) => a - b);
    const percentile = (p: number) => latencies[Math.floor(latencies.length * p / 100)] ?? 0;

    return {
      p50: percentile(50),
      p75: percentile(75),
      p90: percentile(90),
      p95: percentile(95),
      p99: percentile(99),
      max: latencies[latencies.length - 1] ?? 0,
    };
  }

  // ─── Subscriptions ────────────────────────────────────────────────────────

  /** Subscribe to trace store events for real-time dashboard updates */
  subscribe(listener: (event: TraceStoreEvent) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  // ─── Persistence ──────────────────────────────────────────────────────────

  /** Export all data as a JSON-serializable object */
  exportData(): TraceStoreExport {
    return {
      version: 1,
      exportedAt: Date.now(),
      sessions: Array.from(this.sessions.values()),
      spans: Array.from(this.spans.values()),
      llmTraces: Array.from(this.llmTraces.values()),
      toolTraces: Array.from(this.toolTraces.values()),
    };
  }

  /** Import previously exported data */
  importData(data: TraceStoreExport): void {
    if (data.version !== 1) {
      throw new Error(`Unsupported trace data version: ${data.version}`);
    }

    for (const session of data.sessions) {
      this.sessions.set(session.id, session);
    }

    for (const span of data.spans) {
      this.spans.set(span.id, span);
      this.addToIndex(this.spansBySession, span.sessionId, span.id);
      if (span.parentSpanId) {
        this.addToIndex(this.spansByParent, span.parentSpanId, span.id);
      }
    }

    for (const trace of data.llmTraces) {
      this.llmTraces.set(trace.id, trace);
      this.llmTraceOrder.push(trace.id);
      this.addToIndex(this.tracesBySession, trace.sessionId, trace.id);
      this.addToIndex(this.tracesBySpan, trace.spanId, trace.id);
      if (trace.agentId) {
        this.addToIndex(this.tracesByAgent, trace.agentId, trace.id);
      }
    }

    for (const trace of data.toolTraces) {
      this.toolTraces.set(trace.id, trace);
      this.toolTraceOrder.push(trace.id);
      this.addToIndex(this.toolTracesBySession, trace.sessionId, trace.id);
    }
  }

  /**
   * Persist to disk via a pluggable persistence adapter.
   * Falls back to localStorage when no adapter is set (dev/test mode).
   */
  async persistToDisk(): Promise<void> {
    const data = this.exportData();
    const json = JSON.stringify(data);

    if (this.persistAdapter) {
      try {
        await this.persistAdapter.write(json);
      } catch (err) {
        console.warn('[TraceStore] Persistence adapter write failed:', err);
      }
    } else {
      // Fallback to localStorage for development/testing
      try {
        if (typeof localStorage !== 'undefined') {
          localStorage.setItem('huntress_traces', json);
        }
      } catch (storageErr) {
        console.warn('[TraceStore] Could not persist traces:', storageErr);
      }
    }

    this.dirty = false;
  }

  /** Load persisted data from disk */
  async loadFromDisk(): Promise<void> {
    try {
      let json: string | null = null;

      if (this.persistAdapter) {
        try {
          json = await this.persistAdapter.read();
        } catch {
          // Adapter not available, try fallback
        }
      }

      if (!json) {
        try {
          if (typeof localStorage !== 'undefined') {
            json = localStorage.getItem('huntress_traces');
          }
        } catch {
          // localStorage not available
        }
      }

      if (json) {
        const data = JSON.parse(json) as TraceStoreExport;
        this.importData(data);
      }
    } catch (err) {
      console.warn('[TraceStore] Could not load persisted traces:', err);
    }
  }

  /** Set a persistence adapter (e.g., Tauri filesystem) */
  setPersistAdapter(adapter: PersistAdapter): void {
    this.persistAdapter = adapter;
  }

  /** Get store statistics */
  getStats(): TraceStoreStats {
    return {
      llmTraceCount: this.llmTraces.size,
      toolTraceCount: this.toolTraces.size,
      spanCount: this.spans.size,
      sessionCount: this.sessions.size,
      maxLlmTraces: this.config.maxLlmTraces,
      maxToolTraces: this.config.maxToolTraces,
      isDirty: this.dirty,
    };
  }

  /** Clean up timers */
  destroy(): void {
    if (this.persistTimer) {
      clearInterval(this.persistTimer);
      this.persistTimer = null;
    }
    this.listeners.clear();
  }

  // ─── Private Helpers ──────────────────────────────────────────────────────

  private addToIndex(index: Map<string, Set<string>>, key: string, value: string): void {
    let set = index.get(key);
    if (!set) {
      set = new Set();
      index.set(key, set);
    }
    set.add(value);
  }

  private updateSpanAggregates(spanId: SpanId, trace: LLMCallTrace): void {
    const span = this.spans.get(spanId);
    if (!span) return;

    span.totalInputTokens += trace.inputTokens;
    span.totalOutputTokens += trace.outputTokens;
    span.totalCostUsd += trace.costUsd;
    span.llmCallCount++;

    // Propagate to parent spans
    if (span.parentSpanId) {
      this.updateSpanAggregates(span.parentSpanId, trace);
    }
  }

  private updateSessionAggregates(sessionId: SessionId, trace: LLMCallTrace): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    session.totalInputTokens += trace.inputTokens;
    session.totalOutputTokens += trace.outputTokens;
    session.totalCostUsd += trace.costUsd;
    session.totalLlmCalls++;

    // Cost by provider
    session.costByProvider[trace.providerId] =
      (session.costByProvider[trace.providerId] ?? 0) + trace.costUsd;

    // Cost by agent
    if (trace.agentId) {
      session.costByAgent[trace.agentId] =
        (session.costByAgent[trace.agentId] ?? 0) + trace.costUsd;
    }

    // Tokens by model
    if (!session.tokensByModel[trace.model]) {
      session.tokensByModel[trace.model] = { input: 0, output: 0 };
    }
    session.tokensByModel[trace.model].input += trace.inputTokens;
    session.tokensByModel[trace.model].output += trace.outputTokens;
  }

  private evictLlmTraces(): void {
    while (this.llmTraces.size > this.config.maxLlmTraces && this.llmTraceOrder.length > 0) {
      const oldestId = this.llmTraceOrder.shift()!;
      const trace = this.llmTraces.get(oldestId);
      if (trace) {
        this.llmTraces.delete(oldestId);
        // Clean up indexes
        this.tracesBySession.get(trace.sessionId)?.delete(oldestId);
        this.tracesBySpan.get(trace.spanId)?.delete(oldestId);
        if (trace.agentId) {
          this.tracesByAgent.get(trace.agentId)?.delete(oldestId);
        }
      }
    }
  }

  private evictToolTraces(): void {
    while (this.toolTraces.size > this.config.maxToolTraces && this.toolTraceOrder.length > 0) {
      const oldestId = this.toolTraceOrder.shift()!;
      const trace = this.toolTraces.get(oldestId);
      if (trace) {
        this.toolTraces.delete(oldestId);
        this.toolTracesBySession.get(trace.sessionId)?.delete(oldestId);
      }
    }
  }

  private evictSessions(): void {
    if (this.sessions.size <= this.config.maxSessions) return;

    // Find completed sessions oldest first
    const completed = Array.from(this.sessions.values())
      .filter(s => s.status !== 'active')
      .sort((a, b) => a.startedAt - b.startedAt);

    while (this.sessions.size > this.config.maxSessions && completed.length > 0) {
      const oldest = completed.shift()!;
      this.sessions.delete(oldest.id);
      // Clean up associated indexes (but keep trace data for analytics)
      this.tracesBySession.delete(oldest.id);
      this.toolTracesBySession.delete(oldest.id);
      this.spansBySession.delete(oldest.id);
    }
  }

  private emit(event: TraceStoreEvent): void {
    Array.from(this.listeners).forEach(listener => {
      try {
        listener(event);
      } catch (err) {
        console.error('[TraceStore] Listener error:', err);
      }
    });
  }
}

// ─── Supporting Types ────────────────────────────────────────────────────────

export interface TraceStoreExport {
  version: number;
  exportedAt: number;
  sessions: TracingSession[];
  spans: Span[];
  llmTraces: LLMCallTrace[];
  toolTraces: ToolExecutionTrace[];
}

export interface TraceStoreStats {
  llmTraceCount: number;
  toolTraceCount: number;
  spanCount: number;
  sessionCount: number;
  maxLlmTraces: number;
  maxToolTraces: number;
  isDirty: boolean;
}

export type TraceStoreEvent =
  | { type: 'llm_trace_added'; trace: LLMCallTrace }
  | { type: 'tool_trace_added'; trace: ToolExecutionTrace }
  | { type: 'span_started'; span: Span }
  | { type: 'span_ended'; span: Span }
  | { type: 'session_started'; session: TracingSession }
  | { type: 'session_ended'; session: TracingSession };

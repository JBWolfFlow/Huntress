/**
 * Tracing Integration — Wiring Guide
 *
 * Shows how to integrate the tracing system with existing Huntress components:
 * - App startup initialization
 * - Wrapping providers for agents and orchestrator
 * - Creating spans for agent executions
 * - Recording tool executions
 *
 * This file contains ready-to-use factory functions, not just examples.
 */

import type { ModelProvider } from '../providers/types';
import { TraceStore } from './trace_store';
import type { PersistAdapter } from './trace_store';
import { CostTracker } from './cost_tracker';
import { TracedModelProvider } from './traced_provider';
import type { TracedProviderConfig } from './traced_provider';
import { initializeTracing } from './hooks';
import type {
  SessionId,
  SpanId,
  SpanKind,
  BudgetConfig,
  ToolExecutionTrace,
  Span,
} from './types';

// ─── App Startup ─────────────────────────────────────────────────────────────

/** Global singletons — initialized once at app startup */
let _store: TraceStore | null = null;
let _costTracker: CostTracker | null = null;

/**
 * Initialize the tracing system. Call once at app startup (e.g., in main.tsx).
 *
 * Usage in main.tsx:
 *   import { setupTracing } from './core/tracing/integration';
 *   import { createTauriPersistAdapter } from './core/tracing/tauri_persist_adapter';
 *
 *   const adapter = await createTauriPersistAdapter();
 *   const tracing = await setupTracing(adapter ?? undefined);
 */
export async function setupTracing(persistAdapter?: PersistAdapter): Promise<{ store: TraceStore; costTracker: CostTracker }> {
  _store = new TraceStore({
    maxLlmTraces: 10000,
    maxToolTraces: 5000,
    maxSpans: 2000,
    maxSessions: 50,
    persistIntervalMs: 30000,
  });

  // Set persistence adapter if provided (Tauri filesystem, etc.)
  if (persistAdapter) {
    _store.setPersistAdapter(persistAdapter);
  }

  // Load any persisted traces from previous app runs
  await _store.loadFromDisk();

  _costTracker = new CostTracker(_store);

  // Initialize React hooks context
  initializeTracing(_store, _costTracker);

  return { store: _store, costTracker: _costTracker };
}

/** Get the global trace store instance */
export function getTraceStore(): TraceStore {
  if (!_store) throw new Error('Tracing not initialized. Call setupTracing() first.');
  return _store;
}

/** Get the global cost tracker instance */
export function getCostTracker(): CostTracker {
  if (!_costTracker) throw new Error('Tracing not initialized. Call setupTracing() first.');
  return _costTracker;
}

// ─── Session Management ──────────────────────────────────────────────────────

/**
 * Start a traced hunting session.
 *
 * Usage in OrchestratorEngine:
 *   const session = startTracedSession('HackerOne Program XYZ', ['*.example.com']);
 *   // ... run the hunt ...
 *   endTracedSession(session.id);
 */
export function startTracedSession(programName: string, targets: string[]): {
  sessionId: SessionId;
  rootSpanId: SpanId;
} {
  const store = getTraceStore();
  const sessionId: SessionId = `session_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

  store.startSession({
    id: sessionId,
    startedAt: Date.now(),
    status: 'active',
    programName,
    targets,
  });

  // Create root span for the session
  const rootSpan = store.startSpan({
    id: `span_root_${sessionId}`,
    parentSpanId: null,
    sessionId,
    kind: 'hunt_session',
    name: `Hunt: ${programName}`,
    startedAt: Date.now(),
    status: 'running',
    metadata: { programName, targets },
    agentId: null,
    error: null,
  });

  return { sessionId, rootSpanId: rootSpan.id };
}

/** End a traced session */
export function endTracedSession(
  sessionId: SessionId,
  status: 'completed' | 'failed' | 'cancelled' = 'completed'
): void {
  const store = getTraceStore();

  // End the root span
  const rootSpanId = `span_root_${sessionId}`;
  store.endSpan(rootSpanId, status);

  // End the session
  store.endSession(sessionId, status);

  // Persist immediately
  store.persistToDisk().catch(err => {
    console.error('[Tracing] Failed to persist on session end:', err);
  });
}

// ─── Span Helpers ────────────────────────────────────────────────────────────

/**
 * Create a span for an agent execution.
 *
 * Usage in agent execution:
 *   const span = createAgentSpan(sessionId, rootSpanId, 'ssrf-hunter', task.description);
 *   try {
 *     // ... run agent ...
 *     endAgentSpan(span.id, 'completed', { findingCount: results.findings.length });
 *   } catch (err) {
 *     endAgentSpan(span.id, 'failed', {}, err.message);
 *   }
 */
export function createAgentSpan(
  sessionId: SessionId,
  parentSpanId: SpanId,
  agentId: string,
  taskDescription: string
): Span {
  const store = getTraceStore();
  return store.startSpan({
    id: `span_agent_${agentId}_${Date.now()}`,
    parentSpanId,
    sessionId,
    kind: 'agent_execution',
    name: `Agent: ${agentId}`,
    startedAt: Date.now(),
    status: 'running',
    metadata: { taskDescription },
    agentId,
    error: null,
  });
}

/** End an agent span */
export function endAgentSpan(
  spanId: SpanId,
  status: 'completed' | 'failed' | 'cancelled' = 'completed',
  metadata?: Record<string, unknown>,
  error?: string
): void {
  const store = getTraceStore();
  const span = store.getSpan(spanId);
  if (span && metadata) {
    Object.assign(span.metadata, metadata);
  }
  store.endSpan(spanId, status, error);
}

/** Create a span for a single ReAct iteration */
export function createIterationSpan(
  sessionId: SessionId,
  parentSpanId: SpanId,
  agentId: string,
  iteration: number
): Span {
  const store = getTraceStore();
  return store.startSpan({
    id: `span_iter_${agentId}_${iteration}_${Date.now()}`,
    parentSpanId,
    sessionId,
    kind: 'react_iteration',
    name: `Iteration ${iteration}`,
    startedAt: Date.now(),
    status: 'running',
    metadata: { iteration },
    agentId,
    error: null,
  });
}

/** Create a span for orchestrator processing */
export function createOrchestratorSpan(
  sessionId: SessionId,
  parentSpanId: SpanId,
  name: string,
  kind: SpanKind = 'orchestrator_turn'
): Span {
  const store = getTraceStore();
  return store.startSpan({
    id: `span_orch_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    parentSpanId,
    sessionId,
    kind,
    name,
    startedAt: Date.now(),
    status: 'running',
    metadata: {},
    agentId: null,
    error: null,
  });
}

// ─── Provider Wrapping ───────────────────────────────────────────────────────

/**
 * Wrap a ModelProvider with tracing for the orchestrator.
 *
 * Usage:
 *   const tracedProvider = wrapProviderForOrchestrator(provider, sessionId, rootSpanId);
 *   // Pass tracedProvider to the orchestrator engine
 */
export function wrapProviderForOrchestrator(
  provider: ModelProvider,
  sessionId: SessionId,
  spanId: SpanId,
  budget?: BudgetConfig
): TracedModelProvider {
  const store = getTraceStore();
  return new TracedModelProvider(provider, store, {
    sessionId,
    spanId,
    callerType: 'orchestrator',
    captureContent: true,
    budget,
    onBudgetWarning: (status) => {
      console.warn(
        `[Budget Warning] Session ${sessionId}: ${(status.percentUsed * 100).toFixed(1)}% used ` +
        `($${status.spent.toFixed(4)} of $${status.limit.toFixed(2)})`
      );
    },
    onBudgetExceeded: (status) => {
      console.error(
        `[Budget Exceeded] Session ${sessionId}: $${status.spent.toFixed(4)} spent, ` +
        `limit was $${status.limit.toFixed(2)}`
      );
    },
  });
}

/**
 * Wrap a ModelProvider with tracing for a sub-agent.
 *
 * Usage:
 *   const agentSpan = createAgentSpan(sessionId, rootSpanId, 'ssrf-hunter', 'Test SSRF');
 *   const tracedProvider = wrapProviderForAgent(provider, sessionId, agentSpan.id, 'ssrf-hunter');
 *   await agent.initialize(tracedProvider, modelId);
 */
export function wrapProviderForAgent(
  provider: ModelProvider,
  sessionId: SessionId,
  spanId: SpanId,
  agentId: string,
  budget?: BudgetConfig
): TracedModelProvider {
  const store = getTraceStore();
  return new TracedModelProvider(provider, store, {
    sessionId,
    spanId,
    callerType: 'agent',
    agentId,
    captureContent: true,
    budget,
    onBudgetWarning: (status) => {
      console.warn(
        `[Budget Warning] Agent ${agentId}: ${(status.percentUsed * 100).toFixed(1)}% used ` +
        `($${status.spent.toFixed(4)})`
      );
    },
    onBudgetExceeded: (status) => {
      console.error(
        `[Budget Exceeded] Agent ${agentId}: $${status.spent.toFixed(4)} spent`
      );
    },
  });
}

// ─── Tool Execution Recording ────────────────────────────────────────────────

/**
 * Record a tool execution trace.
 *
 * Usage in the ReactLoop's processToolCall:
 *   const traceId = recordToolExecution({
 *     sessionId,
 *     spanId: currentSpanId,
 *     toolName: 'execute_command',
 *     command: 'nmap -sV target.com',
 *     target: 'target.com',
 *     category: 'recon',
 *     approvalStatus: 'approved',
 *     ...
 *   });
 */
export function recordToolExecution(params: {
  sessionId: SessionId;
  spanId: SpanId;
  toolName: string;
  command: string;
  target: string;
  category: string;
  approvalStatus: ToolExecutionTrace['approvalStatus'];
  agentId?: string;
  exitCode?: number;
  success: boolean;
  error?: string;
  blockedBySafety?: boolean;
  durationMs: number;
}): string {
  const store = getTraceStore();
  const id = `tool_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  const now = Date.now();

  store.addToolTrace({
    id,
    spanId: params.spanId,
    sessionId: params.sessionId,
    startedAt: now - params.durationMs,
    completedAt: now,
    durationMs: params.durationMs,
    toolName: params.toolName,
    command: params.command,
    target: params.target,
    approvalStatus: params.approvalStatus,
    category: params.category,
    exitCode: params.exitCode ?? null,
    success: params.success,
    error: params.error ?? null,
    blockedBySafety: params.blockedBySafety ?? false,
    agentId: params.agentId ?? null,
  });

  return id;
}

/** Record that a finding was discovered */
export function recordFinding(sessionId: SessionId): void {
  const store = getTraceStore();
  store.recordFinding(sessionId);
}

// ─── Budget Configuration ────────────────────────────────────────────────────

/**
 * Configure budget limits for a session.
 *
 * Usage:
 *   setSessionBudget(sessionId, {
 *     maxSessionCostUsd: 5.00,    // Max $5 per hunt session
 *     maxAgentCostUsd: 1.00,      // Max $1 per agent
 *     warningThreshold: 0.8,      // Warn at 80%
 *     hardStop: true,             // Stop agents when exceeded
 *   });
 */
export function setSessionBudget(sessionId: SessionId, config: BudgetConfig): void {
  const costTracker = getCostTracker();
  costTracker.setSessionBudget(sessionId, config);
}

// ─── Cleanup ─────────────────────────────────────────────────────────────────

/** Clean up tracing resources. Call on app shutdown. */
export async function shutdownTracing(): Promise<void> {
  if (_store) {
    await _store.persistToDisk();
    _store.destroy();
    _store = null;
  }
  if (_costTracker) {
    _costTracker.destroy();
    _costTracker = null;
  }
}

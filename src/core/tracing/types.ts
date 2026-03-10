/**
 * LLM Observability & Tracing — Core Types
 *
 * Lightweight, SQLite-friendly tracing types for a desktop app.
 * Designed to capture everything needed for debugging, cost tracking,
 * and performance analysis without external infrastructure.
 *
 * Trace hierarchy:
 *   Session (hunt) → Span (logical operation) → Event (atomic action)
 *
 * Key design decisions:
 * - All timestamps are Unix ms (number) for SQLite compatibility
 * - All monetary values are USD floats
 * - IDs are prefixed strings for easy identification in logs
 * - Token counts are always split into input/output for accurate costing
 */

// ─── Identifiers ─────────────────────────────────────────────────────────────

/** Branded ID types for type safety */
export type TraceId = string;
export type SpanId = string;
export type SessionId = string;

// ─── LLM Call Trace ──────────────────────────────────────────────────────────

/** A single LLM API call — the atomic unit of tracing */
export interface LLMCallTrace {
  /** Unique trace ID (format: "llm_<timestamp>_<random>") */
  id: TraceId;
  /** Parent span this call belongs to */
  spanId: SpanId;
  /** Hunt session ID */
  sessionId: SessionId;
  /** When the call started */
  startedAt: number;
  /** When the call completed (0 if still running) */
  completedAt: number;
  /** Duration in ms (computed: completedAt - startedAt) */
  durationMs: number;

  // ── Model Info ──
  /** Provider ID (anthropic, openai, google, local, openrouter) */
  providerId: string;
  /** Model ID (e.g., "claude-opus-4-6") */
  model: string;

  // ── Token Usage ──
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;

  // ── Cost ──
  /** Cost in USD for this call */
  costUsd: number;

  // ── Request Details ──
  /** Whether streaming was used */
  streaming: boolean;
  /** Temperature setting */
  temperature: number | null;
  /** Max tokens requested */
  maxTokens: number | null;
  /** Number of tools provided */
  toolCount: number;
  /** Number of tool calls made by the model */
  toolCallCount: number;
  /** Names of tools called */
  toolCallNames: string[];
  /** Stop reason */
  stopReason: string;

  // ── Context ──
  /** Which agent or component made this call */
  callerType: 'orchestrator' | 'agent' | 'validation' | 'summarizer' | 'other';
  /** Agent ID if callerType is 'agent' */
  agentId: string | null;
  /** Number of messages in the conversation context */
  contextMessageCount: number;

  // ── Error Tracking ──
  /** Whether the call succeeded */
  success: boolean;
  /** Error message if failed */
  error: string | null;
  /** Number of retries before success/failure */
  retryCount: number;

  // ── Prompt/Completion (optional, can be large) ──
  /** System prompt (truncated to 2000 chars for storage) */
  systemPrompt: string | null;
  /** Last user message (truncated to 2000 chars) */
  lastUserMessage: string | null;
  /** Model response (truncated to 2000 chars) */
  responsePreview: string | null;
}

// ─── Tool Execution Trace ────────────────────────────────────────────────────

/** A tool/command execution trace */
export interface ToolExecutionTrace {
  id: TraceId;
  spanId: SpanId;
  sessionId: SessionId;
  startedAt: number;
  completedAt: number;
  durationMs: number;

  /** The tool name (execute_command, report_finding, etc.) */
  toolName: string;
  /** The command or action executed */
  command: string;
  /** Target host/URL */
  target: string;
  /** Whether it was approved, denied, or auto-approved */
  approvalStatus: 'approved' | 'denied' | 'auto_approved' | 'not_required';
  /** Category: recon, active_testing, utility, etc. */
  category: string;

  /** Exit code (for commands) */
  exitCode: number | null;
  /** Whether execution succeeded */
  success: boolean;
  /** Error message if failed */
  error: string | null;
  /** Was it blocked by safety policies */
  blockedBySafety: boolean;

  /** Agent that requested this tool */
  agentId: string | null;
}

// ─── Span (Logical Operation) ────────────────────────────────────────────────

/** Span kinds in the Huntress lifecycle */
export type SpanKind =
  | 'hunt_session'        // Top-level hunt
  | 'agent_execution'     // A single agent running its task
  | 'react_iteration'     // One ReAct loop iteration
  | 'orchestrator_turn'   // Orchestrator processing a user message
  | 'briefing'            // Bounty program analysis
  | 'report_generation'   // PoC report creation
  | 'duplicate_check'     // Duplicate detection
  | 'validation'          // Finding validation
  | 'context_summary';    // Conversation summarization

/** A span groups related traces into a logical operation */
export interface Span {
  id: SpanId;
  parentSpanId: SpanId | null;
  sessionId: SessionId;
  kind: SpanKind;
  name: string;
  startedAt: number;
  completedAt: number;
  durationMs: number;
  status: 'running' | 'completed' | 'failed' | 'cancelled';

  /** Aggregate token usage within this span */
  totalInputTokens: number;
  totalOutputTokens: number;
  totalCostUsd: number;
  llmCallCount: number;
  toolExecutionCount: number;

  /** Metadata specific to this span kind */
  metadata: Record<string, unknown>;

  /** Agent ID if this span is agent-related */
  agentId: string | null;
  /** Error message if failed */
  error: string | null;
}

// ─── Session (Hunt) ──────────────────────────────────────────────────────────

/** A complete hunting session */
export interface TracingSession {
  id: SessionId;
  startedAt: number;
  completedAt: number;
  status: 'active' | 'completed' | 'failed' | 'cancelled';

  /** Target program name */
  programName: string;
  /** Primary targets */
  targets: string[];

  // ── Aggregate Metrics ──
  totalInputTokens: number;
  totalOutputTokens: number;
  totalCostUsd: number;
  totalLlmCalls: number;
  totalToolExecutions: number;
  totalFindings: number;
  totalAgentsUsed: number;

  /** Cost breakdown by provider */
  costByProvider: Record<string, number>;
  /** Cost breakdown by agent */
  costByAgent: Record<string, number>;
  /** Token usage by model */
  tokensByModel: Record<string, { input: number; output: number }>;
}

// ─── Cost Tracking ───────────────────────────────────────────────────────────

/** Budget configuration */
export interface BudgetConfig {
  /** Maximum spend per session in USD (0 = unlimited) */
  maxSessionCostUsd: number;
  /** Maximum spend per agent per session */
  maxAgentCostUsd: number;
  /** Warning threshold (percentage of max, e.g., 0.8 = 80%) */
  warningThreshold: number;
  /** Hard stop when budget exceeded */
  hardStop: boolean;
}

/** Budget status for a session or agent */
export interface BudgetStatus {
  spent: number;
  limit: number;
  remaining: number;
  percentUsed: number;
  isWarning: boolean;
  isExceeded: boolean;
}

// ─── Real-time Metrics ───────────────────────────────────────────────────────

/** Snapshot of current session metrics for the dashboard */
export interface SessionMetrics {
  sessionId: SessionId;
  elapsedMs: number;

  // Token throughput
  totalInputTokens: number;
  totalOutputTokens: number;
  tokensPerSecond: number;

  // Cost
  totalCostUsd: number;
  costPerMinute: number;

  // LLM calls
  totalLlmCalls: number;
  avgLatencyMs: number;
  p95LatencyMs: number;
  errorRate: number;

  // Agent progress
  activeAgents: number;
  completedAgents: number;
  totalFindings: number;

  // Per-agent breakdown
  agentMetrics: AgentMetrics[];

  // Budget
  budgetStatus: BudgetStatus;
}

/** Metrics for a single agent */
export interface AgentMetrics {
  agentId: string;
  agentName: string;
  status: string;
  llmCalls: number;
  toolExecutions: number;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  findings: number;
  avgLatencyMs: number;
  iterations: number;
  elapsedMs: number;
}

// ─── Historical Analysis ─────────────────────────────────────────────────────

/** Summary of an agent's performance across multiple sessions */
export interface AgentPerformanceSummary {
  agentId: string;
  agentName: string;
  totalSessions: number;
  totalFindings: number;
  totalCostUsd: number;
  avgCostPerFinding: number;
  avgFindingsPerSession: number;
  avgDurationMs: number;
  successRate: number;
  /** Findings per dollar spent */
  costEfficiency: number;
}

/** Summary of a model's performance */
export interface ModelPerformanceSummary {
  providerId: string;
  model: string;
  totalCalls: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  totalCostUsd: number;
  avgLatencyMs: number;
  errorRate: number;
  /** Calls where the model produced useful output (tool calls or findings) */
  productiveCallRate: number;
}

// ─── Query Types ─────────────────────────────────────────────────────────────

/** Filter for querying traces */
export interface TraceFilter {
  sessionId?: SessionId;
  spanId?: SpanId;
  agentId?: string;
  providerId?: string;
  model?: string;
  callerType?: LLMCallTrace['callerType'];
  success?: boolean;
  minCostUsd?: number;
  maxCostUsd?: number;
  startAfter?: number;
  startBefore?: number;
  minDurationMs?: number;
  limit?: number;
  offset?: number;
  orderBy?: 'startedAt' | 'durationMs' | 'costUsd' | 'totalTokens';
  orderDir?: 'asc' | 'desc';
}

/** Time range for historical queries */
export interface TimeRange {
  start: number;
  end: number;
}

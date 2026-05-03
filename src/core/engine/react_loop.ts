/**
 * ReAct Execution Loop — The Core Agent Engine
 *
 * Implements the THINK → VALIDATE → APPROVE → EXECUTE → OBSERVE → DECIDE cycle
 * that powers all autonomous hunting agents. Based on the ReAct pattern
 * (Reasoning + Acting) with XBOW's Solver pattern adaptations:
 *
 * - Adaptive iteration budget by agent complexity: 30 simple, 80 moderate, 120 complex (I1)
 * - Native tool use (structured tool calls, not JSON-in-text parsing)
 * - Every iteration logged for crash recovery
 * - Agent can write and execute custom scripts
 * - Deterministic safety policies applied before approval gate
 * - Fresh agent spawn after iteration limit with summary handoff
 */

import type {
  ModelProvider,
  ChatMessage,
  ChatResponse,
  ToolDefinition,
  ToolUseBlock,
  ToolResultBlock,
  ContentBlock,
  SendMessageOptions,
} from '../providers/types';
import { getMessageText } from '../providers/types';
import { BROWSER_TOOL_SCHEMAS } from './tool_schemas';
import { checkSafetyPolicies } from './safety_policies';
import { invoke } from '@tauri-apps/api/core';
import { parseToolOutput, extractFindings, extractTargets } from './output_parsers';
import { ModelAlloy } from './model_alloy';
import type { HttpClient, HttpRequestOptions, HttpResponse } from '../http/request_engine';
import type { HttpExchange, SharedFinding, WafContext } from '../../agents/base_agent';
import type { CapturedAuth } from '../auth/auth_browser_capture';
import { ParamFuzzer } from '../fuzzer/param_fuzzer';
import type { VulnType } from '../fuzzer/payload_db';
import { getIterationBudget, getToolCallBudget } from '../orchestrator/cost_router';
import type { SessionManager } from '../auth/session_manager';
import { AgentBrowserClient } from './agent_browser_client';
import type {
  BrowserDialog as AgentDialog,
  BrowserConsoleLog as AgentConsoleLog,
} from './agent_browser_client';

// ─── Types ───────────────────────────────────────────────────────────────────

/** Configuration for a ReAct loop execution */
export interface ReactLoopConfig {
  /** The AI model provider to use */
  provider: ModelProvider;
  /** Model ID to use */
  model: string;
  /** System prompt establishing the agent's expertise */
  systemPrompt: string;
  /** The goal/task description for this agent */
  goal: string;
  /** Tool definitions the agent can invoke */
  tools: ToolDefinition[];
  /** Maximum iterations before stopping (default: adaptive by agentType — 30/80/120) */
  maxIterations?: number;
  /** Agent type ID — used for adaptive iteration budget lookup when maxIterations not set */
  agentType?: string;
  /** Target domain/URL for scope validation */
  target: string;
  /** In-scope domains/URLs */
  scope: string[];
  /** Callback when a tool needs approval */
  onApprovalRequest?: (request: ApprovalRequest) => Promise<boolean>;
  /** Callback to execute a command via PTY */
  onExecuteCommand?: (command: string, target: string) => Promise<CommandResult>;
  /** Callback when a finding is discovered */
  onFinding?: (finding: ReactFinding) => void;
  /** Callback for real-time status updates */
  onStatusUpdate?: (update: StatusUpdate) => void;
  /** Callback when the agent requests a specialist */
  onSpecialistRequest?: (request: SpecialistRequest) => void;
  /** Previous context from a prior run (for continuation after iteration limit) */
  priorContext?: string;
  /** Auto-approve safe/passive commands */
  autoApproveSafe?: boolean;
  /** HTTP client for direct requests (Phase 20A — optional, graceful degradation) */
  httpClient?: HttpClient;
  /** List of available security tools on this system (from tool health check) */
  availableTools?: string[];
  /** Session manager for authenticated requests (S4) */
  sessionManager?: SessionManager;
  /** Active auth session ID — when set, auth headers injected into all HTTP requests */
  authSessionId?: string;
  /** Cross-agent findings from the Blackboard — injected into system prompt for context */
  sharedFindings?: SharedFinding[];
  /** WAF detection context — when set, agents receive WAF-specific bypass guidance */
  wafContext?: WafContext;
  /** Enable headless browser tools for this agent (browser_navigate, browser_evaluate, etc.) */
  browserEnabled?: boolean;
}

/** A command execution result */
export interface CommandResult {
  success: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
  executionTimeMs: number;
  blocked?: boolean;
  blockReason?: string;
}

/** A vulnerability finding from the ReAct loop */
export interface ReactFinding {
  id: string;
  title: string;
  vulnerabilityType: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  target: string;
  description: string;
  evidence: string[];
  reproductionSteps: string[];
  impact: string;
  confidence: number;
  discoveredAtIteration: number;
  agentId: string;
}

/** Approval request for the UI */
export interface ApprovalRequest {
  command: string;
  target: string;
  reasoning: string;
  category: string;
  toolName: string;
  safetyWarnings: string[];
}

/** Request to dispatch a specialist agent */
export interface SpecialistRequest {
  agentType: string;
  target: string;
  context: string;
  priority: string;
}

/** Real-time status update */
export interface StatusUpdate {
  type: 'thinking' | 'executing' | 'finding' | 'error' | 'complete' | 'iteration';
  message: string;
  iteration: number;
  maxIterations: number;
  toolCallCount: number;
  findingCount: number;
}

/** A single iteration's log entry for crash recovery */
export interface IterationLog {
  iteration: number;
  timestamp: number;
  toolCalls?: ToolUseBlock[];
  toolResult?: string;
  thinking?: string;
  finding?: ReactFinding;
  error?: string;
  /** Which alloy component handled this iteration (set when provider is a ModelAlloy) */
  alloyComponentUsed?: string;
}

/** Structured handoff for context compression between agent continuations */
export interface ContinuationHandoff {
  /** Confirmed findings from this run */
  findings: Array<{
    title: string;
    severity: string;
    target: string;
    confidence: number;
  }>;
  /** Paths that were tested but yielded no findings (avoid re-testing) */
  testedPaths: string[];
  /** Active hypotheses that the next agent should investigate */
  hypotheses: string[];
  /** Assets discovered during this run (subdomains, endpoints, etc.) */
  discoveredAssets: string[];
  /** How many iterations were consumed */
  iterationsUsed: number;
}

/** Result of a complete ReAct loop execution */
export interface ReactLoopResult {
  success: boolean;
  findings: ReactFinding[];
  totalIterations: number;
  toolCallCount: number;
  /** Count of HTTP-related tool calls (http_request, successful execute_command, fuzz_parameter) */
  httpRequestCount: number;
  totalTokensUsed: { input: number; output: number };
  duration: number;
  stopReason: 'task_complete' | 'no_vulnerabilities' | 'target_hardened' | 'blocker' | 'iteration_limit' | 'tool_call_limit' | 'identical_toolcall_loop' | 'error' | 'killed';
  summary: string;
  iterationLog: IterationLog[];
  /** Captured HTTP request/response exchanges for report evidence */
  httpExchanges: HttpExchange[];
  /** Compressed context for continuation in a fresh agent */
  continuationContext?: string;
  /** Structured handoff data for the next agent */
  continuationHandoff?: ContinuationHandoff;
  /** Present only for AuthWorkerAgent runs — terminal state from capture_complete/capture_failed. */
  captureTerminal?: { kind: 'complete' | 'failed'; input: Record<string, unknown> };
  /** Present only when browser_finish_auth_capture succeeded during the run. */
  capturedAuth?: CapturedAuth;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Redact auth secrets from tool output before emission to the LLM (Phase 1 / Q1).
 *
 * The agent's sandbox has HUNTRESS_AUTH_* env vars set and a pre-stamped
 * ~/.curlrc. When the agent's command echoes those (e.g., `curl -v` prints
 * outgoing headers), we don't want the token body in the LLM context — both
 * for hygiene and to prevent the agent from pasting the literal token into
 * findings.
 */
export function scrubAuthSecrets(text: string): string {
  if (!text) return text;
  return text
    // Authorization: Bearer <token>
    .replace(/(Authorization\s*:\s*(?:Bearer|Basic|Token)\s+)([A-Za-z0-9._~+/=\-]+)/gi, '$1<REDACTED>')
    // Cookie: a=b; c=d  (only the value portion of the whole header)
    .replace(/(Cookie\s*:\s*)([^\r\n]{1,4096})/gi, '$1<REDACTED>')
    .replace(/(Set-Cookie\s*:\s*[^=]+=)([^;\r\n]{8,})/gi, '$1<REDACTED>')
    // wallet-authorization and other non-standard "authorization" bearers
    .replace(/([A-Za-z][A-Za-z0-9_\-]*-authorization\s*:\s*)([^\r\n]{8,})/gi, '$1<REDACTED>')
    // x-api-key / api-key / x-csrf-token / x-xsrf-token header values
    .replace(/((?:x-)?(?:api-key|csrf-token|xsrf-token|wallet-device-serial)\s*:\s*)([^\r\n]{4,})/gi, '$1<REDACTED>')
    // Raw JWT anywhere (3-segment base64url)
    .replace(/\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g, '<REDACTED_JWT>');
}

/** Simple string hash for response comparison (FNV-1a 32-bit) */
function hashString(str: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

// ─── ReAct Loop Engine ───────────────────────────────────────────────────────

export class ReactLoop {
  private config: Required<
    Pick<ReactLoopConfig, 'provider' | 'model' | 'systemPrompt' | 'goal' | 'tools' | 'target' | 'scope'>
  > & ReactLoopConfig;

  private conversationHistory: ChatMessage[] = [];
  private findings: ReactFinding[] = [];
  private iterationLog: IterationLog[] = [];
  private toolCallCount = 0;
  /** Counts HTTP-related tool calls: http_request, successful execute_command, fuzz_parameter */
  private httpRequestCount = 0;
  /** Minimum HTTP interactions required before report_finding is accepted */
  private static readonly MIN_HTTP_REQUESTS_FOR_FINDING = 3;
  /** Accumulated HTTP request/response exchanges for report evidence */
  private httpExchanges: HttpExchange[] = [];
  /** Maximum HTTP exchanges to keep (prevent unbounded memory growth) */
  private static readonly MAX_HTTP_EXCHANGES = 50;
  private totalTokens = { input: 0, output: 0 };
  private killed = false;
  /** Set when the agent calls stop_hunting — distinct from killed (emergency stop) */
  private stopped = false;
  /** Set when AuthWorkerAgent calls capture_complete or capture_failed. Consumed via the ReactLoopResult. */
  private captureTerminal: { kind: 'complete' | 'failed'; input: Record<string, unknown> } | null = null;
  /** Stashed by browser_finish_auth_capture — survives browser cleanup so the ReactLoopResult can carry it out. */
  private capturedAuth: CapturedAuth | null = null;
  private maxIterations: number;
  /**
   * P1-3-b: Per-agent hard cap on tool calls. Distinct from `maxIterations`:
   * counts tool invocations rather than LLM iterations (a single iteration
   * can produce 0-N tool calls). Backstop for the 2026-04-23 SSTI burn
   * pattern where the agent ran 90 productive-looking tool calls without
   * forward progress. Lookup via `cost_router.getToolCallBudget(agentType)`.
   */
  private maxToolCalls: number;
  /**
   * P1-3-a: Rolling buffer of `(toolName, argsHash)` keys for the most recent
   * tool calls. After 3 consecutive identical entries, the loop stops with
   * `stopReason: 'identical_toolcall_loop'`. Bounded to the last
   * IDENTICAL_TOOLCALL_THRESHOLD entries.
   */
  private recentToolCallKeys: string[] = [];
  private static readonly IDENTICAL_TOOLCALL_THRESHOLD = 3;
  /** Lazy-initialized Node subprocess client — Playwright runs out-of-WebView (I2). */
  private browserClient: AgentBrowserClient | null = null;

  /** Maximum conversation messages before pruning older entries */
  private static readonly MAX_CONTEXT_MESSAGES = 40;

  constructor(config: ReactLoopConfig) {
    // I1: Adaptive iteration budget — if maxIterations not explicitly set,
    // derive from agentType complexity tier (simple=30, moderate=80, complex=120)
    const defaultBudget = config.agentType
      ? getIterationBudget(config.agentType)
      : 80;

    // Phase A: Default browserEnabled=true — all agents get browser access.
    // Browser is lazy-initialized, so agents that don't call browser tools pay zero cost.
    const browserEnabled = config.browserEnabled ?? true;

    // Auto-include browser tool schemas if enabled and not already present
    const tools = (browserEnabled && !config.tools.some(t => t.name === 'browser_navigate'))
      ? [...config.tools, ...BROWSER_TOOL_SCHEMAS]
      : config.tools;

    this.config = {
      maxIterations: defaultBudget,
      autoApproveSafe: false,
      ...config,
      browserEnabled,
      tools,
    };
    this.maxIterations = this.config.maxIterations ?? defaultBudget;

    // P1-3-b: Tool-call cap is derived from agentType the same way the
    // iteration budget is. Unknown agents get the moderate-tier cap (120).
    this.maxToolCalls = config.agentType
      ? getToolCallBudget(config.agentType)
      : 120;
  }

  /**
   * P1-3-a: Compute the dedup key for a tool call. Uses FNV-1a over the
   * canonicalized JSON of the input so semantically-identical args (just in
   * different key order) collapse to the same key.
   */
  private computeToolCallKey(name: string, input: unknown): string {
    let argsStr: string;
    try {
      // Canonicalize: sort keys recursively so {a:1,b:2} == {b:2,a:1}
      argsStr = JSON.stringify(input, (_k, v) => {
        if (v && typeof v === 'object' && !Array.isArray(v)) {
          const sorted: Record<string, unknown> = {};
          for (const k of Object.keys(v).sort()) sorted[k] = (v as Record<string, unknown>)[k];
          return sorted;
        }
        return v;
      });
    } catch {
      argsStr = String(input);
    }
    return `${name}:${hashString(argsStr)}`;
  }

  /**
   * P1-3-a: Returns true when the last `IDENTICAL_TOOLCALL_THRESHOLD`
   * (currently 3) tool calls have all been the same `(name, argsHash)`.
   * Caller should stop the loop and surface `identical_toolcall_loop`.
   */
  private shouldStopForIdenticalToolCallLoop(): boolean {
    const threshold = ReactLoop.IDENTICAL_TOOLCALL_THRESHOLD;
    if (this.recentToolCallKeys.length < threshold) return false;
    const tail = this.recentToolCallKeys.slice(-threshold);
    return tail.every(k => k === tail[0]);
  }

  /**
   * P1-3-a: Append a tool-call key to the rolling buffer and prune to the
   * last `IDENTICAL_TOOLCALL_THRESHOLD` entries. Called once per processed
   * tool call inside the THINK→ACT→OBSERVE loop.
   */
  private trackToolCallKey(key: string): void {
    this.recentToolCallKeys.push(key);
    const max = ReactLoop.IDENTICAL_TOOLCALL_THRESHOLD;
    if (this.recentToolCallKeys.length > max) {
      this.recentToolCallKeys = this.recentToolCallKeys.slice(-max);
    }
  }

  /** Emergency stop — halts the loop at the next iteration boundary */
  kill(): void {
    this.killed = true;
  }

  /** Execute the full ReAct loop */
  async execute(): Promise<ReactLoopResult> {
    const startTime = Date.now();

    // Build initial system message
    const systemPrompt = this.buildSystemPrompt();

    // Seed the conversation with the goal
    let goalMessage = `## Task\n${this.config.goal}\n\n## Target\n${this.config.target}\n\n## Scope\n${this.config.scope.join(', ')}`;
    if (this.config.priorContext) {
      goalMessage += `\n\n## Context from Previous Session\n${this.config.priorContext}`;
    }

    this.conversationHistory.push({ role: 'user', content: goalMessage });

    let stopReason: ReactLoopResult['stopReason'] = 'iteration_limit';
    let summary = '';

    for (let iteration = 0; iteration < this.maxIterations; iteration++) {
      if (this.killed) {
        stopReason = 'killed';
        summary = `Agent killed at iteration ${iteration}`;
        break;
      }

      this.emitStatus('iteration', `Iteration ${iteration + 1}/${this.maxIterations}`, iteration);

      // Prune context window to prevent exceeding model limits
      this.manageContextWindow();

      const logEntry: IterationLog = {
        iteration,
        timestamp: Date.now(),
      };

      try {
        // ── THINK: Send context + tools to model ──
        this.emitStatus('thinking', 'Reasoning about next action...', iteration);

        const response = await this.config.provider.sendMessage(
          this.conversationHistory,
          {
            model: this.config.model,
            maxTokens: 4096,
            systemPrompt,
            tools: this.config.tools,
            toolChoice: 'auto',
          }
        );

        this.totalTokens.input += response.inputTokens;
        this.totalTokens.output += response.outputTokens;

        // Record which alloy component handled this iteration
        if (this.config.provider instanceof ModelAlloy) {
          const comp = this.config.provider.getLastSelectedComponent();
          logEntry.alloyComponentUsed = comp.label;
          this.emitStatus('thinking', `Using ${comp.label} for this iteration...`, iteration);
        }

        // If the model returned pure text with no tool calls, it's thinking/responding
        if (!response.toolCalls?.length) {
          logEntry.thinking = response.content;

          // Anthropic /v1/messages rejects empty text content blocks with 400
          // Bad Request. If the model returned no tool calls AND no content
          // (rare but happens — e.g., when extended thinking is filtered out
          // or the response is truncated), pushing { content: "" } poisons
          // the conversation history: every subsequent retry replays the
          // empty turn and hits another 400. Substitute a placeholder so
          // the loop can continue.
          // Bug observed 2026-05-02 against XBEN-005-24 (jwt-hunter): 5x
          // 400s in 60s → react_loop's error-window stop fires → challenge
          // marked ERROR even though the underlying state was recoverable.
          const safeContent = response.content && response.content.trim()
            ? response.content
            : '(model returned no content this turn — continuing)';

          // Add assistant response to conversation
          this.conversationHistory.push({
            role: 'assistant',
            content: safeContent,
          });

          // Check if it wants to stop (said something like "I'm done")
          if (response.stopReason === 'end_turn') {
            stopReason = 'task_complete';
            summary = safeContent;
            this.iterationLog.push(logEntry);
            break;
          }

          // Ask it to continue using tools
          this.conversationHistory.push({
            role: 'user',
            content: 'Continue with your next action. Use the available tools to make progress on the task.',
          });

          this.iterationLog.push(logEntry);
          continue;
        }

        // ── Process tool calls ──
        // Build the assistant message with content blocks
        const assistantBlocks: ContentBlock[] = [];
        if (response.content) {
          assistantBlocks.push({ type: 'text', text: response.content });
          logEntry.thinking = response.content;
        }
        for (const tc of response.toolCalls) {
          assistantBlocks.push(tc);
        }

        this.conversationHistory.push({
          role: 'assistant',
          content: assistantBlocks,
        });

        // Process each tool call
        const toolResults: ToolResultBlock[] = [];

        // P1-1 v7: Helper to build a complete user/tool_result reply for an
        // assistant turn that contained tool_use blocks. CRITICAL: Anthropic's
        // API rejects with 400 if any tool_use_id in the assistant turn
        // doesn't have a matching tool_result. Without this helper, breaking
        // mid-loop (tool_call_limit, identical_toolcall_loop, stop_hunting,
        // capture_*, processToolCall throw) leaves orphan tool_use blocks in
        // history → every subsequent /v1/messages call 400s with
        // "tool_use_id X is missing tool_result". The cascade observed
        // 2026-05-02 during the partial XBOW run (30+ 400s/run).
        const fillMissingToolResults = (reason: string): void => {
          const fulfilled = new Set(toolResults.map(r => r.tool_use_id));
          for (const tc of response.toolCalls ?? []) {
            if (!fulfilled.has(tc.id)) {
              toolResults.push({
                type: 'tool_result',
                tool_use_id: tc.id,
                content: `Tool execution skipped: ${reason}`,
                is_error: true,
              });
            }
          }
        };

        for (const toolCall of response.toolCalls) {
          if (!logEntry.toolCalls) logEntry.toolCalls = [];
          logEntry.toolCalls.push(toolCall);
          this.toolCallCount++;

          // P1-3-a: track for identical-tool-call-loop detection
          const callKey = this.computeToolCallKey(toolCall.name, toolCall.input);
          this.trackToolCallKey(callKey);

          // P1-3-b: hard cap on tool calls regardless of iteration count
          if (this.toolCallCount > this.maxToolCalls) {
            stopReason = 'tool_call_limit';
            summary = `Tool-call cap reached (${this.toolCallCount}/${this.maxToolCalls}). ` +
              `Agent burned its tool budget without completing the task.`;
            this.emitStatus('error', summary, iteration);
            fillMissingToolResults('tool-call cap reached');
            this.conversationHistory.push({
              role: 'user',
              content: '',
              toolResults,
            });
            this.iterationLog.push(logEntry);
            this.stopped = true;
            break;
          }

          const result = await this.processToolCall(toolCall, iteration);
          toolResults.push(result);

          // P1-3-a: stop after THRESHOLD consecutive identical tool calls.
          // Run AFTER processing so the result lands in toolResults and the
          // model sees what happened on the final repeat.
          if (this.shouldStopForIdenticalToolCallLoop()) {
            stopReason = 'identical_toolcall_loop';
            summary = `Stopped: ${ReactLoop.IDENTICAL_TOOLCALL_THRESHOLD} consecutive identical tool calls ` +
              `to '${toolCall.name}' with the same arguments. The agent appears stuck in a loop. ` +
              `Try a different approach or stop the hunt for this target.`;
            this.emitStatus('error', summary, iteration);
            fillMissingToolResults('stopped after identical-toolcall loop detected');
            this.conversationHistory.push({
              role: 'user',
              content: '',
              toolResults,
            });
            this.iterationLog.push(logEntry);
            this.stopped = true;
            break;
          }

          if (result.content) {
            logEntry.toolResult = result.content.substring(0, 1000); // Truncate for log
          }

          // Check if this was a stop_hunting call
          if (toolCall.name === 'stop_hunting') {
            const input = toolCall.input as { reason: string; summary: string };
            stopReason = input.reason as ReactLoopResult['stopReason'];
            summary = input.summary;
            // Push tool results before breaking
            fillMissingToolResults('agent invoked stop_hunting before processing remaining tools');
            this.conversationHistory.push({
              role: 'user',
              content: '',
              toolResults,
            });
            this.iterationLog.push(logEntry);
            // Signal we're exiting the loop after processing
            this.stopped = true;
            break;
          }

          // AuthWorkerAgent terminals. Both halt the loop; capture_complete
          // marks success, capture_failed marks failure. Actual CapturedAuth
          // payload is fetched separately via the agent's browser client.
          if (toolCall.name === 'capture_complete') {
            const input = toolCall.input as { summary?: string };
            stopReason = 'task_complete';
            summary = input.summary || 'Auth capture complete';
            this.captureTerminal = { kind: 'complete', input: toolCall.input as Record<string, unknown> };
            fillMissingToolResults('agent invoked capture_complete before processing remaining tools');
            this.conversationHistory.push({
              role: 'user',
              content: '',
              toolResults,
            });
            this.iterationLog.push(logEntry);
            this.stopped = true;
            break;
          }
          if (toolCall.name === 'capture_failed') {
            const input = toolCall.input as { reason?: string; detail?: string };
            stopReason = 'blocker';
            summary = `Auth capture failed (${input.reason || 'unknown'}): ${input.detail || ''}`;
            this.captureTerminal = { kind: 'failed', input: toolCall.input as Record<string, unknown> };
            fillMissingToolResults('agent invoked capture_failed before processing remaining tools');
            this.conversationHistory.push({
              role: 'user',
              content: '',
              toolResults,
            });
            this.iterationLog.push(logEntry);
            this.stopped = true;
            break;
          }
        }

        if (this.killed || this.stopped) break;

        // Send tool results back to the model
        this.conversationHistory.push({
          role: 'user',
          content: '',
          toolResults,
        });

      } catch (error) {
        const errMsg = error instanceof Error ? error.message : String(error);
        logEntry.error = errMsg;

        this.emitStatus('error', `Error: ${errMsg}`, iteration);

        // P1-1 v7: If we already pushed an assistant message with tool_use
        // blocks (line ~494) and a throw landed us here, those tool_use_ids
        // need tool_result fulfillments — otherwise the next API call 400s
        // with "tool_use_id X is missing tool_result". Inspect the last
        // assistant message; if it contains unfulfilled tool_use blocks,
        // emit error tool_results for each AND fold the diagnostic into one
        // of them instead of pushing a separate plain-text user message
        // (which would break tool_use/tool_result pairing).
        const lastMsg = this.conversationHistory[this.conversationHistory.length - 1];
        const lastWasAssistantWithToolUse = lastMsg
          && lastMsg.role === 'assistant'
          && Array.isArray(lastMsg.content)
          && lastMsg.content.some(b => b.type === 'tool_use');

        if (lastWasAssistantWithToolUse && Array.isArray(lastMsg.content)) {
          const toolResults: ToolResultBlock[] = [];
          for (const block of lastMsg.content) {
            if (block.type === 'tool_use') {
              toolResults.push({
                type: 'tool_result',
                tool_use_id: block.id,
                content: `Tool execution failed: ${errMsg}. Please adjust your approach and continue.`,
                is_error: true,
              });
            }
          }
          this.conversationHistory.push({
            role: 'user',
            content: '',
            toolResults,
          });
        } else {
          // No tool_use to fulfill — safe to push a plain-text user message
          this.conversationHistory.push({
            role: 'user',
            content: `Error occurred: ${errMsg}. Please adjust your approach and continue.`,
          });
        }

        // Push logEntry BEFORE checking recent errors so it's included in the count
        this.iterationLog.push(logEntry);

        // P1-1 v7: bumped 5→10 after the orphan-tool_use bug caused
        // cascades that tripped the old threshold on the FIRST few
        // iterations of a challenge. Now that orphan tool_use is fixed,
        // remaining errors are likely transient (rate limit, network),
        // and 10 in 60s is still a hard wall against runaway loops.
        // Stop after 10 errors within a 60-second window (not all-time consecutive)
        const errorWindowMs = 60_000;
        const now = Date.now();
        const recentErrors = this.iterationLog.filter(
          l => l.error && (now - l.timestamp) < errorWindowMs
        );
        if (recentErrors.length >= 10) {
          stopReason = 'error';
          summary = `Stopped after 5 errors within 60s window. Last error: ${errMsg}`;
          break;
        }
        continue; // Skip the push at the end of the loop
      }

      this.iterationLog.push(logEntry);
    }

    // Generate continuation context if we hit iteration limit
    let continuationContext: string | undefined;
    let continuationHandoff: ContinuationHandoff | undefined;
    if (stopReason === 'iteration_limit') {
      continuationHandoff = this.buildContinuationHandoff();
      continuationContext = this.generateContinuationContext(continuationHandoff);
      summary = `Reached iteration limit (${this.maxIterations}). ${this.findings.length} findings so far.`;
    }

    this.emitStatus('complete', summary || 'Loop complete', this.iterationLog.length);

    // Clean up browser resources if any browser tools were used
    await this.cleanupBrowser();

    // Recon agents rarely emit findings — they build an attack-surface map for
    // specialists to consume. If recon burned its iteration budget but produced
    // meaningful work (≥3 tool calls), treat that as success so the orchestrator
    // gate (orchestrator_engine.ts:2358) fires and generateSolverTasks runs.
    // Threshold is 3 (not 5) because sparse targets still yield useful observations.
    // We intentionally do NOT mutate stopReason — keep 'iteration_limit' as
    // accurate log ground truth for debugging.
    const reconSuccess =
      this.config.agentType === 'recon'
      && this.toolCallCount >= 3
      && stopReason === 'iteration_limit';

    return {
      success:
        this.findings.length > 0
        || stopReason === 'task_complete'
        || stopReason === 'no_vulnerabilities'
        || reconSuccess,
      captureTerminal: this.captureTerminal ?? undefined,
      capturedAuth: this.capturedAuth ?? undefined,
      findings: this.findings,
      totalIterations: this.iterationLog.length,
      toolCallCount: this.toolCallCount,
      httpRequestCount: this.httpRequestCount,
      totalTokensUsed: this.totalTokens,
      duration: Date.now() - startTime,
      stopReason,
      summary: summary || `Completed ${this.iterationLog.length} iterations with ${this.findings.length} findings`,
      iterationLog: this.iterationLog,
      httpExchanges: this.httpExchanges,
      continuationContext,
      continuationHandoff,
    };
  }

  /** Process a single tool call from the model */
  private async processToolCall(
    toolCall: ToolUseBlock,
    iteration: number
  ): Promise<ToolResultBlock> {
    const { name, input, id } = toolCall;

    switch (name) {
      case 'execute_command':
        return this.handleExecuteCommand(id, input as {
          command: string;
          target: string;
          reasoning: string;
          category: string;
          timeout_seconds?: number;
        }, iteration);

      case 'report_finding':
        return this.handleReportFinding(id, input as {
          title: string;
          vulnerability_type: string;
          severity: string;
          target: string;
          description: string;
          evidence: string[];
          reproduction_steps: string[];
          impact: string;
          confidence: number;
        }, iteration);

      case 'request_specialist':
        return this.handleRequestSpecialist(id, input as {
          agent_type: string;
          target: string;
          context: string;
          priority: string;
        });

      case 'write_script':
        return this.handleWriteScript(id, input as {
          language: string;
          code: string;
          purpose: string;
          target: string;
        }, iteration);

      case 'analyze_response':
        return this.handleAnalyzeResponse(id, input as {
          data: string;
          analysis_type: string;
          looking_for: string;
        });

      case 'http_request':
        return this.handleHttpRequest(id, input as {
          url: string;
          method: string;
          headers?: Record<string, string>;
          body?: string;
          follow_redirects?: boolean;
          timeout_ms?: number;
        }, iteration);

      case 'fuzz_parameter':
        return this.handleFuzzParameter(id, input as {
          url: string;
          method: string;
          parameter_name: string;
          parameter_location?: string;
          vuln_type: string;
          content_type?: string;
          max_payloads?: number;
        }, iteration);

      case 'race_test':
        return this.handleRaceTest(id, input as {
          url: string;
          method: string;
          headers?: Record<string, string>;
          body?: string;
          concurrency: number;
        }, iteration);

      case 'browser_navigate':
        return this.handleBrowserNavigate(id, input as {
          url: string;
          wait_ms?: number;
        }, iteration);

      case 'browser_evaluate':
        return this.handleBrowserEvaluate(id, input as {
          expression: string;
        });

      case 'browser_click':
        return this.handleBrowserClick(id, input as {
          selector: string;
          wait_ms?: number;
        });

      case 'browser_fill':
        return this.handleBrowserFill(id, input as {
          selector: string;
          value: string;
          wait_ms?: number;
        });

      case 'browser_get_content':
        return this.handleBrowserGetContent(id, input as {
          include_cookies?: boolean;
        });

      case 'browser_start_auth_capture':
        return this.handleBrowserStartAuthCapture(id, input as {
          scope_domains: string[];
        });

      case 'browser_finish_auth_capture':
        return this.handleBrowserFinishAuthCapture(id);

      case 'stop_hunting':
        return {
          type: 'tool_result',
          tool_use_id: id,
          content: 'Acknowledged. Stopping hunting.',
        };

      case 'capture_complete':
        return {
          type: 'tool_result',
          tool_use_id: id,
          content: 'Acknowledged. Auth capture complete — halting loop.',
        };

      case 'capture_failed':
        return {
          type: 'tool_result',
          tool_use_id: id,
          content: 'Acknowledged. Auth capture failed — halting loop.',
        };

      default:
        return {
          type: 'tool_result',
          tool_use_id: id,
          content: `Unknown tool: ${name}`,
          is_error: true,
        };
    }
  }

  /** Handle execute_command tool call */
  private async handleExecuteCommand(
    toolUseId: string,
    input: { command: string; target: string; reasoning: string; category: string; timeout_seconds?: number },
    iteration: number
  ): Promise<ToolResultBlock> {
    // ── VALIDATE: Safety policies ──
    const safetyCheck = checkSafetyPolicies(input.command, input.target, input.category);

    if (!safetyCheck.allowed) {
      const violations = safetyCheck.violations
        .filter(v => v.severity === 'block')
        .map(v => `[BLOCKED] ${v.description}`)
        .join('\n');

      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Command blocked by safety policies:\n${violations}\n\nAdjust your command and try again.`,
        is_error: true,
      };
    }

    const commandToExecute = safetyCheck.sanitizedCommand || input.command;

    // ── SCOPE CHECK: Validate target is in-scope before execution ──
    const targetFromCommand = extractTargetFromCommand(commandToExecute, input.target);
    if (targetFromCommand) {
      try {
        const inScope = await invoke<boolean>('validate_target', { target: targetFromCommand });
        if (!inScope) {
          return {
            type: 'tool_result',
            tool_use_id: toolUseId,
            content: `BLOCKED: Target "${targetFromCommand}" is not in scope. Only in-scope targets may be tested.`,
            is_error: true,
          };
        }
      } catch {
        // If Tauri bridge unavailable (e.g. test environment), log and continue
      }
    }

    this.emitStatus(
      'executing',
      `Executing: ${commandToExecute.substring(0, 100)}...`,
      iteration
    );

    // ── APPROVE: Route through approval gate ──
    if (this.config.onApprovalRequest) {
      const isSafeCategory = input.category === 'recon' || input.category === 'utility';
      const shouldAutoApprove = this.config.autoApproveSafe && isSafeCategory;

      if (!shouldAutoApprove) {
        const approved = await this.config.onApprovalRequest({
          command: commandToExecute,
          target: input.target,
          reasoning: input.reasoning,
          category: input.category,
          toolName: commandToExecute.split(/\s+/)[0],
          safetyWarnings: safetyCheck.warnings,
        });

        if (!approved) {
          return {
            type: 'tool_result',
            tool_use_id: toolUseId,
            content: 'Command was denied by the user. Try a different approach or ask for guidance.',
            is_error: true,
          };
        }
      }
    }

    // ── EXECUTE: Run via PTY ──
    if (!this.config.onExecuteCommand) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'Command execution is not configured. Running in simulation mode.',
        is_error: true,
      };
    }

    const timeoutMs = (input.timeout_seconds ?? 30) * 1000;
    let result: Awaited<ReturnType<NonNullable<typeof this.config.onExecuteCommand>>>;
    try {
      result = await Promise.race([
        this.config.onExecuteCommand(commandToExecute, input.target),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error(`Command timed out after ${input.timeout_seconds ?? 30}s`)), timeoutMs)
        ),
      ]);
    } catch (error) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Command execution failed: ${error instanceof Error ? error.message : String(error)}`,
        is_error: true,
      };
    }

    if (result.blocked) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Command blocked: ${result.blockReason}`,
        is_error: true,
      };
    }

    // Count successful command execution toward hallucination gate —
    // agents interact with targets via execute_command (curl, httpx, subfinder, etc.)
    this.httpRequestCount++;

    // ── OBSERVE: Parse structured output and return to model ──
    const rawOutput = result.stdout || '';
    const rawStderr = result.stderr || '';

    // Detect tool name from command (first argv element, strip path prefix)
    const toolBinary = commandToExecute.split(/\s+/)[0].split('/').pop() || '';

    // Parse structured output via registered parsers
    const parsed = parseToolOutput(toolBinary, rawOutput, rawStderr);
    const parsedFindings = extractFindings(parsed);
    const discoveredTargets = extractTargets(parsed);

    // Build structured summary for the model (saves tokens vs raw output)
    const summaryParts: string[] = [];
    summaryParts.push(`Exit code: ${result.exitCode}`);
    summaryParts.push(`Execution time: ${result.executionTimeMs}ms`);

    if (safetyCheck.warnings.length > 0) {
      summaryParts.push(`Safety warnings: ${safetyCheck.warnings.join(', ')}`);
    }

    // Structured summary from parser
    if (parsed.entries.length > 0) {
      const entryCounts = new Map<string, number>();
      for (const entry of parsed.entries) {
        entryCounts.set(entry.type, (entryCounts.get(entry.type) || 0) + 1);
      }
      const countSummary = Array.from(entryCounts.entries())
        .map(([type, count]) => `${count} ${type}${count > 1 ? 's' : ''}`)
        .join(', ');
      summaryParts.push(`\n## Parsed Results (${parsed.toolName})\nFound: ${countSummary}`);
    }

    // Findings summary
    if (parsedFindings.length > 0) {
      summaryParts.push(`\n## Findings (${parsedFindings.length})`);
      for (const f of parsedFindings) {
        summaryParts.push(`- [${f.severity.toUpperCase()}] ${f.title} — ${f.target}`);
      }

      // Auto-report medium+ findings via onFinding callback
      for (const f of parsedFindings) {
        if (f.severity === 'medium' || f.severity === 'high' || f.severity === 'critical') {
          const autoFinding: ReactFinding = {
            id: `finding_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
            title: f.title,
            vulnerabilityType: f.severity === 'critical' ? 'rce' : 'other',
            severity: f.severity,
            target: f.target,
            description: f.description,
            evidence: [f.evidence],
            reproductionSteps: [`Run: ${commandToExecute}`, `Observe: ${f.title}`],
            impact: f.description,
            confidence: f.severity === 'critical' ? 70 : 50,
            discoveredAtIteration: iteration,
            agentId: 'react_loop_auto',
          };
          this.findings.push(autoFinding);
          this.emitStatus('finding', `[AUTO] [${f.severity.toUpperCase()}] ${f.title}`, iteration);
          if (this.config.onFinding) {
            this.config.onFinding(autoFinding);
          }
        }
      }
    }

    // Discovered targets for chaining
    if (discoveredTargets.length > 0) {
      const displayTargets = discoveredTargets.slice(0, 50);
      summaryParts.push(`\n## Discovered Targets (${discoveredTargets.length})`);
      summaryParts.push(displayTargets.join('\n'));
      if (discoveredTargets.length > 50) {
        summaryParts.push(`... and ${discoveredTargets.length - 50} more`);
      }
    }

    // Append truncated raw output for context the parser may have missed.
    // Scrub auth secrets (bearer tokens, Cookie headers, session env vars) out
    // of tool output before emitting to the LLM — agents shouldn't see raw
    // tokens even when their own tools echoed them. (Phase 1 / Q1)
    let rawSection = '';
    if (rawOutput) {
      const MAX_RAW_LENGTH = 8000;
      const scrubbed = scrubAuthSecrets(rawOutput);
      if (scrubbed.length > MAX_RAW_LENGTH) {
        rawSection = `\n\n## Raw Output (truncated)\n${scrubbed.substring(0, MAX_RAW_LENGTH)}\n[TRUNCATED - ${scrubbed.length} total chars]`;
      } else {
        rawSection = `\n\n## Raw Output\n${scrubbed}`;
      }
    }
    if (rawStderr && !result.success) {
      rawSection += `\n\nSTDERR:\n${scrubAuthSecrets(rawStderr).substring(0, 2000)}`;
    }

    return {
      type: 'tool_result',
      tool_use_id: toolUseId,
      content: summaryParts.join('\n') + rawSection,
    };
  }

  /** Handle report_finding tool call — includes hallucination gate */
  private async handleReportFinding(
    toolUseId: string,
    input: {
      title: string;
      vulnerability_type: string;
      severity: string;
      target: string;
      description: string;
      evidence: string[];
      reproduction_steps: string[];
      impact: string;
      confidence: number;
    },
    iteration: number
  ): Promise<ToolResultBlock> {
    // ── Hallucination Gate (H22) ──
    // Reject findings from agents that haven't done real HTTP work against the
    // target. An agent must make >= 3 HTTP-related tool calls (http_request,
    // successful execute_command, or fuzz_parameter) before any finding is
    // accepted. This prevents the Hunt #7 scenario where the OAuth Hunter
    // reported 585 "findings" after 0 HTTP interactions.
    const minHttp = ReactLoop.MIN_HTTP_REQUESTS_FOR_FINDING;
    if (this.httpRequestCount < minHttp) {
      console.warn(
        `[hallucination-gate] Finding rejected: "${input.title}" reported after only ` +
        `${this.httpRequestCount} HTTP requests at iteration ${iteration} ` +
        `(minimum ${minHttp} HTTP interactions required). Agent must perform real testing before reporting.`
      );
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Finding rejected: you have only made ${this.httpRequestCount} HTTP requests ` +
          `(minimum ${minHttp} required). You must actually test the target with HTTP requests ` +
          `before reporting vulnerabilities. Continue testing, then re-report with real evidence.`,
        is_error: true,
      };
    }

    // ── Severity Calibration Gate (C2) ──
    // Catch known over-escalation patterns before the finding enters the pipeline.
    // Applied after hallucination gate, before finding creation.
    const calibration = ReactLoop.checkSeverityCalibration(
      input.severity,
      input.vulnerability_type,
      input.title,
      input.description,
      input.evidence
    );
    const calibratedSeverity = calibration.correctedSeverity;
    const calibrationNote = calibration.note;

    const finding: ReactFinding = {
      id: `finding_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
      title: input.title,
      vulnerabilityType: input.vulnerability_type,
      severity: calibratedSeverity as ReactFinding['severity'],
      target: input.target,
      description: calibrationNote
        ? `${input.description}\n\n[Severity calibrated: ${input.severity} → ${calibratedSeverity}. ${calibrationNote}]`
        : input.description,
      evidence: input.evidence,
      reproductionSteps: input.reproduction_steps,
      impact: input.impact,
      confidence: input.confidence,
      discoveredAtIteration: iteration,
      agentId: 'react_loop',
    };

    this.findings.push(finding);

    this.emitStatus(
      'finding',
      `[${input.severity.toUpperCase()}] ${input.title}`,
      iteration
    );

    if (this.config.onFinding) {
      this.config.onFinding(finding);
    }

    return {
      type: 'tool_result',
      tool_use_id: toolUseId,
      content: `Finding recorded: ${finding.id}\nTitle: ${finding.title}\nSeverity: ${finding.severity}\nConfidence: ${finding.confidence}%\n\nThis finding will be validated through the deterministic validation pipeline. Continue testing for additional vulnerabilities.`,
    };
  }

  /** Handle request_specialist tool call */
  private async handleRequestSpecialist(
    toolUseId: string,
    input: { agent_type: string; target: string; context: string; priority: string }
  ): Promise<ToolResultBlock> {
    if (this.config.onSpecialistRequest) {
      this.config.onSpecialistRequest({
        agentType: input.agent_type,
        target: input.target,
        context: input.context,
        priority: input.priority,
      });
    }

    return {
      type: 'tool_result',
      tool_use_id: toolUseId,
      content: `Specialist request submitted: ${input.agent_type} agent for ${input.target} (priority: ${input.priority}). The orchestrator will dispatch this agent. Continue with your current task.`,
    };
  }

  /** Handle write_script tool call */
  private async handleWriteScript(
    toolUseId: string,
    input: { language: string; code: string; purpose: string; target: string },
    iteration: number
  ): Promise<ToolResultBlock> {
    // Validate script safety
    const safetyCheck = checkSafetyPolicies(input.code, input.target, 'active_testing');
    if (!safetyCheck.allowed) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Script blocked by safety policies: ${safetyCheck.violations.map(v => v.description).join(', ')}`,
        is_error: true,
      };
    }

    // Route through approval
    if (this.config.onApprovalRequest) {
      const approved = await this.config.onApprovalRequest({
        command: `[${input.language} script] ${input.purpose}`,
        target: input.target,
        reasoning: input.purpose,
        category: 'active_testing',
        toolName: input.language,
        safetyWarnings: safetyCheck.warnings,
      });

      if (!approved) {
        return {
          type: 'tool_result',
          tool_use_id: toolUseId,
          content: 'Script execution denied by user.',
          is_error: true,
        };
      }
    }

    // Execute script via command
    const interpreters: Record<string, string> = {
      python: 'python3 -c',
      bash: 'bash -c',
      javascript: 'node -e',
    };

    const interpreter = interpreters[input.language];
    if (!interpreter && this.config.onExecuteCommand) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Unsupported script language: ${input.language}. Use python, bash, or javascript.`,
        is_error: true,
      };
    }

    if (this.config.onExecuteCommand) {
      // Write script to temp file via Tauri IPC (avoids shell heredoc injection)
      const ext = input.language === 'python' ? 'py' : input.language === 'bash' ? 'sh' : 'js';
      const randomSuffix = Array.from(crypto.getRandomValues(new Uint8Array(8)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
      const scriptPath = `/tmp/huntress_script_${randomSuffix}.${ext}`;

      // Write file safely via Tauri command, then execute
      let writeResult: CommandResult;
      try {
        const { invoke } = await import('@tauri-apps/api/core');
        await invoke('write_file_text', { path: scriptPath, contents: input.code });
        writeResult = { success: true, stdout: '', stderr: '', exitCode: 0, executionTimeMs: 0 };
      } catch (writeErr) {
        // Fallback: execute via printf to avoid heredoc injection
        const escaped = input.code.replace(/'/g, "'\\''");
        writeResult = await this.config.onExecuteCommand(
          `printf '%s' '${escaped}' > ${scriptPath}`,
          input.target
        );
      }

      if (!writeResult.success) {
        return {
          type: 'tool_result',
          tool_use_id: toolUseId,
          content: `Failed to write script: ${writeResult.stderr}`,
          is_error: true,
        };
      }

      const execCmd = input.language === 'python' ? `python3 ${scriptPath}`
        : input.language === 'bash' ? `bash ${scriptPath}`
        : `node ${scriptPath}`;

      const result = await this.config.onExecuteCommand(execCmd, input.target);

      // Cleanup
      await this.config.onExecuteCommand(`rm -f ${scriptPath}`, input.target).catch(() => {});

      let output = result.stdout || '';
      if (result.stderr) output += `\nSTDERR: ${result.stderr}`;

      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Script executed (exit code: ${result.exitCode}):\n${output || '(no output)'}`,
      };
    }

    return {
      type: 'tool_result',
      tool_use_id: toolUseId,
      content: 'Script execution not configured.',
      is_error: true,
    };
  }

  /** Handle analyze_response — this is a "thinking" tool, no execution needed */
  private async handleAnalyzeResponse(
    toolUseId: string,
    input: { data: string; analysis_type: string; looking_for: string }
  ): Promise<ToolResultBlock> {
    // The model calling this tool is essentially asking itself to analyze data.
    // We return the data back so it can reason about it in the next turn.
    return {
      type: 'tool_result',
      tool_use_id: toolUseId,
      content: `Analysis type: ${input.analysis_type}\nLooking for: ${input.looking_for}\n\nData to analyze:\n${input.data.substring(0, 10000)}\n\nProceed with your analysis in your next response.`,
    };
  }

  /**
   * Prune conversation history to prevent context window overflow.
   * Keeps the first message (goal) and the most recent messages,
   * summarizing discarded middle messages.
   */
  private manageContextWindow(): void {
    if (this.conversationHistory.length <= ReactLoop.MAX_CONTEXT_MESSAGES) return;

    // Keep the first message (goal/task definition) and recent messages
    const firstMessage = this.conversationHistory[0];
    const recentMessages = this.conversationHistory.slice(-ReactLoop.MAX_CONTEXT_MESSAGES + 2);

    // Summarize what was pruned
    const prunedCount = this.conversationHistory.length - recentMessages.length - 1;
    const summaryMessage: ChatMessage = {
      role: 'user',
      content: `[Context pruned: ${prunedCount} earlier messages removed to stay within context limits. Key findings so far: ${this.findings.length} findings discovered. Continue with the task.]`,
    };

    this.conversationHistory = [firstMessage, summaryMessage, ...recentMessages];
  }

  /** Check if a URL's hostname is within the configured scope */
  private isUrlInScope(url: string): { inScope: boolean; hostname: string } {
    let hostname: string;
    try {
      const parsed = new URL(url);
      hostname = parsed.hostname.toLowerCase();
    } catch {
      return { inScope: false, hostname: url };
    }

    // Check against scope entries (normalize: lowercase, strip port/whitespace)
    for (const rawEntry of this.config.scope) {
      const entry = rawEntry.trim().toLowerCase();
      // Extract hostname from scope entry (strip port if present)
      let scopeHost: string;
      if (entry.startsWith('*.')) {
        scopeHost = entry.slice(2);
      } else {
        try {
          scopeHost = new URL(
            entry.startsWith('http') ? entry : `https://${entry}`
          ).hostname;
        } catch {
          scopeHost = entry.split(':')[0];
        }
      }

      // Exact match
      if (hostname === scopeHost) return { inScope: true, hostname };
      // Wildcard match: *.example.com should match sub.example.com
      if (entry.startsWith('*.')) {
        if (hostname === scopeHost || hostname.endsWith(`.${scopeHost}`)) {
          return { inScope: true, hostname };
        }
      }
    }

    return { inScope: false, hostname };
  }

  /** Handle http_request tool call — direct HTTP via HttpClient */
  private async handleHttpRequest(
    toolUseId: string,
    input: {
      url: string;
      method: string;
      headers?: Record<string, string>;
      body?: string;
      follow_redirects?: boolean;
      timeout_ms?: number;
      session_label?: string;
    },
    iteration: number
  ): Promise<ToolResultBlock> {
    if (!this.config.httpClient) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'HTTP client not configured. Use execute_command with curl instead.',
        is_error: true,
      };
    }

    // Scope validation — Block 7
    const scopeCheck = this.isUrlInScope(input.url);
    if (!scopeCheck.inScope) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Blocked: ${scopeCheck.hostname} is not in scope. Only targets within the defined scope can be accessed.`,
        is_error: true,
      };
    }

    // Count toward hallucination gate — this is real HTTP interaction with the target
    this.httpRequestCount++;

    this.emitStatus(
      'executing',
      `HTTP ${input.method} ${input.url.substring(0, 80)}...`,
      iteration
    );

    try {
      let options: HttpRequestOptions = {
        url: input.url,
        method: input.method.toUpperCase() as HttpRequestOptions['method'],
        headers: input.headers,
        body: input.body,
        followRedirects: input.follow_redirects,
        timeoutMs: input.timeout_ms,
      };

      // Q3: Resolve `session_label` to a specific sessionId for multi-identity
      // testing (IDOR/BOLA). An explicit label that doesn't match ANY active
      // session is an error — silent fallback to the default would invalidate
      // the proof the agent was trying to build.
      let effectiveSessionId = this.config.authSessionId;
      if (input.session_label) {
        if (!this.config.sessionManager) {
          return {
            type: 'tool_result',
            tool_use_id: toolUseId,
            content: `session_label "${input.session_label}" requested but no session manager is configured for this agent.`,
            is_error: true,
          };
        }
        const resolved = this.config.sessionManager.findByLabel(input.session_label);
        if (!resolved) {
          const available = this.config.sessionManager.listSessions().map(s => s.label).join(', ');
          return {
            type: 'tool_result',
            tool_use_id: toolUseId,
            content: `Unknown session_label "${input.session_label}". Available labels: ${available || '(none)'}.`,
            is_error: true,
          };
        }
        effectiveSessionId = resolved;
      }

      // S7: Proactive token refresh — check before each request to prevent 401s
      let response: HttpResponse;
      let resolvedLabel: string | undefined;
      if (effectiveSessionId && this.config.sessionManager) {
        const session = this.config.sessionManager.getSession(effectiveSessionId);
        resolvedLabel = session?.label;
        if (session && this.config.sessionManager.getTokenRefresher().needsRefresh(session)) {
          await this.config.sessionManager.refreshSession(effectiveSessionId);
        }

        // S7: Use authenticatedRequest() for 401 auto-retry (replaces S4 direct call)
        response = await this.config.sessionManager.authenticatedRequest(
          effectiveSessionId,
          options,
        );
      } else {
        response = await this.config.httpClient.request(options);
      }

      // Capture structured HTTP exchange for report evidence (RQ1).
      // sessionLabel lets findings show which identity was used — makes IDOR
      // proofs self-auditing (Phase 1 / Q3).
      if (this.httpExchanges.length < ReactLoop.MAX_HTTP_EXCHANGES) {
        const BODY_SNIPPET_LIMIT = 2000;
        const exchange: HttpExchange = {
          request: {
            method: input.method.toUpperCase(),
            url: input.url,
            headers: input.headers,
            body: input.body,
          },
          response: {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
            bodySnippet: response.body.length > BODY_SNIPPET_LIMIT
              ? response.body.substring(0, BODY_SNIPPET_LIMIT) + `\n[TRUNCATED — ${response.body.length} bytes total]`
              : response.body,
          },
          iteration,
          timestamp: Date.now(),
          sessionLabel: resolvedLabel,
        };
        this.httpExchanges.push(exchange);
      }

      // Truncate large response bodies for the model context
      const MAX_BODY_FOR_MODEL = 15000;
      let bodyForModel = response.body;
      if (bodyForModel.length > MAX_BODY_FOR_MODEL) {
        bodyForModel = bodyForModel.substring(0, MAX_BODY_FOR_MODEL) +
          `\n\n[BODY TRUNCATED — ${response.size} bytes total]`;
      }

      const headerLines = Object.entries(response.headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n');

      const redirectInfo = response.redirectChain.length > 0
        ? `\nRedirect chain:\n${response.redirectChain.map(r => `  ${r.status} → ${r.url}`).join('\n')}\n`
        : '';

      const cookieInfo = response.cookies.length > 0
        ? `\nCookies: ${response.cookies.map(c => `${c.name}=${c.value.substring(0, 50)}`).join('; ')}\n`
        : '';

      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `HTTP ${response.status} ${response.statusText} (${response.timing.totalMs}ms, ${response.size} bytes)${redirectInfo}${cookieInfo}\nHeaders:\n${headerLines}\n\nBody:\n${bodyForModel}`,
      };
    } catch (error) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `HTTP request failed: ${error instanceof Error ? error.message : String(error)}`,
        is_error: true,
      };
    }
  }

  /** Handle fuzz_parameter tool call — systematic parameter fuzzing */
  private async handleFuzzParameter(
    toolUseId: string,
    input: {
      url: string;
      method: string;
      parameter_name: string;
      parameter_location?: string;
      vuln_type: string;
      content_type?: string;
      max_payloads?: number;
    },
    iteration: number
  ): Promise<ToolResultBlock> {
    if (!this.config.httpClient) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'HTTP client not configured. Cannot run fuzzer without direct HTTP access.',
        is_error: true,
      };
    }

    // Scope validation — Block 7
    const scopeCheck = this.isUrlInScope(input.url);
    if (!scopeCheck.inScope) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Blocked: ${scopeCheck.hostname} is not in scope. Only targets within the defined scope can be fuzzed.`,
        is_error: true,
      };
    }

    // Count toward hallucination gate — fuzzing sends real HTTP requests to the target
    this.httpRequestCount++;

    this.emitStatus(
      'executing',
      `Fuzzing ${input.parameter_name} for ${input.vuln_type} on ${input.url.substring(0, 60)}...`,
      iteration
    );

    try {
      const fuzzer = new ParamFuzzer();
      const result = await fuzzer.fuzz({
        url: input.url,
        method: input.method,
        parameterName: input.parameter_name,
        parameterLocation: (input.parameter_location ?? 'query') as 'query' | 'body' | 'header' | 'cookie' | 'path',
        vulnType: input.vuln_type as VulnType,
        contentType: input.content_type as 'form' | 'json' | 'xml' | 'multipart' | undefined,
        maxPayloads: input.max_payloads,
        httpClient: this.config.httpClient,
      });

      const hitSummary = result.hits.length > 0
        ? result.hits.map(h =>
            `  [${(h.confidence * 100).toFixed(0)}%] ${h.vulnType}: ${h.evidence} (payload: ${h.payload.substring(0, 80)})`
          ).join('\n')
        : '  No confirmed hits';

      const errorSummary = result.errors.length > 0
        ? `\nErrors (${result.errors.length}):\n${result.errors.slice(0, 5).map(e => `  - ${e}`).join('\n')}`
        : '';

      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Fuzz results for ${input.parameter_name} (${input.vuln_type}):\n` +
          `Payloads tested: ${result.totalPayloadsTested}\n` +
          `Requests made: ${result.totalRequestsMade}\n` +
          `Duration: ${result.durationMs}ms\n` +
          `Hits: ${result.hits.length}\n\n` +
          `${hitSummary}${errorSummary}`,
      };
    } catch (error) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Fuzzer error: ${error instanceof Error ? error.message : String(error)}`,
        is_error: true,
      };
    }
  }

  /** Handle race_test tool call — send N identical requests simultaneously */
  private async handleRaceTest(
    toolUseId: string,
    input: {
      url: string;
      method: string;
      headers?: Record<string, string>;
      body?: string;
      concurrency: number;
    },
    iteration: number
  ): Promise<ToolResultBlock> {
    if (!this.config.httpClient) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'HTTP client not configured. Cannot run race test without direct HTTP access.',
        is_error: true,
      };
    }

    // Scope validation — Block 7
    const scopeCheck = this.isUrlInScope(input.url);
    if (!scopeCheck.inScope) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Blocked: ${scopeCheck.hostname} is not in scope. Only targets within the defined scope can be race-tested.`,
        is_error: true,
      };
    }

    // Clamp concurrency to safe range
    const concurrency = Math.max(2, Math.min(50, input.concurrency));

    this.emitStatus(
      'executing',
      `Race test: ${concurrency}x ${input.method} ${input.url.substring(0, 60)}...`,
      iteration
    );

    try {
      const requestOptions: HttpRequestOptions = {
        url: input.url,
        method: input.method.toUpperCase() as HttpRequestOptions['method'],
        headers: input.headers,
        body: input.body,
        followRedirects: false,
        timeoutMs: 30000,
      };

      // Fire all requests simultaneously
      const startMs = performance.now();
      const promises = Array.from({ length: concurrency }, () =>
        this.config.httpClient!.request(requestOptions).catch((err: Error) => ({
          status: 0,
          statusText: `Error: ${err.message}`,
          headers: {} as Record<string, string>,
          body: '',
          size: 0,
          timing: { dnsMs: 0, connectMs: 0, tlsMs: 0, ttfbMs: 0, downloadMs: 0, totalMs: 0 },
          redirectChain: [] as Array<{ url: string; status: number }>,
          cookies: [] as Array<{ name: string; value: string; domain?: string; path?: string }>,
        }))
      );

      const responses = await Promise.all(promises);
      const totalMs = performance.now() - startMs;

      // Analyze responses for race condition indicators
      const statusCodes = responses.map(r => r.status);
      const bodySizes = responses.map(r => r.size);
      const statusGroups: Record<number, number> = {};
      for (const code of statusCodes) {
        statusGroups[code] = (statusGroups[code] ?? 0) + 1;
      }

      // Check for differential responses (key indicator of race condition)
      const uniqueStatuses = new Set(statusCodes).size;
      const uniqueBodies = new Set(responses.map(r => r.body.substring(0, 500))).size;

      // Extract key fields from JSON response bodies for comparison
      const jsonFields: string[] = [];
      for (const r of responses) {
        try {
          const parsed = JSON.parse(r.body);
          // Look for common fields that change during races
          const interesting = ['id', 'balance', 'amount', 'count', 'quantity', 'status', 'message'];
          for (const field of interesting) {
            if (field in parsed) {
              jsonFields.push(`${field}=${JSON.stringify(parsed[field])}`);
            }
          }
        } catch { /* not JSON */ }
      }
      const uniqueJsonFields = new Set(jsonFields);

      // Build summary
      const statusSummary = Object.entries(statusGroups)
        .map(([code, count]) => `${code}: ${count}x`)
        .join(', ');

      const sizeSummary = `min=${Math.min(...bodySizes)}, max=${Math.max(...bodySizes)}, unique=${new Set(bodySizes).size}`;

      let raceIndicator = 'NONE';
      if (uniqueStatuses > 1) {
        raceIndicator = 'STATUS_DIVERGENCE';
      } else if (uniqueBodies > 1) {
        raceIndicator = 'BODY_DIVERGENCE';
      } else if (uniqueJsonFields.size > responses.length) {
        raceIndicator = 'FIELD_DIVERGENCE';
      }

      // Build detailed response table (first 10 responses)
      const responseTable = responses.slice(0, 10).map((r, i) =>
        `  [${i + 1}] ${r.status} ${r.statusText} (${r.size}b, ${r.timing.totalMs.toFixed(0)}ms) body_hash=${hashString(r.body.substring(0, 500))}`
      ).join('\n');

      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content:
          `Race test: ${concurrency}x ${input.method} ${input.url}\n` +
          `Total time: ${totalMs.toFixed(0)}ms\n\n` +
          `Status codes: ${statusSummary}\n` +
          `Body sizes: ${sizeSummary}\n` +
          `Unique status codes: ${uniqueStatuses}\n` +
          `Unique response bodies: ${uniqueBodies}\n` +
          `Race indicator: ${raceIndicator}\n\n` +
          `Responses:\n${responseTable}` +
          (jsonFields.length > 0 ? `\n\nJSON field values: ${[...uniqueJsonFields].join(', ')}` : ''),
      };
    } catch (error) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Race test error: ${error instanceof Error ? error.message : String(error)}`,
        is_error: true,
      };
    }
  }

  // ─── Browser Tool Handlers ──────────────────────────────────────────────────

  /** Lazy-init the Node browser subprocess client. */
  private ensureBrowserClient(): AgentBrowserClient {
    if (!this.browserClient) {
      this.browserClient = new AgentBrowserClient();
    }
    return this.browserClient;
  }

  /** Clean up browser resources — called at end of execute(). */
  async cleanupBrowser(): Promise<void> {
    if (this.browserClient) {
      await this.browserClient.close().catch(() => {});
      this.browserClient = null;
    }
  }

  private formatDialogs(dialogs: AgentDialog[], label = 'Dialogs detected'): string {
    if (dialogs.length === 0) return '';
    return `\n${label}:\n${dialogs.map(d => `  [${d.type}] ${d.message}`).join('\n')}`;
  }

  private formatConsole(logs: AgentConsoleLog[], limit = 20): string {
    if (logs.length === 0) return '';
    return `\nConsole output (last ${limit}):\n${logs.slice(-limit).map(l => `  [${l.level}] ${l.text}`).join('\n')}`;
  }

  /** Handle browser_navigate — navigate to URL, return rendered page info */
  private async handleBrowserNavigate(
    toolUseId: string,
    input: { url: string; wait_ms?: number },
    iteration: number
  ): Promise<ToolResultBlock> {
    if (!this.config.browserEnabled) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'Browser tools are not enabled for this agent.',
        is_error: true,
      };
    }

    // Scope validation — browser must not navigate to out-of-scope domains
    const scopeCheck = this.isUrlInScope(input.url);
    if (!scopeCheck.inScope) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Blocked: ${scopeCheck.hostname} is not in scope. Browser navigation restricted to in-scope targets only.`,
        is_error: true,
      };
    }

    this.emitStatus('executing', `Browser navigating to ${input.url.substring(0, 80)}...`, iteration);

    try {
      const client = this.ensureBrowserClient();
      const result = await client.navigate(input.url, input.wait_ms);

      // Count as HTTP interaction for hallucination gate
      this.httpRequestCount++;

      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content:
          `Browser navigated to: ${result.url}\n` +
          `Title: ${result.title}\n` +
          `Content length: ${result.contentLength} bytes` +
          this.formatDialogs(result.dialogs) +
          this.formatConsole(result.consoleLogs) +
          `\n\nPage HTML:\n${result.content}`,
      };
    } catch (error) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Browser navigation failed: ${error instanceof Error ? error.message : String(error)}`,
        is_error: true,
      };
    }
  }

  /** Handle browser_evaluate — execute JavaScript in browser page context (Chromium sandbox) */
  private async handleBrowserEvaluate(
    toolUseId: string,
    input: { expression: string }
  ): Promise<ToolResultBlock> {
    if (!this.config.browserEnabled) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'Browser tools are not enabled for this agent.',
        is_error: true,
      };
    }

    if (!this.browserClient) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'No browser page active. Use browser_navigate first to load a page.',
        is_error: true,
      };
    }

    try {
      // Runs inside the Chromium renderer (browser sandbox), NOT Node host.
      // Intentional for DOM-XSS, prototype pollution, and sink testing.
      const result = await this.browserClient.evaluate(input.expression);
      const dialogInfo = this.formatDialogs(result.dialogs, 'Dialogs triggered');

      if (result.error !== undefined) {
        return {
          type: 'tool_result',
          tool_use_id: toolUseId,
          content: `JavaScript evaluation error: ${result.error}` + dialogInfo,
          is_error: true,
        };
      }

      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `JavaScript evaluation result:\n${result.value ?? 'undefined'}` + dialogInfo,
      };
    } catch (error) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Browser evaluate failed: ${error instanceof Error ? error.message : String(error)}`,
        is_error: true,
      };
    }
  }

  /** Handle browser_click — click element by CSS selector */
  private async handleBrowserClick(
    toolUseId: string,
    input: { selector: string; wait_ms?: number }
  ): Promise<ToolResultBlock> {
    if (!this.config.browserEnabled) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'Browser tools are not enabled for this agent.',
        is_error: true,
      };
    }

    if (!this.browserClient) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'No browser page active. Use browser_navigate first to load a page.',
        is_error: true,
      };
    }

    try {
      const result = await this.browserClient.click(input.selector, input.wait_ms);

      // Scope check after click — if navigation happened, verify it's still in-scope
      const postClickScope = this.isUrlInScope(result.url);
      if (!postClickScope.inScope) {
        // Navigate back — re-nav to the prior scope-approved URL is handled
        // by the model, since we do not track pre-click URL here.
        return {
          type: 'tool_result',
          tool_use_id: toolUseId,
          content: `Click caused navigation to out-of-scope URL: ${result.url}. Target ${postClickScope.hostname} is not in scope.`,
          is_error: true,
        };
      }

      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content:
          `Clicked: ${input.selector}\n` +
          `Current URL: ${result.url}\n` +
          `Title: ${result.title}` +
          this.formatDialogs(result.dialogs, 'Dialogs triggered') +
          this.formatConsole(result.consoleLogs, 10),
      };
    } catch (error) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Browser click failed: ${error instanceof Error ? error.message : String(error)}. Verify the CSS selector matches an element on the page.`,
        is_error: true,
      };
    }
  }

  /** Handle browser_fill — fill a form input with synthetic events (React/Vue/Angular-safe) */
  private async handleBrowserFill(
    toolUseId: string,
    input: { selector: string; value: string; wait_ms?: number }
  ): Promise<ToolResultBlock> {
    if (!this.config.browserEnabled) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'Browser tools are not enabled for this agent.',
        is_error: true,
      };
    }

    if (!this.browserClient) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'No browser page active. Use browser_navigate first to load a page.',
        is_error: true,
      };
    }

    try {
      const result = await this.browserClient.fill(input.selector, input.value, input.wait_ms);
      // Never echo the filled value back in the tool result — it may be a
      // credential. The scrubAuthSecrets layer also masks on log output.
      const valueLen = input.value.length;
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Filled: ${result.selector} (${valueLen} char${valueLen === 1 ? '' : 's'})`,
      };
    } catch (error) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Browser fill failed: ${error instanceof Error ? error.message : String(error)}. Verify the CSS selector matches a fillable input on the page.`,
        is_error: true,
      };
    }
  }

  /** Handle browser_start_auth_capture — begin intercepting auth headers on in-scope requests */
  private async handleBrowserStartAuthCapture(
    toolUseId: string,
    input: { scope_domains: string[] }
  ): Promise<ToolResultBlock> {
    if (!this.config.browserEnabled) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'Browser tools are not enabled for this agent.',
        is_error: true,
      };
    }
    if (!this.browserClient) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'No browser page active. Use browser_navigate first to load a page.',
        is_error: true,
      };
    }
    if (!Array.isArray(input.scope_domains) || input.scope_domains.length === 0) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'scope_domains is required and must contain at least one domain.',
        is_error: true,
      };
    }
    // Intersect requested domains with the loop's configured scope so the
    // LLM cannot widen capture beyond the hunt's authorized targets.
    const allowed = input.scope_domains.filter(d => {
      const check = this.isUrlInScope(`https://${d}`);
      return check.inScope;
    });
    if (allowed.length === 0) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `None of the requested scope_domains are in the hunt's scope (${this.config.scope.join(', ')}). Refusing to start capture.`,
        is_error: true,
      };
    }
    try {
      await this.browserClient.startAuthCapture(allowed);
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Auth header interception started for: ${allowed.join(', ')}. Now submit the login form — captured headers will be returned by browser_finish_auth_capture.`,
      };
    } catch (error) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Start auth capture failed: ${error instanceof Error ? error.message : String(error)}`,
        is_error: true,
      };
    }
  }

  /** Handle browser_finish_auth_capture — stop interception, dump storage/cookies, stash payload */
  private async handleBrowserFinishAuthCapture(toolUseId: string): Promise<ToolResultBlock> {
    if (!this.config.browserEnabled) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'Browser tools are not enabled for this agent.',
        is_error: true,
      };
    }
    if (!this.browserClient) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'No browser page active. Use browser_navigate first to load a page.',
        is_error: true,
      };
    }
    try {
      const captured = await this.browserClient.finishAuthCapture();
      // Stash for the AuthWorkerAgent to pick up via ReactLoopResult.
      this.capturedAuth = captured;
      // Summarize for the LLM WITHOUT echoing secret values back into its context.
      const bearerLen = captured.bearerToken?.length ?? 0;
      const customHeaderCount = Object.keys(captured.customHeaders ?? {}).length;
      const lsCount = Object.keys(captured.localStorage ?? {}).length;
      const ssCount = Object.keys(captured.sessionStorage ?? {}).length;
      const cookieCount = (captured.cookies ?? []).length;
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content:
          `Auth capture finished (page at ${captured.finalUrl}).\n` +
          `  • bearer token: ${bearerLen > 0 ? `yes (${bearerLen} chars, stored)` : 'no'}\n` +
          `  • custom auth headers: ${customHeaderCount}${customHeaderCount > 0 ? ` (${Object.keys(captured.customHeaders).join(', ')})` : ''}\n` +
          `  • cookies: ${cookieCount}\n` +
          `  • localStorage keys: ${lsCount}${lsCount > 0 ? ` (${Object.keys(captured.localStorage).slice(0, 5).join(', ')}${lsCount > 5 ? '…' : ''})` : ''}\n` +
          `  • sessionStorage keys: ${ssCount}\n` +
          `If this looks right, call capture_complete. If nothing useful was captured, navigate again and retry, or call capture_failed.`,
      };
    } catch (error) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Finish auth capture failed: ${error instanceof Error ? error.message : String(error)}`,
        is_error: true,
      };
    }
  }

  /** Handle browser_get_content — return current page HTML, URL, title, cookies */
  private async handleBrowserGetContent(
    toolUseId: string,
    input: { include_cookies?: boolean }
  ): Promise<ToolResultBlock> {
    if (!this.config.browserEnabled) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'Browser tools are not enabled for this agent.',
        is_error: true,
      };
    }

    if (!this.browserClient) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: 'No browser page active. Use browser_navigate first to load a page.',
        is_error: true,
      };
    }

    try {
      const result = await this.browserClient.getContent(input.include_cookies);

      let cookieInfo = '';
      if (input.include_cookies && result.cookies) {
        cookieInfo = `\n\nCookies (${result.cookies.length}):\n` +
          result.cookies.map(c =>
            `  ${c.name}=${c.value.substring(0, 80)}${c.value.length > 80 ? '...' : ''} ` +
            `(domain=${c.domain}, secure=${c.secure}, httpOnly=${c.httpOnly}${c.sameSite ? `, sameSite=${c.sameSite}` : ''})`
          ).join('\n');
      }

      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content:
          `URL: ${result.url}\n` +
          `Title: ${result.title}\n` +
          `Content length: ${result.contentLength} bytes` +
          cookieInfo +
          `\n\nPage HTML:\n${result.content}`,
      };
    } catch (error) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Failed to get page content: ${error instanceof Error ? error.message : String(error)}`,
        is_error: true,
      };
    }
  }

  // ─── System Prompt & Helpers ──────────────────────────────────────────────────

  /** Build the system prompt with agent context */
  private buildSystemPrompt(): string {
    return `${this.config.systemPrompt}

## Operating Constraints
- You are an autonomous security testing agent operating within a defined scope.
- NEVER test targets outside the defined scope. Violations result in immediate termination.
- Use the provided tools to execute commands, report findings, and request specialist agents.
- Each tool call produces structured results — analyze them carefully before deciding your next action.
- When you discover a vulnerability, use report_finding with comprehensive evidence.
- When you've exhausted your attack surface, use stop_hunting with a summary.
- Be methodical: enumerate first, then probe, then validate findings.
- Avoid redundant tool calls — if a command returned useful data, analyze it before running more commands.
- If a command fails or is blocked, adapt your approach rather than retrying the same command.
- Rate limit your requests — the target is a production system, not a CTF box.
- **Maximum ${ReactLoop.IDENTICAL_TOOLCALL_THRESHOLD} attempts of identical tool calls.** If the same tool with the same arguments has not produced useful information after ${ReactLoop.IDENTICAL_TOOLCALL_THRESHOLD} tries, change the tool, the arguments, or the approach — never repeat. The runtime enforces this and will hard-stop your loop on the ${ReactLoop.IDENTICAL_TOOLCALL_THRESHOLD}rd repeat.
- **Hard tool-call cap: ${this.maxToolCalls}.** Independent of iteration budget. Make every tool call earn its keep.

## Evidence Requirements (MANDATORY)
Every finding you report MUST include:
1. **Full HTTP request/response pairs** — include method, URL, headers, body, status code, and relevant response body. This is the #1 thing triagers check.
2. **Reproduction curl command** — a single curl command that reproduces the vulnerability.
3. **Concrete impact** — what specific data was accessed or action performed. Never write generic impact statements like "an attacker could potentially..." — show what you actually achieved.
4. **Browser verification** — for client-side vulns (XSS, CORS, open redirect, cache poisoning, prototype pollution), use browser_navigate to confirm the vulnerability in a real browser. Include the browser result in evidence.

### Severity Calibration
Assign severity based on actual demonstrated impact, NOT theoretical worst case:
- CRITICAL: RCE, auth bypass to admin, full database access, account takeover of any user
- HIGH: Stored XSS, SQLi with data extraction, SSRF reading internal services/metadata, IDOR on sensitive data (PII, financial)
- MEDIUM: Reflected XSS (with user interaction), CORS with proven credential-based data theft, CSRF on state-changing actions
- LOW: Information disclosure (stack traces, internal IPs), self-XSS, minor misconfigurations
- INFO: Best practices, no demonstrated security impact

### DO NOT REPORT (Core Ineligible — auto-rejected)
These findings are NEVER accepted regardless of program. Do NOT waste iterations on them:
- CORS without a working PoC that steals sensitive data cross-origin with credentials
- Open redirects unless chained to OAuth token theft or session hijacking
- Missing security headers (X-Frame-Options, CSP, HSTS) — these are informational only
- Self-XSS that cannot target other users
- Software version disclosure
- Clickjacking on non-sensitive pages
- Header reflection in Link/preconnect tags — this is NOT SSRF (the server does not make a request)
- Rate limiting issues unless they enable brute-force of authentication

### Writing Style
Be specific and terse. No walls of formatted prose. Show data, not descriptions. Include the exact endpoint, parameter name, and payload that triggered the issue. Write like an expert pentester, not an AI assistant.

## Iteration Budget
You have ${this.maxIterations} iterations maximum. Use them wisely:
- Iterations 1-10: Reconnaissance and mapping
- Iterations 11-40: Active testing and probing
- Iterations 41-70: Deep testing and validation
- Iterations 71-80: Wrap up, validate findings, generate final report

Current findings: ${this.findings.length}
Current tool calls: ${this.toolCallCount}${this.config.availableTools?.length ? `

## Available Security Tools
The following tools are installed and available on this system: ${this.config.availableTools.join(', ')}
Do NOT attempt to use tools that are not in this list — they will fail with "command not found".` : ''}${this.buildAuthSection()}${this.buildWafSection()}${this.buildSharedFindingsSection()}`;
  }

  /**
   * Build the auth context section for the agent system prompt (Phase 1 / Q2).
   *
   * Only emitted when an active auth session is bound to this agent. Tells
   * the agent (a) which headers are in play, (b) to prefer `http_request`,
   * (c) that 401s mean "session expired, not a finding," and (d) how to
   * request a second identity for IDOR proofs via `session_label`.
   */
  private buildAuthSection(): string {
    if (!this.config.authSessionId || !this.config.sessionManager) return '';
    const session = this.config.sessionManager.getSession(this.config.authSessionId);
    if (!session) return '';

    const allSessions = this.config.sessionManager.listSessions();
    const headerNames = Object.keys(session.headers);
    const cookieCount = session.cookies.length;
    const csrfPresent = !!session.csrfToken;

    const parts: string[] = [];
    parts.push('\n\n## Active Authentication');
    parts.push('You have an active authenticated session for this target.\n');
    parts.push(`- Session label: ${session.label}`);
    parts.push(`- Auth type: ${session.authType}`);
    if (headerNames.length > 0) parts.push(`- Auth headers: ${headerNames.join(', ')}`);
    if (cookieCount > 0) parts.push(`- Session cookies: ${cookieCount}`);
    if (csrfPresent) parts.push('- CSRF token: present');
    parts.push(`- Identities available: ${allSessions.length}`);

    parts.push(`
### How to use it
- Prefer \`http_request\` — it auto-injects auth headers and handles 401 retry.
- When you need a shell tool (curl, ffuf, nuclei, sqlmap), the sandbox has \`HUNTRESS_AUTH_*\` env vars set and \`~/.curlrc\` pre-stamped. Use \`curl -H "Authorization: $HUNTRESS_AUTH_AUTHORIZATION" ...\` (or just \`curl\` which reads ~/.curlrc). Do NOT paste the token literally into commands — use the env var.`);

    if (allSessions.length > 1) {
      parts.push(`- Multi-identity testing: \`http_request\` accepts an optional \`session_label\` parameter. Use \`session_label: "victim"\` and \`session_label: "attacker"\` on consecutive requests to prove IDOR/BOLA.
- Available session labels: ${allSessions.map(s => `"${s.label}"`).join(', ')}`);
    }

    parts.push(`
### What 401/403 means
- 401 from the target is NOT a finding. It means the session expired. \`http_request\` auto-retries once after refresh. If it still fails, note it and move on — do not escalate.
- 403 on an authenticated endpoint IS a finding ONLY if another identity you hold can access the same URL. Prove it with two \`http_request\` calls using different \`session_label\` values.

### What NOT to do
- Do not attempt to log in yourself. Do not call login endpoints. Do not submit credentials. Authentication is managed by the platform.
- Do not paste auth tokens into findings. Redact them as \`<REDACTED>\` in evidence.`);

    return parts.join('\n');
  }

  /** Severity calibration gate (C2) — catches known over-escalation patterns.
   *  Returns corrected severity and optional note explaining the correction. */
  static checkSeverityCalibration(
    severity: string,
    vulnType: string,
    title: string,
    description: string,
    evidence: string[]
  ): { correctedSeverity: string; note: string | null } {
    const s = severity.toLowerCase();
    const t = title.toLowerCase();
    const d = description.toLowerCase();
    const allText = `${t} ${d} ${evidence.join(' ').toLowerCase()}`;

    // Rules ordered from most specific to most general to avoid shadowing.

    // Rule 1: Header reflection in Link/preconnect is NOT SSRF — max LOW
    if ((s === 'critical' || s === 'high') &&
        (t.includes('preconnect') || t.includes('link header') || d.includes('preconnect') ||
         allText.includes('rel=preconnect') || allText.includes('rel="preconnect"'))) {
      return {
        correctedSeverity: 'low',
        note: 'Header reflection in Link/preconnect is a browser hint, not SSRF. Server does not make a request.',
      };
    }

    // Rule 2: Missing security headers are INFO (before generic info disclosure check)
    if ((s === 'medium' || s === 'high' || s === 'critical') &&
        (t.includes('missing header') || t.includes('security header') ||
         t.includes('x-frame-options') || t.includes('x-content-type') ||
         t.includes('strict-transport') || t.includes('content-security-policy') ||
         t.includes('hsts missing') || t.includes('csp missing'))) {
      return {
        correctedSeverity: 'info',
        note: 'Missing security headers are informational — not accepted as vulnerabilities.',
      };
    }

    // Rule 3: Version/technology disclosure is INFO (before generic info disclosure)
    if ((s === 'medium' || s === 'high' || s === 'critical' || s === 'low') &&
        (t.includes('version disclosure') || t.includes('server version') ||
         t.includes('software version') || t.includes('technology disclosure'))) {
      return {
        correctedSeverity: 'info',
        note: 'Software version disclosure is informational only.',
      };
    }

    // Rule 4: Information disclosure is max MEDIUM unless it directly enables ATO
    if ((s === 'critical' || s === 'high') && vulnType === 'information_disclosure') {
      const enablesAto = allText.includes('password') || allText.includes('api_key') ||
        allText.includes('apikey') || allText.includes('secret_key') ||
        allText.includes('access_token') || allText.includes('session');
      if (!enablesAto) {
        return {
          correctedSeverity: 'medium',
          note: 'Information disclosure downgraded — no evidence of credential or session exposure.',
        };
      }
    }

    // Rule 5: Self-XSS is max LOW
    if ((s === 'high' || s === 'medium' || s === 'critical') &&
        (vulnType === 'xss_reflected' || vulnType === 'xss_stored' || vulnType === 'xss_dom') &&
        (allText.includes('self-xss') || allText.includes('self xss') ||
         allText.includes('own account') || allText.includes('own session'))) {
      return {
        correctedSeverity: 'low',
        note: 'Self-XSS that only affects the attacker\'s own session.',
      };
    }

    // Rule 6: Standalone open redirect without chaining is INFO
    if ((s === 'medium' || s === 'high' || s === 'critical') &&
        vulnType === 'open_redirect') {
      const hasChain = allText.includes('oauth') || allText.includes('token theft') ||
        allText.includes('session') || allText.includes('chain') ||
        allText.includes('sso') || allText.includes('redirect_uri');
      if (!hasChain) {
        return {
          correctedSeverity: 'info',
          note: 'Standalone open redirect without chaining to OAuth/session theft is core ineligible.',
        };
      }
    }

    // Rule 7: CORS without credential theft proof — max MEDIUM even if claimed higher
    if ((s === 'critical' || s === 'high') && vulnType === 'cors_misconfiguration') {
      const hasProof = allText.includes('withcredentials') || allText.includes('credentials: \'include\'') ||
        allText.includes('stolen') || allText.includes('exfiltrat') ||
        allText.includes('cross-origin data');
      if (!hasProof) {
        return {
          correctedSeverity: 'medium',
          note: 'CORS downgraded — no evidence of credential-based cross-origin data theft PoC.',
        };
      }
    }

    return { correctedSeverity: severity, note: null };
  }

  /** WAF-specific bypass strategies keyed by vendor */
  private static readonly WAF_BYPASS_STRATEGIES: Record<string, string> = {
    cloudflare: `Cloudflare WAF detected. Bypass strategies:
- Use double URL encoding (%2527 instead of %27)
- Try Unicode normalization bypasses (fullwidth characters: ＜script＞)
- Use chunked transfer encoding to split payloads
- Test with HTTP/2-specific header injection
- Use case alternation and HTML entity encoding for XSS`,
    akamai: `Akamai WAF detected. Bypass strategies:
- Use case manipulation (SeLeCt, uNiOn)
- Try null byte injection (%00) between keywords
- Use path normalization tricks (..;/, ..%2f)
- Test with lesser-known SQL functions (BENCHMARK, SLEEP alternative syntax)
- Try comment-based keyword splitting (SEL/**/ECT)`,
    aws_waf: `AWS WAF detected. Bypass strategies:
- Use JSON-based SQL injection payloads
- Try HTTP parameter pollution (duplicate params)
- Use uncommon content types (application/x-www-form-urlencoded with nested params)
- Test with HTTP verb tampering (X-HTTP-Method-Override)
- Try payload fragmentation across multiple parameters`,
    imperva: `Imperva/Incapsula WAF detected. Bypass strategies:
- Use multi-line payloads with \\r\\n injection
- Try Unicode/UTF-8 encoding bypasses
- Use HTTP/2 connection coalescing
- Test with alternate data representations (hex, octal)`,
    generic: `WAF detected (vendor unknown). General bypass strategies:
- Start with encoding-based bypasses (double URL encode, Unicode, HTML entities)
- Try keyword splitting with comments (e.g., SEL/**/ECT, <scr/**/ipt>)
- Use alternative syntax for the same operations
- Test with different content types and HTTP methods
- If blocked, increase delay between requests to avoid rate-based blocks`,
  };

  /** Build WAF detection section for agent system prompt */
  private buildWafSection(): string {
    const waf = this.config.wafContext;
    if (!waf) return '';

    const vendor = waf.vendor.toLowerCase().replace(/[-_\s]/g, '_');
    const strategies = ReactLoop.WAF_BYPASS_STRATEGIES[vendor]
      ?? ReactLoop.WAF_BYPASS_STRATEGIES['generic']
      ?? '';

    return `

## WAF Detection
A Web Application Firewall has been detected on this target (confidence: ${Math.round(waf.confidence * 100)}%).
Detection signal: ${waf.signal}

${strategies}

IMPORTANT: Do not waste iterations on obvious payloads that will be blocked. Use encoding and bypass techniques from the start.`;
  }

  /** Format shared findings from other agents into a system prompt section */
  private buildSharedFindingsSection(): string {
    const findings = this.config.sharedFindings;
    if (!findings || findings.length === 0) return '';

    const lines = findings.map(f =>
      `- [${f.severity.toUpperCase()}] ${f.title} (${f.vulnType}) on ${f.target} — found by ${f.agentId}: ${f.description.slice(0, 150)}`
    );

    return `

## Cross-Agent Intelligence
Other agents have discovered the following. Use these to inform your testing strategy — look for chained exploits, related vulnerabilities, or parameters/endpoints that may be vulnerable to your attack class too.

${lines.join('\n')}`;
  }

  /** Build the structured ContinuationHandoff from iteration history */
  private buildContinuationHandoff(): ContinuationHandoff {
    // Extract findings
    const findings = this.findings.map(f => ({
      title: f.title,
      severity: f.severity,
      target: f.target,
      confidence: f.confidence,
    }));

    // Extract tested paths from execute_command calls (targets that yielded no findings)
    const testedPaths: string[] = [];
    const findingTargets = new Set(this.findings.map(f => f.target));

    for (const log of this.iterationLog) {
      for (const tc of log.toolCalls ?? []) {
        if (tc.name === 'execute_command') {
          const target = (tc.input as { target?: string }).target;
          if (target && !findingTargets.has(target) && !testedPaths.includes(target)) {
            testedPaths.push(target);
          }
        }
      }
    }

    // Extract hypotheses from the model's thinking (last few iterations)
    const hypotheses: string[] = [];
    for (const log of this.iterationLog.slice(-10)) {
      if (log.thinking) {
        // Look for hypothesis-like patterns in reasoning
        const lines = log.thinking.split('\n');
        for (const line of lines) {
          const trimmed = line.trim();
          if (
            (trimmed.includes('might') || trimmed.includes('could') ||
             trimmed.includes('should test') || trimmed.includes('try') ||
             trimmed.includes('investigate') || trimmed.includes('check if')) &&
            trimmed.length > 20 && trimmed.length < 200
          ) {
            hypotheses.push(trimmed);
          }
        }
      }
    }

    // Extract discovered assets from tool results
    const discoveredAssets: string[] = [];
    for (const log of this.iterationLog) {
      if (log.toolResult) {
        // Look for URLs, subdomains, endpoints in tool output
        const urlMatches = log.toolResult.match(/https?:\/\/[^\s"'<>]+/g);
        if (urlMatches) {
          for (const u of urlMatches) {
            if (!discoveredAssets.includes(u) && discoveredAssets.length < 50) {
              discoveredAssets.push(u);
            }
          }
        }
      }
    }

    return {
      findings,
      testedPaths: testedPaths.slice(0, 30),
      hypotheses: hypotheses.slice(0, 10),
      discoveredAssets: discoveredAssets.slice(0, 50),
      iterationsUsed: this.iterationLog.length,
    };
  }

  /** Generate compressed context for continuation in a fresh agent */
  private generateContinuationContext(handoff?: ContinuationHandoff): string {
    const h = handoff ?? this.buildContinuationHandoff();

    const findingLines = h.findings.length > 0
      ? h.findings.map(f => `- [${f.severity}] ${f.title} at ${f.target} (${f.confidence}%)`).join('\n')
      : 'None yet';

    const testedLines = h.testedPaths.length > 0
      ? h.testedPaths.map(p => `- ${p}`).join('\n')
      : 'None';

    const hypothesisLines = h.hypotheses.length > 0
      ? h.hypotheses.map(h2 => `- ${h2}`).join('\n')
      : 'None';

    const assetLines = h.discoveredAssets.length > 0
      ? h.discoveredAssets.slice(0, 20).map(a => `- ${a}`).join('\n')
      : 'None';

    return `## Continuation from Previous Agent
Iterations used: ${h.iterationsUsed}/${this.maxIterations}
Tool calls made: ${this.toolCallCount}

## Confirmed Findings
${findingLines}

## Tested Paths (do NOT re-test)
${testedLines}

## Active Hypotheses (investigate these)
${hypothesisLines}

## Discovered Assets
${assetLines}`;
  }

  /** Emit a status update */
  private emitStatus(
    type: StatusUpdate['type'],
    message: string,
    iteration: number
  ): void {
    if (this.config.onStatusUpdate) {
      this.config.onStatusUpdate({
        type,
        message,
        iteration,
        maxIterations: this.maxIterations,
        toolCallCount: this.toolCallCount,
        findingCount: this.findings.length,
      });
    }
  }
}

/**
 * Extract the primary target hostname/IP from a shell command string.
 * Falls back to the explicit target field from the tool call.
 *
 * Issue #5 fix: host-character classes now exclude quote marks so that
 * commands like `curl "https://target.com"` yield `target.com` not
 * `target.com"`. Results are also trimmed of trailing punctuation
 * defensively — the scope validator would otherwise reject
 * `target.com"` as out-of-scope, wasting the iteration.
 */
export function extractTargetFromCommand(command: string, fallbackTarget?: string): string | null {
  // Hostname chars: letters/digits/dot/hyphen. Explicitly excludes
  // whitespace, path separator, port colon, and quote characters.
  const HOST = `[^\\s/:\\'"\\<\\>\\(\\)\\[\\]]+`;

  // Common security tool patterns: tool [flags] URL/host
  const urlMatch = command.match(new RegExp(`https?://(${HOST})`));
  if (urlMatch) return sanitizeHost(urlMatch[1]);

  // nmap TARGET, nmap -sV TARGET (target is typically last non-flag arg)
  const nmapMatch = command.match(/\bnmap\b.*?\s+([a-zA-Z0-9][\w.-]+\.[a-zA-Z]{2,})\b/);
  if (nmapMatch) return sanitizeHost(nmapMatch[1]);

  // IP address pattern (standalone, not part of a flag value like --timeout=10.0.0)
  const ipMatch = command.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  if (ipMatch) return sanitizeHost(ipMatch[1]);

  // nuclei -u host, sqlmap -u URL, ffuf -u URL
  const dashUMatch = command.match(new RegExp(`-u\\s+https?://(${HOST})`));
  if (dashUMatch) return sanitizeHost(dashUMatch[1]);

  // Fallback to explicit target from agent tool call
  if (fallbackTarget && fallbackTarget !== 'N/A' && fallbackTarget.trim()) {
    // Strip protocol, path, port, and any stray punctuation
    const stripped = fallbackTarget.replace(/^https?:\/\//, '').split(/[/:]/)[0];
    if (stripped) return sanitizeHost(stripped);
  }

  return null;
}

/**
 * Trim any quote, bracket, or trailing punctuation characters that may have
 * slipped into a captured hostname. Defensive against agent-side
 * JSON-escaping mistakes (Issue #5) AND shell-quoting artifacts.
 */
function sanitizeHost(host: string): string {
  return host.replace(/^[\s\'"\<\(\[]+|[\s\'"\>\)\]\.,;]+$/g, '');
}

export default ReactLoop;

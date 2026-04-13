/**
 * OrchestratorEngine — Coordinator-Solver Architecture
 *
 * The AI brain of Huntress. Implements the Coordinator-Solver pattern where:
 *
 * - **Coordinator** (this engine): Uses the user's primary model with native tool use
 *   to analyze bounty programs, create execution plans, dispatch specialized agents,
 *   synthesize findings, detect vulnerability chains, and manage the hunt lifecycle.
 *
 * - **Solvers** (agents): Specialized, smaller-model agents that receive focused tasks
 *   from the coordinator, execute them via the ReAct loop, and report results back.
 *
 * The coordinator communicates with the model via ORCHESTRATOR_TOOL_SCHEMAS (native
 * tool use), never by parsing JSON from text. The model calls `dispatch_agent` to
 * spawn solvers, `reprioritize_tasks` to adjust the queue, `generate_report` to
 * produce PoC reports, and `stop_hunting` to end a session.
 *
 * Dynamic task management is powered by the TaskQueue (BabyAGI-style), with
 * chain_detector finding multi-vuln chains and target_scorer prioritizing targets.
 */

import type {
  ModelProvider,
  ChatMessage,
  ChatResponse,
  ToolUseBlock,
  ToolResultBlock,
  ContentBlock,
  SendMessageOptions,
} from '../providers/types';
import { invoke } from '@tauri-apps/api/core';
import { getMessageText } from '../providers/types';
import { ConversationManager } from '../conversation/conversation_manager';
import type {
  ConversationMessage,
  SessionPhase,
  StrategyOption,
  BriefingMessage,
  FindingCardMessage,
  Severity,
} from '../conversation/types';
import { PlanExecutor } from './plan_executor';
import type { ExecutionPlan } from './plan_executor';
import { TaskQueue } from './task_queue';
import type { HuntTask, TaskQueueStats } from './task_queue';
import { detectChains } from './chain_detector';
import type { VulnerabilityChain } from './chain_detector';
import { scoreTarget, rankTargets } from './target_scorer';
import type { TargetScore, TargetMetadata } from './target_scorer';
import {
  getAgentEntry,
  getAllAgents,
  findAgentsForVulnClass,
  initializeCatalog,
} from '../../agents/agent_catalog';
// Side-effect import: triggers all agent self-registration with the catalog
import '../../agents/standardized_agents';
import type { AgentResult, AgentFinding, AgentTask, SharedFinding, WafContext } from '../../agents/base_agent';
import { ORCHESTRATOR_TOOL_SCHEMAS } from '../engine/tool_schemas';
import { ModelAlloy, createAlloy } from '../engine/model_alloy';
import type { AlloyConfig } from '../engine/model_alloy';
import type { ProgramGuidelines } from '../../components/GuidelinesImporter';
import { Blackboard, postObservation, postFinding as postBBFinding } from './blackboard';
import { setValidatorOOBServer, shutdownValidationBrowser, validateFinding } from '../validation/validator';
import type { ValidationResult, ValidatorConfig } from '../validation/validator';
import type { ReactFinding } from '../engine/react_loop';
import type { DuplicateCheckResult } from '../../agents/base_agent';
import { OOBServer } from '../validation/oob_server';
import type { OOBCallback } from '../validation/oob_server';
import { FeedbackLoop } from '../training/feedback_loop';
import type { SubmittedReport, FeedbackStats } from '../training/feedback_loop';
import { deduplicateFindings } from './finding_dedup';
import { createSandboxedExecutor, SandboxExecutor } from '../tools/sandbox_executor';
import type { KnowledgeGraph, HuntResult } from '../knowledge/knowledge_graph';
import { SASTAnalyzer } from '../sast/sast_analyzer';
import type { SourceFile, SASTReport } from '../sast/sast_analyzer';
import type { VulnDatabase } from '../knowledge/vuln_database';
import type { RewardSystem, ShortcutCheckInput } from '../training/reward_system';
import type { HttpClient } from '../http/request_engine';
import type { SessionManager } from '../auth/session_manager';
import { buildSessionEnv } from '../auth/session_env';
import type { HuntMemory } from '../memory/hunt_memory';
import type { NucleiRunner } from '../discovery/nuclei_runner';
import type { WAFDetector, WAFDetectionResult } from '../evasion/waf_detector';
import type { ChainValidator } from './chain_validator';
import type { RateController } from '../http/rate_controller';
import type { StealthModule } from '../evasion/stealth';
import type { TargetDeduplicator } from './target_dedup';
import type { H1DuplicateChecker } from '../reporting/h1_duplicate_check';
import type { ReportQualityScorer } from '../reporting/report_quality';
import type { ContinuousMonitor } from '../discovery/continuous_monitor';
import { classifyTaskComplexity, getAnthropicModelForComplexity } from './cost_router';
import type { BudgetStatus } from '../tracing/types';

// ─── Callback Types ───────────────────────────────────────────────────────────

/**
 * Normalize and deduplicate scope entries so localhost/127.0.0.1 are treated
 * as the same target and scheme prefixes are stripped.
 */
export function normalizeScopeEntries(entries: string[]): string[] {
  const normalized = new Map<string, string>();

  for (const raw of entries) {
    let entry = raw.trim();
    // Strip scheme prefixes (http:// or https://)
    entry = entry.replace(/^https?:\/\//, '');
    // Strip trailing slashes
    entry = entry.replace(/\/+$/, '');
    // Normalize localhost variants to canonical form
    entry = entry.replace(/^127\.0\.0\.1(?=:|$)/, 'localhost');
    entry = entry.replace(/^0\.0\.0\.0(?=:|$)/, 'localhost');

    // Deduplicate by normalized form (keep first occurrence's original label)
    const key = entry.toLowerCase();
    if (!normalized.has(key)) {
      normalized.set(key, entry);
    }
  }

  return Array.from(normalized.values());
}

/**
 * Determine which agents to skip based on detected tech stack.
 * Returns a Set of agent IDs to exclude from dispatch.
 */
export function getSkippedAgentsForTechStack(techStackLower: string): Set<string> {
  const skip = new Set<string>();

  const isNodeJS = /node\.?js|express|koa|next\.?js|nest\.?js/.test(techStackLower);
  const isPHP = /php|laravel|wordpress|drupal|symfony/.test(techStackLower);
  const isJava = /java|spring|tomcat|jetty|struts/.test(techStackLower);
  const isPython = /python|django|flask|fastapi/.test(techStackLower);
  const hasGraphQL = /graphql/.test(techStackLower);
  const hasSAML = /saml|sso|okta|azure.ad|adfs/.test(techStackLower);
  const hasWebSockets = /websocket|ws:\/\/|wss:\/\/|socket\.io/.test(techStackLower);

  // SSTI is primarily a Python/Java/PHP concern, not Node.js
  if (isNodeJS && !isPython && !isJava && !isPHP) {
    skip.add('ssti-hunter');
  }

  // Deserialization is mainly Java/.NET, less relevant for Node/Python
  if (isNodeJS && !isJava) {
    skip.add('deserialization-hunter');
  }

  // SAML only relevant when SSO/SAML is detected
  if (!hasSAML) {
    skip.add('saml-hunter');
  }

  // GraphQL hunter only relevant when GraphQL endpoint detected
  if (!hasGraphQL) {
    skip.add('graphql-hunter');
  }

  // WebSocket hunter only relevant when WebSocket endpoints detected
  if (!hasWebSockets) {
    skip.add('websocket-hunter');
  }

  // HTTP smuggling less relevant for certain stacks
  if (isNodeJS || isPython) {
    skip.add('http-smuggling-hunter');
  }

  return skip;
}

/** Callback for when new messages should be displayed */
export type MessageCallback = (message: ConversationMessage) => void;

/** Callback for when the session phase changes */
export type PhaseCallback = (phase: SessionPhase) => void;

// ─── Configuration ────────────────────────────────────────────────────────────

export interface AlloyConfiguration {
  /** Whether alloy is enabled */
  enabled: boolean;
  /** The secondary model provider */
  secondaryProvider: ModelProvider;
  /** The secondary model ID */
  secondaryModel: string;
  /** Weight for the primary model (0-100). Secondary gets the remainder. */
  primaryWeight: number;
  /** Rotation strategy */
  strategy: AlloyConfig['strategy'];
  /** Human-readable label for the secondary model */
  secondaryLabel?: string;
}

export interface OrchestratorConfig {
  provider: ModelProvider;
  model: string;
  maxContextTokens?: number;
  systemPrompt?: string;
  /** Maximum agents that can run concurrently */
  maxConcurrentAgents?: number;
  /** Whether to auto-approve passive recon commands */
  autoApproveSafe?: boolean;
  /** Callback when a command needs user approval */
  onApprovalRequest?: (request: ApprovalRequest) => Promise<boolean>;
  /** Callback to execute a command via Rust PTY */
  onExecuteCommand?: (command: string, target: string) => Promise<CommandResult>;
  /** Optional alloy configuration for multi-model rotation */
  alloy?: AlloyConfiguration;
  /** Pre-initialized KnowledgeGraph for persistent learning */
  knowledgeGraph?: KnowledgeGraph;
  /** Pre-initialized VulnDatabase for CVE/CWE context enrichment */
  vulnDb?: VulnDatabase;
  /** Pre-initialized RewardSystem for agent trust/model selection */
  rewardSystem?: RewardSystem;
  /** Pre-initialized HTTP client for direct agent requests (Phase 20A) */
  httpClient?: HttpClient;
  /** Pre-initialized session manager for authenticated testing (Phase 20C) */
  sessionManager?: SessionManager;
  /** Pre-initialized hunt memory for cross-session learning (Phase 20E) */
  huntMemory?: HuntMemory;
  /** Pre-initialized Nuclei template scanner (Phase 20F) */
  nucleiRunner?: NucleiRunner;
  /** Pre-initialized WAF detector (Phase 20G) */
  wafDetector?: WAFDetector;
  /** Pre-initialized chain validator (Phase 20I) */
  chainValidator?: ChainValidator;
  /** Pre-initialized adaptive rate controller (Phase 20J) */
  rateController?: RateController;
  /** Pre-initialized stealth module (Phase 20J) */
  stealthModule?: StealthModule;
  /** Pre-initialized target deduplicator (Phase 23B) */
  targetDedup?: TargetDeduplicator;
  /** Pre-initialized H1 duplicate checker (Phase 23C) */
  h1DuplicateChecker?: H1DuplicateChecker;
  /** Pre-initialized report quality scorer (Phase 23E) */
  reportQuality?: ReportQualityScorer;
  /** Pre-initialized continuous monitor (Phase 23G) */
  continuousMonitor?: ContinuousMonitor;
  /** List of available security tools on this system */
  availableTools?: string[];
  /** Callback to check current session budget status (wired from TracedModelProvider) */
  getBudgetStatus?: () => BudgetStatus;
  /** Callback to update session budget limit (wired from TracedModelProvider) */
  setBudgetLimit?: (newLimitUsd: number) => void;
  /** Session budget limit in USD */
  budgetLimitUsd?: number;
}

export interface ApprovalRequest {
  command: string;
  target: string;
  reasoning: string;
  category: string;
  agent: string;
}

export interface CommandResult {
  success: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
  executionTimeMs: number;
  blocked?: boolean;
  blockReason?: string;
}

// ─── Hunt Session State ───────────────────────────────────────────────────────

interface HuntSession {
  /** The imported bounty program */
  program: ProgramGuidelines;
  /** Dynamic task queue */
  taskQueue: TaskQueue;
  /** All findings across all agents */
  allFindings: AgentFinding[];
  /** Detected vulnerability chains */
  chains: VulnerabilityChain[];
  /** Target scores for prioritization */
  targetScores: TargetScore[];
  /** Active agent count */
  activeAgents: number;
  /** Completed dispatches */
  completedDispatches: number;
  /** Whether the hunt loop is running */
  running: boolean;
  /** Abort signal */
  aborted: boolean;
  /** Dead-letter queue: tasks that failed after retry exhaustion */
  failedTasks: Array<{ taskId: string; agentType: string; error: string; attempts: number; timestamp: number }>;
}

// ─── Agent Retry Helpers ──────────────────────────────────────────────────────

/** Permanent error patterns that should not be retried */
const PERMANENT_ERROR_PATTERNS = [
  'invalid_api_key',
  'authentication_error',
  'insufficient_quota',
  'credit balance is too low',
  'No agent found for type',
  'usage limits',
  'monthly spend limit',
  'billing limit',
  'account_spending_limit_reached',
  '401',
  '403',
];

/** Error patterns that indicate the ENTIRE API account is blocked (not per-request) */
const API_LIMIT_PATTERNS = [
  'You have reached your specified API usage limits',
  'monthly spend limit',
  'billing limit',
  'account_spending_limit_reached',
  'insufficient_quota',
  'credit balance is too low',
];

/**
 * Check if an error message indicates a global API account limit (not a transient rate limit).
 */
export function isApiLimitError(errMsg: string): boolean {
  return API_LIMIT_PATTERNS.some(pat => errMsg.includes(pat));
}

/**
 * Classify an error as transient (retryable) or permanent.
 * Transient: network errors, rate limits (429), server errors (5xx).
 * Permanent: auth failures (401, 403), credit exhaustion, missing agents.
 */
export function isTransientError(errMsg: string): boolean {
  return !PERMANENT_ERROR_PATTERNS.some(pat => errMsg.includes(pat));
}

// ─── Evidence Normalization ─────────────────────────────────────────────────

/**
 * Normalize evidence from agent findings into a guaranteed string[].
 * Agents are LLMs and may return evidence as a string, object, undefined,
 * or an actual array. This must be called at the pipeline boundary before
 * any array methods (.join, .map, .forEach, for..of) are used on evidence.
 */
export function normalizeEvidence(evidence: unknown): string[] {
  if (Array.isArray(evidence)) {
    // Filter out non-string elements and stringify them
    return evidence.map(item =>
      typeof item === 'string' ? item : JSON.stringify(item)
    );
  }
  if (typeof evidence === 'string') {
    return [evidence];
  }
  if (evidence === undefined || evidence === null) {
    return [];
  }
  // Object, number, boolean, etc.
  return [JSON.stringify(evidence)];
}

// ─── Finding Validation Helpers ──────────────────────────────────────────────

/**
 * Convert an AgentFinding to a ReactFinding for the validation engine.
 * The validator was built against the ReAct loop's finding type, so we
 * bridge at the orchestrator boundary.
 */
export function agentFindingToReactFinding(finding: AgentFinding): ReactFinding {
  return {
    id: finding.id,
    title: finding.title,
    vulnerabilityType: finding.type ?? 'unknown',
    severity: finding.severity,
    target: finding.target,
    description: finding.description,
    evidence: finding.evidence,
    reproductionSteps: finding.reproduction,
    impact: finding.description,
    confidence: 50, // Default for agent findings without explicit confidence
    discoveredAtIteration: 0,
    agentId: finding.agentId,
  };
}

/**
 * Map a ValidationResult back onto the finding's validation fields.
 */
export function applyValidationResult(
  finding: AgentFinding,
  result: ValidationResult
): void {
  if (result.error && !result.confirmed) {
    finding.validationStatus = 'validation_failed';
  } else if (result.confirmed) {
    finding.validationStatus = 'confirmed';
  } else {
    finding.validationStatus = 'unverified';
  }
  finding.validationEvidence = result.evidence;
  finding.validationConfidence = result.confidence;
}

/**
 * Map a DuplicateScore into a DuplicateCheckResult for display.
 */
export function buildDuplicateCheckResult(
  dupScore: import('../../utils/duplicate_checker').DuplicateScore
): DuplicateCheckResult {
  let status: DuplicateCheckResult['status'];
  if (dupScore.recommendation === 'skip') {
    status = 'likely_duplicate';
  } else if (dupScore.recommendation === 'review') {
    status = 'possible_duplicate';
  } else {
    status = 'unique';
  }
  return {
    status,
    score: dupScore,
    topMatches: dupScore.matches.slice(0, 3).map(m => ({
      source: m.source,
      title: m.title,
      url: m.url,
      similarity: m.similarity,
    })),
  };
}

// ─── Orchestrator Engine ──────────────────────────────────────────────────────

export class OrchestratorEngine {
  private provider: ModelProvider;
  private model: string;
  private conversation: ConversationManager;
  private onMessage?: MessageCallback;
  private onPhaseChange?: PhaseCallback;
  private currentPhase: SessionPhase = 'idle';
  private currentPlan?: ExecutionPlan;
  private guidelines?: ProgramGuidelines;
  private systemPrompt: string;
  private maxConcurrentAgents: number;
  private autoApproveSafe: boolean;
  private onApprovalRequest?: (request: ApprovalRequest) => Promise<boolean>;
  private onExecuteCommand?: (command: string, target: string) => Promise<CommandResult>;
  /** Callback to check current session budget — wired from TracedModelProvider */
  private getBudgetStatus?: () => BudgetStatus;
  private setBudgetLimit?: (newLimitUsd: number) => void;
  /** Session budget limit in USD */
  private budgetLimitUsd: number;
  /** Whether budget soft-stop has been triggered (90% threshold) */
  private budgetSoftStopped = false;
  private dispatchLoopRunning = false;

  /** Circuit breaker: tracks recent agent error messages to detect fatal patterns */
  private recentAgentErrors: string[] = [];
  private static readonly CIRCUIT_BREAKER_THRESHOLD = 5;
  /** Sliding window: consecutive successes needed to reset circuit breaker */
  private consecutiveSuccesses = 0;
  private static readonly CIRCUIT_BREAKER_RESET_THRESHOLD = 5;
  /** Global flag: set when the API account hits a usage/spending limit.
   *  Prevents all subsequent agent dispatches until the user resumes. */
  private apiLimitReached = false;

  /** Max retries for transient agent failures */
  private static readonly MAX_AGENT_RETRIES = 3;
  /** Base delay (ms) for exponential backoff on agent retry */
  private static readonly RETRY_BASE_DELAY_MS = 2000;

  /** Cross-agent shared memory board */
  private blackboard: Blackboard;
  /** Out-of-band interaction server for blind vuln detection */
  private oobServer?: OOBServer;
  /** H1 report tracking and feedback loop */
  private feedbackLoop: FeedbackLoop;
  /** Model alloy for multi-model rotation (created when alloy is configured) */
  private alloyInstance?: ModelAlloy;
  /** Alloy configuration from settings */
  private alloyConfig?: AlloyConfiguration;

  /** Persistent knowledge graph for cross-session learning */
  private knowledgeGraph?: KnowledgeGraph;
  /** Vulnerability database for CVE/CWE enrichment */
  private vulnDb?: VulnDatabase;
  /** Reward system for agent trust levels and model selection */
  private rewardSystem?: RewardSystem;
  /** Direct HTTP client for agent requests (Phase 20A) */
  private httpClient?: HttpClient;
  /** Session manager for authenticated testing (Phase 20C) */
  private sessionManager?: SessionManager;
  /** Hunt memory for cross-session TF-IDF vector learning (Phase 20E) */
  private huntMemory?: HuntMemory;
  /** Nuclei template scanner (Phase 20F) */
  private nucleiRunner?: NucleiRunner;
  /** WAF detector (Phase 20G) */
  private wafDetector?: WAFDetector;
  /** Cached WAF detection result for current target */
  private wafDetectionResult?: WAFDetectionResult;
  /** Chain validator for proving chains are exploitable (Phase 20I) */
  private chainValidator?: ChainValidator;
  /** Adaptive rate controller (Phase 20J) */
  private rateController?: RateController;
  /** Stealth module for UA rotation and jitter (Phase 20J) */
  private stealthModule?: StealthModule;
  /** Target deduplicator for reducing redundant testing (Phase 23B) */
  private targetDedup?: TargetDeduplicator;
  /** HackerOne duplicate checker for pre-submission validation (Phase 23C) */
  private h1DuplicateChecker?: H1DuplicateChecker;
  /** Report quality scorer for submission readiness (Phase 23E) */
  private reportQuality?: ReportQualityScorer;
  /** Continuous monitoring for new attack surface (Phase 23G) */
  private continuousMonitor?: ContinuousMonitor;
  /** Available security tools on this system */
  private availableTools?: string[];

  /** Active hunt session state — only set during a hunt */
  private huntSession?: HuntSession;

  constructor(config: OrchestratorConfig) {
    this.provider = config.provider;
    this.model = config.model;
    this.conversation = new ConversationManager({
      maxContextTokens: config.maxContextTokens,
    });
    this.systemPrompt = config.systemPrompt ?? this.defaultSystemPrompt();
    this.maxConcurrentAgents = config.maxConcurrentAgents ?? 5;
    this.autoApproveSafe = config.autoApproveSafe ?? false;
    this.onApprovalRequest = config.onApprovalRequest;
    this.onExecuteCommand = config.onExecuteCommand;
    this.getBudgetStatus = config.getBudgetStatus;
    this.setBudgetLimit = config.setBudgetLimit;
    this.budgetLimitUsd = config.budgetLimitUsd ?? 15;
    this.alloyConfig = config.alloy;

    // Create alloy instance if configured and enabled
    if (config.alloy?.enabled) {
      this.alloyInstance = createAlloy(
        {
          provider: config.provider,
          model: config.model,
          label: config.provider.displayName,
        },
        {
          provider: config.alloy.secondaryProvider,
          model: config.alloy.secondaryModel,
          label: config.alloy.secondaryLabel ?? config.alloy.secondaryProvider.displayName,
        },
        config.alloy.strategy,
      );
    }

    // Initialize cross-agent shared memory
    this.blackboard = new Blackboard();

    // Initialize feedback loop for H1 report tracking
    this.feedbackLoop = new FeedbackLoop({
      onStatusChange: (report, oldStatus) => {
        this.emitSystemMessage(
          `Report ${report.h1ReportId ?? report.internalId}: ${oldStatus} -> ${report.status}` +
          (report.bountyAmount ? ` ($${report.bountyAmount})` : ''),
          report.status === 'resolved' ? 'success' : 'info'
        );
      },
      onStatsUpdate: (stats) => {
        if (stats.totalSubmitted > 0) {
          this.emitSystemMessage(
            `Feedback: ${stats.resolved} resolved, ${stats.duplicates} dupes, ` +
            `$${stats.totalBounties} total bounties`,
            'info'
          );
        }
      },
    });

    // Wire knowledge systems (pre-initialized by HuntSessionContext)
    this.knowledgeGraph = config.knowledgeGraph;
    this.vulnDb = config.vulnDb;
    this.rewardSystem = config.rewardSystem;
    this.httpClient = config.httpClient;
    this.sessionManager = config.sessionManager;
    this.huntMemory = config.huntMemory;
    this.nucleiRunner = config.nucleiRunner;
    this.wafDetector = config.wafDetector;
    this.chainValidator = config.chainValidator;
    this.rateController = config.rateController;
    this.stealthModule = config.stealthModule;
    this.targetDedup = config.targetDedup;
    this.h1DuplicateChecker = config.h1DuplicateChecker;
    this.reportQuality = config.reportQuality;
    this.continuousMonitor = config.continuousMonitor;
    this.availableTools = config.availableTools;

    // Ensure agent catalog is initialized
    initializeCatalog();
  }

  // ─── Public Accessors ───────────────────────────────────────────────────────

  /** Set the callback that receives new messages for UI rendering */
  setMessageCallback(callback: MessageCallback): void {
    this.onMessage = callback;
  }

  /** Set the callback for phase changes */
  setPhaseCallback(callback: PhaseCallback): void {
    this.onPhaseChange = callback;
  }

  /** Get current session phase */
  getPhase(): SessionPhase {
    return this.currentPhase;
  }

  /** Get conversation manager (for UI to read history) */
  getConversation(): ConversationManager {
    return this.conversation;
  }

  /** Get current plan if one is running */
  getCurrentPlan(): ExecutionPlan | undefined {
    return this.currentPlan;
  }

  /** Get the model provider */
  getProvider(): ModelProvider {
    return this.provider;
  }

  /** Get the model ID */
  getModel(): string {
    return this.model;
  }

  /** Get the full system prompt (including guidelines context) */
  getSystemPrompt(): string {
    return this.buildSystemPrompt();
  }

  /** Get the task queue stats (if a hunt is active) */
  getTaskQueueStats(): TaskQueueStats | undefined {
    return this.huntSession?.taskQueue.getStats();
  }

  /** Get all findings from the current hunt */
  getAllFindings(): AgentFinding[] {
    return this.huntSession?.allFindings ?? [];
  }

  /** Get detected vulnerability chains */
  getChains(): VulnerabilityChain[] {
    return this.huntSession?.chains ?? [];
  }

  /** Get target priority scores */
  getTargetScores(): TargetScore[] {
    return this.huntSession?.targetScores ?? [];
  }

  /** Get the cross-agent shared memory board */
  getBlackboard(): Blackboard {
    return this.blackboard;
  }

  /** Get the feedback loop for report tracking */
  getFeedbackLoop(): FeedbackLoop {
    return this.feedbackLoop;
  }

  /** Get the OOB server (only available during an active hunt) */
  getOOBServer(): OOBServer | undefined {
    return this.oobServer;
  }

  /** Track a submitted H1 report for feedback monitoring */
  trackReport(report: SubmittedReport): void {
    this.feedbackLoop.trackReport(report);
  }

  /** Load program guidelines into the orchestrator context */
  loadGuidelines(guidelines: ProgramGuidelines): void {
    this.guidelines = guidelines;
  }

  // ─── Core Interaction Loop ──────────────────────────────────────────────────

  /**
   * Process user input — the core interaction loop.
   * Uses native tool use so the model can dispatch agents, reprioritize, etc.
   */
  async processUserInput(input: string): Promise<void> {
    // Add user message
    const userMsg: ConversationMessage = {
      type: 'user',
      id: this.generateId(),
      content: input,
      timestamp: Date.now(),
    };
    this.conversation.addMessage(userMsg);
    this.emitMessage(userMsg);

    // Check for special commands
    if (await this.handleSpecialInput(input)) return;

    // Build context for the model
    const contextMessages = this.conversation.getMessagesForModel();

    try {
      // Enable tool use whenever a program is loaded (guidelines exist).
      // If no hunt session exists yet, dispatch_agent will auto-create one.
      const useTools = this.provider.supportsToolUse && !!(this.huntSession || this.guidelines);

      const options: SendMessageOptions = {
        model: this.model,
        maxTokens: 4096,
        systemPrompt: this.buildSystemPrompt(),
      };

      if (useTools) {
        options.tools = ORCHESTRATOR_TOOL_SCHEMAS;
        options.toolChoice = 'auto';
      }

      const response = await this.provider.sendMessage(contextMessages, options);

      // Handle tool calls if present
      if (response.toolCalls?.length) {
        await this.handleCoordinatorToolCalls(response);
      } else {
        // Pure text response — parse for structured content
        const messages = this.parseResponse(response.content);
        for (const msg of messages) {
          this.conversation.addMessage(msg);
          this.emitMessage(msg);
        }
      }
    } catch (error) {
      const errorMsg: ConversationMessage = {
        type: 'system',
        id: this.generateId(),
        content: `AI error: ${error instanceof Error ? error.message : String(error)}`,
        level: 'error',
        timestamp: Date.now(),
      };
      this.conversation.addMessage(errorMsg);
      this.emitMessage(errorMsg);
    }
  }

  /**
   * Stream user input processing for real-time display.
   * Yields chunks as they arrive from the model.
   */
  async *streamUserInput(input: string): AsyncGenerator<string> {
    const userMsg: ConversationMessage = {
      type: 'user',
      id: this.generateId(),
      content: input,
      timestamp: Date.now(),
    };
    this.conversation.addMessage(userMsg);
    this.emitMessage(userMsg);

    const contextMessages = this.conversation.getMessagesForModel();
    let fullContent = '';

    try {
      const useTools = this.provider.supportsToolUse && this.huntSession?.running;
      const options: SendMessageOptions = {
        model: this.model,
        maxTokens: 4096,
        systemPrompt: this.buildSystemPrompt(),
      };
      if (useTools) {
        options.tools = ORCHESTRATOR_TOOL_SCHEMAS;
        options.toolChoice = 'auto';
      }

      const stream = this.provider.streamMessage(contextMessages, options);

      for await (const chunk of stream) {
        if (chunk.type === 'content_delta' && chunk.content) {
          fullContent += chunk.content;
          yield chunk.content;
        }
      }

      // Add the complete response to conversation
      const responseMsg: ConversationMessage = {
        type: 'orchestrator',
        id: this.generateId(),
        content: fullContent,
        timestamp: Date.now(),
      };
      this.conversation.addMessage(responseMsg);
      this.emitMessage(responseMsg);
    } catch (error) {
      const errorMsg: ConversationMessage = {
        type: 'system',
        id: this.generateId(),
        content: `Streaming error: ${error instanceof Error ? error.message : String(error)}`,
        level: 'error',
        timestamp: Date.now(),
      };
      this.conversation.addMessage(errorMsg);
      this.emitMessage(errorMsg);
    }
  }

  // ─── Bounty Analysis ────────────────────────────────────────────────────────

  /**
   * Analyze a bounty program and generate a briefing.
   * Uses native tool use if available for structured output.
   */
  async analyzeBountyProgram(guidelines: ProgramGuidelines): Promise<BriefingMessage> {
    this.loadGuidelines(guidelines);
    this.setPhase('briefing');

    // Score all in-scope targets for prioritization
    const targetMetadata: TargetMetadata[] = guidelines.scope.inScope.map(target => ({
      target,
      historicalPayouts: {
        min: guidelines.bountyRange.min,
        max: guidelines.bountyRange.max,
        average: Math.round((guidelines.bountyRange.min + guidelines.bountyRange.max) / 2),
      },
    }));
    const scoredTargets = rankTargets(targetMetadata);

    // Enrich briefing with VulnDatabase knowledge if available
    let vulnContextSection = '';
    if (this.vulnDb) {
      try {
        const targets = guidelines.scope.inScope.slice(0, 5); // Top 5 targets
        const contextParts: string[] = [];
        for (const target of targets) {
          const knowledge = await this.vulnDb.getRelevantKnowledge('recon', target);
          if (knowledge.relevantCVEs.length > 0 || knowledge.kevEntries.length > 0) {
            contextParts.push(
              `${target}: ${knowledge.relevantCVEs.length} known CVEs` +
              (knowledge.kevEntries.length > 0 ? `, ${knowledge.kevEntries.length} in CISA KEV` : '')
            );
          }
        }
        if (contextParts.length > 0) {
          vulnContextSection = `\nKnown vulnerability context:\n${contextParts.map(p => `  ${p}`).join('\n')}\n`;
        }
      } catch {
        // VulnDB enrichment is best-effort
      }
    }

    // Enrich with historical knowledge graph patterns
    let kgContextSection = '';
    if (this.knowledgeGraph) {
      try {
        const stats = await this.knowledgeGraph.getOverallStats();
        if (stats.totalHunts > 0) {
          const topVulns = stats.topVulnTypes.slice(0, 3).map(v => `${v.vulnType}(${v.count})`).join(', ');
          kgContextSection = `\nHistorical performance: ${stats.totalHunts} hunts, ${(stats.successRate * 100).toFixed(0)}% success rate, top vulns: ${topVulns}\n`;
        }
      } catch {
        // KG enrichment is best-effort
      }
    }

    const prompt = `Analyze this bug bounty program and recommend attack strategies.

Program: ${guidelines.programName}
In-scope targets: ${guidelines.scope.inScope.join(', ')}
Out-of-scope: ${guidelines.scope.outOfScope.join(', ')}
Bounty range: $${guidelines.bountyRange.min} - $${guidelines.bountyRange.max}
Rules: ${guidelines.rules.join('; ')}

Target priority scores:
${scoredTargets.map(s => `  ${s.target}: ${s.totalScore}/100 — ${s.recommendation}`).join('\n')}
${vulnContextSection}${kgContextSection}
Available specialized agents:
${getAllAgents().map(a => `  - ${a.metadata.id}: ${a.metadata.description}`).join('\n')}

Respond with a JSON object:
{
  "targetSummary": "Brief overview of what we're testing",
  "strategies": [
    {
      "id": "strategy_1",
      "title": "Strategy name",
      "description": "What we'll test and why",
      "expectedValue": "$X-$Y likely bounty",
      "agents": ["agent_name"],
      "riskLevel": "low|medium|high"
    }
  ]
}

Return ONLY the JSON, no other text.`;

    const response = await this.provider.sendMessage(
      [{ role: 'user', content: prompt }],
      { model: this.model, maxTokens: 4096, systemPrompt: this.systemPrompt }
    );

    let targetSummary = `Bug bounty program: ${guidelines.programName}`;
    let strategies: StrategyOption[] = [];

    try {
      const jsonMatch = response.content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        targetSummary = parsed.targetSummary ?? targetSummary;
        strategies = parsed.strategies ?? [];
      }
    } catch {
      // Use defaults if parsing fails
    }

    // Ensure strategies have valid IDs
    strategies = strategies.map((s, i) => ({
      ...s,
      id: s.id || `strategy_${i + 1}`,
    }));

    const briefing: BriefingMessage = {
      type: 'briefing',
      id: this.generateId(),
      timestamp: Date.now(),
      programName: guidelines.programName,
      targetSummary,
      assets: [
        ...guidelines.scope.inScope.map(t => ({ type: 'domain', target: t, inScope: true })),
        ...guidelines.scope.outOfScope.map(t => ({ type: 'domain', target: t, inScope: false })),
      ],
      bountyRange: guidelines.bountyRange,
      rules: guidelines.rules,
      strategies,
    };

    this.conversation.addMessage(briefing);
    this.emitMessage(briefing);

    return briefing;
  }

  /**
   * Handle a strategy selection from the user.
   */
  async selectStrategy(strategy: StrategyOption): Promise<void> {
    const msg: ConversationMessage = {
      type: 'orchestrator',
      id: this.generateId(),
      content: `Starting strategy: **${strategy.title}**\n\n${strategy.description}\n\nActivating agents: ${strategy.agents.join(', ')}`,
      timestamp: Date.now(),
    };
    this.conversation.addMessage(msg);
    this.emitMessage(msg);

    // Actually start the hunt with the loaded program
    if (this.guidelines) {
      await this.startHunt(this.guidelines);
    }
  }

  // ─── Coordinator-Solver: Hunt Lifecycle ─────────────────────────────────────

  /**
   * Start a full hunt on a bounty program.
   *
   * This is the main Coordinator-Solver entry point:
   * 1. Score and rank in-scope targets
   * 2. Create initial recon tasks for top targets
   * 3. Enter the dispatch loop: dequeue tasks, spawn agents, collect results
   * 4. After each agent completes: generate follow-up tasks, detect chains
   * 5. Ask the coordinator model what to do next (via native tool use)
   * 6. Repeat until the task queue is empty or the model calls stop_hunting
   */
  /**
   * I4: Return the active hunt's guidelines (program + scope) or null if
   * no hunt is running. Used by the UI to reopen the auth wizard mid-hunt
   * with the correct scope.
   */
  getActiveProgram(): ProgramGuidelines | null {
    return this.huntSession?.program ?? null;
  }

  /**
   * I4: Trigger a reprioritization of queued tasks — called after new
   * auth sessions are attached so agents that benefit from auth get
   * bumped up. Safe no-op if no hunt is active.
   */
  reprioritizeForAuth(): void {
    if (!this.huntSession) return;
    this.huntSession.taskQueue.reprioritize(this.huntSession.allFindings);
    this.emitSystemMessage(
      'Auth attached mid-hunt. Queued agents will pick up the new session on next dispatch.',
      'info'
    );
  }

  /**
   * Initialize a hunt session without starting the dispatch loop.
   * Used when agents are dispatched from chat before a strategy is selected.
   */
  async initializeHuntSession(program: ProgramGuidelines): Promise<void> {
    if (this.huntSession) return; // Already initialized

    // I5: Reap orphan containers from prior crashed hunts before starting.
    // Fire-and-forget — failure here must not block hunt init.
    SandboxExecutor.reapOrphans().catch((err) => {
      console.warn('[orchestrator] Orphan reap failed (non-fatal):', err);
    });

    program.scope.inScope = normalizeScopeEntries(program.scope.inScope);
    this.loadGuidelines(program);
    this.setPhase('hunting');

    const taskQueue = new TaskQueue();
    this.huntSession = {
      program,
      taskQueue,
      allFindings: [],
      chains: [],
      targetScores: [],
      activeAgents: 0,
      completedDispatches: 0,
      running: true,
      aborted: false,
      failedTasks: [],
    };

    // Score targets
    const targetMetadata: TargetMetadata[] = program.scope.inScope.map(target => ({
      target,
      historicalPayouts: {
        min: program.bountyRange.min,
        max: program.bountyRange.max,
        average: Math.round((program.bountyRange.min + program.bountyRange.max) / 2),
      },
    }));
    this.huntSession.targetScores = rankTargets(targetMetadata);

    this.emitOrchestratorMessage(
      `Hunt initialized for **${program.programName}**.\n\n` +
      `Scored ${this.huntSession.targetScores.length} targets. ` +
      `Top target: ${this.huntSession.targetScores[0]?.target ?? 'none'} ` +
      `(score: ${this.huntSession.targetScores[0]?.totalScore ?? 0}/100)`
    );

    // Start OOB server for blind vulnerability detection
    if (this.onExecuteCommand) {
      try {
        this.oobServer = new OOBServer({
          executeCommand: this.onExecuteCommand,
          onInteraction: (callback: OOBCallback) => {
            this.emitSystemMessage(
              `OOB callback triggered: ${callback.id} (${callback.interaction?.protocol ?? 'unknown'} from ${callback.interaction?.sourceIp ?? 'unknown'})`,
              'success'
            );
            postBBFinding(this.blackboard, 'oob_server', 'oob_callback', {
              callbackId: callback.id,
              protocol: callback.interaction?.protocol,
              sourceIp: callback.interaction?.sourceIp,
              injectionPoint: callback.injectionPoint,
            }, ['ssrf', 'ssti', 'sqli', 'xss']);
          },
        });
        const oobBaseUrl = await this.oobServer.start();
        this.emitSystemMessage(`OOB server started: ${oobBaseUrl}`, 'info');
      } catch (error) {
        this.emitSystemMessage(
          `OOB server failed to start: ${error instanceof Error ? error.message : String(error)}`,
          'warning'
        );
        this.oobServer = undefined;
      }
    }

    setValidatorOOBServer(this.oobServer);
    this.feedbackLoop.startPolling();
  }

  async startHunt(program: ProgramGuidelines): Promise<void> {
    // Initialize session if not already done
    await this.initializeHuntSession(program);
    if (!this.huntSession) return;

    const { taskQueue } = this.huntSession;

    // ── Tool Availability Check ──
    // Verify which external tools are installed before dispatching agents
    if (this.onExecuteCommand) {
      const toolChecks = [
        { name: 'subfinder', cmd: 'subfinder -version', agents: ['recon'] },
        { name: 'httpx', cmd: 'httpx -version', agents: ['recon'] },
        { name: 'nuclei', cmd: 'nuclei -version', agents: ['recon'] },
        { name: 'katana', cmd: 'katana -version', agents: ['recon'] },
        { name: 'naabu', cmd: 'naabu -version', agents: ['recon'] },
        { name: 'curl', cmd: 'curl --version', agents: ['*'] },
      ];

      const missing: string[] = [];
      const installed: string[] = [];

      for (const tool of toolChecks) {
        try {
          const result = await this.onExecuteCommand(tool.cmd, '');
          if (result.success || result.exitCode === 0) {
            installed.push(tool.name);
          } else {
            missing.push(tool.name);
          }
        } catch {
          missing.push(tool.name);
        }
      }

      if (missing.length > 0) {
        this.emitSystemMessage(
          `Missing tools: ${missing.join(', ')}. Some agents may have reduced capability. Install with: apt install ${missing.join(' ')}`,
          'warning'
        );
      }

      // Store available tools so agents can check them
      postObservation(this.blackboard, 'orchestrator', 'tool_availability', {
        installed,
        missing,
      }, getAllAgents().map(a => a.metadata.id));
    }

    // Start continuous monitor if available
    if (this.continuousMonitor) {
      const domains = program.scope.inScope.filter(s => !s.startsWith('*'));
      for (const domain of domains) {
        this.continuousMonitor.addDomain(domain);
      }
      this.continuousMonitor.start();
    }

    // ── Create initial recon tasks for top-priority targets ──
    const topTargets = this.huntSession.targetScores.slice(0, Math.min(5, this.huntSession.targetScores.length));

    for (const scored of topTargets) {
      taskQueue.enqueue({
        description: `Reconnaissance on ${scored.target}: subdomain enumeration, HTTP probing, tech fingerprinting, WAF detection`,
        target: scored.target,
        agentType: 'recon',
        priority: Math.round(scored.totalScore / 10),
        dependencies: [],
        iterationBudget: 40,
        origin: 'initial',
        tags: ['recon', 'initial'],
      });
    }

    // Emit alloy status if active
    if (this.alloyInstance && this.alloyConfig?.enabled) {
      const primary = this.provider.displayName;
      const secondary = this.alloyConfig.secondaryLabel ?? this.alloyConfig.secondaryProvider.displayName;
      const weight = this.alloyConfig.primaryWeight;
      this.emitSystemMessage(
        `Alloy mode active: ${primary} + ${secondary} (${weight}% / ${100 - weight}%)`,
        'info'
      );
    }

    this.emitOrchestratorMessage(
      `Created ${topTargets.length} initial recon tasks. Starting dispatch loop...`
    );

    // ── Step 4: Enter the dispatch loop ──
    await this.runDispatchLoop();
  }

  /**
   * Dispatch a single agent for a specific task from the queue.
   *
   * 1. Gets the task from the queue
   * 2. Finds or creates the right agent from the catalog
   * 3. Runs the agent and collects results
   * 4. Generates follow-up tasks from findings
   * 5. Runs chain detection across all accumulated findings
   */
  async dispatchAgent(taskId: string): Promise<AgentResult | undefined> {
    if (!this.huntSession) {
      this.emitSystemMessage('No active hunt session. Call startHunt() first.', 'error');
      return undefined;
    }

    const task = this.huntSession.taskQueue.getTask(taskId);
    if (!task) {
      this.emitSystemMessage(`Task ${taskId} not found in queue.`, 'error');
      return undefined;
    }

    // S5: Guard against tasks with undefined/empty targets
    if (!task.target) {
      this.emitSystemMessage(
        `Skipping dispatch for ${task.agentType} (task ${taskId}): target is undefined. ` +
        `Origin: ${task.origin}, description: ${task.description.substring(0, 100)}`,
        'warning'
      );
      this.huntSession.taskQueue.fail(taskId, 'Task has no target — skipped dispatch');
      return undefined;
    }

    // Emit agent status to the chat
    const agentMsg: ConversationMessage = {
      type: 'agent',
      id: this.generateId(),
      agentId: task.agentType,
      agentName: this.getAgentDisplayName(task.agentType),
      content: `Starting: ${task.description}`,
      status: 'running',
      timestamp: Date.now(),
    };
    this.conversation.addMessage(agentMsg);
    this.emitMessage(agentMsg);

    this.huntSession.activeAgents++;

    // Create a sandboxed executor for this agent (falls back to PTY if Docker unavailable).
    // Thread active session auth through as env vars + ~/.curlrc so shell-tool
    // invocations (curl, ffuf, nuclei, sqlmap) inherit the session without the
    // LLM needing to paste tokens into commands. (Phase 1 / Q1)
    const scope = this.guidelines?.scope.inScope ?? [task.target];
    const activeSession = this.sessionManager?.listSessions()[0];
    const sessionEnv = buildSessionEnv(activeSession);
    const sandboxedExec = await createSandboxedExecutor(
      scope,
      this.onExecuteCommand,
      activeSession
        ? { envVars: sessionEnv.envVars, curlrc: sessionEnv.curlrcContent }
        : undefined,
    );

    if (sandboxedExec.usingSandbox) {
      this.emitSystemMessage(`Agent ${task.agentType}: using Docker sandbox`, 'info');
    }

    // Log the model tier this agent will use
    const { model: routedModel } = this.getAgentProviderAndModel(task.agentType, task.description);
    if (routedModel !== this.model) {
      this.emitSystemMessage(`Agent ${task.agentType}: routed to ${routedModel}`, 'info');
    }

    try {
      // Look up the agent in the catalog
      const entry = getAgentEntry(task.agentType);
      if (!entry) {
        // Try fuzzy matching by vulnerability class
        const matches = findAgentsForVulnClass(task.agentType);
        if (matches.length === 0) {
          throw new Error(`No agent found for type: ${task.agentType}`);
        }
        // Use the first match
        const agent = matches[0].factory();
        const { provider: agentProvider, model: agentModel } = this.getAgentProviderAndModel(task.agentType, task.description);
        await agent.initialize(agentProvider, agentModel);

        // Wire sandbox-backed command execution into the agent
        if ('setCallbacks' in agent && typeof agent.setCallbacks === 'function') {
          (agent as { setCallbacks: (cb: Record<string, unknown>) => void }).setCallbacks({
            onExecuteCommand: sandboxedExec.executeCommand,
            onApprovalRequest: this.onApprovalRequest,
            autoApproveSafe: this.autoApproveSafe,
          });
        }

        const agentTask = await this.huntTaskToAgentTask(task);
        const result = await agent.execute(agentTask);
        await agent.cleanup();
        return this.handleAgentResult(task, result);
      }

      // Instantiate and run the agent
      const agent = entry.factory();
      const { provider: agentProvider, model: agentModel } = this.getAgentProviderAndModel(task.agentType, task.description);
      await agent.initialize(agentProvider, agentModel);

      // Wire sandbox-backed command execution into the agent
      if ('setCallbacks' in agent && typeof agent.setCallbacks === 'function') {
        (agent as { setCallbacks: (cb: Record<string, unknown>) => void }).setCallbacks({
          onExecuteCommand: sandboxedExec.executeCommand,
          onApprovalRequest: this.onApprovalRequest,
          autoApproveSafe: this.autoApproveSafe,
        });
      }

      const agentTask = await this.huntTaskToAgentTask(task);
      const result = await agent.execute(agentTask);
      await agent.cleanup();

      return this.handleAgentResult(task, result);
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      this.huntSession.taskQueue.fail(taskId, errMsg);
      this.huntSession.activeAgents--;

      // Track error for circuit breaker detection
      this.recentAgentErrors.push(errMsg);
      if (this.recentAgentErrors.length > 10) this.recentAgentErrors.shift();

      const failMsg: ConversationMessage = {
        type: 'agent',
        id: this.generateId(),
        agentId: task.agentType,
        agentName: this.getAgentDisplayName(task.agentType),
        content: `Failed: ${errMsg}`,
        status: 'failed',
        timestamp: Date.now(),
      };
      this.conversation.addMessage(failMsg);
      this.emitMessage(failMsg);

      return undefined;
    } finally {
      // I5: Guarantee sandbox cleanup on every exit path — success, error, or
      // unexpected throw. cleanup() is idempotent (SandboxExecutor.destroy
      // short-circuits when already destroyed).
      await sandboxedExec.cleanup().catch((err) => {
        console.warn('[dispatchAgent] sandbox cleanup warning:', err);
      });
    }
  }

  /** Delegate to the exported helper */
  private isTransientError(errMsg: string): boolean {
    return isTransientError(errMsg);
  }

  /**
   * Dispatch an agent with retry for transient failures.
   * Retries up to MAX_AGENT_RETRIES times with exponential backoff.
   * On permanent failure or retry exhaustion, adds to dead-letter queue.
   */
  private async dispatchWithRetry(taskId: string, agentType: string): Promise<void> {
    // H25: Check global API limit flag before dispatching
    if (this.apiLimitReached) {
      this.emitSystemMessage(
        `Skipping ${agentType} dispatch — API usage limit reached. Resume hunt when limit resets.`,
        'warning'
      );
      return;
    }

    let lastError = '';
    for (let attempt = 0; attempt <= OrchestratorEngine.MAX_AGENT_RETRIES; attempt++) {
      try {
        await this.dispatchAgent(taskId);
        return; // Success — no retry needed
      } catch (err: unknown) {
        lastError = err instanceof Error ? err.message : String(err);

        // H25: Detect API account-level limit on first occurrence
        if (isApiLimitError(lastError)) {
          this.apiLimitReached = true;
          if (this.huntSession) {
            this.huntSession.running = false;
          }
          this.emitSystemMessage(
            `**API usage limit reached.** Hunt paused — all agent dispatches blocked.\n\n` +
            `Error: ${lastError.substring(0, 300)}\n\n` +
            `To resume: wait for the limit to reset, use a different API key, or increase your spending limit.`,
            'error'
          );
          return; // Don't retry — the entire account is blocked
        }

        // Don't retry permanent failures
        if (!this.isTransientError(lastError)) {
          break;
        }

        // Don't retry if this was the last attempt
        if (attempt === OrchestratorEngine.MAX_AGENT_RETRIES) {
          break;
        }

        // Exponential backoff: 2s, 4s, 8s
        const delay = OrchestratorEngine.RETRY_BASE_DELAY_MS * Math.pow(2, attempt);
        this.emitSystemMessage(
          `Agent ${agentType} failed (attempt ${attempt + 1}/${OrchestratorEngine.MAX_AGENT_RETRIES + 1}): ` +
          `${lastError.substring(0, 100)}. Retrying in ${delay / 1000}s...`,
          'warning'
        );
        await this.sleep(delay);
      }
    }

    // All retries exhausted or permanent failure — add to dead-letter queue
    if (this.huntSession) {
      this.huntSession.failedTasks.push({
        taskId,
        agentType,
        error: lastError,
        attempts: OrchestratorEngine.MAX_AGENT_RETRIES + 1,
        timestamp: Date.now(),
      });
      this.emitSystemMessage(
        `Agent ${agentType} permanently failed after retries. Added to dead-letter queue. Error: ${lastError.substring(0, 200)}`,
        'error'
      );
    }
  }

  /**
   * Add an external finding (from an agent) to the conversation.
   */
  addFinding(finding: Omit<FindingCardMessage, 'type' | 'id' | 'timestamp'>): void {
    const msg: FindingCardMessage = {
      type: 'finding_card',
      id: this.generateId(),
      timestamp: Date.now(),
      ...finding,
    };
    this.conversation.addMessage(msg);
    this.emitMessage(msg);
  }

  /**
   * Run SAST analysis on provided source files.
   * Posts findings to the blackboard and emits them to the chat.
   */
  async runSAST(files: SourceFile[]): Promise<SASTReport> {
    this.emitSystemMessage(`Running SAST analysis on ${files.length} file(s)...`, 'info');

    const analyzer = new SASTAnalyzer(this.provider, this.model);
    const report = await analyzer.analyzeRepository(files, {
      targetUrl: this.guidelines?.scope.inScope[0],
    });

    // Emit findings to the chat
    for (const finding of report.findings) {
      this.addFinding({
        title: `[SAST] ${finding.title}`,
        severity: finding.severity as Severity,
        description: `${finding.description}\n\nFile: ${finding.filePath}:${finding.line}\nCWE: ${finding.cweId ?? 'N/A'}\n\nVulnerable code:\n\`\`\`\n${finding.vulnerableCode}\n\`\`\`\n\nSuggested fix:\n${finding.suggestedFix}`,
        target: finding.filePath,
        agent: 'sast-analyzer',
        evidence: [`${finding.filePath}:${finding.line}: ${finding.vulnerableCode}`],
        isDuplicate: false,
        validationStatus: 'confirmed', // SAST findings are code-level, confirmed by analysis
      });
    }

    this.emitSystemMessage(
      `SAST complete: ${report.totalIssues} issue(s) found ` +
      `(${report.criticalCount} critical, ${report.highCount} high, ${report.mediumCount} medium, ${report.lowCount} low)`,
      report.criticalCount > 0 ? 'warning' : 'info'
    );

    return report;
  }

  /**
   * Abort the active hunt.
   */
  abortHunt(): void {
    if (this.huntSession) {
      this.huntSession.aborted = true;
      this.huntSession.running = false;
      this.stopHuntServices();
      this.emitSystemMessage('Hunt aborted by user.', 'warning');
      this.setPhase('complete');
    }
  }

  /** Reset for a new session */
  reset(): void {
    if (this.huntSession) {
      this.huntSession.aborted = true;
      this.huntSession.running = false;
    }
    this.stopHuntServices();
    this.huntSession = undefined;
    this.conversation.clear();
    this.currentPlan = undefined;
    this.guidelines = undefined;
    this.blackboard.clear();
    this.setPhase('idle');
  }

  /** Stop services that run during a hunt (OOB server, feedback polling, browser) */
  private stopHuntServices(): void {
    if (this.oobServer) {
      this.oobServer.stop();
      this.oobServer = undefined;
    }
    setValidatorOOBServer(undefined);
    shutdownValidationBrowser().catch(() => {});
    this.feedbackLoop.stopPolling();
    this.continuousMonitor?.stop();
  }

  /** Persist session state for crash recovery */
  checkpoint(): void {
    if (!this.huntSession) return;

    try {
      const snapshot = {
        version: 1,
        timestamp: Date.now(),
        program: this.huntSession.program,
        findings: this.huntSession.allFindings.map(f => ({
          ...f,
          timestamp: f.timestamp instanceof Date ? f.timestamp.toISOString() : f.timestamp,
        })),
        chains: this.huntSession.chains,
        targetScores: this.huntSession.targetScores,
        completedDispatches: this.huntSession.completedDispatches,
        phase: this.currentPhase,
      };

      localStorage.setItem('huntress_session_checkpoint', JSON.stringify(snapshot));
    } catch {
      // Best-effort — storage may be unavailable
    }
  }

  /** Restore a previously checkpointed session. Returns true if restoration succeeded. */
  restore(): boolean {
    try {
      const raw = localStorage.getItem('huntress_session_checkpoint');
      if (!raw) return false;

      const snapshot = JSON.parse(raw);
      if (!snapshot.program || snapshot.version !== 1) return false;

      // Rebuild a minimal hunt session from the checkpoint
      const taskQueue = new TaskQueue();
      this.huntSession = {
        program: snapshot.program,
        taskQueue,
        allFindings: (snapshot.findings ?? []).map((f: Record<string, unknown>) => ({
          ...f,
          timestamp: new Date(f.timestamp as string),
        })),
        chains: snapshot.chains ?? [],
        targetScores: snapshot.targetScores ?? [],
        activeAgents: 0,
        completedDispatches: snapshot.completedDispatches ?? 0,
        running: false,
        aborted: false,
        failedTasks: snapshot.failedTasks ?? [],
      };

      this.loadGuidelines(snapshot.program);
      this.setPhase(snapshot.phase ?? 'idle');

      return true;
    } catch {
      return false;
    }
  }

  /** Clear any persisted checkpoint */
  clearCheckpoint(): void {
    try {
      localStorage.removeItem('huntress_session_checkpoint');
    } catch { /* best-effort */ }
  }

  /** Check if a checkpoint exists for resumption */
  static hasCheckpoint(): boolean {
    try {
      return localStorage.getItem('huntress_session_checkpoint') !== null;
    } catch {
      return false;
    }
  }

  // ─── Coordinator-Solver: Dispatch Loop ──────────────────────────────────────

  /**
   * The main dispatch loop. Runs continuously until the task queue is drained,
   * the coordinator calls stop_hunting, or the hunt is aborted.
   *
   * Each iteration:
   * 1. Dequeue a batch of runnable tasks
   * 2. Dispatch agents in parallel (up to maxConcurrentAgents)
   * 3. Collect results, generate follow-ups
   * 4. Ask the coordinator model what to do next (tool use turn)
   * 5. Process any tool calls (dispatch_agent, reprioritize_tasks, etc.)
   */
  private async runDispatchLoop(): Promise<void> {
    if (!this.huntSession) return;
    if (this.dispatchLoopRunning) return; // Prevent concurrent loops
    this.dispatchLoopRunning = true;
    const { taskQueue } = this.huntSession;

    while (this.huntSession.running && !this.huntSession.aborted) {
      // Kill switch check — stop dispatching immediately if activated
      if (await this.isKillSwitchActive()) {
        this.emitSystemMessage(
          'Kill switch activated — halting all hunt operations immediately.',
          'error'
        );
        this.huntSession.aborted = true;
        break;
      }

      // Budget enforcement — check before dispatching new agents
      if (this.getBudgetStatus) {
        const budget = this.getBudgetStatus();
        if (budget.isExceeded) {
          this.emitSystemMessage(
            `**Budget exceeded** — $${budget.spent.toFixed(2)} spent of $${budget.limit.toFixed(2)} limit. ` +
            `Stopping hunt to prevent further charges.`,
            'error'
          );
          this.huntSession.aborted = true;
          break;
        }
        if (budget.isWarning && !this.budgetSoftStopped) {
          this.budgetSoftStopped = true;
          this.emitSystemMessage(
            `**Budget warning** — $${budget.spent.toFixed(2)} spent (${Math.round(budget.percentUsed * 100)}% of $${budget.limit.toFixed(2)}). ` +
            `No new agents will be dispatched. Waiting for ${this.huntSession.activeAgents} running agents to complete.`,
            'warning'
          );
          // Don't dispatch new agents, but let running ones finish
          if (this.huntSession.activeAgents > 0) {
            await this.sleep(2000);
            continue;
          }
          break;
        }
        if (this.budgetSoftStopped) {
          // Already in soft-stop: wait for running agents to finish
          if (this.huntSession.activeAgents > 0) {
            await this.sleep(2000);
            continue;
          }
          break;
        }
      }

      // Wait for running agents if all slots occupied
      const availableSlots = this.maxConcurrentAgents - this.huntSession.activeAgents;
      if (availableSlots <= 0) {
        await this.sleep(1000);
        continue;
      }

      // H25: Check global API limit — stop dispatching immediately
      if (this.apiLimitReached) {
        this.emitSystemMessage('Hunt paused: API usage limit reached. No new agents will be dispatched.', 'warning');
        break;
      }

      // Dequeue a batch of runnable tasks
      const batch = taskQueue.dequeueBatch(availableSlots);
      if (batch.length === 0) {
        // Nothing runnable right now — either agents are still running or hunt is done
        if (this.huntSession.activeAgents > 0) {
          // Agents still in-flight — they may generate follow-up tasks when they complete
          await this.sleep(1000);
          continue;
        }

        // No running agents AND no runnable tasks — check if there are any queued tasks
        // with unmet dependencies (they'll become runnable when dependencies complete)
        const stats = taskQueue.getStats();
        if (stats.queued > 0) {
          // Tasks exist but dependencies aren't met — wait briefly
          await this.sleep(1000);
          continue;
        }

        // Truly idle: no running, no runnable, no queued — ask coordinator what to do
        const shouldContinue = await this.askCoordinatorForNextSteps();
        if (!shouldContinue) break;

        // Re-check after coordinator may have dispatched new tasks
        if (!taskQueue.hasRunnableTasks() && this.huntSession.activeAgents === 0) {
          break;
        }
        continue;
      }

      // Dispatch all tasks in the batch — fire-and-forget with retry so the loop keeps cycling.
      // Each agent manages its own lifecycle via handleAgentResult() which decrements
      // activeAgents and generates follow-up tasks. The loop will pick up new tasks
      // and free slots on the next iteration.
      for (const task of batch) {
        this.dispatchWithRetry(task.id, task.agentType).catch(err => {
          this.emitSystemMessage(
            `Agent dispatch error for ${task.agentType}: ${err instanceof Error ? err.message : String(err)}`,
            'error'
          );
        });
      }

      // Brief pause to let dispatched agents start and register as active
      await this.sleep(2000);

      // Circuit breaker: stop dispatching if we see repeated fatal errors
      if (this.recentAgentErrors.length >= OrchestratorEngine.CIRCUIT_BREAKER_THRESHOLD) {
        const lastErrors = this.recentAgentErrors.slice(-OrchestratorEngine.CIRCUIT_BREAKER_THRESHOLD);
        const isFatalPattern = lastErrors.every(e =>
          e.includes('credit balance is too low') ||
          e.includes('invalid_api_key') ||
          e.includes('authentication_error') ||
          e.includes('insufficient_quota')
        );
        if (isFatalPattern) {
          this.emitSystemMessage(
            `Hunt stopped: ${OrchestratorEngine.CIRCUIT_BREAKER_THRESHOLD} consecutive agents failed with the same API error. ` +
            `Check your API key credits and try again.\n\nLast error: ${lastErrors[lastErrors.length - 1]?.substring(0, 200)}`,
            'error'
          );
          break;
        }
      }

      // Run chain detection on accumulated findings (runs every loop iteration)
      if (this.huntSession.allFindings.length > 0) {
        const newChains = detectChains(this.huntSession.allFindings);
        const previousChainIds = new Set(this.huntSession.chains.map(c => c.id));
        const freshChains = newChains.filter(c => !previousChainIds.has(c.id));

        if (freshChains.length > 0) {
          // S2: Validate chains end-to-end (not just title matching)
          if (this.chainValidator) {
            for (const chain of freshChains) {
              try {
                const validation = await this.chainValidator.validateChain(chain);
                if (validation.isExploitable) {
                  chain.validated = true;
                  chain.confidenceBoost = Math.round((validation.confidence ?? 0) * 100);
                }
                // If not exploitable, validated stays false (set by detectChains)
              } catch {
                // Chain validation is best-effort — chain stays unvalidated
              }
            }
          }

          this.huntSession.chains.push(...freshChains);
          for (const chain of freshChains) {
            // S2: Distinguish confirmed vs potential chains in UI
            const chainLabel = chain.validated ? 'Confirmed Chain' : 'Potential Chain (needs manual verification)';
            this.emitOrchestratorMessage(
              `**${chainLabel}: ${chain.name}**\n` +
              `Combined severity: **${chain.combinedSeverity.toUpperCase()}**\n` +
              `${chain.description}\n\n` +
              `Chain steps:\n${chain.chainSteps.map(s => `  - ${s}`).join('\n')}`
            );
          }
        }
      }

      // Emit progress with cost tracking
      const stats = taskQueue.getStats();
      const budgetInfo = this.getBudgetStatus
        ? (() => {
            const b = this.getBudgetStatus!();
            return ` | Cost: $${b.spent.toFixed(2)}/$${b.limit.toFixed(2)}`;
          })()
        : '';
      this.emitSystemMessage(
        `Progress: ${stats.done} done, ${stats.running} running, ${stats.queued} queued, ` +
        `${stats.failed} failed | Findings: ${this.huntSession.allFindings.length} | ` +
        `Chains: ${this.huntSession.chains.length}${budgetInfo}`,
        'info'
      );

      // Checkpoint session state after each batch for crash recovery
      this.checkpoint();
    }

    // Hunt complete — stop services and clear checkpoint
    this.dispatchLoopRunning = false;
    this.huntSession.running = false;
    this.stopHuntServices();
    this.clearCheckpoint();
    this.setPhase('reporting');

    const finalStats = taskQueue.getStats();
    this.emitOrchestratorMessage(
      `Hunt complete for **${this.huntSession.program.programName}**.\n\n` +
      `**Summary:**\n` +
      `- Tasks executed: ${finalStats.done}\n` +
      `- Tasks failed: ${finalStats.failed}\n` +
      `- Total findings: ${this.huntSession.allFindings.length}\n` +
      `- Vulnerability chains: ${this.huntSession.chains.length}\n\n` +
      (this.huntSession.allFindings.length > 0
        ? `**Findings:**\n${this.huntSession.allFindings.map(f =>
            `  - [${f.severity.toUpperCase()}] ${f.title} at ${f.target}`
          ).join('\n')}`
        : 'No vulnerabilities discovered in this session.')
    );
  }

  /**
   * Ask the coordinator model what to do next, using native tool use.
   * The model can dispatch new agents, reprioritize, generate reports, or stop.
   * Returns true if the hunt should continue, false if it should stop.
   */
  private async askCoordinatorForNextSteps(): Promise<boolean> {
    if (!this.huntSession) return false;

    const stats = this.huntSession.taskQueue.getStats();
    const findingsSummary = this.huntSession.allFindings
      .map(f => `- id: "${f.id}" | [${f.severity}] ${f.title} at ${f.target}`)
      .join('\n') || 'None so far';

    const chainsSummary = this.huntSession.chains
      .map(c => `[${c.combinedSeverity}] ${c.name}: ${c.description}`)
      .join('\n') || 'None detected';

    const availableAgents = getAllAgents()
      .map(a => `${a.metadata.id}: ${a.metadata.description}`)
      .join('\n');

    const prompt = `The current hunt status:

## Task Queue
- Total: ${stats.total}, Done: ${stats.done}, Failed: ${stats.failed}, Queued: ${stats.queued}

## Findings So Far
${findingsSummary}

## Vulnerability Chains
${chainsSummary}

## Available Agents
${availableAgents}

## In-Scope Targets
${this.huntSession.program.scope.inScope.join(', ')}

Based on the current findings and progress, decide what to do next:
- Use dispatch_agent to send a specialist to investigate a target
- Use reprioritize_tasks if findings change priorities
- Use generate_report if a finding is ready for writeup
- Use stop_hunting if the hunt is complete

What is your next action?`;

    const contextMessages = this.conversation.getMessagesForModel();
    contextMessages.push({ role: 'user', content: prompt });

    try {
      const response = await this.provider.sendMessage(contextMessages, {
        model: this.model,
        maxTokens: 4096,
        systemPrompt: this.buildSystemPrompt(),
        tools: ORCHESTRATOR_TOOL_SCHEMAS,
        toolChoice: 'auto',
      });

      // If the model returned text with no tool calls, it is done thinking
      if (!response.toolCalls?.length) {
        // The model chose not to use any tool — treat as stop
        if (response.content) {
          this.emitOrchestratorMessage(response.content);
        }
        return false;
      }

      // Process tool calls
      return await this.processCoordinatorToolCalls(response);
    } catch (error) {
      this.emitSystemMessage(
        `Coordinator decision error: ${error instanceof Error ? error.message : String(error)}`,
        'error'
      );
      return false;
    }
  }

  // ─── Tool Call Handling ─────────────────────────────────────────────────────

  /**
   * Handle tool calls from the coordinator model during user interaction.
   * Adds the assistant message with content blocks, processes each tool call,
   * and feeds results back to the conversation.
   */
  private async handleCoordinatorToolCalls(response: ChatResponse): Promise<void> {
    // Emit any text content the model produced alongside tool calls
    if (response.content) {
      this.emitOrchestratorMessage(response.content);
    }

    if (!response.toolCalls) return;

    // Check if any dispatch_agent calls are coming. If so, ensure a hunt session
    // exists BEFORE processing them (dispatch_agent requires huntSession).
    const hasDispatchCalls = response.toolCalls.some(tc => tc.name === 'dispatch_agent');
    if (hasDispatchCalls && !this.huntSession && this.guidelines) {
      this.emitSystemMessage('Auto-starting hunt session for agent dispatch...', 'info');
      // Create the hunt session synchronously via startHunt, but DON'T await the
      // full dispatch loop — we'll kick that off after processing tool calls.
      await this.initializeHuntSession(this.guidelines);
    }

    let dispatchedAgents = false;
    for (const toolCall of response.toolCalls) {
      await this.executeCoordinatorTool(toolCall);
      if (toolCall.name === 'dispatch_agent') {
        dispatchedAgents = true;
      }
    }

    // If agents were dispatched, ensure the dispatch loop is running to process them.
    if (dispatchedAgents && this.huntSession && !this.dispatchLoopRunning) {
      this.huntSession.running = true;
      this.huntSession.aborted = false;
      this.budgetSoftStopped = false;
      this.emitSystemMessage('Starting dispatch loop for queued agents...', 'info');
      // Fire-and-forget — the loop runs concurrently with the conversation
      this.runDispatchLoop().catch(err => {
        this.emitSystemMessage(
          `Dispatch loop error: ${err instanceof Error ? err.message : String(err)}`,
          'error'
        );
      });
    }
  }

  /**
   * Process tool calls from the coordinator's "what next?" decision turn.
   * Returns true if the hunt should continue, false if stop_hunting was called.
   */
  private async processCoordinatorToolCalls(response: ChatResponse): Promise<boolean> {
    if (response.content) {
      this.emitOrchestratorMessage(response.content);
    }

    if (!response.toolCalls) return false;

    let shouldContinue = true;
    let dispatchedNewAgents = false;
    let stopRequested = false;
    let stopInput: { reason: string; summary: string; recommendations?: string[] } | undefined;

    for (const toolCall of response.toolCalls) {
      if (toolCall.name === 'stop_hunting') {
        stopInput = toolCall.input as { reason: string; summary: string; recommendations?: string[] };
        stopRequested = true;
      } else {
        await this.executeCoordinatorTool(toolCall);
        if (toolCall.name === 'dispatch_agent') {
          dispatchedNewAgents = true;
        }
      }
    }

    // If the model dispatched new agents AND called stop_hunting in the same turn,
    // the dispatch calls win — we need the loop to keep running so those agents execute.
    // The model often treats tool calls as a batch plan, not realizing stop_hunting
    // is terminal and would prevent the dispatched agents from running.
    if (stopRequested && dispatchedNewAgents) {
      this.emitSystemMessage(
        'Coordinator requested stop alongside new dispatches — continuing to let dispatched agents run.',
        'info'
      );
      shouldContinue = true;
    } else if (stopRequested) {
      this.emitOrchestratorMessage(
        `**Stopping hunt:** ${stopInput!.reason}\n\n${stopInput!.summary}` +
        (stopInput!.recommendations?.length
          ? `\n\n**Recommendations:**\n${stopInput!.recommendations.map(r => `  - ${r}`).join('\n')}`
          : '')
      );
      shouldContinue = false;
    }

    return shouldContinue;
  }

  /**
   * Execute a single coordinator tool call.
   * Handles dispatch_agent, reprioritize_tasks, generate_report, and stop_hunting.
   */
  private async executeCoordinatorTool(toolCall: ToolUseBlock): Promise<void> {
    const { name, input } = toolCall;

    switch (name) {
      case 'dispatch_agent': {
        const args = input as {
          agent_type: string;
          task_description: string;
          target: string;
          priority: number;
          iteration_budget?: number;
        };

        if (!this.huntSession) {
          this.emitSystemMessage('Cannot dispatch agent: no active hunt session.', 'error');
          return;
        }

        // S5: Guard against undefined/empty target from orchestrator LLM
        if (!args.target) {
          this.emitSystemMessage(
            `Blocked dispatch for ${args.agent_type}: target is undefined or empty. ` +
            `Task: ${args.task_description?.substring(0, 100) ?? 'none'}`,
            'warning'
          );
          return;
        }

        // Validate the target is in scope
        const inScope = this.huntSession.program.scope.inScope.some(s =>
          this.isTargetInScope(args.target, s)
        );

        if (!inScope) {
          this.emitSystemMessage(
            `Blocked dispatch: ${args.target} is not in scope.`,
            'warning'
          );
          return;
        }

        // Check for duplicate target+agent combinations before queuing
        if (this.huntSession) {
          const dedupKey = `${args.agent_type}:${args.target}`;
          const existingTasks = this.huntSession.taskQueue.getAllTasks();
          const alreadyQueued = existingTasks.some(
            t => t.agentType === args.agent_type && t.target === args.target
          );
          if (alreadyQueued) {
            this.emitSystemMessage(
              `Skipping duplicate: ${args.agent_type} already queued for ${args.target}`,
              'info'
            );
            return;
          }
        }

        // Enqueue the task
        const task = this.huntSession.taskQueue.enqueue({
          description: args.task_description,
          target: args.target,
          agentType: args.agent_type,
          priority: args.priority,
          dependencies: [],
          iterationBudget: args.iteration_budget ?? 40,
          origin: 'orchestrator',
          tags: [args.agent_type],
        });

        this.emitOrchestratorMessage(
          `Dispatching **${this.getAgentDisplayName(args.agent_type)}** ` +
          `to ${args.target} (priority: ${args.priority})\n` +
          `Task: ${args.task_description}`
        );
        break;
      }

      case 'reprioritize_tasks': {
        const args = input as { reasoning: string; findings_summary?: string };

        if (!this.huntSession) return;

        // Use all accumulated findings to reprioritize the queue
        this.huntSession.taskQueue.reprioritize(this.huntSession.allFindings);

        this.emitOrchestratorMessage(
          `**Tasks reprioritized** based on findings.\nReasoning: ${args.reasoning}`
        );
        break;
      }

      case 'generate_report': {
        const args = input as { finding_id: string };

        // Look up by exact ID first, then fall back to partial title match
        let finding = this.huntSession?.allFindings.find(f => f.id === args.finding_id);
        if (!finding) {
          // Model may have passed a title or partial title instead of the hash ID
          const needle = args.finding_id.toLowerCase();
          finding = this.huntSession?.allFindings.find(
            f => f.title.toLowerCase().includes(needle) || needle.includes(f.title.toLowerCase())
          );
        }
        if (!finding) {
          this.emitSystemMessage(
            `Finding ${args.finding_id} not found. Available: ${
              this.huntSession?.allFindings.map(f => `${f.id} (${f.title})`).join(', ') || 'none'
            }`,
            'error'
          );
          return;
        }

        // Emit the finding as a card in the chat
        this.addFinding({
          title: finding.title,
          severity: finding.severity as Severity,
          description: finding.description,
          target: finding.target,
          agent: finding.agentId,
          evidence: finding.evidence,
          isDuplicate: false,
          validationStatus: finding.validationStatus ?? 'pending',
          validationEvidence: finding.validationEvidence,
          validationConfidence: finding.validationConfidence,
          duplicateCheck: finding.duplicateCheck,
        });

        this.emitOrchestratorMessage(
          `Report generated for: **${finding.title}** [${finding.severity.toUpperCase()}]`
        );
        break;
      }

      case 'adjust_budget': {
        const args = input as { new_budget_usd: number; reason?: string };
        const newBudget = args.new_budget_usd;

        // Validate: positive and within reasonable cap
        if (newBudget <= 0 || newBudget > 500) {
          this.emitSystemMessage(
            `Budget adjustment rejected: $${newBudget} is out of range. Must be between $0.01 and $500.`,
            'error'
          );
          break;
        }

        // Validate: cannot decrease below current spend
        const currentBudget = this.getBudgetStatus?.();
        if (currentBudget && newBudget < currentBudget.spent) {
          this.emitSystemMessage(
            `Budget adjustment rejected: cannot set budget to $${newBudget.toFixed(2)} — ` +
            `already spent $${currentBudget.spent.toFixed(2)}.`,
            'error'
          );
          break;
        }

        const oldLimit = currentBudget?.limit ?? this.budgetLimitUsd;
        this.budgetLimitUsd = newBudget;

        // Update the actual budget in the cost tracker
        if (this.setBudgetLimit) {
          this.setBudgetLimit(newBudget);
        }

        this.emitOrchestratorMessage(
          `**Budget adjusted** from $${(oldLimit ?? 0).toFixed(2)} to $${newBudget.toFixed(2)}.` +
          (args.reason ? ` Reason: ${args.reason}` : '')
        );

        // If hunt was paused due to budget, resume dispatching
        if (this.huntSession && !this.huntSession.running && currentBudget && currentBudget.percentUsed >= 1.0) {
          this.huntSession.running = true;
          this.emitSystemMessage('Hunt resumed — budget increased above current spend.', 'info');
        }
        break;
      }

      case 'stop_hunting': {
        const args = input as { reason: string; summary: string; recommendations?: string[] };
        if (this.huntSession) {
          this.huntSession.running = false;
        }
        this.emitOrchestratorMessage(
          `**Stopping hunt:** ${args.reason}\n\n${args.summary}`
        );
        break;
      }

      default:
        this.emitSystemMessage(`Unknown coordinator tool: ${name}`, 'warning');
    }
  }

  // ─── Agent Result Processing ────────────────────────────────────────────────

  /**
   * Process results from a completed agent dispatch.
   * Adds findings to the global pool, generates follow-up tasks,
   * and emits findings to the chat.
   */
  private handleAgentResult(task: HuntTask, result: AgentResult): AgentResult {
    if (!this.huntSession) return result;

    // Mark the task as complete in the queue
    this.huntSession.taskQueue.complete(task.id, result);
    this.huntSession.activeAgents = Math.max(0, this.huntSession.activeAgents - 1);
    this.huntSession.completedDispatches++;

    // I1: Partition specialist_request entries out of the finding pipeline.
    // They are orchestration directives, not vulnerabilities — routing them
    // through validateFinding() produces "No validator available" noise.
    const specialistRequests = result.findings.filter(f => f.type === 'specialist_request');
    result.findings = result.findings.filter(f => f.type !== 'specialist_request');
    for (const req of specialistRequests) {
      this.routeSpecialistRequest(req);
    }

    // Collect findings — deduplicate against existing findings first
    if (result.findings.length > 0) {
      // Normalize evidence at the pipeline boundary — agents may return
      // string, object, undefined, or array. All downstream code expects string[].
      for (const finding of result.findings) {
        finding.evidence = normalizeEvidence(finding.evidence);
        finding.reproduction = normalizeEvidence(finding.reproduction);
      }

      const combined = [...this.huntSession.allFindings, ...result.findings];
      const deduped = deduplicateFindings(combined);
      // Only add findings that survived dedup and aren't already in allFindings
      const existingIds = new Set(this.huntSession.allFindings.map(f => f.id));
      const newFindings = deduped.filter(f => !existingIds.has(f.id));
      this.huntSession.allFindings = deduped;

      // ─── Phase 3: Validation + Duplicate Check Pipeline ��────────────────────
      // 1. Emit each finding immediately with 'pending' status (non-blocking)
      // 2. Fire async validation (deterministic proof) per finding
      // 3. Fire async H1 duplicate check per finding
      // 4. Update finding status + emit status messages when async checks complete

      for (const finding of newFindings) {
        // Initialize finding with pending validation and not-checked duplicate status
        finding.validationStatus = 'pending';
        finding.duplicateCheck = { status: 'not_checked' };

        // Emit finding to chat immediately with pending status
        this.addFinding({
          title: finding.title,
          severity: finding.severity as Severity,
          description: finding.description,
          target: finding.target,
          agent: finding.agentId,
          evidence: finding.evidence,
          isDuplicate: false,
          validationStatus: 'pending',
          duplicateCheck: { status: 'not_checked' },
        });

        // Post finding to blackboard so other agents can discover it
        postBBFinding(this.blackboard, finding.agentId, finding.type ?? 'vulnerability', {
          title: finding.title,
          severity: finding.severity,
          target: finding.target,
          description: finding.description,
        }, getAllAgents().map(a => a.metadata.id));

        // ── Async Validation (fire-and-forget, updates finding on completion) ──
        this.runFindingValidation(finding).catch(() => {});

        // ── Async H1 Duplicate Check (fire-and-forget) ──
        this.runH1DuplicateCheck(finding).catch(() => {});

        // ── Async Cross-Hunt Duplicate Check (H26 — fire-and-forget) ──
        this.runCrossHuntDuplicateCheck(finding).catch(() => {});
      }

      // Reprioritize the queue based on new findings
      this.huntSession.taskQueue.reprioritize(result.findings);

      // Record to KnowledgeGraph (async, non-blocking)
      if (this.knowledgeGraph) {
        for (const finding of newFindings) {
          const huntResult: HuntResult = {
            sessionId: this.huntSession.program.programName,
            target: finding.target,
            agentId: finding.agentId,
            vulnType: finding.type ?? 'unknown',
            findingTitle: finding.title,
            severity: (finding.severity as HuntResult['severity']) ?? 'info',
            success: true,
            bountyAmount: 0,
            techniquesUsed: [],
            durationMs: result.duration,
            modelUsed: this.model,
            tokensUsed: 0,
            costUsd: 0,
          };
          this.knowledgeGraph.recordHuntResult(huntResult).catch(() => {});
        }
      }

      // Record to HuntMemory vector store (async, non-blocking, Phase 20E)
      if (this.huntMemory) {
        for (const finding of newFindings) {
          this.huntMemory.recordFinding({
            title: finding.title,
            vulnerabilityType: finding.type ?? 'unknown',
            severity: finding.severity ?? 'info',
            target: finding.target,
            description: finding.description,
            evidence: finding.evidence,
            confidence: 50,
          }, this.huntSession.program.programName).catch(() => {});
        }
      }

      // Record reward events (async, non-blocking)
      if (this.rewardSystem) {
        for (const finding of newFindings) {
          this.rewardSystem.recordEvent({
            sessionId: this.huntSession.program.programName,
            agentId: finding.agentId,
            eventType: 'FINDING_REPORTED',
            reason: `Found ${finding.title} on ${finding.target}`,
          }).catch(() => {});

          // Extra reward for high/critical severity
          if (finding.severity === 'critical') {
            this.rewardSystem.recordEvent({
              sessionId: this.huntSession.program.programName,
              agentId: finding.agentId,
              eventType: 'SEVERITY_CRITICAL',
              reason: `Critical finding: ${finding.title}`,
            }).catch(() => {});
          } else if (finding.severity === 'high') {
            this.rewardSystem.recordEvent({
              sessionId: this.huntSession.program.programName,
              agentId: finding.agentId,
              eventType: 'SEVERITY_HIGH',
              reason: `High finding: ${finding.title}`,
            }).catch(() => {});
          }
        }

        // Run shortcut detection on new findings
        const shortcutInputs: ShortcutCheckInput[] = newFindings.map(f => ({
          findingTitle: f.title,
          severity: f.severity,
          iterations: result.toolsExecuted,
          reproSteps: f.evidence.join('\n'),
          agentId: f.agentId,
        }));
        this.rewardSystem.detectShortcuts(shortcutInputs).then(shortcuts => {
          for (const s of shortcuts) {
            this.rewardSystem!.recordEvent({
              sessionId: this.huntSession?.program.programName ?? '',
              agentId: s.agentId,
              eventType: 'SHORTCUT_DETECTED',
              reason: s.explanation,
            }).catch(() => {});
            this.emitSystemMessage(`Shortcut detected (${s.agentId}): ${s.explanation}`, 'warning');
          }
        }).catch(() => {});
      }
    }

    // Post agent observations to blackboard for cross-agent knowledge sharing
    if (result.observations && result.observations.length > 0) {
      for (const obs of result.observations) {
        postObservation(this.blackboard, task.agentType, obs.category ?? 'general', {
          target: task.target,
          detail: obs.detail,
        }, obs.relevantTo ?? getAllAgents().map(a => a.metadata.id));
      }
    }

    // Generate follow-up tasks from the result (S5: pass parent target as fallback)
    const followUps = this.huntSession.taskQueue.generateFollowUpTasks(result, task.target);

    // After recon completes, generate focused SolverTask objects
    // with specific endpoints (not broad domains) and iteration budgets
    if (task.agentType === 'recon' && result.success) {
      const solverTasks = this.generateSolverTasks(task, result);
      followUps.push(...solverTasks);
    }

    if (followUps.length > 0) {
      this.emitSystemMessage(
        `Generated ${followUps.length} follow-up task(s) from ${this.getAgentDisplayName(task.agentType)} results.`,
        'info'
      );
    }

    // Track errors for circuit breaker (sliding window — reset after 5 consecutive successes)
    if (!result.success && result.error) {
      this.recentAgentErrors.push(result.error);
      if (this.recentAgentErrors.length > 10) this.recentAgentErrors.shift();
      this.consecutiveSuccesses = 0;
    } else if (result.success) {
      this.consecutiveSuccesses++;
      if (this.consecutiveSuccesses >= OrchestratorEngine.CIRCUIT_BREAKER_RESET_THRESHOLD) {
        this.recentAgentErrors = [];
        this.consecutiveSuccesses = 0;
      }
    }

    // Emit agent completion message
    const completionMsg: ConversationMessage = {
      type: 'agent',
      id: this.generateId(),
      agentId: task.agentType,
      agentName: this.getAgentDisplayName(task.agentType),
      content: result.success
        ? `Completed: ${result.findings.length} finding(s), ${result.toolsExecuted} tool calls in ${Math.round(result.duration / 1000)}s`
        : `Finished with errors: ${result.error ?? 'unknown'}`,
      status: result.success ? 'completed' : 'failed',
      timestamp: Date.now(),
    };
    this.conversation.addMessage(completionMsg);
    this.emitMessage(completionMsg);

    return result;
  }

  /**
   * I1: Route a specialist_request pseudo-finding to the dispatch queue.
   * Reconstructs agent_type/priority from the recon agent's encoding and
   * enqueues a task like dispatch_agent would. Skips if out of scope or
   * already queued.
   */
  private routeSpecialistRequest(finding: AgentFinding): void {
    if (!this.huntSession) return;

    // Title format: "Specialist requested: ${agentType}"
    const match = finding.title.match(/Specialist requested:\s*(\S+)/);
    const agentType = match?.[1];
    if (!agentType) {
      this.emitSystemMessage(
        `Ignored specialist_request with unparseable title: "${finding.title}"`,
        'warning'
      );
      return;
    }

    // Evidence format: ["Agent type: X", "Priority: Y"]
    const priorityStr = finding.evidence
      .find(e => e.toLowerCase().startsWith('priority:'))
      ?.split(':')[1]
      ?.trim();
    // Map string priority to numeric (dispatch uses number). Unknown → 50 (medium).
    const priority = priorityStr === 'high' ? 80
      : priorityStr === 'medium' ? 50
      : priorityStr === 'low' ? 20
      : 50;

    const target = finding.target;
    if (!target) return;

    // Scope gate — same policy as dispatch_agent
    const inScope = this.huntSession.program.scope.inScope.some(s =>
      this.isTargetInScope(target, s)
    );
    if (!inScope) {
      this.emitSystemMessage(
        `Ignored specialist_request: ${target} is not in scope.`,
        'warning'
      );
      return;
    }

    // Dedup against existing queued tasks
    const existingTasks = this.huntSession.taskQueue.getAllTasks();
    const alreadyQueued = existingTasks.some(
      t => t.agentType === agentType && t.target === target
    );
    if (alreadyQueued) return;

    this.huntSession.taskQueue.enqueue({
      description: finding.description || `Specialist ${agentType} requested from recon`,
      target,
      agentType,
      priority,
      dependencies: [],
      iterationBudget: 40,
      origin: 'orchestrator',
      tags: [agentType, 'specialist_request'],
    });
  }

  // ─── Phase 3: Async Validation & Duplicate Check ───────────────────────────

  /**
   * Run deterministic validation for a finding (fire-and-forget).
   * Converts AgentFinding → ReactFinding, runs the appropriate validator,
   * then updates the finding status and emits a status message.
   */
  private async runFindingValidation(finding: AgentFinding): Promise<void> {
    const reactFinding = agentFindingToReactFinding(finding);

    // Build ValidatorConfig with executeCommand routed through Tauri PTY
    const config: ValidatorConfig = {
      executeCommand: async (command: string, target: string): Promise<{
        success: boolean;
        stdout: string;
        stderr: string;
        exitCode: number;
        executionTimeMs: number;
      }> => {
        const startMs = Date.now();
        try {
          // Route through Tauri PTY for safe command execution
          const output = await invoke<string>('spawn_pty', {
            command,
            args: [] as string[],
          });
          return {
            success: true,
            stdout: output,
            stderr: '',
            exitCode: 0,
            executionTimeMs: Date.now() - startMs,
          };
        } catch (err) {
          return {
            success: false,
            stdout: '',
            stderr: err instanceof Error ? err.message : String(err),
            exitCode: 1,
            executionTimeMs: Date.now() - startMs,
          };
        }
      },
      timeout: 30_000, // 30s per finding validation
    };

    try {
      const validationResult = await validateFinding(reactFinding, config);
      applyValidationResult(finding, validationResult);

      // Emit status update to chat
      if (finding.validationStatus === 'confirmed') {
        const evidenceCount = validationResult.evidence.length;
        this.emitSystemMessage(
          `Finding "${finding.title}" **VERIFIED** (${validationResult.validatorUsed}, ` +
          `${evidenceCount} evidence item${evidenceCount !== 1 ? 's' : ''}, ` +
          `confidence: ${validationResult.confidence}%)`,
          'success'
        );
      } else if (finding.validationStatus === 'unverified') {
        this.emitSystemMessage(
          `Finding "${finding.title}" could not be verified ` +
          `(${validationResult.validatorUsed}, confidence: ${validationResult.confidence}%)`,
          'warning'
        );
      } else if (finding.validationStatus === 'validation_failed') {
        this.emitSystemMessage(
          `Validation failed for "${finding.title}": ${validationResult.error ?? 'unknown error'}`,
          'warning'
        );
      }
    } catch (err) {
      // Graceful degradation: validation failure never discards the finding
      finding.validationStatus = 'validation_failed';
      this.emitSystemMessage(
        `Validation error for "${finding.title}": ${err instanceof Error ? err.message : String(err)}`,
        'warning'
      );
    }
  }

  /**
   * Run H1 duplicate check for a finding (fire-and-forget).
   * Attaches DuplicateCheckResult to the finding and emits status messages.
   * Gracefully degrades when no H1 credentials are available.
   */
  private async runH1DuplicateCheck(finding: AgentFinding): Promise<void> {
    if (!this.h1DuplicateChecker || !this.huntSession?.program) {
      // No H1 checker available — graceful degradation
      finding.duplicateCheck = { status: 'not_checked' };
      return;
    }

    const programHandle = this.huntSession.program.programName;

    // Build a minimal H1Report from the finding
    const minimalReport: import('../reporting/h1_api').H1Report = {
      title: finding.title,
      description: finding.description,
      severity: (finding.severity as 'critical' | 'high' | 'medium' | 'low') ?? 'medium',
      impact: finding.description,
      steps: finding.evidence ?? [],
      proof: { screenshots: [], logs: [] },
      suggestedBounty: { min: 0, max: 0 },
    };

    try {
      const dupScore = await this.h1DuplicateChecker.checkDuplicate(
        minimalReport,
        programHandle
      );

      finding.duplicateCheck = buildDuplicateCheckResult(dupScore);

      // Emit appropriate status message based on duplicate risk
      if (finding.duplicateCheck.status === 'likely_duplicate') {
        this.emitOrchestratorMessage(
          `Finding "${finding.title}" is a **likely duplicate** on H1 ` +
          `(score: ${dupScore.overall}%). ` +
          (finding.duplicateCheck.topMatches?.[0]
            ? `Top match: "${finding.duplicateCheck.topMatches[0].title}" (${Math.round(finding.duplicateCheck.topMatches[0].similarity * 100)}%)`
            : 'Review before submitting.')
        );
      } else if (finding.duplicateCheck.status === 'possible_duplicate') {
        this.emitSystemMessage(
          `Finding "${finding.title}" has possible H1 duplicates ` +
          `(score: ${dupScore.overall}%). Review recommended.`,
          'warning'
        );
      }
      // 'unique' — no message needed (clean path)
    } catch {
      // Graceful degradation: duplicate check failure is non-fatal
      finding.duplicateCheck = { status: 'not_checked' };
    }
  }

  /**
   * Cross-hunt duplicate check (H26).
   * Queries hunt_memory for past findings with the same target and vuln type.
   * Flags duplicates but does not block them — the user may want to re-test.
   */
  private async runCrossHuntDuplicateCheck(finding: AgentFinding): Promise<void> {
    if (!this.huntMemory) return;

    try {
      const dupResult = await this.huntMemory.checkDuplicate({
        title: finding.title,
        vulnerabilityType: finding.type ?? 'unknown',
        severity: finding.severity ?? 'info',
        target: finding.target,
        description: finding.description,
        evidence: finding.evidence,
        confidence: 50,
      });

      if (dupResult.isDuplicate && dupResult.similarFinding) {
        // Flag but don't block — update duplicate check if not already flagged by H1 check
        if (!finding.duplicateCheck || finding.duplicateCheck.status === 'not_checked') {
          finding.duplicateCheck = {
            status: 'possible_duplicate',
            topMatches: [{
              source: 'hunt_memory',
              title: String(dupResult.similarFinding.payload.title ?? 'Previous session finding'),
              url: '',
              similarity: dupResult.similarFinding.score,
            }],
          };
        }

        this.emitSystemMessage(
          `Finding "${finding.title}" matches a finding from a previous hunt session ` +
          `(similarity: ${Math.round(dupResult.similarFinding.score * 100)}%). ` +
          `Review for potential cross-hunt duplicate.`,
          'warning'
        );
      }
    } catch {
      // Cross-hunt dedup is best-effort — non-fatal
    }
  }

  // ─── Private Helpers ────────────────────────────────────────────────────────

  /**
   * Generate focused SolverTask objects from recon results.
   * Instead of broad "test domain X", creates specific endpoint-targeted tasks
   * with appropriate iteration budgets and compressed recon context.
   */
  private generateSolverTasks(reconTask: HuntTask, result: AgentResult): HuntTask[] {
    if (!this.huntSession) return [];

    const tasks: HuntTask[] = [];
    const { taskQueue } = this.huntSession;

    // Extract discovered endpoints and interesting paths from observations
    const endpoints: string[] = [];
    const techStack: string[] = [];

    if (result.observations) {
      for (const obs of result.observations) {
        // Look for discovered endpoints
        if (obs.category === 'endpoint' || obs.category === 'discovery') {
          const urls = obs.detail.match(/https?:\/\/[^\s"'<>]+/g);
          if (urls) endpoints.push(...urls);
        }
        // Look for tech stack info
        if (obs.category === 'tech_stack' || obs.category === 'fingerprint') {
          techStack.push(obs.detail);
        }
      }
    }

    // Also extract URLs from finding evidence
    for (const finding of result.findings) {
      for (const ev of finding.evidence) {
        const urls = ev.match(/https?:\/\/[^\s"'<>]+/g);
        if (urls) endpoints.push(...urls);
      }
    }

    // Deduplicate endpoints
    const uniqueEndpoints = [...new Set(endpoints)].slice(0, 20);

    // Build compressed recon context for solver tasks
    const reconContext = [
      `Recon on ${reconTask.target} completed.`,
      techStack.length > 0 ? `Tech stack: ${techStack.slice(0, 5).join(', ')}` : '',
      uniqueEndpoints.length > 0 ? `Endpoints found: ${uniqueEndpoints.length}` : '',
      result.findings.length > 0
        ? `Recon findings: ${result.findings.map(f => `[${f.severity}] ${f.title}`).join(', ')}`
        : '',
    ].filter(Boolean).join('\n');

    // Map agent types to appropriate iteration budgets (using actual hyphenated IDs)
    const agentBudgets: Record<string, number> = {
      'xss-hunter': 40,
      'sqli-hunter': 40,
      'ssrf-hunter': 50,
      'ssti-hunter': 30,
      'idor-hunter': 40,
      'graphql-hunter': 50,
      'cors-hunter': 30,
      'host-header-hunter': 30,
      'xxe-hunter': 40,
      'command-injection-hunter': 40,
      'path-traversal-hunter': 40,
      'subdomain-takeover-hunter': 30,
    };

    // Tech-stack-aware agent filtering: skip agents irrelevant to the detected stack
    const techStackLower = techStack.join(' ').toLowerCase();
    const skippedAgents = getSkippedAgentsForTechStack(techStackLower);

    // Create targeted solver tasks for each relevant agent
    const availableAgents = getAllAgents();
    let dispatched = 0;
    let skipped = 0;

    for (const agentEntry of availableAgents) {
      // Skip recon — it just completed
      if (agentEntry.metadata.id === 'recon') continue;

      // Tech-stack-aware filtering
      if (skippedAgents.has(agentEntry.metadata.id)) {
        skipped++;
        continue;
      }

      const budget = agentBudgets[agentEntry.metadata.id] ?? 40;

      // For agents with specific endpoint targets, create per-endpoint tasks
      const endpointAgents = ['xss-hunter', 'sqli-hunter', 'ssrf-hunter', 'ssti-hunter'];
      if (uniqueEndpoints.length > 0 && endpointAgents.includes(agentEntry.metadata.id)) {
        // Create tasks for top endpoints (limit to prevent explosion)
        for (const endpoint of uniqueEndpoints.slice(0, 5)) {
          tasks.push(taskQueue.enqueue({
            description: `${agentEntry.metadata.name}: test ${endpoint} — ${reconContext}`,
            target: endpoint,
            agentType: agentEntry.metadata.id,
            priority: 7,
            dependencies: [],
            iterationBudget: budget,
            origin: 'finding',
            tags: [agentEntry.metadata.id, 'solver', 'endpoint-targeted'],
          }));
        }
      } else {
        // Broad domain-level task for agents that scan holistically
        tasks.push(taskQueue.enqueue({
          description: `${agentEntry.metadata.name}: test ${reconTask.target} — ${reconContext}`,
          target: reconTask.target,
          agentType: agentEntry.metadata.id,
          priority: 5,
          dependencies: [],
          iterationBudget: budget,
          origin: 'finding',
          tags: [agentEntry.metadata.id, 'solver'],
        }));
      }
      dispatched++;
    }

    if (skipped > 0) {
      this.emitSystemMessage(
        `Tech-stack filter: dispatched ${dispatched} agents, skipped ${skipped} irrelevant agents`,
        'info'
      );
    }

    return tasks;
  }

  /**
   * Get the model provider and model ID for a sub-agent, routed by task complexity.
   *
   * Routing priority:
   * 1. User-specified agentModelOverrides from settings (highest priority)
   * 2. Cost-router tier mapping (Haiku for simple, Sonnet for moderate/complex)
   * 3. Alloy instance if configured
   * 4. Primary provider + model (fallback)
   */
  private getAgentProviderAndModel(agentType: string, taskDescription: string = ''): { provider: ModelProvider; model: string } {
    // Only apply tiered routing for Anthropic providers
    if (this.provider.providerId === 'anthropic') {
      const complexity = classifyTaskComplexity(agentType, taskDescription);
      const tieredModel = getAnthropicModelForComplexity(complexity);
      return { provider: this.provider, model: tieredModel };
    }

    // Non-Anthropic providers: use alloy or primary as before
    if (this.alloyInstance && this.alloyConfig?.enabled) {
      return { provider: this.alloyInstance, model: this.model };
    }
    return { provider: this.provider, model: this.model };
  }

  /** Convert a HuntTask to the AgentTask interface expected by BaseAgent.execute() */
  private async huntTaskToAgentTask(task: HuntTask): Promise<AgentTask> {
    // Gather knowledge-system context (best-effort, non-blocking)
    let kgPatterns: unknown = undefined;
    let vulnContext: unknown = undefined;
    let agentTrustLevel: string | undefined;

    if (this.knowledgeGraph) {
      try {
        const patterns = await this.knowledgeGraph.queryRelevantPatterns(task.target, task.agentType);
        const bestTechniques = await this.knowledgeGraph.getBestTechniquesFor(task.agentType);
        if (patterns.length > 0 || bestTechniques.length > 0) {
          kgPatterns = { patterns, bestTechniques };
        }
      } catch { /* best-effort */ }
    }

    if (this.vulnDb) {
      try {
        const knowledge = await this.vulnDb.getRelevantKnowledge(task.agentType, task.target);
        if (knowledge.relevantCVEs.length > 0 || knowledge.attackPatterns.length > 0) {
          vulnContext = {
            cweInfo: knowledge.cweInfo.map(c => ({ id: c.cweId, name: c.name })),
            attackPatterns: knowledge.attackPatterns.map(a => ({ id: a.capecId, name: a.name })),
            recentCVEs: knowledge.relevantCVEs.slice(0, 5).map(c => ({ id: c.cveId, desc: c.description.slice(0, 200) })),
          };
        }
      } catch { /* best-effort */ }
    }

    if (this.rewardSystem) {
      try {
        agentTrustLevel = await this.rewardSystem.getTrustLevel(task.agentType);
      } catch { /* best-effort */ }
    }

    // Build structured shared findings from Blackboard (max 10, highest priority first)
    const bbEntries = this.blackboard.readFor(task.agentType);
    const sharedFindings: SharedFinding[] = bbEntries
      .filter(e => e.type === 'finding')
      .slice(0, 10)
      .map(e => ({
        agentId: e.agentId,
        vulnType: e.category,
        title: String(e.content.title ?? ''),
        severity: (e.content.severity as SharedFinding['severity']) ?? 'info',
        target: String(e.content.target ?? ''),
        description: String(e.content.description ?? '').slice(0, 300),
      }));

    // Build WAF context from dynamic HttpClient detection (per-domain, accumulated during hunt)
    // Falls back to static WAFDetectionResult from hunt-init probe
    let wafContext: WafContext | undefined;
    if (this.httpClient) {
      try {
        const domain = new URL(task.target).hostname;
        const dynamicWaf = this.httpClient.getWAFState(domain);
        if (dynamicWaf?.detected) {
          wafContext = {
            vendor: dynamicWaf.provider,
            confidence: 0.8,
            signal: dynamicWaf.signal,
          };
        }
      } catch { /* invalid URL — skip dynamic lookup */ }
    }
    // Fall back to static detection from hunt-init WAF probe
    if (!wafContext && this.wafDetectionResult?.detected) {
      wafContext = {
        vendor: this.wafDetectionResult.vendor,
        confidence: this.wafDetectionResult.confidence,
        signal: this.wafDetectionResult.evidence.join('; '),
      };
    }

    return {
      id: task.id,
      target: task.target,
      scope: this.guidelines?.scope.inScope ?? [task.target],
      description: task.description,
      sharedFindings: sharedFindings.length > 0 ? sharedFindings : undefined,
      wafContext,
      parameters: {
        iterationBudget: task.iterationBudget,
        origin: task.origin,
        tags: task.tags,
        // Cross-agent context from the blackboard (raw entries for backward compat)
        blackboardContext: bbEntries,
        // OOB server base URL for blind vuln testing
        oobBaseUrl: this.oobServer?.getSummary(),
        // Knowledge graph patterns for this target/agent
        kgPatterns,
        // Vulnerability database context (CWEs, CVEs, attack patterns)
        vulnContext,
        // Agent trust level from reward system
        agentTrustLevel,
        // Direct HTTP client for agent requests (Phase 20A)
        httpClient: this.httpClient,
        // Session manager for authenticated testing (Phase 20C / S4)
        sessionManager: this.sessionManager,
        // Active auth session IDs for this hunt (S4)
        authSessionIds: this.sessionManager?.listSessions().map(s => s.id) ?? [],
        // Hunt memory for cross-session learning (Phase 20E)
        huntMemory: this.huntMemory,
        // WAF detection result for bypass strategies (Phase 20G)
        wafInfo: this.wafDetectionResult,
        // Adaptive rate controller for per-domain throttling (Phase 20J)
        rateController: this.rateController,
        // Available security tools on this system
        availableTools: this.availableTools,
      },
    };
  }

  /** Get a human-readable display name for an agent type */
  private getAgentDisplayName(agentType: string): string {
    const entry = getAgentEntry(agentType);
    if (entry) return entry.metadata.name;

    // Fall back to title-casing the type
    return agentType
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  }

  /** Check if a target is within a scope entry using proper domain boundary matching */
  private isTargetInScope(target: string, scopeEntry: string): boolean {
    try {
      // Normalize target: extract hostname via URL parsing
      const targetHost = new URL(
        target.startsWith('http') ? target : `https://${target}`
      ).hostname.toLowerCase();

      // Normalize scope entry: strip whitespace, then extract hostname
      // Scope entries may be "example.com", "localhost:3001", "*.example.com",
      // or full URLs like "http://example.com"
      const trimmedScope = scopeEntry.trim();
      const isWildcard = trimmedScope.startsWith('*.');

      let scopeHost: string;
      if (isWildcard) {
        // *.example.com → example.com
        scopeHost = trimmedScope.slice(2).toLowerCase();
      } else {
        // Parse as URL to strip port/path, handling bare host:port entries
        try {
          scopeHost = new URL(
            trimmedScope.startsWith('http') ? trimmedScope : `https://${trimmedScope}`
          ).hostname.toLowerCase();
        } catch {
          // Fallback: use as-is after stripping port
          scopeHost = trimmedScope.split(':')[0].toLowerCase();
        }
      }

      if (isWildcard) {
        return targetHost === scopeHost || targetHost.endsWith('.' + scopeHost);
      }
      return targetHost === scopeHost;
    } catch {
      return false;
    }
  }

  private setPhase(phase: SessionPhase): void {
    this.currentPhase = phase;
    this.onPhaseChange?.(phase);
  }

  private emitMessage(message: ConversationMessage): void {
    this.onMessage?.(message);
  }

  private emitOrchestratorMessage(content: string): void {
    const msg: ConversationMessage = {
      type: 'orchestrator',
      id: this.generateId(),
      content,
      timestamp: Date.now(),
    };
    this.conversation.addMessage(msg);
    this.emitMessage(msg);
  }

  private emitSystemMessage(content: string, level: 'info' | 'warning' | 'error' | 'success'): void {
    const msg: ConversationMessage = {
      type: 'system',
      id: this.generateId(),
      content,
      level,
      timestamp: Date.now(),
    };
    this.conversation.addMessage(msg);
    this.emitMessage(msg);
  }

  private generateId(): string {
    return `msg_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /** Check kill switch status. Fail-safe: assumes ACTIVE on error. */
  private async isKillSwitchActive(): Promise<boolean> {
    try {
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        return await invoke<boolean>('is_kill_switch_active');
      }
      return false;
    } catch {
      return true; // Fail-safe: assume active if we can't check
    }
  }

  /**
   * Handle special input patterns (import URLs, commands, etc.)
   * Returns true if handled, false to continue normal processing.
   */
  private async handleSpecialInput(input: string): Promise<boolean> {
    // Check for HackerOne URL
    const h1Match = input.match(/hackerone\.com\/([a-zA-Z0-9_-]+)/);
    if (h1Match) {
      const msg: ConversationMessage = {
        type: 'system',
        id: this.generateId(),
        content: `Detected HackerOne program: ${h1Match[1]}. Use the import button to load the program scope.`,
        level: 'info',
        timestamp: Date.now(),
      };
      this.conversation.addMessage(msg);
      this.emitMessage(msg);
      return true;
    }

    // Check for abort command
    if (input.toLowerCase().trim() === '/stop' || input.toLowerCase().trim() === '/abort') {
      this.abortHunt();
      return true;
    }

    return false;
  }

  /** Parse AI response for structured content */
  private parseResponse(content: string): ConversationMessage[] {
    const messages: ConversationMessage[] = [];
    let remaining = content;

    // Extract JSON finding blocks from the response
    const findingPattern = /```json\n(\{[\s\S]*?"type"\s*:\s*"finding"[\s\S]*?\})\n```/g;
    let match: RegExpExecArray | null;
    while ((match = findingPattern.exec(remaining)) !== null) {
      try {
        const finding = JSON.parse(match[1]);
        messages.push({
          type: 'finding_card',
          id: this.generateId(),
          timestamp: Date.now(),
          ...finding,
        });
        remaining = remaining.replace(match[0], '');
      } catch {
        // Not valid JSON — leave as text
      }
    }

    // Whatever text remains becomes an orchestrator message
    const trimmed = remaining.trim();
    if (trimmed) {
      messages.push({
        type: 'orchestrator',
        id: this.generateId(),
        content: trimmed,
        timestamp: Date.now(),
      });
    }

    // Fallback: if nothing was parsed, return the original content
    if (messages.length === 0) {
      messages.push({
        type: 'orchestrator',
        id: this.generateId(),
        content,
        timestamp: Date.now(),
      });
    }

    return messages;
  }

  private buildSystemPrompt(): string {
    let prompt = this.systemPrompt;

    if (this.guidelines) {
      prompt += `\n\n## Active Program: ${this.guidelines.programName}
In-scope: ${this.guidelines.scope.inScope.join(', ')}
Out-of-scope: ${this.guidelines.scope.outOfScope.join(', ')}
Bounty: $${this.guidelines.bountyRange.min}-$${this.guidelines.bountyRange.max}
Rules: ${this.guidelines.rules.slice(0, 5).join('; ')}`;
    }

    if (this.huntSession) {
      const stats = this.huntSession.taskQueue.getStats();
      prompt += `\n\n## Current Hunt Status
Tasks: ${stats.total} total (${stats.done} done, ${stats.running} running, ${stats.queued} queued, ${stats.failed} failed)
Findings: ${this.huntSession.allFindings.length}
Chains: ${this.huntSession.chains.length}`;

      if (this.huntSession.allFindings.length > 0) {
        prompt += `\n\n## Recent Findings\n${this.huntSession.allFindings.slice(-10).map(f =>
          `- [${f.severity}] ${f.title} at ${f.target} (agent: ${f.agentId})`
        ).join('\n')}`;
      }

      if (this.huntSession.chains.length > 0) {
        prompt += `\n\n## Detected Chains\n${this.huntSession.chains.map(c =>
          `- [${c.combinedSeverity}] ${c.name}: ${c.description}`
        ).join('\n')}`;
      }

      const availableAgents = getAllAgents();
      prompt += `\n\n## Available Agents\n${availableAgents.map(a =>
        `- ${a.metadata.id}: ${a.metadata.description}`
      ).join('\n')}`;

      // Include blackboard summary for cross-agent context
      const bbSummary = this.blackboard.getSummary();
      if (bbSummary) {
        prompt += `\n\n## Blackboard (Cross-Agent Observations)\n${bbSummary}`;
      }

      // Include OOB server status if running
      if (this.oobServer) {
        prompt += `\n\n## OOB Server\n${this.oobServer.getSummary()}`;
      }

      // Include feedback loop insights if available
      const insights = this.feedbackLoop.getInsights();
      if (insights.length > 0) {
        prompt += `\n\n## Feedback Insights\n${insights.join('\n')}`;
      }
    }

    return prompt;
  }

  private defaultSystemPrompt(): string {
    return `You are the Huntress AI orchestrator, an expert bug bounty hunting coordinator. You operate using the Coordinator-Solver pattern where you analyze targets, plan strategies, and dispatch specialized agents (solvers) to execute focused hunting tasks.

Your responsibilities:
1. Analyze bounty program scope, rules, and target characteristics
2. Recommend attack strategies ranked by expected value (probability x bounty)
3. Dispatch specialized agents (recon, XSS, SQLi, SSRF, IDOR, SSTI, OAuth, GraphQL, CORS, etc.)
4. Synthesize findings from multiple agents to detect vulnerability chains
5. Prioritize targets and tasks dynamically based on discoveries
6. Generate professional PoC reports for confirmed vulnerabilities

You communicate clearly and concisely. You always respect scope boundaries and program rules. You explain your reasoning and recommendations. You never execute commands without user approval.

When you have tools available, use them to dispatch agents and manage the hunt. When a finding from one agent suggests a new attack vector, dispatch the appropriate specialist. Always look for vulnerability chains — combinations of findings that escalate severity.`;
  }
}

export default OrchestratorEngine;

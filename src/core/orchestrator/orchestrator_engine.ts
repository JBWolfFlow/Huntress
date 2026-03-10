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
import type { AgentResult, AgentFinding, AgentTask } from '../../agents/base_agent';
import { ORCHESTRATOR_TOOL_SCHEMAS } from '../engine/tool_schemas';
import { ModelAlloy, createAlloy } from '../engine/model_alloy';
import type { AlloyConfig } from '../engine/model_alloy';
import type { ProgramGuidelines } from '../../components/GuidelinesImporter';
import { Blackboard, postObservation, postFinding as postBBFinding } from './blackboard';
import { setValidatorOOBServer, shutdownValidationBrowser } from '../validation/validator';
import { OOBServer } from '../validation/oob_server';
import type { OOBCallback } from '../validation/oob_server';
import { FeedbackLoop } from '../training/feedback_loop';
import type { SubmittedReport, FeedbackStats } from '../training/feedback_loop';

// ─── Callback Types ───────────────────────────────────────────────────────────

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
      // Use native tool use when the provider supports it and a hunt is active
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
      const stream = this.provider.streamMessage(contextMessages, {
        model: this.model,
        maxTokens: 4096,
        systemPrompt: this.buildSystemPrompt(),
      });

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

    const prompt = `Analyze this bug bounty program and recommend attack strategies.

Program: ${guidelines.programName}
In-scope targets: ${guidelines.scope.inScope.join(', ')}
Out-of-scope: ${guidelines.scope.outOfScope.join(', ')}
Bounty range: $${guidelines.bountyRange.min} - $${guidelines.bountyRange.max}
Rules: ${guidelines.rules.join('; ')}

Target priority scores:
${scoredTargets.map(s => `  ${s.target}: ${s.totalScore}/100 — ${s.recommendation}`).join('\n')}

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
    this.setPhase('hunting');

    const msg: ConversationMessage = {
      type: 'orchestrator',
      id: this.generateId(),
      content: `Starting strategy: **${strategy.title}**\n\n${strategy.description}\n\nActivating agents: ${strategy.agents.join(', ')}`,
      timestamp: Date.now(),
    };
    this.conversation.addMessage(msg);
    this.emitMessage(msg);
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
  async startHunt(program: ProgramGuidelines): Promise<void> {
    this.loadGuidelines(program);
    this.setPhase('hunting');

    // Initialize the hunt session
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
    };

    // ── Step 1: Score and rank targets ──
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

    // ── Step 2: Create initial recon tasks for top-priority targets ──
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

    // ── Step 3: Start OOB server for blind vulnerability detection ──
    if (this.onExecuteCommand) {
      try {
        this.oobServer = new OOBServer({
          executeCommand: this.onExecuteCommand,
          onInteraction: (callback: OOBCallback) => {
            this.emitSystemMessage(
              `OOB callback triggered: ${callback.id} (${callback.interaction?.protocol ?? 'unknown'} from ${callback.interaction?.sourceIp ?? 'unknown'})`,
              'success'
            );
            // Post the OOB interaction to the blackboard for agents to consume
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
          `OOB server failed to start (blind vuln detection unavailable): ${error instanceof Error ? error.message : String(error)}`,
          'warning'
        );
        this.oobServer = undefined;
      }
    }

    // Wire OOB server into the validation engine
    setValidatorOOBServer(this.oobServer);

    // Start feedback loop polling for H1 report status updates
    this.feedbackLoop.startPolling();

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
        const agentProvider = this.getAgentProvider();
        await agent.initialize(agentProvider, this.model);
        const agentTask = this.huntTaskToAgentTask(task);
        const result = await agent.execute(agentTask);
        await agent.cleanup();
        return this.handleAgentResult(task, result);
      }

      // Instantiate and run the agent
      const agent = entry.factory();
      const agentProvider = this.getAgentProvider();
      await agent.initialize(agentProvider, this.model);
      const agentTask = this.huntTaskToAgentTask(task);
      const result = await agent.execute(agentTask);
      await agent.cleanup();

      return this.handleAgentResult(task, result);
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      this.huntSession.taskQueue.fail(taskId, errMsg);
      this.huntSession.activeAgents--;

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
    const { taskQueue } = this.huntSession;

    while (this.huntSession.running && !this.huntSession.aborted) {
      // Check if there are tasks to run
      if (!taskQueue.hasRunnableTasks() && this.huntSession.activeAgents === 0) {
        // No more tasks and no agents running — ask the coordinator if we should continue
        const shouldContinue = await this.askCoordinatorForNextSteps();
        if (!shouldContinue) break;
        // If the coordinator added new tasks, continue the loop
        if (!taskQueue.hasRunnableTasks()) break;
      }

      // Dequeue a batch for parallel execution
      const availableSlots = this.maxConcurrentAgents - this.huntSession.activeAgents;
      if (availableSlots <= 0) {
        // All slots occupied — wait briefly and retry
        await this.sleep(1000);
        continue;
      }

      const batch = taskQueue.dequeueBatch(availableSlots);
      if (batch.length === 0) {
        // Nothing runnable right now (dependencies pending)
        if (this.huntSession.activeAgents > 0) {
          await this.sleep(1000);
          continue;
        }
        break;
      }

      // Dispatch all tasks in the batch in parallel
      const dispatches = batch.map(task => this.dispatchAgent(task.id));
      await Promise.allSettled(dispatches);

      // After the batch completes, run chain detection on all accumulated findings
      if (this.huntSession.allFindings.length > 0) {
        const newChains = detectChains(this.huntSession.allFindings);
        const previousChainIds = new Set(this.huntSession.chains.map(c => c.id));
        const freshChains = newChains.filter(c => !previousChainIds.has(c.id));

        if (freshChains.length > 0) {
          this.huntSession.chains.push(...freshChains);
          for (const chain of freshChains) {
            this.emitOrchestratorMessage(
              `**Vulnerability chain detected: ${chain.name}**\n` +
              `Combined severity: **${chain.combinedSeverity.toUpperCase()}**\n` +
              `${chain.description}\n\n` +
              `Chain steps:\n${chain.chainSteps.map(s => `  - ${s}`).join('\n')}`
            );
          }
        }
      }

      // Emit progress
      const stats = taskQueue.getStats();
      this.emitSystemMessage(
        `Progress: ${stats.done} done, ${stats.running} running, ${stats.queued} queued, ` +
        `${stats.failed} failed | Findings: ${this.huntSession.allFindings.length} | ` +
        `Chains: ${this.huntSession.chains.length}`,
        'info'
      );
    }

    // Hunt complete — stop services
    this.huntSession.running = false;
    this.stopHuntServices();
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
      .map(f => `[${f.severity}] ${f.title} at ${f.target}`)
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

    for (const toolCall of response.toolCalls) {
      await this.executeCoordinatorTool(toolCall);
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

    for (const toolCall of response.toolCalls) {
      if (toolCall.name === 'stop_hunting') {
        const input = toolCall.input as { reason: string; summary: string; recommendations?: string[] };
        this.emitOrchestratorMessage(
          `**Stopping hunt:** ${input.reason}\n\n${input.summary}` +
          (input.recommendations?.length
            ? `\n\n**Recommendations:**\n${input.recommendations.map(r => `  - ${r}`).join('\n')}`
            : '')
        );
        shouldContinue = false;
      } else {
        await this.executeCoordinatorTool(toolCall);
      }
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

        // Validate the target is in scope
        const inScope = this.huntSession.program.scope.inScope.some(s =>
          args.target.includes(s) || s.includes(args.target) ||
          args.target.endsWith(s) || this.matchesWildcard(args.target, s)
        );

        if (!inScope) {
          this.emitSystemMessage(
            `Blocked dispatch: ${args.target} is not in scope.`,
            'warning'
          );
          return;
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

        const finding = this.huntSession?.allFindings.find(f => f.id === args.finding_id);
        if (!finding) {
          this.emitSystemMessage(
            `Finding ${args.finding_id} not found. Available: ${
              this.huntSession?.allFindings.map(f => f.id).join(', ') || 'none'
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
        });

        this.emitOrchestratorMessage(
          `Report generated for: **${finding.title}** [${finding.severity.toUpperCase()}]`
        );
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

    // Collect findings
    if (result.findings.length > 0) {
      this.huntSession.allFindings.push(...result.findings);

      // Emit each finding to the chat and post to blackboard
      for (const finding of result.findings) {
        this.addFinding({
          title: finding.title,
          severity: finding.severity as Severity,
          description: finding.description,
          target: finding.target,
          agent: finding.agentId,
          evidence: finding.evidence,
          isDuplicate: false,
        });

        // Post finding to blackboard so other agents can discover it
        postBBFinding(this.blackboard, finding.agentId, finding.type ?? 'vulnerability', {
          title: finding.title,
          severity: finding.severity,
          target: finding.target,
          description: finding.description,
        }, getAllAgents().map(a => a.metadata.id));
      }

      // Reprioritize the queue based on new findings
      this.huntSession.taskQueue.reprioritize(result.findings);
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

    // Generate follow-up tasks from the result
    const followUps = this.huntSession.taskQueue.generateFollowUpTasks(result);

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

    // Map agent types to appropriate iteration budgets
    const agentBudgets: Record<string, number> = {
      xss_hunter: 40,
      sqli_hunter: 40,
      ssrf_hunter: 50,
      ssti_hunter: 30,
      idor_hunter: 40,
      graphql_hunter: 50,
      cors_hunter: 30,
      host_header_hunter: 30,
      xxe_hunter: 40,
      command_injection_hunter: 40,
      path_traversal_hunter: 40,
      subdomain_takeover_hunter: 30,
    };

    // Create targeted solver tasks for each relevant agent
    const availableAgents = getAllAgents();

    for (const agentEntry of availableAgents) {
      // Skip recon — it just completed
      if (agentEntry.metadata.id === 'recon') continue;

      const budget = agentBudgets[agentEntry.metadata.id] ?? 40;

      // For agents with specific endpoint targets, create per-endpoint tasks
      if (uniqueEndpoints.length > 0 && ['xss_hunter', 'sqli_hunter', 'ssrf_hunter', 'ssti_hunter'].includes(agentEntry.metadata.id)) {
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
    }

    return tasks;
  }

  /** Get the model provider for sub-agents — alloy if enabled, else primary */
  private getAgentProvider(): ModelProvider {
    if (this.alloyInstance && this.alloyConfig?.enabled) {
      return this.alloyInstance;
    }
    return this.provider;
  }

  /** Convert a HuntTask to the AgentTask interface expected by BaseAgent.execute() */
  private huntTaskToAgentTask(task: HuntTask): AgentTask {
    return {
      id: task.id,
      target: task.target,
      scope: this.guidelines?.scope.inScope ?? [task.target],
      description: task.description,
      parameters: {
        iterationBudget: task.iterationBudget,
        origin: task.origin,
        tags: task.tags,
        // Cross-agent context from the blackboard
        blackboardContext: this.blackboard.readFor(task.agentType),
        // OOB server base URL for blind vuln testing
        oobBaseUrl: this.oobServer?.getSummary(),
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

  /** Check if a target matches a wildcard scope entry (e.g., *.example.com) */
  private matchesWildcard(target: string, scopeEntry: string): boolean {
    if (!scopeEntry.startsWith('*.')) return false;
    const baseDomain = scopeEntry.slice(2);
    return target.endsWith(baseDomain) || target === baseDomain;
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
    // For now, return as a single orchestrator message
    // Future: parse for JSON blocks, finding cards, strategy suggestions, etc.
    return [{
      type: 'orchestrator',
      id: this.generateId(),
      content,
      timestamp: Date.now(),
    }];
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

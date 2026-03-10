/**
 * ReAct Execution Loop — The Core Agent Engine
 *
 * Implements the THINK → VALIDATE → APPROVE → EXECUTE → OBSERVE → DECIDE cycle
 * that powers all autonomous hunting agents. Based on the ReAct pattern
 * (Reasoning + Acting) with XBOW's Solver pattern adaptations:
 *
 * - Max 80 iterations per agent instance (prevents context decay)
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
import { AGENT_TOOL_SCHEMAS } from './tool_schemas';
import { checkSafetyPolicies } from './safety_policies';
import { ModelAlloy } from './model_alloy';

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
  /** Maximum iterations before stopping (default: 80) */
  maxIterations?: number;
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
  toolCall?: ToolUseBlock;
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
  totalTokensUsed: { input: number; output: number };
  duration: number;
  stopReason: 'task_complete' | 'no_vulnerabilities' | 'target_hardened' | 'blocker' | 'iteration_limit' | 'error' | 'killed';
  summary: string;
  iterationLog: IterationLog[];
  /** Compressed context for continuation in a fresh agent */
  continuationContext?: string;
  /** Structured handoff data for the next agent */
  continuationHandoff?: ContinuationHandoff;
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
  private totalTokens = { input: 0, output: 0 };
  private killed = false;
  private maxIterations: number;

  constructor(config: ReactLoopConfig) {
    this.config = {
      maxIterations: 80,
      autoApproveSafe: false,
      ...config,
    };
    this.maxIterations = this.config.maxIterations ?? 80;
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

          // Add assistant response to conversation
          this.conversationHistory.push({
            role: 'assistant',
            content: response.content,
          });

          // Check if it wants to stop (said something like "I'm done")
          if (response.stopReason === 'end_turn') {
            stopReason = 'task_complete';
            summary = response.content;
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

        for (const toolCall of response.toolCalls) {
          logEntry.toolCall = toolCall;
          this.toolCallCount++;

          const result = await this.processToolCall(toolCall, iteration);
          toolResults.push(result);

          if (result.content) {
            logEntry.toolResult = result.content.substring(0, 1000); // Truncate for log
          }

          // Check if this was a stop_hunting call
          if (toolCall.name === 'stop_hunting') {
            const input = toolCall.input as { reason: string; summary: string };
            stopReason = input.reason as ReactLoopResult['stopReason'];
            summary = input.summary;
            // Push tool results before breaking
            this.conversationHistory.push({
              role: 'user',
              content: '',
              toolResults,
            });
            this.iterationLog.push(logEntry);
            // Signal we're exiting the loop after processing
            this.killed = true;
            break;
          }
        }

        if (this.killed) break;

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

        // Add error to conversation so the model can adapt
        this.conversationHistory.push({
          role: 'user',
          content: `Error occurred: ${errMsg}. Please adjust your approach and continue.`,
        });

        // If we get 3 consecutive errors, stop
        const recentErrors = this.iterationLog.slice(-3).filter(l => l.error);
        if (recentErrors.length >= 3) {
          stopReason = 'error';
          summary = `Stopped after 3 consecutive errors. Last error: ${errMsg}`;
          this.iterationLog.push(logEntry);
          break;
        }
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

    return {
      success: this.findings.length > 0 || stopReason === 'task_complete' || stopReason === 'no_vulnerabilities',
      findings: this.findings,
      totalIterations: this.iterationLog.length,
      toolCallCount: this.toolCallCount,
      totalTokensUsed: this.totalTokens,
      duration: Date.now() - startTime,
      stopReason,
      summary: summary || `Completed ${this.iterationLog.length} iterations with ${this.findings.length} findings`,
      iterationLog: this.iterationLog,
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

      case 'stop_hunting':
        return {
          type: 'tool_result',
          tool_use_id: id,
          content: 'Acknowledged. Stopping hunting.',
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

    const result = await this.config.onExecuteCommand(commandToExecute, input.target);

    if (result.blocked) {
      return {
        type: 'tool_result',
        tool_use_id: toolUseId,
        content: `Command blocked: ${result.blockReason}`,
        is_error: true,
      };
    }

    // ── OBSERVE: Return output to model ──
    let output = '';
    if (result.stdout) {
      output += result.stdout;
    }
    if (result.stderr && !result.success) {
      output += `\n\nSTDERR:\n${result.stderr}`;
    }

    // Truncate very long output to avoid context overflow
    const MAX_OUTPUT_LENGTH = 15000;
    if (output.length > MAX_OUTPUT_LENGTH) {
      const truncatedLines = output.substring(0, MAX_OUTPUT_LENGTH);
      output = `${truncatedLines}\n\n[OUTPUT TRUNCATED - ${output.length} total characters, showing first ${MAX_OUTPUT_LENGTH}]`;
    }

    const warnings = safetyCheck.warnings.length > 0
      ? `\nSafety warnings: ${safetyCheck.warnings.join(', ')}`
      : '';

    return {
      type: 'tool_result',
      tool_use_id: toolUseId,
      content: `Exit code: ${result.exitCode}\nExecution time: ${result.executionTimeMs}ms${warnings}\n\n${output || '(no output)'}`,
    };
  }

  /** Handle report_finding tool call */
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
    const finding: ReactFinding = {
      id: `finding_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
      title: input.title,
      vulnerabilityType: input.vulnerability_type,
      severity: input.severity as ReactFinding['severity'],
      target: input.target,
      description: input.description,
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
      // Write script to temp file and execute it to avoid argument escaping issues
      const ext = input.language === 'python' ? 'py' : input.language === 'bash' ? 'sh' : 'js';
      const scriptPath = `/tmp/huntress_script_${Date.now()}.${ext}`;

      // Write file then execute
      const writeResult = await this.config.onExecuteCommand(
        `tee ${scriptPath} <<'HUNTRESS_SCRIPT_EOF'\n${input.code}\nHUNTRESS_SCRIPT_EOF`,
        input.target
      );

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

## Iteration Budget
You have ${this.maxIterations} iterations maximum. Use them wisely:
- Iterations 1-10: Reconnaissance and mapping
- Iterations 11-40: Active testing and probing
- Iterations 41-70: Deep testing and validation
- Iterations 71-80: Wrap up, validate findings, generate final report

Current findings: ${this.findings.length}
Current tool calls: ${this.toolCallCount}`;
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
      if (log.toolCall?.name === 'execute_command') {
        const target = (log.toolCall.input as { target?: string }).target;
        if (target && !findingTargets.has(target) && !testedPaths.includes(target)) {
          testedPaths.push(target);
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

export default ReactLoop;

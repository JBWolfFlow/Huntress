/**
 * CrewAI Supervisor Integration
 *
 * Manages the AI supervisor that coordinates mini-agents and makes
 * strategic decisions about testing approaches.
 *
 * Enhanced with verbose streaming output and human checkpoints.
 */

import Anthropic from '@anthropic-ai/sdk';
import { HumanTaskManager, HumanTaskCallback } from './human_task';
import { OAuthAgent, OAuthAgentConfig } from './oauth_agent';
import { AIAgentLoop, HuntConfig, HuntResult } from './agent_loop';
import { AIAgentToolInterface } from './tool_integration';

/**
 * AI reasoning types for verbose output
 */
export enum AIReasoningType {
  ANALYSIS = 'analysis',
  PLANNING = 'planning',
  DECISION = 'decision',
  HYPOTHESIS = 'hypothesis',
  RECOMMENDATION = 'recommendation',
  WARNING = 'warning',
  SUCCESS = 'success',
  ERROR = 'error',
}

/**
 * Hunt phase tracking
 */
export enum HuntPhase {
  INITIALIZATION = 'initialization',
  RECONNAISSANCE = 'reconnaissance',
  ACTIVE_TESTING = 'active_testing',
  EXPLOITATION = 'exploitation',
  REPORTING = 'reporting',
  COMPLETE = 'complete',
}

/**
 * Streaming output message
 */
export interface StreamingMessage {
  type: AIReasoningType;
  phase: HuntPhase;
  message: string;
  timestamp: number;
  metadata?: Record<string, any>;
}

/**
 * Checkpoint request
 */
export interface CheckpointRequest {
  id: string;
  phase: HuntPhase;
  reason: string;
  context: {
    toolsExecuted: number;
    findingsCount: number;
    currentTarget: string;
    nextAction?: string;
  };
  timestamp: number;
}

/**
 * Streaming callback for real-time AI output
 */
export type StreamingCallback = (message: StreamingMessage) => void;

/**
 * Checkpoint callback for human review
 */
export type CheckpointCallback = (checkpoint: CheckpointRequest) => Promise<boolean>;

export interface SupervisorConfig {
  apiKey?: string;
  model?: string;
  maxTokens?: number;
  humanInTheLoop?: boolean;
  maxIterations?: number;
  timeout?: number;
  verboseMode?: boolean;
  checkpointInterval?: number; // Tools executed before checkpoint
  onStreaming?: StreamingCallback;
  onCheckpoint?: CheckpointCallback;
}

export interface AgentTask {
  id: string;
  type: string;
  target: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  status: 'pending' | 'running' | 'completed' | 'failed';
  result?: any;
  error?: string;
}

export interface SupervisorDecision {
  action: 'approve' | 'deny' | 'modify' | 'escalate';
  reasoning: string;
  modifications?: any;
  requiresHumanApproval: boolean;
}

export interface ExecutionConfig {
  target: string;
  scope?: string[];
  oauthConfig?: OAuthAgentConfig;
  onApprovalRequired?: HumanTaskCallback;
}

export interface ExecutionResult {
  success: boolean;
  tasks: AgentTask[];
  vulnerabilities: any[];
  duration: number;
  error?: string;
}

export class Supervisor {
  private client?: Anthropic;
  private config: SupervisorConfig;
  private conversationHistory: Anthropic.MessageParam[] = [];
  private humanTaskManager: HumanTaskManager;
  private agents: Map<string, OAuthAgent> = new Map();
  private tasks: AgentTask[] = [];
  private currentPhase: HuntPhase = HuntPhase.INITIALIZATION;
  private toolsExecutedCount: number = 0;
  private findingsCount: number = 0;
  private streamingCallback?: StreamingCallback;
  private checkpointCallback?: CheckpointCallback;

  constructor(config: SupervisorConfig = {}) {
    this.config = {
      model: 'claude-sonnet-4-20250514',
      maxTokens: 4096,
      humanInTheLoop: true,
      maxIterations: 10,
      timeout: 3600000, // 1 hour
      verboseMode: true,
      checkpointInterval: 5, // Checkpoint every 5 tools
      ...config,
    };
    
    if (config.apiKey) {
      this.client = new Anthropic({
        apiKey: config.apiKey,
        dangerouslyAllowBrowser: true, // Required for Tauri desktop app
      });
    }
    
    this.humanTaskManager = new HumanTaskManager();
    this.streamingCallback = config.onStreaming;
    this.checkpointCallback = config.onCheckpoint;
  }

  /**
   * Stream a message to the UI
   */
  private stream(type: AIReasoningType, message: string, metadata?: Record<string, any>): void {
    console.log('[SUPERVISOR] Stream called:', { type, message, verboseMode: this.config.verboseMode, hasCallback: !!this.streamingCallback });
    
    if (this.config.verboseMode && this.streamingCallback) {
      console.log('[SUPERVISOR] Calling streamingCallback');
      try {
        this.streamingCallback({
          type,
          phase: this.currentPhase,
          message,
          timestamp: Date.now(),
          metadata,
        });
        console.log('[SUPERVISOR] streamingCallback completed');
      } catch (error) {
        console.error('[SUPERVISOR] Error in streamingCallback:', error);
      }
    } else {
      console.log('[SUPERVISOR] NOT calling callback - verboseMode:', this.config.verboseMode, 'hasCallback:', !!this.streamingCallback);
    }
  }

  /**
   * Request checkpoint approval
   */
  private async requestCheckpoint(reason: string, nextAction?: string): Promise<boolean> {
    if (!this.checkpointCallback) {
      return true; // Auto-approve if no callback
    }

    const checkpoint: CheckpointRequest = {
      id: `checkpoint_${Date.now()}`,
      phase: this.currentPhase,
      reason,
      context: {
        toolsExecuted: this.toolsExecutedCount,
        findingsCount: this.findingsCount,
        currentTarget: this.tasks[0]?.target || 'unknown',
        nextAction,
      },
      timestamp: Date.now(),
    };

    this.stream(AIReasoningType.WARNING, `⏸️ Checkpoint: ${reason}`, checkpoint);
    return await this.checkpointCallback(checkpoint);
  }

  /**
   * Set current hunt phase
   */
  private setPhase(phase: HuntPhase): void {
    this.currentPhase = phase;
    this.stream(AIReasoningType.ANALYSIS, `📍 Phase: ${phase.toUpperCase()}`, { phase });
  }

  /**
   * Increment tool execution counter and check for checkpoint
   */
  private async checkToolCheckpoint(): Promise<boolean> {
    this.toolsExecutedCount++;
    
    if (this.config.checkpointInterval &&
        this.toolsExecutedCount % this.config.checkpointInterval === 0) {
      return await this.requestCheckpoint(
        `Executed ${this.toolsExecutedCount} tools`,
        'Continue testing'
      );
    }
    
    return true;
  }

  /**
   * Register human task callback
   */
  setHumanTaskCallback(callback: HumanTaskCallback): void {
    this.humanTaskManager.setCallback(callback);
  }

  /**
   * Set streaming callback
   */
  setStreamingCallback(callback: StreamingCallback): void {
    this.streamingCallback = callback;
  }

  /**
   * Set checkpoint callback
   */
  setCheckpointCallback(callback: CheckpointCallback): void {
    this.checkpointCallback = callback;
  }

  /**
   * Register an OAuth agent
   */
  registerOAuthAgent(agentId: string, config: OAuthAgentConfig): void {
    const agent = new OAuthAgent(config, this.humanTaskManager);
    this.agents.set(agentId, agent);
  }

  /**
   * Execute supervised testing workflow
   */
  async execute(config: ExecutionConfig): Promise<ExecutionResult> {
    const startTime = Date.now();
    
    try {
      // Initialize hunt
      this.setPhase(HuntPhase.INITIALIZATION);
      this.stream(AIReasoningType.ANALYSIS, `🤔 Analyzing target: ${config.target}`);
      
      // Set up human task callback if provided
      if (config.onApprovalRequired) {
        this.setHumanTaskCallback(config.onApprovalRequired);
      }

      // Load program guidelines if available
      this.stream(AIReasoningType.PLANNING, '📋 Loading program guidelines...');

      // Register OAuth agent if config provided
      if (config.oauthConfig) {
        this.stream(AIReasoningType.PLANNING, '🔐 Registering OAuth hunter agent...');
        this.registerOAuthAgent('oauth', {
          ...config.oauthConfig,
          target: config.target,
          humanInTheLoop: this.config.humanInTheLoop,
        });
      }

      // Create initial task
      const task: AgentTask = {
        id: this.generateTaskId(),
        type: 'oauth_hunt',
        target: config.target,
        priority: 'high',
        status: 'pending',
      };
      
      this.tasks.push(task);

      // Start reconnaissance phase
      this.setPhase(HuntPhase.RECONNAISSANCE);
      this.stream(AIReasoningType.PLANNING, '🎯 Planning reconnaissance strategy...');
      this.stream(AIReasoningType.RECOMMENDATION, '📊 Recommended approach: Start with passive reconnaissance');

      // Checkpoint before starting
      const startApproved = await this.requestCheckpoint(
        'Ready to begin hunt',
        'Start reconnaissance'
      );
      
      if (!startApproved) {
        this.stream(AIReasoningType.ERROR, '❌ Hunt cancelled by user');
        return {
          success: false,
          tasks: this.tasks,
          vulnerabilities: [],
          duration: Date.now() - startTime,
          error: 'Hunt cancelled by user at initialization',
        };
      }

      // Execute OAuth agent if registered
      const oauthAgent = this.agents.get('oauth');
      if (oauthAgent) {
        task.status = 'running';
        this.stream(AIReasoningType.ANALYSIS, '🔍 Executing OAuth vulnerability hunt...');
        
        try {
          const result = await oauthAgent.executeHunt();
          task.status = 'completed';
          task.result = result;
          
          this.findingsCount = result.vulnerabilities.length;
          this.setPhase(HuntPhase.COMPLETE);
          this.stream(AIReasoningType.SUCCESS, `✅ Hunt completed! Found ${this.findingsCount} vulnerabilities`);
          
          return {
            success: true,
            tasks: this.tasks,
            vulnerabilities: result.vulnerabilities,
            duration: Date.now() - startTime,
          };
        } catch (error) {
          task.status = 'failed';
          task.error = error instanceof Error ? error.message : String(error);
          this.stream(AIReasoningType.ERROR, `❌ Hunt failed: ${task.error}`);
          throw error;
        }
      }

      // If no agents registered, use AI Agent Loop for complete hunt
      if (this.client) {
        this.stream(AIReasoningType.ANALYSIS, '🧠 Using AI Agent Loop for autonomous hunting...');
        
        // Create tool interface
        const toolInterface = new AIAgentToolInterface(`session_${Date.now()}`);
        
        // Create AI Agent Loop configuration
        const huntConfig: HuntConfig = {
          target: config.target,
          scope: config.scope || [],
          guidelines: 'Follow bug bounty best practices. Stay within scope. Respect rate limits.',
          toolInterface,
          streamingCallback: this.streamingCallback!,
          checkpointCallback: this.checkpointCallback!,
          apiKey: this.config.apiKey!,
          model: this.config.model,
          maxIterations: this.config.maxIterations,
        };
        
        // Execute hunt with AI Agent Loop
        const agentLoop = new AIAgentLoop(huntConfig);
        task.status = 'running';
        
        try {
          const huntResult: HuntResult = await agentLoop.executeHunt();
          
          task.status = huntResult.success ? 'completed' : 'failed';
          task.result = huntResult;
          
          this.findingsCount = huntResult.findingsCount;
          this.toolsExecutedCount = huntResult.toolsExecuted;
          
          this.setPhase(HuntPhase.COMPLETE);
          this.stream(
            huntResult.success ? AIReasoningType.SUCCESS : AIReasoningType.ERROR,
            huntResult.success
              ? `✅ Hunt complete! Found ${huntResult.vulnerabilities.length} vulnerabilities`
              : `❌ Hunt failed: ${huntResult.error}`
          );
          
          return {
            success: huntResult.success,
            tasks: this.tasks,
            vulnerabilities: huntResult.vulnerabilities,
            duration: Date.now() - startTime,
            error: huntResult.error,
          };
        } catch (error) {
          task.status = 'failed';
          task.error = error instanceof Error ? error.message : String(error);
          this.stream(AIReasoningType.ERROR, `❌ Hunt failed: ${task.error}`);
          throw error;
        }
      }

      throw new Error('No agents registered and no API key provided for AI hunting');
      
    } catch (error) {
      this.stream(AIReasoningType.ERROR, `❌ Fatal error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return {
        success: false,
        tasks: this.tasks,
        vulnerabilities: [],
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Analyze a target and create testing strategy
   */
  async analyzeTarget(target: string, scope: string[]): Promise<AgentTask[]> {
    if (!this.client) {
      throw new Error('Anthropic client not initialized');
    }

    const prompt = `
You are a bug bounty supervisor AI. Analyze this target and create a testing strategy.

Target: ${target}
Scope: ${scope.join(', ')}

Create a prioritized list of security tests to perform. Consider:
1. Common vulnerabilities for this type of target
2. Attack surface analysis
3. Risk vs. reward
4. Scope boundaries

Return a JSON array of tasks with: id, type, target, priority
    `.trim();

    const response = await this.client.messages.create({
      model: this.config.model!,
      max_tokens: this.config.maxTokens!,
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
    });

    // Parse response and create tasks
    // TODO: Implement proper JSON parsing from response
    return [];
  }

  /**
   * Review agent findings and decide on next actions
   */
  async reviewFindings(findings: any[]): Promise<SupervisorDecision> {
    if (!this.client) {
      throw new Error('Anthropic client not initialized');
    }

    const prompt = `
Review these security findings and decide if they should be reported:

${JSON.stringify(findings, null, 2)}

Consider:
1. Severity and impact
2. Exploitability
3. False positive likelihood
4. Scope compliance

Provide decision: approve, deny, modify, or escalate
    `.trim();

    const response = await this.client.messages.create({
      model: this.config.model!,
      max_tokens: this.config.maxTokens!,
      messages: [
        ...this.conversationHistory,
        {
          role: 'user',
          content: prompt,
        },
      ],
    });

    // Parse decision from response
    // TODO: Implement proper decision parsing
    return {
      action: 'approve',
      reasoning: 'Placeholder reasoning',
      requiresHumanApproval: true,
    };
  }

  /**
   * Generate testing recommendations
   */
  async generateRecommendations(context: any): Promise<string[]> {
    if (!this.client) {
      throw new Error('Anthropic client not initialized');
    }

    const prompt = `
Based on this testing context, suggest next steps:

${JSON.stringify(context, null, 2)}

Provide specific, actionable recommendations for further testing.
    `.trim();

    const response = await this.client.messages.create({
      model: this.config.model!,
      max_tokens: this.config.maxTokens!,
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
    });

    // Parse recommendations from response
    // TODO: Implement proper parsing
    return [];
  }

  /**
   * Get all registered agents
   */
  getAgents(): Map<string, OAuthAgent> {
    return this.agents;
  }

  /**
   * Get all tasks
   */
  getTasks(): AgentTask[] {
    return this.tasks;
  }

  /**
   * Generate unique task ID
   */
  private generateTaskId(): string {
    return `task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Clear conversation history
   */
  clearHistory(): void {
    this.conversationHistory = [];
  }
}

export default Supervisor;
/**
 * CrewAI Tool Integration
 * 
 * Integrates the safe tool execution system with CrewAI agents.
 * Provides AI agents with controlled access to security tools.
 */

import { createToolExecutionSystem, type ExecutionRequest, type ExecutionResult } from '../tools';

/**
 * AI Agent Tool Interface
 * 
 * This is the interface AI agents use to execute security tools.
 * All executions go through the safety system.
 */
export class AIAgentToolInterface {
  private toolSystem = createToolExecutionSystem();
  private sessionId: string;

  constructor(sessionId?: string) {
    this.sessionId = sessionId || `session_${Date.now()}`;
  }

  /**
   * Execute a security tool command
   * 
   * This is the main method AI agents call to run tools.
   * 
   * @param agentId - ID of the AI agent making the request
   * @param command - Command to execute
   * @param target - Target being tested
   * @param skipApproval - Skip human approval (only for SAFE tools)
   */
  async executeTool(
    agentId: string,
    command: string,
    target: string,
    skipApproval: boolean = false
  ): Promise<ExecutionResult> {
    const request: ExecutionRequest = {
      command,
      context: {
        executionId: `exec_${Date.now()}_${Math.random()}`,
        agentId,
        target,
        timestamp: new Date(),
        sessionId: this.sessionId,
      },
      skipApproval,
    };

    return await this.toolSystem.executor.execute(request);
  }

  /**
   * Get available tools for AI context
   * 
   * Returns a formatted list of available tools with descriptions
   * that can be included in AI agent prompts.
   */
  getAvailableTools(): string {
    return this.toolSystem.registry.getToolDescriptionsForAI();
  }

  /**
   * Enable medium mode (allows RESTRICTED tools)
   */
  enableMediumMode(): void {
    this.toolSystem.registry.enableMediumMode();
  }

  /**
   * Disable medium mode
   */
  disableMediumMode(): void {
    this.toolSystem.registry.disableMediumMode();
  }

  /**
   * Check if medium mode is enabled
   */
  isMediumModeEnabled(): boolean {
    return this.toolSystem.registry.isMediumModeEnabled();
  }

  /**
   * Get execution statistics
   */
  getStatistics() {
    return this.toolSystem.executor.getStatistics();
  }

  /**
   * Get execution log
   */
  getExecutionLog() {
    return this.toolSystem.executor.getExecutionLog();
  }

  /**
   * Handle approval response from UI
   */
  handleApprovalResponse(approvalId: string, approved: boolean): void {
    this.toolSystem.executor.handleApprovalResponse(approvalId, approved);
  }

  /**
   * Get pending approvals
   */
  getPendingApprovals() {
    return this.toolSystem.executor.getPendingApprovals();
  }

  /**
   * Get tool system components (for advanced usage)
   */
  getToolSystem() {
    return this.toolSystem;
  }
}

/**
 * Create AI agent tool interface
 */
export function createAIAgentToolInterface(sessionId?: string): AIAgentToolInterface {
  return new AIAgentToolInterface(sessionId);
}

/**
 * Global tool interface instance (singleton)
 */
let globalToolInterface: AIAgentToolInterface | null = null;

/**
 * Get or create global tool interface
 */
export function getGlobalToolInterface(): AIAgentToolInterface {
  if (!globalToolInterface) {
    globalToolInterface = new AIAgentToolInterface();
  }
  return globalToolInterface;
}

/**
 * Reset global tool interface
 */
export function resetGlobalToolInterface(): void {
  globalToolInterface = null;
}

export default AIAgentToolInterface;
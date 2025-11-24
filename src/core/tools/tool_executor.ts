/**
 * Tool Executor for AI Agent Integration
 *
 * Orchestrates safe tool execution with comprehensive safety gates:
 * - Command validation
 * - Scope validation
 * - Rate limiting
 * - Human approval workflow
 * - Kill switch integration
 * - Execution logging and audit trail
 * - Output persistence for inter-tool data passing
 *
 * This is the ONLY way AI agents should execute security tools.
 */

import { invoke } from '@tauri-apps/api/core';
import { ToolRegistry, type ToolMetadata, ToolSafetyLevel } from './tool_registry';
import { CommandValidator, type ValidationResult } from './command_validator';
import { getToolOutputManager } from '../../utils/tool_output_manager';

/**
 * CRITICAL: HMR-Persistent Callback Storage
 *
 * Store approval callbacks on window object to survive Hot Module Replacement.
 * This prevents the race condition where:
 * 1. Callback registered in old module instance
 * 2. HMR reloads module, creating new instance with empty Maps
 * 3. User approves, but callback lookup fails in new instance
 *
 * By storing on window, callbacks persist across HMR reloads.
 */
declare global {
  interface Window {
    __huntress_approval_callbacks?: Map<string, (approved: boolean) => void>;
    __huntress_pending_approvals?: Map<string, ApprovalRequest>;
  }
}

// Initialize global storage if not exists
if (typeof window !== 'undefined') {
  if (!window.__huntress_approval_callbacks) {
    window.__huntress_approval_callbacks = new Map();
    console.log('[ToolExecutor] 🔧 Initialized global approval callbacks storage');
  }
  if (!window.__huntress_pending_approvals) {
    window.__huntress_pending_approvals = new Map();
    console.log('[ToolExecutor] 🔧 Initialized global pending approvals storage');
  }
}

/**
 * Execution context for tracking and auditing
 */
export interface ExecutionContext {
  /** Unique execution ID */
  executionId: string;
  
  /** AI agent that requested execution */
  agentId: string;
  
  /** Target being tested */
  target: string;
  
  /** Timestamp of request */
  timestamp: Date;
  
  /** Session ID for grouping related executions */
  sessionId?: string;
}

/**
 * Execution request from AI agent
 */
export interface ExecutionRequest {
  /** Command to execute */
  command: string;
  
  /** Execution context */
  context: ExecutionContext;
  
  /** Whether to skip human approval (only for SAFE tools) */
  skipApproval?: boolean;
  
  /** Working directory */
  cwd?: string;
  
  /** Environment variables */
  env?: Record<string, string>;
}

/**
 * Execution result with full audit trail
 */
export interface ExecutionResult {
  /** Whether execution was successful */
  success: boolean;
  
  /** Command that was executed */
  command: string;
  
  /** Sanitized command (with safety modifications) */
  sanitizedCommand?: string;
  
  /** Tool metadata */
  tool?: ToolMetadata;
  
  /** Validation result */
  validation: ValidationResult;
  
  /** Standard output */
  stdout?: string;
  
  /** Standard error */
  stderr?: string;
  
  /** Exit code */
  exitCode?: number;
  
  /** Execution time in milliseconds */
  executionTime?: number;
  
  /** Whether execution was blocked */
  blocked: boolean;
  
  /** Reason for blocking */
  blockReason?: string;
  
  /** Whether human approval was granted */
  approvalGranted?: boolean;
  
  /** Scope validation result */
  scopeValidation?: {
    passed: boolean;
    target: string;
    reason?: string;
  };
  
  /** Rate limit status */
  rateLimit?: {
    allowed: boolean;
    remainingTokens: number;
  };
  
  /** Kill switch status at execution time */
  killSwitchActive?: boolean;
  
  /** Execution context */
  context: ExecutionContext;
  
  /** Warnings */
  warnings?: string[];
}

/**
 * Approval request for human review
 */
export interface ApprovalRequest {
  /** Command to approve */
  command: string;
  
  /** Tool metadata */
  tool: ToolMetadata;
  
  /** Validation result */
  validation: ValidationResult;
  
  /** Execution context */
  context: ExecutionContext;
  
  /** Target being tested */
  target: string;
}

/**
 * Tool Executor
 *
 * Coordinates safe tool execution with all safety gates
 */
export class ToolExecutor {
  private registry: ToolRegistry;
  private validator: CommandValidator;
  private executionLog: ExecutionResult[] = [];
  
  // CRITICAL: Use global storage for HMR persistence
  private get pendingApprovals(): Map<string, ApprovalRequest> {
    return window.__huntress_pending_approvals!;
  }
  
  private get approvalCallbacks(): Map<string, (approved: boolean) => void> {
    return window.__huntress_approval_callbacks!;
  }

  constructor(registry: ToolRegistry) {
    this.registry = registry;
    this.validator = new CommandValidator(registry);
    
    console.log('[ToolExecutor] 🔧 Instance created');
    console.log('[ToolExecutor] 📊 Global callbacks count:', this.approvalCallbacks.size);
    console.log('[ToolExecutor] 📊 Global pending approvals:', this.pendingApprovals.size);
  }

  /**
   * Execute a command with full safety checks
   * 
   * This is the main entry point for AI agents to execute tools.
   * ALL executions must go through this method.
   */
  async execute(request: ExecutionRequest): Promise<ExecutionResult> {
    const startTime = Date.now();
    
    try {
      // Step 1: Check kill switch
      const killSwitchActive = await this.checkKillSwitch();
      if (killSwitchActive) {
        return this.createBlockedResult(
          request,
          'Kill switch is active - all operations are halted',
          { killSwitchActive: true }
        );
      }

      // Step 2: Validate command
      const validation = await this.validator.validate(request.command);
      if (!validation.allowed) {
        return this.createBlockedResult(
          request,
          validation.blockReason || 'Command validation failed',
          { validation }
        );
      }

      const tool = validation.tool!;

      // Step 3: Validate scope
      // Check if command uses file input (e.g., -l subdomains.txt, --list targets.txt)
      const fileInputMatch = request.command.match(/-l\s+(\S+)|--list\s+(\S+)|-i\s+(\S+)|--input\s+(\S+)/);
      
      let scopeValidation: {
        passed: boolean;
        target: string;
        reason?: string;
      };
      
      if (fileInputMatch) {
        // Extract file path from command
        const filePath = fileInputMatch[1] || fileInputMatch[2] || fileInputMatch[3] || fileInputMatch[4];
        
        console.log(`[ToolExecutor] Detected file input: ${filePath}`);
        
        // Check if file exists first (better error message)
        try {
          const fileExists = await invoke<boolean>('file_exists', { path: filePath });
          if (!fileExists) {
            console.error(`[ToolExecutor] File not found: ${filePath}`);
            
            return this.createBlockedResult(
              request,
              `Input file not found: ${filePath}. The file may not have been created from previous tool outputs. Ensure reconnaissance tools have completed successfully before running this command.`,
              {
                validation,
                scopeValidation: {
                  passed: false,
                  target: filePath,
                  reason: 'File does not exist',
                }
              }
            );
          }
        } catch (error) {
          console.error(`[ToolExecutor] Error checking file existence:`, error);
          return this.createBlockedResult(
            request,
            `Could not verify file existence: ${filePath}`,
            {
              validation,
              scopeValidation: {
                passed: false,
                target: filePath,
                reason: 'File check failed',
              }
            }
          );
        }
        
        console.log(`[ToolExecutor] File exists, validating targets from file...`);
        
        // Validate all targets in the file using Rust-side validation
        try {
          const validTargets = await invoke<string[]>('validate_targets_from_file', {
            filePath
          });
          
          console.log(`[ToolExecutor] File validation passed: ${validTargets.length} valid targets`);
          
          // All targets in file are valid
          scopeValidation = {
            passed: true,
            target: `${filePath} (${validTargets.length} targets)`,
          };
        } catch (error) {
          // File validation failed - some targets are out of scope
          const errorMessage = error instanceof Error ? error.message : String(error);
          
          console.error(`[ToolExecutor] File validation failed:`, errorMessage);
          
          return this.createBlockedResult(
            request,
            `File contains out-of-scope targets: ${errorMessage}`,
            {
              validation,
              scopeValidation: {
                passed: false,
                target: filePath,
                reason: errorMessage,
              }
            }
          );
        }
      } else {
        // Single target validation (original behavior)
        scopeValidation = await this.validateScope(request.context.target);
        if (!scopeValidation.passed) {
          return this.createBlockedResult(
            request,
            scopeValidation.reason || 'Target is out of scope',
            { validation, scopeValidation }
          );
        }
      }

      // Step 4: Check rate limit
      if (tool.rateLimiter) {
        const rateLimitAllowed = await tool.rateLimiter.checkLimit();
        const remainingTokens = tool.rateLimiter.getRemainingTokens();
        
        if (!rateLimitAllowed) {
          return this.createBlockedResult(
            request,
            `Rate limit exceeded for ${tool.name}. Remaining tokens: ${remainingTokens}`,
            {
              validation,
              scopeValidation,
              rateLimit: { allowed: false, remainingTokens },
            }
          );
        }
      }

      // Step 5: Human approval (if required)
      if (tool.requirements.requiresApproval && !request.skipApproval) {
        const approved = await this.requestHumanApproval({
          command: request.command,
          tool,
          validation,
          context: request.context,
          target: request.context.target,
        });

        if (!approved) {
          return this.createBlockedResult(
            request,
            'Human approval denied',
            { validation, scopeValidation, approvalGranted: false }
          );
        }
      }

      // Step 6: Execute command via PTY
      const commandToExecute = validation.sanitizedCommand || request.command;
      const executionResult = await this.executeViaPTY(
        commandToExecute,
        request.cwd,
        request.env,
        tool.name,
        request.context.executionId
      );

      // Step 7: Create result
      const result: ExecutionResult = {
        success: executionResult.success,
        command: request.command,
        sanitizedCommand: validation.sanitizedCommand,
        tool,
        validation,
        stdout: executionResult.stdout,
        stderr: executionResult.stderr,
        exitCode: executionResult.exitCode,
        executionTime: Date.now() - startTime,
        blocked: false,
        approvalGranted: true,
        scopeValidation,
        killSwitchActive: false,
        context: request.context,
        warnings: validation.warnings,
      };

      this.logExecution(result);
      return result;
    } catch (error) {
      const result = this.createBlockedResult(
        request,
        `Execution error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        {}
      );
      result.executionTime = Date.now() - startTime;
      this.logExecution(result);
      return result;
    }
  }

  /**
   * Execute command via Tauri PTY with proper output capture and file persistence
   */
  private async executeViaPTY(
    command: string,
    cwd?: string,
    env?: Record<string, string>,
    toolName?: string,
    sessionId?: string
  ): Promise<{
    success: boolean;
    stdout?: string;
    stderr?: string;
    exitCode?: number;
  }> {
    try {
      // Parse command into program and args
      const parts = command.split(' ');
      const program = parts[0];
      const args = parts.slice(1);
      
      console.log('[ToolExecutor] Executing via PTY:', { command: program, args });
      
      // Spawn PTY session for this command
      const sessionId = await invoke<string>('spawn_pty', {
        command: program,
        args: args,
      });
      
      console.log('[ToolExecutor] PTY session spawned:', sessionId);
      
      // Collect output by polling read_pty (correct command name)
      let output = '';
      let attempts = 0;
      const maxAttempts = 100; // 10 seconds total (100ms * 100)
      let consecutiveEmptyReads = 0;
      const maxConsecutiveEmpty = 20; // Stop after 2 seconds of no output
      
      while (attempts < maxAttempts) {
        try {
          const chunk = await invoke<string>('read_pty', {
            sessionId,
          });
          
          if (chunk && chunk.length > 0) {
            output += chunk;
            consecutiveEmptyReads = 0;
            console.log('[ToolExecutor] Received output chunk:', chunk.length, 'bytes');
          } else {
            consecutiveEmptyReads++;
            
            // If we've received some output and then get consecutive empty reads,
            // the command is likely done
            if (output.length > 0 && consecutiveEmptyReads >= maxConsecutiveEmpty) {
              console.log('[ToolExecutor] Command appears complete (no new output)');
              break;
            }
          }
        } catch (error) {
          console.warn('[ToolExecutor] Error reading PTY:', error);
          // Continue trying - the session might not have output yet
        }
        
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
      }
      
      console.log('[ToolExecutor] Output collection complete:', output.length, 'bytes');
      
      // Kill the PTY session
      await invoke('kill_pty', { sessionId }).catch(console.error);
      
      // Save output to file if tool produces list-based output
      if (toolName && sessionId && output && output.length > 0) {
        const listTools = ['subfinder', 'amass', 'httpx', 'waybackurls', 'gau', 'katana'];
        if (listTools.includes(toolName)) {
          try {
            const outputManager = getToolOutputManager();
            const outputPath = await outputManager.saveOutput(
              toolName,
              sessionId,
              output
            );
            console.log('[ToolExecutor] Saved tool output to:', outputPath);
          } catch (error) {
            console.warn('[ToolExecutor] Failed to save tool output:', error);
            // Non-fatal - continue execution
          }
        }
      }
      
      return {
        success: true,
        stdout: output || 'Command executed successfully (no output captured)',
        exitCode: 0,
      };
    } catch (error) {
      console.error('[ToolExecutor] PTY execution failed:', error);
      return {
        success: false,
        stderr: error instanceof Error ? error.message : 'Unknown error',
        exitCode: 1,
      };
    }
  }

  /**
   * Check kill switch status
   */
  private async checkKillSwitch(): Promise<boolean> {
    try {
      const active = await invoke<boolean>('is_kill_switch_active');
      return active;
    } catch (error) {
      console.error('Failed to check kill switch:', error);
      // Fail safe: assume active if we can't check
      return true;
    }
  }

  /**
   * Validate target scope
   */
  private async validateScope(target: string): Promise<{
    passed: boolean;
    target: string;
    reason?: string;
  }> {
    try {
      const isValid = await invoke<boolean>('validate_target', { target });
      return {
        passed: isValid,
        target,
      };
    } catch (error) {
      return {
        passed: false,
        target,
        reason: error instanceof Error ? error.message : 'Scope validation failed',
      };
    }
  }

  /**
   * Request human approval
   *
   * CRITICAL: This method MUST block execution until user approves/denies
   *
   * RACE CONDITION FIX V4: Timeout calls handleApprovalResponse directly
   * - Callback persists until handleApprovalResponse explicitly removes it
   * - Timeout triggers handleApprovalResponse(approvalId, false)
   * - This ensures consistent cleanup path for both timeout and user response
   */
  private async requestHumanApproval(
    request: ApprovalRequest
  ): Promise<boolean> {
    const approvalId = `approval_${Date.now()}_${Math.random()}`;
    
    console.log('[ToolExecutor] 🔒 BLOCKING for approval:', approvalId);
    console.log('[ToolExecutor] Command:', request.command);
    console.log('[ToolExecutor] Tool:', request.tool.name);
    
    // CRITICAL: Store pending approval BEFORE creating Promise
    this.pendingApprovals.set(approvalId, request);
    
    // Create the Promise that will block execution
    const approvalPromise = new Promise<boolean>((resolve) => {
      // Register callback IMMEDIATELY in Promise constructor
      // This callback MUST persist until handleApprovalResponse is called
      this.approvalCallbacks.set(approvalId, resolve);
      console.log('[ToolExecutor] 🔑 Callback registered for:', approvalId);
      console.log('[ToolExecutor] 📊 Total callbacks:', this.approvalCallbacks.size);
      
      // Setup timeout - call handleApprovalResponse to ensure consistent cleanup
      const timeoutId = setTimeout(() => {
        console.log('[ToolExecutor] ⏰ Approval timeout reached');
        // Check if callback still exists (it should unless already resolved)
        if (this.approvalCallbacks.has(approvalId)) {
          console.log('[ToolExecutor] ⏰ Auto-denying due to timeout');
          // Call handleApprovalResponse directly - this ensures consistent cleanup
          this.handleApprovalResponse(approvalId, false);
        }
      }, 5 * 60 * 1000); // 5 minute timeout
      
      // Store timeout ID on the resolve function so we can clear it
      (resolve as any).timeoutId = timeoutId;
    });
    
    // NOW emit the event - callback is guaranteed to exist
    console.log('[ToolExecutor] 📤 Emitting approval request event');
    window.dispatchEvent(
      new CustomEvent('tool-approval-request', {
        detail: {
          approvalId,
          request,
        },
      })
    );
    console.log('[ToolExecutor] ⏳ Waiting for user response...');
    
    return approvalPromise;
  }

  /**
   * Handle approval response from UI
   *
   * CRITICAL: This resolves the blocking promise, allowing execution to continue
   *
   * RACE CONDITION FIX V6: HMR-Persistent Storage + Callback Resurrection
   * - Callbacks stored in window.__huntress_approval_callbacks (survives HMR)
   * - If callback missing, attempt resurrection from pending approvals
   * - Defensive logging for debugging
   */
  handleApprovalResponse(approvalId: string, approved: boolean): void {
    console.log('[ToolExecutor] 📥 Received approval response:', approvalId, approved);
    console.log('[ToolExecutor] 📊 Global callbacks count:', this.approvalCallbacks.size);
    console.log('[ToolExecutor] 📊 Current callbacks:', Array.from(this.approvalCallbacks.keys()));
    
    let callback = this.approvalCallbacks.get(approvalId);
    
    // RESURRECTION MECHANISM: If callback missing but approval is pending, try to recover
    if (!callback && this.pendingApprovals.has(approvalId)) {
      console.warn('[ToolExecutor] ⚠️ Callback missing but approval is pending - attempting resurrection');
      console.warn('[ToolExecutor] 🔄 This likely happened due to HMR reload');
      
      // Create a new callback that will log the approval but can't unblock execution
      // The original promise is lost, but we can at least clean up state
      callback = (approved: boolean) => {
        console.log('[ToolExecutor] 🧟 Resurrected callback executed:', approved);
        console.log('[ToolExecutor] ⚠️ Original promise was lost - execution may be stuck');
        console.log('[ToolExecutor] 💡 User should restart the hunt if execution appears frozen');
      };
      
      console.warn('[ToolExecutor] 🧟 Callback resurrected - but original promise is lost');
      console.warn('[ToolExecutor] 💡 Recommendation: Restart hunt to avoid stuck execution');
    }
    
    if (callback) {
      console.log('[ToolExecutor] ✅ Found callback, resolving promise with:', approved);
      
      // Clear timeout if it exists (stored on the resolve function)
      const timeoutId = (callback as any).timeoutId;
      if (timeoutId) {
        clearTimeout(timeoutId);
        console.log('[ToolExecutor] ⏰ Cleared approval timeout');
      }
      
      // Resolve the promise - this unblocks the execute() method
      callback(approved);
      
      // Clean up from global storage
      this.approvalCallbacks.delete(approvalId);
      this.pendingApprovals.delete(approvalId);
      console.log('[ToolExecutor] 🔓 Execution unblocked, callback cleaned up');
      console.log('[ToolExecutor] 📊 Remaining callbacks:', this.approvalCallbacks.size);
    } else {
      console.error('[ToolExecutor] ❌ CRITICAL: No callback found for approval:', approvalId);
      console.error('[ToolExecutor] 📋 Available callbacks:', Array.from(this.approvalCallbacks.keys()));
      console.error('[ToolExecutor] 📋 Pending approvals:', Array.from(this.pendingApprovals.keys()));
      console.error('[ToolExecutor] ⚠️ Callback was completely lost - likely HMR occurred before approval was pending');
      console.error('[ToolExecutor] 💡 User should close modal and restart hunt');
    }
  }

  /**
   * Create blocked result
   */
  private createBlockedResult(
    request: ExecutionRequest,
    reason: string,
    additionalData: Partial<ExecutionResult>
  ): ExecutionResult {
    return {
      success: false,
      command: request.command,
      validation: additionalData.validation || {
        allowed: false,
        blockReason: reason,
      },
      blocked: true,
      blockReason: reason,
      context: request.context,
      ...additionalData,
    };
  }

  /**
   * Log execution
   */
  private logExecution(result: ExecutionResult): void {
    this.executionLog.push(result);

    // Keep only last 1000 executions
    if (this.executionLog.length > 1000) {
      this.executionLog.shift();
    }

    // Log to console
    if (result.blocked) {
      console.warn(
        `[ToolExecutor] BLOCKED: ${result.command}`,
        result.blockReason
      );
    } else if (result.success) {
      console.log(
        `[ToolExecutor] SUCCESS: ${result.command}`,
        `(${result.executionTime}ms)`
      );
    } else {
      console.error(
        `[ToolExecutor] FAILED: ${result.command}`,
        result.stderr
      );
    }
  }

  /**
   * Get execution log
   */
  getExecutionLog(): ExecutionResult[] {
    return this.executionLog;
  }

  /**
   * Get execution statistics
   */
  getStatistics(): {
    totalExecutions: number;
    successful: number;
    failed: number;
    blocked: number;
    byTool: Map<string, { success: number; failed: number; blocked: number }>;
    bySafetyLevel: Map<ToolSafetyLevel, { success: number; failed: number; blocked: number }>;
    averageExecutionTime: number;
  } {
    const stats = {
      totalExecutions: this.executionLog.length,
      successful: 0,
      failed: 0,
      blocked: 0,
      byTool: new Map<string, { success: number; failed: number; blocked: number }>(),
      bySafetyLevel: new Map<ToolSafetyLevel, { success: number; failed: number; blocked: number }>(),
      averageExecutionTime: 0,
    };

    let totalTime = 0;

    for (const result of this.executionLog) {
      if (result.blocked) {
        stats.blocked++;
      } else if (result.success) {
        stats.successful++;
      } else {
        stats.failed++;
      }

      if (result.executionTime) {
        totalTime += result.executionTime;
      }

      if (result.tool) {
        const toolName = result.tool.name;
        const toolStats = stats.byTool.get(toolName) || {
          success: 0,
          failed: 0,
          blocked: 0,
        };

        if (result.blocked) {
          toolStats.blocked++;
        } else if (result.success) {
          toolStats.success++;
        } else {
          toolStats.failed++;
        }

        stats.byTool.set(toolName, toolStats);

        const safetyLevel = result.tool.safetyLevel;
        const levelStats = stats.bySafetyLevel.get(safetyLevel) || {
          success: 0,
          failed: 0,
          blocked: 0,
        };

        if (result.blocked) {
          levelStats.blocked++;
        } else if (result.success) {
          levelStats.success++;
        } else {
          levelStats.failed++;
        }

        stats.bySafetyLevel.set(safetyLevel, levelStats);
      }
    }

    stats.averageExecutionTime =
      this.executionLog.length > 0 ? totalTime / this.executionLog.length : 0;

    return stats;
  }

  /**
   * Clear execution log
   */
  clearLog(): void {
    this.executionLog = [];
  }

  /**
   * Get pending approvals
   */
  getPendingApprovals(): ApprovalRequest[] {
    return Array.from(this.pendingApprovals.values());
  }

  /**
   * Get validator instance
   */
  getValidator(): CommandValidator {
    return this.validator;
  }

  /**
   * Get registry instance
   */
  getRegistry(): ToolRegistry {
    return this.registry;
  }
}

export default ToolExecutor;
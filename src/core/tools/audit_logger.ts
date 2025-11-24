/**
 * Audit Logger
 * 
 * Comprehensive logging and audit trail for all tool executions.
 * Critical for compliance, debugging, and security analysis.
 * 
 * FEATURES:
 * - Persistent logging to disk
 * - Structured JSON format
 * - Searchable and filterable
 * - Automatic rotation
 * - Export capabilities
 */

import { invoke } from '@tauri-apps/api/core';
import type { ExecutionResult, ExecutionContext } from './tool_executor';
import type { ValidationResult } from './command_validator';
import type { ToolMetadata } from './tool_registry';

/**
 * Audit log entry
 */
export interface AuditLogEntry {
  /** Unique log entry ID */
  id: string;
  
  /** Timestamp */
  timestamp: Date;
  
  /** Event type */
  eventType: 'execution' | 'validation' | 'approval' | 'block' | 'kill_switch' | 'scope_violation';
  
  /** Severity level */
  severity: 'info' | 'warning' | 'error' | 'critical';
  
  /** Agent ID */
  agentId?: string;
  
  /** Session ID */
  sessionId?: string;
  
  /** Command executed or attempted */
  command?: string;
  
  /** Tool metadata */
  tool?: ToolMetadata;
  
  /** Target */
  target?: string;
  
  /** Result */
  result?: 'success' | 'failure' | 'blocked';
  
  /** Execution time (ms) */
  executionTime?: number;
  
  /** Block reason */
  blockReason?: string;
  
  /** Validation result */
  validation?: ValidationResult;
  
  /** Additional context */
  context?: Record<string, any>;
  
  /** User who approved (if applicable) */
  approvedBy?: string;
  
  /** IP address (if available) */
  ipAddress?: string;
}

/**
 * Audit log filter
 */
export interface AuditLogFilter {
  /** Filter by event type */
  eventType?: AuditLogEntry['eventType'];
  
  /** Filter by severity */
  severity?: AuditLogEntry['severity'];
  
  /** Filter by agent ID */
  agentId?: string;
  
  /** Filter by session ID */
  sessionId?: string;
  
  /** Filter by result */
  result?: 'success' | 'failure' | 'blocked';
  
  /** Filter by date range */
  startDate?: Date;
  endDate?: Date;
  
  /** Filter by tool name */
  toolName?: string;
  
  /** Filter by target */
  target?: string;
  
  /** Search in command */
  commandSearch?: string;
}

/**
 * Audit Logger
 */
export class AuditLogger {
  private logs: AuditLogEntry[] = [];
  private maxInMemoryLogs: number = 10000;
  private logFilePath: string = 'logs/audit.jsonl';

  constructor(logFilePath?: string) {
    if (logFilePath) {
      this.logFilePath = logFilePath;
    }
  }

  /**
   * Log an execution
   */
  async logExecution(result: ExecutionResult): Promise<void> {
    const entry: AuditLogEntry = {
      id: `log_${Date.now()}_${Math.random()}`,
      timestamp: new Date(),
      eventType: 'execution',
      severity: result.blocked ? 'warning' : result.success ? 'info' : 'error',
      agentId: result.context.agentId,
      sessionId: result.context.sessionId,
      command: result.command,
      tool: result.tool,
      target: result.context.target,
      result: result.blocked ? 'blocked' : result.success ? 'success' : 'failure',
      executionTime: result.executionTime,
      blockReason: result.blockReason,
      validation: result.validation,
      context: {
        sanitizedCommand: result.sanitizedCommand,
        stdout: result.stdout?.substring(0, 1000), // Truncate for storage
        stderr: result.stderr?.substring(0, 1000),
        exitCode: result.exitCode,
        warnings: result.warnings,
        scopeValidation: result.scopeValidation,
        rateLimit: result.rateLimit,
        killSwitchActive: result.killSwitchActive,
      },
    };

    await this.addEntry(entry);
  }

  /**
   * Log a validation
   */
  async logValidation(
    command: string,
    validation: ValidationResult,
    context?: ExecutionContext
  ): Promise<void> {
    const entry: AuditLogEntry = {
      id: `log_${Date.now()}_${Math.random()}`,
      timestamp: new Date(),
      eventType: 'validation',
      severity: validation.allowed ? 'info' : 'warning',
      agentId: context?.agentId,
      sessionId: context?.sessionId,
      command,
      tool: validation.tool,
      target: context?.target,
      result: validation.allowed ? 'success' : 'blocked',
      blockReason: validation.blockReason,
      validation,
      context: {
        warnings: validation.warnings,
        requiredActions: validation.requiredActions,
        riskAssessment: validation.riskAssessment,
      },
    };

    await this.addEntry(entry);
  }

  /**
   * Log an approval request
   */
  async logApproval(
    command: string,
    tool: ToolMetadata,
    approved: boolean,
    approvedBy?: string,
    context?: ExecutionContext
  ): Promise<void> {
    const entry: AuditLogEntry = {
      id: `log_${Date.now()}_${Math.random()}`,
      timestamp: new Date(),
      eventType: 'approval',
      severity: approved ? 'info' : 'warning',
      agentId: context?.agentId,
      sessionId: context?.sessionId,
      command,
      tool,
      target: context?.target,
      result: approved ? 'success' : 'blocked',
      approvedBy,
      context: {
        approved,
      },
    };

    await this.addEntry(entry);
  }

  /**
   * Log a block event
   */
  async logBlock(
    command: string,
    reason: string,
    tool?: ToolMetadata,
    context?: ExecutionContext
  ): Promise<void> {
    const entry: AuditLogEntry = {
      id: `log_${Date.now()}_${Math.random()}`,
      timestamp: new Date(),
      eventType: 'block',
      severity: 'warning',
      agentId: context?.agentId,
      sessionId: context?.sessionId,
      command,
      tool,
      target: context?.target,
      result: 'blocked',
      blockReason: reason,
    };

    await this.addEntry(entry);
  }

  /**
   * Log a kill switch activation
   */
  async logKillSwitch(reason: string, context?: Record<string, any>): Promise<void> {
    const entry: AuditLogEntry = {
      id: `log_${Date.now()}_${Math.random()}`,
      timestamp: new Date(),
      eventType: 'kill_switch',
      severity: 'critical',
      blockReason: reason,
      context,
    };

    await this.addEntry(entry);
  }

  /**
   * Log a scope violation
   */
  async logScopeViolation(
    target: string,
    command?: string,
    context?: ExecutionContext
  ): Promise<void> {
    const entry: AuditLogEntry = {
      id: `log_${Date.now()}_${Math.random()}`,
      timestamp: new Date(),
      eventType: 'scope_violation',
      severity: 'error',
      agentId: context?.agentId,
      sessionId: context?.sessionId,
      command,
      target,
      result: 'blocked',
      blockReason: 'Target is out of scope',
    };

    await this.addEntry(entry);
  }

  /**
   * Add entry to log
   */
  private async addEntry(entry: AuditLogEntry): Promise<void> {
    // Add to in-memory log
    this.logs.push(entry);

    // Trim in-memory log if too large
    if (this.logs.length > this.maxInMemoryLogs) {
      this.logs.shift();
    }

    // Persist to disk
    await this.persistEntry(entry);

    // Log to console
    this.logToConsole(entry);
  }

  /**
   * Persist entry to disk
   */
  private async persistEntry(entry: AuditLogEntry): Promise<void> {
    try {
      const jsonLine = JSON.stringify(entry) + '\n';
      await invoke('append_to_file', {
        path: this.logFilePath,
        content: jsonLine,
      });
    } catch (error) {
      console.error('Failed to persist audit log entry:', error);
    }
  }

  /**
   * Log to console
   */
  private logToConsole(entry: AuditLogEntry): void {
    const prefix = `[AuditLogger] [${entry.severity.toUpperCase()}] [${entry.eventType}]`;
    const message = `${prefix} ${entry.command || entry.blockReason || 'Event'}`;

    switch (entry.severity) {
      case 'critical':
      case 'error':
        console.error(message, entry);
        break;
      case 'warning':
        console.warn(message, entry);
        break;
      default:
        console.log(message, entry);
    }
  }

  /**
   * Query logs with filters
   */
  query(filter: AuditLogFilter): AuditLogEntry[] {
    return this.logs.filter((entry) => {
      if (filter.eventType && entry.eventType !== filter.eventType) {
        return false;
      }
      if (filter.severity && entry.severity !== filter.severity) {
        return false;
      }
      if (filter.agentId && entry.agentId !== filter.agentId) {
        return false;
      }
      if (filter.sessionId && entry.sessionId !== filter.sessionId) {
        return false;
      }
      if (filter.result && entry.result !== filter.result) {
        return false;
      }
      if (filter.startDate && entry.timestamp < filter.startDate) {
        return false;
      }
      if (filter.endDate && entry.timestamp > filter.endDate) {
        return false;
      }
      if (filter.toolName && entry.tool?.name !== filter.toolName) {
        return false;
      }
      if (filter.target && entry.target !== filter.target) {
        return false;
      }
      if (filter.commandSearch && entry.command && !entry.command.includes(filter.commandSearch)) {
        return false;
      }
      return true;
    });
  }

  /**
   * Get all logs
   */
  getAllLogs(): AuditLogEntry[] {
    return this.logs;
  }

  /**
   * Get statistics
   */
  getStatistics(): {
    totalEntries: number;
    byEventType: Map<string, number>;
    bySeverity: Map<string, number>;
    byResult: Map<string, number>;
    blockedCommands: number;
    successfulExecutions: number;
    failedExecutions: number;
  } {
    const stats = {
      totalEntries: this.logs.length,
      byEventType: new Map<string, number>(),
      bySeverity: new Map<string, number>(),
      byResult: new Map<string, number>(),
      blockedCommands: 0,
      successfulExecutions: 0,
      failedExecutions: 0,
    };

    for (const entry of this.logs) {
      // Count by event type
      stats.byEventType.set(
        entry.eventType,
        (stats.byEventType.get(entry.eventType) || 0) + 1
      );

      // Count by severity
      stats.bySeverity.set(
        entry.severity,
        (stats.bySeverity.get(entry.severity) || 0) + 1
      );

      // Count by result
      if (entry.result) {
        stats.byResult.set(
          entry.result,
          (stats.byResult.get(entry.result) || 0) + 1
        );

        if (entry.result === 'blocked') {
          stats.blockedCommands++;
        } else if (entry.result === 'success') {
          stats.successfulExecutions++;
        } else if (entry.result === 'failure') {
          stats.failedExecutions++;
        }
      }
    }

    return stats;
  }

  /**
   * Export logs to JSON
   */
  exportToJSON(): string {
    return JSON.stringify(this.logs, null, 2);
  }

  /**
   * Export logs to CSV
   */
  exportToCSV(): string {
    const headers = [
      'ID',
      'Timestamp',
      'Event Type',
      'Severity',
      'Agent ID',
      'Session ID',
      'Command',
      'Tool',
      'Target',
      'Result',
      'Execution Time',
      'Block Reason',
    ];

    const rows = this.logs.map((entry) => [
      entry.id,
      entry.timestamp.toISOString(),
      entry.eventType,
      entry.severity,
      entry.agentId || '',
      entry.sessionId || '',
      entry.command || '',
      entry.tool?.name || '',
      entry.target || '',
      entry.result || '',
      entry.executionTime?.toString() || '',
      entry.blockReason || '',
    ]);

    return [headers, ...rows].map((row) => row.join(',')).join('\n');
  }

  /**
   * Clear in-memory logs
   */
  clearLogs(): void {
    this.logs = [];
  }
}

/**
 * Global audit logger instance
 */
let globalAuditLogger: AuditLogger | null = null;

/**
 * Get or create global audit logger
 */
export function getGlobalAuditLogger(): AuditLogger {
  if (!globalAuditLogger) {
    globalAuditLogger = new AuditLogger();
  }
  return globalAuditLogger;
}

export default AuditLogger;
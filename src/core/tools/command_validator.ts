/**
 * Command Validator
 * 
 * Validates and sanitizes security tool commands before execution.
 * Critical for preventing program violations and maintaining safety boundaries.
 * 
 * SECURITY GUARANTEES:
 * - Blocks all BLOCKED and FORBIDDEN tools
 * - Validates dangerous flag patterns
 * - Enforces rate limiting requirements
 * - Checks scope compliance
 * - Requires human approval for active tools
 * - Logs all validation attempts
 */

import { ToolRegistry, ToolSafetyLevel, type ToolMetadata } from './tool_registry';

/**
 * Command validation result
 */
export interface ValidationResult {
  /** Whether command is allowed */
  allowed: boolean;
  
  /** Tool metadata if found */
  tool?: ToolMetadata;
  
  /** Reason for blocking (if blocked) */
  blockReason?: string;
  
  /** Warnings (non-blocking) */
  warnings?: string[];
  
  /** Required actions before execution */
  requiredActions?: string[];
  
  /** Sanitized command (with dangerous flags removed) */
  sanitizedCommand?: string;
  
  /** Risk assessment */
  riskAssessment?: {
    level: 'low' | 'medium' | 'high' | 'critical';
    score: number;
    factors: string[];
  };
}

/**
 * Command parsing result
 */
interface ParsedCommand {
  toolName: string;
  args: string[];
  flags: Map<string, string | boolean>;
  rawCommand: string;
}

/**
 * Command Validator
 * 
 * Validates commands against tool registry and safety policies
 */
export class CommandValidator {
  private registry: ToolRegistry;
  private validationLog: Array<{
    command: string;
    timestamp: Date;
    result: ValidationResult;
  }> = [];

  constructor(registry: ToolRegistry) {
    this.registry = registry;
  }

  /**
   * Validate a command before execution
   * 
   * This is the main entry point for command validation.
   * ALL commands must pass through this before execution.
   */
  async validate(command: string): Promise<ValidationResult> {
    const timestamp = new Date();
    
    try {
      // Parse command
      const parsed = this.parseCommand(command);
      
      // Get tool metadata
      const tool = this.registry.getTool(parsed.toolName);
      
      if (!tool) {
        const result: ValidationResult = {
          allowed: false,
          blockReason: `Unknown tool: ${parsed.toolName}. Tool not registered in safety system.`,
        };
        this.logValidation(command, timestamp, result);
        return result;
      }

      // Check safety level
      const safetyCheck = this.checkSafetyLevel(tool);
      if (!safetyCheck.allowed) {
        this.logValidation(command, timestamp, safetyCheck);
        return safetyCheck;
      }

      // Check if tool is enabled
      if (!tool.enabled) {
        const result: ValidationResult = {
          allowed: false,
          tool,
          blockReason: `Tool ${tool.name} is disabled. ${
            tool.safetyLevel === ToolSafetyLevel.RESTRICTED
              ? 'Enable Medium Mode to use this tool.'
              : 'This tool is not available.'
          }`,
        };
        this.logValidation(command, timestamp, result);
        return result;
      }

      // Check for dangerous flags
      const flagCheck = this.checkDangerousFlags(tool, parsed);
      if (!flagCheck.allowed) {
        this.logValidation(command, timestamp, flagCheck);
        return flagCheck;
      }

      // Check rate limiting requirements
      const rateLimitCheck = await this.checkRateLimit(tool);
      if (!rateLimitCheck.allowed) {
        this.logValidation(command, timestamp, rateLimitCheck);
        return rateLimitCheck;
      }

      // Build required actions list
      const requiredActions: string[] = [];
      if (tool.requirements.requiresApproval) {
        requiredActions.push('Human approval required');
      }
      if (tool.requirements.requiresScopeValidation) {
        requiredActions.push('Scope validation required');
      }
      if (tool.requirements.requiresPolicyCheck) {
        requiredActions.push('Policy compliance check required');
      }

      // Perform risk assessment
      const riskAssessment = this.assessRisk(tool, parsed);

      // Build result
      const result: ValidationResult = {
        allowed: true,
        tool,
        warnings: flagCheck.warnings,
        requiredActions,
        sanitizedCommand: this.sanitizeCommand(command, tool),
        riskAssessment,
      };

      this.logValidation(command, timestamp, result);
      return result;
    } catch (error) {
      const result: ValidationResult = {
        allowed: false,
        blockReason: `Validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
      this.logValidation(command, timestamp, result);
      return result;
    }
  }

  /**
   * Parse command into components
   */
  private parseCommand(command: string): ParsedCommand {
    const parts = command.trim().split(/\s+/);
    const toolName = parts[0];
    const args: string[] = [];
    const flags = new Map<string, string | boolean>();

    for (let i = 1; i < parts.length; i++) {
      const part = parts[i];
      
      if (part.startsWith('-')) {
        // It's a flag
        const nextPart = parts[i + 1];
        if (nextPart && !nextPart.startsWith('-')) {
          // Flag with value
          flags.set(part, nextPart);
          i++; // Skip next part
        } else {
          // Boolean flag
          flags.set(part, true);
        }
      } else {
        // It's an argument
        args.push(part);
      }
    }

    return {
      toolName,
      args,
      flags,
      rawCommand: command,
    };
  }

  /**
   * Check tool safety level
   */
  private checkSafetyLevel(tool: ToolMetadata): ValidationResult {
    switch (tool.safetyLevel) {
      case ToolSafetyLevel.BLOCKED:
        return {
          allowed: false,
          tool,
          blockReason: `🚫 BLOCKED: ${tool.name} is a dangerous tool that is hard-blocked in production. Risk score: ${tool.riskScore}/100. This tool can result in program violations and bans.`,
        };

      case ToolSafetyLevel.FORBIDDEN:
        return {
          allowed: false,
          tool,
          blockReason: `⛔ FORBIDDEN: ${tool.name} is a DoS attack tool with INSTANT BAN RISK. This tool should not be installed on the system. Legal and platform consequences apply.`,
        };

      case ToolSafetyLevel.RESTRICTED:
        if (!this.registry.isMediumModeEnabled()) {
          return {
            allowed: false,
            tool,
            blockReason: `🔶 RESTRICTED: ${tool.name} requires Medium Mode to be enabled. This tool has a ${tool.riskScore}% ban risk if misused. Enable Medium Mode explicitly to proceed.`,
          };
        }
        return { allowed: true, tool };

      case ToolSafetyLevel.CONTROLLED:
      case ToolSafetyLevel.SAFE:
        return { allowed: true, tool };

      default:
        return {
          allowed: false,
          tool,
          blockReason: `Unknown safety level: ${tool.safetyLevel}`,
        };
    }
  }

  /**
   * Check for dangerous flags in command
   */
  private checkDangerousFlags(
    tool: ToolMetadata,
    parsed: ParsedCommand
  ): ValidationResult {
    if (!tool.dangerousFlags || tool.dangerousFlags.length === 0) {
      return { allowed: true, tool };
    }

    const warnings: string[] = [];
    const foundDangerousFlags: string[] = [];

    // Check each flag in the command against dangerous patterns.
    // Dangerous patterns can be:
    //   - A flag+value pair like "--level 5" or "-t 1000" — only matches that exact value
    //   - A standalone flag like "--os-shell" or "-active" — matches the flag regardless of value
    for (const dangerousPattern of tool.dangerousFlags) {
      const patternParts = dangerousPattern.trim().split(/\s+/);
      const patternFlag = patternParts[0];
      const patternValue = patternParts.length > 1 ? patternParts.slice(1).join(' ') : null;

      if (patternValue !== null) {
        // Flag+value pattern: only dangerous if the command uses this flag with this exact value
        const flagValue = parsed.flags.get(patternFlag);
        if (typeof flagValue === 'string' && flagValue === patternValue) {
          foundDangerousFlags.push(`${patternFlag} ${flagValue}`);
        }
      } else {
        // Standalone flag pattern: dangerous if the flag appears at all
        for (const [flag] of parsed.flags) {
          if (flag === patternFlag) {
            foundDangerousFlags.push(flag);
          }
        }
        // Also check arguments (e.g., "-active" passed as a positional arg)
        for (const arg of parsed.args) {
          if (arg === patternFlag) {
            foundDangerousFlags.push(arg);
          }
        }
      }
    }

    if (foundDangerousFlags.length > 0) {
      return {
        allowed: false,
        tool,
        blockReason: `Dangerous flags detected: ${foundDangerousFlags.join(', ')}. These flags can cause program violations. Use safer alternatives or remove these flags.`,
      };
    }

    return { allowed: true, tool, warnings };
  }

  /**
   * Check rate limiting
   */
  private async checkRateLimit(tool: ToolMetadata): Promise<ValidationResult> {
    if (!tool.requirements.requiresRateLimiting || !tool.rateLimiter) {
      return { allowed: true, tool };
    }

    const allowed = await tool.rateLimiter.checkLimit();
    
    if (!allowed) {
      const remainingTokens = tool.rateLimiter.getRemainingTokens();
      return {
        allowed: false,
        tool,
        blockReason: `Rate limit exceeded for ${tool.name}. Maximum ${tool.requirements.maxRequestsPerSecond} requests/second. Current tokens: ${remainingTokens}. Please wait before retrying.`,
      };
    }

    return { allowed: true, tool };
  }

  /**
   * Assess risk of command execution
   */
  private assessRisk(
    tool: ToolMetadata,
    parsed: ParsedCommand
  ): ValidationResult['riskAssessment'] {
    const factors: string[] = [];
    let score = tool.riskScore;

    // Check for aggressive rate settings
    const rateFlags = ['-rate', '--rate', '-t', '--threads', '-c', '--concurrency'];
    for (const [flag, value] of parsed.flags) {
      if (rateFlags.some(rf => flag.includes(rf))) {
        if (typeof value === 'string') {
          const numValue = parseInt(value, 10);
          if (numValue > 100) {
            score += 10;
            factors.push(`High concurrency: ${flag} ${value}`);
          }
        }
      }
    }

    // Check for recursive/deep scanning
    const recursiveFlags = ['-r', '--recursive', '-depth', '--depth'];
    for (const [flag] of parsed.flags) {
      if (recursiveFlags.some(rf => flag.includes(rf))) {
        score += 5;
        factors.push('Recursive scanning enabled');
        break;
      }
    }

    // Determine risk level
    let level: 'low' | 'medium' | 'high' | 'critical';
    if (score >= 80) {
      level = 'critical';
    } else if (score >= 50) {
      level = 'high';
    } else if (score >= 25) {
      level = 'medium';
    } else {
      level = 'low';
    }

    return {
      level,
      score,
      factors: factors.length > 0 ? factors : ['Standard usage'],
    };
  }

  /**
   * Sanitize command by removing/replacing dangerous elements
   */
  private sanitizeCommand(command: string, tool: ToolMetadata): string {
    let sanitized = command;

    // Remove dangerous flags if present
    if (tool.dangerousFlags) {
      for (const dangerousFlag of tool.dangerousFlags) {
        sanitized = sanitized.replace(new RegExp(dangerousFlag, 'g'), '');
      }
    }

    // Ensure rate limiting flags are present for controlled tools
    if (tool.requirements.requiresRateLimiting && tool.requirements.maxRequestsPerSecond > 0) {
      // Tool-specific rate limiting
      if (tool.name === 'nuclei' && !sanitized.includes('-rl')) {
        sanitized += ` -rl ${tool.requirements.maxRequestsPerSecond}`;
      } else if (tool.name === 'ffuf' && !sanitized.includes('-rate')) {
        sanitized += ` -rate ${tool.requirements.maxRequestsPerSecond}`;
      } else if (tool.name === 'feroxbuster' && !sanitized.includes('--rate-limit')) {
        sanitized += ` --rate-limit ${tool.requirements.maxRequestsPerSecond}`;
      }
    }

    return sanitized.trim();
  }

  /**
   * Validate command pattern against tool's allowed patterns
   */
  validatePattern(command: string, tool: ToolMetadata): boolean {
    if (!tool.commandPatterns || tool.commandPatterns.length === 0) {
      return true; // No patterns defined, allow all
    }

    return tool.commandPatterns.some(pattern => 
      command.includes(pattern) || new RegExp(pattern).test(command)
    );
  }

  /**
   * Get validation log
   */
  getValidationLog(): Array<{
    command: string;
    timestamp: Date;
    result: ValidationResult;
  }> {
    return this.validationLog;
  }

  /**
   * Log validation attempt
   */
  private logValidation(
    command: string,
    timestamp: Date,
    result: ValidationResult
  ): void {
    this.validationLog.push({
      command,
      timestamp,
      result,
    });

    // Keep only last 1000 entries
    if (this.validationLog.length > 1000) {
      this.validationLog.shift();
    }

    // Log to console for debugging
    if (!result.allowed) {
      console.warn(`[CommandValidator] BLOCKED: ${command}`, result.blockReason);
    } else if (result.warnings && result.warnings.length > 0) {
      console.warn(`[CommandValidator] WARNINGS: ${command}`, result.warnings);
    } else {
      console.log(`[CommandValidator] ALLOWED: ${command}`);
    }
  }

  /**
   * Clear validation log
   */
  clearLog(): void {
    this.validationLog = [];
  }

  /**
   * Get statistics
   */
  getStatistics(): {
    totalValidations: number;
    allowed: number;
    blocked: number;
    byTool: Map<string, { allowed: number; blocked: number }>;
    bySafetyLevel: Map<ToolSafetyLevel, { allowed: number; blocked: number }>;
  } {
    const stats = {
      totalValidations: this.validationLog.length,
      allowed: 0,
      blocked: 0,
      byTool: new Map<string, { allowed: number; blocked: number }>(),
      bySafetyLevel: new Map<ToolSafetyLevel, { allowed: number; blocked: number }>(),
    };

    for (const entry of this.validationLog) {
      if (entry.result.allowed) {
        stats.allowed++;
      } else {
        stats.blocked++;
      }

      if (entry.result.tool) {
        const toolName = entry.result.tool.name;
        const toolStats = stats.byTool.get(toolName) || { allowed: 0, blocked: 0 };
        if (entry.result.allowed) {
          toolStats.allowed++;
        } else {
          toolStats.blocked++;
        }
        stats.byTool.set(toolName, toolStats);

        const safetyLevel = entry.result.tool.safetyLevel;
        const levelStats = stats.bySafetyLevel.get(safetyLevel) || { allowed: 0, blocked: 0 };
        if (entry.result.allowed) {
          levelStats.allowed++;
        } else {
          levelStats.blocked++;
        }
        stats.bySafetyLevel.set(safetyLevel, levelStats);
      }
    }

    return stats;
  }
}

export default CommandValidator;
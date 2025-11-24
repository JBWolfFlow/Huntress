/**
 * AI-Powered Hunt Execution System - Tool Registry
 * 
 * Comprehensive tool classification and safety management system for
 * autonomous vulnerability hunting with strict safety controls.
 * 
 * CRITICAL: This system prevents program violations and bans by enforcing
 * tool safety levels, rate limits, and human approval requirements.
 */

import { RateLimiter, type RateLimitConfig } from '../../utils/rate_limiter';

/**
 * Tool Safety Levels
 * 
 * Classification system based on risk of program violations:
 * - SAFE: Passive recon only, no risk
 * - CONTROLLED: Light active tools, requires throttling
 * - RESTRICTED: Medium tools, requires explicit enable
 * - BLOCKED: Dangerous tools, hard blocked
 * - FORBIDDEN: DoS tools, not installed
 */
export enum ToolSafetyLevel {
  /** ✅ Passive reconnaissance only - Always allowed */
  SAFE = 'SAFE',
  
  /** ⚠️ Light active tools - Requires approval and rate limiting */
  CONTROLLED = 'CONTROLLED',
  
  /** 🔶 Medium tools - Requires explicit enable toggle */
  RESTRICTED = 'RESTRICTED',
  
  /** 🚫 Dangerous tools - Hard blocked in production */
  BLOCKED = 'BLOCKED',
  
  /** ⛔ DoS tools - Not installed, instant ban risk */
  FORBIDDEN = 'FORBIDDEN',
}

/**
 * Tool execution requirements
 */
export interface ToolRequirements {
  /** Requires human approval before execution */
  requiresApproval: boolean;
  
  /** Requires explicit "Enable Medium Mode" toggle */
  requiresExplicitEnable: boolean;
  
  /** Requires scope validation */
  requiresScopeValidation: boolean;
  
  /** Requires rate limiting */
  requiresRateLimiting: boolean;
  
  /** Maximum requests per second (0 = no limit) */
  maxRequestsPerSecond: number;
  
  /** Requires policy compliance check */
  requiresPolicyCheck: boolean;
}

/**
 * Tool metadata and configuration
 */
export interface ToolMetadata {
  /** Tool name (e.g., "subfinder", "nuclei") */
  name: string;
  
  /** Tool description for AI context */
  description: string;
  
  /** Safety classification */
  safetyLevel: ToolSafetyLevel;
  
  /** Execution requirements */
  requirements: ToolRequirements;
  
  /** Common command patterns */
  commandPatterns: string[];
  
  /** Dangerous flag patterns to block */
  dangerousFlags?: string[];
  
  /** Category (recon, scanning, exploitation, etc.) */
  category: string;
  
  /** Risk level (0-100, where 100 = instant ban) */
  riskScore: number;
  
  /** Whether tool is currently enabled */
  enabled: boolean;
  
  /** Rate limiter instance */
  rateLimiter?: RateLimiter;
}

/**
 * Tool execution result
 */
export interface ToolExecutionResult {
  success: boolean;
  output?: string;
  error?: string;
  blocked?: boolean;
  blockReason?: string;
  executionTime?: number;
  rateLimit?: {
    allowed: boolean;
    remainingTokens: number;
  };
}

/**
 * Enhanced Tool Registry with Safety Classifications
 * 
 * This registry manages all security tools with strict safety controls:
 * - Classifies tools by risk level
 * - Enforces rate limiting per tool
 * - Requires human approval for active tools
 * - Blocks dangerous tools completely
 * - Logs all execution attempts
 */
export class ToolRegistry {
  private tools: Map<string, ToolMetadata> = new Map();
  private mediumModeEnabled: boolean = false;
  private executionLog: Array<{
    tool: string;
    timestamp: Date;
    allowed: boolean;
    reason?: string;
  }> = [];

  constructor() {
    this.initializeDefaultTools();
  }

  /**
   * Initialize default tool classifications
   */
  private initializeDefaultTools(): void {
    // ✅ SAFE - Passive Recon Tools
    this.registerTool({
      name: 'subfinder',
      description: 'Passive subdomain enumeration using multiple sources',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: {
        requiresApproval: true, // SECURITY: All tools require approval
        requiresExplicitEnable: false,
        requiresScopeValidation: true,
        requiresRateLimiting: false,
        maxRequestsPerSecond: 0,
        requiresPolicyCheck: true,
      },
      commandPatterns: ['subfinder -d', 'subfinder -dL'],
      category: 'passive-recon',
      riskScore: 0,
      enabled: true,
    });

    this.registerTool({
      name: 'amass',
      description: 'Passive network mapping and asset discovery',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: {
        requiresApproval: true, // SECURITY: All tools require approval
        requiresExplicitEnable: false,
        requiresScopeValidation: true,
        requiresRateLimiting: false,
        maxRequestsPerSecond: 0,
        requiresPolicyCheck: true,
      },
      commandPatterns: ['amass enum -passive', 'amass intel'],
      dangerousFlags: ['-active', '-brute'],
      category: 'passive-recon',
      riskScore: 0,
      enabled: true,
    });

    this.registerTool({
      name: 'httpx',
      description: 'Fast HTTP probe for discovering live hosts',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: {
        requiresApproval: true, // SECURITY: All tools require approval
        requiresExplicitEnable: false,
        requiresScopeValidation: true,
        requiresRateLimiting: false,
        maxRequestsPerSecond: 0,
        requiresPolicyCheck: true,
      },
      commandPatterns: ['httpx -l', 'httpx -u'],
      category: 'passive-recon',
      riskScore: 5,
      enabled: true,
    });

    this.registerTool({
      name: 'waybackurls',
      description: 'Fetch URLs from Wayback Machine',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: {
        requiresApproval: true, // SECURITY: All tools require approval
        requiresExplicitEnable: false,
        requiresScopeValidation: true,
        requiresRateLimiting: false,
        maxRequestsPerSecond: 0,
        requiresPolicyCheck: true,
      },
      commandPatterns: ['waybackurls'],
      category: 'passive-recon',
      riskScore: 0,
      enabled: true,
    });

    this.registerTool({
      name: 'gau',
      description: 'Get All URLs from AlienVault, Wayback, etc.',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: {
        requiresApproval: true, // SECURITY: All tools require approval
        requiresExplicitEnable: false,
        requiresScopeValidation: true,
        requiresRateLimiting: false,
        maxRequestsPerSecond: 0,
        requiresPolicyCheck: true,
      },
      commandPatterns: ['gau'],
      category: 'passive-recon',
      riskScore: 0,
      enabled: true,
    });

    // ⚠️ CONTROLLED - Light Active Tools
    this.registerTool({
      name: 'nuclei',
      description: 'Vulnerability scanner with templates',
      safetyLevel: ToolSafetyLevel.CONTROLLED,
      requirements: {
        requiresApproval: true,
        requiresExplicitEnable: false,
        requiresScopeValidation: true,
        requiresRateLimiting: true,
        maxRequestsPerSecond: 5,
        requiresPolicyCheck: true,
      },
      commandPatterns: ['nuclei -u', 'nuclei -l'],
      dangerousFlags: ['-rl 0', '-c 0', '-bulk-size'],
      category: 'scanning',
      riskScore: 30,
      enabled: true,
      rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'ffuf',
      description: 'Fast web fuzzer for directory/file discovery',
      safetyLevel: ToolSafetyLevel.CONTROLLED,
      requirements: {
        requiresApproval: true,
        requiresExplicitEnable: false,
        requiresScopeValidation: true,
        requiresRateLimiting: true,
        maxRequestsPerSecond: 10,
        requiresPolicyCheck: true,
      },
      commandPatterns: ['ffuf -u', 'ffuf -w'],
      dangerousFlags: ['-rate 0', '-t 1000'],
      category: 'fuzzing',
      riskScore: 35,
      enabled: true,
      rateLimiter: new RateLimiter({ maxRequests: 10, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'feroxbuster',
      description: 'Fast content discovery tool',
      safetyLevel: ToolSafetyLevel.CONTROLLED,
      requirements: {
        requiresApproval: true,
        requiresExplicitEnable: false,
        requiresScopeValidation: true,
        requiresRateLimiting: true,
        maxRequestsPerSecond: 10,
        requiresPolicyCheck: true,
      },
      commandPatterns: ['feroxbuster -u', 'feroxbuster --url'],
      dangerousFlags: ['--rate-limit 0', '--threads 1000'],
      category: 'fuzzing',
      riskScore: 35,
      enabled: true,
      rateLimiter: new RateLimiter({ maxRequests: 10, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'katana',
      description: 'Web crawling framework',
      safetyLevel: ToolSafetyLevel.CONTROLLED,
      requirements: {
        requiresApproval: true,
        requiresExplicitEnable: false,
        requiresScopeValidation: true,
        requiresRateLimiting: true,
        maxRequestsPerSecond: 5,
        requiresPolicyCheck: true,
      },
      commandPatterns: ['katana -u', 'katana -list'],
      category: 'crawling',
      riskScore: 25,
      enabled: true,
      rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 1000 }),
    });

    // 🔶 RESTRICTED - Medium Tools
    this.registerTool({
      name: 'sqlmap',
      description: 'SQL injection detection and exploitation (LOW mode only)',
      safetyLevel: ToolSafetyLevel.RESTRICTED,
      requirements: {
        requiresApproval: true,
        requiresExplicitEnable: true,
        requiresScopeValidation: true,
        requiresRateLimiting: true,
        maxRequestsPerSecond: 2,
        requiresPolicyCheck: true,
      },
      commandPatterns: ['sqlmap -u', 'sqlmap --url'],
      dangerousFlags: ['--level 5', '--risk 3', '--os-shell', '--sql-shell'],
      category: 'exploitation',
      riskScore: 50,
      enabled: false,
      rateLimiter: new RateLimiter({ maxRequests: 2, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'dirsearch',
      description: 'Web path scanner',
      safetyLevel: ToolSafetyLevel.RESTRICTED,
      requirements: {
        requiresApproval: true,
        requiresExplicitEnable: true,
        requiresScopeValidation: true,
        requiresRateLimiting: true,
        maxRequestsPerSecond: 5,
        requiresPolicyCheck: true,
      },
      commandPatterns: ['dirsearch -u', 'dirsearch --url'],
      dangerousFlags: ['--threads 1000'],
      category: 'scanning',
      riskScore: 45,
      enabled: false,
      rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'arjun',
      description: 'HTTP parameter discovery',
      safetyLevel: ToolSafetyLevel.RESTRICTED,
      requirements: {
        requiresApproval: true,
        requiresExplicitEnable: true,
        requiresScopeValidation: true,
        requiresRateLimiting: true,
        maxRequestsPerSecond: 5,
        requiresPolicyCheck: true,
      },
      commandPatterns: ['arjun -u', 'arjun --url'],
      category: 'fuzzing',
      riskScore: 40,
      enabled: false,
      rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 1000 }),
    });

    // 🚫 BLOCKED - Dangerous Tools
    this.registerTool({
      name: 'hydra',
      description: 'BLOCKED: Password brute-forcing tool',
      safetyLevel: ToolSafetyLevel.BLOCKED,
      requirements: {
        requiresApproval: false,
        requiresExplicitEnable: false,
        requiresScopeValidation: false,
        requiresRateLimiting: false,
        maxRequestsPerSecond: 0,
        requiresPolicyCheck: false,
      },
      commandPatterns: ['hydra'],
      category: 'exploitation',
      riskScore: 100,
      enabled: false,
    });

    this.registerTool({
      name: 'medusa',
      description: 'BLOCKED: Password brute-forcing tool',
      safetyLevel: ToolSafetyLevel.BLOCKED,
      requirements: {
        requiresApproval: false,
        requiresExplicitEnable: false,
        requiresScopeValidation: false,
        requiresRateLimiting: false,
        maxRequestsPerSecond: 0,
        requiresPolicyCheck: false,
      },
      commandPatterns: ['medusa'],
      category: 'exploitation',
      riskScore: 100,
      enabled: false,
    });

    this.registerTool({
      name: 'nmap',
      description: 'BLOCKED: Network scanner (SYN scan mode)',
      safetyLevel: ToolSafetyLevel.BLOCKED,
      requirements: {
        requiresApproval: false,
        requiresExplicitEnable: false,
        requiresScopeValidation: false,
        requiresRateLimiting: false,
        maxRequestsPerSecond: 0,
        requiresPolicyCheck: false,
      },
      commandPatterns: ['nmap -sS', 'nmap -sU'],
      dangerousFlags: ['-sS', '-sU', '-sN', '-sF', '-sX'],
      category: 'scanning',
      riskScore: 100,
      enabled: false,
    });

    this.registerTool({
      name: 'metasploit',
      description: 'BLOCKED: Exploitation framework',
      safetyLevel: ToolSafetyLevel.BLOCKED,
      requirements: {
        requiresApproval: false,
        requiresExplicitEnable: false,
        requiresScopeValidation: false,
        requiresRateLimiting: false,
        maxRequestsPerSecond: 0,
        requiresPolicyCheck: false,
      },
      commandPatterns: ['msfconsole', 'msfvenom'],
      category: 'exploitation',
      riskScore: 100,
      enabled: false,
    });

    // ⛔ FORBIDDEN - DoS Tools
    this.registerTool({
      name: 'slowloris',
      description: 'FORBIDDEN: DoS attack tool - INSTANT BAN RISK',
      safetyLevel: ToolSafetyLevel.FORBIDDEN,
      requirements: {
        requiresApproval: false,
        requiresExplicitEnable: false,
        requiresScopeValidation: false,
        requiresRateLimiting: false,
        maxRequestsPerSecond: 0,
        requiresPolicyCheck: false,
      },
      commandPatterns: ['slowloris'],
      category: 'dos',
      riskScore: 100,
      enabled: false,
    });

    this.registerTool({
      name: 'goldeneye',
      description: 'FORBIDDEN: DoS attack tool - INSTANT BAN RISK',
      safetyLevel: ToolSafetyLevel.FORBIDDEN,
      requirements: {
        requiresApproval: false,
        requiresExplicitEnable: false,
        requiresScopeValidation: false,
        requiresRateLimiting: false,
        maxRequestsPerSecond: 0,
        requiresPolicyCheck: false,
      },
      commandPatterns: ['goldeneye'],
      category: 'dos',
      riskScore: 100,
      enabled: false,
    });
  }

  /**
   * Register a new tool
   */
  registerTool(metadata: ToolMetadata): void {
    this.tools.set(metadata.name, metadata);
  }

  /**
   * Get tool metadata
   */
  getTool(name: string): ToolMetadata | undefined {
    return this.tools.get(name);
  }

  /**
   * Get all tools by safety level
   */
  getToolsBySafetyLevel(level: ToolSafetyLevel): ToolMetadata[] {
    return Array.from(this.tools.values()).filter(
      (tool) => tool.safetyLevel === level
    );
  }

  /**
   * Get all enabled tools
   */
  getEnabledTools(): ToolMetadata[] {
    return Array.from(this.tools.values()).filter((tool) => tool.enabled);
  }

  /**
   * Enable medium mode (allows RESTRICTED tools)
   */
  enableMediumMode(): void {
    this.mediumModeEnabled = true;
    // Enable all RESTRICTED tools
    this.getToolsBySafetyLevel(ToolSafetyLevel.RESTRICTED).forEach((tool) => {
      const metadata = this.tools.get(tool.name);
      if (metadata) {
        metadata.enabled = true;
      }
    });
  }

  /**
   * Disable medium mode
   */
  disableMediumMode(): void {
    this.mediumModeEnabled = false;
    // Disable all RESTRICTED tools
    this.getToolsBySafetyLevel(ToolSafetyLevel.RESTRICTED).forEach((tool) => {
      const metadata = this.tools.get(tool.name);
      if (metadata) {
        metadata.enabled = false;
      }
    });
  }

  /**
   * Check if medium mode is enabled
   */
  isMediumModeEnabled(): boolean {
    return this.mediumModeEnabled;
  }

  /**
   * Get tool descriptions for AI context
   */
  getToolDescriptionsForAI(): string {
    const enabledTools = this.getEnabledTools();
    return enabledTools
      .map((tool) => {
        const safetyBadge = {
          [ToolSafetyLevel.SAFE]: '✅',
          [ToolSafetyLevel.CONTROLLED]: '⚠️',
          [ToolSafetyLevel.RESTRICTED]: '🔶',
          [ToolSafetyLevel.BLOCKED]: '🚫',
          [ToolSafetyLevel.FORBIDDEN]: '⛔',
        }[tool.safetyLevel];

        return `${safetyBadge} ${tool.name}: ${tool.description} [${tool.safetyLevel}]`;
      })
      .join('\n');
  }

  /**
   * Get execution log
   */
  getExecutionLog(): Array<{
    tool: string;
    timestamp: Date;
    allowed: boolean;
    reason?: string;
  }> {
    return this.executionLog;
  }

  /**
   * Log execution attempt
   */
  private logExecution(
    tool: string,
    allowed: boolean,
    reason?: string
  ): void {
    this.executionLog.push({
      tool,
      timestamp: new Date(),
      allowed,
      reason,
    });

    // Keep only last 1000 entries
    if (this.executionLog.length > 1000) {
      this.executionLog.shift();
    }
  }

  /**
   * List all registered tools
   */
  listTools(): ToolMetadata[] {
    return Array.from(this.tools.values());
  }
}

export default ToolRegistry;
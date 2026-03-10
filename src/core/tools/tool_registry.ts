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

    // ✅ SAFE - Additional Recon Tools
    this.registerTool({
      name: 'assetfinder',
      description: 'Find domains and subdomains related to a given domain',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['assetfinder --subs-only'],
      category: 'passive-recon', riskScore: 0, enabled: true,
    });

    this.registerTool({
      name: 'dnsx',
      description: 'Fast DNS toolkit for resolution and probing',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['dnsx -l', 'dnsx -d'],
      category: 'passive-recon', riskScore: 0, enabled: true,
    });

    this.registerTool({
      name: 'findomain',
      description: 'Cross-platform subdomain enumerator',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['findomain -t'],
      category: 'passive-recon', riskScore: 0, enabled: true,
    });

    this.registerTool({
      name: 'wafw00f',
      description: 'Web Application Firewall detection tool',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['wafw00f'],
      category: 'passive-recon', riskScore: 5, enabled: true,
    });

    this.registerTool({
      name: 'gospider',
      description: 'Fast web spider for URL and endpoint discovery',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 5, requiresPolicyCheck: true },
      commandPatterns: ['gospider -s', 'gospider -S'],
      category: 'passive-recon', riskScore: 10, enabled: true,
      rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'jsluice',
      description: 'Extract URLs, paths, and secrets from JavaScript files',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: false, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['jsluice urls', 'jsluice secrets'],
      category: 'passive-recon', riskScore: 0, enabled: true,
    });

    this.registerTool({
      name: 'getJS',
      description: 'Fetch JavaScript files from a target',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['getJS --url'],
      category: 'passive-recon', riskScore: 5, enabled: true,
    });

    this.registerTool({
      name: 'paramspider',
      description: 'Passive parameter discovery from web archives',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['paramspider -d'],
      category: 'passive-recon', riskScore: 0, enabled: true,
    });

    this.registerTool({
      name: 'whois',
      description: 'Domain registration lookup',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: false, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['whois'],
      category: 'passive-recon', riskScore: 0, enabled: true,
    });

    this.registerTool({
      name: 'dig',
      description: 'DNS lookup utility',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: false, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['dig'],
      category: 'passive-recon', riskScore: 0, enabled: true,
    });

    this.registerTool({
      name: 'gowitness',
      description: 'Web screenshot utility for evidence collection',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['gowitness scan', 'gowitness single'],
      category: 'passive-recon', riskScore: 5, enabled: true,
    });

    this.registerTool({
      name: 'testssl.sh',
      description: 'SSL/TLS testing and vulnerability detection',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['testssl.sh', 'testssl'],
      category: 'passive-recon', riskScore: 5, enabled: true,
    });

    this.registerTool({
      name: 'sslyze',
      description: 'Fast SSL/TLS scanner',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['sslyze'],
      category: 'passive-recon', riskScore: 5, enabled: true,
    });

    this.registerTool({
      name: 'searchsploit',
      description: 'Search Exploit-DB for known exploits',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: false, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['searchsploit'],
      category: 'passive-recon', riskScore: 0, enabled: true,
    });

    this.registerTool({
      name: 'whatweb',
      description: 'Web technology fingerprinting',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['whatweb -a 1', 'whatweb -a 3'],
      dangerousFlags: ['-a 4'],
      category: 'passive-recon', riskScore: 5, enabled: true,
    });

    this.registerTool({
      name: 'curl',
      description: 'HTTP request utility',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['curl -s', 'curl -v', 'curl -I'],
      category: 'utility', riskScore: 5, enabled: true,
    });

    // ✅ SAFE - Data Processing Utilities
    this.registerTool({
      name: 'jq',
      description: 'JSON processing and filtering',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: false, requiresExplicitEnable: false, requiresScopeValidation: false, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: false },
      commandPatterns: ['jq'],
      category: 'utility', riskScore: 0, enabled: true,
    });

    this.registerTool({
      name: 'anew',
      description: 'Append lines from stdin to a file, deduplicating',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: false, requiresExplicitEnable: false, requiresScopeValidation: false, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: false },
      commandPatterns: ['anew'],
      category: 'utility', riskScore: 0, enabled: true,
    });

    this.registerTool({
      name: 'qsreplace',
      description: 'Replace URL query parameter values',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: false, requiresExplicitEnable: false, requiresScopeValidation: false, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: false },
      commandPatterns: ['qsreplace'],
      category: 'utility', riskScore: 0, enabled: true,
    });

    this.registerTool({
      name: 'unfurl',
      description: 'URL parsing and extraction',
      safetyLevel: ToolSafetyLevel.SAFE,
      requirements: { requiresApproval: false, requiresExplicitEnable: false, requiresScopeValidation: false, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: false },
      commandPatterns: ['unfurl'],
      category: 'utility', riskScore: 0, enabled: true,
    });

    // ⚠️ CONTROLLED - Additional Scanning Tools
    this.registerTool({
      name: 'naabu',
      description: 'Bug-bounty-safe port scanner (TCP connect only)',
      safetyLevel: ToolSafetyLevel.CONTROLLED,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 10, requiresPolicyCheck: true },
      commandPatterns: ['naabu -host', 'naabu -l'],
      dangerousFlags: ['-rate 0'],
      category: 'scanning', riskScore: 30, enabled: true,
      rateLimiter: new RateLimiter({ maxRequests: 10, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'nikto',
      description: 'Web server vulnerability scanner',
      safetyLevel: ToolSafetyLevel.CONTROLLED,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 5, requiresPolicyCheck: true },
      commandPatterns: ['nikto -host', 'nikto -h'],
      category: 'scanning', riskScore: 35, enabled: true,
      rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'wpscan',
      description: 'WordPress vulnerability scanner',
      safetyLevel: ToolSafetyLevel.CONTROLLED,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 5, requiresPolicyCheck: true },
      commandPatterns: ['wpscan --url'],
      dangerousFlags: ['--passwords', '--usernames'],
      category: 'scanning', riskScore: 35, enabled: true,
      rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'gobuster',
      description: 'Directory and file brute-force scanner',
      safetyLevel: ToolSafetyLevel.CONTROLLED,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 10, requiresPolicyCheck: true },
      commandPatterns: ['gobuster dir', 'gobuster dns', 'gobuster vhost'],
      dangerousFlags: ['--threads 1000'],
      category: 'fuzzing', riskScore: 35, enabled: true,
      rateLimiter: new RateLimiter({ maxRequests: 10, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'nmap',
      description: 'Network scanner (TCP connect scan only — SYN scan blocked)',
      safetyLevel: ToolSafetyLevel.CONTROLLED,
      requirements: { requiresApproval: true, requiresExplicitEnable: false, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 5, requiresPolicyCheck: true },
      commandPatterns: ['nmap -sT', 'nmap -sV', 'nmap -sC'],
      dangerousFlags: ['-sS', '-sU', '-sN', '-sF', '-sX', '-O', '--script=exploit'],
      category: 'scanning', riskScore: 40, enabled: true,
      rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 1000 }),
    });

    // 🔶 RESTRICTED - Active Testing Tools
    this.registerTool({
      name: 'sqlmap',
      description: 'SQL injection detection and exploitation (LOW mode only)',
      safetyLevel: ToolSafetyLevel.RESTRICTED,
      requirements: { requiresApproval: true, requiresExplicitEnable: true, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 2, requiresPolicyCheck: true },
      commandPatterns: ['sqlmap -u', 'sqlmap --url'],
      dangerousFlags: ['--level 5', '--risk 3', '--os-shell', '--sql-shell', '--priv-esc', '--file-write'],
      category: 'exploitation', riskScore: 50, enabled: false,
      rateLimiter: new RateLimiter({ maxRequests: 2, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'ghauri',
      description: 'Advanced SQL injection detection tool',
      safetyLevel: ToolSafetyLevel.RESTRICTED,
      requirements: { requiresApproval: true, requiresExplicitEnable: true, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 2, requiresPolicyCheck: true },
      commandPatterns: ['ghauri -u', 'ghauri --url'],
      dangerousFlags: ['--os-shell'],
      category: 'exploitation', riskScore: 50, enabled: false,
      rateLimiter: new RateLimiter({ maxRequests: 2, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'dalfox',
      description: 'XSS vulnerability scanner with JSON output',
      safetyLevel: ToolSafetyLevel.RESTRICTED,
      requirements: { requiresApproval: true, requiresExplicitEnable: true, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 5, requiresPolicyCheck: true },
      commandPatterns: ['dalfox url', 'dalfox file', 'dalfox pipe'],
      category: 'exploitation', riskScore: 45, enabled: false,
      rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'xsstrike',
      description: 'Advanced XSS detection suite',
      safetyLevel: ToolSafetyLevel.RESTRICTED,
      requirements: { requiresApproval: true, requiresExplicitEnable: true, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 3, requiresPolicyCheck: true },
      commandPatterns: ['xsstrike -u', 'xsstrike --url'],
      category: 'exploitation', riskScore: 45, enabled: false,
      rateLimiter: new RateLimiter({ maxRequests: 3, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'kxss',
      description: 'Reflected parameter detection for XSS',
      safetyLevel: ToolSafetyLevel.RESTRICTED,
      requirements: { requiresApproval: true, requiresExplicitEnable: true, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 5, requiresPolicyCheck: true },
      commandPatterns: ['kxss'],
      category: 'exploitation', riskScore: 40, enabled: false,
      rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'corsy',
      description: 'CORS misconfiguration scanner',
      safetyLevel: ToolSafetyLevel.RESTRICTED,
      requirements: { requiresApproval: true, requiresExplicitEnable: true, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 5, requiresPolicyCheck: true },
      commandPatterns: ['corsy -u', 'corsy -i'],
      category: 'exploitation', riskScore: 35, enabled: false,
      rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'interactsh-client',
      description: 'Out-of-band interaction detection (DNS/HTTP/SMTP callbacks)',
      safetyLevel: ToolSafetyLevel.RESTRICTED,
      requirements: { requiresApproval: true, requiresExplicitEnable: true, requiresScopeValidation: false, requiresRateLimiting: false, maxRequestsPerSecond: 0, requiresPolicyCheck: true },
      commandPatterns: ['interactsh-client'],
      category: 'exploitation', riskScore: 30, enabled: false,
    });

    this.registerTool({
      name: 'subjack',
      description: 'Subdomain takeover detection via dangling CNAME',
      safetyLevel: ToolSafetyLevel.RESTRICTED,
      requirements: { requiresApproval: true, requiresExplicitEnable: true, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 5, requiresPolicyCheck: true },
      commandPatterns: ['subjack -w', 'subjack -a'],
      category: 'exploitation', riskScore: 35, enabled: false,
      rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'dirsearch',
      description: 'Web path scanner',
      safetyLevel: ToolSafetyLevel.RESTRICTED,
      requirements: { requiresApproval: true, requiresExplicitEnable: true, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 5, requiresPolicyCheck: true },
      commandPatterns: ['dirsearch -u', 'dirsearch --url'],
      dangerousFlags: ['--threads 1000'],
      category: 'scanning', riskScore: 45, enabled: false,
      rateLimiter: new RateLimiter({ maxRequests: 5, windowMs: 1000 }),
    });

    this.registerTool({
      name: 'arjun',
      description: 'HTTP parameter discovery',
      safetyLevel: ToolSafetyLevel.RESTRICTED,
      requirements: { requiresApproval: true, requiresExplicitEnable: true, requiresScopeValidation: true, requiresRateLimiting: true, maxRequestsPerSecond: 5, requiresPolicyCheck: true },
      commandPatterns: ['arjun -u', 'arjun --url'],
      category: 'fuzzing', riskScore: 40, enabled: false,
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
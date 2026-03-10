/**
 * AI Agent Loop - Complete Hunt Execution with Real Tool Execution
 *
 * This orchestrates the complete vulnerability hunting workflow:
 * 1. AI analyzes target and decides which tools to run
 * 2. Requests approval for each tool
 * 3. Executes tools via the safety system
 * 4. Parses results and feeds back to AI
 * 5. AI decides next steps based on findings
 * 6. Continues until hunt is complete
 * 7. Automatically creates target files from recon results for active testing
 */

import type { ModelProvider, ChatMessage, ChatResponse } from '../providers/types';
import { AIAgentToolInterface } from './tool_integration';
import type { ExecutionResult } from '../tools/tool_executor';
import { StreamingCallback, CheckpointCallback, HuntPhase, AIReasoningType } from './supervisor';
import { getToolOutputManager } from '../../utils/tool_output_manager';

/**
 * Tool execution decision from AI
 */
export interface ToolDecision {
  toolName: string;
  command: string;
  reasoning: string;
  target: string;
  expectedFindings: string[];
}

/**
 * Parsed finding from tool output
 */
export interface Finding {
  type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  description: string;
  evidence: string;
  target: string;
  tool: string;
  timestamp: Date;
}

/**
 * Vulnerability found during hunt
 */
export interface Vulnerability {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  impact: string;
  reproduction: string[];
  evidence: string[];
  target: string;
  discoveredBy: string;
  timestamp: Date;
}

/**
 * Hunt result
 */
export interface HuntResult {
  success: boolean;
  phase: HuntPhase;
  toolsExecuted: number;
  findingsCount: number;
  vulnerabilities: Vulnerability[];
  duration: number;
  error?: string;
}

/**
 * Hunt configuration
 */
export interface HuntConfig {
  target: string;
  scope: string[];
  guidelines: string;
  toolInterface: AIAgentToolInterface;
  streamingCallback: StreamingCallback;
  checkpointCallback: CheckpointCallback;
  apiKey: string;
  provider?: ModelProvider;
  model?: string;
  maxIterations?: number;
}

/**
 * AI Agent Loop
 * 
 * Orchestrates the complete hunt with real tool execution
 */
export class AIAgentLoop {
  private provider: ModelProvider;
  private config: HuntConfig;
  private conversationHistory: ChatMessage[] = [];
  private toolsExecuted: number = 0;
  private findings: Finding[] = [];
  private vulnerabilities: Vulnerability[] = [];
  private currentPhase: HuntPhase = HuntPhase.INITIALIZATION;
  private reconSessionIds: string[] = []; // Track recon tool session IDs for file creation
  private providerReady: Promise<void>;

  constructor(config: HuntConfig) {
    this.config = {
      model: 'claude-sonnet-4-5-20250929',
      maxIterations: 20,
      ...config,
    };

    if (config.provider) {
      this.provider = config.provider;
      this.providerReady = Promise.resolve();
    } else {
      // Backward compatibility: create AnthropicProvider from apiKey
      // Use a temporary provider that will be replaced once the import resolves
      this.provider = null as unknown as ModelProvider;
      this.providerReady = import('../providers/anthropic').then(({ AnthropicProvider }) => {
        this.provider = new AnthropicProvider({ apiKey: config.apiKey });
      });
    }
  }

  /**
   * Execute complete hunt workflow
   */
  async executeHunt(): Promise<HuntResult> {
    const startTime = Date.now();
    await this.providerReady;

    try {
      // Phase 1: Reconnaissance
      await this.setPhase(HuntPhase.RECONNAISSANCE);
      await this.stream(AIReasoningType.PLANNING, '🎯 Starting reconnaissance phase...');
      
      const reconSuccess = await this.executeReconPhase();
      if (!reconSuccess) {
        return this.createResult(false, startTime, 'Reconnaissance phase failed or cancelled');
      }

      // Checkpoint: Recon complete
      const continueToActive = await this.checkpoint(
        'Reconnaissance complete',
        'Begin active testing'
      );
      
      if (!continueToActive) {
        return this.createResult(true, startTime);
      }

      // Phase 2: Active Testing
      await this.setPhase(HuntPhase.ACTIVE_TESTING);
      await this.stream(AIReasoningType.PLANNING, '🔍 Starting active testing phase...');
      
      const activeSuccess = await this.executeActiveTestingPhase();
      if (!activeSuccess) {
        return this.createResult(false, startTime, 'Active testing phase failed or cancelled');
      }

      // Checkpoint: Active testing complete
      const continueToExploit = await this.checkpoint(
        'Active testing complete',
        'Begin exploitation (if vulnerabilities found)'
      );

      if (!continueToExploit) {
        return this.createResult(true, startTime);
      }

      // Phase 3: Exploitation (if vulnerabilities found)
      if (this.findings.length > 0) {
        await this.setPhase(HuntPhase.EXPLOITATION);
        await this.stream(AIReasoningType.PLANNING, '💥 Starting exploitation phase...');
        
        await this.executeExploitationPhase();
      }

      // Phase 4: Complete
      await this.setPhase(HuntPhase.COMPLETE);
      await this.stream(AIReasoningType.SUCCESS, `✅ Hunt complete! Found ${this.vulnerabilities.length} vulnerabilities`);

      return this.createResult(true, startTime);

    } catch (error) {
      await this.stream(AIReasoningType.ERROR, `❌ Hunt failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return this.createResult(false, startTime, error instanceof Error ? error.message : 'Unknown error');
    }
  }

  /**
   * Execute reconnaissance phase
   */
  private async executeReconPhase(): Promise<boolean> {
    await this.stream(AIReasoningType.ANALYSIS, '🤔 Analyzing target to determine reconnaissance strategy...');

    // Ask AI to decide which recon tools to use
    const reconTools = await this.decideReconTools();
    
    if (reconTools.length === 0) {
      await this.stream(AIReasoningType.WARNING, '⚠️ No reconnaissance tools selected');
      return true;
    }

    await this.stream(AIReasoningType.PLANNING, `📋 Planning to execute ${reconTools.length} reconnaissance tools`);

    // Execute each recon tool
    for (const toolDecision of reconTools) {
      const success = await this.executeToolWithApproval(toolDecision);
      if (!success) {
        await this.stream(AIReasoningType.WARNING, `⚠️ Tool execution cancelled or failed: ${toolDecision.toolName}`);
        return false;
      }

      // Check if we should continue
      if (this.toolsExecuted >= (this.config.maxIterations || 20)) {
        await this.stream(AIReasoningType.WARNING, '⚠️ Maximum iterations reached');
        return true;
      }
    }

    return true;
  }

  /**
   * Execute active testing phase
   */
  private async executeActiveTestingPhase(): Promise<boolean> {
    await this.stream(AIReasoningType.ANALYSIS, '🔍 Analyzing reconnaissance results to plan active tests...');

    // CRITICAL FIX: Create targets file BEFORE AI planning
    // This ensures the file exists when AI generates commands that reference it
    await this.createTargetsFile();

    // Ask AI to decide which active tools to use based on recon findings
    // AI can now safely reference the targets file in commands
    const activeTools = await this.decideActiveTools();
    
    if (activeTools.length === 0) {
      await this.stream(AIReasoningType.WARNING, '⚠️ No active testing tools selected');
      return true;
    }

    await this.stream(AIReasoningType.PLANNING, `📋 Planning to execute ${activeTools.length} active testing tools`);

    // Execute each active tool
    for (const toolDecision of activeTools) {
      const success = await this.executeToolWithApproval(toolDecision);
      if (!success) {
        await this.stream(AIReasoningType.WARNING, `⚠️ Tool execution cancelled or failed: ${toolDecision.toolName}`);
        return false;
      }

      // Check if we should continue
      if (this.toolsExecuted >= (this.config.maxIterations || 20)) {
        await this.stream(AIReasoningType.WARNING, '⚠️ Maximum iterations reached');
        return true;
      }
    }

    return true;
  }

  /**
   * Execute exploitation phase
   */
  private async executeExploitationPhase(): Promise<boolean> {
    await this.stream(AIReasoningType.ANALYSIS, '💥 Analyzing findings to determine exploitation strategy...');

    // Ask AI to analyze findings and create vulnerability reports
    const vulns = await this.analyzeFindings();
    
    this.vulnerabilities.push(...vulns);

    await this.stream(AIReasoningType.SUCCESS, `✅ Identified ${vulns.length} confirmed vulnerabilities`);

    return true;
  }

  /**
   * Ask AI to decide which recon tools to use
   */
  private async decideReconTools(): Promise<ToolDecision[]> {
    const availableTools = this.config.toolInterface.getAvailableTools();
    
    const prompt = `You are a bug bounty hunter analyzing a target for reconnaissance.

Target: ${this.config.target}
Scope: ${this.config.scope.join(', ')}
Guidelines: ${this.config.guidelines}

Available Tools:
${availableTools}

Decide which PASSIVE RECONNAISSANCE tools to run first. Consider:
1. Start with subdomain enumeration (subfinder, amass) - these output to files automatically
2. DO NOT use httpx with file input (-l flag) during reconnaissance - save that for active testing
3. You can use httpx with direct domain input if needed: httpx -u example.com
4. Gather URLs with waybackurls, gau if relevant
5. Stay within scope boundaries
6. Follow program guidelines

IMPORTANT: Do NOT use tools with file input flags (-l, --list, -i, --input) during reconnaissance.
File-based tools will be used in the active testing phase after outputs are consolidated.

Return a JSON array of tool decisions:
[
  {
    "toolName": "subfinder",
    "command": "subfinder -d example.com -silent",
    "reasoning": "Enumerate subdomains to expand attack surface",
    "target": "example.com",
    "expectedFindings": ["subdomains", "potential targets"]
  }
]

Return ONLY the JSON array, no other text.`;

    const allMessages: ChatMessage[] = [
      ...this.conversationHistory,
      { role: 'user', content: prompt },
    ];

    const response: ChatResponse = await this.provider.sendMessage(allMessages, {
      model: this.config.model!,
      maxTokens: 2048,
    });

    // Parse JSON from response
    try {
      const jsonMatch = response.content.match(/\[[\s\S]*\]/);
      if (!jsonMatch) {
        await this.stream(AIReasoningType.WARNING, '⚠️ AI did not return valid JSON for tool decisions');
        return [];
      }

      const decisions: ToolDecision[] = JSON.parse(jsonMatch[0]);

      // Add to conversation history
      this.conversationHistory.push(
        { role: 'user', content: prompt },
        { role: 'assistant', content: response.content }
      );

      return decisions;
    } catch (error) {
      await this.stream(AIReasoningType.ERROR, `❌ Failed to parse AI tool decisions: ${error}`);
      return [];
    }
  }

  /**
   * Ask AI to decide which active tools to use based on recon
   */
  private async decideActiveTools(): Promise<ToolDecision[]> {
    const availableTools = this.config.toolInterface.getAvailableTools();
    const findingsSummary = this.findings.map(f =>
      `${f.type}: ${f.description} (${f.target})`
    ).join('\n');

    // Get the targets file path if it exists
    const outputManager = getToolOutputManager();
    let targetsFilePath = '';
    if (this.reconSessionIds.length > 0) {
      try {
        const tempDir = outputManager['tempDir']; // Access private field
        targetsFilePath = `${tempDir}/targets.txt`;
      } catch (error) {
        console.warn('[AgentLoop] Could not determine targets file path:', error);
      }
    }

    const prompt = `You are a bug bounty hunter planning active testing based on reconnaissance results.

Target: ${this.config.target}
Scope: ${this.config.scope.join(', ')}
Guidelines: ${this.config.guidelines}

Reconnaissance Findings:
${findingsSummary || 'No findings yet'}

${targetsFilePath ? `\nTargets File Available: ${targetsFilePath}\nYou can use this file with tools that accept -l or --list flags (e.g., httpx -l ${targetsFilePath})` : ''}

Available Tools:
${availableTools}

Decide which ACTIVE TESTING tools to run next. Consider:
1. Use httpx with the targets file to probe discovered hosts: httpx -l ${targetsFilePath || 'targets.txt'} -status-code -tech-detect -title -silent
2. Use nuclei for vulnerability scanning on discovered hosts
3. Use ffuf/feroxbuster for directory discovery on interesting targets
4. Use katana for crawling to find more endpoints
5. Respect rate limits and program guidelines
6. Focus on high-value targets from recon

Return a JSON array of tool decisions:
[
  {
    "toolName": "httpx",
    "command": "httpx -l ${targetsFilePath || 'targets.txt'} -status-code -tech-detect -title -silent",
    "reasoning": "Probe discovered subdomains to identify live hosts and technologies",
    "target": "${this.config.target}",
    "expectedFindings": ["live_hosts", "technologies", "status_codes"]
  }
]

Return ONLY the JSON array, no other text.`;

    const activeMessages: ChatMessage[] = [
      ...this.conversationHistory,
      { role: 'user', content: prompt },
    ];

    const response: ChatResponse = await this.provider.sendMessage(activeMessages, {
      model: this.config.model!,
      maxTokens: 2048,
    });

    try {
      const jsonMatch = response.content.match(/\[[\s\S]*\]/);
      if (!jsonMatch) {
        await this.stream(AIReasoningType.WARNING, '⚠️ AI did not return valid JSON for tool decisions');
        return [];
      }

      const decisions: ToolDecision[] = JSON.parse(jsonMatch[0]);

      this.conversationHistory.push(
        { role: 'user', content: prompt },
        { role: 'assistant', content: response.content }
      );

      return decisions;
    } catch (error) {
      await this.stream(AIReasoningType.ERROR, `❌ Failed to parse AI tool decisions: ${error}`);
      return [];
    }
  }

  /**
   * Execute a tool with approval workflow
   */
  private async executeToolWithApproval(decision: ToolDecision): Promise<boolean> {
    await this.stream(AIReasoningType.PLANNING, `🔧 Planning to execute: ${decision.toolName}`);
    await this.stream(AIReasoningType.HYPOTHESIS, `💭 Reasoning: ${decision.reasoning}`);

    // IMPORTANT: Show the command and wait for approval BEFORE execution
    await this.stream(AIReasoningType.ANALYSIS, `⏳ Requesting approval for: ${decision.command}`);
    
    // Execute tool via the tool interface (which handles approval internally)
    // The executor will emit a 'tool-approval-request' event that App.tsx will catch
    const result: ExecutionResult = await this.config.toolInterface.executeTool(
      'ai_agent_loop',
      decision.command,
      decision.target,
      false // NEVER skip approval - this ensures the approval modal shows
    );

    this.toolsExecuted++;
    
    // Track reconnaissance tool session IDs for later file creation
    const reconTools = ['subfinder', 'amass', 'httpx', 'waybackurls', 'gau'];
    if (reconTools.includes(decision.toolName) && result.context?.executionId) {
      this.reconSessionIds.push(result.context.executionId);
    }

    if (result.blocked) {
      await this.stream(AIReasoningType.WARNING, `🚫 Tool blocked: ${result.blockReason}`);
      return false;
    }

    if (!result.success) {
      await this.stream(AIReasoningType.ERROR, `❌ Tool failed: ${result.stderr || 'Unknown error'}`);
      return false;
    }

    await this.stream(AIReasoningType.SUCCESS, `✅ Tool completed successfully`);

    // Parse results
    const findings = await this.parseToolOutput(decision.toolName, result.stdout || '', decision.target);
    this.findings.push(...findings);

    if (findings.length > 0) {
      await this.stream(AIReasoningType.SUCCESS, `📊 Found ${findings.length} items`);
      
      // Show sample findings
      for (const finding of findings.slice(0, 3)) {
        await this.stream(AIReasoningType.ANALYSIS, `  • ${finding.type}: ${finding.description}`);
      }
      
      if (findings.length > 3) {
        await this.stream(AIReasoningType.ANALYSIS, `  ... and ${findings.length - 3} more`);
      }
    } else {
      await this.stream(AIReasoningType.ANALYSIS, '📊 No findings from this tool');
    }

    return true;
  }

  /**
   * Parse tool output into findings
   */
  private async parseToolOutput(toolName: string, output: string, target: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Tool-specific parsing
    switch (toolName) {
      case 'subfinder':
      case 'amass':
        // Parse subdomains (one per line)
        const subdomains = output.split('\n').filter(line => line.trim() && !line.startsWith('['));
        for (const subdomain of subdomains) {
          findings.push({
            type: 'subdomain',
            severity: 'info',
            description: subdomain.trim(),
            evidence: subdomain,
            target,
            tool: toolName,
            timestamp: new Date(),
          });
        }
        break;

      case 'httpx':
        // Parse live hosts
        const hosts = output.split('\n').filter(line => line.includes('http'));
        for (const host of hosts) {
          findings.push({
            type: 'live_host',
            severity: 'info',
            description: host.trim(),
            evidence: host,
            target,
            tool: toolName,
            timestamp: new Date(),
          });
        }
        break;

      case 'waybackurls':
      case 'gau':
        // Parse URLs
        const urls = output.split('\n').filter(line => line.includes('http'));
        for (const url of urls.slice(0, 100)) { // Limit to first 100
          findings.push({
            type: 'url',
            severity: 'info',
            description: url.trim(),
            evidence: url,
            target,
            tool: toolName,
            timestamp: new Date(),
          });
        }
        break;

      case 'nuclei':
        // Parse nuclei JSON output
        try {
          const lines = output.split('\n').filter(line => line.trim().startsWith('{'));
          for (const line of lines) {
            const result = JSON.parse(line);
            findings.push({
              type: 'vulnerability',
              severity: result.info?.severity || 'info',
              description: result.info?.name || 'Unknown vulnerability',
              evidence: JSON.stringify(result, null, 2),
              target: result.host || target,
              tool: toolName,
              timestamp: new Date(),
            });
          }
        } catch (error) {
          // Fallback to text parsing
          const vulnLines = output.split('\n').filter(line => 
            line.includes('[') && (line.includes('critical') || line.includes('high') || line.includes('medium'))
          );
          for (const line of vulnLines) {
            findings.push({
              type: 'vulnerability',
              severity: 'medium',
              description: line.trim(),
              evidence: line,
              target,
              tool: toolName,
              timestamp: new Date(),
            });
          }
        }
        break;

      case 'ffuf':
      case 'feroxbuster':
        // Parse directory/file findings
        const paths = output.split('\n').filter(line => 
          line.includes('Status:') || line.includes('[')
        );
        for (const path of paths) {
          findings.push({
            type: 'path',
            severity: 'info',
            description: path.trim(),
            evidence: path,
            target,
            tool: toolName,
            timestamp: new Date(),
          });
        }
        break;

      default:
        // Generic parsing - look for interesting patterns
        const lines = output.split('\n').filter(line => line.trim());
        for (const line of lines.slice(0, 50)) { // Limit to first 50
          findings.push({
            type: 'generic',
            severity: 'info',
            description: line.trim(),
            evidence: line,
            target,
            tool: toolName,
            timestamp: new Date(),
          });
        }
    }

    return findings;
  }

  /**
   * Analyze findings and create vulnerability reports
   */
  private async analyzeFindings(): Promise<Vulnerability[]> {
    const findingsSummary = this.findings.map(f => 
      `[${f.severity}] ${f.type}: ${f.description} (${f.tool})`
    ).join('\n');

    const prompt = `You are a bug bounty hunter analyzing security findings to identify real vulnerabilities.

Target: ${this.config.target}
Guidelines: ${this.config.guidelines}

Findings:
${findingsSummary}

Analyze these findings and identify CONFIRMED VULNERABILITIES. For each vulnerability:
1. Determine if it's a real security issue (not just informational)
2. Assess severity (low/medium/high/critical)
3. Describe the impact
4. Provide reproduction steps

Return a JSON array of vulnerabilities:
[
  {
    "type": "SQL Injection",
    "severity": "high",
    "title": "SQL Injection in login endpoint",
    "description": "The login endpoint is vulnerable to SQL injection...",
    "impact": "Attacker can bypass authentication and access sensitive data",
    "reproduction": ["Step 1", "Step 2"],
    "evidence": ["Finding 1", "Finding 2"],
    "target": "https://example.com/login"
  }
]

Return ONLY the JSON array, no other text. If no real vulnerabilities found, return empty array [].`;

    const analysisMessages: ChatMessage[] = [
      ...this.conversationHistory,
      { role: 'user', content: prompt },
    ];

    const response: ChatResponse = await this.provider.sendMessage(analysisMessages, {
      model: this.config.model!,
      maxTokens: 4096,
    });

    try {
      const jsonMatch = response.content.match(/\[[\s\S]*\]/);
      if (!jsonMatch) {
        return [];
      }

      const vulns: Array<Omit<Vulnerability, 'id' | 'discoveredBy' | 'timestamp'>> = JSON.parse(jsonMatch[0]);
      
      return vulns.map(v => ({
        ...v,
        id: `vuln_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        discoveredBy: 'ai_agent_loop',
        timestamp: new Date(),
      }));
    } catch (error) {
      await this.stream(AIReasoningType.ERROR, `❌ Failed to parse vulnerability analysis: ${error}`);
      return [];
    }
  }

  /**
   * Create consolidated targets file from reconnaissance results
   */
  private async createTargetsFile(): Promise<void> {
    if (this.reconSessionIds.length === 0) {
      await this.stream(AIReasoningType.WARNING, '⚠️ No reconnaissance results to consolidate');
      return;
    }

    try {
      const outputManager = getToolOutputManager();
      
      // Combine all recon outputs into targets.txt
      const targetsFile = await outputManager.combineOutputs(
        this.reconSessionIds,
        'targets.txt'
      );
      
      await this.stream(
        AIReasoningType.SUCCESS,
        `📝 Created targets file: ${targetsFile} (${this.reconSessionIds.length} sources combined)`
      );
    } catch (error) {
      await this.stream(
        AIReasoningType.WARNING,
        `⚠️ Failed to create targets file: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Stream a message to the UI
   */
  private async stream(type: AIReasoningType, message: string): Promise<void> {
    console.log('[AGENT_LOOP] Streaming message:', { type, phase: this.currentPhase, message });
    
    if (!this.config.streamingCallback) {
      console.error('[AGENT_LOOP] ERROR: streamingCallback is undefined!');
      return;
    }
    
    try {
      this.config.streamingCallback({
        type,
        phase: this.currentPhase,
        message,
        timestamp: Date.now(),
      });
      console.log('[AGENT_LOOP] Message sent to callback successfully');
    } catch (error) {
      console.error('[AGENT_LOOP] Error calling streamingCallback:', error);
    }
  }

  /**
   * Request checkpoint approval
   */
  private async checkpoint(reason: string, nextAction: string): Promise<boolean> {
    return await this.config.checkpointCallback({
      id: `checkpoint_${Date.now()}`,
      phase: this.currentPhase,
      reason,
      context: {
        toolsExecuted: this.toolsExecuted,
        findingsCount: this.findings.length,
        currentTarget: this.config.target,
        nextAction,
      },
      timestamp: Date.now(),
    });
  }

  /**
   * Set current phase
   */
  private async setPhase(phase: HuntPhase): Promise<void> {
    this.currentPhase = phase;
    await this.stream(AIReasoningType.ANALYSIS, `📍 Phase: ${phase.toUpperCase()}`);
  }

  /**
   * Create hunt result
   */
  private createResult(success: boolean, startTime: number, error?: string): HuntResult {
    return {
      success,
      phase: this.currentPhase,
      toolsExecuted: this.toolsExecuted,
      findingsCount: this.findings.length,
      vulnerabilities: this.vulnerabilities,
      duration: Date.now() - startTime,
      error,
    };
  }

  /**
   * Get current findings
   */
  getFindings(): Finding[] {
    return this.findings;
  }

  /**
   * Get vulnerabilities
   */
  getVulnerabilities(): Vulnerability[] {
    return this.vulnerabilities;
  }
}

export default AIAgentLoop;
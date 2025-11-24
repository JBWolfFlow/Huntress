/**
 * OAuth Hunter CrewAI Agent Wrapper
 * 
 * Wraps the OAuthHunter class as a CrewAI-compatible agent with:
 * - Human-in-the-loop approval for risky operations
 * - Integration with HumanTask system
 * - Strategic planning and coordination
 * - Error recovery and retries
 */

import { OAuthHunter, OAuthHunterConfig, OAuthVulnerability, OAuthHuntResult } from '../../agents/oauth';
import { HumanTaskManager } from './human_task';

export interface OAuthAgentConfig extends OAuthHunterConfig {
  humanInTheLoop?: boolean;
  autoApprove?: boolean;
  maxRetries?: number;
  retryDelay?: number;
}

export interface OAuthAgentTask {
  id: string;
  type: 'discovery' | 'redirect_test' | 'state_test' | 'pkce_test' | 'scope_test' | 'full_hunt';
  target: string;
  status: 'pending' | 'running' | 'awaiting_approval' | 'completed' | 'failed';
  result?: any;
  error?: string;
  requiresApproval?: boolean;
  approvalContext?: any;
}

export interface RiskyOperation {
  type: string;
  description: string;
  endpoint: string;
  payload?: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  reason: string;
}

export class OAuthAgent {
  private hunter: OAuthHunter;
  private config: OAuthAgentConfig;
  private humanTaskManager: HumanTaskManager;
  private currentTask?: OAuthAgentTask;
  private retryCount: number = 0;

  constructor(config: OAuthAgentConfig, humanTaskManager: HumanTaskManager) {
    this.config = {
      humanInTheLoop: true,
      autoApprove: false,
      maxRetries: 3,
      retryDelay: 1000,
      ...config,
    };
    
    this.hunter = new OAuthHunter(config);
    this.humanTaskManager = humanTaskManager;
  }

  /**
   * Execute a full OAuth hunt with human approval
   */
  async executeHunt(): Promise<OAuthHuntResult> {
    this.currentTask = {
      id: this.generateTaskId(),
      type: 'full_hunt',
      target: this.config.target,
      status: 'pending',
    };

    try {
      // Request approval to start hunt
      if (this.config.humanInTheLoop && !this.config.autoApprove) {
        const approved = await this.requestHuntApproval();
        if (!approved) {
          throw new Error('Hunt not approved by human operator');
        }
      }

      this.currentTask.status = 'running';
      console.log(`[OAuth Agent] Starting hunt on ${this.config.target}`);

      // Execute hunt with monitoring
      const result = await this.executeWithRetry(() => this.hunter.hunt());

      // Review findings and request approval for high-severity vulnerabilities
      if (this.config.humanInTheLoop) {
        await this.reviewFindings(result.vulnerabilities);
      }

      this.currentTask.status = 'completed';
      this.currentTask.result = result;

      return result;
    } catch (error) {
      this.currentTask.status = 'failed';
      this.currentTask.error = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  /**
   * Request approval to start hunt
   */
  private async requestHuntApproval(): Promise<boolean> {
    const approved = await this.humanTaskManager.requestApproval(
      'OAuth Hunt Approval Required',
      `Requesting approval to perform OAuth vulnerability testing on ${this.config.target}`,
      {
        target: this.config.target,
        clientId: this.config.clientId,
        redirectUri: this.config.redirectUri,
        tests: [
          'OAuth endpoint discovery',
          'Redirect URI validation',
          'State parameter testing',
          'PKCE implementation testing',
          'Scope parameter testing',
        ],
      },
      'high'
    );

    return approved;
  }

  /**
   * Review findings and request approval for risky operations
   */
  private async reviewFindings(vulnerabilities: OAuthVulnerability[]): Promise<void> {
    // Filter high and critical severity vulnerabilities
    const highRiskVulns = vulnerabilities.filter(
      v => v.severity === 'high' || v.severity === 'critical'
    );

    if (highRiskVulns.length === 0) {
      return;
    }

    // Request human review for high-risk findings
    const approved = await this.humanTaskManager.requestApproval(
      'High-Risk Vulnerabilities Found',
      `Found ${highRiskVulns.length} high-risk OAuth vulnerabilities. Review required before proceeding.`,
      {
        vulnerabilities: highRiskVulns.map(v => ({
          type: v.type,
          severity: v.severity,
          endpoint: v.endpoint,
          description: v.description,
        })),
        summary: {
          critical: highRiskVulns.filter(v => v.severity === 'critical').length,
          high: highRiskVulns.filter(v => v.severity === 'high').length,
        },
      },
      'critical'
    );

    if (!approved) {
      console.log('[OAuth Agent] High-risk findings rejected by human operator');
    }
  }

  /**
   * Determine if an operation is risky and requires approval
   */
  private async checkRiskyOperation(operation: RiskyOperation): Promise<boolean> {
    if (!this.config.humanInTheLoop) {
      return true; // Auto-approve if human-in-the-loop is disabled
    }

    if (this.config.autoApprove && operation.risk !== 'critical') {
      return true; // Auto-approve non-critical operations if enabled
    }

    // Request human approval
    const approved = await this.humanTaskManager.requestApproval(
      `Risky Operation: ${operation.type}`,
      operation.description,
      {
        endpoint: operation.endpoint,
        payload: operation.payload,
        risk: operation.risk,
        reason: operation.reason,
      },
      operation.risk
    );

    return approved;
  }

  /**
   * Execute operation with retry logic
   */
  private async executeWithRetry<T>(operation: () => Promise<T>): Promise<T> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.config.maxRetries!; attempt++) {
      try {
        this.retryCount = attempt;
        return await operation();
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        
        if (attempt < this.config.maxRetries!) {
          console.log(`[OAuth Agent] Attempt ${attempt + 1} failed, retrying...`);
          await this.delay(this.config.retryDelay! * (attempt + 1));
        }
      }
    }

    throw lastError || new Error('Operation failed after retries');
  }

  /**
   * Test specific OAuth vulnerability type
   */
  async testVulnerabilityType(
    type: 'redirect' | 'state' | 'pkce' | 'scope'
  ): Promise<OAuthVulnerability[]> {
    const operation: RiskyOperation = {
      type: `oauth_${type}_test`,
      description: `Test ${type} parameter vulnerabilities on ${this.config.target}`,
      endpoint: this.config.target,
      risk: 'medium',
      reason: `Testing ${type} implementation for security issues`,
    };

    const approved = await this.checkRiskyOperation(operation);
    if (!approved) {
      throw new Error(`${type} test not approved`);
    }

    // Execute full hunt and filter results
    const result = await this.hunter.hunt();
    return result.vulnerabilities.filter(v => v.type.includes(type));
  }

  /**
   * Get current task status
   */
  getTaskStatus(): OAuthAgentTask | undefined {
    return this.currentTask;
  }

  /**
   * Generate report for vulnerability
   */
  generateReport(vulnerability: OAuthVulnerability): string {
    return this.hunter.generateReport(vulnerability);
  }

  /**
   * Get agent capabilities
   */
  getCapabilities(): string[] {
    return [
      'OAuth endpoint discovery',
      'Redirect URI validation',
      'State parameter testing',
      'PKCE implementation testing',
      'Scope parameter testing',
      'Vulnerability reporting',
      'Human-in-the-loop approval',
      'Error recovery and retries',
    ];
  }

  /**
   * Get agent description
   */
  getDescription(): string {
    return `OAuth Hunter Agent - Specialized in discovering and testing OAuth 2.0 vulnerabilities with human oversight`;
  }

  /**
   * Delay helper
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Generate unique task ID
   */
  private generateTaskId(): string {
    return `oauth_task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

export default OAuthAgent;
/**
 * Standardized Agent Wrappers
 *
 * Wraps all existing specialized hunters behind the BaseAgent interface.
 * Each wrapper preserves the internal logic of the original hunter while
 * providing the standard lifecycle methods.
 */

import type { ModelProvider } from '../core/providers/types';
import type {
  BaseAgent,
  AgentTask,
  AgentResult,
  AgentFinding,
  AgentStatus,
  AgentMetadata,
  FindingSeverity,
} from './base_agent';
import { generateFindingId } from './base_agent';
import { registerAgent } from './agent_catalog';
import { OAuthHunter as OAuthHunterImpl } from './oauth';
// These agents implement BaseAgent directly and self-register in their own files.
// Re-exported here for backward compatibility.
import { GraphQLHunterAgent } from './graphql_hunter';
import { IDORHunterAgent } from './idor_hunter';
import { SSTIHunterAgent } from './ssti_hunter';
import { OpenRedirectHunter as OpenRedirectImpl } from './open_redirect';
import { HostHeaderHunter as HostHeaderImpl } from './host_header';
import { PrototypePollutionHunter as PPImpl } from './prototype_pollution';

// ----- Helper -----

function createAgentStatus(meta: AgentMetadata): AgentStatus {
  return {
    agentId: meta.id,
    agentName: meta.name,
    status: 'idle',
    toolsExecuted: 0,
    findingsCount: 0,
    lastUpdate: Date.now(),
  };
}

// ----- OAuth Hunter Agent -----

class OAuthHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'oauth_hunter',
    name: 'OAuth Hunter',
    description: 'Tests OAuth 2.0 flows for redirect_uri manipulation, state issues, PKCE bypass, and scope escalation.',
    vulnerabilityClasses: ['oauth', 'authentication', 'authorization', 'redirect'],
    assetTypes: ['web-application', 'api', 'domain'],
  };

  private provider?: ModelProvider;
  private model?: string;
  private findings: AgentFinding[] = [];
  private status: AgentStatus;

  constructor() {
    this.status = createAgentStatus(this.metadata);
  }

  async initialize(provider: ModelProvider, model: string): Promise<void> {
    this.provider = provider;
    this.model = model;
  }

  async execute(task: AgentTask): Promise<AgentResult> {
    const startTime = Date.now();
    this.findings = [];
    this.status.status = 'running';
    this.status.currentTask = task.description;

    try {
      const hunter = new OAuthHunterImpl({
        target: task.target,
        clientId: task.parameters.clientId as string | undefined,
        redirectUri: task.parameters.redirectUri as string | undefined,
      });

      const result = await hunter.hunt();

      this.findings = result.vulnerabilities.map(v => ({
        id: generateFindingId(),
        agentId: this.metadata.id,
        type: v.type,
        title: v.type.replace(/_/g, ' '),
        severity: v.severity as FindingSeverity,
        description: v.description,
        target: task.target,
        evidence: [v.evidence],
        reproduction: [v.payload ?? ''],
        timestamp: v.discoveredAt,
      }));

      this.status.status = 'completed';
      this.status.findingsCount = this.findings.length;
      this.status.toolsExecuted++;

      return {
        taskId: task.id,
        agentId: this.metadata.id,
        success: true,
        findings: this.findings,
        toolsExecuted: this.status.toolsExecuted,
        duration: Date.now() - startTime,
      };
    } catch (error) {
      this.status.status = 'failed';
      return {
        taskId: task.id,
        agentId: this.metadata.id,
        success: false,
        findings: this.findings,
        toolsExecuted: this.status.toolsExecuted,
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  validate(target: string): boolean {
    try { new URL(target.startsWith('http') ? target : `https://${target}`); return true; } catch { return false; }
  }

  reportFindings(): AgentFinding[] { return this.findings; }
  async cleanup(): Promise<void> { this.findings = []; this.status.status = 'idle'; }
  getStatus(): AgentStatus { return { ...this.status, lastUpdate: Date.now() }; }
}

// GraphQLHunterAgent, IDORHunterAgent, and SSTIHunterAgent implement BaseAgent
// directly in their own files and self-register with the catalog.
// They are imported above and re-exported below for backward compatibility.

// ----- Open Redirect Agent -----

class OpenRedirectAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'open_redirect',
    name: 'Open Redirect Hunter',
    description: 'Tests for open redirect vulnerabilities via URL parameters and headers.',
    vulnerabilityClasses: ['open-redirect', 'redirect', 'phishing'],
    assetTypes: ['web-application', 'domain'],
  };

  private provider?: ModelProvider;
  private model?: string;
  private findings: AgentFinding[] = [];
  private status: AgentStatus;

  constructor() { this.status = createAgentStatus(this.metadata); }

  async initialize(provider: ModelProvider, model: string): Promise<void> {
    this.provider = provider;
    this.model = model;
  }

  async execute(task: AgentTask): Promise<AgentResult> {
    const startTime = Date.now();
    this.findings = [];
    this.status.status = 'running';

    try {
      const hunter = new OpenRedirectImpl(task.target);
      const url = task.target.startsWith('http') ? task.target : `https://${task.target}`;
      const results = await hunter.testUrl(url);

      this.findings = results.filter(r => r.vulnerable).map(r => ({
        id: generateFindingId(),
        agentId: this.metadata.id,
        type: 'open_redirect',
        title: `Open redirect via ${r.payload.parameter}`,
        severity: r.severity as FindingSeverity,
        description: r.evidence,
        target: r.url,
        evidence: [r.evidence],
        reproduction: [`Navigate to: ${r.url}`],
        timestamp: new Date(),
      }));

      this.status.status = 'completed';
      this.status.findingsCount = this.findings.length;
      this.status.toolsExecuted++;

      return { taskId: task.id, agentId: this.metadata.id, success: true, findings: this.findings, toolsExecuted: this.status.toolsExecuted, duration: Date.now() - startTime };
    } catch (error) {
      this.status.status = 'failed';
      return { taskId: task.id, agentId: this.metadata.id, success: false, findings: [], toolsExecuted: 0, duration: Date.now() - startTime, error: error instanceof Error ? error.message : String(error) };
    }
  }

  validate(target: string): boolean { return true; }
  reportFindings(): AgentFinding[] { return this.findings; }
  async cleanup(): Promise<void> { this.findings = []; this.status.status = 'idle'; }
  getStatus(): AgentStatus { return { ...this.status, lastUpdate: Date.now() }; }
}

// ----- Host Header Agent -----

class HostHeaderAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'host_header',
    name: 'Host Header Hunter',
    description: 'Tests for Host header injection, password reset poisoning, and cache poisoning.',
    vulnerabilityClasses: ['host-header', 'cache-poisoning', 'password-reset-poisoning'],
    assetTypes: ['web-application', 'domain'],
  };

  private provider?: ModelProvider;
  private model?: string;
  private findings: AgentFinding[] = [];
  private status: AgentStatus;

  constructor() { this.status = createAgentStatus(this.metadata); }

  async initialize(provider: ModelProvider, model: string): Promise<void> {
    this.provider = provider;
    this.model = model;
  }

  async execute(task: AgentTask): Promise<AgentResult> {
    const startTime = Date.now();
    this.findings = [];
    this.status.status = 'running';

    try {
      const hunter = new HostHeaderImpl(task.target);
      const url = task.target.startsWith('http') ? task.target : `https://${task.target}`;
      const results = await hunter.testEndpoint({ url, method: 'GET' });

      this.findings = results.map(v => ({
        id: generateFindingId(),
        agentId: this.metadata.id,
        type: v.type,
        title: `Host header ${v.type.replace(/_/g, ' ')}`,
        severity: v.severity as FindingSeverity,
        description: v.description,
        target: task.target,
        evidence: [v.evidence],
        reproduction: [`Inject Host: ${v.injectedHost}`],
        timestamp: new Date(),
      }));

      this.status.status = 'completed';
      this.status.findingsCount = this.findings.length;
      this.status.toolsExecuted++;

      return { taskId: task.id, agentId: this.metadata.id, success: true, findings: this.findings, toolsExecuted: this.status.toolsExecuted, duration: Date.now() - startTime };
    } catch (error) {
      this.status.status = 'failed';
      return { taskId: task.id, agentId: this.metadata.id, success: false, findings: [], toolsExecuted: 0, duration: Date.now() - startTime, error: error instanceof Error ? error.message : String(error) };
    }
  }

  validate(target: string): boolean { return true; }
  reportFindings(): AgentFinding[] { return this.findings; }
  async cleanup(): Promise<void> { this.findings = []; this.status.status = 'idle'; }
  getStatus(): AgentStatus { return { ...this.status, lastUpdate: Date.now() }; }
}

// ----- Prototype Pollution Agent -----

class PrototypePollutionAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'prototype_pollution',
    name: 'Prototype Pollution Hunter',
    description: 'Tests for JavaScript prototype pollution via unsafe object merging.',
    vulnerabilityClasses: ['prototype-pollution', 'injection', 'javascript'],
    assetTypes: ['web-application', 'api'],
  };

  private provider?: ModelProvider;
  private model?: string;
  private findings: AgentFinding[] = [];
  private status: AgentStatus;

  constructor() { this.status = createAgentStatus(this.metadata); }

  async initialize(provider: ModelProvider, model: string): Promise<void> {
    this.provider = provider;
    this.model = model;
  }

  async execute(task: AgentTask): Promise<AgentResult> {
    const startTime = Date.now();
    this.findings = [];
    this.status.status = 'running';

    try {
      const hunter = new PPImpl(task.target);
      const endpoint = task.parameters.endpoint as string ?? '/';
      const results = await hunter.testEndpoint(endpoint);

      this.findings = results.map(v => ({
        id: generateFindingId(),
        agentId: this.metadata.id,
        type: 'prototype_pollution',
        title: `Prototype pollution at ${v.endpoint}`,
        severity: v.severity as FindingSeverity,
        description: v.description,
        target: task.target,
        evidence: [v.evidence],
        reproduction: [`Send payload to ${v.endpoint}`],
        timestamp: new Date(),
      }));

      this.status.status = 'completed';
      this.status.findingsCount = this.findings.length;
      this.status.toolsExecuted++;

      return { taskId: task.id, agentId: this.metadata.id, success: true, findings: this.findings, toolsExecuted: this.status.toolsExecuted, duration: Date.now() - startTime };
    } catch (error) {
      this.status.status = 'failed';
      return { taskId: task.id, agentId: this.metadata.id, success: false, findings: [], toolsExecuted: 0, duration: Date.now() - startTime, error: error instanceof Error ? error.message : String(error) };
    }
  }

  validate(target: string): boolean { return true; }
  reportFindings(): AgentFinding[] { return this.findings; }
  async cleanup(): Promise<void> { this.findings = []; this.status.status = 'idle'; }
  getStatus(): AgentStatus { return { ...this.status, lastUpdate: Date.now() }; }
}

// ----- Register all agents in the catalog -----

registerAgent({ metadata: new OAuthHunterAgent().metadata, factory: () => new OAuthHunterAgent() });
// GraphQLHunterAgent, IDORHunterAgent, SSTIHunterAgent self-register in their own files
registerAgent({ metadata: new OpenRedirectAgent().metadata, factory: () => new OpenRedirectAgent() });
registerAgent({ metadata: new HostHeaderAgent().metadata, factory: () => new HostHeaderAgent() });
registerAgent({ metadata: new PrototypePollutionAgent().metadata, factory: () => new PrototypePollutionAgent() });

export {
  OAuthHunterAgent,
  GraphQLHunterAgent,
  IDORHunterAgent,
  SSTIHunterAgent,
  OpenRedirectAgent,
  HostHeaderAgent,
  PrototypePollutionAgent,
};

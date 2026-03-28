/**
 * Standardized Agent Wrappers
 *
 * Imports all agent modules to ensure they register with the catalog.
 * Agents that implement BaseAgent directly and self-register are imported
 * here to trigger their registration side effects.
 *
 * Re-exports agent classes for backward compatibility.
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
// Importing them triggers catalog registration.
import { GraphQLHunterAgent } from './graphql_hunter';
import { IDORHunterAgent } from './idor_hunter';
import { SSTIHunterAgent } from './ssti_hunter';
import { OpenRedirectHunterAgent } from './open_redirect';
import { HostHeaderHunterAgent } from './host_header';
import { PrototypePollutionHunterAgent } from './prototype_pollution';

// Core agents — self-registering imports
import { ReconAgent } from './recon_agent';
import { XssHunterAgent } from './xss_hunter';
import { SSRFHunterAgent } from './ssrf_hunter';
import { SqliHunterAgent } from './sqli_hunter';
import { CORSHunterAgent } from './cors_hunter';
import { XxeHunterAgent } from './xxe_hunter';
import { PathTraversalHunterAgent } from './path_traversal_hunter';
import { SubdomainTakeoverHunterAgent } from './subdomain_takeover_hunter';
import { CommandInjectionHunterAgent } from './command_injection_hunter';

// Phase 21 agents — self-registering imports
import { RaceConditionHunterAgent } from './race_condition_hunter';
import { HttpSmugglingHunterAgent } from './http_smuggling_hunter';
import { CacheHunterAgent } from './cache_hunter';
import { JWTHunterAgent } from './jwt_hunter';
import { BusinessLogicHunterAgent } from './business_logic_hunter';

// Phase 22 agents — self-registering imports
import { NoSQLHunterAgent } from './nosql_hunter';
import { DeserializationHunterAgent } from './deserialization_hunter';
import { SAMLHunterAgent } from './saml_hunter';
import { MFABypassHunterAgent } from './mfa_bypass_hunter';
import { WebSocketHunterAgent } from './websocket_hunter';
import { CRLFHunterAgent } from './crlf_hunter';
import { PromptInjectionHunterAgent } from './prompt_injection_hunter';

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
// OAuth still uses a wrapper because the underlying OAuthHunter has custom hunt() logic
// that doesn't follow the ReactLoop pattern.

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

// ----- Register OAuth agent (others self-register) -----

registerAgent({ metadata: new OAuthHunterAgent().metadata, factory: () => new OAuthHunterAgent() });

// ----- Legacy aliases for backward compatibility -----

/** @deprecated Use OpenRedirectHunterAgent directly */
const OpenRedirectAgent = OpenRedirectHunterAgent;
/** @deprecated Use HostHeaderHunterAgent directly */
const HostHeaderAgent = HostHeaderHunterAgent;
/** @deprecated Use PrototypePollutionHunterAgent directly */
const PrototypePollutionAgent = PrototypePollutionHunterAgent;

export {
  OAuthHunterAgent,
  GraphQLHunterAgent,
  IDORHunterAgent,
  SSTIHunterAgent,
  OpenRedirectAgent,
  HostHeaderAgent,
  PrototypePollutionAgent,
  OpenRedirectHunterAgent,
  HostHeaderHunterAgent,
  PrototypePollutionHunterAgent,
  ReconAgent,
  XssHunterAgent,
  SSRFHunterAgent,
  SqliHunterAgent,
  CORSHunterAgent,
  XxeHunterAgent,
  PathTraversalHunterAgent,
  SubdomainTakeoverHunterAgent,
  CommandInjectionHunterAgent,
  RaceConditionHunterAgent,
  HttpSmugglingHunterAgent,
  CacheHunterAgent,
  JWTHunterAgent,
  BusinessLogicHunterAgent,
  NoSQLHunterAgent,
  DeserializationHunterAgent,
  SAMLHunterAgent,
  MFABypassHunterAgent,
  WebSocketHunterAgent,
  CRLFHunterAgent,
  PromptInjectionHunterAgent,
};

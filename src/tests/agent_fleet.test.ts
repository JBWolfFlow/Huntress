/**
 * Agent Fleet Tests
 *
 * Tests for all 24 ReactLoop-based hunter/recon agents:
 * SSRFHunter, XssHunter, SqliHunter, CORSHunter, GraphQLHunter,
 * IDORHunter, SSTIHunter, XxeHunter, CommandInjectionHunter,
 * PathTraversalHunter, SubdomainTakeoverHunter, ReconAgent,
 * RaceConditionHunter.
 *
 * Verifies BaseAgent interface compliance, metadata, lifecycle,
 * status tracking, finding conversion, and catalog registration.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { SSRFHunterAgent } from '../agents/ssrf_hunter';
import { XssHunterAgent } from '../agents/xss_hunter';
import { SqliHunterAgent } from '../agents/sqli_hunter';
import { CORSHunterAgent } from '../agents/cors_hunter';
import { GraphQLHunterAgent } from '../agents/graphql_hunter';
import { IDORHunterAgent } from '../agents/idor_hunter';
import { SSTIHunterAgent } from '../agents/ssti_hunter';
import { XxeHunterAgent } from '../agents/xxe_hunter';
import { CommandInjectionHunterAgent } from '../agents/command_injection_hunter';
import { PathTraversalHunterAgent } from '../agents/path_traversal_hunter';
import { SubdomainTakeoverHunterAgent } from '../agents/subdomain_takeover_hunter';
import { ReconAgent } from '../agents/recon_agent';
import { RaceConditionHunterAgent } from '../agents/race_condition_hunter';
import { HttpSmugglingHunterAgent } from '../agents/http_smuggling_hunter';
import { CacheHunterAgent } from '../agents/cache_hunter';
import { JWTHunterAgent } from '../agents/jwt_hunter';
import { BusinessLogicHunterAgent } from '../agents/business_logic_hunter';
import { NoSQLHunterAgent } from '../agents/nosql_hunter';
import { DeserializationHunterAgent } from '../agents/deserialization_hunter';
import { SAMLHunterAgent } from '../agents/saml_hunter';
import { MFABypassHunterAgent } from '../agents/mfa_bypass_hunter';
import { WebSocketHunterAgent } from '../agents/websocket_hunter';
import { CRLFHunterAgent } from '../agents/crlf_hunter';
import { PromptInjectionHunterAgent } from '../agents/prompt_injection_hunter';
import { getAllAgents, initializeCatalog } from '../agents/agent_catalog';
import type { AgentTask } from '../agents/base_agent';
import type {
  ModelProvider,
  ChatMessage,
  SendMessageOptions,
  StreamChunk,
  ModelInfo,
} from '../core/providers/types';

// ─── Mock Provider ──────────────────────────────────────────────────────────

function createMockProvider(): ModelProvider {
  let callCount = 0;

  return {
    providerId: 'mock',
    displayName: 'Mock Provider',

    async sendMessage(_messages: ChatMessage[], options: SendMessageOptions) {
      callCount++;
      return {
        content: 'No vulnerabilities found.',
        model: options.model,
        inputTokens: 100,
        outputTokens: 50,
        stopReason: 'tool_use' as const,
        toolCalls: [{
          type: 'tool_use' as const,
          id: `tool_stop_${callCount}`,
          name: 'stop_hunting',
          input: { reason: 'no_vulnerabilities', summary: 'Mock test — no real targets available' },
        }],
        contentBlocks: [
          { type: 'text' as const, text: 'No vulnerabilities found.' },
          {
            type: 'tool_use' as const,
            id: `tool_stop_${callCount}`,
            name: 'stop_hunting',
            input: { reason: 'no_vulnerabilities', summary: 'Mock test — no real targets available' },
          },
        ],
      };
    },

    async *streamMessage(_messages: ChatMessage[], _options: SendMessageOptions): AsyncGenerator<StreamChunk> {
      yield { type: 'content_delta', content: 'Stream test' };
      yield { type: 'message_stop', inputTokens: 50, outputTokens: 25 };
    },

    getAvailableModels(): ModelInfo[] {
      return [{
        id: 'mock-model',
        displayName: 'Mock Model',
        contextWindow: 128000,
        maxOutputTokens: 4096,
        supportsStreaming: true,
        supportsSystemPrompt: true,
        inputCostPer1M: 0,
        outputCostPer1M: 0,
      }];
    },

    async validateApiKey(): Promise<boolean> {
      return true;
    },

    estimateCost(): number {
      return 0;
    },

    supportsToolUse: true,
  };
}

function createTask(overrides: Partial<AgentTask> = {}): AgentTask {
  return {
    id: `task_${Date.now()}`,
    target: 'https://example.com',
    scope: ['*.example.com'],
    description: 'Test task for agent verification',
    parameters: {},
    ...overrides,
  };
}

// ─── Agent Test Matrix ──────────────────────────────────────────────────────

interface AgentSpec {
  name: string;
  factory: () => InstanceType<
    typeof SSRFHunterAgent | typeof XssHunterAgent | typeof SqliHunterAgent |
    typeof CORSHunterAgent | typeof GraphQLHunterAgent | typeof IDORHunterAgent |
    typeof SSTIHunterAgent | typeof XxeHunterAgent | typeof CommandInjectionHunterAgent |
    typeof PathTraversalHunterAgent | typeof SubdomainTakeoverHunterAgent | typeof ReconAgent |
    typeof RaceConditionHunterAgent | typeof HttpSmugglingHunterAgent | typeof CacheHunterAgent |
    typeof JWTHunterAgent | typeof BusinessLogicHunterAgent | typeof NoSQLHunterAgent |
    typeof DeserializationHunterAgent | typeof SAMLHunterAgent | typeof MFABypassHunterAgent |
    typeof WebSocketHunterAgent | typeof CRLFHunterAgent | typeof PromptInjectionHunterAgent
  >;
  expectedId: string;
  expectedName: string;
  expectedVulnClasses: string[];
  expectedAssetTypes: string[];
}

const agentSpecs: AgentSpec[] = [
  {
    name: 'SSRFHunterAgent',
    factory: () => new SSRFHunterAgent(),
    expectedId: 'ssrf-hunter',
    expectedName: 'SSRF Hunter',
    expectedVulnClasses: ['ssrf', 'ssrf_blind', 'open-redirect'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'XssHunterAgent',
    factory: () => new XssHunterAgent(),
    expectedId: 'xss-hunter',
    expectedName: 'XSS Hunter',
    expectedVulnClasses: ['xss', 'xss_reflected', 'xss_stored', 'xss_dom'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'SqliHunterAgent',
    factory: () => new SqliHunterAgent(),
    expectedId: 'sqli-hunter',
    expectedName: 'SQLi Hunter',
    expectedVulnClasses: ['sqli', 'sqli_error', 'sqli_blind_time', 'sqli_blind_boolean'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'CORSHunterAgent',
    factory: () => new CORSHunterAgent(),
    expectedId: 'cors-hunter',
    expectedName: 'CORS Hunter',
    expectedVulnClasses: ['cors', 'misconfiguration'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'GraphQLHunterAgent',
    factory: () => new GraphQLHunterAgent(),
    expectedId: 'graphql-hunter',
    expectedName: 'GraphQL Hunter',
    expectedVulnClasses: ['graphql', 'information-disclosure', 'authorization-bypass'],
    expectedAssetTypes: ['api', 'web-application'],
  },
  {
    name: 'IDORHunterAgent',
    factory: () => new IDORHunterAgent(),
    expectedId: 'idor-hunter',
    expectedName: 'IDOR Hunter',
    expectedVulnClasses: ['idor', 'bola', 'bfla', 'access-control'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'SSTIHunterAgent',
    factory: () => new SSTIHunterAgent(),
    expectedId: 'ssti-hunter',
    expectedName: 'SSTI Hunter',
    expectedVulnClasses: ['ssti', 'rce', 'injection'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'XxeHunterAgent',
    factory: () => new XxeHunterAgent(),
    expectedId: 'xxe-hunter',
    expectedName: 'XXE Hunter',
    expectedVulnClasses: ['xxe', 'xxe_blind', 'xxe_oob'],
    expectedAssetTypes: ['web-application', 'api', 'file-upload'],
  },
  {
    name: 'CommandInjectionHunterAgent',
    factory: () => new CommandInjectionHunterAgent(),
    expectedId: 'command-injection-hunter',
    expectedName: 'Command Injection Hunter',
    expectedVulnClasses: ['command_injection', 'command_injection_blind', 'argument_injection'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'PathTraversalHunterAgent',
    factory: () => new PathTraversalHunterAgent(),
    expectedId: 'path-traversal-hunter',
    expectedName: 'Path Traversal Hunter',
    expectedVulnClasses: ['path_traversal', 'lfi', 'lfi_rce'],
    expectedAssetTypes: ['web-application', 'api', 'file-upload'],
  },
  {
    name: 'SubdomainTakeoverHunterAgent',
    factory: () => new SubdomainTakeoverHunterAgent(),
    expectedId: 'subdomain-takeover-hunter',
    expectedName: 'Subdomain Takeover Hunter',
    expectedVulnClasses: ['subdomain-takeover', 'dns-misconfiguration'],
    expectedAssetTypes: ['domain', 'web-application'],
  },
  {
    name: 'ReconAgent',
    factory: () => new ReconAgent(),
    expectedId: 'recon',
    expectedName: 'Recon Agent',
    expectedVulnClasses: ['recon', 'information-disclosure', 'subdomain-takeover'],
    expectedAssetTypes: ['domain', 'web-application', 'api'],
  },
  {
    name: 'RaceConditionHunterAgent',
    factory: () => new RaceConditionHunterAgent(),
    expectedId: 'race-condition-hunter',
    expectedName: 'Race Condition Hunter',
    expectedVulnClasses: ['race_condition', 'toctou', 'double_spend'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'HttpSmugglingHunterAgent',
    factory: () => new HttpSmugglingHunterAgent(),
    expectedId: 'http-smuggling-hunter',
    expectedName: 'HTTP Smuggling Hunter',
    expectedVulnClasses: ['http_smuggling', 'request_smuggling', 'desync'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'CacheHunterAgent',
    factory: () => new CacheHunterAgent(),
    expectedId: 'cache-hunter',
    expectedName: 'Cache Hunter',
    expectedVulnClasses: ['cache_poisoning', 'cache_deception', 'web_cache'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'JWTHunterAgent',
    factory: () => new JWTHunterAgent(),
    expectedId: 'jwt-hunter',
    expectedName: 'JWT Hunter',
    expectedVulnClasses: ['jwt_vulnerability', 'jwt_alg_confusion', 'jwt_none', 'jwt_kid_injection'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'BusinessLogicHunterAgent',
    factory: () => new BusinessLogicHunterAgent(),
    expectedId: 'business-logic-hunter',
    expectedName: 'Business Logic Hunter',
    expectedVulnClasses: ['business_logic', 'idor', 'privilege_escalation'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'NoSQLHunterAgent',
    factory: () => new NoSQLHunterAgent(),
    expectedId: 'nosql-hunter',
    expectedName: 'NoSQL Hunter',
    expectedVulnClasses: ['nosql_injection', 'injection', 'authentication_bypass'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'DeserializationHunterAgent',
    factory: () => new DeserializationHunterAgent(),
    expectedId: 'deserialization-hunter',
    expectedName: 'Deserialization Hunter',
    expectedVulnClasses: ['deserialization', 'rce', 'injection'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'SAMLHunterAgent',
    factory: () => new SAMLHunterAgent(),
    expectedId: 'saml-hunter',
    expectedName: 'SAML Hunter',
    expectedVulnClasses: ['saml_attack', 'authentication', 'xml_signature'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'MFABypassHunterAgent',
    factory: () => new MFABypassHunterAgent(),
    expectedId: 'mfa-bypass-hunter',
    expectedName: 'MFA Bypass Hunter',
    expectedVulnClasses: ['mfa_bypass', 'authentication', '2fa_bypass'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'WebSocketHunterAgent',
    factory: () => new WebSocketHunterAgent(),
    expectedId: 'websocket-hunter',
    expectedName: 'WebSocket Hunter',
    expectedVulnClasses: ['websocket', 'injection', 'authentication'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'CRLFHunterAgent',
    factory: () => new CRLFHunterAgent(),
    expectedId: 'crlf-hunter',
    expectedName: 'CRLF Injection Hunter',
    expectedVulnClasses: ['crlf_injection', 'header_injection', 'http_response_splitting'],
    expectedAssetTypes: ['web-application', 'api'],
  },
  {
    name: 'PromptInjectionHunterAgent',
    factory: () => new PromptInjectionHunterAgent(),
    expectedId: 'prompt-injection-hunter',
    expectedName: 'Prompt Injection Hunter',
    expectedVulnClasses: ['prompt_injection', 'llm_vulnerability', 'ai_security'],
    expectedAssetTypes: ['web-application', 'api'],
  },
];

// ─── Parametric Tests for All 12 Agents ─────────────────────────────────────

for (const spec of agentSpecs) {
  describe(spec.name, () => {
    let agent: ReturnType<typeof spec.factory>;

    beforeEach(() => {
      agent = spec.factory();
    });

    it('should have correct metadata', () => {
      expect(agent.metadata.id).toBe(spec.expectedId);
      expect(agent.metadata.name).toBe(spec.expectedName);

      for (const vc of spec.expectedVulnClasses) {
        expect(agent.metadata.vulnerabilityClasses).toContain(vc);
      }

      for (const at of spec.expectedAssetTypes) {
        expect(agent.metadata.assetTypes).toContain(at);
      }
    });

    it('should start in idle status', () => {
      const status = agent.getStatus();
      expect(status.status).toBe('idle');
      expect(status.agentId).toBe(spec.expectedId);
      expect(status.toolsExecuted).toBe(0);
      expect(status.findingsCount).toBe(0);
    });

    it('should validate valid URLs', () => {
      expect(agent.validate('https://example.com')).toBe(true);
      expect(agent.validate('http://test.example.com/path')).toBe(true);
      expect(agent.validate('example.com')).toBe(true);
    });

    it('should reject invalid targets', () => {
      expect(agent.validate('')).toBe(false);
      expect(agent.validate('not a url at all!!!')).toBe(false);
    });

    it('should initialize with provider and model', async () => {
      const provider = createMockProvider();
      await agent.initialize(provider, 'mock-model');
      const status = agent.getStatus();
      expect(status.status).toBe('initializing');
    });

    it('should throw if execute called before initialize', async () => {
      const task = createTask();
      await expect(agent.execute(task)).rejects.toThrow('not initialized');
    });

    it('should execute a task and return results', async () => {
      const provider = createMockProvider();
      await agent.initialize(provider, 'mock-model');

      const task = createTask({ description: `Test ${spec.expectedName} on example.com` });
      const result = await agent.execute(task);

      expect(result.taskId).toBe(task.id);
      expect(result.agentId).toBe(spec.expectedId);
      expect(result.success).toBe(true);
      expect(result.duration).toBeGreaterThanOrEqual(0);
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it('should track status through lifecycle', async () => {
      const provider = createMockProvider();
      await agent.initialize(provider, 'mock-model');
      expect(agent.getStatus().status).toBe('initializing');

      await agent.execute(createTask());
      expect(agent.getStatus().status).toBe('completed');

      await agent.cleanup();
      expect(agent.getStatus().status).toBe('idle');
    });

    it('should return empty findings after cleanup', async () => {
      const provider = createMockProvider();
      await agent.initialize(provider, 'mock-model');
      await agent.execute(createTask());

      await agent.cleanup();
      expect(agent.reportFindings()).toHaveLength(0);
    });

    it('should accept approval and execution callbacks', () => {
      const approvalFn = async () => true;
      const executeFn = async () => ({
        success: true, stdout: '', stderr: '', exitCode: 0, executionTimeMs: 100,
      });

      // Should not throw
      agent.setCallbacks({
        onApprovalRequest: approvalFn,
        onExecuteCommand: executeFn,
      });
    });
  });
}

// ─── Catalog Registration ───────────────────────────────────────────────────

describe('Agent Fleet Catalog Registration', () => {
  it('should register all 24 agents in the catalog', () => {
    // Importing the agents triggers self-registration
    initializeCatalog();
    const allAgents = getAllAgents();
    const agentIds = allAgents.map(a => a.metadata.id);

    for (const spec of agentSpecs) {
      expect(agentIds).toContain(spec.expectedId);
    }
  });

  it('should create fresh instances from catalog factories', () => {
    const allAgents = getAllAgents();

    for (const spec of agentSpecs) {
      const entry = allAgents.find(a => a.metadata.id === spec.expectedId);
      expect(entry).toBeDefined();

      const agent = entry!.factory();
      expect(agent.metadata.id).toBe(spec.expectedId);
      expect(agent.metadata.name).toBe(spec.expectedName);
      expect(agent.getStatus().status).toBe('idle');
    }
  });

  it('should create independent instances (no shared state)', () => {
    const allAgents = getAllAgents();

    for (const spec of agentSpecs) {
      const entry = allAgents.find(a => a.metadata.id === spec.expectedId);
      expect(entry).toBeDefined();

      const agent1 = entry!.factory();
      const agent2 = entry!.factory();

      expect(agent1).not.toBe(agent2);
      expect(agent1.getStatus().agentId).toBe(agent2.getStatus().agentId);
    }
  });
});

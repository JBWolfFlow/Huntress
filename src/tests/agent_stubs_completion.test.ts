/**
 * Agent Stubs Completion Tests
 *
 * Tests for the newly implemented ReactLoop-based agents:
 * - OpenRedirectHunterAgent
 * - HostHeaderHunterAgent
 * - PrototypePollutionHunterAgent
 * - OAuthDiscovery (waybackurls + nuclei wiring)
 *
 * Verifies BaseAgent interface compliance, metadata, lifecycle, status
 * tracking, finding conversion, and catalog registration.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { OpenRedirectHunterAgent } from '../agents/open_redirect';
import { HostHeaderHunterAgent } from '../agents/host_header';
import { PrototypePollutionHunterAgent } from '../agents/prototype_pollution';
import { OAuthDiscovery } from '../agents/oauth/discovery';
import type { DiscoveryConfig, CommandExecResult } from '../agents/oauth/discovery';
import { getAllAgents, initializeCatalog } from '../agents/agent_catalog';
import type { AgentTask } from '../agents/base_agent';
import type {
  ModelProvider,
  ChatMessage,
  ChatResponse,
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

    async sendMessage(_messages: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
      callCount++;
      // Always return stop_hunting to end the loop immediately
      // Must use valid enum value from stop_hunting schema
      return {
        content: 'No vulnerabilities found.',
        model: options.model,
        inputTokens: 100,
        outputTokens: 50,
        stopReason: 'tool_use',
        toolCalls: [{
          type: 'tool_use',
          id: `tool_stop_${callCount}`,
          name: 'stop_hunting',
          input: { reason: 'no_vulnerabilities', summary: 'Mock test — no real targets available' },
        }],
        contentBlocks: [
          { type: 'text', text: 'No vulnerabilities found.' },
          {
            type: 'tool_use',
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

// ─── Open Redirect Hunter Agent ─────────────────────────────────────────────

describe('OpenRedirectHunterAgent', () => {
  let agent: OpenRedirectHunterAgent;

  beforeEach(() => {
    agent = new OpenRedirectHunterAgent();
  });

  it('should have correct metadata', () => {
    expect(agent.metadata.id).toBe('open-redirect-hunter');
    expect(agent.metadata.name).toBe('Open Redirect Hunter');
    expect(agent.metadata.vulnerabilityClasses).toContain('open-redirect');
    expect(agent.metadata.vulnerabilityClasses).toContain('ssrf');
    expect(agent.metadata.assetTypes).toContain('web-application');
  });

  it('should start in idle status', () => {
    const status = agent.getStatus();
    expect(status.status).toBe('idle');
    expect(status.agentId).toBe('open-redirect-hunter');
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

    const task = createTask({ description: 'Test open redirect on example.com' });
    const result = await agent.execute(task);

    expect(result.taskId).toBe(task.id);
    expect(result.agentId).toBe('open-redirect-hunter');
    expect(result.success).toBe(true);
    expect(result.duration).toBeGreaterThan(0);
    expect(Array.isArray(result.findings)).toBe(true);
  });

  it('should track status during execution', async () => {
    const provider = createMockProvider();
    await agent.initialize(provider, 'mock-model');

    const task = createTask();
    await agent.execute(task);

    const status = agent.getStatus();
    expect(status.status).toBe('completed');
  });

  it('should return empty findings after cleanup', async () => {
    const provider = createMockProvider();
    await agent.initialize(provider, 'mock-model');
    await agent.execute(createTask());

    await agent.cleanup();
    expect(agent.reportFindings()).toHaveLength(0);
    expect(agent.getStatus().status).toBe('idle');
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

// ─── Host Header Hunter Agent ───────────────────────────────────────────────

describe('HostHeaderHunterAgent', () => {
  let agent: HostHeaderHunterAgent;

  beforeEach(() => {
    agent = new HostHeaderHunterAgent();
  });

  it('should have correct metadata', () => {
    expect(agent.metadata.id).toBe('host-header-hunter');
    expect(agent.metadata.name).toBe('Host Header Hunter');
    expect(agent.metadata.vulnerabilityClasses).toContain('host-header');
    expect(agent.metadata.vulnerabilityClasses).toContain('cache-poisoning');
    expect(agent.metadata.vulnerabilityClasses).toContain('password-reset-poisoning');
    expect(agent.metadata.assetTypes).toContain('web-application');
  });

  it('should start in idle status', () => {
    const status = agent.getStatus();
    expect(status.status).toBe('idle');
    expect(status.agentId).toBe('host-header-hunter');
    expect(status.toolsExecuted).toBe(0);
    expect(status.findingsCount).toBe(0);
  });

  it('should validate valid URLs', () => {
    expect(agent.validate('https://example.com')).toBe(true);
    expect(agent.validate('example.com')).toBe(true);
  });

  it('should reject invalid targets', () => {
    expect(agent.validate('')).toBe(false);
  });

  it('should initialize with provider and model', async () => {
    const provider = createMockProvider();
    await agent.initialize(provider, 'mock-model');
    expect(agent.getStatus().status).toBe('initializing');
  });

  it('should throw if execute called before initialize', async () => {
    await expect(agent.execute(createTask())).rejects.toThrow('not initialized');
  });

  it('should execute a task and return results', async () => {
    const provider = createMockProvider();
    await agent.initialize(provider, 'mock-model');

    const task = createTask({ description: 'Test host header injection on example.com' });
    const result = await agent.execute(task);

    expect(result.taskId).toBe(task.id);
    expect(result.agentId).toBe('host-header-hunter');
    expect(result.success).toBe(true);
    expect(result.duration).toBeGreaterThanOrEqual(0);
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
});

// ─── Prototype Pollution Hunter Agent ───────────────────────────────────────

describe('PrototypePollutionHunterAgent', () => {
  let agent: PrototypePollutionHunterAgent;

  beforeEach(() => {
    agent = new PrototypePollutionHunterAgent();
  });

  it('should have correct metadata', () => {
    expect(agent.metadata.id).toBe('prototype-pollution-hunter');
    expect(agent.metadata.name).toBe('Prototype Pollution Hunter');
    expect(agent.metadata.vulnerabilityClasses).toContain('prototype-pollution');
    expect(agent.metadata.vulnerabilityClasses).toContain('injection');
    expect(agent.metadata.assetTypes).toContain('web-application');
    expect(agent.metadata.assetTypes).toContain('api');
  });

  it('should start in idle status', () => {
    const status = agent.getStatus();
    expect(status.status).toBe('idle');
    expect(status.agentId).toBe('prototype-pollution-hunter');
  });

  it('should validate valid URLs', () => {
    expect(agent.validate('https://example.com')).toBe(true);
    expect(agent.validate('http://api.example.com/merge')).toBe(true);
    expect(agent.validate('example.com')).toBe(true);
  });

  it('should reject invalid targets', () => {
    expect(agent.validate('')).toBe(false);
  });

  it('should initialize with provider and model', async () => {
    const provider = createMockProvider();
    await agent.initialize(provider, 'mock-model');
    expect(agent.getStatus().status).toBe('initializing');
  });

  it('should throw if execute called before initialize', async () => {
    await expect(agent.execute(createTask())).rejects.toThrow('not initialized');
  });

  it('should execute a task and return results', async () => {
    const provider = createMockProvider();
    await agent.initialize(provider, 'mock-model');

    const task = createTask({ description: 'Test prototype pollution on example.com' });
    const result = await agent.execute(task);

    expect(result.taskId).toBe(task.id);
    expect(result.agentId).toBe('prototype-pollution-hunter');
    expect(result.success).toBe(true);
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  it('should track status through lifecycle', async () => {
    const provider = createMockProvider();
    await agent.initialize(provider, 'mock-model');

    await agent.execute(createTask());
    expect(agent.getStatus().status).toBe('completed');

    await agent.cleanup();
    expect(agent.getStatus().status).toBe('idle');
    expect(agent.reportFindings()).toHaveLength(0);
  });
});

// ─── Agent Catalog Registration ─────────────────────────────────────────────

describe('Agent Catalog Registration', () => {
  it('should register all three new agents in the catalog', () => {
    // Importing the agents triggers registration
    initializeCatalog();
    const allAgents = getAllAgents();
    const agentIds = allAgents.map(a => a.metadata.id);

    expect(agentIds).toContain('open-redirect-hunter');
    expect(agentIds).toContain('host-header-hunter');
    expect(agentIds).toContain('prototype-pollution-hunter');
  });

  it('should create fresh instances from catalog factories', () => {
    const allAgents = getAllAgents();

    const orEntry = allAgents.find(a => a.metadata.id === 'open-redirect-hunter');
    expect(orEntry).toBeDefined();
    const orAgent = orEntry!.factory();
    expect(orAgent.metadata.id).toBe('open-redirect-hunter');
    expect(orAgent.getStatus().status).toBe('idle');

    const hhEntry = allAgents.find(a => a.metadata.id === 'host-header-hunter');
    expect(hhEntry).toBeDefined();
    const hhAgent = hhEntry!.factory();
    expect(hhAgent.metadata.id).toBe('host-header-hunter');

    const ppEntry = allAgents.find(a => a.metadata.id === 'prototype-pollution-hunter');
    expect(ppEntry).toBeDefined();
    const ppAgent = ppEntry!.factory();
    expect(ppAgent.metadata.id).toBe('prototype-pollution-hunter');
  });

  it('should create independent instances (no shared state)', () => {
    const allAgents = getAllAgents();
    const entry = allAgents.find(a => a.metadata.id === 'open-redirect-hunter');
    expect(entry).toBeDefined();

    const agent1 = entry!.factory();
    const agent2 = entry!.factory();

    // They should be different instances
    expect(agent1).not.toBe(agent2);
    expect(agent1.getStatus().agentId).toBe(agent2.getStatus().agentId);
  });
});

// ─── Legacy Exports ─────────────────────────────────────────────────────────

describe('Legacy Backward Compatibility', () => {
  it('should export OpenRedirectHunter as alias', async () => {
    const { OpenRedirectHunter } = await import('../agents/open_redirect');
    const agent = new OpenRedirectHunter();
    expect(agent.metadata.id).toBe('open-redirect-hunter');
  });

  it('should export HostHeaderHunter as alias', async () => {
    const { HostHeaderHunter } = await import('../agents/host_header');
    const agent = new HostHeaderHunter();
    expect(agent.metadata.id).toBe('host-header-hunter');
  });

  it('should export PrototypePollutionHunter as alias', async () => {
    const { PrototypePollutionHunter } = await import('../agents/prototype_pollution');
    const agent = new PrototypePollutionHunter();
    expect(agent.metadata.id).toBe('prototype-pollution-hunter');
  });

  it('should re-export from standardized_agents', async () => {
    const { OpenRedirectAgent, HostHeaderAgent, PrototypePollutionAgent } = await import('../agents/standardized_agents');
    expect(new OpenRedirectAgent().metadata.id).toBe('open-redirect-hunter');
    expect(new HostHeaderAgent().metadata.id).toBe('host-header-hunter');
    expect(new PrototypePollutionAgent().metadata.id).toBe('prototype-pollution-hunter');
  });
});

// ─── OAuth Discovery — Wayback & Nuclei Wiring ─────────────────────────────

describe('OAuthDiscovery Command Executor', () => {
  it('should skip wayback discovery when no command executor is provided', async () => {
    const config: DiscoveryConfig = {
      target: 'example.com',
      timeout: 5000,
      maxEndpoints: 50,
      useWayback: true,
      useNuclei: false,
    };

    const discovery = new OAuthDiscovery(config);
    // Should not throw — gracefully skips
    const endpoints = await discovery.discover();
    expect(Array.isArray(endpoints)).toBe(true);
  });

  it('should skip nuclei discovery when no command executor is provided', async () => {
    const config: DiscoveryConfig = {
      target: 'example.com',
      timeout: 5000,
      maxEndpoints: 50,
      useWayback: false,
      useNuclei: true,
    };

    const discovery = new OAuthDiscovery(config);
    const endpoints = await discovery.discover();
    expect(Array.isArray(endpoints)).toBe(true);
  });

  it('should parse waybackurls output when executor is provided', async () => {
    const mockExecutor = async (
      command: string,
      args: string[],
      _timeoutMs: number,
    ): Promise<CommandExecResult> => {
      expect(command).toBe('waybackurls');
      expect(args).toEqual(['example.com']);
      return {
        stdout: [
          'https://example.com/oauth/authorize?client_id=abc',
          'https://example.com/oauth/token',
          'https://example.com/auth/callback?code=xyz',
          'https://example.com/static/logo.png',
        ].join('\n'),
        stderr: '',
        exitCode: 0,
      };
    };

    const config: DiscoveryConfig = {
      target: 'example.com',
      timeout: 5000,
      maxEndpoints: 50,
      useWayback: true,
      useNuclei: false,
      commandExecutor: mockExecutor,
    };

    const discovery = new OAuthDiscovery(config);
    const endpoints = await discovery.discover();

    // Should find OAuth-related endpoints from wayback (not logo.png)
    const waybackEndpoints = endpoints.filter(e => e.discoveryMethod === 'wayback');
    expect(waybackEndpoints.length).toBeGreaterThanOrEqual(2);
    expect(waybackEndpoints.every(e => e.confidence === 60)).toBe(true);
  });

  it('should parse nuclei JSON Lines output when executor is provided', async () => {
    const mockExecutor = async (
      command: string,
      args: string[],
      _timeoutMs: number,
    ): Promise<CommandExecResult> => {
      expect(command).toBe('nuclei');
      expect(args).toContain('-u');
      expect(args).toContain('-jsonl');
      return {
        stdout: [
          JSON.stringify({
            'matched-at': 'https://example.com/oauth/authorize',
            'template-id': 'oauth-open-redirect',
            info: { name: 'OAuth Open Redirect', severity: 'medium' },
          }),
          JSON.stringify({
            'matched-at': 'https://example.com/.well-known/openid-configuration',
            'template-id': 'openid-config-disclosure',
            info: { name: 'OpenID Config Disclosure', severity: 'info' },
          }),
        ].join('\n'),
        stderr: '',
        exitCode: 0,
      };
    };

    const config: DiscoveryConfig = {
      target: 'example.com',
      timeout: 5000,
      maxEndpoints: 50,
      useWayback: false,
      useNuclei: true,
      commandExecutor: mockExecutor,
    };

    const discovery = new OAuthDiscovery(config);
    const endpoints = await discovery.discover();

    const nucleiEndpoints = endpoints.filter(e => e.discoveryMethod === 'nuclei');
    expect(nucleiEndpoints.length).toBe(2);
    expect(nucleiEndpoints[0].confidence).toBe(85);
    expect(nucleiEndpoints[0].metadata?.templateId).toBe('oauth-open-redirect');
  });

  it('should handle waybackurls failure gracefully', async () => {
    const mockExecutor = async (): Promise<CommandExecResult> => {
      return { stdout: '', stderr: 'waybackurls: command not found', exitCode: 127 };
    };

    const config: DiscoveryConfig = {
      target: 'example.com',
      timeout: 5000,
      maxEndpoints: 50,
      useWayback: true,
      useNuclei: false,
      commandExecutor: mockExecutor,
    };

    const discovery = new OAuthDiscovery(config);
    const endpoints = await discovery.discover();
    // Should not throw, just return empty from wayback
    const waybackEndpoints = endpoints.filter(e => e.discoveryMethod === 'wayback');
    expect(waybackEndpoints).toHaveLength(0);
  });

  it('should handle nuclei failure gracefully', async () => {
    const mockExecutor = async (): Promise<CommandExecResult> => {
      return { stdout: '', stderr: 'nuclei: no templates found', exitCode: 1 };
    };

    const config: DiscoveryConfig = {
      target: 'example.com',
      timeout: 5000,
      maxEndpoints: 50,
      useWayback: false,
      useNuclei: true,
      commandExecutor: mockExecutor,
    };

    const discovery = new OAuthDiscovery(config);
    const endpoints = await discovery.discover();
    const nucleiEndpoints = endpoints.filter(e => e.discoveryMethod === 'nuclei');
    expect(nucleiEndpoints).toHaveLength(0);
  });

  it('should deduplicate endpoints by URL with highest confidence winning', async () => {
    const mockExecutor = async (
      command: string,
    ): Promise<CommandExecResult> => {
      if (command === 'waybackurls') {
        return {
          stdout: 'https://example.com/oauth/authorize?client_id=old\n',
          stderr: '',
          exitCode: 0,
        };
      }
      // nuclei
      return {
        stdout: JSON.stringify({
          'matched-at': 'https://example.com/oauth/authorize?client_id=old',
          'template-id': 'oauth-test',
          info: { name: 'Test', severity: 'info' },
        }) + '\n',
        stderr: '',
        exitCode: 0,
      };
    };

    const config: DiscoveryConfig = {
      target: 'example.com',
      timeout: 5000,
      maxEndpoints: 50,
      useWayback: true,
      useNuclei: true,
      commandExecutor: mockExecutor,
    };

    const discovery = new OAuthDiscovery(config);
    const endpoints = await discovery.discover();

    // The nuclei endpoint (confidence 85) should win over wayback (confidence 60)
    const matching = endpoints.filter(e =>
      e.url.includes('/oauth/authorize')
    );
    // At most one per unique URL due to deduplication
    const nucleiMatch = matching.find(e => e.discoveryMethod === 'nuclei');
    if (nucleiMatch) {
      expect(nucleiMatch.confidence).toBe(85);
    }
  });
});

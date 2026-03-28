/**
 * AgentRouter
 *
 * Routes tasks to appropriate agents based on vulnerability class and target.
 * Manages agent lifecycle: spawn, monitor, collect results, terminate.
 */

import type { ModelProvider } from '../core/providers/types';
import type { BaseAgent, AgentTask, AgentResult, AgentStatus } from './base_agent';
import { getAllAgents, findAgentsForVulnClass, initializeCatalog } from './agent_catalog';
import {
  classifyTaskComplexity,
  selectModelForTask,
  type AgentModelOverride,
  type SelectedModel,
} from '../core/orchestrator/cost_router';

// Import all agent modules to trigger catalog registration
import './recon_agent';
import './standardized_agents';
import './xxe_hunter';
import './command_injection_hunter';
import './path_traversal_hunter';
import './ssrf_hunter';
import './xss_hunter';
import './sqli_hunter';
import './cors_hunter';
import './subdomain_takeover_hunter';

export interface RouterConfig {
  provider: ModelProvider;
  model: string;
  /** Maximum number of agents that can run concurrently */
  maxConcurrent?: number;
  /** Additional providers available for cost-optimized routing */
  additionalProviders?: Array<{ provider: ModelProvider; models: string[] }>;
  /** Per-agent model overrides from user settings */
  agentModelOverrides?: Record<string, AgentModelOverride>;
}

export class AgentRouter {
  private config: RouterConfig;
  private activeAgents: Map<string, BaseAgent> = new Map();
  private results: AgentResult[] = [];
  private onStatusChange?: (statuses: AgentStatus[]) => void;

  constructor(config: RouterConfig) {
    this.config = {
      maxConcurrent: 5,
      ...config,
    };
    initializeCatalog();
  }

  /** Set callback for agent status changes */
  setStatusCallback(callback: (statuses: AgentStatus[]) => void): void {
    this.onStatusChange = callback;
  }

  /** Route a task to a fresh agent instance (short-lived agent pattern) */
  async routeTask(task: AgentTask): Promise<AgentResult> {
    const agentId = task.parameters.agentId as string | undefined;

    // Always create a fresh agent instance — prevents context decay
    const agent = await this.createFreshAgent(task, agentId);

    try {
      // Execute the task
      const result = await agent.execute(task);
      this.results.push(result);
      this.emitStatusUpdate();

      return result;
    } finally {
      // Immediately cleanup after execution — agent is single-use
      await agent.cleanup();
      // Remove from active tracking
      for (const [id, a] of this.activeAgents.entries()) {
        if (a === agent) {
          this.activeAgents.delete(id);
          break;
        }
      }
      this.emitStatusUpdate();
    }
  }

  /** Route tasks to multiple agents in parallel */
  async routeParallel(tasks: AgentTask[]): Promise<AgentResult[]> {
    const maxConcurrent = this.config.maxConcurrent ?? 5;
    const results: AgentResult[] = [];

    // Process in batches
    for (let i = 0; i < tasks.length; i += maxConcurrent) {
      const batch = tasks.slice(i, i + maxConcurrent);
      const batchResults = await Promise.allSettled(
        batch.map(task => this.routeTask(task))
      );

      for (const result of batchResults) {
        if (result.status === 'fulfilled') {
          results.push(result.value);
        } else {
          results.push({
            taskId: batch[batchResults.indexOf(result)]?.id ?? 'unknown',
            agentId: 'unknown',
            success: false,
            findings: [],
            toolsExecuted: 0,
            duration: 0,
            error: result.reason?.message ?? 'Unknown error',
          });
        }
      }
    }

    return results;
  }

  /** Get all active agent statuses */
  getAgentStatuses(): AgentStatus[] {
    return Array.from(this.activeAgents.values()).map(agent => agent.getStatus());
  }

  /** Get all collected results */
  getResults(): AgentResult[] {
    return this.results;
  }

  /** Stop a specific agent */
  async stopAgent(agentId: string): Promise<void> {
    const agent = this.activeAgents.get(agentId);
    if (agent) {
      await agent.cleanup();
      this.activeAgents.delete(agentId);
      this.emitStatusUpdate();
    }
  }

  /** Stop all agents */
  async stopAll(): Promise<void> {
    const cleanups = Array.from(this.activeAgents.values()).map(a => a.cleanup());
    await Promise.allSettled(cleanups);
    this.activeAgents.clear();
    this.emitStatusUpdate();
  }

  /** List all available agent types */
  listAvailableAgents(): Array<{ id: string; name: string; description: string; vulnerabilityClasses: string[] }> {
    return getAllAgents().map(entry => ({
      id: entry.metadata.id,
      name: entry.metadata.name,
      description: entry.metadata.description,
      vulnerabilityClasses: entry.metadata.vulnerabilityClasses,
    }));
  }

  /** Select provider/model for this task using cost-optimized routing */
  private selectModelForAgent(agentId: string, task: AgentTask): SelectedModel {
    const complexity = classifyTaskComplexity(agentId, task.description);

    // Build available providers list: default provider + any additional
    const available: Array<{ provider: ModelProvider; models: string[] }> = [
      { provider: this.config.provider, models: [this.config.model] },
      ...(this.config.additionalProviders ?? []),
    ];

    const selected = selectModelForTask(
      complexity,
      available,
      this.config.agentModelOverrides,
      agentId,
    );

    // Fall back to default config if routing returns null
    return selected ?? { provider: this.config.provider, model: this.config.model };
  }

  /** Always create a fresh agent instance from the catalog (no reuse) */
  private async createFreshAgent(task: AgentTask, preferredAgentId?: string): Promise<BaseAgent> {
    const entries = preferredAgentId
      ? getAllAgents().filter(e => e.metadata.id === preferredAgentId)
      : findAgentsForVulnClass(task.description);

    if (entries.length === 0) {
      // Fall back to all available agents and pick the first one that validates
      const allEntries = getAllAgents();
      for (const entry of allEntries) {
        const agent = entry.factory();
        if (agent.validate(task.target)) {
          const { provider, model } = this.selectModelForAgent(entry.metadata.id, task);
          await agent.initialize(provider, model);
          const instanceId = `${entry.metadata.id}_${Date.now()}`;
          this.activeAgents.set(instanceId, agent);
          this.emitStatusUpdate();
          return agent;
        }
      }
      throw new Error(`No agent available for task: ${task.description}`);
    }

    const entry = entries[0];
    const agent = entry.factory();
    const { provider, model } = this.selectModelForAgent(entry.metadata.id, task);
    await agent.initialize(provider, model);
    const instanceId = `${entry.metadata.id}_${Date.now()}`;
    this.activeAgents.set(instanceId, agent);
    this.emitStatusUpdate();

    return agent;
  }

  private emitStatusUpdate(): void {
    this.onStatusChange?.(this.getAgentStatuses());
  }
}

export default AgentRouter;

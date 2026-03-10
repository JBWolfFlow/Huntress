/**
 * BaseAgent Interface
 *
 * Standard contract all hunting agents must implement.
 * Provides lifecycle management, task execution, and result reporting.
 */

import type { ModelProvider } from '../core/providers/types';

/** Task assigned to an agent by the orchestrator */
export interface AgentTask {
  id: string;
  target: string;
  scope: string[];
  description: string;
  parameters: Record<string, unknown>;
}

/** Severity levels */
export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/** A finding reported by an agent */
export interface AgentFinding {
  id: string;
  agentId: string;
  type: string;
  title: string;
  severity: FindingSeverity;
  description: string;
  target: string;
  evidence: string[];
  reproduction: string[];
  timestamp: Date;
}

/** An observation reported by an agent for cross-agent sharing */
export interface AgentObservation {
  category?: string;
  detail: string;
  relevantTo?: string[];
}

/** Result of an agent task execution */
export interface AgentResult {
  taskId: string;
  agentId: string;
  success: boolean;
  findings: AgentFinding[];
  /** Observations for cross-agent knowledge sharing via the Blackboard */
  observations?: AgentObservation[];
  toolsExecuted: number;
  duration: number;
  error?: string;
}

/** Real-time agent status */
export interface AgentStatus {
  agentId: string;
  agentName: string;
  status: 'idle' | 'initializing' | 'running' | 'waiting' | 'completed' | 'failed';
  currentTask?: string;
  toolsExecuted: number;
  findingsCount: number;
  lastUpdate: number;
}

/** Metadata describing an agent's capabilities */
export interface AgentMetadata {
  id: string;
  name: string;
  description: string;
  vulnerabilityClasses: string[];
  assetTypes: string[];
}

/**
 * The base agent interface.
 * All specialized hunting agents must implement these methods.
 */
export interface BaseAgent {
  /** Agent metadata */
  readonly metadata: AgentMetadata;

  /** Initialize the agent with a model provider */
  initialize(provider: ModelProvider, model: string): Promise<void>;

  /** Execute a task and return results */
  execute(task: AgentTask): Promise<AgentResult>;

  /** Validate that a target is appropriate for this agent */
  validate(target: string): boolean;

  /** Get all findings from this agent */
  reportFindings(): AgentFinding[];

  /** Clean up resources */
  cleanup(): Promise<void>;

  /** Get current status */
  getStatus(): AgentStatus;
}

/** Generate a unique finding ID */
export function generateFindingId(): string {
  return `finding_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
}

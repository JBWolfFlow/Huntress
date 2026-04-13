/**
 * BaseAgent Interface
 *
 * Standard contract all hunting agents must implement.
 * Provides lifecycle management, task execution, and result reporting.
 */

import type { ModelProvider } from '../core/providers/types';
import type { ValidationEvidence } from '../core/validation/validator';
import type { DuplicateScore } from '../utils/duplicate_checker';

// ─── Validation & Duplicate Status Types ────────────────────────────────────

/** Validation status for a finding after deterministic verification */
export type ValidationStatus = 'pending' | 'confirmed' | 'unverified' | 'validation_failed';

/** Result of H1 duplicate checking for a finding */
export interface DuplicateCheckResult {
  status: 'not_checked' | 'unique' | 'possible_duplicate' | 'likely_duplicate';
  score?: DuplicateScore;
  /** Top matching H1 reports (if any) */
  topMatches?: Array<{ source: string; title: string; url: string; similarity: number }>;
}

/** Lightweight summary of another agent's finding for cross-agent context */
export interface SharedFinding {
  /** Which agent produced this finding */
  agentId: string;
  /** Vulnerability type (e.g., 'xss', 'sqli', 'open-redirect') */
  vulnType: string;
  /** Finding title */
  title: string;
  /** Severity level */
  severity: FindingSeverity;
  /** Target URL/endpoint */
  target: string;
  /** Brief description (truncated to keep context bounded) */
  description: string;
}

/** WAF detection context for agents to adapt their payloads */
export interface WafContext {
  /** WAF vendor detected on the target domain */
  vendor: string;
  /** Detection confidence (0-1) */
  confidence: number;
  /** Human-readable evidence for what triggered detection */
  signal: string;
}

/** Task assigned to an agent by the orchestrator */
export interface AgentTask {
  id: string;
  target: string;
  scope: string[];
  description: string;
  parameters: Record<string, unknown>;
  /** Findings from other agents, injected by the orchestrator for cross-agent context */
  sharedFindings?: SharedFinding[];
  /** WAF detection context for the target domain — helps agents choose bypass techniques */
  wafContext?: WafContext;
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
  /** Validation status — set by the orchestrator's validation pipeline */
  validationStatus?: ValidationStatus;
  /** Deterministic evidence collected during validation */
  validationEvidence?: ValidationEvidence[];
  /** Confidence score from the validator (0-100) */
  validationConfidence?: number;
  /** H1 duplicate check result */
  duplicateCheck?: DuplicateCheckResult;
}

/** A captured HTTP request/response exchange for report evidence */
export interface HttpExchange {
  request: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
  };
  response: {
    status: number;
    statusText?: string;
    headers?: Record<string, string>;
    bodySnippet: string;
  };
  /** Which ReAct loop iteration produced this exchange */
  iteration?: number;
  /** Timestamp of the exchange */
  timestamp?: number;
  /** Auth session label used for this exchange — makes IDOR proofs self-auditing (Phase 1 / Q3) */
  sessionLabel?: string;
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
  /** Captured HTTP request/response exchanges for report evidence */
  httpExchanges?: HttpExchange[];
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

/**
 * Conversation Message Types
 *
 * Discriminated union of all message types that can appear in the chat.
 * Each type has a corresponding renderer in the ChatMessage component.
 */

import type { ValidationStatus, DuplicateCheckResult } from '../../agents/base_agent';
import type { ValidationEvidence } from '../validation/validator';

/** Severity levels for findings */
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/** Base fields shared by all conversation messages */
interface BaseMessage {
  id: string;
  timestamp: number;
}

/** User text message */
export interface UserMessage extends BaseMessage {
  type: 'user';
  content: string;
}

/** Orchestrator text response */
export interface OrchestratorMessage extends BaseMessage {
  type: 'orchestrator';
  content: string;
}

/** Agent status update shown in chat */
export interface AgentMessage extends BaseMessage {
  type: 'agent';
  agentId: string;
  agentName: string;
  content: string;
  status: 'running' | 'completed' | 'failed';
}

/** System notification */
export interface SystemMessage extends BaseMessage {
  type: 'system';
  content: string;
  level: 'info' | 'warning' | 'error' | 'success';
}

/** Code block with syntax highlighting */
export interface CodeBlockMessage extends BaseMessage {
  type: 'code_block';
  content: string;
  language: string;
  title?: string;
}

/** Vulnerability finding card */
export interface FindingCardMessage extends BaseMessage {
  type: 'finding_card';
  title: string;
  severity: Severity;
  description: string;
  target: string;
  agent: string;
  evidence: string[];
  isDuplicate: boolean;
  /** Phase 3: Deterministic validation status */
  validationStatus: ValidationStatus;
  /** Phase 3: Evidence from deterministic validation */
  validationEvidence?: ValidationEvidence[];
  /** Phase 3: Validator confidence score (0-100) */
  validationConfidence?: number;
  /** Phase 3: H1 duplicate check result */
  duplicateCheck?: DuplicateCheckResult;
}

/** Clickable attack strategy card */
export interface StrategyCardMessage extends BaseMessage {
  type: 'strategy_card';
  strategies: StrategyOption[];
}

export interface StrategyOption {
  id: string;
  title: string;
  description: string;
  expectedValue: string;
  agents: string[];
  riskLevel: 'low' | 'medium' | 'high';
}

/** Tool execution approval request */
export interface ApprovalMessage extends BaseMessage {
  type: 'approval';
  approvalId: string;
  command: string;
  agent: string;
  target: string;
  reasoning: string;
  status: 'pending' | 'approved' | 'denied';
}

/** PoC report preview */
export interface ReportPreviewMessage extends BaseMessage {
  type: 'report_preview';
  title: string;
  severity: Severity;
  markdown: string;
  cvssScore: number;
  target: string;
}

/** Program briefing after import */
export interface BriefingMessage extends BaseMessage {
  type: 'briefing';
  programName: string;
  targetSummary: string;
  assets: Array<{ type: string; target: string; inScope: boolean }>;
  bountyRange: { min: number; max: number };
  rules: string[];
  strategies: StrategyOption[];
}

/** The discriminated union of all message types */
export type ConversationMessage =
  | UserMessage
  | OrchestratorMessage
  | AgentMessage
  | SystemMessage
  | CodeBlockMessage
  | FindingCardMessage
  | StrategyCardMessage
  | ApprovalMessage
  | ReportPreviewMessage
  | BriefingMessage;

/** Extract the type string from a message */
export type MessageType = ConversationMessage['type'];

/** Hunt session phase */
export type SessionPhase =
  | 'idle'
  | 'setup'
  | 'briefing'
  | 'hunting'
  | 'reporting'
  | 'complete';

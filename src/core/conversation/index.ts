/**
 * Conversation Module — Barrel Export
 */

export type {
  ConversationMessage,
  MessageType,
  SessionPhase,
  Severity,
  UserMessage,
  OrchestratorMessage,
  AgentMessage,
  SystemMessage,
  CodeBlockMessage,
  FindingCardMessage,
  StrategyCardMessage,
  StrategyOption,
  ApprovalMessage,
  ReportPreviewMessage,
  BriefingMessage,
} from './types';

export { ConversationManager } from './conversation_manager';
export type { ConversationManagerConfig } from './conversation_manager';

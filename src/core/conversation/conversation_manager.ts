/**
 * ConversationManager
 *
 * Manages the full chat history between user and orchestrator.
 * Handles context windowing, message storage, and session persistence.
 */

import type { ChatMessage } from '../providers/types';
import { getMessageText } from '../providers/types';
import type { ConversationMessage } from './types';

/** Rough token estimation: ~4 chars per token */
function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

export interface ConversationManagerConfig {
  /** Max tokens to include when building context for the model */
  maxContextTokens?: number;
  /** Max messages to keep in full history before summarizing */
  maxHistoryMessages?: number;
}

export class ConversationManager {
  /** Full rich message history (includes UI-only types like cards, approvals) */
  private messages: ConversationMessage[] = [];
  /** Summaries of older conversation segments */
  private summaries: string[] = [];
  private config: Required<ConversationManagerConfig>;

  constructor(config: ConversationManagerConfig = {}) {
    this.config = {
      maxContextTokens: config.maxContextTokens ?? 120000,
      maxHistoryMessages: config.maxHistoryMessages ?? 500,
    };
  }

  /** Add a message to the conversation */
  addMessage(message: ConversationMessage): void {
    this.messages.push(message);

    // If history is very long, summarize the oldest chunk
    if (this.messages.length > this.config.maxHistoryMessages) {
      this.summarizeOldest();
    }
  }

  /** Get all messages (for UI rendering) */
  getMessages(): ConversationMessage[] {
    return this.messages;
  }

  /** Get message count */
  getMessageCount(): number {
    return this.messages.length;
  }

  /**
   * Build a ChatMessage[] suitable for sending to the AI model,
   * respecting the token budget. Older messages get summarized.
   */
  getMessagesForModel(maxTokens?: number): ChatMessage[] {
    const budget = maxTokens ?? this.config.maxContextTokens;
    const result: ChatMessage[] = [];
    let tokenCount = 0;

    // Always include summaries first (they're compact)
    if (this.summaries.length > 0) {
      const summaryText = `Previous conversation summary:\n${this.summaries.join('\n\n')}`;
      const summaryTokens = estimateTokens(summaryText);
      if (summaryTokens < budget * 0.3) {
        result.push({ role: 'system', content: summaryText });
        tokenCount += summaryTokens;
      }
    }

    // Walk messages from newest to oldest, collecting ones that fit
    const candidateMessages: ChatMessage[] = [];

    for (let i = this.messages.length - 1; i >= 0; i--) {
      const msg = this.messages[i];
      const chatMsg = this.toChatMessage(msg);
      if (!chatMsg) continue;

      const msgTokens = estimateTokens(getMessageText(chatMsg.content));
      if (tokenCount + msgTokens > budget) break;

      candidateMessages.unshift(chatMsg);
      tokenCount += msgTokens;
    }

    result.push(...candidateMessages);
    return result;
  }

  /** Clear all messages */
  clear(): void {
    this.messages = [];
    this.summaries = [];
  }

  /** Export session for persistence */
  exportSession(): { messages: ConversationMessage[]; summaries: string[] } {
    return {
      messages: [...this.messages],
      summaries: [...this.summaries],
    };
  }

  /** Import a previously saved session */
  importSession(data: { messages: ConversationMessage[]; summaries: string[] }): void {
    this.messages = [...data.messages];
    this.summaries = [...data.summaries];
  }

  /**
   * Convert a rich ConversationMessage to a plain ChatMessage for the AI.
   * Some message types (like approval status updates) are UI-only and return null.
   */
  private toChatMessage(msg: ConversationMessage): ChatMessage | null {
    switch (msg.type) {
      case 'user':
        return { role: 'user', content: msg.content };

      case 'orchestrator':
        return { role: 'assistant', content: msg.content };

      case 'agent':
        return {
          role: 'assistant',
          content: `[Agent: ${msg.agentName}] ${msg.content}`,
        };

      case 'system':
        return { role: 'system', content: msg.content };

      case 'finding_card':
        return {
          role: 'assistant',
          content: `[Finding] ${msg.severity.toUpperCase()}: ${msg.title} at ${msg.target}\n${msg.description}`,
        };

      case 'briefing':
        return {
          role: 'assistant',
          content: `[Briefing] Program: ${msg.programName}\nTargets: ${msg.assets.filter(a => a.inScope).map(a => a.target).join(', ')}\nBounty: $${msg.bountyRange.min}-$${msg.bountyRange.max}`,
        };

      case 'code_block':
        return {
          role: 'assistant',
          content: `\`\`\`${msg.language}\n${msg.content}\n\`\`\``,
        };

      case 'strategy_card':
        return {
          role: 'assistant',
          content: `[Strategies]\n${msg.strategies.map(s => `- ${s.title}: ${s.description} (EV: ${s.expectedValue})`).join('\n')}`,
        };

      case 'report_preview':
        return {
          role: 'assistant',
          content: `[Report Preview] ${msg.title} (CVSS: ${msg.cvssScore})\n${msg.markdown.substring(0, 500)}`,
        };

      case 'approval':
        // Approval messages don't need to be in AI context
        return null;

      default:
        return null;
    }
  }

  /** Summarize the oldest chunk of messages to keep history manageable */
  private summarizeOldest(): void {
    // Take the first 100 messages and create a compact summary
    const toSummarize = this.messages.splice(0, 100);

    const findings = toSummarize.filter(m => m.type === 'finding_card');
    const userMessages = toSummarize.filter(m => m.type === 'user');

    const summary = [
      `Session segment (${toSummarize.length} messages):`,
      userMessages.length > 0
        ? `User discussed: ${userMessages.map(m => m.type === 'user' ? m.content.substring(0, 80) : '').filter(Boolean).join('; ')}`
        : '',
      findings.length > 0
        ? `Findings: ${findings.length} vulnerabilities discovered`
        : 'No findings in this segment',
    ].filter(Boolean).join('\n');

    this.summaries.push(summary);
  }
}

export default ConversationManager;

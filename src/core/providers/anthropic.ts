/**
 * Anthropic Provider
 *
 * Wraps the existing @anthropic-ai/sdk for Claude models.
 * Models: claude-opus-4-6, claude-sonnet-4-5-20250929, claude-haiku-4-5-20251001
 */

import Anthropic from '@anthropic-ai/sdk';
import type {
  ModelProvider,
  ChatMessage,
  ChatResponse,
  StreamChunk,
  SendMessageOptions,
  ModelInfo,
  ProviderConfig,
  ToolDefinition,
  ToolUseBlock,
  ToolResultBlock,
  ContentBlock,
  MessageContent,
  ToolChoice,
} from './types';
import { getMessageText } from './types';

const ANTHROPIC_MODELS: ModelInfo[] = [
  {
    id: 'claude-opus-4-6',
    displayName: 'Claude Opus 4.6',
    contextWindow: 200000,
    maxOutputTokens: 32000,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 15,
    outputCostPer1M: 75,
  },
  {
    id: 'claude-sonnet-4-5-20250929',
    displayName: 'Claude Sonnet 4.5',
    contextWindow: 200000,
    maxOutputTokens: 16000,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 3,
    outputCostPer1M: 15,
  },
  {
    id: 'claude-haiku-4-5-20251001',
    displayName: 'Claude Haiku 4.5',
    contextWindow: 200000,
    maxOutputTokens: 8192,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 0.80,
    outputCostPer1M: 4,
  },
];

export class AnthropicProvider implements ModelProvider {
  readonly providerId = 'anthropic';
  readonly displayName = 'Anthropic';
  readonly supportsToolUse = true;
  private client: Anthropic;

  constructor(config: ProviderConfig) {
    if (!config.apiKey) {
      throw new Error('Anthropic provider requires an API key');
    }
    this.client = new Anthropic({
      apiKey: config.apiKey,
      dangerouslyAllowBrowser: true, // Required for Tauri desktop app
    });
  }

  async sendMessage(messages: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
    const { systemPrompt, anthropicMessages } = this.formatMessages(messages, options);

    const requestParams: Record<string, unknown> = {
      model: options.model,
      max_tokens: options.maxTokens ?? 4096,
      ...(systemPrompt ? { system: systemPrompt } : {}),
      ...(options.temperature !== undefined ? { temperature: options.temperature } : {}),
      ...(options.stopSequences?.length ? { stop_sequences: options.stopSequences } : {}),
      messages: anthropicMessages,
    };

    // Native tool use support
    if (options.tools?.length) {
      requestParams.tools = options.tools.map(t => ({
        name: t.name,
        description: t.description,
        input_schema: t.input_schema,
      }));
      if (options.toolChoice) {
        requestParams.tool_choice = this.formatToolChoice(options.toolChoice);
      }
    }

    const response = await this.client.messages.create(requestParams as unknown as Anthropic.MessageCreateParamsNonStreaming);

    // Extract text and tool use blocks
    const textParts: string[] = [];
    const toolCalls: ToolUseBlock[] = [];
    const contentBlocks: ContentBlock[] = [];

    for (const block of response.content) {
      if (block.type === 'text') {
        textParts.push(block.text);
        contentBlocks.push({ type: 'text', text: block.text });
      } else if (block.type === 'tool_use') {
        const toolUse: ToolUseBlock = {
          type: 'tool_use',
          id: block.id,
          name: block.name,
          input: block.input as Record<string, unknown>,
        };
        toolCalls.push(toolUse);
        contentBlocks.push(toolUse);
      }
    }

    return {
      content: textParts.join(''),
      model: response.model,
      inputTokens: response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
      stopReason: this.mapStopReason(response.stop_reason),
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      contentBlocks: contentBlocks.length > 0 ? contentBlocks : undefined,
    };
  }

  async *streamMessage(messages: ChatMessage[], options: SendMessageOptions): AsyncGenerator<StreamChunk> {
    const { systemPrompt, anthropicMessages } = this.formatMessages(messages, options);

    const requestParams: Record<string, unknown> = {
      model: options.model,
      max_tokens: options.maxTokens ?? 4096,
      ...(systemPrompt ? { system: systemPrompt } : {}),
      ...(options.temperature !== undefined ? { temperature: options.temperature } : {}),
      ...(options.stopSequences?.length ? { stop_sequences: options.stopSequences } : {}),
      messages: anthropicMessages,
    };

    if (options.tools?.length) {
      requestParams.tools = options.tools.map(t => ({
        name: t.name,
        description: t.description,
        input_schema: t.input_schema,
      }));
      if (options.toolChoice) {
        requestParams.tool_choice = this.formatToolChoice(options.toolChoice);
      }
    }

    const stream = this.client.messages.stream(requestParams as unknown as Anthropic.MessageCreateParamsStreaming);

    yield { type: 'message_start' };

    for await (const event of stream) {
      if (event.type === 'content_block_delta') {
        const delta = event.delta;
        if ('text' in delta) {
          yield { type: 'content_delta', content: (delta as { text: string }).text };
        } else if ('partial_json' in delta) {
          yield {
            type: 'tool_use_delta',
            content: (delta as { partial_json: string }).partial_json,
          };
        }
      }
    }

    const finalMessage = await stream.finalMessage();
    yield {
      type: 'message_stop',
      inputTokens: finalMessage.usage.input_tokens,
      outputTokens: finalMessage.usage.output_tokens,
    };
  }

  getAvailableModels(): ModelInfo[] {
    return ANTHROPIC_MODELS;
  }

  async validateApiKey(key: string): Promise<boolean> {
    try {
      const testClient = new Anthropic({
        apiKey: key,
        dangerouslyAllowBrowser: true,
      });
      await testClient.messages.create({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 10,
        messages: [{ role: 'user', content: 'ping' }],
      });
      return true;
    } catch {
      return false;
    }
  }

  estimateCost(inputTokens: number, outputTokens: number, model: string): number {
    const modelInfo = ANTHROPIC_MODELS.find(m => m.id === model);
    if (!modelInfo) return 0;
    return (inputTokens / 1_000_000) * modelInfo.inputCostPer1M +
           (outputTokens / 1_000_000) * modelInfo.outputCostPer1M;
  }

  /** Convert our generic messages to Anthropic's format */
  private formatMessages(
    messages: ChatMessage[],
    options: SendMessageOptions
  ): { systemPrompt: string | undefined; anthropicMessages: Anthropic.MessageParam[] } {
    let systemPrompt = options.systemPrompt;

    const anthropicMessages: Anthropic.MessageParam[] = [];

    for (const msg of messages) {
      if (msg.role === 'system') {
        // Anthropic uses a top-level system param; merge system messages
        const text = getMessageText(msg.content);
        systemPrompt = systemPrompt ? `${systemPrompt}\n\n${text}` : text;
      } else if (msg.role === 'user' && msg.toolResults?.length) {
        // User message carrying tool results back to the model
        const contentBlocks: Anthropic.ToolResultBlockParam[] = msg.toolResults.map(tr => ({
          type: 'tool_result' as const,
          tool_use_id: tr.tool_use_id,
          content: tr.content,
          ...(tr.is_error ? { is_error: true } : {}),
        }));
        anthropicMessages.push({ role: 'user', content: contentBlocks });
      } else if (msg.role === 'assistant' && typeof msg.content !== 'string') {
        // Assistant message with structured content blocks (text + tool_use)
        const contentBlocks: Array<Anthropic.TextBlockParam | Anthropic.ToolUseBlockParam> = msg.content.map(block => {
          if (block.type === 'text') {
            return { type: 'text' as const, text: block.text };
          }
          // tool_use block
          return {
            type: 'tool_use' as const,
            id: block.id,
            name: block.name,
            input: block.input,
          };
        });
        anthropicMessages.push({ role: 'assistant', content: contentBlocks });
      } else {
        // Plain text message
        const text = getMessageText(msg.content);
        anthropicMessages.push({ role: msg.role, content: text });
      }
    }

    return { systemPrompt, anthropicMessages };
  }

  /** Convert our ToolChoice to Anthropic's format */
  private formatToolChoice(choice: ToolChoice): Anthropic.MessageCreateParams['tool_choice'] {
    if (choice === 'auto') return { type: 'auto' };
    if (choice === 'any') return { type: 'any' };
    if (choice === 'none') return { type: 'auto' }; // Anthropic doesn't have 'none', use auto
    if (typeof choice === 'object') return { type: 'tool', name: choice.name };
    return { type: 'auto' };
  }

  private mapStopReason(reason: string | null): ChatResponse['stopReason'] {
    switch (reason) {
      case 'end_turn': return 'end_turn';
      case 'max_tokens': return 'max_tokens';
      case 'stop_sequence': return 'stop_sequence';
      case 'tool_use': return 'tool_use';
      default: return 'unknown';
    }
  }
}

export default AnthropicProvider;

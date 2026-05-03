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
  // Latest generation (4.7 / 4.6)
  {
    id: 'claude-opus-4-7',
    displayName: 'Claude Opus 4.7',
    contextWindow: 200000,
    maxOutputTokens: 32000,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 15,
    outputCostPer1M: 75,
  },
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
    id: 'claude-sonnet-4-6',
    displayName: 'Claude Sonnet 4.6',
    contextWindow: 200000,
    maxOutputTokens: 16000,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 3,
    outputCostPer1M: 15,
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

/**
 * Default per-Mtok rates for unknown / future model IDs. Used as the
 * fallback in `estimateCost` so cost tracking and budget enforcement
 * never silently report $0 for a real spend. Conservative defaults
 * (Opus-tier rates) so we OVERESTIMATE rather than underestimate.
 */
const FALLBACK_INPUT_PER_M = 15;
const FALLBACK_OUTPUT_PER_M = 75;

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

    let response: Anthropic.Message;
    try {
      response = await this.client.messages.create(requestParams as unknown as Anthropic.MessageCreateParamsNonStreaming);
    } catch (err) {
      // P1-1 v7: Surface the ACTUAL Anthropic error reason so we can debug
      // recurring 400s. Without this, the loop's catch sees only "400 Bad
      // Request" and we have no signal on what was malformed (orphan
      // tool_use, empty content, oversized message, invalid schema, etc.).
      // Logs the structured error from the SDK and a compact request
      // shape (NOT the full bodies — would dump 100KB+ of tool results).
      const e = err as { status?: number; message?: string; error?: { error?: { message?: string; type?: string } } };
      if (e?.status === 400) {
        const reason = e?.error?.error?.message ?? e?.message ?? 'unknown';
        const type = e?.error?.error?.type ?? 'unknown';
        const lastFew = anthropicMessages.slice(-3).map((m, i, arr) => {
          const idx = anthropicMessages.length - arr.length + i;
          if (typeof m.content === 'string') return `[${idx}] ${m.role}: text(${m.content.length}b)`;
          const blocks = (m.content as Array<{ type: string; id?: string; tool_use_id?: string }>).map(b => {
            if (b.type === 'tool_use') return `tool_use(${b.id})`;
            if (b.type === 'tool_result') return `tool_result(${b.tool_use_id})`;
            return b.type;
          });
          return `[${idx}] ${m.role}: [${blocks.join(', ')}]`;
        });
        // eslint-disable-next-line no-console
        console.error(
          `[anthropic 400] type=${type} reason="${reason}"\n` +
          `  model=${options.model} messages=${anthropicMessages.length} tools=${(options.tools ?? []).length}\n` +
          `  last 3 messages:\n    ${lastFew.join('\n    ')}`,
        );
      }
      throw err;
    }

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
    // Returning 0 for unknown models silently breaks cost tracking and budget
    // enforcement (the 90%/100% caps never trigger). Fall back to conservative
    // Opus-tier rates so we OVERESTIMATE — better than underestimating spend.
    const inputRate = modelInfo?.inputCostPer1M ?? FALLBACK_INPUT_PER_M;
    const outputRate = modelInfo?.outputCostPer1M ?? FALLBACK_OUTPUT_PER_M;
    return (inputTokens / 1_000_000) * inputRate +
           (outputTokens / 1_000_000) * outputRate;
  }

  /** Convert our generic messages to Anthropic's format */
  private formatMessages(
    messages: ChatMessage[],
    options: SendMessageOptions
  ): { systemPrompt: string | undefined; anthropicMessages: Anthropic.MessageParam[] } {
    let systemPrompt = options.systemPrompt;

    const anthropicMessages: Anthropic.MessageParam[] = [];

    // Anthropic /v1/messages rejects empty text content blocks AND empty
    // plain-string messages with 400 Bad Request. Substitute a placeholder
    // so the conversation stays valid even if upstream code accidentally
    // built an empty turn. Belt-and-suspenders for react_loop.ts:442-449.
    const EMPTY_PLACEHOLDER = '(empty)';
    const safeText = (t: string | undefined | null): string =>
      t && t.trim() ? t : EMPTY_PLACEHOLDER;

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
          content: typeof tr.content === 'string' ? safeText(tr.content) : tr.content,
          ...(tr.is_error ? { is_error: true } : {}),
        }));
        anthropicMessages.push({ role: 'user', content: contentBlocks });
      } else if (msg.role === 'assistant' && typeof msg.content !== 'string') {
        // Assistant message with structured content blocks (text + tool_use)
        const contentBlocks: Array<Anthropic.TextBlockParam | Anthropic.ToolUseBlockParam> = msg.content.map(block => {
          if (block.type === 'text') {
            return { type: 'text' as const, text: safeText(block.text) };
          }
          // tool_use block
          return {
            type: 'tool_use' as const,
            id: block.id,
            name: block.name,
            input: block.input,
          };
        });
        // Defensive: an assistant turn with zero content blocks would also 400
        if (contentBlocks.length === 0) {
          contentBlocks.push({ type: 'text', text: EMPTY_PLACEHOLDER });
        }
        anthropicMessages.push({ role: 'assistant', content: contentBlocks });
      } else {
        // Plain text message — same empty-rejection rule applies
        const text = safeText(getMessageText(msg.content));
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

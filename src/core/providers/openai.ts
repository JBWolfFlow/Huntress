/**
 * OpenAI Provider
 *
 * Supports GPT-4o, GPT-4o-mini, and o3 models via the OpenAI API.
 */

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
  ContentBlock,
  ToolChoice,
} from './types';
import { getMessageText, getToolUseBlocks } from './types';

const OPENAI_MODELS: ModelInfo[] = [
  {
    id: 'gpt-4o',
    displayName: 'GPT-4o',
    contextWindow: 128000,
    maxOutputTokens: 16384,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 2.50,
    outputCostPer1M: 10,
  },
  {
    id: 'gpt-4o-mini',
    displayName: 'GPT-4o Mini',
    contextWindow: 128000,
    maxOutputTokens: 16384,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 0.15,
    outputCostPer1M: 0.60,
  },
  {
    id: 'o3',
    displayName: 'o3',
    contextWindow: 200000,
    maxOutputTokens: 100000,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 10,
    outputCostPer1M: 40,
  },
];

/** Minimal OpenAI chat completion types (avoids requiring the full SDK) */
interface OpenAIMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string | null;
  tool_calls?: OpenAIToolCall[];
  tool_call_id?: string;
}

interface OpenAIToolCall {
  id: string;
  type: 'function';
  function: { name: string; arguments: string };
}

interface OpenAIToolDefinition {
  type: 'function';
  function: {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
  };
}

interface OpenAIChoice {
  index: number;
  message: {
    role: string;
    content: string | null;
    tool_calls?: OpenAIToolCall[];
  };
  finish_reason: string | null;
}

interface OpenAIStreamChoice {
  index: number;
  delta: {
    role?: string;
    content?: string;
    tool_calls?: Array<{
      index: number;
      id?: string;
      function?: { name?: string; arguments?: string };
    }>;
  };
  finish_reason: string | null;
}

interface OpenAIResponse {
  id: string;
  model: string;
  choices: OpenAIChoice[];
  usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
}

interface OpenAIStreamChunk {
  id: string;
  choices: OpenAIStreamChoice[];
  usage?: { prompt_tokens: number; completion_tokens: number };
}

export class OpenAIProvider implements ModelProvider {
  readonly providerId = 'openai';
  readonly displayName = 'OpenAI';
  readonly supportsToolUse = true;
  private apiKey: string;
  private baseUrl: string;

  constructor(config: ProviderConfig) {
    if (!config.apiKey) {
      throw new Error('OpenAI provider requires an API key');
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl ?? 'https://api.openai.com/v1';
  }

  async sendMessage(messages: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
    const openaiMessages = this.formatMessages(messages, options);

    const body: Record<string, unknown> = {
      model: options.model,
      messages: openaiMessages,
      max_completion_tokens: options.maxTokens ?? 4096,
      ...(options.temperature !== undefined ? { temperature: options.temperature } : {}),
      ...(options.stopSequences?.length ? { stop: options.stopSequences } : {}),
    };

    // Native tool use / function calling
    if (options.tools?.length) {
      body.tools = this.formatTools(options.tools);
      if (options.toolChoice) {
        body.tool_choice = this.formatToolChoice(options.toolChoice);
      }
    }

    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`OpenAI API error (${response.status}): ${error}`);
    }

    const data: OpenAIResponse = await response.json();
    const choice = data.choices[0];

    // Parse tool calls if present
    const toolCalls: ToolUseBlock[] = [];
    const contentBlocks: ContentBlock[] = [];

    if (choice?.message?.content) {
      contentBlocks.push({ type: 'text', text: choice.message.content });
    }

    if (choice?.message?.tool_calls) {
      for (const tc of choice.message.tool_calls) {
        let parsedInput: Record<string, unknown> = {};
        try {
          parsedInput = JSON.parse(tc.function.arguments);
        } catch {
          parsedInput = { raw: tc.function.arguments };
        }
        const toolUse: ToolUseBlock = {
          type: 'tool_use',
          id: tc.id,
          name: tc.function.name,
          input: parsedInput,
        };
        toolCalls.push(toolUse);
        contentBlocks.push(toolUse);
      }
    }

    return {
      content: choice?.message?.content ?? '',
      model: data.model,
      inputTokens: data.usage?.prompt_tokens ?? 0,
      outputTokens: data.usage?.completion_tokens ?? 0,
      stopReason: this.mapStopReason(choice?.finish_reason),
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      contentBlocks: contentBlocks.length > 0 ? contentBlocks : undefined,
    };
  }

  async *streamMessage(messages: ChatMessage[], options: SendMessageOptions): AsyncGenerator<StreamChunk> {
    const openaiMessages = this.formatMessages(messages, options);

    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: options.model,
        messages: openaiMessages,
        max_completion_tokens: options.maxTokens ?? 4096,
        stream: true,
        stream_options: { include_usage: true },
        ...(options.temperature !== undefined ? { temperature: options.temperature } : {}),
        ...(options.stopSequences?.length ? { stop: options.stopSequences } : {}),
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      yield { type: 'error', error: `OpenAI API error (${response.status}): ${error}` };
      return;
    }

    yield { type: 'message_start' };

    const reader = response.body?.getReader();
    if (!reader) {
      yield { type: 'error', error: 'No response body' };
      return;
    }

    const decoder = new TextDecoder();
    let buffer = '';
    let totalInputTokens = 0;
    let totalOutputTokens = 0;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || !trimmed.startsWith('data: ')) continue;
          const payload = trimmed.slice(6);
          if (payload === '[DONE]') continue;

          try {
            const chunk: OpenAIStreamChunk = JSON.parse(payload);
            const delta = chunk.choices?.[0]?.delta;
            if (delta?.content) {
              yield { type: 'content_delta', content: delta.content };
            }
            if (chunk.usage) {
              totalInputTokens = chunk.usage.prompt_tokens;
              totalOutputTokens = chunk.usage.completion_tokens;
            }
          } catch {
            // Skip malformed chunks
          }
        }
      }
    } finally {
      reader.releaseLock();
    }

    yield {
      type: 'message_stop',
      inputTokens: totalInputTokens,
      outputTokens: totalOutputTokens,
    };
  }

  getAvailableModels(): ModelInfo[] {
    return OPENAI_MODELS;
  }

  async validateApiKey(key: string): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/models`, {
        headers: { 'Authorization': `Bearer ${key}` },
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  estimateCost(inputTokens: number, outputTokens: number, model: string): number {
    const modelInfo = OPENAI_MODELS.find(m => m.id === model);
    if (!modelInfo) return 0;
    return (inputTokens / 1_000_000) * modelInfo.inputCostPer1M +
           (outputTokens / 1_000_000) * modelInfo.outputCostPer1M;
  }

  private formatMessages(messages: ChatMessage[], options: SendMessageOptions): OpenAIMessage[] {
    const result: OpenAIMessage[] = [];

    if (options.systemPrompt) {
      result.push({ role: 'system', content: options.systemPrompt });
    }

    for (const msg of messages) {
      if (msg.role === 'system') {
        result.push({ role: 'system', content: getMessageText(msg.content) });
      } else if (msg.role === 'user' && msg.toolResults?.length) {
        // Tool results go as separate 'tool' role messages in OpenAI
        for (const tr of msg.toolResults) {
          result.push({
            role: 'tool',
            content: tr.content,
            tool_call_id: tr.tool_use_id,
          });
        }
      } else if (msg.role === 'assistant' && typeof msg.content !== 'string') {
        // Assistant message with structured blocks — may contain tool_calls
        const toolUseBlocks = getToolUseBlocks(msg.content);
        const textContent = getMessageText(msg.content);

        if (toolUseBlocks.length > 0) {
          result.push({
            role: 'assistant',
            content: textContent || null,
            tool_calls: toolUseBlocks.map(tu => ({
              id: tu.id,
              type: 'function' as const,
              function: {
                name: tu.name,
                arguments: JSON.stringify(tu.input),
              },
            })),
          });
        } else {
          result.push({ role: 'assistant', content: textContent });
        }
      } else {
        result.push({
          role: msg.role,
          content: getMessageText(msg.content),
        });
      }
    }

    return result;
  }

  /** Convert our ToolDefinition[] to OpenAI format */
  private formatTools(tools: ToolDefinition[]): OpenAIToolDefinition[] {
    return tools.map(t => ({
      type: 'function' as const,
      function: {
        name: t.name,
        description: t.description,
        parameters: t.input_schema,
      },
    }));
  }

  /** Convert our ToolChoice to OpenAI format */
  private formatToolChoice(choice: ToolChoice): unknown {
    if (choice === 'auto') return 'auto';
    if (choice === 'any') return 'required';
    if (choice === 'none') return 'none';
    if (typeof choice === 'object') {
      return { type: 'function', function: { name: choice.name } };
    }
    return 'auto';
  }

  private mapStopReason(reason: string | null | undefined): ChatResponse['stopReason'] {
    switch (reason) {
      case 'stop': return 'end_turn';
      case 'length': return 'max_tokens';
      case 'tool_calls': return 'tool_use';
      default: return 'unknown';
    }
  }
}

export default OpenAIProvider;

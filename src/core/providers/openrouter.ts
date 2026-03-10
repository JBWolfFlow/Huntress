/**
 * OpenRouter Provider
 *
 * Single API key to access any model via OpenRouter's unified API.
 * Uses OpenAI-compatible endpoints.
 */

import type {
  ModelProvider,
  ChatMessage,
  ChatResponse,
  StreamChunk,
  SendMessageOptions,
  ModelInfo,
  ProviderConfig,
} from './types';
import { getMessageText } from './types';

const OPENROUTER_MODELS: ModelInfo[] = [
  {
    id: 'anthropic/claude-opus-4-6',
    displayName: 'Claude Opus 4.6 (via OpenRouter)',
    contextWindow: 200000,
    maxOutputTokens: 32000,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 15,
    outputCostPer1M: 75,
  },
  {
    id: 'anthropic/claude-sonnet-4-5-20250929',
    displayName: 'Claude Sonnet 4.5 (via OpenRouter)',
    contextWindow: 200000,
    maxOutputTokens: 16000,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 3,
    outputCostPer1M: 15,
  },
  {
    id: 'openai/gpt-4o',
    displayName: 'GPT-4o (via OpenRouter)',
    contextWindow: 128000,
    maxOutputTokens: 16384,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 2.50,
    outputCostPer1M: 10,
  },
  {
    id: 'google/gemini-2.5-pro',
    displayName: 'Gemini 2.5 Pro (via OpenRouter)',
    contextWindow: 1048576,
    maxOutputTokens: 65536,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 1.25,
    outputCostPer1M: 10,
  },
  {
    id: 'meta-llama/llama-3.1-70b-instruct',
    displayName: 'Llama 3.1 70B (via OpenRouter)',
    contextWindow: 131072,
    maxOutputTokens: 8192,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 0.52,
    outputCostPer1M: 0.75,
  },
];

interface OpenRouterMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export class OpenRouterProvider implements ModelProvider {
  readonly providerId = 'openrouter';
  readonly displayName = 'OpenRouter';
  private apiKey: string;
  private baseUrl: string;

  constructor(config: ProviderConfig) {
    if (!config.apiKey) {
      throw new Error('OpenRouter provider requires an API key');
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl ?? 'https://openrouter.ai/api/v1';
  }

  async sendMessage(messages: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
    const formattedMessages = this.formatMessages(messages, options);

    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
        'HTTP-Referer': 'https://huntress.app',
        'X-Title': 'Huntress AI Bug Bounty',
      },
      body: JSON.stringify({
        model: options.model,
        messages: formattedMessages,
        max_tokens: options.maxTokens ?? 4096,
        ...(options.temperature !== undefined ? { temperature: options.temperature } : {}),
        ...(options.stopSequences?.length ? { stop: options.stopSequences } : {}),
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`OpenRouter API error (${response.status}): ${error}`);
    }

    const data = await response.json();
    const choice = data.choices?.[0];

    return {
      content: choice?.message?.content ?? '',
      model: data.model ?? options.model,
      inputTokens: data.usage?.prompt_tokens ?? 0,
      outputTokens: data.usage?.completion_tokens ?? 0,
      stopReason: this.mapStopReason(choice?.finish_reason),
    };
  }

  async *streamMessage(messages: ChatMessage[], options: SendMessageOptions): AsyncGenerator<StreamChunk> {
    const formattedMessages = this.formatMessages(messages, options);

    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
        'HTTP-Referer': 'https://huntress.app',
        'X-Title': 'Huntress AI Bug Bounty',
      },
      body: JSON.stringify({
        model: options.model,
        messages: formattedMessages,
        max_tokens: options.maxTokens ?? 4096,
        stream: true,
        ...(options.temperature !== undefined ? { temperature: options.temperature } : {}),
        ...(options.stopSequences?.length ? { stop: options.stopSequences } : {}),
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      yield { type: 'error', error: `OpenRouter API error (${response.status}): ${error}` };
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
            const chunk = JSON.parse(payload);
            const delta = chunk.choices?.[0]?.delta;
            if (delta?.content) {
              yield { type: 'content_delta', content: delta.content };
            }
            if (chunk.usage) {
              totalInputTokens = chunk.usage.prompt_tokens ?? 0;
              totalOutputTokens = chunk.usage.completion_tokens ?? 0;
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
    return OPENROUTER_MODELS;
  }

  async validateApiKey(key: string): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/auth/key`, {
        headers: { 'Authorization': `Bearer ${key}` },
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  estimateCost(inputTokens: number, outputTokens: number, model: string): number {
    const modelInfo = OPENROUTER_MODELS.find(m => m.id === model);
    if (!modelInfo) return 0;
    return (inputTokens / 1_000_000) * modelInfo.inputCostPer1M +
           (outputTokens / 1_000_000) * modelInfo.outputCostPer1M;
  }

  private formatMessages(messages: ChatMessage[], options: SendMessageOptions): OpenRouterMessage[] {
    const result: OpenRouterMessage[] = [];

    if (options.systemPrompt) {
      result.push({ role: 'system', content: options.systemPrompt });
    }

    for (const msg of messages) {
      if (msg.role === 'system') {
        result.push({ role: 'system', content: getMessageText(msg.content) });
      } else if (msg.toolResults?.length) {
        // OpenRouter doesn't have native tool result messages — inline as text
        const toolText = msg.toolResults.map(tr => `[Tool Result] ${tr.content}`).join('\n');
        result.push({ role: 'user', content: toolText });
      } else {
        result.push({ role: msg.role, content: getMessageText(msg.content) });
      }
    }

    return result;
  }

  private mapStopReason(reason: string | null | undefined): ChatResponse['stopReason'] {
    switch (reason) {
      case 'stop': return 'end_turn';
      case 'length': return 'max_tokens';
      default: return 'unknown';
    }
  }
}

export default OpenRouterProvider;

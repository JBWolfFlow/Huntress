/**
 * Local Provider (Ollama)
 *
 * Connects to a local Ollama instance at localhost:11434.
 * No API key required. Supports any model installed locally.
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

const DEFAULT_MODELS: ModelInfo[] = [
  {
    id: 'llama3.1:70b',
    displayName: 'Llama 3.1 70B',
    contextWindow: 131072,
    maxOutputTokens: 8192,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 0,
    outputCostPer1M: 0,
  },
  {
    id: 'llama3.1:8b',
    displayName: 'Llama 3.1 8B',
    contextWindow: 131072,
    maxOutputTokens: 8192,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 0,
    outputCostPer1M: 0,
  },
  {
    id: 'mistral:latest',
    displayName: 'Mistral',
    contextWindow: 32768,
    maxOutputTokens: 8192,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 0,
    outputCostPer1M: 0,
  },
  {
    id: 'qwen2.5:72b',
    displayName: 'Qwen 2.5 72B',
    contextWindow: 131072,
    maxOutputTokens: 8192,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 0,
    outputCostPer1M: 0,
  },
];

interface OllamaMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface OllamaChatResponse {
  model: string;
  message: { role: string; content: string };
  done: boolean;
  total_duration?: number;
  prompt_eval_count?: number;
  eval_count?: number;
}

export class LocalProvider implements ModelProvider {
  readonly providerId = 'local';
  readonly displayName = 'Local (Ollama)';
  private baseUrl: string;
  private cachedModels: ModelInfo[] | null = null;

  constructor(config: ProviderConfig) {
    this.baseUrl = config.baseUrl ?? 'http://localhost:11434';
  }

  async sendMessage(messages: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
    const ollamaMessages = this.formatMessages(messages, options);

    const response = await fetch(`${this.baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: options.model,
        messages: ollamaMessages,
        stream: false,
        options: {
          num_predict: options.maxTokens ?? 4096,
          ...(options.temperature !== undefined ? { temperature: options.temperature } : {}),
          ...(options.stopSequences?.length ? { stop: options.stopSequences } : {}),
        },
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Ollama API error (${response.status}): ${error}`);
    }

    const data: OllamaChatResponse = await response.json();

    return {
      content: data.message?.content ?? '',
      model: data.model,
      inputTokens: data.prompt_eval_count ?? 0,
      outputTokens: data.eval_count ?? 0,
      stopReason: data.done ? 'end_turn' : 'unknown',
    };
  }

  async *streamMessage(messages: ChatMessage[], options: SendMessageOptions): AsyncGenerator<StreamChunk> {
    const ollamaMessages = this.formatMessages(messages, options);

    const response = await fetch(`${this.baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: options.model,
        messages: ollamaMessages,
        stream: true,
        options: {
          num_predict: options.maxTokens ?? 4096,
          ...(options.temperature !== undefined ? { temperature: options.temperature } : {}),
          ...(options.stopSequences?.length ? { stop: options.stopSequences } : {}),
        },
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      yield { type: 'error', error: `Ollama API error (${response.status}): ${error}` };
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
          if (!line.trim()) continue;
          try {
            const chunk: OllamaChatResponse = JSON.parse(line);
            if (chunk.message?.content) {
              yield { type: 'content_delta', content: chunk.message.content };
            }
            if (chunk.done) {
              totalInputTokens = chunk.prompt_eval_count ?? 0;
              totalOutputTokens = chunk.eval_count ?? 0;
            }
          } catch {
            // Skip malformed lines
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
    // Return cached results or defaults
    return this.cachedModels ?? DEFAULT_MODELS;
  }

  async validateApiKey(_key: string): Promise<boolean> {
    // Ollama doesn't use API keys; validate by checking if the server is running
    try {
      const response = await fetch(`${this.baseUrl}/api/tags`);
      if (response.ok) {
        // Cache available models from the server
        const data = await response.json();
        if (data.models && Array.isArray(data.models)) {
          this.cachedModels = data.models.map((m: { name: string; details?: { parameter_size?: string } }) => ({
            id: m.name,
            displayName: m.name,
            contextWindow: 131072,
            maxOutputTokens: 8192,
            supportsStreaming: true,
            supportsSystemPrompt: true,
            inputCostPer1M: 0,
            outputCostPer1M: 0,
          }));
        }
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  estimateCost(_inputTokens: number, _outputTokens: number, _model: string): number {
    return 0; // Local models are free
  }

  private formatMessages(messages: ChatMessage[], options: SendMessageOptions): OllamaMessage[] {
    const result: OllamaMessage[] = [];

    if (options.systemPrompt) {
      result.push({ role: 'system', content: options.systemPrompt });
    }

    for (const msg of messages) {
      if (msg.role === 'system') {
        result.push({ role: 'system', content: getMessageText(msg.content) });
      } else if (msg.toolResults?.length) {
        // Ollama doesn't support tool use natively — inline results as text
        const toolText = msg.toolResults.map(tr => `[Tool Result] ${tr.content}`).join('\n');
        result.push({ role: 'user', content: toolText });
      } else {
        result.push({ role: msg.role, content: getMessageText(msg.content) });
      }
    }

    return result;
  }
}

export default LocalProvider;

/**
 * Google AI Provider
 *
 * Supports Gemini 2.5 Pro and Flash models via the Google Generative AI API.
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
} from './types';
import { getMessageText } from './types';

const GOOGLE_MODELS: ModelInfo[] = [
  {
    id: 'gemini-2.5-pro',
    displayName: 'Gemini 2.5 Pro',
    contextWindow: 1048576,
    maxOutputTokens: 65536,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 1.25,
    outputCostPer1M: 10,
  },
  {
    id: 'gemini-2.5-flash',
    displayName: 'Gemini 2.5 Flash',
    contextWindow: 1048576,
    maxOutputTokens: 65536,
    supportsStreaming: true,
    supportsSystemPrompt: true,
    inputCostPer1M: 0.15,
    outputCostPer1M: 0.60,
  },
];

/** Minimal Google Generative AI types */
interface GoogleContent {
  role: 'user' | 'model';
  parts: Array<{ text: string }>;
}

interface GoogleCandidate {
  content: { role: string; parts: Array<{ text: string }> };
  finishReason: string;
}

interface GoogleResponse {
  candidates: GoogleCandidate[];
  usageMetadata?: {
    promptTokenCount: number;
    candidatesTokenCount: number;
    totalTokenCount: number;
  };
}

export class GoogleProvider implements ModelProvider {
  readonly providerId = 'google';
  readonly displayName = 'Google AI';
  private apiKey: string;
  private baseUrl: string;

  constructor(config: ProviderConfig) {
    if (!config.apiKey) {
      throw new Error('Google AI provider requires an API key');
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl ?? 'https://generativelanguage.googleapis.com/v1beta';
  }

  async sendMessage(messages: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
    const { contents, systemInstruction } = this.formatMessages(messages, options);

    const response = await fetch(
      `${this.baseUrl}/models/${options.model}:generateContent?key=${this.apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents,
          ...(systemInstruction ? { systemInstruction: { parts: [{ text: systemInstruction }] } } : {}),
          generationConfig: {
            maxOutputTokens: options.maxTokens ?? 4096,
            ...(options.temperature !== undefined ? { temperature: options.temperature } : {}),
            ...(options.stopSequences?.length ? { stopSequences: options.stopSequences } : {}),
          },
        }),
      }
    );

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Google AI API error (${response.status}): ${error}`);
    }

    const data: GoogleResponse = await response.json();
    const candidate = data.candidates?.[0];
    const text = candidate?.content?.parts?.map(p => p.text).join('') ?? '';

    return {
      content: text,
      model: options.model,
      inputTokens: data.usageMetadata?.promptTokenCount ?? 0,
      outputTokens: data.usageMetadata?.candidatesTokenCount ?? 0,
      stopReason: this.mapStopReason(candidate?.finishReason),
    };
  }

  async *streamMessage(messages: ChatMessage[], options: SendMessageOptions): AsyncGenerator<StreamChunk> {
    const { contents, systemInstruction } = this.formatMessages(messages, options);

    const response = await fetch(
      `${this.baseUrl}/models/${options.model}:streamGenerateContent?alt=sse&key=${this.apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents,
          ...(systemInstruction ? { systemInstruction: { parts: [{ text: systemInstruction }] } } : {}),
          generationConfig: {
            maxOutputTokens: options.maxTokens ?? 4096,
            ...(options.temperature !== undefined ? { temperature: options.temperature } : {}),
            ...(options.stopSequences?.length ? { stopSequences: options.stopSequences } : {}),
          },
        }),
      }
    );

    if (!response.ok) {
      const error = await response.text();
      yield { type: 'error', error: `Google AI API error (${response.status}): ${error}` };
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

          try {
            const chunk: GoogleResponse = JSON.parse(payload);
            const text = chunk.candidates?.[0]?.content?.parts?.map(p => p.text).join('');
            if (text) {
              yield { type: 'content_delta', content: text };
            }
            if (chunk.usageMetadata) {
              totalInputTokens = chunk.usageMetadata.promptTokenCount;
              totalOutputTokens = chunk.usageMetadata.candidatesTokenCount;
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
    return GOOGLE_MODELS;
  }

  async validateApiKey(key: string): Promise<boolean> {
    try {
      const response = await fetch(
        `${this.baseUrl}/models?key=${key}`
      );
      return response.ok;
    } catch {
      return false;
    }
  }

  estimateCost(inputTokens: number, outputTokens: number, model: string): number {
    const modelInfo = GOOGLE_MODELS.find(m => m.id === model);
    if (!modelInfo) return 0;
    return (inputTokens / 1_000_000) * modelInfo.inputCostPer1M +
           (outputTokens / 1_000_000) * modelInfo.outputCostPer1M;
  }

  private formatMessages(
    messages: ChatMessage[],
    options: SendMessageOptions
  ): { contents: GoogleContent[]; systemInstruction: string | undefined } {
    let systemInstruction = options.systemPrompt;
    const contents: GoogleContent[] = [];

    for (const msg of messages) {
      if (msg.role === 'system') {
        const text = getMessageText(msg.content);
        systemInstruction = systemInstruction
          ? `${systemInstruction}\n\n${text}`
          : text;
      } else {
        contents.push({
          role: msg.role === 'assistant' ? 'model' : 'user',
          parts: [{ text: getMessageText(msg.content) }],
        });
      }
    }

    return { contents, systemInstruction };
  }

  private mapStopReason(reason: string | undefined): ChatResponse['stopReason'] {
    switch (reason) {
      case 'STOP': return 'end_turn';
      case 'MAX_TOKENS': return 'max_tokens';
      default: return 'unknown';
    }
  }
}

export default GoogleProvider;

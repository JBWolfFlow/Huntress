/**
 * Model Provider Tests
 *
 * Tests all 5 providers with mock HTTP responses:
 * - AnthropicProvider (via SDK mock)
 * - OpenAIProvider (via fetch mock)
 * - GoogleProvider (via fetch mock)
 * - LocalProvider / Ollama (via fetch mock)
 * - OpenRouterProvider (via fetch mock)
 * - ProviderFactory (registry, creation, model lookup)
 *
 * No real API calls are made. All HTTP responses are mocked.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { ChatMessage, SendMessageOptions } from '../core/providers/types';

// ─── Helpers ────────────────────────────────────────────────────────────────

const testMessages: ChatMessage[] = [
  { role: 'user', content: 'Test message' },
];

const baseOptions: SendMessageOptions = {
  model: 'test-model',
  maxTokens: 100,
};

/** Create a mock fetch Response */
function mockFetchResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Create a mock SSE stream Response */
function mockSSEResponse(chunks: string[], status = 200): Response {
  const sseData = chunks.map(c => `data: ${c}`).join('\n') + '\ndata: [DONE]\n';
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(sseData));
      controller.close();
    },
  });
  return new Response(stream, {
    status,
    headers: { 'Content-Type': 'text/event-stream' },
  });
}

/** Create a mock NDJSON stream Response (for Ollama) */
function mockNDJSONResponse(chunks: unknown[]): Response {
  const ndjson = chunks.map(c => JSON.stringify(c)).join('\n') + '\n';
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(ndjson));
      controller.close();
    },
  });
  return new Response(stream, {
    status: 200,
    headers: { 'Content-Type': 'application/x-ndjson' },
  });
}

// ─── OpenAI Provider ────────────────────────────────────────────────────────

describe('OpenAIProvider', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch');
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it('should require an API key', async () => {
    const { OpenAIProvider } = await import('../core/providers/openai');
    expect(() => new OpenAIProvider({})).toThrow('requires an API key');
  });

  it('should have correct metadata', async () => {
    const { OpenAIProvider } = await import('../core/providers/openai');
    const provider = new OpenAIProvider({ apiKey: 'sk-test' });
    expect(provider.providerId).toBe('openai');
    expect(provider.displayName).toBe('OpenAI');
    expect(provider.supportsToolUse).toBe(true);
  });

  it('should list available models', async () => {
    const { OpenAIProvider } = await import('../core/providers/openai');
    const provider = new OpenAIProvider({ apiKey: 'sk-test' });
    const models = provider.getAvailableModels();
    expect(models.length).toBeGreaterThanOrEqual(3);

    const ids = models.map(m => m.id);
    expect(ids).toContain('gpt-4o');
    expect(ids).toContain('gpt-4o-mini');
    expect(ids).toContain('o3');
  });

  it('should estimate cost correctly', async () => {
    const { OpenAIProvider } = await import('../core/providers/openai');
    const provider = new OpenAIProvider({ apiKey: 'sk-test' });

    // GPT-4o: $2.50/1M input, $10/1M output
    const cost = provider.estimateCost(1_000_000, 1_000_000, 'gpt-4o');
    expect(cost).toBeCloseTo(12.5);
  });

  it('should return 0 cost for unknown model', async () => {
    const { OpenAIProvider } = await import('../core/providers/openai');
    const provider = new OpenAIProvider({ apiKey: 'sk-test' });
    expect(provider.estimateCost(1000, 1000, 'unknown-model')).toBe(0);
  });

  it('should send a message via fetch', async () => {
    const { OpenAIProvider } = await import('../core/providers/openai');
    const provider = new OpenAIProvider({ apiKey: 'sk-test' });

    fetchSpy.mockResolvedValueOnce(mockFetchResponse({
      id: 'chatcmpl-123',
      model: 'gpt-4o',
      choices: [{
        index: 0,
        message: { role: 'assistant', content: 'Hello from GPT-4o!' },
        finish_reason: 'stop',
      }],
      usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
    }));

    const response = await provider.sendMessage(testMessages, {
      ...baseOptions,
      model: 'gpt-4o',
    });

    expect(response.content).toBe('Hello from GPT-4o!');
    expect(response.model).toBe('gpt-4o');
    expect(response.inputTokens).toBe(10);
    expect(response.outputTokens).toBe(5);
    expect(response.stopReason).toBe('end_turn');

    // Verify the fetch call
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, options] = fetchSpy.mock.calls[0];
    expect(url).toContain('/chat/completions');
    const body = JSON.parse((options as RequestInit).body as string);
    expect(body.model).toBe('gpt-4o');
  });

  it('should handle tool calls in response', async () => {
    const { OpenAIProvider } = await import('../core/providers/openai');
    const provider = new OpenAIProvider({ apiKey: 'sk-test' });

    fetchSpy.mockResolvedValueOnce(mockFetchResponse({
      id: 'chatcmpl-456',
      model: 'gpt-4o',
      choices: [{
        index: 0,
        message: {
          role: 'assistant',
          content: null,
          tool_calls: [{
            id: 'call_abc',
            type: 'function',
            function: {
              name: 'run_command',
              arguments: '{"command":"curl https://example.com"}',
            },
          }],
        },
        finish_reason: 'tool_calls',
      }],
      usage: { prompt_tokens: 50, completion_tokens: 20, total_tokens: 70 },
    }));

    const response = await provider.sendMessage(testMessages, {
      ...baseOptions,
      model: 'gpt-4o',
    });

    expect(response.stopReason).toBe('tool_use');
    expect(response.toolCalls).toHaveLength(1);
    expect(response.toolCalls![0].name).toBe('run_command');
    expect(response.toolCalls![0].input).toEqual({ command: 'curl https://example.com' });
  });

  it('should throw on API error', async () => {
    const { OpenAIProvider } = await import('../core/providers/openai');
    const provider = new OpenAIProvider({ apiKey: 'sk-test' });

    fetchSpy.mockResolvedValueOnce(new Response('Unauthorized', { status: 401 }));

    await expect(provider.sendMessage(testMessages, baseOptions))
      .rejects.toThrow('OpenAI API error (401)');
  });

  it('should validate API key via /models endpoint', async () => {
    const { OpenAIProvider } = await import('../core/providers/openai');
    const provider = new OpenAIProvider({ apiKey: 'sk-test' });

    fetchSpy.mockResolvedValueOnce(mockFetchResponse({ data: [] }));
    expect(await provider.validateApiKey('sk-valid')).toBe(true);

    fetchSpy.mockResolvedValueOnce(new Response('', { status: 401 }));
    expect(await provider.validateApiKey('sk-invalid')).toBe(false);
  });

  it('should stream messages via SSE', async () => {
    const { OpenAIProvider } = await import('../core/providers/openai');
    const provider = new OpenAIProvider({ apiKey: 'sk-test' });

    fetchSpy.mockResolvedValueOnce(mockSSEResponse([
      JSON.stringify({ choices: [{ delta: { content: 'Hello' } }] }),
      JSON.stringify({ choices: [{ delta: { content: ' World' } }] }),
      JSON.stringify({ choices: [{ delta: {} }], usage: { prompt_tokens: 10, completion_tokens: 5 } }),
    ]));

    const chunks: string[] = [];
    let inputTokens = 0;
    let outputTokens = 0;

    for await (const chunk of provider.streamMessage(testMessages, { ...baseOptions, model: 'gpt-4o' })) {
      if (chunk.type === 'content_delta' && chunk.content) {
        chunks.push(chunk.content);
      }
      if (chunk.type === 'message_stop') {
        inputTokens = chunk.inputTokens ?? 0;
        outputTokens = chunk.outputTokens ?? 0;
      }
    }

    expect(chunks.join('')).toBe('Hello World');
    expect(inputTokens).toBe(10);
    expect(outputTokens).toBe(5);
  });

  it('should include system prompt in formatted messages', async () => {
    const { OpenAIProvider } = await import('../core/providers/openai');
    const provider = new OpenAIProvider({ apiKey: 'sk-test' });

    fetchSpy.mockResolvedValueOnce(mockFetchResponse({
      id: 'chatcmpl-sys',
      model: 'gpt-4o',
      choices: [{ index: 0, message: { role: 'assistant', content: 'OK' }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 20, completion_tokens: 1, total_tokens: 21 },
    }));

    await provider.sendMessage(testMessages, {
      ...baseOptions,
      model: 'gpt-4o',
      systemPrompt: 'You are a security tester.',
    });

    const body = JSON.parse((fetchSpy.mock.calls[0][1] as RequestInit).body as string);
    expect(body.messages[0]).toEqual({ role: 'system', content: 'You are a security tester.' });
  });
});

// ─── Google Provider ────────────────────────────────────────────────────────

describe('GoogleProvider', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch');
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it('should require an API key', async () => {
    const { GoogleProvider } = await import('../core/providers/google');
    expect(() => new GoogleProvider({})).toThrow('requires an API key');
  });

  it('should have correct metadata', async () => {
    const { GoogleProvider } = await import('../core/providers/google');
    const provider = new GoogleProvider({ apiKey: 'test-key' });
    expect(provider.providerId).toBe('google');
    expect(provider.displayName).toBe('Google AI');
  });

  it('should list Gemini models', async () => {
    const { GoogleProvider } = await import('../core/providers/google');
    const provider = new GoogleProvider({ apiKey: 'test-key' });
    const models = provider.getAvailableModels();
    const ids = models.map(m => m.id);
    expect(ids).toContain('gemini-2.5-pro');
    expect(ids).toContain('gemini-2.5-flash');
  });

  it('should estimate cost correctly', async () => {
    const { GoogleProvider } = await import('../core/providers/google');
    const provider = new GoogleProvider({ apiKey: 'test-key' });

    // Gemini 2.5 Pro: $1.25/1M input, $10/1M output
    const cost = provider.estimateCost(1_000_000, 1_000_000, 'gemini-2.5-pro');
    expect(cost).toBeCloseTo(11.25);
  });

  it('should send a message via Google API', async () => {
    const { GoogleProvider } = await import('../core/providers/google');
    const provider = new GoogleProvider({ apiKey: 'test-key' });

    fetchSpy.mockResolvedValueOnce(mockFetchResponse({
      candidates: [{
        content: { role: 'model', parts: [{ text: 'Hello from Gemini!' }] },
        finishReason: 'STOP',
      }],
      usageMetadata: { promptTokenCount: 15, candidatesTokenCount: 8, totalTokenCount: 23 },
    }));

    const response = await provider.sendMessage(testMessages, {
      ...baseOptions,
      model: 'gemini-2.5-pro',
    });

    expect(response.content).toBe('Hello from Gemini!');
    expect(response.inputTokens).toBe(15);
    expect(response.outputTokens).toBe(8);
    expect(response.stopReason).toBe('end_turn');

    // Verify URL includes model name and API key
    const url = fetchSpy.mock.calls[0][0] as string;
    expect(url).toContain('gemini-2.5-pro:generateContent');
    expect(url).toContain('key=test-key');
  });

  it('should throw on API error', async () => {
    const { GoogleProvider } = await import('../core/providers/google');
    const provider = new GoogleProvider({ apiKey: 'test-key' });

    fetchSpy.mockResolvedValueOnce(new Response('Bad Request', { status: 400 }));

    await expect(provider.sendMessage(testMessages, { ...baseOptions, model: 'gemini-2.5-pro' }))
      .rejects.toThrow('Google AI API error (400)');
  });

  it('should validate API key via /models endpoint', async () => {
    const { GoogleProvider } = await import('../core/providers/google');
    const provider = new GoogleProvider({ apiKey: 'test-key' });

    fetchSpy.mockResolvedValueOnce(mockFetchResponse({ models: [] }));
    expect(await provider.validateApiKey('valid-key')).toBe(true);

    fetchSpy.mockResolvedValueOnce(new Response('', { status: 403 }));
    expect(await provider.validateApiKey('invalid-key')).toBe(false);
  });

  it('should handle system prompt via systemInstruction', async () => {
    const { GoogleProvider } = await import('../core/providers/google');
    const provider = new GoogleProvider({ apiKey: 'test-key' });

    fetchSpy.mockResolvedValueOnce(mockFetchResponse({
      candidates: [{ content: { role: 'model', parts: [{ text: 'OK' }] }, finishReason: 'STOP' }],
      usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 1, totalTokenCount: 11 },
    }));

    await provider.sendMessage(testMessages, {
      ...baseOptions,
      model: 'gemini-2.5-pro',
      systemPrompt: 'You are a security tester.',
    });

    const body = JSON.parse((fetchSpy.mock.calls[0][1] as RequestInit).body as string);
    expect(body.systemInstruction).toEqual({ parts: [{ text: 'You are a security tester.' }] });
  });

  it('should stream via SSE', async () => {
    const { GoogleProvider } = await import('../core/providers/google');
    const provider = new GoogleProvider({ apiKey: 'test-key' });

    fetchSpy.mockResolvedValueOnce(mockSSEResponse([
      JSON.stringify({
        candidates: [{ content: { role: 'model', parts: [{ text: 'Hello' }] }, finishReason: null }],
      }),
      JSON.stringify({
        candidates: [{ content: { role: 'model', parts: [{ text: ' World' }] }, finishReason: 'STOP' }],
        usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5, totalTokenCount: 15 },
      }),
    ]));

    const chunks: string[] = [];
    for await (const chunk of provider.streamMessage(testMessages, { ...baseOptions, model: 'gemini-2.5-pro' })) {
      if (chunk.type === 'content_delta' && chunk.content) {
        chunks.push(chunk.content);
      }
    }

    expect(chunks.join('')).toBe('Hello World');
  });
});

// ─── Local Provider (Ollama) ────────────────────────────────────────────────

describe('LocalProvider', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch');
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it('should not require an API key', async () => {
    const { LocalProvider } = await import('../core/providers/local');
    const provider = new LocalProvider({});
    expect(provider.providerId).toBe('local');
    expect(provider.displayName).toBe('Local (Ollama)');
  });

  it('should list default models', async () => {
    const { LocalProvider } = await import('../core/providers/local');
    const provider = new LocalProvider({});
    const models = provider.getAvailableModels();
    expect(models.length).toBeGreaterThanOrEqual(3);

    const ids = models.map(m => m.id);
    expect(ids).toContain('llama3.1:70b');
    expect(ids).toContain('llama3.1:8b');
    expect(ids).toContain('mistral:latest');
  });

  it('should always return 0 cost', async () => {
    const { LocalProvider } = await import('../core/providers/local');
    const provider = new LocalProvider({});
    expect(provider.estimateCost(1_000_000, 1_000_000, 'llama3.1:70b')).toBe(0);
  });

  it('should send a message via Ollama API', async () => {
    const { LocalProvider } = await import('../core/providers/local');
    const provider = new LocalProvider({});

    fetchSpy.mockResolvedValueOnce(mockFetchResponse({
      model: 'llama3.1:70b',
      message: { role: 'assistant', content: 'Hello from Llama!' },
      done: true,
      prompt_eval_count: 20,
      eval_count: 12,
    }));

    const response = await provider.sendMessage(testMessages, {
      ...baseOptions,
      model: 'llama3.1:70b',
    });

    expect(response.content).toBe('Hello from Llama!');
    expect(response.model).toBe('llama3.1:70b');
    expect(response.inputTokens).toBe(20);
    expect(response.outputTokens).toBe(12);
    expect(response.stopReason).toBe('end_turn');

    // Verify Ollama-specific request format
    const body = JSON.parse((fetchSpy.mock.calls[0][1] as RequestInit).body as string);
    expect(body.stream).toBe(false);
    expect(body.model).toBe('llama3.1:70b');
  });

  it('should throw on API error', async () => {
    const { LocalProvider } = await import('../core/providers/local');
    const provider = new LocalProvider({});

    fetchSpy.mockResolvedValueOnce(new Response('Model not found', { status: 404 }));

    await expect(provider.sendMessage(testMessages, { ...baseOptions, model: 'nonexistent' }))
      .rejects.toThrow('Ollama API error (404)');
  });

  it('should validate by checking server availability', async () => {
    const { LocalProvider } = await import('../core/providers/local');
    const provider = new LocalProvider({});

    fetchSpy.mockResolvedValueOnce(mockFetchResponse({
      models: [{ name: 'llama3.1:70b' }, { name: 'mistral:latest' }],
    }));
    expect(await provider.validateApiKey('')).toBe(true);

    fetchSpy.mockRejectedValueOnce(new Error('Connection refused'));
    expect(await provider.validateApiKey('')).toBe(false);
  });

  it('should cache models from server on validateApiKey', async () => {
    const { LocalProvider } = await import('../core/providers/local');
    const provider = new LocalProvider({});

    fetchSpy.mockResolvedValueOnce(mockFetchResponse({
      models: [
        { name: 'custom-model:latest' },
        { name: 'llama3.1:70b' },
      ],
    }));

    await provider.validateApiKey('');
    const models = provider.getAvailableModels();
    const ids = models.map(m => m.id);
    expect(ids).toContain('custom-model:latest');
    expect(ids).toContain('llama3.1:70b');
  });

  it('should stream via NDJSON', async () => {
    const { LocalProvider } = await import('../core/providers/local');
    const provider = new LocalProvider({});

    fetchSpy.mockResolvedValueOnce(mockNDJSONResponse([
      { model: 'llama3.1:70b', message: { role: 'assistant', content: 'Hello' }, done: false },
      { model: 'llama3.1:70b', message: { role: 'assistant', content: ' World' }, done: false },
      { model: 'llama3.1:70b', message: { role: 'assistant', content: '' }, done: true, prompt_eval_count: 10, eval_count: 5 },
    ]));

    const chunks: string[] = [];
    let inputTokens = 0;
    let outputTokens = 0;

    for await (const chunk of provider.streamMessage(testMessages, { ...baseOptions, model: 'llama3.1:70b' })) {
      if (chunk.type === 'content_delta' && chunk.content) {
        chunks.push(chunk.content);
      }
      if (chunk.type === 'message_stop') {
        inputTokens = chunk.inputTokens ?? 0;
        outputTokens = chunk.outputTokens ?? 0;
      }
    }

    expect(chunks.join('')).toBe('Hello World');
    expect(inputTokens).toBe(10);
    expect(outputTokens).toBe(5);
  });

  it('should include system prompt in formatted messages', async () => {
    const { LocalProvider } = await import('../core/providers/local');
    const provider = new LocalProvider({});

    fetchSpy.mockResolvedValueOnce(mockFetchResponse({
      model: 'llama3.1:70b',
      message: { role: 'assistant', content: 'OK' },
      done: true,
    }));

    await provider.sendMessage(testMessages, {
      ...baseOptions,
      model: 'llama3.1:70b',
      systemPrompt: 'You are a security tester.',
    });

    const body = JSON.parse((fetchSpy.mock.calls[0][1] as RequestInit).body as string);
    expect(body.messages[0]).toEqual({ role: 'system', content: 'You are a security tester.' });
  });
});

// ─── OpenRouter Provider ────────────────────────────────────────────────────

describe('OpenRouterProvider', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch');
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it('should require an API key', async () => {
    const { OpenRouterProvider } = await import('../core/providers/openrouter');
    expect(() => new OpenRouterProvider({})).toThrow('requires an API key');
  });

  it('should have correct metadata', async () => {
    const { OpenRouterProvider } = await import('../core/providers/openrouter');
    const provider = new OpenRouterProvider({ apiKey: 'sk-or-test' });
    expect(provider.providerId).toBe('openrouter');
    expect(provider.displayName).toBe('OpenRouter');
  });

  it('should list models from multiple providers', async () => {
    const { OpenRouterProvider } = await import('../core/providers/openrouter');
    const provider = new OpenRouterProvider({ apiKey: 'sk-or-test' });
    const models = provider.getAvailableModels();
    const ids = models.map(m => m.id);

    expect(ids).toContain('anthropic/claude-opus-4-6');
    expect(ids).toContain('openai/gpt-4o');
    expect(ids).toContain('google/gemini-2.5-pro');
    expect(ids).toContain('meta-llama/llama-3.1-70b-instruct');
  });

  it('should estimate cost correctly', async () => {
    const { OpenRouterProvider } = await import('../core/providers/openrouter');
    const provider = new OpenRouterProvider({ apiKey: 'sk-or-test' });

    // Claude Opus via OpenRouter: $15/1M input, $75/1M output
    const cost = provider.estimateCost(1_000_000, 1_000_000, 'anthropic/claude-opus-4-6');
    expect(cost).toBeCloseTo(90);
  });

  it('should send a message via OpenRouter API', async () => {
    const { OpenRouterProvider } = await import('../core/providers/openrouter');
    const provider = new OpenRouterProvider({ apiKey: 'sk-or-test' });

    fetchSpy.mockResolvedValueOnce(mockFetchResponse({
      id: 'gen-123',
      model: 'anthropic/claude-opus-4-6',
      choices: [{
        index: 0,
        message: { role: 'assistant', content: 'Hello from OpenRouter!' },
        finish_reason: 'stop',
      }],
      usage: { prompt_tokens: 25, completion_tokens: 10, total_tokens: 35 },
    }));

    const response = await provider.sendMessage(testMessages, {
      ...baseOptions,
      model: 'anthropic/claude-opus-4-6',
    });

    expect(response.content).toBe('Hello from OpenRouter!');
    expect(response.inputTokens).toBe(25);
    expect(response.outputTokens).toBe(10);
    expect(response.stopReason).toBe('end_turn');

    // Verify OpenRouter-specific headers
    const headers = (fetchSpy.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(headers['Authorization']).toBe('Bearer sk-or-test');
    expect(headers['HTTP-Referer']).toBe('https://huntress.app');
    expect(headers['X-Title']).toBe('Huntress AI Bug Bounty');
  });

  it('should throw on API error', async () => {
    const { OpenRouterProvider } = await import('../core/providers/openrouter');
    const provider = new OpenRouterProvider({ apiKey: 'sk-or-test' });

    fetchSpy.mockResolvedValueOnce(new Response('Rate limited', { status: 429 }));

    await expect(provider.sendMessage(testMessages, baseOptions))
      .rejects.toThrow('OpenRouter API error (429)');
  });

  it('should validate API key via /auth/key endpoint', async () => {
    const { OpenRouterProvider } = await import('../core/providers/openrouter');
    const provider = new OpenRouterProvider({ apiKey: 'sk-or-test' });

    fetchSpy.mockResolvedValueOnce(mockFetchResponse({ data: { label: 'Test Key' } }));
    expect(await provider.validateApiKey('sk-or-valid')).toBe(true);

    fetchSpy.mockResolvedValueOnce(new Response('', { status: 401 }));
    expect(await provider.validateApiKey('sk-or-invalid')).toBe(false);
  });

  it('should stream via SSE', async () => {
    const { OpenRouterProvider } = await import('../core/providers/openrouter');
    const provider = new OpenRouterProvider({ apiKey: 'sk-or-test' });

    fetchSpy.mockResolvedValueOnce(mockSSEResponse([
      JSON.stringify({ choices: [{ delta: { content: 'Hello' } }] }),
      JSON.stringify({ choices: [{ delta: { content: ' World' } }] }),
      JSON.stringify({ choices: [{ delta: {} }], usage: { prompt_tokens: 15, completion_tokens: 8 } }),
    ]));

    const chunks: string[] = [];
    for await (const chunk of provider.streamMessage(testMessages, { ...baseOptions, model: 'openai/gpt-4o' })) {
      if (chunk.type === 'content_delta' && chunk.content) {
        chunks.push(chunk.content);
      }
    }

    expect(chunks.join('')).toBe('Hello World');
  });
});

// ─── Anthropic Provider ─────────────────────────────────────────────────────

describe('AnthropicProvider', () => {
  it('should require an API key', async () => {
    const { AnthropicProvider } = await import('../core/providers/anthropic');
    expect(() => new AnthropicProvider({})).toThrow('requires an API key');
  });

  it('should have correct metadata', async () => {
    const { AnthropicProvider } = await import('../core/providers/anthropic');
    const provider = new AnthropicProvider({ apiKey: 'sk-ant-test' });
    expect(provider.providerId).toBe('anthropic');
    expect(provider.displayName).toBe('Anthropic');
    expect(provider.supportsToolUse).toBe(true);
  });

  it('should list Claude models', async () => {
    const { AnthropicProvider } = await import('../core/providers/anthropic');
    const provider = new AnthropicProvider({ apiKey: 'sk-ant-test' });
    const models = provider.getAvailableModels();
    const ids = models.map(m => m.id);

    expect(ids).toContain('claude-opus-4-6');
    expect(ids).toContain('claude-sonnet-4-5-20250929');
    expect(ids).toContain('claude-haiku-4-5-20251001');
  });

  it('should estimate cost correctly', async () => {
    const { AnthropicProvider } = await import('../core/providers/anthropic');
    const provider = new AnthropicProvider({ apiKey: 'sk-ant-test' });

    // Opus: $15/1M input, $75/1M output
    const cost = provider.estimateCost(1_000_000, 1_000_000, 'claude-opus-4-6');
    expect(cost).toBeCloseTo(90);

    // Haiku: $0.80/1M input, $4/1M output
    const haikuCost = provider.estimateCost(1_000_000, 1_000_000, 'claude-haiku-4-5-20251001');
    expect(haikuCost).toBeCloseTo(4.8);
  });

  it('should fall back to non-zero (Opus-tier) cost estimate for unknown model', async () => {
    // P1-1 (2026-05-02): old behavior returned $0 which silently broke
    // budget enforcement. Now falls back to conservative Opus rates so an
    // unknown future model ID never silently masks real spend.
    // See src/tests/p1_1_xbow_cost_estimate.test.ts for the full matrix.
    const { AnthropicProvider } = await import('../core/providers/anthropic');
    const provider = new AnthropicProvider({ apiKey: 'sk-ant-test' });
    const cost = provider.estimateCost(1000, 1000, 'unknown-model');
    expect(cost).toBeGreaterThan(0);
    // 1K input + 1K output × Opus rates ($15 + $75 per Mtok) = $0.090
    expect(cost).toBeCloseTo(0.090, 4);
  });

  it('should have correct model context windows', async () => {
    const { AnthropicProvider } = await import('../core/providers/anthropic');
    const provider = new AnthropicProvider({ apiKey: 'sk-ant-test' });
    const models = provider.getAvailableModels();

    const opus = models.find(m => m.id === 'claude-opus-4-6');
    expect(opus?.contextWindow).toBe(200000);
    expect(opus?.maxOutputTokens).toBe(32000);
    expect(opus?.supportsStreaming).toBe(true);
    expect(opus?.supportsSystemPrompt).toBe(true);
  });
});

// ─── Provider Factory ───────────────────────────────────────────────────────

describe('ProviderFactory', () => {
  it('should register all 5 default providers', async () => {
    const { ProviderFactory } = await import('../core/providers/provider_factory');
    const factory = new ProviderFactory();
    const ids = factory.listProviderIds();

    expect(ids).toContain('anthropic');
    expect(ids).toContain('openai');
    expect(ids).toContain('google');
    expect(ids).toContain('local');
    expect(ids).toContain('openrouter');
    expect(ids).toHaveLength(5);
  });

  it('should create provider instances with API keys', async () => {
    const { ProviderFactory } = await import('../core/providers/provider_factory');
    const factory = new ProviderFactory();

    const openai = factory.create('openai', { apiKey: 'sk-test' });
    expect(openai.providerId).toBe('openai');

    const google = factory.create('google', { apiKey: 'test-key' });
    expect(google.providerId).toBe('google');

    const local = factory.create('local', {});
    expect(local.providerId).toBe('local');
  });

  it('should throw on missing API key for providers that require it', async () => {
    const { ProviderFactory } = await import('../core/providers/provider_factory');
    const factory = new ProviderFactory();

    expect(() => factory.create('openai', {})).toThrow('requires an API key');
    expect(() => factory.create('google', {})).toThrow('requires an API key');
    expect(() => factory.create('openrouter', {})).toThrow('requires an API key');
  });

  it('should not require API key for local provider', async () => {
    const { ProviderFactory } = await import('../core/providers/provider_factory');
    const factory = new ProviderFactory();

    const local = factory.create('local', {});
    expect(local.providerId).toBe('local');
  });

  it('should throw on unknown provider', async () => {
    const { ProviderFactory } = await import('../core/providers/provider_factory');
    const factory = new ProviderFactory();

    expect(() => factory.create('nonexistent', {})).toThrow('Unknown provider: nonexistent');
  });

  it('should list all providers with metadata', async () => {
    const { ProviderFactory } = await import('../core/providers/provider_factory');
    const factory = new ProviderFactory();
    const providers = factory.listProviders();

    expect(providers).toHaveLength(5);

    const anthropic = providers.find(p => p.providerId === 'anthropic');
    expect(anthropic?.displayName).toBe('Anthropic');
    expect(anthropic?.requiresApiKey).toBe(true);
    expect(anthropic?.models.length).toBeGreaterThan(0);

    const local = providers.find(p => p.providerId === 'local');
    expect(local?.requiresApiKey).toBe(false);
  });

  it('should list all models across providers', async () => {
    const { ProviderFactory } = await import('../core/providers/provider_factory');
    const factory = new ProviderFactory();
    const allModels = factory.listAllModels();

    // Should have models from all providers
    expect(allModels.length).toBeGreaterThanOrEqual(10);

    // Each model should have a providerId
    const providerIds = new Set(allModels.map(m => m.providerId));
    expect(providerIds).toContain('anthropic');
    expect(providerIds).toContain('openai');
    expect(providerIds).toContain('google');
    expect(providerIds).toContain('local');
    expect(providerIds).toContain('openrouter');
  });

  it('should find provider for a given model', async () => {
    const { ProviderFactory } = await import('../core/providers/provider_factory');
    const factory = new ProviderFactory();

    expect(factory.findProviderForModel('gpt-4o')).toBe('openai');
    expect(factory.findProviderForModel('claude-opus-4-6')).toBe('anthropic');
    expect(factory.findProviderForModel('gemini-2.5-pro')).toBe('google');
    expect(factory.findProviderForModel('llama3.1:70b')).toBe('local');
    expect(factory.findProviderForModel('anthropic/claude-opus-4-6')).toBe('openrouter');
    expect(factory.findProviderForModel('nonexistent-model')).toBeUndefined();
  });

  it('should check if provider exists', async () => {
    const { ProviderFactory } = await import('../core/providers/provider_factory');
    const factory = new ProviderFactory();

    expect(factory.has('openai')).toBe(true);
    expect(factory.has('nonexistent')).toBe(false);
  });

  it('should return singleton from getProviderFactory', async () => {
    const { getProviderFactory } = await import('../core/providers/provider_factory');
    const f1 = getProviderFactory();
    const f2 = getProviderFactory();
    expect(f1).toBe(f2);
  });
});

// ─── Type Helper Functions ──────────────────────────────────────────────────

describe('Type Helper Functions', () => {
  it('should extract text from string content', async () => {
    const { getMessageText } = await import('../core/providers/types');
    expect(getMessageText('Hello')).toBe('Hello');
  });

  it('should extract text from content blocks', async () => {
    const { getMessageText } = await import('../core/providers/types');
    expect(getMessageText([
      { type: 'text', text: 'Hello' },
      { type: 'tool_use', id: 'tool_1', name: 'test', input: {} },
      { type: 'text', text: ' World' },
    ])).toBe('Hello World');
  });

  it('should extract tool use blocks', async () => {
    const { getToolUseBlocks } = await import('../core/providers/types');

    const blocks = getToolUseBlocks([
      { type: 'text', text: 'Thinking...' },
      { type: 'tool_use', id: 'tool_1', name: 'run_command', input: { cmd: 'ls' } },
      { type: 'tool_use', id: 'tool_2', name: 'stop_hunting', input: { reason: 'done' } },
    ]);

    expect(blocks).toHaveLength(2);
    expect(blocks[0].name).toBe('run_command');
    expect(blocks[1].name).toBe('stop_hunting');
  });

  it('should return empty array for string content', async () => {
    const { getToolUseBlocks } = await import('../core/providers/types');
    expect(getToolUseBlocks('Hello')).toEqual([]);
  });
});

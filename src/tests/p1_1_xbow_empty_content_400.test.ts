/**
 * P1-1 v6 — Empty content 400 regression
 *
 * Bug observed 2026-05-02 during the second XBOW benchmark run: challenges
 * 1, 2, and 3 all errored out (XBEN-005-24 jwt-hunter, XBEN-006-24
 * sqli-hunter, XBEN-009-24 ssti-hunter) with the same pattern — 5+ consecutive
 * 400 Bad Request from Anthropic's /v1/messages endpoint, then react_loop's
 * 5-errors-in-60s rule fires and the challenge is marked ERROR.
 *
 * Root cause: when Anthropic's API returns a response with no tool calls
 * AND empty text content (rare but happens — extended thinking blocks
 * filtered to empty string, or response truncation), react_loop pushed
 * `{ role: 'assistant', content: '' }` to history. Anthropic rejects
 * empty assistant content with 400. Once the empty turn is in history,
 * EVERY retry replays it → another 400 → 5 errors → loop stops.
 *
 * Two-layer fix:
 *   1. react_loop.ts:442-449 substitutes a placeholder when content empty
 *   2. AnthropicProvider.formatMessages sanitizes any empty text/content
 *      block at the API boundary (belt-and-suspenders)
 *
 * These tests pin both layers so the bug can't regress.
 */

import { describe, it, expect } from 'vitest';
import { AnthropicProvider } from '../core/providers/anthropic';
import type { ChatMessage, ContentBlock } from '../core/providers/types';

// We test formatMessages indirectly via the public API by intercepting
// the underlying SDK. Easier: cast and reach into the private method.
const provider = new AnthropicProvider({ apiKey: 'sk-ant-test-key-not-used' });
type Internal = { formatMessages: (m: ChatMessage[], o: { systemPrompt?: string }) => {
  systemPrompt: string | undefined;
  anthropicMessages: Array<{ role: string; content: unknown }>;
} };
const fmt = (provider as unknown as Internal).formatMessages.bind(provider);

describe('AnthropicProvider.formatMessages — empty content sanitization', () => {
  it('replaces empty plain-string assistant content with placeholder', () => {
    // This is the EXACT shape react_loop.ts:446-449 pushed before the v6 fix.
    const { anthropicMessages } = fmt([
      { role: 'user', content: 'hi' },
      { role: 'assistant', content: '' }, // ← would 400 without sanitization
      { role: 'user', content: 'continue' },
    ], {});

    const assistant = anthropicMessages.find(m => m.role === 'assistant');
    expect(assistant).toBeDefined();
    expect(assistant!.content).not.toBe('');
    expect(typeof assistant!.content).toBe('string');
    expect((assistant!.content as string).length).toBeGreaterThan(0);
  });

  it('replaces whitespace-only assistant content with placeholder', () => {
    const { anthropicMessages } = fmt([
      { role: 'user', content: 'hi' },
      { role: 'assistant', content: '   \n  \t  ' },
      { role: 'user', content: 'continue' },
    ], {});

    const assistant = anthropicMessages.find(m => m.role === 'assistant');
    expect((assistant!.content as string).trim().length).toBeGreaterThan(0);
  });

  it('preserves non-empty assistant content untouched', () => {
    const { anthropicMessages } = fmt([
      { role: 'user', content: 'hi' },
      { role: 'assistant', content: 'I will check the page now.' },
    ], {});

    const assistant = anthropicMessages.find(m => m.role === 'assistant');
    expect(assistant!.content).toBe('I will check the page now.');
  });

  it('replaces empty text blocks inside structured assistant content', () => {
    const blocks: ContentBlock[] = [
      { type: 'text', text: '' }, // ← would 400 without sanitization
      { type: 'tool_use', id: 'tu1', name: 'execute_command', input: { command: 'ls' } },
    ];
    const { anthropicMessages } = fmt([
      { role: 'assistant', content: blocks },
    ], {});

    const assistant = anthropicMessages.find(m => m.role === 'assistant');
    const arr = assistant!.content as Array<{ type: string; text?: string }>;
    const textBlock = arr.find(b => b.type === 'text');
    expect(textBlock!.text).not.toBe('');
    expect(textBlock!.text!.length).toBeGreaterThan(0);
    // tool_use block must still pass through
    expect(arr.find(b => b.type === 'tool_use')).toBeDefined();
  });

  it('handles assistant content with ZERO blocks by injecting a placeholder', () => {
    const { anthropicMessages } = fmt([
      { role: 'assistant', content: [] }, // empty array — would 400
    ], {});

    const assistant = anthropicMessages.find(m => m.role === 'assistant');
    const arr = assistant!.content as unknown[];
    expect(arr.length).toBeGreaterThan(0);
  });

  it('replaces empty user plain-text content with placeholder', () => {
    const { anthropicMessages } = fmt([
      { role: 'user', content: '' },
    ], {});

    const user = anthropicMessages.find(m => m.role === 'user');
    expect(user!.content).not.toBe('');
  });

  it('does not mangle tool_result content (must preserve agent output verbatim)', () => {
    const { anthropicMessages } = fmt([
      {
        role: 'user',
        content: '',
        toolResults: [
          { tool_use_id: 'tu1', content: 'HTTP/1.1 200 OK\nContent-Type: text/html', is_error: false },
        ],
      },
    ], {});

    const user = anthropicMessages.find(m => m.role === 'user');
    const arr = user!.content as Array<{ type: string; tool_use_id?: string; content?: string }>;
    expect(arr[0].type).toBe('tool_result');
    expect(arr[0].content).toBe('HTTP/1.1 200 OK\nContent-Type: text/html');
  });

  it('replaces empty tool_result string content with placeholder (defense)', () => {
    // If a tool returned empty stdout, that string would also 400 the API.
    const { anthropicMessages } = fmt([
      {
        role: 'user',
        content: '',
        toolResults: [
          { tool_use_id: 'tu1', content: '', is_error: false },
        ],
      },
    ], {});

    const user = anthropicMessages.find(m => m.role === 'user');
    const arr = user!.content as Array<{ type: string; content?: string }>;
    expect(arr[0].content).not.toBe('');
    expect(arr[0].content!.length).toBeGreaterThan(0);
  });
});

/**
 * P1-1 v7 — Orphan tool_use 400 cascade regression
 *
 * Bug observed 2026-05-02 during the third XBOW benchmark attempt: 30+
 * Anthropic /v1/messages 400 Bad Request errors per run. Empty-content
 * cascade was already fixed in v6, but a separate orphan-tool_use bug
 * remained.
 *
 * Root cause (research agent A confirmed): when the ReactLoop's tool-
 * processing for-loop (react_loop.ts ~502) breaks early — tool_call_limit,
 * identical_toolcall_loop, stop_hunting, capture_complete, capture_failed,
 * or any throw caught by the outer try — the assistant message at line ~494
 * has ALL tool_use blocks already pushed to history, but `toolResults`
 * only contains entries for the tool_use blocks processed BEFORE the break.
 * The next API call then sends an assistant turn with N tool_use blocks
 * but a user turn with K<N tool_results → Anthropic rejects with 400
 * "tool_use_id X is missing tool_result". Once orphaned, every retry
 * replays the broken history → the 5-errors-in-60s rule fires and the
 * challenge is marked ERROR.
 *
 * The fix: react_loop's break paths now call fillMissingToolResults()
 * which generates is_error=true tool_result placeholders for any unfulfilled
 * tool_use_ids before pushing the user message. The catch block also
 * inspects the last assistant message and synthesizes tool_results when
 * needed instead of pushing a plain-text user message that would orphan
 * tool_use blocks.
 *
 * These tests pin the invariant: every assistant turn with tool_use blocks
 * must be followed by a user turn with tool_result blocks for ALL of those
 * tool_use_ids.
 */

import { describe, it, expect } from 'vitest';
import { AnthropicProvider } from '../core/providers/anthropic';
import type { ChatMessage, ContentBlock, ToolResultBlock } from '../core/providers/types';

const provider = new AnthropicProvider({ apiKey: 'sk-ant-test-key' });
type Internal = { formatMessages: (m: ChatMessage[], o: { systemPrompt?: string }) => {
  systemPrompt: string | undefined;
  anthropicMessages: Array<{ role: string; content: unknown }>;
} };
const fmt = (provider as unknown as Internal).formatMessages.bind(provider);

/**
 * Verify the tool_use ↔ tool_result invariant for an assistant→user pair.
 * Returns { valid: true } or { valid: false, missing: [...] }.
 */
function verifyToolUseInvariant(
  messages: ChatMessage[],
): { valid: boolean; missing: string[] } {
  const formatted = fmt(messages, {}).anthropicMessages;
  for (let i = 0; i < formatted.length - 1; i++) {
    const cur = formatted[i];
    if (cur.role !== 'assistant' || !Array.isArray(cur.content)) continue;

    const toolUseIds = (cur.content as Array<{ type: string; id?: string }>)
      .filter(b => b.type === 'tool_use')
      .map(b => b.id!);
    if (toolUseIds.length === 0) continue;

    const next = formatted[i + 1];
    if (next.role !== 'user' || !Array.isArray(next.content)) {
      return { valid: false, missing: toolUseIds };
    }

    const fulfilled = new Set(
      (next.content as Array<{ type: string; tool_use_id?: string }>)
        .filter(b => b.type === 'tool_result')
        .map(b => b.tool_use_id!)
    );
    const missing = toolUseIds.filter(id => !fulfilled.has(id));
    if (missing.length > 0) return { valid: false, missing };
  }
  return { valid: true, missing: [] };
}

// Test fixtures: simulate the conversation history shapes that react_loop
// produces. Using formatMessages as a proxy to verify Anthropic API would
// accept the resulting request.

describe('Anthropic tool_use ↔ tool_result invariant', () => {
  it('GOOD: 1 tool_use followed by 1 tool_result is valid', () => {
    const blocks: ContentBlock[] = [
      { type: 'text', text: 'Let me check.' },
      { type: 'tool_use', id: 'tu1', name: 'execute_command', input: {} },
    ];
    const toolResults: ToolResultBlock[] = [
      { type: 'tool_result', tool_use_id: 'tu1', content: 'ok' },
    ];
    const result = verifyToolUseInvariant([
      { role: 'user', content: 'do it' },
      { role: 'assistant', content: blocks },
      { role: 'user', content: '', toolResults },
    ]);
    expect(result.valid).toBe(true);
  });

  it('BAD: assistant with 3 tool_use but only 1 tool_result is INVALID', () => {
    // This is the EXACT shape react_loop produced before the v7 fix when
    // tool_call_limit hit after processing tool 1 of 3.
    const blocks: ContentBlock[] = [
      { type: 'tool_use', id: 'tu1', name: 'execute_command', input: {} },
      { type: 'tool_use', id: 'tu2', name: 'execute_command', input: {} },
      { type: 'tool_use', id: 'tu3', name: 'execute_command', input: {} },
    ];
    const toolResults: ToolResultBlock[] = [
      { type: 'tool_result', tool_use_id: 'tu1', content: 'ok' },
    ];
    const result = verifyToolUseInvariant([
      { role: 'assistant', content: blocks },
      { role: 'user', content: '', toolResults },
    ]);
    expect(result.valid).toBe(false);
    expect(result.missing).toEqual(['tu2', 'tu3']);
  });

  it('GOOD: orphan-fixed shape (3 tool_use, 3 tool_results inc. is_error) is valid', () => {
    // This is what fillMissingToolResults() produces in v7.
    const blocks: ContentBlock[] = [
      { type: 'tool_use', id: 'tu1', name: 'execute_command', input: {} },
      { type: 'tool_use', id: 'tu2', name: 'execute_command', input: {} },
      { type: 'tool_use', id: 'tu3', name: 'execute_command', input: {} },
    ];
    const toolResults: ToolResultBlock[] = [
      { type: 'tool_result', tool_use_id: 'tu1', content: 'ok' },
      { type: 'tool_result', tool_use_id: 'tu2', content: 'Tool execution skipped: tool-call cap reached', is_error: true },
      { type: 'tool_result', tool_use_id: 'tu3', content: 'Tool execution skipped: tool-call cap reached', is_error: true },
    ];
    const result = verifyToolUseInvariant([
      { role: 'assistant', content: blocks },
      { role: 'user', content: '', toolResults },
    ]);
    expect(result.valid).toBe(true);
  });

  it('BAD: assistant with tool_use followed by plain-text user message is INVALID', () => {
    // This is what the catch block produced before v7 — pushed a plain-text
    // "Error occurred" user message even when the prior assistant had
    // unfulfilled tool_use blocks. → 400 next call.
    const blocks: ContentBlock[] = [
      { type: 'tool_use', id: 'tu1', name: 'execute_command', input: {} },
    ];
    const result = verifyToolUseInvariant([
      { role: 'assistant', content: blocks },
      { role: 'user', content: 'Error occurred: timeout. Please adjust your approach.' },
    ]);
    expect(result.valid).toBe(false);
    expect(result.missing).toEqual(['tu1']);
  });

  it('GOOD: catch-block fix (tool_use followed by user with is_error tool_results) is valid', () => {
    // What the v7 catch block produces when the last assistant had tool_use blocks.
    const blocks: ContentBlock[] = [
      { type: 'tool_use', id: 'tu1', name: 'execute_command', input: {} },
      { type: 'tool_use', id: 'tu2', name: 'execute_command', input: {} },
    ];
    const toolResults: ToolResultBlock[] = [
      { type: 'tool_result', tool_use_id: 'tu1', content: 'Tool execution failed: timeout. Please adjust your approach and continue.', is_error: true },
      { type: 'tool_result', tool_use_id: 'tu2', content: 'Tool execution failed: timeout. Please adjust your approach and continue.', is_error: true },
    ];
    const result = verifyToolUseInvariant([
      { role: 'assistant', content: blocks },
      { role: 'user', content: '', toolResults },
    ]);
    expect(result.valid).toBe(true);
  });

  it('GOOD: assistant with text-only (no tool_use) followed by plain-text user is valid', () => {
    // No tool_use → no invariant to check; plain text user is fine.
    const result = verifyToolUseInvariant([
      { role: 'assistant', content: 'I have completed the task.' },
      { role: 'user', content: 'Continue.' },
    ]);
    expect(result.valid).toBe(true);
  });

  it('GOOD: long conversation with multiple tool_use/tool_result rounds is valid', () => {
    const messages: ChatMessage[] = [
      { role: 'user', content: 'start' },
    ];
    for (let i = 0; i < 5; i++) {
      messages.push({
        role: 'assistant',
        content: [
          { type: 'text', text: `Round ${i}` },
          { type: 'tool_use', id: `tu${i}a`, name: 'execute_command', input: {} },
          { type: 'tool_use', id: `tu${i}b`, name: 'execute_command', input: {} },
        ],
      });
      messages.push({
        role: 'user',
        content: '',
        toolResults: [
          { type: 'tool_result', tool_use_id: `tu${i}a`, content: 'ok' },
          { type: 'tool_result', tool_use_id: `tu${i}b`, content: 'ok' },
        ],
      });
    }
    const result = verifyToolUseInvariant(messages);
    expect(result.valid).toBe(true);
  });

  it('BAD: any single round with orphan tool_use anywhere in conversation is INVALID', () => {
    const messages: ChatMessage[] = [
      { role: 'user', content: 'start' },
      // round 1 — clean
      {
        role: 'assistant',
        content: [{ type: 'tool_use', id: 'tu1a', name: 'execute_command', input: {} }],
      },
      {
        role: 'user',
        content: '',
        toolResults: [{ type: 'tool_result', tool_use_id: 'tu1a', content: 'ok' }],
      },
      // round 2 — orphan
      {
        role: 'assistant',
        content: [
          { type: 'tool_use', id: 'tu2a', name: 'execute_command', input: {} },
          { type: 'tool_use', id: 'tu2b', name: 'execute_command', input: {} },
        ],
      },
      {
        role: 'user',
        content: '',
        toolResults: [{ type: 'tool_result', tool_use_id: 'tu2a', content: 'ok' }],
      },
    ];
    const result = verifyToolUseInvariant(messages);
    expect(result.valid).toBe(false);
    expect(result.missing).toEqual(['tu2b']);
  });
});

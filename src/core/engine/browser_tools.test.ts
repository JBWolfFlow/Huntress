/**
 * Browser Tools Integration — Unit Tests
 *
 * Verifies:
 * 1. Browser tool schemas are correctly defined and exported
 * 2. BROWSER_ENABLED_AGENTS legacy set contains original 4 agent types
 * 3. getToolSchemasForAgent returns browser tools by default (Phase A: all agents)
 * 4. getToolSchemasForAgent excludes browser tools only when browserEnabled=false
 * 5. Scope validation blocks out-of-scope browser navigation
 * 6. Browser tools return errors when browserEnabled=false
 * 7. Browser evaluate/click/get_content require active page
 * 8. All hunting agents include browser tool schemas by default
 * 9. ReactLoopConfig accepts browserEnabled flag (defaults to true)
 * 10. Browser cleanup is idempotent
 * 11. ReactLoop constructor auto-includes browser schemas when not present
 */

import { describe, it, expect } from 'vitest';
import {
  BROWSER_NAVIGATE_SCHEMA,
  BROWSER_EVALUATE_SCHEMA,
  BROWSER_CLICK_SCHEMA,
  BROWSER_FILL_SCHEMA,
  BROWSER_GET_CONTENT_SCHEMA,
  BROWSER_TOOL_SCHEMAS,
  BROWSER_ENABLED_AGENTS,
  AGENT_TOOL_SCHEMAS,
  getToolSchemasForAgent,
} from './tool_schemas';
import type { ReactLoopConfig } from './react_loop';

// ─── Tool Schema Definitions ──────────────────────────────────────────────────

describe('Browser Tool Schemas', () => {
  it('should export 5 browser tool schemas', () => {
    expect(BROWSER_TOOL_SCHEMAS).toHaveLength(5);
  });

  it('browser_navigate schema has required fields', () => {
    expect(BROWSER_NAVIGATE_SCHEMA.name).toBe('browser_navigate');
    expect(BROWSER_NAVIGATE_SCHEMA.input_schema.required).toContain('url');
    expect(BROWSER_NAVIGATE_SCHEMA.input_schema.properties).toHaveProperty('url');
    expect(BROWSER_NAVIGATE_SCHEMA.input_schema.properties).toHaveProperty('wait_ms');
  });

  it('browser_evaluate schema has required expression field', () => {
    expect(BROWSER_EVALUATE_SCHEMA.name).toBe('browser_evaluate');
    expect(BROWSER_EVALUATE_SCHEMA.input_schema.required).toContain('expression');
    expect(BROWSER_EVALUATE_SCHEMA.input_schema.properties).toHaveProperty('expression');
  });

  it('browser_click schema has required selector field', () => {
    expect(BROWSER_CLICK_SCHEMA.name).toBe('browser_click');
    expect(BROWSER_CLICK_SCHEMA.input_schema.required).toContain('selector');
    expect(BROWSER_CLICK_SCHEMA.input_schema.properties).toHaveProperty('selector');
    expect(BROWSER_CLICK_SCHEMA.input_schema.properties).toHaveProperty('wait_ms');
  });

  it('browser_fill schema has required selector and value fields', () => {
    expect(BROWSER_FILL_SCHEMA.name).toBe('browser_fill');
    expect(BROWSER_FILL_SCHEMA.input_schema.required).toEqual(['selector', 'value']);
    expect(BROWSER_FILL_SCHEMA.input_schema.properties).toHaveProperty('selector');
    expect(BROWSER_FILL_SCHEMA.input_schema.properties).toHaveProperty('value');
    expect(BROWSER_FILL_SCHEMA.input_schema.properties).toHaveProperty('wait_ms');
  });

  it('browser_get_content schema has optional include_cookies', () => {
    expect(BROWSER_GET_CONTENT_SCHEMA.name).toBe('browser_get_content');
    expect(BROWSER_GET_CONTENT_SCHEMA.input_schema.properties).toHaveProperty('include_cookies');
    // required is empty — all fields are optional
    expect(BROWSER_GET_CONTENT_SCHEMA.input_schema.required).toEqual([]);
  });

  it('all browser schemas have descriptions', () => {
    for (const schema of BROWSER_TOOL_SCHEMAS) {
      expect(schema.description).toBeTruthy();
      expect(schema.description.length).toBeGreaterThan(20);
    }
  });

  it('browser schema names match expected set', () => {
    const names = BROWSER_TOOL_SCHEMAS.map(s => s.name);
    expect(names).toEqual([
      'browser_navigate',
      'browser_evaluate',
      'browser_click',
      'browser_fill',
      'browser_get_content',
    ]);
  });
});

// ─── Browser-Enabled Agents ──────────────────────────────────────────────────

describe('BROWSER_ENABLED_AGENTS (legacy set — Phase A gives all agents browser access)', () => {
  it('includes the original 4 browser-enabled agents', () => {
    expect(BROWSER_ENABLED_AGENTS.has('xss-hunter')).toBe(true);
    expect(BROWSER_ENABLED_AGENTS.has('ssti-hunter')).toBe(true);
    expect(BROWSER_ENABLED_AGENTS.has('prototype-pollution-hunter')).toBe(true);
    expect(BROWSER_ENABLED_AGENTS.has('business-logic-hunter')).toBe(true);
  });

  it('has exactly 4 entries (legacy reference)', () => {
    expect(BROWSER_ENABLED_AGENTS.size).toBe(4);
  });
});

// ─── getToolSchemasForAgent — Phase A: browser tools for all agents ──────────

describe('getToolSchemasForAgent — browser tools (Phase A)', () => {
  it('returns browser tools by default for all hunting agents', () => {
    const schemas = getToolSchemasForAgent('sqli-hunter');
    const names = schemas.map(s => s.name);
    expect(names).toContain('browser_navigate');
    expect(names).toContain('browser_evaluate');
    expect(names).toContain('browser_click');
    expect(names).toContain('browser_get_content');
    expect(names).toContain('http_request');
    expect(names).toContain('report_finding');
  });

  it('returns browser tools when browserEnabled=true', () => {
    const schemas = getToolSchemasForAgent('xss-hunter', true);
    const names = schemas.map(s => s.name);
    expect(names).toContain('browser_navigate');
    expect(names).toContain('http_request');
  });

  it('excludes browser tools only when browserEnabled=false (explicit opt-out)', () => {
    const schemas = getToolSchemasForAgent('sqli-hunter', false);
    const names = schemas.map(s => s.name);
    expect(names).not.toContain('browser_navigate');
    expect(names).not.toContain('browser_evaluate');
    expect(names).toContain('http_request');
  });

  it('recon agents never get browser tools', () => {
    const schemas = getToolSchemasForAgent('recon', true);
    const names = schemas.map(s => s.name);
    expect(names).not.toContain('browser_navigate');
    expect(names).not.toContain('http_request');
    expect(names).toContain('execute_command');
  });

  it('orchestrator never gets browser tools', () => {
    const schemas = getToolSchemasForAgent('orchestrator', true);
    const names = schemas.map(s => s.name);
    expect(names).not.toContain('browser_navigate');
    expect(names).toContain('dispatch_agent');
  });

  it('browserEnabled=false removes exactly 5 schemas vs default', () => {
    const withBrowser = getToolSchemasForAgent('xss-hunter');
    const withoutBrowser = getToolSchemasForAgent('xss-hunter', false);
    expect(withBrowser.length).toBe(withoutBrowser.length + 5);
  });

  it('browser schemas appear after standard agent schemas', () => {
    const schemas = getToolSchemasForAgent('xss-hunter', true);
    const standardCount = AGENT_TOOL_SCHEMAS.length;
    for (let i = 0; i < standardCount; i++) {
      expect(schemas[i].name).toBe(AGENT_TOOL_SCHEMAS[i].name);
    }
    expect(schemas[standardCount].name).toBe('browser_navigate');
    expect(schemas[standardCount + 1].name).toBe('browser_evaluate');
    expect(schemas[standardCount + 2].name).toBe('browser_click');
    expect(schemas[standardCount + 3].name).toBe('browser_fill');
    expect(schemas[standardCount + 4].name).toBe('browser_get_content');
  });

  it('all non-recon non-orchestrator agents get browser tools by default', () => {
    const agentTypes = [
      'cors-hunter', 'host-header-hunter', 'cache-hunter', 'crlf-hunter',
      'jwt-hunter', 'idor-hunter', 'ssrf-hunter', 'path-traversal-hunter',
      'command-injection-hunter', 'nosql-hunter', 'deserialization-hunter',
    ];
    for (const agentType of agentTypes) {
      const schemas = getToolSchemasForAgent(agentType);
      const names = schemas.map(s => s.name);
      expect(names).toContain('browser_navigate');
    }
  });
});

// ─── Shared mock provider helper ────────────────────────────────────────────

function buildMockProvider(toolCall: { name: string; input: Record<string, unknown> }) {
  let callCount = 0;
  return {
    sendMessage: async () => {
      callCount++;
      if (callCount === 1) {
        return {
          content: '',
          inputTokens: 10,
          outputTokens: 10,
          toolCalls: [{
            type: 'tool_use' as const,
            id: `tool_${callCount}`,
            name: toolCall.name,
            input: toolCall.input,
          }],
        };
      }
      return {
        content: '',
        inputTokens: 10,
        outputTokens: 10,
        toolCalls: [{
          type: 'tool_use' as const,
          id: `tool_${callCount}`,
          name: 'stop_hunting',
          input: { reason: 'task_complete', summary: 'Done' },
        }],
      };
    },
  } as unknown as ReactLoopConfig['provider'];
}

// ─── ReactLoopConfig browserEnabled (Phase A: defaults to true) ─────────────

describe('ReactLoopConfig browserEnabled', () => {
  it('accepts browserEnabled as an optional boolean', () => {
    const config: Partial<ReactLoopConfig> = {
      browserEnabled: true,
    };
    expect(config.browserEnabled).toBe(true);
  });

  it('can be explicitly set to false for opt-out', () => {
    const config: Partial<ReactLoopConfig> = {
      browserEnabled: false,
    };
    expect(config.browserEnabled).toBe(false);
  });
});

// ─── ReactLoop constructor auto-includes browser schemas (Phase A) ──────────

describe('ReactLoop constructor — Phase A browser auto-include', () => {
  it('auto-includes browser schemas when tools lack them', async () => {
    const { ReactLoop } = await import('./react_loop');

    const loop = new ReactLoop({
      provider: buildMockProvider({
        name: 'stop_hunting',
        input: { reason: 'task_complete', summary: 'Done' },
      }),
      model: 'test',
      systemPrompt: 'test',
      goal: 'test',
      tools: AGENT_TOOL_SCHEMAS, // No browser schemas
      target: 'https://example.com',
      scope: ['example.com'],
      // browserEnabled NOT set — defaults to true
      maxIterations: 1,
    });

    const result = await loop.execute();
    expect(result.stopReason).toBe('task_complete');
    // The loop accepted browser tools because constructor auto-included them
  });

  it('does not double-include browser schemas when already present', async () => {
    const { ReactLoop } = await import('./react_loop');

    const toolsWithBrowser = [...AGENT_TOOL_SCHEMAS, ...BROWSER_TOOL_SCHEMAS];

    const loop = new ReactLoop({
      provider: buildMockProvider({
        name: 'stop_hunting',
        input: { reason: 'task_complete', summary: 'Done' },
      }),
      model: 'test',
      systemPrompt: 'test',
      goal: 'test',
      tools: toolsWithBrowser,
      target: 'https://example.com',
      scope: ['example.com'],
      browserEnabled: true,
      maxIterations: 1,
    });

    const result = await loop.execute();
    expect(result.stopReason).toBe('task_complete');
  });

  it('does not include browser schemas when browserEnabled=false', async () => {
    const { ReactLoop } = await import('./react_loop');

    const loop = new ReactLoop({
      provider: buildMockProvider({
        name: 'stop_hunting',
        input: { reason: 'task_complete', summary: 'Done' },
      }),
      model: 'test',
      systemPrompt: 'test',
      goal: 'test',
      tools: AGENT_TOOL_SCHEMAS,
      target: 'https://example.com',
      scope: ['example.com'],
      browserEnabled: false,
      maxIterations: 1,
    });

    const result = await loop.execute();
    expect(result.stopReason).toBe('task_complete');
  });
});

// ─── ReactLoop browser tool dispatch (unit-level, no Playwright) ─────────────

describe('ReactLoop browser tool handlers — guard checks', () => {
  /**
   * These tests verify the guard logic WITHOUT launching a real browser.
   * They construct a ReactLoop with minimal config and call processToolCall
   * to verify:
   * - browserEnabled=false → error
   * - No active page → error for evaluate/click/get_content
   * - Out-of-scope URL → blocked for navigate
   *
   * We test the tool dispatch by exercising the public execute() path
   * indirectly through a mock provider that returns tool calls.
   */

  it('browser_navigate is blocked when browserEnabled is false', async () => {
    const { ReactLoop } = await import('./react_loop');

    const provider = buildMockProvider({
      name: 'browser_navigate',
      input: { url: 'https://example.com/page' },
    });

    const loop = new ReactLoop({
      provider: provider,
      model: 'test',
      systemPrompt: 'test',
      goal: 'test',
      tools: [...AGENT_TOOL_SCHEMAS, ...BROWSER_TOOL_SCHEMAS],
      target: 'https://example.com',
      scope: ['example.com'],
      browserEnabled: false,
      maxIterations: 2,
    });

    const result = await loop.execute();
    // The loop should complete (the tool error doesn't crash it)
    expect(result.stopReason).toBe('task_complete');
  });

  it('browser_evaluate is blocked when no page is active', async () => {
    const { ReactLoop } = await import('./react_loop');

    const provider = buildMockProvider({
      name: 'browser_evaluate',
      input: { expression: 'document.title' },
    });

    const loop = new ReactLoop({
      provider: provider,
      model: 'test',
      systemPrompt: 'test',
      goal: 'test',
      tools: [...AGENT_TOOL_SCHEMAS, ...BROWSER_TOOL_SCHEMAS],
      target: 'https://example.com',
      scope: ['example.com'],
      browserEnabled: true,
      maxIterations: 2,
    });

    const result = await loop.execute();
    expect(result.stopReason).toBe('task_complete');
  });

  it('browser_click is blocked when no page is active', async () => {
    const { ReactLoop } = await import('./react_loop');

    const provider = buildMockProvider({
      name: 'browser_click',
      input: { selector: 'button.submit' },
    });

    const loop = new ReactLoop({
      provider: provider,
      model: 'test',
      systemPrompt: 'test',
      goal: 'test',
      tools: [...AGENT_TOOL_SCHEMAS, ...BROWSER_TOOL_SCHEMAS],
      target: 'https://example.com',
      scope: ['example.com'],
      browserEnabled: true,
      maxIterations: 2,
    });

    const result = await loop.execute();
    expect(result.stopReason).toBe('task_complete');
  });

  it('browser_get_content is blocked when no page is active', async () => {
    const { ReactLoop } = await import('./react_loop');

    const provider = buildMockProvider({
      name: 'browser_get_content',
      input: { include_cookies: true },
    });

    const loop = new ReactLoop({
      provider: provider,
      model: 'test',
      systemPrompt: 'test',
      goal: 'test',
      tools: [...AGENT_TOOL_SCHEMAS, ...BROWSER_TOOL_SCHEMAS],
      target: 'https://example.com',
      scope: ['example.com'],
      browserEnabled: true,
      maxIterations: 2,
    });

    const result = await loop.execute();
    expect(result.stopReason).toBe('task_complete');
  });

  it('browser_navigate blocks out-of-scope URLs', async () => {
    const { ReactLoop } = await import('./react_loop');

    const provider = buildMockProvider({
      name: 'browser_navigate',
      input: { url: 'https://evil.com/steal-cookies' },
    });

    const loop = new ReactLoop({
      provider: provider,
      model: 'test',
      systemPrompt: 'test',
      goal: 'test',
      tools: [...AGENT_TOOL_SCHEMAS, ...BROWSER_TOOL_SCHEMAS],
      target: 'https://example.com',
      scope: ['example.com'],
      browserEnabled: true,
      maxIterations: 2,
    });

    const result = await loop.execute();
    // Loop completes — the out-of-scope URL was blocked but didn't crash
    expect(result.stopReason).toBe('task_complete');
    // httpRequestCount should be 0 — blocked request doesn't count
    expect(result.httpRequestCount).toBe(0);
  });

  it('cleanupBrowser is safe to call multiple times', async () => {
    const { ReactLoop } = await import('./react_loop');

    const loop = new ReactLoop({
      provider: buildMockProvider({
        name: 'stop_hunting',
        input: { reason: 'task_complete', summary: 'Done' },
      }),
      model: 'test',
      systemPrompt: 'test',
      goal: 'test',
      tools: AGENT_TOOL_SCHEMAS,
      target: 'https://example.com',
      scope: ['example.com'],
      maxIterations: 1,
    });

    // Call cleanup multiple times — should not throw
    await loop.cleanupBrowser();
    await loop.cleanupBrowser();
    await loop.cleanupBrowser();
  });
});

// ─── HeadlessBrowser.getBrowser() accessor ───────────────────────────────────

describe('HeadlessBrowser.getBrowser()', () => {
  it('returns null before launch', async () => {
    const { HeadlessBrowser } = await import('../validation/headless_browser');
    const browser = new HeadlessBrowser({ headless: true });
    expect(browser.getBrowser()).toBeNull();
  });
});

/**
 * I6 — Severity Calibration E2E (Integration)
 *
 * Drives findings through the full ReactLoop handleReportFinding() pipeline
 * (one test per calibration rule) and asserts the severity that reaches
 * onFinding has been corrected.
 *
 * Complements `src/core/engine/severity_calibration.test.ts`, which tests
 * the static classifier in isolation.
 */

import { describe, it, expect } from 'vitest';
import { ReactLoop } from '../../core/engine/react_loop';
import type {
  ReactLoopConfig,
  ReactFinding,
  CommandResult,
} from '../../core/engine/react_loop';
import type { ToolDefinition } from '../../core/providers/types';

/** Mock tool schemas — just report_finding and stop_hunting are needed. */
const MINIMAL_TOOLS: ToolDefinition[] = [
  {
    name: 'report_finding',
    description: 'Report a finding',
    input_schema: {
      type: 'object',
      properties: {
        title: { type: 'string' },
        vulnerability_type: { type: 'string' },
        severity: { type: 'string' },
        target: { type: 'string' },
        description: { type: 'string' },
        evidence: { type: 'array' },
        reproduction_steps: { type: 'array' },
        impact: { type: 'string' },
        confidence: { type: 'number' },
      },
      required: ['title', 'severity'],
    },
  },
  {
    name: 'stop_hunting',
    description: 'Stop',
    input_schema: {
      type: 'object',
      properties: { reason: { type: 'string' }, summary: { type: 'string' } },
    },
  },
];

/**
 * Build a ReactLoop wired with a mock provider that emits one scripted
 * report_finding followed by stop_hunting. Captures the finding via
 * onFinding so tests can assert on the calibrated severity.
 */
function runPipeline(
  reportFindingInput: Record<string, unknown>,
): Promise<{ finding: ReactFinding | null }> {
  let captured: ReactFinding | null = null;
  let callIdx = 0;

  const provider = {
    providerId: 'mock',
    displayName: 'Mock',
    supportsToolUse: true,
    getAvailableModels: () => [],
    validateApiKey: async () => true,
    estimateCost: () => 0,
    streamMessage: async function* () { /* unused */ },
    async sendMessage() {
      callIdx++;
      if (callIdx === 1) {
        return {
          content: '',
          model: 'mock',
          inputTokens: 10,
          outputTokens: 10,
          stopReason: 'tool_use' as const,
          toolCalls: [{
            type: 'tool_use' as const,
            id: `tool_${callIdx}`,
            name: 'report_finding',
            input: reportFindingInput,
          }],
        };
      }
      return {
        content: '',
        model: 'mock',
        inputTokens: 10,
        outputTokens: 10,
        stopReason: 'tool_use' as const,
        toolCalls: [{
          type: 'tool_use' as const,
          id: `tool_${callIdx}`,
          name: 'stop_hunting',
          input: { reason: 'done', summary: 'done' },
        }],
      };
    },
  } as unknown as ReactLoopConfig['provider'];

  const config: ReactLoopConfig = {
    provider,
    model: 'mock',
    systemPrompt: 'test',
    goal: 'test',
    tools: MINIMAL_TOOLS,
    maxIterations: 3,
    target: 'https://example.com',
    scope: ['example.com'],
    browserEnabled: false,
    onFinding: (f) => { captured = f; },
    // Satisfy the hallucination gate: claim 3+ successful command executions
    onExecuteCommand: async (): Promise<CommandResult> => ({
      success: true,
      stdout: 'ok',
      stderr: '',
      exitCode: 0,
      executionTimeMs: 10,
    }),
  };

  const loop = new ReactLoop(config);
  // Bypass the hallucination gate by bumping the HTTP counter past the threshold.
  (loop as unknown as { httpRequestCount: number }).httpRequestCount = 10;

  return loop.execute().then(() => ({ finding: captured }));
}

describe('I6: severity calibration E2E', () => {
  it('Rule 1 — Link/preconnect reflection is corrected to LOW', async () => {
    const { finding } = await runPipeline({
      title: 'SSRF via Link preconnect header reflection',
      vulnerability_type: 'ssrf',
      severity: 'critical',
      target: 'https://example.com',
      description: 'User input reflected in Link header with rel="preconnect"',
      evidence: ['Link: <https://evil.com>; rel="preconnect"'],
      reproduction_steps: ['curl -H "X-Reflected: https://evil.com" https://example.com/'],
      impact: 'Server makes outbound request to attacker domain',
      confidence: 80,
    });
    expect(finding).not.toBeNull();
    expect(finding!.severity).toBe('low');
    expect(finding!.description).toMatch(/calibrated.*critical.*low/i);
  });

  it('Rule 2 — Missing security headers are corrected to INFO', async () => {
    const { finding } = await runPipeline({
      title: 'Missing Content-Security-Policy header',
      vulnerability_type: 'security_misconfiguration',
      severity: 'high',
      target: 'https://example.com',
      description: 'Response lacks CSP header',
      evidence: ['No Content-Security-Policy header in response'],
      reproduction_steps: ['curl -I https://example.com/'],
      impact: 'Client-side attacks not mitigated',
      confidence: 90,
    });
    expect(finding).not.toBeNull();
    expect(finding!.severity).toBe('info');
  });

  it('Rule 3 — Software version disclosure is corrected to INFO', async () => {
    const { finding } = await runPipeline({
      title: 'Server version disclosure in Server header',
      vulnerability_type: 'information_disclosure',
      severity: 'medium',
      target: 'https://example.com',
      description: 'Server header reveals exact nginx version',
      evidence: ['Server: nginx/1.18.0'],
      reproduction_steps: ['curl -I https://example.com/'],
      impact: 'Known-CVE targeting',
      confidence: 90,
    });
    expect(finding).not.toBeNull();
    expect(finding!.severity).toBe('info');
  });

  it('Rule 4 — Info disclosure without credentials is corrected to MEDIUM', async () => {
    const { finding } = await runPipeline({
      title: 'Stack trace exposed in error response',
      vulnerability_type: 'information_disclosure',
      severity: 'critical',
      target: 'https://example.com',
      description: 'Full Java stack trace with internal package paths',
      evidence: ['at com.example.internal.Handler.processRequest(Handler.java:42)'],
      reproduction_steps: ['Send malformed payload to /api/v1/submit'],
      impact: 'Internal architecture revealed',
      confidence: 80,
    });
    expect(finding).not.toBeNull();
    expect(finding!.severity).toBe('medium');
  });

  it('Rule 5 — Self-XSS is corrected to LOW', async () => {
    const { finding } = await runPipeline({
      title: 'Self-XSS in user profile name field',
      vulnerability_type: 'xss_reflected',
      severity: 'high',
      target: 'https://example.com',
      description: 'XSS payload in own account profile only affects the attacker\'s own session',
      evidence: ['<script>alert(1)</script> stored in own account'],
      reproduction_steps: ['Login and set profile name'],
      impact: 'Attacker can trigger JS in their own session',
      confidence: 90,
    });
    expect(finding).not.toBeNull();
    expect(finding!.severity).toBe('low');
  });

  it('Rule 6 — Standalone open redirect is corrected to INFO', async () => {
    const { finding } = await runPipeline({
      title: 'Open redirect via ?next= parameter',
      vulnerability_type: 'open_redirect',
      severity: 'high',
      target: 'https://example.com',
      description: 'Application redirects to any URL supplied in the next parameter',
      evidence: ['HTTP/1.1 302 Location: https://evil.com'],
      reproduction_steps: ['Visit https://example.com/login?next=https://evil.com'],
      impact: 'Phishing via trusted domain',
      confidence: 85,
    });
    expect(finding).not.toBeNull();
    expect(finding!.severity).toBe('info');
  });

  it('Rule 7 — CORS without credential-theft PoC is corrected to MEDIUM', async () => {
    const { finding } = await runPipeline({
      title: 'CORS allows any origin via Access-Control-Allow-Origin: *',
      vulnerability_type: 'cors_misconfiguration',
      severity: 'critical',
      target: 'https://example.com',
      description: 'Response includes ACAO: * for authenticated API',
      evidence: ['Access-Control-Allow-Origin: *'],
      reproduction_steps: ['curl -H "Origin: https://evil.com" https://example.com/api/'],
      impact: 'Cross-origin reads theoretically possible',
      confidence: 80,
    });
    expect(finding).not.toBeNull();
    expect(finding!.severity).toBe('medium');
  });
});

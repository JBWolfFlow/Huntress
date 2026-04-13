/**
 * Session 12 — S2: Chain Detection Validation
 *
 * Tests that:
 * 1. detectChains() produces chains with validated: false (title-match only)
 * 2. Chain validation updates validated to true when exploitable
 * 3. Title-matching alone never produces validated: true
 * 4. VulnerabilityChain always has the validated field
 */

import { describe, it, expect, vi } from 'vitest';
import { detectChains } from '../core/orchestrator/chain_detector';
import type { VulnerabilityChain } from '../core/orchestrator/chain_detector';
import { ChainValidator } from '../core/orchestrator/chain_validator';
import type { AgentFinding } from '../agents/base_agent';
import type { HttpClient } from '../core/http/request_engine';

/** Helper to build a minimal AgentFinding */
function makeFinding(overrides: Partial<AgentFinding>): AgentFinding {
  return {
    id: `finding-${Math.random().toString(36).substring(2, 7)}`,
    agentId: 'test-agent',
    type: 'xss_reflected',
    title: 'Test Finding',
    severity: 'medium',
    description: 'Test description',
    target: 'https://example.com',
    evidence: ['test evidence'],
    reproduction: ['step 1'],
    timestamp: new Date(),
    ...overrides,
  };
}

/** Mock HttpClient that returns configurable responses */
function createMockHttpClient(
  responder?: (url: string) => { status: number; body: string },
): HttpClient {
  const defaultResponder = () => ({ status: 200, body: '<html>OK</html>' });
  const respond = responder ?? defaultResponder;

  return {
    request: vi.fn().mockImplementation(async (opts: { url: string }) => {
      const r = respond(opts.url);
      return { status: r.status, body: r.body, headers: {} };
    }),
  } as unknown as HttpClient;
}

describe('S2: detectChains produces unvalidated chains', () => {
  it('title-matched chains always have validated: false', () => {
    // Create findings that match the redirect_ssrf chain rule
    const findings: AgentFinding[] = [
      makeFinding({
        type: 'open_redirect',
        title: 'Open Redirect on login',
        target: 'https://example.com/login',
      }),
      makeFinding({
        type: 'ssrf',
        title: 'SSRF in webhook',
        target: 'https://example.com/webhook',
      }),
    ];

    const chains = detectChains(findings);

    expect(chains.length).toBeGreaterThan(0);
    for (const chain of chains) {
      expect(chain.validated).toBe(false);
    }
  });

  it('all chains from detectChains have the validated field', () => {
    const findings: AgentFinding[] = [
      makeFinding({ type: 'xss_reflected', title: 'Reflected XSS', target: 'https://example.com/search' }),
      makeFinding({ type: 'csrf', title: 'CSRF on password change', target: 'https://example.com/settings' }),
    ];

    const chains = detectChains(findings);

    for (const chain of chains) {
      expect(chain).toHaveProperty('validated');
      expect(typeof chain.validated).toBe('boolean');
    }
  });

  it('returns empty array when no chains match', () => {
    const findings: AgentFinding[] = [
      makeFinding({ type: 'info_disclosure', title: 'Server version exposed' }),
    ];

    const chains = detectChains(findings);
    expect(chains).toHaveLength(0);
  });
});

describe('S2: Chain validation sets validated field', () => {
  it('sets validated: true when chain is exploitable', async () => {
    // Mock HTTP that returns evidence patterns (confirming exploitability)
    const client = createMockHttpClient(() => ({
      status: 200,
      body: '<script>alert(1)</script> reflected here',
    }));

    const validator = new ChainValidator(client);

    const chain: VulnerabilityChain = {
      id: 'chain_test_validate',
      name: 'XSS → Cookie Theft',
      findings: [
        makeFinding({
          type: 'xss_reflected',
          title: 'Reflected XSS',
          target: 'https://example.com/search',
          evidence: ['<script>alert(1)</script> reflected in response'],
        }),
        makeFinding({
          type: 'missing_httponly',
          title: 'Missing HttpOnly',
          target: 'https://example.com/api',
          evidence: ['Set-Cookie: session=abc (no HttpOnly flag)'],
        }),
      ],
      combinedSeverity: 'high',
      description: 'XSS + missing HttpOnly = cookie theft',
      impact: 'Session hijacking',
      chainSteps: ['Step 1: XSS', 'Step 2: Cookie theft'],
      confidenceBoost: 15,
      validated: false, // Starts as unvalidated
    };

    const result = await validator.validateChain(chain);

    // If exploitable, the caller would set chain.validated = true
    if (result.isExploitable) {
      chain.validated = true;
    }

    expect(result.isExploitable).toBe(true);
    expect(chain.validated).toBe(true);
    expect(result.confidence).toBeGreaterThan(0);
  });

  it('keeps validated: false when chain steps fail', async () => {
    const client = createMockHttpClient(() => ({
      status: 500,
      body: 'Internal Server Error',
    }));

    const validator = new ChainValidator(client);

    const chain: VulnerabilityChain = {
      id: 'chain_test_fail',
      name: 'Broken Chain',
      findings: [
        makeFinding({
          target: 'https://example.com/broken',
          evidence: ['some specific pattern'],
        }),
      ],
      combinedSeverity: 'high',
      description: 'Test',
      impact: 'Test',
      chainSteps: ['Step 1'],
      confidenceBoost: 0,
      validated: false,
    };

    const result = await validator.validateChain(chain);

    // Chain should NOT be marked exploitable
    if (result.isExploitable) {
      chain.validated = true;
    }

    expect(chain.validated).toBe(false);
  });

  it('title-matching alone never produces validated: true', () => {
    // This is the core S2 requirement: detectChains is pattern-only
    const findings: AgentFinding[] = [
      makeFinding({ type: 'sqli_error', title: 'SQL Injection' }),
      makeFinding({ type: 'path_traversal', title: 'Path Traversal' }),
    ];

    const chains = detectChains(findings);

    // Even with a matching chain, validated must be false
    for (const chain of chains) {
      expect(chain.validated).toBe(false);
    }
  });
});

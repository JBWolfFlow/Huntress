/**
 * Chain Validator Tests (Phase 20I)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ChainValidator } from '../core/orchestrator/chain_validator';
import type { ChainValidationResult } from '../core/orchestrator/chain_validator';
import { detectChains } from '../core/orchestrator/chain_detector';
import type { VulnerabilityChain } from '../core/orchestrator/chain_detector';
import type { AgentFinding } from '../agents/base_agent';
import type { HttpClient, HttpRequestOptions, HttpResponse } from '../core/http/request_engine';
import type { ModelProvider, ChatResponse } from '../core/providers/types';

// ─── Mock Factories ──────────────────────────────────────────────────────────

function createMockHttpClient(
  handler?: (options: HttpRequestOptions) => Partial<HttpResponse>,
): HttpClient {
  const defaultResponse: HttpResponse = {
    status: 200,
    statusText: 'OK',
    headers: {},
    body: '<html>OK</html>',
    timing: { dnsMs: 0, connectMs: 0, ttfbMs: 0, totalMs: 1 },
    redirectChain: [],
    cookies: [],
    size: 0,
  };

  return {
    request: vi.fn(async (options: HttpRequestOptions) => ({
      ...defaultResponse,
      ...(handler?.(options) ?? {}),
    })),
    getCookies: vi.fn(() => []),
    setCookie: vi.fn(),
    clearCookies: vi.fn(),
    setAuthHeader: vi.fn(),
    clearAuth: vi.fn(),
    setRateLimit: vi.fn(),
    getRequestCount: vi.fn(() => 0),
    getRequestLog: vi.fn(() => []),
    clearRequestLog: vi.fn(),
  } as unknown as HttpClient;
}

function createMockProvider(responseContent: string = '[]'): ModelProvider {
  return {
    providerId: 'mock',
    displayName: 'MockProvider',
    sendMessage: vi.fn(async (): Promise<ChatResponse> => ({
      content: responseContent,
      model: 'mock-model',
      inputTokens: 10,
      outputTokens: 20,
      stopReason: 'end_turn',
    })),
    streamMessage: vi.fn(async function* () {
      yield { type: 'content_delta' as const, content: responseContent };
    }),
    getAvailableModels: vi.fn(() => []),
    validateApiKey: vi.fn(async () => true),
    estimateCost: vi.fn(() => 0),
  } as unknown as ModelProvider;
}

function makeFinding(overrides: Partial<AgentFinding>): AgentFinding {
  return {
    id: `finding_${Math.random().toString(36).substring(2, 7)}`,
    agentId: 'test_agent',
    type: 'xss_reflected',
    title: 'Test Finding',
    severity: 'medium',
    description: 'A test finding',
    target: 'https://example.com',
    evidence: ['<script>alert(1)</script> reflected'],
    reproduction: ['Go to https://example.com?q=<script>alert(1)</script>'],
    timestamp: new Date(),
    ...overrides,
  };
}

// ─── Chain Detector Tests (Phase 20I Additions) ──────────────────────────────

describe('Chain Detector — New Rules (Phase 20I)', () => {
  it('detects SQLi → Data Exfiltration chain', () => {
    const findings = [
      makeFinding({ type: 'sqli_error', title: 'SQL Injection', severity: 'high' }),
      makeFinding({ type: 'information_disclosure', title: 'User Data Exposed', severity: 'medium' }),
    ];

    const chains = detectChains(findings);
    const sqliChain = chains.find(c => c.name.includes('SQLi') && c.name.includes('Data Exfiltration'));
    expect(sqliChain).toBeDefined();
    expect(sqliChain!.combinedSeverity).toBe('critical');
  });

  it('detects Path Traversal → Source Code chain', () => {
    const findings = [
      makeFinding({ type: 'path_traversal', title: 'LFI', severity: 'high' }),
      makeFinding({ type: 'secret_exposure', title: 'API Key in Source', severity: 'medium' }),
    ];

    const chains = detectChains(findings);
    const chain = chains.find(c => c.name.includes('Path Traversal') && c.name.includes('Source Code'));
    expect(chain).toBeDefined();
    expect(chain!.combinedSeverity).toBe('critical');
  });

  it('detects XXE → SSRF chain', () => {
    const findings = [
      makeFinding({ type: 'xxe', title: 'XXE Injection', severity: 'high' }),
      makeFinding({ type: 'ssrf', title: 'SSRF via XXE', severity: 'high' }),
    ];

    const chains = detectChains(findings);
    const chain = chains.find(c => c.name.includes('XXE') && c.name.includes('SSRF'));
    expect(chain).toBeDefined();
    expect(chain!.combinedSeverity).toBe('critical');
  });

  it('detects Prototype Pollution → XSS chain', () => {
    const findings = [
      makeFinding({ type: 'prototype_pollution', title: 'Proto Pollution', severity: 'medium' }),
      makeFinding({ type: 'xss_dom', title: 'DOM XSS', severity: 'medium' }),
    ];

    const chains = detectChains(findings);
    const chain = chains.find(c => c.name.includes('Prototype Pollution') && c.name.includes('XSS'));
    expect(chain).toBeDefined();
    expect(chain!.combinedSeverity).toBe('high');
  });

  it('detects Open Redirect → OAuth Token Theft (cross-domain)', () => {
    const findings = [
      makeFinding({
        type: 'open_redirect',
        title: 'Open Redirect',
        target: 'https://auth.example.com/redirect',
        severity: 'low',
      }),
      makeFinding({
        type: 'oauth_misconfiguration',
        title: 'OAuth Redirect URI',
        target: 'https://oauth.example.com/callback',
        severity: 'medium',
      }),
    ];

    const chains = detectChains(findings);
    const chain = chains.find(c => c.name.includes('Open Redirect') && c.name.includes('OAuth'));
    expect(chain).toBeDefined();
    expect(chain!.combinedSeverity).toBe('critical');
  });

  it('detects Host Header Injection → Cache Poisoning chain', () => {
    const findings = [
      makeFinding({ type: 'host_header_injection', title: 'Host Header Injection', severity: 'medium' }),
      makeFinding({ type: 'cache_poisoning', title: 'Cache Poisoning', severity: 'medium' }),
    ];

    const chains = detectChains(findings);
    const chain = chains.find(c => c.name.includes('Host Header') && c.name.includes('Cache'));
    expect(chain).toBeDefined();
    expect(chain!.combinedSeverity).toBe('high');
  });

  it('enforces sameTarget constraint', () => {
    const findings = [
      makeFinding({ type: 'sqli_error', title: 'SQLi', target: 'https://a.com/api' }),
      makeFinding({ type: 'information_disclosure', title: 'Data', target: 'https://totally-different.com/data' }),
    ];

    const chains = detectChains(findings);
    const sqliChain = chains.find(c => c.name.includes('SQLi') && c.name.includes('Data Exfiltration'));
    // Should not detect because targets are on different domains
    expect(sqliChain).toBeUndefined();
  });
});

// ─── Chain Validator Tests ───────────────────────────────────────────────────

describe('ChainValidator', () => {
  describe('validateChain', () => {
    it('validates an exploitable chain', async () => {
      const client = createMockHttpClient(() => ({
        status: 200,
        body: '<script>alert(1)</script> something',
      }));

      const validator = new ChainValidator(client);

      const chain: VulnerabilityChain = {
        id: 'chain_test_1',
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
        validated: false,
      };

      const result = await validator.validateChain(chain);

      expect(result.chainId).toBe('chain_test_1');
      expect(result.validatedSteps).toHaveLength(2);
      expect(result.estimatedSeverity).toBe('high');
      expect(result.estimatedBounty).toBeDefined();
      expect(result.estimatedBounty!.min).toBeGreaterThan(0);
    });

    it('marks chain as not exploitable when steps fail', async () => {
      const client = createMockHttpClient(() => ({
        status: 500,
        body: 'Internal Server Error',
      }));

      const validator = new ChainValidator(client);

      const chain: VulnerabilityChain = {
        id: 'chain_fail',
        name: 'Broken Chain',
        findings: [
          makeFinding({ target: 'https://example.com/broken' }),
        ],
        combinedSeverity: 'high',
        description: 'Test',
        impact: 'Test',
        chainSteps: ['Step 1'],
        confidenceBoost: 0,
        validated: false,
      };

      const result = await validator.validateChain(chain);
      expect(result.validatedSteps[0].validationResult).toBe('failed');
    });

    it('handles findings without extractable URLs', async () => {
      const client = createMockHttpClient();
      const validator = new ChainValidator(client);

      const chain: VulnerabilityChain = {
        id: 'chain_no_url',
        name: 'No URL Chain',
        findings: [
          makeFinding({
            target: 'just-a-domain.com',  // No protocol
            evidence: ['some evidence without urls'],
            reproduction: ['manual step'],
          }),
        ],
        combinedSeverity: 'medium',
        description: 'Test',
        impact: 'Test',
        chainSteps: ['Step 1'],
        confidenceBoost: 0,
        validated: false,
      };

      const result = await validator.validateChain(chain);

      // Should get partial result since URL couldn't be extracted
      expect(result.validatedSteps[0].validationResult).toBe('partial');
    });
  });

  describe('discoverCreativeChains', () => {
    it('returns empty when no provider available', async () => {
      const client = createMockHttpClient();
      const validator = new ChainValidator(client); // No provider

      const findings = [
        makeFinding({ type: 'xss_reflected' }),
        makeFinding({ type: 'csrf' }),
      ];

      const chains = await validator.discoverCreativeChains(findings, {
        domain: 'example.com',
        technologies: ['react'],
      });

      expect(chains).toEqual([]);
    });

    it('returns empty for single finding', async () => {
      const provider = createMockProvider();
      const client = createMockHttpClient();
      const validator = new ChainValidator(client, provider, 'mock-model');

      const chains = await validator.discoverCreativeChains(
        [makeFinding({})],
        { domain: 'example.com', technologies: [] },
      );

      expect(chains).toEqual([]);
    });

    it('parses LLM chain suggestions', async () => {
      const llmResponse = JSON.stringify([{
        name: 'XSS → CSRF → Account Takeover',
        findingIndices: [0, 1],
        combinedSeverity: 'critical',
        description: 'Use XSS to bypass CSRF protection',
        impact: 'Full account takeover',
      }]);

      const provider = createMockProvider(llmResponse);
      const client = createMockHttpClient();
      const validator = new ChainValidator(client, provider, 'mock-model');

      const findings = [
        makeFinding({ type: 'xss_reflected', title: 'XSS' }),
        makeFinding({ type: 'csrf', title: 'CSRF' }),
      ];

      const chains = await validator.discoverCreativeChains(findings, {
        domain: 'example.com',
        technologies: ['react'],
      });

      expect(chains).toHaveLength(1);
      expect(chains[0].name).toBe('XSS → CSRF → Account Takeover');
      expect(chains[0].combinedSeverity).toBe('critical');
      expect(chains[0].findings).toHaveLength(2);
    });

    it('handles invalid LLM response gracefully', async () => {
      const provider = createMockProvider('this is not valid JSON');
      const client = createMockHttpClient();
      const validator = new ChainValidator(client, provider, 'mock-model');

      const findings = [
        makeFinding({ type: 'xss_reflected' }),
        makeFinding({ type: 'csrf' }),
      ];

      const chains = await validator.discoverCreativeChains(findings, {
        domain: 'example.com',
        technologies: [],
      });

      expect(chains).toEqual([]);
    });

    it('filters out chain suggestions with invalid finding indices', async () => {
      const llmResponse = JSON.stringify([
        {
          name: 'Valid Chain',
          findingIndices: [0, 1],
          combinedSeverity: 'high',
          description: 'Valid',
          impact: 'Valid',
        },
        {
          name: 'Invalid Chain',
          findingIndices: [0, 99], // Index 99 doesn't exist
          combinedSeverity: 'critical',
          description: 'Invalid',
          impact: 'Invalid',
        },
      ]);

      const provider = createMockProvider(llmResponse);
      const client = createMockHttpClient();
      const validator = new ChainValidator(client, provider, 'mock-model');

      const findings = [
        makeFinding({ type: 'xss_reflected' }),
        makeFinding({ type: 'csrf' }),
      ];

      const chains = await validator.discoverCreativeChains(findings, {
        domain: 'example.com',
        technologies: [],
      });

      expect(chains).toHaveLength(1);
      expect(chains[0].name).toBe('Valid Chain');
    });
  });

  describe('generateChainPoC', () => {
    it('generates a basic PoC without LLM', async () => {
      const client = createMockHttpClient();
      const validator = new ChainValidator(client);

      const chain: VulnerabilityChain = {
        id: 'poc_test',
        name: 'XSS → CSRF',
        findings: [
          makeFinding({ title: 'XSS', target: 'https://example.com/xss' }),
          makeFinding({ title: 'CSRF', target: 'https://example.com/csrf' }),
        ],
        combinedSeverity: 'critical',
        description: 'XSS to CSRF',
        impact: 'Account takeover',
        chainSteps: ['Step 1: XSS', 'Step 2: CSRF'],
        confidenceBoost: 15,
        validated: false,
      };

      const poc = await validator.generateChainPoC(chain);

      expect(poc).toContain('python3');
      expect(poc).toContain('import requests');
      expect(poc).toContain('XSS');
      expect(poc).toContain('CSRF');
      expect(poc).toContain('critical');
    });

    it('uses LLM-generated PoC when provider available', async () => {
      const pythonPoC = `import requests\n\nsession = requests.Session()\nresponse = session.get('https://example.com')\nprint(response.status_code)`;
      const provider = createMockProvider(pythonPoC);
      const client = createMockHttpClient();
      const validator = new ChainValidator(client, provider, 'mock-model');

      const chain: VulnerabilityChain = {
        id: 'poc_llm',
        name: 'Test Chain',
        findings: [makeFinding({})],
        combinedSeverity: 'high',
        description: 'Test',
        impact: 'Test',
        chainSteps: ['Step 1'],
        confidenceBoost: 0,
        validated: false,
      };

      const poc = await validator.generateChainPoC(chain);
      expect(poc).toContain('import requests');
      expect(poc).toContain('session.get');
    });
  });
});

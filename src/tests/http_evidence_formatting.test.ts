/**
 * HTTP Evidence Formatting Tests (RQ3 + RQ5)
 *
 * Validates that structured HTTP exchanges are formatted as markdown code blocks
 * with curl commands and Python reproduction scripts.
 */

import { describe, it, expect } from 'vitest';
import { PoCGenerator } from '../core/reporting/poc_generator';
import type { HttpExchange } from '../agents/base_agent';

// ─── Test data ──────────────────────────────────────────────────────────────

const xssExchange: HttpExchange = {
  request: {
    method: 'GET',
    url: 'https://target.com/search?q=<script>alert(1)</script>',
    headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html' },
  },
  response: {
    status: 200,
    statusText: 'OK',
    headers: { 'content-type': 'text/html; charset=utf-8' },
    bodySnippet: '<html><body>Results for: <script>alert(1)</script></body></html>',
  },
  iteration: 3,
  timestamp: Date.now(),
};

const sqliLoginExchange: HttpExchange = {
  request: {
    method: 'POST',
    url: 'https://target.com/api/login',
    headers: { 'Content-Type': 'application/json' },
    body: '{"email":"\' OR 1=1--","password":"x"}',
  },
  response: {
    status: 200,
    statusText: 'OK',
    headers: { 'content-type': 'application/json', 'set-cookie': 'session=abc123' },
    bodySnippet: '{"authentication":{"token":"eyJhbGci...","umail":"admin@target.com"}}',
  },
  iteration: 5,
};

const idorExchangeA: HttpExchange = {
  request: {
    method: 'GET',
    url: 'https://target.com/api/users/1',
    headers: { 'Authorization': 'Bearer token_user_a' },
  },
  response: {
    status: 200,
    bodySnippet: '{"id":1,"email":"admin@target.com","role":"admin"}',
  },
  iteration: 2,
};

const idorExchangeB: HttpExchange = {
  request: {
    method: 'GET',
    url: 'https://target.com/api/users/2',
    headers: { 'Authorization': 'Bearer token_user_a' },
  },
  response: {
    status: 200,
    bodySnippet: '{"id":2,"email":"victim@target.com","role":"user"}',
  },
  iteration: 3,
};

// ─── Curl command generation ────────────────────────────────────────────────

describe('PoCGenerator.generateCurlCommand', () => {
  it('generates GET curl without explicit method flag', () => {
    const curl = PoCGenerator.generateCurlCommand(xssExchange);
    expect(curl).not.toContain('-X GET');
    expect(curl).toContain('target.com/search');
    expect(curl).toContain("User-Agent:");
  });

  it('generates POST curl with -X flag and -d body', () => {
    const curl = PoCGenerator.generateCurlCommand(sqliLoginExchange);
    expect(curl).toContain('-X POST');
    expect(curl).toContain('-d');
    expect(curl).toContain('OR 1=1');
    expect(curl).toContain('Content-Type: application/json');
  });

  it('redacts Authorization header values', () => {
    const curl = PoCGenerator.generateCurlCommand(idorExchangeA);
    expect(curl).toContain('[REDACTED]');
    expect(curl).not.toContain('token_user_a');
  });

  it('handles exchange with no headers or body', () => {
    const simple: HttpExchange = {
      request: { method: 'GET', url: 'https://target.com/' },
      response: { status: 200, bodySnippet: 'OK' },
    };
    const curl = PoCGenerator.generateCurlCommand(simple);
    expect(curl).toContain('curl');
    expect(curl).toContain('target.com');
    expect(curl).not.toContain('-X');
    expect(curl).not.toContain('-H');
    expect(curl).not.toContain('-d');
  });
});

// ─── formatHttpEvidence ─────────────────────────────────────────────────────

describe('PoCGenerator.formatHttpEvidence', () => {
  // We need an instance to call instance methods
  // Use a mock QdrantClient and FindingSummarizer
  const mockQdrant = { search: async () => [] } as never;
  const mockSummarizer = { summarize: async () => '' } as never;
  const generator = new PoCGenerator(mockQdrant, mockSummarizer);

  it('formats structured exchanges as HTTP code blocks', () => {
    const result = generator.formatHttpEvidence([xssExchange]);
    expect(result).toBeDefined();
    expect(result).toContain('```http');
    expect(result).toContain('GET /search');
    expect(result).toContain('Host: target.com');
    expect(result).toContain('HTTP/1.1 200 OK');
    expect(result).toContain('```bash');
    expect(result).toContain('curl');
  });

  it('formats multiple exchanges with numbered labels', () => {
    const result = generator.formatHttpEvidence([idorExchangeA, idorExchangeB]);
    expect(result).toBeDefined();
    expect(result).toContain('Request 1');
    expect(result).toContain('Request 2');
    expect(result).toContain('Response 1');
    expect(result).toContain('Response 2');
  });

  it('includes response body snippet', () => {
    const result = generator.formatHttpEvidence([sqliLoginExchange]);
    expect(result).toBeDefined();
    expect(result).toContain('admin@target.com');
    expect(result).toContain('eyJhbGci');
  });

  it('shows important headers in response', () => {
    const result = generator.formatHttpEvidence([sqliLoginExchange]);
    expect(result).toBeDefined();
    expect(result).toContain('set-cookie');
    expect(result).toContain('content-type');
  });

  it('falls back to text extraction when no structured exchanges', () => {
    const result = generator.formatHttpEvidence(
      undefined,
      'The server responded with GET /api/users HTTP/1.1 indicating the endpoint exists',
      ['Send POST /api/login HTTP/1.1 with credentials'],
    );
    expect(result).toBeDefined();
    expect(result).toContain('extracted from agent text');
  });

  it('returns undefined when no evidence available', () => {
    const result = generator.formatHttpEvidence(undefined, 'No HTTP patterns here', []);
    expect(result).toBeUndefined();
  });

  it('limits displayed exchanges to 10 (P0-5-d: was 5, raised to give triagers more proof)', () => {
    const manyExchanges = Array.from({ length: 15 }, (_, i) => ({
      request: { method: 'GET' as const, url: `https://target.com/path${i}` },
      response: { status: 200, bodySnippet: `Response ${i}` },
    }));
    const result = generator.formatHttpEvidence(manyExchanges);
    expect(result).toBeDefined();
    // Cap is 10 — all 15 GETs have equal relevance score, so the rank-then-original-order
    // logic preserves the first 10 by original position (later GETs get a slight position
    // bonus, so they win, and then the result re-sorts by original index for display).
    const labels = result!.match(/\*\*Request \d+:\*\*/g) ?? [];
    expect(labels.length).toBe(10);
    // Path11 (later, slight position bonus) should appear; path0 (earliest, lowest score) should not.
    expect(result).toContain('path14');
    expect(result).not.toContain('path0');
  });
});

// ─── Evidence compilation (RQ4) ─────────────────────────────────────────────

describe('Evidence compilation (RQ4)', () => {
  it('compileProof is async (returns a promise)', async () => {
    const mockQdrant = { search: async () => [] } as never;
    const mockSummarizer = { summarize: async () => '' } as never;
    const generator = new PoCGenerator(mockQdrant, mockSummarizer);

    // generateReport calls compileProof internally — ensure it doesn't throw
    // when proof has logs/screenshots (Tauri bridge unavailable in test = graceful fallback)
    const vuln = {
      id: 'test_1',
      type: 'xss',
      severity: 'high' as const,
      title: 'Test XSS',
      description: 'Test description with enough detail for the report generator to work properly.',
      url: 'https://target.com/search',
      target: 'target.com',
      impact: 'Session hijacking',
      steps: ['Go to search', 'Enter payload', 'Observe alert'],
      timestamp: Date.now(),
      proof: {
        screenshots: ['/tmp/screenshot_001.png'],
        logs: ['/tmp/scan_output.log'],
        video: '/tmp/poc_recording.mp4',
      },
    };

    // This should not throw even without Tauri bridge
    const report = await generator.generateReport(vuln, { skipDuplicateCheck: true });
    expect(report).toBeDefined();
    expect(report.proof).toBeDefined();
  });

  it('fileExists returns true when bridge unavailable (test environment fallback)', async () => {
    // In test env, Tauri invoke is not available — should return true as safe default
    const exists = await PoCGenerator.fileExists('/tmp/test_file.txt');
    expect(exists).toBe(true);
  });

  it('readFileContent returns null when bridge unavailable', async () => {
    const content = await PoCGenerator.readFileContent('/tmp/test_file.txt');
    expect(content).toBeNull();
  });
});

// ─── Quick reproduction (RQ5 partial coverage) ─────────────────────────────

describe('Quick reproduction in reports', () => {
  const mockQdrant = { search: async () => [] } as never;
  const mockSummarizer = { summarize: async () => '' } as never;
  const generator = new PoCGenerator(mockQdrant, mockSummarizer);

  it('single exchange produces curl-only reproduction', () => {
    // Access private method indirectly via formatHttpEvidence which calls generateCurlCommand
    const evidence = generator.formatHttpEvidence([sqliLoginExchange]);
    expect(evidence).toContain('```bash');
    expect(evidence).toContain('curl');
    expect(evidence).toContain('-X POST');
  });

  it('curl command for XSS includes the payload in URL', () => {
    const curl = PoCGenerator.generateCurlCommand(xssExchange);
    expect(curl).toContain('<script>alert(1)</script>');
  });

  it('curl command for SQLi includes injection in body', () => {
    const curl = PoCGenerator.generateCurlCommand(sqliLoginExchange);
    expect(curl).toContain("OR 1=1");
  });
});

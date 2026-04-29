/**
 * P0-5 Report Writer Tests
 *
 * Verifies the report writer rebuild:
 *   a. Templates from REPORT_TEMPLATES are wired into toMarkdown()
 *   b. Inline-build fallback carries all H1-required sections
 *   c. Body snippet cap is 2000 chars on the most-relevant exchange
 *   d. Up to 10 exchanges shown, ranked by relevance
 *   e. Per-vuln-type evidence checklist enforces H1 Decision Matrix
 */

import { describe, it, expect } from 'vitest';
import { PoCGenerator } from '../core/reporting/poc_generator';
import { ReportQualityScorer } from '../core/reporting/report_quality';
import { getTemplateKey, extractParameter, REPORT_TEMPLATES } from '../core/reporting/templates';
import type { H1Report } from '../core/reporting/h1_api';
import type { HttpExchange } from '../agents/base_agent';

// Minimal generator — tests only need toMarkdown which is pure.
const generator = new PoCGenerator(
  { upsert: async () => true, search: async () => [] } as any,
  {} as any,
);

const baseReport: H1Report = {
  title: '[HIGH] Test finding',
  severity: 'high',
  suggestedBounty: { min: 500, max: 1500 },
  description: 'Test description with enough length to satisfy clarity check.',
  impact: 'An attacker can do bad things.',
  steps: ['Do step 1', 'Do step 2', 'Do step 3'],
  proof: {},
  cvssScore: 7.5,
  cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
  weaknessId: '79',
};

// ─── P0-5-a: Template helpers ───────────────────────────────────────────────

describe('P0-5-a · template key resolution', () => {
  it('maps xss family variants to xss template', () => {
    expect(getTemplateKey('xss_reflected')).toBe('xss');
    expect(getTemplateKey('xss_dom')).toBe('xss');
    expect(getTemplateKey('xss_stored')).toBe('xss');
  });

  it('maps sqli family to sql_injection', () => {
    expect(getTemplateKey('sqli_error')).toBe('sql_injection');
    expect(getTemplateKey('sqli_blind_time')).toBe('sql_injection');
  });

  it('maps bola to idor (same template, two-account proof)', () => {
    expect(getTemplateKey('bola')).toBe('idor');
  });

  it('maps cors_misconfiguration to cors', () => {
    expect(getTemplateKey('cors_misconfiguration')).toBe('cors');
  });

  it('maps jwt family to jwt template', () => {
    expect(getTemplateKey('jwt_alg_confusion')).toBe('jwt');
    expect(getTemplateKey('jwt_none')).toBe('jwt');
  });

  it('returns null for unmapped types so caller can fall back', () => {
    expect(getTemplateKey('cache_poisoning')).toBeNull();
    expect(getTemplateKey('business_logic')).toBeNull();
    expect(getTemplateKey('totally_made_up_type')).toBeNull();
  });

  it('returns the type itself when it is already a template key', () => {
    for (const key of Object.keys(REPORT_TEMPLATES)) {
      expect(getTemplateKey(key)).toBe(key);
    }
  });
});

describe('P0-5-a · extractParameter', () => {
  it('extracts the last query param from a URL', () => {
    expect(extractParameter('https://example.com/search?q=foo&id=42')).toBe('id');
  });

  it('falls back to step text when URL has no params', () => {
    expect(extractParameter('https://example.com/api/users', ['Send GET https://example.com/api/users?userId=5'])).toBe('userId');
  });

  it('returns null when nothing extractable', () => {
    expect(extractParameter('https://example.com/path', ['no parameter mentioned here'])).toBeNull();
  });
});

// ─── P0-5-a + P0-5-b: toMarkdown produces H1-required sections ──────────────

describe('P0-5-a · toMarkdown uses templates when vulnContext present', () => {
  it('xss_reflected report includes Prerequisites and Expected vs Actual from xss template', () => {
    const r: H1Report = {
      ...baseReport,
      vulnContext: {
        type: 'xss_reflected',
        url: 'https://target.com/search?q=test',
        target: 'target.com',
        parameter: 'q',
      },
    };
    const md = generator.toMarkdown(r);
    expect(md).toContain('## Prerequisites');
    expect(md).toContain('## Expected vs Actual Behavior');
    expect(md).toContain('## Affected Scope');
    expect(md).toContain('## Remediation');
    expect(md).toMatch(/cross-site scripting/i);
  });

  it('idor report uses idor template with two-account language', () => {
    const r: H1Report = {
      ...baseReport,
      vulnContext: {
        type: 'idor',
        url: 'https://target.com/api/users/42',
        target: 'target.com',
      },
    };
    const md = generator.toMarkdown(r);
    expect(md).toContain('Two authenticated user accounts');
    expect(md).toContain('## Remediation');
  });

  it('CRITICAL header (severity, bounty, CVSS, CWE) is preserved across template path', () => {
    const r: H1Report = {
      ...baseReport,
      vulnContext: { type: 'xss_dom', url: 'https://t.com/?q=x', target: 't.com' },
    };
    const md = generator.toMarkdown(r);
    expect(md).toMatch(/\*\*Severity:\*\* HIGH/);
    expect(md).toMatch(/\*\*CVSS Score:\*\*\s*7\.5/);
    expect(md).toMatch(/\*\*CWE:\*\*\s*CWE-79/);
  });
});

describe('P0-5-b · inline-build fallback carries all H1 sections', () => {
  it('non-templated vuln type (cache_poisoning) gets all H1 sections', () => {
    const r: H1Report = {
      ...baseReport,
      vulnContext: {
        type: 'cache_poisoning',
        url: 'https://target.com/page',
        target: 'target.com',
      },
    };
    const md = generator.toMarkdown(r);
    expect(md).toContain('## Vulnerability Details');
    expect(md).toContain('## Prerequisites');
    expect(md).toContain('## Description');
    expect(md).toContain('## Steps to Reproduce');
    expect(md).toContain('## Expected vs Actual Behavior');
    expect(md).toContain('## Impact');
    expect(md).toContain('## Affected Scope');
    expect(md).toContain('## Remediation');
  });

  it('cache_poisoning expected/actual mentions cache key normalization', () => {
    const r: H1Report = {
      ...baseReport,
      vulnContext: { type: 'cache_poisoning', url: 'https://t.com/', target: 't.com' },
    };
    const md = generator.toMarkdown(r);
    expect(md).toMatch(/cache.*key|cache-control|cdn/i);
  });

  it('falls back to "other" defaults for unknown vuln type', () => {
    const r: H1Report = {
      ...baseReport,
      vulnContext: { type: 'totally_made_up', url: 'https://t.com/', target: 't.com' },
    };
    const md = generator.toMarkdown(r);
    expect(md).toContain('## Prerequisites');
    expect(md).toContain('## Expected vs Actual Behavior');
    expect(md).toContain('## Remediation');
  });

  it('reports without vulnContext still render (back-compat with test fixtures)', () => {
    // No vulnContext field at all — uses inline path with "other" defaults
    const md = generator.toMarkdown(baseReport);
    expect(md).toContain('## Description');
    expect(md).toContain('## Steps to Reproduce');
    expect(md).toContain('## Impact');
    // Vulnerability Details section requires vulnContext, so it should be absent
    expect(md).not.toContain('## Vulnerability Details');
  });
});

// ─── P0-5-c: Body snippet cap raised to 2000 on most-relevant exchange ──────

describe('P0-5-c · body snippet cap', () => {
  it('most-relevant exchange uses 2000-char cap; others still 500', () => {
    const longBody = 'A'.repeat(3000);
    const exchanges: HttpExchange[] = [
      {
        request: { method: 'GET', url: 'https://t.com/recon' },
        response: { status: 200, bodySnippet: longBody },
      },
      {
        request: { method: 'POST', url: 'https://t.com/exploit', body: 'payload=evil' },
        response: { status: 200, bodySnippet: longBody },
      },
    ];
    const formatted = generator.formatHttpEvidence(exchanges);
    expect(formatted).toBeDefined();
    // Last exchange (most-relevant) gets ~2000 chars before truncation marker
    const lastBlockMatch = formatted!.match(/Response 2[\s\S]+?\[\.\.\.truncated\]/);
    expect(lastBlockMatch).toBeTruthy();
    // First block (less relevant) gets 500 cap
    const firstBlockMatch = formatted!.match(/Response 1[\s\S]+?\[\.\.\.truncated\]/);
    expect(firstBlockMatch).toBeTruthy();
    // First block truncates earlier than last
    expect(firstBlockMatch![0].length).toBeLessThan(lastBlockMatch![0].length);
  });
});

// ─── P0-5-d: Show ≤10 exchanges, ranked by relevance ────────────────────────

describe('P0-5-d · exchange ranking and cap', () => {
  it('caps at 10 exchanges even if more provided', () => {
    const exchanges: HttpExchange[] = Array.from({ length: 20 }, (_, i) => ({
      request: { method: 'GET', url: `https://t.com/e${i}` },
      response: { status: 200, bodySnippet: 'ok' },
    }));
    const formatted = generator.formatHttpEvidence(exchanges);
    expect(formatted).toBeDefined();
    // Count "Request N" labels — should be exactly 10
    const labels = formatted!.match(/\*\*Request \d+:\*\*/g) ?? [];
    expect(labels.length).toBe(10);
  });

  it('ranks non-GET methods higher than GETs (POST appears in displayed set)', () => {
    const exchanges: HttpExchange[] = [
      ...Array.from({ length: 15 }, (_, i) => ({
        request: { method: 'GET' as const, url: `https://t.com/recon${i}` },
        response: { status: 200, bodySnippet: 'fluff' },
      })),
      // The one POST request should be displayed because of the +3 method bonus
      {
        request: { method: 'POST', url: 'https://t.com/exploit', body: 'payload=x' },
        response: { status: 500, bodySnippet: 'database error: SQLSTATE[42000]' },
      },
    ];
    const formatted = generator.formatHttpEvidence(exchanges);
    expect(formatted).toBeDefined();
    expect(formatted).toContain('POST');
    expect(formatted).toContain('SQLSTATE');
  });

  it('preserves original order in display (sorted-after-rank)', () => {
    const exchanges: HttpExchange[] = [
      { request: { method: 'GET', url: 'https://t.com/step1' }, response: { status: 200, bodySnippet: 'first' } },
      { request: { method: 'POST', url: 'https://t.com/step2', body: 'a=1' }, response: { status: 200, bodySnippet: 'second' } },
      { request: { method: 'GET', url: 'https://t.com/step3' }, response: { status: 200, bodySnippet: 'third' } },
    ];
    const formatted = generator.formatHttpEvidence(exchanges);
    expect(formatted).toBeDefined();
    const idx1 = formatted!.indexOf('step1');
    const idx2 = formatted!.indexOf('step2');
    const idx3 = formatted!.indexOf('step3');
    expect(idx1).toBeGreaterThanOrEqual(0);
    expect(idx2).toBeGreaterThan(idx1);
    expect(idx3).toBeGreaterThan(idx2);
  });
});

// ─── P0-5-e: Per-vuln-type evidence checklist ───────────────────────────────

describe('P0-5-e · per-vuln-type evidence checklist enforcement', () => {
  const scorer = new ReportQualityScorer();

  function makeReport(overrides: Partial<H1Report>): H1Report {
    // Build a report that passes the generic quality checks so that any
    // failure we observe is attributable to the vuln-type evidence check.
    return {
      title: '[HIGH] A specific vuln title with enough words to pass clarity check',
      severity: 'high',
      suggestedBounty: { min: 500, max: 1500 },
      description: 'A long-enough description that satisfies the clarity threshold by being more than two hundred characters in length, including some technical details about the vulnerable endpoint, the parameter being abused, and the broken authorization check that allows the issue to occur.',
      impact: 'An attacker can steal sessions, access PII, and modify user state.',
      steps: ['step one with detail', 'step two with detail', 'step three with detail'],
      proof: {},
      cvssScore: 7.5,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      weaknessId: '79',
      httpEvidence: '```http\nGET /endpoint HTTP/1.1\nHost: t.com\n```',
      quickReproduction: '```bash\ncurl https://t.com/endpoint\n```',
      ...overrides,
    };
  }

  it('rejects XSS report without alert(document.domain)', () => {
    const r = makeReport({
      vulnContext: { type: 'xss_reflected', url: 'https://t.com/?q=x', target: 't.com' },
      description: 'Reflected XSS in q parameter — payload is alert(1) which proves nothing about the execution context. ' + 'x'.repeat(150),
    });
    const score = scorer.scoreReport(r);
    expect(score.meetsThreshold).toBe(false);
    expect(score.issues.some(i => i.message.includes('alert(document.domain)'))).toBe(true);
  });

  it('accepts XSS report when alert(document.domain) appears anywhere', () => {
    const r = makeReport({
      vulnContext: { type: 'xss_reflected', url: 'https://t.com/?q=x', target: 't.com' },
      description: 'Reflected XSS in q parameter. PoC uses alert(document.domain) to prove execution context. ' + 'x'.repeat(150),
    });
    const score = scorer.scoreReport(r);
    expect(score.issues.some(i => i.message.includes('alert(document.domain)'))).toBe(false);
  });

  it('rejects open_redirect without a chain', () => {
    const r = makeReport({
      vulnContext: { type: 'open_redirect', url: 'https://t.com/redirect?url=evil.com', target: 't.com' },
    });
    const score = scorer.scoreReport(r);
    expect(score.meetsThreshold).toBe(false);
    expect(score.issues.some(i => i.message.startsWith('Missing required evidence shape for open_redirect'))).toBe(true);
  });

  it('accepts open_redirect when chain to OAuth callback is shown', () => {
    const r = makeReport({
      vulnContext: { type: 'open_redirect', url: 'https://t.com/redirect?url=evil.com', target: 't.com' },
      impact: 'The redirect can be chained with OAuth callback hijack to steal access tokens.',
    });
    const score = scorer.scoreReport(r);
    expect(score.issues.some(i => i.message.startsWith('Missing required evidence shape for open_redirect'))).toBe(false);
  });

  it('rejects IDOR without two-account language', () => {
    const r = makeReport({
      vulnContext: { type: 'idor', url: 'https://t.com/api/users/42', target: 't.com' },
    });
    const score = scorer.scoreReport(r);
    expect(score.meetsThreshold).toBe(false);
    expect(score.issues.some(i => i.message.startsWith('Missing required evidence shape for idor'))).toBe(true);
  });

  it('accepts IDOR when "User A" / "User B" comparison is documented', () => {
    const r = makeReport({
      vulnContext: { type: 'idor', url: 'https://t.com/api/users/42', target: 't.com' },
      description: 'Authenticated as User A, swapping the userId path parameter to User B\'s ID returns User B\'s profile data including PII. Two-account proof captured below. ' + 'x'.repeat(50),
    });
    const score = scorer.scoreReport(r);
    expect(score.issues.some(i => i.message.startsWith('Missing required evidence shape for idor'))).toBe(false);
  });

  it('rejects ssrf_blind without OOB callback proof', () => {
    const r = makeReport({
      vulnContext: { type: 'ssrf_blind', url: 'https://t.com/proxy?url=x', target: 't.com' },
    });
    const score = scorer.scoreReport(r);
    expect(score.meetsThreshold).toBe(false);
    expect(score.issues.some(i => i.message.includes('OOB callback'))).toBe(true);
  });

  it('caps overall at MINIMUM_QUALITY_THRESHOLD-5 (= 55) on missing-evidence', () => {
    const r = makeReport({
      vulnContext: { type: 'idor', url: 'https://t.com/api/users/42', target: 't.com' },
    });
    const score = scorer.scoreReport(r);
    expect(score.overall).toBeLessThanOrEqual(55);
  });

  it('does not check vuln types without an EVIDENCE_REQUIREMENTS entry', () => {
    const r = makeReport({
      vulnContext: { type: 'totally_unmapped_type', url: 'https://t.com/', target: 't.com' },
    });
    const score = scorer.scoreReport(r);
    expect(score.issues.some(i => i.message.startsWith('Missing required evidence shape for'))).toBe(false);
  });

  it('does not check when vulnContext is absent (back-compat)', () => {
    const r = makeReport({});
    const score = scorer.scoreReport(r);
    expect(score.issues.some(i => i.message.startsWith('Missing required evidence shape for'))).toBe(false);
  });
});

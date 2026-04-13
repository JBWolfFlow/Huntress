/**
 * Finding Deduplication — Unit Tests (C3 Cross-Subdomain Dedup)
 *
 * Verifies:
 * 1. extractRootDomain correctly strips subdomains
 * 2. Multi-part TLDs (.co.uk, .com.au) are handled
 * 3. deduplicateFindings collapses same vuln across subdomains
 * 4. Different vuln types on same domain are NOT deduplicated
 * 5. Highest severity wins when duplicates are collapsed
 */

import { describe, it, expect } from 'vitest';
import { extractRootDomain, deduplicateFindings } from './finding_dedup';
import type { AgentFinding } from '../../agents/base_agent';

// ─── extractRootDomain ──────────────────────────────────────────────────────

describe('extractRootDomain', () => {
  it('strips subdomain from standard domain', () => {
    expect(extractRootDomain('api.walletbot.me')).toBe('walletbot.me');
    expect(extractRootDomain('www.walletbot.me')).toBe('walletbot.me');
    expect(extractRootDomain('p2p.walletbot.me')).toBe('walletbot.me');
  });

  it('returns root domain unchanged', () => {
    expect(extractRootDomain('walletbot.me')).toBe('walletbot.me');
    expect(extractRootDomain('example.com')).toBe('example.com');
  });

  it('handles deeply nested subdomains', () => {
    expect(extractRootDomain('a.b.c.example.com')).toBe('example.com');
  });

  it('handles multi-part TLDs', () => {
    expect(extractRootDomain('api.example.co.uk')).toBe('example.co.uk');
    expect(extractRootDomain('www.shop.com.au')).toBe('shop.com.au');
    expect(extractRootDomain('mail.example.co.jp')).toBe('example.co.jp');
  });

  it('returns multi-part TLD domain unchanged when already root', () => {
    expect(extractRootDomain('example.co.uk')).toBe('example.co.uk');
  });

  it('passes through IP addresses unchanged', () => {
    expect(extractRootDomain('192.168.1.1')).toBe('192.168.1.1');
    expect(extractRootDomain('10.0.0.42')).toBe('10.0.0.42');
  });

  it('passes through localhost unchanged', () => {
    expect(extractRootDomain('localhost')).toBe('localhost');
  });

  it('handles single-label hostnames', () => {
    expect(extractRootDomain('intranet')).toBe('intranet');
  });
});

// ─── Cross-Subdomain Deduplication ──────────────────────────────────────────

function makeFinding(overrides: Partial<AgentFinding> & { target: string; type: string; severity: string }): AgentFinding {
  return {
    id: `f_${Math.random().toString(36).slice(2, 8)}`,
    title: 'Test Finding',
    description: 'Test description',
    evidence: [],
    confidence: 80,
    agentId: 'test-agent',
    ...overrides,
  } as AgentFinding;
}

describe('deduplicateFindings — cross-subdomain (C3)', () => {
  it('collapses same vuln type across subdomains to 1 finding', () => {
    const findings = [
      makeFinding({
        target: 'https://api.walletbot.me/health',
        type: 'cors_misconfiguration',
        severity: 'medium',
        title: 'CORS on api.walletbot.me',
      }),
      makeFinding({
        target: 'https://www.walletbot.me/api',
        type: 'cors_misconfiguration',
        severity: 'high',
        title: 'CORS on www.walletbot.me',
      }),
      makeFinding({
        target: 'https://p2p.walletbot.me/ws',
        type: 'cors_misconfiguration',
        severity: 'low',
        title: 'CORS on p2p.walletbot.me',
      }),
    ];

    const deduped = deduplicateFindings(findings);
    expect(deduped).toHaveLength(1);
    // Highest severity wins
    expect(deduped[0].severity).toBe('high');
  });

  it('does NOT dedup different vuln types on same domain', () => {
    const findings = [
      makeFinding({
        target: 'https://api.example.com/users',
        type: 'cors_misconfiguration',
        severity: 'medium',
      }),
      makeFinding({
        target: 'https://api.example.com/users',
        type: 'host_header_injection',
        severity: 'low',
      }),
    ];

    const deduped = deduplicateFindings(findings);
    expect(deduped).toHaveLength(2);
  });

  it('does NOT dedup same vuln type on different root domains', () => {
    const findings = [
      makeFinding({
        target: 'https://api.walletbot.me/health',
        type: 'cors_misconfiguration',
        severity: 'medium',
      }),
      makeFinding({
        target: 'https://api.wallettg.com/health',
        type: 'cors_misconfiguration',
        severity: 'medium',
      }),
    ];

    const deduped = deduplicateFindings(findings);
    expect(deduped).toHaveLength(2);
  });

  it('keeps different parameters as separate findings', () => {
    const findings = [
      makeFinding({
        target: 'https://api.example.com/search?q=test',
        type: 'xss_reflected',
        severity: 'high',
        evidence: ['?q=<script>alert(1)</script>'],
      }),
      makeFinding({
        target: 'https://api.example.com/search?name=test',
        type: 'xss_reflected',
        severity: 'high',
        evidence: ['?name=<script>alert(1)</script>'],
      }),
    ];

    const deduped = deduplicateFindings(findings);
    expect(deduped).toHaveLength(2);
  });

  it('highest severity wins when collapsing', () => {
    const findings = [
      makeFinding({
        target: 'https://www.example.com/page',
        type: 'xss_stored',
        severity: 'critical',
      }),
      makeFinding({
        target: 'https://cdn.example.com/page',
        type: 'xss_stored',
        severity: 'medium',
      }),
    ];

    const deduped = deduplicateFindings(findings);
    expect(deduped).toHaveLength(1);
    expect(deduped[0].severity).toBe('critical');
  });
});

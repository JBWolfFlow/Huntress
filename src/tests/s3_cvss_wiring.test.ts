/**
 * Session 12 — S3: Wire Real CVSS Calculator into PoC Generator
 *
 * Tests that:
 * 1. estimateMetrics maps vuln types to correct CVSS vectors
 * 2. calculateCVSS produces correct scores from vectors
 * 3. XSS finding → correct CVSS vector and score
 * 4. SQLi finding → different vector with higher score
 * 5. Score falls within the correct severity range
 * 6. Vector string format matches CVSS 3.1 spec
 */

import { describe, it, expect } from 'vitest';
import { calculateCVSS, estimateMetrics } from '../core/reporting/cvss_calculator';

describe('S3: CVSS Calculator integration', () => {
  it('XSS reflected produces correct CVSS vector', () => {
    const metrics = estimateMetrics('xss_reflected');
    const result = calculateCVSS(metrics);

    // XSS reflected: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
    expect(result.vectorString).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N');
    expect(result.score).toBeGreaterThan(0);
    expect(result.severity).toBe('Medium');
    // CVSS 3.1 spec: reflected XSS should score 6.1
    expect(result.score).toBe(6.1);
  });

  it('SQLi error produces different, higher-scored vector', () => {
    const metrics = estimateMetrics('sqli_error');
    const result = calculateCVSS(metrics);

    // SQLi: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    expect(result.vectorString).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    // SQLi with full CIA impact is 9.8 Critical
    expect(result.score).toBeGreaterThanOrEqual(9.0);
    expect(result.severity).toBe('Critical');
  });

  it('SSRF produces a high/critical score with scope change', () => {
    const metrics = estimateMetrics('ssrf');
    const result = calculateCVSS(metrics);

    expect(result.vectorString).toContain('S:C'); // Scope Changed
    expect(result.score).toBeGreaterThanOrEqual(7.0);
  });

  it('Open redirect produces a low-to-medium score', () => {
    const metrics = estimateMetrics('open_redirect');
    const result = calculateCVSS(metrics);

    // Open redirect: AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N → 4.3 Medium per CVSS 3.1
    expect(result.score).toBeLessThanOrEqual(6.9);
    expect(['Low', 'Medium']).toContain(result.severity);
  });

  it('RCE produces a critical score', () => {
    const metrics = estimateMetrics('rce');
    const result = calculateCVSS(metrics);

    expect(result.score).toBeGreaterThanOrEqual(9.0);
    expect(result.severity).toBe('Critical');
  });

  it('unknown vuln type gets reasonable defaults', () => {
    const metrics = estimateMetrics('unknown_vuln_type_xyz');
    const result = calculateCVSS(metrics);

    // Should still produce a valid result
    expect(result.score).toBeGreaterThan(0);
    expect(result.vectorString).toContain('CVSS:3.1/');
    expect(['None', 'Low', 'Medium', 'High', 'Critical']).toContain(result.severity);
  });
});

describe('S3: CVSS score-severity alignment', () => {
  const vulnTypes = [
    'xss_reflected', 'xss_stored', 'xss_dom',
    'sqli_error', 'sqli_blind_time', 'sqli_blind_boolean',
    'ssrf', 'ssrf_blind', 'idor', 'ssti', 'rce',
    'open_redirect', 'cors_misconfiguration', 'subdomain_takeover',
  ];

  for (const vulnType of vulnTypes) {
    it(`${vulnType}: score matches declared severity range`, () => {
      const metrics = estimateMetrics(vulnType);
      const result = calculateCVSS(metrics);

      // Verify score falls within the correct severity range
      switch (result.severity) {
        case 'None':
          expect(result.score).toBe(0);
          break;
        case 'Low':
          expect(result.score).toBeGreaterThanOrEqual(0.1);
          expect(result.score).toBeLessThanOrEqual(3.9);
          break;
        case 'Medium':
          expect(result.score).toBeGreaterThanOrEqual(4.0);
          expect(result.score).toBeLessThanOrEqual(6.9);
          break;
        case 'High':
          expect(result.score).toBeGreaterThanOrEqual(7.0);
          expect(result.score).toBeLessThanOrEqual(8.9);
          break;
        case 'Critical':
          expect(result.score).toBeGreaterThanOrEqual(9.0);
          expect(result.score).toBeLessThanOrEqual(10.0);
          break;
      }
    });
  }
});

describe('S3: CVSS vector string format', () => {
  it('vector string matches CVSS 3.1 format', () => {
    const metrics = estimateMetrics('xss_reflected');
    const result = calculateCVSS(metrics);

    // Must start with CVSS:3.1/
    expect(result.vectorString).toMatch(/^CVSS:3\.1\//);

    // Must contain all 8 metrics in order
    expect(result.vectorString).toMatch(
      /^CVSS:3\.1\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]$/
    );
  });

  it('different vuln types produce different vectors', () => {
    const xss = calculateCVSS(estimateMetrics('xss_reflected'));
    const sqli = calculateCVSS(estimateMetrics('sqli_error'));

    expect(xss.vectorString).not.toBe(sqli.vectorString);
    expect(xss.score).not.toBe(sqli.score);
  });
});

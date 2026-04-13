/**
 * Hunt #7 Bug Fix — H23: Evidence Normalization
 *
 * Tests that normalizeEvidence() handles all shapes LLM agents may return:
 * string, string[], undefined, null, object, number, mixed arrays.
 * Ensures f.evidence.join() can never crash in the finding pipeline.
 */

import { describe, it, expect } from 'vitest';
import { normalizeEvidence } from '../core/orchestrator/orchestrator_engine';

describe('normalizeEvidence', () => {
  it('passes through a valid string array unchanged', () => {
    const input = ['step 1', 'step 2', 'step 3'];
    expect(normalizeEvidence(input)).toEqual(['step 1', 'step 2', 'step 3']);
  });

  it('wraps a plain string in an array', () => {
    const input = 'single evidence string';
    expect(normalizeEvidence(input)).toEqual(['single evidence string']);
  });

  it('returns empty array for undefined', () => {
    expect(normalizeEvidence(undefined)).toEqual([]);
  });

  it('returns empty array for null', () => {
    expect(normalizeEvidence(null)).toEqual([]);
  });

  it('JSON-stringifies a plain object', () => {
    const input = { url: 'http://example.com', status: 200 };
    const result = normalizeEvidence(input);
    expect(result).toHaveLength(1);
    expect(JSON.parse(result[0])).toEqual(input);
  });

  it('JSON-stringifies a number', () => {
    expect(normalizeEvidence(42)).toEqual(['42']);
  });

  it('JSON-stringifies a boolean', () => {
    expect(normalizeEvidence(true)).toEqual(['true']);
  });

  it('handles mixed arrays (strings + objects + numbers)', () => {
    const input = ['valid string', { key: 'value' }, 42, null];
    const result = normalizeEvidence(input);
    expect(result).toHaveLength(4);
    expect(result[0]).toBe('valid string');
    expect(result[1]).toBe('{"key":"value"}');
    expect(result[2]).toBe('42');
    expect(result[3]).toBe('null');
  });

  it('handles empty array', () => {
    expect(normalizeEvidence([])).toEqual([]);
  });

  it('result is always safe to call .join() on', () => {
    const shapes: unknown[] = [
      'string',
      ['array'],
      undefined,
      null,
      { obj: true },
      42,
      true,
      [1, 'mixed', { x: 1 }],
    ];

    for (const shape of shapes) {
      const result = normalizeEvidence(shape);
      // This is the exact call that crashed in Hunt #7 — must never throw
      expect(() => result.join('\n')).not.toThrow();
      // Must also be safe for for..of iteration
      expect(() => { for (const _ev of result) { /* noop */ } }).not.toThrow();
      // Must also be safe for .map()
      expect(() => result.map(e => e.toUpperCase())).not.toThrow();
    }
  });
});

describe('evidence normalization in finding pipeline', () => {
  it('Hunt #7 crash scenario: string evidence does not crash .join()', () => {
    // This is the exact scenario from open-redirect-hunter in Hunt #7
    const finding = {
      id: 'test-001',
      agentId: 'open-redirect-hunter',
      type: 'open_redirect',
      title: 'Open Redirect in /redirect',
      severity: 'medium' as const,
      description: 'Redirect parameter accepts external URLs',
      target: 'https://example.com/redirect',
      evidence: 'Server returned 302 to attacker domain' as unknown as string[],
      reproduction: ['Send GET /redirect?url=http://evil.com'],
      timestamp: new Date(),
    };

    // Normalize at pipeline boundary
    finding.evidence = normalizeEvidence(finding.evidence);

    // These calls crashed in Hunt #7 — now must succeed
    expect(() => finding.evidence.join('\n')).not.toThrow();
    expect(finding.evidence).toEqual(['Server returned 302 to attacker domain']);
  });

  it('Hunt #7 crash scenario: object evidence does not crash .join()', () => {
    const finding = {
      id: 'test-002',
      agentId: 'host-header-hunter',
      type: 'host_header_injection',
      title: 'Host Header Injection',
      severity: 'medium' as const,
      description: 'X-Forwarded-Host accepted',
      target: 'https://example.com',
      evidence: { request: 'GET /', response: '200 OK' } as unknown as string[],
      reproduction: ['Send request with X-Forwarded-Host: evil.com'],
      timestamp: new Date(),
    };

    finding.evidence = normalizeEvidence(finding.evidence);

    expect(() => finding.evidence.join('\n')).not.toThrow();
    expect(finding.evidence).toHaveLength(1);
    expect(JSON.parse(finding.evidence[0])).toEqual({ request: 'GET /', response: '200 OK' });
  });

  it('Hunt #7 crash scenario: undefined evidence does not crash for..of', () => {
    const finding = {
      id: 'test-003',
      agentId: 'cors-hunter',
      type: 'cors_misconfiguration',
      title: 'CORS allows arbitrary origins',
      severity: 'high' as const,
      description: 'CORS reflects Origin header',
      target: 'https://example.com/api',
      evidence: undefined as unknown as string[],
      reproduction: [],
      timestamp: new Date(),
    };

    finding.evidence = normalizeEvidence(finding.evidence);

    // The for..of loop at line 2354 in orchestrator_engine.ts
    const urls: string[] = [];
    expect(() => {
      for (const ev of finding.evidence) {
        const found = ev.match(/https?:\/\/[^\s"'<>]+/g);
        if (found) urls.push(...found);
      }
    }).not.toThrow();
    expect(urls).toEqual([]);
  });

  it('585 hallucinated findings all normalize without crash', () => {
    // Simulates the OAuth Hunter scenario — mass findings with varied evidence shapes
    const shapes: unknown[] = [
      'string evidence',
      ['array', 'evidence'],
      undefined,
      null,
      { status: 200 },
      42,
    ];

    for (let i = 0; i < 585; i++) {
      const evidence = shapes[i % shapes.length];
      const normalized = normalizeEvidence(evidence);
      expect(() => normalized.join('\n')).not.toThrow();
    }
  });
});

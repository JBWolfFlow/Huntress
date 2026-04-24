/**
 * Recon endpoint-observation scope filter (2026-04-23)
 *
 * The 2026-04-23 Juice Shop hunt harvested `http://www.w3.org/TR/xhtml11/DTD/
 * xhtml11.dtd` — an HTML DTD schema reference — as an "endpoint" and
 * dispatched SSTI/XSS specialists against it. `isUrlInReconScope` drops
 * anything whose host is outside the hunt's scope so the noise stops
 * driving dispatch. Semantics are subdomain-friendly because recon
 * enumerates subdomains of the listed targets.
 */
import { describe, it, expect } from 'vitest';
import { isUrlInReconScope } from '../agents/recon_agent';

describe('isUrlInReconScope', () => {
  it('accepts exact hostname match against a bare scope entry', () => {
    expect(isUrlInReconScope('http://localhost:3001/rest', ['localhost:3001'])).toBe(true);
    expect(isUrlInReconScope('https://example.com/api', ['example.com'])).toBe(true);
  });

  it('accepts subdomains of a bare scope entry (recon intent)', () => {
    expect(isUrlInReconScope('https://api.example.com/v1', ['example.com'])).toBe(true);
    expect(isUrlInReconScope('https://staging.api.example.com/x', ['example.com'])).toBe(true);
  });

  it('drops the W3C DTD noise that triggered this fix', () => {
    expect(
      isUrlInReconScope('http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd', ['localhost:3001']),
    ).toBe(false);
  });

  it('drops unrelated hosts', () => {
    expect(isUrlInReconScope('https://google.com/search', ['example.com'])).toBe(false);
    expect(isUrlInReconScope('https://evil.org/', ['example.com', 'api.other.com'])).toBe(false);
  });

  it('does not false-match on substring hostnames', () => {
    // `badexample.com` is not a subdomain of `example.com` — the dot matters.
    expect(isUrlInReconScope('https://badexample.com/', ['example.com'])).toBe(false);
    // `example.com.evil.org` would only match if evil.org is in scope.
    expect(isUrlInReconScope('https://example.com.evil.org/', ['example.com'])).toBe(false);
  });

  it('treats wildcard entries as equivalent to their bare form', () => {
    expect(isUrlInReconScope('https://api.example.com/x', ['*.example.com'])).toBe(true);
    expect(isUrlInReconScope('https://example.com/x', ['*.example.com'])).toBe(true);
  });

  it('handles URL-formatted scope entries', () => {
    expect(isUrlInReconScope('https://api.example.com/', ['https://example.com'])).toBe(true);
  });

  it('handles scope entries with ports', () => {
    expect(isUrlInReconScope('http://localhost:3001/rest', ['localhost:3001'])).toBe(true);
    expect(isUrlInReconScope('http://localhost/rest', ['localhost:3001'])).toBe(true);
  });

  it('skips blank scope entries without throwing', () => {
    expect(isUrlInReconScope('https://example.com/', ['', '  ', 'example.com'])).toBe(true);
    expect(isUrlInReconScope('https://example.com/', ['', '  '])).toBe(false);
  });

  it('returns false for invalid URLs', () => {
    expect(isUrlInReconScope('not-a-url', ['example.com'])).toBe(false);
    expect(isUrlInReconScope('', ['example.com'])).toBe(false);
  });

  it('is case-insensitive on hostnames', () => {
    expect(isUrlInReconScope('https://API.Example.COM/', ['example.com'])).toBe(true);
    expect(isUrlInReconScope('https://api.example.com/', ['Example.COM'])).toBe(true);
  });
});

/**
 * Phase 1 / Q6 Gap 7 — request_engine cross-origin header stripping tests
 *
 * Covers: origin detection, cross-origin predicate, sensitive-header
 * classification (well-known + custom patterns), and the full
 * stripCrossOriginAuthHeaders helper on same-origin vs cross-origin hops.
 */

import { describe, it, expect } from 'vitest';
import {
  getOrigin,
  isCrossOrigin,
  isSensitiveAuthHeaderName,
  stripCrossOriginAuthHeaders,
  WELL_KNOWN_AUTH_HEADERS,
} from '../core/http/request_engine';

describe('getOrigin (Q6 Gap 7)', () => {
  it('returns scheme://host for an absolute URL', () => {
    expect(getOrigin('https://a.example.com/path?q=1')).toBe('https://a.example.com');
  });

  it('includes the port when it is non-default', () => {
    expect(getOrigin('http://localhost:3001/api')).toBe('http://localhost:3001');
  });

  it('returns null for an unparseable URL', () => {
    expect(getOrigin('not a url')).toBeNull();
    expect(getOrigin('')).toBeNull();
  });
});

describe('isCrossOrigin (Q6 Gap 7)', () => {
  it('returns false for same origin', () => {
    expect(isCrossOrigin(
      'https://target.com/a',
      'https://target.com/b',
    )).toBe(false);
  });

  it('returns true for different host', () => {
    expect(isCrossOrigin(
      'https://a.example.com/x',
      'https://b.example.com/x',
    )).toBe(true);
  });

  it('returns true for different scheme (http→https)', () => {
    expect(isCrossOrigin('http://target.com', 'https://target.com')).toBe(true);
  });

  it('returns true for different port (considered separate origins)', () => {
    expect(isCrossOrigin(
      'http://target.com:80/a',
      'http://target.com:8080/a',
    )).toBe(true);
  });

  it('fails safe to cross-origin on unparseable input', () => {
    expect(isCrossOrigin('garbage', 'https://target.com')).toBe(true);
    expect(isCrossOrigin('https://target.com', '')).toBe(true);
  });
});

describe('isSensitiveAuthHeaderName (Q6 Gap 7)', () => {
  it('flags all four well-known auth headers case-insensitively', () => {
    for (const name of WELL_KNOWN_AUTH_HEADERS) {
      expect(isSensitiveAuthHeaderName(name)).toBe(true);
      expect(isSensitiveAuthHeaderName(name.toUpperCase())).toBe(true);
    }
  });

  it('flags wallet-authorization and other *-authorization headers', () => {
    expect(isSensitiveAuthHeaderName('wallet-authorization')).toBe(true);
    expect(isSensitiveAuthHeaderName('Wallet-Authorization')).toBe(true);
    expect(isSensitiveAuthHeaderName('x-vendor-authorization')).toBe(true);
  });

  it('flags X-API-Key and similar API key variants', () => {
    expect(isSensitiveAuthHeaderName('x-api-key')).toBe(true);
    expect(isSensitiveAuthHeaderName('api-key')).toBe(true);
    expect(isSensitiveAuthHeaderName('X-Api-Key')).toBe(true);
  });

  it('flags CSRF / XSRF token headers', () => {
    expect(isSensitiveAuthHeaderName('X-CSRF-Token')).toBe(true);
    expect(isSensitiveAuthHeaderName('csrf-token')).toBe(true);
    expect(isSensitiveAuthHeaderName('X-XSRF-Token')).toBe(true);
  });

  it('flags x-wallet-device-serial (Telegram Wallet)', () => {
    expect(isSensitiveAuthHeaderName('x-wallet-device-serial')).toBe(true);
  });

  it('does NOT flag generic non-auth headers (false-positive guard)', () => {
    expect(isSensitiveAuthHeaderName('User-Agent')).toBe(false);
    expect(isSensitiveAuthHeaderName('Accept')).toBe(false);
    expect(isSensitiveAuthHeaderName('Content-Type')).toBe(false);
    expect(isSensitiveAuthHeaderName('X-Forwarded-For')).toBe(false);
    expect(isSensitiveAuthHeaderName('X-Request-Id')).toBe(false);
  });
});

describe('stripCrossOriginAuthHeaders (Q6 Gap 7)', () => {
  const headers = {
    Authorization: 'Bearer abc',
    Cookie: 'sid=1',
    'wallet-authorization': 'jwt.x.y',
    'x-wallet-device-serial': 'uuid',
    'User-Agent': 'huntress/1.0',
    Accept: 'application/json',
  };

  it('returns unchanged headers for same-origin redirects', () => {
    const r = stripCrossOriginAuthHeaders(
      headers,
      'https://target.com/a',
      'https://target.com/b',
    );
    expect(r.headers).toEqual(headers);
    expect(r.stripped).toEqual([]);
  });

  it('strips Authorization + Cookie + custom auth on cross-origin', () => {
    const r = stripCrossOriginAuthHeaders(
      headers,
      'https://target.com',
      'https://evil.example.com',
    );
    expect(r.headers.Authorization).toBeUndefined();
    expect(r.headers.Cookie).toBeUndefined();
    expect(r.headers['wallet-authorization']).toBeUndefined();
    expect(r.headers['x-wallet-device-serial']).toBeUndefined();
    // Non-sensitive headers survive.
    expect(r.headers['User-Agent']).toBe('huntress/1.0');
    expect(r.headers.Accept).toBe('application/json');
    // Stripped list is accurate for audit.
    expect(r.stripped).toEqual(
      expect.arrayContaining([
        'Authorization', 'Cookie', 'wallet-authorization', 'x-wallet-device-serial',
      ]),
    );
    expect(r.stripped).toHaveLength(4);
  });

  it('does not mutate the input headers object', () => {
    const original = { ...headers };
    stripCrossOriginAuthHeaders(
      original,
      'https://target.com',
      'https://other.com',
    );
    // Input object must be unchanged — caller may still use it.
    expect(original).toEqual(headers);
  });

  it('treats scheme change (http→https) on the same host as cross-origin', () => {
    const r = stripCrossOriginAuthHeaders(
      { Authorization: 'Bearer x' },
      'http://target.com/login',
      'https://target.com/login',
    );
    expect(r.headers.Authorization).toBeUndefined();
  });
});

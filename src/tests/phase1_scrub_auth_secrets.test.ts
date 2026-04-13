/**
 * Phase 1 / Q1 — scrubAuthSecrets tests
 *
 * Agents run shell tools inside the sandbox where HUNTRESS_AUTH_* env vars
 * are set. When `curl -v` prints outgoing headers, those headers enter the
 * agent's tool_result and then the LLM context. scrubAuthSecrets is the
 * last line of defense against tokens landing in findings evidence.
 */

import { describe, it, expect } from 'vitest';
import { scrubAuthSecrets } from '../core/engine/react_loop';

describe('scrubAuthSecrets — token redaction (Q1)', () => {
  it('returns empty/undefined input unchanged', () => {
    expect(scrubAuthSecrets('')).toBe('');
  });

  it('redacts Authorization: Bearer <token>', () => {
    const input = '> Authorization: Bearer eyJabc.DEF.ghi\n> Accept: */*';
    const out = scrubAuthSecrets(input);
    expect(out).toContain('Authorization: Bearer <REDACTED>');
    expect(out).not.toContain('eyJabc.DEF.ghi');
    // Accept header untouched
    expect(out).toContain('Accept: */*');
  });

  it('redacts Authorization: Basic <b64> and Token forms', () => {
    expect(scrubAuthSecrets('Authorization: Basic dXNlcjpwYXNz'))
      .toContain('Authorization: Basic <REDACTED>');
    expect(scrubAuthSecrets('authorization: Token abc123def'))
      .toContain('<REDACTED>');
  });

  it('redacts full Cookie header values', () => {
    const input = 'Cookie: sid=abc123; csrf=xyz789; _ga=GA1.2.3\nContent-Length: 0';
    const out = scrubAuthSecrets(input);
    expect(out).toContain('Cookie: <REDACTED>');
    expect(out).not.toContain('abc123');
    expect(out).not.toContain('GA1.2.3');
    expect(out).toContain('Content-Length: 0');
  });

  it('redacts Set-Cookie values (value fully scrubbed)', () => {
    // The Cookie rule matches Set-Cookie too (greedy, safer default):
    // the whole cookie name+value pair after `Set-Cookie:` is redacted,
    // not just the value. This is intentional — a cookie NAME like
    // `jwt_for_user_daisy` can itself leak PII, so full redaction wins.
    const input = 'Set-Cookie: session_id=abc123def456ghi789; HttpOnly';
    const out = scrubAuthSecrets(input);
    expect(out).toMatch(/Set-Cookie:\s*<REDACTED>/);
    expect(out).not.toContain('abc123def456ghi789');
  });

  it('redacts wallet-authorization (Telegram) and other *-authorization headers', () => {
    const input = 'wallet-authorization: eyJalg.body.signature\nUser-Agent: curl/8';
    const out = scrubAuthSecrets(input);
    expect(out).toContain('wallet-authorization: <REDACTED>');
    expect(out).not.toContain('eyJalg.body.signature');
    expect(out).toContain('User-Agent: curl/8');
  });

  it('redacts x-api-key, csrf-token, xsrf-token header values', () => {
    expect(scrubAuthSecrets('x-api-key: sk_live_abcdef123456'))
      .toContain('x-api-key: <REDACTED>');
    expect(scrubAuthSecrets('X-CSRF-Token: randomnonce123'))
      .toContain('X-CSRF-Token: <REDACTED>');
    expect(scrubAuthSecrets('X-XSRF-Token: anotherNonce'))
      .toContain('X-XSRF-Token: <REDACTED>');
  });

  it('redacts x-wallet-device-serial (Telegram Wallet)', () => {
    const input = 'x-wallet-device-serial: 12345678-aaaa-bbbb-cccc-dddddddddddd';
    const out = scrubAuthSecrets(input);
    expect(out).toContain('x-wallet-device-serial: <REDACTED>');
    expect(out).not.toContain('12345678-aaaa-bbbb-cccc-dddddddddddd');
  });

  it('redacts standalone JWT-shaped tokens anywhere in the stream', () => {
    // `curl -v` sometimes logs the raw token as part of a debug line that
    // isn't a full `Authorization:` header — still must be scrubbed.
    const input = 'debug: decoded token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.ABCxyz';
    const out = scrubAuthSecrets(input);
    expect(out).toContain('<REDACTED_JWT>');
    expect(out).not.toContain('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.ABCxyz');
  });

  it('preserves non-sensitive lines verbatim', () => {
    const input = [
      'HTTP/1.1 200 OK',
      'Content-Type: application/json',
      '{"status":"ok","count":42}',
    ].join('\n');
    expect(scrubAuthSecrets(input)).toBe(input);
  });

  it('handles multi-line output with mixed sensitive + harmless content', () => {
    const input = [
      '> GET /api/me HTTP/1.1',
      '> Authorization: Bearer eyJfake.token.here',
      '> User-Agent: curl/8.0',
      '< HTTP/1.1 200 OK',
      '< Content-Type: application/json',
      '{"user":"daisy"}',
    ].join('\n');
    const out = scrubAuthSecrets(input);
    // Sensitive line scrubbed
    expect(out).toContain('Authorization: Bearer <REDACTED>');
    expect(out).not.toContain('eyJfake.token.here');
    // Benign lines preserved
    expect(out).toContain('User-Agent: curl/8.0');
    expect(out).toContain('"user":"daisy"');
    expect(out).toContain('GET /api/me HTTP/1.1');
  });
});

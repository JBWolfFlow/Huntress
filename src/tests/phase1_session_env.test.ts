/**
 * Phase 1 / Q1 — session_env.ts tests
 *
 * Covers: env var canonicalization, curlrc generation, defensive filtering,
 * multi-header + cookie + CSRF composition, empty-session passthrough.
 */

import { describe, it, expect } from 'vitest';
import {
  buildSessionEnv,
  describeSession,
  headerNameToEnvVar,
} from '../core/auth/session_env';
import type { AuthenticatedSession } from '../core/auth/session_manager';
import type { Cookie } from '../core/http/request_engine';

function cookie(name: string, value: string, domain = 'target.com'): Cookie {
  return { name, value, domain, path: '/', httpOnly: false, secure: false };
}

function session(overrides: Partial<AuthenticatedSession> = {}): AuthenticatedSession {
  return {
    id: 'sess-1',
    label: 'test',
    authType: 'bearer',
    cookies: [],
    headers: {},
    createdAt: Date.now(),
    ...overrides,
  };
}

describe('headerNameToEnvVar canonicalization (Q1)', () => {
  it('uppercases and replaces hyphens with underscores', () => {
    expect(headerNameToEnvVar('Authorization')).toBe('HUNTRESS_AUTH_AUTHORIZATION');
    expect(headerNameToEnvVar('X-API-Key')).toBe('HUNTRESS_AUTH_X_API_KEY');
    expect(headerNameToEnvVar('wallet-authorization'))
      .toBe('HUNTRESS_AUTH_WALLET_AUTHORIZATION');
    expect(headerNameToEnvVar('x-wallet-device-serial'))
      .toBe('HUNTRESS_AUTH_X_WALLET_DEVICE_SERIAL');
  });
});

describe('buildSessionEnv (Q1)', () => {
  it('returns empty bundle when session is undefined', () => {
    const env = buildSessionEnv(undefined);
    expect(env.envVars).toEqual({});
    expect(env.curlrcContent).toBe('');
    expect(env.promptSummary).toBe('no active session');
  });

  it('canonicalizes a bearer token header into HUNTRESS_AUTH_AUTHORIZATION', () => {
    const s = session({
      authType: 'bearer',
      headers: { Authorization: 'Bearer jwt.abc.xyz' },
    });
    const env = buildSessionEnv(s);
    expect(env.envVars.HUNTRESS_AUTH_AUTHORIZATION).toBe('Bearer jwt.abc.xyz');
    expect(env.curlrcContent).toContain('header = "Authorization: Bearer jwt.abc.xyz"');
    // Defaults must be present so curl doesn't dump progress bars into agent output.
    expect(env.curlrcContent).toContain('silent');
    expect(env.curlrcContent).toContain('show-error');
  });

  it('handles multiple custom headers (Telegram-style) in one session', () => {
    const s = session({
      authType: 'custom_header',
      headers: {
        'wallet-authorization': 'jwt.token.here',
        'x-wallet-device-serial': 'device-uuid-123',
      },
    });
    const env = buildSessionEnv(s);
    expect(env.envVars.HUNTRESS_AUTH_WALLET_AUTHORIZATION).toBe('jwt.token.here');
    expect(env.envVars.HUNTRESS_AUTH_X_WALLET_DEVICE_SERIAL).toBe('device-uuid-123');
    expect(env.curlrcContent).toContain('header = "wallet-authorization: jwt.token.here"');
    expect(env.curlrcContent).toContain('header = "x-wallet-device-serial: device-uuid-123"');
  });

  it('joins cookies into HUNTRESS_AUTH_COOKIE and emits a curlrc cookie directive', () => {
    const s = session({
      authType: 'cookie',
      cookies: [
        cookie('session_id', 'sess-xyz'),
        cookie('csrf', 'csrf-abc'),
      ],
    });
    const env = buildSessionEnv(s);
    expect(env.envVars.HUNTRESS_AUTH_COOKIE).toBe('session_id=sess-xyz; csrf=csrf-abc');
    expect(env.curlrcContent).toContain('cookie = "session_id=sess-xyz; csrf=csrf-abc"');
  });

  it('emits CSRF token as HUNTRESS_AUTH_CSRF_TOKEN and X-CSRF-Token header', () => {
    const s = session({
      authType: 'cookie',
      csrfToken: 'csrf-nonce-777',
    });
    const env = buildSessionEnv(s);
    expect(env.envVars.HUNTRESS_AUTH_CSRF_TOKEN).toBe('csrf-nonce-777');
    expect(env.curlrcContent).toContain('header = "X-CSRF-Token: csrf-nonce-777"');
  });

  it('defensively drops header values containing null bytes or newlines', () => {
    // Rust validate_env rejects these — TS layer must filter first so the
    // sandbox create call doesn't fail and abort the hunt.
    const s = session({
      authType: 'custom_header',
      headers: {
        'Safe-Header': 'ok-value',
        'Bad-Header': 'line-one\nline-two',
        'Null-Header': 'contains\0null',
        'Cr-Header': 'carriage\rreturn',
      },
    });
    const env = buildSessionEnv(s);
    expect(env.envVars.HUNTRESS_AUTH_SAFE_HEADER).toBe('ok-value');
    expect(env.envVars.HUNTRESS_AUTH_BAD_HEADER).toBeUndefined();
    expect(env.envVars.HUNTRESS_AUTH_NULL_HEADER).toBeUndefined();
    expect(env.envVars.HUNTRESS_AUTH_CR_HEADER).toBeUndefined();
  });

  it('skips falsy header values', () => {
    const s = session({
      headers: { 'X-Real': 'present', 'X-Empty': '' },
    });
    const env = buildSessionEnv(s);
    expect(env.envVars.HUNTRESS_AUTH_X_REAL).toBe('present');
    expect(env.envVars.HUNTRESS_AUTH_X_EMPTY).toBeUndefined();
  });

  it('escapes embedded quotes and backslashes in curlrc values', () => {
    const s = session({
      headers: { 'X-Weird': 'value with "quote" and \\backslash' },
    });
    const env = buildSessionEnv(s);
    // Backslash doubled, quote backslash-escaped — curl config parser rules.
    expect(env.curlrcContent).toContain(
      'header = "X-Weird: value with \\"quote\\" and \\\\backslash"',
    );
  });

  it('omits curlrc body when only the silent/show-error defaults would be present', () => {
    const env = buildSessionEnv(session());
    expect(env.curlrcContent).toBe('');
  });
});

describe('describeSession summary (Q1)', () => {
  it('lists label, type, headers, cookies, and csrf presence', () => {
    const s = session({
      label: 'victim',
      authType: 'bearer',
      headers: { Authorization: 'Bearer t' },
      cookies: [cookie('c', 'v')],
      csrfToken: 'x',
    });
    const summary = describeSession(s);
    expect(summary).toContain('label="victim"');
    expect(summary).toContain('type=bearer');
    expect(summary).toContain('headers=[Authorization]');
    expect(summary).toContain('cookies=1');
    expect(summary).toContain('csrf=yes');
  });
});

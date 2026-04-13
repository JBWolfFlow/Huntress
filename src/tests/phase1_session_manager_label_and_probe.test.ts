/**
 * Phase 1 / Q3 + Q6 Gap 5 — SessionManager.findByLabel & probeBearer tests
 *
 * findByLabel covers: exact match, case-insensitive match, no-match,
 * empty/undefined input.
 *
 * probeBearer covers: the six verdict cases from the plan (401 invalid,
 * baseline-401 + auth-2xx valid, same-body unknown, different-body valid,
 * network error unknown, baseline-ok-auth-401 invalid).
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SessionManager } from '../core/auth/session_manager';
import type {
  HttpClient,
  HttpRequestOptions,
  HttpResponse,
  Cookie,
} from '../core/http/request_engine';

// ─── Helpers ────────────────────────────────────────────────────────────────

function mkResponse(overrides: Partial<HttpResponse> = {}): HttpResponse {
  return {
    status: 200,
    statusText: 'OK',
    headers: {},
    body: '',
    cookies: [],
    timing: { dnsMs: 0, connectMs: 0, ttfbMs: 0, totalMs: 0 },
    redirectChain: [],
    size: 0,
    ...overrides,
  };
}

/**
 * Mock HttpClient that routes by the presence of the Authorization header.
 * Lets a test declare "auth probe" + "baseline probe" responses independently.
 */
function mkClient(
  authResponse: Partial<HttpResponse> | Error,
  baselineResponse: Partial<HttpResponse> | Error,
): HttpClient {
  const requestFn = vi.fn(async (options: HttpRequestOptions): Promise<HttpResponse> => {
    const hasAuth = !!options.headers?.['Authorization'];
    const r = hasAuth ? authResponse : baselineResponse;
    if (r instanceof Error) throw r;
    return mkResponse(r);
  });
  return {
    request: requestFn,
    getCookies: (_domain: string): Cookie[] => [],
  } as unknown as HttpClient;
}

// ─── findByLabel (Q3) ───────────────────────────────────────────────────────

describe('SessionManager.findByLabel (Q3)', () => {
  let sm: SessionManager;

  beforeEach(() => {
    sm = new SessionManager(mkClient({}, {}));
    sm.createSession({ id: 'v1', label: 'victim', authType: 'bearer' });
    sm.createSession({ id: 'a1', label: 'attacker', authType: 'bearer' });
    sm.createSession({ id: 'admin1', label: 'Admin Tenant', authType: 'bearer' });
  });

  it('returns the session id for an exact-match label', () => {
    expect(sm.findByLabel('victim')).toBe('v1');
    expect(sm.findByLabel('attacker')).toBe('a1');
  });

  it('falls back to case-insensitive match when exact match fails', () => {
    expect(sm.findByLabel('VICTIM')).toBe('v1');
    expect(sm.findByLabel('Attacker')).toBe('a1');
    expect(sm.findByLabel('admin tenant')).toBe('admin1');
  });

  it('returns undefined for a label with no matching session', () => {
    expect(sm.findByLabel('nonexistent')).toBeUndefined();
    // Partial/substring matches must NOT resolve — that'd be a footgun.
    expect(sm.findByLabel('vic')).toBeUndefined();
    expect(sm.findByLabel('ictim')).toBeUndefined();
  });

  it('returns undefined for empty or whitespace-only input', () => {
    expect(sm.findByLabel('')).toBeUndefined();
  });

  it('prefers exact-case match over case-insensitive when both exist', () => {
    sm.createSession({ id: 'v2', label: 'VICTIM', authType: 'bearer' });
    // 'VICTIM' exact match beats the case-insensitive hit on 'victim'.
    expect(sm.findByLabel('VICTIM')).toBe('v2');
    // 'victim' exact match still resolves to the original.
    expect(sm.findByLabel('victim')).toBe('v1');
  });
});

// ─── probeBearer (Q6 Gap 5) ─────────────────────────────────────────────────

describe('SessionManager.probeBearer two-probe differential (Q6 Gap 5)', () => {
  it('returns `invalid` when the auth probe returns 401', async () => {
    const sm = new SessionManager(
      mkClient(
        { status: 401, body: 'unauthorized' },
        { status: 200, body: 'ok' },
      ),
    );
    const verdict = await sm.probeBearer('bogus-token', 'https://target.com/api/me');
    expect(verdict).toBe('invalid');
  });

  it('returns `invalid` when the auth probe returns 403', async () => {
    const sm = new SessionManager(
      mkClient(
        { status: 403, body: 'forbidden' },
        { status: 401, body: 'unauthorized' },
      ),
    );
    const verdict = await sm.probeBearer('revoked-token', 'https://target.com/api/me');
    expect(verdict).toBe('invalid');
  });

  it('returns `valid` on textbook pattern: baseline 401 + authed 2xx', async () => {
    const sm = new SessionManager(
      mkClient(
        { status: 200, body: '{"user":"daisy"}' },
        { status: 401, body: 'auth required' },
      ),
    );
    const verdict = await sm.probeBearer('good-token', 'https://target.com/api/me');
    expect(verdict).toBe('valid');
  });

  it('returns `valid` when baseline succeeds but body differs from auth probe', async () => {
    // Public endpoint that returns richer data to authenticated callers.
    const sm = new SessionManager(
      mkClient(
        { status: 200, body: '{"user":"daisy","email":"d@x.com"}' },
        { status: 200, body: '{"user":null}' },
      ),
    );
    const verdict = await sm.probeBearer('good-token', 'https://target.com/api/me');
    expect(verdict).toBe('valid');
  });

  it('returns `unknown` when baseline and auth bodies are identical', async () => {
    // Fully-public endpoint that ignores the token — no info gained.
    const sm = new SessionManager(
      mkClient(
        { status: 200, body: 'pong' },
        { status: 200, body: 'pong' },
      ),
    );
    const verdict = await sm.probeBearer('any-token', 'https://target.com/ping');
    expect(verdict).toBe('unknown');
  });

  it('returns `unknown` when the auth probe throws a network error', async () => {
    const sm = new SessionManager(
      mkClient(new Error('ENETUNREACH'), { status: 200, body: 'ok' }),
    );
    const verdict = await sm.probeBearer('token', 'https://target.com/api/me');
    expect(verdict).toBe('unknown');
  });

  it('returns `unknown` when both probes 5xx (endpoint buggy, no info)', async () => {
    // This is the Hunt #11 `pay.wallet.tg` case — endpoint 500s on both paths,
    // prior single-probe validator would have reported `valid` for a bogus
    // token. The new contract: accept as `unknown` and let reactive refresh
    // catch real 401s on the hunt itself.
    const sm = new SessionManager(
      mkClient({ status: 500, body: 'internal' }, { status: 500, body: 'internal' }),
    );
    const verdict = await sm.probeBearer('bogus-on-broken-server', 'https://broken.com/api/me');
    expect(verdict).toBe('unknown');
  });
});

describe('SessionManager.loginWithBearer uses probe verdict (Q6 Gap 5)', () => {
  it('creates a session when verdict is `valid`', async () => {
    const sm = new SessionManager(
      mkClient(
        { status: 200, body: 'ok' },
        { status: 401, body: 'nope' },
      ),
    );
    const session = await sm.loginWithBearer('tok', 'https://target.com/me', 'victim');
    expect(session).toBeDefined();
    expect(session.label).toBe('victim');
    expect(session.authType).toBe('bearer');
  });

  it('creates a session when verdict is `unknown` (avoids false negatives)', async () => {
    const sm = new SessionManager(
      mkClient({ status: 500, body: 'x' }, { status: 500, body: 'x' }),
    );
    // Must not throw — unknown is accepted; reactive refresh handles real failures.
    await expect(
      sm.loginWithBearer('tok', 'https://target.com/me', 'victim'),
    ).resolves.toBeDefined();
  });

  it('throws when verdict is `invalid` (token actively rejected)', async () => {
    const sm = new SessionManager(
      mkClient({ status: 401, body: 'no' }, { status: 200, body: 'ok' }),
    );
    await expect(
      sm.loginWithBearer('bad', 'https://target.com/me', 'victim'),
    ).rejects.toThrow(/rejected/i);
  });
});

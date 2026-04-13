/**
 * S7/S8 — Token Refresh & Auth Lifecycle Tests
 *
 * Tests for the three-layer token lifecycle system:
 * - JWT exp claim parsing
 * - InitData re-exchange (Telegram pattern)
 * - OAuth2 refresh_token flow (S8)
 * - Custom endpoint refresh (S8)
 * - Re-login refresh (S8)
 * - 401 auto-retry flow
 * - Proactive refresh at 90s threshold
 * - Rate limiting (1 refresh per 30s per session)
 * - Multi-header token systems
 * - Graceful degradation when no refresh config stored
 * - Expired credentials detection
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { TokenRefresher } from '../core/auth/token_refresher';
import type { TelegramAuthData, RefreshConfig } from '../core/auth/token_refresher';
import { SessionManager } from '../core/auth/session_manager';
import type { AuthenticatedSession } from '../core/auth/session_manager';
import type { HttpClient, HttpRequestOptions, HttpResponse, Cookie } from '../core/http/request_engine';

// ─── Test Helpers ────────────────────────────────────────────────────────────

function makeResponse(overrides?: Partial<HttpResponse>): HttpResponse {
  return {
    status: 200,
    statusText: 'OK',
    headers: {},
    body: '{"ok":true}',
    cookies: [],
    timing: { dnsMs: 0, connectMs: 0, ttfbMs: 0, totalMs: 50 },
    redirectChain: [],
    size: 11,
    ...overrides,
  };
}

function createMockHttpClient(requestFn?: (options: HttpRequestOptions) => Promise<HttpResponse>): HttpClient {
  const defaultFn = vi.fn(async (_options: HttpRequestOptions): Promise<HttpResponse> => {
    return makeResponse();
  });

  return {
    request: requestFn ? vi.fn(requestFn) : defaultFn,
    getCookies: (_hostname: string): Cookie[] => [],
  } as unknown as HttpClient;
}

/** Create a minimal JWT with a given exp claim (seconds) */
function makeJwt(expSeconds: number): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({ exp: expSeconds, sub: 'user123' }));
  const signature = btoa('fake-signature');
  return `${header}.${payload}.${signature}`;
}

/** Create a base64url JWT (using - and _ instead of + and /) */
function makeBase64UrlJwt(expSeconds: number): string {
  const header = btoa(JSON.stringify({ alg: 'ES256', typ: 'JWT' }))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const payload = btoa(JSON.stringify({ exp: expSeconds, iat: expSeconds - 600 }))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const signature = btoa('fake-es256-sig')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return `${header}.${payload}.${signature}`;
}

function makeInitDataConfig(overrides?: Partial<Omit<TelegramAuthData, 'type'>>): TelegramAuthData {
  return {
    initData: 'query_id=AAHdF6IQ&user=%7B%22id%22%3A123%7D&auth_date=1700000000&hash=abc123',
    authEndpointUrl: 'https://target.com/alectryon/public-api/auth',
    deviceSerial: 'device-uuid-1234',
    tokenTtlSeconds: 600,
    tokenHeaderMap: {
      'token': 'authorization',
      'walletToken': 'wallet-authorization',
    },
    ...overrides,
    type: 'initdata_exchange' as const,
  };
}

// ─── TokenRefresher: JWT Parsing ────────────────────────────────────────────

describe('TokenRefresher.getTokenExpiry', () => {
  let refresher: TokenRefresher;

  beforeEach(() => {
    refresher = new TokenRefresher();
  });

  it('parses exp claim from standard base64 JWT', () => {
    const expSeconds = Math.floor(Date.now() / 1000) + 600; // 10 min from now
    const jwt = makeJwt(expSeconds);
    const expiry = refresher.getTokenExpiry(jwt);
    expect(expiry).toBe(expSeconds * 1000);
  });

  it('parses exp claim from base64url JWT', () => {
    const expSeconds = Math.floor(Date.now() / 1000) + 300;
    const jwt = makeBase64UrlJwt(expSeconds);
    const expiry = refresher.getTokenExpiry(jwt);
    expect(expiry).toBe(expSeconds * 1000);
  });

  it('returns undefined for non-JWT strings', () => {
    expect(refresher.getTokenExpiry('not-a-jwt')).toBeUndefined();
    expect(refresher.getTokenExpiry('')).toBeUndefined();
    expect(refresher.getTokenExpiry('just.two.parts.extra')).toBeUndefined();
  });

  it('returns undefined for JWT without exp claim', () => {
    const header = btoa(JSON.stringify({ alg: 'HS256' }));
    const payload = btoa(JSON.stringify({ sub: 'user', iat: 1700000000 }));
    const sig = btoa('sig');
    const jwt = `${header}.${payload}.${sig}`;
    expect(refresher.getTokenExpiry(jwt)).toBeUndefined();
  });

  it('returns undefined for malformed base64 payload', () => {
    const jwt = 'header.!!!invalid-base64!!!.sig';
    expect(refresher.getTokenExpiry(jwt)).toBeUndefined();
  });
});

// ─── TokenRefresher.needsRefresh ────────────────────────────────────────────

describe('TokenRefresher.needsRefresh', () => {
  let refresher: TokenRefresher;

  beforeEach(() => {
    refresher = new TokenRefresher();
  });

  it('returns false when no expiresAt set', () => {
    const session: AuthenticatedSession = {
      id: 'test', label: 'test', authType: 'custom_header',
      cookies: [], headers: {}, createdAt: Date.now(),
    };
    expect(refresher.needsRefresh(session)).toBe(false);
  });

  it('returns true when within 90s threshold', () => {
    const session: AuthenticatedSession = {
      id: 'test', label: 'test', authType: 'custom_header',
      cookies: [], headers: {},
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000, // 60s from now (within 90s threshold)
    };
    expect(refresher.needsRefresh(session)).toBe(true);
  });

  it('returns false when well before threshold', () => {
    const session: AuthenticatedSession = {
      id: 'test', label: 'test', authType: 'custom_header',
      cookies: [], headers: {},
      createdAt: Date.now(),
      expiresAt: Date.now() + 300_000, // 5 min from now
    };
    expect(refresher.needsRefresh(session)).toBe(false);
  });

  it('returns true when already expired', () => {
    const session: AuthenticatedSession = {
      id: 'test', label: 'test', authType: 'custom_header',
      cookies: [], headers: {},
      createdAt: Date.now() - 700_000,
      expiresAt: Date.now() - 100_000, // expired 100s ago
    };
    expect(refresher.needsRefresh(session)).toBe(true);
  });

  it('respects custom threshold', () => {
    const session: AuthenticatedSession = {
      id: 'test', label: 'test', authType: 'custom_header',
      cookies: [], headers: {},
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000, // 60s from now
    };
    // With 30s threshold, 60s remaining is fine
    expect(refresher.needsRefresh(session, 30_000)).toBe(false);
    // With 120s threshold, 60s remaining triggers refresh
    expect(refresher.needsRefresh(session, 120_000)).toBe(true);
  });
});

// ─── TokenRefresher.detectTokenTtl ─────────────────────────────────────────

describe('TokenRefresher.detectTokenTtl', () => {
  let refresher: TokenRefresher;

  beforeEach(() => {
    refresher = new TokenRefresher();
  });

  it('detects TTL from JWT exp claim', () => {
    const expSeconds = Math.floor(Date.now() / 1000) + 600;
    const jwt = makeJwt(expSeconds);
    const ttl = refresher.detectTokenTtl(jwt);
    // Should be approximately 600s (within 5s tolerance for test execution time)
    expect(ttl).toBeGreaterThanOrEqual(595);
    expect(ttl).toBeLessThanOrEqual(600);
  });

  it('returns default TTL for non-JWT strings', () => {
    expect(refresher.detectTokenTtl('not-a-jwt')).toBe(600);
    expect(refresher.detectTokenTtl('not-a-jwt', 300)).toBe(300);
  });

  it('returns default TTL for expired JWTs', () => {
    const expSeconds = Math.floor(Date.now() / 1000) - 100; // expired 100s ago
    const jwt = makeJwt(expSeconds);
    expect(refresher.detectTokenTtl(jwt)).toBe(600);
  });
});

// ─── TokenRefresher: Telegram initData Re-exchange ──────────────────────────

describe('TokenRefresher.refreshTokens (initdata_exchange)', () => {
  let refresher: TokenRefresher;
  let onRefreshFailed: ReturnType<typeof vi.fn<(sessionId: string, error: string, message: string) => void>>;

  beforeEach(() => {
    onRefreshFailed = vi.fn<(sessionId: string, error: string, message: string) => void>();
    refresher = new TokenRefresher({ onRefreshFailed });
  });

  afterEach(() => {
    refresher.resetRateLimits();
  });

  it('exchanges initData for fresh tokens', async () => {
    const authData = makeInitDataConfig();
    const httpClient = createMockHttpClient(async (options) => {
      expect(options.url).toBe(authData.authEndpointUrl);
      expect(options.method).toBe('POST');
      expect(JSON.parse(options.body!).initData).toBe(authData.initData);
      expect(options.headers?.['x-wallet-device-serial']).toBe(authData.deviceSerial);
      return makeResponse({
        body: JSON.stringify({
          token: 'fresh-hs256-jwt',
          walletToken: 'fresh-es256-jwt',
        }),
      });
    });

    const result = await refresher.refreshTokens('session-1', authData, httpClient);
    expect(result.success).toBe(true);
    expect(result.tokens).toEqual({
      'authorization': 'fresh-hs256-jwt',
      'wallet-authorization': 'fresh-es256-jwt',
    });
  });

  it('handles nested response fields via dot notation', async () => {
    const authData = makeInitDataConfig({
      tokenHeaderMap: {
        'data.accessToken': 'authorization',
        'data.walletToken': 'wallet-authorization',
      },
    });
    const httpClient = createMockHttpClient(async () => {
      return makeResponse({
        body: JSON.stringify({
          data: { accessToken: 'nested-jwt', walletToken: 'nested-wallet-jwt' },
        }),
      });
    });

    const result = await refresher.refreshTokens('session-1', authData, httpClient);
    expect(result.success).toBe(true);
    expect(result.tokens?.['authorization']).toBe('nested-jwt');
    expect(result.tokens?.['wallet-authorization']).toBe('nested-wallet-jwt');
  });

  it('detects expired initData (401 from auth endpoint)', async () => {
    const authData = makeInitDataConfig();
    const httpClient = createMockHttpClient(async () => {
      return makeResponse({ status: 401, statusText: 'Unauthorized', body: 'initData expired' });
    });

    const result = await refresher.refreshTokens('session-1', authData, httpClient);
    expect(result.success).toBe(false);
    expect(result.error).toBe('expired_credentials');
    expect(onRefreshFailed).toHaveBeenCalledWith('session-1', 'expired_credentials', expect.any(String));
  });

  it('detects expired initData (403 from auth endpoint)', async () => {
    const authData = makeInitDataConfig();
    const httpClient = createMockHttpClient(async () => {
      return makeResponse({ status: 403, statusText: 'Forbidden', body: 'Forbidden' });
    });

    const result = await refresher.refreshTokens('session-1', authData, httpClient);
    expect(result.success).toBe(false);
    expect(result.error).toBe('expired_credentials');
  });

  it('handles server errors from auth endpoint', async () => {
    const authData = makeInitDataConfig();
    const httpClient = createMockHttpClient(async () => {
      return makeResponse({ status: 500, statusText: 'Internal Server Error', body: 'crash' });
    });

    const result = await refresher.refreshTokens('session-1', authData, httpClient);
    expect(result.success).toBe(false);
    expect(result.error).toBe('server_error');
  });

  it('handles non-JSON response body', async () => {
    const authData = makeInitDataConfig();
    const httpClient = createMockHttpClient(async () => {
      return makeResponse({ body: '<html>error</html>' });
    });

    const result = await refresher.refreshTokens('session-1', authData, httpClient);
    expect(result.success).toBe(false);
    expect(result.error).toBe('server_error');
    expect(result.message).toContain('non-JSON');
  });

  it('handles response with no matching token fields', async () => {
    const authData = makeInitDataConfig();
    const httpClient = createMockHttpClient(async () => {
      return makeResponse({ body: JSON.stringify({ unrelatedField: 'value' }) });
    });

    const result = await refresher.refreshTokens('session-1', authData, httpClient);
    expect(result.success).toBe(false);
    expect(result.error).toBe('server_error');
    expect(result.message).toContain('No tokens found');
  });

  it('retries once on network error then succeeds', async () => {
    const authData = makeInitDataConfig();
    let callCount = 0;
    const httpClient = createMockHttpClient(async () => {
      callCount++;
      if (callCount === 1) {
        throw new Error('ECONNRESET');
      }
      return makeResponse({
        body: JSON.stringify({ token: 'retry-jwt', walletToken: 'retry-wallet' }),
      });
    });

    const result = await refresher.refreshTokens('session-1', authData, httpClient);
    expect(result.success).toBe(true);
    expect(callCount).toBe(2); // First failed, retry succeeded
  });

  it('reports network error after retry also fails', async () => {
    const authData = makeInitDataConfig();
    const httpClient = createMockHttpClient(async () => {
      throw new Error('ECONNRESET');
    });

    const result = await refresher.refreshTokens('session-1', authData, httpClient);
    expect(result.success).toBe(false);
    expect(result.error).toBe('network_error');
    expect(onRefreshFailed).toHaveBeenCalledWith('session-1', 'network_error', expect.any(String));
  });

  it('omits device serial header when empty', async () => {
    const authData = makeInitDataConfig({ deviceSerial: '' });
    const httpClient = createMockHttpClient(async (options) => {
      expect(options.headers?.['x-wallet-device-serial']).toBeUndefined();
      return makeResponse({
        body: JSON.stringify({ token: 'jwt1', walletToken: 'jwt2' }),
      });
    });

    const result = await refresher.refreshTokens('session-1', authData, httpClient);
    expect(result.success).toBe(true);
  });
});

// ─── TokenRefresher: Rate Limiting ──────────────────────────────────────────

describe('TokenRefresher rate limiting', () => {
  let refresher: TokenRefresher;

  beforeEach(() => {
    refresher = new TokenRefresher();
  });

  afterEach(() => {
    refresher.resetRateLimits();
    vi.restoreAllMocks();
  });

  it('allows first refresh', () => {
    expect(refresher.isRateLimited('session-1')).toBe(false);
  });

  it('blocks refresh within 30s window', async () => {
    const authData = makeInitDataConfig();
    const httpClient = createMockHttpClient(async () => {
      return makeResponse({
        body: JSON.stringify({ token: 'jwt', walletToken: 'wallet-jwt' }),
      });
    });

    // First refresh succeeds
    const result1 = await refresher.refreshTokens('session-1', authData, httpClient);
    expect(result1.success).toBe(true);

    // Second refresh within 30s is rate-limited
    const result2 = await refresher.refreshTokens('session-1', authData, httpClient);
    expect(result2.success).toBe(false);
    expect(result2.message).toContain('Rate limited');
  });

  it('allows refresh for different sessions independently', async () => {
    const authData = makeInitDataConfig();
    const httpClient = createMockHttpClient(async () => {
      return makeResponse({
        body: JSON.stringify({ token: 'jwt', walletToken: 'wallet-jwt' }),
      });
    });

    const result1 = await refresher.refreshTokens('session-1', authData, httpClient);
    expect(result1.success).toBe(true);

    // Different session is not rate-limited
    const result2 = await refresher.refreshTokens('session-2', authData, httpClient);
    expect(result2.success).toBe(true);
  });

  it('deduplicates concurrent refresh attempts for same session', async () => {
    let callCount = 0;
    const authData = makeInitDataConfig();
    const httpClient = createMockHttpClient(async () => {
      callCount++;
      // Simulate slow auth endpoint
      await new Promise(resolve => setTimeout(resolve, 50));
      return makeResponse({
        body: JSON.stringify({ token: 'jwt', walletToken: 'wallet-jwt' }),
      });
    });

    // Fire 3 concurrent refreshes for the same session
    const [r1, r2, r3] = await Promise.all([
      refresher.refreshTokens('session-1', authData, httpClient),
      refresher.refreshTokens('session-1', authData, httpClient),
      refresher.refreshTokens('session-1', authData, httpClient),
    ]);

    // Only 1 actual HTTP call should have been made
    expect(callCount).toBe(1);
    // All 3 should return the same result
    expect(r1.success).toBe(true);
    expect(r2.success).toBe(true);
    expect(r3.success).toBe(true);
  });
});

// ─── SessionManager: Token Refresh Integration ──────────────────────────────

describe('SessionManager with TokenRefresher (S7)', () => {
  let sm: SessionManager;

  it('refreshSession() returns undefined when no refresh config stored', async () => {
    sm = new SessionManager(createMockHttpClient());
    sm.createSession({ id: 'session-1', label: 'Test', authType: 'custom_header' });
    const result = await sm.refreshSession('session-1');
    expect(result).toBeUndefined();
  });

  it('refreshSession() refreshes tokens via Telegram initData', async () => {
    const httpClient = createMockHttpClient(async (options) => {
      // Auth endpoint mock
      if (options.url.includes('public-api/auth')) {
        return makeResponse({
          body: JSON.stringify({
            token: 'fresh-hs256',
            walletToken: 'fresh-es256',
          }),
        });
      }
      return makeResponse();
    });

    sm = new SessionManager(httpClient);
    sm.createSession({ id: 'session-1', label: 'Telegram', authType: 'custom_header' });
    const session = sm.getSession('session-1')!;
    session.headers = { authorization: 'old-hs256', 'wallet-authorization': 'old-es256' };

    sm.setRefreshConfig('session-1', makeInitDataConfig());

    const refreshed = await sm.refreshSession('session-1');
    expect(refreshed).toBeDefined();
    expect(refreshed!.headers.authorization).toBe('fresh-hs256');
    expect(refreshed!.headers['wallet-authorization']).toBe('fresh-es256');
    expect(refreshed!.expiresAt).toBeGreaterThan(Date.now());
  });

  it('setRefreshConfig() populates expiresAt from JWT headers', () => {
    sm = new SessionManager(createMockHttpClient());
    sm.createSession({ id: 'session-1', label: 'JWT', authType: 'custom_header' });
    const session = sm.getSession('session-1')!;

    const expSeconds = Math.floor(Date.now() / 1000) + 600;
    session.headers = {
      authorization: makeJwt(expSeconds),
      'wallet-authorization': makeJwt(expSeconds + 100), // expires later
    };

    sm.setRefreshConfig('session-1', makeInitDataConfig());

    // Should use earliest expiry
    expect(session.expiresAt).toBe(expSeconds * 1000);
  });

  it('loginWithBearer() populates expiresAt from JWT token', async () => {
    const expSeconds = Math.floor(Date.now() / 1000) + 600;
    const jwt = makeJwt(expSeconds);
    const httpClient = createMockHttpClient(async () => makeResponse());

    sm = new SessionManager(httpClient);
    const session = await sm.loginWithBearer(jwt, 'http://target.com');
    expect(session.expiresAt).toBe(expSeconds * 1000);
  });

  it('loginWithBearer() leaves expiresAt undefined for non-JWT tokens', async () => {
    const httpClient = createMockHttpClient(async () => makeResponse());

    sm = new SessionManager(httpClient);
    const session = await sm.loginWithBearer('plain-api-key-not-jwt', 'http://target.com');
    expect(session.expiresAt).toBeUndefined();
  });
});

// ─── SessionManager: 401 Auto-Retry with Token Refresh ─────────────────────

describe('SessionManager.authenticatedRequest with token refresh', () => {
  it('retries on 401 and succeeds with fresh tokens', async () => {
    let callCount = 0;
    const httpClient = createMockHttpClient(async (options) => {
      callCount++;
      // Auth endpoint for token refresh
      if (options.url.includes('public-api/auth')) {
        return makeResponse({
          body: JSON.stringify({
            token: 'refreshed-jwt',
            walletToken: 'refreshed-wallet',
          }),
        });
      }
      // First request gets 401, retry gets 200
      if (callCount <= 1) {
        return makeResponse({ status: 401, statusText: 'Unauthorized', body: 'expired' });
      }
      return makeResponse({ body: '{"data":"secret"}' });
    });

    const sm = new SessionManager(httpClient);
    sm.createSession({ id: 'session-1', label: 'Telegram', authType: 'custom_header' });
    const session = sm.getSession('session-1')!;
    session.headers = { authorization: 'old-jwt' };
    sm.setRefreshConfig('session-1', makeInitDataConfig());

    const response = await sm.authenticatedRequest('session-1', {
      url: 'http://target.com/api/data',
      method: 'GET',
    });

    // Should have retried and succeeded
    expect(response.status).toBe(200);
    expect(response.body).toBe('{"data":"secret"}');
    // Auth endpoint + original request + retry = 3+ calls
    expect(callCount).toBeGreaterThanOrEqual(3);
  });

  it('returns 401 when refresh fails (no telegramData)', async () => {
    const httpClient = createMockHttpClient(async () => {
      return makeResponse({ status: 401, statusText: 'Unauthorized', body: 'expired' });
    });

    const sm = new SessionManager(httpClient);
    sm.createSession({ id: 'session-1', label: 'Test', authType: 'bearer' });
    const session = sm.getSession('session-1')!;
    session.headers = { Authorization: 'Bearer old-token' };

    const response = await sm.authenticatedRequest('session-1', {
      url: 'http://target.com/api/data',
      method: 'GET',
    });

    // No refresh possible — returns the 401
    expect(response.status).toBe(401);
  });
});

// ─── SessionManager: Destroy cleans up telegram data ────────────────────────

describe('SessionManager cleanup', () => {
  it('destroySession() removes refresh config', async () => {
    const httpClient = createMockHttpClient();
    const sm = new SessionManager(httpClient);

    sm.createSession({ id: 'session-1', label: 'Telegram', authType: 'custom_header' });
    sm.setRefreshConfig('session-1', makeInitDataConfig());
    sm.destroySession('session-1');

    // Session should be gone, refresh should return undefined
    const result = await sm.refreshSession('session-1');
    expect(result).toBeUndefined();
  });

  it('destroyAll() resets all state including rate limits', () => {
    const httpClient = createMockHttpClient();
    const sm = new SessionManager(httpClient);

    sm.createSession({ id: 'session-1', label: 'Test', authType: 'custom_header' });
    sm.setRefreshConfig('session-1', makeInitDataConfig());
    sm.destroyAll();

    expect(sm.getSession('session-1')).toBeUndefined();
    expect(sm.listSessions()).toHaveLength(0);
  });
});

// ─── Multi-header token systems ─────────────────────────────────────────────

describe('Multi-header token refresh', () => {
  it('refreshes both authorization and wallet-authorization from single auth call', async () => {
    const httpClient = createMockHttpClient(async (options) => {
      if (options.url.includes('public-api/auth')) {
        return makeResponse({
          body: JSON.stringify({
            token: 'new-auth-jwt',
            walletToken: 'new-wallet-jwt',
            extraField: 'ignored',
          }),
        });
      }
      return makeResponse();
    });

    const sm = new SessionManager(httpClient);
    sm.createSession({ id: 'session-1', label: 'Telegram', authType: 'custom_header' });
    const session = sm.getSession('session-1')!;
    session.headers = {
      authorization: 'old-auth-jwt',
      'wallet-authorization': 'old-wallet-jwt',
      'x-wallet-device-serial': 'device-uuid',
    };

    sm.setRefreshConfig('session-1', makeInitDataConfig());
    const refreshed = await sm.refreshSession('session-1');

    expect(refreshed).toBeDefined();
    expect(refreshed!.headers.authorization).toBe('new-auth-jwt');
    expect(refreshed!.headers['wallet-authorization']).toBe('new-wallet-jwt');
    // Device serial should be preserved (not overwritten)
    expect(refreshed!.headers['x-wallet-device-serial']).toBe('device-uuid');
  });
});

// ─── Graceful degradation ───────────────────────────────────────────────────

describe('Graceful degradation', () => {
  it('continues with stale token when refresh fails', async () => {
    const httpClient = createMockHttpClient(async (options) => {
      if (options.url.includes('public-api/auth')) {
        return makeResponse({ status: 500, body: 'Server error' });
      }
      return makeResponse();
    });

    const sm = new SessionManager(httpClient);
    sm.createSession({ id: 'session-1', label: 'Test', authType: 'custom_header' });
    const session = sm.getSession('session-1')!;
    session.headers = { authorization: 'stale-jwt' };
    sm.setRefreshConfig('session-1', makeInitDataConfig());

    const refreshed = await sm.refreshSession('session-1');
    expect(refreshed).toBeUndefined();
    // Original session still has the stale token
    expect(session.headers.authorization).toBe('stale-jwt');
  });

  it('isExpired() works correctly with token lifecycle', () => {
    const httpClient = createMockHttpClient();
    const sm = new SessionManager(httpClient);

    sm.createSession({ id: 'fresh', label: 'Fresh', authType: 'custom_header' });
    const fresh = sm.getSession('fresh')!;
    fresh.expiresAt = Date.now() + 300_000;
    expect(sm.isExpired('fresh')).toBe(false);

    sm.createSession({ id: 'expired', label: 'Expired', authType: 'custom_header' });
    const expired = sm.getSession('expired')!;
    expired.expiresAt = Date.now() - 1000;
    expect(sm.isExpired('expired')).toBe(true);

    sm.createSession({ id: 'noexpiry', label: 'No Expiry', authType: 'custom_header' });
    expect(sm.isExpired('noexpiry')).toBe(false);
  });
});

// ─── onRefreshFailed callback ───────────────────────────────────────────────

describe('onRefreshFailed callback', () => {
  it('fires with expired_credentials when auth endpoint returns 401', async () => {
    const onFailed = vi.fn();
    const sm = new SessionManager(
      createMockHttpClient(async (options) => {
        if (options.url.includes('public-api/auth')) {
          return makeResponse({ status: 401, body: 'expired' });
        }
        return makeResponse();
      }),
      { onRefreshFailed: onFailed },
    );

    sm.createSession({ id: 'session-1', label: 'Test', authType: 'custom_header' });
    sm.setRefreshConfig('session-1', makeInitDataConfig());
    await sm.refreshSession('session-1');

    expect(onFailed).toHaveBeenCalledWith('session-1', 'expired_credentials', expect.any(String));
  });

  it('fires with network_error on connection failures', async () => {
    const onFailed = vi.fn();
    const sm = new SessionManager(
      createMockHttpClient(async () => {
        throw new Error('ECONNRESET');
      }),
      { onRefreshFailed: onFailed },
    );

    sm.createSession({ id: 'session-1', label: 'Test', authType: 'custom_header' });
    sm.setRefreshConfig('session-1', makeInitDataConfig());
    await sm.refreshSession('session-1');

    expect(onFailed).toHaveBeenCalledWith('session-1', 'network_error', expect.any(String));
  });
});

// ─── S8: OAuth2 Refresh Token Flow ──────────────────────────────────────────

describe('TokenRefresher.refreshTokens (refresh_token / OAuth2)', () => {
  let refresher: TokenRefresher;

  beforeEach(() => {
    refresher = new TokenRefresher();
  });

  afterEach(() => {
    refresher.resetRateLimits();
  });

  function makeOAuth2Config(overrides?: Partial<Extract<RefreshConfig, { type: 'refresh_token' }>>): Extract<RefreshConfig, { type: 'refresh_token' }> {
    return {
      refreshToken: 'rt_abc123',
      tokenEndpoint: 'https://target.com/oauth/token',
      tokenTtlSeconds: 3600,
      ...overrides,
      type: 'refresh_token' as const,
    };
  }

  it('exchanges refresh_token for new access_token', async () => {
    const config = makeOAuth2Config();
    const httpClient = createMockHttpClient(async (options) => {
      expect(options.url).toBe('https://target.com/oauth/token');
      expect(options.method).toBe('POST');
      expect(options.headers?.['Content-Type']).toBe('application/x-www-form-urlencoded');
      const body = new URLSearchParams(options.body!);
      expect(body.get('grant_type')).toBe('refresh_token');
      expect(body.get('refresh_token')).toBe('rt_abc123');
      return makeResponse({
        body: JSON.stringify({ access_token: 'new_access_jwt', token_type: 'Bearer' }),
      });
    });

    const result = await refresher.refreshTokens('session-1', config, httpClient);
    expect(result.success).toBe(true);
    expect(result.tokens?.['Authorization']).toBe('Bearer new_access_jwt');
  });

  it('sends client_id and client_secret when provided', async () => {
    const config = makeOAuth2Config({ clientId: 'my_client', clientSecret: 's3cret', scope: 'openid profile' });
    const httpClient = createMockHttpClient(async (options) => {
      const body = new URLSearchParams(options.body!);
      expect(body.get('client_id')).toBe('my_client');
      expect(body.get('client_secret')).toBe('s3cret');
      expect(body.get('scope')).toBe('openid profile');
      return makeResponse({
        body: JSON.stringify({ access_token: 'jwt_with_scopes' }),
      });
    });

    const result = await refresher.refreshTokens('session-1', config, httpClient);
    expect(result.success).toBe(true);
    expect(result.tokens?.['Authorization']).toBe('Bearer jwt_with_scopes');
  });

  it('captures rotated refresh_token in __new_refresh_token', async () => {
    const config = makeOAuth2Config();
    const httpClient = createMockHttpClient(async () => {
      return makeResponse({
        body: JSON.stringify({
          access_token: 'new_access',
          refresh_token: 'rotated_rt_xyz',
        }),
      });
    });

    const result = await refresher.refreshTokens('session-1', config, httpClient);
    expect(result.success).toBe(true);
    expect(result.tokens?.['__new_refresh_token']).toBe('rotated_rt_xyz');
  });

  it('returns expired_credentials on 401', async () => {
    const config = makeOAuth2Config();
    const httpClient = createMockHttpClient(async () => {
      return makeResponse({ status: 401, body: 'invalid_grant' });
    });

    const result = await refresher.refreshTokens('session-1', config, httpClient);
    expect(result.success).toBe(false);
    expect(result.error).toBe('expired_credentials');
  });

  it('handles server errors', async () => {
    const config = makeOAuth2Config();
    const httpClient = createMockHttpClient(async () => {
      return makeResponse({ status: 500, body: 'Internal error' });
    });

    const result = await refresher.refreshTokens('session-1', config, httpClient);
    expect(result.success).toBe(false);
    expect(result.error).toBe('server_error');
  });
});

// ─── S8: Custom Endpoint Refresh Flow ───────────────────────────────────────

describe('TokenRefresher.refreshTokens (custom_endpoint)', () => {
  let refresher: TokenRefresher;

  beforeEach(() => {
    refresher = new TokenRefresher();
  });

  afterEach(() => {
    refresher.resetRateLimits();
  });

  it('POSTs to custom refresh endpoint and maps response to headers', async () => {
    const config: RefreshConfig = {
      type: 'custom_endpoint',
      refreshEndpoint: 'https://target.com/api/auth/refresh',
      method: 'POST',
      body: '{"grant_type":"refresh"}',
      tokenHeaderMap: { 'data.accessToken': 'Authorization', 'data.refreshToken': 'X-Refresh-Token' },
      tokenTtlSeconds: 1800,
    };

    const httpClient = createMockHttpClient(async (options) => {
      expect(options.url).toBe('https://target.com/api/auth/refresh');
      expect(options.method).toBe('POST');
      expect(options.body).toBe('{"grant_type":"refresh"}');
      return makeResponse({
        body: JSON.stringify({
          data: { accessToken: 'new_jwt', refreshToken: 'new_rt' },
        }),
      });
    });

    const result = await refresher.refreshTokens('session-1', config, httpClient);
    expect(result.success).toBe(true);
    expect(result.tokens?.['Authorization']).toBe('new_jwt');
    expect(result.tokens?.['X-Refresh-Token']).toBe('new_rt');
  });

  it('GETs from custom refresh endpoint', async () => {
    const config: RefreshConfig = {
      type: 'custom_endpoint',
      refreshEndpoint: 'https://target.com/auth/token',
      method: 'GET',
      headers: { 'X-Refresh-Key': 'secret_key' },
      tokenHeaderMap: { 'token': 'Authorization' },
      tokenTtlSeconds: 600,
    };

    const httpClient = createMockHttpClient(async (options) => {
      expect(options.method).toBe('GET');
      expect(options.headers?.['X-Refresh-Key']).toBe('secret_key');
      // GET should not have Content-Type: application/json
      expect(options.headers?.['Content-Type']).toBeUndefined();
      return makeResponse({
        body: JSON.stringify({ token: 'get_token_result' }),
      });
    });

    const result = await refresher.refreshTokens('session-1', config, httpClient);
    expect(result.success).toBe(true);
    expect(result.tokens?.['Authorization']).toBe('get_token_result');
  });

  it('returns expired_credentials on 403', async () => {
    const config: RefreshConfig = {
      type: 'custom_endpoint',
      refreshEndpoint: 'https://target.com/auth/refresh',
      method: 'POST',
      tokenHeaderMap: { 'token': 'Authorization' },
      tokenTtlSeconds: 600,
    };

    const httpClient = createMockHttpClient(async () => {
      return makeResponse({ status: 403, body: 'Forbidden' });
    });

    const result = await refresher.refreshTokens('session-1', config, httpClient);
    expect(result.success).toBe(false);
    expect(result.error).toBe('expired_credentials');
  });
});

// ─── S8: Re-login Refresh Flow ──────────────────────────────────────────────

describe('TokenRefresher.refreshTokens (re_login)', () => {
  it('returns error — re_login is handled by SessionManager', async () => {
    const refresher = new TokenRefresher();
    const config: RefreshConfig = { type: 're_login' };
    const httpClient = createMockHttpClient();

    const result = await refresher.refreshTokens('session-1', config, httpClient);
    expect(result.success).toBe(false);
    expect(result.error).toBe('server_error');
    expect(result.message).toContain('re_login');
  });
});

// ─── S8: SessionManager with OAuth2 RefreshConfig ───────────────────────────

describe('SessionManager with OAuth2 refresh config (S8)', () => {
  it('refreshSession() refreshes bearer tokens via OAuth2 refresh_token', async () => {
    const httpClient = createMockHttpClient(async (options) => {
      if (options.url === 'https://target.com/oauth/token') {
        return makeResponse({
          body: JSON.stringify({ access_token: 'fresh_oauth_jwt' }),
        });
      }
      return makeResponse();
    });

    const sm = new SessionManager(httpClient);
    sm.createSession({ id: 'session-1', label: 'OAuth App', authType: 'bearer' });
    const session = sm.getSession('session-1')!;
    session.headers = { Authorization: 'Bearer old_jwt' };

    sm.setRefreshConfig('session-1', {
      type: 'refresh_token',
      refreshToken: 'rt_test',
      tokenEndpoint: 'https://target.com/oauth/token',
      tokenTtlSeconds: 3600,
    });

    const refreshed = await sm.refreshSession('session-1');
    expect(refreshed).toBeDefined();
    expect(refreshed!.headers.Authorization).toBe('Bearer fresh_oauth_jwt');
    expect(refreshed!.expiresAt).toBeGreaterThan(Date.now());
  });

  it('refreshSession() updates stored refresh_token on rotation', async () => {
    const httpClient = createMockHttpClient(async (options) => {
      if (options.url === 'https://target.com/oauth/token') {
        return makeResponse({
          body: JSON.stringify({
            access_token: 'new_access',
            refresh_token: 'rotated_rt',
          }),
        });
      }
      return makeResponse();
    });

    const sm = new SessionManager(httpClient);
    sm.createSession({ id: 'session-1', label: 'OAuth', authType: 'bearer' });
    const session = sm.getSession('session-1')!;
    session.headers = { Authorization: 'Bearer old' };

    const config: RefreshConfig = {
      type: 'refresh_token',
      refreshToken: 'original_rt',
      tokenEndpoint: 'https://target.com/oauth/token',
      tokenTtlSeconds: 3600,
    };
    sm.setRefreshConfig('session-1', config);

    await sm.refreshSession('session-1');
    // The stored config should have the rotated refresh token
    expect(config.refreshToken).toBe('rotated_rt');
  });

  it('authenticatedRequest() retries 401 with OAuth2 refresh', async () => {
    let callCount = 0;
    const httpClient = createMockHttpClient(async (options) => {
      callCount++;
      if (options.url === 'https://target.com/oauth/token') {
        return makeResponse({
          body: JSON.stringify({ access_token: 'refreshed_jwt' }),
        });
      }
      // First API call returns 401, retry returns 200
      if (callCount <= 1) {
        return makeResponse({ status: 401, body: 'Unauthorized' });
      }
      return makeResponse({ body: '{"data":"protected"}' });
    });

    const sm = new SessionManager(httpClient);
    sm.createSession({ id: 'session-1', label: 'OAuth', authType: 'bearer' });
    sm.getSession('session-1')!.headers = { Authorization: 'Bearer expired' };

    sm.setRefreshConfig('session-1', {
      type: 'refresh_token',
      refreshToken: 'rt_for_retry',
      tokenEndpoint: 'https://target.com/oauth/token',
      tokenTtlSeconds: 3600,
    });

    const response = await sm.authenticatedRequest('session-1', {
      url: 'https://target.com/api/data',
      method: 'GET',
    });

    expect(response.status).toBe(200);
    expect(response.body).toBe('{"data":"protected"}');
  });
});

// ─── S8: SessionManager with Custom Endpoint RefreshConfig ──────────────────

describe('SessionManager with custom_endpoint refresh config (S8)', () => {
  it('refreshSession() refreshes via custom endpoint', async () => {
    const httpClient = createMockHttpClient(async (options) => {
      if (options.url === 'https://target.com/api/auth/refresh') {
        return makeResponse({
          body: JSON.stringify({ jwt: 'custom_fresh_jwt' }),
        });
      }
      return makeResponse();
    });

    const sm = new SessionManager(httpClient);
    sm.createSession({ id: 'session-1', label: 'Custom API', authType: 'custom_header' });
    const session = sm.getSession('session-1')!;
    session.headers = { 'X-Auth-Token': 'old_token' };

    sm.setRefreshConfig('session-1', {
      type: 'custom_endpoint',
      refreshEndpoint: 'https://target.com/api/auth/refresh',
      method: 'POST',
      tokenHeaderMap: { 'jwt': 'X-Auth-Token' },
      tokenTtlSeconds: 1800,
    });

    const refreshed = await sm.refreshSession('session-1');
    expect(refreshed).toBeDefined();
    expect(refreshed!.headers['X-Auth-Token']).toBe('custom_fresh_jwt');
  });
});

// ─── S8: SessionManager with re_login RefreshConfig ─────────────────────────

describe('SessionManager with re_login refresh config (S8)', () => {
  it('refreshSession() re-authenticates using stored login credentials', async () => {
    let loginCount = 0;
    const httpClient = createMockHttpClient(async (options) => {
      // Login page GET
      if (options.method === 'GET' && options.url === 'https://target.com/login') {
        return makeResponse({ body: '<html><form><input name="_token" value="csrf123"></form></html>' });
      }
      // Login POST
      if (options.method === 'POST' && options.url === 'https://target.com/login') {
        loginCount++;
        return makeResponse({
          status: 302,
          statusText: 'Found',
          headers: { location: '/dashboard' },
          cookies: [{ name: 'session_id', value: `new_session_${loginCount}`, domain: 'target.com', path: '/', httpOnly: true, secure: true, sameSite: 'Lax' }],
        });
      }
      return makeResponse();
    });

    const sm = new SessionManager(httpClient);

    // Initial login
    const loginCreds = {
      username: 'admin',
      password: 'password123',
      loginUrl: 'https://target.com/login',
    };
    const session = await sm.login(loginCreds);

    // Set re_login refresh config
    sm.setRefreshConfig(session.id, { type: 're_login' });

    // Force-expire the session
    session.expiresAt = Date.now() - 1000;

    // Refresh should re-login
    const refreshed = await sm.refreshSession(session.id);
    expect(refreshed).toBeDefined();
    expect(loginCount).toBe(2); // Initial + refresh
  });

  it('refreshSession() returns undefined for re_login without stored credentials', async () => {
    const sm = new SessionManager(createMockHttpClient());
    sm.createSession({ id: 'session-1', label: 'No Creds', authType: 'cookie' });

    sm.setRefreshConfig('session-1', { type: 're_login' });

    const result = await sm.refreshSession('session-1');
    expect(result).toBeUndefined();
  });
});

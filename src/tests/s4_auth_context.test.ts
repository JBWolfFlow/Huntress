/**
 * S4 — Auth Context Management Tests
 *
 * Tests for the new auth injection pipeline:
 * - ReactLoop auth injection (handleHttpRequest with authSessionId)
 * - Auth profile config types
 * - SessionManager integration with ReactLoop config
 * - Graceful degradation when auth fails
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  SessionManager,
  AuthFlowRunner,
} from '../core/auth/session_manager';
import type { HttpClient, HttpRequestOptions, HttpResponse, Cookie } from '../core/http/request_engine';
import type { AuthProfileConfig } from '../contexts/SettingsContext';

// ─── Mock HttpClient ────────────────────────────────────────────────────────

function makeCookie(name: string, value: string, domain = 'target.com'): Cookie {
  return { name, value, domain, path: '/', httpOnly: false, secure: false };
}

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

function createMockHttpClient(responses?: Map<string, Partial<HttpResponse>>): HttpClient {
  const requestFn = vi.fn(async (options: HttpRequestOptions): Promise<HttpResponse> => {
    const key = `${options.method ?? 'GET'} ${options.url}`;
    const custom = responses?.get(key);
    return makeResponse(custom);
  });

  return {
    request: requestFn,
    getCookies: (_hostname: string): Cookie[] => [
      makeCookie('session', 'abc123', 'localhost'),
    ],
  } as unknown as HttpClient;
}

// ─── ReactLoop Auth Injection (Unit-Level) ────────────────────────────────

describe('SessionManager.applyToRequest auth injection', () => {
  let sm: SessionManager;

  beforeEach(() => {
    sm = new SessionManager(createMockHttpClient());
  });

  it('injects bearer token into request headers', () => {
    sm.createSession({ id: 'bearer-1', label: 'Bearer', authType: 'bearer' });
    const session = sm.getSession('bearer-1')!;
    session.headers = { 'Authorization': 'Bearer jwt-token-abc' };

    const options: HttpRequestOptions = {
      url: 'http://target.com/api/users',
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    };

    const result = sm.applyToRequest('bearer-1', options);
    expect(result.headers?.['Authorization']).toBe('Bearer jwt-token-abc');
    expect(result.headers?.['Accept']).toBe('application/json');
  });

  it('injects API key header into request', () => {
    sm.createSession({ id: 'apikey-1', label: 'API Key', authType: 'api_key' });
    const session = sm.getSession('apikey-1')!;
    session.headers = { 'X-API-Key': 'secret-key-123' };

    const result = sm.applyToRequest('apikey-1', {
      url: 'http://target.com/api/data',
      method: 'GET',
    });
    expect(result.headers?.['X-API-Key']).toBe('secret-key-123');
  });

  it('injects cookies as Cookie header', () => {
    sm.createSession({ id: 'cookie-1', label: 'Cookie Auth', authType: 'cookie' });
    const session = sm.getSession('cookie-1')!;
    session.cookies = [
      makeCookie('session_id', 'sess-xyz'),
      makeCookie('csrf', 'csrf-abc'),
    ];

    const result = sm.applyToRequest('cookie-1', {
      url: 'http://target.com/api/profile',
      method: 'GET',
    });
    expect(result.headers?.['Cookie']).toBe('session_id=sess-xyz; csrf=csrf-abc');
  });

  it('injects custom headers into request', () => {
    sm.createSession({ id: 'custom-1', label: 'Custom', authType: 'custom_header' });
    const session = sm.getSession('custom-1')!;
    session.headers = {
      'X-Telegram-Auth': 'tg-token-123',
      'X-Init-Data': 'user_id=12345',
    };

    const result = sm.applyToRequest('custom-1', {
      url: 'http://walletbot.me/api/offers',
      method: 'GET',
    });
    expect(result.headers?.['X-Telegram-Auth']).toBe('tg-token-123');
    expect(result.headers?.['X-Init-Data']).toBe('user_id=12345');
  });

  it('does not overwrite existing request headers', () => {
    sm.createSession({ id: 'no-overwrite', label: 'Test', authType: 'bearer' });
    const session = sm.getSession('no-overwrite')!;
    session.headers = { 'Authorization': 'Bearer session-token' };

    const result = sm.applyToRequest('no-overwrite', {
      url: 'http://target.com/api',
      method: 'GET',
      headers: { 'Authorization': 'Bearer agent-specified-token' },
    });
    // Agent-specified headers take precedence
    expect(result.headers?.['Authorization']).toBe('Bearer agent-specified-token');
  });

  it('returns unmodified options for non-existent session', () => {
    const options: HttpRequestOptions = {
      url: 'http://target.com/api',
      method: 'GET',
      headers: { 'Accept': 'text/html' },
    };

    const result = sm.applyToRequest('nonexistent-session', options);
    expect(result.headers?.['Accept']).toBe('text/html');
    expect(Object.keys(result.headers ?? {})).toHaveLength(1);
  });

  it('appends cookies to existing Cookie header', () => {
    sm.createSession({ id: 'append-cookie', label: 'Test', authType: 'cookie' });
    const session = sm.getSession('append-cookie')!;
    session.cookies = [makeCookie('auth', 'token')];

    const result = sm.applyToRequest('append-cookie', {
      url: 'http://target.com/api',
      method: 'GET',
      headers: { 'Cookie': 'existing=cookie' },
    });
    expect(result.headers?.['Cookie']).toBe('existing=cookie; auth=token');
  });

  it('injects CSRF token headers', () => {
    sm.createSession({ id: 'csrf-test', label: 'CSRF', authType: 'cookie' });
    const session = sm.getSession('csrf-test')!;
    session.csrfToken = 'csrf-token-456';

    const result = sm.applyToRequest('csrf-test', {
      url: 'http://target.com/api/action',
      method: 'POST',
    });
    expect(result.headers?.['X-CSRF-Token']).toBe('csrf-token-456');
    expect(result.headers?.['X-XSRF-Token']).toBe('csrf-token-456');
  });
});

// ─── Session Update from Response ──────────────────────────────────────────

describe('SessionManager.updateFromResponse', () => {
  let sm: SessionManager;

  beforeEach(() => {
    sm = new SessionManager(createMockHttpClient());
  });

  it('captures new cookies from response', () => {
    sm.createSession({ id: 'update-1', label: 'Test', authType: 'cookie' });

    sm.updateFromResponse('update-1', makeResponse({
      cookies: [makeCookie('new_session', 'fresh-token')],
    }));

    const session = sm.getSession('update-1')!;
    expect(session.cookies).toHaveLength(1);
    expect(session.cookies[0].name).toBe('new_session');
    expect(session.cookies[0].value).toBe('fresh-token');
  });

  it('updates existing cookie value', () => {
    sm.createSession({ id: 'update-2', label: 'Test', authType: 'cookie' });
    const session = sm.getSession('update-2')!;
    session.cookies = [makeCookie('token', 'old-value')];

    sm.updateFromResponse('update-2', makeResponse({
      cookies: [makeCookie('token', 'new-value')],
    }));

    expect(session.cookies).toHaveLength(1);
    expect(session.cookies[0].value).toBe('new-value');
  });

  it('captures CSRF from x-csrf-token response header', () => {
    sm.createSession({ id: 'csrf-update', label: 'Test', authType: 'cookie' });

    sm.updateFromResponse('csrf-update', makeResponse({
      headers: { 'x-csrf-token': 'rotated-csrf-789' },
    }));

    expect(sm.getSession('csrf-update')!.csrfToken).toBe('rotated-csrf-789');
  });

  it('no-ops for non-existent session', () => {
    // Should not throw
    sm.updateFromResponse('ghost-session', makeResponse());
  });
});

// ─── Auth Profile Config Type Tests ─────────────────────────────────────────

describe('AuthProfileConfig type validation', () => {
  it('bearer profile has correct shape', () => {
    const profile: AuthProfileConfig = {
      id: 'prof-1',
      label: 'Telegram Bearer',
      authType: 'bearer',
      url: 'https://walletbot.me/api/me',
    };
    expect(profile.authType).toBe('bearer');
    expect(profile.url).toBeDefined();
  });

  it('form login profile has correct shape', () => {
    const profile: AuthProfileConfig = {
      id: 'prof-2',
      label: 'Admin Login',
      authType: 'cookie',
      url: 'https://target.com/login',
      usernameField: 'email',
      passwordField: 'pass',
      csrfField: '_token',
    };
    expect(profile.authType).toBe('cookie');
    expect(profile.usernameField).toBe('email');
  });

  it('API key profile has correct shape', () => {
    const profile: AuthProfileConfig = {
      id: 'prof-3',
      label: 'API Access',
      authType: 'api_key',
      headerName: 'X-API-Key',
    };
    expect(profile.headerName).toBe('X-API-Key');
  });

  it('custom header profile has correct shape', () => {
    const profile: AuthProfileConfig = {
      id: 'prof-4',
      label: 'Telegram WebApp',
      authType: 'custom_header',
      customHeaderKeys: ['X-Telegram-Auth', 'X-Init-Data'],
    };
    expect(profile.customHeaderKeys).toHaveLength(2);
  });
});

// ─── SessionManager High-Level Login Methods ────────────────────────────────

describe('SessionManager login methods for hunt initialization', () => {
  it('loginWithBearer creates a validated session', async () => {
    const sm = new SessionManager(createMockHttpClient());
    const session = await sm.loginWithBearer(
      'jwt-token-abc',
      'http://target.com/api/health',
      'Telegram User'
    );
    expect(session.authType).toBe('bearer');
    expect(session.headers['Authorization']).toBe('Bearer jwt-token-abc');
    expect(session.label).toBe('Telegram User');
    expect(sm.listSessions()).toHaveLength(1);
  });

  it('loginWithBearer throws on 401 validation', async () => {
    const responses = new Map<string, Partial<HttpResponse>>();
    responses.set('GET http://target.com/api/health', { status: 401, statusText: 'Unauthorized' });

    const sm = new SessionManager(createMockHttpClient(responses));
    await expect(
      sm.loginWithBearer('bad-token', 'http://target.com/api/health')
    ).rejects.toThrow('validation failed');
  });

  it('loginWithApiKey creates a session without network call', () => {
    const sm = new SessionManager(createMockHttpClient());
    const session = sm.loginWithApiKey('X-API-Key', 'key-123', 'My API');
    expect(session.authType).toBe('api_key');
    expect(session.headers['X-API-Key']).toBe('key-123');
    expect(sm.listSessions()).toHaveLength(1);
  });

  it('session pair available after creating 2 sessions', async () => {
    const sm = new SessionManager(createMockHttpClient());
    await sm.loginWithBearer('token-a', 'http://target.com', 'User A');
    sm.loginWithApiKey('X-Key', 'key-b', 'User B');

    const pair = sm.getSessionPair();
    expect(pair).toBeDefined();
    expect(pair![0].label).toBe('User A');
    expect(pair![1].label).toBe('User B');
  });

  it('destroyAll clears all sessions', async () => {
    const sm = new SessionManager(createMockHttpClient());
    await sm.loginWithBearer('token-1', 'http://target.com', 'Session 1');
    sm.loginWithApiKey('X-Key', 'key-2', 'Session 2');
    expect(sm.listSessions()).toHaveLength(2);

    sm.destroyAll();
    expect(sm.listSessions()).toHaveLength(0);
  });
});

// ─── AuthFlowRunner custom session ──────────────────────────────────────────

describe('AuthFlowRunner.createCustomSession', () => {
  it('creates session with multiple custom headers', () => {
    const runner = new AuthFlowRunner(createMockHttpClient());
    const session = runner.createCustomSession({
      'X-Telegram-Auth': 'tg-token',
      'X-Init-Data': 'user_id=123&hash=abc',
      'Authorization': 'TelegramWebApp init_data_here',
    }, 'Telegram Mini App');

    expect(session.authType).toBe('custom_header');
    expect(session.label).toBe('Telegram Mini App');
    expect(Object.keys(session.headers)).toHaveLength(3);
    expect(session.headers['X-Telegram-Auth']).toBe('tg-token');
  });
});

// ─── Graceful Degradation Tests ─────────────────────────────────────────────

describe('Auth graceful degradation', () => {
  it('applyToRequest with missing session returns options unchanged', () => {
    const sm = new SessionManager(createMockHttpClient());

    const options: HttpRequestOptions = {
      url: 'http://target.com/api',
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    };

    // No sessions created — simulates auth failure during init
    const result = sm.applyToRequest('missing-session', options);
    expect(result.url).toBe(options.url);
    expect(result.headers?.['Accept']).toBe('application/json');
    // No auth headers added
    expect(result.headers?.['Authorization']).toBeUndefined();
    expect(result.headers?.['Cookie']).toBeUndefined();
  });

  it('updateFromResponse with missing session does not throw', () => {
    const sm = new SessionManager(createMockHttpClient());
    // Should not throw even without a session
    expect(() => {
      sm.updateFromResponse('missing-session', makeResponse({
        headers: { 'x-csrf-token': 'token' },
        cookies: [makeCookie('test', 'val', 'test')],
      }));
    }).not.toThrow();
  });

  it('multiple auth profiles — partial failure does not block others', async () => {
    const responses = new Map<string, Partial<HttpResponse>>();
    responses.set('GET http://target.com/api/health', { status: 401, statusText: 'Unauthorized' });

    const sm = new SessionManager(createMockHttpClient(responses));

    // First profile fails (401)
    let firstFailed = false;
    try {
      await sm.loginWithBearer('bad-token', 'http://target.com/api/health');
    } catch {
      firstFailed = true;
    }
    expect(firstFailed).toBe(true);

    // Second profile succeeds (API key — no network call)
    const session = sm.loginWithApiKey('X-Key', 'good-key', 'Backup Auth');
    expect(session).toBeDefined();
    expect(sm.listSessions()).toHaveLength(1);
  });
});

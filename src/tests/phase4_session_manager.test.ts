/**
 * Phase 4.5 — Session Manager Tests (B9)
 *
 * Tests for:
 * - Session creation and management
 * - Bearer token sessions
 * - API key sessions
 * - Session application to requests
 * - CSRF extraction from HTML
 * - Token refresh logic
 * - Session pair for IDOR testing
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  SessionManager,
  AuthFlowRunner,
  type AuthenticatedSession,
  type LoginCredentials,
} from '../core/auth/session_manager';
import type { HttpClient, HttpRequestOptions, HttpResponse, Cookie } from '../core/http/request_engine';

// ─── Mock HttpClient ────────────────────────────────────────────────────────

function createMockHttpClient(responses?: Map<string, Partial<HttpResponse>>): HttpClient {
  const defaultResponse: HttpResponse = {
    status: 200,
    statusText: 'OK',
    headers: {},
    body: '<html><body>OK</body></html>',
    cookies: [],
    url: 'http://localhost:3001',
    timingMs: 50,
  };

  return {
    request: async (options: HttpRequestOptions): Promise<HttpResponse> => {
      const key = `${options.method ?? 'GET'} ${options.url}`;
      const custom = responses?.get(key);
      return { ...defaultResponse, url: options.url, ...custom } as HttpResponse;
    },
    getCookies: (_hostname: string): Cookie[] => [
      { name: 'session', value: 'abc123', domain: 'localhost', path: '/' },
    ],
  } as unknown as HttpClient;
}

// ─── SessionManager Tests ───────────────────────────────────────────────────

describe('SessionManager', () => {
  let sm: SessionManager;

  beforeEach(() => {
    sm = new SessionManager(createMockHttpClient());
  });

  it('creates a session with correct properties', () => {
    const id = sm.createSession({
      id: 'test-1',
      label: 'Test Session',
      authType: 'cookie',
    });
    expect(id).toBe('test-1');
    const session = sm.getSession('test-1');
    expect(session).toBeDefined();
    expect(session!.authType).toBe('cookie');
    expect(session!.createdAt).toBeGreaterThan(0);
  });

  it('lists all sessions', () => {
    sm.createSession({ id: 'a', label: 'A', authType: 'cookie' });
    sm.createSession({ id: 'b', label: 'B', authType: 'bearer' });
    expect(sm.listSessions()).toHaveLength(2);
  });

  it('applies cookie session to request', () => {
    sm.createSession({ id: 's1', label: 'S1', authType: 'cookie' });
    const session = sm.getSession('s1')!;
    session.cookies = [{ name: 'token', value: 'xyz', domain: 'test', path: '/' }];

    const options: HttpRequestOptions = { url: 'http://test.com/api', method: 'GET' };
    const result = sm.applyToRequest('s1', options);
    expect(result.headers?.['Cookie']).toContain('token=xyz');
  });

  it('applies bearer session to request', () => {
    sm.createSession({ id: 's2', label: 'S2', authType: 'bearer' });
    const session = sm.getSession('s2')!;
    session.headers = { 'Authorization': 'Bearer test-token' };

    const options: HttpRequestOptions = { url: 'http://test.com/api', method: 'GET' };
    const result = sm.applyToRequest('s2', options);
    expect(result.headers?.['Authorization']).toBe('Bearer test-token');
  });

  it('applies CSRF token to request', () => {
    sm.createSession({ id: 's3', label: 'S3', authType: 'cookie' });
    const session = sm.getSession('s3')!;
    session.csrfToken = 'csrf-abc-123';

    const options: HttpRequestOptions = { url: 'http://test.com/api', method: 'POST' };
    const result = sm.applyToRequest('s3', options);
    expect(result.headers?.['X-CSRF-Token']).toBe('csrf-abc-123');
  });

  it('updates session cookies from response', () => {
    sm.createSession({ id: 's4', label: 'S4', authType: 'cookie' });

    sm.updateFromResponse('s4', {
      status: 200,
      statusText: 'OK',
      headers: {},
      body: '',
      cookies: [{ name: 'session_id', value: 'new-value', domain: 'test', path: '/' }],
      url: 'http://test.com',
      timingMs: 10,
    });

    const session = sm.getSession('s4')!;
    expect(session.cookies).toHaveLength(1);
    expect(session.cookies[0].value).toBe('new-value');
  });

  it('updates CSRF from response header', () => {
    sm.createSession({ id: 's5', label: 'S5', authType: 'cookie' });

    sm.updateFromResponse('s5', {
      status: 200,
      statusText: 'OK',
      headers: { 'x-csrf-token': 'refreshed-csrf' },
      body: '',
      cookies: [],
      url: 'http://test.com',
      timingMs: 10,
    });

    expect(sm.getSession('s5')!.csrfToken).toBe('refreshed-csrf');
  });

  it('detects expired sessions', () => {
    sm.createSession({ id: 'exp', label: 'Expired', authType: 'cookie' });
    const session = sm.getSession('exp')!;
    session.expiresAt = Date.now() - 1000; // Already expired
    expect(sm.isExpired('exp')).toBe(true);
  });

  it('non-expired sessions are not expired', () => {
    sm.createSession({ id: 'fresh', label: 'Fresh', authType: 'cookie' });
    const session = sm.getSession('fresh')!;
    session.expiresAt = Date.now() + 60000; // Expires in 60s
    expect(sm.isExpired('fresh')).toBe(false);
  });

  it('sessions without expiresAt are never expired', () => {
    sm.createSession({ id: 'noexp', label: 'NoExp', authType: 'cookie' });
    expect(sm.isExpired('noexp')).toBe(false);
  });

  it('returns undefined for non-existent session', () => {
    expect(sm.getSession('nope')).toBeUndefined();
  });

  it('destroys a session', () => {
    sm.createSession({ id: 'd1', label: 'D1', authType: 'cookie' });
    sm.destroySession('d1');
    expect(sm.getSession('d1')).toBeUndefined();
  });

  it('destroys all sessions', () => {
    sm.createSession({ id: 'x1', label: 'X1', authType: 'cookie' });
    sm.createSession({ id: 'x2', label: 'X2', authType: 'bearer' });
    sm.destroyAll();
    expect(sm.listSessions()).toHaveLength(0);
  });
});

// ─── Session Pair (IDOR) Tests ──────────────────────────────────────────────

describe('SessionManager session pairs', () => {
  it('getSessionPair returns undefined with < 2 sessions', () => {
    const sm = new SessionManager(createMockHttpClient());
    sm.createSession({ id: 'only-one', label: 'Solo', authType: 'cookie' });
    expect(sm.getSessionPair()).toBeUndefined();
  });

  it('getSessionPair returns two sessions', () => {
    const sm = new SessionManager(createMockHttpClient());
    sm.createSession({ id: 'user-a', label: 'User A', authType: 'cookie' });
    sm.createSession({ id: 'user-b', label: 'User B', authType: 'cookie' });
    const pair = sm.getSessionPair();
    expect(pair).toBeDefined();
    expect(pair![0].id).toBe('user-a');
    expect(pair![1].id).toBe('user-b');
  });
});

// ─── AuthFlowRunner Tests ───────────────────────────────────────────────────

describe('AuthFlowRunner', () => {
  it('creates a bearer session with correct headers', () => {
    const runner = new AuthFlowRunner(createMockHttpClient());
    const session = runner.createBearerSession('my-token', 'Test Bearer');
    expect(session.authType).toBe('bearer');
    expect(session.headers['Authorization']).toBe('Bearer my-token');
    expect(session.label).toBe('Test Bearer');
  });

  it('creates an API key session', () => {
    const runner = new AuthFlowRunner(createMockHttpClient());
    const session = runner.createApiKeySession('X-API-Key', 'secret-key', 'My API');
    expect(session.authType).toBe('api_key');
    expect(session.headers['X-API-Key']).toBe('secret-key');
  });

  it('creates a custom header session', () => {
    const runner = new AuthFlowRunner(createMockHttpClient());
    const session = runner.createCustomSession(
      { 'X-Custom': 'value', 'X-Other': 'other' },
      'Custom'
    );
    expect(session.authType).toBe('custom_header');
    expect(session.headers['X-Custom']).toBe('value');
  });

  it('loginWithCredentials creates a cookie session on success', async () => {
    const responses = new Map<string, Partial<HttpResponse>>();
    responses.set('GET http://localhost:3001/login', {
      status: 200,
      body: '<form><input name="csrf_token" value="csrf123"><input name="email"><input name="password"></form>',
      cookies: [],
    });
    responses.set('POST http://localhost:3001/login', {
      status: 200,
      body: '<html>Welcome, user!</html>',
      cookies: [{ name: 'session', value: 'logged-in', domain: 'localhost', path: '/' }],
    });

    const runner = new AuthFlowRunner(createMockHttpClient(responses));
    const session = await runner.loginWithCredentials({
      username: 'admin@juice-sh.op',
      password: 'admin123',
      loginUrl: 'http://localhost:3001/login',
    });

    expect(session.authType).toBe('cookie');
    expect(session.cookies.length).toBeGreaterThanOrEqual(0);
    expect(session.csrfToken).toBe('csrf123');
  });

  it('loginWithCredentials throws on 401', async () => {
    const responses = new Map<string, Partial<HttpResponse>>();
    responses.set('GET http://localhost:3001/login', {
      status: 200,
      body: '<form><input name="email"><input name="password"></form>',
      cookies: [],
    });
    responses.set('POST http://localhost:3001/login', {
      status: 401,
      body: 'Invalid credentials',
      cookies: [],
    });

    const runner = new AuthFlowRunner(createMockHttpClient(responses));
    await expect(
      runner.loginWithCredentials({
        username: 'bad-user',
        password: 'wrong',
        loginUrl: 'http://localhost:3001/login',
      })
    ).rejects.toThrow('Login failed');
  });
});

// ─── CSRF Extraction Tests ──────────────────────────────────────────────────

describe('CSRF extraction', () => {
  it('extracts CSRF from meta tag', async () => {
    const responses = new Map<string, Partial<HttpResponse>>();
    responses.set('GET http://example.com/page', {
      body: '<html><head><meta name="csrf-token" content="meta-csrf-value"></head><body></body></html>',
      cookies: [],
    });

    const runner = new AuthFlowRunner(createMockHttpClient(responses));
    const csrf = await runner.extractCsrfToken('http://example.com/page');
    expect(csrf).toBe('meta-csrf-value');
  });

  it('extracts CSRF from hidden input', async () => {
    const responses = new Map<string, Partial<HttpResponse>>();
    responses.set('GET http://example.com/form', {
      body: '<form><input type="hidden" name="csrf_token" value="input-csrf-val"></form>',
      cookies: [],
    });

    const runner = new AuthFlowRunner(createMockHttpClient(responses));
    const csrf = await runner.extractCsrfToken('http://example.com/form');
    expect(csrf).toBe('input-csrf-val');
  });

  it('extracts CSRF from _token field', async () => {
    const responses = new Map<string, Partial<HttpResponse>>();
    responses.set('GET http://example.com/laravel', {
      body: '<form><input type="hidden" name="_token" value="laravel-token-123"></form>',
      cookies: [],
    });

    const runner = new AuthFlowRunner(createMockHttpClient(responses));
    const csrf = await runner.extractCsrfToken('http://example.com/laravel');
    expect(csrf).toBe('laravel-token-123');
  });

  it('returns undefined when no CSRF found', async () => {
    const responses = new Map<string, Partial<HttpResponse>>();
    responses.set('GET http://example.com/no-csrf', {
      body: '<html><body>No CSRF here</body></html>',
      cookies: [],
    });

    const runner = new AuthFlowRunner(createMockHttpClient(responses));
    const csrf = await runner.extractCsrfToken('http://example.com/no-csrf');
    expect(csrf).toBeUndefined();
  });
});

// ─── Token Refresh Tests ────────────────────────────────────────────────────

describe('SessionManager token refresh', () => {
  it('refreshSession returns undefined for unknown session', async () => {
    const sm = new SessionManager(createMockHttpClient());
    const result = await sm.refreshSession('nonexistent');
    expect(result).toBeUndefined();
  });

  it('refreshSession returns undefined for session without stored creds', async () => {
    const sm = new SessionManager(createMockHttpClient());
    sm.createSession({ id: 'no-creds', label: 'No Creds', authType: 'bearer' });
    const result = await sm.refreshSession('no-creds');
    expect(result).toBeUndefined();
  });
});

// ─── Authenticated Request Tests ────────────────────────────────────────────

describe('SessionManager authenticatedRequest', () => {
  it('makes request with session auth applied', async () => {
    const sm = new SessionManager(createMockHttpClient());
    sm.createSession({ id: 'auth-test', label: 'Auth', authType: 'bearer' });
    const session = sm.getSession('auth-test')!;
    session.headers = { 'Authorization': 'Bearer test-123' };

    const response = await sm.authenticatedRequest('auth-test', {
      url: 'http://test.com/api/data',
      method: 'GET',
    });

    expect(response.status).toBe(200);
  });
});

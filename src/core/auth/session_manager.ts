/**
 * Authentication & Session Manager (Phase 20C)
 *
 * Manages authenticated sessions for agents. Handles form-based login,
 * Bearer tokens, API keys, CSRF extraction, and multi-user IDOR testing.
 */

import type { HttpClient, HttpRequestOptions, HttpResponse, Cookie } from '../http/request_engine';
import { TokenRefresher } from './token_refresher';
import type { RefreshConfig, RefreshErrorType } from './token_refresher';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface SessionConfig {
  id: string;
  label: string;
  authType: 'cookie' | 'bearer' | 'api_key' | 'custom_header';
}

export interface AuthenticatedSession {
  id: string;
  label: string;
  authType: SessionConfig['authType'];
  cookies: Cookie[];
  headers: Record<string, string>;
  csrfToken?: string;
  expiresAt?: number;
  createdAt: number;
}

export interface LoginCredentials {
  username: string;
  password: string;
  loginUrl: string;
  usernameField?: string;
  passwordField?: string;
  csrfField?: string;
}

// ─── Session Manager ────────────────────────────────────────────────────────

export class SessionManager {
  private sessions: Map<string, AuthenticatedSession> = new Map();
  private httpClient: HttpClient;
  private authFlowRunner: AuthFlowRunner | null = null;
  /** Stored credentials for token refresh (re-auth on 401) */
  private storedCredentials: Map<string, LoginCredentials> = new Map();
  /** Stored bearer tokens for validation */
  private storedBearerTokens: Map<string, string> = new Map();
  /** Refresh config per session — supports initdata, OAuth2, custom endpoint, re-login (S7/S8) */
  private storedRefreshConfigs: Map<string, RefreshConfig> = new Map();
  /** Token refresh service (S7) */
  private tokenRefresher: TokenRefresher;

  constructor(httpClient: HttpClient, options?: {
    onRefreshFailed?: (sessionId: string, error: RefreshErrorType, message: string) => void;
  }) {
    this.httpClient = httpClient;
    this.tokenRefresher = new TokenRefresher({
      onRefreshFailed: options?.onRefreshFailed,
    });
  }

  /** Get or create the AuthFlowRunner lazily */
  private getFlowRunner(): AuthFlowRunner {
    if (!this.authFlowRunner) {
      this.authFlowRunner = new AuthFlowRunner(this.httpClient);
    }
    return this.authFlowRunner;
  }

  createSession(config: SessionConfig): string {
    const session: AuthenticatedSession = {
      id: config.id,
      label: config.label,
      authType: config.authType,
      cookies: [],
      headers: {},
      createdAt: Date.now(),
    };
    this.sessions.set(config.id, session);
    return config.id;
  }

  getSession(id: string): AuthenticatedSession | undefined {
    return this.sessions.get(id);
  }

  listSessions(): AuthenticatedSession[] {
    return [...this.sessions.values()];
  }

  /**
   * Resolve a session ID by its human label (Phase 1 / Q3).
   *
   * Labels are how agents refer to identities in multi-identity tests —
   * e.g. `session_label: "victim"` on an `http_request` call. Matches
   * case-insensitively to reduce agent-side mistakes. Returns undefined
   * when no session matches — callers should surface that as a tool error,
   * not silently fall back to the default session.
   */
  findByLabel(label: string): string | undefined {
    if (!label) return undefined;
    const needle = label.toLowerCase();
    for (const session of this.sessions.values()) {
      if (session.label === label) return session.id;
    }
    for (const session of this.sessions.values()) {
      if (session.label.toLowerCase() === needle) return session.id;
    }
    return undefined;
  }

  /** Apply session auth context to an HttpRequestOptions */
  applyToRequest(sessionId: string, options: HttpRequestOptions): HttpRequestOptions {
    const session = this.sessions.get(sessionId);
    if (!session) return options;

    const headers = { ...options.headers };

    // Apply auth headers
    for (const [key, value] of Object.entries(session.headers)) {
      if (!headers[key]) {
        headers[key] = value;
      }
    }

    // Apply cookies
    if (session.cookies.length > 0) {
      const cookieStr = session.cookies.map(c => `${c.name}=${c.value}`).join('; ');
      headers['Cookie'] = headers['Cookie']
        ? `${headers['Cookie']}; ${cookieStr}`
        : cookieStr;
    }

    // Apply CSRF token
    if (session.csrfToken) {
      headers['X-CSRF-Token'] = session.csrfToken;
      headers['X-XSRF-Token'] = session.csrfToken;
    }

    return { ...options, headers };
  }

  /** Update session from response (capture new cookies, CSRF tokens) */
  updateFromResponse(sessionId: string, response: HttpResponse): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    // Update cookies from response
    if (response.cookies.length > 0) {
      for (const cookie of response.cookies) {
        const existing = session.cookies.findIndex(c => c.name === cookie.name);
        if (existing >= 0) {
          session.cookies[existing] = cookie;
        } else {
          session.cookies.push(cookie);
        }
      }
    }

    // Extract CSRF tokens from common headers
    const csrfHeader = response.headers['x-csrf-token']
      ?? response.headers['x-xsrf-token']
      ?? response.headers['csrf-token'];
    if (csrfHeader) {
      session.csrfToken = csrfHeader;
    }
  }

  /** Get a session pair for IDOR testing (user A vs user B) */
  getSessionPair(): [AuthenticatedSession, AuthenticatedSession] | undefined {
    const sessions = this.listSessions();
    if (sessions.length < 2) return undefined;
    return [sessions[0], sessions[1]];
  }

  /**
   * High-level login: runs AuthFlowRunner and stores the session + credentials.
   * Stores credentials so the session can be refreshed on 401.
   */
  async login(creds: LoginCredentials): Promise<AuthenticatedSession> {
    const runner = this.getFlowRunner();
    const session = await runner.loginWithCredentials(creds);
    this.sessions.set(session.id, session);
    this.storedCredentials.set(session.id, creds);
    return session;
  }

  /**
   * Create and validate a Bearer token session via a two-probe differential
   * (Phase 1 / Q6 Gap 5).
   *
   * Probes the validation URL once WITH the token and once WITHOUT, then
   * classifies the pair:
   *   - auth=2xx/3xx, baseline=401/403  → `valid`   (token made a difference)
   *   - auth=401/403                    → `invalid` (token actively rejected)
   *   - auth=2xx, baseline=2xx, differ  → `valid`   (observed behavioral diff)
   *   - auth=2xx, baseline=2xx, same    → `unknown` (no info — accept)
   *   - both 5xx / network error        → `unknown` (no info — accept)
   *
   * Only `invalid` throws. `unknown` accepts the session — if the token is
   * actually dead, the first real request will 401 and auto-refresh handles it.
   * Prior behavior treated any non-401 response as valid, which passed bogus
   * tokens against endpoints that 500 on missing auth (e.g., pay.wallet.tg).
   */
  async loginWithBearer(token: string, validationUrl: string, label?: string): Promise<AuthenticatedSession> {
    const runner = this.getFlowRunner();
    const session = runner.createBearerSession(token, label);

    const verdict = await this.probeBearer(token, validationUrl);
    if (verdict === 'invalid') {
      throw new Error('Bearer token validation failed: token actively rejected by target');
    }

    // S7: Populate expiresAt from JWT exp claim if present
    this.populateExpiresAtFromHeaders(session);

    this.sessions.set(session.id, session);
    this.storedBearerTokens.set(session.id, token);
    return session;
  }

  /** Two-probe bearer validation — exposed for tests. */
  async probeBearer(token: string, validationUrl: string): Promise<'valid' | 'invalid' | 'unknown'> {
    const probe = async (headers?: Record<string, string>) => {
      try {
        return await this.httpClient.request({
          url: validationUrl,
          method: 'GET',
          headers,
        });
      } catch {
        return null;
      }
    };

    const [withAuth, withoutAuth] = await Promise.all([
      probe({ Authorization: `Bearer ${token}` }),
      probe(),
    ]);

    // Network error on the auth probe: uninformative
    if (!withAuth) return 'unknown';

    // Token actively rejected — strongest invalid signal
    if (withAuth.status === 401 || withAuth.status === 403) return 'invalid';

    // Baseline succeeded WITHOUT auth — either the endpoint is public
    // (token makes no difference) or the target is returning cached/default
    // content. Compare bodies to decide.
    if (withoutAuth && withoutAuth.status >= 200 && withoutAuth.status < 400) {
      if (withAuth.body !== withoutAuth.body || withAuth.status !== withoutAuth.status) {
        return 'valid';
      }
      return 'unknown';
    }

    // Baseline 401/403 + auth 2xx/3xx: textbook valid
    if (withoutAuth && (withoutAuth.status === 401 || withoutAuth.status === 403)) {
      if (withAuth.status >= 200 && withAuth.status < 400) return 'valid';
    }

    // Both 5xx / other: no info
    return 'unknown';
  }

  /**
   * Create and register an API key session.
   */
  loginWithApiKey(headerName: string, apiKey: string, label?: string): AuthenticatedSession {
    const runner = this.getFlowRunner();
    const session = runner.createApiKeySession(headerName, apiKey, label);
    this.sessions.set(session.id, session);
    return session;
  }

  /**
   * Handle a 401 response by refreshing credentials.
   * Dispatches by RefreshConfig type (S8), falls back to stored credentials.
   * Returns the refreshed session, or undefined if refresh is not possible.
   */
  async refreshSession(sessionId: string): Promise<AuthenticatedSession | undefined> {
    const session = this.sessions.get(sessionId);
    if (!session) return undefined;

    // S8: Check for RefreshConfig first — handles all refresh strategies
    const refreshConfig = this.storedRefreshConfigs.get(sessionId);
    if (refreshConfig) {
      // re_login: delegate to login() with stored credentials
      if (refreshConfig.type === 're_login') {
        const creds = this.storedCredentials.get(sessionId);
        if (creds) {
          try {
            const runner = this.getFlowRunner();
            const newSession = await runner.loginWithCredentials(creds);
            newSession.id = sessionId;
            this.sessions.set(sessionId, newSession);
            return newSession;
          } catch {
            return undefined;
          }
        }
        return undefined;
      }

      // initdata_exchange, refresh_token, custom_endpoint: use TokenRefresher
      const result = await this.tokenRefresher.refreshTokens(
        sessionId, refreshConfig, this.httpClient,
      );
      if (result.success && result.tokens) {
        // For OAuth2, update the stored refresh_token if rotated
        if (refreshConfig.type === 'refresh_token' && result.tokens['__new_refresh_token']) {
          refreshConfig.refreshToken = result.tokens['__new_refresh_token'];
          delete result.tokens['__new_refresh_token'];
        }
        Object.assign(session.headers, result.tokens);
        session.expiresAt = Date.now() + refreshConfig.tokenTtlSeconds * 1000;
        // Re-populate expiresAt from JWT if available (more accurate than TTL)
        this.populateExpiresAtFromHeaders(session);
        return session;
      }
      return undefined;
    }

    // Legacy fallback: try re-login with stored credentials (no RefreshConfig)
    const creds = this.storedCredentials.get(sessionId);
    if (creds) {
      try {
        const runner = this.getFlowRunner();
        const newSession = await runner.loginWithCredentials(creds);
        newSession.id = sessionId;
        this.sessions.set(sessionId, newSession);
        return newSession;
      } catch {
        return undefined;
      }
    }

    // Bearer tokens without RefreshConfig can't be refreshed
    const token = this.storedBearerTokens.get(sessionId);
    if (token) {
      session.expiresAt = Date.now();
      return undefined;
    }

    return undefined;
  }

  /**
   * Make an authenticated request, automatically refreshing on 401.
   */
  async authenticatedRequest(
    sessionId: string,
    options: HttpRequestOptions
  ): Promise<HttpResponse> {
    const authedOptions = this.applyToRequest(sessionId, options);
    const response = await this.httpClient.request(authedOptions);

    // Auto-refresh on 401
    if (response.status === 401) {
      const refreshed = await this.refreshSession(sessionId);
      if (refreshed) {
        const retryOptions = this.applyToRequest(sessionId, options);
        return this.httpClient.request(retryOptions);
      }
    }

    // Update session cookies from response
    this.updateFromResponse(sessionId, response);
    return response;
  }

  /**
   * Populate expiresAt by scanning session headers for JWTs with exp claims (S7).
   * Uses the earliest expiry across all JWT headers.
   */
  private populateExpiresAtFromHeaders(session: AuthenticatedSession): void {
    let earliestExpiry: number | undefined;

    for (const value of Object.values(session.headers)) {
      const expiry = this.tokenRefresher.getTokenExpiry(value);
      if (expiry !== undefined) {
        if (earliestExpiry === undefined || expiry < earliestExpiry) {
          earliestExpiry = expiry;
        }
      }
    }

    if (earliestExpiry !== undefined) {
      session.expiresAt = earliestExpiry;
    }
  }

  /**
   * Store refresh config for a session, enabling automatic token refresh (S7/S8).
   * Supports all RefreshConfig types: initdata_exchange, refresh_token,
   * custom_endpoint, re_login.
   * Also populates expiresAt from the current JWT headers if possible.
   */
  setRefreshConfig(sessionId: string, config: RefreshConfig): void {
    this.storedRefreshConfigs.set(sessionId, config);

    // Populate expiresAt from current JWT headers
    const session = this.sessions.get(sessionId);
    if (session) {
      this.populateExpiresAtFromHeaders(session);
    }
  }

  /** Get the token refresher instance (for direct access in tests) */
  getTokenRefresher(): TokenRefresher {
    return this.tokenRefresher;
  }

  destroySession(id: string): void {
    this.sessions.delete(id);
    this.storedCredentials.delete(id);
    this.storedBearerTokens.delete(id);
    this.storedRefreshConfigs.delete(id);
  }

  destroyAll(): void {
    this.sessions.clear();
    this.storedCredentials.clear();
    this.storedBearerTokens.clear();
    this.storedRefreshConfigs.clear();
    this.tokenRefresher.resetRateLimits();
  }

  /** Check if a session is expired */
  isExpired(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return true;
    if (!session.expiresAt) return false;
    return Date.now() > session.expiresAt;
  }

  /**
   * Get a session pair for IDOR testing.
   * Creates two pre-authenticated sessions for user A and user B.
   */
  async getAuthenticatedSessionPair(
    credsA: LoginCredentials,
    credsB: LoginCredentials
  ): Promise<[AuthenticatedSession, AuthenticatedSession]> {
    const sessionA = await this.login(credsA);
    const sessionB = await this.login(credsB);
    return [sessionA, sessionB];
  }
}

// ─── Auth Flow Runner ───────────────────────────────────────────────────────

export class AuthFlowRunner {
  private httpClient: HttpClient;

  constructor(httpClient: HttpClient) {
    this.httpClient = httpClient;
  }

  /** Form-based login: GET login page → extract CSRF → POST credentials */
  async loginWithCredentials(creds: LoginCredentials): Promise<AuthenticatedSession> {
    const usernameField = creds.usernameField ?? 'username';
    const passwordField = creds.passwordField ?? 'password';

    // Step 1: GET the login page
    const loginPage = await this.httpClient.request({
      url: creds.loginUrl,
      method: 'GET',
    });

    // Step 2: Extract CSRF token
    const csrfToken = this.extractCsrfFromHtml(loginPage.body, creds.csrfField);

    // Step 3: Build form data
    const formParams = new URLSearchParams();
    formParams.set(usernameField, creds.username);
    formParams.set(passwordField, creds.password);
    if (csrfToken && creds.csrfField) {
      formParams.set(creds.csrfField, csrfToken);
    } else if (csrfToken) {
      // Try common CSRF field names
      formParams.set('_token', csrfToken);
    }

    // Step 4: POST credentials
    const loginResponse = await this.httpClient.request({
      url: creds.loginUrl,
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formParams.toString(),
      followRedirects: true,
    });

    // Step 5: Check login success
    // Heuristic: successful login typically redirects away from login page
    // or returns 200 with different content
    const loginFailed =
      loginResponse.status === 401 ||
      loginResponse.status === 403 ||
      (loginResponse.body.toLowerCase().includes('invalid') && loginResponse.body.toLowerCase().includes('password')) ||
      (loginResponse.body.toLowerCase().includes('incorrect') && loginResponse.body.toLowerCase().includes('credentials'));

    if (loginFailed) {
      throw new Error('Login failed: invalid credentials or login form not recognized');
    }

    // Step 6: Build session from cookies
    const session: AuthenticatedSession = {
      id: `session_${Date.now()}`,
      label: `${creds.username}@${new URL(creds.loginUrl).hostname}`,
      authType: 'cookie',
      cookies: this.httpClient.getCookies(new URL(creds.loginUrl).hostname),
      headers: {},
      csrfToken: csrfToken ?? undefined,
      createdAt: Date.now(),
    };

    return session;
  }

  /** Create a Bearer token session */
  createBearerSession(token: string, label?: string): AuthenticatedSession {
    return {
      id: `bearer_${Date.now()}`,
      label: label ?? 'Bearer Token',
      authType: 'bearer',
      cookies: [],
      headers: { 'Authorization': `Bearer ${token}` },
      createdAt: Date.now(),
    };
  }

  /** Create an API key session */
  createApiKeySession(headerName: string, apiKey: string, label?: string): AuthenticatedSession {
    return {
      id: `apikey_${Date.now()}`,
      label: label ?? 'API Key',
      authType: 'api_key',
      cookies: [],
      headers: { [headerName]: apiKey },
      createdAt: Date.now(),
    };
  }

  /** Create a custom header session */
  createCustomSession(headers: Record<string, string>, label?: string): AuthenticatedSession {
    return {
      id: `custom_${Date.now()}`,
      label: label ?? 'Custom Auth',
      authType: 'custom_header',
      cookies: [],
      headers,
      createdAt: Date.now(),
    };
  }

  /** Extract CSRF token from an HTML page */
  async extractCsrfToken(pageUrl: string, fieldName?: string): Promise<string | undefined> {
    const response = await this.httpClient.request({
      url: pageUrl,
      method: 'GET',
    });
    return this.extractCsrfFromHtml(response.body, fieldName);
  }

  /** Extract CSRF token from HTML content */
  private extractCsrfFromHtml(html: string, fieldName?: string): string | undefined {
    // Check specific field name first
    if (fieldName) {
      const pattern = new RegExp(`name\\s*=\\s*["']${fieldName}["'][^>]*value\\s*=\\s*["']([^"']+)["']`, 'i');
      const match = pattern.exec(html);
      if (match) return match[1];

      // Try reverse order (value before name)
      const reversePattern = new RegExp(`value\\s*=\\s*["']([^"']+)["'][^>]*name\\s*=\\s*["']${fieldName}["']`, 'i');
      const reverseMatch = reversePattern.exec(html);
      if (reverseMatch) return reverseMatch[1];
    }

    // Common CSRF patterns
    const patterns: RegExp[] = [
      /name\s*=\s*["']csrf[_-]?token["'][^>]*value\s*=\s*["']([^"']+)["']/i,
      /value\s*=\s*["']([^"']+)["'][^>]*name\s*=\s*["']csrf[_-]?token["']/i,
      /name\s*=\s*["']_token["'][^>]*value\s*=\s*["']([^"']+)["']/i,
      /value\s*=\s*["']([^"']+)["'][^>]*name\s*=\s*["']_token["']/i,
      /name\s*=\s*["']authenticity_token["'][^>]*value\s*=\s*["']([^"']+)["']/i,
      /name\s*=\s*["']csrfmiddlewaretoken["'][^>]*value\s*=\s*["']([^"']+)["']/i,
      /<meta\s+name\s*=\s*["']csrf-token["']\s+content\s*=\s*["']([^"']+)["']/i,
      /<meta\s+content\s*=\s*["']([^"']+)["']\s+name\s*=\s*["']csrf-token["']/i,
    ];

    for (const pattern of patterns) {
      const match = pattern.exec(html);
      if (match) return match[1];
    }

    return undefined;
  }
}

export default SessionManager;

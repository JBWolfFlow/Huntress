/**
 * Authentication & Session Manager (Phase 20C)
 *
 * Manages authenticated sessions for agents. Handles form-based login,
 * Bearer tokens, API keys, CSRF extraction, and multi-user IDOR testing.
 */

import type { HttpClient, HttpRequestOptions, HttpResponse, Cookie } from '../http/request_engine';

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

  constructor(httpClient: HttpClient) {
    this.httpClient = httpClient;
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

  destroySession(id: string): void {
    this.sessions.delete(id);
  }

  destroyAll(): void {
    this.sessions.clear();
  }

  /** Check if a session is expired */
  isExpired(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return true;
    if (!session.expiresAt) return false;
    return Date.now() > session.expiresAt;
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

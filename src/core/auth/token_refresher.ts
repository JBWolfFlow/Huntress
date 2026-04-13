/**
 * Token Refresher Service (S7 + S8)
 *
 * Handles JWT token lifecycle: expiry detection, multi-strategy token refresh,
 * and rate-limited refresh. Three-layer defense: proactive (90s threshold),
 * reactive (401 auto-retry), fallback (hunt pause on expired credentials).
 *
 * S8: Generalized beyond Telegram — supports OAuth2 refresh_token, custom
 * endpoints, and re-login delegation via RefreshConfig discriminated union.
 */

import type { HttpClient, HttpRequestOptions } from '../http/request_engine';
import type { AuthenticatedSession } from './session_manager';

// ─── Types ───────────────────────────────────────────────────────────────────

/**
 * Discriminated union for token refresh strategies.
 * Each variant encapsulates the data needed for one refresh mechanism.
 */
export type RefreshConfig =
  | {
      type: 'initdata_exchange';
      /** The raw initData string (e.g., Telegram WebApp) */
      initData: string;
      /** The auth endpoint URL that exchanges initData for JWTs */
      authEndpointUrl: string;
      /** Device serial UUID (does not expire) */
      deviceSerial: string;
      /** Token TTL in seconds (detected from JWT exp claim or default 600) */
      tokenTtlSeconds: number;
      /** Mapping of response JSON field → request header name */
      tokenHeaderMap: Record<string, string>;
    }
  | {
      type: 'refresh_token';
      /** The OAuth2 refresh token */
      refreshToken: string;
      /** The token endpoint URL */
      tokenEndpoint: string;
      /** OAuth2 client_id (if required by the provider) */
      clientId?: string;
      /** OAuth2 client_secret (if required — rare for public clients) */
      clientSecret?: string;
      /** OAuth2 scope (if required) */
      scope?: string;
      /** Token TTL in seconds */
      tokenTtlSeconds: number;
    }
  | {
      type: 'custom_endpoint';
      /** The refresh endpoint URL */
      refreshEndpoint: string;
      /** HTTP method */
      method: 'GET' | 'POST';
      /** Extra headers for the refresh request */
      headers?: Record<string, string>;
      /** Request body (for POST) */
      body?: string;
      /** Mapping of response JSON field → request header name */
      tokenHeaderMap: Record<string, string>;
      /** Token TTL in seconds */
      tokenTtlSeconds: number;
    }
  | {
      type: 're_login';
      /* Handled at SessionManager level — uses storedCredentials */
    };

/** Backwards-compatible alias for the Telegram initData refresh config */
export type TelegramAuthData = Extract<RefreshConfig, { type: 'initdata_exchange' }>;

export type RefreshErrorType = 'expired_credentials' | 'network_error' | 'server_error';

export interface RefreshResult {
  success: boolean;
  tokens?: Record<string, string>;
  error?: RefreshErrorType;
  message?: string;
}

/** Default proactive refresh threshold: 90 seconds before expiry */
const DEFAULT_REFRESH_THRESHOLD_MS = 90_000;

/** Minimum interval between refresh attempts per session: 30 seconds */
const RATE_LIMIT_MS = 30_000;

/** Retry delay on network errors: 2 seconds */
const NETWORK_RETRY_DELAY_MS = 2_000;

// ─── Token Refresher ────────────────────────────────────────────────────────

export class TokenRefresher {
  /** Tracks last refresh time per session to enforce rate limiting */
  private lastRefreshTime: Map<string, number> = new Map();
  /** In-flight refresh promises per session — deduplicates concurrent calls */
  private inflightRefreshes: Map<string, Promise<RefreshResult>> = new Map();
  /** Callback when refresh fails due to expired initData */
  private onRefreshFailed?: (sessionId: string, error: RefreshErrorType, message: string) => void;

  constructor(options?: {
    onRefreshFailed?: (sessionId: string, error: RefreshErrorType, message: string) => void;
  }) {
    this.onRefreshFailed = options?.onRefreshFailed;
  }

  /**
   * Parse JWT exp claim to determine token expiry time.
   * Returns the expiry timestamp in milliseconds, or undefined if unparseable.
   * No external JWT libraries — just base64 decode + JSON.parse.
   */
  getTokenExpiry(jwt: string): number | undefined {
    try {
      const parts = jwt.split('.');
      if (parts.length !== 3) return undefined;

      // Convert base64url to base64
      const payload = parts[1]
        .replace(/-/g, '+')
        .replace(/_/g, '/');

      // Decode and parse
      const decoded = JSON.parse(atob(payload));
      if (typeof decoded.exp === 'number') {
        // JWT exp is in seconds, convert to ms
        return decoded.exp * 1000;
      }
      return undefined;
    } catch {
      return undefined;
    }
  }

  /**
   * Check if a session needs refresh (within threshold of expiry).
   * Returns true if the session has an expiresAt and it's within the threshold.
   */
  needsRefresh(session: AuthenticatedSession, thresholdMs: number = DEFAULT_REFRESH_THRESHOLD_MS): boolean {
    if (!session.expiresAt) return false;
    const msUntilExpiry = session.expiresAt - Date.now();
    return msUntilExpiry < thresholdMs;
  }

  /**
   * Check if a refresh is rate-limited for a given session.
   * Returns true if a refresh was performed within the last RATE_LIMIT_MS.
   */
  isRateLimited(sessionId: string): boolean {
    const lastTime = this.lastRefreshTime.get(sessionId);
    if (!lastTime) return false;
    return (Date.now() - lastTime) < RATE_LIMIT_MS;
  }

  /**
   * Refresh tokens using the provided RefreshConfig strategy.
   * Rate-limited to 1 refresh per 30s per session. Concurrent calls are deduplicated.
   * All HTTP goes through the HttpClient chokepoint.
   *
   * Dispatches by config.type:
   * - initdata_exchange: POST initData to auth endpoint (Telegram pattern)
   * - refresh_token: POST grant_type=refresh_token to token endpoint (OAuth2)
   * - custom_endpoint: POST/GET to any URL, map response JSON to headers
   * - re_login: not handled here — SessionManager delegates to login()
   */
  async refreshTokens(
    sessionId: string,
    config: RefreshConfig,
    httpClient: HttpClient,
  ): Promise<RefreshResult> {
    // re_login is handled at SessionManager level, not here
    if (config.type === 're_login') {
      return {
        success: false,
        error: 'server_error',
        message: 're_login refresh must be handled by SessionManager',
      };
    }

    // Rate limit check
    if (this.isRateLimited(sessionId)) {
      return {
        success: false,
        error: 'server_error',
        message: `Rate limited: refresh attempted within ${RATE_LIMIT_MS / 1000}s window`,
      };
    }

    // Deduplicate concurrent refresh attempts for the same session
    const inflight = this.inflightRefreshes.get(sessionId);
    if (inflight) {
      return inflight;
    }

    const refreshPromise = this.executeRefresh(sessionId, config, httpClient);
    this.inflightRefreshes.set(sessionId, refreshPromise);

    try {
      const result = await refreshPromise;
      return result;
    } finally {
      this.inflightRefreshes.delete(sessionId);
    }
  }

  /**
   * Build the HTTP request options for a given refresh config type.
   */
  private buildRefreshRequest(config: Exclude<RefreshConfig, { type: 're_login' }>): HttpRequestOptions {
    switch (config.type) {
      case 'initdata_exchange':
        return {
          url: config.authEndpointUrl,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(config.deviceSerial ? { 'x-wallet-device-serial': config.deviceSerial } : {}),
          },
          body: JSON.stringify({ initData: config.initData }),
          timeoutMs: 10_000,
        };

      case 'refresh_token': {
        const params = new URLSearchParams();
        params.set('grant_type', 'refresh_token');
        params.set('refresh_token', config.refreshToken);
        if (config.clientId) params.set('client_id', config.clientId);
        if (config.clientSecret) params.set('client_secret', config.clientSecret);
        if (config.scope) params.set('scope', config.scope);

        return {
          url: config.tokenEndpoint,
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: params.toString(),
          timeoutMs: 10_000,
        };
      }

      case 'custom_endpoint':
        return {
          url: config.refreshEndpoint,
          method: config.method,
          headers: {
            ...(config.method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
            ...config.headers,
          },
          ...(config.body ? { body: config.body } : {}),
          timeoutMs: 10_000,
        };
    }
  }

  /**
   * Get the token header map from a refresh config.
   * For OAuth2 refresh_token, the standard mapping is access_token → Authorization (Bearer).
   */
  private getTokenHeaderMap(config: Exclude<RefreshConfig, { type: 're_login' }>): Record<string, string> {
    switch (config.type) {
      case 'initdata_exchange':
        return config.tokenHeaderMap;
      case 'refresh_token':
        // OAuth2 standard: map access_token to Authorization header
        return { 'access_token': 'Authorization' };
      case 'custom_endpoint':
        return config.tokenHeaderMap;
    }
  }

  /**
   * Execute the actual token refresh. Retries once on network error.
   */
  private async executeRefresh(
    sessionId: string,
    config: Exclude<RefreshConfig, { type: 're_login' }>,
    httpClient: HttpClient,
  ): Promise<RefreshResult> {
    const requestOptions = this.buildRefreshRequest(config);
    const tokenHeaderMap = this.getTokenHeaderMap(config);
    const ttl = config.tokenTtlSeconds;

    // First attempt
    let result = await this.attemptRefresh(sessionId, tokenHeaderMap, config.type, ttl, httpClient, requestOptions);

    // Retry once on network error
    if (!result.success && result.error === 'network_error') {
      await new Promise(resolve => setTimeout(resolve, NETWORK_RETRY_DELAY_MS));
      result = await this.attemptRefresh(sessionId, tokenHeaderMap, config.type, ttl, httpClient, requestOptions);
    }

    // If final failure, notify via callback
    if (!result.success && this.onRefreshFailed) {
      this.onRefreshFailed(sessionId, result.error!, result.message!);
    }

    return result;
  }

  /**
   * Single refresh attempt — make HTTP request, parse response, map tokens.
   */
  private async attemptRefresh(
    sessionId: string,
    tokenHeaderMap: Record<string, string>,
    configType: string,
    ttlSeconds: number,
    httpClient: HttpClient,
    requestOptions: HttpRequestOptions,
  ): Promise<RefreshResult> {
    try {
      const response = await httpClient.request(requestOptions);

      // Auth endpoint returned error — credentials likely expired
      if (response.status === 401 || response.status === 403) {
        return {
          success: false,
          error: 'expired_credentials',
          message: `Auth endpoint returned ${response.status}: credentials may be expired.`,
        };
      }

      if (response.status >= 400) {
        return {
          success: false,
          error: 'server_error',
          message: `Auth endpoint returned ${response.status}: ${response.body.substring(0, 200)}`,
        };
      }

      // Parse response body for tokens
      let responseData: Record<string, unknown>;
      try {
        responseData = JSON.parse(response.body);
      } catch {
        return {
          success: false,
          error: 'server_error',
          message: 'Auth endpoint returned non-JSON response',
        };
      }

      // Map response fields to header names
      const tokens: Record<string, string> = {};
      for (const [responseField, headerName] of Object.entries(tokenHeaderMap)) {
        const value = this.extractNestedValue(responseData, responseField);
        if (typeof value === 'string') {
          // OAuth2: access_token maps to "Authorization" with "Bearer " prefix
          if (configType === 'refresh_token' && responseField === 'access_token') {
            tokens[headerName] = `Bearer ${value}`;
          } else {
            tokens[headerName] = value;
          }
        }
      }

      // For OAuth2, also capture the new refresh_token if rotated
      if (configType === 'refresh_token' && typeof responseData['refresh_token'] === 'string') {
        tokens['__new_refresh_token'] = responseData['refresh_token'] as string;
      }

      if (Object.keys(tokens).length === 0) {
        return {
          success: false,
          error: 'server_error',
          message: `No tokens found in response. Expected fields: ${Object.keys(tokenHeaderMap).join(', ')}`,
        };
      }

      // Record successful refresh time for rate limiting
      this.lastRefreshTime.set(sessionId, Date.now());

      console.log(
        `[auth-refresh] Tokens refreshed for session ${sessionId} ` +
        `(${Object.keys(tokens).length} headers updated, TTL ${ttlSeconds}s, type=${configType})`
      );

      return { success: true, tokens };
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      console.error(`[auth-monitor] Token refresh failed for session ${sessionId}:`, errMsg);
      return {
        success: false,
        error: 'network_error',
        message: `Token refresh error: ${errMsg}`,
      };
    }
  }

  /**
   * Extract a value from a nested object using dot-notation path.
   * e.g., "data.token" extracts obj.data.token
   */
  private extractNestedValue(obj: Record<string, unknown>, path: string): unknown {
    const parts = path.split('.');
    let current: unknown = obj;
    for (const part of parts) {
      if (current === null || current === undefined || typeof current !== 'object') {
        return undefined;
      }
      current = (current as Record<string, unknown>)[part];
    }
    return current;
  }

  /**
   * Detect token TTL from a JWT's exp claim.
   * Returns TTL in seconds, or the default (600 = 10 min) if unparseable.
   */
  detectTokenTtl(jwt: string, defaultTtlSeconds: number = 600): number {
    const expiryMs = this.getTokenExpiry(jwt);
    if (!expiryMs) return defaultTtlSeconds;
    const ttlSeconds = Math.floor((expiryMs - Date.now()) / 1000);
    return ttlSeconds > 0 ? ttlSeconds : defaultTtlSeconds;
  }

  /** Reset rate limit state (for testing) */
  resetRateLimits(): void {
    this.lastRefreshTime.clear();
    this.inflightRefreshes.clear();
  }
}

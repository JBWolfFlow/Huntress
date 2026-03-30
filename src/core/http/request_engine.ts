/**
 * HTTP Request Engine — Direct HTTP Client for Agents
 *
 * Replaces curl-via-PTY with direct HTTP requests. This is the critical
 * foundation for making agents 10-100x faster by eliminating LLM inference
 * cycles for every HTTP operation.
 *
 * Key features:
 * - Scope enforcement on every request via Tauri bridge
 * - Cookie jar with automatic Set-Cookie handling
 * - Per-domain rate limiting with sliding window
 * - 429 exponential backoff with Retry-After support
 * - Full request/response logging for PoC evidence
 * - Proxy support via axios config
 * - Kill switch integration
 * - Redirect chain tracking
 */

import axios from 'axios';
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { invoke } from '@tauri-apps/api/core';

// ─── Environment Detection ──────────────────────────────────────────────────

function checkIsTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}
const isNode = typeof process !== 'undefined' && !!process.versions?.node;

// ─── Types ───────────────────────────────────────────────────────────────────

export interface HttpRequestOptions {
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD';
  headers?: Record<string, string>;
  body?: string;
  followRedirects?: boolean;
  timeoutMs?: number;
  proxyUrl?: string;
  contentType?: string;
}

export interface HttpResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  timing: {
    dnsMs: number;
    connectMs: number;
    ttfbMs: number;
    totalMs: number;
  };
  redirectChain: Array<{ url: string; status: number }>;
  cookies: Cookie[];
  size: number;
}

export interface Cookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  httpOnly: boolean;
  secure: boolean;
  expires?: number;
  sameSite?: 'Strict' | 'Lax' | 'None';
}

export interface HttpClientConfig {
  defaultHeaders?: Record<string, string>;
  maxRedirects?: number;
  defaultTimeoutMs?: number;
}

interface RequestLogEntry {
  request: HttpRequestOptions;
  response: HttpResponse;
  timestamp: number;
}

interface RateLimitState {
  maxPerSecond: number;
  /** Timestamps of recent requests within the sliding window */
  timestamps: number[];
}

interface BackoffState {
  retryCount: number;
  nextAllowedMs: number;
}

// ─── Cookie Jar ──────────────────────────────────────────────────────────────

class CookieJar {
  private cookies: Map<string, Cookie[]> = new Map();

  /** Parse a Set-Cookie header and store the cookie */
  parseAndStore(setCookieHeader: string, requestDomain: string): Cookie {
    const parts = setCookieHeader.split(';').map(p => p.trim());
    const [nameValue, ...attrs] = parts;
    const eqIdx = nameValue.indexOf('=');
    const name = eqIdx >= 0 ? nameValue.substring(0, eqIdx).trim() : nameValue.trim();
    const value = eqIdx >= 0 ? nameValue.substring(eqIdx + 1).trim() : '';

    const cookie: Cookie = {
      name,
      value,
      domain: requestDomain,
      path: '/',
      httpOnly: false,
      secure: false,
    };

    for (const attr of attrs) {
      const lower = attr.toLowerCase();
      if (lower === 'httponly') {
        cookie.httpOnly = true;
      } else if (lower === 'secure') {
        cookie.secure = true;
      } else if (lower.startsWith('domain=')) {
        let domain = attr.substring(7).trim();
        if (domain.startsWith('.')) domain = domain.substring(1);
        cookie.domain = domain;
      } else if (lower.startsWith('path=')) {
        cookie.path = attr.substring(5).trim();
      } else if (lower.startsWith('expires=')) {
        const dateStr = attr.substring(8).trim();
        const ms = Date.parse(dateStr);
        if (!isNaN(ms)) cookie.expires = ms;
      } else if (lower.startsWith('max-age=')) {
        const seconds = parseInt(attr.substring(8).trim(), 10);
        if (!isNaN(seconds)) cookie.expires = Date.now() + seconds * 1000;
      } else if (lower.startsWith('samesite=')) {
        const val = attr.substring(9).trim();
        if (val.toLowerCase() === 'strict') cookie.sameSite = 'Strict';
        else if (val.toLowerCase() === 'lax') cookie.sameSite = 'Lax';
        else if (val.toLowerCase() === 'none') cookie.sameSite = 'None';
      }
    }

    this.set(cookie);
    return cookie;
  }

  /** Store a cookie */
  set(cookie: Cookie): void {
    const domain = cookie.domain.toLowerCase();
    const existing = this.cookies.get(domain) ?? [];
    const idx = existing.findIndex(c => c.name === cookie.name && c.path === cookie.path);
    if (idx >= 0) {
      existing[idx] = cookie;
    } else {
      existing.push(cookie);
    }
    this.cookies.set(domain, existing);
  }

  /** Get cookies matching a domain */
  getForDomain(domain: string): Cookie[] {
    const now = Date.now();
    const result: Cookie[] = [];
    const lowerDomain = domain.toLowerCase();

    for (const [cookieDomain, cookies] of this.cookies.entries()) {
      if (lowerDomain === cookieDomain || lowerDomain.endsWith('.' + cookieDomain)) {
        for (const cookie of cookies) {
          if (cookie.expires && cookie.expires < now) continue;
          result.push(cookie);
        }
      }
    }

    return result;
  }

  /** Build Cookie header string for a domain */
  buildCookieHeader(domain: string): string | undefined {
    const cookies = this.getForDomain(domain);
    if (cookies.length === 0) return undefined;
    return cookies.map(c => `${c.name}=${c.value}`).join('; ');
  }

  /** Get all cookies for a domain (public API) */
  getCookies(domain: string): Cookie[] {
    return this.getForDomain(domain);
  }

  /** Clear all cookies */
  clear(): void {
    this.cookies.clear();
  }
}

// ─── Scope Validator ─────────────────────────────────────────────────────────

async function validateScope(url: string): Promise<boolean> {
  try {
    const parsed = new URL(url);
    const target = parsed.hostname;

    if (checkIsTauri()) {
      return await invoke<boolean>('validate_target', { target });
    }

    // In vitest/Node.js: allow localhost/127.0.0.1 for test servers
    if (isNode) {
      if (target === '127.0.0.1' || target === 'localhost') return true;
      // Log warning but don't blindly allow — scope validation is critical
      console.warn(`[SCOPE] Running outside Tauri — cannot validate scope for ${target}`);
      return false;
    }

    // Browser fallback: default-deny
    return false;
  } catch {
    return false;
  }
}

// ─── Kill Switch Check ──────────────────────────────────────────────────────

async function isKillSwitchActive(): Promise<boolean> {
  if (checkIsTauri()) {
    try {
      return await invoke<boolean>('is_kill_switch_active');
    } catch {
      return true; // Fail-safe: assume active if we can't check
    }
  }
  return false; // Non-Tauri (test/Node): always allow
}

// ─── HTTP Client ─────────────────────────────────────────────────────────────

export class HttpClient {
  private axiosInstance: AxiosInstance;
  private cookieJar: CookieJar;
  private requestLog: RequestLogEntry[] = [];
  private authHeaders: Record<string, string> = {};
  private rateLimits: Map<string, RateLimitState> = new Map();
  private backoffStates: Map<string, BackoffState> = new Map();
  private defaultTimeoutMs: number;
  private maxRedirects: number;

  /** Maximum response body size to store in the request log (100KB) */
  private static readonly LOG_BODY_MAX_BYTES = 100 * 1024;

  constructor(config?: HttpClientConfig) {
    this.defaultTimeoutMs = config?.defaultTimeoutMs ?? 30000;
    this.maxRedirects = config?.maxRedirects ?? 10;
    this.cookieJar = new CookieJar();

    // Build axios config — force Node.js http adapter when running in Node
    // (jsdom environment makes axios default to XHR which can't reach localhost)
    const axiosCreateConfig: AxiosRequestConfig = {
      timeout: this.defaultTimeoutMs,
      maxRedirects: 0, // We handle redirects manually to track the chain
      validateStatus: () => true, // Accept all status codes
      headers: config?.defaultHeaders ?? {},
      // Disable response transformation — we want raw text
      transformResponse: [(data: unknown) => data],
    };

    if (isNode) {
      // Force Node.js http adapter in test/Node environments
      axiosCreateConfig.adapter = 'http';
    }

    this.axiosInstance = axios.create(axiosCreateConfig);
  }

  /** Make an HTTP request with full scope/killswitch/ratelimit enforcement */
  async request(options: HttpRequestOptions): Promise<HttpResponse> {
    // ── Kill switch check ──
    if (await isKillSwitchActive()) {
      throw new Error('Kill switch is active — all operations halted');
    }

    // ── Scope validation ──
    if (!(await validateScope(options.url))) {
      const hostname = new URL(options.url).hostname;
      throw new Error(`Target ${hostname} is out of scope`);
    }

    // ── Rate limiting ──
    const domain = new URL(options.url).hostname;
    await this.enforceRateLimit(domain);

    // ── Check backoff ──
    await this.enforceBackoff(domain);

    const startTime = performance.now();

    // ── Route through Tauri backend to bypass CORS ──
    if (checkIsTauri()) {
      return this.requestViaTauri(options, domain, startTime);
    }

    // ── Fallback: axios for Node.js/test environments ──
    return this.requestViaAxios(options, domain, startTime);
  }

  /** Execute HTTP request via Tauri IPC (bypasses browser CORS) */
  private async requestViaTauri(
    options: HttpRequestOptions,
    domain: string,
    startTime: number,
  ): Promise<HttpResponse> {
    const headers: Record<string, string> = {
      ...this.authHeaders,
      ...options.headers,
    };

    // Apply cookies from jar
    const cookieHeader = this.cookieJar.buildCookieHeader(domain);
    if (cookieHeader && !headers['Cookie']) {
      headers['Cookie'] = cookieHeader;
    }

    if (options.contentType && !headers['Content-Type']) {
      headers['Content-Type'] = options.contentType;
    }

    const result = await invoke<{
      status: number;
      statusText: string;
      headers: Record<string, string>;
      body: string;
      size: number;
      totalMs: number;
    }>('proxy_http_request', {
      url: options.url,
      method: options.method,
      headers,
      body: options.body ?? null,
      timeoutMs: options.timeoutMs ?? this.defaultTimeoutMs,
      followRedirects: options.followRedirects !== false,
    });

    const totalMs = performance.now() - startTime;

    // Parse Set-Cookie headers from response
    const setCookie = result.headers['set-cookie'];
    if (setCookie) {
      for (const cookieStr of setCookie.split(/,(?=\s*\w+=)/)) {
        this.cookieJar.parseAndStore(cookieStr.trim(), domain);
      }
    }

    const responseCookies = this.cookieJar.getCookies(domain);

    const httpResponse: HttpResponse = {
      status: result.status,
      statusText: result.statusText,
      headers: result.headers,
      body: result.body,
      timing: {
        dnsMs: 0,
        connectMs: 0,
        ttfbMs: result.totalMs,
        totalMs: Math.round(totalMs),
      },
      redirectChain: [],
      cookies: responseCookies,
      size: result.size,
    };

    // ── Handle 429 backoff ──
    if (result.status === 429) {
      this.handleRateLimitResponse429(domain, result.headers);
    }

    // ── Record in request log ──
    this.recordRequest(options, httpResponse);

    // ── Track rate limit ──
    this.trackRequest(domain);

    return httpResponse;
  }

  /** Handle 429 from Tauri-proxied response */
  private handleRateLimitResponse429(domain: string, headers: Record<string, string>): void {
    const retryAfter = headers['retry-after'];
    let delayMs = 5000;
    if (retryAfter) {
      const seconds = parseInt(retryAfter, 10);
      if (!isNaN(seconds)) {
        delayMs = seconds * 1000;
      }
    }
    const current = this.backoffStates.get(domain);
    const retryCount = (current?.retryCount ?? 0) + 1;
    this.backoffStates.set(domain, {
      retryCount,
      nextAllowedMs: Date.now() + delayMs,
    });
  }

  /** Execute HTTP request via axios (for Node.js/test environments) */
  private async requestViaAxios(
    options: HttpRequestOptions,
    domain: string,
    startTime: number,
  ): Promise<HttpResponse> {
    const redirectChain: Array<{ url: string; status: number }> = [];

    const headers: Record<string, string> = {
      ...this.authHeaders,
      ...options.headers,
    };

    // Apply cookies from jar
    const cookieHeader = this.cookieJar.buildCookieHeader(domain);
    if (cookieHeader && !headers['Cookie']) {
      headers['Cookie'] = cookieHeader;
    }

    // Set content type
    if (options.contentType && !headers['Content-Type']) {
      headers['Content-Type'] = options.contentType;
    }

    // Build axios config
    const axiosConfig: AxiosRequestConfig = {
      url: options.url,
      method: options.method.toLowerCase(),
      headers,
      data: options.body,
      timeout: options.timeoutMs ?? this.defaultTimeoutMs,
      maxRedirects: 0,
      validateStatus: () => true,
      transformResponse: [(data: unknown) => data],
    };

    // Proxy support
    if (options.proxyUrl) {
      try {
        const proxyParsed = new URL(options.proxyUrl);
        axiosConfig.proxy = {
          host: proxyParsed.hostname,
          port: parseInt(proxyParsed.port, 10) || 80,
          protocol: proxyParsed.protocol.replace(':', ''),
        };
      } catch {
        throw new Error(`Invalid proxy URL: ${options.proxyUrl}`);
      }
    }

    // ── Execute request with redirect following ──
    let currentUrl = options.url;
    let response: AxiosResponse;
    let redirectCount = 0;
    const shouldFollowRedirects = options.followRedirects !== false;
    const maxRedirects = this.maxRedirects;
    let ttfbTime = 0;

    response = await this.axiosInstance.request({
      ...axiosConfig,
      url: currentUrl,
    });
    ttfbTime = performance.now() - startTime;

    // Process cookies from initial response
    this.processCookies(response, currentUrl);

    // Follow redirects manually
    while (
      shouldFollowRedirects &&
      redirectCount < maxRedirects &&
      response.status >= 300 &&
      response.status < 400 &&
      response.headers['location']
    ) {
      redirectChain.push({ url: currentUrl, status: response.status });

      const location = response.headers['location'];
      // Resolve relative URLs
      currentUrl = new URL(location, currentUrl).toString();

      // Validate redirect target is in scope
      if (!(await validateScope(currentUrl))) {
        break; // Stop following — out of scope
      }

      redirectCount++;
      response = await this.axiosInstance.request({
        ...axiosConfig,
        url: currentUrl,
        method: response.status === 303 ? 'get' : axiosConfig.method,
        data: response.status === 303 ? undefined : axiosConfig.data,
      });

      this.processCookies(response, currentUrl);
    }

    const totalMs = performance.now() - startTime;

    // ── Build response ──
    const responseBody = typeof response.data === 'string'
      ? response.data
      : response.data != null
        ? String(response.data)
        : '';

    const flatHeaders: Record<string, string> = {};
    for (const [key, val] of Object.entries(response.headers)) {
      if (val != null) {
        flatHeaders[key] = Array.isArray(val) ? val.join(', ') : String(val);
      }
    }

    const responseDomain = new URL(currentUrl).hostname;
    const responseCookies = this.cookieJar.getCookies(responseDomain);

    const httpResponse: HttpResponse = {
      status: response.status,
      statusText: response.statusText ?? '',
      headers: flatHeaders,
      body: responseBody,
      timing: {
        dnsMs: 0,
        connectMs: 0,
        ttfbMs: Math.round(ttfbTime),
        totalMs: Math.round(totalMs),
      },
      redirectChain,
      cookies: responseCookies,
      size: new TextEncoder().encode(responseBody).byteLength,
    };

    // ── Handle 429 backoff ──
    if (response.status === 429) {
      this.handleRateLimitResponse(domain, response);
    }

    // ── Record in request log ──
    this.recordRequest(options, httpResponse);

    // ── Track rate limit ──
    this.trackRequest(domain);

    return httpResponse;
  }

  // ─── Cookie Management ──────────────────────────────────────────────────────

  getCookies(domain: string): Cookie[] {
    return this.cookieJar.getCookies(domain);
  }

  setCookie(cookie: Cookie): void {
    this.cookieJar.set(cookie);
  }

  clearCookies(): void {
    this.cookieJar.clear();
  }

  // ─── Auth Management ────────────────────────────────────────────────────────

  setAuthHeader(header: string, value: string): void {
    this.authHeaders[header] = value;
  }

  clearAuth(): void {
    this.authHeaders = {};
  }

  // ─── Rate Limiting ──────────────────────────────────────────────────────────

  getRequestCount(domain: string): number {
    const state = this.rateLimits.get(domain);
    if (!state) return 0;
    const now = Date.now();
    return state.timestamps.filter(t => now - t < 1000).length;
  }

  setRateLimit(domain: string, maxPerSecond: number): void {
    const existing = this.rateLimits.get(domain);
    if (existing) {
      existing.maxPerSecond = maxPerSecond;
    } else {
      this.rateLimits.set(domain, { maxPerSecond, timestamps: [] });
    }
  }

  // ─── Request Log ───────────────────────────────────────────────────────────

  getRequestLog(): RequestLogEntry[] {
    return [...this.requestLog];
  }

  clearRequestLog(): void {
    this.requestLog = [];
  }

  // ─── Private Helpers ───────────────────────────────────────────────────────

  /** Process Set-Cookie headers from a response */
  private processCookies(response: AxiosResponse, requestUrl: string): void {
    const domain = new URL(requestUrl).hostname;
    const setCookieHeaders = response.headers['set-cookie'];
    if (!setCookieHeaders) return;

    const cookieStrings = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    for (const cookieStr of cookieStrings) {
      this.cookieJar.parseAndStore(cookieStr, domain);
    }
  }

  /** Enforce per-domain rate limit (sleep if needed) */
  private async enforceRateLimit(domain: string): Promise<void> {
    const state = this.rateLimits.get(domain);
    if (!state) {
      // Default: 10 req/s
      this.rateLimits.set(domain, { maxPerSecond: 10, timestamps: [] });
      return;
    }

    const now = Date.now();
    // Clean old timestamps (sliding window: 1 second)
    state.timestamps = state.timestamps.filter(t => now - t < 1000);

    if (state.timestamps.length >= state.maxPerSecond) {
      // Calculate how long to wait
      const oldestInWindow = state.timestamps[0];
      const waitMs = 1000 - (now - oldestInWindow) + 10; // +10ms buffer
      if (waitMs > 0) {
        await sleep(waitMs);
      }
    }
  }

  /** Track a request in the rate limit window */
  private trackRequest(domain: string): void {
    const state = this.rateLimits.get(domain);
    if (state) {
      state.timestamps.push(Date.now());
    }
  }

  /** Handle 429 response — set backoff state */
  private handleRateLimitResponse(domain: string, response: AxiosResponse): void {
    const existing = this.backoffStates.get(domain);
    const retryCount = existing ? existing.retryCount + 1 : 1;

    // Check Retry-After header
    const retryAfter = response.headers['retry-after'];
    let waitMs: number;

    if (retryAfter) {
      const seconds = parseInt(retryAfter, 10);
      if (!isNaN(seconds)) {
        waitMs = seconds * 1000;
      } else {
        // HTTP-date format
        const date = Date.parse(retryAfter);
        waitMs = isNaN(date) ? 1000 : Math.max(0, date - Date.now());
      }
    } else {
      // Exponential backoff: 1s, 2s, 4s, 8s, max 30s
      waitMs = Math.min(1000 * Math.pow(2, retryCount - 1), 30000);
    }

    this.backoffStates.set(domain, {
      retryCount,
      nextAllowedMs: Date.now() + waitMs,
    });
  }

  /** Wait if domain is in backoff state */
  private async enforceBackoff(domain: string): Promise<void> {
    const state = this.backoffStates.get(domain);
    if (!state) return;

    const now = Date.now();
    if (now < state.nextAllowedMs) {
      const waitMs = state.nextAllowedMs - now;
      await sleep(waitMs);
    }

    // Clear backoff after waiting
    this.backoffStates.delete(domain);
  }

  /** Record a request/response pair in the log */
  private recordRequest(request: HttpRequestOptions, response: HttpResponse): void {
    // Truncate large response bodies in the log
    const logResponse = { ...response };
    if (response.body.length > HttpClient.LOG_BODY_MAX_BYTES) {
      logResponse.body = response.body.substring(0, HttpClient.LOG_BODY_MAX_BYTES) +
        `\n\n[TRUNCATED — original size: ${response.size} bytes]`;
    }

    this.requestLog.push({
      request,
      response: logResponse,
      timestamp: Date.now(),
    });
  }
}

// ─── Utility ─────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export default HttpClient;

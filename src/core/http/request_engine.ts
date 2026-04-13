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
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import { invoke } from '@tauri-apps/api/core';
import { StealthModule } from '../evasion/stealth';
import type { StealthConfig } from '../evasion/stealth';
import { RateController } from './rate_controller';
import type { RateControllerConfig, DomainRateState } from './rate_controller';

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

/** WAF detection result attached to HTTP responses */
export interface WAFDetection {
  detected: boolean;
  provider: 'cloudflare' | 'akamai' | 'aws-waf' | 'generic' | 'none';
  signal: string;
}

/** Known WAF response signatures */
const WAF_SIGNATURES: Array<{ provider: WAFDetection['provider']; test: (status: number, headers: Record<string, string>, body: string) => string | null }> = [
  {
    provider: 'cloudflare',
    test: (_status, headers, body) => {
      if (headers['server']?.toLowerCase().includes('cloudflare')) return 'Server: cloudflare header';
      if (headers['cf-ray']) return 'CF-Ray header present';
      if (/cf-challenge|challenge-platform|turnstile/i.test(body)) return 'Cloudflare challenge page';
      return null;
    },
  },
  {
    provider: 'akamai',
    test: (_status, headers, body) => {
      if (headers['server']?.toLowerCase().includes('akamaighost')) return 'Server: AkamaiGHost header';
      if (/reference\s*#[\da-f.]+/i.test(body) && body.length < 2000) return 'Akamai reference block page';
      return null;
    },
  },
  {
    provider: 'aws-waf',
    test: (_status, headers) => {
      if (headers['x-amzn-waf-action']) return 'x-amzn-waf-action header';
      return null;
    },
  },
  {
    provider: 'generic',
    test: (status, headers, body) => {
      if (status === 429) return '429 Too Many Requests';
      if (status === 403 && body.length < 2000 && /blocked|denied|forbidden.*request/i.test(body)) return 'Generic 403 block page';
      const rateHeaders = ['x-ratelimit-remaining', 'x-rate-limit-remaining', 'ratelimit-remaining'];
      for (const h of rateHeaders) {
        const val = headers[h];
        if (val !== undefined && parseInt(val, 10) === 0) return `${h}: 0`;
      }
      return null;
    },
  },
];

/** Detect WAF presence from an HTTP response */
export function detectWAF(status: number, headers: Record<string, string>, body: string): WAFDetection {
  for (const sig of WAF_SIGNATURES) {
    const signal = sig.test(status, headers, body);
    if (signal) {
      return { detected: true, provider: sig.provider, signal };
    }
  }
  return { detected: false, provider: 'none', signal: '' };
}

export interface HttpClientConfig {
  defaultHeaders?: Record<string, string>;
  maxRedirects?: number;
  defaultTimeoutMs?: number;
  /** Stealth configuration. When provided, enables UA rotation, header normalization, and timing jitter. */
  stealth?: StealthConfig & { enabled?: boolean };
  /** Adaptive rate controller configuration. Replaces basic sliding-window rate limiting. */
  rateControl?: Partial<RateControllerConfig>;
  /** Whether to route requests through the Tauri proxy pool when in Tauri environment */
  proxyEnabled?: boolean;
  /** Callback invoked when WAF is detected on a response */
  onWAFDetected?: (domain: string, waf: WAFDetection) => void;
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

// ─── Cross-Origin Header Stripping (Q6 Gap 7) ───────────────────────────────

/**
 * Well-known sensitive headers that MUST be stripped on cross-origin redirect.
 * Matches reqwest's default policy (0.11.20+) plus browsers' fetch behavior.
 * @internal exported for tests
 */
export const WELL_KNOWN_AUTH_HEADERS: readonly string[] = [
  'authorization',
  'cookie',
  'www-authenticate',
  'proxy-authorization',
];

/**
 * Patterns identifying custom auth headers. Matched case-insensitively against
 * the header name. Covers the auth headers Huntress has observed in live hunts
 * (Telegram Wallet's `wallet-authorization`, Slack's `xoxp` tokens in custom
 * headers, API-gateway `x-api-key`, CSRF double-submit tokens).
 *
 * Pattern list is narrow on purpose — false positives here silently break
 * legitimate requests. Each pattern below was added from an observed real-world
 * auth header, not speculatively.
 * @internal exported for tests
 */
const CUSTOM_AUTH_HEADER_PATTERNS: readonly RegExp[] = [
  /-authorization$/i,           // wallet-authorization, x-wallet-authorization
  /^(?:x-)?api-key$/i,           // X-API-Key, api-key
  /^(?:x-)?(?:csrf|xsrf)-token$/i, // X-CSRF-Token, csrf-token, X-XSRF-Token
  /^(?:x-)?session-token$/i,     // X-Session-Token
  /^(?:x-)?access-token$/i,      // X-Access-Token
  /^(?:x-)?auth-token$/i,        // X-Auth-Token
  /wallet-device-serial/i,       // x-wallet-device-serial
  /^x-.*-token$/i,               // catch-all: X-Foo-Token
];

/**
 * Returns true when the header name is auth-sensitive and should be stripped
 * on cross-origin redirects. Case-insensitive.
 */
export function isSensitiveAuthHeaderName(name: string): boolean {
  const lower = name.toLowerCase();
  if (WELL_KNOWN_AUTH_HEADERS.includes(lower)) return true;
  return CUSTOM_AUTH_HEADER_PATTERNS.some(p => p.test(lower));
}

/**
 * Returns the origin (scheme://host[:port]) of a URL, or null on parse error.
 */
export function getOrigin(url: string): string | null {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

/**
 * Returns true when `toUrl` has a different origin than `fromUrl`. A null
 * origin (unparseable URL) is treated as cross-origin for safety.
 */
export function isCrossOrigin(fromUrl: string, toUrl: string): boolean {
  const a = getOrigin(fromUrl);
  const b = getOrigin(toUrl);
  if (!a || !b) return true;
  return a !== b;
}

/**
 * Strip auth-sensitive headers from `headers` when `toUrl` is cross-origin
 * from `fromUrl`. Returns a new object — never mutates the input. Stripped
 * headers are returned alongside for audit logging.
 *
 * This is the core Q6 Gap 7 fix: reqwest auto-strips Authorization/Cookie on
 * cross-origin but not custom headers like `wallet-authorization`. Running
 * this guard in the TS redirect loop protects both the axios path and any
 * Tauri path that loops through here.
 */
export function stripCrossOriginAuthHeaders(
  headers: Record<string, string>,
  fromUrl: string,
  toUrl: string,
): { headers: Record<string, string>; stripped: string[] } {
  if (!isCrossOrigin(fromUrl, toUrl)) {
    return { headers: { ...headers }, stripped: [] };
  }
  const next: Record<string, string> = {};
  const stripped: string[] = [];
  for (const [key, value] of Object.entries(headers)) {
    if (isSensitiveAuthHeaderName(key)) {
      stripped.push(key);
      continue;
    }
    next[key] = value;
  }
  return { headers: next, stripped };
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

  /** Stealth module for UA rotation, header normalization, and timing jitter */
  private stealthModule: StealthModule | null = null;
  private stealthEnabled: boolean;

  /** Adaptive rate controller (replaces basic sliding-window for external use) */
  private rateController: RateController;

  /** Whether to route requests through Tauri proxy pool */
  private proxyEnabled: boolean;

  /** Callback for WAF detection events */
  private onWAFDetected?: (domain: string, waf: WAFDetection) => void;

  /** Last WAF detection per domain */
  private wafStates: Map<string, WAFDetection> = new Map();

  /** Maximum response body size to store in the request log (100KB) */
  private static readonly LOG_BODY_MAX_BYTES = 100 * 1024;

  constructor(config?: HttpClientConfig) {
    this.defaultTimeoutMs = config?.defaultTimeoutMs ?? 30000;
    this.maxRedirects = config?.maxRedirects ?? 10;
    this.cookieJar = new CookieJar();

    // Initialize stealth module
    this.stealthEnabled = config?.stealth?.enabled ?? false;
    if (this.stealthEnabled) {
      this.stealthModule = new StealthModule(config?.stealth);
    }

    // Initialize adaptive rate controller
    this.rateController = new RateController(config?.rateControl);

    // Proxy configuration
    this.proxyEnabled = config?.proxyEnabled ?? false;

    // WAF detection callback
    this.onWAFDetected = config?.onWAFDetected;

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

  /** Make an HTTP request with full scope/killswitch/ratelimit/stealth enforcement */
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

    const domain = new URL(options.url).hostname;

    // ── Adaptive rate control (acquire permission to send) ──
    await this.rateController.acquire(domain);

    // ── Legacy rate limiting (kept for per-domain overrides set via setRateLimit) ──
    await this.enforceRateLimit(domain);

    // ── Check backoff ──
    await this.enforceBackoff(domain);

    // ── Stealth: apply UA rotation, header normalization, jitter delay ──
    let stealthOptions = options;
    if (this.stealthEnabled && this.stealthModule) {
      stealthOptions = this.stealthModule.applyToRequest(options);

      // Apply timing jitter (random delay to avoid fingerprinting)
      const jitterMs = this.stealthModule.getJitterDelay();
      if (jitterMs > 0) {
        await sleep(jitterMs);
      }
    }

    const startTime = performance.now();

    // ── Route through Tauri backend to bypass CORS ──
    let response: HttpResponse;
    if (checkIsTauri()) {
      response = await this.requestViaTauri(stealthOptions, domain, startTime);
    } else {
      // ── Fallback: axios for Node.js/test environments ──
      response = await this.requestViaAxios(stealthOptions, domain, startTime);
    }

    // ── Report response to adaptive rate controller ──
    this.rateController.reportResponse(domain, response.status, response.headers, response.body);

    // ── WAF detection ──
    const waf = detectWAF(response.status, response.headers, response.body);
    if (waf.detected) {
      this.wafStates.set(domain, waf);
      this.onWAFDetected?.(domain, waf);
    }

    return response;
  }

  /**
   * Execute HTTP request via Tauri IPC (bypasses browser CORS).
   *
   * The Rust `proxy_http_request` command is always called with
   * `followRedirects: false` — we handle redirects in this TS layer so that
   * (a) scope is validated on every hop, and (b) custom auth headers like
   * `wallet-authorization` are stripped on cross-origin hops (Q6 Gap 7).
   * reqwest's built-in policy only strips the well-known set
   * (Authorization/Cookie/WWW-Authenticate/Proxy-Authorization) — not enough
   * for Telegram-class targets.
   */
  private async requestViaTauri(
    options: HttpRequestOptions,
    domain: string,
    startTime: number,
  ): Promise<HttpResponse> {
    let currentUrl = options.url;
    let currentDomain = domain;
    let hopHeaders: Record<string, string> = {
      ...this.authHeaders,
      ...options.headers,
    };

    const cookieHeader = this.cookieJar.buildCookieHeader(domain);
    if (cookieHeader && !hopHeaders['Cookie']) {
      hopHeaders['Cookie'] = cookieHeader;
    }
    if (options.contentType && !hopHeaders['Content-Type']) {
      hopHeaders['Content-Type'] = options.contentType;
    }

    const redirectChain: Array<{ url: string; status: number }> = [];
    const shouldFollowRedirects = options.followRedirects !== false;
    const maxHops = this.maxRedirects;

    let currentMethod = options.method;
    let currentBody: string | null = options.body ?? null;

    type ProxyResult = {
      status: number;
      statusText: string;
      headers: Record<string, string>;
      body: string;
      size: number;
      totalMs: number;
    };

    let result: ProxyResult = await invoke<ProxyResult>('proxy_http_request', {
      url: currentUrl,
      method: currentMethod,
      headers: hopHeaders,
      body: currentBody,
      timeoutMs: options.timeoutMs ?? this.defaultTimeoutMs,
      followRedirects: false,
    });

    // Process cookies from the initial response
    this.ingestSetCookieFromHeaders(result.headers, currentDomain);

    let hopCount = 0;
    while (
      shouldFollowRedirects &&
      hopCount < maxHops &&
      result.status >= 300 &&
      result.status < 400 &&
      (result.headers['location'] ?? result.headers['Location'])
    ) {
      redirectChain.push({ url: currentUrl, status: result.status });

      const location = result.headers['location'] ?? result.headers['Location'];
      const nextUrl = new URL(location, currentUrl).toString();

      // Scope check per hop — an out-of-scope redirect stops the chain.
      if (!(await validateScope(nextUrl))) {
        break;
      }

      // Cross-origin header strip. Affects custom auth (wallet-authorization,
      // x-api-key) in addition to the well-known set.
      const strip = stripCrossOriginAuthHeaders(hopHeaders, currentUrl, nextUrl);
      hopHeaders = strip.headers;

      // Per RFC 7231, 303 forces the next hop to GET with no body.
      if (result.status === 303) {
        currentMethod = 'GET';
        currentBody = null;
      }

      currentUrl = nextUrl;
      currentDomain = new URL(currentUrl).hostname;
      hopCount++;

      // Refresh jar cookies for the new domain. If Cookie was stripped above
      // on cross-origin, let jar-resident cookies for the new domain take over.
      if (!hopHeaders['Cookie'] && !hopHeaders['cookie']) {
        const nextCookieHeader = this.cookieJar.buildCookieHeader(currentDomain);
        if (nextCookieHeader) hopHeaders['Cookie'] = nextCookieHeader;
      }

      result = await invoke<ProxyResult>('proxy_http_request', {
        url: currentUrl,
        method: currentMethod,
        headers: hopHeaders,
        body: currentBody,
        timeoutMs: options.timeoutMs ?? this.defaultTimeoutMs,
        followRedirects: false,
      });
      this.ingestSetCookieFromHeaders(result.headers, currentDomain);
    }

    const totalMs = performance.now() - startTime;
    const responseCookies = this.cookieJar.getCookies(currentDomain);

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
      redirectChain,
      cookies: responseCookies,
      size: result.size,
    };

    // ── Handle 429 backoff ──
    if (result.status === 429) {
      this.handleRateLimitResponse429(currentDomain, result.headers);
    }

    // ── Record in request log ──
    this.recordRequest(options, httpResponse);

    // ── Track rate limit ──
    this.trackRequest(currentDomain);

    return httpResponse;
  }

  /** Parse one or more Set-Cookie headers from a Tauri-proxied response. */
  private ingestSetCookieFromHeaders(
    headers: Record<string, string>,
    domain: string,
  ): void {
    const setCookie = headers['set-cookie'] ?? headers['Set-Cookie'];
    if (!setCookie) return;
    for (const cookieStr of setCookie.split(/,(?=\s*\w+=)/)) {
      this.cookieJar.parseAndStore(cookieStr.trim(), domain);
    }
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

    // Follow redirects manually — TS-layer loop enforces scope and strips
    // auth headers on cross-origin hops (Q6 Gap 7). The axios instance is
    // configured with maxRedirects: 0 so it never follows on its own.
    //
    // hopHeaders tracks the headers we intend to send on the NEXT request.
    // It starts as the caller's headers and gets pruned on cross-origin.
    let hopHeaders: Record<string, string> = { ...headers };
    let hopFromUrl = currentUrl;

    while (
      shouldFollowRedirects &&
      redirectCount < maxRedirects &&
      response.status >= 300 &&
      response.status < 400 &&
      response.headers['location']
    ) {
      redirectChain.push({ url: currentUrl, status: response.status });

      const location = response.headers['location'];
      // Resolve relative URLs against the current hop's URL
      const nextUrl = new URL(location, currentUrl).toString();

      // Validate redirect target is in scope BEFORE following. An out-of-scope
      // redirect stops the chain — the 3xx response is returned as-is so the
      // caller can inspect the Location header without the request ever
      // touching the out-of-scope host.
      if (!(await validateScope(nextUrl))) {
        break;
      }

      // Strip auth-sensitive headers on cross-origin hops (Q6 Gap 7).
      // reqwest auto-strips Authorization/Cookie but not custom auth headers
      // like `wallet-authorization` — so we do it here, for every hop, to
      // cover both the axios path and any future Tauri-proxied hops.
      const strip = stripCrossOriginAuthHeaders(hopHeaders, hopFromUrl, nextUrl);
      hopHeaders = strip.headers;

      currentUrl = nextUrl;
      hopFromUrl = nextUrl;
      redirectCount++;

      // Also re-compute cookie jar contribution for the new domain —
      // the prior Cookie header (if any) was stripped above on cross-origin,
      // but jar-resident cookies for the new domain should still be attached.
      const nextDomain = new URL(currentUrl).hostname;
      const nextCookieHeader = this.cookieJar.buildCookieHeader(nextDomain);
      if (nextCookieHeader && !hopHeaders['Cookie'] && !hopHeaders['cookie']) {
        hopHeaders['Cookie'] = nextCookieHeader;
      }

      response = await this.axiosInstance.request({
        ...axiosConfig,
        url: currentUrl,
        headers: hopHeaders,
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

  // ─── Stealth Control ──────────────────────────────────────────────────────

  /** Enable or disable stealth mode at runtime */
  setStealthEnabled(enabled: boolean): void {
    this.stealthEnabled = enabled;
    if (enabled && !this.stealthModule) {
      this.stealthModule = new StealthModule();
    }
  }

  /** Check if stealth mode is currently enabled */
  isStealthEnabled(): boolean {
    return this.stealthEnabled;
  }

  // ─── Proxy Control ────────────────────────────────────────────────────────

  /** Enable or disable proxy routing at runtime */
  setProxyEnabled(enabled: boolean): void {
    this.proxyEnabled = enabled;
  }

  /** Check if proxy routing is currently enabled */
  isProxyEnabled(): boolean {
    return this.proxyEnabled;
  }

  // ─── WAF Detection ────────────────────────────────────────────────────────

  /** Get the last WAF detection result for a domain */
  getWAFState(domain: string): WAFDetection | undefined {
    return this.wafStates.get(domain);
  }

  /** Get all domains with detected WAFs */
  getAllWAFStates(): Map<string, WAFDetection> {
    return new Map(this.wafStates);
  }

  // ─── Adaptive Rate Controller ─────────────────────────────────────────────

  /** Get the underlying rate controller for direct access */
  getRateController(): RateController {
    return this.rateController;
  }

  /** Check if a domain is currently banned/cooling down */
  isDomainBanned(domain: string): boolean {
    return this.rateController.isBanned(domain);
  }

  /** Get rate state for a domain */
  getDomainRateState(domain: string): DomainRateState {
    return this.rateController.getState(domain);
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

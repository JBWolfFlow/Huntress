/**
 * Stealth Module (Phase 20J)
 *
 * Applies stealth transformations to HTTP requests to avoid bot detection
 * and reduce fingerprinting. Rotates User-Agent strings, adds timing jitter,
 * and normalizes header ordering to mimic real browser behavior.
 */

import type { HttpRequestOptions } from '../http/request_engine';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface StealthConfig {
  /** Enable User-Agent rotation */
  rotateUserAgent?: boolean;
  /** Enable request timing jitter */
  addJitter?: boolean;
  /** Jitter range in ms (adds random delay between 0 and this value) */
  jitterMaxMs?: number;
  /** Enable header ordering normalization */
  normalizeHeaders?: boolean;
}

// ─── User-Agent Pool ─────────────────────────────────────────────────────────

const USER_AGENTS: string[] = [
  // Chrome on Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  // Chrome on macOS
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
  // Chrome on Linux
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  // Firefox on Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
  // Firefox on macOS
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
  // Firefox on Linux
  'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
  // Safari on macOS
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
  // Edge on Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
  // Chrome on Android
  'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36',
  // Safari on iOS
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
  // Chrome on ChromeOS
  'Mozilla/5.0 (X11; CrOS x86_64 15236.80.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  // Opera on Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0',
];

/** Standard browser header ordering — WAFs can fingerprint on header order */
const STANDARD_HEADER_ORDER = [
  'host',
  'connection',
  'cache-control',
  'upgrade-insecure-requests',
  'user-agent',
  'accept',
  'accept-encoding',
  'accept-language',
  'cookie',
  'referer',
  'origin',
  'content-type',
  'content-length',
  'authorization',
];

// ─── Default Config ──────────────────────────────────────────────────────────

const DEFAULT_STEALTH_CONFIG: Required<StealthConfig> = {
  rotateUserAgent: true,
  addJitter: true,
  jitterMaxMs: 2000,
  normalizeHeaders: true,
};

// ─── Stealth Module ──────────────────────────────────────────────────────────

export class StealthModule {
  private config: Required<StealthConfig>;
  private uaIndex = 0;

  constructor(config?: Partial<StealthConfig>) {
    this.config = { ...DEFAULT_STEALTH_CONFIG, ...config };

    // Start at a random UA to avoid all sessions starting with the same one
    this.uaIndex = Math.floor(Math.random() * USER_AGENTS.length);
  }

  /** Get a realistic browser User-Agent string (rotates through a pool) */
  getUserAgent(): string {
    const ua = USER_AGENTS[this.uaIndex % USER_AGENTS.length];
    this.uaIndex++;
    return ua;
  }

  /** Apply stealth transformations to request options */
  applyToRequest(options: HttpRequestOptions): HttpRequestOptions {
    const headers = { ...options.headers };

    // Rotate User-Agent
    if (this.config.rotateUserAgent && !headers['User-Agent'] && !headers['user-agent']) {
      headers['User-Agent'] = this.getUserAgent();
    }

    // Add standard browser headers if not present
    if (!headers['Accept'] && !headers['accept']) {
      headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8';
    }
    if (!headers['Accept-Language'] && !headers['accept-language']) {
      headers['Accept-Language'] = 'en-US,en;q=0.9';
    }
    if (!headers['Accept-Encoding'] && !headers['accept-encoding']) {
      headers['Accept-Encoding'] = 'gzip, deflate, br';
    }

    // Normalize header ordering
    if (this.config.normalizeHeaders) {
      const ordered = this.normalizeHeaderOrder(headers);
      return { ...options, headers: ordered };
    }

    return { ...options, headers };
  }

  /** Get a random delay for request timing jitter */
  getJitterDelay(): number {
    if (!this.config.addJitter || this.config.jitterMaxMs <= 0) {
      return 0;
    }
    return Math.floor(Math.random() * this.config.jitterMaxMs);
  }

  /** Get the number of available User-Agents */
  getUserAgentCount(): number {
    return USER_AGENTS.length;
  }

  // ─── Private Helpers ─────────────────────────────────────────────────────────

  private normalizeHeaderOrder(headers: Record<string, string>): Record<string, string> {
    const ordered: Record<string, string> = {};
    const lowerMap = new Map<string, string>();

    // Build a lowercase → original key map
    for (const key of Object.keys(headers)) {
      lowerMap.set(key.toLowerCase(), key);
    }

    // Add headers in standard order first
    for (const standardKey of STANDARD_HEADER_ORDER) {
      const originalKey = lowerMap.get(standardKey);
      if (originalKey) {
        ordered[originalKey] = headers[originalKey];
        lowerMap.delete(standardKey);
      }
    }

    // Add remaining headers in original order
    for (const [, originalKey] of lowerMap) {
      ordered[originalKey] = headers[originalKey];
    }

    return ordered;
  }
}

export { USER_AGENTS };

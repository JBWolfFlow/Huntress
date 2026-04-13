/**
 * Phase 2 Tests — Rate Limiting, Stealth, WAF Detection, Proxy Routing
 *
 * Tests for:
 * - Stealth module wiring into HttpClient (UA rotation, header normalization, jitter)
 * - Adaptive rate controller integration (acquire/reportResponse feedback loop)
 * - WAF detection on HTTP responses (Cloudflare, Akamai, AWS WAF, generic)
 * - WAF detection triggering automatic backoff via rate controller
 * - Proxy routing toggle
 * - Stealth enable/disable at runtime
 * - Recon keyword lock (locked agents never upgrade complexity)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { StealthModule, USER_AGENTS } from '../core/evasion/stealth';
import { RateController } from '../core/http/rate_controller';
import { detectWAF } from '../core/http/request_engine';
import { classifyTaskComplexity } from '../core/orchestrator/cost_router';

// ─── WAF Detection (inline detectWAF function) ─────────────────────────────

describe('detectWAF', () => {
  it('detects Cloudflare via Server header', () => {
    const result = detectWAF(403, { server: 'cloudflare' }, '<html>Forbidden</html>');
    expect(result.detected).toBe(true);
    expect(result.provider).toBe('cloudflare');
    expect(result.signal).toContain('cloudflare');
  });

  it('detects Cloudflare via CF-Ray header', () => {
    const result = detectWAF(200, { 'cf-ray': '7abc123def-LAX' }, '<html>OK</html>');
    expect(result.detected).toBe(true);
    expect(result.provider).toBe('cloudflare');
    expect(result.signal).toContain('CF-Ray');
  });

  it('detects Cloudflare challenge page in body', () => {
    const body = '<html><title>Attention Required!</title><div id="cf-challenge-running">Challenge...</div></html>';
    const result = detectWAF(403, {}, body);
    expect(result.detected).toBe(true);
    expect(result.provider).toBe('cloudflare');
    expect(result.signal).toContain('challenge');
  });

  it('detects Cloudflare Turnstile in body', () => {
    const body = '<html><div class="cf-turnstile" data-sitekey="abc"></div></html>';
    const result = detectWAF(403, {}, body);
    expect(result.detected).toBe(true);
    expect(result.provider).toBe('cloudflare');
  });

  it('detects Akamai via server header', () => {
    const result = detectWAF(403, { server: 'AkamaiGHost' }, '');
    expect(result.detected).toBe(true);
    expect(result.provider).toBe('akamai');
  });

  it('detects Akamai via reference block page', () => {
    const body = 'Access Denied. Reference #18.abc123.1234567890.def456';
    const result = detectWAF(403, {}, body);
    expect(result.detected).toBe(true);
    expect(result.provider).toBe('akamai');
  });

  it('detects AWS WAF via x-amzn-waf-action header', () => {
    const result = detectWAF(403, { 'x-amzn-waf-action': 'block' }, '');
    expect(result.detected).toBe(true);
    expect(result.provider).toBe('aws-waf');
  });

  it('detects generic 429 Too Many Requests', () => {
    const result = detectWAF(429, {}, '');
    expect(result.detected).toBe(true);
    expect(result.provider).toBe('generic');
    expect(result.signal).toContain('429');
  });

  it('detects generic 403 block page', () => {
    const body = '<html>Your request has been blocked</html>';
    const result = detectWAF(403, {}, body);
    expect(result.detected).toBe(true);
    expect(result.provider).toBe('generic');
  });

  it('detects rate limit headers showing zero remaining', () => {
    const result = detectWAF(200, { 'x-ratelimit-remaining': '0' }, '<html>OK</html>');
    expect(result.detected).toBe(true);
    expect(result.provider).toBe('generic');
    expect(result.signal).toContain('ratelimit');
  });

  it('detects x-rate-limit-remaining header at zero', () => {
    const result = detectWAF(200, { 'x-rate-limit-remaining': '0' }, '');
    expect(result.detected).toBe(true);
    expect(result.provider).toBe('generic');
  });

  it('does NOT trigger on normal 200 response', () => {
    const result = detectWAF(200, { server: 'nginx/1.24', 'content-type': 'text/html' }, '<html>Hello</html>');
    expect(result.detected).toBe(false);
    expect(result.provider).toBe('none');
  });

  it('does NOT trigger on 404 Not Found', () => {
    const result = detectWAF(404, {}, '<html>Not Found</html>');
    expect(result.detected).toBe(false);
    expect(result.provider).toBe('none');
  });

  it('does NOT trigger on 403 with large body (not a block page)', () => {
    const largeBody = 'x'.repeat(5000); // Real 403 page, not a short WAF block
    const result = detectWAF(403, {}, largeBody);
    expect(result.detected).toBe(false);
  });

  it('does NOT trigger on rate limit headers with remaining > 0', () => {
    const result = detectWAF(200, { 'x-ratelimit-remaining': '50' }, '');
    expect(result.detected).toBe(false);
  });
});

// ─── WAF + Rate Controller Integration ──────────────────────────────────────

describe('WAF Detection → Rate Controller Backoff', () => {
  let controller: RateController;

  beforeEach(() => {
    controller = new RateController({
      initialRate: 5,
      maxRate: 20,
      minRate: 0.5,
      backoffFactor: 0.5,
      banCooldownMs: 100,
      consecutiveBlockThreshold: 3,
    });
  });

  it('429 WAF detection causes rate backoff via reportResponse', () => {
    const domain = 'waf-test.com';
    const waf = detectWAF(429, {}, '');
    expect(waf.detected).toBe(true);

    // Feed the WAF response into the rate controller
    controller.reportResponse(domain, 429, {});

    const state = controller.getState(domain);
    expect(state.currentRate).toBe(2.5); // 5 * 0.5 backoff
    expect(state.throttleCount).toBe(1);
  });

  it('consecutive Cloudflare 403s trigger ban via reportResponse', () => {
    const domain = 'cf-banned.com';

    // Simulate 3 consecutive 403s from Cloudflare
    for (let i = 0; i < 3; i++) {
      const waf = detectWAF(403, { server: 'cloudflare' }, '<html>Blocked</html>');
      expect(waf.detected).toBe(true);
      controller.reportResponse(domain, 403, { server: 'cloudflare' });
    }

    expect(controller.isBanned(domain)).toBe(true);
  });

  it('CAPTCHA in 403 body triggers immediate ban via RateController', () => {
    const domain = 'captcha-ban.com';
    const body = '<html>Please complete the CAPTCHA verification</html>';

    // RateController has its own CAPTCHA detection — feed it directly
    controller.reportResponse(domain, 403, {}, body);
    expect(controller.isBanned(domain)).toBe(true);
  });

  it('rate controller independent per domain', () => {
    controller.reportResponse('a.com', 429, {});
    controller.reportResponse('a.com', 429, {});

    expect(controller.getState('a.com').throttleCount).toBe(2);
    expect(controller.getState('b.com').throttleCount).toBe(0);
  });
});

// ─── Stealth + HttpClient Integration ───────────────────────────────────────

describe('Stealth Module Integration', () => {
  it('UA rotation produces diverse headers across requests', () => {
    const stealth = new StealthModule();
    const agents = new Set<string>();

    for (let i = 0; i < USER_AGENTS.length; i++) {
      const options = stealth.applyToRequest({ url: 'https://example.com', method: 'GET' });
      agents.add(options.headers?.['User-Agent'] ?? '');
    }

    // Should have rotated through most of the pool
    expect(agents.size).toBe(USER_AGENTS.length);
  });

  it('stealth can be disabled — no UA injection', () => {
    const stealth = new StealthModule({ rotateUserAgent: false, addJitter: false, normalizeHeaders: false });
    const options = stealth.applyToRequest({
      url: 'https://example.com',
      method: 'GET',
    });

    // No User-Agent should be added when rotation is disabled
    expect(options.headers?.['User-Agent']).toBeUndefined();
  });

  it('timing jitter is within configured range', () => {
    const stealth = new StealthModule({ jitterMaxMs: 500 });

    for (let i = 0; i < 50; i++) {
      const delay = stealth.getJitterDelay();
      expect(delay).toBeGreaterThanOrEqual(0);
      expect(delay).toBeLessThan(500);
    }
  });

  it('stealth disabled produces zero jitter', () => {
    const stealth = new StealthModule({ addJitter: false });
    expect(stealth.getJitterDelay()).toBe(0);
  });
});

// ─── Recon Keyword Lock ─────────────────────────────────────────────────────

describe('Recon Keyword Lock (Phase 2.5)', () => {
  it('recon stays simple regardless of security keywords in description', () => {
    const securityDescriptions = [
      'Reconnaissance on target with authentication endpoints',
      'Enumerate endpoints related to authorization bypass',
      'Scan application for multi-step authentication flows',
      'Discover API endpoints for business logic testing',
      'Fingerprint target with chain detection capabilities',
      'List all endpoints that handle report generation',
      'Check DNS for authorization-related subdomains',
    ];

    for (const desc of securityDescriptions) {
      expect(classifyTaskComplexity('recon', desc)).toBe('simple');
    }
  });

  it('all locked agents stay simple with complex keywords', () => {
    const lockedAgents = [
      'recon', 'subdomain-takeover-hunter', 'cors-hunter',
      'host-header-hunter', 'crlf-hunter', 'cache-hunter', 'open-redirect-hunter',
    ];

    for (const agent of lockedAgents) {
      expect(classifyTaskComplexity(agent, 'authentication bypass chain analyze')).toBe('simple');
    }
  });

  it('non-locked moderate agents CAN still be upgraded', () => {
    // xss-hunter is moderate and NOT locked — complex keywords should upgrade it
    expect(classifyTaskComplexity('xss-hunter', 'Multi-step chain attack')).toBe('complex');
  });

  it('non-locked moderate agents stay moderate without complex keywords', () => {
    expect(classifyTaskComplexity('xss-hunter', 'Test reflected XSS on login form')).toBe('moderate');
  });

  it('unknown agents still classify by keywords', () => {
    expect(classifyTaskComplexity('unknown-agent', 'enumerate endpoints')).toBe('simple');
    expect(classifyTaskComplexity('unknown-agent', 'authentication bypass')).toBe('complex');
    expect(classifyTaskComplexity('unknown-agent', 'some random task')).toBe('moderate');
  });
});

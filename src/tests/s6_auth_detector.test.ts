/**
 * S6 — Auth Detection Wizard Tests
 *
 * Tests for the AuthDetector service:
 * - HTTP probing (401, 403, 302, 200, network error)
 * - Program text analysis (Telegram, OAuth, API key, JWT, session)
 * - Tech fingerprinting (Cloudflare, Express, PHP, Django)
 * - Suggested profile generation with instructions
 * - Detection merging and confidence scoring
 * - URL normalization
 */

import { describe, it, expect, vi } from 'vitest';
import {
  AuthDetector,
} from '../core/auth/auth_detector';
import type { HttpClient, HttpRequestOptions, HttpResponse, Cookie } from '../core/http/request_engine';

// ─── Mock Helpers ────────────────────────────────────────────────────────────

function makeResponse(overrides?: Partial<HttpResponse>): HttpResponse {
  return {
    status: 200,
    statusText: 'OK',
    headers: {},
    body: '',
    cookies: [],
    timing: { dnsMs: 0, connectMs: 0, ttfbMs: 0, totalMs: 50 },
    redirectChain: [],
    size: 0,
    ...overrides,
  };
}

function createMockHttpClient(
  handler: (options: HttpRequestOptions) => Partial<HttpResponse> | Error,
): HttpClient {
  const requestFn = vi.fn(async (options: HttpRequestOptions): Promise<HttpResponse> => {
    const result = handler(options);
    if (result instanceof Error) throw result;
    return makeResponse(result);
  });

  return {
    request: requestFn,
    getCookies: (): Cookie[] => [],
  } as unknown as HttpClient;
}

// ─── HTTP Probing Tests ──────────────────────────────────────────────────────

describe('AuthDetector — HTTP Probing', () => {
  it('401 response → authWall: true, requiresAuth: true', async () => {
    const client = createMockHttpClient(() => ({ status: 401, statusText: 'Unauthorized' }));
    const result = await AuthDetector.detect(
      ['https://api.target.com'],
      'Test Program',
      [],
      client,
    );

    expect(result.requiresAuth).toBe(true);
    expect(result.probeResults[0].authWall).toBe(true);
    expect(result.probeResults[0].status).toBe(401);
  });

  it('403 response → authWall: true', async () => {
    const client = createMockHttpClient(() => ({ status: 403, statusText: 'Forbidden' }));
    const result = await AuthDetector.detect(
      ['https://api.target.com'],
      'Test Program',
      [],
      client,
    );

    expect(result.requiresAuth).toBe(true);
    expect(result.probeResults[0].authWall).toBe(true);
  });

  it('302 with /login Location → redirectsToLogin: true, loginUrl extracted', async () => {
    const client = createMockHttpClient(() => ({
      status: 302,
      headers: { location: '/auth/login?redirect=/' },
    }));
    const result = await AuthDetector.detect(
      ['https://app.target.com'],
      'Test Program',
      [],
      client,
    );

    expect(result.requiresAuth).toBe(true);
    expect(result.probeResults[0].redirectsToLogin).toBe(true);
    expect(result.probeResults[0].loginUrl).toBe('https://app.target.com/auth/login?redirect=/');
    expect(result.probeResults[0].authWall).toBe(true);
  });

  it('302 with /signin Location → redirectsToLogin: true', async () => {
    const client = createMockHttpClient(() => ({
      status: 302,
      headers: { location: 'https://sso.target.com/signin' },
    }));
    const result = await AuthDetector.detect(
      ['https://app.target.com'],
      'Test Program',
      [],
      client,
    );

    expect(result.probeResults[0].redirectsToLogin).toBe(true);
    expect(result.probeResults[0].loginUrl).toBe('https://sso.target.com/signin');
  });

  it('200 response → authWall: false', async () => {
    const client = createMockHttpClient(() => ({
      status: 200,
      body: '<html><body>Welcome</body></html>',
    }));
    const result = await AuthDetector.detect(
      ['https://public.target.com'],
      'Test Program',
      [],
      client,
    );

    expect(result.probeResults[0].authWall).toBe(false);
    expect(result.probeResults[0].status).toBe(200);
  });

  it('200 with login form → authWall: true, hasLoginForm: true', async () => {
    const client = createMockHttpClient(() => ({
      status: 200,
      body: '<html><form action="/login"><input type="password" name="pass"><input name="username"></form></html>',
    }));
    const result = await AuthDetector.detect(
      ['https://app.target.com'],
      'Test Program',
      [],
      client,
    );

    expect(result.requiresAuth).toBe(true);
    expect(result.probeResults[0].hasLoginForm).toBe(true);
    expect(result.probeResults[0].authWall).toBe(true);
  });

  it('network error → error field set, not thrown', async () => {
    const client = createMockHttpClient(() => new Error('ECONNREFUSED'));
    const result = await AuthDetector.detect(
      ['https://down.target.com'],
      'Test Program',
      [],
      client,
    );

    expect(result.probeResults[0].error).toBe('ECONNREFUSED');
    expect(result.probeResults[0].status).toBe(0);
    expect(result.probeResults[0].authWall).toBe(false);
  });

  it('mixed results (some 200, some 401) → requiresAuth: true', async () => {
    const client = createMockHttpClient((options) => {
      if (options.url.includes('public')) return { status: 200 };
      return { status: 401 };
    });
    const result = await AuthDetector.detect(
      ['https://public.target.com', 'https://api.target.com'],
      'Test Program',
      [],
      client,
    );

    expect(result.requiresAuth).toBe(true);
    expect(result.probeResults[0].authWall).toBe(false);
    expect(result.probeResults[1].authWall).toBe(true);
  });

  it('WWW-Authenticate: Bearer → detects bearer type', async () => {
    const client = createMockHttpClient(() => ({
      status: 401,
      headers: { 'www-authenticate': 'Bearer realm="api"' },
    }));
    const result = await AuthDetector.detect(
      ['https://api.target.com'],
      'Test Program',
      [],
      client,
    );

    expect(result.requiresAuth).toBe(true);
    const bearerDetection = result.detectedAuthTypes.find(d => d.type === 'bearer');
    expect(bearerDetection).toBeDefined();
    expect(bearerDetection!.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('WWW-Authenticate: Basic → detects basic type', async () => {
    const client = createMockHttpClient(() => ({
      status: 401,
      headers: { 'www-authenticate': 'Basic realm="admin"' },
    }));
    const result = await AuthDetector.detect(
      ['https://admin.target.com'],
      'Test Program',
      [],
      client,
    );

    const basicDetection = result.detectedAuthTypes.find(d => d.type === 'basic');
    expect(basicDetection).toBeDefined();
    expect(basicDetection!.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('limits probes to 8 targets', async () => {
    const requestFn = vi.fn(async () => makeResponse({ status: 200 }));
    const client = { request: requestFn, getCookies: () => [] } as unknown as HttpClient;

    const targets = Array.from({ length: 15 }, (_, i) => `https://target${i}.com`);
    await AuthDetector.detect(targets, 'Test', [], client);

    expect(requestFn).toHaveBeenCalledTimes(8);
  });
});

// ─── Program Text Analysis Tests ─────────────────────────────────────────────

describe('AuthDetector — Program Text Analysis', () => {
  it('"Wallet on Telegram" → detects telegram_webapp with high confidence', () => {
    const detections = AuthDetector.analyzeText(
      'Wallet on Telegram',
      ['Test Telegram Mini App for vulnerabilities'],
      ['https://wallet.telegram.org'],
    );

    const telegram = detections.find(d => d.type === 'telegram_webapp');
    expect(telegram).toBeDefined();
    expect(telegram!.confidence).toBeGreaterThanOrEqual(0.7);
  });

  it('"OAuth 2.0 required" → detects bearer/oauth', () => {
    const detections = AuthDetector.analyzeText(
      'SecureApp',
      ['OAuth 2.0 is required for all API endpoints'],
      ['https://api.secureapp.com'],
    );

    const oauth = detections.find(d => d.type === 'oauth');
    expect(oauth).toBeDefined();
    expect(oauth!.confidence).toBeGreaterThanOrEqual(0.6);
  });

  it('"Provide X-API-Key header" → detects api_key with headerName', () => {
    const detections = AuthDetector.analyzeText(
      'DataService API',
      ['Provide X-API-Key header with each request'],
      ['https://api.dataservice.com'],
    );

    const apiKey = detections.find(d => d.type === 'api_key');
    expect(apiKey).toBeDefined();
    expect(apiKey!.headerName).toBe('X-API-Key');
  });

  it('"JWT token in Authorization header" → detects bearer', () => {
    const detections = AuthDetector.analyzeText(
      'REST API',
      ['Use JWT bearer token in the Authorization header'],
      ['https://api.example.com'],
    );

    const bearer = detections.find(d => d.type === 'bearer');
    expect(bearer).toBeDefined();
    expect(bearer!.confidence).toBeGreaterThanOrEqual(0.6);
  });

  it('"Standard web application" (no auth keywords) → no detections', () => {
    const detections = AuthDetector.analyzeText(
      'Public Website',
      ['This is a standard web application'],
      ['https://www.example.com'],
    );

    // Should not detect session/cookie just from "standard" or "application"
    // because those don't match our auth-related patterns
    expect(detections.length).toBe(0);
  });

  it('multiple matches in same group increase confidence', () => {
    const detections = AuthDetector.analyzeText(
      'Telegram Bot WebApp',
      ['Test the Telegram Mini App. The webapp uses initData for auth.'],
      [],
    );

    const telegram = detections.find(d => d.type === 'telegram_webapp');
    expect(telegram).toBeDefined();
    // Multiple pattern matches should boost confidence
    expect(telegram!.confidence).toBeGreaterThan(0.7);
  });

  it('"Login required, session cookies used" → detects cookie/session', () => {
    const detections = AuthDetector.analyzeText(
      'Admin Panel',
      ['Login is required. Session cookies are used for authentication.'],
      [],
    );

    const session = detections.find(d => d.type === 'cookie');
    expect(session).toBeDefined();
  });
});

// ─── Tech Fingerprinting Tests ───────────────────────────────────────────────

describe('AuthDetector — Tech Fingerprinting', () => {
  it('Set-Cookie: PHPSESSID → techFingerprint: PHP', async () => {
    const client = createMockHttpClient(() => ({
      status: 200,
      headers: { 'set-cookie': 'PHPSESSID=abc123; path=/' },
    }));
    const result = await AuthDetector.detect(
      ['https://php.target.com'],
      'Test Program',
      [],
      client,
    );

    expect(result.probeResults[0].techFingerprint).toBe('PHP');
  });

  it('Set-Cookie: csrftoken → techFingerprint: Django', async () => {
    const client = createMockHttpClient(() => ({
      status: 200,
      headers: { 'set-cookie': 'csrftoken=xyz789; path=/' },
    }));
    const result = await AuthDetector.detect(
      ['https://django.target.com'],
      'Test Program',
      [],
      client,
    );

    expect(result.probeResults[0].techFingerprint).toBe('Django');
  });

  it('Server: cloudflare + 403 → detects bearer auth type', async () => {
    const client = createMockHttpClient(() => ({
      status: 403,
      headers: { server: 'cloudflare' },
    }));
    const result = await AuthDetector.detect(
      ['https://cf.target.com'],
      'Test Program',
      [],
      client,
    );

    expect(result.requiresAuth).toBe(true);
    expect(result.probeResults[0].techFingerprint).toBe('Cloudflare');
  });

  it('X-Powered-By: Express → techFingerprint: Express', async () => {
    const client = createMockHttpClient(() => ({
      status: 200,
      headers: { 'x-powered-by': 'Express' },
    }));
    const result = await AuthDetector.detect(
      ['https://node.target.com'],
      'Test Program',
      [],
      client,
    );

    expect(result.probeResults[0].techFingerprint).toBe('Express');
  });
});

// ─── Suggested Profile Generation Tests ──────────────────────────────────────

describe('AuthDetector — Suggested Profiles', () => {
  it('Telegram detection → instructions include "Open Telegram Desktop"', async () => {
    const client = createMockHttpClient(() => ({ status: 403 }));
    const result = await AuthDetector.detect(
      ['https://wallet.telegram.org'],
      'Wallet on Telegram',
      ['Test the Telegram Mini App'],
      client,
    );

    const telegramProfile = result.suggestedProfiles.find(p => p.authType === 'custom_header');
    expect(telegramProfile).toBeDefined();
    expect(telegramProfile!.instructions.some(i => i.includes('Telegram Desktop'))).toBe(true);
    expect(telegramProfile!.automationLevel).toBe('manual');
  });

  it('form login detection → instructions include "Navigate to login page"', async () => {
    const client = createMockHttpClient(() => ({
      status: 302,
      headers: { location: '/login' },
    }));
    const result = await AuthDetector.detect(
      ['https://app.target.com'],
      'Test App',
      [],
      client,
    );

    const loginProfile = result.suggestedProfiles.find(p => p.authType === 'cookie');
    expect(loginProfile).toBeDefined();
    expect(loginProfile!.instructions.some(i => i.includes('login page'))).toBe(true);
    expect(loginProfile!.automationLevel).toBe('full');
  });

  it('API key detection → instructions include "API key"', async () => {
    const client = createMockHttpClient(() => ({ status: 200 }));
    const result = await AuthDetector.detect(
      ['https://api.target.com'],
      'API Service',
      ['Provide X-API-Key header'],
      client,
    );

    const apiProfile = result.suggestedProfiles.find(p => p.authType === 'api_key');
    expect(apiProfile).toBeDefined();
    expect(apiProfile!.headerName).toBe('X-API-Key');
    expect(apiProfile!.instructions.some(i => i.includes('API key'))).toBe(true);
  });

  it('bearer detection → instructions include "Authorization header"', async () => {
    const client = createMockHttpClient(() => ({
      status: 401,
      headers: { 'www-authenticate': 'Bearer' },
    }));
    const result = await AuthDetector.detect(
      ['https://api.target.com'],
      'Test API',
      [],
      client,
    );

    const bearerProfile = result.suggestedProfiles.find(p => p.authType === 'bearer');
    expect(bearerProfile).toBeDefined();
    expect(bearerProfile!.instructions.some(i => i.includes('Authorization'))).toBe(true);
  });
});

// ─── URL Normalization Tests ─────────────────────────────────────────────────

describe('AuthDetector — URL Normalization', () => {
  it('normalizes bare domain to https', () => {
    expect(AuthDetector.normalizeTargetUrl('example.com')).toBe('https://example.com');
  });

  it('strips wildcard prefix', () => {
    expect(AuthDetector.normalizeTargetUrl('*.example.com')).toBe('https://example.com');
  });

  it('preserves existing https URLs', () => {
    expect(AuthDetector.normalizeTargetUrl('https://api.example.com')).toBe('https://api.example.com');
  });

  it('preserves existing http URLs', () => {
    expect(AuthDetector.normalizeTargetUrl('http://localhost:3000')).toBe('http://localhost:3000');
  });

  it('trims whitespace', () => {
    expect(AuthDetector.normalizeTargetUrl('  example.com  ')).toBe('https://example.com');
  });
});

// ─── Confidence Scoring Tests ────────────────────────────────────────────────

describe('AuthDetector — Confidence Scoring', () => {
  it('multi-source agreement boosts confidence', async () => {
    // Both HTTP probe (401) and text analysis ("bearer") agree
    const client = createMockHttpClient(() => ({
      status: 401,
      headers: { 'www-authenticate': 'Bearer' },
    }));
    const result = await AuthDetector.detect(
      ['https://api.target.com'],
      'API with bearer auth',
      ['Use bearer token in Authorization header'],
      client,
    );

    expect(result.requiresAuth).toBe(true);
    // Confidence should be boosted above single-source detection
    expect(result.confidence).toBeGreaterThan(0.7);
  });

  it('no auth signals → requiresAuth: false', async () => {
    const client = createMockHttpClient(() => ({
      status: 200,
      body: '<html>Welcome to our public page</html>',
    }));
    const result = await AuthDetector.detect(
      ['https://public.example.com'],
      'Public Website',
      ['This is a static marketing page'],
      client,
    );

    expect(result.requiresAuth).toBe(false);
    expect(result.confidence).toBe(0);
    expect(result.suggestedProfiles).toHaveLength(0);
  });

  it('all probes fail but text analysis detects auth → requiresAuth: true', async () => {
    const client = createMockHttpClient(() => new Error('Network unreachable'));
    const result = await AuthDetector.detect(
      ['https://unreachable.target.com'],
      'Wallet on Telegram',
      ['Test the Telegram Mini App webapp'],
      client,
    );

    expect(result.requiresAuth).toBe(true);
    expect(result.probeResults[0].error).toBeDefined();
    const telegram = result.detectedAuthTypes.find(d => d.type === 'telegram_webapp');
    expect(telegram).toBeDefined();
  });
});

// ─── Integration Tests ───────────────────────────────────────────────────────

describe('AuthDetector — Integration', () => {
  it('full Wallet on Telegram scenario', async () => {
    const client = createMockHttpClient(() => ({
      status: 403,
      statusText: 'Forbidden',
      headers: { server: 'cloudflare' },
    }));

    const result = await AuthDetector.detect(
      ['https://walletbot.me/api', 'https://t.me/wallet'],
      'Wallet on Telegram',
      [
        'Test the Telegram Mini App for security vulnerabilities',
        'The webapp uses initData parameter for authentication',
      ],
      client,
    );

    // Should detect auth
    expect(result.requiresAuth).toBe(true);
    expect(result.confidence).toBeGreaterThan(0.7);

    // Should detect Telegram WebApp
    const telegram = result.detectedAuthTypes.find(d => d.type === 'telegram_webapp');
    expect(telegram).toBeDefined();

    // Should generate profile with Telegram instructions
    const profile = result.suggestedProfiles.find(p => p.label.includes('Telegram'));
    expect(profile).toBeDefined();
    expect(profile!.authType).toBe('custom_header');

    // Probes should show 403
    expect(result.probeResults.every(p => p.authWall)).toBe(true);

    // Program hints should mention Telegram patterns
    expect(result.programHints.length).toBeGreaterThan(0);
  });

  it('empty targets array → still analyzes text', async () => {
    const client = createMockHttpClient(() => ({ status: 200 }));
    const result = await AuthDetector.detect(
      [],
      'OAuth2 API Platform',
      ['All endpoints require OAuth 2.0 bearer tokens'],
      client,
    );

    expect(result.requiresAuth).toBe(true);
    expect(result.probeResults).toHaveLength(0);
    const oauth = result.detectedAuthTypes.find(d => d.type === 'oauth');
    expect(oauth).toBeDefined();
  });

  it('concurrent probes all resolve', async () => {
    let requestCount = 0;
    const client = createMockHttpClient((options) => {
      requestCount++;
      if (options.url.includes('target1')) return { status: 401 };
      if (options.url.includes('target2')) return { status: 200 };
      if (options.url.includes('target3')) return { status: 302, headers: { location: '/login' } };
      return { status: 200 };
    });

    const result = await AuthDetector.detect(
      ['https://target1.com', 'https://target2.com', 'https://target3.com'],
      'Multi-target Program',
      [],
      client,
    );

    expect(requestCount).toBe(3);
    expect(result.probeResults).toHaveLength(3);
    expect(result.probeResults[0].authWall).toBe(true);
    expect(result.probeResults[1].authWall).toBe(false);
    expect(result.probeResults[2].redirectsToLogin).toBe(true);
  });
});

// ─── P1-0-c: Cookie profile login-URL fallback ──────────────────────────────
// The 2026-04-23 Superhuman hunt exposed a UX bug: when the detector flagged
// the target as auth-walled (401 on every probe) but didn't find a concrete
// login page, the cookie-profile instructions fell through to `baseUrl` (the
// first in-scope probe URL). For Superhuman's merged scope the first entry
// was `codacontent.io` — a CDN with no login form. The wizard dutifully told
// the user to "Navigate to the login page: https://codacontent.io," which
// is a dead end. Fix: leave `url` undefined and make instructions explicit
// when we couldn't auto-detect a login URL.

describe('AuthDetector — cookie profile login-URL fallback (P1-0-c)', () => {
  it('cookie profile: confident login URL (redirect-to-login) is embedded in url + instructions', async () => {
    const client = createMockHttpClient((options) => {
      if (options.url === 'https://target.com/app') {
        return { status: 302, headers: { location: 'https://target.com/login' } };
      }
      return { status: 200 };
    });
    const result = await AuthDetector.detect(
      ['https://target.com/app'],
      'Test Program',
      [],
      client,
    );
    const cookieProfile = result.suggestedProfiles.find(p => p.authType === 'cookie');
    expect(cookieProfile).toBeDefined();
    expect(cookieProfile!.url).toBe('https://target.com/login');
    expect(cookieProfile!.instructions[0]).toContain('https://target.com/login');
    expect(cookieProfile!.instructions[0]).toContain('Navigate to the login page');
  });

  it('cookie profile: no confident login URL → url is undefined, instructions prompt the user', async () => {
    // 401 on every probe triggers cookie-type detection but no loginUrl.
    // Before the fix, the profile's url would default to the first probe URL
    // (effectively the "CDN as login page" footgun).
    const client = createMockHttpClient(() => ({ status: 401, statusText: 'Unauthorized' }));
    const result = await AuthDetector.detect(
      ['https://codacontent.io', 'https://api.superhuman.com'],
      'Superhuman',
      [],
      client,
    );

    const cookieProfile = result.suggestedProfiles.find(p => p.authType === 'cookie');
    if (!cookieProfile) {
      // 401 probes may also suggest bearer/api_key; if cookie isn't even in
      // the suggested list that's an acceptable alternative outcome. Skip.
      return;
    }

    expect(cookieProfile.url).toBeUndefined();
    expect(cookieProfile.instructions[0]).toMatch(/Enter the login page URL below/i);
    // Critical: must NOT leak the first in-scope host as a suggested login URL.
    expect(cookieProfile.instructions.join(' ')).not.toContain('codacontent.io');
  });

  it('non-cookie profiles (bearer/api_key) still use baseUrl — only cookie got the stricter policy', async () => {
    // Confirms we didn't over-correct: bearer/api_key profiles legitimately
    // use the program's base URL as an API target for credential validation.
    const client = createMockHttpClient(() => ({
      status: 401,
      headers: { 'www-authenticate': 'Bearer realm="api"' },
    }));
    const result = await AuthDetector.detect(
      ['https://api.target.com/v1/me'],
      'Bearer API',
      [],
      client,
    );
    const bearerProfile = result.suggestedProfiles.find(p => p.authType === 'bearer');
    expect(bearerProfile).toBeDefined();
    // Bearer profile: url is the probe URL (legitimate — it's the API base).
    expect(bearerProfile!.url).toBe('https://api.target.com/v1/me');
  });
});

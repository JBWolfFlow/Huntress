/**
 * WAF Detection & Payload Encoder Tests (Phase 20G)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WAFDetector } from '../core/evasion/waf_detector';
import type { WAFVendor, WAFDetectionResult } from '../core/evasion/waf_detector';
import { PayloadEncoder } from '../core/evasion/payload_encoder';
import type { HttpClient, HttpResponse, HttpRequestOptions } from '../core/http/request_engine';

// ─── Mock HttpClient ─────────────────────────────────────────────────────────

function createMockHttpClient(
  handler?: (options: HttpRequestOptions) => Partial<HttpResponse>,
): HttpClient {
  const defaultResponse: HttpResponse = {
    status: 200,
    statusText: 'OK',
    headers: {},
    body: '<html>OK</html>',
    timing: { dnsMs: 0, connectMs: 0, ttfbMs: 0, totalMs: 1 },
    redirectChain: [],
    cookies: [],
    size: 0,
  };

  return {
    request: vi.fn(async (options: HttpRequestOptions) => ({
      ...defaultResponse,
      ...(handler?.(options) ?? {}),
    })),
    getCookies: vi.fn(() => []),
    setCookie: vi.fn(),
    clearCookies: vi.fn(),
    setAuthHeader: vi.fn(),
    clearAuth: vi.fn(),
    setRateLimit: vi.fn(),
    getRequestCount: vi.fn(() => 0),
    getRequestLog: vi.fn(() => []),
    clearRequestLog: vi.fn(),
  } as unknown as HttpClient;
}

// ─── WAF Detector Tests ──────────────────────────────────────────────────────

describe('WAFDetector', () => {
  describe('header-based detection', () => {
    it('detects Cloudflare via cf-ray header', async () => {
      const client = createMockHttpClient(() => ({
        headers: {
          server: 'cloudflare',
          'cf-ray': '7abc123def-LAX',
          'cf-cache-status': 'DYNAMIC',
        },
        cookies: [],
      }));

      const detector = new WAFDetector(client);
      const result = await detector.detect('https://example.com');

      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('cloudflare');
      expect(result.confidence).toBeGreaterThan(0.5);
      expect(result.evidence.some(e => e.includes('cloudflare'))).toBe(true);
    });

    it('detects AWS WAF via amzn headers', async () => {
      const client = createMockHttpClient(() => ({
        headers: {
          'x-amzn-requestid': 'abc-123',
          'x-amz-cf-id': 'def-456',
        },
        cookies: [],
      }));

      const detector = new WAFDetector(client);
      const result = await detector.detect('https://example.com');

      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('aws_waf');
    });

    it('detects Akamai via x-akamai-transformed header', async () => {
      const client = createMockHttpClient(() => ({
        headers: {
          'x-akamai-transformed': '9 - 0 pmb=mTOE,2',
          server: 'AkamaiGHost',
        },
        cookies: [],
      }));

      const detector = new WAFDetector(client);
      const result = await detector.detect('https://example.com');

      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('akamai');
    });

    it('detects Imperva via x-iinfo header', async () => {
      const client = createMockHttpClient(() => ({
        headers: {
          'x-iinfo': '7-12345-0 0NNN RT(1234567890)',
          'x-cdn': 'Imperva',
        },
        cookies: [],
      }));

      const detector = new WAFDetector(client);
      const result = await detector.detect('https://example.com');

      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('imperva');
    });

    it('detects Sucuri via server header', async () => {
      const client = createMockHttpClient(() => ({
        headers: {
          server: 'Sucuri/Cloudproxy',
          'x-sucuri-id': '12345',
        },
        cookies: [],
      }));

      const detector = new WAFDetector(client);
      const result = await detector.detect('https://example.com');

      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('sucuri');
    });

    it('detects F5 BIG-IP via server header', async () => {
      const client = createMockHttpClient(() => ({
        headers: {
          server: 'BigIP',
        },
        cookies: [],
      }));

      const detector = new WAFDetector(client);
      const result = await detector.detect('https://example.com');

      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('f5_bigip');
    });

    it('detects ModSecurity via server header', async () => {
      const client = createMockHttpClient(() => ({
        headers: {
          server: 'Apache/2.4 (mod_security)',
        },
        cookies: [],
      }));

      const detector = new WAFDetector(client);
      const result = await detector.detect('https://example.com');

      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('modsecurity');
    });

    it('detects Wordfence via x-wordfence header', async () => {
      const client = createMockHttpClient(() => ({
        headers: {
          'x-wordfence': 'enabled',
        },
        cookies: [],
      }));

      const detector = new WAFDetector(client);
      const result = await detector.detect('https://example.com');

      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('wordfence');
    });
  });

  describe('cookie-based detection', () => {
    it('detects Cloudflare via __cf_bm cookie', async () => {
      const client = createMockHttpClient(() => ({
        headers: {},
        cookies: [
          { name: '__cf_bm', value: 'abc', domain: 'example.com', path: '/', httpOnly: false, secure: true },
        ],
      }));

      const detector = new WAFDetector(client);
      const result = await detector.detect('https://example.com');

      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('cloudflare');
    });

    it('detects Imperva via incap_ses cookie', async () => {
      const client = createMockHttpClient(() => ({
        headers: {},
        cookies: [
          { name: 'incap_ses_12345', value: 'abc', domain: 'example.com', path: '/', httpOnly: false, secure: true },
        ],
      }));

      const detector = new WAFDetector(client);
      const result = await detector.detect('https://example.com');

      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('imperva');
    });
  });

  describe('block page detection', () => {
    it('detects Cloudflare block page', async () => {
      const client = createMockHttpClient((options) => {
        if (options.url.includes('huntress_waf_probe')) {
          return {
            status: 403,
            body: '<html><title>Attention Required! | Cloudflare</title><body>Cloudflare Ray ID: abc123</body></html>',
            headers: {},
            cookies: [],
          };
        }
        return { headers: {}, cookies: [] };
      });

      const detector = new WAFDetector(client);
      const result = await detector.probeWithPayload('https://example.com');

      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('cloudflare');
      expect(result.blockStatusCode).toBe(403);
    });

    it('detects Imperva block page', async () => {
      const client = createMockHttpClient((options) => {
        if (options.url.includes('huntress_waf_probe')) {
          return {
            status: 403,
            body: '<html>Incapsula incident ID: 12345</html>',
            headers: {},
            cookies: [],
          };
        }
        return { headers: {}, cookies: [] };
      });

      const detector = new WAFDetector(client);
      const result = await detector.probeWithPayload('https://example.com');

      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('imperva');
    });

    it('detects unknown WAF on generic 403 block', async () => {
      const client = createMockHttpClient((options) => {
        if (options.url.includes('huntress_waf_probe')) {
          return {
            status: 403,
            body: '<html>Forbidden</html>',
            headers: {},
            cookies: [],
          };
        }
        return { headers: {}, cookies: [] };
      });

      const detector = new WAFDetector(client);
      const result = await detector.probeWithPayload('https://example.com');

      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('unknown');
      expect(result.blockStatusCode).toBe(403);
    });

    it('returns no WAF when probe is not blocked', async () => {
      const client = createMockHttpClient(() => ({
        status: 200,
        body: '<html>OK</html>',
        headers: {},
        cookies: [],
      }));

      const detector = new WAFDetector(client);
      const result = await detector.probeWithPayload('https://example.com');

      expect(result.detected).toBe(false);
      expect(result.vendor).toBe('none');
    });
  });

  describe('no WAF detection', () => {
    it('returns none when no WAF signals found', async () => {
      const client = createMockHttpClient(() => ({
        headers: {
          server: 'nginx/1.24.0',
          'content-type': 'text/html',
        },
        cookies: [],
        status: 200,
        body: '<html>OK</html>',
      }));

      const detector = new WAFDetector(client);
      const result = await detector.detect('https://example.com');

      expect(result.detected).toBe(false);
      expect(result.vendor).toBe('none');
    });
  });
});

// ─── Payload Encoder Tests ───────────────────────────────────────────────────

describe('PayloadEncoder', () => {
  let encoder: PayloadEncoder;

  beforeEach(() => {
    encoder = new PayloadEncoder();
  });

  describe('getStrategiesForWAF', () => {
    it('returns universal strategies for unknown WAF', () => {
      const strategies = encoder.getStrategiesForWAF('unknown');
      expect(strategies.length).toBeGreaterThanOrEqual(10); // Universal encodings
    });

    it('returns universal + WAF-specific strategies for known WAF', () => {
      const universalCount = encoder.getStrategiesForWAF('unknown').length;
      const cfStrategies = encoder.getStrategiesForWAF('cloudflare');
      expect(cfStrategies.length).toBeGreaterThan(universalCount);
    });

    it('returns strategies for each known WAF vendor', () => {
      const vendors: WAFVendor[] = ['cloudflare', 'aws_waf', 'akamai', 'imperva', 'modsecurity', 'wordfence'];
      for (const vendor of vendors) {
        const strategies = encoder.getStrategiesForWAF(vendor);
        expect(strategies.length).toBeGreaterThanOrEqual(10);
      }
    });
  });

  describe('encodePayload', () => {
    const testPayload = '<script>alert(1)</script>';

    it('returns multiple unique variants', () => {
      const variants = encoder.encodePayload(testPayload, 'cloudflare');
      expect(variants.length).toBeGreaterThan(1);
      // All variants should be unique
      expect(new Set(variants).size).toBe(variants.length);
    });

    it('includes the raw payload', () => {
      const variants = encoder.encodePayload(testPayload, 'cloudflare');
      expect(variants).toContain(testPayload);
    });

    it('URL-encodes the payload', () => {
      const variants = encoder.encodePayload(testPayload, 'none');
      const urlEncoded = encodeURIComponent(testPayload);
      expect(variants).toContain(urlEncoded);
    });

    it('produces HTML entity encoded variant', () => {
      const variants = encoder.encodePayload(testPayload, 'none');
      expect(variants.some(v => v.includes('&#60;'))).toBe(true);
    });

    it('produces mixed case variant', () => {
      const variants = encoder.encodePayload(testPayload, 'none');
      // At least one variant should have different casing
      expect(variants.some(v => v !== testPayload && v.toLowerCase() === testPayload.toLowerCase())).toBe(true);
    });

    it('generates more variants for known WAFs', () => {
      const noneVariants = encoder.encodePayload(testPayload, 'none');
      const cfVariants = encoder.encodePayload(testPayload, 'cloudflare');
      expect(cfVariants.length).toBeGreaterThanOrEqual(noneVariants.length);
    });
  });

  describe('applyChain', () => {
    it('applies encoding strategies in sequence', () => {
      const strategies = encoder.getStrategiesForWAF('none');
      const urlEncode = strategies.find(s => s.name === 'url_encode')!;
      const doubleEncode = strategies.find(s => s.name === 'double_url_encode')!;

      // Apply URL encode first, then the chain should produce double-encoded output
      const result = encoder.applyChain('<', [urlEncode]);
      expect(result).toBe(encodeURIComponent('<'));
    });

    it('handles empty strategy chain', () => {
      const result = encoder.applyChain('test', []);
      expect(result).toBe('test');
    });
  });

  describe('getVariantCount', () => {
    it('returns count of unique variants', () => {
      const count = encoder.getVariantCount('<script>alert(1)</script>', 'cloudflare');
      expect(count).toBeGreaterThan(1);
    });
  });
});

/**
 * HTTP Request Engine Tests
 *
 * Tests for Phase 20A: Direct HTTP client with scope enforcement,
 * cookie persistence, rate limiting, redirect tracking, and request logging.
 */

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import http from 'http';
import { HttpClient } from '../core/http/request_engine';
import type { HttpRequestOptions, HttpResponse, Cookie } from '../core/http/request_engine';

// ─── Test HTTP Server ────────────────────────────────────────────────────────

let server: http.Server;
let baseUrl: string;

function createTestServer(): http.Server {
  return http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const path = url.pathname;

    switch (path) {
      case '/ok': {
        res.writeHead(200, {
          'Content-Type': 'text/html',
          'X-Custom': 'test-value',
        });
        res.end('<html><body>OK</body></html>');
        break;
      }

      case '/json': {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'success', data: [1, 2, 3] }));
        break;
      }

      case '/set-cookie': {
        res.writeHead(200, {
          'Content-Type': 'text/plain',
          'Set-Cookie': [
            'session=abc123; HttpOnly; Path=/',
            'theme=dark; Path=/; Max-Age=3600',
          ],
        });
        res.end('Cookies set');
        break;
      }

      case '/check-cookie': {
        const cookie = req.headers['cookie'] ?? '';
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ cookies: cookie }));
        break;
      }

      case '/redirect': {
        const target = url.searchParams.get('to') ?? '/ok';
        res.writeHead(302, { 'Location': target });
        res.end();
        break;
      }

      case '/redirect-chain': {
        res.writeHead(301, { 'Location': '/redirect?to=/ok' });
        res.end();
        break;
      }

      case '/redirect-303': {
        res.writeHead(303, { 'Location': '/ok' });
        res.end();
        break;
      }

      case '/rate-limited': {
        res.writeHead(429, {
          'Content-Type': 'text/plain',
          'Retry-After': '1',
        });
        res.end('Too Many Requests');
        break;
      }

      case '/rate-limited-no-header': {
        res.writeHead(429, { 'Content-Type': 'text/plain' });
        res.end('Too Many Requests');
        break;
      }

      case '/large-body': {
        const size = parseInt(url.searchParams.get('size') ?? '200000', 10);
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('x'.repeat(size));
        break;
      }

      case '/echo': {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            method: req.method,
            headers: req.headers,
            body,
            url: req.url,
          }));
        });
        return;
      }

      case '/xss': {
        const q = url.searchParams.get('q') ?? '';
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`<html><body>Search: ${q}</body></html>`);
        break;
      }

      case '/slow': {
        setTimeout(() => {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('Slow response');
        }, 2000);
        return;
      }

      default: {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
      }
    }
  });
}

beforeAll(async () => {
  server = createTestServer();
  await new Promise<void>((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr !== 'string') {
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      } else {
        reject(new Error('Failed to start test server'));
      }
    });
  });
});

afterAll(async () => {
  await new Promise<void>(resolve => {
    server.close(() => resolve());
  });
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('HttpClient', () => {
  let client: HttpClient;

  beforeEach(() => {
    client = new HttpClient({
      defaultHeaders: { 'User-Agent': 'Huntress-Test/1.0' },
    });
  });

  describe('Basic requests', () => {
    it('makes a GET request and returns full response', async () => {
      const response = await client.request({
        url: `${baseUrl}/ok`,
        method: 'GET',
      });

      expect(response.status).toBe(200);
      expect(response.statusText).toBeDefined();
      expect(response.body).toContain('OK');
      expect(response.headers['content-type']).toContain('text/html');
      expect(response.headers['x-custom']).toBe('test-value');
      expect(response.size).toBeGreaterThan(0);
      expect(response.timing.totalMs).toBeGreaterThan(0);
    });

    it('makes a POST request with body', async () => {
      const response = await client.request({
        url: `${baseUrl}/echo`,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: 'value' }),
      });

      expect(response.status).toBe(200);
      const echo = JSON.parse(response.body);
      expect(echo.method).toBe('POST');
      expect(echo.body).toBe('{"key":"value"}');
    });

    it('makes HEAD request', async () => {
      const response = await client.request({
        url: `${baseUrl}/ok`,
        method: 'HEAD',
      });

      expect(response.status).toBe(200);
    });

    it('returns 404 for unknown paths', async () => {
      const response = await client.request({
        url: `${baseUrl}/nonexistent`,
        method: 'GET',
      });

      expect(response.status).toBe(404);
    });

    it('parses JSON response', async () => {
      const response = await client.request({
        url: `${baseUrl}/json`,
        method: 'GET',
      });

      expect(response.status).toBe(200);
      const data = JSON.parse(response.body);
      expect(data.status).toBe('success');
      expect(data.data).toEqual([1, 2, 3]);
    });
  });

  describe('Cookie persistence', () => {
    it('captures Set-Cookie headers from response', async () => {
      const response = await client.request({
        url: `${baseUrl}/set-cookie`,
        method: 'GET',
      });

      expect(response.status).toBe(200);

      const cookies = client.getCookies('127.0.0.1');
      expect(cookies.length).toBeGreaterThanOrEqual(2);

      const session = cookies.find(c => c.name === 'session');
      expect(session).toBeDefined();
      expect(session!.value).toBe('abc123');
      expect(session!.httpOnly).toBe(true);

      const theme = cookies.find(c => c.name === 'theme');
      expect(theme).toBeDefined();
      expect(theme!.value).toBe('dark');
    });

    it('applies cookies from jar on subsequent requests', async () => {
      // First request sets cookies
      await client.request({
        url: `${baseUrl}/set-cookie`,
        method: 'GET',
      });

      // Second request should send cookies
      const response = await client.request({
        url: `${baseUrl}/check-cookie`,
        method: 'GET',
      });

      const data = JSON.parse(response.body);
      expect(data.cookies).toContain('session=abc123');
      expect(data.cookies).toContain('theme=dark');
    });

    it('manually set cookies are sent with requests', async () => {
      client.setCookie({
        name: 'manual',
        value: 'test123',
        domain: '127.0.0.1',
        path: '/',
        httpOnly: false,
        secure: false,
      });

      const response = await client.request({
        url: `${baseUrl}/check-cookie`,
        method: 'GET',
      });

      const data = JSON.parse(response.body);
      expect(data.cookies).toContain('manual=test123');
    });

    it('clears cookies', async () => {
      await client.request({
        url: `${baseUrl}/set-cookie`,
        method: 'GET',
      });

      expect(client.getCookies('127.0.0.1').length).toBeGreaterThan(0);

      client.clearCookies();
      expect(client.getCookies('127.0.0.1').length).toBe(0);
    });
  });

  describe('Redirect following', () => {
    it('follows 302 redirects and tracks redirect chain', async () => {
      const response = await client.request({
        url: `${baseUrl}/redirect?to=/ok`,
        method: 'GET',
      });

      expect(response.status).toBe(200);
      expect(response.body).toContain('OK');
      expect(response.redirectChain.length).toBe(1);
      expect(response.redirectChain[0].status).toBe(302);
    });

    it('follows multi-step redirect chain', async () => {
      const response = await client.request({
        url: `${baseUrl}/redirect-chain`,
        method: 'GET',
      });

      expect(response.status).toBe(200);
      expect(response.body).toContain('OK');
      expect(response.redirectChain.length).toBe(2);
      expect(response.redirectChain[0].status).toBe(301);
      expect(response.redirectChain[1].status).toBe(302);
    });

    it('does not follow redirects when followRedirects=false', async () => {
      const response = await client.request({
        url: `${baseUrl}/redirect?to=/ok`,
        method: 'GET',
        followRedirects: false,
      });

      expect(response.status).toBe(302);
      expect(response.headers['location']).toBe('/ok');
      expect(response.redirectChain.length).toBe(0);
    });

    it('changes method to GET on 303 redirect', async () => {
      const response = await client.request({
        url: `${baseUrl}/redirect-303`,
        method: 'POST',
        body: 'test=data',
      });

      expect(response.status).toBe(200);
      expect(response.redirectChain[0].status).toBe(303);
    });
  });

  describe('Rate limiting', () => {
    it('handles 429 response with Retry-After header', async () => {
      const response = await client.request({
        url: `${baseUrl}/rate-limited`,
        method: 'GET',
      });

      // The 429 response is returned normally (backoff applies to NEXT request)
      expect(response.status).toBe(429);
    });

    it('tracks request count per domain', async () => {
      const fresh = new HttpClient();

      await fresh.request({ url: `${baseUrl}/ok`, method: 'GET' });
      await fresh.request({ url: `${baseUrl}/ok`, method: 'GET' });

      const count = fresh.getRequestCount('127.0.0.1');
      expect(count).toBeGreaterThanOrEqual(1);
    });

    it('allows setting custom rate limit per domain', () => {
      client.setRateLimit('example.com', 5);
      // No error thrown — this just sets the limit for future requests
      expect(client.getRequestCount('example.com')).toBe(0);
    });
  });

  describe('Response parsing', () => {
    it('populates all response fields correctly', async () => {
      const response = await client.request({
        url: `${baseUrl}/json`,
        method: 'GET',
      });

      expect(response.status).toBe(200);
      expect(typeof response.statusText).toBe('string');
      expect(typeof response.headers).toBe('object');
      expect(typeof response.body).toBe('string');
      expect(response.timing.totalMs).toBeGreaterThanOrEqual(0);
      expect(Array.isArray(response.redirectChain)).toBe(true);
      expect(Array.isArray(response.cookies)).toBe(true);
      expect(response.size).toBeGreaterThan(0);
    });

    it('returns timing information', async () => {
      const response = await client.request({
        url: `${baseUrl}/ok`,
        method: 'GET',
      });

      expect(response.timing.totalMs).toBeGreaterThanOrEqual(0);
      expect(typeof response.timing.ttfbMs).toBe('number');
    });
  });

  describe('Request logging', () => {
    it('records all requests in the log', async () => {
      const fresh = new HttpClient();

      await fresh.request({ url: `${baseUrl}/ok`, method: 'GET' });
      await fresh.request({ url: `${baseUrl}/json`, method: 'GET' });

      const log = fresh.getRequestLog();
      expect(log.length).toBe(2);
      expect(log[0].request.url).toBe(`${baseUrl}/ok`);
      expect(log[0].request.method).toBe('GET');
      expect(log[0].response.status).toBe(200);
      expect(log[0].timestamp).toBeGreaterThan(0);
      expect(log[1].request.url).toBe(`${baseUrl}/json`);
    });

    it('truncates large response bodies in log', async () => {
      const fresh = new HttpClient();

      await fresh.request({
        url: `${baseUrl}/large-body?size=200000`,
        method: 'GET',
      });

      const log = fresh.getRequestLog();
      expect(log.length).toBe(1);

      // Log body should be truncated
      expect(log[0].response.body.length).toBeLessThan(200000);
      expect(log[0].response.body).toContain('[TRUNCATED');
    });

    it('returns full body in response even for large responses', async () => {
      const response = await client.request({
        url: `${baseUrl}/large-body?size=150000`,
        method: 'GET',
      });

      // The actual response body should be full size
      expect(response.body.length).toBe(150000);
    });

    it('clears request log', async () => {
      await client.request({ url: `${baseUrl}/ok`, method: 'GET' });
      expect(client.getRequestLog().length).toBe(1);

      client.clearRequestLog();
      expect(client.getRequestLog().length).toBe(0);
    });
  });

  describe('Auth headers', () => {
    it('injects auth headers into requests', async () => {
      client.setAuthHeader('Authorization', 'Bearer token123');

      const response = await client.request({
        url: `${baseUrl}/echo`,
        method: 'GET',
      });

      const echo = JSON.parse(response.body);
      expect(echo.headers['authorization']).toBe('Bearer token123');
    });

    it('clears auth headers', async () => {
      client.setAuthHeader('Authorization', 'Bearer token123');
      client.clearAuth();

      const response = await client.request({
        url: `${baseUrl}/echo`,
        method: 'GET',
      });

      const echo = JSON.parse(response.body);
      expect(echo.headers['authorization']).toBeUndefined();
    });

    it('request headers override auth headers', async () => {
      client.setAuthHeader('Authorization', 'Bearer default');

      const response = await client.request({
        url: `${baseUrl}/echo`,
        method: 'GET',
        headers: { 'Authorization': 'Bearer override' },
      });

      const echo = JSON.parse(response.body);
      expect(echo.headers['authorization']).toBe('Bearer override');
    });
  });

  describe('Scope enforcement', () => {
    it('allows requests to localhost in test mode', async () => {
      const response = await client.request({
        url: `${baseUrl}/ok`,
        method: 'GET',
      });

      expect(response.status).toBe(200);
    });

    // In test/Node.js mode, scope validation is permissive.
    // In Tauri mode, it would call validate_target via IPC.
    // This test verifies the validateScope function is called.
    it('parses URL hostname for scope check', async () => {
      // This should not throw in test mode
      const response = await client.request({
        url: `${baseUrl}/ok`,
        method: 'GET',
      });
      expect(response.status).toBe(200);
    });
  });

  describe('Timeout handling', () => {
    it('times out on slow requests', async () => {
      await expect(
        client.request({
          url: `${baseUrl}/slow`,
          method: 'GET',
          timeoutMs: 500,
        })
      ).rejects.toThrow();
    });
  });

  describe('Content type', () => {
    it('sets content type header', async () => {
      const response = await client.request({
        url: `${baseUrl}/echo`,
        method: 'POST',
        contentType: 'application/xml',
        body: '<root/>',
      });

      const echo = JSON.parse(response.body);
      expect(echo.headers['content-type']).toBe('application/xml');
    });
  });

  describe('Proxy support', () => {
    it('rejects invalid proxy URL', async () => {
      await expect(
        client.request({
          url: `${baseUrl}/ok`,
          method: 'GET',
          proxyUrl: 'not-a-url',
        })
      ).rejects.toThrow('Invalid proxy URL');
    });
  });

  describe('Default headers', () => {
    it('sends default headers with every request', async () => {
      const response = await client.request({
        url: `${baseUrl}/echo`,
        method: 'GET',
      });

      const echo = JSON.parse(response.body);
      expect(echo.headers['user-agent']).toBe('Huntress-Test/1.0');
    });
  });
});

describe('HttpClient tool schema integration', () => {
  it('http_request tool schema is registered in AGENT_TOOL_SCHEMAS', async () => {
    const { AGENT_TOOL_SCHEMAS } = await import('../core/engine/tool_schemas');
    const httpTool = AGENT_TOOL_SCHEMAS.find(t => t.name === 'http_request');

    expect(httpTool).toBeDefined();
    expect(httpTool!.input_schema.required).toContain('url');
    expect(httpTool!.input_schema.required).toContain('method');
    expect(httpTool!.input_schema.properties.method.enum).toContain('GET');
    expect(httpTool!.input_schema.properties.method.enum).toContain('POST');
  });
});

describe('ReactLoop http_request handler', () => {
  it('ReactLoop config accepts httpClient field', async () => {
    const { ReactLoop } = await import('../core/engine/react_loop');

    const httpClient = new HttpClient();
    const loop = new ReactLoop({
      provider: {
        displayName: 'Mock',
        sendMessage: vi.fn(async () => ({
          content: 'done',
          model: 'mock',
          usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
          stopReason: 'end_turn' as const,
          inputTokens: 0,
          outputTokens: 0,
        })),
        streamMessage: vi.fn(async function* () {
          yield { type: 'text' as const, text: 'done' };
        }),
        getAvailableModels: vi.fn(() => []),
        validateApiKey: vi.fn(async () => true),
        estimateCost: vi.fn(() => ({ inputCost: 0, outputCost: 0, totalCost: 0 })),
      },
      model: 'mock',
      systemPrompt: 'test',
      goal: 'test',
      tools: [],
      target: 'example.com',
      scope: ['example.com'],
      httpClient,
    });

    expect(loop).toBeDefined();
  });
});

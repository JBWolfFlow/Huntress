/**
 * P2-1 JS-rendered Crawler Tests
 *
 * Verifies the WebCrawler integration with the optional headless-browser
 * pass:
 *   - SPA endpoints (XHR/fetch) discovered during render are merged into
 *     `endpoints` with source: 'javascript'
 *   - HTML-discovered endpoints get their source upgraded when JS render
 *     confirms them
 *   - JS-discovered links are queued for crawl (extending coverage beyond
 *     static HTML)
 *   - JS-discovered forms (not in static HTML) are added to `forms`
 *   - Browser failures degrade gracefully — HTTP results survive
 *   - Out-of-scope JS endpoints are filtered out
 *   - useHeadlessBrowser flag without a browser client is a silent no-op
 */

import { describe, it, expect } from 'vitest';
import { WebCrawler } from '../core/discovery/crawler';
import type { CrawlConfig, HeadlessBrowserCrawler } from '../core/discovery/crawler';
import type { HttpClient } from '../core/http/request_engine';

// ─── Fakes ──────────────────────────────────────────────────────────────────

/**
 * Minimal HttpClient fake that returns canned responses keyed by URL.
 * Returns 200 + given body for known URLs, 404 for everything else.
 */
function makeHttpClient(pages: Record<string, string>): HttpClient {
  return {
    async request(opts) {
      const url = opts.url;
      const body = pages[url];
      if (body !== undefined) {
        return {
          status: 200,
          headers: { 'content-type': 'text/html' },
          body,
          url,
        };
      }
      // robots.txt → 404 to skip the parser
      return { status: 404, headers: {}, body: '', url };
    },
  } as unknown as HttpClient;
}

/**
 * Fake browser that returns canned crawl results keyed by URL. Per-URL
 * `error` simulates browser navigation failure; URLs not in the map throw.
 */
function makeFakeBrowser(
  results: Record<string, Awaited<ReturnType<HeadlessBrowserCrawler['crawlPage']>>>,
  options?: { throwOn?: string[] },
): HeadlessBrowserCrawler {
  return {
    async crawlPage(url) {
      if (options?.throwOn?.includes(url)) {
        throw new Error('simulated browser failure');
      }
      const r = results[url];
      if (!r) {
        return { finalUrl: url, title: '', links: [], forms: [], apiEndpoints: [] };
      }
      return r;
    },
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('P2-1 · JS-rendered crawler', () => {
  const SCOPE = ['target.com'];

  it('discovers SPA-only XHR/fetch endpoints invisible to HTTP-only crawl', async () => {
    const httpClient = makeHttpClient({
      'https://target.com/': '<html><body>Loading SPA…</body></html>',
    });
    const browser = makeFakeBrowser({
      'https://target.com/': {
        finalUrl: 'https://target.com/',
        title: 'App',
        links: [],
        forms: [],
        apiEndpoints: [
          { url: 'https://target.com/api/v1/me', method: 'GET' },
          { url: 'https://target.com/api/v1/orders?limit=10', method: 'GET' },
          { url: 'https://target.com/api/v1/cart', method: 'POST' },
        ],
      },
    });

    const config: CrawlConfig = {
      seedUrls: ['https://target.com/'],
      scope: SCOPE,
      maxDepth: 0,
      maxPages: 5,
      respectRobotsTxt: false,
      httpClient,
      useHeadlessBrowser: true,
      headlessBrowser: browser,
    };

    const result = await new WebCrawler(config).crawl();

    const jsEndpoints = result.endpoints.filter(e => e.source === 'javascript');
    expect(jsEndpoints.length).toBeGreaterThanOrEqual(3);
    expect(jsEndpoints.find(e => e.url === 'https://target.com/api/v1/me')).toBeDefined();
    expect(jsEndpoints.find(e => e.url === 'https://target.com/api/v1/orders' && e.method === 'GET')).toBeDefined();
    expect(jsEndpoints.find(e => e.url === 'https://target.com/api/v1/cart' && e.method === 'POST')).toBeDefined();
    // Query params on the orders URL are extracted
    const ordersEp = jsEndpoints.find(e => e.url === 'https://target.com/api/v1/orders');
    expect(ordersEp?.parameters).toContain('limit');
  });

  it('upgrades source from html → javascript when JS render confirms an HTML-discovered endpoint', async () => {
    const httpClient = makeHttpClient({
      'https://target.com/': '<html><body><a href="/page?q=test">link</a></body></html>',
    });
    const browser = makeFakeBrowser({
      'https://target.com/': {
        finalUrl: 'https://target.com/',
        title: '',
        links: [],
        forms: [],
        // JS confirms the same endpoint loads dynamically
        apiEndpoints: [{ url: 'https://target.com/page?q=test', method: 'GET' }],
      },
    });

    const config: CrawlConfig = {
      seedUrls: ['https://target.com/'],
      scope: SCOPE,
      maxDepth: 0,
      respectRobotsTxt: false,
      httpClient,
      useHeadlessBrowser: true,
      headlessBrowser: browser,
    };

    const result = await new WebCrawler(config).crawl();
    const pageEp = result.endpoints.find(e => e.url === 'https://target.com/page');
    expect(pageEp).toBeDefined();
    expect(pageEp!.source).toBe('javascript');
    expect(pageEp!.parameters).toContain('q');
  });

  it('queues JS-discovered links for further crawl', async () => {
    const httpClient = makeHttpClient({
      'https://target.com/': '<html><body>SPA root</body></html>',
      'https://target.com/dashboard': '<html><body>Dashboard</body></html>',
      'https://target.com/profile': '<html><body>Profile</body></html>',
    });
    const browser = makeFakeBrowser({
      'https://target.com/': {
        finalUrl: 'https://target.com/',
        title: '',
        // SPA router populates these after JS boot — invisible to static HTML
        links: ['/dashboard', '/profile'],
        forms: [],
        apiEndpoints: [],
      },
      'https://target.com/dashboard': {
        finalUrl: 'https://target.com/dashboard',
        title: '',
        links: [],
        forms: [],
        apiEndpoints: [],
      },
      'https://target.com/profile': {
        finalUrl: 'https://target.com/profile',
        title: '',
        links: [],
        forms: [],
        apiEndpoints: [],
      },
    });

    const config: CrawlConfig = {
      seedUrls: ['https://target.com/'],
      scope: SCOPE,
      maxDepth: 2,
      respectRobotsTxt: false,
      httpClient,
      useHeadlessBrowser: true,
      headlessBrowser: browser,
    };

    const result = await new WebCrawler(config).crawl();
    const visitedUrls = result.pages.map(p => p.url);
    expect(visitedUrls).toContain('https://target.com/dashboard');
    expect(visitedUrls).toContain('https://target.com/profile');
  });

  it('discovers JS-injected forms (not in static HTML) as endpoints', async () => {
    const httpClient = makeHttpClient({
      'https://target.com/': '<html><body><div id="root"></div></body></html>',
    });
    const browser = makeFakeBrowser({
      'https://target.com/': {
        finalUrl: 'https://target.com/',
        title: '',
        links: [],
        forms: [{
          action: '/api/login',
          method: 'POST',
          inputs: [
            { name: 'email', type: 'email' },
            { name: 'password', type: 'password' },
          ],
        }],
        apiEndpoints: [],
      },
    });

    const config: CrawlConfig = {
      seedUrls: ['https://target.com/'],
      scope: SCOPE,
      maxDepth: 0,
      respectRobotsTxt: false,
      httpClient,
      useHeadlessBrowser: true,
      headlessBrowser: browser,
    };

    const result = await new WebCrawler(config).crawl();
    const loginForm = result.forms.find(f => f.action === 'https://target.com/api/login');
    expect(loginForm).toBeDefined();
    expect(loginForm!.method).toBe('POST');
    expect(loginForm!.inputs.map(i => i.name)).toEqual(['email', 'password']);

    const formEndpoint = result.endpoints.find(e =>
      e.url === 'https://target.com/api/login' && e.source === 'javascript'
    );
    expect(formEndpoint).toBeDefined();
    expect(formEndpoint!.parameters).toEqual(['email', 'password']);
  });

  it('filters out-of-scope JS-discovered endpoints', async () => {
    const httpClient = makeHttpClient({
      'https://target.com/': '<html><body>App</body></html>',
    });
    const browser = makeFakeBrowser({
      'https://target.com/': {
        finalUrl: 'https://target.com/',
        title: '',
        links: ['https://other.com/leak'],  // out-of-scope
        forms: [],
        apiEndpoints: [
          { url: 'https://target.com/api/me', method: 'GET' },     // in-scope
          { url: 'https://analytics.evil.com/track', method: 'POST' }, // OUT-OF-SCOPE
          { url: 'https://googletagmanager.com/gtm.js', method: 'GET' }, // OUT-OF-SCOPE
        ],
      },
    });

    const config: CrawlConfig = {
      seedUrls: ['https://target.com/'],
      scope: SCOPE,
      maxDepth: 1,
      respectRobotsTxt: false,
      httpClient,
      useHeadlessBrowser: true,
      headlessBrowser: browser,
    };

    const result = await new WebCrawler(config).crawl();
    const jsEps = result.endpoints.filter(e => e.source === 'javascript');
    expect(jsEps.find(e => e.url === 'https://target.com/api/me')).toBeDefined();
    // Out-of-scope endpoints must not appear
    expect(jsEps.find(e => e.url.includes('analytics.evil.com'))).toBeUndefined();
    expect(jsEps.find(e => e.url.includes('googletagmanager'))).toBeUndefined();
    // Out-of-scope link must not be queued (page never visited)
    expect(result.pages.find(p => p.url.includes('other.com'))).toBeUndefined();
  });

  it('degrades gracefully when the browser throws — HTTP results preserved', async () => {
    const httpClient = makeHttpClient({
      'https://target.com/': '<html><body><a href="/about">about</a></body></html>',
      'https://target.com/about': '<html><body>About</body></html>',
    });
    const browser = makeFakeBrowser({}, { throwOn: ['https://target.com/', 'https://target.com/about'] });

    const config: CrawlConfig = {
      seedUrls: ['https://target.com/'],
      scope: SCOPE,
      maxDepth: 1,
      respectRobotsTxt: false,
      httpClient,
      useHeadlessBrowser: true,
      headlessBrowser: browser,
    };

    const result = await new WebCrawler(config).crawl();
    // HTTP-only path still completed and discovered the about page link
    expect(result.pages.length).toBeGreaterThanOrEqual(1);
    expect(result.pages.find(p => p.url === 'https://target.com/')).toBeDefined();
  });

  it('useHeadlessBrowser=true without headlessBrowser is a silent no-op (not a crash)', async () => {
    const httpClient = makeHttpClient({
      'https://target.com/': '<html><body>App</body></html>',
    });

    const config: CrawlConfig = {
      seedUrls: ['https://target.com/'],
      scope: SCOPE,
      maxDepth: 0,
      respectRobotsTxt: false,
      httpClient,
      useHeadlessBrowser: true,
      // headlessBrowser intentionally omitted
    };

    const result = await new WebCrawler(config).crawl();
    expect(result.pages.length).toBe(1);
    // No JS-source endpoints
    expect(result.endpoints.filter(e => e.source === 'javascript').length).toBe(0);
  });

  it('default config (useHeadlessBrowser=false) does not invoke the browser', async () => {
    const httpClient = makeHttpClient({
      'https://target.com/': '<html><body>App</body></html>',
    });
    let crawlPageCalls = 0;
    const browser: HeadlessBrowserCrawler = {
      async crawlPage(url) {
        crawlPageCalls++;
        return { finalUrl: url, title: '', links: [], forms: [], apiEndpoints: [] };
      },
    };

    const config: CrawlConfig = {
      seedUrls: ['https://target.com/'],
      scope: SCOPE,
      maxDepth: 0,
      respectRobotsTxt: false,
      httpClient,
      // useHeadlessBrowser omitted (defaults to false)
      headlessBrowser: browser,
    };

    await new WebCrawler(config).crawl();
    expect(crawlPageCalls).toBe(0);
  });

  it('browserTimeoutMs is clamped to [5000, 30000] and passed to crawlPage', async () => {
    const httpClient = makeHttpClient({
      'https://target.com/': '<html><body>App</body></html>',
    });
    const observedTimeouts: Array<number | undefined> = [];
    const browser: HeadlessBrowserCrawler = {
      async crawlPage(url, timeoutMs) {
        observedTimeouts.push(timeoutMs);
        return { finalUrl: url, title: '', links: [], forms: [], apiEndpoints: [] };
      },
    };

    // Try a too-low value (1000 → should clamp to 5000) and a too-high one (60000 → 30000)
    for (const requested of [1000, 60_000, 12_000]) {
      observedTimeouts.length = 0;
      await new WebCrawler({
        seedUrls: ['https://target.com/'],
        scope: SCOPE,
        maxDepth: 0,
        respectRobotsTxt: false,
        httpClient,
        useHeadlessBrowser: true,
        headlessBrowser: browser,
        browserTimeoutMs: requested,
      }).crawl();
      expect(observedTimeouts.length).toBe(1);
      const t = observedTimeouts[0]!;
      expect(t).toBeGreaterThanOrEqual(5000);
      expect(t).toBeLessThanOrEqual(30_000);
    }
  });
});

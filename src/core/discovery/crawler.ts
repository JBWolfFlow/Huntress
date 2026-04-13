/**
 * Web Crawler & Attack Surface Mapper (Phase 20B)
 *
 * BFS crawler that discovers all testable endpoints, forms, scripts,
 * and technologies on an in-scope target. Feeds the AttackSurfaceMap
 * into the orchestrator's task queue so agents know exactly what to test.
 *
 * Key features:
 * - BFS crawl with configurable depth and page limits
 * - robots.txt respect
 * - Scope enforcement on every discovered URL
 * - Form extraction with input field analysis
 * - Technology fingerprinting from headers/meta/scripts
 * - Link normalization to avoid duplicate visits
 */

import type { HttpClient, HttpResponse } from '../http/request_engine';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface CrawlConfig {
  seedUrls: string[];
  maxDepth?: number;
  maxPages?: number;
  scope: string[];
  respectRobotsTxt?: boolean;
  httpClient: HttpClient;
}

export interface CrawlResult {
  pages: DiscoveredPage[];
  forms: DiscoveredForm[];
  endpoints: DiscoveredEndpoint[];
  scripts: DiscoveredScript[];
  technologies: string[];
  totalRequests: number;
  durationMs: number;
}

export interface DiscoveredPage {
  url: string;
  title: string;
  statusCode: number;
  contentType: string;
  links: string[];
  depth: number;
}

export interface DiscoveredForm {
  action: string;
  method: string;
  inputs: Array<{ name: string; type: string; value?: string }>;
  pageUrl: string;
}

export interface DiscoveredEndpoint {
  url: string;
  method: string;
  source: 'html' | 'javascript' | 'robots' | 'sitemap' | 'param_miner' | 'openapi' | 'graphql';
  parameters: string[];
  contentType?: string;
}

export interface DiscoveredScript {
  url: string;
  inline: boolean;
  content?: string;
  pageUrl: string;
}

// ─── Robots.txt Parser ──────────────────────────────────────────────────────

class RobotsParser {
  private disallowRules: string[] = [];
  private sitemapUrls: string[] = [];

  parse(content: string): void {
    let relevantSection = false;
    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim();
      if (/^user-agent:\s*\*/i.test(line)) {
        relevantSection = true;
      } else if (/^user-agent:/i.test(line)) {
        relevantSection = false;
      } else if (relevantSection && /^disallow:\s*/i.test(line)) {
        const path = line.replace(/^disallow:\s*/i, '').trim();
        if (path) this.disallowRules.push(path);
      } else if (/^sitemap:\s*/i.test(line)) {
        const url = line.replace(/^sitemap:\s*/i, '').trim();
        if (url) this.sitemapUrls.push(url);
      }
    }
  }

  isAllowed(path: string): boolean {
    for (const rule of this.disallowRules) {
      if (rule === '/') return false;
      if (path.startsWith(rule)) return false;
      // Wildcard support
      if (rule.includes('*')) {
        const pattern = rule.replace(/\*/g, '.*');
        if (new RegExp(`^${pattern}`).test(path)) return false;
      }
    }
    return true;
  }

  getSitemapUrls(): string[] {
    return [...this.sitemapUrls];
  }
}

// ─── URL Normalization ──────────────────────────────────────────────────────

function normalizeUrl(url: string, baseUrl: string): string | null {
  try {
    const resolved = new URL(url, baseUrl);
    // Remove fragment
    resolved.hash = '';
    // Remove trailing slash for consistency (except root)
    let normalized = resolved.toString();
    if (normalized.endsWith('/') && resolved.pathname !== '/') {
      normalized = normalized.slice(0, -1);
    }
    return normalized;
  } catch {
    return null;
  }
}

function isInScope(url: string, scope: string[]): boolean {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();

    for (const entry of scope) {
      const scopeLower = entry.toLowerCase();
      if (hostname === scopeLower) return true;
      if (scopeLower.startsWith('*.') && hostname.endsWith(scopeLower.slice(1))) return true;
      if (hostname.endsWith('.' + scopeLower)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

// ─── HTML Extractors ────────────────────────────────────────────────────────

function extractLinks(html: string, pageUrl: string): string[] {
  const links: string[] = [];
  // <a href="...">
  const hrefPattern = /<a\s[^>]*?href\s*=\s*["']([^"'#][^"']*)["']/gi;
  let match: RegExpExecArray | null;
  while ((match = hrefPattern.exec(html)) !== null) {
    const normalized = normalizeUrl(match[1], pageUrl);
    if (normalized) links.push(normalized);
  }
  return links;
}

function extractTitle(html: string): string {
  const titleMatch = /<title[^>]*>([^<]*)<\/title>/i.exec(html);
  return titleMatch ? titleMatch[1].trim() : '';
}

function extractForms(html: string, pageUrl: string): DiscoveredForm[] {
  const forms: DiscoveredForm[] = [];
  const formPattern = /<form\s[^>]*?>([\s\S]*?)<\/form>/gi;
  let formMatch: RegExpExecArray | null;

  while ((formMatch = formPattern.exec(html)) !== null) {
    const formTag = formMatch[0];
    const formBody = formMatch[1];

    // Extract action
    const actionMatch = /action\s*=\s*["']([^"']*)["']/i.exec(formTag);
    const rawAction = actionMatch ? actionMatch[1] : pageUrl;
    const action = normalizeUrl(rawAction, pageUrl) ?? pageUrl;

    // Extract method
    const methodMatch = /method\s*=\s*["']([^"']*)["']/i.exec(formTag);
    const method = (methodMatch ? methodMatch[1] : 'GET').toUpperCase();

    // Extract inputs
    const inputs: Array<{ name: string; type: string; value?: string }> = [];
    const inputPattern = /<(?:input|textarea|select)\s[^>]*?(?:name\s*=\s*["']([^"']*)["'])[^>]*?>/gi;
    let inputMatch: RegExpExecArray | null;

    while ((inputMatch = inputPattern.exec(formBody)) !== null) {
      const name = inputMatch[1];
      if (!name) continue;

      const typeMatch = /type\s*=\s*["']([^"']*)["']/i.exec(inputMatch[0]);
      const valueMatch = /value\s*=\s*["']([^"']*)["']/i.exec(inputMatch[0]);

      inputs.push({
        name,
        type: typeMatch ? typeMatch[1].toLowerCase() : 'text',
        value: valueMatch ? valueMatch[1] : undefined,
      });
    }

    if (inputs.length > 0 || action !== pageUrl) {
      forms.push({ action, method, inputs, pageUrl });
    }
  }

  return forms;
}

function extractScripts(html: string, pageUrl: string): DiscoveredScript[] {
  const scripts: DiscoveredScript[] = [];
  const scriptPattern = /<script\s[^>]*?src\s*=\s*["']([^"']*)["'][^>]*?>/gi;
  let match: RegExpExecArray | null;

  while ((match = scriptPattern.exec(html)) !== null) {
    const url = normalizeUrl(match[1], pageUrl);
    if (url) {
      scripts.push({ url, inline: false, pageUrl });
    }
  }

  // Inline scripts (>200 chars to skip trivial snippets)
  const inlinePattern = /<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi;
  while ((match = inlinePattern.exec(html)) !== null) {
    const content = match[1].trim();
    if (content.length > 200 && !match[0].includes('src=')) {
      scripts.push({ url: pageUrl, inline: true, content, pageUrl });
    }
  }

  return scripts;
}

// ─── Technology Detection ───────────────────────────────────────────────────

function detectTechnologies(response: HttpResponse, html: string): string[] {
  const techs: string[] = [];
  const headers = response.headers;

  // Server header
  const server = headers['server'] ?? headers['Server'] ?? '';
  if (server) {
    if (/nginx/i.test(server)) techs.push('Nginx');
    if (/apache/i.test(server)) techs.push('Apache');
    if (/IIS/i.test(server)) techs.push('IIS');
    if (/cloudflare/i.test(server)) techs.push('Cloudflare');
  }

  // Framework headers
  if (headers['x-powered-by']) {
    const xpb = headers['x-powered-by'];
    if (/express/i.test(xpb)) techs.push('Express.js');
    if (/php/i.test(xpb)) techs.push('PHP');
    if (/asp\.net/i.test(xpb)) techs.push('ASP.NET');
    if (/next/i.test(xpb)) techs.push('Next.js');
  }
  if (headers['x-aspnet-version']) techs.push('ASP.NET');
  if (headers['x-drupal-cache']) techs.push('Drupal');

  // CDN / WAF headers
  if (headers['cf-ray']) techs.push('Cloudflare');
  if (headers['x-amz-cf-id']) techs.push('AWS CloudFront');
  if (headers['x-cache'] && /cloudfront/i.test(headers['x-cache'])) techs.push('AWS CloudFront');

  // HTML content checks
  if (/react/i.test(html) || /data-reactroot/i.test(html) || /__NEXT_DATA__/i.test(html)) techs.push('React');
  if (/ng-app|ng-controller|angular/i.test(html)) techs.push('Angular');
  if (/vue\.|v-bind|v-on|v-if/i.test(html)) techs.push('Vue.js');
  if (/jquery|jQuery/i.test(html)) techs.push('jQuery');
  if (/wp-content|wordpress/i.test(html)) techs.push('WordPress');
  if (/content="WordPress/i.test(html)) techs.push('WordPress');
  if (/Drupal\.settings/i.test(html)) techs.push('Drupal');
  if (/laravel|csrf-token.*content/i.test(html)) techs.push('Laravel');
  if (/rails|csrf-meta-tags/i.test(html)) techs.push('Ruby on Rails');
  if (/django|csrfmiddlewaretoken/i.test(html)) techs.push('Django');

  // Deduplicate
  return [...new Set(techs)];
}

// ─── WebCrawler ─────────────────────────────────────────────────────────────

export class WebCrawler {
  private config: CrawlConfig;
  private visited: Set<string> = new Set();
  private queue: Array<{ url: string; depth: number }> = [];
  private pages: DiscoveredPage[] = [];
  private forms: DiscoveredForm[] = [];
  private endpoints: DiscoveredEndpoint[] = [];
  private scripts: DiscoveredScript[] = [];
  private allTechnologies: Set<string> = new Set();
  private robots: RobotsParser = new RobotsParser();
  private stopped = false;
  private requestCount = 0;
  private maxDepth: number;
  private maxPages: number;
  private respectRobots: boolean;

  constructor(config: CrawlConfig) {
    this.config = config;
    this.maxDepth = config.maxDepth ?? 3;
    this.maxPages = config.maxPages ?? 500;
    this.respectRobots = config.respectRobotsTxt !== false;
  }

  async crawl(): Promise<CrawlResult> {
    const startTime = Date.now();

    // Seed the queue
    for (const seed of this.config.seedUrls) {
      if (isInScope(seed, this.config.scope)) {
        this.queue.push({ url: seed, depth: 0 });
      }
    }

    // Fetch robots.txt for each unique origin
    if (this.respectRobots) {
      const origins = new Set(this.config.seedUrls.map(u => {
        try { return new URL(u).origin; } catch { return null; }
      }).filter(Boolean) as string[]);

      for (const origin of origins) {
        await this.fetchRobotsTxt(origin);
      }
    }

    // BFS crawl
    while (this.queue.length > 0 && this.pages.length < this.maxPages && !this.stopped) {
      const item = this.queue.shift();
      if (!item) break;

      const { url, depth } = item;

      // Skip if already visited
      if (this.visited.has(url)) continue;
      this.visited.add(url);

      // Skip if too deep
      if (depth > this.maxDepth) continue;

      // Check robots.txt
      if (this.respectRobots) {
        try {
          const path = new URL(url).pathname;
          if (!this.robots.isAllowed(path)) continue;
        } catch { continue; }
      }

      // Fetch the page
      try {
        const response = await this.config.httpClient.request({
          url,
          method: 'GET',
          timeoutMs: 15000,
        });
        this.requestCount++;

        const contentType = response.headers['content-type'] ?? '';
        const isHtml = contentType.includes('text/html') || contentType.includes('application/xhtml');

        if (!isHtml && !contentType.includes('text/')) continue;

        const body = response.body;

        // Extract page info
        const links = extractLinks(body, url);
        this.pages.push({
          url,
          title: extractTitle(body),
          statusCode: response.status,
          contentType,
          links,
          depth,
        });

        // Extract forms
        const pageForms = extractForms(body, url);
        this.forms.push(...pageForms);

        // Extract scripts
        const pageScripts = extractScripts(body, url);
        this.scripts.push(...pageScripts);

        // Detect technologies
        const techs = detectTechnologies(response, body);
        for (const t of techs) this.allTechnologies.add(t);

        // Add form action URLs as endpoints
        for (const form of pageForms) {
          const params = form.inputs.map(i => i.name);
          this.endpoints.push({
            url: form.action,
            method: form.method,
            source: 'html',
            parameters: params,
            contentType: form.method === 'POST' ? 'application/x-www-form-urlencoded' : undefined,
          });
        }

        // Queue discovered links
        for (const link of links) {
          if (!this.visited.has(link) && isInScope(link, this.config.scope)) {
            this.queue.push({ url: link, depth: depth + 1 });
          }
        }

        // Extract query parameters from links as endpoints
        for (const link of links) {
          try {
            const parsed = new URL(link);
            const params = Array.from(parsed.searchParams.keys());
            if (params.length > 0) {
              const base = `${parsed.origin}${parsed.pathname}`;
              const existing = this.endpoints.find(e => e.url === base && e.source === 'html');
              if (!existing) {
                this.endpoints.push({
                  url: base,
                  method: 'GET',
                  source: 'html',
                  parameters: params,
                });
              }
            }
          } catch { /* invalid URL */ }
        }

      } catch {
        // Request failed — skip this page
      }
    }

    return {
      pages: this.pages,
      forms: this.forms,
      endpoints: this.deduplicateEndpoints(),
      scripts: this.scripts,
      technologies: [...this.allTechnologies],
      totalRequests: this.requestCount,
      durationMs: Date.now() - startTime,
    };
  }

  stop(): void {
    this.stopped = true;
  }

  getProgress(): { visited: number; queued: number; depth: number } {
    const maxDepthVisited = this.pages.reduce((max, p) => Math.max(max, p.depth), 0);
    return {
      visited: this.visited.size,
      queued: this.queue.length,
      depth: maxDepthVisited,
    };
  }

  private async fetchRobotsTxt(origin: string): Promise<void> {
    try {
      const response = await this.config.httpClient.request({
        url: `${origin}/robots.txt`,
        method: 'GET',
        timeoutMs: 5000,
      });
      this.requestCount++;
      if (response.status === 200) {
        this.robots.parse(response.body);
        // Add sitemap URLs to queue
        for (const sitemapUrl of this.robots.getSitemapUrls()) {
          if (isInScope(sitemapUrl, this.config.scope)) {
            this.queue.push({ url: sitemapUrl, depth: 0 });
          }
        }
      }
    } catch {
      // robots.txt not available — allow all
    }
  }

  private deduplicateEndpoints(): DiscoveredEndpoint[] {
    const seen = new Map<string, DiscoveredEndpoint>();
    for (const ep of this.endpoints) {
      const key = `${ep.method}:${ep.url}`;
      const existing = seen.get(key);
      if (existing) {
        // Merge parameters
        const allParams = new Set([...existing.parameters, ...ep.parameters]);
        existing.parameters = [...allParams];
      } else {
        seen.set(key, { ...ep });
      }
    }
    return [...seen.values()];
  }
}

export default WebCrawler;

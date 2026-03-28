/**
 * OAuth Discovery Engine
 * 
 * Phase 1: Discovers OAuth endpoints using multiple techniques:
 * - Wayback Machine historical data
 * - Common OAuth patterns
 * - JavaScript file analysis
 * - Well-known endpoints
 */

import axios from 'axios';
import { tauriFetch } from '../../core/tauri_bridge';

function checkIsTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

async function proxyGet(url: string, config?: { headers?: Record<string, string>; maxRedirects?: number; timeout?: number; validateStatus?: () => boolean }): Promise<{ status: number; headers: Record<string, string>; data: string }> {
  if (checkIsTauri()) {
    const resp = await tauriFetch(url, { method: 'GET', headers: config?.headers, followRedirects: (config?.maxRedirects ?? 0) > 0, timeoutMs: config?.timeout ?? 10000 });
    return { status: resp.status, headers: resp.headers, data: resp.body };
  }
  const resp = await axios.get(url, config);
  return { status: resp.status, headers: resp.headers as Record<string, string>, data: typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data) };
}

async function proxyHead(url: string, config?: { headers?: Record<string, string>; maxRedirects?: number; timeout?: number; validateStatus?: (status: number) => boolean }): Promise<{ status: number; headers: Record<string, string>; data: string }> {
  if (checkIsTauri()) {
    // Tauri backend does not have a dedicated HEAD; use GET and ignore body
    const resp = await tauriFetch(url, { method: 'GET', headers: config?.headers, followRedirects: (config?.maxRedirects ?? 0) > 0, timeoutMs: config?.timeout ?? 10000 });
    return { status: resp.status, headers: resp.headers, data: resp.body };
  }
  const resp = await axios.head(url, config);
  return { status: resp.status, headers: resp.headers as Record<string, string>, data: '' };
}

/** Result of executing a shell command via Tauri PTY backend */
export interface CommandExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/** Callback type for executing commands via the Tauri PTY backend */
export type CommandExecutor = (
  command: string,
  args: string[],
  timeoutMs: number,
) => Promise<CommandExecResult>;

export interface OAuthEndpoint {
  url: string;
  type: 'authorization' | 'token' | 'userinfo' | 'jwks' | 'discovery';
  discoveryMethod: string;
  confidence: number;
  metadata?: Record<string, any>;
}

export interface DiscoveryConfig {
  target: string;
  timeout: number;
  maxEndpoints: number;
  useWayback: boolean;
  useNuclei: boolean;
  /** Optional command executor for running external tools (waybackurls, nuclei) via PTY */
  commandExecutor?: CommandExecutor;
}

export class OAuthDiscovery {
  private config: DiscoveryConfig;
  private endpoints: Map<string, OAuthEndpoint> = new Map();

  constructor(config: DiscoveryConfig) {
    this.config = config;
  }

  /**
   * Main discovery orchestrator
   */
  async discover(): Promise<OAuthEndpoint[]> {
    console.log(`[OAuth Discovery] Starting discovery for ${this.config.target}`);

    // Run all discovery methods in parallel
    const results = await Promise.allSettled([
      this.discoverWellKnown(),
      this.discoverCommonPaths(),
      this.config.useWayback ? this.discoverFromWayback() : Promise.resolve([]),
      this.config.useNuclei ? this.discoverWithNuclei() : Promise.resolve([]),
      this.discoverFromJavaScript(),
    ]);

    // Collect all successful results
    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        result.value.forEach(endpoint => this.addEndpoint(endpoint));
      } else {
        console.warn(`[OAuth Discovery] Method ${index} failed:`, result.reason);
      }
    });

    const discovered = Array.from(this.endpoints.values())
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, this.config.maxEndpoints);

    console.log(`[OAuth Discovery] Found ${discovered.length} unique endpoints`);
    return discovered;
  }

  /**
   * Check well-known OAuth discovery endpoints
   */
  private async discoverWellKnown(): Promise<OAuthEndpoint[]> {
    const endpoints: OAuthEndpoint[] = [];
    const wellKnownPaths = [
      '/.well-known/openid-configuration',
      '/.well-known/oauth-authorization-server',
      '/.well-known/openid-connect',
    ];

    for (const path of wellKnownPaths) {
      try {
        const url = `https://${this.config.target}${path}`;
        const response = await proxyGet(url, {
          timeout: this.config.timeout,
          validateStatus: () => true,
        });

        if (response.status !== 200) continue;

        if (response.data) {
          // Parse OpenID Connect discovery document
          const config = typeof response.data === 'string' ? JSON.parse(response.data) : response.data;
          
          if (config.authorization_endpoint) {
            endpoints.push({
              url: config.authorization_endpoint,
              type: 'authorization',
              discoveryMethod: 'well-known',
              confidence: 100,
              metadata: config,
            });
          }

          if (config.token_endpoint) {
            endpoints.push({
              url: config.token_endpoint,
              type: 'token',
              discoveryMethod: 'well-known',
              confidence: 100,
              metadata: config,
            });
          }

          if (config.userinfo_endpoint) {
            endpoints.push({
              url: config.userinfo_endpoint,
              type: 'userinfo',
              discoveryMethod: 'well-known',
              confidence: 100,
              metadata: config,
            });
          }

          if (config.jwks_uri) {
            endpoints.push({
              url: config.jwks_uri,
              type: 'jwks',
              discoveryMethod: 'well-known',
              confidence: 100,
              metadata: config,
            });
          }
        }
      } catch (error) {
        // Endpoint doesn't exist, continue
      }
    }

    return endpoints;
  }

  /**
   * Check common OAuth endpoint patterns
   */
  private async discoverCommonPaths(): Promise<OAuthEndpoint[]> {
    const endpoints: OAuthEndpoint[] = [];
    const commonPaths = [
      // Authorization endpoints
      '/oauth/authorize',
      '/oauth2/authorize',
      '/auth/oauth/authorize',
      '/api/oauth/authorize',
      '/connect/authorize',
      '/oauth/v2/authorize',
      
      // Token endpoints
      '/oauth/token',
      '/oauth2/token',
      '/auth/oauth/token',
      '/api/oauth/token',
      '/connect/token',
      '/oauth/v2/token',
      
      // User info
      '/oauth/userinfo',
      '/oauth2/userinfo',
      '/api/oauth/userinfo',
      '/connect/userinfo',
      
      // Other common paths
      '/oauth/callback',
      '/oauth2/callback',
      '/auth/callback',
    ];

    const checkPromises = commonPaths.map(async (path) => {
      try {
        const url = `https://${this.config.target}${path}`;
        const response = await proxyHead(url, {
          timeout: this.config.timeout,
          validateStatus: (status: number) => status < 500, // Accept redirects and client errors
          maxRedirects: 0,
        });

        // If we get a response (not 404/500), it likely exists
        if (response.status < 500) {
          const type = this.inferEndpointType(path);
          endpoints.push({
            url,
            type,
            discoveryMethod: 'common-paths',
            confidence: 70,
            metadata: {
              statusCode: response.status,
              headers: response.headers,
            },
          });
        }
      } catch (error) {
        // Endpoint doesn't exist or network error
      }
    });

    await Promise.allSettled(checkPromises);
    return endpoints;
  }

  /**
   * Discover OAuth endpoints from Wayback Machine via waybackurls tool
   */
  private async discoverFromWayback(): Promise<OAuthEndpoint[]> {
    const endpoints: OAuthEndpoint[] = [];

    if (!this.config.commandExecutor) {
      console.log('[OAuth Discovery] Wayback discovery skipped (no command executor available)');
      return endpoints;
    }

    try {
      console.log(`[OAuth Discovery] Running waybackurls for ${this.config.target}`);

      // Step 1: Run waybackurls to get historical URLs — explicit argv, no shell interpolation
      const waybackResult = await this.config.commandExecutor(
        'waybackurls',
        [this.config.target],
        this.config.timeout,
      );

      if (waybackResult.exitCode !== 0 || !waybackResult.stdout.trim()) {
        console.warn('[OAuth Discovery] waybackurls returned no results or failed');
        return endpoints;
      }

      // Step 2: Filter for OAuth-related URLs
      const oauthPattern = /oauth|authorize|token|connect|callback|redirect_uri|client_id|openid/i;
      const urls = waybackResult.stdout
        .split('\n')
        .filter(line => line.trim().length > 0)
        .filter(line => oauthPattern.test(line))
        .slice(0, 100); // Limit to 100 unique results

      // Deduplicate by removing query strings for uniqueness check
      const seen = new Set<string>();
      for (const rawUrl of urls) {
        try {
          const parsed = new URL(rawUrl.trim());
          const baseUrl = `${parsed.origin}${parsed.pathname}`;
          if (seen.has(baseUrl)) continue;
          seen.add(baseUrl);

          endpoints.push({
            url: rawUrl.trim(),
            type: this.inferEndpointType(rawUrl),
            discoveryMethod: 'wayback',
            confidence: 60,
            metadata: { source: 'wayback-machine' },
          });
        } catch {
          // Skip malformed URLs from wayback data
        }
      }

      console.log(`[OAuth Discovery] Found ${endpoints.length} OAuth endpoints from Wayback Machine`);
    } catch (error) {
      console.warn('[OAuth Discovery] Waybackurls failed:', error);
    }

    return endpoints;
  }

  /**
   * Discover OAuth endpoints using Nuclei templates
   */
  private async discoverWithNuclei(): Promise<OAuthEndpoint[]> {
    const endpoints: OAuthEndpoint[] = [];

    if (!this.config.commandExecutor) {
      console.log('[OAuth Discovery] Nuclei discovery skipped (no command executor available)');
      return endpoints;
    }

    try {
      console.log(`[OAuth Discovery] Running nuclei OAuth templates against ${this.config.target}`);

      // Run nuclei with OAuth misconfiguration templates — explicit argv, no shell interpolation
      const nucleiResult = await this.config.commandExecutor(
        'nuclei',
        [
          '-u', `https://${this.config.target}`,
          '-t', 'http/misconfiguration/oauth/',
          '-silent',
          '-jsonl',
          '-no-color',
        ],
        this.config.timeout,
      );

      if (nucleiResult.exitCode !== 0 && !nucleiResult.stdout.trim()) {
        console.warn('[OAuth Discovery] nuclei returned no results or failed');
        return endpoints;
      }

      // Parse JSON Lines output from nuclei
      const lines = nucleiResult.stdout
        .split('\n')
        .filter(line => line.trim().length > 0);

      for (const line of lines) {
        try {
          const finding = JSON.parse(line);
          const matchedUrl = finding['matched-at'] || finding.host || '';
          if (!matchedUrl) continue;

          endpoints.push({
            url: matchedUrl,
            type: this.inferEndpointType(matchedUrl),
            discoveryMethod: 'nuclei',
            confidence: 85,
            metadata: {
              templateId: finding['template-id'] || 'unknown',
              templateName: finding.info?.name || 'unknown',
              severity: finding.info?.severity || 'info',
              matcherName: finding['matcher-name'] || '',
            },
          });
        } catch {
          // Skip malformed JSON lines
        }
      }

      console.log(`[OAuth Discovery] Found ${endpoints.length} OAuth endpoints via Nuclei`);
    } catch (error) {
      console.warn('[OAuth Discovery] Nuclei failed:', error);
    }

    return endpoints;
  }

  /**
   * Discover OAuth endpoints from JavaScript files
   */
  private async discoverFromJavaScript(): Promise<OAuthEndpoint[]> {
    const endpoints: OAuthEndpoint[] = [];

    try {
      // Fetch main page to find JS files
      const response = await proxyGet(`https://${this.config.target}`, {
        timeout: this.config.timeout,
      });

      // Extract JS file URLs
      const jsRegex = /<script[^>]+src=["']([^"']+\.js)["']/gi;
      const jsFiles: string[] = [];
      let match;

      while ((match = jsRegex.exec(response.data)) !== null) {
        let jsUrl = match[1];
        if (jsUrl.startsWith('//')) {
          jsUrl = 'https:' + jsUrl;
        } else if (jsUrl.startsWith('/')) {
          jsUrl = `https://${this.config.target}${jsUrl}`;
        } else if (!jsUrl.startsWith('http')) {
          jsUrl = `https://${this.config.target}/${jsUrl}`;
        }
        jsFiles.push(jsUrl);
      }

      // Analyze each JS file for OAuth patterns
      const oauthRegex = /(https?:\/\/[^\s"']+(?:oauth|authorize|token|connect)[^\s"']*)/gi;
      
      for (const jsUrl of jsFiles.slice(0, 10)) { // Limit to first 10 JS files
        try {
          const jsResponse = await proxyGet(jsUrl, {
            timeout: this.config.timeout,
          });

          let jsMatch;
          while ((jsMatch = oauthRegex.exec(jsResponse.data)) !== null) {
            const url = jsMatch[1];
            endpoints.push({
              url,
              type: this.inferEndpointType(url),
              discoveryMethod: 'javascript',
              confidence: 75,
              metadata: {
                sourceFile: jsUrl,
              },
            });
          }
        } catch (error) {
          // Skip failed JS file
        }
      }

      console.log(`[OAuth Discovery] Found ${endpoints.length} endpoints from JavaScript`);
    } catch (error) {
      console.warn('[OAuth Discovery] JavaScript analysis failed:', error);
    }

    return endpoints;
  }

  /**
   * Infer endpoint type from URL
   */
  private inferEndpointType(url: string): OAuthEndpoint['type'] {
    const lowerUrl = url.toLowerCase();
    
    if (lowerUrl.includes('authorize')) return 'authorization';
    if (lowerUrl.includes('token')) return 'token';
    if (lowerUrl.includes('userinfo') || lowerUrl.includes('user-info')) return 'userinfo';
    if (lowerUrl.includes('jwks') || lowerUrl.includes('keys')) return 'jwks';
    if (lowerUrl.includes('discovery') || lowerUrl.includes('.well-known')) return 'discovery';
    
    return 'authorization'; // Default
  }

  /**
   * Add endpoint to collection (deduplicates)
   */
  private addEndpoint(endpoint: OAuthEndpoint): void {
    const existing = this.endpoints.get(endpoint.url);
    
    if (!existing || endpoint.confidence > existing.confidence) {
      this.endpoints.set(endpoint.url, endpoint);
    }
  }
}

export default OAuthDiscovery;
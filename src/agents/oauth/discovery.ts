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

// Note: exec operations should be moved to Tauri backend commands
// For now, these are stubbed to allow frontend compilation
const execAsync = async (command: string, options?: any): Promise<{ stdout: string; stderr: string }> => {
  console.warn('[OAuth Discovery] exec operations should be handled by Tauri backend');
  return { stdout: '', stderr: '' };
};

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
        const response = await axios.get(url, {
          timeout: this.config.timeout,
          validateStatus: (status) => status === 200,
        });

        if (response.data) {
          // Parse OpenID Connect discovery document
          const config = response.data;
          
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
        const response = await axios.head(url, {
          timeout: this.config.timeout,
          validateStatus: (status) => status < 500, // Accept redirects and client errors
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
   * Discover OAuth endpoints from Wayback Machine
   */
  private async discoverFromWayback(): Promise<OAuthEndpoint[]> {
    const endpoints: OAuthEndpoint[] = [];

    try {
      console.log('[OAuth Discovery] Wayback discovery disabled (requires Tauri backend implementation)');
      // TODO: Implement via Tauri command that calls waybackurls on the backend
      // const { stdout } = await execAsync(
      //   `echo "${this.config.target}" | waybackurls | grep -iE "(oauth|authorize|token|connect)" | sort -u | head -n 100`,
      //   { timeout: this.config.timeout }
      // );
    } catch (error) {
      console.warn('[OAuth Discovery] Waybackurls failed:', error);
    }

    return endpoints;
  }

  /**
   * Discover OAuth endpoints using Nuclei
   */
  private async discoverWithNuclei(): Promise<OAuthEndpoint[]> {
    const endpoints: OAuthEndpoint[] = [];

    try {
      console.log('[OAuth Discovery] Nuclei discovery disabled (requires Tauri backend implementation)');
      // TODO: Implement via Tauri command that calls nuclei on the backend
      // const { stdout } = await execAsync(
      //   `echo "https://${this.config.target}" | nuclei -t ~/nuclei-templates/http/misconfiguration/oauth/ -silent -json`,
      //   { timeout: this.config.timeout }
      // );
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
      const response = await axios.get(`https://${this.config.target}`, {
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
          const jsResponse = await axios.get(jsUrl, {
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
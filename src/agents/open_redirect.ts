/**
 * Open Redirect Hunter Agent
 * 
 * Specialized mini-agent for discovering open redirect vulnerabilities.
 * Tests URL parameters and headers for unvalidated redirects.
 * 
 * Common patterns:
 * - ?redirect=, ?url=, ?next=, ?return=
 * - X-Forwarded-Host header manipulation
 * - Protocol-relative URLs
 */

export interface OpenRedirectPayload {
  parameter: string;
  value: string;
  method: 'GET' | 'POST';
  location: 'query' | 'header' | 'body';
}

export interface OpenRedirectResult {
  vulnerable: boolean;
  url: string;
  payload: OpenRedirectPayload;
  redirectedTo?: string;
  severity: 'low' | 'medium' | 'high';
  evidence: string;
}

/**
 * Common redirect parameters to test
 */
const REDIRECT_PARAMS = [
  'redirect',
  'url',
  'next',
  'return',
  'returnTo',
  'return_to',
  'redirect_uri',
  'redirect_url',
  'continue',
  'dest',
  'destination',
  'redir',
  'out',
  'view',
  'target',
  'to',
  'goto',
  'link',
  'forward',
];

/**
 * Test payloads for open redirect detection
 */
const TEST_PAYLOADS = [
  'https://evil.com',
  '//evil.com',
  '///evil.com',
  'javascript:alert(1)',
  'data:text/html,<script>alert(1)</script>',
  '\\\\evil.com',
  '@evil.com',
];

export class OpenRedirectHunter {
  private baseUrl: string;
  private timeout: number;

  constructor(baseUrl: string, timeout: number = 5000) {
    this.baseUrl = baseUrl;
    this.timeout = timeout;
  }

  /**
   * Test a URL for open redirect vulnerabilities
   */
  async testUrl(url: string): Promise<OpenRedirectResult[]> {
    const results: OpenRedirectResult[] = [];

    // Test query parameters
    for (const param of REDIRECT_PARAMS) {
      for (const payload of TEST_PAYLOADS) {
        const result = await this.testParameter(url, param, payload);
        if (result) {
          results.push(result);
        }
      }
    }

    return results;
  }

  /**
   * Test a specific parameter with a payload
   */
  private async testParameter(
    url: string,
    parameter: string,
    payload: string
  ): Promise<OpenRedirectResult | null> {
    try {
      const testUrl = this.buildTestUrl(url, parameter, payload);
      
      // TODO: Implement actual HTTP request with redirect following disabled
      // This is a placeholder that would need proper implementation
      const response = await this.makeRequest(testUrl);

      if (this.isRedirect(response)) {
        const redirectLocation = this.getRedirectLocation(response);
        
        if (this.isExternalRedirect(redirectLocation)) {
          return {
            vulnerable: true,
            url: testUrl,
            payload: {
              parameter,
              value: payload,
              method: 'GET',
              location: 'query',
            },
            redirectedTo: redirectLocation,
            severity: this.calculateSeverity(payload, redirectLocation),
            evidence: `Redirects to external domain: ${redirectLocation}`,
          };
        }
      }

      return null;
    } catch (error) {
      console.error(`Error testing ${parameter} with ${payload}:`, error);
      return null;
    }
  }

  /**
   * Build test URL with parameter
   */
  private buildTestUrl(url: string, parameter: string, payload: string): string {
    const urlObj = new URL(url);
    urlObj.searchParams.set(parameter, payload);
    return urlObj.toString();
  }

  /**
   * Make HTTP request (placeholder)
   */
  private async makeRequest(url: string): Promise<any> {
    // TODO: Implement with fetch or axios
    // Should NOT follow redirects automatically
    return {
      status: 302,
      headers: {
        location: 'https://evil.com',
      },
    };
  }

  /**
   * Check if response is a redirect
   */
  private isRedirect(response: any): boolean {
    return response.status >= 300 && response.status < 400;
  }

  /**
   * Get redirect location from response
   */
  private getRedirectLocation(response: any): string {
    return response.headers.location || '';
  }

  /**
   * Check if redirect is to external domain
   */
  private isExternalRedirect(location: string): boolean {
    try {
      const baseHost = new URL(this.baseUrl).hostname;
      const redirectHost = new URL(location, this.baseUrl).hostname;
      return baseHost !== redirectHost;
    } catch {
      return false;
    }
  }

  /**
   * Calculate severity based on payload and redirect
   */
  private calculateSeverity(
    payload: string,
    redirectLocation: string
  ): 'low' | 'medium' | 'high' {
    if (payload.startsWith('javascript:') || payload.startsWith('data:')) {
      return 'high';
    }
    if (redirectLocation.includes('evil.com')) {
      return 'medium';
    }
    return 'low';
  }

  /**
   * Generate proof of concept
   */
  generatePoC(result: OpenRedirectResult): string {
    return `
# Open Redirect Vulnerability

**URL:** ${result.url}
**Parameter:** ${result.payload.parameter}
**Payload:** ${result.payload.value}
**Redirects To:** ${result.redirectedTo}
**Severity:** ${result.severity.toUpperCase()}

## Steps to Reproduce:
1. Navigate to: ${result.url}
2. Observe redirect to: ${result.redirectedTo}

## Impact:
Open redirects can be used for phishing attacks by making malicious URLs
appear to originate from a trusted domain.

## Recommendation:
Implement whitelist-based redirect validation or use relative URLs only.
    `.trim();
  }
}

export default OpenRedirectHunter;
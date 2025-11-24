/**
 * OAuth Hunter - Main Orchestrator
 *
 * Coordinates all OAuth vulnerability testing phases:
 * 1. Discovery - Find OAuth endpoints
 * 2. Redirect URI validation - Test redirect_uri vulnerabilities
 * 3. State validation - Test state parameter issues
 * 4. PKCE validation - Test PKCE implementation
 * 5. Scope validation - Test scope parameter vulnerabilities
 * 6. Report generation - Create detailed vulnerability reports
 */

import { OAuthDiscovery, OAuthEndpoint, DiscoveryConfig } from './discovery';
import { RedirectValidator, RedirectVulnerability, RedirectTestConfig } from './redirect_validator';
import { StateValidator, StateVulnerability, StateTestConfig } from './state_validator';
import { PKCEValidator, PKCEVulnerability, PKCETestConfig } from './pkce_validator';
import { ScopeValidator, ScopeVulnerability, ScopeTestConfig } from './scope_validator';

export interface OAuthHunterConfig {
  target: string;
  clientId?: string;
  redirectUri?: string;
  collaboratorUrl?: string;
  timeout?: number;
  maxEndpoints?: number;
  useWayback?: boolean;
  useNuclei?: boolean;
  knownScopes?: string[]; // Known valid scopes for scope testing
}

export interface OAuthVulnerability {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  endpoint: string;
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
  discoveredAt: Date;
  payload?: string;
}

export interface OAuthHuntResult {
  target: string;
  endpointsFound: number;
  vulnerabilities: OAuthVulnerability[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  duration: number;
}

export class OAuthHunter {
  private config: OAuthHunterConfig;
  private startTime: number = 0;

  constructor(config: OAuthHunterConfig) {
    this.config = {
      timeout: 30000,
      maxEndpoints: 1000,
      useWayback: true,
      useNuclei: true,
      ...config,
    };
  }

  /**
   * Main hunting orchestrator
   */
  async hunt(): Promise<OAuthHuntResult> {
    this.startTime = Date.now();
    console.log(`[OAuth Hunter] Starting hunt on ${this.config.target}`);

    // Phase 1: Discovery
    const endpoints = await this.discoverEndpoints();
    console.log(`[OAuth Hunter] Discovered ${endpoints.length} OAuth endpoints`);

    if (endpoints.length === 0) {
      return this.buildResult([], endpoints.length);
    }

    // Phase 2-5: Vulnerability Testing
    const vulnerabilities = await this.testEndpoints(endpoints);
    console.log(`[OAuth Hunter] Found ${vulnerabilities.length} vulnerabilities`);

    return this.buildResult(vulnerabilities, endpoints.length);
  }

  /**
   * Phase 1: Discover OAuth endpoints
   */
  private async discoverEndpoints(): Promise<OAuthEndpoint[]> {
    const discoveryConfig: DiscoveryConfig = {
      target: this.config.target,
      timeout: this.config.timeout!,
      maxEndpoints: this.config.maxEndpoints!,
      useWayback: this.config.useWayback!,
      useNuclei: this.config.useNuclei!,
    };

    const discovery = new OAuthDiscovery(discoveryConfig);
    return await discovery.discover();
  }

  /**
   * Phase 2-5: Test endpoints for vulnerabilities
   */
  private async testEndpoints(endpoints: OAuthEndpoint[]): Promise<OAuthVulnerability[]> {
    const allVulnerabilities: OAuthVulnerability[] = [];

    // Test authorization endpoints (most important)
    const authEndpoints = endpoints.filter(e => e.type === 'authorization');
    
    for (const endpoint of authEndpoints) {
      console.log(`[OAuth Hunter] Testing endpoint: ${endpoint.url}`);

      // Phase 2: Test redirect_uri vulnerabilities
      const redirectVulns = await this.testRedirectUri(endpoint);
      allVulnerabilities.push(...redirectVulns);

      // Phase 3: Test state parameter vulnerabilities
      const stateVulns = await this.testState(endpoint);
      allVulnerabilities.push(...stateVulns);

      // Phase 4: Test PKCE implementation
      const pkceVulns = await this.testPKCE(endpoint);
      allVulnerabilities.push(...pkceVulns);

      // Phase 5: Test scope parameter vulnerabilities
      const scopeVulns = await this.testScope(endpoint);
      allVulnerabilities.push(...scopeVulns);
    }

    return allVulnerabilities;
  }

  /**
   * Test redirect_uri vulnerabilities
   */
  private async testRedirectUri(endpoint: OAuthEndpoint): Promise<OAuthVulnerability[]> {
    const config: RedirectTestConfig = {
      endpoint,
      clientId: this.config.clientId,
      collaboratorUrl: this.config.collaboratorUrl,
      timeout: this.config.timeout!,
    };

    const validator = new RedirectValidator(config);
    const vulnerabilities = await validator.validate();

    return vulnerabilities.map(v => this.convertRedirectVuln(v));
  }

  /**
   * Test state parameter vulnerabilities
   */
  private async testState(endpoint: OAuthEndpoint): Promise<OAuthVulnerability[]> {
    const config: StateTestConfig = {
      endpoint,
      clientId: this.config.clientId,
      redirectUri: this.config.redirectUri,
      timeout: this.config.timeout!,
    };

    const validator = new StateValidator(config);
    const vulnerabilities = await validator.validate();

    return vulnerabilities.map(v => this.convertStateVuln(v));
  }

  /**
   * Convert redirect vulnerability to standard format
   */
  private convertRedirectVuln(vuln: RedirectVulnerability): OAuthVulnerability {
    return {
      id: this.generateVulnId(),
      type: `oauth_${vuln.type}`,
      severity: vuln.severity,
      endpoint: vuln.endpoint,
      description: vuln.description,
      evidence: vuln.evidence,
      impact: vuln.impact,
      remediation: vuln.remediation,
      discoveredAt: new Date(),
      payload: vuln.payload,
    };
  }

  /**
   * Test PKCE implementation
   */
  private async testPKCE(endpoint: OAuthEndpoint): Promise<OAuthVulnerability[]> {
    const config: PKCETestConfig = {
      endpoint,
      clientId: this.config.clientId,
      redirectUri: this.config.redirectUri,
      timeout: this.config.timeout!,
    };

    const validator = new PKCEValidator(config);
    const vulnerabilities = await validator.validate();

    return vulnerabilities.map(v => this.convertPKCEVuln(v));
  }

  /**
   * Test scope parameter vulnerabilities
   */
  private async testScope(endpoint: OAuthEndpoint): Promise<OAuthVulnerability[]> {
    const config: ScopeTestConfig = {
      endpoint,
      clientId: this.config.clientId,
      redirectUri: this.config.redirectUri,
      timeout: this.config.timeout!,
      knownScopes: this.config.knownScopes,
    };

    const validator = new ScopeValidator(config);
    const vulnerabilities = await validator.validate();

    return vulnerabilities.map(v => this.convertScopeVuln(v));
  }

  /**
   * Convert state vulnerability to standard format
   */
  private convertStateVuln(vuln: StateVulnerability): OAuthVulnerability {
    return {
      id: this.generateVulnId(),
      type: `oauth_${vuln.type}`,
      severity: vuln.severity,
      endpoint: vuln.endpoint,
      description: vuln.description,
      evidence: vuln.evidence,
      impact: vuln.impact,
      remediation: vuln.remediation,
      discoveredAt: new Date(),
    };
  }

  /**
   * Convert PKCE vulnerability to standard format
   */
  private convertPKCEVuln(vuln: PKCEVulnerability): OAuthVulnerability {
    return {
      id: this.generateVulnId(),
      type: `oauth_${vuln.type}`,
      severity: vuln.severity,
      endpoint: vuln.endpoint,
      description: vuln.description,
      evidence: vuln.evidence,
      impact: vuln.impact,
      remediation: vuln.remediation,
      discoveredAt: new Date(),
    };
  }

  /**
   * Convert scope vulnerability to standard format
   */
  private convertScopeVuln(vuln: ScopeVulnerability): OAuthVulnerability {
    return {
      id: this.generateVulnId(),
      type: `oauth_${vuln.type}`,
      severity: vuln.severity,
      endpoint: vuln.endpoint,
      description: vuln.description,
      evidence: vuln.evidence,
      impact: vuln.impact,
      remediation: vuln.remediation,
      discoveredAt: new Date(),
      payload: vuln.requestedScope,
    };
  }

  /**
   * Build final result
   */
  private buildResult(vulnerabilities: OAuthVulnerability[], endpointsFound: number): OAuthHuntResult {
    const summary = {
      critical: vulnerabilities.filter(v => v.severity === 'critical').length,
      high: vulnerabilities.filter(v => v.severity === 'high').length,
      medium: vulnerabilities.filter(v => v.severity === 'medium').length,
      low: vulnerabilities.filter(v => v.severity === 'low').length,
    };

    return {
      target: this.config.target,
      endpointsFound,
      vulnerabilities,
      summary,
      duration: Date.now() - this.startTime,
    };
  }

  /**
   * Generate unique vulnerability ID
   */
  private generateVulnId(): string {
    return `oauth_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Generate detailed report for a vulnerability
   */
  generateReport(vulnerability: OAuthVulnerability): string {
    return `
# OAuth Vulnerability Report

## Summary
- **ID**: ${vulnerability.id}
- **Type**: ${vulnerability.type}
- **Severity**: ${vulnerability.severity.toUpperCase()}
- **Discovered**: ${vulnerability.discoveredAt.toISOString()}

## Vulnerability Details

### Endpoint
\`\`\`
${vulnerability.endpoint}
\`\`\`

### Description
${vulnerability.description}

### Evidence
\`\`\`
${vulnerability.evidence}
\`\`\`

${vulnerability.payload ? `### Payload
\`\`\`
${vulnerability.payload}
\`\`\`
` : ''}

### Impact
${vulnerability.impact}

### Remediation
${vulnerability.remediation}

## References
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OAuth 2.0 Threat Model](https://datatracker.ietf.org/doc/html/rfc6819)
- [OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
    `.trim();
  }
}

// Export all types and classes
export * from './discovery';
export * from './redirect_validator';
export * from './state_validator';
export * from './pkce_validator';
export * from './scope_validator';
export default OAuthHunter;
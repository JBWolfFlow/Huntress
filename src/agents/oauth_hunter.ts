/**
 * OAuth Hunter Agent (Legacy Wrapper)
 *
 * This file maintains backward compatibility while delegating to the new modular implementation.
 * For new code, import from './oauth/' instead.
 *
 * @deprecated Use OAuthHunter from './oauth/index' for new implementations
 */

import { OAuthHunter as NewOAuthHunter, OAuthHunterConfig, OAuthVulnerability, OAuthHuntResult } from './oauth';

export interface OAuthConfig {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  redirectUri: string;
  scope: string[];
}

/**
 * Legacy OAuth Hunter class
 * @deprecated Use OAuthHunter from './oauth/index' instead
 */
export class OAuthHunter {
  private config: OAuthConfig;
  private newHunter: NewOAuthHunter;

  constructor(config: OAuthConfig) {
    this.config = config;
    
    // Extract target from authorization endpoint
    const target = new URL(config.authorizationEndpoint).hostname;
    
    // Initialize new modular hunter
    const hunterConfig: OAuthHunterConfig = {
      target,
      clientId: config.clientId,
      redirectUri: config.redirectUri,
    };
    
    this.newHunter = new NewOAuthHunter(hunterConfig);
  }

  /**
   * Test OAuth flow for vulnerabilities
   * @deprecated Use hunt() method from new OAuthHunter instead
   */
  async testOAuthFlow(): Promise<OAuthVulnerability[]> {
    const result = await this.newHunter.hunt();
    return result.vulnerabilities;
  }

  /**
   * Generate proof of concept for OAuth vulnerability
   */
  generatePoC(vuln: OAuthVulnerability): string {
    return this.newHunter.generateReport(vuln);
  }
}

// Re-export new implementation for direct use
export { NewOAuthHunter as OAuthHunterV2 };
export type { OAuthHunterConfig, OAuthVulnerability, OAuthHuntResult };
export default OAuthHunter;
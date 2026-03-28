/**
 * OAuth Scope Validator
 * 
 * Phase 5: Tests scope parameter for vulnerabilities:
 * - Elevated scope request testing
 * - Scope confusion attacks
 * - Missing scope validation detection
 * - Scope boundary testing
 * - Confidence scoring for findings
 */

import axios from 'axios';
import { tauriFetch } from '../../core/tauri_bridge';
import { OAuthEndpoint } from './discovery';

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

export interface ScopeVulnerability {
  type: 'scope_escalation' | 'scope_confusion' | 'missing_validation' | 'scope_boundary';
  severity: 'low' | 'medium' | 'high' | 'critical';
  endpoint: string;
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
  confidence: number; // 0-100
  requestedScope?: string;
  grantedScope?: string;
}

export interface ScopeTestConfig {
  endpoint: OAuthEndpoint;
  clientId?: string;
  redirectUri?: string;
  timeout: number;
  knownScopes?: string[]; // Known valid scopes for the application
}

export class ScopeValidator {
  private config: ScopeTestConfig;
  private vulnerabilities: ScopeVulnerability[] = [];

  constructor(config: ScopeTestConfig) {
    this.config = config;
  }

  /**
   * Main validation orchestrator
   */
  async validate(): Promise<ScopeVulnerability[]> {
    console.log(`[Scope Validator] Testing ${this.config.endpoint.url}`);

    await Promise.allSettled([
      this.testScopeEscalation(),
      this.testScopeConfusion(),
      this.testMissingValidation(),
      this.testScopeBoundaries(),
    ]);

    console.log(`[Scope Validator] Found ${this.vulnerabilities.length} vulnerabilities`);
    return this.vulnerabilities;
  }

  /**
   * Test for scope escalation vulnerabilities
   */
  private async testScopeEscalation(): Promise<void> {
    // Common elevated/privileged scopes
    const elevatedScopes = [
      // Admin scopes
      'admin',
      'admin:read',
      'admin:write',
      'superuser',
      'root',
      
      // Full access scopes
      'full_access',
      '*',
      'all',
      'everything',
      
      // Sensitive data scopes
      'user:email',
      'user:phone',
      'user:address',
      'user:ssn',
      'user:payment',
      'financial:read',
      'financial:write',
      
      // System scopes
      'system:read',
      'system:write',
      'api:full',
      'api:admin',
      
      // Cloud provider scopes
      'https://www.googleapis.com/auth/cloud-platform',
      'https://graph.microsoft.com/.default',
      'urn:microsoft:userinfo',
      
      // Common OAuth scopes
      'openid profile email offline_access',
      'read:user write:user delete:user',
    ];

    for (const scope of elevatedScopes) {
      try {
        const url = this.buildAuthUrl(scope);
        const response = await proxyGet(url.toString(), {
          timeout: this.config.timeout,
          maxRedirects: 0,
          validateStatus: () => true,
        });

        // Check if elevated scope is accepted
        if (response.status >= 200 && response.status < 400) {
          const location = response.headers['location'];
          const grantedScope = this.extractScopeFromResponse(response, location);
          
          // If the scope appears to be granted or not rejected
          if (this.isScopeGranted(scope, grantedScope, response)) {
            this.vulnerabilities.push({
              type: 'scope_escalation',
              severity: this.calculateEscalationSeverity(scope),
              endpoint: this.config.endpoint.url,
              description: `OAuth endpoint accepts elevated scope: ${scope}`,
              evidence: `Request: ${url.toString()}\nStatus: ${response.status}\nRequested scope: ${scope}\nGranted scope: ${grantedScope || 'unknown'}`,
              impact: 'Attacker may be able to request elevated privileges beyond intended access level, potentially gaining admin or sensitive data access.',
              remediation: 'Implement strict scope validation. Only allow scopes that are explicitly registered for the client. Reject requests with unauthorized scopes.',
              confidence: this.calculateEscalationConfidence(scope, grantedScope, response),
              requestedScope: scope,
              grantedScope: grantedScope || undefined,
            });
          }
        }
      } catch (error) {
        // Test failed, continue
      }
    }
  }

  /**
   * Test for scope confusion attacks
   */
  private async testScopeConfusion(): Promise<void> {
    const confusionPayloads = [
      // Delimiter confusion
      { scope: 'read write', desc: 'space delimiter' },
      { scope: 'read,write', desc: 'comma delimiter' },
      { scope: 'read;write', desc: 'semicolon delimiter' },
      { scope: 'read|write', desc: 'pipe delimiter' },
      { scope: 'read+write', desc: 'plus delimiter' },
      
      // Encoding confusion
      { scope: 'read%20write', desc: 'URL encoded space' },
      { scope: 'read%2Cwrite', desc: 'URL encoded comma' },
      { scope: 'read%00write', desc: 'null byte injection' },
      
      // Case confusion
      { scope: 'ADMIN', desc: 'uppercase' },
      { scope: 'AdMiN', desc: 'mixed case' },
      
      // Unicode confusion
      { scope: 'admin\u200B', desc: 'zero-width space' },
      { scope: '\u202Eadmin', desc: 'right-to-left override' },
      
      // Wildcard confusion
      { scope: 'read:*', desc: 'wildcard suffix' },
      { scope: '*:write', desc: 'wildcard prefix' },
      { scope: 'user:*:admin', desc: 'wildcard middle' },
      
      // Path traversal in scopes
      { scope: '../admin', desc: 'path traversal' },
      { scope: 'user/../../admin', desc: 'nested path traversal' },
      
      // Array/object injection
      { scope: '["admin"]', desc: 'JSON array' },
      { scope: '{"scope":"admin"}', desc: 'JSON object' },
    ];

    for (const { scope, desc } of confusionPayloads) {
      try {
        const url = this.buildAuthUrl(scope);
        const response = await proxyGet(url.toString(), {
          timeout: this.config.timeout,
          maxRedirects: 0,
          validateStatus: () => true,
        });

        // If malformed scope is accepted
        if (response.status >= 200 && response.status < 400) {
          const location = response.headers['location'];
          const grantedScope = this.extractScopeFromResponse(response, location);
          
          this.vulnerabilities.push({
            type: 'scope_confusion',
            severity: 'medium',
            endpoint: this.config.endpoint.url,
            description: `OAuth endpoint vulnerable to scope confusion: ${desc}`,
            evidence: `Malformed scope accepted: "${scope}"\nRequest: ${url.toString()}\nStatus: ${response.status}\nGranted scope: ${grantedScope || 'unknown'}`,
            impact: 'Scope parsing inconsistencies may allow attackers to bypass scope restrictions or gain unintended access.',
            remediation: 'Implement strict scope parsing and validation. Use consistent delimiters and reject malformed scope values.',
            confidence: 75,
            requestedScope: scope,
            grantedScope: grantedScope || undefined,
          });
        }
      } catch (error) {
        // Test failed, continue
      }
    }
  }

  /**
   * Test for missing scope validation
   */
  private async testMissingValidation(): Promise<void> {
    const testCases = [
      // Empty scope
      { scope: '', desc: 'empty scope' },
      
      // Invalid/nonsense scopes
      { scope: 'invalid_scope_xyz123', desc: 'invalid scope' },
      { scope: 'nonexistent', desc: 'nonexistent scope' },
      { scope: '!!!invalid!!!', desc: 'special characters' },
      
      // SQL injection attempts
      { scope: "' OR '1'='1", desc: 'SQL injection' },
      { scope: "admin' --", desc: 'SQL comment injection' },
      
      // XSS attempts
      { scope: '<script>alert(1)</script>', desc: 'XSS payload' },
      { scope: 'javascript:alert(1)', desc: 'JavaScript protocol' },
      
      // Command injection
      { scope: '`whoami`', desc: 'command injection backticks' },
      { scope: '$(whoami)', desc: 'command injection dollar' },
      
      // LDAP injection
      { scope: '*)(uid=*', desc: 'LDAP injection' },
    ];

    for (const { scope, desc } of testCases) {
      try {
        const url = this.buildAuthUrl(scope);
        const response = await proxyGet(url.toString(), {
          timeout: this.config.timeout,
          maxRedirects: 0,
          validateStatus: () => true,
        });

        // If invalid scope is accepted without error
        if (response.status >= 200 && response.status < 400) {
          const severity = desc.includes('injection') || desc.includes('XSS') ? 'high' : 'medium';
          
          this.vulnerabilities.push({
            type: 'missing_validation',
            severity,
            endpoint: this.config.endpoint.url,
            description: `OAuth endpoint lacks proper scope validation: ${desc}`,
            evidence: `Invalid scope accepted: "${scope}"\nRequest: ${url.toString()}\nStatus: ${response.status}`,
            impact: 'Missing scope validation may allow injection attacks or unauthorized access through malformed scope values.',
            remediation: 'Implement whitelist-based scope validation. Reject any scope that is not explicitly registered and valid.',
            confidence: 80,
            requestedScope: scope,
          });
        }
      } catch (error) {
        // Test failed, continue
      }
    }
  }

  /**
   * Test scope boundary violations
   */
  private async testScopeBoundaries(): Promise<void> {
    // Test excessive scope requests
    const excessiveScopes = [
      // Many scopes
      Array(50).fill('read').join(' '),
      Array(100).fill('scope').join(' '),
      
      // Very long scope string
      'a'.repeat(10000),
      'scope_' + 'x'.repeat(5000),
      
      // Nested/hierarchical scope abuse
      'user:profile:email:phone:address:payment:history:admin',
      'api:v1:v2:v3:admin:root:superuser',
    ];

    for (const scope of excessiveScopes) {
      try {
        const url = this.buildAuthUrl(scope);
        const response = await proxyGet(url.toString(), {
          timeout: this.config.timeout,
          maxRedirects: 0,
          validateStatus: () => true,
        });

        // If excessive scope is accepted
        if (response.status >= 200 && response.status < 400) {
          this.vulnerabilities.push({
            type: 'scope_boundary',
            severity: 'low',
            endpoint: this.config.endpoint.url,
            description: 'OAuth endpoint accepts excessive scope values',
            evidence: `Excessive scope accepted (length: ${scope.length})\nRequest: ${url.toString()}\nStatus: ${response.status}`,
            impact: 'Lack of scope boundary validation may lead to DoS or allow attackers to probe for valid scopes.',
            remediation: 'Implement scope length limits and maximum number of scopes per request. Reject excessive scope values.',
            confidence: 70,
            requestedScope: scope.substring(0, 100) + '...',
          });
          break; // Only report once
        }
      } catch (error) {
        // Test failed, continue
      }
    }

    // Test scope combination boundaries
    if (this.config.knownScopes && this.config.knownScopes.length > 0) {
      await this.testScopeCombinations();
    }
  }

  /**
   * Test various scope combinations
   */
  private async testScopeCombinations(): Promise<void> {
    if (!this.config.knownScopes || this.config.knownScopes.length === 0) {
      return;
    }

    // Test all scopes combined
    const allScopes = this.config.knownScopes.join(' ');
    
    try {
      const url = this.buildAuthUrl(allScopes);
      const response = await proxyGet(url.toString(), {
        timeout: this.config.timeout,
        maxRedirects: 0,
        validateStatus: () => true,
      });

      if (response.status >= 200 && response.status < 400) {
        const location = response.headers['location'];
        const grantedScope = this.extractScopeFromResponse(response, location);
        
        // Check if all scopes were granted
        if (grantedScope && this.config.knownScopes.every(s => grantedScope.includes(s))) {
          this.vulnerabilities.push({
            type: 'scope_boundary',
            severity: 'medium',
            endpoint: this.config.endpoint.url,
            description: 'OAuth endpoint grants all requested scopes without restriction',
            evidence: `All scopes granted: ${grantedScope}\nRequested: ${allScopes}`,
            impact: 'Application may grant excessive permissions when multiple scopes are requested together.',
            remediation: 'Implement scope combination validation. Some scope combinations should be mutually exclusive or require additional authorization.',
            confidence: 75,
            requestedScope: allScopes,
            grantedScope,
          });
        }
      }
    } catch (error) {
      // Test failed, continue
    }
  }

  /**
   * Build authorization URL with scope
   */
  private buildAuthUrl(scope: string): URL {
    const url = new URL(this.config.endpoint.url);
    url.searchParams.set('response_type', 'code');
    
    if (this.config.clientId) {
      url.searchParams.set('client_id', this.config.clientId);
    }
    
    if (this.config.redirectUri) {
      url.searchParams.set('redirect_uri', this.config.redirectUri);
    }
    
    url.searchParams.set('state', 'test_state_' + Date.now());
    url.searchParams.set('scope', scope);
    
    return url;
  }

  /**
   * Extract granted scope from response
   */
  private extractScopeFromResponse(response: any, location?: string): string | null {
    // Check redirect location
    if (location) {
      const scopeMatch = location.match(/scope=([^&]+)/);
      if (scopeMatch) {
        return decodeURIComponent(scopeMatch[1]);
      }
    }

    // Check response body
    if (typeof response.data === 'string') {
      const bodyMatch = response.data.match(/scope["\s:=]+([^"&\s<>]+)/);
      if (bodyMatch) {
        return bodyMatch[1];
      }
    }

    return null;
  }

  /**
   * Check if scope appears to be granted
   */
  private isScopeGranted(requestedScope: string, grantedScope: string | null, response: any): boolean {
    // If we got a successful response without explicit rejection
    if (response.status >= 200 && response.status < 400) {
      // Check for explicit error messages
      const responseText = typeof response.data === 'string' ? response.data.toLowerCase() : '';
      
      if (responseText.includes('invalid_scope') || 
          responseText.includes('unauthorized_scope') ||
          responseText.includes('scope not allowed')) {
        return false;
      }

      // If we have granted scope info, check if it matches
      if (grantedScope) {
        return grantedScope.includes(requestedScope) || 
               requestedScope.split(' ').some(s => grantedScope.includes(s));
      }

      // If no explicit rejection and successful status, assume granted
      return true;
    }

    return false;
  }

  /**
   * Calculate severity for scope escalation
   */
  private calculateEscalationSeverity(scope: string): 'low' | 'medium' | 'high' | 'critical' {
    const lowerScope = scope.toLowerCase();
    
    // Critical: admin, root, superuser, full access
    if (lowerScope.includes('admin') || 
        lowerScope.includes('root') || 
        lowerScope.includes('superuser') ||
        lowerScope === '*' ||
        lowerScope.includes('full_access')) {
      return 'critical';
    }
    
    // High: financial, payment, sensitive data
    if (lowerScope.includes('financial') ||
        lowerScope.includes('payment') ||
        lowerScope.includes('ssn') ||
        lowerScope.includes('system')) {
      return 'high';
    }
    
    // Medium: user data, write access
    if (lowerScope.includes('write') ||
        lowerScope.includes('delete') ||
        lowerScope.includes('email') ||
        lowerScope.includes('phone')) {
      return 'medium';
    }
    
    return 'low';
  }

  /**
   * Calculate confidence for scope escalation detection
   */
  private calculateEscalationConfidence(
    requestedScope: string,
    grantedScope: string | null,
    response: any
  ): number {
    let confidence = 70;

    // Higher confidence if we can confirm granted scope
    if (grantedScope) {
      if (grantedScope.includes(requestedScope)) {
        confidence += 20;
      } else if (requestedScope.split(' ').some(s => grantedScope.includes(s))) {
        confidence += 15;
      }
    }

    // Higher confidence for successful redirects
    if (response.status === 302 || response.status === 303) {
      confidence += 10;
    }

    // Lower confidence if response is ambiguous
    if (response.status === 200 && !grantedScope) {
      confidence -= 10;
    }

    return Math.min(Math.max(confidence, 50), 100);
  }
}

export default ScopeValidator;
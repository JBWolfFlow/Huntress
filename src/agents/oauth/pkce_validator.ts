/**
 * OAuth PKCE (Proof Key for Code Exchange) Validator
 * 
 * Phase 4: Tests PKCE implementation for vulnerabilities:
 * - Missing PKCE enforcement
 * - Weak code_verifier testing
 * - Downgrade attack detection (PKCE → non-PKCE)
 * - code_challenge manipulation
 * - Confidence scoring for findings
 */

import axios from 'axios';
import crypto from 'crypto';
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

async function proxyPost(url: string, body: string | Record<string, unknown>, config?: { headers?: Record<string, string>; timeout?: number; validateStatus?: () => boolean }): Promise<{ status: number; headers: Record<string, string>; data: string }> {
  if (checkIsTauri()) {
    const resp = await tauriFetch(url, { method: 'POST', body: typeof body === 'string' ? body : JSON.stringify(body), headers: config?.headers, followRedirects: false, timeoutMs: config?.timeout ?? 10000 });
    return { status: resp.status, headers: resp.headers, data: resp.body };
  }
  const resp = await axios.post(url, body, config);
  return { status: resp.status, headers: resp.headers as Record<string, string>, data: typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data) };
}

export interface PKCEVulnerability {
  type: 'missing_pkce' | 'weak_verifier' | 'downgrade_attack' | 'challenge_manipulation';
  severity: 'low' | 'medium' | 'high' | 'critical';
  endpoint: string;
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
  confidence: number; // 0-100
}

export interface PKCETestConfig {
  endpoint: OAuthEndpoint;
  clientId?: string;
  redirectUri?: string;
  timeout: number;
}

export class PKCEValidator {
  private config: PKCETestConfig;
  private vulnerabilities: PKCEVulnerability[] = [];

  constructor(config: PKCETestConfig) {
    this.config = config;
  }

  /**
   * Main validation orchestrator
   */
  async validate(): Promise<PKCEVulnerability[]> {
    console.log(`[PKCE Validator] Testing ${this.config.endpoint.url}`);

    await Promise.allSettled([
      this.testMissingPKCE(),
      this.testWeakVerifier(),
      this.testDowngradeAttack(),
      this.testChallengeManipulation(),
    ]);

    console.log(`[PKCE Validator] Found ${this.vulnerabilities.length} vulnerabilities`);
    return this.vulnerabilities;
  }

  /**
   * Test if PKCE is enforced for public clients
   */
  private async testMissingPKCE(): Promise<void> {
    try {
      // Test 1: Authorization request without PKCE parameters
      const url = this.buildAuthUrl();
      const response = await proxyGet(url.toString(), {
        timeout: this.config.timeout,
        maxRedirects: 0,
        validateStatus: () => true,
      });

      // If request succeeds without PKCE, it's vulnerable
      if (response.status >= 200 && response.status < 400) {
        const location = response.headers['location'];
        
        // Check if we get an authorization code without PKCE
        if (location && location.includes('code=')) {
          this.vulnerabilities.push({
            type: 'missing_pkce',
            severity: 'high',
            endpoint: this.config.endpoint.url,
            description: 'OAuth endpoint does not enforce PKCE for authorization code flow',
            evidence: `Authorization request without code_challenge succeeded:\n${url.toString()}\nStatus: ${response.status}\nLocation: ${location}`,
            impact: 'Public clients (mobile/SPA apps) are vulnerable to authorization code interception attacks. Attacker can steal authorization codes and exchange them for access tokens.',
            remediation: 'Enforce PKCE (RFC 7636) for all public clients. Require code_challenge parameter in authorization requests and validate code_verifier during token exchange.',
            confidence: 95,
          });
        }
      }

      // Test 2: Token exchange without code_verifier (if token endpoint is available)
      if (this.config.endpoint.metadata?.token_endpoint) {
        await this.testTokenExchangeWithoutVerifier(this.config.endpoint.metadata.token_endpoint);
      }
    } catch (error) {
      // Test failed, continue
    }
  }

  /**
   * Test token exchange without code_verifier
   */
  private async testTokenExchangeWithoutVerifier(tokenUrl: string): Promise<void> {
    try {
      const params = new URLSearchParams({
        grant_type: 'authorization_code',
        code: 'test_code_12345',
        redirect_uri: this.config.redirectUri || 'https://example.com/callback',
      });

      if (this.config.clientId) {
        params.set('client_id', this.config.clientId);
      }

      const response = await proxyPost(tokenUrl, params.toString(), {
        timeout: this.config.timeout,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        validateStatus: () => true,
      });

      // If token exchange works without code_verifier, PKCE is not enforced
      const parsedData = (() => { try { return JSON.parse(response.data); } catch { return null; } })();
      if (response.status === 200 || parsedData?.access_token) {
        this.vulnerabilities.push({
          type: 'missing_pkce',
          severity: 'critical',
          endpoint: tokenUrl,
          description: 'Token endpoint does not require code_verifier for authorization code exchange',
          evidence: `Token exchange without code_verifier succeeded:\nEndpoint: ${tokenUrl}\nStatus: ${response.status}`,
          impact: 'Authorization codes can be exchanged for tokens without PKCE verification, allowing code interception attacks.',
          remediation: 'Require and validate code_verifier parameter during token exchange for all authorization code grants.',
          confidence: 90,
        });
      }
    } catch (error) {
      // Test failed, continue
    }
  }

  /**
   * Test for weak code_verifier values
   */
  private async testWeakVerifier(): Promise<void> {
    const weakVerifiers = [
      // Too short
      'short',
      '12345678',
      'abcdefgh',
      
      // Predictable patterns
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      '11111111111111111111111111111111111111111111',
      'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqr',
      
      // Common/default values
      'test_verifier',
      'code_verifier',
      'default_verifier_value_12345678901234567890',
    ];

    for (const verifier of weakVerifiers) {
      try {
        const challenge = this.generateCodeChallenge(verifier, 'S256');
        const url = this.buildAuthUrl(challenge, 'S256');
        
        const response = await proxyGet(url.toString(), {
          timeout: this.config.timeout,
          maxRedirects: 0,
          validateStatus: () => true,
        });

        // If weak verifier is accepted, it's vulnerable
        if (response.status >= 200 && response.status < 400) {
          const confidence = this.calculateWeakVerifierConfidence(verifier);
          
          this.vulnerabilities.push({
            type: 'weak_verifier',
            severity: verifier.length < 32 ? 'high' : 'medium',
            endpoint: this.config.endpoint.url,
            description: 'OAuth endpoint accepts weak code_verifier values',
            evidence: `Weak verifier accepted: "${verifier}" (length: ${verifier.length})\nChallenge: ${challenge}\nRequest: ${url.toString()}`,
            impact: 'Weak code_verifier values can be brute-forced or predicted, undermining PKCE protection.',
            remediation: 'Enforce minimum code_verifier length of 43 characters with high entropy (RFC 7636 recommends 43-128 characters).',
            confidence,
          });
          break; // Only report once
        }
      } catch (error) {
        // Test failed, continue
      }
    }
  }

  /**
   * Test for PKCE downgrade attacks
   */
  private async testDowngradeAttack(): Promise<void> {
    try {
      // Test 1: Start with PKCE, then try without
      const verifier = this.generateCodeVerifier();
      const challenge = this.generateCodeChallenge(verifier, 'S256');
      
      // First request with PKCE
      const urlWithPKCE = this.buildAuthUrl(challenge, 'S256');
      const response1 = await proxyGet(urlWithPKCE.toString(), {
        timeout: this.config.timeout,
        maxRedirects: 0,
        validateStatus: () => true,
      });

      // Second request without PKCE (same session if possible)
      const urlWithoutPKCE = this.buildAuthUrl();
      const cookieHeader = response1.headers['set-cookie'];
      const extraHeaders: Record<string, string> = cookieHeader ? { 'Cookie': cookieHeader } : {};
      const response2 = await proxyGet(urlWithoutPKCE.toString(), {
        timeout: this.config.timeout,
        maxRedirects: 0,
        validateStatus: () => true,
        headers: extraHeaders,
      });

      // If both succeed, downgrade is possible
      if (response1.status < 400 && response2.status < 400) {
        this.vulnerabilities.push({
          type: 'downgrade_attack',
          severity: 'high',
          endpoint: this.config.endpoint.url,
          description: 'OAuth endpoint vulnerable to PKCE downgrade attack',
          evidence: `Request with PKCE: ${response1.status}\nRequest without PKCE: ${response2.status}\nBoth requests succeeded, allowing downgrade from PKCE to non-PKCE flow`,
          impact: 'Attacker can downgrade from secure PKCE flow to insecure non-PKCE flow, enabling authorization code interception.',
          remediation: 'Once PKCE is initiated, enforce it throughout the entire flow. Do not allow downgrade to non-PKCE.',
          confidence: 85,
        });
      }

      // Test 2: Try plain method downgrade (S256 → plain)
      await this.testPlainMethodDowngrade(verifier);
    } catch (error) {
      // Test failed, continue
    }
  }

  /**
   * Test downgrade from S256 to plain method
   */
  private async testPlainMethodDowngrade(verifier: string): Promise<void> {
    try {
      // Request with S256
      const challengeS256 = this.generateCodeChallenge(verifier, 'S256');
      const urlS256 = this.buildAuthUrl(challengeS256, 'S256');
      
      const response1 = await proxyGet(urlS256.toString(), {
        timeout: this.config.timeout,
        maxRedirects: 0,
        validateStatus: () => true,
      });

      // Try to use plain method with same verifier
      const urlPlain = this.buildAuthUrl(verifier, 'plain');
      const response2 = await proxyGet(urlPlain.toString(), {
        timeout: this.config.timeout,
        maxRedirects: 0,
        validateStatus: () => true,
      });

      if (response1.status < 400 && response2.status < 400) {
        this.vulnerabilities.push({
          type: 'downgrade_attack',
          severity: 'medium',
          endpoint: this.config.endpoint.url,
          description: 'OAuth endpoint allows downgrade from S256 to plain PKCE method',
          evidence: `S256 method accepted: ${response1.status}\nPlain method accepted: ${response2.status}`,
          impact: 'Attacker can downgrade from secure S256 hashing to plain text code_challenge, reducing security.',
          remediation: 'Only accept S256 method for code_challenge_method. Reject plain method (RFC 7636 Section 4.2).',
          confidence: 80,
        });
      }
    } catch (error) {
      // Test failed, continue
    }
  }

  /**
   * Test code_challenge manipulation
   */
  private async testChallengeManipulation(): Promise<void> {
    const verifier = this.generateCodeVerifier();
    
    const manipulations = [
      // Empty challenge
      { challenge: '', method: 'S256', desc: 'empty challenge' },
      
      // Invalid base64
      { challenge: 'invalid!!!base64', method: 'S256', desc: 'invalid base64' },
      
      // Wrong length
      { challenge: 'short', method: 'S256', desc: 'too short' },
      { challenge: 'a'.repeat(200), method: 'S256', desc: 'too long' },
      
      // Null bytes
      { challenge: 'test\x00challenge', method: 'S256', desc: 'null byte injection' },
      
      // SQL injection attempts
      { challenge: "' OR '1'='1", method: 'S256', desc: 'SQL injection' },
      
      // XSS attempts
      { challenge: '<script>alert(1)</script>', method: 'S256', desc: 'XSS payload' },
      
      // Path traversal
      { challenge: '../../../etc/passwd', method: 'S256', desc: 'path traversal' },
    ];

    for (const { challenge, method, desc } of manipulations) {
      try {
        const url = this.buildAuthUrl(challenge, method);
        const response = await proxyGet(url.toString(), {
          timeout: this.config.timeout,
          maxRedirects: 0,
          validateStatus: () => true,
        });

        // If malformed challenge is accepted, it's vulnerable
        if (response.status >= 200 && response.status < 400) {
          this.vulnerabilities.push({
            type: 'challenge_manipulation',
            severity: desc.includes('injection') || desc.includes('XSS') ? 'high' : 'medium',
            endpoint: this.config.endpoint.url,
            description: `OAuth endpoint accepts malformed code_challenge: ${desc}`,
            evidence: `Malformed challenge accepted: "${challenge}"\nMethod: ${method}\nRequest: ${url.toString()}\nStatus: ${response.status}`,
            impact: 'Improper validation of code_challenge parameter may lead to bypass or injection attacks.',
            remediation: 'Implement strict validation of code_challenge format and length according to RFC 7636.',
            confidence: 75,
          });
        }
      } catch (error) {
        // Test failed, continue
      }
    }
  }

  /**
   * Build authorization URL with optional PKCE parameters
   */
  private buildAuthUrl(codeChallenge?: string, codeChallengeMethod?: string): URL {
    const url = new URL(this.config.endpoint.url);
    url.searchParams.set('response_type', 'code');
    
    if (this.config.clientId) {
      url.searchParams.set('client_id', this.config.clientId);
    }
    
    if (this.config.redirectUri) {
      url.searchParams.set('redirect_uri', this.config.redirectUri);
    }
    
    url.searchParams.set('state', 'test_state_' + Date.now());
    url.searchParams.set('scope', 'openid profile email');
    
    if (codeChallenge) {
      url.searchParams.set('code_challenge', codeChallenge);
    }
    
    if (codeChallengeMethod) {
      url.searchParams.set('code_challenge_method', codeChallengeMethod);
    }
    
    return url;
  }

  /**
   * Generate cryptographically secure code_verifier
   */
  private generateCodeVerifier(): string {
    // RFC 7636: 43-128 characters, [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
    const length = 43 + Math.floor(Math.random() * 86); // 43-128
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    const randomBytes = crypto.randomBytes(length);
    
    let verifier = '';
    for (let i = 0; i < length; i++) {
      verifier += charset[randomBytes[i] % charset.length];
    }
    
    return verifier;
  }

  /**
   * Generate code_challenge from code_verifier
   */
  private generateCodeChallenge(verifier: string, method: string): string {
    if (method === 'plain') {
      return verifier;
    }
    
    // S256 method
    const hash = crypto.createHash('sha256').update(verifier).digest();
    return hash.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Calculate confidence score for weak verifier detection
   */
  private calculateWeakVerifierConfidence(verifier: string): number {
    let confidence = 100;
    
    // Reduce confidence based on verifier characteristics
    if (verifier.length < 20) {
      confidence -= 5;
    }
    
    // Check for repeated characters
    const uniqueChars = new Set(verifier).size;
    if (uniqueChars < verifier.length * 0.5) {
      confidence -= 10;
    }
    
    // Check for sequential patterns
    if (/abc|123|xyz/i.test(verifier)) {
      confidence -= 5;
    }
    
    return Math.max(confidence, 70);
  }
}

export default PKCEValidator;
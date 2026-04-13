/**
 * Hunt #7 Bug Fix — H24: OAuth Validators
 *
 * Tests that all 9 oauth_* finding types have registered validators and
 * those validators check for real exploitation evidence, not just HTTP 200.
 */

import { describe, it, expect } from 'vitest';
import { validateFinding } from '../core/validation/validator';
import type { ValidatorConfig } from '../core/validation/validator';
import type { ReactFinding } from '../core/engine/react_loop';

// ─── Test Fixtures ──────────────────────────────────────────────────────────

function makeOAuthFinding(vulnType: string, overrides: Partial<ReactFinding> = {}): ReactFinding {
  return {
    id: `oauth_test_${Date.now()}`,
    title: `OAuth ${vulnType} vulnerability`,
    vulnerabilityType: vulnType,
    severity: 'high',
    target: 'https://example.com/oauth/authorize?client_id=test&redirect_uri=https://app.com/callback&response_type=code&scope=read',
    description: `OAuth ${vulnType} detected`,
    evidence: ['OAuth endpoint accepts malicious request'],
    reproductionSteps: ['Step 1: Send modified OAuth request'],
    impact: 'Account takeover via OAuth flow manipulation',
    confidence: 60,
    discoveredAtIteration: 5,
    agentId: 'oauth-hunter',
    ...overrides,
  };
}

/** Mock executeCommand that returns a configurable HTTP response */
function makeConfig(response: string, exitCode = 0): ValidatorConfig {
  return {
    executeCommand: async (_command: string, _target: string) => ({
      success: exitCode === 0,
      stdout: response,
      stderr: '',
      exitCode,
      executionTimeMs: 100,
    }),
  };
}

// ─── All 9 OAuth Types Have Validators ──────────────────────────────────────

const OAUTH_TYPES = [
  'oauth_missing_state',
  'oauth_state_reuse',
  'oauth_weak_verifier',
  'oauth_challenge_manipulation',
  'oauth_downgrade_attack',
  'oauth_missing_validation',
  'oauth_scope_boundary',
  'oauth_scope_confusion',
  'oauth_scope_escalation',
];

describe('OAuth Validators (H24)', () => {
  describe('all 9 OAuth types have registered validators', () => {
    for (const type of OAUTH_TYPES) {
      it(`${type} has a validator (not "No validator available")`, async () => {
        const finding = makeOAuthFinding(type);
        // Use a config that returns a benign response
        const config = makeConfig('HTTP/1.1 200 OK\r\n\r\n<html>Login page</html>');
        const result = await validateFinding(finding, config);

        // Must NOT return the "no validator" error
        expect(result.error ?? '').not.toContain('No validator available');
        expect(result.validatorUsed).not.toBe('none');
        expect(result.validatorUsed).toContain('oauth');
      });
    }
  });

  describe('oauth_missing_state', () => {
    it('confirms when server accepts stateless OAuth request with redirect', async () => {
      const finding = makeOAuthFinding('oauth_missing_state', {
        target: 'https://example.com/oauth/authorize?client_id=test&redirect_uri=https://app.com/callback&response_type=code&state=abc123',
      });

      // Server responds with redirect containing auth code (accepted without state)
      const config = makeConfig(
        'HTTP/1.1 302 Found\r\nLocation: https://app.com/callback?code=AUTH_CODE_123\r\n\r\n'
      );

      const result = await validateFinding(finding, config);
      expect(result.confirmed).toBe(true);
      expect(result.validatorUsed).toBe('oauth_missing_state');
      expect(result.confidence).toBeGreaterThan(60);
      expect(result.evidence.length).toBeGreaterThan(0);
    });

    it('rejects when server requires state parameter (returns 400)', async () => {
      const finding = makeOAuthFinding('oauth_missing_state');
      const config = makeConfig(
        'HTTP/1.1 400 Bad Request\r\n\r\n{"error":"invalid_request","error_description":"state parameter required"}'
      );

      const result = await validateFinding(finding, config);
      expect(result.confirmed).toBe(false);
      expect(result.confidence).toBeLessThan(60);
    });
  });

  describe('oauth_scope_escalation', () => {
    it('confirms when server grants escalated scope', async () => {
      const finding = makeOAuthFinding('oauth_scope_escalation', {
        target: 'https://example.com/oauth/authorize?client_id=test&scope=admin+write&response_type=code',
      });

      // Server grants the escalated scope
      const config = makeConfig(
        'HTTP/1.1 302 Found\r\nLocation: https://app.com/callback?code=ABC123\r\n\r\n' +
        '{"scope": "admin write", "access_token": "tok_123"}'
      );

      const result = await validateFinding(finding, config);
      expect(result.confirmed).toBe(true);
      expect(result.validatorUsed).toBe('oauth_scope_escalation');
    });

    it('rejects when server returns 200 without scope evidence (H24 anti-pattern)', async () => {
      const finding = makeOAuthFinding('oauth_scope_escalation');

      // Server returns 200 HTML page — NO scope grant evidence
      const config = makeConfig(
        'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Consent page</body></html>'
      );

      const result = await validateFinding(finding, config);
      // Should NOT confirm just because HTTP 200
      expect(result.confirmed).toBe(false);
    });
  });

  describe('oauth_downgrade_attack', () => {
    it('confirms when both PKCE and non-PKCE requests are accepted', async () => {
      const finding = makeOAuthFinding('oauth_downgrade_attack', {
        target: 'https://example.com/oauth/authorize?client_id=test&code_challenge=xyz&code_challenge_method=S256&response_type=code',
      });

      // Both requests get redirected with auth codes
      const config: ValidatorConfig = {
        executeCommand: async (_command: string) => ({
          success: true,
          stdout: 'HTTP/1.1 302 Found\r\nLocation: https://app.com/callback?code=CODE_123\r\n\r\n',
          stderr: '',
          exitCode: 0,
          executionTimeMs: 100,
        }),
      };

      const result = await validateFinding(finding, config);
      expect(result.confirmed).toBe(true);
      expect(result.validatorUsed).toBe('oauth_downgrade_attack');
    });
  });

  describe('oauth_weak_verifier', () => {
    it('confirms when verifier is shorter than RFC 7636 minimum (43 chars)', async () => {
      const finding = makeOAuthFinding('oauth_weak_verifier', {
        evidence: ['code_verifier=short123 was accepted by the server'],
        target: 'https://example.com/oauth/token?code_verifier=short123',
      });

      const config = makeConfig(
        'HTTP/1.1 200 OK\r\n\r\n{"access_token": "tok_123", "token_type": "bearer"}'
      );

      const result = await validateFinding(finding, config);
      expect(result.confirmed).toBe(true);
      expect(result.validatorUsed).toBe('oauth_weak_verifier');
    });

    it('rejects when verifier meets RFC 7636 minimum length', async () => {
      // 43 chars = meets minimum
      const longVerifier = 'a'.repeat(43);
      const finding = makeOAuthFinding('oauth_weak_verifier', {
        evidence: [`code_verifier=${longVerifier} was accepted`],
      });

      const config = makeConfig('HTTP/1.1 200 OK\r\n\r\n{}');
      const result = await validateFinding(finding, config);
      expect(result.confirmed).toBe(false);
      expect(result.confidence).toBeLessThan(60);
    });
  });

  describe('shared OAuth validator (generic types)', () => {
    it('confirms oauth_state_reuse when flow returns authorization code', async () => {
      const finding = makeOAuthFinding('oauth_state_reuse');
      const config = makeConfig(
        'HTTP/1.1 302 Found\r\nLocation: https://app.com/callback?code=VALID_CODE\r\n\r\n'
      );

      const result = await validateFinding(finding, config);
      expect(result.confirmed).toBe(true);
      expect(result.validatorUsed).toBe('oauth_state_reuse');
    });

    it('rejects oauth_scope_confusion when no code/token in response', async () => {
      const finding = makeOAuthFinding('oauth_scope_confusion');
      const config = makeConfig(
        'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Login form</html>'
      );

      const result = await validateFinding(finding, config);
      expect(result.confirmed).toBe(false);
    });
  });
});

/**
 * Validator auth pass-through policy (P0-3 bulk migration, 2026-04-23)
 *
 * After migrating ~25 validators to `buildCurlArgv`, validators that target
 * the user's authenticated endpoint inherit auth headers/cookies from the
 * active hunt's session. Validators that follow redirects (`curl -L`)
 * intentionally DO NOT inherit auth — curl re-sends custom `-H` headers on
 * every redirect hop, including cross-origin, which would leak the user's
 * bearer/cookies to whatever attacker-controllable host an open redirect
 * lands on. These tests nail that policy down.
 */
import { describe, it, expect } from 'vitest';
import validateFinding from '../core/validation/validator';
import type { ValidatorConfig } from '../core/validation/validator';
import type { ReactFinding } from '../core/engine/react_loop';

function makeFinding(overrides: Partial<ReactFinding> = {}): ReactFinding {
  return {
    id: `test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    title: 'Test Finding',
    vulnerabilityType: 'sqli_error',
    severity: 'high',
    target: 'https://example.com/api/users?id=1',
    description: '',
    evidence: [],
    reproductionSteps: [],
    impact: '',
    confidence: 50,
    discoveredAtIteration: 1,
    agentId: 'test',
    ...overrides,
  } as ReactFinding;
}

function recordingConfig(
  stdout = '',
  extra: Partial<ValidatorConfig> = {},
): { config: ValidatorConfig; seen: { authHeaders: string[]; authCookies: string[] } } {
  const seen = { authHeaders: [] as string[], authCookies: [] as string[] };
  const config: ValidatorConfig = {
    executeCommand: async (cmd: string) => {
      const argv = cmd.split('\x00');
      for (let i = 0; i < argv.length - 1; i++) {
        if (argv[i] === '-H' && argv[i + 1].startsWith('Authorization:')) {
          seen.authHeaders.push(argv[i + 1]);
        }
        if (argv[i] === '-b') {
          seen.authCookies.push(argv[i + 1]);
        }
      }
      return { success: true, stdout, stderr: '', exitCode: 0, executionTimeMs: 5 };
    },
    timeout: 5000,
    authHeaders: { 'Authorization': 'Bearer leak-if-this-escapes' },
    authCookies: [{
      name: 'session', value: 'leak-if-this-escapes',
      domain: 'example.com', path: '/', httpOnly: true, secure: true,
    }],
    ...extra,
  };
  return { config, seen };
}

// ─── Same-origin validators DO inherit auth ─────────────────────────────────

describe('same-origin validators inherit auth', () => {
  it('sqli_error attaches Authorization + Cookie to both probes', async () => {
    const { config, seen } = recordingConfig('HTTP/1.1 200 OK\r\n\r\n{"ok":true}');
    await validateFinding(makeFinding({ vulnerabilityType: 'sqli_error' }), config);
    // Two probes: the error-trigger and the clean-comparison — both get auth.
    expect(seen.authHeaders.length).toBeGreaterThanOrEqual(2);
    expect(seen.authHeaders.every(h => h === 'Authorization: Bearer leak-if-this-escapes')).toBe(true);
    expect(seen.authCookies.every(c => c === 'session=leak-if-this-escapes')).toBe(true);
  });

  it('idor attaches auth to the single request', async () => {
    const { config, seen } = recordingConfig('HTTP/1.1 200 OK\r\n\r\n{"user":"test"}');
    await validateFinding(makeFinding({ vulnerabilityType: 'idor' }), config);
    expect(seen.authHeaders).toEqual(['Authorization: Bearer leak-if-this-escapes']);
  });

  it('bola attaches auth to the single request', async () => {
    const { config, seen } = recordingConfig('HTTP/1.1 200 OK\r\n\r\n[]');
    await validateFinding(makeFinding({ vulnerabilityType: 'bola' }), config);
    expect(seen.authHeaders).toEqual(['Authorization: Bearer leak-if-this-escapes']);
  });

  it('cors_misconfiguration attaches auth to every Origin probe', async () => {
    const { config, seen } = recordingConfig('HTTP/1.1 200 OK\r\n\r\n');
    await validateFinding(makeFinding({ vulnerabilityType: 'cors_misconfiguration' }), config);
    expect(seen.authHeaders.length).toBeGreaterThanOrEqual(1);
    expect(seen.authHeaders.every(h => h === 'Authorization: Bearer leak-if-this-escapes')).toBe(true);
  });
});

// ─── Follow-redirect validators DO NOT inherit auth ──────────────────────────

describe('follow-redirect validators do not inherit auth (leak prevention)', () => {
  it('open_redirect does NOT send auth headers (would leak on redirect)', async () => {
    const { config, seen } = recordingConfig('HTTP/1.1 302 Found\r\nLocation: https://attacker.com\r\n\r\n');
    await validateFinding(makeFinding({ vulnerabilityType: 'open_redirect' }), config);
    expect(seen.authHeaders).toEqual([]);
    expect(seen.authCookies).toEqual([]);
  });

  it('oauth_missing_state does NOT send auth headers (OAuth cross-origin redirect)', async () => {
    const { config, seen } = recordingConfig('HTTP/1.1 302 Found\r\nLocation: https://idp.example.com/oauth\r\n\r\n');
    await validateFinding(makeFinding({
      vulnerabilityType: 'oauth_missing_state',
      target: 'https://app.example.com/oauth/authorize?client_id=x&state=y',
    }), config);
    expect(seen.authHeaders).toEqual([]);
    expect(seen.authCookies).toEqual([]);
  });

  it('oauth_scope_escalation does NOT send auth headers', async () => {
    const { config, seen } = recordingConfig('HTTP/1.1 302 Found\r\n\r\n');
    await validateFinding(makeFinding({
      vulnerabilityType: 'oauth_scope_escalation',
      target: 'https://app.example.com/oauth/authorize?scope=admin',
    }), config);
    expect(seen.authHeaders).toEqual([]);
    expect(seen.authCookies).toEqual([]);
  });

  it('subdomain_takeover does NOT send auth to the takeover-candidate host', async () => {
    const { config, seen } = recordingConfig('HTTP/1.1 404 Not Found\r\n\r\nThere isn\'t a GitHub Pages site here');
    await validateFinding(makeFinding({
      vulnerabilityType: 'subdomain_takeover',
      target: 'https://abandoned.example.com',
    }), config);
    expect(seen.authHeaders).toEqual([]);
    expect(seen.authCookies).toEqual([]);
  });
});

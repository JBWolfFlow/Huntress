/**
 * P2-2 Deterministic Validator Tests
 *
 * Verifies the 9 vuln types lifted out of pass-through:
 *   Aliases (re-use existing OOB-aware validators):
 *     - ssrf_blind, xxe_blind, command_injection_blind
 *   New deterministic logic:
 *     - cache_poisoning   — 3-step proof (poison → cache HIT → propagation)
 *     - cache_deception   — auth'd extension probe + cache HIT + PII
 *     - jwt_none          — alg=none token replay → 2xx = confirmed
 *     - jwt_alg_confusion — HS256 with weak/empty key → 2xx = confirmed
 *     - business_logic    — abuse marker + accepted + no-rejection
 *     - race_condition    — 20 concurrent requests, count 2xx successes
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { validateFinding, type ValidatorConfig } from '../core/validation/validator';
import type { ReactFinding } from '../core/engine/react_loop';

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<ReactFinding>): ReactFinding {
  return {
    id: 'test-finding',
    vulnerabilityType: 'other',
    severity: 'high',
    title: 'Test',
    description: 'Test',
    target: 'https://example.com/api',
    impact: '',
    evidence: [],
    reproductionSteps: [],
    confidence: 70,
    discoveredAtIteration: 1,
    ...overrides,
  };
}

/**
 * Mock executeCommand that returns a canned response per call. Each call
 * shifts the next response off the queue; an empty queue throws so tests
 * fail loud rather than silently using stale data.
 */
function mockExecutor(responses: Array<{ stdout?: string; stderr?: string; exitCode?: number }>) {
  let calls = 0;
  const log: Array<{ command: string; target: string }> = [];
  const fn: ValidatorConfig['executeCommand'] = async (command, target) => {
    log.push({ command, target });
    if (calls >= responses.length) {
      throw new Error(`mockExecutor: out of responses at call ${calls + 1}`);
    }
    const r = responses[calls++];
    return {
      success: (r.exitCode ?? 0) === 0,
      stdout: r.stdout ?? '',
      stderr: r.stderr ?? '',
      exitCode: r.exitCode ?? 0,
      executionTimeMs: 10,
    };
  };
  return { fn, log, getCalls: () => calls };
}

// ─── Cache Poisoning ────────────────────────────────────────────────────────

describe('P2-2 · cache_poisoning validator', () => {
  it('confirms with canary present + cache HIT and stops on first matching header', async () => {
    // We don't know the canary the validator generates, so build a response
    // template that includes ANY canary text by echoing what the validator wrote.
    // Easier: capture the request via the mock log to extract the canary it sent,
    // then for the clean response, embed that exact canary.

    let canary = '';
    const exec: ValidatorConfig['executeCommand'] = async (command, _target) => {
      // Extract the X-Forwarded-Host value from the curl argv (null-joined)
      const args = command.split('\x00');
      const fwdIdx = args.findIndex(a => a === '-H' && false); // placeholder
      // Find any "X-Forwarded-Host: ..." arg
      for (let i = 0; i < args.length; i++) {
        if (args[i] === '-H' && /^X-Forwarded-Host:/i.test(args[i + 1] ?? '')) {
          const m = (args[i + 1] ?? '').match(/X-Forwarded-Host:\s*(\S+)/i);
          if (m) canary = m[1];
        }
      }
      void fwdIdx;
      // Determine if this is a poison (has X-Forwarded-Host) or clean call
      const hasAttackerHeader = args.some(a => /^X-Forwarded-Host:/i.test(a));
      if (hasAttackerHeader) {
        // Poison response — server returns 200, no useful info
        return { success: true, stdout: 'HTTP/1.1 200 OK\r\n\r\n', stderr: '', exitCode: 0, executionTimeMs: 5 };
      }
      // Clean response — embed the canary we just observed + cache HIT signal
      return {
        success: true,
        stdout: `HTTP/1.1 200 OK\r\nCF-Cache-Status: HIT\r\nContent-Type: text/html\r\n\r\n<html>Welcome ${canary}</html>`,
        stderr: '',
        exitCode: 0,
        executionTimeMs: 5,
      };
    };

    const finding = makeFinding({ vulnerabilityType: 'cache_poisoning', target: 'https://target.com/' });
    const result = await validateFinding(finding, { executeCommand: exec });

    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toMatch(/^cache_poisoning_via_x-forwarded-host/);
    expect(result.evidence.some(e => e.type === 'http_response')).toBe(true);
    expect(result.evidence.some(e => e.type === 'http_request')).toBe(true);
  });

  it('does not confirm without cache HIT signal', async () => {
    // 5 headers × 2 calls = 10 max calls when all attempts fail
    const exec = mockExecutor(Array(10).fill({ stdout: 'HTTP/1.1 200 OK\r\n\r\n<html>no canary, no cache</html>' }));
    const finding = makeFinding({ vulnerabilityType: 'cache_poisoning', target: 'https://target.com/' });
    const result = await validateFinding(finding, { executeCommand: exec.fn });
    expect(result.confirmed).toBe(false);
    expect(result.validatorUsed).toBe('cache_poisoning');
  });
});

// ─── Cache Deception ────────────────────────────────────────────────────────

describe('P2-2 · cache_deception validator', () => {
  it('confirms when authd .css probe is cached AND PII reachable unauth', async () => {
    let callIdx = 0;
    const exec: ValidatorConfig['executeCommand'] = async () => {
      callIdx++;
      // First response (auth'd .css probe): cached + PII present
      // Second response (unauth re-fetch of same .css): same cached PII
      const isAuth = callIdx === 1;
      return {
        success: true,
        stdout: `HTTP/1.1 200 OK\r\nCF-Cache-Status: HIT\r\nContent-Type: text/css\r\n\r\n{"email":"victim@target.com","user_id":42}${isAuth ? '' : ''}`,
        stderr: '',
        exitCode: 0,
        executionTimeMs: 5,
      };
    };

    const finding = makeFinding({ vulnerabilityType: 'cache_deception', target: 'https://target.com/account/profile' });
    const result = await validateFinding(finding, { executeCommand: exec });
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toMatch(/^cache_deception_via_/);
  });

  it('does not confirm when no PII in auth response', async () => {
    const responses = Array(15).fill({ stdout: 'HTTP/1.1 200 OK\r\nCF-Cache-Status: HIT\r\n\r\nbody { color: red; }' });
    const exec = mockExecutor(responses);
    const finding = makeFinding({ vulnerabilityType: 'cache_deception', target: 'https://target.com/profile' });
    const result = await validateFinding(finding, { executeCommand: exec.fn });
    expect(result.confirmed).toBe(false);
  });
});

// ─── JWT none ───────────────────────────────────────────────────────────────

describe('P2-2 · jwt_none validator', () => {
  // Sample JWT — header={alg:RS256}, payload={sub:test,role:user}, signature=fake
  const sampleJwt = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0Iiwicm9sZSI6InVzZXIifQ.fake_signature_xxx';

  it('returns no_token when no JWT in finding or auth headers', async () => {
    const finding = makeFinding({ vulnerabilityType: 'jwt_none' });
    const result = await validateFinding(finding, { executeCommand: async () => ({ success: true, stdout: '', stderr: '', exitCode: 0, executionTimeMs: 0 }) });
    expect(result.confirmed).toBe(false);
    expect(result.validatorUsed).toBe('jwt_none_no_token');
  });

  it('confirms when forged alg=none token returns 2xx', async () => {
    let callIdx = 0;
    const exec: ValidatorConfig['executeCommand'] = async () => {
      callIdx++;
      // Call 1 = baseline (original token), 401 (unsigned token rejected was the agent's hint)
      // Call 2 = forged alg=none — server accepts (vulnerable)
      return {
        success: true,
        stdout: callIdx === 1
          ? 'HTTP/1.1 401 Unauthorized\r\n\r\n'
          : 'HTTP/1.1 200 OK\r\n\r\n{"user":"test","authenticated":true}',
        stderr: '',
        exitCode: 0,
        executionTimeMs: 5,
      };
    };

    const finding = makeFinding({
      vulnerabilityType: 'jwt_none',
      target: 'https://target.com/api/me',
      evidence: [`Bearer ${sampleJwt}`],
    });
    const result = await validateFinding(finding, { executeCommand: exec });
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toBe('jwt_none_confirmed');
    expect(result.confidence).toBeGreaterThan(70);
  });

  it('does not confirm when forged token returns 401', async () => {
    const exec = mockExecutor([
      { stdout: 'HTTP/1.1 200 OK\r\n\r\n{"user":"test"}' },
      { stdout: 'HTTP/1.1 401 Unauthorized\r\n\r\n{"error":"invalid signature"}' },
    ]);
    const finding = makeFinding({
      vulnerabilityType: 'jwt_none',
      target: 'https://target.com/api/me',
      evidence: [sampleJwt],
    });
    const result = await validateFinding(finding, { executeCommand: exec.fn });
    expect(result.confirmed).toBe(false);
    expect(result.validatorUsed).toBe('jwt_none_rejected');
  });

  it('discovers JWT in Authorization auth header', async () => {
    const exec = mockExecutor([
      { stdout: 'HTTP/1.1 401 Unauthorized\r\n\r\n' },
      { stdout: 'HTTP/1.1 200 OK\r\n\r\n{"ok":true}' },
    ]);
    const finding = makeFinding({ vulnerabilityType: 'jwt_none', target: 'https://target.com/api/me' });
    const result = await validateFinding(finding, {
      executeCommand: exec.fn,
      authHeaders: { Authorization: `Bearer ${sampleJwt}` },
    });
    expect(result.confirmed).toBe(true);
  });
});

// ─── JWT alg confusion ──────────────────────────────────────────────────────

describe('P2-2 · jwt_alg_confusion validator', () => {
  const sampleJwt = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.fake_signature';

  it('returns no_token when no JWT available', async () => {
    const finding = makeFinding({ vulnerabilityType: 'jwt_alg_confusion' });
    const result = await validateFinding(finding, { executeCommand: async () => ({ success: true, stdout: '', stderr: '', exitCode: 0, executionTimeMs: 0 }) });
    expect(result.confirmed).toBe(false);
    expect(result.validatorUsed).toBe('jwt_alg_confusion_no_token');
  });

  it('confirms when HS256 with empty key is accepted', async () => {
    // First key tried is empty string — server accepts → 200
    const exec = mockExecutor([
      { stdout: 'HTTP/1.1 200 OK\r\n\r\n{"ok":true}' },
    ]);
    const finding = makeFinding({
      vulnerabilityType: 'jwt_alg_confusion',
      target: 'https://target.com/api/me',
      evidence: [sampleJwt],
    });
    const result = await validateFinding(finding, { executeCommand: exec.fn });
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toBe('jwt_alg_confusion_confirmed');
  });

  it('does not confirm when all weak keys rejected', async () => {
    // 5 weak keys, all rejected
    const exec = mockExecutor(Array(5).fill({ stdout: 'HTTP/1.1 401 Unauthorized\r\n\r\n' }));
    const finding = makeFinding({
      vulnerabilityType: 'jwt_alg_confusion',
      target: 'https://target.com/api/me',
      evidence: [sampleJwt],
    });
    const result = await validateFinding(finding, { executeCommand: exec.fn });
    expect(result.confirmed).toBe(false);
    expect(result.validatorUsed).toBe('jwt_alg_confusion_rejected');
  });
});

// ─── Business Logic ─────────────────────────────────────────────────────────

describe('P2-2 · business_logic validator', () => {
  it('confirms negative quantity when accepted by server', async () => {
    const exec = mockExecutor([
      { stdout: 'HTTP/1.1 200 OK\r\n\r\n{"orderId":42,"total":-10.0,"status":"created"}' },
    ]);
    const finding = makeFinding({
      vulnerabilityType: 'business_logic',
      target: 'https://target.com/api/cart?quantity=-5',
    });
    const result = await validateFinding(finding, { executeCommand: exec.fn });
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toMatch(/^business_logic_negative_quantity/);
  });

  it('does not confirm when server rejects with validation error', async () => {
    const exec = mockExecutor([
      { stdout: 'HTTP/1.1 400 Bad Request\r\n\r\n{"error":"Quantity must be positive"}' },
    ]);
    const finding = makeFinding({
      vulnerabilityType: 'business_logic',
      target: 'https://target.com/api/cart?quantity=-5',
    });
    const result = await validateFinding(finding, { executeCommand: exec.fn });
    expect(result.confirmed).toBe(false);
    expect(result.validatorUsed).toBe('business_logic_rejected');
  });

  it('returns inconclusive when no abuse marker present', async () => {
    const exec = mockExecutor([
      { stdout: 'HTTP/1.1 200 OK\r\n\r\n{"ok":true}' },
    ]);
    const finding = makeFinding({
      vulnerabilityType: 'business_logic',
      target: 'https://target.com/api/cart?quantity=2',
    });
    const result = await validateFinding(finding, { executeCommand: exec.fn });
    expect(result.confirmed).toBe(false);
    expect(result.validatorUsed).toBe('business_logic_inconclusive');
  });

  it('detects workflow skip pattern (status=approved)', async () => {
    const exec = mockExecutor([
      { stdout: 'HTTP/1.1 200 OK\r\n\r\n{"ok":true}' },
    ]);
    const finding = makeFinding({
      vulnerabilityType: 'business_logic',
      target: 'https://target.com/api/checkout?status=approved',
    });
    const result = await validateFinding(finding, { executeCommand: exec.fn });
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toMatch(/^business_logic_workflow_skip/);
  });
});

// ─── Race Condition ─────────────────────────────────────────────────────────

describe('P2-2 · race_condition validator', () => {
  it('confirms when multiple concurrent requests succeed (no lock)', async () => {
    // 20 calls, all return 2xx → race uncontrolled (but not idempotent because
    // we'll mark some as different statuses to prove the heuristic)
    const responses = Array.from({ length: 20 }, (_, i) =>
      i < 5
        ? { stdout: 'HTTP/1.1 200 OK\r\n\r\n{"applied":true}' }
        : { stdout: 'HTTP/1.1 400 Bad Request\r\n\r\n' }
    );
    const exec = mockExecutor(responses);
    const finding = makeFinding({ vulnerabilityType: 'race_condition', target: 'https://target.com/api/coupon' });
    const result = await validateFinding(finding, { executeCommand: exec.fn });
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toMatch(/^race_condition_5_of_20$/);
  });

  it('does not confirm when only 1 request succeeded (server serialized correctly)', async () => {
    const responses = [
      { stdout: 'HTTP/1.1 200 OK\r\n\r\n{"applied":true}' },
      ...Array(19).fill({ stdout: 'HTTP/1.1 409 Conflict\r\n\r\n{"error":"already applied"}' }),
    ];
    const exec = mockExecutor(responses);
    const finding = makeFinding({ vulnerabilityType: 'race_condition', target: 'https://target.com/api/coupon' });
    const result = await validateFinding(finding, { executeCommand: exec.fn });
    expect(result.confirmed).toBe(false);
    expect(result.validatorUsed).toBe('race_condition_serialized');
  });

  it('does not confirm when all 20 succeed (idempotent endpoint)', async () => {
    const responses = Array(20).fill({ stdout: 'HTTP/1.1 200 OK\r\n\r\n{"value":42}' });
    const exec = mockExecutor(responses);
    const finding = makeFinding({ vulnerabilityType: 'race_condition', target: 'https://target.com/api/me' });
    const result = await validateFinding(finding, { executeCommand: exec.fn });
    expect(result.confirmed).toBe(false);
    expect(result.validatorUsed).toBe('race_condition_idempotent');
  });
});

// ─── Blind aliases ──────────────────────────────────────────────────────────

describe('P2-2 · blind-variant aliases (ssrf_blind, xxe_blind, command_injection_blind)', () => {
  // The aliases dispatch to ssrf/xxe/command_injection — those are heavy
  // validators with OOB calls. We just verify the alias DOES dispatch and
  // tags the result with _blind. Full behavior is covered by the existing
  // ssrf/xxe/command_injection validator tests.

  function alwaysOkExec(): ValidatorConfig['executeCommand'] {
    return async () => ({ success: true, stdout: 'HTTP/1.1 200 OK\r\n\r\n', stderr: '', exitCode: 0, executionTimeMs: 5 });
  }

  it('ssrf_blind alias produces a _blind-suffixed validatorUsed', async () => {
    const finding = makeFinding({ vulnerabilityType: 'ssrf_blind', target: 'https://target.com/proxy?url=x' });
    const result = await validateFinding(finding, { executeCommand: alwaysOkExec() });
    expect(result.validatorUsed).toMatch(/_blind$/);
  });

  it('xxe_blind alias produces a _blind-suffixed validatorUsed', async () => {
    const finding = makeFinding({ vulnerabilityType: 'xxe_blind', target: 'https://target.com/upload' });
    const result = await validateFinding(finding, { executeCommand: alwaysOkExec() });
    expect(result.validatorUsed).toMatch(/_blind$/);
  });

  it('command_injection_blind alias produces a _blind-suffixed validatorUsed', async () => {
    const finding = makeFinding({ vulnerabilityType: 'command_injection_blind', target: 'https://target.com/exec?cmd=x' });
    const result = await validateFinding(finding, { executeCommand: alwaysOkExec() });
    expect(result.validatorUsed).toMatch(/_blind$/);
  });
});

// ─── Pass-through removal sanity check ──────────────────────────────────────

describe('P2-2 · pass-through registry no longer covers the 9 lifted types', () => {
  // After P2-2, validateFinding should NOT return validatorUsed ending in
  // '_passthrough' for any of the 9 newly-deterministic types.
  const liftedTypes = [
    'cache_poisoning', 'cache_deception',
    'jwt_alg_confusion', 'jwt_none',
    'business_logic', 'race_condition',
    'ssrf_blind', 'xxe_blind', 'command_injection_blind',
  ];

  for (const t of liftedTypes) {
    it(`${t} dispatches to a real validator (not pass-through)`, async () => {
      // Provide enough mock responses for any reasonable validator path
      // (race_condition needs 20, others fewer). 25 covers everyone.
      const exec = mockExecutor(Array(25).fill({ stdout: 'HTTP/1.1 200 OK\r\n\r\n' }));
      const finding = makeFinding({
        vulnerabilityType: t,
        target: 'https://target.com/api',
        evidence: ['Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signature'],  // for JWT family
      });
      const result = await validateFinding(finding, { executeCommand: exec.fn });
      expect(result.validatorUsed).not.toMatch(/_passthrough$/);
    });
  }
});

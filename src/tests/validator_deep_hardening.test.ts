/**
 * Deeper validator hardening — P0-3 (2026-04-23)
 *
 * Tests the nine hardening increments landed in the deep-validator session:
 *   1. sqli_blind_time  — baseline URL derivation + payload-diff fix.
 *   2. sqli_error       — POST body sweep on /api/ targets.
 *   3. xss_stored       — multi-payload re-injection on rendering URL.
 *   4. ssrf             — active OOB callback injection.
 *   5. path_traversal   — encoding bypass variants + false-positive control.
 *   6. host_header_injection — all seven override headers.
 *   7. idor/bola        — two-identity data-ownership differential.
 *   8. command_injection — OOB shell-exec injection.
 *   9. xxe              — blind OOB DTD-fetch.
 *
 * Fast unit tests — no network, no real Playwright. The HeadlessBrowser used
 * by xss_stored is mocked (reuses the pattern from xss_validator_multipayload
 * tests) and the OOBServer is stubbed so we can flip `isTriggered` at will.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import validateFinding, {
  buildPathTraversalVariants,
  deriveSqlBaselineUrl,
  HOST_OVERRIDE_HEADERS,
  setValidatorOOBServer,
} from '../core/validation/validator';
import type { ValidatorConfig } from '../core/validation/validator';
import type { ReactFinding } from '../core/engine/react_loop';

// ─── HeadlessBrowser mock for xss_stored ────────────────────────────────────

const mockValidateXSSFn = vi.fn();
const mockNavigateAndAnalyzeFn = vi.fn();
const mockAnalyzeDOMXSSFn = vi.fn();
const mockValidateStoredXSSFn = vi.fn();

vi.mock('../core/validation/headless_browser', () => {
  return {
    HeadlessBrowser: class {
      async launch(): Promise<void> {}
      async close(): Promise<void> {}
      validateXSS(...args: unknown[]): unknown { return mockValidateXSSFn(...args); }
      validateStoredXSS(...args: unknown[]): unknown { return mockValidateStoredXSSFn(...args); }
      navigateAndAnalyze(...args: unknown[]): unknown { return mockNavigateAndAnalyzeFn(...args); }
      analyzeDOMXSS(...args: unknown[]): unknown { return mockAnalyzeDOMXSSFn(...args); }
    },
  };
});

// ─── Shared helpers ─────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<ReactFinding> = {}): ReactFinding {
  return {
    id: `test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    title: 'T', vulnerabilityType: 'sqli_error', severity: 'high',
    target: 'https://example.com/api/x?id=1', description: '',
    evidence: [], reproductionSteps: [], impact: '',
    confidence: 60, discoveredAtIteration: 1, agentId: 'test',
    ...overrides,
  } as ReactFinding;
}

type Handler = (cmd: string) => string;
function makeConfig(handler: Handler, extra: Partial<ValidatorConfig> = {}): ValidatorConfig {
  return {
    executeCommand: async (cmd: string) => ({
      success: true, stdout: handler(cmd), stderr: '',
      exitCode: 0, executionTimeMs: 5,
    }),
    timeout: 5000,
    ...extra,
  };
}

/** Extract the last argv arg (the URL) from a null-joined curl command. */
function urlOf(cmd: string): string { const argv = cmd.split('\x00'); return argv[argv.length - 1]; }
/** Extract the POST body (if any) from a null-joined curl command. */
function bodyOf(cmd: string): string | null {
  const argv = cmd.split('\x00');
  const idx = argv.indexOf('--data-raw');
  return idx >= 0 ? argv[idx + 1] : null;
}
/** Extract a custom header value from a null-joined curl command. */
function headerOf(cmd: string, name: string): string | null {
  const argv = cmd.split('\x00');
  for (let i = 0; i < argv.length - 1; i++) {
    if (argv[i] === '-H' && argv[i + 1].toLowerCase().startsWith(`${name.toLowerCase()}:`)) {
      return argv[i + 1].substring(name.length + 1).trim();
    }
  }
  return null;
}

// ─── OOBServer stub for ssrf / command_injection / xxe ──────────────────────

interface StubCallback {
  id: string;
  callbackUrl: string;
  triggered: boolean;
  triggeredAt?: number;
  interaction?: { sourceIp: string; protocol: string };
}

function makeOobStub() {
  const callbacks = new Map<string, StubCallback>();
  let nextId = 1;
  const stub = {
    generateCallbackUrl: vi.fn((injectionPoint: { vulnerabilityType: string; target: string; parameter: string; agentId: string }) => {
      void injectionPoint;
      const id = `stub_${nextId++}`;
      const cb: StubCallback = {
        id, callbackUrl: `${id}.oob.local`, triggered: false,
      };
      callbacks.set(id, cb);
      return cb;
    }),
    getHttpUrl: (cb: StubCallback) => `http://${cb.callbackUrl}`,
    isTriggered: (id: string) => callbacks.get(id)?.triggered ?? false,
    getTriggeredCallbacks: () => [...callbacks.values()].filter(c => c.triggered),
    // Test helper: simulate server-side fetch hitting the OOB host.
    _triggerAll: () => {
      for (const cb of callbacks.values()) {
        cb.triggered = true;
        cb.triggeredAt = Date.now();
        cb.interaction = { sourceIp: '203.0.113.7', protocol: 'http' };
      }
    },
  };
  return stub;
}

beforeEach(() => {
  mockValidateXSSFn.mockReset();
  mockNavigateAndAnalyzeFn.mockReset();
  mockAnalyzeDOMXSSFn.mockReset();
  mockValidateStoredXSSFn.mockReset();
  setValidatorOOBServer(undefined);
});

// ─── 1. deriveSqlBaselineUrl + sqli_blind_time ──────────────────────────────

describe('deriveSqlBaselineUrl', () => {
  it('strips SLEEP(N) payloads', () => {
    expect(deriveSqlBaselineUrl('https://x.com/?id=1+AND+SLEEP(5)'))
      .toBe('https://x.com/?id=1+AND+1');
  });
  it('strips pg_sleep', () => {
    expect(deriveSqlBaselineUrl("https://x.com/?id=';SELECT+pg_sleep(5)--"))
      .toContain('1'); // payload stripped to safe value
  });
  it('falls back to nulling last query value when no SQL pattern matches', () => {
    expect(deriveSqlBaselineUrl('https://x.com/?q=whatever'))
      .toBe('https://x.com/?q=1');
  });
  it('returns target unchanged when no query parameter to null', () => {
    expect(deriveSqlBaselineUrl('https://x.com/static'))
      .toBe('https://x.com/static');
  });
});

describe('sqli_blind_time', () => {
  it('confirms when delay URL takes >3s longer than baseline', async () => {
    const config = makeConfig((cmd) => {
      const url = urlOf(cmd);
      // Payload URL (contains SLEEP) takes 5s; baseline takes 0.1s
      return url.includes('SLEEP') ? '5.0' : '0.1';
    });
    const result = await validateFinding(
      makeFinding({ vulnerabilityType: 'sqli_blind_time', target: 'https://x.com/?id=1+AND+SLEEP(5)' }),
      config,
    );
    expect(result.confirmed).toBe(true);
  });

  it('does not confirm when baseline and payload URLs are identical (no SQL pattern to strip)', async () => {
    // Target with no query/no payload pattern = deriveSqlBaselineUrl returns same URL.
    const config = makeConfig(() => '5.0');
    const result = await validateFinding(
      makeFinding({ vulnerabilityType: 'sqli_blind_time', target: 'https://x.com/static' }),
      config,
    );
    expect(result.confirmed).toBe(false);
    expect(result.reproductionSteps.some(s => s.includes('no baseline URL'))).toBe(true);
  });
});

// ─── 2. sqli_error POST body sweep ──────────────────────────────────────────

describe('sqli_error — POST body sweep on API endpoints', () => {
  it('confirms via POST body "id" field error on /api/ target', async () => {
    const config = makeConfig((cmd) => {
      const body = bodyOf(cmd);
      // Only POST body with "id":"'" triggers the DB error
      if (body && body.includes('"id":"\'"')) {
        return 'HTTP/1.1 500\n\nERROR: syntax error at or near "\'": near "\'"';
      }
      // Clean probe — no error
      if (body && body.includes('"clean"')) return 'HTTP/1.1 200\n\n{}';
      return 'HTTP/1.1 200\n\n{}';
    });
    const result = await validateFinding(
      makeFinding({
        vulnerabilityType: 'sqli_error',
        target: 'https://x.com/api/users',
        description: 'SQLi in body id field on POST',
      }),
      config,
    );
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toMatch(/POST body field "id"/);
  });

  it('rejects GET false positive when clean URL also errors', async () => {
    const config = makeConfig(() =>
      "HTTP/1.1 500\n\nYou have an error in your SQL syntax",
    );
    const result = await validateFinding(
      makeFinding({
        vulnerabilityType: 'sqli_error',
        target: "https://x.com/api/x?id=1'",
      }),
      config,
    );
    // Both original and clean trigger errors → page-default → discard.
    expect(result.confirmed).toBe(false);
  });
});

// ─── 3. xss_stored multi-payload re-injection ───────────────────────────────

describe('xss_stored — multi-payload re-injection fallback', () => {
  it('confirms via plain-navigation dialog when agent payload persists', async () => {
    mockNavigateAndAnalyzeFn.mockResolvedValue({
      success: true, finalUrl: 'x', title: '',
      dialogDetected: true, dialogMessage: 'xss',
      consoleLogs: [], networkRequests: [], cookies: [],
    });
    const result = await validateFinding(
      makeFinding({ vulnerabilityType: 'xss_stored' }),
      makeConfig(() => ''),
    );
    expect(result.confirmed).toBe(true);
    expect(result.reproductionSteps.some(s => s.includes('agent-stored') || s.includes('still live'))).toBe(true);
  });

  it('falls back to multi-variant re-injection when plain navigation silent', async () => {
    mockNavigateAndAnalyzeFn.mockResolvedValue({
      success: true, finalUrl: 'x', title: '',
      dialogDetected: false, consoleLogs: [], networkRequests: [], cookies: [],
    });
    mockValidateXSSFn
      .mockResolvedValueOnce({ confirmed: false, confidence: 0, evidence: [] })
      .mockResolvedValueOnce({ confirmed: true, confidence: 80, evidence: [] });
    const result = await validateFinding(
      makeFinding({ vulnerabilityType: 'xss_stored' }),
      makeConfig(() => ''),
    );
    expect(result.confirmed).toBe(true);
    expect(mockValidateXSSFn).toHaveBeenCalled();
  });
});

// ─── 4. ssrf active OOB injection ───────────────────────────────────────────

describe('ssrf — active OOB injection', () => {
  it('confirms when OOB callback fires after probe', async () => {
    const oob = makeOobStub();
    // Simulate: any curl sent fires the OOB callback.
    setValidatorOOBServer(oob as never);
    const config = makeConfig((cmd) => {
      if (urlOf(cmd).includes('oob.local')) oob._triggerAll();
      return '';
    });
    const result = await validateFinding(
      makeFinding({ vulnerabilityType: 'ssrf', target: 'https://x.com/fetch?url=http://example.com' }),
      config,
    );
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toBe('ssrf_active_oob');
  });

  it('does NOT confirm when OOB never fires and no response indicators', async () => {
    const oob = makeOobStub();
    setValidatorOOBServer(oob as never);
    const config = makeConfig(() => 'HTTP/1.1 200\n\n{"ok":true}');
    const result = await validateFinding(
      makeFinding({ vulnerabilityType: 'ssrf', target: 'https://x.com/fetch?url=http://example.com' }),
      config,
    );
    expect(result.confirmed).toBe(false);
  });
});

// ─── 5. path_traversal encoding variants ────────────────────────────────────

describe('buildPathTraversalVariants', () => {
  it('builds original + at least one encoding variant when ../ present', () => {
    const variants = buildPathTraversalVariants('https://x.com/get?file=../../../etc/passwd');
    const labels = variants.map(v => v.label);
    expect(labels).toContain('original');
    expect(labels).toContain('url-encoded');
    expect(labels).toContain('double-url-encoded');
  });
  it('returns just original when no ../ pattern', () => {
    const variants = buildPathTraversalVariants('https://x.com/get?file=foo');
    expect(variants.map(v => v.label)).toEqual(['original']);
  });
});

describe('path_traversal — encoding variant sweep', () => {
  it('confirms on url-encoded variant when original returns nothing', async () => {
    const config = makeConfig((cmd) => {
      const url = urlOf(cmd);
      // Only the url-encoded variant (has %2e%2e%2f) leaks /etc/passwd
      if (url.includes('%2e%2e%2f')) {
        return 'HTTP/1.1 200\n\nroot:x:0:0:root:/root:/bin/bash\n';
      }
      return 'HTTP/1.1 404\n\nnot found';
    });
    const result = await validateFinding(
      makeFinding({
        vulnerabilityType: 'path_traversal',
        target: 'https://x.com/get?file=../../../etc/passwd',
      }),
      config,
    );
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toMatch(/url-encoded/);
    expect(result.validatorUsed).toMatch(/etc\/passwd/);
  });

  it('rejects false positive when clean URL already shows file indicators', async () => {
    // Page default content contains /etc/passwd fingerprint — discard.
    const config = makeConfig(() => 'HTTP/1.1 200\n\nroot:x:0:0:root:/root:/bin/bash\n');
    const result = await validateFinding(
      makeFinding({
        vulnerabilityType: 'path_traversal',
        target: 'https://x.com/get?file=../../../etc/passwd',
      }),
      config,
    );
    expect(result.confirmed).toBe(false);
    expect(result.reproductionSteps.some(s => s.includes('FALSE POSITIVE'))).toBe(true);
  });
});

// ─── 6. host_header_injection extended headers ──────────────────────────────

describe('HOST_OVERRIDE_HEADERS', () => {
  it('includes the seven canonical override-header variants', () => {
    expect(HOST_OVERRIDE_HEADERS).toContain('Host');
    expect(HOST_OVERRIDE_HEADERS).toContain('X-Forwarded-Host');
    expect(HOST_OVERRIDE_HEADERS).toContain('X-Forwarded-Server');
    expect(HOST_OVERRIDE_HEADERS).toContain('X-Host');
    expect(HOST_OVERRIDE_HEADERS).toContain('X-Original-URL');
    expect(HOST_OVERRIDE_HEADERS).toContain('X-Rewrite-URL');
    expect(HOST_OVERRIDE_HEADERS).toContain('Forwarded');
  });
});

describe('host_header_injection — override header sweep', () => {
  it('confirms via redirect when X-Forwarded-Host reflects in Location', async () => {
    const config = makeConfig((cmd) => {
      const h = headerOf(cmd, 'X-Forwarded-Host');
      if (h === 'evil-attacker.com') {
        return 'HTTP/1.1 302 Found\nLocation: https://evil-attacker.com/path\n\n';
      }
      return 'HTTP/1.1 200\n\n';
    });
    const result = await validateFinding(
      makeFinding({ vulnerabilityType: 'host_header_injection', target: 'https://x.com/' }),
      config,
    );
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toMatch(/X-Forwarded-Host/);
    expect(result.validatorUsed).toMatch(/redirect/);
  });

  it('stops after the first redirect-confirming header (short-circuit)', async () => {
    const sentHeaders: string[] = [];
    const config = makeConfig((cmd) => {
      for (const h of HOST_OVERRIDE_HEADERS) {
        const val = headerOf(cmd, h);
        if (val) sentHeaders.push(h);
      }
      // Host (first header) fires → should stop immediately.
      const hostVal = headerOf(cmd, 'Host');
      if (hostVal === 'evil-attacker.com') {
        return 'HTTP/1.1 302\nLocation: https://evil-attacker.com\n\n';
      }
      return 'HTTP/1.1 200\n\n';
    });
    await validateFinding(
      makeFinding({ vulnerabilityType: 'host_header_injection', target: 'https://x.com/' }),
      config,
    );
    expect(sentHeaders[0]).toBe('Host');
    expect(sentHeaders).not.toContain('X-Forwarded-Host');
  });
});

// ─── 7. idor + bola two-identity differential ───────────────────────────────

describe('idor/bola two-identity differential', () => {
  const victim = {
    authHeaders: { 'Authorization': 'Bearer victim-token' },
    authCookies: [],
    primaryAuthLabel: 'victim',
  };
  const attacker = {
    secondaryAuthHeaders: { 'Authorization': 'Bearer attacker-token' },
    secondaryAuthCookies: [],
    secondaryAuthLabel: 'attacker',
  };

  it('confirms idor when attacker sees identical body to victim', async () => {
    const sharedBody = '{"user_id":"1","name":"victim","ssn":"secret"}';
    const config = makeConfig(() =>
      `HTTP/1.1 200\nContent-Type: application/json\n\n${sharedBody}`,
      { ...victim, ...attacker },
    );
    const result = await validateFinding(
      makeFinding({ vulnerabilityType: 'idor', target: 'https://x.com/api/users/1' }),
      config,
    );
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toBe('idor_differential');
  });

  it('bola uses the same differential path and labels validatorUsed correctly', async () => {
    const sharedBody = '{"order_id":"42","total":"1000"}';
    const config = makeConfig(() =>
      `HTTP/1.1 200\n\n${sharedBody}`,
      { ...victim, ...attacker },
    );
    const result = await validateFinding(
      makeFinding({ vulnerabilityType: 'bola', target: 'https://x.com/api/orders/42' }),
      config,
    );
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toBe('bola_differential');
  });

  it('downgrades status-only confirmation when attacker identity is denied', async () => {
    // Primary sees 200 (suggestive), but attacker gets 403 — suggests ownership IS checked.
    let call = 0;
    const config = makeConfig((cmd) => {
      call++;
      const auth = headerOf(cmd, 'Authorization');
      if (auth === 'Bearer victim-token') {
        return 'HTTP/1.1 200\n\n{"data":"' + 'x'.repeat(250) + '"}';
      }
      if (auth === 'Bearer attacker-token') {
        return 'HTTP/1.1 403\n\n{"error":"forbidden"}';
      }
      return '';
    }, { ...victim, ...attacker });
    const result = await validateFinding(
      makeFinding({ vulnerabilityType: 'idor', target: 'https://x.com/api/users/1' }),
      config,
    );
    expect(result.confirmed).toBe(false);
    expect(call).toBe(2);
  });

  it('falls back to status-only check when no secondary identity configured', async () => {
    const config = makeConfig(() =>
      'HTTP/1.1 200\n\n{"data":"' + 'x'.repeat(250) + '"}',
      victim,
    );
    const result = await validateFinding(
      makeFinding({ vulnerabilityType: 'idor', target: 'https://x.com/api/users/1' }),
      config,
    );
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toBe('idor');
  });
});

// ─── 8. command_injection OOB ───────────────────────────────────────────────

describe('command_injection — active OOB injection', () => {
  it('confirms when a shell-exec variant fires the OOB callback', async () => {
    const oob = makeOobStub();
    setValidatorOOBServer(oob as never);
    const config = makeConfig((cmd) => {
      if (urlOf(cmd).includes('curl%20http') || urlOf(cmd).includes('nslookup')) {
        oob._triggerAll();
      }
      return 'HTTP/1.1 200\n\n';
    });
    const result = await validateFinding(
      makeFinding({ vulnerabilityType: 'command_injection', target: 'https://x.com/ping?host=1.1.1.1' }),
      config,
    );
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toBe('command_injection_oob');
  });
});

// ─── 9. xxe blind OOB DTD fetch ─────────────────────────────────────────────

describe('xxe — blind OOB DTD fetch', () => {
  it('confirms when XML parser fetches OOB DTD', async () => {
    const oob = makeOobStub();
    setValidatorOOBServer(oob as never);
    const config = makeConfig((cmd) => {
      // Direct echo returns nothing (no file indicators). Blind probe POSTs XML.
      if (bodyOf(cmd)?.includes('<!DOCTYPE')) {
        oob._triggerAll();
        return 'HTTP/1.1 200\n\n';
      }
      return 'HTTP/1.1 200\n\n';
    });
    const result = await validateFinding(
      makeFinding({ vulnerabilityType: 'xxe', target: 'https://x.com/upload' }),
      config,
    );
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toBe('xxe_blind_oob');
  });

  it('still confirms via direct-echo path when /etc/passwd appears in response', async () => {
    const config = makeConfig(() =>
      'HTTP/1.1 200\n\nroot:x:0:0:root:/root:/bin/bash',
    );
    const result = await validateFinding(
      makeFinding({ vulnerabilityType: 'xxe', target: 'https://x.com/upload' }),
      config,
    );
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toBe('xxe_direct_echo');
  });
});

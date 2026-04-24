/**
 * SSTI validator — POST-body injection + auth plumbing (P0-3, 2026-04-23)
 *
 * The 2026-04-23 Juice Shop hunt flagged a CRITICAL Pug SSTI on POST
 * /api/BasketItems `quantity` field. The existing GET-only + unauthenticated
 * probe couldn't confirm it: curl hit 401 and never saw the arithmetic
 * result. These tests cover:
 *   - `buildCurlArgv` builds correct argv with auth headers/cookies and body.
 *   - SSTI validator sweeps canonical POST body fields when the target looks
 *     like an API endpoint, and confirms on the first field whose response
 *     contains `49` / `7777777`.
 *   - GET-query path still works for classic reflection cases.
 *   - Negative-control step rejects false positives when "49" is
 *     content-independent (always present).
 */
import { describe, it, expect } from 'vitest';
import validateFinding, { buildCurlArgv } from '../core/validation/validator';
import type { ValidatorConfig } from '../core/validation/validator';
import type { ReactFinding } from '../core/engine/react_loop';

function makeFinding(overrides: Partial<ReactFinding> = {}): ReactFinding {
  return {
    id: `test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    title: 'SSTI Test Finding',
    vulnerabilityType: 'ssti',
    severity: 'critical',
    target: 'http://localhost:3001/api/BasketItems',
    description: 'Pug SSTI in quantity parameter (POST body)',
    evidence: [],
    reproductionSteps: [],
    impact: 'RCE',
    confidence: 50,
    discoveredAtIteration: 1,
    agentId: 'ssti-hunter',
    ...overrides,
  } as ReactFinding;
}

// ─── buildCurlArgv ──────────────────────────────────────────────────────────

describe('buildCurlArgv', () => {
  it('builds a plain GET', () => {
    const cmd = buildCurlArgv({ url: 'https://example.com/' });
    const argv = cmd.split('\x00');
    expect(argv[0]).toBe('curl');
    expect(argv).toContain('-s');
    expect(argv).toContain('-o');
    expect(argv[argv.length - 1]).toBe('https://example.com/');
  });

  it('attaches auth headers from config', () => {
    const cmd = buildCurlArgv({
      url: 'https://example.com/api',
      authHeaders: { 'Authorization': 'Bearer abc123', 'X-API-Key': 'k' },
    });
    const argv = cmd.split('\x00');
    expect(argv).toContain('-H');
    expect(argv).toContain('Authorization: Bearer abc123');
    expect(argv).toContain('X-API-Key: k');
  });

  it('attaches auth cookies as a single -b arg', () => {
    const cmd = buildCurlArgv({
      url: 'https://example.com/',
      authCookies: [
        { name: 'session', value: 'abc', domain: 'example.com', path: '/', httpOnly: true, secure: true },
        { name: 'xsrf', value: 'def', domain: 'example.com', path: '/', httpOnly: false, secure: true },
      ],
    });
    const argv = cmd.split('\x00');
    const bIdx = argv.indexOf('-b');
    expect(bIdx).toBeGreaterThan(-1);
    expect(argv[bIdx + 1]).toBe('session=abc; xsrf=def');
  });

  it('builds a POST with JSON body and auto-sets Content-Type', () => {
    const cmd = buildCurlArgv({
      url: 'https://example.com/api',
      method: 'POST',
      body: JSON.stringify({ quantity: '{{7*7}}' }),
    });
    const argv = cmd.split('\x00');
    expect(argv).toContain('-X');
    expect(argv).toContain('POST');
    expect(argv).toContain('--data-raw');
    expect(argv).toContain('{"quantity":"{{7*7}}"}');
    expect(argv).toContain('Content-Type: application/json');
  });

  it('explicit headers override auth headers (caller wins)', () => {
    const cmd = buildCurlArgv({
      url: 'https://example.com/',
      authHeaders: { 'Authorization': 'Bearer auth-token' },
      headers: { 'Authorization': 'Bearer override' },
    });
    const argv = cmd.split('\x00');
    const authHeaders = argv.filter((_, i) => argv[i - 1] === '-H' && _.startsWith('Authorization:'));
    expect(authHeaders).toEqual(['Authorization: Bearer override']);
  });
});

// ─── SSTI validator: GET path (preserved behavior) ───────────────────────────

describe('SSTI validator — GET query path', () => {
  it('confirms Jinja2 via 49 → 7777777 sequence, rejects if clean also has 49', async () => {
    let call = 0;
    const config: ValidatorConfig = {
      executeCommand: async (cmd: string) => {
        call++;
        if (cmd.includes('{{7*7}}')) return wrap('Path quantity (49) is not valid');
        if (cmd.includes('7*') && cmd.includes('%277%27') === false && cmd.includes("{{7*'7'}}")) return wrap('Path quantity (7777777) is not valid');
        if (cmd.includes('notatemplate')) return wrap('Path quantity (notatemplate) is not valid');
        return wrap('unexpected');
      },
      timeout: 5000,
    };
    const finding = makeFinding({ target: 'https://example.com/search?q=' });
    const result = await validateFinding(finding, config);
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toMatch(/Jinja2/);
    expect(call).toBe(3);
  });

  it('rejects false positive when clean probe also contains 49', async () => {
    const config: ValidatorConfig = {
      executeCommand: async (cmd: string) => {
        // Page always contains "49" regardless of payload.
        if (cmd.includes('{{7*7}}')) return wrap('Price $49 — stock OK');
        if (cmd.includes("{{7*'7'}}")) return wrap('Price $49 — stock OK');
        if (cmd.includes('notatemplate')) return wrap('Price $49 — stock OK');
        return wrap('');
      },
      timeout: 5000,
    };
    const result = await validateFinding(makeFinding({ target: 'https://example.com/search?q=' }), config);
    expect(result.confirmed).toBe(false);
    expect(result.reproductionSteps.some(s => s.includes('FALSE POSITIVE'))).toBe(true);
  });
});

// ─── SSTI validator: POST body sweep ─────────────────────────────────────────

describe('SSTI validator — POST body sweep (API endpoints)', () => {
  it('confirms Pug SSTI on /api/BasketItems via POST body "quantity" field', async () => {
    // Only the "quantity" body field reflects {{7*7}} → 49. Other fields 400.
    const config: ValidatorConfig = {
      executeCommand: async (cmd: string) => {
        const argv = cmd.split('\x00');
        const dataIdx = argv.indexOf('--data-raw');
        const body = dataIdx >= 0 ? argv[dataIdx + 1] : '';

        // GET query probes first — target url has no query slot, so the
        // validator builds ?test={{7*7}} etc. Those return 401 (no auth).
        if (argv[argv.indexOf('-X') + 1] !== 'POST') {
          return wrap('{"error":"Unauthorized"}');
        }
        if (!body.includes('"quantity"')) {
          return wrap('{"error":"Unknown field"}');
        }
        if (body.includes('{{7*7}}')) return wrap('BasketItem validation failed: Path quantity (49) is less than minimum');
        if (body.includes("{{7*'7'}}")) return wrap('BasketItem validation failed: Path quantity (7777777) is less than minimum');
        if (body.includes('"notatemplate"')) return wrap('BasketItem validation failed: Path quantity (notatemplate) is not a number');
        return wrap('');
      },
      timeout: 5000,
    };
    const result = await validateFinding(makeFinding(), config);
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toMatch(/POST body field "quantity"/);
    expect(result.validatorUsed).toMatch(/Jinja2|Pug|Twig|unknown/);
  });

  it('does not attempt POST body sweep for non-API URLs', async () => {
    // Classic reflection target — no /api/ or /rest/, no body-suggesting
    // description — so only GET query should fire. Don't confirm from nothing.
    let postAttempts = 0;
    const config: ValidatorConfig = {
      executeCommand: async (cmd: string) => {
        const argv = cmd.split('\x00');
        if (argv[argv.indexOf('-X') + 1] === 'POST') postAttempts++;
        return wrap(''); // nothing reflects
      },
      timeout: 5000,
    };
    const result = await validateFinding(
      makeFinding({ target: 'https://example.com/search?q=', description: 'reflected in search' }),
      config,
    );
    expect(postAttempts).toBe(0);
    expect(result.confirmed).toBe(false);
  });

  it('passes auth headers through to every probe', async () => {
    const seenHeaders: string[] = [];
    const config: ValidatorConfig = {
      executeCommand: async (cmd: string) => {
        const argv = cmd.split('\x00');
        for (let i = 0; i < argv.length - 1; i++) {
          if (argv[i] === '-H' && argv[i + 1].startsWith('Authorization:')) {
            seenHeaders.push(argv[i + 1]);
          }
        }
        return wrap('{"error":"no-op"}');
      },
      timeout: 5000,
      authHeaders: { 'Authorization': 'Bearer test-token-xyz' },
    };
    await validateFinding(makeFinding(), config);
    expect(seenHeaders.length).toBeGreaterThan(0);
    expect(seenHeaders.every(h => h === 'Authorization: Bearer test-token-xyz')).toBe(true);
  });

  it('aborts early once the first confirming site is found', async () => {
    // "quantity" reflects → should confirm and stop before sweeping other fields.
    const calls: string[] = [];
    const config: ValidatorConfig = {
      executeCommand: async (cmd: string) => {
        calls.push(cmd);
        const argv = cmd.split('\x00');
        const body = argv[argv.indexOf('--data-raw') + 1] ?? '';
        if (!body.includes('"quantity"')) return wrap('{}');
        if (body.includes('{{7*7}}')) return wrap('(49) is not valid');
        if (body.includes("{{7*'7'}}")) return wrap('(7777777) is not valid');
        if (body.includes('"notatemplate"')) return wrap('(notatemplate) is not a number');
        return wrap('');
      },
      timeout: 5000,
    };
    await validateFinding(makeFinding(), config);
    // Expected call pattern: 1 GET math probe (fails → 49 not in body), then
    // per-field POST sweep until "quantity" hits. Once confirmed, no further
    // probes. "quantity" is the first field in SSTI_BODY_FIELDS, so we
    // should see:
    //   1 GET math, 1 GET finger (short-circuited if GET math missed 49), ...
    // Actually GET math returns `{}` so skipped — validator moves to POST
    // sweep. For "quantity", sends 3 probes (math/finger/clean). Confirms.
    // Subsequent fields never attempted.
    const postBodies: string[] = [];
    for (const c of calls) {
      const argv = c.split('\x00');
      const dataIdx = argv.indexOf('--data-raw');
      if (dataIdx >= 0) postBodies.push(argv[dataIdx + 1]);
    }
    // All POST bodies should target "quantity" — we must bail before sweeping
    // other fields like "test" or "input".
    const nonQuantityPosts = postBodies.filter(b => !b.includes('"quantity"'));
    expect(nonQuantityPosts.length).toBe(0);
    // Sanity check: we DID send some POSTs.
    expect(postBodies.length).toBeGreaterThan(0);
  });
});

function wrap(body: string): { success: boolean; stdout: string; stderr: string; exitCode: number; executionTimeMs: number } {
  return { success: true, stdout: body, stderr: '', exitCode: 0, executionTimeMs: 5 };
}

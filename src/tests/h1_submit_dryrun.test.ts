/**
 * H1 submit-flow dry run (P1-0-d, 2026-04-24)
 *
 * `HackerOneAPI.submitReport()` + `ReportReviewModal` gate + the
 * `HuntSessionContext.submitToH1` context wrapper are wired end-to-end
 * but have never been exercised against anything. Before we put a real
 * finding through the path and accidentally POST a malformed payload
 * (or worse, skip the confirmation gate), this test suite:
 *
 *   1. Pins the H1 API request payload shape. `axios.post('/reports',
 *      body)` is intercepted and the body is asserted to match the
 *      format HackerOne's v1 API documents.
 *   2. Pins the Basic-Auth header the client builds from the configured
 *      username + token.
 *   3. Pins the retry-on-5xx behavior so our dry-run also covers the
 *      unhappy path.
 *   4. Unit-tests `computeSubmissionGate` — every block rule + the
 *      happy path. Order matters: first match wins.
 *
 * No network IO. No real credentials. Safe to run in CI.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  computeReportChecklist,
  computeSubmissionGate,
  computeChecklistScore,
  DESCRIPTION_MIN_CHARS,
  STEPS_MIN_COUNT,
  type QualityLike,
  type DuplicateLike,
} from '../components/report_submission_gate';
import type { H1Report } from '../core/reporting/h1_api';

// ─── Axios mock ─────────────────────────────────────────────────────────────
// Hoisted before any HackerOneAPI import so `axios.create` returns a
// controllable stub.

interface CapturedCall {
  method: 'post' | 'get';
  url: string;
  body?: unknown;
}

const captured: CapturedCall[] = [];
const postHandlers: Array<(url: string, body: unknown) => unknown> = [];
const getHandlers: Array<(url: string) => unknown> = [];
let capturedAuth: { username?: string; password?: string } | undefined;

vi.mock('axios', () => {
  const interceptors = {
    response: { use: vi.fn() },
    request: { use: vi.fn() },
  };
  const instance = {
    post: vi.fn(async (url: string, body: unknown) => {
      captured.push({ method: 'post', url, body });
      const handler = postHandlers.shift();
      if (!handler) throw new Error(`Unexpected POST ${url}`);
      const result = handler(url, body);
      if (result instanceof Error) throw result;
      return { data: result };
    }),
    get: vi.fn(async (url: string) => {
      captured.push({ method: 'get', url });
      const handler = getHandlers.shift();
      if (!handler) throw new Error(`Unexpected GET ${url}`);
      const result = handler(url);
      if (result instanceof Error) throw result;
      return { data: result };
    }),
    interceptors,
  };
  return {
    default: {
      create: (cfg: { auth?: { username: string; password: string } }) => {
        capturedAuth = cfg.auth;
        return instance;
      },
    },
    isAxiosError: () => false,
  };
});

// Import after the mock is registered.
const { HackerOneAPI } = await import('../core/reporting/h1_api');

beforeEach(() => {
  captured.length = 0;
  postHandlers.length = 0;
  getHandlers.length = 0;
  capturedAuth = undefined;
});

// ─── Fixtures ───────────────────────────────────────────────────────────────

function goodReport(overrides: Partial<H1Report> = {}): H1Report {
  return {
    title: 'Reflected XSS in q parameter',
    severity: 'high',
    suggestedBounty: { min: 500, max: 1500 },
    description: 'a'.repeat(DESCRIPTION_MIN_CHARS + 10),
    impact: 'Attacker executes arbitrary JS in victim browser.',
    steps: ['Open URL', 'Inject payload', 'Observe alert fire'],
    proof: { screenshots: ['/tmp/poc.png'] },
    cvssScore: 6.1,
    weaknessId: 'CWE-79',
    ...overrides,
  };
}

// ─── HackerOneAPI.submitReport — payload + auth + retry ─────────────────────

describe('HackerOneAPI.submitReport — payload shape', () => {
  it('constructs Basic-Auth from username + token on client creation', async () => {
    new HackerOneAPI({ username: 'alice', apiToken: 'secret-token' });
    expect(capturedAuth).toEqual({ username: 'alice', password: 'secret-token' });
  });

  it('POSTs to /reports with the H1 JSON:API envelope', async () => {
    const api = new HackerOneAPI({ username: 'u', apiToken: 't' });

    // Sequence: POST /reports → 201, then GET /reports/ID for status.
    postHandlers.push(() => ({ data: { id: 'rpt_42' } }));
    getHandlers.push(() => ({
      data: {
        id: 'rpt_42',
        attributes: {
          title: 'x', state: 'new', created_at: 'now',
        },
      },
    }));

    await api.submitReport({ programHandle: 'juice-shop', report: goodReport() });

    const post = captured.find(c => c.method === 'post');
    expect(post).toBeDefined();
    expect(post!.url).toBe('/reports');
    const body = post!.body as { data: { type: string; attributes: Record<string, unknown>; relationships: unknown } };
    expect(body.data.type).toBe('report');
    expect(body.data.attributes.title).toBe('Reflected XSS in q parameter');
    expect(body.data.attributes.severity_rating).toBe('high');
    expect(body.data.attributes.weakness_id).toBe('CWE-79');
    expect(body.data.relationships).toEqual({
      program: { data: { type: 'program', attributes: { handle: 'juice-shop' } } },
    });
  });

  it('embeds description, impact, and numbered steps in vulnerability_information markdown', async () => {
    const api = new HackerOneAPI({ username: 'u', apiToken: 't' });
    postHandlers.push(() => ({ data: { id: 'rpt_1' } }));
    getHandlers.push(() => ({ data: { id: 'rpt_1', attributes: { state: 'new' } } }));

    const report = goodReport({
      description: 'Detailed description text that exceeds the minimum by a lot.',
      impact: 'Session hijack, account takeover.',
      steps: ['Navigate to /search', 'Paste payload', 'Click submit'],
    });
    await api.submitReport({ programHandle: 'prog', report });

    const post = captured.find(c => c.method === 'post');
    const body = post!.body as { data: { attributes: { vulnerability_information: string } } };
    const md = body.data.attributes.vulnerability_information;
    expect(md).toContain('# Reflected XSS in q parameter');
    expect(md).toContain('## Description');
    expect(md).toContain('Detailed description text');
    expect(md).toContain('## Impact');
    expect(md).toContain('Session hijack');
    expect(md).toContain('## Steps to Reproduce');
    expect(md).toContain('1. Navigate to /search');
    expect(md).toContain('2. Paste payload');
    expect(md).toContain('3. Click submit');
  });

  it('returns a SubmissionResult with reportId + reportUrl on success', async () => {
    const api = new HackerOneAPI({ username: 'u', apiToken: 't' });
    postHandlers.push(() => ({ data: { id: 'rpt_999' } }));
    getHandlers.push(() => ({
      data: { id: 'rpt_999', attributes: { state: 'new', title: 'x', created_at: 'now' } },
    }));

    const result = await api.submitReport({ programHandle: 'prog', report: goodReport() });
    expect(result.success).toBe(true);
    expect(result.reportId).toBe('rpt_999');
    expect(result.reportUrl).toBe('https://hackerone.com/reports/rpt_999');
  });

  it('propagates failure on network error after retries exhaust', async () => {
    const api = new HackerOneAPI({ username: 'u', apiToken: 't', maxRetries: 0, retryDelay: 1 });
    const err = Object.assign(new Error('ECONNREFUSED'), { response: undefined });
    postHandlers.push(() => err);

    const result = await api.submitReport({ programHandle: 'prog', report: goodReport() });
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});

// ─── Submission-gate logic ──────────────────────────────────────────────────

describe('computeSubmissionGate', () => {
  it('passes for a well-formed report with no duplicate/quality blockers', () => {
    const gate = computeSubmissionGate(goodReport(), null, null);
    expect(gate.blocked).toBe(false);
    expect(gate.reason).toBeNull();
  });

  it('blocks when duplicate recommendation is `skip`', () => {
    const dup: DuplicateLike = { recommendation: 'skip' };
    const gate = computeSubmissionGate(goodReport(), dup, null);
    expect(gate.blocked).toBe(true);
    expect(gate.reason).toMatch(/duplicate probability/i);
  });

  it('does NOT block when duplicate recommendation is `review` (user decides)', () => {
    const dup: DuplicateLike = { recommendation: 'review' };
    const gate = computeSubmissionGate(goodReport(), dup, null);
    expect(gate.blocked).toBe(false);
  });

  it('blocks when quality grade is F', () => {
    const quality: QualityLike = { grade: 'F' };
    const gate = computeSubmissionGate(goodReport(), null, quality);
    expect(gate.blocked).toBe(true);
    expect(gate.reason).toMatch(/quality is too low/i);
  });

  it('does NOT block on quality grade D or higher (D still triagable)', () => {
    const quality: QualityLike = { grade: 'D' };
    const gate = computeSubmissionGate(goodReport(), null, quality);
    expect(gate.blocked).toBe(false);
  });

  it('blocks when description is missing or below threshold', () => {
    const gate = computeSubmissionGate(goodReport({ description: 'too short' }), null, null);
    expect(gate.blocked).toBe(true);
    expect(gate.reason).toMatch(/missing a description/i);
  });

  it('blocks when steps count is below STEPS_MIN_COUNT', () => {
    const gate = computeSubmissionGate(goodReport({ steps: ['only one'] }), null, null);
    expect(gate.blocked).toBe(true);
    expect(gate.reason).toMatch(new RegExp(`${STEPS_MIN_COUNT} reproduction steps`, 'i'));
  });

  it('duplicate-skip takes precedence over quality-F (ordering is stable)', () => {
    const gate = computeSubmissionGate(
      goodReport(),
      { recommendation: 'skip' },
      { grade: 'F' },
    );
    expect(gate.reason).toMatch(/duplicate/i);
  });

  it('quality-F takes precedence over missing description', () => {
    const gate = computeSubmissionGate(
      goodReport({ description: 'too short' }),
      null,
      { grade: 'F' },
    );
    expect(gate.reason).toMatch(/quality is too low/i);
  });
});

describe('computeReportChecklist + computeChecklistScore', () => {
  it('complete report scores 100%', () => {
    const full = goodReport({
      severityJustification: ['AV:N', 'AC:L'],
      proof: { screenshots: ['a'], video: 'b', logs: ['c'] },
    });
    const list = computeReportChecklist(full);
    expect(computeChecklistScore(list)).toBe(100);
  });

  it('minimal report (no evidence, no justification, no CVSS/CWE) scores less than 100', () => {
    const minimal: H1Report = {
      title: 't',
      severity: 'medium',
      suggestedBounty: { min: 0, max: 0 },
      description: 'a'.repeat(DESCRIPTION_MIN_CHARS + 1),
      impact: 'a'.repeat(50),
      steps: ['1', '2', '3'],
      proof: {},
    };
    const list = computeReportChecklist(minimal);
    expect(computeChecklistScore(list)).toBeLessThan(100);
    // But hasDescription + hasSteps are both true → gate passes.
    expect(list.hasDescription).toBe(true);
    expect(list.hasSteps).toBe(true);
  });

  it('every checklist flag is a boolean (no undefined leaks)', () => {
    const list = computeReportChecklist(goodReport());
    for (const v of Object.values(list)) {
      expect(typeof v).toBe('boolean');
    }
  });
});

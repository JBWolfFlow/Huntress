/**
 * Phase 1 / Q2 — ReactLoop auth section system-prompt tests
 *
 * Validates buildAuthSection's contract:
 *   - emitted only when authSessionId + sessionManager resolve to a session
 *   - includes label, auth type, header names, cookie count, CSRF presence
 *   - multi-identity hints only when listSessions().length > 1
 *   - never instructs the agent to log in
 *   - tells the agent 401 is not a finding
 *
 * Tests access the private helper via the `any`-cast idiom. That's standard
 * for vitest private-method testing and lets us assert on exact output rather
 * than round-tripping through a mocked provider.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ReactLoop } from '../core/engine/react_loop';
import type { ReactLoopConfig } from '../core/engine/react_loop';
import { SessionManager } from '../core/auth/session_manager';
import type {
  ModelProvider,
  ChatMessage,
  ChatResponse,
  SendMessageOptions,
  StreamChunk,
  ModelInfo,
} from '../core/providers/types';
import type { HttpClient, HttpRequestOptions, HttpResponse, Cookie } from '../core/http/request_engine';
import { vi } from 'vitest';

// ─── Shared mocks ───────────────────────────────────────────────────────────

const noopProvider: ModelProvider = {
  providerId: 'mock',
  displayName: 'Mock',
  async sendMessage(_m: ChatMessage[], options: SendMessageOptions): Promise<ChatResponse> {
    return {
      content: '',
      model: options.model,
      inputTokens: 0,
      outputTokens: 0,
      stopReason: 'end_turn',
      toolCalls: [],
      contentBlocks: [],
    };
  },
  async *streamMessage(_m: ChatMessage[], _o: SendMessageOptions): AsyncGenerator<StreamChunk> {
    yield { type: 'message_stop', inputTokens: 0, outputTokens: 0 };
  },
  getAvailableModels(): ModelInfo[] {
    return [{
      id: 'mock', displayName: 'Mock', contextWindow: 128000, maxOutputTokens: 4096,
      supportsStreaming: true, supportsSystemPrompt: true,
      inputCostPer1M: 0, outputCostPer1M: 0,
    }];
  },
  async validateApiKey(_key: string): Promise<boolean> { return true; },
  estimateCost(_i: number, _o: number, _m: string): number { return 0; },
};

function cookie(name: string, value: string): Cookie {
  return { name, value, domain: 'target.com', path: '/', httpOnly: false, secure: false };
}

function mockHttpClient(): HttpClient {
  return {
    request: vi.fn(async (_o: HttpRequestOptions): Promise<HttpResponse> => ({
      status: 200, statusText: 'OK', headers: {}, body: '', cookies: [],
      timing: { dnsMs: 0, connectMs: 0, ttfbMs: 0, totalMs: 0 },
      redirectChain: [], size: 0,
    })),
    getCookies: (_d: string): Cookie[] => [],
  } as unknown as HttpClient;
}

function makeConfig(overrides: Partial<ReactLoopConfig> = {}): ReactLoopConfig {
  return {
    provider: noopProvider,
    model: 'mock',
    systemPrompt: 'You are a security tester.',
    goal: 'Test target',
    tools: [],
    target: 'https://target.com',
    scope: ['target.com'],
    maxIterations: 1,
    ...overrides,
  };
}

/** Invoke the private buildAuthSection helper through a type-cast. */
function callBuildAuthSection(loop: ReactLoop): string {
  return (loop as unknown as { buildAuthSection: () => string }).buildAuthSection();
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('buildAuthSection — conditional injection (Q2)', () => {
  it('returns empty string when no authSessionId is configured', () => {
    const loop = new ReactLoop(makeConfig());
    expect(callBuildAuthSection(loop)).toBe('');
  });

  it('returns empty string when authSessionId is set but no sessionManager', () => {
    const loop = new ReactLoop(makeConfig({ authSessionId: 'sess-1' }));
    expect(callBuildAuthSection(loop)).toBe('');
  });

  it('returns empty string when the referenced session is not found', () => {
    const sm = new SessionManager(mockHttpClient());
    const loop = new ReactLoop(makeConfig({
      authSessionId: 'does-not-exist',
      sessionManager: sm,
    }));
    expect(callBuildAuthSection(loop)).toBe('');
  });
});

describe('buildAuthSection — content shape for each auth type (Q2)', () => {
  let sm: SessionManager;

  beforeEach(() => {
    sm = new SessionManager(mockHttpClient());
  });

  it('renders bearer session: label, type=bearer, Authorization header', () => {
    sm.createSession({ id: 's', label: 'victim', authType: 'bearer' });
    const sess = sm.getSession('s')!;
    sess.headers = { Authorization: 'Bearer t' };

    const out = callBuildAuthSection(
      new ReactLoop(makeConfig({ authSessionId: 's', sessionManager: sm })),
    );

    expect(out).toContain('## Active Authentication');
    expect(out).toContain('Session label: victim');
    expect(out).toContain('Auth type: bearer');
    expect(out).toContain('Auth headers: Authorization');
    expect(out).toContain('Identities available: 1');
  });

  it('renders cookie session with CSRF: shows cookie count and CSRF marker', () => {
    sm.createSession({ id: 's', label: 'user-a', authType: 'cookie' });
    const sess = sm.getSession('s')!;
    sess.cookies = [cookie('session', 'abc'), cookie('csrf', 'nonce')];
    sess.csrfToken = 'csrf-nonce';

    const out = callBuildAuthSection(
      new ReactLoop(makeConfig({ authSessionId: 's', sessionManager: sm })),
    );
    expect(out).toContain('Session cookies: 2');
    expect(out).toContain('CSRF token: present');
  });

  it('renders custom_header session with multiple Telegram-shaped headers', () => {
    sm.createSession({ id: 's', label: 'wallet-victim', authType: 'custom_header' });
    const sess = sm.getSession('s')!;
    sess.headers = {
      'wallet-authorization': 'jwt',
      'x-wallet-device-serial': 'uuid',
    };

    const out = callBuildAuthSection(
      new ReactLoop(makeConfig({ authSessionId: 's', sessionManager: sm })),
    );
    expect(out).toContain('Auth type: custom_header');
    expect(out).toContain('wallet-authorization');
    expect(out).toContain('x-wallet-device-serial');
  });
});

describe('buildAuthSection — multi-identity gating (Q2/Q3)', () => {
  it('omits the multi-identity hint block when only one identity is active', () => {
    const sm = new SessionManager(mockHttpClient());
    sm.createSession({ id: 'a', label: 'solo', authType: 'bearer' });
    sm.getSession('a')!.headers = { Authorization: 'Bearer t' };

    const out = callBuildAuthSection(
      new ReactLoop(makeConfig({ authSessionId: 'a', sessionManager: sm })),
    );
    expect(out).toContain('Identities available: 1');
    // The dedicated multi-identity-instructions block and the "Available
    // session labels:" enumeration must NOT appear for single-session agents
    // — saves prompt tokens and avoids agents requesting a non-existent label.
    // (Note: the generic 403/IDOR safety line still mentions session_label —
    //  that's intentional and applies even when only one identity is loaded,
    //  because the agent can be told mid-hunt to acquire a second one.)
    expect(out).not.toContain('Multi-identity testing:');
    expect(out).not.toContain('Available session labels:');
  });

  it('includes session_label + available labels when 2+ identities present', () => {
    const sm = new SessionManager(mockHttpClient());
    sm.createSession({ id: 'v', label: 'victim', authType: 'bearer' });
    sm.createSession({ id: 'a', label: 'attacker', authType: 'bearer' });
    sm.getSession('v')!.headers = { Authorization: 'Bearer v' };
    sm.getSession('a')!.headers = { Authorization: 'Bearer a' };

    const out = callBuildAuthSection(
      new ReactLoop(makeConfig({ authSessionId: 'v', sessionManager: sm })),
    );
    expect(out).toContain('Identities available: 2');
    expect(out).toContain('session_label');
    expect(out).toContain('"victim"');
    expect(out).toContain('"attacker"');
    expect(out).toContain('IDOR/BOLA');
  });
});

describe('buildAuthSection — safety instructions (Q2)', () => {
  let sm: SessionManager;
  let out: string;

  beforeEach(() => {
    sm = new SessionManager(mockHttpClient());
    sm.createSession({ id: 's', label: 'victim', authType: 'bearer' });
    sm.getSession('s')!.headers = { Authorization: 'Bearer t' };
    out = callBuildAuthSection(
      new ReactLoop(makeConfig({ authSessionId: 's', sessionManager: sm })),
    );
  });

  it('tells the agent that 401 is not a finding', () => {
    expect(out).toMatch(/401.*NOT a finding/i);
  });

  it('instructs the agent to prefer http_request', () => {
    expect(out).toContain('Prefer `http_request`');
  });

  it('explains HUNTRESS_AUTH_* env vars and ~/.curlrc for shell tools', () => {
    expect(out).toContain('HUNTRESS_AUTH_');
    expect(out).toContain('~/.curlrc');
  });

  it('explicitly forbids the agent from attempting to log in', () => {
    expect(out).toMatch(/do not attempt to log in/i);
    expect(out).toMatch(/do not.*submit credentials/i);
  });

  it('tells the agent to redact tokens in findings', () => {
    expect(out).toMatch(/<REDACTED>/);
    expect(out).toMatch(/do not paste auth tokens/i);
  });
});

/**
 * P1-1 v4 — XBOW Full Capability Wiring
 *
 * Pins the contract that the XBOW benchmark runner now dispatches the
 * REAL Huntress specialist hunters (not the stub 3-tool CTF agent that
 * scored 0/104 in the 2026-05-02 first run). Three behaviors must hold:
 *
 *   1. selectAgentForChallenge() picks the right specialist for each
 *      challenge tag, with a sane fallback chain.
 *   2. extractFlagFromAgentRun() finds FLAG{...} in any text source the
 *      agent emits — HTTP response bodies, evidence, descriptions,
 *      titles, reproduction commands.
 *   3. Every agent ID referenced in XBOW_TAG_TO_AGENT_ID is actually
 *      registered in the catalog (regression for the side-effect import
 *      that wires all 27 hunters into the runner).
 */

import { describe, it, expect } from 'vitest';
import '../agents/standardized_agents'; // ensure registration before catalog reads
import { getAgentEntry } from '../agents/agent_catalog';
import {
  XBOW_TAG_TO_AGENT_ID,
  selectAgentForChallenge,
  extractFlagFromAgentRun,
  type Challenge,
} from '../core/benchmark/xbow_runner';
import type { AgentFinding, HttpExchange } from '../agents/base_agent';

function ch(overrides: Partial<Challenge> = {}): Challenge {
  return {
    id: 'XBEN-test',
    name: 'Test Challenge',
    description: 'A synthetic challenge',
    level: 1,
    tags: [],
    winCondition: 'flag',
    directory: '/tmp/test',
    ...overrides,
  };
}

function finding(overrides: Partial<AgentFinding> = {}): AgentFinding {
  return {
    id: 'F-test',
    agentId: 'test-agent',
    type: 'test',
    title: '',
    severity: 'medium',
    description: '',
    target: 'https://target/',
    evidence: [],
    reproduction: [],
    timestamp: new Date(),
    ...overrides,
  };
}

function exchange(bodySnippet: string): HttpExchange {
  return {
    request: { method: 'GET', url: 'https://target/', headers: {} },
    response: {
      status: 200,
      headers: {},
      bodySnippet,
    },
    timestamp: Date.now(),
  };
}

// ─── selectAgentForChallenge ────────────────────────────────────────────────

describe('selectAgentForChallenge — direct tag mapping', () => {
  it('routes sqli challenges to sqli-hunter', () => {
    expect(selectAgentForChallenge(ch({ tags: ['sqli'] }))).toBe('sqli-hunter');
  });

  it('routes xss challenges to xss-hunter', () => {
    expect(selectAgentForChallenge(ch({ tags: ['xss'] }))).toBe('xss-hunter');
  });

  it('routes ssti challenges to ssti-hunter', () => {
    expect(selectAgentForChallenge(ch({ tags: ['ssti'] }))).toBe('ssti-hunter');
  });

  it('routes idor / privilege_escalation / default_credentials all to idor-hunter', () => {
    expect(selectAgentForChallenge(ch({ tags: ['idor'] }))).toBe('idor-hunter');
    expect(selectAgentForChallenge(ch({ tags: ['privilege_escalation'] }))).toBe('idor-hunter');
    expect(selectAgentForChallenge(ch({ tags: ['default_credentials'] }))).toBe('idor-hunter');
  });

  it('routes ssrf challenges to ssrf-hunter', () => {
    expect(selectAgentForChallenge(ch({ tags: ['ssrf'] }))).toBe('ssrf-hunter');
  });

  it('routes lfi / path_traversal / arbitrary_file_upload to path-traversal-hunter', () => {
    expect(selectAgentForChallenge(ch({ tags: ['lfi'] }))).toBe('path-traversal-hunter');
    expect(selectAgentForChallenge(ch({ tags: ['path_traversal'] }))).toBe('path-traversal-hunter');
    expect(selectAgentForChallenge(ch({ tags: ['arbitrary_file_upload'] }))).toBe('path-traversal-hunter');
  });

  it('routes jwt and crypto challenges to jwt-hunter', () => {
    expect(selectAgentForChallenge(ch({ tags: ['jwt'] }))).toBe('jwt-hunter');
    expect(selectAgentForChallenge(ch({ tags: ['crypto'] }))).toBe('jwt-hunter');
  });

  it('routes graphql challenges to graphql-hunter', () => {
    expect(selectAgentForChallenge(ch({ tags: ['graphql'] }))).toBe('graphql-hunter');
  });

  it('routes command_injection to command-injection-hunter', () => {
    expect(selectAgentForChallenge(ch({ tags: ['command_injection'] }))).toBe('command-injection-hunter');
  });

  it('routes xxe to xxe-hunter and nosqli to nosql-hunter', () => {
    expect(selectAgentForChallenge(ch({ tags: ['xxe'] }))).toBe('xxe-hunter');
    expect(selectAgentForChallenge(ch({ tags: ['nosqli'] }))).toBe('nosql-hunter');
  });

  it('routes race_condition / smuggling_desync / business_logic / insecure_deserialization correctly', () => {
    expect(selectAgentForChallenge(ch({ tags: ['race_condition'] }))).toBe('race-condition-hunter');
    expect(selectAgentForChallenge(ch({ tags: ['smuggling_desync'] }))).toBe('http-smuggling-hunter');
    expect(selectAgentForChallenge(ch({ tags: ['business_logic'] }))).toBe('business-logic-hunter');
    expect(selectAgentForChallenge(ch({ tags: ['insecure_deserialization'] }))).toBe('deserialization-hunter');
  });

  it('first matching tag wins when a challenge has multiple tags', () => {
    expect(selectAgentForChallenge(ch({ tags: ['sqli', 'xss'] }))).toBe('sqli-hunter');
    expect(selectAgentForChallenge(ch({ tags: ['xss', 'sqli'] }))).toBe('xss-hunter');
  });
});

describe('selectAgentForChallenge — fallback chain', () => {
  it('falls back to recon when tag matches nothing', () => {
    const agentId = selectAgentForChallenge(ch({ tags: ['totally-fictional-vuln-class-xyz-123'] }));
    expect(agentId).toBe('recon');
  });

  it('falls back to recon when tags array is empty', () => {
    expect(selectAgentForChallenge(ch({ tags: [] }))).toBe('recon');
  });

  it('returns a registered agent id from any fallback path', () => {
    // Whatever the fuzzy lookup returns must be a real catalog entry,
    // otherwise the runner crashes when it calls factory().
    const agentId = selectAgentForChallenge(ch({ tags: ['unknown-tag-xyz'] }));
    expect(getAgentEntry(agentId)).toBeDefined();
  });
});

// ─── XBOW_TAG_TO_AGENT_ID catalog regression ────────────────────────────────

describe('XBOW_TAG_TO_AGENT_ID — every agent is actually registered', () => {
  it('every mapped agent ID exists in the agent catalog', () => {
    const missing: Array<{ tag: string; agentId: string }> = [];
    for (const [tag, agentId] of Object.entries(XBOW_TAG_TO_AGENT_ID)) {
      if (!getAgentEntry(agentId)) {
        missing.push({ tag, agentId });
      }
    }
    expect(missing).toEqual([]);
  });

  it('recon fallback agent is registered', () => {
    expect(getAgentEntry('recon')).toBeDefined();
  });
});

// ─── extractFlagFromAgentRun ────────────────────────────────────────────────

describe('extractFlagFromAgentRun — HTTP exchange scanning (preferred)', () => {
  it('finds FLAG{...} in response bodySnippet', () => {
    const flag = extractFlagFromAgentRun(
      [],
      [exchange('Welcome admin! Your secret: FLAG{server_pwned_2026}')],
    );
    expect(flag).toBe('FLAG{server_pwned_2026}');
  });

  it('finds lowercase flag{...} too', () => {
    const flag = extractFlagFromAgentRun([], [exchange('Hidden: flag{lowercase_match}')]);
    expect(flag).toBe('flag{lowercase_match}');
  });

  it('returns the FIRST flag when multiple are present in one body', () => {
    const flag = extractFlagFromAgentRun(
      [],
      [exchange('FLAG{first} and later FLAG{second}')],
    );
    expect(flag).toBe('FLAG{first}');
  });

  it('scans HTTP exchanges before findings', () => {
    // Exchange has the real flag, finding has a fake — exchange must win.
    const flag = extractFlagFromAgentRun(
      [finding({ evidence: ['FLAG{from_finding}'] })],
      [exchange('Server response: FLAG{from_http}')],
    );
    expect(flag).toBe('FLAG{from_http}');
  });
});

describe('extractFlagFromAgentRun — finding text scanning (fallback)', () => {
  it('finds FLAG{...} in finding.evidence', () => {
    const flag = extractFlagFromAgentRun(
      [finding({ evidence: ['Extracted via SQL: FLAG{sqli_pwned}'] })],
      [],
    );
    expect(flag).toBe('FLAG{sqli_pwned}');
  });

  it('finds FLAG{...} in finding.description', () => {
    const flag = extractFlagFromAgentRun(
      [finding({ description: 'Got the flag: FLAG{from_desc}' })],
      [],
    );
    expect(flag).toBe('FLAG{from_desc}');
  });

  it('finds FLAG{...} in finding.title', () => {
    const flag = extractFlagFromAgentRun(
      [finding({ title: 'Discovered FLAG{title_match}' })],
      [],
    );
    expect(flag).toBe('FLAG{title_match}');
  });

  it('finds FLAG{...} in finding.reproduction commands', () => {
    const flag = extractFlagFromAgentRun(
      [finding({ reproduction: ['curl https://target/admin → FLAG{repro_match}'] })],
      [],
    );
    expect(flag).toBe('FLAG{repro_match}');
  });

  it('returns undefined when no flag is anywhere', () => {
    const flag = extractFlagFromAgentRun(
      [finding({ evidence: ['ordinary finding text'], description: 'no flag here' })],
      [exchange('200 OK, nothing of note')],
    );
    expect(flag).toBeUndefined();
  });

  it('returns undefined for empty inputs', () => {
    expect(extractFlagFromAgentRun([], [])).toBeUndefined();
  });

  it('handles findings with empty optional fields without throwing', () => {
    const minimal: AgentFinding = {
      id: 'F-min',
      agentId: 'test',
      type: 'test',
      title: 'no flag',
      severity: 'low',
      description: 'no flag',
      target: 'https://target/',
      evidence: [],
      reproduction: [],
      timestamp: new Date(),
    };
    expect(() => extractFlagFromAgentRun([minimal], [])).not.toThrow();
  });
});

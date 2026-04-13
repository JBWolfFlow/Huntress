/**
 * Hunt #7 Bug Fix — H26: Cross-Hunt Duplicate Detection
 *
 * Tests that HuntMemory.checkDuplicate() and queryPastFindingsForTarget()
 * can detect findings from previous hunt sessions.
 */

import { describe, it, expect } from 'vitest';
import { HuntMemory } from '../core/memory/hunt_memory';
import type { AgentFindingInput } from '../core/memory/hunt_memory';

// ─── Mock Qdrant Client ───────────────────────────────────────────────────

function createMockQdrant(storedFindings: Array<{ title: string; vulnType: string; target: string; score: number; sessionId: string }>) {
  return {
    initializeCollection: async () => {},
    upsertPoint: async () => {},
    search: async () => [],
    searchWithFilter: async (_vector: number[], filter: Record<string, string>, _limit: number) => {
      if (filter.type === 'finding') {
        return storedFindings.map((f, i) => ({
          id: `finding_${i}`,
          score: f.score,
          payload: {
            type: 'finding',
            title: f.title,
            vulnType: f.vulnType,
            target: f.target,
            severity: 'high',
            sessionId: f.sessionId,
            timestamp: Date.now() - 86400000, // 1 day ago
          },
        }));
      }
      return [];
    },
  };
}

function makeFindingInput(overrides: Partial<AgentFindingInput> = {}): AgentFindingInput {
  return {
    title: 'Host Header Injection via X-Forwarded-Host',
    vulnerabilityType: 'host_header_injection',
    severity: 'medium',
    target: 'https://wallet.telegram.org',
    description: 'X-Forwarded-Host header reflected in response',
    evidence: ['curl -H "X-Forwarded-Host: evil.com" returned reflected header'],
    confidence: 60,
    ...overrides,
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('Cross-Hunt Duplicate Detection (H26)', () => {
  it('detects duplicate finding from previous session', async () => {
    const qdrant = createMockQdrant([{
      title: 'Host Header Injection via X-Forwarded-Host',
      vulnType: 'host_header_injection',
      target: 'https://wallet.telegram.org',
      score: 0.92, // Above 0.85 threshold
      sessionId: 'hunt-session-1',
    }]);

    const memory = new HuntMemory(qdrant as never);
    await memory.initialize();

    const finding = makeFindingInput();
    const result = await memory.checkDuplicate(finding);

    expect(result.isDuplicate).toBe(true);
    expect(result.similarFinding).toBeDefined();
    expect(result.similarFinding!.score).toBeGreaterThanOrEqual(0.85);
  });

  it('does not flag unique findings as duplicates', async () => {
    const qdrant = createMockQdrant([{
      title: 'Some Other Finding',
      vulnType: 'xss_reflected',
      target: 'https://other-target.com',
      score: 0.3, // Below threshold
      sessionId: 'hunt-session-1',
    }]);

    const memory = new HuntMemory(qdrant as never);
    await memory.initialize();

    const finding = makeFindingInput();
    const result = await memory.checkDuplicate(finding);

    expect(result.isDuplicate).toBe(false);
  });

  it('queries past findings for target domain', async () => {
    const qdrant = createMockQdrant([
      {
        title: 'CORS Misconfiguration',
        vulnType: 'cors_misconfiguration',
        target: 'https://wallet.telegram.org/api',
        score: 0.88,
        sessionId: 'hunt-session-1',
      },
      {
        title: 'Host Header Injection',
        vulnType: 'host_header_injection',
        target: 'https://wallet.telegram.org',
        score: 0.91,
        sessionId: 'hunt-session-1',
      },
    ]);

    const memory = new HuntMemory(qdrant as never);
    await memory.initialize();

    const results = await memory.queryPastFindingsForTarget('https://wallet.telegram.org');

    expect(results.length).toBeGreaterThan(0);
    expect(results[0].title).toBeTruthy();
    expect(results[0].sessionId).toBe('hunt-session-1');
  });

  it('gracefully degrades when Qdrant is unavailable', async () => {
    const memory = new HuntMemory(null);
    await memory.initialize();

    const finding = makeFindingInput();
    const result = await memory.checkDuplicate(finding);

    expect(result.isDuplicate).toBe(false);
  });

  it('records finding for future cross-hunt detection', async () => {
    let storedPoint: Record<string, unknown> | null = null;
    const qdrant = {
      initializeCollection: async () => {},
      upsertPoint: async (point: Record<string, unknown>) => {
        storedPoint = point;
      },
      search: async () => [],
      searchWithFilter: async () => [],
    };

    const memory = new HuntMemory(qdrant as never);
    await memory.initialize();

    await memory.recordFinding(makeFindingInput(), 'hunt-session-2');

    expect(storedPoint).not.toBeNull();
    expect((storedPoint as Record<string, unknown>).payload).toBeDefined();
  });
});

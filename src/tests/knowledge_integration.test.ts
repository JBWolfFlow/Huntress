/**
 * Knowledge Integration Tests
 *
 * Tests the wiring of KnowledgeGraph, RewardSystem, VulnDatabase, and
 * SASTAnalyzer into the orchestrator and session context.
 *
 * Note: In vitest (non-Tauri), the SQLite bridge returns no-op results.
 * These tests verify the modules initialize, accept inputs, and return
 * well-typed results without crashing — not actual persistence.
 */

import { describe, it, expect, vi } from 'vitest';
import { KnowledgeGraph } from '../core/knowledge/knowledge_graph';
import type { HuntResult, LearnedPattern, OverallStats } from '../core/knowledge/knowledge_graph';
import { RewardSystem } from '../core/training/reward_system';
import type { TrustLevel, RewardMetrics } from '../core/training/reward_system';
import { VulnDatabase } from '../core/knowledge/vuln_database';
import { SASTAnalyzer } from '../core/sast/sast_analyzer';
import type { ModelProvider, ChatMessage, SendMessageOptions, ChatResponse } from '../core/providers/types';

// ─── Mock Provider ────────────────────────────────────────────────────────────

function createMockProvider(responseContent: string = '[]'): ModelProvider {
  return {
    displayName: 'MockProvider',
    sendMessage: vi.fn(async (_msgs: ChatMessage[], _opts: SendMessageOptions): Promise<ChatResponse> => ({
      content: responseContent,
      model: 'mock-model',
      usage: { inputTokens: 10, outputTokens: 20, totalTokens: 30 },
      stopReason: 'end_turn',
    })),
    streamMessage: vi.fn(async function* () {
      yield { type: 'text' as const, text: responseContent };
    }),
    getAvailableModels: vi.fn(() => [{ id: 'mock-model', name: 'Mock', contextWindow: 4096 }]),
    validateApiKey: vi.fn(async () => true),
    estimateCost: vi.fn(() => ({ inputCost: 0, outputCost: 0, totalCost: 0 })),
  };
}

// ─── KnowledgeGraph Tests ────────────────────────────────────────────────────

describe('KnowledgeGraph', () => {
  it('initializes without error', async () => {
    const kg = new KnowledgeGraph('test_kg.db');
    await kg.initialize();
    expect(kg).toBeDefined();
  });

  it('records hunt result without crashing', async () => {
    const kg = new KnowledgeGraph('test_kg.db');
    await kg.initialize();

    const result: HuntResult = {
      sessionId: 'session-1',
      target: 'https://example.com',
      agentId: 'oauth-hunter',
      vulnType: 'oauth_redirect_uri',
      findingTitle: 'Open Redirect via redirect_uri',
      severity: 'high',
      success: true,
      bountyAmount: 500,
      techniquesUsed: ['redirect_uri_manipulation'],
      durationMs: 30000,
      modelUsed: 'claude-sonnet-4-6',
      tokensUsed: 5000,
      costUsd: 0.05,
    };

    const id = await kg.recordHuntResult(result);
    expect(typeof id).toBe('string');
    expect(id.length).toBeGreaterThan(0);
  });

  it('records learned patterns without crashing', async () => {
    const kg = new KnowledgeGraph('test_kg.db');
    await kg.initialize();

    const pattern: LearnedPattern = {
      patternType: 'vuln_technique',
      patternKey: 'oauth_redirect_uri',
      patternValue: 'Try ..%2f..%2f bypass on redirect_uri validation',
      confidence: 0.8,
      source: 'session-1',
    };

    const id = await kg.recordLearnedPattern(pattern);
    expect(typeof id).toBe('string');
  });

  it('queries relevant patterns (returns array)', async () => {
    const kg = new KnowledgeGraph('test_kg.db');
    await kg.initialize();

    const patterns = await kg.queryRelevantPatterns('example.com', 'xss');
    expect(Array.isArray(patterns)).toBe(true);
  });

  it('returns overall stats with correct shape', async () => {
    const kg = new KnowledgeGraph('test_kg.db');
    await kg.initialize();

    const stats: OverallStats = await kg.getOverallStats();
    expect(typeof stats.totalHunts).toBe('number');
    expect(typeof stats.successRate).toBe('number');
    expect(typeof stats.totalBounties).toBe('number');
    expect(typeof stats.avgBounty).toBe('number');
    expect(Array.isArray(stats.topVulnTypes)).toBe(true);
    expect(Array.isArray(stats.topAgents)).toBe(true);
    expect(['improving', 'stable', 'declining']).toContain(stats.recentTrend);
  });

  it('returns best techniques for a vuln type', async () => {
    const kg = new KnowledgeGraph('test_kg.db');
    await kg.initialize();

    const techniques = await kg.getBestTechniquesFor('sqli');
    expect(Array.isArray(techniques)).toBe(true);
  });

  it('returns agent performance with correct shape', async () => {
    const kg = new KnowledgeGraph('test_kg.db');
    await kg.initialize();

    const perf = await kg.getAgentPerformance('oauth-hunter');
    expect(typeof perf.agentId).toBe('string');
    expect(typeof perf.totalHunts).toBe('number');
    expect(typeof perf.successes).toBe('number');
    expect(typeof perf.failures).toBe('number');
    expect(typeof perf.successRate).toBe('number');
  });
});

// ─── RewardSystem Tests ──────────────────────────────────────────────────────

describe('RewardSystem', () => {
  it('initializes without error', async () => {
    const reward = new RewardSystem('test_reward.db');
    await reward.initialize();
    expect(reward).toBeDefined();
  });

  it('records events without crashing', async () => {
    const reward = new RewardSystem('test_reward.db');
    await reward.initialize();

    const id = await reward.recordEvent({
      sessionId: 'session-1',
      agentId: 'oauth-hunter',
      eventType: 'FINDING_REPORTED',
      reason: 'Found open redirect',
    });
    expect(typeof id).toBe('string');
    expect(id.length).toBeGreaterThan(0);
  });

  it('returns a valid trust level for any agent', async () => {
    const reward = new RewardSystem('test_reward.db');
    await reward.initialize();

    const trust: TrustLevel = await reward.getTrustLevel('new-agent');
    expect(['untrusted', 'basic', 'trusted', 'expert']).toContain(trust);
  });

  it('returns recommended model from available tiers', async () => {
    const reward = new RewardSystem('test_reward.db');
    await reward.initialize();

    const model = await reward.getRecommendedModel('test-agent', ['tier1', 'tier2', 'tier3']);
    expect(typeof model).toBe('string');
  });

  it('returns auto-approve categories array', async () => {
    const reward = new RewardSystem('test_reward.db');
    await reward.initialize();

    const categories = await reward.getRecommendedAutoApproveLevel('test-agent');
    expect(Array.isArray(categories)).toBe(true);
  });

  it('detects shortcuts in findings', async () => {
    const reward = new RewardSystem('test_reward.db');
    await reward.initialize();

    const shortcuts = await reward.detectShortcuts([
      {
        findingTitle: 'Critical RCE',
        severity: 'critical',
        iterations: 1,
        agentId: 'fast-agent',
      },
    ]);

    expect(Array.isArray(shortcuts)).toBe(true);
    // At minimum, a 1-iteration critical finding should trigger some detection
    expect(shortcuts.length).toBeGreaterThanOrEqual(1);
    expect(shortcuts[0].agentId).toBe('fast-agent');
    // The exact type depends on which shortcut fires first — just verify it's valid
    expect(['severity_inflation', 'copy_paste', 'missing_repro', 'suspiciously_fast']).toContain(shortcuts[0].shortcutType);
  });

  it('exports metrics with correct shape', async () => {
    const reward = new RewardSystem('test_reward.db');
    await reward.initialize();

    const metrics: RewardMetrics = await reward.exportMetrics();
    expect(typeof metrics.totalPoints).toBe('number');
    expect(typeof metrics.totalEvents).toBe('number');
    expect(typeof metrics.positiveRatio).toBe('number');
    expect(Array.isArray(metrics.topRewardTypes)).toBe(true);
    expect(Array.isArray(metrics.topPenaltyTypes)).toBe(true);
  });

  it('returns leaderboard with correct shape', async () => {
    const reward = new RewardSystem('test_reward.db');
    await reward.initialize();

    const leaderboard = await reward.getLeaderboard();
    expect(Array.isArray(leaderboard)).toBe(true);
  });
});

// ─── VulnDatabase Tests ──────────────────────────────────────────────────────

describe('VulnDatabase', () => {
  it('initializes without error', async () => {
    const vulnDb = new VulnDatabase('test_vulndb.db');
    await vulnDb.initialize();
    expect(vulnDb).toBeDefined();
  });

  it('returns vuln context with bundled CWE data', async () => {
    const vulnDb = new VulnDatabase('test_vulndb.db');
    await vulnDb.initialize();

    const context = await vulnDb.getVulnContext('xss');
    expect(context.vulnType).toBe('xss');
    expect(context.cweIds.length).toBeGreaterThanOrEqual(1);
    expect(context.cweInfo.length).toBeGreaterThanOrEqual(1);
    expect(context.cweInfo[0].cweId).toBe('CWE-79');
  });

  it('returns relevant knowledge for agent context', async () => {
    const vulnDb = new VulnDatabase('test_vulndb.db');
    await vulnDb.initialize();

    const knowledge = await vulnDb.getRelevantKnowledge('sqli', 'https://example.com');
    expect(knowledge.agentType).toBe('sqli');
    expect(knowledge.target).toBe('https://example.com');
    expect(Array.isArray(knowledge.cweInfo)).toBe(true);
    expect(Array.isArray(knowledge.attackPatterns)).toBe(true);
  });

  it('returns CWE info for all mapped vuln types', async () => {
    const vulnDb = new VulnDatabase('test_vulndb.db');
    await vulnDb.initialize();

    const vulnTypes = ['xss', 'sqli', 'ssrf', 'csrf', 'command_injection', 'xxe', 'path_traversal'];
    for (const vt of vulnTypes) {
      const ctx = await vulnDb.getVulnContext(vt);
      expect(ctx.cweIds.length).toBeGreaterThanOrEqual(1);
    }
  });
});

// ─── SASTAnalyzer Tests ──────────────────────────────────────────────────────

describe('SASTAnalyzer', () => {
  it('constructs with a provider and model', () => {
    const provider = createMockProvider();
    const analyzer = new SASTAnalyzer(provider, 'mock-model');
    expect(analyzer).toBeDefined();
  });

  it('analyzes a code snippet without crashing', async () => {
    const provider = createMockProvider('No vulnerabilities found.');
    const analyzer = new SASTAnalyzer(provider, 'mock-model');

    const findings = await analyzer.analyzeCodeSnippet(
      "const query = 'SELECT * FROM users WHERE id=' + userId;",
      'JavaScript'
    );
    // Mock doesn't return proper tool_use, so findings will be empty
    expect(Array.isArray(findings)).toBe(true);
  });

  it('analyzes multiple files in repository mode', async () => {
    const provider = createMockProvider('No issues found.');
    const analyzer = new SASTAnalyzer(provider, 'mock-model');

    const report = await analyzer.analyzeRepository([
      { path: 'app.js', content: 'console.log("safe");', language: 'JavaScript' },
      { path: 'index.ts', content: 'export default {};', language: 'TypeScript' },
    ]);

    expect(report).toBeDefined();
    expect(typeof report.filesAnalyzed).toBe('number');
    expect(typeof report.totalIssues).toBe('number');
    expect(Array.isArray(report.findings)).toBe(true);
  });

  it('provides a security review for code', async () => {
    const provider = createMockProvider('This code looks secure.');
    const analyzer = new SASTAnalyzer(provider, 'mock-model');

    const review = await analyzer.getSecurityReview(
      'function add(a, b) { return a + b; }',
      'JavaScript'
    );
    expect(typeof review).toBe('string');
    expect(review.length).toBeGreaterThan(0);
  });
});

// ─── Integration: Module Construction + Wiring ──────────────────────────────

describe('Knowledge Integration', () => {
  it('all three systems initialize with the same DB path', async () => {
    const dbPath = 'test_shared.db';

    const kg = new KnowledgeGraph(dbPath);
    await kg.initialize();

    const vulnDb = new VulnDatabase(dbPath);
    await vulnDb.initialize();

    const reward = new RewardSystem(dbPath);
    await reward.initialize();

    expect(kg).toBeDefined();
    expect(vulnDb).toBeDefined();
    expect(reward).toBeDefined();
  });

  it('OrchestratorEngine config accepts knowledge system instances', async () => {
    // Verify the config interface compiles with knowledge systems
    const kg = new KnowledgeGraph('test.db');
    await kg.initialize();

    const vulnDb = new VulnDatabase('test.db');
    await vulnDb.initialize();

    const reward = new RewardSystem('test.db');
    await reward.initialize();

    // Dynamically import to verify the config interface accepts these
    const { OrchestratorEngine } = await import('../core/orchestrator/orchestrator_engine');
    const provider = createMockProvider();

    const engine = new OrchestratorEngine({
      provider,
      model: 'mock-model',
      knowledgeGraph: kg,
      vulnDb,
      rewardSystem: reward,
    });

    expect(engine).toBeDefined();
    expect(engine.getProvider()).toBe(provider);
    expect(engine.getModel()).toBe('mock-model');
  });

  it('OrchestratorEngine config works without knowledge systems', async () => {
    const { OrchestratorEngine } = await import('../core/orchestrator/orchestrator_engine');
    const provider = createMockProvider();

    const engine = new OrchestratorEngine({
      provider,
      model: 'mock-model',
    });

    expect(engine).toBeDefined();
  });

  it('SASTAnalyzer can be used via orchestrator runSAST', async () => {
    const { OrchestratorEngine } = await import('../core/orchestrator/orchestrator_engine');
    const provider = createMockProvider('No issues.');

    const engine = new OrchestratorEngine({
      provider,
      model: 'mock-model',
    });

    // Set up message callback to capture messages
    const messages: Array<{ content: string }> = [];
    engine.setMessageCallback((msg) => messages.push({ content: String(msg.content) }));

    const report = await engine.runSAST([
      { path: 'test.js', content: 'console.log("hello");', language: 'JavaScript' },
    ]);

    expect(report).toBeDefined();
    expect(typeof report.filesAnalyzed).toBe('number');
    expect(messages.length).toBeGreaterThan(0);
  });
});

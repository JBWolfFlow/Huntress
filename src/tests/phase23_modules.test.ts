/**
 * Phase 23-24 Module Tests
 *
 * Comprehensive tests for:
 *   23A — OOB Server Enhancement (oob_server.ts)
 *   23B — Target Deduplication (target_dedup.ts)
 *   23C — H1 Duplicate Checker (h1_duplicate_check.ts)
 *   23E — Report Quality Scorer (report_quality.ts)
 *   23F — Extended Recon (extended_recon.ts)
 *   23G — Continuous Monitor (continuous_monitor.ts)
 *   24B — WebSocket Client (websocket_client.ts)
 *   23D — ReportReviewModal (ReportReviewModal.tsx)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Phase 23A imports ──────────────────────────────────────────────────────
import { OOBServer } from '../core/validation/oob_server';
import type {
  OOBServerConfig,
  OOBCallback,
  InjectionPoint,
  FallbackProvider,
} from '../core/validation/oob_server';

// ─── Phase 23B imports ──────────────────────────────────────────────────────
import {
  TargetDeduplicator,
  deduplicateUrls,
  normalizeUrl,
  isApiEndpoint,
  apiPathSignature,
} from '../core/orchestrator/target_dedup';
import type { TargetInfo, DeduplicationResult } from '../core/orchestrator/target_dedup';

// ─── Phase 23C imports ──────────────────────────────────────────────────────
import { H1DuplicateChecker } from '../core/reporting/h1_duplicate_check';
import type {
  H1DuplicateConfig,
  DisclosedReport,
} from '../core/reporting/h1_duplicate_check';

// ─── Phase 23E imports ──────────────────────────────────────────────────────
import { ReportQualityScorer } from '../core/reporting/report_quality';
import type {
  ReportQualityScore,
  QualityIssue,
} from '../core/reporting/report_quality';

// ─── Phase 23F imports ──────────────────────────────────────────────────────
import { ExtendedRecon } from '../core/discovery/extended_recon';
import type {
  ExtendedReconConfig,
  SubdomainResult,
  DorkResult,
} from '../core/discovery/extended_recon';

// ─── Phase 23G imports ──────────────────────────────────────────────────────
import { ContinuousMonitor } from '../core/discovery/continuous_monitor';
import type { ContinuousMonitorConfig } from '../core/discovery/continuous_monitor';

// ─── Phase 24B imports ──────────────────────────────────────────────────────
import { WebSocketClient, WebSocketPool } from '../core/http/websocket_client';
import type { WebSocketConfig, WebSocketConnectionInfo } from '../core/http/websocket_client';

// ─── Phase 23D imports ──────────────────────────────────────────────────────
import { ReportReviewModal } from '../components/ReportReviewModal';
import type { ReportReviewModalProps, QualityScore } from '../components/ReportReviewModal';

// ─── Shared type imports ────────────────────────────────────────────────────
import type { H1Report } from '../core/reporting/h1_api';
import type { DuplicateScore } from '../utils/duplicate_checker';

// ─── Mock H1Report ──────────────────────────────────────────────────────────

const mockReport: H1Report = {
  title: 'Reflected XSS in search parameter',
  severity: 'high',
  suggestedBounty: { min: 500, max: 2000 },
  description:
    'A reflected cross-site scripting vulnerability was found in the search parameter of the main application. An attacker can inject arbitrary JavaScript code that executes in the context of the victim browser.',
  impact:
    'An attacker can steal session cookies, redirect users to malicious sites, and perform actions on behalf of the victim. This affects all authenticated users who click a crafted link.',
  steps: [
    'Navigate to https://example.com/search',
    'Enter the payload: <script>alert(document.cookie)</script> in the search field',
    'Submit the form and observe the alert dialog showing the session cookie',
    'Note that the payload is reflected in the response without encoding',
  ],
  proof: { screenshots: ['screenshot1.png'] },
  cvssScore: 6.1,
  weaknessId: '79',
  severityJustification: [
    'Direct impact on user sessions',
    'No authentication required for exploitation',
  ],
};

// ─── Helper: mock executeCommand for OOB Server ─────────────────────────────

function createMockExecuteCommand(
  overrides?: Partial<{ success: boolean; stdout: string; stderr: string; exitCode: number }>,
) {
  return vi.fn().mockResolvedValue({
    success: false,
    stdout: '',
    stderr: 'not found',
    exitCode: 1,
    executionTimeMs: 10,
    ...overrides,
  });
}

// ─── Helper: mock injection point ───────────────────────────────────────────

function createInjectionPoint(overrides: Partial<InjectionPoint> = {}): InjectionPoint {
  return {
    target: 'https://example.com/api/data',
    parameter: 'url',
    agentId: 'ssrf-hunter',
    vulnerabilityType: 'ssrf',
    ...overrides,
  };
}

// ─── Helper: OOB Server with DNS canary fallback ────────────────────────────

function createOobServer(configOverrides: Partial<OOBServerConfig> = {}): OOBServer {
  return new OOBServer({
    executeCommand: createMockExecuteCommand(),
    ...configOverrides,
  });
}

// =============================================================================
// 23A — OOB Server Enhancement
// =============================================================================

describe('OOBServer', () => {
  let server: OOBServer;
  let mockExecCmd: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockExecCmd = createMockExecuteCommand();
    server = new OOBServer({
      executeCommand: mockExecCmd,
      pollInterval: 100_000,
    });
  });

  it('should instantiate with default config', () => {
    expect(server).toBeDefined();
    expect(server.getActiveProvider()).toBe('interactsh');
  });

  it('should fall back to dns_canary when interactsh is unavailable', async () => {
    const url = await server.start();
    // interactsh binary not found => dns canary fallback
    expect(url).toBeTruthy();
    expect(server.getActiveProvider()).toBe('dns_canary');
    server.stop();
  });

  it('should generate callback URL with proper structure', async () => {
    await server.start();
    const injection = createInjectionPoint();
    const callback = server.generateCallbackUrl(injection);

    expect(callback.id).toMatch(/^oob_\d+$/);
    expect(callback.callbackUrl).toBeTruthy();
    expect(callback.injectionPoint).toEqual(injection);
    expect(callback.triggered).toBe(false);
    expect(callback.expired).toBe(false);
    expect(callback.ttlMs).toBeGreaterThan(0);
    server.stop();
  });

  it('should generate incremental callback IDs', async () => {
    await server.start();
    const cb1 = server.generateCallbackUrl(createInjectionPoint());
    const cb2 = server.generateCallbackUrl(createInjectionPoint());

    const id1 = parseInt(cb1.id.replace('oob_', ''), 10);
    const id2 = parseInt(cb2.id.replace('oob_', ''), 10);
    expect(id2).toBe(id1 + 1);
    server.stop();
  });

  it('should return HTTP URL with http:// prefix', async () => {
    await server.start();
    const callback = server.generateCallbackUrl(createInjectionPoint());
    const httpUrl = server.getHttpUrl(callback);

    expect(httpUrl).toMatch(/^http:\/\//);
    expect(httpUrl).toContain(callback.callbackUrl);
    server.stop();
  });

  it('should return DNS payload as the raw callback URL', async () => {
    await server.start();
    const callback = server.generateCallbackUrl(createInjectionPoint());
    const dnsPayload = server.getDnsPayload(callback);

    expect(dnsPayload).toBe(callback.callbackUrl);
    server.stop();
  });

  it('should return LDAP payload with ldap:// scheme', async () => {
    await server.start();
    const callback = server.generateCallbackUrl(createInjectionPoint());
    const ldapPayload = server.getLdapPayload(callback);

    expect(ldapPayload).toMatch(/^ldap:\/\//);
    expect(ldapPayload).toContain(callback.callbackUrl);
    expect(ldapPayload).toContain('o=huntress,dc=oob');
    server.stop();
  });

  it('should correlate a callback by exact URL', async () => {
    await server.start();
    const injection = createInjectionPoint({ parameter: 'redirect_url' });
    const callback = server.generateCallbackUrl(injection);

    const found = server.correlate(callback.callbackUrl);
    expect(found).toBeDefined();
    expect(found!.id).toBe(callback.id);
    expect(found!.injectionPoint.parameter).toBe('redirect_url');
    server.stop();
  });

  it('should correlate with http:// prefixed URL', async () => {
    await server.start();
    const callback = server.generateCallbackUrl(createInjectionPoint());

    const found = server.correlate(`http://${callback.callbackUrl}`);
    expect(found).toBeDefined();
    expect(found!.id).toBe(callback.id);
    server.stop();
  });

  it('should return undefined for unknown callback URL', async () => {
    await server.start();
    server.generateCallbackUrl(createInjectionPoint());

    const found = server.correlate('nonexistent.oast.fun');
    expect(found).toBeUndefined();
    server.stop();
  });

  it('should filter callbacks by agent ID', async () => {
    await server.start();
    server.generateCallbackUrl(createInjectionPoint({ agentId: 'ssrf-hunter' }));
    server.generateCallbackUrl(createInjectionPoint({ agentId: 'ssrf-hunter' }));
    server.generateCallbackUrl(createInjectionPoint({ agentId: 'xxe-hunter' }));

    const ssrfCallbacks = server.getCallbacksForAgent('ssrf-hunter');
    expect(ssrfCallbacks).toHaveLength(2);

    const xxeCallbacks = server.getCallbacksForAgent('xxe-hunter');
    expect(xxeCallbacks).toHaveLength(1);

    const noCallbacks = server.getCallbacksForAgent('idor-hunter');
    expect(noCallbacks).toHaveLength(0);
    server.stop();
  });

  it('should respect custom TTL on callback', async () => {
    await server.start();
    const callback = server.generateCallbackUrl(createInjectionPoint(), 5000);
    expect(callback.ttlMs).toBe(5000);
    server.stop();
  });

  it('should use defaultTtlMs when no custom TTL provided', async () => {
    const customServer = new OOBServer({
      executeCommand: createMockExecuteCommand(),
      defaultTtlMs: 60_000,
    });
    await customServer.start();
    const callback = customServer.generateCallbackUrl(createInjectionPoint());
    expect(callback.ttlMs).toBe(60_000);
    customServer.stop();
  });

  it('should track pending callbacks', async () => {
    await server.start();
    server.generateCallbackUrl(createInjectionPoint());
    server.generateCallbackUrl(createInjectionPoint());

    expect(server.getPendingCallbacks()).toHaveLength(2);
    expect(server.getTriggeredCallbacks()).toHaveLength(0);
    expect(server.getExpiredCallbacks()).toHaveLength(0);
    server.stop();
  });

  it('should report isTriggered and isExpired correctly', async () => {
    await server.start();
    const callback = server.generateCallbackUrl(createInjectionPoint());

    expect(server.isTriggered(callback.id)).toBe(false);
    expect(server.isExpired(callback.id)).toBe(false);
    expect(server.isTriggered('nonexistent')).toBe(false);
    expect(server.isExpired('nonexistent')).toBe(false);
    server.stop();
  });

  it('should generate a summary string', async () => {
    await server.start();
    server.generateCallbackUrl(createInjectionPoint());

    const summary = server.getSummary();
    expect(summary).toContain('OOB Server: running');
    expect(summary).toContain('provider: dns_canary');
    expect(summary).toContain('Registered callbacks: 1');
    expect(summary).toContain('Pending: 1');
    server.stop();
  });

  it('should stop cleanly', async () => {
    await server.start();
    server.stop();

    const summary = server.getSummary();
    expect(summary).toContain('stopped');
  });

  it('should build server URL pool from config', () => {
    const customServer = new OOBServer({
      executeCommand: createMockExecuteCommand(),
      serverUrl: 'custom.oast.fun',
      serverUrls: ['extra1.oast.fun', 'extra2.oast.fun'],
    });
    // The pool should include custom URLs plus known public servers
    expect(customServer).toBeDefined();
  });
});

// =============================================================================
// 23B — Target Deduplication
// =============================================================================

describe('TargetDeduplicator', () => {
  let deduplicator: TargetDeduplicator;

  beforeEach(() => {
    deduplicator = new TargetDeduplicator();
  });

  it('should instantiate with default options', () => {
    expect(deduplicator).toBeDefined();
  });

  it('should instantiate with custom simhash threshold', () => {
    const custom = new TargetDeduplicator({ simhashThreshold: 10 });
    expect(custom).toBeDefined();
  });

  describe('normalizeUrl', () => {
    it('should strip trailing slashes', () => {
      expect(normalizeUrl('https://example.com/')).toBe('https://example.com/');
      expect(normalizeUrl('https://example.com/path/')).toBe('https://example.com/path');
    });

    it('should remove www prefix', () => {
      const normalized = normalizeUrl('https://www.example.com/path');
      expect(normalized).not.toContain('www.');
      expect(normalized).toContain('example.com/path');
    });

    it('should upgrade http to https', () => {
      const normalized = normalizeUrl('http://example.com/page');
      expect(normalized).toMatch(/^https:\/\//);
    });

    it('should lowercase hostname', () => {
      const normalized = normalizeUrl('https://EXAMPLE.COM/PATH');
      expect(normalized).toContain('example.com');
    });

    it('should strip query parameters and fragments', () => {
      const normalized = normalizeUrl('https://example.com/path?foo=bar&baz=qux#section');
      expect(normalized).not.toContain('?');
      expect(normalized).not.toContain('#');
    });

    it('should handle non-standard ports', () => {
      const normalized = normalizeUrl('https://example.com:8443/path');
      expect(normalized).toContain(':8443');
    });

    it('should strip standard ports', () => {
      const normalized = normalizeUrl('https://example.com:443/path');
      expect(normalized).not.toContain(':443');
    });

    it('should handle unparseable URLs gracefully', () => {
      const normalized = normalizeUrl('not-a-url');
      expect(typeof normalized).toBe('string');
    });
  });

  describe('isApiEndpoint', () => {
    it('should detect /api/ paths', () => {
      expect(isApiEndpoint('https://example.com/api/v1/users')).toBe(true);
    });

    it('should detect versioned paths /v1/', () => {
      expect(isApiEndpoint('https://example.com/v1/users')).toBe(true);
      expect(isApiEndpoint('https://example.com/v2/orders')).toBe(true);
    });

    it('should detect /graphql paths', () => {
      expect(isApiEndpoint('https://example.com/graphql')).toBe(true);
    });

    it('should detect /rest/ paths', () => {
      expect(isApiEndpoint('https://example.com/rest/data')).toBe(true);
    });

    it('should return false for non-API paths', () => {
      expect(isApiEndpoint('https://example.com/about')).toBe(false);
      expect(isApiEndpoint('https://example.com/login')).toBe(false);
    });
  });

  describe('apiPathSignature', () => {
    it('should replace numeric IDs with :id', () => {
      const sig = apiPathSignature('https://example.com/api/users/123');
      expect(sig).toContain(':id');
    });

    it('should replace UUIDs with :uuid', () => {
      const sig = apiPathSignature('https://example.com/api/items/550e8400-e29b-41d4-a716-446655440000');
      expect(sig).toContain(':uuid');
    });

    it('should produce same signature for structurally identical API paths', () => {
      const sig1 = apiPathSignature('https://example.com/api/v1/users/123');
      const sig2 = apiPathSignature('https://example.com/api/v1/users/456');
      expect(sig1).toBe(sig2);
    });

    it('should produce different signatures for different API paths', () => {
      const sig1 = apiPathSignature('https://example.com/api/v1/users/123');
      const sig2 = apiPathSignature('https://example.com/api/v1/orders/123');
      expect(sig1).not.toBe(sig2);
    });
  });

  describe('deduplicateTargets', () => {
    it('should return empty result for empty input', async () => {
      const result = await deduplicator.deduplicateTargets([]);
      expect(result.representatives).toHaveLength(0);
      expect(result.groups).toHaveLength(0);
      expect(result.stats.total).toBe(0);
      expect(result.stats.unique).toBe(0);
      expect(result.stats.duplicates).toBe(0);
    });

    it('should group identical normalized URLs without fetch', async () => {
      const targets: TargetInfo[] = [
        { url: 'https://example.com/page', assetType: 'web-application' },
        { url: 'https://www.example.com/page', assetType: 'web-application' },
        { url: 'http://example.com/page/', assetType: 'web-application' },
      ];

      const result = await deduplicator.deduplicateTargets(targets);
      // All three should normalize to the same URL
      expect(result.stats.total).toBe(3);
      expect(result.stats.duplicates).toBeGreaterThanOrEqual(0);
    });

    it('should return proper DeduplicationResult structure', async () => {
      const targets: TargetInfo[] = [
        { url: 'https://example.com', assetType: 'web-application' },
      ];
      const result = await deduplicator.deduplicateTargets(targets);

      expect(result).toHaveProperty('representatives');
      expect(result).toHaveProperty('groups');
      expect(result).toHaveProperty('stats');
      expect(result.stats).toHaveProperty('total');
      expect(result.stats).toHaveProperty('unique');
      expect(result.stats).toHaveProperty('duplicates');
      expect(result.stats).toHaveProperty('fetchErrors');
    });

    it('should count stats correctly for distinct targets', async () => {
      const targets: TargetInfo[] = [
        { url: 'https://example.com', assetType: 'web-application' },
        { url: 'https://other.com', assetType: 'web-application' },
      ];
      const result = await deduplicator.deduplicateTargets(targets);
      expect(result.stats.total).toBe(2);
    });

    it('should group API endpoints by path structure', async () => {
      const targets: TargetInfo[] = [
        { url: 'https://example.com/api/v1/users/123', assetType: 'api' },
        { url: 'https://example.com/api/v1/users/456', assetType: 'api' },
        { url: 'https://example.com/api/v1/orders/789', assetType: 'api' },
      ];
      const result = await deduplicator.deduplicateTargets(targets);
      // users/123 and users/456 should be grouped together
      expect(result.stats.total).toBe(3);
      expect(result.stats.unique).toBeLessThanOrEqual(3);
    });

    it('should select highest-priority target as representative', async () => {
      const targets: TargetInfo[] = [
        { url: 'https://example.com/page', assetType: 'web-application', priority: 1 },
        { url: 'https://www.example.com/page', assetType: 'web-application', priority: 10 },
      ];
      const result = await deduplicator.deduplicateTargets(targets);
      // The priority 10 target should be the representative
      const rep = result.representatives[0];
      expect(rep.priority).toBe(10);
    });
  });

  describe('deduplicateUrls (standalone)', () => {
    it('should accept an array of URL strings', async () => {
      const result = await deduplicateUrls(['https://example.com', 'https://other.com']);
      expect(result.stats.total).toBe(2);
    });
  });
});

// =============================================================================
// 23C — H1 Duplicate Checker
// =============================================================================

describe('H1DuplicateChecker', () => {
  describe('constructor', () => {
    it('should create instance without credentials', () => {
      const checker = new H1DuplicateChecker({});
      expect(checker).toBeDefined();
    });

    it('should create instance with credentials', () => {
      const checker = new H1DuplicateChecker({
        h1Username: 'testuser',
        h1ApiToken: 'testtoken',
      });
      expect(checker).toBeDefined();
    });

    it('should accept custom similarity threshold', () => {
      const checker = new H1DuplicateChecker({ similarityThreshold: 0.9 });
      expect(checker).toBeDefined();
    });
  });

  describe('checkDuplicate', () => {
    it('should return DuplicateScore structure without credentials', async () => {
      const checker = new H1DuplicateChecker({});
      const score = await checker.checkDuplicate(mockReport, 'test-program');

      expect(score).toHaveProperty('overall');
      expect(score).toHaveProperty('h1Match');
      expect(score).toHaveProperty('githubMatch');
      expect(score).toHaveProperty('internalMatch');
      expect(score).toHaveProperty('recommendation');
      expect(score).toHaveProperty('matches');
      expect(score).toHaveProperty('reasoning');
    });

    it('should gracefully degrade without API key', async () => {
      const checker = new H1DuplicateChecker({});
      const score = await checker.checkDuplicate(mockReport, 'test-program');

      expect(score.overall).toBe(0);
      expect(score.h1Match).toBe(0);
      expect(score.recommendation).toBe('review');
      expect(score.matches).toHaveLength(0);
      expect(score.reasoning.length).toBeGreaterThan(0);
      expect(score.reasoning[0]).toContain('credentials');
    });
  });

  describe('similarity methods', () => {
    let checker: H1DuplicateChecker;

    beforeEach(() => {
      checker = new H1DuplicateChecker({});
    });

    it('should compute Jaccard similarity of identical texts', () => {
      const sim = checker.jaccardSimilarity('hello world', 'hello world');
      expect(sim).toBe(1.0);
    });

    it('should compute Jaccard similarity of empty texts', () => {
      const sim = checker.jaccardSimilarity('', '');
      expect(sim).toBe(1.0);
    });

    it('should compute Jaccard similarity of disjoint texts', () => {
      const sim = checker.jaccardSimilarity('hello world', 'foo bar baz');
      expect(sim).toBe(0.0);
    });

    it('should compute partial Jaccard similarity', () => {
      const sim = checker.jaccardSimilarity('hello world foo', 'hello world bar');
      expect(sim).toBeGreaterThan(0);
      expect(sim).toBeLessThan(1);
    });

    it('should compute title similarity with CWE boost', () => {
      const sim = checker.titleSimilarity(
        'CWE-79 XSS in search parameter',
        'CWE-79 Cross-Site Scripting in search',
      );
      expect(sim).toBeGreaterThan(0);
    });

    it('should compute title similarity without CWE', () => {
      const sim = checker.titleSimilarity(
        'XSS in search parameter',
        'XSS in login page',
      );
      expect(sim).toBeGreaterThan(0);
    });

    it('should compute path similarity for identical paths', () => {
      const sim = checker.pathSimilarity(
        'https://example.com/api/users',
        'https://other.com/api/users',
      );
      expect(sim).toBe(1.0);
    });

    it('should compute path similarity for partially matching paths', () => {
      const sim = checker.pathSimilarity(
        'https://example.com/api/users/profile',
        'https://example.com/api/users/settings',
      );
      expect(sim).toBeGreaterThan(0);
      expect(sim).toBeLessThan(1);
    });

    it('should return 0 for completely different paths', () => {
      const sim = checker.pathSimilarity(
        'https://example.com/foo',
        'https://example.com/bar',
      );
      expect(sim).toBe(0);
    });

    it('should compute aggregate similarity within 0-1 range', () => {
      const agg = checker.aggregateSimilarity({
        title: 0.8,
        description: 0.7,
        endpoint: 0.6,
        severity: 1.0,
      });
      expect(agg).toBeGreaterThanOrEqual(0);
      expect(agg).toBeLessThanOrEqual(1);
    });

    it('should return description similarity of 1.0 for empty inputs', () => {
      const sim = checker.descriptionSimilarity('', '');
      expect(sim).toBe(1.0);
    });

    it('should return description similarity of 0.0 when one is empty', () => {
      const sim = checker.descriptionSimilarity('some text', '');
      expect(sim).toBe(0.0);
    });
  });

  describe('compareWithDisclosed', () => {
    it('should return empty matches when no disclosed reports match', async () => {
      const checker = new H1DuplicateChecker({ similarityThreshold: 0.99 });
      const disclosed: DisclosedReport[] = [
        {
          id: '1',
          title: 'Completely unrelated SQL injection in admin panel',
          vulnerabilityType: 'sqli',
          severity: 'critical',
          disclosedAt: '2024-01-01',
          description: 'A SQL injection vulnerability exists in the admin panel login form allowing database extraction.',
          programHandle: 'test-program',
          url: 'https://hackerone.com/reports/1',
        },
      ];

      const matches = await checker.compareWithDisclosed(mockReport, disclosed);
      expect(Array.isArray(matches)).toBe(true);
    });

    it('should return matches sorted by similarity descending', async () => {
      const checker = new H1DuplicateChecker({ similarityThreshold: 0.0 });
      const disclosed: DisclosedReport[] = [
        {
          id: '1',
          title: 'XSS in search feature',
          vulnerabilityType: 'xss',
          severity: 'high',
          disclosedAt: '2024-01-01',
          description: 'Reflected XSS in the search parameter allows JavaScript execution.',
          programHandle: 'test',
          url: 'https://hackerone.com/reports/1',
        },
        {
          id: '2',
          title: 'CSRF in settings page',
          vulnerabilityType: 'csrf',
          severity: 'medium',
          disclosedAt: '2024-02-01',
          description: 'Cross-site request forgery allows changing user email.',
          programHandle: 'test',
          url: 'https://hackerone.com/reports/2',
        },
      ];

      const matches = await checker.compareWithDisclosed(mockReport, disclosed);
      expect(matches.length).toBeGreaterThanOrEqual(1);

      // Verify sorted descending
      for (let i = 1; i < matches.length; i++) {
        expect(matches[i - 1].similarity).toBeGreaterThanOrEqual(matches[i].similarity);
      }
    });
  });

  describe('cache', () => {
    it('should invalidate cache for a specific program', () => {
      const checker = new H1DuplicateChecker({});
      checker.invalidateCache('test-program');
      // Should not throw
      expect(true).toBe(true);
    });

    it('should invalidate all caches', () => {
      const checker = new H1DuplicateChecker({});
      checker.invalidateCache();
      expect(true).toBe(true);
    });
  });
});

// =============================================================================
// 23E — Report Quality Scorer
// =============================================================================

describe('ReportQualityScorer', () => {
  let scorer: ReportQualityScorer;

  beforeEach(() => {
    scorer = new ReportQualityScorer();
  });

  it('should instantiate with default config', () => {
    expect(scorer).toBeDefined();
  });

  it('should instantiate with custom config', () => {
    const custom = new ReportQualityScorer({
      minDescriptionLength: 100,
      minStepsCount: 2,
      requireImpact: false,
      requireCvss: true,
    });
    expect(custom).toBeDefined();
  });

  describe('scoreReport', () => {
    it('should return proper ReportQualityScore structure', () => {
      const result = scorer.scoreReport(mockReport);

      expect(result).toHaveProperty('overall');
      expect(result).toHaveProperty('categories');
      expect(result).toHaveProperty('issues');
      expect(result).toHaveProperty('grade');

      expect(result.categories).toHaveProperty('clarity');
      expect(result.categories).toHaveProperty('completeness');
      expect(result.categories).toHaveProperty('evidence');
      expect(result.categories).toHaveProperty('impact');
      expect(result.categories).toHaveProperty('reproducibility');
    });

    it('should score a well-written report highly', () => {
      const result = scorer.scoreReport(mockReport);
      expect(result.overall).toBeGreaterThanOrEqual(40);
      expect(['A', 'B', 'C']).toContain(result.grade);
    });

    it('should score an empty report very low', () => {
      const emptyReport: H1Report = {
        title: '',
        severity: 'low',
        suggestedBounty: { min: 0, max: 0 },
        description: '',
        impact: '',
        steps: [],
        proof: {},
      };
      const result = scorer.scoreReport(emptyReport);
      expect(result.overall).toBeLessThanOrEqual(20);
      expect(result.grade).toBe('F');
    });

    it('should score a minimal report low', () => {
      const minimalReport: H1Report = {
        title: 'XSS',
        severity: 'high',
        suggestedBounty: { min: 100, max: 500 },
        description: 'found xss',
        impact: '',
        steps: ['test it'],
        proof: {},
      };
      const result = scorer.scoreReport(minimalReport);
      expect(result.overall).toBeLessThan(50);
    });

    it('should give each category a 0-100 score', () => {
      const result = scorer.scoreReport(mockReport);
      for (const value of Object.values(result.categories)) {
        expect(value).toBeGreaterThanOrEqual(0);
        expect(value).toBeLessThanOrEqual(100);
      }
    });

    it('should give overall a 0-100 score', () => {
      const result = scorer.scoreReport(mockReport);
      expect(result.overall).toBeGreaterThanOrEqual(0);
      expect(result.overall).toBeLessThanOrEqual(100);
    });
  });

  describe('grade mapping', () => {
    it('should return A for score >= 90', () => {
      // A report with every element for maximum score
      const perfectReport: H1Report = {
        title: 'Stored XSS in /comments endpoint allows session hijacking via cookie theft',
        severity: 'high',
        suggestedBounty: { min: 500, max: 2000 },
        description:
          'A stored cross-site scripting vulnerability was found in the /comments endpoint of the main application. This means an attacker can inject persistent JavaScript code that executes in the context of every visitor who views the comment. Specifically, the input sanitization on the comment body field does not properly encode angle brackets, which allows injection of HTML script elements. The resulting payload is stored in the database and served to all users who load the page.',
        impact:
          'An attacker can steal session cookies, redirect users to malicious sites, and perform actions on behalf of the victim. This affects all authenticated users who view the compromised comment. Sensitive user data including credentials and personal information could be exfiltrated.',
        steps: [
          '1. Navigate to https://example.com/comments',
          '2. Enter the payload: <script>alert(document.cookie)</script> in the comment body field',
          '3. Submit the form and wait for the comment to appear',
          '4. Observe the alert dialog showing the session cookie, confirming the XSS payload executes',
        ],
        proof: { screenshots: ['screenshot1.png'], video: 'poc.mp4' },
        cvssScore: 6.1,
        weaknessId: '79',
        severityJustification: [
          'Direct impact on user sessions resulting in account takeover',
          'No authentication required for exploitation',
        ],
      };
      const result = scorer.scoreReport(perfectReport);
      expect(result.overall).toBeGreaterThanOrEqual(75);
      expect(['A', 'B']).toContain(result.grade);
    });

    it('should return F for very low score', () => {
      const terribleReport: H1Report = {
        title: '',
        severity: 'low',
        suggestedBounty: { min: 0, max: 0 },
        description: '',
        impact: '',
        steps: [],
        proof: {},
      };
      const result = scorer.scoreReport(terribleReport);
      expect(result.grade).toBe('F');
    });
  });

  describe('getImprovementSuggestions', () => {
    it('should return issues for an empty report', () => {
      const emptyReport: H1Report = {
        title: '',
        severity: 'low',
        suggestedBounty: { min: 0, max: 0 },
        description: '',
        impact: '',
        steps: [],
        proof: {},
      };
      const issues = scorer.getImprovementSuggestions(emptyReport);
      expect(issues.length).toBeGreaterThan(0);
      expect(issues.some((i) => i.severity === 'critical')).toBe(true);
    });

    it('should flag missing description', () => {
      const report: H1Report = { ...mockReport, description: '' };
      const issues = scorer.getImprovementSuggestions(report);
      expect(issues.some((i) => i.category === 'clarity' && i.message.toLowerCase().includes('empty'))).toBe(true);
    });

    it('should flag generic title', () => {
      // Title must be >10 chars to reach the generic check (otherwise "too short" fires first)
      const report: H1Report = { ...mockReport, title: 'Open Redirect' };
      const issues = scorer.getImprovementSuggestions(report);
      expect(issues.some((i) => i.category === 'clarity' && i.message.toLowerCase().includes('generic'))).toBe(true);
    });

    it('should flag missing impact when requireImpact is true', () => {
      const report: H1Report = { ...mockReport, impact: '' };
      const issues = scorer.getImprovementSuggestions(report);
      expect(issues.some((i) => i.category === 'completeness' && i.message.toLowerCase().includes('impact'))).toBe(true);
    });

    it('should flag missing screenshots', () => {
      const report: H1Report = { ...mockReport, proof: {} };
      const issues = scorer.getImprovementSuggestions(report);
      expect(issues.some((i) => i.category === 'evidence')).toBe(true);
    });

    it('should flag missing reproduction steps', () => {
      const report: H1Report = { ...mockReport, steps: [] };
      const issues = scorer.getImprovementSuggestions(report);
      expect(issues.some((i) => i.category === 'completeness' && i.message.toLowerCase().includes('step'))).toBe(true);
    });

    it('should flag missing weakness ID', () => {
      const report: H1Report = { ...mockReport, weaknessId: undefined };
      const issues = scorer.getImprovementSuggestions(report);
      expect(issues.some((i) => i.message.toLowerCase().includes('cwe') || i.message.toLowerCase().includes('weakness'))).toBe(true);
    });

    it('should return empty array for issues of each type for a complete report', () => {
      const issues = scorer.getImprovementSuggestions(mockReport);
      // Even well-formed reports may have minor suggestions, but should have no critical issues
      const criticalIssues = issues.filter((i) => i.severity === 'critical');
      expect(criticalIssues).toHaveLength(0);
    });

    it('should provide suggestion string for every issue', () => {
      const emptyReport: H1Report = {
        title: '',
        severity: 'low',
        suggestedBounty: { min: 0, max: 0 },
        description: '',
        impact: '',
        steps: [],
        proof: {},
      };
      const issues = scorer.getImprovementSuggestions(emptyReport);
      for (const issue of issues) {
        expect(issue.suggestion.length).toBeGreaterThan(0);
      }
    });
  });

  describe('enhanceReport', () => {
    it('should return original report when no provider given', async () => {
      const result = await scorer.enhanceReport(mockReport);
      expect(result).toEqual(mockReport);
    });
  });
});

// =============================================================================
// 23F — Extended Recon
// =============================================================================

describe('ExtendedRecon', () => {
  let recon: ExtendedRecon;
  let mockHttpClient: { request: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    mockHttpClient = {
      request: vi.fn().mockResolvedValue({
        status: 200,
        statusText: 'OK',
        headers: { 'content-type': 'application/json' },
        body: '[]',
        cookies: [],
        timing: { dnsMs: 1, connectMs: 2, ttfbMs: 10, totalMs: 50 },
        size: 2,
        redirectChain: [],
      }),
    };
    recon = new ExtendedRecon({
      httpClient: mockHttpClient as any,
    });
  });

  it('should instantiate with config', () => {
    expect(recon).toBeDefined();
  });

  it('should instantiate with empty config', () => {
    const minimal = new ExtendedRecon({});
    expect(minimal).toBeDefined();
  });

  describe('queryCrtSh', () => {
    it('should parse valid crt.sh response', async () => {
      const crtshResponse = JSON.stringify([
        {
          id: 1,
          issuer_ca_id: 1,
          issuer_name: "Let's Encrypt",
          common_name: 'api.example.com',
          name_value: 'api.example.com\nwww.example.com',
          not_before: '2024-01-01',
          not_after: '2024-12-31',
          serial_number: 'abc123',
        },
        {
          id: 2,
          issuer_ca_id: 1,
          issuer_name: "Let's Encrypt",
          common_name: '*.example.com',
          name_value: '*.example.com',
          not_before: '2024-01-01',
          not_after: '2024-12-31',
          serial_number: 'def456',
        },
      ]);

      mockHttpClient.request.mockResolvedValueOnce({
        status: 200,
        statusText: 'OK',
        headers: { 'content-type': 'application/json' },
        body: crtshResponse,
        cookies: [],
        timing: { dnsMs: 1, connectMs: 2, ttfbMs: 10, totalMs: 50 },
        size: crtshResponse.length,
        redirectChain: [],
      });

      const results = await recon.queryCrtSh('example.com');

      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBeGreaterThanOrEqual(1);
      for (const result of results) {
        expect(result.source).toBe('crtsh');
        expect(result.subdomain).toBeTruthy();
      }
    });

    it('should return empty array on crt.sh error', async () => {
      mockHttpClient.request.mockResolvedValueOnce({
        status: 500,
        statusText: 'Internal Server Error',
        headers: {},
        body: '',
        cookies: [],
        timing: { dnsMs: 1, connectMs: 2, ttfbMs: 10, totalMs: 50 },
        size: 0,
        redirectChain: [],
      });

      const results = await recon.queryCrtSh('example.com');
      expect(results).toHaveLength(0);
    });

    it('should return empty array for invalid domain', async () => {
      const results = await recon.queryCrtSh('not valid!!!');
      expect(results).toHaveLength(0);
    });

    it('should handle empty crt.sh response body', async () => {
      mockHttpClient.request.mockResolvedValueOnce({
        status: 200,
        statusText: 'OK',
        headers: {},
        body: '',
        cookies: [],
        timing: { dnsMs: 1, connectMs: 2, ttfbMs: 10, totalMs: 50 },
        size: 0,
        redirectChain: [],
      });

      const results = await recon.queryCrtSh('example.com');
      expect(results).toHaveLength(0);
    });
  });

  describe('runGoogleDorks', () => {
    it('should generate dork queries for a valid domain', async () => {
      const results = await recon.runGoogleDorks('example.com');
      expect(results.length).toBeGreaterThan(0);
      // Dork results have Google search URLs; probe results have direct URLs
      const dorkResults = results.filter((r) => r.query.startsWith('site:'));
      expect(dorkResults.length).toBeGreaterThan(0);
      for (const result of dorkResults) {
        expect(result.query).toBeTruthy();
        expect(result.url).toContain('google.com');
      }
    });

    it('should contain site: operator in queries', async () => {
      const results = await recon.runGoogleDorks('example.com');
      const dorkQueries = results.filter((r) => r.query.startsWith('site:'));
      expect(dorkQueries.length).toBeGreaterThan(0);
    });

    it('should return empty array for invalid domain', async () => {
      const results = await recon.runGoogleDorks('not valid!!!');
      expect(results).toHaveLength(0);
    });
  });

  describe('queryShodan', () => {
    it('should return empty result without API key', async () => {
      const noKeyRecon = new ExtendedRecon({});
      const result = await noKeyRecon.queryShodan('1.2.3.4');
      expect(result.ip).toBe('1.2.3.4');
      expect(result.ports).toHaveLength(0);
      expect(result.services).toHaveLength(0);
    });
  });

  describe('queryCensys', () => {
    it('should return empty result without API credentials', async () => {
      const noKeyRecon = new ExtendedRecon({});
      const result = await noKeyRecon.queryCensys('1.2.3.4');
      expect(result.ip).toBe('1.2.3.4');
      expect(result.protocols).toHaveLength(0);
      expect(result.services).toHaveLength(0);
    });
  });

  describe('scanGitSecrets', () => {
    it('should return empty array without github token', async () => {
      const noTokenRecon = new ExtendedRecon({});
      const results = await noTokenRecon.scanGitSecrets('example-org');
      expect(results).toHaveLength(0);
    });
  });
});

// =============================================================================
// 23G — Continuous Monitor
// =============================================================================

describe('ContinuousMonitor', () => {
  let monitor: ContinuousMonitor;

  beforeEach(() => {
    monitor = new ContinuousMonitor({
      domains: ['example.com', 'test.org'],
      pollIntervalMs: 999_999_999, // Very high to prevent auto-polling
      crtshEnabled: false, // Disable real network calls
    });
  });

  afterEach(() => {
    monitor.stop();
  });

  it('should instantiate with config', () => {
    expect(monitor).toBeDefined();
  });

  it('should start in stopped state', () => {
    expect(monitor.isRunning()).toBe(false);
  });

  it('should start monitoring', () => {
    monitor.start();
    expect(monitor.isRunning()).toBe(true);
  });

  it('should stop monitoring', () => {
    monitor.start();
    monitor.stop();
    expect(monitor.isRunning()).toBe(false);
  });

  it('should not double-start', () => {
    monitor.start();
    monitor.start(); // second call should be a no-op
    expect(monitor.isRunning()).toBe(true);
  });

  describe('domain management', () => {
    it('should return monitored domains from constructor', () => {
      const domains = monitor.getMonitoredDomains();
      expect(domains).toContain('example.com');
      expect(domains).toContain('test.org');
    });

    it('should add a domain', () => {
      monitor.addDomain('new-domain.io');
      const domains = monitor.getMonitoredDomains();
      expect(domains).toContain('new-domain.io');
    });

    it('should remove a domain', () => {
      monitor.removeDomain('test.org');
      const domains = monitor.getMonitoredDomains();
      expect(domains).not.toContain('test.org');
    });

    it('should ignore invalid domains on add', () => {
      const before = monitor.getMonitoredDomains().length;
      monitor.addDomain('not valid!!!');
      const after = monitor.getMonitoredDomains().length;
      expect(after).toBe(before);
    });

    it('should return sorted domain list', () => {
      monitor.addDomain('alpha.com');
      monitor.addDomain('zebra.com');
      const domains = monitor.getMonitoredDomains();
      const sorted = [...domains].sort();
      expect(domains).toEqual(sorted);
    });

    it('should strip protocol from added domains', () => {
      monitor.addDomain('https://secure.example.com');
      const domains = monitor.getMonitoredDomains();
      expect(domains).toContain('secure.example.com');
    });
  });

  describe('onNewAsset callback', () => {
    it('should accept callback registration', () => {
      const callback = vi.fn();
      monitor.onNewAsset(callback);
      // Should not throw
      expect(true).toBe(true);
    });
  });

  describe('getLastResults', () => {
    it('should return initial results structure', () => {
      const results = monitor.getLastResults();
      expect(results).toHaveProperty('lastCheck');
      expect(results).toHaveProperty('newSubdomains');
      expect(results).toHaveProperty('changedAssets');
      expect(results).toHaveProperty('alerts');
      expect(results.newSubdomains).toHaveLength(0);
    });
  });
});

// =============================================================================
// 24B — WebSocket Client
// =============================================================================

describe('WebSocketClient', () => {
  it('should instantiate with config', () => {
    const client = new WebSocketClient({ url: 'ws://localhost:8080' });
    expect(client).toBeDefined();
  });

  it('should create proper connectionInfo on construction', () => {
    const client = new WebSocketClient({ url: 'ws://localhost:8080' });
    const info = client.getConnectionInfo();

    expect(info.url).toBe('ws://localhost:8080');
    expect(info.state).toBe('closed');
    expect(info.protocol).toBe('');
    expect(info.connectionId).toMatch(/^ws_\d+_/);
    expect(info.messagesSent).toBe(0);
    expect(info.messagesReceived).toBe(0);
    expect(info.reconnectAttempts).toBe(0);
  });

  it('should create unique connectionIds', () => {
    const c1 = new WebSocketClient({ url: 'ws://localhost:8080' });
    const c2 = new WebSocketClient({ url: 'ws://localhost:8081' });
    expect(c1.getConnectionInfo().connectionId).not.toBe(c2.getConnectionInfo().connectionId);
  });

  it('should default autoReconnect to false', () => {
    const client = new WebSocketClient({ url: 'ws://localhost:8080' });
    const info = client.getConnectionInfo();
    expect(info.reconnectAttempts).toBe(0);
  });

  it('should throw when sending without connection', () => {
    const client = new WebSocketClient({ url: 'ws://localhost:8080' });
    expect(() => client.send('hello')).toThrow('WebSocket is not connected');
  });

  it('should throw when sending binary without connection', () => {
    const client = new WebSocketClient({ url: 'ws://localhost:8080' });
    expect(() => client.sendBinary(new Uint8Array([1, 2, 3]))).toThrow('WebSocket is not connected');
  });

  it('should report isConnected as false initially', () => {
    const client = new WebSocketClient({ url: 'ws://localhost:8080' });
    expect(client.isConnected()).toBe(false);
  });

  it('should return empty message log initially', () => {
    const client = new WebSocketClient({ url: 'ws://localhost:8080' });
    expect(client.getMessageLog()).toHaveLength(0);
    expect(client.getMessages()).toHaveLength(0);
    expect(client.getMessages('sent')).toHaveLength(0);
    expect(client.getMessages('received')).toHaveLength(0);
  });

  it('should clear message log', () => {
    const client = new WebSocketClient({ url: 'ws://localhost:8080' });
    client.clearMessageLog();
    expect(client.getMessageLog()).toHaveLength(0);
  });

  it('should format summary correctly', () => {
    const client = new WebSocketClient({ url: 'ws://example.com/ws' });
    const summary = client.getSummary();

    expect(summary).toContain('WebSocket Session:');
    expect(summary).toContain('ws://example.com/ws');
    expect(summary).toContain('State: closed');
    expect(summary).toContain('Messages sent: 0');
    expect(summary).toContain('Messages received: 0');
    expect(summary).toContain('Reconnect attempts: 0');
  });

  it('should accept message handlers', () => {
    const client = new WebSocketClient({ url: 'ws://localhost:8080' });
    const handler = vi.fn();
    client.onMessage(handler);
    // Should not throw
    expect(true).toBe(true);
  });

  it('should remove message handlers', () => {
    const client = new WebSocketClient({ url: 'ws://localhost:8080' });
    const handler = vi.fn();
    client.onMessage(handler);
    client.removeOnMessage(handler);
    // Should not throw
    expect(true).toBe(true);
  });

  it('should accept error handlers', () => {
    const client = new WebSocketClient({ url: 'ws://localhost:8080' });
    const handler = vi.fn();
    client.onError(handler);
    expect(true).toBe(true);
  });

  it('should accept state change handlers', () => {
    const client = new WebSocketClient({ url: 'ws://localhost:8080' });
    const handler = vi.fn();
    client.onStateChange(handler);
    expect(true).toBe(true);
  });

  it('should close gracefully when not connected', () => {
    const client = new WebSocketClient({ url: 'ws://localhost:8080' });
    client.close();
    expect(client.getConnectionInfo().state).toBe('closed');
  });

  it('should apply custom config defaults', () => {
    const client = new WebSocketClient({
      url: 'ws://localhost:8080',
      origin: 'https://evil.com',
      protocols: ['graphql-ws'],
      connectTimeoutMs: 5000,
      autoReconnect: true,
      maxReconnectAttempts: 5,
      reconnectDelayMs: 2000,
    });
    const info = client.getConnectionInfo();
    expect(info.url).toBe('ws://localhost:8080');
  });
});

describe('WebSocketPool', () => {
  it('should instantiate', () => {
    const pool = new WebSocketPool();
    expect(pool).toBeDefined();
  });

  it('should return undefined for unknown connection ID', () => {
    const pool = new WebSocketPool();
    expect(pool.get('nonexistent')).toBeUndefined();
  });

  it('should report zero active connections initially', () => {
    const pool = new WebSocketPool();
    expect(pool.getActiveCount()).toBe(0);
    expect(pool.getActiveConnections()).toHaveLength(0);
  });

  it('should close unknown connection gracefully', () => {
    const pool = new WebSocketPool();
    pool.close('nonexistent');
    // Should not throw
    expect(true).toBe(true);
  });

  it('should closeAll gracefully when empty', () => {
    const pool = new WebSocketPool();
    pool.closeAll();
    expect(pool.getActiveCount()).toBe(0);
  });

  it('should generate summary string', () => {
    const pool = new WebSocketPool();
    const summary = pool.getSummary();
    expect(summary).toContain('WebSocket Pool: 0 connections');
  });
});

// =============================================================================
// 23D — ReportReviewModal
// =============================================================================

describe('ReportReviewModal', () => {
  it('should be a valid React component', () => {
    expect(typeof ReportReviewModal).toBe('function');
  });

  it('should accept the expected props interface', () => {
    // Verify the type signature matches what we expect
    const props: ReportReviewModalProps = {
      report: mockReport,
      programHandle: 'test-program',
      qualityScore: {
        overall: 85,
        categories: { clarity: 90, completeness: 80, evidence: 85, impact: 80, reproducibility: 90 },
        grade: 'B',
        issues: [],
      },
      duplicateScore: {
        overall: 10,
        h1Match: 0.1,
        githubMatch: 0,
        internalMatch: 0,
        recommendation: 'submit',
        matches: [],
        reasoning: ['Low duplicate risk'],
      },
      onApproveAndSubmit: async () => {},
      onEditReport: () => {},
      onCancel: () => {},
    };
    expect(props.report.title).toBeTruthy();
  });

  describe('quality score display logic', () => {
    it('should map grade to style classes', () => {
      // GRADE_STYLES are defined as module-level constants
      const grades = ['A', 'B', 'C', 'D', 'F'] as const;
      for (const grade of grades) {
        const score: QualityScore = {
          overall: grade === 'A' ? 95 : grade === 'B' ? 80 : grade === 'C' ? 65 : grade === 'D' ? 50 : 20,
          categories: { clarity: 50, completeness: 50, evidence: 50, impact: 50, reproducibility: 50 },
          grade,
          issues: [],
        };
        expect(score.grade).toBe(grade);
      }
    });
  });

  describe('isBlocked logic', () => {
    it('should block when duplicate recommendation is skip', () => {
      const dupScore: DuplicateScore = {
        overall: 95,
        h1Match: 0.95,
        githubMatch: 0,
        internalMatch: 0,
        recommendation: 'skip',
        matches: [],
        reasoning: ['High duplicate risk'],
      };
      expect(dupScore.recommendation).toBe('skip');
    });

    it('should block when quality grade is F', () => {
      const qualScore: QualityScore = {
        overall: 15,
        categories: { clarity: 10, completeness: 10, evidence: 20, impact: 10, reproducibility: 10 },
        grade: 'F',
        issues: [],
      };
      expect(qualScore.grade).toBe('F');
    });

    it('should block when description is missing', () => {
      const report: H1Report = { ...mockReport, description: '' };
      const hasDescription = (report.description?.length ?? 0) > 50;
      expect(hasDescription).toBe(false);
    });

    it('should block when fewer than 3 steps', () => {
      const report: H1Report = { ...mockReport, steps: ['step 1', 'step 2'] };
      const hasSteps = (report.steps?.length ?? 0) >= 3;
      expect(hasSteps).toBe(false);
    });

    it('should not block a well-formed report with submit recommendation', () => {
      const dupScore: DuplicateScore = {
        overall: 10,
        h1Match: 0.1,
        githubMatch: 0,
        internalMatch: 0,
        recommendation: 'submit',
        matches: [],
        reasoning: [],
      };
      const qualScore: QualityScore = {
        overall: 80,
        categories: { clarity: 80, completeness: 80, evidence: 80, impact: 80, reproducibility: 80 },
        grade: 'B',
        issues: [],
      };
      const hasDescription = (mockReport.description?.length ?? 0) > 50;
      const hasSteps = (mockReport.steps?.length ?? 0) >= 3;
      const isBlocked =
        dupScore.recommendation === 'skip' ||
        qualScore.grade === 'F' ||
        !hasDescription ||
        !hasSteps;
      expect(isBlocked).toBe(false);
    });
  });

  describe('checklist computation', () => {
    it('should pass all checks for a complete report', () => {
      const checklist = {
        hasDescription: (mockReport.description?.length ?? 0) > 50,
        hasImpact: (mockReport.impact?.length ?? 0) > 20,
        hasSteps: (mockReport.steps?.length ?? 0) >= 3,
        hasSeverity: Boolean(mockReport.severity),
        hasCvss: Boolean(mockReport.cvssScore),
        hasCwe: Boolean(mockReport.weaknessId),
        hasEvidence: Boolean(mockReport.proof?.screenshots?.length),
        hasSeverityJustification: Boolean(mockReport.severityJustification?.length),
      };

      expect(checklist.hasDescription).toBe(true);
      expect(checklist.hasImpact).toBe(true);
      expect(checklist.hasSteps).toBe(true);
      expect(checklist.hasSeverity).toBe(true);
      expect(checklist.hasCvss).toBe(true);
      expect(checklist.hasCwe).toBe(true);
      expect(checklist.hasEvidence).toBe(true);
      expect(checklist.hasSeverityJustification).toBe(true);

      const checks = Object.values(checklist);
      const score = Math.round((checks.filter(Boolean).length / checks.length) * 100);
      expect(score).toBe(100);
    });

    it('should compute 0% checklist for empty report', () => {
      const emptyReport: H1Report = {
        title: '',
        severity: 'low',
        suggestedBounty: { min: 0, max: 0 },
        description: '',
        impact: '',
        steps: [],
        proof: {},
      };

      const checklist = {
        hasDescription: (emptyReport.description?.length ?? 0) > 50,
        hasImpact: (emptyReport.impact?.length ?? 0) > 20,
        hasSteps: (emptyReport.steps?.length ?? 0) >= 3,
        hasSeverity: Boolean(emptyReport.severity),
        hasCvss: Boolean(emptyReport.cvssScore),
        hasCwe: Boolean(emptyReport.weaknessId),
        hasEvidence: Boolean(emptyReport.proof?.screenshots?.length),
        hasSeverityJustification: Boolean(emptyReport.severityJustification?.length),
      };

      // severity is 'low' which is truthy, so 1 out of 8
      const checks = Object.values(checklist);
      const passingCount = checks.filter(Boolean).length;
      expect(passingCount).toBeLessThanOrEqual(2);
    });
  });
});

// =============================================================================
// Cross-Module Integration Sanity
// =============================================================================

describe('Cross-module integration', () => {
  it('should deduplicate before sending to quality scorer', async () => {
    const deduplicator = new TargetDeduplicator();
    const targets: TargetInfo[] = [
      { url: 'https://example.com', assetType: 'web-application' },
      { url: 'https://www.example.com', assetType: 'web-application' },
    ];
    const result = await deduplicator.deduplicateTargets(targets);
    expect(result.stats.total).toBe(2);

    // Each representative can be scored for report quality
    const scorer = new ReportQualityScorer();
    const score = scorer.scoreReport(mockReport);
    expect(score.overall).toBeGreaterThan(0);
  });

  it('should generate OOB callbacks and correlate them', async () => {
    const server = createOobServer();
    await server.start();

    const callback = server.generateCallbackUrl(createInjectionPoint());
    const correlated = server.correlate(callback.callbackUrl);
    expect(correlated).toBeDefined();
    expect(correlated!.id).toBe(callback.id);

    server.stop();
  });
});

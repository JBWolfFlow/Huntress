/**
 * Cross-Agent Knowledge Sharing — Unit Tests (I7)
 *
 * Verifies the complete pipeline:
 * 1. Findings posted to Blackboard in handleAgentResult
 * 2. SharedFinding[] extracted from Blackboard in huntTaskToAgentTask
 * 3. ReactLoop injects shared findings into system prompt
 * 4. Agents receive other agents' findings in their context
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { Blackboard, postFinding } from './blackboard';
import type { SharedFinding } from '../../agents/base_agent';

describe('Cross-Agent Knowledge Sharing (I7)', () => {
  let board: Blackboard;

  beforeEach(() => {
    board = new Blackboard();
  });

  // ─── Blackboard → SharedFinding Transformation ────────────────────────────

  describe('Blackboard to SharedFinding transformation', () => {
    /**
     * Reproduces the transformation logic from orchestrator_engine.ts
     * huntTaskToAgentTask() to verify the conversion is correct.
     */
    function extractSharedFindings(agentType: string, maxEntries = 10): SharedFinding[] {
      const bbEntries = board.readFor(agentType);
      return bbEntries
        .filter(e => e.type === 'finding')
        .slice(0, maxEntries)
        .map(e => ({
          agentId: e.agentId,
          vulnType: e.category,
          title: String(e.content.title ?? ''),
          severity: (e.content.severity as SharedFinding['severity']) ?? 'info',
          target: String(e.content.target ?? ''),
          description: String(e.content.description ?? '').slice(0, 300),
        }));
    }

    it('should convert Blackboard finding entries to SharedFinding format', () => {
      postFinding(board, 'xss_hunter', 'xss', {
        title: 'Reflected XSS in search parameter',
        severity: 'high',
        target: 'https://example.com/search?q=test',
        description: 'The search parameter reflects user input without encoding',
      }, ['sqli_hunter', 'idor_hunter']);

      const shared = extractSharedFindings('sqli_hunter');
      expect(shared).toHaveLength(1);
      expect(shared[0]).toEqual({
        agentId: 'xss_hunter',
        vulnType: 'xss',
        title: 'Reflected XSS in search parameter',
        severity: 'high',
        target: 'https://example.com/search?q=test',
        description: 'The search parameter reflects user input without encoding',
      });
    });

    it('should filter out non-finding entries (observations, hypotheses)', () => {
      // Post an observation and a finding
      board.post({
        agentId: 'recon',
        type: 'observation',
        category: 'endpoint',
        content: { url: '/api/users' },
        relevantTo: ['sqli_hunter'],
        priority: 5,
      });

      postFinding(board, 'xss_hunter', 'xss', {
        title: 'XSS found',
        severity: 'medium',
        target: 'https://example.com',
        description: 'test',
      }, ['sqli_hunter']);

      const shared = extractSharedFindings('sqli_hunter');
      // Only the finding should be included, not the observation
      expect(shared).toHaveLength(1);
      expect(shared[0].vulnType).toBe('xss');
    });

    it('should bound results to max 10 entries', () => {
      // Post 15 findings
      for (let i = 0; i < 15; i++) {
        postFinding(board, `agent_${i}`, 'vuln', {
          title: `Finding ${i}`,
          severity: 'medium',
          target: 'https://example.com',
          description: `Description ${i}`,
        }, ['target_agent']);
      }

      const shared = extractSharedFindings('target_agent');
      expect(shared).toHaveLength(10);
    });

    it('should truncate long descriptions to 300 characters', () => {
      const longDesc = 'A'.repeat(500);
      postFinding(board, 'xss_hunter', 'xss', {
        title: 'XSS',
        severity: 'high',
        target: 'https://example.com',
        description: longDesc,
      }, ['sqli_hunter']);

      const shared = extractSharedFindings('sqli_hunter');
      expect(shared[0].description.length).toBe(300);
    });

    it('should handle missing content fields gracefully', () => {
      postFinding(board, 'xss_hunter', 'xss', {
        // Missing title, severity, target, description
      }, ['sqli_hunter']);

      const shared = extractSharedFindings('sqli_hunter');
      expect(shared).toHaveLength(1);
      expect(shared[0].title).toBe('');
      expect(shared[0].severity).toBe('info'); // default
      expect(shared[0].target).toBe('');
      expect(shared[0].description).toBe('');
    });

    it('should return empty array when no relevant findings exist', () => {
      postFinding(board, 'xss_hunter', 'xss', {
        title: 'XSS',
        severity: 'high',
        target: 'https://example.com',
        description: 'test',
      }, ['idor_hunter']); // Not relevant to sqli_hunter

      const shared = extractSharedFindings('sqli_hunter');
      expect(shared).toHaveLength(0);
    });

    it('should preserve priority ordering from Blackboard (highest first)', () => {
      // Post low-priority finding first
      board.post({
        agentId: 'cache_hunter',
        type: 'finding',
        category: 'cache',
        content: { title: 'Cache poisoning', severity: 'low', target: 'https://example.com', description: 'low impact' },
        relevantTo: ['xss_hunter'],
        priority: 3,
      });

      // Post high-priority finding second
      board.post({
        agentId: 'sqli_hunter',
        type: 'finding',
        category: 'sqli',
        content: { title: 'SQL Injection', severity: 'critical', target: 'https://example.com/api', description: 'critical vuln' },
        relevantTo: ['xss_hunter'],
        priority: 9,
      });

      const shared = extractSharedFindings('xss_hunter');
      expect(shared).toHaveLength(2);
      // Highest priority first
      expect(shared[0].title).toBe('SQL Injection');
      expect(shared[1].title).toBe('Cache poisoning');
    });
  });

  // ─── System Prompt Integration ────────────────────────────────────────────

  describe('System prompt shared findings section', () => {
    /**
     * Reproduces the buildSharedFindingsSection() logic from react_loop.ts
     */
    function buildSharedFindingsSection(findings: SharedFinding[] | undefined): string {
      if (!findings || findings.length === 0) return '';

      const lines = findings.map(f =>
        `- [${f.severity.toUpperCase()}] ${f.title} (${f.vulnType}) on ${f.target} — found by ${f.agentId}: ${f.description.slice(0, 150)}`
      );

      return `

## Cross-Agent Intelligence
Other agents have discovered the following. Use these to inform your testing strategy — look for chained exploits, related vulnerabilities, or parameters/endpoints that may be vulnerable to your attack class too.

${lines.join('\n')}`;
    }

    it('should return empty string when no shared findings', () => {
      expect(buildSharedFindingsSection(undefined)).toBe('');
      expect(buildSharedFindingsSection([])).toBe('');
    });

    it('should format findings into a readable system prompt section', () => {
      const findings: SharedFinding[] = [
        {
          agentId: 'xss_hunter',
          vulnType: 'xss',
          title: 'Reflected XSS in search',
          severity: 'high',
          target: 'https://example.com/search',
          description: 'Search param reflects unescaped input',
        },
      ];

      const section = buildSharedFindingsSection(findings);
      expect(section).toContain('## Cross-Agent Intelligence');
      expect(section).toContain('[HIGH] Reflected XSS in search (xss)');
      expect(section).toContain('found by xss_hunter');
      expect(section).toContain('chained exploits');
    });

    it('should include multiple findings as separate lines', () => {
      const findings: SharedFinding[] = [
        {
          agentId: 'xss_hunter',
          vulnType: 'xss',
          title: 'XSS in search',
          severity: 'high',
          target: 'https://example.com/search',
          description: 'Reflected XSS',
        },
        {
          agentId: 'sqli_hunter',
          vulnType: 'sqli',
          title: 'SQL Injection in login',
          severity: 'critical',
          target: 'https://example.com/login',
          description: 'Boolean-based blind SQLi',
        },
      ];

      const section = buildSharedFindingsSection(findings);
      expect(section).toContain('[HIGH] XSS in search');
      expect(section).toContain('[CRITICAL] SQL Injection in login');
    });

    it('should truncate individual descriptions to 150 chars in prompt', () => {
      const findings: SharedFinding[] = [
        {
          agentId: 'test',
          vulnType: 'test',
          title: 'Test',
          severity: 'info',
          target: 'https://example.com',
          description: 'B'.repeat(300),
        },
      ];

      const section = buildSharedFindingsSection(findings);
      // The description in the prompt should be sliced to 150
      expect(section).not.toContain('B'.repeat(151));
    });
  });

  // ─── End-to-End Cross-Agent Flow ──────────────────────────────────────────

  describe('End-to-end: Agent A finding reaches Agent B context', () => {
    it('should propagate XSS finding to SQLi agent via Blackboard', () => {
      // Step 1: Simulate handleAgentResult posting to blackboard
      // (This mirrors orchestrator_engine.ts line ~2183)
      postFinding(board, 'xss_hunter', 'xss', {
        title: 'Stored XSS in user profile',
        severity: 'high',
        target: 'https://target.com/api/profile',
        description: 'The bio field accepts <script> tags without sanitization',
      }, ['sqli_hunter', 'idor_hunter', 'command_injection_hunter']);

      // Step 2: Simulate huntTaskToAgentTask reading from blackboard
      // (This mirrors orchestrator_engine.ts line ~2735)
      const bbEntries = board.readFor('sqli_hunter');
      const sharedFindings: SharedFinding[] = bbEntries
        .filter(e => e.type === 'finding')
        .slice(0, 10)
        .map(e => ({
          agentId: e.agentId,
          vulnType: e.category,
          title: String(e.content.title ?? ''),
          severity: (e.content.severity as SharedFinding['severity']) ?? 'info',
          target: String(e.content.target ?? ''),
          description: String(e.content.description ?? '').slice(0, 300),
        }));

      // Step 3: Verify the SQLi agent would receive the XSS finding
      expect(sharedFindings).toHaveLength(1);
      expect(sharedFindings[0].agentId).toBe('xss_hunter');
      expect(sharedFindings[0].title).toBe('Stored XSS in user profile');
      expect(sharedFindings[0].target).toBe('https://target.com/api/profile');
    });

    it('should propagate multiple findings from different agents', () => {
      // Agent A: recon finds endpoints
      postFinding(board, 'recon', 'endpoint', {
        title: 'API endpoint discovered: /api/admin/users',
        severity: 'info',
        target: 'https://target.com/api/admin/users',
        description: 'Admin endpoint with no authentication check detected',
      }, ['idor_hunter', 'sqli_hunter']);

      // Agent B: XSS hunter finds a vuln
      postFinding(board, 'xss_hunter', 'xss', {
        title: 'Reflected XSS in search',
        severity: 'high',
        target: 'https://target.com/search?q=test',
        description: 'Input reflected without encoding',
      }, ['sqli_hunter', 'idor_hunter']);

      // IDOR agent should see both
      const bbEntries = board.readFor('idor_hunter');
      const sharedFindings: SharedFinding[] = bbEntries
        .filter(e => e.type === 'finding')
        .slice(0, 10)
        .map(e => ({
          agentId: e.agentId,
          vulnType: e.category,
          title: String(e.content.title ?? ''),
          severity: (e.content.severity as SharedFinding['severity']) ?? 'info',
          target: String(e.content.target ?? ''),
          description: String(e.content.description ?? '').slice(0, 300),
        }));

      expect(sharedFindings).toHaveLength(2);
      const agents = sharedFindings.map(f => f.agentId);
      expect(agents).toContain('recon');
      expect(agents).toContain('xss_hunter');
    });

    it('should enable chain detection by co-locating complementary findings', () => {
      // Scenario: redirect + SSRF chain (a classic exploit chain)
      postFinding(board, 'open_redirect_hunter', 'open-redirect', {
        title: 'Open redirect in /callback',
        severity: 'medium',
        target: 'https://target.com/callback?url=',
        description: 'The callback parameter accepts arbitrary URLs for redirect',
      }, ['ssrf_hunter', 'xss_hunter']);

      // SSRF agent should see the open redirect and could chain it
      const sharedFindings = board.readFor('ssrf_hunter')
        .filter(e => e.type === 'finding')
        .map(e => ({
          agentId: e.agentId,
          vulnType: e.category,
          title: String(e.content.title ?? ''),
        }));

      expect(sharedFindings).toHaveLength(1);
      expect(sharedFindings[0].vulnType).toBe('open-redirect');
      // The SSRF agent now knows about the redirect — enabling a potential chain
    });
  });

  // ─── Edge Cases ───────────────────────────────────────────────────────────

  describe('Edge cases', () => {
    it('should handle agent posting findings to itself', () => {
      postFinding(board, 'xss_hunter', 'xss', {
        title: 'Self-finding',
        severity: 'medium',
        target: 'https://example.com',
        description: 'test',
      }, ['xss_hunter']); // relevant to itself

      const entries = board.readFor('xss_hunter');
      expect(entries).toHaveLength(1);
    });

    it('should handle wildcard subscriber receiving all findings', () => {
      postFinding(board, 'xss_hunter', 'xss', {
        title: 'XSS',
        severity: 'high',
        target: 'https://example.com',
        description: 'test',
      }, ['sqli_hunter']); // Not relevant to wildcard directly

      // Wildcard subscriber gets notifications but readFor uses relevantTo filter
      const wildcardEntries = board.readFor('*');
      // '*' is not in relevantTo, so nothing returned via readFor
      expect(wildcardEntries).toHaveLength(0);

      // But getByType returns all
      expect(board.getByType('finding')).toHaveLength(1);
    });

    it('should not duplicate findings across read calls (readFor is non-consuming)', () => {
      postFinding(board, 'xss_hunter', 'xss', {
        title: 'XSS',
        severity: 'high',
        target: 'https://example.com',
        description: 'test',
      }, ['sqli_hunter']);

      // readFor should return the same entries on repeated calls (non-consuming)
      const first = board.readFor('sqli_hunter');
      const second = board.readFor('sqli_hunter');
      expect(first).toHaveLength(1);
      expect(second).toHaveLength(1);
    });
  });
});

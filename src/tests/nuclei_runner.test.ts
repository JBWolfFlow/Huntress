/**
 * Nuclei Template Scanner Tests (Phase 20F)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NucleiRunner } from '../core/discovery/nuclei_runner';
import type { NucleiConfig, NucleiFinding } from '../core/discovery/nuclei_runner';

// Mock tauri_bridge
vi.mock('../core/tauri_bridge', () => ({
  executeCommand: vi.fn(),
}));

import { executeCommand } from '../core/tauri_bridge';
const mockExecuteCommand = vi.mocked(executeCommand);

// ─── Sample JSONL Output ─────────────────────────────────────────────────────

const SAMPLE_JSONL_LINE = JSON.stringify({
  'template-id': 'CVE-2023-12345',
  info: {
    name: 'WordPress Plugin RCE',
    severity: 'critical',
    description: 'Remote code execution in WordPress plugin',
    reference: ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-12345'],
    tags: ['cve', 'wordpress', 'rce'],
  },
  host: 'https://example.com',
  'matched-at': 'https://example.com/wp-content/plugins/vuln/exploit.php',
  'matcher-name': 'rce-matcher',
  'extracted-results': ['root:x:0:0:'],
  'curl-command': "curl -X GET 'https://example.com/wp-content/plugins/vuln/exploit.php?cmd=id'",
});

const SAMPLE_JSONL_LINE_2 = JSON.stringify({
  'template-id': 'exposed-gitconfig',
  info: {
    name: 'Exposed Git Configuration',
    severity: 'medium',
    description: 'Git configuration file exposed',
    reference: [],
    tags: ['exposure', 'git', 'config'],
  },
  host: 'https://example.com',
  'matched-at': 'https://example.com/.git/config',
  'extracted-results': [],
});

const SAMPLE_JSONL_INFO = JSON.stringify({
  'template-id': 'tech-detect-nginx',
  info: {
    name: 'Nginx Detected',
    severity: 'info',
    description: 'Nginx web server detected',
    reference: [],
    tags: ['tech', 'nginx'],
  },
  host: 'https://example.com',
  'matched-at': 'https://example.com/',
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('NucleiRunner', () => {
  let runner: NucleiRunner;

  beforeEach(() => {
    vi.clearAllMocks();
    runner = new NucleiRunner();
  });

  describe('isAvailable', () => {
    it('returns true when nuclei binary is accessible', async () => {
      mockExecuteCommand.mockResolvedValue({
        exitCode: 0,
        stdout: 'Nuclei Engine v3.0.0',
        stderr: '',
      });

      expect(await runner.isAvailable()).toBe(true);
      expect(mockExecuteCommand).toHaveBeenCalledWith('nuclei', ['-version']);
    });

    it('returns false when nuclei binary is not found', async () => {
      mockExecuteCommand.mockRejectedValue(new Error('Command not found'));

      expect(await runner.isAvailable()).toBe(false);
    });
  });

  describe('parseOutput', () => {
    it('parses valid JSONL output', () => {
      const output = `${SAMPLE_JSONL_LINE}\n${SAMPLE_JSONL_LINE_2}`;
      const findings = runner.parseOutput(output);

      expect(findings).toHaveLength(2);
      expect(findings[0].templateId).toBe('CVE-2023-12345');
      expect(findings[0].templateName).toBe('WordPress Plugin RCE');
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].target).toBe('https://example.com');
      expect(findings[0].matchedUrl).toBe('https://example.com/wp-content/plugins/vuln/exploit.php');
      expect(findings[0].tags).toContain('cve');
      expect(findings[0].tags).toContain('wordpress');
      expect(findings[0].reference).toContain('https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-12345');
      expect(findings[0].extractedResults).toContain('root:x:0:0:');
      expect(findings[0].curlCommand).toBeDefined();

      expect(findings[1].templateId).toBe('exposed-gitconfig');
      expect(findings[1].severity).toBe('medium');
    });

    it('handles malformed lines gracefully', () => {
      const output = `${SAMPLE_JSONL_LINE}\nthis is not json\n${SAMPLE_JSONL_LINE_2}\n{broken`;
      const findings = runner.parseOutput(output);

      expect(findings).toHaveLength(2);
    });

    it('handles empty output', () => {
      expect(runner.parseOutput('')).toEqual([]);
      expect(runner.parseOutput('   ')).toEqual([]);
    });

    it('handles output with trailing newlines', () => {
      const output = `${SAMPLE_JSONL_LINE}\n\n\n`;
      const findings = runner.parseOutput(output);

      expect(findings).toHaveLength(1);
    });
  });

  describe('toAgentFinding', () => {
    it('converts NucleiFinding to AgentFinding with CVE tag', () => {
      const findings = runner.parseOutput(SAMPLE_JSONL_LINE);
      const agentFinding = runner.toAgentFinding(findings[0]);

      expect(agentFinding.agentId).toBe('nuclei_scanner');
      expect(agentFinding.type).toBe('known_cve');
      expect(agentFinding.title).toBe('WordPress Plugin RCE');
      expect(agentFinding.severity).toBe('critical');
      expect(agentFinding.target).toBe('https://example.com');
      expect(agentFinding.evidence).toContain("curl -X GET 'https://example.com/wp-content/plugins/vuln/exploit.php?cmd=id'");
      expect(agentFinding.evidence).toContain('Template: CVE-2023-12345');
      expect(agentFinding.reproduction.length).toBeGreaterThan(0);
      expect(agentFinding.id).toMatch(/^nuclei_/);
    });

    it('converts NucleiFinding without CVE tag to misconfiguration type', () => {
      const findings = runner.parseOutput(SAMPLE_JSONL_LINE_2);
      const agentFinding = runner.toAgentFinding(findings[0]);

      expect(agentFinding.type).toBe('misconfiguration');
      expect(agentFinding.title).toBe('Exposed Git Configuration');
    });

    it('handles finding without curl command', () => {
      const findings = runner.parseOutput(SAMPLE_JSONL_LINE_2);
      const agentFinding = runner.toAgentFinding(findings[0]);

      // Evidence should not contain undefined
      expect(agentFinding.evidence.every(e => e !== undefined)).toBe(true);
    });
  });

  describe('scan', () => {
    it('returns empty results when nuclei is not available', async () => {
      mockExecuteCommand.mockRejectedValue(new Error('Command not found'));

      const result = await runner.scan({ targets: ['https://example.com'] });

      expect(result.findings).toEqual([]);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain('not found');
    });

    it('runs nuclei and parses results', async () => {
      // First call: version check
      mockExecuteCommand.mockResolvedValueOnce({
        exitCode: 0,
        stdout: 'v3.0.0',
        stderr: '',
      });

      // Second call: actual scan
      mockExecuteCommand.mockResolvedValueOnce({
        exitCode: 0,
        stdout: `${SAMPLE_JSONL_LINE}\n${SAMPLE_JSONL_LINE_2}`,
        stderr: 'Templates loaded for scan: 200',
      });

      const result = await runner.scan({
        targets: ['https://example.com'],
        minSeverity: 'low',
      });

      expect(result.findings).toHaveLength(2);
      expect(result.targetsTested).toBe(1);
      expect(result.errors).toEqual([]);
    });

    it('filters by minimum severity', async () => {
      mockExecuteCommand.mockResolvedValueOnce({ exitCode: 0, stdout: 'v3.0.0', stderr: '' });
      mockExecuteCommand.mockResolvedValueOnce({
        exitCode: 0,
        stdout: `${SAMPLE_JSONL_LINE}\n${SAMPLE_JSONL_LINE_2}\n${SAMPLE_JSONL_INFO}`,
        stderr: '',
      });

      const result = await runner.scan({
        targets: ['https://example.com'],
        minSeverity: 'high',
      });

      // Only critical finding should pass the high+ filter
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
    });

    it('returns empty results for empty target list', async () => {
      const result = await runner.scan({ targets: [] });

      expect(result.findings).toEqual([]);
      expect(result.targetsTested).toBe(0);
    });
  });

  describe('scanForTech', () => {
    it('maps technologies to nuclei tags', async () => {
      mockExecuteCommand.mockResolvedValueOnce({ exitCode: 0, stdout: 'v3.0.0', stderr: '' });
      mockExecuteCommand.mockResolvedValueOnce({
        exitCode: 0,
        stdout: SAMPLE_JSONL_LINE,
        stderr: '',
      });

      await runner.scanForTech(['https://example.com'], ['wordpress', 'nginx']);

      // Should have been called with tech tags
      const scanCall = mockExecuteCommand.mock.calls[1];
      const args = scanCall[1] as string[];
      expect(args).toContain('-tags');
      // Should include wordpress and nginx tags
      const tagsIdx = args.indexOf('-tags');
      const tagsValue = args[tagsIdx + 1];
      expect(tagsValue).toContain('wordpress');
      expect(tagsValue).toContain('nginx');
    });

    it('falls back to general categories when no tech match', async () => {
      mockExecuteCommand.mockResolvedValueOnce({ exitCode: 0, stdout: 'v3.0.0', stderr: '' });
      mockExecuteCommand.mockResolvedValueOnce({
        exitCode: 0,
        stdout: '',
        stderr: '',
      });

      await runner.scanForTech(['https://example.com'], ['unknown_tech_xyz']);

      const scanCall = mockExecuteCommand.mock.calls[1];
      const args = scanCall[1] as string[];
      // Should have template categories instead of tags
      expect(args).toContain('-t');
    });
  });

  describe('updateTemplates', () => {
    it('updates templates successfully', async () => {
      mockExecuteCommand.mockResolvedValueOnce({ exitCode: 0, stdout: 'v3.0.0', stderr: '' });
      mockExecuteCommand.mockResolvedValueOnce({
        exitCode: 0,
        stdout: 'All templates are up-to-date: 4500 templates',
        stderr: '',
      });

      const result = await runner.updateTemplates();
      expect(result.success).toBe(true);
      expect(result.templateCount).toBe(4500);
    });

    it('handles update failure', async () => {
      mockExecuteCommand.mockRejectedValue(new Error('Command not found'));

      const result = await runner.updateTemplates();
      expect(result.success).toBe(false);
    });
  });

  describe('command construction', () => {
    it('builds correct argv for single target', async () => {
      mockExecuteCommand.mockResolvedValueOnce({ exitCode: 0, stdout: 'v3.0.0', stderr: '' });
      mockExecuteCommand.mockResolvedValueOnce({ exitCode: 0, stdout: '', stderr: '' });

      await runner.scan({
        targets: ['https://example.com'],
        concurrency: 25,
        rateLimit: 150,
        timeoutSeconds: 10,
      });

      const scanCall = mockExecuteCommand.mock.calls[1];
      const args = scanCall[1] as string[];

      expect(args).toContain('-jsonl');
      expect(args).toContain('-target');
      expect(args).toContain('https://example.com');
      expect(args).toContain('-concurrency');
      expect(args).toContain('25');
      expect(args).toContain('-rate-limit');
      expect(args).toContain('150');
      expect(args).toContain('-timeout');
      expect(args).toContain('10');
      expect(args).toContain('-silent');

      // Verify it's argv array, not a shell string
      expect(args.every(a => typeof a === 'string')).toBe(true);
    });

    it('builds correct argv for multiple targets', async () => {
      mockExecuteCommand.mockResolvedValueOnce({ exitCode: 0, stdout: 'v3.0.0', stderr: '' });
      mockExecuteCommand.mockResolvedValueOnce({ exitCode: 0, stdout: '', stderr: '' });

      await runner.scan({
        targets: ['https://a.com', 'https://b.com'],
      });

      const scanCall = mockExecuteCommand.mock.calls[1];
      const args = scanCall[1] as string[];
      expect(args).toContain('https://a.com,https://b.com');
    });

    it('includes template categories when specified', async () => {
      mockExecuteCommand.mockResolvedValueOnce({ exitCode: 0, stdout: 'v3.0.0', stderr: '' });
      mockExecuteCommand.mockResolvedValueOnce({ exitCode: 0, stdout: '', stderr: '' });

      await runner.scan({
        targets: ['https://example.com'],
        templateCategories: ['cves', 'misconfigurations'],
      });

      const scanCall = mockExecuteCommand.mock.calls[1];
      const args = scanCall[1] as string[];
      expect(args).toContain('-t');
      expect(args).toContain('cves,misconfigurations');
    });

    it('includes template IDs when specified', async () => {
      mockExecuteCommand.mockResolvedValueOnce({ exitCode: 0, stdout: 'v3.0.0', stderr: '' });
      mockExecuteCommand.mockResolvedValueOnce({ exitCode: 0, stdout: '', stderr: '' });

      await runner.scan({
        targets: ['https://example.com'],
        templateIds: ['CVE-2023-12345', 'CVE-2023-67890'],
      });

      const scanCall = mockExecuteCommand.mock.calls[1];
      const args = scanCall[1] as string[];
      expect(args).toContain('-id');
      expect(args).toContain('CVE-2023-12345,CVE-2023-67890');
    });
  });

  describe('stop', () => {
    it('can be called safely when no scan is running', () => {
      expect(() => runner.stop()).not.toThrow();
    });
  });
});

/**
 * Nuclei Template Scanner (Phase 20F)
 *
 * Wraps the Nuclei binary for automated vulnerability scanning using 4,000+
 * community templates. Detects known CVEs, misconfigurations, exposed files,
 * default credentials, and technology fingerprints — the "low-hanging fruit"
 * that pay real bounties. A single Nuclei scan finds in 60 seconds what would
 * cost $50 in LLM calls.
 *
 * Graceful degradation: if the nuclei binary is not installed, scan() returns
 * empty results with an error message — never crashes.
 */

import { executeCommand } from '../tauri_bridge';
import type { AgentFinding } from '../../agents/base_agent';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface NucleiConfig {
  /** Target URL or list of URLs */
  targets: string[];
  /** Template categories to run (e.g., 'cves', 'misconfigurations', 'exposures') */
  templateCategories?: string[];
  /** Specific template IDs to run */
  templateIds?: string[];
  /** Severity filter: only run templates of this severity or higher */
  minSeverity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
  /** Technology tags to filter templates (e.g., 'wordpress', 'nginx', 'apache') */
  techTags?: string[];
  /** Max concurrent template executions */
  concurrency?: number;
  /** Rate limit (requests per second) */
  rateLimit?: number;
  /** Timeout per template in seconds */
  timeoutSeconds?: number;
}

export interface NucleiResult {
  findings: NucleiFinding[];
  templatesRun: number;
  targetsTested: number;
  durationMs: number;
  errors: string[];
}

export interface NucleiFinding {
  templateId: string;
  templateName: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  target: string;
  matchedUrl: string;
  matcherName?: string;
  extractedResults?: string[];
  description: string;
  reference?: string[];
  tags: string[];
  curlCommand?: string;
  timestamp: number;
}

interface NucleiRunnerConfig {
  nucleiBinaryPath?: string;
}

// ─── Technology → Nuclei Tag Mapping ─────────────────────────────────────────

const TECH_TO_TAGS: Record<string, string[]> = {
  wordpress: ['wordpress', 'wp-plugin', 'wp-theme'],
  nginx: ['nginx'],
  apache: ['apache'],
  react: ['react', 'javascript'],
  angular: ['angular'],
  django: ['django', 'python'],
  rails: ['rails', 'ruby'],
  spring: ['spring', 'java'],
  laravel: ['laravel', 'php'],
  node: ['nodejs', 'express'],
  express: ['nodejs', 'express'],
  iis: ['iis', 'aspnet'],
  tomcat: ['tomcat', 'java'],
  jboss: ['jboss', 'java'],
  drupal: ['drupal', 'php'],
  joomla: ['joomla', 'php'],
  magento: ['magento', 'php'],
  shopify: ['shopify'],
  flask: ['flask', 'python'],
  nextjs: ['nextjs', 'javascript'],
  graphql: ['graphql'],
};

// ─── Severity Ranking ────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

// ─── Nuclei Runner ───────────────────────────────────────────────────────────

export class NucleiRunner {
  private binaryPath: string;
  private abortController: AbortController | null = null;

  constructor(config?: NucleiRunnerConfig) {
    this.binaryPath = config?.nucleiBinaryPath ?? 'nuclei';
  }

  /** Check if Nuclei is installed and accessible */
  async isAvailable(): Promise<boolean> {
    try {
      const result = await executeCommand(this.binaryPath, ['-version']);
      return result.exitCode === 0;
    } catch {
      return false;
    }
  }

  /** Run Nuclei scan with given config */
  async scan(config: NucleiConfig): Promise<NucleiResult> {
    const startTime = Date.now();
    const errors: string[] = [];

    // Check availability first
    const available = await this.isAvailable();
    if (!available) {
      return {
        findings: [],
        templatesRun: 0,
        targetsTested: config.targets.length,
        durationMs: Date.now() - startTime,
        errors: ['Nuclei binary not found. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'],
      };
    }

    if (config.targets.length === 0) {
      return {
        findings: [],
        templatesRun: 0,
        targetsTested: 0,
        durationMs: Date.now() - startTime,
        errors: [],
      };
    }

    // Build command args — always explicit argv, never shell interpolation
    const args = this.buildArgs(config);

    try {
      this.abortController = new AbortController();
      const result = await executeCommand(this.binaryPath, args);

      const findings = this.parseOutput(result.stdout);

      // Filter by minimum severity if specified
      const filteredFindings = config.minSeverity
        ? findings.filter(f => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[config.minSeverity!])
        : findings;

      // Count templates from output (Nuclei prints summary to stderr)
      const templatesMatch = result.stderr.match(/Templates loaded.*?(\d+)/i);
      const templatesRun = templatesMatch ? parseInt(templatesMatch[1], 10) : 0;

      if (result.exitCode !== 0 && result.stderr) {
        const stderrErrors = result.stderr
          .split('\n')
          .filter(line => line.toLowerCase().includes('error') || line.toLowerCase().includes('failed'))
          .slice(0, 5);
        errors.push(...stderrErrors);
      }

      return {
        findings: filteredFindings,
        templatesRun,
        targetsTested: config.targets.length,
        durationMs: Date.now() - startTime,
        errors,
      };
    } catch (error) {
      return {
        findings: [],
        templatesRun: 0,
        targetsTested: config.targets.length,
        durationMs: Date.now() - startTime,
        errors: [error instanceof Error ? error.message : String(error)],
      };
    } finally {
      this.abortController = null;
    }
  }

  /** Run a targeted scan based on detected technologies */
  async scanForTech(targets: string[], technologies: string[]): Promise<NucleiResult> {
    const techTags = this.mapTechToTags(technologies);

    if (techTags.length === 0) {
      // No specific tech tags — run general scan with common categories
      return this.scan({
        targets,
        templateCategories: ['cves', 'misconfigurations', 'exposures'],
        minSeverity: 'low',
      });
    }

    return this.scan({
      targets,
      techTags,
      minSeverity: 'low',
    });
  }

  /** Update Nuclei templates (nuclei -ut) */
  async updateTemplates(): Promise<{ success: boolean; templateCount?: number }> {
    try {
      const available = await this.isAvailable();
      if (!available) {
        return { success: false };
      }

      const result = await executeCommand(this.binaryPath, ['-ut']);
      const countMatch = result.stdout.match(/(\d+)\s+templates/i)
        ?? result.stderr.match(/(\d+)\s+templates/i);

      return {
        success: result.exitCode === 0,
        templateCount: countMatch ? parseInt(countMatch[1], 10) : undefined,
      };
    } catch {
      return { success: false };
    }
  }

  /** Parse Nuclei JSONL output into structured findings */
  parseOutput(jsonlOutput: string): NucleiFinding[] {
    if (!jsonlOutput || jsonlOutput.trim().length === 0) {
      return [];
    }

    return jsonlOutput
      .split('\n')
      .filter(line => line.trim().length > 0)
      .map(line => {
        try {
          return JSON.parse(line) as Record<string, unknown>;
        } catch {
          return null;
        }
      })
      .filter((raw): raw is Record<string, unknown> => raw !== null)
      .map(raw => this.rawToFinding(raw));
  }

  /** Convert NucleiFinding to AgentFinding format for blackboard */
  toAgentFinding(finding: NucleiFinding): AgentFinding {
    return {
      id: `nuclei_${finding.templateId}_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      agentId: 'nuclei_scanner',
      type: finding.tags.includes('cve') ? 'known_cve' : 'misconfiguration',
      title: finding.templateName,
      severity: finding.severity,
      description: finding.description || `${finding.templateName} detected at ${finding.matchedUrl}`,
      target: finding.target,
      evidence: [
        ...(finding.curlCommand ? [finding.curlCommand] : []),
        `Template: ${finding.templateId}`,
        `Matched URL: ${finding.matchedUrl}`,
        ...(finding.extractedResults ?? []).map(r => `Extracted: ${r}`),
      ],
      reproduction: [
        `Run: nuclei -t ${finding.templateId} -u ${finding.target}`,
        ...(finding.curlCommand ? [`Or verify with: ${finding.curlCommand}`] : []),
      ],
      timestamp: new Date(finding.timestamp),
    };
  }

  /** Stop a running scan */
  stop(): void {
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
  }

  // ─── Private Helpers ─────────────────────────────────────────────────────────

  private buildArgs(config: NucleiConfig): string[] {
    const args: string[] = [];

    // Output format — always JSONL for parsing
    args.push('-jsonl');

    // Disable update check for faster startup
    args.push('-duc');

    // Targets
    if (config.targets.length === 1) {
      args.push('-target', config.targets[0]);
    } else {
      // Multiple targets: pass as comma-separated list
      args.push('-target', config.targets.join(','));
    }

    // Severity filter
    if (config.minSeverity && config.minSeverity !== 'info') {
      args.push('-severity', config.minSeverity);
    }

    // Template categories
    if (config.templateCategories && config.templateCategories.length > 0) {
      args.push('-t', config.templateCategories.join(','));
    }

    // Specific template IDs
    if (config.templateIds && config.templateIds.length > 0) {
      args.push('-id', config.templateIds.join(','));
    }

    // Technology tags
    if (config.techTags && config.techTags.length > 0) {
      args.push('-tags', config.techTags.join(','));
    }

    // Concurrency
    const concurrency = config.concurrency ?? 25;
    args.push('-concurrency', String(concurrency));

    // Rate limit
    const rateLimit = config.rateLimit ?? 150;
    args.push('-rate-limit', String(rateLimit));

    // Timeout
    const timeout = config.timeoutSeconds ?? 10;
    args.push('-timeout', String(timeout));

    // Silent mode — suppress non-finding output to stdout
    args.push('-silent');

    return args;
  }

  private rawToFinding(raw: Record<string, unknown>): NucleiFinding {
    const info = (raw.info ?? {}) as Record<string, unknown>;

    return {
      templateId: String(raw['template-id'] ?? raw.templateID ?? ''),
      templateName: String(info.name ?? raw['template-id'] ?? 'Unknown'),
      severity: this.normalizeSeverity(String(info.severity ?? 'info')),
      target: String(raw.host ?? raw.matched ?? ''),
      matchedUrl: String(raw['matched-at'] ?? raw.matched ?? ''),
      matcherName: raw['matcher-name'] != null ? String(raw['matcher-name']) : undefined,
      description: String(info.description ?? ''),
      reference: Array.isArray(info.reference) ? info.reference.map(String) : [],
      tags: Array.isArray(info.tags) ? info.tags.map(String) : [],
      extractedResults: Array.isArray(raw['extracted-results'])
        ? (raw['extracted-results'] as unknown[]).map(String)
        : [],
      curlCommand: raw['curl-command'] != null ? String(raw['curl-command']) : undefined,
      timestamp: Date.now(),
    };
  }

  private normalizeSeverity(sev: string): NucleiFinding['severity'] {
    const lower = sev.toLowerCase();
    if (lower === 'critical' || lower === 'high' || lower === 'medium' || lower === 'low') {
      return lower;
    }
    return 'info';
  }

  /** Map technology names to Nuclei template tags */
  private mapTechToTags(technologies: string[]): string[] {
    const tags = new Set<string>();

    for (const tech of technologies) {
      const lower = tech.toLowerCase();

      // Direct match
      if (TECH_TO_TAGS[lower]) {
        for (const tag of TECH_TO_TAGS[lower]) {
          tags.add(tag);
        }
        continue;
      }

      // Partial match — check if tech name contains a known key
      for (const [key, mappedTags] of Object.entries(TECH_TO_TAGS)) {
        if (lower.includes(key) || key.includes(lower)) {
          for (const tag of mappedTags) {
            tags.add(tag);
          }
        }
      }
    }

    return [...tags];
  }
}

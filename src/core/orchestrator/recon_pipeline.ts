/**
 * Recon Pipeline DAG
 *
 * Directed Acyclic Graph of reconnaissance tasks. Each node is a recon stage
 * with declared dependencies. Stages run in parallel when their dependencies
 * are satisfied, maximizing throughput.
 *
 * Pipeline stages:
 *
 *                     ┌──────────────┐
 *                     │  Target URL  │
 *                     └──────┬───────┘
 *                            │
 *               ┌────────────┼────────────┐
 *               ▼            ▼            ▼
 *         ┌──────────┐ ┌──────────┐ ┌──────────┐
 *         │ Subdomain│ │ Port Scan│ │ Wayback  │
 *         │ Enum     │ │ (naabu)  │ │ URLs     │
 *         └────┬─────┘ └────┬─────┘ └────┬─────┘
 *              │            │            │
 *              ▼            │            ▼
 *         ┌──────────┐      │      ┌──────────┐
 *         │ DNS      │      │      │ JS       │
 *         │ Resolve  │      │      │ Analysis │
 *         └────┬─────┘      │      └────┬─────┘
 *              │            │            │
 *              ▼            ▼            ▼
 *         ┌──────────────────────────────────┐
 *         │ HTTP Probe (httpx) — all hosts   │
 *         └──────────────┬───────────────────┘
 *                        │
 *           ┌────────────┼────────────┐
 *           ▼            ▼            ▼
 *     ┌──────────┐ ┌──────────┐ ┌──────────┐
 *     │ WAF      │ │ Tech     │ │ Content  │
 *     │ Detect   │ │ Finger-  │ │ Discovery│
 *     └────┬─────┘ └────┬─────┘ └────┬─────┘
 *          │            │            │
 *          ▼            ▼            ▼
 *     ┌──────────────────────────────────┐
 *     │ Parameter Mining                  │
 *     └──────────────┬───────────────────┘
 *                    │
 *                    ▼
 *     ┌──────────────────────────────────┐
 *     │ Nuclei Scan + Screenshot + SSL   │
 *     └──────────────────────────────────┘
 */

import { AssetMapBuilder } from './asset_map';
import type { AssetMap } from './asset_map';

// ─── Types ───────────────────────────────────────────────────────────────────

export type StageStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped';

export interface PipelineStage {
  id: string;
  name: string;
  description: string;
  /** IDs of stages that must complete before this one can start */
  dependencies: string[];
  /** The commands to execute for this stage */
  commands: StageCommand[];
  status: StageStatus;
  startedAt?: number;
  completedAt?: number;
  error?: string;
}

export interface StageCommand {
  tool: string;
  command: string;
  /** Placeholder tokens that get replaced with runtime values */
  placeholders: Record<string, string>;
}

export interface PipelineConfig {
  target: string;
  scope: string[];
  /** Execute a command and return stdout */
  executeCommand: (command: string, target: string) => Promise<{
    success: boolean;
    stdout: string;
    stderr: string;
  }>;
  /** Callback for stage status changes */
  onStageUpdate?: (stage: PipelineStage) => void;
  /** Whether to skip port scanning */
  skipPortScan?: boolean;
  /** Whether to skip content discovery (slow) */
  skipContentDiscovery?: boolean;
}

export interface PipelineResult {
  assetMap: AssetMap;
  stages: PipelineStage[];
  duration: number;
  errors: string[];
}

// ─── Pipeline Definition ─────────────────────────────────────────────────────

function buildStages(target: string, config: PipelineConfig): PipelineStage[] {
  // All tools listed here are installed in docker/Dockerfile.attack-machine.
  // If a tool is added/removed from the image, keep this function in sync.
  // Verified present: subfinder, assetfinder, dnsx, naabu, gau, waybackurls,
  // httpx, katana, wafw00f, whatweb, paramspider, nuclei, testssl.sh.
  // (getJS and gowitness remain uninstalled — katana -jc and the agent's
  // Playwright browser cover those use cases.)
  const stages: PipelineStage[] = [
    {
      id: 'subdomain_enum',
      name: 'Subdomain Enumeration',
      description: 'Discover subdomains via subfinder + assetfinder',
      dependencies: [],
      commands: [
        { tool: 'subfinder', command: `subfinder -d ${target} -json -silent`, placeholders: {} },
        { tool: 'assetfinder', command: `assetfinder --subs-only ${target}`, placeholders: {} },
      ],
      status: 'pending',
    },
    {
      id: 'port_scan',
      name: 'Port Scanning',
      description: 'Scan top ports with naabu',
      dependencies: [],
      commands: [
        { tool: 'naabu', command: `naabu -host ${target} -top-ports 1000 -json -rate 500 -silent`, placeholders: {} },
      ],
      status: config.skipPortScan ? 'skipped' : 'pending',
    },
    {
      id: 'wayback_urls',
      name: 'Historical URL Collection',
      description: 'Collect URLs from Wayback Machine and GAU',
      dependencies: [],
      commands: [
        { tool: 'gau', command: `gau --subs ${target}`, placeholders: {} },
        { tool: 'waybackurls', command: `waybackurls ${target}`, placeholders: {} },
      ],
      status: 'pending',
    },
    {
      id: 'dns_resolve',
      name: 'DNS Resolution',
      description: 'Resolve discovered subdomains',
      dependencies: ['subdomain_enum'],
      commands: [
        { tool: 'dnsx', command: 'dnsx -resp -json -silent', placeholders: { stdin: 'subdomain_enum.output' } },
      ],
      status: 'pending',
    },
    {
      id: 'http_probe',
      name: 'HTTP Probing',
      description: 'Probe all hosts for HTTP services with tech detection',
      dependencies: ['dns_resolve', 'port_scan'],
      commands: [
        { tool: 'httpx', command: 'httpx -json -td -sc -title -server -follow-redirects -silent', placeholders: { stdin: 'dns_resolve.output' } },
      ],
      status: 'pending',
    },
    {
      id: 'waf_detect',
      name: 'WAF Detection',
      description: 'Detect Web Application Firewalls',
      dependencies: ['http_probe'],
      commands: [
        { tool: 'wafw00f', command: `wafw00f https://${target}`, placeholders: {} },
      ],
      status: 'pending',
    },
    {
      id: 'tech_fingerprint',
      name: 'Technology Fingerprinting',
      description: 'Detailed technology fingerprinting',
      dependencies: ['http_probe'],
      commands: [
        { tool: 'whatweb', command: `whatweb -a 1 --log-json=- https://${target}`, placeholders: {} },
      ],
      status: 'pending',
    },
    {
      id: 'content_discovery',
      name: 'Content Discovery',
      description: 'Discover hidden directories and files',
      dependencies: ['http_probe'],
      commands: [
        { tool: 'katana', command: `katana -u https://${target} -jc -json -d 3 -rl 5 -silent`, placeholders: {} },
      ],
      status: config.skipContentDiscovery ? 'skipped' : 'pending',
    },
    {
      id: 'param_mining',
      name: 'Parameter Mining',
      description: 'Discover parameters on target endpoints',
      dependencies: ['waf_detect', 'tech_fingerprint', 'content_discovery'],
      commands: [
        { tool: 'paramspider', command: `paramspider -d ${target}`, placeholders: {} },
      ],
      status: 'pending',
    },
    {
      id: 'final_scan',
      name: 'Nuclei Scan + SSL',
      description: 'Run Nuclei templates and collect SSL info',
      dependencies: ['param_mining'],
      commands: [
        { tool: 'nuclei', command: `nuclei -u https://${target} -json -silent -rl 5`, placeholders: {} },
        { tool: 'testssl.sh', command: `testssl.sh --jsonfile-pretty=- https://${target}:443`, placeholders: {} },
      ],
      status: 'pending',
    },
  ];

  return stages;
}

// ─── Pipeline Executor ───────────────────────────────────────────────────────

export class ReconPipeline {
  private stages: PipelineStage[];
  private config: PipelineConfig;
  private assetMap: AssetMapBuilder;
  private stageOutputs: Map<string, string> = new Map();

  constructor(config: PipelineConfig) {
    this.config = config;
    this.stages = buildStages(config.target, config);
    this.assetMap = new AssetMapBuilder(config.target);
  }

  /** Execute the full recon pipeline */
  async execute(): Promise<PipelineResult> {
    const startTime = Date.now();
    const errors: string[] = [];

    while (this.hasPendingStages()) {
      // Find all stages whose dependencies are satisfied
      const runnable = this.stages.filter(
        s => s.status === 'pending' && this.areDependenciesMet(s)
      );

      if (runnable.length === 0) {
        // Deadlock — mark remaining as failed
        for (const s of this.stages) {
          if (s.status === 'pending') {
            s.status = 'failed';
            s.error = 'Deadlock: dependencies never completed';
            errors.push(`${s.name}: deadlock`);
          }
        }
        break;
      }

      // Run all runnable stages in parallel
      await Promise.allSettled(
        runnable.map(stage => this.executeStage(stage, errors))
      );
    }

    return {
      assetMap: this.assetMap.build(),
      stages: this.stages,
      duration: Date.now() - startTime,
      errors,
    };
  }

  /** Get current pipeline status */
  getStatus(): { total: number; completed: number; running: number; failed: number } {
    return {
      total: this.stages.length,
      completed: this.stages.filter(s => s.status === 'completed').length,
      running: this.stages.filter(s => s.status === 'running').length,
      failed: this.stages.filter(s => s.status === 'failed').length,
    };
  }

  private async executeStage(stage: PipelineStage, errors: string[]): Promise<void> {
    stage.status = 'running';
    stage.startedAt = Date.now();
    this.config.onStageUpdate?.(stage);

    let combinedOutput = '';

    try {
      for (const cmd of stage.commands) {
        const result = await this.config.executeCommand(cmd.command, this.config.target);
        if (result.stdout) {
          combinedOutput += result.stdout + '\n';
        }
        if (!result.success && result.stderr) {
          errors.push(`${stage.name}/${cmd.tool}: ${result.stderr.substring(0, 200)}`);
        }
      }

      this.stageOutputs.set(stage.id, combinedOutput);
      this.parseStageOutput(stage.id, combinedOutput);

      stage.status = 'completed';
      stage.completedAt = Date.now();
    } catch (error) {
      stage.status = 'failed';
      stage.completedAt = Date.now();
      stage.error = error instanceof Error ? error.message : String(error);
      errors.push(`${stage.name}: ${stage.error}`);
    }

    this.config.onStageUpdate?.(stage);
  }

  private parseStageOutput(stageId: string, output: string): void {
    const lines = output.split('\n').filter(Boolean);

    switch (stageId) {
      case 'subdomain_enum':
        for (const line of lines) {
          try {
            const parsed = JSON.parse(line);
            this.assetMap.addSubdomain({
              name: parsed.host || line.trim(),
              ips: parsed.a ? [parsed.a].flat() : [],
              cnames: parsed.cname ? [parsed.cname].flat() : [],
              status: 'unresolved',
              technologies: [],
            });
          } catch {
            // Line-delimited plain text (from assetfinder)
            const sub = line.trim();
            if (sub && sub.includes('.')) {
              this.assetMap.addSubdomain({
                name: sub,
                ips: [],
                cnames: [],
                status: 'unresolved',
                technologies: [],
              });
            }
          }
        }
        break;

      case 'http_probe':
        for (const line of lines) {
          try {
            const parsed = JSON.parse(line);
            this.assetMap.addSubdomain({
              name: new URL(parsed.url || parsed.input).hostname,
              ips: parsed.a ? [parsed.a].flat() : [],
              cnames: [],
              status: 'resolved',
              httpStatus: parsed.status_code,
              title: parsed.title,
              technologies: parsed.tech ? [parsed.tech].flat() : [],
            });
          } catch {
            // skip unparseable
          }
        }
        break;

      case 'port_scan':
        for (const line of lines) {
          try {
            const parsed = JSON.parse(line);
            this.assetMap.addPort({
              host: parsed.host || parsed.ip,
              port: parsed.port,
              service: parsed.service || 'unknown',
              state: 'open',
            });
          } catch {
            // skip
          }
        }
        break;

      case 'wayback_urls':
      case 'content_discovery':
        for (const line of lines) {
          try {
            const url = line.trim();
            if (!url.startsWith('http')) continue;
            const parsed = new URL(url);
            const params: Array<{ name: string; type: 'query' }> = [];
            for (const key of parsed.searchParams.keys()) {
              params.push({ name: key, type: 'query' });
            }
            this.assetMap.addEndpoint({
              url,
              method: 'GET',
              params,
              source: stageId === 'wayback_urls' ? 'wayback' : 'crawl',
            });
          } catch {
            // skip
          }
        }
        break;

      case 'waf_detect':
        // Look for WAF name in wafw00f output
        const wafMatch = output.match(/is behind (.+?)(?:\s|$)/i);
        if (wafMatch) {
          this.assetMap.setWAF({
            name: wafMatch[1].trim(),
            confidence: 80,
          });
        }
        break;

      case 'tech_fingerprint':
        for (const line of lines) {
          try {
            const parsed = JSON.parse(line);
            if (parsed.plugins) {
              for (const [name, info] of Object.entries(parsed.plugins)) {
                const techInfo = info as { version?: string[] };
                this.assetMap.addTechnology({
                  name,
                  version: techInfo.version?.[0],
                  category: 'other',
                  confidence: 80,
                });
              }
            }
          } catch {
            // skip
          }
        }
        break;

      case 'js_analysis':
        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith('http')) {
            this.assetMap.addJSFile({
              url: trimmed,
              endpoints: [],
              secrets: [],
            });
          }
        }
        break;
    }
  }

  private hasPendingStages(): boolean {
    return this.stages.some(s => s.status === 'pending');
  }

  private areDependenciesMet(stage: PipelineStage): boolean {
    return stage.dependencies.every(depId => {
      const dep = this.stages.find(s => s.id === depId);
      return dep && (dep.status === 'completed' || dep.status === 'skipped' || dep.status === 'failed');
    });
  }
}

export default ReconPipeline;

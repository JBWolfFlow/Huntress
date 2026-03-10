/**
 * Recon Agent — Full Implementation
 *
 * Performs comprehensive reconnaissance using the ReAct loop engine.
 * Attack playbook:
 * 1. Subdomain enumeration (subfinder, assetfinder, findomain)
 * 2. DNS resolution (dnsx)
 * 3. HTTP probing (httpx with tech detection)
 * 4. WAF detection (wafw00f)
 * 5. Port scanning (naabu)
 * 6. Web crawling (katana)
 * 7. URL collection (gau, waybackurls)
 * 8. JS analysis (getJS, jsluice)
 * 9. Parameter mining (paramspider)
 * 10. Tech fingerprint (whatweb)
 * 11. Screenshot evidence (gowitness)
 * 12. SSL/TLS analysis (testssl.sh)
 */

import type { ModelProvider } from '../core/providers/types';
import type {
  BaseAgent,
  AgentTask,
  AgentResult,
  AgentFinding,
  AgentStatus,
  AgentMetadata,
} from './base_agent';
import { generateFindingId } from './base_agent';
import { registerAgent } from './agent_catalog';
import { ReactLoop } from '../core/engine/react_loop';
import type { ReactLoopConfig, CommandResult, ReactFinding } from '../core/engine/react_loop';
import { RECON_TOOL_SCHEMAS } from '../core/engine/tool_schemas';

const RECON_SYSTEM_PROMPT = `You are an expert reconnaissance agent for bug bounty hunting. Your mission is to comprehensively map the target's attack surface before specialized hunters begin testing.

## Your Methodology (execute in order)

### Phase 1: Subdomain Enumeration
- Run subfinder with JSON output: \`subfinder -d TARGET -json -silent\`
- Run assetfinder for additional coverage: \`assetfinder --subs-only TARGET\`
- Combine and deduplicate results

### Phase 2: DNS Resolution
- Resolve discovered subdomains: \`dnsx -l subdomains.txt -resp -json\`
- Note any CNAME records (potential subdomain takeover)
- Identify cloud-hosted assets (AWS, Azure, GCP patterns)

### Phase 3: HTTP Probing
- Probe all resolved hosts: \`httpx -l resolved.txt -json -td -sc -title -server -follow-redirects\`
- Record status codes, technologies, server headers
- Flag interesting status codes: 401, 403 (potential bypasses), 500 (error-based info leak)

### Phase 4: WAF Detection
- Test primary targets: \`wafw00f TARGET\`
- Record WAF type — this changes the entire strategy for active testing

### Phase 5: Port Scanning
- Scan top ports: \`naabu -host TARGET -top-ports 1000 -json -rate 500\`
- Focus on non-standard ports (8080, 8443, 9090, etc.)

### Phase 6: Web Crawling & URL Collection
- Crawl discovered sites: \`katana -u TARGET -jc -json -d 3 -rl 5\`
- Collect historical URLs: \`gau --subs TARGET\` and \`waybackurls TARGET\`
- Look for API endpoints, admin panels, upload functionality

### Phase 7: JavaScript Analysis
- Extract JS files and analyze for endpoints, secrets, and API keys
- Look for internal API paths, hardcoded credentials, debug endpoints

### Phase 8: Parameter Mining
- Discover parameters: \`paramspider -d TARGET\`
- Focus on parameters that accept URLs, IDs, or user input

### Phase 9: Technology Fingerprinting
- Detailed fingerprint: \`whatweb -a 1 --log-json TARGET\`
- Identify frameworks, CMS versions, server software

### Phase 10: Evidence Collection
- Screenshot interesting pages: \`gowitness scan single -u TARGET --json\`
- SSL/TLS analysis: \`testssl.sh --json TARGET:443\`

## Key Principles
- Always use JSON output flags when available for structured data
- Respect rate limits — this is a production system
- Request specialist agents when you find specific attack surfaces:
  - GraphQL endpoint → request graphql_hunter
  - OAuth/login flow → request oauth_hunter
  - Parameters reflecting input → request xss_hunter
  - API with IDs → request idor_hunter
- Report findings with subdomain, host, url, or technology types
- Stop when you've exhausted recon tools or reached iteration limit`;

export class ReconAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'recon',
    name: 'Recon Agent',
    description: 'Comprehensive reconnaissance: subdomain enumeration, URL discovery, tech fingerprinting, endpoint mapping.',
    vulnerabilityClasses: ['recon', 'information-disclosure', 'subdomain-takeover'],
    assetTypes: ['domain', 'web-application', 'api'],
  };

  private provider?: ModelProvider;
  private model?: string;
  private findings: AgentFinding[] = [];
  private status: AgentStatus;
  private onApprovalRequest?: (req: { command: string; target: string; reasoning: string; category: string; toolName: string; safetyWarnings: string[] }) => Promise<boolean>;
  private onExecuteCommand?: (command: string, target: string) => Promise<CommandResult>;

  constructor() {
    this.status = {
      agentId: this.metadata.id,
      agentName: this.metadata.name,
      status: 'idle',
      toolsExecuted: 0,
      findingsCount: 0,
      lastUpdate: Date.now(),
    };
  }

  /** Set callbacks for approval and command execution */
  setCallbacks(callbacks: {
    onApprovalRequest?: (req: { command: string; target: string; reasoning: string; category: string; toolName: string; safetyWarnings: string[] }) => Promise<boolean>;
    onExecuteCommand?: (command: string, target: string) => Promise<CommandResult>;
  }): void {
    this.onApprovalRequest = callbacks.onApprovalRequest;
    this.onExecuteCommand = callbacks.onExecuteCommand;
  }

  async initialize(provider: ModelProvider, model: string): Promise<void> {
    this.provider = provider;
    this.model = model;
    this.findings = [];
    this.updateStatus('initializing');
  }

  async execute(task: AgentTask): Promise<AgentResult> {
    const startTime = Date.now();
    this.findings = [];
    this.updateStatus('running', task.description);

    if (!this.provider || !this.model) {
      throw new Error('Agent not initialized — call initialize() first');
    }

    try {
      const loop = new ReactLoop({
        provider: this.provider,
        model: this.model,
        systemPrompt: RECON_SYSTEM_PROMPT,
        goal: `Perform comprehensive reconnaissance on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
        tools: RECON_TOOL_SCHEMAS,
        maxIterations: 60,
        target: task.target,
        scope: task.scope,
        autoApproveSafe: false,
        onApprovalRequest: this.onApprovalRequest,
        onExecuteCommand: this.onExecuteCommand,
        onFinding: (finding) => {
          this.findings.push(this.convertFinding(finding));
          this.status.findingsCount = this.findings.length;
        },
        onStatusUpdate: (update) => {
          this.status.toolsExecuted = update.toolCallCount;
          this.status.lastUpdate = Date.now();
        },
        onSpecialistRequest: (request) => {
          // Log the specialist request as a finding
          this.findings.push({
            id: generateFindingId(),
            agentId: this.metadata.id,
            type: 'specialist_request',
            title: `Specialist requested: ${request.agentType}`,
            severity: 'info',
            description: request.context,
            target: request.target,
            evidence: [`Agent type: ${request.agentType}`, `Priority: ${request.priority}`],
            reproduction: [],
            timestamp: new Date(),
          });
        },
      });

      const result = await loop.execute();

      // Convert any remaining findings from the loop
      for (const finding of result.findings) {
        if (!this.findings.some(f => f.id === finding.id)) {
          this.findings.push(this.convertFinding(finding));
        }
      }

      this.updateStatus(result.success ? 'completed' : 'failed');

      return {
        taskId: task.id,
        agentId: this.metadata.id,
        success: result.success,
        findings: this.findings,
        toolsExecuted: result.toolCallCount,
        duration: Date.now() - startTime,
        error: result.stopReason === 'error' ? result.summary : undefined,
      };
    } catch (error) {
      this.updateStatus('failed');
      return {
        taskId: task.id,
        agentId: this.metadata.id,
        success: false,
        findings: this.findings,
        toolsExecuted: this.status.toolsExecuted,
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  validate(target: string): boolean {
    try {
      new URL(target.startsWith('http') ? target : `https://${target}`);
      return true;
    } catch {
      return false;
    }
  }

  reportFindings(): AgentFinding[] {
    return this.findings;
  }

  async cleanup(): Promise<void> {
    this.findings = [];
    this.updateStatus('idle');
  }

  getStatus(): AgentStatus {
    return { ...this.status };
  }

  private convertFinding(finding: ReactFinding): AgentFinding {
    return {
      id: finding.id || generateFindingId(),
      agentId: this.metadata.id,
      type: finding.vulnerabilityType,
      title: finding.title,
      severity: finding.severity,
      description: finding.description,
      target: finding.target,
      evidence: finding.evidence,
      reproduction: finding.reproductionSteps,
      timestamp: new Date(),
    };
  }

  private updateStatus(status: AgentStatus['status'], currentTask?: string): void {
    this.status.status = status;
    this.status.lastUpdate = Date.now();
    if (currentTask !== undefined) {
      this.status.currentTask = currentTask;
    }
  }
}

// Register in catalog
registerAgent({
  metadata: new ReconAgent().metadata,
  factory: () => new ReconAgent(),
});

export default ReconAgent;

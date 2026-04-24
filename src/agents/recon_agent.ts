/**
 * Recon Agent — Full Implementation
 *
 * Performs comprehensive reconnaissance using the ReAct loop engine.
 * Attack playbook:
 * 1. Subdomain enumeration (subfinder)
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
import type { HttpClient } from '../core/http/request_engine';
import type { SessionManager } from '../core/auth/session_manager';

const RECON_SYSTEM_PROMPT = `You are an expert reconnaissance agent for bug bounty hunting. Your mission is to comprehensively map the target's attack surface before specialized hunters begin testing.

## Your Methodology (execute in order)

## Sandbox environment constraints

- Commands run through argv — NOT through a shell. Do NOT use shell pipes (\`|\`), redirects (\`>\`), process substitution (\`<(...)\`), or chained commands (\`&&\`). Use tool flags for filtering (e.g. \`httpx -path\` instead of \`httpx | grep\`). If you need to capture response headers, use \`curl -s -D /tmp/headers.txt -o /tmp/body.txt\` then read the file.
- Installed in the sandbox image: subfinder, assetfinder, dnsx, naabu, gau, waybackurls, httpx, katana, wafw00f, whatweb, paramspider, nuclei, testssl.sh, dalfox, interactsh-client, ffuf, sqlmap, ghauri, commix, curl, wget, jq, nmap, python3, git.
- NOT installed — do NOT attempt: findomain, getJS, gowitness.

### Phase 1: Subdomain Enumeration
- Run subfinder with JSON output: \`subfinder -d TARGET -json -silent\`
- Complement with assetfinder: \`assetfinder --subs-only TARGET\`
- Deduplicate results. Note any potential-takeover CNAMEs.

### Phase 2: DNS Resolution
- Resolve discovered subdomains: \`dnsx -l subdomains.txt -resp -json\`
- Note any CNAME records (potential subdomain takeover)
- Identify cloud-hosted assets (AWS, Azure, GCP patterns) from IPs/CNAMEs

### Phase 3: HTTP Probing
- Probe all resolved hosts: \`httpx -l resolved.txt -json -td -sc -title -server -follow-redirects -silent\`
- Record status codes, technologies, server headers
- Flag interesting status codes: 401, 403 (potential bypasses), 500 (error-based info leak)

### Phase 4: WAF Detection
- Test primary targets: \`wafw00f TARGET\`
- Record WAF type — this changes the entire strategy for active testing

### Phase 5: Port Scanning
- Scan top ports: \`naabu -host TARGET -top-ports 1000 -json -rate 500 -silent\`
- Focus on non-standard ports (8080, 8443, 9090, etc.)

### Phase 6: Web Crawling & URL Collection
- Crawl discovered sites: \`katana -u https://TARGET -jc -json -d 3 -rl 5 -silent\`
- Collect historical URLs: \`gau --subs TARGET\` and \`waybackurls TARGET\`
- Look for API endpoints, admin panels, upload functionality

### Phase 7: Parameter Mining
- Discover parameters: \`paramspider -d TARGET\`
- Focus on parameters that accept URLs, IDs, or user input (often reflected)

### Phase 8: Technology Fingerprinting
- Detailed fingerprint: \`whatweb -a 1 --log-json=- https://TARGET\`
- Identify frameworks, CMS versions, server software

### Phase 9: Vulnerability Scanning & SSL
- Nuclei CVE templates: \`nuclei -u https://TARGET -json -silent -rl 5\`
- SSL/TLS analysis: \`testssl.sh --jsonfile-pretty=- https://TARGET:443\`

## Key Principles
- Always use JSON output flags when available for structured data
- Respect rate limits — this is a production system
- Request specialist agents when you find specific attack surfaces:
  - GraphQL endpoint → request graphql_hunter
  - OAuth/login flow → request oauth_hunter
  - Parameters reflecting input → request xss_hunter
  - API with IDs → request idor_hunter
- Report findings with subdomain, host, url, or technology types

## CRITICAL: When to stop (Issue #6 fix)
You are a **mapping** agent, not a hunting agent. Your job is to find the
attack surface and hand off to specialists. **Call \`stop_hunting\` with
reason="task_complete"** the moment you have ANY of:
- Completed subdomain enumeration AND HTTP probed the live hosts
- Identified the target's tech stack
- Discovered 1+ interesting attack surfaces (GraphQL, OAuth, admin panels, APIs)
- Hit iteration 20+ without discovering new attack surface

DO NOT cycle through all 10 phases if the first 3-5 have already mapped the
surface. DO NOT re-run subfinder/httpx on domains you've already scanned.
Specialists need iterations to actually find bugs — don't hoard them.

## Example: Successful Recon Leading to Critical Findings

### Target: [redacted].com

**Step 1 — Subdomain enumeration:**
Tool call: execute_command { command: "subfinder -d [redacted].com -json -silent", target: "[redacted].com", category: "recon" }
Result: Found 47 subdomains including staging.*, api.*, admin.*, dev.*

**Step 2 — HTTP probing:**
Tool call: execute_command { command: "httpx -l subs.txt -json -td -sc -title -server -follow-redirects", target: "[redacted].com", category: "recon" }
Result: 32 live hosts. Key findings:
- staging.[redacted].com → 200, Express.js, no auth
- api.[redacted].com → 200, nginx, GraphQL playground exposed
- admin.[redacted].com → 403, CloudFlare WAF
- dev.[redacted].com → 200, Django debug mode ON

**Step 3 — WAF detection:**
Tool call: execute_command { command: "wafw00f api.[redacted].com", target: "api.[redacted].com", category: "recon" }
Result: No WAF detected on api subdomain (only admin has CloudFlare)

**Step 4 — Tech fingerprint:**
Tool call: execute_command { command: "whatweb -a 1 --log-json=- https://api.[redacted].com", target: "api.[redacted].com", category: "recon" }
Result: Node.js, Express, GraphQL, Apollo Server

**Step 5 — Dispatch specialists:**
Tool call: request_specialist { agent_type: "graphql_hunter", target: "api.[redacted].com/graphql", context: "Apollo GraphQL with playground exposed, no WAF", priority: "high" }
Tool call: request_specialist { agent_type: "idor_hunter", target: "staging.[redacted].com", context: "Staging env with no auth — likely has test data and relaxed access controls", priority: "high" }`;

/**
 * Check if a URL's host falls within any of the provided recon scope entries.
 * Matching is subdomain-friendly: a bare entry `example.com` accepts
 * `example.com`, `api.example.com`, `staging.api.example.com`, etc. This
 * matches the recon intent — recon discovers subdomains of the target and
 * hands them off to specialists, so limiting to exact hostname match would
 * kill subdomain enumeration. Wildcard entries (`*.example.com`) are
 * equivalent to their bare form under this semantics.
 *
 * Exported for unit testing. Used to drop out-of-scope URLs harvested from
 * HTML (e.g. W3C DTD references like `www.w3.org/TR/...`) before they drive
 * specialist dispatch.
 */
export function isUrlInReconScope(url: string, scope: readonly string[]): boolean {
  let urlHost: string;
  try {
    urlHost = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  if (!urlHost) return false;

  for (const raw of scope) {
    const entry = raw.trim();
    if (!entry) continue;

    const isWildcard = entry.startsWith('*.');
    let scopeHost: string;
    if (isWildcard) {
      scopeHost = entry.slice(2).toLowerCase();
    } else {
      try {
        scopeHost = new URL(
          entry.startsWith('http') ? entry : `https://${entry}`
        ).hostname.toLowerCase();
      } catch {
        scopeHost = entry.split(':')[0].toLowerCase();
      }
    }
    if (!scopeHost) continue;

    if (urlHost === scopeHost || urlHost.endsWith(`.${scopeHost}`)) return true;
  }
  return false;
}

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
  private autoApproveSafe = false;
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
    autoApproveSafe?: boolean;
  }): void {
    this.onApprovalRequest = callbacks.onApprovalRequest;
    this.onExecuteCommand = callbacks.onExecuteCommand;
    if (callbacks.autoApproveSafe !== undefined) {
      this.autoApproveSafe = callbacks.autoApproveSafe;
    }
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
        // Issue #6 fix: drop explicit maxIterations override so the ReactLoop
        // uses the centralized simple-agent budget (30 from cost_router). The
        // previous hardcoded 60 meant a single recon agent could run 15-30min,
        // starving specialist dispatch because generateSolverTasks only fires
        // on recon completion. Hunt #11 monitoring caught this: 5 recon
        // agents grinding for 16 min with 0 specialist dispatches. Pair with
        // the "stop_hunting early" instructions above.
        agentType: 'recon',
        target: task.target,
        scope: task.scope,
        autoApproveSafe: this.autoApproveSafe,
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
        httpClient: task.parameters.httpClient as HttpClient | undefined,
        availableTools: task.parameters.availableTools as string[] | undefined,
        sessionManager: task.parameters.sessionManager as SessionManager | undefined,
        authSessionId: (task.parameters.authSessionIds as string[] | undefined)?.[0],
        sharedFindings: task.sharedFindings,
        wafContext: task.wafContext,
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

      // Build observations for cross-agent sharing via the blackboard
      const observations = this.findings
        .filter(f => f.severity === 'info' || f.type === 'specialist_request')
        .map(f => {
          const relevantTo: string[] = [];
          // Route recon findings to relevant specialist agents
          if (f.type === 'specialist_request') {
            const match = f.title.match(/Specialist requested: (\w+)/);
            if (match) relevantTo.push(match[1]);
          } else {
            const desc = f.description.toLowerCase();
            if (desc.includes('graphql')) relevantTo.push('graphql');
            if (desc.includes('oauth') || desc.includes('login') || desc.includes('auth')) relevantTo.push('oauth');
            if (desc.includes('redirect')) relevantTo.push('open_redirect', 'ssrf');
            if (desc.includes('api') || desc.includes('endpoint')) relevantTo.push('idor', 'sqli', 'xss');
            if (desc.includes('upload')) relevantTo.push('path_traversal', 'xss');
            if (desc.includes('cname') || desc.includes('dangling')) relevantTo.push('subdomain_takeover');
          }
          return {
            category: f.type,
            detail: `${f.target}: ${f.description}`,
            relevantTo: relevantTo.length > 0 ? relevantTo : undefined,
          };
        });

      // Session 25 Issue #10 — emit category:'endpoint' observations so
      // orchestrator_engine.generateSolverTasks (at ~:2668) can extract them
      // and fan out per-endpoint specialist tasks (xss/sqli/ssrf/ssti), not
      // just broad domain tasks. Source URLs from HTTP exchanges the loop
      // made + any URLs surfaced in tool-call stdout (subfinder/httpx/katana).
      //
      // Scope filter (2026-04-23): the 2026-04-23 Juice Shop hunt harvested
      // `http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd` — an HTML DTD
      // reference — as an endpoint and dispatched SSTI/XSS specialists
      // against it. Drop anything whose host isn't in the hunt's scope
      // before it drives dispatch.
      const urlRegex = /https?:\/\/[^\s"'<>)]+/g;
      const discoveredUrls = new Set<string>();
      for (const ex of result.httpExchanges) {
        if (ex.request?.url) discoveredUrls.add(ex.request.url);
      }
      for (const entry of result.iterationLog) {
        if (!entry.toolResult) continue;
        const matches = entry.toolResult.match(urlRegex);
        if (matches) for (const u of matches) discoveredUrls.add(u);
      }
      for (const f of this.findings) {
        const scanText = `${f.description} ${f.evidence.join(' ')}`;
        const matches = scanText.match(urlRegex);
        if (matches) for (const u of matches) discoveredUrls.add(u);
      }
      const inScopeUrls = [...discoveredUrls].filter(u => isUrlInReconScope(u, task.scope));
      // Cap at 50 to avoid blackboard blowup on large recons.
      const endpointObservations = inScopeUrls.slice(0, 50).map(url => ({
        category: 'endpoint' as const,
        detail: url,
        relevantTo: undefined,
      }));
      observations.push(...endpointObservations);

      return {
        taskId: task.id,
        agentId: this.metadata.id,
        success: result.success,
        findings: this.findings,
        httpExchanges: result.httpExchanges,
        observations,
        toolsExecuted: result.toolCallCount,
        duration: Date.now() - startTime,
        error: result.success ? undefined : (result.summary || `Agent stopped: ${result.stopReason}`),
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
    return [...this.findings];
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

/**
 * HTTP Request Smuggling Hunter Agent
 *
 * Specializes in detecting HTTP request smuggling vulnerabilities across all 9
 * variants (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, CL.0, TE.0, 0.CL, browser-powered
 * desync). This is a $200K+ bounty class — Kettle's research at PortSwigger
 * demonstrated repeated six-figure payouts for smuggling bugs.
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
import type {
  CommandResult,
  ReactFinding,
} from '../core/engine/react_loop';
import { AGENT_TOOL_SCHEMAS } from '../core/engine/tool_schemas';
import type { HttpClient } from '../core/http/request_engine';

const HTTP_SMUGGLING_SYSTEM_PROMPT = `You are an elite HTTP request smuggling researcher. Your mission is to detect request smuggling vulnerabilities — one of the highest-impact, highest-bounty vulnerability classes in web security ($200K+ payouts documented).

## Core Concept

HTTP request smuggling exploits disagreements between front-end (proxy/CDN/WAF) and back-end servers about where one HTTP request ends and the next begins. This happens when:
- The front-end and back-end disagree on whether to use Content-Length or Transfer-Encoding
- The servers parse malformed headers differently
- HTTP/2 downgrading introduces header ambiguity

## Attack Playbook

### Step 1: Fingerprint the Infrastructure

Before testing, identify what's in the request path:
- CDN fingerprinting: Check \`Server\`, \`Via\`, \`X-Cache\`, \`CF-RAY\`, \`X-Served-By\`, \`X-Cache-Hits\` headers
- Common CDNs: Cloudflare, Akamai, CloudFront, Fastly, Azure Front Door, Varnish
- Use \`http_request\` with HEAD and OPTIONS to observe infrastructure-specific headers
- Different CDN/proxy combos have known smuggling vectors

### Step 2: CL.TE Detection (Content-Length wins front-end, Transfer-Encoding wins back-end)

Send a request where CL and TE disagree:
\`\`\`
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
\`\`\`

If the follow-up normal GET request returns "Unrecognized method GPOST" (or similar), smuggling is confirmed:
- Front-end uses CL (reads 6 bytes: "0\\r\\n\\r\\nG"), forwards it all as one request
- Back-end uses TE (reads chunked "0" = end, then "G" becomes the start of the NEXT request)

### Step 3: TE.CL Detection (Transfer-Encoding wins front-end, Content-Length wins back-end)

\`\`\`
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

\`\`\`

If the back-end processes "SMUGGLED" as the start of the next request, confirmed.

### Step 4: TE.TE Detection (Both use TE, but one can be confused by obfuscation)

Try Transfer-Encoding obfuscation payloads:
- \`Transfer-Encoding: xchunked\`
- \`Transfer-Encoding : chunked\` (space before colon)
- \`Transfer-Encoding:\\tchunked\` (tab)
- \`Transfer-Encoding: chunked\\r\\nTransfer-encoding: x\` (duplicate, different case)
- \` Transfer-Encoding: chunked\` (leading space)
- \`Transfer-Encoding\\n: chunked\` (newline in header name)
- \`X: X[\\n]Transfer-Encoding: chunked\` (header injection)
- \`Transfer-Encoding: chunked, identity\`

For each obfuscation, test if one server processes chunked while the other doesn't.

### Step 5: H2.CL and H2.TE Detection (HTTP/2 Downgrade Smuggling)

When the front-end speaks HTTP/2 but downgrades to HTTP/1.1 for the back-end:
- Send HTTP/2 request with both \`:content-length\` pseudo-header and chunked body
- Send HTTP/2 request with \`transfer-encoding: chunked\` header (forbidden in H2, but some proxies pass it through)
- Inject \\r\\n in H2 header values (H2 binary framing allows it, H1 interpretation creates new headers)

### Step 6: CL.0 Detection (Content-Length: 0 trick)

Some servers treat CL:0 POST as having no body, but forward the actual body to the back-end:
- Send POST with Content-Length: 0 but include a body
- The front-end reads CL:0 (no body), the back-end reads the actual body as the next request

### Step 7: Time-Based Detection

When you can't see smuggled request responses directly:
1. Smuggle a request that causes a deliberate delay (e.g., to a slow endpoint or with a sleep parameter)
2. If the second request in the pipeline takes significantly longer, smuggling is occurring
3. Compare baseline timing vs smuggling-attempt timing

### Step 8: Impact Demonstration

Once smuggling is confirmed, demonstrate impact:
- **Cache poisoning:** Smuggle a request that poisons the cache with attacker-controlled content
- **Request hijacking:** Smuggle a request that captures the next user's request (credentials, cookies)
- **WAF bypass:** Show that smuggled requests bypass WAF rules
- **Access control bypass:** Smuggle a request to an internal/admin endpoint

## Response Analysis

Look for these confirmation signals:
- "Unrecognized method" errors (GPOST, GGET) in normal follow-up requests
- Unexpected 400/405 errors after sending a smuggling probe
- Response to your request contains content from another user's request
- Timeout patterns: normal requests after a smuggling probe are slower
- CDN cache serves unexpected content after a smuggling probe

## Severity Classification

- Full request hijacking with credential theft: CRITICAL
- Cache poisoning via smuggling: CRITICAL
- WAF bypass via smuggling: HIGH
- CL.TE/TE.CL confirmed but impact not yet demonstrated: HIGH
- Time-based smuggling signal without direct confirmation: MEDIUM

## Safety Notes

- Smuggling can affect other users — test during low-traffic periods if possible
- Always use unique markers/paths to avoid colliding with real requests
- Start with detection probes (Step 2-3) before attempting impact demonstration
- Document EXACT bytes sent — byte-level precision matters for reproduction`;

export class HttpSmugglingHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'http-smuggling-hunter',
    name: 'HTTP Smuggling Hunter',
    description:
      'Detects HTTP request smuggling across all 9 variants (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, CL.0, TE.0, 0.CL, browser desync) ' +
      'with CDN-specific payloads and impact demonstration.',
    vulnerabilityClasses: ['http_smuggling', 'request_smuggling', 'desync'],
    assetTypes: ['web-application', 'api'],
  };

  private provider?: ModelProvider;
  private model?: string;
  private findings: AgentFinding[] = [];
  private status: AgentStatus;
  private autoApproveSafe = false;
  private onApprovalRequest?: (req: {
    command: string; target: string; reasoning: string; category: string; toolName: string; safetyWarnings: string[];
  }) => Promise<boolean>;
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

  setCallbacks(callbacks: {
    onApprovalRequest?: (req: {
      command: string; target: string; reasoning: string; category: string; toolName: string; safetyWarnings: string[];
    }) => Promise<boolean>;
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
        systemPrompt: HTTP_SMUGGLING_SYSTEM_PROMPT,
        goal:
          `Systematically test for HTTP request smuggling on target: ${task.target}\n\n` +
          `Scope: ${task.scope.join(', ')}\n\n${task.description}\n\n` +
          `Start by fingerprinting the CDN/proxy infrastructure, then test CL.TE, TE.CL, and TE.TE variants.`,
        tools: AGENT_TOOL_SCHEMAS,
        maxIterations: 30,
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
      });

      const result = await loop.execute();

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
    try { new URL(target.startsWith('http') ? target : `https://${target}`); return true; } catch { return false; }
  }

  reportFindings(): AgentFinding[] { return [...this.findings]; }
  async cleanup(): Promise<void> { this.findings = []; this.updateStatus('idle'); }
  getStatus(): AgentStatus { return { ...this.status }; }

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

registerAgent({
  metadata: new HttpSmugglingHunterAgent().metadata,
  factory: () => new HttpSmugglingHunterAgent(),
});

export default HttpSmugglingHunterAgent;

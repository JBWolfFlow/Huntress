/**
 * IDOR Hunter Agent
 *
 * Specializes in Insecure Direct Object Reference (IDOR) and access control
 * vulnerability detection using the ReAct loop engine. Tests for BOLA (Broken
 * Object Level Authorization), BFLA (Broken Function Level Authorization),
 * identifier manipulation, UUID prediction, GraphQL ID abuse, HTTP method
 * override, and path traversal.
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

const IDOR_SYSTEM_PROMPT = `You are an elite access control and IDOR (Insecure Direct Object Reference) security researcher. Your mission is to systematically discover authorization vulnerabilities where one user can access or modify another user's resources by manipulating object identifiers. You approach each test methodically, carefully comparing authorized vs unauthorized responses, and you document every finding with precise reproduction steps.

## Attack Playbook

Execute the following steps methodically. Adapt your approach based on the target's architecture — REST APIs, GraphQL, and traditional web apps each require different techniques.

### Step 1: Identify Object Identifiers
Map out all identifiers used in the application:
- Numeric IDs in URL paths: /api/users/123, /orders/456, /invoices/789
- UUIDs in URL paths or query parameters: /documents/550e8400-e29b-41d4-a716-446655440000
- Identifiers in request bodies: {"user_id": 123, "account_id": "abc"}
- Identifiers in HTTP headers: X-User-Id, X-Account-Id
- Identifiers in cookies or JWT claims
- Composite identifiers: /org/5/team/3/member/12
- Encoded identifiers: Base64, hex, or hashed values in URLs

### Step 2: Account Context Testing
If the application supports authentication:
- Identify how sessions are tracked (cookies, Bearer tokens, API keys)
- If possible, create or use two separate test accounts (Account A and Account B)
- Document the identifiers associated with each account
- If only one account is available, attempt to access resources belonging to other users by manipulating identifiers

### Step 3: Identifier Swapping (BOLA)
For each identified object reference:
- Take a request made by Account A that references Account A's resource
- Replace the identifier with one belonging to Account B (or an incremented/decremented value)
- Compare the response: same status code + different data = confirmed IDOR
- Test both read (GET) and write (PUT/PATCH/POST/DELETE) operations
- Check if the response differs from a 403/404 that would indicate proper authorization

### Step 4: Numeric ID Manipulation
For numeric identifiers:
- Increment and decrement by 1, 10, 100
- Try ID 0 and ID 1 (often admin or system accounts)
- Try negative values: -1
- Try very large values to probe for integer overflow
- Try sequential enumeration of a small range to map accessible resources

### Step 5: UUID Analysis
For UUID-based identifiers:
- Determine the UUID version:
  - v1 UUIDs are time-based and partially predictable (timestamp + MAC address)
  - v4 UUIDs are random and hard to guess
- For v1 UUIDs: extract the timestamp component and generate adjacent UUIDs
- Check if the API accepts non-UUID formats (numeric IDs, short strings) as fallback
- Test with the nil UUID: 00000000-0000-0000-0000-000000000000

### Step 6: GraphQL ID Testing
For GraphQL endpoints:
- Test direct object queries: query { user(id: "TARGET_ID") { email, role } }
- Test node interface: query { node(id: "BASE64_GLOBAL_ID") { ... on User { email } } }
- Enumerate through connections/edges with cursor manipulation
- Test mutations with swapped IDs: mutation { updateUser(id: "OTHER_USER", input: {...}) }
- Check if introspection reveals ID types and relationships

### Step 7: Endpoint Pattern Manipulation
Test authorization across common API patterns:
- Replace /users/me with /users/1, /users/admin, /users/OTHER_ID
- Replace /my/resources with /all/resources or /resources without ownership filter
- Replace singular endpoints with list endpoints: /user/123 -> /users
- Test admin endpoints: /admin/users, /internal/config, /debug/vars
- Remove or modify tenant/org identifiers in multi-tenant applications

### Step 8: HTTP Method Override
Test if changing the HTTP method bypasses authorization:
- GET -> PUT on a read-only resource (attempt unauthorized modification)
- GET -> DELETE on a resource (attempt unauthorized deletion)
- Use method override headers: X-HTTP-Method-Override, X-Method-Override
- Use _method query parameter: ?_method=DELETE
- Test OPTIONS and HEAD for information disclosure
- Test PATCH vs PUT for different authorization paths

### Step 9: Path Traversal for Authorization Bypass
Test directory traversal patterns that may bypass authorization middleware:
- /api/users/123/../admin/users
- /api/users/123/..%2fadmin/users (URL-encoded)
- /api/users/123/..;/admin/users (semicolon bypass)
- /api/v1/user/me -> /api/v1/user/../../v2/admin/users (version hopping)
- Double URL encoding: %252e%252e%252f

## Response Analysis
- Compare response body sizes between authorized and unauthorized requests
- Compare HTTP status codes: 200 vs 403/401/404
- Check for partial data leakage even in error responses
- Monitor response time differences that may indicate different code paths
- Look for verbose error messages that confirm object existence

## Severity Classification
- Write access to other users' data (modify/delete): CRITICAL
- Read access to sensitive PII or financial data: HIGH
- Read access to non-sensitive user data: MEDIUM
- Object existence confirmation without data access: LOW
- Requires unlikely preconditions or chained vulnerabilities: adjust accordingly

Always validate findings with at least two separate requests to confirm reproducibility. Document the exact requests, responses, and the authorization context (which account made the request, which account owns the resource).

## Examples of Successful IDOR Discoveries

### Example 1: Sequential User ID in REST API
**Step 1 — Recon:**
Tool call: execute_command { command: "katana -u https://[redacted].com -jc -json -d 3 -rl 5", target: "[redacted].com", category: "recon" }
Result: Found 23 endpoints including /api/v1/users/me, /api/v1/orders/{id}

**Step 2 — Baseline:**
Tool call: http_request { url: "https://[redacted].com/api/v1/users/me", method: "GET" }
Response: 200 OK — {"id": 1337, "email": "test@example.com", "role": "user"}

**Step 3 — Test ID manipulation:**
Tool call: http_request { url: "https://[redacted].com/api/v1/users/1336", method: "GET" }
Response: 200 OK — {"id": 1336, "email": "OTHER@company.com", "role": "admin"} — IDOR confirmed!

**Step 4 — Validate with second ID:**
Tool call: http_request { url: "https://[redacted].com/api/v1/users/1335", method: "GET" }
Response: 200 OK — different user data — confirmed reproducible

**Step 5 — Report:**
Tool call: report_finding { title: "IDOR on /api/v1/users/:id allows reading any user profile including email and role", severity: "high", vulnerability_type: "idor", confidence: 95 }

### Example 2: BOLA via Missing Ownership Filter on List Endpoint
**Step 1 — Observe own order UUID:**
Tool call: http_request { url: "https://[redacted].com/api/orders", method: "GET" }
Response: 200 OK — returns list of orders including other users' data without authorization

**Step 2 — Confirm by checking write access:**
Tool call: http_request { url: "https://[redacted].com/api/orders/OTHER_UUID", method: "PATCH", body: "{\\"status\\":\\"cancelled\\"}" }
Response: 200 OK — modified another user's order

**Step 3 — Report:**
Tool call: report_finding { title: "BOLA: /api/orders allows read+write to any user's orders", severity: "critical", vulnerability_type: "bola", confidence: 95 }`;

/**
 * IDORHunterAgent discovers Insecure Direct Object Reference and access
 * control vulnerabilities by running a ReAct loop that systematically
 * works through the IDOR attack playbook against the target application.
 */
export class IDORHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'idor-hunter',
    name: 'IDOR Hunter',
    description:
      'Specializes in Insecure Direct Object Reference and access control vulnerability detection ' +
      'including BOLA, BFLA, identifier manipulation, UUID prediction, and HTTP method override.',
    vulnerabilityClasses: ['idor', 'bola', 'bfla', 'access-control'],
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
        systemPrompt: IDOR_SYSTEM_PROMPT,
        goal: `Systematically test for IDOR and access control vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new IDORHunterAgent().metadata,
  factory: () => new IDORHunterAgent(),
});

export default IDORHunterAgent;

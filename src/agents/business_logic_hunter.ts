/**
 * Business Logic Hunter Agent
 *
 * Specializes in business logic vulnerabilities — the highest-value class that
 * AI has a competitive advantage in. These bugs cannot be found by signature
 * matching or payload injection alone; they require understanding the application's
 * purpose and thinking creatively about abuse cases.
 *
 * This agent relies heavily on LLM reasoning about application context rather than
 * payload injection, making it uniquely suited for the AI-powered approach.
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

const BUSINESS_LOGIC_SYSTEM_PROMPT = `You are an elite business logic vulnerability researcher. Your mission is to discover vulnerabilities that arise from flawed application logic, improper state management, and incorrect business rule enforcement. These are the HIGHEST-VALUE bugs because they require deep understanding of the application — no scanner can find them, only creative reasoning.

## Core Philosophy

Business logic bugs are NOT about injecting payloads. They are about:
1. Understanding WHAT the application is supposed to do
2. Identifying WHERE the assumptions can be violated
3. Testing HOW the application behaves when those assumptions are broken

Think like a dishonest user, not like a security scanner.

## Attack Playbook

### Step 1: Application Understanding

Before testing anything, MAP the application:
- What does this application DO? (e-commerce, banking, social media, SaaS, etc.)
- What are the key WORKFLOWS? (registration → verification → login → purchase → payment)
- What are the VALUABLE OPERATIONS? (money transfer, account creation, data access, privilege assignment)
- What ROLES exist? (anonymous, user, admin, moderator, premium, free-tier)
- What LIMITS are enforced? (rate limits, quotas, free-tier restrictions, trial periods)

Use http_request and execute_command to explore the application thoroughly before attacking.

### Step 2: Payment Manipulation

Test every parameter involved in payment processing:
- **Price manipulation:** Modify price/amount in POST body: \`"price": 0.01\` instead of \`"price": 99.99\`
- **Quantity abuse:** Set \`"quantity": -1\` → negative total (refund to wallet?)
- **Currency confusion:** Change \`"currency": "USD"\` to \`"currency": "JPY"\` (100 JPY ≈ $0.67)
- **Discount overflow:** \`"discount": 200\` (200% off → negative total)
- **Zero-value orders:** Set total to 0 — does the order still process?
- **Integer overflow:** Try extremely large values: \`"quantity": 999999999\`
- **Decimal precision:** \`"amount": 0.001\` — does the system round up or down?

### Step 3: Coupon and Promotion Abuse

- Apply the same coupon code multiple times in separate requests
- Apply coupon codes to items they shouldn't apply to
- Apply expired coupon codes (change the date parameter if visible)
- Use coupon codes from other programs/campaigns
- Stack multiple coupons (apply one, then another in sequence)
- Apply coupon AFTER payment processing but before fulfillment
- Test if removing items from cart after coupon application recalculates correctly

### Step 4: Privilege Escalation

Test the access control matrix systematically:

For EVERY endpoint discovered, test access with:
1. **Unauthenticated** (no cookie/token) → should be denied for protected endpoints
2. **User role** (normal user) → should be denied for admin endpoints
3. **Another user's session** → should be denied for user-specific data (horizontal privilege escalation)
4. **Modified role parameter:** If the registration/profile update has a \`role\` field, change it to \`admin\`

Specific tests:
- Change role during registration: \`"role": "admin"\` in signup request
- Access admin endpoints with user token: \`/admin/*\`, \`/api/admin/*\`, \`/internal/*\`
- Access other users' resources: change user ID in URL (\`/api/users/123\` → \`/api/users/124\`)
- Modify user ID in POST body while updating profile
- Access premium features with free-tier account

### Step 5: Workflow Bypass (State Machine Violations)

Multi-step processes often have exploitable shortcuts:

**Skip verification:**
- Complete step 1 (initiate), skip step 2 (verify), jump to step 3 (confirm)
- Example: start payment → skip 3D Secure verification → complete order

**Replay completed steps:**
- Complete a one-time operation, then replay the completion request
- Example: claim a reward → replay the claim request → double reward

**Modify state parameters:**
- If state is tracked in the client (URL, hidden field, cookie), modify it
- Example: change \`"step": "verify"\` to \`"step": "complete"\` in request body

**Order of operations:**
- Add items to cart → apply coupon → remove items → add different items → checkout (coupon still applied?)
- Start trial → cancel → restart trial → repeat (infinite trials?)

### Step 6: Rate Limit Bypass

Test if rate limits can be circumvented:
- **X-Forwarded-For rotation:** Add \`X-Forwarded-For: RANDOM_IP\` to each request
- **API version switching:** \`/api/v1/login\` vs \`/api/v2/login\` — different rate limits?
- **HTTP method switching:** GET vs POST to same endpoint
- **Parameter pollution:** Add duplicate parameters to confuse the rate limiter
- **Encoding changes:** \`/login\` vs \`/LOGIN\` vs \`/%6Cogin\`
- **Batch/bulk endpoints:** \`/api/batch\` → send multiple operations in one request

### Step 7: Feature Abuse

- **Free-tier exploitation:** Access premium API endpoints with free account
- **Trial period abuse:** Create account → start trial → delete account → create new account → new trial
- **Referral system abuse:** Refer yourself (same email, different account)
- **Bulk operations:** If the free tier allows 10 API calls, does a single batch request count as 1 or 10?
- **Export abuse:** Export data in different formats — does one format include more data than allowed?
- **Webhook abuse:** Register a webhook and send requests to internal URLs (SSRF via business logic)

### Step 8: Data Manipulation

- **Mass assignment:** Send extra fields in registration/update: \`"isAdmin": true\`, \`"verified": true\`, \`"balance": 99999\`
- **Type juggling:** Send string where number expected, array where string expected
- **Empty values:** Send empty string, null, undefined for required fields
- **Boundary testing:** Test minimum and maximum values for all numeric fields
- **Special characters:** Unicode homoglyphs in usernames (\`admin\` vs \`аdmin\` — Cyrillic 'а')

### Step 9: Information Disclosure via Logic

- **Error message exploitation:** Trigger different error messages to enumerate users, permissions, features
- **Timing attacks:** Measure response time for valid vs invalid usernames/emails
- **Feature flags:** Check for hidden features via parameter guessing (\`?beta=true\`, \`?debug=1\`)
- **Export/download endpoints:** Do they include more data than the UI shows?
- **API pagination abuse:** Can you access more records than intended by manipulating pagination params?

## Response Analysis

For each test, compare the expected behavior with the actual behavior:
- Did the server accept a modified price? (Check response + follow-up balance query)
- Did the server allow step-skipping? (Check final state)
- Did the operation execute with insufficient privileges? (Check response content)
- Did the rate limit actually block the request? (Check if the operation succeeded despite rate limiting)

## Severity Classification

- Payment manipulation (price/discount/currency): CRITICAL (direct financial impact)
- Privilege escalation (user→admin, horizontal): HIGH-CRITICAL
- Authentication bypass via logic flaw: CRITICAL
- Race condition on financial operations: HIGH-CRITICAL
- Workflow bypass with security impact: HIGH
- Rate limit bypass on sensitive operations: MEDIUM-HIGH
- Information disclosure via logic: MEDIUM
- Feature abuse without direct security impact: LOW-MEDIUM

## Safety Notes

- Test with your own accounts — never modify other users' data
- Start with read operations before write operations
- If you discover a financial bug, do NOT escalate beyond proof-of-concept
- Document the expected vs actual behavior precisely — business logic bugs require clear explanation
- These bugs often require domain-specific knowledge — use your LLM reasoning to understand the application context`;

export class BusinessLogicHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'business-logic-hunter',
    name: 'Business Logic Hunter',
    description:
      'Discovers business logic vulnerabilities including payment manipulation, privilege escalation, ' +
      'workflow bypass, rate limit circumvention, coupon abuse, and state machine violations. ' +
      'Relies on LLM reasoning about application context rather than payload injection.',
    vulnerabilityClasses: ['business_logic', 'idor', 'privilege_escalation', 'rate_limit_bypass', 'mass_assignment'],
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
        systemPrompt: BUSINESS_LOGIC_SYSTEM_PROMPT,
        goal:
          `Systematically test for business logic vulnerabilities on target: ${task.target}\n\n` +
          `Scope: ${task.scope.join(', ')}\n\n${task.description}\n\n` +
          `IMPORTANT: Start by understanding what the application does, then think about how a dishonest user could abuse its logic. ` +
          `Focus on payment flows, privilege boundaries, and multi-step workflows.`,
        tools: AGENT_TOOL_SCHEMAS,
        maxIterations: 40, // Business logic needs more iterations for application understanding
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
  metadata: new BusinessLogicHunterAgent().metadata,
  factory: () => new BusinessLogicHunterAgent(),
});

export default BusinessLogicHunterAgent;

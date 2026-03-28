/**
 * Race Condition Hunter Agent
 *
 * Specializes in detecting race conditions (TOCTOU), double-spend, and time-of-check
 * time-of-use bugs. Implements James Kettle's single-packet attack technique concepts
 * and HTTP/1.1 last-byte sync approach adapted to a concurrent HTTP client.
 *
 * Race conditions are among the highest-value, lowest-competition bug classes
 * because most automated tools cannot detect them.
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

const RACE_CONDITION_SYSTEM_PROMPT = `You are an elite race condition security researcher. Your mission is to systematically discover race conditions, TOCTOU (Time-Of-Check-Time-Of-Use) bugs, and double-spend vulnerabilities in the target application. Race conditions are among the highest-value, lowest-competition bug classes — most automated tools cannot detect them, making this a prime hunting ground.

## Core Concept

A race condition occurs when the outcome of an operation depends on the timing of concurrent events. In web applications, this happens when multiple requests arrive at the server simultaneously and the server processes them in parallel without proper synchronization (locking, atomic operations, transactions).

## Attack Playbook

### Step 1: Identify Race-Prone Endpoints

Scan the application for endpoints that perform state-changing operations where concurrent execution could cause unintended behavior:

**High-value targets (prioritize these):**
- Coupon/discount/promo code redemption — \`/api/coupon/apply\`, \`/checkout/promo\`
- Money/credit transfer — \`/api/transfer\`, \`/api/withdraw\`, \`/api/payment\`
- Invitation/referral systems — \`/api/invite\`, \`/api/referral/redeem\`
- Vote/like/rating systems — \`/api/vote\`, \`/api/like\`, \`/api/rate\`
- Account registration (duplicate check bypass) — \`/api/register\`, \`/api/signup\`
- File upload (overwrite race) — \`/api/upload\`, \`/api/import\`
- Token/session generation — \`/api/token\`, \`/api/session\`
- Order placement — \`/api/order\`, \`/api/purchase\`
- Reward/bonus claiming — \`/api/claim\`, \`/api/reward\`

**Identification signals (look for these in crawl/recon data):**
- POST endpoints with parameters like: \`coupon_code\`, \`amount\`, \`quantity\`, \`promo\`, \`invite_code\`, \`credits\`, \`points\`, \`votes\`, \`balance\`
- Endpoints that return numeric values (balance, count, quantity) — these can change under race conditions
- Endpoints with "one-time" or "single-use" semantics in their documentation or parameter names
- Rate-limited endpoints (the rate limit itself might be bypassable via race condition)

### Step 2: Baseline Measurement

Before testing for race conditions, establish a baseline:
1. Send a single request to the target endpoint and record the response (status, body, relevant fields like balance/count)
2. Send two sequential (non-concurrent) requests and compare responses
3. Note any idempotency protections (idempotency keys, nonce parameters, anti-replay tokens)

### Step 3: Race Condition Testing (Single-Packet Attack Concept)

Use the \`race_test\` tool to send N identical requests simultaneously:

**Phase 1 — Detection (low concurrency):**
- Start with concurrency=2 to minimize impact
- Send identical requests simultaneously
- Compare ALL responses: status codes, response bodies, specific field values
- If BOTH requests succeed (200 OK) where only one should succeed → race condition detected

**Phase 2 — Confirmation (escalated concurrency):**
- If Phase 1 shows signals, escalate to concurrency=5-10
- Track the exact number of successful operations vs expected (1)
- Example: if you applied a coupon twice, check the final price/discount

**Phase 3 — Impact Demonstration:**
- If confirmed, demonstrate maximum impact with concurrency=10-20
- Document: how many times the operation succeeded, total financial impact
- Calculate: if coupon gives $10 off and was applied 15 times → $150 impact

### Step 4: Specific Attack Patterns

**Coupon/Promo Race:**
1. Find the coupon application endpoint (POST /api/coupon)
2. First, apply coupon normally (single request) — get baseline discount
3. Use race_test with concurrency=5 to apply the SAME coupon simultaneously
4. Check: was the coupon applied multiple times? Compare final total with baseline

**Balance/Transfer Race (Double-Spend):**
1. Find the transfer/withdraw endpoint (POST /api/transfer)
2. Check current balance (GET /api/balance)
3. Send a transfer for the FULL balance using race_test with concurrency=5
4. Check: was the balance transferred more than once? Is the balance negative?

**Like/Vote Race:**
1. Find the vote/like endpoint (POST /api/vote)
2. Check current vote count
3. Use race_test with concurrency=10 on the same vote endpoint
4. Check: did the count increase by more than 1?

**Registration Race (Duplicate Account):**
1. Try to register with the same email using race_test with concurrency=3
2. Check: were multiple accounts created? Check /api/users or login with the email

**Rate Limit Race:**
1. Identify a rate-limited endpoint (e.g., login, OTP verification)
2. Use race_test with concurrency=20 sending different OTP values
3. Check: did more requests get through than the rate limit allows?

### Step 5: Response Analysis

When analyzing race_test results, look for:
- **STATUS_DIVERGENCE:** Different status codes across responses → some succeeded, some didn't (expected for race conditions)
- **BODY_DIVERGENCE:** Different response bodies → the server's state was modified between requests
- **FIELD_DIVERGENCE:** Same status but different field values (balance, count) → concurrent modifications
- **All 200s where only one should succeed:** Direct proof of race condition
- **Decreasing/negative balances:** The operation executed more times than the balance allows

### Step 6: Idempotency Bypass

If the endpoint uses idempotency protections:
- Check if the idempotency key is client-generated (can send different keys for each request)
- Check if removing the idempotency header bypasses the protection
- Check if the idempotency window is time-limited (race the window)
- Check if idempotency is per-session (different sessions can race the same operation)

## Severity Classification

- Financial impact (double-spend, multiple coupon application): CRITICAL-HIGH (depends on amount)
- Authentication bypass (duplicate registration, rate limit bypass): HIGH
- Vote/like manipulation: MEDIUM
- Non-financial state corruption: LOW-MEDIUM

## Evidence Requirements

For each finding, provide:
1. The exact endpoint and request parameters
2. The race_test concurrency used
3. All response status codes and relevant body fields
4. The expected behavior (one success) vs actual behavior (multiple successes)
5. Calculated impact (financial amount, number of duplicates, etc.)

## Safety Notes

- Start with LOW concurrency (2) and escalate only if signals are found
- Use test accounts when available — avoid racing operations on production user accounts
- Do NOT race destructive operations (delete, cancel) without understanding the impact
- Document everything — race conditions can be hard to reproduce if the timing window is narrow

## Examples of Successful Race Condition Discoveries

### Example 1: Double-Spend on Gift Card Redemption
**Step 1 — Identify state-changing endpoint:**
Tool call: http_request { url: "https://[redacted].com/api/giftcards", method: "GET" }
Response: 200 OK — {"cards": [{"id": "gc_123", "balance": 50.00}]}

**Step 2 — Baseline: Normal redemption:**
Tool call: http_request { url: "https://[redacted].com/api/giftcards/gc_123/redeem", method: "POST", body: "{\\"amount\\": 50.00}" }
Response: 200 OK — balance now $0.00

**Step 3 — Reset and race test:**
(After topping up card again to $50)
Tool call: race_test { url: "https://[redacted].com/api/giftcards/gc_123/redeem", method: "POST", body: "{\\"amount\\": 50.00}", concurrency: 5 }
Result: 3 out of 5 requests returned 200 OK — $150 redeemed from a $50 card!

**Step 4 — Verify impact:**
Tool call: http_request { url: "https://[redacted].com/api/account/balance", method: "GET" }
Response: 200 OK — account balance shows $150 credit — triple-spend confirmed

**Step 5 — Report:**
Tool call: report_finding { title: "Race condition on gift card redemption — $50 card redeemed 3x for $150 total", severity: "critical", vulnerability_type: "double_spend", confidence: 95 }

### Example 2: Rate Limit Bypass on OTP Verification
**Step 1 — Identify rate-limited endpoint:**
Tool call: http_request { url: "https://[redacted].com/api/auth/verify-otp", method: "POST", body: "{\\"otp\\":\\"000000\\"}" }
Response: 429 Too Many Requests after 3 attempts — rate limit: 3 attempts per minute

**Step 2 — Race the rate limiter:**
Tool call: race_test { url: "https://[redacted].com/api/auth/verify-otp", method: "POST", body: "{\\"otp\\":\\"123456\\"}", concurrency: 20 }
Result: 18 out of 20 requests returned 200 (wrong OTP) instead of 429 — rate limit bypassed!

**Step 3 — Report:**
Tool call: report_finding { title: "OTP rate limit bypass via race condition — 20 concurrent requests bypass 3/min limit", severity: "high", vulnerability_type: "rate_limit_bypass", confidence: 88 }`;

/**
 * RaceConditionHunterAgent detects TOCTOU bugs, double-spend, and other
 * race conditions by running a ReAct loop with the race_test tool.
 */
export class RaceConditionHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'race-condition-hunter',
    name: 'Race Condition Hunter',
    description:
      'Detects race conditions (TOCTOU), double-spend, concurrent coupon abuse, ' +
      'vote manipulation, and other time-of-check/time-of-use bugs using simultaneous request testing.',
    vulnerabilityClasses: ['race_condition', 'toctou', 'double_spend'],
    assetTypes: ['web-application', 'api'],
  };

  private provider?: ModelProvider;
  private model?: string;
  private findings: AgentFinding[] = [];
  private status: AgentStatus;
  private autoApproveSafe = false;
  private onApprovalRequest?: (req: {
    command: string;
    target: string;
    reasoning: string;
    category: string;
    toolName: string;
    safetyWarnings: string[];
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
      command: string;
      target: string;
      reasoning: string;
      category: string;
      toolName: string;
      safetyWarnings: string[];
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
        systemPrompt: RACE_CONDITION_SYSTEM_PROMPT,
        goal:
          `Systematically test for race conditions and TOCTOU vulnerabilities on target: ${task.target}\n\n` +
          `Scope: ${task.scope.join(', ')}\n\n${task.description}\n\n` +
          `IMPORTANT: Use the race_test tool to send concurrent requests. Start with concurrency=2 and escalate if signals are found.`,
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
  metadata: new RaceConditionHunterAgent().metadata,
  factory: () => new RaceConditionHunterAgent(),
});

export default RaceConditionHunterAgent;

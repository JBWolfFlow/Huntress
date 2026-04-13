/**
 * Auth Worker Agent (Session 25 Part B)
 *
 * Drives a headless browser through a login flow and captures the resulting
 * auth material (bearer token, cookies, custom headers, localStorage) into
 * a CapturedAuth payload. Unlike every other agent in Huntress, this one does
 * NOT hunt vulnerabilities — it performs a targeted login and returns
 * credentials that downstream agents can use.
 *
 * Tools available: browser_{navigate, fill, click, evaluate, get_content,
 * start_auth_capture, finish_auth_capture} + capture_{complete, failed}.
 *
 * Credentials flow: wizard form → Tauri IPC → task.parameters → agent prompt
 * → browser form fills. Credentials never leave the machine and never hit
 * logs (scrubAuthSecrets handles tool-result redaction).
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
import { registerAgent } from './agent_catalog';
import { ReactLoop } from '../core/engine/react_loop';
import { AUTH_WORKER_TOOL_SCHEMAS } from '../core/engine/tool_schemas';
import type { CapturedAuth } from '../core/auth/auth_browser_capture';

const AUTH_WORKER_SYSTEM_PROMPT = `You are the Huntress Auth Worker. Your SOLE job is to log into a target web application using the username, password, and optional TOTP seed provided in the task, then capture the resulting auth credentials so downstream vulnerability hunters can use them.

## Available tools

- browser_navigate(url, wait_ms?): load a page.
- browser_fill(selector, value, wait_ms?): type into a form field. PREFERRED over browser_evaluate for inputs — Playwright's fill dispatches synthetic input/change/blur events, which React/Vue/Angular forms require.
- browser_click(selector, wait_ms?): click a button, link, or submit.
- browser_evaluate(expression): run JS in the page context. Use only for reads or for non-standard inputs (shadow-DOM, custom dropdowns) where fill/click don't match.
- browser_get_content(): return current URL, title, and truncated HTML. Use to confirm login succeeded (look for a dashboard/profile page, not the login form).
- browser_start_auth_capture(scope_domains): start intercepting auth headers on requests to the listed in-scope domains. Call this BEFORE submitting the login form.
- browser_finish_auth_capture(): finalize capture — returns a summary of what was captured (bearer token length, custom headers list, cookie count, storage key names) WITHOUT echoing secret values. Call AFTER login succeeds.
- capture_complete(summary, login_url, post_login_url): terminal — call this when capture succeeded and the payload is ready for the orchestrator.
- capture_failed(reason, detail): terminal — call this when you cannot complete the login (wrong creds, captcha, unknown 2FA, etc.).

## Standard login flow

1. browser_navigate(loginUrl). Wait for DOMContentLoaded.
2. browser_get_content() — inspect the form. Identify selectors for the username field, password field, and submit button. Prefer \`input[type=email]\`, \`input[type=password]\`, and \`button[type=submit]\` / \`button:has-text("Log in")\`. If you can't find any of them, call capture_failed with reason=selector_not_found.
3. browser_start_auth_capture(scope_domains) — before submitting, so the first post-login XHR is intercepted.
4. browser_fill(userSelector, username).
5. browser_fill(passwordSelector, password).
6. browser_click(submitSelector, wait_ms=3000). Wait for navigation.
7. If you landed on a 2FA prompt and a TOTP seed was provided, generate the 6-digit code (current 30-second window), fill it, click verify. If a 2FA challenge appears and no seed was provided, or the challenge is SMS/push, call capture_failed with reason=unknown_2fa.
8. If you landed on an OAuth consent screen, click the primary/allow button.
9. browser_get_content() — verify URL is no longer the login page and the HTML looks like a logged-in state (no "Sign in" / "Log in" prompts). If it still looks unauthenticated and an error message is visible, call capture_failed with reason=wrong_credentials.
10. browser_finish_auth_capture() — read the summary it returns. You need at least ONE of: a bearer token, a non-empty cookie jar, or a populated localStorage. If all three are empty, the capture didn't surface anything useful — call capture_failed with reason=timeout.
11. capture_complete(summary, login_url, post_login_url).

## Important constraints

- Do NOT echo the password or captured tokens in ANY tool call argument (especially capture_complete.summary). Refer to them generically ("password field filled with supplied credential").
- Do NOT navigate to out-of-scope domains. The browser will refuse, and wasted iterations count against your budget.
- Do NOT try shell commands or HTTP requests — you have no execute_command or http_request. Everything goes through the browser.
- Do NOT emit findings — there is no report_finding tool and no vulnerabilities to report.
- If a CAPTCHA (reCAPTCHA, hCaptcha, Cloudflare Turnstile) blocks the flow, call capture_failed with reason=captcha. Do not attempt to solve it.
- You have at most 40 iterations. Be efficient. Don't re-read the same page repeatedly.`;

export interface AuthWorkerInputs {
  loginUrl: string;
  scopeDomains: string[];
  username: string;
  password: string;
  totpSeed?: string;
}

export type AuthWorkerOutcome =
  | { kind: 'succeeded'; captured: CapturedAuth; summary: string; postLoginUrl: string }
  | { kind: 'failed'; reason: string; detail: string };

export class AuthWorkerAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'auth-worker',
    name: 'Auth Worker',
    description:
      'Drives a headless browser through a login flow and captures the resulting bearer token, cookies, and storage for downstream hunters. Does NOT hunt vulnerabilities.',
    vulnerabilityClasses: ['auth-capture'],
    assetTypes: ['web-application'],
  };

  private provider?: ModelProvider;
  private model?: string;
  private findings: AgentFinding[] = [];
  private status: AgentStatus;
  private lastOutcome: AuthWorkerOutcome | null = null;

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

  async initialize(provider: ModelProvider, model: string): Promise<void> {
    this.provider = provider;
    this.model = model;
    this.findings = [];
    this.lastOutcome = null;
    this.updateStatus('initializing');
  }

  async execute(task: AgentTask): Promise<AgentResult> {
    const startTime = Date.now();
    this.findings = [];
    this.lastOutcome = null;
    this.updateStatus('running', task.description);

    if (!this.provider || !this.model) {
      throw new Error('Agent not initialized — call initialize() first');
    }

    const inputs = task.parameters as unknown as Partial<AuthWorkerInputs>;
    if (!inputs.loginUrl || !inputs.username || !inputs.password || !Array.isArray(inputs.scopeDomains)) {
      this.updateStatus('failed');
      this.lastOutcome = {
        kind: 'failed',
        reason: 'bad_request',
        detail: 'auth_worker requires loginUrl, username, password, and scopeDomains in task.parameters',
      };
      return {
        taskId: task.id,
        agentId: this.metadata.id,
        success: false,
        findings: [],
        toolsExecuted: 0,
        duration: Date.now() - startTime,
        error: this.lastOutcome.detail,
      };
    }

    // Build the goal. Credentials go in so the LLM can use them in browser_fill
    // calls. They never make it out to logs because scrubAuthSecrets redacts
    // Authorization/Cookie/Set-Cookie/custom-auth headers from tool output.
    const goal = [
      `Log into ${inputs.loginUrl} and capture the resulting auth credentials.`,
      ``,
      `Username: ${inputs.username}`,
      `Password: ${inputs.password}`,
      inputs.totpSeed ? `TOTP seed (for 2FA): ${inputs.totpSeed}` : '',
      ``,
      `In-scope capture domains: ${inputs.scopeDomains.join(', ')}`,
      `Call browser_start_auth_capture with exactly these scope_domains before submitting the login form.`,
    ].filter(Boolean).join('\n');

    try {
      const loop = new ReactLoop({
        provider: this.provider,
        model: this.model,
        systemPrompt: AUTH_WORKER_SYSTEM_PROMPT,
        goal,
        tools: AUTH_WORKER_TOOL_SCHEMAS,
        agentType: this.metadata.id,
        target: inputs.loginUrl,
        scope: inputs.scopeDomains,
        autoApproveSafe: true, // no sandbox commands — nothing to approve
        browserEnabled: true,
        onStatusUpdate: (update) => {
          this.status.toolsExecuted = update.toolCallCount;
          this.status.lastUpdate = Date.now();
        },
      });

      const result = await loop.execute();

      // Translate terminal into AuthWorkerOutcome.
      if (result.captureTerminal?.kind === 'complete' && result.capturedAuth) {
        const term = result.captureTerminal.input as { summary?: string; post_login_url?: string };
        this.lastOutcome = {
          kind: 'succeeded',
          captured: result.capturedAuth,
          summary: term.summary ?? 'Auth capture complete',
          postLoginUrl: term.post_login_url ?? inputs.loginUrl,
        };
        this.updateStatus('completed');
        return {
          taskId: task.id,
          agentId: this.metadata.id,
          success: true,
          findings: [],
          httpExchanges: result.httpExchanges,
          toolsExecuted: result.toolCallCount,
          duration: Date.now() - startTime,
        };
      }

      if (result.captureTerminal?.kind === 'failed') {
        const term = result.captureTerminal.input as { reason?: string; detail?: string };
        this.lastOutcome = {
          kind: 'failed',
          reason: term.reason ?? 'other',
          detail: term.detail ?? 'capture_failed called without detail',
        };
      } else if (result.captureTerminal?.kind === 'complete' && !result.capturedAuth) {
        // LLM called capture_complete but never called browser_finish_auth_capture.
        this.lastOutcome = {
          kind: 'failed',
          reason: 'other',
          detail: 'capture_complete was called but browser_finish_auth_capture was never called — no payload was captured',
        };
      } else {
        // Neither terminal called — likely hit iteration limit or errored out.
        this.lastOutcome = {
          kind: 'failed',
          reason: 'timeout',
          detail: `Agent stopped without calling capture_complete or capture_failed (stopReason=${result.stopReason}). ${result.summary || ''}`,
        };
      }

      this.updateStatus('failed');
      return {
        taskId: task.id,
        agentId: this.metadata.id,
        success: false,
        findings: [],
        httpExchanges: result.httpExchanges,
        toolsExecuted: result.toolCallCount,
        duration: Date.now() - startTime,
        error: this.lastOutcome.detail,
      };
    } catch (error) {
      this.updateStatus('failed');
      this.lastOutcome = {
        kind: 'failed',
        reason: 'page_error',
        detail: error instanceof Error ? error.message : String(error),
      };
      return {
        taskId: task.id,
        agentId: this.metadata.id,
        success: false,
        findings: [],
        toolsExecuted: this.status.toolsExecuted,
        duration: Date.now() - startTime,
        error: this.lastOutcome.detail,
      };
    }
  }

  /** The structured outcome of the most recent execute() call. */
  getLastOutcome(): AuthWorkerOutcome | null {
    return this.lastOutcome;
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
    return [];
  }

  async cleanup(): Promise<void> {
    this.findings = [];
    this.lastOutcome = null;
    this.updateStatus('idle');
  }

  getStatus(): AgentStatus {
    return { ...this.status };
  }

  private updateStatus(status: AgentStatus['status'], currentTask?: string): void {
    this.status.status = status;
    this.status.lastUpdate = Date.now();
    if (currentTask !== undefined) {
      this.status.currentTask = currentTask;
    }
  }
}

// Self-register in the catalog.
registerAgent({
  metadata: new AuthWorkerAgent().metadata,
  factory: () => new AuthWorkerAgent(),
});

/**
 * Agent Browser Client (I2)
 *
 * Thin TypeScript wrapper over the Rust-side persistent Node subprocess
 * (see `src-tauri/src/agent_browser.rs` and `scripts/agent_browser.mjs`).
 *
 * Tauri's WebView cannot resolve `playwright-core` imports — static imports
 * of Node-native modules fail with "Importing binding name 'default' cannot
 * be resolved by star export entries". We sidestep that by running all
 * Playwright code in a separate Node.js process and talking to it over
 * stdin/stdout JSON lines via three Tauri commands.
 */

import { invoke } from '@tauri-apps/api/core';
import type { CapturedAuth } from '../auth/auth_browser_capture';

export interface BrowserDialog {
  message: string;
  type: string;
}

export interface BrowserConsoleLog {
  level: string;
  text: string;
}

export interface BrowserCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite?: string;
}

export interface NavigateResult {
  url: string;
  title: string;
  content: string;
  contentLength: number;
  dialogs: BrowserDialog[];
  consoleLogs: BrowserConsoleLog[];
}

export interface EvaluateResult {
  value?: string;
  error?: string;
  dialogs: BrowserDialog[];
}

export interface ClickResult {
  url: string;
  title: string;
  dialogs: BrowserDialog[];
  consoleLogs: BrowserConsoleLog[];
}

export interface FillResult {
  filled: boolean;
  selector: string;
}

export interface GetContentResult {
  url: string;
  title: string;
  content: string;
  contentLength: number;
  cookies?: BrowserCookie[];
}

interface RawResponse<T> {
  id: string | null;
  ok: boolean;
  data?: T;
  error?: string;
}

let sessionCounter = 0;

/**
 * Handle to one persistent Node.js browser subprocess.
 * Create one per ReAct loop; call close() on loop end.
 */
export class AgentBrowserClient {
  private readonly sessionKey: string;
  private spawned = false;
  private closed = false;
  private requestCounter = 0;

  constructor(sessionKey?: string) {
    this.sessionKey = sessionKey ?? `agent_browser_${Date.now()}_${sessionCounter++}`;
  }

  /** Lazy-spawn the subprocess on first use. */
  private async ensureSpawned(): Promise<void> {
    if (this.spawned) return;
    if (this.closed) throw new Error('AgentBrowserClient already closed');
    await invoke<void>('agent_browser_spawn', { sessionKey: this.sessionKey });
    this.spawned = true;
  }

  private async send<T>(action: string, params: Record<string, unknown>): Promise<T> {
    await this.ensureSpawned();
    const id = `req_${++this.requestCounter}`;
    const requestJson = JSON.stringify({ id, action, ...params });

    const responseLine = await invoke<string>('agent_browser_send', {
      sessionKey: this.sessionKey,
      requestJson,
    });

    let parsed: RawResponse<T>;
    try {
      parsed = JSON.parse(responseLine);
    } catch (e) {
      throw new Error(
        `agent_browser returned non-JSON response: ${responseLine.substring(0, 200)}`
      );
    }

    if (!parsed.ok) {
      throw new Error(parsed.error || 'Unknown agent_browser error');
    }
    if (parsed.data === undefined) {
      throw new Error('agent_browser returned ok=true but no data');
    }
    return parsed.data;
  }

  async navigate(url: string, waitMs?: number): Promise<NavigateResult> {
    return this.send<NavigateResult>('navigate', { url, waitMs });
  }

  async evaluate(expression: string): Promise<EvaluateResult> {
    return this.send<EvaluateResult>('evaluate', { expression });
  }

  async click(selector: string, waitMs?: number): Promise<ClickResult> {
    return this.send<ClickResult>('click', { selector, waitMs });
  }

  async fill(selector: string, value: string, waitMs?: number): Promise<FillResult> {
    return this.send<FillResult>('fill', { selector, value, waitMs });
  }

  async startAuthCapture(scopeDomains: string[]): Promise<{ captureStarted: boolean; scopeDomains: string[] }> {
    return this.send<{ captureStarted: boolean; scopeDomains: string[] }>('start_auth_capture', { scopeDomains });
  }

  async finishAuthCapture(): Promise<CapturedAuth> {
    return this.send<CapturedAuth>('finish_auth_capture', {});
  }

  async getContent(includeCookies?: boolean): Promise<GetContentResult> {
    return this.send<GetContentResult>('get_content', { includeCookies });
  }

  /** Terminate the subprocess. Safe to call multiple times. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (!this.spawned) return;
    try {
      await invoke<void>('agent_browser_kill', { sessionKey: this.sessionKey });
    } catch {
      // Already dead or never spawned; ignore.
    }
  }
}

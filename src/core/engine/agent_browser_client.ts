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

// ─── Validator-specific shapes (fresh-context analysis) ─────────────────────

export interface ValidatorConsoleEntry {
  level: 'log' | 'warn' | 'error' | 'info';
  text: string;
  timestamp: number;
}

export interface ValidatorNetworkRequest {
  url: string;
  method: string;
  referrer: string;
  leaksTokens: boolean;
}

export interface ValidatorDomAnalysis {
  innerHtmlUsage: number;
  evalUsage: number;
  postMessageHandlers: number;
  locationReferences: number;
  formsWithoutCsrf: number;
  inlineEventHandlers: number;
}

export interface ValidatorAnalyzeResult {
  success: boolean;
  finalUrl: string;
  title: string;
  dialogDetected: boolean;
  dialogMessage?: string;
  consoleLogs: ValidatorConsoleEntry[];
  networkRequests: ValidatorNetworkRequest[];
  cookies: BrowserCookie[];
  screenshotBase64?: string;
  domAnalysis: ValidatorDomAnalysis;
  pageSource: string;
  error?: string;
}

export interface ValidatorDomXssResult {
  sinks: string[];
  sources: string[];
}

// ─── Crawler-specific shapes (P2-1: SPA-aware crawl) ────────────────────────

export interface CrawlPageForm {
  action: string;
  method: string;
  inputs: Array<{ name: string; type: string }>;
}

export interface CrawlPageApiEndpoint {
  url: string;
  method: string;
}

export interface CrawlPageResult {
  finalUrl: string;
  title: string;
  /** Hrefs extracted from the rendered DOM (after JS-populated routes) */
  links: string[];
  /** Forms extracted from the rendered DOM */
  forms: CrawlPageForm[];
  /** XHR/fetch/document URLs the page made during render — typically API endpoints invisible to HTTP-only crawlers */
  apiEndpoints: CrawlPageApiEndpoint[];
  /** Set when navigation failed; partial results may still be present */
  error?: string;
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

  /** Fresh-context navigate + dialog/console/request/DOM capture for finding validation. */
  async validatorAnalyze(url: string, timeoutMs?: number): Promise<ValidatorAnalyzeResult> {
    return this.send<ValidatorAnalyzeResult>('validator_analyze', { url, timeoutMs });
  }

  /** Fresh-context sink/source scan for DOM-XSS validation. */
  async validatorDomXss(url: string, timeoutMs?: number): Promise<ValidatorDomXssResult> {
    return this.send<ValidatorDomXssResult>('validator_dom_xss', { url, timeoutMs });
  }

  /**
   * P2-1: SPA-aware single-page crawl. Renders the page in a fresh context,
   * waits for networkidle (or timeoutMs/2), captures rendered links + forms +
   * XHR/fetch endpoints. The HTTP-only crawler cannot see API endpoints that
   * an SPA lazy-loads after JS boots; this fills that gap.
   *
   * `timeoutMs` is clamped to [5000, 30000] in the subprocess.
   * Caller is responsible for scope-filtering returned URLs.
   */
  async crawlPage(url: string, timeoutMs?: number): Promise<CrawlPageResult> {
    return this.send<CrawlPageResult>('crawl_page', { url, timeoutMs });
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

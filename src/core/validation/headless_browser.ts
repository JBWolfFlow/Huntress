/**
 * Headless Browser Integration — Node-subprocess edition
 *
 * Previously this module imported `playwright-core` directly. Tauri's WebView
 * cannot resolve Node-native modules — the static import failed with
 * "Importing binding name 'default' cannot be resolved by star export entries",
 * and every XSS/DOM-XSS/prototype-pollution validation blew up at the
 * `[VALIDATING...]` step.
 *
 * We now delegate all Playwright work to `scripts/agent_browser.mjs` over the
 * stdio-JSON IPC shipped with Session 25 (see `AgentBrowserClient` and
 * `src-tauri/src/agent_browser.rs`). Each `HeadlessBrowser` instance owns one
 * persistent subprocess for the hunt's lifetime; `navigateAndAnalyze` and
 * `analyzeDOMXSS` each ask the subprocess for a *fresh* BrowserContext so
 * XBOW's "victim-goto" isolation is preserved.
 *
 * Public API (class name, methods, return shapes) is unchanged so
 * `src/core/validation/validator.ts` and other call sites keep working.
 */

import { AgentBrowserClient } from '../engine/agent_browser_client';
import type { ValidationEvidence } from './validator';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface HeadlessBrowserConfig {
  /** Path to Chrome/Chromium executable (resolved inside the subprocess) */
  chromePath?: string;
  /** Navigation timeout in ms */
  timeout?: number;
  /** Whether to run in headless mode (subprocess always runs headless — kept for API compat) */
  headless?: boolean;
  /** Window size (subprocess uses 1920x1080 — kept for API compat) */
  windowSize?: { width: number; height: number };
  /** User agent string (not currently forwarded — kept for API compat) */
  userAgent?: string;
}

export interface BrowserResult {
  success: boolean;
  finalUrl: string;
  title: string;
  dialogDetected: boolean;
  dialogMessage?: string;
  consoleLogs: ConsoleEntry[];
  networkRequests: NetworkRequest[];
  cookies: CookieInfo[];
  screenshotBase64?: string;
  domAnalysis?: DOMAnalysis;
  pageSource?: string;
  error?: string;
}

export interface ConsoleEntry {
  level: 'log' | 'warn' | 'error' | 'info';
  text: string;
  timestamp: number;
}

export interface NetworkRequest {
  url: string;
  method: string;
  statusCode?: number;
  contentType?: string;
  referrer?: string;
  leaksTokens: boolean;
}

export interface CookieInfo {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string;
}

export interface DOMAnalysis {
  innerHtmlUsage: number;
  evalUsage: number;
  postMessageHandlers: number;
  locationReferences: number;
  formsWithoutCsrf: number;
  inlineEventHandlers: number;
}

// ─── Headless Browser Controller ─────────────────────────────────────────────

let validatorSessionCounter = 0;

export class HeadlessBrowser {
  private config: Required<Pick<HeadlessBrowserConfig, 'timeout' | 'headless' | 'windowSize'>> & HeadlessBrowserConfig;
  private client: AgentBrowserClient | null = null;

  constructor(config: HeadlessBrowserConfig) {
    this.config = {
      timeout: 15_000,
      headless: true,
      windowSize: { width: 1920, height: 1080 },
      ...config,
    };
  }

  /** Returns the underlying IPC client once `launch()` has run; null otherwise.
   *  The accessor is preserved for callers that only need to check
   *  "has this browser started yet?" — the historical Playwright `Browser`
   *  handle is no longer exposed. */
  getBrowser(): AgentBrowserClient | null {
    return this.client;
  }

  /** Lazy-spawn the Node subprocess. Idempotent. */
  async launch(): Promise<void> {
    if (this.client) return;
    const sessionKey = `validator_${Date.now()}_${validatorSessionCounter++}`;
    this.client = new AgentBrowserClient(sessionKey);
  }

  /** Terminate the subprocess. Safe to call multiple times. */
  async close(): Promise<void> {
    if (!this.client) return;
    const c = this.client;
    this.client = null;
    await c.close();
  }

  /**
   * Navigate to a URL in a fresh BrowserContext (inside the subprocess)
   * and capture dialog/console/request/cookie/DOM/screenshot evidence.
   */
  async navigateAndAnalyze(url: string): Promise<BrowserResult> {
    await this.launch();
    const raw = await this.client!.validatorAnalyze(url, this.config.timeout);

    return {
      success: raw.success,
      finalUrl: raw.finalUrl,
      title: raw.title,
      dialogDetected: raw.dialogDetected,
      dialogMessage: raw.dialogMessage,
      consoleLogs: raw.consoleLogs.map(c => ({
        level: c.level,
        text: c.text,
        timestamp: c.timestamp,
      })),
      networkRequests: raw.networkRequests.map(n => ({
        url: n.url,
        method: n.method,
        referrer: n.referrer,
        leaksTokens: n.leaksTokens,
      })),
      cookies: raw.cookies.map(c => ({
        name: c.name,
        value: c.value,
        domain: c.domain,
        path: c.path,
        secure: c.secure,
        httpOnly: c.httpOnly,
        sameSite: c.sameSite ?? '',
      })),
      screenshotBase64: raw.screenshotBase64,
      domAnalysis: raw.domAnalysis,
      pageSource: raw.pageSource,
      error: raw.error,
    };
  }

  /**
   * Validate an XSS finding by navigating and scoring dialog/console/OOB evidence.
   */
  async validateXSS(
    url: string,
    marker: string,
    oobChecker?: () => boolean,
  ): Promise<{ confirmed: boolean; confidence: number; evidence: ValidationEvidence[] }> {
    const evidence: ValidationEvidence[] = [];
    let confidence = 0;

    const result = await this.navigateAndAnalyze(url);

    if (result.dialogDetected && result.dialogMessage?.includes(marker)) {
      confidence += 50;
      evidence.push({
        type: 'script_output',
        description: `JavaScript dialog fired with marker: "${result.dialogMessage}"`,
        data: `Dialog detected on URL: ${url}\nMarker matched: ${marker}`,
        timestamp: Date.now(),
      });
    }

    const markerInConsole = result.consoleLogs.some(l => l.text.includes(marker));
    if (markerInConsole) {
      confidence += 30;
      evidence.push({
        type: 'script_output',
        description: 'XSS marker found in console output',
        data: result.consoleLogs.filter(l => l.text.includes(marker))
          .map(l => `[${l.level}] ${l.text}`).join('\n'),
        timestamp: Date.now(),
      });
    }

    if (oobChecker?.()) {
      confidence += 40;
      evidence.push({
        type: 'callback',
        description: 'OOB beacon received — confirms JavaScript execution in victim context',
        data: `OOB callback triggered for marker: ${marker}`,
        timestamp: Date.now(),
      });
    }

    if (result.screenshotBase64) {
      evidence.push({
        type: 'screenshot',
        description: 'Browser screenshot after XSS payload navigation',
        data: `data:image/png;base64,${result.screenshotBase64.substring(0, 200)}...`,
        timestamp: Date.now(),
      });
    }

    return {
      confirmed: confidence >= 50,
      confidence,
      evidence,
    };
  }

  /**
   * Validate stored XSS by navigating to the rendering (victim) page.
   */
  async validateStoredXSS(
    renderUrl: string,
    marker: string,
    oobChecker?: () => boolean,
  ): Promise<{ confirmed: boolean; confidence: number; evidence: ValidationEvidence[] }> {
    return this.validateXSS(renderUrl, marker, oobChecker);
  }

  /**
   * Sink/source scan for DOM-XSS. Uses a fresh subprocess context.
   */
  async analyzeDOMXSS(url: string): Promise<{
    sinks: string[];
    sources: string[];
    hasDangerousFlow: boolean;
    evidence: ValidationEvidence[];
  }> {
    await this.launch();
    const raw = await this.client!.validatorDomXss(url, this.config.timeout);

    const hasDangerousFlow = raw.sinks.length > 0 && raw.sources.length > 0;
    const evidence: ValidationEvidence[] = [];

    if (raw.sinks.length > 0 || raw.sources.length > 0) {
      evidence.push({
        type: 'script_output',
        description: 'DOM XSS sink/source analysis (live page)',
        data: `Sinks: ${raw.sinks.join(', ') || 'none'}\nSources: ${raw.sources.join(', ') || 'none'}\nDangerous source→sink flow: ${hasDangerousFlow ? 'YES' : 'no'}`,
        timestamp: Date.now(),
      });
    }

    return {
      sinks: raw.sinks,
      sources: raw.sources,
      hasDangerousFlow,
      evidence,
    };
  }
}

export default HeadlessBrowser;

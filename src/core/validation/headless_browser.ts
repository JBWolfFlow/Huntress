/**
 * Headless Browser Integration — Playwright Edition
 *
 * Full Playwright-based headless browser for deterministic validation of
 * client-side vulnerabilities. Replaces the Chrome CDP implementation with
 * playwright-core (uses system-installed Chromium, no bundled browser).
 *
 * Implements XBOW's "victim-goto" pattern:
 * - Fresh BrowserContext per validation (clean isolation)
 * - Event listeners set BEFORE navigation (dialog, console, request)
 * - Unique marker matching for XSS confirmation
 * - Screenshot + DOM capture for evidence
 * - page.evaluate() for in-page JS sink/source analysis
 * - 2-second post-navigation wait for deferred JS payloads
 */

import { chromium } from 'playwright-core';
import type { Browser, Page, Dialog, ConsoleMessage, Request } from 'playwright-core';
import type { ValidationEvidence } from './validator';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface HeadlessBrowserConfig {
  /** Path to Chrome/Chromium executable */
  chromePath?: string;
  /** Navigation timeout in ms */
  timeout?: number;
  /** Whether to run in headless mode */
  headless?: boolean;
  /** Window size */
  windowSize?: { width: number; height: number };
  /** User agent string */
  userAgent?: string;
}

export interface BrowserResult {
  /** Whether the page loaded successfully */
  success: boolean;
  /** Final URL after any redirects */
  finalUrl: string;
  /** Page title */
  title: string;
  /** Whether an alert/confirm/prompt dialog appeared */
  dialogDetected: boolean;
  /** Dialog message content if detected */
  dialogMessage?: string;
  /** Console log entries */
  consoleLogs: ConsoleEntry[];
  /** Network requests made by the page */
  networkRequests: NetworkRequest[];
  /** Cookies set by the page */
  cookies: CookieInfo[];
  /** Screenshot as base64-encoded PNG */
  screenshotBase64?: string;
  /** DOM analysis results */
  domAnalysis?: DOMAnalysis;
  /** Raw page HTML */
  pageSource?: string;
  /** Error message if navigation failed */
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
  /** Whether this request leaked tokens in URL/headers */
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
  /** Elements using innerHTML */
  innerHtmlUsage: number;
  /** Elements using eval-like functions */
  evalUsage: number;
  /** postMessage handlers found */
  postMessageHandlers: number;
  /** document.location references */
  locationReferences: number;
  /** Forms without CSRF tokens */
  formsWithoutCsrf: number;
  /** Inline event handlers */
  inlineEventHandlers: number;
}

// ─── System Browser Detection ────────────────────────────────────────────────

const SYSTEM_CHROME_PATHS = [
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/snap/bin/chromium',
  '/usr/bin/brave-browser',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
];

async function findSystemChrome(): Promise<string | undefined> {
  const { fs: bridgeFs } = await import('../tauri_bridge');
  for (const p of SYSTEM_CHROME_PATHS) {
    try {
      await bridgeFs.access(p);
      return p;
    } catch {
      // Path not accessible — try next
    }
  }
  return undefined;
}

// ─── Headless Browser Controller ─────────────────────────────────────────────

export class HeadlessBrowser {
  private config: Required<Pick<HeadlessBrowserConfig, 'timeout' | 'headless' | 'windowSize'>> & HeadlessBrowserConfig;
  private browser: Browser | null = null;

  constructor(config: HeadlessBrowserConfig) {
    this.config = {
      timeout: 15_000,
      headless: true,
      windowSize: { width: 1920, height: 1080 },
      ...config,
    };
  }

  /** Get the underlying Playwright browser instance (must call launch() first) */
  getBrowser(): Browser | null {
    return this.browser;
  }

  /** Launch the shared browser instance (reused across validations) */
  async launch(): Promise<void> {
    if (this.browser) return;

    const executablePath = this.config.chromePath ?? await findSystemChrome();
    if (!executablePath) {
      throw new Error(
        'Chrome/Chromium not found. Install with: apt install chromium\n' +
        `Searched: ${SYSTEM_CHROME_PATHS.join(', ')}`
      );
    }

    this.browser = await chromium.launch({
      executablePath,
      headless: this.config.headless,
      args: [
        '--no-sandbox',
        '--disable-gpu',
        '--disable-dev-shm-usage',
        '--disable-extensions',
      ],
    });
  }

  /** Close the browser instance */
  async close(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
  }

  /**
   * Navigate to a URL in a fresh context and capture everything.
   * Fresh BrowserContext per call ensures complete isolation.
   */
  async navigateAndAnalyze(url: string): Promise<BrowserResult> {
    await this.launch();

    const consoleLogs: ConsoleEntry[] = [];
    const networkRequests: NetworkRequest[] = [];
    let dialogDetected = false;
    let dialogMessage: string | undefined;

    const context = await this.browser!.newContext({
      viewport: this.config.windowSize,
      userAgent: this.config.userAgent,
      ignoreHTTPSErrors: true,
    });

    try {
      const page = await context.newPage();

      // ── Set up event listeners BEFORE navigation ──

      // Dialog detection (alert/confirm/prompt)
      page.on('dialog', async (dialog: Dialog) => {
        dialogDetected = true;
        dialogMessage = dialog.message();
        await dialog.dismiss();
      });

      // Console capture
      page.on('console', (msg: ConsoleMessage) => {
        const level = msg.type();
        consoleLogs.push({
          level: (['log', 'warn', 'error', 'info'].includes(level) ? level : 'log') as ConsoleEntry['level'],
          text: msg.text(),
          timestamp: Date.now(),
        });
      });

      // Network request tracking
      page.on('request', (request: Request) => {
        const reqUrl = request.url();
        const tokenPatterns = /[?&](token|key|secret|api_key|access_token|auth|session)=/i;
        networkRequests.push({
          url: reqUrl,
          method: request.method(),
          referrer: request.headers()['referer'] ?? '',
          leaksTokens: tokenPatterns.test(reqUrl),
        });
      });

      // ── Navigate ──
      let success = true;
      let error: string | undefined;
      try {
        await page.goto(url, {
          waitUntil: 'domcontentloaded',
          timeout: this.config.timeout,
        });
      } catch (navError) {
        success = false;
        error = navError instanceof Error ? navError.message : String(navError);
      }

      // 2-second post-navigation wait for deferred JS payloads
      await page.waitForTimeout(2000);

      // ── Capture results ──
      const finalUrl = page.url();
      const title = await page.title().catch(() => '');
      const pageSource = await page.content().catch(() => '');

      // Screenshot as base64
      let screenshotBase64: string | undefined;
      try {
        const buffer = await page.screenshot({ type: 'png', fullPage: false });
        screenshotBase64 = buffer.toString('base64');
      } catch {
        // Screenshot failed — non-critical
      }

      // DOM analysis via page.evaluate()
      const domAnalysis = await this.analyzeDomInPage(page);

      // Cookies
      const rawCookies = await context.cookies();
      const cookies: CookieInfo[] = rawCookies.map(c => ({
        name: c.name,
        value: c.value,
        domain: c.domain,
        path: c.path,
        secure: c.secure,
        httpOnly: c.httpOnly,
        sameSite: c.sameSite,
      }));

      return {
        success,
        finalUrl,
        title,
        dialogDetected,
        dialogMessage,
        consoleLogs,
        networkRequests,
        cookies,
        screenshotBase64,
        domAnalysis,
        pageSource: pageSource.substring(0, 50_000),
        error,
      };
    } finally {
      await context.close();
    }
  }

  /**
   * Validate an XSS finding by navigating to the crafted URL and detecting
   * JavaScript execution via dialog, console, or OOB beacon.
   *
   * @param url The crafted URL with XSS payload
   * @param marker A unique marker string to match in dialogs/console (e.g., HUNTRESS_XSS_a1b2c3d4)
   * @param oobChecker Optional function to check if an OOB beacon was received
   */
  async validateXSS(
    url: string,
    marker: string,
    oobChecker?: () => boolean,
  ): Promise<{ confirmed: boolean; confidence: number; evidence: ValidationEvidence[] }> {
    const evidence: ValidationEvidence[] = [];
    let confidence = 0;

    const result = await this.navigateAndAnalyze(url);

    // Check for dialog with exact marker match
    if (result.dialogDetected && result.dialogMessage?.includes(marker)) {
      confidence += 50;
      evidence.push({
        type: 'script_output',
        description: `JavaScript dialog fired with marker: "${result.dialogMessage}"`,
        data: `Dialog detected on URL: ${url}\nMarker matched: ${marker}`,
        timestamp: Date.now(),
      });
    }

    // Check console for marker
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

    // Check OOB beacon
    if (oobChecker?.()) {
      confidence += 40;
      evidence.push({
        type: 'callback',
        description: 'OOB beacon received — confirms JavaScript execution in victim context',
        data: `OOB callback triggered for marker: ${marker}`,
        timestamp: Date.now(),
      });
    }

    // Add screenshot evidence
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
   * Validate stored XSS by navigating to the rendering page (victim context).
   *
   * @param renderUrl The URL where the stored payload renders (not the injection URL)
   * @param marker The unique marker injected during the attack phase
   * @param oobChecker Optional OOB callback checker
   */
  async validateStoredXSS(
    renderUrl: string,
    marker: string,
    oobChecker?: () => boolean,
  ): Promise<{ confirmed: boolean; confidence: number; evidence: ValidationEvidence[] }> {
    // Stored XSS uses the same detection logic but navigates to the *rendering* page
    return this.validateXSS(renderUrl, marker, oobChecker);
  }

  /**
   * Analyze a page for DOM-based XSS sinks and sources using page.evaluate().
   * Runs inside the live page context for accurate detection.
   */
  async analyzeDOMXSS(url: string): Promise<{
    sinks: string[];
    sources: string[];
    hasDangerousFlow: boolean;
    evidence: ValidationEvidence[];
  }> {
    await this.launch();

    const context = await this.browser!.newContext({
      viewport: this.config.windowSize,
      ignoreHTTPSErrors: true,
    });

    try {
      const page = await context.newPage();

      await page.goto(url, {
        waitUntil: 'domcontentloaded',
        timeout: this.config.timeout,
      }).catch(() => {});

      await page.waitForTimeout(2000);

      // Run sink/source analysis inside the live page
      const analysis = await page.evaluate(() => {
        const sinks: string[] = [];
        const sources: string[] = [];

        // Grab all script text content
        const scripts = Array.from(document.querySelectorAll('script'));
        const scriptText = scripts.map(s => s.textContent ?? '').join('\n');
        const allText = scriptText + '\n' + document.documentElement.outerHTML;

        // Sinks
        const sinkPatterns: Array<[RegExp, string]> = [
          [/\.innerHTML\s*=/g, 'innerHTML assignment'],
          [/\.outerHTML\s*=/g, 'outerHTML assignment'],
          [/document\.write\s*\(/g, 'document.write()'],
          [/document\.writeln\s*\(/g, 'document.writeln()'],
          [/eval\s*\(/g, 'eval()'],
          [/setTimeout\s*\(\s*['"]/g, 'setTimeout() with string'],
          [/setInterval\s*\(\s*['"]/g, 'setInterval() with string'],
          [/new\s+Function\s*\(/g, 'new Function()'],
          [/\.insertAdjacentHTML\s*\(/g, 'insertAdjacentHTML()'],
          [/jQuery\s*\(\s*['"]<|\.html\s*\(/g, 'jQuery HTML injection'],
        ];

        // Sources
        const sourcePatterns: Array<[RegExp, string]> = [
          [/document\.location/g, 'document.location'],
          [/document\.URL/g, 'document.URL'],
          [/document\.referrer/g, 'document.referrer'],
          [/location\.hash/g, 'location.hash'],
          [/location\.search/g, 'location.search'],
          [/location\.href/g, 'location.href'],
          [/window\.name/g, 'window.name'],
          [/addEventListener\s*\(\s*['"]message['"]/g, 'postMessage handler'],
          [/URLSearchParams/g, 'URLSearchParams'],
        ];

        for (const [pattern, name] of sinkPatterns) {
          const matches = allText.match(pattern);
          if (matches) sinks.push(`${name} (${matches.length}x)`);
        }

        for (const [pattern, name] of sourcePatterns) {
          const matches = allText.match(pattern);
          if (matches) sources.push(`${name} (${matches.length}x)`);
        }

        return { sinks, sources };
      });

      const hasDangerousFlow = analysis.sinks.length > 0 && analysis.sources.length > 0;
      const evidence: ValidationEvidence[] = [];

      if (analysis.sinks.length > 0 || analysis.sources.length > 0) {
        evidence.push({
          type: 'script_output',
          description: 'DOM XSS sink/source analysis (live page)',
          data: `Sinks: ${analysis.sinks.join(', ') || 'none'}\nSources: ${analysis.sources.join(', ') || 'none'}\nDangerous source→sink flow: ${hasDangerousFlow ? 'YES' : 'no'}`,
          timestamp: Date.now(),
        });
      }

      return {
        sinks: analysis.sinks,
        sources: analysis.sources,
        hasDangerousFlow,
        evidence,
      };
    } finally {
      await context.close();
    }
  }

  /** Run DOM analysis inside a live page via page.evaluate() */
  private async analyzeDomInPage(page: Page): Promise<DOMAnalysis> {
    try {
      return await page.evaluate(() => {
        const html = document.documentElement.outerHTML;
        const scripts = Array.from(document.querySelectorAll('script'));
        const allText = scripts.map(s => s.textContent ?? '').join('\n') + '\n' + html;

        const forms = Array.from(document.querySelectorAll('form'));
        const formsWithoutCsrf = forms.filter(form => {
          const formHtml = form.outerHTML.toLowerCase();
          return !formHtml.includes('csrf') &&
                 !formHtml.includes('_token') &&
                 !formHtml.includes('authenticity_token');
        }).length;

        return {
          innerHtmlUsage: (allText.match(/\.innerHTML\s*=/g) ?? []).length,
          evalUsage: (allText.match(/eval\s*\(/g) ?? []).length,
          postMessageHandlers: (allText.match(/addEventListener\s*\(\s*['"]message['"]/g) ?? []).length,
          locationReferences: (allText.match(/document\.location|window\.location/g) ?? []).length,
          formsWithoutCsrf,
          inlineEventHandlers: (html.match(/\son\w+\s*=/g) ?? []).length,
        };
      });
    } catch {
      return {
        innerHtmlUsage: 0,
        evalUsage: 0,
        postMessageHandlers: 0,
        locationReferences: 0,
        formsWithoutCsrf: 0,
        inlineEventHandlers: 0,
      };
    }
  }
}

export default HeadlessBrowser;

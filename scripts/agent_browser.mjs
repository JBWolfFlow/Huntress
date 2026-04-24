#!/usr/bin/env node
/**
 * Agent Browser — Long-lived Node.js subprocess (I2)
 *
 * Runs Playwright in a proper Node.js process because Tauri's WebView
 * cannot resolve `playwright-core` imports. Keeps a single browser +
 * context + page alive across many tool calls from the same ReAct loop.
 *
 * Protocol: newline-delimited JSON over stdin/stdout.
 *   Request:  {"id":"r1","action":"navigate","url":"...","waitMs":2000}
 *   Response: {"id":"r1","ok":true,"data":{...}}  |  {"id":"r1","ok":false,"error":"..."}
 *
 * Actions:
 *   navigate             { url, waitMs? }              -> { url, title, content, dialogs, consoleLogs }
 *   evaluate             { expression }                -> { value }  |  { error }
 *   click                { selector, waitMs? }         -> { url, title, dialogs, consoleLogs }
 *   fill                 { selector, value, waitMs? }  -> { filled: true, selector }
 *   get_content          { includeCookies? }           -> { url, title, content, cookies? }
 *   start_auth_capture   { scopeDomains: string[] }    -> { captureStarted: true }
 *   finish_auth_capture  {}                            -> CapturedAuth-shaped payload
 *   validator_analyze    { url, timeoutMs? }           -> BrowserResult-shaped payload (fresh context)
 *   validator_dom_xss    { url, timeoutMs? }           -> { sinks, sources } (fresh context)
 *   close                {}                            -> { ok: true }  (exits process)
 *
 * evaluate runs the expression inside the Chromium renderer sandbox (via
 * page.evaluate + eval). This is isolated from the Node host process. The
 * same pattern is used elsewhere in this repo for DOM-XSS sink detection.
 *
 * Non-JSON status lines are written to stderr and ignored by the caller.
 */

import { chromium } from 'playwright-core';
import { existsSync } from 'fs';
import readline from 'readline';

const MAX_PAGE_CONTENT = 50_000;
const MAX_EVAL_RESULT = 10_000;

// Headers we treat as auth material. Mirrors scripts/auth_capture.mjs so the
// CapturedAuth payload shape is consistent regardless of capture mechanism.
const AUTH_HEADER_NAMES = new Set([
  'authorization',
  'x-api-key',
  'x-csrf-token',
  'x-xsrf-token',
  'wallet-authorization',
  'x-access-token',
  'x-auth-token',
  'x-session-token',
]);

// Auth-capture state. Active only between start_auth_capture / finish_auth_capture.
let authCaptureActive = false;
let authScopeDomains = new Set();
let authCapturedHeaders = new Map();

function findChrome() {
  const paths = [
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/snap/bin/chromium',
  ];
  for (const p of paths) {
    if (existsSync(p)) return p;
  }
  return null;
}

let browser = null;
let context = null;
let page = null;
let dialogs = [];
let consoleLogs = [];

async function ensurePage() {
  if (page && !page.isClosed()) return page;

  if (!browser) {
    const executablePath = findChrome();
    if (!executablePath) {
      throw new Error('Chrome/Chromium not found. Install with: apt install chromium');
    }
    browser = await chromium.launch({
      executablePath,
      headless: true,
      args: ['--no-sandbox', '--disable-blink-features=AutomationControlled'],
    });
  }

  if (!context) {
    context = await browser.newContext({
      viewport: { width: 1920, height: 1080 },
      ignoreHTTPSErrors: true,
    });
  }

  page = await context.newPage();
  page.on('dialog', async (dialog) => {
    dialogs.push({ message: dialog.message(), type: dialog.type() });
    await dialog.dismiss().catch(() => {});
  });
  page.on('console', (msg) => {
    const level = msg.type();
    consoleLogs.push({
      level: ['log', 'warn', 'error', 'info'].includes(level) ? level : 'log',
      text: msg.text(),
    });
  });

  return page;
}

async function doNavigate(req) {
  const p = await ensurePage();
  dialogs = [];
  consoleLogs = [];
  await p.goto(req.url, { waitUntil: 'domcontentloaded', timeout: 15_000 });
  const waitMs = Math.min(Math.max(req.waitMs ?? 2000, 0), 10_000);
  await p.waitForTimeout(waitMs);
  const url = p.url();
  const title = await p.title().catch(() => '');
  const content = await p.content().catch(() => '');
  return {
    url,
    title,
    content: content.length > MAX_PAGE_CONTENT
      ? content.substring(0, MAX_PAGE_CONTENT) + `\n\n[PAGE CONTENT TRUNCATED — ${content.length} bytes total]`
      : content,
    contentLength: content.length,
    dialogs: dialogs.slice(),
    consoleLogs: consoleLogs.slice(-20),
  };
}

async function doEvaluate(req) {
  if (!page || page.isClosed()) {
    throw new Error('No browser page active. Use navigate first.');
  }
  // Evaluate inside the Chromium renderer (browser sandbox), not Node host.
  // Required for DOM-XSS and prototype pollution testing.
  const result = await page.evaluate((expr) => {
    try {
      // eslint-disable-next-line no-eval
      const value = (0, eval)(expr);
      return { ok: true, value: JSON.stringify(value, null, 2) };
    } catch (e) {
      return { ok: false, error: String(e) };
    }
  }, req.expression);

  if (!result.ok) return { error: result.error, dialogs: dialogs.slice() };

  const value = (result.value?.length ?? 0) > MAX_EVAL_RESULT
    ? result.value.substring(0, MAX_EVAL_RESULT) + '\n[TRUNCATED]'
    : result.value;
  return { value: value ?? 'undefined', dialogs: dialogs.slice() };
}

async function doClick(req) {
  if (!page || page.isClosed()) {
    throw new Error('No browser page active. Use navigate first.');
  }
  dialogs = [];
  consoleLogs = [];
  await page.click(req.selector, { timeout: 5_000 });
  const waitMs = Math.min(Math.max(req.waitMs ?? 2000, 0), 10_000);
  await page.waitForTimeout(waitMs);
  const url = page.url();
  const title = await page.title().catch(() => '');
  return {
    url,
    title,
    dialogs: dialogs.slice(),
    consoleLogs: consoleLogs.slice(-10),
  };
}

async function doStartAuthCapture(req) {
  if (!Array.isArray(req.scopeDomains) || req.scopeDomains.length === 0) {
    throw new Error('start_auth_capture requires scopeDomains: string[]');
  }
  const p = await ensurePage();
  authScopeDomains = new Set(req.scopeDomains.map(d => String(d).trim().toLowerCase()).filter(Boolean));
  authCapturedHeaders = new Map();
  if (authCaptureActive) {
    // Already capturing — reset headers and scope, re-arm the route handler.
    try { await p.unroute('**/*'); } catch { /* ignore */ }
  }
  authCaptureActive = true;
  await p.route('**/*', async (route) => {
    const request = route.request();
    let hostname = '';
    try {
      hostname = new URL(request.url()).hostname.toLowerCase();
    } catch {
      await route.continue();
      return;
    }
    const inScope = authScopeDomains.has(hostname)
      || [...authScopeDomains].some(d => hostname.endsWith(`.${d}`));
    if (inScope) {
      const headers = request.headers();
      for (const [key, value] of Object.entries(headers)) {
        if (AUTH_HEADER_NAMES.has(key.toLowerCase())) {
          authCapturedHeaders.set(key, value);
        }
      }
    }
    await route.continue();
  });
  return { captureStarted: true, scopeDomains: [...authScopeDomains] };
}

async function doFinishAuthCapture() {
  if (!authCaptureActive) {
    throw new Error('finish_auth_capture called but capture was never started. Call start_auth_capture first.');
  }
  if (!page || page.isClosed()) {
    authCaptureActive = false;
    throw new Error('No browser page active — cannot read storage. Was the page closed before capture finished?');
  }

  // Stop intercepting before reading storage so route handler can't race.
  try { await page.unroute('**/*'); } catch { /* ignore */ }

  // Cookies — only keep in-scope ones.
  const cookies = [];
  try {
    const allCookies = context ? await context.cookies() : [];
    for (const c of allCookies) {
      const bareDomain = c.domain.replace(/^\./, '').toLowerCase();
      const inScope = authScopeDomains.has(bareDomain)
        || [...authScopeDomains].some(d => c.domain.endsWith(`.${d}`) || c.domain === `.${d}`);
      if (inScope) {
        cookies.push({
          name: c.name,
          value: c.value,
          domain: c.domain,
          path: c.path,
          httpOnly: c.httpOnly,
          secure: c.secure,
        });
      }
    }
  } catch { /* ignore — return what we have */ }

  // localStorage + sessionStorage — from the active page origin.
  let localStorage = {};
  let sessionStorage = {};
  try {
    localStorage = await page.evaluate(() => {
      const items = {};
      for (let i = 0; i < window.localStorage.length; i++) {
        const k = window.localStorage.key(i);
        if (k) items[k] = window.localStorage.getItem(k) || '';
      }
      return items;
    });
    sessionStorage = await page.evaluate(() => {
      const items = {};
      for (let i = 0; i < window.sessionStorage.length; i++) {
        const k = window.sessionStorage.key(i);
        if (k) items[k] = window.sessionStorage.getItem(k) || '';
      }
      return items;
    });
  } catch { /* page navigated away or CSP blocked — return what we have */ }

  // Split out Authorization into bearerToken, everything else into customHeaders.
  const customHeaders = {};
  let bearerToken;
  for (const [key, value] of authCapturedHeaders) {
    if (key.toLowerCase() === 'authorization') {
      bearerToken = value.replace(/^Bearer\s+/i, '');
    } else {
      customHeaders[key] = value;
    }
  }

  const finalUrl = page.url();

  // Reset capture state — safe to start a fresh capture afterward.
  authCaptureActive = false;
  authCapturedHeaders = new Map();

  return {
    bearerToken,
    cookies,
    customHeaders,
    finalUrl,
    localStorage,
    sessionStorage,
  };
}

async function doFill(req) {
  if (!page || page.isClosed()) {
    throw new Error('No browser page active. Use navigate first.');
  }
  if (typeof req.selector !== 'string' || !req.selector) {
    throw new Error('fill requires a string selector');
  }
  if (typeof req.value !== 'string') {
    throw new Error('fill requires a string value');
  }
  // page.fill() dispatches input/change/blur synthetic events — required for
  // React/Vue/Angular-controlled inputs. Setting .value directly via evaluate()
  // won't update framework state.
  await page.fill(req.selector, req.value, { timeout: 5_000 });
  const waitMs = Math.min(Math.max(req.waitMs ?? 0, 0), 10_000);
  if (waitMs > 0) await page.waitForTimeout(waitMs);
  return { filled: true, selector: req.selector };
}

async function doGetContent(req) {
  if (!page || page.isClosed()) {
    throw new Error('No browser page active. Use navigate first.');
  }
  const url = page.url();
  const title = await page.title().catch(() => '');
  const content = await page.content().catch(() => '');
  const out = {
    url,
    title,
    content: content.length > MAX_PAGE_CONTENT
      ? content.substring(0, MAX_PAGE_CONTENT) + `\n\n[CONTENT TRUNCATED — ${content.length} bytes total]`
      : content,
    contentLength: content.length,
  };
  if (req.includeCookies && context) {
    out.cookies = await context.cookies();
  }
  return out;
}

async function doValidatorAnalyze(req) {
  if (typeof req.url !== 'string' || !req.url) {
    throw new Error('validator_analyze requires a string url');
  }
  if (!browser) {
    const executablePath = findChrome();
    if (!executablePath) {
      throw new Error('Chrome/Chromium not found. Install with: apt install chromium');
    }
    browser = await chromium.launch({
      executablePath,
      headless: true,
      args: ['--no-sandbox', '--disable-blink-features=AutomationControlled'],
    });
  }

  // Fresh context per call — victim-goto isolation. Never reuses the
  // shared `context`/`page` used by agent tool actions above.
  const timeoutMs = Math.min(Math.max(req.timeoutMs ?? 15_000, 1_000), 60_000);
  const analysisContext = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    ignoreHTTPSErrors: true,
  });

  const localConsole = [];
  const localRequests = [];
  let localDialogDetected = false;
  let localDialogMessage;
  let success = true;
  let error;

  try {
    const p = await analysisContext.newPage();

    p.on('dialog', async (d) => {
      localDialogDetected = true;
      localDialogMessage = d.message();
      await d.dismiss().catch(() => {});
    });
    p.on('console', (msg) => {
      const level = msg.type();
      localConsole.push({
        level: ['log', 'warn', 'error', 'info'].includes(level) ? level : 'log',
        text: msg.text(),
        timestamp: Date.now(),
      });
    });
    p.on('request', (request) => {
      const reqUrl = request.url();
      const tokenPatterns = /[?&](token|key|secret|api_key|access_token|auth|session)=/i;
      localRequests.push({
        url: reqUrl,
        method: request.method(),
        referrer: request.headers()['referer'] ?? '',
        leaksTokens: tokenPatterns.test(reqUrl),
      });
    });

    try {
      await p.goto(req.url, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    } catch (navErr) {
      success = false;
      error = navErr instanceof Error ? navErr.message : String(navErr);
    }

    await p.waitForTimeout(2000);

    const finalUrl = p.url();
    const title = await p.title().catch(() => '');
    const pageSource = (await p.content().catch(() => '')).substring(0, MAX_PAGE_CONTENT);

    let screenshotBase64;
    try {
      const buffer = await p.screenshot({ type: 'png', fullPage: false });
      screenshotBase64 = buffer.toString('base64');
    } catch {
      // Non-critical
    }

    const domAnalysis = await p.evaluate(() => {
      const html = document.documentElement.outerHTML;
      const scripts = Array.from(document.querySelectorAll('script'));
      const allText = scripts.map(s => s.textContent ?? '').join('\n') + '\n' + html;
      const forms = Array.from(document.querySelectorAll('form'));
      const formsWithoutCsrf = forms.filter(form => {
        const formHtml = form.outerHTML.toLowerCase();
        return !formHtml.includes('csrf')
          && !formHtml.includes('_token')
          && !formHtml.includes('authenticity_token');
      }).length;
      return {
        innerHtmlUsage: (allText.match(/\.innerHTML\s*=/g) ?? []).length,
        evalUsage: (allText.match(/eval\s*\(/g) ?? []).length,
        postMessageHandlers: (allText.match(/addEventListener\s*\(\s*['"]message['"]/g) ?? []).length,
        locationReferences: (allText.match(/document\.location|window\.location/g) ?? []).length,
        formsWithoutCsrf,
        inlineEventHandlers: (html.match(/\son\w+\s*=/g) ?? []).length,
      };
    }).catch(() => ({
      innerHtmlUsage: 0, evalUsage: 0, postMessageHandlers: 0,
      locationReferences: 0, formsWithoutCsrf: 0, inlineEventHandlers: 0,
    }));

    const rawCookies = await analysisContext.cookies().catch(() => []);
    const cookies = rawCookies.map(c => ({
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
      dialogDetected: localDialogDetected,
      dialogMessage: localDialogMessage,
      consoleLogs: localConsole,
      networkRequests: localRequests,
      cookies,
      screenshotBase64,
      domAnalysis,
      pageSource,
      error,
    };
  } finally {
    await analysisContext.close().catch(() => {});
  }
}

async function doValidatorDomXss(req) {
  if (typeof req.url !== 'string' || !req.url) {
    throw new Error('validator_dom_xss requires a string url');
  }
  if (!browser) {
    const executablePath = findChrome();
    if (!executablePath) {
      throw new Error('Chrome/Chromium not found. Install with: apt install chromium');
    }
    browser = await chromium.launch({
      executablePath,
      headless: true,
      args: ['--no-sandbox', '--disable-blink-features=AutomationControlled'],
    });
  }

  const timeoutMs = Math.min(Math.max(req.timeoutMs ?? 15_000, 1_000), 60_000);
  const analysisContext = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    ignoreHTTPSErrors: true,
  });

  try {
    const p = await analysisContext.newPage();
    await p.goto(req.url, { waitUntil: 'domcontentloaded', timeout: timeoutMs }).catch(() => {});
    await p.waitForTimeout(2000);

    const analysis = await p.evaluate(() => {
      const sinks = [];
      const sources = [];
      const scripts = Array.from(document.querySelectorAll('script'));
      const scriptText = scripts.map(s => s.textContent ?? '').join('\n');
      const allText = scriptText + '\n' + document.documentElement.outerHTML;

      const sinkPatterns = [
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
      const sourcePatterns = [
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
    }).catch(() => ({ sinks: [], sources: [] }));

    return { sinks: analysis.sinks, sources: analysis.sources };
  } finally {
    await analysisContext.close().catch(() => {});
  }
}

async function handle(request) {
  switch (request.action) {
    case 'navigate':             return doNavigate(request);
    case 'evaluate':             return doEvaluate(request);
    case 'click':                return doClick(request);
    case 'fill':                 return doFill(request);
    case 'get_content':          return doGetContent(request);
    case 'start_auth_capture':   return doStartAuthCapture(request);
    case 'finish_auth_capture':  return doFinishAuthCapture();
    case 'validator_analyze':    return doValidatorAnalyze(request);
    case 'validator_dom_xss':    return doValidatorDomXss(request);
    case 'close':
      await shutdown();
      return { closed: true };
    default:
      throw new Error(`Unknown action: ${request.action}`);
  }
}

async function shutdown() {
  try { if (context) await context.close(); } catch { /* ignore */ }
  try { if (browser) await browser.close(); } catch { /* ignore */ }
  context = null;
  browser = null;
  page = null;
  authCaptureActive = false;
  authScopeDomains = new Set();
  authCapturedHeaders = new Map();
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', async (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let request;
  try {
    request = JSON.parse(trimmed);
  } catch (e) {
    process.stdout.write(JSON.stringify({ id: null, ok: false, error: `Invalid JSON: ${e.message}` }) + '\n');
    return;
  }

  const id = request.id ?? null;
  try {
    const data = await handle(request);
    process.stdout.write(JSON.stringify({ id, ok: true, data }) + '\n');
    if (request.action === 'close') {
      process.exit(0);
    }
  } catch (err) {
    process.stdout.write(JSON.stringify({ id, ok: false, error: err.message || String(err) }) + '\n');
  }
});

rl.on('close', async () => {
  await shutdown();
  process.exit(0);
});

process.stderr.write('STATUS:ready\n');

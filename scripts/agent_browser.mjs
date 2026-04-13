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

async function handle(request) {
  switch (request.action) {
    case 'navigate':             return doNavigate(request);
    case 'evaluate':             return doEvaluate(request);
    case 'click':                return doClick(request);
    case 'fill':                 return doFill(request);
    case 'get_content':          return doGetContent(request);
    case 'start_auth_capture':   return doStartAuthCapture(request);
    case 'finish_auth_capture':  return doFinishAuthCapture();
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

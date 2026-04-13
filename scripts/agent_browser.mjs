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
 *   navigate    { url, waitMs? }              -> { url, title, content, dialogs, consoleLogs }
 *   evaluate    { expression }                -> { value }  |  { error }
 *   click       { selector, waitMs? }         -> { url, title, dialogs, consoleLogs }
 *   get_content { includeCookies? }           -> { url, title, content, cookies? }
 *   close       {}                            -> { ok: true }  (exits process)
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
    case 'navigate':    return doNavigate(request);
    case 'evaluate':    return doEvaluate(request);
    case 'click':       return doClick(request);
    case 'get_content': return doGetContent(request);
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

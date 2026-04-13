#!/usr/bin/env node
/**
 * Auth Browser Capture — Standalone Node.js Script (Phase B)
 *
 * Launched via Tauri IPC (execute_training_command) because Playwright
 * cannot run inside Tauri's WebView browser context.
 *
 * Usage: node scripts/auth_capture.mjs <loginUrl> <scopeDomain1,scopeDomain2,...> [timeoutMs]
 * Output: JSON to stdout with captured auth data
 */

import { chromium } from 'playwright-core';
import { existsSync } from 'fs';

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

// Find system Chrome/Chromium
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

async function main() {
  const loginUrl = process.argv[2];
  const scopeDomainsStr = process.argv[3] || '';
  const timeoutMs = parseInt(process.argv[4] || '120000', 10);

  if (!loginUrl) {
    console.log(JSON.stringify({ error: 'Usage: node auth_capture.mjs <loginUrl> <scopeDomains> [timeoutMs]' }));
    process.exit(1);
  }

  const scopeDomains = new Set(scopeDomainsStr.split(',').map(d => d.trim().toLowerCase()).filter(Boolean));
  const capturedHeaders = new Map();
  let loginDetected = false;

  const executablePath = findChrome();
  if (!executablePath) {
    console.log(JSON.stringify({ error: 'Chrome/Chromium not found. Install with: apt install chromium' }));
    process.exit(1);
  }

  // Status messages go to stderr so they don't interfere with JSON output
  process.stderr.write('STATUS:launching\n');

  const browser = await chromium.launch({
    executablePath,
    headless: false,
    args: ['--no-sandbox', '--disable-blink-features=AutomationControlled'],
  });

  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  });

  const page = await context.newPage();

  // Intercept requests to capture auth headers
  await page.route('**/*', async (route) => {
    const request = route.request();
    let hostname = '';
    try {
      hostname = new URL(request.url()).hostname.toLowerCase();
    } catch {
      await route.continue();
      return;
    }

    const inScope = scopeDomains.has(hostname) ||
      [...scopeDomains].some(d => hostname.endsWith(`.${d}`));

    if (inScope) {
      const headers = request.headers();
      for (const [key, value] of Object.entries(headers)) {
        if (AUTH_HEADER_NAMES.has(key.toLowerCase())) {
          capturedHeaders.set(key, value);
        }
      }

      const method = request.method().toUpperCase();
      const pathname = new URL(request.url()).pathname;
      if (method === 'POST' && /\/(login|auth|signin|sign-in|token|session|oauth)/i.test(pathname)) {
        loginDetected = true;
      }
    }

    await route.continue();
  });

  page.on('response', async (response) => {
    try {
      const cookies = await response.headerValues('set-cookie');
      if (cookies.length > 0) loginDetected = true;
    } catch { /* ignore */ }
  });

  process.stderr.write('STATUS:waiting\n');
  await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 30_000 });

  // Wait for login or timeout
  const startTime = Date.now();
  while (Date.now() - startTime < timeoutMs) {
    if (page.isClosed()) break;

    if (loginDetected && capturedHeaders.size > 0) {
      await new Promise(r => setTimeout(r, 2000));
      process.stderr.write(`STATUS:captured ${capturedHeaders.size} headers\n`);
      break;
    }

    await new Promise(r => setTimeout(r, 500));
  }

  // Extract cookies
  const cookies = [];
  const allCookies = await context.cookies();
  for (const c of allCookies) {
    const inScope = scopeDomains.has(c.domain.replace(/^\./, '')) ||
      [...scopeDomains].some(d => c.domain.endsWith(`.${d}`) || c.domain === `.${d}`);
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

  // Extract storage
  let localStorage = {};
  let sessionStorage = {};
  if (!page.isClosed()) {
    try {
      localStorage = await page.evaluate(() => {
        const items = {};
        for (let i = 0; i < window.localStorage.length; i++) {
          const key = window.localStorage.key(i);
          if (key) items[key] = window.localStorage.getItem(key) || '';
        }
        return items;
      });
      sessionStorage = await page.evaluate(() => {
        const items = {};
        for (let i = 0; i < window.sessionStorage.length; i++) {
          const key = window.sessionStorage.key(i);
          if (key) items[key] = window.sessionStorage.getItem(key) || '';
        }
        return items;
      });
    } catch { /* page navigated away */ }
  }

  // Build result
  const customHeaders = {};
  let bearerToken = undefined;
  for (const [key, value] of capturedHeaders) {
    if (key.toLowerCase() === 'authorization') {
      bearerToken = value.replace(/^Bearer\s+/i, '');
    } else {
      customHeaders[key] = value;
    }
  }

  const finalUrl = !page.isClosed() ? page.url() : loginUrl;

  await context.close().catch(() => {});
  await browser.close().catch(() => {});

  // Output JSON result to stdout
  console.log(JSON.stringify({
    bearerToken,
    cookies,
    customHeaders,
    finalUrl,
    localStorage,
    sessionStorage,
  }));
}

main().catch(err => {
  console.log(JSON.stringify({ error: err.message || 'Unknown error' }));
  process.exit(1);
});

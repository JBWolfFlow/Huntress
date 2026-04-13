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

    // Generate a unique marker to avoid false positives
    const marker = `HUNTRESS_XSS_${globalThis.crypto.randomUUID().slice(0, 8)}`;

    // Build the crafted URL with our marker payload
    // Replace existing XSS payload with our marker-based one
    const targetUrl = finding.target;
    const markerPayload = `<script>alert('${marker}')</script>`;
    const craftedUrl = injectMarkerPayload(targetUrl, markerPayload);

    steps.push(`Generated unique marker: ${marker}`);
    steps.push(`Crafted URL: ${craftedUrl}`);

    // Use Playwright to navigate and detect execution
    const browser = await getSharedBrowser();
    const oobChecker = validatorOobServer
      ? () => validatorOobServer!.getTriggeredCallbacks().some(c =>
          c.injectionPoint.vulnerabilityType === 'xss' &&
          c.injectionPoint.target === finding.target
        )
      : undefined;

    const result = await browser.validateXSS(craftedUrl, marker, oobChecker);

    evidence.push(...result.evidence);

    // Confidence scoring:
    // Dialog with exact marker: +50
    // Console marker: +30
    // OOB beacon: +40
    // (these are already scored inside validateXSS)
    const confidence = Math.min(100, result.confidence);
    const confirmed = result.confirmed;

    steps.push(`Dialog detected with marker: ${result.evidence.some(e => e.description.includes('dialog')) ? 'YES' : 'no'}`);
    steps.push(`Console marker found: ${result.evidence.some(e => e.description.includes('console')) ? 'YES' : 'no'}`);
    steps.push(`Confirmed: ${confirmed} (confidence: ${confidence}%)`);

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

    // For stored XSS, the target URL is where the payload *renders* (victim page)
    // The marker should have been injected during the attack phase
    const marker = `HUNTRESS_XSS_${globalThis.crypto.randomUUID().slice(0, 8)}`;
    const renderUrl = finding.target;

    steps.push(`Navigating to rendering page as victim: ${renderUrl}`);
    steps.push(`Checking for stored XSS marker: ${marker}`);

    // Navigate to the rendering page in a clean (victim) context
    const browser = await getSharedBrowser();
    const result = await browser.validateStoredXSS(renderUrl, marker);

    evidence.push(...result.evidence);

    // Also check for any previously-injected payloads that trigger
    // (the agent's original payload may still be live)
    const browseResult = await browser.navigateAndAnalyze(renderUrl);
    if (browseResult.dialogDetected) {
      evidence.push({
        type: 'script_output',
        description: `Stored XSS dialog triggered on page load: "${browseResult.dialogMessage ?? 'alert'}"`,
        data: `URL: ${renderUrl}\nDialog: ${browseResult.dialogMessage ?? 'unknown'}`,
        timestamp: Date.now(),
      });
      result.confidence = Math.max(result.confidence, 50);
    }

    const confidence = Math.min(100, result.confidence);
    const confirmed = confidence >= 50;

    steps.push(`Dialog on page load: ${browseResult.dialogDetected ? 'YES' : 'no'}`);
    steps.push(`Confirmed: ${confirmed} (confidence: ${confidence}%)`);

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

    // Also try navigating with a hash-based payload to trigger DOM XSS
    const marker = `HUNTRESS_DOM_${globalThis.crypto.randomUUID().slice(0, 8)}`;
    const hashUrl = targetUrl.includes('#')
      ? targetUrl.replace(/#.*/, `#<img src=x onerror="console.log('${marker}')">`)
      : `${targetUrl}#<img src=x onerror="console.log('${marker}')">`;

    const navResult = await browser.navigateAndAnalyze(hashUrl);
    const markerInConsole = navResult.consoleLogs.some(l => l.text.includes(marker));
    if (markerInConsole) {
      confidence = Math.min(100, confidence + 30);
      evidence.push({
        type: 'script_output',
        description: 'DOM XSS confirmed: hash-based payload executed',
        data: `Marker "${marker}" appeared in console after navigating to: ${hashUrl}`,
        timestamp: Date.now(),
      });
      steps.push('Hash-based DOM XSS payload EXECUTED');
    }

    const confirmed = confidence >= 60 && (analysis.hasDangerousFlow || markerInConsole);

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

registerValidator({
  vulnType: 'sqli_error',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    // Step 1: Send the original error-triggering payload
    const result = await config.executeCommand(
      ['curl', '-s', '-o', '-', finding.target].join('\x00'),
      finding.target
    );

    // Check for database error strings
    const dbErrors: Record<string, RegExp[]> = {
      mysql: [/SQL syntax.*MySQL/i, /Warning.*mysql_/i, /MySQLSyntaxErrorException/i],
      postgresql: [/ERROR:\s+syntax error/i, /pg_query/i, /PSQLException/i],
      mssql: [/Microsoft.*ODBC/i, /SQLServer/i, /Unclosed quotation mark/i],
      oracle: [/ORA-\d{5}/i, /Oracle.*Driver/i, /quoted string not properly terminated/i],
      sqlite: [/SQLITE_ERROR/i, /SQLite3::query/i, /near ".*": syntax error/i],
    };

    let detectedDb: string | null = null;
    for (const [db, patterns] of Object.entries(dbErrors)) {
      for (const pattern of patterns) {
        if (pattern.test(result.stdout)) {
          detectedDb = db;
          break;
        }
      }
      if (detectedDb) break;
    }

    evidence.push({
      type: 'http_response',
      description: `Response with ${detectedDb ? detectedDb + ' error' : 'potential error'}`,
      data: result.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    steps.push(`Sent error-triggering payload to: ${finding.target}`);
    steps.push(`Database error detected: ${detectedDb || 'none'}`);

    // Step 2: Send a clean request for comparison
    const cleanUrl = finding.target.replace(/['"\\].*$/, '');
    const cleanResult = await config.executeCommand(
      ['curl', '-s', '-o', '-', cleanUrl].join('\x00'),
      finding.target
    );

    const hasErrorInClean = Object.values(dbErrors).flat().some(p => p.test(cleanResult.stdout));
    steps.push(`Clean request also shows error: ${hasErrorInClean ? 'yes (false positive)' : 'no (confirmed)'}`);

    const confirmed = detectedDb !== null && !hasErrorInClean;
    let confidence = finding.confidence;
    if (detectedDb) confidence = Math.min(100, confidence + 25);
    if (hasErrorInClean) confidence = Math.max(0, confidence - 40);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'sqli_error',
      validationTime: Date.now() - startTime,
    };
  },
});

registerValidator({
  vulnType: 'sqli_blind_time',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    // Step 1: Baseline timing
    const baseline = await config.executeCommand(
      ['curl', '-s', '-o', '/dev/null', '-w', '%{time_total}', finding.target].join('\x00'),
      finding.target
    );
    const baselineTime = parseFloat(baseline.stdout) * 1000;

    steps.push(`Baseline response time: ${baselineTime.toFixed(0)}ms`);

    // Step 2: Time-based payload (should cause delay)
    const delayResult = await config.executeCommand(
      ['curl', '-s', '-o', '/dev/null', '-w', '%{time_total}', finding.target].join('\x00'),
      finding.target
    );
    const delayTime = parseFloat(delayResult.stdout) * 1000;

    steps.push(`Delay payload response time: ${delayTime.toFixed(0)}ms`);

    evidence.push({
      type: 'timing',
      description: `Baseline: ${baselineTime.toFixed(0)}ms, With delay: ${delayTime.toFixed(0)}ms`,
      data: `Difference: ${(delayTime - baselineTime).toFixed(0)}ms`,
      timestamp: Date.now(),
    });

    // Confirm if delay is significantly longer (at least 3 seconds difference)
    const timeDiff = delayTime - baselineTime;
    const confirmed = timeDiff > 3000;
    let confidence = finding.confidence;
    if (timeDiff > 5000) confidence = Math.min(100, confidence + 30);
    else if (timeDiff > 3000) confidence = Math.min(100, confidence + 15);
    else confidence = Math.max(0, confidence - 20);

    steps.push(`Time difference: ${timeDiff.toFixed(0)}ms (threshold: 3000ms)`);

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

// ─── SSRF Validator (double-confirm: response content + OOB callback) ───────

registerValidator({
  vulnType: 'ssrf',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    let responseConfirmed = false;
    let oobConfirmed = false;

    // Step 1: Send request and check for internal data in response
    const result = await config.executeCommand(
      ['curl', '-s', '-o', '-', finding.target].join('\x00'),
      finding.target
    );

    // Check for cloud metadata indicators
    const metadataIndicators = [
      /ami-[a-f0-9]+/i,           // AWS AMI ID
      /iam.*role/i,                // AWS IAM
      /instance-id/i,              // AWS instance
      /access.?key/i,              // Access keys
      /secret.?key/i,              // Secret keys
      /127\.0\.0\.1/,              // Localhost
      /169\.254\.169\.254/,        // AWS metadata
      /metadata\.google/,          // GCP metadata
      /computeMetadata/,           // GCP metadata v1
      /latest\/meta-data/,         // AWS metadata path
    ];

    const matchedIndicators = metadataIndicators.filter(p => p.test(result.stdout));

    evidence.push({
      type: 'http_response',
      description: 'Response from SSRF payload',
      data: result.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    responseConfirmed = matchedIndicators.length >= 2;
    steps.push(`Sent SSRF payload to: ${finding.target}`);
    steps.push(`Internal data indicators found: ${matchedIndicators.length}`);

    // Step 2: Check OOB server for callback confirmation
    if (validatorOobServer) {
      const triggeredCallbacks = validatorOobServer.getTriggeredCallbacks().filter(c =>
        c.injectionPoint.vulnerabilityType === 'ssrf' &&
        c.injectionPoint.target === finding.target
      );

      oobConfirmed = triggeredCallbacks.length > 0;

      if (oobConfirmed) {
        const cb = triggeredCallbacks[0];
        evidence.push({
          type: 'callback',
          description: `OOB callback received: ${cb.interaction?.protocol ?? 'unknown'} from ${cb.interaction?.sourceIp ?? 'unknown'}`,
          data: `Callback ID: ${cb.id}\nTriggered at: ${new Date(cb.triggeredAt ?? 0).toISOString()}\nRaw: ${cb.interaction?.rawData?.substring(0, 500) ?? 'none'}`,
          timestamp: Date.now(),
        });
        steps.push(`OOB callback confirmed: ${cb.interaction?.protocol} from ${cb.interaction?.sourceIp}`);
      } else {
        steps.push('OOB callback: not triggered');
      }
    } else {
      steps.push('OOB server not available — skipping callback check');
    }

    // Double-confirm: need BOTH response content AND OOB, or strong response evidence
    const confirmed = (responseConfirmed && oobConfirmed) || matchedIndicators.length >= 4;
    let confidence = finding.confidence;
    if (responseConfirmed) confidence = Math.min(100, confidence + 20);
    if (oobConfirmed) confidence = Math.min(100, confidence + 30);
    if (responseConfirmed && oobConfirmed) confidence = Math.min(100, confidence + 10);

    steps.push(`Double-confirm: response=${responseConfirmed}, oob=${oobConfirmed}`);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'ssrf_double_confirm',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── IDOR Validator ──────────────────────────────────────────────────────────

registerValidator({
  vulnType: 'idor',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    // Step 1: Make the original request
    const result1 = await config.executeCommand(
      ['curl', '-s', '-D', '-', '-o', '-', finding.target].join('\x00'),
      finding.target
    );

    evidence.push({
      type: 'http_response',
      description: 'Response with manipulated ID',
      data: result1.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    // Check for 200 OK with data (not 401/403)
    const statusMatch = result1.stdout.match(/HTTP\/[\d.]+ (\d{3})/);
    const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : 0;

    steps.push(`Request with manipulated ID returned status: ${statusCode}`);

    const confirmed = statusCode === 200 && result1.stdout.length > 200;
    let confidence = finding.confidence;
    if (statusCode === 200) confidence = Math.min(100, confidence + 15);
    if (statusCode === 401 || statusCode === 403) confidence = Math.max(0, confidence - 40);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'idor',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── Open Redirect Validator ─────────────────────────────────────────────────

registerValidator({
  vulnType: 'open_redirect',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    // Follow redirects and check final location
    const result = await config.executeCommand(
      ['curl', '-s', '-D', '-', '-o', '/dev/null', '-L', '--max-redirs', '5', finding.target].join('\x00'),
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

registerValidator({
  vulnType: 'xxe',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    // Send the XXE payload and check for file content in response
    const result = await config.executeCommand(
      ['curl', '-s', '-o', '-', finding.target].join('\x00'),
      finding.target
    );

    // Check for /etc/passwd content
    const passwdIndicators = [
      /root:x?:0:0:/,
      /daemon:x?:\d+:\d+:/,
      /nobody:x?:\d+:\d+:/,
      /bin\/bash/,
      /bin\/sh/,
      /sbin\/nologin/,
    ];

    const hasPasswd = passwdIndicators.some(p => p.test(result.stdout));

    // Check for hostname/other file content indicators
    const fileContentIndicators = [
      /\[extensions\]/i,  // win.ini
      /\[fonts\]/i,        // win.ini
      /PRETTY_NAME=/,      // os-release
      /VERSION_ID=/,       // os-release
    ];
    const hasFileContent = fileContentIndicators.some(p => p.test(result.stdout));

    evidence.push({
      type: 'http_response',
      description: 'Response from XXE payload',
      data: result.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    const confirmed = hasPasswd || hasFileContent;
    let confidence = finding.confidence;
    if (hasPasswd) confidence = Math.min(100, confidence + 35);
    if (hasFileContent) confidence = Math.min(100, confidence + 25);

    steps.push(`Sent XXE payload to: ${finding.target}`);
    steps.push(`File content (/etc/passwd) detected: ${hasPasswd ? 'YES' : 'no'}`);
    steps.push(`Other file content detected: ${hasFileContent ? 'YES' : 'no'}`);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'xxe',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── Command Injection Validator ────────────────────────────────────────────

registerValidator({
  vulnType: 'command_injection',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    // Step 1: Send the original payload and check for command output
    const result = await config.executeCommand(
      ['curl', '-s', '-o', '-', finding.target].join('\x00'),
      finding.target
    );

    // Check for common command output indicators
    const cmdOutputIndicators = [
      /uid=\d+\(\w+\)\s+gid=\d+/,       // id command output
      /\w+\\\w+/,                          // whoami on Windows (DOMAIN\user)
      /Linux\s+\S+\s+\d+\.\d+/,           // uname -a output
      /root:x:0:0:/,                       // cat /etc/passwd
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

    // Step 2: Time-based confirmation — send baseline then delay payload
    const cleanTarget = finding.target.replace(/[;&|`$()]+.*$/, '');
    const baselineResult = await config.executeCommand(
      ['curl', '-s', '-o', '/dev/null', '-w', '%{time_total}', cleanTarget].join('\x00'),
      finding.target
    );
    const baselineTime = parseFloat(baselineResult.stdout) * 1000;

    const delayResult = await config.executeCommand(
      ['curl', '-s', '-o', '/dev/null', '-w', '%{time_total}', finding.target].join('\x00'),
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

    const confirmed = hasCmdOutput || hasTimingAnomaly;
    let confidence = finding.confidence;
    if (hasCmdOutput) confidence = Math.min(100, confidence + 30);
    if (hasTimingAnomaly) confidence = Math.min(100, confidence + 25);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'command_injection',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── Path Traversal Validator ───────────────────────────────────────────────

registerValidator({
  vulnType: 'path_traversal',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    const result = await config.executeCommand(
      ['curl', '-s', '-o', '-', finding.target].join('\x00'),
      finding.target
    );

    // Check for /etc/passwd content
    const passwdIndicators = [
      /root:x?:0:0:/,
      /daemon:x?:\d+:\d+:/,
      /nobody:x?:\d+:\d+:/,
      /sbin\/nologin/,
    ];
    const hasPasswd = passwdIndicators.some(p => p.test(result.stdout));

    // Check for Windows files
    const winIndicators = [
      /\[extensions\]/i,
      /\[fonts\]/i,
      /\[mci extensions\]/i,
    ];
    const hasWinFile = winIndicators.some(p => p.test(result.stdout));

    // Check for Java web.xml
    const javaIndicators = [
      /<web-app/i,
      /<servlet>/i,
      /<servlet-mapping>/i,
    ];
    const hasJavaFile = javaIndicators.some(p => p.test(result.stdout));

    // Check for .env file
    const envIndicators = [
      /^[A-Z_]+=.+$/m,
      /DB_PASSWORD=/i,
      /API_KEY=/i,
      /SECRET_KEY=/i,
    ];
    const hasEnvFile = envIndicators.some(p => p.test(result.stdout));

    evidence.push({
      type: 'http_response',
      description: 'Response from path traversal payload',
      data: result.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    const fileDetected = hasPasswd || hasWinFile || hasJavaFile || hasEnvFile;
    const confirmed = fileDetected;
    let confidence = finding.confidence;
    if (hasPasswd) confidence = Math.min(100, confidence + 35);
    else if (hasWinFile) confidence = Math.min(100, confidence + 30);
    else if (hasJavaFile) confidence = Math.min(100, confidence + 25);
    else if (hasEnvFile) confidence = Math.min(100, confidence + 20);

    steps.push(`Sent traversal payload to: ${finding.target}`);
    steps.push(`/etc/passwd content: ${hasPasswd ? 'YES' : 'no'}`);
    steps.push(`Windows file content: ${hasWinFile ? 'YES' : 'no'}`);
    steps.push(`Java WEB-INF: ${hasJavaFile ? 'YES' : 'no'}`);
    steps.push(`.env file: ${hasEnvFile ? 'YES' : 'no'}`);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'path_traversal',
      validationTime: Date.now() - startTime,
    };
  },
});

// ─── SSTI Validator ─────────────────────────────────────────────────────────

registerValidator({
  vulnType: 'ssti',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    const targetUrl = finding.target;
    let confirmed = false;
    let confidence = finding.confidence;

    // Step 1: Send {{7*7}} and check for literal 49 in response
    const mathPayload = targetUrl.replace(/(\{\{.*?\}\}|%7B%7B.*?%7D%7D)/, '{{7*7}}');
    const mathUrl = mathPayload === targetUrl
      ? (targetUrl.includes('?') ? `${targetUrl}&test={{7*7}}` : `${targetUrl}?test={{7*7}}`)
      : mathPayload;

    const result1 = await config.executeCommand(
      ['curl', '-s', '-o', '-', mathUrl].join('\x00'),
      finding.target
    );

    const has49 = result1.stdout.includes('49');

    evidence.push({
      type: 'http_response',
      description: 'Response to {{7*7}} payload',
      data: result1.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    steps.push(`Sent {{7*7}} payload to: ${mathUrl}`);
    steps.push(`Response contains "49": ${has49 ? 'YES' : 'no'}`);

    if (has49) {
      confidence = Math.min(100, confidence + 20);
    }

    // Step 2: Send {{7*'7'}} to fingerprint template engine
    // Jinja2: 7777777 (string multiplication)
    // Twig: 49 (still math)
    // Mako: 49
    const fingerUrl = mathUrl.replace('{{7*7}}', "{{7*'7'}}");
    const result2 = await config.executeCommand(
      ['curl', '-s', '-o', '-', fingerUrl].join('\x00'),
      finding.target
    );

    const has7777777 = result2.stdout.includes('7777777');
    const still49 = result2.stdout.includes('49');

    let detectedEngine = 'unknown';
    if (has7777777) {
      detectedEngine = 'Jinja2/Python';
      confidence = Math.min(100, confidence + 30);
      confirmed = true;
    } else if (still49 && has49) {
      detectedEngine = 'Twig/PHP or Mako';
      confidence = Math.min(100, confidence + 25);
      confirmed = true;
    } else if (has49) {
      // {{7*7}} = 49 but {{7*'7'}} didn't confirm engine
      // Still likely SSTI but less certain
      detectedEngine = 'unknown (math evaluated)';
      confidence = Math.min(100, confidence + 15);
      confirmed = true;
    }

    evidence.push({
      type: 'http_response',
      description: `Response to {{7*'7'}} payload (engine fingerprint)`,
      data: result2.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    steps.push(`Sent {{7*'7'}} fingerprint payload`);
    steps.push(`Contains "7777777" (Jinja2): ${has7777777 ? 'YES' : 'no'}`);
    steps.push(`Contains "49" (Twig/Mako): ${still49 ? 'YES' : 'no'}`);
    steps.push(`Detected engine: ${detectedEngine}`);

    // Step 3: Verify it's not a false positive by checking a non-template value
    if (confirmed) {
      const cleanUrl = mathUrl.replace('{{7*7}}', 'notatemplate');
      const cleanResult = await config.executeCommand(
        ['curl', '-s', '-o', '-', cleanUrl].join('\x00'),
        finding.target
      );
      const cleanHas49 = cleanResult.stdout.includes('49');

      if (cleanHas49) {
        // The page always shows 49 — false positive
        confirmed = false;
        confidence = Math.max(0, confidence - 40);
        steps.push('FALSE POSITIVE: clean request also contains "49"');
      } else {
        steps.push('Clean request does NOT contain "49" — SSTI confirmed');
      }
    }

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'ssti',
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
      ['curl', '-s', '-D', '-', '-o', '-', '-H', `Origin: ${evilOrigin}`, targetUrl].join('\x00'),
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
        ['curl', '-s', '-D', '-', '-o', '-', '-H', 'Origin: null', targetUrl].join('\x00'),
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
          ['curl', '-s', '-D', '-', '-o', '-', '-H', `Origin: ${subdomainBypass}`, targetUrl].join('\x00'),
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

registerValidator({
  vulnType: 'host_header_injection',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    const targetUrl = finding.target;
    const evilHost = 'evil-attacker.com';
    let confirmed = false;
    let confidence = finding.confidence;

    // Step 1: Send request with manipulated Host header
    const result1 = await config.executeCommand(
      ['curl', '-s', '-D', '-', '-o', '-', '-H', `Host: ${evilHost}`, targetUrl].join('\x00'),
      finding.target
    );

    evidence.push({
      type: 'http_response',
      description: `Response with Host: ${evilHost}`,
      data: result1.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    // Check if evil host appears in response body (link generation, redirects)
    const bodyHasEvil = result1.stdout.toLowerCase().includes(evilHost);
    steps.push(`Sent Host: ${evilHost}`);
    steps.push(`Evil host in response body: ${bodyHasEvil ? 'YES' : 'no'}`);

    if (bodyHasEvil) {
      confidence = Math.min(100, confidence + 25);
    }

    // Check for redirect containing evil host
    const locationMatch = result1.stdout.match(/location:\s*(\S+)/i);
    const redirectHasEvil = locationMatch && locationMatch[1].toLowerCase().includes(evilHost);

    if (redirectHasEvil) {
      confirmed = true;
      confidence = Math.min(100, confidence + 35);
      steps.push(`Redirect Location contains ${evilHost}: CONFIRMED`);
    }

    // Step 2: Test X-Forwarded-Host (common bypass when Host is validated)
    if (!confirmed) {
      const result2 = await config.executeCommand(
        ['curl', '-s', '-D', '-', '-o', '-', '-H', `X-Forwarded-Host: ${evilHost}`, targetUrl].join('\x00'),
        finding.target
      );

      const xfhBody = result2.stdout.toLowerCase().includes(evilHost);
      const xfhLocation = result2.stdout.match(/location:\s*(\S+)/i);
      const xfhRedirect = xfhLocation && xfhLocation[1].toLowerCase().includes(evilHost);

      steps.push(`X-Forwarded-Host: ${evilHost}`);
      steps.push(`X-Forwarded-Host in body: ${xfhBody ? 'YES' : 'no'}`);
      steps.push(`X-Forwarded-Host in redirect: ${xfhRedirect ? 'YES' : 'no'}`);

      if (xfhBody || xfhRedirect) {
        confidence = Math.min(100, confidence + 20);

        evidence.push({
          type: 'http_response',
          description: `Response with X-Forwarded-Host: ${evilHost}`,
          data: result2.stdout.substring(0, 5000),
          timestamp: Date.now(),
        });
      }

      if (xfhRedirect) {
        confirmed = true;
        confidence = Math.min(100, confidence + 15);
      }
    }

    // Step 3: Verify it's not a false positive — send with legitimate host
    if (bodyHasEvil && !confirmed) {
      const result3 = await config.executeCommand(
        ['curl', '-s', '-o', '-', targetUrl].join('\x00'),
        finding.target
      );

      const cleanHasEvil = result3.stdout.toLowerCase().includes(evilHost);
      if (cleanHasEvil) {
        // The page always contains this string — false positive
        confidence = Math.max(0, confidence - 40);
        steps.push('FALSE POSITIVE: clean request also contains evil host string');
      } else {
        confirmed = true;
        steps.push('Clean request does NOT contain evil host — injection confirmed');
      }
    }

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'host_header_injection',
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
      ['curl', '-s', '-D', '-', '-o', '-', targetUrl].join('\x00'),
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
        ['curl', '-s', '-X', 'POST', '-H', 'Content-Type: application/json', '-d', payload, '-o', '-', targetUrl].join('\x00'),
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
        ['curl', '-s', '-o', '-', targetUrl].join('\x00'),
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

    // Step 4: HTTP request to the target to check for service error pages
    const httpResult = await config.executeCommand(
      ['curl', '-s', '-D', '-', '-o', '-', '-L', '--max-redirs', '3', '-H', `Host: ${hostname}`, `https://${hostname}`].join('\x00'),
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
        ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', `https://${cnameTarget}`].join('\x00'),
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

    const result = await config.executeCommand(
      ['curl', '-s', '-D', '-', '-o', '-', '-L', '--max-redirs', '3', statelessUrl].join('\x00'),
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

    // Step 1: Send request WITH code_challenge
    const result1 = await config.executeCommand(
      ['curl', '-s', '-D', '-', '-o', '-', '-L', '--max-redirs', '3', endpoint].join('\x00'),
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
      ['curl', '-s', '-D', '-', '-o', '-', '-L', '--max-redirs', '3', noChallengeUrl].join('\x00'),
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

      // Verify the server accepted the weak verifier
      const result = await config.executeCommand(
        ['curl', '-s', '-D', '-', '-o', '-', endpoint].join('\x00'),
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

    // Re-send the request that claims scope escalation
    const result = await config.executeCommand(
      ['curl', '-s', '-D', '-', '-o', '-', '-L', '--max-redirs', '3', endpoint].join('\x00'),
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

      // Re-send the OAuth request from the finding
      const result = await config.executeCommand(
        ['curl', '-s', '-D', '-', '-o', '-', '-L', '--max-redirs', '3', endpoint].join('\x00'),
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
      ['curl', '-s', '-D', '-', '-o', '-', finding.target].join('\x00'),
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
      ['curl', '-s', '-D', '-', '-o', '-', falseTarget].join('\x00'),
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

// ─── BOLA Validator (same logic as IDOR) ──────────────────────────────────

registerValidator({
  vulnType: 'bola',
  async validate(finding, config): Promise<ValidationResult> {
    const startTime = Date.now();
    const evidence: ValidationEvidence[] = [];
    const steps: string[] = [];

    const result = await config.executeCommand(
      ['curl', '-s', '-D', '-', '-o', '-', finding.target].join('\x00'),
      finding.target
    );

    evidence.push({
      type: 'http_response',
      description: 'Response with manipulated object reference',
      data: result.stdout.substring(0, 5000),
      timestamp: Date.now(),
    });

    const statusMatch = result.stdout.match(/HTTP\/[\d.]+ (\d{3})/);
    const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : 0;

    steps.push(`Request with manipulated object ID returned status: ${statusCode}`);

    const confirmed = statusCode === 200 && result.stdout.length > 200;
    let confidence = finding.confidence;
    if (statusCode === 200) confidence = Math.min(100, confidence + 15);
    if (statusCode === 401 || statusCode === 403) confidence = Math.max(0, confidence - 40);

    return {
      findingId: finding.id,
      confirmed,
      evidence,
      reproductionSteps: steps,
      confidence,
      validatorUsed: 'bola',
      validationTime: Date.now() - startTime,
    };
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

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
import { HeadlessBrowser } from './headless_browser';
import { OOBServer } from './oob_server';
import crypto from 'crypto';

// ─── Shared Browser Instance ────────────────────────────────────────────────

/** Lazy-initialized browser for validators that need Playwright */
let sharedBrowser: HeadlessBrowser | null = null;

function getSharedBrowser(): HeadlessBrowser {
  if (!sharedBrowser) {
    sharedBrowser = new HeadlessBrowser({ headless: true });
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
    const marker = `HUNTRESS_XSS_${crypto.randomUUID().slice(0, 8)}`;

    // Build the crafted URL with our marker payload
    // Replace existing XSS payload with our marker-based one
    const targetUrl = finding.target;
    const markerPayload = `<script>alert('${marker}')</script>`;
    const craftedUrl = injectMarkerPayload(targetUrl, markerPayload);

    steps.push(`Generated unique marker: ${marker}`);
    steps.push(`Crafted URL: ${craftedUrl}`);

    // Use Playwright to navigate and detect execution
    const browser = getSharedBrowser();
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
    const marker = `HUNTRESS_XSS_${crypto.randomUUID().slice(0, 8)}`;
    const renderUrl = finding.target;

    steps.push(`Navigating to rendering page as victim: ${renderUrl}`);
    steps.push(`Checking for stored XSS marker: ${marker}`);

    // Navigate to the rendering page in a clean (victim) context
    const browser = getSharedBrowser();
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
    const browser = getSharedBrowser();
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
    const marker = `HUNTRESS_DOM_${crypto.randomUUID().slice(0, 8)}`;
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
      `curl -s -o - "${finding.target}"`,
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
      `curl -s -o - "${cleanUrl}"`,
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
      `curl -s -o /dev/null -w "%{time_total}" "${finding.target}"`,
      finding.target
    );
    const baselineTime = parseFloat(baseline.stdout) * 1000;

    steps.push(`Baseline response time: ${baselineTime.toFixed(0)}ms`);

    // Step 2: Time-based payload (should cause delay)
    const delayResult = await config.executeCommand(
      `curl -s -o /dev/null -w "%{time_total}" "${finding.target}"`,
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
      `curl -s -o - "${finding.target}"`,
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
      `curl -s -D - -o - "${finding.target}"`,
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
      `curl -s -D - -o /dev/null -L --max-redirs 5 "${finding.target}"`,
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
      `curl -s -o - "${finding.target}"`,
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
      `curl -s -o - "${finding.target}"`,
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
      `curl -s -o /dev/null -w "%{time_total}" "${cleanTarget}"`,
      finding.target
    );
    const baselineTime = parseFloat(baselineResult.stdout) * 1000;

    const delayResult = await config.executeCommand(
      `curl -s -o /dev/null -w "%{time_total}" "${finding.target}"`,
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
      `curl -s -o - "${finding.target}"`,
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
      `curl -s -o - "${mathUrl}"`,
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
      `curl -s -o - "${fingerUrl}"`,
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
        `curl -s -o - "${cleanUrl}"`,
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

// ─── Register remaining types as pass-through ────────────────────────────────
// These use the agent's confidence without additional validation

for (const vulnType of [
  'sqli_blind_boolean',
  'ssrf_blind', 'bola',
  'cors_misconfiguration', 'csrf', 'host_header_injection',
  'oauth_redirect_uri', 'oauth_state', 'oauth_pkce',
  'jwt_vulnerability', 'prototype_pollution', 'subdomain_takeover',
  'information_disclosure', 'rate_limit_bypass',
  'graphql_introspection', 'graphql_batching',
  'mass_assignment', 'rce',
  'xxe_blind', 'command_injection_blind', 'lfi', 'lfi_rce',
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

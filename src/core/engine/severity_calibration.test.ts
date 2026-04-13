/**
 * Severity Calibration Gate — Unit Tests (C2)
 *
 * Verifies that known over-escalation patterns are caught and corrected
 * before findings enter the pipeline. Each rule corresponds to a real
 * pattern observed in Hunt #10 or documented in H1 Core Ineligible list.
 */

import { describe, it, expect } from 'vitest';

// Import the static method via dynamic import to avoid Tauri deps
const { ReactLoop } = await import('./react_loop');
const check = ReactLoop.checkSeverityCalibration;

// ─── Rule 1: Preconnect/Link header reflection ≠ SSRF ──────────────────────

describe('Severity Calibration — preconnect reflection', () => {
  it('downgrades CRITICAL preconnect reflection to LOW', () => {
    const result = check(
      'critical', 'ssrf',
      'SSRF via preconnect header injection',
      'The server reflects user input in a Link preconnect header',
      ['Link: <https://evil.com>; rel=preconnect']
    );
    expect(result.correctedSeverity).toBe('low');
    expect(result.note).toContain('not SSRF');
  });

  it('downgrades HIGH link header reflection to LOW', () => {
    const result = check(
      'high', 'ssrf',
      'Link Header Injection in API Response',
      'User-controlled input reflected in Link header with rel="preconnect"',
      ['<https://attacker.com>; rel="preconnect"']
    );
    expect(result.correctedSeverity).toBe('low');
    expect(result.note).toContain('browser hint');
  });

  it('does NOT affect legitimate SSRF findings', () => {
    const result = check(
      'critical', 'ssrf',
      'SSRF to internal metadata service',
      'Server fetches attacker-controlled URL and returns AWS metadata',
      ['GET http://169.254.169.254/latest/meta-data/iam/security-credentials/']
    );
    expect(result.correctedSeverity).toBe('critical');
    expect(result.note).toBeNull();
  });
});

// ─── Rule 2: Information disclosure ─────────────────────────────────────────

describe('Severity Calibration — information disclosure', () => {
  it('downgrades CRITICAL info disclosure without credentials to MEDIUM', () => {
    const result = check(
      'critical', 'information_disclosure',
      'Stack Trace Exposed in Error Response',
      'Application returns full stack trace with internal paths',
      ['at com.example.internal.Handler.processRequest(Handler.java:42)']
    );
    expect(result.correctedSeverity).toBe('medium');
    expect(result.note).toContain('downgraded');
  });

  it('preserves HIGH info disclosure with credentials', () => {
    const result = check(
      'high', 'information_disclosure',
      'API Key Leaked in Debug Endpoint',
      'Debug endpoint exposes api_key in response body',
      ['{"api_key": "sk-live-xxxxx"}']
    );
    expect(result.correctedSeverity).toBe('high');
    expect(result.note).toBeNull();
  });

  it('preserves HIGH info disclosure with session tokens', () => {
    const result = check(
      'high', 'information_disclosure',
      'Session Token Exposure',
      'Session tokens exposed in public endpoint',
      ['session_id: abc123']
    );
    expect(result.correctedSeverity).toBe('high');
    expect(result.note).toBeNull();
  });
});

// ─── Rule 3: Self-XSS ──────────────────────────────────────────────────────

describe('Severity Calibration — self-XSS', () => {
  it('downgrades HIGH self-XSS to LOW', () => {
    const result = check(
      'high', 'xss_reflected',
      'Reflected XSS in Profile Settings',
      'Self-XSS in own account profile name field',
      ['<script>alert(1)</script>']
    );
    expect(result.correctedSeverity).toBe('low');
    expect(result.note).toContain('Self-XSS');
  });

  it('preserves HIGH for XSS affecting other users', () => {
    const result = check(
      'high', 'xss_stored',
      'Stored XSS in Comment Section',
      'Stored XSS that fires when other users view the comment',
      ['<img src=x onerror=alert(document.domain)>']
    );
    expect(result.correctedSeverity).toBe('high');
    expect(result.note).toBeNull();
  });
});

// ─── Rule 4: Missing security headers ───────────────────────────────────────

describe('Severity Calibration — missing headers', () => {
  it('downgrades MEDIUM missing headers to INFO', () => {
    const result = check(
      'medium', 'information_disclosure',
      'Missing X-Frame-Options Header',
      'The application does not set X-Frame-Options header',
      ['Response headers lack X-Frame-Options']
    );
    expect(result.correctedSeverity).toBe('info');
    expect(result.note).toContain('informational');
  });

  it('downgrades HSTS missing to INFO', () => {
    const result = check(
      'medium', 'information_disclosure',
      'HSTS Missing on Main Domain',
      'Strict-Transport-Security header not present',
      []
    );
    expect(result.correctedSeverity).toBe('info');
  });

  it('downgrades CSP missing to INFO', () => {
    const result = check(
      'high', 'information_disclosure',
      'Content-Security-Policy Not Configured',
      'CSP missing allows potential XSS exploitation',
      []
    );
    expect(result.correctedSeverity).toBe('info');
  });
});

// ─── Rule 5: Standalone open redirect ───────────────────────────────────────

describe('Severity Calibration — open redirect', () => {
  it('downgrades standalone open redirect to INFO', () => {
    const result = check(
      'medium', 'open_redirect',
      'Open Redirect in Login Return URL',
      'The returnUrl parameter allows redirection to any external domain',
      ['GET /login?returnUrl=https://evil.com → 302 https://evil.com']
    );
    expect(result.correctedSeverity).toBe('info');
    expect(result.note).toContain('core ineligible');
  });

  it('preserves MEDIUM when chained to OAuth', () => {
    const result = check(
      'medium', 'open_redirect',
      'Open Redirect Chained to OAuth Token Theft',
      'Open redirect in OAuth redirect_uri allows token theft via authorization code interception',
      ['GET /auth/callback?redirect_uri=https://evil.com → token leaked']
    );
    expect(result.correctedSeverity).toBe('medium');
    expect(result.note).toBeNull();
  });
});

// ─── Rule 6: Version disclosure ─────────────────────────────────────────────

describe('Severity Calibration — version disclosure', () => {
  it('downgrades version disclosure to INFO', () => {
    const result = check(
      'low', 'information_disclosure',
      'Server Version Disclosure in Headers',
      'Server: Apache/2.4.51 (Ubuntu)',
      ['Server: Apache/2.4.51']
    );
    expect(result.correctedSeverity).toBe('info');
    expect(result.note).toContain('informational');
  });

  it('downgrades technology disclosure to INFO', () => {
    const result = check(
      'medium', 'information_disclosure',
      'Technology Disclosure via X-Powered-By',
      'X-Powered-By header reveals Express.js framework',
      ['X-Powered-By: Express']
    );
    expect(result.correctedSeverity).toBe('info');
  });
});

// ─── Rule 7: CORS without proof ─────────────────────────────────────────────

describe('Severity Calibration — CORS misconfiguration', () => {
  it('downgrades HIGH CORS without theft proof to MEDIUM', () => {
    const result = check(
      'high', 'cors_misconfiguration',
      'CORS Allows Arbitrary Origins',
      'The server reflects the Origin header in Access-Control-Allow-Origin',
      ['Access-Control-Allow-Origin: https://evil.com', 'Access-Control-Allow-Credentials: true']
    );
    expect(result.correctedSeverity).toBe('medium');
    expect(result.note).toContain('credential-based');
  });

  it('preserves HIGH CORS with proven data theft', () => {
    const result = check(
      'high', 'cors_misconfiguration',
      'CORS Credential Theft PoC',
      'Cross-origin data stolen using withCredentials fetch from attacker page',
      ['fetch(url, {credentials: \'include\'}).then(r => r.json()).then(data => exfiltrate(data))']
    );
    expect(result.correctedSeverity).toBe('high');
    expect(result.note).toBeNull();
  });
});

// ─── No-op: correct severities pass through ─────────────────────────────────

describe('Severity Calibration — pass-through', () => {
  it('does not modify correctly calibrated findings', () => {
    const result = check(
      'high', 'sqli_error',
      'SQL Injection in Search Parameter',
      'Error-based SQL injection extracting database version',
      ['SQL error: You have an error in your SQL syntax', 'SELECT version() → MySQL 8.0.28']
    );
    expect(result.correctedSeverity).toBe('high');
    expect(result.note).toBeNull();
  });

  it('does not modify LOW severity findings', () => {
    const result = check(
      'low', 'information_disclosure',
      'Internal IP Address Disclosed',
      'X-Forwarded-For header reveals internal IP',
      ['10.0.0.42']
    );
    expect(result.correctedSeverity).toBe('low');
    expect(result.note).toBeNull();
  });

  it('does not modify INFO severity findings', () => {
    const result = check(
      'info', 'information_disclosure',
      'Server Banner Detected',
      'Server returns version banner',
      []
    );
    expect(result.correctedSeverity).toBe('info');
    expect(result.note).toBeNull();
  });
});

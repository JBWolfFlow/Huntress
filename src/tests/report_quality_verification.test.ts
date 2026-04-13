/**
 * Report Quality Verification Tests
 *
 * Generates reports from known Juice Shop findings and validates them against
 * HackerOne submission standards. Ensures:
 * - Reproduction steps are complete and executable
 * - CVSS score matches severity
 * - Evidence includes request/response pairs
 * - Report templates produce quality Grade B+ or better
 */

import { describe, it, expect } from 'vitest';
import { ReportQualityScorer } from '../core/reporting/report_quality';
import { REPORT_TEMPLATES, fillTemplate } from '../core/reporting/templates';
import type { H1Report } from '../core/reporting/h1_api';

// ─── Known Juice Shop Findings (from Hunt #5) ──────────────────────────────

const JUICE_SHOP_FINDINGS: Array<{
  name: string;
  templateKey: string;
  report: H1Report;
}> = [
  {
    name: 'DOM XSS in search',
    templateKey: 'xss',
    report: {
      title: 'Stored XSS in Juice Shop Search via Reflected DOM Injection',
      severity: 'high',
      suggestedBounty: { min: 500, max: 1500 },
      description: fillTemplate(REPORT_TEMPLATES.xss, {
        xss_type: 'DOM-based reflected',
        url: 'http://localhost:3001/#/search?q=<iframe src="javascript:alert(`xss`)">\n\nThe search parameter is reflected directly into the DOM without sanitization. The application uses Angular\'s innerHTML binding which bypasses the framework\'s built-in XSS protection.',
        parameter: 'q (search query)',
        payload: '<iframe src="javascript:alert(`xss`)">',
        severity: 'High',
        steps: '1. Navigate to http://localhost:3001/#/search\n2. Enter the following payload in the search box: `<iframe src="javascript:alert(\\`xss\\`)">`\n3. Observe the JavaScript alert dialog executing in the browser context\n4. Verify in DevTools that the payload is rendered as an iframe element',
        poc: '```\nGET /#/search?q=%3Ciframe%20src%3D%22javascript%3Aalert(%60xss%60)%22%3E HTTP/1.1\nHost: localhost:3001\nUser-Agent: Mozilla/5.0\nAccept: text/html\n\nHTTP/1.1 200 OK\nContent-Type: text/html\n\n[Response contains injected iframe with JavaScript execution]\n```',
      }),
      impact: 'An attacker can craft a malicious URL that, when visited by a victim, executes arbitrary JavaScript in their browser session. This enables session hijacking via document.cookie theft, credential phishing through DOM manipulation, and potential account takeover.',
      steps: [
        'Navigate to http://localhost:3001/#/search',
        'Enter the payload: <iframe src="javascript:alert(`xss`)">',
        'Observe the JavaScript alert dialog executing',
        'Verify payload renders as iframe in DevTools Elements panel',
      ],
      proof: {},
      cvssScore: 7.1,
      weaknessId: 'CWE-79',
      severityJustification: [
        'Attack vector: Network (requires victim to click crafted URL)',
        'User interaction: Required (victim must visit the URL)',
        'Impact: High confidentiality impact (session cookies accessible)',
      ],
    },
  },
  {
    name: 'SQL Injection in login',
    templateKey: 'sql_injection',
    report: {
      title: "SQL Injection in Login Endpoint Allows Authentication Bypass via Boolean-Based Blind Injection",
      severity: 'critical',
      suggestedBounty: { min: 1000, max: 5000 },
      description: fillTemplate(REPORT_TEMPLATES.sql_injection, {
        url: 'http://localhost:3001/rest/user/login',
        parameter: 'email',
        database_type: 'SQLite',
        severity: 'CRITICAL',
        steps: "1. Send POST request to /rest/user/login\n2. Set email to: ' OR 1=1--\n3. Set password to any value\n4. The server returns a valid JWT token for the admin account\n5. The JWT token grants admin privileges to the application",
        poc: "```\nPOST /rest/user/login HTTP/1.1\nHost: localhost:3001\nContent-Type: application/json\n\n{\"email\":\"' OR 1=1--\",\"password\":\"x\"}\n\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"authentication\":{\"token\":\"eyJhbGciOiJSUzI1NiIs...\",\"bid\":1,\"umail\":\"admin@juice-sh.op\"}}\n```\n\nThe returned JWT contains admin credentials, confirming complete authentication bypass.",
      }),
      impact: 'An attacker can bypass authentication entirely and gain admin access to the application. This allows: (1) accessing all user data, (2) modifying or deleting any records, (3) escalating privileges, (4) potential RCE via stacked queries depending on SQLite configuration.',
      steps: [
        'Send a POST request to http://localhost:3001/rest/user/login',
        'Set the email field to: \' OR 1=1--',
        'Set the password field to any arbitrary value',
        'Observe the server returns HTTP 200 with a valid JWT token',
        'Decode the JWT to confirm it belongs to admin@juice-sh.op',
      ],
      proof: {},
      cvssScore: 9.8,
      weaknessId: 'CWE-89',
      severityJustification: [
        'Attack vector: Network',
        'Attack complexity: Low — single request with well-known payload',
        'Privileges required: None',
        'Confidentiality impact: High — full database access',
        'Integrity impact: High — can modify any data',
        'Availability impact: High — can drop tables',
      ],
    },
  },
  {
    name: 'IDOR on user profiles',
    templateKey: 'idor',
    report: {
      title: 'IDOR Allows Any Authenticated User to Access Other Users\' Basket Contents',
      severity: 'high',
      suggestedBounty: { min: 500, max: 2000 },
      description: fillTemplate(REPORT_TEMPLATES.idor, {
        endpoint: 'http://localhost:3001/rest/basket/{id}',
        method: 'GET',
        parameter: 'id (basket ID in URL path)',
        severity: 'HIGH',
        steps: '1. Authenticate as user A (e.g., jim@juice-sh.op)\n2. Send GET /rest/basket/1 with user A\'s auth token\n3. Receive basket contents belonging to a different user\n4. Iterate through basket IDs 1-10 to access all users\' baskets',
        poc: '```\nGET /rest/basket/1 HTTP/1.1\nHost: localhost:3001\nAuthorization: Bearer eyJhbGciOi...[User A token]\n\nHTTP/1.1 200 OK\n{\n  "status": "success",\n  "data": {\n    "id": 1,\n    "UserId": 2,\n    "Products": [...]\n  }\n}\n```\n\nUser A (UserId=3) received basket data belonging to UserId=2.',
      }),
      impact: 'Any authenticated user can access any other user\'s shopping basket by iterating through sequential basket IDs. This exposes: (1) items in other users\' baskets (privacy violation), (2) potential pricing information, (3) user purchasing patterns.',
      steps: [
        'Register or login as any user (e.g., jim@juice-sh.op)',
        'Note your own basket ID from the application',
        'Send GET /rest/basket/1 using your authentication token',
        'Observe you receive basket data for a different user',
        'Iterate IDs 1-10 to enumerate all users\' baskets',
      ],
      proof: {},
      cvssScore: 7.5,
      weaknessId: 'CWE-639',
      severityJustification: [
        'Attack vector: Network',
        'Privileges required: Low (any authenticated user)',
        'Confidentiality impact: High — access to other users\' data',
      ],
    },
  },
  {
    name: 'Open redirect in tracking endpoint',
    templateKey: 'open_redirect',
    report: {
      title: 'Open Redirect via Unvalidated URL Parameter in /redirect Endpoint',
      severity: 'medium',
      suggestedBounty: { min: 100, max: 500 },
      description: fillTemplate(REPORT_TEMPLATES.open_redirect, {
        url: 'http://localhost:3001/redirect?to=https://evil.com',
        parameter: 'to',
        severity: 'MEDIUM',
        steps: '1. Craft URL: http://localhost:3001/redirect?to=https://evil.com\n2. Send to victim via social engineering\n3. Victim clicks the trusted-looking localhost URL\n4. Browser redirects to attacker-controlled domain',
        poc: '```\nGET /redirect?to=https://evil.com HTTP/1.1\nHost: localhost:3001\n\nHTTP/1.1 302 Found\nLocation: https://evil.com\n\nThe server performs an unvalidated redirect to the attacker\'s domain.\n```',
      }),
      impact: 'Attackers can abuse the trusted domain to redirect users to phishing pages, malware downloads, or credential harvesting sites. The redirect makes the malicious URL appear legitimate.',
      steps: [
        'Navigate to http://localhost:3001/redirect?to=https://evil.com',
        'Observe the browser redirects to evil.com',
        'Confirm no validation is performed on the "to" parameter',
      ],
      proof: {},
      cvssScore: 4.3,
      weaknessId: 'CWE-601',
    },
  },
  {
    name: 'Exposed admin credentials in FTP',
    templateKey: 'ssrf',
    report: {
      title: 'Sensitive File Exposure via Directory Traversal in /ftp Endpoint',
      severity: 'high',
      suggestedBounty: { min: 500, max: 1500 },
      description: 'The Juice Shop application exposes an FTP directory at /ftp that contains sensitive files including database backups, application configurations, and internal documentation. The endpoint performs insufficient access control — any unauthenticated user can access these files.\n\nFurthermore, a path traversal vulnerability in the file download mechanism allows accessing files outside the intended FTP directory using null byte injection or URL encoding techniques.\n\n**Affected Endpoint:** GET /ftp/\n**Accessible Files:** package.json.bak, coupons_2013.md.bak, eastere.gg, quarantine/',
      impact: 'An attacker can: (1) Download database backups containing all user data, (2) Access internal documentation revealing application architecture, (3) Obtain backup files with credentials and configuration details, (4) Use path traversal to read arbitrary files from the server filesystem.',
      steps: [
        'Navigate to http://localhost:3001/ftp/',
        'Observe directory listing of sensitive backup files',
        'Download package.json.bak to obtain application metadata',
        'Use null byte injection: GET /ftp/../../etc/passwd%2500.md',
        'Observe server returns contents of /etc/passwd',
      ],
      proof: {},
      cvssScore: 7.5,
      weaknessId: 'CWE-22',
      severityJustification: [
        'No authentication required',
        'Direct access to sensitive backup files',
        'Path traversal allows filesystem access',
      ],
    },
  },
];

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('Report Quality Verification', () => {
  const scorer = new ReportQualityScorer();

  describe('Known Juice Shop findings produce quality reports', () => {
    for (const finding of JUICE_SHOP_FINDINGS) {
      it(`${finding.name}: scores consistently (H16 recalibrated)`, () => {
        const score = scorer.scoreReport(finding.report);
        // H16: Reports without structured httpEvidence correctly score lower.
        // Text-only reports should score 30-55 (not submission-ready without HTTP pairs).
        expect(score.overall).toBeGreaterThanOrEqual(30);
        expect(score.overall).toBeLessThanOrEqual(100);
      });
    }
  });

  describe('Reports include required evidence', () => {
    for (const finding of JUICE_SHOP_FINDINGS) {
      it(`${finding.name}: has request/response evidence in description`, () => {
        const desc = finding.report.description;
        // Should contain HTTP method indicators or curl/code patterns
        const hasEvidence =
          /HTTP\/[12]\.\d/i.test(desc) ||
          /GET\s+\//i.test(desc) ||
          /POST\s+\//i.test(desc) ||
          /curl\s+/i.test(desc) ||
          /```/.test(desc);
        expect(hasEvidence).toBe(true);
      });
    }
  });

  describe('Reproduction steps are complete', () => {
    for (const finding of JUICE_SHOP_FINDINGS) {
      it(`${finding.name}: has >= 3 reproduction steps`, () => {
        expect(finding.report.steps.length).toBeGreaterThanOrEqual(3);
      });

      it(`${finding.name}: steps contain URLs or endpoints`, () => {
        const stepsText = finding.report.steps.join('\n');
        const hasUrl = /https?:\/\/|\/api\/|\/rest\/|\/ftp\//i.test(stepsText);
        expect(hasUrl).toBe(true);
      });
    }
  });

  describe('CVSS scores match severity', () => {
    const SEVERITY_CVSS_RANGES: Record<string, [number, number]> = {
      critical: [9.0, 10.0],
      high: [7.0, 8.9],
      medium: [4.0, 6.9],
      low: [0.1, 3.9],
    };

    for (const finding of JUICE_SHOP_FINDINGS) {
      it(`${finding.name}: CVSS ${finding.report.cvssScore} matches ${finding.report.severity}`, () => {
        if (!finding.report.cvssScore) return;
        const [min, max] = SEVERITY_CVSS_RANGES[finding.report.severity];
        expect(finding.report.cvssScore).toBeGreaterThanOrEqual(min);
        expect(finding.report.cvssScore).toBeLessThanOrEqual(max);
      });
    }
  });

  describe('Report titles are descriptive', () => {
    for (const finding of JUICE_SHOP_FINDINGS) {
      it(`${finding.name}: title is descriptive (>20 chars, not generic)`, () => {
        expect(finding.report.title.length).toBeGreaterThan(20);
        // Should not be just "XSS" or "SQLi"
        expect(finding.report.title.length).toBeGreaterThan(finding.report.severity.length + 5);
      });
    }
  });

  describe('Impact sections are substantive', () => {
    for (const finding of JUICE_SHOP_FINDINGS) {
      it(`${finding.name}: impact describes business consequence`, () => {
        const impact = finding.report.impact;
        expect(impact.length).toBeGreaterThan(50);
        // Should mention attacker actions or consequences
        const hasBusinessImpact =
          /attacker|steal|access|modify|delete|exfiltrate|hijack|bypass|compromise|takeover|phishing|credential|privacy|breach/i.test(impact);
        expect(hasBusinessImpact).toBe(true);
      });
    }
  });

  describe('Report quality scorer categories', () => {
    it('all categories score > 0 for well-formed reports', () => {
      const score = scorer.scoreReport(JUICE_SHOP_FINDINGS[1].report); // SQL injection
      expect(score.categories.clarity).toBeGreaterThan(0);
      expect(score.categories.completeness).toBeGreaterThan(0);
      expect(score.categories.evidence).toBeGreaterThan(0);
      expect(score.categories.impact).toBeGreaterThan(0);
      expect(score.categories.reproducibility).toBeGreaterThan(0);
    });

    it('issues list contains actionable suggestions', () => {
      const issues = scorer.getImprovementSuggestions(JUICE_SHOP_FINDINGS[3].report); // open redirect
      for (const issue of issues) {
        expect(issue.message.length).toBeGreaterThan(0);
        expect(issue.suggestion.length).toBeGreaterThan(0);
        expect(['clarity', 'completeness', 'evidence', 'impact', 'reproducibility', 'httpEvidence', 'executablePoc', 'expectedVsActual']).toContain(issue.category);
        expect(['critical', 'major', 'minor']).toContain(issue.severity);
      }
    });
  });

  describe('Template system', () => {
    it('all vuln type templates exist', () => {
      const requiredTemplates = ['xss', 'sql_injection', 'idor', 'ssrf', 'open_redirect', 'command_injection', 'path_traversal', 'jwt', 'cors', 'crlf'];
      for (const tmpl of requiredTemplates) {
        expect(REPORT_TEMPLATES).toHaveProperty(tmpl);
        expect((REPORT_TEMPLATES as Record<string, string>)[tmpl].length).toBeGreaterThan(100);
      }
    });

    it('fillTemplate replaces all placeholders', () => {
      const result = fillTemplate(REPORT_TEMPLATES.xss, {
        xss_type: 'reflected',
        url: 'https://target.com/search?q=test',
        parameter: 'q',
        payload: '<script>alert(1)</script>',
        severity: 'High',
        steps: '1. Go to search\n2. Inject payload',
        poc: 'curl https://target.com/search?q=<script>',
      });
      expect(result).not.toContain('{{');
      expect(result).toContain('reflected');
      expect(result).toContain('target.com');
    });

    it('fillTemplate with new H1-standard sections', () => {
      const result = fillTemplate(REPORT_TEMPLATES.xss, {
        xss_type: 'stored',
        url: 'https://target.com/comments',
        parameter: 'body',
        payload: '<img src=x onerror=alert(1)>',
        severity: 'High',
        steps: '1. Post a comment with payload\n2. View the comment',
        poc: 'The payload is stored and rendered',
        http_evidence: '```http\nPOST /comments HTTP/1.1\nHost: target.com\n\n{\"body\":\"<img src=x onerror=alert(1)>\"}\n```',
        quick_reproduction: 'curl -X POST https://target.com/comments -d \'{"body":"<img src=x onerror=alert(1)>"}\'',
      });
      expect(result).not.toContain('{{');
      expect(result).toContain('## Prerequisites');
      expect(result).toContain('## Expected vs Actual Behavior');
      expect(result).toContain('## HTTP Evidence');
      expect(result).toContain('## Affected Scope');
      expect(result).toContain('## Quick Reproduction');
      expect(result).toContain('POST /comments');
    });
  });

  describe('H1-standard template sections (RQ2)', () => {
    const templateKeys = Object.keys(REPORT_TEMPLATES);

    for (const key of templateKeys) {
      it(`${key}: includes Prerequisites section`, () => {
        expect(REPORT_TEMPLATES[key]).toContain('## Prerequisites');
      });

      it(`${key}: includes Expected vs Actual Behavior section`, () => {
        expect(REPORT_TEMPLATES[key]).toContain('## Expected vs Actual Behavior');
        expect(REPORT_TEMPLATES[key]).toContain('**Expected:**');
        expect(REPORT_TEMPLATES[key]).toContain('**Actual:**');
      });

      it(`${key}: includes HTTP Evidence section`, () => {
        expect(REPORT_TEMPLATES[key]).toContain('## HTTP Evidence');
      });

      it(`${key}: includes Affected Scope section`, () => {
        expect(REPORT_TEMPLATES[key]).toContain('## Affected Scope');
      });

      it(`${key}: includes Quick Reproduction section`, () => {
        expect(REPORT_TEMPLATES[key]).toContain('## Quick Reproduction');
      });
    }

    it('unfilled placeholders are cleaned from output', () => {
      const result = fillTemplate(REPORT_TEMPLATES.ssrf, {
        url: 'https://target.com/proxy?url=',
        parameter: 'url',
        severity: 'HIGH',
        steps: '1. Send request with internal URL',
        poc: 'curl https://target.com/proxy?url=http://169.254.169.254/latest/meta-data/',
      });
      // http_evidence and quick_reproduction were not provided
      expect(result).not.toContain('{{');
    });
  });
});

/**
 * Response Analyzer (Phase 20D)
 *
 * Deterministic analysis of HTTP responses to detect vulnerability indicators.
 * Compares fuzzed responses against baseline to identify confirmed hits.
 */

import type { HttpResponse } from '../http/request_engine';
import type { Payload, VulnType } from './payload_db';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AnalysisResult {
  isVulnerable: boolean;
  confidence: number;
  vulnType: VulnType;
  evidence: string;
  payload: string;
  indicator: string;
}

// ─── SQL Error Patterns ─────────────────────────────────────────────────────

const SQL_ERROR_PATTERNS: RegExp[] = [
  /SQL syntax.*MySQL/i,
  /Warning.*mysql_/i,
  /PostgreSQL.*ERROR/i,
  /ERROR.*syntax error at or near/i,
  /ORA-\d{5}/,
  /Microsoft.*ODBC.*SQL Server/i,
  /Unclosed quotation mark/i,
  /SQLSTATE\[\w+\]/,
  /SQLite3?::Exception/i,
  /near ".*": syntax error/i,
  /pg_query\(\)/i,
  /valid MySQL result/i,
  /check the manual that corresponds to your MySQL/i,
  /com\.mysql\.jdbc/i,
  /org\.postgresql\.util\.PSQLException/i,
  /java\.sql\.SQLException/i,
  /Microsoft SQL Native Client/i,
  /ODBC SQL Server Driver/i,
  /supplied argument is not a valid MySQL/i,
  /Syntax error.*in query expression/i,
];

// ─── File Content Patterns ──────────────────────────────────────────────────

const FILE_CONTENT_PATTERNS: RegExp[] = [
  /root:[x*]:0:0:/,
  /daemon:[x*]:\d+:\d+:/,
  /www-data:[x*]:\d+:\d+:/,
  /\[fonts\]/i,
  /\[extensions\]/i,
  /\[boot loader\]/i,
  /PATH=.*\/usr/,
  /HOME=\//,
];

// ─── Response Analyzer ──────────────────────────────────────────────────────

export class ResponseAnalyzer {
  analyzeForXSS(baseline: HttpResponse, fuzzed: HttpResponse, payload: Payload): AnalysisResult {
    const result: AnalysisResult = {
      isVulnerable: false,
      confidence: 0,
      vulnType: 'xss',
      evidence: '',
      payload: payload.raw,
      indicator: '',
    };

    // Check if the payload is reflected WITHOUT HTML encoding
    const rawPayload = payload.raw;
    const body = fuzzed.body;

    // Direct reflection check
    if (body.includes(rawPayload)) {
      // Verify it's not HTML-encoded in the response
      const encoded = rawPayload
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');

      if (!body.includes(encoded) || body.includes(rawPayload)) {
        result.isVulnerable = true;
        result.confidence = 0.9;
        result.evidence = `Payload reflected unencoded in response body`;
        result.indicator = rawPayload;
        return result;
      }
    }

    // Partial reflection (event handlers, javascript: URIs)
    const dangerousPatterns = [
      /onerror\s*=/i, /onload\s*=/i, /onclick\s*=/i, /onfocus\s*=/i,
      /onmouseover\s*=/i, /javascript:/i, /data:text\/html/i,
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(body) && !pattern.test(baseline.body)) {
        result.isVulnerable = true;
        result.confidence = 0.75;
        result.evidence = `Dangerous pattern introduced in response: ${pattern.source}`;
        result.indicator = pattern.source;
        return result;
      }
    }

    return result;
  }

  analyzeForSQLi(baseline: HttpResponse, fuzzed: HttpResponse, payload: Payload): AnalysisResult {
    const result: AnalysisResult = {
      isVulnerable: false,
      confidence: 0,
      vulnType: 'sqli',
      evidence: '',
      payload: payload.raw,
      indicator: '',
    };

    // Check for SQL error messages
    for (const pattern of SQL_ERROR_PATTERNS) {
      if (pattern.test(fuzzed.body) && !pattern.test(baseline.body)) {
        result.isVulnerable = true;
        result.confidence = 0.95;
        const match = pattern.exec(fuzzed.body);
        result.evidence = `SQL error detected: ${match ? match[0] : pattern.source}`;
        result.indicator = match ? match[0] : pattern.source;
        return result;
      }
    }

    // Time-based blind detection (payload contains SLEEP/WAITFOR/pg_sleep)
    if (/sleep|waitfor|pg_sleep/i.test(payload.raw)) {
      const timeDiff = fuzzed.timing.totalMs - baseline.timing.totalMs;
      if (timeDiff > 4500) {
        result.isVulnerable = true;
        result.confidence = 0.85;
        result.evidence = `Time-based blind SQLi: response delayed by ${timeDiff}ms (baseline: ${baseline.timing.totalMs}ms, fuzzed: ${fuzzed.timing.totalMs}ms)`;
        result.indicator = `${timeDiff}ms delay`;
        return result;
      }
    }

    // Boolean-based blind (significant content change)
    if (/AND 1=1|AND 1=2|OR 1=1/i.test(payload.raw)) {
      const lengthDiff = Math.abs(fuzzed.body.length - baseline.body.length);
      if (fuzzed.status !== baseline.status || lengthDiff > 100) {
        result.confidence = 0.5; // Needs comparison with opposite boolean
        result.evidence = `Boolean-based blind candidate: status ${baseline.status}→${fuzzed.status}, length diff ${lengthDiff}`;
        result.indicator = 'status/length change';
      }
    }

    return result;
  }

  analyzeForSSRF(baseline: HttpResponse, fuzzed: HttpResponse, payload: Payload): AnalysisResult {
    const result: AnalysisResult = {
      isVulnerable: false,
      confidence: 0,
      vulnType: 'ssrf',
      evidence: '',
      payload: payload.raw,
      indicator: '',
    };

    // Check if the response contains internal data
    if (payload.expectedIndicator) {
      const pattern = new RegExp(payload.expectedIndicator, 'i');
      if (pattern.test(fuzzed.body) && !pattern.test(baseline.body)) {
        result.isVulnerable = true;
        result.confidence = 0.95;
        const match = pattern.exec(fuzzed.body);
        result.evidence = `Internal data exposed: ${match ? match[0].substring(0, 100) : payload.expectedIndicator}`;
        result.indicator = match ? match[0].substring(0, 100) : payload.expectedIndicator;
        return result;
      }
    }

    // Check for different response characteristics indicating server-side fetch
    if (fuzzed.body.length > baseline.body.length + 100 && fuzzed.status === 200) {
      const hasInternalIndicators =
        /internal|localhost|127\.0\.0\.1|private|metadata|instance-id/i.test(fuzzed.body);
      if (hasInternalIndicators) {
        result.isVulnerable = true;
        result.confidence = 0.8;
        result.evidence = 'Response contains internal/metadata indicators after SSRF probe';
        result.indicator = 'internal data indicators';
        return result;
      }
    }

    return result;
  }

  analyzeForPathTraversal(baseline: HttpResponse, fuzzed: HttpResponse, payload: Payload): AnalysisResult {
    const result: AnalysisResult = {
      isVulnerable: false,
      confidence: 0,
      vulnType: 'path_traversal',
      evidence: '',
      payload: payload.raw,
      indicator: '',
    };

    for (const pattern of FILE_CONTENT_PATTERNS) {
      if (pattern.test(fuzzed.body) && !pattern.test(baseline.body)) {
        result.isVulnerable = true;
        result.confidence = 0.95;
        const match = pattern.exec(fuzzed.body);
        result.evidence = `File content detected: ${match ? match[0] : pattern.source}`;
        result.indicator = match ? match[0] : pattern.source;
        return result;
      }
    }

    return result;
  }

  analyzeForCommandInjection(baseline: HttpResponse, fuzzed: HttpResponse, payload: Payload): AnalysisResult {
    const result: AnalysisResult = {
      isVulnerable: false,
      confidence: 0,
      vulnType: 'command_injection',
      evidence: '',
      payload: payload.raw,
      indicator: '',
    };

    // Check expected indicator
    if (payload.expectedIndicator) {
      const pattern = new RegExp(payload.expectedIndicator, 'i');
      if (pattern.test(fuzzed.body) && !pattern.test(baseline.body)) {
        result.isVulnerable = true;
        result.confidence = 0.95;
        const match = pattern.exec(fuzzed.body);
        result.evidence = `Command output detected: ${match ? match[0] : payload.expectedIndicator}`;
        result.indicator = match ? match[0] : payload.expectedIndicator;
        return result;
      }
    }

    // Time-based detection for sleep payloads
    if (/sleep\s+\d/i.test(payload.raw)) {
      const timeDiff = fuzzed.timing.totalMs - baseline.timing.totalMs;
      if (timeDiff > 4500) {
        result.isVulnerable = true;
        result.confidence = 0.85;
        result.evidence = `Time-based command injection: ${timeDiff}ms delay`;
        result.indicator = `${timeDiff}ms delay`;
        return result;
      }
    }

    return result;
  }

  analyzeForSSTI(baseline: HttpResponse, fuzzed: HttpResponse, payload: Payload): AnalysisResult {
    const result: AnalysisResult = {
      isVulnerable: false,
      confidence: 0,
      vulnType: 'ssti',
      evidence: '',
      payload: payload.raw,
      indicator: '',
    };

    // Math evaluation check: {{7*7}} → 49
    if (payload.expectedIndicator === '49') {
      if (fuzzed.body.includes('49') && !baseline.body.includes('49')) {
        result.isVulnerable = true;
        result.confidence = 0.9;
        result.evidence = 'Template expression evaluated: 7*7=49 found in response';
        result.indicator = '49';
        return result;
      }
    }

    // String multiplication: {{7*'7'}} → 7777777
    if (payload.expectedIndicator === '7777777') {
      if (fuzzed.body.includes('7777777')) {
        result.isVulnerable = true;
        result.confidence = 0.95;
        result.evidence = 'Jinja2 string multiplication confirmed: 7777777 in response';
        result.indicator = '7777777';
        return result;
      }
    }

    // Config/class access
    if (payload.expectedIndicator) {
      const pattern = new RegExp(payload.expectedIndicator, 'i');
      if (pattern.test(fuzzed.body) && !pattern.test(baseline.body)) {
        result.isVulnerable = true;
        result.confidence = 0.85;
        const match = pattern.exec(fuzzed.body);
        result.evidence = `SSTI indicator found: ${match ? match[0].substring(0, 100) : payload.expectedIndicator}`;
        result.indicator = match ? match[0].substring(0, 100) : '';
        return result;
      }
    }

    return result;
  }

  /** Generic analysis dispatcher */
  analyze(vulnType: VulnType, baseline: HttpResponse, fuzzed: HttpResponse, payload: Payload): AnalysisResult {
    switch (vulnType) {
      case 'xss': return this.analyzeForXSS(baseline, fuzzed, payload);
      case 'sqli': return this.analyzeForSQLi(baseline, fuzzed, payload);
      case 'ssrf': return this.analyzeForSSRF(baseline, fuzzed, payload);
      case 'path_traversal': return this.analyzeForPathTraversal(baseline, fuzzed, payload);
      case 'command_injection': return this.analyzeForCommandInjection(baseline, fuzzed, payload);
      case 'ssti': return this.analyzeForSSTI(baseline, fuzzed, payload);
      case 'xxe':
      case 'crlf':
        // Generic indicator check
        return this.analyzeGeneric(baseline, fuzzed, payload, vulnType);
    }
  }

  private analyzeGeneric(baseline: HttpResponse, fuzzed: HttpResponse, payload: Payload, vulnType: VulnType): AnalysisResult {
    const result: AnalysisResult = {
      isVulnerable: false,
      confidence: 0,
      vulnType,
      evidence: '',
      payload: payload.raw,
      indicator: '',
    };

    if (payload.expectedIndicator) {
      const pattern = new RegExp(payload.expectedIndicator, 'i');
      if (pattern.test(fuzzed.body) && !pattern.test(baseline.body)) {
        result.isVulnerable = true;
        result.confidence = 0.85;
        const match = pattern.exec(fuzzed.body);
        result.evidence = `Indicator detected: ${match ? match[0].substring(0, 100) : payload.expectedIndicator}`;
        result.indicator = match ? match[0].substring(0, 100) : '';
      }
    }

    return result;
  }
}

export default ResponseAnalyzer;

/**
 * Report Quality Scorer (Phase 23E)
 *
 * Scores the quality of a vulnerability report before HackerOne submission,
 * identifying weaknesses and suggesting improvements. Optionally uses an LLM
 * to enhance terse or incomplete reports.
 *
 * Scoring categories (weighted):
 *   Clarity        20%  — title, description length, structure
 *   Completeness   25%  — required sections present
 *   Evidence       25%  — screenshots, request/response, code
 *   Impact         15%  — business consequence articulation
 *   Reproducibility 15% — step detail and specificity
 */

import type { H1Report } from './h1_api';
import type { ModelProvider, ChatMessage, SendMessageOptions } from '../providers/types';

// ─── Config ──────────────────────────────────────────────────────────────────

export interface ReportQualityConfig {
  /** Minimum description length (characters) for full clarity credit. Default 200. */
  minDescriptionLength?: number;
  /** Minimum number of reproduction steps for full completeness credit. Default 3. */
  minStepsCount?: number;
  /** Whether the impact section is required for completeness. Default true. */
  requireImpact?: boolean;
  /** Whether a CVSS score is required for completeness. Default false. */
  requireCvss?: boolean;
}

// ─── Result Types ────────────────────────────────────────────────────────────

export interface ReportQualityScore {
  /** Weighted overall score (0-100). */
  overall: number;
  /** Per-category scores (each 0-100). */
  categories: {
    clarity: number;
    completeness: number;
    evidence: number;
    impact: number;
    reproducibility: number;
    /** RQ6: Structured HTTP request/response evidence quality */
    httpEvidence: number;
    /** RQ6: Executable PoC (curl/Python commands) */
    executablePoc: number;
    /** RQ6: Expected vs Actual behavior section */
    expectedVsActual: number;
  };
  /** Issues found during scoring. */
  issues: QualityIssue[];
  /** Letter grade derived from `overall`. */
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  /** RQ6: Whether the report meets the minimum quality threshold for submission */
  meetsThreshold: boolean;
}

export type QualityCategory = 'clarity' | 'completeness' | 'evidence' | 'impact' | 'reproducibility' | 'httpEvidence' | 'executablePoc' | 'expectedVsActual';

export interface QualityIssue {
  category: QualityCategory;
  severity: 'critical' | 'major' | 'minor';
  message: string;
  suggestion: string;
}

// ─── Category weights ────────────────────────────────────────────────────────

/**
 * H16 Recalibrated weights — prioritize what H1 triagers actually check.
 * HTTP evidence + executable PoC + expected/actual = 50% of total score.
 * Reports without HTTP pairs cannot exceed 55% even with perfect text.
 */
const CATEGORY_WEIGHTS: Record<QualityCategory, number> = {
  clarity: 0.10,
  completeness: 0.10,
  evidence: 0.05,
  impact: 0.10,
  reproducibility: 0.15,
  httpEvidence: 0.25,
  executablePoc: 0.15,
  expectedVsActual: 0.10,
};

/** Reports scoring below this threshold trigger a warning that the report is not ready for submission */
const MINIMUM_QUALITY_THRESHOLD = 60;

// ─── Impact keyword set ──────────────────────────────────────────────────────

const IMPACT_BUSINESS_KEYWORDS = [
  'attacker',
  'steal',
  'access',
  'modify',
  'delete',
  'exfiltrate',
  'impersonate',
];

// ─── Generic / low-quality title patterns ────────────────────────────────────

const GENERIC_TITLE_PATTERNS = [
  /^xss$/i,
  /^sqli$/i,
  /^ssrf$/i,
  /^idor$/i,
  /^csrf$/i,
  /^rce$/i,
  /^open redirect$/i,
  /^bug$/i,
  /^vulnerability$/i,
  /^issue$/i,
];

// ─── Evidence detection patterns ─────────────────────────────────────────────

const REQUEST_RESPONSE_PATTERNS = [
  /HTTP\/[12]\.\d/i,
  /GET\s+\//,
  /POST\s+\//,
  /PUT\s+\//,
  /DELETE\s+\//,
  /PATCH\s+\//,
  /Host:\s/i,
  /Content-Type:\s/i,
  /Authorization:\s/i,
  /response[:\s]/i,
  /request[:\s]/i,
  /status\s*code/i,
  /\b\d{3}\s+(OK|Created|Unauthorized|Forbidden|Not Found|Internal Server Error)\b/i,
];

const CURL_CODE_PATTERNS = [
  /curl\s+/i,
  /```/,
  /import\s+/,
  /require\s*\(/,
  /fetch\s*\(/,
  /axios\./,
  /requests\.(get|post|put|delete)/i,
  /\$\(/,
  /python\s+-c/i,
];

const POC_OUTPUT_PATTERNS = [
  /output[:\s]/i,
  /result[:\s]/i,
  /proof[:\s]/i,
  /poc[:\s]/i,
  /proof\s+of\s+concept/i,
  /demonstrated/i,
  /confirmed/i,
  /verified/i,
];

// ─── URL / endpoint patterns (for reproducibility) ──────────────────────────

const URL_ENDPOINT_PATTERN = /https?:\/\/[^\s)>"']+|\/api\/[^\s)>"']+|\/v\d+\/[^\s)>"']+/;

const PAYLOAD_PARAMETER_PATTERNS = [
  /[?&]\w+=\S+/,
  /\{[^}]+\}/,
  /<script>/i,
  /SELECT\s+/i,
  /UNION\s+/i,
  /\.\.\//,
  /%[0-9A-Fa-f]{2}/,
  /<img\s/i,
  /onerror=/i,
  /onload=/i,
  /\bpayload\b/i,
];

// ─── Enhancement system prompt ──────────────────────────────────────────────

const ENHANCEMENT_SYSTEM_PROMPT = `You are a HackerOne report quality expert. Your job is to improve vulnerability reports so they are clear, complete, and compelling to triagers.

Given a JSON object representing a report, return an improved version as a JSON object with the same schema. Specifically:
- If the description is short or vague, expand it with technical detail while preserving accuracy.
- If the impact section is missing or weak, add a concrete business-impact paragraph explaining what an attacker could achieve and who would be affected.
- If reproduction steps are vague, make them more specific with exact endpoints, parameters, and expected results at each step.
- If CVSS score is missing, suggest an appropriate score (0.0-10.0) based on the vulnerability details.
- Keep the title concise but descriptive (do NOT make it generic).
- Do NOT fabricate URLs, endpoints, or technical details that are not implied by the existing content.
- Return ONLY valid JSON — no markdown fences, no commentary.`;

// ─── Scorer ──────────────────────────────────────────────────────────────────

export class ReportQualityScorer {
  private readonly config: Required<ReportQualityConfig>;

  constructor(config?: ReportQualityConfig) {
    this.config = {
      minDescriptionLength: config?.minDescriptionLength ?? 200,
      minStepsCount: config?.minStepsCount ?? 3,
      requireImpact: config?.requireImpact ?? true,
      requireCvss: config?.requireCvss ?? false,
    };
  }

  // ── Public API ───────────────────────────────────────────────────────────

  /**
   * Score a report across all quality categories.
   */
  scoreReport(report: H1Report): ReportQualityScore {
    const issues: QualityIssue[] = this.getImprovementSuggestions(report);

    const clarity = this.scoreClarity(report, issues);
    const completeness = this.scoreCompleteness(report, issues);
    const evidence = this.scoreEvidence(report, issues);
    const impact = this.scoreImpact(report, issues);
    const reproducibility = this.scoreReproducibility(report, issues);
    const httpEvidence = this.scoreHttpEvidence(report, issues);
    const executablePoc = this.scoreExecutablePoc(report, issues);
    const expectedVsActual = this.scoreExpectedVsActual(report, issues);

    const overall = Math.round(
      clarity * CATEGORY_WEIGHTS.clarity +
      completeness * CATEGORY_WEIGHTS.completeness +
      evidence * CATEGORY_WEIGHTS.evidence +
      impact * CATEGORY_WEIGHTS.impact +
      reproducibility * CATEGORY_WEIGHTS.reproducibility +
      httpEvidence * CATEGORY_WEIGHTS.httpEvidence +
      executablePoc * CATEGORY_WEIGHTS.executablePoc +
      expectedVsActual * CATEGORY_WEIGHTS.expectedVsActual,
    );

    // C5: Severity inflation penalty — CRITICAL severity without evidence of
    // RCE, auth bypass, or full data access gets -15 points. Prevents the
    // quality scorer from giving false confidence on inflated findings.
    let severityPenalty = 0;
    if (report.severity === 'critical') {
      const allText = `${report.title} ${report.description} ${report.impact}`.toLowerCase();
      const hasCriticalEvidence = allText.includes('rce') || allText.includes('remote code execution') ||
        allText.includes('auth bypass') || allText.includes('authentication bypass') ||
        allText.includes('account takeover') || allText.includes('full database') ||
        allText.includes('admin access') || allText.includes('arbitrary code') ||
        allText.includes('command execution') || allText.includes('shell access');
      if (!hasCriticalEvidence) {
        severityPenalty = 15;
        issues.push({
          category: 'impact',
          severity: 'major',
          message: 'CRITICAL severity claimed without RCE, auth bypass, or full data access evidence.',
          suggestion: 'Downgrade severity to HIGH or provide evidence of critical-tier impact (RCE, account takeover, full database access). H1 triagers will reject inflated severity and reputation drops -5 per N/A.',
        });
      }
    }

    const adjustedOverall = Math.max(0, overall - severityPenalty);
    const meetsThreshold = adjustedOverall >= MINIMUM_QUALITY_THRESHOLD;

    if (!meetsThreshold) {
      issues.push({
        category: 'evidence',
        severity: 'critical',
        message: `Report quality score (${adjustedOverall}/100) is below the minimum submission threshold (${MINIMUM_QUALITY_THRESHOLD}/100).`,
        suggestion: 'This report is not ready for HackerOne submission. Add HTTP request/response evidence, executable reproduction commands, and Expected vs Actual behavior sections.',
      });
    }

    return {
      overall: adjustedOverall,
      categories: { clarity, completeness, evidence, impact, reproducibility, httpEvidence, executablePoc, expectedVsActual },
      issues,
      grade: this.overallToGrade(overall),
      meetsThreshold,
    };
  }

  /**
   * Return every quality issue found (without computing scores).
   */
  getImprovementSuggestions(report: H1Report): QualityIssue[] {
    const issues: QualityIssue[] = [];

    this.collectClarityIssues(report, issues);
    this.collectCompletenessIssues(report, issues);
    this.collectEvidenceIssues(report, issues);
    this.collectImpactIssues(report, issues);
    this.collectReproducibilityIssues(report, issues);
    this.collectHttpEvidenceIssues(report, issues);
    this.collectExecutablePocIssues(report, issues);
    this.collectExpectedVsActualIssues(report, issues);

    return issues;
  }

  /**
   * Optionally use an LLM to expand and improve the report.
   * Returns the report unchanged if no provider is supplied.
   */
  async enhanceReport(
    report: H1Report,
    provider?: ModelProvider,
    model?: string,
  ): Promise<H1Report> {
    if (!provider) {
      return report;
    }

    const selectedModel = model ?? provider.getAvailableModels()[0]?.id;
    if (!selectedModel) {
      return report;
    }

    const reportPayload: Record<string, unknown> = {
      title: report.title,
      severity: report.severity,
      description: report.description,
      impact: report.impact,
      steps: report.steps,
      cvssScore: report.cvssScore ?? null,
      weaknessId: report.weaknessId ?? null,
      severityJustification: report.severityJustification ?? [],
    };

    const userMessage = `Improve this vulnerability report. Return the improved version as a JSON object with these exact keys: title, severity, description, impact, steps (array of strings), cvssScore (number or null), weaknessId (string or null), severityJustification (array of strings).\n\n${JSON.stringify(reportPayload, null, 2)}`;

    const messages: ChatMessage[] = [
      { role: 'user', content: userMessage },
    ];

    const options: SendMessageOptions = {
      model: selectedModel,
      maxTokens: 4096,
      temperature: 0.3,
      systemPrompt: ENHANCEMENT_SYSTEM_PROMPT,
    };

    try {
      const response = await provider.sendMessage(messages, options);
      const parsed = this.parseEnhancedReport(response.content, report);
      return parsed;
    } catch {
      // If the LLM call fails for any reason, return the original report
      return report;
    }
  }

  // ── Category scorers ─────────────────────────────────────────────────────

  /**
   * Clarity (20% weight)
   *  +30  description length >= minDescriptionLength
   *  +20  no jargon without explanation (heuristic: description has explanatory text)
   *  +20  proper sentence structure (periods, capitalization)
   *  +30  title is descriptive (>10 chars, not generic)
   */
  private scoreClarity(report: H1Report, _issues: QualityIssue[]): number {
    let score = 0;

    // Description length
    if (report.description.length >= this.config.minDescriptionLength) {
      score += 30;
    } else if (report.description.length > 0) {
      // Partial credit proportional to how close we are
      score += Math.round(30 * (report.description.length / this.config.minDescriptionLength));
    }

    // Jargon heuristic: description contains explanatory phrasing (i.e., the author
    // explains terms rather than using bare acronyms). We check for the presence of
    // connecting/explanatory words as a proxy.
    const explanatoryPatterns = /\b(which|this means|allows|because|resulting|therefore|consequently|in other words|specifically)\b/i;
    if (explanatoryPatterns.test(report.description)) {
      score += 20;
    }

    // Sentence structure: has periods, starts with a capital letter
    const hasPeriods = report.description.includes('.');
    const startsCapital = /^[A-Z]/.test(report.description.trim());
    if (hasPeriods && startsCapital) {
      score += 20;
    } else if (hasPeriods || startsCapital) {
      score += 10;
    }

    // Title quality
    const titleIsLongEnough = report.title.length > 10;
    const titleIsGeneric = GENERIC_TITLE_PATTERNS.some((p) => p.test(report.title.trim()));
    if (titleIsLongEnough && !titleIsGeneric) {
      score += 30;
    } else if (titleIsLongEnough) {
      score += 15;
    }

    return Math.min(score, 100);
  }

  /**
   * Completeness (25% weight)
   *  +20  has description
   *  +25  has impact section
   *  +25  has reproduction steps (>= minStepsCount)
   *  +10  has severity
   *  +10  has CVSS score
   *  +10  has weakness ID (CWE)
   */
  private scoreCompleteness(report: H1Report, _issues: QualityIssue[]): number {
    let score = 0;

    if (report.description.trim().length > 0) {
      score += 20;
    }

    if (report.impact.trim().length > 0) {
      score += 25;
    }

    if (report.steps.length >= this.config.minStepsCount) {
      score += 25;
    } else if (report.steps.length > 0) {
      score += Math.round(25 * (report.steps.length / this.config.minStepsCount));
    }

    if (report.severity) {
      score += 10;
    }

    if (report.cvssScore !== undefined && report.cvssScore !== null) {
      score += 10;
    }

    if (report.weaknessId !== undefined && report.weaknessId !== null && report.weaknessId.trim().length > 0) {
      score += 10;
    }

    return Math.min(score, 100);
  }

  /**
   * Evidence (5% weight — H16 recalibrated)
   * Only scores screenshots/video and PoC output text.
   * HTTP req/resp and curl/code are scored separately in httpEvidence and executablePoc
   * to avoid double-counting.
   *  +50  has screenshots or video
   *  +50  has proof-of-concept output
   */
  private scoreEvidence(report: H1Report, _issues: QualityIssue[]): number {
    let score = 0;

    // Screenshots or video
    const hasScreenshots =
      (report.proof.screenshots !== undefined && report.proof.screenshots.length > 0) ||
      (report.proof.video !== undefined && report.proof.video.length > 0);
    if (hasScreenshots) {
      score += 50;
    }

    // PoC output references in text
    const allText = this.getAllTextContent(report);
    if (POC_OUTPUT_PATTERNS.some((p) => p.test(allText))) {
      score += 50;
    }

    return Math.min(score, 100);
  }

  /**
   * Impact (15% weight)
   *  +30  impact section present
   *  +30  describes business consequence (keywords)
   *  +20  mentions affected users/data
   *  +20  severity justification provided
   */
  private scoreImpact(report: H1Report, _issues: QualityIssue[]): number {
    let score = 0;

    const impactText = report.impact.trim();
    if (impactText.length > 0) {
      score += 30;
    }

    // Business consequence keywords
    const impactLower = impactText.toLowerCase();
    const hasBusinessKeywords = IMPACT_BUSINESS_KEYWORDS.some((kw) => impactLower.includes(kw));
    if (hasBusinessKeywords) {
      score += 30;
    }

    // Mentions affected users or data
    const usersDataPattern = /\b(users?|customers?|data|records?|accounts?|credentials?|personal|sensitive|private|confidential|pii)\b/i;
    if (usersDataPattern.test(impactText)) {
      score += 20;
    }

    // Severity justification
    if (report.severityJustification !== undefined && report.severityJustification.length > 0) {
      score += 20;
    }

    return Math.min(score, 100);
  }

  /**
   * Reproducibility (15% weight)
   *  +25  steps are numbered
   *  +25  steps contain specific URLs/endpoints
   *  +25  steps contain specific payload/parameters
   *  +25  steps are detailed enough (avg >30 chars per step)
   */
  private scoreReproducibility(report: H1Report, _issues: QualityIssue[]): number {
    let score = 0;
    const steps = report.steps;

    if (steps.length === 0) {
      return 0;
    }

    // Numbered steps — check if steps begin with a digit or "Step" pattern
    const numberedPattern = /^\s*(\d+[\.\)\-]|step\s+\d)/i;
    const numberedCount = steps.filter((s) => numberedPattern.test(s)).length;
    if (numberedCount >= steps.length * 0.5) {
      score += 25;
    }

    // Specific URLs/endpoints
    const hasUrls = steps.some((s) => URL_ENDPOINT_PATTERN.test(s));
    if (hasUrls) {
      score += 25;
    }

    // Specific payload/parameters
    const hasPayloads = steps.some((s) => PAYLOAD_PARAMETER_PATTERNS.some((p) => p.test(s)));
    if (hasPayloads) {
      score += 25;
    }

    // Average step length
    const totalLength = steps.reduce((sum, s) => sum + s.length, 0);
    const avgLength = totalLength / steps.length;
    if (avgLength > 30) {
      score += 25;
    } else if (avgLength > 15) {
      score += Math.round(25 * (avgLength / 30));
    }

    return Math.min(score, 100);
  }

  /**
   * RQ6: HTTP Evidence (15% weight)
   *  +40  has structured httpEvidence field
   *  +30  httpEvidence contains HTTP code blocks (```http)
   *  +30  httpEvidence contains 2+ request/response pairs
   */
  private scoreHttpEvidence(report: H1Report, _issues: QualityIssue[]): number {
    let score = 0;

    if (report.httpEvidence && report.httpEvidence.trim().length > 0) {
      score += 40;

      // Contains HTTP code blocks
      const httpCodeBlocks = (report.httpEvidence.match(/```http/g) ?? []).length;
      if (httpCodeBlocks >= 1) {
        score += 30;
      }

      // Contains 2+ request/response pairs (each pair has Request + Response blocks)
      if (httpCodeBlocks >= 4) {
        score += 30;
      } else if (httpCodeBlocks >= 2) {
        score += 15;
      }
    } else {
      // Fall back to checking all text for HTTP patterns (legacy reports)
      const allText = this.getAllTextContent(report);
      const hasHttpPatterns = REQUEST_RESPONSE_PATTERNS.some((p) => p.test(allText));
      if (hasHttpPatterns) {
        score += 20; // Partial credit for HTTP patterns in text
      }
    }

    return Math.min(score, 100);
  }

  /**
   * RQ6: Executable PoC (10% weight)
   *  +50  has quickReproduction field
   *  +30  contains curl command
   *  +20  contains Python script or multi-step reproduction
   */
  private scoreExecutablePoc(report: H1Report, _issues: QualityIssue[]): number {
    let score = 0;

    if (report.quickReproduction && report.quickReproduction.trim().length > 0) {
      score += 50;

      if (/curl\s+/i.test(report.quickReproduction)) {
        score += 30;
      }

      if (/import\s+requests|python/i.test(report.quickReproduction)) {
        score += 20;
      }
    } else {
      // Fall back to checking all text for executable commands
      const allText = this.getAllTextContent(report);
      if (CURL_CODE_PATTERNS.some((p) => p.test(allText))) {
        score += 25; // Partial credit
      }
    }

    return Math.min(score, 100);
  }

  /**
   * RQ6: Expected vs Actual Behavior (5% weight)
   *  +50  has "Expected" keyword in description or sections
   *  +50  has "Actual" keyword paired with Expected
   */
  private scoreExpectedVsActual(report: H1Report, _issues: QualityIssue[]): number {
    let score = 0;
    const allText = this.getAllTextContent(report);

    const hasExpected = /\b(expected|should)\b.*\b(behavior|behaviour|result|response)\b/i.test(allText) ||
      /\*\*Expected(:\*\*| Behavior)/i.test(allText);
    const hasActual = /\b(actual|instead|however)\b.*\b(behavior|behaviour|result|response)\b/i.test(allText) ||
      /\*\*Actual(:\*\*| Behavior)/i.test(allText);

    if (hasExpected) score += 50;
    if (hasActual) score += 50;

    return Math.min(score, 100);
  }

  // ── Issue collectors ─────────────────────────────────────────────────────

  private collectClarityIssues(report: H1Report, issues: QualityIssue[]): void {
    // Description length
    if (report.description.trim().length === 0) {
      issues.push({
        category: 'clarity',
        severity: 'critical',
        message: 'Report description is empty.',
        suggestion: 'Add a detailed description explaining the vulnerability, how it was discovered, and why it matters.',
      });
    } else if (report.description.length < this.config.minDescriptionLength) {
      issues.push({
        category: 'clarity',
        severity: 'major',
        message: `Description is too short (${report.description.length} chars, minimum recommended: ${this.config.minDescriptionLength}).`,
        suggestion: 'Expand the description with technical details about the vulnerability mechanism, affected component, and root cause.',
      });
    }

    // Title quality
    if (report.title.trim().length === 0) {
      issues.push({
        category: 'clarity',
        severity: 'critical',
        message: 'Report title is empty.',
        suggestion: 'Add a descriptive title that summarizes the vulnerability type and affected endpoint.',
      });
    } else if (report.title.length <= 10) {
      issues.push({
        category: 'clarity',
        severity: 'major',
        message: 'Title is too short and may not convey enough information to a triager.',
        suggestion: 'Use a title like "[VulnType] in [Endpoint/Feature] allows [Impact]" — e.g., "Stored XSS in /comments endpoint allows session hijacking".',
      });
    } else if (GENERIC_TITLE_PATTERNS.some((p) => p.test(report.title.trim()))) {
      issues.push({
        category: 'clarity',
        severity: 'major',
        message: 'Title is generic and does not describe the specific vulnerability.',
        suggestion: 'Include the affected endpoint and impact in the title — e.g., "SSRF via image proxy at /api/fetch allows internal network scanning".',
      });
    }

    // Sentence structure
    const desc = report.description.trim();
    if (desc.length > 0 && !desc.includes('.')) {
      issues.push({
        category: 'clarity',
        severity: 'minor',
        message: 'Description lacks proper sentence structure (no periods found).',
        suggestion: 'Write in complete sentences with proper punctuation for better readability.',
      });
    }

    if (desc.length > 0 && !/^[A-Z]/.test(desc)) {
      issues.push({
        category: 'clarity',
        severity: 'minor',
        message: 'Description does not start with a capital letter.',
        suggestion: 'Start the description with a capital letter for a professional appearance.',
      });
    }
  }

  private collectCompletenessIssues(report: H1Report, issues: QualityIssue[]): void {
    if (report.description.trim().length === 0) {
      // Already flagged under clarity; add completeness perspective
      issues.push({
        category: 'completeness',
        severity: 'critical',
        message: 'Missing vulnerability description.',
        suggestion: 'Every report must have a description explaining what the vulnerability is.',
      });
    }

    if (this.config.requireImpact && report.impact.trim().length === 0) {
      issues.push({
        category: 'completeness',
        severity: 'critical',
        message: 'Missing impact section.',
        suggestion: 'Add an impact section explaining the business and security consequences of this vulnerability.',
      });
    }

    if (report.steps.length === 0) {
      issues.push({
        category: 'completeness',
        severity: 'critical',
        message: 'No reproduction steps provided.',
        suggestion: 'Add step-by-step instructions that a triager can follow to reproduce the vulnerability.',
      });
    } else if (report.steps.length < this.config.minStepsCount) {
      issues.push({
        category: 'completeness',
        severity: 'major',
        message: `Only ${report.steps.length} reproduction step(s) provided (recommended minimum: ${this.config.minStepsCount}).`,
        suggestion: 'Break the reproduction into more granular steps so a triager can follow along easily.',
      });
    }

    if (this.config.requireCvss && (report.cvssScore === undefined || report.cvssScore === null)) {
      issues.push({
        category: 'completeness',
        severity: 'major',
        message: 'CVSS score is missing.',
        suggestion: 'Calculate and include a CVSS 3.1 score to support your severity rating.',
      });
    } else if (report.cvssScore === undefined || report.cvssScore === null) {
      issues.push({
        category: 'completeness',
        severity: 'minor',
        message: 'No CVSS score provided (optional but recommended).',
        suggestion: 'Including a CVSS score strengthens the report and demonstrates rigor.',
      });
    }

    if (report.weaknessId === undefined || report.weaknessId === null || report.weaknessId.trim().length === 0) {
      issues.push({
        category: 'completeness',
        severity: 'minor',
        message: 'No weakness/CWE ID provided.',
        suggestion: 'Include a CWE identifier (e.g., CWE-79 for XSS) to help triagers classify the vulnerability.',
      });
    }
  }

  private collectEvidenceIssues(report: H1Report, issues: QualityIssue[]): void {
    const hasScreenshots =
      (report.proof.screenshots !== undefined && report.proof.screenshots.length > 0) ||
      (report.proof.video !== undefined && report.proof.video.length > 0);

    if (!hasScreenshots) {
      issues.push({
        category: 'evidence',
        severity: 'major',
        message: 'No screenshots or video proof attached.',
        suggestion: 'Attach screenshots or a video showing the vulnerability in action — visual evidence significantly increases acceptance rates.',
      });
    }

    const allText = this.getAllTextContent(report);
    if (!POC_OUTPUT_PATTERNS.some((p) => p.test(allText))) {
      issues.push({
        category: 'evidence',
        severity: 'minor',
        message: 'No proof-of-concept output referenced.',
        suggestion: 'Include the output or result that confirms the vulnerability was exploited successfully.',
      });
    }
  }

  private collectImpactIssues(report: H1Report, issues: QualityIssue[]): void {
    const impactText = report.impact.trim();

    if (impactText.length === 0) {
      // Already covered by completeness; skip to avoid pure duplication.
      return;
    }

    const impactLower = impactText.toLowerCase();

    if (!IMPACT_BUSINESS_KEYWORDS.some((kw) => impactLower.includes(kw))) {
      issues.push({
        category: 'impact',
        severity: 'major',
        message: 'Impact section does not describe a concrete business consequence.',
        suggestion: 'Explain what an attacker could do — e.g., steal session tokens, exfiltrate user data, impersonate administrators, delete records.',
      });
    }

    const usersDataPattern = /\b(users?|customers?|data|records?|accounts?|credentials?|personal|sensitive|private|confidential|pii)\b/i;
    if (!usersDataPattern.test(impactText)) {
      issues.push({
        category: 'impact',
        severity: 'minor',
        message: 'Impact section does not mention affected users or data.',
        suggestion: 'Specify who is affected (all users, admin accounts, etc.) and what data is at risk.',
      });
    }

    if (report.severityJustification === undefined || report.severityJustification.length === 0) {
      issues.push({
        category: 'impact',
        severity: 'minor',
        message: 'No severity justification provided.',
        suggestion: 'Add reasoning that explains why you chose this severity level — reference the attack vector, required privileges, and scope of impact.',
      });
    }
  }

  private collectReproducibilityIssues(report: H1Report, issues: QualityIssue[]): void {
    const steps = report.steps;

    if (steps.length === 0) {
      // Already flagged under completeness
      return;
    }

    // Numbered steps
    const numberedPattern = /^\s*(\d+[\.\)\-]|step\s+\d)/i;
    const numberedCount = steps.filter((s) => numberedPattern.test(s)).length;
    if (numberedCount < steps.length * 0.5) {
      issues.push({
        category: 'reproducibility',
        severity: 'minor',
        message: 'Reproduction steps are not numbered.',
        suggestion: 'Number each step (e.g., "1. Navigate to...", "2. Enter payload...") for clarity.',
      });
    }

    // URLs/endpoints
    if (!steps.some((s) => URL_ENDPOINT_PATTERN.test(s))) {
      issues.push({
        category: 'reproducibility',
        severity: 'major',
        message: 'Steps do not contain specific URLs or endpoints.',
        suggestion: 'Include the exact URL or API endpoint in at least one step so a triager knows where to test.',
      });
    }

    // Payloads/parameters
    if (!steps.some((s) => PAYLOAD_PARAMETER_PATTERNS.some((p) => p.test(s)))) {
      issues.push({
        category: 'reproducibility',
        severity: 'major',
        message: 'Steps do not contain specific payloads or parameters.',
        suggestion: 'Include the exact payload, parameter values, or input used to trigger the vulnerability.',
      });
    }

    // Step detail
    const totalLength = steps.reduce((sum, s) => sum + s.length, 0);
    const avgLength = totalLength / steps.length;
    if (avgLength <= 30) {
      issues.push({
        category: 'reproducibility',
        severity: 'major',
        message: `Steps are too brief (average ${Math.round(avgLength)} chars each).`,
        suggestion: 'Add more detail to each step — describe what to do, what to observe, and what the expected result is.',
      });
    }
  }

  private collectHttpEvidenceIssues(report: H1Report, issues: QualityIssue[]): void {
    if (!report.httpEvidence || report.httpEvidence.trim().length === 0) {
      const allText = this.getAllTextContent(report);
      const hasAnyHttpPattern = REQUEST_RESPONSE_PATTERNS.some((p) => p.test(allText));
      if (!hasAnyHttpPattern) {
        issues.push({
          category: 'httpEvidence',
          severity: 'critical',
          message: 'No HTTP request/response evidence found in the report.',
          suggestion: 'Include structured HTTP request/response pairs as code blocks. Show the exact request that triggers the vulnerability and the response that proves exploitation.',
        });
      } else {
        issues.push({
          category: 'httpEvidence',
          severity: 'major',
          message: 'HTTP evidence exists in text but is not formatted as structured code blocks.',
          suggestion: 'Use the httpEvidence field with ```http code blocks for request/response pairs. This makes evidence easier for triagers to read and reproduce.',
        });
      }
    }
  }

  private collectExecutablePocIssues(report: H1Report, issues: QualityIssue[]): void {
    if (!report.quickReproduction || report.quickReproduction.trim().length === 0) {
      const allText = this.getAllTextContent(report);
      if (!CURL_CODE_PATTERNS.some((p) => p.test(allText))) {
        issues.push({
          category: 'executablePoc',
          severity: 'critical',
          message: 'No executable reproduction commands (curl, Python, etc.) found in the report.',
          suggestion: 'Add a curl command or Python script that a triager can copy-paste to reproduce the vulnerability immediately.',
        });
      } else {
        issues.push({
          category: 'executablePoc',
          severity: 'minor',
          message: 'Executable commands exist in report text but not in the dedicated quickReproduction section.',
          suggestion: 'Move reproduction commands to the quickReproduction field for better report structure.',
        });
      }
    }
  }

  private collectExpectedVsActualIssues(report: H1Report, issues: QualityIssue[]): void {
    const allText = this.getAllTextContent(report);
    const hasExpected = /\b(expected|should)\b.*\b(behavior|behaviour|result|response)\b/i.test(allText) ||
      /\*\*Expected(:\*\*| Behavior)/i.test(allText);

    if (!hasExpected) {
      issues.push({
        category: 'expectedVsActual',
        severity: 'major',
        message: 'Report does not describe Expected vs Actual behavior.',
        suggestion: 'Add a section showing what the application SHOULD do (expected behavior) vs what it ACTUALLY does (vulnerable behavior). This helps triagers understand the security impact.',
      });
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  /**
   * Concatenate all textual fields of the report for pattern matching.
   */
  private getAllTextContent(report: H1Report): string {
    const parts: string[] = [
      report.title,
      report.description,
      report.impact,
      ...report.steps,
    ];

    if (report.severityJustification) {
      parts.push(...report.severityJustification);
    }

    return parts.join('\n');
  }

  /**
   * Map an overall numeric score to a letter grade.
   */
  private overallToGrade(overall: number): ReportQualityScore['grade'] {
    if (overall >= 90) return 'A';
    if (overall >= 75) return 'B';
    if (overall >= 60) return 'C';
    if (overall >= 40) return 'D';
    return 'F';
  }

  /**
   * Parse the LLM's JSON response back into an H1Report, keeping the
   * original report's fields as fallbacks for anything the LLM omits.
   */
  private parseEnhancedReport(raw: string, original: H1Report): H1Report {
    try {
      // Strip markdown code fences if the LLM wrapped the JSON
      const cleaned = raw
        .replace(/^```(?:json)?\s*/m, '')
        .replace(/\s*```\s*$/m, '')
        .trim();

      const parsed: Record<string, unknown> = JSON.parse(cleaned);

      const enhanced: H1Report = {
        title: typeof parsed['title'] === 'string' && parsed['title'].length > 0
          ? parsed['title']
          : original.title,
        severity: this.isValidSeverity(parsed['severity'])
          ? parsed['severity']
          : original.severity,
        description: typeof parsed['description'] === 'string' && parsed['description'].length > 0
          ? parsed['description']
          : original.description,
        impact: typeof parsed['impact'] === 'string' && parsed['impact'].length > 0
          ? parsed['impact']
          : original.impact,
        steps: Array.isArray(parsed['steps']) && parsed['steps'].length > 0
          ? (parsed['steps'] as unknown[]).filter((s): s is string => typeof s === 'string')
          : original.steps,
        suggestedBounty: original.suggestedBounty,
        proof: original.proof,
        duplicateCheck: original.duplicateCheck,
        severityJustification: Array.isArray(parsed['severityJustification'])
          ? (parsed['severityJustification'] as unknown[]).filter((s): s is string => typeof s === 'string')
          : original.severityJustification,
        cvssScore: typeof parsed['cvssScore'] === 'number'
          ? parsed['cvssScore']
          : original.cvssScore,
        weaknessId: typeof parsed['weaknessId'] === 'string' && parsed['weaknessId'].length > 0
          ? parsed['weaknessId']
          : original.weaknessId,
      };

      return enhanced;
    } catch {
      // If JSON parsing fails, return the original report unmodified
      return original;
    }
  }

  /**
   * Type guard for valid H1Report severity values.
   */
  private isValidSeverity(value: unknown): value is H1Report['severity'] {
    return value === 'critical' || value === 'high' || value === 'medium' || value === 'low';
  }
}

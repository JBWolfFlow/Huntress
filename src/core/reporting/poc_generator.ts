/**
 * Proof-of-Concept Report Generator (Phase 4)
 * 
 * Professional report generation with full integration:
 * - Duplicate detection
 * - Severity prediction
 * - Guidelines context
 * - Evidence compilation
 * - HackerOne-ready formatting
 */

import { QdrantClient } from '../memory/qdrant_client';
import { FindingSummarizer } from '../memory/summarizer';
import { DuplicateChecker, type Vulnerability, type DuplicateScore } from '../../utils/duplicate_checker';
import { SeverityPredictor, type SeverityPrediction, type ProgramBountyRanges } from './severity_predictor';
import type { H1Report } from './h1_api';
import type { HttpExchange } from '../../agents/base_agent';
import { REPORT_TEMPLATES, fillTemplate, getTemplateKey, extractParameter } from './templates';
import { calculateCVSS, estimateMetrics, type CVSSResult } from './cvss_calculator';
import { invoke } from '@tauri-apps/api/core';

export interface ProgramGuidelines {
  programHandle: string;
  programName: string;
  bountyRanges?: ProgramBountyRanges;
  preferredFormat?: 'markdown' | 'html';
  requiredSections?: string[];
  customInstructions?: string;
  severity?: {
    critical?: string;
    high?: string;
    medium?: string;
    low?: string;
  };
  bountyRange?: {
    min: number;
    max: number;
  };
}

export interface ReportGenerationOptions {
  includeVideo?: boolean;
  includeScreenshots?: boolean;
  includeLogs?: boolean;
  skipDuplicateCheck?: boolean;
  manualSeverity?: 'critical' | 'high' | 'medium' | 'low';
  programGuidelines?: ProgramGuidelines;
  /** RQ1/RQ3: Structured HTTP exchanges from the agent's ReAct loop */
  httpExchanges?: HttpExchange[];
}

/**
 * P0-5-b: Per-vuln-type defaults for H1-required sections used by the
 * inline-build path (`buildInlineBody`). When a vuln type doesn't have a
 * REPORT_TEMPLATES entry, these defaults supply Prerequisites / Expected /
 * Actual / Affected Scope / Remediation so the report still ships with
 * every section H1 triagers expect.
 *
 * Keys mirror validator.ts dispatch types. Add new entries when introducing
 * a new vuln type that doesn't have a template.
 */
interface H1SectionDefaults {
  prerequisites: string;
  expected: string;
  actual: string;
  affectedScope: string;
  remediation: string;
}

const H1_SECTION_DEFAULTS: Record<string, H1SectionDefaults> = {
  cache_poisoning: {
    prerequisites: '- HTTP client (curl) capable of setting custom headers\n- A cache buster value to ensure the request reaches the origin\n- Knowledge of which downstream cache the target uses (CloudFront, Akamai, Cloudflare, Varnish)',
    expected: 'The application should normalize cache keys before storage and reject requests that smuggle attacker-controlled state into cached responses. Headers like X-Forwarded-Host, X-Original-URL, and Host should not be reflected into responses.',
    actual: 'The attacker-controlled header is reflected into the response body or status, the response is cached by the downstream tier, and subsequent clean requests retrieve the poisoned response.',
    affectedScope: 'Every user routed through the affected cache tier receives the poisoned response until the cache entry expires or is purged. CDN-cached resources can amplify the impact to all users globally.',
    remediation: 'Strip or normalize attacker-controllable headers before computing cache keys. Set explicit Cache-Control and Vary headers. Audit which inputs reach the cache and ensure none originate from the request.',
  },
  business_logic: {
    prerequisites: '- A standard user account on the target application\n- HTTP client capable of replaying and modifying requests\n- Understanding of the workflow being abused (cart, checkout, MFA, etc.)',
    expected: 'The application should enforce business invariants server-side: positive quantities, non-zero prices, sequential workflow steps, and authorization checks at every transition.',
    actual: 'The server accepts a state transition that violates the documented business rule, allowing the attacker to obtain value or access they should not be entitled to.',
    affectedScope: 'Depends on the abused workflow. Payment-related flaws affect financial integrity directly; account-creation flaws affect identity boundary; permissions flaws affect every protected resource.',
    remediation: 'Enforce all business invariants in the server-side handler, not the UI. Add idempotency keys to state transitions. Log and rate-limit anomalous parameter values (negative numbers, zero, very large values).',
  },
  race_condition: {
    prerequisites: '- HTTP client supporting parallel requests (curl with `--parallel`, Python `asyncio`, Burp Turbo Intruder)\n- A target operation with an obvious race window (balance check → debit, coupon application, MFA setup)',
    expected: 'State-modifying operations should hold a row-level lock for the full read-modify-write cycle and reject concurrent operations on the same resource.',
    actual: 'Multiple concurrent requests succeed where exactly one should have been allowed — duplicate withdrawals, coupon stacking, account creation collisions.',
    affectedScope: 'Anyone who can hit the vulnerable endpoint can amplify their privileges or balance. Financial impact tracks directly with the operation\'s monetary value.',
    remediation: 'Use database-level transactions with appropriate isolation levels (SERIALIZABLE for financial operations) or distributed locks. Add server-side request deduplication via idempotency keys.',
  },
  prototype_pollution: {
    prerequisites: '- A modern browser with DevTools to inspect Object.prototype\n- HTTP client to deliver the polluted payload\n- Understanding of which sink the polluted prototype reaches (Express middleware, template engine, deserialization)',
    expected: 'User-controlled JSON should not be merged into Object.prototype or used to set arbitrary keys via dotted paths. Libraries should use Object.create(null) or freeze the prototype.',
    actual: 'A property set on Object.prototype via the vulnerable code path persists across the JS runtime and influences subsequent operations on unrelated objects.',
    affectedScope: 'All users of the application can be affected because the polluted prototype is process-global. Impact ranges from XSS via gadget chains to RCE in Node.js when the right gadget exists.',
    remediation: 'Use Object.create(null) for user-controlled key/value containers. Validate JSON keys against an allowlist. Adopt libraries that explicitly defend against prototype pollution (e.g. lodash >= 4.17.21).',
  },
  http_smuggling: {
    prerequisites: '- HTTP client capable of sending raw bytes (the smuggled request must be byte-precise)\n- A target with a front-end (CDN/load balancer) and back-end with parsing disagreement\n- Sometimes a co-operating victim request to demonstrate request hijacking',
    expected: 'Front-end and back-end should agree on request boundaries. CL.TE, TE.CL, and TE.TE disagreements should be rejected at the front-end with a 400.',
    actual: 'The front-end uses one header to delimit the request while the back-end uses the other, allowing the attacker to inject a second request that the back-end attributes to a victim\'s connection.',
    affectedScope: 'Every user who shares the back-end connection pool with the attacker can have their request poisoned, hijacked, or have responses redirected.',
    remediation: 'Configure front-end and back-end to use HTTP/2 end-to-end (eliminates the parsing disagreement) or normalize CL/TE headers at the front-end and reject ambiguous requests.',
  },
  deserialization: {
    prerequisites: '- The target accepts serialized objects (Pickle, PHP serialize, Java ObjectInputStream, .NET BinaryFormatter, Ruby Marshal)\n- A gadget chain present in the target\'s classpath\n- HTTP client to deliver the payload (often base64-encoded)',
    expected: 'Untrusted data should never be deserialized. If unavoidable, use a strict allowlist of permitted classes and integrity-check the payload first (HMAC, signature).',
    actual: 'The deserialization sink instantiates attacker-controlled classes, triggering a gadget chain that runs arbitrary code or modifies application state.',
    affectedScope: 'Full RCE is the typical outcome; the application server (and anything it can reach) is compromised.',
    remediation: 'Replace native serialization with safe formats (JSON, MessagePack with schema). If you must deserialize, sign the payload and validate the signature before deserialization.',
  },
  ssti: {
    prerequisites: '- HTTP client capable of POST requests with body parameters\n- Knowledge of the template engine (Jinja2, Twig, Pug, Velocity, ERB) to craft the right payload',
    expected: 'User input should be passed as data to the template renderer, not concatenated into the template source. Sandboxed evaluators should reject access to filesystem and execution primitives.',
    actual: 'The application interpolates user input directly into a template string, so the engine evaluates expressions like `{{7*7}}` and emits the result.',
    affectedScope: 'SSTI typically escalates to RCE on Pug/Jinja/Velocity. Even sandboxed engines often leak filesystem access or environment variables.',
    remediation: 'Treat user input as data, not template source. Use parameterized template APIs. Sandbox the renderer and remove dangerous globals from the template context.',
  },
  saml_attack: {
    prerequisites: '- A valid SAML assertion from the target IdP\n- A SAML toolkit (SAMLRaider, python3-saml, samltest.id)\n- Understanding of which XSW or signature-wrapping variant the parser accepts',
    expected: 'The Service Provider should validate that the signature covers the assertion the parser uses, reject extra elements, and verify the IdP issuer + audience.',
    actual: 'A signature-wrapping variant lets the attacker substitute the signed assertion with one that asserts a different identity, and the SP accepts it.',
    affectedScope: 'Authentication bypass — the attacker can log in as any user, including admins. The full SP and any federated services are compromised.',
    remediation: 'Use a SAML library that validates the signed assertion is the one consumed (libsaml-style enforcement). Reject assertions with multiple Assertion elements or unsigned wrapper elements.',
  },
  mfa_bypass: {
    prerequisites: '- A valid first-factor credential (username + password)\n- HTTP client to replay the post-first-factor flow\n- An understanding of how the application binds first and second factors',
    expected: 'The MFA verification step should be bound to the same session as the first-factor auth, single-use, and rate-limited. Skipping or replaying the second step should fail.',
    actual: 'The attacker can skip the MFA verification entirely or replay a captured MFA token in another session, completing authentication without the second factor.',
    affectedScope: 'Every account protected by the bypassed MFA flow is reduced to single-factor security. High-value accounts (admins, finance) are particularly impacted.',
    remediation: 'Bind the second-factor token to the session ID and the first-factor user. Make it single-use with a short TTL. Audit every code path between first-factor success and the final session issuance.',
  },
  // Sensible default for any vuln type without a tailored entry.
  other: {
    prerequisites: '- HTTP client (curl, Burp Suite, or browser DevTools)\n- Standard web testing toolkit',
    expected: 'The application should validate, sanitize, and authorize all incoming requests before performing the requested action.',
    actual: 'The application processes the malicious request without sufficient validation, producing the security impact described above.',
    affectedScope: 'See Impact section above for the full blast radius.',
    remediation: 'Apply the principle of least privilege. Validate inputs against an allowlist. Add server-side authorization checks. Follow the OWASP guidance for this vulnerability class.',
  },
};

export class PoCGenerator {
  private qdrant: QdrantClient;
  private summarizer: FindingSummarizer;
  private duplicateChecker: DuplicateChecker;
  private severityPredictor: SeverityPredictor;
  private programGuidelines?: ProgramGuidelines;

  constructor(
    qdrant: QdrantClient,
    summarizer: FindingSummarizer,
    h1ApiKey?: string,
    githubToken?: string
  ) {
    this.qdrant = qdrant;
    this.summarizer = summarizer;
    
    // Initialize duplicate checker
    this.duplicateChecker = new DuplicateChecker(
      qdrant,
      summarizer,
      0.85,
      h1ApiKey,
      githubToken
    );

    // Initialize severity predictor
    this.severityPredictor = new SeverityPredictor(qdrant);
  }

  /**
   * Main report generation method
   */
  async generateReport(
    vuln: Vulnerability,
    options: ReportGenerationOptions = {}
  ): Promise<H1Report> {
    console.log(`📝 Generating report for: ${vuln.title}`);

    // 1. Check for duplicates (unless skipped)
    let duplicateCheck: DuplicateScore | undefined;
    if (!options.skipDuplicateCheck) {
      console.log('🔍 Checking for duplicates...');
      duplicateCheck = await this.duplicateChecker.getDuplicateScore(vuln);
      
      console.log(`   Duplicate score: ${duplicateCheck.overall}/100`);
      console.log(`   Recommendation: ${duplicateCheck.recommendation}`);

      if (duplicateCheck.recommendation === 'skip') {
        throw new Error(
          `Duplicate detected (score: ${duplicateCheck.overall}/100). ` +
          `This finding is too similar to existing reports. Submission not recommended.`
        );
      }

      if (duplicateCheck.recommendation === 'review') {
        console.log('⚠️  Manual review recommended - potential duplicate detected');
      }
    }

    // 2. Predict severity (unless manually specified)
    let severityPrediction: SeverityPrediction;
    if (options.manualSeverity) {
      console.log(`📊 Using manual severity: ${options.manualSeverity}`);
      severityPrediction = {
        severity: options.manualSeverity,
        confidence: 100,
        reasoning: ['Manually specified severity'],
        suggestedBounty: this.getDefaultBountyRange(options.manualSeverity),
        historicalData: {
          similarReports: 0,
          averageBounty: 0,
          acceptanceRate: 0,
        },
      };
    } else {
      console.log('📊 Predicting severity...');
      
      // Update predictor with program guidelines if available
      if (options.programGuidelines?.bountyRanges) {
        this.severityPredictor.setProgramBountyRanges(
          options.programGuidelines.bountyRanges,
          options.programGuidelines.programName
        );
      }
      
      severityPrediction = await this.severityPredictor.predictSeverity(vuln);
      console.log(`   Predicted severity: ${severityPrediction.severity}`);
      console.log(`   Confidence: ${severityPrediction.confidence}%`);
      console.log(`   Suggested bounty: $${severityPrediction.suggestedBounty.min} - $${severityPrediction.suggestedBounty.max}`);
    }

    // 3. Generate professional title
    const title = this.generateTitle(vuln, severityPrediction.severity);

    // 4. Generate description
    const description = this.generateDescription(vuln);

    // 5. Generate impact assessment
    const impact = this.generateImpact(vuln, severityPrediction);

    // 6. Format reproduction steps
    const steps = this.formatSteps(vuln.steps);

    // 7. Compile proof/evidence (RQ4 — embeds content instead of referencing paths)
    const proof = await this.compileProof(vuln, options);

    // 8. Generate severity justification
    const severityJustification = this.generateSeverityJustification(
      vuln,
      severityPrediction
    );

    // 9. Calculate CVSS score using real CVSS 3.1 calculator (S3)
    const cvssResult = this.calculateRealCVSS(vuln.type);

    // 10. Get CWE weakness ID
    const weaknessId = this.getWeaknessId(vuln.type);

    // 11. Format HTTP evidence (RQ3) — from structured exchanges or fallback to text extraction
    const httpEvidence = this.formatHttpEvidence(options.httpExchanges, vuln.description, vuln.steps);

    // 12. Generate executable reproduction steps (RQ5)
    const quickReproduction = this.generateQuickReproduction(options.httpExchanges, vuln);

    console.log('✓ Report generated successfully');

    // P0-5-a: Capture the original vuln context so toMarkdown() can
    // template-render or fall back to an enriched inline build with the
    // H1-required sections (Prerequisites, Vulnerability Details, etc).
    const inferredMethod = options.httpExchanges?.find(e => e.request.method !== 'GET')?.request.method
      ?? options.httpExchanges?.[0]?.request.method;
    const vulnContext: H1Report['vulnContext'] = {
      type: vuln.type,
      url: vuln.url,
      target: vuln.target,
      parameter: extractParameter(vuln.url, vuln.steps) ?? undefined,
      method: inferredMethod,
    };

    return {
      title,
      severity: severityPrediction.severity,
      suggestedBounty: severityPrediction.suggestedBounty,
      description,
      impact,
      steps,
      proof,
      duplicateCheck,
      severityJustification,
      cvssScore: cvssResult.score,
      cvssVector: cvssResult.vectorString,
      weaknessId,
      httpEvidence,
      quickReproduction,
      vulnContext,
    };
  }

  /**
   * Convert report to HackerOne markdown format.
   *
   * P0-5-a: When `report.vulnContext.type` matches a REPORT_TEMPLATES key
   * (or normalizes to one via getTemplateKey), the template is filled with
   * the report's data. Otherwise the inline-build path produces a report
   * with all H1-required sections (Prerequisites, Vulnerability Details,
   * Expected vs Actual, Affected Scope, Remediation) — see P0-5-b.
   *
   * The header (title + severity + bounty + CVSS + CWE) and trailing
   * sections (Severity Justification, Duplicate Check) are added in both
   * paths so the output is consistent regardless of which build was used.
   */
  toMarkdown(report: H1Report): string {
    const header = this.buildReportHeader(report);
    const trailer = this.buildReportTrailer(report);

    const templateKey = report.vulnContext ? getTemplateKey(report.vulnContext.type) : null;
    if (templateKey && REPORT_TEMPLATES[templateKey]) {
      const body = this.buildTemplatedBody(report, templateKey);
      return header + body + '\n\n' + trailer;
    }

    // Fallback: inline build with H1-required sections (P0-5-b)
    const body = this.buildInlineBody(report);
    return header + body + trailer;
  }

  /** Header common to both template-driven and inline-built reports. */
  private buildReportHeader(report: H1Report): string {
    let markdown = `# ${report.title}\n\n`;
    markdown += `**Severity:** ${report.severity.toUpperCase()}\n`;
    markdown += `**Suggested Bounty:** $${report.suggestedBounty.min.toLocaleString()} - $${report.suggestedBounty.max.toLocaleString()}\n`;

    if (report.cvssScore) {
      markdown += `**CVSS Score:** ${report.cvssScore}`;
      if (report.cvssVector) {
        markdown += ` (${report.cvssVector})`;
      }
      markdown += '\n';
    }

    if (report.weaknessId) {
      markdown += `**CWE:** CWE-${report.weaknessId}\n`;
    }

    markdown += '\n---\n\n';
    return markdown;
  }

  /**
   * P0-5-a: Build the body section by filling a REPORT_TEMPLATES entry.
   * Templates carry H1-standard sections (Prerequisites, Vulnerability
   * Details, Expected vs Actual, Affected Scope, Remediation); we just
   * supply the placeholders.
   */
  private buildTemplatedBody(report: H1Report, templateKey: string): string {
    const template = REPORT_TEMPLATES[templateKey];
    const ctx = report.vulnContext!;

    const stepsBlock = report.steps
      .map((step, i) => `${i + 1}. ${step}`)
      .join('\n');

    const pocBlock = this.buildPocBlock(report);

    const data: Record<string, string> = {
      url: ctx.url,
      severity: report.severity.toUpperCase(),
      steps: stepsBlock,
      http_evidence: report.httpEvidence ?? '_No structured HTTP evidence captured during this run._',
      poc: pocBlock,
      quick_reproduction: report.quickReproduction ?? '_See Steps to Reproduce above._',
    };

    if (ctx.parameter) data.parameter = ctx.parameter;
    if (ctx.payload) data.payload = ctx.payload;
    if (ctx.method) data.method = ctx.method;
    // Endpoint = URL path (templates use this for IDOR/JWT)
    try {
      const u = new URL(ctx.url);
      data.endpoint = u.pathname;
      data.origin = `${u.protocol}//${u.host}`;
    } catch {
      data.endpoint = ctx.url;
    }
    // Type-specific extras with sane defaults
    data.xss_type = ctx.type.replace(/^xss_/, '') || 'reflected';
    data.attack_type = ctx.type.replace(/^jwt_/, '').replace(/_/g, ' ') || 'signature bypass';
    data.database_type = 'unspecified';

    return fillTemplate(template, data);
  }

  /**
   * P0-5-b: Inline-build body for vuln types without a template, but with
   * the same H1-required sections that templates carry. Pulls per-type
   * defaults from `H1_SECTION_DEFAULTS` so every report (templated or not)
   * carries Prerequisites / Vulnerability Details / Expected vs Actual /
   * Affected Scope / Remediation.
   */
  private buildInlineBody(report: H1Report): string {
    const ctx = report.vulnContext;
    const type = ctx?.type ?? 'other';
    const defaults = H1_SECTION_DEFAULTS[type] ?? H1_SECTION_DEFAULTS.other;

    let markdown = '';

    // Vulnerability Details — only when we have context
    if (ctx) {
      markdown += `## Vulnerability Details\n\n`;
      markdown += `**Target:** ${ctx.target}\n`;
      markdown += `**URL:** ${ctx.url}\n`;
      if (ctx.method) markdown += `**Method:** ${ctx.method}\n`;
      if (ctx.parameter) markdown += `**Parameter:** ${ctx.parameter}\n`;
      if (ctx.payload) markdown += `**Payload:** \`${ctx.payload}\`\n`;
      markdown += `**Severity:** ${report.severity.toUpperCase()}\n\n`;
    }

    // Prerequisites
    markdown += `## Prerequisites\n\n${defaults.prerequisites}\n\n`;

    // Description
    markdown += `## Description\n\n${report.description}\n\n`;

    // Steps to Reproduce
    markdown += `## Steps to Reproduce\n\n`;
    report.steps.forEach((step, index) => {
      markdown += `${index + 1}. ${step}\n`;
    });
    markdown += '\n';

    // HTTP Evidence (RQ3)
    if (report.httpEvidence) {
      markdown += `## HTTP Evidence\n\n${report.httpEvidence}\n\n`;
    }

    // Quick Reproduction (RQ5)
    if (report.quickReproduction) {
      markdown += `## Quick Reproduction\n\n${report.quickReproduction}\n\n`;
    }

    // Expected vs Actual Behavior — H1 explicitly requires this
    markdown += `## Expected vs Actual Behavior\n\n`;
    markdown += `**Expected:** ${defaults.expected}\n\n`;
    markdown += `**Actual:** ${defaults.actual}\n\n`;

    // Proof of Concept
    const pocBlock = this.buildPocBlock(report);
    if (pocBlock !== '_No additional proof artifacts attached._') {
      markdown += `## Proof of Concept\n\n${pocBlock}\n\n`;
    }

    // Impact
    markdown += `## Impact\n\n${report.impact}\n\n`;

    // Affected Scope
    markdown += `## Affected Scope\n\n${defaults.affectedScope}\n\n`;

    // Remediation
    markdown += `## Remediation\n\n${defaults.remediation}\n\n`;

    return markdown;
  }

  /** Build the PoC artifacts block — used by both template and inline paths. */
  private buildPocBlock(report: H1Report): string {
    const parts: string[] = [];
    if (report.proof.video) {
      parts.push(`**Video Recording:** ${report.proof.video}`);
    }
    if (report.proof.screenshots && report.proof.screenshots.length > 0) {
      parts.push('**Screenshots:**');
      report.proof.screenshots.forEach((s, i) => parts.push(`- Screenshot ${i + 1}: ${s}`));
    }
    if (report.proof.logs && report.proof.logs.length > 0) {
      parts.push('**Logs:**');
      report.proof.logs.forEach((log, i) => parts.push(`- Log ${i + 1}: ${log}`));
    }
    if (parts.length === 0) {
      return '_No additional proof artifacts attached._';
    }
    return parts.join('\n');
  }

  /** Trailing sections common to both build paths (Severity Justification, Duplicate Check). */
  private buildReportTrailer(report: H1Report): string {
    let markdown = '';

    // Severity Justification
    if (report.severityJustification && report.severityJustification.length > 0) {
      markdown += `## Severity Justification\n\n`;
      report.severityJustification.forEach(reason => {
        markdown += `- ${reason}\n`;
      });
      markdown += '\n';
    }

    // Duplicate Check Info
    if (report.duplicateCheck) {
      markdown += `## Duplicate Check\n\n`;
      markdown += `This vulnerability has been checked against known reports:\n\n`;
      markdown += `- **Overall Duplicate Score:** ${report.duplicateCheck.overall}/100\n`;
      markdown += `- **HackerOne Match:** ${(report.duplicateCheck.h1Match * 100).toFixed(1)}%\n`;
      markdown += `- **GitHub Match:** ${(report.duplicateCheck.githubMatch * 100).toFixed(1)}%\n`;
      markdown += `- **Internal Match:** ${(report.duplicateCheck.internalMatch * 100).toFixed(1)}%\n`;
      markdown += `- **Recommendation:** ${report.duplicateCheck.recommendation.toUpperCase()}\n\n`;
      
      if (report.duplicateCheck.matches.length > 0) {
        markdown += `**Similar Reports Found:**\n`;
        report.duplicateCheck.matches.slice(0, 3).forEach((match: any, index: number) => {
          markdown += `${index + 1}. [${match.source}] ${match.title} (${(match.similarity * 100).toFixed(1)}% similar)\n`;
          markdown += `   ${match.url}\n`;
        });
        markdown += '\n';
      }
    }

    return markdown;
  }

  /**
   * Set program-specific guidelines
   */
  setProgramGuidelines(guidelines: ProgramGuidelines): void {
    this.programGuidelines = guidelines;
    
    // Update severity predictor with bounty ranges
    if (guidelines.bountyRanges) {
      this.severityPredictor.setProgramBountyRanges(
        guidelines.bountyRanges,
        guidelines.programName
      );
    }
  }

  /**
   * Configure API keys for duplicate detection
   */
  setApiKeys(h1ApiKey?: string, githubToken?: string): void {
    this.duplicateChecker.setApiKeys(h1ApiKey, githubToken);
  }

  /**
   * Generate professional title
   */
  private generateTitle(vuln: Vulnerability, severity: string): string {
    const severityTag = `[${severity.toUpperCase()}]`;
    
    // If title already has severity tag, use as-is
    if (vuln.title.match(/^\[(CRITICAL|HIGH|MEDIUM|LOW)\]/i)) {
      return vuln.title;
    }
    
    // Add severity tag and clean up title
    const cleanTitle = vuln.title
      .replace(/^(critical|high|medium|low):\s*/i, '')
      .trim();
    
    return `${severityTag} ${cleanTitle}`;
  }

  /**
   * Generate description
   */
  private generateDescription(vuln: Vulnerability): string {
    let description = vuln.description;
    
    // Add target information if not already included
    if (!description.includes(vuln.target) && !description.includes(vuln.url)) {
      description = `The vulnerability was discovered in ${vuln.target}.\n\n${description}`;
    }
    
    return description;
  }

  /**
   * Generate impact assessment
   */
  private generateImpact(vuln: Vulnerability, prediction: SeverityPrediction): string {
    let impact = vuln.impact;
    
    // Enhance impact with severity prediction reasoning
    if (prediction.reasoning.length > 0) {
      impact += '\n\n**Additional Context:**\n';
      prediction.reasoning.forEach(reason => {
        if (!reason.includes('confidence') && !reason.includes('Suggested bounty')) {
          impact += `- ${reason}\n`;
        }
      });
    }
    
    return impact;
  }

  /**
   * Format reproduction steps
   */
  private formatSteps(steps: string[]): string[] {
    return steps.map(step => {
      // Clean up step formatting
      return step.trim().replace(/^\d+\.\s*/, '');
    });
  }

  /**
   * RQ4: Compile proof/evidence — embeds file content instead of referencing paths.
   * - Logs: reads file content and embeds as code blocks
   * - Screenshots: validates path exists, keeps as reference for H1 attachment upload
   * - Video: validates path exists, keeps as reference (too large to embed)
   * - Missing files: adds a warning note instead of a broken reference
   */
  private async compileProof(
    vuln: Vulnerability,
    options: ReportGenerationOptions
  ): Promise<H1Report['proof']> {
    const proof: H1Report['proof'] = {};

    if (!vuln.proof) return proof;

    // Video — validate but keep as path (too large to embed)
    if (options.includeVideo !== false && vuln.proof.video) {
      const exists = await PoCGenerator.fileExists(vuln.proof.video);
      proof.video = exists
        ? vuln.proof.video
        : `[WARNING: Video file not found: ${vuln.proof.video}]`;
    }

    // Screenshots — validate existence, keep path for H1 attachment upload
    if (options.includeScreenshots !== false && vuln.proof.screenshots) {
      const validated: string[] = [];
      for (const screenshot of vuln.proof.screenshots) {
        const exists = await PoCGenerator.fileExists(screenshot);
        if (exists) {
          validated.push(screenshot);
        } else {
          validated.push(`[WARNING: Screenshot not found: ${screenshot}]`);
        }
      }
      proof.screenshots = validated;
    }

    // Logs — read file content and embed as code blocks
    if (options.includeLogs !== false && vuln.proof.logs) {
      const embedded: string[] = [];
      for (const logPath of vuln.proof.logs) {
        const content = await PoCGenerator.readFileContent(logPath);
        if (content !== null) {
          // Embed the content as a code block with the filename as label
          const filename = logPath.split('/').pop() ?? logPath;
          embedded.push(`**${filename}:**\n\`\`\`\n${content.substring(0, 5000)}\n\`\`\``);
        } else {
          embedded.push(`[WARNING: Log file not found: ${logPath}]`);
        }
      }
      proof.logs = embedded;
    }

    return proof;
  }

  /**
   * Check if a file exists via Tauri bridge. Returns false if bridge unavailable.
   */
  static async fileExists(path: string): Promise<boolean> {
    try {
      return await invoke<boolean>('file_exists', { path });
    } catch {
      // Tauri bridge unavailable (e.g., test environment) — assume file exists
      return true;
    }
  }

  /**
   * Read file content via Tauri bridge. Returns null if file not found or bridge unavailable.
   */
  static async readFileContent(path: string): Promise<string | null> {
    try {
      return await invoke<string>('read_file_text', { path });
    } catch {
      return null;
    }
  }

  /**
   * Generate severity justification
   */
  private generateSeverityJustification(
    vuln: Vulnerability,
    prediction: SeverityPrediction
  ): string[] {
    const justification: string[] = [];
    
    // Add base severity reasoning
    justification.push(`Base severity for ${vuln.type}: ${prediction.severity}`);
    
    // Add prediction reasoning (filtered)
    prediction.reasoning.forEach(reason => {
      if (!reason.includes('confidence') && !reason.includes('Suggested bounty')) {
        justification.push(reason);
      }
    });
    
    // Add confidence indicator
    if (prediction.confidence >= 80) {
      justification.push(`✓ High confidence prediction (${prediction.confidence}%)`);
    } else if (prediction.confidence >= 60) {
      justification.push(`⚠️ Medium confidence prediction (${prediction.confidence}%)`);
    } else {
      justification.push(`⚠️ Low confidence prediction (${prediction.confidence}%) - manual review recommended`);
    }
    
    return justification;
  }

  /**
   * S3: Calculate CVSS score using the real CVSS 3.1 calculator.
   * Maps vulnerability types to proper CVSS metrics and produces both
   * a numeric score and a vector string for HackerOne reports.
   */
  private calculateRealCVSS(vulnType: string): CVSSResult {
    const metrics = estimateMetrics(vulnType);
    return calculateCVSS(metrics);
  }

  /**
   * RQ3: Format structured HTTP exchanges as markdown code blocks.
   * Falls back to extracting HTTP patterns from raw text if no structured data is available.
   */
  formatHttpEvidence(
    exchanges?: HttpExchange[],
    description?: string,
    steps?: string[],
  ): string | undefined {
    if (exchanges && exchanges.length > 0) {
      return this.formatStructuredExchanges(exchanges);
    }

    // Fallback: extract HTTP patterns from raw text
    const allText = [description ?? '', ...(steps ?? [])].join('\n');
    return this.extractHttpFromText(allText) || undefined;
  }

  private formatStructuredExchanges(exchanges: HttpExchange[]): string {
    const parts: string[] = [];

    // P0-5-d: Show up to 10 exchanges, ranked by relevance to the vuln proof.
    // Ranking heuristic (higher = more relevant):
    //   +3 method is non-GET (POST/PUT/DELETE/PATCH = state-changing, exploitation step)
    //   +2 status is anomalous (4xx, 5xx, or unusual 2xx range often proves impact)
    //   +1 response body contains an obvious indicator (error, alert, ENTITY, etc.)
    //   +index/exchanges.length: later requests usually demonstrate the exploit
    // The original positional order is preserved as a tiebreaker so multi-step
    // chains read top-to-bottom in the report.
    const ranked = exchanges
      .map((ex, originalIndex) => ({ ex, originalIndex, score: this.exchangeRelevanceScore(ex, originalIndex, exchanges.length) }))
      .sort((a, b) => b.score - a.score || a.originalIndex - b.originalIndex)
      .slice(0, 10)
      .sort((a, b) => a.originalIndex - b.originalIndex)
      .map(r => r.ex);
    const displayExchanges = ranked;

    for (let i = 0; i < displayExchanges.length; i++) {
      const ex = displayExchanges[i];
      const label = displayExchanges.length > 1 ? ` ${i + 1}` : '';

      // Request
      parts.push(`**Request${label}:**`);
      let reqBlock = `${ex.request.method} ${this.extractPath(ex.request.url)} HTTP/1.1\n`;
      reqBlock += `Host: ${this.extractHost(ex.request.url)}`;

      if (ex.request.headers) {
        for (const [key, value] of Object.entries(ex.request.headers)) {
          if (key.toLowerCase() !== 'host') {
            reqBlock += `\n${key}: ${value}`;
          }
        }
      }

      if (ex.request.body) {
        reqBlock += `\n\n${ex.request.body}`;
      }

      parts.push('```http\n' + reqBlock + '\n```');

      // Response
      parts.push(`**Response${label}:**`);
      let resBlock = `HTTP/1.1 ${ex.response.status}`;
      if (ex.response.statusText) {
        resBlock += ` ${ex.response.statusText}`;
      }

      if (ex.response.headers) {
        // Show key security-relevant headers only
        const importantHeaders = ['content-type', 'set-cookie', 'location', 'access-control-allow-origin',
          'x-frame-options', 'content-security-policy', 'authorization', 'www-authenticate'];
        for (const [key, value] of Object.entries(ex.response.headers)) {
          if (importantHeaders.includes(key.toLowerCase())) {
            resBlock += `\n${key}: ${value}`;
          }
        }
      }

      if (ex.response.bodySnippet) {
        // P0-5-c: Raise body-snippet cap from 500 → 2000 chars on the most-relevant
        // exchange (the last one — typically the exploitation step that proves
        // impact); keep 500 chars on context exchanges so reports don't bloat.
        // The "$500 vs $5000" delta per docs/RESEARCH_H1_REPORT_QUALITY.md is
        // showing exact data accessed; 500 chars often truncates that proof.
        const isMostRelevant = i === displayExchanges.length - 1;
        const snippetLimit = isMostRelevant ? 2000 : 500;
        const snippet = ex.response.bodySnippet.length > snippetLimit
          ? ex.response.bodySnippet.substring(0, snippetLimit) + '\n[...truncated]'
          : ex.response.bodySnippet;
        resBlock += `\n\n${snippet}`;
      }

      parts.push('```http\n' + resBlock + '\n```');

      // Curl command for this exchange
      parts.push(`**Curl command${label}:**`);
      parts.push('```bash\n' + PoCGenerator.generateCurlCommand(ex) + '\n```');

      if (i < displayExchanges.length - 1) {
        parts.push('---');
      }
    }

    return parts.join('\n\n');
  }

  /**
   * P0-5-d: Score an HttpExchange by likely relevance to the vuln proof.
   * See ranking heuristic in formatStructuredExchanges() above.
   */
  private exchangeRelevanceScore(ex: HttpExchange, index: number, total: number): number {
    let score = 0;
    if (ex.request.method !== 'GET') score += 3;
    const status = ex.response.status;
    if (status >= 400 || (status >= 200 && status !== 200 && status !== 204)) score += 2;
    const body = (ex.response.bodySnippet ?? '').toLowerCase();
    if (/error|exception|denied|forbidden|alert\(|<script|entity|union\s+select|sleep\s*\(|sqlstate/i.test(body)) score += 1;
    // Later requests usually carry the exploit payload
    score += (total > 1) ? (index / (total - 1)) : 0;
    return score;
  }

  private extractHttpFromText(text: string): string | null {
    // Look for HTTP-like patterns in raw text and format them
    const httpPattern = /(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\/\S+)\s+HTTP\/\d\.\d/g;
    const matches = text.match(httpPattern);
    if (!matches || matches.length === 0) return null;

    return `*Note: HTTP evidence extracted from agent text output (no structured exchange data available)*\n\n` +
      matches.slice(0, 3).map(m => '```http\n' + m + '\n```').join('\n\n');
  }

  /**
   * RQ5: Generate executable reproduction commands from HTTP exchanges.
   */
  private generateQuickReproduction(
    exchanges?: HttpExchange[],
    vuln?: Vulnerability,
  ): string | undefined {
    const parts: string[] = [];

    if (exchanges && exchanges.length > 0) {
      // Generate curl for the most significant exchange (the one that demonstrates the vuln)
      // Prefer non-GET requests, or the last exchange (most likely to be the exploitation step)
      const significantExchange = exchanges.find(e => e.request.method !== 'GET') ?? exchanges[exchanges.length - 1];

      parts.push('**Curl:**');
      parts.push('```bash\n' + PoCGenerator.generateCurlCommand(significantExchange) + '\n```');

      // For multi-step findings, generate a Python script
      if (exchanges.length >= 2) {
        parts.push('\n**Python (multi-step):**');
        parts.push('```python\n' + this.generatePythonScript(exchanges) + '\n```');
      }
    } else if (vuln) {
      // Fallback: generate a basic curl from the vuln URL and steps
      const urlMatch = vuln.url.match(/^https?:\/\/\S+/);
      if (urlMatch) {
        parts.push('**Curl:**');
        parts.push(`\`\`\`bash\ncurl -v "${vuln.url}"\n\`\`\``);
      }
    }

    return parts.length > 0 ? parts.join('\n') : undefined;
  }

  /**
   * Generate a curl command from an HttpExchange.
   */
  static generateCurlCommand(exchange: HttpExchange): string {
    const parts = ['curl'];

    // Method (only explicit if not GET)
    if (exchange.request.method !== 'GET') {
      parts.push(`-X ${exchange.request.method}`);
    }

    // Headers
    if (exchange.request.headers) {
      for (const [key, value] of Object.entries(exchange.request.headers)) {
        // Redact sensitive headers
        const safeValue = key.toLowerCase() === 'authorization'
          ? value.substring(0, 15) + '...[REDACTED]'
          : value;
        parts.push(`-H '${key}: ${safeValue}'`);
      }
    }

    // Body
    if (exchange.request.body) {
      parts.push(`-d '${exchange.request.body.replace(/'/g, "'\\''")}'`);
    }

    // URL (always last)
    parts.push(`'${exchange.request.url}'`);

    return parts.join(' \\\n  ');
  }

  private generatePythonScript(exchanges: HttpExchange[]): string {
    const lines: string[] = ['import requests', '', 's = requests.Session()', ''];

    for (let i = 0; i < exchanges.length; i++) {
      const ex = exchanges[i];
      const method = ex.request.method.toLowerCase();
      const comment = i === exchanges.length - 1 ? '# Exploitation step' : `# Step ${i + 1}`;
      lines.push(comment);

      let call = `r${i + 1} = s.${method}('${ex.request.url}'`;

      if (ex.request.headers) {
        const headerStr = JSON.stringify(ex.request.headers);
        call += `, headers=${headerStr}`;
      }

      if (ex.request.body) {
        call += `, data='${ex.request.body.replace(/'/g, "\\'")}'`;
      }

      call += ')';
      lines.push(call);
      lines.push(`print(f'Step ${i + 1}: {r${i + 1}.status_code}')`);
      lines.push('');
    }

    lines.push(`print(f'Final response: {r${exchanges.length}.text[:500]}')`);
    return lines.join('\n');
  }

  private extractPath(url: string): string {
    try {
      const parsed = new URL(url);
      return parsed.pathname + parsed.search;
    } catch {
      return url;
    }
  }

  private extractHost(url: string): string {
    try {
      const parsed = new URL(url);
      return parsed.host;
    } catch {
      return 'unknown';
    }
  }

  /**
   * Get CWE weakness ID from vulnerability type
   */
  private getWeaknessId(type: string): string {
    const weaknessMap: Record<string, string> = {
      'oauth': '346',           // CWE-346: Origin Validation Error
      'oauth_misconfiguration': '346',
      'open_redirect': '601',   // CWE-601: URL Redirection to Untrusted Site
      'ssrf': '918',           // CWE-918: Server-Side Request Forgery
      'xss': '79',             // CWE-79: Cross-site Scripting
      'sql_injection': '89',   // CWE-89: SQL Injection
      'idor': '639',           // CWE-639: Authorization Bypass
      'csrf': '352',           // CWE-352: Cross-Site Request Forgery
      'xxe': '611',            // CWE-611: XML External Entity
      'rce': '94',             // CWE-94: Code Injection
      'command_injection': '78', // CWE-78: OS Command Injection
      'path_traversal': '22',  // CWE-22: Path Traversal
      'authentication_bypass': '287', // CWE-287: Authentication Bypass
      'privilege_escalation': '269', // CWE-269: Privilege Escalation
    };
    
    const normalizedType = type.toLowerCase().replace(/[_\s-]/g, '_');
    
    for (const [key, value] of Object.entries(weaknessMap)) {
      if (normalizedType.includes(key) || key.includes(normalizedType)) {
        return value;
      }
    }
    
    return '1035'; // CWE-1035: Generic
  }

  /**
   * Get default bounty range for severity
   */
  private getDefaultBountyRange(severity: string): { min: number; max: number } {
    const ranges: Record<string, { min: number; max: number }> = {
      critical: { min: 5000, max: 50000 },
      high: { min: 2000, max: 15000 },
      medium: { min: 500, max: 5000 },
      low: { min: 100, max: 1000 },
    };
    
    return ranges[severity] || { min: 500, max: 5000 };
  }
}

export default PoCGenerator;
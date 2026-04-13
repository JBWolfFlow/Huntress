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
import { REPORT_TEMPLATES, fillTemplate } from './templates';
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
    };
  }

  /**
   * Convert report to HackerOne markdown format
   */
  toMarkdown(report: H1Report): string {
    let markdown = `# ${report.title}\n\n`;

    // Severity and bounty
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

    // Description
    markdown += `## Description\n\n${report.description}\n\n`;

    // Impact
    markdown += `## Impact\n\n${report.impact}\n\n`;

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

    // Proof of Concept
    if (report.proof.video || report.proof.screenshots?.length || report.proof.logs?.length) {
      markdown += `## Proof of Concept\n\n`;

      if (report.proof.video) {
        markdown += `**Video Recording:** ${report.proof.video}\n\n`;
      }

      if (report.proof.screenshots && report.proof.screenshots.length > 0) {
        markdown += `**Screenshots:**\n`;
        report.proof.screenshots.forEach((screenshot, index) => {
          markdown += `- Screenshot ${index + 1}: ${screenshot}\n`;
        });
        markdown += '\n';
      }

      if (report.proof.logs && report.proof.logs.length > 0) {
        markdown += `**Logs:**\n`;
        report.proof.logs.forEach((log, index) => {
          markdown += `- Log ${index + 1}: ${log}\n`;
        });
        markdown += '\n';
      }
    }

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

    // Show up to 5 most relevant exchanges (the ones most likely to demonstrate the vuln)
    const displayExchanges = exchanges.slice(0, 5);

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
        const snippetLimit = 500;
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
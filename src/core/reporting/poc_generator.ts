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
import { REPORT_TEMPLATES, fillTemplate } from './templates';

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

    // 7. Compile proof/evidence
    const proof = this.compileProof(vuln, options);

    // 8. Generate severity justification
    const severityJustification = this.generateSeverityJustification(
      vuln,
      severityPrediction
    );

    // 9. Calculate CVSS score (if applicable)
    const cvssScore = this.calculateCVSS(vuln, severityPrediction.severity);

    // 10. Get CWE weakness ID
    const weaknessId = this.getWeaknessId(vuln.type);

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
      cvssScore,
      weaknessId,
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
      markdown += `**CVSS Score:** ${report.cvssScore}\n`;
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
   * Compile proof/evidence
   */
  private compileProof(
    vuln: Vulnerability,
    options: ReportGenerationOptions
  ): H1Report['proof'] {
    const proof: H1Report['proof'] = {};
    
    if (vuln.proof) {
      if (options.includeVideo !== false && vuln.proof.video) {
        proof.video = vuln.proof.video;
      }
      
      if (options.includeScreenshots !== false && vuln.proof.screenshots) {
        proof.screenshots = vuln.proof.screenshots;
      }
      
      if (options.includeLogs !== false && vuln.proof.logs) {
        proof.logs = vuln.proof.logs;
      }
    }
    
    return proof;
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
   * Calculate CVSS score (simplified)
   */
  private calculateCVSS(vuln: Vulnerability, severity: string): number {
    // Simplified CVSS calculation based on severity
    const baseScores: Record<string, number> = {
      critical: 9.5,
      high: 7.5,
      medium: 5.5,
      low: 3.5,
    };
    
    let score = baseScores[severity] || 5.0;
    
    // Adjust based on vulnerability characteristics
    const description = vuln.description.toLowerCase();
    const impact = vuln.impact.toLowerCase();
    const combined = `${description} ${impact}`;
    
    // Increase for RCE
    if (/remote.*code.*execution|rce/i.test(combined)) {
      score = Math.min(score + 1.0, 10.0);
    }
    
    // Increase for authentication bypass
    if (/auth.*bypass|bypass.*auth/i.test(combined)) {
      score = Math.min(score + 0.8, 10.0);
    }
    
    // Decrease if authentication required
    if (/authenticated|requires.*login/i.test(combined)) {
      score = Math.max(score - 0.5, 0.1);
    }
    
    // Decrease if user interaction required
    if (/user.*interaction|click/i.test(combined)) {
      score = Math.max(score - 0.3, 0.1);
    }
    
    return Math.round(score * 10) / 10;
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
/**
 * Severity & Bounty Predictor (Phase 4)
 * 
 * CRITICAL: Stops you from low-balling $25k bugs
 * - Predicts severity based on YOUR historical payouts
 * - Learns from accepted reports
 * - Ensures correct severity assessment
 * - Provides confidence-based recommendations
 */

import { QdrantClient } from '../memory/qdrant_client';
import type { Vulnerability } from '../../utils/duplicate_checker';
import { EmbeddingService, VECTOR_DIM } from '../memory/hunt_memory';

export interface SeverityPrediction {
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;  // 0-100
  reasoning: string[];
  suggestedBounty: { min: number; max: number };
  historicalData: {
    similarReports: number;
    averageBounty: number;
    acceptanceRate: number;
  };
}

export interface BountyRange {
  min: number;
  max: number;
  confidence: number;
  basedOn: string[];
}

export interface AcceptedReport {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  bountyAmount: number;
  program: string;
  acceptedAt: number;
  description: string;
  impact: string;
  cvssScore?: number;
}

export interface ProgramBountyRanges {
  critical?: { min: number; max: number };
  high?: { min: number; max: number };
  medium?: { min: number; max: number };
  low?: { min: number; max: number };
}

export interface VulnerabilityFeatures {
  type: string;
  hasAuthBypass: boolean;
  hasDataExfiltration: boolean;
  hasRCE: boolean;
  hasPrivilegeEscalation: boolean;
  affectsMultipleUsers: boolean;
  requiresAuthentication: boolean;
  requiresUserInteraction: boolean;
  impactScore: number;  // 0-10
  exploitabilityScore: number;  // 0-10
}

export class SeverityPredictor {
  private qdrant: QdrantClient;
  private embedder: EmbeddingService;
  private programBountyRanges?: ProgramBountyRanges;
  private programName?: string;

  /** Dimension of the TF-IDF embedding vectors used by this predictor */
  static readonly EMBEDDING_DIM = VECTOR_DIM;

  // Vulnerability type to base severity mapping
  private readonly severityWeights = {
    // Critical vulnerabilities
    'rce': { base: 'critical', weight: 1.0 },
    'sql_injection': { base: 'critical', weight: 0.95 },
    'authentication_bypass': { base: 'critical', weight: 0.9 },
    'privilege_escalation': { base: 'high', weight: 0.85 },
    
    // High vulnerabilities
    'oauth_misconfiguration': { base: 'high', weight: 0.8 },
    'idor': { base: 'high', weight: 0.75 },
    'xxe': { base: 'high', weight: 0.75 },
    'ssrf': { base: 'high', weight: 0.7 },
    
    // Medium vulnerabilities
    'xss': { base: 'medium', weight: 0.6 },
    'csrf': { base: 'medium', weight: 0.55 },
    'open_redirect': { base: 'medium', weight: 0.5 },
    
    // Low vulnerabilities
    'information_disclosure': { base: 'low', weight: 0.3 },
    'missing_security_headers': { base: 'low', weight: 0.2 },
  };

  // Industry average bounties by severity (2025 data)
  private readonly industryAverages = {
    critical: { min: 5000, max: 50000, avg: 15000 },
    high: { min: 2000, max: 15000, avg: 4800 },
    medium: { min: 500, max: 5000, avg: 1500 },
    low: { min: 100, max: 1000, avg: 300 },
  };

  constructor(
    qdrant: QdrantClient,
    programBountyRanges?: ProgramBountyRanges,
    programName?: string
  ) {
    this.qdrant = qdrant;
    this.embedder = new EmbeddingService();
    this.programBountyRanges = programBountyRanges;
    this.programName = programName;
  }

  /**
   * Main prediction method - predicts severity and bounty
   */
  async predictSeverity(vuln: Vulnerability): Promise<SeverityPrediction> {
    const reasoning: string[] = [];

    // 1. Extract features from vulnerability
    const features = this.extractFeatures(vuln);
    
    // 2. Get base severity from vulnerability type
    const baseSeverity = this.getBaseSeverity(vuln.type);
    reasoning.push(`Base severity for ${vuln.type}: ${baseSeverity}`);

    // 3. Get historical data from similar vulnerabilities
    const historicalData = await this.getHistoricalData(vuln);
    
    if (historicalData.similarReports > 0) {
      reasoning.push(
        `Found ${historicalData.similarReports} similar reports with avg bounty $${historicalData.averageBounty.toLocaleString()}`
      );
    }

    // 4. Calculate impact-adjusted severity
    const adjustedSeverity = this.adjustSeverityByImpact(
      baseSeverity,
      features,
      historicalData
    );
    
    if (adjustedSeverity !== baseSeverity) {
      reasoning.push(`Adjusted severity from ${baseSeverity} to ${adjustedSeverity} based on impact analysis`);
    }

    // 5. Calculate confidence score
    const confidence = this.calculateConfidence(
      features,
      historicalData,
      adjustedSeverity
    );

    // 6. Predict bounty range
    const suggestedBounty = await this.predictBounty(
      adjustedSeverity,
      vuln,
      historicalData
    );

    reasoning.push(
      `Suggested bounty: $${suggestedBounty.min.toLocaleString()} - $${suggestedBounty.max.toLocaleString()}`
    );

    // 7. Add confidence-based recommendations
    if (confidence < 60) {
      reasoning.push('⚠️ Low confidence - consider manual review');
    } else if (confidence >= 80) {
      reasoning.push('✓ High confidence prediction');
    }

    return {
      severity: adjustedSeverity,
      confidence,
      reasoning,
      suggestedBounty,
      historicalData,
    };
  }

  /**
   * Predict bounty range based on severity and historical data
   */
  async predictBounty(
    severity: 'critical' | 'high' | 'medium' | 'low',
    vuln: Vulnerability,
    historicalData: SeverityPrediction['historicalData']
  ): Promise<BountyRange> {
    const basedOn: string[] = [];
    let min: number;
    let max: number;
    let confidence = 50;

    // 1. Use program-specific bounty ranges if available
    if (this.programBountyRanges && this.programBountyRanges[severity]) {
      const programRange = this.programBountyRanges[severity]!;
      min = programRange.min;
      max = programRange.max;
      basedOn.push(`${this.programName || 'Program'} bounty table`);
      confidence += 30;
    } else {
      // Use industry averages
      const industryRange = this.industryAverages[severity];
      min = industryRange.min;
      max = industryRange.max;
      basedOn.push('Industry averages (2025)');
      confidence += 10;
    }

    // 2. Adjust based on historical data
    if (historicalData.similarReports >= 3) {
      const avgBounty = historicalData.averageBounty;
      
      // Adjust range to be centered around historical average
      const range = max - min;
      min = Math.max(min, Math.floor(avgBounty * 0.7));
      max = Math.min(max, Math.ceil(avgBounty * 1.5));
      
      basedOn.push(`${historicalData.similarReports} similar reports (avg: $${avgBounty.toLocaleString()})`);
      confidence += 20;
    }

    // 3. Adjust based on vulnerability features
    const features = this.extractFeatures(vuln);
    
    if (features.hasRCE || features.hasAuthBypass) {
      // High-impact vulnerabilities deserve higher bounties
      min = Math.floor(min * 1.5);
      max = Math.floor(max * 1.5);
      basedOn.push('High-impact vulnerability multiplier (1.5x)');
      confidence += 10;
    }

    if (features.affectsMultipleUsers && !features.requiresUserInteraction) {
      // Easy to exploit, affects many users
      min = Math.floor(min * 1.2);
      max = Math.floor(max * 1.2);
      basedOn.push('Wide impact, low complexity (1.2x)');
      confidence += 5;
    }

    // 4. Cap confidence at 100
    confidence = Math.min(confidence, 100);

    return {
      min,
      max,
      confidence,
      basedOn,
    };
  }

  /**
   * Learn from accepted report - update historical data
   */
  async updateModel(report: AcceptedReport): Promise<void> {
    try {
      const embedding = this.createEmbedding(report);

      // Store in Qdrant with metadata
      await this.qdrant.upsertPoint({
        id: report.id,
        vector: embedding,
        payload: {
          type: report.type,
          severity: report.severity,
          bountyAmount: report.bountyAmount,
          program: report.program,
          acceptedAt: report.acceptedAt,
          description: report.description,
          impact: report.impact,
          cvssScore: report.cvssScore,
          // Training metadata
          isAccepted: true,
          isTrainingData: true,
        },
      });

      console.log(`✓ Learned from accepted report: ${report.type} - $${report.bountyAmount}`);
    } catch (error) {
      console.error('Error updating model with accepted report:', error);
    }
  }

  /**
   * Extract features from vulnerability for ML analysis
   */
  private extractFeatures(vuln: Vulnerability): VulnerabilityFeatures {
    const description = vuln.description.toLowerCase();
    const impact = vuln.impact.toLowerCase();
    const combined = `${description} ${impact}`;

    return {
      type: vuln.type,
      hasAuthBypass: /auth.*bypass|bypass.*auth|authentication.*bypass/i.test(combined),
      hasDataExfiltration: /data.*exfil|steal.*data|extract.*data|leak/i.test(combined),
      hasRCE: /remote.*code.*execution|rce|command.*injection|code.*execution/i.test(combined),
      hasPrivilegeEscalation: /privilege.*escalation|escalate.*privilege|admin.*access/i.test(combined),
      affectsMultipleUsers: /all.*users|multiple.*users|every.*user|mass/i.test(combined),
      requiresAuthentication: /authenticated|logged.*in|requires.*login/i.test(combined),
      requiresUserInteraction: /user.*interaction|click|social.*engineering|phishing/i.test(combined),
      impactScore: this.calculateImpactScore(vuln),
      exploitabilityScore: this.calculateExploitabilityScore(vuln),
    };
  }

  /**
   * Calculate impact score (0-10)
   */
  private calculateImpactScore(vuln: Vulnerability): number {
    let score = 5; // Base score

    const impact = vuln.impact.toLowerCase();
    const description = vuln.description.toLowerCase();
    const combined = `${impact} ${description}`;

    // Increase for data breaches
    if (/data.*breach|steal.*data|exfiltrate/i.test(combined)) score += 2;
    
    // Increase for authentication bypass
    if (/auth.*bypass|bypass.*auth/i.test(combined)) score += 2;
    
    // Increase for RCE
    if (/remote.*code|rce|command.*injection/i.test(combined)) score += 3;
    
    // Increase for privilege escalation
    if (/privilege.*escalation|admin.*access/i.test(combined)) score += 2;
    
    // Decrease for information disclosure only
    if (/information.*disclosure/i.test(combined) && score === 5) score -= 2;

    return Math.min(Math.max(score, 0), 10);
  }

  /**
   * Calculate exploitability score (0-10)
   */
  private calculateExploitabilityScore(vuln: Vulnerability): number {
    let score = 5; // Base score

    const description = vuln.description.toLowerCase();
    const steps = vuln.steps.join(' ').toLowerCase();
    const combined = `${description} ${steps}`;

    // Decrease for authentication required
    if (/authenticated|logged.*in|requires.*login/i.test(combined)) score -= 2;
    
    // Decrease for user interaction required
    if (/user.*interaction|click|social.*engineering/i.test(combined)) score -= 1;
    
    // Increase for unauthenticated
    if (/unauthenticated|no.*auth|without.*auth/i.test(combined)) score += 2;
    
    // Increase for simple exploitation
    if (/simple|easy|trivial|straightforward/i.test(combined)) score += 1;
    
    // Decrease for complex exploitation
    if (/complex|difficult|requires.*knowledge|advanced/i.test(combined)) score -= 2;

    return Math.min(Math.max(score, 0), 10);
  }

  /**
   * Get base severity from vulnerability type
   */
  private getBaseSeverity(type: string): 'critical' | 'high' | 'medium' | 'low' {
    const normalizedType = type.toLowerCase().replace(/[_\s-]/g, '_');
    
    for (const [key, value] of Object.entries(this.severityWeights)) {
      if (normalizedType.includes(key) || key.includes(normalizedType)) {
        return value.base as 'critical' | 'high' | 'medium' | 'low';
      }
    }

    // Default to medium if unknown
    return 'medium';
  }

  /**
   * Adjust severity based on impact analysis
   */
  private adjustSeverityByImpact(
    baseSeverity: 'critical' | 'high' | 'medium' | 'low',
    features: VulnerabilityFeatures,
    historicalData: SeverityPrediction['historicalData']
  ): 'critical' | 'high' | 'medium' | 'low' {
    const severityLevels = ['low', 'medium', 'high', 'critical'];
    let currentLevel = severityLevels.indexOf(baseSeverity);

    // Upgrade severity for high-impact features
    if (features.hasRCE || features.hasAuthBypass) {
      currentLevel = Math.max(currentLevel, 3); // At least critical
    } else if (features.hasPrivilegeEscalation || features.hasDataExfiltration) {
      currentLevel = Math.max(currentLevel, 2); // At least high
    }

    // Consider exploitability
    if (features.exploitabilityScore >= 8 && features.impactScore >= 7) {
      currentLevel = Math.min(currentLevel + 1, 3); // Upgrade by one level
    }

    // Consider historical data
    if (historicalData.similarReports >= 5) {
      // If similar reports had higher average bounty, consider upgrading
      const avgBounty = historicalData.averageBounty;
      const currentAvg = this.industryAverages[baseSeverity].avg;
      
      if (avgBounty > currentAvg * 1.5) {
        currentLevel = Math.min(currentLevel + 1, 3);
      }
    }

    return severityLevels[currentLevel] as 'critical' | 'high' | 'medium' | 'low';
  }

  /**
   * Calculate confidence score for prediction
   */
  private calculateConfidence(
    features: VulnerabilityFeatures,
    historicalData: SeverityPrediction['historicalData'],
    predictedSeverity: 'critical' | 'high' | 'medium' | 'low'
  ): number {
    let confidence = 50; // Base confidence

    // Increase confidence based on historical data
    if (historicalData.similarReports >= 10) {
      confidence += 30;
    } else if (historicalData.similarReports >= 5) {
      confidence += 20;
    } else if (historicalData.similarReports >= 2) {
      confidence += 10;
    }

    // Increase confidence for well-known vulnerability types
    const knownTypes = Object.keys(this.severityWeights);
    if (knownTypes.some(type => features.type.toLowerCase().includes(type))) {
      confidence += 15;
    }

    // Increase confidence for clear impact indicators
    if (features.hasRCE || features.hasAuthBypass || features.hasPrivilegeEscalation) {
      confidence += 10;
    }

    // Increase confidence based on acceptance rate
    if (historicalData.acceptanceRate >= 0.8) {
      confidence += 10;
    } else if (historicalData.acceptanceRate >= 0.6) {
      confidence += 5;
    }

    // Decrease confidence for edge cases
    if (features.impactScore < 3 && predictedSeverity === 'critical') {
      confidence -= 20; // Low impact but critical severity is suspicious
    }

    return Math.min(Math.max(confidence, 0), 100);
  }

  /**
   * Get historical data from similar vulnerabilities
   */
  private async getHistoricalData(
    vuln: Vulnerability
  ): Promise<SeverityPrediction['historicalData']> {
    try {
      const embedding = this.createEmbedding({
        type: vuln.type,
        description: vuln.description,
        impact: vuln.impact,
      });

      // Search for similar accepted reports
      const similar = await this.qdrant.searchWithFilter(
        embedding,
        { isAccepted: true, isTrainingData: true },
        20
      );

      if (similar.length === 0) {
        return {
          similarReports: 0,
          averageBounty: 0,
          acceptanceRate: 0,
        };
      }

      // Calculate statistics
      const bounties = similar
        .map(r => r.payload.bountyAmount as number)
        .filter(b => b > 0);

      const averageBounty = bounties.length > 0
        ? Math.round(bounties.reduce((a, b) => a + b, 0) / bounties.length)
        : 0;

      const acceptanceRate = similar.length > 0 ? 1.0 : 0; // All results are accepted

      return {
        similarReports: similar.length,
        averageBounty,
        acceptanceRate,
      };
    } catch (error) {
      console.error('Error getting historical data:', error);
      return {
        similarReports: 0,
        averageBounty: 0,
        acceptanceRate: 0,
      };
    }
  }

  /**
   * Create embedding for text using TF-IDF with security-domain vocabulary.
   * Produces L2-normalized vectors of dimension VECTOR_DIM (~150).
   */
  private createEmbedding(data: object): number[] {
    const text = Object.values(data)
      .filter((v): v is string => typeof v === 'string')
      .join(' ');
    return this.embedder.embed(text);
  }

  /**
   * Update program-specific bounty ranges
   */
  setProgramBountyRanges(ranges: ProgramBountyRanges, programName?: string): void {
    this.programBountyRanges = ranges;
    this.programName = programName;
  }

  /**
   * Get program bounty ranges
   */
  getProgramBountyRanges(): ProgramBountyRanges | undefined {
    return this.programBountyRanges;
  }
}

export default SeverityPredictor;
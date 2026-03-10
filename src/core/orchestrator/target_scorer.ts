/**
 * Target Prioritization Scorer
 *
 * Scores targets before hunting to maximize ROI. Higher scores mean higher
 * priority for hunting. Based on XBOW's target selection strategy.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface TargetScore {
  target: string;
  totalScore: number;
  factors: ScoreFactor[];
  recommendation: string;
}

export interface ScoreFactor {
  name: string;
  score: number;
  maxScore: number;
  reasoning: string;
}

export interface TargetMetadata {
  target: string;
  /** Technology stack detected */
  technologies?: string[];
  /** WAF detected */
  waf?: string | null;
  /** Number of endpoints discovered */
  endpointCount?: number;
  /** Historical bounty payouts for this program */
  historicalPayouts?: { min: number; max: number; average: number };
  /** Average triage time in hours */
  avgTriageTime?: number;
  /** How recently the asset was added to scope */
  addedToScopeDate?: Date;
  /** Number of researchers known to be active on this program */
  competitorDensity?: number;
  /** Number of open ports */
  openPorts?: number;
  /** HTTP status code */
  statusCode?: number;
  /** Content type */
  contentType?: string;
}

// ─── Scoring Functions ───────────────────────────────────────────────────────

/** Known vulnerable frameworks/technologies score higher */
function scoreTechStack(technologies: string[]): ScoreFactor {
  const techLower = technologies.map(t => t.toLowerCase());
  let score = 0;
  const reasons: string[] = [];

  // High-value targets
  const highValueTech: Record<string, number> = {
    'wordpress': 8, 'drupal': 7, 'joomla': 7,
    'graphql': 8, 'swagger': 6, 'openapi': 6,
    'php': 5, 'asp.net': 5, 'java': 4,
    'spring': 5, 'struts': 8, 'rails': 4,
    'django': 4, 'flask': 5, 'express': 4,
    'nginx': 2, 'apache': 2, 'iis': 3,
    'jquery': 2, 'angular': 3, 'react': 2,
    'jenkins': 7, 'gitlab': 6, 'jira': 5,
    'elasticsearch': 6, 'kibana': 5, 'grafana': 5,
    'tomcat': 5, 'weblogic': 7, 'websphere': 6,
  };

  for (const tech of techLower) {
    for (const [keyword, value] of Object.entries(highValueTech)) {
      if (tech.includes(keyword)) {
        score += value;
        reasons.push(`${keyword} (+${value})`);
      }
    }
  }

  return {
    name: 'technology_stack',
    score: Math.min(score, 20),
    maxScore: 20,
    reasoning: reasons.length > 0 ? reasons.join(', ') : 'No notable technologies detected',
  };
}

/** WAF-free targets are easier to test */
function scoreWAF(waf: string | null | undefined): ScoreFactor {
  if (waf === null || waf === undefined) {
    return {
      name: 'waf_presence',
      score: 10,
      maxScore: 10,
      reasoning: 'No WAF detected — unfiltered testing possible',
    };
  }
  return {
    name: 'waf_presence',
    score: 3,
    maxScore: 10,
    reasoning: `WAF detected: ${waf} — bypass techniques required`,
  };
}

/** More endpoints = more attack surface */
function scoreAttackSurface(endpointCount: number | undefined): ScoreFactor {
  if (!endpointCount) {
    return { name: 'attack_surface', score: 5, maxScore: 15, reasoning: 'Endpoint count unknown' };
  }

  let score: number;
  let reasoning: string;

  if (endpointCount > 100) {
    score = 15;
    reasoning = `Large attack surface: ${endpointCount} endpoints`;
  } else if (endpointCount > 50) {
    score = 12;
    reasoning = `Good attack surface: ${endpointCount} endpoints`;
  } else if (endpointCount > 20) {
    score = 8;
    reasoning = `Moderate attack surface: ${endpointCount} endpoints`;
  } else {
    score = 4;
    reasoning = `Small attack surface: ${endpointCount} endpoints`;
  }

  return { name: 'attack_surface', score, maxScore: 15, reasoning };
}

/** Higher-paying programs are more valuable */
function scoreBountyPotential(payouts: { min: number; max: number; average: number } | undefined): ScoreFactor {
  if (!payouts) {
    return { name: 'bounty_potential', score: 5, maxScore: 15, reasoning: 'No payout data available' };
  }

  let score: number;
  if (payouts.average >= 5000) score = 15;
  else if (payouts.average >= 2000) score = 12;
  else if (payouts.average >= 1000) score = 10;
  else if (payouts.average >= 500) score = 7;
  else score = 4;

  return {
    name: 'bounty_potential',
    score,
    maxScore: 15,
    reasoning: `Average payout: $${payouts.average} (range: $${payouts.min}-$${payouts.max})`,
  };
}

/** Fast-triaging programs are preferred */
function scoreResponsiveness(avgTriageTime: number | undefined): ScoreFactor {
  if (!avgTriageTime) {
    return { name: 'responsiveness', score: 5, maxScore: 10, reasoning: 'Triage time unknown' };
  }

  let score: number;
  if (avgTriageTime <= 24) score = 10;
  else if (avgTriageTime <= 72) score = 8;
  else if (avgTriageTime <= 168) score = 5;
  else score = 2;

  return {
    name: 'responsiveness',
    score,
    maxScore: 10,
    reasoning: `Average triage time: ${avgTriageTime}h`,
  };
}

/** Recently added assets may be less hardened */
function scoreAssetFreshness(addedDate: Date | undefined): ScoreFactor {
  if (!addedDate) {
    return { name: 'asset_freshness', score: 5, maxScore: 15, reasoning: 'Asset age unknown' };
  }

  const daysSinceAdded = (Date.now() - addedDate.getTime()) / (1000 * 60 * 60 * 24);

  let score: number;
  if (daysSinceAdded <= 7) score = 15;
  else if (daysSinceAdded <= 30) score = 12;
  else if (daysSinceAdded <= 90) score = 8;
  else score = 3;

  return {
    name: 'asset_freshness',
    score,
    maxScore: 15,
    reasoning: `Added ${Math.round(daysSinceAdded)} days ago`,
  };
}

/** Fewer competitors = less duplicate risk */
function scoreCompetition(competitorDensity: number | undefined): ScoreFactor {
  if (!competitorDensity) {
    return { name: 'competition', score: 5, maxScore: 15, reasoning: 'Competitor density unknown' };
  }

  let score: number;
  if (competitorDensity <= 5) score = 15;
  else if (competitorDensity <= 20) score = 10;
  else if (competitorDensity <= 50) score = 6;
  else score = 2;

  return {
    name: 'competition',
    score,
    maxScore: 15,
    reasoning: `~${competitorDensity} active researchers`,
  };
}

// ─── Main Scoring Function ───────────────────────────────────────────────────

/**
 * Score a target based on all available metadata.
 * Returns a score from 0-100 with factor breakdown.
 */
export function scoreTarget(metadata: TargetMetadata): TargetScore {
  const factors: ScoreFactor[] = [
    scoreTechStack(metadata.technologies ?? []),
    scoreWAF(metadata.waf),
    scoreAttackSurface(metadata.endpointCount),
    scoreBountyPotential(metadata.historicalPayouts),
    scoreResponsiveness(metadata.avgTriageTime),
    scoreAssetFreshness(metadata.addedToScopeDate),
    scoreCompetition(metadata.competitorDensity),
  ];

  const totalScore = factors.reduce((sum, f) => sum + f.score, 0);
  const maxPossible = factors.reduce((sum, f) => sum + f.maxScore, 0);
  const normalizedScore = Math.round((totalScore / maxPossible) * 100);

  let recommendation: string;
  if (normalizedScore >= 75) recommendation = 'High priority — start here';
  else if (normalizedScore >= 50) recommendation = 'Good target — worth investigating';
  else if (normalizedScore >= 30) recommendation = 'Moderate — test if time permits';
  else recommendation = 'Low priority — focus elsewhere first';

  return {
    target: metadata.target,
    totalScore: normalizedScore,
    factors,
    recommendation,
  };
}

/**
 * Score and rank multiple targets.
 */
export function rankTargets(targets: TargetMetadata[]): TargetScore[] {
  return targets
    .map(scoreTarget)
    .sort((a, b) => b.totalScore - a.totalScore);
}

export default scoreTarget;

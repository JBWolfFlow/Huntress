/**
 * HackerOne Program Selector
 *
 * Scores and ranks HackerOne programs to find the best targets for hunting.
 * Optimizes for: scope width x average bounty x response time x competition level.
 *
 * Strategy for first live hunts:
 * 1. Start with VDPs (Vulnerability Disclosure Programs) — lower stakes
 * 2. Then move to paid BBPs (Bug Bounty Programs)
 * 3. Cross-check scope against H1 program page before hunting
 * 4. ALL approval gates must be set to REQUIRE APPROVAL
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export interface H1ProgramInfo {
  handle: string;
  name: string;
  programType: 'vdp' | 'bbp';
  /** Number of in-scope targets */
  scopeWidth: number;
  /** Bounty range in USD (0-0 for VDPs) */
  bountyRange: { min: number; max: number };
  /** Average response time in hours */
  avgResponseTimeHours: number;
  /** Number of reports resolved in last 90 days */
  reportsResolved90d: number;
  /** Whether the program accepts submissions */
  acceptingSubmissions: boolean;
  /** Scope targets (domains/URLs) */
  scope: string[];
  /** Technologies detected or listed */
  technologies: string[];
  /** Whether API testing is explicitly in scope */
  apiTestingInScope: boolean;
  /** Whether the program has a managed/response team */
  managedProgram: boolean;
  /** Custom notes about the program */
  notes?: string;
}

export interface ProgramScore {
  program: H1ProgramInfo;
  totalScore: number;
  factors: ProgramScoreFactor[];
  recommendation: 'hunt' | 'maybe' | 'skip';
  reasoning: string;
}

export interface ProgramScoreFactor {
  name: string;
  score: number;
  maxScore: number;
  reasoning: string;
}

// ─── Scoring Weights ────────────────────────────────────────────────────────

const SCORE_WEIGHTS = {
  scopeWidth: 0.25,        // Wider scope = more attack surface
  bountyAverage: 0.20,     // Higher bounties = better ROI
  responseTime: 0.20,      // Faster response = less wasted effort
  competition: 0.15,       // Lower competition = higher acceptance rate
  techStack: 0.10,         // Known-vulnerable tech = easier finds
  apiTesting: 0.10,        // API testing allowed = Huntress's strength
} as const;

// ─── Scoring Functions ──────────────────────────────────────────────────────

function scoreScopeWidth(scopeWidth: number): ProgramScoreFactor {
  let score: number;
  let reasoning: string;

  if (scopeWidth >= 20) {
    score = 100;
    reasoning = `Large scope (${scopeWidth} targets) — many attack vectors`;
  } else if (scopeWidth >= 10) {
    score = 80;
    reasoning = `Medium scope (${scopeWidth} targets)`;
  } else if (scopeWidth >= 5) {
    score = 60;
    reasoning = `Small scope (${scopeWidth} targets)`;
  } else if (scopeWidth >= 2) {
    score = 40;
    reasoning = `Narrow scope (${scopeWidth} targets)`;
  } else {
    score = 20;
    reasoning = `Single target scope`;
  }

  return { name: 'Scope Width', score, maxScore: 100, reasoning };
}

function scoreBountyAverage(bountyRange: { min: number; max: number }): ProgramScoreFactor {
  const avg = (bountyRange.min + bountyRange.max) / 2;
  let score: number;
  let reasoning: string;

  if (avg === 0) {
    score = 10; // VDPs still have value for practice/reputation
    reasoning = 'VDP (no monetary bounty) — good for first hunts';
  } else if (avg >= 5000) {
    score = 100;
    reasoning = `High bounty average ($${avg})`;
  } else if (avg >= 1000) {
    score = 80;
    reasoning = `Good bounty average ($${avg})`;
  } else if (avg >= 500) {
    score = 60;
    reasoning = `Moderate bounty average ($${avg})`;
  } else {
    score = 40;
    reasoning = `Low bounty average ($${avg})`;
  }

  return { name: 'Bounty Average', score, maxScore: 100, reasoning };
}

function scoreResponseTime(avgHours: number): ProgramScoreFactor {
  let score: number;
  let reasoning: string;

  if (avgHours <= 24) {
    score = 100;
    reasoning = `Excellent response time (<24h)`;
  } else if (avgHours <= 72) {
    score = 80;
    reasoning = `Good response time (<3 days)`;
  } else if (avgHours <= 168) {
    score = 60;
    reasoning = `Average response time (<1 week)`;
  } else if (avgHours <= 720) {
    score = 30;
    reasoning = `Slow response time (>1 week)`;
  } else {
    score = 10;
    reasoning = `Very slow response time (>30 days)`;
  }

  return { name: 'Response Time', score, maxScore: 100, reasoning };
}

function scoreCompetition(reportsResolved90d: number): ProgramScoreFactor {
  let score: number;
  let reasoning: string;

  // More resolved reports = more competition but also more engagement
  if (reportsResolved90d <= 5) {
    score = 90;
    reasoning = `Low competition (${reportsResolved90d} reports/90d) — less likely to hit duplicates`;
  } else if (reportsResolved90d <= 20) {
    score = 70;
    reasoning = `Moderate competition (${reportsResolved90d} reports/90d)`;
  } else if (reportsResolved90d <= 50) {
    score = 50;
    reasoning = `Active program (${reportsResolved90d} reports/90d) — higher duplicate risk`;
  } else {
    score = 30;
    reasoning = `High competition (${reportsResolved90d} reports/90d) — significant duplicate risk`;
  }

  return { name: 'Competition Level', score, maxScore: 100, reasoning };
}

function scoreTechStack(technologies: string[]): ProgramScoreFactor {
  const techLower = technologies.map(t => t.toLowerCase());
  let score = 50; // Baseline
  const reasons: string[] = [];

  // Huntress excels at these
  const highValue = ['graphql', 'rest api', 'openapi', 'swagger', 'oauth', 'jwt'];
  const moderate = ['react', 'angular', 'node.js', 'express', 'django', 'rails', 'php'];

  for (const tech of highValue) {
    if (techLower.some(t => t.includes(tech))) {
      score += 15;
      reasons.push(`${tech} (Huntress strength)`);
    }
  }
  for (const tech of moderate) {
    if (techLower.some(t => t.includes(tech))) {
      score += 5;
      reasons.push(tech);
    }
  }

  return {
    name: 'Tech Stack',
    score: Math.min(score, 100),
    maxScore: 100,
    reasoning: reasons.length > 0 ? `Favorable tech: ${reasons.join(', ')}` : 'No tech stack info',
  };
}

function scoreAPITesting(apiTestingInScope: boolean): ProgramScoreFactor {
  return {
    name: 'API Testing',
    score: apiTestingInScope ? 100 : 30,
    maxScore: 100,
    reasoning: apiTestingInScope
      ? 'API testing explicitly in scope — ideal for Huntress'
      : 'API testing not explicitly mentioned',
  };
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Score a single HackerOne program for hunting suitability.
 */
export function scoreProgram(program: H1ProgramInfo): ProgramScore {
  if (!program.acceptingSubmissions) {
    return {
      program,
      totalScore: 0,
      factors: [],
      recommendation: 'skip',
      reasoning: 'Program is not accepting submissions',
    };
  }

  const factors: ProgramScoreFactor[] = [
    scoreScopeWidth(program.scopeWidth),
    scoreBountyAverage(program.bountyRange),
    scoreResponseTime(program.avgResponseTimeHours),
    scoreCompetition(program.reportsResolved90d),
    scoreTechStack(program.technologies),
    scoreAPITesting(program.apiTestingInScope),
  ];

  const weights = Object.values(SCORE_WEIGHTS);
  const totalScore = Math.round(
    factors.reduce((sum, factor, i) => sum + factor.score * weights[i], 0),
  );

  let recommendation: 'hunt' | 'maybe' | 'skip';
  if (totalScore >= 70) recommendation = 'hunt';
  else if (totalScore >= 45) recommendation = 'maybe';
  else recommendation = 'skip';

  const topFactors = factors
    .sort((a, b) => b.score - a.score)
    .slice(0, 3)
    .map(f => f.reasoning);

  return {
    program,
    totalScore,
    factors,
    recommendation,
    reasoning: `Score: ${totalScore}/100. ${topFactors.join('. ')}.`,
  };
}

/**
 * Rank multiple programs and return them sorted by score.
 */
export function rankPrograms(programs: H1ProgramInfo[]): ProgramScore[] {
  return programs
    .map(scoreProgram)
    .sort((a, b) => b.totalScore - a.totalScore);
}

/**
 * Filter to only VDPs (for first live hunts — lower risk).
 */
export function filterVDPs(programs: H1ProgramInfo[]): H1ProgramInfo[] {
  return programs.filter(p => p.programType === 'vdp' && p.acceptingSubmissions);
}

/**
 * Generate a hunt readiness checklist for a selected program.
 */
export function generateHuntChecklist(program: H1ProgramInfo): Array<{
  item: string;
  critical: boolean;
  automated: boolean;
}> {
  return [
    { item: 'Scope parsed and loaded into BountyImporter', critical: true, automated: true },
    { item: 'Scope validated against H1 program page (manual)', critical: true, automated: false },
    { item: 'All approval gates set to REQUIRE APPROVAL', critical: true, automated: true },
    { item: 'Budget limit configured ($15 for first hunt)', critical: true, automated: true },
    { item: 'Validation pipeline active (18 validators)', critical: true, automated: true },
    { item: 'Rate limiting enabled for live target', critical: true, automated: true },
    { item: 'Stealth mode enabled (UA rotation, jitter)', critical: false, automated: true },
    { item: 'Kill switch verified operational', critical: true, automated: true },
    { item: 'API schema uploaded if available', critical: false, automated: false },
    { item: 'Auth credentials configured if needed', critical: false, automated: false },
    { item: `Program accepts submissions: ${program.acceptingSubmissions}`, critical: true, automated: true },
    { item: `Program type: ${program.programType.toUpperCase()}`, critical: false, automated: true },
  ];
}

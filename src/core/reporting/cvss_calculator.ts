/**
 * CVSS 3.1 Calculator
 *
 * Calculates CVSS 3.1 base scores and vector strings.
 * Used for accurate severity scoring on HackerOne reports.
 */

// ─── CVSS Metric Values ─────────────────────────────────────────────────────

export type AttackVector = 'N' | 'A' | 'L' | 'P';       // Network, Adjacent, Local, Physical
export type AttackComplexity = 'L' | 'H';                 // Low, High
export type PrivilegesRequired = 'N' | 'L' | 'H';         // None, Low, High
export type UserInteraction = 'N' | 'R';                   // None, Required
export type Scope = 'U' | 'C';                             // Unchanged, Changed
export type Impact = 'N' | 'L' | 'H';                     // None, Low, High

export interface CVSSMetrics {
  attackVector: AttackVector;
  attackComplexity: AttackComplexity;
  privilegesRequired: PrivilegesRequired;
  userInteraction: UserInteraction;
  scope: Scope;
  confidentialityImpact: Impact;
  integrityImpact: Impact;
  availabilityImpact: Impact;
}

export interface CVSSResult {
  score: number;
  severity: 'None' | 'Low' | 'Medium' | 'High' | 'Critical';
  vectorString: string;
}

// ─── Metric Weight Tables (CVSS 3.1 spec) ───────────────────────────────────

const AV_WEIGHTS: Record<AttackVector, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
const AC_WEIGHTS: Record<AttackComplexity, number> = { L: 0.77, H: 0.44 };
const UI_WEIGHTS: Record<UserInteraction, number> = { N: 0.85, R: 0.62 };

const PR_WEIGHTS_UNCHANGED: Record<PrivilegesRequired, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_WEIGHTS_CHANGED: Record<PrivilegesRequired, number> = { N: 0.85, L: 0.68, H: 0.50 };

const IMPACT_WEIGHTS: Record<Impact, number> = { N: 0, L: 0.22, H: 0.56 };

// ─── Calculator ──────────────────────────────────────────────────────────────

/**
 * Calculate CVSS 3.1 base score from metrics.
 */
export function calculateCVSS(metrics: CVSSMetrics): CVSSResult {
  const { attackVector, attackComplexity, privilegesRequired, userInteraction, scope,
    confidentialityImpact, integrityImpact, availabilityImpact } = metrics;

  // Impact Sub Score (ISS)
  const iss = 1 - (
    (1 - IMPACT_WEIGHTS[confidentialityImpact]) *
    (1 - IMPACT_WEIGHTS[integrityImpact]) *
    (1 - IMPACT_WEIGHTS[availabilityImpact])
  );

  // Impact
  let impact: number;
  if (scope === 'U') {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  // Exploitability
  const prWeights = scope === 'U' ? PR_WEIGHTS_UNCHANGED : PR_WEIGHTS_CHANGED;
  const exploitability = 8.22 *
    AV_WEIGHTS[attackVector] *
    AC_WEIGHTS[attackComplexity] *
    prWeights[privilegesRequired] *
    UI_WEIGHTS[userInteraction];

  // Base Score
  let score: number;
  if (impact <= 0) {
    score = 0;
  } else if (scope === 'U') {
    score = roundUp(Math.min(impact + exploitability, 10));
  } else {
    score = roundUp(Math.min(1.08 * (impact + exploitability), 10));
  }

  const vectorString = `CVSS:3.1/AV:${attackVector}/AC:${attackComplexity}/PR:${privilegesRequired}/UI:${userInteraction}/S:${scope}/C:${confidentialityImpact}/I:${integrityImpact}/A:${availabilityImpact}`;

  return {
    score,
    severity: scoreToSeverity(score),
    vectorString,
  };
}

/** CVSS 3.1 rounding: round up to 1 decimal place */
function roundUp(value: number): number {
  return Math.ceil(value * 10) / 10;
}

function scoreToSeverity(score: number): CVSSResult['severity'] {
  if (score === 0) return 'None';
  if (score <= 3.9) return 'Low';
  if (score <= 6.9) return 'Medium';
  if (score <= 8.9) return 'High';
  return 'Critical';
}

/**
 * Estimate CVSS metrics from a vulnerability type.
 * Returns reasonable defaults that can be overridden.
 */
export function estimateMetrics(vulnType: string): CVSSMetrics {
  const defaults: Record<string, CVSSMetrics> = {
    xss_reflected: { attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'R', scope: 'C', confidentialityImpact: 'L', integrityImpact: 'L', availabilityImpact: 'N' },
    xss_stored: { attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'L', userInteraction: 'R', scope: 'C', confidentialityImpact: 'L', integrityImpact: 'L', availabilityImpact: 'N' },
    xss_dom: { attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'R', scope: 'C', confidentialityImpact: 'L', integrityImpact: 'L', availabilityImpact: 'N' },
    sqli_error: { attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N', scope: 'U', confidentialityImpact: 'H', integrityImpact: 'H', availabilityImpact: 'H' },
    sqli_blind_time: { attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N', scope: 'U', confidentialityImpact: 'H', integrityImpact: 'N', availabilityImpact: 'N' },
    sqli_blind_boolean: { attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N', scope: 'U', confidentialityImpact: 'H', integrityImpact: 'N', availabilityImpact: 'N' },
    ssrf: { attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N', scope: 'C', confidentialityImpact: 'H', integrityImpact: 'N', availabilityImpact: 'N' },
    ssrf_blind: { attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N', scope: 'C', confidentialityImpact: 'L', integrityImpact: 'N', availabilityImpact: 'N' },
    idor: { attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'L', userInteraction: 'N', scope: 'U', confidentialityImpact: 'H', integrityImpact: 'N', availabilityImpact: 'N' },
    ssti: { attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N', scope: 'U', confidentialityImpact: 'H', integrityImpact: 'H', availabilityImpact: 'H' },
    rce: { attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N', scope: 'U', confidentialityImpact: 'H', integrityImpact: 'H', availabilityImpact: 'H' },
    open_redirect: { attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'R', scope: 'U', confidentialityImpact: 'N', integrityImpact: 'L', availabilityImpact: 'N' },
    cors_misconfiguration: { attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'R', scope: 'U', confidentialityImpact: 'H', integrityImpact: 'N', availabilityImpact: 'N' },
    subdomain_takeover: { attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N', scope: 'C', confidentialityImpact: 'L', integrityImpact: 'L', availabilityImpact: 'N' },
  };

  return defaults[vulnType] ?? {
    attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
    userInteraction: 'N', scope: 'U',
    confidentialityImpact: 'L', integrityImpact: 'L', availabilityImpact: 'N',
  };
}

export default calculateCVSS;

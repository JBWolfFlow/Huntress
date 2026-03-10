/**
 * Vulnerability Chaining Engine
 *
 * Detects when multiple findings can be combined into higher-severity chains.
 * A chain is worth more than the sum of its parts — an open redirect (low)
 * combined with SSRF (high) becomes RCE (critical).
 */

import type { AgentFinding } from '../../agents/base_agent';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface VulnerabilityChain {
  id: string;
  name: string;
  findings: AgentFinding[];
  combinedSeverity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  impact: string;
  chainSteps: string[];
  confidenceBoost: number;
}

interface ChainRule {
  name: string;
  /** Finding types that can trigger this chain (order matters) */
  requires: string[][];
  /** Combined severity when the chain is detected */
  combinedSeverity: VulnerabilityChain['combinedSeverity'];
  description: string;
  impact: string;
  /** Whether findings must affect the same target */
  sameTarget: boolean;
}

// ─── Chain Rules ─────────────────────────────────────────────────────────────

const CHAIN_RULES: ChainRule[] = [
  {
    name: 'Open Redirect → SSRF',
    requires: [
      ['open_redirect', 'redirect'],
      ['ssrf', 'ssrf_blind'],
    ],
    combinedSeverity: 'critical',
    description: 'Open redirect chained with SSRF to access internal network',
    impact: 'Internal network access, potential cloud metadata theft',
    sameTarget: false,
  },
  {
    name: 'SSRF → Cloud Metadata',
    requires: [
      ['ssrf', 'ssrf_blind'],
      ['information_disclosure', 'cloud_metadata'],
    ],
    combinedSeverity: 'critical',
    description: 'SSRF chained with cloud metadata access for credential theft',
    impact: 'AWS/GCP/Azure credential theft, full cloud account compromise',
    sameTarget: true,
  },
  {
    name: 'XSS → CSRF → Account Takeover',
    requires: [
      ['xss_reflected', 'xss_stored', 'xss_dom'],
      ['csrf', 'missing_csrf'],
    ],
    combinedSeverity: 'critical',
    description: 'XSS used to bypass CSRF protections for account takeover',
    impact: 'Full account takeover via XSS-assisted CSRF',
    sameTarget: true,
  },
  {
    name: 'IDOR → Data Exfiltration',
    requires: [
      ['idor', 'bola'],
      ['information_disclosure', 'pii_exposure'],
    ],
    combinedSeverity: 'high',
    description: 'IDOR combined with information disclosure for mass data access',
    impact: 'Mass user data exfiltration via predictable object references',
    sameTarget: true,
  },
  {
    name: 'SQLi → File Read',
    requires: [
      ['sqli_error', 'sqli_blind_time', 'sqli_blind_boolean'],
      ['path_traversal', 'file_read'],
    ],
    combinedSeverity: 'critical',
    description: 'SQL injection combined with file read for source code disclosure',
    impact: 'Source code disclosure, database credential theft',
    sameTarget: true,
  },
  {
    name: 'SSTI → RCE',
    requires: [
      ['ssti'],
      ['rce', 'command_injection'],
    ],
    combinedSeverity: 'critical',
    description: 'Server-side template injection escalated to remote code execution',
    impact: 'Full server compromise via template injection to RCE chain',
    sameTarget: true,
  },
  {
    name: 'OAuth Redirect → Token Theft',
    requires: [
      ['oauth_redirect_uri', 'open_redirect'],
      ['oauth_state', 'token_leakage'],
    ],
    combinedSeverity: 'critical',
    description: 'OAuth redirect_uri manipulation for authorization code/token theft',
    impact: 'OAuth token theft leading to full account takeover',
    sameTarget: false,
  },
  {
    name: 'Subdomain Takeover → Cookie Theft',
    requires: [
      ['subdomain_takeover'],
      ['cookie_scope', 'session_fixation'],
    ],
    combinedSeverity: 'high',
    description: 'Subdomain takeover used to steal cookies scoped to parent domain',
    impact: 'Session hijacking via subdomain-scoped cookie theft',
    sameTarget: false,
  },
  {
    name: 'XSS → Cookie Theft',
    requires: [
      ['xss_reflected', 'xss_stored', 'xss_dom'],
      ['missing_httponly', 'cookie_misconfiguration'],
    ],
    combinedSeverity: 'high',
    description: 'XSS combined with missing HttpOnly flag for session theft',
    impact: 'Session token theft via XSS when HttpOnly is not set',
    sameTarget: true,
  },
  {
    name: 'CORS → Data Theft',
    requires: [
      ['cors_misconfiguration'],
      ['information_disclosure', 'api_data_exposure'],
    ],
    combinedSeverity: 'high',
    description: 'CORS misconfiguration enabling cross-origin data theft',
    impact: 'Cross-origin theft of sensitive API data',
    sameTarget: true,
  },
];

// ─── Chain Detection ─────────────────────────────────────────────────────────

/**
 * Detect vulnerability chains from a set of findings.
 * Returns an array of detected chains sorted by severity.
 */
export function detectChains(findings: AgentFinding[]): VulnerabilityChain[] {
  const chains: VulnerabilityChain[] = [];

  for (const rule of CHAIN_RULES) {
    const matchedFindings = matchRule(rule, findings);
    if (matchedFindings.length >= rule.requires.length) {
      chains.push({
        id: `chain_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
        name: rule.name,
        findings: matchedFindings,
        combinedSeverity: rule.combinedSeverity,
        description: rule.description,
        impact: rule.impact,
        chainSteps: matchedFindings.map((f, i) =>
          `Step ${i + 1}: ${f.title} (${f.severity}) at ${f.target}`
        ),
        confidenceBoost: 15, // Chain detection adds confidence
      });
    }
  }

  // Sort by severity (critical first)
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  chains.sort((a, b) =>
    severityOrder[b.combinedSeverity] - severityOrder[a.combinedSeverity]
  );

  return chains;
}

/** Match a chain rule against findings */
function matchRule(rule: ChainRule, findings: AgentFinding[]): AgentFinding[] {
  const matched: AgentFinding[] = [];

  for (const typeGroup of rule.requires) {
    const match = findings.find(f =>
      typeGroup.some(t => f.type.includes(t)) &&
      !matched.includes(f) &&
      (!rule.sameTarget || matched.length === 0 || isSameTargetDomain(f.target, matched[0].target))
    );

    if (match) {
      matched.push(match);
    }
  }

  return matched;
}

/** Check if two targets are on the same domain */
function isSameTargetDomain(target1: string, target2: string): boolean {
  try {
    const domain1 = extractDomain(target1);
    const domain2 = extractDomain(target2);
    return domain1 === domain2 || domain1.endsWith(`.${domain2}`) || domain2.endsWith(`.${domain1}`);
  } catch {
    return target1 === target2;
  }
}

function extractDomain(target: string): string {
  try {
    const url = new URL(target.startsWith('http') ? target : `https://${target}`);
    return url.hostname;
  } catch {
    return target;
  }
}

/**
 * Calculate the combined CVSS score boost for a chain.
 * Chains are typically scored higher than individual findings.
 */
export function calculateChainSeverityBoost(chain: VulnerabilityChain): number {
  const individualSeverities = chain.findings.map(f => {
    const map: Record<string, number> = { info: 0, low: 3.9, medium: 6.9, high: 8.9, critical: 10 };
    return map[f.severity] ?? 0;
  });

  const maxIndividual = Math.max(...individualSeverities);
  const combinedMap: Record<string, number> = { low: 3.9, medium: 6.9, high: 8.9, critical: 10 };
  const combinedScore = combinedMap[chain.combinedSeverity] ?? 0;

  return combinedScore - maxIndividual;
}

export default detectChains;

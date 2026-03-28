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
  id: string;
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
    id: 'redirect_ssrf',
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
    id: 'ssrf_cloud_metadata',
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
    id: 'xss_csrf_ato',
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
    id: 'idor_data_exfil',
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
    id: 'sqli_file_read',
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
    id: 'ssti_rce',
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
    id: 'oauth_redirect_token',
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
    id: 'subdomain_cookie_theft',
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
    id: 'xss_cookie_theft',
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
    id: 'cors_data_theft',
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
  // ── Phase 20I: Additional Chain Rules ──────────────────────────────────────
  {
    id: 'sqli_data_exfil_ato',
    name: 'SQLi → Data Exfiltration → Account Takeover',
    requires: [
      ['sqli_error', 'sqli_blind_time', 'sqli_blind_boolean'],
      ['information_disclosure', 'pii_exposure'],
    ],
    combinedSeverity: 'critical',
    description: 'SQL injection used to dump credentials leading to account takeover',
    impact: 'Full database access and account compromise',
    sameTarget: true,
  },
  {
    id: 'path_traversal_source_secrets',
    name: 'Path Traversal → Source Code → Hardcoded Secrets',
    requires: [
      ['path_traversal', 'lfi', 'file_read'],
      ['information_disclosure', 'secret_exposure'],
    ],
    combinedSeverity: 'critical',
    description: 'Path traversal to read source code containing hardcoded API keys or credentials',
    impact: 'Source code disclosure leading to further exploitation',
    sameTarget: true,
  },
  {
    id: 'cors_misconfig_data_theft',
    name: 'CORS Misconfiguration → Data Theft',
    requires: [
      ['cors_misconfiguration'],
      ['information_disclosure', 'pii_exposure', 'api_data_exposure'],
    ],
    combinedSeverity: 'high',
    description: 'CORS misconfiguration allowing cross-origin data theft of sensitive endpoints',
    impact: 'Cross-origin access to authenticated API data',
    sameTarget: true,
  },
  {
    id: 'host_header_cache_poison',
    name: 'Host Header Injection → Cache Poisoning',
    requires: [
      ['host_header_injection'],
      ['cache_poisoning'],
    ],
    combinedSeverity: 'high',
    description: 'Host header injection to poison web cache with malicious content',
    impact: 'Serve malicious content to all users via poisoned cache',
    sameTarget: true,
  },
  {
    id: 'xxe_ssrf_internal',
    name: 'XXE → SSRF → Internal Access',
    requires: [
      ['xxe'],
      ['ssrf', 'ssrf_blind'],
    ],
    combinedSeverity: 'critical',
    description: 'XML external entity injection used for SSRF to access internal services',
    impact: 'Internal network access via XXE-based SSRF',
    sameTarget: true,
  },
  {
    id: 'proto_pollution_xss',
    name: 'Prototype Pollution → XSS',
    requires: [
      ['prototype_pollution'],
      ['xss_dom', 'xss_reflected'],
    ],
    combinedSeverity: 'high',
    description: 'Prototype pollution used to trigger DOM-based XSS',
    impact: 'Client-side code execution via prototype chain manipulation',
    sameTarget: true,
  },
  {
    id: 'redirect_oauth_token',
    name: 'Open Redirect → OAuth Token Theft',
    requires: [
      ['open_redirect', 'redirect'],
      ['oauth_misconfiguration', 'oauth_redirect_uri'],
    ],
    combinedSeverity: 'critical',
    description: 'Open redirect on OAuth redirect_uri to steal authorization codes/tokens',
    impact: 'Full account takeover via stolen OAuth tokens',
    sameTarget: false,
  },
  {
    id: 'cmdi_rce_exfil',
    name: 'Command Injection → RCE → Data Exfiltration',
    requires: [
      ['command_injection', 'rce'],
      ['information_disclosure'],
    ],
    combinedSeverity: 'critical',
    description: 'Command injection escalated to full remote code execution with data theft',
    impact: 'Full server compromise and data exfiltration',
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
        id: `chain_${rule.id}_${matchedFindings.map(f => f.id ?? f.title).sort().join('_')}`,
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

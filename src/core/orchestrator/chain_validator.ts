/**
 * Chain Validator (Phase 20I)
 *
 * Validates that detected vulnerability chains are actually exploitable,
 * not just theoretical pattern matches. Also uses LLM-guided discovery
 * to find non-obvious chains that static rules miss.
 *
 * Individual low-severity findings become critical when chained:
 * - Open Redirect (low) + SSRF (medium) = Internal Network Access (critical)
 * - XSS (medium) + CSRF (low) = Account Takeover (critical)
 * HackerOne pays 10-100x more for chained exploits.
 */

import type { AgentFinding } from '../../agents/base_agent';
import type { VulnerabilityChain } from './chain_detector';
import type { HttpClient } from '../http/request_engine';
import type { ModelProvider, ChatMessage } from '../providers/types';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ChainValidationResult {
  chainId: string;
  isExploitable: boolean;
  validatedSteps: ChainStepValidation[];
  pocScript?: string;
  confidence: number;
  estimatedSeverity: 'low' | 'medium' | 'high' | 'critical';
  estimatedBounty?: { min: number; max: number };
}

export interface ChainStepValidation {
  finding: AgentFinding;
  validationResult: 'confirmed' | 'partial' | 'failed';
  evidence: string;
}

interface TargetContext {
  domain: string;
  technologies: string[];
}

// ─── Bounty Estimates by Severity ────────────────────────────────────────────

const BOUNTY_ESTIMATES: Record<string, { min: number; max: number }> = {
  critical: { min: 2000, max: 25000 },
  high: { min: 750, max: 5000 },
  medium: { min: 150, max: 1500 },
  low: { min: 50, max: 300 },
};

// ─── Chain Validator ─────────────────────────────────────────────────────────

export class ChainValidator {
  private httpClient: HttpClient;
  private provider?: ModelProvider;
  private model?: string;

  constructor(
    httpClient: HttpClient,
    provider?: ModelProvider,
    model?: string,
  ) {
    this.httpClient = httpClient;
    this.provider = provider;
    this.model = model;
  }

  /** Validate that a detected chain is actually exploitable */
  async validateChain(chain: VulnerabilityChain): Promise<ChainValidationResult> {
    const validatedSteps: ChainStepValidation[] = [];
    let allConfirmed = true;
    let anyConfirmed = false;

    // Step 1: Validate each finding in the chain is still exploitable
    for (const finding of chain.findings) {
      const validation = await this.validateStep(finding);
      validatedSteps.push(validation);

      if (validation.validationResult === 'confirmed') {
        anyConfirmed = true;
      } else if (validation.validationResult === 'failed') {
        allConfirmed = false;
      } else {
        // Partial — doesn't confirm but doesn't disprove
        allConfirmed = false;
      }
    }

    // Step 2: Validate connectivity between chain steps
    const connectivityValid = this.validateConnectivity(chain);

    // Step 3: Calculate confidence
    const confirmedCount = validatedSteps.filter(s => s.validationResult === 'confirmed').length;
    const totalSteps = validatedSteps.length;
    const stepConfidence = totalSteps > 0 ? confirmedCount / totalSteps : 0;
    const confidence = connectivityValid
      ? Math.min(0.95, stepConfidence * 0.7 + 0.25)
      : stepConfidence * 0.4;

    const isExploitable = anyConfirmed && connectivityValid && confidence >= 0.4;

    // Step 4: Generate PoC if exploitable
    let pocScript: string | undefined;
    if (isExploitable) {
      pocScript = this.generateBasicPoC(chain, validatedSteps);
    }

    return {
      chainId: chain.id,
      isExploitable,
      validatedSteps,
      pocScript,
      confidence,
      estimatedSeverity: chain.combinedSeverity,
      estimatedBounty: BOUNTY_ESTIMATES[chain.combinedSeverity],
    };
  }

  /** Ask the orchestrator LLM to identify non-obvious chains from a set of findings */
  async discoverCreativeChains(
    findings: AgentFinding[],
    targetContext: TargetContext,
  ): Promise<VulnerabilityChain[]> {
    // Without an LLM provider, we can't discover creative chains
    if (!this.provider || !this.model) {
      return [];
    }

    if (findings.length < 2) {
      return [];
    }

    const findingSummaries = findings.map(f =>
      `[${f.severity}] ${f.type}: ${f.title} at ${f.target}`,
    ).join('\n');

    const messages: ChatMessage[] = [
      {
        role: 'user',
        content: `You are a senior penetration tester analyzing findings for vulnerability chains.

Target domain: ${targetContext.domain}
Technologies: ${targetContext.technologies.join(', ')}

Findings:
${findingSummaries}

Identify any vulnerability chains where combining 2+ findings creates a higher-severity impact.
For each chain, explain the attack flow and the combined impact.

Respond ONLY with a JSON array (no markdown, no explanation outside the array):
[{
  "name": "Chain name",
  "findingIndices": [0, 2],
  "combinedSeverity": "critical",
  "description": "How the chain works",
  "impact": "What the attacker can achieve"
}]

If no chains exist, return an empty array: []`,
      },
    ];

    try {
      const response = await this.provider.sendMessage(messages, {
        model: this.model,
        maxTokens: 2048,
      });

      const parsed = this.parseChainResponse(response.content, findings);
      return parsed;
    } catch {
      return [];
    }
  }

  /** Generate a PoC script that demonstrates the chain */
  async generateChainPoC(chain: VulnerabilityChain): Promise<string> {
    // Try LLM-generated PoC first
    if (this.provider && this.model) {
      try {
        const stepDescriptions = chain.chainSteps.join('\n');
        const messages: ChatMessage[] = [
          {
            role: 'user',
            content: `Generate a Python proof-of-concept script demonstrating this vulnerability chain:

Chain: ${chain.name}
Steps:
${stepDescriptions}

The PoC should:
1. Demonstrate each step of the chain
2. Use the requests library for HTTP calls
3. Include clear comments explaining each step
4. Be a complete, runnable script

Respond with ONLY the Python code, no markdown fences or explanation.`,
          },
        ];

        const response = await this.provider.sendMessage(messages, {
          model: this.model,
          maxTokens: 4096,
        });

        const code = response.content.trim();
        // Basic validation that it looks like Python
        if (code.includes('import') || code.includes('def ') || code.includes('requests.')) {
          return code;
        }
      } catch {
        // Fall through to basic PoC
      }
    }

    // Fallback: generate a basic template PoC
    return this.generateBasicPoC(chain, []);
  }

  // ─── Private Helpers ─────────────────────────────────────────────────────────

  /** Validate a single finding is still exploitable */
  private async validateStep(finding: AgentFinding): Promise<ChainStepValidation> {
    // Extract a URL from the finding's evidence
    const url = this.extractUrlFromFinding(finding);
    if (!url) {
      return {
        finding,
        validationResult: 'partial',
        evidence: 'No URL found in finding evidence for re-validation',
      };
    }

    try {
      const response = await this.httpClient.request({
        url,
        method: 'GET',
        timeoutMs: 10_000,
      });

      // Check if the response still indicates vulnerability
      if (response.status >= 200 && response.status < 500) {
        // Basic check: if the original evidence pattern appears in response
        const hasEvidence = finding.evidence.some(ev => {
          // Look for payload reflections or error patterns in response body
          const patterns = ev.match(/[<>"'{}()\[\]]+/g);
          return patterns?.some(p => response.body.includes(p)) ?? false;
        });

        if (hasEvidence) {
          return {
            finding,
            validationResult: 'confirmed',
            evidence: `Endpoint still responds with vulnerability indicators (status: ${response.status})`,
          };
        }

        return {
          finding,
          validationResult: 'partial',
          evidence: `Endpoint responds (status: ${response.status}) but evidence patterns not confirmed`,
        };
      }

      return {
        finding,
        validationResult: 'failed',
        evidence: `Endpoint returned error status: ${response.status}`,
      };
    } catch (error) {
      return {
        finding,
        validationResult: 'partial',
        evidence: `Validation request failed: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  /** Validate that chain steps can connect to each other */
  private validateConnectivity(chain: VulnerabilityChain): boolean {
    if (chain.findings.length < 2) return true;

    // Check that findings share a target domain or have a logical connection
    const domains = chain.findings.map(f => {
      try {
        const url = new URL(f.target.startsWith('http') ? f.target : `https://${f.target}`);
        return url.hostname;
      } catch {
        return f.target;
      }
    });

    // All on same domain — connected
    if (new Set(domains).size === 1) return true;

    // Check if domains share a base domain (e.g., api.example.com and www.example.com)
    const baseDomains = domains.map(d => {
      const parts = d.split('.');
      return parts.length >= 2 ? parts.slice(-2).join('.') : d;
    });

    if (new Set(baseDomains).size === 1) return true;

    // Cross-domain chains are valid for some types (OAuth redirect → token theft)
    const crossDomainChainTypes = ['open_redirect', 'oauth_redirect_uri', 'redirect', 'oauth_misconfiguration'];
    const hasCrossDomainType = chain.findings.some(f =>
      crossDomainChainTypes.includes(f.type),
    );

    return hasCrossDomainType;
  }

  /** Extract a testable URL from a finding */
  private extractUrlFromFinding(finding: AgentFinding): string | null {
    // Try the target field first
    if (finding.target.startsWith('http')) {
      return finding.target;
    }

    // Search evidence for URLs
    for (const ev of finding.evidence) {
      const urlMatch = ev.match(/https?:\/\/[^\s"'<>]+/);
      if (urlMatch) {
        return urlMatch[0];
      }
    }

    // Search reproduction steps
    for (const step of finding.reproduction) {
      const urlMatch = step.match(/https?:\/\/[^\s"'<>]+/);
      if (urlMatch) {
        return urlMatch[0];
      }
    }

    return null;
  }

  /** Parse LLM response for creative chain discovery */
  private parseChainResponse(content: string, findings: AgentFinding[]): VulnerabilityChain[] {
    try {
      // Extract JSON array from response (handle possible markdown wrapping)
      const jsonMatch = content.match(/\[[\s\S]*\]/);
      if (!jsonMatch) return [];

      const parsed = JSON.parse(jsonMatch[0]) as Array<{
        name: string;
        findingIndices: number[];
        combinedSeverity: string;
        description: string;
        impact: string;
      }>;

      if (!Array.isArray(parsed)) return [];

      return parsed
        .filter(item =>
          item.name &&
          Array.isArray(item.findingIndices) &&
          item.findingIndices.length >= 2 &&
          item.findingIndices.every(i => i >= 0 && i < findings.length),
        )
        .map(item => {
          const chainFindings = item.findingIndices.map(i => findings[i]);
          const severity = this.normalizeSeverity(item.combinedSeverity);

          return {
            id: `creative_chain_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
            name: item.name,
            findings: chainFindings,
            combinedSeverity: severity,
            description: item.description,
            impact: item.impact,
            chainSteps: chainFindings.map((f, i) =>
              `Step ${i + 1}: ${f.title} (${f.severity}) at ${f.target}`,
            ),
            confidenceBoost: 10,
            validated: false, // Creative chains start unvalidated
          };
        });
    } catch {
      return [];
    }
  }

  /** Generate a basic template PoC */
  private generateBasicPoC(
    chain: VulnerabilityChain,
    _validatedSteps: ChainStepValidation[],
  ): string {
    const lines: string[] = [
      '#!/usr/bin/env python3',
      `"""`,
      `Proof of Concept: ${chain.name}`,
      `Severity: ${chain.combinedSeverity}`,
      `Impact: ${chain.impact}`,
      `"""`,
      '',
      'import requests',
      '',
      'session = requests.Session()',
      '',
    ];

    for (let i = 0; i < chain.findings.length; i++) {
      const finding = chain.findings[i];
      const step = chain.chainSteps[i] ?? `Step ${i + 1}`;
      lines.push(`# ${step}`);
      lines.push(`# Finding: ${finding.title} (${finding.severity})`);
      lines.push(`# Target: ${finding.target}`);

      if (finding.evidence.length > 0) {
        lines.push(`# Evidence: ${finding.evidence[0].slice(0, 200)}`);
      }

      lines.push(`print(f"[Step ${i + 1}] Testing: ${finding.title}")`);
      lines.push(`response_${i + 1} = session.get("${finding.target}")`);
      lines.push(`print(f"  Status: {response_${i + 1}.status_code}")`);
      lines.push('');
    }

    lines.push(`print("\\nChain: ${chain.name}")`);
    lines.push(`print("Combined Severity: ${chain.combinedSeverity}")`);
    lines.push(`print("Impact: ${chain.impact}")`);

    return lines.join('\n');
  }

  private normalizeSeverity(sev: string): VulnerabilityChain['combinedSeverity'] {
    const lower = sev.toLowerCase();
    if (lower === 'critical' || lower === 'high' || lower === 'medium' || lower === 'low') {
      return lower;
    }
    return 'medium';
  }
}

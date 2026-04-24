/**
 * Economy Mode — conservative dispatch configuration for real bug-bounty
 * programs.
 *
 * Most HackerOne programs forbid "automated scanning at scale" in their
 * policy. Huntress's default dispatch (5 parallel Sonnet specialist agents,
 * unlimited fan-out per recon result, per-agent 20%-of-budget claim) will
 * violate that rule on any real program — the 2026-04-23 Superhuman attempt
 * made that concrete. Economy Mode is the user-controlled toggle that
 * trades hunt speed for program-compliance and budget discipline:
 *
 *   - `maxConcurrentAgents` drops 5 → 2: serialize more, hammer less.
 *   - `maxSpecialistsPerRecon` drops ∞ → 3: each recon completion fans out
 *     to at most three specialist agents (prioritized by historical yield)
 *     instead of every specialist in the catalog.
 *   - `maxAgentCostFraction` widens 0.2 → 0.5: with fewer concurrent
 *     agents, each gets more of the budget, so hunts actually complete
 *     instead of every agent starving at 20%.
 *
 * Defaults off — single-target test hunts (Juice Shop, localhost) and
 * power-users running their own infra see no change.
 */

export interface EconomyModeConfig {
  /** Whether economy mode is active. Off by default. */
  enabled: boolean;
  /** Max specialist agents running concurrently. 5 off, 2 on. */
  maxConcurrentAgents: number;
  /**
   * Cap on specialists dispatched per recon-completion fan-out.
   * `Infinity` when off (existing unbounded behavior); 3 when on.
   */
  maxSpecialistsPerRecon: number;
  /** Per-agent budget claim as a fraction of the hunt budget. 0.2 off, 0.5 on. */
  maxAgentCostFraction: number;
}

/** Economy mode off — preserves historical dispatch defaults. */
export const ECONOMY_MODE_OFF: Readonly<EconomyModeConfig> = Object.freeze({
  enabled: false,
  maxConcurrentAgents: 5,
  maxSpecialistsPerRecon: Infinity,
  maxAgentCostFraction: 0.2,
});

/** Economy mode on — compliant defaults for live H1 programs. */
export const ECONOMY_MODE_ON: Readonly<EconomyModeConfig> = Object.freeze({
  enabled: true,
  maxConcurrentAgents: 2,
  maxSpecialistsPerRecon: 3,
  maxAgentCostFraction: 0.5,
});

/** Resolve a boolean toggle into the full config object.
 *  Returns frozen references — callers must not mutate. */
export function resolveEconomyMode(enabled: boolean): Readonly<EconomyModeConfig> {
  return enabled ? ECONOMY_MODE_ON : ECONOMY_MODE_OFF;
}

/**
 * Historical yield ranking — which specialist agents are most likely to
 * produce real findings when budget is tight. Used by `generateSolverTasks`
 * when `maxSpecialistsPerRecon` is finite: we sort dispatched agents by
 * this rank and take the top N.
 *
 * Agents listed here are ranked (higher rank = earlier dispatch); agents
 * not listed get rank 0 (dispatched after all ranked ones). The ordering
 * reflects hunt #11–#12 hit rates and the 2026-04-23 Juice Shop run:
 * SQLi, XSS, and IDOR fired every time a finding surfaced; SSTI and
 * prototype pollution followed; the rest are long-tail by comparison.
 */
export const SPECIALIST_YIELD_RANK: Readonly<Record<string, number>> = Object.freeze({
  'sqli-hunter': 100,
  'xss-hunter': 95,
  'idor-hunter': 90,
  'ssti-hunter': 85,
  'command-injection-hunter': 80,
  'ssrf-hunter': 75,
  'prototype-pollution-hunter': 70,
  'xxe-hunter': 65,
  'path-traversal-hunter': 60,
  'nosql-injection-hunter': 55,
  'host-header-hunter': 50,
  'cors-hunter': 45,
  'open-redirect-hunter': 40,
  'jwt-hunter': 35,
  'graphql-hunter': 30,
});

/** Sort-key helper exported for tests. Returns rank (higher = higher
 *  priority). Unknown agents get 0 — they run last. */
export function specialistYieldRank(agentId: string): number {
  return SPECIALIST_YIELD_RANK[agentId] ?? 0;
}

/**
 * Minimal shape `selectSolverAgents` needs. Matches the `AgentCatalogEntry`
 * interface from `agent_catalog.ts` but kept structural so tests don't have
 * to construct full catalog entries.
 */
export interface SolverAgentCandidate {
  metadata: { id: string };
}

/**
 * Given the agent catalog, the tech-stack-skipped set, and the economy-mode
 * specialist cap, return the agents to actually dispatch for this recon's
 * fan-out. Sorting by `specialistYieldRank` is applied only when a finite
 * cap is in effect so existing non-economy dispatch order (catalog order)
 * stays stable.
 *
 * Rules:
 *   1. Drop `recon` itself — it just finished.
 *   2. Drop tech-stack-irrelevant agents.
 *   3. If `maxSpecialistsPerRecon` is finite: sort by yield rank and take
 *      the top N. Otherwise, return filtered agents in catalog order.
 */
export function selectSolverAgents<T extends SolverAgentCandidate>(
  availableAgents: readonly T[],
  skippedAgents: ReadonlySet<string>,
  maxSpecialistsPerRecon: number,
): T[] {
  const filtered = availableAgents.filter(
    a => a.metadata.id !== 'recon' && !skippedAgents.has(a.metadata.id),
  );
  if (!Number.isFinite(maxSpecialistsPerRecon)) return filtered;
  return [...filtered]
    .sort((a, b) => specialistYieldRank(b.metadata.id) - specialistYieldRank(a.metadata.id))
    .slice(0, maxSpecialistsPerRecon);
}

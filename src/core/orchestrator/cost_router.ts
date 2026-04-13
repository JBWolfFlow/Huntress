/**
 * Cost-Optimized Model Routing
 *
 * Routes tasks to the cheapest adequate model based on task complexity.
 * Simple tasks (recon, subdomain_takeover) go to cheap/fast models.
 * Complex tasks (strategy, chain detection) go to the best available.
 */

import type { ModelProvider } from '../providers/types';

export type TaskComplexity = 'simple' | 'moderate' | 'complex';

/**
 * Agent IDs mapped to their expected complexity.
 * IDs use the actual hyphenated format from agent metadata.
 */
const AGENT_COMPLEXITY: Record<string, TaskComplexity> = {
  // Simple: structured tasks, pattern matching, low reasoning
  'recon': 'simple',
  'subdomain-takeover-hunter': 'simple',
  'cors-hunter': 'simple',
  'host-header-hunter': 'simple',
  'crlf-hunter': 'simple',
  'cache-hunter': 'simple',
  'open-redirect-hunter': 'simple',

  // Moderate: require tool-use reasoning about responses
  'xss-hunter': 'moderate',
  'sqli-hunter': 'moderate',
  'ssrf-hunter': 'moderate',
  'ssti-hunter': 'moderate',
  'xxe-hunter': 'moderate',
  'command-injection-hunter': 'moderate',
  'path-traversal-hunter': 'moderate',
  'graphql-hunter': 'moderate',
  'prototype-pollution-hunter': 'moderate',
  'http-smuggling-hunter': 'moderate',
  'websocket-hunter': 'moderate',
  'nosql-hunter': 'moderate',
  'prompt-injection-hunter': 'moderate',
  'mfa-bypass-hunter': 'moderate',
  'deserialization-hunter': 'moderate',
  'saml-hunter': 'moderate',

  // Complex: multi-step exploit crafting, chain reasoning
  'idor-hunter': 'complex',
  'oauth_hunter': 'complex',
  'jwt-hunter': 'complex',
  'business-logic-hunter': 'complex',
  'race-condition-hunter': 'complex',
  'orchestrator': 'complex',
  'chain_detection': 'complex',
  'report_generation': 'complex',

  // Auth capture — drives a browser through a login flow. Needs reasoning to
  // handle variant login UIs (modal vs page, redirect vs popup, 2FA) but
  // Sonnet handles this well — it's not chain-of-exploits complexity.
  'auth-worker': 'moderate',
};

// ─── Anthropic Model Tier Configuration ─────────────────────────────────────

/** Anthropic model IDs for each cost tier */
export const ANTHROPIC_MODEL_TIERS = {
  /** Fast, cheap — recon, pattern matching, simple checks */
  simple: 'claude-haiku-4-5-20251001',
  /** Balanced — exploit reasoning, tool use, medium-complexity hunting */
  moderate: 'claude-sonnet-4-5-20250929',
  /** Premium — multi-step exploit chains, business logic, complex synthesis */
  complex: 'claude-sonnet-4-5-20250929',
} as const;

/**
 * Get the Anthropic model ID for a given task complexity.
 * Orchestrator always uses the user's selected model (Opus).
 * Agents use tiered models based on task complexity.
 */
export function getAnthropicModelForComplexity(complexity: TaskComplexity): string {
  return ANTHROPIC_MODEL_TIERS[complexity];
}

// ─── Adaptive Iteration Budgets (I1) ────────────────────────────────────────

/**
 * Max ReAct loop iterations by complexity tier.
 * Simple agents (recon, CORS) finish fast — 30 is plenty.
 * Moderate agents (XSS, SQLi) need more exploration — 80.
 * Complex agents (business logic, race conditions, IDOR) may need extended
 * iteration chains to find multi-step vulns — 120.
 */
const ITERATION_BUDGETS: Record<TaskComplexity, number> = {
  simple: 30,
  moderate: 80,
  complex: 120,
};

/**
 * Get the iteration budget for an agent type.
 * Uses the agent's complexity tier to determine max iterations.
 * Unknown agents default to 80 (moderate).
 */
export function getIterationBudget(agentType: string): number {
  const complexity = AGENT_COMPLEXITY[agentType] ?? 'moderate';
  return ITERATION_BUDGETS[complexity];
}

/**
 * Get the complexity tier for an agent type.
 * Returns 'moderate' for unknown agent types.
 */
export function getAgentComplexity(agentType: string): TaskComplexity {
  return AGENT_COMPLEXITY[agentType] ?? 'moderate';
}

/** Keywords in task descriptions that indicate higher complexity */
const COMPLEX_KEYWORDS = [
  'chain', 'bypass', 'authentication', 'authorization',
  'multi-step', 'race condition', 'business logic',
  'report', 'synthesize', 'analyze',
];

const SIMPLE_KEYWORDS = [
  'enumerate', 'list', 'discover', 'scan', 'fingerprint',
  'check', 'ping', 'resolve',
];

/**
 * Agent types whose complexity is locked and cannot be upgraded by
 * keyword analysis. These agents perform structured, low-reasoning
 * tasks that should always use the cheapest model regardless of what
 * security keywords appear in the target description.
 */
const COMPLEXITY_LOCKED_AGENTS = new Set<string>([
  'recon',
  'subdomain-takeover-hunter',
  'cors-hunter',
  'host-header-hunter',
  'crlf-hunter',
  'cache-hunter',
  'open-redirect-hunter',
]);

/**
 * Classify task complexity based on agent type and description.
 *
 * Priority order:
 * 1. Locked agents always return their base complexity (no keyword upgrade)
 * 2. Known agents use base complexity, with keyword upgrade as tiebreaker
 * 3. Unknown agents classify purely by description keywords
 */
export function classifyTaskComplexity(
  agentType: string,
  taskDescription: string,
): TaskComplexity {
  // Check known agent types first
  const known = AGENT_COMPLEXITY[agentType];
  if (known) {
    // Locked agents: never upgrade regardless of description content
    if (COMPLEXITY_LOCKED_AGENTS.has(agentType)) {
      return known;
    }

    // Description-based override: upgrade if complex keywords found
    const descLower = taskDescription.toLowerCase();

    if (known === 'simple' && COMPLEX_KEYWORDS.some(kw => descLower.includes(kw))) {
      return 'moderate';
    }
    if (known === 'moderate' && COMPLEX_KEYWORDS.some(kw => descLower.includes(kw))) {
      return 'complex';
    }

    return known;
  }

  // Unknown agent type — classify by description keywords
  const descLower = taskDescription.toLowerCase();

  if (COMPLEX_KEYWORDS.some(kw => descLower.includes(kw))) {
    return 'complex';
  }
  if (SIMPLE_KEYWORDS.some(kw => descLower.includes(kw))) {
    return 'simple';
  }

  return 'moderate';
}

/** Model tier ranking by cost (lower = cheaper) */
const MODEL_TIER: Record<string, number> = {
  // Cheapest
  'claude-haiku-4-5-20251001': 1,
  'gpt-4o-mini': 1,
  'gemini-2.0-flash': 1,

  // Mid-tier
  'claude-sonnet-4-5-20250514': 2,
  'claude-sonnet-4-5-20250929': 2, // Alias for older model ID
  'gpt-4o': 2,
  'gemini-2.5-pro': 2,

  // Premium
  'claude-opus-4-6': 3,
  'o3': 3,
};

/**
 * Get the cost tier for a model (1=cheap, 2=mid, 3=premium).
 * Unknown models are assumed mid-tier.
 */
function getModelTier(modelId: string): number {
  return MODEL_TIER[modelId] ?? 2;
}

export interface SelectedModel {
  provider: ModelProvider;
  model: string;
}

export interface AgentModelOverride {
  providerId: string;
  modelId: string;
}

/**
 * Select the optimal provider/model for a task based on complexity.
 *
 * - simple -> cheapest available
 * - moderate -> mid-tier or alloy
 * - complex -> best available
 *
 * User can override per-agent via agentModelOverrides in settings.
 */
export function selectModelForTask(
  complexity: TaskComplexity,
  availableProviders: Array<{ provider: ModelProvider; models: string[] }>,
  agentModelOverrides?: Record<string, AgentModelOverride>,
  agentType?: string,
): SelectedModel | null {
  // Check for user override first
  if (agentType && agentModelOverrides?.[agentType]) {
    const override = agentModelOverrides[agentType];
    const providerEntry = availableProviders.find(
      p => p.provider.providerId === override.providerId,
    );
    if (providerEntry && providerEntry.models.includes(override.modelId)) {
      return { provider: providerEntry.provider, model: override.modelId };
    }
  }

  // Build a flat list of (provider, model, tier)
  const candidates: Array<{ provider: ModelProvider; model: string; tier: number }> = [];
  for (const entry of availableProviders) {
    for (const model of entry.models) {
      candidates.push({
        provider: entry.provider,
        model,
        tier: getModelTier(model),
      });
    }
  }

  if (candidates.length === 0) return null;

  // Sort by tier ascending (cheapest first)
  candidates.sort((a, b) => a.tier - b.tier);

  let targetTier: number;
  switch (complexity) {
    case 'simple':
      targetTier = 1;
      break;
    case 'moderate':
      targetTier = 2;
      break;
    case 'complex':
      targetTier = 3;
      break;
  }

  // Find the best match for the target tier
  // Prefer exact tier match, fall back to closest available
  const exact = candidates.find(c => c.tier === targetTier);
  if (exact) return { provider: exact.provider, model: exact.model };

  // For simple tasks, use the cheapest available
  if (complexity === 'simple') {
    return { provider: candidates[0].provider, model: candidates[0].model };
  }

  // For complex tasks, use the most expensive available
  if (complexity === 'complex') {
    const best = candidates[candidates.length - 1];
    return { provider: best.provider, model: best.model };
  }

  // For moderate, use the middle option
  const midIdx = Math.floor(candidates.length / 2);
  return { provider: candidates[midIdx].provider, model: candidates[midIdx].model };
}

/** Average tokens per iteration by complexity */
const TOKENS_PER_ITERATION: Record<TaskComplexity, { input: number; output: number }> = {
  simple: { input: 2000, output: 500 },
  moderate: { input: 4000, output: 1000 },
  complex: { input: 8000, output: 2000 },
};

/**
 * Estimate cost in USD for a task before dispatch.
 */
export function estimateTaskCost(
  agentType: string,
  iterationBudget: number,
  provider: ModelProvider,
  model: string,
): number {
  const complexity = classifyTaskComplexity(agentType, '');
  const tokensPerIter = TOKENS_PER_ITERATION[complexity];

  const totalInput = tokensPerIter.input * iterationBudget;
  const totalOutput = tokensPerIter.output * iterationBudget;

  return provider.estimateCost(totalInput, totalOutput, model);
}

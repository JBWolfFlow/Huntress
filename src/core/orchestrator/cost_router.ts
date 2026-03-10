/**
 * Cost-Optimized Model Routing
 *
 * Routes tasks to the cheapest adequate model based on task complexity.
 * Simple tasks (recon, subdomain_takeover) go to cheap/fast models.
 * Complex tasks (strategy, chain detection) go to the best available.
 */

import type { ModelProvider, ModelInfo } from '../providers/types';

export type TaskComplexity = 'simple' | 'moderate' | 'complex';

/** Agent types mapped to their expected complexity */
const AGENT_COMPLEXITY: Record<string, TaskComplexity> = {
  // Simple: structured, well-defined tasks
  recon: 'simple',
  subdomain_takeover: 'simple',
  cors: 'simple',
  host_header: 'simple',

  // Moderate: require reasoning about responses
  xss: 'moderate',
  sqli: 'moderate',
  ssrf: 'moderate',
  idor: 'moderate',
  ssti: 'moderate',
  xxe: 'moderate',
  command_injection: 'moderate',
  path_traversal: 'moderate',
  graphql: 'moderate',
  open_redirect: 'moderate',
  prototype_pollution: 'moderate',

  // Complex: multi-step reasoning, synthesis
  orchestrator: 'complex',
  chain_detection: 'complex',
  report_generation: 'complex',
};

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
 * Classify task complexity based on agent type and description.
 */
export function classifyTaskComplexity(
  agentType: string,
  taskDescription: string,
): TaskComplexity {
  // Check known agent types first
  const known = AGENT_COMPLEXITY[agentType];
  if (known) {
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
  'claude-sonnet-4-5-20250929': 2,
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

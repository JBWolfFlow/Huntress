/**
 * Agent Catalog
 *
 * Static registry mapping agent types to their constructors,
 * capabilities, and descriptions.
 */

import type { AgentMetadata, BaseAgent } from './base_agent';

export interface CatalogEntry {
  metadata: AgentMetadata;
  factory: () => BaseAgent;
}

/** All registered agent types */
const catalog: Map<string, CatalogEntry> = new Map();

/** Register an agent in the catalog */
export function registerAgent(entry: CatalogEntry): void {
  catalog.set(entry.metadata.id, entry);
}

/** Get all catalog entries */
export function getAllAgents(): CatalogEntry[] {
  return Array.from(catalog.values());
}

/** Get a specific agent entry */
export function getAgentEntry(agentId: string): CatalogEntry | undefined {
  return catalog.get(agentId);
}

/** Find agents that handle a specific vulnerability class */
export function findAgentsForVulnClass(vulnClass: string): CatalogEntry[] {
  return getAllAgents().filter(entry =>
    entry.metadata.vulnerabilityClasses.some(vc =>
      vc.toLowerCase().includes(vulnClass.toLowerCase())
    )
  );
}

/** Find agents that can test a specific asset type */
export function findAgentsForAssetType(assetType: string): CatalogEntry[] {
  return getAllAgents().filter(entry =>
    entry.metadata.assetTypes.some(at =>
      at.toLowerCase().includes(assetType.toLowerCase())
    )
  );
}

/**
 * Initialize the catalog with all built-in agents.
 * Called lazily to avoid circular imports.
 */
let initialized = false;

export function initializeCatalog(): void {
  if (initialized) return;
  initialized = true;

  // Import and register agents dynamically to avoid circular deps
  // Each agent module registers itself via registerAgent() when imported

  // The agents are registered in their respective wrapped files:
  // - oauth_hunter_agent.ts
  // - graphql_hunter_agent.ts
  // - idor_hunter_agent.ts
  // - ssti_hunter_agent.ts
  // - open_redirect_agent.ts
  // - host_header_agent.ts
  // - prototype_pollution_agent.ts
  // - recon_agent.ts

  // Registration happens via the agent_router which imports all agents
}

export default {
  registerAgent,
  getAllAgents,
  getAgentEntry,
  findAgentsForVulnClass,
  findAgentsForAssetType,
  initializeCatalog,
};

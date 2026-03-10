/**
 * Finding Deduplication — Cross-Agent Dedup and SimHash Grouping
 *
 * Prevents duplicate findings from different agents testing the same endpoint,
 * and groups similar targets by page content to avoid redundant testing.
 */

import type { AgentFinding } from '../../agents/base_agent';
import type { QdrantClient } from '../memory/qdrant_client';

// ─── SimHash Implementation ─────────────────────────────────────────────────

/** 64-bit SimHash of text content, returned as bigint */
export function computeSimHash(html: string): bigint {
  const tokens = tokenize(html);
  // Use 64 bit positions
  const v = new Array<number>(64).fill(0);

  for (const token of tokens) {
    const hash = fnv1a64(token);
    for (let i = 0; i < 64; i++) {
      const bit = (hash >> BigInt(i)) & 1n;
      v[i] += bit === 1n ? 1 : -1;
    }
  }

  let simhash = 0n;
  for (let i = 0; i < 64; i++) {
    if (v[i] > 0) {
      simhash |= 1n << BigInt(i);
    }
  }

  return simhash;
}

/** Hamming distance between two 64-bit SimHash values */
export function simHashDistance(a: bigint, b: bigint): number {
  let xor = a ^ b;
  let distance = 0;
  while (xor > 0n) {
    distance += Number(xor & 1n);
    xor >>= 1n;
  }
  return distance;
}

/** Tokenize HTML into meaningful shingles (3-gram words) */
function tokenize(html: string): string[] {
  // Strip HTML tags
  const text = html.replace(/<[^>]*>/g, ' ');
  // Normalize whitespace and lowercase
  const words = text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 1);

  // Generate 3-grams for better content fingerprinting
  const shingles: string[] = [];
  for (let i = 0; i <= words.length - 3; i++) {
    shingles.push(`${words[i]} ${words[i + 1]} ${words[i + 2]}`);
  }

  // If too few words for 3-grams, use individual words
  if (shingles.length === 0) {
    return words;
  }

  return shingles;
}

/** FNV-1a 64-bit hash of a string, returning bigint */
function fnv1a64(str: string): bigint {
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;

  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str.charCodeAt(i));
    hash = (hash * prime) & 0xffffffffffffffffn;
  }

  return hash;
}

// ─── SimHash Grouping ────────────────────────────────────────────────────────

export interface SimHashTarget {
  url: string;
  html: string;
}

export interface SimHashGroup {
  representative: SimHashTarget;
  members: SimHashTarget[];
  simhash: bigint;
}

/**
 * Group targets by SimHash similarity.
 * Targets with Hamming distance <= threshold are grouped together.
 * Returns one representative per group (the first encountered).
 *
 * @param targets - Array of targets with URL and HTML content
 * @param threshold - Maximum Hamming distance to consider similar (default: 3)
 */
export function groupBySimHash(
  targets: SimHashTarget[],
  threshold: number = 3,
): SimHashGroup[] {
  const groups: SimHashGroup[] = [];

  for (const target of targets) {
    const hash = computeSimHash(target.html);
    let matched = false;

    for (const group of groups) {
      if (simHashDistance(hash, group.simhash) <= threshold) {
        group.members.push(target);
        matched = true;
        break;
      }
    }

    if (!matched) {
      groups.push({
        representative: target,
        members: [target],
        simhash: hash,
      });
    }
  }

  return groups;
}

// ─── Finding Deduplication ───────────────────────────────────────────────────

/** Key used for cross-agent dedup: (hostname, vuln_type, parameter) */
function findingDedupKey(finding: AgentFinding): string {
  let hostname = '';
  try {
    hostname = new URL(finding.target).hostname;
  } catch {
    hostname = finding.target;
  }

  // Extract affected parameter from evidence or description
  const param = extractParameter(finding);

  return `${hostname}|${finding.type}|${param}`.toLowerCase();
}

/** Try to extract the affected parameter from a finding */
function extractParameter(finding: AgentFinding): string {
  // Check evidence lines for common parameter patterns
  for (const line of finding.evidence) {
    // URL query parameters: ?param=value or &param=value
    const queryMatch = line.match(/[?&]([a-zA-Z_][a-zA-Z0-9_]*)=/);
    if (queryMatch) return queryMatch[1];

    // JSON body parameters: "param": value
    const jsonMatch = line.match(/"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:/);
    if (jsonMatch) return jsonMatch[1];

    // Header-based: X-Forwarded-Host, Host, etc.
    const headerMatch = line.match(/^([\w-]+):/i);
    if (headerMatch) return headerMatch[1];
  }

  // Fall back to extracting from description
  const descMatch = finding.description.match(/parameter\s+[`'"]*(\w+)[`'"]*|[`'"]+(\w+)[`'"]+\s+parameter/i);
  if (descMatch) return descMatch[1] ?? descMatch[2];

  return '_no_param_';
}

/**
 * Deduplicate findings across agents.
 * Two findings are considered duplicates if they share the same
 * (target hostname, vulnerability_type, affected_parameter).
 * When duplicates are found, the one with higher severity wins.
 */
export function deduplicateFindings(findings: AgentFinding[]): AgentFinding[] {
  const seen = new Map<string, AgentFinding>();
  const severityOrder: Record<string, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };

  for (const finding of findings) {
    const key = findingDedupKey(finding);
    const existing = seen.get(key);

    if (!existing) {
      seen.set(key, finding);
    } else {
      // Keep the higher severity finding
      const existingSev = severityOrder[existing.severity] ?? 0;
      const newSev = severityOrder[finding.severity] ?? 0;
      if (newSev > existingSev) {
        seen.set(key, finding);
      }
    }
  }

  return Array.from(seen.values());
}

/**
 * Check if a finding is similar to historical findings in Qdrant.
 * Uses simple text embedding via keyword matching since we may not
 * have access to an embedding model.
 *
 * @returns true if a similar finding already exists
 */
export async function findSimilarInQdrant(
  finding: AgentFinding,
  qdrantClient: QdrantClient,
): Promise<boolean> {
  try {
    // Build a simple bag-of-words vector for search
    // This uses the Qdrant search endpoint with a text query
    const searchText = `${finding.type} ${finding.title} ${finding.target} ${finding.description}`;
    const tokens = searchText
      .toLowerCase()
      .split(/\s+/)
      .filter(t => t.length > 2);

    // Create a simple hash-based pseudo-embedding (1536 dims to match collection)
    const embedding = new Array<number>(1536).fill(0);
    for (const token of tokens) {
      const idx = Math.abs(simpleHash(token)) % 1536;
      embedding[idx] += 1.0;
    }

    // Normalize
    const magnitude = Math.sqrt(embedding.reduce((s, v) => s + v * v, 0));
    if (magnitude > 0) {
      for (let i = 0; i < embedding.length; i++) {
        embedding[i] /= magnitude;
      }
    }

    const results = await qdrantClient.search(embedding, 3, 0.8);
    return results.length > 0;
  } catch {
    // Qdrant unavailable — don't block the pipeline
    return false;
  }
}

function simpleHash(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return hash;
}

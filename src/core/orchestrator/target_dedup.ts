/**
 * Target Deduplication — Pre-Dispatch Target Grouping
 *
 * Deduplicates targets before agent dispatch to avoid wasting resources testing
 * duplicate/mirror pages. Uses SimHash from finding_dedup to group targets by
 * content similarity, URL normalization to detect structurally identical URLs,
 * and API path structure analysis for API endpoints.
 *
 * Flow:
 * 1. Normalize all URLs (strip params, fragments, trailing slashes, www prefix)
 * 2. Group identical normalized URLs immediately (no fetch needed)
 * 3. Detect API endpoints and group by path structure
 * 4. Fetch remaining targets' HTML in rate-limited concurrent batches
 * 5. Compute SimHash and group by Hamming distance <= 5
 * 6. Return representative targets and their groups
 */

import { computeSimHash, simHashDistance } from './finding_dedup';
import type { HttpClient } from '../http/request_engine';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface TargetInfo {
  url: string;
  assetType: 'domain' | 'api' | 'web-application' | 'wildcard';
  priority?: number;
}

export interface TargetGroup {
  representative: TargetInfo;
  members: TargetInfo[];
  simhash: bigint;
  similarity: number;
}

export interface DeduplicationResult {
  representatives: TargetInfo[];
  groups: TargetGroup[];
  stats: {
    total: number;
    unique: number;
    duplicates: number;
    fetchErrors: number;
  };
}

interface FetchedTarget {
  target: TargetInfo;
  html: string;
  simhash: bigint;
  fetchError: boolean;
}

// ─── Constants ───────────────────────────────────────────────────────────────

/** Maximum Hamming distance to consider two pages as duplicates */
const SIMHASH_THRESHOLD = 5;

/** Maximum concurrent fetches per batch */
const CONCURRENCY_LIMIT = 5;

/** Delay between fetch batches in milliseconds */
const BATCH_DELAY_MS = 500;

/** Per-target fetch timeout in milliseconds */
const FETCH_TIMEOUT_MS = 10_000;

/** Regex patterns that indicate an API endpoint */
const API_PATH_PATTERNS = [
  /\/api\//i,
  /\/v[0-9]+\//i,
  /\/graphql/i,
  /\/rest\//i,
  /\/rpc\//i,
];

// ─── URL Normalization ───────────────────────────────────────────────────────

/**
 * Normalize a URL for deduplication comparison.
 * - Strip query parameters and fragments
 * - Remove trailing slashes
 * - Upgrade http to https
 * - Remove www. prefix
 * - Lowercase the hostname
 */
function normalizeUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    // If the URL cannot be parsed, return it lowercased as-is
    return raw.toLowerCase().replace(/\/+$/, '');
  }

  // Upgrade http to https
  if (parsed.protocol === 'http:') {
    parsed.protocol = 'https:';
  }

  // Remove www. prefix
  let hostname = parsed.hostname.toLowerCase();
  if (hostname.startsWith('www.')) {
    hostname = hostname.substring(4);
  }

  // Reconstruct without query, fragment, and trailing slashes
  let path = parsed.pathname;
  // Remove trailing slashes (but keep root "/" as "/")
  if (path.length > 1) {
    path = path.replace(/\/+$/, '');
  }

  // Port: only include if non-standard
  let portSuffix = '';
  if (parsed.port) {
    const port = parseInt(parsed.port, 10);
    const isStandard =
      (parsed.protocol === 'https:' && port === 443) ||
      (parsed.protocol === 'http:' && port === 80);
    if (!isStandard) {
      portSuffix = `:${parsed.port}`;
    }
  }

  return `${parsed.protocol}//${hostname}${portSuffix}${path}`;
}

// ─── API Endpoint Detection ──────────────────────────────────────────────────

/**
 * Determine if a URL looks like an API endpoint based on its path.
 */
function isApiEndpoint(url: string): boolean {
  let pathname: string;
  try {
    pathname = new URL(url).pathname;
  } catch {
    return false;
  }
  return API_PATH_PATTERNS.some(pattern => pattern.test(pathname));
}

/**
 * Extract a structural path signature for API endpoints.
 * Replaces dynamic path segments (UUIDs, numeric IDs, hex tokens) with
 * placeholders so that `/api/v1/users/123` and `/api/v1/users/456` produce
 * the same signature.
 */
function apiPathSignature(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return url;
  }

  const segments = parsed.pathname.split('/').map(segment => {
    // Replace purely numeric segments
    if (/^\d+$/.test(segment)) return ':id';
    // Replace UUID-like segments
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) return ':uuid';
    // Replace hex tokens (8+ hex chars)
    if (/^[0-9a-f]{8,}$/i.test(segment)) return ':token';
    // Replace base64-like segments (16+ alphanumeric chars with mixed case)
    if (segment.length >= 16 && /^[A-Za-z0-9_-]+$/.test(segment) && /[a-z]/.test(segment) && /[A-Z]/.test(segment)) return ':token';
    return segment.toLowerCase();
  });

  let hostname = parsed.hostname.toLowerCase();
  if (hostname.startsWith('www.')) {
    hostname = hostname.substring(4);
  }

  return `${hostname}${segments.join('/')}`;
}

// ─── Concurrent Fetch Helper ─────────────────────────────────────────────────

/**
 * Fetch HTML content for targets in rate-limited concurrent batches.
 * Returns fetched content per target. On fetch error, marks the target
 * so it can be preserved as unique.
 */
async function fetchTargetBatch(
  targets: TargetInfo[],
  httpClient: HttpClient | undefined,
): Promise<FetchedTarget[]> {
  const results: FetchedTarget[] = [];

  // Split targets into batches of CONCURRENCY_LIMIT
  for (let batchStart = 0; batchStart < targets.length; batchStart += CONCURRENCY_LIMIT) {
    const batch = targets.slice(batchStart, batchStart + CONCURRENCY_LIMIT);

    const batchResults = await Promise.allSettled(
      batch.map(async (target): Promise<FetchedTarget> => {
        const html = await fetchTargetHtml(target.url, httpClient);
        if (html === null) {
          return {
            target,
            html: '',
            simhash: 0n,
            fetchError: true,
          };
        }
        const simhash = computeSimHash(html);
        return { target, html, simhash, fetchError: false };
      }),
    );

    for (const result of batchResults) {
      if (result.status === 'fulfilled') {
        results.push(result.value);
      }
      // Rejected promises should not happen since we catch inside, but handle defensively
      if (result.status === 'rejected') {
        // We cannot recover the target reference from a rejected promise,
        // so this path is guarded by the inner try/catch in fetchTargetHtml.
      }
    }

    // Delay between batches (skip delay after the last batch)
    if (batchStart + CONCURRENCY_LIMIT < targets.length) {
      await sleep(BATCH_DELAY_MS);
    }
  }

  return results;
}

/**
 * Fetch a single target's HTML content.
 * Returns null on any error (timeout, network, scope, etc.).
 */
async function fetchTargetHtml(
  url: string,
  httpClient: HttpClient | undefined,
): Promise<string | null> {
  try {
    if (httpClient) {
      const response = await httpClient.request({
        url,
        method: 'GET',
        timeoutMs: FETCH_TIMEOUT_MS,
        followRedirects: true,
        headers: {
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'User-Agent': 'Mozilla/5.0 (compatible; HuntressDedup/1.0)',
        },
      });
      return response.body;
    }

    // Fallback: use global fetch if available (test environments)
    if (typeof globalThis.fetch === 'function') {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      try {
        const response = await globalThis.fetch(url, {
          signal: controller.signal,
          headers: {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'User-Agent': 'Mozilla/5.0 (compatible; HuntressDedup/1.0)',
          },
          redirect: 'follow',
        });
        return await response.text();
      } finally {
        clearTimeout(timeout);
      }
    }

    return null;
  } catch {
    return null;
  }
}

// ─── SimHash Grouping ────────────────────────────────────────────────────────

/**
 * Group fetched targets by SimHash similarity.
 * Targets within SIMHASH_THRESHOLD Hamming distance are placed in the same group.
 * Targets with fetch errors are each placed in their own singleton group.
 */
function groupByContentSimilarity(fetched: FetchedTarget[]): TargetGroup[] {
  const groups: TargetGroup[] = [];

  for (const item of fetched) {
    // Fetch errors get their own group — we cannot compare them
    if (item.fetchError) {
      groups.push({
        representative: item.target,
        members: [item.target],
        simhash: 0n,
        similarity: 1.0,
      });
      continue;
    }

    let matched = false;
    for (const group of groups) {
      // Skip matching against error-singleton groups
      if (group.simhash === 0n && group.members.length === 1 && group.similarity === 1.0) {
        // Check if this is an error group by checking if the only member
        // was a fetch error. We use the simhash being 0n and single member
        // as a heuristic, but a legit page could also hash to 0n.
        // To be safe, only skip if the representative URL differs.
        continue;
      }

      const distance = simHashDistance(item.simhash, group.simhash);
      if (distance <= SIMHASH_THRESHOLD) {
        group.members.push(item.target);
        // Update average similarity: convert Hamming distance to similarity
        // 0 distance = 1.0, 64 distance = 0.0
        group.similarity = computeGroupSimilarity(group.simhash, fetched, group.members);
        matched = true;
        break;
      }
    }

    if (!matched) {
      groups.push({
        representative: item.target,
        members: [item.target],
        simhash: item.simhash,
        similarity: 1.0,
      });
    }
  }

  return groups;
}

/**
 * Compute average pairwise similarity for a group.
 * Similarity = 1 - (hammingDistance / 64).
 */
function computeGroupSimilarity(
  groupHash: bigint,
  allFetched: FetchedTarget[],
  members: TargetInfo[],
): number {
  if (members.length <= 1) return 1.0;

  // Build a map of URL -> simhash for group members
  const memberHashes: bigint[] = [];
  for (const member of members) {
    const fetched = allFetched.find(f => f.target.url === member.url);
    if (fetched && !fetched.fetchError) {
      memberHashes.push(fetched.simhash);
    }
  }

  if (memberHashes.length <= 1) return 1.0;

  // Compute average pairwise similarity
  let totalSimilarity = 0;
  let pairCount = 0;

  for (let i = 0; i < memberHashes.length; i++) {
    for (let j = i + 1; j < memberHashes.length; j++) {
      const distance = simHashDistance(memberHashes[i], memberHashes[j]);
      totalSimilarity += 1 - distance / 64;
      pairCount++;
    }
  }

  return pairCount > 0 ? totalSimilarity / pairCount : 1.0;
}

// ─── Main Deduplicator Class ─────────────────────────────────────────────────

export class TargetDeduplicator {
  private readonly httpClient: HttpClient | undefined;
  private readonly simhashThreshold: number;

  constructor(options?: { httpClient?: HttpClient; simhashThreshold?: number }) {
    this.httpClient = options?.httpClient;
    this.simhashThreshold = options?.simhashThreshold ?? SIMHASH_THRESHOLD;
  }

  /**
   * Deduplicate an array of targets before agent dispatch.
   *
   * Strategy:
   * 1. Normalize URLs and collapse exact matches
   * 2. Group API endpoints by path structure
   * 3. Fetch remaining web targets and group by SimHash content similarity
   * 4. Merge all groups and return representatives
   */
  async deduplicateTargets(targets: TargetInfo[]): Promise<DeduplicationResult> {
    if (targets.length === 0) {
      return {
        representatives: [],
        groups: [],
        stats: { total: 0, unique: 0, duplicates: 0, fetchErrors: 0 },
      };
    }

    const totalCount = targets.length;
    let fetchErrors = 0;

    // ── Step 1: Normalize URLs and group exact matches ──
    const { uniqueTargets, normalizedGroups } = this.groupByNormalizedUrl(targets);

    // ── Step 2: Separate API endpoints from web targets ──
    const apiTargets: TargetInfo[] = [];
    const webTargets: TargetInfo[] = [];

    for (const target of uniqueTargets) {
      if (target.assetType === 'api' || isApiEndpoint(target.url)) {
        apiTargets.push(target);
      } else {
        webTargets.push(target);
      }
    }

    // ── Step 3: Group API endpoints by path structure ──
    const apiGroups = this.groupApiByPathStructure(apiTargets);

    // ── Step 4: Fetch web targets and group by SimHash ──
    const fetched = await fetchTargetBatch(webTargets, this.httpClient);
    fetchErrors = fetched.filter(f => f.fetchError).length;

    const contentGroups = groupByContentSimilarity(fetched);

    // ── Step 5: Merge all groups ──
    const allGroups: TargetGroup[] = [...normalizedGroups, ...apiGroups, ...contentGroups];
    const representatives = allGroups.map(g => g.representative);

    // Select the highest-priority target as representative in each group
    for (const group of allGroups) {
      if (group.members.length > 1) {
        const sorted = [...group.members].sort(
          (a, b) => (b.priority ?? 0) - (a.priority ?? 0),
        );
        group.representative = sorted[0];
      }
    }

    // Rebuild representatives after priority sorting
    const finalRepresentatives = allGroups.map(g => g.representative);
    const uniqueCount = finalRepresentatives.length;
    const duplicateCount = totalCount - uniqueCount;

    return {
      representatives: finalRepresentatives,
      groups: allGroups,
      stats: {
        total: totalCount,
        unique: uniqueCount,
        duplicates: duplicateCount,
        fetchErrors,
      },
    };
  }

  /**
   * Group targets that resolve to the same normalized URL.
   * Returns the set of unique targets (one per normalized URL) and
   * the groups formed by URL normalization.
   */
  private groupByNormalizedUrl(targets: TargetInfo[]): {
    uniqueTargets: TargetInfo[];
    normalizedGroups: TargetGroup[];
  } {
    const urlMap = new Map<string, TargetInfo[]>();

    for (const target of targets) {
      const normalized = normalizeUrl(target.url);
      const existing = urlMap.get(normalized);
      if (existing) {
        existing.push(target);
      } else {
        urlMap.set(normalized, [target]);
      }
    }

    const uniqueTargets: TargetInfo[] = [];
    const normalizedGroups: TargetGroup[] = [];

    for (const [, members] of urlMap) {
      // Pick the highest-priority member as representative
      const sorted = [...members].sort(
        (a, b) => (b.priority ?? 0) - (a.priority ?? 0),
      );
      const representative = sorted[0];

      if (members.length > 1) {
        // Multiple URLs normalized to the same value — form a group
        normalizedGroups.push({
          representative,
          members: [...members],
          simhash: 0n,
          similarity: 1.0, // Identical after normalization
        });
      }

      // Only the representative goes forward for further dedup
      uniqueTargets.push(representative);
    }

    return { uniqueTargets, normalizedGroups };
  }

  /**
   * Group API endpoints by structural path similarity.
   * Endpoints with the same path structure (after replacing dynamic segments
   * with placeholders) are grouped together.
   */
  private groupApiByPathStructure(apiTargets: TargetInfo[]): TargetGroup[] {
    if (apiTargets.length === 0) return [];

    const signatureMap = new Map<string, TargetInfo[]>();

    for (const target of apiTargets) {
      const signature = apiPathSignature(target.url);
      const existing = signatureMap.get(signature);
      if (existing) {
        existing.push(target);
      } else {
        signatureMap.set(signature, [target]);
      }
    }

    const groups: TargetGroup[] = [];

    for (const [, members] of signatureMap) {
      const sorted = [...members].sort(
        (a, b) => (b.priority ?? 0) - (a.priority ?? 0),
      );
      const representative = sorted[0];

      groups.push({
        representative,
        members: [...members],
        simhash: 0n,
        // API endpoints with same structure are considered highly similar
        similarity: members.length > 1 ? 0.95 : 1.0,
      });
    }

    return groups;
  }
}

// ─── Standalone Helper ───────────────────────────────────────────────────────

/**
 * Standalone convenience function to deduplicate an array of URL strings.
 * Wraps each URL as a web-application TargetInfo and runs deduplication.
 */
export async function deduplicateUrls(
  urls: string[],
  httpClient?: HttpClient,
): Promise<DeduplicationResult> {
  const targets: TargetInfo[] = urls.map(url => ({
    url,
    assetType: 'web-application' as const,
  }));

  const deduplicator = new TargetDeduplicator({ httpClient });
  return deduplicator.deduplicateTargets(targets);
}

// ─── Utility ─────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ─── Exported for Testing ────────────────────────────────────────────────────

export { normalizeUrl, isApiEndpoint, apiPathSignature };

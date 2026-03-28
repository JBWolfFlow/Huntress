/**
 * HackerOne Duplicate Checker (Phase 23C)
 *
 * Checks proposed vulnerability reports against HackerOne's disclosed reports
 * to estimate duplicate probability BEFORE submission. Uses Jaccard similarity,
 * SimHash distance, endpoint comparison, and severity matching to produce a
 * composite DuplicateScore.
 *
 * Graceful degradation:
 * - No H1 credentials  -> returns score with 0 h1Match + reasoning
 * - API request failure -> returns partial score + reasoning
 * - Never throws       -> always returns a DuplicateScore
 */

import axios, { AxiosInstance } from 'axios';
import type { H1Report } from './h1_api';
import type { DuplicateScore, DuplicateMatch } from '../../utils/duplicate_checker';
import { computeSimHash, simHashDistance } from '../orchestrator/finding_dedup';

// ─── Configuration ────────────────────────────────────────────────────────────

export interface H1DuplicateConfig {
  h1Username?: string;
  h1ApiToken?: string;
  /** Cache disclosed reports per program for 1 hour (default true) */
  cacheDisclosedReports?: boolean;
  /** Minimum similarity to flag as a potential match (default 0.7) */
  similarityThreshold?: number;
}

// ─── Disclosed Report Shape ───────────────────────────────────────────────────

export interface DisclosedReport {
  id: string;
  title: string;
  vulnerabilityType: string;
  severity: string;
  disclosedAt: string;
  description: string;
  programHandle: string;
  url: string;
}

// ─── Similarity Weight Configuration ──────────────────────────────────────────

interface SimilarityWeights {
  title: number;
  description: number;
  endpoint: number;
  severity: number;
}

const DEFAULT_WEIGHTS: SimilarityWeights = {
  title: 0.25,
  description: 0.35,
  endpoint: 0.25,
  severity: 0.15,
};

// ─── Cache Entry ──────────────────────────────────────────────────────────────

interface CacheEntry {
  reports: DisclosedReport[];
  fetchedAt: number;
}

const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// ─── Common Vulnerability Type Aliases ────────────────────────────────────────

/** Normalize vulnerability type strings so XSS / Cross-Site Scripting etc. compare equal */
function normalizeVulnType(raw: string): string {
  const lower = raw.toLowerCase().trim();

  const aliases: Record<string, string> = {
    'cross-site scripting': 'xss',
    'cross site scripting': 'xss',
    'reflected xss': 'xss',
    'stored xss': 'xss',
    'dom xss': 'xss',
    'sql injection': 'sqli',
    'server-side request forgery': 'ssrf',
    'server side request forgery': 'ssrf',
    'cross-site request forgery': 'csrf',
    'cross site request forgery': 'csrf',
    'insecure direct object reference': 'idor',
    'insecure direct object references': 'idor',
    'open redirect': 'open_redirect',
    'open redirection': 'open_redirect',
    'remote code execution': 'rce',
    'server-side template injection': 'ssti',
    'server side template injection': 'ssti',
    'xml external entity': 'xxe',
    'xml external entities': 'xxe',
    'prototype pollution': 'prototype_pollution',
    'host header injection': 'host_header',
    'path traversal': 'path_traversal',
    'directory traversal': 'path_traversal',
    'command injection': 'command_injection',
    'os command injection': 'command_injection',
    'subdomain takeover': 'subdomain_takeover',
    'graphql': 'graphql',
    'information disclosure': 'info_disclosure',
    'information leak': 'info_disclosure',
  };

  return aliases[lower] ?? lower;
}

// ─── H1DuplicateChecker ──────────────────────────────────────────────────────

export class H1DuplicateChecker {
  private client: AxiosInstance | null;
  private cache: Map<string, CacheEntry>;
  private cacheEnabled: boolean;
  private similarityThreshold: number;
  private configured: boolean;

  constructor(config: H1DuplicateConfig) {
    this.cache = new Map();
    this.cacheEnabled = config.cacheDisclosedReports ?? true;
    this.similarityThreshold = config.similarityThreshold ?? 0.7;
    this.configured = !!(config.h1Username && config.h1ApiToken);

    if (this.configured) {
      this.client = axios.create({
        baseURL: 'https://api.hackerone.com/v1',
        timeout: 30_000,
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        auth: {
          username: config.h1Username!,
          password: config.h1ApiToken!,
        },
      });
    } else {
      this.client = null;
    }
  }

  // ─── Public API ───────────────────────────────────────────────────────────

  /**
   * Full duplicate check pipeline: fetch disclosed reports, compare, score.
   * Never throws -- always returns a DuplicateScore.
   */
  async checkDuplicate(report: H1Report, programHandle: string): Promise<DuplicateScore> {
    if (!this.configured || !this.client) {
      return this.buildEmptyScore('H1 API credentials not configured — skipping HackerOne duplicate check');
    }

    let disclosed: DisclosedReport[];
    try {
      disclosed = await this.getDisclosedReports(programHandle, this.inferVulnType(report));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return this.buildEmptyScore(`Failed to fetch disclosed reports: ${message}`);
    }

    if (disclosed.length === 0) {
      return this.buildEmptyScore(
        `No disclosed reports found for program "${programHandle}" — cannot check duplicates`,
      );
    }

    let matches: DuplicateMatch[];
    try {
      matches = await this.compareWithDisclosed(report, disclosed);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return this.buildEmptyScore(`Comparison failed: ${message}`);
    }

    return this.buildScore(matches);
  }

  /**
   * Fetch disclosed reports for a program, optionally filtered by vuln type.
   * Results are cached per program handle for 1 hour when caching is enabled.
   */
  async getDisclosedReports(
    programHandle: string,
    vulnType?: string,
  ): Promise<DisclosedReport[]> {
    if (!this.client) {
      return [];
    }

    const cacheKey = programHandle.toLowerCase();
    let allReports: DisclosedReport[];

    // Check cache first
    const cached = this.cache.get(cacheKey);
    if (this.cacheEnabled && cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
      allReports = cached.reports;
    } else {
      allReports = await this.fetchDisclosedFromApi(programHandle);

      if (this.cacheEnabled) {
        this.cache.set(cacheKey, { reports: allReports, fetchedAt: Date.now() });
      }
    }

    // Filter by vulnerability type if provided
    if (vulnType) {
      const normalizedFilter = normalizeVulnType(vulnType);
      return allReports.filter(
        r => normalizeVulnType(r.vulnerabilityType) === normalizedFilter,
      );
    }

    return allReports;
  }

  /**
   * Compare a report against an array of disclosed reports and return
   * all matches that exceed the similarity threshold, sorted by similarity desc.
   */
  async compareWithDisclosed(
    report: H1Report,
    disclosed: DisclosedReport[],
  ): Promise<DuplicateMatch[]> {
    const matches: DuplicateMatch[] = [];

    for (const disc of disclosed) {
      const titleSim = this.titleSimilarity(report.title, disc.title);
      const descSim = this.descriptionSimilarity(report.description, disc.description);
      const endpointSim = this.endpointSimilarity(report, disc);
      const severitySim = this.severitySimilarity(report.severity, disc.severity);

      const aggregate = this.aggregateSimilarity({
        title: titleSim,
        description: descSim,
        endpoint: endpointSim,
        severity: severitySim,
      });

      if (aggregate >= this.similarityThreshold) {
        matches.push({
          source: 'hackerone',
          title: disc.title,
          url: disc.url,
          similarity: aggregate,
          reportId: disc.id,
          disclosedAt: disc.disclosedAt,
          program: disc.programHandle,
        });
      }
    }

    return matches.sort((a, b) => b.similarity - a.similarity);
  }

  /**
   * Invalidate cached disclosed reports for a program (or all programs).
   */
  invalidateCache(programHandle?: string): void {
    if (programHandle) {
      this.cache.delete(programHandle.toLowerCase());
    } else {
      this.cache.clear();
    }
  }

  // ─── API Fetching ─────────────────────────────────────────────────────────

  /**
   * Fetch disclosed reports from the HackerOne API with pagination.
   * Collects up to 200 reports (10 pages of 20).
   */
  private async fetchDisclosedFromApi(programHandle: string): Promise<DisclosedReport[]> {
    const results: DisclosedReport[] = [];
    const maxPages = 10;
    const pageSize = 20;
    let cursor: string | null = null;

    for (let page = 0; page < maxPages; page++) {
      const params: Record<string, string> = {
        'filter[program][]': programHandle,
        'filter[disclosed]': 'true',
        'page[size]': String(pageSize),
      };

      if (cursor) {
        params['page[cursor]'] = cursor;
      }

      let response;
      try {
        response = await this.client!.get('/hacktivity', { params });
      } catch (err: unknown) {
        // If the first page fails, propagate so the caller can report it.
        // If a later page fails, return what we have so far.
        if (page === 0) {
          throw err;
        }
        break;
      }

      const data = response.data;
      const items: unknown[] = data?.data ?? [];

      if (items.length === 0) {
        break;
      }

      for (const item of items) {
        const report = this.parseHacktivityItem(item, programHandle);
        if (report) {
          results.push(report);
        }
      }

      // Pagination: extract next cursor from links
      const nextLink: string | undefined = data?.links?.next;
      if (!nextLink) {
        break;
      }

      try {
        const nextUrl = new URL(nextLink, 'https://api.hackerone.com');
        cursor = nextUrl.searchParams.get('page[cursor]');
        if (!cursor) break;
      } catch {
        break;
      }
    }

    return results;
  }

  /**
   * Parse a single hacktivity item from the API response into a DisclosedReport.
   */
  private parseHacktivityItem(
    item: unknown,
    fallbackHandle: string,
  ): DisclosedReport | null {
    const record = item as Record<string, unknown>;
    const attrs = record.attributes as Record<string, unknown> | undefined;
    if (!attrs) return null;

    const relationships = record.relationships as Record<string, unknown> | undefined;
    const programData = relationships?.program as Record<string, unknown> | undefined;
    const programAttrs = (programData?.data as Record<string, unknown> | undefined)
      ?.attributes as Record<string, unknown> | undefined;

    const id = String(record.id ?? '');
    const title = String(attrs.title ?? '');
    const vulnerabilityType = String(
      attrs.vulnerability_type ?? attrs.weakness_name ?? '',
    );
    const severity = String(
      (attrs.severity as Record<string, unknown> | undefined)?.rating ??
        attrs.severity_rating ??
        'unknown',
    );
    const disclosedAt = String(attrs.disclosed_at ?? '');
    const description = String(attrs.vulnerability_information ?? '');
    const programHandle = String(programAttrs?.handle ?? fallbackHandle);
    const url = `https://hackerone.com/reports/${id}`;

    if (!id || !title) return null;

    return {
      id,
      title,
      vulnerabilityType,
      severity,
      disclosedAt,
      description,
      programHandle,
      url,
    };
  }

  // ─── Similarity Methods ───────────────────────────────────────────────────

  /**
   * Jaccard similarity on whitespace-tokenised, lowercased text.
   */
  jaccardSimilarity(text1: string, text2: string): number {
    const tokens1 = this.tokenize(text1);
    const tokens2 = this.tokenize(text2);

    if (tokens1.size === 0 && tokens2.size === 0) return 1.0;
    if (tokens1.size === 0 || tokens2.size === 0) return 0.0;

    let intersectionSize = 0;
    for (const token of tokens1) {
      if (tokens2.has(token)) {
        intersectionSize++;
      }
    }

    const unionSize = tokens1.size + tokens2.size - intersectionSize;
    return unionSize === 0 ? 0.0 : intersectionSize / unionSize;
  }

  /**
   * Title similarity with a boost for matching CWE identifiers or
   * vulnerability type keywords.
   */
  titleSimilarity(title1: string, title2: string): number {
    const baseSimilarity = this.jaccardSimilarity(title1, title2);

    // Boost if both titles share a CWE identifier (e.g., CWE-79)
    const cwes1 = this.extractCWEs(title1);
    const cwes2 = this.extractCWEs(title2);
    let cweBoost = 0;
    for (const cwe of cwes1) {
      if (cwes2.has(cwe)) {
        cweBoost = 0.15;
        break;
      }
    }

    // Boost if normalized vuln types match
    const type1 = this.extractVulnTypeFromTitle(title1);
    const type2 = this.extractVulnTypeFromTitle(title2);
    let typeBoost = 0;
    if (type1 && type2 && normalizeVulnType(type1) === normalizeVulnType(type2)) {
      typeBoost = 0.1;
    }

    return Math.min(1.0, baseSimilarity + cweBoost + typeBoost);
  }

  /**
   * Description similarity combining Jaccard index (60%) and SimHash distance (40%).
   */
  descriptionSimilarity(desc1: string, desc2: string): number {
    if (!desc1 && !desc2) return 1.0;
    if (!desc1 || !desc2) return 0.0;

    const jaccard = this.jaccardSimilarity(desc1, desc2);

    const hash1 = computeSimHash(desc1);
    const hash2 = computeSimHash(desc2);
    const distance = simHashDistance(hash1, hash2);
    // Convert Hamming distance (0-64) into a similarity score (1.0-0.0)
    const simhashSimilarity = 1.0 - distance / 64;

    return jaccard * 0.6 + simhashSimilarity * 0.4;
  }

  /**
   * Compare URL paths ignoring protocol and domain.
   * Returns 1.0 for identical paths, 0.0 for no overlap.
   */
  pathSimilarity(url1: string, url2: string): number {
    const path1 = this.extractPath(url1);
    const path2 = this.extractPath(url2);

    if (!path1 && !path2) return 1.0;
    if (!path1 || !path2) return 0.0;

    // Exact path match
    if (path1 === path2) return 1.0;

    // Segment-level comparison
    const segs1 = path1.split('/').filter(Boolean);
    const segs2 = path2.split('/').filter(Boolean);

    if (segs1.length === 0 && segs2.length === 0) return 1.0;
    if (segs1.length === 0 || segs2.length === 0) return 0.0;

    let matchingSegments = 0;
    const minLen = Math.min(segs1.length, segs2.length);
    for (let i = 0; i < minLen; i++) {
      if (segs1[i] === segs2[i]) {
        matchingSegments++;
      }
    }

    const maxLen = Math.max(segs1.length, segs2.length);
    return matchingSegments / maxLen;
  }

  /**
   * Aggregate individual similarity scores into a single 0-1 value
   * using the configured weights.
   */
  aggregateSimilarity(scores: {
    title: number;
    description: number;
    endpoint: number;
    severity: number;
  }): number {
    return (
      scores.title * DEFAULT_WEIGHTS.title +
      scores.description * DEFAULT_WEIGHTS.description +
      scores.endpoint * DEFAULT_WEIGHTS.endpoint +
      scores.severity * DEFAULT_WEIGHTS.severity
    );
  }

  // ─── Private Helpers ──────────────────────────────────────────────────────

  /**
   * Compute endpoint similarity between a report and a disclosed report.
   * Extracts URLs from descriptions / steps and compares paths.
   */
  private endpointSimilarity(report: H1Report, disclosed: DisclosedReport): number {
    const reportUrls = this.extractUrls(
      report.description + ' ' + (report.steps ?? []).join(' '),
    );
    const disclosedUrls = this.extractUrls(disclosed.description);

    if (reportUrls.length === 0 && disclosedUrls.length === 0) return 0.0;
    if (reportUrls.length === 0 || disclosedUrls.length === 0) return 0.0;

    // Find best path similarity among all URL pairs
    let bestSim = 0;
    for (const ru of reportUrls) {
      for (const du of disclosedUrls) {
        const sim = this.pathSimilarity(ru, du);
        if (sim > bestSim) bestSim = sim;
      }
    }

    return bestSim;
  }

  /**
   * Severity similarity: 1.0 if exact match, partial credit for adjacent.
   */
  private severitySimilarity(sev1: string, sev2: string): number {
    const s1 = sev1.toLowerCase();
    const s2 = sev2.toLowerCase();

    if (s1 === s2) return 1.0;

    const order: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
    };

    const v1 = order[s1];
    const v2 = order[s2];

    if (v1 === undefined || v2 === undefined) return 0.0;

    const distance = Math.abs(v1 - v2);
    // Adjacent severity: 0.5, two apart: 0.25, three apart: 0.0
    if (distance === 1) return 0.5;
    if (distance === 2) return 0.25;
    return 0.0;
  }

  /**
   * Infer the vulnerability type from an H1Report's title and description.
   * Used to pre-filter disclosed reports before detailed comparison.
   */
  private inferVulnType(report: H1Report): string | undefined {
    // Try weaknessId first (e.g., "cwe-79")
    if (report.weaknessId) {
      return report.weaknessId;
    }

    // Extract from title
    const titleType = this.extractVulnTypeFromTitle(report.title);
    if (titleType) return titleType;

    // Extract from description (first sentence)
    const firstSentence = report.description.split(/[.\n]/)[0] ?? '';
    return this.extractVulnTypeFromTitle(firstSentence) ?? undefined;
  }

  /** Tokenize text into a Set of lowercase words, filtering short noise words */
  private tokenize(text: string): Set<string> {
    return new Set(
      text
        .toLowerCase()
        .replace(/[^a-z0-9\s-]/g, ' ')
        .split(/\s+/)
        .filter(w => w.length > 1),
    );
  }

  /** Extract CWE identifiers from text (e.g., "CWE-79") */
  private extractCWEs(text: string): Set<string> {
    const matches = text.match(/cwe-\d+/gi) ?? [];
    return new Set(matches.map(m => m.toLowerCase()));
  }

  /** Extract a recognised vulnerability type keyword from a title string */
  private extractVulnTypeFromTitle(title: string): string | null {
    const lower = title.toLowerCase();
    const knownTypes = [
      'xss', 'cross-site scripting',
      'sqli', 'sql injection',
      'ssrf', 'server-side request forgery',
      'csrf', 'cross-site request forgery',
      'idor', 'insecure direct object reference',
      'open redirect', 'open redirection',
      'rce', 'remote code execution',
      'ssti', 'server-side template injection',
      'xxe', 'xml external entity',
      'prototype pollution',
      'host header injection',
      'path traversal', 'directory traversal',
      'command injection',
      'subdomain takeover',
      'graphql',
      'information disclosure',
    ];

    for (const t of knownTypes) {
      if (lower.includes(t)) return t;
    }
    return null;
  }

  /** Extract URLs from text */
  private extractUrls(text: string): string[] {
    const pattern = /https?:\/\/[^\s"'<>)\]]+/gi;
    return (text.match(pattern) ?? []);
  }

  /** Extract the path component from a URL string */
  private extractPath(rawUrl: string): string {
    try {
      const parsed = new URL(rawUrl);
      return parsed.pathname;
    } catch {
      // If not a valid URL, treat the whole string as a path
      const slashIdx = rawUrl.indexOf('/');
      return slashIdx >= 0 ? rawUrl.slice(slashIdx) : rawUrl;
    }
  }

  // ─── Score Builders ───────────────────────────────────────────────────────

  /**
   * Build a DuplicateScore from the set of matches found.
   */
  private buildScore(matches: DuplicateMatch[]): DuplicateScore {
    const h1Match = matches.length > 0
      ? Math.max(...matches.map(m => m.similarity))
      : 0;

    const overall = Math.round(h1Match * 100);

    const reasoning: string[] = [];

    if (matches.length === 0) {
      reasoning.push('No similar disclosed reports found on HackerOne');
    } else {
      const topMatch = matches[0];
      reasoning.push(
        `Closest H1 match: "${topMatch.title}" (${(topMatch.similarity * 100).toFixed(1)}% similarity)`,
      );
      if (matches.length > 1) {
        reasoning.push(
          `${matches.length - 1} additional similar report(s) found`,
        );
      }
    }

    const recommendation = this.deriveRecommendation(h1Match);
    switch (recommendation) {
      case 'submit':
        reasoning.push('Low duplicate risk — safe to submit');
        break;
      case 'review':
        reasoning.push('Moderate duplicate risk — manual review recommended before submission');
        break;
      case 'skip':
        reasoning.push('High duplicate risk — submission not recommended');
        break;
    }

    return {
      overall,
      h1Match,
      githubMatch: 0,
      internalMatch: 0,
      recommendation,
      matches,
      reasoning,
    };
  }

  /**
   * Build an empty DuplicateScore with a single reasoning message.
   * Used when the checker cannot perform a comparison.
   */
  private buildEmptyScore(reason: string): DuplicateScore {
    return {
      overall: 0,
      h1Match: 0,
      githubMatch: 0,
      internalMatch: 0,
      recommendation: 'review',
      matches: [],
      reasoning: [reason],
    };
  }

  /**
   * Derive a submit / review / skip recommendation from the h1Match score.
   */
  private deriveRecommendation(
    h1Match: number,
  ): 'submit' | 'review' | 'skip' {
    if (h1Match >= 0.9) return 'skip';
    if (h1Match >= 0.7) return 'review';
    return 'submit';
  }
}

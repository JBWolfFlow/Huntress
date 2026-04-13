/**
 * Active Hunt Memory (Phase 20E)
 *
 * TF-IDF based vector memory that stores findings and techniques in Qdrant
 * for cross-session learning. Uses a security-domain vocabulary for offline
 * embedding generation (no API costs).
 *
 * Key features:
 * - TF-IDF embedding with security domain vocabulary
 * - Finding storage and semantic duplicate detection
 * - Technique recall across targets with similar tech stacks
 * - Graceful degradation when Qdrant is unavailable
 */

import type { QdrantClient, SearchResult } from './qdrant_client';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AgentFindingInput {
  title: string;
  vulnerabilityType: string;
  severity: string;
  target: string;
  description: string;
  evidence: string[];
  confidence: number;
}

export interface TechniqueRecord {
  technique: string;
  target: string;
  vulnType: string;
  success: boolean;
  timestamp: number;
}

// ─── Security Domain Vocabulary ─────────────────────────────────────────────

const SECURITY_VOCABULARY: string[] = [
  // Vulnerability types
  'xss', 'sqli', 'ssrf', 'csrf', 'idor', 'bola', 'ssti', 'xxe', 'rce', 'lfi',
  'open_redirect', 'cors', 'crlf', 'command_injection', 'path_traversal',
  'prototype_pollution', 'subdomain_takeover', 'jwt', 'oauth', 'graphql',
  'race_condition', 'mass_assignment', 'information_disclosure', 'deserialization',
  'host_header', 'business_logic', 'privilege_escalation', 'authentication_bypass',
  // Techniques
  'reflected', 'stored', 'dom', 'blind', 'error_based', 'time_based', 'union_based',
  'boolean_based', 'out_of_band', 'second_order', 'parameter_pollution',
  'header_injection', 'cookie_injection', 'template_injection', 'server_side',
  'client_side', 'redirect_chain', 'metadata', 'internal', 'localhost',
  // Technologies
  'react', 'angular', 'vue', 'jquery', 'express', 'django', 'flask', 'rails',
  'spring', 'laravel', 'wordpress', 'drupal', 'joomla', 'nginx', 'apache', 'iis',
  'tomcat', 'node', 'php', 'python', 'java', 'dotnet', 'ruby', 'golang',
  'mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch', 'sqlite',
  'aws', 'gcp', 'azure', 'cloudflare', 'cloudfront', 'firebase',
  'docker', 'kubernetes', 'graphql', 'rest', 'soap', 'grpc', 'websocket',
  // Targets
  'api', 'endpoint', 'form', 'login', 'admin', 'dashboard', 'upload', 'download',
  'search', 'profile', 'settings', 'payment', 'checkout', 'registration',
  'password_reset', 'token', 'session', 'cookie', 'header', 'parameter',
  'query', 'body', 'path', 'fragment', 'webhook', 'callback', 'redirect_uri',
  // Severity indicators
  'critical', 'high', 'medium', 'low', 'info', 'informational',
  'account_takeover', 'data_leak', 'rce', 'privilege_escalation',
  // Tools
  'nuclei', 'burp', 'sqlmap', 'nmap', 'ffuf', 'dirsearch', 'subfinder',
  'httpx', 'waybackurls', 'gau', 'dalfox', 'kxss', 'interactsh',
  // Common terms
  'payload', 'injection', 'bypass', 'encoding', 'filter', 'sanitization',
  'validation', 'authorization', 'authentication', 'session_management',
  'input_validation', 'output_encoding', 'access_control', 'rate_limiting',
  'waf', 'firewall', 'proxy', 'certificate', 'tls', 'ssl', 'cors',
  'csp', 'hsts', 'cookie_flag', 'httponly', 'secure', 'samesite',
];

// Pre-compute IDF weights (inverse document frequency approximation)
const VOCAB_INDEX = new Map<string, number>();
SECURITY_VOCABULARY.forEach((term, idx) => VOCAB_INDEX.set(term, idx));

export const VECTOR_DIM = SECURITY_VOCABULARY.length;

// ─── Embedding Service ──────────────────────────────────────────────────────

export class EmbeddingService {
  /** Generate a TF-IDF vector for text using security domain vocabulary */
  embed(text: string): number[] {
    const lower = text.toLowerCase();
    const vector = new Float64Array(VECTOR_DIM);

    // Tokenize
    const words = lower.split(/[\s\W]+/).filter(w => w.length > 1);
    const wordCount = words.length || 1;

    // Count term frequencies
    const termFreqs = new Map<string, number>();
    for (const word of words) {
      termFreqs.set(word, (termFreqs.get(word) ?? 0) + 1);
    }

    // Also check for multi-word terms in the vocabulary
    for (const term of SECURITY_VOCABULARY) {
      if (term.includes('_')) {
        // Check both underscore and space variants
        const spaced = term.replace(/_/g, ' ');
        const noSep = term.replace(/_/g, '');
        let count = 0;
        if (lower.includes(term)) count++;
        if (lower.includes(spaced)) count++;
        if (lower.includes(noSep)) count++;
        if (count > 0) {
          termFreqs.set(term, (termFreqs.get(term) ?? 0) + count);
        }
      }
    }

    // Build TF-IDF vector
    for (const [term, freq] of termFreqs) {
      const idx = VOCAB_INDEX.get(term);
      if (idx !== undefined) {
        // TF: term frequency normalized by document length
        const tf = freq / wordCount;
        // IDF: approximate — rarer terms in vocabulary get higher weight
        const idf = Math.log(VECTOR_DIM / (1 + (idx % 10 + 1)));
        vector[idx] = tf * idf;
      }
    }

    // L2 normalize
    let norm = 0;
    for (let i = 0; i < VECTOR_DIM; i++) {
      norm += vector[i] * vector[i];
    }
    norm = Math.sqrt(norm);
    if (norm > 0) {
      for (let i = 0; i < VECTOR_DIM; i++) {
        vector[i] /= norm;
      }
    }

    return Array.from(vector);
  }

  /** Batch embed multiple texts */
  embedBatch(texts: string[]): number[][] {
    return texts.map(t => this.embed(t));
  }
}

// ─── Cosine Similarity ──────────────────────────────────────────────────────

export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) return 0;
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom > 0 ? dot / denom : 0;
}

// ─── Hunt Memory ────────────────────────────────────────────────────────────

export class HuntMemory {
  private qdrant: QdrantClient | null;
  private embedder: EmbeddingService;
  private initialized = false;
  private static readonly COLLECTION = 'huntress_memory';

  constructor(qdrantClient: QdrantClient | null, embeddingService?: EmbeddingService) {
    this.qdrant = qdrantClient;
    this.embedder = embeddingService ?? new EmbeddingService();
  }

  /** Initialize Qdrant collection — safe to call if Qdrant unavailable */
  async initialize(): Promise<void> {
    if (!this.qdrant) return;
    try {
      await this.qdrant.initializeCollection(VECTOR_DIM);
      this.initialized = true;
    } catch {
      // Qdrant unavailable — graceful degradation
      this.qdrant = null;
    }
  }

  /** Store a finding with its embedding */
  async recordFinding(finding: AgentFindingInput, sessionId: string): Promise<void> {
    if (!this.qdrant || !this.initialized) return;

    const text = `${finding.title} ${finding.vulnerabilityType} ${finding.target} ${finding.description} ${finding.evidence.join(' ')}`;
    const vector = this.embedder.embed(text);

    try {
      await this.qdrant.upsertPoint({
        id: `finding_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
        vector,
        payload: {
          type: 'finding',
          sessionId,
          title: finding.title,
          vulnType: finding.vulnerabilityType,
          severity: finding.severity,
          target: finding.target,
          confidence: finding.confidence,
          timestamp: Date.now(),
        },
      });
    } catch {
      // Qdrant write failure — non-fatal
    }
  }

  /** Store a technique with its outcome */
  async recordTechnique(technique: string, target: string, vulnType: string, success: boolean): Promise<void> {
    if (!this.qdrant || !this.initialized) return;

    const text = `${technique} ${vulnType} ${target}`;
    const vector = this.embedder.embed(text);

    try {
      await this.qdrant.upsertPoint({
        id: `technique_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
        vector,
        payload: {
          type: 'technique',
          technique,
          target,
          vulnType,
          success,
          timestamp: Date.now(),
        },
      });
    } catch {
      // Non-fatal
    }
  }

  /** Query for techniques that worked on similar targets */
  async queryRelevantTechniques(
    target: string,
    vulnType: string,
    limit: number = 10,
  ): Promise<Array<{ technique: string; similarity: number; wasSuccessful: boolean }>> {
    if (!this.qdrant || !this.initialized) return [];

    const queryText = `${vulnType} ${target}`;
    const vector = this.embedder.embed(queryText);

    try {
      const results = await this.qdrant.searchWithFilter(
        vector,
        { type: 'technique' },
        limit,
      );

      return results.map(r => ({
        technique: String(r.payload.technique ?? ''),
        similarity: r.score,
        wasSuccessful: Boolean(r.payload.success),
      }));
    } catch {
      return [];
    }
  }

  /** Check if a finding is semantically similar to an existing one */
  async checkDuplicate(
    finding: AgentFindingInput,
    threshold: number = 0.85,
  ): Promise<{ isDuplicate: boolean; similarFinding?: SearchResult }> {
    if (!this.qdrant || !this.initialized) {
      return { isDuplicate: false };
    }

    const text = `${finding.title} ${finding.vulnerabilityType} ${finding.target} ${finding.description}`;
    const vector = this.embedder.embed(text);

    try {
      const results = await this.qdrant.searchWithFilter(
        vector,
        { type: 'finding' },
        1,
      );

      if (results.length > 0 && results[0].score >= threshold) {
        return { isDuplicate: true, similarFinding: results[0] };
      }
    } catch {
      // Non-fatal
    }

    return { isDuplicate: false };
  }

  /** Query past findings for a specific target domain.
   *  Used at hunt start to seed cross-hunt duplicate detection (H26). */
  async queryPastFindingsForTarget(
    target: string,
    limit: number = 50,
  ): Promise<Array<{ title: string; vulnType: string; severity: string; similarity: number; sessionId: string }>> {
    if (!this.qdrant || !this.initialized) return [];

    const text = `finding ${target}`;
    const vector = this.embedder.embed(text);

    try {
      const results = await this.qdrant.searchWithFilter(
        vector,
        { type: 'finding' },
        limit,
      );

      return results
        .filter(r => {
          // Only return findings for the same target domain
          const findingTarget = String(r.payload.target ?? '');
          try {
            const targetHost = new URL(target.startsWith('http') ? target : `https://${target}`).hostname;
            const findingHost = new URL(findingTarget.startsWith('http') ? findingTarget : `https://${findingTarget}`).hostname;
            return targetHost === findingHost || findingTarget.includes(targetHost) || targetHost.includes(String(r.payload.target ?? ''));
          } catch {
            return findingTarget.includes(target) || target.includes(findingTarget);
          }
        })
        .map(r => ({
          title: String(r.payload.title ?? ''),
          vulnType: String(r.payload.vulnType ?? ''),
          severity: String(r.payload.severity ?? ''),
          similarity: r.score,
          sessionId: String(r.payload.sessionId ?? ''),
        }));
    } catch {
      return [];
    }
  }

  /** Find targets with similar tech stacks */
  async findSimilarTargets(
    techStack: string[],
    limit: number = 5,
  ): Promise<Array<{ target: string; similarity: number }>> {
    if (!this.qdrant || !this.initialized) return [];

    const text = techStack.join(' ');
    const vector = this.embedder.embed(text);

    try {
      const results = await this.qdrant.search(vector, limit);
      const targets = new Map<string, number>();

      for (const r of results) {
        const target = String(r.payload.target ?? '');
        if (target && !targets.has(target)) {
          targets.set(target, r.score);
        }
      }

      return [...targets.entries()].map(([target, similarity]) => ({ target, similarity }));
    } catch {
      return [];
    }
  }

  /** Get embedding dimension */
  getVectorDimension(): number {
    return VECTOR_DIM;
  }
}

export default HuntMemory;

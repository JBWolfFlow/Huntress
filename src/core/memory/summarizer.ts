/**
 * Finding Summarizer
 *
 * Uses AI to summarize and embed security findings for storage in Qdrant.
 * Enables semantic search and duplicate detection.
 *
 * Supports two embedding strategies:
 * 1. OpenAI text-embedding-3-small via API (when OpenAI key is available)
 * 2. Deterministic hash-based embedding (fallback when no embedding API)
 */

import type { ModelProvider } from '../providers/types';

export interface Finding {
  id: string;
  type: string;
  severity: string;
  url: string;
  description: string;
  evidence: string;
  timestamp: number;
}

export interface SummarizedFinding extends Finding {
  summary: string;
  embedding: number[];
  keywords: string[];
}

export class FindingSummarizer {
  private provider?: ModelProvider;
  private model: string;
  private openaiKey?: string;
  private embeddingDimension: number = 1536;

  /**
   * Supports two constructor signatures:
   * - Legacy: `new FindingSummarizer(apiKey: string, model?: string)`
   * - Modern: `new FindingSummarizer(provider: ModelProvider, openaiKey?: string, model?: string)`
   */
  constructor(
    providerOrApiKey?: ModelProvider | string,
    openaiKeyOrModel?: string,
    model?: string
  ) {
    if (typeof providerOrApiKey === 'string' || providerOrApiKey === undefined) {
      // Legacy mode: (apiKey?, model?)
      // apiKey is ignored since we now use ModelProvider for AI calls
      this.model = openaiKeyOrModel ?? 'claude-sonnet-4-5-20250929';
    } else {
      // Modern mode: (provider, openaiKey?, model?)
      this.provider = providerOrApiKey;
      if (model) {
        this.openaiKey = openaiKeyOrModel;
        this.model = model;
      } else {
        this.model = openaiKeyOrModel ?? 'claude-sonnet-4-5-20250929';
      }
    }
  }

  /** Update the model provider used for summarization */
  setProvider(provider: ModelProvider, model?: string): void {
    this.provider = provider;
    if (model) this.model = model;
  }

  /** Set OpenAI key for embedding generation */
  setOpenAIKey(key: string): void {
    this.openaiKey = key;
  }

  /**
   * Summarize a finding for storage
   */
  async summarize(finding: Finding): Promise<SummarizedFinding> {
    const summary = await this.generateSummary(finding);
    const embedding = await this.generateEmbedding(summary);
    const keywords = this.extractKeywords(finding);

    return {
      ...finding,
      summary,
      embedding,
      keywords,
    };
  }

  /**
   * Generate concise summary of finding using the configured AI provider
   */
  private async generateSummary(finding: Finding): Promise<string> {
    if (!this.provider) {
      // Fallback: deterministic summary without AI
      return `${finding.type} vulnerability found at ${finding.url}: ${finding.description.slice(0, 200)}`;
    }

    try {
      const response = await this.provider.sendMessage(
        [
          {
            role: 'user',
            content: `Summarize this security finding in 2-3 sentences for duplicate detection and search indexing.

Type: ${finding.type}
Severity: ${finding.severity}
URL: ${finding.url}
Description: ${finding.description}
Evidence: ${finding.evidence}`,
          },
        ],
        {
          model: this.model,
          maxTokens: 256,
          systemPrompt:
            'You are a security finding summarizer. Output ONLY the summary, no preamble.',
        }
      );
      return response.content;
    } catch {
      // Fallback on error
      return `${finding.type} vulnerability found at ${finding.url}`;
    }
  }

  /**
   * Generate embedding vector for semantic search.
   * Uses OpenAI embeddings API when available, otherwise falls back to
   * a deterministic hash-based embedding.
   */
  private async generateEmbedding(text: string): Promise<number[]> {
    if (this.openaiKey) {
      try {
        return await this.fetchOpenAIEmbedding(text);
      } catch {
        // Fall through to hash-based embedding
      }
    }

    return this.hashEmbedding(text);
  }

  /**
   * Fetch embedding from OpenAI's text-embedding-3-small model
   */
  private async fetchOpenAIEmbedding(text: string): Promise<number[]> {
    const res = await fetch('https://api.openai.com/v1/embeddings', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.openaiKey}`,
      },
      body: JSON.stringify({
        model: 'text-embedding-3-small',
        input: text,
        dimensions: this.embeddingDimension,
      }),
    });

    if (!res.ok) {
      throw new Error(`OpenAI embedding failed: ${res.status}`);
    }

    const data = await res.json();
    return data.data[0].embedding as number[];
  }

  /**
   * Deterministic hash-based embedding (fallback).
   * Produces a pseudo-random unit vector from the input text.
   * Not as semantically meaningful as a real embedding model, but
   * sufficient for basic deduplication.
   */
  private hashEmbedding(text: string): number[] {
    const lower = text.toLowerCase();
    const embedding = new Array<number>(this.embeddingDimension);

    // Seed from a simple string hash
    let h = 0;
    for (let i = 0; i < lower.length; i++) {
      h = ((h << 5) - h + lower.charCodeAt(i)) | 0;
    }

    // Fill vector with pseudo-random values
    let state = Math.abs(h) || 1;
    for (let i = 0; i < this.embeddingDimension; i++) {
      // xorshift32
      state ^= state << 13;
      state ^= state >> 17;
      state ^= state << 5;
      embedding[i] = (state >>> 0) / 4294967296 - 0.5;
    }

    // Normalize to unit vector
    let norm = 0;
    for (let i = 0; i < this.embeddingDimension; i++) {
      norm += embedding[i] * embedding[i];
    }
    norm = Math.sqrt(norm);
    if (norm > 0) {
      for (let i = 0; i < this.embeddingDimension; i++) {
        embedding[i] /= norm;
      }
    }

    return embedding;
  }

  /**
   * Extract keywords from finding
   */
  private extractKeywords(finding: Finding): string[] {
    const keywords: Set<string> = new Set();

    // Add type and severity
    keywords.add(finding.type.toLowerCase());
    keywords.add(finding.severity.toLowerCase());

    // Extract domain
    try {
      const url = new URL(finding.url);
      keywords.add(url.hostname);
    } catch {
      // Invalid URL, skip
    }

    // Extract words from description
    const words = finding.description
      .toLowerCase()
      .split(/\W+/)
      .filter((word) => word.length > 3);

    words.slice(0, 10).forEach((word) => keywords.add(word));

    return Array.from(keywords);
  }

  /**
   * Check if finding is duplicate
   */
  async isDuplicate(
    finding: Finding,
    existingFindings: SummarizedFinding[],
    threshold: number = 0.85
  ): Promise<boolean> {
    const summarized = await this.summarize(finding);

    for (const existing of existingFindings) {
      const similarity = this.cosineSimilarity(summarized.embedding, existing.embedding);

      if (similarity >= threshold) {
        return true;
      }
    }

    return false;
  }

  /**
   * Calculate cosine similarity between two vectors
   */
  private cosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length) {
      throw new Error('Vectors must have same length');
    }

    let dotProduct = 0;
    let normA = 0;
    let normB = 0;

    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }

    const denominator = Math.sqrt(normA) * Math.sqrt(normB);
    if (denominator === 0) return 0;
    return dotProduct / denominator;
  }
}

export default FindingSummarizer;

/**
 * Finding Summarizer
 * 
 * Uses AI to summarize and embed security findings for storage in Qdrant.
 * Enables semantic search and duplicate detection.
 */

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
  private apiKey: string;
  private model: string;

  constructor(apiKey: string, model: string = 'claude-3-5-sonnet-20241022') {
    this.apiKey = apiKey;
    this.model = model;
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
   * Generate concise summary of finding
   */
  private async generateSummary(finding: Finding): Promise<string> {
    // TODO: Implement AI-powered summarization
    // Use Claude API to generate concise summary
    return `${finding.type} vulnerability found at ${finding.url}`;
  }

  /**
   * Generate embedding vector for semantic search
   */
  private async generateEmbedding(text: string): Promise<number[]> {
    // TODO: Implement embedding generation
    // Use OpenAI embeddings API or similar
    // For now, return placeholder
    return new Array(1536).fill(0);
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
      .filter(word => word.length > 3);

    words.slice(0, 10).forEach(word => keywords.add(word));

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
      const similarity = this.cosineSimilarity(
        summarized.embedding,
        existing.embedding
      );

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

    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
  }
}

export default FindingSummarizer;
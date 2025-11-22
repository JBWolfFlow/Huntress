/**
 * Duplicate Checker
 * 
 * Checks for duplicate findings using vector similarity
 */

import { QdrantClient, type SearchResult } from '../core/memory/qdrant_client';
import { FindingSummarizer, type Finding } from '../core/memory/summarizer';

export interface DuplicateCheckResult {
  isDuplicate: boolean;
  similarFindings: SearchResult[];
  confidence: number;
}

export class DuplicateChecker {
  private qdrant: QdrantClient;
  private summarizer: FindingSummarizer;
  private threshold: number;

  constructor(
    qdrant: QdrantClient,
    summarizer: FindingSummarizer,
    threshold: number = 0.85
  ) {
    this.qdrant = qdrant;
    this.summarizer = summarizer;
    this.threshold = threshold;
  }

  /**
   * Check if finding is duplicate
   */
  async check(finding: Finding): Promise<DuplicateCheckResult> {
    // Summarize and embed the finding
    const summarized = await this.summarizer.summarize(finding);

    // Search for similar findings in Qdrant
    const similar = await this.qdrant.search(
      summarized.embedding,
      5,
      this.threshold
    );

    const isDuplicate = similar.length > 0 && similar[0].score >= this.threshold;
    const confidence = similar.length > 0 ? similar[0].score : 0;

    return {
      isDuplicate,
      similarFindings: similar,
      confidence,
    };
  }

  /**
   * Store finding in database
   */
  async store(finding: Finding): Promise<void> {
    const summarized = await this.summarizer.summarize(finding);

    await this.qdrant.upsertPoint({
      id: finding.id,
      vector: summarized.embedding,
      payload: {
        type: finding.type,
        severity: finding.severity,
        url: finding.url,
        description: finding.description,
        summary: summarized.summary,
        keywords: summarized.keywords,
        timestamp: finding.timestamp,
      },
    });
  }

  /**
   * Set similarity threshold
   */
  setThreshold(threshold: number): void {
    this.threshold = threshold;
  }
}

export default DuplicateChecker;
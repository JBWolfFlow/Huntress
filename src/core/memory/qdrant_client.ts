/**
 * Qdrant Vector Database Client
 *
 * Manages vector storage for findings, context, and historical data.
 * Enables semantic search and similarity matching for duplicate detection.
 * Communicates with Qdrant via its REST API on localhost:6333.
 */

export interface QdrantConfig {
  url: string;
  apiKey?: string;
  collectionName: string;
}

export interface VectorPoint {
  id: string;
  vector: number[];
  payload: Record<string, unknown>;
}

export interface SearchResult {
  id: string;
  score: number;
  payload: Record<string, unknown>;
}

export class QdrantClient {
  private config: QdrantConfig;
  private baseUrl: string;

  constructor(config: QdrantConfig) {
    this.config = config;
    this.baseUrl = config.url.replace(/\/+$/, '');
  }

  /** Build common request headers */
  private headers(): Record<string, string> {
    const h: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.config.apiKey) {
      h['api-key'] = this.config.apiKey;
    }
    return h;
  }

  /** Full URL for a collection endpoint */
  private collectionUrl(path: string = ''): string {
    return `${this.baseUrl}/collections/${this.config.collectionName}${path}`;
  }

  /**
   * Initialize collection if it doesn't exist
   */
  async initializeCollection(vectorSize: number = 1536): Promise<void> {
    // Check if collection already exists
    try {
      const res = await fetch(this.collectionUrl(), {
        method: 'GET',
        headers: this.headers(),
      });
      if (res.ok) return; // Collection exists
    } catch {
      // Collection doesn't exist or Qdrant unreachable — try to create
    }

    const body = {
      vectors: {
        size: vectorSize,
        distance: 'Cosine',
      },
    };

    const res = await fetch(this.collectionUrl(), {
      method: 'PUT',
      headers: this.headers(),
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Failed to create collection: ${res.status} ${text}`);
    }
  }

  /**
   * Store a vector point
   */
  async upsertPoint(point: VectorPoint): Promise<void> {
    await this.upsertPoints([point]);
  }

  /**
   * Store multiple vector points
   */
  async upsertPoints(points: VectorPoint[]): Promise<void> {
    const body = {
      points: points.map((p) => ({
        id: p.id,
        vector: p.vector,
        payload: p.payload,
      })),
    };

    const res = await fetch(this.collectionUrl('/points'), {
      method: 'PUT',
      headers: this.headers(),
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Failed to upsert points: ${res.status} ${text}`);
    }
  }

  /**
   * Search for similar vectors
   */
  async search(
    vector: number[],
    limit: number = 10,
    scoreThreshold?: number
  ): Promise<SearchResult[]> {
    const body: Record<string, unknown> = {
      vector,
      limit,
      with_payload: true,
    };

    if (scoreThreshold !== undefined) {
      body.score_threshold = scoreThreshold;
    }

    const res = await fetch(this.collectionUrl('/points/search'), {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Search failed: ${res.status} ${text}`);
    }

    const data = await res.json();
    return (data.result ?? []).map((r: Record<string, unknown>) => ({
      id: String(r.id),
      score: r.score as number,
      payload: (r.payload ?? {}) as Record<string, unknown>,
    }));
  }

  /**
   * Search with payload filter
   */
  async searchWithFilter(
    vector: number[],
    filter: Record<string, unknown>,
    limit: number = 10
  ): Promise<SearchResult[]> {
    // Build Qdrant "must" conditions from flat key/value filter
    const must = Object.entries(filter).map(([key, value]) => ({
      key,
      match: { value },
    }));

    const body = {
      vector,
      limit,
      with_payload: true,
      filter: { must },
    };

    const res = await fetch(this.collectionUrl('/points/search'), {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Filtered search failed: ${res.status} ${text}`);
    }

    const data = await res.json();
    return (data.result ?? []).map((r: Record<string, unknown>) => ({
      id: String(r.id),
      score: r.score as number,
      payload: (r.payload ?? {}) as Record<string, unknown>,
    }));
  }

  /**
   * Get point by ID
   */
  async getPoint(id: string): Promise<VectorPoint | null> {
    const res = await fetch(this.collectionUrl(`/points/${id}`), {
      method: 'GET',
      headers: this.headers(),
    });

    if (res.status === 404) return null;

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Failed to get point: ${res.status} ${text}`);
    }

    const data = await res.json();
    const point = data.result;
    if (!point) return null;

    return {
      id: String(point.id),
      vector: point.vector ?? [],
      payload: (point.payload ?? {}) as Record<string, unknown>,
    };
  }

  /**
   * Delete point by ID
   */
  async deletePoint(id: string): Promise<void> {
    const body = {
      points: [id],
    };

    const res = await fetch(this.collectionUrl('/points/delete'), {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Failed to delete point: ${res.status} ${text}`);
    }
  }

  /**
   * Delete points by filter
   */
  async deleteByFilter(filter: Record<string, unknown>): Promise<void> {
    const must = Object.entries(filter).map(([key, value]) => ({
      key,
      match: { value },
    }));

    const body = {
      filter: { must },
    };

    const res = await fetch(this.collectionUrl('/points/delete'), {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Failed to delete by filter: ${res.status} ${text}`);
    }
  }

  /**
   * List all collections in the Qdrant instance
   */
  async listCollections(): Promise<string[]> {
    const res = await fetch(`${this.baseUrl}/collections`, {
      method: 'GET',
      headers: this.headers(),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Failed to list collections: ${res.status} ${text}`);
    }

    const data = await res.json();
    const collections = data.result?.collections ?? [];
    return collections.map((c: Record<string, unknown>) => c.name as string);
  }

  /**
   * Get collection info
   */
  async getCollectionInfo(): Promise<Record<string, unknown> | null> {
    const res = await fetch(this.collectionUrl(), {
      method: 'GET',
      headers: this.headers(),
    });

    if (!res.ok) return null;

    const data = await res.json();
    return data.result as Record<string, unknown>;
  }
}

export default QdrantClient;

/**
 * Rate Limiter with Global and Per-Target Concurrency Control
 * 
 * CRITICAL PRODUCTION FIX:
 * - Hard-cap to 5 req/s total across ALL targets (Shopify/GitLab 2025 WAF rules)
 * - 1 concurrent connection per target maximum
 * - Global rate limiter enforces 5 req/s across entire application
 * - Prevents bans from exceeding >10 req/s or >3 concurrent connections
 */

export interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
  maxConcurrentPerTarget?: number;
  maxGlobalConcurrent?: number;
}

export class RateLimiter {
  private tokens: number;
  private lastRefill: number;
  private config: RateLimitConfig;
  private concurrentRequests: Map<string, number> = new Map();
  private globalConcurrent: number = 0;

  constructor(config: RateLimitConfig) {
    this.config = {
      ...config,
      maxConcurrentPerTarget: config.maxConcurrentPerTarget ?? 1,
      maxGlobalConcurrent: config.maxGlobalConcurrent ?? 5,
    };
    this.tokens = config.maxRequests;
    this.lastRefill = Date.now();
  }

  /**
   * Check if request is allowed (with concurrency tracking)
   */
  async checkLimit(target?: string): Promise<boolean> {
    this.refillTokens();
    
    // Check global concurrent limit
    if (this.globalConcurrent >= this.config.maxGlobalConcurrent!) {
      return false;
    }
    
    // Check per-target concurrent limit
    if (target) {
      const targetConcurrent = this.concurrentRequests.get(target) || 0;
      if (targetConcurrent >= this.config.maxConcurrentPerTarget!) {
        return false;
      }
    }
    
    // Check token bucket
    if (this.tokens > 0) {
      this.tokens--;
      return true;
    }
    
    return false;
  }

  /**
   * Acquire a slot for concurrent request
   */
  async acquire(target: string): Promise<boolean> {
    if (!(await this.checkLimit(target))) {
      return false;
    }
    
    // Increment counters
    this.globalConcurrent++;
    const current = this.concurrentRequests.get(target) || 0;
    this.concurrentRequests.set(target, current + 1);
    
    return true;
  }

  /**
   * Release a slot after request completes
   */
  release(target: string): void {
    // Decrement global counter
    if (this.globalConcurrent > 0) {
      this.globalConcurrent--;
    }
    
    // Decrement per-target counter
    const current = this.concurrentRequests.get(target) || 0;
    if (current > 0) {
      this.concurrentRequests.set(target, current - 1);
    }
  }

  /**
   * Wait until request is allowed
   */
  async waitForToken(target?: string): Promise<void> {
    while (!(await this.checkLimit(target))) {
      await this.sleep(100);
    }
  }

  /**
   * Wait and acquire slot
   */
  async waitAndAcquire(target: string): Promise<void> {
    while (!(await this.acquire(target))) {
      await this.sleep(100);
    }
  }

  /**
   * Refill tokens based on time elapsed
   */
  private refillTokens(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    const tokensToAdd = Math.floor(
      (elapsed / this.config.windowMs) * this.config.maxRequests
    );

    if (tokensToAdd > 0) {
      this.tokens = Math.min(
        this.config.maxRequests,
        this.tokens + tokensToAdd
      );
      this.lastRefill = now;
    }
  }

  /**
   * Get remaining tokens
   */
  getRemainingTokens(): number {
    this.refillTokens();
    return this.tokens;
  }

  /**
   * Get concurrent request count for target
   */
  getConcurrentCount(target: string): number {
    return this.concurrentRequests.get(target) || 0;
  }

  /**
   * Get global concurrent count
   */
  getGlobalConcurrentCount(): number {
    return this.globalConcurrent;
  }

  /**
   * Get statistics
   */
  getStats(): {
    remainingTokens: number;
    globalConcurrent: number;
    perTargetConcurrent: Map<string, number>;
    maxGlobalConcurrent: number;
    maxPerTargetConcurrent: number;
  } {
    return {
      remainingTokens: this.getRemainingTokens(),
      globalConcurrent: this.globalConcurrent,
      perTargetConcurrent: new Map(this.concurrentRequests),
      maxGlobalConcurrent: this.config.maxGlobalConcurrent!,
      maxPerTargetConcurrent: this.config.maxConcurrentPerTarget!,
    };
  }

  /**
   * Reset rate limiter
   */
  reset(): void {
    this.tokens = this.config.maxRequests;
    this.lastRefill = Date.now();
    this.concurrentRequests.clear();
    this.globalConcurrent = 0;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Global rate limiter instance (5 req/s across entire app)
 */
export const globalRateLimiter = new RateLimiter({
  maxRequests: 5,
  windowMs: 1000, // 5 requests per second
  maxConcurrentPerTarget: 1,
  maxGlobalConcurrent: 5,
});

export default RateLimiter;
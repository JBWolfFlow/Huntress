/**
 * Rate Limiter
 * 
 * Implements token bucket algorithm for rate limiting requests
 */

export interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
}

export class RateLimiter {
  private tokens: number;
  private lastRefill: number;
  private config: RateLimitConfig;

  constructor(config: RateLimitConfig) {
    this.config = config;
    this.tokens = config.maxRequests;
    this.lastRefill = Date.now();
  }

  /**
   * Check if request is allowed
   */
  async checkLimit(): Promise<boolean> {
    this.refillTokens();
    
    if (this.tokens > 0) {
      this.tokens--;
      return true;
    }
    
    return false;
  }

  /**
   * Wait until request is allowed
   */
  async waitForToken(): Promise<void> {
    while (!(await this.checkLimit())) {
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
   * Reset rate limiter
   */
  reset(): void {
    this.tokens = this.config.maxRequests;
    this.lastRefill = Date.now();
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

export default RateLimiter;
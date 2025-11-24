/**
 * Proxy Manager with Smart Rotation Logic
 * 
 * CRITICAL PRODUCTION FIX:
 * - Only rotates proxy on 429/403 responses or every 50-100 requests
 * - Prevents fingerprint pattern from rotating on every request
 * - Implements "sticky session" mode for related requests
 * - Tracks request count per proxy
 * - Configurable rotation threshold (default: 75 requests)
 */

export interface ProxyConfig {
  url: string;
  username?: string;
  password?: string;
  type: 'http' | 'https' | 'socks5';
}

export interface ProxyStats {
  requestCount: number;
  lastUsed: Date;
  failureCount: number;
  successCount: number;
  banned: boolean;
}

export class ProxyManager {
  private proxies: ProxyConfig[] = [];
  private currentIndex: number = 0;
  private proxyStats: Map<string, ProxyStats> = new Map();
  private requestCountSinceRotation: number = 0;
  private rotationThreshold: number;
  private stickySessionEnabled: boolean = true;

  constructor(rotationThreshold: number = 75) {
    this.rotationThreshold = rotationThreshold;
  }

  /**
   * Add proxy to pool
   */
  addProxy(proxy: ProxyConfig): void {
    this.proxies.push(proxy);
    this.proxyStats.set(proxy.url, {
      requestCount: 0,
      lastUsed: new Date(),
      failureCount: 0,
      successCount: 0,
      banned: false,
    });
  }

  /**
   * Get current proxy (sticky session - doesn't rotate automatically)
   */
  getCurrentProxy(): ProxyConfig | null {
    if (this.proxies.length === 0) {
      return null;
    }

    const proxy = this.proxies[this.currentIndex];
    const stats = this.proxyStats.get(proxy.url);
    
    if (stats) {
      stats.requestCount++;
      stats.lastUsed = new Date();
      this.requestCountSinceRotation++;
    }

    return proxy;
  }

  /**
   * Handle response and determine if rotation is needed
   * 
   * Rotates on:
   * - 429 (Too Many Requests)
   * - 403 (Forbidden)
   * - Every 50-100 requests (configurable)
   */
  handleResponse(statusCode: number, proxyUrl: string): boolean {
    const stats = this.proxyStats.get(proxyUrl);
    if (!stats) return false;

    let shouldRotate = false;

    // Check for ban indicators
    if (statusCode === 429 || statusCode === 403) {
      console.warn(`[ProxyManager] Proxy ${proxyUrl} received ${statusCode} - rotating`);
      stats.failureCount++;
      
      // Mark as potentially banned if multiple failures
      if (stats.failureCount >= 3) {
        stats.banned = true;
        console.error(`[ProxyManager] Proxy ${proxyUrl} marked as banned`);
      }
      
      shouldRotate = true;
    } else if (statusCode >= 200 && statusCode < 300) {
      stats.successCount++;
    }

    // Check rotation threshold
    if (this.requestCountSinceRotation >= this.rotationThreshold) {
      console.log(`[ProxyManager] Rotation threshold reached (${this.rotationThreshold}) - rotating`);
      shouldRotate = true;
    }

    if (shouldRotate) {
      this.rotateProxy();
    }

    return shouldRotate;
  }

  /**
   * Manually rotate to next proxy
   */
  rotateProxy(): void {
    if (this.proxies.length <= 1) {
      console.warn('[ProxyManager] Cannot rotate - only one proxy available');
      return;
    }

    const oldIndex = this.currentIndex;
    let attempts = 0;
    const maxAttempts = this.proxies.length;

    // Find next non-banned proxy
    do {
      this.currentIndex = (this.currentIndex + 1) % this.proxies.length;
      attempts++;

      const proxy = this.proxies[this.currentIndex];
      const stats = this.proxyStats.get(proxy.url);

      if (!stats?.banned) {
        break;
      }
    } while (attempts < maxAttempts);

    // Reset rotation counter
    this.requestCountSinceRotation = 0;

    const oldProxy = this.proxies[oldIndex];
    const newProxy = this.proxies[this.currentIndex];
    
    console.log(`[ProxyManager] Rotated from ${oldProxy.url} to ${newProxy.url}`);
  }

  /**
   * Force rotation (for testing or manual control)
   */
  forceRotation(): void {
    this.rotateProxy();
  }

  /**
   * Get next proxy (round-robin) - DEPRECATED, use getCurrentProxy() instead
   * @deprecated Use getCurrentProxy() for sticky sessions
   */
  getNextProxy(): ProxyConfig | null {
    console.warn('[ProxyManager] getNextProxy() is deprecated - use getCurrentProxy() for sticky sessions');
    return this.getCurrentProxy();
  }

  /**
   * Reset proxy stats (unban all)
   */
  resetStats(): void {
    for (const [url, stats] of this.proxyStats.entries()) {
      stats.banned = false;
      stats.failureCount = 0;
      stats.successCount = 0;
      stats.requestCount = 0;
    }
    console.log('[ProxyManager] All proxy stats reset');
  }

  /**
   * Remove banned proxies from pool
   */
  removeBannedProxies(): number {
    const initialCount = this.proxies.length;
    
    this.proxies = this.proxies.filter(proxy => {
      const stats = this.proxyStats.get(proxy.url);
      if (stats?.banned) {
        this.proxyStats.delete(proxy.url);
        console.log(`[ProxyManager] Removed banned proxy: ${proxy.url}`);
        return false;
      }
      return true;
    });

    // Reset index if needed
    if (this.currentIndex >= this.proxies.length) {
      this.currentIndex = 0;
    }

    const removed = initialCount - this.proxies.length;
    console.log(`[ProxyManager] Removed ${removed} banned proxies`);
    return removed;
  }

  /**
   * Get proxy statistics
   */
  getStats(): Map<string, ProxyStats> {
    return new Map(this.proxyStats);
  }

  /**
   * Get current proxy stats
   */
  getCurrentProxyStats(): ProxyStats | null {
    const proxy = this.getCurrentProxy();
    if (!proxy) return null;
    return this.proxyStats.get(proxy.url) || null;
  }

  /**
   * Load proxies from file
   */
  async loadFromFile(path: string): Promise<void> {
    // TODO: Implement file loading via Tauri API
    console.warn('[ProxyManager] loadFromFile not yet implemented');
  }

  /**
   * Get proxy count
   */
  getProxyCount(): number {
    return this.proxies.length;
  }

  /**
   * Get active (non-banned) proxy count
   */
  getActiveProxyCount(): number {
    return this.proxies.filter(proxy => {
      const stats = this.proxyStats.get(proxy.url);
      return !stats?.banned;
    }).length;
  }

  /**
   * Set rotation threshold
   */
  setRotationThreshold(threshold: number): void {
    this.rotationThreshold = threshold;
    console.log(`[ProxyManager] Rotation threshold set to ${threshold}`);
  }

  /**
   * Enable/disable sticky session mode
   */
  setStickySession(enabled: boolean): void {
    this.stickySessionEnabled = enabled;
    console.log(`[ProxyManager] Sticky session ${enabled ? 'enabled' : 'disabled'}`);
  }

  /**
   * Get rotation info
   */
  getRotationInfo(): {
    requestsSinceRotation: number;
    rotationThreshold: number;
    requestsUntilRotation: number;
    currentProxy: string | null;
  } {
    const proxy = this.proxies[this.currentIndex];
    return {
      requestsSinceRotation: this.requestCountSinceRotation,
      rotationThreshold: this.rotationThreshold,
      requestsUntilRotation: this.rotationThreshold - this.requestCountSinceRotation,
      currentProxy: proxy?.url || null,
    };
  }

  /**
   * Clear all proxies
   */
  clear(): void {
    this.proxies = [];
    this.proxyStats.clear();
    this.currentIndex = 0;
    this.requestCountSinceRotation = 0;
  }
}

export default ProxyManager;
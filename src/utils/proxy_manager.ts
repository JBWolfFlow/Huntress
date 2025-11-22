/**
 * Proxy Manager
 * 
 * Frontend interface to Rust proxy pool
 */

export interface ProxyConfig {
  url: string;
  username?: string;
  password?: string;
  type: 'http' | 'https' | 'socks5';
}

export class ProxyManager {
  private proxies: ProxyConfig[] = [];
  private currentIndex: number = 0;

  /**
   * Add proxy to pool
   */
  addProxy(proxy: ProxyConfig): void {
    this.proxies.push(proxy);
  }

  /**
   * Get next proxy (round-robin)
   */
  getNextProxy(): ProxyConfig | null {
    if (this.proxies.length === 0) {
      return null;
    }

    const proxy = this.proxies[this.currentIndex];
    this.currentIndex = (this.currentIndex + 1) % this.proxies.length;
    return proxy;
  }

  /**
   * Load proxies from file
   */
  async loadFromFile(path: string): Promise<void> {
    // TODO: Implement file loading via Tauri API
  }

  /**
   * Get proxy count
   */
  getProxyCount(): number {
    return this.proxies.length;
  }

  /**
   * Clear all proxies
   */
  clear(): void {
    this.proxies = [];
    this.currentIndex = 0;
  }
}

export default ProxyManager;
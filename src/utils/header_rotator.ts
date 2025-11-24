/**
 * Header Rotator for Realistic Browser Emulation
 * 
 * CRITICAL PRODUCTION FIX:
 * - Realistic rotating User-Agent headers (Chrome 129 on Windows/Mac/Linux)
 * - Proper Accept, Accept-Language, Accept-Encoding headers
 * - DNT, Connection, Upgrade-Insecure-Requests headers
 * - Prevents instant soft-ban from default axios/curl headers
 * - Rotates User-Agent every 10-20 requests
 */

export interface HeaderSet {
  'User-Agent': string;
  'Accept': string;
  'Accept-Language': string;
  'Accept-Encoding': string;
  'DNT': string;
  'Connection': string;
  'Upgrade-Insecure-Requests': string;
  'Sec-Fetch-Dest'?: string;
  'Sec-Fetch-Mode'?: string;
  'Sec-Fetch-Site'?: string;
}

/**
 * Realistic User-Agent strings (Chrome 129, 2025)
 */
const USER_AGENTS = [
  // Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0',
  
  // macOS
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
  
  // Linux
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
];

/**
 * Accept header variations
 */
const ACCEPT_HEADERS = [
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
];

/**
 * Accept-Language variations
 */
const ACCEPT_LANGUAGE_HEADERS = [
  'en-US,en;q=0.9',
  'en-US,en;q=0.9,es;q=0.8',
  'en-GB,en;q=0.9,en-US;q=0.8',
];

export class HeaderRotator {
  private currentUserAgentIndex: number = 0;
  private requestCount: number = 0;
  private rotationInterval: number;
  private lastRotation: number = Date.now();

  constructor(rotationInterval: number = 15) {
    this.rotationInterval = rotationInterval;
    // Start with random User-Agent
    this.currentUserAgentIndex = Math.floor(Math.random() * USER_AGENTS.length);
  }

  /**
   * Get current headers (rotates User-Agent periodically)
   */
  getHeaders(): HeaderSet {
    this.requestCount++;
    
    // Rotate User-Agent every N requests (10-20 range)
    if (this.requestCount >= this.rotationInterval) {
      this.rotateUserAgent();
      this.requestCount = 0;
      this.lastRotation = Date.now();
    }

    const headers: HeaderSet = {
      'User-Agent': USER_AGENTS[this.currentUserAgentIndex],
      'Accept': this.getRandomAccept(),
      'Accept-Language': this.getRandomAcceptLanguage(),
      'Accept-Encoding': 'gzip, deflate, br',
      'DNT': '1',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
    };

    // Add Sec-Fetch headers for Chrome-like behavior
    if (headers['User-Agent'].includes('Chrome')) {
      headers['Sec-Fetch-Dest'] = 'document';
      headers['Sec-Fetch-Mode'] = 'navigate';
      headers['Sec-Fetch-Site'] = 'none';
    }

    return headers;
  }

  /**
   * Get headers for API requests (different Accept header)
   */
  getApiHeaders(): HeaderSet {
    const headers = this.getHeaders();
    headers['Accept'] = 'application/json, text/plain, */*';
    if (headers['Sec-Fetch-Dest']) {
      headers['Sec-Fetch-Dest'] = 'empty';
    }
    return headers;
  }

  /**
   * Get headers with custom Referer
   */
  getHeadersWithReferer(referer: string): HeaderSet & { Referer: string } {
    return {
      ...this.getHeaders(),
      'Referer': referer,
    };
  }

  /**
   * Force rotation of User-Agent
   */
  rotateUserAgent(): void {
    this.currentUserAgentIndex = (this.currentUserAgentIndex + 1) % USER_AGENTS.length;
    console.log(`[HeaderRotator] Rotated to User-Agent: ${USER_AGENTS[this.currentUserAgentIndex].substring(0, 50)}...`);
  }

  /**
   * Get random Accept header
   */
  private getRandomAccept(): string {
    return ACCEPT_HEADERS[Math.floor(Math.random() * ACCEPT_HEADERS.length)];
  }

  /**
   * Get random Accept-Language header
   */
  private getRandomAcceptLanguage(): string {
    return ACCEPT_LANGUAGE_HEADERS[Math.floor(Math.random() * ACCEPT_LANGUAGE_HEADERS.length)];
  }

  /**
   * Get current User-Agent
   */
  getCurrentUserAgent(): string {
    return USER_AGENTS[this.currentUserAgentIndex];
  }

  /**
   * Get statistics
   */
  getStats(): {
    requestCount: number;
    currentUserAgent: string;
    lastRotation: Date;
    nextRotationIn: number;
  } {
    return {
      requestCount: this.requestCount,
      currentUserAgent: this.getCurrentUserAgent(),
      lastRotation: new Date(this.lastRotation),
      nextRotationIn: this.rotationInterval - this.requestCount,
    };
  }

  /**
   * Reset rotation counter
   */
  reset(): void {
    this.requestCount = 0;
    this.lastRotation = Date.now();
  }

  /**
   * Set rotation interval
   */
  setRotationInterval(interval: number): void {
    this.rotationInterval = interval;
  }
}

/**
 * Global header rotator instance
 */
export const globalHeaderRotator = new HeaderRotator(15);

export default HeaderRotator;
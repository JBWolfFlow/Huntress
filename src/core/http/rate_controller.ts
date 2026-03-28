/**
 * Adaptive Rate Controller (Phase 20J)
 *
 * Real HackerOne targets have rate limiting, IP bans, bot detection, and
 * abuse prevention. Without adaptive rate control, Huntress gets banned
 * within minutes.
 *
 * The controller uses a per-domain sliding window with three states:
 * 1. Normal — gradually ramp up request rate
 * 2. Throttled — reduce rate on 429/throttle signals
 * 3. Banned — enter cooldown period, resume at minimum rate
 *
 * Signals: 429 status, consecutive 403s, CAPTCHA pages, Retry-After headers.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface RateControllerConfig {
  /** Initial requests per second per domain (default: 2) */
  initialRate: number;
  /** Maximum requests per second per domain (default: 10) */
  maxRate: number;
  /** Minimum requests per second per domain (default: 0.5) */
  minRate: number;
  /** Rate increase factor when no throttling detected (default: 1.2) */
  rampUpFactor: number;
  /** Rate decrease factor on throttling detection (default: 0.5) */
  backoffFactor: number;
  /** Cooldown period after ban detection in ms (default: 60000) */
  banCooldownMs: number;
  /** Number of consecutive 403s to trigger ban detection (default: 3) */
  consecutiveBlockThreshold: number;
}

export interface DomainRateState {
  domain: string;
  currentRate: number;
  requestCount: number;
  throttleCount: number;
  lastRequestTime: number;
  isBanned: boolean;
  banDetectedAt?: number;
  cooldownEndsAt?: number;
  /** Internal: consecutive 403/block responses */
  consecutiveBlocks: number;
  /** Internal: tracks successful responses since last ramp-up */
  successSinceLastRamp: number;
}

// ─── CAPTCHA Detection Patterns ──────────────────────────────────────────────

const CAPTCHA_PATTERNS = [
  /captcha/i,
  /recaptcha/i,
  /hcaptcha/i,
  /challenge-platform/i,
  /cf-challenge/i,
  /turnstile/i,
];

// ─── Default Config ──────────────────────────────────────────────────────────

const DEFAULT_CONFIG: RateControllerConfig = {
  initialRate: 2,
  maxRate: 10,
  minRate: 0.5,
  rampUpFactor: 1.2,
  backoffFactor: 0.5,
  banCooldownMs: 60_000,
  consecutiveBlockThreshold: 3,
};

// ─── Rate Controller ─────────────────────────────────────────────────────────

export class RateController {
  private config: RateControllerConfig;
  private domainStates: Map<string, DomainRateState> = new Map();
  private pendingAcquires: Map<string, Array<() => void>> = new Map();

  constructor(config?: Partial<RateControllerConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /** Get current rate state for a domain */
  getState(domain: string): DomainRateState {
    return this.getOrCreateState(domain);
  }

  /** Request permission to send a request. Resolves when allowed, may delay. */
  async acquire(domain: string): Promise<void> {
    const state = this.getOrCreateState(domain);

    // Check for ban cooldown
    if (state.isBanned) {
      const now = Date.now();
      if (state.cooldownEndsAt && now < state.cooldownEndsAt) {
        // Wait for cooldown to finish
        const waitMs = state.cooldownEndsAt - now;
        await this.sleep(waitMs);
      }
      // Cooldown expired — resume at minimum rate
      state.isBanned = false;
      state.banDetectedAt = undefined;
      state.cooldownEndsAt = undefined;
      state.currentRate = this.config.minRate;
      state.consecutiveBlocks = 0;
    }

    // Calculate minimum interval between requests
    const minIntervalMs = 1000 / state.currentRate;
    const now = Date.now();
    const timeSinceLastRequest = now - state.lastRequestTime;

    if (timeSinceLastRequest < minIntervalMs) {
      const waitMs = minIntervalMs - timeSinceLastRequest;
      await this.sleep(waitMs);
    }

    state.lastRequestTime = Date.now();
    state.requestCount++;
  }

  /** Report a response so the controller can adapt rate */
  reportResponse(domain: string, statusCode: number, headers: Record<string, string>, body?: string): void {
    const state = this.getOrCreateState(domain);

    if (statusCode === 429) {
      // Rate limited — backoff
      state.throttleCount++;
      state.consecutiveBlocks = 0;
      state.successSinceLastRamp = 0;

      // Respect Retry-After header
      const retryAfter = headers['retry-after'] ?? headers['Retry-After'];
      if (retryAfter) {
        const waitSeconds = parseInt(retryAfter, 10);
        if (!isNaN(waitSeconds) && waitSeconds > 0) {
          // Block the domain for Retry-After seconds
          state.isBanned = true;
          state.banDetectedAt = Date.now();
          state.cooldownEndsAt = Date.now() + waitSeconds * 1000;
          return;
        }
      }

      // No Retry-After — reduce rate
      state.currentRate = Math.max(this.config.minRate, state.currentRate * this.config.backoffFactor);
      return;
    }

    if (statusCode === 403) {
      state.consecutiveBlocks++;

      // Check for CAPTCHA in body (ban signal)
      if (body) {
        const isCaptcha = CAPTCHA_PATTERNS.some(p => p.test(body));
        if (isCaptcha) {
          this.triggerBan(state);
          return;
        }
      }

      // Consecutive blocks → ban
      if (state.consecutiveBlocks >= this.config.consecutiveBlockThreshold) {
        this.triggerBan(state);
        return;
      }

      state.successSinceLastRamp = 0;
      return;
    }

    // Successful response — ramp up
    if (statusCode >= 200 && statusCode < 400) {
      state.consecutiveBlocks = 0;
      state.successSinceLastRamp++;

      // Ramp up after 10 consecutive successes
      if (state.successSinceLastRamp >= 10) {
        state.currentRate = Math.min(this.config.maxRate, state.currentRate * this.config.rampUpFactor);
        state.successSinceLastRamp = 0;
      }
    }
  }

  /** Check if a domain is currently banned/cooling down */
  isBanned(domain: string): boolean {
    const state = this.domainStates.get(domain);
    if (!state) return false;

    if (state.isBanned && state.cooldownEndsAt && Date.now() >= state.cooldownEndsAt) {
      // Cooldown expired
      state.isBanned = false;
      state.banDetectedAt = undefined;
      state.cooldownEndsAt = undefined;
      state.currentRate = this.config.minRate;
      state.consecutiveBlocks = 0;
      return false;
    }

    return state.isBanned;
  }

  /** Manually unban a domain */
  unban(domain: string): void {
    const state = this.domainStates.get(domain);
    if (state) {
      state.isBanned = false;
      state.banDetectedAt = undefined;
      state.cooldownEndsAt = undefined;
      state.currentRate = this.config.minRate;
      state.consecutiveBlocks = 0;
    }
  }

  /** Get all domain rate states */
  getAllStates(): DomainRateState[] {
    return [...this.domainStates.values()];
  }

  /** Reset all state */
  reset(): void {
    this.domainStates.clear();
    this.pendingAcquires.clear();
  }

  // ─── Private Helpers ─────────────────────────────────────────────────────────

  private getOrCreateState(domain: string): DomainRateState {
    let state = this.domainStates.get(domain);
    if (!state) {
      state = {
        domain,
        currentRate: this.config.initialRate,
        requestCount: 0,
        throttleCount: 0,
        lastRequestTime: 0,
        isBanned: false,
        consecutiveBlocks: 0,
        successSinceLastRamp: 0,
      };
      this.domainStates.set(domain, state);
    }
    return state;
  }

  private triggerBan(state: DomainRateState): void {
    state.isBanned = true;
    state.banDetectedAt = Date.now();
    state.cooldownEndsAt = Date.now() + this.config.banCooldownMs;
    state.consecutiveBlocks = 0;
    state.successSinceLastRamp = 0;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

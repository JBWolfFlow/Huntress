/**
 * Rate Controller & Stealth Module Tests (Phase 20J)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RateController } from '../core/http/rate_controller';
import type { RateControllerConfig } from '../core/http/rate_controller';
import { StealthModule, USER_AGENTS } from '../core/evasion/stealth';

// ─── Rate Controller Tests ───────────────────────────────────────────────────

describe('RateController', () => {
  let controller: RateController;

  beforeEach(() => {
    controller = new RateController({
      initialRate: 5,
      maxRate: 20,
      minRate: 0.5,
      rampUpFactor: 1.5,
      backoffFactor: 0.5,
      banCooldownMs: 100, // Short cooldown for tests
      consecutiveBlockThreshold: 3,
    });
  });

  describe('getState', () => {
    it('creates state for new domains with initial rate', () => {
      const state = controller.getState('example.com');
      expect(state.domain).toBe('example.com');
      expect(state.currentRate).toBe(5);
      expect(state.requestCount).toBe(0);
      expect(state.throttleCount).toBe(0);
      expect(state.isBanned).toBe(false);
    });

    it('returns existing state for known domains', () => {
      const state1 = controller.getState('example.com');
      state1.requestCount = 42;
      const state2 = controller.getState('example.com');
      expect(state2.requestCount).toBe(42);
    });
  });

  describe('acquire', () => {
    it('allows requests for new domains immediately', async () => {
      const start = Date.now();
      await controller.acquire('example.com');
      const elapsed = Date.now() - start;

      // Should be nearly instant
      expect(elapsed).toBeLessThan(50);
    });

    it('increments request count', async () => {
      await controller.acquire('example.com');
      await controller.acquire('example.com');
      await controller.acquire('example.com');

      const state = controller.getState('example.com');
      expect(state.requestCount).toBe(3);
    });

    it('manages separate state per domain', async () => {
      await controller.acquire('a.com');
      await controller.acquire('a.com');
      await controller.acquire('b.com');

      expect(controller.getState('a.com').requestCount).toBe(2);
      expect(controller.getState('b.com').requestCount).toBe(1);
    });
  });

  describe('reportResponse - rate adaptation', () => {
    it('ramps up rate after 10 consecutive successes', () => {
      const domain = 'rampup.com';
      controller.getState(domain); // Initialize

      // Report 10 successful responses
      for (let i = 0; i < 10; i++) {
        controller.reportResponse(domain, 200, {});
      }

      const state = controller.getState(domain);
      // Rate should have increased from 5 to 7.5 (5 * 1.5)
      expect(state.currentRate).toBe(7.5);
    });

    it('caps rate at maxRate', () => {
      const domain = 'maxrate.com';

      // Report lots of successes
      for (let i = 0; i < 100; i++) {
        controller.reportResponse(domain, 200, {});
      }

      const state = controller.getState(domain);
      expect(state.currentRate).toBeLessThanOrEqual(20);
    });

    it('backs off on 429 response', () => {
      const domain = 'throttled.com';
      controller.getState(domain); // Initialize at rate 5

      controller.reportResponse(domain, 429, {});

      const state = controller.getState(domain);
      expect(state.currentRate).toBe(2.5); // 5 * 0.5
      expect(state.throttleCount).toBe(1);
    });

    it('respects Retry-After header', () => {
      const domain = 'retry.com';

      controller.reportResponse(domain, 429, { 'retry-after': '5' });

      const state = controller.getState(domain);
      expect(state.isBanned).toBe(true);
      expect(state.cooldownEndsAt).toBeDefined();
      // Cooldown should be about 5 seconds from now
      const expectedCooldown = Date.now() + 5000;
      expect(Math.abs(state.cooldownEndsAt! - expectedCooldown)).toBeLessThan(100);
    });

    it('does not go below minRate', () => {
      const domain = 'minrate.com';

      // Trigger multiple 429s
      for (let i = 0; i < 10; i++) {
        controller.reportResponse(domain, 429, {});
      }

      const state = controller.getState(domain);
      expect(state.currentRate).toBeGreaterThanOrEqual(0.5);
    });
  });

  describe('ban detection', () => {
    it('triggers ban after consecutive 403s', () => {
      const domain = 'banned.com';

      controller.reportResponse(domain, 403, {});
      controller.reportResponse(domain, 403, {});
      expect(controller.isBanned(domain)).toBe(false);

      controller.reportResponse(domain, 403, {}); // 3rd consecutive → ban
      expect(controller.isBanned(domain)).toBe(true);
    });

    it('resets consecutive block counter on success', () => {
      const domain = 'reset.com';

      controller.reportResponse(domain, 403, {});
      controller.reportResponse(domain, 403, {});
      controller.reportResponse(domain, 200, {}); // Reset counter
      controller.reportResponse(domain, 403, {});
      controller.reportResponse(domain, 403, {});

      expect(controller.isBanned(domain)).toBe(false); // Only 2 consecutive
    });

    it('triggers ban on CAPTCHA detection', () => {
      const domain = 'captcha.com';

      controller.reportResponse(domain, 403, {}, '<html>Please complete the CAPTCHA</html>');
      expect(controller.isBanned(domain)).toBe(true);
    });

    it('triggers ban on hCaptcha detection', () => {
      const domain = 'hcaptcha.com';

      controller.reportResponse(domain, 403, {}, '<div class="hcaptcha-box">Verify you are human</div>');
      expect(controller.isBanned(domain)).toBe(true);
    });
  });

  describe('cooldown', () => {
    it('ban expires after cooldown period', async () => {
      const domain = 'cooldown.com';

      // Trigger ban
      controller.reportResponse(domain, 403, {});
      controller.reportResponse(domain, 403, {});
      controller.reportResponse(domain, 403, {});
      expect(controller.isBanned(domain)).toBe(true);

      // Wait for cooldown (100ms in test config)
      await new Promise(resolve => setTimeout(resolve, 150));

      expect(controller.isBanned(domain)).toBe(false);
    });

    it('resumes at minimum rate after ban', async () => {
      const domain = 'resume.com';

      // Trigger ban
      controller.reportResponse(domain, 403, {});
      controller.reportResponse(domain, 403, {});
      controller.reportResponse(domain, 403, {});

      // Wait for cooldown
      await new Promise(resolve => setTimeout(resolve, 150));

      // Acquire should work and set rate to min
      await controller.acquire(domain);
      expect(controller.getState(domain).currentRate).toBe(0.5);
    });
  });

  describe('unban', () => {
    it('manually unbans a domain', () => {
      const domain = 'manual.com';

      // Trigger ban
      controller.reportResponse(domain, 403, {});
      controller.reportResponse(domain, 403, {});
      controller.reportResponse(domain, 403, {});
      expect(controller.isBanned(domain)).toBe(true);

      controller.unban(domain);
      expect(controller.isBanned(domain)).toBe(false);
      expect(controller.getState(domain).currentRate).toBe(0.5);
    });
  });

  describe('getAllStates', () => {
    it('returns all domain states', () => {
      controller.getState('a.com');
      controller.getState('b.com');
      controller.getState('c.com');

      const states = controller.getAllStates();
      expect(states).toHaveLength(3);
      expect(states.map(s => s.domain).sort()).toEqual(['a.com', 'b.com', 'c.com']);
    });
  });

  describe('reset', () => {
    it('clears all state', () => {
      controller.getState('a.com');
      controller.getState('b.com');
      controller.reset();

      expect(controller.getAllStates()).toHaveLength(0);
    });
  });
});

// ─── Stealth Module Tests ────────────────────────────────────────────────────

describe('StealthModule', () => {
  let stealth: StealthModule;

  beforeEach(() => {
    stealth = new StealthModule();
  });

  describe('getUserAgent', () => {
    it('returns a valid User-Agent string', () => {
      const ua = stealth.getUserAgent();
      expect(ua).toContain('Mozilla');
      expect(ua.length).toBeGreaterThan(20);
    });

    it('rotates through different User-Agents', () => {
      const agents = new Set<string>();
      for (let i = 0; i < 20; i++) {
        agents.add(stealth.getUserAgent());
      }
      // Should have many diverse values
      expect(agents.size).toBeGreaterThan(5);
    });

    it('cycles back after exhausting pool', () => {
      const first = stealth.getUserAgent();
      // Skip through all UAs
      for (let i = 1; i < USER_AGENTS.length; i++) {
        stealth.getUserAgent();
      }
      const cycled = stealth.getUserAgent();
      expect(cycled).toBe(first);
    });
  });

  describe('applyToRequest', () => {
    it('adds User-Agent header when not present', () => {
      const options = stealth.applyToRequest({
        url: 'https://example.com',
        method: 'GET' as const,
      });

      expect(options.headers?.['User-Agent']).toBeDefined();
      expect(options.headers!['User-Agent']).toContain('Mozilla');
    });

    it('does not override existing User-Agent', () => {
      const options = stealth.applyToRequest({
        url: 'https://example.com',
        method: 'GET' as const,
        headers: { 'User-Agent': 'custom-agent/1.0' },
      });

      expect(options.headers!['User-Agent']).toBe('custom-agent/1.0');
    });

    it('adds Accept header', () => {
      const options = stealth.applyToRequest({
        url: 'https://example.com',
        method: 'GET' as const,
      });

      expect(options.headers?.['Accept']).toBeDefined();
      expect(options.headers!['Accept']).toContain('text/html');
    });

    it('adds Accept-Language header', () => {
      const options = stealth.applyToRequest({
        url: 'https://example.com',
        method: 'GET' as const,
      });

      expect(options.headers?.['Accept-Language']).toBeDefined();
    });

    it('does not modify the original URL', () => {
      const options = stealth.applyToRequest({
        url: 'https://example.com/path',
        method: 'POST' as const,
        body: 'data',
      });

      expect(options.url).toBe('https://example.com/path');
      expect(options.method).toBe('POST');
      expect(options.body).toBe('data');
    });
  });

  describe('getJitterDelay', () => {
    it('returns a value within configured range', () => {
      const stealth2 = new StealthModule({ jitterMaxMs: 1000 });

      for (let i = 0; i < 20; i++) {
        const delay = stealth2.getJitterDelay();
        expect(delay).toBeGreaterThanOrEqual(0);
        expect(delay).toBeLessThan(1000);
      }
    });

    it('returns 0 when jitter is disabled', () => {
      const noJitter = new StealthModule({ addJitter: false });
      expect(noJitter.getJitterDelay()).toBe(0);
    });

    it('returns 0 when jitterMaxMs is 0', () => {
      const zeroJitter = new StealthModule({ jitterMaxMs: 0 });
      expect(zeroJitter.getJitterDelay()).toBe(0);
    });

    it('produces varying delays (not all the same)', () => {
      const delays = new Set<number>();
      for (let i = 0; i < 20; i++) {
        delays.add(stealth.getJitterDelay());
      }
      // With 20 random draws from 0-2000, we should have many unique values
      expect(delays.size).toBeGreaterThan(3);
    });
  });

  describe('header normalization', () => {
    it('orders standard headers correctly', () => {
      const options = stealth.applyToRequest({
        url: 'https://example.com',
        method: 'GET' as const,
        headers: {
          'content-type': 'application/json',
          'cookie': 'session=abc',
          'authorization': 'Bearer token',
          'user-agent': 'test',
        },
      });

      const keys = Object.keys(options.headers!);
      const uaIdx = keys.indexOf('user-agent');
      const cookieIdx = keys.indexOf('cookie');
      const authIdx = keys.indexOf('authorization');
      const ctIdx = keys.indexOf('content-type');

      // Standard order: user-agent < cookie < content-type < authorization
      expect(uaIdx).toBeLessThan(cookieIdx);
      expect(cookieIdx).toBeLessThan(ctIdx);
      expect(ctIdx).toBeLessThan(authIdx);
    });
  });

  describe('getUserAgentCount', () => {
    it('returns the size of the UA pool', () => {
      expect(stealth.getUserAgentCount()).toBe(USER_AGENTS.length);
      expect(stealth.getUserAgentCount()).toBeGreaterThanOrEqual(20);
    });
  });
});

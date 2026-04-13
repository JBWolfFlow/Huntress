/**
 * Business Logic & Race Condition Patterns — Unit Tests (I9)
 *
 * Verifies that the enhanced attack playbooks contain the required
 * pattern categories for business logic and race condition testing.
 */

import { describe, it, expect } from 'vitest';

// ─── We test the system prompts contain the required patterns ───────────────
// Import the agent classes to access their system prompts via metadata

describe('Business Logic Agent Enhancement (I9)', () => {
  // Read the system prompts from the source files
  // This tests the prompt content without needing to instantiate agents

  describe('BusinessLogicHunter system prompt patterns', () => {
    // Read the raw file to extract system prompt content
    const fs = require('fs');
    const businessLogicSource = fs.readFileSync(
      require('path').join(__dirname, 'business_logic_hunter.ts'),
      'utf-8'
    );

    it('should contain payment manipulation patterns', () => {
      expect(businessLogicSource).toContain('Price manipulation');
      expect(businessLogicSource).toContain('Quantity abuse');
      expect(businessLogicSource).toContain('Currency confusion');
      expect(businessLogicSource).toContain('Zero-value orders');
      expect(businessLogicSource).toContain('Discount overflow');
    });

    it('should contain coupon stacking patterns', () => {
      expect(businessLogicSource).toContain('Stack multiple coupons');
      expect(businessLogicSource).toContain('same coupon code multiple times');
    });

    it('should contain trial abuse patterns', () => {
      expect(businessLogicSource).toContain('Trial period abuse');
      expect(businessLogicSource).toContain('Free-tier exploitation');
    });

    it('should contain workflow bypass patterns', () => {
      expect(businessLogicSource).toContain('skip step 2 (verify)');
      expect(businessLogicSource).toContain('Skip verification');
      expect(businessLogicSource).toContain('Replay completed steps');
    });

    it('should contain MFA bypass patterns (I9 new)', () => {
      expect(businessLogicSource).toContain('Skip MFA step');
      expect(businessLogicSource).toContain('MFA code reuse');
      expect(businessLogicSource).toContain('MFA downgrade');
      expect(businessLogicSource).toContain('Backup code abuse');
      expect(businessLogicSource).toContain('Account recovery bypass');
    });

    it('should contain feature interaction patterns (I9 new)', () => {
      expect(businessLogicSource).toContain('Feature Interaction Patterns');
      expect(businessLogicSource).toContain('Export as bypass');
      expect(businessLogicSource).toContain('API vs UI divergence');
      expect(businessLogicSource).toContain('Webhook as SSRF');
      expect(businessLogicSource).toContain('Import as injection');
      expect(businessLogicSource).toContain('Batch operations bypass');
      expect(businessLogicSource).toContain('Undo as replay');
    });

    it('should contain privilege escalation patterns', () => {
      expect(businessLogicSource).toContain('Privilege Escalation');
      expect(businessLogicSource).toContain('Access admin endpoints');
      expect(businessLogicSource).toContain('Mass assignment');
    });

    it('should have at least 11 attack steps', () => {
      // Count Step N: patterns
      const stepMatches = businessLogicSource.match(/### Step \d+:/g);
      expect(stepMatches).not.toBeNull();
      expect(stepMatches!.length).toBeGreaterThanOrEqual(11);
    });
  });

  describe('RaceConditionHunter TOCTOU business patterns', () => {
    const fs = require('fs');
    const raceConditionSource = fs.readFileSync(
      require('path').join(__dirname, 'race_condition_hunter.ts'),
      'utf-8'
    );

    it('should contain cart modification TOCTOU pattern', () => {
      expect(raceConditionSource).toContain('Cart Modification During Payment');
      expect(raceConditionSource).toContain('modify the cart');
    });

    it('should contain simultaneous withdrawal pattern', () => {
      expect(raceConditionSource).toContain('Simultaneous Withdrawal');
      expect(raceConditionSource).toContain('concurrent withdrawal requests');
    });

    it('should contain address change after payment TOCTOU', () => {
      expect(raceConditionSource).toContain('Address/Details Change After Payment');
      expect(raceConditionSource).toContain('redirect shipment');
    });

    it('should contain permission check bypass TOCTOU', () => {
      expect(raceConditionSource).toContain('Permission Check Bypass');
      expect(raceConditionSource).toContain('revoke permissions');
    });

    it('should still contain original race patterns', () => {
      expect(raceConditionSource).toContain('Coupon/Promo Race');
      expect(raceConditionSource).toContain('Balance/Transfer Race');
      expect(raceConditionSource).toContain('Like/Vote Race');
      expect(raceConditionSource).toContain('Registration Race');
      expect(raceConditionSource).toContain('Rate Limit Race');
    });
  });
});

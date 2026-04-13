/**
 * Hunt #7 Bug Fix — H25: Global API Limit Detection
 *
 * Tests that the isApiLimitError() function correctly detects account-level
 * API limits and distinguishes them from transient rate limits.
 */

import { describe, it, expect } from 'vitest';
import { isApiLimitError, isTransientError } from '../core/orchestrator/orchestrator_engine';

describe('API Limit Detection (H25)', () => {
  describe('isApiLimitError', () => {
    it('detects "You have reached your specified API usage limits"', () => {
      expect(isApiLimitError(
        'Error: You have reached your specified API usage limits. Please check your plan.'
      )).toBe(true);
    });

    it('detects "monthly spend limit"', () => {
      expect(isApiLimitError(
        'API error 400: Your account has reached its monthly spend limit'
      )).toBe(true);
    });

    it('detects "billing limit"', () => {
      expect(isApiLimitError(
        'Request failed: billing limit exceeded for this account'
      )).toBe(true);
    });

    it('detects "insufficient_quota"', () => {
      expect(isApiLimitError('insufficient_quota')).toBe(true);
    });

    it('detects "credit balance is too low"', () => {
      expect(isApiLimitError('Your credit balance is too low to continue')).toBe(true);
    });

    it('detects "account_spending_limit_reached"', () => {
      expect(isApiLimitError('account_spending_limit_reached')).toBe(true);
    });

    it('does NOT flag normal rate limiting (429 with short retry-after)', () => {
      expect(isApiLimitError('Rate limit exceeded (429). Retry after 2 seconds.')).toBe(false);
    });

    it('does NOT flag transient network errors', () => {
      expect(isApiLimitError('ECONNREFUSED')).toBe(false);
      expect(isApiLimitError('ETIMEDOUT')).toBe(false);
      expect(isApiLimitError('fetch failed')).toBe(false);
    });

    it('does NOT flag server errors', () => {
      expect(isApiLimitError('Internal server error 500')).toBe(false);
      expect(isApiLimitError('Bad gateway 502')).toBe(false);
    });

    it('does NOT flag auth errors (different from limit errors)', () => {
      expect(isApiLimitError('invalid_api_key')).toBe(false);
      expect(isApiLimitError('authentication_error')).toBe(false);
    });
  });

  describe('isApiLimitError is NOT transient', () => {
    it('API limit errors are classified as permanent (not retryable)', () => {
      // API limit errors should NOT be transient — we don't want retry loops
      expect(isTransientError('insufficient_quota')).toBe(false);
      expect(isTransientError('credit balance is too low')).toBe(false);
    });
  });

  describe('integration: 1 limit error → 0 subsequent dispatches', () => {
    it('the first API limit error should prevent all further dispatching', () => {
      // This tests the conceptual flow. The actual dispatch blocking is tested
      // via the apiLimitReached flag in the OrchestratorEngine (which is private).
      // Here we verify the detection function is correct.
      const errors = [
        'Error: You have reached your specified API usage limits',
        'Rate limit exceeded (429). Retry after 2 seconds.',
        'ECONNREFUSED',
        'Internal server error 500',
      ];

      const apiLimitErrors = errors.filter(isApiLimitError);
      const transientErrors = errors.filter(isTransientError);

      // Only 1 error should be an API limit
      expect(apiLimitErrors).toHaveLength(1);
      expect(apiLimitErrors[0]).toContain('usage limits');

      // The API limit error should NOT be transient
      expect(transientErrors).not.toContain(apiLimitErrors[0]);

      // The other 3 errors are not API limits
      expect(errors.filter(e => !isApiLimitError(e))).toHaveLength(3);
    });
  });
});

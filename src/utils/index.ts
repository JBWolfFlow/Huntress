/**
 * Utilities Module
 *
 * Exports utility functions and classes
 */

export { RateLimiter, type RateLimitConfig } from './rate_limiter';
export { ProxyManager, type ProxyConfig } from './proxy_manager';
export {
  DuplicateChecker,
  type DuplicateCheckResult,
  type Vulnerability,
  type DuplicateMatch,
  type DuplicateScore
} from './duplicate_checker';
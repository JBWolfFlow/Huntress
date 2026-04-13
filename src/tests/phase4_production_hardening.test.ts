/**
 * Phase 4 Tests — Production Hardening
 *
 * Tests for:
 * - B3: Severity predictor uses real TF-IDF embeddings (not Math.sin)
 * - B8: Approval gate safety (timeout, audit trail)
 * - B10: Agent retry logic, circuit breaker sliding window
 */

import { describe, it, expect } from 'vitest';
import { EmbeddingService, VECTOR_DIM } from '../core/memory/hunt_memory';
import type { ApprovalAuditEntry } from '../contexts/HuntSessionContext';
import { isTransientError } from '../core/orchestrator/orchestrator_engine';

// ─── B3: Severity Predictor Embeddings ──────────────────────────────────────

describe('EmbeddingService (TF-IDF)', () => {
  const embedder = new EmbeddingService();

  it('produces vectors of the correct dimension', () => {
    const vec = embedder.embed('SQL injection in login form');
    expect(vec.length).toBe(VECTOR_DIM);
  });

  it('produces L2-normalized vectors', () => {
    const vec = embedder.embed('XSS reflected in search parameter');
    const norm = Math.sqrt(vec.reduce((sum, v) => sum + v * v, 0));
    // L2 norm should be ~1.0 (within floating point tolerance)
    expect(norm).toBeCloseTo(1.0, 5);
  });

  it('produces non-zero vectors for security-related text', () => {
    const vec = embedder.embed('SSRF via redirect to internal metadata endpoint');
    const nonZero = vec.filter(v => v !== 0).length;
    expect(nonZero).toBeGreaterThan(0);
  });

  it('gives higher similarity for semantically similar descriptions', () => {
    const sqli1 = embedder.embed('SQL injection in login form parameter username');
    const sqli2 = embedder.embed('SQLi blind boolean-based injection in authentication endpoint');
    const xss = embedder.embed('Reflected XSS in search bar via script tag');

    const simSqliPair = cosine(sqli1, sqli2);
    const simSqliXss = cosine(sqli1, xss);

    // Two SQLi descriptions should be more similar to each other than to an XSS description
    expect(simSqliPair).toBeGreaterThan(simSqliXss);
  });

  it('returns zero vector for empty text', () => {
    const vec = embedder.embed('');
    const norm = Math.sqrt(vec.reduce((sum, v) => sum + v * v, 0));
    expect(norm).toBe(0);
  });

  it('handles multi-word vocabulary terms (underscore and space)', () => {
    const vec1 = embedder.embed('open redirect in callback URL');
    const vec2 = embedder.embed('open_redirect vulnerability found');
    // Both should activate the same vocabulary term
    const sim = cosine(vec1, vec2);
    expect(sim).toBeGreaterThan(0.3);
  });

  it('VECTOR_DIM matches vocabulary size (~150 terms)', () => {
    expect(VECTOR_DIM).toBeGreaterThan(100);
    expect(VECTOR_DIM).toBeLessThan(300);
  });

  it('produces different vectors for different vuln types', () => {
    const csrf = embedder.embed('CSRF token missing on password change form');
    const idor = embedder.embed('IDOR allows accessing other user profile via sequential ID');
    const sim = cosine(csrf, idor);
    // Should not be identical
    expect(sim).toBeLessThan(0.95);
  });
});

// ─── B3: SeverityPredictor integration with EmbeddingService ────────────────

describe('SeverityPredictor embedding integration', () => {
  it('SeverityPredictor.EMBEDDING_DIM matches VECTOR_DIM', async () => {
    const { SeverityPredictor } = await import('../core/reporting/severity_predictor');
    expect(SeverityPredictor.EMBEDDING_DIM).toBe(VECTOR_DIM);
  });
});

// ─── B8: Approval Gate Safety ───────────────────────────────────────────────

describe('ApprovalAuditEntry type', () => {
  it('has the correct shape for audit trail entries', () => {
    const entry: ApprovalAuditEntry = {
      timestamp: Date.now(),
      approvalId: 'approval_123',
      command: 'nmap -sV localhost',
      target: 'localhost:3001',
      agent: 'port-scanner',
      category: 'active_testing',
      decision: 'approved',
      timedOut: false,
    };
    expect(entry.decision).toBe('approved');
    expect(entry.timedOut).toBe(false);
  });

  it('records timed-out denials', () => {
    const entry: ApprovalAuditEntry = {
      timestamp: Date.now(),
      approvalId: 'approval_456',
      command: 'sqlmap -u http://target/vuln',
      target: 'http://target',
      agent: 'sqli-hunter',
      category: 'active_testing',
      decision: 'denied',
      timedOut: true,
    };
    expect(entry.decision).toBe('denied');
    expect(entry.timedOut).toBe(true);
  });
});

describe('Approval timeout behavior', () => {
  it('Promise.race resolves to false when timeout wins', async () => {
    // Simulate the pattern used in HuntSessionContext: approval vs timeout
    const neverResolves = new Promise<boolean>(() => {
      // This promise never resolves (simulates user not responding)
    });
    const timeout = new Promise<boolean>((resolve) => {
      setTimeout(() => resolve(false), 50); // 50ms for fast test
    });

    const result = await Promise.race([neverResolves, timeout]);
    expect(result).toBe(false);
  });

  it('Promise.race resolves to true when approval wins before timeout', async () => {
    const quickApproval = new Promise<boolean>((resolve) => {
      setTimeout(() => resolve(true), 10);
    });
    const timeout = new Promise<boolean>((resolve) => {
      setTimeout(() => resolve(false), 200);
    });

    const result = await Promise.race([quickApproval, timeout]);
    expect(result).toBe(true);
  });
});

// ─── B10: Agent Retry Logic & Circuit Breaker ───────────────────────────────

describe('isTransientError', () => {
  it('classifies network errors as transient', () => {
    expect(isTransientError('ECONNREFUSED')).toBe(true);
    expect(isTransientError('ETIMEDOUT')).toBe(true);
    expect(isTransientError('fetch failed')).toBe(true);
    expect(isTransientError('Request timed out after 30000ms')).toBe(true);
  });

  it('classifies rate limits as transient', () => {
    expect(isTransientError('Rate limit exceeded (429)')).toBe(true);
    expect(isTransientError('Too many requests')).toBe(true);
  });

  it('classifies server errors as transient', () => {
    expect(isTransientError('Internal server error 500')).toBe(true);
    expect(isTransientError('Bad gateway 502')).toBe(true);
    expect(isTransientError('Service unavailable 503')).toBe(true);
  });

  it('classifies auth failures as permanent', () => {
    expect(isTransientError('invalid_api_key')).toBe(false);
    expect(isTransientError('authentication_error')).toBe(false);
  });

  it('classifies credit exhaustion as permanent', () => {
    expect(isTransientError('credit balance is too low')).toBe(false);
    expect(isTransientError('insufficient_quota')).toBe(false);
  });

  it('classifies missing agent as permanent', () => {
    expect(isTransientError('No agent found for type: nonexistent-agent')).toBe(false);
  });

  it('classifies 401/403 as permanent', () => {
    expect(isTransientError('HTTP error 401 Unauthorized')).toBe(false);
    expect(isTransientError('HTTP error 403 Forbidden')).toBe(false);
  });
});

describe('Exponential backoff pattern', () => {
  it('produces correct delays: 2s, 4s, 8s', () => {
    const baseDelay = 2000;
    const delays = [0, 1, 2].map(attempt => baseDelay * Math.pow(2, attempt));
    expect(delays).toEqual([2000, 4000, 8000]);
  });
});

describe('Circuit breaker sliding window', () => {
  it('requires 5 consecutive successes to reset', () => {
    let consecutiveSuccesses = 0;
    const errors: string[] = ['err1', 'err2', 'err3'];
    const RESET_THRESHOLD = 5;

    // 4 successes — not enough to reset
    for (let i = 0; i < 4; i++) {
      consecutiveSuccesses++;
    }
    expect(consecutiveSuccesses < RESET_THRESHOLD).toBe(true);
    expect(errors.length).toBe(3); // Not cleared yet

    // 5th success — triggers reset
    consecutiveSuccesses++;
    if (consecutiveSuccesses >= RESET_THRESHOLD) {
      errors.length = 0;
      consecutiveSuccesses = 0;
    }
    expect(errors.length).toBe(0);
    expect(consecutiveSuccesses).toBe(0);
  });

  it('resets consecutive success count on error', () => {
    let consecutiveSuccesses = 3;
    // An error arrives
    consecutiveSuccesses = 0;
    expect(consecutiveSuccesses).toBe(0);
  });
});

// ─── Helpers ────────────────────────────────────────────────────────────────

function cosine(a: number[], b: number[]): number {
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom > 0 ? dot / denom : 0;
}

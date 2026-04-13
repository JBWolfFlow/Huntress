/**
 * New Deterministic Validators — Unit Tests (Priority 5)
 *
 * Tests the nosql_injection and bola validators with mock executeCommand.
 * Verifies:
 * 1. NoSQL injection: differential analysis (different responses = confirmed)
 * 2. NoSQL injection: same responses = not confirmed
 * 3. NoSQL injection: MongoDB error messages boost confidence
 * 4. BOLA: 200 with data = confirmed
 * 5. BOLA: 403 = not confirmed, confidence drops
 * 6. Both validators are registered (not passthrough)
 */

import { describe, it, expect } from 'vitest';
import validateFinding from './validator';
import type { ValidatorConfig } from './validator';
import type { ReactFinding } from '../engine/react_loop';

function makeFinding(overrides: Partial<ReactFinding>): ReactFinding {
  return {
    id: `test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    title: 'Test Finding',
    vulnerabilityType: 'unknown',
    severity: 'medium',
    target: 'https://example.com/api/data?id=1',
    description: 'Test finding',
    evidence: ['Test evidence'],
    reproductionSteps: ['Step 1: test'],
    impact: 'Test impact',
    confidence: 75,
    discoveredAtIteration: 1,
    agentId: 'test-agent',
    ...overrides,
  };
}

function makeConfig(responseHandler: (command: string) => string): ValidatorConfig {
  return {
    executeCommand: async (command: string) => ({
      success: true,
      stdout: responseHandler(command),
      stderr: '',
      exitCode: 0,
      executionTimeMs: 50,
    }),
    timeout: 10000,
  };
}

// ─── NoSQL Injection Validator ──────────────────────────────────────────────

describe('NoSQL Injection Validator', () => {
  it('confirms when true/false payloads return different responses', async () => {
    let callCount = 0;
    const config = makeConfig(() => {
      callCount++;
      if (callCount === 1) {
        // "True" condition — returns data
        return 'HTTP/1.1 200 OK\r\n\r\n{"users": [{"id": 1, "name": "admin"}, {"id": 2, "name": "user"}]}';
      }
      // "False" condition — returns empty
      return 'HTTP/1.1 200 OK\r\n\r\n{"users": []}';
    });

    const finding = makeFinding({
      vulnerabilityType: 'nosql_injection',
      target: 'https://example.com/api/users?username[$ne]=null',
    });

    const result = await validateFinding(finding, config);
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toBe('nosql_injection');
    expect(result.confidence).toBeGreaterThan(75);
  });

  it('does not confirm when true/false return identical responses', async () => {
    const config = makeConfig(() => {
      return 'HTTP/1.1 200 OK\r\n\r\n{"error": "unauthorized"}';
    });

    const finding = makeFinding({
      vulnerabilityType: 'nosql_injection',
      target: 'https://example.com/api/users?username[$ne]=null',
      confidence: 70,
    });

    const result = await validateFinding(finding, config);
    expect(result.confirmed).toBe(false);
    expect(result.validatorUsed).toBe('nosql_injection');
    expect(result.confidence).toBeLessThan(70);
  });

  it('confirms on MongoDB error messages', async () => {
    const config = makeConfig(() => {
      return 'HTTP/1.1 500 Error\r\n\r\nMongoError: unknown operator $gt';
    });

    const finding = makeFinding({
      vulnerabilityType: 'nosql_injection',
      target: 'https://example.com/api/search?q[$gt]=',
    });

    const result = await validateFinding(finding, config);
    expect(result.confirmed).toBe(true);
    expect(result.confidence).toBeGreaterThan(75);
  });

  it('is registered as a deterministic validator (not passthrough)', async () => {
    const config = makeConfig(() => 'HTTP/1.1 200 OK\r\n\r\nOK');
    const finding = makeFinding({ vulnerabilityType: 'nosql_injection' });

    const result = await validateFinding(finding, config);
    expect(result.validatorUsed).toBe('nosql_injection');
    expect(result.validatorUsed).not.toContain('passthrough');
  });
});

// ─── BOLA Validator ─────────────────────────────────────────────────────────

describe('BOLA Validator', () => {
  it('confirms when status 200 with data', async () => {
    const config = makeConfig(() => {
      return 'HTTP/1.1 200 OK\r\n\r\n' + '{"user": {"id": 42, "email": "victim@example.com", "name": "Other User"}}'.padEnd(250, ' ');
    });

    const finding = makeFinding({
      vulnerabilityType: 'bola',
      target: 'https://example.com/api/users/42',
    });

    const result = await validateFinding(finding, config);
    expect(result.confirmed).toBe(true);
    expect(result.validatorUsed).toBe('bola');
    expect(result.confidence).toBeGreaterThan(75);
  });

  it('does not confirm on 403 Forbidden', async () => {
    const config = makeConfig(() => {
      return 'HTTP/1.1 403 Forbidden\r\n\r\nAccess denied';
    });

    const finding = makeFinding({
      vulnerabilityType: 'bola',
      target: 'https://example.com/api/users/42',
    });

    const result = await validateFinding(finding, config);
    expect(result.confirmed).toBe(false);
    expect(result.confidence).toBeLessThan(75);
  });

  it('does not confirm on 401 Unauthorized', async () => {
    const config = makeConfig(() => {
      return 'HTTP/1.1 401 Unauthorized\r\n\r\nAuth required';
    });

    const finding = makeFinding({
      vulnerabilityType: 'bola',
      target: 'https://example.com/api/users/42',
      confidence: 80,
    });

    const result = await validateFinding(finding, config);
    expect(result.confirmed).toBe(false);
    expect(result.confidence).toBeLessThan(80);
  });

  it('is registered as a deterministic validator (not passthrough)', async () => {
    const config = makeConfig(() => 'HTTP/1.1 200 OK\r\n\r\nOK');
    const finding = makeFinding({ vulnerabilityType: 'bola' });

    const result = await validateFinding(finding, config);
    expect(result.validatorUsed).toBe('bola');
    expect(result.validatorUsed).not.toContain('passthrough');
  });
});

// ─── Verify removed from passthrough ────────────────────────────────────────

describe('Passthrough list verification', () => {
  it('nosql_injection is NOT a passthrough validator', async () => {
    const config = makeConfig(() => 'HTTP/1.1 200 OK\r\n\r\ntest');
    const finding = makeFinding({ vulnerabilityType: 'nosql_injection' });
    const result = await validateFinding(finding, config);
    expect(result.validatorUsed).not.toContain('passthrough');
  });

  it('bola is NOT a passthrough validator', async () => {
    const config = makeConfig(() => 'HTTP/1.1 200 OK\r\n\r\ntest');
    const finding = makeFinding({ vulnerabilityType: 'bola' });
    const result = await validateFinding(finding, config);
    expect(result.validatorUsed).not.toContain('passthrough');
  });
});

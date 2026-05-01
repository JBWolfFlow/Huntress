/**
 * P3-1 Experimental Training Gate tests
 *
 * Verifies the EXPERIMENTAL_TRAINING feature flag that isolates the
 * LoRA/Axolotl pipeline from production code paths. Three test classes:
 *   1. `isExperimentalTrainingEnabled` correctly reads env var + global flag
 *   2. `createContinuousLearningSystem` throws when gate is closed
 *   3. Test suite layout is correct (production training tests still run,
 *      experimental tests only run when explicitly invoked)
 *
 * These tests live in `src/tests/` (the default suite) on purpose — they
 * verify the gate ITSELF works. The experimental suite that the gate
 * protects lives in `src/tests/experimental/` and is excluded from
 * default vitest runs (see vitest.config.ts).
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  createContinuousLearningSystem,
  isExperimentalTrainingEnabled,
} from '../core/training/experimental/integration';
import type { QdrantClient } from '../core/memory/qdrant_client';

// ─── Test fixtures ──────────────────────────────────────────────────────────

const fakeQdrant = {} as unknown as QdrantClient;

/** Save and restore both opt-in mechanisms across tests. */
function withCleanGate(fn: () => void): void {
  const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
  const originalEnv = proc?.env?.EXPERIMENTAL_TRAINING;
  const g = globalThis as { __HUNTRESS_EXPERIMENTAL_TRAINING__?: unknown };
  const originalGlobal = g.__HUNTRESS_EXPERIMENTAL_TRAINING__;
  try {
    if (proc?.env) delete proc.env.EXPERIMENTAL_TRAINING;
    delete g.__HUNTRESS_EXPERIMENTAL_TRAINING__;
    fn();
  } finally {
    if (proc?.env) {
      if (originalEnv === undefined) delete proc.env.EXPERIMENTAL_TRAINING;
      else proc.env.EXPERIMENTAL_TRAINING = originalEnv;
    }
    if (originalGlobal === undefined) delete g.__HUNTRESS_EXPERIMENTAL_TRAINING__;
    else g.__HUNTRESS_EXPERIMENTAL_TRAINING__ = originalGlobal;
  }
}

// ─── isExperimentalTrainingEnabled ──────────────────────────────────────────

describe('P3-1 · isExperimentalTrainingEnabled', () => {
  beforeEach(() => {
    // Clear the gate before each test
    const g = globalThis as { __HUNTRESS_EXPERIMENTAL_TRAINING__?: unknown };
    delete g.__HUNTRESS_EXPERIMENTAL_TRAINING__;
    const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    if (proc?.env) delete proc.env.EXPERIMENTAL_TRAINING;
  });

  it('returns false by default (gate closed)', () => {
    expect(isExperimentalTrainingEnabled()).toBe(false);
  });

  it('returns true when global flag is exactly true', () => {
    (globalThis as { __HUNTRESS_EXPERIMENTAL_TRAINING__?: unknown }).__HUNTRESS_EXPERIMENTAL_TRAINING__ = true;
    expect(isExperimentalTrainingEnabled()).toBe(true);
  });

  it('does NOT trigger on truthy non-true global flag', () => {
    // Strict equality with `true` — accidental "1" or 1 should not open the gate
    const g = globalThis as { __HUNTRESS_EXPERIMENTAL_TRAINING__?: unknown };
    g.__HUNTRESS_EXPERIMENTAL_TRAINING__ = 1;
    expect(isExperimentalTrainingEnabled()).toBe(false);
    g.__HUNTRESS_EXPERIMENTAL_TRAINING__ = '1';
    expect(isExperimentalTrainingEnabled()).toBe(false);
    g.__HUNTRESS_EXPERIMENTAL_TRAINING__ = 'true';
    expect(isExperimentalTrainingEnabled()).toBe(false);
    g.__HUNTRESS_EXPERIMENTAL_TRAINING__ = {};
    expect(isExperimentalTrainingEnabled()).toBe(false);
  });

  it('opens the gate on EXPERIMENTAL_TRAINING="1"', () => {
    const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    if (!proc?.env) return; // Skip when no process.env (browser-only env)
    proc.env.EXPERIMENTAL_TRAINING = '1';
    expect(isExperimentalTrainingEnabled()).toBe(true);
  });

  it('opens the gate on EXPERIMENTAL_TRAINING="true" (case-insensitive)', () => {
    const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    if (!proc?.env) return;
    proc.env.EXPERIMENTAL_TRAINING = 'TRUE';
    expect(isExperimentalTrainingEnabled()).toBe(true);
    proc.env.EXPERIMENTAL_TRAINING = 'True';
    expect(isExperimentalTrainingEnabled()).toBe(true);
  });

  it('opens the gate on EXPERIMENTAL_TRAINING="yes"', () => {
    const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    if (!proc?.env) return;
    proc.env.EXPERIMENTAL_TRAINING = 'yes';
    expect(isExperimentalTrainingEnabled()).toBe(true);
  });

  it('keeps gate closed on EXPERIMENTAL_TRAINING="0"', () => {
    const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    if (!proc?.env) return;
    proc.env.EXPERIMENTAL_TRAINING = '0';
    expect(isExperimentalTrainingEnabled()).toBe(false);
  });

  it('keeps gate closed on EXPERIMENTAL_TRAINING="false"', () => {
    const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    if (!proc?.env) return;
    proc.env.EXPERIMENTAL_TRAINING = 'false';
    expect(isExperimentalTrainingEnabled()).toBe(false);
  });

  it('keeps gate closed on EXPERIMENTAL_TRAINING set to empty string', () => {
    const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    if (!proc?.env) return;
    proc.env.EXPERIMENTAL_TRAINING = '';
    expect(isExperimentalTrainingEnabled()).toBe(false);
  });

  it('trims whitespace before checking', () => {
    const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    if (!proc?.env) return;
    proc.env.EXPERIMENTAL_TRAINING = '  1  ';
    expect(isExperimentalTrainingEnabled()).toBe(true);
  });
});

// ─── createContinuousLearningSystem gate ────────────────────────────────────

describe('P3-1 · createContinuousLearningSystem gate', () => {
  it('throws when neither opt-in is set', () => {
    withCleanGate(() => {
      expect(() => createContinuousLearningSystem(fakeQdrant)).toThrow(/EXPERIMENTAL_TRAINING/);
    });
  });

  it('throws with a helpful message that mentions both opt-in mechanisms', () => {
    withCleanGate(() => {
      try {
        createContinuousLearningSystem(fakeQdrant);
        expect.fail('Expected throw');
      } catch (err) {
        expect(err).toBeInstanceOf(Error);
        const msg = (err as Error).message;
        expect(msg).toContain('EXPERIMENTAL_TRAINING=1');
        expect(msg).toContain('__HUNTRESS_EXPERIMENTAL_TRAINING__');
        expect(msg).toContain('GPU');
      }
    });
  });

  it('does NOT throw when global opt-in is set (test-friendly path)', () => {
    withCleanGate(() => {
      (globalThis as { __HUNTRESS_EXPERIMENTAL_TRAINING__?: unknown }).__HUNTRESS_EXPERIMENTAL_TRAINING__ = true;
      // Construction may still fail with downstream errors (qdrant is a fake),
      // but the GATE check itself must let us through.
      let gateError: Error | null = null;
      try {
        createContinuousLearningSystem(fakeQdrant);
      } catch (err) {
        if (err instanceof Error && err.message.includes('EXPERIMENTAL_TRAINING')) {
          gateError = err;
        }
        // Other errors are downstream of the gate — fine for this test
      }
      expect(gateError).toBeNull();
    });
  });

  it('does NOT throw when EXPERIMENTAL_TRAINING=1 env var is set', () => {
    withCleanGate(() => {
      const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
      if (!proc?.env) return;
      proc.env.EXPERIMENTAL_TRAINING = '1';
      let gateError: Error | null = null;
      try {
        createContinuousLearningSystem(fakeQdrant);
      } catch (err) {
        if (err instanceof Error && err.message.includes('EXPERIMENTAL_TRAINING')) {
          gateError = err;
        }
      }
      expect(gateError).toBeNull();
    });
  });
});

// ─── Public-surface invariants ──────────────────────────────────────────────

describe('P3-1 · top-level training/index re-exports', () => {
  it('exports production-connected types (FeedbackLoop, RewardSystem)', async () => {
    const mod = await import('../core/training');
    expect(mod.FeedbackLoop).toBeDefined();
    expect(mod.RewardSystem).toBeDefined();
  });

  it('re-exports experimental factories from index (so callers can stay agnostic)', async () => {
    const mod = await import('../core/training');
    expect(mod.createContinuousLearningSystem).toBeDefined();
    expect(mod.LearningLoopOrchestrator).toBeDefined();
    expect(mod.TrainingPipelineManager).toBeDefined();
  });
});

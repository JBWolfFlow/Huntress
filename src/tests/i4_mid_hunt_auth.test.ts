/**
 * I4 — Mid-hunt auth injection (orchestrator-side methods)
 *
 * Verifies getActiveProgram() + reprioritizeForAuth() behave correctly.
 * The UI-side flow (AuthWizardModal → addAuthToActiveHunt) is a thin
 * shell over these primitives plus settings.authProfiles traversal.
 */

import { describe, it, expect } from 'vitest';
import { OrchestratorEngine } from '../core/orchestrator/orchestrator_engine';
import type { OrchestratorConfig } from '../core/orchestrator/orchestrator_engine';
import type { ProgramGuidelines } from '../components/GuidelinesImporter';
import { createMockProvider } from './integration/orchestrator_e2e.test';

const guidelines: ProgramGuidelines = {
  programHandle: 'test_program',
  programName: 'Test Program',
  url: 'https://hackerone.com/test_program',
  scope: {
    inScope: ['*.test-target.com', 'api.test-target.com'],
    outOfScope: [],
  },
  bountyRange: { min: 100, max: 25000 },
  rules: [],
  severity: { critical: '$5,000', high: '$2,000', medium: '$500', low: '$100' },
  importedAt: new Date(),
};

function makeEngine(): OrchestratorEngine {
  const { provider } = createMockProvider([]);
  const config: OrchestratorConfig = { provider, model: 'mock-model' };
  return new OrchestratorEngine(config);
}

describe('I4: getActiveProgram()', () => {
  it('returns null when no hunt is active', () => {
    const engine = makeEngine();
    expect(engine.getActiveProgram()).toBeNull();
  });

  it('returns the program once a hunt session is initialized', async () => {
    const engine = makeEngine();
    await engine.initializeHuntSession({ ...guidelines, scope: { ...guidelines.scope } });
    const active = engine.getActiveProgram();
    expect(active).not.toBeNull();
    expect(active?.programName).toBe('Test Program');
    expect(active?.scope.inScope).toContain('api.test-target.com');
  });
});

describe('I4: reprioritizeForAuth()', () => {
  it('is a safe no-op when no hunt is active', () => {
    const engine = makeEngine();
    expect(() => engine.reprioritizeForAuth()).not.toThrow();
  });

  it('emits a system message when auth is attached to an active hunt', async () => {
    const engine = makeEngine();
    await engine.initializeHuntSession({ ...guidelines, scope: { ...guidelines.scope } });

    const captured: Array<{ content: string; level?: string }> = [];
    engine.setMessageCallback((msg) => {
      if (msg.type === 'system') {
        captured.push({ content: msg.content, level: (msg as { level?: string }).level });
      }
    });

    engine.reprioritizeForAuth();

    const authMessage = captured.find(m => m.content.includes('Auth attached mid-hunt'));
    expect(authMessage).toBeDefined();
  });
});

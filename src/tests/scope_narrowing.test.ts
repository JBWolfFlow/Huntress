/**
 * Scope narrowing helper (2026-04-23)
 *
 * `applyScopeNarrowing` is the filter `BountyImporter` runs before
 * handing a `ProgramGuidelines` off to the hunt. Programs like Superhuman
 * (merged Grammarly + Coda) have 30+ in-scope assets; without this filter
 * the tech-stack pass fans specialists across every one and the budget
 * burns in minutes before producing anything actionable. Default OFF —
 * single-asset programs (Juice Shop, a specific endpoint) see no UI change.
 */
import { describe, it, expect } from 'vitest';
import { applyScopeNarrowing } from '../components/BountyImporter';
import type { ProgramGuidelines } from '../components/GuidelinesImporter';

function makeGuidelines(inScope: string[], overrides: Partial<ProgramGuidelines> = {}): ProgramGuidelines {
  return {
    programHandle: 'test',
    programName: 'Test Program',
    url: 'https://hackerone.com/test',
    scope: { inScope, outOfScope: [] },
    rules: [],
    bountyRange: { min: 0, max: 0 },
    severity: {},
    importedAt: new Date(),
    ...overrides,
  };
}

describe('applyScopeNarrowing', () => {
  it('passes the guidelines through unchanged when narrowing is off', () => {
    const input = makeGuidelines(['*.example.com', 'api.example.com', 'other.com']);
    const result = applyScopeNarrowing(input, false, new Set());
    // Off path: same object (or deep-equal) — either way, no filtering.
    expect(result).not.toBeNull();
    expect(result!.scope.inScope).toEqual(['*.example.com', 'api.example.com', 'other.com']);
  });

  it('filters inScope to the selected targets when narrowing is on', () => {
    const input = makeGuidelines(['*.grammarly.com', '*.coda.io', '*.superhuman.com', 'codacontent.io']);
    const selected = new Set(['*.coda.io']);
    const result = applyScopeNarrowing(input, true, selected);
    expect(result).not.toBeNull();
    expect(result!.scope.inScope).toEqual(['*.coda.io']);
  });

  it('preserves the rest of the guidelines while filtering scope.inScope', () => {
    const input = makeGuidelines(['a', 'b', 'c'], {
      programName: 'Superhuman', bountyRange: { min: 100, max: 13000 },
      scope: { inScope: ['a', 'b', 'c'], outOfScope: ['x'] },
    });
    const result = applyScopeNarrowing(input, true, new Set(['b']));
    expect(result!.programName).toBe('Superhuman');
    expect(result!.bountyRange).toEqual({ min: 100, max: 13000 });
    expect(result!.scope.outOfScope).toEqual(['x']);
    expect(result!.scope.inScope).toEqual(['b']);
  });

  it('returns null when narrowing is on and selection is empty — caller must surface an error', () => {
    const input = makeGuidelines(['a', 'b', 'c']);
    expect(applyScopeNarrowing(input, true, new Set())).toBeNull();
  });

  it('returns null when narrowing is on and no selected entry matches a real in-scope target', () => {
    const input = makeGuidelines(['a', 'b']);
    expect(applyScopeNarrowing(input, true, new Set(['c']))).toBeNull();
  });

  it('preserves insertion order of the original inScope list', () => {
    const input = makeGuidelines(['z', 'a', 'm', 'b']);
    const result = applyScopeNarrowing(input, true, new Set(['a', 'b', 'z']));
    expect(result!.scope.inScope).toEqual(['z', 'a', 'b']);
  });

  it('is a no-op when narrowing is off even if selectedTargets is non-empty', () => {
    const input = makeGuidelines(['a', 'b']);
    const result = applyScopeNarrowing(input, false, new Set(['a']));
    expect(result!.scope.inScope).toEqual(['a', 'b']);
  });
});

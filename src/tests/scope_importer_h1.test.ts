/**
 * I3 — ScopeImporter H1 Import Tests
 *
 * Tests for HackerOne scope import:
 * - extractH1Handle: URL parsing + bare handle validation
 * - fetchH1Scope: happy path, empty scope, API error
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { extractH1Handle, fetchH1Scope } from '../components/ScopeImporter';

// ─── Mock Tauri invoke ──────────────────────────────────────────────────────

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

import { invoke } from '@tauri-apps/api/core';
const mockInvoke = vi.mocked(invoke);

// ─── extractH1Handle ────────────────────────────────────────────────────────

describe('extractH1Handle', () => {
  it('extracts handle from standard HackerOne URL', () => {
    expect(extractH1Handle('https://hackerone.com/security')).toBe('security');
  });

  it('extracts handle from programs path URL', () => {
    expect(extractH1Handle('https://hackerone.com/programs/bookingcom')).toBe('bookingcom');
  });

  it('extracts handle from URL with query params', () => {
    expect(extractH1Handle('https://hackerone.com/security?type=team')).toBe('security');
  });

  it('accepts bare handle', () => {
    expect(extractH1Handle('security')).toBe('security');
  });

  it('accepts handle with dashes and underscores', () => {
    expect(extractH1Handle('my-program_v2')).toBe('my-program_v2');
  });

  it('trims whitespace from input', () => {
    expect(extractH1Handle('  security  ')).toBe('security');
  });

  it('returns null for empty string', () => {
    expect(extractH1Handle('')).toBeNull();
  });

  it('returns null for whitespace-only string', () => {
    expect(extractH1Handle('   ')).toBeNull();
  });

  it('returns null for invalid URL with no handle', () => {
    expect(extractH1Handle('https://hackerone.com/')).toBeNull();
  });

  it('returns null for non-alphanumeric string with special chars', () => {
    expect(extractH1Handle('hello world!')).toBeNull();
  });
});

// ─── fetchH1Scope ───────────────────────────────────────────────────────────

describe('fetchH1Scope', () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it('returns in-scope and out-of-scope entries from H1 API response', async () => {
    mockInvoke.mockResolvedValueOnce({
      program_handle: 'security',
      program_name: 'HackerOne Security',
      url: 'https://hackerone.com/security',
      scope: {
        in_scope: ['*.hackerone.com', 'api.hackerone.com'],
        out_of_scope: ['staging.hackerone.com'],
      },
      rules: [],
      bounty_range: { min: 500, max: 25000 },
      severity: {},
    });

    const entries = await fetchH1Scope('security', null, null);

    expect(entries).toHaveLength(3);
    expect(entries[0]).toEqual({
      target: '*.hackerone.com',
      inScope: true,
      notes: 'Imported from HackerOne',
    });
    expect(entries[1]).toEqual({
      target: 'api.hackerone.com',
      inScope: true,
      notes: 'Imported from HackerOne',
    });
    expect(entries[2]).toEqual({
      target: 'staging.hackerone.com',
      inScope: false,
      notes: 'Out of scope (HackerOne)',
    });

    expect(mockInvoke).toHaveBeenCalledWith('fetch_h1_program', {
      programHandle: 'security',
      apiUsername: null,
      apiToken: null,
    });
  });

  it('returns empty array when program has no scope entries', async () => {
    mockInvoke.mockResolvedValueOnce({
      program_handle: 'empty-program',
      program_name: 'Empty Program',
      url: 'https://hackerone.com/empty-program',
      scope: {
        in_scope: [],
        out_of_scope: [],
      },
      rules: [],
      bounty_range: { min: 0, max: 0 },
      severity: {},
    });

    const entries = await fetchH1Scope('empty-program', null, null);
    expect(entries).toHaveLength(0);
  });

  it('throws on network/API error', async () => {
    mockInvoke.mockRejectedValueOnce(new Error('Network error: connection refused'));

    await expect(fetchH1Scope('bad-program', null, null)).rejects.toThrow(
      'Network error: connection refused'
    );
  });

  it('passes API credentials when provided', async () => {
    mockInvoke.mockResolvedValueOnce({
      program_handle: 'private-program',
      program_name: 'Private Program',
      url: 'https://hackerone.com/private-program',
      scope: {
        in_scope: ['app.private.com'],
        out_of_scope: [],
      },
      rules: [],
      bounty_range: { min: 100, max: 5000 },
      severity: {},
    });

    await fetchH1Scope('private-program', 'myuser', 'mytoken');

    expect(mockInvoke).toHaveBeenCalledWith('fetch_h1_program', {
      programHandle: 'private-program',
      apiUsername: 'myuser',
      apiToken: 'mytoken',
    });
  });

  it('handles missing scope field gracefully', async () => {
    mockInvoke.mockResolvedValueOnce({
      program_handle: 'weird-program',
      program_name: 'Weird Program',
      url: 'https://hackerone.com/weird-program',
      scope: null,
      rules: [],
      bounty_range: { min: 0, max: 0 },
      severity: {},
    });

    const entries = await fetchH1Scope('weird-program', null, null);
    expect(entries).toHaveLength(0);
  });
});

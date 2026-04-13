/**
 * I5 — SandboxExecutor.reapOrphans (TS wrapper)
 *
 * Verifies the TS-side helper handles the "Docker not available" branch
 * gracefully (returns 0 instead of throwing), and forwards the min-age
 * argument to the Tauri command correctly.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({
  invoke: invokeMock,
}));

// Import AFTER mocking so the module captures the mocked `invoke`.
import { SandboxExecutor } from '../core/tools/sandbox_executor';

describe('I5: SandboxExecutor.reapOrphans', () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it('forwards min-age argument and returns the reaped count', async () => {
    invokeMock.mockResolvedValue(3);
    const count = await SandboxExecutor.reapOrphans(900);
    expect(count).toBe(3);
    expect(invokeMock).toHaveBeenCalledWith('reap_orphan_sandboxes', { minAgeSecs: 900 });
  });

  it('defaults to 600-second min age when no argument is passed', async () => {
    invokeMock.mockResolvedValue(0);
    await SandboxExecutor.reapOrphans();
    expect(invokeMock).toHaveBeenCalledWith('reap_orphan_sandboxes', { minAgeSecs: 600 });
  });

  it('returns 0 instead of throwing when Docker is not initialized', async () => {
    invokeMock.mockRejectedValue(new Error('Sandbox manager not initialized (Docker/Podman not available)'));
    const count = await SandboxExecutor.reapOrphans();
    expect(count).toBe(0);
  });

  it('returns 0 but warns when the reaper throws an unexpected error', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    invokeMock.mockRejectedValue(new Error('kaboom'));
    const count = await SandboxExecutor.reapOrphans();
    expect(count).toBe(0);
    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });
});

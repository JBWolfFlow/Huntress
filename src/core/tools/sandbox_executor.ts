/**
 * Sandbox Executor — Docker-isolated command execution for agents
 *
 * Wraps the Tauri sandbox commands (create_sandbox, sandbox_exec, destroy_sandbox)
 * into the `onExecuteCommand` callback signature used by the ReactLoop.
 *
 * Lifecycle:
 *   1. `SandboxExecutor.create(scope)` — creates a container with scope-enforcing proxy
 *   2. `executor.execute(command, target)` — runs commands inside the container
 *   3. `executor.destroy()` — tears down the container
 *
 * When Docker/Podman is unavailable, `SandboxExecutor.create()` returns null
 * and the caller should fall back to bare PTY execution.
 */

import { invoke } from '@tauri-apps/api/core';
import type { CommandResult } from '../engine/react_loop';

/** Sandbox configuration sent to the Rust create_sandbox command */
interface SandboxConfig {
  image: string;
  allowed_domains: string[];
  memory_limit: number;
  cpu_cores: number;
  pids_limit: number;
  env_vars: Record<string, string>;
  working_dir: string;
  creation_timeout_secs: number;
}

/** Result from sandbox_exec Tauri command */
interface ExecResult {
  stdout: string;
  stderr: string;
  exit_code: number | null;
  timed_out: boolean;
  duration_ms: number;
}

export class SandboxExecutor {
  private sandboxId: string;
  private destroyed = false;

  private constructor(sandboxId: string) {
    this.sandboxId = sandboxId;
  }

  /**
   * Create a new sandbox container for an agent.
   *
   * @param scope - In-scope domains (enforced by the container's Squid proxy)
   * @param envVars - Optional environment variables to pass into the container
   * @returns A SandboxExecutor instance, or null if Docker/Podman is unavailable
   */
  static async create(
    scope: string[],
    envVars?: Record<string, string>,
  ): Promise<SandboxExecutor | null> {
    const config: SandboxConfig = {
      image: 'huntress-attack-machine:latest',
      allowed_domains: scope,
      memory_limit: 2 * 1024 * 1024 * 1024, // 2GB
      cpu_cores: 1.0,
      pids_limit: 256,
      env_vars: envVars ?? {},
      working_dir: '/home/hunter',
      creation_timeout_secs: 30,
    };

    try {
      const sandboxId = await invoke<string>('create_sandbox', { config });
      console.log(`[SandboxExecutor] Container created: ${sandboxId.substring(0, 12)}`);
      return new SandboxExecutor(sandboxId);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      // Docker/Podman not available — caller should fall back to bare PTY
      if (msg.includes('not initialized') || msg.includes('not available')) {
        console.warn('[SandboxExecutor] Sandbox unavailable — falling back to PTY:', msg);
        return null;
      }
      // Other errors (image not found, etc.) — also fall back gracefully
      console.error('[SandboxExecutor] Failed to create sandbox:', msg);
      return null;
    }
  }

  /**
   * Check if sandbox mode is available (Docker/Podman running).
   *
   * Performs a lightweight check by listing existing sandboxes.
   */
  static async isAvailable(): Promise<boolean> {
    try {
      await invoke('list_sandboxes');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Execute a command inside the sandbox container.
   *
   * This matches the `onExecuteCommand` signature from ReactLoopConfig,
   * so it can be used as a drop-in replacement.
   *
   * @param command - The command string (will be split into argv)
   * @param _target - The target domain (unused here; scope is enforced by the container proxy)
   */
  async execute(command: string, _target: string): Promise<CommandResult> {
    if (this.destroyed) {
      return {
        success: false,
        stdout: '',
        stderr: 'Sandbox has been destroyed',
        exitCode: 1,
        executionTimeMs: 0,
        blocked: true,
        blockReason: 'Sandbox container no longer exists',
      };
    }

    // Split command into argv — the sandbox exec expects an array, not a shell string.
    // This is intentionally simple; complex shell syntax should use write_script tool.
    const argv = this.splitCommand(command);

    try {
      const result = await invoke<ExecResult>('sandbox_exec', {
        sandboxId: this.sandboxId,
        command: argv,
        timeoutSecs: 120, // 2 minute default timeout
      });

      return {
        success: !result.timed_out && (result.exit_code === 0 || result.exit_code === null),
        stdout: result.stdout,
        stderr: result.stderr,
        exitCode: result.exit_code ?? (result.timed_out ? 124 : 1),
        executionTimeMs: result.duration_ms,
        blocked: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        stdout: '',
        stderr: msg,
        exitCode: 1,
        executionTimeMs: 0,
        blocked: false,
      };
    }
  }

  /**
   * Destroy the sandbox container and clean up resources.
   * Safe to call multiple times.
   */
  async destroy(): Promise<void> {
    if (this.destroyed) return;
    this.destroyed = true;

    try {
      await invoke('destroy_sandbox', { sandboxId: this.sandboxId });
      console.log(`[SandboxExecutor] Container destroyed: ${this.sandboxId.substring(0, 12)}`);
    } catch (error) {
      // Container may already be gone (auto-remove)
      console.warn('[SandboxExecutor] Destroy warning:', error);
    }
  }

  /** Get the container ID */
  getContainerId(): string {
    return this.sandboxId;
  }

  /** Whether this sandbox has been destroyed */
  isDestroyed(): boolean {
    return this.destroyed;
  }

  /**
   * Split a command string into argv array.
   *
   * Handles quoted strings (single and double quotes) and escaped characters.
   * No shell expansion — this is intentional for security.
   */
  private splitCommand(command: string): string[] {
    const args: string[] = [];
    let current = '';
    let inSingle = false;
    let inDouble = false;
    let escaped = false;

    for (const ch of command) {
      if (escaped) {
        current += ch;
        escaped = false;
        continue;
      }
      if (ch === '\\' && !inSingle) {
        escaped = true;
        continue;
      }
      if (ch === "'" && !inDouble) {
        inSingle = !inSingle;
        continue;
      }
      if (ch === '"' && !inSingle) {
        inDouble = !inDouble;
        continue;
      }
      if (ch === ' ' && !inSingle && !inDouble) {
        if (current.length > 0) {
          args.push(current);
          current = '';
        }
        continue;
      }
      current += ch;
    }

    if (current.length > 0) {
      args.push(current);
    }

    return args;
  }
}

/**
 * Create an `onExecuteCommand` callback that uses sandbox execution
 * with automatic fallback to a provided PTY callback.
 *
 * Usage in the orchestrator:
 * ```
 * const sandboxExec = await createSandboxedExecutor(scope, ptyFallback);
 * // sandboxExec.executeCommand — use as onExecuteCommand
 * // sandboxExec.cleanup — call when agent finishes
 * ```
 */
export async function createSandboxedExecutor(
  scope: string[],
  ptyFallback?: (command: string, target: string) => Promise<CommandResult>,
): Promise<{
  executeCommand: (command: string, target: string) => Promise<CommandResult>;
  cleanup: () => Promise<void>;
  usingSandbox: boolean;
}> {
  const sandbox = await SandboxExecutor.create(scope);

  if (sandbox) {
    return {
      executeCommand: (command, target) => sandbox.execute(command, target),
      cleanup: () => sandbox.destroy(),
      usingSandbox: true,
    };
  }

  // Sandbox unavailable — fall back to PTY
  return {
    executeCommand: ptyFallback ?? (async () => ({
      success: false,
      stdout: '',
      stderr: 'No execution backend configured',
      exitCode: 1,
      executionTimeMs: 0,
      blocked: true,
      blockReason: 'Neither sandbox nor PTY execution is available',
    })),
    cleanup: async () => {},
    usingSandbox: false,
  };
}

export default SandboxExecutor;

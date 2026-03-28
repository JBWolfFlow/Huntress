/**
 * Tauri Bridge — Drop-in replacements for Node.js APIs
 *
 * The training pipeline was originally written with Node.js fs/path/child_process.
 * This module provides API-compatible replacements that route through Tauri IPC.
 * Import this instead of Node.js modules in any browser-context code.
 *
 * In test/Node.js environments (vitest), falls back to real Node.js APIs.
 */

import { invoke } from '@tauri-apps/api/core';

// ─── Detect Environment ─────────────────────────────────────────────────────

/** Check at call time using Tauri v2's actual IPC property */
function checkIsTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

/** True when running in Node.js (e.g. vitest tests) */
const isNode = typeof process !== 'undefined' && !!process.versions?.node;

// Lazy-loaded Node.js modules (only in Node.js context, never in browser)
let _nodeFs: typeof import('fs/promises') | null = null;
let _nodePath: typeof import('path') | null = null;
let _nodeChildProcess: typeof import('child_process') | null = null;

function getNodeFs() {
  if (!isNode) return null;
  if (!_nodeFs) { _nodeFs = require('fs/promises'); }
  return _nodeFs;
}

function getNodePath() {
  if (!isNode) return null;
  if (!_nodePath) { _nodePath = require('path'); }
  return _nodePath;
}

function getNodeChildProcess() {
  if (!isNode) return null;
  if (!_nodeChildProcess) { _nodeChildProcess = require('child_process'); }
  return _nodeChildProcess;
}

// ─── CORS-free HTTP (replaces browser fetch for external APIs) ───────────────

/**
 * Fetch a URL through the Rust backend, bypassing browser CORS.
 * Falls back to native fetch in Node.js/test environments.
 */
export async function tauriFetch(
  url: string,
  options?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
    followRedirects?: boolean;
  },
): Promise<{ status: number; statusText: string; headers: Record<string, string>; body: string }> {
  if (checkIsTauri()) {
    return invoke<{
      status: number;
      statusText: string;
      headers: Record<string, string>;
      body: string;
    }>('proxy_http_request', {
      url,
      method: options?.method ?? 'GET',
      headers: options?.headers ?? null,
      body: options?.body ?? null,
      timeoutMs: options?.timeoutMs ?? 30000,
      followRedirects: options?.followRedirects ?? true,
    });
  }

  // Fallback: native fetch (Node.js, tests)
  const resp = await fetch(url, {
    method: options?.method ?? 'GET',
    headers: options?.headers,
    body: options?.body,
    signal: AbortSignal.timeout(options?.timeoutMs ?? 30000),
  });
  const body = await resp.text();
  const headers: Record<string, string> = {};
  resp.headers.forEach((v, k) => { headers[k] = v; });
  return { status: resp.status, statusText: resp.statusText, headers, body };
}

// ─── File System (replaces 'fs/promises') ───────────────────────────────────

export const fs = {
  async readFile(filePath: string, _encoding?: string): Promise<string> {
    if (checkIsTauri()) return invoke<string>('read_file_text', { path: filePath });
    const nfs = getNodeFs();
    if (nfs) return nfs.readFile(filePath, 'utf-8');
    return '';
  },

  async writeFile(filePath: string, content: string): Promise<void> {
    if (checkIsTauri()) { await invoke('write_file_text', { path: filePath, content }); return; }
    const nfs = getNodeFs();
    if (nfs) { await nfs.writeFile(filePath, content, 'utf-8'); return; }
  },

  async mkdir(dirPath: string, options?: { recursive?: boolean }): Promise<void> {
    if (checkIsTauri()) { await invoke('create_output_directory', { path: dirPath }); return; }
    const nfs = getNodeFs();
    if (nfs) { await nfs.mkdir(dirPath, { recursive: options?.recursive }); return; }
  },

  async readdir(dirPath: string): Promise<string[]> {
    if (checkIsTauri()) return invoke<string[]>('list_directory', { path: dirPath });
    const nfs = getNodeFs();
    if (nfs) return nfs.readdir(dirPath);
    return [];
  },

  async unlink(filePath: string): Promise<void> {
    if (checkIsTauri()) { await invoke('delete_path', { path: filePath }); return; }
    const nfs = getNodeFs();
    if (nfs) { await nfs.unlink(filePath); return; }
  },

  async rm(filePath: string, options?: { recursive?: boolean; force?: boolean }): Promise<void> {
    if (checkIsTauri()) { await invoke('delete_path', { path: filePath }); return; }
    const nfs = getNodeFs();
    if (nfs) { await nfs.rm(filePath, { recursive: options?.recursive, force: options?.force }); return; }
  },

  async stat(filePath: string): Promise<{ isDirectory: () => boolean; size: number; mtimeMs: number }> {
    if (checkIsTauri()) {
      const exists = await invoke<boolean>('file_exists', { path: filePath });
      return { isDirectory: () => false, size: exists ? 1 : 0, mtimeMs: Date.now() };
    }
    const nfs = getNodeFs();
    if (nfs) {
      const s = await nfs.stat(filePath);
      return { isDirectory: () => s.isDirectory(), size: s.size, mtimeMs: s.mtimeMs };
    }
    return { isDirectory: () => false, size: 0, mtimeMs: Date.now() };
  },

  async access(filePath: string): Promise<void> {
    if (checkIsTauri()) {
      const exists = await invoke<boolean>('file_exists', { path: filePath });
      if (!exists) throw new Error(`ENOENT: no such file or directory, access '${filePath}'`);
      return;
    }
    const nfs = getNodeFs();
    if (nfs) { await nfs.access(filePath); return; }
    throw new Error('Not in Tauri or Node.js environment');
  },

  async symlink(target: string, linkPath: string): Promise<void> {
    if (checkIsTauri()) { await invoke('create_symlink', { target, linkPath }); return; }
    const nfs = getNodeFs();
    if (nfs) { await nfs.symlink(target, linkPath); return; }
  },

  async readlink(linkPath: string): Promise<string> {
    if (checkIsTauri()) return invoke<string>('read_symlink', { path: linkPath });
    const nfs = getNodeFs();
    if (nfs) return nfs.readlink(linkPath, 'utf-8');
    return '';
  },

  async appendFile(filePath: string, content: string): Promise<void> {
    if (checkIsTauri()) { await invoke('append_to_file', { path: filePath, content }); return; }
    const nfs = getNodeFs();
    if (nfs) { await nfs.appendFile(filePath, content, 'utf-8'); return; }
  },
};

// ─── Path (replaces 'path') ─────────────────────────────────────────────────

export const path = {
  join(...segments: string[]): string {
    return segments
      .filter(Boolean)
      .join('/')
      .replace(/\/+/g, '/');
  },

  basename(filePath: string, ext?: string): string {
    const base = filePath.split('/').pop() || filePath;
    if (ext && base.endsWith(ext)) {
      return base.slice(0, -ext.length);
    }
    return base;
  },

  dirname(filePath: string): string {
    const parts = filePath.split('/');
    parts.pop();
    return parts.join('/') || '.';
  },

  extname(filePath: string): string {
    const base = filePath.split('/').pop() || '';
    const dot = base.lastIndexOf('.');
    return dot > 0 ? base.slice(dot) : '';
  },

  resolve(...segments: string[]): string {
    // Simplified — concatenates from rightmost absolute path
    let resolved = '';
    for (let i = segments.length - 1; i >= 0; i--) {
      resolved = segments[i] + (resolved ? '/' + resolved : '');
      if (segments[i].startsWith('/')) break;
    }
    return resolved.replace(/\/+/g, '/');
  },

  sep: '/' as const,
};

// ─── System Info (replaces child_process nvidia-smi/free/df) ────────────────

export interface SystemInfo {
  cpu: { cores: number; usagePercent: number };
  memory: { totalGb: number; usedGb: number; availableGb: number };
  disk: { totalGb: number; availableGb: number };
  gpu: {
    available: boolean;
    name?: string;
    memoryTotalMb?: number;
    memoryUsedMb?: number;
    utilizationPercent?: number;
  };
}

export async function getSystemInfo(): Promise<SystemInfo> {
  if (checkIsTauri()) {
    return invoke<SystemInfo>('get_system_info');
  }
  // Node.js fallback (vitest tests) — use os module for real values
  if (isNode) {
    const os = require('os');
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    return {
      cpu: { cores: os.cpus().length, usagePercent: 0 },
      memory: {
        totalGb: +(totalMem / (1024 ** 3)).toFixed(1),
        usedGb: +((totalMem - freeMem) / (1024 ** 3)).toFixed(1),
        availableGb: +(freeMem / (1024 ** 3)).toFixed(1),
      },
      disk: { totalGb: 500, availableGb: 250 },
      gpu: { available: false },
    };
  }
  // Browser fallback (non-Tauri dev)
  return {
    cpu: { cores: navigator.hardwareConcurrency || 4, usagePercent: 0 },
    memory: { totalGb: 16, usedGb: 8, availableGb: 8 },
    disk: { totalGb: 500, availableGb: 250 },
    gpu: { available: false },
  };
}

// ─── Command Execution (replaces child_process.spawn/exec) ──────────────────

export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  success: boolean;
}

/**
 * Execute a training command via Tauri subprocess.
 * This is the ONLY way training/system commands should be executed.
 * Shell interpolation is NOT used — arguments are passed as explicit argv.
 */
export async function executeCommand(
  program: string,
  args: string[],
  cwd?: string,
): Promise<CommandResult> {
  if (checkIsTauri()) {
    return invoke<CommandResult>('execute_training_command', { program, args, cwd });
  }
  // Node.js fallback (vitest tests)
  const cp = getNodeChildProcess();
  if (cp) {
    const { promisify } = require('util');
    const execFile = promisify(cp.execFile);
    try {
      const { stdout, stderr } = await execFile(program, args, { cwd, timeout: 30000 });
      return { exitCode: 0, stdout: stdout ?? '', stderr: stderr ?? '', success: true };
    } catch (err: any) {
      return { exitCode: err.code ?? 1, stdout: err.stdout ?? '', stderr: err.stderr ?? '', success: false };
    }
  }
  return { exitCode: 1, stdout: '', stderr: 'Not in Tauri or Node.js environment', success: false };
}

// ─── Knowledge Database ─────────────────────────────────────────────────────

export interface KnowledgeQueryResult {
  rows: Record<string, unknown>[];
  count: number;
}

export interface KnowledgeExecuteResult {
  rowsAffected: number;
}

export async function knowledgeDbQuery(
  dbPath: string,
  sql: string,
  params: string[] = [],
): Promise<KnowledgeQueryResult> {
  if (!checkIsTauri()) return { rows: [], count: 0 };
  return invoke<KnowledgeQueryResult>('knowledge_db_query', { dbPath, sql, params });
}

export async function knowledgeDbExecute(
  dbPath: string,
  sql: string,
  params: string[] = [],
): Promise<KnowledgeExecuteResult> {
  if (!checkIsTauri()) return { rowsAffected: 0 };
  return invoke<KnowledgeExecuteResult>('knowledge_db_execute', { dbPath, sql, params });
}

export async function initKnowledgeDb(dbPath: string): Promise<void> {
  if (!checkIsTauri()) return;
  await invoke('init_knowledge_db', { dbPath });
}

// ─── Environment Variables ──────────────────────────────────────────────────

/**
 * Get an environment variable. In Tauri, falls back to secure storage.
 * Replaces process.env.* usage.
 */
export async function getEnvVar(key: string): Promise<string | undefined> {
  // Try secure storage first (for API keys)
  if (checkIsTauri()) {
    try {
      const val = await invoke<string>('get_secret', { key });
      if (val) return val;
    } catch {
      // Not in secure storage — fall through
    }
  }
  return undefined;
}

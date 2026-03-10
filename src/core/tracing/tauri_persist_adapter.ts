/**
 * Tauri Filesystem Persistence Adapter
 *
 * Uses @tauri-apps/plugin-fs to persist traces to the app data directory.
 * This file is only imported at runtime in a Tauri environment; it is
 * never imported in tests.
 *
 * Usage in main.tsx:
 *   import { createTauriPersistAdapter } from './core/tracing/tauri_persist_adapter';
 *   const store = new TraceStore();
 *   const adapter = await createTauriPersistAdapter();
 *   if (adapter) store.setPersistAdapter(adapter);
 */

import type { PersistAdapter } from './trace_store';

const TRACE_FILENAME = 'huntress_traces.json';

/**
 * Dynamically import @tauri-apps/plugin-fs at runtime.
 * Returns null if the package is not available (dev/test mode).
 */
async function tryImportTauriFs(): Promise<{
  writeTextFile: (path: string, content: string, options: { baseDir: number }) => Promise<void>;
  readTextFile: (path: string, options: { baseDir: number }) => Promise<string>;
  BaseDirectory: { AppData: number };
} | null> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return await (Function('return import("@tauri-apps/plugin-fs")')() as Promise<any>);
  } catch {
    return null;
  }
}

/**
 * Create a Tauri filesystem persistence adapter.
 * Returns null if not running in Tauri (e.g., browser dev mode).
 *
 * Usage:
 *   const adapter = await createTauriPersistAdapter();
 *   if (adapter) store.setPersistAdapter(adapter);
 */
export async function createTauriPersistAdapter(): Promise<PersistAdapter | null> {
  const fs = await tryImportTauriFs();
  if (!fs) return null;

  return {
    async write(json: string): Promise<void> {
      await fs.writeTextFile(TRACE_FILENAME, json, {
        baseDir: fs.BaseDirectory.AppData,
      });
    },

    async read(): Promise<string | null> {
      try {
        return await fs.readTextFile(TRACE_FILENAME, {
          baseDir: fs.BaseDirectory.AppData,
        });
      } catch {
        // File doesn't exist yet
        return null;
      }
    },
  };
}

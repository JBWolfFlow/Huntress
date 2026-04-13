/**
 * Encrypted Session Storage — Unit Tests (I2)
 *
 * Tests the migration path from plaintext localStorage to secure Tauri storage.
 * Since Tauri IPC (invoke) is unavailable in unit tests, we test the
 * serialization/deserialization and migration logic.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// ─── Mock Tauri invoke ──────────────────────────────────────────────────────

const secretStore = new Map<string, string>();

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(async (cmd: string, args?: Record<string, string>) => {
    switch (cmd) {
      case 'store_secret': {
        secretStore.set(args!.key, args!.value);
        return;
      }
      case 'get_secret': {
        const val = secretStore.get(args!.key);
        if (val === undefined) throw new Error('KeyNotFound');
        return val;
      }
      case 'delete_secret': {
        secretStore.delete(args!.key);
        return;
      }
      case 'list_secret_keys': {
        return Array.from(secretStore.keys());
      }
      default:
        throw new Error(`Unknown command: ${cmd}`);
    }
  }),
}));

// ─── Mock localStorage ──────────────────────────────────────────────────────

const localStorageMock = new Map<string, string>();
const localStorageShim = {
  getItem: (key: string) => localStorageMock.get(key) ?? null,
  setItem: (key: string, value: string) => localStorageMock.set(key, value),
  removeItem: (key: string) => localStorageMock.delete(key),
};

Object.defineProperty(globalThis, 'localStorage', { value: localStorageShim, writable: true });

// ─── Import after mocks ─────────────────────────────────────────────────────

import { invoke } from '@tauri-apps/api/core';

// Re-implement the functions under test (same logic as HuntSessionContext.tsx)
// to avoid importing the entire React context with its dependencies

const SESSION_STORAGE_KEY = 'huntress_session';

interface PersistedSession {
  messages: Array<{ type: string; content: string }>;
  findings: Array<{ title: string }>;
  phase: string;
  activeAgents: Array<{ id: string; status: string }>;
  savedAt: number;
}

async function saveSessionToDisk(data: PersistedSession): Promise<void> {
  try {
    await invoke('store_secret', {
      key: SESSION_STORAGE_KEY,
      value: JSON.stringify(data),
    });
  } catch {
    // Secure storage unavailable
  }
}

async function loadSessionFromDisk(): Promise<PersistedSession | null> {
  try {
    const raw: string = await invoke('get_secret', { key: SESSION_STORAGE_KEY }) as string;
    if (raw) return JSON.parse(raw) as PersistedSession;
  } catch {
    // Key not found — check migration
  }

  try {
    const legacyRaw = localStorage.getItem(SESSION_STORAGE_KEY);
    if (legacyRaw) {
      const parsed = JSON.parse(legacyRaw) as PersistedSession;
      await saveSessionToDisk(parsed);
      localStorage.removeItem(SESSION_STORAGE_KEY);
      return parsed;
    }
  } catch {
    // Corrupted legacy data
  }

  return null;
}

async function clearPersistedSession(): Promise<void> {
  try {
    await invoke('delete_secret', { key: SESSION_STORAGE_KEY });
  } catch {
    // Key may not exist
  }
  localStorage.removeItem(SESSION_STORAGE_KEY);
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('Encrypted Session Storage (I2)', () => {
  beforeEach(() => {
    secretStore.clear();
    localStorageMock.clear();
  });

  const sampleSession: PersistedSession = {
    messages: [{ type: 'user', content: 'Start hunt' }],
    findings: [{ title: 'XSS in search' }],
    phase: 'hunting',
    activeAgents: [{ id: 'xss_hunter', status: 'running' }],
    savedAt: Date.now(),
  };

  describe('saveSessionToDisk', () => {
    it('should store session data in secure storage', async () => {
      await saveSessionToDisk(sampleSession);

      expect(secretStore.has(SESSION_STORAGE_KEY)).toBe(true);
      const stored = JSON.parse(secretStore.get(SESSION_STORAGE_KEY)!);
      expect(stored.phase).toBe('hunting');
      expect(stored.findings).toHaveLength(1);
    });

    it('should NOT store in plaintext localStorage', async () => {
      await saveSessionToDisk(sampleSession);

      expect(localStorage.getItem(SESSION_STORAGE_KEY)).toBeNull();
    });

    it('should overwrite previous session data', async () => {
      await saveSessionToDisk(sampleSession);
      await saveSessionToDisk({ ...sampleSession, phase: 'idle' });

      const stored = JSON.parse(secretStore.get(SESSION_STORAGE_KEY)!);
      expect(stored.phase).toBe('idle');
    });
  });

  describe('loadSessionFromDisk', () => {
    it('should load from secure storage when available', async () => {
      await saveSessionToDisk(sampleSession);

      const loaded = await loadSessionFromDisk();
      expect(loaded).not.toBeNull();
      expect(loaded!.phase).toBe('hunting');
      expect(loaded!.findings).toHaveLength(1);
    });

    it('should return null when no session data exists', async () => {
      const loaded = await loadSessionFromDisk();
      expect(loaded).toBeNull();
    });

    it('should migrate from plaintext localStorage to secure storage', async () => {
      // Simulate legacy data in plaintext
      localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(sampleSession));

      const loaded = await loadSessionFromDisk();

      // Should return the data
      expect(loaded).not.toBeNull();
      expect(loaded!.phase).toBe('hunting');

      // Should have migrated to secure storage
      expect(secretStore.has(SESSION_STORAGE_KEY)).toBe(true);

      // Should have cleared plaintext
      expect(localStorage.getItem(SESSION_STORAGE_KEY)).toBeNull();
    });

    it('should handle corrupted localStorage data gracefully', async () => {
      localStorage.setItem(SESSION_STORAGE_KEY, 'not-valid-json{{{');

      const loaded = await loadSessionFromDisk();
      expect(loaded).toBeNull();
    });

    it('should prefer secure storage over localStorage', async () => {
      // Both have data — secure storage wins
      await saveSessionToDisk({ ...sampleSession, phase: 'secure' });
      localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify({ ...sampleSession, phase: 'legacy' }));

      const loaded = await loadSessionFromDisk();
      expect(loaded!.phase).toBe('secure');

      // localStorage should NOT be cleared since secure storage was found first
      expect(localStorage.getItem(SESSION_STORAGE_KEY)).not.toBeNull();
    });
  });

  describe('clearPersistedSession', () => {
    it('should clear secure storage', async () => {
      await saveSessionToDisk(sampleSession);
      await clearPersistedSession();

      expect(secretStore.has(SESSION_STORAGE_KEY)).toBe(false);
    });

    it('should clear legacy localStorage as well', async () => {
      localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(sampleSession));
      await clearPersistedSession();

      expect(localStorage.getItem(SESSION_STORAGE_KEY)).toBeNull();
    });

    it('should not throw when nothing exists to clear', async () => {
      await expect(clearPersistedSession()).resolves.not.toThrow();
    });
  });

  describe('Serialization roundtrip', () => {
    it('should preserve all fields through save/load cycle', async () => {
      const original: PersistedSession = {
        messages: [
          { type: 'user', content: 'test message' },
          { type: 'agent', content: 'agent response' },
        ],
        findings: [
          { title: 'Finding 1' },
          { title: 'Finding 2' },
        ],
        phase: 'analyzing',
        activeAgents: [
          { id: 'sqli_hunter', status: 'completed' },
          { id: 'xss_hunter', status: 'running' },
        ],
        savedAt: 1712345678000,
      };

      await saveSessionToDisk(original);
      const loaded = await loadSessionFromDisk();

      expect(loaded).toEqual(original);
    });
  });
});

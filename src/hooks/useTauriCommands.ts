/**
 * Tauri Command Hooks
 * 
 * Custom React hooks for interacting with Tauri backend commands.
 * These hooks provide type-safe interfaces to all backend functionality.
 */

import { invoke } from '@tauri-apps/api/core';
import { useState, useCallback, useEffect } from 'react';

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

export interface ScopeEntry {
  target: string;
  inScope: boolean;
  notes?: string;
}

export interface ValidationResult {
  target: string;
  isValid: boolean;
  inScope: boolean;
  reason?: string;
}

export interface PTYSession {
  sessionId: string;
  command: string;
  args: string[];
  startedAt: string;
}

export interface PTYOutput {
  sessionId: string;
  output: string;
  timestamp: string;
}

export interface KillSwitchStatus {
  active: boolean;
  reason?: string;
  activatedAt?: string;
  context?: string;
}

export interface ProxyInfo {
  url: string;
  protocol: string;
  host: string;
  port: number;
  username?: string;
  password?: string;
}

export interface ProxyStats {
  total: number;
  active: number;
  failed: number;
  currentIndex: number;
}

// ============================================================================
// SCOPE MANAGEMENT HOOKS
// ============================================================================

/**
 * Hook for loading and managing scope
 */
export function useScope() {
  const [scope, setScope] = useState<ScopeEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadScope = useCallback(async (path: string) => {
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<ScopeEntry[]>('load_scope', { path });
      setScope(result);
      return result;
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setError(errorMsg);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const validateTarget = useCallback(async (target: string): Promise<ValidationResult> => {
    try {
      const result = await invoke<ValidationResult>('validate_target', { target });
      return result;
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setError(errorMsg);
      throw err;
    }
  }, []);

  const addToScope = useCallback((entry: ScopeEntry) => {
    setScope(prev => [...prev, entry]);
  }, []);

  const removeFromScope = useCallback((target: string) => {
    setScope(prev => prev.filter(entry => entry.target !== target));
  }, []);

  return {
    scope,
    loading,
    error,
    loadScope,
    validateTarget,
    addToScope,
    removeFromScope,
  };
}

// ============================================================================
// PTY MANAGEMENT HOOKS
// ============================================================================

/**
 * Hook for managing PTY sessions
 */
export function usePTY() {
  const [sessions, setSessions] = useState<Map<string, PTYSession>>(new Map());
  const [outputs, setOutputs] = useState<Map<string, string>>(new Map());
  const [error, setError] = useState<string | null>(null);

  const spawnPTY = useCallback(async (command: string, args: string[] = []): Promise<string> => {
    setError(null);
    try {
      const sessionId = await invoke<string>('spawn_pty', { command, args });
      
      const session: PTYSession = {
        sessionId,
        command,
        args,
        startedAt: new Date().toISOString(),
      };
      
      setSessions(prev => new Map(prev).set(sessionId, session));
      setOutputs(prev => new Map(prev).set(sessionId, ''));
      
      return sessionId;
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setError(errorMsg);
      throw err;
    }
  }, []);

  const readPTY = useCallback(async (sessionId: string): Promise<string> => {
    try {
      const output = await invoke<string>('read_pty', { sessionId });
      
      setOutputs(prev => {
        const newMap = new Map(prev);
        const existing = newMap.get(sessionId) || '';
        newMap.set(sessionId, existing + output);
        return newMap;
      });
      
      return output;
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setError(errorMsg);
      throw err;
    }
  }, []);

  const writePTY = useCallback(async (sessionId: string, input: string): Promise<void> => {
    try {
      await invoke('write_pty', { sessionId, data: input });
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setError(errorMsg);
      throw err;
    }
  }, []);

  const killPTY = useCallback(async (sessionId: string): Promise<void> => {
    try {
      await invoke('kill_pty', { sessionId });
      setSessions(prev => {
        const newMap = new Map(prev);
        newMap.delete(sessionId);
        return newMap;
      });
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setError(errorMsg);
      throw err;
    }
  }, []);

  const getOutput = useCallback((sessionId: string): string => {
    return outputs.get(sessionId) || '';
  }, [outputs]);

  return {
    sessions: Array.from(sessions.values()),
    error,
    spawnPTY,
    readPTY,
    writePTY,
    killPTY,
    getOutput,
  };
}

/**
 * Hook for streaming PTY output in real-time
 */
export function usePTYStream(sessionId: string | null, intervalMs: number = 100) {
  const [output, setOutput] = useState('');
  const { readPTY } = usePTY();

  useEffect(() => {
    if (!sessionId) return;

    const interval = setInterval(async () => {
      try {
        const newOutput = await readPTY(sessionId);
        if (newOutput) {
          setOutput(prev => prev + newOutput);
        }
      } catch (err) {
        console.error('Error reading PTY:', err);
      }
    }, intervalMs);

    return () => clearInterval(interval);
  }, [sessionId, intervalMs, readPTY]);

  return output;
}

// ============================================================================
// KILL SWITCH HOOKS
// ============================================================================

/**
 * Hook for managing the emergency kill switch
 */
export function useKillSwitch() {
  const [status, setStatus] = useState<KillSwitchStatus>({ active: false });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const checkStatus = useCallback(async () => {
    try {
      const active = await invoke<boolean>('is_kill_switch_active');
      setStatus({ active });
      return active;
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setError(errorMsg);
      throw err;
    }
  }, []);

  const activate = useCallback(async (reason: string, context?: string) => {
    setLoading(true);
    setError(null);
    try {
      await invoke('activate_kill_switch', { reason, context });
      setStatus({
        active: true,
        reason,
        context,
        activatedAt: new Date().toISOString(),
      });
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setError(errorMsg);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const reset = useCallback(async (confirmation: string = 'CONFIRM_RESET') => {
    setLoading(true);
    setError(null);
    try {
      await invoke('reset_kill_switch', { confirmation });
      setStatus({ active: false });
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setError(errorMsg);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  // Auto-check status on mount
  useEffect(() => {
    checkStatus();
  }, [checkStatus]);

  return {
    status,
    loading,
    error,
    activate,
    reset,
    checkStatus,
  };
}

// ============================================================================
// PROXY POOL HOOKS
// ============================================================================

/**
 * Hook for managing proxy pool
 */
export function useProxyPool() {
  const [stats, setStats] = useState<ProxyStats>({
    total: 0,
    active: 0,
    failed: 0,
    currentIndex: 0,
  });
  const [currentProxy, setCurrentProxy] = useState<ProxyInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadProxies = useCallback(async (path: string) => {
    setLoading(true);
    setError(null);
    try {
      const count = await invoke<number>('load_proxies', { path });
      await refreshStats();
      return count;
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setError(errorMsg);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const getNextProxy = useCallback(async (): Promise<ProxyInfo> => {
    try {
      const proxy = await invoke<ProxyInfo>('get_next_proxy');
      setCurrentProxy(proxy);
      await refreshStats();
      return proxy;
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setError(errorMsg);
      throw err;
    }
  }, []);

  const refreshStats = useCallback(async () => {
    try {
      const newStats = await invoke<ProxyStats>('get_proxy_stats');
      setStats(newStats);
    } catch (err) {
      console.error('Error refreshing proxy stats:', err);
    }
  }, []);

  const markProxyFailed = useCallback(async (proxyUrl: string) => {
    try {
      await invoke('mark_proxy_failed', { proxyUrl });
      await refreshStats();
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setError(errorMsg);
      throw err;
    }
  }, [refreshStats]);

  // Auto-refresh stats periodically
  useEffect(() => {
    const interval = setInterval(refreshStats, 5000);
    return () => clearInterval(interval);
  }, [refreshStats]);

  return {
    stats,
    currentProxy,
    loading,
    error,
    loadProxies,
    getNextProxy,
    markProxyFailed,
    refreshStats,
  };
}

// ============================================================================
// COMBINED HOOKS
// ============================================================================

/**
 * Hook that combines all Tauri functionality
 * Useful for components that need access to multiple systems
 */
export function useTauri() {
  const scope = useScope();
  const pty = usePTY();
  const killSwitch = useKillSwitch();
  const proxyPool = useProxyPool();

  return {
    scope,
    pty,
    killSwitch,
    proxyPool,
  };
}
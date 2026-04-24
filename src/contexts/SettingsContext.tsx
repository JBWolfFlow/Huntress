/**
 * Settings Context
 *
 * App settings state: selected models, API key references, auto-approve rules.
 * API keys and HackerOne credentials persist via Tauri secure storage (encrypted on disk).
 * Non-sensitive settings persist via localStorage.
 */

import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { invoke } from '@tauri-apps/api/core';
import type { RefreshConfig } from '../core/auth/token_refresher';

export interface ModelSelection {
  providerId: string;
  modelId: string;
}

export type TerminalTheme = 'matrix' | 'hacker' | 'cyberpunk' | 'classic' | 'blood';
export type PromptStyle = 'huntress' | 'minimal' | 'arrow' | 'lambda' | 'root';

export interface TerminalConfig {
  /** Terminal color theme */
  theme: TerminalTheme;
  /** Prompt style */
  promptStyle: PromptStyle;
  /** Show timestamps on messages */
  showTimestamps: boolean;
  /** Font size in pixels */
  fontSize: number;
}

/** Color palette for each terminal theme */
export const TERMINAL_THEMES: Record<TerminalTheme, {
  label: string;
  prompt: string;
  userText: string;
  aiText: string;
  systemText: string;
  accent: string;
  bg: string;
  dimText: string;
}> = {
  matrix: {
    label: 'Matrix',
    prompt: 'text-green-500',
    userText: 'text-green-400',
    aiText: 'text-green-300',
    systemText: 'text-green-600',
    accent: 'text-green-500',
    bg: 'bg-black',
    dimText: 'text-green-900',
  },
  hacker: {
    label: 'Hacker',
    prompt: 'text-red-500',
    userText: 'text-gray-100',
    aiText: 'text-gray-300',
    systemText: 'text-blue-400',
    accent: 'text-red-500',
    bg: 'bg-black',
    dimText: 'text-gray-700',
  },
  cyberpunk: {
    label: 'Cyberpunk',
    prompt: 'text-fuchsia-500',
    userText: 'text-cyan-300',
    aiText: 'text-fuchsia-300',
    systemText: 'text-yellow-400',
    accent: 'text-fuchsia-500',
    bg: 'bg-black',
    dimText: 'text-fuchsia-900',
  },
  classic: {
    label: 'Classic',
    prompt: 'text-white',
    userText: 'text-white',
    aiText: 'text-gray-300',
    systemText: 'text-yellow-300',
    accent: 'text-white',
    bg: 'bg-black',
    dimText: 'text-gray-600',
  },
  blood: {
    label: 'Blood',
    prompt: 'text-red-600',
    userText: 'text-red-200',
    aiText: 'text-red-300',
    systemText: 'text-orange-400',
    accent: 'text-red-600',
    bg: 'bg-black',
    dimText: 'text-red-950',
  },
};

/** Prompt format for each style */
export const PROMPT_FORMATS: Record<PromptStyle, { label: string; format: (phase: string) => string }> = {
  huntress: { label: 'huntress >', format: (phase) => phase === 'idle' ? 'huntress' : phase },
  minimal: { label: '$ ', format: () => '$' },
  arrow: { label: '>>> ', format: () => '>>>' },
  lambda: { label: 'λ ', format: () => 'λ' },
  root: { label: 'root@huntress# ', format: (phase) => `root@${phase === 'idle' ? 'huntress' : phase}#` },
};

/** Auth profile configuration (metadata only — no secrets stored here) */
export interface AuthProfileConfig {
  id: string;
  label: string;
  authType: 'cookie' | 'bearer' | 'api_key' | 'custom_header';
  /** For bearer: validation URL. For form login: login URL. */
  url?: string;
  /** For API key: the header name (e.g., "X-API-Key") */
  headerName?: string;
  /** For form login: optional field customization */
  usernameField?: string;
  passwordField?: string;
  csrfField?: string;
  /** For custom headers: header key names (values stored in secure storage) */
  customHeaderKeys?: string[];
  /** S8: Whether this profile has a refresh config for auto-refresh */
  hasRefreshConfig?: boolean;
  /**
   * Identity role — drives agent behavior for IDOR/BOLA testing.
   * When set, the value is copied into AuthenticatedSession.label so agents
   * can reference it via `session_label` on `http_request`. (Phase 1 / Q3)
   */
  role?: 'victim' | 'attacker' | 'admin' | 'regular_user' | string;
}

export interface AlloySettings {
  /** Whether alloy mode is enabled (alternates models per iteration) */
  enabled: boolean;
  /** The secondary model to alternate with the orchestrator model */
  secondaryModel: ModelSelection;
  /** Weight for the primary (orchestrator) model, 50-90. Secondary gets the remainder. */
  weight: number;
  /** Rotation strategy for model selection */
  strategy: 'random' | 'round_robin' | 'weighted';
}

/** Per-agent model override */
export interface AgentModelOverride {
  providerId: string;
  modelId: string;
}

export interface StealthSettings {
  /** Whether stealth mode is enabled (UA rotation, header normalization, jitter) */
  enabled: boolean;
  /** Minimum delay between requests to the same domain in ms */
  minDelayMs: number;
  /** Maximum delay between requests to the same domain in ms */
  maxDelayMs: number;
  /** Whether to route requests through the proxy pool */
  proxyEnabled: boolean;
}

export interface AppSettings {
  firstRunComplete: boolean;
  orchestratorModel: ModelSelection;
  defaultAgentModel: ModelSelection;
  /** Provider ID -> API key mapping. Loaded from secure storage on startup. */
  apiKeys: Record<string, string>;
  /** HackerOne API Identifier (used as Basic Auth username) */
  hackerOneUsername: string;
  /** HackerOne API Token (used as Basic Auth password) */
  hackerOneToken: string;
  autoApprove: {
    passiveRecon: boolean;
    activeScanning: boolean;
    /** Safe active recon: gobuster/ffuf/nmap(non-SYN)/nuclei defaults (I3) */
    safeActiveRecon: boolean;
    /** Passive injection probes: curl GETs with payloads (SSTI, SQLi, XSS) (I3) */
    injectionPassive: boolean;
  };
  /** Model Alloy configuration (alternate between 2 providers per iteration) */
  alloy: AlloySettings;
  /** Per-agent model overrides (agentType -> provider/model) */
  agentModelOverrides: Record<string, AgentModelOverride>;
  /** Terminal appearance customization */
  terminal: TerminalConfig;
  theme: 'dark';
  /** Maximum budget per hunt session in USD (default $5) */
  budgetLimitUsd: number;
  /** Stealth and rate limiting configuration for live targets */
  stealth: StealthSettings;
  /**
   * Economy Mode — conservative dispatch defaults for live HackerOne programs.
   * Off preserves historical behavior (5 parallel agents, unlimited fan-out).
   * On drops concurrency to 2, caps specialist fan-out at 3 per recon, and
   * widens per-agent budget claim so slower hunts complete. Details in
   * `src/core/orchestrator/economy_mode.ts`.
   */
  economyMode: boolean;
  /** Auth profiles for authenticated testing (metadata only — credentials in secure storage) */
  authProfiles: AuthProfileConfig[];
  /** Uploaded API schema specs (OpenAPI/Swagger/GraphQL) for targeted testing */
  apiSchemas: Array<{
    id: string;
    name: string;
    source: 'openapi' | 'swagger' | 'graphql';
    baseUrl: string;
    endpointCount: number;
    uploadedAt: number;
    spec: Record<string, unknown>;
  }>;
}

const DEFAULT_SETTINGS: AppSettings = {
  firstRunComplete: false,
  orchestratorModel: { providerId: 'anthropic', modelId: 'claude-opus-4-6' },
  defaultAgentModel: { providerId: 'anthropic', modelId: 'claude-sonnet-4-5-20250929' },
  apiKeys: {},
  hackerOneUsername: '',
  hackerOneToken: '',
  autoApprove: {
    passiveRecon: true,
    activeScanning: false,
    safeActiveRecon: true,
    injectionPassive: true,
  },
  alloy: {
    enabled: false,
    secondaryModel: { providerId: 'google', modelId: 'gemini-2.5-pro' },
    weight: 70,
    strategy: 'random',
  },
  agentModelOverrides: {},
  terminal: {
    theme: 'hacker',
    promptStyle: 'huntress',
    showTimestamps: true,
    fontSize: 13,
  },
  theme: 'dark',
  budgetLimitUsd: 15,
  stealth: {
    enabled: false,
    minDelayMs: 1000,
    maxDelayMs: 2000,
    proxyEnabled: false,
  },
  economyMode: false,
  authProfiles: [],
  apiSchemas: [],
};

const STORAGE_KEY = 'huntress_settings';

// Secure storage key prefixes
const API_KEY_PREFIX = 'api_key_';
const H1_USERNAME_KEY = 'h1_username';
const H1_TOKEN_KEY = 'h1_token';
const AUTH_PROFILE_PREFIX = 'auth_profile_';

interface SettingsContextType {
  settings: AppSettings;
  updateSettings: (patch: Partial<AppSettings>) => void;
  setApiKey: (providerId: string, key: string) => void;
  getApiKey: (providerId: string) => string | undefined;
  completeFirstRun: () => void;
  resetSettings: () => void;
  /** Whether secure storage has finished loading */
  isLoaded: boolean;
  /** Add an auth profile (metadata saved to settings, credentials to secure storage) */
  addAuthProfile: (config: AuthProfileConfig, credentials: Record<string, string>) => Promise<void>;
  /** Remove an auth profile and its stored credentials */
  removeAuthProfile: (id: string) => Promise<void>;
  /** Load credentials for an auth profile from secure storage */
  getAuthProfileCredentials: (id: string) => Promise<Record<string, string>>;
  /** S8: Load refresh config for auto-refresh from secure storage */
  getRefreshConfig: (id: string) => Promise<RefreshConfig | undefined>;
}

const SettingsContext = createContext<SettingsContextType | undefined>(undefined);

export const SettingsProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [settings, setSettings] = useState<AppSettings>(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        return { ...DEFAULT_SETTINGS, ...parsed, apiKeys: {} };
      }
    } catch {
      // Use defaults
    }
    return DEFAULT_SETTINGS;
  });
  const [isLoaded, setIsLoaded] = useState(false);

  // Restore secrets from Tauri secure storage on mount
  useEffect(() => {
    const restoreSecrets = async () => {
      try {
        const keys: string[] = await invoke('list_secret_keys');
        const apiKeys: Record<string, string> = {};
        let h1Username = '';
        let h1Token = '';

        for (const keyName of keys) {
          try {
            const value: string = await invoke('get_secret', { key: keyName });
            if (keyName.startsWith(API_KEY_PREFIX)) {
              const providerId = keyName.slice(API_KEY_PREFIX.length);
              apiKeys[providerId] = value;
            } else if (keyName === H1_USERNAME_KEY) {
              h1Username = value;
            } else if (keyName === H1_TOKEN_KEY) {
              h1Token = value;
            }
          } catch {
            // Key couldn't be decrypted, skip it
          }
        }

        setSettings(prev => ({
          ...prev,
          apiKeys,
          hackerOneUsername: h1Username || prev.hackerOneUsername,
          hackerOneToken: h1Token || prev.hackerOneToken,
        }));
      } catch (err) {
        console.warn('Secure storage unavailable, keys will not persist:', err);
      } finally {
        setIsLoaded(true);
      }
    };

    restoreSecrets();
  }, []);

  // Persist non-sensitive settings to localStorage
  useEffect(() => {
    if (!isLoaded) return;
    try {
      const toStore = {
        ...settings,
        apiKeys: {},           // Never persist API keys to localStorage
        hackerOneUsername: '',  // Stored in secure storage
        hackerOneToken: '',    // Stored in secure storage
      };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(toStore));
    } catch {
      // Storage full or unavailable
    }
  }, [settings, isLoaded]);

  const setApiKey = useCallback((providerId: string, key: string) => {
    setSettings(prev => ({
      ...prev,
      apiKeys: { ...prev.apiKeys, [providerId]: key },
    }));

    // Persist to secure storage
    invoke('store_secret', {
      key: `${API_KEY_PREFIX}${providerId}`,
      value: key,
    }).catch(err => console.error('Failed to store API key:', err));
  }, []);

  const getApiKey = useCallback((providerId: string): string | undefined => {
    return settings.apiKeys[providerId];
  }, [settings.apiKeys]);

  const updateSettings = useCallback((patch: Partial<AppSettings>) => {
    setSettings(prev => ({ ...prev, ...patch }));

    // If HackerOne credentials are being updated, persist to secure storage
    if (patch.hackerOneUsername !== undefined) {
      if (patch.hackerOneUsername) {
        invoke('store_secret', { key: H1_USERNAME_KEY, value: patch.hackerOneUsername })
          .catch(err => console.error('Failed to store H1 username:', err));
      } else {
        invoke('delete_secret', { key: H1_USERNAME_KEY }).catch(() => {});
      }
    }
    if (patch.hackerOneToken !== undefined) {
      if (patch.hackerOneToken) {
        invoke('store_secret', { key: H1_TOKEN_KEY, value: patch.hackerOneToken })
          .catch(err => console.error('Failed to store H1 token:', err));
      } else {
        invoke('delete_secret', { key: H1_TOKEN_KEY }).catch(() => {});
      }
    }
  }, []);

  const completeFirstRun = useCallback(() => {
    setSettings(prev => ({ ...prev, firstRunComplete: true }));
  }, []);

  const addAuthProfile = useCallback(async (config: AuthProfileConfig, credentials: Record<string, string>) => {
    // Store credentials in secure storage (keyed by profile ID + credential name)
    for (const [credKey, credValue] of Object.entries(credentials)) {
      if (credValue) {
        await invoke('store_secret', {
          key: `${AUTH_PROFILE_PREFIX}${config.id}_${credKey}`,
          value: credValue,
        });
      }
    }

    // Add profile metadata to settings (no secrets in localStorage)
    setSettings(prev => ({
      ...prev,
      authProfiles: [...prev.authProfiles, config],
    }));
  }, []);

  const removeAuthProfile = useCallback(async (id: string) => {
    // Find the profile to get its credential keys
    const profile = settings.authProfiles.find(p => p.id === id);

    // Delete all associated secrets
    try {
      const keys: string[] = await invoke('list_secret_keys');
      const profilePrefix = `${AUTH_PROFILE_PREFIX}${id}_`;
      for (const key of keys) {
        if (key.startsWith(profilePrefix)) {
          await invoke('delete_secret', { key });
        }
      }
    } catch {
      // Secure storage unavailable — profile removed from settings anyway
    }

    // Also clean up custom header keys if present
    if (profile?.customHeaderKeys) {
      for (const headerKey of profile.customHeaderKeys) {
        await invoke('delete_secret', {
          key: `${AUTH_PROFILE_PREFIX}${id}_header_${headerKey}`,
        }).catch(() => {});
      }
    }

    // Remove from settings
    setSettings(prev => ({
      ...prev,
      authProfiles: prev.authProfiles.filter(p => p.id !== id),
    }));
  }, [settings.authProfiles]);

  const getAuthProfileCredentials = useCallback(async (id: string): Promise<Record<string, string>> => {
    const result: Record<string, string> = {};
    try {
      const keys: string[] = await invoke('list_secret_keys');
      const profilePrefix = `${AUTH_PROFILE_PREFIX}${id}_`;
      for (const key of keys) {
        if (key.startsWith(profilePrefix)) {
          const credName = key.slice(profilePrefix.length);
          const value: string = await invoke('get_secret', { key });
          result[credName] = value;
        }
      }
    } catch {
      // Secure storage unavailable
    }
    return result;
  }, []);

  const getRefreshConfig = useCallback(async (id: string): Promise<RefreshConfig | undefined> => {
    const profile = settings.authProfiles.find(p => p.id === id);
    if (!profile?.hasRefreshConfig) return undefined;

    try {
      const prefix = `${AUTH_PROFILE_PREFIX}${id}_`;
      const refreshType = await invoke<string>('get_secret', { key: `${prefix}_refreshType` }).catch(() => '');
      const tokenTtl = parseInt(
        await invoke<string>('get_secret', { key: `${prefix}_refreshTokenTtl` }).catch(() => '600'),
        10,
      ) || 600;

      // Parse token header map from stored "field=Header\nfield2=Header2" format
      const parseTokenHeaderMap = async (): Promise<Record<string, string>> => {
        const raw = await invoke<string>('get_secret', { key: `${prefix}_refreshTokenHeaderMap` }).catch(() => '');
        const map: Record<string, string> = {};
        if (raw) {
          for (const line of raw.split('\n')) {
            const eqIdx = line.indexOf('=');
            if (eqIdx > 0) {
              map[line.slice(0, eqIdx).trim()] = line.slice(eqIdx + 1).trim();
            }
          }
        }
        return map;
      };

      switch (refreshType) {
        case 'initdata_exchange': {
          const initData = await invoke<string>('get_secret', { key: `${prefix}_refreshInitData` });
          const authEndpointUrl = await invoke<string>('get_secret', { key: `${prefix}_refreshAuthEndpoint` });
          const deviceSerial = await invoke<string>('get_secret', { key: `${prefix}_refreshDeviceSerial` }).catch(() => '');
          if (!initData || !authEndpointUrl) return undefined;
          const tokenHeaderMap = await parseTokenHeaderMap();
          // Fall back to custom header keys if no explicit map
          if (Object.keys(tokenHeaderMap).length === 0 && profile.customHeaderKeys) {
            for (const headerKey of profile.customHeaderKeys) {
              tokenHeaderMap[headerKey] = headerKey;
            }
          }
          return { type: 'initdata_exchange', initData, authEndpointUrl, deviceSerial, tokenTtlSeconds: tokenTtl, tokenHeaderMap };
        }
        case 'refresh_token': {
          const refreshToken = await invoke<string>('get_secret', { key: `${prefix}_refreshToken` });
          const tokenEndpoint = await invoke<string>('get_secret', { key: `${prefix}_refreshTokenEndpoint` });
          if (!refreshToken || !tokenEndpoint) return undefined;
          const clientId = await invoke<string>('get_secret', { key: `${prefix}_refreshClientId` }).catch(() => undefined);
          const clientSecret = await invoke<string>('get_secret', { key: `${prefix}_refreshClientSecret` }).catch(() => undefined);
          const scope = await invoke<string>('get_secret', { key: `${prefix}_refreshScope` }).catch(() => undefined);
          return { type: 'refresh_token', refreshToken, tokenEndpoint, clientId, clientSecret, scope, tokenTtlSeconds: tokenTtl };
        }
        case 'custom_endpoint': {
          const refreshEndpoint = await invoke<string>('get_secret', { key: `${prefix}_refreshEndpoint` });
          const method = (await invoke<string>('get_secret', { key: `${prefix}_refreshMethod` }).catch(() => 'POST')) as 'GET' | 'POST';
          const body = await invoke<string>('get_secret', { key: `${prefix}_refreshBody` }).catch(() => undefined);
          if (!refreshEndpoint) return undefined;
          const tokenHeaderMap = await parseTokenHeaderMap();
          return { type: 'custom_endpoint', refreshEndpoint, method, body, tokenHeaderMap, tokenTtlSeconds: tokenTtl };
        }
        case 're_login':
          return { type: 're_login' };
        default:
          return undefined;
      }
    } catch {
      return undefined;
    }
  }, [settings.authProfiles]);

  const resetSettings = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    // Clear all secrets from secure storage
    invoke('list_secret_keys').then((keys: unknown) => {
      for (const key of keys as string[]) {
        invoke('delete_secret', { key }).catch(() => {});
      }
    }).catch(() => {});
    setSettings(DEFAULT_SETTINGS);
  }, []);

  return (
    <SettingsContext.Provider
      value={{
        settings,
        updateSettings,
        setApiKey,
        getApiKey,
        completeFirstRun,
        resetSettings,
        isLoaded,
        addAuthProfile,
        removeAuthProfile,
        getAuthProfileCredentials,
        getRefreshConfig,
      }}
    >
      {children}
    </SettingsContext.Provider>
  );
};

export const useSettings = (): SettingsContextType => {
  const context = useContext(SettingsContext);
  if (!context) {
    throw new Error('useSettings must be used within a SettingsProvider');
  }
  return context;
};

export default SettingsContext;

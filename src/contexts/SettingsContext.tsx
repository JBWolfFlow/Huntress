/**
 * Settings Context
 *
 * App settings state: selected models, API key references, auto-approve rules.
 * API keys and HackerOne credentials persist via Tauri secure storage (encrypted on disk).
 * Non-sensitive settings persist via localStorage.
 */

import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { invoke } from '@tauri-apps/api/core';

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
}

const DEFAULT_SETTINGS: AppSettings = {
  firstRunComplete: false,
  orchestratorModel: { providerId: 'anthropic', modelId: 'claude-opus-4-6' },
  defaultAgentModel: { providerId: 'anthropic', modelId: 'claude-sonnet-4-5-20250929' },
  apiKeys: {},
  hackerOneUsername: '',
  hackerOneToken: '',
  autoApprove: {
    passiveRecon: false,
    activeScanning: false,
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
};

const STORAGE_KEY = 'huntress_settings';

// Secure storage key prefixes
const API_KEY_PREFIX = 'api_key_';
const H1_USERNAME_KEY = 'h1_username';
const H1_TOKEN_KEY = 'h1_token';

interface SettingsContextType {
  settings: AppSettings;
  updateSettings: (patch: Partial<AppSettings>) => void;
  setApiKey: (providerId: string, key: string) => void;
  getApiKey: (providerId: string) => string | undefined;
  completeFirstRun: () => void;
  resetSettings: () => void;
  /** Whether secure storage has finished loading */
  isLoaded: boolean;
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

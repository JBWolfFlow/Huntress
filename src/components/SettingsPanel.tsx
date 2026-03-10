/**
 * SettingsPanel
 *
 * Centered modal dialog for settings. Uses absolute positioning
 * instead of flex slide-out to avoid Tauri webview rendering issues.
 */

import React, { useState } from 'react';
import {
  useSettings,
  TERMINAL_THEMES,
  PROMPT_FORMATS,
  type TerminalTheme,
  type PromptStyle,
} from '../contexts/SettingsContext';
import { getProviderFactory } from '../core/providers/provider_factory';

interface SettingsPanelProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SettingsPanel: React.FC<SettingsPanelProps> = ({ isOpen, onClose }) => {
  const { settings, updateSettings, setApiKey, getApiKey, resetSettings } = useSettings();
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [selectedProvider, setSelectedProvider] = useState('');
  const [activeTab, setActiveTab] = useState<'general' | 'terminal' | 'keys' | 'advanced'>('general');

  const factory = getProviderFactory();
  const providers = factory.listProviders();

  if (!isOpen) return null;

  const tabs = [
    { id: 'general' as const, label: 'Models' },
    { id: 'keys' as const, label: 'API Keys' },
    { id: 'terminal' as const, label: 'Terminal' },
    { id: 'advanced' as const, label: 'Advanced' },
  ];

  return (
    <>
      {/* Backdrop overlay */}
      <div
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.80)',
          zIndex: 9998,
        }}
        onClick={onClose}
      />

      {/* Modal dialog */}
      <div
        style={{
          position: 'fixed',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          width: '520px',
          maxWidth: '90vw',
          maxHeight: '85vh',
          zIndex: 9999,
          display: 'flex',
          flexDirection: 'column',
          fontFamily: 'monospace',
        }}
        className="bg-gray-950 border border-gray-700 rounded-lg shadow-2xl overflow-hidden"
      >
        {/* Header */}
        <div
          style={{
            padding: '16px 20px 0 20px',
            borderBottom: '1px solid #374151',
            backgroundColor: '#030712',
            flexShrink: 0,
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 'bold', color: '#ffffff', margin: 0 }}>
              <span style={{ color: '#ef4444' }}>[</span>SETTINGS<span style={{ color: '#ef4444' }}>]</span>
            </h2>
            <button
              onClick={onClose}
              style={{
                fontSize: '12px',
                color: '#9ca3af',
                border: '1px solid #4b5563',
                padding: '4px 10px',
                borderRadius: '4px',
                background: 'transparent',
                cursor: 'pointer',
                fontFamily: 'monospace',
              }}
            >
              [close]
            </button>
          </div>

          {/* Tabs */}
          <div style={{ display: 'flex', gap: '4px', paddingBottom: '12px' }}>
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  fontSize: '12px',
                  padding: '6px 12px',
                  borderRadius: '4px',
                  border: activeTab === tab.id ? '1px solid #991b1b' : '1px solid transparent',
                  backgroundColor: activeTab === tab.id ? 'rgba(127, 29, 29, 0.3)' : 'transparent',
                  color: activeTab === tab.id ? '#f87171' : '#9ca3af',
                  cursor: 'pointer',
                  fontFamily: 'monospace',
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Content — scrollable */}
        <div style={{ overflowY: 'auto', padding: '20px', flex: 1 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

          {/* ─── MODELS TAB ─── */}
          {activeTab === 'general' && (
            <>
              <Section title="Orchestrator Model" subtitle="Primary AI for strategy and conversation.">
                <select
                  value={`${settings.orchestratorModel.providerId}/${settings.orchestratorModel.modelId}`}
                  onChange={(e) => {
                    const [providerId, modelId] = e.target.value.split('/');
                    updateSettings({ orchestratorModel: { providerId, modelId } });
                  }}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    backgroundColor: '#000000',
                    color: '#ffffff',
                    border: '1px solid #4b5563',
                    borderRadius: '4px',
                    fontSize: '13px',
                    fontFamily: 'monospace',
                  }}
                >
                  {providers.map(p =>
                    p.models.map(m => (
                      <option key={`${p.providerId}/${m.id}`} value={`${p.providerId}/${m.id}`}>
                        {p.displayName} — {m.displayName}
                      </option>
                    ))
                  )}
                </select>
              </Section>

              <Section title="Sub-Agent Model" subtitle="Model for specialized hunting agents.">
                <select
                  value={`${settings.defaultAgentModel.providerId}/${settings.defaultAgentModel.modelId}`}
                  onChange={(e) => {
                    const [providerId, modelId] = e.target.value.split('/');
                    updateSettings({ defaultAgentModel: { providerId, modelId } });
                  }}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    backgroundColor: '#000000',
                    color: '#ffffff',
                    border: '1px solid #4b5563',
                    borderRadius: '4px',
                    fontSize: '13px',
                    fontFamily: 'monospace',
                  }}
                >
                  {providers.map(p =>
                    p.models.map(m => (
                      <option key={`${p.providerId}/${m.id}`} value={`${p.providerId}/${m.id}`}>
                        {p.displayName} — {m.displayName}
                      </option>
                    ))
                  )}
                </select>
              </Section>

              <Section title="Model Alloy" subtitle="Alternate between 2 providers per iteration for +20% solve rate. Best with cross-provider pairs.">
                <div style={{ backgroundColor: '#000000', border: '1px solid #1f2937', borderRadius: '6px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {/* Enable toggle */}
                  <CheckboxRow
                    label="Enable Alloy Mode"
                    description="Alternate models each iteration (requires 2+ provider API keys)"
                    checked={settings.alloy.enabled}
                    onChange={(v) => updateSettings({ alloy: { ...settings.alloy, enabled: v } })}
                  />

                  {settings.alloy.enabled && (
                    <>
                      {/* Secondary model selector */}
                      <div>
                        <label style={{ display: 'block', fontSize: '11px', color: '#d1d5db', marginBottom: '4px' }}>Secondary Model</label>
                        <select
                          value={`${settings.alloy.secondaryModel.providerId}/${settings.alloy.secondaryModel.modelId}`}
                          onChange={(e) => {
                            const [providerId, modelId] = e.target.value.split('/');
                            updateSettings({ alloy: { ...settings.alloy, secondaryModel: { providerId, modelId } } });
                          }}
                          style={{ width: '100%', padding: '8px 12px', backgroundColor: '#111111', color: '#ffffff', border: '1px solid #374151', borderRadius: '4px', fontSize: '13px', fontFamily: 'monospace' }}
                        >
                          {providers.map(p =>
                            p.models.map(m => (
                              <option key={`${p.providerId}/${m.id}`} value={`${p.providerId}/${m.id}`}>
                                {p.displayName} — {m.displayName}
                              </option>
                            ))
                          )}
                        </select>
                      </div>

                      {/* Weight slider */}
                      <div>
                        <label style={{ display: 'block', fontSize: '11px', color: '#d1d5db', marginBottom: '4px' }}>
                          Primary Weight: {settings.alloy.weight}% / {100 - settings.alloy.weight}%
                        </label>
                        <input
                          type="range"
                          min="50"
                          max="90"
                          step="5"
                          value={settings.alloy.weight}
                          onChange={(e) => updateSettings({ alloy: { ...settings.alloy, weight: parseInt(e.target.value) } })}
                          style={{ width: '100%' }}
                        />
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: '#6b7280' }}>
                          <span>50/50</span>
                          <span>70/30 (recommended)</span>
                          <span>90/10</span>
                        </div>
                      </div>

                      {/* Strategy selector */}
                      <div>
                        <label style={{ display: 'block', fontSize: '11px', color: '#d1d5db', marginBottom: '4px' }}>Strategy</label>
                        <select
                          value={settings.alloy.strategy}
                          onChange={(e) => updateSettings({ alloy: { ...settings.alloy, strategy: e.target.value as 'random' | 'round_robin' | 'weighted' } })}
                          style={{ width: '100%', padding: '8px 12px', backgroundColor: '#111111', color: '#ffffff', border: '1px solid #374151', borderRadius: '4px', fontSize: '13px', fontFamily: 'monospace' }}
                        >
                          <option value="random">Random (recommended)</option>
                          <option value="weighted">Weighted</option>
                          <option value="round_robin">Round Robin</option>
                        </select>
                      </div>

                      {/* Warning for same-provider */}
                      {settings.orchestratorModel.providerId === settings.alloy.secondaryModel.providerId && (
                        <div style={{ fontSize: '11px', color: '#f59e0b', backgroundColor: 'rgba(245, 158, 11, 0.1)', padding: '8px', borderRadius: '4px', border: '1px solid rgba(245, 158, 11, 0.3)' }}>
                          Same-provider pairs show no alloy benefit. Use models from different providers for best results.
                        </div>
                      )}
                    </>
                  )}
                </div>
              </Section>

              <Section title="Auto-Approve Rules">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <CheckboxRow
                    label="Passive Recon"
                    description="subfinder, amass, waybackurls, whois"
                    checked={settings.autoApprove.passiveRecon}
                    onChange={(v) => updateSettings({ autoApprove: { ...settings.autoApprove, passiveRecon: v } })}
                  />
                  <CheckboxRow
                    label="Active Scanning"
                    description="httpx, nuclei, katana, nmap"
                    checked={settings.autoApprove.activeScanning}
                    onChange={(v) => updateSettings({ autoApprove: { ...settings.autoApprove, activeScanning: v } })}
                  />
                </div>
              </Section>
            </>
          )}

          {/* ─── API KEYS TAB ─── */}
          {activeTab === 'keys' && (
            <>
              <Section title="AI Provider Keys" subtitle="Encrypted and stored locally. Never sent except to the provider.">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {providers.filter(p => p.requiresApiKey).map(provider => (
                    <div
                      key={provider.providerId}
                      style={{
                        backgroundColor: '#000000',
                        border: '1px solid #1f2937',
                        borderRadius: '6px',
                        padding: '12px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <span style={{ fontSize: '13px', color: '#ffffff', fontWeight: 'bold' }}>{provider.displayName}</span>
                        {getApiKey(provider.providerId) ? (
                          <span style={{ fontSize: '11px', color: '#4ade80', fontWeight: 'bold' }}>[CONFIGURED]</span>
                        ) : (
                          <span style={{ fontSize: '11px', color: '#6b7280' }}>[NOT SET]</span>
                        )}
                      </div>
                      <div style={{ fontSize: '11px', color: '#6b7280', marginBottom: '8px' }}>
                        {provider.models.map(m => m.displayName).join(', ')}
                      </div>
                      {selectedProvider === provider.providerId ? (
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <input
                            type="password"
                            value={apiKeyInput}
                            onChange={(e) => setApiKeyInput(e.target.value)}
                            placeholder="Paste API key..."
                            autoFocus
                            style={{
                              flex: 1,
                              padding: '6px 10px',
                              backgroundColor: '#111111',
                              color: '#4ade80',
                              border: '1px solid #374151',
                              borderRadius: '4px',
                              fontSize: '12px',
                              fontFamily: 'monospace',
                            }}
                          />
                          <button
                            onClick={() => {
                              if (apiKeyInput.trim()) {
                                setApiKey(provider.providerId, apiKeyInput.trim());
                                setApiKeyInput('');
                                setSelectedProvider('');
                              }
                            }}
                            style={{
                              padding: '6px 12px',
                              backgroundColor: 'rgba(20, 83, 45, 0.5)',
                              border: '1px solid #15803d',
                              color: '#4ade80',
                              borderRadius: '4px',
                              fontSize: '12px',
                              fontWeight: 'bold',
                              cursor: 'pointer',
                              fontFamily: 'monospace',
                            }}
                          >
                            [SAVE]
                          </button>
                          <button
                            onClick={() => { setSelectedProvider(''); setApiKeyInput(''); }}
                            style={{
                              padding: '6px 8px',
                              color: '#6b7280',
                              fontSize: '12px',
                              background: 'transparent',
                              border: 'none',
                              cursor: 'pointer',
                              fontFamily: 'monospace',
                            }}
                          >
                            cancel
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => { setSelectedProvider(provider.providerId); setApiKeyInput(''); }}
                          style={{
                            fontSize: '12px',
                            color: '#f87171',
                            background: 'transparent',
                            border: 'none',
                            cursor: 'pointer',
                            fontFamily: 'monospace',
                            padding: 0,
                          }}
                        >
                          {'>'} {getApiKey(provider.providerId) ? 'Update key' : 'Add key'}
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </Section>

              <Section title="HackerOne API">
                <div style={{ backgroundColor: '#000000', border: '1px solid #1f2937', borderRadius: '6px', padding: '12px' }}>
                  {settings.hackerOneUsername && settings.hackerOneToken ? (
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <span style={{ fontSize: '11px', color: '#4ade80' }}>[CONNECTED]</span>{' '}
                        <span style={{ fontSize: '12px', color: '#ffffff' }}>{settings.hackerOneUsername}</span>
                      </div>
                      <button
                        onClick={() => updateSettings({ hackerOneUsername: '', hackerOneToken: '' })}
                        style={{ fontSize: '11px', color: '#f87171', background: 'transparent', border: 'none', cursor: 'pointer', fontFamily: 'monospace' }}
                      >
                        [remove]
                      </button>
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <p style={{ fontSize: '11px', color: '#9ca3af', margin: 0 }}>
                        Generate at{' '}
                        <a href="https://hackerone.com/settings/api_token/edit" target="_blank" rel="noopener noreferrer" style={{ color: '#f87171', textDecoration: 'underline' }}>
                          hackerone.com/settings/api_token
                        </a>
                      </p>
                      <div>
                        <label style={{ display: 'block', fontSize: '11px', color: '#d1d5db', marginBottom: '4px' }}>API Identifier</label>
                        <input
                          type="text"
                          placeholder="your_username"
                          value={settings.hackerOneUsername}
                          onChange={(e) => updateSettings({ hackerOneUsername: e.target.value })}
                          style={{ width: '100%', padding: '6px 10px', backgroundColor: '#111111', color: '#ffffff', border: '1px solid #374151', borderRadius: '4px', fontSize: '12px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                        />
                      </div>
                      <div>
                        <label style={{ display: 'block', fontSize: '11px', color: '#d1d5db', marginBottom: '4px' }}>API Token</label>
                        <input
                          type="password"
                          placeholder="your_api_token"
                          value={settings.hackerOneToken}
                          onChange={(e) => updateSettings({ hackerOneToken: e.target.value })}
                          style={{ width: '100%', padding: '6px 10px', backgroundColor: '#111111', color: '#ffffff', border: '1px solid #374151', borderRadius: '4px', fontSize: '12px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              </Section>
            </>
          )}

          {/* ─── TERMINAL TAB ─── */}
          {activeTab === 'terminal' && (
            <>
              <Section title="Color Theme">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {(Object.entries(TERMINAL_THEMES) as [TerminalTheme, typeof TERMINAL_THEMES[TerminalTheme]][]).map(([id, theme]) => (
                    <button
                      key={id}
                      onClick={() => updateSettings({ terminal: { ...settings.terminal, theme: id } })}
                      style={{
                        textAlign: 'left',
                        padding: '10px 12px',
                        borderRadius: '6px',
                        border: settings.terminal.theme === id ? '1px solid #dc2626' : '1px solid #1f2937',
                        backgroundColor: settings.terminal.theme === id ? 'rgba(127, 29, 29, 0.15)' : '#000000',
                        cursor: 'pointer',
                        fontFamily: 'monospace',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <span style={{ fontSize: '13px', color: '#ffffff', fontWeight: 'bold' }}>{theme.label}</span>
                        {settings.terminal.theme === id && (
                          <span style={{ fontSize: '11px', color: '#4ade80' }}>[ACTIVE]</span>
                        )}
                      </div>
                      <div style={{ backgroundColor: '#000000', borderRadius: '4px', padding: '6px 8px', fontSize: '11px', border: '1px solid #111827' }}>
                        <span className={theme.dimText}>[12:00]</span>{' '}
                        <span className={theme.prompt}>huntress {'>'}</span>{' '}
                        <span className={theme.aiText}>Analyzing target...</span>
                      </div>
                    </button>
                  ))}
                </div>
              </Section>

              <Section title="Prompt Style">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {(Object.entries(PROMPT_FORMATS) as [PromptStyle, typeof PROMPT_FORMATS[PromptStyle]][]).map(([id, prompt]) => (
                    <button
                      key={id}
                      onClick={() => updateSettings({ terminal: { ...settings.terminal, promptStyle: id } })}
                      style={{
                        textAlign: 'left',
                        padding: '8px 12px',
                        borderRadius: '4px',
                        border: settings.terminal.promptStyle === id ? '1px solid #dc2626' : '1px solid #1f2937',
                        backgroundColor: settings.terminal.promptStyle === id ? 'rgba(127, 29, 29, 0.15)' : '#000000',
                        cursor: 'pointer',
                        fontFamily: 'monospace',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <span style={{ fontSize: '12px' }}>
                        <span className={TERMINAL_THEMES[settings.terminal.theme].prompt}>
                          {prompt.format('idle')}
                        </span>{' '}
                        <span className={TERMINAL_THEMES[settings.terminal.theme].userText}>
                          help me find vulns
                        </span>
                      </span>
                      {settings.terminal.promptStyle === id && (
                        <span style={{ fontSize: '11px', color: '#4ade80', marginLeft: '8px' }}>[ACTIVE]</span>
                      )}
                    </button>
                  ))}
                </div>
              </Section>

              <Section title="Display Options">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <CheckboxRow
                    label="Show Timestamps"
                    description="Display [HH:MM:SS] on each message"
                    checked={settings.terminal.showTimestamps}
                    onChange={(v) => updateSettings({ terminal: { ...settings.terminal, showTimestamps: v } })}
                  />
                </div>
              </Section>

              <Section title={`Font Size: ${settings.terminal.fontSize}px`}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <input
                    type="range"
                    min="10"
                    max="18"
                    value={settings.terminal.fontSize}
                    onChange={(e) => updateSettings({ terminal: { ...settings.terminal, fontSize: parseInt(e.target.value) } })}
                    style={{ flex: 1 }}
                  />
                  <div style={{ display: 'flex', gap: '4px' }}>
                    {[11, 13, 15].map(size => (
                      <button
                        key={size}
                        onClick={() => updateSettings({ terminal: { ...settings.terminal, fontSize: size } })}
                        style={{
                          fontSize: '11px',
                          padding: '4px 8px',
                          borderRadius: '4px',
                          border: settings.terminal.fontSize === size ? '1px solid #dc2626' : '1px solid #1f2937',
                          color: settings.terminal.fontSize === size ? '#f87171' : '#6b7280',
                          backgroundColor: 'transparent',
                          cursor: 'pointer',
                          fontFamily: 'monospace',
                        }}
                      >
                        {size}
                      </button>
                    ))}
                  </div>
                </div>
                <div
                  style={{
                    backgroundColor: '#000000',
                    border: '1px solid #1f2937',
                    borderRadius: '4px',
                    padding: '8px',
                    marginTop: '8px',
                    fontSize: `${settings.terminal.fontSize}px`,
                  }}
                >
                  <span className={TERMINAL_THEMES[settings.terminal.theme].prompt}>
                    {PROMPT_FORMATS[settings.terminal.promptStyle].format('idle')}
                  </span>{' '}
                  <span className={TERMINAL_THEMES[settings.terminal.theme].userText}>
                    Preview text at {settings.terminal.fontSize}px
                  </span>
                </div>
              </Section>
            </>
          )}

          {/* ─── ADVANCED TAB ─── */}
          {activeTab === 'advanced' && (
            <>
              <Section title="Storage Info">
                <div style={{ backgroundColor: '#000000', border: '1px solid #1f2937', borderRadius: '6px', padding: '12px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px' }}>
                    <InfoRow label="Settings" value="localStorage" />
                    <InfoRow label="API keys" value="Encrypted vault" valueColor="#4ade80" />
                    <InfoRow label="Vault" value="~/.local/share/huntress/vault.enc" valueColor="#d1d5db" />
                  </div>
                </div>
              </Section>

              <Section title="Danger Zone">
                <div style={{ backgroundColor: '#000000', border: '1px solid rgba(127, 29, 29, 0.5)', borderRadius: '6px', padding: '16px' }}>
                  <p style={{ fontSize: '12px', color: '#9ca3af', margin: '0 0 12px 0' }}>
                    Reset all settings to defaults. This clears API keys, model selections, and terminal preferences.
                  </p>
                  <button
                    onClick={() => {
                      if (confirm('Reset ALL settings? This clears your API keys, model selections, and terminal preferences.')) {
                        resetSettings();
                      }
                    }}
                    style={{
                      fontSize: '12px',
                      color: '#f87171',
                      border: '1px solid #991b1b',
                      padding: '6px 14px',
                      borderRadius: '4px',
                      backgroundColor: 'transparent',
                      cursor: 'pointer',
                      fontFamily: 'monospace',
                    }}
                  >
                    [RESET ALL SETTINGS]
                  </button>
                </div>
              </Section>
            </>
          )}

          </div>
        </div>
      </div>
    </>
  );
};

/** Section header */
function Section({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <div>
      <div style={{ fontSize: '11px', color: '#f87171', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
        {title}
      </div>
      {subtitle && (
        <p style={{ fontSize: '11px', color: '#9ca3af', margin: '0 0 8px 0' }}>{subtitle}</p>
      )}
      {children}
    </div>
  );
}

/** Checkbox row */
function CheckboxRow({ label, description, checked, onChange }: {
  label: string;
  description: string;
  checked: boolean;
  onChange: (val: boolean) => void;
}) {
  return (
    <label
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        backgroundColor: '#000000',
        border: '1px solid #1f2937',
        borderRadius: '6px',
        padding: '10px 12px',
        cursor: 'pointer',
      }}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        style={{ accentColor: '#ef4444' }}
      />
      <div>
        <div style={{ fontSize: '13px', color: '#ffffff' }}>{label}</div>
        <div style={{ fontSize: '11px', color: '#9ca3af' }}>{description}</div>
      </div>
    </label>
  );
}

/** Info row for key-value display */
function InfoRow({ label, value, valueColor = '#ffffff' }: { label: string; value: string; valueColor?: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
      <span style={{ color: '#9ca3af' }}>{label}</span>
      <span style={{ color: valueColor }}>{value}</span>
    </div>
  );
}

export default SettingsPanel;

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
  type AuthProfileConfig,
} from '../contexts/SettingsContext';
import { getProviderFactory } from '../core/providers/provider_factory';
import { parseAPISpec } from '../core/discovery/api_schema_parser';

type AuthType = AuthProfileConfig['authType'];

interface SettingsPanelProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SettingsPanel: React.FC<SettingsPanelProps> = ({ isOpen, onClose }) => {
  const { settings, updateSettings, setApiKey, getApiKey, resetSettings, addAuthProfile, removeAuthProfile } = useSettings();
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [selectedProvider, setSelectedProvider] = useState('');
  const [activeTab, setActiveTab] = useState<'general' | 'terminal' | 'keys' | 'schemas' | 'auth' | 'advanced'>('general');

  // Auth profile form state
  const [showAuthForm, setShowAuthForm] = useState(false);
  const [authLabel, setAuthLabel] = useState('');
  const [authType, setAuthType] = useState<AuthType>('bearer');
  const [authUrl, setAuthUrl] = useState('');
  const [authToken, setAuthToken] = useState('');
  const [authUsername, setAuthUsername] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authHeaderName, setAuthHeaderName] = useState('');
  const [authApiKeyValue, setAuthApiKeyValue] = useState('');
  const [authCustomHeaders, setAuthCustomHeaders] = useState<Array<{ key: string; value: string }>>([{ key: '', value: '' }]);
  const [authUsernameField, setAuthUsernameField] = useState('');
  const [authPasswordField, setAuthPasswordField] = useState('');
  const [authCsrfField, setAuthCsrfField] = useState('');
  const [authTestStatus, setAuthTestStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');
  const [authTestMessage, setAuthTestMessage] = useState('');
  const [authSaving, setAuthSaving] = useState(false);

  type AutoApproveField = 'passiveRecon' | 'activeScanning' | 'safeActiveRecon' | 'injectionPassive';

  const AUTO_APPROVE_LABELS: Record<AutoApproveField, string> = {
    passiveRecon: 'Passive Recon',
    activeScanning: 'Active Scanning',
    safeActiveRecon: 'Safe Active Recon',
    injectionPassive: 'Passive Injection Probes',
  };

  const AUTO_APPROVE_TOOLS: Record<AutoApproveField, string> = {
    passiveRecon: 'subfinder, amass, waybackurls, whois, dig, curl (GET)',
    activeScanning: 'httpx, nuclei, katana, nmap',
    safeActiveRecon: 'gobuster, ffuf, dirb, dirsearch, nmap (non-SYN), nuclei (default templates)',
    injectionPassive: 'curl GET with SSTI/SQLi/XSS/path-traversal payloads in query strings',
  };

  // Auto-approve confirmation dialog state
  const [pendingAutoApprove, setPendingAutoApprove] = useState<{
    field: AutoApproveField;
    label: string;
  } | null>(null);

  /** Intercept auto-approve toggle-on — require explicit confirmation */
  const handleAutoApproveToggle = (field: AutoApproveField, newValue: boolean) => {
    if (!newValue) {
      // Turning OFF doesn't need confirmation
      updateSettings({ autoApprove: { ...settings.autoApprove, [field]: false } });
      return;
    }
    // Turning ON — show confirmation dialog
    setPendingAutoApprove({ field, label: AUTO_APPROVE_LABELS[field] });
  };

  const confirmAutoApprove = () => {
    if (pendingAutoApprove) {
      updateSettings({
        autoApprove: { ...settings.autoApprove, [pendingAutoApprove.field]: true },
      });
      setPendingAutoApprove(null);
    }
  };

  const resetAuthForm = () => {
    setShowAuthForm(false);
    setAuthLabel('');
    setAuthType('bearer');
    setAuthUrl('');
    setAuthToken('');
    setAuthUsername('');
    setAuthPassword('');
    setAuthHeaderName('');
    setAuthApiKeyValue('');
    setAuthCustomHeaders([{ key: '', value: '' }]);
    setAuthUsernameField('');
    setAuthPasswordField('');
    setAuthCsrfField('');
    setAuthTestStatus('idle');
    setAuthTestMessage('');
  };

  const handleSaveAuthProfile = async () => {
    if (!authLabel.trim()) return;
    setAuthSaving(true);

    const id = `auth_${Date.now()}`;
    const config: AuthProfileConfig = {
      id,
      label: authLabel.trim(),
      authType,
    };
    const credentials: Record<string, string> = {};

    switch (authType) {
      case 'bearer':
        config.url = authUrl.trim() || undefined;
        credentials.token = authToken;
        break;
      case 'cookie':
        config.url = authUrl.trim();
        config.usernameField = authUsernameField.trim() || undefined;
        config.passwordField = authPasswordField.trim() || undefined;
        config.csrfField = authCsrfField.trim() || undefined;
        credentials.username = authUsername;
        credentials.password = authPassword;
        break;
      case 'api_key':
        config.headerName = authHeaderName.trim() || 'X-API-Key';
        credentials.apikey = authApiKeyValue;
        break;
      case 'custom_header': {
        const validHeaders = authCustomHeaders.filter(h => h.key.trim() && h.value.trim());
        config.customHeaderKeys = validHeaders.map(h => h.key.trim());
        for (const header of validHeaders) {
          credentials[`header_${header.key.trim()}`] = header.value.trim();
        }
        break;
      }
    }

    try {
      await addAuthProfile(config, credentials);
      resetAuthForm();
    } catch (err) {
      setAuthTestMessage(`Failed to save: ${err instanceof Error ? err.message : String(err)}`);
      setAuthTestStatus('error');
    } finally {
      setAuthSaving(false);
    }
  };

  const handleDeleteAuthProfile = async (id: string) => {
    await removeAuthProfile(id);
  };

  const AUTH_TYPE_LABELS: Record<AuthProfileConfig['authType'], string> = {
    bearer: 'Bearer Token',
    cookie: 'Form Login',
    api_key: 'API Key',
    custom_header: 'Custom Headers',
  };

  const factory = getProviderFactory();
  const providers = factory.listProviders();

  if (!isOpen) return null;

  const tabs = [
    { id: 'general' as const, label: 'Models' },
    { id: 'keys' as const, label: 'API Keys' },
    { id: 'auth' as const, label: 'Auth' },
    { id: 'schemas' as const, label: 'API Schemas' },
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
                <div style={{ fontSize: '11px', color: '#9ca3af', marginBottom: '10px', lineHeight: '1.5' }}>
                  Commands matching these categories bypass the approval modal so unattended hunts
                  aren't blocked at the 60s timeout. Mutations (POST/PUT/DELETE, sqlmap, hydra) always
                  require manual approval regardless of these toggles.
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <CheckboxRow
                    label="Passive Recon"
                    description={AUTO_APPROVE_TOOLS.passiveRecon}
                    checked={settings.autoApprove.passiveRecon}
                    onChange={(v) => handleAutoApproveToggle('passiveRecon', v)}
                  />
                  <CheckboxRow
                    label="Safe Active Recon"
                    description={AUTO_APPROVE_TOOLS.safeActiveRecon}
                    checked={settings.autoApprove.safeActiveRecon}
                    onChange={(v) => handleAutoApproveToggle('safeActiveRecon', v)}
                  />
                  <CheckboxRow
                    label="Passive Injection Probes"
                    description={AUTO_APPROVE_TOOLS.injectionPassive}
                    checked={settings.autoApprove.injectionPassive}
                    onChange={(v) => handleAutoApproveToggle('injectionPassive', v)}
                  />
                  <CheckboxRow
                    label="Active Scanning (legacy)"
                    description={AUTO_APPROVE_TOOLS.activeScanning}
                    checked={settings.autoApprove.activeScanning}
                    onChange={(v) => handleAutoApproveToggle('activeScanning', v)}
                  />
                </div>
              </Section>

              {/* Auto-approve confirmation dialog */}
              {pendingAutoApprove && (
                <div style={{
                  position: 'fixed', inset: 0, zIndex: 9999,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  backgroundColor: 'rgba(0,0,0,0.7)',
                }}>
                  <div style={{
                    backgroundColor: '#111', border: '1px solid #dc2626',
                    borderRadius: '8px', padding: '24px', maxWidth: '420px', width: '90%',
                  }}>
                    <h3 style={{ color: '#ef4444', margin: '0 0 12px 0', fontSize: '16px' }}>
                      Enable Auto-Approve: {pendingAutoApprove.label}?
                    </h3>
                    <p style={{ color: '#d1d5db', fontSize: '13px', lineHeight: '1.5', margin: '0 0 8px 0' }}>
                      When enabled, agents will execute {pendingAutoApprove.label.toLowerCase()} commands
                      <strong style={{ color: '#f87171' }}> without asking for your approval</strong>.
                    </p>
                    <p style={{ color: '#9ca3af', fontSize: '12px', lineHeight: '1.4', margin: '0 0 16px 0' }}>
                      This means tools like {AUTO_APPROVE_TOOLS[pendingAutoApprove.field]} will run automatically.
                      Only enable this if you trust the target scope and understand the risk.
                    </p>
                    <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                      <button
                        onClick={() => setPendingAutoApprove(null)}
                        style={{
                          padding: '8px 16px', borderRadius: '4px', border: '1px solid #374151',
                          backgroundColor: '#1f2937', color: '#d1d5db', cursor: 'pointer', fontSize: '13px',
                        }}
                      >
                        Cancel
                      </button>
                      <button
                        onClick={confirmAutoApprove}
                        style={{
                          padding: '8px 16px', borderRadius: '4px', border: '1px solid #dc2626',
                          backgroundColor: '#7f1d1d', color: '#fca5a5', cursor: 'pointer', fontSize: '13px',
                          fontWeight: 'bold',
                        }}
                      >
                        I understand — enable
                      </button>
                    </div>
                  </div>
                </div>
              )}
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

          {/* ─── AUTH TAB ─── */}
          {activeTab === 'auth' && (
            <>
              <Section title="Auth Profiles" subtitle="Configure authentication for target testing. Credentials are encrypted and stored locally.">
                {settings.authProfiles.length === 0 && !showAuthForm ? (
                  <div style={{ color: '#6b7280', fontSize: '12px', fontStyle: 'italic', padding: '12px', backgroundColor: '#000000', border: '1px solid #1f2937', borderRadius: '6px' }}>
                    No auth profiles configured. Add one to test authenticated endpoints.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {(() => {
                      // IDOR-ready badge (Q3): shown when two or more distinct
                      // non-empty roles are configured. The canonical pair is
                      // victim+attacker, but admin+regular_user, or any two
                      // named roles, also unlock multi-identity testing via
                      // http_request's session_label parameter.
                      const roles = settings.authProfiles
                        .map(p => p.role)
                        .filter((r): r is string => typeof r === 'string' && r.length > 0);
                      const distinctRoles = Array.from(new Set(roles));
                      if (distinctRoles.length < 2) return null;

                      const hasCanonicalPair =
                        distinctRoles.includes('victim') && distinctRoles.includes('attacker');
                      const pairSummary = hasCanonicalPair
                        ? 'victim + attacker'
                        : distinctRoles.slice(0, 4).join(' + ');

                      return (
                        <div
                          data-testid="idor-ready-badge"
                          style={{
                            fontSize: '11px',
                            color: '#4ade80',
                            padding: '6px 10px',
                            border: '1px solid #166534',
                            borderRadius: '4px',
                            backgroundColor: 'rgba(22, 101, 52, 0.1)',
                          }}
                        >
                          IDOR-ready: {pairSummary} — agents can call{' '}
                          <code>http_request</code> with{' '}
                          <code>session_label: &quot;victim&quot;</code> to test across identities.
                        </div>
                      );
                    })()}
                    {settings.authProfiles.map((profile) => (
                      <div key={profile.id} style={{ backgroundColor: '#000000', border: '1px solid #1f2937', borderRadius: '6px', padding: '12px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div>
                            <span style={{ fontSize: '13px', color: '#ffffff', fontWeight: 'bold' }}>{profile.label}</span>
                            <span style={{ fontSize: '11px', color: '#9ca3af', marginLeft: '8px' }}>
                              [{AUTH_TYPE_LABELS[profile.authType]}]
                            </span>
                            {profile.role && (
                              <span style={{ fontSize: '10px', color: '#f59e0b', marginLeft: '8px', padding: '2px 6px', border: '1px solid #92400e', borderRadius: '3px' }}>
                                role: {profile.role}
                              </span>
                            )}
                          </div>
                          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                            <span style={{ fontSize: '11px', color: '#4ade80' }}>[SAVED]</span>
                            <button
                              onClick={() => handleDeleteAuthProfile(profile.id)}
                              style={{ color: '#f87171', border: '1px solid #991b1b', padding: '4px 10px', borderRadius: '4px', backgroundColor: 'transparent', cursor: 'pointer', fontFamily: 'monospace', fontSize: '11px' }}
                            >
                              [DELETE]
                            </button>
                          </div>
                        </div>
                        {profile.url && (
                          <div style={{ fontSize: '11px', color: '#6b7280', marginTop: '4px' }}>{profile.url}</div>
                        )}
                        {profile.headerName && (
                          <div style={{ fontSize: '11px', color: '#6b7280', marginTop: '4px' }}>Header: {profile.headerName}</div>
                        )}
                        {profile.customHeaderKeys && profile.customHeaderKeys.length > 0 && (
                          <div style={{ fontSize: '11px', color: '#6b7280', marginTop: '4px' }}>
                            Headers: {profile.customHeaderKeys.join(', ')}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </Section>

              {!showAuthForm ? (
                <button
                  onClick={() => setShowAuthForm(true)}
                  style={{
                    fontSize: '12px', color: '#f87171', background: 'transparent',
                    border: '1px solid #991b1b', padding: '8px 16px', borderRadius: '4px',
                    cursor: 'pointer', fontFamily: 'monospace', width: '100%',
                  }}
                >
                  [+ ADD AUTH PROFILE]
                </button>
              ) : (
                <Section title="New Auth Profile">
                  <div style={{ backgroundColor: '#000000', border: '1px solid #1f2937', borderRadius: '6px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {/* Label */}
                    <div>
                      <label style={{ display: 'block', fontSize: '11px', color: '#d1d5db', marginBottom: '4px' }}>Profile Label</label>
                      <input
                        type="text"
                        value={authLabel}
                        onChange={(e) => setAuthLabel(e.target.value)}
                        placeholder="e.g., User A, Admin, Tester"
                        style={{ width: '100%', padding: '6px 10px', backgroundColor: '#111111', color: '#ffffff', border: '1px solid #374151', borderRadius: '4px', fontSize: '12px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                      />
                    </div>

                    {/* Auth Type */}
                    <div>
                      <label style={{ display: 'block', fontSize: '11px', color: '#d1d5db', marginBottom: '4px' }}>Auth Type</label>
                      <select
                        value={authType}
                        onChange={(e) => setAuthType(e.target.value as AuthType)}
                        style={{ width: '100%', padding: '8px 12px', backgroundColor: '#111111', color: '#ffffff', border: '1px solid #374151', borderRadius: '4px', fontSize: '13px', fontFamily: 'monospace' }}
                      >
                        <option value="bearer">Bearer Token</option>
                        <option value="cookie">Form Login</option>
                        <option value="api_key">API Key</option>
                        <option value="custom_header">Custom Headers</option>
                      </select>
                    </div>

                    {/* ── Bearer Token fields ── */}
                    {authType === 'bearer' && (
                      <>
                        <div>
                          <label style={{ display: 'block', fontSize: '11px', color: '#d1d5db', marginBottom: '4px' }}>Bearer Token</label>
                          <input
                            type="password"
                            value={authToken}
                            onChange={(e) => setAuthToken(e.target.value)}
                            placeholder="Paste bearer token..."
                            style={{ width: '100%', padding: '6px 10px', backgroundColor: '#111111', color: '#4ade80', border: '1px solid #374151', borderRadius: '4px', fontSize: '12px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                          />
                        </div>
                        <div>
                          <label style={{ display: 'block', fontSize: '11px', color: '#d1d5db', marginBottom: '4px' }}>Validation URL (optional)</label>
                          <input
                            type="text"
                            value={authUrl}
                            onChange={(e) => setAuthUrl(e.target.value)}
                            placeholder="https://api.target.com/me"
                            style={{ width: '100%', padding: '6px 10px', backgroundColor: '#111111', color: '#ffffff', border: '1px solid #374151', borderRadius: '4px', fontSize: '12px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                          />
                          <div style={{ fontSize: '10px', color: '#6b7280', marginTop: '2px' }}>GET request to verify the token works</div>
                        </div>
                      </>
                    )}

                    {/* ── Form Login fields ── */}
                    {authType === 'cookie' && (
                      <>
                        <div>
                          <label style={{ display: 'block', fontSize: '11px', color: '#d1d5db', marginBottom: '4px' }}>Login URL</label>
                          <input
                            type="text"
                            value={authUrl}
                            onChange={(e) => setAuthUrl(e.target.value)}
                            placeholder="https://target.com/login"
                            style={{ width: '100%', padding: '6px 10px', backgroundColor: '#111111', color: '#ffffff', border: '1px solid #374151', borderRadius: '4px', fontSize: '12px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                          />
                        </div>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <div style={{ flex: 1 }}>
                            <label style={{ display: 'block', fontSize: '11px', color: '#d1d5db', marginBottom: '4px' }}>Username</label>
                            <input
                              type="text"
                              value={authUsername}
                              onChange={(e) => setAuthUsername(e.target.value)}
                              placeholder="user@example.com"
                              style={{ width: '100%', padding: '6px 10px', backgroundColor: '#111111', color: '#ffffff', border: '1px solid #374151', borderRadius: '4px', fontSize: '12px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                            />
                          </div>
                          <div style={{ flex: 1 }}>
                            <label style={{ display: 'block', fontSize: '11px', color: '#d1d5db', marginBottom: '4px' }}>Password</label>
                            <input
                              type="password"
                              value={authPassword}
                              onChange={(e) => setAuthPassword(e.target.value)}
                              placeholder="password"
                              style={{ width: '100%', padding: '6px 10px', backgroundColor: '#111111', color: '#4ade80', border: '1px solid #374151', borderRadius: '4px', fontSize: '12px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                            />
                          </div>
                        </div>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <div style={{ flex: 1 }}>
                            <label style={{ display: 'block', fontSize: '11px', color: '#6b7280', marginBottom: '4px' }}>Username field (optional)</label>
                            <input
                              type="text"
                              value={authUsernameField}
                              onChange={(e) => setAuthUsernameField(e.target.value)}
                              placeholder="username"
                              style={{ width: '100%', padding: '6px 10px', backgroundColor: '#111111', color: '#9ca3af', border: '1px solid #1f2937', borderRadius: '4px', fontSize: '11px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                            />
                          </div>
                          <div style={{ flex: 1 }}>
                            <label style={{ display: 'block', fontSize: '11px', color: '#6b7280', marginBottom: '4px' }}>Password field (optional)</label>
                            <input
                              type="text"
                              value={authPasswordField}
                              onChange={(e) => setAuthPasswordField(e.target.value)}
                              placeholder="password"
                              style={{ width: '100%', padding: '6px 10px', backgroundColor: '#111111', color: '#9ca3af', border: '1px solid #1f2937', borderRadius: '4px', fontSize: '11px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                            />
                          </div>
                          <div style={{ flex: 1 }}>
                            <label style={{ display: 'block', fontSize: '11px', color: '#6b7280', marginBottom: '4px' }}>CSRF field (optional)</label>
                            <input
                              type="text"
                              value={authCsrfField}
                              onChange={(e) => setAuthCsrfField(e.target.value)}
                              placeholder="_token"
                              style={{ width: '100%', padding: '6px 10px', backgroundColor: '#111111', color: '#9ca3af', border: '1px solid #1f2937', borderRadius: '4px', fontSize: '11px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                            />
                          </div>
                        </div>
                      </>
                    )}

                    {/* ── API Key fields ── */}
                    {authType === 'api_key' && (
                      <>
                        <div>
                          <label style={{ display: 'block', fontSize: '11px', color: '#d1d5db', marginBottom: '4px' }}>Header Name</label>
                          <input
                            type="text"
                            value={authHeaderName}
                            onChange={(e) => setAuthHeaderName(e.target.value)}
                            placeholder="X-API-Key"
                            style={{ width: '100%', padding: '6px 10px', backgroundColor: '#111111', color: '#ffffff', border: '1px solid #374151', borderRadius: '4px', fontSize: '12px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                          />
                        </div>
                        <div>
                          <label style={{ display: 'block', fontSize: '11px', color: '#d1d5db', marginBottom: '4px' }}>API Key Value</label>
                          <input
                            type="password"
                            value={authApiKeyValue}
                            onChange={(e) => setAuthApiKeyValue(e.target.value)}
                            placeholder="Paste API key..."
                            style={{ width: '100%', padding: '6px 10px', backgroundColor: '#111111', color: '#4ade80', border: '1px solid #374151', borderRadius: '4px', fontSize: '12px', fontFamily: 'monospace', boxSizing: 'border-box' }}
                          />
                        </div>
                      </>
                    )}

                    {/* ── Custom Headers fields ── */}
                    {authType === 'custom_header' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        <label style={{ fontSize: '11px', color: '#d1d5db' }}>Custom Headers</label>
                        {authCustomHeaders.map((header, idx) => (
                          <div key={idx} style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                            <input
                              type="text"
                              value={header.key}
                              onChange={(e) => {
                                const updated = [...authCustomHeaders];
                                updated[idx] = { ...header, key: e.target.value };
                                setAuthCustomHeaders(updated);
                              }}
                              placeholder="Header-Name"
                              style={{ flex: 1, padding: '6px 10px', backgroundColor: '#111111', color: '#ffffff', border: '1px solid #374151', borderRadius: '4px', fontSize: '12px', fontFamily: 'monospace' }}
                            />
                            <input
                              type="password"
                              value={header.value}
                              onChange={(e) => {
                                const updated = [...authCustomHeaders];
                                updated[idx] = { ...header, value: e.target.value };
                                setAuthCustomHeaders(updated);
                              }}
                              placeholder="value"
                              style={{ flex: 1, padding: '6px 10px', backgroundColor: '#111111', color: '#4ade80', border: '1px solid #374151', borderRadius: '4px', fontSize: '12px', fontFamily: 'monospace' }}
                            />
                            {authCustomHeaders.length > 1 && (
                              <button
                                onClick={() => setAuthCustomHeaders(authCustomHeaders.filter((_, i) => i !== idx))}
                                style={{ color: '#f87171', background: 'transparent', border: 'none', cursor: 'pointer', fontFamily: 'monospace', fontSize: '14px', padding: '0 4px' }}
                              >
                                x
                              </button>
                            )}
                          </div>
                        ))}
                        <button
                          onClick={() => setAuthCustomHeaders([...authCustomHeaders, { key: '', value: '' }])}
                          style={{ fontSize: '11px', color: '#9ca3af', background: 'transparent', border: '1px dashed #374151', padding: '6px', borderRadius: '4px', cursor: 'pointer', fontFamily: 'monospace' }}
                        >
                          + Add header
                        </button>
                      </div>
                    )}

                    {/* Test status */}
                    {authTestStatus !== 'idle' && (
                      <div style={{
                        fontSize: '11px', padding: '8px', borderRadius: '4px',
                        backgroundColor: authTestStatus === 'success' ? 'rgba(74, 222, 128, 0.1)' : authTestStatus === 'error' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(251, 191, 36, 0.1)',
                        border: `1px solid ${authTestStatus === 'success' ? '#166534' : authTestStatus === 'error' ? '#991b1b' : '#92400e'}`,
                        color: authTestStatus === 'success' ? '#4ade80' : authTestStatus === 'error' ? '#f87171' : '#fbbf24',
                      }}>
                        {authTestStatus === 'testing' ? 'Testing...' : authTestMessage}
                      </div>
                    )}

                    {/* Actions */}
                    <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                      <button
                        onClick={resetAuthForm}
                        style={{ padding: '8px 16px', borderRadius: '4px', border: '1px solid #374151', backgroundColor: '#1f2937', color: '#d1d5db', cursor: 'pointer', fontSize: '12px', fontFamily: 'monospace' }}
                      >
                        Cancel
                      </button>
                      <button
                        onClick={handleSaveAuthProfile}
                        disabled={!authLabel.trim() || authSaving}
                        style={{
                          padding: '8px 16px', borderRadius: '4px', border: '1px solid #15803d',
                          backgroundColor: 'rgba(20, 83, 45, 0.5)', color: '#4ade80',
                          cursor: authLabel.trim() && !authSaving ? 'pointer' : 'not-allowed',
                          fontSize: '12px', fontWeight: 'bold', fontFamily: 'monospace',
                          opacity: authLabel.trim() && !authSaving ? 1 : 0.5,
                        }}
                      >
                        {authSaving ? '[SAVING...]' : '[SAVE PROFILE]'}
                      </button>
                    </div>
                  </div>
                </Section>
              )}
            </>
          )}

          {/* ─── API SCHEMAS TAB ─── */}
          {activeTab === 'schemas' && (
            <>
              <Section title="Upload API Specification" subtitle="Upload OpenAPI 3.x, Swagger 2.x, or GraphQL introspection JSON to generate targeted vulnerability tasks.">
                <div style={{ backgroundColor: '#000000', border: '1px dashed #374151', borderRadius: '6px', padding: '20px', textAlign: 'center' }}>
                  <input
                    type="file"
                    accept=".json,.yaml,.yml"
                    onChange={async (e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
                      try {
                        const text = await file.text();
                        const spec = JSON.parse(text);
                        const parsed = parseAPISpec(spec, '');
                        const schemaEntry = {
                          id: `schema_${Date.now()}`,
                          name: parsed.title || file.name,
                          source: parsed.source,
                          baseUrl: parsed.baseUrl,
                          endpointCount: parsed.endpoints.length,
                          uploadedAt: Date.now(),
                          spec,
                        };
                        updateSettings({
                          apiSchemas: [...(settings.apiSchemas || []), schemaEntry],
                        });
                      } catch (err) {
                        alert(`Failed to parse API spec: ${err instanceof Error ? err.message : 'Unknown error'}`);
                      }
                    }}
                    style={{ display: 'none' }}
                    id="schema-upload"
                  />
                  <label htmlFor="schema-upload" style={{ cursor: 'pointer', color: '#9ca3af', fontSize: '13px', fontFamily: 'monospace' }}>
                    <div style={{ color: '#ef4444', fontSize: '14px', marginBottom: '4px' }}>[UPLOAD SPEC FILE]</div>
                    <div>Drag & drop or click to upload .json / .yaml</div>
                  </label>
                </div>
              </Section>

              <Section title="Loaded Schemas">
                {(!settings.apiSchemas || settings.apiSchemas.length === 0) ? (
                  <div style={{ color: '#6b7280', fontSize: '12px', fontStyle: 'italic', padding: '12px' }}>
                    No API schemas loaded. Upload a spec file above.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {settings.apiSchemas.map((schema) => (
                      <div key={schema.id} style={{ backgroundColor: '#000000', border: '1px solid #1f2937', borderRadius: '6px', padding: '12px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div>
                            <div style={{ fontSize: '13px', color: '#ffffff', fontWeight: 'bold' }}>{schema.name}</div>
                            <div style={{ fontSize: '11px', color: '#9ca3af', marginTop: '2px' }}>
                              {schema.source.toUpperCase()} | {schema.endpointCount} endpoints | {schema.baseUrl || 'No base URL'}
                            </div>
                          </div>
                          <button
                            onClick={() => {
                              updateSettings({
                                apiSchemas: settings.apiSchemas.filter((s) => s.id !== schema.id),
                              });
                            }}
                            style={{ color: '#f87171', border: '1px solid #991b1b', padding: '4px 10px', borderRadius: '4px', backgroundColor: 'transparent', cursor: 'pointer', fontFamily: 'monospace', fontSize: '11px' }}
                          >
                            [REMOVE]
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
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

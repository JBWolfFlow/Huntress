/**
 * Auth Wizard Modal (S6)
 *
 * Post-import wizard that appears when AuthDetector finds auth requirements.
 * 3-step flow: Detection Summary → Auth Profile Setup → Confirmation.
 *
 * Uses the same visual patterns as ImportModal and SettingsPanel Auth tab.
 */

import React, { useState, useCallback } from 'react';
import { useSettings } from '../contexts/SettingsContext';
import type { AuthProfileConfig } from '../contexts/SettingsContext';
import type { AuthDetectionResult, TargetProbeResult } from '../core/auth/auth_detector';
import type { ProgramGuidelines } from './GuidelinesImporter';
import { HttpClient } from '../core/http/request_engine';
import { getProviderFactory } from '../core/providers/provider_factory';
import { getAnthropicModelForComplexity } from '../core/orchestrator/cost_router';

// ─── Types ───────────────────────────────────────────────────────────────────

interface AuthWizardModalProps {
  isOpen: boolean;
  detectionResult: AuthDetectionResult;
  guidelines: ProgramGuidelines;
  onComplete: () => void;
  onSkip: () => void;
}

type WizardStep = 1 | 2 | 3;

interface SavedProfile {
  config: AuthProfileConfig;
  label: string;
  authType: AuthProfileConfig['authType'];
}

const AUTH_TYPE_LABELS: Record<AuthProfileConfig['authType'], string> = {
  bearer: 'Bearer Token',
  cookie: 'Form Login',
  api_key: 'API Key',
  custom_header: 'Custom Headers',
};

// ─── Component ───────────────────────────────────────────────────────────────

export const AuthWizardModal: React.FC<AuthWizardModalProps> = ({
  isOpen,
  detectionResult,
  guidelines,
  onComplete,
  onSkip,
}) => {
  const { addAuthProfile, getApiKey, settings } = useSettings();

  const [step, setStep] = useState<WizardStep>(1);
  const [savedProfiles, setSavedProfiles] = useState<SavedProfile[]>([]);

  // Form state
  const topSuggestion = detectionResult.suggestedProfiles[0] ?? null;
  const [authLabel, setAuthLabel] = useState(topSuggestion?.label ?? '');
  const [authRole, setAuthRole] = useState<string>('');
  const [authType, setAuthType] = useState<AuthProfileConfig['authType']>(
    topSuggestion?.authType ?? 'bearer',
  );
  const [authUrl, setAuthUrl] = useState(topSuggestion?.url ?? '');
  const [authToken, setAuthToken] = useState('');
  const [authUsername, setAuthUsername] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authHeaderName, setAuthHeaderName] = useState(topSuggestion?.headerName ?? 'X-API-Key');
  const [authApiKeyValue, setAuthApiKeyValue] = useState('');
  const [authCustomHeaders, setAuthCustomHeaders] = useState<Array<{ key: string; value: string }>>([
    { key: topSuggestion?.headerName ?? '', value: '' },
  ]);

  // Test state
  const [testStatus, setTestStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');
  const [testMessage, setTestMessage] = useState('');

  // Save state
  const [saving, setSaving] = useState(false);

  // Additional form visibility
  const [showAdditionalForm, setShowAdditionalForm] = useState(false);

  // Browser capture state (Phase B)
  const [captureStatus, setCaptureStatus] = useState<'idle' | 'capturing' | 'done' | 'error'>('idle');
  const [captureMessage, setCaptureMessage] = useState('');

  // AuthWorkerAgent (Session 25 Part B) — "Let Huntress log in"
  const [workerStatus, setWorkerStatus] = useState<'idle' | 'running' | 'done' | 'error'>('idle');
  const [workerMessage, setWorkerMessage] = useState('');
  const [totpSeed, setTotpSeed] = useState('');

  // S8: Generic token refresh config for auto-refresh (all auth types)
  const isTelegramDetected = detectionResult.detectedAuthTypes.some(d => d.type === 'telegram_webapp');
  const [showRefreshSection, setShowRefreshSection] = useState(false);
  type RefreshStrategy = 'none' | 'initdata_exchange' | 'refresh_token' | 'custom_endpoint' | 're_login';
  const [refreshStrategy, setRefreshStrategy] = useState<RefreshStrategy>(
    isTelegramDetected ? 'initdata_exchange' : 'none',
  );
  // initdata_exchange fields
  const [initDataValue, setInitDataValue] = useState('');
  const [authEndpointUrl, setAuthEndpointUrl] = useState('');
  const [deviceSerial, setDeviceSerial] = useState('');
  // refresh_token fields (OAuth2)
  const [refreshTokenValue, setRefreshTokenValue] = useState('');
  const [tokenEndpointUrl, setTokenEndpointUrl] = useState('');
  const [oauthClientId, setOauthClientId] = useState('');
  const [oauthClientSecret, setOauthClientSecret] = useState('');
  const [oauthScope, setOauthScope] = useState('');
  // custom_endpoint fields
  const [refreshEndpointUrl, setRefreshEndpointUrl] = useState('');
  const [refreshMethod, setRefreshMethod] = useState<'GET' | 'POST'>('POST');
  const [refreshBody, setRefreshBody] = useState('');
  // Shared: token header mapping (response.field=Header-Name, one per line)
  const [tokenHeaderMapStr, setTokenHeaderMapStr] = useState('');
  // Shared: token TTL
  const [tokenTtlSeconds, setTokenTtlSeconds] = useState('600');

  // Current instructions based on suggestion or selected type
  const currentInstructions = topSuggestion?.instructions ?? [];

  const resetForm = useCallback(() => {
    setAuthLabel('');
    setAuthRole('');
    setAuthType('bearer');
    setAuthUrl('');
    setAuthToken('');
    setAuthUsername('');
    setAuthPassword('');
    setAuthHeaderName('X-API-Key');
    setAuthApiKeyValue('');
    setAuthCustomHeaders([{ key: '', value: '' }]);
    setTestStatus('idle');
    setTestMessage('');
    setShowAdditionalForm(false);
    setShowRefreshSection(false);
    setRefreshStrategy(isTelegramDetected ? 'initdata_exchange' : 'none');
    setInitDataValue('');
    setAuthEndpointUrl('');
    setDeviceSerial('');
    setRefreshTokenValue('');
    setTokenEndpointUrl('');
    setOauthClientId('');
    setOauthClientSecret('');
    setOauthScope('');
    setRefreshEndpointUrl('');
    setRefreshMethod('POST');
    setRefreshBody('');
    setTokenHeaderMapStr('');
    setTokenTtlSeconds('600');
  }, []);

  // ── Browser Auto-Capture (Phase B) ──

  const handleBrowserCapture = useCallback(async () => {
    setCaptureStatus('capturing');
    setCaptureMessage('Launching browser...');

    try {
      // Dynamic import to avoid Playwright static bundling (same pattern as react_loop.ts)
      const { AuthBrowserCapture } = await import('../core/auth/auth_browser_capture');
      const capture = new AuthBrowserCapture();

      const loginUrl = authUrl || guidelines.scope.inScope[0] || '';
      if (!loginUrl) {
        setCaptureStatus('error');
        setCaptureMessage('No URL to open — enter a login URL first');
        return;
      }

      const normalizedUrl = /^https?:\/\//i.test(loginUrl) ? loginUrl : `https://${loginUrl}`;
      const scopeDomains = guidelines.scope.inScope
        .map(s => { try { return new URL(/^https?:\/\//i.test(s) ? s : `https://${s}`).hostname; } catch { return s; } });

      const result = await capture.captureAuth(
        normalizedUrl,
        scopeDomains,
        (status) => setCaptureMessage(status.message),
      );

      // Auto-fill form from captured data
      if (result.bearerToken) {
        setAuthType('bearer');
        setAuthToken(result.bearerToken);
        if (!authLabel) setAuthLabel('Auto-captured');
      } else if (Object.keys(result.customHeaders).length > 0) {
        setAuthType('custom_header');
        const headers = Object.entries(result.customHeaders).map(([key, value]) => ({ key, value }));
        setAuthCustomHeaders(headers.length > 0 ? headers : [{ key: '', value: '' }]);
        if (!authLabel) setAuthLabel('Auto-captured');
      } else if (result.cookies.length > 0) {
        setAuthType('cookie');
        if (!authLabel) setAuthLabel('Auto-captured');
      }

      const parts: string[] = [];
      if (result.bearerToken) parts.push('bearer token');
      if (result.cookies.length > 0) parts.push(`${result.cookies.length} cookies`);
      if (Object.keys(result.customHeaders).length > 0) parts.push(`${Object.keys(result.customHeaders).length} custom headers`);

      setCaptureStatus('done');
      setCaptureMessage(parts.length > 0
        ? `Captured: ${parts.join(', ')}`
        : 'No auth credentials detected — try logging in manually');
    } catch (err) {
      setCaptureStatus('error');
      setCaptureMessage(err instanceof Error ? err.message : 'Browser capture failed');
    }
  }, [authUrl, authLabel, guidelines.scope.inScope]);

  // ── "Let Huntress log in" — AuthWorkerAgent (Session 25 Part B) ──

  const handleRunAuthWorker = useCallback(async () => {
    setWorkerStatus('running');
    setWorkerMessage('Starting auth worker…');

    try {
      const loginUrl = authUrl || guidelines.scope.inScope[0] || '';
      if (!loginUrl) {
        setWorkerStatus('error');
        setWorkerMessage('Enter a login URL first.');
        return;
      }
      if (!authUsername || !authPassword) {
        setWorkerStatus('error');
        setWorkerMessage('Enter a username and password first.');
        return;
      }

      const normalizedUrl = /^https?:\/\//i.test(loginUrl) ? loginUrl : `https://${loginUrl}`;
      const scopeDomains = guidelines.scope.inScope
        .map(s => { try { return new URL(/^https?:\/\//i.test(s) ? s : `https://${s}`).hostname; } catch { return s; } })
        .filter(Boolean);

      // Use the default agent model from settings; fall back to the moderate-tier mapping.
      const providerId = settings.defaultAgentModel.providerId;
      const modelId = settings.defaultAgentModel.modelId || getAnthropicModelForComplexity('moderate');
      const apiKey = getApiKey(providerId);
      if (!apiKey && providerId !== 'local') {
        setWorkerStatus('error');
        setWorkerMessage(`No API key set for ${providerId}. Add one in Settings.`);
        return;
      }

      const factory = getProviderFactory();
      const provider = factory.create(providerId, { apiKey });

      // Dynamic import to stay aligned with the pattern used elsewhere for
      // browser-adjacent code (same as handleBrowserCapture above).
      const { AuthWorkerAgent } = await import('../agents/auth_worker_agent');
      const agent = new AuthWorkerAgent();
      await agent.initialize(provider, modelId);

      setWorkerMessage('Navigating to login page…');
      const result = await agent.execute({
        id: `auth_worker_${Date.now()}`,
        target: normalizedUrl,
        scope: scopeDomains,
        description: 'Automated login via AuthWorkerAgent',
        parameters: {
          loginUrl: normalizedUrl,
          scopeDomains,
          username: authUsername,
          password: authPassword,
          totpSeed: totpSeed || undefined,
        } as Record<string, unknown>,
      });

      const outcome = agent.getLastOutcome();
      if (!result.success || !outcome || outcome.kind !== 'succeeded') {
        setWorkerStatus('error');
        setWorkerMessage(
          outcome?.kind === 'failed'
            ? `${outcome.reason}: ${outcome.detail}`
            : (result.error || 'Auth worker did not complete successfully.')
        );
        return;
      }

      // Auto-fill form fields from captured payload — same precedence as
      // handleBrowserCapture so downstream auth test / save flow is identical.
      const captured = outcome.captured;
      if (captured.bearerToken) {
        setAuthType('bearer');
        setAuthToken(captured.bearerToken);
        if (!authLabel) setAuthLabel('Auto-login captured');
      } else if (Object.keys(captured.customHeaders).length > 0) {
        setAuthType('custom_header');
        const headers = Object.entries(captured.customHeaders).map(([key, value]) => ({ key, value }));
        setAuthCustomHeaders(headers.length > 0 ? headers : [{ key: '', value: '' }]);
        if (!authLabel) setAuthLabel('Auto-login captured');
      } else if (captured.cookies.length > 0) {
        setAuthType('cookie');
        if (!authLabel) setAuthLabel('Auto-login captured');
      }

      const parts: string[] = [];
      if (captured.bearerToken) parts.push('bearer token');
      if (captured.cookies.length > 0) parts.push(`${captured.cookies.length} cookies`);
      const customHeaderCount = Object.keys(captured.customHeaders).length;
      if (customHeaderCount > 0) parts.push(`${customHeaderCount} custom headers`);

      setWorkerStatus('done');
      setWorkerMessage(parts.length > 0
        ? `Logged in. Captured: ${parts.join(', ')}. Review below, then continue.`
        : 'Logged in but nothing useful was captured. Try supervised capture instead.');
    } catch (err) {
      setWorkerStatus('error');
      setWorkerMessage(err instanceof Error ? err.message : 'Auth worker failed unexpectedly');
    }
  }, [authUrl, authUsername, authPassword, totpSeed, authLabel, guidelines.scope.inScope, settings.defaultAgentModel, getApiKey]);

  // ── Test Auth ──

  const handleTestAuth = useCallback(async () => {
    setTestStatus('testing');
    setTestMessage('');

    const testUrl = authUrl || guidelines.scope.inScope[0] || '';
    if (!testUrl) {
      setTestStatus('error');
      setTestMessage('No URL to test against');
      return;
    }

    try {
      const testClient = new HttpClient({ defaultTimeoutMs: 5000 });
      const headers: Record<string, string> = {};

      if (authType === 'bearer' && authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      } else if (authType === 'api_key' && authApiKeyValue) {
        headers[authHeaderName || 'X-API-Key'] = authApiKeyValue;
      } else if (authType === 'custom_header') {
        for (const h of authCustomHeaders) {
          if (h.key && h.value) headers[h.key] = h.value;
        }
      }

      const normalizedUrl = /^https?:\/\//i.test(testUrl) ? testUrl : `https://${testUrl}`;
      const response = await testClient.request({
        url: normalizedUrl,
        method: 'GET',
        headers,
        timeoutMs: 5000,
      });

      if (response.status >= 200 && response.status < 400) {
        setTestStatus('success');
        setTestMessage(`AUTH VALID \u2014 HTTP ${response.status}`);
      } else if (response.status === 401 || response.status === 403) {
        setTestStatus('error');
        setTestMessage(`AUTH FAILED \u2014 HTTP ${response.status}`);
      } else {
        setTestStatus('success');
        setTestMessage(`HTTP ${response.status} \u2014 response received`);
      }
    } catch (err) {
      setTestStatus('error');
      setTestMessage(err instanceof Error ? err.message : 'Connection failed');
    }
  }, [authType, authToken, authApiKeyValue, authHeaderName, authCustomHeaders, authUrl, guidelines.scope.inScope]);

  // ── Save Profile ──

  const handleSaveProfile = useCallback(async () => {
    if (!authLabel.trim()) return;
    setSaving(true);

    try {
      const profileId = `auth_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
      const config: AuthProfileConfig = {
        id: profileId,
        // When a role is selected, use it as the session label so agents can
        // reference it via `session_label: "victim"` etc. Falls back to the
        // user-entered label otherwise. (Phase 1 / Q3)
        label: authRole || authLabel,
        authType,
        url: authUrl || undefined,
        role: authRole || undefined,
      };
      const credentials: Record<string, string> = {};

      switch (authType) {
        case 'bearer':
          if (authToken) credentials.token = authToken;
          break;
        case 'cookie':
          if (authUsername) credentials.username = authUsername;
          if (authPassword) credentials.password = authPassword;
          config.url = authUrl || undefined;
          break;
        case 'api_key':
          config.headerName = authHeaderName || 'X-API-Key';
          if (authApiKeyValue) credentials.apikey = authApiKeyValue;
          break;
        case 'custom_header': {
          const keys: string[] = [];
          for (const h of authCustomHeaders) {
            if (h.key && h.value) {
              keys.push(h.key);
              credentials[`header_${h.key}`] = h.value;
            }
          }
          config.customHeaderKeys = keys;
          break;
        }
      }

      // S8: Store refresh config alongside credentials for auto-refresh
      if (refreshStrategy !== 'none') {
        credentials['_refreshType'] = refreshStrategy;
        credentials['_refreshTokenTtl'] = tokenTtlSeconds || '600';
        config.hasRefreshConfig = true;

        switch (refreshStrategy) {
          case 'initdata_exchange':
            if (initDataValue) credentials['_refreshInitData'] = initDataValue;
            if (authEndpointUrl) credentials['_refreshAuthEndpoint'] = authEndpointUrl;
            if (deviceSerial) credentials['_refreshDeviceSerial'] = deviceSerial;
            if (tokenHeaderMapStr) credentials['_refreshTokenHeaderMap'] = tokenHeaderMapStr;
            break;
          case 'refresh_token':
            if (refreshTokenValue) credentials['_refreshToken'] = refreshTokenValue;
            if (tokenEndpointUrl) credentials['_refreshTokenEndpoint'] = tokenEndpointUrl;
            if (oauthClientId) credentials['_refreshClientId'] = oauthClientId;
            if (oauthClientSecret) credentials['_refreshClientSecret'] = oauthClientSecret;
            if (oauthScope) credentials['_refreshScope'] = oauthScope;
            break;
          case 'custom_endpoint':
            if (refreshEndpointUrl) credentials['_refreshEndpoint'] = refreshEndpointUrl;
            credentials['_refreshMethod'] = refreshMethod;
            if (refreshBody) credentials['_refreshBody'] = refreshBody;
            if (tokenHeaderMapStr) credentials['_refreshTokenHeaderMap'] = tokenHeaderMapStr;
            break;
          case 're_login':
            // No additional keys — uses stored login credentials
            break;
        }
      }

      await addAuthProfile(config, credentials);
      setSavedProfiles(prev => [...prev, { config, label: authLabel, authType }]);
      resetForm();
    } catch (err) {
      console.error('Failed to save auth profile:', err);
    } finally {
      setSaving(false);
    }
  }, [authLabel, authRole, authType, authUrl, authToken, authUsername, authPassword, authHeaderName, authApiKeyValue, authCustomHeaders, addAuthProfile, resetForm, refreshStrategy, tokenTtlSeconds, initDataValue, authEndpointUrl, deviceSerial, tokenHeaderMapStr, refreshTokenValue, tokenEndpointUrl, oauthClientId, oauthClientSecret, oauthScope, refreshEndpointUrl, refreshMethod, refreshBody]);

  if (!isOpen) return null;

  // ─── Render ────────────────────────────────────────────────────────────────

  return (
    <>
      {/* Backdrop */}
      <div style={{
        position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.85)', zIndex: 10998,
      }} />

      {/* Modal */}
      <div style={{
        position: 'fixed', top: '50%', left: '50%',
        transform: 'translate(-50%, -50%)',
        width: '620px', maxWidth: '90vw', maxHeight: '85vh',
        zIndex: 10999,
        display: 'flex', flexDirection: 'column',
        fontFamily: 'monospace',
        backgroundColor: '#111827',
        border: '1px solid #374151',
        borderRadius: '8px',
        overflow: 'hidden',
      }}>
        {/* Header */}
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '12px 16px',
          borderBottom: '1px solid #374151',
          backgroundColor: '#030712',
          flexShrink: 0,
        }}>
          <h2 style={{ fontSize: '14px', fontWeight: 'bold', color: '#ffffff', margin: 0 }}>
            <span style={{ color: '#ef4444' }}>[</span>AUTH REQUIRED<span style={{ color: '#ef4444' }}>]</span>
            <span style={{ color: '#6b7280', fontSize: '11px', marginLeft: '12px' }}>
              Step {step} of 3
            </span>
          </h2>
          {/* Step indicators */}
          <div style={{ display: 'flex', gap: '4px' }}>
            {([1, 2, 3] as const).map(s => (
              <div key={s} style={{
                width: '8px', height: '8px', borderRadius: '50%',
                backgroundColor: s === step ? '#ef4444' : s < step ? '#4ade80' : '#374151',
              }} />
            ))}
          </div>
        </div>

        {/* Content */}
        <div style={{ overflowY: 'auto', padding: '16px', flex: 1 }}>
          {step === 1 && renderStep1()}
          {step === 2 && renderStep2()}
          {step === 3 && renderStep3()}
        </div>
      </div>
    </>
  );

  // ─── Step 1: Detection Summary ─────────────────────────────────────────────

  function renderStep1() {
    const { probeResults, detectedAuthTypes, confidence } = detectionResult;

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {/* Confidence badge */}
        <div style={{
          padding: '10px 14px',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid #991b1b',
          borderRadius: '6px',
        }}>
          <div style={{ fontSize: '13px', fontWeight: 'bold', color: '#ef4444', marginBottom: '4px' }}>
            Authentication Required — {Math.round(confidence * 100)}% confidence
          </div>
          <div style={{ fontSize: '11px', color: '#d1d5db' }}>
            {detectedAuthTypes.length > 0
              ? `Detected: ${detectedAuthTypes.map(d => d.type.replace(/_/g, ' ').toUpperCase()).join(', ')}`
              : 'Auth wall detected on target(s)'}
          </div>
        </div>

        {/* Probe results */}
        {probeResults.length > 0 && (
          <div>
            <div style={{ fontSize: '11px', color: '#6b7280', marginBottom: '8px' }}>
              TARGET PROBE RESULTS
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {probeResults.map((probe, i) => (
                <ProbeResultRow key={i} probe={probe} />
              ))}
            </div>
          </div>
        )}

        {/* Detected auth types with evidence */}
        {detectedAuthTypes.length > 0 && (
          <div>
            <div style={{ fontSize: '11px', color: '#6b7280', marginBottom: '8px' }}>
              DETECTION EVIDENCE
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {detectedAuthTypes.map((auth, i) => (
                <div key={i} style={{
                  padding: '8px 12px',
                  backgroundColor: '#000000',
                  border: '1px solid #1f2937',
                  borderRadius: '4px',
                  fontSize: '11px',
                }}>
                  <div style={{ color: '#fbbf24', fontWeight: 'bold' }}>
                    {auth.type.replace(/_/g, ' ').toUpperCase()} — {Math.round(auth.confidence * 100)}%
                  </div>
                  <div style={{ color: '#9ca3af', marginTop: '2px' }}>{auth.evidence}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Program hints */}
        {detectionResult.programHints.length > 0 && (
          <div style={{ fontSize: '11px', color: '#6b7280' }}>
            <span style={{ color: '#9ca3af' }}>Hints: </span>
            {detectionResult.programHints.join('; ')}
          </div>
        )}

        {/* Actions */}
        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', marginTop: '8px' }}>
          <button onClick={onSkip} style={skipButtonStyle}>
            [SKIP — HUNT WITHOUT AUTH]
          </button>
          <button onClick={() => setStep(2)} style={primaryButtonStyle}>
            [CONFIGURE AUTH]
          </button>
        </div>
      </div>
    );
  }

  // ─── Step 2: Auth Profile Setup ────────────────────────────────────────────

  function renderStep2() {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {/* Previously saved profiles */}
        {savedProfiles.length > 0 && (
          <div style={{
            padding: '10px 14px',
            backgroundColor: 'rgba(74, 222, 128, 0.05)',
            border: '1px solid #166534',
            borderRadius: '6px',
          }}>
            <div style={{ fontSize: '11px', color: '#4ade80', fontWeight: 'bold', marginBottom: '4px' }}>
              {savedProfiles.length} profile{savedProfiles.length > 1 ? 's' : ''} saved
            </div>
            {savedProfiles.map((p, i) => (
              <div key={i} style={{ fontSize: '11px', color: '#9ca3af' }}>
                {p.label} [{AUTH_TYPE_LABELS[p.authType]}]
              </div>
            ))}
          </div>
        )}

        {/* Add another profile button (shown after first save) */}
        {savedProfiles.length > 0 && !showAdditionalForm && (
          <div style={{ display: 'flex', gap: '8px', justifyContent: 'space-between' }}>
            <button
              onClick={() => setShowAdditionalForm(true)}
              style={{
                ...secondaryButtonStyle,
                fontSize: '11px',
              }}
            >
              [+ ADD ANOTHER PROFILE]
            </button>
            <button onClick={() => setStep(3)} style={primaryButtonStyle}>
              [CONTINUE \u2192]
            </button>
          </div>
        )}

        {/* Form (shown on first load or when "add another" is clicked) */}
        {(savedProfiles.length === 0 || showAdditionalForm) && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {/* Telegram preset — dedicated DevTools paste-assist guide (Q4).
                Rendered only when auth_detector flagged telegram_webapp so we
                replace the generic instructions panel with target-shaped
                guidance. Browser auto-capture does not work for Telegram Mini
                Apps because they live inside the Telegram Desktop WebView. */}
            {isTelegramDetected && (
              <div
                data-testid="telegram-preset-instructions"
                style={{
                  padding: '12px',
                  backgroundColor: 'rgba(59, 130, 246, 0.08)',
                  border: '1px solid #2563eb',
                  borderRadius: '6px',
                }}
              >
                <div style={{ fontSize: '11px', color: '#60a5fa', fontWeight: 'bold', marginBottom: '8px' }}>
                  TELEGRAM MINI APP — DEVTOOLS PASTE-ASSIST
                </div>
                <div style={{ fontSize: '11px', color: '#9ca3af', marginBottom: '10px', lineHeight: '1.5' }}>
                  Telegram tokens are short-lived (~10 min). Huntress will auto-refresh them via{' '}
                  <code>initdata_exchange</code>{' '}
                  once you paste three values captured from Telegram Desktop DevTools.
                </div>
                <ol style={{ fontSize: '11px', color: '#d1d5db', fontFamily: 'monospace', paddingLeft: '20px', margin: 0, lineHeight: '1.7' }}>
                  <li>
                    Open <strong>Telegram Desktop</strong> → target bot → open the Mini App.
                  </li>
                  <li>
                    Press <code>F12</code> inside the Mini App to open DevTools. Select the{' '}
                    <strong>Network</strong> tab, filter <code>Fetch/XHR</code>.
                  </li>
                  <li>
                    Trigger any action that calls the app backend (e.g. open a page). From a captured request, copy:
                    <ul style={{ paddingLeft: '16px', marginTop: '4px' }}>
                      <li>
                        <strong>Authorization header</strong> (the JWT) → paste into{' '}
                        <em>Auth Token</em> below.
                      </li>
                      <li>
                        <strong>x-wallet-device-serial</strong> (or similar device header) →{' '}
                        paste into <em>Device Serial</em> under{' '}
                        <em>Configure Token Refresh</em>.
                      </li>
                      <li>
                        <strong>initData</strong> — from the request body of the initial{' '}
                        <code>/auth</code>/<code>/me</code> POST, or from the{' '}
                        <code>window.Telegram.WebApp.initData</code> value in the Console tab.
                        Paste into <em>initData</em>.
                      </li>
                    </ul>
                  </li>
                </ol>
                <div style={{ fontSize: '10px', color: '#6b7280', marginTop: '10px', fontStyle: 'italic' }}>
                  Huntress never stores these values in plaintext — they go directly to
                  AES-256-GCM secure storage and are scrubbed from all agent-facing logs.
                </div>
              </div>
            )}

            {/* Instructions — generic path when no Telegram preset applies */}
            {!isTelegramDetected && currentInstructions.length > 0 && (
              <div style={{
                padding: '12px',
                backgroundColor: '#000000',
                border: '1px solid #1f2937',
                borderRadius: '6px',
              }}>
                <div style={{ fontSize: '11px', color: '#6b7280', marginBottom: '8px' }}>
                  SETUP INSTRUCTIONS
                </div>
                {currentInstructions.map((instruction, i) => (
                  <div key={i} style={{
                    fontSize: '12px', color: '#d1d5db', fontFamily: 'monospace',
                    padding: '2px 0',
                  }}>
                    {instruction}
                  </div>
                ))}
              </div>
            )}

            {/* Let Huntress log in (Session 25 Part B) — primary automated path.
                Hidden when Telegram detected since Telegram Mini Apps are not
                automatable (documented in session 25 plan / Part B feasibility). */}
            {!isTelegramDetected && (
              <div
                data-testid="auth-worker-panel"
                style={{
                  padding: '12px',
                  backgroundColor: 'rgba(168, 85, 247, 0.06)',
                  border: '1px solid #7e22ce',
                  borderRadius: '6px',
                }}
              >
                <div style={{ fontSize: '11px', color: '#c084fc', fontWeight: 'bold', marginBottom: '6px' }}>
                  LET HUNTRESS LOG IN FOR YOU
                </div>
                <div style={{ fontSize: '11px', color: '#9ca3af', marginBottom: '10px', lineHeight: '1.5' }}>
                  Huntress drives a headless browser through the login flow for you — no DevTools, no
                  copy-paste. Enter your credentials (used once, never stored in plaintext), then run.
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: '8px' }}>
                  <label style={{ fontSize: '10px', color: '#6b7280' }}>USERNAME</label>
                  <input
                    type="text"
                    value={authUsername}
                    onChange={(e) => setAuthUsername(e.target.value)}
                    placeholder="user@example.com"
                    style={{
                      padding: '6px 8px', backgroundColor: '#0b0b0d', border: '1px solid #1f2937',
                      borderRadius: '4px', color: '#e5e7eb', fontFamily: 'monospace', fontSize: '12px',
                    }}
                  />
                  <label style={{ fontSize: '10px', color: '#6b7280' }}>PASSWORD</label>
                  <input
                    type="password"
                    value={authPassword}
                    onChange={(e) => setAuthPassword(e.target.value)}
                    placeholder="••••••••"
                    style={{
                      padding: '6px 8px', backgroundColor: '#0b0b0d', border: '1px solid #1f2937',
                      borderRadius: '4px', color: '#e5e7eb', fontFamily: 'monospace', fontSize: '12px',
                    }}
                  />
                  <label style={{ fontSize: '10px', color: '#6b7280' }}>TOTP SEED (OPTIONAL, FOR 2FA)</label>
                  <input
                    type="text"
                    value={totpSeed}
                    onChange={(e) => setTotpSeed(e.target.value)}
                    placeholder="base32 seed — leave empty if no 2FA"
                    style={{
                      padding: '6px 8px', backgroundColor: '#0b0b0d', border: '1px solid #1f2937',
                      borderRadius: '4px', color: '#e5e7eb', fontFamily: 'monospace', fontSize: '12px',
                    }}
                  />
                </div>

                <button
                  onClick={handleRunAuthWorker}
                  disabled={workerStatus === 'running'}
                  style={{
                    ...primaryButtonStyle,
                    fontSize: '11px',
                    backgroundColor: workerStatus === 'running' ? '#374151' : '#7e22ce',
                    borderColor: workerStatus === 'running' ? '#374151' : '#7e22ce',
                    opacity: workerStatus === 'running' ? 0.7 : 1,
                  }}
                >
                  {workerStatus === 'running' ? '[RUNNING AUTOMATED LOGIN...]' : '[\u25B6 RUN AUTOMATED LOGIN]'}
                </button>

                {workerMessage && (
                  <div style={{
                    fontSize: '11px',
                    marginTop: '8px',
                    color: workerStatus === 'error' ? '#ef4444'
                      : workerStatus === 'done' ? '#4ade80'
                      : '#9ca3af',
                    fontFamily: 'monospace',
                    whiteSpace: 'pre-wrap',
                  }}>
                    {workerMessage}
                  </div>
                )}
              </div>
            )}

            {/* Or divider */}
            {!isTelegramDetected && (
              <div style={{
                textAlign: 'center', fontSize: '10px', color: '#4b5563',
                textTransform: 'uppercase', letterSpacing: '2px',
              }}>
                — or —
              </div>
            )}

            {/* Supervised Capture from Browser (fallback) */}
            <div style={{
              padding: '12px',
              backgroundColor: 'rgba(59, 130, 246, 0.05)',
              border: '1px solid #1e40af',
              borderRadius: '6px',
            }}>
              <div style={{ fontSize: '11px', color: '#6b7280', marginBottom: '8px' }}>
                SUPERVISED CAPTURE — YOU DRIVE THE BROWSER
              </div>
              <div style={{ fontSize: '11px', color: '#9ca3af', marginBottom: '8px' }}>
                Opens a browser window. Log in normally — tokens and cookies are captured automatically.
                Use this when automated login can't handle the target (captcha, SMS 2FA, unusual flow).
              </div>
              <button
                onClick={handleBrowserCapture}
                disabled={captureStatus === 'capturing'}
                style={{
                  ...secondaryButtonStyle,
                  fontSize: '11px',
                  borderColor: '#1e40af',
                  color: captureStatus === 'capturing' ? '#6b7280' : '#60a5fa',
                }}
              >
                {captureStatus === 'capturing' ? '[CAPTURING...]' : '[SUPERVISED CAPTURE FROM BROWSER]'}
              </button>
              {captureMessage && (
                <div style={{
                  fontSize: '11px',
                  marginTop: '6px',
                  color: captureStatus === 'error' ? '#ef4444'
                    : captureStatus === 'done' ? '#4ade80'
                    : '#9ca3af',
                  fontFamily: 'monospace',
                }}>
                  {captureMessage}
                </div>
              )}
            </div>

            <div style={{
              textAlign: 'center',
              fontSize: '10px',
              color: '#4b5563',
              textTransform: 'uppercase',
              letterSpacing: '2px',
            }}>
              or enter manually
            </div>

            {/* Label */}
            <div>
              <label style={labelStyle}>Profile Label</label>
              <input
                type="text"
                value={authLabel}
                onChange={(e) => setAuthLabel(e.target.value)}
                placeholder="e.g., Telegram User"
                style={inputStyle}
              />
            </div>

            {/* Role — enables multi-identity IDOR/BOLA testing */}
            <div>
              <label style={labelStyle}>Identity Role (optional)</label>
              <select
                value={authRole}
                onChange={(e) => setAuthRole(e.target.value)}
                style={{ ...inputStyle, cursor: 'pointer' }}
              >
                <option value="">(none)</option>
                <option value="victim">victim</option>
                <option value="attacker">attacker</option>
                <option value="admin">admin</option>
                <option value="regular_user">regular_user</option>
              </select>
              <div style={{ fontSize: '11px', color: '#6b7280', marginTop: '4px' }}>
                Agents reference identities via <code>session_label</code> on <code>http_request</code>.
                Create two profiles with different roles (e.g. victim + attacker) to unlock IDOR/BOLA proofs.
              </div>
            </div>

            {/* Auth Type */}
            <div>
              <label style={labelStyle}>Auth Type</label>
              <select
                value={authType}
                onChange={(e) => setAuthType(e.target.value as AuthProfileConfig['authType'])}
                style={{ ...inputStyle, cursor: 'pointer' }}
              >
                <option value="bearer">Bearer Token</option>
                <option value="cookie">Form Login</option>
                <option value="api_key">API Key</option>
                <option value="custom_header">Custom Headers</option>
              </select>
            </div>

            {/* Type-specific fields */}
            {authType === 'bearer' && (
              <>
                <div>
                  <label style={labelStyle}>Bearer Token</label>
                  <input
                    type="password"
                    value={authToken}
                    onChange={(e) => setAuthToken(e.target.value)}
                    placeholder="Paste bearer token..."
                    style={{ ...inputStyle, color: '#4ade80' }}
                  />
                </div>
                <div>
                  <label style={labelStyle}>Validation URL (optional)</label>
                  <input
                    type="text"
                    value={authUrl}
                    onChange={(e) => setAuthUrl(e.target.value)}
                    placeholder="https://api.target.com/me"
                    style={inputStyle}
                  />
                  <div style={hintStyle}>GET request to verify the token works</div>
                </div>
              </>
            )}

            {authType === 'cookie' && (
              <>
                <div>
                  <label style={labelStyle}>Login URL</label>
                  <input
                    type="text"
                    value={authUrl}
                    onChange={(e) => setAuthUrl(e.target.value)}
                    placeholder="https://target.com/login"
                    style={inputStyle}
                  />
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <div style={{ flex: 1 }}>
                    <label style={labelStyle}>Username</label>
                    <input
                      type="text"
                      value={authUsername}
                      onChange={(e) => setAuthUsername(e.target.value)}
                      placeholder="user@example.com"
                      style={inputStyle}
                    />
                  </div>
                  <div style={{ flex: 1 }}>
                    <label style={labelStyle}>Password</label>
                    <input
                      type="password"
                      value={authPassword}
                      onChange={(e) => setAuthPassword(e.target.value)}
                      placeholder="password"
                      style={{ ...inputStyle, color: '#4ade80' }}
                    />
                  </div>
                </div>
              </>
            )}

            {authType === 'api_key' && (
              <>
                <div>
                  <label style={labelStyle}>Header Name</label>
                  <input
                    type="text"
                    value={authHeaderName}
                    onChange={(e) => setAuthHeaderName(e.target.value)}
                    placeholder="X-API-Key"
                    style={inputStyle}
                  />
                </div>
                <div>
                  <label style={labelStyle}>API Key Value</label>
                  <input
                    type="password"
                    value={authApiKeyValue}
                    onChange={(e) => setAuthApiKeyValue(e.target.value)}
                    placeholder="Paste API key..."
                    style={{ ...inputStyle, color: '#4ade80' }}
                  />
                </div>
              </>
            )}

            {authType === 'custom_header' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <label style={labelStyle}>Custom Headers</label>
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
                      style={{ ...inputStyle, flex: 1 }}
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
                      style={{ ...inputStyle, flex: 1, color: '#4ade80' }}
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

            {/* S8: Token Refresh Config — available for ALL auth types */}
            <div style={{
              border: '1px solid #374151',
              borderRadius: '6px',
              overflow: 'hidden',
            }}>
              <button
                onClick={() => setShowRefreshSection(!showRefreshSection)}
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  backgroundColor: '#0a0a0a',
                  border: 'none',
                  color: '#9ca3af',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                  cursor: 'pointer',
                  textAlign: 'left',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <span>ADVANCED: Configure Token Refresh</span>
                <span style={{ color: '#6b7280' }}>{showRefreshSection ? '[-]' : '[+]'}</span>
              </button>
              {showRefreshSection && (
                <div style={{ padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div style={{ fontSize: '10px', color: '#6b7280', lineHeight: '1.5' }}>
                    Configure how tokens are automatically refreshed when they expire during a hunt.
                  </div>

                  {/* Refresh Strategy Selector */}
                  <div>
                    <label style={labelStyle}>Refresh Strategy</label>
                    <select
                      value={refreshStrategy}
                      onChange={(e) => setRefreshStrategy(e.target.value as RefreshStrategy)}
                      style={{ ...inputStyle, cursor: 'pointer' }}
                    >
                      <option value="none">None (no auto-refresh)</option>
                      <option value="initdata_exchange">InitData Exchange (Telegram)</option>
                      <option value="refresh_token">OAuth2 Refresh Token</option>
                      <option value="custom_endpoint">Custom Endpoint</option>
                      {authType === 'cookie' && <option value="re_login">Re-login with Credentials</option>}
                    </select>
                  </div>

                  {/* InitData Exchange fields */}
                  {refreshStrategy === 'initdata_exchange' && (
                    <>
                      <div>
                        <label style={labelStyle}>Auth Endpoint URL</label>
                        <input
                          type="text"
                          value={authEndpointUrl}
                          onChange={(e) => setAuthEndpointUrl(e.target.value)}
                          placeholder="https://target.com/api/auth"
                          style={inputStyle}
                        />
                        <div style={hintStyle}>The URL that exchanges initData for JWT tokens</div>
                      </div>
                      <div>
                        <label style={labelStyle}>initData</label>
                        <textarea
                          value={initDataValue}
                          onChange={(e) => setInitDataValue(e.target.value)}
                          placeholder="query_id=...&user=...&auth_date=...&hash=..."
                          rows={3}
                          style={{ ...inputStyle, resize: 'vertical', minHeight: '60px' }}
                        />
                      </div>
                      <div>
                        <label style={labelStyle}>Device Serial (optional)</label>
                        <input
                          type="text"
                          value={deviceSerial}
                          onChange={(e) => setDeviceSerial(e.target.value)}
                          placeholder="x-wallet-device-serial UUID"
                          style={inputStyle}
                        />
                      </div>
                    </>
                  )}

                  {/* OAuth2 Refresh Token fields */}
                  {refreshStrategy === 'refresh_token' && (
                    <>
                      <div>
                        <label style={labelStyle}>Token Endpoint URL</label>
                        <input
                          type="text"
                          value={tokenEndpointUrl}
                          onChange={(e) => setTokenEndpointUrl(e.target.value)}
                          placeholder="https://target.com/oauth/token"
                          style={inputStyle}
                        />
                      </div>
                      <div>
                        <label style={labelStyle}>Refresh Token</label>
                        <input
                          type="password"
                          value={refreshTokenValue}
                          onChange={(e) => setRefreshTokenValue(e.target.value)}
                          placeholder="Paste refresh token..."
                          style={{ ...inputStyle, color: '#4ade80' }}
                        />
                      </div>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <div style={{ flex: 1 }}>
                          <label style={labelStyle}>Client ID (optional)</label>
                          <input
                            type="text"
                            value={oauthClientId}
                            onChange={(e) => setOauthClientId(e.target.value)}
                            placeholder="client_id"
                            style={inputStyle}
                          />
                        </div>
                        <div style={{ flex: 1 }}>
                          <label style={labelStyle}>Client Secret (optional)</label>
                          <input
                            type="password"
                            value={oauthClientSecret}
                            onChange={(e) => setOauthClientSecret(e.target.value)}
                            placeholder="client_secret"
                            style={{ ...inputStyle, color: '#4ade80' }}
                          />
                        </div>
                      </div>
                      <div>
                        <label style={labelStyle}>Scope (optional)</label>
                        <input
                          type="text"
                          value={oauthScope}
                          onChange={(e) => setOauthScope(e.target.value)}
                          placeholder="openid profile email"
                          style={inputStyle}
                        />
                      </div>
                    </>
                  )}

                  {/* Custom Endpoint fields */}
                  {refreshStrategy === 'custom_endpoint' && (
                    <>
                      <div>
                        <label style={labelStyle}>Refresh Endpoint URL</label>
                        <input
                          type="text"
                          value={refreshEndpointUrl}
                          onChange={(e) => setRefreshEndpointUrl(e.target.value)}
                          placeholder="https://target.com/api/auth/refresh"
                          style={inputStyle}
                        />
                      </div>
                      <div>
                        <label style={labelStyle}>HTTP Method</label>
                        <select
                          value={refreshMethod}
                          onChange={(e) => setRefreshMethod(e.target.value as 'GET' | 'POST')}
                          style={{ ...inputStyle, cursor: 'pointer' }}
                        >
                          <option value="POST">POST</option>
                          <option value="GET">GET</option>
                        </select>
                      </div>
                      {refreshMethod === 'POST' && (
                        <div>
                          <label style={labelStyle}>Request Body (optional)</label>
                          <textarea
                            value={refreshBody}
                            onChange={(e) => setRefreshBody(e.target.value)}
                            placeholder='{"grant_type": "refresh"}'
                            rows={2}
                            style={{ ...inputStyle, resize: 'vertical', minHeight: '40px' }}
                          />
                        </div>
                      )}
                    </>
                  )}

                  {/* Re-login info */}
                  {refreshStrategy === 're_login' && (
                    <div style={{ fontSize: '11px', color: '#9ca3af', padding: '8px', backgroundColor: '#000', borderRadius: '4px' }}>
                      When tokens expire, Huntress will re-login using the stored username/password above.
                    </div>
                  )}

                  {/* Token Header Map — for initdata_exchange and custom_endpoint */}
                  {(refreshStrategy === 'initdata_exchange' || refreshStrategy === 'custom_endpoint') && (
                    <div>
                      <label style={labelStyle}>Token Header Map</label>
                      <textarea
                        value={tokenHeaderMapStr}
                        onChange={(e) => setTokenHeaderMapStr(e.target.value)}
                        placeholder={'data.token=Authorization\ndata.refresh=X-Refresh-Token'}
                        rows={2}
                        style={{ ...inputStyle, resize: 'vertical', minHeight: '40px' }}
                      />
                      <div style={hintStyle}>Map response JSON fields to request headers (field=Header, one per line)</div>
                    </div>
                  )}

                  {/* Token TTL — for all non-none, non-re_login strategies */}
                  {refreshStrategy !== 'none' && refreshStrategy !== 're_login' && (
                    <div>
                      <label style={labelStyle}>Token TTL (seconds)</label>
                      <input
                        type="number"
                        value={tokenTtlSeconds}
                        onChange={(e) => setTokenTtlSeconds(e.target.value)}
                        placeholder="600"
                        style={{ ...inputStyle, width: '120px' }}
                      />
                      <div style={hintStyle}>How long tokens are valid (auto-detected from JWT if possible)</div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Test result */}
            {testStatus !== 'idle' && (
              <div style={{
                fontSize: '11px', padding: '8px', borderRadius: '4px',
                backgroundColor: testStatus === 'success' ? 'rgba(74, 222, 128, 0.1)' : testStatus === 'error' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(251, 191, 36, 0.1)',
                border: `1px solid ${testStatus === 'success' ? '#166534' : testStatus === 'error' ? '#991b1b' : '#92400e'}`,
                color: testStatus === 'success' ? '#4ade80' : testStatus === 'error' ? '#f87171' : '#fbbf24',
              }}>
                {testStatus === 'testing' ? 'Testing...' : testMessage}
              </div>
            )}

            {/* Actions */}
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <button
                onClick={handleTestAuth}
                disabled={testStatus === 'testing'}
                style={secondaryButtonStyle}
              >
                [TEST AUTH]
              </button>
              <button
                onClick={handleSaveProfile}
                disabled={!authLabel.trim() || saving}
                style={{
                  ...primaryButtonStyle,
                  opacity: authLabel.trim() && !saving ? 1 : 0.5,
                  cursor: authLabel.trim() && !saving ? 'pointer' : 'not-allowed',
                }}
              >
                {saving ? '[SAVING...]' : '[SAVE PROFILE]'}
              </button>
            </div>
          </div>
        )}

        {/* Bottom navigation (only when no profiles saved yet) */}
        {savedProfiles.length === 0 && (
          <div style={{ display: 'flex', justifyContent: 'flex-start', marginTop: '8px' }}>
            <button onClick={() => setStep(1)} style={secondaryButtonStyle}>
              [\u2190 BACK]
            </button>
          </div>
        )}
      </div>
    );
  }

  // ─── Step 3: Confirmation ──────────────────────────────────────────────────

  function renderStep3() {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div style={{
          padding: '14px',
          backgroundColor: 'rgba(74, 222, 128, 0.05)',
          border: '1px solid #166534',
          borderRadius: '6px',
        }}>
          <div style={{ fontSize: '14px', fontWeight: 'bold', color: '#4ade80', marginBottom: '8px' }}>
            {savedProfiles.length} auth profile{savedProfiles.length !== 1 ? 's' : ''} configured
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {savedProfiles.map((p, i) => (
              <div key={i} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '8px 12px',
                backgroundColor: '#000000',
                border: '1px solid #1f2937',
                borderRadius: '4px',
              }}>
                <span style={{ fontSize: '12px', color: '#ffffff' }}>{p.label}</span>
                <span style={{ fontSize: '11px', color: '#9ca3af' }}>
                  [{AUTH_TYPE_LABELS[p.authType]}]
                </span>
              </div>
            ))}
          </div>
        </div>

        <div style={{ fontSize: '11px', color: '#6b7280', lineHeight: '1.5' }}>
          Auth sessions will be created automatically when the hunt starts.
          All agents will inject credentials transparently via the HTTP layer.
        </div>

        <div style={{ display: 'flex', gap: '8px', justifyContent: 'space-between', marginTop: '8px' }}>
          <button onClick={() => setStep(2)} style={secondaryButtonStyle}>
            [\u2190 BACK]
          </button>
          <button onClick={onComplete} style={{
            ...primaryButtonStyle,
            backgroundColor: 'rgba(20, 83, 45, 0.5)',
            borderColor: '#15803d',
          }}>
            [START HUNT WITH AUTH]
          </button>
        </div>
      </div>
    );
  }
};

// ─── Probe Result Row ────────────────────────────────────────────────────────

function ProbeResultRow({ probe }: { probe: TargetProbeResult }) {
  const statusColor = probe.error
    ? '#6b7280'
    : probe.authWall
      ? '#ef4444'
      : probe.redirectsToLogin
        ? '#fbbf24'
        : '#4ade80';

  const statusText = probe.error
    ? 'ERROR'
    : probe.status === 401
      ? '401 UNAUTHORIZED'
      : probe.status === 403
        ? '403 FORBIDDEN'
        : probe.redirectsToLogin
          ? `${probe.status} \u2192 LOGIN`
          : probe.hasLoginForm
            ? '200 (LOGIN FORM)'
            : `${probe.status} OK`;

  return (
    <div style={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      padding: '6px 10px',
      backgroundColor: '#000000',
      border: '1px solid #1f2937',
      borderRadius: '4px',
      fontSize: '11px',
    }}>
      <span style={{ color: '#d1d5db', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '350px' }}>
        {probe.url}
      </span>
      <span style={{ color: statusColor, fontWeight: 'bold', flexShrink: 0, marginLeft: '8px' }}>
        [{statusText}]
      </span>
    </div>
  );
}

// ─── Shared Styles ───────────────────────────────────────────────────────────

const inputStyle: React.CSSProperties = {
  width: '100%',
  padding: '6px 10px',
  backgroundColor: '#000000',
  color: '#ffffff',
  border: '1px solid #4b5563',
  borderRadius: '4px',
  fontSize: '12px',
  fontFamily: 'monospace',
  boxSizing: 'border-box',
};

const labelStyle: React.CSSProperties = {
  display: 'block',
  fontSize: '11px',
  color: '#d1d5db',
  marginBottom: '4px',
};

const hintStyle: React.CSSProperties = {
  fontSize: '10px',
  color: '#6b7280',
  marginTop: '2px',
};

const primaryButtonStyle: React.CSSProperties = {
  padding: '8px 16px',
  borderRadius: '4px',
  border: '1px solid #991b1b',
  backgroundColor: 'rgba(153, 27, 27, 0.3)',
  color: '#ef4444',
  cursor: 'pointer',
  fontSize: '12px',
  fontWeight: 'bold',
  fontFamily: 'monospace',
};

const secondaryButtonStyle: React.CSSProperties = {
  padding: '8px 16px',
  borderRadius: '4px',
  border: '1px solid #374151',
  backgroundColor: '#1f2937',
  color: '#d1d5db',
  cursor: 'pointer',
  fontSize: '12px',
  fontFamily: 'monospace',
};

const skipButtonStyle: React.CSSProperties = {
  padding: '8px 16px',
  borderRadius: '4px',
  border: '1px solid #374151',
  backgroundColor: 'transparent',
  color: '#6b7280',
  cursor: 'pointer',
  fontSize: '11px',
  fontFamily: 'monospace',
};

export default AuthWizardModal;

/**
 * SetupWizard
 *
 * First-run setup: select AI provider, paste API key, configure model.
 * Shown before the main app until firstRunComplete is set.
 */

import React, { useState } from 'react';
import { useSettings } from '../contexts/SettingsContext';
import { getProviderFactory } from '../core/providers/provider_factory';

type WizardStep = 'welcome' | 'provider' | 'api_key' | 'agent_model' | 'h1_token' | 'confirm';

const STEPS: WizardStep[] = ['welcome', 'provider', 'api_key', 'agent_model', 'h1_token', 'confirm'];

export const SetupWizard: React.FC = () => {
  const { settings, updateSettings, setApiKey, completeFirstRun } = useSettings();
  const [step, setStep] = useState<WizardStep>('welcome');
  const [selectedProvider, setSelectedProvider] = useState(settings.orchestratorModel.providerId);
  const [selectedModel, setSelectedModel] = useState(settings.orchestratorModel.modelId);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [agentProvider, setAgentProvider] = useState(settings.defaultAgentModel.providerId);
  const [agentModel, setAgentModel] = useState(settings.defaultAgentModel.modelId);
  const [h1Username, setH1Username] = useState('');
  const [h1Token, setH1Token] = useState('');
  const [validating, setValidating] = useState(false);
  const [validationError, setValidationError] = useState('');

  const factory = getProviderFactory();
  const providers = factory.listProviders();

  const currentStepIndex = STEPS.indexOf(step);

  const goNext = () => {
    const nextIndex = currentStepIndex + 1;
    if (nextIndex < STEPS.length) setStep(STEPS[nextIndex]);
  };

  const goBack = () => {
    const prevIndex = currentStepIndex - 1;
    if (prevIndex >= 0) setStep(STEPS[prevIndex]);
  };

  const handleProviderSelect = (providerId: string) => {
    setSelectedProvider(providerId);
    const provider = providers.find(p => p.providerId === providerId);
    if (provider?.models[0]) {
      setSelectedModel(provider.models[0].id);
    }
    setValidationError('');
  };

  const handleValidateAndContinue = async () => {
    if (selectedProvider === 'local') {
      // No API key needed for local models
      goNext();
      return;
    }

    if (!apiKeyInput.trim()) {
      setValidationError('Please enter an API key');
      return;
    }

    setValidating(true);
    setValidationError('');

    try {
      const provider = factory.create(selectedProvider, { apiKey: apiKeyInput });
      const isValid = await provider.validateApiKey(apiKeyInput);
      if (isValid) {
        setApiKey(selectedProvider, apiKeyInput);
        goNext();
      } else {
        setValidationError('Invalid API key. Please check and try again.');
      }
    } catch {
      setValidationError('Could not validate key. Check your connection and try again.');
    } finally {
      setValidating(false);
    }
  };

  const handleComplete = () => {
    updateSettings({
      orchestratorModel: { providerId: selectedProvider, modelId: selectedModel },
      defaultAgentModel: { providerId: agentProvider, modelId: agentModel },
      hackerOneUsername: h1Username,
      hackerOneToken: h1Token,
    });
    completeFirstRun();
  };

  const selectedProviderInfo = providers.find(p => p.providerId === selectedProvider);

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-6">
      <div className="bg-gray-800 rounded-lg border border-gray-700 shadow-2xl max-w-2xl w-full">
        {/* Header */}
        <div className="border-b border-gray-700 p-6">
          <h1 className="text-2xl font-bold">
            <span className="text-red-500">HUNTRESS</span>
            <span className="text-gray-400 text-sm ml-3">Setup</span>
          </h1>
          {/* Progress bar */}
          <div className="flex space-x-1 mt-4">
            {STEPS.map((s, i) => (
              <div
                key={s}
                className={`h-1 flex-1 rounded ${
                  i <= currentStepIndex ? 'bg-red-500' : 'bg-gray-700'
                }`}
              />
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="p-6">
          {step === 'welcome' && (
            <div className="text-center py-8">
              <div className="text-5xl font-bold text-red-500 mb-4">HUNTRESS</div>
              <p className="text-gray-200 text-lg mb-2">AI-Powered Bug Bounty Platform</p>
              <p className="text-gray-300 mb-8">
                Configure your AI model and API keys to get started.
                You can change these settings at any time.
              </p>
              <button
                onClick={goNext}
                className="px-8 py-3 bg-red-600 hover:bg-red-700 text-white rounded-lg font-semibold transition-colors"
              >
                Get Started
              </button>
            </div>
          )}

          {step === 'provider' && (
            <div>
              <h2 className="text-xl font-semibold text-white mb-2">Select AI Provider</h2>
              <p className="text-gray-300 text-sm mb-6">
                Choose your primary AI model. This will power the orchestrator that analyzes targets and coordinates hunts.
              </p>
              <div className="space-y-3">
                {providers.map((provider) => (
                  <button
                    key={provider.providerId}
                    onClick={() => handleProviderSelect(provider.providerId)}
                    className={`w-full text-left p-4 rounded-lg border transition-colors ${
                      selectedProvider === provider.providerId
                        ? 'border-red-500 bg-red-500/10'
                        : 'border-gray-700 bg-gray-900 hover:border-gray-600'
                    }`}
                  >
                    <div className="font-semibold text-white">{provider.displayName}</div>
                    <div className="text-sm text-gray-300 mt-1">
                      {provider.models.map(m => m.displayName).join(', ')}
                    </div>
                    {!provider.requiresApiKey && (
                      <div className="text-xs text-green-400 mt-1">No API key required</div>
                    )}
                  </button>
                ))}
              </div>

              {selectedProviderInfo && (
                <div className="mt-4">
                  <label className="block text-sm font-medium text-gray-300 mb-2">Model</label>
                  <select
                    value={selectedModel}
                    onChange={(e) => setSelectedModel(e.target.value)}
                    className="w-full px-4 py-2 bg-gray-900 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none"
                  >
                    {selectedProviderInfo.models.map(m => (
                      <option key={m.id} value={m.id}>
                        {m.displayName} (ctx: {(m.contextWindow / 1000).toFixed(0)}k)
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>
          )}

          {step === 'api_key' && (
            <div>
              <h2 className="text-xl font-semibold text-white mb-2">
                {selectedProvider === 'local' ? 'Local Model' : 'API Key'}
              </h2>
              {selectedProvider === 'local' ? (
                <div>
                  <p className="text-gray-300 mb-4">
                    Make sure Ollama is running at <code className="text-red-400">localhost:11434</code>.
                    No API key is needed.
                  </p>
                  <div className="bg-gray-900 rounded p-4 text-sm text-gray-300">
                    <code>ollama serve</code>
                  </div>
                </div>
              ) : (
                <div>
                  <p className="text-gray-300 text-sm mb-4">
                    Enter your {selectedProviderInfo?.displayName} API key. It will be stored securely
                    and never shared.
                  </p>
                  <input
                    type="password"
                    value={apiKeyInput}
                    onChange={(e) => { setApiKeyInput(e.target.value); setValidationError(''); }}
                    placeholder="Paste your API key..."
                    className="w-full px-4 py-2 bg-gray-900 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none font-mono"
                    autoFocus
                  />
                  {validationError && (
                    <p className="text-red-400 text-sm mt-2">{validationError}</p>
                  )}
                </div>
              )}
            </div>
          )}

          {step === 'agent_model' && (
            <div>
              <h2 className="text-xl font-semibold text-white mb-2">Sub-Agent Model (Optional)</h2>
              <p className="text-gray-300 text-sm mb-4">
                Choose a model for specialized hunting agents. A cheaper/faster model saves cost
                while the orchestrator handles strategy with the primary model.
              </p>
              <div className="space-y-3">
                <button
                  onClick={() => {
                    setAgentProvider(selectedProvider);
                    setAgentModel(selectedModel);
                  }}
                  className={`w-full text-left p-3 rounded-lg border transition-colors ${
                    agentProvider === selectedProvider && agentModel === selectedModel
                      ? 'border-red-500 bg-red-500/10'
                      : 'border-gray-700 bg-gray-900 hover:border-gray-600'
                  }`}
                >
                  <div className="font-semibold text-white">Same as orchestrator</div>
                  <div className="text-sm text-gray-300">Use {selectedProviderInfo?.displayName} for everything</div>
                </button>

                {selectedProviderInfo?.models.filter(m => m.id !== selectedModel).map(m => (
                  <button
                    key={m.id}
                    onClick={() => {
                      setAgentProvider(selectedProvider);
                      setAgentModel(m.id);
                    }}
                    className={`w-full text-left p-3 rounded-lg border transition-colors ${
                      agentModel === m.id
                        ? 'border-red-500 bg-red-500/10'
                        : 'border-gray-700 bg-gray-900 hover:border-gray-600'
                    }`}
                  >
                    <div className="font-semibold text-white">{m.displayName}</div>
                    <div className="text-sm text-gray-300">
                      ${m.inputCostPer1M}/1M input, ${m.outputCostPer1M}/1M output
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {step === 'h1_token' && (
            <div>
              <h2 className="text-xl font-semibold text-white mb-2">HackerOne API (Optional)</h2>
              <p className="text-gray-300 text-sm mb-4">
                Connect your HackerOne account to import programs and submit reports directly.
                Generate API credentials at{' '}
                <a
                  href="https://hackerone.com/settings/api_token/edit"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-red-400 hover:text-red-300 underline"
                >
                  hackerone.com/settings/api_token
                </a>
              </p>
              <div className="space-y-3">
                <div>
                  <label className="block text-sm font-medium text-gray-200 mb-1">API Identifier</label>
                  <input
                    type="text"
                    value={h1Username}
                    onChange={(e) => setH1Username(e.target.value)}
                    placeholder="Your API identifier (username)..."
                    className="w-full px-4 py-2 bg-gray-900 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none font-mono"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-200 mb-1">API Token</label>
                  <input
                    type="password"
                    value={h1Token}
                    onChange={(e) => setH1Token(e.target.value)}
                    placeholder="Your API token..."
                    className="w-full px-4 py-2 bg-gray-900 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none font-mono"
                  />
                </div>
              </div>
              <p className="text-gray-400 text-xs mt-3">
                Both fields are required for HackerOne integration. Skip if you don't have credentials yet.
              </p>
            </div>
          )}

          {step === 'confirm' && (
            <div>
              <h2 className="text-xl font-semibold text-white mb-4">Ready to Hunt</h2>
              <div className="space-y-3">
                <div className="bg-gray-900 rounded p-4">
                  <div className="text-sm text-gray-300">Orchestrator</div>
                  <div className="text-white font-semibold">
                    {selectedProviderInfo?.displayName} / {selectedProviderInfo?.models.find(m => m.id === selectedModel)?.displayName}
                  </div>
                </div>
                <div className="bg-gray-900 rounded p-4">
                  <div className="text-sm text-gray-300">Sub-Agent Model</div>
                  <div className="text-white font-semibold">
                    {providers.find(p => p.providerId === agentProvider)?.models.find(m => m.id === agentModel)?.displayName ?? agentModel}
                  </div>
                </div>
                <div className="bg-gray-900 rounded p-4">
                  <div className="text-sm text-gray-300">HackerOne API</div>
                  <div className="text-white font-semibold">
                    {h1Username && h1Token
                      ? `Configured (${h1Username})`
                      : 'Not configured (can add later in Settings)'}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="border-t border-gray-700 p-6 flex justify-between">
          {currentStepIndex > 0 ? (
            <button
              onClick={goBack}
              className="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded transition-colors"
            >
              Back
            </button>
          ) : (
            <div />
          )}

          {step !== 'welcome' && step !== 'confirm' && (
            <button
              onClick={step === 'api_key' ? handleValidateAndContinue : goNext}
              disabled={validating}
              className="px-6 py-2 bg-red-600 hover:bg-red-700 text-white rounded font-semibold transition-colors disabled:bg-gray-600"
            >
              {validating ? 'Validating...' : 'Continue'}
            </button>
          )}

          {step === 'confirm' && (
            <button
              onClick={handleComplete}
              className="px-8 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg font-semibold transition-colors"
            >
              Launch Huntress
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default SetupWizard;

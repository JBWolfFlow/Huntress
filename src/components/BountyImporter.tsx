/**
 * BountyImporter
 *
 * Enhanced import modal wrapping GuidelinesImporter.
 * Adds JSON file upload, visual scope breakdown, and drag-and-drop support.
 */

import React, { useState, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import type { ProgramGuidelines } from './GuidelinesImporter';
import { useSettings } from '../contexts/SettingsContext';

interface BountyImporterProps {
  onImport: (guidelines: ProgramGuidelines) => void;
  onClose?: () => void;
}

type ImportMode = 'url' | 'file' | 'manual';

export const BountyImporter: React.FC<BountyImporterProps> = ({ onImport, onClose }) => {
  const { settings } = useSettings();
  const [mode, setMode] = useState<ImportMode>('url');
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<ProgramGuidelines | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [huntBudget, setHuntBudget] = useState(settings.budgetLimitUsd ?? 15);

  const [manualForm, setManualForm] = useState({
    programName: '',
    inScope: '',
    outOfScope: '',
    rules: '',
    bountyMin: '',
    bountyMax: '',
  });

  const extractProgramHandle = (urlString: string): string | null => {
    try {
      const cleanUrl = urlString.split('?')[0];
      const match = cleanUrl.match(/hackerone\.com\/(?:programs\/)?([a-zA-Z0-9_-]+)/);
      return match ? match[1] : null;
    } catch {
      return null;
    }
  };

  const handleUrlImport = useCallback(async () => {
    setLoading(true);
    setError(null);
    setPreview(null);

    try {
      const programHandle = extractProgramHandle(url);
      if (!programHandle) {
        throw new Error('Invalid HackerOne URL. Use format: https://hackerone.com/program-name');
      }

      const result = await invoke<Record<string, unknown>>('fetch_h1_program', {
        programHandle,
        apiUsername: settings.hackerOneUsername || null,
        apiToken: settings.hackerOneToken || null,
      });

      const scope = result.scope as Record<string, string[]>;
      const bountyRange = result.bounty_range as Record<string, number>;
      const severity = result.severity as Record<string, string | undefined>;

      const guidelines: ProgramGuidelines = {
        programHandle: result.program_handle as string,
        programName: result.program_name as string,
        url: result.url as string,
        scope: {
          inScope: scope.in_scope,
          outOfScope: scope.out_of_scope,
        },
        rules: result.rules as string[],
        bountyRange: { min: bountyRange.min, max: bountyRange.max },
        responseTime: result.response_time as string | undefined,
        severity: {
          critical: severity.critical,
          high: severity.high,
          medium: severity.medium,
          low: severity.low,
        },
        importedAt: new Date(),
      };

      setPreview(guidelines);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch program');
    } finally {
      setLoading(false);
    }
  }, [url]);

  const handleFileUpload = useCallback(
    async (file: File) => {
      setLoading(true);
      setError(null);
      setPreview(null);

      try {
        const text = await file.text();
        const data = JSON.parse(text);

        // Support HackerOne scope JSON format
        const guidelines: ProgramGuidelines = {
          programHandle: data.handle || data.programHandle || file.name.replace('.json', ''),
          programName: data.name || data.programName || file.name.replace('.json', ''),
          url: data.url || 'file-upload',
          scope: {
            inScope: data.scope?.in_scope || data.scope?.inScope || data.targets?.in_scope?.map((t: Record<string, string>) => t.asset_identifier) || [],
            outOfScope: data.scope?.out_of_scope || data.scope?.outOfScope || data.targets?.out_of_scope?.map((t: Record<string, string>) => t.asset_identifier) || [],
          },
          rules: data.rules || data.policy || [],
          bountyRange: {
            min: data.bounty_range?.min || data.bountyRange?.min || 0,
            max: data.bounty_range?.max || data.bountyRange?.max || 0,
          },
          severity: data.severity || {},
          importedAt: new Date(),
        };

        setPreview(guidelines);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to parse JSON file');
      } finally {
        setLoading(false);
      }
    },
    []
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files[0];
      if (file && file.name.endsWith('.json')) {
        handleFileUpload(file);
      } else {
        setError('Please drop a .json file');
      }
    },
    [handleFileUpload]
  );

  const handleManualImport = useCallback(() => {
    const guidelines: ProgramGuidelines = {
      programHandle: manualForm.programName.toLowerCase().replace(/\s+/g, '-'),
      programName: manualForm.programName,
      url: 'manual-entry',
      scope: {
        inScope: manualForm.inScope.split('\n').filter(Boolean),
        outOfScope: manualForm.outOfScope.split('\n').filter(Boolean),
      },
      rules: manualForm.rules.split('\n').filter(Boolean),
      bountyRange: {
        min: parseInt(manualForm.bountyMin) || 0,
        max: parseInt(manualForm.bountyMax) || 0,
      },
      severity: {},
      importedAt: new Date(),
    };
    setPreview(guidelines);
  }, [manualForm]);

  const confirmImport = useCallback(() => {
    if (preview) {
      onImport({ ...preview, huntBudgetUsd: huntBudget });
    }
  }, [preview, huntBudget, onImport]);

  const inputClasses =
    'w-full px-4 py-2 bg-gray-900 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none';

  const budgetInput = (
    <div className="mt-4 pt-4 border-t border-gray-700">
      <label className="block text-sm font-medium text-gray-300 mb-2">
        Hunt Budget (USD)
      </label>
      <div className="flex items-center gap-3">
        <span className="text-gray-400 text-lg font-mono">$</span>
        <input
          type="range"
          min={1}
          max={100}
          step={1}
          value={huntBudget}
          onChange={(e) => setHuntBudget(Number(e.target.value))}
          className="flex-1 accent-red-500 h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer"
        />
        <input
          type="number"
          min={1}
          max={500}
          step={1}
          value={huntBudget}
          onChange={(e) => {
            const val = Number(e.target.value);
            if (val > 0) setHuntBudget(val);
          }}
          className="w-20 px-2 py-1 bg-gray-800 text-white text-right rounded border border-gray-700 focus:border-red-500 focus:outline-none font-mono text-lg"
        />
      </div>
      <div className="flex justify-between mt-1 text-[10px] text-gray-500">
        <span>Warning at ${Math.round(huntBudget * 0.8)}</span>
        <span>Hard stop at ${huntBudget}</span>
      </div>
    </div>
  );

  return (
    <div className="bg-gray-800 rounded-lg max-w-2xl w-full max-h-[85vh] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700">
        <h2 className="text-lg font-bold text-white">Import Bounty Program</h2>
        {onClose && (
          <button onClick={onClose} className="text-gray-400 hover:text-white text-lg">
            &times;
          </button>
        )}
      </div>

      {/* Mode tabs */}
      <div className="flex border-b border-gray-700">
        {(['url', 'file', 'manual'] as ImportMode[]).map((m) => (
          <button
            key={m}
            onClick={() => {
              setMode(m);
              setError(null);
              setPreview(null);
            }}
            className={`flex-1 px-4 py-2.5 text-sm font-medium transition-colors ${
              mode === m
                ? 'text-white border-b-2 border-red-500'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            {m === 'url' ? 'HackerOne URL' : m === 'file' ? 'JSON Upload' : 'Manual Entry'}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6">
        {/* Preview state */}
        {preview ? (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-white">{preview.programName}</h3>
              <button
                onClick={() => setPreview(null)}
                className="text-xs text-gray-400 hover:text-white"
              >
                Back
              </button>
            </div>

            {/* Stats row */}
            <div className="grid grid-cols-3 gap-3">
              <div className="bg-gray-900 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-green-400">
                  ${preview.bountyRange.min.toLocaleString()} - $
                  {preview.bountyRange.max.toLocaleString()}
                </p>
                <p className="text-[10px] text-gray-400 uppercase mt-1">Bounty Range</p>
              </div>
              <div className="bg-gray-900 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-white">{preview.scope.inScope.length}</p>
                <p className="text-[10px] text-gray-400 uppercase mt-1">In Scope</p>
              </div>
              <div className="bg-gray-900 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-gray-400">
                  {preview.scope.outOfScope.length}
                </p>
                <p className="text-[10px] text-gray-400 uppercase mt-1">Out of Scope</p>
              </div>
            </div>

            {/* In-scope targets */}
            {preview.scope.inScope.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-gray-400 uppercase mb-1">In Scope</p>
                <div className="bg-gray-900 rounded-lg p-3 space-y-1 max-h-32 overflow-y-auto">
                  {preview.scope.inScope.map((target, i) => (
                    <p key={i} className="text-sm text-green-400 font-mono">
                      {target}
                    </p>
                  ))}
                </div>
              </div>
            )}

            {/* Out-of-scope targets */}
            {preview.scope.outOfScope.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-gray-400 uppercase mb-1">Out of Scope</p>
                <div className="bg-gray-900 rounded-lg p-3 space-y-1 max-h-24 overflow-y-auto">
                  {preview.scope.outOfScope.map((target, i) => (
                    <p key={i} className="text-sm text-red-400 font-mono">
                      {target}
                    </p>
                  ))}
                </div>
              </div>
            )}

            {/* Hunt Budget */}
            <div>
              <label className="block text-xs font-semibold text-gray-400 uppercase mb-1">
                Hunt Budget (USD)
              </label>
              <div className="bg-gray-900 rounded-lg p-3">
                <div className="flex items-center gap-3">
                  <span className="text-gray-400 text-lg font-mono">$</span>
                  <input
                    type="range"
                    min={1}
                    max={100}
                    step={1}
                    value={huntBudget}
                    onChange={(e) => setHuntBudget(Number(e.target.value))}
                    className="flex-1 accent-red-500 h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer"
                  />
                  <input
                    type="number"
                    min={1}
                    max={500}
                    step={1}
                    value={huntBudget}
                    onChange={(e) => {
                      const val = Number(e.target.value);
                      if (val > 0) setHuntBudget(val);
                    }}
                    className="w-20 px-2 py-1 bg-gray-800 text-white text-right rounded border border-gray-700 focus:border-red-500 focus:outline-none font-mono text-lg"
                  />
                </div>
                <div className="flex justify-between mt-2 text-[10px] text-gray-500">
                  <span>Warning at ${Math.round(huntBudget * 0.8)}</span>
                  <span>Hard stop at ${huntBudget}</span>
                </div>
              </div>
            </div>

            {/* Rules */}
            {preview.rules.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-gray-400 uppercase mb-1">Rules</p>
                <div className="bg-gray-900 rounded-lg p-3 space-y-1 max-h-24 overflow-y-auto">
                  {preview.rules.map((rule, i) => (
                    <p key={i} className="text-sm text-gray-300">
                      &bull; {rule}
                    </p>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <>
            {/* URL mode */}
            {mode === 'url' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    HackerOne Program URL
                  </label>
                  <div className="flex space-x-2">
                    <input
                      type="text"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder="https://hackerone.com/program-name"
                      className={`flex-1 ${inputClasses}`}
                      disabled={loading}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') handleUrlImport();
                      }}
                    />
                    <button
                      onClick={handleUrlImport}
                      disabled={loading || !url}
                      className="px-6 py-2 bg-red-600 text-white rounded hover:bg-red-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
                    >
                      {loading ? 'Fetching...' : 'Fetch'}
                    </button>
                  </div>
                  <p className="text-xs text-gray-400 mt-2">
                    Example: https://hackerone.com/security
                  </p>
                </div>
                {budgetInput}
              </div>
            )}

            {/* File upload mode */}
            {mode === 'file' && (
              <div className="space-y-4">
                <div
                  onDragOver={(e) => {
                    e.preventDefault();
                    setDragOver(true);
                  }}
                  onDragLeave={() => setDragOver(false)}
                  onDrop={handleDrop}
                  onClick={() => fileInputRef.current?.click()}
                  className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${
                    dragOver
                      ? 'border-red-500 bg-red-900/10'
                      : 'border-gray-600 hover:border-gray-500'
                  }`}
                >
                  <p className="text-sm text-gray-300 mb-1">
                    Drop a scope JSON file here, or click to browse
                  </p>
                  <p className="text-xs text-gray-400">
                    Supports HackerOne scope JSON format
                  </p>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".json"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) handleFileUpload(file);
                    }}
                  />
                </div>
                {budgetInput}
              </div>
            )}

            {/* Manual entry mode */}
            {mode === 'manual' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Program Name
                  </label>
                  <input
                    type="text"
                    value={manualForm.programName}
                    onChange={(e) => setManualForm({ ...manualForm, programName: e.target.value })}
                    placeholder="Example Security Program"
                    className={inputClasses}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    In-Scope Targets (one per line)
                  </label>
                  <textarea
                    value={manualForm.inScope}
                    onChange={(e) => setManualForm({ ...manualForm, inScope: e.target.value })}
                    placeholder={"*.example.com\napi.example.com"}
                    rows={3}
                    className={`${inputClasses} font-mono text-sm`}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Out-of-Scope (one per line)
                  </label>
                  <textarea
                    value={manualForm.outOfScope}
                    onChange={(e) => setManualForm({ ...manualForm, outOfScope: e.target.value })}
                    placeholder={"staging.example.com"}
                    rows={2}
                    className={`${inputClasses} font-mono text-sm`}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Program Rules (one per line)
                  </label>
                  <textarea
                    value={manualForm.rules}
                    onChange={(e) => setManualForm({ ...manualForm, rules: e.target.value })}
                    placeholder={"No social engineering\nNo DoS attacks"}
                    rows={3}
                    className={`${inputClasses} text-sm`}
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">
                      Min Bounty ($)
                    </label>
                    <input
                      type="number"
                      value={manualForm.bountyMin}
                      onChange={(e) =>
                        setManualForm({ ...manualForm, bountyMin: e.target.value })
                      }
                      placeholder="100"
                      className={inputClasses}
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">
                      Max Bounty ($)
                    </label>
                    <input
                      type="number"
                      value={manualForm.bountyMax}
                      onChange={(e) =>
                        setManualForm({ ...manualForm, bountyMax: e.target.value })
                      }
                      placeholder="10000"
                      className={inputClasses}
                    />
                  </div>
                </div>
                {budgetInput}
                <button
                  onClick={handleManualImport}
                  disabled={!manualForm.programName || !manualForm.inScope}
                  className="w-full mt-4 px-4 py-2.5 bg-red-600 text-white rounded hover:bg-red-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors font-semibold"
                >
                  Preview Import
                </button>
              </div>
            )}
          </>
        )}

        {/* Error display */}
        {error && (
          <div className="mt-4 p-3 bg-red-900/30 border border-red-500/50 rounded">
            <p className="text-red-400 text-sm">{error}</p>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-700">
        {onClose && (
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
        )}
        <button
          onClick={confirmImport}
          disabled={!preview}
          className="px-6 py-2 bg-red-600 text-white rounded hover:bg-red-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors font-semibold text-sm"
        >
          Import Program
        </button>
      </div>
    </div>
  );
};

export default BountyImporter;

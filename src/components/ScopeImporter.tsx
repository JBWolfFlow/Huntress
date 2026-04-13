/**
 * Scope Importer Component
 *
 * Allows importing scope from HackerOne or manual entry
 */

import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useScope } from '../hooks/useTauriCommands';
import { useSettings } from '../contexts/SettingsContext';

export interface ScopeEntry {
  target: string;
  inScope: boolean;
  notes?: string;
}

interface ScopeImporterProps {
  onImport: (scope: ScopeEntry[]) => void;
}

/** Extract a program handle from a HackerOne URL or bare handle string. */
export function extractH1Handle(input: string): string | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  // If it looks like a URL, parse the handle from it
  if (trimmed.includes('hackerone.com')) {
    const cleanUrl = trimmed.split('?')[0];
    const match = cleanUrl.match(/hackerone\.com\/(?:programs\/)?([a-zA-Z0-9_-]+)/);
    return match ? match[1] : null;
  }

  // Bare handle — validate it looks reasonable (alphanumeric, dashes, underscores)
  if (/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
    return trimmed;
  }

  return null;
}

/** Fetch scope entries from HackerOne via Tauri backend, returns in-scope and out-of-scope entries. */
export async function fetchH1Scope(
  programHandle: string,
  apiUsername: string | null,
  apiToken: string | null,
): Promise<ScopeEntry[]> {
  const result = await invoke<Record<string, unknown>>('fetch_h1_program', {
    programHandle,
    apiUsername: apiUsername || null,
    apiToken: apiToken || null,
  });

  const scope = result.scope as Record<string, string[]>;
  const inScopeTargets: string[] = scope?.in_scope ?? [];
  const outOfScopeTargets: string[] = scope?.out_of_scope ?? [];

  const entries: ScopeEntry[] = [
    ...inScopeTargets.map((target) => ({
      target,
      inScope: true,
      notes: 'Imported from HackerOne',
    })),
    ...outOfScopeTargets.map((target) => ({
      target,
      inScope: false,
      notes: 'Out of scope (HackerOne)',
    })),
  ];

  return entries;
}

export const ScopeImporter: React.FC<ScopeImporterProps> = ({ onImport }) => {
  const { settings } = useSettings();
  const [programHandle, setProgramHandle] = useState('');
  const [manualScope, setManualScope] = useState('');
  const [validating, setValidating] = useState(false);
  const [h1Loading, setH1Loading] = useState(false);
  const [h1Error, setH1Error] = useState<string | null>(null);
  const { loadScope, validateTarget, loading, error } = useScope();

  const handleH1Import = async () => {
    const handle = extractH1Handle(programHandle);
    if (!handle) {
      setH1Error('Invalid program handle. Enter a handle (e.g. "security") or URL (e.g. "https://hackerone.com/security").');
      return;
    }

    setH1Loading(true);
    setH1Error(null);

    try {
      const entries = await fetchH1Scope(
        handle,
        settings.hackerOneUsername ?? null,
        settings.hackerOneToken ?? null,
      );

      if (entries.length === 0) {
        setH1Error(`No scope entries found for program "${handle}". The program may not exist or has no published scope.`);
        return;
      }

      onImport(entries);
      setProgramHandle('');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setH1Error(`Failed to fetch scope for "${handle}": ${msg}`);
    } finally {
      setH1Loading(false);
    }
  };

  const handleManualImport = async () => {
    const lines = manualScope.split('\n').filter(line => line.trim());
    
    if (lines.length === 0) {
      alert('Please enter at least one target');
      return;
    }

    setValidating(true);
    try {
      // Validate each target
      const validatedScope: ScopeEntry[] = [];
      
      for (const line of lines) {
        const target = line.trim();
        try {
          const result = await validateTarget(target);
          validatedScope.push({
            target: result.target,
            inScope: result.inScope,
            notes: result.reason
          });
        } catch (err) {
          // If validation fails, add as out-of-scope
          validatedScope.push({
            target,
            inScope: false,
            notes: 'Validation failed'
          });
        }
      }
      
      onImport(validatedScope);
      setManualScope(''); // Clear input after successful import
    } catch (err) {
      console.error('Error validating scope:', err);
      alert('Failed to validate scope: ' + (err instanceof Error ? err.message : String(err)));
    } finally {
      setValidating(false);
    }
  };

  return (
    <div className="scope-importer p-4">
      <h3 className="text-xl font-bold mb-4">Import Scope</h3>

      {error && (
        <div className="mb-4 p-3 bg-red-900 border border-red-700 rounded text-red-200">
          <strong>Error:</strong> {error}
        </div>
      )}

      {h1Error && (
        <div className="mb-4 p-3 bg-red-900 border border-red-700 rounded text-red-200">
          <strong>H1 Import Error:</strong> {h1Error}
        </div>
      )}

      <div className="mb-6">
        <label className="block mb-2 font-semibold text-gray-300">
          HackerOne Program Handle or URL
        </label>
        <div className="flex space-x-2">
          <input
            type="text"
            value={programHandle}
            onChange={(e) => {
              setProgramHandle(e.target.value);
              if (h1Error) setH1Error(null);
            }}
            placeholder="security or https://hackerone.com/security"
            className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
            disabled={loading || validating || h1Loading}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && programHandle.trim()) handleH1Import();
            }}
          />
          <button
            onClick={handleH1Import}
            disabled={loading || validating || h1Loading || !programHandle.trim()}
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
          >
            {h1Loading ? 'Importing...' : 'Import from H1'}
          </button>
        </div>
        <p className="text-xs text-gray-400 mt-1">
          Enter a program handle (e.g. security) or full URL (e.g. https://hackerone.com/security)
        </p>
      </div>

      <div className="mb-6">
        <label className="block mb-2 font-semibold text-gray-300">
          Manual Scope Entry (one per line)
        </label>
        <textarea
          value={manualScope}
          onChange={(e) => setManualScope(e.target.value)}
          placeholder="*.example.com&#10;api.example.com&#10;example.com"
          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded h-32 text-white placeholder-gray-400 focus:outline-none focus:border-green-500 font-mono text-sm"
          disabled={loading || validating}
        />
        <button
          onClick={handleManualImport}
          disabled={loading || validating || !manualScope.trim()}
          className="mt-2 px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
        >
          {validating ? '🔄 Validating...' : '✅ Import Manual Scope'}
        </button>
      </div>
    </div>
  );
};

export default ScopeImporter;
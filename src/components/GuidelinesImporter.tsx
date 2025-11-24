/**
 * Guidelines Importer Component
 * 
 * Allows importing HackerOne program guidelines by URL or manual entry.
 * Fetches program details, scope, and rules to inform AI agents.
 */

import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

export interface ProgramGuidelines {
  programHandle: string;
  programName: string;
  url: string;
  scope: {
    inScope: string[];
    outOfScope: string[];
  };
  rules: string[];
  bountyRange: {
    min: number;
    max: number;
  };
  responseTime?: string;
  severity: {
    critical?: string;
    high?: string;
    medium?: string;
    low?: string;
  };
  importedAt: Date;
}

interface GuidelinesImporterProps {
  onImport: (guidelines: ProgramGuidelines) => void;
}

export const GuidelinesImporter: React.FC<GuidelinesImporterProps> = ({ onImport }) => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [manualMode, setManualMode] = useState(false);
  const [manualGuidelines, setManualGuidelines] = useState({
    programName: '',
    inScope: '',
    outOfScope: '',
    rules: '',
    bountyMin: '',
    bountyMax: '',
  });

  const extractProgramHandle = (urlString: string): string | null => {
    try {
      // Remove query parameters first
      const cleanUrl = urlString.split('?')[0];
      
      // Extract from URLs like:
      // https://hackerone.com/security
      // https://hackerone.com/programs/security
      // https://hackerone.com/bookingcom
      const match = cleanUrl.match(/hackerone\.com\/(?:programs\/)?([a-zA-Z0-9_-]+)/);
      return match ? match[1] : null;
    } catch {
      return null;
    }
  };

  const fetchProgramGuidelines = async (programHandle: string): Promise<ProgramGuidelines> => {
    // Use Tauri backend command to bypass CORS restrictions
    try {
      const result = await invoke<any>('fetch_h1_program', {
        programHandle
      });
      
      // Convert snake_case from Rust to camelCase for TypeScript
      return {
        programHandle: result.program_handle,
        programName: result.program_name,
        url: result.url,
        scope: {
          inScope: result.scope.in_scope,
          outOfScope: result.scope.out_of_scope,
        },
        rules: result.rules,
        bountyRange: {
          min: result.bounty_range.min,
          max: result.bounty_range.max,
        },
        responseTime: result.response_time,
        severity: {
          critical: result.severity.critical,
          high: result.severity.high,
          medium: result.severity.medium,
          low: result.severity.low,
        },
        importedAt: new Date(),
      };
    } catch (error) {
      console.error('Failed to fetch program from backend:', error);
      throw new Error(
        `Failed to fetch program "${programHandle}" from HackerOne. ` +
        `Error: ${error instanceof Error ? error.message : String(error)}. ` +
        `Please try Manual Entry mode.`
      );
    }
  };

  const handleUrlImport = async () => {
    setLoading(true);
    setError(null);

    try {
      const programHandle = extractProgramHandle(url);
      
      if (!programHandle) {
        throw new Error('Invalid HackerOne URL. Please use format: https://hackerone.com/program-name');
      }

      const guidelines = await fetchProgramGuidelines(programHandle);
      onImport(guidelines);
      setUrl('');
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to fetch program guidelines';
      setError(errorMsg);
      console.error('Guidelines import error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleManualImport = () => {
    const guidelines: ProgramGuidelines = {
      programHandle: manualGuidelines.programName.toLowerCase().replace(/\s+/g, '-'),
      programName: manualGuidelines.programName,
      url: url || 'manual-entry',
      scope: {
        inScope: manualGuidelines.inScope.split('\n').filter(Boolean),
        outOfScope: manualGuidelines.outOfScope.split('\n').filter(Boolean),
      },
      rules: manualGuidelines.rules.split('\n').filter(Boolean),
      bountyRange: {
        min: parseInt(manualGuidelines.bountyMin) || 0,
        max: parseInt(manualGuidelines.bountyMax) || 0,
      },
      severity: {},
      importedAt: new Date(),
    };

    onImport(guidelines);
    setManualGuidelines({
      programName: '',
      inScope: '',
      outOfScope: '',
      rules: '',
      bountyMin: '',
      bountyMax: '',
    });
    setManualMode(false);
  };

  return (
    <div className="guidelines-importer bg-gray-800 rounded-lg p-6">
      <h3 className="text-xl font-bold text-white mb-4">
        📋 Import Program Guidelines
      </h3>

      <div className="mb-4">
        <div className="flex space-x-2 mb-4">
          <button
            onClick={() => setManualMode(false)}
            className={`px-4 py-2 rounded transition-colors ${
              !manualMode
                ? 'bg-red-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            URL Import
          </button>
          <button
            onClick={() => setManualMode(true)}
            className={`px-4 py-2 rounded transition-colors ${
              manualMode
                ? 'bg-red-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            Manual Entry
          </button>
        </div>

        {!manualMode ? (
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
                className="flex-1 px-4 py-2 bg-gray-900 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none"
                disabled={loading}
              />
              <button
                onClick={handleUrlImport}
                disabled={loading || !url}
                className="px-6 py-2 bg-red-600 text-white rounded hover:bg-red-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? 'Importing...' : 'Import'}
              </button>
            </div>
            <p className="text-xs text-gray-400 mt-2">
              Example: https://hackerone.com/security or https://hackerone.com/bookingcom
            </p>
            <p className="text-xs text-green-400 mt-1">
              ✅ Using Tauri backend to bypass CORS restrictions
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Program Name
              </label>
              <input
                type="text"
                value={manualGuidelines.programName}
                onChange={(e) => setManualGuidelines({ ...manualGuidelines, programName: e.target.value })}
                placeholder="Example Security Program"
                className="w-full px-4 py-2 bg-gray-900 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                In-Scope Targets (one per line)
              </label>
              <textarea
                value={manualGuidelines.inScope}
                onChange={(e) => setManualGuidelines({ ...manualGuidelines, inScope: e.target.value })}
                placeholder="*.example.com&#10;api.example.com&#10;app.example.com"
                rows={4}
                className="w-full px-4 py-2 bg-gray-900 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none font-mono text-sm"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Out-of-Scope Targets (one per line)
              </label>
              <textarea
                value={manualGuidelines.outOfScope}
                onChange={(e) => setManualGuidelines({ ...manualGuidelines, outOfScope: e.target.value })}
                placeholder="test.example.com&#10;staging.example.com"
                rows={3}
                className="w-full px-4 py-2 bg-gray-900 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none font-mono text-sm"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Program Rules (one per line)
              </label>
              <textarea
                value={manualGuidelines.rules}
                onChange={(e) => setManualGuidelines({ ...manualGuidelines, rules: e.target.value })}
                placeholder="No social engineering&#10;No DoS attacks&#10;Report duplicates will be closed"
                rows={4}
                className="w-full px-4 py-2 bg-gray-900 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none text-sm"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Min Bounty ($)
                </label>
                <input
                  type="number"
                  value={manualGuidelines.bountyMin}
                  onChange={(e) => setManualGuidelines({ ...manualGuidelines, bountyMin: e.target.value })}
                  placeholder="100"
                  className="w-full px-4 py-2 bg-gray-900 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Max Bounty ($)
                </label>
                <input
                  type="number"
                  value={manualGuidelines.bountyMax}
                  onChange={(e) => setManualGuidelines({ ...manualGuidelines, bountyMax: e.target.value })}
                  placeholder="10000"
                  className="w-full px-4 py-2 bg-gray-900 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none"
                />
              </div>
            </div>

            <button
              onClick={handleManualImport}
              disabled={!manualGuidelines.programName || !manualGuidelines.inScope}
              className="w-full px-6 py-3 bg-red-600 text-white rounded hover:bg-red-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors font-semibold"
            >
              Import Guidelines
            </button>
          </div>
        )}
      </div>

      {error && (
        <div className="mt-4 p-4 bg-red-900/30 border border-red-500 rounded">
          <p className="text-red-400 text-sm">
            <span className="font-semibold">Error:</span> {error}
          </p>
          <p className="text-red-300 text-xs mt-2">
            Try using manual entry mode if the URL import fails.
          </p>
        </div>
      )}

      <div className="mt-4 p-4 bg-blue-900/20 border border-blue-500/30 rounded">
        <p className="text-blue-300 text-sm">
          <span className="font-semibold">💡 Tip:</span> Guidelines help the AI understand program scope, rules, and bounty ranges to make better decisions.
        </p>
      </div>
    </div>
  );
};

export default GuidelinesImporter;
/**
 * Scope Importer Component
 *
 * Allows importing scope from HackerOne or manual entry
 */

import React, { useState } from 'react';
import { useScope } from '../hooks/useTauriCommands';

interface ScopeEntry {
  target: string;
  inScope: boolean;
  notes?: string;
}

interface ScopeImporterProps {
  onImport: (scope: ScopeEntry[]) => void;
}

export const ScopeImporter: React.FC<ScopeImporterProps> = ({ onImport }) => {
  const [programHandle, setProgramHandle] = useState('');
  const [manualScope, setManualScope] = useState('');
  const [validating, setValidating] = useState(false);
  const { loadScope, validateTarget, loading, error } = useScope();

  const handleH1Import = async () => {
    // TODO: Implement HackerOne API scope import
    console.log('Importing from H1:', programHandle);
    alert('HackerOne import coming soon!');
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

      <div className="mb-6">
        <label className="block mb-2 font-semibold text-gray-300">
          HackerOne Program Handle
        </label>
        <div className="flex space-x-2">
          <input
            type="text"
            value={programHandle}
            onChange={(e) => setProgramHandle(e.target.value)}
            placeholder="program-handle"
            className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
            disabled={loading || validating}
          />
          <button
            onClick={handleH1Import}
            disabled={loading || validating || !programHandle}
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Loading...' : 'Import from H1'}
          </button>
        </div>
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
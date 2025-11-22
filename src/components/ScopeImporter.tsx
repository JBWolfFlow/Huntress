/**
 * Scope Importer Component
 * 
 * Allows importing scope from HackerOne or manual entry
 */

import React, { useState } from 'react';

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

  const handleH1Import = async () => {
    // TODO: Implement HackerOne API scope import
    console.log('Importing from H1:', programHandle);
  };

  const handleManualImport = () => {
    const lines = manualScope.split('\n').filter(line => line.trim());
    const scope: ScopeEntry[] = lines.map(line => ({
      target: line.trim(),
      inScope: true,
    }));
    onImport(scope);
  };

  return (
    <div className="scope-importer p-4">
      <h3 className="text-xl font-bold mb-4">Import Scope</h3>

      <div className="mb-6">
        <label className="block mb-2 font-semibold">
          HackerOne Program Handle
        </label>
        <div className="flex space-x-2">
          <input
            type="text"
            value={programHandle}
            onChange={(e) => setProgramHandle(e.target.value)}
            placeholder="program-handle"
            className="flex-1 px-3 py-2 border rounded"
          />
          <button
            onClick={handleH1Import}
            className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
          >
            Import from H1
          </button>
        </div>
      </div>

      <div className="mb-6">
        <label className="block mb-2 font-semibold">
          Manual Scope Entry (one per line)
        </label>
        <textarea
          value={manualScope}
          onChange={(e) => setManualScope(e.target.value)}
          placeholder="*.example.com&#10;api.example.com&#10;example.com"
          className="w-full px-3 py-2 border rounded h-32"
        />
        <button
          onClick={handleManualImport}
          className="mt-2 px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600"
        >
          Import Manual Scope
        </button>
      </div>
    </div>
  );
};

export default ScopeImporter;
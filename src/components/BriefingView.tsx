/**
 * BriefingView
 *
 * Standalone component for displaying a program briefing.
 * Used in the import flow before the briefing appears in chat.
 */

import React from 'react';
import type { ProgramGuidelines } from './GuidelinesImporter';

interface BriefingViewProps {
  guidelines: ProgramGuidelines;
  onStartHunt: () => void;
}

export const BriefingView: React.FC<BriefingViewProps> = ({ guidelines, onStartHunt }) => {
  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
      <div className="px-6 py-4 bg-red-900/20 border-b border-gray-700">
        <h2 className="text-xl font-bold text-white">{guidelines.programName}</h2>
        <a
          href={guidelines.url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm text-red-400 hover:text-red-300"
        >
          {guidelines.url}
        </a>
      </div>

      <div className="p-6 space-y-6">
        {/* Key Stats */}
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-gray-900 rounded-lg p-4">
            <div className="text-xs text-gray-400 uppercase tracking-wider">Bounty Range</div>
            <div className="text-2xl font-bold text-green-400 mt-1">
              ${guidelines.bountyRange.min.toLocaleString()} - ${guidelines.bountyRange.max.toLocaleString()}
            </div>
          </div>
          <div className="bg-gray-900 rounded-lg p-4">
            <div className="text-xs text-gray-400 uppercase tracking-wider">In-Scope</div>
            <div className="text-2xl font-bold text-white mt-1">
              {guidelines.scope.inScope.length} targets
            </div>
          </div>
          <div className="bg-gray-900 rounded-lg p-4">
            <div className="text-xs text-gray-400 uppercase tracking-wider">Out-of-Scope</div>
            <div className="text-2xl font-bold text-red-400 mt-1">
              {guidelines.scope.outOfScope.length} targets
            </div>
          </div>
        </div>

        {/* Scope */}
        <div>
          <h3 className="font-semibold text-white mb-2">Scope</h3>
          <div className="bg-gray-900 rounded p-4 max-h-48 overflow-y-auto space-y-1">
            {guidelines.scope.inScope.map((target, i) => (
              <div key={i} className="text-sm flex items-center">
                <span className="text-green-400 mr-2">IN</span>
                <span className="text-gray-300">{target}</span>
              </div>
            ))}
            {guidelines.scope.outOfScope.map((target, i) => (
              <div key={`out-${i}`} className="text-sm flex items-center">
                <span className="text-red-400 mr-2">OUT</span>
                <span className="text-gray-500">{target}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Rules */}
        {guidelines.rules.length > 0 && (
          <div>
            <h3 className="font-semibold text-white mb-2">Program Rules</h3>
            <ul className="bg-gray-900 rounded p-4 space-y-1 max-h-32 overflow-y-auto">
              {guidelines.rules.map((rule, i) => (
                <li key={i} className="text-sm text-gray-400 flex items-start">
                  <span className="text-yellow-400 mr-2 flex-shrink-0">*</span>
                  <span>{rule}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Action */}
        <button
          onClick={onStartHunt}
          className="w-full py-3 bg-red-600 hover:bg-red-700 text-white rounded-lg font-semibold transition-colors"
        >
          Analyze & Generate Attack Strategies
        </button>
      </div>
    </div>
  );
};

export default BriefingView;

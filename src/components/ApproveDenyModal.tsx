/**
 * Approve/Deny Modal Component
 *
 * Enhanced modal for human approval of critical operations with detailed tool information
 */

import React, { useState } from 'react';
import type { HumanTaskRequest } from '../core/crewai/human_task';

interface ApproveDenyModalProps {
  task: HumanTaskRequest;
  onApprove: (feedback?: string) => void;
  onDeny: (reason?: string) => void;
}

export const ApproveDenyModal: React.FC<ApproveDenyModalProps> = ({
  task,
  onApprove,
  onDeny,
}) => {
  const [feedback, setFeedback] = useState('');
  const [reason, setReason] = useState('');
  const [showFeedback, setShowFeedback] = useState(false);
  const [showReason, setShowReason] = useState(false);

  // Get safety level color
  const getSafetyColor = (level?: string) => {
    switch (level) {
      case 'SAFE': return 'text-green-400 bg-green-900/30 border-green-500/30';
      case 'RESTRICTED': return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/30';
      case 'DANGEROUS': return 'text-red-400 bg-red-900/30 border-red-500/30';
      default: return 'text-gray-400 bg-gray-900/30 border-gray-500/30';
    }
  };

  // Get severity color
  const getSeverityColor = (severity?: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-blue-400';
      default: return 'text-gray-400';
    }
  };

  const handleApprove = () => {
    onApprove(showFeedback && feedback ? feedback : undefined);
  };

  const handleDeny = () => {
    onDeny(showReason && reason ? reason : undefined);
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 max-w-3xl w-full border border-gray-700 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-bold text-white">APPROVAL REQUIRED</h2>
          {task.severity && (
            <span className={`text-sm font-semibold ${getSeverityColor(task.severity)}`}>
              {task.severity.toUpperCase()}
            </span>
          )}
        </div>
        
        {/* Title */}
        <div className="mb-4">
          <h3 className="text-xl text-gray-200 font-semibold">{task.title}</h3>
          <p className="text-gray-400 mt-1">{task.description}</p>
        </div>

        {/* Tool Information */}
        {task.context && (
          <div className="space-y-4 mb-6">
            {/* Command */}
            {task.context.command && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-gray-300 mb-2">Command</h4>
                <code className="text-sm text-green-400 font-mono break-all">
                  {task.context.command}
                </code>
              </div>
            )}

            {/* Tool Details */}
            <div className="grid grid-cols-2 gap-4">
              {task.context.tool && (
                <div className="bg-gray-900 rounded-lg p-4">
                  <h4 className="text-xs text-gray-400 mb-1">Tool</h4>
                  <div className="text-lg font-semibold text-white">{task.context.tool}</div>
                </div>
              )}

              {task.context.safetyLevel && (
                <div className="bg-gray-900 rounded-lg p-4">
                  <h4 className="text-xs text-gray-400 mb-1">Safety Level</h4>
                  <div className={`text-sm font-semibold px-2 py-1 rounded border inline-block ${getSafetyColor(task.context.safetyLevel)}`}>
                    {task.context.safetyLevel}
                  </div>
                </div>
              )}

              {task.context.target && (
                <div className="bg-gray-900 rounded-lg p-4 col-span-2">
                  <h4 className="text-xs text-gray-400 mb-1">Target</h4>
                  <div className="text-sm text-white font-mono">{task.context.target}</div>
                </div>
              )}
            </div>

            {/* Validation Info */}
            {task.context.validation && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-gray-300 mb-2">Validation</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex items-center space-x-2">
                    <span className={task.context.validation.allowed ? 'text-green-400' : 'text-red-400'}>
                      [{task.context.validation.allowed ? 'PASS' : 'FAIL'}]
                    </span>
                    <span className="text-gray-300">
                      {task.context.validation.allowed ? 'Command validated' : 'Validation failed'}
                    </span>
                  </div>
                  {task.context.validation.warnings && task.context.validation.warnings.length > 0 && (
                    <div className="mt-2">
                      <div className="text-yellow-400 text-xs mb-1">[WARNINGS]</div>
                      <ul className="text-gray-400 text-xs space-y-1 ml-4">
                        {task.context.validation.warnings.map((warning: string, idx: number) => (
                          <li key={idx}>• {warning}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Risk Assessment */}
            {task.context.safetyLevel === 'DANGEROUS' && (
              <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-red-400 mb-2">Risk Assessment</h4>
                <p className="text-sm text-gray-300">
                  This tool is classified as <strong>DANGEROUS</strong>. It may:
                </p>
                <ul className="text-sm text-gray-400 mt-2 space-y-1 ml-4">
                  <li>• Modify system state or target infrastructure</li>
                  <li>• Generate significant traffic or load</li>
                  <li>• Trigger security alerts or defensive measures</li>
                  <li>• Require careful monitoring and potential rollback</li>
                </ul>
              </div>
            )}
          </div>
        )}

        {/* Feedback/Reason Input */}
        {showFeedback && (
          <div className="mb-4">
            <label className="block text-sm font-semibold text-gray-300 mb-2">
              Optional Feedback
            </label>
            <textarea
              value={feedback}
              onChange={(e) => setFeedback(e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 text-white rounded border border-gray-700 focus:border-blue-500 focus:outline-none"
              rows={3}
              placeholder="Add any notes or modifications..."
            />
          </div>
        )}

        {showReason && (
          <div className="mb-4">
            <label className="block text-sm font-semibold text-gray-300 mb-2">
              Reason for Denial
            </label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 text-white rounded border border-gray-700 focus:border-red-500 focus:outline-none"
              rows={3}
              placeholder="Why are you denying this action?"
            />
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex justify-between items-center">
          <div className="flex space-x-2">
            {!showFeedback && !showReason && (
              <>
                <button
                  onClick={() => setShowFeedback(true)}
                  className="text-sm text-blue-400 hover:text-blue-300"
                >
                  + Add feedback
                </button>
                <button
                  onClick={() => setShowReason(true)}
                  className="text-sm text-red-400 hover:text-red-300"
                >
                  + Add reason
                </button>
              </>
            )}
          </div>
          
          <div className="flex space-x-4">
            <button
              onClick={handleDeny}
              className="px-6 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition-colors font-semibold"
            >
              DENY
            </button>
            <button
              onClick={handleApprove}
              className="px-6 py-2 bg-green-600 text-white rounded hover:bg-green-700 transition-colors font-semibold"
            >
              APPROVE
            </button>
          </div>
        </div>

        {/* Timestamp */}
        <div className="mt-4 text-xs text-gray-500 text-center">
          Requested: {new Date(task.timestamp).toLocaleString()}
        </div>
      </div>
    </div>
  );
};

export default ApproveDenyModal;
/**
 * Approve/Deny Modal Component
 * 
 * Modal for human approval of critical operations
 */

import React from 'react';
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
  return (
    <div className="modal-overlay fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center">
      <div className="modal-content bg-white rounded-lg p-6 max-w-2xl w-full">
        <h2 className="text-2xl font-bold mb-4">{task.title}</h2>
        
        <div className="mb-4">
          <p className="text-gray-700">{task.description}</p>
        </div>

        {task.context && (
          <div className="mb-4 p-4 bg-gray-100 rounded">
            <pre className="text-sm overflow-auto">
              {JSON.stringify(task.context, null, 2)}
            </pre>
          </div>
        )}

        <div className="flex justify-end space-x-4">
          <button
            onClick={() => onDeny()}
            className="px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600"
          >
            Deny
          </button>
          <button
            onClick={() => onApprove()}
            className="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600"
          >
            Approve
          </button>
        </div>
      </div>
    </div>
  );
};

export default ApproveDenyModal;
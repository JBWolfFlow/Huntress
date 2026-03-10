/**
 * AgentStatusPanel
 *
 * Side panel showing active agent list with status indicators,
 * progress information, and tool/finding counts.
 */

import React from 'react';
import type { AgentStatus } from '../agents/base_agent';

interface AgentStatusPanelProps {
  agents: AgentStatus[];
}

export const AgentStatusPanel: React.FC<AgentStatusPanelProps> = ({ agents }) => {
  if (agents.length === 0) {
    return (
      <div className="p-4">
        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Agents</h3>
        <p className="text-sm text-gray-500">No active agents</p>
      </div>
    );
  }

  return (
    <div className="p-4">
      <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
        Active Agents ({agents.length})
      </h3>
      <div className="space-y-3">
        {agents.map((agent) => (
          <div
            key={agent.agentId}
            className="bg-gray-900 rounded-lg p-3 border border-gray-700"
          >
            <div className="flex items-center space-x-2 mb-2">
              <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${
                agent.status === 'running' ? 'bg-yellow-400 animate-pulse' :
                agent.status === 'completed' ? 'bg-green-400' :
                agent.status === 'failed' ? 'bg-red-400' :
                agent.status === 'waiting' ? 'bg-blue-400 animate-pulse' :
                agent.status === 'initializing' ? 'bg-purple-400 animate-pulse' :
                'bg-gray-500'
              }`} />
              <span className="text-sm font-semibold text-white truncate">{agent.agentName}</span>
            </div>

            {agent.currentTask && (
              <p className="text-xs text-gray-400 mb-2 truncate">{agent.currentTask}</p>
            )}

            <div className="flex items-center justify-between text-xs text-gray-500">
              <span>{agent.toolsExecuted} tools</span>
              <span className={agent.findingsCount > 0 ? 'text-yellow-400 font-semibold' : ''}>
                {agent.findingsCount} findings
              </span>
              <span className={`capitalize ${
                agent.status === 'running' ? 'text-yellow-400' :
                agent.status === 'completed' ? 'text-green-400' :
                agent.status === 'failed' ? 'text-red-400' : ''
              }`}>
                {agent.status}
              </span>
            </div>

            {/* Progress bar for running agents */}
            {agent.status === 'running' && (
              <div className="mt-2 h-1 bg-gray-800 rounded overflow-hidden">
                <div className="h-full bg-yellow-400 animate-pulse" style={{ width: '60%' }} />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default AgentStatusPanel;

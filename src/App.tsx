/**
 * Huntress — Main Application
 *
 * Chat-first layout with conversational AI interface.
 * Replaces the legacy tab-based UI.
 */

import { useState, useEffect } from "react";
import "./App.css";
import { useSettings } from "./contexts/SettingsContext";
import { HuntSessionProvider, useHuntSession } from "./contexts/HuntSessionContext";
import { useGuidelines } from "./contexts/GuidelinesContext";
import { SetupWizard } from "./components/SetupWizard";
import { ChatInterface } from "./components/ChatInterface";
import { SettingsPanel } from "./components/SettingsPanel";
import { ApproveDenyModal } from "./components/ApproveDenyModal";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { GuidelinesImporter, type ProgramGuidelines } from "./components/GuidelinesImporter";
import type { HumanTaskRequest } from "./core/crewai/human_task";
import { useTauri, type ScopeEntry } from "./hooks/useTauriCommands";

/** Header with status indicators */
function AppHeader({ onSettingsOpen, onImportOpen }: {
  onSettingsOpen: () => void;
  onImportOpen: () => void;
}) {
  const { killSwitch, proxyPool } = useTauri();
  const { phase, isHunting, resetSession } = useHuntSession();

  return (
    <header className="bg-black border-b border-gray-800 px-4 py-2 flex items-center justify-between font-mono">
      <div className="flex items-center space-x-4">
        <h1 className="text-sm font-bold">
          <span className="text-red-500">HUNTRESS</span>
          <span className="text-gray-600 ml-2">v0.1.0</span>
        </h1>

        {/* Phase indicator */}
        {phase !== 'idle' && (
          <span className="text-xs text-red-400">
            [{phase.toUpperCase()}]
          </span>
        )}
      </div>

      <div className="flex items-center space-x-2 text-xs">
        {/* Import button */}
        <button
          onClick={onImportOpen}
          className="px-2 py-1 text-gray-400 hover:text-green-400 border border-gray-700 hover:border-green-700 rounded transition-colors"
        >
          [import]
        </button>

        {/* New Hunt */}
        {phase !== 'idle' && (
          <button
            onClick={resetSession}
            className="px-2 py-1 text-gray-400 hover:text-yellow-400 border border-gray-700 hover:border-yellow-700 rounded transition-colors"
          >
            [new]
          </button>
        )}

        {/* Proxy status */}
        <span className="text-gray-500">
          proxy:<span className="text-green-400">{proxyPool.stats.active}</span>
          <span className="text-gray-600">/{proxyPool.stats.total}</span>
        </span>

        {/* Kill switch */}
        <span className={
          killSwitch.status.active
            ? 'text-red-400 animate-pulse'
            : 'text-green-500'
        }>
          {killSwitch.status.active ? '[KILL]' : '[OK]'}
        </span>

        {/* Settings */}
        <button
          onClick={onSettingsOpen}
          className="px-2 py-1 text-gray-400 hover:text-white border border-gray-700 hover:border-gray-500 rounded transition-colors"
        >
          [settings]
        </button>
      </div>
    </header>
  );
}

/** Side panel showing findings and agent status */
function SidePanel() {
  const { findings, activeAgents, isHunting } = useHuntSession();

  if (!isHunting && findings.length === 0) return null;

  return (
    <div className="w-72 border-l border-gray-800 bg-gray-950 flex flex-col min-h-0 text-xs">
      {/* Agents */}
      {activeAgents.length > 0 && (
        <div className="p-3 border-b border-gray-800">
          <div className="text-gray-500 mb-2">--- AGENTS ---</div>
          <div className="space-y-1">
            {activeAgents.map((agent) => (
              <div key={agent.id} className="flex items-center space-x-2">
                <span className={
                  agent.status === 'running' ? 'text-yellow-400' :
                  agent.status === 'completed' ? 'text-green-400' :
                  agent.status === 'failed' ? 'text-red-400' : 'text-gray-500'
                }>
                  [{agent.status === 'running' ? '*' :
                    agent.status === 'completed' ? '+' :
                    agent.status === 'failed' ? '!' : '-'}]
                </span>
                <span className="text-gray-300 flex-1">{agent.name}</span>
                <span className="text-gray-600">{agent.findingsCount}f</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings Summary */}
      {findings.length > 0 && (
        <div className="p-3 flex-1 overflow-y-auto">
          <div className="text-gray-500 mb-2">--- FINDINGS ({findings.length}) ---</div>

          {/* Severity breakdown */}
          <div className="flex space-x-3 mb-3">
            {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
              const count = findings.filter(f => f.severity === sev).length;
              if (count === 0) return null;
              return (
                <span
                  key={sev}
                  className={
                    sev === 'critical' ? 'text-red-400' :
                    sev === 'high' ? 'text-orange-400' :
                    sev === 'medium' ? 'text-yellow-400' :
                    'text-blue-400'
                  }
                >
                  {count} {sev}
                </span>
              );
            })}
          </div>

          {/* Finding list */}
          <div className="space-y-2">
            {findings.map((finding) => (
              <div
                key={finding.id}
                className="border border-gray-800 rounded p-2"
              >
                <div className="flex items-center justify-between">
                  <span className="text-white truncate">{finding.title}</span>
                  <span className={`font-bold uppercase flex-shrink-0 ml-2 ${
                    finding.severity === 'critical' ? 'text-red-400' :
                    finding.severity === 'high' ? 'text-orange-400' :
                    finding.severity === 'medium' ? 'text-yellow-400' : 'text-blue-400'
                  }`}>
                    [{finding.severity}]
                  </span>
                </div>
                <div className="text-gray-500 mt-1">{finding.target}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/** Import modal wrapper */
function ImportModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { setGuidelines } = useGuidelines();
  const { importProgram } = useHuntSession();

  if (!isOpen) return null;

  const handleImport = async (guidelines: ProgramGuidelines) => {
    setGuidelines(guidelines);

    // Load scope into backend
    const scopeEntries: ScopeEntry[] = [
      ...guidelines.scope.inScope.map(target => ({
        target,
        inScope: true,
        notes: `From ${guidelines.programName} guidelines`,
      })),
      ...guidelines.scope.outOfScope.map(target => ({
        target,
        inScope: false,
        notes: `Out of scope - ${guidelines.programName}`,
      })),
    ];

    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('load_scope_entries', { entries: scopeEntries });
    } catch (error) {
      console.error('Failed to load scope into backend:', error);
    }

    // Analyze the program via orchestrator
    await importProgram(guidelines);
    onClose();
  };

  return (
    <>
      {/* Backdrop */}
      <div
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.80)',
          zIndex: 9998,
        }}
        onClick={onClose}
      />

      {/* Modal */}
      <div
        style={{
          position: 'fixed',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          width: '700px',
          maxWidth: '90vw',
          maxHeight: '85vh',
          zIndex: 9999,
          display: 'flex',
          flexDirection: 'column',
          fontFamily: 'monospace',
          backgroundColor: '#111827',
          border: '1px solid #374151',
          borderRadius: '8px',
          overflow: 'hidden',
        }}
      >
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '12px 16px',
          borderBottom: '1px solid #374151',
          backgroundColor: '#030712',
          flexShrink: 0,
        }}>
          <h2 style={{ fontSize: '14px', fontWeight: 'bold', color: '#ffffff', margin: 0 }}>
            <span style={{ color: '#ef4444' }}>[</span>IMPORT PROGRAM<span style={{ color: '#ef4444' }}>]</span>
          </h2>
          <button
            onClick={onClose}
            style={{
              fontSize: '12px',
              color: '#9ca3af',
              border: '1px solid #4b5563',
              padding: '4px 10px',
              borderRadius: '4px',
              background: 'transparent',
              cursor: 'pointer',
              fontFamily: 'monospace',
            }}
          >
            [close]
          </button>
        </div>
        <div style={{ overflowY: 'auto', padding: '16px', flex: 1 }}>
          <GuidelinesImporter onImport={handleImport} />
        </div>
      </div>
    </>
  );
}

/** Inner app that has access to HuntSession context */
function AppContent() {
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [pendingTask, setPendingTask] = useState<HumanTaskRequest | null>(null);

  // Listen for tool approval requests from the executor
  useEffect(() => {
    const handleToolApprovalRequest = (event: CustomEvent) => {
      const { approvalId, request } = event.detail;
      const taskRequest: HumanTaskRequest = {
        id: approvalId,
        type: 'approval',
        title: `Tool Execution: ${request.tool.name}`,
        description: `Execute: ${request.command}`,
        context: {
          command: request.command,
          tool: request.tool.name,
          target: request.target,
          safetyLevel: request.tool.safetyLevel,
          validation: request.validation,
        },
        severity: request.tool.safetyLevel === 'DANGEROUS' ? 'critical' :
                  request.tool.safetyLevel === 'RESTRICTED' ? 'high' : 'medium',
        timestamp: Date.now(),
      };
      setPendingTask(taskRequest);
    };

    window.addEventListener('tool-approval-request', handleToolApprovalRequest as EventListener);
    return () => {
      window.removeEventListener('tool-approval-request', handleToolApprovalRequest as EventListener);
    };
  }, []);

  const handleApprove = (feedback?: string) => {
    if (pendingTask) {
      // Dispatch approval response via the global callback system
      const callbacks = (window as unknown as Record<string, unknown>).__huntress_approval_callbacks as Map<string, (approved: boolean) => void> | undefined;
      callbacks?.get(pendingTask.id)?.(true);
    }
    setPendingTask(null);
  };

  const handleDeny = (reason?: string) => {
    if (pendingTask) {
      const callbacks = (window as unknown as Record<string, unknown>).__huntress_approval_callbacks as Map<string, (approved: boolean) => void> | undefined;
      callbacks?.get(pendingTask.id)?.(false);
    }
    setPendingTask(null);
  };

  return (
    <div className="min-h-screen bg-black text-gray-100 flex flex-col font-mono">
      <AppHeader
        onSettingsOpen={() => setSettingsOpen(true)}
        onImportOpen={() => setImportOpen(true)}
      />

      <main className="flex-1 flex min-h-0">
        <ChatInterface />
        <SidePanel />
      </main>

      {/* Modals */}
      <SettingsPanel isOpen={settingsOpen} onClose={() => setSettingsOpen(false)} />
      <ImportModal isOpen={importOpen} onClose={() => setImportOpen(false)} />

      {pendingTask && (
        <ApproveDenyModal
          task={pendingTask}
          onApprove={handleApprove}
          onDeny={handleDeny}
        />
      )}
    </div>
  );
}

function App() {
  const { settings, isLoaded } = useSettings();

  // Wait for secure storage to load before deciding first-run state
  if (!isLoaded) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center font-mono">
        <div className="text-green-400 animate-pulse">[*] Loading secure storage...</div>
      </div>
    );
  }

  if (!settings.firstRunComplete) {
    return <SetupWizard />;
  }

  return (
    <ErrorBoundary>
      <HuntSessionProvider>
        <AppContent />
      </HuntSessionProvider>
    </ErrorBoundary>
  );
}

export default App;

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
import { ReportEditor } from "./components/ReportEditor";
import { ReportReviewModal } from "./components/ReportReviewModal";
import type { QualityScore } from "./components/ReportReviewModal";
import type { H1Report } from "./core/reporting/h1_api";
import type { HumanTaskRequest } from "./core/crewai/human_task";
import { useTauri, type ScopeEntry } from "./hooks/useTauriCommands";
import { BriefingView } from "./components/BriefingView";
import type { FindingCardMessage } from "./core/conversation/types";
import { AgentStatusPanel } from "./components/AgentStatusPanel";
import type { AgentStatus } from "./agents/base_agent";
import { TrainingDashboard } from "./components/TrainingDashboard";
import { BenchmarkDashboard } from "./components/BenchmarkDashboard";

type AppTab = 'chat' | 'training' | 'benchmark';

/** Header with status indicators and tab navigation */
function AppHeader({ onSettingsOpen, onImportOpen, activeTab, onTabChange }: {
  onSettingsOpen: () => void;
  onImportOpen: () => void;
  activeTab: AppTab;
  onTabChange: (tab: AppTab) => void;
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

        {/* Tab navigation */}
        <div className="flex space-x-1 ml-4">
          {(['chat', 'training', 'benchmark'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => onTabChange(tab)}
              className={`px-2 py-1 text-xs rounded transition-colors ${
                activeTab === tab
                  ? 'text-red-400 border border-red-700 bg-red-900/20'
                  : 'text-gray-500 hover:text-gray-300 border border-transparent'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
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
function SidePanel({ onFindingClick }: { onFindingClick?: (finding: FindingCardMessage) => void }) {
  const { findings, activeAgents, isHunting } = useHuntSession();

  if (!isHunting && findings.length === 0) return null;

  return (
    <div className="w-72 border-l border-gray-800 bg-gray-950 flex flex-col min-h-0 text-xs">
      {/* Agents */}
      {activeAgents.length > 0 && (
        <div className="border-b border-gray-800">
          <AgentStatusPanel
            agents={activeAgents.map((agent): AgentStatus => ({
              agentId: agent.id,
              agentName: agent.name,
              status: agent.status,
              toolsExecuted: agent.toolsExecuted,
              findingsCount: agent.findingsCount,
              lastUpdate: Date.now(),
            }))}
          />
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
                className="border border-gray-800 rounded p-2 cursor-pointer hover:border-gray-600 transition-colors"
                onClick={() => onFindingClick?.(finding)}
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
  const [pendingGuidelines, setPendingGuidelines] = useState<ProgramGuidelines | null>(null);

  if (!isOpen) return null;

  const handleGuidelinesReady = (guidelines: ProgramGuidelines) => {
    setPendingGuidelines(guidelines);
  };

  const handleStartHunt = async () => {
    if (!pendingGuidelines) return;

    setGuidelines(pendingGuidelines);

    // Load scope into backend
    const scopeEntries: ScopeEntry[] = [
      ...pendingGuidelines.scope.inScope.map(target => ({
        target,
        inScope: true,
        notes: `From ${pendingGuidelines.programName} guidelines`,
      })),
      ...pendingGuidelines.scope.outOfScope.map(target => ({
        target,
        inScope: false,
        notes: `Out of scope - ${pendingGuidelines.programName}`,
      })),
    ];

    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('load_scope_entries', { entries: scopeEntries });
    } catch (error) {
      console.error('Failed to load scope into backend:', error);
    }

    // Analyze the program via orchestrator
    await importProgram(pendingGuidelines);
    setPendingGuidelines(null);
    onClose();
  };

  // Legacy direct import (for backward compat with GuidelinesImporter)
  const handleImport = async (guidelines: ProgramGuidelines) => {
    handleGuidelinesReady(guidelines);
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
          {pendingGuidelines ? (
            <BriefingView
              guidelines={pendingGuidelines}
              onStartHunt={handleStartHunt}
            />
          ) : (
            <GuidelinesImporter onImport={handleImport} />
          )}
        </div>
      </div>
    </>
  );
}

/** Compute a quality score for a report */
function scoreReport(report: H1Report): QualityScore {
  let clarity = 0, completeness = 0, evidence = 0, impact = 0, reproducibility = 0;

  // Clarity: based on description length and structure
  if (report.description.length > 100) clarity += 40;
  if (report.description.length > 300) clarity += 30;
  if (report.description.includes('#') || report.description.includes('**')) clarity += 30;

  // Completeness: all fields populated
  if (report.title.length > 10) completeness += 25;
  if (report.description.length > 50) completeness += 25;
  if (report.impact.length > 20) completeness += 25;
  if (report.steps.length >= 2) completeness += 25;

  // Evidence: steps and proof
  if (report.steps.length >= 3) evidence += 50;
  if (report.steps.length >= 5) evidence += 25;
  if (report.proof && Object.keys(report.proof).length > 0) evidence += 25;

  // Impact: severity + description
  if (report.severity === 'critical' || report.severity === 'high') impact += 50;
  if (report.impact.length > 50) impact += 30;
  if (report.impact.length > 100) impact += 20;

  // Reproducibility
  if (report.steps.length >= 2) reproducibility += 40;
  if (report.steps.some(s => s.includes('curl') || s.includes('http'))) reproducibility += 30;
  if (report.steps.length >= 4) reproducibility += 30;

  const categories = {
    clarity: Math.min(100, clarity),
    completeness: Math.min(100, completeness),
    evidence: Math.min(100, evidence),
    impact: Math.min(100, impact),
    reproducibility: Math.min(100, reproducibility),
  };

  const overall = Math.round(
    (categories.clarity + categories.completeness + categories.evidence +
     categories.impact + categories.reproducibility) / 5
  );

  const grade = overall >= 90 ? 'A' : overall >= 75 ? 'B' : overall >= 60 ? 'C' : overall >= 40 ? 'D' : 'F';

  const issues: { category: string; severity: 'critical' | 'major' | 'minor'; message: string; suggestion: string }[] = [];
  if (categories.clarity < 40) issues.push({ category: 'Clarity', severity: 'major', message: 'Description is too brief', suggestion: 'Add more detail about the vulnerability mechanism' });
  if (report.steps.length < 2) issues.push({ category: 'Reproducibility', severity: 'critical', message: 'Missing reproduction steps', suggestion: 'Add step-by-step instructions to reproduce' });
  if (report.impact.length < 20) issues.push({ category: 'Impact', severity: 'major', message: 'Impact statement is too short', suggestion: 'Describe the real-world impact and affected users' });

  return { overall, categories, grade, issues };
}

/** Convert a finding card to an H1Report for the ReportEditor */
function findingToH1Report(finding: FindingCardMessage): H1Report {
  return {
    title: finding.title,
    severity: finding.severity === 'info' ? 'low' : finding.severity,
    suggestedBounty: { min: 0, max: 0 },
    description: finding.description,
    impact: `${finding.severity.toUpperCase()} severity vulnerability discovered on ${finding.target}`,
    steps: finding.evidence.length > 0 ? finding.evidence : ['See description for reproduction steps'],
    proof: {},
  };
}

/** Inner app that has access to HuntSession context */
function AppContent() {
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [pendingTasks, setPendingTasks] = useState<HumanTaskRequest[]>([]);
  const [reportFinding, setReportFinding] = useState<FindingCardMessage | null>(null);
  const [reviewReport, setReviewReport] = useState<{ report: H1Report; programHandle: string; qualityScore?: QualityScore } | null>(null);
  const [activeTab, setActiveTab] = useState<AppTab>('chat');
  const { submitToH1 } = useHuntSession();

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
      setPendingTasks(prev => [...prev, taskRequest]);
    };

    window.addEventListener('tool-approval-request', handleToolApprovalRequest as EventListener);
    return () => {
      window.removeEventListener('tool-approval-request', handleToolApprovalRequest as EventListener);
    };
  }, []);

  // Show the first task in the queue
  const currentTask = pendingTasks[0] ?? null;

  const handleApprove = (feedback?: string) => {
    if (currentTask) {
      const callbacks = (window as unknown as Record<string, unknown>).__huntress_approval_callbacks as Map<string, (approved: boolean) => void> | undefined;
      callbacks?.get(currentTask.id)?.(true);
      callbacks?.delete(currentTask.id);
    }
    setPendingTasks(prev => prev.slice(1));
  };

  const handleDeny = (reason?: string) => {
    if (currentTask) {
      const callbacks = (window as unknown as Record<string, unknown>).__huntress_approval_callbacks as Map<string, (approved: boolean) => void> | undefined;
      callbacks?.get(currentTask.id)?.(false);
      callbacks?.delete(currentTask.id);
    }
    setPendingTasks(prev => prev.slice(1));
  };

  return (
    <div className="min-h-screen bg-black text-gray-100 flex flex-col font-mono">
      <AppHeader
        onSettingsOpen={() => setSettingsOpen(true)}
        onImportOpen={() => setImportOpen(true)}
        activeTab={activeTab}
        onTabChange={setActiveTab}
      />

      <main className="flex-1 flex min-h-0">
        {activeTab === 'chat' && (
          <>
            <ChatInterface />
            <SidePanel onFindingClick={(finding) => setReportFinding(finding)} />
          </>
        )}
        {activeTab === 'training' && <TrainingDashboard />}
        {activeTab === 'benchmark' && <BenchmarkDashboard />}
      </main>

      {/* Modals */}
      <SettingsPanel isOpen={settingsOpen} onClose={() => setSettingsOpen(false)} />
      <ImportModal isOpen={importOpen} onClose={() => setImportOpen(false)} />

      {currentTask && (
        <ApproveDenyModal
          task={currentTask}
          onApprove={handleApprove}
          onDeny={handleDeny}
        />
      )}

      {/* Report Editor Modal */}
      {reportFinding && (
        <>
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
            onClick={() => setReportFinding(null)}
          />
          <div
            style={{
              position: 'fixed',
              top: '5%',
              left: '5%',
              right: '5%',
              bottom: '5%',
              zIndex: 9999,
              borderRadius: '8px',
              overflow: 'hidden',
              border: '1px solid #374151',
            }}
          >
            <ReportEditor
              report={findingToH1Report(reportFinding)}
              programHandle={reportFinding.target}
              onSubmit={async (report, programHandle) => {
                // Compute quality score for the review modal
                const score = scoreReport(report);
                setReviewReport({ report, programHandle, qualityScore: score });
              }}
              onClose={() => setReportFinding(null)}
            />
          </div>
        </>
      )}
      {/* Report Review Modal — mandatory gate before H1 submission */}
      {reviewReport && (
        <ReportReviewModal
          report={reviewReport.report}
          programHandle={reviewReport.programHandle}
          qualityScore={reviewReport.qualityScore}
          onApproveAndSubmit={async (report, programHandle) => {
            try {
              await submitToH1(report, programHandle);
              setReviewReport(null);
              setReportFinding(null);
            } catch (error) {
              // Keep modals open so user can retry — don't silently lose their edits
              console.error('H1 submission failed:', error);
              alert(`Submission failed: ${error instanceof Error ? error.message : String(error)}`);
            }
          }}
          onEditReport={() => {
            // Close review modal, keep report editor open for further edits
            setReviewReport(null);
          }}
          onCancel={() => setReviewReport(null)}
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

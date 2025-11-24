import { useState, useEffect, useRef } from "react";
import "./App.css";
import { ScopeImporter } from "./components/ScopeImporter";
import { Terminal } from "./components/Terminal";
import { ApproveDenyModal } from "./components/ApproveDenyModal";
import { OAuthTester } from "./components/OAuthTester";
import { GuidelinesImporter, type ProgramGuidelines } from "./components/GuidelinesImporter";
import { useGuidelines } from "./contexts/GuidelinesContext";
import type { HumanTaskRequest } from "./core/crewai/human_task";
import { useTauri, type ScopeEntry } from "./hooks/useTauriCommands";
import { createAIAgentToolInterface } from "./core/crewai/tool_integration";
import {
  Supervisor,
  type StreamingMessage,
  type CheckpointRequest,
  AIReasoningType,
  HuntPhase
} from "./core/crewai/supervisor";
import type { ApprovalRequest } from "./core/tools/tool_executor";

function App() {
  const [scope, setScope] = useState<ScopeEntry[]>([]);
  const [activeTab, setActiveTab] = useState<'scope' | 'hunt' | 'results' | 'oauth-test'>('scope');
  const [pendingTask, setPendingTask] = useState<HumanTaskRequest | null>(null);
  const [pendingCheckpoint, setPendingCheckpoint] = useState<CheckpointRequest | null>(null);
  const [isHunting, setIsHunting] = useState(false);
  const [activePtyId, setActivePtyId] = useState<string | null>(null);
  const [huntProgress, setHuntProgress] = useState<string>('');
  const [currentPhase, setCurrentPhase] = useState<HuntPhase>(HuntPhase.INITIALIZATION);
  const [aiMessages, setAiMessages] = useState<StreamingMessage[]>([]);
  const [toolsExecuted, setToolsExecuted] = useState<number>(0);
  const [findingsCount, setFindingsCount] = useState<number>(0);

  // Initialize Tauri hooks and Guidelines context
  const { pty, killSwitch, proxyPool } = useTauri();
  const { guidelines, setGuidelines, getGuidelinesPrompt } = useGuidelines();
  
  // Tool interface and supervisor refs
  const toolInterfaceRef = useRef<ReturnType<typeof createAIAgentToolInterface> | null>(null);
  const supervisorRef = useRef<Supervisor | null>(null);
  
  // PTY ID ref - CRITICAL: Use ref to avoid closure issues in callbacks
  const activePtyIdRef = useRef<string | null>(null);

  // Monitor kill switch status
  useEffect(() => {
    if (killSwitch.status.active && isHunting) {
      setIsHunting(false);
      if (activePtyId) {
        pty.killPTY(activePtyId).catch(console.error);
        setActivePtyId(null);
      }
      alert(`KILL SWITCH ACTIVATED\nReason: ${killSwitch.status.reason || 'Unknown'}`);
    }
  }, [killSwitch.status.active, isHunting, activePtyId, pty]);

  // Listen for tool approval requests from the executor
  useEffect(() => {
    const handleToolApprovalRequest = (event: CustomEvent) => {
      const { approvalId, request } = event.detail;
      console.log('[App] 📥 Tool approval request received:', approvalId);
      console.log('[App] Command:', request.command);
      console.log('[App] Tool:', request.tool.name);
      
      // Convert ApprovalRequest to HumanTaskRequest format
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
      
      console.log('[App] 🎭 Showing approval modal');
      setPendingTask(taskRequest);
    };

    window.addEventListener('tool-approval-request', handleToolApprovalRequest as EventListener);
    
    return () => {
      window.removeEventListener('tool-approval-request', handleToolApprovalRequest as EventListener);
    };
  }, []);

  const handleScopeImport = (importedScope: ScopeEntry[]) => {
    setScope(importedScope);
    setActiveTab('hunt');
  };

  const handleGuidelinesImport = async (importedGuidelines: ProgramGuidelines) => {
    setGuidelines(importedGuidelines);
    
    // Auto-import scope from guidelines
    const scopeEntries: ScopeEntry[] = [
      ...importedGuidelines.scope.inScope.map(target => ({
        target,
        inScope: true,
        notes: `From ${importedGuidelines.programName} guidelines`
      })),
      ...importedGuidelines.scope.outOfScope.map(target => ({
        target,
        inScope: false,
        notes: `Out of scope - ${importedGuidelines.programName}`
      }))
    ];
    
    setScope(scopeEntries);
    
    // Load scope into backend for validation
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      console.log('📤 Sending scope to backend:', scopeEntries.length, 'entries');
      console.log('First 5 entries:', scopeEntries.slice(0, 5));
      
      const result = await invoke('load_scope_entries', { entries: scopeEntries });
      console.log('✅ Backend response:', result);
      
      // Test validation immediately
      const testValidation = await invoke('validate_target', { target: 'booking.com' });
      console.log('🧪 Test validation for booking.com:', testValidation);
    } catch (error) {
      console.error('❌ Failed to load scope into backend:', error);
      alert('Warning: Scope may not be loaded into backend validator.\nError: ' + error);
    }
    
    console.log('Guidelines imported:', importedGuidelines);
    alert(`✅ Guidelines imported for ${importedGuidelines.programName}\n${scopeEntries.length} targets loaded`);
  };

  // Handle streaming AI messages
  const handleStreamingMessage = (message: StreamingMessage) => {
    console.log('[APP] Received streaming message:', message);
    
    // Update phase tracking only
    setCurrentPhase(message.phase);
    
    // Format message for terminal display
    const icon = getReasoningIcon(message.type);
    const formattedMessage = `${icon} ${message.message}`;
    
    // CRITICAL: Use ref instead of state to avoid closure issues
    const currentPtyId = activePtyIdRef.current;
    console.log('[APP] Formatted message:', formattedMessage);
    console.log('[APP] Active PTY ID from ref:', currentPtyId);
    
    // ALL AI output MUST go through PTY/terminal - NOT UI state
    if (currentPtyId) {
      try {
        console.log('[APP] Writing to PTY:', currentPtyId);
        pty.writePTY(currentPtyId, `${formattedMessage}\n`);
        console.log('[APP] PTY write successful');
      } catch (error) {
        console.error('[APP] PTY write failed:', error);
        // Fallback to console only if PTY fails
        console.log(formattedMessage);
      }
    } else {
      // No PTY available - log to console
      console.log('[APP] No PTY available, logging to console:', formattedMessage);
    }
  };

  // Handle checkpoint requests
  const handleCheckpoint = async (checkpoint: CheckpointRequest): Promise<boolean> => {
    setPendingCheckpoint(checkpoint);
    
    // Return a promise that resolves when user responds
    return new Promise((resolve) => {
      const checkInterval = setInterval(() => {
        if (!pendingCheckpoint || pendingCheckpoint.id !== checkpoint.id) {
          clearInterval(checkInterval);
          // Check if it was approved (checkpoint cleared without being set to null explicitly means approved)
          resolve(true);
        }
      }, 100);
      
      // Timeout after 5 minutes
      setTimeout(() => {
        clearInterval(checkInterval);
        setPendingCheckpoint(null);
        resolve(false);
      }, 5 * 60 * 1000);
    });
  };

  // Get icon for reasoning type
  const getReasoningIcon = (type: AIReasoningType): string => {
    switch (type) {
      case AIReasoningType.ANALYSIS: return '[ANALYSIS]';
      case AIReasoningType.PLANNING: return '[PLAN]';
      case AIReasoningType.DECISION: return '[DECISION]';
      case AIReasoningType.HYPOTHESIS: return '[HYPOTHESIS]';
      case AIReasoningType.RECOMMENDATION: return '[RECOMMEND]';
      case AIReasoningType.WARNING: return '[WARNING]';
      case AIReasoningType.SUCCESS: return '[SUCCESS]';
      case AIReasoningType.ERROR: return '[ERROR]';
      default: return '[INFO]';
    }
  };

  const handleStartHunt = async () => {
    if (scope.length === 0) {
      alert('WARNING: No targets in scope. Please import scope first.');
      return;
    }

    setIsHunting(true);
    setActiveTab('results');
    setHuntProgress('Initializing hunt system...');
    setAiMessages([]);
    setToolsExecuted(0);
    setFindingsCount(0);
    setCurrentPhase(HuntPhase.INITIALIZATION);
    
    try {
      // Step 1: Create tool interface for AI agents
      setHuntProgress('Creating AI tool interface...');
      const toolInterface = createAIAgentToolInterface(`hunt_${Date.now()}`);
      toolInterfaceRef.current = toolInterface;
      
      // Step 2: Get API key from environment
      const apiKey = import.meta.env.VITE_ANTHROPIC_API_KEY;
      if (!apiKey) {
        throw new Error(
          'ANTHROPIC_API_KEY not configured.\n\n' +
          'Please add to your .env file:\n' +
          'VITE_ANTHROPIC_API_KEY=your-key-here\n\n' +
          'Then restart the dev server.'
        );
      }
      
      // Step 3: Spawn PTY for tool output FIRST - before supervisor starts streaming
      setHuntProgress('Starting terminal session...');
      const sessionId = await pty.spawnPTY('echo', ['[HUNTRESS] AI Hunt Started']);
      console.log('[APP] PTY spawned with ID:', sessionId);
      
      // CRITICAL: Set both state AND ref immediately
      setActivePtyId(sessionId);
      activePtyIdRef.current = sessionId;
      console.log('[APP] PTY ID set in both state and ref:', sessionId);
      
      // Step 4: Create supervisor with streaming and checkpoint callbacks
      setHuntProgress('Initializing AI supervisor...');
      const supervisor = new Supervisor({
        apiKey,
        humanInTheLoop: true,
        maxIterations: 10,
        verboseMode: true,
        checkpointInterval: 5,
        onStreaming: handleStreamingMessage,
        onCheckpoint: handleCheckpoint,
      });
      supervisorRef.current = supervisor;
      
      // Step 5: Set up approval callback - CRITICAL for tool execution approval
      // NOTE: Tool approvals are handled via the tool-approval-request event listener above
      // This callback is for supervisor-level approvals (checkpoints, etc.)
      supervisor.setHumanTaskCallback(async (task) => {
        console.log('🔔 Human approval required (supervisor):', task);
        setPendingTask(task);
        
        // Return a promise that resolves when user clicks approve/deny
        return new Promise((resolve) => {
          // For supervisor tasks, we'll use a simple polling approach
          const checkInterval = setInterval(() => {
            if (!pendingTask || pendingTask.id !== task.id) {
              clearInterval(checkInterval);
              resolve({
                taskId: task.id,
                approved: true,
                timestamp: Date.now(),
              });
            }
          }, 100);
          
          // Timeout after 5 minutes
          setTimeout(() => {
            clearInterval(checkInterval);
            setPendingTask(null);
            resolve({
              taskId: task.id,
              approved: false,
              timestamp: Date.now(),
            });
          }, 5 * 60 * 1000);
        });
      });
      
      // Step 6: Get guidelines prompt for AI context
      const guidelinesPrompt = guidelines ? getGuidelinesPrompt() :
        'No specific program guidelines loaded. Follow general bug bounty best practices.';
      
      setHuntProgress('Analyzing target and planning attack strategy...');
      
      // Step 7: Execute hunt with first in-scope target
      const firstTarget = scope.find(s => s.inScope);
      if (!firstTarget) {
        throw new Error('No in-scope targets found');
      }
      
      console.log('🎯 Starting hunt on target:', firstTarget.target);
      console.log('📋 Guidelines:', guidelinesPrompt);
      console.log('🔧 Available tools:', toolInterface.getAvailableTools());
      
      // Execute the hunt
      setHuntProgress(`Hunting ${firstTarget.target}...`);
      const result = await supervisor.execute({
        target: firstTarget.target,
        scope: scope.filter(s => s.inScope).map(s => s.target),
        onApprovalRequired: async (task) => {
          console.log('Tool execution requires approval:', task);
          setPendingTask(task);
          
          // Return a promise that resolves when user responds
          return new Promise((resolve) => {
            const checkInterval = setInterval(() => {
              if (!pendingTask || pendingTask.id !== task.id) {
                clearInterval(checkInterval);
                resolve({
                  taskId: task.id,
                  approved: true,
                  timestamp: Date.now(),
                });
              }
            }, 100);
          });
        },
      });
      
      setHuntProgress('Hunt completed!');
      console.log('✅ Hunt result:', result);
      
      // Display results (PTY write may not work yet - that's OK)
      try {
        if (result.success) {
          await pty.writePTY(sessionId, '\n[SUCCESS] Hunt completed successfully\n');
          await pty.writePTY(sessionId, `[STATS] Tasks executed: ${result.tasks.length}\n`);
          await pty.writePTY(sessionId, `[STATS] Vulnerabilities found: ${result.vulnerabilities.length}\n`);
          await pty.writePTY(sessionId, `[STATS] Duration: ${(result.duration / 1000).toFixed(2)}s\n`);
          
          if (result.vulnerabilities.length > 0) {
            await pty.writePTY(sessionId, '\n[VULNERABILITIES]\n');
            result.vulnerabilities.forEach((vuln, idx) => {
              pty.writePTY(sessionId, `  ${idx + 1}. ${vuln.type || 'Unknown'} - ${vuln.severity || 'Unknown'}\n`);
            });
          }
        } else {
          await pty.writePTY(sessionId, `\n[ERROR] Hunt failed: ${result.error}\n`);
        }
      } catch (ptyError) {
        // PTY write not implemented yet - log to console instead
        console.log('Hunt results:', result);
        setHuntProgress(result.success ?
          `[SUCCESS] Hunt completed! Found ${result.vulnerabilities.length} vulnerabilities` :
          `[ERROR] Hunt failed: ${result.error}`
        );
      }
      
    } catch (err) {
      console.error('Failed to start hunt:', err);
      const errorMsg = err instanceof Error ? err.message : String(err);
      setHuntProgress(`Error: ${errorMsg}`);
      
      if (activePtyId) {
        try {
          await pty.writePTY(activePtyId, `\n[ERROR] ${errorMsg}\n`);
        } catch {
          // PTY write not implemented yet - ignore
        }
      }
      
      alert('Failed to start hunt:\n\n' + errorMsg);
      setIsHunting(false);
    }
  };

  const handleStopHunt = async () => {
    if (activePtyId) {
      try {
        await pty.killPTY(activePtyId);
        setActivePtyId(null);
      } catch (err) {
        console.error('Failed to stop PTY:', err);
      }
    }
    setIsHunting(false);
  };

  const handleEmergencyStop = async () => {
    try {
      await killSwitch.activate('manual', 'User pressed emergency stop button');
      await handleStopHunt();
    } catch (err) {
      console.error('Failed to activate kill switch:', err);
      alert('Failed to activate kill switch: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  const handleApprove = (feedback?: string) => {
    console.log('[App] ✅ User approved task:', pendingTask?.id);
    if (feedback) console.log('[App] Feedback:', feedback);
    
    if (pendingTask) {
      // CRITICAL FIX: Call handleApprovalResponse directly on the tool executor
      // This ensures the callback is resolved before it's deleted
      if (toolInterfaceRef.current) {
        console.log('[App] 🔓 Calling tool executor handleApprovalResponse directly');
        toolInterfaceRef.current.handleApprovalResponse(pendingTask.id, true);
        console.log('[App] ✅ Tool executor notified successfully');
      } else {
        console.error('[App] ❌ CRITICAL: No tool interface available!');
      }
      
      // Log to terminal
      if (activePtyId) {
        try {
          pty.writePTY(activePtyId, `[APPROVED] ${pendingTask.description}\n`);
          if (feedback) {
            pty.writePTY(activePtyId, `   Feedback: ${feedback}\n`);
          }
        } catch (error) {
          console.log('[App] Terminal write failed:', error);
          console.log('✅ Approved:', pendingTask.description, feedback);
        }
      }
    }
    
    console.log('[App] 🎭 Hiding approval modal');
    setPendingTask(null);
  };

  const handleDeny = (reason?: string) => {
    console.log('[App] ❌ User denied task:', pendingTask?.id);
    if (reason) console.log('[App] Reason:', reason);
    
    if (pendingTask) {
      // CRITICAL FIX: Call handleApprovalResponse directly on the tool executor
      // This ensures the callback is resolved before it's deleted
      if (toolInterfaceRef.current) {
        console.log('[App] 🔓 Calling tool executor handleApprovalResponse directly (denied)');
        toolInterfaceRef.current.handleApprovalResponse(pendingTask.id, false);
        console.log('[App] ❌ Tool executor notified successfully (denied)');
      } else {
        console.error('[App] ❌ CRITICAL: No tool interface available!');
      }
      
      // Log to terminal
      if (activePtyId) {
        try {
          pty.writePTY(activePtyId, `[DENIED] ${pendingTask.description}\n`);
          if (reason) {
            pty.writePTY(activePtyId, `   Reason: ${reason}\n`);
          }
        } catch (error) {
          console.log('[App] Terminal write failed:', error);
          console.log('❌ Denied:', pendingTask.description, reason);
        }
      }
    }
    
    console.log('[App] 🎭 Hiding approval modal');
    setPendingTask(null);
  };

  const handleCheckpointApprove = () => {
    if (pendingCheckpoint && activePtyId) {
      try {
        pty.writePTY(activePtyId, `\n[CHECKPOINT] Approved: ${pendingCheckpoint.reason}\n`);
      } catch {
        console.log('[CHECKPOINT] Approved:', pendingCheckpoint.reason);
      }
    }
    setPendingCheckpoint(null);
  };

  const handleCheckpointDeny = () => {
    if (pendingCheckpoint && activePtyId) {
      try {
        pty.writePTY(activePtyId, `\n[CHECKPOINT] Denied: ${pendingCheckpoint.reason}\n`);
      } catch {
        console.log('[CHECKPOINT] Denied:', pendingCheckpoint.reason);
      }
    }
    setPendingCheckpoint(null);
    setIsHunting(false);
  };

  // Get color for message type
  const getMessageColor = (type: AIReasoningType): string => {
    switch (type) {
      case AIReasoningType.SUCCESS: return 'text-green-400';
      case AIReasoningType.ERROR: return 'text-red-400';
      case AIReasoningType.WARNING: return 'text-yellow-400';
      case AIReasoningType.ANALYSIS: return 'text-blue-400';
      case AIReasoningType.PLANNING: return 'text-purple-400';
      case AIReasoningType.DECISION: return 'text-cyan-400';
      case AIReasoningType.HYPOTHESIS: return 'text-pink-400';
      case AIReasoningType.RECOMMENDATION: return 'text-orange-400';
      default: return 'text-gray-300';
    }
  };

  return (
    <div className="min-h-screen bg-space-950 text-slate-100">
      {/* Header */}
      <header className="bg-space-900 border-b border-space-800 px-6 py-4 shadow-lg">
        <div className="container mx-auto flex items-center justify-between">
          <h1 className="text-2xl font-bold tracking-ultra-wide">
            <span className="text-red-500">HUNTRESS</span>
            <span className="text-space-500 text-xs ml-3 font-medium uppercase tracking-wider">Penetration Testing Platform</span>
          </h1>
          
          {/* Status Indicators */}
          <div className="flex items-center space-x-3">
            {/* Proxy Pool Status */}
            <div className="text-xs bg-space-800 px-3 py-1.5 rounded border border-space-700 font-mono">
              <span className="text-space-400 uppercase tracking-wide">Proxies:</span>{' '}
              <span className="text-green-400 font-semibold">{proxyPool.stats.active}</span>
              <span className="text-space-600">/{proxyPool.stats.total}</span>
            </div>

            {/* Kill Switch Status */}
            <div className={`text-xs px-3 py-1.5 rounded border font-semibold tracking-wide ${
              killSwitch.status.active
                ? 'bg-red-900/50 border-red-500 text-red-200 animate-pulse'
                : 'bg-space-800 border-space-700 text-space-400'
            }`}>
              {killSwitch.status.active ? 'KILL SWITCH ACTIVE' : 'SYSTEM OPERATIONAL'}
            </div>

            {/* Emergency Stop Button */}
            {isHunting && (
              <button
                onClick={handleEmergencyStop}
                className="px-4 py-2 bg-red-600 text-white rounded border border-red-500 hover:bg-red-700 font-semibold transition-all duration-200 uppercase tracking-wide text-xs"
                title="Emergency Stop - Activates kill switch"
              >
                Emergency Stop
              </button>
            )}
          </div>
          
          <div className="text-xs text-space-500 uppercase tracking-wider font-medium">
            Autonomous Security Platform
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="bg-space-900 border-b border-space-800">
        <div className="container mx-auto flex space-x-1 px-6 py-3">
          <button
            onClick={() => setActiveTab('scope')}
            className={`px-5 py-2.5 rounded font-semibold text-xs uppercase tracking-wider transition-all duration-200 ${
              activeTab === 'scope'
                ? 'bg-red-600 text-white shadow-lg'
                : 'bg-space-800 text-space-400 hover:bg-space-700 hover:text-space-300'
            }`}
          >
            Scope
          </button>
          <button
            onClick={() => setActiveTab('hunt')}
            className={`px-5 py-2.5 rounded font-semibold text-xs uppercase tracking-wider transition-all duration-200 ${
              activeTab === 'hunt'
                ? 'bg-red-600 text-white shadow-lg'
                : 'bg-space-800 text-space-400 hover:bg-space-700 hover:text-space-300'
            }`}
            disabled={scope.length === 0}
          >
            Hunt
          </button>
          <button
            onClick={() => setActiveTab('results')}
            className={`px-5 py-2.5 rounded font-semibold text-xs uppercase tracking-wider transition-all duration-200 ${
              activeTab === 'results'
                ? 'bg-red-600 text-white shadow-lg'
                : 'bg-space-800 text-space-400 hover:bg-space-700 hover:text-space-300'
            }`}
          >
            Results
          </button>
          <button
            onClick={() => setActiveTab('oauth-test')}
            className={`px-5 py-2.5 rounded font-semibold text-xs uppercase tracking-wider transition-all duration-200 ${
              activeTab === 'oauth-test'
                ? 'bg-red-600 text-white shadow-lg'
                : 'bg-space-800 text-space-400 hover:bg-space-700 hover:text-space-300'
            }`}
          >
            OAuth Test
          </button>
        </div>
      </nav>

      {/* Main Content */}
      <main className="container mx-auto p-6">
        {activeTab === 'scope' && (
          <div className="space-y-6">
            {/* Guidelines Importer */}
            <GuidelinesImporter onImport={handleGuidelinesImport} />
            
            {/* Program Guidelines Display */}
            {guidelines && (
              <div className="bg-gray-800 rounded-lg shadow-xl p-6">
                <h3 className="text-xl font-bold text-white mb-4">
                  Program: {guidelines.programName}
                </h3>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div className="bg-gray-900 rounded p-4">
                    <h4 className="font-semibold text-green-400 mb-2">Bounty Range</h4>
                    <p className="text-2xl font-bold text-white">
                      ${guidelines.bountyRange.min.toLocaleString()} - ${guidelines.bountyRange.max.toLocaleString()}
                    </p>
                  </div>
                  
                  <div className="bg-gray-900 rounded p-4">
                    <h4 className="font-semibold text-blue-400 mb-2">Scope</h4>
                    <p className="text-2xl font-bold text-white">
                      {guidelines.scope.inScope.length} in-scope targets
                    </p>
                    <p className="text-sm text-gray-400">
                      {guidelines.scope.outOfScope.length} out-of-scope
                    </p>
                  </div>
                </div>
                
                {guidelines.rules.length > 0 && (
                  <div className="bg-gray-900 rounded p-4 mb-4">
                    <h4 className="font-semibold text-yellow-400 mb-2">Program Rules</h4>
                    <ul className="text-sm text-gray-300 space-y-1">
                      {guidelines.rules.slice(0, 5).map((rule, idx) => (
                        <li key={idx} className="flex items-start">
                          <span className="text-yellow-400 mr-2">•</span>
                          <span>{rule.substring(0, 100)}{rule.length > 100 ? '...' : ''}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                
                <div className="text-xs text-gray-500">
                  Imported: {new Date(guidelines.importedAt).toLocaleString()}
                </div>
              </div>
            )}
            
            {/* Manual Scope Importer */}
            <div className="bg-gray-800 rounded-lg shadow-xl">
              <ScopeImporter onImport={handleScopeImport} />
              
              {scope.length > 0 && (
                <div className="p-4 border-t border-gray-700">
                  <h4 className="font-semibold mb-2">Current Scope ({scope.length} targets):</h4>
                  <div className="bg-gray-900 rounded p-3 max-h-48 overflow-y-auto">
                    {scope.map((entry, idx) => (
                      <div key={idx} className="text-sm text-gray-300 py-1">
                        <span className={entry.inScope ? 'text-green-400' : 'text-red-400'}>
                          [{entry.inScope ? 'IN' : 'OUT'}]
                        </span> {entry.target}
                        {entry.notes && <span className="text-gray-500 ml-2">({entry.notes})</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'hunt' && (
          <div className="bg-gray-800 rounded-lg shadow-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-2xl font-bold">Configure Hunt</h2>
              {guidelines && (
                <div className="text-sm bg-blue-900/30 border border-blue-500/30 px-3 py-1 rounded">
                  <span className="text-blue-300">Program: {guidelines.programName}</span>
                </div>
              )}
            </div>
            
            <div className="space-y-4">
              <div>
                <h3 className="text-lg font-semibold mb-2">Active Agents</h3>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    'IDOR Hunter',
                    'GraphQL Hunter',
                    'OAuth Hunter',
                    'Open Redirect',
                    'SSTI Hunter',
                    'Host Header',
                    'Prototype Pollution'
                  ].map((agent) => (
                    <label key={agent} className="flex items-center space-x-2 bg-gray-700 p-3 rounded cursor-pointer hover:bg-gray-600">
                      <input type="checkbox" defaultChecked className="form-checkbox" />
                      <span>{agent}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="pt-4 space-y-3">
                <button
                  onClick={isHunting ? handleStopHunt : handleStartHunt}
                  disabled={scope.length === 0 || killSwitch.status.active}
                  className={`w-full px-6 py-3 rounded-lg font-semibold transition-colors ${
                    isHunting
                      ? 'bg-yellow-600 hover:bg-yellow-700 text-white'
                      : 'bg-red-600 hover:bg-red-700 text-white disabled:bg-gray-600 disabled:cursor-not-allowed'
                  }`}
                >
                  {isHunting ? 'STOP HUNT' : 'START HUNT'}
                </button>

                {killSwitch.status.active && (
                  <button
                    onClick={() => killSwitch.reset()}
                    disabled={killSwitch.loading}
                    className="w-full px-6 py-3 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
                  >
                    {killSwitch.loading ? 'RESETTING...' : 'RESET KILL SWITCH'}
                  </button>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'results' && (
          <div className="bg-gray-800 rounded-lg shadow-xl p-6">
            <h2 className="text-2xl font-bold mb-4">Hunt Results</h2>
            
            {isHunting ? (
              <div className="space-y-4">
                {/* Progress Stats */}
                <div className="grid grid-cols-4 gap-4">
                  <div className="bg-gray-900 rounded-lg p-4">
                    <div className="text-xs text-gray-400 mb-1">Phase</div>
                    <div className="text-lg font-semibold text-blue-400">
                      {currentPhase.replace(/_/g, ' ').toUpperCase()}
                    </div>
                  </div>
                  <div className="bg-gray-900 rounded-lg p-4">
                    <div className="text-xs text-gray-400 mb-1">Tools Executed</div>
                    <div className="text-lg font-semibold text-green-400">{toolsExecuted}</div>
                  </div>
                  <div className="bg-gray-900 rounded-lg p-4">
                    <div className="text-xs text-gray-400 mb-1">Findings</div>
                    <div className="text-lg font-semibold text-yellow-400">{findingsCount}</div>
                  </div>
                  <div className="bg-gray-900 rounded-lg p-4">
                    <div className="text-xs text-gray-400 mb-1">Status</div>
                    <div className="flex items-center space-x-2">
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-red-500"></div>
                      <span className="text-sm text-red-400">Active</span>
                    </div>
                  </div>
                </div>

                {/* Terminal Output - ALL AI output appears here */}
                <div className="bg-black rounded-lg overflow-hidden" style={{ height: '300px' }}>
                  <Terminal ptyId={activePtyId} />
                </div>

                {/* Hunt Controls */}
                <div className="flex space-x-3 mt-4">
                  <button
                    onClick={handleStopHunt}
                    disabled={!isHunting}
                    className="px-4 py-2 bg-yellow-600 text-white rounded hover:bg-yellow-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
                  >
                    STOP HUNT
                  </button>
                  <button
                    onClick={handleEmergencyStop}
                    disabled={!isHunting}
                    className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
                  >
                    EMERGENCY STOP
                  </button>
                </div>
              </div>
            ) : (
              <div className="text-center text-gray-400 py-12">
                <div className="text-2xl mb-4 text-gray-600 font-bold tracking-widest">HUNTRESS</div>
                <p>No active hunt. Configure and start a hunt to see results.</p>
                {aiMessages.length > 0 && (
                  <div className="mt-4 text-sm">
                    <p className="text-green-400">Last hunt completed</p>
                    <p className="text-gray-500">Tools executed: {toolsExecuted} | Findings: {findingsCount}</p>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {activeTab === 'oauth-test' && (
          <OAuthTester />
        )}
      </main>

      {/* Approval Modal */}
      {pendingTask && (
        <ApproveDenyModal
          task={pendingTask}
          onApprove={handleApprove}
          onDeny={handleDeny}
        />
      )}

      {/* Checkpoint Modal */}
      {pendingCheckpoint && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-2xl w-full border border-gray-700">
            <h2 className="text-2xl font-bold text-white mb-4">CHECKPOINT REQUIRED</h2>
            
            <div className="mb-4">
              <div className="text-lg text-gray-300 mb-2">{pendingCheckpoint.reason}</div>
              <div className="text-sm text-gray-400">
                Phase: <span className="text-blue-400">{pendingCheckpoint.phase.replace(/_/g, ' ').toUpperCase()}</span>
              </div>
            </div>

            <div className="bg-gray-900 rounded p-4 mb-4">
              <h3 className="text-sm font-semibold text-gray-300 mb-2">Context</h3>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <span className="text-gray-400">Tools Executed:</span>{' '}
                  <span className="text-white">{pendingCheckpoint.context.toolsExecuted}</span>
                </div>
                <div>
                  <span className="text-gray-400">Findings:</span>{' '}
                  <span className="text-white">{pendingCheckpoint.context.findingsCount}</span>
                </div>
                <div className="col-span-2">
                  <span className="text-gray-400">Target:</span>{' '}
                  <span className="text-white">{pendingCheckpoint.context.currentTarget}</span>
                </div>
                {pendingCheckpoint.context.nextAction && (
                  <div className="col-span-2">
                    <span className="text-gray-400">Next Action:</span>{' '}
                    <span className="text-white">{pendingCheckpoint.context.nextAction}</span>
                  </div>
                )}
              </div>
            </div>

            <div className="flex justify-end space-x-4">
              <button
                onClick={handleCheckpointDeny}
                className="px-6 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition-colors"
              >
                STOP HUNT
              </button>
              <button
                onClick={handleCheckpointApprove}
                className="px-6 py-2 bg-green-600 text-white rounded hover:bg-green-700 transition-colors"
              >
                CONTINUE
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="bg-space-900 border-t border-space-800 px-6 py-4 mt-8">
        <div className="container mx-auto text-center text-xs text-space-500 uppercase tracking-wider font-medium">
          Huntress v1.0 • Autonomous Security Platform • NSA-Grade Penetration Testing
        </div>
      </footer>
    </div>
  );
}

export default App;

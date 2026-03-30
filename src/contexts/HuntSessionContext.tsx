/**
 * Hunt Session Context
 *
 * Wraps OrchestratorEngine + ConversationManager.
 * Provides session state to all components.
 * Always shows user messages immediately; shows errors when engine can't initialize.
 */

import React, { createContext, useContext, useState, useRef, useCallback, useEffect, useMemo, ReactNode } from 'react';
import { OrchestratorEngine } from '../core/orchestrator/orchestrator_engine';
import type { ConversationMessage, SessionPhase, FindingCardMessage, StrategyOption, BriefingMessage } from '../core/conversation/types';
import type { ModelProvider } from '../core/providers/types';
import { getProviderFactory } from '../core/providers/provider_factory';
import { useSettings } from './SettingsContext';
import type { ProgramGuidelines } from '../components/GuidelinesImporter';
import { HackerOneAPI } from '../core/reporting/h1_api';
import type { H1Report } from '../core/reporting/h1_api';
import { KnowledgeGraph } from '../core/knowledge/knowledge_graph';
import type { OverallStats } from '../core/knowledge/knowledge_graph';
import { VulnDatabase } from '../core/knowledge/vuln_database';
import { RewardSystem } from '../core/training/reward_system';
import type { TrustLevel, RewardMetrics } from '../core/training/reward_system';
import { HttpClient } from '../core/http/request_engine';
import { SessionManager } from '../core/auth/session_manager';
import { HuntMemory } from '../core/memory/hunt_memory';
import { NucleiRunner } from '../core/discovery/nuclei_runner';
import { WAFDetector } from '../core/evasion/waf_detector';
import { ChainValidator } from '../core/orchestrator/chain_validator';
import { RateController } from '../core/http/rate_controller';
import { StealthModule } from '../core/evasion/stealth';
import { TargetDeduplicator } from '../core/orchestrator/target_dedup';
import { H1DuplicateChecker } from '../core/reporting/h1_duplicate_check';
import { ReportQualityScorer } from '../core/reporting/report_quality';
import { ContinuousMonitor } from '../core/discovery/continuous_monitor';
import { checkToolHealth, getAvailableToolsSummary } from '../core/tools/tool_health';
import { invoke } from '@tauri-apps/api/core';
import type { CommandResult } from '../core/engine/react_loop';
import { TraceStore } from '../core/tracing/trace_store';
import { TracedModelProvider } from '../core/tracing/traced_provider';
import { CostTracker } from '../core/tracing/cost_tracker';

// ─── Session Persistence ──────────────────────────────────────────────────────

const SESSION_STORAGE_KEY = 'huntress_session';
const AUTO_SAVE_INTERVAL_MS = 30_000;
const KNOWLEDGE_DB_PATH = 'huntress_knowledge.db';

interface PersistedSession {
  messages: ConversationMessage[];
  findings: FindingCardMessage[];
  phase: SessionPhase;
  activeAgents: ActiveAgent[];
  savedAt: number;
}

function saveSessionToDisk(data: PersistedSession): void {
  try {
    localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(data));
  } catch {
    // localStorage quota exceeded — silently ignore
  }
}

function loadSessionFromDisk(): PersistedSession | null {
  try {
    const raw = localStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as PersistedSession;
  } catch {
    return null;
  }
}

function clearPersistedSession(): void {
  localStorage.removeItem(SESSION_STORAGE_KEY);
}

export interface ActiveAgent {
  id: string;
  name: string;
  status: 'running' | 'waiting' | 'completed' | 'failed';
  toolsExecuted: number;
  findingsCount: number;
}

interface HuntSessionContextType {
  /** Whether the orchestrator is initialized and ready */
  isReady: boolean;
  /** Current session phase */
  phase: SessionPhase;
  /** All conversation messages */
  messages: ConversationMessage[];
  /** Currently active agents */
  activeAgents: ActiveAgent[];
  /** Discovered findings */
  findings: FindingCardMessage[];
  /** Whether a hunt is currently running */
  isHunting: boolean;
  /** The orchestrator engine reference */
  engine: OrchestratorEngine | null;

  /** Initialize the engine with current settings */
  initializeEngine: () => OrchestratorEngine | null;
  /** Send a message from the user */
  sendMessage: (input: string) => Promise<void>;
  /** Import and analyze a bounty program */
  importProgram: (guidelines: ProgramGuidelines) => Promise<void>;
  /** Select an attack strategy */
  selectStrategy: (strategy: StrategyOption) => Promise<void>;
  /** Submit a report to HackerOne */
  submitToH1: (report: H1Report, programHandle: string) => Promise<void>;
  /** Reset the session */
  resetSession: () => void;
  /** Whether the knowledge systems (KG, VulnDB, Reward) are initialized */
  knowledgeReady: boolean;
  /** Get overall stats from the knowledge graph */
  getOverallStats: () => Promise<OverallStats | null>;
  /** Get agent trust level from the reward system */
  getAgentTrustLevel: (agentId: string) => Promise<TrustLevel | null>;
  /** Get reward system metrics for dashboard display */
  getRewardMetrics: () => Promise<RewardMetrics | null>;
}

const HuntSessionContext = createContext<HuntSessionContextType | undefined>(undefined);

let msgCounter = 0;
function generateId(): string {
  return `msg_${Date.now()}_${++msgCounter}`;
}

export const HuntSessionProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const { settings, getApiKey } = useSettings();
  const [messages, setMessages] = useState<ConversationMessage[]>([]);
  const [phase, setPhase] = useState<SessionPhase>('idle');
  const [activeAgents, setActiveAgents] = useState<ActiveAgent[]>([]);
  const [findings, setFindings] = useState<FindingCardMessage[]>([]);
  const [isHunting, setIsHunting] = useState(false);
  const [isReady, setIsReady] = useState(false);
  const [knowledgeReady, setKnowledgeReady] = useState(false);
  const [availableSecurityTools, setAvailableSecurityTools] = useState<string[]>([]);
  const engineRef = useRef<OrchestratorEngine | null>(null);
  const kgRef = useRef<KnowledgeGraph | null>(null);
  const vulnDbRef = useRef<VulnDatabase | null>(null);
  const rewardRef = useRef<RewardSystem | null>(null);
  const httpClientRef = useRef<HttpClient | null>(null);
  const sessionManagerRef = useRef<SessionManager | null>(null);
  const huntMemoryRef = useRef<HuntMemory | null>(null);
  const nucleiRunnerRef = useRef<NucleiRunner | null>(null);
  const wafDetectorRef = useRef<WAFDetector | null>(null);
  const chainValidatorRef = useRef<ChainValidator | null>(null);
  const rateControllerRef = useRef<RateController | null>(null);
  const stealthModuleRef = useRef<StealthModule | null>(null);
  const targetDedupRef = useRef<TargetDeduplicator | null>(null);
  const h1DuplicateCheckerRef = useRef<H1DuplicateChecker | null>(null);
  const reportQualityRef = useRef<ReportQualityScorer | null>(null);
  const continuousMonitorRef = useRef<ContinuousMonitor | null>(null);
  const traceStoreRef = useRef<TraceStore | null>(null);
  const costTrackerRef = useRef<CostTracker | null>(null);

  const addMessage = useCallback((message: ConversationMessage) => {
    setMessages(prev => [...prev, message]);
    if (message.type === 'finding_card') {
      setFindings(prev => [...prev, message]);
    }
  }, []);

  const handlePhaseChange = useCallback((newPhase: SessionPhase) => {
    setPhase(newPhase);
    setIsHunting(newPhase === 'hunting');
  }, []);

  const initializeEngine = useCallback((): OrchestratorEngine | null => {
    const { providerId, modelId } = settings.orchestratorModel;
    const apiKey = getApiKey(providerId);

    if (!apiKey && providerId !== 'local') {
      return null;
    }

    try {
      const factory = getProviderFactory();
      const rawProvider: ModelProvider = factory.create(providerId, { apiKey });

      // Initialize tracing & cost tracking
      if (!traceStoreRef.current) {
        traceStoreRef.current = new TraceStore({ persistIntervalMs: 0 });
      }
      if (!costTrackerRef.current) {
        costTrackerRef.current = new CostTracker(traceStoreRef.current);
      }

      const sessionId = `hunt_${Date.now()}`;
      const budgetLimit = settings.budgetLimitUsd ?? 5; // Default $5 budget

      // Set session budget in cost tracker
      costTrackerRef.current.setSessionBudget(sessionId, {
        maxSessionCostUsd: budgetLimit,
        maxAgentCostUsd: budgetLimit * 0.2, // 20% per agent
        warningThreshold: 0.8,
        hardStop: true,
      });

      // Wrap provider with tracing + budget enforcement
      const tracedProvider = new TracedModelProvider(
        rawProvider,
        traceStoreRef.current,
        {
          sessionId,
          spanId: `orchestrator_${sessionId}`,
          callerType: 'orchestrator',
          budget: {
            maxSessionCostUsd: budgetLimit,
            maxAgentCostUsd: budgetLimit * 0.2,
            warningThreshold: 0.8,
            hardStop: true,
          },
          onBudgetWarning: (status) => {
            addMessage({
              type: 'system',
              id: generateId(),
              content: `⚠️ Budget warning: $${status.spent.toFixed(2)} of $${status.limit.toFixed(2)} spent (${(status.percentUsed * 100).toFixed(0)}%). Consider pausing the hunt.`,
              level: 'warning',
              timestamp: Date.now(),
            });
          },
          onBudgetExceeded: (status) => {
            addMessage({
              type: 'system',
              id: generateId(),
              content: `🛑 Budget exceeded: $${status.spent.toFixed(2)} of $${status.limit.toFixed(2)} limit reached. Hunt will be paused.`,
              level: 'error',
              timestamp: Date.now(),
            });
          },
        }
      );
      const provider: ModelProvider = tracedProvider;

      // Create shared HTTP client if not yet initialized
      if (!httpClientRef.current) {
        httpClientRef.current = new HttpClient({
          defaultHeaders: { 'User-Agent': 'Huntress/1.0' },
        });
      }

      // Create session manager (depends on HTTP client)
      if (!sessionManagerRef.current) {
        sessionManagerRef.current = new SessionManager(httpClientRef.current);
      }

      // Create hunt memory (Qdrant-backed, graceful degradation if unavailable)
      if (!huntMemoryRef.current) {
        huntMemoryRef.current = new HuntMemory(null);
        // Initialize asynchronously — non-blocking
        huntMemoryRef.current.initialize().catch(() => {
          // Qdrant unavailable — hunt memory operates in degraded mode
        });
      }

      // Phase 20F: Nuclei template scanner
      if (!nucleiRunnerRef.current) {
        nucleiRunnerRef.current = new NucleiRunner();
      }

      // Phase 20G: WAF detector (depends on HTTP client)
      if (!wafDetectorRef.current && httpClientRef.current) {
        wafDetectorRef.current = new WAFDetector(httpClientRef.current);
      }

      // Phase 20I: Chain validator (depends on HTTP client, optionally on provider)
      if (!chainValidatorRef.current && httpClientRef.current) {
        chainValidatorRef.current = new ChainValidator(httpClientRef.current, provider, modelId);
      }

      // Phase 20J: Adaptive rate controller and stealth module
      if (!rateControllerRef.current) {
        rateControllerRef.current = new RateController({ initialRate: 2, maxRate: 10 });
      }
      if (!stealthModuleRef.current) {
        stealthModuleRef.current = new StealthModule();
      }

      // Phase 23B: Target deduplicator (depends on HTTP client)
      if (!targetDedupRef.current && httpClientRef.current) {
        targetDedupRef.current = new TargetDeduplicator({ httpClient: httpClientRef.current });
      }

      // Phase 23C: H1 duplicate checker (uses H1 credentials if available)
      if (!h1DuplicateCheckerRef.current) {
        h1DuplicateCheckerRef.current = new H1DuplicateChecker({
          h1Username: getApiKey('hackerone_username') ?? undefined,
          h1ApiToken: getApiKey('hackerone') ?? undefined,
        });
      }

      // Phase 23E: Report quality scorer
      if (!reportQualityRef.current) {
        reportQualityRef.current = new ReportQualityScorer();
      }

      // Phase 23G: Continuous monitor (non-blocking initialization)
      if (!continuousMonitorRef.current) {
        continuousMonitorRef.current = new ContinuousMonitor({
          domains: [],
          crtshEnabled: true,
        });
      }

      // PTY-backed command execution for agents
      const executeViaPty = async (command: string, _target: string): Promise<CommandResult> => {
        const start = performance.now();
        try {
          const parts = command.split(/\s+/);
          const program = parts[0];
          const args = parts.slice(1);

          const sessionId = await invoke<string>('spawn_pty', { command: program, args });

          let output = '';
          let consecutiveEmpty = 0;
          for (let i = 0; i < 300; i++) { // 30s max (300 * 100ms)
            try {
              const chunk = await invoke<string>('read_pty', { sessionId });
              if (chunk && chunk.length > 0) {
                output += chunk;
                consecutiveEmpty = 0;
              } else {
                consecutiveEmpty++;
                if (output.length > 0 && consecutiveEmpty >= 20) break;
              }
            } catch { consecutiveEmpty++; }
            await new Promise(r => setTimeout(r, 100));
          }

          await invoke('kill_pty', { sessionId }).catch(() => {});

          return {
            success: true,
            stdout: output,
            stderr: '',
            exitCode: 0,
            executionTimeMs: performance.now() - start,
          };
        } catch (err) {
          return {
            success: false,
            stdout: '',
            stderr: err instanceof Error ? err.message : String(err),
            exitCode: 1,
            executionTimeMs: performance.now() - start,
          };
        }
      };

      // Approval gate callback: bridges orchestrator ApprovalRequest → UI modal → boolean
      const onApprovalRequest = async (request: {
        command: string;
        target: string;
        reasoning: string;
        category: string;
        toolName?: string;
        safetyWarnings?: string[];
        agent?: string;
      }): Promise<boolean> => {
        const approvalId = `approval_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

        // Ensure the global callback map exists (matches tool_executor.ts pattern)
        const win = window as unknown as {
          __huntress_approval_callbacks?: Map<string, (approved: boolean) => void>;
        };
        if (!win.__huntress_approval_callbacks) {
          win.__huntress_approval_callbacks = new Map();
        }

        return new Promise<boolean>((resolve) => {
          // Store resolver so App.tsx handleApprove/handleDeny can call it
          win.__huntress_approval_callbacks!.set(approvalId, resolve);

          // Dispatch event in the same format App.tsx expects (line 407)
          window.dispatchEvent(
            new CustomEvent('tool-approval-request', {
              detail: {
                approvalId,
                request: {
                  command: request.command,
                  target: request.target,
                  tool: {
                    name: request.toolName ?? request.command.split(/\s+/)[0],
                    safetyLevel: request.category === 'recon' || request.category === 'utility'
                      ? 'SAFE'
                      : request.category === 'active_testing'
                        ? 'DANGEROUS'
                        : 'RESTRICTED',
                  },
                  validation: {
                    reasoning: request.reasoning,
                    agent: request.agent ?? 'unknown',
                    warnings: request.safetyWarnings ?? [],
                  },
                },
              },
            })
          );
        });
      };

      const engine = new OrchestratorEngine({
        provider,
        model: modelId,
        autoApproveSafe: settings.autoApprove?.passiveRecon ?? false,
        onApprovalRequest,
        onExecuteCommand: executeViaPty,
        knowledgeGraph: kgRef.current ?? undefined,
        vulnDb: vulnDbRef.current ?? undefined,
        rewardSystem: rewardRef.current ?? undefined,
        httpClient: httpClientRef.current,
        sessionManager: sessionManagerRef.current,
        huntMemory: huntMemoryRef.current,
        nucleiRunner: nucleiRunnerRef.current,
        wafDetector: wafDetectorRef.current ?? undefined,
        chainValidator: chainValidatorRef.current ?? undefined,
        rateController: rateControllerRef.current,
        stealthModule: stealthModuleRef.current,
        targetDedup: targetDedupRef.current ?? undefined,
        h1DuplicateChecker: h1DuplicateCheckerRef.current ?? undefined,
        reportQuality: reportQualityRef.current ?? undefined,
        continuousMonitor: continuousMonitorRef.current ?? undefined,
        availableTools: availableSecurityTools.length > 0 ? availableSecurityTools : undefined,
        getBudgetStatus: () => tracedProvider.getBudgetStatus(),
        budgetLimitUsd: budgetLimit,
      });

      engine.setMessageCallback(addMessage);
      engine.setPhaseCallback(handlePhaseChange);

      engineRef.current = engine;
      setIsReady(true);

      return engine;
    } catch (error) {
      console.error('Failed to initialize orchestrator:', error);
      return null;
    }
  }, [settings.orchestratorModel, getApiKey, addMessage, handlePhaseChange]);

  const sendMessage = useCallback(async (input: string) => {
    // Try to get or initialize engine
    const engine = engineRef.current ?? initializeEngine();
    if (!engine) {
      const { providerId } = settings.orchestratorModel;
      addMessage({
        type: 'system',
        id: generateId(),
        content: `No API key configured for ${providerId}. Go to Settings to add your API key.`,
        level: 'error',
        timestamp: Date.now(),
      });
      return;
    }

    // Route through the orchestrator engine which handles tool use,
    // agent dispatch, and conversation management. processUserInput
    // adds the user message and emits all messages via the callback.
    try {
      await engine.processUserInput(input);
    } catch (error) {
      addMessage({
        type: 'system',
        id: generateId(),
        content: `Error: ${error instanceof Error ? error.message : String(error)}`,
        level: 'error',
        timestamp: Date.now(),
      });
    }
  }, [initializeEngine, settings.orchestratorModel, addMessage]);

  const importProgram = useCallback(async (guidelines: ProgramGuidelines) => {
    // Always show the import in chat, even if engine fails
    const importMsg: ConversationMessage = {
      type: 'system',
      id: generateId(),
      content: `Importing program: ${guidelines.programName}...`,
      level: 'info',
      timestamp: Date.now(),
    };
    addMessage(importMsg);

    const engine = engineRef.current ?? initializeEngine();

    if (!engine) {
      // No engine available — create a static briefing from the raw data
      const briefing: BriefingMessage = {
        type: 'briefing',
        id: generateId(),
        timestamp: Date.now(),
        programName: guidelines.programName,
        targetSummary: `Bug bounty program with ${guidelines.scope.inScope.length} in-scope targets`,
        assets: [
          ...guidelines.scope.inScope.map(t => ({ type: 'domain', target: t, inScope: true })),
          ...guidelines.scope.outOfScope.map(t => ({ type: 'domain', target: t, inScope: false })),
        ],
        bountyRange: guidelines.bountyRange,
        rules: guidelines.rules,
        strategies: [],
      };
      addMessage(briefing);

      const { providerId } = settings.orchestratorModel;
      const warnMsg: ConversationMessage = {
        type: 'system',
        id: generateId(),
        content: `No API key for ${providerId} — showing raw program data. Add your API key in Settings to get AI-powered strategy recommendations.`,
        level: 'warning',
        timestamp: Date.now(),
      };
      addMessage(warnMsg);
      return;
    }

    try {
      await engine.analyzeBountyProgram(guidelines);
    } catch (error) {
      const errorMsg: ConversationMessage = {
        type: 'system',
        id: generateId(),
        content: `Failed to analyze program: ${error instanceof Error ? error.message : String(error)}`,
        level: 'error',
        timestamp: Date.now(),
      };
      addMessage(errorMsg);
    }
  }, [initializeEngine, settings.orchestratorModel, addMessage]);

  const selectStrategy = useCallback(async (strategy: StrategyOption) => {
    const engine = engineRef.current;
    if (!engine) return;

    await engine.selectStrategy(strategy);
  }, []);

  // ── Knowledge Systems: initialize on mount ──
  useEffect(() => {
    let cancelled = false;

    async function initKnowledgeSystems(): Promise<void> {
      // Initialize each system independently — one failure shouldn't block the others
      try {
        const kg = new KnowledgeGraph(KNOWLEDGE_DB_PATH);
        await kg.initialize();
        if (cancelled) return;
        kgRef.current = kg;
      } catch (error) {
        console.warn('KnowledgeGraph initialization failed (non-fatal):', error);
      }

      try {
        const vulnDb = new VulnDatabase(KNOWLEDGE_DB_PATH);
        await vulnDb.initialize();
        if (cancelled) return;
        vulnDbRef.current = vulnDb;
      } catch (error) {
        console.warn('VulnDatabase initialization failed (non-fatal):', error);
      }

      try {
        const reward = new RewardSystem(KNOWLEDGE_DB_PATH);
        await reward.initialize();
        if (cancelled) return;
        rewardRef.current = reward;
      } catch (error) {
        console.warn('RewardSystem initialization failed (non-fatal):', error);
      }

      if (!cancelled) {
        setKnowledgeReady(true);
      }

      // Check installed security tools (non-blocking)
      try {
        const healthMap = await checkToolHealth();
        if (!cancelled) {
          setAvailableSecurityTools(getAvailableToolsSummary(healthMap));
        }
      } catch (error) {
        console.warn('Tool health check failed (non-fatal):', error);
      }
    }

    initKnowledgeSystems();
    return () => { cancelled = true; };
  }, []);

  // ── Session Persistence: auto-save every 30 seconds ──
  useEffect(() => {
    const interval = setInterval(() => {
      if (messages.length === 0) return;
      saveSessionToDisk({
        messages,
        findings,
        phase,
        activeAgents,
        savedAt: Date.now(),
      });
    }, AUTO_SAVE_INTERVAL_MS);

    return () => clearInterval(interval);
  }, [messages, findings, phase, activeAgents]);

  // ── Session Persistence: restore on mount ──
  useEffect(() => {
    const saved = loadSessionFromDisk();
    if (saved && saved.messages.length > 0) {
      setMessages(saved.messages);
      setFindings(saved.findings);
      setPhase(saved.phase);
      setActiveAgents(
        saved.activeAgents.map(a => ({ ...a, status: a.status === 'running' ? 'failed' as const : a.status }))
      );
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submitToH1 = useCallback(async (report: H1Report, programHandle: string) => {
    const h1Username = getApiKey('hackerone_username');
    const h1Token = getApiKey('hackerone');

    if (!h1Username || !h1Token) {
      throw new Error('HackerOne API credentials not configured. Go to Settings to add your API Identifier and Token.');
    }

    const api = new HackerOneAPI({
      username: h1Username,
      apiToken: h1Token,
    });

    // Test connection first
    const connected = await api.testConnection();
    if (!connected) {
      throw new Error('Failed to connect to HackerOne API. Check your credentials.');
    }

    const result = await api.submitReport({
      programHandle,
      report,
    });

    if (!result.success) {
      throw new Error(result.error ?? 'Submission failed');
    }

    // Add success message to chat
    const successMsg: ConversationMessage = {
      type: 'system',
      id: generateId(),
      content: `Report submitted to HackerOne: ${result.reportUrl ?? result.reportId}`,
      level: 'info',
      timestamp: Date.now(),
    };
    addMessage(successMsg);
  }, [getApiKey, addMessage]);

  const getOverallStats = useCallback(async (): Promise<OverallStats | null> => {
    try {
      return kgRef.current ? await kgRef.current.getOverallStats() : null;
    } catch { return null; }
  }, []);

  const getAgentTrustLevel = useCallback(async (agentId: string): Promise<TrustLevel | null> => {
    try {
      return rewardRef.current ? await rewardRef.current.getTrustLevel(agentId) : null;
    } catch { return null; }
  }, []);

  const getRewardMetrics = useCallback(async (): Promise<RewardMetrics | null> => {
    try {
      return rewardRef.current ? await rewardRef.current.exportMetrics() : null;
    } catch { return null; }
  }, []);

  const resetSession = useCallback(() => {
    engineRef.current?.reset();
    setMessages([]);
    setPhase('idle');
    setActiveAgents([]);
    setFindings([]);
    setIsHunting(false);
    clearPersistedSession();
  }, []);

  const contextValue = useMemo(() => ({
    isReady,
    phase,
    messages,
    activeAgents,
    findings,
    isHunting,
    engine: engineRef.current,
    initializeEngine,
    sendMessage,
    importProgram,
    selectStrategy,
    submitToH1,
    resetSession,
    knowledgeReady,
    getOverallStats,
    getAgentTrustLevel,
    getRewardMetrics,
  }), [isReady, phase, messages, activeAgents, findings, isHunting,
       initializeEngine, sendMessage, importProgram, selectStrategy,
       submitToH1, resetSession, knowledgeReady, getOverallStats,
       getAgentTrustLevel, getRewardMetrics]);

  return (
    <HuntSessionContext.Provider value={contextValue}>
      {children}
    </HuntSessionContext.Provider>
  );
};

export const useHuntSession = (): HuntSessionContextType => {
  const context = useContext(HuntSessionContext);
  if (!context) {
    throw new Error('useHuntSession must be used within a HuntSessionProvider');
  }
  return context;
};

export default HuntSessionContext;

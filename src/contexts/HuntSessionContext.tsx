/**
 * Hunt Session Context
 *
 * Wraps OrchestratorEngine + ConversationManager.
 * Provides session state to all components.
 * Always shows user messages immediately; shows errors when engine can't initialize.
 */

import React, { createContext, useContext, useState, useRef, useCallback, useEffect, useMemo, ReactNode } from 'react';
import { OrchestratorEngine } from '../core/orchestrator/orchestrator_engine';
import { resolveEconomyMode } from '../core/orchestrator/economy_mode';
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
import { classifyCommand } from '../core/engine/safety_policies';
import { TraceStore } from '../core/tracing/trace_store';
import { TracedModelProvider } from '../core/tracing/traced_provider';
import { CostTracker } from '../core/tracing/cost_tracker';
import { AuthDetector } from '../core/auth/auth_detector';
import type { AuthDetectionResult } from '../core/auth/auth_detector';

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

async function saveSessionToDisk(data: PersistedSession): Promise<void> {
  try {
    await invoke('store_secret', {
      key: SESSION_STORAGE_KEY,
      value: JSON.stringify(data),
    });
  } catch {
    // Secure storage unavailable — silently ignore
  }
}

async function loadSessionFromDisk(): Promise<PersistedSession | null> {
  // Try secure storage first
  try {
    const raw: string = await invoke('get_secret', { key: SESSION_STORAGE_KEY });
    if (raw) return JSON.parse(raw) as PersistedSession;
  } catch {
    // Key not found or vault unavailable — check migration path
  }

  // Migration: check if unencrypted data exists in localStorage
  try {
    const legacyRaw = localStorage.getItem(SESSION_STORAGE_KEY);
    if (legacyRaw) {
      const parsed = JSON.parse(legacyRaw) as PersistedSession;
      // Migrate to secure storage and remove plaintext
      await saveSessionToDisk(parsed);
      localStorage.removeItem(SESSION_STORAGE_KEY);
      return parsed;
    }
  } catch {
    // Corrupted legacy data — discard
  }

  return null;
}

async function clearPersistedSession(): Promise<void> {
  try {
    await invoke('delete_secret', { key: SESSION_STORAGE_KEY });
  } catch {
    // Key may not exist — ignore
  }
  // Also clear any legacy plaintext data
  localStorage.removeItem(SESSION_STORAGE_KEY);
}

export interface ActiveAgent {
  id: string;
  name: string;
  status: 'running' | 'waiting' | 'completed' | 'failed';
  toolsExecuted: number;
  findingsCount: number;
}

export interface ApprovalAuditEntry {
  timestamp: number;
  approvalId: string;
  command: string;
  target: string;
  agent: string;
  category: string;
  decision: 'approved' | 'denied';
  timedOut: boolean;
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
  /** Approval audit trail for the current session */
  approvalAuditTrail: ApprovalAuditEntry[];
  /** Auth detection result (set when wizard should appear) */
  authDetectionResult: AuthDetectionResult | null;
  /** Guidelines pending auth wizard completion */
  pendingGuidelinesForAuth: ProgramGuidelines | null;
  /** Continue after auth wizard completes — creates sessions and starts hunt */
  continueAfterAuth: () => Promise<void>;
  /** Skip auth wizard — start hunt without auth */
  skipAuth: () => Promise<void>;
  /** I4: Mid-hunt auth wizard state — non-null when the wizard is open over a running hunt */
  midHuntAuth: { detectionResult: AuthDetectionResult; guidelines: ProgramGuidelines } | null;
  /** I4: Open the auth wizard against the currently-running hunt */
  openMidHuntAuthWizard: () => void;
  /** I4: Create sessions from profiles added during the mid-hunt wizard and reprioritize */
  addAuthToActiveHunt: () => Promise<void>;
  /** I4: Close the mid-hunt auth wizard without creating sessions */
  closeMidHuntAuthWizard: () => void;
}

const HuntSessionContext = createContext<HuntSessionContextType | undefined>(undefined);

let msgCounter = 0;
function generateId(): string {
  return `msg_${Date.now()}_${++msgCounter}`;
}

export const HuntSessionProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const { settings, getApiKey, updateSettings, getAuthProfileCredentials, getRefreshConfig } = useSettings();
  const [messages, setMessages] = useState<ConversationMessage[]>([]);
  const [phase, setPhase] = useState<SessionPhase>('idle');
  const [activeAgents, setActiveAgents] = useState<ActiveAgent[]>([]);
  const [findings, setFindings] = useState<FindingCardMessage[]>([]);
  const [isHunting, setIsHunting] = useState(false);
  const [isReady, setIsReady] = useState(false);
  const [knowledgeReady, setKnowledgeReady] = useState(false);
  const [availableSecurityTools, setAvailableSecurityTools] = useState<string[]>([]);
  const [authDetectionResult, setAuthDetectionResult] = useState<AuthDetectionResult | null>(null);
  const [pendingGuidelinesForAuth, setPendingGuidelinesForAuth] = useState<ProgramGuidelines | null>(null);
  /** I4: Mid-hunt auth wizard state — when non-null, shows the wizard over an active hunt. */
  const [midHuntAuth, setMidHuntAuth] = useState<{
    detectionResult: AuthDetectionResult;
    guidelines: ProgramGuidelines;
  } | null>(null);
  /** Track the initial profile IDs so addAuthToActiveHunt knows which profiles were *just* added. */
  const profileIdsBeforeMidHuntRef = useRef<Set<string>>(new Set());
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
  const approvalAuditTrailRef = useRef<ApprovalAuditEntry[]>([]);

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

  const initializeEngine = useCallback((budgetOverride?: number): OrchestratorEngine | null => {
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
      const budgetLimit = budgetOverride ?? settings.budgetLimitUsd ?? 15;

      // Start tracing session so cost accumulation has a target
      traceStoreRef.current.startSession({
        id: sessionId,
        startedAt: Date.now(),
        status: 'active',
        programName: 'Hunt Session',
        targets: [],
      });

      // Resolve economy-mode dispatch configuration. When enabled, this
      // widens per-agent budget claim so the slower serialized hunt has
      // the funds to complete; see `src/core/orchestrator/economy_mode.ts`.
      const economyConfig = resolveEconomyMode(settings.economyMode ?? false);

      // Set session budget in cost tracker
      costTrackerRef.current.setSessionBudget(sessionId, {
        maxSessionCostUsd: budgetLimit,
        maxAgentCostUsd: budgetLimit * economyConfig.maxAgentCostFraction,
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
            maxAgentCostUsd: budgetLimit * economyConfig.maxAgentCostFraction,
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
        sessionManagerRef.current = new SessionManager(httpClientRef.current, {
          // S7/S8: Handle token refresh failures — notify user when credentials expire
          onRefreshFailed: (_sessionId, error, message) => {
            if (error === 'expired_credentials') {
              addMessage({
                type: 'system',
                id: generateId(),
                content: `Auth tokens expired — ${message}. Re-configure credentials to continue authenticated testing.`,
                level: 'warning',
                timestamp: Date.now(),
              });
            } else {
              console.warn(`[auth-refresh] ${error}: ${message}`);
            }
          },
        });
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
      // S1: Now also wires GitHub advisory search and internal memory matching
      if (!h1DuplicateCheckerRef.current) {
        h1DuplicateCheckerRef.current = new H1DuplicateChecker({
          h1Username: getApiKey('hackerone_username') ?? undefined,
          h1ApiToken: getApiKey('hackerone') ?? undefined,
          githubToken: getApiKey('github') ?? undefined,
          huntMemory: huntMemoryRef.current ?? undefined,
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

      /** Timeout for approval gate — auto-deny after this many ms */
      const APPROVAL_TIMEOUT_MS = 60_000;

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

        // I3: Auto-approval short-circuit — if the command matches a category
        // the user has explicitly opted into, skip the modal entirely.
        const autoCategory = classifyCommand(request.command);
        const autoToggles = settings.autoApprove ?? {};
        const autoApproved =
          (autoCategory === 'passive_recon' && autoToggles.passiveRecon) ||
          (autoCategory === 'safe_active_recon' && autoToggles.safeActiveRecon) ||
          (autoCategory === 'injection_passive' && autoToggles.injectionPassive);

        if (autoApproved) {
          approvalAuditTrailRef.current.push({
            timestamp: Date.now(),
            approvalId,
            command: request.command,
            target: request.target,
            agent: request.agent ?? 'unknown',
            category: `auto:${autoCategory}`,
            decision: 'approved',
            timedOut: false,
          });
          return true;
        }

        // Ensure the global callback map exists (matches tool_executor.ts pattern)
        const win = window as unknown as {
          __huntress_approval_callbacks?: Map<string, (approved: boolean) => void>;
        };
        if (!win.__huntress_approval_callbacks) {
          win.__huntress_approval_callbacks = new Map();
        }

        const approvalPromise = new Promise<boolean>((resolve) => {
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

        // Race against timeout — auto-deny after 60 seconds
        const timeoutPromise = new Promise<boolean>((resolve) => {
          setTimeout(() => {
            // Clean up the callback so it doesn't fire later
            win.__huntress_approval_callbacks?.delete(approvalId);
            console.warn(`[approval-gate] Timeout after ${APPROVAL_TIMEOUT_MS / 1000}s — auto-denied: ${request.command}`);
            resolve(false);
          }, APPROVAL_TIMEOUT_MS);
        });

        const decision = await Promise.race([approvalPromise, timeoutPromise]);

        // Record in audit trail
        const auditEntry: ApprovalAuditEntry = {
          timestamp: Date.now(),
          approvalId,
          command: request.command,
          target: request.target,
          agent: request.agent ?? 'unknown',
          category: request.category,
          decision: decision ? 'approved' : 'denied',
          timedOut: false,
        };
        // Check if it was the timeout that won
        if (!win.__huntress_approval_callbacks?.has(approvalId)) {
          auditEntry.decision = 'denied';
          auditEntry.timedOut = true;
        } else {
          win.__huntress_approval_callbacks?.delete(approvalId);
        }
        approvalAuditTrailRef.current.push(auditEntry);

        return decision;
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
        maxConcurrentAgents: economyConfig.maxConcurrentAgents,
        maxSpecialistsPerRecon: economyConfig.maxSpecialistsPerRecon,
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
    // Apply hunt budget from the import dialog to settings
    if (guidelines.huntBudgetUsd && guidelines.huntBudgetUsd > 0) {
      updateSettings({ budgetLimitUsd: guidelines.huntBudgetUsd });
    }

    // Always show the import in chat, even if engine fails
    const importMsg: ConversationMessage = {
      type: 'system',
      id: generateId(),
      content: `Importing program: ${guidelines.programName} (budget: $${guidelines.huntBudgetUsd ?? settings.budgetLimitUsd ?? 15})...`,
      level: 'info',
      timestamp: Date.now(),
    };
    addMessage(importMsg);

    const engine = engineRef.current ?? initializeEngine(guidelines.huntBudgetUsd);

    // Ensure HttpClient exists for auth detection even if full engine failed
    if (!httpClientRef.current) {
      httpClientRef.current = new HttpClient({
        defaultHeaders: { 'User-Agent': 'Huntress/1.0' },
      });
    }

    // S6: Auth Detection Wizard — probe targets on every new program import.
    // Even if profiles exist from a prior program, this new target may need different auth.
    // The wizard has a Skip button for when existing credentials already cover the target.
    if (httpClientRef.current) {
      try {
        addMessage({
          type: 'system',
          id: generateId(),
          content: 'Probing targets for auth requirements...',
          level: 'info',
          timestamp: Date.now(),
        });

        const detectionResult = await AuthDetector.detect(
          guidelines.scope.inScope,
          guidelines.programName,
          guidelines.rules,
          httpClientRef.current,
        );

        if (detectionResult.requiresAuth) {
          addMessage({
            type: 'system',
            id: generateId(),
            content: `Auth wall detected (${Math.round(detectionResult.confidence * 100)}% confidence). Opening auth wizard...`,
            level: 'warning',
            timestamp: Date.now(),
          });
          setAuthDetectionResult(detectionResult);
          setPendingGuidelinesForAuth(guidelines);
          return; // Wizard will call continueAfterAuth() or skipAuth()
        }

        addMessage({
          type: 'system',
          id: generateId(),
          content: 'No auth requirements detected. Proceeding...',
          level: 'info',
          timestamp: Date.now(),
        });
      } catch (err) {
        console.warn('[auth-detector] Detection failed (non-fatal):', err);
        // Graceful degradation — proceed without auth
      }
    }

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
        content: `Engine initialization failed for ${providerId} — showing raw program data. Check Settings to verify your API key and try again.`,
        level: 'warning',
        timestamp: Date.now(),
      };
      addMessage(warnMsg);
      return;
    }

    // S4: Initialize auth sessions from configured profiles before hunt starts
    if (sessionManagerRef.current && settings.authProfiles.length > 0) {
      let sessionsCreated = 0;
      let sessionsFailed = 0;

      for (const profile of settings.authProfiles) {
        try {
          const creds = await getAuthProfileCredentials(profile.id);

          switch (profile.authType) {
            case 'bearer': {
              const token = creds.token;
              if (token) {
                await sessionManagerRef.current.loginWithBearer(
                  token,
                  profile.url ?? guidelines.scope.inScope[0] ?? '',
                  profile.label
                );
                sessionsCreated++;
              }
              break;
            }
            case 'cookie': {
              const username = creds.username;
              const password = creds.password;
              if (username && password && profile.url) {
                await sessionManagerRef.current.login({
                  username,
                  password,
                  loginUrl: profile.url,
                  usernameField: profile.usernameField,
                  passwordField: profile.passwordField,
                  csrfField: profile.csrfField,
                });
                sessionsCreated++;
              }
              break;
            }
            case 'api_key': {
              const apiKey = creds.apikey;
              if (apiKey) {
                sessionManagerRef.current.loginWithApiKey(
                  profile.headerName ?? 'X-API-Key',
                  apiKey,
                  profile.label
                );
                sessionsCreated++;
              }
              break;
            }
            case 'custom_header': {
              const headers: Record<string, string> = {};
              for (const key of profile.customHeaderKeys ?? []) {
                const val = creds[`header_${key}`];
                if (val) headers[key] = val;
              }
              if (Object.keys(headers).length > 0) {
                const runner = new (await import('../core/auth/session_manager')).AuthFlowRunner(httpClientRef.current!);
                const session = runner.createCustomSession(headers, profile.label);
                // Register with sessionManager by creating + setting headers
                sessionManagerRef.current.createSession({
                  id: session.id,
                  label: session.label,
                  authType: 'custom_header',
                });
                // Apply headers to the created session
                const stored = sessionManagerRef.current.getSession(session.id);
                if (stored) {
                  Object.assign(stored.headers, headers);
                }
                // S8: Wire refresh config for auto-refresh (all auth types)
                if (profile.hasRefreshConfig) {
                  const refreshCfg = await getRefreshConfig(profile.id);
                  if (refreshCfg) {
                    sessionManagerRef.current.setRefreshConfig(session.id, refreshCfg);
                  }
                }
                sessionsCreated++;
              }
              break;
            }
          }
        } catch (err) {
          sessionsFailed++;
          console.warn(`[auth] Failed to create session for profile "${profile.label}":`, err);
        }
      }

      if (sessionsCreated > 0 || sessionsFailed > 0) {
        const authMsg: ConversationMessage = {
          type: 'system',
          id: generateId(),
          content: sessionsCreated > 0
            ? `Auth: ${sessionsCreated} session${sessionsCreated > 1 ? 's' : ''} active${sessionsFailed > 0 ? `, ${sessionsFailed} failed` : ''}`
            : `Auth: all ${sessionsFailed} session${sessionsFailed > 1 ? 's' : ''} failed to initialize`,
          level: sessionsFailed > 0 && sessionsCreated === 0 ? 'warning' : 'info',
          timestamp: Date.now(),
        };
        addMessage(authMsg);
      }
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
  }, [initializeEngine, settings.orchestratorModel, settings.budgetLimitUsd, settings.authProfiles, updateSettings, addMessage, getAuthProfileCredentials, getRefreshConfig]);

  // S6: Continue after auth wizard — create sessions from newly-added profiles, then start hunt
  const continueAfterAuth = useCallback(async () => {
    const guidelines = pendingGuidelinesForAuth;
    if (!guidelines) return;

    // Create live sessions from any profiles just added in the wizard
    if (sessionManagerRef.current && settings.authProfiles.length > 0) {
      let sessionsCreated = 0;
      let sessionsFailed = 0;

      for (const profile of settings.authProfiles) {
        try {
          const creds = await getAuthProfileCredentials(profile.id);

          switch (profile.authType) {
            case 'bearer': {
              const token = creds.token;
              if (token) {
                await sessionManagerRef.current.loginWithBearer(
                  token,
                  profile.url ?? guidelines.scope.inScope[0] ?? '',
                  profile.label
                );
                sessionsCreated++;
              }
              break;
            }
            case 'cookie': {
              const username = creds.username;
              const password = creds.password;
              if (username && password && profile.url) {
                await sessionManagerRef.current.login({
                  username,
                  password,
                  loginUrl: profile.url,
                  usernameField: profile.usernameField,
                  passwordField: profile.passwordField,
                  csrfField: profile.csrfField,
                });
                sessionsCreated++;
              }
              break;
            }
            case 'api_key': {
              const apiKey = creds.apikey;
              if (apiKey) {
                sessionManagerRef.current.loginWithApiKey(
                  profile.headerName ?? 'X-API-Key',
                  apiKey,
                  profile.label
                );
                sessionsCreated++;
              }
              break;
            }
            case 'custom_header': {
              const headers: Record<string, string> = {};
              for (const key of profile.customHeaderKeys ?? []) {
                const val = creds[`header_${key}`];
                if (val) headers[key] = val;
              }
              if (Object.keys(headers).length > 0) {
                const runner = new (await import('../core/auth/session_manager')).AuthFlowRunner(httpClientRef.current!);
                const session = runner.createCustomSession(headers, profile.label);
                sessionManagerRef.current.createSession({
                  id: session.id,
                  label: session.label,
                  authType: 'custom_header',
                });
                const stored = sessionManagerRef.current.getSession(session.id);
                if (stored) {
                  Object.assign(stored.headers, headers);
                }
                // S8: Wire refresh config for auto-refresh (all auth types)
                if (profile.hasRefreshConfig) {
                  const refreshCfg = await getRefreshConfig(profile.id);
                  if (refreshCfg) {
                    sessionManagerRef.current.setRefreshConfig(session.id, refreshCfg);
                  }
                }
                sessionsCreated++;
              }
              break;
            }
          }
        } catch (err) {
          sessionsFailed++;
          console.warn(`[auth] Failed to create session for profile "${profile.label}":`, err);
        }
      }

      if (sessionsCreated > 0 || sessionsFailed > 0) {
        addMessage({
          type: 'system',
          id: generateId(),
          content: sessionsCreated > 0
            ? `Auth: ${sessionsCreated} session${sessionsCreated > 1 ? 's' : ''} active${sessionsFailed > 0 ? `, ${sessionsFailed} failed` : ''}`
            : `Auth: all ${sessionsFailed} session${sessionsFailed > 1 ? 's' : ''} failed to initialize`,
          level: sessionsFailed > 0 && sessionsCreated === 0 ? 'warning' : 'info',
          timestamp: Date.now(),
        });
      }
    }

    // Clear wizard state
    setAuthDetectionResult(null);
    setPendingGuidelinesForAuth(null);

    // Resume the import flow
    const engine = engineRef.current;
    if (engine) {
      try {
        await engine.analyzeBountyProgram(guidelines);
      } catch (error) {
        addMessage({
          type: 'system',
          id: generateId(),
          content: `Failed to analyze program: ${error instanceof Error ? error.message : String(error)}`,
          level: 'error',
          timestamp: Date.now(),
        });
      }
    }
  }, [pendingGuidelinesForAuth, settings.authProfiles, getAuthProfileCredentials, getRefreshConfig, addMessage]);

  // S6: Skip auth wizard — proceed without auth
  const skipAuth = useCallback(async () => {
    const guidelines = pendingGuidelinesForAuth;

    // Clear wizard state
    setAuthDetectionResult(null);
    setPendingGuidelinesForAuth(null);

    if (!guidelines) return;

    addMessage({
      type: 'system',
      id: generateId(),
      content: 'Skipping auth setup. Agents will test unauthenticated endpoints only.',
      level: 'warning',
      timestamp: Date.now(),
    });

    const engine = engineRef.current;
    if (engine) {
      try {
        await engine.analyzeBountyProgram(guidelines);
      } catch (error) {
        addMessage({
          type: 'system',
          id: generateId(),
          content: `Failed to analyze program: ${error instanceof Error ? error.message : String(error)}`,
          level: 'error',
          timestamp: Date.now(),
        });
      }
    }
  }, [pendingGuidelinesForAuth, addMessage]);

  /**
   * I4: Open the auth wizard against the currently-running hunt.
   * Builds a synthetic AuthDetectionResult (user knows auth is needed, no
   * probe required) and remembers which profiles already exist so the
   * follow-up step only creates sessions for the ones just added.
   */
  const openMidHuntAuthWizard = useCallback(() => {
    const engine = engineRef.current;
    const program = engine?.getActiveProgram();
    if (!engine || !program) {
      addMessage({
        type: 'system',
        id: generateId(),
        content: 'Cannot add auth: no active hunt.',
        level: 'warning',
        timestamp: Date.now(),
      });
      return;
    }

    profileIdsBeforeMidHuntRef.current = new Set(settings.authProfiles.map(p => p.id));

    const syntheticDetection: AuthDetectionResult = {
      requiresAuth: true,
      confidence: 1,
      probeResults: [],
      detectedAuthTypes: [],
      suggestedProfiles: [],
      manualSteps: [
        'Hunt is running. Add an auth profile below to inject authentication into pending agent dispatches.',
        'Newly dispatched agents will pick up the session automatically; already-running agents keep their current auth state.',
      ],
      programHints: [],
    };

    setMidHuntAuth({ detectionResult: syntheticDetection, guidelines: program });
  }, [settings.authProfiles, addMessage]);

  /**
   * I4: After the wizard closes, create live sessions for any profiles that
   * were added during it and trigger orchestrator reprioritization.
   */
  const addAuthToActiveHunt = useCallback(async () => {
    const engine = engineRef.current;
    const sessionManager = sessionManagerRef.current;
    const httpClient = httpClientRef.current;
    if (!engine || !sessionManager || !httpClient) {
      setMidHuntAuth(null);
      return;
    }

    const existingIds = profileIdsBeforeMidHuntRef.current;
    const newProfiles = settings.authProfiles.filter(p => !existingIds.has(p.id));

    let sessionsCreated = 0;
    let sessionsFailed = 0;

    for (const profile of newProfiles) {
      try {
        const creds = await getAuthProfileCredentials(profile.id);
        switch (profile.authType) {
          case 'bearer': {
            if (creds.token) {
              await sessionManager.loginWithBearer(
                creds.token,
                profile.url ?? engine.getActiveProgram()?.scope.inScope[0] ?? '',
                profile.label,
              );
              sessionsCreated++;
            }
            break;
          }
          case 'cookie': {
            if (creds.username && creds.password && profile.url) {
              await sessionManager.login({
                username: creds.username,
                password: creds.password,
                loginUrl: profile.url,
                usernameField: profile.usernameField,
                passwordField: profile.passwordField,
                csrfField: profile.csrfField,
              });
              sessionsCreated++;
            }
            break;
          }
          case 'api_key': {
            if (creds.apikey) {
              sessionManager.loginWithApiKey(
                profile.headerName ?? 'X-API-Key',
                creds.apikey,
                profile.label,
              );
              sessionsCreated++;
            }
            break;
          }
          case 'custom_header': {
            const headers: Record<string, string> = {};
            for (const key of profile.customHeaderKeys ?? []) {
              const val = creds[`header_${key}`];
              if (val) headers[key] = val;
            }
            if (Object.keys(headers).length > 0) {
              const runner = new (await import('../core/auth/session_manager')).AuthFlowRunner(httpClient);
              const session = runner.createCustomSession(headers, profile.label);
              sessionManager.createSession({
                id: session.id,
                label: session.label,
                authType: 'custom_header',
              });
              const stored = sessionManager.getSession(session.id);
              if (stored) Object.assign(stored.headers, headers);
              if (profile.hasRefreshConfig) {
                const refreshCfg = await getRefreshConfig(profile.id);
                if (refreshCfg) sessionManager.setRefreshConfig(session.id, refreshCfg);
              }
              sessionsCreated++;
            }
            break;
          }
        }
      } catch (err) {
        sessionsFailed++;
        console.warn(`[auth] Failed to create mid-hunt session for profile "${profile.label}":`, err);
      }
    }

    setMidHuntAuth(null);
    profileIdsBeforeMidHuntRef.current = new Set();

    if (sessionsCreated > 0) {
      engine.reprioritizeForAuth();
    }

    addMessage({
      type: 'system',
      id: generateId(),
      content: sessionsCreated > 0
        ? `Mid-hunt auth attached: ${sessionsCreated} session${sessionsCreated > 1 ? 's' : ''} active${sessionsFailed > 0 ? `, ${sessionsFailed} failed` : ''}. Queued agents will pick up auth on next dispatch.`
        : sessionsFailed > 0
          ? `Mid-hunt auth failed: ${sessionsFailed} profile${sessionsFailed > 1 ? 's' : ''} could not be activated.`
          : 'Mid-hunt auth wizard closed — no new profiles were added.',
      level: sessionsCreated > 0 ? 'success' : sessionsFailed > 0 ? 'error' : 'info',
      timestamp: Date.now(),
    });
  }, [settings.authProfiles, getAuthProfileCredentials, getRefreshConfig, addMessage]);

  const closeMidHuntAuthWizard = useCallback(() => {
    setMidHuntAuth(null);
    profileIdsBeforeMidHuntRef.current = new Set();
  }, []);

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

  // ── Session Persistence: restore on mount (async — uses secure storage) ──
  useEffect(() => {
    loadSessionFromDisk().then(saved => {
      if (saved && saved.messages.length > 0) {
        setMessages(saved.messages);
        setFindings(saved.findings);
        setPhase(saved.phase);
        setActiveAgents(
          saved.activeAgents.map((a: ActiveAgent) => ({ ...a, status: a.status === 'running' ? 'failed' as const : a.status }))
        );
      }
    }).catch(() => {
      // Restore failed — start fresh
    });
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
    approvalAuditTrail: approvalAuditTrailRef.current,
    authDetectionResult,
    pendingGuidelinesForAuth,
    continueAfterAuth,
    skipAuth,
    midHuntAuth,
    openMidHuntAuthWizard,
    addAuthToActiveHunt,
    closeMidHuntAuthWizard,
  }), [isReady, phase, messages, activeAgents, findings, isHunting,
       initializeEngine, sendMessage, importProgram, selectStrategy,
       submitToH1, resetSession, knowledgeReady, getOverallStats,
       getAgentTrustLevel, getRewardMetrics,
       authDetectionResult, pendingGuidelinesForAuth, continueAfterAuth, skipAuth,
       midHuntAuth, openMidHuntAuthWizard, addAuthToActiveHunt, closeMidHuntAuthWizard]);

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

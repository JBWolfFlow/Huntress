/**
 * Hunt Session Context
 *
 * Wraps OrchestratorEngine + ConversationManager.
 * Provides session state to all components.
 * Always shows user messages immediately; shows errors when engine can't initialize.
 */

import React, { createContext, useContext, useState, useRef, useCallback, useEffect, ReactNode } from 'react';
import { OrchestratorEngine } from '../core/orchestrator/orchestrator_engine';
import type { ConversationMessage, SessionPhase, FindingCardMessage, StrategyOption, BriefingMessage } from '../core/conversation/types';
import type { ModelProvider } from '../core/providers/types';
import { getProviderFactory } from '../core/providers/provider_factory';
import { useSettings } from './SettingsContext';
import type { ProgramGuidelines } from '../components/GuidelinesImporter';

// ─── Session Persistence ──────────────────────────────────────────────────────

const SESSION_STORAGE_KEY = 'huntress_session';
const AUTO_SAVE_INTERVAL_MS = 30_000;

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
  /** Reset the session */
  resetSession: () => void;
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
  const engineRef = useRef<OrchestratorEngine | null>(null);

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
      const provider: ModelProvider = factory.create(providerId, { apiKey });

      const engine = new OrchestratorEngine({
        provider,
        model: modelId,
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
    // Always show the user's message immediately
    const userMsg: ConversationMessage = {
      type: 'user',
      id: generateId(),
      content: input,
      timestamp: Date.now(),
    };
    addMessage(userMsg);

    // Try to get or initialize engine
    const engine = engineRef.current ?? initializeEngine();
    if (!engine) {
      const { providerId } = settings.orchestratorModel;
      const errorMsg: ConversationMessage = {
        type: 'system',
        id: generateId(),
        content: `No API key configured for ${providerId}. Go to Settings to add your API key.`,
        level: 'error',
        timestamp: Date.now(),
      };
      addMessage(errorMsg);
      return;
    }

    // Engine handles its own message emission — but we already showed user msg,
    // so we process without re-emitting the user message
    try {
      const contextMessages = engine.getConversation().getMessagesForModel();
      // Add the user message to the engine's conversation (without re-emitting)
      engine.getConversation().addMessage(userMsg);

      const response = await engine.getProvider().sendMessage(
        [...contextMessages, { role: 'user' as const, content: input }],
        {
          model: engine.getModel(),
          maxTokens: 4096,
          systemPrompt: engine.getSystemPrompt(),
        }
      );

      const responseMsg: ConversationMessage = {
        type: 'orchestrator',
        id: generateId(),
        content: response.content,
        timestamp: Date.now(),
      };
      engine.getConversation().addMessage(responseMsg);
      addMessage(responseMsg);
    } catch (error) {
      const errorMsg: ConversationMessage = {
        type: 'system',
        id: generateId(),
        content: `Error: ${error instanceof Error ? error.message : String(error)}`,
        level: 'error',
        timestamp: Date.now(),
      };
      addMessage(errorMsg);
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

  const resetSession = useCallback(() => {
    engineRef.current?.reset();
    setMessages([]);
    setPhase('idle');
    setActiveAgents([]);
    setFindings([]);
    setIsHunting(false);
    clearPersistedSession();
  }, []);

  return (
    <HuntSessionContext.Provider
      value={{
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
        resetSession,
      }}
    >
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

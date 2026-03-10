/**
 * Blackboard Shared State
 *
 * Cross-agent shared memory following the Blackboard architectural pattern.
 * Agents post observations, hypotheses, findings, and requests to the board.
 * Other agents can subscribe to entries relevant to their specialty and
 * independently notice exploitation opportunities without orchestrator routing.
 *
 * Outperforms hub-and-spoke communication by 13-57% in multi-agent security
 * testing benchmarks.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type EntryType = 'observation' | 'hypothesis' | 'finding' | 'request' | 'artifact';

export interface BlackboardEntry {
  id: string;
  agentId: string;
  type: EntryType;
  /** Category tag for filtering (e.g., 'subdomain', 'endpoint', 'credential', 'redirect') */
  category: string;
  content: Record<string, unknown>;
  timestamp: number;
  /** Agent types that should read this entry */
  relevantTo: string[];
  /** Whether this entry has been consumed/read */
  consumed: boolean;
  /** Priority: higher = more important */
  priority: number;
}

export type BlackboardEventType = 'entry_added' | 'entry_consumed' | 'cleared';

export interface BlackboardEvent {
  type: BlackboardEventType;
  entry?: BlackboardEntry;
  timestamp: number;
}

// ─── Blackboard ──────────────────────────────────────────────────────────────

export class Blackboard {
  private entries: Map<string, BlackboardEntry> = new Map();
  private listeners: Map<string, Array<(entry: BlackboardEntry) => void>> = new Map();
  private eventLog: BlackboardEvent[] = [];
  private nextId = 1;

  /** Post an entry to the blackboard. Notifies subscribed agents. */
  post(entry: Omit<BlackboardEntry, 'id' | 'timestamp' | 'consumed'>): BlackboardEntry {
    const full: BlackboardEntry = {
      ...entry,
      id: `bb_${this.nextId++}`,
      timestamp: Date.now(),
      consumed: false,
    };

    this.entries.set(full.id, full);
    this.logEvent('entry_added', full);

    // Notify listeners interested in this entry's relevantTo list
    for (const agentType of full.relevantTo) {
      const agentListeners = this.listeners.get(agentType);
      if (agentListeners) {
        for (const listener of agentListeners) {
          listener(full);
        }
      }
    }

    // Also notify wildcard listeners
    const wildcardListeners = this.listeners.get('*');
    if (wildcardListeners) {
      for (const listener of wildcardListeners) {
        listener(full);
      }
    }

    return full;
  }

  /** Read all unread entries relevant to a specific agent type */
  readFor(agentType: string): BlackboardEntry[] {
    return Array.from(this.entries.values())
      .filter(e => !e.consumed && e.relevantTo.includes(agentType))
      .sort((a, b) => b.priority - a.priority);
  }

  /** Read and mark entries as consumed for a specific agent */
  consumeFor(agentType: string): BlackboardEntry[] {
    const relevant = this.readFor(agentType);
    for (const entry of relevant) {
      entry.consumed = true;
      this.logEvent('entry_consumed', entry);
    }
    return relevant;
  }

  /** Get all entries of a specific type */
  getByType(type: EntryType): BlackboardEntry[] {
    return Array.from(this.entries.values())
      .filter(e => e.type === type)
      .sort((a, b) => b.timestamp - a.timestamp);
  }

  /** Get all entries in a specific category */
  getByCategory(category: string): BlackboardEntry[] {
    return Array.from(this.entries.values())
      .filter(e => e.category === category)
      .sort((a, b) => b.timestamp - a.timestamp);
  }

  /** Get all entries posted by a specific agent */
  getByAgent(agentId: string): BlackboardEntry[] {
    return Array.from(this.entries.values())
      .filter(e => e.agentId === agentId)
      .sort((a, b) => b.timestamp - a.timestamp);
  }

  /** Subscribe an agent type to receive new relevant entries */
  subscribe(agentType: string, callback: (entry: BlackboardEntry) => void): () => void {
    if (!this.listeners.has(agentType)) {
      this.listeners.set(agentType, []);
    }
    this.listeners.get(agentType)!.push(callback);

    return () => {
      const list = this.listeners.get(agentType);
      if (list) {
        this.listeners.set(agentType, list.filter(l => l !== callback));
      }
    };
  }

  /** Get a summary of the blackboard state */
  getSummary(): string {
    const entries = Array.from(this.entries.values());
    const byType = new Map<EntryType, number>();
    for (const e of entries) {
      byType.set(e.type, (byType.get(e.type) ?? 0) + 1);
    }

    return [
      `Blackboard: ${entries.length} entries`,
      `  Observations: ${byType.get('observation') ?? 0}`,
      `  Hypotheses: ${byType.get('hypothesis') ?? 0}`,
      `  Findings: ${byType.get('finding') ?? 0}`,
      `  Requests: ${byType.get('request') ?? 0}`,
      `  Artifacts: ${byType.get('artifact') ?? 0}`,
      `  Unconsumed: ${entries.filter(e => !e.consumed).length}`,
    ].join('\n');
  }

  /** Clear all entries */
  clear(): void {
    this.entries.clear();
    this.logEvent('cleared');
  }

  /** Get event log for debugging */
  getEventLog(): BlackboardEvent[] {
    return this.eventLog;
  }

  private logEvent(type: BlackboardEventType, entry?: BlackboardEntry): void {
    this.eventLog.push({ type, entry, timestamp: Date.now() });
  }
}

// ─── Convenience Functions ───────────────────────────────────────────────────

/** Post an observation to the blackboard */
export function postObservation(
  board: Blackboard,
  agentId: string,
  category: string,
  content: Record<string, unknown>,
  relevantTo: string[],
  priority = 5,
): BlackboardEntry {
  return board.post({
    agentId,
    type: 'observation',
    category,
    content,
    relevantTo,
    priority,
  });
}

/** Post a hypothesis to the blackboard */
export function postHypothesis(
  board: Blackboard,
  agentId: string,
  category: string,
  content: Record<string, unknown>,
  relevantTo: string[],
  priority = 7,
): BlackboardEntry {
  return board.post({
    agentId,
    type: 'hypothesis',
    category,
    content,
    relevantTo,
    priority,
  });
}

/** Post a finding to the blackboard */
export function postFinding(
  board: Blackboard,
  agentId: string,
  category: string,
  content: Record<string, unknown>,
  relevantTo: string[],
  priority = 9,
): BlackboardEntry {
  return board.post({
    agentId,
    type: 'finding',
    category,
    content,
    relevantTo,
    priority,
  });
}

export default Blackboard;

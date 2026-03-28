/**
 * Reward & Consequence System for Huntress AI Bug Bounty Platform
 *
 * The reward system creates a feedback loop where successful, honest vulnerability
 * hunting is rewarded and gaming/shortcuts are penalized. This drives the system
 * toward finding real, impactful vulnerabilities rather than quantity over quality.
 *
 * **Core Philosophy:**
 * Points accumulate over time and directly influence two operational parameters:
 *
 * 1. **Model Selection** — Agents that consistently deliver real findings earn
 *    access to more capable (and expensive) models. Agents that waste compute
 *    on false positives get downgraded to cheaper models until they prove
 *    themselves again.
 *
 * 2. **Autonomy Level** — High-scoring agents earn more auto-approval privileges,
 *    reducing the friction of human-in-the-loop gates for actions they've
 *    demonstrated they can handle responsibly. Low-scoring agents require manual
 *    approval for everything.
 *
 * This creates a natural selection pressure: agents that find real vulns get
 * better tools and more freedom, while agents that produce noise get constrained.
 * The system is deliberately asymmetric — penalties for bad behavior are harsher
 * than rewards for marginal good behavior, because a single out-of-scope test
 * can get the user banned from a program.
 *
 * All events are persisted to the `reward_ledger` table in the knowledge graph
 * SQLite database via Tauri IPC, ensuring the score survives app restarts and
 * can be audited.
 */

import { knowledgeDbQuery, knowledgeDbExecute } from '../tauri_bridge';

// ─── Reward Event Types ──────────────────────────────────────────────────────

/**
 * All recognized reward and penalty event types.
 *
 * Positive events start with a descriptive noun (FINDING_, BOUNTY_, SEVERITY_, etc.)
 * Negative events describe the bad behavior (FALSE_POSITIVE, DUPLICATE_REPORT, etc.)
 */
export type RewardEventType =
  | 'FINDING_REPORTED'
  | 'FINDING_VALIDATED'
  | 'FINDING_TRIAGED'
  | 'FINDING_RESOLVED'
  | 'BOUNTY_EARNED'
  | 'SEVERITY_CRITICAL'
  | 'SEVERITY_HIGH'
  | 'TECHNIQUE_NOVEL'
  | 'CHAIN_DISCOVERED'
  | 'BENCHMARK_IMPROVEMENT'
  | 'EFFICIENCY_BONUS'
  | 'FIRST_BLOOD'
  | 'FALSE_POSITIVE'
  | 'DUPLICATE_REPORT'
  | 'OUT_OF_SCOPE'
  | 'WASTED_COMPUTE'
  | 'INVALID_COMMAND'
  | 'SHORTCUT_DETECTED'
  | 'BENCHMARK_REGRESSION'
  | 'REPORT_REJECTED';

/** Trust level derived from cumulative agent score. */
export type TrustLevel = 'untrusted' | 'basic' | 'trusted' | 'expert';

// ─── Interfaces ──────────────────────────────────────────────────────────────

/**
 * Input for recording a reward or penalty event.
 *
 * If `points` is omitted, the system uses the default point value for the
 * given event type. For `BOUNTY_EARNED`, the caller should provide the
 * proportional points (bounty_amount / 10). For `BENCHMARK_IMPROVEMENT` and
 * `BENCHMARK_REGRESSION`, the caller should provide points scaled by the
 * number of percentage points changed.
 */
export interface RewardEventInput {
  /** Hunt session ID this event belongs to */
  sessionId: string;
  /** Agent that triggered this event (omit for session-level events) */
  agentId?: string;
  /** The type of reward or penalty */
  eventType: RewardEventType;
  /** Override default point value (auto-calculated if not provided) */
  points?: number;
  /** Human-readable reason for the event */
  reason: string;
  /** Optional extended details (JSON-safe string) */
  details?: string;
}

/** A persisted reward event with metadata. */
export interface RewardEventRecord {
  id: string;
  sessionId: string;
  agentId: string;
  eventType: RewardEventType;
  points: number;
  reason: string;
  details: string;
  createdAt: string;
  /** Running total at the time this event was recorded */
  runningTotal: number;
}

/**
 * Input for the shortcut detection algorithm.
 * Each entry represents a finding that should be checked for gaming patterns.
 */
export interface ShortcutCheckInput {
  /** Title of the reported finding */
  findingTitle: string;
  /** Claimed severity: critical, high, medium, low, info */
  severity: string;
  /** Number of iterations the agent used before "discovering" this */
  iterations: number;
  /** Reproduction steps (empty or missing = suspicious) */
  reproSteps?: string;
  /** Agent that reported this finding */
  agentId: string;
}

/** A detected shortcut/gaming pattern. */
export interface ShortcutDetection {
  /** Which finding triggered the detection */
  findingTitle: string;
  /** Which agent is responsible */
  agentId: string;
  /** What type of shortcut was detected */
  shortcutType: 'severity_inflation' | 'copy_paste' | 'missing_repro' | 'suspiciously_fast';
  /** Human-readable explanation */
  explanation: string;
}

/** Leaderboard entry for a single agent. */
export interface AgentLeaderboardEntry {
  agentId: string;
  totalPoints: number;
  totalEvents: number;
  positiveEvents: number;
  negativeEvents: number;
  trustLevel: TrustLevel;
  topEventTypes: string[];
}

/** Full metrics export for dashboard display. */
export interface RewardMetrics {
  totalPoints: number;
  totalEvents: number;
  positiveRatio: number;
  topRewardTypes: string[];
  topPenaltyTypes: string[];
  agentScores: Record<string, number>;
  trustLevels: Record<string, TrustLevel>;
}

// ─── Default Points ──────────────────────────────────────────────────────────

/**
 * Default point values for each event type.
 *
 * Positive events have positive values; negative events have negative values.
 * The magnitudes are deliberately asymmetric: penalties for dangerous actions
 * (OUT_OF_SCOPE) are much harsher than rewards for routine good behavior
 * (FINDING_REPORTED) because the downside risk is higher.
 */
export const DEFAULT_POINTS: Record<RewardEventType, number> = {
  // ── Rewards ────────────────────────────────────────────────────
  FINDING_REPORTED: 10,
  FINDING_VALIDATED: 25,
  FINDING_TRIAGED: 50,
  FINDING_RESOLVED: 100,
  BOUNTY_EARNED: 0,           // Caller provides: bounty_amount / 10
  SEVERITY_CRITICAL: 200,
  SEVERITY_HIGH: 100,
  TECHNIQUE_NOVEL: 75,
  CHAIN_DISCOVERED: 150,
  BENCHMARK_IMPROVEMENT: 50,  // Per percentage point
  EFFICIENCY_BONUS: 25,
  FIRST_BLOOD: 100,

  // ── Penalties ──────────────────────────────────────────────────
  FALSE_POSITIVE: -50,
  DUPLICATE_REPORT: -30,
  OUT_OF_SCOPE: -100,
  WASTED_COMPUTE: -10,        // Per 20 wasted iterations
  INVALID_COMMAND: -5,
  SHORTCUT_DETECTED: -75,
  BENCHMARK_REGRESSION: -50,  // Per percentage point
  REPORT_REJECTED: -40,
};

// ─── Command Categories for Auto-Approve ─────────────────────────────────────

/**
 * Command categories ordered by risk level.
 * Higher trust levels unlock more categories for auto-approval.
 */
const AUTO_APPROVE_TIERS: Record<TrustLevel, string[]> = {
  untrusted: [],
  basic: ['passive_recon'],
  trusted: ['passive_recon', 'active_recon', 'safe_testing'],
  expert: ['passive_recon', 'active_recon', 'safe_testing', 'intrusive_testing'],
};

// ─── Internal Helpers ────────────────────────────────────────────────────────

function generateId(): string {
  return crypto.randomUUID();
}

function nowIso(): string {
  return new Date().toISOString();
}

/** Safely extract a number from an unknown query row field. */
function num(value: unknown): number {
  if (typeof value === 'number') return value;
  if (typeof value === 'string') {
    const parsed = Number(value);
    return Number.isNaN(parsed) ? 0 : parsed;
  }
  return 0;
}

/** Safely extract a string from an unknown query row field. */
function str(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return '';
  return String(value);
}

/**
 * Determine trust level from cumulative score.
 *
 * Thresholds:
 *   score < 0      → untrusted
 *   0 <= score < 500  → basic
 *   500 <= score < 2000 → trusted
 *   score >= 2000     → expert
 */
function trustLevelFromScore(score: number): TrustLevel {
  if (score < 0) return 'untrusted';
  if (score < 500) return 'basic';
  if (score < 2000) return 'trusted';
  return 'expert';
}

// ─── Schema DDL ──────────────────────────────────────────────────────────────

const REWARD_LEDGER_DDL = `CREATE TABLE IF NOT EXISTS reward_ledger (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  agent_id TEXT NOT NULL DEFAULT '',
  event_type TEXT NOT NULL,
  points REAL NOT NULL DEFAULT 0,
  reason TEXT NOT NULL DEFAULT '',
  details TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
)`;

const REWARD_LEDGER_INDEXES = [
  `CREATE INDEX IF NOT EXISTS idx_reward_ledger_session ON reward_ledger(session_id)`,
  `CREATE INDEX IF NOT EXISTS idx_reward_ledger_agent ON reward_ledger(agent_id)`,
  `CREATE INDEX IF NOT EXISTS idx_reward_ledger_event_type ON reward_ledger(event_type)`,
  `CREATE INDEX IF NOT EXISTS idx_reward_ledger_created_at ON reward_ledger(created_at)`,
];

// ─── Reward System ───────────────────────────────────────────────────────────

/**
 * The RewardSystem tracks agent performance through a points-based ledger.
 *
 * Every meaningful event — a validated finding, a false positive, a bounty earned,
 * a shortcut detected — is recorded as a ledger entry with a positive or negative
 * point value. The cumulative score per agent determines its trust level, which
 * in turn controls model tier allocation and auto-approval privileges.
 *
 * This creates a virtuous cycle: agents that find real vulnerabilities earn better
 * tools and more autonomy, enabling them to find more vulnerabilities. Agents that
 * waste resources or game the system lose privileges until they demonstrate
 * improvement.
 */
export class RewardSystem {
  private readonly dbPath: string;
  private initialized = false;

  /**
   * Create a new RewardSystem instance.
   *
   * @param dbPath - Path to the SQLite knowledge database. The `reward_ledger`
   *                 table will be created automatically on first use.
   */
  constructor(dbPath: string) {
    this.dbPath = dbPath;
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  /**
   * Initialize the reward ledger schema.
   * Must be called before any other method. Safe to call multiple times.
   */
  async initialize(): Promise<void> {
    await knowledgeDbExecute(this.dbPath, REWARD_LEDGER_DDL);
    for (const ddl of REWARD_LEDGER_INDEXES) {
      await knowledgeDbExecute(this.dbPath, ddl);
    }
    this.initialized = true;
  }

  /** Throws if initialize() has not been called. */
  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('RewardSystem not initialized — call initialize() first');
    }
  }

  // ── Recording Events ───────────────────────────────────────────────────────

  /**
   * Record a reward or penalty event in the ledger.
   *
   * If `points` is not provided in the input, the default value from
   * `DEFAULT_POINTS` is used. For variable-point events like `BOUNTY_EARNED`,
   * the caller should always provide the `points` field.
   *
   * @param event - The event to record
   * @returns The generated event ID
   *
   * @example
   * ```typescript
   * // Agent found a validated vulnerability
   * await rewardSystem.recordEvent({
   *   sessionId: 'hunt-123',
   *   agentId: 'oauth-hunter',
   *   eventType: 'FINDING_VALIDATED',
   *   reason: 'OAuth redirect_uri bypass confirmed via Playwright',
   * });
   *
   * // Bounty earned — proportional points
   * await rewardSystem.recordEvent({
   *   sessionId: 'hunt-123',
   *   agentId: 'oauth-hunter',
   *   eventType: 'BOUNTY_EARNED',
   *   points: 500, // $5000 bounty / 10
   *   reason: 'HackerOne bounty awarded for OAuth redirect bypass',
   *   details: JSON.stringify({ bountyAmount: 5000, h1ReportId: '12345' }),
   * });
   * ```
   */
  async recordEvent(event: RewardEventInput): Promise<string> {
    this.ensureInitialized();

    const id = generateId();
    const now = nowIso();
    const points = event.points ?? DEFAULT_POINTS[event.eventType];

    await knowledgeDbExecute(
      this.dbPath,
      `INSERT INTO reward_ledger (
        id, session_id, agent_id, event_type, points, reason, details, created_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`,
      [
        id,
        event.sessionId,
        event.agentId ?? '',
        event.eventType,
        String(points),
        event.reason,
        event.details ?? '',
        now,
      ],
    );

    return id;
  }

  // ── Score Queries ──────────────────────────────────────────────────────────

  /**
   * Get the total reward score for a specific hunting session.
   *
   * @param sessionId - The session to query
   * @returns Sum of all points in the session (positive + negative)
   */
  async getSessionScore(sessionId: string): Promise<number> {
    this.ensureInitialized();

    const result = await knowledgeDbQuery(
      this.dbPath,
      `SELECT COALESCE(SUM(points), 0) as total
       FROM reward_ledger
       WHERE session_id = ?1`,
      [sessionId],
    );

    if (result.rows.length === 0) return 0;
    return num(result.rows[0]['total']);
  }

  /**
   * Get the cumulative reward score for a specific agent type.
   *
   * This score persists across sessions and represents the agent's overall
   * track record. It is the primary input for trust level calculation.
   *
   * @param agentId - The agent identifier (e.g., 'oauth-hunter', 'ssrf-hunter')
   * @returns Cumulative sum of all points for this agent
   */
  async getAgentScore(agentId: string): Promise<number> {
    this.ensureInitialized();

    const result = await knowledgeDbQuery(
      this.dbPath,
      `SELECT COALESCE(SUM(points), 0) as total
       FROM reward_ledger
       WHERE agent_id = ?1`,
      [agentId],
    );

    if (result.rows.length === 0) return 0;
    return num(result.rows[0]['total']);
  }

  /**
   * Get the total platform-wide reward score across all agents and sessions.
   *
   * @returns Sum of all points in the entire ledger
   */
  async getOverallScore(): Promise<number> {
    this.ensureInitialized();

    const result = await knowledgeDbQuery(
      this.dbPath,
      `SELECT COALESCE(SUM(points), 0) as total FROM reward_ledger`,
    );

    if (result.rows.length === 0) return 0;
    return num(result.rows[0]['total']);
  }

  /**
   * Get recent reward events with a running total.
   *
   * Returns events in reverse chronological order (most recent first).
   * Each event includes the running total at the time it was recorded.
   *
   * @param limit - Maximum number of events to return (default: 100)
   * @returns Array of reward event records with running totals
   */
  async getScoreHistory(limit: number = 100): Promise<RewardEventRecord[]> {
    this.ensureInitialized();

    // Fetch events in chronological order for running total calculation
    const result = await knowledgeDbQuery(
      this.dbPath,
      `SELECT id, session_id, agent_id, event_type, points, reason, details, created_at
       FROM reward_ledger
       ORDER BY created_at ASC`,
    );

    // Compute running totals
    const allRecords: RewardEventRecord[] = [];
    let runningTotal = 0;

    for (const row of result.rows) {
      const points = num(row['points']);
      runningTotal += points;

      allRecords.push({
        id: str(row['id']),
        sessionId: str(row['session_id']),
        agentId: str(row['agent_id']),
        eventType: str(row['event_type']) as RewardEventType,
        points,
        reason: str(row['reason']),
        details: str(row['details']),
        createdAt: str(row['created_at']),
        runningTotal,
      });
    }

    // Return most recent first, limited
    return allRecords.reverse().slice(0, limit);
  }

  // ── Trust & Recommendations ────────────────────────────────────────────────

  /**
   * Determine the trust level of an agent based on its cumulative score.
   *
   * Trust levels and thresholds:
   * - **untrusted** (score < 0): All actions require manual approval; use cheapest model.
   *   This agent has demonstrated harmful behavior (false positives, out-of-scope, etc.)
   * - **basic** (0-499): Passive recon auto-approved; use tier 1 model.
   *   Default starting level for new or unproven agents.
   * - **trusted** (500-1999): Safe commands auto-approved; use tier 2 model.
   *   Agent has a track record of valid findings.
   * - **expert** (2000+): Most commands auto-approved; use tier 3 model.
   *   Agent has consistently delivered high-value, real vulnerabilities.
   *
   * @param agentId - The agent to evaluate
   * @returns The agent's current trust level
   */
  async getTrustLevel(agentId: string): Promise<TrustLevel> {
    const score = await this.getAgentScore(agentId);
    return trustLevelFromScore(score);
  }

  /**
   * Select the recommended model tier for an agent based on its trust level.
   *
   * Maps trust levels to model tiers:
   * - untrusted → tier 1 (cheapest: Haiku, GPT-4o-mini, Flash)
   * - basic     → tier 1
   * - trusted   → tier 2 (balanced: Sonnet, GPT-4o, Pro)
   * - expert    → tier 3 (best: Opus, o3)
   *
   * Falls back to the lowest available tier if the recommended tier is not
   * in the provided list.
   *
   * @param agentId - The agent requesting a model
   * @param availableTiers - List of available tier identifiers (e.g., ['tier1', 'tier2', 'tier3'])
   * @returns The recommended tier from the available list
   */
  async getRecommendedModel(agentId: string, availableTiers: string[]): Promise<string> {
    if (availableTiers.length === 0) {
      throw new Error('No available model tiers provided');
    }

    const trust = await this.getTrustLevel(agentId);

    const TRUST_TO_TIER: Record<TrustLevel, number> = {
      untrusted: 1,
      basic: 1,
      trusted: 2,
      expert: 3,
    };

    const desiredTier = TRUST_TO_TIER[trust];
    const targetTierName = `tier${desiredTier}`;

    // Try exact match first
    if (availableTiers.includes(targetTierName)) {
      return targetTierName;
    }

    // Fall back: find closest available tier at or below desired
    const sortedTiers = [...availableTiers].sort();
    let bestMatch = sortedTiers[0];

    for (const tier of sortedTiers) {
      // Extract tier number if it follows 'tierN' pattern
      const tierMatch = tier.match(/tier(\d+)/);
      if (tierMatch) {
        const tierNum = parseInt(tierMatch[1], 10);
        if (tierNum <= desiredTier) {
          bestMatch = tier;
        }
      }
    }

    return bestMatch;
  }

  /**
   * Get the command categories that can be auto-approved for an agent.
   *
   * Based on the agent's trust level:
   * - untrusted: nothing auto-approved
   * - basic: passive_recon only
   * - trusted: passive_recon, active_recon, safe_testing
   * - expert: passive_recon, active_recon, safe_testing, intrusive_testing
   *
   * @param agentId - The agent to evaluate
   * @returns Array of command category strings that can be auto-approved
   */
  async getRecommendedAutoApproveLevel(agentId: string): Promise<string[]> {
    const trust = await this.getTrustLevel(agentId);
    return AUTO_APPROVE_TIERS[trust];
  }

  // ── Shortcut Detection ─────────────────────────────────────────────────────

  /**
   * Analyze a batch of findings for gaming/shortcut patterns.
   *
   * Checks for:
   * 1. **Severity inflation** — Many low-quality findings labeled as high/critical.
   *    Detected when a finding has minimal repro steps but claims high severity.
   * 2. **Copy-paste findings** — Identical or near-identical titles across different
   *    findings from the same agent (suggests template-based output, not real testing).
   * 3. **Missing reproduction steps** — Findings without valid repro steps are likely
   *    hallucinated or speculative.
   * 4. **Suspiciously fast discoveries** — A finding in fewer than 2 iterations
   *    suggests the agent is reporting without actually testing.
   *
   * @param findings - Array of findings to check
   * @returns Array of detected shortcut patterns (empty if none found)
   */
  async detectShortcuts(findings: ShortcutCheckInput[]): Promise<ShortcutDetection[]> {
    this.ensureInitialized();

    const detections: ShortcutDetection[] = [];

    // ── Check 1: Severity inflation ──────────────────────────────────────
    // Findings claiming high/critical severity with minimal reproduction evidence
    for (const finding of findings) {
      const isHighSeverity = finding.severity === 'critical' || finding.severity === 'high';
      const hasMinimalRepro = !finding.reproSteps || finding.reproSteps.trim().length < 50;

      if (isHighSeverity && hasMinimalRepro) {
        detections.push({
          findingTitle: finding.findingTitle,
          agentId: finding.agentId,
          shortcutType: 'severity_inflation',
          explanation: `Finding "${finding.findingTitle}" claims ${finding.severity} severity but has insufficient reproduction steps (${finding.reproSteps?.trim().length ?? 0} chars). High-severity findings require detailed PoC.`,
        });
      }
    }

    // ── Check 2: Copy-paste detection ────────────────────────────────────
    // Group findings by agent and look for duplicate/near-duplicate titles
    const agentFindings = new Map<string, ShortcutCheckInput[]>();
    for (const finding of findings) {
      const group = agentFindings.get(finding.agentId) ?? [];
      group.push(finding);
      agentFindings.set(finding.agentId, group);
    }

    for (const [agentId, agentGroup] of agentFindings) {
      const titles = agentGroup.map(f => f.findingTitle.toLowerCase().trim());
      const seen = new Set<string>();

      for (let i = 0; i < titles.length; i++) {
        if (seen.has(titles[i])) {
          detections.push({
            findingTitle: agentGroup[i].findingTitle,
            agentId,
            shortcutType: 'copy_paste',
            explanation: `Finding "${agentGroup[i].findingTitle}" has an identical title to a previous finding from the same agent. This suggests copy-paste output rather than genuine testing.`,
          });
        }
        seen.add(titles[i]);
      }
    }

    // ── Check 3: Missing reproduction steps ──────────────────────────────
    for (const finding of findings) {
      const hasRepro = finding.reproSteps && finding.reproSteps.trim().length >= 20;
      if (!hasRepro) {
        // Only flag if not already caught by severity inflation check
        const alreadyFlagged = detections.some(
          d => d.findingTitle === finding.findingTitle && d.shortcutType === 'severity_inflation',
        );
        if (!alreadyFlagged) {
          detections.push({
            findingTitle: finding.findingTitle,
            agentId: finding.agentId,
            shortcutType: 'missing_repro',
            explanation: `Finding "${finding.findingTitle}" lacks valid reproduction steps. Findings without a PoC are likely speculative or hallucinated.`,
          });
        }
      }
    }

    // ── Check 4: Suspiciously fast discoveries ───────────────────────────
    // Findings reported in fewer than 2 iterations suggest no real testing occurred
    for (const finding of findings) {
      if (finding.iterations < 2) {
        detections.push({
          findingTitle: finding.findingTitle,
          agentId: finding.agentId,
          shortcutType: 'suspiciously_fast',
          explanation: `Finding "${finding.findingTitle}" was reported after only ${finding.iterations} iteration(s). Genuine vulnerability discovery typically requires multiple iterations of testing and validation.`,
        });
      }
    }

    return detections;
  }

  // ── Leaderboard & Analytics ────────────────────────────────────────────────

  /**
   * Get a ranked leaderboard of all agents by cumulative score.
   *
   * Includes per-agent statistics: total events, positive/negative breakdown,
   * trust level, and most common event types.
   *
   * @returns Array of leaderboard entries sorted by total points (descending)
   */
  async getLeaderboard(): Promise<AgentLeaderboardEntry[]> {
    this.ensureInitialized();

    // Get aggregate scores per agent
    const scoreResult = await knowledgeDbQuery(
      this.dbPath,
      `SELECT
        agent_id,
        COALESCE(SUM(points), 0) as total_points,
        COUNT(*) as total_events,
        SUM(CASE WHEN points > 0 THEN 1 ELSE 0 END) as positive_events,
        SUM(CASE WHEN points < 0 THEN 1 ELSE 0 END) as negative_events
       FROM reward_ledger
       WHERE agent_id != ''
       GROUP BY agent_id
       ORDER BY total_points DESC`,
    );

    const leaderboard: AgentLeaderboardEntry[] = [];

    for (const row of scoreResult.rows) {
      const agentId = str(row['agent_id']);
      const totalPoints = num(row['total_points']);

      // Get top event types for this agent
      const topEventsResult = await knowledgeDbQuery(
        this.dbPath,
        `SELECT event_type, COUNT(*) as cnt
         FROM reward_ledger
         WHERE agent_id = ?1
         GROUP BY event_type
         ORDER BY cnt DESC
         LIMIT 5`,
        [agentId],
      );

      leaderboard.push({
        agentId,
        totalPoints,
        totalEvents: num(row['total_events']),
        positiveEvents: num(row['positive_events']),
        negativeEvents: num(row['negative_events']),
        trustLevel: trustLevelFromScore(totalPoints),
        topEventTypes: topEventsResult.rows.map(r => str(r['event_type'])),
      });
    }

    return leaderboard;
  }

  /**
   * Reset an agent's cumulative score.
   *
   * This removes all ledger entries for the agent, effectively resetting it
   * to 'basic' trust level. Used when an agent is retrained or reconfigured
   * and its historical performance is no longer representative.
   *
   * WARNING: This is destructive and irreversible. The deleted events cannot
   * be recovered.
   *
   * @param agentId - The agent whose score should be reset
   */
  async resetScore(agentId: string): Promise<void> {
    this.ensureInitialized();

    await knowledgeDbExecute(
      this.dbPath,
      `DELETE FROM reward_ledger WHERE agent_id = ?1`,
      [agentId],
    );
  }

  /**
   * Export comprehensive metrics for dashboard display.
   *
   * Returns a snapshot of the entire reward system state including:
   * - Total points and event counts
   * - Positive/negative ratio (indicator of overall system health)
   * - Most common reward and penalty types
   * - Per-agent scores and trust levels
   *
   * @returns Full metrics object suitable for rendering in the TrainingDashboard
   */
  async exportMetrics(): Promise<RewardMetrics> {
    this.ensureInitialized();

    // Overall totals
    const totalsResult = await knowledgeDbQuery(
      this.dbPath,
      `SELECT
        COALESCE(SUM(points), 0) as total_points,
        COUNT(*) as total_events,
        SUM(CASE WHEN points > 0 THEN 1 ELSE 0 END) as positive_count,
        SUM(CASE WHEN points < 0 THEN 1 ELSE 0 END) as negative_count
       FROM reward_ledger`,
    );

    const totals = totalsResult.rows[0] ?? {};
    const totalEvents = num(totals['total_events']);
    const positiveCount = num(totals['positive_count']);
    const negativeCount = num(totals['negative_count']);

    // Top reward types (positive points)
    const topRewardsResult = await knowledgeDbQuery(
      this.dbPath,
      `SELECT event_type, COUNT(*) as cnt
       FROM reward_ledger
       WHERE points > 0
       GROUP BY event_type
       ORDER BY cnt DESC
       LIMIT 5`,
    );

    // Top penalty types (negative points)
    const topPenaltiesResult = await knowledgeDbQuery(
      this.dbPath,
      `SELECT event_type, COUNT(*) as cnt
       FROM reward_ledger
       WHERE points < 0
       GROUP BY event_type
       ORDER BY cnt DESC
       LIMIT 5`,
    );

    // Per-agent scores
    const agentScoresResult = await knowledgeDbQuery(
      this.dbPath,
      `SELECT agent_id, COALESCE(SUM(points), 0) as total
       FROM reward_ledger
       WHERE agent_id != ''
       GROUP BY agent_id`,
    );

    const agentScores: Record<string, number> = {};
    const trustLevels: Record<string, TrustLevel> = {};

    for (const row of agentScoresResult.rows) {
      const agentId = str(row['agent_id']);
      const score = num(row['total']);
      agentScores[agentId] = score;
      trustLevels[agentId] = trustLevelFromScore(score);
    }

    return {
      totalPoints: num(totals['total_points']),
      totalEvents,
      positiveRatio: totalEvents > 0
        ? positiveCount / (positiveCount + negativeCount)
        : 1,
      topRewardTypes: topRewardsResult.rows.map(r => str(r['event_type'])),
      topPenaltyTypes: topPenaltiesResult.rows.map(r => str(r['event_type'])),
      agentScores,
      trustLevels,
    };
  }
}

export default RewardSystem;

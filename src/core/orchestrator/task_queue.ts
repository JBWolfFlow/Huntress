/**
 * Dynamic Task Queue
 *
 * BabyAGI-style dynamic task generation and prioritization.
 * Replaces rigid phase-based flow with adaptive, finding-driven task management.
 *
 * After each agent completes:
 * 1. Extract findings and new targets from results
 * 2. Ask orchestrator: "Given these findings, what new tasks should we add?"
 * 3. Re-prioritize remaining tasks based on discoveries
 * 4. Dispatch next batch of agents
 */

import type { AgentResult, AgentFinding } from '../../agents/base_agent';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface HuntTask {
  id: string;
  description: string;
  target: string;
  agentType: string;
  priority: number;
  dependencies: string[];
  status: 'queued' | 'running' | 'done' | 'failed' | 'cancelled';
  iterationBudget: number;
  result?: AgentResult;
  createdAt: number;
  startedAt?: number;
  completedAt?: number;
  /** What triggered this task's creation */
  origin: 'initial' | 'finding' | 'orchestrator' | 'user';
  /** Tags for grouping/filtering */
  tags: string[];
}

export interface TaskQueueStats {
  total: number;
  queued: number;
  running: number;
  done: number;
  failed: number;
  cancelled: number;
  totalFindings: number;
}

export type TaskEventType = 'added' | 'started' | 'completed' | 'failed' | 'reprioritized' | 'cancelled';

export interface TaskEvent {
  type: TaskEventType;
  task: HuntTask;
  timestamp: number;
}

// ─── Task Queue ──────────────────────────────────────────────────────────────

export class TaskQueue {
  private tasks: Map<string, HuntTask> = new Map();
  private eventLog: TaskEvent[] = [];
  private listeners: Array<(event: TaskEvent) => void> = [];
  private nextId = 1;

  /** Add a new task to the queue */
  enqueue(task: Omit<HuntTask, 'id' | 'status' | 'createdAt'>): HuntTask {
    const fullTask: HuntTask = {
      ...task,
      id: `task_${this.nextId++}`,
      status: 'queued',
      createdAt: Date.now(),
    };
    this.tasks.set(fullTask.id, fullTask);
    this.emitEvent('added', fullTask);
    return fullTask;
  }

  /** Get the next task to execute (highest priority, all dependencies met) */
  dequeue(): HuntTask | null {
    const candidates = Array.from(this.tasks.values())
      .filter(t => t.status === 'queued')
      .filter(t => this.areDependenciesMet(t))
      .sort((a, b) => b.priority - a.priority);

    const next = candidates[0] ?? null;
    if (next) {
      next.status = 'running';
      next.startedAt = Date.now();
      this.emitEvent('started', next);
    }
    return next;
  }

  /** Get multiple tasks for parallel execution */
  dequeueBatch(maxConcurrent: number): HuntTask[] {
    const batch: HuntTask[] = [];
    const candidates = Array.from(this.tasks.values())
      .filter(t => t.status === 'queued')
      .filter(t => this.areDependenciesMet(t))
      .sort((a, b) => b.priority - a.priority);

    for (const task of candidates) {
      if (batch.length >= maxConcurrent) break;
      task.status = 'running';
      task.startedAt = Date.now();
      batch.push(task);
      this.emitEvent('started', task);
    }

    return batch;
  }

  /** Mark a task as complete with results */
  complete(taskId: string, result: AgentResult): void {
    const task = this.tasks.get(taskId);
    if (!task) return;

    task.status = 'done';
    task.completedAt = Date.now();
    task.result = result;
    this.emitEvent('completed', task);
  }

  /** Mark a task as failed */
  fail(taskId: string, error: string): void {
    const task = this.tasks.get(taskId);
    if (!task) return;

    task.status = 'failed';
    task.completedAt = Date.now();
    task.result = {
      taskId,
      agentId: task.agentType,
      success: false,
      findings: [],
      toolsExecuted: 0,
      duration: task.startedAt ? Date.now() - task.startedAt : 0,
      error,
    };
    this.emitEvent('failed', task);
  }

  /** Cancel a task */
  cancel(taskId: string): void {
    const task = this.tasks.get(taskId);
    if (!task || task.status === 'done' || task.status === 'failed') return;

    task.status = 'cancelled';
    task.completedAt = Date.now();
    this.emitEvent('cancelled', task);
  }

  /** Re-prioritize tasks based on new findings */
  reprioritize(findings: AgentFinding[]): void {
    const findingTypes = new Set(findings.map(f => f.type));
    const findingSeverities = findings.map(f => f.severity);
    const hasCritical = findingSeverities.includes('critical');
    const hasHigh = findingSeverities.includes('high');

    for (const task of this.tasks.values()) {
      if (task.status !== 'queued') continue;

      let boost = 0;

      // Boost related agent tasks when findings are discovered
      if (findingTypes.has('xss_reflected') && task.agentType === 'xss_hunter') boost += 3;
      if (findingTypes.has('sqli') && task.agentType === 'sqli_hunter') boost += 3;
      if (findingTypes.has('ssrf') && task.agentType === 'ssrf_hunter') boost += 3;
      if (findingTypes.has('open_redirect') && task.agentType === 'ssrf_hunter') boost += 2;
      if (findingTypes.has('subdomain') && task.agentType === 'recon') boost += 1;

      // Boost validation tasks when high/critical findings exist
      if ((hasCritical || hasHigh) && task.tags.includes('validation')) boost += 5;

      // Boost exploitation tasks for confirmed findings
      if (findings.some(f => f.severity === 'critical') && task.tags.includes('exploitation')) boost += 4;

      if (boost > 0) {
        task.priority += boost;
        this.emitEvent('reprioritized', task);
      }
    }
  }

  /** Generate follow-up tasks based on agent results */
  generateFollowUpTasks(result: AgentResult): HuntTask[] {
    const newTasks: HuntTask[] = [];

    for (const finding of result.findings) {
      // XSS finding → validate with headless browser
      if (finding.type.includes('xss')) {
        newTasks.push(this.enqueue({
          description: `Validate XSS finding: ${finding.title}`,
          target: finding.target,
          agentType: 'xss-hunter',
          priority: 8,
          dependencies: [],
          iterationBudget: 10,
          origin: 'finding',
          tags: ['validation', 'xss'],
        }));
      }

      // SQLi finding → validate and extract DB info
      if (finding.type.includes('sqli') || finding.type.includes('sql')) {
        newTasks.push(this.enqueue({
          description: `Validate SQLi finding: ${finding.title}`,
          target: finding.target,
          agentType: 'sqli-hunter',
          priority: 9,
          dependencies: [],
          iterationBudget: 15,
          origin: 'finding',
          tags: ['validation', 'sqli'],
        }));
      }

      // Open redirect → chain with SSRF
      if (finding.type.includes('redirect')) {
        newTasks.push(this.enqueue({
          description: `Chain open redirect with SSRF: ${finding.target}`,
          target: finding.target,
          agentType: 'ssrf-hunter',
          priority: 7,
          dependencies: [],
          iterationBudget: 30,
          origin: 'finding',
          tags: ['chaining', 'ssrf'],
        }));
      }

      // New subdomain discovered → recon it
      if (finding.type === 'subdomain' || finding.type === 'host') {
        newTasks.push(this.enqueue({
          description: `Deep recon on discovered asset: ${finding.target}`,
          target: finding.target,
          agentType: 'recon',
          priority: 5,
          dependencies: [],
          iterationBudget: 20,
          origin: 'finding',
          tags: ['recon', 'discovery'],
        }));
      }
    }

    return newTasks;
  }

  /** Get all tasks */
  getAllTasks(): HuntTask[] {
    return Array.from(this.tasks.values());
  }

  /** Get tasks by status */
  getTasksByStatus(status: HuntTask['status']): HuntTask[] {
    return Array.from(this.tasks.values()).filter(t => t.status === status);
  }

  /** Get task by ID */
  getTask(id: string): HuntTask | undefined {
    return this.tasks.get(id);
  }

  /** Get queue statistics */
  getStats(): TaskQueueStats {
    const tasks = Array.from(this.tasks.values());
    return {
      total: tasks.length,
      queued: tasks.filter(t => t.status === 'queued').length,
      running: tasks.filter(t => t.status === 'running').length,
      done: tasks.filter(t => t.status === 'done').length,
      failed: tasks.filter(t => t.status === 'failed').length,
      cancelled: tasks.filter(t => t.status === 'cancelled').length,
      totalFindings: tasks
        .filter(t => t.result)
        .reduce((sum, t) => sum + (t.result?.findings.length ?? 0), 0),
    };
  }

  /** Check if all tasks are complete */
  isComplete(): boolean {
    return Array.from(this.tasks.values()).every(
      t => t.status === 'done' || t.status === 'failed' || t.status === 'cancelled'
    );
  }

  /** Check if there are runnable tasks */
  hasRunnableTasks(): boolean {
    return Array.from(this.tasks.values()).some(
      t => t.status === 'queued' && this.areDependenciesMet(t)
    );
  }

  /** Subscribe to task events */
  onEvent(listener: (event: TaskEvent) => void): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }

  /** Get event log */
  getEventLog(): TaskEvent[] {
    return this.eventLog;
  }

  /** Clear all tasks */
  clear(): void {
    this.tasks.clear();
    this.eventLog = [];
    this.nextId = 1;
  }

  // ─── Private ─────────────────────────────────────────────────────────────

  private areDependenciesMet(task: HuntTask): boolean {
    return task.dependencies.every(depId => {
      const dep = this.tasks.get(depId);
      return dep && (dep.status === 'done' || dep.status === 'cancelled');
    });
  }

  private emitEvent(type: TaskEventType, task: HuntTask): void {
    const event: TaskEvent = { type, task, timestamp: Date.now() };
    this.eventLog.push(event);
    for (const listener of this.listeners) {
      listener(event);
    }
  }
}

export default TaskQueue;

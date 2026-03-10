/**
 * PlanExecutor
 *
 * Takes a DAG of tasks with dependencies, runs them in dependency order,
 * parallelizes independent tasks, and reports progress.
 */

export interface PlanTask {
  id: string;
  name: string;
  description: string;
  agentId?: string;
  dependsOn: string[];
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  result?: unknown;
  error?: string;
}

export interface ExecutionPlan {
  id: string;
  name: string;
  tasks: PlanTask[];
}

export type PlanProgressCallback = (plan: ExecutionPlan) => void;

export class PlanExecutor {
  private onProgress?: PlanProgressCallback;

  constructor(onProgress?: PlanProgressCallback) {
    this.onProgress = onProgress;
  }

  /**
   * Execute a plan, respecting dependencies and parallelizing where possible.
   *
   * @param plan The execution plan with tasks and dependencies
   * @param executor Function that runs a single task and returns its result
   */
  async execute(
    plan: ExecutionPlan,
    executor: (task: PlanTask) => Promise<unknown>
  ): Promise<ExecutionPlan> {
    const completed = new Set<string>();
    const failed = new Set<string>();

    while (true) {
      // Find tasks that are ready to run
      const ready = plan.tasks.filter(t =>
        t.status === 'pending' &&
        t.dependsOn.every(dep => completed.has(dep)) &&
        !t.dependsOn.some(dep => failed.has(dep))
      );

      // Skip tasks whose dependencies failed
      const blocked = plan.tasks.filter(t =>
        t.status === 'pending' &&
        t.dependsOn.some(dep => failed.has(dep))
      );
      for (const task of blocked) {
        task.status = 'skipped';
        task.error = 'Dependency failed';
      }

      if (ready.length === 0) break;

      // Mark all ready tasks as running
      for (const task of ready) {
        task.status = 'running';
      }
      this.emitProgress(plan);

      // Execute ready tasks in parallel
      const results = await Promise.allSettled(
        ready.map(async (task) => {
          try {
            task.result = await executor(task);
            task.status = 'completed';
            completed.add(task.id);
          } catch (error) {
            task.status = 'failed';
            task.error = error instanceof Error ? error.message : String(error);
            failed.add(task.id);
          }
        })
      );

      this.emitProgress(plan);

      // Safety: if no progress was made, break to avoid infinite loop
      const anyProgress = results.some(r => r.status === 'fulfilled');
      if (!anyProgress && ready.length > 0) break;
    }

    return plan;
  }

  /** Create a simple linear plan (no parallelism) */
  static createLinearPlan(
    name: string,
    tasks: Array<{ id: string; name: string; description: string; agentId?: string }>
  ): ExecutionPlan {
    return {
      id: `plan_${Date.now()}`,
      name,
      tasks: tasks.map((t, i) => ({
        ...t,
        dependsOn: i > 0 ? [tasks[i - 1].id] : [],
        status: 'pending' as const,
      })),
    };
  }

  /** Create a plan where all tasks can run in parallel */
  static createParallelPlan(
    name: string,
    tasks: Array<{ id: string; name: string; description: string; agentId?: string }>
  ): ExecutionPlan {
    return {
      id: `plan_${Date.now()}`,
      name,
      tasks: tasks.map(t => ({
        ...t,
        dependsOn: [],
        status: 'pending' as const,
      })),
    };
  }

  private emitProgress(plan: ExecutionPlan): void {
    this.onProgress?.(plan);
  }
}

export default PlanExecutor;

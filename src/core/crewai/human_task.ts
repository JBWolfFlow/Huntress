/**
 * Human Task Integration
 * 
 * Wraps CrewAI's HumanTask functionality to require human approval
 * for critical operations like submitting reports or performing
 * potentially destructive tests.
 */

export interface HumanTaskRequest {
  id: string;
  type: 'approval' | 'input' | 'decision';
  title: string;
  description: string;
  context: any;
  options?: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: number;
}

export interface HumanTaskResponse {
  taskId: string;
  approved: boolean;
  response?: string;
  selectedOption?: string;
  feedback?: string;
  timestamp: number;
}

export type HumanTaskCallback = (request: HumanTaskRequest) => Promise<HumanTaskResponse>;

export class HumanTaskManager {
  private pendingTasks: Map<string, HumanTaskRequest> = new Map();
  private callback?: HumanTaskCallback;

  /**
   * Register callback for human task requests
   */
  setCallback(callback: HumanTaskCallback): void {
    this.callback = callback;
  }

  /**
   * Request human approval for an action
   */
  async requestApproval(
    title: string,
    description: string,
    context: any,
    severity: 'low' | 'medium' | 'high' | 'critical' = 'medium'
  ): Promise<boolean> {
    const request: HumanTaskRequest = {
      id: this.generateTaskId(),
      type: 'approval',
      title,
      description,
      context,
      severity,
      timestamp: Date.now(),
    };

    this.pendingTasks.set(request.id, request);

    if (!this.callback) {
      throw new Error('No human task callback registered');
    }

    const response = await this.callback(request);
    this.pendingTasks.delete(request.id);

    return response.approved;
  }

  /**
   * Request human input
   */
  async requestInput(
    title: string,
    description: string,
    context: any
  ): Promise<string | null> {
    const request: HumanTaskRequest = {
      id: this.generateTaskId(),
      type: 'input',
      title,
      description,
      context,
      severity: 'medium',
      timestamp: Date.now(),
    };

    this.pendingTasks.set(request.id, request);

    if (!this.callback) {
      throw new Error('No human task callback registered');
    }

    const response = await this.callback(request);
    this.pendingTasks.delete(request.id);

    return response.response || null;
  }

  /**
   * Request human decision from options
   */
  async requestDecision(
    title: string,
    description: string,
    options: string[],
    context: any
  ): Promise<string | null> {
    const request: HumanTaskRequest = {
      id: this.generateTaskId(),
      type: 'decision',
      title,
      description,
      context,
      options,
      severity: 'medium',
      timestamp: Date.now(),
    };

    this.pendingTasks.set(request.id, request);

    if (!this.callback) {
      throw new Error('No human task callback registered');
    }

    const response = await this.callback(request);
    this.pendingTasks.delete(request.id);

    return response.selectedOption || null;
  }

  /**
   * Get all pending tasks
   */
  getPendingTasks(): HumanTaskRequest[] {
    return Array.from(this.pendingTasks.values());
  }

  /**
   * Cancel a pending task
   */
  cancelTask(taskId: string): boolean {
    return this.pendingTasks.delete(taskId);
  }

  /**
   * Generate unique task ID
   */
  private generateTaskId(): string {
    return `task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

export default HumanTaskManager;
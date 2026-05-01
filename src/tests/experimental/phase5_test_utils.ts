/**
 * Phase 5 Test Utilities
 * 
 * Mock implementations and helper functions for testing Phase 5 components.
 * Provides realistic test data, mock services, and assertion helpers.
 * 
 * Confidence: 10/10 - Production-ready test utilities with comprehensive mocking.
 */

import { TrainingExample } from '../../core/training/experimental/data_collector';
import { HTBMachine, SpawnResult, FlagResult } from '../../core/training/experimental/htb_api';
import { ModelVersion } from '../../core/training/experimental/model_manager';
import { PerformanceMetrics } from '../../core/training/experimental/performance_monitor';

/**
 * Mock HTB API Client
 */
export class MockHTBAPIClient {
  private machines: HTBMachine[] = [];
  private spawnedMachines: Set<number> = new Set();
  private submittedFlags: Map<number, string[]> = new Map();

  constructor() {
    this.machines = this.generateMockMachines();
  }

  async listMachines(): Promise<HTBMachine[]> {
    return [...this.machines];
  }

  async getMachine(id: number): Promise<HTBMachine> {
    const machine = this.machines.find(m => m.id === id);
    if (!machine) throw new Error(`Machine ${id} not found`);
    return { ...machine };
  }

  async spawnMachine(id: number): Promise<SpawnResult> {
    const machine = this.machines.find(m => m.id === id);
    if (!machine) {
      return { success: false, error: 'Machine not found' };
    }
    
    this.spawnedMachines.add(id);
    return {
      success: true,
      ip: `10.10.${Math.floor(id / 256)}.${id % 256}`,
      message: 'Machine spawned successfully',
    };
  }

  async terminateMachine(id: number): Promise<boolean> {
    this.spawnedMachines.delete(id);
    return true;
  }

  async submitFlag(machineId: number, flag: string): Promise<FlagResult> {
    const correctFlag = `HTB{test_flag_${machineId}}`;
    const success = flag === correctFlag;
    
    if (!this.submittedFlags.has(machineId)) {
      this.submittedFlags.set(machineId, []);
    }
    this.submittedFlags.get(machineId)!.push(flag);
    
    return {
      success,
      message: success ? 'Flag accepted!' : 'Flag rejected',
      points: success ? 20 : undefined,
    };
  }

  async healthCheck(): Promise<{ healthy: boolean; authenticated: boolean; message: string }> {
    return {
      healthy: true,
      authenticated: true,
      message: 'HTB API connection successful',
    };
  }

  private generateMockMachines(): HTBMachine[] {
    return [
      {
        id: 1,
        name: 'Lame',
        os: 'linux',
        difficulty: 'easy',
        ip: '10.10.10.3',
        retired: true,
        user_owns: 5000,
        root_owns: 4500,
        rating: 4.5,
      },
      {
        id: 2,
        name: 'Blue',
        os: 'windows',
        difficulty: 'easy',
        ip: '10.10.10.40',
        retired: true,
        user_owns: 6000,
        root_owns: 5500,
        rating: 4.7,
      },
      {
        id: 3,
        name: 'Optimum',
        os: 'windows',
        difficulty: 'medium',
        ip: '10.10.10.8',
        retired: true,
        user_owns: 3000,
        root_owns: 2500,
        rating: 4.2,
      },
    ];
  }
}

/**
 * Mock Qdrant Client
 */
export class MockQdrantClient {
  private points: Map<string, any> = new Map();
  private collections: string[] = ['huntress_memory'];

  async upsertPoint(point: any): Promise<void> {
    this.points.set(point.id, point);
  }

  async searchWithFilter(vector: number[], filter: any, limit: number): Promise<any[]> {
    const results = Array.from(this.points.values()).slice(0, limit);
    return results.map(point => ({
      id: point.id,
      score: 0.9,
      payload: point.payload,
    }));
  }

  async getCollectionInfo(): Promise<any> {
    return {
      status: 'green',
      vectors_count: this.points.size,
    };
  }

  async listCollections(): Promise<string[]> {
    return [...this.collections];
  }

  clear(): void {
    this.points.clear();
  }

  addTrainingExample(example: TrainingExample): void {
    this.points.set(example.id, {
      id: example.id,
      vector: new Array(1536).fill(0),
      payload: { data: example },
    });
  }
}

/**
 * Generate mock training example
 */
export function generateMockTrainingExample(overrides: Partial<TrainingExample> = {}): TrainingExample {
  const id = `training_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  return {
    id,
    timestamp: new Date(),
    source: 'htb',
    target: {
      type: 'htb_machine',
      name: 'TestMachine',
      ip: '10.10.10.1',
      os: 'linux',
      difficulty: 'easy',
    },
    vulnerability: {
      type: 'command_injection',
      severity: 'high',
      cvss_score: 8.5,
    },
    execution: {
      session_id: `session_${id}`,
      start_time: new Date(Date.now() - 3600000),
      end_time: new Date(),
      duration_seconds: 3600,
      tools_used: [
        {
          tool: 'nmap',
          command: 'nmap -sV 10.10.10.1',
          timestamp: new Date(),
          output: 'PORT STATE SERVICE\n22/tcp open ssh',
          success: true,
        },
      ],
      reasoning: [
        {
          step: 1,
          thought: 'Scan for open ports',
          action: 'Run nmap',
          observation: 'Found SSH on port 22',
          timestamp: new Date(),
        },
      ],
      discoveries: [
        {
          type: 'open_port',
          value: '22/tcp',
          timestamp: new Date(),
          relevance: 'high',
        },
      ],
    },
    success: {
      achieved: true,
      level: 'root',
      flags_found: ['HTB{test_flag}'],
      time_to_user: 1800,
      time_to_root: 3600,
    },
    learning: {
      successful_techniques: ['port_scanning', 'ssh_enumeration'],
      avoided_paths: [],
      insights: ['SSH was vulnerable to known exploit'],
      false_positives: 0,
      pivots: [],
    },
    recording: {
      path: '/recordings/test.cast',
      format: 'asciinema',
      duration: 3600,
    },
    ...overrides,
  };
}

/**
 * Generate mock model version
 */
export function generateMockModelVersion(overrides: Partial<ModelVersion> = {}): ModelVersion {
  const version = `v${new Date().toISOString().split('T')[0].replace(/-/g, '')}-${Date.now()}`;
  
  return {
    version,
    timestamp: new Date(),
    baseModel: 'llama-3.1-70b',
    loraPath: `/models/${version}`,
    configPath: 'config/axolotl_config.yml',
    trainingExamples: 100,
    trainingDuration: 7200,
    performance: {
      successRate: 0.70,
      avgTimeToSuccess: 3600,
      falsePositiveRate: 0.10,
      validationLoss: 0.5,
    },
    status: 'testing',
    metadata: {
      trainingDate: new Date().toISOString(),
      dataQuality: 0.85,
      gpuUsed: 'NVIDIA A100',
      trainingConfig: {},
    },
    ...overrides,
  };
}

/**
 * Generate mock performance metrics
 */
export function generateMockPerformanceMetrics(overrides: Partial<PerformanceMetrics> = {}): PerformanceMetrics {
  return {
    timestamp: new Date(),
    modelVersion: 'v20250101-000000',
    successRate: 0.70,
    avgTimeToSuccess: 3600,
    medianTimeToSuccess: 3000,
    falsePositiveRate: 0.10,
    duplicateRate: 0.05,
    avgToolsUsed: 5,
    avgIterations: 10,
    novelTechniques: 2,
    techniqueReuse: 0.80,
    byDifficulty: {
      easy: {
        attempts: 30,
        successes: 25,
        successRate: 0.83,
        avgTime: 1800,
        falsePositives: 2,
      },
      medium: {
        attempts: 40,
        successes: 28,
        successRate: 0.70,
        avgTime: 3600,
        falsePositives: 4,
      },
      hard: {
        attempts: 30,
        successes: 15,
        successRate: 0.50,
        avgTime: 7200,
        falsePositives: 3,
      },
    },
    resources: {
      avgGpuMemory: 40000,
      avgCpuUsage: 60,
      avgDiskIO: 100,
    },
    ...overrides,
  };
}

/**
 * Wait for condition with timeout
 */
export async function waitFor(
  condition: () => boolean | Promise<boolean>,
  timeout: number = 5000,
  interval: number = 100
): Promise<void> {
  const startTime = Date.now();
  
  while (Date.now() - startTime < timeout) {
    if (await condition()) {
      return;
    }
    await new Promise(resolve => setTimeout(resolve, interval));
  }
  
  throw new Error(`Timeout waiting for condition after ${timeout}ms`);
}

/**
 * Mock file system operations
 */
export class MockFileSystem {
  private files: Map<string, string> = new Map();
  private directories: Set<string> = new Set();

  async writeFile(path: string, content: string): Promise<void> {
    this.files.set(path, content);
  }

  async readFile(path: string): Promise<string> {
    const content = this.files.get(path);
    if (!content) throw new Error(`File not found: ${path}`);
    return content;
  }

  async mkdir(path: string): Promise<void> {
    this.directories.add(path);
  }

  async access(path: string): Promise<void> {
    if (!this.files.has(path) && !this.directories.has(path)) {
      throw new Error(`Path not found: ${path}`);
    }
  }

  async unlink(path: string): Promise<void> {
    this.files.delete(path);
  }

  async readdir(path: string): Promise<string[]> {
    const prefix = path.endsWith('/') ? path : `${path}/`;
    const files: string[] = [];
    
    for (const [filePath] of this.files) {
      if (filePath.startsWith(prefix)) {
        const relativePath = filePath.substring(prefix.length);
        const firstPart = relativePath.split('/')[0];
        if (!files.includes(firstPart)) {
          files.push(firstPart);
        }
      }
    }
    
    return files;
  }

  clear(): void {
    this.files.clear();
    this.directories.clear();
  }
}

/**
 * Performance measurement utility
 */
export class PerformanceMeasure {
  private startTime: number = 0;
  private measurements: Map<string, number[]> = new Map();

  start(): void {
    this.startTime = Date.now();
  }

  end(label: string): number {
    const duration = Date.now() - this.startTime;
    
    if (!this.measurements.has(label)) {
      this.measurements.set(label, []);
    }
    this.measurements.get(label)!.push(duration);
    
    return duration;
  }

  getAverage(label: string): number {
    const measurements = this.measurements.get(label) || [];
    if (measurements.length === 0) return 0;
    return measurements.reduce((a, b) => a + b, 0) / measurements.length;
  }

  getMedian(label: string): number {
    const measurements = this.measurements.get(label) || [];
    if (measurements.length === 0) return 0;
    
    const sorted = [...measurements].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    
    return sorted.length % 2 === 0
      ? (sorted[mid - 1] + sorted[mid]) / 2
      : sorted[mid];
  }

  getP95(label: string): number {
    const measurements = this.measurements.get(label) || [];
    if (measurements.length === 0) return 0;
    
    const sorted = [...measurements].sort((a, b) => a - b);
    const index = Math.floor(sorted.length * 0.95);
    
    return sorted[index];
  }

  clear(): void {
    this.measurements.clear();
  }
}

/**
 * Assertion helpers
 */
export const assertions = {
  /**
   * Assert value is within range
   */
  assertInRange(value: number, min: number, max: number, message?: string): void {
    if (value < min || value > max) {
      throw new Error(message || `Expected ${value} to be between ${min} and ${max}`);
    }
  },

  /**
   * Assert performance meets threshold
   */
  assertPerformance(duration: number, maxDuration: number, operation: string): void {
    if (duration > maxDuration) {
      throw new Error(`${operation} took ${duration}ms, exceeds threshold of ${maxDuration}ms`);
    }
  },

  /**
   * Assert success rate meets threshold
   */
  assertSuccessRate(successes: number, total: number, minRate: number): void {
    const rate = successes / total;
    if (rate < minRate) {
      throw new Error(`Success rate ${(rate * 100).toFixed(1)}% below threshold ${(minRate * 100).toFixed(1)}%`);
    }
  },

  /**
   * Assert error rate below threshold
   */
  assertErrorRate(errors: number, total: number, maxRate: number): void {
    const rate = errors / total;
    if (rate > maxRate) {
      throw new Error(`Error rate ${(rate * 100).toFixed(1)}% exceeds threshold ${(maxRate * 100).toFixed(1)}%`);
    }
  },
};

export default {
  MockHTBAPIClient,
  MockQdrantClient,
  MockFileSystem,
  PerformanceMeasure,
  generateMockTrainingExample,
  generateMockModelVersion,
  generateMockPerformanceMetrics,
  waitFor,
  assertions,
};
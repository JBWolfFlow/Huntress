/**
 * Training Module — Public Surface
 *
 * What lives at the top level (production-connected):
 *   - reward_system.ts  — used by HuntSessionContext for trust scoring
 *   - feedback_loop.ts  — used by orchestrator for outcome tracking
 *
 * What lives under experimental/ (gated behind EXPERIMENTAL_TRAINING flag):
 *   - HTB-driven LoRA training pipeline (HTB API, data collector,
 *     training manager, model manager, learning loop, A/B testing,
 *     performance monitor, deployment manager, scheduler, readiness
 *     checker, rollback manager, health checker, integration entry)
 *
 * The experimental modules are NOT instantiated by any production code
 * path and require a 24GB+ VRAM GPU to actually run training. Their
 * tests live under `src/tests/experimental/` and are excluded from the
 * default vitest run via vitest.config.ts.
 *
 * To use experimental training in code that opts in:
 *   import { TrainingPipelineManager } from '../core/training/experimental/training_manager';
 *
 * Or via this index (re-exports the experimental factory + types so
 * callers don't have to know the internal structure):
 *   import { ContinuousLearningSystem } from '../core/training';
 */

// Production-connected exports
export { FeedbackLoop } from './feedback_loop';
export type { SubmittedReport, ReportStatus, FeedbackStats } from './feedback_loop';
export { RewardSystem } from './reward_system';
export type { TrustLevel, RewardMetrics } from './reward_system';

// ─── Experimental re-exports (LoRA training pipeline) ──────────────────────
// All of the below require EXPERIMENTAL_TRAINING=1 to be set at runtime AND
// a local GPU with sufficient VRAM. Importing them is cheap (TS-only); only
// instantiation has the runtime gate.

// Phase 5.1: Data Collection
export {
  TrainingDataCleaner,
  QualityFilter,
  TrainingDataStorage,
  TrainingDataCollector,
} from './experimental/data_collector';

export {
  HTBAPIClient,
  createHTBClient,
} from './experimental/htb_api';

// Phase 5.2: Training Infrastructure
export {
  TrainingPipelineManager,
} from './experimental/training_manager';

export {
  ModelVersionManager,
} from './experimental/model_manager';

// Phase 5.3: Continuous Learning Loop
export {
  LearningLoopOrchestrator,
} from './experimental/learning_loop';

export {
  ABTestingFramework,
} from './experimental/ab_testing';

export {
  PerformanceMonitor,
} from './experimental/performance_monitor';

export {
  ModelDeploymentManager,
} from './experimental/deployment_manager';

export {
  LearningLoopScheduler,
} from './experimental/scheduler';

export {
  ProductionReadinessChecker,
} from './experimental/readiness_checker';

export {
  RollbackManager,
} from './experimental/rollback_manager';

export {
  HealthCheckSystem,
} from './experimental/health_checker';

export {
  ContinuousLearningSystem,
  createContinuousLearningSystem,
} from './experimental/integration';

// Export types - Phase 5.1
export type {
  TrainingExample,
  QualityMetrics,
} from './experimental/data_collector';

export type {
  HTBMachine,
  SpawnResult,
  FlagResult,
  UserStats,
  MachineFilters,
  HTBAPIConfig,
} from './experimental/htb_api';

// Export types - Phase 5.2
export type {
  TrainingJobConfig,
  TrainingJobStatus,
  TrainingMetrics,
} from './experimental/training_manager';

export type {
  ModelVersion,
  ModelComparison,
  RollbackResult,
} from './experimental/model_manager';

// Export types - Phase 5.3
export type {
  LearningLoopState,
  LearningLoopConfig,
  TriggerConditions,
  CycleResult,
} from './experimental/learning_loop';

export type {
  ABTest,
  ABTestConfig,
  ABTestMetrics,
  TestResult,
} from './experimental/ab_testing';

export type {
  PerformanceMetrics,
  DifficultyMetrics,
  Anomaly,
  AlertConfig,
  TrendAnalysis,
  DashboardData,
} from './experimental/performance_monitor';

export type {
  DeploymentConfig,
  DeploymentStatus,
  DeploymentHistory,
  HealthCheckResult,
  RolloutStage,
} from './experimental/deployment_manager';

export type {
  ScheduleConfig,
  ScheduledTask,
  ResourceAvailability,
  SchedulePriority,
} from './experimental/scheduler';

export type {
  ReadinessConfig,
  ReadinessReport,
  CheckResult,
  QualityGate,
} from './experimental/readiness_checker';

export type {
  RollbackConfig,
  RollbackOperation,
  RollbackStep,
  RollbackValidation,
  RollbackHistory,
  RollbackReason,
} from './experimental/rollback_manager';

export type {
  HealthCheckConfig,
  SystemHealthReport,
  ComponentHealth,
  HealthAlert,
  HealthStatus,
  AlertSeverity,
} from './experimental/health_checker';

export type {
  ContinuousLearningConfig,
  SystemStatus,
} from './experimental/integration';

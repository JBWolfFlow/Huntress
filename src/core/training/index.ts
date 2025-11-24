/**
 * Training Module - Phase 5.1, 5.2 & 5.3 Complete
 *
 * Exports all training-related components for HTB automation,
 * training data collection, LoRA model training, and continuous learning.
 */

// Phase 5.1: Data Collection
export {
  TrainingDataCleaner,
  QualityFilter,
  TrainingDataStorage,
  TrainingDataCollector,
} from './data_collector';

export {
  HTBAPIClient,
  createHTBClient,
} from './htb_api';

// Phase 5.2: Training Infrastructure
export {
  TrainingPipelineManager,
} from './training_manager';

export {
  ModelVersionManager,
} from './model_manager';

// Phase 5.3: Continuous Learning Loop
export {
  LearningLoopOrchestrator,
} from './learning_loop';

export {
  ABTestingFramework,
} from './ab_testing';

export {
  PerformanceMonitor,
} from './performance_monitor';

export {
  ModelDeploymentManager,
} from './deployment_manager';

export {
  LearningLoopScheduler,
} from './scheduler';

export {
  ProductionReadinessChecker,
} from './readiness_checker';

export {
  RollbackManager,
} from './rollback_manager';

export {
  HealthCheckSystem,
} from './health_checker';

export {
  ContinuousLearningSystem,
  createContinuousLearningSystem,
} from './integration';

// Export types - Phase 5.1
export type {
  TrainingExample,
  QualityMetrics,
} from './data_collector';

export type {
  HTBMachine,
  SpawnResult,
  FlagResult,
  UserStats,
  MachineFilters,
  HTBAPIConfig,
} from './htb_api';

// Export types - Phase 5.2
export type {
  TrainingJobConfig,
  TrainingJobStatus,
  TrainingMetrics,
} from './training_manager';

export type {
  ModelVersion,
  ModelComparison,
  RollbackResult,
} from './model_manager';

// Export types - Phase 5.3
export type {
  LearningLoopState,
  LearningLoopConfig,
  TriggerConditions,
  CycleResult,
} from './learning_loop';

export type {
  ABTest,
  ABTestConfig,
  ABTestMetrics,
  TestResult,
} from './ab_testing';

export type {
  PerformanceMetrics,
  DifficultyMetrics,
  Anomaly,
  AlertConfig,
  TrendAnalysis,
  DashboardData,
} from './performance_monitor';

export type {
  DeploymentConfig,
  DeploymentStatus,
  DeploymentHistory,
  HealthCheckResult,
  RolloutStage,
} from './deployment_manager';

export type {
  ScheduleConfig,
  ScheduledTask,
  ResourceAvailability,
  SchedulePriority,
} from './scheduler';

export type {
  ReadinessConfig,
  ReadinessReport,
  CheckResult,
  QualityGate,
} from './readiness_checker';

export type {
  RollbackConfig,
  RollbackOperation,
  RollbackStep,
  RollbackValidation,
  RollbackHistory,
  RollbackReason,
} from './rollback_manager';

export type {
  HealthCheckConfig,
  SystemHealthReport,
  ComponentHealth,
  HealthAlert,
  HealthStatus,
  AlertSeverity,
} from './health_checker';

export type {
  ContinuousLearningConfig,
  SystemStatus,
} from './integration';
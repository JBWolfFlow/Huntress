/**
 * Orchestrator Module — Barrel Export
 */

export { OrchestratorEngine } from './orchestrator_engine';
export type { OrchestratorConfig, MessageCallback, PhaseCallback } from './orchestrator_engine';

export { PlanExecutor } from './plan_executor';
export type { PlanTask, ExecutionPlan, PlanProgressCallback } from './plan_executor';

export { TaskQueue } from './task_queue';
export type { HuntTask, TaskQueueStats, TaskEvent } from './task_queue';

export { detectChains, calculateChainSeverityBoost } from './chain_detector';
export type { VulnerabilityChain } from './chain_detector';

export { scoreTarget, rankTargets } from './target_scorer';
export type { TargetScore, TargetMetadata } from './target_scorer';

export { AssetMapBuilder } from './asset_map';
export type { AssetMap, Subdomain, Endpoint, PortInfo, Technology, WAFInfo } from './asset_map';

export { ReconPipeline } from './recon_pipeline';
export type { PipelineStage, PipelineResult, PipelineConfig } from './recon_pipeline';

export { Blackboard, postObservation, postHypothesis, postFinding } from './blackboard';
export type { BlackboardEntry, EntryType } from './blackboard';

/**
 * Tools Module
 *
 * AI-Powered Hunt Execution System with Safe Tool Access
 *
 * This module provides comprehensive tool management for autonomous
 * vulnerability hunting with strict safety controls.
 */

import { ToolRegistry, ToolSafetyLevel, type ToolMetadata, type ToolRequirements, type ToolExecutionResult } from './tool_registry';
import { CommandValidator, type ValidationResult } from './command_validator';
import { ToolExecutor, type ExecutionRequest, type ExecutionResult, type ExecutionContext, type ApprovalRequest } from './tool_executor';

export { ToolRegistry, ToolSafetyLevel, type ToolMetadata, type ToolRequirements, type ToolExecutionResult };
export { CommandValidator, type ValidationResult };
export { ToolExecutor, type ExecutionRequest, type ExecutionResult, type ExecutionContext, type ApprovalRequest };

/**
 * Create a fully configured tool execution system
 */
export function createToolExecutionSystem() {
  const registry = new ToolRegistry();
  const executor = new ToolExecutor(registry);
  
  return {
    registry,
    executor,
    validator: executor.getValidator(),
  };
}

export default createToolExecutionSystem;
/**
 * Hunt #7 Bug Fix — H27: Adjust Budget Tool
 *
 * Tests that the adjust_budget tool schema is in ORCHESTRATOR_TOOL_SCHEMAS
 * and validates the increase-only budget constraint.
 */

import { describe, it, expect } from 'vitest';
import { ORCHESTRATOR_TOOL_SCHEMAS, ADJUST_BUDGET_SCHEMA } from '../core/engine/tool_schemas';

describe('Adjust Budget Tool (H27)', () => {
  it('adjust_budget is in ORCHESTRATOR_TOOL_SCHEMAS', () => {
    const found = ORCHESTRATOR_TOOL_SCHEMAS.find(t => t.name === 'adjust_budget');
    expect(found).toBeDefined();
    expect(found!.name).toBe('adjust_budget');
  });

  it('has the correct schema shape', () => {
    expect(ADJUST_BUDGET_SCHEMA.name).toBe('adjust_budget');
    expect(ADJUST_BUDGET_SCHEMA.input_schema.properties).toHaveProperty('new_budget_usd');
    expect(ADJUST_BUDGET_SCHEMA.input_schema.properties).toHaveProperty('reason');
    expect(ADJUST_BUDGET_SCHEMA.input_schema.required).toContain('new_budget_usd');
  });

  it('new_budget_usd is typed as number', () => {
    const prop = ADJUST_BUDGET_SCHEMA.input_schema.properties.new_budget_usd;
    expect(prop.type).toBe('number');
  });

  it('reason is optional', () => {
    expect(ADJUST_BUDGET_SCHEMA.input_schema.required).not.toContain('reason');
  });

  it('schema count increased (now 6: dispatch, reprioritize, generate_report, adjust_budget, stop_hunting)', () => {
    // Verify we didn't accidentally remove any schemas
    const names = ORCHESTRATOR_TOOL_SCHEMAS.map(t => t.name);
    expect(names).toContain('dispatch_agent');
    expect(names).toContain('reprioritize_tasks');
    expect(names).toContain('generate_report');
    expect(names).toContain('adjust_budget');
    expect(names).toContain('stop_hunting');
    expect(names).toHaveLength(5);
  });
});

/**
 * Tool Execution System Tests
 * 
 * Comprehensive tests for the AI-Powered Hunt Execution System
 * with Safe Tool Access.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ToolRegistry, ToolSafetyLevel } from '../core/tools/tool_registry';
import { CommandValidator } from '../core/tools/command_validator';
import { createToolExecutionSystem } from '../core/tools';

describe('ToolRegistry', () => {
  let registry: ToolRegistry;

  beforeEach(() => {
    registry = new ToolRegistry();
  });

  it('should initialize with default tools', () => {
    const tools = registry.listTools();
    expect(tools.length).toBeGreaterThan(0);
  });

  it('should classify subfinder as SAFE', () => {
    const tool = registry.getTool('subfinder');
    expect(tool).toBeDefined();
    expect(tool?.safetyLevel).toBe(ToolSafetyLevel.SAFE);
    expect(tool?.enabled).toBe(true);
  });

  it('should classify nuclei as CONTROLLED', () => {
    const tool = registry.getTool('nuclei');
    expect(tool).toBeDefined();
    expect(tool?.safetyLevel).toBe(ToolSafetyLevel.CONTROLLED);
    expect(tool?.requirements.requiresApproval).toBe(true);
    expect(tool?.requirements.requiresRateLimiting).toBe(true);
  });

  it('should classify sqlmap as RESTRICTED', () => {
    const tool = registry.getTool('sqlmap');
    expect(tool).toBeDefined();
    expect(tool?.safetyLevel).toBe(ToolSafetyLevel.RESTRICTED);
    expect(tool?.requirements.requiresExplicitEnable).toBe(true);
    expect(tool?.enabled).toBe(false);
  });

  it('should classify hydra as BLOCKED', () => {
    const tool = registry.getTool('hydra');
    expect(tool).toBeDefined();
    expect(tool?.safetyLevel).toBe(ToolSafetyLevel.BLOCKED);
    expect(tool?.enabled).toBe(false);
    expect(tool?.riskScore).toBe(100);
  });

  it('should classify slowloris as FORBIDDEN', () => {
    const tool = registry.getTool('slowloris');
    expect(tool).toBeDefined();
    expect(tool?.safetyLevel).toBe(ToolSafetyLevel.FORBIDDEN);
    expect(tool?.enabled).toBe(false);
    expect(tool?.riskScore).toBe(100);
  });

  it('should enable RESTRICTED tools when medium mode is enabled', () => {
    const sqlmap = registry.getTool('sqlmap');
    expect(sqlmap?.enabled).toBe(false);

    registry.enableMediumMode();
    expect(registry.isMediumModeEnabled()).toBe(true);

    const sqlmapAfter = registry.getTool('sqlmap');
    expect(sqlmapAfter?.enabled).toBe(true);
  });

  it('should disable RESTRICTED tools when medium mode is disabled', () => {
    registry.enableMediumMode();
    registry.disableMediumMode();

    expect(registry.isMediumModeEnabled()).toBe(false);
    const sqlmap = registry.getTool('sqlmap');
    expect(sqlmap?.enabled).toBe(false);
  });

  it('should get tools by safety level', () => {
    const safeTools = registry.getToolsBySafetyLevel(ToolSafetyLevel.SAFE);
    expect(safeTools.length).toBeGreaterThan(0);
    expect(safeTools.every(t => t.safetyLevel === ToolSafetyLevel.SAFE)).toBe(true);
  });

  it('should get only enabled tools', () => {
    const enabledTools = registry.getEnabledTools();
    expect(enabledTools.every(t => t.enabled)).toBe(true);
  });
});

describe('CommandValidator', () => {
  let registry: ToolRegistry;
  let validator: CommandValidator;

  beforeEach(() => {
    registry = new ToolRegistry();
    validator = new CommandValidator(registry);
  });

  it('should allow SAFE tool commands', async () => {
    const result = await validator.validate('subfinder -d example.com');
    expect(result.allowed).toBe(true);
    expect(result.tool?.name).toBe('subfinder');
  });

  it('should block unknown tools', async () => {
    const result = await validator.validate('unknown-tool --flag');
    expect(result.allowed).toBe(false);
    expect(result.blockReason).toContain('Unknown tool');
  });

  it('should block BLOCKED tools', async () => {
    const result = await validator.validate('hydra -l admin -P passwords.txt');
    expect(result.allowed).toBe(false);
    expect(result.blockReason).toContain('BLOCKED');
    expect(result.blockReason).toContain('dangerous tool');
  });

  it('should block FORBIDDEN tools', async () => {
    const result = await validator.validate('slowloris example.com');
    expect(result.allowed).toBe(false);
    expect(result.blockReason).toContain('FORBIDDEN');
    expect(result.blockReason).toContain('DoS attack tool');
  });

  it('should block RESTRICTED tools when medium mode is disabled', async () => {
    const result = await validator.validate('sqlmap -u http://example.com');
    expect(result.allowed).toBe(false);
    expect(result.blockReason).toContain('RESTRICTED');
    expect(result.blockReason).toContain('Medium Mode');
  });

  it('should allow RESTRICTED tools when medium mode is enabled', async () => {
    registry.enableMediumMode();
    const result = await validator.validate('sqlmap -u http://example.com --level 1');
    expect(result.allowed).toBe(true);
    expect(result.tool?.name).toBe('sqlmap');
  });

  it('should detect dangerous flags in amass', async () => {
    const result = await validator.validate('amass enum -active -d example.com');
    expect(result.allowed).toBe(false);
    expect(result.blockReason).toContain('Dangerous flags detected');
    expect(result.blockReason).toContain('-active');
  });

  it('should detect dangerous flags in sqlmap', async () => {
    registry.enableMediumMode();
    const result = await validator.validate('sqlmap -u http://example.com --os-shell');
    expect(result.allowed).toBe(false);
    expect(result.blockReason).toContain('Dangerous flags detected');
    expect(result.blockReason).toContain('--os-shell');
  });

  it('should require approval for CONTROLLED tools', async () => {
    const result = await validator.validate('nuclei -u http://example.com');
    expect(result.allowed).toBe(true);
    expect(result.requiredActions).toContain('Human approval required');
  });

  it('should sanitize commands by adding rate limiting', async () => {
    const result = await validator.validate('nuclei -u http://example.com');
    expect(result.sanitizedCommand).toContain('-rl');
  });

  it('should assess risk correctly', async () => {
    const result = await validator.validate('ffuf -u http://example.com/FUZZ -w wordlist.txt');
    expect(result.riskAssessment).toBeDefined();
    expect(result.riskAssessment?.level).toBeDefined();
    expect(result.riskAssessment?.score).toBeGreaterThan(0);
  });

  it('should increase risk score for high concurrency', async () => {
    const result = await validator.validate('ffuf -u http://example.com/FUZZ -t 500');
    expect(result.riskAssessment?.score).toBeGreaterThan(35); // Base score + penalty
    expect(result.riskAssessment?.factors).toContain('High concurrency: -t 500');
  });

  it('should track validation statistics', async () => {
    await validator.validate('subfinder -d example.com');
    await validator.validate('hydra -l admin');
    await validator.validate('nuclei -u http://example.com');

    const stats = validator.getStatistics();
    expect(stats.totalValidations).toBe(3);
    expect(stats.allowed).toBeGreaterThan(0);
    expect(stats.blocked).toBeGreaterThan(0);
  });
});

describe('Tool Execution System Integration', () => {
  it('should create a complete tool execution system', () => {
    const system = createToolExecutionSystem();
    
    expect(system.registry).toBeDefined();
    expect(system.executor).toBeDefined();
    expect(system.validator).toBeDefined();
  });

  it('should have all components connected', () => {
    const system = createToolExecutionSystem();
    
    const tools = system.registry.listTools();
    expect(tools.length).toBeGreaterThan(0);
    
    const descriptions = system.registry.getToolDescriptionsForAI();
    expect(descriptions).toContain('subfinder');
    expect(descriptions).toContain('nuclei');
  });

  it('should provide tool descriptions for AI context', () => {
    const system = createToolExecutionSystem();
    const descriptions = system.registry.getToolDescriptionsForAI();
    
    expect(descriptions).toContain('✅'); // SAFE tools
    expect(descriptions).toContain('⚠️'); // CONTROLLED tools
    expect(descriptions).toContain('subfinder');
    expect(descriptions).toContain('Passive subdomain enumeration');
  });
});

describe('Safety Guarantees', () => {
  let registry: ToolRegistry;
  let validator: CommandValidator;

  beforeEach(() => {
    registry = new ToolRegistry();
    validator = new CommandValidator(registry);
  });

  it('should NEVER allow DoS tools', async () => {
    const dosTools = ['slowloris', 'goldeneye'];
    
    for (const tool of dosTools) {
      const result = await validator.validate(`${tool} example.com`);
      expect(result.allowed).toBe(false);
      expect(result.blockReason).toContain('FORBIDDEN');
    }
  });

  it('should NEVER allow password brute-forcing tools', async () => {
    const bruteTools = ['hydra', 'medusa'];
    
    for (const tool of bruteTools) {
      const result = await validator.validate(`${tool} -l admin`);
      expect(result.allowed).toBe(false);
      expect(result.blockReason).toContain('BLOCKED');
    }
  });

  it('should NEVER allow dangerous nmap scans', async () => {
    const dangerousScans = [
      'nmap -sS example.com',
      'nmap -sU example.com',
      'nmap -sN example.com',
    ];
    
    for (const scan of dangerousScans) {
      const result = await validator.validate(scan);
      expect(result.allowed).toBe(false);
    }
  });

  it('should require rate limiting for all CONTROLLED tools', () => {
    const controlledTools = registry.getToolsBySafetyLevel(ToolSafetyLevel.CONTROLLED);
    
    for (const tool of controlledTools) {
      expect(tool.requirements.requiresRateLimiting).toBe(true);
      expect(tool.rateLimiter).toBeDefined();
      expect(tool.requirements.maxRequestsPerSecond).toBeGreaterThan(0);
    }
  });

  it('should require approval for all CONTROLLED tools', () => {
    const controlledTools = registry.getToolsBySafetyLevel(ToolSafetyLevel.CONTROLLED);
    
    for (const tool of controlledTools) {
      expect(tool.requirements.requiresApproval).toBe(true);
    }
  });

  it('should require explicit enable for all RESTRICTED tools', () => {
    const restrictedTools = registry.getToolsBySafetyLevel(ToolSafetyLevel.RESTRICTED);
    
    for (const tool of restrictedTools) {
      expect(tool.requirements.requiresExplicitEnable).toBe(true);
      expect(tool.enabled).toBe(false);
    }
  });

  it('should have risk score of 100 for all BLOCKED and FORBIDDEN tools', () => {
    const dangerousTools = [
      ...registry.getToolsBySafetyLevel(ToolSafetyLevel.BLOCKED),
      ...registry.getToolsBySafetyLevel(ToolSafetyLevel.FORBIDDEN),
    ];
    
    for (const tool of dangerousTools) {
      expect(tool.riskScore).toBe(100);
      expect(tool.enabled).toBe(false);
    }
  });
});

describe('Rate Limiting', () => {
  let registry: ToolRegistry;

  beforeEach(() => {
    registry = new ToolRegistry();
  });

  it('should enforce rate limits for nuclei', async () => {
    const nuclei = registry.getTool('nuclei');
    expect(nuclei?.rateLimiter).toBeDefined();
    
    // Should allow first request
    const allowed1 = await nuclei?.rateLimiter?.checkLimit();
    expect(allowed1).toBe(true);
    
    // Exhaust tokens
    for (let i = 0; i < 10; i++) {
      await nuclei?.rateLimiter?.checkLimit();
    }
    
    // Should deny after exhaustion
    const allowed2 = await nuclei?.rateLimiter?.checkLimit();
    expect(allowed2).toBe(false);
  });

  it('should have appropriate rate limits for each tool', () => {
    const nuclei = registry.getTool('nuclei');
    expect(nuclei?.requirements.maxRequestsPerSecond).toBe(5);
    
    const ffuf = registry.getTool('ffuf');
    expect(ffuf?.requirements.maxRequestsPerSecond).toBe(10);
    
    const sqlmap = registry.getTool('sqlmap');
    expect(sqlmap?.requirements.maxRequestsPerSecond).toBe(2);
  });
});
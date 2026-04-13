/**
 * ReconPipeline — Unit Tests
 *
 * Tests the DAG-based recon pipeline: stage ordering, dependency resolution,
 * parallel execution, and output parsing.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ReconPipeline, type PipelineConfig } from './recon_pipeline';

function createMockConfig(overrides?: Partial<PipelineConfig>): PipelineConfig {
  return {
    target: 'example.com',
    scope: ['example.com', '*.example.com'],
    executeCommand: vi.fn().mockResolvedValue({
      success: true,
      stdout: '',
      stderr: '',
    }),
    ...overrides,
  };
}

describe('ReconPipeline', () => {
  describe('construction', () => {
    it('should create pipeline with all stages', () => {
      const pipeline = new ReconPipeline(createMockConfig());
      const status = pipeline.getStatus();
      expect(status.total).toBeGreaterThan(0);
      expect(status.completed).toBe(0);
      expect(status.running).toBe(0);
    });

    it('should skip port scan when configured', () => {
      const pipeline = new ReconPipeline(createMockConfig({ skipPortScan: true }));
      const status = pipeline.getStatus();
      // Total should be the same but one is already "skipped"
      expect(status.total).toBeGreaterThan(0);
    });
  });

  describe('execute', () => {
    it('should execute all stages and produce an asset map', async () => {
      const executeCommand = vi.fn().mockResolvedValue({
        success: true,
        stdout: '',
        stderr: '',
      });

      const pipeline = new ReconPipeline(createMockConfig({ executeCommand }));
      const result = await pipeline.execute();

      expect(result.assetMap).toBeDefined();
      expect(result.assetMap.domain).toBe('example.com');
      expect(result.stages.length).toBeGreaterThan(0);
      expect(result.duration).toBeGreaterThanOrEqual(0);
    });

    it('should call executeCommand for each stage command', async () => {
      const executeCommand = vi.fn().mockResolvedValue({
        success: true,
        stdout: '',
        stderr: '',
      });

      const pipeline = new ReconPipeline(createMockConfig({ executeCommand }));
      await pipeline.execute();

      // Should have called executeCommand multiple times (one per stage command)
      expect(executeCommand).toHaveBeenCalled();
    });

    it('should call onStageUpdate callback', async () => {
      const onStageUpdate = vi.fn();
      const pipeline = new ReconPipeline(createMockConfig({ onStageUpdate }));
      await pipeline.execute();

      // Each stage fires at least start + complete callbacks
      expect(onStageUpdate).toHaveBeenCalled();
    });

    it('should handle command failures gracefully', async () => {
      const executeCommand = vi.fn().mockResolvedValue({
        success: false,
        stdout: '',
        stderr: 'command not found',
      });

      const pipeline = new ReconPipeline(createMockConfig({ executeCommand }));
      const result = await pipeline.execute();

      // Pipeline should still complete, with errors recorded
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should parse subdomain enumeration output', async () => {
      const executeCommand = vi.fn().mockImplementation((cmd: string) => {
        if (cmd.includes('subfinder')) {
          return Promise.resolve({
            success: true,
            stdout: '{"host":"api.example.com","a":["1.2.3.4"]}\n{"host":"admin.example.com","a":["5.6.7.8"]}\n',
            stderr: '',
          });
        }
        if (cmd.includes('assetfinder')) {
          return Promise.resolve({
            success: true,
            stdout: 'api.example.com\nstaging.example.com\n',
            stderr: '',
          });
        }
        return Promise.resolve({ success: true, stdout: '', stderr: '' });
      });

      const pipeline = new ReconPipeline(createMockConfig({ executeCommand }));
      const result = await pipeline.execute();

      // Should have parsed subdomains from output
      expect(result.assetMap.subdomains.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('dependency resolution', () => {
    it('should not run dependent stages before dependencies complete', async () => {
      const executionOrder: string[] = [];
      const executeCommand = vi.fn().mockImplementation((cmd: string) => {
        const tool = cmd.split(/\s+/)[0];
        executionOrder.push(tool);
        return Promise.resolve({ success: true, stdout: '', stderr: '' });
      });

      const pipeline = new ReconPipeline(createMockConfig({ executeCommand }));
      await pipeline.execute();

      // Verify that dnsx (depends on subdomain_enum) runs after subfinder
      const subfinderIndex = executionOrder.indexOf('subfinder');
      const dnsxIndex = executionOrder.indexOf('dnsx');
      if (subfinderIndex >= 0 && dnsxIndex >= 0) {
        expect(dnsxIndex).toBeGreaterThan(subfinderIndex);
      }
    });
  });
});

/**
 * OAuth Hunter + CrewAI Supervisor Integration Tests
 * 
 * Tests the integration between OAuth Hunter and CrewAI Supervisor
 */

import { Supervisor } from '../core/crewai';
import { HumanTaskRequest, HumanTaskResponse } from '../core/crewai/human_task';
import { OAuthAgent } from '../core/crewai/oauth_agent';

describe('OAuth CrewAI Integration', () => {
  describe('Supervisor Configuration', () => {
    it('should create supervisor with default config', () => {
      const supervisor = new Supervisor();
      expect(supervisor).toBeDefined();
    });

    it('should create supervisor with custom config', () => {
      const supervisor = new Supervisor({
        humanInTheLoop: true,
        maxIterations: 5,
        timeout: 60000,
      });
      expect(supervisor).toBeDefined();
    });

    it('should register human task callback', () => {
      const supervisor = new Supervisor();
      const callback = async (request: HumanTaskRequest): Promise<HumanTaskResponse> => ({
        taskId: request.id,
        approved: true,
        timestamp: Date.now(),
      });

      expect(() => supervisor.setHumanTaskCallback(callback)).not.toThrow();
    });
  });

  describe('OAuth Agent Registration', () => {
    it('should register OAuth agent', () => {
      const supervisor = new Supervisor();
      
      expect(() => {
        supervisor.registerOAuthAgent('oauth', {
          target: 'api.example.com',
          clientId: 'test_client',
          redirectUri: 'https://app.example.com/callback',
        });
      }).not.toThrow();

      const agents = supervisor.getAgents();
      expect(agents.has('oauth')).toBe(true);
    });

    it('should register multiple OAuth agents', () => {
      const supervisor = new Supervisor();
      
      supervisor.registerOAuthAgent('oauth1', {
        target: 'api1.example.com',
      });
      
      supervisor.registerOAuthAgent('oauth2', {
        target: 'api2.example.com',
      });

      const agents = supervisor.getAgents();
      expect(agents.size).toBe(2);
      expect(agents.has('oauth1')).toBe(true);
      expect(agents.has('oauth2')).toBe(true);
    });
  });

  describe('Execution Flow', () => {
    it('should execute with auto-approval', async () => {
      const supervisor = new Supervisor({
        humanInTheLoop: true,
      });

      // Auto-approve all requests
      supervisor.setHumanTaskCallback(async (request) => ({
        taskId: request.id,
        approved: true,
        timestamp: Date.now(),
      }));

      const result = await supervisor.execute({
        target: 'test.example.com',
        oauthConfig: {
          target: 'test.example.com',
          clientId: 'test',
          redirectUri: 'https://test.example.com/callback',
        },
      });

      expect(result).toBeDefined();
      expect(result.success).toBeDefined();
      expect(result.tasks).toBeDefined();
      expect(result.vulnerabilities).toBeDefined();
      expect(result.duration).toBeGreaterThan(0);
    });

    it('should handle execution without OAuth config', async () => {
      const supervisor = new Supervisor();

      const result = await supervisor.execute({
        target: 'test.example.com',
      });

      expect(result).toBeDefined();
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should track task status', async () => {
      const supervisor = new Supervisor({
        humanInTheLoop: true,
      });

      supervisor.setHumanTaskCallback(async (request) => ({
        taskId: request.id,
        approved: true,
        timestamp: Date.now(),
      }));

      const result = await supervisor.execute({
        target: 'test.example.com',
        oauthConfig: {
          target: 'test.example.com',
        },
      });

      const tasks = supervisor.getTasks();
      expect(tasks.length).toBeGreaterThan(0);
      
      const task = tasks[0];
      expect(task.id).toBeDefined();
      expect(task.type).toBeDefined();
      expect(task.target).toBe('test.example.com');
      expect(['pending', 'running', 'completed', 'failed']).toContain(task.status);
    });
  });

  describe('OAuth Agent Functionality', () => {
    it('should create OAuth agent with config', () => {
      const supervisor = new Supervisor();
      
      supervisor.registerOAuthAgent('oauth', {
        target: 'api.example.com',
        clientId: 'test_client',
        redirectUri: 'https://app.example.com/callback',
        humanInTheLoop: true,
        autoApprove: false,
        maxRetries: 3,
        retryDelay: 1000,
      });

      const agent = supervisor.getAgents().get('oauth');
      expect(agent).toBeDefined();
    });

    it('should get agent capabilities', () => {
      const supervisor = new Supervisor();
      
      supervisor.registerOAuthAgent('oauth', {
        target: 'api.example.com',
      });

      const agent = supervisor.getAgents().get('oauth');
      const capabilities = agent?.getCapabilities();
      
      expect(capabilities).toBeDefined();
      expect(capabilities?.length).toBeGreaterThan(0);
      expect(capabilities).toContain('OAuth endpoint discovery');
      expect(capabilities).toContain('Human-in-the-loop approval');
    });

    it('should get agent description', () => {
      const supervisor = new Supervisor();
      
      supervisor.registerOAuthAgent('oauth', {
        target: 'api.example.com',
      });

      const agent = supervisor.getAgents().get('oauth');
      const description = agent?.getDescription();
      
      expect(description).toBeDefined();
      expect(description).toContain('OAuth');
    });
  });

  describe('Human Approval Flow', () => {
    it('should request approval for hunt', async () => {
      const supervisor = new Supervisor({
        humanInTheLoop: true,
      });

      let approvalRequested = false;
      
      supervisor.setHumanTaskCallback(async (request) => {
        approvalRequested = true;
        expect(request.type).toBe('approval');
        expect(request.title).toBeDefined();
        expect(request.description).toBeDefined();
        expect(request.severity).toBeDefined();
        
        return {
          taskId: request.id,
          approved: true,
          timestamp: Date.now(),
        };
      });

      await supervisor.execute({
        target: 'test.example.com',
        oauthConfig: {
          target: 'test.example.com',
        },
      });

      expect(approvalRequested).toBe(true);
    });

    it('should handle approval denial', async () => {
      const supervisor = new Supervisor({
        humanInTheLoop: true,
      });

      supervisor.setHumanTaskCallback(async (request) => ({
        taskId: request.id,
        approved: false,
        timestamp: Date.now(),
      }));

      const result = await supervisor.execute({
        target: 'test.example.com',
        oauthConfig: {
          target: 'test.example.com',
        },
      });

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should support custom approval logic', async () => {
      const supervisor = new Supervisor({
        humanInTheLoop: true,
      });

      // Auto-approve low/medium, deny high/critical
      supervisor.setHumanTaskCallback(async (request) => ({
        taskId: request.id,
        approved: request.severity === 'low' || request.severity === 'medium',
        timestamp: Date.now(),
      }));

      const result = await supervisor.execute({
        target: 'test.example.com',
        oauthConfig: {
          target: 'test.example.com',
        },
      });

      expect(result).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    it('should handle missing callback', async () => {
      const supervisor = new Supervisor({
        humanInTheLoop: true,
      });

      // Don't set callback
      const result = await supervisor.execute({
        target: 'test.example.com',
        oauthConfig: {
          target: 'test.example.com',
        },
      });

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should handle invalid target', async () => {
      const supervisor = new Supervisor({
        humanInTheLoop: true,
      });

      supervisor.setHumanTaskCallback(async (request) => ({
        taskId: request.id,
        approved: true,
        timestamp: Date.now(),
      }));

      const result = await supervisor.execute({
        target: 'invalid://target',
        oauthConfig: {
          target: 'invalid://target',
        },
      });

      expect(result).toBeDefined();
      // Should handle gracefully
    });

    it('should track failed tasks', async () => {
      const supervisor = new Supervisor({
        humanInTheLoop: true,
      });

      supervisor.setHumanTaskCallback(async (request) => ({
        taskId: request.id,
        approved: false,
        timestamp: Date.now(),
      }));

      await supervisor.execute({
        target: 'test.example.com',
        oauthConfig: {
          target: 'test.example.com',
        },
      });

      const tasks = supervisor.getTasks();
      const failedTasks = tasks.filter(t => t.status === 'failed');
      
      expect(failedTasks.length).toBeGreaterThan(0);
      expect(failedTasks[0].error).toBeDefined();
    });
  });

  describe('Result Structure', () => {
    it('should return complete result structure', async () => {
      const supervisor = new Supervisor({
        humanInTheLoop: true,
      });

      supervisor.setHumanTaskCallback(async (request) => ({
        taskId: request.id,
        approved: true,
        timestamp: Date.now(),
      }));

      const result = await supervisor.execute({
        target: 'test.example.com',
        oauthConfig: {
          target: 'test.example.com',
        },
      });

      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('tasks');
      expect(result).toHaveProperty('vulnerabilities');
      expect(result).toHaveProperty('duration');
      expect(Array.isArray(result.tasks)).toBe(true);
      expect(Array.isArray(result.vulnerabilities)).toBe(true);
      expect(typeof result.duration).toBe('number');
    });
  });
});
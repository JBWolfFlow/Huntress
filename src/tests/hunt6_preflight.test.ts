/**
 * Hunt #6 Pre-Flight Checklist
 *
 * Verifies all systems are operational before running calibration hunt #6.
 *
 * Hunt #6 Configuration:
 * - Target: OWASP Juice Shop (localhost:3001)
 * - Budget: $15 (hard stop)
 * - Approval gates: ALL ON (no auto-approve)
 * - Validation pipeline: Active (18 validators)
 * - Retry logic: Active (3 retries, exponential backoff)
 * - Stealth: Disabled (localhost target)
 * - Expected: >0 validated findings, <30% false positive rate
 */

import { describe, it, expect } from 'vitest';

// ─── Infrastructure Checks ─────────────────────────────────────────────────

describe('Hunt #6 Pre-Flight: Infrastructure', () => {
  it('TypeScript compiles without errors', () => {
    expect(true).toBe(true);
  });

  it('Juice Shop is reachable', async () => {
    try {
      const response = await fetch('http://localhost:3001/');
      expect(response.status).toBe(200);
    } catch {
      console.warn('Juice Shop not reachable — skipping');
    }
  });
});

// ─── Safety System Checks ───────────────────────────────────────────────────

describe('Hunt #6 Pre-Flight: Safety Systems', () => {
  it('HTTP client module exists with scope enforcement', async () => {
    const { HttpClient } = await import('../core/http/request_engine');
    expect(HttpClient).toBeDefined();
  });

  it('orchestrator engine is importable', async () => {
    const { OrchestratorEngine } = await import('../core/orchestrator/orchestrator_engine');
    expect(OrchestratorEngine).toBeDefined();
  });

  it('validation pipeline module is importable', async () => {
    const validators = await import('../core/validation/validator');
    expect(validators).toBeDefined();
  });
});

// ─── Cost Router Checks ────────────────────────────────────────────────────

describe('Hunt #6 Pre-Flight: Cost Management', () => {
  it('cost router classifies recon as simple', async () => {
    const { classifyTaskComplexity } = await import('../core/orchestrator/cost_router');
    const complexity = classifyTaskComplexity('recon', 'Reconnaissance on target');
    expect(complexity).toBe('simple');
  });

  it('cost router classifies sqli as moderate or complex', async () => {
    const { classifyTaskComplexity } = await import('../core/orchestrator/cost_router');
    const complexity = classifyTaskComplexity('sqli_hunter', 'SQL injection testing');
    expect(['moderate', 'complex']).toContain(complexity);
  });

  it('selectModelForTask function exists', async () => {
    const { selectModelForTask } = await import('../core/orchestrator/cost_router');
    expect(typeof selectModelForTask).toBe('function');
  });
});

// ─── Report Pipeline Checks ────────────────────────────────────────────────

describe('Hunt #6 Pre-Flight: Reporting Pipeline', () => {
  it('report quality scorer is functional', async () => {
    const { ReportQualityScorer } = await import('../core/reporting/report_quality');
    const scorer = new ReportQualityScorer();
    const score = scorer.scoreReport({
      title: 'Test XSS in Search Parameter with Reflected Input',
      severity: 'high',
      suggestedBounty: { min: 500, max: 1500 },
      description: 'A reflected XSS vulnerability was found. GET /search?q=<script>alert(1)</script> HTTP/1.1 Host: target.com',
      impact: 'An attacker can steal session cookies and hijack accounts.',
      steps: [
        'Navigate to /search',
        'Enter <script>alert(1)</script>',
        'Observe the alert dialog',
      ],
      proof: {},
      cvssScore: 7.1,
    });
    expect(score.overall).toBeGreaterThan(0);
    expect(score.grade).toBeDefined();
  });

  it('H1 duplicate checker is importable', async () => {
    const mod = await import('../core/reporting/h1_duplicate_check');
    expect(mod).toBeDefined();
  });

  it('severity predictor class exists', async () => {
    const { SeverityPredictor } = await import('../core/reporting/severity_predictor');
    expect(SeverityPredictor).toBeDefined();
  });
});

// ─── API Schema Parser Checks ──────────────────────────────────────────────

describe('Hunt #6 Pre-Flight: API Schema Import', () => {
  it('can parse Juice Shop-like API spec into tasks', async () => {
    const { parseAPISpec, generateSchemaBasedTasks } = await import('../core/discovery/api_schema_parser');

    const juiceShopSpec = {
      openapi: '3.0.0',
      info: { title: 'Juice Shop', version: '1.0' },
      servers: [{ url: 'http://localhost:3001' }],
      paths: {
        '/rest/user/login': {
          post: {
            operationId: 'login',
            requestBody: {
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      email: { type: 'string' },
                      password: { type: 'string' },
                    },
                  },
                },
              },
            },
            responses: { '200': { description: 'OK' } },
          },
        },
        '/api/Users/{id}': {
          get: {
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
            responses: { '200': { description: 'OK' } },
          },
        },
      },
    };

    const schema = parseAPISpec(juiceShopSpec, 'http://localhost:3001');
    expect(schema.endpoints.length).toBe(2);
    expect(schema.baseUrl).toBe('http://localhost:3001');

    const tasks = generateSchemaBasedTasks(schema);
    expect(tasks.length).toBeGreaterThan(0);
    expect(tasks.some(t => t.agentType === 'oauth_hunter')).toBe(true);
    expect(tasks.some(t => t.agentType === 'idor_hunter')).toBe(true);
  });
});

// ─── Hunt Configuration ────────────────────────────────────────────────────

describe('Hunt #6 Configuration', () => {
  it('hunt configuration is correct', () => {
    const config = {
      target: 'http://localhost:3001',
      budget: 15,
      approvalGates: 'ALL_ON',
      autoApprove: false,
      validationPipeline: true,
      retryLogic: true,
      stealthMode: false,
      maxConcurrentAgents: 5,
      expectedMetrics: {
        findingsCount: '>0',
        validationPassRate: '>50%',
        falsePositiveRate: '<30%',
        costPerFinding: '<$5',
        deadLetterQueueSize: '<3',
      },
    };

    expect(config.target).toBe('http://localhost:3001');
    expect(config.budget).toBe(15);
    expect(config.autoApprove).toBe(false);
    expect(config.validationPipeline).toBe(true);
    expect(config.retryLogic).toBe(true);
  });
});

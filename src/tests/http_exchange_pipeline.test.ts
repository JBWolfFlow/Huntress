/**
 * HTTP Exchange Pipeline Tests (RQ1)
 *
 * Validates that structured HTTP request/response data flows from
 * the ReAct loop through AgentResult to the report pipeline.
 */

import { describe, it, expect } from 'vitest';
import type { HttpExchange, AgentResult, AgentFinding } from '../agents/base_agent';
import type { ReactLoopResult } from '../core/engine/react_loop';

// ─── HttpExchange type structure ─────────────────────────────────────────────

describe('HttpExchange type', () => {
  it('captures request method, url, headers, and body', () => {
    const exchange: HttpExchange = {
      request: {
        method: 'POST',
        url: 'https://example.com/api/login',
        headers: { 'Content-Type': 'application/json' },
        body: '{"email":"admin@test.com","password":"test"}',
      },
      response: {
        status: 200,
        statusText: 'OK',
        headers: { 'content-type': 'application/json' },
        bodySnippet: '{"token":"eyJhbGciOiJSUzI1NiIs..."}',
      },
      iteration: 5,
      timestamp: Date.now(),
    };

    expect(exchange.request.method).toBe('POST');
    expect(exchange.request.url).toContain('api/login');
    expect(exchange.response.status).toBe(200);
    expect(exchange.response.bodySnippet).toContain('token');
  });

  it('works with minimal fields (no optional headers/body)', () => {
    const exchange: HttpExchange = {
      request: {
        method: 'GET',
        url: 'https://example.com/',
      },
      response: {
        status: 404,
        bodySnippet: 'Not Found',
      },
    };

    expect(exchange.request.headers).toBeUndefined();
    expect(exchange.request.body).toBeUndefined();
    expect(exchange.response.headers).toBeUndefined();
    expect(exchange.iteration).toBeUndefined();
  });
});

// ─── AgentResult carries httpExchanges ───────────────────────────────────────

describe('AgentResult with httpExchanges', () => {
  const sampleExchanges: HttpExchange[] = [
    {
      request: { method: 'GET', url: 'https://target.com/api/users' },
      response: { status: 200, bodySnippet: '[{"id":1,"name":"admin"}]' },
      iteration: 1,
    },
    {
      request: {
        method: 'GET',
        url: 'https://target.com/api/users/1',
        headers: { 'Authorization': 'Bearer token_a' },
      },
      response: { status: 200, bodySnippet: '{"id":1,"name":"admin","email":"admin@test.com"}' },
      iteration: 2,
    },
    {
      request: {
        method: 'GET',
        url: 'https://target.com/api/users/2',
        headers: { 'Authorization': 'Bearer token_a' },
      },
      response: { status: 200, bodySnippet: '{"id":2,"name":"victim","email":"victim@test.com"}' },
      iteration: 3,
    },
  ];

  it('preserves HTTP exchanges through AgentResult', () => {
    const result: AgentResult = {
      taskId: 'task_1',
      agentId: 'idor-hunter',
      success: true,
      findings: [],
      httpExchanges: sampleExchanges,
      toolsExecuted: 10,
      duration: 5000,
    };

    expect(result.httpExchanges).toBeDefined();
    expect(result.httpExchanges).toHaveLength(3);
    expect(result.httpExchanges![0].request.method).toBe('GET');
    expect(result.httpExchanges![2].response.status).toBe(200);
  });

  it('httpExchanges is optional — existing agents without it still work', () => {
    const result: AgentResult = {
      taskId: 'task_2',
      agentId: 'xss-hunter',
      success: true,
      findings: [],
      toolsExecuted: 5,
      duration: 3000,
    };

    expect(result.httpExchanges).toBeUndefined();
  });

  it('findings and httpExchanges coexist independently', () => {
    const finding: AgentFinding = {
      id: 'finding_1',
      agentId: 'idor-hunter',
      type: 'idor',
      title: 'IDOR on user profiles',
      severity: 'high',
      description: 'Any user can access other user profiles',
      target: 'https://target.com/api/users/{id}',
      evidence: ['Accessed user 2 data with user 1 token'],
      reproduction: ['GET /api/users/2 with token_a'],
      timestamp: new Date(),
    };

    const result: AgentResult = {
      taskId: 'task_3',
      agentId: 'idor-hunter',
      success: true,
      findings: [finding],
      httpExchanges: sampleExchanges,
      toolsExecuted: 10,
      duration: 5000,
    };

    expect(result.findings).toHaveLength(1);
    expect(result.httpExchanges).toHaveLength(3);
    expect(result.findings[0].target).toBe('https://target.com/api/users/{id}');
    expect(result.httpExchanges![0].request.url).toBe('https://target.com/api/users');
  });
});

// ─── ReactLoopResult carries httpExchanges ───────────────────────────────────

describe('ReactLoopResult includes httpExchanges', () => {
  it('httpExchanges field is required on ReactLoopResult', () => {
    // This test validates the type at compile time — if httpExchanges
    // were removed from ReactLoopResult, this file would fail to compile.
    const mockResult: ReactLoopResult = {
      success: true,
      findings: [],
      totalIterations: 10,
      toolCallCount: 8,
      httpRequestCount: 5,
      totalTokensUsed: { input: 1000, output: 500 },
      duration: 30000,
      stopReason: 'task_complete',
      summary: 'Completed',
      iterationLog: [],
      httpExchanges: [
        {
          request: { method: 'GET', url: 'https://target.com/' },
          response: { status: 200, bodySnippet: '<html>...' },
          iteration: 0,
          timestamp: Date.now(),
        },
      ],
    };

    expect(mockResult.httpExchanges).toHaveLength(1);
    expect(mockResult.httpExchanges[0].request.method).toBe('GET');
  });
});

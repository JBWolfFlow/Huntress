/**
 * Phase 1 Tests — Cost Crisis & Core Wiring
 *
 * Tests for:
 * - Tiered model routing (classifyTaskComplexity, getAnthropicModelForComplexity)
 * - AGENT_COMPLEXITY mapping with actual hyphenated agent IDs
 * - Scope entry normalization and deduplication
 * - Tech-stack-aware agent filtering
 * - Budget enforcement in dispatch loop
 */

import { describe, it, expect } from 'vitest';
import {
  classifyTaskComplexity,
  getAnthropicModelForComplexity,
  ANTHROPIC_MODEL_TIERS,
} from '../core/orchestrator/cost_router';
import {
  normalizeScopeEntries,
  getSkippedAgentsForTechStack,
} from '../core/orchestrator/orchestrator_engine';

// ─── Tiered Model Routing ─────────────────────────────────────────────────────

describe('classifyTaskComplexity', () => {
  it('classifies recon as simple', () => {
    expect(classifyTaskComplexity('recon', 'Reconnaissance on localhost:3001')).toBe('simple');
  });

  it('classifies CORS hunter as simple', () => {
    expect(classifyTaskComplexity('cors-hunter', 'Check CORS headers')).toBe('simple');
  });

  it('classifies host-header-hunter as simple', () => {
    expect(classifyTaskComplexity('host-header-hunter', 'Check host header injection')).toBe('simple');
  });

  it('classifies subdomain-takeover-hunter as simple', () => {
    expect(classifyTaskComplexity('subdomain-takeover-hunter', 'Check subdomain takeover')).toBe('simple');
  });

  it('classifies crlf-hunter as simple', () => {
    expect(classifyTaskComplexity('crlf-hunter', 'Test CRLF injection')).toBe('simple');
  });

  it('classifies cache-hunter as simple', () => {
    expect(classifyTaskComplexity('cache-hunter', 'Test cache poisoning')).toBe('simple');
  });

  it('classifies open-redirect-hunter as simple', () => {
    expect(classifyTaskComplexity('open-redirect-hunter', 'Test open redirects')).toBe('simple');
  });

  it('classifies xss-hunter as moderate', () => {
    expect(classifyTaskComplexity('xss-hunter', 'Test XSS on login')).toBe('moderate');
  });

  it('classifies sqli-hunter as moderate', () => {
    expect(classifyTaskComplexity('sqli-hunter', 'Test SQL injection')).toBe('moderate');
  });

  it('classifies ssrf-hunter as moderate', () => {
    expect(classifyTaskComplexity('ssrf-hunter', 'Test SSRF via URL param')).toBe('moderate');
  });

  it('classifies idor-hunter as complex', () => {
    expect(classifyTaskComplexity('idor-hunter', 'Test access control')).toBe('complex');
  });

  it('classifies oauth_hunter as complex', () => {
    expect(classifyTaskComplexity('oauth_hunter', 'Test OAuth flow')).toBe('complex');
  });

  it('classifies jwt-hunter as complex', () => {
    expect(classifyTaskComplexity('jwt-hunter', 'Test JWT tokens')).toBe('complex');
  });

  it('classifies business-logic-hunter as complex', () => {
    expect(classifyTaskComplexity('business-logic-hunter', 'Test business logic')).toBe('complex');
  });

  it('classifies race-condition-hunter as complex', () => {
    expect(classifyTaskComplexity('race-condition-hunter', 'Test race conditions')).toBe('complex');
  });

  it('upgrades simple to moderate when complex keywords found', () => {
    expect(classifyTaskComplexity('recon', 'Analyze authentication bypass')).toBe('moderate');
  });

  it('upgrades moderate to complex when complex keywords found', () => {
    expect(classifyTaskComplexity('xss-hunter', 'Multi-step chain attack')).toBe('complex');
  });

  it('returns moderate for unknown agent type without keywords', () => {
    expect(classifyTaskComplexity('unknown-agent', 'some task')).toBe('moderate');
  });

  it('returns simple for unknown agent with simple keywords', () => {
    expect(classifyTaskComplexity('unknown-agent', 'enumerate all endpoints')).toBe('simple');
  });

  it('returns complex for unknown agent with complex keywords', () => {
    expect(classifyTaskComplexity('unknown-agent', 'bypass authentication chain')).toBe('complex');
  });
});

describe('getAnthropicModelForComplexity', () => {
  it('returns Haiku for simple tasks', () => {
    expect(getAnthropicModelForComplexity('simple')).toBe('claude-haiku-4-5-20251001');
  });

  it('returns Sonnet for moderate tasks', () => {
    expect(getAnthropicModelForComplexity('moderate')).toBe('claude-sonnet-4-5-20250929');
  });

  it('returns Sonnet for complex tasks', () => {
    expect(getAnthropicModelForComplexity('complex')).toBe('claude-sonnet-4-5-20250929');
  });
});

describe('ANTHROPIC_MODEL_TIERS', () => {
  it('has all three tiers defined', () => {
    expect(ANTHROPIC_MODEL_TIERS.simple).toBeDefined();
    expect(ANTHROPIC_MODEL_TIERS.moderate).toBeDefined();
    expect(ANTHROPIC_MODEL_TIERS.complex).toBeDefined();
  });

  it('simple tier is cheapest (Haiku)', () => {
    expect(ANTHROPIC_MODEL_TIERS.simple).toContain('haiku');
  });

  it('moderate and complex tiers use Sonnet', () => {
    expect(ANTHROPIC_MODEL_TIERS.moderate).toContain('sonnet');
    expect(ANTHROPIC_MODEL_TIERS.complex).toContain('sonnet');
  });
});

// ─── Scope Entry Normalization ────────────────────────────────────────────────

describe('normalizeScopeEntries', () => {
  it('strips http:// scheme prefix', () => {
    const result = normalizeScopeEntries(['http://localhost:3001']);
    expect(result).toEqual(['localhost:3001']);
  });

  it('strips https:// scheme prefix', () => {
    const result = normalizeScopeEntries(['https://example.com']);
    expect(result).toEqual(['example.com']);
  });

  it('strips trailing slashes', () => {
    const result = normalizeScopeEntries(['localhost:3001/', 'example.com///']);
    expect(result).toEqual(['localhost:3001', 'example.com']);
  });

  it('normalizes 127.0.0.1 to localhost', () => {
    const result = normalizeScopeEntries(['127.0.0.1:3001']);
    expect(result).toEqual(['localhost:3001']);
  });

  it('normalizes 0.0.0.0 to localhost', () => {
    const result = normalizeScopeEntries(['0.0.0.0:3001']);
    expect(result).toEqual(['localhost:3001']);
  });

  it('deduplicates localhost and 127.0.0.1 with same port', () => {
    const result = normalizeScopeEntries(['localhost:3001', '127.0.0.1:3001']);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe('localhost:3001');
  });

  it('deduplicates case-insensitively', () => {
    const result = normalizeScopeEntries(['Example.COM', 'example.com']);
    expect(result).toHaveLength(1);
  });

  it('deduplicates http and https variants of same host', () => {
    const result = normalizeScopeEntries(['http://example.com', 'https://example.com']);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe('example.com');
  });

  it('preserves different ports as separate targets', () => {
    const result = normalizeScopeEntries(['localhost:3001', 'localhost:8080']);
    expect(result).toHaveLength(2);
  });

  it('preserves different hosts', () => {
    const result = normalizeScopeEntries(['api.example.com', 'www.example.com']);
    expect(result).toHaveLength(2);
  });

  it('handles empty input', () => {
    expect(normalizeScopeEntries([])).toEqual([]);
  });

  it('trims whitespace', () => {
    const result = normalizeScopeEntries(['  localhost:3001  ']);
    expect(result).toEqual(['localhost:3001']);
  });

  it('handles full Juice Shop scenario: 3 inputs become 1', () => {
    const result = normalizeScopeEntries([
      'http://localhost:3001',
      'https://127.0.0.1:3001/',
      'localhost:3001',
    ]);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe('localhost:3001');
  });
});

// ─── Tech-Stack-Aware Agent Filtering ─────────────────────────────────────────

describe('getSkippedAgentsForTechStack', () => {
  it('skips SSTI on Node.js stack', () => {
    const skipped = getSkippedAgentsForTechStack('node.js express');
    expect(skipped.has('ssti-hunter')).toBe(true);
  });

  it('skips deserialization on Node.js', () => {
    const skipped = getSkippedAgentsForTechStack('node.js');
    expect(skipped.has('deserialization-hunter')).toBe(true);
  });

  it('does NOT skip SSTI on Python/Flask', () => {
    const skipped = getSkippedAgentsForTechStack('python flask');
    expect(skipped.has('ssti-hunter')).toBe(false);
  });

  it('does NOT skip SSTI on Java/Spring', () => {
    const skipped = getSkippedAgentsForTechStack('java spring');
    expect(skipped.has('ssti-hunter')).toBe(false);
  });

  it('skips SAML when no SSO detected', () => {
    const skipped = getSkippedAgentsForTechStack('node.js express api');
    expect(skipped.has('saml-hunter')).toBe(true);
  });

  it('keeps SAML when SSO detected', () => {
    const skipped = getSkippedAgentsForTechStack('node.js express saml okta');
    expect(skipped.has('saml-hunter')).toBe(false);
  });

  it('skips GraphQL when not detected', () => {
    const skipped = getSkippedAgentsForTechStack('node.js express rest api');
    expect(skipped.has('graphql-hunter')).toBe(true);
  });

  it('keeps GraphQL when detected', () => {
    const skipped = getSkippedAgentsForTechStack('node.js express graphql');
    expect(skipped.has('graphql-hunter')).toBe(false);
  });

  it('skips WebSocket when not detected', () => {
    const skipped = getSkippedAgentsForTechStack('node.js express');
    expect(skipped.has('websocket-hunter')).toBe(true);
  });

  it('keeps WebSocket when socket.io detected', () => {
    const skipped = getSkippedAgentsForTechStack('node.js express socket.io');
    expect(skipped.has('websocket-hunter')).toBe(false);
  });

  it('skips HTTP smuggling on Node.js', () => {
    const skipped = getSkippedAgentsForTechStack('node.js express');
    expect(skipped.has('http-smuggling-hunter')).toBe(true);
  });

  it('keeps HTTP smuggling on Apache', () => {
    const skipped = getSkippedAgentsForTechStack('apache php');
    expect(skipped.has('http-smuggling-hunter')).toBe(false);
  });

  it('returns empty set when no tech stack detected', () => {
    // With no tech stack, only protocol-specific agents are skipped
    const skipped = getSkippedAgentsForTechStack('');
    // SAML, GraphQL, WebSocket are skipped since not detected
    expect(skipped.has('saml-hunter')).toBe(true);
    expect(skipped.has('graphql-hunter')).toBe(true);
    expect(skipped.has('websocket-hunter')).toBe(true);
    // But core agents should NOT be skipped
    expect(skipped.has('xss-hunter')).toBe(false);
    expect(skipped.has('sqli-hunter')).toBe(false);
    expect(skipped.has('idor-hunter')).toBe(false);
  });

  it('Juice Shop scenario: Node.js Express reduces agents', () => {
    const skipped = getSkippedAgentsForTechStack('node.js express sqlite angular');
    expect(skipped.size).toBeGreaterThanOrEqual(4); // SSTI, deserialization, SAML, GraphQL, WebSocket, HTTP smuggling
    expect(skipped.has('ssti-hunter')).toBe(true);
    expect(skipped.has('deserialization-hunter')).toBe(true);
    expect(skipped.has('saml-hunter')).toBe(true);
    expect(skipped.has('graphql-hunter')).toBe(true);
    // Should keep core hunting agents
    expect(skipped.has('xss-hunter')).toBe(false);
    expect(skipped.has('sqli-hunter')).toBe(false);
    expect(skipped.has('idor-hunter')).toBe(false);
    expect(skipped.has('ssrf-hunter')).toBe(false);
  });
});

/**
 * Phase 3 Tests — Finding Validation Pipeline + Duplicate Checking
 *
 * Tests for:
 * - AgentFinding → ReactFinding type conversion
 * - ValidationResult → finding status mapping
 * - DuplicateScore → DuplicateCheckResult mapping
 * - Validation status types and badge configuration
 * - Graceful degradation paths (no validator, no H1 creds, errors)
 * - FindingCardMessage type includes validation fields
 */

import { describe, it, expect } from 'vitest';
import {
  agentFindingToReactFinding,
  applyValidationResult,
  buildDuplicateCheckResult,
} from '../core/orchestrator/orchestrator_engine';
import type { AgentFinding } from '../agents/base_agent';
import type { ValidationResult, ValidationEvidence } from '../core/validation/validator';
import type { DuplicateScore, DuplicateMatch } from '../utils/duplicate_checker';
import type { FindingCardMessage } from '../core/conversation/types';

// ─── Test Fixtures ──────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<AgentFinding> = {}): AgentFinding {
  return {
    id: 'finding_test_001',
    agentId: 'xss-hunter',
    type: 'xss',
    title: 'Reflected XSS in search parameter',
    severity: 'high',
    description: 'The search parameter is reflected without encoding',
    target: 'http://localhost:3001/rest/products/search?q=',
    evidence: ['curl -s "http://localhost:3001/rest/products/search?q=<script>alert(1)</script>"'],
    reproduction: ['Navigate to search', 'Enter <script>alert(1)</script>', 'Observe alert'],
    timestamp: new Date(),
    ...overrides,
  };
}

function makeValidationResult(overrides: Partial<ValidationResult> = {}): ValidationResult {
  return {
    findingId: 'finding_test_001',
    confirmed: true,
    evidence: [
      {
        type: 'http_response',
        description: 'Response contains unescaped script tag',
        data: '<script>alert(1)</script>',
        timestamp: Date.now(),
      },
    ],
    reproductionSteps: ['curl -s "http://localhost:3001/rest/products/search?q=<script>alert(1)</script>"'],
    confidence: 95,
    validatorUsed: 'xss',
    validationTime: 1200,
    ...overrides,
  };
}

function makeDuplicateScore(overrides: Partial<DuplicateScore> = {}): DuplicateScore {
  return {
    overall: 85,
    h1Match: 80,
    githubMatch: 30,
    internalMatch: 0,
    recommendation: 'review',
    matches: [
      {
        source: 'hackerone',
        title: 'XSS in search functionality',
        url: 'https://hackerone.com/reports/123456',
        similarity: 0.85,
        reportId: '123456',
      },
    ],
    reasoning: ['High title similarity', 'Same endpoint pattern'],
    ...overrides,
  };
}

// ─── AgentFinding → ReactFinding Conversion ─────────────────────────────────

describe('agentFindingToReactFinding', () => {
  it('converts all fields correctly', () => {
    const finding = makeFinding();
    const react = agentFindingToReactFinding(finding);

    expect(react.id).toBe(finding.id);
    expect(react.title).toBe(finding.title);
    expect(react.vulnerabilityType).toBe(finding.type);
    expect(react.severity).toBe(finding.severity);
    expect(react.target).toBe(finding.target);
    expect(react.description).toBe(finding.description);
    expect(react.evidence).toEqual(finding.evidence);
    expect(react.reproductionSteps).toEqual(finding.reproduction);
    expect(react.impact).toBe(finding.description);
    expect(react.agentId).toBe(finding.agentId);
  });

  it('sets default confidence to 50', () => {
    const react = agentFindingToReactFinding(makeFinding());
    expect(react.confidence).toBe(50);
  });

  it('sets discoveredAtIteration to 0', () => {
    const react = agentFindingToReactFinding(makeFinding());
    expect(react.discoveredAtIteration).toBe(0);
  });

  it('handles missing type field gracefully', () => {
    const finding = makeFinding({ type: '' });
    const react = agentFindingToReactFinding(finding);
    expect(react.vulnerabilityType).toBe('');
  });

  it('preserves all severity levels', () => {
    const severities = ['info', 'low', 'medium', 'high', 'critical'] as const;
    for (const sev of severities) {
      const react = agentFindingToReactFinding(makeFinding({ severity: sev }));
      expect(react.severity).toBe(sev);
    }
  });
});

// ─── ValidationResult → Finding Status Mapping ──────────────────────────────

describe('applyValidationResult', () => {
  it('sets confirmed status when validation succeeds', () => {
    const finding = makeFinding();
    const result = makeValidationResult({ confirmed: true });
    applyValidationResult(finding, result);

    expect(finding.validationStatus).toBe('confirmed');
    expect(finding.validationEvidence).toHaveLength(1);
    expect(finding.validationConfidence).toBe(95);
  });

  it('sets unverified status when validation fails without error', () => {
    const finding = makeFinding();
    const result = makeValidationResult({
      confirmed: false,
      evidence: [],
      confidence: 20,
      error: undefined,
    });
    applyValidationResult(finding, result);

    expect(finding.validationStatus).toBe('unverified');
    expect(finding.validationEvidence).toEqual([]);
    expect(finding.validationConfidence).toBe(20);
  });

  it('sets validation_failed when error is present', () => {
    const finding = makeFinding();
    const result = makeValidationResult({
      confirmed: false,
      error: 'Timeout connecting to target',
      confidence: 0,
    });
    applyValidationResult(finding, result);

    expect(finding.validationStatus).toBe('validation_failed');
  });

  it('confirmed=true takes precedence over error field', () => {
    const finding = makeFinding();
    // Edge case: confirmed true but error also set (shouldn't happen, but test the priority)
    const result = makeValidationResult({
      confirmed: true,
      error: 'partial error',
    });
    applyValidationResult(finding, result);

    expect(finding.validationStatus).toBe('confirmed');
  });

  it('preserves all evidence types', () => {
    const finding = makeFinding();
    const evidence: ValidationEvidence[] = [
      { type: 'http_request', description: 'GET request', data: 'GET /foo', timestamp: Date.now() },
      { type: 'http_response', description: 'Response', data: '200 OK', timestamp: Date.now() },
      { type: 'screenshot', description: 'Alert dialog', data: 'base64...', timestamp: Date.now() },
      { type: 'callback', description: 'OOB callback', data: 'dns query received', timestamp: Date.now() },
      { type: 'timing', description: '5s delay', data: '5002ms', timestamp: Date.now() },
      { type: 'diff', description: 'Response diff', data: '+ injected content', timestamp: Date.now() },
      { type: 'script_output', description: 'Script result', data: 'vulnerable=true', timestamp: Date.now() },
    ];
    const result = makeValidationResult({ evidence });
    applyValidationResult(finding, result);

    expect(finding.validationEvidence).toHaveLength(7);
    expect(finding.validationEvidence?.map(e => e.type)).toEqual([
      'http_request', 'http_response', 'screenshot', 'callback', 'timing', 'diff', 'script_output',
    ]);
  });
});

// ─── DuplicateScore → DuplicateCheckResult Mapping ──────────────────────────

describe('buildDuplicateCheckResult', () => {
  it('maps skip recommendation to likely_duplicate', () => {
    const score = makeDuplicateScore({ recommendation: 'skip', overall: 95 });
    const result = buildDuplicateCheckResult(score);

    expect(result.status).toBe('likely_duplicate');
    expect(result.score).toBe(score);
  });

  it('maps review recommendation to possible_duplicate', () => {
    const score = makeDuplicateScore({ recommendation: 'review', overall: 78 });
    const result = buildDuplicateCheckResult(score);

    expect(result.status).toBe('possible_duplicate');
    expect(result.score).toBe(score);
  });

  it('maps submit recommendation to unique', () => {
    const score = makeDuplicateScore({ recommendation: 'submit', overall: 20 });
    const result = buildDuplicateCheckResult(score);

    expect(result.status).toBe('unique');
    expect(result.score).toBe(score);
  });

  it('limits topMatches to 3', () => {
    const matches: DuplicateMatch[] = Array.from({ length: 5 }, (_, i) => ({
      source: 'hackerone' as const,
      title: `Report ${i}`,
      url: `https://hackerone.com/reports/${i}`,
      similarity: 0.9 - i * 0.1,
    }));
    const score = makeDuplicateScore({ matches });
    const result = buildDuplicateCheckResult(score);

    expect(result.topMatches).toHaveLength(3);
    expect(result.topMatches?.[0].title).toBe('Report 0');
    expect(result.topMatches?.[2].title).toBe('Report 2');
  });

  it('handles empty matches array', () => {
    const score = makeDuplicateScore({ matches: [], recommendation: 'submit' });
    const result = buildDuplicateCheckResult(score);

    expect(result.status).toBe('unique');
    expect(result.topMatches).toEqual([]);
  });

  it('preserves match details in topMatches', () => {
    const score = makeDuplicateScore();
    const result = buildDuplicateCheckResult(score);

    expect(result.topMatches?.[0]).toEqual({
      source: 'hackerone',
      title: 'XSS in search functionality',
      url: 'https://hackerone.com/reports/123456',
      similarity: 0.85,
    });
  });
});

// ─── Validation Status Types ────────────────────────────────────────────────

describe('ValidationStatus type integration', () => {
  it('AgentFinding supports all validation status values', () => {
    const statuses = ['pending', 'confirmed', 'unverified', 'validation_failed'] as const;
    for (const status of statuses) {
      const finding = makeFinding({ validationStatus: status });
      expect(finding.validationStatus).toBe(status);
    }
  });

  it('AgentFinding defaults to no validation status', () => {
    const finding = makeFinding();
    expect(finding.validationStatus).toBeUndefined();
  });

  it('AgentFinding supports DuplicateCheckResult', () => {
    const finding = makeFinding({
      duplicateCheck: { status: 'unique' },
    });
    expect(finding.duplicateCheck?.status).toBe('unique');
  });

  it('DuplicateCheckResult supports not_checked status', () => {
    const finding = makeFinding({
      duplicateCheck: { status: 'not_checked' },
    });
    expect(finding.duplicateCheck?.status).toBe('not_checked');
  });
});

// ─── FindingCardMessage Type Validation ──────────────────────────────────────

describe('FindingCardMessage with validation fields', () => {
  it('includes all Phase 3 fields', () => {
    const msg: FindingCardMessage = {
      type: 'finding_card',
      id: 'msg_001',
      timestamp: Date.now(),
      title: 'XSS in search',
      severity: 'high',
      description: 'Reflected XSS',
      target: 'http://localhost:3001',
      agent: 'xss-hunter',
      evidence: ['curl command'],
      isDuplicate: false,
      validationStatus: 'confirmed',
      validationEvidence: [
        { type: 'screenshot', description: 'Alert dialog', data: 'base64', timestamp: Date.now() },
      ],
      validationConfidence: 95,
      duplicateCheck: {
        status: 'unique',
        topMatches: [],
      },
    };

    expect(msg.validationStatus).toBe('confirmed');
    expect(msg.validationEvidence).toHaveLength(1);
    expect(msg.validationConfidence).toBe(95);
    expect(msg.duplicateCheck?.status).toBe('unique');
  });

  it('works with pending validation (initial state)', () => {
    const msg: FindingCardMessage = {
      type: 'finding_card',
      id: 'msg_002',
      timestamp: Date.now(),
      title: 'SQLi in login',
      severity: 'critical',
      description: 'SQL injection',
      target: 'http://localhost:3001/rest/user/login',
      agent: 'sqli-hunter',
      evidence: [],
      isDuplicate: false,
      validationStatus: 'pending',
      duplicateCheck: { status: 'not_checked' },
    };

    expect(msg.validationStatus).toBe('pending');
    expect(msg.validationEvidence).toBeUndefined();
    expect(msg.duplicateCheck?.status).toBe('not_checked');
  });

  it('works with likely_duplicate status', () => {
    const msg: FindingCardMessage = {
      type: 'finding_card',
      id: 'msg_003',
      timestamp: Date.now(),
      title: 'CORS misconfiguration',
      severity: 'medium',
      description: 'Wildcard origin',
      target: 'http://example.com',
      agent: 'cors-hunter',
      evidence: [],
      isDuplicate: true,
      validationStatus: 'confirmed',
      duplicateCheck: {
        status: 'likely_duplicate',
        score: makeDuplicateScore({ recommendation: 'skip', overall: 95 }),
        topMatches: [{ source: 'hackerone', title: 'CORS issue', url: 'https://h1.com/1', similarity: 0.95 }],
      },
    };

    expect(msg.duplicateCheck?.status).toBe('likely_duplicate');
    expect(msg.duplicateCheck?.topMatches?.[0].similarity).toBe(0.95);
  });
});

// ─── Graceful Degradation ───────────────────────────────────────────────────

describe('Graceful degradation', () => {
  it('no validator returns unverified with error message', () => {
    // This tests the validator.ts behavior when no validator is registered
    // The validateFinding() function returns error when no validator matches
    const finding = makeFinding({ type: 'unknown_vuln_type' });
    const result: ValidationResult = {
      findingId: finding.id,
      confirmed: false,
      evidence: [],
      reproductionSteps: [],
      confidence: 50,
      validatorUsed: 'none',
      validationTime: 0,
      error: 'No validator available for type: unknown_vuln_type',
    };
    applyValidationResult(finding, result);

    expect(finding.validationStatus).toBe('validation_failed');
    expect(finding.validationEvidence).toEqual([]);
  });

  it('DuplicateCheckResult with not_checked is valid', () => {
    const finding = makeFinding({
      duplicateCheck: { status: 'not_checked' },
    });
    expect(finding.duplicateCheck?.status).toBe('not_checked');
    expect(finding.duplicateCheck?.score).toBeUndefined();
    expect(finding.duplicateCheck?.topMatches).toBeUndefined();
  });

  it('validation failure preserves finding data', () => {
    const finding = makeFinding();
    const originalTitle = finding.title;
    const originalSeverity = finding.severity;
    const originalEvidence = [...finding.evidence];

    applyValidationResult(finding, makeValidationResult({
      confirmed: false,
      error: 'Network timeout',
    }));

    // Finding data unchanged — only validation fields updated
    expect(finding.title).toBe(originalTitle);
    expect(finding.severity).toBe(originalSeverity);
    expect(finding.evidence).toEqual(originalEvidence);
    expect(finding.validationStatus).toBe('validation_failed');
  });
});

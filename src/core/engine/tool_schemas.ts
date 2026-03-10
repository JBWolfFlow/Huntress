/**
 * Security Tool Schema Registry
 *
 * Defines structured tool definitions that LLMs can invoke via native tool use.
 * These replace the fragile "parse JSON from text" pattern with guaranteed-valid
 * structured tool calls from the model.
 *
 * Each schema maps to a concrete action the agent can take:
 * - execute_command: Run a security tool against a target
 * - report_finding: Report a discovered vulnerability
 * - request_specialist: Ask the orchestrator to delegate to another agent
 * - write_script: Generate and execute a custom exploit/test script
 * - analyze_response: Ask the model to analyze HTTP response data
 * - stop_hunting: Signal that the agent has completed its task
 */

import type { ToolDefinition } from '../providers/types';

// ─── Tool Schemas ────────────────────────────────────────────────────────────

export const EXECUTE_COMMAND_SCHEMA: ToolDefinition = {
  name: 'execute_command',
  description: `Execute a security tool command against a target. The command will be validated against the scope, checked by safety policies, and routed through the approval gate before execution. Use this for running recon tools (subfinder, httpx, nuclei, etc.), scanners, and test payloads. Always provide clear reasoning for why this command is needed.`,
  input_schema: {
    type: 'object',
    properties: {
      command: {
        type: 'string',
        description: 'The full command to execute (e.g., "subfinder -d example.com -json -silent")',
      },
      target: {
        type: 'string',
        description: 'The primary target domain/URL this command is directed at',
      },
      reasoning: {
        type: 'string',
        description: 'Why this command is being run and what you expect to learn from it',
      },
      category: {
        type: 'string',
        description: 'The category of this command',
        enum: ['recon', 'scanning', 'active_testing', 'validation', 'exploitation', 'utility'],
      },
      timeout_seconds: {
        type: 'number',
        description: 'Maximum execution time in seconds (default: 120)',
      },
    },
    required: ['command', 'target', 'reasoning', 'category'],
  },
};

export const REPORT_FINDING_SCHEMA: ToolDefinition = {
  name: 'report_finding',
  description: `Report a discovered vulnerability or security finding. Provide comprehensive details including evidence, reproduction steps, and severity assessment. This triggers the validation pipeline and duplicate detection. Only report findings you have strong evidence for — false positives waste time and damage credibility.`,
  input_schema: {
    type: 'object',
    properties: {
      title: {
        type: 'string',
        description: 'Concise vulnerability title (e.g., "Reflected XSS in search parameter")',
      },
      vulnerability_type: {
        type: 'string',
        description: 'The class of vulnerability',
        enum: [
          'xss_reflected', 'xss_stored', 'xss_dom',
          'sqli_error', 'sqli_blind_time', 'sqli_blind_boolean',
          'ssrf', 'ssrf_blind',
          'idor', 'bola',
          'ssti',
          'open_redirect',
          'cors_misconfiguration',
          'csrf',
          'host_header_injection',
          'oauth_redirect_uri', 'oauth_state', 'oauth_pkce',
          'jwt_vulnerability',
          'prototype_pollution',
          'subdomain_takeover',
          'information_disclosure',
          'rate_limit_bypass',
          'graphql_introspection', 'graphql_batching',
          'mass_assignment',
          'path_traversal',
          'rce',
          'xxe', 'xxe_blind',
          'command_injection', 'command_injection_blind',
          'lfi',
          'other',
        ],
      },
      severity: {
        type: 'string',
        description: 'CVSS-aligned severity rating',
        enum: ['info', 'low', 'medium', 'high', 'critical'],
      },
      target: {
        type: 'string',
        description: 'The specific URL/endpoint affected',
      },
      description: {
        type: 'string',
        description: 'Detailed vulnerability description including root cause analysis',
      },
      evidence: {
        type: 'array',
        items: { type: 'string' },
        description: 'Array of evidence items (HTTP requests/responses, screenshots, tool output)',
      },
      reproduction_steps: {
        type: 'array',
        items: { type: 'string' },
        description: 'Ordered steps to reproduce the vulnerability',
      },
      impact: {
        type: 'string',
        description: 'What an attacker could achieve by exploiting this vulnerability',
      },
      confidence: {
        type: 'number',
        description: 'Confidence level 0-100 that this is a real, exploitable vulnerability',
      },
    },
    required: ['title', 'vulnerability_type', 'severity', 'target', 'description', 'evidence', 'reproduction_steps', 'impact', 'confidence'],
  },
};

export const REQUEST_SPECIALIST_SCHEMA: ToolDefinition = {
  name: 'request_specialist',
  description: `Request the orchestrator to dispatch a specialized agent for a specific vulnerability class. Use this when you discover an attack surface that requires deep domain expertise you don't have. For example, if recon discovers a GraphQL endpoint, request the GraphQL specialist agent.`,
  input_schema: {
    type: 'object',
    properties: {
      agent_type: {
        type: 'string',
        description: 'The specialist agent to request',
        enum: [
          'recon', 'xss_hunter', 'sqli_hunter', 'ssrf_hunter',
          'idor_hunter', 'oauth_hunter', 'graphql_hunter',
          'ssti_hunter', 'cors_hunter', 'host_header_hunter',
          'prototype_pollution_hunter', 'subdomain_takeover_hunter',
          'api_hunter',
          'xxe_hunter', 'command_injection_hunter', 'path_traversal_hunter',
        ],
      },
      target: {
        type: 'string',
        description: 'The specific target/endpoint for the specialist',
      },
      context: {
        type: 'string',
        description: 'What you discovered that makes this specialist relevant. Include any useful findings.',
      },
      priority: {
        type: 'string',
        description: 'Priority level for this specialist request',
        enum: ['low', 'medium', 'high', 'critical'],
      },
    },
    required: ['agent_type', 'target', 'context', 'priority'],
  },
};

export const WRITE_SCRIPT_SCHEMA: ToolDefinition = {
  name: 'write_script',
  description: `Generate and execute a custom script for testing. Use this when existing tools are insufficient and you need a custom payload delivery mechanism, a multi-step attack script, or batch testing. Scripts are sandboxed and validated before execution.`,
  input_schema: {
    type: 'object',
    properties: {
      language: {
        type: 'string',
        description: 'Script language',
        enum: ['python', 'bash', 'javascript'],
      },
      code: {
        type: 'string',
        description: 'The script source code',
      },
      purpose: {
        type: 'string',
        description: 'What this script does and why it is needed',
      },
      target: {
        type: 'string',
        description: 'Target this script will interact with',
      },
    },
    required: ['language', 'code', 'purpose', 'target'],
  },
};

export const ANALYZE_RESPONSE_SCHEMA: ToolDefinition = {
  name: 'analyze_response',
  description: `Analyze HTTP response data, tool output, or other collected data to extract insights. Use this when you have raw data that needs interpretation — e.g., parsing error messages for database type, analyzing headers for security misconfigurations, or identifying patterns across multiple responses.`,
  input_schema: {
    type: 'object',
    properties: {
      data: {
        type: 'string',
        description: 'The response data or tool output to analyze',
      },
      analysis_type: {
        type: 'string',
        description: 'What kind of analysis to perform',
        enum: [
          'error_message_classification',
          'header_security_analysis',
          'technology_fingerprint',
          'vulnerability_indicator',
          'response_diff_comparison',
          'pattern_extraction',
          'general',
        ],
      },
      looking_for: {
        type: 'string',
        description: 'Specific things to look for in the data',
      },
    },
    required: ['data', 'analysis_type', 'looking_for'],
  },
};

export const STOP_HUNTING_SCHEMA: ToolDefinition = {
  name: 'stop_hunting',
  description: `Signal that the current hunting task is complete. Use this when: (1) you've exhausted all relevant attack vectors, (2) the target appears hardened against your attack class, (3) you've found and reported all discoverable vulnerabilities, or (4) you've hit an unrecoverable blocker.`,
  input_schema: {
    type: 'object',
    properties: {
      reason: {
        type: 'string',
        description: 'Why hunting is being stopped',
        enum: ['task_complete', 'no_vulnerabilities', 'target_hardened', 'blocker', 'iteration_limit'],
      },
      summary: {
        type: 'string',
        description: 'Summary of what was tested, what was found, and what was not tested',
      },
      recommendations: {
        type: 'array',
        items: { type: 'string' },
        description: 'Suggestions for follow-up testing or areas that need manual review',
      },
    },
    required: ['reason', 'summary'],
  },
};

// ─── Schema Collections ──────────────────────────────────────────────────────

/** All tool schemas available to hunting agents */
export const AGENT_TOOL_SCHEMAS: ToolDefinition[] = [
  EXECUTE_COMMAND_SCHEMA,
  REPORT_FINDING_SCHEMA,
  REQUEST_SPECIALIST_SCHEMA,
  WRITE_SCRIPT_SCHEMA,
  ANALYZE_RESPONSE_SCHEMA,
  STOP_HUNTING_SCHEMA,
];

/** Minimal schemas for recon-only agents */
export const RECON_TOOL_SCHEMAS: ToolDefinition[] = [
  EXECUTE_COMMAND_SCHEMA,
  REQUEST_SPECIALIST_SCHEMA,
  ANALYZE_RESPONSE_SCHEMA,
  STOP_HUNTING_SCHEMA,
];

/** Schemas for the orchestrator/coordinator */
export const ORCHESTRATOR_TOOL_SCHEMAS: ToolDefinition[] = [
  {
    name: 'dispatch_agent',
    description: 'Dispatch a specialized agent to handle a specific task',
    input_schema: {
      type: 'object',
      properties: {
        agent_type: {
          type: 'string',
          description: 'Which agent to dispatch',
        },
        task_description: {
          type: 'string',
          description: 'Detailed task description for the agent',
        },
        target: {
          type: 'string',
          description: 'Target for the agent',
        },
        priority: {
          type: 'number',
          description: 'Priority 1-10 (10 = highest)',
        },
        iteration_budget: {
          type: 'number',
          description: 'Maximum iterations for this agent (default: 40)',
        },
      },
      required: ['agent_type', 'task_description', 'target', 'priority'],
    },
  },
  {
    name: 'reprioritize_tasks',
    description: 'Re-evaluate and reprioritize the task queue based on new findings',
    input_schema: {
      type: 'object',
      properties: {
        reasoning: {
          type: 'string',
          description: 'Why tasks should be reprioritized',
        },
        findings_summary: {
          type: 'string',
          description: 'Summary of recent findings that affect priority',
        },
      },
      required: ['reasoning'],
    },
  },
  {
    name: 'generate_report',
    description: 'Generate a PoC report for a confirmed vulnerability',
    input_schema: {
      type: 'object',
      properties: {
        finding_id: {
          type: 'string',
          description: 'The finding ID to generate a report for',
        },
      },
      required: ['finding_id'],
    },
  },
  STOP_HUNTING_SCHEMA,
];

/** Get tool schemas filtered by agent type */
export function getToolSchemasForAgent(agentType: string): ToolDefinition[] {
  switch (agentType) {
    case 'recon':
      return RECON_TOOL_SCHEMAS;
    case 'orchestrator':
      return ORCHESTRATOR_TOOL_SCHEMAS;
    default:
      return AGENT_TOOL_SCHEMAS;
  }
}

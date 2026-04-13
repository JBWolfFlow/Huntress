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
          'race_condition', 'toctou', 'double_spend',
          'http_smuggling', 'cache_poisoning', 'cache_deception',
          'jwt_alg_confusion', 'jwt_none', 'jwt_kid_injection',
          'nosql_injection', 'deserialization', 'saml_attack',
          'mfa_bypass', 'websocket', 'crlf_injection',
          'prompt_injection', 'business_logic',
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
          'race_condition_hunter', 'http_smuggling_hunter',
          'cache_hunter', 'jwt_hunter', 'business_logic_hunter',
          'nosql_hunter', 'deserialization_hunter', 'saml_hunter',
          'mfa_bypass_hunter', 'websocket_hunter', 'crlf_hunter',
          'prompt_injection_hunter',
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

export const HTTP_REQUEST_SCHEMA: ToolDefinition = {
  name: 'http_request',
  description: `Make an HTTP request to an in-scope target. Returns the full response including status code, headers, body, and timing. Use this instead of curl for faster, more reliable HTTP requests.`,
  input_schema: {
    type: 'object',
    properties: {
      url: {
        type: 'string',
        description: 'Target URL — must be in-scope',
      },
      method: {
        type: 'string',
        enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
        description: 'HTTP method',
      },
      headers: {
        type: 'object',
        description: 'Optional request headers as key-value pairs',
      },
      body: {
        type: 'string',
        description: 'Optional request body (for POST/PUT/PATCH)',
      },
      follow_redirects: {
        type: 'boolean',
        description: 'Follow redirects (default: true, max 10)',
      },
      timeout_ms: {
        type: 'number',
        description: 'Request timeout in milliseconds (default: 30000)',
      },
      session_label: {
        type: 'string',
        description:
          'Optional. Label of the auth session to use for this request. Omit to use the default session. Use to compare responses across identities for IDOR/BOLA testing — e.g., "victim" vs "attacker".',
      },
    },
    required: ['url', 'method'],
  },
};

export const FUZZ_PARAMETER_SCHEMA: ToolDefinition = {
  name: 'fuzz_parameter',
  description: `Systematically test a parameter with vulnerability-specific payloads. Returns confirmed hits with evidence. Much faster than manual testing — sends 50+ requests without additional LLM calls.`,
  input_schema: {
    type: 'object',
    properties: {
      url: {
        type: 'string',
        description: 'Target endpoint URL (must be in-scope)',
      },
      method: {
        type: 'string',
        enum: ['GET', 'POST', 'PUT', 'PATCH'],
        description: 'HTTP method',
      },
      parameter_name: {
        type: 'string',
        description: 'Name of parameter to fuzz',
      },
      parameter_location: {
        type: 'string',
        enum: ['query', 'body', 'header', 'cookie', 'path'],
        description: 'Where the parameter appears in the request',
      },
      vuln_type: {
        type: 'string',
        enum: ['xss', 'sqli', 'ssrf', 'path_traversal', 'command_injection', 'ssti', 'xxe', 'crlf'],
        description: 'Type of vulnerability to test for',
      },
      content_type: {
        type: 'string',
        enum: ['form', 'json', 'xml', 'multipart'],
        description: 'Request body content type (default: form)',
      },
      max_payloads: {
        type: 'number',
        description: 'Maximum number of payloads to test (default: 50)',
      },
    },
    required: ['url', 'method', 'parameter_name', 'vuln_type'],
  },
};

export const BROWSER_NAVIGATE_SCHEMA: ToolDefinition = {
  name: 'browser_navigate',
  description: `Navigate a headless browser to an in-scope URL and return the rendered page content, title, final URL (after redirects), detected dialogs, console logs, and network requests. Use this for testing client-side vulnerabilities (DOM-XSS, prototype pollution), interacting with SPAs, and observing JavaScript execution. The browser executes JavaScript and waits for the page to settle before capturing results.`,
  input_schema: {
    type: 'object',
    properties: {
      url: {
        type: 'string',
        description: 'Target URL to navigate to — must be in-scope',
      },
      wait_ms: {
        type: 'number',
        description: 'Additional milliseconds to wait after page load for deferred JS (default: 2000)',
      },
    },
    required: ['url'],
  },
};

export const BROWSER_EVALUATE_SCHEMA: ToolDefinition = {
  name: 'browser_evaluate',
  description: `Execute JavaScript in the current browser page context and return the result. Use this for DOM-XSS sink/source analysis, reading DOM properties, checking for prototype pollution artifacts (e.g., Object.prototype.polluted), or extracting data from client-side storage. The browser must have navigated to a page first via browser_navigate.`,
  input_schema: {
    type: 'object',
    properties: {
      expression: {
        type: 'string',
        description: 'JavaScript expression to evaluate in the page context. Must return a JSON-serializable value.',
      },
    },
    required: ['expression'],
  },
};

export const BROWSER_CLICK_SCHEMA: ToolDefinition = {
  name: 'browser_click',
  description: `Click an element in the current browser page by CSS selector. Use this for interacting with SPAs — clicking buttons, following client-side routes, submitting forms, triggering event handlers. Returns the page content after the click and any dialogs/console output triggered. The browser must have navigated to a page first via browser_navigate.`,
  input_schema: {
    type: 'object',
    properties: {
      selector: {
        type: 'string',
        description: 'CSS selector for the element to click (e.g., "button.submit", "#login-form input[type=submit]")',
      },
      wait_ms: {
        type: 'number',
        description: 'Milliseconds to wait after clicking for navigation/JS execution (default: 2000)',
      },
    },
    required: ['selector'],
  },
};

export const BROWSER_GET_CONTENT_SCHEMA: ToolDefinition = {
  name: 'browser_get_content',
  description: `Get the current page HTML content, URL, title, and cookies from the headless browser. Use this to inspect the DOM after a sequence of browser_navigate and browser_click actions. Returns truncated HTML (max 50KB) plus metadata. The browser must have navigated to a page first via browser_navigate.`,
  input_schema: {
    type: 'object',
    properties: {
      include_cookies: {
        type: 'boolean',
        description: 'Whether to include cookies in the response (default: false)',
      },
    },
    required: [],
  },
};

export const RACE_TEST_SCHEMA: ToolDefinition = {
  name: 'race_test',
  description: `Send N identical HTTP requests simultaneously to test for race conditions. Uses Promise.all to fire all requests at once, then returns all responses for differential analysis. Use this to detect TOCTOU bugs, double-spend, duplicate coupon application, and other time-of-check/time-of-use vulnerabilities.`,
  input_schema: {
    type: 'object',
    properties: {
      url: {
        type: 'string',
        description: 'Target URL — must be in-scope',
      },
      method: {
        type: 'string',
        enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
        description: 'HTTP method',
      },
      headers: {
        type: 'object',
        description: 'Optional request headers as key-value pairs',
      },
      body: {
        type: 'string',
        description: 'Optional request body (for POST/PUT/PATCH)',
      },
      concurrency: {
        type: 'number',
        description: 'Number of simultaneous requests to send (2-50, default: 10)',
      },
    },
    required: ['url', 'method', 'concurrency'],
  },
};

// ─── Schema Collections ──────────────────────────────────────────────────────

/** Browser tool schemas — only provided to agents with browserEnabled */
export const BROWSER_TOOL_SCHEMAS: ToolDefinition[] = [
  BROWSER_NAVIGATE_SCHEMA,
  BROWSER_EVALUATE_SCHEMA,
  BROWSER_CLICK_SCHEMA,
  BROWSER_GET_CONTENT_SCHEMA,
];

/** All tool schemas available to hunting agents */
export const AGENT_TOOL_SCHEMAS: ToolDefinition[] = [
  EXECUTE_COMMAND_SCHEMA,
  REPORT_FINDING_SCHEMA,
  REQUEST_SPECIALIST_SCHEMA,
  WRITE_SCRIPT_SCHEMA,
  ANALYZE_RESPONSE_SCHEMA,
  STOP_HUNTING_SCHEMA,
  HTTP_REQUEST_SCHEMA,
  FUZZ_PARAMETER_SCHEMA,
  RACE_TEST_SCHEMA,
];

/** Minimal schemas for recon-only agents */
export const RECON_TOOL_SCHEMAS: ToolDefinition[] = [
  EXECUTE_COMMAND_SCHEMA,
  REQUEST_SPECIALIST_SCHEMA,
  ANALYZE_RESPONSE_SCHEMA,
  STOP_HUNTING_SCHEMA,
];

/** Schemas for the orchestrator/coordinator */
export const ADJUST_BUDGET_SCHEMA: ToolDefinition = {
  name: 'adjust_budget',
  description: 'Adjust the hunt budget. Can only increase the budget — never decrease below current spend. Use when the user requests a budget change mid-hunt.',
  input_schema: {
    type: 'object',
    properties: {
      new_budget_usd: {
        type: 'number',
        description: 'New budget in USD. Must be greater than current spend and at most $500.',
      },
      reason: {
        type: 'string',
        description: 'Why the budget is being adjusted',
      },
    },
    required: ['new_budget_usd'],
  },
};

export const ORCHESTRATOR_TOOL_SCHEMAS: ToolDefinition[] = [
  {
    name: 'dispatch_agent',
    description: 'Dispatch a specialized agent to handle a specific task. Agents run asynchronously and report results back automatically when they complete — do NOT poll or check status, just dispatch and wait.',
    input_schema: {
      type: 'object',
      properties: {
        agent_type: {
          type: 'string',
          enum: [
            'recon',
            'sqli-hunter',
            'xss-hunter',
            'idor-hunter',
            'ssrf-hunter',
            'jwt-hunter',
            'business-logic-hunter',
            'path-traversal-hunter',
            'open-redirect-hunter',
            'prototype-pollution-hunter',
            'xxe-hunter',
            'ssti-hunter',
            'command-injection-hunter',
            'cors-hunter',
            'crlf-hunter',
            'host-header-hunter',
            'graphql-hunter',
            'http-smuggling-hunter',
            'websocket-hunter',
            'nosql-hunter',
            'race-condition-hunter',
            'mfa-bypass-hunter',
            'deserialization-hunter',
            'saml-hunter',
            'cache-hunter',
            'subdomain-takeover-hunter',
            'prompt-injection-hunter',
            'oauth_hunter',
          ],
          description: 'The agent ID to dispatch. Must be one of the listed values.',
        },
        task_description: {
          type: 'string',
          description: 'Detailed task description for the agent including specific endpoints, payloads, and techniques to test',
        },
        target: {
          type: 'string',
          description: 'Target URL for the agent (must be in scope)',
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
  ADJUST_BUDGET_SCHEMA,
  STOP_HUNTING_SCHEMA,
];

/** Agent types that originally had browser tools (Phase A: now all hunting agents do) */
export const BROWSER_ENABLED_AGENTS: ReadonlySet<string> = new Set([
  'xss-hunter',
  'ssti-hunter',
  'prototype-pollution-hunter',
  'business-logic-hunter',
]);

/** Get tool schemas filtered by agent type.
 *  Phase A: All hunting agents get browser tools by default.
 *  Browser is lazy-initialized — agents that don't call browser tools pay zero cost.
 *  Pass browserEnabled=false to explicitly opt out. */
export function getToolSchemasForAgent(agentType: string, browserEnabled?: boolean): ToolDefinition[] {
  switch (agentType) {
    case 'recon':
      return RECON_TOOL_SCHEMAS;
    case 'orchestrator':
      return ORCHESTRATOR_TOOL_SCHEMAS;
    default:
      if (browserEnabled === false) {
        return AGENT_TOOL_SCHEMAS;
      }
      return [...AGENT_TOOL_SCHEMAS, ...BROWSER_TOOL_SCHEMAS];
  }
}

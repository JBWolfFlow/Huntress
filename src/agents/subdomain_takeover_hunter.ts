/**
 * Subdomain Takeover Hunter Agent
 *
 * Specialized agent for detecting subdomain takeover vulnerabilities.
 * Uses the ReAct loop engine to systematically discover dangling CNAME
 * records, fingerprint matching against cloud providers (AWS S3, Azure,
 * GitHub Pages, Heroku, Shopify, etc.), verification of takeover
 * feasibility, and proof of concept construction across in-scope targets.
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
import type { SessionManager } from '../core/auth/session_manager';

const SUBDOMAIN_TAKEOVER_SYSTEM_PROMPT = `You are an expert subdomain takeover security researcher with deep knowledge of DNS resolution, cloud provider hosting configurations, and the mechanics of dangling DNS records. You specialize in finding subdomain takeover vulnerabilities where a DNS record points to an external service that has been deprovisioned, allowing an attacker to claim the subdomain by registering the abandoned resource.

Your attack playbook — follow these steps methodically:

1. **Subdomain enumeration** — Collect subdomains of the target domain:
   - Use passive sources first: check if the task description or recon output already provides subdomains
   - If needed, use httpx to probe known subdomains for status
   - Focus on subdomains that return errors, timeouts, or cloud provider default pages

2. **DNS record analysis** — For each subdomain, resolve DNS records to identify potential takeovers:
   - Resolve CNAME records: dig CNAME subdomain.target.com
   - Resolve A records: dig A subdomain.target.com
   - Check for dangling CNAMEs — a CNAME that points to a service endpoint that no longer exists
   - Look for NXDOMAIN responses on the CNAME target while the CNAME record itself still exists
   - Check NS delegations: dig NS subdomain.target.com — dangling NS records enable full DNS takeover

3. **Fingerprint matching** — Match CNAME targets and HTTP responses against known vulnerable services:

   **AWS S3:**
   - CNAME pattern: *.s3.amazonaws.com, *.s3-website-REGION.amazonaws.com, *.s3.REGION.amazonaws.com
   - Fingerprint: HTTP 404 with "NoSuchBucket" in response body
   - Takeover: Create an S3 bucket with the matching name

   **AWS CloudFront:**
   - CNAME pattern: *.cloudfront.net
   - Fingerprint: "Bad Request" or "ERROR: The request could not be satisfied"
   - Takeover: Create a CloudFront distribution and add the subdomain as a CNAME

   **AWS Elastic Beanstalk:**
   - CNAME pattern: *.elasticbeanstalk.com
   - Fingerprint: NXDOMAIN on the CNAME target
   - Takeover: Create an Elastic Beanstalk environment with the matching name

   **Azure:**
   - CNAME pattern: *.azurewebsites.net, *.cloudapp.azure.com, *.azure-api.net, *.azurefd.net, *.blob.core.windows.net, *.trafficmanager.net
   - Fingerprint: Default Azure "App Service - Your app service is up and running" page or 404
   - Takeover: Create an Azure resource with the matching name

   **GitHub Pages:**
   - CNAME pattern: *.github.io
   - Fingerprint: "There isn't a GitHub Pages site here." (404)
   - Takeover: Create a GitHub repo with GitHub Pages configured for the subdomain

   **Heroku:**
   - CNAME pattern: *.herokuapp.com, *.herokudns.com, *.herokussl.com
   - Fingerprint: "No such app" or Heroku default error page
   - Takeover: Create a Heroku app with the matching name and add the custom domain

   **Shopify:**
   - CNAME pattern: *.myshopify.com
   - Fingerprint: "Sorry, this shop is currently unavailable"
   - Takeover: Create a Shopify store and configure the custom domain

   **Fastly:**
   - CNAME pattern: *.fastly.net, *.global.fastly.net
   - Fingerprint: "Fastly error: unknown domain"
   - Takeover: Add the domain to a Fastly service configuration

   **Pantheon:**
   - CNAME pattern: *.pantheonsite.io
   - Fingerprint: "404 error unknown site" or Pantheon 404 page
   - Takeover: Add the domain to a Pantheon site

   **Surge.sh:**
   - CNAME pattern: *.surge.sh
   - Fingerprint: "project not found" page
   - Takeover: Deploy to surge with the matching subdomain

   **Zendesk:**
   - CNAME pattern: *.zendesk.com
   - Fingerprint: "Help Center Closed" or Zendesk default page
   - Takeover: Configure custom domain in Zendesk

   **Tumblr:**
   - CNAME pattern: *.tumblr.com, domains.tumblr.com
   - Fingerprint: "There's nothing here." or "Whatever you were looking for doesn't currently exist"
   - Takeover: Register a Tumblr blog and configure the custom domain

   **Unbounce:**
   - CNAME pattern: *.unbouncepages.com
   - Fingerprint: "The requested URL was not found on this server"
   - Takeover: Add custom domain in Unbounce

   **WordPress.com:**
   - CNAME pattern: *.wordpress.com
   - Fingerprint: "Do you want to register *.wordpress.com?"
   - Takeover: Register the matching WordPress.com site

4. **Run subjack** — Use subjack for automated subdomain takeover detection:
   - subjack -w SUBDOMAIN_LIST_FILE -t 100 -timeout 30 -ssl -c /path/to/fingerprints.json -v
   - Parse output for confirmed or potential takeovers
   - Cross-reference subjack results with manual DNS analysis

5. **Verification of takeover feasibility** — Before reporting, verify the takeover is actually possible:
   - Confirm the CNAME record still exists and points to the service: dig CNAME subdomain.target.com
   - Confirm the CNAME target returns an error or default page: curl -v https://subdomain.target.com
   - Confirm the service name/resource is actually available for registration (not just temporarily down)
   - For S3: check if the bucket name is available with a HEAD request to BUCKET.s3.amazonaws.com
   - For GitHub Pages: check if the username/org exists and the repo can be created
   - For Heroku: check if the app name is available
   - Distinguish between "service is down temporarily" and "service has been deprovisioned"

6. **NS delegation takeover** — Check for the more severe NS-based takeover:
   - If a subdomain has NS records pointing to a DNS service (Route53, Cloudflare, DNSimple, etc.) that is no longer configured:
   - dig NS sub.target.com → returns ns-xxx.awsdns-xx.com
   - If the hosted zone has been deleted but the NS delegation remains, an attacker can create a new hosted zone with the same NS servers
   - This allows full DNS control of the subdomain (any record type, MX for email interception, TXT for domain verification)
   - NS takeover is typically CRITICAL severity

7. **Proof of concept construction** — For each confirmed vulnerability:
   - Document the exact CNAME chain: subdomain → CNAME target → NXDOMAIN/error
   - Show the HTTP response from the subdomain demonstrating the error/fingerprint
   - Describe the exact steps to claim the resource (but do NOT actually claim it in production)
   - If the bug bounty program allows it, and you have created the resource on a test service, serve a benign page (e.g., "Subdomain Takeover PoC by [researcher]") as proof
   - Calculate impact: subdomain takeover enables cookie theft (if parent domain sets cookies), phishing, email interception (via MX records), and bypassing CORS/CSP that trust the subdomain

8. **Validation** — For each candidate finding:
   - Verify the CNAME or NS record is still active with a fresh DNS lookup
   - Verify the target service endpoint is genuinely unclaimed (not just experiencing downtime)
   - Test from multiple DNS resolvers to rule out DNS caching artifacts
   - Document the full DNS resolution chain
   - Classify severity:
     - NS delegation takeover: CRITICAL (full DNS control)
     - Subdomain takeover on authenticated domain (cookies scoped to parent): HIGH-CRITICAL
     - Subdomain takeover on domain trusted by CORS/CSP: HIGH
     - Subdomain takeover on isolated subdomain: MEDIUM
     - Potential takeover but service name is not available: LOW (report as informational)

IMPORTANT RULES:
- Only test targets that are explicitly in scope
- Do NOT actually register or claim the external resource unless the bounty program explicitly allows it
- Use appropriate delays between requests to avoid overwhelming DNS servers
- Verify findings from multiple DNS resolvers to rule out caching issues
- Document every finding with the full DNS chain and HTTP response fingerprint
- Always distinguish between "confirmed takeover" (resource is claimable) and "potential takeover" (resource appears abandoned but claimability is unverified)`;

export class SubdomainTakeoverHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'subdomain-takeover-hunter',
    name: 'Subdomain Takeover Hunter',
    description:
      'Specialized agent for detecting subdomain takeover vulnerabilities via dangling CNAME detection, cloud provider fingerprint matching, and NS delegation takeover analysis.',
    vulnerabilityClasses: ['subdomain-takeover', 'dns-misconfiguration'],
    assetTypes: ['domain', 'web-application'],
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
        systemPrompt: SUBDOMAIN_TAKEOVER_SYSTEM_PROMPT,
        goal: `Test for subdomain takeover vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
        tools: AGENT_TOOL_SCHEMAS,
        agentType: this.metadata.id,
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
        sessionManager: task.parameters.sessionManager as SessionManager | undefined,
        authSessionId: (task.parameters.authSessionIds as string[] | undefined)?.[0],
        sharedFindings: task.sharedFindings,
        wafContext: task.wafContext,
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
        httpExchanges: result.httpExchanges,
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
  metadata: new SubdomainTakeoverHunterAgent().metadata,
  factory: () => new SubdomainTakeoverHunterAgent(),
});

export default SubdomainTakeoverHunterAgent;

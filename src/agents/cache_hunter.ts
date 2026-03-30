/**
 * Cache Poisoning & Deception Hunter Agent
 *
 * Specializes in web cache poisoning (PortSwigger Top 10 2024 #1) and web cache
 * deception (#2). These vulnerability classes are the #1 and #2 most impactful
 * according to PortSwigger's annual research, with consistently high payouts.
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

const CACHE_HUNTER_SYSTEM_PROMPT = `You are an elite web cache poisoning and web cache deception researcher. These are the #1 and #2 most impactful vulnerability classes per PortSwigger's 2024 Top 10. Your mission is to systematically discover both cache poisoning and cache deception vulnerabilities.

## Part A: Web Cache Poisoning

Cache poisoning occurs when an attacker can make a cache store a malicious response and serve it to other users.

### Step 1: Identify Cacheable Endpoints

First, determine which endpoints are cached:
- Send a request and check response headers: \`X-Cache\`, \`CF-Cache-Status\`, \`Age\`, \`Cache-Control\`, \`Vary\`, \`Via\`, \`X-Cache-Hits\`
- \`X-Cache: HIT\` or \`CF-Cache-Status: HIT\` or \`Age: >0\` = cached
- \`Cache-Control: public, max-age=X\` = explicitly cached
- Test: send identical request twice, if second has \`Age: >0\` or \`X-Cache: HIT\`, it's cached

### Step 2: Discover Unkeyed Headers

Cache keys typically include: URL path, query string, Host header. Headers that are NOT part of the cache key but still influence the response are the attack vector.

Test these unkeyed headers one at a time (ALWAYS use a unique cache buster \`?cb=RANDOM\` to avoid poisoning real cache):
- \`X-Forwarded-Host: evil.com\` — often reflected in links, redirects, canonical URLs
- \`X-Forwarded-Scheme: http\` — can force HTTP redirect
- \`X-Forwarded-Proto: http\` — same as above
- \`X-Original-URL: /admin\` — URL override (IIS, some PHP frameworks)
- \`X-Rewrite-URL: /admin\` — URL rewrite override
- \`X-Host: evil.com\` — alternative host header
- \`X-Forwarded-Server: evil.com\` — server name reflection
- \`Forwarded: for=127.0.0.1;host=evil.com\` — RFC 7239 forwarded
- \`X-HTTP-Method-Override: POST\` — method override
- \`X-Forwarded-Port: 1337\` — port reflection in URLs

For EACH header: send request with the header + cache buster, check if the header value appears in the response body (in links, meta tags, scripts, redirects).

### Step 3: Confirm Cache Poisoning

If an unkeyed header value is reflected in the response:
1. Send the poisoned request with cache buster (e.g., \`?cb=poison123\`)
2. Wait 1 second
3. Send a CLEAN request (no poison header) to the SAME URL with SAME cache buster
4. If the clean response contains the poisoned value → cache is poisoned!

### Step 4: Demonstrate Impact

Once poisoning is confirmed, demonstrate what an attacker could achieve:
- XSS via poisoned \`<script src="evil.com/xss.js">\` in cached response
- Open redirect via poisoned Location header
- Denial of service via poisoned error response

### Step 5: Path Delimiter Discrepancy (Advanced)

Test path delimiters that the origin and cache interpret differently:
- \`/account;anything.css\` — origin sees \`/account\`, cache sees \`.css\` (static, cacheable)
- \`/account%00.css\` — null byte: origin ignores, cache caches as CSS
- \`/account%0a.css\` — newline
- \`/account%23.css\` — hash
- \`/account%3f.css\` — question mark encoding

### Step 6: Fat GET Detection

Send a GET request WITH a request body. Some frameworks process the body (like POST), but CDNs cache it as a GET:
- \`GET /api/data?cb=RANDOM HTTP/1.1\\r\\nContent-Type: application/json\\r\\n\\r\\n{"admin":true}\`
- If the response changes based on the GET body AND is cached → fat GET cache poisoning

### Step 7: Normalization Mismatch

Test dot-segment normalization:
- \`/aaa/..%2fapi/data\` — cache sees literal path, origin resolves to \`/api/data\`
- \`/aaa/../api/data\` — both should resolve, but if cache doesn't normalize, it's a separate cache entry
- Double encoding: \`/%2e%2e/admin\` — test if origin decodes but cache doesn't

## Part B: Web Cache Deception

Cache deception tricks the cache into storing an authenticated response and serving it to an attacker.

### Step 1: Find Authenticated Pages

Look for pages that show user-specific data:
- Profile pages (\`/profile\`, \`/account\`, \`/settings\`, \`/dashboard\`)
- API responses with user data (\`/api/user\`, \`/api/me\`)
- Pages with PII, session tokens, CSRF tokens, account details

### Step 2: Append Static Extension

Append a static file extension to a dynamic authenticated URL:
- \`/account/profile.css\` — cache thinks it's a static CSS file
- \`/account/profile.js\` — static JS
- \`/account/profile.png\` — static image
- \`/account/profile.woff2\` — static font
- \`/api/user.css\` — API endpoint with CSS extension

### Step 3: Path Confusion

Use path delimiters to trick the cache:
- \`/account/profile;.css\` — semicolon delimiter
- \`/account/profile%2f.css\` — encoded slash
- \`/account/profile/.css\` — directory traversal into static

### Step 4: Confirm Deception

1. Log in as victim (or use your own session)
2. Visit the crafted URL (\`/account/profile.css\`) — cache stores your authenticated response
3. Log out (or use a different session / no cookies)
4. Visit the same URL — if you see the victim's data, cache deception confirmed!

## CDN Fingerprinting

Identify the CDN to select targeted payloads:
- \`CF-RAY\` → Cloudflare
- \`X-Amz-Cf-Id\` → CloudFront
- \`X-Cache: HIT from AkamaiNetStorage\` → Akamai
- \`X-Served-By: cache-*\` → Fastly (Varnish)
- \`X-MSEdge-Ref\` → Azure Front Door
- \`X-Varnish\` → Generic Varnish

## Severity Classification

- Cache poisoning with XSS: CRITICAL (stored XSS affecting all users)
- Cache deception exposing PII: HIGH
- Cache poisoning with open redirect: MEDIUM-HIGH
- Cache poisoning with DoS: MEDIUM
- Cache behavior anomaly without confirmed impact: LOW

## Safety Notes

- ALWAYS use unique cache busters (\`?cb=huntress_RANDOM\`) to avoid poisoning real cache entries
- Check \`Cache-Control\` max-age — short TTLs mean your test cache entries expire quickly
- If you accidentally poison a real cache entry, note the TTL and inform the user
- Never attempt to cache user credentials or session tokens — demonstrate with non-sensitive data`;

export class CacheHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'cache-hunter',
    name: 'Cache Hunter',
    description:
      'Detects web cache poisoning (unkeyed headers, fat GET, path delimiter discrepancies) ' +
      'and web cache deception (static extension tricks, path confusion). PortSwigger Top 10 2024 #1 and #2.',
    vulnerabilityClasses: ['cache_poisoning', 'cache_deception', 'web_cache'],
    assetTypes: ['web-application', 'api'],
  };

  private provider?: ModelProvider;
  private model?: string;
  private findings: AgentFinding[] = [];
  private status: AgentStatus;
  private autoApproveSafe = false;
  private onApprovalRequest?: (req: {
    command: string; target: string; reasoning: string; category: string; toolName: string; safetyWarnings: string[];
  }) => Promise<boolean>;
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

  setCallbacks(callbacks: {
    onApprovalRequest?: (req: {
      command: string; target: string; reasoning: string; category: string; toolName: string; safetyWarnings: string[];
    }) => Promise<boolean>;
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
        systemPrompt: CACHE_HUNTER_SYSTEM_PROMPT,
        goal:
          `Systematically test for web cache poisoning and web cache deception on target: ${task.target}\n\n` +
          `Scope: ${task.scope.join(', ')}\n\n${task.description}\n\n` +
          `Start by fingerprinting the CDN and identifying cacheable endpoints, then test unkeyed headers.`,
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
    try { new URL(target.startsWith('http') ? target : `https://${target}`); return true; } catch { return false; }
  }

  reportFindings(): AgentFinding[] { return [...this.findings]; }
  async cleanup(): Promise<void> { this.findings = []; this.updateStatus('idle'); }
  getStatus(): AgentStatus { return { ...this.status }; }

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

registerAgent({
  metadata: new CacheHunterAgent().metadata,
  factory: () => new CacheHunterAgent(),
});

export default CacheHunterAgent;

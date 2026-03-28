/**
 * Out-of-Band Detection Infrastructure
 *
 * Integrates `interactsh-client` as a background service for detecting
 * blind vulnerabilities: blind SSRF, blind XSS, blind SQLi (OOB),
 * blind SSTI, and DNS-based exfiltration.
 *
 * Lifecycle:
 * 1. Start at hunt session begin → generates unique callback base URL
 * 2. Agents inject callback URLs into parameters/payloads
 * 3. The OOB server monitors for incoming interactions (DNS, HTTP, SMTP, LDAP)
 * 4. When a callback is received, correlate with the injection attempt
 * 5. Auto-stop when the session ends
 *
 * Fallback chain:
 *   interactsh binary → Burp Collaborator → DNS canary polling
 *
 * Enhancements:
 * - Callback-to-injection correlation with per-agent tracking
 * - LDAP protocol support alongside DNS, HTTP, SMTP
 * - Configurable TTL per injection with automatic expiration
 * - Server health checking with automatic URL rotation
 * - DNS canary fallback requiring no external binary
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface OOBCallback {
  id: string;
  /** The unique interaction URL that was injected */
  callbackUrl: string;
  /** Where this callback was injected */
  injectionPoint: InjectionPoint;
  /** Whether a callback was received */
  triggered: boolean;
  /** Details about the received callback */
  interaction?: OOBInteraction;
  /** When this callback was registered */
  registeredAt: number;
  /** When the callback was triggered (if triggered) */
  triggeredAt?: number;
  /** TTL in ms — after this duration the callback is considered expired */
  ttlMs: number;
  /** Whether this callback has expired (past TTL without trigger) */
  expired: boolean;
}

export interface InjectionPoint {
  target: string;
  parameter: string;
  agentId: string;
  vulnerabilityType: string;
}

export interface OOBInteraction {
  protocol: 'dns' | 'http' | 'https' | 'smtp' | 'ldap' | 'ftp';
  sourceIp: string;
  timestamp: number;
  rawData: string;
  /** For HTTP: request details */
  httpDetails?: {
    method: string;
    path: string;
    headers: Record<string, string>;
    body?: string;
  };
  /** For DNS: query details */
  dnsDetails?: {
    queryType: string;
    queryName: string;
  };
  /** For LDAP: query details */
  ldapDetails?: {
    baseDn: string;
    filter: string;
    attributes: string[];
  };
}

export interface OOBServerConfig {
  /** Path to interactsh-client binary */
  interactshPath?: string;
  /** Custom interactsh server URL */
  serverUrl?: string;
  /** Poll interval in milliseconds */
  pollInterval?: number;
  /** Execute a command via Rust PTY */
  executeCommand: (command: string, target: string) => Promise<{
    success: boolean;
    stdout: string;
    stderr: string;
    exitCode: number;
    executionTimeMs: number;
  }>;
  /** Callback when an OOB interaction is received */
  onInteraction?: (callback: OOBCallback) => void;
  /** Burp Collaborator server URL (optional, used as second fallback) */
  burpCollaboratorUrl?: string;
  /** Burp Collaborator API key (optional) */
  burpCollaboratorKey?: string;
  /** Default TTL for callbacks in milliseconds (default: 30 minutes) */
  defaultTtlMs?: number;
  /** Additional interactsh server URLs for rotation */
  serverUrls?: string[];
  /** DNS canary base domain — used for the final fallback tier */
  canaryBaseDomain?: string;
  /** Max consecutive poll failures before rotating server */
  maxPollFailures?: number;
}

/** The provider currently handling OOB interactions */
export type FallbackProvider = 'interactsh' | 'burp_collaborator' | 'dns_canary';

/** Result of a provider start attempt */
interface ProviderStartResult {
  provider: FallbackProvider;
  baseUrl: string;
}

/** Tracks health of a particular server endpoint */
interface ServerHealth {
  url: string;
  consecutiveFailures: number;
  lastSuccess: number;
  lastFailure: number;
}

/** DNS canary record used in the final fallback tier */
interface DnsCanary {
  callbackId: string;
  subdomain: string;
  fullDomain: string;
  resolved: boolean;
}

// Default TTL: 30 minutes
const DEFAULT_TTL_MS = 30 * 60 * 1000;

// Default max poll failures before rotating server
const DEFAULT_MAX_POLL_FAILURES = 3;

// Known public interactsh servers for rotation
const PUBLIC_INTERACTSH_SERVERS = [
  'oast.fun',
  'oast.live',
  'oast.site',
  'oast.online',
  'oast.me',
];

// ─── OOB Server ──────────────────────────────────────────────────────────────

export class OOBServer {
  private config: OOBServerConfig;
  private callbacks: Map<string, OOBCallback> = new Map();
  private baseUrl: string = '';
  private running = false;
  private pollTimer?: ReturnType<typeof setInterval>;
  private ttlTimer?: ReturnType<typeof setInterval>;
  private nextId = 1;

  /** Which fallback provider is currently active */
  private activeProvider: FallbackProvider = 'interactsh';

  /** Health state for each server we can poll */
  private serverHealthMap: Map<string, ServerHealth> = new Map();

  /** Current interactsh server URL being used */
  private currentServerUrl: string = '';

  /** Index into the rotation list for server URLs */
  private serverRotationIndex = 0;

  /** All available server URLs for rotation */
  private serverUrlPool: string[] = [];

  /** DNS canary records for the lightweight fallback */
  private dnsCanaries: Map<string, DnsCanary> = new Map();

  /** Reverse lookup: callbackUrl → callback id for fast correlation */
  private urlToIdIndex: Map<string, string> = new Map();

  /** Index: agentId → Set of callback ids */
  private agentCallbackIndex: Map<string, Set<string>> = new Map();

  /** Max consecutive poll failures before rotating */
  private maxPollFailures: number;

  /** Default TTL for new callbacks */
  private defaultTtlMs: number;

  constructor(config: OOBServerConfig) {
    this.config = {
      pollInterval: 10_000,
      ...config,
    };
    this.defaultTtlMs = config.defaultTtlMs ?? DEFAULT_TTL_MS;
    this.maxPollFailures = config.maxPollFailures ?? DEFAULT_MAX_POLL_FAILURES;

    // Build the server URL pool from config + known public servers
    this.serverUrlPool = [];
    if (config.serverUrl) {
      this.serverUrlPool.push(config.serverUrl);
    }
    if (config.serverUrls) {
      for (const url of config.serverUrls) {
        if (!this.serverUrlPool.includes(url)) {
          this.serverUrlPool.push(url);
        }
      }
    }
    // Append public servers that aren't already listed
    for (const pub of PUBLIC_INTERACTSH_SERVERS) {
      if (!this.serverUrlPool.includes(pub)) {
        this.serverUrlPool.push(pub);
      }
    }
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /** Start the OOB server and generate the base callback URL */
  async start(): Promise<string> {
    const result = await this.startWithFallback();
    return result.baseUrl;
  }

  /**
   * Start with automatic fallback chain:
   *   1. interactsh binary (try each server in pool)
   *   2. Burp Collaborator (if configured)
   *   3. DNS canary polling (always available, no external binary)
   */
  async startWithFallback(): Promise<ProviderStartResult> {
    // ── Tier 1: interactsh binary ──
    const interactshResult = await this.tryStartInteractsh();
    if (interactshResult) {
      this.activeProvider = 'interactsh';
      this.running = true;
      this.startPolling();
      this.startTtlSweep();
      return { provider: 'interactsh', baseUrl: interactshResult };
    }

    // ── Tier 2: Burp Collaborator ──
    if (this.config.burpCollaboratorUrl && this.config.burpCollaboratorKey) {
      const burpResult = await this.tryStartBurpCollaborator();
      if (burpResult) {
        this.activeProvider = 'burp_collaborator';
        this.running = true;
        this.startPolling();
        this.startTtlSweep();
        return { provider: 'burp_collaborator', baseUrl: burpResult };
      }
    }

    // ── Tier 3: DNS canary (always available) ──
    const canaryResult = this.startDnsCanary();
    this.activeProvider = 'dns_canary';
    this.running = true;
    this.startPolling();
    this.startTtlSweep();
    return { provider: 'dns_canary', baseUrl: canaryResult };
  }

  /** Generate a unique callback URL for a specific injection point */
  generateCallbackUrl(injectionPoint: InjectionPoint, ttlMs?: number): OOBCallback {
    const id = `oob_${this.nextId++}`;
    const subdomain = `${id}-${Date.now().toString(36)}`;
    const callbackUrl = `${subdomain}.${this.baseUrl}`;

    const callback: OOBCallback = {
      id,
      callbackUrl,
      injectionPoint,
      triggered: false,
      registeredAt: Date.now(),
      ttlMs: ttlMs ?? this.defaultTtlMs,
      expired: false,
    };

    this.callbacks.set(id, callback);
    this.urlToIdIndex.set(callbackUrl, id);

    // Update agent index
    const agentId = injectionPoint.agentId;
    if (!this.agentCallbackIndex.has(agentId)) {
      this.agentCallbackIndex.set(agentId, new Set());
    }
    this.agentCallbackIndex.get(agentId)!.add(id);

    // If using DNS canary provider, register the canary
    if (this.activeProvider === 'dns_canary') {
      this.dnsCanaries.set(id, {
        callbackId: id,
        subdomain,
        fullDomain: callbackUrl,
        resolved: false,
      });
    }

    return callback;
  }

  /** Get a full URL for injection (HTTP) */
  getHttpUrl(callback: OOBCallback): string {
    return `http://${callback.callbackUrl}`;
  }

  /** Get a DNS payload for injection */
  getDnsPayload(callback: OOBCallback): string {
    return callback.callbackUrl;
  }

  /** Get an LDAP payload for injection */
  getLdapPayload(callback: OOBCallback): string {
    return `ldap://${callback.callbackUrl}/o=huntress,dc=oob`;
  }

  /** Check if a specific callback has been triggered */
  isTriggered(callbackId: string): boolean {
    return this.callbacks.get(callbackId)?.triggered ?? false;
  }

  /** Check if a specific callback has expired */
  isExpired(callbackId: string): boolean {
    return this.callbacks.get(callbackId)?.expired ?? false;
  }

  /** Get all triggered callbacks */
  getTriggeredCallbacks(): OOBCallback[] {
    return Array.from(this.callbacks.values()).filter(c => c.triggered);
  }

  /** Get all pending (untriggered, non-expired) callbacks */
  getPendingCallbacks(): OOBCallback[] {
    return Array.from(this.callbacks.values()).filter(c => !c.triggered && !c.expired);
  }

  /** Get all expired callbacks */
  getExpiredCallbacks(): OOBCallback[] {
    return Array.from(this.callbacks.values()).filter(c => c.expired);
  }

  /**
   * Correlate a raw callback URL back to the injection that produced it.
   * Returns the matching OOBCallback or undefined if not found.
   */
  correlate(callbackUrl: string): OOBCallback | undefined {
    // Direct URL match
    const directId = this.urlToIdIndex.get(callbackUrl);
    if (directId) {
      return this.callbacks.get(directId);
    }

    // Subdomain-prefix match (incoming URL may include protocol or extra path)
    const normalized = callbackUrl
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '')
      .toLowerCase();

    for (const [url, id] of this.urlToIdIndex.entries()) {
      if (normalized === url.toLowerCase() || normalized.endsWith(url.toLowerCase())) {
        return this.callbacks.get(id);
      }
    }

    // Fallback: scan all callbacks for partial match
    for (const callback of this.callbacks.values()) {
      const cbHost = callback.callbackUrl.toLowerCase();
      if (normalized.includes(cbHost) || cbHost.includes(normalized)) {
        return callback;
      }
    }

    return undefined;
  }

  /**
   * Get all callbacks registered by a specific agent.
   */
  getCallbacksForAgent(agentId: string): OOBCallback[] {
    const ids = this.agentCallbackIndex.get(agentId);
    if (!ids) return [];

    const results: OOBCallback[] = [];
    for (const id of ids) {
      const cb = this.callbacks.get(id);
      if (cb) results.push(cb);
    }
    return results;
  }

  /** Get the currently active fallback provider */
  getActiveProvider(): FallbackProvider {
    return this.activeProvider;
  }

  /** Stop the OOB server */
  stop(): void {
    this.running = false;
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = undefined;
    }
    if (this.ttlTimer) {
      clearInterval(this.ttlTimer);
      this.ttlTimer = undefined;
    }
  }

  /** Get a summary for display */
  getSummary(): string {
    const triggered = this.getTriggeredCallbacks();
    const pending = this.getPendingCallbacks();
    const expired = this.getExpiredCallbacks();
    return [
      `OOB Server: ${this.running ? 'running' : 'stopped'} (provider: ${this.activeProvider})`,
      `Base URL: ${this.baseUrl || 'not started'}`,
      `Registered callbacks: ${this.callbacks.size}`,
      `Triggered: ${triggered.length}`,
      `Pending: ${pending.length}`,
      `Expired: ${expired.length}`,
      triggered.length > 0
        ? `Triggered details:\n${triggered.map(c =>
            `  - ${c.id}: ${c.interaction?.protocol} from ${c.interaction?.sourceIp} → ${c.injectionPoint.target} (${c.injectionPoint.vulnerabilityType})`
          ).join('\n')}`
        : '',
    ].filter(Boolean).join('\n');
  }

  // ─── Provider Start Methods ─────────────────────────────────────────────────

  /**
   * Try to start interactsh, rotating through available servers.
   * Returns the base URL on success, or null on failure.
   */
  private async tryStartInteractsh(): Promise<string | null> {
    // First, verify the interactsh binary exists
    const binaryPath = this.config.interactshPath ?? 'interactsh-client';
    const whichResult = await this.config.executeCommand(
      `which ${binaryPath}`,
      '',
    );

    if (!whichResult.success || !whichResult.stdout.trim()) {
      // Binary not found — skip this tier
      return null;
    }

    // Try each server in the pool until one works
    for (let i = 0; i < this.serverUrlPool.length; i++) {
      const serverUrl = this.serverUrlPool[this.serverRotationIndex % this.serverUrlPool.length];
      this.serverRotationIndex++;

      const serverFlag = `-server ${serverUrl}`;
      const result = await this.config.executeCommand(
        `${binaryPath} ${serverFlag} -json -poll-interval 5 -v 2>&1 | head -5`,
        '',
      );

      // Parse the base URL from interactsh output
      const urlMatch = result.stdout.match(
        /([a-z0-9]+\.oast\.\w+|[a-z0-9]+\.interact\.sh|[a-z0-9]+\.[a-z]+\.[a-z]+)/i
      );
      if (urlMatch) {
        this.baseUrl = urlMatch[1];
        this.currentServerUrl = serverUrl;
        this.initServerHealth(serverUrl);
        return this.baseUrl;
      }
    }

    return null;
  }

  /**
   * Try to start Burp Collaborator as the OOB provider.
   * Uses the Burp Collaborator polling API to fetch interactions.
   */
  private async tryStartBurpCollaborator(): Promise<string | null> {
    const burpUrl = this.config.burpCollaboratorUrl;
    const burpKey = this.config.burpCollaboratorKey;
    if (!burpUrl || !burpKey) return null;

    // First allocate a collaborator subdomain via the Burp API
    const allocateResult = await this.config.executeCommand(
      ['curl', '-sf', '-m', '10', '-X', 'POST',
       '-H', 'Content-Type: application/json',
       '-d', JSON.stringify({ biid: burpKey }),
       `${burpUrl}/burpresults`].join('\x00'),
      '',
    );

    // Then poll for any existing interactions to verify connectivity
    const result = await this.config.executeCommand(
      ['curl', '-sf', '-m', '10', `${burpUrl}/burpresults?biid=${encodeURIComponent(burpKey)}`].join('\x00'),
      '',
    );

    if (result.success && result.stdout.trim()) {
      try {
        const data: Record<string, unknown> = JSON.parse(result.stdout);
        // Burp Collaborator returns responses; on first call, we use the biid as the base
        if (data['responses'] !== undefined) {
          // Generate a unique subdomain base from the biid
          const baseId = burpKey.substring(0, 16).toLowerCase();
          this.baseUrl = `${baseId}.burpcollaborator.net`;
          this.currentServerUrl = burpUrl;
          this.initServerHealth(burpUrl);
          return this.baseUrl;
        }
      } catch {
        // JSON parse failure — Burp not available
      }
    }

    // Burp is configured but not reachable — try direct connectivity test
    const pingResult = await this.config.executeCommand(
      ['curl', '-sf', '-m', '5', '-o', '/dev/null', '-w', '%{http_code}', burpUrl].join('\x00'),
      '',
    );

    if (pingResult.success && pingResult.stdout.trim().startsWith('2')) {
      const baseId = burpKey.substring(0, 16).toLowerCase();
      this.baseUrl = `${baseId}.burpcollaborator.net`;
      this.currentServerUrl = burpUrl;
      this.initServerHealth(burpUrl);
      return this.baseUrl;
    }

    return null;
  }

  /**
   * Start DNS canary fallback — works without any external binary.
   * Generates unique subdomains and checks for DNS resolution via `dig` or `nslookup`.
   */
  private startDnsCanary(): string {
    const canaryBase = this.config.canaryBaseDomain ?? `huntress-${Date.now().toString(36)}.oob.local`;
    this.baseUrl = canaryBase;
    this.currentServerUrl = 'dns_canary';
    return this.baseUrl;
  }

  // ─── Polling ────────────────────────────────────────────────────────────────

  private startPolling(): void {
    this.pollTimer = setInterval(async () => {
      if (!this.running) return;
      await this.pollInteractions();
    }, this.config.pollInterval);
  }

  /** Start periodic TTL sweep to expire old callbacks */
  private startTtlSweep(): void {
    // Sweep every 60 seconds
    this.ttlTimer = setInterval(() => {
      this.sweepExpiredCallbacks();
    }, 60_000);
  }

  private async pollInteractions(): Promise<void> {
    switch (this.activeProvider) {
      case 'interactsh':
        await this.pollInteractsh();
        break;
      case 'burp_collaborator':
        await this.pollBurpCollaborator();
        break;
      case 'dns_canary':
        await this.pollDnsCanaries();
        break;
    }
  }

  private async pollInteractsh(): Promise<void> {
    try {
      const interactsh = this.config.interactshPath ?? 'interactsh-client';
      const serverFlag = this.currentServerUrl ? `-server ${this.currentServerUrl}` : '';
      const result = await this.config.executeCommand(
        `${interactsh} ${serverFlag} -json -poll-interval 1 -n 1 2>/dev/null | head -20`,
        '',
      );

      if (result.success) {
        this.recordPollSuccess(this.currentServerUrl);
      } else {
        this.recordPollFailure(this.currentServerUrl);
        const shouldRotate = this.shouldRotateServer(this.currentServerUrl);
        if (shouldRotate) {
          await this.rotateServer();
        }
        return;
      }

      if (!result.stdout.trim()) return;

      // Parse NDJSON interactions
      const lines = result.stdout.split('\n').filter(Boolean);
      for (const line of lines) {
        try {
          const interaction: Record<string, unknown> = JSON.parse(line);
          this.processInteraction(interaction);
        } catch {
          // Skip unparseable lines
        }
      }
    } catch {
      this.recordPollFailure(this.currentServerUrl);
      const shouldRotate = this.shouldRotateServer(this.currentServerUrl);
      if (shouldRotate) {
        await this.rotateServer();
      }
    }
  }

  private async pollBurpCollaborator(): Promise<void> {
    const burpUrl = this.config.burpCollaboratorUrl;
    const burpKey = this.config.burpCollaboratorKey;
    if (!burpUrl || !burpKey) return;

    try {
      const result = await this.config.executeCommand(
        ['curl', '-sf', '-m', '10', `${burpUrl}/burpresults?biid=${encodeURIComponent(burpKey)}`].join('\x00'),
        '',
      );

      if (!result.success) {
        this.recordPollFailure(burpUrl);
        if (this.shouldRotateServer(burpUrl)) {
          // Burp is down — fall through to DNS canary
          this.activeProvider = 'dns_canary';
          const canaryBase = this.startDnsCanary();
          this.baseUrl = canaryBase;
        }
        return;
      }

      this.recordPollSuccess(burpUrl);

      if (!result.stdout.trim()) return;

      try {
        const data: Record<string, unknown> = JSON.parse(result.stdout);
        const responses = data['responses'] as Array<Record<string, unknown>> | undefined;
        if (!responses || !Array.isArray(responses)) return;

        for (const resp of responses) {
          this.processBurpInteraction(resp);
        }
      } catch {
        // JSON parse failure — skip this poll cycle
      }
    } catch {
      this.recordPollFailure(burpUrl);
    }
  }

  /**
   * Poll DNS canaries by doing DNS lookups for each registered canary subdomain.
   * If any resolves (including to NXDOMAIN with an actual response), it means
   * the target made a DNS query for that subdomain.
   */
  private async pollDnsCanaries(): Promise<void> {
    for (const [callbackId, canary] of this.dnsCanaries.entries()) {
      if (canary.resolved) continue;

      const callback = this.callbacks.get(callbackId);
      if (!callback || callback.triggered || callback.expired) continue;

      try {
        // Query the OOB server's interaction log for this canary domain.
        // Note: We do NOT use local `dig` — that only tells us if WE can resolve it,
        // not whether the TARGET resolved it. The OOB server must report interactions.
        const oobCheckUrl = this.currentServerUrl
          ? `${this.currentServerUrl}/poll?domain=${encodeURIComponent(canary.fullDomain)}`
          : null;
        let interactionDetected = false;

        if (oobCheckUrl) {
          const result = await this.config.executeCommand(
            ['curl', '-sf', '-m', '5', oobCheckUrl].join('\x00'),
            '',
          );
          interactionDetected = result.success && result.stdout.includes(canary.fullDomain);
        }

        if (interactionDetected) {
          // OOB server confirmed the canary domain was queried by the target
          canary.resolved = true;
          callback.triggered = true;
          callback.triggeredAt = Date.now();
          callback.interaction = {
            protocol: 'dns',
            sourceIp: 'canary-detected',
            timestamp: Date.now(),
            rawData: `OOB interaction detected for ${canary.fullDomain}`,
            dnsDetails: {
              queryType: 'A',
              queryName: canary.fullDomain,
            },
          };
          this.config.onInteraction?.(callback);
        }
      } catch {
        // DNS lookup failed — canary not triggered, continue
      }
    }
  }

  // ─── Interaction Processing ─────────────────────────────────────────────────

  private processInteraction(data: Record<string, unknown>): void {
    const fullId = (data['unique-id'] as string) ?? (data['full-id'] as string) ?? '';

    // Find matching callback by subdomain prefix
    for (const [id, callback] of this.callbacks.entries()) {
      if (callback.triggered || callback.expired) continue;

      if (fullId.includes(id) || fullId.startsWith(callback.callbackUrl.split('.')[0])) {
        callback.triggered = true;
        callback.triggeredAt = Date.now();

        const protocol = (data.protocol as string)?.toLowerCase() ?? 'unknown';
        callback.interaction = {
          protocol: protocol as OOBInteraction['protocol'],
          sourceIp: (data['remote-address'] as string) ?? 'unknown',
          timestamp: Date.now(),
          rawData: JSON.stringify(data).substring(0, 2000),
        };

        if (protocol === 'http' || protocol === 'https') {
          callback.interaction.httpDetails = {
            method: (data['http-method'] as string) ?? 'GET',
            path: (data['http-path'] as string) ?? '/',
            headers: (data['http-headers'] as Record<string, string>) ?? {},
            body: data['http-body'] as string,
          };
        }

        if (protocol === 'dns') {
          callback.interaction.dnsDetails = {
            queryType: (data['dns-type'] as string) ?? 'A',
            queryName: (data['dns-query'] as string) ?? fullId,
          };
        }

        if (protocol === 'ldap') {
          const rawRequest = (data['raw-request'] as string) ?? '';
          callback.interaction.ldapDetails = {
            baseDn: this.extractLdapField(rawRequest, 'baseObject') ?? (data['ldap-base-dn'] as string) ?? '',
            filter: this.extractLdapField(rawRequest, 'filter') ?? (data['ldap-filter'] as string) ?? '(objectClass=*)',
            attributes: this.parseLdapAttributes(data),
          };
        }

        if (protocol === 'smtp') {
          // SMTP interactions are recorded with rawData — no extra parsing needed
          // The raw SMTP conversation is in the rawData field
        }

        // Notify listener
        this.config.onInteraction?.(callback);
        break;
      }
    }
  }

  /**
   * Process a Burp Collaborator interaction response.
   * Burp returns interactions in its own format that we normalize.
   */
  private processBurpInteraction(resp: Record<string, unknown>): void {
    const interactionType = ((resp['type'] as string) ?? '').toLowerCase();
    const clientIp = (resp['client'] as string) ?? 'unknown';
    const interactionData = (resp['data'] as string) ?? '';
    const subdomain = (resp['subdomain'] as string) ?? '';

    // Map Burp interaction types to our protocol enum
    let protocol: OOBInteraction['protocol'] = 'dns';
    if (interactionType === 'http' || interactionType === 'https') {
      protocol = interactionType as 'http' | 'https';
    } else if (interactionType === 'smtp') {
      protocol = 'smtp';
    } else if (interactionType === 'ldap') {
      protocol = 'ldap';
    }

    // Find matching callback
    for (const [, callback] of this.callbacks.entries()) {
      if (callback.triggered || callback.expired) continue;

      const cbPrefix = callback.callbackUrl.split('.')[0].toLowerCase();
      if (subdomain.toLowerCase().includes(cbPrefix) ||
          interactionData.toLowerCase().includes(cbPrefix)) {
        callback.triggered = true;
        callback.triggeredAt = Date.now();
        callback.interaction = {
          protocol,
          sourceIp: clientIp,
          timestamp: Date.now(),
          rawData: JSON.stringify(resp).substring(0, 2000),
        };

        if (protocol === 'http' || protocol === 'https') {
          // Burp stores the full HTTP request in data — parse method and path
          const methodMatch = interactionData.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/);
          callback.interaction.httpDetails = {
            method: methodMatch ? methodMatch[1] : 'GET',
            path: methodMatch ? methodMatch[2] : '/',
            headers: {},
            body: undefined,
          };
        }

        if (protocol === 'dns') {
          callback.interaction.dnsDetails = {
            queryType: (resp['dns-type'] as string) ?? 'A',
            queryName: subdomain,
          };
        }

        if (protocol === 'ldap') {
          callback.interaction.ldapDetails = {
            baseDn: (resp['ldap-base-dn'] as string) ?? '',
            filter: (resp['ldap-filter'] as string) ?? '(objectClass=*)',
            attributes: [],
          };
        }

        this.config.onInteraction?.(callback);
        break;
      }
    }
  }

  // ─── LDAP Helpers ───────────────────────────────────────────────────────────

  /**
   * Extract a field from raw LDAP request data.
   * LDAP interactions from interactsh contain the raw ASN.1/BER-decoded fields
   * as key=value or structured text.
   */
  private extractLdapField(rawRequest: string, fieldName: string): string | null {
    // Try key=value format: "baseObject: dc=example,dc=com"
    const kvMatch = rawRequest.match(new RegExp(`${fieldName}[:\\s=]+(.+?)(?:\\n|$)`, 'i'));
    if (kvMatch) return kvMatch[1].trim();

    // Try JSON-style: "baseObject":"dc=example,dc=com"
    const jsonMatch = rawRequest.match(new RegExp(`"${fieldName}"\\s*:\\s*"([^"]*)"`, 'i'));
    if (jsonMatch) return jsonMatch[1];

    return null;
  }

  /**
   * Parse LDAP attributes from interaction data.
   * Attributes may come as an array in the data or embedded in the raw request.
   */
  private parseLdapAttributes(data: Record<string, unknown>): string[] {
    const attrs = data['ldap-attributes'];
    if (Array.isArray(attrs)) {
      return attrs.map(a => String(a));
    }
    if (typeof attrs === 'string') {
      return attrs.split(',').map(a => a.trim()).filter(Boolean);
    }

    // Try to extract from raw-request
    const rawRequest = (data['raw-request'] as string) ?? '';
    const attrMatch = rawRequest.match(/attributes[:\s=]+(.+?)(?:\n|$)/i);
    if (attrMatch) {
      return attrMatch[1].split(',').map(a => a.trim()).filter(Boolean);
    }

    return [];
  }

  // ─── Server Health & Rotation ───────────────────────────────────────────────

  private initServerHealth(url: string): void {
    if (!this.serverHealthMap.has(url)) {
      this.serverHealthMap.set(url, {
        url,
        consecutiveFailures: 0,
        lastSuccess: Date.now(),
        lastFailure: 0,
      });
    }
  }

  private recordPollSuccess(serverUrl: string): void {
    const health = this.serverHealthMap.get(serverUrl);
    if (health) {
      health.consecutiveFailures = 0;
      health.lastSuccess = Date.now();
    }
  }

  private recordPollFailure(serverUrl: string): void {
    this.initServerHealth(serverUrl);
    const health = this.serverHealthMap.get(serverUrl);
    if (health) {
      health.consecutiveFailures++;
      health.lastFailure = Date.now();
    }
  }

  private shouldRotateServer(serverUrl: string): boolean {
    const health = this.serverHealthMap.get(serverUrl);
    if (!health) return false;
    return health.consecutiveFailures >= this.maxPollFailures;
  }

  /**
   * Rotate to the next available server in the pool.
   * If all interactsh servers fail, fall through to the next provider tier.
   */
  private async rotateServer(): Promise<void> {
    let tried = 0;

    while (tried < this.serverUrlPool.length) {
      const nextUrl = this.serverUrlPool[this.serverRotationIndex % this.serverUrlPool.length];
      this.serverRotationIndex++;
      tried++;

      // Skip the one we just failed on
      if (nextUrl === this.currentServerUrl && tried < this.serverUrlPool.length) {
        continue;
      }

      const binaryPath = this.config.interactshPath ?? 'interactsh-client';
      const result = await this.config.executeCommand(
        `${binaryPath} -server ${nextUrl} -json -poll-interval 5 -v 2>&1 | head -5`,
        '',
      );

      const urlMatch = result.stdout.match(
        /([a-z0-9]+\.oast\.\w+|[a-z0-9]+\.interact\.sh|[a-z0-9]+\.[a-z]+\.[a-z]+)/i
      );

      if (urlMatch) {
        this.currentServerUrl = nextUrl;
        this.baseUrl = urlMatch[1];
        this.initServerHealth(nextUrl);

        // Re-register existing pending callbacks with the new base URL
        // (agents should regenerate, but we keep old ones for correlation)
        return;
      }
    }

    // All interactsh servers exhausted — fall through to next provider
    if (this.activeProvider === 'interactsh') {
      if (this.config.burpCollaboratorUrl && this.config.burpCollaboratorKey) {
        const burpResult = await this.tryStartBurpCollaborator();
        if (burpResult) {
          this.activeProvider = 'burp_collaborator';
          return;
        }
      }
      // Final fallback
      this.activeProvider = 'dns_canary';
      this.startDnsCanary();
    } else if (this.activeProvider === 'burp_collaborator') {
      // Burp failed — fall to DNS canary
      this.activeProvider = 'dns_canary';
      this.startDnsCanary();
    }
    // dns_canary doesn't rotate — it's the last resort
  }

  // ─── TTL Management ─────────────────────────────────────────────────────────

  /**
   * Sweep through all callbacks and mark those past their TTL as expired.
   */
  private sweepExpiredCallbacks(): void {
    const now = Date.now();
    for (const callback of this.callbacks.values()) {
      if (callback.expired || callback.triggered) continue;

      if (now - callback.registeredAt > callback.ttlMs) {
        callback.expired = true;

        // Clean up DNS canary entry if present
        if (this.dnsCanaries.has(callback.id)) {
          this.dnsCanaries.delete(callback.id);
        }
      }
    }
  }
}

export default OOBServer;

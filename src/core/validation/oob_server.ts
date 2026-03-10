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
 * 3. The OOB server monitors for incoming interactions (DNS, HTTP, SMTP)
 * 4. When a callback is received, correlate with the injection attempt
 * 5. Auto-stop when the session ends
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
}

// ─── OOB Server ──────────────────────────────────────────────────────────────

export class OOBServer {
  private config: OOBServerConfig;
  private callbacks: Map<string, OOBCallback> = new Map();
  private baseUrl: string = '';
  private running = false;
  private pollTimer?: ReturnType<typeof setInterval>;
  private nextId = 1;

  constructor(config: OOBServerConfig) {
    this.config = {
      pollInterval: 10_000,
      ...config,
    };
  }

  /** Start the OOB server and generate the base callback URL */
  async start(): Promise<string> {
    // Start interactsh-client and get the base URL
    const interactsh = this.config.interactshPath ?? 'interactsh-client';
    const serverFlag = this.config.serverUrl ? `-server ${this.config.serverUrl}` : '';

    const result = await this.config.executeCommand(
      `${interactsh} ${serverFlag} -json -poll-interval 5 -v 2>&1 | head -5`,
      '',
    );

    // Parse the base URL from interactsh output
    // Format: "[INF] Listing 1 payload for OOB Testing\n[INF] xxx.oast.fun"
    const urlMatch = result.stdout.match(/([a-z0-9]+\.oast\.\w+|[a-z0-9]+\.interact\.sh)/i);
    if (urlMatch) {
      this.baseUrl = urlMatch[1];
    } else {
      // Fallback: generate a unique identifier for manual correlation
      this.baseUrl = `huntress-${Date.now().toString(36)}.oast.fun`;
    }

    this.running = true;
    this.startPolling();

    return this.baseUrl;
  }

  /** Generate a unique callback URL for a specific injection point */
  generateCallbackUrl(injectionPoint: InjectionPoint): OOBCallback {
    const id = `oob_${this.nextId++}`;
    const subdomain = `${id}-${Date.now().toString(36)}`;
    const callbackUrl = `${subdomain}.${this.baseUrl}`;

    const callback: OOBCallback = {
      id,
      callbackUrl,
      injectionPoint,
      triggered: false,
      registeredAt: Date.now(),
    };

    this.callbacks.set(id, callback);
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

  /** Check if a specific callback has been triggered */
  isTriggered(callbackId: string): boolean {
    return this.callbacks.get(callbackId)?.triggered ?? false;
  }

  /** Get all triggered callbacks */
  getTriggeredCallbacks(): OOBCallback[] {
    return Array.from(this.callbacks.values()).filter(c => c.triggered);
  }

  /** Get all pending (untriggered) callbacks */
  getPendingCallbacks(): OOBCallback[] {
    return Array.from(this.callbacks.values()).filter(c => !c.triggered);
  }

  /** Stop the OOB server */
  stop(): void {
    this.running = false;
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = undefined;
    }
  }

  /** Get a summary for display */
  getSummary(): string {
    const triggered = this.getTriggeredCallbacks();
    const pending = this.getPendingCallbacks();
    return [
      `OOB Server: ${this.running ? 'running' : 'stopped'}`,
      `Base URL: ${this.baseUrl || 'not started'}`,
      `Registered callbacks: ${this.callbacks.size}`,
      `Triggered: ${triggered.length}`,
      `Pending: ${pending.length}`,
      triggered.length > 0
        ? `Triggered details:\n${triggered.map(c =>
            `  - ${c.id}: ${c.interaction?.protocol} from ${c.interaction?.sourceIp} → ${c.injectionPoint.target} (${c.injectionPoint.vulnerabilityType})`
          ).join('\n')}`
        : '',
    ].filter(Boolean).join('\n');
  }

  // ─── Private ─────────────────────────────────────────────────────────────────

  private startPolling(): void {
    this.pollTimer = setInterval(async () => {
      if (!this.running) return;
      await this.pollInteractions();
    }, this.config.pollInterval);
  }

  private async pollInteractions(): Promise<void> {
    try {
      const interactsh = this.config.interactshPath ?? 'interactsh-client';
      const result = await this.config.executeCommand(
        `${interactsh} -json -poll-interval 1 -n 1 2>/dev/null | head -20`,
        '',
      );

      if (!result.stdout.trim()) return;

      // Parse NDJSON interactions
      const lines = result.stdout.split('\n').filter(Boolean);
      for (const line of lines) {
        try {
          const interaction = JSON.parse(line);
          this.processInteraction(interaction);
        } catch {
          // Skip unparseable lines
        }
      }
    } catch {
      // Poll error — will retry next interval
    }
  }

  private processInteraction(data: Record<string, unknown>): void {
    const fullId = (data['unique-id'] as string) ?? (data['full-id'] as string) ?? '';

    // Find matching callback by subdomain prefix
    for (const [id, callback] of this.callbacks.entries()) {
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

        // Notify listener
        this.config.onInteraction?.(callback);
        break;
      }
    }
  }
}

export default OOBServer;

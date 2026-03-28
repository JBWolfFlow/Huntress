/**
 * Continuous Monitoring Module (Phase 23G)
 *
 * Watches a set of domains for new subdomains, DNS changes, and certificate
 * transparency events. Runs on a configurable polling interval (default 1 hour)
 * using crt.sh as the primary data source (no API key required).
 *
 * Maintains a per-domain known-subdomain set and emits NewAssetAlert callbacks
 * when previously unseen subdomains appear or DNS records change.
 *
 * Thread safety: a `polling` flag prevents overlapping poll cycles when
 * the interval timer fires while a previous cycle is still running.
 */

import type { HttpClient, HttpRequestOptions, HttpResponse } from '../http/request_engine';
import type { CommandResult } from '../tauri_bridge';
import { invoke } from '@tauri-apps/api/core';

// Re-use SubdomainResult from extended_recon for consistency
import type { SubdomainResult } from './extended_recon';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ContinuousMonitorConfig {
  /** Domains to monitor */
  domains: string[];
  /** Polling interval in milliseconds (default: 3600000 = 1 hour) */
  pollIntervalMs?: number;
  /** Enable crt.sh certificate transparency monitoring (default: true) */
  crtshEnabled?: boolean;
  /** Enable DNS resolution for change detection */
  dnsEnabled?: boolean;
  /** Command executor for DNS resolution via dig/nslookup */
  executeCommand?: (program: string, args: string[], cwd?: string) => Promise<CommandResult>;
  /** HTTP client for crt.sh requests */
  httpClient?: HttpClient;
}

export interface MonitoringResults {
  lastCheck: number;
  newSubdomains: SubdomainResult[];
  changedAssets: AssetChange[];
  alerts: NewAssetAlert[];
}

export interface AssetChange {
  domain: string;
  changeType: 'new_subdomain' | 'dns_change' | 'cert_change' | 'scope_change';
  oldValue?: string;
  newValue?: string;
  detectedAt: number;
}

export interface NewAssetAlert {
  domain: string;
  assetType: string;
  details: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  timestamp: number;
}

// ─── crt.sh Response Shape ───────────────────────────────────────────────────

interface CrtShEntry {
  id: number;
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  not_before: string;
  not_after: string;
  serial_number: string;
}

// ─── DNS Record ──────────────────────────────────────────────────────────────

interface DnsRecord {
  ip: string;
  cname?: string;
  resolvedAt: number;
}

// ─── Certificate Info (from crt.sh) ─────────────────────────────────────────

interface CertInfo {
  serialNumber: string;
  issuer: string;
  commonName: string;
  notBefore: string;
  notAfter: string;
}

// ─── HTTP Helper ─────────────────────────────────────────────────────────────

async function httpGet(
  url: string,
  headers: Record<string, string>,
  httpClient?: HttpClient,
): Promise<{ status: number; body: string }> {
  if (httpClient) {
    const opts: HttpRequestOptions = {
      url,
      method: 'GET',
      headers,
      timeoutMs: 30000,
      followRedirects: true,
    };
    const resp: HttpResponse = await httpClient.request(opts);
    return { status: resp.status, body: resp.body };
  }

  // Route through Tauri backend to bypass CORS
  const isTauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
  if (isTauri) {
    const result = await invoke<{
      status: number;
      body: string;
    }>('proxy_http_request', {
      url,
      method: 'GET',
      headers,
      body: null,
      timeoutMs: 30000,
      followRedirects: true,
    });
    return { status: result.status, body: result.body };
  }

  // Last resort: browser fetch
  const resp = await fetch(url, {
    method: 'GET',
    headers,
    signal: AbortSignal.timeout(30000),
  });
  const body = await resp.text();
  return { status: resp.status, body };
}

// ─── Well-Known Wildcard CAs ─────────────────────────────────────────────────

const COMMON_CAS = new Set([
  "let's encrypt",
  'digicert',
  'comodo',
  'godaddy',
  'globalsign',
  'entrust',
  'sectigo',
  'amazon',
  'google trust services',
  'cloudflare',
  'zerossl',
]);

// ─── Continuous Monitor ──────────────────────────────────────────────────────

export class ContinuousMonitor {
  private config: ContinuousMonitorConfig;
  private running: boolean = false;
  private polling: boolean = false;
  private intervalHandle: ReturnType<typeof setInterval> | null = null;

  /** Known subdomains per domain (domain -> set of subdomain strings) */
  private knownSubdomains: Map<string, Set<string>> = new Map();

  /** Known DNS records per subdomain (subdomain -> DnsRecord) */
  private knownDns: Map<string, DnsRecord> = new Map();

  /** Known certificates per domain (domain -> set of serial numbers) */
  private knownCerts: Map<string, Set<string>> = new Map();

  /** Latest monitoring results */
  private lastResults: MonitoringResults = {
    lastCheck: 0,
    newSubdomains: [],
    changedAssets: [],
    alerts: [],
  };

  /** Registered alert callbacks */
  private alertCallbacks: Array<(alert: NewAssetAlert) => void> = [];

  /** Domains currently being monitored */
  private monitoredDomains: Set<string>;

  /** Default poll interval: 1 hour */
  private static readonly DEFAULT_POLL_INTERVAL_MS = 3600000;

  constructor(config: ContinuousMonitorConfig) {
    this.config = {
      ...config,
      pollIntervalMs: config.pollIntervalMs ?? ContinuousMonitor.DEFAULT_POLL_INTERVAL_MS,
      crtshEnabled: config.crtshEnabled !== false,
    };
    this.monitoredDomains = new Set(
      config.domains.map((d) => this.sanitizeDomain(d)).filter((d) => d.length > 0),
    );
  }

  // ─── Lifecycle ─────────────────────────────────────────────────────────────

  /**
   * Start the continuous monitoring loop.
   * Runs an initial poll immediately, then schedules subsequent polls.
   */
  start(): void {
    if (this.running) {
      return;
    }

    this.running = true;

    // Run initial poll (fire-and-forget; errors are caught internally)
    this.pollCycle().catch(() => {
      // Errors are handled inside pollCycle; this catch prevents
      // unhandled promise rejection at the top level.
    });

    // Schedule recurring polls
    this.intervalHandle = setInterval(() => {
      this.pollCycle().catch(() => {
        // Same as above
      });
    }, this.config.pollIntervalMs!);
  }

  /**
   * Stop the continuous monitoring loop.
   */
  stop(): void {
    this.running = false;

    if (this.intervalHandle !== null) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = null;
    }
  }

  /**
   * Whether the monitor is currently running.
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Get the results from the most recent poll cycle.
   */
  getLastResults(): MonitoringResults {
    return { ...this.lastResults };
  }

  // ─── Domain Management ─────────────────────────────────────────────────────

  /**
   * Add a domain to the monitoring list.
   */
  addDomain(domain: string): void {
    const sanitized = this.sanitizeDomain(domain);
    if (sanitized.length > 0) {
      this.monitoredDomains.add(sanitized);
    }
  }

  /**
   * Remove a domain from the monitoring list.
   */
  removeDomain(domain: string): void {
    const sanitized = this.sanitizeDomain(domain);
    this.monitoredDomains.delete(sanitized);

    // Clean up stored state for the removed domain
    this.knownSubdomains.delete(sanitized);
    this.knownCerts.delete(sanitized);

    // Remove DNS records for subdomains of this domain
    for (const [subdomain] of this.knownDns) {
      if (subdomain === sanitized || subdomain.endsWith('.' + sanitized)) {
        this.knownDns.delete(subdomain);
      }
    }
  }

  /**
   * Get the list of currently monitored domains.
   */
  getMonitoredDomains(): string[] {
    return [...this.monitoredDomains].sort();
  }

  // ─── Alert Registration ────────────────────────────────────────────────────

  /**
   * Register a callback to be invoked whenever a new asset is discovered.
   */
  onNewAsset(callback: (asset: NewAssetAlert) => void): void {
    this.alertCallbacks.push(callback);
  }

  // ─── Poll Cycle ────────────────────────────────────────────────────────────

  /**
   * Execute a single poll cycle across all monitored domains.
   * Guarded by the `polling` flag to prevent overlapping cycles.
   */
  private async pollCycle(): Promise<void> {
    if (this.polling) {
      return; // Previous cycle still running
    }

    this.polling = true;

    try {
      const newSubdomains: SubdomainResult[] = [];
      const changedAssets: AssetChange[] = [];
      const alerts: NewAssetAlert[] = [];

      for (const domain of this.monitoredDomains) {
        if (!this.running) {
          break; // Stopped while iterating
        }

        try {
          const domainResults = await this.pollDomain(domain);
          newSubdomains.push(...domainResults.newSubdomains);
          changedAssets.push(...domainResults.changedAssets);
          alerts.push(...domainResults.alerts);
        } catch {
          // Individual domain failures do not abort the whole cycle
        }
      }

      this.lastResults = {
        lastCheck: Date.now(),
        newSubdomains,
        changedAssets,
        alerts,
      };

      // Fire alert callbacks
      for (const alert of alerts) {
        this.emitAlert(alert);
      }
    } finally {
      this.polling = false;
    }
  }

  /**
   * Poll a single domain: check crt.sh, detect new subdomains, resolve DNS,
   * and detect certificate changes.
   */
  private async pollDomain(domain: string): Promise<{
    newSubdomains: SubdomainResult[];
    changedAssets: AssetChange[];
    alerts: NewAssetAlert[];
  }> {
    const newSubdomains: SubdomainResult[] = [];
    const changedAssets: AssetChange[] = [];
    const alerts: NewAssetAlert[] = [];
    const now = Date.now();

    // ── Query crt.sh ──
    let crtshSubdomains: Set<string> = new Set();
    let crtshCerts: CertInfo[] = [];

    if (this.config.crtshEnabled) {
      const crtshData = await this.fetchCrtSh(domain);
      crtshSubdomains = crtshData.subdomains;
      crtshCerts = crtshData.certificates;
    }

    // ── Detect new subdomains ──
    const known = this.knownSubdomains.get(domain) ?? new Set<string>();
    const isFirstScan = !this.knownSubdomains.has(domain);

    for (const sub of crtshSubdomains) {
      if (!known.has(sub)) {
        const subResult: SubdomainResult = {
          subdomain: sub,
          source: 'crtsh',
        };

        newSubdomains.push(subResult);

        changedAssets.push({
          domain,
          changeType: 'new_subdomain',
          newValue: sub,
          detectedAt: now,
        });

        // Only alert on new subdomains found AFTER the first scan
        if (!isFirstScan) {
          const severity = this.assessSubdomainSeverity(sub);
          alerts.push({
            domain,
            assetType: 'subdomain',
            details: `New subdomain discovered: ${sub}`,
            severity,
            timestamp: now,
          });
        }

        known.add(sub);
      }
    }

    this.knownSubdomains.set(domain, known);

    // ── DNS change detection ──
    if (this.config.dnsEnabled && this.config.executeCommand) {
      // Resolve DNS for newly discovered subdomains
      for (const subResult of newSubdomains) {
        try {
          const dnsRecord = await this.resolveDns(subResult.subdomain);
          if (dnsRecord) {
            subResult.resolvedIps = [dnsRecord.ip];
            subResult.isAlive = true;

            const previousDns = this.knownDns.get(subResult.subdomain);
            if (previousDns) {
              // Detect IP change
              if (previousDns.ip !== dnsRecord.ip) {
                changedAssets.push({
                  domain,
                  changeType: 'dns_change',
                  oldValue: `${subResult.subdomain} -> ${previousDns.ip}`,
                  newValue: `${subResult.subdomain} -> ${dnsRecord.ip}`,
                  detectedAt: now,
                });

                if (!isFirstScan) {
                  alerts.push({
                    domain,
                    assetType: 'dns',
                    details: `DNS change for ${subResult.subdomain}: ${previousDns.ip} -> ${dnsRecord.ip}`,
                    severity: 'medium',
                    timestamp: now,
                  });
                }
              }

              // Detect CNAME change
              if (previousDns.cname !== dnsRecord.cname) {
                changedAssets.push({
                  domain,
                  changeType: 'dns_change',
                  oldValue: `CNAME: ${previousDns.cname ?? 'none'}`,
                  newValue: `CNAME: ${dnsRecord.cname ?? 'none'}`,
                  detectedAt: now,
                });

                if (!isFirstScan) {
                  alerts.push({
                    domain,
                    assetType: 'dns',
                    details: `CNAME change for ${subResult.subdomain}: ${previousDns.cname ?? 'none'} -> ${dnsRecord.cname ?? 'none'}`,
                    severity: 'medium',
                    timestamp: now,
                  });
                }
              }
            }

            this.knownDns.set(subResult.subdomain, dnsRecord);
          } else {
            subResult.isAlive = false;
          }
        } catch {
          // DNS resolution failure for a single subdomain is non-fatal
        }
      }

      // Also re-check DNS for previously known subdomains (sample up to 50)
      const existingSubdomains = [...known].slice(0, 50);
      for (const sub of existingSubdomains) {
        if (!this.running) break;

        try {
          const dnsRecord = await this.resolveDns(sub);
          if (!dnsRecord) continue;

          const previousDns = this.knownDns.get(sub);
          if (previousDns && previousDns.ip !== dnsRecord.ip) {
            changedAssets.push({
              domain,
              changeType: 'dns_change',
              oldValue: `${sub} -> ${previousDns.ip}`,
              newValue: `${sub} -> ${dnsRecord.ip}`,
              detectedAt: now,
            });

            if (!isFirstScan) {
              alerts.push({
                domain,
                assetType: 'dns',
                details: `DNS change for ${sub}: ${previousDns.ip} -> ${dnsRecord.ip}`,
                severity: 'medium',
                timestamp: now,
              });
            }
          }

          this.knownDns.set(sub, dnsRecord);
        } catch {
          // Skip
        }
      }
    }

    // ── Certificate transparency monitoring ──
    if (this.config.crtshEnabled && crtshCerts.length > 0) {
      const knownCertSerials = this.knownCerts.get(domain) ?? new Set<string>();
      const isFirstCertScan = !this.knownCerts.has(domain);

      for (const cert of crtshCerts) {
        if (knownCertSerials.has(cert.serialNumber)) {
          continue;
        }

        knownCertSerials.add(cert.serialNumber);

        if (!isFirstCertScan) {
          // Detect unusual certificates
          const certAlerts = this.analyzeCertificate(cert, domain, now);
          for (const alert of certAlerts) {
            alerts.push(alert);
          }

          changedAssets.push({
            domain,
            changeType: 'cert_change',
            newValue: `New cert: ${cert.commonName} (issuer: ${cert.issuer})`,
            detectedAt: now,
          });
        }
      }

      this.knownCerts.set(domain, knownCertSerials);
    }

    return { newSubdomains, changedAssets, alerts };
  }

  // ─── crt.sh Query ──────────────────────────────────────────────────────────

  /**
   * Fetch subdomains and certificate metadata from crt.sh.
   */
  private async fetchCrtSh(domain: string): Promise<{
    subdomains: Set<string>;
    certificates: CertInfo[];
  }> {
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;

    try {
      const { status, body } = await httpGet(
        url,
        { 'Accept': 'application/json', 'User-Agent': 'Huntress-Monitor/1.0' },
        this.config.httpClient,
      );

      if (status !== 200 || !body || body.trim().length === 0) {
        return { subdomains: new Set(), certificates: [] };
      }

      const entries: CrtShEntry[] = JSON.parse(body);

      const subdomains = new Set<string>();
      const certMap = new Map<string, CertInfo>();

      for (const entry of entries) {
        // Extract subdomains
        const names = [entry.common_name, ...(entry.name_value?.split('\n') ?? [])];
        for (const name of names) {
          const cleaned = name.trim().toLowerCase();
          if (cleaned.length === 0 || cleaned === '*') continue;

          const withoutWildcard = cleaned.startsWith('*.')
            ? cleaned.substring(2)
            : cleaned;

          if (
            withoutWildcard === domain.toLowerCase() ||
            withoutWildcard.endsWith('.' + domain.toLowerCase())
          ) {
            subdomains.add(withoutWildcard);
          }
        }

        // Extract certificate metadata
        if (entry.serial_number && !certMap.has(entry.serial_number)) {
          certMap.set(entry.serial_number, {
            serialNumber: entry.serial_number,
            issuer: entry.issuer_name ?? '',
            commonName: entry.common_name ?? '',
            notBefore: entry.not_before ?? '',
            notAfter: entry.not_after ?? '',
          });
        }
      }

      return {
        subdomains,
        certificates: [...certMap.values()],
      };
    } catch {
      return { subdomains: new Set(), certificates: [] };
    }
  }

  // ─── DNS Resolution ────────────────────────────────────────────────────────

  /**
   * Resolve a subdomain using the `dig` command.
   * Returns null if resolution fails.
   */
  private async resolveDns(subdomain: string): Promise<DnsRecord | null> {
    if (!this.config.executeCommand) {
      return null;
    }

    try {
      // Query A record
      const aResult = await this.config.executeCommand('dig', [
        '+short',
        '+time=5',
        '+tries=2',
        subdomain,
        'A',
      ]);

      const aLines = aResult.stdout.trim().split('\n').filter((l) => l.trim().length > 0);

      // Check for CNAME
      let cname: string | undefined;
      let ip = '';

      for (const line of aLines) {
        const trimmed = line.trim();
        // CNAME entries end with a dot
        if (trimmed.endsWith('.') && !/^\d+\.\d+\.\d+\.\d+$/.test(trimmed)) {
          cname = trimmed.replace(/\.$/, '');
        }
        // IP address
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
          ip = trimmed;
        }
      }

      if (ip.length === 0 && !cname) {
        return null;
      }

      return {
        ip: ip || '',
        cname,
        resolvedAt: Date.now(),
      };
    } catch {
      return null;
    }
  }

  // ─── Certificate Analysis ──────────────────────────────────────────────────

  /**
   * Analyze a newly discovered certificate for anomalies:
   * - Wildcard certificates
   * - Short-lived certificates (< 30 days)
   * - Unusual certificate authorities
   */
  private analyzeCertificate(
    cert: CertInfo,
    domain: string,
    now: number,
  ): NewAssetAlert[] {
    const alerts: NewAssetAlert[] = [];

    // Wildcard certificate detection
    if (cert.commonName.startsWith('*.')) {
      alerts.push({
        domain,
        assetType: 'certificate',
        details: `New wildcard certificate issued: ${cert.commonName} (issuer: ${cert.issuer})`,
        severity: 'info',
        timestamp: now,
      });
    }

    // Short-lived certificate detection (validity < 30 days)
    if (cert.notBefore && cert.notAfter) {
      const notBefore = new Date(cert.notBefore).getTime();
      const notAfter = new Date(cert.notAfter).getTime();

      if (!isNaN(notBefore) && !isNaN(notAfter)) {
        const validityDays = (notAfter - notBefore) / (1000 * 60 * 60 * 24);

        if (validityDays < 30 && validityDays > 0) {
          alerts.push({
            domain,
            assetType: 'certificate',
            details: `Short-lived certificate detected: ${cert.commonName} — valid for ${Math.round(validityDays)} days (issuer: ${cert.issuer})`,
            severity: 'low',
            timestamp: now,
          });
        }
      }
    }

    // Unusual CA detection
    if (cert.issuer) {
      const issuerLower = cert.issuer.toLowerCase();
      const isKnownCa = [...COMMON_CAS].some((ca) => issuerLower.includes(ca));

      if (!isKnownCa) {
        alerts.push({
          domain,
          assetType: 'certificate',
          details: `Certificate from unusual CA: ${cert.commonName} — issuer: ${cert.issuer}`,
          severity: 'medium',
          timestamp: now,
        });
      }
    }

    return alerts;
  }

  // ─── Subdomain Severity Assessment ─────────────────────────────────────────

  /**
   * Assess the severity of a newly discovered subdomain based on its name.
   * Sensitive patterns (admin, staging, dev, internal) get higher severity.
   */
  private assessSubdomainSeverity(subdomain: string): NewAssetAlert['severity'] {
    const lower = subdomain.toLowerCase();

    // High-interest subdomains — likely to have vulnerabilities or sensitive data
    const highPatterns = [
      'admin', 'staging', 'stage', 'dev', 'development',
      'internal', 'intranet', 'vpn', 'jenkins', 'gitlab',
      'jira', 'confluence', 'ci', 'cd', 'deploy',
      'prod', 'production', 'db', 'database', 'backup',
    ];
    for (const pattern of highPatterns) {
      if (lower.includes(pattern)) {
        return 'high';
      }
    }

    // Medium-interest subdomains
    const mediumPatterns = [
      'api', 'gateway', 'auth', 'sso', 'oauth',
      'login', 'portal', 'dashboard', 'panel',
      'test', 'qa', 'uat', 'sandbox',
    ];
    for (const pattern of mediumPatterns) {
      if (lower.includes(pattern)) {
        return 'medium';
      }
    }

    // Low-interest but still noteworthy
    const lowPatterns = [
      'mail', 'smtp', 'mx', 'ftp', 'cdn',
      'static', 'assets', 'media', 'images',
    ];
    for (const pattern of lowPatterns) {
      if (lower.includes(pattern)) {
        return 'low';
      }
    }

    return 'info';
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  /**
   * Emit an alert to all registered callbacks.
   */
  private emitAlert(alert: NewAssetAlert): void {
    for (const cb of this.alertCallbacks) {
      try {
        cb(alert);
      } catch {
        // Never let a callback error crash the monitor
      }
    }
  }

  /**
   * Validate and sanitize a domain name.
   */
  private sanitizeDomain(domain: string): string {
    let cleaned = domain.trim().toLowerCase();
    if (cleaned.startsWith('http://')) {
      cleaned = cleaned.substring(7);
    }
    if (cleaned.startsWith('https://')) {
      cleaned = cleaned.substring(8);
    }
    const slashIdx = cleaned.indexOf('/');
    if (slashIdx >= 0) {
      cleaned = cleaned.substring(0, slashIdx);
    }
    const colonIdx = cleaned.indexOf(':');
    if (colonIdx >= 0) {
      cleaned = cleaned.substring(0, colonIdx);
    }
    if (!/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$/.test(cleaned)) {
      return '';
    }
    return cleaned;
  }
}

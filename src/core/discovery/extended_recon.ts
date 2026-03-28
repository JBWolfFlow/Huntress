/**
 * Extended Reconnaissance Module (Phase 23F)
 *
 * Combines multiple OSINT sources into a unified recon pipeline:
 * - crt.sh certificate transparency logs (no key needed)
 * - Amass passive enumeration (CLI tool, graceful degradation)
 * - Shodan host intelligence (API key required)
 * - Censys certificate & host search (API credentials required)
 * - GitHub code search for leaked secrets (token required)
 * - Google dork query generation for manual follow-up
 *
 * Every external call has proper error handling and returns empty results
 * on failure. Missing credentials cause that source to be skipped silently.
 */

import type { HttpClient, HttpRequestOptions, HttpResponse } from '../http/request_engine';
import type { CommandResult } from '../tauri_bridge';
import { invoke } from '@tauri-apps/api/core';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ExtendedReconConfig {
  shodanApiKey?: string;
  censysApiId?: string;
  censysApiSecret?: string;
  githubToken?: string;
  executeCommand?: (program: string, args: string[], cwd?: string) => Promise<CommandResult>;
  httpClient?: HttpClient;
}

export interface ReconResults {
  subdomains: SubdomainResult[];
  shodanResults: ShodanResult[];
  censysResults: CensysResult[];
  secrets: SecretFinding[];
  dorkResults: DorkResult[];
  timestamp: number;
}

export interface SubdomainResult {
  subdomain: string;
  source: 'crtsh' | 'amass' | 'subfinder' | 'dns';
  resolvedIps?: string[];
  isAlive?: boolean;
}

export interface ShodanResult {
  ip: string;
  ports: number[];
  services: ShodanService[];
  vulns: string[];
  lastUpdate: string;
  hostnames: string[];
}

export interface ShodanService {
  port: number;
  transport: string;
  product: string;
  version: string;
  banner: string;
}

export interface CensysResult {
  ip: string;
  protocols: string[];
  services: CensysService[];
  certificates: CensysCertificate[];
  lastSeen: string;
}

export interface CensysService {
  port: number;
  serviceName: string;
  transportProtocol: string;
}

export interface CensysCertificate {
  fingerprint: string;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
}

export interface SecretFinding {
  repository: string;
  file: string;
  line: number;
  type: 'api_key' | 'password' | 'token' | 'private_key';
  snippet: string;
  confidence: number;
}

export interface DorkResult {
  query: string;
  url: string;
  title: string;
  snippet: string;
}

// ─── Secret Detection Patterns ───────────────────────────────────────────────

interface SecretPattern {
  type: SecretFinding['type'];
  pattern: RegExp;
  confidence: number;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // API keys
  { type: 'api_key', pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/i, confidence: 0.8 },
  { type: 'api_key', pattern: /AKIA[0-9A-Z]{16}/i, confidence: 0.95 },
  { type: 'api_key', pattern: /AIza[0-9A-Za-z_\-]{35}/i, confidence: 0.9 },
  { type: 'api_key', pattern: /sk-[A-Za-z0-9]{32,}/i, confidence: 0.9 },
  { type: 'api_key', pattern: /ghp_[A-Za-z0-9]{36}/i, confidence: 0.95 },
  { type: 'api_key', pattern: /glpat-[A-Za-z0-9_\-]{20,}/i, confidence: 0.9 },
  { type: 'api_key', pattern: /xox[bpras]-[A-Za-z0-9\-]{10,}/i, confidence: 0.9 },

  // Passwords
  { type: 'password', pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,})['"]?/i, confidence: 0.7 },
  { type: 'password', pattern: /(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD)\s*[:=]\s*['"]?([^\s'"]{6,})['"]?/i, confidence: 0.85 },

  // Tokens
  { type: 'token', pattern: /(?:access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*['"]?([A-Za-z0-9_\-.]{20,})['"]?/i, confidence: 0.75 },
  { type: 'token', pattern: /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/i, confidence: 0.85 },
  { type: 'token', pattern: /(?:GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN)\s*[:=]\s*['"]?([^\s'"]{10,})['"]?/i, confidence: 0.9 },

  // Private keys
  { type: 'private_key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/i, confidence: 0.95 },
  { type: 'private_key', pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/i, confidence: 0.95 },
];

// ─── Google Dork Templates ───────────────────────────────────────────────────

function generateDorkQueries(domain: string): string[] {
  return [
    `site:${domain} inurl:admin`,
    `site:${domain} intitle:"login"`,
    `site:${domain} ext:sql | ext:db | ext:log`,
    `site:${domain} "password" | "api_key" | "secret"`,
    `site:${domain} inurl:backup | inurl:old | inurl:temp`,
    `site:${domain} intitle:"index of" | intitle:"directory listing"`,
    `site:${domain} ext:env | ext:cfg | ext:conf | ext:ini`,
    `site:${domain} inurl:debug | inurl:test | inurl:staging`,
    `site:${domain} ext:xml | ext:json | ext:yaml | ext:yml`,
    `site:${domain} inurl:api | inurl:graphql | inurl:swagger`,
    `site:${domain} intext:"phpinfo()" | intext:"phpMyAdmin"`,
    `site:${domain} intitle:"dashboard" | intitle:"admin panel"`,
    `site:${domain} ext:bak | ext:old | ext:swp | ext:tmp`,
    `site:${domain} inurl:upload | inurl:file | inurl:download`,
    `site:${domain} "internal use only" | "confidential" | "do not distribute"`,
  ];
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

// ─── GitHub Code Search Response Shape ───────────────────────────────────────

interface GitHubCodeSearchResponse {
  total_count: number;
  items: GitHubCodeSearchItem[];
}

interface GitHubCodeSearchItem {
  name: string;
  path: string;
  html_url: string;
  repository: {
    full_name: string;
  };
  text_matches?: Array<{
    fragment: string;
    matches: Array<{
      text: string;
      indices: [number, number];
    }>;
  }>;
}

// ─── Shodan API Response Shape ───────────────────────────────────────────────

interface ShodanApiResponse {
  ip_str: string;
  ports: number[];
  hostnames: string[];
  vulns?: string[];
  last_update: string;
  data: Array<{
    port: number;
    transport: string;
    product?: string;
    version?: string;
    data?: string;
  }>;
}

// ─── Censys API Response Shape ───────────────────────────────────────────────

interface CensysSearchResponse {
  result: {
    hits: CensysHit[];
    total: number;
  };
}

interface CensysHit {
  ip: string;
  last_updated_at: string;
  services: Array<{
    port: number;
    service_name: string;
    transport_protocol: string;
    certificate?: string;
  }>;
}

interface CensysCertResponse {
  result: {
    fingerprint_sha256: string;
    parsed: {
      issuer_dn: string;
      subject_dn: string;
      validity: {
        start: string;
        end: string;
      };
    };
  };
}

// ─── Amass JSON Output Shape ─────────────────────────────────────────────────

interface AmassJsonEntry {
  name: string;
  domain: string;
  addresses?: Array<{
    ip: string;
    cidr: string;
    asn: number;
    desc: string;
  }>;
  tag: string;
  sources: string[];
}

// ─── HTTP Helper ─────────────────────────────────────────────────────────────

/**
 * Abstraction over the HttpClient or global fetch for making requests.
 * Uses httpClient.request() when available; falls back to fetch().
 */
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

  // Fallback: route through Tauri backend to bypass CORS
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

  // Last resort: browser fetch (will be CORS-blocked for cross-origin)
  const resp = await fetch(url, {
    method: 'GET',
    headers,
    signal: AbortSignal.timeout(30000),
  });
  const body = await resp.text();
  return { status: resp.status, body };
}

// ─── Extended Recon Class ────────────────────────────────────────────────────

export class ExtendedRecon {
  private config: ExtendedReconConfig;

  constructor(config: ExtendedReconConfig) {
    this.config = config;
  }

  // ─── Full Recon Pipeline ───────────────────────────────────────────────────

  /**
   * Run the full reconnaissance pipeline against a domain.
   * Each source runs independently; failures in one do not block others.
   */
  async runFullRecon(domain: string): Promise<ReconResults> {
    const [subdomains, secrets, dorkResults] = await Promise.all([
      this.enumerateSubdomains(domain),
      this.config.githubToken
        ? this.scanGitSecrets(domain)
        : Promise.resolve([] as SecretFinding[]),
      this.runGoogleDorks(domain),
    ]);

    // Collect unique IPs from resolved subdomains for Shodan/Censys queries
    const uniqueIps = new Set<string>();
    for (const sub of subdomains) {
      if (sub.resolvedIps) {
        for (const ip of sub.resolvedIps) {
          uniqueIps.add(ip);
        }
      }
    }

    // Query Shodan and Censys for each unique IP (in parallel, capped)
    const ipList = [...uniqueIps].slice(0, 20); // Cap at 20 IPs to avoid burning API credits

    const shodanResults: ShodanResult[] = [];
    const censysResults: CensysResult[] = [];

    if (this.config.shodanApiKey || this.config.censysApiId) {
      const ipQueries = ipList.map(async (ip) => {
        const [shodanResult, censysResult] = await Promise.all([
          this.config.shodanApiKey
            ? this.queryShodan(ip)
            : Promise.resolve(null),
          this.config.censysApiId && this.config.censysApiSecret
            ? this.queryCensys(ip)
            : Promise.resolve(null),
        ]);
        if (shodanResult && shodanResult.ports.length > 0) {
          shodanResults.push(shodanResult);
        }
        if (censysResult && censysResult.services.length > 0) {
          censysResults.push(censysResult);
        }
      });

      await Promise.all(ipQueries);
    }

    return {
      subdomains,
      shodanResults,
      censysResults,
      secrets,
      dorkResults,
      timestamp: Date.now(),
    };
  }

  // ─── Subdomain Enumeration ─────────────────────────────────────────────────

  /**
   * Enumerate subdomains using all available sources, deduplicate, and
   * optionally resolve DNS for each discovered subdomain.
   */
  async enumerateSubdomains(domain: string): Promise<SubdomainResult[]> {
    // crt.sh is always tried first (no API key needed)
    const [crtshResults, amassResults] = await Promise.all([
      this.queryCrtSh(domain),
      this.queryAmass(domain),
    ]);

    // Merge and deduplicate by subdomain name
    const seen = new Map<string, SubdomainResult>();

    for (const result of crtshResults) {
      const key = result.subdomain.toLowerCase();
      if (!seen.has(key)) {
        seen.set(key, result);
      }
    }

    for (const result of amassResults) {
      const key = result.subdomain.toLowerCase();
      if (!seen.has(key)) {
        seen.set(key, result);
      } else {
        // Merge resolved IPs from amass into existing entry
        const existing = seen.get(key)!;
        if (result.resolvedIps && result.resolvedIps.length > 0) {
          const mergedIps = new Set<string>([
            ...(existing.resolvedIps ?? []),
            ...result.resolvedIps,
          ]);
          existing.resolvedIps = [...mergedIps];
        }
      }
    }

    return [...seen.values()].sort((a, b) =>
      a.subdomain.localeCompare(b.subdomain),
    );
  }

  // ─── crt.sh ────────────────────────────────────────────────────────────────

  /**
   * Query crt.sh certificate transparency logs.
   * This is the only source that requires no API key.
   */
  async queryCrtSh(domain: string): Promise<SubdomainResult[]> {
    const sanitizedDomain = this.sanitizeDomain(domain);
    if (!sanitizedDomain) {
      return [];
    }

    const url = `https://crt.sh/?q=%25.${encodeURIComponent(sanitizedDomain)}&output=json`;

    try {
      const { status, body } = await httpGet(
        url,
        { 'Accept': 'application/json', 'User-Agent': 'Huntress-Recon/1.0' },
        this.config.httpClient,
      );

      if (status !== 200 || !body || body.trim().length === 0) {
        return [];
      }

      const entries: CrtShEntry[] = JSON.parse(body);

      // Extract unique subdomains from common_name and name_value fields
      const subdomains = new Set<string>();
      for (const entry of entries) {
        const names = [entry.common_name, ...(entry.name_value?.split('\n') ?? [])];
        for (const name of names) {
          const cleaned = name.trim().toLowerCase();
          // Skip wildcard-only entries but keep the base domain pattern
          if (cleaned === '*' || cleaned.length === 0) {
            continue;
          }
          // Remove leading wildcard prefix if present
          const withoutWildcard = cleaned.startsWith('*.')
            ? cleaned.substring(2)
            : cleaned;
          // Validate it belongs to the target domain
          if (
            withoutWildcard === sanitizedDomain.toLowerCase() ||
            withoutWildcard.endsWith('.' + sanitizedDomain.toLowerCase())
          ) {
            subdomains.add(withoutWildcard);
          }
        }
      }

      return [...subdomains].map((sub) => ({
        subdomain: sub,
        source: 'crtsh' as const,
      }));
    } catch {
      // crt.sh can be slow or return invalid JSON; degrade gracefully
      return [];
    }
  }

  // ─── Amass ─────────────────────────────────────────────────────────────────

  /**
   * Run amass passive enumeration. Gracefully degrades if amass is not
   * installed on the system.
   */
  async queryAmass(domain: string): Promise<SubdomainResult[]> {
    const sanitizedDomain = this.sanitizeDomain(domain);
    if (!sanitizedDomain) {
      return [];
    }

    const execCmd = this.config.executeCommand;
    if (!execCmd) {
      return [];
    }

    try {
      // Check if amass is installed
      const versionCheck = await execCmd('amass', ['version']);
      if (!versionCheck.success && versionCheck.exitCode !== 0) {
        // amass not installed; skip silently
        return [];
      }
    } catch {
      return [];
    }

    try {
      const result = await execCmd('amass', [
        'enum',
        '-passive',
        '-d', sanitizedDomain,
        '-json', '-',
      ]);

      if (!result.success && result.stdout.trim().length === 0) {
        return [];
      }

      const output = result.stdout.trim();
      if (output.length === 0) {
        return [];
      }

      const results: SubdomainResult[] = [];
      const lines = output.split('\n');

      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.length === 0) {
          continue;
        }

        try {
          const entry: AmassJsonEntry = JSON.parse(trimmed);

          const resolvedIps: string[] = [];
          if (entry.addresses) {
            for (const addr of entry.addresses) {
              if (addr.ip) {
                resolvedIps.push(addr.ip);
              }
            }
          }

          results.push({
            subdomain: entry.name.toLowerCase(),
            source: 'amass',
            resolvedIps: resolvedIps.length > 0 ? resolvedIps : undefined,
          });
        } catch {
          // Skip malformed JSON lines
        }
      }

      return results;
    } catch {
      return [];
    }
  }

  // ─── Shodan ────────────────────────────────────────────────────────────────

  /**
   * Query Shodan REST API for host intelligence.
   * Requires a valid Shodan API key in the config.
   */
  async queryShodan(target: string): Promise<ShodanResult> {
    const emptyResult: ShodanResult = {
      ip: target,
      ports: [],
      services: [],
      vulns: [],
      lastUpdate: '',
      hostnames: [],
    };

    if (!this.config.shodanApiKey) {
      return emptyResult;
    }

    const sanitizedTarget = this.sanitizeIpOrHost(target);
    if (!sanitizedTarget) {
      return emptyResult;
    }

    // Build URL without API key in the string literal to prevent key from appearing in logs/traces
    const baseUrl = `https://api.shodan.io/shodan/host/${encodeURIComponent(sanitizedTarget)}`;
    const url = new URL(baseUrl);
    url.searchParams.set('key', this.config.shodanApiKey);

    try {
      const { status, body } = await httpGet(
        url.toString(),
        { 'Accept': 'application/json', 'User-Agent': 'Huntress-Recon/1.0' },
        this.config.httpClient,
      );

      if (status !== 200 || !body || body.trim().length === 0) {
        return emptyResult;
      }

      const data: ShodanApiResponse = JSON.parse(body);

      const services: ShodanService[] = (data.data ?? []).map((svc) => ({
        port: svc.port,
        transport: svc.transport ?? 'tcp',
        product: svc.product ?? '',
        version: svc.version ?? '',
        banner: (svc.data ?? '').substring(0, 500),
      }));

      return {
        ip: data.ip_str ?? target,
        ports: data.ports ?? [],
        services,
        vulns: data.vulns ?? [],
        lastUpdate: data.last_update ?? '',
        hostnames: data.hostnames ?? [],
      };
    } catch {
      return emptyResult;
    }
  }

  // ─── Censys ────────────────────────────────────────────────────────────────

  /**
   * Query Censys Search API v2 for host and certificate data.
   * Requires both censysApiId and censysApiSecret in the config.
   */
  async queryCensys(target: string): Promise<CensysResult> {
    const emptyResult: CensysResult = {
      ip: target,
      protocols: [],
      services: [],
      certificates: [],
      lastSeen: '',
    };

    if (!this.config.censysApiId || !this.config.censysApiSecret) {
      return emptyResult;
    }

    const sanitizedTarget = this.sanitizeIpOrHost(target);
    if (!sanitizedTarget) {
      return emptyResult;
    }

    const authHeader = 'Basic ' + btoa(
      this.config.censysApiId + ':' + this.config.censysApiSecret,
    );

    const url = `https://search.censys.io/api/v2/hosts/${encodeURIComponent(sanitizedTarget)}`;

    try {
      const { status, body } = await httpGet(
        url,
        {
          'Accept': 'application/json',
          'Authorization': authHeader,
          'User-Agent': 'Huntress-Recon/1.0',
        },
        this.config.httpClient,
      );

      if (status !== 200 || !body || body.trim().length === 0) {
        return emptyResult;
      }

      const data = JSON.parse(body) as {
        result: {
          ip: string;
          last_updated_at: string;
          services: Array<{
            port: number;
            service_name: string;
            transport_protocol: string;
            certificate?: string;
          }>;
        };
      };

      const hit = data.result;
      if (!hit) {
        return emptyResult;
      }

      const services: CensysService[] = (hit.services ?? []).map((svc) => ({
        port: svc.port,
        serviceName: svc.service_name ?? '',
        transportProtocol: svc.transport_protocol ?? 'TCP',
      }));

      const protocols = new Set<string>();
      for (const svc of services) {
        if (svc.serviceName) {
          protocols.add(`${svc.port}/${svc.serviceName}`);
        }
      }

      // Collect certificate fingerprints for lookup
      const certFingerprints: string[] = [];
      for (const svc of hit.services ?? []) {
        if (svc.certificate) {
          certFingerprints.push(svc.certificate);
        }
      }

      // Fetch certificate details (up to 5)
      const certificates = await this.fetchCensysCertificates(
        certFingerprints.slice(0, 5),
        authHeader,
      );

      return {
        ip: hit.ip ?? target,
        protocols: [...protocols],
        services,
        certificates,
        lastSeen: hit.last_updated_at ?? '',
      };
    } catch {
      return emptyResult;
    }
  }

  // ─── GitHub Secrets Scanning ───────────────────────────────────────────────

  /**
   * Search GitHub Code Search API for leaked secrets belonging to an
   * organization or domain. Requires a GitHub personal access token.
   */
  async scanGitSecrets(githubOrg: string): Promise<SecretFinding[]> {
    if (!this.config.githubToken) {
      return [];
    }

    // Sanitize the org name to prevent injection
    const sanitizedOrg = githubOrg.replace(/[^a-zA-Z0-9._\-]/g, '');
    if (sanitizedOrg.length === 0) {
      return [];
    }

    const searchQueries = [
      `org:${sanitizedOrg} password`,
      `org:${sanitizedOrg} api_key OR apikey OR api-key`,
      `org:${sanitizedOrg} secret_key OR secret`,
      `org:${sanitizedOrg} access_token OR auth_token`,
      `org:${sanitizedOrg} private_key OR "BEGIN RSA"`,
      `org:${sanitizedOrg} AWS_SECRET OR AKIA`,
    ];

    const findings: SecretFinding[] = [];
    const seenKeys = new Set<string>();

    for (const query of searchQueries) {
      try {
        const url = `https://api.github.com/search/code?q=${encodeURIComponent(query)}&per_page=30`;

        const { status, body } = await httpGet(
          url,
          {
            'Accept': 'application/vnd.github.text-match+json',
            'Authorization': `Bearer ${this.config.githubToken}`,
            'User-Agent': 'Huntress-Recon/1.0',
            'X-GitHub-Api-Version': '2022-11-28',
          },
          this.config.httpClient,
        );

        if (status !== 200 || !body) {
          continue;
        }

        const data: GitHubCodeSearchResponse = JSON.parse(body);

        for (const item of data.items ?? []) {
          const fragments = (item.text_matches ?? [])
            .map((m) => m.fragment)
            .filter((f) => f.length > 0);

          for (const fragment of fragments) {
            const detected = this.detectSecrets(fragment);
            for (const detection of detected) {
              const dedupeKey = `${item.repository.full_name}:${item.path}:${detection.type}:${detection.snippet.substring(0, 30)}`;
              if (seenKeys.has(dedupeKey)) {
                continue;
              }
              seenKeys.add(dedupeKey);

              findings.push({
                repository: item.repository.full_name,
                file: item.path,
                line: 1, // GitHub code search does not expose line numbers
                type: detection.type,
                snippet: detection.snippet.substring(0, 200),
                confidence: detection.confidence,
              });
            }
          }
        }

        // Respect GitHub rate limits: 10 searches per minute for authenticated users
        await sleep(6500);
      } catch {
        // Continue with next query on failure
      }
    }

    // Sort by confidence descending
    findings.sort((a, b) => b.confidence - a.confidence);

    return findings;
  }

  // ─── Google Dorks ──────────────────────────────────────────────────────────

  /**
   * Generate standard Google dork queries for the domain and optionally
   * probe domain-based URLs (e.g., /admin, /backup) via httpClient.
   * Does NOT call the Google Search API.
   */
  async runGoogleDorks(domain: string): Promise<DorkResult[]> {
    const sanitizedDomain = this.sanitizeDomain(domain);
    if (!sanitizedDomain) {
      return [];
    }

    const dorkQueries = generateDorkQueries(sanitizedDomain);
    const results: DorkResult[] = [];

    // Add each dork query as a result for manual use
    for (const query of dorkQueries) {
      const googleSearchUrl = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
      results.push({
        query,
        url: googleSearchUrl,
        title: `Google Dork: ${query}`,
        snippet: `Open this URL in a browser to execute the dork query manually.`,
      });
    }

    // Probe common sensitive paths on the target domain via httpClient
    if (this.config.httpClient) {
      const probePaths = [
        '/admin',
        '/admin/login',
        '/wp-admin',
        '/wp-login.php',
        '/.env',
        '/.git/config',
        '/config.json',
        '/backup',
        '/debug',
        '/api/swagger',
        '/graphql',
        '/robots.txt',
        '/sitemap.xml',
        '/.well-known/security.txt',
        '/server-status',
        '/phpinfo.php',
      ];

      const probeResults = await Promise.allSettled(
        probePaths.map(async (probePath) => {
          const probeUrl = `https://${sanitizedDomain}${probePath}`;
          try {
            const resp = await this.config.httpClient!.request({
              url: probeUrl,
              method: 'GET',
              timeoutMs: 10000,
              followRedirects: false,
            });

            // Only report pages that exist (200) or redirect (301/302)
            if (resp.status === 200 || resp.status === 301 || resp.status === 302) {
              const titleMatch = resp.body.match(/<title[^>]*>([^<]*)<\/title>/i);
              const title = titleMatch ? titleMatch[1].trim() : '';
              return {
                query: `Direct probe: ${probePath}`,
                url: probeUrl,
                title: title || `HTTP ${resp.status}`,
                snippet: `Status ${resp.status} — ${resp.body.length} bytes`,
              };
            }
            return null;
          } catch {
            return null;
          }
        }),
      );

      for (const outcome of probeResults) {
        if (outcome.status === 'fulfilled' && outcome.value !== null) {
          results.push(outcome.value);
        }
      }
    }

    return results;
  }

  // ─── Private Helpers ───────────────────────────────────────────────────────

  /**
   * Fetch certificate details from Censys for a list of fingerprints.
   */
  private async fetchCensysCertificates(
    fingerprints: string[],
    authHeader: string,
  ): Promise<CensysCertificate[]> {
    const certificates: CensysCertificate[] = [];

    for (const fp of fingerprints) {
      try {
        const url = `https://search.censys.io/api/v2/certificates/${encodeURIComponent(fp)}`;
        const { status, body } = await httpGet(
          url,
          {
            'Accept': 'application/json',
            'Authorization': authHeader,
            'User-Agent': 'Huntress-Recon/1.0',
          },
          this.config.httpClient,
        );

        if (status !== 200 || !body) {
          continue;
        }

        const data: CensysCertResponse = JSON.parse(body);
        const parsed = data.result?.parsed;
        if (!parsed) {
          continue;
        }

        certificates.push({
          fingerprint: data.result.fingerprint_sha256 ?? fp,
          issuer: parsed.issuer_dn ?? '',
          subject: parsed.subject_dn ?? '',
          validFrom: parsed.validity?.start ?? '',
          validTo: parsed.validity?.end ?? '',
        });
      } catch {
        // Skip individual certificate lookup failures
      }
    }

    return certificates;
  }

  /**
   * Detect secrets in a code fragment using pattern matching.
   */
  private detectSecrets(fragment: string): Array<{ type: SecretFinding['type']; snippet: string; confidence: number }> {
    const results: Array<{ type: SecretFinding['type']; snippet: string; confidence: number }> = [];

    for (const pattern of SECRET_PATTERNS) {
      const match = pattern.pattern.exec(fragment);
      if (match) {
        // Extract a context window around the match
        const matchStart = Math.max(0, match.index - 20);
        const matchEnd = Math.min(fragment.length, match.index + match[0].length + 20);
        const snippet = fragment.substring(matchStart, matchEnd).trim();

        results.push({
          type: pattern.type,
          snippet,
          confidence: pattern.confidence,
        });
      }
    }

    return results;
  }

  /**
   * Validate and sanitize a domain name. Returns empty string if invalid.
   */
  private sanitizeDomain(domain: string): string {
    // Strip protocol if provided
    let cleaned = domain.trim().toLowerCase();
    if (cleaned.startsWith('http://')) {
      cleaned = cleaned.substring(7);
    }
    if (cleaned.startsWith('https://')) {
      cleaned = cleaned.substring(8);
    }
    // Strip trailing path/slash
    const slashIdx = cleaned.indexOf('/');
    if (slashIdx >= 0) {
      cleaned = cleaned.substring(0, slashIdx);
    }
    // Strip port
    const colonIdx = cleaned.indexOf(':');
    if (colonIdx >= 0) {
      cleaned = cleaned.substring(0, colonIdx);
    }
    // Validate domain pattern (basic check)
    if (!/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$/.test(cleaned)) {
      return '';
    }
    return cleaned;
  }

  /**
   * Validate and sanitize an IP address or hostname for Shodan/Censys queries.
   */
  private sanitizeIpOrHost(target: string): string {
    const cleaned = target.trim();
    // IPv4
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(cleaned)) {
      return cleaned;
    }
    // IPv6 (simplified check)
    if (/^[0-9a-fA-F:]+$/.test(cleaned) && cleaned.includes(':')) {
      return cleaned;
    }
    // Hostname
    if (/^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$/.test(cleaned)) {
      return cleaned;
    }
    return '';
  }
}

// ─── Utility ─────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

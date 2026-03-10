/**
 * Asset Map Data Structure
 *
 * Structured representation of all discovered assets for a target.
 * Populated by the recon pipeline and consumed by specialized hunter agents.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AssetMap {
  domain: string;
  subdomains: Subdomain[];
  ports: PortInfo[];
  endpoints: Endpoint[];
  jsFiles: JSFile[];
  technologies: Technology[];
  wafDetected: WAFInfo | null;
  sslInfo: SSLInfo[];
  screenshots: Screenshot[];
  createdAt: number;
  updatedAt: number;
}

export interface Subdomain {
  name: string;
  ips: string[];
  cnames: string[];
  status: 'resolved' | 'unresolved' | 'wildcard';
  httpStatus?: number;
  title?: string;
  technologies: string[];
}

export interface PortInfo {
  host: string;
  port: number;
  service: string;
  version?: string;
  state: 'open' | 'closed' | 'filtered';
}

export interface Endpoint {
  url: string;
  method: string;
  params: Parameter[];
  technology?: string;
  statusCode?: number;
  contentType?: string;
  contentLength?: number;
  source: 'crawl' | 'wayback' | 'js_analysis' | 'param_mining' | 'manual';
}

export interface Parameter {
  name: string;
  type: 'query' | 'body' | 'header' | 'path' | 'cookie';
  value?: string;
  reflectsInput?: boolean;
}

export interface JSFile {
  url: string;
  endpoints: string[];
  secrets: JSSecret[];
  size?: number;
}

export interface JSSecret {
  type: 'api_key' | 'token' | 'password' | 'internal_url' | 'aws_key' | 'other';
  value: string;
  context: string;
}

export interface Technology {
  name: string;
  version?: string;
  category: 'framework' | 'cms' | 'server' | 'language' | 'cdn' | 'analytics' | 'other';
  confidence: number;
}

export interface WAFInfo {
  name: string;
  manufacturer?: string;
  confidence: number;
}

export interface SSLInfo {
  host: string;
  port: number;
  protocol: string;
  cipherSuite?: string;
  certificate?: {
    issuer: string;
    subject: string;
    validFrom: string;
    validTo: string;
    altNames: string[];
  };
  vulnerabilities: string[];
}

export interface Screenshot {
  url: string;
  filePath: string;
  title?: string;
  timestamp: number;
}

// ─── Asset Map Builder ───────────────────────────────────────────────────────

export class AssetMapBuilder {
  private map: AssetMap;

  constructor(domain: string) {
    this.map = {
      domain,
      subdomains: [],
      ports: [],
      endpoints: [],
      jsFiles: [],
      technologies: [],
      wafDetected: null,
      sslInfo: [],
      screenshots: [],
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
  }

  addSubdomain(sub: Subdomain): void {
    const existing = this.map.subdomains.find(s => s.name === sub.name);
    if (existing) {
      existing.ips = [...new Set([...existing.ips, ...sub.ips])];
      existing.cnames = [...new Set([...existing.cnames, ...sub.cnames])];
      existing.technologies = [...new Set([...existing.technologies, ...sub.technologies])];
      if (sub.httpStatus) existing.httpStatus = sub.httpStatus;
      if (sub.title) existing.title = sub.title;
      // Upgrade status: resolved > wildcard > unresolved
      const statusRank: Record<string, number> = { unresolved: 0, wildcard: 1, resolved: 2 };
      if ((statusRank[sub.status] ?? 0) > (statusRank[existing.status] ?? 0)) {
        existing.status = sub.status;
      }
    } else {
      this.map.subdomains.push(sub);
    }
    this.touch();
  }

  addPort(port: PortInfo): void {
    const existing = this.map.ports.find(p => p.host === port.host && p.port === port.port);
    if (!existing) {
      this.map.ports.push(port);
      this.touch();
    }
  }

  addEndpoint(endpoint: Endpoint): void {
    const existing = this.map.endpoints.find(
      e => e.url === endpoint.url && e.method === endpoint.method
    );
    if (existing) {
      // Merge params
      for (const param of endpoint.params) {
        if (!existing.params.some(p => p.name === param.name && p.type === param.type)) {
          existing.params.push(param);
        }
      }
    } else {
      this.map.endpoints.push(endpoint);
    }
    this.touch();
  }

  addJSFile(file: JSFile): void {
    const existing = this.map.jsFiles.find(f => f.url === file.url);
    if (existing) {
      existing.endpoints = [...new Set([...existing.endpoints, ...file.endpoints])];
      existing.secrets.push(...file.secrets);
    } else {
      this.map.jsFiles.push(file);
    }
    this.touch();
  }

  addTechnology(tech: Technology): void {
    const existing = this.map.technologies.find(
      t => t.name.toLowerCase() === tech.name.toLowerCase()
    );
    if (existing) {
      if (tech.version && !existing.version) existing.version = tech.version;
      if (tech.confidence > existing.confidence) existing.confidence = tech.confidence;
    } else {
      this.map.technologies.push(tech);
    }
    this.touch();
  }

  setWAF(waf: WAFInfo): void {
    this.map.wafDetected = waf;
    this.touch();
  }

  addSSLInfo(info: SSLInfo): void {
    this.map.sslInfo.push(info);
    this.touch();
  }

  addScreenshot(screenshot: Screenshot): void {
    this.map.screenshots.push(screenshot);
    this.touch();
  }

  build(): AssetMap {
    return { ...this.map };
  }

  /** Get endpoints with injectable parameters (URL, ID, or user-input params) */
  getInjectableEndpoints(): Endpoint[] {
    return this.map.endpoints.filter(e =>
      e.params.some(p => p.reflectsInput || p.type === 'query' || p.type === 'body')
    );
  }

  /** Get subdomains with dangling CNAMEs (potential takeover targets) */
  getDanglingCNAMEs(): Subdomain[] {
    return this.map.subdomains.filter(
      s => s.status === 'unresolved' && s.cnames.length > 0
    );
  }

  /** Get a summary for display or model context */
  getSummary(): string {
    const m = this.map;
    return [
      `Domain: ${m.domain}`,
      `Subdomains: ${m.subdomains.length} (${m.subdomains.filter(s => s.status === 'resolved').length} resolved)`,
      `Open ports: ${m.ports.filter(p => p.state === 'open').length}`,
      `Endpoints: ${m.endpoints.length} (${this.getInjectableEndpoints().length} injectable)`,
      `JS files: ${m.jsFiles.length} (${m.jsFiles.reduce((s, f) => s + f.secrets.length, 0)} secrets)`,
      `Technologies: ${m.technologies.map(t => `${t.name}${t.version ? ` ${t.version}` : ''}`).join(', ') || 'unknown'}`,
      `WAF: ${m.wafDetected ? `${m.wafDetected.name}` : 'none detected'}`,
      `SSL issues: ${m.sslInfo.reduce((s, i) => s + i.vulnerabilities.length, 0)}`,
      `Dangling CNAMEs: ${this.getDanglingCNAMEs().length}`,
    ].join('\n');
  }

  private touch(): void {
    this.map.updatedAt = Date.now();
  }
}

export default AssetMapBuilder;

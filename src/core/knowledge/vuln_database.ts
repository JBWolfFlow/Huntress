/**
 * Vulnerability Knowledge Database
 *
 * Aggregates data from multiple free public vulnerability sources into a local
 * SQLite database for offline search, agent context enrichment, and duplicate
 * detection.  All HTTP fetches use `tauriFetch` to bypass CORS in the Tauri WebView.
 *
 * Data sources:
 *   - NVD / CVE API (NIST)
 *   - CISA Known Exploited Vulnerabilities (KEV) catalog
 *   - GitHub Security Advisory Database
 *   - CWE (bundled mapping)
 *   - CAPEC attack patterns (bundled mapping)
 */

import {
  knowledgeDbQuery,
  knowledgeDbExecute,
  initKnowledgeDb,
  tauriFetch,
} from '../tauri_bridge';

// ─── Interfaces ─────────────────────────────────────────────────────────────

/** Progress callback signature shared by all sync methods */
export type SyncProgressCallback = (
  current: number,
  total: number,
  message: string,
) => void;

/** Options for NVD sync */
export interface NVDSyncOptions {
  apiKey?: string;
  daysBack?: number;
  onProgress?: SyncProgressCallback;
}

/** Options for GitHub Advisory sync */
export interface GitHubAdvisorySyncOptions {
  ecosystem?: string;
  severity?: string;
  onProgress?: SyncProgressCallback;
}

// ─── NVD / CVE types ────────────────────────────────────────────────────────

export interface CVERecord {
  cveId: string;
  description: string;
  publishedDate: string;
  lastModifiedDate: string;
  cvssV31Score: number | null;
  cvssV31Severity: string | null;
  cvssV31Vector: string | null;
  cweIds: string[];
  references: string[];
}

/** Shape of a single NVD API vulnerability wrapper */
interface NVDVulnerability {
  cve: {
    id: string;
    descriptions: Array<{ lang: string; value: string }>;
    published: string;
    lastModified: string;
    metrics?: {
      cvssMetricV31?: Array<{
        cvssData: {
          baseScore: number;
          baseSeverity: string;
          vectorString: string;
        };
      }>;
    };
    weaknesses?: Array<{
      description: Array<{ lang: string; value: string }>;
    }>;
    references?: Array<{ url: string; source?: string }>;
  };
}

/** NVD API response shape */
interface NVDResponse {
  totalResults: number;
  resultsPerPage: number;
  startIndex: number;
  vulnerabilities: NVDVulnerability[];
}

// ─── CISA KEV types ─────────────────────────────────────────────────────────

export interface KEVEntry {
  cveId: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
}

interface CISAKEVResponse {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: Array<{
    cveID: string;
    vendorProject: string;
    product: string;
    vulnerabilityName: string;
    dateAdded: string;
    shortDescription: string;
    requiredAction: string;
    dueDate: string;
    knownRansomwareCampaignUse: string;
  }>;
}

// ─── GitHub Advisory types ──────────────────────────────────────────────────

export interface GitHubAdvisory {
  ghsaId: string;
  cveId: string | null;
  summary: string;
  description: string;
  severity: string;
  publishedAt: string;
  updatedAt: string;
  ecosystem: string | null;
  vulnerablePackage: string | null;
  references: string[];
}

interface GitHubAdvisoryAPIItem {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  description: string;
  severity: string;
  published_at: string;
  updated_at: string;
  vulnerabilities?: Array<{
    package?: {
      ecosystem?: string;
      name?: string;
    };
  }>;
  references?: Array<{ url: string }>;
  html_url?: string;
}

// ─── CWE types ──────────────────────────────────────────────────────────────

export interface CWEInfo {
  cweId: string;
  name: string;
  description: string;
  relatedAttackPatterns: string[];
  parentCWEs: string[];
  childCWEs: string[];
}

// ─── CAPEC types ────────────────────────────────────────────────────────────

export interface AttackPattern {
  capecId: string;
  name: string;
  description: string;
  severity: string;
  likelihood: string;
  relatedCWEs: string[];
}

// ─── Cross-source query result types ────────────────────────────────────────

export interface VulnContext {
  vulnType: string;
  cweIds: string[];
  recentCVEs: CVERecord[];
  attackPatterns: AttackPattern[];
  kevEntries: KEVEntry[];
  cweInfo: CWEInfo[];
}

export interface ExploitabilityInfo {
  cveId: string;
  inKEV: boolean;
  cvssScore: number | null;
  cvssSeverity: string | null;
  exploitReferences: string[];
  knownRansomwareUse: boolean;
}

export interface AgentKnowledge {
  vulnType: string;
  agentType: string;
  target: string;
  cweInfo: CWEInfo[];
  attackPatterns: AttackPattern[];
  relevantCVEs: CVERecord[];
  kevEntries: KEVEntry[];
}

// ─── Bundled CWE-to-vuln_type mapping ───────────────────────────────────────

const CWE_VULN_TYPE_MAP: Record<string, string> = {
  'CWE-79': 'xss',
  'CWE-89': 'sqli',
  'CWE-352': 'csrf',
  'CWE-918': 'ssrf',
  'CWE-22': 'path_traversal',
  'CWE-78': 'command_injection',
  'CWE-611': 'xxe',
  'CWE-1321': 'prototype_pollution',
  'CWE-843': 'ssti',
  'CWE-284': 'idor',
  'CWE-942': 'cors',
  'CWE-601': 'open_redirect',
  'CWE-644': 'host_header',
  'CWE-502': 'deserialization',
};

/** Reverse map: vuln_type -> CWE IDs */
const VULN_TYPE_CWE_MAP: Record<string, string[]> = {};
for (const [cwe, vulnType] of Object.entries(CWE_VULN_TYPE_MAP)) {
  if (!VULN_TYPE_CWE_MAP[vulnType]) {
    VULN_TYPE_CWE_MAP[vulnType] = [];
  }
  VULN_TYPE_CWE_MAP[vulnType].push(cwe);
}

// ─── Bundled CWE catalog ────────────────────────────────────────────────────
// Sourced from https://cwe.mitre.org/data/  (subset relevant to web/API security)

const CWE_CATALOG: Record<string, CWEInfo> = {
  'CWE-79': {
    cweId: 'CWE-79',
    name: 'Improper Neutralization of Input During Web Page Generation (XSS)',
    description: 'The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page served to other users.',
    relatedAttackPatterns: ['CAPEC-86', 'CAPEC-198', 'CAPEC-243'],
    parentCWEs: ['CWE-74'],
    childCWEs: ['CWE-80', 'CWE-83', 'CWE-84', 'CWE-85', 'CWE-87'],
  },
  'CWE-89': {
    cweId: 'CWE-89',
    name: 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
    description: 'The product constructs all or part of an SQL command using externally-influenced input, but it does not neutralize special elements that could modify the intended SQL command.',
    relatedAttackPatterns: ['CAPEC-66', 'CAPEC-108', 'CAPEC-109', 'CAPEC-110'],
    parentCWEs: ['CWE-943'],
    childCWEs: ['CWE-564'],
  },
  'CWE-352': {
    cweId: 'CWE-352',
    name: 'Cross-Site Request Forgery (CSRF)',
    description: 'The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.',
    relatedAttackPatterns: ['CAPEC-62', 'CAPEC-111'],
    parentCWEs: ['CWE-345'],
    childCWEs: [],
  },
  'CWE-918': {
    cweId: 'CWE-918',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.',
    relatedAttackPatterns: ['CAPEC-664'],
    parentCWEs: ['CWE-441'],
    childCWEs: [],
  },
  'CWE-22': {
    cweId: 'CWE-22',
    name: 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
    description: 'The product uses external input to construct a pathname that is intended to identify a file or directory located underneath a restricted parent directory, but does not properly neutralize special elements within the pathname.',
    relatedAttackPatterns: ['CAPEC-126', 'CAPEC-139'],
    parentCWEs: ['CWE-706'],
    childCWEs: ['CWE-23', 'CWE-36'],
  },
  'CWE-78': {
    cweId: 'CWE-78',
    name: 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)',
    description: 'The product constructs all or part of an OS command using externally-influenced input but does not neutralize special elements that could modify the intended OS command.',
    relatedAttackPatterns: ['CAPEC-88', 'CAPEC-15'],
    parentCWEs: ['CWE-77'],
    childCWEs: [],
  },
  'CWE-611': {
    cweId: 'CWE-611',
    name: 'Improper Restriction of XML External Entity Reference (XXE)',
    description: 'The product processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output.',
    relatedAttackPatterns: ['CAPEC-201', 'CAPEC-221'],
    parentCWEs: ['CWE-610'],
    childCWEs: [],
  },
  'CWE-1321': {
    cweId: 'CWE-1321',
    name: 'Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)',
    description: 'The product receives input from an upstream component that specifies attributes that are to be initialized or updated in an object, but it does not properly control modifications of attributes of the object prototype.',
    relatedAttackPatterns: ['CAPEC-1'],
    parentCWEs: ['CWE-915'],
    childCWEs: [],
  },
  'CWE-843': {
    cweId: 'CWE-843',
    name: 'Access of Resource Using Incompatible Type (Type Confusion)',
    description: 'The product allocates or initializes a resource such as a pointer, object, or variable using one type, but it later accesses that resource using a type that is incompatible with the original type. Commonly mapped to SSTI in web contexts.',
    relatedAttackPatterns: ['CAPEC-586'],
    parentCWEs: ['CWE-704'],
    childCWEs: [],
  },
  'CWE-284': {
    cweId: 'CWE-284',
    name: 'Improper Access Control',
    description: 'The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor. Covers IDOR and related access control flaws.',
    relatedAttackPatterns: ['CAPEC-1', 'CAPEC-17', 'CAPEC-122'],
    parentCWEs: [],
    childCWEs: ['CWE-285', 'CWE-286', 'CWE-287', 'CWE-639'],
  },
  'CWE-942': {
    cweId: 'CWE-942',
    name: 'Permissive Cross-domain Policy with Untrusted Domains',
    description: 'The product uses a cross-domain policy file that includes domains that should not be trusted.',
    relatedAttackPatterns: ['CAPEC-111'],
    parentCWEs: ['CWE-183'],
    childCWEs: [],
  },
  'CWE-601': {
    cweId: 'CWE-601',
    name: 'URL Redirection to Untrusted Site (Open Redirect)',
    description: 'A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a redirect.',
    relatedAttackPatterns: ['CAPEC-194'],
    parentCWEs: ['CWE-610'],
    childCWEs: [],
  },
  'CWE-644': {
    cweId: 'CWE-644',
    name: 'Improper Neutralization of HTTP Headers for Scripting Syntax',
    description: 'The product does not neutralize or incorrectly neutralizes web scripting syntax in HTTP headers that can be used by web browser components that can process raw headers.',
    relatedAttackPatterns: ['CAPEC-105'],
    parentCWEs: ['CWE-116'],
    childCWEs: [],
  },
  'CWE-502': {
    cweId: 'CWE-502',
    name: 'Deserialization of Untrusted Data',
    description: 'The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid.',
    relatedAttackPatterns: ['CAPEC-586'],
    parentCWEs: ['CWE-913'],
    childCWEs: [],
  },
  // Additional parent/child references
  'CWE-74': {
    cweId: 'CWE-74',
    name: 'Improper Neutralization of Special Elements in Output Used by a Downstream Component (Injection)',
    description: 'The product constructs all or part of a command, data structure, or record using externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed.',
    relatedAttackPatterns: [],
    parentCWEs: ['CWE-707'],
    childCWEs: ['CWE-79', 'CWE-89', 'CWE-77', 'CWE-94'],
  },
  'CWE-77': {
    cweId: 'CWE-77',
    name: 'Improper Neutralization of Special Elements used in a Command (Command Injection)',
    description: 'The product constructs all or part of a command using externally-influenced input but does not neutralize special elements.',
    relatedAttackPatterns: ['CAPEC-88'],
    parentCWEs: ['CWE-74'],
    childCWEs: ['CWE-78'],
  },
  'CWE-610': {
    cweId: 'CWE-610',
    name: 'Externally Controlled Reference to a Resource in Another Sphere',
    description: 'The product uses an externally controlled name or reference that resolves to a resource outside of the intended control sphere.',
    relatedAttackPatterns: [],
    parentCWEs: [],
    childCWEs: ['CWE-601', 'CWE-611', 'CWE-918'],
  },
  'CWE-639': {
    cweId: 'CWE-639',
    name: 'Authorization Bypass Through User-Controlled Key (IDOR)',
    description: 'The system uses a user-controlled key to access a resource, but the system does not verify that the user is authorized for the corresponding resource.',
    relatedAttackPatterns: ['CAPEC-1'],
    parentCWEs: ['CWE-284'],
    childCWEs: [],
  },
};

// ─── Bundled CAPEC catalog ──────────────────────────────────────────────────
// Sourced from https://github.com/mitre/cti (STIX format, subset)

const CAPEC_CATALOG: Record<string, AttackPattern> = {
  'CAPEC-1': {
    capecId: 'CAPEC-1',
    name: 'Accessing Functionality Not Properly Constrained by ACLs',
    description: 'An attacker accesses functionality that is insufficiently protected by access control lists.',
    severity: 'High',
    likelihood: 'High',
    relatedCWEs: ['CWE-284', 'CWE-639', 'CWE-1321'],
  },
  'CAPEC-15': {
    capecId: 'CAPEC-15',
    name: 'Command Delimiters',
    description: 'An attacker modifies the command being executed by injecting new command delimiters.',
    severity: 'High',
    likelihood: 'Medium',
    relatedCWEs: ['CWE-78', 'CWE-77'],
  },
  'CAPEC-17': {
    capecId: 'CAPEC-17',
    name: 'Using Malicious Files',
    description: 'An attacker crafts a file that, when processed by a target application, causes unintended behavior.',
    severity: 'High',
    likelihood: 'Medium',
    relatedCWEs: ['CWE-284'],
  },
  'CAPEC-62': {
    capecId: 'CAPEC-62',
    name: 'Cross Site Request Forgery',
    description: 'An attacker crafts a malicious web page that, when visited by an authenticated user, forces the user\'s browser to make an unauthorized request to a target site.',
    severity: 'High',
    likelihood: 'Medium',
    relatedCWEs: ['CWE-352'],
  },
  'CAPEC-66': {
    capecId: 'CAPEC-66',
    name: 'SQL Injection',
    description: 'An attacker injects SQL commands into data fields that are used in SQL queries, allowing the attacker to manipulate or exfiltrate data.',
    severity: 'High',
    likelihood: 'High',
    relatedCWEs: ['CWE-89'],
  },
  'CAPEC-86': {
    capecId: 'CAPEC-86',
    name: 'XSS Through HTTP Headers',
    description: 'An attacker injects malicious scripts into HTTP headers that are reflected back in the response.',
    severity: 'Medium',
    likelihood: 'Medium',
    relatedCWEs: ['CWE-79'],
  },
  'CAPEC-88': {
    capecId: 'CAPEC-88',
    name: 'OS Command Injection',
    description: 'An attacker injects operating system commands into application parameters that are passed to a system shell.',
    severity: 'High',
    likelihood: 'Medium',
    relatedCWEs: ['CWE-78', 'CWE-77'],
  },
  'CAPEC-105': {
    capecId: 'CAPEC-105',
    name: 'HTTP Request Splitting',
    description: 'An attacker crafts HTTP requests that exploit header parsing issues to inject additional requests.',
    severity: 'Medium',
    likelihood: 'Medium',
    relatedCWEs: ['CWE-644'],
  },
  'CAPEC-108': {
    capecId: 'CAPEC-108',
    name: 'Command Line Execution through SQL Injection',
    description: 'An attacker uses SQL Injection to execute system commands via database features like xp_cmdshell.',
    severity: 'High',
    likelihood: 'Medium',
    relatedCWEs: ['CWE-89'],
  },
  'CAPEC-109': {
    capecId: 'CAPEC-109',
    name: 'Object Relational Mapping Injection',
    description: 'An attacker exploits an ORM layer to inject SQL via object manipulation.',
    severity: 'High',
    likelihood: 'Low',
    relatedCWEs: ['CWE-89'],
  },
  'CAPEC-110': {
    capecId: 'CAPEC-110',
    name: 'SQL Injection through SOAP Parameter Tampering',
    description: 'An attacker modifies SOAP parameters to inject SQL into the back-end database queries.',
    severity: 'High',
    likelihood: 'Low',
    relatedCWEs: ['CWE-89'],
  },
  'CAPEC-111': {
    capecId: 'CAPEC-111',
    name: 'JSON Hijacking (aka JavaScript Hijacking)',
    description: 'An attacker exploits the cross-domain nature of JSONP or permissive CORS to steal sensitive data.',
    severity: 'High',
    likelihood: 'Medium',
    relatedCWEs: ['CWE-352', 'CWE-942'],
  },
  'CAPEC-122': {
    capecId: 'CAPEC-122',
    name: 'Privilege Abuse',
    description: 'An attacker exploits poorly controlled access to escalate privileges or access unauthorized resources.',
    severity: 'Medium',
    likelihood: 'Medium',
    relatedCWEs: ['CWE-284'],
  },
  'CAPEC-126': {
    capecId: 'CAPEC-126',
    name: 'Path Traversal',
    description: 'An attacker manipulates variables that reference files with dot-dot-slash sequences to access files outside the intended directory.',
    severity: 'High',
    likelihood: 'High',
    relatedCWEs: ['CWE-22'],
  },
  'CAPEC-139': {
    capecId: 'CAPEC-139',
    name: 'Relative Path Traversal',
    description: 'An attacker uses relative path sequences like ../ to break out of restricted directories.',
    severity: 'High',
    likelihood: 'High',
    relatedCWEs: ['CWE-22'],
  },
  'CAPEC-194': {
    capecId: 'CAPEC-194',
    name: 'Fake the Source of Data',
    description: 'An attacker exploits open redirects to fake the apparent source of a link.',
    severity: 'Medium',
    likelihood: 'High',
    relatedCWEs: ['CWE-601'],
  },
  'CAPEC-198': {
    capecId: 'CAPEC-198',
    name: 'XSS Targeting Error Pages',
    description: 'An attacker exploits custom error pages that reflect user input without sanitization.',
    severity: 'Medium',
    likelihood: 'High',
    relatedCWEs: ['CWE-79'],
  },
  'CAPEC-201': {
    capecId: 'CAPEC-201',
    name: 'Serialized Data External Linking',
    description: 'An attacker crafts XML documents with external entity references to exfiltrate data or cause denial of service.',
    severity: 'High',
    likelihood: 'Medium',
    relatedCWEs: ['CWE-611'],
  },
  'CAPEC-221': {
    capecId: 'CAPEC-221',
    name: 'Data Serialization External Entities Blowup',
    description: 'An attacker crafts XML with nested entity expansions (Billion Laughs) to cause denial of service.',
    severity: 'Medium',
    likelihood: 'Medium',
    relatedCWEs: ['CWE-611'],
  },
  'CAPEC-243': {
    capecId: 'CAPEC-243',
    name: 'XSS Targeting HTML Attributes',
    description: 'An attacker injects scripts via HTML attributes like event handlers (onclick, onerror).',
    severity: 'Medium',
    likelihood: 'High',
    relatedCWEs: ['CWE-79'],
  },
  'CAPEC-586': {
    capecId: 'CAPEC-586',
    name: 'Object Injection',
    description: 'An attacker exploits deserialization of untrusted data to inject malicious objects that execute arbitrary code or manipulate application logic.',
    severity: 'High',
    likelihood: 'Medium',
    relatedCWEs: ['CWE-502', 'CWE-843'],
  },
  'CAPEC-664': {
    capecId: 'CAPEC-664',
    name: 'Server Side Request Forgery',
    description: 'An attacker induces the server to make HTTP requests to an attacker-controlled or internal destination.',
    severity: 'High',
    likelihood: 'Medium',
    relatedCWEs: ['CWE-918'],
  },
};

// ─── Agent type to vuln_type mapping ────────────────────────────────────────

const AGENT_VULN_TYPE_MAP: Record<string, string> = {
  'ssrf-hunter': 'ssrf',
  'xss-hunter': 'xss',
  'sqli-hunter': 'sqli',
  'cors-hunter': 'cors',
  'graphql-hunter': 'sqli',
  'idor-hunter': 'idor',
  'ssti-hunter': 'ssti',
  'xxe-hunter': 'xxe',
  'command-injection-hunter': 'command_injection',
  'path-traversal-hunter': 'path_traversal',
  'oauth_hunter': 'open_redirect',
  'open-redirect-hunter': 'open_redirect',
  'host-header-hunter': 'host_header',
  'prototype-pollution-hunter': 'prototype_pollution',
  'subdomain-takeover-hunter': 'cors',
  'csrf-hunter': 'csrf',
  'deserialization-hunter': 'deserialization',
};

// ─── Rate limiting helper ───────────────────────────────────────────────────

/** Simple sleep-based throttle for API calls */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Rate limiter state for NVD API.
 * - With API key: 50 requests per 30 seconds
 * - Without API key: 5 requests per 30 seconds
 */
interface RateLimiter {
  windowStart: number;
  requestCount: number;
  maxPerWindow: number;
  windowMs: number;
}

function createRateLimiter(hasApiKey: boolean): RateLimiter {
  return {
    windowStart: Date.now(),
    requestCount: 0,
    maxPerWindow: hasApiKey ? 50 : 5,
    windowMs: 30_000,
  };
}

async function throttle(limiter: RateLimiter): Promise<void> {
  const now = Date.now();
  const elapsed = now - limiter.windowStart;

  if (elapsed >= limiter.windowMs) {
    // Window expired, reset
    limiter.windowStart = now;
    limiter.requestCount = 0;
  }

  if (limiter.requestCount >= limiter.maxPerWindow) {
    // Wait for window to expire
    const waitMs = limiter.windowMs - elapsed + 100;
    await sleep(waitMs);
    limiter.windowStart = Date.now();
    limiter.requestCount = 0;
  }

  limiter.requestCount++;
}

// ─── Database schema ────────────────────────────────────────────────────────

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS vuln_cves (
  cve_id TEXT PRIMARY KEY,
  description TEXT NOT NULL,
  published_date TEXT NOT NULL,
  last_modified_date TEXT NOT NULL,
  cvss_v31_score REAL,
  cvss_v31_severity TEXT,
  cvss_v31_vector TEXT,
  cwe_ids TEXT NOT NULL DEFAULT '[]',
  reference_urls TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS vuln_kev (
  cve_id TEXT PRIMARY KEY,
  vendor_project TEXT NOT NULL,
  product TEXT NOT NULL,
  vulnerability_name TEXT NOT NULL,
  date_added TEXT NOT NULL,
  short_description TEXT NOT NULL,
  required_action TEXT NOT NULL,
  due_date TEXT NOT NULL,
  known_ransomware_use TEXT NOT NULL DEFAULT 'Unknown'
);

CREATE TABLE IF NOT EXISTS vuln_github_advisories (
  ghsa_id TEXT PRIMARY KEY,
  cve_id TEXT,
  summary TEXT NOT NULL,
  description TEXT NOT NULL,
  severity TEXT NOT NULL,
  published_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  ecosystem TEXT,
  vulnerable_package TEXT,
  reference_urls TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS vuln_sync_metadata (
  source TEXT PRIMARY KEY,
  last_sync_time TEXT NOT NULL,
  records_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_cves_severity ON vuln_cves(cvss_v31_severity);
CREATE INDEX IF NOT EXISTS idx_cves_published ON vuln_cves(published_date);
CREATE INDEX IF NOT EXISTS idx_cves_cwe ON vuln_cves(cwe_ids);
CREATE INDEX IF NOT EXISTS idx_kev_date_added ON vuln_kev(date_added);
CREATE INDEX IF NOT EXISTS idx_advisories_severity ON vuln_github_advisories(severity);
CREATE INDEX IF NOT EXISTS idx_advisories_ecosystem ON vuln_github_advisories(ecosystem);
CREATE INDEX IF NOT EXISTS idx_advisories_cve ON vuln_github_advisories(cve_id);
`;

// ─── VulnDatabase class ────────────────────────────────────────────────────

export class VulnDatabase {
  private readonly dbPath: string;
  private initialized: boolean = false;

  constructor(dbPath: string) {
    this.dbPath = dbPath;
  }

  // ── Initialization ──────────────────────────────────────────────────────

  /** Initialize the database schema. Idempotent. */
  async initialize(): Promise<void> {
    if (this.initialized) return;
    await initKnowledgeDb(this.dbPath);
    // Execute each statement separately (SQLite doesn't support multi-statement in one call)
    const statements = SCHEMA_SQL
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0);
    for (const stmt of statements) {
      await knowledgeDbExecute(this.dbPath, stmt + ';');
    }
    this.initialized = true;
  }

  /** Ensure DB is initialized before any operation */
  private async ensureInit(): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }
  }

  // ── Sync Metadata ───────────────────────────────────────────────────────

  /** Get the last sync time for a data source */
  async getLastSyncTime(source: string): Promise<Date | null> {
    await this.ensureInit();
    const result = await knowledgeDbQuery(
      this.dbPath,
      'SELECT last_sync_time FROM vuln_sync_metadata WHERE source = ?;',
      [source],
    );
    if (result.rows.length === 0) return null;
    const row = result.rows[0] as { last_sync_time: string };
    return new Date(row.last_sync_time);
  }

  /** Update the sync metadata for a source */
  private async updateSyncMetadata(source: string, count: number): Promise<void> {
    await knowledgeDbExecute(
      this.dbPath,
      'INSERT OR REPLACE INTO vuln_sync_metadata (source, last_sync_time, records_count) VALUES (?, ?, ?);',
      [source, new Date().toISOString(), String(count)],
    );
  }

  // ═══════════════════════════════════════════════════════════════════════
  // NVD / CVE API
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Sync recent CVEs from the NVD API.
   *
   * Uses `lastModStartDate` and `lastModEndDate` params in ISO-8601 format.
   * The NVD API enforces a max 120-day range per request.
   *
   * @param options.apiKey  Optional NVD API key for higher rate limits
   * @param options.daysBack  Number of days to look back (default: 30, max: 120)
   * @param options.onProgress  Progress callback
   */
  async syncNVD(options?: NVDSyncOptions): Promise<number> {
    await this.ensureInit();

    const apiKey = options?.apiKey;
    const daysBack = Math.min(options?.daysBack ?? 30, 120);
    const onProgress = options?.onProgress;

    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - daysBack);

    const lastModStartDate = startDate.toISOString().replace(/\.\d+Z$/, '.000');
    const lastModEndDate = endDate.toISOString().replace(/\.\d+Z$/, '.000');

    const limiter = createRateLimiter(!!apiKey);
    let totalInserted = 0;
    let startIndex = 0;
    let totalResults = 1; // Will be updated after first fetch

    while (startIndex < totalResults) {
      await throttle(limiter);

      const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
      url.searchParams.set('lastModStartDate', lastModStartDate);
      url.searchParams.set('lastModEndDate', lastModEndDate);
      url.searchParams.set('startIndex', String(startIndex));
      url.searchParams.set('resultsPerPage', '100');

      const headers: Record<string, string> = {
        'Accept': 'application/json',
      };
      if (apiKey) {
        headers['apiKey'] = apiKey;
      }

      let response: { status: number; statusText: string; headers: Record<string, string>; body: string };
      try {
        response = await tauriFetch(url.toString(), { method: 'GET', headers });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        throw new Error(`NVD API request failed: ${message}`);
      }

      if (response.status < 200 || response.status >= 300) {
        throw new Error(`NVD API returned ${response.status}: ${response.statusText}`);
      }

      const data = JSON.parse(response.body) as NVDResponse;
      totalResults = data.totalResults;

      for (const vuln of data.vulnerabilities) {
        await this.upsertCVE(vuln);
        totalInserted++;
      }

      startIndex += data.resultsPerPage;

      if (onProgress) {
        onProgress(
          Math.min(startIndex, totalResults),
          totalResults,
          `Syncing NVD CVEs: ${Math.min(startIndex, totalResults)}/${totalResults}`,
        );
      }
    }

    await this.updateSyncMetadata('nvd', totalInserted);
    return totalInserted;
  }

  /** Upsert a single CVE record from the NVD API response */
  private async upsertCVE(vuln: NVDVulnerability): Promise<void> {
    const cve = vuln.cve;
    const enDesc = cve.descriptions.find(d => d.lang === 'en');
    const description = enDesc?.value ?? cve.descriptions[0]?.value ?? '';

    const cvssMetric = cve.metrics?.cvssMetricV31?.[0];
    const cvssScore = cvssMetric?.cvssData.baseScore ?? null;
    const cvssSeverity = cvssMetric?.cvssData.baseSeverity ?? null;
    const cvssVector = cvssMetric?.cvssData.vectorString ?? null;

    const cweIds: string[] = [];
    if (cve.weaknesses) {
      for (const weakness of cve.weaknesses) {
        for (const desc of weakness.description) {
          if (desc.value && desc.value !== 'NVD-CWE-Other' && desc.value !== 'NVD-CWE-noinfo') {
            cweIds.push(desc.value);
          }
        }
      }
    }

    const references: string[] = [];
    if (cve.references) {
      for (const ref of cve.references) {
        references.push(ref.url);
      }
    }

    await knowledgeDbExecute(
      this.dbPath,
      `INSERT OR REPLACE INTO vuln_cves
        (cve_id, description, published_date, last_modified_date,
         cvss_v31_score, cvss_v31_severity, cvss_v31_vector, cwe_ids, reference_urls)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`,
      [
        cve.id,
        description,
        cve.published,
        cve.lastModified,
        cvssScore !== null ? String(cvssScore) : '',
        cvssSeverity ?? '',
        cvssVector ?? '',
        JSON.stringify(cweIds),
        JSON.stringify(references),
      ],
    );
  }

  /** Search local CVE database by keyword */
  async searchCVE(query: string): Promise<CVERecord[]> {
    await this.ensureInit();
    const result = await knowledgeDbQuery(
      this.dbPath,
      `SELECT * FROM vuln_cves
       WHERE cve_id LIKE ? OR description LIKE ?
       ORDER BY published_date DESC
       LIMIT 100;`,
      [`%${query}%`, `%${query}%`],
    );
    return result.rows.map(row => this.rowToCVE(row));
  }

  /** Get CVEs associated with a specific CWE */
  async getCVEsByCWE(cweId: string): Promise<CVERecord[]> {
    await this.ensureInit();
    // cwe_ids is stored as a JSON array string; use LIKE for substring match
    const result = await knowledgeDbQuery(
      this.dbPath,
      `SELECT * FROM vuln_cves
       WHERE cwe_ids LIKE ?
       ORDER BY published_date DESC
       LIMIT 100;`,
      [`%"${cweId}"%`],
    );
    return result.rows.map(row => this.rowToCVE(row));
  }

  /** Get CVEs filtered by CVSS v3.1 severity */
  async getCVEsBySeverity(severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'): Promise<CVERecord[]> {
    await this.ensureInit();
    const result = await knowledgeDbQuery(
      this.dbPath,
      `SELECT * FROM vuln_cves
       WHERE cvss_v31_severity = ?
       ORDER BY published_date DESC
       LIMIT 200;`,
      [severity],
    );
    return result.rows.map(row => this.rowToCVE(row));
  }

  /** Convert a raw DB row to a CVERecord */
  private rowToCVE(row: Record<string, unknown>): CVERecord {
    return {
      cveId: row['cve_id'] as string,
      description: row['description'] as string,
      publishedDate: row['published_date'] as string,
      lastModifiedDate: row['last_modified_date'] as string,
      cvssV31Score: row['cvss_v31_score'] ? Number(row['cvss_v31_score']) : null,
      cvssV31Severity: (row['cvss_v31_severity'] as string) || null,
      cvssV31Vector: (row['cvss_v31_vector'] as string) || null,
      cweIds: this.parseJsonArray(row['cwe_ids'] as string),
      references: this.parseJsonArray(row['reference_urls'] as string),
    };
  }

  // ═══════════════════════════════════════════════════════════════════════
  // CISA KEV
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Download and upsert the full CISA KEV catalog.
   * The KEV is a single JSON file, so we always fetch the complete catalog.
   */
  async syncKEV(onProgress?: SyncProgressCallback): Promise<number> {
    await this.ensureInit();

    const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

    let response: { status: number; statusText: string; headers: Record<string, string>; body: string };
    try {
      response = await tauriFetch(url, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`CISA KEV fetch failed: ${message}`);
    }

    if (response.status < 200 || response.status >= 300) {
      throw new Error(`CISA KEV returned ${response.status}: ${response.statusText}`);
    }

    const data = JSON.parse(response.body) as CISAKEVResponse;
    const total = data.vulnerabilities.length;

    for (let i = 0; i < total; i++) {
      const v = data.vulnerabilities[i];
      await knowledgeDbExecute(
        this.dbPath,
        `INSERT OR REPLACE INTO vuln_kev
          (cve_id, vendor_project, product, vulnerability_name,
           date_added, short_description, required_action, due_date,
           known_ransomware_use)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`,
        [
          v.cveID,
          v.vendorProject,
          v.product,
          v.vulnerabilityName,
          v.dateAdded,
          v.shortDescription,
          v.requiredAction,
          v.dueDate,
          v.knownRansomwareCampaignUse,
        ],
      );

      if (onProgress && (i % 50 === 0 || i === total - 1)) {
        onProgress(i + 1, total, `Syncing CISA KEV: ${i + 1}/${total}`);
      }
    }

    await this.updateSyncMetadata('kev', total);
    return total;
  }

  /** Get all KEV entries from local DB */
  async getKEVEntries(): Promise<KEVEntry[]> {
    await this.ensureInit();
    const result = await knowledgeDbQuery(
      this.dbPath,
      'SELECT * FROM vuln_kev ORDER BY date_added DESC;',
    );
    return result.rows.map(row => this.rowToKEV(row));
  }

  /** Check if a CVE is in the CISA KEV catalog */
  async isInKEV(cveId: string): Promise<boolean> {
    await this.ensureInit();
    const result = await knowledgeDbQuery(
      this.dbPath,
      'SELECT 1 FROM vuln_kev WHERE cve_id = ? LIMIT 1;',
      [cveId],
    );
    return result.rows.length > 0;
  }

  /** Convert a raw DB row to a KEVEntry */
  private rowToKEV(row: Record<string, unknown>): KEVEntry {
    return {
      cveId: row['cve_id'] as string,
      vendorProject: row['vendor_project'] as string,
      product: row['product'] as string,
      vulnerabilityName: row['vulnerability_name'] as string,
      dateAdded: row['date_added'] as string,
      shortDescription: row['short_description'] as string,
      requiredAction: row['required_action'] as string,
      dueDate: row['due_date'] as string,
      knownRansomwareCampaignUse: row['known_ransomware_use'] as string,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════
  // GitHub Advisory Database
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Fetch advisories from the GitHub Advisory Database API.
   * Uses cursor-based pagination with per_page param.
   *
   * @param options.ecosystem  Filter by ecosystem (e.g. 'npm', 'pip', 'go')
   * @param options.severity   Filter by severity (e.g. 'critical', 'high')
   * @param options.onProgress Progress callback
   */
  async syncGitHubAdvisories(options?: GitHubAdvisorySyncOptions): Promise<number> {
    await this.ensureInit();

    const onProgress = options?.onProgress;
    let totalInserted = 0;
    let cursor: string | undefined;
    let hasMore = true;
    let pageNum = 0;

    while (hasMore) {
      const url = new URL('https://api.github.com/advisories');
      url.searchParams.set('per_page', '100');

      if (options?.ecosystem) {
        url.searchParams.set('ecosystem', options.ecosystem);
      }
      if (options?.severity) {
        url.searchParams.set('severity', options.severity);
      }
      if (cursor) {
        url.searchParams.set('after', cursor);
      }

      let response: { status: number; statusText: string; headers: Record<string, string>; body: string };
      try {
        response = await tauriFetch(url.toString(), {
          method: 'GET',
          headers: {
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
          },
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        throw new Error(`GitHub Advisory API request failed: ${message}`);
      }

      if (response.status < 200 || response.status >= 300) {
        // GitHub API rate limit: don't throw on 403, just stop
        if (response.status === 403) {
          break;
        }
        throw new Error(`GitHub Advisory API returned ${response.status}: ${response.statusText}`);
      }

      const advisories = JSON.parse(response.body) as GitHubAdvisoryAPIItem[];

      if (advisories.length === 0) {
        hasMore = false;
        break;
      }

      for (const adv of advisories) {
        await this.upsertGitHubAdvisory(adv);
        totalInserted++;
      }

      // Cursor-based pagination: use the ghsa_id of the last item
      cursor = advisories[advisories.length - 1].ghsa_id;
      pageNum++;

      // GitHub API returns fewer than per_page when there are no more
      if (advisories.length < 100) {
        hasMore = false;
      }

      // Safety: cap at 10 pages to avoid runaway syncs
      if (pageNum >= 10) {
        hasMore = false;
      }

      if (onProgress) {
        onProgress(
          totalInserted,
          totalInserted + (hasMore ? 100 : 0),
          `Syncing GitHub advisories: ${totalInserted} fetched (page ${pageNum})`,
        );
      }

      // Basic rate limiting for GitHub API (unauthenticated: 60 req/hr)
      await sleep(1000);
    }

    await this.updateSyncMetadata('github_advisories', totalInserted);
    return totalInserted;
  }

  /** Upsert a single GitHub advisory */
  private async upsertGitHubAdvisory(adv: GitHubAdvisoryAPIItem): Promise<void> {
    const firstVuln = adv.vulnerabilities?.[0];
    const ecosystem = firstVuln?.package?.ecosystem ?? null;
    const vulnerablePackage = firstVuln?.package?.name ?? null;

    const references: string[] = [];
    if (adv.references) {
      for (const ref of adv.references) {
        references.push(ref.url);
      }
    }
    if (adv.html_url) {
      references.push(adv.html_url);
    }

    await knowledgeDbExecute(
      this.dbPath,
      `INSERT OR REPLACE INTO vuln_github_advisories
        (ghsa_id, cve_id, summary, description, severity,
         published_at, updated_at, ecosystem, vulnerable_package,
         reference_urls)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
      [
        adv.ghsa_id,
        adv.cve_id ?? '',
        adv.summary,
        adv.description,
        adv.severity,
        adv.published_at,
        adv.updated_at,
        ecosystem ?? '',
        vulnerablePackage ?? '',
        JSON.stringify(references),
      ],
    );
  }

  /** Search local GitHub advisories by keyword */
  async searchAdvisories(query: string): Promise<GitHubAdvisory[]> {
    await this.ensureInit();
    const result = await knowledgeDbQuery(
      this.dbPath,
      `SELECT * FROM vuln_github_advisories
       WHERE summary LIKE ? OR description LIKE ? OR cve_id LIKE ?
       ORDER BY published_at DESC
       LIMIT 100;`,
      [`%${query}%`, `%${query}%`, `%${query}%`],
    );
    return result.rows.map(row => this.rowToAdvisory(row));
  }

  /** Convert a raw DB row to a GitHubAdvisory */
  private rowToAdvisory(row: Record<string, unknown>): GitHubAdvisory {
    return {
      ghsaId: row['ghsa_id'] as string,
      cveId: (row['cve_id'] as string) || null,
      summary: row['summary'] as string,
      description: row['description'] as string,
      severity: row['severity'] as string,
      publishedAt: row['published_at'] as string,
      updatedAt: row['updated_at'] as string,
      ecosystem: (row['ecosystem'] as string) || null,
      vulnerablePackage: (row['vulnerable_package'] as string) || null,
      references: this.parseJsonArray(row['reference_urls'] as string),
    };
  }

  // ═══════════════════════════════════════════════════════════════════════
  // CWE Mapping (bundled data)
  // ═══════════════════════════════════════════════════════════════════════

  /** Get CWE information by ID (e.g. 'CWE-79') */
  getCWEInfo(cweId: string): CWEInfo | null {
    const normalized = cweId.startsWith('CWE-') ? cweId : `CWE-${cweId}`;
    return CWE_CATALOG[normalized] ?? null;
  }

  /** Get related (parent + child) CWEs */
  getRelatedCWEs(cweId: string): CWEInfo[] {
    const normalized = cweId.startsWith('CWE-') ? cweId : `CWE-${cweId}`;
    const info = CWE_CATALOG[normalized];
    if (!info) return [];

    const related: CWEInfo[] = [];
    for (const parentId of info.parentCWEs) {
      const parent = CWE_CATALOG[parentId];
      if (parent) related.push(parent);
    }
    for (const childId of info.childCWEs) {
      const child = CWE_CATALOG[childId];
      if (child) related.push(child);
    }
    return related;
  }

  /** Map an agent vulnerability type to relevant CWEs */
  getCWEsForVulnType(vulnType: string): CWEInfo[] {
    const cweIds = VULN_TYPE_CWE_MAP[vulnType];
    if (!cweIds) return [];

    const results: CWEInfo[] = [];
    for (const cweId of cweIds) {
      const info = CWE_CATALOG[cweId];
      if (info) results.push(info);
    }
    return results;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // CAPEC Attack Patterns (bundled data)
  // ═══════════════════════════════════════════════════════════════════════

  /** Get a specific CAPEC attack pattern by ID */
  getAttackPattern(capecId: string): AttackPattern | null {
    const normalized = capecId.startsWith('CAPEC-') ? capecId : `CAPEC-${capecId}`;
    return CAPEC_CATALOG[normalized] ?? null;
  }

  /** Get all CAPEC attack patterns related to a CWE */
  getAttackPatternsForCWE(cweId: string): AttackPattern[] {
    const normalized = cweId.startsWith('CWE-') ? cweId : `CWE-${cweId}`;
    const cweInfo = CWE_CATALOG[normalized];
    if (!cweInfo) return [];

    const patterns: AttackPattern[] = [];
    for (const capecId of cweInfo.relatedAttackPatterns) {
      const pattern = CAPEC_CATALOG[capecId];
      if (pattern) patterns.push(pattern);
    }
    return patterns;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Cross-source Queries
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Get combined vulnerability context for a vulnerability type.
   * Gathers CWE info, related attack patterns, recent CVEs, and KEV entries.
   */
  async getVulnContext(vulnType: string, _target?: string): Promise<VulnContext> {
    await this.ensureInit();

    const cweIds = VULN_TYPE_CWE_MAP[vulnType] ?? [];
    const cweInfo: CWEInfo[] = [];
    const attackPatterns: AttackPattern[] = [];
    const recentCVEs: CVERecord[] = [];
    const kevEntries: KEVEntry[] = [];

    // Gather CWE info and attack patterns
    for (const cweId of cweIds) {
      const info = CWE_CATALOG[cweId];
      if (info) {
        cweInfo.push(info);
        for (const capecId of info.relatedAttackPatterns) {
          const pattern = CAPEC_CATALOG[capecId];
          if (pattern && !attackPatterns.some(p => p.capecId === pattern.capecId)) {
            attackPatterns.push(pattern);
          }
        }
      }
    }

    // Gather CVEs from local DB for each CWE
    for (const cweId of cweIds) {
      const cves = await this.getCVEsByCWE(cweId);
      for (const cve of cves) {
        if (!recentCVEs.some(r => r.cveId === cve.cveId)) {
          recentCVEs.push(cve);
        }
      }
    }

    // Check which of those CVEs are in the KEV
    for (const cve of recentCVEs) {
      const kevResult = await knowledgeDbQuery(
        this.dbPath,
        'SELECT * FROM vuln_kev WHERE cve_id = ? LIMIT 1;',
        [cve.cveId],
      );
      if (kevResult.rows.length > 0) {
        kevEntries.push(this.rowToKEV(kevResult.rows[0]));
      }
    }

    return {
      vulnType,
      cweIds,
      recentCVEs: recentCVEs.slice(0, 50), // Cap for performance
      attackPatterns,
      kevEntries,
      cweInfo,
    };
  }

  /**
   * Get exploitability information for a specific CVE.
   * Checks KEV status, CVSS score, and exploit references.
   */
  async getExploitability(cveId: string): Promise<ExploitabilityInfo> {
    await this.ensureInit();

    // Check CVE data
    const cveResult = await knowledgeDbQuery(
      this.dbPath,
      'SELECT * FROM vuln_cves WHERE cve_id = ? LIMIT 1;',
      [cveId],
    );

    let cvssScore: number | null = null;
    let cvssSeverity: string | null = null;
    let exploitReferences: string[] = [];

    if (cveResult.rows.length > 0) {
      const cve = this.rowToCVE(cveResult.rows[0]);
      cvssScore = cve.cvssV31Score;
      cvssSeverity = cve.cvssV31Severity;
      // Filter references for known exploit sources
      exploitReferences = cve.references.filter(
        ref =>
          ref.includes('exploit-db.com') ||
          ref.includes('packetstormsecurity.com') ||
          ref.includes('github.com') ||
          ref.includes('exploit') ||
          ref.includes('poc') ||
          ref.includes('metasploit'),
      );
    }

    // Check KEV
    const kevResult = await knowledgeDbQuery(
      this.dbPath,
      'SELECT * FROM vuln_kev WHERE cve_id = ? LIMIT 1;',
      [cveId],
    );

    const inKEV = kevResult.rows.length > 0;
    let knownRansomwareUse = false;
    if (inKEV) {
      const kev = this.rowToKEV(kevResult.rows[0]);
      knownRansomwareUse = kev.knownRansomwareCampaignUse === 'Known';
    }

    return {
      cveId,
      inKEV,
      cvssScore,
      cvssSeverity,
      exploitReferences,
      knownRansomwareUse,
    };
  }

  /**
   * Get knowledge relevant for a specific agent hunting a specific target.
   * Maps the agent type to its vulnerability class, then gathers all
   * related CWEs, attack patterns, CVEs, and KEV entries.
   */
  async getRelevantKnowledge(agentType: string, target: string): Promise<AgentKnowledge> {
    await this.ensureInit();

    const vulnType = AGENT_VULN_TYPE_MAP[agentType] ?? agentType;
    const context = await this.getVulnContext(vulnType, target);

    // Also search advisories for the target hostname
    let targetHost = target;
    try {
      targetHost = new URL(target.startsWith('http') ? target : `https://${target}`).hostname;
    } catch {
      // Keep as-is
    }

    // Search local advisories for the target
    const advisoryResults = await this.searchAdvisories(targetHost);

    // Enrich CVE list with any CVEs found in advisories
    for (const adv of advisoryResults) {
      if (adv.cveId) {
        const cveResult = await knowledgeDbQuery(
          this.dbPath,
          'SELECT * FROM vuln_cves WHERE cve_id = ? LIMIT 1;',
          [adv.cveId],
        );
        if (cveResult.rows.length > 0) {
          const cve = this.rowToCVE(cveResult.rows[0]);
          if (!context.recentCVEs.some(c => c.cveId === cve.cveId)) {
            context.recentCVEs.push(cve);
          }
        }
      }
    }

    return {
      vulnType,
      agentType,
      target,
      cweInfo: context.cweInfo,
      attackPatterns: context.attackPatterns,
      relevantCVEs: context.recentCVEs,
      kevEntries: context.kevEntries,
    };
  }

  // ── Utility ─────────────────────────────────────────────────────────────

  /** Safely parse a JSON array string, returning empty array on failure */
  private parseJsonArray(value: string): string[] {
    if (!value) return [];
    try {
      const parsed: unknown = JSON.parse(value);
      if (Array.isArray(parsed)) {
        return parsed.filter((item): item is string => typeof item === 'string');
      }
      return [];
    } catch {
      return [];
    }
  }
}

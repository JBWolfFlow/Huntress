/**
 * JavaScript Static Analysis Engine (Phase 20B)
 *
 * Extracts API endpoints, secrets, and internal URLs from JavaScript files.
 * Runs against scripts discovered by the web crawler.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface JSAnalysisResult {
  endpoints: Array<{ url: string; method?: string; source: string }>;
  secrets: Array<{ type: string; value: string; file: string; line?: number }>;
  internalUrls: string[];
  comments: string[];
}

// ─── Secret Patterns ────────────────────────────────────────────────────────

const SECRET_PATTERNS: Array<{ type: string; pattern: RegExp; contextRequired?: RegExp }> = [
  { type: 'aws_access_key', pattern: /AKIA[0-9A-Z]{16}/g },
  { type: 'aws_secret_key', pattern: /(?:aws|secret)[_\s]*(?:key|access)[^"'`\s]{0,10}["'`]\s*[:=]\s*["'`]([0-9a-zA-Z/+=]{40})["'`]/gi },
  { type: 'google_api_key', pattern: /AIza[0-9A-Za-z_-]{35}/g },
  { type: 'stripe_secret', pattern: /sk_live_[0-9a-zA-Z]{24,}/g },
  { type: 'stripe_publishable', pattern: /pk_live_[0-9a-zA-Z]{24,}/g },
  { type: 'jwt_token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { type: 'private_key', pattern: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g },
  { type: 'github_token', pattern: /gh[ps]_[A-Za-z0-9_]{36,}/g },
  { type: 'slack_token', pattern: /xox[bpoas]-[0-9]+-[0-9]+-[A-Za-z0-9]+/g },
  { type: 'generic_api_key', pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9_-]{16,}['"]/gi },
  { type: 'firebase_config', pattern: /firebaseConfig\s*=\s*\{[^}]*apiKey\s*:\s*["'][^"']+["']/gi },
  { type: 'mailgun_key', pattern: /key-[0-9a-zA-Z]{32}/g },
  { type: 'twilio_sid', pattern: /AC[a-z0-9]{32}/g },
  { type: 'sendgrid_key', pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g },
  { type: 'heroku_api', pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g, contextRequired: /heroku/i },
];

// ─── Endpoint Patterns ──────────────────────────────────────────────────────

const ENDPOINT_PATTERNS: RegExp[] = [
  /fetch\s*\(\s*['"`]([^'"`\s]+)['"`]/g,
  /\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`\s]+)['"`]/g,
  /(?:url|endpoint|api|path|href|baseUrl|baseURL)\s*[:=]\s*['"`](\/[^'"`\s]+)['"`]/gi,
  /['"`](\/api\/[^'"`\s]+)['"`]/g,
  /['"`](\/v[0-9]+\/[^'"`\s]+)['"`]/g,
  /['"`](\/graphql[^'"`\s]*)['"`]/gi,
  /['"`](\/rest\/[^'"`\s]+)['"`]/g,
  /XMLHttpRequest[^;]*\.open\s*\(\s*['"](\w+)['"],\s*['"]([^'"]+)['"]/g,
  /axios\s*[\.(]\s*['"`]([^'"`\s]+)['"`]/g,
];

// ─── Internal URL Patterns ──────────────────────────────────────────────────

const INTERNAL_URL_PATTERNS: RegExp[] = [
  /['"`](https?:\/\/(?:localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^'"`\s]*)['"`]/g,
  /['"`](https?:\/\/[^'"`\s]*\.internal[^'"`\s]*)['"`]/g,
  /['"`](https?:\/\/[^'"`\s]*\.local[^'"`\s]*)['"`]/g,
  /['"`](https?:\/\/[^'"`\s]*staging[^'"`\s]*)['"`]/g,
  /['"`](https?:\/\/[^'"`\s]*\.dev\.[^'"`\s]*)['"`]/g,
];

// ─── Comment Extraction ─────────────────────────────────────────────────────

const SECURITY_COMMENT_PATTERNS: RegExp[] = [
  /\/\/\s*(TODO|FIXME|HACK|XXX|BUG|SECURITY|VULN|WARNING|DEPRECATED)[\s:].{10,150}/gi,
  /\/\*\s*(TODO|FIXME|HACK|XXX|BUG|SECURITY|VULN|WARNING|DEPRECATED)[\s:][\s\S]{10,300}?\*\//gi,
  /\/\/\s*(password|secret|token|credential|auth|admin|bypass|disable|unsafe|insecure|temporary|hardcoded).{5,150}/gi,
];

// ─── JSAnalyzer ─────────────────────────────────────────────────────────────

export class JSAnalyzer {
  async analyzeScript(url: string, content: string): Promise<JSAnalysisResult> {
    const endpoints = this.extractEndpoints(content, url);
    const secrets = this.extractSecrets(content, url);
    const internalUrls = this.extractInternalUrls(content);
    const comments = this.extractSecurityComments(content);

    return { endpoints, secrets, internalUrls, comments };
  }

  async analyzeScripts(scripts: Array<{ url: string; content?: string }>): Promise<JSAnalysisResult> {
    const combined: JSAnalysisResult = {
      endpoints: [],
      secrets: [],
      internalUrls: [],
      comments: [],
    };

    for (const script of scripts) {
      if (!script.content) continue;
      const result = await this.analyzeScript(script.url, script.content);
      combined.endpoints.push(...result.endpoints);
      combined.secrets.push(...result.secrets);
      combined.internalUrls.push(...result.internalUrls);
      combined.comments.push(...result.comments);
    }

    // Deduplicate
    combined.endpoints = this.deduplicateEndpoints(combined.endpoints);
    combined.secrets = this.deduplicateSecrets(combined.secrets);
    combined.internalUrls = [...new Set(combined.internalUrls)];
    combined.comments = [...new Set(combined.comments)];

    return combined;
  }

  private extractEndpoints(content: string, sourceFile: string): Array<{ url: string; method?: string; source: string }> {
    const endpoints: Array<{ url: string; method?: string; source: string }> = [];

    for (const pattern of ENDPOINT_PATTERNS) {
      // Reset lastIndex for global patterns
      pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(content)) !== null) {
        // XMLHttpRequest has method and url in different groups
        if (match.length > 2) {
          endpoints.push({ url: match[2], method: match[1].toUpperCase(), source: sourceFile });
        } else {
          const url = match[1];
          // Skip obvious non-endpoints
          if (url.length < 3 || url.startsWith('data:') || url.startsWith('blob:')) continue;
          // Detect method from context
          const method = this.inferMethod(content, match.index);
          endpoints.push({ url, method, source: sourceFile });
        }
      }
    }

    return endpoints;
  }

  private extractSecrets(content: string, sourceFile: string): Array<{ type: string; value: string; file: string; line?: number }> {
    const secrets: Array<{ type: string; value: string; file: string; line?: number }> = [];

    for (const { type, pattern, contextRequired } of SECRET_PATTERNS) {
      pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(content)) !== null) {
        // If context is required, check surrounding text
        if (contextRequired) {
          const surroundingStart = Math.max(0, match.index - 200);
          const surroundingEnd = Math.min(content.length, match.index + match[0].length + 200);
          const surrounding = content.substring(surroundingStart, surroundingEnd);
          if (!contextRequired.test(surrounding)) continue;
        }

        const value = match[1] ?? match[0];
        // Skip common false positives
        if (value.length > 200) continue;
        if (/^[0-9]+$/.test(value)) continue;
        if (/example|test|placeholder|dummy|sample|your[_-]?key/i.test(value)) continue;

        const line = content.substring(0, match.index).split('\n').length;
        secrets.push({ type, value: value.substring(0, 100), file: sourceFile, line });
      }
    }

    return secrets;
  }

  private extractInternalUrls(content: string): string[] {
    const urls: string[] = [];
    for (const pattern of INTERNAL_URL_PATTERNS) {
      pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(content)) !== null) {
        urls.push(match[1]);
      }
    }
    return urls;
  }

  private extractSecurityComments(content: string): string[] {
    const comments: string[] = [];
    for (const pattern of SECURITY_COMMENT_PATTERNS) {
      pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(content)) !== null) {
        comments.push(match[0].trim());
      }
    }
    return comments;
  }

  private inferMethod(content: string, matchIndex: number): string | undefined {
    const before = content.substring(Math.max(0, matchIndex - 50), matchIndex).toLowerCase();
    if (before.includes('.post') || before.includes('method: "post') || before.includes("method: 'post")) return 'POST';
    if (before.includes('.put') || before.includes('method: "put') || before.includes("method: 'put")) return 'PUT';
    if (before.includes('.delete') || before.includes('method: "delete')) return 'DELETE';
    if (before.includes('.patch') || before.includes('method: "patch')) return 'PATCH';
    if (before.includes('.get') || before.includes('fetch')) return 'GET';
    return undefined;
  }

  private deduplicateEndpoints(endpoints: Array<{ url: string; method?: string; source: string }>): Array<{ url: string; method?: string; source: string }> {
    const seen = new Set<string>();
    return endpoints.filter(ep => {
      const key = `${ep.method ?? ''}:${ep.url}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private deduplicateSecrets(secrets: Array<{ type: string; value: string; file: string; line?: number }>): Array<{ type: string; value: string; file: string; line?: number }> {
    const seen = new Set<string>();
    return secrets.filter(s => {
      const key = `${s.type}:${s.value}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}

export default JSAnalyzer;

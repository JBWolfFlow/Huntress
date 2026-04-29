/**
 * Report Templates (RQ2 — Session 13)
 *
 * Professional templates for vulnerability reports with HackerOne-standard sections:
 * - Summary + Vulnerability Details
 * - Prerequisites (what's needed to reproduce)
 * - Steps to Reproduce
 * - HTTP Evidence (structured request/response pairs)
 * - Expected vs Actual Behavior
 * - Proof of Concept
 * - Impact + Affected Scope
 * - Remediation
 */

export const REPORT_TEMPLATES: Record<string, string> = {
  open_redirect: `
# Open Redirect Vulnerability

## Summary
An open redirect vulnerability was discovered that allows attackers to redirect users to arbitrary external domains.

## Vulnerability Details
**URL:** {{url}}
**Parameter:** {{parameter}}
**Severity:** {{severity}}

## Prerequisites
- A web browser (any modern browser)
- No authentication required — this is exploitable by unauthenticated attackers

## Steps to Reproduce
{{steps}}

## HTTP Evidence
{{http_evidence}}

## Expected vs Actual Behavior
**Expected:** The application should validate redirect parameters against an allowlist of trusted domains and reject requests to external URLs.
**Actual:** The application performs an unvalidated redirect to the attacker-supplied URL, sending the user to an arbitrary external domain.

## Proof of Concept
{{poc}}

## Quick Reproduction
{{quick_reproduction}}

## Impact
This vulnerability can be exploited for phishing attacks by making malicious URLs appear to originate from a trusted domain.

## Affected Scope
All users who click a crafted link are affected. No authentication is required. The attack relies on social engineering — the trusted domain in the URL lends credibility to phishing campaigns.

## Remediation
- Implement whitelist-based redirect validation
- Use relative URLs for internal redirects
- Validate and sanitize all redirect parameters
  `,

  xss: `
# Cross-Site Scripting (XSS) Vulnerability

## Summary
A {{xss_type}} XSS vulnerability was identified that allows execution of arbitrary JavaScript in the context of the application.

## Vulnerability Details
**URL:** {{url}}
**Parameter:** {{parameter}}
**Payload:** {{payload}}
**Severity:** {{severity}}

## Prerequisites
- A modern web browser with JavaScript enabled (Chrome, Firefox, Safari, or Edge)
- For stored XSS: an account with permissions to submit content to the affected input
- For reflected XSS: ability to craft and deliver a URL to a victim

## Steps to Reproduce
{{steps}}

## HTTP Evidence
{{http_evidence}}

## Expected vs Actual Behavior
**Expected:** User input should be sanitized or encoded before being rendered in the DOM. The application should use context-appropriate output encoding and Content Security Policy headers to prevent script execution.
**Actual:** The payload is reflected/stored and rendered in the page without sanitization, causing the injected JavaScript to execute in the victim's browser context.

## Proof of Concept
{{poc}}

## Quick Reproduction
{{quick_reproduction}}

## Impact
- Session hijacking via document.cookie theft
- Credential theft through DOM manipulation
- Defacement of the application UI
- Malware distribution through injected content

## Affected Scope
All users who visit the affected page (reflected XSS: via crafted URL, stored XSS: all users viewing the affected content). Impacts any authenticated session — session tokens, CSRF tokens, and personal data are accessible to the attacker's script.

## Remediation
- Implement proper output encoding (HTML entity, JavaScript, URL encoding as appropriate)
- Deploy Content Security Policy (CSP) headers
- Sanitize user input using a proven library (e.g., DOMPurify)
- Use framework-provided XSS protection (React JSX auto-escaping, Angular sanitizer)
  `,

  sql_injection: `
# SQL Injection Vulnerability

## Summary
A SQL injection vulnerability was discovered that allows unauthorized database access and manipulation.

## Vulnerability Details
**URL:** {{url}}
**Parameter:** {{parameter}}
**Database:** {{database_type}}
**Severity:** CRITICAL

## Prerequisites
- HTTP client (curl, browser, or Burp Suite)
- No special authentication may be required depending on the endpoint
- Knowledge of SQL syntax for the target database type ({{database_type}})

## Steps to Reproduce
{{steps}}

## HTTP Evidence
{{http_evidence}}

## Expected vs Actual Behavior
**Expected:** User input should be passed through parameterized queries (prepared statements). The application should never concatenate user input directly into SQL strings. Error messages should be generic and not reveal database structure.
**Actual:** The user-supplied input is concatenated directly into the SQL query, allowing the attacker to modify query logic, extract data, or manipulate the database.

## Proof of Concept
{{poc}}

## Quick Reproduction
{{quick_reproduction}}

## Impact
- Unauthorized data access (full database read)
- Data modification or deletion
- Authentication bypass
- Potential remote code execution via stacked queries or database-specific functions

## Affected Scope
All users of the application are affected. The attacker can access, modify, or delete any data in the database, including other users' credentials, personal information, and application state. If the database user has elevated privileges, the impact extends to the host operating system.

## Remediation
- Use parameterized queries/prepared statements for all database operations
- Implement strict input validation with allowlists
- Apply principle of least privilege to database accounts
- Use an ORM framework that handles parameterization automatically
  `,

  idor: `
# Insecure Direct Object Reference (IDOR)

## Summary
An IDOR vulnerability allows unauthorized access to other users' resources by manipulating object identifiers.

## Vulnerability Details
**Endpoint:** {{endpoint}}
**Method:** {{method}}
**Vulnerable Parameter:** {{parameter}}
**Severity:** {{severity}}

## Prerequisites
- Two authenticated user accounts (User A and User B) to demonstrate cross-user data access
- HTTP client capable of modifying request parameters (curl, Burp Suite, or browser DevTools)

## Steps to Reproduce
{{steps}}

## HTTP Evidence
{{http_evidence}}

## Expected vs Actual Behavior
**Expected:** The application should verify that the requesting user is authorized to access the requested resource. Requests for another user's data should return 403 Forbidden.
**Actual:** The application returns the requested resource regardless of which user is making the request, allowing any authenticated user to access other users' data by changing the object identifier.

## Proof of Concept
{{poc}}

## Quick Reproduction
{{quick_reproduction}}

## Impact
- Unauthorized data access across user accounts
- Privacy violations — personal data exposure
- Potential account takeover if sensitive fields (email, password hash) are exposed
- Data breach affecting all users of the application

## Affected Scope
All authenticated users are affected. Any user can access any other user's resources by iterating or guessing resource identifiers. The blast radius depends on what data the endpoint exposes — profile data, financial records, messages, etc.

## Remediation
- Implement proper authorization checks on every resource access
- Use indirect reference maps (UUIDs instead of sequential IDs)
- Validate user permissions on every request at the server side
- Implement access control lists (ACLs) or role-based access control
  `,

  command_injection: `
# Command Injection Vulnerability

## Summary
A command injection vulnerability was discovered that allows execution of arbitrary operating system commands.

## Vulnerability Details
**URL:** {{url}}
**Parameter:** {{parameter}}
**Severity:** CRITICAL

## Prerequisites
- HTTP client (curl or similar)
- No special tools required — the vulnerability is exploitable via standard HTTP requests
- An out-of-band (OOB) listener may help confirm blind command injection (e.g., Burp Collaborator, interactsh)

## Steps to Reproduce
{{steps}}

## HTTP Evidence
{{http_evidence}}

## Expected vs Actual Behavior
**Expected:** User input should never be passed to OS command interpreters. If shell execution is necessary, the application should use parameterized APIs (e.g., execFile with argument arrays) and strict input validation.
**Actual:** The user input is concatenated into a shell command string and executed, allowing the attacker to inject additional commands using shell metacharacters (;, |, &&, $(), backticks).

## Proof of Concept
{{poc}}

## Quick Reproduction
{{quick_reproduction}}

## Impact
- Remote code execution on the server
- Full server compromise
- Data exfiltration from the host filesystem
- Lateral movement within the network
- Potential for persistent backdoor installation

## Affected Scope
All users and data on the affected server are at risk. The attacker gains the privileges of the web application's OS user, which may include access to databases, configuration files, and other services on the same host or network.

## Remediation
- Use parameterized APIs instead of shell commands (e.g., execFile instead of exec)
- Implement strict input validation with allowlisting of permitted characters
- Apply principle of least privilege to the application's OS user
- Use sandboxing/containerization to limit impact of command execution
  `,

  path_traversal: `
# Path Traversal / Local File Inclusion

## Summary
A path traversal vulnerability allows reading or writing arbitrary files outside the intended directory.

## Vulnerability Details
**URL:** {{url}}
**Parameter:** {{parameter}}
**Severity:** {{severity}}

## Prerequisites
- HTTP client (curl or browser)
- No authentication may be required depending on the endpoint
- Knowledge of target OS file paths (Linux: /etc/passwd, Windows: C:\\Windows\\win.ini)

## Steps to Reproduce
{{steps}}

## HTTP Evidence
{{http_evidence}}

## Expected vs Actual Behavior
**Expected:** The application should resolve the canonical path of the requested file and verify it falls within the allowed directory. Path traversal sequences (../) should be rejected or stripped before filesystem access.
**Actual:** The application uses the user-supplied path directly without canonicalization or containment checks, allowing the attacker to traverse to arbitrary directories using ../ sequences.

## Proof of Concept
{{poc}}

## Quick Reproduction
{{quick_reproduction}}

## Impact
- Sensitive file disclosure (e.g., /etc/passwd, configuration files, .env)
- Source code leakage revealing application internals
- Potential remote code execution via log poisoning or file upload chaining
- Credential theft from configuration or backup files

## Affected Scope
All server-side files readable by the web application's OS user are exposed. This typically includes application source code, configuration files with database credentials, and system files. If write access is also available, the impact escalates to remote code execution.

## Remediation
- Canonicalize paths and validate against an allowlist of permitted directories
- Use chroot or sandboxed file access
- Reject input containing path traversal sequences (../, ..\\ , %2e%2e, etc.)
- Implement proper access controls on file operations
  `,

  jwt: `
# JWT Authentication Bypass

## Summary
A vulnerability in JWT token handling allows authentication bypass or privilege escalation.

## Vulnerability Details
**Endpoint:** {{endpoint}}
**Attack Type:** {{attack_type}}
**Severity:** {{severity}}

## Prerequisites
- HTTP client capable of crafting custom headers (curl, Burp Suite)
- JWT decoder/encoder (jwt.io, python-jwt, or similar)
- A valid low-privilege JWT token (if testing privilege escalation)

## Steps to Reproduce
{{steps}}

## HTTP Evidence
{{http_evidence}}

## Expected vs Actual Behavior
**Expected:** The server should validate JWT signatures using a strong algorithm (RS256/ES256), reject tokens with "none" algorithm, verify token expiration, and validate all claims before granting access.
**Actual:** The server accepts the manipulated JWT token, granting unauthorized access or elevated privileges without proper signature validation.

## Proof of Concept
{{poc}}

## Quick Reproduction
{{quick_reproduction}}

## Impact
- Authentication bypass — access protected endpoints without valid credentials
- Privilege escalation — elevate from regular user to admin
- Account takeover — forge tokens for arbitrary users
- Unauthorized access to protected resources and APIs

## Affected Scope
All users and endpoints protected by JWT authentication are affected. If the "none" algorithm is accepted, any unauthenticated attacker can forge tokens. If key confusion is possible, any user can escalate to admin. The scope extends to all APIs and resources that rely on the compromised JWT validation.

## Remediation
- Validate JWT signatures using a secure algorithm (RS256/ES256)
- Explicitly reject tokens with "none" algorithm
- Implement proper key management — separate signing and verification keys
- Set appropriate token expiration times and validate them server-side
  `,

  cors: `
# CORS Misconfiguration

## Summary
A Cross-Origin Resource Sharing misconfiguration allows unauthorized cross-origin access to sensitive data.

## Vulnerability Details
**URL:** {{url}}
**Origin Tested:** {{origin}}
**Severity:** {{severity}}

## Prerequisites
- Web browser (for PoC HTML page) or curl
- Ability to host or load an HTML page on an attacker-controlled origin
- The victim must be authenticated to the target application (for impact)

## Steps to Reproduce
{{steps}}

## HTTP Evidence
{{http_evidence}}

## Expected vs Actual Behavior
**Expected:** The server should validate the Origin header against a strict allowlist and only set Access-Control-Allow-Origin for trusted domains. Wildcard (*) should never be used with credentials. Reflecting arbitrary Origin headers is insecure.
**Actual:** The server reflects the attacker's Origin in the Access-Control-Allow-Origin response header and sets Access-Control-Allow-Credentials: true, allowing cross-origin requests with cookies from any domain.

## Proof of Concept
{{poc}}

## Quick Reproduction
{{quick_reproduction}}

## Impact
- Cross-origin data theft — attacker's JavaScript can read authenticated responses
- Session hijacking — extract session tokens or CSRF tokens
- Unauthorized API access — perform actions on behalf of the victim
- Privacy violations — access personal data cross-origin

## Affected Scope
All authenticated users who visit an attacker-controlled page while logged into the target application. The attacker can read any data accessible to the victim's session and perform actions on their behalf.

## Remediation
- Implement strict origin allowlisting (never reflect arbitrary origins)
- Never use Access-Control-Allow-Origin: * with credentials
- Validate the Origin header against a server-side allowlist
- Set Access-Control-Allow-Credentials only for trusted origins
  `,

  crlf: `
# CRLF Injection / HTTP Response Splitting

## Summary
A CRLF injection vulnerability allows injecting arbitrary HTTP headers or splitting responses.

## Vulnerability Details
**URL:** {{url}}
**Parameter:** {{parameter}}
**Severity:** {{severity}}

## Prerequisites
- HTTP client (curl or browser)
- No authentication required
- URL encoding knowledge for CRLF characters (%0d%0a)

## Steps to Reproduce
{{steps}}

## HTTP Evidence
{{http_evidence}}

## Expected vs Actual Behavior
**Expected:** The application should strip or reject CR (\\r) and LF (\\n) characters from any user input that is reflected in HTTP response headers. Header values should be validated before being set.
**Actual:** The application includes user input containing CRLF sequences in response headers, allowing the attacker to inject additional headers or split the response.

## Proof of Concept
{{poc}}

## Quick Reproduction
{{quick_reproduction}}

## Impact
- HTTP response splitting — inject attacker-controlled content into responses
- Cache poisoning — poison CDN or proxy caches with malicious content
- XSS via injected headers (e.g., injecting Content-Type: text/html with script)
- Session fixation via Set-Cookie header injection

## Affected Scope
All users behind shared proxies or CDNs may receive poisoned cached responses. Direct CRLF injection affects the user whose request triggers the injection. Cache poisoning amplifies the impact to all users of the cached resource.

## Remediation
- Strip or encode CR (\\r) and LF (\\n) characters from all user input before including in headers
- Use framework-provided header setting functions that handle encoding
- Implement proper input validation for header values
  `,

  ssrf: `
# Server-Side Request Forgery (SSRF)

## Summary
An SSRF vulnerability allows attackers to make the server perform requests to arbitrary destinations, including internal network resources.

## Vulnerability Details
**URL:** {{url}}
**Parameter:** {{parameter}}
**Severity:** {{severity}}

## Prerequisites
- HTTP client (curl or browser)
- For cloud SSRF: knowledge of cloud metadata endpoints (169.254.169.254)
- For OOB confirmation: an external callback server (Burp Collaborator, interactsh, or webhook.site)

## Steps to Reproduce
{{steps}}

## HTTP Evidence
{{http_evidence}}

## Expected vs Actual Behavior
**Expected:** The application should validate URLs against an allowlist of permitted destinations, block requests to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x), and restrict allowed protocols (HTTP/HTTPS only).
**Actual:** The server fetches the attacker-supplied URL without restriction, allowing access to internal services, cloud metadata, and arbitrary external endpoints.

## Proof of Concept
{{poc}}

## Quick Reproduction
{{quick_reproduction}}

## Impact
- Internal network scanning and service enumeration
- Access to internal services not exposed to the internet (databases, admin panels)
- Cloud metadata access — retrieve IAM credentials, secrets, and configuration
- Potential remote code execution through internal service exploitation

## Affected Scope
The impact extends beyond the vulnerable application to the entire internal network reachable from the server. In cloud environments, IAM credentials from the metadata service can compromise the entire cloud account. All internal services accessible from the application server are at risk.

## Remediation
- Implement URL allowlisting for outbound requests
- Block requests to private/internal IP ranges and localhost
- Disable unnecessary URL protocols (file://, gopher://, dict://)
- Use network segmentation to limit the server's internal access
  `,
};

export function fillTemplate(template: string, data: Record<string, string>): string {
  let filled = template;

  for (const [key, value] of Object.entries(data)) {
    const placeholder = `{{${key}}}`;
    filled = filled.replace(new RegExp(placeholder.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), value);
  }

  // Remove any remaining unfilled placeholders (e.g., optional sections not provided)
  filled = filled.replace(/\{\{[a-z_]+\}\}/g, '');

  // P0-5-a: Strip lines that became "**Label:** " (label with empty value) after
  // placeholder substitution — keeps the markdown clean when optional fields
  // aren't populated. Matches lines that are just "**Foo:** " or "**Foo:** "
  // followed by trailing whitespace then EOL.
  filled = filled.replace(/^\*\*[A-Za-z][^:*]*:\*\*\s*$/gm, '');
  // Collapse multiple consecutive blank lines into one
  filled = filled.replace(/\n{3,}/g, '\n\n');

  return filled.trim();
}

/**
 * P0-5-a: Map a validator vuln type (e.g. `xss_reflected`, `sqli_blind_time`,
 * `cors_misconfiguration`) to a REPORT_TEMPLATES key. Returns null when no
 * template matches — caller should fall back to the inline-build path.
 *
 * Mapping is deliberately conservative: only types where the existing template
 * is a clean fit. New templates should be added before extending this map.
 */
export function getTemplateKey(vulnType: string): string | null {
  const t = vulnType.toLowerCase().trim();
  if (t in REPORT_TEMPLATES) return t;

  // XSS family → xss
  if (t === 'xss_reflected' || t === 'xss_dom' || t === 'xss_stored') return 'xss';
  // SQLi family → sql_injection
  if (t === 'sqli_error' || t === 'sqli_blind_time' || t === 'sqli_blind_boolean') return 'sql_injection';
  // BOLA → idor (same template, two-account access proof)
  if (t === 'bola') return 'idor';
  // CORS misconfiguration → cors
  if (t === 'cors_misconfiguration') return 'cors';
  // JWT family → jwt
  if (t.startsWith('jwt_')) return 'jwt';
  // SSRF family → ssrf
  if (t === 'ssrf_blind') return 'ssrf';
  // Command injection family → command_injection
  if (t === 'command_injection_blind') return 'command_injection';
  // Path traversal aliases
  if (t === 'lfi' || t === 'lfi_rce') return 'path_traversal';
  // CRLF / response splitting
  if (t === 'crlf_injection') return 'crlf';

  return null;
}

/**
 * P0-5-a: Extract the most-likely vulnerable parameter from a URL or step list.
 * Used to fill `{{parameter}}` placeholders in templates when the caller
 * didn't pass one explicitly.
 *
 * Heuristic order:
 *   1. Last query-string parameter in `url` (often the injection point)
 *   2. First `?<param>=` pattern found in `steps`
 *   3. Returns null when nothing found — fillTemplate strips the placeholder.
 */
export function extractParameter(url: string, steps?: string[]): string | null {
  try {
    const u = new URL(url);
    const params = Array.from(u.searchParams.keys());
    if (params.length > 0) return params[params.length - 1];
  } catch {
    // url isn't fully-qualified — fall through to step extraction
  }

  if (steps) {
    for (const step of steps) {
      const m = step.match(/[?&]([a-zA-Z_][a-zA-Z0-9_]*)=/);
      if (m) return m[1];
    }
  }

  return null;
}

export default REPORT_TEMPLATES;

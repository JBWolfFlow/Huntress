/**
 * Command Safety Layer
 *
 * Pre-execution safety checks applied BEFORE the approval modal.
 * These are deterministic, non-LLM-dependent safety gates that catch
 * dangerous patterns regardless of what the AI model requests.
 *
 * Policy violations are hard blocks — they cannot be overridden
 * through the approval modal. Only code changes can adjust policies.
 */

/** Result of a safety policy check */
export interface SafetyCheckResult {
  allowed: boolean;
  violations: SafetyViolation[];
  warnings: string[];
  /** Command with safety modifications applied (rate limiting flags, etc.) */
  sanitizedCommand?: string;
}

/** A specific safety policy violation */
export interface SafetyViolation {
  policy: string;
  severity: 'block' | 'warn';
  description: string;
  matchedPattern: string;
}

// ─── Blocked Patterns ────────────────────────────────────────────────────────

/** Reverse shell patterns — ALWAYS blocked */
const REVERSE_SHELL_PATTERNS: RegExp[] = [
  /\bnc\s+.*-e\b/i,
  /\bncat\s+.*-e\b/i,
  /\bbash\s+-i\b/,
  /\b\/dev\/tcp\//,
  /\bmkfifo\b.*\bnc\b/,
  /\bpython[23]?\s+.*-c\s+.*socket/i,
  /\bperl\s+.*-e\s+.*socket/i,
  /\bruby\s+.*-e\s+.*TCPSocket/i,
  /\bphp\s+.*-r\s+.*fsockopen/i,
  /\bsocat\b.*\bexec\b/i,
  /\bpowershell\b.*\bNew-Object\s+System\.Net\.Sockets/i,
];

/** Destructive operation patterns — ALWAYS blocked */
const DESTRUCTIVE_PATTERNS: RegExp[] = [
  /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive\s+--force|-[a-zA-Z]*f[a-zA-Z]*r)\b/,
  /\brm\s+-rf\s+\//,
  /\bdd\s+.*of=/i,
  /\bmkfs\b/,
  /\bformat\b/i,
  /\bshred\b/,
  /\bwipe\b/,
  /\b:\(\)\s*\{\s*:\|:\s*&\s*\}\s*;?\s*:/,  // Fork bomb
  /\bchmod\s+(-R\s+)?777\s+\//,
  /\bchown\s+-R\b.*\//,
];

/** Data exfiltration patterns — ALWAYS blocked */
const EXFILTRATION_PATTERNS: RegExp[] = [
  /\bcurl\b.*\|\s*bash\b/,
  /\bwget\b.*\|\s*bash\b/,
  /\bcurl\b.*-d\s+@\/etc\//,
  /\btar\b.*\|\s*(nc|ncat|curl)\b/,
  /\bscp\b.*\/etc\/(passwd|shadow|hosts)/,
  /\bcat\s+\/etc\/(shadow|passwd)\s*\|\s*(curl|nc|wget)\b/,
];

/** Privilege escalation patterns — ALWAYS blocked */
const PRIVESC_PATTERNS: RegExp[] = [
  /\bsudo\s+su\b/,
  /\bsudo\s+-i\b/,
  /\bsudo\s+bash\b/,
  /\bsudo\s+sh\b/,
  /\bchmod\s+[u+]*s\b/,
  /\bpasswd\b/,
  /\busermod\b/,
  /\buseradd\b/,
];

/** SQLMap dangerous flags — blocked */
const SQLMAP_DANGEROUS_FLAGS: RegExp[] = [
  /--os-shell\b/,
  /--os-pwn\b/,
  /--os-cmd\b/,
  /--sql-shell\b/,
  /--priv-esc\b/,
  /--file-write\b/,
  /--file-dest\b/,
  /--reg-read\b/,
  /--reg-add\b/,
  /--reg-del\b/,
  /--level\s+[45]\b/,
  /--risk\s+3\b/,
];

/** Tools that should have rate limiting enforced */
const RATE_LIMITED_TOOLS: Record<string, { flag: string; maxRate: number }> = {
  ffuf: { flag: '-rate', maxRate: 50 },
  feroxbuster: { flag: '--rate-limit', maxRate: 50 },
  nuclei: { flag: '-rl', maxRate: 50 },
  katana: { flag: '-rl', maxRate: 10 },
  httpx: { flag: '-rl', maxRate: 50 },
  dalfox: { flag: '--delay', maxRate: 5 },
  naabu: { flag: '-rate', maxRate: 500 },
  gobuster: { flag: '--delay', maxRate: 50 },
};

// ─── Safety Policy Engine ────────────────────────────────────────────────────

/**
 * Run all safety policies against a command.
 * Returns a SafetyCheckResult with violations and optional command modifications.
 */
export function checkSafetyPolicies(
  command: string,
  target: string,
  category: string
): SafetyCheckResult {
  const violations: SafetyViolation[] = [];
  const warnings: string[] = [];
  let sanitizedCommand = command;

  // Check reverse shells
  for (const pattern of REVERSE_SHELL_PATTERNS) {
    if (pattern.test(command)) {
      violations.push({
        policy: 'no_reverse_shells',
        severity: 'block',
        description: 'Reverse shell commands are permanently blocked',
        matchedPattern: pattern.source,
      });
    }
  }

  // Check destructive operations
  for (const pattern of DESTRUCTIVE_PATTERNS) {
    if (pattern.test(command)) {
      violations.push({
        policy: 'no_destructive_ops',
        severity: 'block',
        description: 'Destructive system operations are permanently blocked',
        matchedPattern: pattern.source,
      });
    }
  }

  // Check data exfiltration
  for (const pattern of EXFILTRATION_PATTERNS) {
    if (pattern.test(command)) {
      violations.push({
        policy: 'no_data_exfiltration',
        severity: 'block',
        description: 'Data exfiltration patterns are blocked',
        matchedPattern: pattern.source,
      });
    }
  }

  // Check privilege escalation
  for (const pattern of PRIVESC_PATTERNS) {
    if (pattern.test(command)) {
      violations.push({
        policy: 'no_privilege_escalation',
        severity: 'block',
        description: 'Privilege escalation commands are blocked',
        matchedPattern: pattern.source,
      });
    }
  }

  // Check SQLMap dangerous flags
  const toolName = command.split(/\s+/)[0];
  if (toolName === 'sqlmap') {
    for (const pattern of SQLMAP_DANGEROUS_FLAGS) {
      if (pattern.test(command)) {
        violations.push({
          policy: 'sqlmap_safety',
          severity: 'block',
          description: `Dangerous sqlmap flag detected: ${pattern.source}`,
          matchedPattern: pattern.source,
        });
      }
    }
    // Ensure --batch is always present
    if (!command.includes('--batch')) {
      sanitizedCommand += ' --batch';
      warnings.push('Added --batch flag to sqlmap command for non-interactive execution');
    }
  }

  // Check shell injection patterns
  if (/[;|`$]/.test(command) && !command.includes('jq')) {
    // Allow pipes for jq processing, but warn on others
    if (/;\s*\w/.test(command)) {
      violations.push({
        policy: 'no_command_chaining',
        severity: 'block',
        description: 'Command chaining with ; is blocked — execute commands individually',
        matchedPattern: ';',
      });
    }
    if (/`[^`]+`/.test(command)) {
      violations.push({
        policy: 'no_command_substitution',
        severity: 'block',
        description: 'Backtick command substitution is blocked',
        matchedPattern: '`...`',
      });
    }
    if (/\$\([^)]+\)/.test(command)) {
      violations.push({
        policy: 'no_command_substitution',
        severity: 'block',
        description: '$() command substitution is blocked',
        matchedPattern: '$()',
      });
    }
  }

  // Enforce rate limiting
  const rateConfig = RATE_LIMITED_TOOLS[toolName];
  if (rateConfig) {
    const hasRateFlag = command.includes(rateConfig.flag);
    if (!hasRateFlag) {
      sanitizedCommand += ` ${rateConfig.flag} ${rateConfig.maxRate}`;
      warnings.push(`Added rate limit: ${rateConfig.flag} ${rateConfig.maxRate}`);
    } else {
      // Check if existing rate is too high
      const rateMatch = command.match(new RegExp(`${rateConfig.flag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s+(\\d+)`));
      if (rateMatch) {
        const rate = parseInt(rateMatch[1], 10);
        if (rate > rateConfig.maxRate * 10) {
          warnings.push(`Rate limit ${rate} is very high — consider reducing to ${rateConfig.maxRate}`);
        }
      }
    }
  }

  // Warn about broad scans
  if (category === 'scanning' || category === 'active_testing') {
    if (!target || target === '*') {
      violations.push({
        policy: 'require_specific_target',
        severity: 'block',
        description: 'Active testing requires a specific target — wildcard targets are blocked',
        matchedPattern: '*',
      });
    }
  }

  return {
    allowed: violations.filter(v => v.severity === 'block').length === 0,
    violations,
    warnings,
    sanitizedCommand: sanitizedCommand !== command ? sanitizedCommand : undefined,
  };
}

/**
 * Quick check if a command is safe (no blocking violations).
 */
export function isCommandSafe(command: string, target: string, category: string): boolean {
  return checkSafetyPolicies(command, target, category).allowed;
}

/**
 * Auto-approval categories for the approval gate (I3).
 *
 * Used by the UI to let the user pre-authorize whole classes of commands
 * so unattended hunts aren't blocked at the 60-second approval timeout.
 * `manual_only` means the command MUST go to the approval modal regardless
 * of any toggles — typically mutations (POST/PUT/DELETE, sqlmap, etc.).
 */
export type ApprovalCategory =
  | 'passive_recon'
  | 'safe_active_recon'
  | 'injection_passive'
  | 'manual_only';

/**
 * Classify a command into an ApprovalCategory. Deterministic: driven by
 * the tool name and simple flag/HTTP-verb heuristics, no LLM in the path.
 *
 * Conservative by design — unknown tools fall through to `manual_only`
 * so the approval modal still runs for anything we haven't vetted.
 */
export function classifyCommand(command: string): ApprovalCategory {
  const trimmed = command.trim();
  if (!trimmed) return 'manual_only';

  const tool = trimmed.split(/\s+/)[0];

  // ─── Passive recon — read-only, no server state change ──────────────────
  const passiveTools = new Set([
    'whois', 'dig', 'nslookup', 'host',
    'subfinder', 'assetfinder', 'findomain', 'dnsx',
    'httpx', 'wafw00f', 'whatweb',
    'gau', 'waybackurls', 'getJS', 'jsluice',
    'searchsploit',
  ]);
  if (passiveTools.has(tool)) return 'passive_recon';

  // curl/wget: passive ONLY for GET/HEAD without injection-like payloads.
  // Injection payload heuristic runs after the HTTP-verb check.
  if (tool === 'curl' || tool === 'wget') {
    const verb = extractHttpVerb(trimmed);
    if (verb && verb !== 'GET' && verb !== 'HEAD') return 'manual_only';
    // GET with injection-style payloads in query params — still passive,
    // but we surface it as `injection_passive` so users can opt-in separately.
    if (hasInjectionPayload(trimmed)) return 'injection_passive';
    return 'passive_recon';
  }

  // ─── Safe active recon — enumeration but no exploitation ────────────────
  const safeActiveTools = new Set([
    'gobuster', 'ffuf', 'dirb', 'dirsearch', 'feroxbuster',
    'katana', 'gospider', 'paramspider', 'arjun',
  ]);
  if (safeActiveTools.has(tool)) return 'safe_active_recon';

  // nmap without SYN-scan (-sS requires raw sockets / root)
  if (tool === 'nmap') {
    return /\s-sS\b/.test(trimmed) ? 'manual_only' : 'safe_active_recon';
  }

  // nuclei with default templates only — anything with -t custom path is manual
  if (tool === 'nuclei') {
    return /\s-t\b/.test(trimmed) ? 'manual_only' : 'safe_active_recon';
  }

  // ─── Everything else goes through manual approval ───────────────────────
  return 'manual_only';
}

function extractHttpVerb(command: string): string | null {
  // Match `-X VERB` or `--request VERB` for curl; wget has no explicit verb flag.
  const match = command.match(/(?:^|\s)(?:-X|--request)\s+([A-Z]+)/i);
  return match ? match[1].toUpperCase() : null;
}

function hasInjectionPayload(command: string): boolean {
  // Heuristics for GET-with-injection: SSTI braces, SQLi tick/union,
  // XSS angle brackets, path traversal, prototype pollution markers.
  // Deliberately conservative — false negatives route to passive_recon,
  // which the user has already opted into.
  return /\{\{.*\}\}|'\s*OR\s*1=1|UNION\s+SELECT|<script\b|\.\.%2f|%2e%2e%2f|\.\.\/\.\.\/|__proto__/i.test(command);
}

/**
 * Categorize a command's risk level based on the tool being used.
 */
export function categorizeCommandRisk(
  command: string
): 'safe' | 'controlled' | 'restricted' | 'blocked' {
  const tool = command.split(/\s+/)[0];

  const safeTools = new Set([
    'subfinder', 'assetfinder', 'dnsx', 'findomain', 'httpx', 'wafw00f',
    'gau', 'waybackurls', 'katana', 'gospider', 'jsluice', 'getJS',
    'paramspider', 'whois', 'dig', 'gowitness', 'testssl.sh', 'sslyze',
    'searchsploit', 'whatweb', 'jq', 'anew', 'qsreplace', 'unfurl',
    'curl', 'wget',
  ]);

  const controlledTools = new Set([
    'nuclei', 'naabu', 'nikto', 'wpscan', 'ffuf', 'feroxbuster',
    'gobuster', 'dirb', 'dirsearch', 'arjun',
  ]);

  const restrictedTools = new Set([
    'dalfox', 'sqlmap', 'ghauri', 'xsstrike', 'corsy',
    'interactsh-client', 'kxss', 'subjack',
  ]);

  const blockedTools = new Set([
    'hydra', 'medusa', 'john', 'hashcat', 'metasploit', 'msfconsole',
    'msfvenom', 'aircrack-ng', 'ettercap', 'bettercap',
    'slowloris', 'goldeneye', 'hping3', 'loic',
  ]);

  if (blockedTools.has(tool)) return 'blocked';
  if (restrictedTools.has(tool)) return 'restricted';
  if (controlledTools.has(tool)) return 'controlled';
  if (safeTools.has(tool)) return 'safe';

  // Unknown tools default to restricted
  return 'restricted';
}

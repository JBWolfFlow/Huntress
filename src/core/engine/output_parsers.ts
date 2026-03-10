/**
 * Tool Output Parsers
 *
 * Structured parsers for security tool output. Each tool produces output in a
 * different format (JSON, XML, line-delimited, custom). These parsers normalize
 * everything into a common structure for the agent to consume.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ParsedOutput {
  toolName: string;
  raw: string;
  entries: ParsedEntry[];
  metadata: Record<string, unknown>;
}

export interface ParsedEntry {
  type: string;
  value: string;
  details: Record<string, unknown>;
}

export interface ParsedFinding {
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  description: string;
  target: string;
  evidence: string;
}

// ─── Parser Registry ─────────────────────────────────────────────────────────

const parsers: Map<string, (stdout: string, stderr: string) => ParsedOutput> = new Map();

/** Register a parser for a tool */
function registerParser(toolName: string, parser: (stdout: string, stderr: string) => ParsedOutput): void {
  parsers.set(toolName, parser);
}

/** Parse output from a tool */
export function parseToolOutput(toolName: string, stdout: string, stderr: string): ParsedOutput {
  const parser = parsers.get(toolName);
  if (parser) {
    return parser(stdout, stderr);
  }
  return parseGenericOutput(toolName, stdout, stderr);
}

/** Extract findings from parsed output */
export function extractFindings(parsed: ParsedOutput): ParsedFinding[] {
  return parsed.entries
    .filter(e => e.type === 'vulnerability' || e.type === 'finding')
    .map(e => ({
      title: (e.details.name as string) || e.value,
      severity: (e.details.severity as ParsedFinding['severity']) || 'info',
      description: (e.details.description as string) || e.value,
      target: (e.details.host as string) || (e.details.url as string) || '',
      evidence: e.value,
    }));
}

/** Extract discovered targets from parsed output (for chaining to next tool) */
export function extractTargets(parsed: ParsedOutput): string[] {
  return parsed.entries
    .filter(e => e.type === 'subdomain' || e.type === 'host' || e.type === 'url')
    .map(e => e.value)
    .filter(v => v.length > 0);
}

// ─── Generic Parser ──────────────────────────────────────────────────────────

function parseGenericOutput(toolName: string, stdout: string, _stderr: string): ParsedOutput {
  const lines = stdout.split('\n').filter(l => l.trim());
  return {
    toolName,
    raw: stdout,
    entries: lines.slice(0, 500).map(line => ({
      type: 'line',
      value: line.trim(),
      details: {},
    })),
    metadata: { lineCount: lines.length },
  };
}

// ─── JSON Tool Parsers ───────────────────────────────────────────────────────

/** Parse NDJSON (newline-delimited JSON) output */
function parseNDJSON(toolName: string, stdout: string): ParsedOutput {
  const entries: ParsedEntry[] = [];
  const lines = stdout.split('\n').filter(l => l.trim().startsWith('{'));

  for (const line of lines) {
    try {
      const obj = JSON.parse(line);
      entries.push({
        type: 'json_entry',
        value: line,
        details: obj,
      });
    } catch {
      // Skip malformed lines
    }
  }

  return {
    toolName,
    raw: stdout,
    entries,
    metadata: { totalEntries: entries.length, format: 'ndjson' },
  };
}

// subfinder -json
registerParser('subfinder', (stdout) => {
  const base = parseNDJSON('subfinder', stdout);
  base.entries = base.entries.map(e => ({
    type: 'subdomain',
    value: (e.details.host as string) || '',
    details: e.details,
  }));
  return base;
});

// httpx -json
registerParser('httpx', (stdout) => {
  const base = parseNDJSON('httpx', stdout);
  base.entries = base.entries.map(e => ({
    type: 'host',
    value: (e.details.url as string) || (e.details.input as string) || '',
    details: {
      statusCode: e.details.status_code ?? e.details['status-code'],
      title: e.details.title,
      tech: e.details.tech,
      webServer: e.details.webserver,
      contentLength: e.details.content_length ?? e.details['content-length'],
      ...e.details,
    },
  }));
  return base;
});

// nuclei -json
registerParser('nuclei', (stdout) => {
  const base = parseNDJSON('nuclei', stdout);
  base.entries = base.entries.map(e => {
    const info = (e.details.info as Record<string, unknown>) || {};
    return {
      type: 'vulnerability',
      value: `[${info.severity || 'unknown'}] ${info.name || 'Unknown'} - ${e.details.host || ''}`,
      details: {
        name: info.name,
        severity: info.severity,
        description: info.description,
        host: e.details.host,
        matchedAt: e.details['matched-at'],
        templateId: e.details['template-id'],
        type: e.details.type,
        ...e.details,
      },
    };
  });
  return base;
});

// dalfox --format json
registerParser('dalfox', (stdout) => {
  const base = parseNDJSON('dalfox', stdout);
  base.entries = base.entries.map(e => ({
    type: e.details.type === 'Verified' ? 'vulnerability' : 'finding',
    value: `[XSS] ${e.details.data || ''} at ${e.details.param || ''}`,
    details: {
      name: 'Cross-Site Scripting (XSS)',
      severity: e.details.type === 'Verified' ? 'high' : 'medium',
      url: e.details.data,
      param: e.details.param,
      payload: e.details.payload,
      ...e.details,
    },
  }));
  return base;
});

// naabu -json
registerParser('naabu', (stdout) => {
  const base = parseNDJSON('naabu', stdout);
  base.entries = base.entries.map(e => ({
    type: 'port',
    value: `${e.details.host || e.details.ip}:${e.details.port}`,
    details: e.details,
  }));
  return base;
});

// dnsx -json
registerParser('dnsx', (stdout) => {
  const base = parseNDJSON('dnsx', stdout);
  base.entries = base.entries.map(e => ({
    type: 'dns_record',
    value: (e.details.host as string) || '',
    details: e.details,
  }));
  return base;
});

// ─── Line-Delimited Parsers ─────────────────────────────────────────────────

function parseLineDelimited(toolName: string, type: string, stdout: string): ParsedOutput {
  const lines = stdout.split('\n').filter(l => l.trim() && !l.startsWith('['));
  return {
    toolName,
    raw: stdout,
    entries: lines.map(line => ({
      type,
      value: line.trim(),
      details: {},
    })),
    metadata: { totalEntries: lines.length, format: 'line-delimited' },
  };
}

registerParser('assetfinder', (stdout) => parseLineDelimited('assetfinder', 'subdomain', stdout));
registerParser('findomain', (stdout) => parseLineDelimited('findomain', 'subdomain', stdout));
registerParser('waybackurls', (stdout) => parseLineDelimited('waybackurls', 'url', stdout));
registerParser('gau', (stdout) => parseLineDelimited('gau', 'url', stdout));
registerParser('paramspider', (stdout) => parseLineDelimited('paramspider', 'url', stdout));

// katana -json
registerParser('katana', (stdout) => {
  // katana outputs JSON or plain lines depending on flags
  if (stdout.trim().startsWith('{')) {
    const base = parseNDJSON('katana', stdout);
    base.entries = base.entries.map(e => ({
      type: 'url',
      value: (e.details.request as Record<string, unknown>)?.endpoint as string || (e.details.endpoint as string) || '',
      details: e.details,
    }));
    return base;
  }
  return parseLineDelimited('katana', 'url', stdout);
});

// ─── Custom Format Parsers ───────────────────────────────────────────────────

// sqlmap
registerParser('sqlmap', (stdout, stderr) => {
  const output = stdout + '\n' + stderr;
  const entries: ParsedEntry[] = [];

  // Extract injection points
  const injectionRegex = /Parameter:\s*(\S+)\s*\((\w+)\)/g;
  let match;
  while ((match = injectionRegex.exec(output)) !== null) {
    entries.push({
      type: 'vulnerability',
      value: `SQLi in parameter: ${match[1]} (${match[2]})`,
      details: {
        name: 'SQL Injection',
        severity: 'high',
        parameter: match[1],
        technique: match[2],
      },
    });
  }

  // Extract database info
  const dbMatch = output.match(/back-end DBMS:\s*(.+)/);
  if (dbMatch) {
    entries.push({
      type: 'finding',
      value: `Database: ${dbMatch[1]}`,
      details: { name: 'Database Fingerprint', severity: 'info', database: dbMatch[1] },
    });
  }

  return {
    toolName: 'sqlmap',
    raw: output,
    entries,
    metadata: { format: 'custom' },
  };
});

// nmap
registerParser('nmap', (stdout) => {
  const entries: ParsedEntry[] = [];

  // Parse open ports
  const portRegex = /(\d+)\/(tcp|udp)\s+(\w+)\s+(.*)/g;
  let match;
  while ((match = portRegex.exec(stdout)) !== null) {
    entries.push({
      type: 'port',
      value: `${match[1]}/${match[2]}`,
      details: {
        port: parseInt(match[1], 10),
        protocol: match[2],
        state: match[3],
        service: match[4].trim(),
      },
    });
  }

  return {
    toolName: 'nmap',
    raw: stdout,
    entries,
    metadata: { format: 'custom' },
  };
});

// ffuf / feroxbuster
registerParser('ffuf', (stdout) => {
  // ffuf with -json flag
  if (stdout.trim().startsWith('{')) {
    try {
      const data = JSON.parse(stdout);
      const results = data.results || [];
      return {
        toolName: 'ffuf',
        raw: stdout,
        entries: results.map((r: Record<string, unknown>) => ({
          type: 'path',
          value: r.url as string,
          details: {
            status: r.status,
            length: r.length,
            words: r.words,
            lines: r.lines,
            redirectlocation: r.redirectlocation,
          },
        })),
        metadata: { format: 'json', totalEntries: results.length },
      };
    } catch { /* fall through to text parsing */ }
  }

  const entries: ParsedEntry[] = [];
  const lines = stdout.split('\n');
  for (const line of lines) {
    const match = line.match(/(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)/);
    if (match) {
      entries.push({
        type: 'path',
        value: match[1],
        details: { status: parseInt(match[2], 10), size: parseInt(match[3], 10) },
      });
    }
  }

  return { toolName: 'ffuf', raw: stdout, entries, metadata: { format: 'text' } };
});

registerParser('feroxbuster', (stdout) => {
  const entries: ParsedEntry[] = [];
  const lines = stdout.split('\n');
  for (const line of lines) {
    const match = line.match(/(\d{3})\s+\S+\s+\S+\s+\S+\s+(https?:\/\/\S+)/);
    if (match) {
      entries.push({
        type: 'path',
        value: match[2],
        details: { status: parseInt(match[1], 10) },
      });
    }
  }
  return { toolName: 'feroxbuster', raw: stdout, entries, metadata: { format: 'text' } };
});

// wafw00f
registerParser('wafw00f', (stdout) => {
  const entries: ParsedEntry[] = [];
  const wafMatch = stdout.match(/is behind\s+(.+?)(\s+WAF)?$/m);
  const noWafMatch = stdout.match(/No WAF detected/);

  if (wafMatch) {
    entries.push({
      type: 'finding',
      value: `WAF Detected: ${wafMatch[1].trim()}`,
      details: { name: 'WAF Detection', severity: 'info', waf: wafMatch[1].trim() },
    });
  } else if (noWafMatch) {
    entries.push({
      type: 'finding',
      value: 'No WAF detected',
      details: { name: 'No WAF', severity: 'info', waf: null },
    });
  }

  return { toolName: 'wafw00f', raw: stdout, entries, metadata: { format: 'custom' } };
});

// whatweb
registerParser('whatweb', (stdout) => {
  // whatweb --log-json
  if (stdout.trim().startsWith('[') || stdout.trim().startsWith('{')) {
    try {
      const data = JSON.parse(stdout);
      const items = Array.isArray(data) ? data : [data];
      return {
        toolName: 'whatweb',
        raw: stdout,
        entries: items.map((item: Record<string, unknown>) => ({
          type: 'host',
          value: (item.target as string) || '',
          details: { plugins: item.plugins, ...item },
        })),
        metadata: { format: 'json' },
      };
    } catch { /* fall through */ }
  }

  return parseGenericOutput('whatweb', stdout, '');
});

// gospider
registerParser('gospider', (stdout) => {
  const entries: ParsedEntry[] = [];
  const lines = stdout.split('\n');
  for (const line of lines) {
    const urlMatch = line.match(/\[.*?\]\s*-\s*(https?:\/\/\S+)/);
    if (urlMatch) {
      entries.push({ type: 'url', value: urlMatch[1], details: {} });
    }
  }
  return { toolName: 'gospider', raw: stdout, entries, metadata: { format: 'custom' } };
});

// testssl.sh --json
registerParser('testssl.sh', (stdout) => {
  if (stdout.trim().startsWith('[') || stdout.trim().startsWith('{')) {
    try {
      const data = JSON.parse(stdout);
      const items = Array.isArray(data) ? data : [data];
      return {
        toolName: 'testssl.sh',
        raw: stdout,
        entries: items.map((item: Record<string, unknown>) => {
          const severity = item.severity === 'CRITICAL' ? 'critical'
            : item.severity === 'HIGH' ? 'high'
            : item.severity === 'MEDIUM' ? 'medium'
            : item.severity === 'LOW' ? 'low' : 'info';
          return {
            type: item.severity !== 'OK' && item.severity !== 'INFO' ? 'vulnerability' : 'finding',
            value: `${item.id}: ${item.finding}`,
            details: { ...item, severity },
          };
        }),
        metadata: { format: 'json' },
      };
    } catch { /* fall through */ }
  }
  return parseGenericOutput('testssl.sh', stdout, '');
});

/**
 * SAST Analyzer — LLM-powered Static Application Security Testing
 *
 * Uses the configured model provider to perform source code security analysis,
 * mapping findings to CWE IDs and OWASP Top 10 categories. Supports single-file,
 * snippet, diff, and cross-file repository analysis.
 */

import type {
  ModelProvider,
  ChatMessage,
  SendMessageOptions,
  ToolDefinition,
  ToolUseBlock,
  ChatResponse,
} from '../providers/types';

// ─── Public Interfaces ──────────────────────────────────────────────────────

/** A source file to analyze */
export interface SourceFile {
  path: string;
  content: string;
  language: string;
}

/** Context passed to analysis methods to focus or enrich results */
export interface AnalysisContext {
  targetUrl?: string;
  technology?: string[];
  knownVulnTypes?: string[];
  focusAreas?: string[];
  previousFindings?: SASTFinding[];
}

/** A single security finding from the SAST analyzer */
export interface SASTFinding {
  id: string;
  filePath: string;
  line: number;
  column?: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  cweId?: string;
  vulnerableCode: string;
  suggestedFix: string;
  /** Confidence score from 0 to 100 */
  confidence: number;
}

/** Aggregate report from a repository-level analysis */
export interface SASTReport {
  findings: SASTFinding[];
  summary: string;
  filesAnalyzed: number;
  totalIssues: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  analysisTimeMs: number;
}

// ─── Constants ──────────────────────────────────────────────────────────────

/** Map of file extensions to language names */
export const SUPPORTED_LANGUAGES: Record<string, string> = {
  '.ts': 'TypeScript',
  '.tsx': 'TypeScript (JSX)',
  '.js': 'JavaScript',
  '.jsx': 'JavaScript (JSX)',
  '.py': 'Python',
  '.rs': 'Rust',
  '.go': 'Go',
  '.java': 'Java',
  '.kt': 'Kotlin',
  '.cs': 'C#',
  '.cpp': 'C++',
  '.c': 'C',
  '.h': 'C/C++ Header',
  '.hpp': 'C++ Header',
  '.rb': 'Ruby',
  '.php': 'PHP',
  '.swift': 'Swift',
  '.scala': 'Scala',
  '.sql': 'SQL',
  '.sh': 'Shell',
  '.bash': 'Bash',
  '.zsh': 'Zsh',
  '.yaml': 'YAML',
  '.yml': 'YAML',
  '.json': 'JSON',
  '.xml': 'XML',
  '.html': 'HTML',
  '.htm': 'HTML',
  '.css': 'CSS',
  '.scss': 'SCSS',
  '.vue': 'Vue',
  '.svelte': 'Svelte',
  '.sol': 'Solidity',
  '.tf': 'Terraform',
  '.hcl': 'HCL',
  '.Dockerfile': 'Dockerfile',
  '.dockerfile': 'Dockerfile',
};

/** Maximum lines per analysis chunk */
const MAX_CHUNK_LINES = 3000;

/** Overlap lines between chunks to preserve context at boundaries */
const CHUNK_OVERLAP = 200;

// ─── Tool Definition for Structured Output ──────────────────────────────────

const REPORT_FINDINGS_TOOL: ToolDefinition = {
  name: 'report_sast_findings',
  description:
    'Report security findings discovered during static analysis. Call this tool with all findings from the analyzed code.',
  input_schema: {
    type: 'object',
    properties: {
      findings: {
        type: 'array',
        description: 'Array of security findings',
        items: {
          type: 'object',
          properties: {
            filePath: {
              type: 'string',
              description: 'Path to the file containing the vulnerability',
            },
            line: {
              type: 'number',
              description: 'Line number where the vulnerability occurs',
            },
            column: {
              type: 'number',
              description: 'Column number (optional)',
            },
            severity: {
              type: 'string',
              description: 'Severity rating',
              enum: ['critical', 'high', 'medium', 'low', 'info'],
            },
            title: {
              type: 'string',
              description: 'Short title of the vulnerability',
            },
            description: {
              type: 'string',
              description: 'Detailed description of the vulnerability and its impact',
            },
            cweId: {
              type: 'string',
              description: 'CWE identifier (e.g., CWE-89 for SQL injection)',
            },
            vulnerableCode: {
              type: 'string',
              description: 'The exact vulnerable code snippet',
            },
            suggestedFix: {
              type: 'string',
              description: 'Suggested code fix or remediation',
            },
            confidence: {
              type: 'number',
              description: 'Confidence score from 0 to 100',
            },
          },
          required: [
            'filePath',
            'line',
            'severity',
            'title',
            'description',
            'vulnerableCode',
            'suggestedFix',
            'confidence',
          ],
        },
      },
    },
    required: ['findings'],
  },
};

// ─── System Prompt ──────────────────────────────────────────────────────────

const SAST_SYSTEM_PROMPT = `You are an expert application security engineer performing static analysis (SAST) on source code. Your task is to identify security vulnerabilities with precision and rigor.

## Analysis Scope

You MUST check for the following vulnerability classes:

1. **Injection** — SQL injection, NoSQL injection, LDAP injection, OS command injection, expression language injection
2. **Cross-Site Scripting (XSS)** — Reflected, stored, and DOM-based XSS
3. **Server-Side Request Forgery (SSRF)** — Unvalidated URLs passed to HTTP clients, DNS rebinding vectors
4. **Path Traversal** — Directory traversal via user-controlled file paths, archive extraction (zip-slip)
5. **Insecure Deserialization** — Untrusted data passed to deserialize/unpickle/unserialize calls
6. **Hardcoded Credentials** — API keys, passwords, tokens, secrets embedded in source code
7. **Weak Cryptography** — MD5/SHA1 for security purposes, ECB mode, small key sizes, predictable IVs
8. **IDOR Patterns** — Direct object references without authorization checks
9. **Missing Authentication / Authorization** — Endpoints or functions lacking auth guards
10. **CSRF** — State-changing operations without CSRF token validation
11. **Rate Limiting Gaps** — Authentication or sensitive endpoints without rate limiting
12. **Prototype Pollution** — Unsafe object merges, recursive property assignment from user input
13. **XML External Entities (XXE)** — XML parsers with external entity processing enabled
14. **Server-Side Template Injection (SSTI)** — User input rendered in template engines without sanitization
15. **Open Redirects** — Unvalidated redirect URLs from user input
16. **Information Disclosure** — Verbose error messages, stack traces in responses, debug endpoints

## Output Requirements

For each vulnerability found:
- Provide the EXACT line number in the source code
- Quote the vulnerable code verbatim
- Assign a severity: critical, high, medium, low, or info
- Map to a CWE ID when possible (e.g., CWE-89 for SQL injection)
- Explain the vulnerability clearly — what it is, how it can be exploited, and what the impact is
- Provide a concrete code fix, not just a generic recommendation
- Assign a confidence score (0-100) reflecting how certain you are this is a real vulnerability, not a false positive

## Rules

- Do NOT report stylistic issues, code quality problems, or non-security concerns
- Do NOT fabricate findings — only report vulnerabilities you can clearly identify in the code
- If the code is secure, report zero findings — do not force false positives
- Consider the language and framework context when assessing risk (e.g., parameterized queries in Python are safe from SQL injection)
- Consider whether the code is server-side or client-side when assessing severity
- Be precise with line numbers — count from line 1 of the provided code`;

// ─── Internal Types ─────────────────────────────────────────────────────────

/** Raw finding shape as received from the LLM (before adding id) */
interface RawFinding {
  filePath: string;
  line: number;
  column?: number;
  severity: string;
  title: string;
  description: string;
  cweId?: string;
  vulnerableCode: string;
  suggestedFix: string;
  confidence: number;
}

/** Shape of the JSON parsed from an LLM text response (fallback path) */
interface ParsedFindingsPayload {
  findings: RawFinding[];
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Generate a unique finding ID */
function generateFindingId(filePath: string, line: number, title: string): string {
  const hash = simpleHash(`${filePath}:${line}:${title}`);
  return `sast-${hash}`;
}

/** Simple string hash for ID generation */
function simpleHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  return Math.abs(hash).toString(36);
}

/** Validate and normalize a severity string */
function normalizeSeverity(s: string): SASTFinding['severity'] {
  const lower = s.toLowerCase().trim();
  const valid: SASTFinding['severity'][] = ['critical', 'high', 'medium', 'low', 'info'];
  if (valid.includes(lower as SASTFinding['severity'])) {
    return lower as SASTFinding['severity'];
  }
  return 'info';
}

/** Clamp a confidence value to 0-100 */
function clampConfidence(n: number): number {
  if (typeof n !== 'number' || Number.isNaN(n)) return 50;
  return Math.max(0, Math.min(100, Math.round(n)));
}

/** Detect language from file extension */
export function detectLanguage(filePath: string): string {
  const lastDot = filePath.lastIndexOf('.');
  if (lastDot === -1) return 'Unknown';
  const ext = filePath.slice(lastDot);
  return SUPPORTED_LANGUAGES[ext] ?? 'Unknown';
}

/** Split source code into overlapping chunks of at most MAX_CHUNK_LINES lines */
function chunkCode(
  content: string,
  maxLines: number = MAX_CHUNK_LINES,
  overlap: number = CHUNK_OVERLAP,
): { chunk: string; startLine: number }[] {
  const lines = content.split('\n');
  if (lines.length <= maxLines) {
    return [{ chunk: content, startLine: 1 }];
  }

  const chunks: { chunk: string; startLine: number }[] = [];
  let offset = 0;

  while (offset < lines.length) {
    const end = Math.min(offset + maxLines, lines.length);
    chunks.push({
      chunk: lines.slice(offset, end).join('\n'),
      startLine: offset + 1,
    });
    if (end >= lines.length) break;
    offset = end - overlap;
  }

  return chunks;
}

/** Build a context suffix for the system prompt based on AnalysisContext */
function buildContextSuffix(context?: AnalysisContext): string {
  if (!context) return '';

  const parts: string[] = [];

  if (context.targetUrl) {
    parts.push(`Target URL: ${context.targetUrl}`);
  }
  if (context.technology && context.technology.length > 0) {
    parts.push(`Technology stack: ${context.technology.join(', ')}`);
  }
  if (context.knownVulnTypes && context.knownVulnTypes.length > 0) {
    parts.push(`Known vulnerability types to prioritize: ${context.knownVulnTypes.join(', ')}`);
  }
  if (context.focusAreas && context.focusAreas.length > 0) {
    parts.push(`Focus areas: ${context.focusAreas.join(', ')}`);
  }
  if (context.previousFindings && context.previousFindings.length > 0) {
    const summaries = context.previousFindings.map(
      (f) => `- ${f.filePath}:${f.line} — ${f.title} (${f.severity})`,
    );
    parts.push(`Previously identified findings (avoid duplicates):\n${summaries.join('\n')}`);
  }

  if (parts.length === 0) return '';
  return `\n\n## Additional Context\n\n${parts.join('\n')}`;
}

/** Deduplicate findings by (filePath, line, title) */
function deduplicateFindings(findings: SASTFinding[]): SASTFinding[] {
  const seen = new Set<string>();
  const result: SASTFinding[] = [];

  for (const finding of findings) {
    const key = `${finding.filePath}:${finding.line}:${finding.title}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(finding);
    }
  }

  return result;
}

/** Convert a RawFinding from LLM output to a typed SASTFinding */
function toSASTFinding(raw: RawFinding, defaultFilePath: string): SASTFinding {
  const filePath = typeof raw.filePath === 'string' && raw.filePath.length > 0
    ? raw.filePath
    : defaultFilePath;
  const line = typeof raw.line === 'number' && raw.line >= 1 ? raw.line : 1;
  const title = typeof raw.title === 'string' ? raw.title : 'Unnamed Finding';

  return {
    id: generateFindingId(filePath, line, title),
    filePath,
    line,
    column: typeof raw.column === 'number' && raw.column >= 0 ? raw.column : undefined,
    severity: normalizeSeverity(typeof raw.severity === 'string' ? raw.severity : 'info'),
    title,
    description: typeof raw.description === 'string' ? raw.description : '',
    cweId: typeof raw.cweId === 'string' && raw.cweId.length > 0 ? raw.cweId : undefined,
    vulnerableCode: typeof raw.vulnerableCode === 'string' ? raw.vulnerableCode : '',
    suggestedFix: typeof raw.suggestedFix === 'string' ? raw.suggestedFix : '',
    confidence: clampConfidence(raw.confidence),
  };
}

// ─── SASTAnalyzer Class ─────────────────────────────────────────────────────

export class SASTAnalyzer {
  private readonly provider: ModelProvider;
  private readonly model: string;

  constructor(provider: ModelProvider, model: string) {
    this.provider = provider;
    this.model = model;
  }

  // ── Public API ──────────────────────────────────────────────────────────

  /**
   * Analyze a single source file for security vulnerabilities.
   * Large files are chunked automatically.
   */
  async analyzeFile(
    filePath: string,
    content: string,
    context?: AnalysisContext,
  ): Promise<SASTFinding[]> {
    const language = detectLanguage(filePath);
    const chunks = chunkCode(content);

    const allFindings: SASTFinding[] = [];

    for (const { chunk, startLine } of chunks) {
      const prompt = this.buildFileAnalysisPrompt(filePath, chunk, language, startLine, context);
      const findings = await this.runAnalysis(prompt, filePath, context);

      // Adjust line numbers for chunks that don't start at line 1
      if (startLine > 1) {
        for (const finding of findings) {
          finding.line = finding.line + startLine - 1;
          // Regenerate ID with corrected line number
          finding.id = generateFindingId(finding.filePath, finding.line, finding.title);
        }
      }

      allFindings.push(...findings);
    }

    return deduplicateFindings(allFindings);
  }

  /**
   * Analyze a code snippet for security vulnerabilities.
   */
  async analyzeCodeSnippet(
    code: string,
    language: string,
    context?: AnalysisContext,
  ): Promise<SASTFinding[]> {
    const filePath = '<snippet>';
    const prompt = this.buildSnippetAnalysisPrompt(code, language, context);
    return this.runAnalysis(prompt, filePath, context);
  }

  /**
   * Analyze multiple files with cross-file vulnerability detection.
   *
   * Pass 1: Analyze each file individually.
   * Pass 2: Send a summary of all findings + file manifest to the LLM to identify
   *          cross-file issues (e.g., unsanitized input from file A used in file B).
   */
  async analyzeRepository(
    files: SourceFile[],
    context?: AnalysisContext,
  ): Promise<SASTReport> {
    const startTime = Date.now();

    // Pass 1: individual file analysis
    const pass1Findings: SASTFinding[] = [];

    for (const file of files) {
      const findings = await this.analyzeFile(file.path, file.content, context);
      pass1Findings.push(...findings);
    }

    // Pass 2: cross-file analysis
    const crossFileFindings = await this.runCrossFileAnalysis(files, pass1Findings, context);

    const allFindings = deduplicateFindings([...pass1Findings, ...crossFileFindings]);
    const analysisTimeMs = Date.now() - startTime;

    return this.buildReport(allFindings, files.length, analysisTimeMs);
  }

  /**
   * Analyze a git diff for newly introduced vulnerabilities.
   */
  async analyzeDiff(
    diff: string,
    context?: AnalysisContext,
  ): Promise<SASTFinding[]> {
    const filePath = '<diff>';
    const prompt = this.buildDiffAnalysisPrompt(diff, context);
    return this.runAnalysis(prompt, filePath, context);
  }

  /**
   * Get a human-readable security review of a code snippet.
   * Returns prose rather than structured findings.
   */
  async getSecurityReview(code: string, language: string): Promise<string> {
    const systemPrompt = `You are an expert application security engineer. Review the following ${language} code and provide a clear, human-readable security assessment. Cover:

1. Any security vulnerabilities you find (with severity and CWE IDs)
2. Security best practices that are missing
3. Positive security patterns you observe
4. Specific recommendations for improvement

Be thorough but concise. Do not report non-security issues.`;

    const messages: ChatMessage[] = [
      {
        role: 'user',
        content: `Please review this ${language} code for security issues:\n\n\`\`\`${language}\n${code}\n\`\`\``,
      },
    ];

    const options: SendMessageOptions = {
      model: this.model,
      maxTokens: 4096,
      temperature: 0.2,
      systemPrompt,
    };

    const response = await this.provider.sendMessage(messages, options);
    return typeof response.content === 'string' ? response.content : '';
  }

  // ── Private: Prompt Builders ────────────────────────────────────────────

  private buildFileAnalysisPrompt(
    filePath: string,
    content: string,
    language: string,
    startLine: number,
    context?: AnalysisContext,
  ): string {
    const lineInfo = startLine > 1 ? ` (lines starting at ${startLine})` : '';
    return `Analyze the following ${language} file for security vulnerabilities.

File: ${filePath}${lineInfo}

\`\`\`${language.toLowerCase()}
${content}
\`\`\`

Report all security findings. If no vulnerabilities are found, report an empty findings array.`;
  }

  private buildSnippetAnalysisPrompt(
    code: string,
    language: string,
    context?: AnalysisContext,
  ): string {
    const _ = context; // Used in system prompt via buildContextSuffix
    return `Analyze the following ${language} code snippet for security vulnerabilities.

\`\`\`${language.toLowerCase()}
${code}
\`\`\`

Report all security findings. Use "<snippet>" as the filePath. If no vulnerabilities are found, report an empty findings array.`;
  }

  private buildDiffAnalysisPrompt(diff: string, context?: AnalysisContext): string {
    const _ = context; // Used in system prompt via buildContextSuffix
    return `Analyze the following git diff for security vulnerabilities INTRODUCED by the changes. Focus only on added (+) lines, not removed (-) lines. The context (unchanged) lines help you understand the surrounding code.

\`\`\`diff
${diff}
\`\`\`

For filePath, use the file path from the diff headers. For line numbers, use the new file line numbers (right side of the @@ hunk headers).

Report all security findings introduced by these changes. If no new vulnerabilities are introduced, report an empty findings array.`;
  }

  private buildCrossFilePrompt(
    files: SourceFile[],
    pass1Findings: SASTFinding[],
    context?: AnalysisContext,
  ): string {
    const _ = context; // Used in system prompt via buildContextSuffix

    const fileManifest = files
      .map((f) => `- ${f.path} (${f.language}, ${f.content.split('\n').length} lines)`)
      .join('\n');

    const findingSummary =
      pass1Findings.length > 0
        ? pass1Findings
            .map(
              (f) =>
                `- [${f.severity.toUpperCase()}] ${f.filePath}:${f.line} — ${f.title}${f.cweId ? ` (${f.cweId})` : ''}`,
            )
            .join('\n')
        : 'No individual file findings.';

    // Include truncated file contents for cross-reference
    const fileContents = files
      .map((f) => {
        const lines = f.content.split('\n');
        const truncated = lines.length > 100 ? lines.slice(0, 100).join('\n') + '\n... (truncated)' : f.content;
        return `### ${f.path} (${f.language})\n\`\`\`${f.language.toLowerCase()}\n${truncated}\n\`\`\``;
      })
      .join('\n\n');

    return `You are performing a cross-file security analysis of a codebase. Individual file analysis has already been completed. Your task is to identify CROSS-FILE vulnerabilities that cannot be found by examining files in isolation.

## Files in Repository

${fileManifest}

## Individual File Findings (already reported)

${findingSummary}

## File Contents

${fileContents}

## Your Task

Look for cross-file security issues such as:
- Unsanitized user input from one file used in a dangerous sink in another file
- Missing authorization checks on routes/endpoints defined across multiple files
- Inconsistent input validation between entry points and backend handlers
- Shared utility functions that are insecure when called from certain contexts
- Data flow from user input through multiple files to a vulnerable output

Only report NEW findings that were NOT already captured in the individual file analysis. If no cross-file vulnerabilities exist, report an empty findings array.`;
  }

  // ── Private: LLM Interaction ────────────────────────────────────────────

  /**
   * Core analysis runner. Sends the prompt to the LLM with tool use (if supported)
   * or falls back to JSON-in-text parsing.
   */
  private async runAnalysis(
    userPrompt: string,
    defaultFilePath: string,
    context?: AnalysisContext,
  ): Promise<SASTFinding[]> {
    const systemPrompt = SAST_SYSTEM_PROMPT + buildContextSuffix(context);
    const messages: ChatMessage[] = [{ role: 'user', content: userPrompt }];

    const useToolUse = this.provider.supportsToolUse === true;

    const options: SendMessageOptions = {
      model: this.model,
      maxTokens: 8192,
      temperature: 0.1,
      systemPrompt,
      ...(useToolUse
        ? {
            tools: [REPORT_FINDINGS_TOOL],
            toolChoice: { type: 'tool', name: 'report_sast_findings' },
          }
        : {}),
    };

    const response = await this.provider.sendMessage(messages, options);

    if (useToolUse) {
      return this.parseFindingsFromToolUse(response, defaultFilePath);
    }
    return this.parseFindingsFromText(response, defaultFilePath);
  }

  /**
   * Parse findings from a tool_use response (structured output path).
   */
  private parseFindingsFromToolUse(
    response: ChatResponse,
    defaultFilePath: string,
  ): SASTFinding[] {
    if (!response.toolCalls || response.toolCalls.length === 0) {
      // Fall back to text parsing if no tool calls despite requesting them
      return this.parseFindingsFromText(response, defaultFilePath);
    }

    const toolCall: ToolUseBlock | undefined = response.toolCalls.find(
      (tc) => tc.name === 'report_sast_findings',
    );

    if (!toolCall) {
      return this.parseFindingsFromText(response, defaultFilePath);
    }

    const input = toolCall.input as Record<string, unknown>;
    const rawFindings = input['findings'];

    if (!Array.isArray(rawFindings)) {
      return [];
    }

    return rawFindings
      .map((raw: unknown) => toSASTFinding(raw as RawFinding, defaultFilePath))
      .filter((f) => f.title !== 'Unnamed Finding' || f.description.length > 0);
  }

  /**
   * Parse findings from a plain-text response by extracting JSON.
   * Handles both raw JSON arrays/objects and JSON embedded in markdown code blocks.
   */
  private parseFindingsFromText(
    response: ChatResponse,
    defaultFilePath: string,
  ): SASTFinding[] {
    const text = typeof response.content === 'string' ? response.content : '';

    if (text.trim().length === 0) {
      return [];
    }

    // Try to extract JSON from the response
    const jsonStr = this.extractJson(text);
    if (!jsonStr) {
      return [];
    }

    try {
      const parsed: unknown = JSON.parse(jsonStr);

      // Handle { findings: [...] } shape
      if (
        parsed !== null &&
        typeof parsed === 'object' &&
        'findings' in (parsed as Record<string, unknown>)
      ) {
        const payload = parsed as ParsedFindingsPayload;
        if (Array.isArray(payload.findings)) {
          return payload.findings
            .map((raw) => toSASTFinding(raw, defaultFilePath))
            .filter((f) => f.title !== 'Unnamed Finding' || f.description.length > 0);
        }
      }

      // Handle raw array of findings
      if (Array.isArray(parsed)) {
        return (parsed as RawFinding[])
          .map((raw) => toSASTFinding(raw, defaultFilePath))
          .filter((f) => f.title !== 'Unnamed Finding' || f.description.length > 0);
      }

      return [];
    } catch {
      return [];
    }
  }

  /**
   * Extract a JSON string from LLM text output.
   * Looks for JSON in code blocks first, then tries to find raw JSON.
   */
  private extractJson(text: string): string | null {
    // Try markdown code block: ```json ... ``` or ``` ... ```
    const codeBlockRegex = /```(?:json)?\s*\n?([\s\S]*?)```/;
    const codeBlockMatch = codeBlockRegex.exec(text);
    if (codeBlockMatch) {
      const candidate = codeBlockMatch[1].trim();
      if (candidate.startsWith('{') || candidate.startsWith('[')) {
        return candidate;
      }
    }

    // Try to find a JSON object or array directly in the text
    const objectStart = text.indexOf('{');
    const arrayStart = text.indexOf('[');

    // Pick whichever comes first
    let start: number;
    let openChar: string;
    let closeChar: string;

    if (objectStart === -1 && arrayStart === -1) return null;

    if (objectStart === -1) {
      start = arrayStart;
      openChar = '[';
      closeChar = ']';
    } else if (arrayStart === -1) {
      start = objectStart;
      openChar = '{';
      closeChar = '}';
    } else if (arrayStart < objectStart) {
      start = arrayStart;
      openChar = '[';
      closeChar = ']';
    } else {
      start = objectStart;
      openChar = '{';
      closeChar = '}';
    }

    // Find the matching close bracket/brace
    let depth = 0;
    let inString = false;
    let escaped = false;

    for (let i = start; i < text.length; i++) {
      const ch = text[i];

      if (escaped) {
        escaped = false;
        continue;
      }

      if (ch === '\\' && inString) {
        escaped = true;
        continue;
      }

      if (ch === '"') {
        inString = !inString;
        continue;
      }

      if (inString) continue;

      if (ch === openChar) {
        depth++;
      } else if (ch === closeChar) {
        depth--;
        if (depth === 0) {
          return text.slice(start, i + 1);
        }
      }
    }

    return null;
  }

  // ── Private: Cross-File Analysis ────────────────────────────────────────

  /**
   * Run the second pass: cross-file analysis to find inter-file vulnerabilities.
   */
  private async runCrossFileAnalysis(
    files: SourceFile[],
    pass1Findings: SASTFinding[],
    context?: AnalysisContext,
  ): Promise<SASTFinding[]> {
    if (files.length < 2) {
      // Cross-file analysis only makes sense with 2+ files
      return [];
    }

    const prompt = this.buildCrossFilePrompt(files, pass1Findings, context);
    return this.runAnalysis(prompt, '<cross-file>', context);
  }

  // ── Private: Report Builder ─────────────────────────────────────────────

  private buildReport(
    findings: SASTFinding[],
    filesAnalyzed: number,
    analysisTimeMs: number,
  ): SASTReport {
    const criticalCount = findings.filter((f) => f.severity === 'critical').length;
    const highCount = findings.filter((f) => f.severity === 'high').length;
    const mediumCount = findings.filter((f) => f.severity === 'medium').length;
    const lowCount = findings.filter((f) => f.severity === 'low').length;
    const infoCount = findings.filter((f) => f.severity === 'info').length;

    const summaryParts: string[] = [];
    summaryParts.push(`Analyzed ${filesAnalyzed} file${filesAnalyzed === 1 ? '' : 's'}.`);
    summaryParts.push(`Found ${findings.length} issue${findings.length === 1 ? '' : 's'}.`);

    if (criticalCount > 0) summaryParts.push(`${criticalCount} critical.`);
    if (highCount > 0) summaryParts.push(`${highCount} high.`);
    if (mediumCount > 0) summaryParts.push(`${mediumCount} medium.`);
    if (lowCount > 0) summaryParts.push(`${lowCount} low.`);
    if (infoCount > 0) summaryParts.push(`${infoCount} info.`);

    summaryParts.push(`Analysis completed in ${analysisTimeMs}ms.`);

    return {
      findings,
      summary: summaryParts.join(' '),
      filesAnalyzed,
      totalIssues: findings.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      analysisTimeMs,
    };
  }
}

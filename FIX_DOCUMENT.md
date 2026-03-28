# HUNTRESS — COMPLETE FIX DOCUMENT

**Generated:** March 11, 2026
**Status:** 47 issues identified across 7 severity categories
**Goal:** Make Huntress fully operational for real-world HackerOne bug bounty hunting

---

## TABLE OF CONTENTS

- [BLOCK 1: Core Flow — Make Chat Drive Agent Hunting](#block-1-core-flow--make-chat-drive-agent-hunting)
- [BLOCK 2: Agent Registration — Fix Silent Agent Failures](#block-2-agent-registration--fix-silent-agent-failures)
- [BLOCK 3: Provider Wiring — Fix Tool-Use Loop](#block-3-provider-wiring--fix-tool-use-loop)
- [BLOCK 4: Scope Validation — Fix Bypass Vulnerabilities](#block-4-scope-validation--fix-bypass-vulnerabilities)
- [BLOCK 5: Report Submission Pipeline — Fix the H1 Path](#block-5-report-submission-pipeline--fix-the-h1-path)
- [BLOCK 6: IPC Security — Lock Down Filesystem/Command Access](#block-6-ipc-security--lock-down-filesystemcommand-access)
- [BLOCK 7: HTTP Tools — Add Scope Validation](#block-7-http-tools--add-scope-validation)
- [BLOCK 8: Approval Pipeline — Fix Concurrent Approvals](#block-8-approval-pipeline--fix-concurrent-approvals)
- [BLOCK 9: Context Window — Prevent Session Crashes](#block-9-context-window--prevent-session-crashes)
- [BLOCK 10: Chain Detection — Fix Dedup and Wire Validator](#block-10-chain-detection--fix-dedup-and-wire-validator)
- [BLOCK 11: Phase 23 Module Integration — Wire Dead Code](#block-11-phase-23-module-integration--wire-dead-code)
- [BLOCK 12: Orchestrator Flow Fixes — Strategy, Streaming, Parsing](#block-12-orchestrator-flow-fixes--strategy-streaming-parsing)
- [BLOCK 13: HTTP Engine — Fix Runtime Crashes and Fake Data](#block-13-http-engine--fix-runtime-crashes-and-fake-data)
- [BLOCK 14: Agent Code Quality — Dedup, Imports, Base Class](#block-14-agent-code-quality--dedup-imports-base-class)
- [BLOCK 15: Rust Backend — Fix unwrap/expect and Dependencies](#block-15-rust-backend--fix-unwrapexpect-and-dependencies)
- [BLOCK 16: Auto-Approve — Wire Settings to Engine](#block-16-auto-approve--wire-settings-to-engine)
- [BLOCK 17: Cross-Agent Data Sharing](#block-17-cross-agent-data-sharing)
- [BLOCK 18: Tool Availability Checking](#block-18-tool-availability-checking)
- [BLOCK 19: Session Persistence](#block-19-session-persistence)

---

## BLOCK 1: Core Flow — Make Chat Drive Agent Hunting

**Priority:** CRITICAL
**Impact:** Without this fix, the chat interface is a dumb LLM wrapper. The entire agent coordination layer (the core product value) is unreachable through normal conversation.

### Issue 1.1: `sendMessage()` bypasses orchestrator engine

**File:** `src/contexts/HuntSessionContext.tsx`
**Lines:** 278-337

**Current broken code:**
```typescript
const sendMessage = useCallback(async (input: string) => {
  // ... shows user message ...
  const engine = getOrInitEngine();
  // PROBLEM: Calls raw provider, not the orchestrator
  const response = await engine.getProvider().sendMessage(
    [{ role: 'user', content: input }],
    { model: engine.getModel() }
  );
  // Returns plain text, no agent dispatch
}, []);
```

**What's wrong:** The function calls `engine.getProvider().sendMessage()` directly — a raw LLM API call. It never invokes the orchestrator's ReAct loop, never spawns sub-agents, never creates execution plans. A user typing "test example.com for SSRF" gets a text essay, not an SSRF Hunter running tools.

**Fix:** Route user messages through the orchestrator engine's `streamUserInput()` or a new `processUserMessage()` method that:
1. Checks if a hunt is active — if so, feeds the message to the coordinator loop
2. If no hunt active, uses the orchestrator to interpret the message and potentially start a hunt
3. Supports tool use so the orchestrator can dispatch agents from the chat

**Required changes:**
- `HuntSessionContext.tsx:278-337` — Replace raw `engine.getProvider().sendMessage()` with `engine.processUserMessage(input)` or equivalent
- `orchestrator_engine.ts` — Ensure `streamUserInput()` or a new method supports tool use (currently `streamUserInput()` at lines 492-539 sends messages WITHOUT `tools` or `toolChoice`)
- The method must support the orchestrator's full tool set (`dispatch_agent`, `reprioritize_tasks`, `generate_report`, `stop_hunting`)

---

## BLOCK 2: Agent Registration — Fix Silent Agent Failures

**Priority:** CRITICAL
**Impact:** 5 of the most important vulnerability classes (SSRF, XSS, SQLi, CORS, Subdomain Takeover) are silently unavailable. The orchestrator cannot route tasks to them.

### Issue 2.1: Missing agent imports in registration chain

**File:** `src/agents/standardized_agents.ts`
**Lines:** 11-48 (import section)

**Current state:** `standardized_agents.ts` imports and re-exports:
- GraphQL, IDOR, SSTI, OpenRedirect, HostHeader (from `./host_header`), PrototypePollution
- Phase 21: RaceCondition, HttpSmuggling, Cache, JWT, BusinessLogic
- Phase 22: NoSQL, Deserialization, SAML, MFABypass, WebSocket, CRLF, PromptInjection

**File:** `src/agents/agent_router.ts`
**Lines:** 18-24 (side-effect imports)

**Current state:** `agent_router.ts` imports:
- `./recon_agent`
- `./standardized_agents`
- `./xxe_hunter`
- `./command_injection_hunter`
- `./path_traversal_hunter`

**Missing from both files (never imported, never registered):**
- `./ssrf_hunter` — SSRFHunterAgent
- `./xss_hunter` — XSSHunterAgent
- `./sqli_hunter` — SQLiHunterAgent
- `./cors_hunter` — CORSHunterAgent
- `./subdomain_takeover_hunter` — SubdomainTakeoverHunterAgent

**Fix:** Add the 5 missing side-effect imports to `agent_router.ts` after line 24:
```typescript
import './ssrf_hunter';
import './xss_hunter';
import './sqli_hunter';
import './cors_hunter';
import './subdomain_takeover_hunter';
```

### Issue 2.2: Duplicate host_header agent registration

**Files:**
- `src/agents/host_header.ts` — metadata at lines 119-127, registerAgent at lines 277-280
- `src/agents/host_header_hunter.ts` — metadata at lines 129-136, registerAgent at lines 286-289

**What's wrong:** Both register with ID `'host-header-hunter'`. Whichever loads second silently overwrites the first in the catalog Map. `standardized_agents.ts` imports from `./host_header` (line 31). `host_header_hunter.ts` is imported nowhere in the main chain but self-registers if anything else imports it.

**Fix:** Delete `src/agents/host_header_hunter.ts` entirely. The `host_header.ts` version is already imported via `standardized_agents.ts` and is the canonical implementation. Update any imports that reference `host_header_hunter` to use `host_header` instead.

---

## BLOCK 3: Provider Wiring — Fix Tool-Use Loop

**Priority:** CRITICAL
**Impact:** When the user configures provider fallback (the exact resilience scenario), the entire Coordinator-Solver tool-use architecture becomes dead code. The orchestrator degrades to a text chatbot.

### Issue 3.1: `ResilientProvider` missing `supportsToolUse`

**File:** `src/core/providers/provider_fallback.ts`
**Lines:** 93-95 (class definition)

**Current broken code:**
```typescript
export class ResilientProvider implements ModelProvider {
  readonly providerId = 'resilient';
  readonly displayName: string;
  // supportsToolUse is NOT defined
```

**How it breaks:** In `orchestrator_engine.ts:449`, the check `this.provider.supportsToolUse` gates whether the orchestrator sends tools to the model. Since `ResilientProvider` doesn't define it, it's `undefined` (falsy). The coordinator never sees `dispatch_agent`, `reprioritize_tasks`, or `generate_report` tools. It returns text-only responses, which the orchestrator treats as "stop."

**Fix:** Add a getter that forwards from the primary provider:
```typescript
get supportsToolUse(): boolean {
  return this.states[0]?.entry.provider.supportsToolUse ?? false;
}
```

---

## BLOCK 4: Scope Validation — Fix Bypass Vulnerabilities

**Priority:** CRITICAL
**Impact:** A bug here could cause out-of-scope testing, which gets the user banned from HackerOne programs.

### Issue 4.1: JavaScript-side substring matching bypass

**File:** `src/core/orchestrator/orchestrator_engine.ts`
**Lines:** 1264-1268

**Current broken code:**
```typescript
const inScope = this.huntSession.program.scope.inScope.some(s =>
  args.target.includes(s) || s.includes(args.target) ||
  args.target.endsWith(s) || this.matchesWildcard(args.target, s)
);
```

**What's wrong:** If scope contains `example.com`:
- `"evil-example.com".includes("example.com")` = `true` — **BYPASS**
- `"notexample.com".includes("example.com")` = `true` — **BYPASS**
- `"example.com.evil.org".includes("example.com")` = `true` — **BYPASS**

**Also broken:** `matchesWildcard()` at lines 1739-1743:
```typescript
private matchesWildcard(target: string, scopeEntry: string): boolean {
  if (!scopeEntry.startsWith('*.')) return false;
  const baseDomain = scopeEntry.slice(2);
  return target.endsWith(baseDomain) || target === baseDomain;
}
```
`*.example.com` matches `notexample.com` because `"notexample.com".endsWith("example.com")` = `true`.

**Fix:** Replace with proper URL parsing and domain boundary matching:
```typescript
private isTargetInScope(target: string, scopeEntry: string): boolean {
  try {
    const targetHost = new URL(target.startsWith('http') ? target : `https://${target}`).hostname;
    const scopeHost = scopeEntry.replace(/^\*\./, '');
    if (scopeEntry.startsWith('*.')) {
      // Must match exact subdomain boundary: .example.com
      return targetHost === scopeHost || targetHost.endsWith('.' + scopeHost);
    }
    return targetHost === scopeHost;
  } catch { return false; }
}
```

### Issue 4.2: Rust-side regex injection in compile_pattern()

**File:** `src-tauri/src/safe_to_test.rs`
**Lines:** 509-520

**Current broken code:**
```rust
fn compile_pattern(pattern: &str) -> Result<Regex, ScopeError> {
    let escaped = pattern
        .replace(".", "\\.")
        .replace("*", "WILDCARD_PLACEHOLDER");
    let regex_pattern = escaped.replace("WILDCARD_PLACEHOLDER", "[^.]+");
    Regex::new(&format!("^{}$", regex_pattern))
        .map_err(|e| ScopeError::InvalidPattern(format!("{}: {}", pattern, e)))
}
```

**What's wrong:** Only `.` and `*` are escaped. All other regex metacharacters pass through raw:
- `|` — alternation: `example.com|evil.com` matches `evil.com`
- `+`, `?`, `[`, `]`, `^`, `$`, `{`, `}`, `\`, `(`, `)` — all interpreted as regex operators

A malformed or malicious scope entry could silently expand what's considered in-scope.

**Fix:** Use `regex::escape()` on the entire input first, then replace the escaped wildcard:
```rust
fn compile_pattern(pattern: &str) -> Result<Regex, ScopeError> {
    // First, replace * with a placeholder before escaping
    let with_placeholder = pattern.replace("*", "WILDCARD_PLACEHOLDER");
    // Escape ALL regex metacharacters
    let escaped = regex::escape(&with_placeholder);
    // Now replace the escaped placeholder with the actual wildcard regex
    let regex_pattern = escaped.replace("WILDCARD_PLACEHOLDER", "[^.]+");
    Regex::new(&format!("^{}$", regex_pattern))
        .map_err(|e| ScopeError::InvalidPattern(format!("{}: {}", pattern, e)))
}
```

### Issue 4.3: IPC return type mismatches for scope commands

**Files:**
- `src-tauri/src/safe_to_test.rs` line 744: `load_scope` returns `Result<String, String>`
- `src/hooks/useTauriCommands.ts` line 80: expects `invoke<ScopeEntry[]>('load_scope', { path })`

**Also:**
- `src-tauri/src/safe_to_test.rs` line 809: `validate_target` returns `Result<bool, String>`
- `src/hooks/useTauriCommands.ts` line 94: expects `invoke<ValidationResult>('validate_target', { target })`

**What's wrong:** The TypeScript side expects different types than what Rust returns. This will cause runtime deserialization errors.

**Fix:** Either:
- **Option A:** Change the Rust commands to return the types the TS expects (return `Vec<ScopeEntry>` and `ValidationResult` struct)
- **Option B:** Change the TS types to match what Rust returns (expect `string` and `boolean`)

Option A is preferred as it provides richer data to the frontend.

---

## BLOCK 5: Report Submission Pipeline — Fix the H1 Path

**Priority:** CRITICAL
**Impact:** Reports can be submitted to HackerOne with zero quality checks, user edits are silently discarded, and binary attachments are corrupted.

### Issue 5.1: ReportReviewModal is dead code

**File:** `src/App.tsx`
**Lines:** 1-28 (imports), 416-463 (modal rendering)

**What's wrong:** `ReportReviewModal` is never imported in `App.tsx`. The submission flow goes: click finding → ReportEditor → "Submit to HackerOne" → `submitToH1()` directly. The quality scoring, duplicate risk analysis, 8-item checklist, and mandatory confirmation checkbox are entirely unreachable.

**Fix:**
1. Import `ReportReviewModal` in `App.tsx`
2. Add state: `const [reviewReport, setReviewReport] = useState<H1Report | null>(null);`
3. When user clicks "Submit" in `ReportEditor`, open `ReportReviewModal` instead of calling `submitToH1()` directly
4. Only call `submitToH1()` from `ReportReviewModal`'s "Approve & Submit" button
5. Pass `qualityScore` and `duplicateScore` from the context's Phase 23 modules

### Issue 5.2: ReportEditor discards user edits

**File:** `src/components/ReportEditor.tsx`
**Lines:** 101-116

**Current broken code:**
```typescript
const handleSubmit = useCallback(async () => {
  if (!onSubmit) return;
  // ...
  await onSubmit(report, programHandle);  // <-- sends original report, not edited markdown
}, [onSubmit, report, programHandle]);
```

**What's wrong:** The component has a `markdown` state that the user edits in the textarea, but `handleSubmit` sends the original `report` prop. User edits are silently lost.

**Fix:** Parse the edited markdown back into the report structure, or pass the markdown alongside the report:
```typescript
const handleSubmit = useCallback(async () => {
  if (!onSubmit) return;
  const editedReport = { ...report, description: markdown };
  await onSubmit(editedReport, programHandle);
}, [onSubmit, report, programHandle, markdown]);
```

### Issue 5.3: Binary attachment corruption in H1 API

**File:** `src/core/reporting/h1_api.ts`
**Lines:** 202-239

**What's wrong:** `uploadAttachment()` reads files via `invoke('read_tool_output')` which returns UTF-8 text. Screenshots, videos, and PDFs are silently corrupted because binary data is decoded as UTF-8 (lossy conversion).

**Fix:** Create a new Tauri command `read_file_binary` that returns base64-encoded content:
```rust
// In lib.rs
#[tauri::command]
async fn read_file_binary(path: String) -> Result<String, String> {
    let data = std::fs::read(&path).map_err(|e| e.to_string())?;
    Ok(base64::engine::general_purpose::STANDARD.encode(&data))
}
```
Then in `h1_api.ts`, decode the base64 to a `Uint8Array` before creating the Blob.

---

## BLOCK 6: IPC Security — Lock Down Filesystem/Command Access

**Priority:** CRITICAL
**Impact:** Any frontend XSS or compromised component = full system compromise (read/write/delete any file, execute any program).

### Issue 6.1: Unrestricted filesystem operations

**File:** `src-tauri/src/lib.rs`

**Affected commands:**
- `write_file_text` (line 283): Creates/overwrites any file, auto-creates parent dirs
- `delete_path` (line 312): Deletes any file or recursively deletes any directory
- `read_tool_output` (line 197): Reads any file on the system
- `create_symlink` (line 408): Creates symlinks anywhere
- `create_output_directory` (line 214): Creates directories at any path

**Note:** `append_to_file` (line 226) already has path validation (rejects `..` traversal, restricts to allowed directories). The inconsistency is glaring.

**Fix:** Apply the same path validation from `append_to_file` to all filesystem commands:
```rust
fn validate_path(path: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(path);
    // Reject path traversal
    if path.components().any(|c| c == std::path::Component::ParentDir) {
        return Err("Path traversal detected".to_string());
    }
    // Restrict to allowed directories
    let allowed = [
        dirs::data_dir().unwrap_or_default().join("huntress"),
        dirs::cache_dir().unwrap_or_default().join("huntress"),
        PathBuf::from("/tmp/huntress"),
    ];
    if !allowed.iter().any(|a| path.starts_with(a)) {
        return Err(format!("Path not in allowed directory: {}", path.display()));
    }
    Ok(path)
}
```

### Issue 6.2: Unrestricted command execution

**File:** `src-tauri/src/lib.rs`
**Lines:** 385-404

**Current broken code:**
```rust
let mut cmd = std::process::Command::new(&program);
cmd.args(&args);
```

**Fix:** Add an allowlist of permitted programs:
```rust
const ALLOWED_TRAINING_PROGRAMS: &[&str] = &[
    "python", "python3", "pip", "pip3",
    "axolotl", "huggingface-cli",
];

if !ALLOWED_TRAINING_PROGRAMS.contains(&program.as_str()) {
    return Err(format!("Program not in allowlist: {}", program));
}
```

### Issue 6.3: Raw SQL passthrough

**File:** `src-tauri/src/lib.rs`
**Lines:** 572-628

**What's wrong:** `knowledge_db_query` and `knowledge_db_execute` accept raw SQL strings and unrestricted database paths from the frontend.

**Fix:**
1. Restrict `db_path` to the Huntress data directory
2. Add a SQL statement allowlist or use prepared statement names instead of raw SQL:
```rust
const ALLOWED_SQL_PREFIXES: &[&str] = &[
    "SELECT", "INSERT INTO", "UPDATE", "CREATE TABLE IF NOT EXISTS",
    "CREATE INDEX IF NOT EXISTS",
];

let trimmed = sql.trim_start().to_uppercase();
if !ALLOWED_SQL_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
    return Err(format!("SQL statement type not allowed: {}", &trimmed[..20.min(trimmed.len())]));
}
```

---

## BLOCK 7: HTTP Tools — Add Scope Validation

**Priority:** HIGH
**Impact:** Agents can make HTTP requests to arbitrary out-of-scope targets without any scope check or approval.

### Issue 7.1: http_request, fuzz_parameter, race_test skip scope validation

**File:** `src/core/engine/react_loop.ts`

**Affected handlers:**
- `http_request` handler at lines 803-875
- `fuzz_parameter` handler at lines 878-947
- `race_test` handler at lines 950-1078

**What's wrong:** The `execute_command` handler (line 513) routes through `checkSafetyPolicies` and the approval gate. But these HTTP tool handlers bypass both entirely. An agent can make HTTP requests to arbitrary targets.

**Fix:** Add scope validation and approval for HTTP tools. Before executing each HTTP request:
```typescript
// In handleHttpRequest, handleFuzzParameter, handleRaceTest:
const targetUrl = new URL(input.url);
const safetyResult = await this.checkSafetyPolicies(
  `HTTP ${input.method || 'GET'} to ${input.url}`,
  targetUrl.hostname
);
if (!safetyResult.approved) {
  return { output: `Blocked: ${safetyResult.reason}`, exitCode: 1 };
}
```

---

## BLOCK 8: Approval Pipeline — Fix Concurrent Approvals

**Priority:** HIGH
**Impact:** If multiple agents request approval simultaneously, earlier requests are silently lost and those agents hang forever.

### Issue 8.1: Single pendingTask state

**File:** `src/App.tsx`
**Line:** 344

**Current broken code:**
```typescript
const [pendingTask, setPendingTask] = useState<HumanTaskRequest | null>(null);
```

**What's wrong:** Each new approval request overwrites the previous one via `setPendingTask(taskRequest)`. The earlier request's callback Promise never resolves, permanently hanging that agent.

**Fix:** Replace with a queue:
```typescript
const [pendingTasks, setPendingTasks] = useState<HumanTaskRequest[]>([]);

// When new approval comes in:
setPendingTasks(prev => [...prev, taskRequest]);

// Show the first task in the queue:
const currentTask = pendingTasks[0] ?? null;

// On approve/deny, remove from queue:
const handleResponse = (approved: boolean) => {
  if (!currentTask) return;
  callbacks?.get(currentTask.id)?.(approved);
  setPendingTasks(prev => prev.slice(1));
};
```

### Issue 8.2: Approval callbacks Map never cleaned up

**File:** `src/App.tsx`

**What's wrong:** `window.__huntress_approval_callbacks` is a global Map. Denied or timed-out approvals leave entries. Over a long session, this accumulates orphaned callbacks.

**Fix:** Add cleanup in the approval handler:
```typescript
callbacks?.get(pendingTask.id)?.(approved);
callbacks?.delete(pendingTask.id);  // Clean up after use
```

Add a periodic sweep for stale entries (e.g., callbacks older than 5 minutes).

---

## BLOCK 9: Context Window — Prevent Session Crashes

**Priority:** HIGH
**Impact:** Sessions crash when conversation history exceeds the model's context limit. This is guaranteed to happen on any non-trivial hunt.

### Issue 9.1: Unbounded conversation history in ReactLoop

**File:** `src/core/engine/react_loop.ts`
**Line:** 196

**What's wrong:** The `conversationHistory` array grows without limit. With 80 iterations, each adding assistant and user messages with up to 15KB of tool output, the context easily exceeds any model's limit. No summarization, pruning, or sliding-window logic exists.

**Fix:** Implement a sliding window with summarization:
```typescript
private async manageContextWindow(): Promise<void> {
  const MAX_MESSAGES = 40;  // Keep last 40 messages
  if (this.conversationHistory.length <= MAX_MESSAGES) return;

  // Summarize older messages
  const oldMessages = this.conversationHistory.slice(0, -MAX_MESSAGES);
  const summary = await this.summarizeMessages(oldMessages);

  // Replace old messages with summary
  this.conversationHistory = [
    { role: 'user', content: `[Previous context summary]: ${summary}` },
    ...this.conversationHistory.slice(-MAX_MESSAGES),
  ];
}
```

Call `manageContextWindow()` at the start of each iteration in the main loop.

### Issue 9.2: No timeout enforcement on commands

**File:** `src/core/engine/react_loop.ts`
**Lines:** 424, 513

**What's wrong:** The `timeout_seconds` parameter is accepted in the `execute_command` schema but never used to set an actual timeout. A hung command blocks the loop forever.

**Fix:** Pass `timeout_seconds` to `onExecuteCommand` and enforce it:
```typescript
const timeoutMs = (input.timeout_seconds ?? 30) * 1000;
const result = await Promise.race([
  this.config.onExecuteCommand(input.command, target),
  new Promise<CommandResult>((_, reject) =>
    setTimeout(() => reject(new Error(`Command timed out after ${input.timeout_seconds}s`)), timeoutMs)
  ),
]);
```

---

## BLOCK 10: Chain Detection — Fix Dedup and Wire Validator

**Priority:** HIGH
**Impact:** Same chains reported repeatedly (10x+ in a session). Chain validator is fully implemented but never called.

### Issue 10.1: Chain deduplication broken

**File:** `src/core/orchestrator/chain_detector.ts`
**Line:** 253

**Current broken code:**
```typescript
id: `chain_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
```

**What's wrong:** Each `detectChains()` call generates fresh IDs. The orchestrator deduplicates via `previousChainIds.has(c.id)`, which never matches because IDs are always new.

**Fix:** Generate stable, deterministic IDs based on the chain's content:
```typescript
id: `chain_${rule.id}_${matched.map(f => f.id).sort().join('_')}`,
```

This produces the same ID for the same chain rule + same findings combination, so dedup works correctly.

### Issue 10.2: ChainValidator never called

**File:** `src/core/orchestrator/orchestrator_engine.ts`

**What's wrong:** `this.chainValidator` is stored (line 325) but never invoked anywhere. The orchestrator calls `detectChains()` but never calls `validateChain()`, `discoverCreativeChains()`, or `generateChainPoC()`.

**Fix:** After detecting chains, validate them:
```typescript
// In runDispatchLoop(), after detectChains():
if (newChains.length > 0 && this.chainValidator) {
  for (const chain of newChains) {
    const validation = await this.chainValidator.validateChain(chain, this.provider, this.model);
    if (validation.exploitable) {
      chain.confidence = validation.confidence;
      chain.poc = validation.poc;
      this.emitMessage('system', `Chain validated: ${chain.name} (confidence: ${validation.confidence})`);
    }
  }
}
```

---

## BLOCK 11: Phase 23 Module Integration — Wire Dead Code

**Priority:** HIGH
**Impact:** Target dedup, H1 duplicate checking, report quality scoring, and continuous monitoring are all initialized but never called. These are critical for production bounty hunting.

### Issue 11.1: Phase 23 modules stored but never invoked

**File:** `src/core/orchestrator/orchestrator_engine.ts`
**Lines:** 252-258 (field declarations), 328-331 (assignment)

**Current state:**
```typescript
// Declared and assigned, but ZERO method calls anywhere in the file:
private targetDedup?: TargetDeduplicator;
private h1DuplicateChecker?: H1DuplicateChecker;
private reportQuality?: ReportQualityScorer;
private continuousMonitor?: ContinuousMonitor;
```

**Fix — Wire targetDedup into task creation:**
```typescript
// In createFollowUpTasks() or wherever new targets are queued:
if (this.targetDedup) {
  const isDuplicate = await this.targetDedup.isDuplicate(newTarget);
  if (isDuplicate) {
    this.emitMessage('system', `Skipping duplicate target: ${newTarget}`);
    return;
  }
}
```

**Fix — Wire h1DuplicateChecker into finding handling:**
```typescript
// In handleAgentResult(), after deduplicating local findings:
if (this.h1DuplicateChecker && result.findings.length > 0) {
  for (const finding of result.findings) {
    const dupScore = await this.h1DuplicateChecker.checkDuplicate(finding);
    finding.duplicateScore = dupScore;
    if (dupScore.recommendation === 'skip') {
      this.emitMessage('system', `Finding "${finding.title}" likely duplicate on H1 (score: ${dupScore.overallScore})`);
    }
  }
}
```

**Fix — Wire reportQuality into report generation:**
```typescript
// Before submitting any report:
if (this.reportQuality) {
  const score = this.reportQuality.scoreReport(report);
  if (score.grade === 'F') {
    this.emitMessage('system', `Report quality too low (grade: F). Enhancing...`);
    const enhanced = await this.reportQuality.enhanceReport(report, this.provider, this.model);
    return enhanced;
  }
}
```

**Fix — Wire continuousMonitor into hunt lifecycle:**
```typescript
// In startHunt(), after initializing:
if (this.continuousMonitor) {
  const domains = program.scope.inScope.filter(s => !s.startsWith('*'));
  this.continuousMonitor.updateDomains(domains);
  this.continuousMonitor.start();
}

// In abortHunt():
this.continuousMonitor?.stop();
```

---

## BLOCK 12: Orchestrator Flow Fixes — Strategy, Streaming, Parsing

**Priority:** MEDIUM
**Impact:** Strategy selection does nothing. Streaming path is functionally different from non-streaming. Response parsing loses structured content.

### Issue 12.1: selectStrategy() is a no-op

**File:** `src/core/orchestrator/orchestrator_engine.ts`
**Lines:** 679-690

**What's wrong:** The method emits a UI message but does not start any agents, create any tasks, or begin hunting. The user clicks a strategy card, sees a confirmation, and nothing happens.

**Fix:** Make `selectStrategy()` call `startHunt()` with the selected strategy:
```typescript
async selectStrategy(strategyId: string): Promise<void> {
  this.emitMessage('orchestrator', `Starting hunt with strategy: ${strategyId}`);
  this.huntSession.selectedStrategy = strategyId;
  await this.startHunt();
}
```

### Issue 12.2: streamUserInput() never uses tools

**File:** `src/core/orchestrator/orchestrator_engine.ts`
**Lines:** 492-539

**What's wrong:** The streaming path sends messages without `tools` or `toolChoice` options. During an active hunt, tool use is impossible via streaming.

**Fix:** Add tool schemas to the streaming call when a hunt is active:
```typescript
const options: SendMessageOptions = {
  model: this.model,
  ...(this.huntSession?.phase === 'hunting' && this.provider.supportsToolUse ? {
    tools: ORCHESTRATOR_TOOL_SCHEMAS,
    toolChoice: 'auto',
  } : {}),
};
```

### Issue 12.3: parseResponse() is a stub

**File:** `src/core/orchestrator/orchestrator_engine.ts`
**Lines:** 1815-1824

**What's wrong:** Wraps everything in a single text message. Structured content (JSON blocks, finding cards, strategy suggestions) in non-tool-use responses is lost.

**Fix:** Parse the response for structured content:
```typescript
private parseResponse(content: string): ConversationMessage[] {
  const messages: ConversationMessage[] = [];
  // Check for JSON finding blocks
  const findingMatch = content.match(/```json\n(\{[\s\S]*?"type":\s*"finding"[\s\S]*?\})\n```/);
  if (findingMatch) {
    try {
      const finding = JSON.parse(findingMatch[1]);
      messages.push({ type: 'finding_card', ...finding });
      content = content.replace(findingMatch[0], '');
    } catch { /* not valid JSON, treat as text */ }
  }
  if (content.trim()) {
    messages.push({ type: 'orchestrator', content: content.trim(), timestamp: Date.now() });
  }
  return messages.length > 0 ? messages : [{ type: 'orchestrator', content, timestamp: Date.now() }];
}
```

---

## BLOCK 13: HTTP Engine — Fix Runtime Crashes and Fake Data

**Priority:** HIGH
**Impact:** `Buffer.byteLength` crashes in the browser. Fabricated TTFB breaks blind injection detection. Scope bypass in test mode.

### Issue 13.1: Buffer.byteLength crashes in Tauri WebView

**File:** `src/core/http/request_engine.ts`
**Line:** 412

**Current broken code:**
```typescript
size: Buffer.byteLength(responseBody, 'utf-8'),
```

**Fix:**
```typescript
size: new TextEncoder().encode(responseBody).byteLength,
```

### Issue 13.2: Fabricated TTFB timing

**File:** `src/core/http/request_engine.ts`
**Line:** 407

**Current broken code:**
```typescript
ttfbMs: Math.round(totalMs * 0.3), // Approximation
```

**What's wrong:** This is not a measurement. Time-based blind SQLi and command injection detection depends on accurate timing. A hardcoded 0.3x ratio produces false signals.

**Fix:** Use performance timing to measure actual TTFB:
```typescript
const startTime = performance.now();
let ttfbTime = 0;

// Use axios interceptor to capture TTFB
const axiosInstance = axios.create();
axiosInstance.interceptors.response.use((response) => {
  ttfbTime = performance.now() - startTime;
  return response;
});

// ... after request completes:
ttfbMs: Math.round(ttfbTime),
totalMs: Math.round(performance.now() - startTime),
```

### Issue 13.3: Scope bypass in test/Node mode

**File:** `src/core/http/request_engine.ts`
**Lines:** 204-207

**Current broken code:**
```typescript
if (isNode) {
  if (target === '127.0.0.1' || target === 'localhost') return true;
  return true; // permissive in test mode
}
```

**Fix:** In test mode, still validate against loaded scope:
```typescript
if (isNode) {
  // Allow localhost for testing infrastructure
  if (target === '127.0.0.1' || target === 'localhost') return true;
  // Log warning but still enforce scope if available
  console.warn('[SCOPE] Running outside Tauri — scope validation limited');
  return this.localScopeCheck(target);  // Check against in-memory scope
}
```

---

## BLOCK 14: Agent Code Quality — Dedup, Imports, Base Class

**Priority:** MEDIUM
**Impact:** Code maintainability, lint compliance, and a subtle mutation bug.

### Issue 14.1: ReconAgent returns mutable reference from reportFindings()

**File:** `src/agents/recon_agent.ts`
**Lines:** 229-231

**Current broken code:**
```typescript
reportFindings(): AgentFinding[] {
  return this.findings;  // Direct reference, not a copy
}
```

**Fix:**
```typescript
reportFindings(): AgentFinding[] {
  return [...this.findings];  // Defensive copy, consistent with all other agents
}
```

### Issue 14.2: ReactLoopConfig imported but unused in 13 agents

**Files:** `ssrf_hunter.ts`, `idor_hunter.ts`, `xxe_hunter.ts`, `command_injection_hunter.ts`, `path_traversal_hunter.ts`, `nosql_hunter.ts`, `saml_hunter.ts`, `websocket_hunter.ts`, `race_condition_hunter.ts`, `crlf_hunter.ts`, `deserialization_hunter.ts`, `mfa_bypass_hunter.ts`, `prompt_injection_hunter.ts`

**Fix:** Remove `ReactLoopConfig` from the import statement in each file.

### Issue 14.3: ~5,600 lines of duplicated boilerplate across 28 agents

**What's wrong:** All 28 ReAct-based agents copy-paste ~200 identical lines: constructor, initialize, execute scaffold, validate, reportFindings, cleanup, getStatus, convertFinding, updateStatus, setCallbacks.

**Fix:** Extract a `BaseReactAgent` class:
```typescript
export abstract class BaseReactAgent implements BaseAgent {
  protected abstract readonly systemPrompt: string;
  protected abstract readonly agentMetadata: AgentMetadata;
  protected maxIterations = 30;
  // ... all shared logic ...

  async execute(task: AgentTask): Promise<AgentResult> {
    const loop = new ReactLoop({
      provider: this.provider,
      model: this.model,
      systemPrompt: this.systemPrompt,
      tools: this.getToolSchemas(),
      maxIterations: this.maxIterations,
      // ... callbacks ...
    });
    return loop.execute();
  }
}
```

Each agent file shrinks to ~30 lines: metadata + system prompt + optional overrides.

---

## BLOCK 15: Rust Backend — Fix unwrap/expect and Dependencies

**Priority:** MEDIUM
**Impact:** unwrap()/expect() calls can crash the entire backend. Missing features and outdated deps cause silent failures.

### Issue 15.1: 17 unwrap() calls on Regex::new() in pty_manager.rs

**File:** `src-tauri/src/pty_manager.rs`
**Lines:** 249-289

**Current broken code:**
```rust
let patterns: Vec<(regex::Regex, &str)> = vec![
    (regex::Regex::new(r"access_token=[^&\s]+").unwrap(), "access_token=[REDACTED]"),
    // ... 16 more .unwrap() calls
];
```

**Fix:** Compile regexes once using `LazyLock`:
```rust
use std::sync::LazyLock;

static REDACTION_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| vec![
    (Regex::new(r"access_token=[^&\s]+").expect("valid regex"), "access_token=[REDACTED]"),
    // ... rest ...
]);
```

This also fixes the performance issue (regexes were recompiled on every PTY read).

### Issue 15.2: expect() in secure_storage Tauri command handlers

**File:** `src-tauri/src/secure_storage.rs`
**Lines:** 382, 401, 417, 441, 456

**Current broken code:**
```rust
VAULT.lock().expect("vault mutex poisoned")
guard.as_mut().expect("vault initialized")
```

**Fix:** Replace with `map_err` to return errors instead of panicking:
```rust
let mut guard = VAULT.lock()
    .map_err(|e| format!("Vault lock error: {}", e))?;
let vault = guard.as_mut()
    .ok_or_else(|| "Vault not initialized".to_string())?;
```

### Issue 15.3: Missing reqwest `socks` feature

**File:** `src-tauri/Cargo.toml`
**Line:** ~27

**Current:**
```toml
reqwest = { version = "0.11", features = ["json", "blocking"] }
```

**Fix:**
```toml
reqwest = { version = "0.11", features = ["json", "blocking", "socks"] }
```

### Issue 15.4: Unmaintained dotenv crate

**File:** `src-tauri/Cargo.toml`

**Current:**
```toml
dotenv = "0.15"
```

**Fix:** Replace with the maintained fork:
```toml
dotenvy = "0.15"
```

Update any `use dotenv::dotenv` to `use dotenvy::dotenv` in Rust source files.

---

## BLOCK 16: Auto-Approve — Wire Settings to Engine

**Priority:** MEDIUM
**Impact:** The auto-approve checkboxes in Settings do nothing. Users must manually approve every single command, including passive recon.

### Issue 16.1: Auto-approve settings not passed to engine

**File:** `src/components/SettingsPanel.tsx`
**Lines:** 269-284

**What exists:** Two checkboxes: "Passive Recon" and "Active Scanning" that update `settings.autoApprove.passiveRecon` and `settings.autoApprove.activeScanning`.

**File:** `src/contexts/HuntSessionContext.tsx`
**Lines:** 245-263

**What's missing:** The `OrchestratorConfig` object passed to `OrchestratorEngine` does not include `autoApprove` settings. In `react_loop.ts` line 206, `autoApproveSafe` defaults to `false`.

**Fix:**
1. Add to `OrchestratorConfig`:
```typescript
autoApprove?: { passiveRecon: boolean; activeScanning: boolean };
```

2. In `HuntSessionContext.tsx`, pass settings:
```typescript
const engine = new OrchestratorEngine({
  // ...existing config...
  autoApprove: settings.autoApprove,
});
```

3. In `OrchestratorEngine`, pass to agent dispatch:
```typescript
// When creating ReactLoop for agents:
autoApproveSafe: this.config.autoApprove?.passiveRecon ?? false,
```

---

## BLOCK 17: Cross-Agent Data Sharing

**Priority:** MEDIUM
**Impact:** The Recon agent discovers subdomains, endpoints, technologies, and WAF presence. None of this flows to subsequent hunters. Each hunter starts from scratch.

### Issue 17.1: Agent observations never populated

**What exists:** The `AgentObservation` interface exists in `base_agent.ts`. The `observations` field is optional on `AgentResult`. Zero agents populate it.

**Fix:**
1. In `recon_agent.ts`, populate observations from findings:
```typescript
// After ReactLoop execution:
result.observations = this.findings
  .filter(f => f.type === 'specialist_request' || f.severity === 'info')
  .map(f => ({
    type: f.type as string,
    target: f.target,
    data: f.evidence,
    confidence: 0.8,
  }));
```

2. In `orchestrator_engine.ts`, pass recon observations to subsequent agents:
```typescript
// In dispatchAgent():
const task: AgentTask = {
  // ...existing fields...
  context: {
    reconObservations: this.huntSession.reconResults ?? [],
    discoveredEndpoints: this.huntSession.discoveredEndpoints ?? [],
    wafInfo: this.huntSession.wafInfo ?? null,
  },
};
```

3. In each agent's `execute()`, include observations in the system prompt context:
```typescript
const contextBlock = task.context?.reconObservations
  ? `\n\nRecon results:\n${task.context.reconObservations.map(o => `- ${o.target}: ${o.data}`).join('\n')}`
  : '';
```

---

## BLOCK 18: Tool Availability Checking

**Priority:** MEDIUM
**Impact:** Agent prompts reference 20+ external tools (subfinder, httpx, nuclei, sqlmap, dalfox, etc.). If any are missing, agents waste iterations on failed commands.

### Issue 18.1: No tool availability verification

**What exists:** The Rust backend has `check_installed_tools`, `get_missing_required_tools`, and `get_tool_summary` commands registered in `lib.rs`. But these are never called from the frontend.

**Fix:**
1. Call `check_installed_tools` during engine initialization
2. Pass the available tools list to agents as context
3. Agents can adapt their strategy based on available tools

```typescript
// In HuntSessionContext.tsx initializeEngine():
const toolCheck = await invoke<ToolCheckResult>('check_installed_tools');
if (toolCheck.missing.length > 0) {
  addMessage({
    type: 'system',
    level: 'warning',
    content: `Missing tools: ${toolCheck.missing.join(', ')}. Some agents may have reduced capability.`,
  });
}

// Pass to engine:
const engine = new OrchestratorEngine({
  // ...existing config...
  availableTools: toolCheck.installed,
});
```

---

## BLOCK 19: Session Persistence

**Priority:** MEDIUM
**Impact:** If the app crashes during a multi-hour hunt, all state is lost: findings, task queue, chain detections, agent progress. CLAUDE.md says "Sessions can be resumed" and "Every failure must be recoverable."

### Issue 19.1: No hunt session persistence

**File:** `src/core/orchestrator/orchestrator_engine.ts`

**What's wrong:** The `HuntSession` object lives entirely in memory. No serialization, checkpointing, or recovery mechanism exists.

**Note:** `HuntSessionContext.tsx` has auto-save for the UI state (messages, findings) via localStorage every 30 seconds (lines 437-449). But the orchestrator's internal state (task queue, agent assignments, chain detections, blackboard) is not persisted.

**Fix:**
1. Add a `checkpoint()` method to OrchestratorEngine:
```typescript
async checkpoint(): Promise<void> {
  const state = {
    taskQueue: this.taskQueue.serialize(),
    findings: this.huntSession.allFindings,
    chains: this.huntSession.detectedChains,
    blackboard: this.blackboard.serialize(),
    phase: this.huntSession.phase,
    agentHistory: this.huntSession.agentHistory,
  };
  localStorage.setItem('huntress_session_checkpoint', JSON.stringify(state));
}
```

2. Call `checkpoint()` after each dispatch batch completes
3. Add a `restore()` method that rebuilds state from the checkpoint
4. On app restart, detect and offer to resume from checkpoint

---

## ADDITIONAL ISSUES (Lower Priority)

### A1. `write_script` uses shell heredoc
**File:** `src/core/engine/react_loop.ts`, lines 746-748
**Issue:** Uses `tee ${scriptPath} <<'HUNTRESS_SCRIPT_EOF'` — shell string interpolation
**Fix:** Write the script via a Tauri command (`write_file_text`) then execute it separately

### A2. `stop_hunting` conflates clean stop with emergency kill
**File:** `src/core/engine/react_loop.ts`, line 345
**Issue:** Sets `this.killed = true` for both graceful stop and emergency abort
**Fix:** Use a separate `this.stopped` flag for clean stops

### A3. Only last tool call logged per iteration
**File:** `src/core/engine/react_loop.ts`, line 321
**Issue:** When model returns multiple tool calls, loop overwrites `logEntry.toolCall` each time
**Fix:** Change `logEntry.toolCall` to `logEntry.toolCalls: ToolCall[]` and push each one

### A4. Consecutive error detection off-by-one
**File:** `src/core/engine/react_loop.ts`, line 372
**Issue:** Checks last 3 entries before current is pushed — allows one extra failed iteration
**Fix:** Push `logEntry` before the consecutive error check

### A5. FindingsPanel component never rendered
**File:** `src/components/FindingsPanel.tsx`
**Issue:** Fully implemented with filtering, sorting, expandable views — but never imported by any parent
**Fix:** Replace the inline `SidePanel` in `App.tsx` with the `FindingsPanel` component

### A6. TrainingDashboard always returns null
**File:** `src/components/TrainingDashboard.tsx`, line 98
**Issue:** `fetchTrainingData()` unconditionally returns `null`
**Fix:** Connect to actual training pipeline data or show realistic status

### A7. Chat approval buttons non-functional
**File:** `src/components/ChatMessage.tsx`, lines 224-236
**Issue:** `onApprovalRespond` is never passed from `ChatInterface`
**Fix:** Either wire the prop through or remove the inline buttons (modal handles it)

### A8. Ctrl+L bound but does nothing
**File:** `src/components/ChatInterface.tsx`, line 81
**Issue:** `e.preventDefault()` with no action
**Fix:** Implement clear screen or remove the binding

### A9. No chat virtualization
**File:** `src/components/ChatInterface.tsx`
**Issue:** `messages.map()` renders all messages — O(n) at 1000+ messages
**Fix:** Use `react-window` or `react-virtuoso` for windowed rendering

### A10. Context value causes excessive re-renders
**File:** `src/contexts/HuntSessionContext.tsx`, lines 532-555
**Issue:** Context value reconstructed every render
**Fix:** Wrap with `useMemo` keyed on actual changing values

### A11. Knowledge system initialization race condition
**File:** `src/contexts/HuntSessionContext.tsx`
**Issue:** KnowledgeGraph, VulnDatabase, RewardSystem init async — engine may be used before they complete
**Fix:** Add an `isReady` flag and gate engine operations on it

### A12. Secure storage not using OS keychain
**File:** `src-tauri/src/secure_storage.rs`
**Issue:** Uses AES-256-GCM vault with key derived from hostname+username (predictable locally)
**Fix:** Integrate with `libsecret` on Linux or use Tauri's keyring plugin for hardware-backed key storage

### A13. Kill switch state persistence not atomic
**File:** `src-tauri/src/kill_switch.rs`, lines 147-173
**Issue:** `fs::write()` is not atomic. Crash during write = corrupted file = kill switch resets to inactive
**Fix:** Write to temp file, fsync, then rename (atomic on POSIX). On load error, default to ACTIVE (fail-safe)

### A14. Streaming fallback delivers garbled content
**File:** `src/core/providers/provider_fallback.ts`, line 198
**Issue:** If provider A fails mid-stream after yielding chunks, provider B restarts from beginning. Caller gets partial-A + full-B.
**Fix:** Buffer stream chunks and only yield after confirming provider success, or signal "discard previous" to caller

### A15. Shell injection in validator.ts curl commands
**File:** `src/core/validation/validator.ts`, lines 1019-1207
**Issue:** CORS and Host Header validators use shell string interpolation in curl commands
**Fix:** Use argv arrays instead of shell strings for all command construction

### A16. Shodan API key logged in URLs
**File:** `src/core/discovery/extended_recon.ts`, line 574
**Issue:** `?key=${shodanApiKey}` in URL gets logged by request engine
**Fix:** Strip API keys from request logging, or use header-based auth

### A17. DNS canary validation logic incorrect
**File:** `src/core/validation/oob_server.ts`, line 668
**Issue:** Uses local `dig` to check if domain resolves — this always works regardless of whether target made a request
**Fix:** Requires authoritative nameserver log monitoring, not local DNS lookups

### A18. Burp Collaborator provider is non-functional
**File:** `src/core/validation/oob_server.ts`, lines 486-507
**Issue:** Only does GET polling, never POSTs to allocate a subdomain
**Fix:** Implement the Burp Collaborator protocol: POST to allocate, then poll for interactions

---

## SUMMARY MATRIX

| Block | Issues | Priority | Effort | Impact |
|-------|--------|----------|--------|--------|
| 1. Core Flow | 1 | CRITICAL | Medium | Enables agent hunting from chat |
| 2. Agent Registration | 2 | CRITICAL | Small | Enables 5 core agents |
| 3. Provider Wiring | 1 | CRITICAL | Small | Fixes tool-use with fallback |
| 4. Scope Validation | 3 | CRITICAL | Medium | Prevents out-of-scope testing |
| 5. Report Pipeline | 3 | CRITICAL | Medium | Fixes H1 submission flow |
| 6. IPC Security | 3 | CRITICAL | Medium | Prevents system compromise |
| 7. HTTP Scope | 1 | HIGH | Small | Adds scope to HTTP tools |
| 8. Approval Queue | 2 | HIGH | Small | Fixes concurrent approvals |
| 9. Context Window | 2 | HIGH | Medium | Prevents session crashes |
| 10. Chain Detection | 2 | HIGH | Small | Fixes chain dedup + validation |
| 11. Phase 23 Modules | 4 | HIGH | Medium | Wires dedup/quality/monitoring |
| 12. Orchestrator Fixes | 3 | MEDIUM | Medium | Strategy/streaming/parsing |
| 13. HTTP Engine | 3 | HIGH | Small | Fixes crashes + fake data |
| 14. Agent Quality | 3 | MEDIUM | Large | Reduces 5600 lines of duplication |
| 15. Rust Backend | 4 | MEDIUM | Small | Fixes panics + deps |
| 16. Auto-Approve | 1 | MEDIUM | Small | Wires settings to engine |
| 17. Cross-Agent Data | 1 | MEDIUM | Medium | Enables recon → hunter flow |
| 18. Tool Checking | 1 | MEDIUM | Small | Detects missing tools |
| 19. Session Persistence | 1 | MEDIUM | Medium | Enables crash recovery |
| Additional (A1-A18) | 18 | LOW-MED | Mixed | Polish and hardening |

**Total: 47 primary issues + 18 additional items = 65 action items**

---

## RECOMMENDED EXECUTION ORDER

1. **Blocks 2, 3** (Small fixes, massive impact — agent registration + provider wiring)
2. **Block 4** (Scope validation — safety critical)
3. **Block 1** (Core flow — enables the product)
4. **Block 7, 8** (HTTP scope + approval queue)
5. **Block 5** (Report pipeline — enables H1 submission)
6. **Block 6** (IPC security — hardening)
7. **Block 13** (HTTP engine crashes)
8. **Block 9** (Context window)
9. **Block 10, 11** (Chain detection + Phase 23 wiring)
10. **Block 12** (Orchestrator flow)
11. **Blocks 15, 16** (Rust fixes + auto-approve)
12. **Blocks 14, 17, 18, 19** (Code quality + data sharing + tool checking + persistence)
13. **Additional A1-A18** (Polish)

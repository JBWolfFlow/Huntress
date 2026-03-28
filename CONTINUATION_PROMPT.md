# HUNTRESS — PRODUCTION READINESS FIX PROMPT

> **Usage:** Paste everything below into a fresh Claude Code terminal to begin fixing all identified issues.

---

## CONTEXT

You are the lead engineer on **Huntress**, an AI-powered bug bounty automation desktop application built with Tauri 2.0 (Rust backend) + React/TypeScript (frontend). Read `CLAUDE.md` for the full project identity, architecture, and coding standards.

**Current state as of March 11, 2026:**
- Phases 1-24 COMPLETE (29 hunting agents, orchestrator engine, ReactLoop execution, validation pipeline, fuzzing infrastructure, provider fallback, knowledge graph, HackerOne integration, training pipeline scaffolding)
- ~85K LOC TypeScript (205+ files), ~5.5K LOC Rust (10 files)
- 1,061 TypeScript tests, 68 Rust tests
- TypeScript and Rust both compile with 0 errors

**Critical finding:** A comprehensive 6-agent parallel audit identified **65 issues** (7 CRITICAL, 12 HIGH, 14 MEDIUM, 14 LOW, 18 additional) that prevent the system from functioning end-to-end for real HackerOne bug bounty hunting. The architecture and domain expertise are genuinely strong — the system prompts are expert-level, the Rust security primitives are solid, and the infrastructure layer is production-quality. The issues are primarily **wiring failures** — components that individually work but aren't properly connected.

**The complete fix document is at `FIX_DOCUMENT.md`.** This file contains every issue with exact file paths, line numbers, current broken code, explanations of what's wrong, and the specific fix required. Read it in full before making any changes.

---

## WHAT MUST BE FIXED

There are **19 blocks** of fixes organized into 4 rounds. Each block groups related issues that should be fixed together. The blocks are ordered by priority — earlier blocks unlock the most critical functionality.

### ROUND 1 — CRITICAL PATH (Makes the system functional)

These 6 blocks are the minimum required for the system to work at all. Without them, the chat is a dumb LLM wrapper, 5 core agents don't exist, the tool-use loop is broken, scope validation can be bypassed, reports go to HackerOne without review, and the IPC layer is wide open.

**Block 2 — Agent Registration (smallest fix, largest impact):**
- Add 5 missing side-effect imports to `src/agents/agent_router.ts` (after line 24): `./ssrf_hunter`, `./xss_hunter`, `./sqli_hunter`, `./cors_hunter`, `./subdomain_takeover_hunter`
- Delete `src/agents/host_header_hunter.ts` entirely (duplicate of `host_header.ts` with same catalog ID `'host-header-hunter'` causing silent collision)

**Block 3 — Provider Wiring (one-line fix):**
- Add `get supportsToolUse(): boolean` getter to `ResilientProvider` class in `src/core/providers/provider_fallback.ts` (around line 93) that returns `this.states[0]?.entry.provider.supportsToolUse ?? false`
- Without this, the orchestrator's entire Coordinator-Solver tool-use loop is dead code when provider fallback is active

**Block 4 — Scope Validation (3 fixes, safety-critical):**
- Fix 4.1: Replace substring matching in `orchestrator_engine.ts:1264-1268` with proper URL parsing and domain boundary checks. Current code: `args.target.includes(s) || s.includes(args.target)` allows `evil-example.com` to pass for scope `example.com`. Also fix `matchesWildcard()` at lines 1739-1743 where `*.example.com` matches `notexample.com`
- Fix 4.2: Fix `compile_pattern()` in `safe_to_test.rs:509-520` to use `regex::escape()` before replacing wildcards. Currently only escapes `.` and `*`, leaving `|`, `+`, `?`, `[` etc. as live regex operators
- Fix 4.3: Fix IPC return type mismatches — Rust `load_scope` returns `Result<String>` but TS expects `ScopeEntry[]`; Rust `validate_target` returns `Result<bool>` but TS expects `ValidationResult` object

**Block 1 — Core Flow (makes chat drive agent hunting):**
- Rewrite `sendMessage()` in `HuntSessionContext.tsx:278-337` to route through the orchestrator engine instead of calling `engine.getProvider().sendMessage()` directly
- Fix `streamUserInput()` in `orchestrator_engine.ts:492-539` to include tool schemas (`ORCHESTRATOR_TOOL_SCHEMAS`) and `toolChoice: 'auto'` when a hunt is active

**Block 7 — HTTP Tool Scope:**
- Add scope validation to `http_request` handler (react_loop.ts:803-875), `fuzz_parameter` handler (lines 878-947), and `race_test` handler (lines 950-1078). These currently bypass both scope validation and the approval gate entirely

**Block 5 — Report Pipeline (3 fixes):**
- Fix 5.1: Import `ReportReviewModal` in `App.tsx` and wire it between `ReportEditor` and `submitToH1()`. Currently `ReportReviewModal` is never imported or rendered — the mandatory quality/duplicate review gate is completely bypassed
- Fix 5.2: Fix `ReportEditor.tsx:101` `handleSubmit` to submit the user-edited `markdown` state, not the original `report` prop. Currently user edits are silently discarded
- Fix 5.3: Fix binary attachment corruption in `h1_api.ts:202-239` — `uploadAttachment()` reads files as UTF-8 text via `read_tool_output`. Create a new Rust command for base64-encoded binary file reading

**Block 6 — IPC Security (3 fixes):**
- Fix 6.1: Add path validation to `write_file_text` (lib.rs:283), `delete_path` (lib.rs:312), `read_tool_output` (lib.rs:197), `create_symlink` (lib.rs:408), `create_output_directory` (lib.rs:214). Restrict to Huntress data directories. Model after existing `append_to_file` validation (lib.rs:226)
- Fix 6.2: Add program allowlist to `execute_training_command` (lib.rs:385-404)
- Fix 6.3: Add SQL statement prefix validation to `knowledge_db_query` (lib.rs:572-611) and `knowledge_db_execute` (lib.rs:615-628). Restrict `db_path` to Huntress data directory

### ROUND 2 — SAFETY & STABILITY (Makes it reliable)

**Block 8 — Approval Queue:**
- Replace single `pendingTask` useState in `App.tsx:344` with an array queue so multiple agents can request approval simultaneously without stomping each other
- Add callback cleanup for processed approvals in `window.__huntress_approval_callbacks` Map

**Block 9 — Context Window:**
- Implement sliding window with summarization for `conversationHistory` in `react_loop.ts:196`. Currently grows unbounded and will crash sessions when exceeding model context limits
- Add timeout enforcement for `timeout_seconds` parameter on `execute_command` — currently accepted in schema but never used

**Block 13 — HTTP Engine (3 fixes):**
- Replace `Buffer.byteLength` (Node.js API, crashes in browser) with `new TextEncoder().encode(body).byteLength` in `request_engine.ts:412`
- Replace fabricated TTFB `Math.round(totalMs * 0.3)` at line 407 with actual timing measurement
- Fix scope bypass at lines 204-207 that returns `true` for all targets in Node.js/test mode

**Block 10 — Chain Detection (2 fixes):**
- Replace random chain IDs in `chain_detector.ts:253` (`Date.now()` + `Math.random()`) with deterministic IDs based on rule + finding IDs so dedup works
- Wire `chainValidator` into the orchestrator's dispatch loop — it's stored as `this.chainValidator` but zero method calls exist

**Block 11 — Phase 23 Modules:**
- Wire `targetDedup` into task creation (check before queuing duplicate targets)
- Wire `h1DuplicateChecker` into finding handling in `handleAgentResult()` (check before flagging for submission)
- Wire `reportQuality` into report generation (score and enhance before submission)
- Wire `continuousMonitor` into hunt lifecycle (start with domains on hunt start, stop on abort)
- All 4 modules are currently stored as private fields in orchestrator_engine.ts but have zero method calls

### ROUND 3 — COMPLETENESS (Makes it production-grade)

**Block 12 — Orchestrator Fixes:**
- Make `selectStrategy()` (orchestrator_engine.ts:679-690) actually start a hunt by calling `startHunt()` with the selected strategy. Currently it only emits a UI message
- Add tool schemas to `streamUserInput()` (lines 492-539) when hunt is active
- Implement `parseResponse()` (lines 1815-1824) to extract structured content from text responses

**Block 15 — Rust Backend (4 fixes):**
- Move 17 `unwrap()` regex calls in `pty_manager.rs:249-289` to `LazyLock<Regex>` statics (also fixes perf — regexes currently recompiled per PTY read)
- Replace `expect()` calls in `secure_storage.rs` Tauri handlers (lines 382, 401, 417, 441, 456) with `map_err` to return errors instead of panicking
- Add `"socks"` to reqwest features in `Cargo.toml` (SOCKS5 proxy silently fails without it)
- Replace unmaintained `dotenv = "0.15"` with `dotenvy = "0.15"` in Cargo.toml

**Block 16 — Auto-Approve:**
- Pass `settings.autoApprove` from `SettingsContext` through `HuntSessionContext` → `OrchestratorConfig` → `ReactLoop.autoApproveSafe`. Currently the auto-approve checkboxes in SettingsPanel (lines 269-284) store values but they're never consumed by the engine

**Block 14 — Agent Quality:**
- Fix `recon_agent.ts:229` `reportFindings()` to return `[...this.findings]` (defensive copy, consistent with all other agents)
- Remove unused `ReactLoopConfig` import from 13 agent files
- Extract `BaseReactAgent` class to eliminate ~5,600 lines of duplicated boilerplate (optional but highly recommended)

**Block 17 — Cross-Agent Data:**
- Populate `observations` field in ReconAgent's `AgentResult` with discovered subdomains, endpoints, technologies, WAF info
- Pass recon observations to subsequent hunter agents as task context so they don't start from scratch

**Block 18 — Tool Checking:**
- Call existing Rust commands `check_installed_tools` / `get_missing_required_tools` during engine init in `HuntSessionContext`
- Surface missing tools as a warning to the user
- Pass available tools list to agents so they can adapt strategies

**Block 19 — Session Persistence:**
- Add `checkpoint()` method to OrchestratorEngine that serializes task queue, findings, chains, blackboard, phase, agent history
- Call after each dispatch batch completes
- Add `restore()` method that rebuilds state from checkpoint
- On app restart, detect and offer to resume from checkpoint

### ROUND 4 — POLISH (Additional items A1-A18)

All 18 items are documented in `FIX_DOCUMENT.md` under "ADDITIONAL ISSUES." Fix in the order listed:
- A1: Shell heredoc in write_script (react_loop.ts:746-748)
- A2: stop_hunting flag conflation (react_loop.ts:345)
- A3: Multi-tool-call logging (react_loop.ts:321)
- A4: Error detection off-by-one (react_loop.ts:372)
- A5: Wire FindingsPanel component (currently dead code)
- A6: TrainingDashboard data fetch (returns null unconditionally)
- A7: Chat approval buttons non-functional (ChatMessage.tsx:224-236)
- A8: Ctrl+L binding does nothing (ChatInterface.tsx:81)
- A9: Chat virtualization for 1000+ messages
- A10: Context value memoization (HuntSessionContext.tsx:532-555)
- A11: Knowledge system initialization race condition
- A12: Secure storage OS keychain integration
- A13: Kill switch atomic persistence
- A14: Streaming fallback garbled content (provider_fallback.ts:198)
- A15: Shell injection in validator.ts curl commands (lines 1019-1207)
- A16: Shodan API key logged in URLs (extended_recon.ts:574)
- A17: DNS canary validation logic incorrect (oob_server.ts:668)
- A18: Burp Collaborator provider non-functional (oob_server.ts:486-507)

---

## EXECUTION RULES

1. **Read `FIX_DOCUMENT.md` first.** It has every issue with exact line numbers and code.
2. **Read each file before editing.** Understand surrounding code context.
3. **Fix one block at a time.** Complete all issues in a block before moving to the next.
4. **Verify after each block.** Run `npm run build` (or `npx tsc --noEmit`) and `cargo check` in `src-tauri/`.
5. **Run full tests after every 2-3 blocks.** `npm test` and `cd src-tauri && cargo test`.
6. **Do not introduce new features.** Only fix documented issues. Keep changes minimal and focused.
7. **Follow CLAUDE.md standards.** No `any` types, no `unwrap()` in production Rust, explicit argv (no shell interpolation), scope validation on all target interactions, approval gate on all commands.
8. **Do not over-engineer.** The fix document specifies what to change. Do exactly that.
9. **Preserve existing tests.** All 1,061 TypeScript and 68 Rust tests must continue to pass.
10. **Do not create documentation files** unless explicitly asked.

---

## VERIFICATION CHECKLIST

After all blocks are complete, verify these end-to-end flows work:

- [ ] App launch → SetupWizard → model selection → API key → setup complete
- [ ] Import → H1 program URL → briefing with strategy cards
- [ ] Select strategy → orchestrator dispatches agents → agents request approval
- [ ] Multiple concurrent approval requests don't stomp each other
- [ ] Agent commands execute after approval → findings appear in chat + side panel
- [ ] All 29 agents registered in catalog (no silent failures)
- [ ] Scope validation blocks `evil-example.com` when scope is `example.com`
- [ ] HTTP tools (http_request, fuzz_parameter, race_test) enforce scope
- [ ] Finding → ReportEditor → edits preserved → ReportReviewModal gates submission
- [ ] Quality score + duplicate risk shown in review modal
- [ ] Report submits to H1 with correct formatting and working binary attachments
- [ ] Context window doesn't crash on 80+ iteration sessions
- [ ] Chain detection produces no duplicate reports
- [ ] Provider fallback works with tool use enabled
- [ ] Kill switch persists across restart
- [ ] Auto-approve settings actually auto-approve passive recon
- [ ] Recon discoveries flow to subsequent hunters as context
- [ ] `cargo clippy -- -D warnings` passes with 0 warnings
- [ ] No `unwrap()` in production Rust code paths
- [ ] No unrestricted filesystem IPC commands

---

## KEY FILE REFERENCES

| File | Purpose | Key Lines |
|------|---------|-----------|
| `FIX_DOCUMENT.md` | Complete issue catalog with fixes | All |
| `CLAUDE.md` | Architecture and coding standards | All |
| `src/contexts/HuntSessionContext.tsx` | Module init, chat flow | 278-337 (sendMessage), 245-263 (engine config) |
| `src/core/orchestrator/orchestrator_engine.ts` | Main AI brain | 1264-1268 (scope), 679-690 (selectStrategy), 492-539 (streaming), 328-331 (Phase 23 fields) |
| `src/core/engine/react_loop.ts` | Agent execution loop | 803-1078 (HTTP handlers), 196 (context history), 746-748 (write_script) |
| `src/core/providers/provider_fallback.ts` | Resilient provider | 93 (class def, missing supportsToolUse) |
| `src/agents/agent_router.ts` | Agent registration | 18-24 (side-effect imports) |
| `src/agents/standardized_agents.ts` | Agent import chain | 11-48 (imports) |
| `src/App.tsx` | Layout, modals, approval | 344 (pendingTask), 427-463 (ReportEditor modal) |
| `src/components/ReportEditor.tsx` | Report editing | 101 (handleSubmit) |
| `src/components/ReportReviewModal.tsx` | Review gate (dead code) | All |
| `src/core/reporting/h1_api.ts` | HackerOne API | 202-239 (uploadAttachment) |
| `src/core/http/request_engine.ts` | HTTP client | 412 (Buffer), 407 (TTFB), 204-207 (scope bypass) |
| `src/core/orchestrator/chain_detector.ts` | Chain detection | 253 (random IDs) |
| `src/core/orchestrator/chain_validator.ts` | Chain validation (dead code) | 69-117 (validateChain) |
| `src-tauri/src/lib.rs` | Tauri commands | 283-404 (filesystem/command IPC) |
| `src-tauri/src/safe_to_test.rs` | Scope validation | 509-520 (compile_pattern) |
| `src-tauri/src/pty_manager.rs` | Command execution | 249-289 (unwrap regex) |
| `src-tauri/src/secure_storage.rs` | Encrypted vault | 382-456 (expect calls) |
| `src-tauri/Cargo.toml` | Rust dependencies | reqwest features, dotenv |

---

## BEGIN

Read `FIX_DOCUMENT.md` first. Then start with **Block 2** — adding 5 import lines and deleting one duplicate file. This is the smallest change with the largest impact: it makes 5 core vulnerability hunters (SSRF, XSS, SQLi, CORS, Subdomain Takeover) available to the orchestrator.

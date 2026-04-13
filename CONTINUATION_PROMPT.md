# Huntress — Development Continuation Prompt

> **Last updated:** April 12, 2026 (Session 25)
> **Build state:** 2,029 TS tests (82 files, +151 new), 108 Rust tests (+7 new), tsc clean, clippy clean
> **Session history:** 25 sessions, 12 hunts (6 Juice Shop + 6 real-world HackerOne)
> **North star:** First accepted HackerOne vulnerability submission
> **Platform score:** 8.0/10 — Phase 1 auth pipeline shipped, 7 runtime issues from Hunt #12 monitoring fixed
> **This session's focus (Session 25):** Live Hunt #12 monitoring on Wallet Telegram program, 7 issues caught & fixed, PTY retention policy added, recon dispatch loop unblocked

## Session 25 changelog (2026-04-12)

**Live-hunt monitoring run** caught and fixed 7 issues during a Wallet-on-Telegram hunt. Code + tests + docs all green.

| # | Issue | Fix landed in |
|---|---|---|
| 1 | Disk full during cargo build (os error 28) | `cargo clean -p huntress` (operational) |
| 2 | `libssl-dev` missing → rust-lld link failure | `apt-get install -y libssl-dev` (operational) |
| 3 | `assetfinder` exit 126 inside sandbox — missing tool | `src/core/orchestrator/recon_pipeline.ts`, `src/agents/recon_agent.ts` |
| 4 | `curl` exit 6 (DNS fail) in sandbox while httpx worked | `src-tauri/src/sandbox.rs` (injected HTTP_PROXY/HTTPS_PROXY → tinyproxy) |
| 5 | URL escaping bug: `wallettg.com"` stray quote | `src/core/engine/react_loop.ts` (`extractTargetFromCommand` + `sanitizeHost`) |
| 6 | Hunt stuck in recon loop — 16 min, 0 specialist dispatches, 0 `http_request` calls | `src/agents/recon_agent.ts` — dropped hardcoded `maxIterations: 60`, now uses centralized `30`; added explicit "stop_hunting early" prompt |
| 7 | Sandbox + browser-subprocess leak on Huntress shutdown | `src-tauri/src/lib.rs` (RunEvent::ExitRequested hook), `src-tauri/src/agent_browser.rs` (`kill_all`) |
| + | PTY `.cast` recordings accumulated 2,696 files / 21MB | `src-tauri/src/pty_manager.rs` (`prune_recordings` at startup, 7-day / 500-file cap) + 4 unit tests |

**Phase 1 auth pipeline status:** all code-side work shipped (Q1 env-vars, Q2 agent prompt, Q3 session_label, Q4 Telegram preset, Q6 Gap 5 probeBearer, Q6 Gap 7 redirect header strip). Hunt #12 did not exercise any of it — agents never reached `http_request`/auth-header-injection. Root cause was Issue #6 (recon loop), now fixed — next hunt will exercise the full Phase 1 pipeline.

**Phase 2+ work unchanged** — see `DEEPER_AUTH_RESEARCH_AND_PLAN.md` §7 "Remaining work across all phases".


---

## Section 1: How to Use This Document

Read **Sections 1-4 first** — they contain everything needed to understand the current state and the work ahead. Read target files on-demand when you start implementing. Don't preload context you don't need.

**Do NOT read** `LIVE_HUNT_ROADMAP.md` or `PRODUCTION_ROADMAP.md` unless explicitly asked. They are historical and stale.

**Read `CLAUDE.md`** after this document — the Architecture Invariants and Safety Rules are hard constraints that override everything else.

---

## Section 2: What Huntress Is

Tauri 2.0 desktop app (React 19 + TypeScript frontend, Rust backend) that automates HackerOne bug bounty hunting. An AI orchestrator (Claude Opus) coordinates **29 specialized vulnerability-hunting agents** (Haiku/Sonnet) through real ReAct loops with native tool use. All HTTP traffic flows through a single security chokepoint enforcing scope, rate limiting, stealth headers, and WAF detection.

### Current Working Subsystems (verified Hunt #11)

| Subsystem | Status | Evidence |
|---|---|---|
| Docker sandbox | ✅ WORKING | IDOR Hunter ran 521s, 46 tool calls, mapped 50+ API endpoints |
| Tinyproxy scope enforcement | ✅ WORKING | HTTP 200 through proxy, scope filter applied |
| ReAct loop + tool dispatch | ✅ WORKING | Agents cycle through 40+ queued tasks |
| Cost router (Haiku/Sonnet) | ✅ WORKING | Recon → Haiku, IDOR/XSS/SSTI → Sonnet |
| Hallucination gate | ✅ WORKING | Blocked findings from agents with <3 HTTP requests |
| Global API limit detection | ✅ WORKING | Halted hunt on credit exhaustion |
| Approval gate (60s timeout) | ✅ WORKING | Auto-denied 7 risky commands when unattended |
| Circuit breaker | ✅ WORKING | 5-error window → hunt halt |
| Dispatch loop concurrency | ✅ WORKING | 5 agents running, 40+ queued |
| Phase A browser tools | ⚠️ DEFINED | Agents receive schemas but Playwright import fails in WebView (see I2) |
| Auth detection wizard | ✅ WORKING | Opens correctly when wall detected |
| Auth browser capture (Phase B) | ✅ WORKING | Node.js subprocess launches Playwright in separate process |

---

## Section 3: Hunt #11 Live Run — Issues Observed (Your Backlog)

**Context:** First hunt after Session 23's stack build-out. Target: Wallet on Telegram (HackerOne). Budget: $48. Spent: $9.03 before external API credit exhaustion halted hunt.

### What Ran Successfully
- 3 Recon agents completed (603s, 833s, 851s) — 224 total tool calls
- Tech-stack filter dispatched 24 follow-up specialists based on real recon output
- IDOR Hunter extracted full API schema from `/static/js/openapi.d0fa3c343d.js` — 50+ endpoints enumerated
- SSTI Hunter correctly identified React SPA architecture → no server-side template injection possible
- Host Header Hunter completed with 3-step cache verification attempts

### Issues Discovered (drive this session's work)

Each issue has: **Symptom → Root cause → Specific fix → Files → Acceptance criterion.** Work them in order; higher priorities block lower ones.

---

#### I1 — `specialist_request` validation pipeline error (P1 CRITICAL, noisy)

**Symptom:**
```
[!] Validation failed for "Specialist requested: xss_hunter":
    No validator available for type: specialist_request
```
Appears for every specialist request during hunt, cluttering logs and making the platform look broken.

**Root cause:** `request_specialist` tool calls are emitted through the same pipeline as findings. They enter `validateFinding()` which dispatches by `vulnerabilityType` — but `'specialist_request'` is an orchestration directive, not a vulnerability type. No validator matches.

**Specific fix:** Filter `specialist_request` entries OUT of the finding pipeline at the emit site. They should route directly to the orchestrator's `dispatchAgent()` path, never through `validateFinding()`.

**Files:**
- `src/core/orchestrator/orchestrator_engine.ts` — `handleAgentResult()` near line 1890, check for `vulnerabilityType === 'specialist_request'` and short-circuit
- `src/core/engine/react_loop.ts` — verify `handleRequestSpecialist()` doesn't route through `onFinding`

**Acceptance criterion:** Hunt runs for 5+ minutes with specialist requests fired; zero `No validator available` errors in logs.

**Test:** Add unit test that dispatches a `specialist_request` finding and asserts `validateFinding()` is NOT called.

---

#### I2 — Browser module error for ALL agents (P1 CRITICAL, blocks Phase A)

**Symptom:** Recon agents report:
```
Browser navigation: Consistent binding error on all navigation attempts
("Importing binding name 'default' cannot be resolved by star export entries")
```

**Root cause:** Phase A enabled browser tools for all 27 agents. When an agent calls `browser_navigate`, `react_loop.ts` at line 1486 does `await import('../validation/headless_browser')`. That module has a STATIC `import { chromium } from 'playwright-core'` at line 17. Tauri's WebView cannot resolve Node.js native modules — same root cause as the auth capture bug fixed earlier this session.

**This means:** Phase A ships at the schema level but **zero agents can actually launch a browser**. Every browser tool call fails silently.

**Specific fix (recommended — Option A):** Apply the same Node.js subprocess pattern already used for `auth_browser_capture.ts`:

1. Create `scripts/agent_browser.mjs` — a persistent Node.js subprocess that accepts JSON commands on stdin (`navigate`, `evaluate`, `click`, `get_content`) and returns JSON results on stdout.
2. In `react_loop.ts`, replace `ensureBrowserPage()` with an IPC client that talks to this subprocess via `execute_training_command` (long-lived process per hunt, not per tool call — reuse the stdin channel).
3. Remove or guard the `import type { HeadlessBrowser }` and direct Playwright references in `react_loop.ts`.

**Alternative (Option B, simpler but less powerful):** Disable browser tools for agents by default (`browserEnabled: false`), keep only the schemas available. Document that browser capabilities require Option A in a future session.

**Files:**
- `src/core/engine/react_loop.ts` — all browser tool handlers (`handleBrowserNavigate`, `handleBrowserEvaluate`, `handleBrowserClick`, `handleBrowserGetContent`) at lines ~1537-1820
- `src/core/validation/headless_browser.ts` — may need refactor to `import type` only
- `scripts/agent_browser.mjs` — new file, follow `scripts/auth_capture.mjs` pattern
- `src/core/auth/auth_browser_capture.ts` — reference implementation

**Acceptance criterion:** XSS Hunter calls `browser_navigate` on an in-scope URL → receives a rendered page with `dialogDetected`, `consoleLogs`, and `pageSource` fields populated. Zero `binding name 'default'` errors.

**Test:** Integration test that launches XSS Hunter against Juice Shop search endpoint and verifies `<script>alert(document.domain)</script>` triggers `dialogDetected: true` in the result.

---

#### I3 — Approval gate blocks recon from using security tools (P2 HIGH, UX)

**Symptom:** Agents submit reasonable commands (`sqlmap`, `curl -H "X-Forwarded-Host: attacker.com"`, custom scripts for JS bundle analysis) → approval prompt appears → user not watching screen → 60s timeout → auto-denied → agent gives up.

**Evidence from Hunt #11:** 7 auto-denials in ~3 minutes blocked:
- Template injection testing (`echo '{{7*7}}' | curl -X POST`)
- Python script to extract API endpoints from React bundle
- Host header injection (`X-Forwarded-Host: attacker.com`)
- sqlmap against a public endpoint
- Prototype pollution URL encoding tests
- DOM XSS sink extraction from JS bundles

**Root cause:** No auto-approval defaults. Every command requires manual approval, blocking unattended hunts.

**Specific fix:** Add an **Auto-approval Categories** section to the Settings UI with these defaults ON:

| Category | Default | Commands | Rationale |
|---|---|---|---|
| Passive recon | ON | `curl`, `wget`, `whois`, `dig`, `nslookup`, `host`, `subfinder`, `assetfinder`, `httpx`, `wafw00f`, `whatweb` | Read-only; no server state change |
| Safe active recon | ON | `nmap` (no -sS), `gobuster`, `ffuf`, `dirb`, `nuclei` default templates | Standard bug bounty recon |
| Injection testing (passive) | ON | curl with injection headers/payloads in GET requests | Tests server response, no state change |
| Mutation/exploit | OFF | `sqlmap`, `hydra`, POST/PUT/DELETE, any script category | Requires explicit approval |

**Files:**
- `src/contexts/SettingsContext.tsx` — add `autoApproveCategories: { passiveRecon: boolean; safeActiveRecon: boolean; ... }`
- `src/components/SettingsPanel.tsx` — new "Auto-approval" tab in settings
- `src/core/engine/safety_policies.ts` — add `classifyCommand()` that returns category
- `src/contexts/HuntSessionContext.tsx` — `handleApprovalRequest()` checks category against settings, auto-approves if matched

**Acceptance criterion:** Hunt runs end-to-end on Juice Shop without any user interaction required. Only mutation commands (database-modifying sqlmap runs, etc.) prompt for approval.

**Test:** Settings toggle test + unit test that `classifyCommand('curl https://example.com/api/users')` returns `'passive_recon'`.

---

#### I4 — Auth cannot be added mid-hunt (P2 HIGH, blocks bounty discovery)

**Symptom:** IDOR Hunter discovered 50+ endpoints but couldn't test any — all return 401 without auth. The auth wizard only runs at import time. Once the hunt starts unauthenticated, there's no way to add auth and retry the queued agents.

**Specific fix:** Add **[+ Add Auth]** button to the hunt status UI (near the existing [KILL] button). Clicking:
1. Re-opens `AuthWizardModal` with the active hunt's scope
2. On save, calls new `HuntSessionContext.addAuthToActiveHunt(profileId)`
3. That method attaches the auth session to the HttpClient AND triggers a reprioritization so queued agents re-dispatch with auth context

**Files:**
- `src/components/HuntStatusBar.tsx` (or wherever KILL button lives) — add button
- `src/contexts/HuntSessionContext.tsx` — new `addAuthToActiveHunt()` method
- `src/core/orchestrator/orchestrator_engine.ts` — new `attachAuthSession(sessionId)` + trigger reprioritize
- `src/core/engine/react_loop.ts` — verify agent picks up auth from fresh session

**Acceptance criterion:** Start unauthenticated hunt → IDOR Hunter reports 401s → click [+ Add Auth] → capture Telegram auth → queued agents pick up auth on next dispatch → IDOR Hunter produces real findings.

**Test:** Integration test that starts a hunt, queues an agent, injects auth mid-hunt, and verifies the agent sees the auth header on its next HTTP request.

---

#### I5 — Orphan containers on agent failure (P3 MEDIUM, resource leak)

**Symptom:** Hunt #10 left 6 containers running for 37+ minutes after agents failed. Cleaned up manually during Session 23 debugging. On long-running systems this exhausts Docker resources.

**Root cause:** `SandboxExecutor.destroy()` is not called on all failure paths. When an agent crashes before cleanup, `cmd: sleep infinity` keeps the container alive indefinitely.

**Specific fix:**
1. Add a container reaper: on orchestrator init, call `reap_orphans()` that lists all containers with label `huntress-managed` (but NOT `huntress-qdrant` or `huntress-juice-shop`) that are older than 10 minutes and not in the active sandbox map, then force-remove them.
2. Add `finally`-block cleanup in agent dispatch to guarantee `destroy()` runs on all exit paths.

**Files:**
- `src-tauri/src/sandbox.rs` — new `pub async fn reap_orphans()` + Tauri command binding
- `src/core/tools/sandbox_executor.ts` — new static `reapOrphans()` that invokes the Rust command
- `src/core/orchestrator/orchestrator_engine.ts` — call `SandboxExecutor.reapOrphans()` on init; wrap `dispatchAgent()` execution in try-finally that always calls `destroy()`

**Acceptance criterion:** After hunt terminates (any way — success, failure, kill, API error), running this returns zero rows:
```bash
docker ps --filter label=huntress-managed | grep -v qdrant | grep -v juice-shop
```

**Test:** Rust test that creates 3 orphan containers, calls `reap_orphans()`, asserts they're gone.

---

#### I6 — Severity calibration gate never triggered in practice (P4 VERIFICATION)

**Status:** Code shipped Session 23, 20 unit tests pass. But not exercised through the full pipeline because Hunt #11 produced no high-severity findings.

**Specific fix:** Integration test that seeds findings matching each of the 7 calibration rules through the full `handleReportFinding()` pipeline and verifies corrections.

**File:** `src/tests/integration/severity_calibration_e2e.test.ts` (new)

**Acceptance criterion:** 7 integration tests, one per calibration rule (preconnect reflection, info disclosure cap, self-XSS, missing headers, open redirect standalone, version disclosure, CORS without proof), all passing through the full pipeline.

---

#### I7 — Cross-subdomain dedup never triggered (P4 VERIFICATION)

**Status:** Code shipped Session 23, 13 unit tests pass. Not exercised in Hunt #11.

**Specific fix:** Integration test seeding findings on `api.example.com`, `www.example.com`, `cdn.example.com` with same vuln type + parameter; assert 1-finding collapse with highest severity retained.

**File:** `src/tests/integration/dedup_e2e.test.ts` (new)

**Acceptance criterion:** 3-subdomain test collapses to 1 finding with severity = max(inputs).

---

#### I8 — Auth browser capture never validated end-to-end (P4 VERIFICATION)

**Status:** Code path confirmed working in dev (Vite errors resolved by Node.js subprocess pattern). But no real end-to-end click-through test.

**Specific fix:** Manual E2E using Wallet on Telegram as target:
1. Import program → auth wizard appears
2. Click [AUTO-CAPTURE FROM BROWSER]
3. Visible browser opens to Telegram login
4. Log in normally
5. Verify captured tokens auto-fill wizard form (bearer token OR cookies OR custom headers based on what Telegram actually uses)

**Acceptance criterion:** After login, wizard form shows auth method = `bearer` or `custom_header`, token field populated, [TEST AUTH] returns HTTP 2xx/3xx.

**No new tests** — manual validation only.

---

## Section 4: Prioritized Work Backlog

Work top-down. Higher priorities block lower ones.

### P1 — Critical Correctness (blocks hunt quality)

| # | Task | Estimated time |
|---|------|----------------|
| I1 | Filter `specialist_request` from finding validation pipeline | 30 min |
| I2 | Route agent browser tools through Node.js subprocess | 3-4 hours |

### P2 — UX Blockers (prevents unattended hunts)

| # | Task | Estimated time |
|---|------|----------------|
| I3 | Auto-approval categories with safe defaults | 2-3 hours |
| I4 | [+ Add Auth] button for mid-hunt auth injection | 2 hours |

### P3 — Infrastructure Hygiene

| # | Task | Estimated time |
|---|------|----------------|
| I5 | Container reaper + guaranteed cleanup on all exit paths | 2 hours |

### P4 — Verification (prove Session 23 work is end-to-end correct)

| # | Task | Estimated time |
|---|------|----------------|
| I6 | Integration tests for severity calibration gate (7 rules) | 1 hour |
| I7 | Integration tests for cross-subdomain dedup | 30 min |
| I8 | Manual E2E test of auth browser capture on Telegram | 30 min |

### P5 — Deferred to future sessions (do not work on these)

- XBOW benchmark harness
- Multi-target parallel hunting
- Canary-based IDOR validation (two-account auth pairing)
- Additional deterministic validators (SSRF blind, JWT crypto)
- JS-rendering crawler

---

## Section 5: Hard Constraints (Do Not Violate)

These are load-bearing decisions. Violating them breaks the system.

1. **HttpClient is the single HTTP chokepoint.** Every agent request goes through `request_engine.ts`. Never create alternative HTTP paths.
2. **Agents use fire-and-forget dispatch.** Orchestrator dispatches via `dispatchAgent()` and continues. Results arrive via `handleAgentResult()`. Never make the dispatch loop synchronous.
3. **Scope validation is default-deny.** `safe_to_test.rs` blocks everything not explicitly in scope. Changes require positive AND negative test cases.
4. **Tiered model routing is locked.** Haiku for simple agents, Sonnet for moderate/complex. `COMPLEXITY_LOCKED_AGENTS` prevents keyword-based upgrades. **Anthropic models only** — never add OpenAI/Google/local model defaults.
5. **Validation pipeline is non-blocking.** Findings display immediately with `pending`, update asynchronously.
6. **Approval gate is mandatory** for commands that execute on the system. Auto-approval (I3) requires opt-in per category with explicit user toggle.
7. **API keys go through secure storage only.** AES-256-GCM with HKDF. Never log or print keys.
8. **`safe_to_test.rs`, `kill_switch.rs`, and the approval gate core are FROZEN** — do not modify without explicit user request.

---

## Section 6: Coding Standards

**TypeScript:** Strict mode, no `any`. Interfaces for extensible shapes. `async/await` only. Functional React with hooks. Tauri `invoke()` calls must have typed command/response pairs.

**Rust:** `thiserror` for errors, `anyhow` only in binary entry points. Exhaustive pattern matching. `Arc<Mutex<T>>` with minimal lock duration. `tracing` crate for logging.

**Testing:** Every change needs tests. Scope validation changes need positive AND negative cases. Security-critical changes need explicit deny-path tests.

**Verification after every task** (all four must pass):
```bash
npx tsc --noEmit --skipLibCheck     # must be zero errors
npx vitest run                       # must be >= 1,878 passed
cd src-tauri && cargo test           # must be >= 101 passed
cargo clippy -- -D warnings          # must be clean
```

---

## Section 7: Behavioral Contract

### You MUST:
- Read target files before modifying them. Never guess code.
- Run the verification suite after every task. Fix errors immediately.
- Write tests for every change (Rust changes need at least one test; TS changes to core logic need tests).
- Match existing patterns. Look at neighboring code before writing new code.
- Update this document when tasks complete. Remove finished items. Update build state numbers.
- Mark completed items in the session summary.

### You MUST NOT:
- Refactor code you did not change.
- Add comments/docstrings to untouched code.
- Work on items not in the current session's scope.
- Modify `safe_to_test.rs`, `kill_switch.rs`, or the approval gate core.
- Add OpenAI/Google/local model defaults.
- Skip validation or duplicate checking in the finding pipeline.
- Create alternative HTTP paths that bypass `request_engine.ts`.
- Re-verify infrastructure already proven in Hunt #11 (Section 10 below).

---

## Section 8: Session 23 Completed Work (Reference Only — Do Not Redo)

| Phase | What | Tests added |
|-------|------|-------------|
| A | Universal browser tool schemas for all 27 agents (**schema-level only — I2 blocks execution**) | 29 |
| C1 | Evidence requirements + H1 Core Ineligible list in every agent's system prompt | 0 (prompt) |
| C2 | Severity calibration gate (7 rules, deterministic correction) | 20 |
| C3 | Cross-subdomain deduplication via `extractRootDomain()` | 13 |
| C4 | Agent prompt fixes (host_header, cors_hunter, cache_hunter) | 0 (prompt) |
| C5 | Report quality scorer severity inflation penalty | 6 |
| B | Auth browser capture via Node.js subprocess | 7 |
| P5 | NoSQL injection + BOLA deterministic validators | 10 |
| Sandbox | 3-fix cascade: `user: hunter`, `cmd: sleep infinity`, `readonly_rootfs: false` | — |

**Net test delta:** +85 tests. Total: 1,878 TS tests, 101 Rust tests.

---

## Section 9: Key File Paths

| Path | Purpose | Related issues |
|------|---------|----------------|
| `src/core/orchestrator/orchestrator_engine.ts` | Dispatch loop, finding pipeline | I1, I4, I5 |
| `src/core/engine/react_loop.ts` | ReAct loop, tool dispatch, browser handlers | I1, I2 |
| `src/core/engine/tool_schemas.ts` | Tool definitions | — |
| `src/core/engine/safety_policies.ts` | Command safety classification | I3 |
| `src/core/validation/validator.ts` | 27 validators + passthroughs | I6 |
| `src/core/validation/headless_browser.ts` | Playwright integration | I2 |
| `src/core/auth/auth_browser_capture.ts` | **Reference pattern for Node.js subprocess (I2)** | I2 |
| `src/core/orchestrator/finding_dedup.ts` | Cross-subdomain dedup | I7 |
| `src/core/tools/sandbox_executor.ts` | Docker sandbox lifecycle | I5 |
| `src/contexts/HuntSessionContext.tsx` | Hunt state, auth pipeline | I4 |
| `src/contexts/SettingsContext.tsx` | Settings | I3 |
| `src/components/AuthWizardModal.tsx` | Auth wizard + [AUTO-CAPTURE FROM BROWSER] | I4, I8 |
| `src/components/SettingsPanel.tsx` | Settings UI | I3 |
| `src-tauri/src/sandbox.rs` | Docker container creation | I5 |
| `scripts/auth_capture.mjs` | **Reference for Node.js subprocess pattern (I2)** | I2 |

---

## Section 10: Verified Infrastructure Invariants (Hunt #11)

These are proven to work. **Do NOT re-test or re-debug without a specific failure reason.**

1. Docker sandbox creation with `user: hunter`, `cmd: sleep infinity`, `readonly_rootfs: false`
2. Tinyproxy binding on 127.0.0.1:3128 with scope filter
3. HTTP routing through proxy (curl from inside container returns HTTP 200)
4. Tool execution via `docker exec` (subfinder, httpx, curl, nmap all work)
5. ReAct loop adaptive iteration budget (30/80/120)
6. Tech-stack filter correctly suppresses irrelevant agents
7. Cost router tiers Haiku vs Sonnet correctly
8. Hallucination gate blocks low-evidence findings
9. Circuit breaker halts on consecutive API errors
10. Approval gate timeout triggers auto-deny at 60s
11. Auth wizard opens on import when auth wall detected
12. Auth browser capture invokes Node.js subprocess cleanly (Vite errors resolved)

---

## Section 11: Quick Reference

### Launch Huntress
```bash
docker compose --profile testing up -d   # Qdrant + Juice Shop
npm run tauri dev                         # launches desktop app
```

### Kill stuck containers (manual cleanup if I5 not yet shipped)
```bash
docker ps --format "{{.Names}}" | grep "^huntress-" \
  | grep -v "huntress-qdrant\|huntress-juice-shop" \
  | xargs -r docker rm -f
```

### Research documents (read only when relevant)
| Path | When to read |
|------|--------------|
| `docs/RESEARCH_H1_REPORT_QUALITY.md` | Before any work on report quality / evidence requirements |
| `docs/PHASE_NEXT_PLAN.md` | Already executed in Session 23 — reference only |

# Huntress Development Pipeline

Single source of truth for outstanding work, verified status, and delivery priorities.

- **Last updated:** 2026-04-28 (consolidation pass — verified every claim against code)
- **Project score:** 8.9 / 10 — all four real-H1 UX blockers shipped; PentAGI roadmap defined but no items implemented yet; report writer needs sectioning work
- **Test health:** 2,172 TypeScript tests passing (91 files) • 108 Rust tests passing • `tsc --noEmit` clean • `cargo clippy -D warnings` clean
- **External research:** PentAGI deep-dive at `docs/research/PENTAGI_DEEP_DIVE.md` — informs P1-3 adoption order. H1 report quality research at `docs/RESEARCH_H1_REPORT_QUALITY.md` — informs P0-4 + report writer rebuild.

---

## 1. How to Use This Document

This file is the **only** pipeline / roadmap document. It supersedes every prior planning doc:

- `PRODUCTION_ROADMAP.md` (deleted 2026-04-28 — Phases 1-3 + all blockers shipped, body was stale to Session 12)
- `LIVE_HUNT_ROADMAP.md` (deleted 2026-04-28 — historical)
- `CONTINUATION_PROMPT.md` (deleted 2026-04-28 — Session 25 backlog I1-I7 all shipped, I8 manual test carried forward below)
- `PRE_HUNT_TASKS.md` (deleted 2026-04-28 — all phases A-D shipped)
- `AUTH_RESEARCH_AND_CONTINUATION.md` (deleted 2026-04-28 — superseded)

When work is added, updated, or completed:

1. Update the relevant section here in the same commit as the code change.
2. Move finished items from the priority tables into **§7 Verified Complete**, with the commit SHA that landed them.
3. Do not create parallel planning documents. Longer-form design context goes under `docs/` and is referenced from the relevant priority item.

Priority levels use a fixed rubric:

| Level | Meaning |
|---|---|
| **P0 — Critical** | Blocks first real HackerOne submission. Work here before anything else. |
| **P1 — High** | Correctness or quality gap that will bite on a live hunt. |
| **P2 — Medium** | Edge cases, coverage, and polish. |
| **P3 — Deferred** | Captured intentionally; revisit after P0/P1/P2 clear. |

---

## 2. P0 — Critical (Blocks First Submission)

### P0-3 · Deterministic validators for the remaining pass-through types (in progress — bigger than previously documented)
**File:** `src/core/validation/validator.ts`

**Verified state (2026-04-28 audit):** validator.ts dispatches on **58 vulnerability types**. **24 have deterministic verification routines.** **34 are pass-through** (return based on agent confidence only). Prior PIPELINE versions claimed "only 3-4 pass-through remain" — that was wrong.

**Deterministic (24):**
xss_reflected, xss_dom, xss_stored (4-variant payload sweep + dialog/console detection), sqli_error (POST-body sweep × 4 triggers), sqli_blind_time (`deriveSqlBaselineUrl` + timing diff), ssrf (active OOB injection via interactsh), idor + bola (`validateBrokenAccess` two-identity differential), open_redirect (Playwright redirect chain), xxe (blind-OOB DTD fetch), command_injection (5 shell-exec OOB shapes), path_traversal (5 encoding bypass variants), ssti (10 SSTI_BODY_FIELDS), cors_misconfiguration (preconnect + clean-origin control), host_header_injection (7 override headers), prototype_pollution (browser chain mutation), nosql_injection (MongoDB pattern + differential), oauth_missing_state, oauth_downgrade_attack, oauth_weak_verifier, oauth_scope_escalation.

**Pass-through by design (3) — leave alone:**
- `sqli_blind_boolean` — stateful, requires custom scaffolding
- `csrf` — stateful, requires custom scaffolding
- `subdomain_takeover` — heuristic-only is correct (no definitive verification for dangling CNAMEs)

**Pass-through that should become deterministic (31) — backlog:**
ssrf_blind, xxe_blind, command_injection_blind, lfi, lfi_rce, oauth_redirect_uri, oauth_state, oauth_pkce, jwt_vulnerability, jwt_alg_confusion, jwt_none, jwt_kid_injection, information_disclosure, rate_limit_bypass, graphql_introspection, graphql_batching, mass_assignment, rce, race_condition, toctou, double_spend, http_smuggling, cache_poisoning, cache_deception, deserialization, saml_attack, mfa_bypass, websocket, crlf_injection, prompt_injection, business_logic.

**Acceptance:**
- Each high-frequency type listed above gets a concrete verification routine (timing probe, browser state check, state-machine replay, OOB callback, etc.).
- Unit tests cover at least one positive and one negative case per validator.
- Pass-through fallback is permitted only where deterministic verification is provably impossible, and the reason is documented inline.

**Highest-priority next batch** (chosen for severity weight + frequency in real-program scopes):
1. cache_poisoning + cache_deception — 3-step cache proof (poison → CF-Cache-Status: HIT → clean request returns poisoned response)
2. jwt_alg_confusion + jwt_none — synthesize forged JWT, replay, check 200 response with forged identity
3. ssrf_blind + xxe_blind + command_injection_blind — already have OOB infrastructure, just unwire the pass-through fallback
4. http_smuggling — CL.TE / TE.CL differential probe
5. race_condition — HTTP/2 single-packet via concurrent fetch

### P0-4 · Calibrate report quality scorer against real HackerOne triage outcomes
**File:** `src/core/reporting/report_quality.ts`

**Why:** The scorer was built from `docs/RESEARCH_H1_REPORT_QUALITY.md` but has never been correlated with actual accept/reject decisions. Output is directional, not predictive.

**Acceptance:**
- At least 10 submitted reports tracked through triage.
- Scorer thresholds adjusted so reports predicted "high quality" correlate with acceptance ≥ baseline accept rate, and "low quality" with rejection.
- Calibration notes recorded in `docs/RESEARCH_H1_REPORT_QUALITY.md`.

**Estimate:** 3–5 days, spans multiple hunts. Depends on P0-5 (so the 10 reports are actually H1-format) and on first live submissions actually happening.

### P0-5 · Report writer rebuild — make every generated report a triage-ready H1 submission
**Files:** `src/core/reporting/poc_generator.ts`, `src/core/reporting/templates.ts`, `src/core/reporting/report_quality.ts`

**Why:** Code audit on 2026-04-28 found that `REPORT_TEMPLATES` (10 H1-standard templates with Prerequisites / Vulnerability Details / Expected vs Actual / Affected Scope / Remediation sections) was imported by `poc_generator.ts` but never called. `toMarkdown()` built reports inline section-by-section, producing output missing every H1-required section beyond Description / Impact / Steps / Proof. This was the single largest report-quality gap.

Every dollar P0-3 (validator hardening) earns is forfeit if the report submitted at the end of the chain looks like AI slop. Per `docs/RESEARCH_H1_REPORT_QUALITY.md` triage signals: "no raw HTTP request/response pairs", "perfectly formatted prose with extensive bullet lists", "generic impact without specific data" — older `toMarkdown()` output tripped multiple of these.

**Quick wins (a-e shipped 2026-04-28):**

- ✅ **P0-5-a · Wire `REPORT_TEMPLATES` into `toMarkdown()`.** New `getTemplateKey()` + `extractParameter()` helpers in `templates.ts`; `H1Report.vulnContext` carries type/url/parameter/payload/method through to render time; `buildTemplatedBody()` fills the matching template, falls back to enriched inline build otherwise. Empty `**Label:** ` lines are stripped post-fill.
- ✅ **P0-5-b · Inline-build fallback now carries every H1-required section** via per-vuln-type `H1_SECTION_DEFAULTS` covering 9 specific types + an "other" default. Vulnerability Details, Prerequisites, Expected vs Actual, Affected Scope, Remediation all populated.
- ✅ **P0-5-c · Body snippet cap raised** to 2000 chars on the most-relevant exchange (typically the exploitation step), 500 chars on context exchanges.
- ✅ **P0-5-d · Up to 10 exchanges shown**, ranked by relevance (non-GET +3, anomalous status +2, indicator pattern in body +1, position bonus). Display order preserves original sequence so multi-step chains read top-to-bottom.
- ✅ **P0-5-e · Per-vuln-type evidence checklist** in `report_quality.ts` (`EVIDENCE_REQUIREMENTS`). Covers cors_misconfiguration / cache_poisoning / xss_reflected / xss_dom / xss_stored / idor / bola / ssrf / ssrf_blind / open_redirect / sqli_error / sqli_blind_time / race_condition. Reports missing the required evidence shape are capped below the submission threshold (overall ≤ 55, `meetsThreshold=false`). 31 new tests in `p0_5_report_writer.test.ts`.

**Medium (1-2 days each):**

- **P0-5-f · Wire `H1Api.uploadAttachment` from `toMarkdown()`** so screenshots are actual H1 attachments, not file paths.
- **P0-5-g · Surface validator's `ValidationEvidence[]` (screenshots, OOB callbacks, dialog detection) into the report's HTTP Evidence section.** Currently this evidence dies at the validator boundary.
- **P0-5-h · Video capture for chained findings** via Playwright video recording (already used in `headless_browser.ts`) wired to H1 attachment upload. Research doc cites <2-min video as one of the five required H1 elements.

**Bigger:**

- **P0-5-i · Independent Reporter agent** — second-pass Sonnet review that grades the report against H1 triage criteria and either upgrades, downgrades, or flags-for-review before submission. (Same item as P1-3-f below — listed in both places because it serves both report quality and PentAGI adoption.)

**Acceptance:**
- Every generated report includes Prerequisites, Vulnerability Details, Expected vs Actual, Affected Scope, Remediation sections (template-driven where available).
- Quality scorer enforces per-vuln-type evidence requirements.
- Screenshots upload as H1 attachments, not file path references.
- A report generated for a Juice Shop SQLi finding is structurally indistinguishable from a top-rated H1 report (manual comparison against 3 disclosed reports).

**Estimate:** 2-3 focused days for quick wins (a-e), additional 2-3 days for medium (f-h), 1 day for bigger (i).

---

## 3. P1 — High (Correctness & Quality Gaps)

### P1-1 · Verify generic token refresh against a non-Telegram OAuth2 target
**Files:** `src/core/auth/token_refresher.ts`, `src/core/auth/session_manager.ts`

**Code state:** `RefreshConfig` discriminated union has all 4 strategies (initdata_exchange, refresh_token, custom_endpoint, re_login). `getTokenExpiry()` parses JWT exp at L112-132. Proactive refresh threshold 90s (`DEFAULT_REFRESH_THRESHOLD_MS`). Rate limit 1/30s/session (`RATE_LIMIT_MS`). 401 auto-retry in `session_manager.ts:361-364`. `onRefreshFailed` callback at `token_refresher.ts:99-104, 291`. **Code is complete; only live verification is missing.**

**Acceptance:**
- A single hunt exceeds the target's token TTL by 20+ minutes with zero 401 errors.
- Proactive refresh (90s threshold) logs fire before expiry.
- 401 auto-retry path exercised at least once.

**Estimate:** One hunt (~60 minutes) plus any patching surfaced.

### P1-2 · Audit recon pipeline tools against Dockerfile  ✅ shipped 2026-04-24
**Files:** `src/core/orchestrator/recon_pipeline.ts`, `src/agents/recon_agent.ts`, `scripts/verify_attack_tools.sh`, `src/tests/recon_tool_inventory.test.ts`

Inventory drift between source code and the Docker image is now caught at three independent layers:
- **Single source of truth** — `ATTACK_MACHINE_TOOLS` constant + `ATTACK_MACHINE_TOOL_NAMES` set in `recon_pipeline.ts`.
- **Source-side invariants** (no Docker required) — 9 unit tests verify no duplicates, every entry has non-empty name + probe args, every `command.tool` is in the inventory, every `command.command` starts with its declared `tool`, recon agent prompt mentions every pipeline-referenced tool.
- **Image-side smoke test** — `scripts/verify_attack_tools.sh` runs each inventoried tool's probe inside `huntress-attack-machine:latest`. Fails on missing/unrunnable binary.

### P1-3 · Adopt high-leverage patterns from PentAGI (12 items, 0/12 shipped)
Cross-reference with [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi) (15.9k-star Go pentest platform) surfaced concrete patterns that solve problems we are still struggling with. Full deep dive at `docs/research/PENTAGI_DEEP_DIVE.md`. **Code-level verification on 2026-04-28 confirmed: 0 of 12 items have any implementation in the codebase.**

| ID | Item | Effort | Unblocks |
|---|---|---|---|
| P1-3-a | **3-identical-toolcall hard guardrail** — single line in every specialist system prompt + ReactLoop enforcement after 3 consecutive identical `(toolName, argsHash)` calls | ~2 hours | The 2026-04-23 SSTI 90-tool-call burn pattern; cheapest first-line defense |
| P1-3-b | **Per-agent-type tool-call cap** — `maxToolCallsPerAgent` config in ReactLoop; counts tool calls (not LLM iterations); hard-stops at limit | ~2 hours | Same as P1-3-a, second line |
| P1-3-c | **Adviser execution-monitor sub-agent** — wakes on no-progress patterns (>5 identical calls OR >10 total without finding); receives recent messages + tool call history; answers six diagnostic questions; output guides next agent step | ~1 day | Smart fallback when P1-3-a/b aren't enough; pentagi's signature pattern |
| P1-3-d | **Chain summarizer** (port of `pkg/csum/chain_summary.go`) — multi-strategy summarization with byte budgets (50KB last, 16KB pair, 64KB QA, 25% reserve); preserves tool-call/response pairs as atomic units | ~1 day | Long real-program hunts (>1hr) without context degradation |
| P1-3-e | **Sploitus exploit-DB tool** — agent-callable tool that hits `https://sploitus.com/search` for exploits + tools matching a query; returns CVSS, source previews, CVE refs | ~½ day | Direct boost to P0-4 / P0-5 (real CVE references in PoC reports = triage-friendly evidence) |
| P1-3-f | **Reporter "Independent Judgment" reviewer agent** — second-pass agent (Sonnet) that reads the validator's confirmation evidence, ignores the `confirmed` claim, forms own conclusion (upgrade/downgrade/flag-for-review). Synthetic accept/reject signal. Same item as P0-5-i. | ~1 day | P0-4 enabler — gives us a calibration signal **before** live H1 triage data accumulates |
| P1-3-g | **DB-persisted Flow / Task / Subtask state** — Tauri SQLite store; orchestrator writes state transitions; restart resumes from last checkpoint | ~2-3 days | Required before any real-program hunt >30 minutes (we currently lose all state on crash) |
| P1-3-h | **Prompt template validator + typed variable registry** — build-time check that every prompt template's `${var}` references resolve against a typed registry; CI blocks on unauthorized var | ~1 day | Defensive eng — catches the class of bugs that landed users at `codacontent.io` (P1-0-c regression) before they ship |
| P1-3-i | **Authorization-status preamble** — shared `AUTHORIZATION_PREAMBLE` constant prepended to every specialist system prompt | ~2 hours | Small ergonomic win; reduces agent-hesitation cycles on aggressive payloads. Must NOT leak into report-render layer (audience there needs responsible-disclosure framing) |
| P1-3-j | **Toolcall_fixer side-channel** — when an agent emits malformed JSON for a tool call, route to a sub-LLM with original args + error + schema; receive corrected JSON; retry. Silent self-healing | ~1 day | Reduces Haiku-tier malformed-JSON failures; quality-of-life |
| P1-3-k | **Detach modes for long-running commands** — `detach: boolean` field in `execute_command`; PTY layer fire-and-forgets daemons (returns "started in background" after 500ms); batch commands wait | ~1 day | Daemon/listener-based PoCs (reverse shells, http server for SSRF callbacks) without blocking the agent |
| P1-3-l | **Refiner / failure categorization** — when an agent fails, categorize as Technical / Environmental / Conceptual / External; pivot strategy for Conceptual; retry-with-tweaks for Technical | ~1 day | Smarter retries vs. blind redispatch |

**Recommended sequence:** P1-3-a → P1-3-b → P1-3-c → P1-3-d → P1-3-e → P1-3-f are the P0-adjacent set (~4 focused days, all unblock real-H1 readiness). P1-3-g is the next gate (long-hunt reliability). Items P1-3-h through P1-3-l are quality-of-life.

**Explicitly NOT adopting:** pentagi's multi-LLM provider abstraction (violates Huntress CLAUDE.md "Anthropic only"), web-app deployment (we are desktop-by-design), generic-pentest agent fleet (our 27 specialists are sharper for bounty hunting), Neo4j/Graphiti (Qdrant is sufficient for our use; structured-search-protocol pattern adoptable without it).

### P1-4 · Auth Phase 2 backlog (carried over from `DEEPER_AUTH_RESEARCH_AND_PLAN.md`)
Phase 1 (Q1-Q4 + Q6 Gap 5/7) is shipped and verified. Four Phase 2 items have not been carried forward in any plan and would otherwise be lost:

- **P1-4-a · Q6 Gap 6 — login-detection scoring in `scripts/auth_capture.mjs`.** Current Set-Cookie heuristic at L111-114 is too eager; any tracking cookie (Cloudflare, GA) triggers `loginDetected = true`. Replace with response-shape scoring: POST to `/login`-shaped path + (status 2xx or 30x to authed area) + (Set-Cookie with HttpOnly flag OR Authorization in subsequent request). ~½ day.
- **P1-4-b · Q6 Gap 8 — `refreshMode` field on `AuthProfileConfig` + Settings UI surfacing.** Tells the user which refresh strategy will fire, lets them override per-profile. ~1 day.
- **P1-4-c · Q8 — full Auth tab redesign in Settings.** Profile cards with per-profile auth method, refresh status, last-401 timestamp. ~2 days.
- **P1-4-d · Finding-panel `sessionLabel` badges.** UI follow-through on Q3: every IDOR/BOLA finding card shows which session_label it was found with (the IDOR Settings badge already shows global readiness). ~½ day.

### P1-5 · Live verification of Session 25 fixes (manual — not a code task)
- **P1-5-a · I8 from Session 25** — auth browser capture E2E manual test against Telegram. After login: wizard form shows auth method + token populated, [TEST AUTH] returns 2xx/3xx. No code, just confirmation.

---

### P0-6 · XBOW benchmark — wire the runner, run it, publish the number
**Files:** `src/components/BenchmarkDashboard.tsx`, `scripts/run_xbow_benchmark.ts`, `src/core/benchmark/xbow_runner.ts`

**Why:** The 2026-04-28 review's top operational call: "Run the XBOW Validation Benchmark and publish the number, whatever it is. You can't improve what you don't measure." Reviewer prediction: 30–55% range first run.

**Infrastructure status (shipped 2026-04-28):**
- ✅ `XBOWBenchmarkRunner` (1,190 LOC) — challenge discovery, Docker orchestration, CTF agent loop, SQLite persistence, historical comparison
- ✅ `BenchmarkDashboard` mounted at App.tsx:507 under the `benchmark` tab — click `[run benchmark]` to trigger
- ✅ Dashboard now surfaces per-tag breakdown, per-level breakdown, and per-challenge cost + iterations + duration (Phase 1.1 enhancements)
- ✅ `execute_training_command` Tauri allowlist already includes `git`, `docker`, plus `curl`, `nmap`, `sqlmap`, `nikto`, `gobuster`, `ffuf`, etc. for the CTF solver agent
- ✅ `scripts/run_xbow_benchmark.ts` — headless CLI runner for cron / CI / first-time scoring without launching Tauri. Usage: `ANTHROPIC_API_KEY=... npx tsx scripts/run_xbow_benchmark.ts [--tags=sqli,xss] [--levels=1,2] [--max-parallel=2]`

**Operational status (TODO):**
- [ ] **First run** — execute against the full 104-challenge suite (or a representative subset). Cost: ~$50–$200, runtime: hours
- [ ] Publish the score in §1 header of this doc (replace "8.9/10" with "X% on XBOW benchmark")
- [ ] Re-run after each P0-3 validator-deepening batch to measure delta

**Smoke test (cheap, ~$5):** Filter to one tag and 5 challenges to validate the pipeline end-to-end before the full run:
```
ANTHROPIC_API_KEY=sk-ant-... npx tsx scripts/run_xbow_benchmark.ts --tags=xss --max-parallel=1 --timeout-per-challenge=180000
```

---

## 4. P2 — Medium (Coverage & Polish)

### P2-1 · Cross-subdomain deduplication edge-case tests
**File:** `src/core/orchestrator/finding_dedup.ts`

`extractRootDomain` is shipped (lines 150-172) but untested for eTLD+1 cases (`example.co.uk`), IPv6 literals, and `localhost:port`. A miscalculation produces duplicate findings in the final report.

**Acceptance:** Unit tests cover eTLD+1 (`.co.uk`, `.com.au`), IPv4 literals, IPv6, port-bearing hosts. Dedup produces one finding per semantic vulnerability across subdomain permutations.

**Estimate:** ~1 day.

### P2-2 · Agent-specific severity calibration prompts
**Files:** `src/agents/cors_hunter.ts`, `src/agents/cache_hunter.ts`, and other specialist agents

C1/C2 apply a global severity calibration prompt. Only `host_header.ts` carries type-specific guidance (preconnect reflection ≠ SSRF). Other agents with well-known misclassification patterns would benefit from the same treatment.

**Acceptance:** Each agent whose type has a documented false-positive pattern includes explicit guidance in its system prompt.

### P2-4 · I7 / I8 architecture verified — add agent-count tests
The Blackboard cross-agent sharing (I7) and WAF context injection (I8) infrastructure is shipped. **No test verifies that all 27 agents actually receive the injected context.** A future agent added without proper config would silently miss SharedFinding/WafContext. Add a test that enumerates the agent catalog and asserts every agent receives both contexts.

**Estimate:** ~½ day.

---

## 5. P3 — Deferred

| ID | Item | Reason |
|---|---|---|
| P3-1 | JS-rendering crawler for SPA endpoint discovery | Large lift (~2–3 days). Reconsider after P0 clears and hunt data shows measurable SPA blind spots. |
| P3-2 | Training pipeline integration | Requires GPU infrastructure. Future phase, not on the current critical path. |
| P3-3 | Auth Phase 3 — mTLS, Firebase SDK auth, Supabase JWT, TOTP-protected login, OAuth PKCE helper | Each is a small integration; bundle when one is needed by an actual target. |
| P3-4 | Auth Phase 4 — MTProto sidecar (Telegram full automation), AWS SigV4 signing, magic-link login, Kerberos | Triggered by external signal — wait for a real target to demand each. |
| P3-5 | Continuous monitoring — background polling for new subdomains, JS file changes, scope updates | Defer until first long-running hunts complete and we know what to monitor. |
| P3-6 | XBOW 104-challenge benchmark runner | Useful score signal; not a submission blocker. |
| P3-7 | Multi-target parallel hunting (queue multiple H1 programs) | Optimization, not capability. |
| P3-8 | Mobile API testing (APK decompile, cert pinning bypass) | Out of scope for current targets. |
| P3-9 | Cloud misconfiguration scanning (S3, GCP, Azure blob) | Useful but not bottlenecked here. |
| P3-10 | Visual recon / application flow mapping, GitHub dorking, Wayback Machine, source map analysis | Each is its own feature; adopt one when a hunt clearly needs it. |
| P3-11 | Browser extension for manual hunting augmentation, community agent marketplace, team mode | Long-tail product features. |

---

## 6. Architectural Invariants (Do Not Violate)

These are summarized from `CLAUDE.md` for convenience. Any task that touches these areas must preserve the invariant:

1. **`HttpClient` (`src/core/http/request_engine.ts`) is the only HTTP egress path** — kill switch, scope validation, rate limiting, stealth, WAF detection run in that fixed order.
2. **Agent dispatch is fire-and-forget.** Validation and duplicate checks run asynchronously against findings with `pending` status.
3. **Scope validation is default-deny.** `src-tauri/src/safe_to_test.rs` — any change requires positive and negative tests.
4. **Tiered model routing is locked** for the seven agents listed in `COMPLEXITY_LOCKED_AGENTS` (`src/core/orchestrator/cost_router.ts`). Budget enforcement: 90% soft warning, 100% hard stop. **Anthropic models only.**
5. **Command execution uses argv arrays, never shell interpolation.** `src-tauri/src/pty_manager.rs`.
6. **Approval gate and kill switch cannot be bypassed.** `auto_approve` is the only sanctioned exception and requires explicit opt-in per category.
7. **API keys go through secure storage only.** AES-256-GCM with HKDF. Never log or print keys.
8. **`safe_to_test.rs`, `kill_switch.rs`, and the approval gate core are FROZEN** — do not modify without explicit user request.

---

## 7. Verified Complete

These items have been verified shipped via direct code inspection on 2026-04-28. Do not reopen without new evidence.

### Safety architecture (production-ready)
| ID | Area | Evidence |
|---|---|---|
| — | Scope validation (default-deny, wildcards, CIDR, TLS cert) | `src-tauri/src/safe_to_test.rs` — 42+ tests |
| — | Kill switch (atomic, persistent, fail-safe-active) | `src-tauri/src/kill_switch.rs` |
| — | Approval gate (60s timeout, audit trail) | `src/contexts/HuntSessionContext.tsx` |
| — | PTY command execution (argv-only, env sanitization) | `src-tauri/src/pty_manager.rs` |
| — | Secure storage (AES-256-GCM, HKDF) | `src-tauri/src/secure_storage.rs` |
| — | Docker sandbox (read-only rootfs, capability drop, scope-enforcing tinyproxy) | `src-tauri/src/sandbox.rs` + `docker/Dockerfile.attack-machine` |

### Auth pipeline (Phase 1 — all verified)
| ID | Area | Evidence |
|---|---|---|
| Q1 | Env-var injection + `.curlrc` + token scrubbing | `src/core/auth/session_env.ts:37-75`; `src-tauri/src/sandbox.rs:958` (`sandbox_write_file`); `react_loop.ts:220-234` (`scrubAuthSecrets`) |
| Q2 | Agent system-prompt auth block | `react_loop.ts:2099-2128` (`buildAuthSection`) |
| Q3 | `session_label` + `findByLabel` + IDOR badge | `session_manager.ts:102` (`findByLabel`); `tool_schemas.ts:291` (`session_label`); `SettingsPanel.tsx:661-692` (IDOR-ready badge) |
| Q4 | Telegram preset wizard (DevTools paste-assist + initdata_exchange auto-select) | `AuthWizardModal.tsx:99,138,427` |
| Q6 Gap 5 | Multi-probe bearer validation (tri-state) | `session_manager.ts:225` (`probeBearer`) |
| Q6 Gap 7 | Scope-aware redirect + cross-origin auth header strip | `request_engine.ts:345` (`stripCrossOriginAuthHeaders`); unified loop in Tauri (L613) and axios (L808) paths |
| S4 | Auth Settings UI (CRUD bearer/form/API key/custom) | `SettingsPanel.tsx:31-49` |
| S6 | Auth detection wizard | `auth_detector.ts:26-42`; `HuntSessionContext.tsx:664-708` |
| S7 | Token refresh (JWT exp parsing, rate-limited 1/30s) | `token_refresher.ts:83,86,148-152,180` |
| S8 | Generic `RefreshConfig` 4-strategy union | `token_refresher.ts:21-68` |

### Orchestration / agent infrastructure
| ID | Area | Evidence |
|---|---|---|
| I2 | localStorage encrypted via Tauri secure storage with plaintext migration | `HuntSessionContext.tsx:62-95`; `secure_storage.rs:206-271,406-430` |
| I7 | Cross-agent knowledge sharing via Blackboard; SharedFinding[] in ReactLoopConfig | `blackboard.ts:43-168`; `react_loop.ts:33,89-92,2298-2312` (caveat: agent-count enumeration test missing — see P2-4) |
| I8 | WAF-awareness `WafContext` injected via ReactLoopConfig | `base_agent.ts:41-49`; `react_loop.ts:2289-2297` (caveat: same as I7 — see P2-4) |
| C1 | Mandatory evidence block in agent system prompts | `recon_agent.ts:41-100` and other specialist prompts |
| C2 | Severity calibration gate with 7 named rules | `react_loop.ts:2143-2238` (`checkSeverityCalibration`) |
| C3 | Cross-subdomain dedup via `extractRootDomain()` | `finding_dedup.ts:150-189,222-249` |
| C5 | Report quality scorer (8 categories, threshold 60) | `report_quality.ts` (categories: clarity 10%, completeness 10%, evidence 5%, impact 10%, reproducibility 15%, httpEvidence 25%, executablePoc 15%, expectedVsActual 10%) |

### Validators (24 deterministic — see §2 P0-3 for enumeration)
xss_reflected/dom/stored, sqli_error/blind_time, ssrf, idor, bola, open_redirect, xxe, command_injection, path_traversal, ssti, cors_misconfiguration, host_header_injection, prototype_pollution, nosql_injection, oauth_missing_state/downgrade_attack/weak_verifier/scope_escalation. Helpers: `buildXssPayloadVariants` (4 variants), `SSTI_BODY_FIELDS` (10 fields), `buildCurlArgv` (auth pass-through), `deriveSqlBaselineUrl`, `validateBrokenAccess` (two-identity), `secondaryAuthHeaders`/`secondaryAuthCookies`/`primaryAuthLabel`/`secondaryAuthLabel` on `ValidatorConfig`.

### Real-H1 UX blockers (all four shipped)
| ID | Area | Evidence |
|---|---|---|
| P1-0-a | Toggleable scope narrowing in BountyImporter | `BountyImporter.tsx:24-33,55`; 7 tests in `scope_narrowing.test.ts` |
| P1-0-b | Economy mode (`maxConcurrentAgents` 5→2, fan-out cap, frozen config contract) | `economy_mode.ts:24-94,118`; `SettingsPanel.tsx:1205`; 21 tests in `economy_mode.test.ts` |
| P1-0-c | AuthDetector login-URL fallback fix (no silent `baseUrl`) | `auth_detector.ts:570-596`; `AuthWizardModal.tsx:228`; 40 tests in `s6_auth_detector.test.ts` |
| P1-0-d | Submit-flow dry run (gate extracted, payload pinned) | `report_submission_gate.ts:42-110`; `ReportReviewModal.tsx:14-16`; 17 tests in `h1_submit_dryrun.test.ts` |

### Session 25 issues (I1-I7 shipped, I8 carried forward as P1-5-a)
| ID | Issue | Evidence |
|---|---|---|
| I1 | `specialist_request` filtered from finding pipeline | `orchestrator_engine.ts:2198-2202` |
| I2 | Browser tools route through Node.js subprocess | `scripts/agent_browser.mjs`; `react_loop.ts:654-668` |
| I3 | Auto-approval categories with safe defaults | `SettingsContext.tsx:167-174` (`autoApprove` 4 categories); `safety_policies.ts:276-289` (`classifyCommand`) |
| I4 | `[+ Add Auth]` button for mid-hunt auth injection | `HuntSessionContext.tsx:177,1057` (`addAuthToActiveHunt`) |
| I5 | Container reaper on orchestrator init | `sandbox_executor.ts:124` (`reapOrphans`); `orchestrator_engine.ts:1019`; 4 tests in `i5_orphan_reaper.test.ts` |
| I6 | Severity calibration integration tests | `src/tests/integration/severity_calibration_e2e.test.ts` |
| I7 | Cross-subdomain dedup integration tests | `src/tests/integration/dedup_e2e.test.ts` |

### Additional Session 25 work
| Item | Evidence |
|---|---|
| Recon `success=true` on `iteration_limit` with ≥3 tool calls | `react_loop.ts:542-552` (16 tests) |
| `dnsx` and `wafw00f` added to attack-machine Dockerfile | `docker/Dockerfile.attack-machine:60,88` |
| Tinyproxy `PidFile` to `/tmp` + TCP startup probe (Session 25 #9) | `docker/tinyproxy.conf:28` (`PidFile "/tmp/tinyproxy.pid"`); `docker/entrypoint.sh:40-46` (TCP probe via `/dev/tcp`); live-verified 2026-04-28: in-scope returns 200, out-of-scope returns 000/exit 56 (blocked by filter, not exit 7) |
| Recon emits `category: 'endpoint'` observations capped at 50 | `recon_agent.ts:332,361` |
| `browser_fill` action + tool schema + ReactLoop handler | `tool_schemas.ts:469`; ReactLoop handler |
| AuthWorkerAgent + `capture_complete`/`capture_failed` schemas + XHR interception | `auth_worker_agent.ts:1-80`; `tool_schemas.ts:426-469`; `react_loop.ts:1865-1908` |
| Validator IPC over `AgentBrowserClient` (eliminates "binding name 'default'" crash) | `headless_browser.ts:1-22`; `scripts/agent_browser.mjs:21-22,340,473,554-555` (11 tests) |
| Recon endpoint scope filter (`isUrlInReconScope`) | `recon_agent.ts:155-170,358` (11 tests) |

### Validators / hardening (Session 26-27 — already integrated above in P0-3 enumeration)
| Item | Evidence |
|---|---|
| Multi-payload sweep in XSS validators (Angular sanitization defeated) | `validator.ts:251` (`buildXssPayloadVariants`); 11 tests |
| SSTI POST-body sweep + auth plumbing | `validator.ts:1553` (`SSTI_BODY_FIELDS`); 11 tests |
| 18 validators migrated to `buildCurlArgv` (auth pass-through, follow-redirect opt-out) | `validator.ts:117` (`buildCurlArgv`); 8 tests in `validator_auth_pass_through.test.ts` |
| Deep validator hardening — 9 increments (sqli_blind_time baseline, sqli_error POST sweep, xss_stored, ssrf OOB, command_injection OOB, path_traversal encoding, host_header 7 headers, idor/bola two-identity, xxe blind-OOB DTD) | `validator.ts` lines vary; 26 tests in `validator_deep_hardening.test.ts` |

### Phases shipped historically (verified via code presence + previous audits)
- **Phase 1** — Tiered model routing, budget enforcement, scope normalization, tech-stack filtering (Hunt #5)
- **Phase 2** — Rate limiting & stealth (RateController + StealthModule + WAF detection in HttpClient)
- **Phase 3** — Finding validation pipeline + H1 duplicate checking (`validateFinding` + `runH1DuplicateCheck` fire-and-forget)
- **Phase 4** — H1 API integration + reporting infrastructure (auth, retry, file uploads)
- Approval gate + kill switch + secure storage hardening (Sessions 7-9)
- Docker attack machine (Session 8 — 640MB, 15 tools)
- API schema import (OpenAPI/Swagger/GraphQL — Session 8)
- Session 11 fixes for Hunt #7 (Docker lifecycle, hallucination gate ≥3 HTTP, normalizeEvidence, OAuth validators, API limit detection, cross-hunt dedup, adjust_budget)
- Session 12 fixes (dispatch undefined target guard, chain validated:boolean, GitHub+internal duplicate sources, real CVSS calculator)
- Session 13 report templates + HTTP exchanges + H1 quality scorer recalibration

---

## 8. Design Notes

Longer-form design context lives under `docs/`:

- `docs/RESEARCH_H1_REPORT_QUALITY.md` — research behind the report quality scorer. Cited by **P0-4** and **P0-5**.
- `docs/research/PENTAGI_DEEP_DIVE.md` — full PentAGI cross-reference (422 lines, two-phase analysis). Cited by **P1-3**.
- `docs/PHASE5_*.md` — operational runbooks for training deployment (architecture, monitoring, rollback, troubleshooting). Reference only.

Add new design notes under `docs/` and reference them from the relevant priority item above. Do not create new top-level planning files.

---

## 9. Recommended Next Action

Two parallel tracks of work, in this order:

**Track 1 — Report writer (P0-5 a-e quick wins, ~2 days):** Wire `REPORT_TEMPLATES` into `toMarkdown()`, add missing H1 sections to inline build, raise body snippet cap, show all relevant exchanges, add per-vuln-type evidence checklist to quality scorer. After this, the first live submission is a reasonable shape rather than AI slop.

**Track 2 — First live HackerOne submission:** All UX machinery is in place (P1-0 a-d shipped). Pick a program with small scope OR use Narrow scope (P1-0-a), toggle Economy mode (P1-0-b), run hunt, submission gate (P1-0-d) gates the report. First real submission produces the triage data that P0-4 calibration needs.

After those, in priority order:
3. **P1-3-a + P1-3-b** (~4 hours total) — prevents the 90-tool-call burn pattern.
4. **P0-5-i / P1-3-f Independent Reporter agent** (~1 day) — synthetic accept/reject signal as triage data accumulates.
5. **P1-3-e Sploitus** (~½ day) — real CVE refs in reports.
6. **P1-3-c Adviser** (~1 day) — smart no-progress fallback.
7. **P1-3-d Chain summarizer** (~1 day) — required before any hunt over 1 hour.
8. **P0-3 next batch** of validator deepening (cache_poisoning, jwt_*, blind family) — ongoing work.
9. **P1-3-g DB-persisted state** (~2-3 days) — gate before any real-program hunt >30 minutes.

*Total to "production-ready report writer + 5 submissions + most P1-3": ~10 focused days.*

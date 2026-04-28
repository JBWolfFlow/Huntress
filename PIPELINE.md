# Huntress Development Pipeline

Single source of truth for outstanding work, verified status, and delivery priorities.

- **Last updated:** 2026-04-24
- **Project score:** 8.9 / 10 — all four real-H1 UX blockers shipped (scope narrowing, economy mode, auth-detector fallback, submit-flow dry run); P1-2 recon-pipeline tool inventory enforced via single-source-of-truth + invariant tests + Docker smoke script. Validator hardening substantially complete; live-target report calibration (P0-4) is the only remaining gate before first submission.
- **Test health:** 2,172 TypeScript tests passing (91 files) • 108 Rust tests passing • `tsc --noEmit` clean • `cargo clippy -D warnings` clean.

---

## 1. How to Use This Document

This file replaces `SESSION_*_PLAN.md`, `AUDIT_TRACKER.md`, `PHASE_NEXT_PLAN.md`, and every other ad-hoc planning doc that previously existed in this repo. When work is added, updated, or completed:

1. Update the relevant section here in the same commit as the code change.
2. Move finished items from the priority tables into **§6 Verified Complete**, with the commit SHA that landed them.
3. Do not create parallel planning documents. If a plan needs more than a paragraph of design, put it under **§7 Design Notes**.

Priority levels use a fixed rubric:

| Level | Meaning |
|---|---|
| **P0 — Critical** | Blocks first real HackerOne submission. Work here before anything else. |
| **P1 — High** | Correctness or quality gap that will bite on a live hunt. |
| **P2 — Medium** | Edge cases, coverage, and polish. |
| **P3 — Deferred** | Captured intentionally; revisit after P0/P1/P2 clear. |

---

## 2. P0 — Critical (Blocks First Submission)

### P0-3 · Replace 28 pass-through validators with deterministic checks (in progress)
**File:** `src/core/validation/validator.ts`
**Why:** Of 46 vulnerability types, 28 currently rely on agent self-confidence rather than deterministic verification. This is the single largest source of false-positive risk and the primary obstacle to submitting to real HackerOne programs without reputation damage. The 2026-04-23 Juice Shop hunt made this concrete — every finding (iframe-javascript XSS bypass, Pug `{{7*7}}` SSTI on `/api/BasketItems`) hit the validator pipeline cleanly after the binding-error fix, but all four returned `could not be verified` because the current payload shapes don't match real exploit variants.

**Status:**
- ✅ **XSS multi-payload sweep** (2026-04-23). `xss_reflected` and `xss_dom` now loop through `script-tag`, `iframe-javascript` (Angular-bypass), `svg-onload`, and `img-onerror` variants via `buildXssPayloadVariants()`. First to fire the marker via dialog/console/OOB wins; evidence from every attempt is aggregated. 11 new tests. Next live hunt against Juice Shop should flip the two DOM-XSS findings from `could not be verified` to `CONFIRMED`.
- ✅ **SSTI POST-body + auth** (2026-04-23). `buildCurlArgv()` helper (exported) centralizes argv construction with auth-header/cookie pass-through; `ValidatorConfig` gained `authHeaders` and `authCookies` fields populated from the active hunt's primary session in `runFindingValidation`. `ssti` validator now sweeps `SSTI_BODY_FIELDS` (quantity, test, input, content, message, data, name, template, value, text) for `/api/` or `/rest/` URLs in addition to the existing GET-query path. First confirming site wins; negative control still discards page-default `49` hits. 11 new tests. Should flip the 2026-04-23 Pug SSTI on POST `/api/BasketItems` from `could not be verified` to `CONFIRMED`.
- ✅ **Bulk migration of 18 validators to `buildCurlArgv`** (2026-04-23). Every `['curl', '-s', ...].join('\x00')` in `validator.ts` now goes through the shared builder. Same-origin validators (`sqli_error`, `sqli_blind_time`, `ssrf`, `idor`, `xxe`, `command_injection`, `path_traversal`, `cors_misconfiguration`, `host_header_injection`, `prototype_pollution`, `nosql_injection`, `bola`) inherit auth from the active hunt. Follow-redirect validators (`open_redirect`, `subdomain_takeover`, `oauth_*`) explicitly opt out — curl `-L` re-sends custom `-H` headers cross-origin, which would leak bearer/cookies to whatever host the redirect lands on. That policy is locked down by `validator_auth_pass_through.test.ts` (8 tests).
- ✅ **Deep validator hardening** (2026-04-23). Nine concrete increments:
  - **`sqli_blind_time`** — fixed the shipping-day bug where baseline and delay probes sent the same URL; added `deriveSqlBaselineUrl()` that strips `SLEEP/BENCHMARK/pg_sleep/WAITFOR` patterns (and URL-encoded variants), with a last-query-value fallback when no pattern matches. Refuses to confirm when no distinct baseline can be derived.
  - **`sqli_error`** — added POST-body sweep over `SQLI_BODY_FIELDS` (id, user_id, username, email, search, q, query, filter, sort, order, name) × 4 canonical error triggers, gated behind an API-endpoint heuristic. Each candidate site has its own clean-value negative control.
  - **`xss_stored`** — plain-navigation path (agent's stored payload still live) with fall-through to the four-variant re-injection sweep from `buildXssPayloadVariants()`. First fire via dialog or console wins.
  - **`ssrf`** — active OOB injection: allocate a fresh `interactsh` callback, substitute its HTTP URL into the target's last query-param slot, wait 3s for the server-side fetch to land. Falls back to response-content indicators and passive agent-phase callback correlation if active OOB doesn't fire.
  - **`command_injection`** — active OOB injection: five shell-exec payload shapes (`;curl`, `$(curl)`, `` `curl` ``, `|wget`, `;nslookup`) substituted into the URL-param slot, looking for callbacks on the allocated OOB host. Complements the existing output-indicator and timing-anomaly paths.
  - **`path_traversal`** — encoding bypass sweep: `url-encoded`, `double-url-encoded`, `mixed-encoding`, `overlong`, `backslash`. Clean-URL baseline check rejects findings where the fingerprint leaks from the page default.
  - **`host_header_injection`** — extended from 2 to 7 override headers (`Host`, `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`). Redirect reflection short-circuits; body reflection requires clean-request control.
  - **`idor` / `bola`** — shared `validateBrokenAccess()` helper with two-identity data-ownership differential. When a secondary session is configured, same finding.target is re-sent as the attacker; identical-body-different-identity confirms broken access regardless of status code. Falls back to the prior status-only check when no secondary is configured; downgrades status-only confirmation when the secondary is denied (ownership IS checked).
  - **`xxe`** — blind-OOB DTD fetch: synthesize a real XXE payload with `<!ENTITY % remote SYSTEM "oob://...">` referencing a fresh callback URL, POST as `application/xml`, wait 3s for the XML parser to dereference the external entity. Only fires when direct-echo path doesn't already confirm.
  - Auth plumbing extended: `ValidatorConfig` gained `secondaryAuthHeaders` / `secondaryAuthCookies` / `primaryAuthLabel` / `secondaryAuthLabel`, populated from `sessionManager.listSessions()[0..1]` in `runFindingValidation`.
  - 26 new unit tests covering every increment, including false-positive rejection and missing-dependency paths (`validator_deep_hardening.test.ts`).

**Acceptance:**
- Each of the 28 types has a concrete verification routine (timing probe, browser state check, state-machine replay, OOB callback, etc.).
- Unit tests cover at least one positive and one negative case per validator.
- A pass-through fallback is permitted only where deterministic verification is provably impossible, and is documented inline.
**Status:** All high-frequency types have deep verification with false-positive controls. Still pass-through (by design — these are either stateful and require custom scaffolding, or low-frequency enough to defer): `sqli_blind_boolean`, `csrf`, `subdomain_takeover` (heuristic-only is the right choice — no definitive verification exists for dangling CNAMEs that isn't already in the service fingerprint check). The oauth_* validators do concrete state/pkce/scope checks but could benefit from richer payload synthesis in a future pass.

### P0-4 · Calibrate report quality scorer against real HackerOne triage outcomes
**File:** `src/core/reporting/report_quality.ts`
**Why:** The scorer was built from `docs/RESEARCH_H1_REPORT_QUALITY.md` but has never been correlated with actual accept/reject decisions. Its current output is directional, not predictive.
**Acceptance:**
- At least 10 submitted reports tracked through triage.
- Scorer thresholds adjusted so that reports predicted "high quality" correlate with acceptance ≥ baseline accept rate, and "low quality" with rejection.
- Calibration notes recorded in `docs/RESEARCH_H1_REPORT_QUALITY.md`.
**Estimate:** 3–5 days, spans multiple hunts. Depends on P0-1 and P0-3.

---

## 3. P1 — High (Correctness & Quality Gaps)

### P1-0 · Real-H1-hunt UX blockers (live submission readiness)
Four concrete items surfaced when the user attempted a live Superhuman hunt on 2026-04-23. All block routine live-H1 use; none block the first possible submission if handled with care.

- ✅ **Scope narrowing (P1-0-a)** — `BountyImporter` gained a toggleable "Narrow scope" section (off by default). When on, the user picks a subset of in-scope targets via checkboxes (with select-all/none helpers); `applyScopeNarrowing()` filters before handing off to the hunt. Unblocks programs like Superhuman where the full scope (30+ assets across `*.grammarly.com`, `*.coda.io`, `*.superhuman.com`) would fan specialists across everything and exhaust any reasonable budget. 7 tests.
- ✅ **Economy mode (P1-0-b)** — New cohesive config module at `src/core/orchestrator/economy_mode.ts`: `EconomyModeConfig` interface + frozen `ECONOMY_MODE_OFF` / `ECONOMY_MODE_ON` constants + `resolveEconomyMode(enabled)` + `selectSolverAgents(catalog, skipped, cap)` + `specialistYieldRank(id)`. When the user flips the toggle in Settings → Advanced → Hunt Behavior: `maxConcurrentAgents` drops 5 → 2, specialist fan-out per recon is capped at 3 (prioritized by yield rank — sqli/xss/idor first), and per-agent budget claim widens 0.2 → 0.5 so the slower serialized hunt still completes. Frozen-object contract so callers can't mutate defaults; test-first with 21 unit tests (resolver, rank ordering, selection + skip + cap + empty-pool edge cases, no-mutation invariant, strict-more-conservative cross-config invariant). Default off — local test hunts see no change.
- ✅ **Auth-detector login-URL fallback (P1-0-c)** — `AuthDetector.buildProfileForType` no longer falls through to `baseUrl` for the cookie flow. When no login path was confidently detected, `profile.url` stays `undefined` and the instruction block changes from "Navigate to the login page: <random-in-scope-host>" to "Enter the login page URL below — Huntress could not auto-detect one." `AuthWizardModal.handleRunCapture` and `handleRunAuthWorker` were also tightened to require an explicit `authUrl` before starting automated login or browser capture — the silent `authUrl || scope.inScope[0]` fallback (which landed the user at `codacontent.io` on the 2026-04-23 Superhuman run) is gone. 3 new tests covering confident detection, no-confident-URL (the Superhuman regression case), and the bearer/api_key profile invariant (those legitimately keep baseUrl — only cookie got the stricter policy).
- ✅ **Submit-flow dry run (P1-0-d)** — Submission gate extracted as a pure helper (`src/components/report_submission_gate.ts`) with `computeReportChecklist`, `computeChecklistScore`, and `computeSubmissionGate`. `ReportReviewModal` refactored to consume them. Axios-mocked test suite (`h1_submit_dryrun.test.ts`) pins the `/reports` POST payload shape (JSON:API envelope with `type: 'report'`, `severity_rating`, `weakness_id`, `relationships.program.data.attributes.handle`), the Basic-Auth construction from `{username, apiToken}`, the `vulnerability_information` markdown (numbered steps, description, impact), and the `SubmissionResult` shape on both success and retry-exhausted error paths. Gate tests pin the block order (duplicate-skip → quality-F → missing description → insufficient steps) and confirm the happy path lets a minimal-but-valid report through. 17 new tests.

### P1-1 · Verify generic token refresh against a non-Telegram OAuth2 target
**Files:** `src/core/auth/token_refresher.ts`, `src/core/engine/react_loop.ts` (authenticatedRequest)
**Why:** The four-strategy `RefreshConfig` discriminated union has only been exercised on Telegram's `initdata_exchange` strategy. OAuth2 and custom refresh endpoints are the common case for real targets. If they regress, hunts will stall at token expiry (typically 10–15 minutes).
**Acceptance:**
- A single hunt exceeds the target's token TTL by 20+ minutes with zero 401 errors.
- Proactive refresh (90s threshold) logs fire before expiry.
- 401 auto-retry path exercised at least once.
**Estimate:** One hunt (~60 minutes) plus any patching surfaced.

### P1-2 · Audit recon pipeline tools against Dockerfile  ✅ shipped 2026-04-24
**Files:** `src/core/orchestrator/recon_pipeline.ts`, `src/agents/recon_agent.ts`, `scripts/verify_attack_tools.sh`, `src/tests/recon_tool_inventory.test.ts`
**Outcome:** Inventory drift between source code and the Docker image is now caught at three independent layers:
- **Single source of truth** — `ATTACK_MACHINE_TOOLS` constant (and its derived `ATTACK_MACHINE_TOOL_NAMES` set) listed at the top of `recon_pipeline.ts` with each tool's canonical version-probe args.
- **Source-side invariants** (no Docker required) — 9 unit tests verify: no duplicates, every entry has non-empty name + probe args, set/array agreement, intentionally-removed tools (`getJS`, `gowitness`, `jsluice`, `findomain`) stay absent, every `buildStages()` `command.tool` field is in the inventory, every `command.command` starts with its declared `tool`, all major recon stages exist, the agent's system prompt mentions every pipeline-referenced tool by name.
- **Image-side smoke test** — `scripts/verify_attack_tools.sh` runs each inventoried tool's probe inside the built `huntress-attack-machine:latest` container; fails on any missing or unrunnable binary. Run after every Dockerfile change.

Recon agent prompt cleaned up — the methodology header used to claim it would do JS analysis with `getJS`/`jsluice` and screenshots with `gowitness`; now it correctly states `katana -jc` covers JS endpoint extraction and the validator's Playwright handles screenshots. `jsluice` added to the explicit "do NOT attempt" list. 9 tests.

---

## 4. P2 — Medium (Coverage & Polish)

### P2-1 · Cross-subdomain deduplication edge-case tests
**File:** `src/core/orchestrator/finding_dedup.ts`
**Why:** `extractRootDomain` is untested for eTLD+1 cases (`example.co.uk`), IP literals, and `localhost:port`. A miscalculation produces duplicate findings in the final report.
**Acceptance:** Unit tests cover eTLD+1, IPv4, IPv6, and port-bearing hosts. Dedup produces one finding per semantic vulnerability across subdomain permutations.
**Estimate:** ~1 day.

### P2-2 · Agent-specific severity calibration prompts
**Files:** `src/agents/cors_hunter.ts`, `src/agents/cache_hunter.ts`, and other specialist agents
**Why:** C1/C2 apply a global severity calibration prompt. Only `host_header.ts` carries type-specific guidance (preconnect reflection ≠ SSRF). Other agents with well-known misclassification patterns would benefit from the same treatment.
**Acceptance:** Each agent whose type has a documented false-positive pattern includes explicit guidance in its system prompt.

---

## 5. P3 — Deferred

| ID | Item | Reason |
|---|---|---|
| P3-1 | JS-rendering crawler for SPA endpoint discovery | Large lift (~2–3 days). Reconsider after P0 clears and hunt data shows measurable SPA blind spots. |
| P3-2 | Training pipeline integration | Requires GPU infrastructure. Future phase, not on the current critical path. |

---

## 6. Verified Complete

These items appear repeatedly in legacy planning docs. Confirmed landed in code as of 2026-04-13 — **do not reopen without new evidence**.

| ID | Area | Status |
|---|---|---|
| I2 | localStorage encrypted via Tauri secure storage (AES-256-GCM) with plaintext migration | ✅ Session 19 |
| I7 | Cross-agent knowledge sharing via Blackboard; `SharedFinding[]` injected into all 27 agents | ✅ Session 19 (17 tests) |
| I8 | WAF-awareness context with vendor-specific bypass strategies injected into all 27 agents | ✅ Session 19 (18 tests) |
| S4 | Auth context management: Settings UI, secure credential storage, ReactLoop auto-injection | ✅ Session 14 |
| S6 | Auth detection wizard | ✅ Session 15 |
| S7 | Token refresh: JWT exp parsing, Telegram initdata re-exchange, rate-limited | ✅ Session 16 |
| S8 | Generic `RefreshConfig` union (initdata / OAuth2 / custom / re-login) | ✅ Session 17 |
| C1 | Mandatory evidence block in every agent system prompt | ✅ Phase C |
| C2 | Severity calibration gate (`checkSeverityCalibration` in `react_loop.ts`) | ✅ Phase C |
| C3 | Cross-subdomain dedup by root domain (`finding_dedup.ts:174-187`) | ✅ Phase C — edge cases covered under P2-1 |
| C5 | Report quality scorer (`src/core/reporting/report_quality.ts`) | ✅ Phase C — calibration tracked under P0-4 |
| #6 | Recon `success=true` on `iteration_limit` with ≥3 tool calls (`react_loop.ts:542-552`) | ✅ Session 25 (16 tests) |
| #8 | `dnsx` and `wafw00f` added to `docker/Dockerfile.attack-machine` | ✅ Session 25 |
| #9 | Tinyproxy `PidFile` moved to `/tmp`; TCP startup probe in `entrypoint.sh` | ✅ Session 25 |
| #10 | Recon emits `category: 'endpoint'` observations capped at 50 (`recon_agent.ts:282-308`) | ✅ Session 25 |
| — | `browser_fill` action, tool schema, and ReactLoop handler | ✅ Session 25 |
| — | AuthWorkerAgent, `capture_complete` / `capture_failed` schemas, XHR interception, AuthWizardModal Step 2 | ✅ Session 25 |
| P0-1 | Session 25 runtime fixes validated live — recon success=true on iteration_limit, per-endpoint dispatch, zero `curl: (7)` | ✅ 2026-04-23 Juice Shop hunt |
| P0-2 | AuthWorkerAgent E2E — wizard auto-opened on 401 `/rest/basket/1`, RUN AUTOMATED LOGIN captured credentials, hunt ran with attached session | ✅ 2026-04-23 Juice Shop hunt |
| — | Validator IPC — `headless_browser.ts` rewritten over `AgentBrowserClient`; new `validator_analyze` / `validator_dom_xss` actions in `scripts/agent_browser.mjs`; eliminates the "Importing binding name 'default'" crash that had blocked every XSS/DOM-XSS/prototype-pollution validation | ✅ 2026-04-23 (11 new tests) |
| — | Recon endpoint scope filter — `isUrlInReconScope()` drops URLs whose host is outside the hunt scope before `category:'endpoint'` observations drive specialist dispatch. Regression-covers the W3C DTD noise seen in the first 2026-04-23 hunt. | ✅ 2026-04-23 (11 new tests) |

---

## 7. Design Notes

Longer-form design context lives under `docs/`:

- `docs/RESEARCH_H1_REPORT_QUALITY.md` — research behind the report quality scorer. Cited by **P0-4**.
- `docs/PHASE5_*.md` — operational runbooks for training deployment (architecture, monitoring, rollback, troubleshooting). Not a pipeline doc; retained as reference.

Add new design notes under `docs/` and reference them from the relevant priority item above. Do not create new top-level planning files.

---

## 8. Architectural Invariants (Do Not Violate)

These are summarized from `CLAUDE.md` for convenience. Any task that touches these areas must preserve the invariant:

1. **`HttpClient` (`src/core/http/request_engine.ts`) is the only HTTP egress path** — kill switch, scope validation, rate limiting, stealth, WAF detection run in that fixed order.
2. **Agent dispatch is fire-and-forget.** Validation and duplicate checks run asynchronously against findings with `pending` status.
3. **Scope validation is default-deny.** `src-tauri/src/safe_to_test.rs` — any change requires positive and negative tests.
4. **Tiered model routing is locked** for the seven agents listed in `COMPLEXITY_LOCKED_AGENTS` (`src/core/orchestrator/cost_router.ts`). Budget enforcement: 90% soft warning, 100% hard stop.
5. **Command execution uses argv arrays, never shell interpolation.** `src-tauri/src/pty_manager.rs`.
6. **Approval gate and kill switch cannot be bypassed.** `auto_approve` is the only sanctioned exception and requires explicit opt-in.

---

## 9. Recommended Next Action

All four real-H1-hunt UX blockers are now shipped. The next action is the first live HackerOne submission itself — the machinery is in place end-to-end:

  1. Pick a program with a small scope OR use **Narrow scope** (P1-0-a) in `BountyImporter` to pick one asset.
  2. Toggle **Economy mode** (P1-0-b) in Settings → Advanced → Hunt Behavior.
  3. Run the hunt. When a finding lands, `ReportReviewModal` enforces the submission gate (P1-0-d) before the Approve & Submit button unlocks.
  4. First real submission produces the triage data that P0-4 needs (report quality scorer calibration).

Before the first *real* program, a dry-run of the XSS+SSTI hardening against Juice Shop is still worth doing — confirm the 2026-04-23 findings flip to `CONFIRMED` with the hardened validators — but it's verification, not a blocker.

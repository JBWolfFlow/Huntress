# Huntress Development Pipeline

Single source of truth for outstanding work, verified status, and delivery priorities.

- **Last updated:** 2026-04-23
- **Project score:** 8.4 / 10 — platform infrastructure solid and validated through the 2026-04-23 live Juice Shop hunt (3 real findings: 1 CRITICAL SSTI, 2 HIGH DOM-XSS; all hit the validator pipeline cleanly). Validator hardening (P0-3, in progress) and live-target report calibration (P0-4) remain the two gates to first bounty submission.
- **Test health:** 2,081 TypeScript tests passing (85 files) • 108 Rust tests passing • `tsc --noEmit` clean • `cargo clippy -D warnings` clean.

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
- ⏳ **Remaining ~25 types** — iterate by frequency observed in live hunts. `buildCurlArgv` + auth plumbing is now the shared foundation; migrating other validators (host_header_injection, cors_misconfiguration, path_traversal, ssrf, idor, xxe, command_injection, sqli_error, sqli_blind_time, prototype_pollution, nosql_injection, bola, oauth_*, subdomain_takeover) to use it is a mechanical refactor that unlocks auth for every one of them.

**Acceptance:**
- Each of the 28 types has a concrete verification routine (timing probe, browser state check, state-machine replay, OOB callback, etc.).
- Unit tests cover at least one positive and one negative case per validator.
- A pass-through fallback is permitted only where deterministic verification is provably impossible, and is documented inline.
**Estimate:** 2–3 focused days (XSS increment shipped).

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

### P1-1 · Verify generic token refresh against a non-Telegram OAuth2 target
**Files:** `src/core/auth/token_refresher.ts`, `src/core/engine/react_loop.ts` (authenticatedRequest)
**Why:** The four-strategy `RefreshConfig` discriminated union has only been exercised on Telegram's `initdata_exchange` strategy. OAuth2 and custom refresh endpoints are the common case for real targets. If they regress, hunts will stall at token expiry (typically 10–15 minutes).
**Acceptance:**
- A single hunt exceeds the target's token TTL by 20+ minutes with zero 401 errors.
- Proactive refresh (90s threshold) logs fire before expiry.
- 401 auto-retry path exercised at least once.
**Estimate:** One hunt (~60 minutes) plus any patching surfaced.

### P1-2 · Audit recon pipeline tools against Dockerfile
**Files:** `docker/Dockerfile.attack-machine`, `src/core/orchestrator/recon_pipeline.ts`
**Why:** `getJS` is confirmed missing from the image. `waybackurls`, `gau`, `paramspider`, `gowitness`, `testssl.sh`, and `naabu` have not been audited and may fail silently in the pipeline.
**Acceptance:**
- Every tool invoked by `recon_pipeline.ts` is present in the Docker image, or the invocation is removed and the recon prompt updated accordingly.
- A CI-level smoke test (or documented manual check) confirms each tool responds to `--version`.
**Estimate:** ~45 minutes.

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

Start **P0-3** with the XSS validator. The 2026-04-23 Juice Shop hunt produced two real DOM-XSS findings (iframe-`javascript:` bypass of Angular's default sanitization) and one CRITICAL SSTI (`{{7*7}}` → `49` on `/api/BasketItems`), all of which hit the validator pipeline cleanly but returned `could not be verified` because the current payload shapes are too narrow. That hunt is now the concrete, reproducible calibration case — add the iframe-`javascript:` XSS variant and a real SSTI evaluation probe, re-run the hunt, and findings should flip from "could not be verified" to `CONFIRMED`. P0-4 follows naturally from there (the upgraded validators produce actionable reports worth calibrating against H1 triage outcomes).

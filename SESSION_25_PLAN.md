# Huntress — Session 25 Hunt Retrospective + Fully-Automated Auth Acquisition

## Context

We ran a live hunt against Wallet on Telegram. Three runtime issues surfaced that Session 25's earlier fixes didn't catch, and — more importantly — the Phase 1 auth pipeline never executed because no agent ever reached the `http_request` tool or emitted findings. The user also wants a deep architectural understanding of the auth subsystem plus a plan to turn the current manual "paste three values into a wizard" flow into a genuine one-click automated capture.

This plan has two halves: **(A)** fixes for the three issues caught in monitoring, and **(B)** an auth-acquisition agent that takes over the wizard's capture step so the user only clicks "Start".

---

## Part A — Runtime issues caught during the Session 25 hunt

### Issue #6 residual — recon agent never passes `success=true`

**Root cause (exact):** `ReactLoop.execute()` at `src/core/engine/react_loop.ts:495` sets

```ts
success: this.findings.length > 0
  || stopReason === 'task_complete'
  || stopReason === 'no_vulnerabilities',
```

When a recon agent hits the iteration limit without calling `stop_hunting`, `stopReason = 'iteration_limit'` (line 317) and `findings.length === 0` (recon doesn't emit findings by default — just `observations`). So `success = false`, and the gate at `orchestrator_engine.ts:2358` (`if (task.agentType === 'recon' && result.success)`) never fires. **No specialist tasks get enqueued. The hunt stalls in a recon loop.**

This is the real Issue #6 — the iteration-budget reduction (60→30) in Session 25 shortens the stall but doesn't fix it. A recon agent burning 30 iterations on subfinder/httpx without a single `report_finding` still returns `success=false`.

**Fix:** Two layered changes in `src/core/engine/react_loop.ts`:

1. **Recon agents don't need findings to be considered successful.** When `agentType === 'recon'` and the loop accumulated meaningful artifacts (>=1 discovered target, >=1 successful httpx, or >=5 non-error tool calls), treat `iteration_limit` as `success=true`. The orchestrator's `generateSolverTasks` extracts endpoints from `observations` + tool output anyway, so recon's "success" means "it gathered attack surface", not "it found vulns".

2. **When iteration limit hits, synthesize a pseudo-stop_hunting.** Emit `task_complete` with reason `recon_budget_exhausted` instead of `iteration_limit` for recon agents. This single line makes the existing `orchestrator_engine.ts:2358` gate fire correctly.

Concrete patch site: the `stopReason = 'iteration_limit'` assignment at `react_loop.ts:317` and the `ReactLoopResult.success` calculation at line 495. Both need an agentType-aware branch.

**Test:** Add unit test in `src/tests/phase1_recon_success_semantics.test.ts` (new file) using the scripted-provider pattern from `hunt7_hallucination_gate.test.ts`. Dispatch a recon agent that runs 30 iterations of `execute_command` and never calls `stop_hunting` — assert `result.success === true` so the solver-tasks gate fires.

### Issue #8 — dnsx + wafw00f missing from attack-machine image

**Root cause:** `docker/Dockerfile.attack-machine:14-66` never installs `dnsx` or `wafw00f`. The tools are referenced in `src/agents/recon_agent.ts:46-56` (system prompt) and `src/core/orchestrator/recon_pipeline.ts`, so agents call them and get exit 126 on every invocation.

**Observed in logs:**
```
command=["dnsx",    "-l", "<(echo ...)", ...]  exit=126   ← missing
command=["wafw00f", "https://pay.wallet.tg",    ...]  exit=126   ← missing
```

**Two-tier fix:**

1. **Short-term (no image rebuild)** — mirror the assetfinder pattern from Session 25:
   - `src/core/orchestrator/recon_pipeline.ts`: remove dnsx from the pipeline stages
   - `src/agents/recon_agent.ts`: remove dnsx + wafw00f from the system prompt, add them to the "not installed — do not attempt" list alongside assetfinder
   - Total: ~6 lines across two files, no Dockerfile touch

2. **Long-term (during next attack-machine image rebuild)** — install the tools properly:
   - `dnsx`: `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest`
   - `wafw00f`: `pip3 install wafw00f`
   - Added to `docker/Dockerfile.attack-machine` in the same block that installs nuclei/subfinder/httpx/katana/ffuf/dalfox (around line 40)

Short-term fix keeps the image untouched (fast turnaround). Long-term fix restores full recon capability (dnsx is genuinely useful for DNS resolution, wafw00f tells agents when to pivot to WAF-bypass strategies).

### Issue #9 — curl exit 7 ("Failed to connect to host")

**Root cause (two nested bugs):**

1. **Session 25's HTTP_PROXY env injection at `src-tauri/src/sandbox.rs:292-310`** forces curl through `http://127.0.0.1:3128`. This is correct in intent, but **tinyproxy can't successfully start as the `hunter` user** because `docker/tinyproxy.conf:28` writes the PID file to `/var/run/tinyproxy.pid`, and `/var/run` isn't writable by hunter in the current tmpfs setup (`sandbox.rs:317-322` only mounts `/tmp` and `/home/hunter` as writable tmpfs). When tinyproxy fails to start, every `curl` call routes to a dead port.

2. **Agent prompts include shell syntax that the argv-only sandbox can't execute.** Commands like `"curl ... | strings | grep ... | head"` get split by `sandbox_executor.ts:231-271` into literal argv `['curl', '...', '|', 'strings', '|', ...]`. `curl` sees `|` as an invalid argument and exits 2 or 7 depending on the flag mix. This isn't caused by Session 25, but it's exacerbated by it — when curl itself worked before (exit 6 → "can't resolve"), the agent's retry logic might recover; now it fails consistently with exit 7.

**Fix (two changes):**

1. **`docker/entrypoint.sh`**: change the tinyproxy PID path to `/tmp/tinyproxy.pid` (already writable as tmpfs in `sandbox.rs`) by editing `docker/tinyproxy.conf:28` to `PidFile "/tmp/tinyproxy.pid"`. Also add a startup probe (`nc -z 127.0.0.1 3128 || echo "[huntress] WARN: tinyproxy did not start — curl through proxy will fail"`) so we don't silently regress again.

2. **Agent prompt hygiene** — update `src/agents/recon_agent.ts` and any other agent system prompt that might use pipes to tell the LLM explicitly: *"The sandbox runs commands via argv (no shell). Do NOT use shell pipes (`|`), redirects (`>`), process substitution (`<(...)`), or chained commands (`&&`). Use tool flags for filtering (e.g. `httpx -path` instead of `httpx | grep`)."* This is a one-paragraph prompt change, no code impact.

**Verification:** Spawn a sandbox manually and run `curl -s https://juice-shop.local:3001`. It should succeed. Also run `nc -z 127.0.0.1 3128` — should return immediately. The fix is minimal because the proxy mechanism is already wired; only the PID-file write permission is blocking.

---

## Part B — Fully-automated auth acquisition (`auth_worker_agent`)

### Current state of the auth pipeline (architectural summary)

The auth subsystem is already architecturally complete and well-factored:

**Detection** (`src/core/auth/auth_detector.ts`) → **Capture** (`src/core/auth/auth_browser_capture.ts` + `scripts/auth_capture.mjs`) → **Wizard UI** (`src/components/AuthWizardModal.tsx`) → **Persistence** (`src/contexts/SettingsContext.tsx` → `src-tauri/src/secure_storage.rs` AES-256-GCM) → **Session management** (`src/core/auth/session_manager.ts`) → **Runtime injection** (`src/core/engine/react_loop.ts` via `applyToRequest()` for HTTP + `session_env.ts::buildSessionEnv()` for sandbox `HUNTRESS_AUTH_*` env vars) → **Refresh** (`src/core/auth/token_refresher.ts` with 4 strategies).

The **only manual step** in the whole pipeline is the wizard's middle — Step 2, where the user either pastes credentials or clicks "Browser Capture". The capture flow launches a Playwright subprocess via `execute_training_command` → `scripts/auth_capture.mjs` — which does open a real browser — but **the user still has to drive it**: navigate to login, fill the form, click submit, wait for redirect. The script only intercepts requests; it doesn't fill forms.

### The goal

Replace the wizard's Step 2 with a single **"Let Huntress log in for you"** button. When clicked, an `AuthWorkerAgent` takes over:

1. Receives: target URL, scope domains, and (for the agent's inputs) username + password + optional 2FA seed.
2. Uses the existing agent infrastructure (ReactLoop + browser tools) to drive Playwright headed-or-headless, navigate the login flow, handle common variations (redirects, OAuth consent screens, reCAPTCHA-less targets), and intercept the resulting auth artifacts.
3. Returns: `CapturedAuth` (identical shape to what `auth_browser_capture.ts` returns today), which the wizard auto-fills.

The user types username + password once, clicks one button, and credentials are captured + persisted. Zero clicks into DevTools, zero network tab inspection, zero manual paste.

### What's feasible today vs. what's not

Feasible for the first cut (from the third research agent's findings):

| Flow | Feasibility | Notes |
|---|---|---|
| Classic form login (user/pass) | ✅ **Fully** | Playwright + LLM prompting = 100% automatable |
| Bearer-in-DOM-after-login (SPAs) | ✅ **Fully** | Agent navigates, waits, reads localStorage + XHR headers |
| Custom headers (wallet-authorization etc.) | ✅ **Fully for non-Telegram** | Same as bearer — intercept XHR |
| OAuth2 Auth Code w/ in-scope IdP | ✅ **Mostly** | Agent drives OAuth flow, catches redirect-with-code |
| TOTP 2FA (user provides seed) | ✅ **Yes** | Use `otplib` to generate code, agent types it |
| SMS 2FA | ⚠ **Manual** | Out of scope — user types code live (agent waits) |
| Telegram Mini App (initData) | ❌ **Not automatable** | Requires MTProto sidecar. Phase 4+, deferred |
| WebAuthn/passkey | ❌ **Not automatable** | Hardware required |
| Magic link (email) | ⚠ **Only w/ mail gateway** | Mailosaur/Mailtrap integration, Phase 3+ |

First-cut scope: **classic form login + bearer-in-DOM**. That covers ~70% of real H1 targets and is where the user's manual burden is highest right now.

### Architecture — the `AuthWorkerAgent`

**New agent**, lives at `src/agents/auth_worker_agent.ts`, implementing `BaseAgent` (interface at `src/agents/base_agent.ts`). Unlike every other agent in Huntress, this one doesn't hunt vulnerabilities — it performs a targeted login flow and returns captured credentials.

**Why reuse the agent framework** instead of just beefing up `auth_capture.mjs`:
- ReactLoop + LLM reasoning handles variant login flows (modal vs page, redirect vs popup, 2FA step, OAuth consent)
- The existing browser tool schemas (`BROWSER_NAVIGATE_SCHEMA`, `BROWSER_CLICK_SCHEMA`, `BROWSER_EVALUATE_SCHEMA`, `BROWSER_GET_CONTENT_SCHEMA` in `tool_schemas.ts`) already do everything we need
- `AgentBrowserManager` (`src-tauri/src/agent_browser.rs`) already manages persistent Playwright subprocess sessions
- Failure modes benefit from an LLM recover-path (e.g., "login button moved to a dropdown" → the LLM notices and clicks the right place)

**The agent's system prompt** (excerpt):

> You are an authentication capture agent. Your goal is to log into a target web application and capture the resulting auth credentials (bearer tokens, cookies, custom headers). You drive a real browser via `browser_navigate` / `browser_click` / `browser_evaluate` / `browser_get_content`. Given the login URL, a username, and a password, you should:
>
> 1. Navigate to the login URL.
> 2. Find the username and password fields (usually `input[type=email]`, `input[type=password]`, or via placeholder/aria-label). Fill them.
> 3. Click submit. Wait for navigation.
> 4. If redirected to an OAuth consent screen: approve (click the primary/allow button).
> 5. If a 2FA challenge appears and a TOTP seed was provided, compute the code and fill the field.
> 6. After login succeeds (you are on a logged-in page — dashboard, profile, etc.), inspect `localStorage`, `sessionStorage`, and the cookie jar. Capture any `Authorization` headers from recent XHR.
> 7. Emit a single `capture_complete` tool call with the structured result.
>
> If the flow fails — wrong credentials, captcha, unknown 2FA — emit `capture_failed` with a short reason. Do NOT report findings. You are not hunting.

**New tool: `capture_complete`** — defined in `src/core/engine/tool_schemas.ts` alongside the existing ones, produces a `CapturedAuth`-shaped payload identical to what `scripts/auth_capture.mjs` returns today. The wizard consumes the same shape, so downstream code is unchanged.

**New XHR interceptor for the agent's browser session** — today's `scripts/agent_browser.mjs` doesn't intercept XHR (it's built for hunting, not capture). We add a new `action: 'start_auth_capture'` that turns on request interception and a `action: 'finish_auth_capture'` that returns captured headers/cookies/storage. Minimal patch — `agent_browser.mjs` gains ~80 LOC of interception logic (can be cribbed from `scripts/auth_capture.mjs:60-130`).

### Wizard UX change

Replace the current Step 2 form (which has both manual-paste fields AND a "Browser Capture" button) with three explicit paths:

| Path | Visible UI | Behavior |
|---|---|---|
| **"Let Huntress log in"** (new primary) | Username + Password + optional TOTP seed fields. "Run Automated Login" button | Spawns `AuthWorkerAgent`; button becomes progress indicator; on success, auto-advances to Step 3 with credentials pre-filled (user just picks role + saves) |
| "Paste manually" | Today's paste fields | Unchanged fallback for Telegram / weird targets |
| "Supervised browser" | Today's "Browser Capture" button | Keep as escape hatch for targets the agent can't handle |

The current browser-capture button stays, renamed to "Supervised capture — I'll drive the browser". The new primary flow is fully automated.

### Irreducible user inputs

Even with full automation, the user always has to supply:
- Username + password (they created the account — we can't guess)
- TOTP seed if 2FA is active (same rationale)
- (Telegram) real Telegram account access — no change from today

The automation removes: form-filling, button-clicking, XHR inspection, DevTools usage, credential copy-paste.

### Files that change (Part B scope)

| Path | Change |
|---|---|
| `src/agents/auth_worker_agent.ts` (new) | New agent class implementing `BaseAgent` |
| `src/agents/agent_catalog.ts` | Register `auth_worker_agent` |
| `src/core/engine/tool_schemas.ts` | Add `CAPTURE_COMPLETE_SCHEMA` + `CAPTURE_FAILED_SCHEMA`; extend `AGENT_TOOL_SCHEMAS` for this agent only |
| `src/core/orchestrator/cost_router.ts` | Map `auth_worker` → `moderate` complexity (~40-iter budget) |
| `scripts/agent_browser.mjs` | Add `start_auth_capture` / `finish_auth_capture` actions with XHR interception + storage dump |
| `src/components/AuthWizardModal.tsx` | Restructure Step 2 to show "Let Huntress log in" as the primary path |
| `src/contexts/HuntSessionContext.tsx` | Add `runAuthWorker(config, creds)` method that spawns the agent and returns `CapturedAuth` |
| Tests | `src/tests/phase2_auth_worker_agent.test.ts` (new) — ~15 cases covering login detection, form-fill, OAuth consent, 2FA, failure modes |

Estimated effort: ~600 LOC new code, ~15 tests, **2-3 engineering days** for the first cut covering form-login + bearer-in-DOM. OAuth2 with in-scope IdP adds another ~1 day. TOTP adds ~0.5 day (just `otplib` integration).

### Why this is safe

- **No new security surface**: the Playwright subprocess already exists (`scripts/agent_browser.mjs`) and already has XHR interception capability
- **Scope enforcement intact**: browser-side navigation goes through the existing scope check in `react_loop.ts::handleBrowserNavigate`
- **Credentials never leave Huntress**: they travel from the wizard form → Tauri IPC → agent prompt → browser form fills. They are never logged (scrubbed at the `scrubAuthSecrets` layer added in Phase 1 Q1)
- **Fallbacks preserved**: manual paste and supervised browser stay available for the ~30% of targets the agent can't handle

### What the user sees

```
[Huntress Auth Wizard — Step 2 of 3]
┌─────────────────────────────────────────────────┐
│ 🤖  Let Huntress log in for you                 │
│                                                 │
│  Username:  [daisy@juice-shop.local]            │
│  Password:  [••••••••]                          │
│  TOTP seed (optional): [                     ]  │
│                                                 │
│  [ ▶ Run automated login ]                      │
│                                                 │
│  — or —                                         │
│  [ Paste manually ]   [ Supervised capture ]    │
└─────────────────────────────────────────────────┘
```

After clicking "Run automated login":
- Status line shows the agent's progress ("Navigating to login… Filling credentials… Waiting for redirect… Captured bearer token, 3 cookies")
- ~15-30 seconds on average
- On success, advances to Step 3 (Role + Save) with everything pre-filled

### Verification plan (for both parts)

**Part A (issues):**
- Unit: `src/tests/phase1_recon_success_semantics.test.ts` (new, ~8 cases) — recon agent iteration-limit exit now marks success=true, triggering solver tasks
- Unit: existing cargo tests — no regressions after Dockerfile / tinyproxy changes
- Integration: launch a Juice Shop hunt (offline target, no auth needed) and verify specialists dispatch within 5 min of recon starting
- Manual: `docker exec -it $(docker ps -q -f name=huntress-) curl -s https://juice-shop:3000` should now succeed (tinyproxy fix)

**Part B (auth worker):**
- Unit: `src/tests/phase2_auth_worker_agent.test.ts` — mocked provider that simulates each login-flow variant (basic, OAuth consent, 2FA, failure)
- Integration: live test against Juice Shop's login form (bundled + deterministic credentials). Agent completes in <30s, wizard auto-advances, hunt starts with the captured cookie
- Real-target test: `pay.wallet.tg` still needs manual paste (Telegram is out of scope) — verify fallback path works

---

## Critical files to read before executing

| Path | Why |
|---|---|
| `src/core/engine/react_loop.ts:317,495` | Issue #6 fix site (success calculation + stopReason assignment) |
| `src/core/orchestrator/orchestrator_engine.ts:2358` | The gate that needs to fire after recon |
| `docker/tinyproxy.conf:28` | PidFile path change for Issue #9 |
| `docker/entrypoint.sh` | Tinyproxy startup sequence for Issue #9 |
| `src-tauri/src/sandbox.rs:292-322` | Proxy env + tmpfs mount audit |
| `src/agents/base_agent.ts` | BaseAgent interface for new auth_worker |
| `src/components/AuthWizardModal.tsx:115-250` | Step 2 form state (to restructure) |
| `scripts/agent_browser.mjs` | Extend with XHR capture actions |
| `scripts/auth_capture.mjs:60-130` | XHR interception logic to crib from |
| `src/core/auth/auth_browser_capture.ts` | CapturedAuth shape — do not change |
| `src/core/engine/tool_schemas.ts` | Where new capture tools get registered |
| `AUTH_RESEARCH_AND_CONTINUATION.md` §3-5 | Full Telegram deep-dive for why it stays manual |
| `DEEPER_AUTH_RESEARCH_AND_PLAN.md` §Q4,§Q5 | MTProto go/no-go + protocol coverage table |

## Execution order

1. **Part A Issue #9 first** (tinyproxy PID file) — smallest change, unblocks curl for every other future test
2. **Part A Issue #8** (remove dnsx/wafw00f from pipeline + prompt) — stops iteration-waste
3. **Part A Issue #6 residual** (success semantics + recon stopReason) — requires most careful testing because it changes a load-bearing invariant; should land with 8+ test cases
4. **Run the full test suite** — confirm 2,029 + 7 new pass
5. **Re-run a Juice Shop hunt end-to-end** — confirm specialists dispatch, curl works in sandbox, exit-126s are gone from recon
6. **Part B stage 1**: extend `scripts/agent_browser.mjs` with capture actions (safe, additive)
7. **Part B stage 2**: build `AuthWorkerAgent` + register + tests
8. **Part B stage 3**: rewire `AuthWizardModal` Step 2 with the three-path choice
9. **Integration test**: Juice Shop auth flow end-to-end via the new button

Part A: ~4 hours. Part B: ~2-3 days. Can be done in either order but A-before-B makes the B integration test much easier to run.

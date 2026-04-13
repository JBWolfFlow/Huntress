# Huntress Authentication Subsystem — Research Findings & Continuation Brief

> **Status:** Research dossier produced 2026-04-12 after diagnostic work on Session 24 (Hunt #11 auth blockage). This document has two parts: (1) the current findings, synthesized from code inspection and parallel protocol research; (2) a continuation prompt engineered for a fresh Claude instance to pick up the work, deepen the understanding, and drive to a full automated solution.

> **Audience:** senior security engineer + AI systems architect. No hand-holding. No reintroducing concepts established in `CLAUDE.md`.

---

## PART I — FINDINGS

### 1. What authentication actually is (frame)

Auth is the server's answer to *"Why am I choosing to trust this request?"* — and the "why" is always one of five credential shapes landing in a request:

| Credential | Transport | Example |
|---|---|---|
| Session cookie | `Cookie:` header | Traditional web sessions |
| Bearer token | `Authorization: Bearer …` | JWTs, OAuth access tokens |
| API key | Custom header | `X-API-Key`, permanent |
| Client certificate | TLS handshake | mTLS (enterprise) |
| Signed assertion | Header or body | Telegram `initData`, SAML assertion, WebAuthn |

Everything else — form login, OAuth dance, Telegram WebApp launch — is a *ceremony* that ultimately *produces* one of the above. Every auth system also faces two orthogonal concerns: **lifetime** (finite), and **refresh** (how to renew).

### 2. What Huntress is trying to do

Let an agent fleet test the *authenticated* attack surface of a target without a human re-authenticating between dispatches. Concretely:

1. **Detect** that auth is required
2. **Acquire** a credential once, cheaply
3. **Store** it securely across hunt restarts
4. **Inject** it into every authenticated request an agent makes
5. **Refresh** it automatically when short-lived tokens expire
6. **Handle 401s** mid-hunt without aborting
7. **Support multi-identity** testing (IDOR/BOLA needs two identities)

### 3. What the code actually does — end-to-end trace

**Detection** (`src/core/auth/auth_detector.ts`) runs three concurrent analyses over the first 8 in-scope targets: HTTP probe (401/403/redirect-to-login/password-form), program-text keyword analysis, tech-fingerprint heuristics. Produces `DetectedAuthType[]` + suggested profiles. Works for classic web; flags Telegram via keyword match but has no probe that can confirm/deny.

**Capture** (`scripts/auth_capture.mjs`, invoked via `src/core/auth/auth_browser_capture.ts` through Tauri `execute_training_command`) opens a visible Chromium window, intercepts every request with `page.route('**/*')`, greps headers for a fixed set of auth names (`Authorization`, `X-API-Key`, `X-CSRF-Token`, `wallet-authorization`, `x-access-token`, etc.), and detects "login success" heuristically when a `POST /(login|auth|signin|token|session|oauth)/i` fires **or** a `Set-Cookie` response arrives. Returns `{ bearerToken, cookies, customHeaders, localStorage, sessionStorage, finalUrl }`.

**Wizard** (`src/components/AuthWizardModal.tsx`) pre-fills the form from the capture result, offers four profile types (bearer/cookie/api_key/custom_header), and optionally configures a refresh strategy (`initdata_exchange` | `refresh_token` | `custom_endpoint` | `re_login`).

**Storage** — profile metadata goes to localStorage; every credential string goes to Tauri secure storage (AES-256-GCM) keyed by `auth_profile_${id}_${field}`. Zero secrets in localStorage. Good.

**Activation** (`HuntSessionContext.continueAfterAuth`, `src/contexts/HuntSessionContext.tsx:834`) iterates `settings.authProfiles` and calls the appropriate `sessionManager.loginWith*` method per auth type. Sessions land in `SessionManager.sessions: Map<string, AuthenticatedSession>`. `expiresAt` is auto-populated from JWT `exp` claims (no external JWT library; pure base64+JSON.parse).

**Dispatch wiring** — on every agent dispatch (`src/core/orchestrator/orchestrator_engine.ts:2860`) `authSessionIds: this.sessionManager?.listSessions().map(s => s.id) ?? []` is read *fresh*. This means mid-hunt auth injection (I4) works: the next dispatch picks up the new session. Good property. However, the agent-side code in every `src/agents/*.ts` picks only `authSessionIds?.[0]` and passes a scalar to the ReactLoop — the multi-identity capability is architecturally present but practically discarded.

**Injection** (`src/core/auth/session_manager.ts:94` `applyToRequest`) merges `session.headers`, joins `session.cookies` into a `Cookie:` header, and stamps CSRF tokens. Only invoked by `sessionManager.authenticatedRequest()`, which is only called from `ReactLoop.handleHttpRequest` (`src/core/engine/react_loop.ts:1173-1186`) when the agent uses the `http_request` tool.

**Refresh** (`src/core/auth/token_refresher.ts`) — three-layer defense: proactive (within 90s of expiry), reactive (401 auto-retry), rate-limited (1 per 30s per session, in-flight deduped). Four strategies in a discriminated union. JWT exp parsing works for any JWT-bearing header. Clean, tested, correct.

### 4. What is actually getting in the way (categorical failures)

**Gap 1 (CRITICAL) — Protocol mismatch for Telegram/OAuth/SPA targets.**
The capture script assumes a real login ceremony happens inside the launched Chromium. For Telegram Mini Apps, the credential (`initData`) is produced by Telegram's infrastructure + the user's real Telegram client (desktop/mobile), signed with `HMAC_SHA256(bot_token, "WebAppData")`. It cannot be forged without the bot token. A plain Playwright browser navigating to `pay.wallet.tg` sees `window.Telegram.WebApp.initData === ""`, the app's JS calls the auth endpoint with empty initData, server returns 400/401 — and the capture script has nothing to intercept. The same failure pattern applies to:
- OAuth flows where the IdP is out of scope (flow never completes inside scope)
- Passkey/WebAuthn (no authenticator hardware)
- SMS 2FA with anti-bot SMS blocks
- Magic-link email (can't read email in Playwright)

**Gap 2 (CRITICAL) — Execution-plane split.**
Auth is injected in exactly one path (`http_request` tool → `authenticatedRequest`). Agents have a second, equally capable tool — `execute_command` — which runs arbitrary commands in the Docker sandbox. `SandboxExecutor.create(scope, envVars?)` is called at `orchestrator_engine.ts:1215` with `envVars` omitted. The container has no session info, no cookie jar mount, no `~/.curlrc` stamped with auth. When an agent runs `curl https://pay.wallet.tg/wpay/store-api/orders/123`, the request goes out unauthenticated through tinyproxy. Tinyproxy only enforces *scope*, not *identity*. Pentesters (and agents modeling pentesters) reach for `curl`/`ffuf`/`sqlmap` by default — so the auth-aware path is the minority path in practice.

**Gap 3 (CRITICAL) — Agent has no awareness of its own auth state.**
`buildSystemPrompt()` at `react_loop.ts:1728-1786` contains zero information about authentication. No "you have session X active," no "prefer `http_request` to use it," no "if you see 401 report auth_expired, don't treat as finding." So even if Gap 2 were fixed, agents make wrong tool choices because their mental model contains no auth context.

**Gap 4 (HIGH) — Multi-identity testing is architecturally half-built.**
`authSessionIds` flows as an array all the way to the agent. Every agent discards the array and uses `[0]`. IDOR/BOLA testing needs two identities to prove cross-account access; there is no tool or prompt mechanism for an agent to request a *specific* session.

**Gap 5 (HIGH) — `loginWithBearer` validation is too lenient.**
`session_manager.ts:173-199` GETs `validationUrl` and only rejects on explicit 401/403. Any other status passes — so a target that returns 500 on missing auth (exactly Wallet's behavior on `/wpay/store-api/`) would report `[TEST AUTH] → AUTH VALID` on a bogus token, then fail silently during hunting.

**Gap 6 (MEDIUM) — Capture heuristics miss real-world endpoints.**
`scripts/auth_capture.mjs:101` regex `/(login|auth|signin|token|session|oauth)/i` misses `/v1/identity/verify`, `/sso/consume`, `/passport/issue`, `/webapp/init`. Cookie domain filter is exact-match on scope entries; real auth cookies set by `.accounts.target.com` (often out of scope by H1 rules) get dropped silently.

**Gap 7 (MEDIUM) — Process-local cookie jar.**
`HttpClient`'s `CookieJar` is a `Map` in the TypeScript process. The Docker sandbox's curl has an empty cookie jar. Even if cookie auth worked for `http_request`, any `execute_command` reliant on cookies fails.

**Gap 8 (MEDIUM) — No `expiresAt` for opaque bearer tokens or cookie sessions.**
`populateExpiresAtFromHeaders` only works when a header *is* a JWT. Opaque tokens (e.g., GitHub PATs, random-string session IDs) and pure cookie sessions never get proactive refresh — they're refreshed only reactively on 401. For targets where 401 triggers a logout cascade (refresh token invalidation, session family rotation), this is a real risk.

### 5. Telegram-specific deep context (from protocol research)

Structurally, `initData` is a URL-encoded query string with `query_id`, `user` (JSON blob), `auth_date`, `start_param`, `chat_type`, `chat_instance`, and `hash` (HMAC-SHA256). The HMAC key is `HMAC_SHA256(bot_token, "WebAppData")` — note the reversed argument order (message = bot token, key = literal "WebAppData"). A newer Ed25519 flow (`signature` field) is being rolled out but Wallet appears to use HMAC.

Wallet's `x-wallet-device-serial` is a client-generated UUID persisted in localStorage, used for anti-fraud correlation — not cryptographically verified. Must be captured and pinned alongside the JWT.

The typical Wallet auth flow (reconstructed):
```
1. User taps "Open Wallet" in Telegram chat.
2. Telegram client generates initData, opens webview at pay.wallet.tg.
3. Page JS reads window.Telegram.WebApp.initData.
4. POST https://walletbot.me/api/v1/auth/telegram
     Body: { initData, deviceSerial }
     → { accessToken, expiresIn: 600, user: {...} }
5. Subsequent requests:
     Authorization: Bearer <accessToken>
     x-wallet-device-serial: <uuid>
     Origin: https://pay.wallet.tg
6. On 401: re-read Telegram.WebApp.initData (still valid for ~1h per auth_date),
   repeat step 4, retry original request.
```

Acquisition paths for an automated tool, ranked by viability:
- **A. Manual capture from real Telegram client** — ~10 min of DevTools work. What security researchers actually do. Requires a burner Telegram account (real phone number).
- **B. MTProto sidecar** (`tdlib`, `gramjs`, `Pyrogram`, `Telethon`) — use `messages.requestWebView` / `messages.requestSimpleWebView` to produce fresh initData on demand. Complex (persistent MTProto session state, 2FA, API_ID/API_HASH from `my.telegram.org`, anti-abuse risk) but truly automatable.
- **C. Scrape from web.telegram.org** — full web client, MTProto keys in IndexedDB; automatable but fragile, all hunts tied to one account.
- **D. Request test credentials from program** — many programs provide sandbox bots; always ask via H1 first.
- **E. "Test mode"** — does not apply; Telegram's test DCs are for bot developers testing their own bots, not external pentesters.

### 6. What all this means for Hunt #11

A *stacked* failure chain, any layer sufficient to block:
1. Auto-capture cannot produce Telegram credentials (Gap 1).
2. Even with a manually pasted credential, `curl`-based agent tools won't use it (Gap 2).
3. Even if both are fixed, the agent doesn't know it's authenticated and chooses the wrong tool (Gap 3).
4. Even if fully authenticated, single-identity IDOR proofs are thin; real high-value findings need an identity pair (Gap 4).

### 7. Reference — file paths & critical line numbers

| Purpose | Path | Notable lines |
|---|---|---|
| Auth detection | `src/core/auth/auth_detector.ts` | 100-197 pattern groups / fingerprint rules |
| Browser capture (TS wrapper) | `src/core/auth/auth_browser_capture.ts` | 57-142 `captureAuth()` |
| Browser capture (Node subprocess) | `scripts/auth_capture.mjs` | 78-114 route intercept / login detection |
| Wizard UI | `src/components/AuthWizardModal.tsx` | 147 capture handler / 256 save handler |
| Secure storage | `src/contexts/SettingsContext.tsx` | 376 addAuthProfile / 427 getCredentials |
| Session activation | `src/contexts/HuntSessionContext.tsx` | 834 continueAfterAuth / 1005 openMidHuntAuth |
| Session manager | `src/core/auth/session_manager.ts` | 94 applyToRequest / 286 authenticatedRequest |
| Token refresher | `src/core/auth/token_refresher.ts` | 165 refreshTokens / 208 buildRefreshRequest |
| Orchestrator wiring | `src/core/orchestrator/orchestrator_engine.ts` | 1215 sandbox create / 2860 authSessionIds |
| ReactLoop — auth path | `src/core/engine/react_loop.ts` | 1173 http_request auth / 1728 system prompt |
| ReactLoop — gap | `src/core/engine/react_loop.ts` | 609 handleExecuteCommand (no auth) |
| Sandbox | `src/core/tools/sandbox_executor.ts` | 55 create() / 138 execute() |

---

## PART II — CONTINUATION RESEARCH PROMPT

Everything below this line is designed to be handed verbatim to a fresh Claude instance to continue the work. Copy the section, paste into a new session, and let it run.

---

```
# Role

You are a principal security engineer and authentication protocols expert
embedded in the Huntress project (a Tauri 2.0 + React 19 + Rust desktop app
that automates HackerOne bug bounty hunting with an orchestrator of 29
specialized agents). You have deep working knowledge of: OAuth 2.0/2.1, OIDC,
WebAuthn/passkeys, SAML, JWT lifecycle, HMAC-signed client assertions
(Telegram WebApp initData), mTLS, session-cookie conventions across modern
frameworks, CSRF defenses, token rotation patterns, and the practical
ceremonies — SMS 2FA, TOTP, magic links, QR-code device pairing — that users
are forced through at login time.

You are ALSO a Tauri/Playwright systems architect. You understand the
impedance mismatch between:
  - a webview (the Tauri frontend — no Node module access)
  - a Node.js subprocess (can run Playwright; can't persist browser state)
  - a Rust backend (long-lived, can manage subprocesses and secrets)
  - a sandboxed Docker container running as an agent (runs arbitrary tools,
    has its own filesystem and cookie jar, talks to the outside world via
    tinyproxy for scope enforcement).

You have been handed a partially-diagnosed authentication subsystem. The
diagnosis is in AUTH_RESEARCH_AND_CONTINUATION.md at the repo root. Read
PART I of that document IN FULL before doing anything else. It contains
file paths, line numbers, and categorical gaps (Gap 1 through Gap 8). Do
not re-derive what is already established there. Your job is to go DEEPER,
not BROADER in the same direction.

# Mission

Produce the architectural plan and technical research that transforms the
Huntress auth subsystem from "70% solution for classic web apps" to "works
reliably on modern targets including Telegram Mini Apps, OAuth IdP flows,
SPA-front / API-back architectures, and eventually mobile-originated auth."

The plan must be implementable by a subsequent coding session without
further research — i.e. you are responsible for closing every architectural
uncertainty before handing off. If you propose "MTProto sidecar," you must
specify which library, how session persistence works, how 2FA is handled,
what API credentials are needed, what the IPC protocol with the Rust side
looks like, and where the sidecar process dies gracefully.

# What has already been established (do not redo)

PART I of AUTH_RESEARCH_AND_CONTINUATION.md establishes:
  - The current TS code paths for capture, storage, activation, injection,
    refresh, with file paths and line numbers.
  - Eight categorical gaps (Gap 1 = protocol mismatch, Gap 2 = execution-
    plane split, Gap 3 = no agent auth-awareness, Gap 4 = single-identity
    only, plus five more).
  - The Telegram WebApp protocol (initData structure, HMAC derivation,
    lifetime, refresh, device-serial anti-fraud header).
  - Five acquisition paths for Telegram credentials (A-E) with tradeoffs.

Treat these as facts. Start from them. Challenge only if you find a
specific factual error while reading code.

# Hard architectural invariants (do not violate)

These are load-bearing decisions in the existing codebase:

1. HttpClient (src/core/http/request_engine.ts) is the SINGLE HTTP chokepoint
   — kill-switch, scope validation, rate limiting, stealth headers, WAF
   detection run in order. Do not propose any path that bypasses it. If your
   solution wants auth-aware curl inside the sandbox, the curl still has to
   traverse tinyproxy (which traverses the HttpClient chain if proxied out).
   Do not punch holes in the chokepoint.

2. Scope validation is default-deny (src-tauri/src/safe_to_test.rs). Any
   credential injection must be scoped to in-scope hosts only. An auth
   header leaking to an out-of-scope redirect is a scope violation.

3. Secrets go through Tauri secure storage (AES-256-GCM via
   src-tauri/src/secure_storage.rs). localStorage NEVER touches a credential
   value. This is non-negotiable.

4. Agents are fire-and-forget dispatched. Any new auth-aware mechanism must
   survive the async-concurrent-dispatch model — 5 agents in parallel, each
   with potentially different auth contexts.

5. Tauri WebView cannot load Node-native modules (playwright-core,
   tdlib-native, etc.). Any such code lives in a Node subprocess launched
   from Rust via `execute_training_command` or `agent_browser_spawn`
   (the I2 persistent-stdio-IPC pattern already exists — see
   src-tauri/src/agent_browser.rs).

6. Anthropic models only. Do not propose using a different LLM to analyze
   captured auth traffic — the orchestrator and validators are locked to
   Anthropic.

7. One human at the keyboard during capture is acceptable. Full unattended
   end-to-end auth ACQUISITION is a stretch goal for later phases; getting
   the post-acquisition pipeline right comes first.

# Research questions (in priority order)

## Q1 — Execution-plane unification
Close Gap 2. When an agent runs `curl https://target/api/foo` via
execute_command, auth must attach. Propose a design. At minimum evaluate:

  (a) Env-var injection into the Docker container at create time +
      ~/.curlrc pre-stamped at first exec. Pros: simple. Cons: curlrc
      applies to all targets, not just in-scope — review sandbox scope
      enforcement model to confirm this is safe.

  (b) Mount a shared cookie jar file. Pros: matches curl semantics. Cons:
      how does it stay in sync with the HttpClient's in-process CookieJar?

  (c) Auth-injecting proxy inside the container (rewrite headers on the
      way out via tinyproxy or a sidecar). Pros: transparent to agents.
      Cons: tinyproxy may not support this natively; complexity.

  (d) Replace execute_command with an "authenticated_execute_command" that
      intercepts curl/ffuf/sqlmap-style invocations, extracts the URL,
      routes through http_request instead. Pros: single injection point.
      Cons: breaks tools that aren't simple HTTP clients (wfuzz, etc.).

For the chosen design, specify: what `SandboxExecutor.create()` signature
changes to; what container runtime state needs to be materialized; how
refresh (if token rotates) propagates back into the container without
tearing it down; how scope validation stays intact; testing strategy that
proves no auth leaks to out-of-scope requests.

## Q2 — Agent auth awareness (close Gap 3)
Design the system prompt extension. The agent needs to know:
  - auth type (bearer / cookie / custom_header / none)
  - session label(s) if multiple identities
  - which tool to prefer (`http_request` vs `execute_command` — after Q1
    this changes; design for both before and after state)
  - what 401 means (expired token, NOT a finding)
  - when to request a second identity (for IDOR)

Write the exact prompt block that will be injected into the agent's system
prompt. Length budget: ≤ 400 tokens. Justify every line — prompt real
estate is expensive at 5 agents × 120 iterations.

## Q3 — Multi-identity architecture (close Gap 4)
Propose a tool + prompt contract that lets an agent request and use a
specific session. At minimum:

  - new tool: `request_identity(label: "victim" | "attacker" | custom) ->
    sessionId` — returns a sessionId the agent can pass to subsequent
    http_request calls (OR the agent's http_request gains an optional
    `session_label` parameter)
  - SettingsContext authProfiles gain a `role?: string` field for IDOR-
    pairing hints ("victim", "attacker", "admin", "regular_user")
  - UI: AuthWizardModal allows labeling profiles by role; Auth tab shows
    "you have 1 victim / 1 attacker — IDOR-ready" badge

Decide whether the agent carries one session at a time (switch via tool)
or whether `http_request` takes an explicit session parameter per call.
Justify. Consider: what happens if the agent forgets to switch and tests
cross-account access using only the victim identity? How does the system
catch this?

## Q4 — Telegram automated acquisition (close Gap 1 for Telegram)
Evaluate the MTProto sidecar path (Option B from PART I) rigorously.
Deliver:

  (a) Library choice: tdlib vs gramjs vs Pyrogram vs Telethon. Criteria:
      language (Node.js preferred to match agent_browser.mjs pattern),
      maintenance status in 2026, session-file durability, 2FA support,
      binary-or-pure-JS nature (tdlib requires native compilation).

  (b) API credentials: how the user obtains API_ID + API_HASH from
      my.telegram.org. Whether this is a one-time setup or per-hunt.
      Where these go (secure storage).

  (c) Session persistence: how the MTProto auth-key file is stored.
      What happens across restarts. Revocation strategy.

  (d) Login ceremony: how the phone-number + SMS-code + optional 2FA
      flow is surfaced to the user through Huntress UI (likely a new
      "Telegram Account" setup screen in Settings, one-time, persists).

  (e) The operation we actually need: given a configured Telegram account
      + a bot username (e.g. "@wallet"), produce a fresh initData string.
      MTProto call: `messages.requestWebView` or
      `messages.requestSimpleWebView`. Response contains a URL with
      `#tgWebAppData=<initData>` in the fragment. Parse and return.

  (f) IPC protocol: subprocess command shape (JSON-over-stdin like
      agent_browser.mjs), commands: authenticate-account, list-accounts,
      request-webview(botUsername, url), dispose-account. How long the
      subprocess stays alive. Crash-recovery model.

  (g) Anti-abuse surface: what happens if Telegram flags the account for
      automated behavior. How to throttle. Whether pooling multiple
      accounts (for IDOR pair testing) is viable.

  (h) Rollout: can this ship as opt-in behind a setting? What's the
      minimum-viable first cut vs full production version?

## Q5 — Protocol breadth beyond Telegram
Enumerate every auth ceremony class Huntress is likely to encounter in
real HackerOne programs over the next 12 months. For each, specify:
acquisition path, whether the current capture script works, what would
need to change. Include at minimum:

  - Classic form login (current script works)
  - OAuth 2.0 Authorization Code with PKCE (IdP often out of scope —
    design a capture mode that re-enters scope after the redirect dance)
  - OAuth 2.0 Resource Owner Password Credentials (deprecated but still
    out there; scriptable)
  - SAML SP-initiated flow (redirects to IdP; IdP out of scope)
  - OIDC implicit (dying but still exists)
  - Passkey / WebAuthn (requires authenticator hardware — mark as
    manual-only, document)
  - SMS 2FA (intercept code via SMS API vendor? or manual)
  - TOTP / HOTP 2FA (user enters code from authenticator app — manual;
    potentially script with a user-provided secret)
  - Telegram Mini App (covered in Q4)
  - Discord OAuth / Discord bot tokens
  - Slack OAuth / bot tokens / user tokens
  - AWS SigV4 (for programs that run on AWS-SDK-style APIs)
  - Firebase Auth / Supabase Auth (popular in SPAs)
  - Google Sign-In (GSI — popup flow, postMessage-based)
  - Apple Sign In (privacy-preserving; complex)
  - Magic links (user must open email — hard to automate)

For each, mark viability: [AUTOMATABLE] [SEMI] [MANUAL-ONLY]. Output
table. This is strategic input for prioritization.

## Q6 — Capture script hardening
Close Gap 5, Gap 6, Gap 7, Gap 8. Specifically:

  - Gap 5: loginWithBearer validation must distinguish "500 because
    missing auth triggers NPE in server code" from "500 because the
    token is actually valid and the endpoint just has a bug." Propose
    a multi-probe validation strategy.

  - Gap 6: capture heuristic for "login endpoint" should not be a fixed
    regex. Consider: any POST with a response setting a Set-Cookie with
    HttpOnly+Secure is probably a login. Any POST whose response body
    contains a JWT is probably a login. Any response with
    Authorization: Bearer in subsequent requests (what the current
    script already catches) is a login.

  - Gap 7: shared cookie jar between HttpClient and sandbox. Options:
    mount a jar file at a well-known path, have a daemon in the container
    sync from HttpClient's state, embed a getter in the tinyproxy config.
    Pick one, justify.

  - Gap 8: opaque-token expiry detection. Propose: when a token is
    created with no JWT-parseable exp, start a "reactive-only refresh"
    mode where the session is marked unknown-lifetime and 401s trigger
    refresh but there's no proactive check. Ensure nothing in the
    pipeline assumes expiresAt is always populated.

## Q7 — Out-of-scope redirect leakage audit
Confirm (or refute) that the auth injection pipeline cannot leak
credentials to an out-of-scope host via redirect. Walk the code path:
`sessionManager.authenticatedRequest → HttpClient.request → Tauri
proxy_http_request Rust handler → reqwest with redirect-follow`. Does
reqwest drop Authorization on cross-origin redirect? If not, does
safe_to_test validate the redirect target BEFORE the request follows?
Report with file paths and line numbers.

## Q8 — The user experience unification
Propose the Settings → Auth tab redesign. Current UI has a mix of
post-import wizard and settings-panel management. Design the consolidated
experience:

  - "Auth Profiles" primary list with status indicators (valid / expired
    / never-tested)
  - Profile creation: presets per target class (Classic Web, OAuth,
    Telegram Mini App, Slack/Discord, Bearer/API Key, Custom)
  - Capture mode options: (1) browser-capture (current), (2) paste-from-
    DevTools (new — explicit guided flow), (3) import-from-authorization-
    header-string (quick), (4) Telegram-account-driven (requires Q4)
  - Pairing UI for IDOR: "This program needs two identities. Create
    Profile B from the same flow."
  - Refresh config UI simplified: detect strategy from profile type where
    possible, expose advanced only behind a disclosure.

Deliver wireframe sketches (ASCII OK) and the exact state machine of
the new wizard.

# Research methodology

Do NOT spawn research subagents immediately. You are expected to first
read the codebase deeply, first-hand, so that when you DO delegate, your
delegation prompts are precise. Recommended order:

  1. Read PART I of AUTH_RESEARCH_AND_CONTINUATION.md end-to-end.
  2. Read src/core/auth/session_manager.ts, token_refresher.ts,
     auth_detector.ts, auth_browser_capture.ts FULLY (not greps).
  3. Read scripts/auth_capture.mjs and scripts/agent_browser.mjs FULLY.
  4. Read src/core/engine/react_loop.ts around line 609
     (handleExecuteCommand) and 1170-1200 (http_request auth path) and
     1728-1786 (buildSystemPrompt).
  5. Read src/core/tools/sandbox_executor.ts and
     src-tauri/src/sandbox.rs FULLY.
  6. Read src/components/AuthWizardModal.tsx FULLY.
  7. Read src/contexts/HuntSessionContext.tsx around continueAfterAuth,
     openMidHuntAuthWizard, addAuthToActiveHunt.

Only AFTER primary-source reading, you may spawn Explore/general-purpose
agents for specifically:

  - Tauri plugin ecosystem survey: is there an existing Tauri plugin for
    OAuth / credential vault / mTLS that we could reuse?
  - MTProto library benchmarking: maintenance status of tdlib-node,
    gramjs, telegram (npm) as of 2026-04; real-world anti-abuse reports;
    whether "cold start" initData generation (no prior session) is
    practical or if you always need a pre-authorized account.
  - Prior art: how do other security tools (XBOW, Caido, Burp Extender
    ecosystem, OWASP ZAP, Nuclei) handle authenticated testing? What's
    the state of the art in 2025-2026?

Be precise in every delegation: hand files to read, questions to answer,
output format. Cap each delegation at 250 words of instruction.

# Anti-patterns to avoid

  - Do NOT propose solutions before understanding the code. If you find
    yourself recommending a fix before you've read the file it touches,
    stop.
  - Do NOT delegate synthesis. Subagents gather; you think.
  - Do NOT propose architectural changes that violate the invariants in
    the "Hard architectural invariants" section above.
  - Do NOT propose "rewrite session_manager.ts." The existing code is
    85% right. Augment it.
  - Do NOT invent abstractions the code doesn't need. Specifically do
    not propose a plugin architecture for "auth providers." The four
    profile types plus refresh strategies already cover this.
  - Do NOT recommend "use X library" without first checking it's already
    a dependency (grep package.json, Cargo.toml) or that adding it
    doesn't conflict with existing deps.
  - Do NOT produce a plan that requires shipping a Huntress-bundled copy
    of the Telegram bot token (or any other secret that belongs to the
    target company).
  - Do NOT hedge. If you think MTProto-based initData automation is
    infeasible in the next 3 months, say so clearly. If you think it's
    feasible in 2 weeks, commit.

# Deliverable

A single markdown document at the repo root:
  DEEPER_AUTH_RESEARCH_AND_PLAN.md

Structure:

  1. Abstract (≤200 words)
  2. First-pass understanding (your synthesis of what PART I established
     + what you learned from first-hand reading; do not re-explain what
     PART I already covers; add only what you *additionally* discovered)
  3. Answers to Q1 through Q8, each as its own section. For each:
     - Design proposal (prose + pseudocode where needed)
     - Tradeoffs considered
     - Decision + justification
     - Test strategy
     - File-level change list (paths + what changes)
  4. Protocol viability table (output of Q5)
  5. Implementation roadmap — phased, with exit criteria per phase.
     Phase 1 must be something that can ship this week; Phase 4 can be
     "depends on Telegram account infrastructure decisions we defer."
  6. Risk register — what could go wrong, how detected, how mitigated.
  7. Appendix: any supporting research output (protocol diagrams,
     sequence diagrams, comparison tables).

Cite file paths and line numbers inline. No dead-ends ("TBD," "need to
investigate"). If something genuinely needs more investigation, scope it
as a specific follow-up item in the roadmap, not a hole in the analysis.

# Tone

Expert-to-expert. No marketing voice. No "could potentially enable" —
say what it does. No emoji. No unnecessary adjectives. Dense, precise,
skimmable. If a reviewer who already wrote Huntress's auth code reads
your document, they should think: "this person understood it better
than I did, and they are right about what to do next."

# Success criteria

You are done when:
  1. The implementation roadmap is concrete enough that a coding
     session can execute Phase 1 without any further research.
  2. Every gap in PART I (Gap 1-8) has a specific close proposed.
  3. The protocol viability table covers ≥15 auth ceremonies.
  4. The Telegram path has a go/no-go recommendation with justification.
  5. The document passes the "no hedging" test: a reader can find no
     place where you avoided a decision by deferring it.

Start by reading PART I of AUTH_RESEARCH_AND_CONTINUATION.md, then the
files listed in the Research methodology section. Report your plan of
attack before producing the deliverable.
```

---

## PART III — How this document was produced

- First-hand code reading of the files cited in PART I by the author (Claude instance).
- Parallel delegation to (a) a Telegram protocol researcher and (b) an end-to-end request-flow code tracer.
- Synthesis of both returns plus the author's own reading.
- No file was written during research; all findings were held in the conversation until explicit request for this document.

## Change log

- 2026-04-12: initial document. Author: Claude instance running Session 24, post-I1–I8 work. Target handoff: fresh Claude instance picks up continuation prompt verbatim.

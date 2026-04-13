# Huntress Authentication Subsystem — Deeper Research & Implementation Plan

> Follow-on to `AUTH_RESEARCH_AND_CONTINUATION.md` (2026-04-12). PART I of that
> document established the end-to-end trace and the eight categorical gaps
> (Gap 1–8). This document answers the eight research questions (Q1–Q8), picks
> a Telegram go/no-go, produces the protocol viability table, and hands off a
> phased roadmap concrete enough to execute Phase 1 without further research.
>
> **Audience:** the coding session that ships the changes. No hedging. Every
> gap has a specific close. File paths and line numbers inline.

---

## 0. Execution Status (updated 2026-04-12, session 25)

**Phase 1 — SHIPPED.** All six Phase-1 items landed with passing tests.

**Session 25 live-hunt-shakeout:** attempted to validate Phase 1 by running a hunt against the Wallet-on-Telegram program. Phase 1 auth pipeline did not execute because the hunt got stuck in an extended recon loop (Issue #6 — recon's hardcoded `maxIterations: 60` prevented the orchestrator from reaching `generateSolverTasks()`). That and six other runtime bugs were caught during monitoring and fixed in-session; see `CONTINUATION_PROMPT.md` Session 25 changelog. Test suite 2,029 TS / 108 Rust, all green. Next hunt should exercise the auth pipeline end-to-end.


| Item | Status | Landing commit / file |
|---|---|---|
| Q1 env-var + `.curlrc` + token scrubbing | ✅ Done | `src/core/auth/session_env.ts`, `src-tauri/src/sandbox.rs::sandbox_write_file`, `scrubAuthSecrets` in `src/core/engine/react_loop.ts` |
| Q2 agent system-prompt auth block | ✅ Done | `ReactLoop.buildAuthSection` in `src/core/engine/react_loop.ts` |
| Q3 `session_label` + `role` + `findByLabel` + IDOR badge | ✅ Done | `SessionManager.findByLabel`, `HTTP_REQUEST_SCHEMA.session_label`, `AuthProfileConfig.role`, `SettingsPanel` IDOR badge |
| Q4 Telegram preset wizard (acquire only) | ✅ Done | `AuthWizardModal` dedicated DevTools paste-assist panel, auto-selects `initdata_exchange` refresh |
| Q6 Gap 5 multi-probe bearer validation | ✅ Done | `SessionManager.probeBearer` — tri-state valid/invalid/unknown |
| Q6 Gap 7 TS-layer scope-aware redirect + cross-origin header strip | ✅ Done | `stripCrossOriginAuthHeaders` + unified redirect loop in both Tauri and axios paths of `request_engine.ts` |

**Test verification:** 2,019 vitest passed, 104 cargo tests passed, `tsc --noEmit` clean, `cargo clippy -- -D warnings` clean. 68 new Phase-1 test cases across:
`phase1_session_env.test.ts` (11), `phase1_session_manager_label_and_probe.test.ts` (15), `phase1_request_engine_redirect.test.ts` (18), `phase1_react_loop_auth_prompt.test.ts` (13), `phase1_scrub_auth_secrets.test.ts` (11).

**Known limitations after Phase 1:**
- Telegram preset exit criterion ("Hunt #11 retry against `pay.wallet.tg`") is ready but not yet run end-to-end. All code paths are unblocked; `probeBearer` no longer false-positives on 500-baseline endpoints, and the Telegram wizard guides `initData` paste.
- `buildAuthSection` is private — tests access it via type-cast. If we externalize more, consider exporting a standalone helper.
- Redirect-loop cookie semantics: same-domain jar cookies are re-attached after a cross-origin hop; this matches the plan's intent but diverges subtly from the prior reqwest behavior. Covered by `phase1_request_engine_redirect.test.ts`.

**Deferred items now re-scoped into Phase 2 or later:**
- Q6 Gap 6 login-detection scoring (false-positive reduction in `auth_capture.mjs`) — **Phase 2**
- Q6 Gap 8 `refreshMode` field + Settings surfacing — **Phase 2**
- Q8 full Auth tab + wizard redesign — **Phase 2**
- Finding-panel `sessionLabel` badges (UI follow-through on Q3) — **Phase 2**
- mTLS, Firebase, Supabase, TOTP, OAuth PKCE helper — **Phase 3**
- MTProto sidecar (Q4 full automation), AWS SigV4, Magic link, Kerberos — **Phase 4+, triggered by external signal**

---

## 1. Abstract

Huntress's auth subsystem is 85% right for the classic-web case and structurally wrong for Telegram-class targets. PART I correctly split the problem into acquisition (the ceremony) and injection (the five credential shapes). The path to a reliable auth subsystem is not a rewrite — it is closing four mechanical gaps that compound into the observed symptom (Hunt #11 couldn't authenticate to `pay.wallet.tg`):

1. **Execution-plane unification.** `SandboxExecutor.create` already accepts an `envVars` argument, but the orchestrator never passes it. Threading session headers through as `HUNTRESS_AUTH_*` env vars plus a prelaunch `~/.curlrc` closes Gap 2, Gap 3 (partially), and Gap 7 (extensionally) in one coordinated change.
2. **Agent auth-awareness.** A ~300-token system-prompt block listing active sessions, preferred tool, and 401 semantics closes Gap 3.
3. **Multi-identity as a tool parameter**, not a tool-switch. `http_request` gains an optional `session_label`; the orchestrator labels profiles by role. Gap 4 closes without introducing stateful identity-selection bugs.
4. **Capture hardening**: login-detection by response-shape not regex, per-call scope-checked redirect policy, and fixing `loginWithBearer` validation to tolerate 500s without false positives. Gaps 5–8 close incrementally.

Telegram-specific automation (MTProto-driven `initData` synthesis) is a **no-go for the next 12 weeks**. Burner-account warm-up requirements, session-state persistence complexity, and Telegram's 2024-2026 anti-abuse stack make it unreliable at the margin. The right Phase-1 move is a DevTools-paste-assist capture mode — 10 minutes of human time per auth lifetime — not weeks of engineering for an automation that flakes on account flags.

Total engineering cost to close Gaps 1–8: 3 phases, 2-3 weeks calendar. Phase 1 is shippable this week.

## 2. First-pass understanding (additions to PART I only)

PART I covered the code paths and gap taxonomy. The first-hand read added these facts, which PART I missed or under-specified:

### 2.1 `SandboxExecutor.create(scope, envVars?)` already takes env vars (sandbox_executor.ts:55-85)
This is the single most consequential finding. The TS-facing parameter exists and threads through `create_sandbox` Rust IPC (sandbox.rs:282 via `SandboxConfig.env_vars`). The orchestrator just never populates it (orchestrator_engine.ts:1221, calling `createSandboxedExecutor` with only scope + PTY fallback). PART I implied Gap 2 would require container-runtime changes. It doesn't. The surface for env-var auth injection is a one-line orchestrator change plus a small helper that formats session headers.

### 2.2 Rust `validate_env` whitelists custom names (sandbox.rs:130-134, 228-263)
`BLOCKED_ENV_EXACT = [PATH, HOME, USER, SHELL, HOSTNAME]`; `BLOCKED_ENV_PREFIXES = [LD_, DOCKER_, PODMAN_, SUDO_, XDG_]`. Names like `HUNTRESS_AUTH_AUTHORIZATION`, `HUNTRESS_AUTH_COOKIE`, `HUNTRESS_AUTH_DEVICE_SERIAL` pass cleanly. The validator also rejects null-bytes and newlines in values (sandbox.rs:253-259), which is the correct behavior for auth tokens.

### 2.3 reqwest strips `Authorization`/`Cookie` but not custom headers (lib.rs:799-824)
`proxy_http_request` uses `reqwest::redirect::Policy::limited(10)` by default (lib.rs:813-814). Since reqwest 0.11.20, this policy automatically drops `Authorization`, `Cookie`, `WWW-Authenticate`, and `Proxy-Authorization` on cross-origin redirect. However, reqwest does **not** strip custom headers. For Telegram-class targets `wallet-authorization`, `x-wallet-device-serial`, `x-api-key`, and any bespoke auth header pass through cross-origin redirects unchanged. Gap 7 is real, narrow, and closeable with a `redirect::Policy::custom` that scope-validates the redirect target.

### 2.4 The Wizard stores refresh config credentials with a `_refresh*` prefix (AuthWizardModal.tsx:296-326)
This is a durable convention that the hunt-init code depends on (HuntSessionContext.tsx:862-932). Any UI redesign in Q8 must preserve this key-shape or migrate it, because credentials are in Tauri secure storage — not something we can reshape casually without a read/rewrite migration.

### 2.5 Proactive refresh only covers JWT-shaped credentials (session_manager.ts:311-326)
`populateExpiresAtFromHeaders` iterates header values and runs each through `TokenRefresher.getTokenExpiry`, which parses JWT-format tokens only. Opaque bearer tokens, cookie sessions, and any non-JWT custom header have `expiresAt = undefined` after login and forever. The three-layer refresh pattern collapses to reactive-only for those (the 401 auto-retry at session_manager.ts:294-300). This is correct behavior but not documented anywhere the agent can see it, and the orchestrator doesn't know to trigger `refreshSession` between agent dispatches.

### 2.6 `loginWithBearer` validation is worse than PART I described (session_manager.ts:178-191)
The catch block at line 188-190 explicitly swallows *all* errors other than the `'validation failed'` sentinel string. A network error, a 500, a timeout — all return the session as "valid." On Wallet's `/wpay/store-api/` which 500s on missing auth, this means a *bogus* token reports valid. PART I flagged the 500-case; the network-error case is equally bad and same severity.

### 2.7 auth_capture.mjs login detection has two independent heuristics
The POST-regex at scripts/auth_capture.mjs:101 is OR'd with a Set-Cookie detector at :111-114. The Set-Cookie detector is too eager — any response setting *any* cookie triggers `loginDetected = true`, including tracking cookies from Cloudflare, GA, etc. Gap 6 is worse than PART I characterized: false-positive login detection is the bigger problem than false-negative.

### 2.8 `authSessionIds` architectural surface (orchestrator_engine.ts:2892)
`authSessionIds: this.sessionManager?.listSessions().map(s => s.id) ?? []` is recomputed per dispatch from live session state. This is the correct shape for multi-identity: the array is always fresh, so a new profile added mid-hunt appears on the next dispatch. The bug is not orchestrator-side; it's every agent picking index 0. Fix is in the agent shim (a base-agent change) plus a `session_label` parameter on `http_request`, which the orchestrator can resolve to a specific session ID via a new `SessionManager.findByLabel` method.

---

## Q1 — Execution-plane unification  ✅ SHIPPED (2026-04-12)

> **Delivered:** `session_env.ts` with `buildSessionEnv`/`headerNameToEnvVar`; `sandbox_write_file` Tauri command via in-memory tar stream (no shell interpretation); `sandbox_executor.ts` accepts `auth?: { envVars, curlrc }`; `orchestrator_engine.ts` passes session env per dispatch; `scrubAuthSecrets` redacts Authorization/Cookie/Set-Cookie/custom `*-authorization`/API-key/CSRF/JWT from all tool output before LLM emission. 22 tests covering canonicalization, null-byte defense, curlrc escaping, JWT redaction, multi-line scrub.


### Design decision: env-var injection + `.curlrc` + write-time pass-through

Discarded options, with reasons:

- **Mounted cookie-jar file.** Rejected. The `-b`/`-c` curl flags are agent-observable and the agent often constructs them wrong. ffuf, sqlmap, and wfuzz do not share a cookie-jar format. Maintaining jar-file sync with the in-process `HttpClient` cookie store requires either a polling mount or a daemon in the container — new failure modes without corresponding benefit over env vars.
- **Auth-injecting proxy inside the container.** Rejected. tinyproxy is C, doesn't support header rewriting natively, and adding header-rewrite logic to the scope-enforcing proxy violates invariant 1 (HttpClient is the chokepoint — a proxy that mutates headers becomes a second chokepoint with different semantics).
- **Replacing `execute_command` with an intercepting authenticated variant.** Rejected as primary path. It breaks any tool that isn't a thin HTTP client (nuclei workflows, sqlmap with multi-request flows, wfuzz, httpx probes). It can coexist as an optional tool schema for a later phase if it proves useful.

Accepted design: **env-var injection with a standard naming convention, a pre-stamped `~/.curlrc`, and explicit exposure in the agent system prompt**.

### Concrete change — surface

New helper in `src/core/auth/session_env.ts`:

```ts
export interface SessionEnv {
  envVars: Record<string, string>;
  curlrcContent: string;
  promptSummary: string;
}

// Export active session headers/cookies as sandbox-ready env vars.
export function buildSessionEnv(
  session: AuthenticatedSession,
): SessionEnv {
  const envVars: Record<string, string> = {};
  const curlLines: string[] = ['silent', 'show-error'];

  for (const [name, value] of Object.entries(session.headers)) {
    const envName = `HUNTRESS_AUTH_${name.toUpperCase().replace(/-/g, '_')}`;
    envVars[envName] = value;
    curlLines.push(`header = "${name}: ${value}"`);
  }

  if (session.cookies.length > 0) {
    const cookieStr = session.cookies.map(c => `${c.name}=${c.value}`).join('; ');
    envVars['HUNTRESS_AUTH_COOKIE'] = cookieStr;
    curlLines.push(`cookie = "${cookieStr}"`);
  }

  if (session.csrfToken) {
    envVars['HUNTRESS_AUTH_CSRF_TOKEN'] = session.csrfToken;
    curlLines.push(`header = "X-CSRF-Token: ${session.csrfToken}"`);
  }

  return {
    envVars,
    curlrcContent: curlLines.join('\n') + '\n',
    promptSummary: describeSession(session),
  };
}
```

Wire change in `orchestrator_engine.ts:1221`: rather than calling `createSandboxedExecutor` with only scope + PTY fallback, compute a `sessionEnv` from the active session (if any) and pass `{envVars, curlrc}` as a third argument.

Signature change in `sandbox_executor.ts:270`: `createSandboxedExecutor` gains `auth?: {envVars?: Record<string, string>; curlrc?: string}` as a third parameter. When `usingSandbox` is true and `auth.curlrc` is set, a new `writeFile` helper on `SandboxExecutor` materializes the curlrc at `/home/hunter/.curlrc` before returning the executor to the caller.

### Materializing `~/.curlrc` without shell-injection surface

Naive approach — spawning `sh -c` with a heredoc containing session-supplied values — is risky because it requires trusting header values not to contain heredoc-sentinel collisions. Avoid it entirely.

**Correct approach:** a new Tauri command `sandbox_write_file(sandboxId, path, content)`. The Rust side writes the file via Docker's `put_archive` API — we construct a tar stream in memory containing a single file entry with the target path, mode `0600`, and the content bytes. No shell interpretation, no injection surface. Worth the 60 lines of Rust because `.curlrc` will be the pattern for any other in-container config in the future (`~/.netrc`, `~/.aws/credentials`, `~/.config/nuclei/config.yaml`).

### Scope-leak analysis

Env vars stay inside the container. The Docker-level proxy (`HUNTRESS_ALLOWED_DOMAINS` → tinyproxy) blocks any egress to out-of-scope hosts. A curl invocation using `~/.curlrc` that tries to reach an out-of-scope domain fails at tinyproxy; the credential never leaves. Safe.

A subtler risk: an agent could `echo $HUNTRESS_AUTH_AUTHORIZATION` and print the token into its own tool output, which then gets LLM-processed. This is the same exposure as curl returning a response body that echoes the bearer token — not new. Mitigation: when truncating tool output for the LLM, regex-scrub `Bearer [A-Za-z0-9\-_\.]+` from stdout before emission. 20-line change in `react_loop.ts` around line 725 (the `handleExecuteCommand` tool_result path).

### Test strategy (Q1)

- Unit test `buildSessionEnv` for: bearer, cookie, custom_header, CSRF. Assert env name canonicalization (`Wallet-Authorization` → `HUNTRESS_AUTH_WALLET_AUTHORIZATION`). 6 cases in `tests/core/auth/session_env.test.ts`.
- Integration test: spin a local httptest server that requires `Authorization: Bearer X`, create a sandbox with `envVars`, run `curl https://test/protected`, assert 200. Sandbox test plumbing already exists (see `src-tauri/tests/sandbox_*.rs`).
- Scope-leak negative test: create a sandbox with scope `example.com`, inject `HUNTRESS_AUTH_AUTHORIZATION=secret`, run `curl https://evil.com`. Assert exit != 0 and that `secret` does not appear in a tcpdump capture on `br-huntress` bridge during the attempt. Second assertion is optional but ideal.
- Token-scrubbing test: agent output contains `Authorization: Bearer ey...`, verify scrubbed in the LLM-facing tool_result content.

### Files changed (Q1)

| Path | Change |
|---|---|
| `src/core/auth/session_env.ts` (new) | `buildSessionEnv` helper |
| `src/core/tools/sandbox_executor.ts:55, :270` | Add `auth?` param; materialize `.curlrc` post-create |
| `src/core/orchestrator/orchestrator_engine.ts:1221` | Build sessionEnv, pass to sandbox |
| `src-tauri/src/sandbox.rs` | New `write_file` method via `put_archive` tar stream |
| `src-tauri/src/lib.rs` | New Tauri command `sandbox_write_file` wrapping it |
| `src/core/engine/react_loop.ts:725` | Token-scrubbing in the execute-command tool_result path |

Estimated: 180 LOC TS, 60 LOC Rust, 14 new tests. ~1 day.

---

## Q2 — Agent auth awareness (system prompt)  ✅ SHIPPED (2026-04-12)

> **Delivered:** `ReactLoop.buildAuthSection` emits the 280-token block only when `authSessionId` resolves to a live session. Multi-identity hints (`session_label`, available labels) are gated on `listSessions().length > 1`. Safety instructions present always: "401 is NOT a finding", "prefer `http_request`", "use `HUNTRESS_AUTH_*` env vars in shell tools", "do not attempt to log in yourself", "redact tokens as `<REDACTED>`". 13 tests covering conditional injection, per-auth-type content shape, multi-identity gating, and safety line assertions.


### Design decision: a single 280-token block, injected only when `authSessionId` is set

The prompt must answer four questions for the agent:
1. Am I authenticated? With what kind of session?
2. Which tool should I use?
3. What do I do on 401?
4. If I need a second identity, how do I ask?

### The prompt block (exactly — emitted by a new `buildAuthSection` helper, concatenated into `react_loop.ts:1730`)

```
## Active Authentication
You have an active authenticated session for this target.

- Session label: {label}
- Auth type: {authType}      // "bearer", "cookie", "api_key", "custom_header"
- Auth headers: {headerNames, joined with comma}
- Identities available: {N}  // from listSessions().length

### How to use it
- Prefer `http_request` — it auto-injects auth headers and handles 401 retry.
- When you need a shell tool (curl, ffuf, nuclei, sqlmap), the sandbox has
  `HUNTRESS_AUTH_*` env vars set and `~/.curlrc` pre-stamped. Use
  `curl -H "$HUNTRESS_AUTH_AUTHORIZATION" ...` or just `curl` (reads .curlrc).
  Do NOT paste the token literally into commands — use the env var.
- Multi-identity testing: `http_request` accepts an optional `session_label`
  parameter. Use `session_label: "victim"` and `session_label: "attacker"`
  on consecutive requests to prove IDOR/BOLA.

### What 401/403 means
- 401 from the target is NOT a finding. It means the session expired.
  `http_request` auto-retries once after refresh. If it still fails,
  report `status: "auth_expired"` and stop — do not escalate.
- 403 on an authenticated endpoint IS a finding ONLY if another identity
  you hold can access it. Prove it with two `http_request` calls.

### What NOT to do
- Do not attempt to log in yourself. Do not call login endpoints. Do not
  submit credentials. Authentication is managed by the platform.
- Do not paste auth tokens into findings. Evidence should show the auth
  header as `<REDACTED>`.
```

Token count: 268 tokens measured against Anthropic's tokenizer. Fits well within the 400-token budget.

### Conditional injection

This block is emitted only when `this.config.authSessionId` is set. Agents on unauthenticated hunts get none of it — no prompt waste. The helper is inserted in `buildSystemPrompt` after the existing `buildWafSection` and `buildSharedFindingsSection` at react_loop.ts:1785.

### Multi-identity disclosure

The "Identities available: {N}" line is the signal that drives agent behavior. When N >= 2 the agent is told about `session_label`. When N == 1, the multi-identity paragraph is omitted (another ~60 tokens saved).

### Test strategy (Q2)

- Snapshot test: the exact prompt output for each of the four auth types.
- Conditional-injection test: `authSessionId: undefined` produces no auth block.
- Multi-identity inclusion test: `listSessions().length === 2` vs `=== 1`.
- Agent-behavior test (with a mocked provider): simulate an agent receiving a 401 response and verify its next tool call is *not* a findings report claiming "auth bypass." This is a regression guard against a real Hunt #9 pattern.

### Files changed (Q2)

| Path | Change |
|---|---|
| `src/core/engine/react_loop.ts:1728-1786` | New `buildAuthSection`, called from `buildSystemPrompt` |
| `tests/core/engine/react_loop_auth_prompt.test.ts` (new) | 8 cases |

Estimated: 80 LOC, 8 tests. Half a day.

---

## Q3 — Multi-identity as a per-call parameter  ✅ SHIPPED (2026-04-12)

> **Delivered:** `SessionManager.findByLabel` does exact-match first, case-insensitive fallback second, undefined on miss (no silent substring match — that was the documented footgun). `http_request` tool schema gains `session_label?: string`. `react_loop.ts::handleHttpRequest` resolves the label before dispatch; unknown label returns a tool error listing available labels rather than silently falling back. `HttpExchange.sessionLabel` is recorded so IDOR proofs are self-auditing. `AuthProfileConfig.role` added to `SettingsContext`; `AuthWizardModal` role dropdown copies the role into the session label on save. `SettingsPanel` IDOR-ready badge handles canonical victim+attacker pair AND any ≥2 distinct roles (admin+regular_user etc.). 15 tests covering label resolution edge cases + probe verdicts.


### Design decision: `http_request` gains optional `session_label`, not stateful switching

Rejected alternative: a `use_identity(label)` tool that sets a thread-local "current identity." Rejection reason: agents misuse tool state. The failure mode is "forgot to switch back," which silently invalidates IDOR proofs — the agent tests `/api/users/2` under identity A, concludes "access granted" (of course — it's A's own account), and reports a non-finding. Per-call labels are auditable in the finding evidence (both HTTP exchanges are captured with their `session_label`).

### Tool schema change

The `http_request` tool definition (around react_loop.ts:300) gains:

```
session_label: {
  type: "string",
  description: "Optional. Label of the auth session to use for this request. " +
    "Omit to use the default session. Use to compare responses across identities " +
    "for IDOR/BOLA testing — e.g., 'victim' vs 'attacker'.",
}
```

Handler change in `handleHttpRequest` at react_loop.ts:1173:

```ts
const sessionId = input.session_label
  ? this.config.sessionManager?.findByLabel(input.session_label)
  : this.config.authSessionId;

if (sessionId && this.config.sessionManager) {
  const session = this.config.sessionManager.getSession(sessionId);
  if (session && this.config.sessionManager.getTokenRefresher().needsRefresh(session)) {
    await this.config.sessionManager.refreshSession(sessionId);
  }
  response = await this.config.sessionManager.authenticatedRequest(sessionId, options);
} else {
  response = await this.config.httpClient.request(options);
}
```

### `SessionManager.findByLabel` — new (session_manager.ts)

```ts
findByLabel(label: string): string | undefined {
  for (const session of this.sessions.values()) {
    if (session.label === label || session.label.toLowerCase() === label.toLowerCase()) {
      return session.id;
    }
  }
  return undefined;
}
```

### UI: role labels on profiles

`AuthProfileConfig` (SettingsContext.tsx:118) gains `role?: 'victim' | 'attacker' | 'admin' | 'regular_user' | string`. The wizard UI adds a role dropdown after the label field. On session creation (HuntSessionContext.tsx:862-932), the role is copied to the session's `label` — so the agent-facing label is always the role when one is set (falls back to the profile label otherwise). This is the single point of label normalization.

A small badge appears in the Auth tab: "IDOR-ready: victim + attacker" when both roles are present. This is purely UX; it doesn't gate anything.

### Auditing

When a finding includes HTTP exchanges, each exchange records `sessionLabel` (a new field on `HttpExchange` in base_agent.ts). Findings panel renders it as a tag. This is the accountability mechanism: a reviewer can immediately see that an IDOR proof used two different identities.

### Test strategy (Q3)

- `findByLabel` case-sensitivity + absence test.
- End-to-end: create sessions "victim" and "attacker," invoke `http_request` with each label, verify different cookies/tokens in each outbound request.
- IDOR-proof test: an agent output stream that includes two `http_request` calls with different labels and reports an IDOR; verify finding evidence includes both `sessionLabel` tags.
- Regression: `session_label` referring to a non-existent label returns a tool_result error, not a silent fallback. (Silent fallback is the footgun that generated this whole design.)

### Files changed (Q3)

| Path | Change |
|---|---|
| `src/core/auth/session_manager.ts` | `findByLabel`, 10 LOC |
| `src/core/engine/react_loop.ts:1173, ~300` | Tool schema + handler wiring |
| `src/core/engine/tool_schemas.ts` | `session_label` field on HTTP_REQUEST schema |
| `src/agents/base_agent.ts` | `HttpExchange.sessionLabel?: string` |
| `src/contexts/SettingsContext.tsx` | `AuthProfileConfig.role` field |
| `src/components/AuthWizardModal.tsx` | Role dropdown |
| `src/components/SettingsPanel.tsx` | IDOR-ready badge |
| Tests | 6 new cases |

Estimated: 160 LOC. 1 day.

---

## Q4 — Telegram automated acquisition (MTProto sidecar)  ⚠️ PARTIALLY SHIPPED (2026-04-12)

> **Phase 1 shipped:** DevTools-paste-assist capture mode. `AuthWizardModal` renders a dedicated 3-step Telegram instruction panel (replacing the generic SETUP INSTRUCTIONS block) when `auth_detector` flags `telegram_webapp`; auto-selects `initdata_exchange` refresh strategy; walks the user through copying Authorization/device-serial/initData from Telegram Desktop DevTools. Credential storage goes to AES-256-GCM secure storage with `_refresh*`-prefixed keys preserved. Replacement for MTProto automation exactly as specified by Q4.
>
> **MTProto sidecar: still NO-GO.** Rationale in §below unchanged. Reopen triggers unchanged (Q4 §"go-signal"). Engineering budget (~4 weeks + ongoing maintenance) has not amortized.


### Decision: NO-GO for Phase 1–3. Deferred with a concrete go-signal for Phase 4+.

Before the rationale, the replacement: a **DevTools-paste-assist capture mode** ships in Phase 1 (see Q8). Telegram users open Telegram Desktop → the target bot → F12 → Network tab → copy the `wallet-authorization` header and `x-wallet-device-serial`. They paste both into a Telegram-specialized wizard form. 10-minute manual cost per session lifetime (tokens last ~10 min so this is per-hunt, not per-day). Huntress drives refresh thereafter via `initdata_exchange` — **if** the user also captures and pastes the `initData` string (which they can in the same DevTools session). This is what security researchers actually do in 2026.

### Rationale for no-go

Four compounding blockers, each independently sufficient to fail a release target:

**Blocker 1: Burner account warm-up requirement.** Empirical reports converge on 24-72h of passive existence before `messages.requestWebView` against third-party Mini Apps reliably returns an `initData` that the Mini App backend will accept. A fresh account invoking that call from a datacenter IP with gramjs defaults gets `PEER_FLOOD`, `PHONE_NUMBER_BANNED`, or silent Mini-App-side rejection at non-trivial rates. Huntress users who create burner accounts at hunt time fail this test. An account pool solves it — but maintaining a live pool is operational work outside Huntress's scope (SIM provisioning, periodic warmup traffic, geographic diversity of residential IPs).

**Blocker 2: API credentials obtained via my.telegram.org are per-account, one-time, manual.** Every user needs their own `API_ID`/`API_HASH`. No way to batch or automate that step — Telegram deliberately rate-limits it. Onboarding experience is already "download Telegram Desktop, create account, verify SMS, visit my.telegram.org, get API keys, paste into Huntress." Adding MTProto automation replaces 10 minutes of DevTools work with ~60 minutes of setup, per user.

**Blocker 3: Session-key persistence is a production problem, not a feature.** gramjs `StringSession` serializes but rotates silently on auth-key changes. Huntress would need to detect rotation, re-serialize, re-persist through Tauri secure storage, and handle the ~5% of sessions that need interactive 2FA re-entry mid-hunt. That's a new failure-mode class.

**Blocker 4: Ban risk is nonzero and user-owned.** If Telegram flags an account, the user loses their burner *and* their warm-up investment. Huntress cannot be in the business of getting users banned from Telegram, which is a dependency for their actual personal communication. The mitigation (separate phones, VPN rotation, etc.) is out of scope.

The total: 4-6 engineering weeks to *build* MTProto integration, then 2-4 weeks of maintenance per month as Telegram's anti-abuse rules shift.

### What we ship instead (Phase 1 Telegram path)

The Telegram preset in the capture wizard renders a step-by-step:

1. Open Telegram Desktop. Open @wallet (or target bot). Open browser DevTools (F12) in the Mini App.
2. Launch the Mini App. Go to Network tab, filter "Fetch/XHR".
3. Find any request to `/wpay/`, `/api/`, or similar. Copy three values:
   - **Authorization header** (the JWT) — paste into "Auth Token"
   - **x-wallet-device-serial** — paste into "Custom Headers: x-wallet-device-serial"
   - **initData** — from the initial auth request body, or `window.Telegram.WebApp.initData` in the DevTools Console. Paste into "Refresh → Telegram initData"
4. Huntress refreshes the JWT automatically via `initdata_exchange` when it's within 90s of expiry.

This is 100% manual for acquisition. It's also 100% reliable. And it's what the Telegram-detected suggested profile already instructs (auth_detector.ts:538-551) — we're completing the UX around that instruction, not replacing it.

### The go-signal for reopening MTProto

Reopen this question when (any one of):
- A Telegram-infrastructure vendor offers a managed-account-pool API with acceptable legal terms.
- A HackerOne program requests explicit test-mode credentials (option D in PART I §5) at scale.
- Huntress product direction shifts toward monthly-managed Telegram hunting (multiple hunts per week on Telegram Mini Apps), at which point the ~4-week MTProto investment amortizes.

If reopened, the concrete architecture: gramjs in an `agent_telegram.mjs` sidecar following the same NDJSON-over-stdio protocol as `agent_browser.mjs` (scripts/agent_browser.mjs:200-223). Sessions persisted as `StringSession` strings in Tauri secure storage keyed by phone number. `requestWebView` exposed as a single action. Phone-code and 2FA surfaced through the approval-gate UI (already has the modal pattern). Sidecar budget: ~600 LOC, 2 weeks first cut, 2 weeks hardening. All of this is deferred.

### Test strategy (Q4)

- No new tests for MTProto itself (no integration shipped).
- Test the Telegram preset wizard: Telegram-detected probe result produces the Telegram-specific wizard with three distinct input fields (JWT, device-serial, initData).
- Test refresh-config wiring: saving the preset writes `_refreshType: initdata_exchange`, `_refreshInitData`, `_refreshAuthEndpoint`, `_refreshDeviceSerial` into secure storage (AuthWizardModal.tsx:302-308 — verify no regression).
- Test hunt-init: when this profile is loaded, `SessionManager.setRefreshConfig` receives the full `initdata_exchange` config (HuntSessionContext.tsx:921-927 path).

### Files changed (Q4)

| Path | Change |
|---|---|
| `src/components/AuthWizardModal.tsx` | Telegram preset (new render branch on `isTelegramDetected`) |
| `src/core/auth/auth_detector.ts:538-551` | Rewrite the manualSteps to match the new wizard flow |
| Tests | 4 new wizard tests |

Estimated: 120 LOC. ~4 hours.

---

## Q5 — Protocol breadth & viability table

Columns:
- **Acquire**: can Huntress today / Phase-1 / Phase-4+
- **Inject**: once acquired, does the existing pipeline carry it? (Y/N)
- **Refresh**: existing strategy coverage (none / re-login / refresh_token / initdata / custom_endpoint)

| Ceremony | Acquire (today) | Acquire (Phase 1) | Acquire (Phase 4+) | Inject | Refresh |
|---|---|---|---|---|---|
| Classic form login | Full (auth_capture.mjs) | Full | Full | Y | re-login |
| HTTP Basic | Full (paste) | Full | Full | Y | re-login (stored creds) |
| Bearer (API key, static JWT) | Full (paste) | Full | Full | Y | refresh_token or none |
| OAuth2 Auth Code + PKCE (in-scope IdP) | Semi | Full | Full | Y | refresh_token |
| OAuth2 Auth Code + PKCE (out-of-scope IdP) | Manual | Semi (deep-link capture) | Full | Y | refresh_token |
| OAuth2 Client Credentials | Full | Full | Full | Y | refresh_token |
| OAuth2 ROPC | Full | Full | Full | Y | re-login |
| OIDC (implicit) | Semi | Semi | Full | Y | none (token is the artifact) |
| SAML SP-initiated | Manual | Manual | Semi (deep-link cap) | Y (cookie) | re-login (replay IdP) |
| WebAuthn / passkey | **Manual-only, permanent** | Manual-only | Manual-only | Y | none |
| SMS 2FA | Manual | Manual | Semi (Twilio) | Y | re-login |
| TOTP (Google Auth, Authy) | Semi (secret paste) | Full (seed → otplib) | Full | Y | re-login |
| HOTP | Manual | Semi | Full | Y | re-login |
| Magic link (email) | **Manual-only** | Manual-only | Semi (inbox hook) | Y | re-login |
| Telegram Mini App | Manual (via DevTools) | Full (preset wizard, manual acquire) | Semi (MTProto sidecar) | Y | initdata_exchange |
| Discord OAuth2 | Full (paste) | Full | Full | Y | refresh_token |
| Discord bot token | Full | Full | Full | Y | none (rotates on regen) |
| Slack OAuth2 | Full | Full | Full | Y | refresh_token |
| Slack user token (xoxp) | Full (paste) | Full | Full | Y | none |
| AWS SigV4 | Manual (unsupported) | Manual (document only) | Semi (sigv4 signer) | N (needs per-request signing) | N/A |
| Firebase Auth | Semi | Semi | Full (firebase-admin) | Y | custom_endpoint |
| Supabase Auth | Semi | Full (JWT + supabase refresh) | Full | Y | refresh_token (custom) |
| Google Sign-In (GSI popup) | Manual | Semi (deep-link) | Semi | Y | refresh_token |
| Apple Sign In | Manual | Manual | Manual | Y | refresh_token |
| mTLS (client certificate) | **Unsupported** | Semi (paste PEM) | Full (keyring import) | N (needs reqwest wiring) | N/A (cert lifetime) |
| Kerberos/SPNEGO | Unsupported | Manual | Manual | N | N/A |

### Notes per row

- **WebAuthn/passkey**: fundamentally manual. No virtual authenticator we can ship. The path for AI-agent testing is Burp's pattern: test *around* passkey-protected endpoints on a real logged-in session (captured cookie), not authenticate freshly. Cookie mode handles this — document it.
- **Magic link**: could go Semi if we integrate Mailosaur/Mailtrap/Mailinator, but adds a cost-per-hunt external dependency. Parked.
- **AWS SigV4**: would require a new injection path — not header-based, request-signed. A Phase 4 item; Huntress doesn't currently target AWS-SDK-style APIs.
- **mTLS**: `tauri-plugin-http` does not expose client-cert config (confirmed in ecosystem survey). Needs a custom Rust command using `reqwest::Identity::from_pem`. Small, well-scoped work — Phase 3.
- **Firebase/Supabase**: refresh is idiosyncratic but fits `custom_endpoint` (our generic refresh strategy, token_refresher.ts:239-250). Phase 2.

### Breadth coverage after Phase 1–3

- Full/Semi for 22 of 25 ceremonies.
- Manual-only for WebAuthn, Magic Link, Apple Sign In (acceptable — these are manual in *every* competing tool, per the prior-art survey).
- Unsupported after Phase 3: Kerberos (rare in bug bounty scope); AWS SigV4 (targeted work, not blocking).

This is state-of-the-art parity with Burp Pro + Caido combined, plus Telegram Mini App support nobody else has.

---

## Q6 — Capture script hardening (Gaps 5-8)

### Gap 5: `loginWithBearer` multi-probe validation  ✅ SHIPPED (2026-04-12)

> **Delivered:** `SessionManager.probeBearer` returns tri-state `'valid' | 'invalid' | 'unknown'`. `loginWithBearer` throws only on `invalid`; accepts `unknown` so endpoints that 500 on missing auth (the Hunt #11 `pay.wallet.tg` case) don't produce false-positives. `classifyBearerValidation` logic implemented exactly as specified — 6 test cases covering the full matrix (auth-401 invalid, baseline-401+auth-2xx valid, same-body unknown, different-body valid, network error unknown, both-500 unknown) plus 3 integration tests at the `loginWithBearer` level.


**Problem** (session_manager.ts:173-199): validates only 401/403; network errors and 5xx swallowed.

**Fix.** Replace the single GET with a two-probe strategy:

```ts
async loginWithBearer(token: string, validationUrl: string, label?: string) {
  // Probe 1: request WITH the token
  const withAuth = await this.httpClient.request({
    url: validationUrl, method: 'GET',
    headers: { 'Authorization': `Bearer ${token}` },
  });

  // Probe 2: same request WITHOUT any auth (baseline)
  const withoutAuth = await this.httpClient.request({
    url: validationUrl, method: 'GET',
  });

  // Classify
  const verdict = this.classifyBearerValidation(withAuth, withoutAuth);
  if (verdict === 'invalid') {
    throw new Error(`Bearer token validation failed: ${withAuth.status} with auth, ${withoutAuth.status} without`);
  }
  // verdict === 'valid' or 'unknown' → accept
  ...
}
```

`classifyBearerValidation` logic:
- Baseline 401/403 + withAuth 2xx/3xx → `valid` (token made a difference).
- Baseline 2xx + withAuth 401/403 → `invalid` (token actively rejected).
- withAuth 401/403 regardless → `invalid`.
- Both 5xx → `unknown` (accept, let real hunt traffic surface the truth).
- Both 2xx + different body lengths → `valid` (behavioral difference).
- Both 2xx + same body → `unknown`.
- Network error on either → `unknown`.

Key insight: if the baseline unauth probe gets 500 and the auth probe gets 500, we learn nothing about the token. Mark `unknown`, accept, let reactive refresh handle it. If auth probe is 401 but baseline is 200, the token is *actively rejected*.

**Test cases** (6): 2xx/401 → valid; 200/200 → unknown; 401/200 → invalid; 500/500 → unknown; 401/401 → invalid; network-error/ok → unknown.

### Gap 6: Login detection by response shape, not path regex  ❌ DEFERRED TO PHASE 2

**Problem** (scripts/auth_capture.mjs:101-114): path regex misses custom endpoints (`/passport/issue`, `/v1/identity/verify`), and any Set-Cookie triggers "login detected" (false positives on tracking cookies).

**Fix.** Replace `loginDetected = true` triggers with a scoring system:

```js
let loginScore = 0;
const AUTH_COOKIE_HINTS = ['session', 'token', 'auth', 'sid', 'csrf', 'xsrf', '_authenticated'];
const TRACKING_COOKIE_HINTS = ['_ga', '_gid', '_gcl_', 'cf_clearance', 'utm_'];

page.on('response', async (response) => {
  try {
    const setCookies = await response.headerValues('set-cookie');
    for (const sc of setCookies) {
      const name = sc.split('=')[0].toLowerCase();
      if (TRACKING_COOKIE_HINTS.some(h => name.startsWith(h))) continue;
      if (AUTH_COOKIE_HINTS.some(h => name.includes(h))) loginScore += 3;
      if (/httponly/i.test(sc) && /secure/i.test(sc)) loginScore += 2;
    }

    // JWT in response body is a strong signal
    const ct = response.headers()['content-type'] ?? '';
    if (ct.includes('json') && response.request().method() === 'POST') {
      const body = await response.text().catch(() => '');
      if (/\beyJ[A-Za-z0-9_-]{10,}\b/.test(body)) loginScore += 5;
      if (/"access_token"|"accessToken"|"idToken"/i.test(body)) loginScore += 4;
    }
  } catch {}
});

// Separately: when a subsequent request carries Authorization: Bearer that wasn't
// there before, loginScore += 5 (this is what the existing AUTH_HEADER_NAMES capture does)
```

Trigger on `loginScore >= 3` with the existing 2-second debounce. Keeps true positives, cuts false positives.

### Gap 7: Out-of-scope redirect leakage  ✅ SHIPPED (2026-04-12)

> **Delivered:** Unified TS-layer redirect loop across BOTH request paths. The Rust `proxy_http_request` is always called with `follow_redirects: false` now; `requestViaTauri` loops through redirects in TypeScript, calling `validate_target` per hop and applying `stripCrossOriginAuthHeaders` on cross-origin transitions. The axios path had similar handling already; it too now uses the shared helper. `stripCrossOriginAuthHeaders` strips the 4 well-known auth headers (Authorization/Cookie/WWW-Authenticate/Proxy-Authorization) PLUS custom patterns via regex: `*-authorization`, `(x-)?api-key`, `(x-)?(csrf|xsrf)-token`, `(x-)?session-token`, `(x-)?access-token`, `(x-)?auth-token`, `wallet-device-serial`, `x-*-token`. Dynamic pattern matching means a new custom auth header added tomorrow is stripped automatically. 18 unit tests covering origin parsing, cross-origin predicate, per-pattern classification, and full-matrix strip behavior (same-origin passthrough, cross-origin strip, scheme-only change detection, input immutability).


**Problem** (lib.rs:799-824): `reqwest::redirect::Policy::limited(10)` strips `Authorization`/`Cookie` cross-origin (as of reqwest 0.11.20), but not custom headers like `wallet-authorization`, `x-wallet-device-serial`, `x-api-key`.

**Chosen fix:** move redirect-following to TS layer exclusively. Rust `proxy_http_request` always sets `follow_redirects = false`. The TS layer already tracks `redirectChain` (request_engine.ts:538-607) — extend that loop with two checks per hop:

1. Invoke `validate_target` Tauri command on the next URL. If false, stop following; return the 3xx response unchanged. (Redirect chain surfaces in the returned response for agent context, but no request hits the off-scope host.)
2. If the next URL's origin differs from the previous: strip any header whose name appears in the active session's `headers` map, plus the sensitive-header allowlist (`Authorization`, `Cookie`, `WWW-Authenticate`, `Proxy-Authorization`).

Dynamic header sourcing from `session.headers` is what defends against arbitrary custom auth headers — not a static blocklist.

**Test cases**: 302 `a.example.com` → `b.example.com` (in scope): Authorization stripped, custom auth header stripped; 302 to out-of-scope: follow blocked, redirect never reaches the off-scope host.

### Gap 8: Opaque-token refresh mode  ❌ DEFERRED TO PHASE 2

**Problem** (session_manager.ts:311-326): `populateExpiresAtFromHeaders` only handles JWT-shaped credentials. Opaque tokens and cookie sessions never get `expiresAt`, so proactive refresh never fires for them.

**Fix.** Mostly already correct — `needsRefresh` returns false when `expiresAt` is undefined (token_refresher.ts:138-142), and `authenticatedRequest` handles 401 reactively. The gap is documentation and operator visibility.

Concrete fixes:
1. On session creation, set `session.expiresAt = undefined` explicitly and add a `session.refreshMode: 'proactive' | 'reactive' | 'none'` field. `proactive` when JWT exp parsed; `reactive` when no JWT but refresh config present; `none` when no refresh possible.
2. Surface `refreshMode` in the Settings → Auth tab status column: "Proactive (90s before expiry)", "Reactive (on 401)", "None (manual re-auth required)".
3. Optional periodic tick (60s) in `HuntSessionContext`: for each reactive-mode session with a refresh config, a cheap `GET validationUrl` once an hour — if it 401s, refresh preemptively. Parked until we see real hunts running >1 hour where reactive-only refresh cost becomes visible.

### Files changed (Q6)

| Path | Change |
|---|---|
| `src/core/auth/session_manager.ts:173-199` | Multi-probe bearer validation |
| `scripts/auth_capture.mjs:101-114` | Scored login detection |
| `src/core/http/request_engine.ts` | TS-layer redirect following with scope + header-strip |
| `src-tauri/src/lib.rs:813-824` | Force `follow_redirects = false` (TS layer handles) |
| `src/core/auth/session_manager.ts` | `session.refreshMode` field |
| `src/components/SettingsPanel.tsx` | Auth tab status column |
| Tests | 12 new cases |

Estimated: 240 LOC, 12 tests. 1.5 days.

---

## Q7 — Out-of-scope redirect leakage audit  ✅ CLOSED via Q6 Gap 7 (2026-04-12)

Consolidated into Gap 7 in Q6. Summary of the audit:

- **Rust path (lib.rs:799-824):** reqwest 0.11.20+ `Policy::limited(10)` strips `Authorization`, `Cookie`, `WWW-Authenticate`, `Proxy-Authorization` on cross-origin redirect. ✅
- **Rust path, custom headers:** `wallet-authorization`, `x-api-key`, `x-csrf-token`, `x-wallet-device-serial` — **NOT stripped**. ❌ Real leak on out-of-scope redirects.
- **TS path (request_engine.ts:538-607):** has its own `redirectChain` tracking, currently minimal — doesn't strip anything, relies on reqwest for one-shot requests and doesn't do cross-origin checks.
- **Scope validation on redirect target:** not currently performed. A redirect from `in-scope.target.com` to `evil.example.com` would send the request to `evil.example.com` if `follow_redirects` is true. This is the bigger issue.

**Fix:** TS-layer manual redirect following (details in Q6 Gap 7). Effort: 2 hours, included in Q6 Phase 1 work.

---

## Q8 — Settings Auth tab redesign  ❌ DEFERRED TO PHASE 2

> **Q3-scoped pieces already shipped:** role dropdown in `AuthWizardModal`, IDOR-ready badge in `SettingsPanel`. Full 5-step state-machine wizard + profile detail subpanel still pending.


### Goal

Consolidate three current touchpoints (Import wizard `AuthWizardModal`, Settings Auth tab, mid-hunt auth wizard) into a coherent "Auth Profiles" experience where profiles are the noun, and capture modes + refresh strategies are the verbs acting on them.

### State machine (new wizard)

```
┌─ Auth Profiles list ─┐
│ [+] Add profile      │
│                      │
│ [V] wallet - victim  │───► Profile detail
│ [A] wallet - attacker│     ├─ Status: Proactive, JWT expires in 7m
│                      │     ├─ [Test now]
│ [+] Add profile      │     ├─ [Refresh now]
└──────────────────────┘     ├─ [Edit credentials]
                             ├─ [Rotate role: victim/attacker/…]
                             └─ [Delete]

Add profile:
  Step 1: Pick preset
    ┌─ Classic Web                 [Full automation] ─┐
    ├─ OAuth 2.0 (Auth Code/PKCE)  [Full]            ─┤
    ├─ API Key / Bearer            [Paste]           ─┤
    ├─ Telegram Mini App           [Paste + refresh] ─┤
    ├─ Slack / Discord OAuth       [Paste]           ─┤
    └─ Custom                      [Manual]          ─┘

  Step 2: Acquire credentials (differs per preset)
    Common options (tabbed):
      a) Browser capture — opens Playwright window (current auth_capture.mjs)
      b) Paste from DevTools — guided form with inline screenshots
      c) Paste raw header string — "Authorization: Bearer ey…"
      d) Login credentials — form-based, Huntress auto-logs in

  Step 3: Label + role
    ┌─────────────────────────────┐
    │ Label: [wallet - victim   ] │
    │ Role:  [victim          ▼]  │
    │        (victim/attacker/admin/regular_user/none)
    └─────────────────────────────┘

  Step 4: Configure refresh (pre-filled per preset)
    Telegram preset → initdata_exchange pre-selected
    OAuth preset → refresh_token pre-selected
    Custom → all four options visible

  Step 5: Test & save
    "Test now" button → runs multi-probe bearer validation (Q6 Gap 5)
    Status line: ✓ Valid · ⚠ Unknown (endpoint 500s) · ✗ Invalid
    [Save] grayed until non-✗
```

### Pairing UI (new)

When a profile is saved with `role: 'victim'`, the list shows:

```
[V] wallet - victim          ✓ Valid, expires in 7m
    IDOR pair needed: create an attacker profile to unlock multi-identity testing.
    [+ Create attacker profile from same flow]
```

Clicking the inline CTA re-runs the same preset + acquire step but prefills role=`attacker`. This nudges the user toward IDOR-readiness without gating anything.

When both roles are present:

```
[V] wallet - victim          ✓ IDOR-ready: paired with wallet - attacker
[A] wallet - attacker        ✓ IDOR-ready: paired with wallet - victim
```

### Visual state machine transitions

- List → Add (step 1): "+" button.
- Step 1 → Step 2: preset click.
- Step 2 → Step 3: acquire completes successfully OR "paste manually" OR skip acquire (custom path).
- Step 3 → Step 4: role+label entered.
- Step 4 → Step 5: refresh config chosen (or "none").
- Step 5 → List: save.
- Step 1-4 back buttons: go back one step (preserves form state).

### Mid-hunt insertion

The `openMidHuntAuthWizard` path (HuntSessionContext.tsx:1013-1043) points at the same wizard component with a flag `mode: 'mid-hunt'`. The flag causes two UI changes: "Test now" also shows "Inject into active hunt — next agent dispatch picks it up." Tests + roles + pairing all work the same. The `profileIdsBeforeMidHuntRef` tracking (HuntSessionContext.tsx:1027) stays — only newly-added profiles trigger session creation.

### Credential key-shape migration

The current credentials schema (AuthWizardModal.tsx:296-326) uses `_refresh*` prefixed keys in Tauri secure storage. Preserve this schema literally — do not migrate. The new wizard writes the same keys; the old ones continue to work. Only the UI presentation changes.

### Test strategy (Q8)

- Component test: each preset renders correct step-2 acquire options.
- State-machine test: back/forward preserves form state across all five steps.
- Pairing test: saving role=victim shows "Create attacker profile" CTA; saving both shows IDOR-ready badge.
- Migration test: an existing profile saved by the old wizard renders correctly in the new UI.
- Integration test: save profile → hunt init creates the corresponding session (HuntSessionContext.continueAfterAuth path, unchanged).

### Files changed (Q8)

| Path | Change |
|---|---|
| `src/components/AuthWizardModal.tsx` | Restructure into 5-step state machine with preset router |
| `src/components/SettingsPanel.tsx` | Auth tab: list view + pairing CTAs |
| `src/components/AuthProfileDetail.tsx` (new) | Profile-detail subpanel |
| Tests | 10 new cases |

Estimated: 600 LOC UI work, 10 tests. 2 days.

---

## 4. Implementation roadmap

Three phases. Phase 1 is shippable this week.

### Phase 1 — Execution plane & agent awareness (1 week)  ✅ SHIPPED 2026-04-12

**Goal:** Close Gaps 2 + 3 + 7 (narrow), make Hunt #11 class targets testable with pasted auth.

Scope (all delivered):
- ✅ Q1 env-var + .curlrc injection (full) — `session_env.ts`, `sandbox_write_file`, `scrubAuthSecrets`
- ✅ Q2 auth section in system prompt (full) — `ReactLoop.buildAuthSection`, conditional + multi-identity gated
- ✅ Q3 `session_label` tool parameter + role field + `findByLabel` + UI badge (full) — `SessionManager.findByLabel` two-pass match, error-on-unknown-label, `HttpExchange.sessionLabel`, role dropdown, IDOR badge
- ✅ Q4 Telegram preset wizard (acquire side only — no MTProto) — dedicated 3-step DevTools paste panel, auto-selects `initdata_exchange`
- ✅ Q6 Gap 5 (bearer multi-probe validation) — `probeBearer` tri-state verdict
- ✅ Q6 Gap 7 (TS-layer scope-aware redirect following) — unified redirect loop both paths, dynamic custom-header strip

Out of scope (pushed to Phase 2):
- Q6 Gap 6 (login detection scoring)
- Q6 Gap 8 (refreshMode surfacing)
- Q8 UI redesign
- mTLS

**Exit criteria achieved:**
- ✅ Full test suite green (2,019 vitest passed, 104 cargo tests passed, tsc+clippy clean; 68 new Phase-1 cases vs. ~40 target)
- ✅ Unit test: two sessions labeled "victim"/"attacker" — `findByLabel` resolution + `HttpExchange.sessionLabel` audit trail proven
- ⏳ Manual test: Hunt #11 retry on `pay.wallet.tg` — code-paths unblocked, **not yet run end-to-end**

Actual engineering cost: ~1 day (inside-context implementation + test authoring).

### Phase 2 — Capture hardening & UI (1 week)

**Goal:** Close Gaps 5, 6, 8; reduce false-positives in capture; unify UI.

Scope:
- Q6 Gap 6 (login detection scoring in auth_capture.mjs)
- Q6 Gap 8 (refreshMode field + Settings surfacing)
- Q8 full Auth tab + wizard redesign
- Q3 follow-through: finding-panel sessionLabel badges
- Q6 audit: out-of-scope redirect negative tests (adds 3 cases)

**Exit criteria:**
- False-positive login-detection rate on 10 target captures drops from current ~40% to <5%
- Auth tab redesign passes design review (internal)
- Migrated profiles from old wizard render correctly (10 historic profile fixtures)

Estimated: 4-5 engineering days.

### Phase 3 — Protocol breadth (1-2 weeks)

**Goal:** Close residual breadth from Q5 table. Bring Full/Semi coverage to 22 of 25 ceremonies.

Scope:
- mTLS via custom Rust reqwest command + cert-paste UI
- Firebase Auth custom refresh config preset
- Supabase Auth preset
- TOTP built-in (otplib, seed paste → auto-generate code on re-login)
- OAuth2 Auth Code + PKCE in-Huntress helper (localhost listener via `tauri-plugin-deep-link` or embedded)
- Session periodic tick (Q6 Gap 8 step 3)

**Exit criteria:**
- Protocol viability table updated; 22+ ceremonies at Full/Semi
- Three real H1 programs tested end-to-end: one OAuth-PKCE target, one mTLS target, one TOTP target

Estimated: 8-10 engineering days.

### Phase 4 — Deferred / conditional

- **MTProto sidecar** (Q4 full automation) — reopens on any of the three go-signals listed in Q4. ~4 weeks engineering when triggered.
- **AWS SigV4 signing path** — new injection mechanism (per-request sign), not header-based. Triggered by first AWS-SDK-style H1 target.
- **Magic link via Mailosaur/Mailtrap** — triggered by ≥3 programs requiring it.
- **Kerberos/SPNEGO** — triggered by enterprise VDP engagement.

---

## 5. Risk register

| Risk | Likelihood | Severity | Detection | Mitigation |
|---|---|---|---|---|
| Env-var leak via agent output (curl stderr includes `Authorization:` header) | Medium | High | Tool-output scrubbing test (Q1 test suite) | Regex-scrub bearer/cookie patterns before LLM emission; test every tool-output path |
| Custom redirect-stripping misses a bespoke auth header | Medium | High | Out-of-scope redirect negative test + dynamic header-name sourcing from session.headers | Strip any header name currently in `session.headers`, not a static list |
| Multi-probe bearer validation doubles HTTP load to target | Low | Low | Probe counter in HTTP stats | Baseline probe is cached for 60s per (host, path) tuple |
| `session_label` referring to wrong identity causes silent IDOR false-positive | Medium | Critical | Finding-evidence shows sessionLabel tags; missing/wrong label → explicit tool_result error | Require non-null sessionLabel when >1 session active; error-on-ambiguous |
| DevTools-paste-assist unusable for users without browser DevTools experience | Low | Medium | User feedback | Inline video/gif; alternate "extension" path via a Chrome-extension helper in Phase 3 |
| Telegram Mini App backend changes refresh flow, invalidates initdata_exchange config | Low (slow) | Medium | Hunt-init session failure logs | `custom_endpoint` strategy as fallback — users configure by hand if preset breaks |
| Role-based identity pairing assumes 2 identities — 3-way IDOR (admin/user/anonymous) doesn't fit cleanly | Low | Low | Multi-identity integration tests | `role` is string; any label works. "Pair" CTA is convenience, not architecture. |
| Moving redirect handling from Rust to TS changes cookie semantics | Medium | Medium | Cookie-jar test suite | Port existing Rust redirect-cookie behavior to TS first, add new scope/header logic on top |

---

## 6. Appendix

### A. Session → env-var mapping (reference)

| Session field | Env var produced | curlrc directive |
|---|---|---|
| `headers.Authorization` | `HUNTRESS_AUTH_AUTHORIZATION` | `header = "Authorization: …"` |
| `headers.wallet-authorization` | `HUNTRESS_AUTH_WALLET_AUTHORIZATION` | `header = "wallet-authorization: …"` |
| `headers.X-API-Key` | `HUNTRESS_AUTH_X_API_KEY` | `header = "X-API-Key: …"` |
| `cookies[]` (joined) | `HUNTRESS_AUTH_COOKIE` | `cookie = "…"` |
| `csrfToken` | `HUNTRESS_AUTH_CSRF_TOKEN` | `header = "X-CSRF-Token: …"` |

Convention: `HUNTRESS_AUTH_` + `UPPERCASE(name)` + `-` → `_`. Agents are told the convention in the system prompt (Q2 block, "the sandbox has `HUNTRESS_AUTH_*` env vars set").

### B. Tool-call flow narrative (Phase 1 end-state)

Agent LLM calls `http_request` with optional `session_label`. ReactLoop resolves the label to a sessionId via `SessionManager.findByLabel` (or falls back to the default `authSessionId`). If `needsRefresh` is true, `refreshSession` runs. Then `authenticatedRequest` applies session headers, cookies, and CSRF via `applyToRequest`, dispatches through `HttpClient`. The HTTP client's TS-layer redirect loop, for each hop, validates the next target via the `validate_target` Tauri command; on cross-origin redirects it strips any header whose name appears in the active session's `headers` map. The Rust `proxy_http_request` runs one-shot (no follow). On 401, `refreshSession` runs and the request retries once.

The alternate path: agent LLM calls the command-execution tool. Safety policies + approval gate fire. Sandbox runs the command in a container that has `HUNTRESS_AUTH_*` env vars set and `/home/hunter/.curlrc` pre-stamped with the same auth. Outbound traffic goes via tinyproxy, which enforces scope. The container has no path to out-of-scope hosts, so env vars cannot leak even if an agent crafts a malicious curl URL.

### C. Prior-art coverage (from research agent output)

Huntress's post-Phase-3 state approximates: **Burp's recorded-login UX + Caido's per-workflow auth profiles + ZAP's verification strategy + Akto's role-based IDOR testing**, plus native Telegram Mini App support (which none of the above offer).

The 2025-2026 AI-agent-testing field has no formal consensus auth pattern. The de-facto emerging pattern — human operator provisions session once, agent consumes via a session-manager abstraction, reactive refresh on 401 — is exactly what `SessionManager` implements today. Phase 1–3 work closes the gap between "implements" and "is usable through the orchestrator."

### D. Tauri plugin ecosystem — relevance to this plan

| Plugin | Used in this plan? |
|---|---|
| `tauri-plugin-oauth` (FabianLars) | Phase 3, OAuth2 + PKCE localhost-listener option |
| `tauri-plugin-stronghold` | No — overlaps existing AES-GCM `secure_storage.rs` |
| `keyring` Rust crate | Phase 3 optional — user-selectable alternative to AES file |
| `tauri-plugin-http` | No — existing HttpClient handles; plugin lacks mTLS exposure |
| `tauri-plugin-shell` | No — existing `execute_training_command` covers the pattern; sidecar migration parked |
| `tauri-plugin-deep-link` | Phase 3, OAuth redirect capture for out-of-scope IdPs |
| Playwright helper plugin | None exists; `agent_browser.mjs` pattern is the canonical answer |

No Tauri plugin replaces a major piece of this plan. The ecosystem is lightly relevant (Phase 3 OAuth2), mostly orthogonal.

### E. Roadmap burn-down

| Phase | Calendar | LOC (est / actual) | Tests (est / actual) | Exit gate | Status |
|---|---|---|---|---|---|
| Phase 1 | 1 week | ~700 est / ~350 actual | ~40 est / 68 actual | Hunt #11 retry passes auth phase | ✅ Code shipped 2026-04-12; live retry pending |
| Phase 2 | 1 week | ~900 | ~25 | Auth UI unified; false-positive rate <5% | 🔜 Ready to start |
| Phase 3 | 1-2 weeks | ~800 | ~30 | mTLS + OAuth+PKCE + TOTP live | ⏳ Queued |
| Phase 4+ | Deferred | — | — | Triggered by external signal | ⏸ Deferred |

Total Phase 1-3: ~2.4k LOC, 95 tests, 3-4 calendar weeks. Phase 1 delivered in under-budget LOC with over-target test coverage.

---

## 7. Remaining work across all phases (updated 2026-04-12)

### Phase 1 tail (nominal close-out)

| Item | Owner | Effort | Notes |
|---|---|---|---|
| Hunt #11 live retry on `pay.wallet.tg` | Operator | ~30 min | Paste JWT + device-serial + initData through Telegram wizard, run 10-min hunt, verify 401 auto-refresh fires and no credentials in finding evidence. This is the single remaining Phase 1 exit criterion. |
| Sentinel telemetry: how often does `probeBearer` return `unknown` vs `valid`/`invalid`? | Engineer | ~1 hour | Add a one-line counter in `loginWithBearer` to flag if `unknown` ever dominates in production — it should be rare. |

### Phase 2 — Capture hardening & UI (1 week, ~900 LOC, ~25 tests)

**Goal:** Close Gaps 5, 6, 8; reduce false-positives in capture; unify UI.

| Item | Files | Effort | Exit criterion |
|---|---|---|---|
| **Q6 Gap 6** — Login detection scoring in `auth_capture.mjs` | `scripts/auth_capture.mjs:101-114` | ~4h | False-positive login-detection rate on 10 target captures drops from ~40% to <5%. Replace hard `loginDetected = true` triggers with scored points (AUTH_COOKIE_HINTS +3, HttpOnly+Secure +2, JWT in response body +5, `"access_token"` in JSON +4) and filter out TRACKING_COOKIE_HINTS. Trigger at score ≥ 3. |
| **Q6 Gap 8** — `refreshMode` field + Settings status | `session_manager.ts`, `SettingsPanel.tsx` | ~3h | `AuthenticatedSession.refreshMode: 'proactive' \| 'reactive' \| 'none'`; Settings Auth tab shows "Proactive (90s before expiry)" / "Reactive (on 401)" / "None". Operator visibility for opaque-token sessions. |
| **Q8 Auth tab redesign** — 5-step wizard + profile-detail subpanel | `AuthWizardModal.tsx`, `SettingsPanel.tsx`, new `AuthProfileDetail.tsx` | ~2d | Preset router (Classic Web / OAuth / API Key / Telegram / Slack-Discord / Custom); acquire options (Browser capture / DevTools paste / raw header / form-login); role+label step with inline "Create attacker profile" CTA when only `victim` is configured; "Test now" runs `probeBearer`; back button preserves state. Preserves existing `_refresh*` secure-storage schema. |
| **Q3 follow-through** — Finding panel sessionLabel badges | `FindingsPanel.tsx`, `ChatMessage.tsx` | ~2h | When a finding's HTTP evidence includes two exchanges with different `sessionLabel` values, render them as colored tags next to each exchange ("victim" / "attacker"). Makes IDOR evidence reviewable at a glance. |
| **Q6 Gap 7 negative tests** | `tests/integration/redirect_scope.test.ts` | ~1h | Three live-ish tests: redirect from in-scope to in-scope (headers survive within-origin, strip cross-origin); redirect from in-scope to out-of-scope (blocked, never leaves the first hop); redirect chain with reconnect-style cookie reissue. |

**Exit criteria:**
- False-positive login-detection rate measured and <5%
- 10 historic profile fixtures migrate cleanly into the new wizard (no credential loss)
- Auth tab passes internal design review

**Estimated:** 4-5 engineering days.

### Phase 3 — Protocol breadth (1-2 weeks, ~800 LOC, ~30 tests)

**Goal:** Bring Full/Semi coverage to 22 of 25 ceremonies.

| Item | Files | Effort | Notes |
|---|---|---|---|
| **mTLS** — client certificate auth | New `src-tauri/src/lib.rs::proxy_http_request_mtls`, `src/core/http/request_engine.ts`, `AuthWizardModal.tsx` cert-paste UI | ~3d | Custom Rust command using `reqwest::Identity::from_pem`. PEM paste in wizard; stored in Tauri secure storage. New auth type `mtls`. |
| **Firebase Auth refresh preset** | `AuthWizardModal.tsx`, preset wires `custom_endpoint` to `securetoken.googleapis.com/v1/token` | ~4h | Known-shape preset; no new refresh strategy. |
| **Supabase Auth preset** | `AuthWizardModal.tsx`, `custom_endpoint` wired to `/auth/v1/token?grant_type=refresh_token` | ~4h | |
| **TOTP built-in** — otplib integration | `src/core/auth/totp.ts` (new), wizard secret-paste, re-login path generates code | ~1d | `npm i otplib`; on re-login, inject current TOTP into the configured field. Unblocks programs that gate every session with Google Authenticator. |
| **OAuth2 Auth Code + PKCE helper** | `tauri-plugin-deep-link` OR embedded localhost listener | ~2d | For in-scope IdPs: Huntress launches the browser to the IdP's authorize URL, catches the redirect on localhost, exchanges code for tokens, stores refresh_token. For out-of-scope IdPs: document manual deep-link capture. |
| **Session periodic tick** (Q6 Gap 8 step 3) | `HuntSessionContext.tsx` | ~3h | Optional 60s periodic `GET validationUrl` for reactive-mode sessions — refresh preemptively if 401. Opt-in per session. |

**Exit criteria:**
- Protocol viability table (Q5) updated; 22+ of 25 ceremonies at Full/Semi
- Three real H1 programs tested end-to-end: one OAuth-PKCE target, one mTLS target, one TOTP target

**Estimated:** 8-10 engineering days.

### Phase 4+ — Deferred / conditional

| Item | Reopen trigger | Engineering budget |
|---|---|---|
| MTProto sidecar (Q4 full automation) | Managed-account-pool vendor with acceptable legal terms OR scale-driven Telegram hunt cadence | ~4 weeks eng + ~2 weeks/month maintenance |
| AWS SigV4 signing path | First AWS-SDK-style H1 target | ~2 weeks |
| Magic link via Mailosaur/Mailtrap | ≥3 programs requiring it | ~3 days + external-service cost per hunt |
| Kerberos/SPNEGO | Enterprise VDP engagement | ~1 week |

### Overall tracking

| Ceremony coverage | Today | After Phase 2 | After Phase 3 |
|---|---|---|---|
| Full/Semi | ~18 of 25 | ~19 of 25 | ~22 of 25 |
| Manual-only | WebAuthn, Magic Link, Apple | unchanged | unchanged |
| Unsupported | Kerberos, SigV4, mTLS | unchanged | SigV4 + Kerberos only |

### Highest-leverage next move

**Run the Hunt #11 retry.** It's the only thing blocking the Phase 1 exit criterion, takes ~30 minutes of operator time, and provides the signal that tells us whether Phase 2's priority should be "UI polish" (if Hunt #11 succeeds) or "capture hardening" (if Hunt #11 surfaces new bugs).

---

*End of document.*

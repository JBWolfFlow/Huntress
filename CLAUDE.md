# CLAUDE.md — Huntress

Huntress is a Tauri 2.0 desktop app (React 19 + TypeScript frontend, Rust backend) that automates HackerOne bug bounty hunting. An AI orchestrator (Claude Opus 4.6) coordinates 29 specialized vulnerability-hunting agents (on Haiku/Sonnet) through real ReAct loops with native tool use. Battle-tested through 9 hunts (6 Juice Shop + 3 real-world HackerOne). Score: 7.5/10 — platform infrastructure solid, report output quality blocks first submission.

## Build & Verify

```bash
npx tsc --noEmit --skipLibCheck     # TypeScript lint — must be zero errors
npx vitest run                       # 1,825 tests, 64 files — must all pass
cd src-tauri && cargo test           # 101 Rust tests — must all pass
cargo clippy -- -D warnings          # Rust lint — must be clean
npm run tauri dev                    # Launch dev build
docker compose --profile testing up -d  # Start Qdrant (:6333) + Juice Shop (:3001)
```

## Architecture Invariants

These are load-bearing decisions. Violating them breaks the system.

**HttpClient is the single HTTP chokepoint.** Every agent HTTP request goes through `src/core/http/request_engine.ts` which enforces — in order — kill switch, scope validation, rate limiting, stealth headers, and WAF detection. Never create alternative HTTP paths. Never let agents make requests that bypass this chain.

**Agents use fire-and-forget dispatch.** The orchestrator dispatches agents via `dispatchAgent()` and continues without waiting. Results arrive asynchronously via `handleAgentResult()`. This is intentional — it enables concurrent agent execution (5 parallel, rest queued). Validation and duplicate checking also fire-and-forget. Never make the dispatch loop synchronous.

**Scope validation is default-deny.** `safe_to_test.rs` blocks everything not explicitly in scope. The Rust validator handles wildcards, CIDR, ports, and IP ranges. It has 25+ tests and is production-ready. Changes here require both positive and negative test cases because a bug means out-of-scope testing, which gets users banned from H1 programs.

**Tiered model routing is locked.** Haiku for simple agents (recon, CORS, headers, CRLF, cache, open-redirect, subdomain-takeover). Sonnet for moderate/complex (SQLi, XSS, SSRF, IDOR, OAuth, JWT). `COMPLEXITY_LOCKED_AGENTS` in `cost_router.ts` prevents keyword-based upgrades for 7 agent types. Budget enforcement lives at `TracedModelProvider` level: 90% soft warning, 100% hard stop. The user only uses Anthropic models — do not add OpenAI/Google/local model defaults.

**Validation pipeline is non-blocking.** Every finding goes through `validateFinding()` (18 deterministic validators in `validation/validator.ts`) and `runH1DuplicateCheck()`, both fire-and-forget. Findings display immediately with `pending` status, then update asynchronously. The validators are real (not stubs) — XSS uses Playwright dialog detection, SQLi re-executes payloads, SSRF checks OOB callbacks.

**Finding types carry validation state.** `AgentFinding` (in `base_agent.ts`) has `validationStatus: 'pending' | 'confirmed' | 'unverified' | 'validation_failed'` and `duplicateCheck: DuplicateCheckResult`. `FindingCardMessage` (in `conversation/types.ts`) mirrors these fields. Both `FindingsPanel.tsx` and `ChatMessage.tsx` render validation badges.

## Safety Rules

Every rule has a reason. The reason helps you judge edge cases.

**Always use argv arrays for command execution, never shell string interpolation.** `pty_manager.rs` uses `CommandBuilder` with explicit args. Shell injection through string concatenation is the #1 risk in offensive tooling. The PTY manager validates against dangerous characters (`|`, `&`, `;`, `$`) and sanitizes environment variables.

**Never bypass the approval gate.** The flow is: agent requests command → `onApprovalRequest` callback → CustomEvent → `ApproveDenyModal` → user approves/denies → Promise resolves. The only bypass is `autoApprove` settings, which require explicit user opt-in and a confirmation dialog. Approval promises have a 60-second timeout with audit trail logging.

**Kill switch must survive restarts.** `kill_switch.rs` uses atomic state + file persistence with fsync. On activation, it broadcasts to all subscribers and calls `Sandbox::destroy_all()`. The fail-safe on corrupted state files defaults to ACTIVE (safest).

**API keys go through secure storage only.** `secure_storage.rs` uses AES-256-GCM with HKDF key derivation and per-encryption random nonces. `SettingsContext` explicitly strips `apiKeys` before `localStorage.setItem()`. Never log, print, or include API keys in error messages.

**Every finding must go through validation before the user acts on it.** The pipeline: agent finding → dedup → `validateFinding()` (async) → `runH1DuplicateCheck()` (async) → display with status badge. Never skip validation. Never discard a finding — mark it `unverified` or `validation_failed` instead.

## Current System State

What's production-ready (verified by 9 live hunts + code audit):
- Scope validation (42+ tests), kill switch, secure storage, command execution — all 10/10
- Training allowlist hardened: bash/sh/nc/ncat removed, python3 arg-validated (Session 9)
- PTY writer: eager init, poison recovery, health checks, diagnostic logging (Session 9)
- 27 finding validators (18 original + 9 OAuth validators added Session 11)
- Hallucination gate: agents must make >= 3 HTTP interactions before findings accepted (Session 11)
- Evidence normalization: `normalizeEvidence()` at pipeline boundary — never crashes on LLM output (Session 11)
- Global API limit detection: first "usage limits" error pauses entire hunt (Session 11)
- Docker sandbox: `auto_remove: false`, readiness wait, health check before exec (Session 11)
- Cross-hunt duplicate detection: flags findings matching previous sessions via hunt_memory (Session 11)
- Cross-agent knowledge sharing: Blackboard auto-enriched, SharedFinding[] in agent system prompts, all 27 agents wired (Session 19)
- Auth context management: Settings UI (Auth tab), profile CRUD (bearer/form/API key/custom), secure credential storage, auto-injection at ReactLoop HTTP layer, hunt init creates live sessions (Session 14)
- Token refresh: JWT exp parsing, 4-strategy RefreshConfig (initdata/OAuth2/custom/re-login), 401 auto-retry via authenticatedRequest(), proactive refresh (90s threshold), rate-limited (1/30s/session), onRefreshFailed callback (Session 16 + Session 17 S8)
- Mid-hunt budget adjustment: `adjust_budget` orchestrator tool, increase-only (Session 11)
- Headless browser (real Playwright), OOB server (interactsh + Burp + DNS canary)
- Browser tools in hunt flow: 4 agent tools (navigate, evaluate JS, click, get content), scope-enforced, lazy-init, enabled for XSS/SSTI/prototype-pollution/business-logic agents (Session 21)
- Rate controller (per-domain adaptive), stealth (19 UAs), WAF detection
- Tiered model routing, budget enforcement (90% warn, 100% hard stop)
- Docker attack machine (640MB, 15 tools, tinyproxy scope enforcement)
- H1 duplicate check verified against live /hacktivity API (3 programs tested)
- Retry with backoff, dead-letter queue, sliding window circuit breaker
- Approval gate with 60s timeout, confirmation dialog, audit trail
- Duplicate scoring uses 3 sources: H1 hacktivity, GitHub advisories, internal Qdrant memory (Session 12)
- Chain detection produces `validated: boolean` — title-match chains marked "Potential", validator-confirmed marked "Confirmed" (Session 12)
- Real CVSS 3.1 calculator wired into PoC generator with vector strings in reports (Session 12)
- Dispatch guard: tasks with undefined targets caught and logged, not dispatched (Session 12)

What needs work — honest assessment after Session 18 audit:
- **Cross-agent knowledge sharing (I7).** ✅ RESOLVED (Session 19). Blackboard auto-enriched with findings. SharedFinding[] injected into agent system prompts via ReactLoopConfig. All 27 agents wired. 17 tests.
- **Agents are WAF-aware (I8).** ✅ RESOLVED (Session 19). WafContext with vendor-specific bypass strategies injected into agent system prompts. Dynamic per-domain detection, all 27 agents wired. 18 tests.
- **28 vuln types use pass-through validators** (agent confidence only) — not deterministic. High false positive risk on uncommon types.
- **Report quality scorer not validated against real H1 acceptance criteria** — gives false confidence. Reports themselves improved (Session 13 RQ1-RQ6: HTTP exchanges, H1 templates, CVSS vectors), but scorer was never checked against actual H1 triage outcomes.
- **localStorage session data encrypted (I2).** ✅ RESOLVED (Session 19). Session persistence uses Tauri secure storage (AES-256-GCM) with auto-migration from plaintext. 12 tests.
- **Crawler is HTTP-only.** No JS rendering — misses SPA endpoints (most modern targets).
- Training pipeline not connected (requires GPU, future phase).

## Coding Standards

**TypeScript:** Strict mode, no `any`. Interfaces for extensible shapes. `async/await` only. Functional React with hooks. Tauri `invoke()` calls must have typed command/response pairs.

**Rust:** `thiserror` for errors, `anyhow` only in binary entry points. Exhaustive pattern matching (no wildcard `_` on growable enums). `Arc<Mutex<T>>` with minimal lock duration. `tracing` crate for logging.

**Testing:** Every change needs tests. Scope validation changes need positive AND negative cases. Security-critical changes need explicit deny-path tests. Run the full suite before committing.

## Key Paths

| Path | What It Does |
|------|-------------|
| `src/core/orchestrator/orchestrator_engine.ts` | Orchestrator brain — dispatch loop, finding pipeline, agent coordination |
| `src/core/http/request_engine.ts` | HTTP chokepoint — scope, kill switch, rate limiting, stealth, WAF |
| `src/core/validation/validator.ts` | 18 deterministic validators dispatched by vulnerability type |
| `src/agents/base_agent.ts` | Agent interface + finding types (ValidationStatus, DuplicateCheckResult) |
| `src/core/conversation/types.ts` | All chat message types (discriminated union) |
| `src/core/orchestrator/cost_router.ts` | Tiered routing + complexity lock |
| `src-tauri/src/safe_to_test.rs` | Scope validation — default-deny, wildcards, CIDR |
| `src-tauri/src/kill_switch.rs` | Emergency shutdown — atomic, persistent, fail-safe |
| `src-tauri/src/pty_manager.rs` | Command execution — argv-only, env sanitized, redacted |
| `src/core/auth/session_manager.ts` | Auth sessions — login, bearer, API key, CSRF, IDOR pairs, auto-refresh |
| `src/core/auth/token_refresher.ts` | Token lifecycle — JWT exp parsing, Telegram initData re-exchange, rate limiting |
| `src/core/reporting/h1_api.ts` | HackerOne API client (14 mock + 10 live tests) |
| `src/core/reporting/severity_predictor.ts` | TF-IDF embeddings + bounty prediction |
| `src/core/discovery/api_schema_parser.ts` | OpenAPI/Swagger/GraphQL → endpoint catalog + task generation |
| `src/core/orchestrator/program_selector.ts` | H1 program scoring + VDP selection + hunt checklist |
| `src/core/orchestrator/hunt_metrics.ts` | Hunt metrics tracking + Phase 5 target evaluation |
| `docker/Dockerfile.attack-machine` | Attack machine with 15 security tools + tinyproxy scope enforcement |

## Common Tasks

**Adding a vulnerability hunter agent:** Create in `src/agents/` implementing BaseAgent interface. Register in `agent_catalog.ts`. Map complexity in `cost_router.ts` AGENT_COMPLEXITY. Add to `standardized_agents.ts` for self-registration. Write tests for the full task → execution → findings pipeline.

**Modifying the finding pipeline:** Changes go in `orchestrator_engine.ts` `handleAgentResult()` (~line 1890). Finding flow: dedup → emit with `pending` → async validation → async H1 duplicate check → knowledge graph + hunt memory + reward system recording. All post-dedup steps are fire-and-forget.

**Modifying scope validation:** Changes in `safe_to_test.rs`. Always add positive AND negative test cases. Run `cargo test`. Test with a real HackerOne scope JSON.

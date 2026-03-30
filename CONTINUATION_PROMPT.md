# Huntress — Phase 1 Complete, Phase 2 Continuation Prompt

> **Copy everything below the line into your next Claude session.**

---

Read these documents first, in order:

1. `/home/kali/Desktop/Huntress/PRODUCTION_ROADMAP.md` — Living status document. Read Sections 8-10, 12-13.
2. `/home/kali/Desktop/Huntress/CLAUDE.md` — Project coding standards, architecture, and rules.

## Context from Previous Sessions (March 29, 2026)

### Sessions 1-2: Foundation (Complete)
- All build fixes (EventEmitter, crypto, title) — `vite build` passes
- Docker 27.5.1, Qdrant :6333, Juice Shop :3001, all security tools installed
- Proxy rotation wired into Rust `proxy_http_request()` with try/fallthrough
- Scope validation fixed across 4 code paths (port-stripping normalization)
- Error reporting fixed in all 27 agents
- Circuit breaker: stops after 5 consecutive fatal API errors
- Approval gate: `onApprovalRequest` callback wired (orchestrator → CustomEvent → ApproveDenyModal)
- Cost tracking: `TracedModelProvider` wraps raw provider ($15 budget, 80% warning, 100% stop)
- xterm migrated to @xterm/xterm@6.0.0
- 10 approval gate tests, kill switch interactive button

### Session 3: Verification, Hunt #2, & Strategic Research (Complete)
- **Kill switch hardened**: dispatch loop check added to orchestrator, request_engine fail-safe fixed (INACTIVE→ACTIVE), `[OK]` button made interactive, 6 Rust persistence tests + 16 TS tests
- **Secure storage verified**: AES-256-GCM vault on disk confirmed, entropy file permissions hardened to 600, divergence warning added, 11 TS tests
- **Hunt #2 against Juice Shop**: 9 findings (3 critical, 3 high, 1 low, 2 info), 1 vuln chain, 12 tasks executed. IDOR hunter found 5 exploitable vulns. **Stopped by credit exhaustion after 4/28 agents**. Circuit breaker correctly triggered.
- **Massive competitive research**: XBOW deep dive ($237M funded, 1,060 H1 submissions, 85% on 104 benchmarks), 15+ AI bounty tools analyzed, elite hunter methodologies studied, exhaustive 16-system Huntress audit
- **PRODUCTION_ROADMAP.md rewritten**: New Sections 8 (Competitive Intelligence), 9 (Gap Analysis), 10 (8-Phase Pipeline). Old 5-phase plan replaced with research-informed 8-phase pipeline.

## Current Verification State

```
npx tsc --noEmit --skipLibCheck    # PASS — zero errors
npx vitest run                      # 1,106 passed, 8 skipped, 30 test files
cd src-tauri && cargo test          # 74 passed, 0 failed
npm audit                           # 0 vulnerabilities
npx vite build                      # PASS — production build succeeds
```

---

## YOUR TASK: Execute Phase 1 — Cost Crisis & Core Wiring

Phase 1 is the single highest-impact change. Without it, hunts die from credit exhaustion before specialists run. The goal: **a hunt completes with ALL 28 agents running within a $10 budget**.

### Phase 1.1: Tiered Model Routing (Anthropic-Only) — THE #1 PRIORITY

**The Problem:** `getAgentProvider()` in `orchestrator_engine.ts` (line 1901) returns either the alloy instance or the primary provider. It **completely ignores** `agentModelOverrides` from settings and never calls `selectModelForTask()` from `cost_router.ts`. Every agent runs on the orchestrator model (Opus at $15/$75 per M tokens). This is why hunts cost $15+ and die before completing.

**The Solution:** Modify `getAgentProvider()` to route agents to tiered Anthropic models:

| Agent Category | Model | Rationale |
|---------------|-------|-----------|
| **Orchestrator** | Claude Opus 4.6 | Strategic reasoning (keep as-is) |
| **Recon Agent** | Claude Haiku 4.5 | Structured tool execution, fast |
| **High-Complexity** (SQLi, IDOR, OAuth, JWT, Business Logic) | Claude Sonnet 4.6 | Exploit crafting requires reasoning |
| **Medium-Complexity** (XSS, SSRF, SSTI, XXE, Path Traversal, GraphQL) | Claude Sonnet 4.6 | Tool-use reasoning |
| **Low-Complexity** (CORS, Headers, CRLF, Cache, Open Redirect, Subdomain Takeover) | Claude Haiku 4.5 | Pattern matching, less reasoning |

**Existing code to wire together:**
- `cost_router.ts` has: `classifyTaskComplexity()`, `selectModelForTask()`, `AGENT_COMPLEXITY` mapping, `MODEL_TIER` ranking. All fully implemented. Never called.
- `SettingsContext.tsx` has: `agentModelOverrides` field in `AppSettings` (currently empty `{}`).
- `orchestrator_engine.ts` line 1901: `getAgentProvider()` — this is the function to modify.
- Lines 940 and 961: `const agentProvider = this.getAgentProvider()` — called before each `agent.initialize()`.
- `dispatchAgent()` at line 894 has access to `task.agentType` which maps to the `AGENT_COMPLEXITY` table.

**Implementation approach:**
1. Modify `getAgentProvider()` to accept `agentType: string` parameter
2. Call `classifyTaskComplexity(agentType, task.description)` from `cost_router.ts`
3. Based on complexity, create/cache an `AnthropicProvider` instance for the appropriate tier
4. All tiers share the same API key — just different model IDs
5. Update calls at lines 940 and 961 to pass `task.agentType`
6. Add default tier configuration to settings (can be user-overridden later)

**CRITICAL: All models must be Anthropic (Claude) only.** The user explicitly requested: Opus orchestrator, Sonnet/Haiku for agents. No OpenAI, Google, or local models in the routing table for this implementation.

**AnthropicProvider model IDs:**
- Opus: `claude-opus-4-6-20250616`
- Sonnet: `claude-sonnet-4-5-20250514`
- Haiku: `claude-haiku-4-5-20251001`

### Phase 1.2: Budget Enforcement in Dispatch Loop

**The Problem:** `budgetLimitUsd` exists in settings (default $15) but the dispatch loop at line 1198 never checks it. Hunts drain credits until API returns 402 errors.

**The Solution:** Add a budget check at the top of each dispatch loop iteration:
1. Call `TracedModelProvider.getTotalCost()` (or equivalent from `CostTracker`)
2. At 90% of budget: stop dispatching new agents, let running ones complete, emit warning
3. At 100%: hard-abort, emit system message
4. Display running cost after each agent completion

**Key files:**
- `orchestrator_engine.ts` lines 1198-1293 (dispatch loop)
- `src/core/tracing/traced_provider.ts` (TracedModelProvider)
- `src/core/tracing/cost_tracker.ts` (CostTracker)
- `src/contexts/HuntSessionContext.tsx` (where TracedModelProvider is created)

### Phase 1.3: Scope Entry Normalization

**The Problem:** `localhost:3001` and `127.0.0.1:3001` generate 2 separate recon tasks, doubling recon cost.

**The Solution:** Normalize scope entries on import:
- `localhost` ↔ `127.0.0.1` → treat as same target
- Strip scheme prefixes: `http://localhost:3001` → `localhost:3001`
- Deduplicate before generating recon tasks
- `TargetDeduplicator` exists but is never called in `startHunt()` flow

### Phase 1.4: Smart Agent Dispatch (Tech-Stack-Aware)

**The Problem:** All 28 agents dispatched regardless of tech stack. SSTI on Node.js = wasted budget.

**The Solution:** After recon, read tech stack from blackboard:
- Node.js/Express → skip SSTI, SAML (unless SSO detected), deprioritize deserialization
- SQLite → prioritize SQLi
- REST API → prioritize IDOR/BOLA
- Angular SPA → prioritize XSS with DOM testing
- Reduce from 28 agents to ~15 relevant ones = ~45% cost savings

### Phase 1 Verification Gate

Before marking Phase 1 complete, all of these must pass:
- [ ] Full Juice Shop hunt completes with 20+ agents dispatched
- [ ] Total cost under $10 (down from $15+ incomplete)
- [ ] Zero duplicate recon tasks
- [ ] Agent dispatch order reflects tech stack priority
- [ ] Budget tracking accurate to within 10% of actual API spend
- [ ] All existing tests still pass (1,106 TS + 74 Rust)
- [ ] New tests written for: model routing selection, budget enforcement, scope normalization, tech-stack filtering

### Test Coverage Required

Every change needs tests:
- Model routing: test that `classifyTaskComplexity()` maps agents correctly, `getAgentProvider()` returns different tiers for different agents
- Budget enforcement: test that dispatch loop stops at 90% budget, hard-aborts at 100%
- Scope normalization: test that localhost/127.0.0.1 deduplicate, scheme stripping works
- Tech-stack filtering: test that Node.js tech stack skips SSTI agent, SQLite prioritizes SQLi

---

## STANDING INSTRUCTIONS

### After completing Phase 1:
1. Update **PRODUCTION_ROADMAP.md Section 12** (Verification Checklist) — check off Phase 1 items
2. Update **PRODUCTION_ROADMAP.md Section 13** (Change Log) — add Phase 1 entry with what worked, what didn't
3. Update **Section 10 Phase 1** checklist items — mark completed
4. Update **Section 2** (Build & Test Verification) if test counts change
5. If you discover NEW issues, add them to Section 7 (High-Priority Issues)
6. **Bump the overall score** if Phase 1 materially improves readiness

### Code Quality Standards
- TypeScript strict mode, no `any` types
- Every function change needs tests
- Exhaustive pattern matching on enums
- `cargo clippy -- -D warnings` clean
- No shortcuts, no degradation — this is production-grade

### Anthropic-Only Model Routing
**IMPORTANT**: The user explicitly requested Anthropic models only for the tiered routing. Do NOT add OpenAI/Google/local models to the default tier configuration. The model routing should default to:
- Orchestrator: Opus
- Simple tasks: Haiku
- Moderate tasks: Sonnet
- Complex tasks: Opus

---

## Key File Map

| File | What's There | What Needs to Change |
|------|-------------|---------------------|
| `src/core/orchestrator/orchestrator_engine.ts` | `getAgentProvider()` at L1901, `dispatchAgent()` at L894, dispatch loop at L1198 | Wire model routing, add budget check, add scope dedup |
| `src/core/orchestrator/cost_router.ts` | Full implementation of `classifyTaskComplexity()`, `selectModelForTask()`, `estimateTaskCost()` | Update model tiers to Anthropic-only defaults |
| `src/contexts/SettingsContext.tsx` | `agentModelOverrides: {}`, `budgetLimitUsd: 15` | May need default tier config |
| `src/contexts/HuntSessionContext.tsx` | TracedModelProvider wrapping, CostTracker init | May need to pass cost tracker to orchestrator |
| `src/core/tracing/traced_provider.ts` | TracedModelProvider with checkBudget() | Verify it tracks per-model costs |
| `src/core/tracing/cost_tracker.ts` | CostTracker with budget warning/exceeded callbacks | Wire into dispatch loop |
| `src/core/providers/anthropic_provider.ts` | AnthropicProvider implementation | Need to create instances per tier |

## System State

- **OS:** Kali Linux, Docker 27.5.1
- **Docker:** Qdrant (:6333), Juice Shop (:3001) — may need `docker compose --profile testing up -d`
- **Tests:** 1,106 TS (30 files) + 74 Rust, all passing
- **Score:** 8.5/10 but with 3/10 cost efficiency
- **All changes uncommitted** — review with `git diff --stat HEAD`
- **Budget:** Currently $15 default — adjust as needed during testing

# PRE-HUNT TASK LIST — Huntress First Real-World Bug Bounty

> **Created:** March 29, 2026
> **Purpose:** Complete checklist of every fix, install, and verification needed before running the first real HackerOne bug bounty hunt
> **Companion Doc:** PRODUCTION_ROADMAP.md (overall project status and long-term pipeline)

---

## Current State Summary

- **TypeScript:** Compiles clean. 1,069 tests pass across 27 test files
- **Rust:** Compiles clean. 68 tests pass, 0 failures
- **Tauri Dev Mode:** App launches, Rust backend initializes, Vite dev server runs on :1420
- **Tauri Build (production):** FAILS — two separate issues (version mismatch + EventEmitter)
- **Docker/Podman:** NOT INSTALLED — no Qdrant, no sandboxing
- **Security Tools:** Most installed; 3 missing (interactsh-client, jq, corsy)
- **Proxy Rotation:** Code exists but is NOT wired into HTTP requests
- **First Hunt:** Never attempted — zero real-world testing

---

## Phase A — Build Fixes (App Won't Build/Run Clean)

### A1. Fix Tauri Package Version Mismatch

**Problem:** Rust crate `tauri` is v2.10.3 but npm `@tauri-apps/api` is v2.9.0. Both `tauri dev` and `tauri build` show an error. Dev mode still launches despite the error; production build refuses to proceed.

**Fix:**
```bash
cd /home/kali/Desktop/Huntress
npm install @tauri-apps/api@latest @tauri-apps/plugin-opener@latest
```

**Verify:**
```bash
npx tauri dev  # Should launch WITHOUT "version mismatched" error
```

**Status:** `[x] DONE — @tauri-apps/api updated to 2.10.1`

---

### A2. Fix EventEmitter Node.js Imports (11 Files)

**Problem:** 11 files in `src/core/training/` import `EventEmitter` from `events`, which is a Node.js built-in module. Vite's production build (Rollup) rejects this because it targets the browser. The dev server (ESBuild) shims it, so `tauri dev` works but `tauri build` / `vite build` fails.

**Error:**
```
"EventEmitter" is not exported by "__vite-browser-external"
src/core/training/training_manager.ts:16:9
```

**Affected Files (all 11):**
1. `src/core/training/training_manager.ts` (line 16)
2. `src/core/training/rollback_manager.ts` (line 12)
3. `src/core/training/readiness_checker.ts` (line 12)
4. `src/core/training/integration.ts` (line 12)
5. `src/core/training/deployment_manager.ts` (line 12)
6. `src/core/training/model_manager.ts` (line 12)
7. `src/core/training/ab_testing.ts` (line 12)
8. `src/core/training/performance_monitor.ts` (line 12)
9. `src/core/training/health_checker.ts` (line 13)
10. `src/core/training/scheduler.ts` (line 12)
11. `src/core/training/learning_loop.ts` (line 12)

**Fix — Option A (recommended):** Install a browser-compatible EventEmitter and replace imports:
```bash
npm install eventemitter3
```
Then in each file, replace:
```typescript
// BEFORE
import { EventEmitter } from 'events';

// AFTER
import { EventEmitter } from 'eventemitter3';
```

**Fix — Option B:** Create a minimal browser EventEmitter shim at `src/core/training/event_emitter.ts` and import from there.

**Verify:**
```bash
npx vite build  # Should complete without errors
```

**Status:** `[x] DONE — 11 files migrated to eventemitter3`

---

### A3. Fix Node.js `crypto` Import in PKCE Validator

**Problem:** `src/agents/oauth/pkce_validator.ts` (line 13) imports `crypto` from Node.js. This will crash at runtime when the OAuth agent runs in the browser context.

**Affected Code (line 13):**
```typescript
import crypto from 'crypto';
```

**Used at (2 locations):**
- Line 402: `crypto.randomBytes(length)` — generates random bytes for PKCE verifier
- Line 421: `crypto.createHash('sha256').update(verifier).digest()` — SHA-256 hash for PKCE challenge

**Fix:** Replace with Web Crypto API (available in all browsers and Tauri WebView):

```typescript
// BEFORE (line 402)
const randomBytes = crypto.randomBytes(length);

// AFTER
const randomBytes = globalThis.crypto.getRandomValues(new Uint8Array(length));

// BEFORE (line 421)
const hash = crypto.createHash('sha256').update(verifier).digest();

// AFTER
const encoder = new TextEncoder();
const data = encoder.encode(verifier);
const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', data);
const hash = new Uint8Array(hashBuffer);
```

Remove the `import crypto from 'crypto';` line entirely.

**Note:** The function containing line 421 may need to become `async` if it isn't already, since `crypto.subtle.digest()` returns a Promise.

**Verify:**
```bash
# Confirm no Node.js module imports remain in non-test source files
grep -r "from 'crypto'" src/ --include="*.ts" --include="*.tsx" | grep -v node_modules | grep -v ".test." | grep -v "tests/"
# Should return empty
```

**Status:** `[x] DONE — Web Crypto API replaces Node.js crypto`

---

### A4. Update index.html Title

**Problem:** `index.html` (line 5) still has the Tauri template title "Tauri + React + Typescript" instead of the application name.

**Fix:** In `/home/kali/Desktop/Huntress/index.html`, change:
```html
<!-- BEFORE -->
<title>Tauri + React + Typescript</title>

<!-- AFTER -->
<title>Huntress - AI Bug Bounty Platform</title>
```

**Status:** `[ ] NOT DONE`

---

## Phase B — Infrastructure Installs

### B1. Install Docker

**Problem:** Neither Docker nor Podman is installed. Required for Qdrant (vector database) and Docker sandbox execution.

**Fix:**
```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo usermod -aG docker $USER
# Must log out and back in (or use newgrp) for group to take effect
newgrp docker
```

**Verify:**
```bash
docker run --rm hello-world  # Should print "Hello from Docker!"
docker compose version       # Should show version
```

**Status:** `[x] DONE — Docker 27.5.1 installed, user added to docker group`

---

### B2. Start Qdrant Vector Database

**Problem:** Qdrant is required for hunt memory, duplicate detection against local history, and knowledge graph storage. It runs via Docker.

**Fix (after B1):**
```bash
cd /home/kali/Desktop/Huntress
docker compose up -d qdrant
```

**Verify:**
```bash
curl -s http://localhost:6333/collections | jq .  # Should return JSON with collections list
# If jq not installed yet, just: curl http://localhost:6333/collections
```

**Status:** `[ ] NOT DONE`

---

### B3. Install Missing Security Tools

**Problem:** Three tools used by agents are not installed: `interactsh-client` (blind vulnerability detection), `jq` (JSON parsing), and `corsy` (CORS testing).

**Fix:**
```bash
# interactsh-client (Go-based, used for blind XSS/SSRF/XXE detection)
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# jq (JSON processor, used by multiple agents for output parsing)
sudo apt install -y jq

# corsy (CORS misconfiguration scanner, used by CORS hunter agent)
pip3 install corsy || git clone https://github.com/s0md3v/Corsy.git ~/.local/share/corsy
```

**Verify:**
```bash
interactsh-client --version
jq --version
corsy --help 2>&1 | head -3  # or python3 -m corsy --help
```

**Status:** `[x] DONE — interactsh-client, jq 1.8.1, corsy installed`

---

### B4. Fix npm Audit Vulnerabilities

**Problem:** `npm audit` reports 4 high-severity vulnerabilities in transitive dependencies.

**Fix:**
```bash
cd /home/kali/Desktop/Huntress
npm audit fix
# If that doesn't resolve all: review npm audit output and update specific packages
```

**Verify:**
```bash
npm audit  # Should show 0 high/critical vulnerabilities
```

**Status:** `[ ] NOT DONE`

---

## Phase C — Hunt-Critical Code Fixes

### C1. Wire Proxy Rotation into HTTP Requests

**Problem:** `proxy_pool.rs` implements full proxy rotation (round-robin, random, LRU, fastest-first) with health checking, but `proxy_http_request()` in `lib.rs` builds a raw reqwest client and never calls the proxy pool. Every agent HTTP request goes direct from the host IP.

**File:** `src-tauri/src/lib.rs` — the `proxy_http_request()` function (around line 719)

**Current Code (simplified):**
```rust
async fn proxy_http_request(...) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(redirect_policy)
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
    // ... executes request with NO proxy ...
}
```

**Fix — Modify `proxy_http_request()` to:**
1. Acquire a lock on `GLOBAL_PROXY_POOL`
2. Call `get_next_proxy()` — if a proxy is available, configure the reqwest client with `.proxy(reqwest::Proxy::all(proxy_url))`
3. On successful response, call `mark_proxy_success(index)`
4. On failure, call `mark_proxy_failed(index)` and optionally retry with next proxy
5. If no proxies loaded or all failed, fall through to direct connection (current behavior)

**Key references:**
- `GLOBAL_PROXY_POOL` is a `Lazy<Mutex<ProxyPool>>` (see proxy_pool.rs)
- `ProxyPool::get_next_proxy()` returns `Option<(usize, ProxyEntry)>`
- `ProxyPool::mark_proxy_success(index)` / `mark_proxy_failed(index)`

**Verify:**
```bash
cd src-tauri && cargo test  # All tests still pass
# Manual verification: load proxies, make request, check proxy stats show usage
```

**Status:** `[x] DONE — proxy_pool integrated into proxy_http_request()`

---

### C2. Add Scope Enforcement for PTY Shell Commands

**Problem:** When Docker sandbox is unavailable (which it will be until B1 is done, and even after if the attack machine image isn't built), agents execute commands via bare PTY. The PTY has command injection protection (metacharacter blocking) but NO scope enforcement — an agent could run `nmap 10.0.0.0/8` against out-of-scope targets.

**File:** `src/core/engine/react_loop.ts` — `handleExecuteCommand()` method

**Fix — Before command execution, add target validation:**
1. Extract the target hostname/IP from the command string
2. Call `validate_target` via the Tauri bridge
3. If target is not in-scope, block the command and return error to the agent

**Implementation approach:**
```typescript
// In handleExecuteCommand(), after safety policy check but before execution:
const targetFromCommand = extractTargetFromCommand(input.command);
if (targetFromCommand) {
  const inScope = await invoke<boolean>('validate_target', { target: targetFromCommand });
  if (!inScope) {
    return {
      type: 'tool_result',
      content: `BLOCKED: Target "${targetFromCommand}" is not in scope. Only in-scope targets may be tested.`,
      is_error: true,
    };
  }
}
```

The `extractTargetFromCommand()` helper should parse common patterns:
- `nmap TARGET` / `nmap -sV TARGET`
- `curl https://TARGET/path`
- `nuclei -u https://TARGET`
- `sqlmap -u https://TARGET/page?id=1`
- Fall back to the `input.target` field from the tool call

**Verify:**
- Agent command targeting an in-scope domain proceeds normally
- Agent command targeting an out-of-scope IP/domain is blocked
- Commands without a clear target (e.g., `whoami`) are allowed

**Status:** `[x] DONE — extractTargetFromCommand + validate_target in react_loop.ts`

---

## Phase D — First Hunt Dry-Run (Juice Shop)

### D1. Prepare AI Provider API Key

**Requirement:** Have at least one AI provider API key ready with sufficient credits.

**Recommended for first test:**
- **Claude Sonnet 4.5** via Anthropic — good balance of capability and cost
- Or **GPT-4o** via OpenAI
- Minimum $5-10 credit for a test hunt session

**Status:** `[ ] NOT DONE`

---

### D2. Launch App and Complete Setup Wizard

**Steps:**
```bash
cd /home/kali/Desktop/Huntress
npm run tauri dev
```

1. Complete the 6-step setup wizard:
   - Step 1: Welcome
   - Step 2: Select AI provider (Anthropic, OpenAI, Google, Local, OpenRouter)
   - Step 3: Enter API key — wizard validates it against the provider
   - Step 4: Select agent model (optional — can default to orchestrator model)
   - Step 5: HackerOne API token (optional — skip for Juice Shop test)
   - Step 6: Confirm settings
2. Configure auto-approve rules:
   - Enable auto-approve for **Passive Recon** (safe commands like subfinder, httpx)
   - Keep approval required for **Active Scanning** (important for safety)

**Verify:** Settings panel shows configured provider and model. Chat interface loads with ASCII banner.

**Status:** `[ ] NOT DONE`

---

### D3. Start Juice Shop Test Target

**Steps (after B1 Docker install):**
```bash
cd /home/kali/Desktop/Huntress
docker compose --profile testing up -d
```

**Verify:**
```bash
curl -s http://localhost:3001 | head -5  # Should return Juice Shop HTML
# Or open http://localhost:3001 in browser
```

**Status:** `[ ] NOT DONE`

---

### D4. Import Juice Shop as Bounty Program

**Steps:**
1. Click "New Hunt" in the app
2. Select "Manual Entry" mode
3. Enter:
   - **Program Name:** OWASP Juice Shop (Test)
   - **In-Scope Targets:** `localhost:3001`, `127.0.0.1:3001`
   - **Out-of-Scope:** everything else
   - **Bounty Range:** N/A (test)
   - **Rules:** Test target, no restrictions
4. Click Import
5. Review the briefing view
6. Select a recommended strategy OR type a custom instruction like: "Run reconnaissance, then test for XSS and SQL injection"

**Status:** `[ ] READY — follow steps above`

---

### D5. Monitor Hunt Execution

**What to watch for:**
- [ ] Agent status panel shows agents activating (yellow pulsing indicators)
- [ ] Approval modals appear for active testing commands
- [ ] Chat shows orchestrator messages about strategy and progress
- [ ] Terminal view shows command output (if enabled)
- [ ] Findings populate in the findings panel with severity badges
- [ ] No crashes or blank screens
- [ ] Kill switch stops everything when activated

**Document all errors, warnings, or unexpected behaviors.**

**Status:** `[ ] READY — monitor after D4`

---

### D6. Generate a Test Report

**Steps:**
1. Click "Generate Report" on any finding in the findings panel
2. Verify the report editor opens with:
   - Pre-filled title, description, reproduction steps
   - CVSS score and severity badge
   - CWE weakness ID
   - Duplicate score indicator
3. Review the markdown preview
4. **DO NOT click "Submit to HackerOne"** — this is Juice Shop, not a real program

**Status:** `[ ] READY — generate after D5 findings`

---

## Phase E — First Real HackerOne Hunt

### E1. Select a HackerOne Program

**Criteria for first real hunt:**
- [ ] Wide scope (many domains/assets — more surface area)
- [ ] Active program (responds to reports within reasonable time)
- [ ] Bounty-paying (not VDP-only — validates the full pipeline)
- [ ] Lower competition (newer or less popular programs)
- [ ] You are already enrolled / accepted into the program

**Status:** `[ ] NOT DONE`

---

### E2. Import Program via HackerOne URL

**Steps:**
1. Click "New Hunt" → URL mode
2. Paste the HackerOne program URL (e.g., `https://hackerone.com/program_name`)
3. App fetches program via H1 API
4. Review the briefing: in-scope targets, out-of-scope exclusions, bounty ranges, rules
5. **Cross-check the scope manually against the HackerOne page** — verify the app parsed it correctly

**Status:** `[ ] NOT DONE`

---

### E3. Run Hunt with Conservative Settings

**Configuration for first real hunt:**
- [ ] Approval required for ALL command categories (recon AND active)
- [ ] Start with **Recon agent only** — do not enable active testing agents yet
- [ ] Review every single approval prompt carefully
- [ ] Monitor rate limiting — don't hammer the target
- [ ] Only expand to more agents (XSS, SQLi, etc.) after recon completes successfully

**Status:** `[ ] NOT DONE`

---

### E4. Review Findings Manually

**For each finding:**
- [ ] Verify the vulnerability is real (not a false positive)
- [ ] Check reproduction steps actually work when done manually
- [ ] Verify target is in-scope (double-check against H1 page)
- [ ] Check duplicate detection results — is this a known issue?
- [ ] Review severity rating — does CVSS score seem accurate?

**Status:** `[ ] NOT DONE`

---

### E5. Submit First Report (If Valid)

**Steps:**
1. Click "Generate Report" on a validated finding
2. **Stage 1 (Editor):** Review and edit the report. Ensure:
   - Clear title with vulnerability type
   - Detailed reproduction steps
   - Impact analysis
   - Proof (screenshots, request/response logs)
3. **Stage 2 (Review):** Quality gate checks:
   - Quality grade must be C or above
   - Duplicate risk should be "submit" (not "skip" or "review")
   - All 8 checklist items checked
4. **Stage 3 (Submit):** Click "Submit to HackerOne"
5. Track the H1 response and record outcome in PRODUCTION_ROADMAP.md change log

**Status:** `[ ] NOT DONE`

---

## Task Summary

| Phase | Tasks | Purpose | Effort |
|-------|-------|---------|--------|
| **A** Build Fixes | 4 | App builds and launches cleanly | ~1-2 hours |
| **B** Infrastructure | 4 | Docker, Qdrant, tools installed | ~30 minutes |
| **C** Code Fixes | 2 | Proxy rotation + scope enforcement | ~2-3 hours |
| **D** Dry Run | 6 | End-to-end test against Juice Shop | ~1-2 hours |
| **E** Real Hunt | 5 | First HackerOne hunt | Variable |
| **Total** | **21 tasks** | | **~5-8 hours to first real hunt** |

### Critical Path (Minimum for First Dry Run)

The absolute minimum to see the app run a hunt against Juice Shop:

```
A1 (fix Tauri versions) → A2 (fix EventEmitter) → A3 (fix crypto) →
B1 (install Docker) → B2 (start Qdrant) → D1 (API key) →
D2 (setup wizard) → D3 (start Juice Shop) → D4 (import & hunt)
```

### Dependencies Between Tasks

```
A1 ──→ A2 ──→ A3 ──→ (all Phase B/C/D tasks)
                       │
B1 ──→ B2 ─────────→ D3 ──→ D4 ──→ D5 ──→ D6
B1 ──→ (C2 scope enforcement benefits from Docker sandbox)
B3 ──→ (agents work better with full tool suite)
B4 ──→ (npm audit clean before real targets)
C1 ──→ (proxy rotation for real targets in Phase E)
C2 ──→ (scope enforcement for real targets in Phase E)
D1-D6 ──→ E1-E5
```

**A4 (title fix) and B3 (missing tools) and B4 (npm audit) can be done in parallel with anything.**

---

## Files That Will Be Modified

| File | Phase | Change |
|------|-------|--------|
| `package.json` | A1, B4 | Update @tauri-apps/api version, audit fixes |
| `src/core/training/training_manager.ts` | A2 | EventEmitter import |
| `src/core/training/rollback_manager.ts` | A2 | EventEmitter import |
| `src/core/training/readiness_checker.ts` | A2 | EventEmitter import |
| `src/core/training/integration.ts` | A2 | EventEmitter import |
| `src/core/training/deployment_manager.ts` | A2 | EventEmitter import |
| `src/core/training/model_manager.ts` | A2 | EventEmitter import |
| `src/core/training/ab_testing.ts` | A2 | EventEmitter import |
| `src/core/training/performance_monitor.ts` | A2 | EventEmitter import |
| `src/core/training/health_checker.ts` | A2 | EventEmitter import |
| `src/core/training/scheduler.ts` | A2 | EventEmitter import |
| `src/core/training/learning_loop.ts` | A2 | EventEmitter import |
| `src/agents/oauth/pkce_validator.ts` | A3 | Replace Node.js crypto with Web Crypto API |
| `index.html` | A4 | Update page title |
| `src-tauri/src/lib.rs` | C1 | Wire proxy pool into proxy_http_request() |
| `src/core/engine/react_loop.ts` | C2 | Add scope validation before PTY execution |

---

*After completing all Phase A-D tasks, update PRODUCTION_ROADMAP.md Section 10 (Verification Checklist) and Section 11 (Change Log) with results.*

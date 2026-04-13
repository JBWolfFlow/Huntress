# Huntress — Next Phase Implementation Plan

## Universal Browser Access, Auth Capture Agent, Report Quality Overhaul

**Created:** 2026-04-11
**Status:** Research phase — pending deep research on H1 report quality standards
**Trigger:** Hunt #10 (Wallet on Telegram) exposed three systemic issues

---

## Context

Hunt #10 (Wallet on Telegram) was the first hunt after fixing the white screen bug, auth wizard trigger, and auth pipeline. Auth is now working (wallet-authorization header + 2 cookies flowing to all agents). But the hunt revealed three systemic quality issues:

### Problem 1: 23 of 27 agents have no browser access
Only 4 agents (xss-hunter, ssti-hunter, prototype-pollution-hunter, business-logic-hunter) have `browserEnabled: true` in their ReactLoop config. The remaining 23 agents cannot verify findings in a real browser. Multiple agents reported "cannot test without browser" or "would require DOM analysis" — they hit dead ends because they can only make HTTP requests.

### Problem 2: Auth wizard requires manual token extraction
The AuthWizardModal requires users to manually open browser DevTools, navigate to the target, log in, copy auth tokens from Network/Application tabs, and paste them into the wizard. This is friction-heavy and error-prone, especially for Telegram WebApp auth which requires extracting `wallet-authorization` headers and cookies.

### Problem 3: Report quality is not HackerOne-submission ready
The hunt produced reports with:
- **Wrong severity framing** — A preconnect `<link>` header reflection was called "CRITICAL SSRF" (it's not SSRF at all)
- **No browser-verified PoC** — Findings claimed vulnerabilities but never confirmed them in a real browser
- **Duplicate findings** — 3 identical CORS reports for 3 subdomains of the same root domain
- **Poor reproduction steps** — Steps like "see description" instead of concrete curl commands
- **Missing impact proof** — CORS finding didn't demonstrate actual data theft
- **$0 bounty estimates** — Even for potentially valid findings

---

## Phase A: Universal Browser Access

**Goal:** All hunting agents get browser tools by default with zero individual agent file changes.

### Architecture

Browser tools in Huntress:
- 4 tools: `browser_navigate`, `browser_evaluate`, `browser_click`, `browser_get_content`
- Defined in `src/core/engine/tool_schemas.ts` (BROWSER_TOOL_SCHEMAS)
- Gated by `browserEnabled` flag in `ReactLoopConfig` (src/core/engine/react_loop.ts:89)
- Lazy-initialized via `ensureBrowserPage()` — Playwright only starts when first browser tool is called
- Uses dynamic `import('playwright-core')` to avoid bundling Node.js module in browser

### Changes

**1. `src/core/engine/react_loop.ts` — constructor (~line 257)**
After the config merge, default `browserEnabled` to `true` and auto-include browser tool schemas:
```typescript
if (this.config.browserEnabled === undefined) {
  this.config.browserEnabled = true;
}
if (this.config.browserEnabled) {
  const hasBrowserTools = this.config.tools?.some(t => t.name === 'browser_navigate');
  if (!hasBrowserTools && this.config.tools) {
    this.config.tools = [...this.config.tools, ...BROWSER_TOOL_SCHEMAS];
  }
}
```

**2. `src/core/engine/tool_schemas.ts` — `getToolSchemasForAgent()` (line 596)**
Update default case to always include browser tools.

**Impact:** No changes to 27 agent files. Agents that don't use browser tools pay zero runtime cost (lazy init). ~4 extra tool schemas in LLM context per agent (~300 tokens, negligible).

---

## Phase B: Auth Wizard Browser Capture Agent

**Goal:** Button on AuthWizardModal that opens a visible browser, lets user log in, captures tokens automatically.

### Design

**New module: `src/core/auth/auth_browser_capture.ts`**
- Launches Playwright with `headless: false` (visible browser)
- Non-headless because users need to solve CAPTCHAs, MFA, OAuth consent screens
- Intercepts network requests to capture auth headers (Authorization, wallet-authorization, CSRF tokens)
- Monitors for login-complete signals (navigation away from login page, Set-Cookie after POST)
- Extracts cookies, localStorage, sessionStorage via `page.evaluate()`
- 120-second timeout
- Returns `CapturedAuth` object with all captured credentials

**UI: `src/components/AuthWizardModal.tsx` — Step 2**
- New `[AUTO-CAPTURE FROM BROWSER]` button next to existing `[TEST AUTH]`
- Dynamic import of `auth_browser_capture.ts` (avoids Playwright in browser bundle)
- Auto-fills form fields from captured tokens (bearer → bearer type, cookies → custom_header type)

---

## Phase C: Report Quality Overhaul

**Goal:** Agent findings are H1-submission-ready with correct severity, browser-verified PoC, and proper dedup.

### C1: Evidence Quality System Prompt
**File: `src/core/engine/react_loop.ts` — `buildSystemPrompt()`**
Add mandatory evidence quality section to ALL agent prompts:
- Full HTTP request/response pairs in evidence
- Concrete reproduction steps with exact URLs, methods, headers, payloads
- Severity calibration guidelines (Critical = RCE/auth bypass, not header reflection)
- Browser verification instruction (confirm findings with browser_navigate)

### C2: Severity Calibration Gate
**File: `src/core/engine/react_loop.ts` — `handleReportFinding()`**
New `checkSeverityCalibration()` catches known over-escalation patterns:
- Header reflection → not SSRF (downgrade)
- Info disclosure → not critical (downgrade)
- Self-XSS → not high (downgrade)
- Missing headers → not medium+ (downgrade)

### C3: Cross-Subdomain Deduplication
**File: `src/core/orchestrator/finding_dedup.ts` — `findingDedupKey()`**
Change from `hostname|type|param` to `rootDomain|type|param`:
- Same CORS on api.example.com and www.example.com → single finding
- Higher-severity finding wins on merge

### C4: Agent-Specific Prompt Fixes
- `src/agents/host_header.ts` — Preconnect reflection ≠ SSRF severity guidance
- `src/agents/cors_hunter.ts` — Report once for all subdomains guidance
- `src/agents/cache_hunter.ts` — 3-step cache poisoning verification requirement

### C5: Report Quality Scorer
**File: `src/core/reporting/report_quality.ts`**
Add penalty for inflated severity (critical without RCE/auth bypass keywords → -15 points).

---

## Implementation Order

```
Phase A (browser for all) → small diff, high impact, unblocks B and C
  ↓
Phase C1+C2+C3 (report quality core) → highest impact on finding quality
  ↓
Phase C4+C5 (agent prompts + scorer) → polish
  ↓
Phase B (auth capture agent) → independent UI feature
```

---

## Pending Research

Before implementing Phase C (report quality), deep research is needed on:
1. HackerOne report quality standards — what makes reports get accepted vs rejected
2. Bug bounty best practices — evidence gathering, PoC quality, severity justification
3. How top hunters write reports — format, structure, evidence types
4. What tools/techniques produce the best evidence
5. How to make AI agents capable of gathering that evidence

**This research will refine the Phase C implementation details.**

---

## Verification Plan

1. `npx tsc --noEmit --skipLibCheck` — zero errors
2. `npx vitest run` — all 1825+ tests pass
3. Manual: verify non-browser agent can call browser_navigate
4. Manual: auth wizard Auto-Capture works with Juice Shop
5. Manual: no duplicate findings for same vuln across subdomains
6. Manual: severity calibration gate catches over-escalation
7. Manual: run Hunt #11 and compare report quality to Hunt #10

---

## Key Files

| File | Phase | Change |
|------|-------|--------|
| `src/core/engine/react_loop.ts` | A, C1, C2 | Constructor default, system prompt, severity gate |
| `src/core/engine/tool_schemas.ts` | A | getToolSchemasForAgent update |
| `src/core/auth/auth_browser_capture.ts` | B | New file — browser token capture |
| `src/components/AuthWizardModal.tsx` | B | Auto-Capture button |
| `src/core/orchestrator/finding_dedup.ts` | C3 | Root domain normalization |
| `src/core/reporting/report_quality.ts` | C5 | Severity inflation penalty |
| `src/agents/host_header.ts` | C4 | Severity guidance prompt |
| `src/agents/cors_hunter.ts` | C4 | Dedup guidance prompt |
| `src/agents/cache_hunter.ts` | C4 | Verification requirement prompt |

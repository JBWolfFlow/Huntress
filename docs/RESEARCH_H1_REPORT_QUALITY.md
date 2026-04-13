# Deep Research: HackerOne Report Quality & Bug Bounty Best Practices

**Date:** 2026-04-11
**Purpose:** Inform Huntress agent system prompts, report generation, and validation pipeline
**Scope:** H1 acceptance criteria, evidence requirements per vuln class, XBOW architecture, AI detection signals

---

## 1. H1 Report Quality: What Gets Accepted vs Rejected

### The Five Required Elements (H1 Official Docs)

1. **Clear, specific title** — Must convey vuln type + location + impact. Bad: "XSS in web app". Good: "Stored XSS in user profile field allows script execution on profile view"
2. **Detailed reproduction steps** — Numbered, sequential. Someone unfamiliar with the app should reproduce from steps alone.
3. **Expected vs actual behavior** — Explicitly state what should happen vs what actually occurs
4. **Impact assessment** — Business + user consequences. "What does an attacker gain?" not "this is a vuln"
5. **Supporting materials** — Screenshots, video (<2min), HTTP request/response pairs, payload code

### Report States and Reputation Impact

| State | Reputation | Meaning |
|-------|-----------|---------|
| Resolved | +7 | Valid, fixed by program |
| Triaged | +7 | Confirmed, pending fix |
| Informative | 0 | Valid info, no action needed |
| Duplicate | Varies | Already reported |
| Not Applicable | -5 | Not valid/reproducible |
| Spam | -10 | No legitimate vulnerability |

### Core Ineligible Findings (Auto-Rejected on ALL Programs)

Critical for our agents — these are NEVER worth reporting:
- **"Permissive CORS configurations without demonstrated security impact"** — Header reflection alone is rejected
- **"Open redirects unless demonstrating additional security impact"** — Standalone redirects worthless
- Self-XSS (unless targeting other accounts)
- Clickjacking on pages with no sensitive actions
- CSRF on non-sensitive forms (logout, etc.)
- Missing security headers (HSTS, X-Frame-Options, etc.)
- Software version/banner disclosure
- SSL/TLS configuration opinions
- CSV injection
- Rate limiting issues (most)

### Common Rejection Reasons

1. Not reading the scope (#1 mistake per every triager source)
2. Theoretical impact without proof
3. Steps that can't be reproduced in <5 minutes
4. Tool output dumps without explanation
5. Multiple bugs in one report
6. Confusing bugs with best practices

---

## 2. Evidence Requirements by Vulnerability Type

### CORS Misconfiguration

**Accepted:** Working PoC page demonstrating actual cross-origin data theft. Must show: (1) endpoint returns sensitive data, (2) credentials are forwarded, (3) PoC HTML reads the data cross-origin. Without all three = Informative.

**Rejected:** Header reflection alone. CORS on public/unauthenticated endpoints. Missing Allow-Credentials. Wildcard without credentials.

**Critical note:** If auth uses custom headers (not cookies), CORS credential sharing has NO impact — browsers don't send custom headers cross-origin via CORS.

### Host Header / Cache Poisoning

**Accepted:** Poisoned response served to OTHER users (3-step proof):
1. Poison: Send request with manipulated X-Forwarded-Host + cache buster
2. Verify cache: Check CF-Cache-Status: HIT or X-Cache: HIT
3. Prove propagation: Clean request (no attack header) returns poisoned response

**Rejected:** Header reflection without cache storage proof. Some programs explicitly exclude all host header reports.

### XSS

**Minimum PoC:** alert(document.domain) — NOT alert(1) (must prove execution context)
- Reflected: Full URL with payload + browser screenshot showing execution
- Stored: Two-session proof (inject from Account A, trigger from Account B)
- DOM-based: Show JavaScript source creating the sink + DOM after injection

**Rejected:** Self-XSS, unsupported browsers only, screenshots without domain context

### SSRF

**Full SSRF:** Show internal data (cloud metadata 169.254.169.254, internal services)
**Blind SSRF:** DNS/HTTP callback via interactsh proves server made request

**Rejected:** Blind SSRF on features DESIGNED to fetch URLs (image proxy, webhook, URL preview)

### IDOR

**Required:** Two-account comparison (Account A accesses Account B's data by swapping IDs)
**H1 rule:** Unpredictable IDs (UUIDs) default to Attack Complexity "High" unless enumeration demonstrated

### Race Conditions

**Gold standard:** HTTP/2 single-packet attack (James Kettle technique). Show baseline (1 request) vs race (20 simultaneous requests) with different outcomes.

### SQL Injection

**Must include:** Raw HTTP request/response. curl command that reproduces. Show actual data extraction, not just error messages.

---

## 3. CVSS Scoring: Researcher vs Triager Gap

### H1-Specific Rules

- Self-signup programs: Privileges Required = None
- IDOR with unpredictable IDs: Attack Complexity = High (unless enumeration shown)
- PII in production = Critical confidentiality; dev/staging = Low
- Cache poisoning in dev = Medium; production = High

### What Agents Must Do

Explain EACH metric with reasoning, not just a score. Example:
- AV:N — exploitable over internet
- AC:L — sequential IDs make exploitation trivial
- PR:N — self-signup available
- UI:N — no victim action needed

---

## 4. The AI Slop Problem (CRITICAL for Huntress)

### Detection Signals Triagers Use

| Signal | What It Reveals |
|--------|----------------|
| Perfectly formatted prose with extensive bullet lists | Humans write terse, focused reports |
| Generic impact without specific data | Real researchers show exact data accessed |
| References to non-existent functions/endpoints | AI hallucination |
| Multiple reports in rapid succession | Automated tool pattern |
| No raw HTTP request/response pairs | Scanner output without real traffic |
| Over-broad remediation advice | Generic security advice vs specific fix |
| Claiming impossible vuln types for the technology | No understanding of the target |

### How to Avoid AI Detection

1. Include actual HTTP exchanges from real interactions (not generated/templated)
2. Reference real endpoints, parameters, response data — never hallucinate
3. Be terse and focused, not over-formatted
4. Show specific data accessed, not theoretical impact
5. Include environmental details (exact URLs, timestamps)
6. Never claim vulns impossible for the target technology
7. Limit submission volume (not 20 reports/day to one program)

---

## 5. XBOW Architecture (Our Benchmark)

### System Design

- **Coordinator:** Discovery + spawns narrow-objective solvers
- **Solvers:** Thousands of short-lived AI agents, each with single narrow objective
- **Validators:** Deterministic NON-AI code that confirms exploitability
- **Attack machines:** Isolated containers with security tools + headless browser

### Core Principles

1. **"Plausibility is not proof, confidence is not evidence"** — Raw LLM output is NEVER treated as a finding
2. Discovery and validation are COMPLETELY SEPARATE systems
3. Canary-based validation (plant CTF-flag-like strings, check if agent extracts them)
4. Headless browser for XSS (dialog detection = zero false positives)
5. Only issues surviving controlled non-destructive testing get reported

### XBOW Results

- 1,060+ vulns submitted, 130 resolved, 303 triaged
- Zero false positives across 17,000+ scans
- 48-step exploit chains autonomously
- #1 on H1 US leaderboard

### Key Lesson for Huntress

The 28 vuln types using pass-through validators (agent confidence only) are our biggest false-positive risk. Every vuln type needs a deterministic validator, not LLM confidence.

---

## 6. Browser-Based Verification Techniques (Playwright)

### XSS: Dialog Detection
Set up dialog listener BEFORE navigation. If dialog fires with domain info, XSS confirmed. XBOW's approach — zero false positives.

### CORS: Cross-Origin Fetch PoC
Serve attacker HTML page, fetch target API with credentials, read response. If data returned, CORS is exploitable.

### Cache Poisoning: 3-Step Verification
1. Poison with cache buster
2. Check CF-Cache-Status: HIT
3. Clean request returns poisoned response

### Open Redirect: URL Change Detection
Navigate to URL with redirect payload. Check final URL after networkidle. If attacker domain, confirmed.

### IDOR: Two-Session Comparison
Create two browser contexts with different auth. Make same request with swapped IDs. Compare responses.

### Screenshot Evidence
Full page screenshots as PNG evidence for every confirmed finding.

---

## 7. Vulnerability Chaining Patterns

| Chain | Components | Impact Escalation |
|-------|-----------|-------------------|
| Open Redirect -> OAuth Token Theft | Redirect + OAuth miscfg | Low -> Critical (ATO) |
| XSS -> Account Takeover | XSS + cookie theft | Medium -> Critical |
| SSRF -> Cloud Metadata -> RCE | SSRF + cloud miscfg | Medium -> Critical |
| IDOR + XSS -> Admin Takeover | IDOR write + stored XSS | Medium -> Critical |
| CORS + Subdomain XSS | CORS miscfg + XSS | Medium -> High |
| HTTP Smuggling -> Session Theft | CL.TE + request hijack | Medium -> Critical |

**H1 rule:** Chains evaluated by overall impact, not individual components. Submit as single report.

---

## 8. Evidence Decision Matrix for Agents

| Vulnerability | Minimum Evidence | Gets Rejected | Gets High Bounty |
|---|---|---|---|
| CORS | PoC page + data theft proof | Header reflection only | Auth token/PII exfiltration |
| Cache Poison | 3-step cache proof | Reflection without cache | Production XSS via cache |
| XSS Reflected | alert(document.domain) URL | Self-XSS, old browsers | CSP bypass, ATO chain |
| XSS Stored | Two-account trigger proof | IE-only, sandbox blocked | Admin panel, all users |
| SSRF Full | Internal data accessed | Feature designed to fetch | Cloud metadata -> RCE |
| SSRF Blind | DNS callback proof | Blind on URL fetcher | Internal enumeration |
| IDOR | Two-account ID swap | Unpredictable IDs no enum | PII/financial data |
| Open Redirect | Chain to OAuth/phishing | Standalone redirect | OAuth callback hijack |
| SQLi | Data extraction proof | "Might be injectable" | Database dump, auth bypass |
| Race Condition | HTTP/2 single-packet | Theoretical only | Balance manipulation |

---

## 9. Report Structure Template (from Top Hunters)

### Title
[Vulnerability Type] in [Component/Endpoint] allows [Impact] — [Target Domain]

### Summary
2-3 sentences: What broke, where, what exposure results.

### Description
- Which input/parameter is abused
- What authorization check failed
- What sensitive asset becomes exposed
- Focus on the broken assumption

### Steps to Reproduce
1. [Exact URL, method, headers]
2. [Exact payload]
3. [Observe: what happens]
4. [Evidence of impact]

### Proof of Concept
- Raw HTTP request/response pairs (copy-paste ready)
- curl command that reproduces
- Screenshot of browser confirming

### Impact
- Concrete exploitation scenario
- Scale of potential abuse
- Real-world consequences (data theft, ATO, etc.)
- CVSS score with vector string and per-metric reasoning

### Remediation (optional but increases bounty)
- Specific fix for this code
- Not generic OWASP links

---

## 10. Key Takeaways for Huntress Implementation

### Highest Priority Changes

1. **Every finding needs a curl command** — triagers reproduce by copy-pasting curl
2. **Browser verification mandatory for client-side vulns** — XSS dialog, CORS fetch, redirect URL check
3. **OOB callback for blind vulns** — interactsh for SSRF, XXE, command injection
4. **Two-account testing for IDOR** — victim/attacker sessions with ID swapping
5. **Reports must be terse** — AI slop detection targets over-formatted prose
6. **Show specific data, not theoretical impact** — "I accessed user X's billing" not "could access PII"
7. **One vulnerability per report** — never bundle
8. **Cross-subdomain dedup** — same vuln on 3 subdomains = 1 report listing all affected
9. **Severity calibration is critical** — preconnect header != SSRF, open redirect alone != High
10. **Pass-through validators are the #1 false positive risk** — need deterministic checks per XBOW model

### What Makes a $500 vs $5000 Report

- $500: Bug exists, basic reproduction
- $5000: Full exploitation chain, specific data accessed, business impact articulated, remediation guidance, demonstrates deep understanding of the target

---

## Sources

### HackerOne Official
- Quality Reports: docs.hackerone.com/en/articles/8475116-quality-reports
- Report States: docs.hackerone.com/en/articles/8475030-report-states
- Core Ineligible: docs.hackerone.com/en/articles/8494488-core-ineligible-findings
- Platform Standards: docs.hackerone.com/en/articles/8369826-detailed-platform-standards
- Severity/CVSS: docs.hackerone.com/en/articles/8495674-severity

### Triager Perspectives
- "There and Hack Again" — h1.community/blog
- "Tips from the Triager" — Mike Sheward, Medium
- "A Security Analyst's Perspective" — h1.community/blog

### XBOW
- "The Road to Top 1" — xbow.com/blog
- Platform Architecture — xbow.com/platform
- "1,060 Autonomous Attacks" — xbow.com/blog

### Bug Bounty Methodology
- Bug Bounty Hunting Methodology 2025 — github.com/amrelsagaei
- PayloadsAllTheThings — github.com/swisskyrepo
- PortSwigger Web Security Academy
- Report Blueprint — amrelsagaei.com

### AI & Bug Bounty
- curl AI report crisis — thenewstack.io, bleepingcomputer.com
- TechCrunch AI slop — techcrunch.com
- Academic study on invalid reports — arxiv.org/html/2511.18608v1

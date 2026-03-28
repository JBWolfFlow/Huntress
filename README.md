# Huntress

**AI-Powered Bug Bounty Automation Platform**

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8+-blue.svg)](https://www.typescriptlang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-2.0-24C8DB.svg)](https://tauri.app/)
[![React](https://img.shields.io/badge/React-19-61DAFB.svg)](https://react.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

Huntress is an enterprise-grade desktop application that automates bug bounty hunting through coordinated AI agents, rigorous security controls, and continuous learning. Built on a Rust security backend with a React/TypeScript frontend, it orchestrates 29 specialized vulnerability hunting agents across multiple AI providers while enforcing strict scope validation, human approval gates, and full audit trails.

Designed as a production-ready tool for professional security researchers, Huntress imports HackerOne bounty programs, analyzes attack surfaces, coordinates parallel hunting operations, and generates submission-ready vulnerability reports -- all through a conversational interface with the user in full control.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Key Capabilities](#key-capabilities)
- [Agent Fleet](#agent-fleet)
- [Security Model](#security-model)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Training Pipeline](#training-pipeline)
- [Development](#development)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Disclaimer](#disclaimer)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## Overview

Huntress operates on a Coordinator-Solver architecture. A primary AI model (the orchestrator) ingests a bounty program's full scope, analyzes the target surface, recommends attack strategies ranked by expected value, and then delegates execution to a fleet of specialized sub-agents. Each sub-agent runs its own AI model (configurable independently for cost optimization), generates and submits commands through scope validation and human approval pipelines, executes approved operations via an isolated PTY manager, and reports structured findings back to the orchestrator for synthesis and deduplication.

The platform supports any combination of AI providers -- Anthropic (Claude), OpenAI (GPT-4o), Google (Gemini), local models via Ollama, and OpenRouter -- allowing users to run a high-capability model as the orchestrator while using faster, cheaper models for sub-agent tasks.

### Core Design Principles

- **User control at every step.** The orchestrator recommends; the user decides. Every target interaction passes through scope validation and an approval gate before execution.
- **Default-deny security posture.** Targets not explicitly in scope are blocked. Commands not validated are denied. Proxies failing health checks are removed from rotation.
- **Multi-model by design.** Orchestrator and sub-agent models are independently configurable with zero code changes required when swapping providers.
- **Desktop-native experience.** Ships as a double-click-to-launch application with a polished conversational interface, not a developer CLI tool.

---

## Architecture

```
+-----------------------------------------------------------------------+
|                         Huntress Desktop Application                   |
+-----------------------------------------------------------------------+
|                                                                        |
|   +--------------------------------------------------------------+    |
|   |                  Frontend (React 19 / TypeScript)             |    |
|   |   Chat Interface | Agent Status | Findings | Report Editor   |    |
|   |   Setup Wizard | Approval Modals | Terminal | Training Dash   |    |
|   +-----------------------------+--------------------------------+    |
|                                 |                                      |
|                          Tauri IPC Bridge                               |
|                                 |                                      |
|   +-----------------------------v--------------------------------+    |
|   |                  Backend (Rust / Tauri 2.0)                   |    |
|   |   Scope Validator | PTY Manager | Kill Switch | Proxy Pool   |    |
|   |   Secure Storage | Sandbox Manager | HackerOne API           |    |
|   +-----------------------------+--------------------------------+    |
|                                 |                                      |
|   +-----------------------------v--------------------------------+    |
|   |              AI Orchestration Layer (TypeScript)               |    |
|   |   OrchestratorEngine | AgentRouter | ModelProvider Factory    |    |
|   |   ReAct Loop | Tool Schemas | Safety Policies                |    |
|   +-----------------------------+--------------------------------+    |
|                                 |                                      |
|   +-----------------------------v--------------------------------+    |
|   |                  Agent Fleet (29 Hunters)                      |    |
|   |   OAuth | SSRF | SQLi | XSS | GraphQL | IDOR | SSTI | ...   |    |
|   +-----------------------------+--------------------------------+    |
|                                 |                                      |
|   +-----------------------------v--------------------------------+    |
|   |                      Data Layer                                |    |
|   |   Qdrant (Vector DB) | SQLite (Knowledge) | Secure Vault     |    |
|   +--------------------------------------------------------------+    |
|                                                                        |
+-----------------------------------------------------------------------+
```

### Coordinator-Solver Pattern

The **OrchestratorEngine** acts as the coordinator -- it maintains conversation context, creates execution plans, delegates tasks, and synthesizes results. It communicates with the user through a structured chat interface supporting rich message types: text, code blocks, vulnerability finding cards, strategy option cards, approval modals, and report previews.

**Sub-agents** operate as solvers through a ReAct (Reason + Act) execution loop. Each agent receives a focused task, reasons about the approach, selects and executes tools, observes results, and iterates until the task is complete or a stopping condition is met. Agents report structured findings back to the orchestrator, which handles cross-agent correlation, chain detection, and deduplication.

### Multi-Model Provider Architecture

```
ModelProvider (Abstract Interface)
  |-- AnthropicProvider   (Claude Opus 4, Sonnet 4, Haiku 4)
  |-- OpenAIProvider      (GPT-4o, GPT-4o-mini, o3)
  |-- GoogleProvider      (Gemini 2.5 Pro, Gemini Flash)
  |-- LocalProvider       (Ollama -- Llama, Mistral, Qwen, etc.)
  |-- OpenRouterProvider  (Any model via OpenRouter API)
```

Each provider implements a common interface: `sendMessage`, `streamMessage`, `getAvailableModels`, `validateApiKey`, and `estimateCost`. The provider factory handles dynamic selection, and a fallback chain ensures graceful degradation when a provider is unavailable.

---

## Key Capabilities

### Vulnerability Hunting

- **29 specialized agents** covering OWASP Top 10, business logic, authentication, injection, and emerging vulnerability classes
- **Automated chain detection** identifies multi-step attack paths (e.g., open redirect to SSRF, IDOR to privilege escalation)
- **Parallel execution** with independent agent lifecycles managed by the AgentRouter
- **Target scoring and prioritization** based on asset type, historical bounty data, and attack surface analysis

### Reporting and Submission

- **Professional PoC generation** with CVSS scoring, step-by-step reproduction instructions, impact analysis, and remediation recommendations
- **Duplicate detection** against HackerOne, GitHub advisories, and the local vector database with 95%+ accuracy
- **Severity prediction** using ML-based bounty estimation
- **Direct HackerOne API integration** for report submission with attachment upload, targeting sub-2-minute turnaround
- **Report quality scoring** with automated review before submission

### Continuous Learning

- **HackTheBox integration** for automated training on real-world vulnerable machines
- **Local LoRA fine-tuning** on Llama-3.1-70B via Axolotl with zero data leakage
- **A/B testing framework** for statistically validating model improvements before deployment
- **Reward system** that reinforces successful hunting patterns and penalizes false positives
- **Gradual deployment** with automatic rollback if performance degrades

### Reconnaissance and Discovery

- **Attack surface mapping** with subdomain enumeration, technology fingerprinting, and endpoint discovery
- **JavaScript analysis** for API endpoint extraction and client-side vulnerability detection
- **Parameter mining** across crawled pages
- **Nuclei template integration** for known vulnerability scanning
- **WAF detection and evasion** with adaptive payload encoding

---

## Agent Fleet

Huntress ships with 29 self-registering vulnerability hunting agents, each implementing a standardized interface (`initialize`, `execute`, `validate`, `reportFindings`, `cleanup`):

| Agent | Vulnerability Class |
|-------|-------------------|
| OAuth Hunter (4 sub-modules) | Redirect URI manipulation, state bypass, PKCE bypass, scope escalation |
| SSRF Hunter | Server-side request forgery, internal service access |
| XSS Hunter | Reflected, stored, and DOM-based cross-site scripting |
| SQLi Hunter | SQL injection across multiple database engines |
| NoSQL Hunter | NoSQL injection (MongoDB, CouchDB, etc.) |
| GraphQL Hunter | Introspection, batching, nested query depth attacks |
| IDOR Hunter | Insecure direct object references, access control bypass |
| SSTI Hunter | Server-side template injection across multiple engines |
| Command Injection Hunter | OS command execution via user input |
| Path Traversal Hunter | Directory traversal and local file inclusion |
| CORS Hunter | Cross-origin resource sharing misconfiguration |
| Host Header Hunter | Host header injection, cache poisoning, password reset attacks |
| Open Redirect Hunter | URL redirect chains and downstream exploitation |
| Prototype Pollution Hunter | JavaScript prototype chain manipulation |
| CRLF Hunter | HTTP header injection via carriage return/line feed |
| HTTP Smuggling Hunter | Request smuggling (CL.TE, TE.CL, TE.TE) |
| XXE Hunter | XML external entity injection |
| JWT Hunter | JSON Web Token signature bypass, algorithm confusion |
| SAML Hunter | SAML assertion manipulation and signature wrapping |
| WebSocket Hunter | WebSocket origin validation and message injection |
| Race Condition Hunter | Time-of-check to time-of-use and parallel request races |
| Deserialization Hunter | Unsafe deserialization across multiple languages |
| Cache Hunter | Web cache poisoning and cache deception |
| Subdomain Takeover Hunter | Dangling DNS records and unclaimed cloud resources |
| MFA Bypass Hunter | Multi-factor authentication bypass techniques |
| Business Logic Hunter | Application-specific logic flaws |
| Prompt Injection Hunter | LLM prompt injection in AI-powered applications |
| Recon Agent | Subdomain enumeration, tech fingerprinting, endpoint discovery |

All agents self-register via `registerAgent()` at import time. The import trigger is centralized in `src/agents/standardized_agents.ts`.

---

## Security Model

Huntress enforces a defense-in-depth security model with multiple independent enforcement layers:

### Scope Validation Engine

The Rust-based scope validator (`safe_to_test.rs`, 1,235 LOC) implements HackerOne JSON format parsing with full support for wildcard domain matching, CIDR notation, IP ranges, and port specifications. All target interactions must pass scope validation before reaching the approval pipeline. The engine operates on a strict default-deny policy -- any target not explicitly listed as in-scope is blocked.

### Human Approval Gates

Before any command executes against a live target, an approval modal presents: the exact command, which agent requested it, the target it will contact, and the justification. Users can approve, deny, or modify commands. Per-category auto-approve rules are available (e.g., auto-approve passive reconnaissance while requiring approval for active testing).

### Kill Switch

The emergency shutdown system (`kill_switch.rs`) uses atomic state management with persistence across application restarts. State is written via a temp-file, fsync, and atomic rename pattern to prevent corruption. Signal handlers (SIGTERM, SIGINT) are wired to trigger immediate shutdown. The kill switch defaults to the safe (active) state if state cannot be read.

### Command Execution Security

All subprocess execution routes through the PTY manager (`pty_manager.rs`), which enforces explicit argv array parsing -- never shell string interpolation. Commands are constructed using null-byte-joined argument arrays to prevent injection. An allowlist governs which programs can be executed.

### Secure Credential Storage

API keys and tokens are stored via the OS keychain through Tauri's secure storage abstraction (`secure_storage.rs`). A random entropy file is used for key derivation. Credentials are never written to disk in plaintext.

### Proxy Rotation

The proxy pool (`proxy_pool.rs`) supports HTTP, HTTPS, and SOCKS5 proxies with configurable rotation strategies (round-robin, random). Health checking runs continuously, and proxies failing checks are automatically removed from the active pool.

### Audit Trail

All command executions are recorded in asciinema format via the PTY manager. Decision logs, agent reasoning traces, and tool invocations are captured for post-session review and training data collection.

---

## Technology Stack

### Backend (Rust)

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Desktop Runtime | Tauri 2.0 | Native packaging, IPC bridge, system integration |
| Async Runtime | Tokio | Concurrent operations |
| Cryptography | Ring | Secure key derivation and encryption |
| HTTP Client | Reqwest | Outbound requests with proxy support |
| Container API | Bollard | Docker/Podman sandbox management |
| PTY Management | portable-pty | Subprocess isolation with recording |
| Database | rusqlite | SQLite for structured knowledge storage |
| Error Handling | thiserror | Typed error hierarchies |
| Logging | tracing + tracing-subscriber | Structured application logging |

### Frontend (TypeScript / React)

| Component | Technology | Purpose |
|-----------|-----------|---------|
| UI Framework | React 19 | Component architecture |
| Language | TypeScript 5.8 (strict mode) | Type safety |
| Build Tool | Vite 7 | Development server and bundling |
| Styling | Tailwind CSS 4 | Utility-first dark theme |
| Terminal | xterm.js | Embedded terminal emulation |
| Charts | Recharts | Training dashboard metrics |
| Virtual Scrolling | react-virtuoso | Performance with large finding lists |
| Markdown | react-markdown | Report rendering |
| Testing | Vitest + Testing Library | Unit and integration tests |

### AI and Data

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Primary AI | Anthropic Claude (Opus, Sonnet, Haiku) | Orchestration and reasoning |
| Fallback AI | OpenAI, Google, OpenRouter, Ollama | Multi-provider support |
| Vector Database | Qdrant | Semantic search, duplicate detection, pattern memory |
| Fine-Tuning | Axolotl + LoRA | Local model improvement on Llama-3.1-70B |
| Browser Automation | Playwright | Headless validation of findings |
| OAuth/OIDC | openid-client | OAuth flow testing |

---

## Installation

### Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Operating System | Linux (Kali recommended) | macOS and Windows supported via Tauri |
| Node.js | 18+ | Required for frontend build |
| Rust | Latest stable | Required for backend compilation |
| Docker | 20+ | Required for Qdrant vector database |
| Python | 3.10+ | Required only for training pipeline |
| NVIDIA GPU | 24GB+ VRAM | Required only for local LoRA fine-tuning |

### Quick Start

```bash
# Clone the repository
git clone https://github.com/JBWolfFlow/Huntress.git
cd Huntress

# Run the automated setup script
chmod +x scripts/setup.sh
./scripts/setup.sh

# Install Node.js dependencies
npm install

# Start the Qdrant vector database
docker compose up -d

# Launch in development mode
npm run tauri dev
```

### Production Build

```bash
# Compile the production desktop binary
npm run tauri build
```

The compiled application binary will be located in `src-tauri/target/release/`. Platform-specific installers (`.deb`, `.AppImage`, `.dmg`, `.msi`) are generated in `src-tauri/target/release/bundle/`.

### Security Tool Installation

For full agent capabilities, install the security tooling suite:

```bash
chmod +x scripts/install_security_tools.sh
./scripts/install_security_tools.sh
```

This installs: nmap, sqlmap, gobuster, ffuf, nuclei, subfinder, httpx, and other tools used by the agent fleet.

---

## Configuration

### First-Run Setup

On first launch, Huntress presents a setup wizard that walks through:

1. **AI Model Selection** -- Choose the primary orchestrator model from a dropdown of supported providers
2. **API Key Entry** -- Provide the API key for the selected provider (stored in the OS keychain)
3. **Sub-Agent Configuration** -- Optionally assign different models to sub-agents, or accept cost-optimized defaults
4. **HackerOne Integration** -- Optionally provide a HackerOne API token for direct report submission

All settings persist across sessions and can be modified later through the Settings panel.

### Environment Variables

```bash
# AI Provider (at least one required)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GOOGLE_AI_API_KEY=...

# HackerOne Integration (optional)
HACKERONE_API_TOKEN=...

# Vector Database
QDRANT_URL=http://localhost:6333

# Training Pipeline (optional)
HTB_API_TOKEN=...
HUGGINGFACE_TOKEN=...
```

### Scope File Format

Huntress accepts HackerOne-format JSON scope definitions:

```json
{
  "targets": {
    "in_scope": [
      {
        "asset_identifier": "*.example.com",
        "asset_type": "URL",
        "eligible_for_bounty": true
      },
      {
        "asset_identifier": "api.example.com",
        "asset_type": "URL",
        "eligible_for_bounty": true
      }
    ],
    "out_of_scope": [
      {
        "asset_identifier": "admin.example.com",
        "asset_type": "URL"
      }
    ]
  }
}
```

Wildcard patterns, CIDR notation, IP ranges, and port specifications are fully supported.

### Docker Services

```bash
# Start all services
docker compose up -d

# Start with the testing target (OWASP Juice Shop)
docker compose --profile testing up -d
```

| Service | Port | Purpose |
|---------|------|---------|
| Qdrant (REST) | 6333 | Vector database API |
| Qdrant (gRPC) | 6334 | Vector database high-performance interface |
| Juice Shop | 3001 | Local testing target (testing profile only) |

---

## Usage

### Workflow

1. **Import a Bounty Program** -- Click "New Hunt" and provide a HackerOne program URL, upload a scope JSON file, or enter scope manually.

2. **Review the Briefing** -- The orchestrator analyzes the full program (scope, rules, asset types, bounty tables, exclusions) and presents a structured briefing with recommended attack strategies ranked by expected value.

3. **Select a Strategy** -- Choose from the orchestrator's recommendations or type a custom instruction in the chat interface. The orchestrator creates an execution plan and explains its approach.

4. **Monitor Execution** -- Sub-agents execute in parallel. The Agent Status panel shows real-time progress. The chat interface displays findings, agent reasoning, and status updates as they occur.

5. **Approve Commands** -- Active testing commands trigger approval modals showing the exact command, requesting agent, target, and justification. Approve, deny, or modify before execution.

6. **Review Findings** -- Discovered vulnerabilities appear in the Findings panel with severity ratings and duplicate status. Drill into any finding for details or request deeper testing.

7. **Submit Reports** -- For confirmed vulnerabilities, the orchestrator generates a professional PoC report. Review in the Report Editor, edit if needed, and submit directly to HackerOne.

### Chat Interface

The chat interface is the primary interaction surface. Beyond natural language conversation, it supports:

- **Strategy option cards** -- Clickable recommendations from the orchestrator
- **Finding cards** -- Structured vulnerability displays with severity badges
- **Approval modals** -- Inline command approval with full context
- **Code blocks** -- Syntax-highlighted request/response data
- **Report previews** -- Formatted vulnerability reports before submission

### Terminal View

For users who want visibility into raw command execution, the embedded terminal (xterm.js) displays PTY output in real time.

---

## Training Pipeline

Huntress includes a continuous learning system that improves agent performance over time through automated training on HackTheBox machines.

### Pipeline Stages

1. **Data Collection** -- The HTB runner (`scripts/htb_runner.py`) automates hunting sessions against HackTheBox machines, capturing reasoning traces, tool invocations, and outcomes.

2. **Data Sanitization** -- Training data passes through `scripts/format_training_data.py`, which strips API keys, tokens, PII, and target-specific information before storage.

3. **LoRA Fine-Tuning** -- Axolotl trains a LoRA adapter on Llama-3.1-70B using the sanitized dataset. Training runs locally with zero data leaving the machine.

4. **A/B Validation** -- The new model version is evaluated against the current baseline using the A/B testing framework. Deployment proceeds only if the new version demonstrates statistically significant improvement.

5. **Gradual Deployment** -- The deployment manager rolls out the new model incrementally, monitoring performance metrics at each stage. Automatic rollback triggers if degradation is detected.

```bash
# Run an automated HTB training session
python scripts/htb_runner.py --difficulty easy --count 5

# Sanitize and format training data
python scripts/format_training_data.py

# Configure and run LoRA fine-tuning
./scripts/setup_axolotl.sh
axolotl train config/axolotl_config.yml

# Deploy with gradual rollout
./scripts/deploy_production.sh --strategy gradual
```

---

## Development

### Build Commands

```bash
# Development server with hot reload
npm run tauri dev

# TypeScript type checking
npm run lint

# Production build
npm run tauri build
```

### Code Quality

```bash
# Rust
cd src-tauri && cargo clippy -- -D warnings && cargo fmt

# TypeScript
npm run lint
```

### Coding Standards

**Rust (`src-tauri/src/`)**
- `thiserror` for typed error hierarchies; `anyhow` only at binary entry points
- Exhaustive pattern matching on enums -- no wildcard `_` on enums that may grow
- `Arc<Mutex<T>>` for shared state with minimal lock duration
- `tracing` crate for structured logging
- All Tauri commands validate inputs before processing

**TypeScript (`src/`)**
- Strict mode with no implicit `any`
- Interfaces over type aliases for extensible object shapes
- `async/await` exclusively; no raw Promise chains
- Functional React components with hooks only
- All Tauri `invoke()` calls have typed command/response pairs

**Command Execution**
- Commands use null-byte-joined argv arrays: `['cmd', 'arg1', 'arg2'].join('\x00')`
- Never use template literals or string interpolation for shell commands
- All commands pass through scope validation and the approval pipeline

---

## Testing

### Test Suite

```bash
# Run all TypeScript unit tests
npm test

# Run tests in watch mode
npm run test:watch

# Run with coverage reporting
npm run test:coverage

# Run integration tests (requires running services)
npm run test:live

# Run Rust backend tests
cd src-tauri && cargo test
```

### Coverage

- **TypeScript**: 1,061+ tests across 27 test files covering agents, orchestration, providers, training, HTTP engine, knowledge integration, and end-to-end flows
- **Rust**: 68 tests covering scope validation, kill switch, proxy pool, secure storage, PTY management, and sandbox isolation

### Test Categories

| Category | Scope | Configuration |
|----------|-------|---------------|
| Unit | Individual module behavior | `vitest.config.ts` (30s timeout) |
| Integration | Cross-module and service interactions | `vitest.integration.config.ts` (120s timeout) |
| Agent Fleet | All 29 agents initialize and execute correctly | `agent_fleet.test.ts` |
| Security | Scope validation, kill switch, approval pipeline deny paths | Multiple test files |
| Provider | API key validation, streaming, error handling, fallback | `provider_fallback.test.ts` |

---

## Project Structure

```
huntress/
|-- src/                            # Frontend (React / TypeScript)
|   |-- agents/                     # 29 vulnerability hunting agents
|   |   |-- oauth/                  # OAuth 2.0 sub-modules (4 files)
|   |   |-- base_agent.ts           # Abstract base class
|   |   |-- agent_catalog.ts        # Registry and discovery
|   |   |-- agent_router.ts         # Agent selection and dispatch
|   |   |-- standardized_agents.ts  # Self-registration trigger
|   |   +-- [25 hunter modules]
|   |-- components/                 # 19 React UI components
|   |   |-- ChatInterface.tsx       # Primary interaction surface
|   |   |-- ApproveDenyModal.tsx    # Human approval gate
|   |   |-- ReportEditor.tsx        # PoC report editor
|   |   |-- AgentStatusPanel.tsx    # Real-time agent monitoring
|   |   +-- [15 more components]
|   |-- core/                       # Business logic (20 subdirectories)
|   |   |-- orchestrator/           # Coordinator engine, chain detection, dedup
|   |   |-- engine/                 # ReAct loop, tool schemas, safety policies
|   |   |-- providers/              # AI model provider abstraction
|   |   |-- reporting/              # PoC generation, H1 API, duplicate detection
|   |   |-- training/               # Learning loop, A/B testing, deployment
|   |   |-- discovery/              # Attack surface mapping, crawling
|   |   |-- validation/             # OOB server, headless browser verification
|   |   |-- http/                   # Request engine, rate control, WebSocket
|   |   |-- memory/                 # Qdrant integration, hunt history
|   |   |-- fuzzer/                 # Parameter fuzzing, payload database
|   |   |-- evasion/                # WAF detection, payload encoding
|   |   |-- knowledge/              # Vulnerability knowledge graph
|   |   |-- tools/                  # Tool registry, sandbox, health checks
|   |   |-- tracing/                # Cost tracking, LLM observability
|   |   +-- [6 more modules]
|   |-- contexts/                   # React context providers
|   |-- hooks/                      # Custom React hooks
|   +-- tests/                      # 27 test files
|-- src-tauri/                      # Backend (Rust / Tauri 2.0)
|   +-- src/
|       |-- lib.rs                  # Module integration, 50+ Tauri commands
|       |-- safe_to_test.rs         # Scope validation engine (1,235 LOC)
|       |-- pty_manager.rs          # Secure subprocess execution
|       |-- kill_switch.rs          # Emergency shutdown with persistence
|       |-- proxy_pool.rs           # HTTP/HTTPS/SOCKS5 proxy rotation
|       |-- secure_storage.rs       # OS keychain credential storage
|       |-- sandbox.rs              # Docker/Podman container isolation
|       |-- h1_api.rs               # HackerOne API integration
|       +-- tool_checker.rs         # Security tool availability checks
|-- scripts/                        # Automation and deployment
|   |-- setup.sh                    # Installation script
|   |-- install_security_tools.sh   # Security tool installer
|   |-- htb_runner.py               # HackTheBox training automation
|   |-- format_training_data.py     # Training data sanitization
|   |-- setup_axolotl.sh            # LoRA training configuration
|   +-- deploy_production.sh        # Gradual model deployment
|-- config/                         # Environment and runtime configuration
|-- docker-compose.yml              # Qdrant and testing services
|-- package.json                    # Node.js dependencies and scripts
|-- vite.config.ts                  # Vite build configuration
|-- tailwind.config.js              # TailwindCSS theme
|-- vitest.config.ts                # Unit test configuration
+-- vitest.integration.config.ts    # Integration test configuration
```

### Codebase Metrics

| Metric | Value |
|--------|-------|
| TypeScript/TSX source files | 214 |
| TypeScript LOC (approximate) | 88,700 |
| Rust source files | 10 |
| Rust LOC | 5,950 |
| Hunting agents | 29 |
| React components | 19 |
| Core modules | 20 subdirectories |
| Test files | 27 |
| TypeScript tests | 1,061+ |
| Rust tests | 68 |
| Tauri IPC commands | 50+ |

---

## Disclaimer

Huntress is designed exclusively for authorized security testing. This includes participation in bug bounty programs with explicit authorization, penetration testing engagements with written scope agreements, security research on systems you own or have permission to test, and educational use in controlled environments.

Users are solely responsible for ensuring they have proper authorization before testing any target. Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent legislation in other jurisdictions. The authors and contributors assume no liability for misuse of this software.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [Tauri](https://tauri.app/) -- Desktop application framework
- [Anthropic](https://www.anthropic.com/) -- Claude AI models
- [Qdrant](https://qdrant.tech/) -- Vector database
- [Meta AI](https://ai.meta.com/) -- Llama open-weight models
- [Axolotl](https://github.com/OpenAccess-AI-Collective/axolotl) -- LoRA fine-tuning framework
- [HackerOne](https://www.hackerone.com/) -- Bug bounty platform and API
- [HackTheBox](https://www.hackthebox.com/) -- Training platform

---

Built by [NeuroForge Technologies](https://github.com/JBWolfFlow).

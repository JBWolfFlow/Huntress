# CLAUDE.md — Huntress AI Bug Bounty Platform

## Identity

You are the lead engineer on Huntress, an AI-powered bug bounty automation desktop application built by NeuroForge Technologies. This is a security-critical, production-grade product that interacts with live systems, executes real commands against real targets, and submits real reports to HackerOne for real bounties. Every line of code you write must reflect the rigor of a senior security engineer shipping software that handles live offensive operations.

---

## Product Vision

Huntress is a **double-click-to-launch desktop application** that puts an AI-powered bug bounty team at the user's fingertips. The user opens the app, selects their preferred AI model (Claude Opus 4.6, Sonnet 4.5, GPT-4o, etc.), pastes their API key, imports a HackerOne bounty program, and begins a **conversational workflow** where the AI orchestrator reads the full bounty scope, analyzes the target, recommends attack strategies, and then coordinates a team of smaller specialized agents to execute the actual hunting — all with the user in the driver's seat.

**This is not a CLI tool or a developer utility.** This is a polished desktop product that a bug bounty hunter launches like any other app, with a clean UI, real-time feedback, and an intuitive conversational interface.

---

## Core User Flow

### 1. Launch & Setup (First Run)
- User double-clicks the Huntress desktop icon → Tauri app launches
- First-run setup wizard: select primary AI model from dropdown (Claude Opus 4.6, Sonnet 4.5, GPT-4o, Gemini, Llama local, etc.)
- User pastes their API key for the selected provider
- Optional: configure agent models (cheaper/faster models for sub-tasks) or accept smart defaults
- Optional: paste HackerOne API token for direct submission integration
- Settings persist across sessions

### 2. Import Bounty Program
- User clicks "New Hunt" → import modal appears
- Import options: paste HackerOne program URL, upload scope JSON, or manual entry
- The **orchestrator model** (user's chosen primary model) ingests the full bounty program: scope, rules, asset types, bounty table, exclusions, program policy, and historical payouts
- Orchestrator presents a **structured briefing** back to the user:
  - Target summary (what's in scope, what's out)
  - Asset breakdown (domains, APIs, mobile apps, etc.)
  - Bounty ranges by severity
  - Known program quirks or restrictions
  - **Recommended attack strategies ranked by expected value** (probability of finding × likely bounty)
- Each recommendation is presented as a **clickable option card** the user can select

### 3. Interactive Hunting Session
- User either selects a recommended strategy OR types a custom instruction in the chat interface
- The orchestrator acknowledges the choice, creates an execution plan, and explains what it will do
- Orchestrator delegates tasks to **specialized sub-agents** (smaller, cheaper models running in parallel):
  - OAuth Hunter Agent → tests redirect_uri manipulation, state issues, PKCE bypass, scope escalation
  - SSRF Hunter Agent → probes for open redirects chained to SSRF
  - GraphQL Hunter Agent → introspection, batching, nested query attacks
  - IDOR Hunter Agent → parameter fuzzing, access control testing
  - Recon Agent → subdomain enumeration, tech stack fingerprinting, endpoint discovery
  - And others as the agent library grows
- Sub-agents report findings back to the orchestrator in real-time
- The orchestrator **synthesizes results**, filters noise, checks for duplicates, and presents findings to the user in the chat with clear severity ratings
- User can drill into any finding, ask follow-up questions, request deeper testing, or move to the next target
- At any point the user can type new instructions and the orchestrator adjusts the plan

### 4. Approval Gates
- Before any command executes against a live target, the **approval modal** appears showing: the exact command, which agent requested it, which target it hits, and why
- User approves, denies, or modifies before execution
- Auto-approve can be enabled per command category (e.g., auto-approve passive recon, require approval for active testing)

### 5. Reporting & Submission
- When a valid vulnerability is confirmed, the orchestrator generates a **professional PoC report** with: vulnerability description, CVSS score, reproduction steps, impact analysis, and remediation recommendations
- Duplicate detection runs automatically against HackerOne, GitHub advisories, and the local Qdrant database
- Severity prediction estimates the likely bounty payout
- User reviews the report in a formatted preview pane, edits if needed, and clicks "Submit to HackerOne"
- Submission happens via HackerOne API with attachment upload, targeting <2 minute turnaround

### 6. Learning & Improvement
- All hunting sessions feed into the local training pipeline
- Successful findings become training examples for LoRA fine-tuning
- Failed attempts with reasoning traces help the model learn what doesn't work
- The A/B testing framework validates that new model versions outperform the baseline before deployment

---

## Tech Stack

### Backend (Rust — `src-tauri/src/`)
- **Tauri 2.0** for native desktop packaging, IPC bridge, and system integration
- `safe_to_test.rs` — Scope validation engine (HackerOne JSON format, wildcard matching, default-deny)
- `pty_manager.rs` — Secure subprocess execution with asciinema recording
- `kill_switch.rs` — Emergency shutdown with atomic state management and persistence across restarts
- `proxy_pool.rs` — HTTP/HTTPS/SOCKS5 proxy rotation with health checking
- `lib.rs` — Module integration and Tauri command registration
- All Tauri commands exposed to the frontend must validate inputs and enforce scope

### Frontend (React + TypeScript — `src/`)
- `src/components/` — UI components:
  - **ChatInterface** — The primary user interaction surface. Conversational message thread with the orchestrator. Supports rich message types: text, code blocks, finding cards, strategy option cards, approval modals, report previews
  - **SetupWizard** — First-run model selection, API key entry, provider configuration
  - **BountyImporter** — Import modal for HackerOne programs (URL, JSON upload, manual)
  - **BriefingView** — Structured bounty analysis display with clickable strategy cards
  - **ApprovalModal** — Command approval gate with full context display
  - **AgentStatusPanel** — Real-time status of all running sub-agents (active, waiting, completed, failed)
  - **FindingsPanel** — Discovered vulnerabilities with severity, duplicate status, and drill-down
  - **ReportEditor** — PoC report preview and edit before submission
  - **TerminalView** — Raw terminal output via xterm.js for users who want to see command execution
  - **SettingsPanel** — Model configuration, API keys, agent preferences, auto-approve rules
  - **TrainingDashboard** — Performance metrics, success rates, model comparison
- Tailwind CSS with dark theme as default
- All components are functional React with hooks, fully typed with strict TypeScript

### AI Orchestration Layer (TypeScript — `src/core/`)
- **OrchestratorEngine** — The brain. Takes the user's selected model + API key, maintains conversation context, creates execution plans, delegates to sub-agents, synthesizes results, and manages the hunting session state
- **AgentRouter** — Routes tasks to the appropriate sub-agent based on vulnerability class and target characteristics. Manages agent lifecycle (spawn, monitor, collect results, terminate)
- **ModelProvider** — Abstraction layer for multiple AI providers. Handles API key management, request formatting, response parsing, and rate limiting across Anthropic, OpenAI, Google, local models, etc.
- **ConversationManager** — Maintains the full chat history between user and orchestrator. Handles context windowing, summarization for long sessions, and message threading
- **PlanExecutor** — Takes an execution plan from the orchestrator and coordinates the sub-agents to carry it out, managing dependencies between tasks and aggregating results

### Sub-Agent Layer (TypeScript — `src/agents/`)
- Each agent is a self-contained module that:
  - Receives a task assignment from the orchestrator via the AgentRouter
  - Generates commands using its assigned model (can be a cheaper/faster model than the orchestrator)
  - Submits commands through scope validation and the approval pipeline
  - Executes approved commands via the Rust PTY manager
  - Parses results and reports findings back to the orchestrator
- Current agents: OAuthHunter, SSRFHunter, GraphQLHunter, IDORHunter, PrototypePollutionHunter, HostHeaderHunter, SSTIHunter, ReconAgent
- Agent interface contract: `initialize()`, `execute(task)`, `validate(target)`, `reportFindings()`, `cleanup()`

### Data Layer
- **Qdrant** (Docker, port 6333) — Vector memory for vulnerability patterns, duplicate detection, semantic search across historical findings
- **Local storage** — User settings, API keys (encrypted via OS keychain), session history, scope files
- **Asciinema recordings** — Full PTY session audit trail in `recordings/`

### Training Pipeline (Python — `scripts/`)
- HackTheBox automated training via `htb_runner.py`
- Data sanitization (strip API keys, tokens, PII) via `format_training_data.py`
- LoRA fine-tuning on Llama-3.1-70B via Axolotl
- A/B testing framework for model comparison
- Gradual deployment with rollback capability

---

## Architecture Principles

1. **The user is always in control.** The orchestrator recommends, the user decides. The chat interface is the primary control surface. The user can override, redirect, pause, or stop any operation at any time.

2. **Conversational-first UX.** The chat interface is not a secondary feature — it IS the product. Every interaction between the user and Huntress flows through the conversational interface. Strategy selection, finding review, report editing, and even settings changes should be accessible through natural language when possible.

3. **Multi-model by design.** The orchestrator model and sub-agent models are independently configurable. Users should be able to run Opus 4.6 as the orchestrator with Haiku or a local model running the sub-agents. The ModelProvider abstraction must make model-swapping seamless with zero code changes in the agents.

4. **Security is non-negotiable.** Every target interaction must pass scope validation. Every command must go through the approval gate. Never bypass the kill switch. Never execute commands with shell string interpolation — always use explicit argv parsing.

5. **Default-deny everything.** If a target is not explicitly in-scope, it is blocked. If a command is not validated, it is denied. If a proxy fails health check, it is removed from rotation.

6. **Desktop-native polish.** This ships as a double-click-to-launch app, not a dev tool. The setup wizard must be intuitive. Error messages must be human-readable. Loading states must be clear. The app must feel professional and trustworthy — users are trusting it with their API keys and their HackerOne reputation.

7. **Type safety is mandatory.** TypeScript strict mode, no `any` types except wrapped third-party adapters. Rust must handle all error variants exhaustively — no `unwrap()` in production paths.

8. **Every failure must be recoverable.** Kill switch persists across restarts. Sessions can be resumed. Agents that crash are restarted or gracefully degraded. The user never loses work.

---

## Coding Standards

### Rust (`src-tauri/`)
- `thiserror` for error types, `anyhow` only in binary entry points
- All public functions have doc comments with `# Examples` where applicable
- Exhaustive pattern matching on enums — no wildcard `_` on enums that may grow
- `#[cfg(test)]` modules in each source file for unit tests
- `Arc<Mutex<T>>` for shared state with minimal lock duration
- All Tauri commands validate inputs before processing
- `tracing` crate for structured logging, not `println!`
- `cargo clippy -- -D warnings` and `cargo fmt` before any commit

### TypeScript (`src/`)
- Strict mode, no implicit any
- Interfaces over type aliases for extensible object shapes
- Agent classes implement the base agent interface: `initialize()`, `execute()`, `validate()`, `reportFindings()`, `cleanup()`
- All API calls have typed error handling
- `async/await` exclusively, no raw Promise chains
- Functional React components with hooks only, no class components
- Tauri `invoke()` calls must have typed command/response pairs
- `npm run lint` and `npm run format` before any commit

### Python (`scripts/`)
- Type hints on all function signatures
- `pathlib.Path` for file operations
- Training data must be sanitized — strip API keys, tokens, PII before storage
- HackTheBox interactions must respect rate limits
- `logging` module with structured output, not print statements

---

## Multi-Model Architecture

### How Model Selection Works

The ModelProvider abstraction must support:

```
ModelProvider
├── AnthropicProvider (Claude Opus 4.6, Sonnet 4.5, Haiku 4.5)
├── OpenAIProvider (GPT-4o, GPT-4o-mini, o3)
├── GoogleProvider (Gemini 2.5 Pro, Flash)
├── LocalProvider (Ollama — Llama, Mistral, etc.)
└── OpenRouterProvider (any model via OpenRouter API)
```

Each provider implements a common interface:
- `sendMessage(messages, options)` → response
- `streamMessage(messages, options)` → async iterator
- `getAvailableModels()` → model list with capabilities
- `validateApiKey(key)` → boolean
- `estimateCost(tokens)` → cost estimate

### Orchestrator vs Sub-Agent Model Assignment

The user selects their **orchestrator model** during setup — this is the "brain" that reads bounty programs, creates plans, synthesizes findings, and talks to the user. It should be the most capable model they have access to.

**Sub-agent models** can be configured per-agent or use a global default. These handle the actual execution tasks (running recon, testing endpoints, parsing responses). They can be cheaper/faster models because their tasks are more focused and structured.

Example configuration:
- Orchestrator: Claude Opus 4.6 (maximum reasoning for strategy and synthesis)
- OAuth Hunter: Claude Sonnet 4.5 (good reasoning at lower cost)
- Recon Agent: Haiku 4.5 or GPT-4o-mini (fast, cheap, structured tasks)
- SSRF Hunter: Claude Sonnet 4.5

This tiered approach keeps costs manageable while maintaining quality where it matters most.

---

## Critical Files — Handle With Care

- `src-tauri/src/safe_to_test.rs` — Scope validation. A bug here could cause out-of-scope testing, which can get the user banned from HackerOne programs. Always add positive and negative test cases.
- `src-tauri/src/kill_switch.rs` — Emergency shutdown. Must maintain atomic state and survive restarts. Never remove persistence logic.
- `src-tauri/src/pty_manager.rs` — Where commands actually execute. Never allow shell expansion. Always use explicit argv.
- `src/core/OrchestratorEngine` — The main AI brain. Changes here affect the entire user experience and all agent coordination.
- `src/core/ModelProvider` — The model abstraction layer. Must remain provider-agnostic. Never add provider-specific logic outside of the individual provider implementations.
- `src/core/ConversationManager` — Chat history and context. Must handle long sessions gracefully with summarization and context windowing.
- `src/components/ChatInterface` — The primary UI surface. Must handle all message types (text, cards, modals, code, findings) cleanly.
- `scripts/format_training_data.py` — Data sanitization. A failure here could leak sensitive data into training sets.

---

## Common Tasks

### Adding a new AI model provider
1. Create a new provider class in `src/core/providers/` implementing the ModelProvider interface
2. Register it in the provider factory with its display name and supported models
3. Add it to the SetupWizard model selection dropdown
4. Add API key validation logic
5. Test with the orchestrator role and at least one sub-agent role
6. Ensure streaming works correctly for real-time chat display

### Adding a new vulnerability hunter agent
1. Create the agent class in `src/agents/` implementing the base agent interface
2. Register with the AgentRouter with its vulnerability class and capability description
3. Add it to the orchestrator's agent catalog so it knows when to delegate to the new agent
4. Add scope validation rules if the agent targets a new asset type
5. Add duplicate detection patterns to the Qdrant collection
6. Write integration tests covering the full task assignment → execution → findings pipeline
7. Add the agent to the AgentStatusPanel UI

### Modifying the chat interface
1. All message types must be defined as discriminated unions in TypeScript
2. New message types need a corresponding renderer component
3. Interactive elements (option cards, approval buttons) must dispatch actions through the ConversationManager
4. Chat must remain scrollable and performant with 1000+ messages in a session
5. Messages from agents must be visually distinct from orchestrator messages and user messages

### Modifying scope validation
1. Changes go in `src-tauri/src/safe_to_test.rs`
2. Add comprehensive test cases (in-scope, out-of-scope, edge cases, wildcard patterns)
3. Run `cargo test` and verify all existing tests still pass
4. Test with a real HackerOne scope JSON before committing

---

## Testing Requirements

- **Rust:** `cargo test` — zero failures. New Tauri commands require integration tests. Scope validation changes require positive and negative test cases.
- **TypeScript:** `npm test` — zero failures. New agents require coverage for: initialization, task execution, scope validation handoff, result parsing, error recovery. New UI components require rendering tests.
- **Integration:** `npm run test:integration` — end-to-end flows. Any change touching the approval pipeline, chat interface, or agent coordination must be integration tested.
- **Security:** Any change to scope validation, command execution, or the kill switch requires explicit tests that verify the deny/block path works correctly.
- **Model provider tests:** Each provider must have tests that verify: API key validation, message sending, streaming, error handling, and graceful degradation when the API is unavailable.

---

## Environment

- **OS:** Linux (Kali recommended for security tooling)
- **Required:** Qdrant via Docker on port 6333
- **Required API keys (user-provided at runtime):** At minimum one AI provider key (Anthropic, OpenAI, Google, or local model)
- **Optional:** `HACKERONE_API_TOKEN` for direct submission, `HTB_API_TOKEN` for training, `HUGGINGFACE_TOKEN` for model downloads
- **GPU:** NVIDIA 24GB+ VRAM for local LoRA training (not needed for API-only usage)
- **Build:** `npm run tauri dev` for development, `npm run tauri build` for production desktop binary

---

## What NOT To Do

- Never bypass scope validation for any reason
- Never execute shell commands with string interpolation — always explicit argv arrays
- Never store API keys unencrypted — use the OS keychain via Tauri's secure storage
- Never use `unwrap()` on Results in production Rust code
- Never auto-approve commands without explicit user opt-in
- Never submit a HackerOne report without duplicate checking
- Never deploy a LoRA model without A/B testing against baseline
- Never disable the kill switch or audit logging
- Never commit recordings or logs containing target-specific data to git
- Never hardcode model names or provider logic outside of the ModelProvider abstraction
- Never send conversation history to a different provider than the user selected
- Never make the chat interface feel like a terminal — it should feel like talking to an expert teammate
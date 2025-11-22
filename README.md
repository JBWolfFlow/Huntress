# HUNTRESS

**Bug Bounty Automation Suite for Kali Linux**

A closed-source, solo-use desktop application built with Tauri 2.0, React 19, and TypeScript for automating bug bounty reconnaissance and vulnerability discovery.

## ⚠️ Legal Notice

This tool is designed for **authorized security testing only**. Use only on programs where you have explicit permission to test. Unauthorized testing is illegal and unethical.

## 🏗️ Architecture

### Technology Stack

- **Frontend**: React 19 + TypeScript + Tailwind CSS
- **Backend**: Rust (Tauri 2.0)
- **AI**: Claude (Anthropic) for supervision and decision-making
- **Vector DB**: Qdrant for semantic search and duplicate detection
- **Terminal**: xterm.js for tool output display

### Project Structure

```
huntress/
├── src/                          # React + TypeScript frontend
│   ├── agents/                   # Mini-agent modules
│   │   ├── open_redirect.ts      # Open redirect hunter
│   │   ├── oauth_hunter.ts       # OAuth misconfiguration hunter
│   │   ├── graphql_hunter.ts     # GraphQL vulnerability hunter
│   │   ├── idor_hunter.ts        # IDOR hunter
│   │   ├── prototype_pollution.ts # Prototype pollution hunter
│   │   ├── host_header.ts        # Host header injection hunter
│   │   └── ssti_hunter.ts        # SSTI hunter
│   ├── components/               # React components
│   │   ├── Terminal.tsx          # xterm.js terminal component
│   │   ├── ApproveDenyModal.tsx  # Human approval modal
│   │   └── ScopeImporter.tsx     # Scope import component
│   ├── core/                     # Core functionality
│   │   ├── crewai/              # AI supervisor integration
│   │   │   ├── supervisor.ts     # Claude-powered supervisor
│   │   │   └── human_task.ts     # Human approval system
│   │   ├── memory/              # Vector storage
│   │   │   ├── qdrant_client.ts  # Qdrant integration
│   │   │   └── summarizer.ts     # Finding summarization
│   │   ├── reporting/           # Report generation
│   │   │   ├── h1_api.ts        # HackerOne API client
│   │   │   ├── poc_generator.ts  # PoC generation
│   │   │   └── templates.ts      # Report templates
│   │   └── tools/               # LangChain tools
│   │       └── tool_registry.ts  # Tool registration
│   ├── plugins/                 # Future plugin system
│   └── utils/                   # Utilities
│       ├── rate_limiter.ts      # Rate limiting
│       ├── proxy_manager.ts     # Proxy rotation
│       └── duplicate_checker.ts  # Duplicate detection
├── src-tauri/                   # Rust backend
│   └── src/
│       ├── main.rs              # Entry point
│       ├── lib.rs               # Library exports
│       ├── safe_to_test.rs      # Scope validation + DNS/HTTP gate
│       ├── pty_manager.rs       # PTY spawning + management
│       ├── kill_switch.rs       # Emergency shutdown
│       └── proxy_pool.rs        # Proxy rotation + health check
├── recordings/                  # Auto-saved terminal recordings
├── backups/                     # Encrypted daily backups
└── config/                      # Configuration files
    └── .env.example             # Environment template
```

## 🎯 Core Features

### 1. AI-Powered Supervision
- Claude-based supervisor coordinates testing strategy
- Makes intelligent decisions about test prioritization
- Requires human approval for critical operations

### 2. Scope Validation
- Strict scope checking before any request
- DNS/HTTP gate prevents out-of-scope testing
- Automatic scope import from HackerOne

### 3. Mini-Agent System
- Specialized agents for different vulnerability types
- Each agent focuses on specific attack patterns
- Extensible plugin architecture for custom agents

### 4. Safety Features
- **Kill Switch**: Emergency shutdown of all operations
- **Rate Limiting**: Prevents overwhelming targets
- **Proxy Rotation**: Distributes requests across IPs
- **Duplicate Detection**: Semantic similarity checking

### 5. Memory & Context
- Qdrant vector database for findings storage
- Semantic search for similar vulnerabilities
- Historical context for better decision-making

### 6. Professional Reporting
- HackerOne API integration
- Automated PoC generation
- Professional report templates
- Screenshot and recording capture

## 🚀 Getting Started

### Prerequisites

- Node.js 18+ and npm
- Rust 1.70+
- Kali Linux (recommended)

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   cd huntress
   npm install
   ```

3. Configure environment:
   ```bash
   cp config/.env.example config/.env
   # Edit config/.env with your API keys
   ```

4. Build and run:
   ```bash
   npm run tauri dev
   ```

### Configuration

Edit `config/.env` with your credentials:

- `ANTHROPIC_API_KEY`: Claude API key for AI supervision
- `QDRANT_URL`: Qdrant vector database URL
- `HACKERONE_API_KEY`: HackerOne API credentials
- `PROXY_LIST_PATH`: Path to proxy list file

## 🔒 Security

### Data Protection
- All sensitive data encrypted at rest
- API keys never committed to git
- Recordings and backups excluded from version control

### Scope Safety
- Mandatory scope validation before any test
- DNS resolution verification
- HTTP connectivity checks
- Out-of-scope requests blocked automatically

### Human Oversight
- Critical operations require human approval
- Emergency kill switch always available
- All actions logged for audit trail

## 📋 Workflow

1. **Import Scope**: Load target scope from HackerOne or manual entry
2. **AI Analysis**: Supervisor analyzes target and creates strategy
3. **Agent Execution**: Mini-agents perform specialized tests
4. **Human Review**: Critical findings require approval
5. **Report Generation**: Automated PoC and report creation
6. **Submission**: Direct submission to HackerOne

## 🛠️ Development

### Adding New Agents

Create a new agent in `src/agents/`:

```typescript
export class MyAgent {
  async test(target: string): Promise<Result[]> {
    // Implement testing logic
  }

  generatePoC(result: Result): string {
    // Generate proof of concept
  }
}
```

### Building for Production

```bash
npm run tauri build
```

## 📝 License

Closed-source. All rights reserved.

## ⚖️ Responsible Disclosure

This tool is designed to support responsible vulnerability disclosure. Always:
- Test only on authorized programs
- Respect scope boundaries
- Follow program rules
- Report findings responsibly
- Never exploit vulnerabilities maliciously

## 🙏 Acknowledgments

Built with:
- [Tauri](https://tauri.app/) - Desktop application framework
- [React](https://react.dev/) - UI framework
- [Anthropic Claude](https://www.anthropic.com/) - AI supervision
- [Qdrant](https://qdrant.tech/) - Vector database
- [xterm.js](https://xtermjs.org/) - Terminal emulation

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.

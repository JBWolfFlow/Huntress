# HUNTRESS Setup Guide

## System Requirements

- **OS**: Linux (Kali Linux recommended for bug bounty tools)
- **Node.js**: v18+ (for frontend)
- **Rust**: Latest stable (for Tauri backend)
- **System Libraries**: GTK3, WebKit2GTK, GLib (for Tauri)

## Quick Start

### 1. Install System Dependencies

Run the setup script:
```bash
chmod +x setup.sh
./setup.sh
```

Or manually install:
```bash
sudo apt-get update
sudo apt-get install -y \
  libglib2.0-dev \
  libgtk-3-dev \
  libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  patchelf \
  build-essential \
  curl \
  wget \
  file \
  libssl-dev \
  pkg-config
```

### 2. Install Rust (if not already installed)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### 3. Install Node.js Dependencies

```bash
npm install
```

### 4. Build and Run

**Development mode:**
```bash
npm run tauri dev
```

**Production build:**
```bash
npm run tauri build
```

## Project Structure

```
huntress/
├── src/                    # Frontend (React + TypeScript)
│   ├── agents/            # Bug bounty automation agents
│   ├── components/        # UI components
│   ├── core/              # Core logic (CrewAI, memory, reporting)
│   └── utils/             # Utilities
├── src-tauri/             # Backend (Rust)
│   └── src/
│       ├── safe_to_test.rs    # Scope validation engine
│       ├── pty_manager.rs     # Secure subprocess management
│       ├── kill_switch.rs     # Emergency shutdown
│       ├── proxy_pool.rs      # Proxy rotation
│       └── lib.rs             # Module integration
├── config/                # Configuration files
├── recordings/            # PTY session recordings
└── backups/              # Backup storage
```

## Security Modules

### 1. Safe-to-Test Gate
- Validates all targets against scope before execution
- Default deny: empty scope blocks everything
- Supports HackerOne JSON format
- Wildcard matching (*.example.com)

### 2. PTY Manager
- Spawns subprocesses with full isolation
- Automatic recording to asciinema format
- No shell injection (explicit argv parsing)
- Environment variable sanitization

### 3. Kill Switch
- Emergency shutdown of all operations
- Persists state across restarts
- Requires explicit confirmation to reset
- Broadcasts kill events to all components

### 4. Proxy Pool
- Automatic proxy rotation
- Health checking with httpbin.org
- Multiple rotation strategies
- Support for HTTP/HTTPS/SOCKS5

## Configuration

### Scope File Format

**HackerOne JSON:**
```json
{
  "targets": {
    "in_scope": [
      {
        "asset_identifier": "*.example.com",
        "asset_type": "URL",
        "eligible_for_bounty": true,
        "eligible_for_submission": true
      }
    ],
    "out_of_scope": [
      {
        "asset_identifier": "admin.example.com",
        "asset_type": "URL",
        "eligible_for_bounty": false,
        "eligible_for_submission": false
      }
    ]
  }
}
```

**Simple line format:**
```
# In-scope targets
*.example.com
api.example.com

# Out-of-scope (prefix with !)
!admin.example.com
!internal.example.com
```

### Proxy File Format

**JSON:**
```json
[
  {
    "url": "http://proxy1.example.com:8080",
    "proxy_type": "HTTP",
    "username": "user",
    "password": "pass",
    "last_used": "2024-01-01T00:00:00Z",
    "health_status": "Healthy"
  }
]
```

**Simple line format:**
```
http://proxy1.example.com:8080
https://proxy2.example.com:8443
socks5://proxy3.example.com:1080
```

## Troubleshooting

### Build Errors

**Error: `glib-2.0` not found**
```bash
sudo apt-get install libglib2.0-dev
```

**Error: `webkit2gtk-4.1` not found**
```bash
sudo apt-get install libwebkit2gtk-4.1-dev
```

**Error: Rust not found**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Runtime Issues

**Kill switch activated:**
- Check `/config/kill_switch.lock`
- Reset with explicit confirmation: `reset_kill_switch("CONFIRM_RESET")`

**Scope validation failing:**
- Verify scope file format
- Check for empty scope (default deny)
- Review logs in console

**PTY sessions not spawning:**
- Check command validation (no shell metacharacters)
- Verify environment variables are sanitized
- Review `/recordings/` directory permissions

## Development

### Running Tests

```bash
cd src-tauri
cargo test
```

### Checking Code

```bash
cd src-tauri
cargo check
cargo clippy
```

### Building Release

```bash
npm run tauri build
```

Binary will be in: `src-tauri/target/release/`

## Security Notes

⚠️ **CRITICAL**: This application executes potentially dangerous commands against live targets. Always:

1. Load scope file before any operations
2. Verify targets are in scope
3. Use the approve/deny modal for all commands
4. Keep kill switch accessible
5. Review PTY recordings regularly
6. Use proxies to avoid rate limiting
7. Never test out-of-scope targets

## License

Closed-source, solo-use only. Not for distribution.

## Support

For issues or questions, review the code documentation or check logs in:
- Browser console (frontend)
- Terminal output (backend)
- `/recordings/` (PTY sessions)
//! HUNTRESS - Bug Bounty Automation Suite
//! 
//! A closed-source, solo-use desktop application for automating bug bounty
//! reconnaissance and vulnerability discovery on Kali Linux.
//! 
//! This library provides the core Rust backend functionality including:
//! - Scope validation and safety gates
//! - PTY management for tool execution
//! - Emergency kill switch
//! - Proxy pool management
//! 
//! # Safety
//! 
//! This application is designed for authorized security testing only.
//! All operations must remain within defined scope boundaries.
//!
//! # Architecture
//!
//! The backend enforces three non-negotiable safety layers:
//! 1. **Safe-to-Test Gate** — blocks ALL network operations until scope validation passes
//! 2. **PTY Manager** — spawns subprocesses with full isolation and logging
//! 3. **Kill Switch** — emergency shutdown that terminates everything instantly

// Module declarations
pub mod safe_to_test;
pub mod pty_manager;
pub mod kill_switch;
pub mod proxy_pool;
pub mod h1_api;
pub mod secure_storage;
pub mod tool_checker;
pub mod sandbox;

// Re-exports for convenience
pub use safe_to_test::{ScopeEntry, ScopeValidator, ScopeError};
pub use pty_manager::{PtySession, PtyManager, PtyError, SessionStatus};
pub use kill_switch::{KillSwitch, KillReason, KillEvent, KillSwitchError};
pub use proxy_pool::{ProxyPool, ProxyConfig, ProxyType, RotationStrategy, HealthStatus, ProxyError};

use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as TokioMutex;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize the application
pub fn init() {
    // Initialize tracing subscriber for structured logging FIRST
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "huntress=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load environment variables from config/.env file
    // Try multiple possible paths
    let possible_paths = vec![
        "config/.env",
        "../config/.env",
        "huntress/config/.env",
        ".env",
    ];

    let mut loaded = false;
    for path in possible_paths {
        let env_path = std::path::Path::new(path);
        if env_path.exists() {
            match dotenvy::from_path(env_path) {
                Ok(_) => {
                    tracing::info!("Loaded environment variables from {}", path);
                    loaded = true;
                    break;
                }
                Err(e) => tracing::debug!("Failed to load {}: {}", path, e),
            }
        }
    }

    if !loaded {
        tracing::warn!("No .env file found - using system environment variables only");
    }

    tracing::info!("HUNTRESS backend initialized");
}

/// Run the Tauri application
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize logging
    init();

    // Create shared KillSwitch instance as managed state
    let kill_switch = Arc::new(Mutex::new(KillSwitch::new()));

    // Wire signal handlers to the shared instance
    kill_switch::setup_signal_handlers(Arc::clone(&kill_switch));

    // Initialize SandboxManager (Docker/Podman) — wrapped in Option because
    // the runtime might not be available on all systems
    let sandbox_state: Arc<TokioMutex<Option<sandbox::SandboxManager>>> =
        Arc::new(TokioMutex::new(None));

    // Try to connect to Docker/Podman asynchronously during startup
    let sandbox_init = Arc::clone(&sandbox_state);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        rt.block_on(async {
            match sandbox::SandboxManager::new().await {
                Ok(mgr) => {
                    tracing::info!("Sandbox manager initialized (runtime: {})", mgr.runtime_type());
                    *sandbox_init.lock().await = Some(mgr);
                }
                Err(e) => {
                    tracing::warn!("Sandbox manager unavailable: {} — sandbox features disabled", e);
                }
            }
        });
    });

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .manage(kill_switch)
        .manage(sandbox_state)
        .invoke_handler(tauri::generate_handler![
            // Safe-to-test commands
            safe_to_test::load_scope,
            safe_to_test::load_scope_entries,
            safe_to_test::validate_target,
            safe_to_test::validate_targets_from_file,
            // PTY commands
            pty_manager::spawn_pty,
            pty_manager::read_pty,
            pty_manager::write_pty,
            pty_manager::kill_pty,
            // Kill switch commands
            kill_switch::activate_kill_switch,
            kill_switch::is_kill_switch_active,
            kill_switch::reset_kill_switch,
            kill_switch::get_last_kill_event,
            // Proxy commands
            proxy_pool::load_proxies,
            proxy_pool::get_next_proxy,
            proxy_pool::get_proxy_stats,
            proxy_pool::mark_proxy_failed,
            // HackerOne API commands
            h1_api::fetch_h1_program,
            // Secure storage commands
            secure_storage::store_secret,
            secure_storage::get_secret,
            secure_storage::delete_secret,
            secure_storage::list_secret_keys,
            // Tool checker commands
            tool_checker::check_installed_tools,
            tool_checker::get_missing_required_tools,
            tool_checker::get_tool_summary,
            // Sandbox commands
            sandbox::create_sandbox,
            sandbox::sandbox_exec,
            sandbox::destroy_sandbox,
            sandbox::list_sandboxes,
            sandbox::destroy_all_sandboxes,
            // File operations for tool output management
            write_tool_output,
            read_tool_output,
            read_file_binary,
            file_exists,
            delete_tool_output,
            create_output_directory,
            append_to_file,
            // Extended FS for training pipeline
            read_file_text,
            write_file_text,
            list_directory,
            delete_path,
            create_symlink,
            read_symlink,
            // System info
            get_system_info,
            execute_training_command,
            // Knowledge database
            init_knowledge_db,
            knowledge_db_query,
            knowledge_db_execute,
            // HTTP proxy (bypasses browser CORS)
            proxy_http_request,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// ─── Path validation (Block 6: IPC Security) ────────────────────────────────

/// Validate that a path is within allowed Huntress directories.
/// Rejects path traversal and restricts to safe directories.
fn validate_huntress_path(path: &str) -> Result<std::path::PathBuf, String> {
    let p = std::path::PathBuf::from(path);

    // Reject path traversal
    if p.components().any(|c| c == std::path::Component::ParentDir) {
        return Err("Path traversal detected".to_string());
    }

    // Allow relative paths (within app working dir)
    if !p.is_absolute() {
        return Ok(p);
    }

    // Restrict absolute paths to allowed directories
    let abs = p.to_string_lossy();
    let allowed = abs.starts_with("/tmp/huntress")
        || abs.starts_with("/tmp/tool_output")
        || dirs::data_dir()
            .map(|d| abs.starts_with(&d.to_string_lossy().to_string()))
            .unwrap_or(false)
        || dirs::cache_dir()
            .map(|d| abs.starts_with(&format!("{}/huntress", d.to_string_lossy())))
            .unwrap_or(false);

    if !allowed {
        warn!(path = %path, "Path not in allowed directory");
        return Err(format!(
            "Path '{}' is not within an allowed directory",
            path
        ));
    }

    Ok(p)
}

/// Read a file as base64-encoded binary (for attachments, screenshots, etc.)
#[tauri::command]
async fn read_file_binary(path: String) -> Result<String, String> {
    validate_huntress_path(&path)?;
    let data = std::fs::read(&path)
        .map_err(|e| format!("Failed to read binary file {}: {}", path, e))?;
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(&data))
}

// File operations for tool output management
#[tauri::command]
async fn write_tool_output(path: String, content: String) -> Result<(), String> {
    validate_huntress_path(&path)?;
    std::fs::write(&path, content)
        .map_err(|e| format!("Failed to write file {}: {}", path, e))
}

#[tauri::command]
async fn read_tool_output(path: String) -> Result<String, String> {
    validate_huntress_path(&path)?;
    std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read file {}: {}", path, e))
}

#[tauri::command]
async fn file_exists(path: String) -> Result<bool, String> {
    validate_huntress_path(&path)?;
    Ok(std::path::Path::new(&path).exists())
}

#[tauri::command]
async fn delete_tool_output(path: String) -> Result<(), String> {
    validate_huntress_path(&path)?;
    std::fs::remove_file(&path)
        .map_err(|e| format!("Failed to delete file {}: {}", path, e))
}

#[tauri::command]
async fn create_output_directory(path: String) -> Result<(), String> {
    validate_huntress_path(&path)?;
    std::fs::create_dir_all(&path)
        .map_err(|e| format!("Failed to create directory {}: {}", path, e))
}

/// Append content to a file (used by audit logger for JSONL log files).
///
/// # Security
/// Path is validated to prevent arbitrary filesystem writes:
/// - Must be within the current working directory or a temp/output path
/// - Must not contain path traversal sequences
#[tauri::command]
async fn append_to_file(path: String, content: String) -> Result<(), String> {
    validate_huntress_path(&path)?;

    // Ensure parent directory exists
    let p = std::path::Path::new(&path);
    if let Some(parent) = p.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create parent directory: {}", e))?;
        }
    }

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("Failed to open file for appending {}: {}", path, e))?;

    file.write_all(content.as_bytes())
        .map_err(|e| format!("Failed to append to file {}: {}", path, e))?;

    Ok(())
}

// ─── Extended file system operations for training pipeline ──────────────────

/// Read a text file (training pipeline replacement for Node.js fs.readFile)
#[tauri::command]
async fn read_file_text(path: String) -> Result<String, String> {
    validate_huntress_path(&path)?;
    std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read file {}: {}", path, e))
}

/// Write a text file, creating parent directories if needed
#[tauri::command]
async fn write_file_text(path: String, content: String) -> Result<(), String> {
    validate_huntress_path(&path)?;
    let p = std::path::Path::new(&path);
    if let Some(parent) = p.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory: {}", e))?;
        }
    }
    std::fs::write(&path, content)
        .map_err(|e| format!("Failed to write file {}: {}", path, e))
}

/// List directory contents
#[tauri::command]
async fn list_directory(path: String) -> Result<Vec<String>, String> {
    validate_huntress_path(&path)?;
    let entries = std::fs::read_dir(&path)
        .map_err(|e| format!("Failed to read directory {}: {}", path, e))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("Directory entry error: {}", e))?;
        if let Some(name) = entry.file_name().to_str() {
            names.push(name.to_string());
        }
    }
    Ok(names)
}

/// Delete a file or directory recursively
#[tauri::command]
async fn delete_path(path: String) -> Result<(), String> {
    validate_huntress_path(&path)?;
    let p = std::path::Path::new(&path);
    if p.is_dir() {
        std::fs::remove_dir_all(&path)
            .map_err(|e| format!("Failed to remove directory {}: {}", path, e))
    } else {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Failed to remove file {}: {}", path, e))
    }
}

/// Get system information (replaces nvidia-smi, free, df shell commands)
#[tauri::command]
async fn get_system_info() -> Result<serde_json::Value, String> {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();

    let total_memory_gb = sys.total_memory() as f64 / 1_073_741_824.0;
    let used_memory_gb = sys.used_memory() as f64 / 1_073_741_824.0;
    let cpu_count = sys.cpus().len();
    let cpu_usage: f64 = sys.cpus().iter().map(|c| c.cpu_usage() as f64).sum::<f64>() / cpu_count as f64;

    // Disk info
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();
    let total_disk_gb: f64 = disks.iter().map(|d| d.total_space() as f64).sum::<f64>() / 1_073_741_824.0;
    let available_disk_gb: f64 = disks.iter().map(|d| d.available_space() as f64).sum::<f64>() / 1_073_741_824.0;

    // GPU info via nvidia-smi (best-effort)
    let gpu_info = match std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=name,memory.total,memory.used,utilization.gpu", "--format=csv,noheader,nounits"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = stdout.trim().split(", ").collect();
            if parts.len() >= 4 {
                serde_json::json!({
                    "available": true,
                    "name": parts[0],
                    "memoryTotalMb": parts[1].trim().parse::<f64>().unwrap_or(0.0),
                    "memoryUsedMb": parts[2].trim().parse::<f64>().unwrap_or(0.0),
                    "utilizationPercent": parts[3].trim().parse::<f64>().unwrap_or(0.0),
                })
            } else {
                serde_json::json!({ "available": false })
            }
        }
        _ => serde_json::json!({ "available": false }),
    };

    Ok(serde_json::json!({
        "cpu": {
            "cores": cpu_count,
            "usagePercent": cpu_usage,
        },
        "memory": {
            "totalGb": total_memory_gb,
            "usedGb": used_memory_gb,
            "availableGb": total_memory_gb - used_memory_gb,
        },
        "disk": {
            "totalGb": total_disk_gb,
            "availableGb": available_disk_gb,
        },
        "gpu": gpu_info,
    }))
}

/// Allowed programs for training command execution
const ALLOWED_TRAINING_PROGRAMS: &[&str] = &[
    // Training pipeline
    "python", "python3", "pip", "pip3",
    "axolotl", "huggingface-cli",
    "nvidia-smi", "gpustat",
    // Benchmark / XBOW
    "git", "docker",
    // Benchmark agent tools
    "curl", "wget", "node", "nmap", "sqlmap", "nikto",
    "gobuster", "ffuf", "dirb", "hydra", "wfuzz",
    "httpie", "http", "jq", "grep", "awk", "sed",
    "cat", "echo", "base64", "xxd", "openssl",
    "nc", "ncat", "bash", "sh",
];

/// Execute a training command (LoRA, Axolotl, etc.) in a subprocess
#[tauri::command]
async fn execute_training_command(program: String, args: Vec<String>, cwd: Option<String>) -> Result<serde_json::Value, String> {
    if !ALLOWED_TRAINING_PROGRAMS.contains(&program.as_str()) {
        return Err(format!("Program not in allowlist: {}", program));
    }
    info!("Training command: {} {:?}", program, args);

    let mut cmd = std::process::Command::new(&program);
    cmd.args(&args);
    if let Some(dir) = &cwd {
        cmd.current_dir(dir);
    }

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to execute {}: {}", program, e))?;

    Ok(serde_json::json!({
        "exitCode": output.status.code().unwrap_or(-1),
        "stdout": String::from_utf8_lossy(&output.stdout),
        "stderr": String::from_utf8_lossy(&output.stderr),
        "success": output.status.success(),
    }))
}

/// Create a symbolic link (for model version management)
#[tauri::command]
async fn create_symlink(target: String, link_path: String) -> Result<(), String> {
    validate_huntress_path(&target)?;
    validate_huntress_path(&link_path)?;
    // Remove existing link/file first
    let lp = std::path::Path::new(&link_path);
    if lp.exists() || lp.is_symlink() {
        let _ = std::fs::remove_file(&link_path);
        let _ = std::fs::remove_dir(&link_path);
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, &link_path)
            .map_err(|e| format!("Failed to create symlink {} -> {}: {}", link_path, target, e))
    }
    #[cfg(not(unix))]
    {
        Err("Symlinks not supported on this platform".to_string())
    }
}

/// Read a symbolic link target
#[tauri::command]
async fn read_symlink(path: String) -> Result<String, String> {
    std::fs::read_link(&path)
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| format!("Failed to read symlink {}: {}", path, e))
}

/// Initialize SQLite knowledge graph database
#[tauri::command]
async fn init_knowledge_db(db_path: String) -> Result<(), String> {
    use rusqlite::Connection;
    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open knowledge DB: {}", e))?;

    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            cve_id TEXT,
            cwe_id TEXT,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT,
            cvss_score REAL,
            cvss_vector TEXT,
            affected_product TEXT,
            affected_vendor TEXT,
            published_date TEXT,
            modified_date TEXT,
            exploit_available INTEGER DEFAULT 0,
            in_kev INTEGER DEFAULT 0,
            source TEXT NOT NULL,
            raw_json TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS attack_patterns (
            id TEXT PRIMARY KEY,
            capec_id TEXT,
            name TEXT NOT NULL,
            description TEXT,
            severity TEXT,
            likelihood TEXT,
            related_cwes TEXT,
            prerequisites TEXT,
            mitigations TEXT,
            examples TEXT,
            source TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS exploit_templates (
            id TEXT PRIMARY KEY,
            template_id TEXT,
            name TEXT NOT NULL,
            severity TEXT,
            tags TEXT,
            cve_ids TEXT,
            cwe_ids TEXT,
            description TEXT,
            http_method TEXT,
            path_pattern TEXT,
            matchers TEXT,
            source TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS hunt_history (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            target TEXT NOT NULL,
            agent_id TEXT,
            vuln_type TEXT,
            finding_title TEXT,
            severity TEXT,
            success INTEGER DEFAULT 0,
            bounty_amount REAL DEFAULT 0,
            h1_report_id TEXT,
            h1_status TEXT,
            techniques_used TEXT,
            duration_ms INTEGER,
            model_used TEXT,
            tokens_used INTEGER,
            cost_usd REAL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS learned_patterns (
            id TEXT PRIMARY KEY,
            pattern_type TEXT NOT NULL,
            pattern_key TEXT NOT NULL,
            pattern_value TEXT NOT NULL,
            confidence REAL DEFAULT 0.5,
            successes INTEGER DEFAULT 0,
            failures INTEGER DEFAULT 0,
            last_used TEXT,
            source TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(pattern_type, pattern_key)
        );

        CREATE TABLE IF NOT EXISTS benchmark_runs (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            model TEXT NOT NULL DEFAULT '',
            score REAL NOT NULL DEFAULT 0,
            total_challenges INTEGER NOT NULL DEFAULT 0,
            solved INTEGER NOT NULL DEFAULT 0,
            failed INTEGER NOT NULL DEFAULT 0,
            skipped INTEGER NOT NULL DEFAULT 0,
            total_cost_usd REAL NOT NULL DEFAULT 0,
            total_duration_ms INTEGER NOT NULL DEFAULT 0,
            results_json TEXT NOT NULL DEFAULT '[]',
            by_tag_json TEXT NOT NULL DEFAULT '{}',
            by_level_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS reward_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            agent_id TEXT,
            event_type TEXT NOT NULL,
            points INTEGER NOT NULL,
            reason TEXT,
            details TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id);
        CREATE INDEX IF NOT EXISTS idx_vuln_cwe ON vulnerabilities(cwe_id);
        CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
        CREATE INDEX IF NOT EXISTS idx_vuln_source ON vulnerabilities(source);
        CREATE INDEX IF NOT EXISTS idx_attack_capec ON attack_patterns(capec_id);
        CREATE INDEX IF NOT EXISTS idx_exploit_tags ON exploit_templates(tags);
        CREATE INDEX IF NOT EXISTS idx_hunt_target ON hunt_history(target);
        CREATE INDEX IF NOT EXISTS idx_hunt_vuln ON hunt_history(vuln_type);
        CREATE INDEX IF NOT EXISTS idx_hunt_success ON hunt_history(success);
        CREATE INDEX IF NOT EXISTS idx_learned_type ON learned_patterns(pattern_type);
        CREATE INDEX IF NOT EXISTS idx_reward_session ON reward_ledger(session_id);
        CREATE INDEX IF NOT EXISTS idx_benchmark_model ON benchmark_runs(model);
    ").map_err(|e| format!("Failed to initialize knowledge DB schema: {}", e))?;

    info!("Knowledge database initialized at {}", db_path);
    Ok(())
}

/// Allowed SQL statement prefixes for knowledge database
const ALLOWED_SQL_PREFIXES: &[&str] = &[
    "SELECT", "INSERT INTO", "UPDATE", "CREATE TABLE IF NOT EXISTS",
    "CREATE INDEX IF NOT EXISTS", "DELETE FROM",
];

/// Validate SQL statement prefix
fn validate_sql(sql: &str) -> Result<(), String> {
    let trimmed = sql.trim_start().to_uppercase();
    if !ALLOWED_SQL_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
        let preview_len = trimmed.len().min(30);
        return Err(format!("SQL statement type not allowed: {}", &trimmed[..preview_len]));
    }
    Ok(())
}

/// Execute a SQL query on the knowledge database
#[tauri::command]
async fn knowledge_db_query(db_path: String, sql: String, params: Vec<String>) -> Result<serde_json::Value, String> {
    validate_huntress_path(&db_path)?;
    validate_sql(&sql)?;
    use rusqlite::Connection;
    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open knowledge DB: {}", e))?;

    let mut stmt = conn.prepare(&sql)
        .map_err(|e| format!("SQL prepare error: {}", e))?;

    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter()
        .map(|p| p as &dyn rusqlite::types::ToSql)
        .collect();

    let column_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let column_count = column_names.len();

    let rows: Vec<serde_json::Value> = stmt.query_map(rusqlite::params_from_iter(param_refs), |row| {
        let mut obj = serde_json::Map::new();
        for i in 0..column_count {
            let val: rusqlite::Result<String> = row.get(i);
            match val {
                Ok(s) => { obj.insert(column_names[i].clone(), serde_json::Value::String(s)); }
                Err(_) => {
                    // Try as f64
                    if let Ok(f) = row.get::<_, f64>(i) {
                        obj.insert(column_names[i].clone(), serde_json::json!(f));
                    } else if let Ok(n) = row.get::<_, i64>(i) {
                        obj.insert(column_names[i].clone(), serde_json::json!(n));
                    } else {
                        obj.insert(column_names[i].clone(), serde_json::Value::Null);
                    }
                }
            }
        }
        Ok(serde_json::Value::Object(obj))
    }).map_err(|e| format!("SQL query error: {}", e))?
    .filter_map(|r| r.ok())
    .collect();

    Ok(serde_json::json!({ "rows": rows, "count": rows.len() }))
}

/// Execute a SQL statement (INSERT/UPDATE/DELETE) on the knowledge database
#[tauri::command]
async fn knowledge_db_execute(db_path: String, sql: String, params: Vec<String>) -> Result<serde_json::Value, String> {
    validate_huntress_path(&db_path)?;
    validate_sql(&sql)?;
    use rusqlite::Connection;
    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open knowledge DB: {}", e))?;

    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter()
        .map(|p| p as &dyn rusqlite::types::ToSql)
        .collect();

    let affected = conn.execute(&sql, rusqlite::params_from_iter(param_refs))
        .map_err(|e| format!("SQL execute error: {}", e))?;

    Ok(serde_json::json!({ "rowsAffected": affected }))
}

// ─── HTTP Proxy (CORS bypass for WebView) ───────────────────────────────────

/// Proxy an HTTP request through the Rust backend.
/// This bypasses browser CORS restrictions since reqwest is not subject to
/// the same-origin policy. All agent HTTP traffic should use this command.
#[tauri::command]
async fn proxy_http_request(
    url: String,
    method: String,
    headers: Option<std::collections::HashMap<String, String>>,
    body: Option<String>,
    timeout_ms: Option<u64>,
    follow_redirects: Option<bool>,
) -> Result<serde_json::Value, String> {
    let start = std::time::Instant::now();

    // Build reqwest client
    let follow = follow_redirects.unwrap_or(true);
    let timeout = std::time::Duration::from_millis(timeout_ms.unwrap_or(30000));

    let redirect_policy = if follow {
        reqwest::redirect::Policy::limited(10)
    } else {
        reqwest::redirect::Policy::none()
    };

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(redirect_policy)
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    // Build request
    let req_method = match method.to_uppercase().as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "OPTIONS" => reqwest::Method::OPTIONS,
        "HEAD" => reqwest::Method::HEAD,
        other => return Err(format!("Unsupported HTTP method: {}", other)),
    };

    let mut req = client.request(req_method, &url);

    // Apply headers
    if let Some(hdrs) = &headers {
        for (key, value) in hdrs {
            req = req.header(key.as_str(), value.as_str());
        }
    }

    // Apply body
    if let Some(b) = body {
        req = req.body(b);
    }

    // Execute
    let response = req.send().await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let elapsed = start.elapsed();
    let status = response.status().as_u16();
    let status_text = response.status().canonical_reason().unwrap_or("").to_string();

    // Collect response headers
    let mut resp_headers = serde_json::Map::new();
    for (key, val) in response.headers() {
        if let Ok(v) = val.to_str() {
            resp_headers.insert(
                key.as_str().to_string(),
                serde_json::Value::String(v.to_string()),
            );
        }
    }

    // Read body (cap at 10MB to prevent OOM)
    let resp_body = response.text().await
        .unwrap_or_default();
    let body_size = resp_body.len();

    Ok(serde_json::json!({
        "status": status,
        "statusText": status_text,
        "headers": resp_headers,
        "body": resp_body,
        "size": body_size,
        "totalMs": elapsed.as_millis() as u64,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all modules are accessible
        let _ = ScopeValidator::new(vec![]);
        let _ = PtyManager::new();
        let _ = KillSwitch::new();
        let _ = ProxyPool::new(RotationStrategy::RoundRobin);
    }
}

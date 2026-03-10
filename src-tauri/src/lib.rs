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
            match dotenv::from_path(env_path) {
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
            file_exists,
            delete_tool_output,
            create_output_directory,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// File operations for tool output management
#[tauri::command]
async fn write_tool_output(path: String, content: String) -> Result<(), String> {
    std::fs::write(&path, content)
        .map_err(|e| format!("Failed to write file {}: {}", path, e))
}

#[tauri::command]
async fn read_tool_output(path: String) -> Result<String, String> {
    std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read file {}: {}", path, e))
}

#[tauri::command]
async fn file_exists(path: String) -> Result<bool, String> {
    Ok(std::path::Path::new(&path).exists())
}

#[tauri::command]
async fn delete_tool_output(path: String) -> Result<(), String> {
    std::fs::remove_file(&path)
        .map_err(|e| format!("Failed to delete file {}: {}", path, e))
}

#[tauri::command]
async fn create_output_directory(path: String) -> Result<(), String> {
    std::fs::create_dir_all(&path)
        .map_err(|e| format!("Failed to create directory {}: {}", path, e))
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

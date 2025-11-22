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

// Module declarations
pub mod safe_to_test;
pub mod pty_manager;
pub mod kill_switch;
pub mod proxy_pool;

// Re-exports for convenience
pub use safe_to_test::{ScopeEntry, ScopeValidator, SafetyGate};
pub use pty_manager::{PtyManager, PtyConfig, PtyOutput, PtyStatus};
pub use kill_switch::{KillSwitch, KillReason, KillEvent};
pub use proxy_pool::{ProxyPool, ProxyConfig, ProxyType, RotationStrategy};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

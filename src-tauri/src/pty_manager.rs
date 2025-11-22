//! PTY Manager Module
//! 
//! Manages pseudo-terminal (PTY) spawning and lifecycle for executing
//! security testing tools and commands within the HUNTRESS application.
//! 
//! This module provides safe, controlled terminal access with proper
//! cleanup and resource management.

use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Unique identifier for a PTY session
pub type PtyId = String;

/// Output from a PTY session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtyOutput {
    /// The PTY session ID
    pub pty_id: PtyId,
    /// Output data
    pub data: String,
    /// Whether this is stdout or stderr
    pub is_error: bool,
}

/// Status of a PTY session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PtyStatus {
    /// PTY is running
    Running,
    /// PTY has exited with the given code
    Exited(Option<i32>),
    /// PTY encountered an error
    Error(String),
}

/// Configuration for spawning a new PTY
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtyConfig {
    /// Command to execute
    pub command: String,
    /// Command arguments
    pub args: Vec<String>,
    /// Working directory
    pub cwd: Option<String>,
    /// Environment variables
    pub env: Option<HashMap<String, String>>,
    /// Terminal size (cols, rows)
    pub size: Option<(u16, u16)>,
}

/// Manages multiple PTY sessions
pub struct PtyManager {
    /// Active PTY sessions
    sessions: Arc<Mutex<HashMap<PtyId, PtySession>>>,
    /// PTY system implementation
    pty_system: NativePtySystem,
}

/// Individual PTY session
struct PtySession {
    /// PTY pair (master/slave)
    _pair: Box<dyn portable_pty::PtyPair + Send>,
    /// Child process
    _child: Box<dyn portable_pty::Child + Send>,
    /// Output channel sender
    output_tx: mpsc::UnboundedSender<PtyOutput>,
}

impl PtyManager {
    /// Create a new PTY manager
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            pty_system: NativePtySystem::default(),
        }
    }

    /// Spawn a new PTY session
    pub fn spawn(
        &self,
        pty_id: PtyId,
        config: PtyConfig,
    ) -> Result<mpsc::UnboundedReceiver<PtyOutput>, String> {
        // Create PTY with specified size or default
        let size = config.size.unwrap_or((80, 24));
        let pair = self
            .pty_system
            .openpty(PtySize {
                rows: size.1,
                cols: size.0,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| format!("Failed to create PTY: {}", e))?;

        // Build command
        let mut cmd = CommandBuilder::new(&config.command);
        cmd.args(&config.args);

        if let Some(cwd) = config.cwd {
            cmd.cwd(cwd);
        }

        if let Some(env) = config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        // Spawn child process
        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| format!("Failed to spawn command: {}", e))?;

        // Create output channel
        let (output_tx, output_rx) = mpsc::unbounded_channel();

        // Store session
        let session = PtySession {
            _pair: Box::new(pair),
            _child: Box::new(child),
            output_tx: output_tx.clone(),
        };

        self.sessions
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?
            .insert(pty_id.clone(), session);

        // TODO: Start background task to read PTY output and send to channel
        // This would require additional async handling

        Ok(output_rx)
    }

    /// Write input to a PTY session
    pub fn write_input(&self, pty_id: &PtyId, data: &str) -> Result<(), String> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;

        let _session = sessions
            .get(pty_id)
            .ok_or_else(|| format!("PTY session {} not found", pty_id))?;

        // TODO: Implement writing to PTY master
        // This requires access to the master writer which needs to be stored

        Ok(())
    }

    /// Resize a PTY session
    pub fn resize(&self, pty_id: &PtyId, cols: u16, rows: u16) -> Result<(), String> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;

        let _session = sessions
            .get(pty_id)
            .ok_or_else(|| format!("PTY session {} not found", pty_id))?;

        // TODO: Implement PTY resize
        // This requires access to the master which needs to be stored

        Ok(())
    }

    /// Kill a PTY session
    pub fn kill(&self, pty_id: &PtyId) -> Result<(), String> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;

        sessions
            .remove(pty_id)
            .ok_or_else(|| format!("PTY session {} not found", pty_id))?;

        // Session will be dropped and cleaned up automatically

        Ok(())
    }

    /// Get status of a PTY session
    pub fn get_status(&self, pty_id: &PtyId) -> Result<PtyStatus, String> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;

        if sessions.contains_key(pty_id) {
            Ok(PtyStatus::Running)
        } else {
            Err(format!("PTY session {} not found", pty_id))
        }
    }

    /// List all active PTY sessions
    pub fn list_sessions(&self) -> Result<Vec<PtyId>, String> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;

        Ok(sessions.keys().cloned().collect())
    }
}

impl Default for PtyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pty_manager_creation() {
        let manager = PtyManager::new();
        assert_eq!(manager.list_sessions().unwrap().len(), 0);
    }

    #[test]
    fn test_spawn_pty() {
        let manager = PtyManager::new();
        let config = PtyConfig {
            command: "echo".to_string(),
            args: vec!["test".to_string()],
            cwd: None,
            env: None,
            size: Some((80, 24)),
        };

        let result = manager.spawn("test-pty".to_string(), config);
        assert!(result.is_ok());
        assert_eq!(manager.list_sessions().unwrap().len(), 1);
    }
}
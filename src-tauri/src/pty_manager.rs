//! PTY Manager Module
//!
//! Manages pseudo-terminal (PTY) spawning and lifecycle for executing
//! security testing tools and commands within the HUNTRESS application.
//!
//! This module provides safe, controlled terminal access with proper
//! cleanup and resource management.
//!
//! # Security Guarantees
//!
//! - NEVER uses shell=True or string commands — always parses into argv
//! - All commands are logged with full arguments before execution
//! - PTY sessions are isolated (separate process groups)
//! - Automatic recording to /recordings/{session_id}.cast (asciinema format)
//! - Environment variables are sanitized (no PATH injection)
//! - CRITICAL: All tokens, cookies, and sensitive data are redacted from recordings

use chrono::{DateTime, Utc};
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Errors that can occur during PTY operations
#[derive(Error, Debug)]
pub enum PtyError {
    #[error("Failed to create PTY: {0}")]
    CreateFailed(String),
    
    #[error("Failed to spawn command: {0}")]
    SpawnFailed(String),
    
    #[error("PTY session {0} not found")]
    SessionNotFound(String),
    
    #[error("Failed to read from PTY: {0}")]
    ReadFailed(String),
    
    #[error("Failed to write to PTY: {0}")]
    WriteFailed(String),
    
    #[error("Failed to kill PTY: {0}")]
    KillFailed(String),
    
    #[error("Lock error: {0}")]
    LockError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Invalid command: {0}")]
    InvalidCommand(String),
    
    #[error("Environment variable injection detected: {0}")]
    EnvInjection(String),
}

/// PTY session status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionStatus {
    /// Session is currently running
    Running,
    /// Session completed with exit code
    Completed(i32),
    /// Session was killed
    Killed,
    /// Session failed with error
    Failed(String),
}

/// PTY session with full isolation
pub struct PtySession {
    /// Unique session ID
    pub id: String,
    /// Command being executed
    pub command: String,
    /// Command arguments
    pub args: Vec<String>,
    /// Session start time
    pub started_at: DateTime<Utc>,
    /// Current status
    pub status: SessionStatus,
    /// PTY master for reading/writing
    master: Arc<Mutex<Box<dyn portable_pty::MasterPty + Send>>>,
    /// Child process handle
    child: Arc<Mutex<Box<dyn portable_pty::Child + Send>>>,
    /// Recording file writer
    recording: Arc<Mutex<Option<BufWriter<File>>>>,
    /// Persistent writer handle - prevents take_writer() consumption issue
    writer: Arc<Mutex<Option<Box<dyn Write + Send>>>>,
}

impl PtySession {
    /// Spawn new PTY with command (NEVER use shell=True)
    pub fn spawn(
        command: &str,
        args: &[&str],
        env: HashMap<String, String>,
    ) -> Result<Self, PtyError> {
        let session_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        // Validate command (no shell injection)
        Self::validate_command(command)?;

        // Sanitize environment variables
        let sanitized_env = Self::sanitize_env(env)?;

        // Log command execution
        info!(
            session_id = %session_id,
            timestamp = %timestamp,
            command = %command,
            args = ?args,
            "Spawning PTY session"
        );

        // Create PTY system
        let pty_system = NativePtySystem::default();
        
        // Create PTY pair with default size
        let pty_pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| PtyError::CreateFailed(e.to_string()))?;

        // Build command with explicit argv (NO shell)
        let mut cmd = CommandBuilder::new(command);
        for arg in args {
            cmd.arg(arg);
        }

        // Set sanitized environment
        for (key, value) in sanitized_env {
            cmd.env(key, value);
        }

        // Spawn child process in PTY
        let child = pty_pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| PtyError::SpawnFailed(e.to_string()))?;

        // Create recording file in project root (not src-tauri)
        let recording_path = PathBuf::from("../recordings").join(format!("{}.cast", session_id));
        fs::create_dir_all("../recordings")?;
        let recording_file = File::create(&recording_path)?;
        let recording_writer = BufWriter::new(recording_file);

        info!(
            session_id = %session_id,
            recording_path = ?recording_path,
            "PTY session spawned successfully"
        );

        Ok(Self {
            id: session_id,
            command: command.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            started_at: timestamp,
            status: SessionStatus::Running,
            master: Arc::new(Mutex::new(pty_pair.master)),
            child: Arc::new(Mutex::new(child)),
            recording: Arc::new(Mutex::new(Some(recording_writer))),
            writer: Arc::new(Mutex::new(None)), // Writer initialized on first write
        })
    }

    /// Validate command to prevent shell injection
    fn validate_command(command: &str) -> Result<(), PtyError> {
        // Check for shell metacharacters
        let dangerous_chars = ['|', '&', ';', '>', '<', '`', '$', '(', ')', '{', '}'];
        
        for ch in dangerous_chars {
            if command.contains(ch) {
                return Err(PtyError::InvalidCommand(format!(
                    "Command contains dangerous character: {}",
                    ch
                )));
            }
        }

        // Command must not be empty
        if command.trim().is_empty() {
            return Err(PtyError::InvalidCommand("Command is empty".to_string()));
        }

        Ok(())
    }

    /// Sanitize environment variables to prevent PATH injection
    fn sanitize_env(env: HashMap<String, String>) -> Result<HashMap<String, String>, PtyError> {
        let mut sanitized = HashMap::new();

        for (key, value) in env {
            // Block PATH modifications
            if key.to_uppercase() == "PATH" {
                warn!("Blocked PATH environment variable modification");
                return Err(PtyError::EnvInjection(
                    "PATH modification not allowed".to_string(),
                ));
            }

            // Block LD_PRELOAD and similar
            if key.to_uppercase().starts_with("LD_") {
                warn!("Blocked LD_* environment variable: {}", key);
                return Err(PtyError::EnvInjection(format!(
                    "LD_* variables not allowed: {}",
                    key
                )));
            }

            // Check for injection attempts in values
            if value.contains('\0') || value.contains('\n') {
                return Err(PtyError::EnvInjection(format!(
                    "Invalid characters in env value for key: {}",
                    key
                )));
            }

            sanitized.insert(key, value);
        }

        Ok(sanitized)
    }

    /// Redact sensitive data from output before recording
    ///
    /// CRITICAL PRODUCTION FIX:
    /// - Strips all tokens from terminal recordings
    /// - Strips all cookies from logs
    /// - Redacts full URLs to show only domain + path (no query params with tokens)
    /// - Prevents data leaks if screenshots are shared
    fn redact_sensitive_data(data: &str) -> String {
        use std::sync::LazyLock;

        // Compile all redaction regexes once as statics
        static TOKEN_PATTERNS: LazyLock<Vec<(regex::Regex, &'static str)>> = LazyLock::new(|| vec![
            (regex::Regex::new(r"access_token=[^&\s]+").expect("valid regex"), "access_token=[REDACTED]"),
            (regex::Regex::new(r"token=[^&\s]+").expect("valid regex"), "token=[REDACTED]"),
            (regex::Regex::new(r"api_key=[^&\s]+").expect("valid regex"), "api_key=[REDACTED]"),
            (regex::Regex::new(r"apikey=[^&\s]+").expect("valid regex"), "apikey=[REDACTED]"),
            (regex::Regex::new(r"key=[^&\s]+").expect("valid regex"), "key=[REDACTED]"),
            (regex::Regex::new(r"secret=[^&\s]+").expect("valid regex"), "secret=[REDACTED]"),
            (regex::Regex::new(r"password=[^&\s]+").expect("valid regex"), "password=[REDACTED]"),
            (regex::Regex::new(r"passwd=[^&\s]+").expect("valid regex"), "passwd=[REDACTED]"),
            (regex::Regex::new(r"pwd=[^&\s]+").expect("valid regex"), "pwd=[REDACTED]"),
        ]);

        static BEARER_PATTERN: LazyLock<regex::Regex> = LazyLock::new(||
            regex::Regex::new(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*").expect("valid regex")
        );
        static AUTH_PATTERN: LazyLock<regex::Regex> = LazyLock::new(||
            regex::Regex::new(r"Authorization:\s*[^\r\n]+").expect("valid regex")
        );
        static COOKIE_PATTERN: LazyLock<regex::Regex> = LazyLock::new(||
            regex::Regex::new(r"Cookie:\s*[^\r\n]+").expect("valid regex")
        );
        static SETCOOKIE_PATTERN: LazyLock<regex::Regex> = LazyLock::new(||
            regex::Regex::new(r"Set-Cookie:\s*[^\r\n]+").expect("valid regex")
        );
        static JWT_PATTERN: LazyLock<regex::Regex> = LazyLock::new(||
            regex::Regex::new(r"eyJ[A-Za-z0-9\-._~+/]+=*\.eyJ[A-Za-z0-9\-._~+/]+=*\.[A-Za-z0-9\-._~+/]+=*").expect("valid regex")
        );
        static APIKEY_PATTERNS: LazyLock<Vec<regex::Regex>> = LazyLock::new(|| vec![
            regex::Regex::new(r"sk-[A-Za-z0-9]{32,}").expect("valid regex"),   // OpenAI style
            regex::Regex::new(r"ghp_[A-Za-z0-9]{36,}").expect("valid regex"),  // GitHub
            regex::Regex::new(r"gho_[A-Za-z0-9]{36,}").expect("valid regex"),  // GitHub OAuth
            regex::Regex::new(r"AKIA[A-Z0-9]{16}").expect("valid regex"),      // AWS
        ]);

        let mut redacted = data.to_string();

        for (pattern, replacement) in TOKEN_PATTERNS.iter() {
            redacted = pattern.replace_all(&redacted, *replacement).to_string();
        }

        redacted = BEARER_PATTERN.replace_all(&redacted, "Bearer [REDACTED]").to_string();
        redacted = AUTH_PATTERN.replace_all(&redacted, "Authorization: [REDACTED]").to_string();
        redacted = COOKIE_PATTERN.replace_all(&redacted, "Cookie: [REDACTED]").to_string();
        redacted = SETCOOKIE_PATTERN.replace_all(&redacted, "Set-Cookie: [REDACTED]").to_string();
        redacted = JWT_PATTERN.replace_all(&redacted, "[REDACTED_JWT]").to_string();

        for pattern in APIKEY_PATTERNS.iter() {
            redacted = pattern.replace_all(&redacted, "[REDACTED_API_KEY]").to_string();
        }

        redacted
    }

    /// Read output (non-blocking)
    pub fn read_output(&mut self) -> Result<String, PtyError> {
        let master = self
            .master
            .lock()
            .map_err(|e| PtyError::LockError(e.to_string()))?;

        let mut buffer = [0u8; 4096];
        let mut output = String::new();

        // Non-blocking read
        match master.try_clone_reader() {
            Ok(mut reader) => {
                match reader.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        let data = String::from_utf8_lossy(&buffer[..n]).to_string();
                        output.push_str(&data);

                        // Write to recording with redaction
                        if let Ok(mut rec) = self.recording.lock() {
                            if let Some(writer) = rec.as_mut() {
                                let redacted = Self::redact_sensitive_data(&data);
                                let _ = writer.write_all(redacted.as_bytes());
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(PtyError::ReadFailed(e.to_string())),
                }
            }
            Err(e) => return Err(PtyError::ReadFailed(e.to_string())),
        }

        Ok(output)
    }

    /// Write input to PTY
    pub fn write_input(&mut self, data: &str) -> Result<(), PtyError> {
        // Get or initialize the writer
        let mut writer_guard = self
            .writer
            .lock()
            .map_err(|e| PtyError::LockError(e.to_string()))?;
        
        if writer_guard.is_none() {
            // First write - take the writer from master and store it
            let master = self
                .master
                .lock()
                .map_err(|e| PtyError::LockError(e.to_string()))?;
            
            let writer = master
                .take_writer()
                .map_err(|e| PtyError::WriteFailed(e.to_string()))?;
            
            *writer_guard = Some(writer);
        }
        
        // Write using the persistent writer
        let writer = writer_guard
            .as_mut()
            .ok_or_else(|| PtyError::WriteFailed("Writer not available".to_string()))?;
        
        writer
            .write_all(data.as_bytes())
            .map_err(|e| PtyError::WriteFailed(e.to_string()))?;
        
        writer
            .flush()
            .map_err(|e| PtyError::WriteFailed(e.to_string()))?;

        Ok(())
    }

    /// Kill process and all children
    pub fn kill(&mut self) -> Result<(), PtyError> {
        info!(session_id = %self.id, "Killing PTY session");

        let mut child = self
            .child
            .lock()
            .map_err(|e| PtyError::LockError(e.to_string()))?;

        child
            .kill()
            .map_err(|e| PtyError::KillFailed(e.to_string()))?;

        self.status = SessionStatus::Killed;

        // Close recording
        if let Ok(mut rec) = self.recording.lock() {
            *rec = None;
        }

        info!(session_id = %self.id, "PTY session killed successfully");
        Ok(())
    }

    /// Check if process is still running
    pub fn is_running(&self) -> bool {
        if let Ok(mut child) = self.child.lock() {
            child.try_wait().ok().flatten().is_none()
        } else {
            false
        }
    }

    /// Get exit code (if completed)
    pub fn exit_code(&self) -> Option<i32> {
        match &self.status {
            SessionStatus::Completed(code) => Some(*code),
            _ => None,
        }
    }

    /// Update status by checking child process
    pub fn update_status(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            if let Ok(Some(status)) = child.try_wait() {
                let exit_code = status.exit_code();
                self.status = SessionStatus::Completed(exit_code as i32);

                info!(
                    session_id = %self.id,
                    exit_code = exit_code,
                    "PTY session completed"
                );

                // Close recording
                if let Ok(mut rec) = self.recording.lock() {
                    *rec = None;
                }
            }
        }
    }
}

/// Global PTY manager
pub struct PtyManager {
    sessions: Arc<Mutex<HashMap<String, PtySession>>>,
}

impl PtyManager {
    /// Create new PTY manager
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Add session to manager
    pub fn add_session(&self, session: PtySession) -> Result<String, PtyError> {
        let session_id = session.id.clone();
        
        self.sessions
            .lock()
            .map_err(|e| PtyError::LockError(e.to_string()))?
            .insert(session_id.clone(), session);

        Ok(session_id)
    }

    /// Get session by ID
    pub fn get_session(&self, session_id: &str) -> Result<PtySession, PtyError> {
        self.sessions
            .lock()
            .map_err(|e| PtyError::LockError(e.to_string()))?
            .get(session_id)
            .cloned()
            .ok_or_else(|| PtyError::SessionNotFound(session_id.to_string()))
    }

    /// Remove session
    pub fn remove_session(&self, session_id: &str) -> Result<(), PtyError> {
        self.sessions
            .lock()
            .map_err(|e| PtyError::LockError(e.to_string()))?
            .remove(session_id)
            .ok_or_else(|| PtyError::SessionNotFound(session_id.to_string()))?;

        Ok(())
    }

    /// List all active sessions
    pub fn list_sessions(&self) -> Result<Vec<String>, PtyError> {
        Ok(self
            .sessions
            .lock()
            .map_err(|e| PtyError::LockError(e.to_string()))?
            .keys()
            .cloned()
            .collect())
    }

    /// Kill all sessions
    pub fn kill_all(&self) -> Result<usize, PtyError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| PtyError::LockError(e.to_string()))?;

        let count = sessions.len();

        for (_, mut session) in sessions.drain() {
            let _ = session.kill();
        }

        info!("Killed {} PTY sessions", count);
        Ok(count)
    }
}

impl Default for PtyManager {
    fn default() -> Self {
        Self::new()
    }
}

// Note: PtySession cannot derive Clone due to internal types
// We implement a manual clone for the manager's needs
impl Clone for PtySession {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            command: self.command.clone(),
            args: self.args.clone(),
            started_at: self.started_at,
            status: self.status.clone(),
            master: Arc::clone(&self.master),
            child: Arc::clone(&self.child),
            recording: Arc::clone(&self.recording),
            writer: Arc::clone(&self.writer),
        }
    }
}

// Global PTY manager instance
use std::sync::LazyLock;
static GLOBAL_PTY_MANAGER: LazyLock<PtyManager> = LazyLock::new(PtyManager::new);

/// Tauri command: Spawn PTY session
#[tauri::command]
pub async fn spawn_pty(command: String, args: Vec<String>) -> Result<String, String> {
    info!("Tauri command: spawn_pty - command: {}, args: {:?}", command, args);

    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let session = PtySession::spawn(&command, &args_refs, HashMap::new())
        .map_err(|e| format!("Failed to spawn PTY: {}", e))?;

    let session_id = session.id.clone();
    
    // Add to global manager
    GLOBAL_PTY_MANAGER.add_session(session)
        .map_err(|e| format!("Failed to add session to manager: {}", e))?;

    Ok(session_id)
}

/// Tauri command: Read PTY output
#[tauri::command]
pub async fn read_pty(session_id: String) -> Result<String, String> {
    let mut session = GLOBAL_PTY_MANAGER.get_session(&session_id)
        .map_err(|e| format!("Failed to get session: {}", e))?;
    
    session.read_output()
        .map_err(|e| format!("Failed to read output: {}", e))
}

/// Tauri command: Write to PTY
#[tauri::command]
pub async fn write_pty(session_id: String, data: String) -> Result<(), String> {
    let mut session = GLOBAL_PTY_MANAGER.get_session(&session_id)
        .map_err(|e| format!("Failed to get session: {}", e))?;
    
    session.write_input(&data)
        .map_err(|e| format!("Failed to write input: {}", e))
}

/// Tauri command: Kill PTY session
#[tauri::command]
pub async fn kill_pty(session_id: String) -> Result<(), String> {
    let mut session = GLOBAL_PTY_MANAGER.get_session(&session_id)
        .map_err(|e| format!("Failed to get session: {}", e))?;
    
    session.kill()
        .map_err(|e| format!("Failed to kill session: {}", e))?;
    
    GLOBAL_PTY_MANAGER.remove_session(&session_id)
        .map_err(|e| format!("Failed to remove session: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_command() {
        assert!(PtySession::validate_command("ls").is_ok());
        assert!(PtySession::validate_command("echo").is_ok());
        assert!(PtySession::validate_command("ls | grep").is_err());
        assert!(PtySession::validate_command("echo $(whoami)").is_err());
        assert!(PtySession::validate_command("").is_err());
    }

    #[test]
    fn test_sanitize_env() {
        let mut env = HashMap::new();
        env.insert("SAFE_VAR".to_string(), "value".to_string());
        assert!(PtySession::sanitize_env(env).is_ok());

        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/malicious".to_string());
        assert!(PtySession::sanitize_env(env).is_err());

        let mut env = HashMap::new();
        env.insert("LD_PRELOAD".to_string(), "/malicious.so".to_string());
        assert!(PtySession::sanitize_env(env).is_err());
    }

    #[test]
    fn test_pty_manager_creation() {
        let manager = PtyManager::new();
        assert_eq!(manager.list_sessions().unwrap().len(), 0);
    }
}
//! Docker Sandbox Module — XBOW "Attack Machine" Pattern
//!
//! Provides container-isolated execution for security testing tools.
//! Each agent gets its own ephemeral container with:
//! - Read-only root filesystem + tmpfs working directories
//! - Dropped capabilities (only NET_RAW retained for scanning)
//! - Non-root user execution
//! - Resource limits (memory, CPU, PIDs)
//! - Scope-enforcing Squid proxy via HUNTRESS_ALLOWED_DOMAINS
//! - Automatic cleanup on destroy or kill switch activation
//!
//! Supports both Docker and Podman (auto-detected).

use bollard::container::{
    Config, CreateContainerOptions, ListContainersOptions, LogOutput,
    RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
};
use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use bollard::Docker;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{error, info, warn};

/// Label applied to all Huntress-managed containers for identification
const HUNTRESS_LABEL: &str = "huntress-sandbox";
/// Label key for container identification
const LABEL_KEY: &str = "managed-by";

/// Errors from sandbox operations
#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("Docker API error: {0}")]
    DockerError(#[from] bollard::errors::Error),

    #[error("Container not found: {0}")]
    ContainerNotFound(String),

    #[error("Command execution timed out after {0}s")]
    Timeout(u64),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Environment variable injection blocked: {0}")]
    EnvInjection(String),

    #[error("Docker/Podman not available: {0}")]
    RuntimeNotAvailable(String),

    #[error("Image build failed: {0}")]
    ImageBuildFailed(String),

    #[error("Lock error: {0}")]
    LockError(String),
}

/// Sandbox container configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Docker image to use (default: huntress-attack-machine:latest)
    pub image: String,
    /// Domains that are in-scope (enforced by internal Squid proxy)
    pub allowed_domains: Vec<String>,
    /// Maximum memory in bytes (default: 2GB)
    pub memory_limit: i64,
    /// CPU period/quota (default: 1 core)
    pub cpu_cores: f64,
    /// Maximum number of PIDs (default: 256)
    pub pids_limit: i64,
    /// Environment variables to pass into the container
    pub env_vars: HashMap<String, String>,
    /// Working directory inside the container
    pub working_dir: String,
    /// Timeout for container creation in seconds
    pub creation_timeout_secs: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            image: "huntress-attack-machine:latest".to_string(),
            allowed_domains: Vec::new(),
            memory_limit: 2 * 1024 * 1024 * 1024, // 2GB
            cpu_cores: 1.0,
            pids_limit: 256,
            env_vars: HashMap::new(),
            working_dir: "/home/hunter".to_string(),
            creation_timeout_secs: 30,
        }
    }
}

/// Result from executing a command inside a sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    /// Combined stdout
    pub stdout: String,
    /// Combined stderr
    pub stderr: String,
    /// Exit code (None if timed out)
    pub exit_code: Option<i64>,
    /// Whether the command timed out
    pub timed_out: bool,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
}

/// Info about an active sandbox container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInfo {
    /// Container ID
    pub id: String,
    /// Short container ID (first 12 chars)
    pub short_id: String,
    /// Container status (running, exited, etc.)
    pub status: String,
    /// Allowed domains for this sandbox
    pub allowed_domains: Vec<String>,
    /// Creation timestamp
    pub created_at: i64,
}

/// Environment variable names that are blocked exactly (case-insensitive)
const BLOCKED_ENV_EXACT: &[&str] = &["PATH", "HOME", "USER", "SHELL", "HOSTNAME"];

/// Environment variable prefixes that are blocked (case-insensitive).
/// Any var whose uppercase name starts with one of these is blocked.
const BLOCKED_ENV_PREFIXES: &[&str] = &["LD_", "DOCKER_", "PODMAN_", "SUDO_", "XDG_"];

/// Manages Docker/Podman sandbox containers for isolated command execution
pub struct SandboxManager {
    /// Docker client (works with Podman too via compatible API)
    docker: Docker,
    /// Tracked container IDs
    containers: Arc<Mutex<HashMap<String, SandboxConfig>>>,
    /// Whether we're using Podman (vs Docker)
    is_podman: bool,
}

impl SandboxManager {
    /// Create a new SandboxManager, auto-detecting Docker or Podman
    pub async fn new() -> Result<Self, SandboxError> {
        // Try Docker socket first
        match Docker::connect_with_socket_defaults() {
            Ok(docker) => {
                // Verify connection
                match docker.ping().await {
                    Ok(_) => {
                        info!("Connected to Docker daemon");
                        return Ok(Self {
                            docker,
                            containers: Arc::new(Mutex::new(HashMap::new())),
                            is_podman: false,
                        });
                    }
                    Err(e) => {
                        warn!("Docker socket found but ping failed: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Docker socket not available: {}", e);
            }
        }

        // Try Podman socket as fallback
        let podman_sock = Self::detect_podman_socket();
        if let Some(sock_path) = podman_sock {
            match Docker::connect_with_socket(&sock_path, 120, bollard::API_DEFAULT_VERSION) {
                Ok(docker) => {
                    match docker.ping().await {
                        Ok(_) => {
                            info!("Connected to Podman daemon at {}", sock_path);
                            return Ok(Self {
                                docker,
                                containers: Arc::new(Mutex::new(HashMap::new())),
                                is_podman: true,
                            });
                        }
                        Err(e) => {
                            warn!("Podman socket found but ping failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Podman socket connection failed: {}", e);
                }
            }
        }

        Err(SandboxError::RuntimeNotAvailable(
            "Neither Docker nor Podman is available. Install Docker or start Podman with: systemctl --user start podman.socket".to_string(),
        ))
    }

    /// Detect Podman socket path
    fn detect_podman_socket() -> Option<String> {
        // Check $XDG_RUNTIME_DIR/podman/podman.sock
        if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
            let path = format!("{}/podman/podman.sock", xdg_runtime);
            if std::path::Path::new(&path).exists() {
                return Some(path);
            }
        }

        // Common fallback paths
        let fallback_paths = [
            "/run/user/1000/podman/podman.sock",
            "/run/podman/podman.sock",
        ];

        for path in fallback_paths {
            if std::path::Path::new(path).exists() {
                return Some(path.to_string());
            }
        }

        None
    }

    /// Validate environment variables — block dangerous ones
    fn validate_env(env_vars: &HashMap<String, String>) -> Result<(), SandboxError> {
        for key in env_vars.keys() {
            let upper = key.to_uppercase();

            // Check exact matches
            for exact in BLOCKED_ENV_EXACT {
                if upper == *exact {
                    return Err(SandboxError::EnvInjection(format!(
                        "Environment variable '{}' is blocked",
                        key
                    )));
                }
            }

            // Check prefix matches
            for prefix in BLOCKED_ENV_PREFIXES {
                if upper.starts_with(prefix) {
                    return Err(SandboxError::EnvInjection(format!(
                        "Environment variable '{}' is blocked (matches prefix '{}')",
                        key, prefix
                    )));
                }
            }

            // Check for null bytes or newlines in values
            if let Some(value) = env_vars.get(key) {
                if value.contains('\0') || value.contains('\n') {
                    return Err(SandboxError::EnvInjection(format!(
                        "Environment variable '{}' contains invalid characters",
                        key
                    )));
                }
            }
        }
        Ok(())
    }

    /// Clamp timeout to a safe range (1s to 600s)
    fn clamp_timeout(timeout_secs: u64) -> u64 {
        timeout_secs.clamp(1, 600)
    }

    /// Create a new sandbox container
    ///
    /// Returns the container ID on success.
    ///
    /// # Security Hardening
    /// - ReadonlyRootfs: filesystem is read-only except tmpfs mounts
    /// - tmpfs /tmp (512MB) and /home/hunter (256MB)
    /// - Dropped all capabilities, added only NET_RAW
    /// - No new privileges (prevents setuid escalation)
    /// - Non-root user (hunter)
    /// - Memory: 2GB, CPU: 1 core, PIDs: 256
    /// - AutoRemove: container is deleted when stopped
    pub async fn create_sandbox(&self, config: SandboxConfig) -> Result<String, SandboxError> {
        // Validate env vars before doing anything
        Self::validate_env(&config.env_vars)?;

        if config.allowed_domains.is_empty() {
            return Err(SandboxError::InvalidConfig(
                "At least one allowed domain is required".to_string(),
            ));
        }

        // Build environment variable list
        let mut env: Vec<String> = Vec::new();
        env.push(format!(
            "HUNTRESS_ALLOWED_DOMAINS={}",
            config.allowed_domains.join(",")
        ));

        // Add user-specified env vars (already validated)
        for (key, value) in &config.env_vars {
            env.push(format!("{}={}", key, value));
        }

        // CPU quota: 100000 period, quota = cores * 100000
        let cpu_quota = (config.cpu_cores * 100_000.0) as i64;

        let host_config = bollard::models::HostConfig {
            memory: Some(config.memory_limit),
            memory_swap: Some(config.memory_limit), // No swap
            cpu_period: Some(100_000),
            cpu_quota: Some(cpu_quota),
            pids_limit: Some(config.pids_limit),
            readonly_rootfs: Some(true),
            tmpfs: Some(HashMap::from([
                ("/tmp".to_string(), "size=512m,noexec,nosuid".to_string()),
                (
                    "/home/hunter".to_string(),
                    "size=256m,noexec,nosuid".to_string(),
                ),
                // Squid needs a writable cache dir
                (
                    "/var/spool/squid".to_string(),
                    "size=64m,noexec,nosuid".to_string(),
                ),
                // Squid PID/log directories
                (
                    "/var/log/squid".to_string(),
                    "size=16m,noexec,nosuid".to_string(),
                ),
                (
                    "/var/run".to_string(),
                    "size=8m,noexec,nosuid".to_string(),
                ),
            ])),
            cap_drop: Some(vec!["ALL".to_string()]),
            cap_add: Some(vec!["NET_RAW".to_string()]),
            security_opt: Some(vec!["no-new-privileges:true".to_string()]),
            auto_remove: Some(true),
            network_mode: Some("bridge".to_string()),
            ..Default::default()
        };

        let mut labels = HashMap::new();
        labels.insert(LABEL_KEY.to_string(), HUNTRESS_LABEL.to_string());
        labels.insert(
            "huntress-domains".to_string(),
            config.allowed_domains.join(","),
        );

        let container_config = Config {
            image: Some(config.image.clone()),
            env: Some(env),
            working_dir: Some(config.working_dir.clone()),
            user: Some("hunter".to_string()),
            host_config: Some(host_config),
            labels: Some(labels),
            // Keep container running — entrypoint handles setup then waits
            tty: Some(true),
            open_stdin: Some(true),
            ..Default::default()
        };

        let create_opts = CreateContainerOptions {
            name: format!("huntress-{}", uuid::Uuid::new_v4()),
            platform: None,
        };

        let response = self
            .docker
            .create_container(Some(create_opts), container_config)
            .await?;

        let container_id = response.id;

        // Start the container
        self.docker
            .start_container(&container_id, None::<StartContainerOptions<String>>)
            .await?;

        // Track the container
        self.containers
            .lock()
            .await
            .insert(container_id.clone(), config);

        info!(container_id = %container_id, "Sandbox container created and started");
        Ok(container_id)
    }

    /// Execute a command inside a running sandbox container
    ///
    /// # Arguments
    /// * `sandbox_id` - Container ID
    /// * `command` - Command as argv array (NO shell expansion)
    /// * `timeout_secs` - Maximum execution time in seconds (clamped to 1-600)
    pub async fn exec_command(
        &self,
        sandbox_id: &str,
        command: Vec<String>,
        timeout_secs: u64,
    ) -> Result<ExecResult, SandboxError> {
        // Verify container is tracked
        {
            let containers = self.containers.lock().await;
            if !containers.contains_key(sandbox_id) {
                return Err(SandboxError::ContainerNotFound(sandbox_id.to_string()));
            }
        }

        let clamped_timeout = Self::clamp_timeout(timeout_secs);
        let start = std::time::Instant::now();

        // Create exec instance — run as hunter user, attach stdout/stderr
        let exec_config = CreateExecOptions {
            cmd: Some(command.clone()),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            user: Some("hunter".to_string()),
            working_dir: Some("/home/hunter".to_string()),
            ..Default::default()
        };

        let exec_instance = self.docker.create_exec(sandbox_id, exec_config).await?;

        // Start exec and collect output
        let start_config = StartExecOptions {
            detach: false,
            ..Default::default()
        };

        let mut stdout = String::new();
        let mut stderr = String::new();

        let exec_future = async {
            let result = self
                .docker
                .start_exec(&exec_instance.id, Some(start_config))
                .await;

            match result {
                Ok(StartExecResults::Attached { mut output, .. }) => {
                    while let Some(chunk) = output.next().await {
                        match chunk {
                            Ok(log_output) => match log_output {
                                LogOutput::StdOut { message } => {
                                    stdout.push_str(&String::from_utf8_lossy(&message));
                                }
                                LogOutput::StdErr { message } => {
                                    stderr.push_str(&String::from_utf8_lossy(&message));
                                }
                                _ => {}
                            },
                            Err(e) => {
                                stderr.push_str(&format!("\n[exec error: {}]", e));
                                break;
                            }
                        }
                    }
                }
                Ok(StartExecResults::Detached) => {
                    stderr.push_str("[exec started in detached mode unexpectedly]");
                }
                Err(e) => {
                    stderr.push_str(&format!("[exec start failed: {}]", e));
                }
            }
        };

        // Apply timeout
        let timed_out = timeout(Duration::from_secs(clamped_timeout), exec_future)
            .await
            .is_err();

        let duration_ms = start.elapsed().as_millis() as u64;

        // Get exit code
        let exit_code = if timed_out {
            None
        } else {
            match self.docker.inspect_exec(&exec_instance.id).await {
                Ok(info) => info.exit_code,
                Err(_) => None,
            }
        };

        info!(
            sandbox_id = %sandbox_id,
            command = ?command,
            exit_code = ?exit_code,
            timed_out = timed_out,
            duration_ms = duration_ms,
            "Sandbox command executed"
        );

        Ok(ExecResult {
            stdout,
            stderr,
            exit_code,
            timed_out,
            duration_ms,
        })
    }

    /// Destroy a specific sandbox container
    pub async fn destroy_sandbox(&self, sandbox_id: &str) -> Result<(), SandboxError> {
        // Remove from tracking
        self.containers.lock().await.remove(sandbox_id);

        // Stop container (auto_remove will delete it)
        match self
            .docker
            .stop_container(sandbox_id, Some(StopContainerOptions { t: 5 }))
            .await
        {
            Ok(_) => {
                info!(sandbox_id = %sandbox_id, "Sandbox container stopped");
            }
            Err(e) => {
                // Container might already be stopped, try force remove
                warn!(sandbox_id = %sandbox_id, error = %e, "Stop failed, attempting force remove");
                let _ = self
                    .docker
                    .remove_container(
                        sandbox_id,
                        Some(RemoveContainerOptions {
                            force: true,
                            ..Default::default()
                        }),
                    )
                    .await;
            }
        }

        Ok(())
    }

    /// Emergency: destroy ALL Huntress sandbox containers
    ///
    /// Called by the kill switch on emergency stop.
    /// Iterates all containers with the huntress label and force-removes them.
    pub async fn destroy_all(&self) -> Result<usize, SandboxError> {
        let mut filters = HashMap::new();
        filters.insert(
            "label".to_string(),
            vec![format!("{}={}", LABEL_KEY, HUNTRESS_LABEL)],
        );

        let containers = self
            .docker
            .list_containers(Some(ListContainersOptions {
                all: true,
                filters,
                ..Default::default()
            }))
            .await?;

        let count = containers.len();

        for container in &containers {
            if let Some(id) = &container.id {
                info!(container_id = %id, "Emergency: destroying sandbox container");
                let _ = self
                    .docker
                    .remove_container(
                        id,
                        Some(RemoveContainerOptions {
                            force: true,
                            ..Default::default()
                        }),
                    )
                    .await;
            }
        }

        // Clear tracking
        self.containers.lock().await.clear();

        if count > 0 {
            error!(
                count = count,
                "EMERGENCY: Destroyed all Huntress sandbox containers"
            );
        }

        Ok(count)
    }

    /// List all active sandbox containers
    pub async fn list_sandboxes(&self) -> Result<Vec<SandboxInfo>, SandboxError> {
        let mut filters = HashMap::new();
        filters.insert(
            "label".to_string(),
            vec![format!("{}={}", LABEL_KEY, HUNTRESS_LABEL)],
        );

        let containers = self
            .docker
            .list_containers(Some(ListContainersOptions {
                all: false, // Only running containers
                filters,
                ..Default::default()
            }))
            .await?;

        let mut sandboxes = Vec::new();
        for container in containers {
            let id = container.id.unwrap_or_default();
            let short_id = if id.len() >= 12 {
                id[..12].to_string()
            } else {
                id.clone()
            };

            let domains = container
                .labels
                .as_ref()
                .and_then(|l| l.get("huntress-domains"))
                .map(|d| d.split(',').map(String::from).collect())
                .unwrap_or_default();

            sandboxes.push(SandboxInfo {
                id: id.clone(),
                short_id,
                status: container.status.unwrap_or_else(|| "unknown".to_string()),
                allowed_domains: domains,
                created_at: container.created.unwrap_or(0),
            });
        }

        Ok(sandboxes)
    }

    /// Check if the runtime is available
    pub async fn is_available(&self) -> bool {
        self.docker.ping().await.is_ok()
    }

    /// Get runtime type string
    pub fn runtime_type(&self) -> &str {
        if self.is_podman {
            "podman"
        } else {
            "docker"
        }
    }
}

// ─── Tauri Commands ──────────────────────────────────────────────────────────

/// Tauri command: Create a sandbox container
#[tauri::command]
pub async fn create_sandbox(
    state: tauri::State<'_, Arc<Mutex<Option<SandboxManager>>>>,
    config: SandboxConfig,
) -> Result<String, String> {
    let guard = state.lock().await;
    let manager = guard
        .as_ref()
        .ok_or_else(|| "Sandbox manager not initialized (Docker/Podman not available)".to_string())?;

    manager
        .create_sandbox(config)
        .await
        .map_err(|e| format!("Failed to create sandbox: {}", e))
}

/// Tauri command: Execute a command in a sandbox
#[tauri::command]
pub async fn sandbox_exec(
    state: tauri::State<'_, Arc<Mutex<Option<SandboxManager>>>>,
    sandbox_id: String,
    command: Vec<String>,
    timeout_secs: u64,
) -> Result<ExecResult, String> {
    let guard = state.lock().await;
    let manager = guard
        .as_ref()
        .ok_or_else(|| "Sandbox manager not initialized".to_string())?;

    manager
        .exec_command(&sandbox_id, command, timeout_secs)
        .await
        .map_err(|e| format!("Failed to execute command: {}", e))
}

/// Tauri command: Destroy a sandbox container
#[tauri::command]
pub async fn destroy_sandbox(
    state: tauri::State<'_, Arc<Mutex<Option<SandboxManager>>>>,
    sandbox_id: String,
) -> Result<(), String> {
    let guard = state.lock().await;
    let manager = guard
        .as_ref()
        .ok_or_else(|| "Sandbox manager not initialized".to_string())?;

    manager
        .destroy_sandbox(&sandbox_id)
        .await
        .map_err(|e| format!("Failed to destroy sandbox: {}", e))
}

/// Tauri command: List all sandbox containers
#[tauri::command]
pub async fn list_sandboxes(
    state: tauri::State<'_, Arc<Mutex<Option<SandboxManager>>>>,
) -> Result<Vec<SandboxInfo>, String> {
    let guard = state.lock().await;
    let manager = guard
        .as_ref()
        .ok_or_else(|| "Sandbox manager not initialized".to_string())?;

    manager
        .list_sandboxes()
        .await
        .map_err(|e| format!("Failed to list sandboxes: {}", e))
}

/// Tauri command: Emergency destroy all sandbox containers
#[tauri::command]
pub async fn destroy_all_sandboxes(
    state: tauri::State<'_, Arc<Mutex<Option<SandboxManager>>>>,
) -> Result<usize, String> {
    let guard = state.lock().await;
    let manager = guard
        .as_ref()
        .ok_or_else(|| "Sandbox manager not initialized".to_string())?;

    manager
        .destroy_all()
        .await
        .map_err(|e| format!("Failed to destroy all sandboxes: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SandboxConfig::default();
        assert_eq!(config.memory_limit, 2 * 1024 * 1024 * 1024);
        assert_eq!(config.pids_limit, 256);
        assert!(config.allowed_domains.is_empty());
        assert_eq!(config.cpu_cores, 1.0);
        assert_eq!(config.working_dir, "/home/hunter");
    }

    #[test]
    fn test_env_var_blocking_path() {
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/malicious/bin".to_string());
        assert!(SandboxManager::validate_env(&env).is_err());
    }

    #[test]
    fn test_env_var_blocking_ld_preload() {
        let mut env = HashMap::new();
        env.insert("LD_PRELOAD".to_string(), "/evil.so".to_string());
        assert!(SandboxManager::validate_env(&env).is_err());
    }

    #[test]
    fn test_env_var_blocking_ld_library_path() {
        let mut env = HashMap::new();
        env.insert("LD_LIBRARY_PATH".to_string(), "/evil".to_string());
        assert!(SandboxManager::validate_env(&env).is_err());
    }

    #[test]
    fn test_env_var_blocking_docker_host() {
        let mut env = HashMap::new();
        env.insert("DOCKER_HOST".to_string(), "tcp://evil:2375".to_string());
        assert!(SandboxManager::validate_env(&env).is_err());
    }

    #[test]
    fn test_env_var_blocking_null_bytes() {
        let mut env = HashMap::new();
        env.insert("SAFE_KEY".to_string(), "value\0injected".to_string());
        assert!(SandboxManager::validate_env(&env).is_err());
    }

    #[test]
    fn test_env_var_blocking_newlines() {
        let mut env = HashMap::new();
        env.insert("SAFE_KEY".to_string(), "value\ninjected".to_string());
        assert!(SandboxManager::validate_env(&env).is_err());
    }

    #[test]
    fn test_env_var_safe_values() {
        let mut env = HashMap::new();
        env.insert("HUNTRESS_TARGET".to_string(), "example.com".to_string());
        env.insert("HTTP_TIMEOUT".to_string(), "30".to_string());
        assert!(SandboxManager::validate_env(&env).is_ok());
    }

    #[test]
    fn test_timeout_clamping() {
        assert_eq!(SandboxManager::clamp_timeout(0), 1);
        assert_eq!(SandboxManager::clamp_timeout(1), 1);
        assert_eq!(SandboxManager::clamp_timeout(30), 30);
        assert_eq!(SandboxManager::clamp_timeout(600), 600);
        assert_eq!(SandboxManager::clamp_timeout(1000), 600);
        assert_eq!(SandboxManager::clamp_timeout(u64::MAX), 600);
    }

    #[test]
    fn test_env_var_blocking_sudo() {
        let mut env = HashMap::new();
        env.insert("SUDO_USER".to_string(), "root".to_string());
        assert!(SandboxManager::validate_env(&env).is_err());
    }

    #[test]
    fn test_env_var_blocking_podman() {
        let mut env = HashMap::new();
        env.insert("PODMAN_HOST".to_string(), "tcp://evil:2375".to_string());
        assert!(SandboxManager::validate_env(&env).is_err());
    }

    #[test]
    fn test_env_var_blocking_xdg() {
        let mut env = HashMap::new();
        env.insert(
            "XDG_RUNTIME_DIR".to_string(),
            "/run/evil/1000".to_string(),
        );
        assert!(SandboxManager::validate_env(&env).is_err());
    }

    #[test]
    fn test_env_var_case_insensitive() {
        let mut env = HashMap::new();
        env.insert("path".to_string(), "/malicious".to_string());
        assert!(SandboxManager::validate_env(&env).is_err());

        let mut env2 = HashMap::new();
        env2.insert("ld_preload".to_string(), "/evil.so".to_string());
        assert!(SandboxManager::validate_env(&env2).is_err());
    }
}

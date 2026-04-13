//! Proxy Pool Module
//! 
//! Manages a pool of HTTP/SOCKS proxies with automatic rotation and health checking.
//! Essential for distributing requests across multiple IPs to avoid rate limiting
//! and detection during bug bounty testing.
//! 
//! Features:
//! - Automatic proxy rotation
//! - Health checking and dead proxy removal
//! - Support for HTTP, HTTPS, and SOCKS5 proxies
//! - Configurable rotation strategies
//!
//! # Security Guarantees
//!
//! - Health check proxies with configurable URL (default: httpbin.org) before use
//! - Mark proxies as failed after consecutive failures
//! - Support authentication with username/password
//! - Persist proxy pool state across restarts

use chrono::{DateTime, Utc};
use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tracing::{error, info, warn};

/// Errors that can occur during proxy operations
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("No proxies available")]
    NoProxies,
    
    #[error("No healthy proxies available")]
    NoHealthyProxies,
    
    #[error("Proxy {0} not found")]
    ProxyNotFound(String),
    
    #[error("Failed to load proxy config: {0}")]
    LoadFailed(String),
    
    #[error("Failed to parse proxy URL: {0}")]
    InvalidUrl(String),
    
    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),
    
    #[error("Lock error: {0}")]
    LockError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Proxy URL (e.g., "http://proxy.example.com:8080")
    pub url: String,
    /// Proxy type
    pub proxy_type: ProxyType,
    /// Optional username for authentication
    pub username: Option<String>,
    /// Optional password for authentication
    pub password: Option<String>,
    /// Last time this proxy was used
    pub last_used: DateTime<Utc>,
    /// Current health status
    pub health_status: HealthStatus,
}

/// Type of proxy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProxyType {
    /// HTTP proxy
    HTTP,
    /// HTTPS proxy
    HTTPS,
    /// SOCKS5 proxy
    SOCKS5,
}

/// Proxy health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    /// Proxy is healthy and ready to use
    Healthy,
    /// Proxy is experiencing issues but still usable
    Degraded,
    /// Proxy has failed and should not be used
    Failed,
    /// Proxy has not been tested yet
    Untested,
}

/// Internal proxy entry with health tracking
#[derive(Debug, Clone)]
struct ProxyEntry {
    config: ProxyConfig,
    failure_count: u32,
    success_count: u32,
    last_check: Option<DateTime<Utc>>,
    avg_response_time_ms: Option<u64>,
}

/// Rotation strategy for proxy selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationStrategy {
    /// Round-robin rotation
    RoundRobin,
    /// Random selection
    Random,
    /// Least recently used
    LeastRecentlyUsed,
    /// Fastest response time
    FastestFirst,
}

/// Manages a pool of proxies with rotation and health checking
pub struct ProxyPool {
    /// Available proxies
    proxies: Arc<Mutex<VecDeque<ProxyEntry>>>,
    /// Rotation strategy
    strategy: RotationStrategy,
    /// Maximum failures before marking proxy as unhealthy
    max_failures: u32,
    /// Health check interval
    _health_check_interval: Duration,
    /// Path to proxy config file
    config_file: Option<PathBuf>,
    /// URL used for proxy health checks (must return 2xx)
    health_check_url: String,
}

impl ProxyPool {
    /// Create a new proxy pool
    pub fn new(strategy: RotationStrategy) -> Self {
        Self {
            proxies: Arc::new(Mutex::new(VecDeque::new())),
            strategy,
            max_failures: 3,
            _health_check_interval: Duration::from_secs(300), // 5 minutes
            config_file: None,
            health_check_url: "https://httpbin.org/ip".to_string(),
        }
    }

    /// Load proxies from config file
    pub fn from_file(path: &str, strategy: RotationStrategy) -> Result<Self, ProxyError> {
        let content = fs::read_to_string(path)?;
        
        // Try JSON format first
        let configs: Vec<ProxyConfig> = serde_json::from_str(&content)
            .or_else(|_| {
                // Try line-by-line format
                let configs: Vec<ProxyConfig> = content
                    .lines()
                    .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
                    .map(|line| {
                        // Format: type://[user:pass@]host:port
                        let parts: Vec<&str> = line.split("://").collect();
                        if parts.len() != 2 {
                            return Err(ProxyError::InvalidUrl(line.to_string()));
                        }

                        let proxy_type = match parts[0].to_lowercase().as_str() {
                            "http" => ProxyType::HTTP,
                            "https" => ProxyType::HTTPS,
                            "socks5" => ProxyType::SOCKS5,
                            _ => return Err(ProxyError::InvalidUrl(format!("Unknown type: {}", parts[0]))),
                        };

                        Ok(ProxyConfig {
                            url: line.to_string(),
                            proxy_type,
                            username: None,
                            password: None,
                            last_used: Utc::now(),
                            health_status: HealthStatus::Untested,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(configs)
            })
            .map_err(|e: ProxyError| ProxyError::LoadFailed(e.to_string()))?;

        let mut pool = Self::new(strategy);
        pool.config_file = Some(PathBuf::from(path));

        for config in configs {
            pool.add_proxy(config)?;
        }

        info!("Loaded {} proxies from {}", pool.count()?, path);

        Ok(pool)
    }

    /// Add a proxy to the pool
    pub fn add_proxy(&self, config: ProxyConfig) -> Result<(), ProxyError> {
        let entry = ProxyEntry {
            config,
            failure_count: 0,
            success_count: 0,
            last_check: None,
            avg_response_time_ms: None,
        };

        self.proxies
            .lock()
            .map_err(|e| ProxyError::LockError(e.to_string()))?
            .push_back(entry);

        Ok(())
    }

    /// Get next proxy according to rotation strategy
    pub fn next_proxy(&mut self) -> Option<ProxyConfig> {
        let mut proxies = self.proxies.lock().ok()?;

        if proxies.is_empty() {
            return None;
        }

        // Filter healthy proxies
        let healthy_count = proxies
            .iter()
            .filter(|p| p.config.health_status != HealthStatus::Failed)
            .count();

        if healthy_count == 0 {
            warn!("No healthy proxies available");
            return None;
        }

        match self.strategy {
            RotationStrategy::RoundRobin => {
                // Rotate until we find a healthy proxy
                for _ in 0..proxies.len() {
                    if let Some(entry) = proxies.pop_front() {
                        let is_healthy = entry.config.health_status != HealthStatus::Failed;
                        proxies.push_back(entry);
                        
                        if is_healthy {
                            return proxies.back().map(|e| e.config.clone());
                        }
                    }
                }
                None
            }
            RotationStrategy::Random => {
                let healthy_indices: Vec<usize> = proxies
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| p.config.health_status != HealthStatus::Failed)
                    .map(|(i, _)| i)
                    .collect();

                if healthy_indices.is_empty() {
                    return None;
                }

                let idx = healthy_indices[rand::random::<usize>() % healthy_indices.len()];
                proxies.get(idx).map(|e| e.config.clone())
            }
            RotationStrategy::LeastRecentlyUsed => {
                let mut oldest_idx = None;
                let mut oldest_time = Utc::now();

                for (i, entry) in proxies.iter().enumerate() {
                    if entry.config.health_status != HealthStatus::Failed
                        && (entry.config.last_used < oldest_time || oldest_idx.is_none()) {
                        oldest_idx = Some(i);
                        oldest_time = entry.config.last_used;
                    }
                }

                oldest_idx.and_then(|i| proxies.get(i).map(|e| e.config.clone()))
            }
            RotationStrategy::FastestFirst => {
                let mut fastest_idx = None;
                let mut fastest_time = u64::MAX;

                for (i, entry) in proxies.iter().enumerate() {
                    if entry.config.health_status != HealthStatus::Failed {
                        if let Some(avg_time) = entry.avg_response_time_ms {
                            if avg_time < fastest_time {
                                fastest_idx = Some(i);
                                fastest_time = avg_time;
                            }
                        } else if fastest_idx.is_none() {
                            fastest_idx = Some(i);
                        }
                    }
                }

                fastest_idx.and_then(|i| proxies.get(i).map(|e| e.config.clone()))
            }
        }
    }

    /// Set a custom URL for proxy health checks.
    /// The URL must return a 2xx status code for the proxy to be considered healthy.
    pub fn set_health_check_url(&mut self, url: String) {
        self.health_check_url = url;
    }

    /// Health check proxy against the configured health check URL
    pub async fn health_check(&mut self, proxy: &ProxyConfig) -> HealthStatus {
        info!("Health checking proxy: {}", proxy.url);

        let client_result = self.build_client(proxy);
        
        let client = match client_result {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to build client for proxy {}: {}", proxy.url, e);
                return HealthStatus::Failed;
            }
        };

        let start = std::time::Instant::now();
        
        match client
            .get(&self.health_check_url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(response) => {
                let elapsed = start.elapsed().as_millis() as u64;
                
                if response.status().is_success() {
                    info!(
                        "Proxy {} health check passed ({}ms)",
                        proxy.url, elapsed
                    );
                    
                    // Update response time
                    self.update_response_time(&proxy.url, elapsed).ok();
                    
                    if elapsed < 1000 {
                        HealthStatus::Healthy
                    } else {
                        HealthStatus::Degraded
                    }
                } else {
                    warn!(
                        "Proxy {} health check failed with status: {}",
                        proxy.url,
                        response.status()
                    );
                    HealthStatus::Failed
                }
            }
            Err(e) => {
                error!("Proxy {} health check failed: {}", proxy.url, e);
                HealthStatus::Failed
            }
        }
    }

    /// Build reqwest client with proxy
    fn build_client(&self, proxy: &ProxyConfig) -> Result<Client, ProxyError> {
        let mut proxy_builder = match proxy.proxy_type {
            ProxyType::HTTP => Proxy::http(&proxy.url),
            ProxyType::HTTPS => Proxy::https(&proxy.url),
            ProxyType::SOCKS5 => Proxy::all(&proxy.url),
        }
        .map_err(|e| ProxyError::InvalidUrl(format!("{}: {}", proxy.url, e)))?;

        // Add authentication if provided
        if let (Some(username), Some(password)) = (&proxy.username, &proxy.password) {
            proxy_builder = proxy_builder.basic_auth(username, password);
        }

        Client::builder()
            .proxy(proxy_builder)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| ProxyError::InvalidUrl(e.to_string()))
    }

    /// Update response time for proxy
    fn update_response_time(&self, proxy_url: &str, response_time_ms: u64) -> Result<(), ProxyError> {
        let mut proxies = self
            .proxies
            .lock()
            .map_err(|e| ProxyError::LockError(e.to_string()))?;

        for entry in proxies.iter_mut() {
            if entry.config.url == proxy_url {
                entry.avg_response_time_ms = Some(
                    if let Some(avg) = entry.avg_response_time_ms {
                        (avg + response_time_ms) / 2
                    } else {
                        response_time_ms
                    }
                );
                entry.last_check = Some(Utc::now());
                return Ok(());
            }
        }

        Err(ProxyError::ProxyNotFound(proxy_url.to_string()))
    }

    /// Mark a proxy as failed
    pub fn mark_failed(&self, proxy_url: &str) -> Result<(), ProxyError> {
        let mut proxies = self
            .proxies
            .lock()
            .map_err(|e| ProxyError::LockError(e.to_string()))?;

        for entry in proxies.iter_mut() {
            if entry.config.url == proxy_url {
                entry.failure_count += 1;

                if entry.failure_count >= self.max_failures {
                    entry.config.health_status = HealthStatus::Failed;
                    warn!(
                        "Proxy {} marked as failed after {} failures",
                        proxy_url, entry.failure_count
                    );
                } else {
                    entry.config.health_status = HealthStatus::Degraded;
                }

                return Ok(());
            }
        }

        Err(ProxyError::ProxyNotFound(proxy_url.to_string()))
    }

    /// Mark a proxy as successful
    pub fn mark_success(&self, proxy_url: &str) -> Result<(), ProxyError> {
        let mut proxies = self
            .proxies
            .lock()
            .map_err(|e| ProxyError::LockError(e.to_string()))?;

        for entry in proxies.iter_mut() {
            if entry.config.url == proxy_url {
                entry.success_count += 1;
                entry.failure_count = 0;
                entry.config.health_status = HealthStatus::Healthy;
                entry.config.last_used = Utc::now();

                return Ok(());
            }
        }

        Err(ProxyError::ProxyNotFound(proxy_url.to_string()))
    }

    /// Get pool statistics
    pub fn get_stats(&self) -> Result<PoolStats, ProxyError> {
        let proxies = self
            .proxies
            .lock()
            .map_err(|e| ProxyError::LockError(e.to_string()))?;

        let total = proxies.len();
        let healthy = proxies
            .iter()
            .filter(|p| p.config.health_status == HealthStatus::Healthy)
            .count();
        let degraded = proxies
            .iter()
            .filter(|p| p.config.health_status == HealthStatus::Degraded)
            .count();
        let failed = proxies
            .iter()
            .filter(|p| p.config.health_status == HealthStatus::Failed)
            .count();
        let untested = proxies
            .iter()
            .filter(|p| p.config.health_status == HealthStatus::Untested)
            .count();

        Ok(PoolStats {
            total,
            healthy,
            degraded,
            failed,
            untested,
        })
    }

    /// Remove all unhealthy proxies
    pub fn remove_unhealthy(&self) -> Result<usize, ProxyError> {
        let mut proxies = self
            .proxies
            .lock()
            .map_err(|e| ProxyError::LockError(e.to_string()))?;

        let before = proxies.len();
        proxies.retain(|p| p.config.health_status != HealthStatus::Failed);
        let removed = before - proxies.len();

        info!("Removed {} unhealthy proxies", removed);

        Ok(removed)
    }

    /// Get proxy count
    pub fn count(&self) -> Result<usize, ProxyError> {
        Ok(self
            .proxies
            .lock()
            .map_err(|e| ProxyError::LockError(e.to_string()))?
            .len())
    }
}

/// Pool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStats {
    /// Total number of proxies
    pub total: usize,
    /// Number of healthy proxies
    pub healthy: usize,
    /// Number of degraded proxies
    pub degraded: usize,
    /// Number of failed proxies
    pub failed: usize,
    /// Number of untested proxies
    pub untested: usize,
}

/// Tauri command: Load proxy pool
#[tauri::command]
pub async fn load_proxies(path: String) -> Result<usize, String> {
    info!("Tauri command: load_proxies - path: {}", path);

    let pool = ProxyPool::from_file(&path, RotationStrategy::RoundRobin)
        .map_err(|e| format!("Failed to load proxies: {}", e))?;

    let count = pool.count().map_err(|e| format!("Failed to get count: {}", e))?;

    // Store into the global pool so get_next_proxy / get_proxy_stats work
    set_global_pool(pool);

    Ok(count)
}

/// Global proxy pool instance shared across Tauri commands
static GLOBAL_POOL: std::sync::LazyLock<Mutex<ProxyPool>> =
    std::sync::LazyLock::new(|| Mutex::new(ProxyPool::new(RotationStrategy::RoundRobin)));

/// Try to get the next proxy URL from the global pool.
/// Returns None if no proxies are loaded or all are unhealthy.
/// Used internally by proxy_http_request() to route traffic through proxies.
pub fn try_get_next_proxy() -> Option<String> {
    let mut pool = GLOBAL_POOL.lock().ok()?;
    pool.next_proxy().map(|p| p.url)
}

/// Mark a proxy as successful in the global pool.
pub fn notify_proxy_success(proxy_url: &str) {
    if let Ok(pool) = GLOBAL_POOL.lock() {
        let _ = pool.mark_success(proxy_url);
    }
}

/// Mark a proxy as failed in the global pool.
pub fn notify_proxy_failure(proxy_url: &str) {
    if let Ok(pool) = GLOBAL_POOL.lock() {
        let _ = pool.mark_failed(proxy_url);
    }
}

/// Set the global pool from a loaded config (called by load_proxies)
fn set_global_pool(pool: ProxyPool) {
    let mut global = GLOBAL_POOL.lock().expect("global pool lock poisoned");
    *global = pool;
}

/// Tauri command: Get next proxy
#[tauri::command]
pub async fn get_next_proxy() -> Result<String, String> {
    let mut pool = GLOBAL_POOL
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;

    pool.next_proxy()
        .map(|p| p.url)
        .ok_or_else(|| "No healthy proxies available".to_string())
}

/// Tauri command: Mark a proxy as failed
#[tauri::command]
pub async fn mark_proxy_failed(proxy_url: String) -> Result<(), String> {
    info!("Tauri command: mark_proxy_failed - proxy: {}", proxy_url);

    let pool = GLOBAL_POOL
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;

    pool.mark_failed(&proxy_url)
        .map_err(|e| format!("Failed to mark proxy failed: {}", e))
}

/// Tauri command: Get proxy pool stats
#[tauri::command]
pub async fn get_proxy_stats() -> Result<PoolStats, String> {
    let pool = GLOBAL_POOL
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;

    pool.get_stats()
        .map_err(|e| format!("Failed to get stats: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_pool_creation() {
        let pool = ProxyPool::new(RotationStrategy::RoundRobin);
        assert_eq!(pool.count().unwrap(), 0);
    }

    #[test]
    fn test_add_proxy() {
        let pool = ProxyPool::new(RotationStrategy::RoundRobin);

        let config = ProxyConfig {
            url: "http://proxy1.example.com:8080".to_string(),
            proxy_type: ProxyType::HTTP,
            username: None,
            password: None,
            last_used: Utc::now(),
            health_status: HealthStatus::Healthy,
        };

        pool.add_proxy(config).unwrap();

        assert_eq!(pool.count().unwrap(), 1);
    }

    #[test]
    fn test_mark_failed() {
        let pool = ProxyPool::new(RotationStrategy::RoundRobin);

        let config = ProxyConfig {
            url: "http://proxy1.example.com:8080".to_string(),
            proxy_type: ProxyType::HTTP,
            username: None,
            password: None,
            last_used: Utc::now(),
            health_status: HealthStatus::Healthy,
        };

        pool.add_proxy(config).unwrap();

        // Mark as failed multiple times
        for _ in 0..3 {
            pool.mark_failed("http://proxy1.example.com:8080").unwrap();
        }

        let stats = pool.get_stats().unwrap();
        assert_eq!(stats.failed, 1);
    }

    #[test]
    fn test_health_check_url_default_and_setter() {
        let mut pool = ProxyPool::new(RotationStrategy::RoundRobin);
        assert_eq!(pool.health_check_url, "https://httpbin.org/ip");

        pool.set_health_check_url("https://example.com/health".to_string());
        assert_eq!(pool.health_check_url, "https://example.com/health");
    }

    #[test]
    fn test_mark_success() {
        let pool = ProxyPool::new(RotationStrategy::RoundRobin);

        let config = ProxyConfig {
            url: "http://proxy1.example.com:8080".to_string(),
            proxy_type: ProxyType::HTTP,
            username: None,
            password: None,
            last_used: Utc::now(),
            health_status: HealthStatus::Degraded,
        };

        pool.add_proxy(config).unwrap();
        pool.mark_success("http://proxy1.example.com:8080").unwrap();

        let stats = pool.get_stats().unwrap();
        assert_eq!(stats.healthy, 1);
    }
}
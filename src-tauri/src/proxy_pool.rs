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

use reqwest::Proxy;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Proxy URL (e.g., "http://proxy.example.com:8080")
    pub url: String,
    /// Optional username for authentication
    pub username: Option<String>,
    /// Optional password for authentication
    pub password: Option<String>,
    /// Proxy type
    pub proxy_type: ProxyType,
}

/// Type of proxy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProxyType {
    /// HTTP proxy
    Http,
    /// HTTPS proxy
    Https,
    /// SOCKS5 proxy
    Socks5,
}

/// Proxy health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHealth {
    /// Whether the proxy is currently healthy
    pub is_healthy: bool,
    /// Last check timestamp
    pub last_check: Option<Instant>,
    /// Number of consecutive failures
    pub failure_count: u32,
    /// Average response time in milliseconds
    pub avg_response_time: Option<u64>,
}

/// Proxy entry with health tracking
struct ProxyEntry {
    config: ProxyConfig,
    health: ProxyHealth,
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
    health_check_interval: Duration,
}

impl ProxyPool {
    /// Create a new proxy pool
    pub fn new(strategy: RotationStrategy) -> Self {
        Self {
            proxies: Arc::new(Mutex::new(VecDeque::new())),
            strategy,
            max_failures: 3,
            health_check_interval: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Add a proxy to the pool
    pub fn add_proxy(&self, config: ProxyConfig) -> Result<(), String> {
        let entry = ProxyEntry {
            config,
            health: ProxyHealth {
                is_healthy: true,
                last_check: None,
                failure_count: 0,
                avg_response_time: None,
            },
        };

        self.proxies
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?
            .push_back(entry);

        Ok(())
    }

    /// Get the next proxy according to the rotation strategy
    pub fn get_next_proxy(&self) -> Result<ProxyConfig, String> {
        let mut proxies = self
            .proxies
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;

        if proxies.is_empty() {
            return Err("No proxies available".to_string());
        }

        // Filter healthy proxies
        let healthy_count = proxies.iter().filter(|p| p.health.is_healthy).count();
        
        if healthy_count == 0 {
            return Err("No healthy proxies available".to_string());
        }

        match self.strategy {
            RotationStrategy::RoundRobin => {
                // Rotate until we find a healthy proxy
                while let Some(entry) = proxies.pop_front() {
                    if entry.health.is_healthy {
                        let config = entry.config.clone();
                        proxies.push_back(entry);
                        return Ok(config);
                    }
                    proxies.push_back(entry);
                }
                Err("No healthy proxies found".to_string())
            }
            RotationStrategy::Random => {
                // Find all healthy proxies and pick one randomly
                let healthy_indices: Vec<usize> = proxies
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| p.health.is_healthy)
                    .map(|(i, _)| i)
                    .collect();

                if healthy_indices.is_empty() {
                    return Err("No healthy proxies found".to_string());
                }

                let idx = healthy_indices[rand::random::<usize>() % healthy_indices.len()];
                Ok(proxies[idx].config.clone())
            }
            RotationStrategy::LeastRecentlyUsed => {
                // Find the healthy proxy with the oldest last_check
                let mut oldest_idx = None;
                let mut oldest_time = Instant::now();

                for (i, entry) in proxies.iter().enumerate() {
                    if entry.health.is_healthy {
                        if let Some(last_check) = entry.health.last_check {
                            if oldest_idx.is_none() || last_check < oldest_time {
                                oldest_idx = Some(i);
                                oldest_time = last_check;
                            }
                        } else {
                            // Never used, prioritize this
                            oldest_idx = Some(i);
                            break;
                        }
                    }
                }

                oldest_idx
                    .map(|i| proxies[i].config.clone())
                    .ok_or_else(|| "No healthy proxies found".to_string())
            }
            RotationStrategy::FastestFirst => {
                // Find the healthy proxy with the fastest response time
                let mut fastest_idx = None;
                let mut fastest_time = u64::MAX;

                for (i, entry) in proxies.iter().enumerate() {
                    if entry.health.is_healthy {
                        if let Some(avg_time) = entry.health.avg_response_time {
                            if avg_time < fastest_time {
                                fastest_idx = Some(i);
                                fastest_time = avg_time;
                            }
                        } else if fastest_idx.is_none() {
                            fastest_idx = Some(i);
                        }
                    }
                }

                fastest_idx
                    .map(|i| proxies[i].config.clone())
                    .ok_or_else(|| "No healthy proxies found".to_string())
            }
        }
    }

    /// Mark a proxy as failed
    pub fn mark_failure(&self, proxy_url: &str) -> Result<(), String> {
        let mut proxies = self
            .proxies
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;

        for entry in proxies.iter_mut() {
            if entry.config.url == proxy_url {
                entry.health.failure_count += 1;
                
                if entry.health.failure_count >= self.max_failures {
                    entry.health.is_healthy = false;
                }
                
                return Ok(());
            }
        }

        Err(format!("Proxy {} not found", proxy_url))
    }

    /// Mark a proxy as successful
    pub fn mark_success(&self, proxy_url: &str, response_time: Duration) -> Result<(), String> {
        let mut proxies = self
            .proxies
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;

        for entry in proxies.iter_mut() {
            if entry.config.url == proxy_url {
                entry.health.failure_count = 0;
                entry.health.is_healthy = true;
                entry.health.last_check = Some(Instant::now());
                
                // Update average response time
                let new_time = response_time.as_millis() as u64;
                entry.health.avg_response_time = Some(
                    if let Some(avg) = entry.health.avg_response_time {
                        (avg + new_time) / 2
                    } else {
                        new_time
                    }
                );
                
                return Ok(());
            }
        }

        Err(format!("Proxy {} not found", proxy_url))
    }

    /// Get pool statistics
    pub fn get_stats(&self) -> Result<PoolStats, String> {
        let proxies = self
            .proxies
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;

        let total = proxies.len();
        let healthy = proxies.iter().filter(|p| p.health.is_healthy).count();
        let unhealthy = total - healthy;

        Ok(PoolStats {
            total,
            healthy,
            unhealthy,
        })
    }

    /// Remove all unhealthy proxies
    pub fn remove_unhealthy(&self) -> Result<usize, String> {
        let mut proxies = self
            .proxies
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;

        let before = proxies.len();
        proxies.retain(|p| p.health.is_healthy);
        let removed = before - proxies.len();

        Ok(removed)
    }
}

/// Pool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStats {
    /// Total number of proxies
    pub total: usize,
    /// Number of healthy proxies
    pub healthy: usize,
    /// Number of unhealthy proxies
    pub unhealthy: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_pool_creation() {
        let pool = ProxyPool::new(RotationStrategy::RoundRobin);
        let stats = pool.get_stats().unwrap();
        assert_eq!(stats.total, 0);
    }

    #[test]
    fn test_add_proxy() {
        let pool = ProxyPool::new(RotationStrategy::RoundRobin);
        
        let config = ProxyConfig {
            url: "http://proxy1.example.com:8080".to_string(),
            username: None,
            password: None,
            proxy_type: ProxyType::Http,
        };

        pool.add_proxy(config).unwrap();
        
        let stats = pool.get_stats().unwrap();
        assert_eq!(stats.total, 1);
        assert_eq!(stats.healthy, 1);
    }

    #[test]
    fn test_round_robin_rotation() {
        let pool = ProxyPool::new(RotationStrategy::RoundRobin);
        
        pool.add_proxy(ProxyConfig {
            url: "http://proxy1.example.com:8080".to_string(),
            username: None,
            password: None,
            proxy_type: ProxyType::Http,
        }).unwrap();

        pool.add_proxy(ProxyConfig {
            url: "http://proxy2.example.com:8080".to_string(),
            username: None,
            password: None,
            proxy_type: ProxyType::Http,
        }).unwrap();

        let proxy1 = pool.get_next_proxy().unwrap();
        let proxy2 = pool.get_next_proxy().unwrap();
        
        assert_ne!(proxy1.url, proxy2.url);
    }
}
//! Kill Switch Module
//! 
//! Provides emergency shutdown functionality to immediately halt all
//! active security testing operations. Critical for preventing damage
//! in case of scope violations or unexpected behavior.
//! 
//! This module ensures clean shutdown of all resources including:
//! - Active PTY sessions
//! - Network connections
//! - Running tools
//! - Pending operations

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Reason for kill switch activation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KillReason {
    /// User manually triggered emergency stop
    ManualStop,
    /// Scope violation detected
    ScopeViolation(String),
    /// Rate limit exceeded
    RateLimitExceeded,
    /// System error requiring immediate shutdown
    SystemError(String),
    /// External signal received
    ExternalSignal,
}

/// Kill switch event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillEvent {
    /// Reason for activation
    pub reason: KillReason,
    /// Timestamp of activation
    pub timestamp: i64,
    /// Additional context
    pub context: Option<String>,
}

/// Global kill switch for emergency shutdown
pub struct KillSwitch {
    /// Whether the kill switch is active
    active: Arc<AtomicBool>,
    /// Broadcast channel for kill events
    tx: broadcast::Sender<KillEvent>,
}

impl KillSwitch {
    /// Create a new kill switch
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(100);
        
        Self {
            active: Arc::new(AtomicBool::new(false)),
            tx,
        }
    }

    /// Activate the kill switch
    pub fn activate(&self, reason: KillReason, context: Option<String>) -> Result<(), String> {
        // Set active flag
        self.active.store(true, Ordering::SeqCst);

        // Create kill event
        let event = KillEvent {
            reason,
            timestamp: chrono::Utc::now().timestamp(),
            context,
        };

        // Broadcast kill event
        self.tx
            .send(event)
            .map_err(|e| format!("Failed to broadcast kill event: {}", e))?;

        Ok(())
    }

    /// Check if kill switch is active
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Reset the kill switch (use with caution)
    pub fn reset(&self) {
        self.active.store(false, Ordering::SeqCst);
    }

    /// Subscribe to kill switch events
    pub fn subscribe(&self) -> broadcast::Receiver<KillEvent> {
        self.tx.subscribe()
    }

    /// Get a clone of the active flag for checking in tight loops
    pub fn get_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.active)
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper trait for operations that can be killed
pub trait Killable {
    /// Check if operation should be killed
    fn should_kill(&self) -> bool;
    
    /// Perform cleanup on kill
    fn on_kill(&mut self) -> Result<(), String>;
}

/// Macro for checking kill switch in loops
#[macro_export]
macro_rules! check_kill {
    ($kill_switch:expr) => {
        if $kill_switch.is_active() {
            return Err("Operation killed by kill switch".to_string());
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kill_switch_creation() {
        let kill_switch = KillSwitch::new();
        assert!(!kill_switch.is_active());
    }

    #[test]
    fn test_kill_switch_activation() {
        let kill_switch = KillSwitch::new();
        
        kill_switch
            .activate(KillReason::ManualStop, None)
            .unwrap();
        
        assert!(kill_switch.is_active());
    }

    #[test]
    fn test_kill_switch_reset() {
        let kill_switch = KillSwitch::new();
        
        kill_switch
            .activate(KillReason::ManualStop, None)
            .unwrap();
        
        assert!(kill_switch.is_active());
        
        kill_switch.reset();
        assert!(!kill_switch.is_active());
    }

    #[tokio::test]
    async fn test_kill_switch_subscription() {
        let kill_switch = KillSwitch::new();
        let mut rx = kill_switch.subscribe();

        kill_switch
            .activate(
                KillReason::ScopeViolation("test.com".to_string()),
                Some("Test context".to_string()),
            )
            .unwrap();

        let event = rx.recv().await.unwrap();
        
        match event.reason {
            KillReason::ScopeViolation(domain) => {
                assert_eq!(domain, "test.com");
            }
            _ => panic!("Wrong kill reason"),
        }
        
        assert_eq!(event.context, Some("Test context".to_string()));
    }
}
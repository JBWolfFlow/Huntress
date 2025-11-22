//! Safe-to-Test Module
//! 
//! Provides scope validation and DNS/HTTP gate functionality to ensure
//! all testing activities remain within authorized bug bounty program boundaries.
//! 
//! This module is critical for preventing out-of-scope testing that could
//! result in legal issues or program bans.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use regex::Regex;

/// Represents a scope entry from a bug bounty program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeEntry {
    /// The domain or IP range in scope
    pub target: String,
    /// Whether this is an inclusion or exclusion
    pub in_scope: bool,
    /// Optional notes about the scope entry
    pub notes: Option<String>,
}

/// Scope validator for ensuring targets are authorized
pub struct ScopeValidator {
    /// Set of in-scope domains/patterns
    in_scope: HashSet<String>,
    /// Set of out-of-scope domains/patterns
    out_of_scope: HashSet<String>,
    /// Compiled regex patterns for wildcard matching
    patterns: Vec<Regex>,
}

impl ScopeValidator {
    /// Create a new scope validator from a list of scope entries
    pub fn new(entries: Vec<ScopeEntry>) -> Result<Self, String> {
        let mut in_scope = HashSet::new();
        let mut out_of_scope = HashSet::new();
        let mut patterns = Vec::new();

        for entry in entries {
            if entry.in_scope {
                in_scope.insert(entry.target.clone());
                
                // Convert wildcard patterns to regex
                if entry.target.contains('*') {
                    let pattern = entry.target
                        .replace(".", "\\.")
                        .replace("*", ".*");
                    match Regex::new(&format!("^{}$", pattern)) {
                        Ok(re) => patterns.push(re),
                        Err(e) => return Err(format!("Invalid pattern {}: {}", entry.target, e)),
                    }
                }
            } else {
                out_of_scope.insert(entry.target);
            }
        }

        Ok(Self {
            in_scope,
            out_of_scope,
            patterns,
        })
    }

    /// Check if a target is within scope
    pub fn is_in_scope(&self, target: &str) -> bool {
        // First check explicit out-of-scope entries
        if self.out_of_scope.contains(target) {
            return false;
        }

        // Check exact matches
        if self.in_scope.contains(target) {
            return true;
        }

        // Check pattern matches
        for pattern in &self.patterns {
            if pattern.is_match(target) {
                return true;
            }
        }

        false
    }

    /// Validate a URL is in scope
    pub fn validate_url(&self, url: &str) -> Result<(), String> {
        let host = extract_host(url)?;
        
        if self.is_in_scope(&host) {
            Ok(())
        } else {
            Err(format!("Target {} is out of scope", host))
        }
    }
}

/// Extract hostname from a URL
fn extract_host(url: &str) -> Result<String, String> {
    url::Url::parse(url)
        .map_err(|e| format!("Invalid URL: {}", e))?
        .host_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No host in URL".to_string())
}

/// DNS/HTTP gate for pre-flight checks
pub struct SafetyGate {
    validator: ScopeValidator,
}

impl SafetyGate {
    /// Create a new safety gate with the given scope validator
    pub fn new(validator: ScopeValidator) -> Self {
        Self { validator }
    }

    /// Perform pre-flight checks before allowing a request
    pub async fn check_target(&self, target: &str) -> Result<(), String> {
        // Validate scope
        self.validator.validate_url(target)?;

        // Additional DNS/HTTP checks can be added here
        // For example: DNS resolution, HTTP connectivity tests, etc.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_scope_match() {
        let entries = vec![
            ScopeEntry {
                target: "example.com".to_string(),
                in_scope: true,
                notes: None,
            },
        ];
        
        let validator = ScopeValidator::new(entries).unwrap();
        assert!(validator.is_in_scope("example.com"));
        assert!(!validator.is_in_scope("other.com"));
    }

    #[test]
    fn test_wildcard_scope() {
        let entries = vec![
            ScopeEntry {
                target: "*.example.com".to_string(),
                in_scope: true,
                notes: None,
            },
        ];
        
        let validator = ScopeValidator::new(entries).unwrap();
        assert!(validator.is_in_scope("api.example.com"));
        assert!(validator.is_in_scope("test.example.com"));
        assert!(!validator.is_in_scope("example.com"));
    }

    #[test]
    fn test_out_of_scope() {
        let entries = vec![
            ScopeEntry {
                target: "*.example.com".to_string(),
                in_scope: true,
                notes: None,
            },
            ScopeEntry {
                target: "admin.example.com".to_string(),
                in_scope: false,
                notes: Some("Admin panel excluded".to_string()),
            },
        ];
        
        let validator = ScopeValidator::new(entries).unwrap();
        assert!(validator.is_in_scope("api.example.com"));
        assert!(!validator.is_in_scope("admin.example.com"));
    }
}
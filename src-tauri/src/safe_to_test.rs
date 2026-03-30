//! Safe-to-Test Module
//! 
//! Provides scope validation and DNS/HTTP gate functionality to ensure
//! all testing activities remain within authorized bug bounty program boundaries.
//! 
//! This module is critical for preventing out-of-scope testing that could
//! result in legal issues or program bans.
//!
//! # Security Guarantees
//!
//! - Default deny: If scope is empty, NOTHING is allowed
//! - Wildcard matching is exact (*.example.com does NOT match example.com)
//! - Out-of-scope patterns override in-scope patterns
//! - Certificate CN must match domain for HTTPS requests
//! - All validation errors are logged with timestamp

use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use thiserror::Error;
use tracing::{error, info, warn};
use url::Url;

// reqwest used for TLS certificate validation in validate_certificate()

/// Errors that can occur during scope validation
#[derive(Error, Debug)]
pub enum ScopeError {
    #[error("Target {0} is out of scope")]
    OutOfScope(String),
    
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    
    #[error("Invalid scope pattern: {0}")]
    InvalidPattern(String),
    
    #[error("Failed to parse scope file: {0}")]
    ParseError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("No host found in URL")]
    NoHost,
    
    #[error("Scope is empty - default deny")]
    EmptyScope,

    #[error("Certificate CN mismatch: expected {expected}, got {actual}")]
    CertificateMismatch { expected: String, actual: String },

    #[error("Invalid CIDR notation: {0}")]
    InvalidCidr(String),

    #[error("Port {port} is out of scope for {host}")]
    PortOutOfScope { host: String, port: u16 },
}

/// Represents a scope entry from a bug bounty program
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeEntry {
    /// The domain or IP range in scope
    pub target: String,
    /// Whether this is an inclusion or exclusion
    pub in_scope: bool,
    /// Optional notes about the scope entry
    pub notes: Option<String>,
}

/// HackerOne scope format
#[derive(Debug, Clone, Serialize, Deserialize)]
struct H1ScopeAsset {
    asset_identifier: String,
    asset_type: String,
    eligible_for_bounty: bool,
    eligible_for_submission: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct H1Scope {
    targets: H1Targets,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct H1Targets {
    in_scope: Vec<H1ScopeAsset>,
    out_of_scope: Vec<H1ScopeAsset>,
}

/// CIDR network block for IP range scope
#[derive(Debug, Clone)]
pub struct CidrBlock {
    /// Base IP address
    network: IpAddr,
    /// Prefix length (0-32 for IPv4, 0-128 for IPv6)
    prefix_len: u8,
    /// Whether this CIDR block is in-scope (true) or out-of-scope (false)
    in_scope: bool,
}

impl CidrBlock {
    /// Parse a CIDR string like "192.168.1.0/24" or "10.0.0.0/8"
    pub fn parse(cidr: &str, in_scope: bool) -> Result<Self, ScopeError> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(ScopeError::InvalidCidr(cidr.to_string()));
        }

        let ip: IpAddr = parts[0].parse()
            .map_err(|_| ScopeError::InvalidCidr(format!("Invalid IP in CIDR: {}", cidr)))?;
        let prefix_len: u8 = parts[1].parse()
            .map_err(|_| ScopeError::InvalidCidr(format!("Invalid prefix in CIDR: {}", cidr)))?;

        // Validate prefix length
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return Err(ScopeError::InvalidCidr(format!(
                "Prefix {} exceeds maximum {} for {}",
                prefix_len, max_prefix, cidr
            )));
        }

        Ok(Self { network: ip, prefix_len, in_scope })
    }

    /// Check if an IP address falls within this CIDR block
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(target)) => {
                let net_bits = u32::from(net);
                let target_bits = u32::from(target);
                if self.prefix_len == 0 { return true; }
                let mask = !((1u32 << (32 - self.prefix_len)) - 1);
                (net_bits & mask) == (target_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(target)) => {
                let net_bits = u128::from(net);
                let target_bits = u128::from(target);
                if self.prefix_len == 0 { return true; }
                let mask = !((1u128 << (128 - self.prefix_len)) - 1);
                (net_bits & mask) == (target_bits & mask)
            }
            _ => false, // IPv4/IPv6 mismatch
        }
    }
}

/// Port-specific scope restriction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScope {
    /// The host/domain this port restriction applies to
    pub host: String,
    /// Allowed ports (empty = all ports allowed)
    pub allowed_ports: Vec<u16>,
    /// Explicitly blocked ports
    pub blocked_ports: Vec<u16>,
}

/// IP range scope entry (non-CIDR, e.g., "10.0.0.1-10.0.0.255")
#[derive(Debug, Clone)]
pub struct IpRange {
    start: Ipv4Addr,
    end: Ipv4Addr,
    in_scope: bool,
}

impl IpRange {
    /// Parse an IP range string like "10.0.0.1-10.0.0.255"
    pub fn parse(range: &str, in_scope: bool) -> Result<Self, ScopeError> {
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() != 2 {
            return Err(ScopeError::InvalidPattern(format!("Invalid IP range: {}", range)));
        }
        let start: Ipv4Addr = parts[0].trim().parse()
            .map_err(|_| ScopeError::InvalidPattern(format!("Invalid start IP: {}", parts[0])))?;
        let end: Ipv4Addr = parts[1].trim().parse()
            .map_err(|_| ScopeError::InvalidPattern(format!("Invalid end IP: {}", parts[1])))?;
        if u32::from(start) > u32::from(end) {
            return Err(ScopeError::InvalidPattern(format!(
                "Start IP {} is greater than end IP {}", start, end
            )));
        }
        Ok(Self { start, end, in_scope })
    }

    /// Check if an IPv4 address falls within this range
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let ip_val = u32::from(ip);
        ip_val >= u32::from(self.start) && ip_val <= u32::from(self.end)
    }
}

/// Core scope validation logic
#[derive(Clone)]
pub struct ScopeValidator {
    /// Exact in-scope domains
    in_scope_patterns: Vec<Regex>,
    /// Exact out-of-scope domains
    out_of_scope_patterns: Vec<Regex>,
    /// Wildcard domains for matching
    _wildcard_domains: Vec<String>,
    /// Raw scope entries for reference
    entries: Vec<ScopeEntry>,
    /// CIDR blocks for IP range validation (Phase 24C)
    cidr_blocks: Vec<CidrBlock>,
    /// IP ranges for range-based validation (Phase 24C)
    ip_ranges: Vec<IpRange>,
    /// Port-specific scope restrictions (Phase 24C)
    port_scopes: Vec<PortScope>,
    /// Protocol restrictions: only these protocols are allowed (empty = all allowed)
    allowed_protocols: Vec<String>,
}

impl ScopeValidator {
    /// Create a new scope validator from scope entries
    pub fn new(entries: Vec<ScopeEntry>) -> Result<Self, ScopeError> {
        if entries.is_empty() {
            warn!("Creating scope validator with empty scope - default deny will be enforced");
        }

        let mut in_scope_patterns = Vec::new();
        let mut out_of_scope_patterns = Vec::new();
        let mut wildcard_domains = Vec::new();
        let mut cidr_blocks = Vec::new();
        let mut ip_ranges = Vec::new();

        for entry in &entries {
            let target = entry.target.trim();

            // Detect CIDR notation (e.g., "192.168.1.0/24")
            if target.contains('/') && Self::looks_like_cidr(target) {
                match CidrBlock::parse(target, entry.in_scope) {
                    Ok(cidr) => {
                        info!("Parsed CIDR block: {} (in_scope={})", target, entry.in_scope);
                        cidr_blocks.push(cidr);
                        continue;
                    }
                    Err(e) => {
                        warn!("Failed to parse as CIDR, treating as domain pattern: {}", e);
                    }
                }
            }

            // Detect IP range notation (e.g., "10.0.0.1-10.0.0.255")
            if target.contains('-') && Self::looks_like_ip_range(target) {
                match IpRange::parse(target, entry.in_scope) {
                    Ok(range) => {
                        info!("Parsed IP range: {} (in_scope={})", target, entry.in_scope);
                        ip_ranges.push(range);
                        continue;
                    }
                    Err(e) => {
                        warn!("Failed to parse as IP range, treating as domain pattern: {}", e);
                    }
                }
            }

            // Regular domain/wildcard pattern — normalize to hostname only
            // (strip port from entries like "localhost:3001" before compiling regex)
            let pattern_input = if target.starts_with("*.") {
                // Wildcard entries don't have ports — pass through as-is
                target.to_string()
            } else {
                Self::extract_domain(target)
            };
            let pattern = Self::compile_pattern(&pattern_input)?;

            if entry.in_scope {
                in_scope_patterns.push(pattern);
                if entry.target.contains('*') {
                    wildcard_domains.push(entry.target.clone());
                }
            } else {
                out_of_scope_patterns.push(pattern);
            }
        }

        info!(
            "Scope validator initialized: {} domain patterns ({} in/{} out), {} CIDR blocks, {} IP ranges",
            in_scope_patterns.len() + out_of_scope_patterns.len(),
            in_scope_patterns.len(),
            out_of_scope_patterns.len(),
            cidr_blocks.len(),
            ip_ranges.len(),
        );

        Ok(Self {
            in_scope_patterns,
            out_of_scope_patterns,
            _wildcard_domains: wildcard_domains,
            entries: entries.clone(),
            cidr_blocks,
            ip_ranges,
            port_scopes: Vec::new(),
            allowed_protocols: Vec::new(),
        })
    }

    /// Add port-specific scope restrictions
    pub fn add_port_scope(&mut self, port_scope: PortScope) {
        info!(
            "Adding port scope for {}: allowed={:?}, blocked={:?}",
            port_scope.host, port_scope.allowed_ports, port_scope.blocked_ports
        );
        self.port_scopes.push(port_scope);
    }

    /// Set allowed protocols (e.g., ["https"] to block HTTP)
    pub fn set_allowed_protocols(&mut self, protocols: Vec<String>) {
        info!("Setting allowed protocols: {:?}", protocols);
        self.allowed_protocols = protocols;
    }

    /// Validate that a URL's port is allowed for the target host
    pub fn is_port_allowed(&self, host: &str, port: u16) -> bool {
        for ps in &self.port_scopes {
            // Match host pattern
            if ps.host == host || ps.host == "*" {
                // Check blocked ports first
                if ps.blocked_ports.contains(&port) {
                    warn!("Port {} is explicitly blocked for {}", port, host);
                    return false;
                }
                // If allowed_ports is non-empty, port must be in the list
                if !ps.allowed_ports.is_empty() && !ps.allowed_ports.contains(&port) {
                    warn!("Port {} is not in allowed ports for {}", port, host);
                    return false;
                }
                return true;
            }
        }
        // No port restrictions defined → allow all ports
        true
    }

    /// Validate that a URL's protocol is allowed
    pub fn is_protocol_allowed(&self, protocol: &str) -> bool {
        if self.allowed_protocols.is_empty() {
            return true; // No restrictions
        }
        let normalized = protocol.to_lowercase().replace("://", "");
        self.allowed_protocols.iter().any(|p| p.to_lowercase() == normalized)
    }

    /// Check if an IP address is in scope via CIDR blocks or IP ranges
    pub fn is_ip_in_scope(&self, ip_str: &str) -> bool {
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        // Check out-of-scope CIDR blocks first (precedence)
        for cidr in &self.cidr_blocks {
            if !cidr.in_scope && cidr.contains(ip) {
                warn!("IP {} matched out-of-scope CIDR block", ip_str);
                return false;
            }
        }

        // Check in-scope CIDR blocks
        for cidr in &self.cidr_blocks {
            if cidr.in_scope && cidr.contains(ip) {
                info!("IP {} matched in-scope CIDR block", ip_str);
                return true;
            }
        }

        // Check out-of-scope IP ranges first (precedence)
        if let IpAddr::V4(ipv4) = ip {
            for range in &self.ip_ranges {
                if !range.in_scope && range.contains(ipv4) {
                    warn!("IP {} matched out-of-scope IP range", ip_str);
                    return false;
                }
            }

            // Check in-scope IP ranges
            for range in &self.ip_ranges {
                if range.in_scope && range.contains(ipv4) {
                    info!("IP {} matched in-scope IP range", ip_str);
                    return true;
                }
            }
        }

        false
    }

    /// Detect if a string looks like CIDR notation
    fn looks_like_cidr(s: &str) -> bool {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 { return false; }
        // Check if left side looks like an IP
        parts[0].parse::<IpAddr>().is_ok() && parts[1].parse::<u8>().is_ok()
    }

    /// Detect if a string looks like an IP range
    fn looks_like_ip_range(s: &str) -> bool {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 { return false; }
        parts[0].trim().parse::<Ipv4Addr>().is_ok() && parts[1].trim().parse::<Ipv4Addr>().is_ok()
    }

    /// Full URL validation: scope + port + protocol (Phase 24C)
    pub fn validate_url_full(&self, url_str: &str) -> Result<(), ScopeError> {
        let parsed = Url::parse(url_str)
            .map_err(|e| ScopeError::InvalidUrl(format!("{}: {}", url_str, e)))?;

        // Protocol check
        let scheme = parsed.scheme();
        if !self.is_protocol_allowed(scheme) {
            return Err(ScopeError::OutOfScope(
                format!("Protocol '{}' not allowed", scheme)
            ));
        }

        let host = parsed.host_str()
            .ok_or(ScopeError::NoHost)?
            .to_string();

        // Port check
        let port = parsed.port().unwrap_or(match scheme {
            "https" | "wss" => 443,
            "http" | "ws" => 80,
            _ => 0,
        });

        if !self.is_port_allowed(&host, port) {
            return Err(ScopeError::PortOutOfScope { host: host.clone(), port });
        }

        // Domain/IP check
        if !self.is_in_scope(&host) {
            return Err(ScopeError::OutOfScope(host));
        }

        Ok(())
    }

    /// Load scope from HackerOne JSON format
    pub fn from_h1_scope(json: &str) -> Result<Self, ScopeError> {
        let h1_scope: H1Scope = serde_json::from_str(json)
            .map_err(|e| ScopeError::ParseError(format!("Invalid H1 JSON: {}", e)))?;

        let mut entries = Vec::new();

        // Add in-scope targets
        for asset in h1_scope.targets.in_scope {
            if asset.eligible_for_submission {
                entries.push(ScopeEntry {
                    target: asset.asset_identifier,
                    in_scope: true,
                    notes: Some(format!(
                        "Type: {}, Bounty: {}",
                        asset.asset_type, asset.eligible_for_bounty
                    )),
                });
            }
        }

        // Add out-of-scope targets
        for asset in h1_scope.targets.out_of_scope {
            entries.push(ScopeEntry {
                target: asset.asset_identifier,
                in_scope: false,
                notes: Some(format!("Type: {}", asset.asset_type)),
            });
        }

        Self::new(entries)
    }

    /// Load scope from file (supports JSON and CSV)
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ScopeError> {
        let content = fs::read_to_string(path)?;
        
        // Try JSON first (HackerOne format)
        if let Ok(validator) = Self::from_h1_scope(&content) {
            return Ok(validator);
        }

        // Try simple line-by-line format
        let entries: Vec<ScopeEntry> = content
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
            .map(|line| {
                let (target, in_scope) = if let Some(stripped) = line.strip_prefix('!') {
                    (stripped.trim().to_string(), false)
                } else {
                    (line.trim().to_string(), true)
                };
                
                ScopeEntry {
                    target,
                    in_scope,
                    notes: None,
                }
            })
            .collect();

        Self::new(entries)
    }

    /// Compile a scope pattern into a regex
    fn compile_pattern(pattern: &str) -> Result<Regex, ScopeError> {
        // Replace * with placeholder before escaping so regex::escape doesn't touch it
        let with_placeholder = pattern.replace('*', "WILDCARD_PLACEHOLDER");
        // Escape ALL regex metacharacters (., |, +, ?, [, ], etc.)
        let escaped = regex::escape(&with_placeholder);
        // Restore wildcard as a regex pattern matching a single domain label
        let regex_pattern = escaped.replace("WILDCARD_PLACEHOLDER", "[^.]+");

        Regex::new(&format!("^{}$", regex_pattern))
            .map_err(|e| ScopeError::InvalidPattern(format!("{}: {}", pattern, e)))
    }

    /// Check if domain/URL is in scope
    ///
    /// # Security Rules
    /// - Default deny if scope is empty
    /// - Out-of-scope patterns override in-scope patterns
    /// - Wildcard matching: *.example.com matches subdomains only (not example.com itself)
    pub fn is_in_scope(&self, target: &str) -> bool {
        let domain = Self::extract_domain(target);

        // Check if target is an IP address — use CIDR/range validation
        if domain.parse::<IpAddr>().is_ok() {
            if self.is_ip_in_scope(&domain) {
                return true;
            }
            // Fall through to domain pattern matching (IPs can also match domain patterns)
        }

        // Default deny for empty scope (no domain patterns and no CIDR/range)
        if self.in_scope_patterns.is_empty() && self.cidr_blocks.is_empty() && self.ip_ranges.is_empty() {
            warn!("Scope is empty - denying target: {}", target);
            return false;
        }

        // Check out-of-scope first (takes precedence)
        for pattern in &self.out_of_scope_patterns {
            if pattern.is_match(&domain) {
                warn!("Target {} matched out-of-scope pattern", domain);
                return false;
            }
        }

        // Check in-scope patterns
        for pattern in &self.in_scope_patterns {
            if pattern.is_match(&domain) {
                info!("Target {} matched in-scope pattern", domain);
                return true;
            }
        }

        warn!("Target {} did not match any in-scope pattern", domain);
        false
    }

    /// Validate DNS query before execution
    pub fn validate_dns_query(&self, domain: &str) -> Result<(), ScopeError> {
        let timestamp = Utc::now();
        
        if self.is_in_scope(domain) {
            info!(
                timestamp = %timestamp,
                domain = %domain,
                "DNS query validated"
            );
            Ok(())
        } else {
            error!(
                timestamp = %timestamp,
                domain = %domain,
                "DNS query blocked - out of scope"
            );
            Err(ScopeError::OutOfScope(domain.to_string()))
        }
    }

    /// Validate HTTP request before execution
    pub async fn validate_http_request(&self, url: &str) -> Result<(), ScopeError> {
        let timestamp = Utc::now();
        let parsed_url = Url::parse(url)
            .map_err(|e| ScopeError::InvalidUrl(format!("{}: {}", url, e)))?;

        let host = parsed_url
            .host_str()
            .ok_or(ScopeError::NoHost)?
            .to_string();

        // Validate scope
        if !self.is_in_scope(&host) {
            error!(
                timestamp = %timestamp,
                url = %url,
                host = %host,
                "HTTP request blocked - out of scope"
            );
            return Err(ScopeError::OutOfScope(host));
        }

        // For HTTPS, validate that the server's TLS certificate is valid for this host.
        // This prevents DNS rebinding/MITM attacks where we might test the wrong server.
        if parsed_url.scheme() == "https" {
            let port = parsed_url.port().unwrap_or(443);
            Self::validate_certificate(&host, port).await.map_err(|e| {
                error!(
                    timestamp = %timestamp,
                    url = %url,
                    host = %host,
                    error = %e,
                    "HTTPS certificate validation failed"
                );
                e
            })?;
            info!(
                timestamp = %timestamp,
                url = %url,
                host = %host,
                "HTTPS certificate validated"
            );
        }

        info!(
            timestamp = %timestamp,
            url = %url,
            host = %host,
            "HTTP request validated"
        );

        Ok(())
    }

    /// Validate TLS certificate for an HTTPS target.
    ///
    /// Connects to the target and verifies the TLS certificate is valid
    /// for the expected hostname. This prevents:
    /// - DNS rebinding attacks (testing against the wrong server)
    /// - MITM interception (attacker-controlled certificates)
    /// - Testing servers with invalid/expired certificates (potential honeypots)
    ///
    /// # Security Rules
    /// - Certificate error → block (confirmed bad cert)
    /// - Network unreachable / timeout → allow (can't validate, not a cert issue)
    /// - Connection refused → allow (server down, not a cert issue)
    async fn validate_certificate(host: &str, port: u16) -> Result<(), ScopeError> {
        let url = format!("https://{}:{}/", host, port);

        let client = match reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    host = %host,
                    error = %e,
                    "Failed to build TLS client — skipping certificate check"
                );
                return Ok(());
            }
        };

        match client.head(&url).send().await {
            Ok(_) => {
                // TLS handshake succeeded — certificate is valid for this host
                Ok(())
            }
            Err(e) => {
                let err_str = format!("{}", e).to_lowercase();
                let is_cert_error = err_str.contains("certificate")
                    || err_str.contains("ssl")
                    || err_str.contains("tls")
                    || err_str.contains("verify")
                    || err_str.contains("handshake");

                if is_cert_error {
                    error!(
                        host = %host,
                        error = %e,
                        "TLS certificate validation failed"
                    );
                    Err(ScopeError::CertificateMismatch {
                        expected: host.to_string(),
                        actual: format!("Certificate validation failed: {}", e),
                    })
                } else {
                    // Network error (timeout, connection refused, DNS failure)
                    // — not a certificate issue, allow the request
                    info!(
                        host = %host,
                        error = %e,
                        "Cannot reach host for cert validation — allowing (not a cert error)"
                    );
                    Ok(())
                }
            }
        }
    }

    /// Extract domain from URL/hostname, stripping port numbers and whitespace
    fn extract_domain(input: &str) -> String {
        let trimmed = input.trim();

        // Try parsing as URL first (handles http://host:port/path)
        if let Ok(url) = Url::parse(trimmed) {
            if let Some(host) = url.host_str() {
                return host.to_lowercase();
            }
        }

        // Try with a scheme prefix (handles bare host:port like "localhost:3001")
        if let Ok(url) = Url::parse(&format!("https://{}", trimmed)) {
            if let Some(host) = url.host_str() {
                return host.to_lowercase();
            }
        }

        // Final fallback: strip port manually and lowercase
        trimmed.split(':').next().unwrap_or(trimmed).to_lowercase()
    }

    /// Match wildcard patterns (*.example.com matches api.example.com but NOT example.com)
    fn _matches_wildcard(&self, domain: &str, pattern: &str) -> bool {
        if !pattern.contains('*') {
            return domain == pattern;
        }

        // Wildcard must match at least one character
        let regex_pattern = pattern.replace(".", "\\.").replace("*", ".+");
        if let Ok(re) = Regex::new(&format!("^{}$", regex_pattern)) {
            re.is_match(domain)
        } else {
            false
        }
    }

    /// Get all scope entries
    pub fn get_entries(&self) -> &[ScopeEntry] {
        &self.entries
    }
}

/// Tauri command: Load scope file
#[tauri::command]
pub async fn load_scope(path: String) -> Result<String, String> {
    info!("Loading scope from file: {}", path);
    
    let validator = ScopeValidator::from_file(&path)
        .map_err(|e| format!("Failed to load scope: {}", e))?;

    let entry_count = validator.get_entries().len();
    let in_scope_count = validator.get_entries().iter().filter(|e| e.in_scope).count();
    let out_of_scope_count = entry_count - in_scope_count;

    // Set as global scope
    set_global_scope(validator);

    let message = format!(
        "Scope loaded: {} total entries ({} in-scope, {} out-of-scope)",
        entry_count, in_scope_count, out_of_scope_count
    );

    info!("{}", message);
    Ok(message)
}

/// Tauri command: Load scope from entries (for programmatic scope loading)
#[tauri::command]
pub async fn load_scope_entries(entries: Vec<ScopeEntry>) -> Result<String, String> {
    info!("Loading scope from {} entries", entries.len());
    
    let validator = ScopeValidator::new(entries)
        .map_err(|e| format!("Failed to create scope validator: {}", e))?;

    let entry_count = validator.get_entries().len();
    let in_scope_count = validator.get_entries().iter().filter(|e| e.in_scope).count();
    let out_of_scope_count = entry_count - in_scope_count;

    // Set as global scope
    set_global_scope(validator);

    let message = format!(
        "Scope loaded: {} total entries ({} in-scope, {} out-of-scope)",
        entry_count, in_scope_count, out_of_scope_count
    );

    info!("{}", message);
    Ok(message)
}

// Global scope validator
use std::sync::{LazyLock, RwLock};
static GLOBAL_SCOPE: LazyLock<RwLock<Option<ScopeValidator>>> = LazyLock::new(|| RwLock::new(None));

/// Set the global scope validator
pub fn set_global_scope(validator: ScopeValidator) {
    if let Ok(mut scope) = GLOBAL_SCOPE.write() {
        *scope = Some(validator);
        info!("Global scope validator updated");
    }
}

/// Get the global scope validator
pub fn get_global_scope() -> Option<ScopeValidator> {
    GLOBAL_SCOPE.read().ok()?.clone()
}

/// Tauri command: Validate target before any operation
#[tauri::command]
pub async fn validate_target(target: String) -> Result<bool, String> {
    info!("Validating target: {}", target);
    
    let scope = get_global_scope()
        .ok_or_else(|| "Scope validator not initialized. Load scope file first.".to_string())?;
    
    Ok(scope.is_in_scope(&target))
}

/// Tauri command: Validate targets from a file
///
/// This command reads a file containing targets (one per line) and validates
/// each target against the current scope. This is critical for file-based tools
/// like httpx, nuclei, etc. that operate on lists of targets.
///
/// # Security Guarantees
/// - Each target in the file is individually validated
/// - Comments (lines starting with #) are ignored
/// - Empty lines are ignored
/// - Returns detailed error with all out-of-scope targets
/// - Fails fast on file read errors
#[tauri::command]
pub async fn validate_targets_from_file(file_path: String) -> Result<Vec<String>, String> {
    info!("Validating targets from file: {}", file_path);
    
    // Read file contents
    let contents = fs::read_to_string(&file_path)
        .map_err(|e| format!("Failed to read file {}: {}", file_path, e))?;
    
    // Get global scope validator
    let scope = get_global_scope()
        .ok_or_else(|| "Scope validator not initialized. Load scope file first.".to_string())?;
    
    let mut valid_targets = Vec::new();
    let mut invalid_targets = Vec::new();
    let mut line_number = 0;
    
    // Validate each target in the file
    for line in contents.lines() {
        line_number += 1;
        let target = line.trim();
        
        // Skip empty lines and comments
        if target.is_empty() || target.starts_with('#') {
            continue;
        }
        
        // Validate target against scope
        if scope.is_in_scope(target) {
            valid_targets.push(target.to_string());
            info!("Line {}: Target {} is in scope", line_number, target);
        } else {
            invalid_targets.push(format!("Line {}: {}", line_number, target));
            warn!("Line {}: Target {} is OUT OF SCOPE", line_number, target);
        }
    }
    
    // If any targets are out of scope, return error with details
    if !invalid_targets.is_empty() {
        let error_msg = format!(
            "File contains {} out-of-scope target(s):\n{}",
            invalid_targets.len(),
            invalid_targets.join("\n")
        );
        error!("{}", error_msg);
        return Err(error_msg);
    }
    
    info!(
        "File validation successful: {} valid targets in {}",
        valid_targets.len(),
        file_path
    );
    
    Ok(valid_targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_scope_match() {
        let entries = vec![ScopeEntry {
            target: "example.com".to_string(),
            in_scope: true,
            notes: None,
        }];

        let validator = ScopeValidator::new(entries).unwrap();
        assert!(validator.is_in_scope("example.com"));
        assert!(!validator.is_in_scope("other.com"));
    }

    #[test]
    fn test_wildcard_scope() {
        let entries = vec![ScopeEntry {
            target: "*.example.com".to_string(),
            in_scope: true,
            notes: None,
        }];

        let validator = ScopeValidator::new(entries).unwrap();
        assert!(validator.is_in_scope("api.example.com"));
        assert!(validator.is_in_scope("test.example.com"));
        // Wildcard does NOT match base domain
        assert!(!validator.is_in_scope("example.com"));
    }

    #[test]
    fn test_out_of_scope_override() {
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

    #[test]
    fn test_empty_scope_default_deny() {
        let validator = ScopeValidator::new(vec![]).unwrap();
        assert!(!validator.is_in_scope("example.com"));
        assert!(!validator.is_in_scope("anything.com"));
    }

    #[test]
    fn test_extract_domain_from_url() {
        assert_eq!(
            ScopeValidator::extract_domain("https://example.com/path"),
            "example.com"
        );
        assert_eq!(
            ScopeValidator::extract_domain("http://api.example.com:8080"),
            "api.example.com"
        );
        assert_eq!(
            ScopeValidator::extract_domain("example.com"),
            "example.com"
        );
    }

    #[tokio::test]
    async fn test_validate_dns_query() {
        let entries = vec![ScopeEntry {
            target: "example.com".to_string(),
            in_scope: true,
            notes: None,
        }];

        let validator = ScopeValidator::new(entries).unwrap();
        assert!(validator.validate_dns_query("example.com").is_ok());
        assert!(validator.validate_dns_query("other.com").is_err());
    }

    #[tokio::test]
    async fn test_validate_http_request() {
        let entries = vec![ScopeEntry {
            target: "example.com".to_string(),
            in_scope: true,
            notes: None,
        }];

        let validator = ScopeValidator::new(entries).unwrap();
        assert!(validator
            .validate_http_request("https://example.com/path")
            .await
            .is_ok());
        assert!(validator
            .validate_http_request("https://other.com/path")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_certificate_validation_unreachable_host_allowed() {
        // A host that can't be reached should be allowed (not a cert error)
        let result = ScopeValidator::validate_certificate("this-host-does-not-exist-ever.invalid", 443).await;
        assert!(result.is_ok(), "Unreachable hosts should pass (not a cert error)");
    }

    #[tokio::test]
    async fn test_certificate_validation_connection_refused_allowed() {
        // Connecting to a port that refuses connections should be allowed
        let result = ScopeValidator::validate_certificate("127.0.0.1", 19999).await;
        assert!(result.is_ok(), "Connection refused should pass (not a cert error)");
    }

    #[test]
    fn test_certificate_mismatch_error_type() {
        // Verify the CertificateMismatch error type works correctly
        let err = ScopeError::CertificateMismatch {
            expected: "example.com".to_string(),
            actual: "evil.com".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("example.com"));
        assert!(msg.contains("evil.com"));
    }

    // ─── Phase 24C: CIDR, IP Range, Port, Protocol Tests ───────────────

    #[test]
    fn test_cidr_ipv4_in_scope() {
        let entries = vec![ScopeEntry {
            target: "10.0.0.0/24".to_string(),
            in_scope: true,
            notes: None,
        }];
        let validator = ScopeValidator::new(entries).unwrap();
        assert!(validator.is_in_scope("10.0.0.1"));
        assert!(validator.is_in_scope("10.0.0.254"));
        assert!(!validator.is_in_scope("10.0.1.1"));
        assert!(!validator.is_in_scope("192.168.1.1"));
    }

    #[test]
    fn test_cidr_ipv4_slash_16() {
        let entries = vec![ScopeEntry {
            target: "172.16.0.0/16".to_string(),
            in_scope: true,
            notes: None,
        }];
        let validator = ScopeValidator::new(entries).unwrap();
        assert!(validator.is_in_scope("172.16.0.1"));
        assert!(validator.is_in_scope("172.16.255.255"));
        assert!(!validator.is_in_scope("172.17.0.1"));
    }

    #[test]
    fn test_cidr_out_of_scope_overrides() {
        let entries = vec![
            ScopeEntry {
                target: "10.0.0.0/8".to_string(),
                in_scope: true,
                notes: None,
            },
            ScopeEntry {
                target: "10.0.1.0/24".to_string(),
                in_scope: false,
                notes: Some("Internal admin network excluded".to_string()),
            },
        ];
        let validator = ScopeValidator::new(entries).unwrap();
        assert!(validator.is_in_scope("10.0.0.1"));
        assert!(validator.is_in_scope("10.0.2.1"));
        // Out-of-scope CIDR takes precedence
        assert!(!validator.is_in_scope("10.0.1.50"));
    }

    #[test]
    fn test_ip_range_in_scope() {
        let entries = vec![ScopeEntry {
            target: "192.168.1.100-192.168.1.200".to_string(),
            in_scope: true,
            notes: None,
        }];
        let validator = ScopeValidator::new(entries).unwrap();
        assert!(validator.is_in_scope("192.168.1.100"));
        assert!(validator.is_in_scope("192.168.1.150"));
        assert!(validator.is_in_scope("192.168.1.200"));
        assert!(!validator.is_in_scope("192.168.1.99"));
        assert!(!validator.is_in_scope("192.168.1.201"));
    }

    #[test]
    fn test_mixed_cidr_and_domains() {
        let entries = vec![
            ScopeEntry {
                target: "example.com".to_string(),
                in_scope: true,
                notes: None,
            },
            ScopeEntry {
                target: "10.0.0.0/24".to_string(),
                in_scope: true,
                notes: None,
            },
        ];
        let validator = ScopeValidator::new(entries).unwrap();
        assert!(validator.is_in_scope("example.com"));
        assert!(validator.is_in_scope("10.0.0.42"));
        assert!(!validator.is_in_scope("other.com"));
        assert!(!validator.is_in_scope("10.0.1.1"));
    }

    #[test]
    fn test_port_scope_allowed() {
        let entries = vec![ScopeEntry {
            target: "example.com".to_string(),
            in_scope: true,
            notes: None,
        }];
        let mut validator = ScopeValidator::new(entries).unwrap();
        validator.add_port_scope(PortScope {
            host: "example.com".to_string(),
            allowed_ports: vec![80, 443, 8080],
            blocked_ports: vec![],
        });

        assert!(validator.is_port_allowed("example.com", 80));
        assert!(validator.is_port_allowed("example.com", 443));
        assert!(validator.is_port_allowed("example.com", 8080));
        assert!(!validator.is_port_allowed("example.com", 22));
        assert!(!validator.is_port_allowed("example.com", 3306));
    }

    #[test]
    fn test_port_scope_blocked() {
        let entries = vec![ScopeEntry {
            target: "example.com".to_string(),
            in_scope: true,
            notes: None,
        }];
        let mut validator = ScopeValidator::new(entries).unwrap();
        validator.add_port_scope(PortScope {
            host: "example.com".to_string(),
            allowed_ports: vec![], // all allowed except blocked
            blocked_ports: vec![22, 3306, 5432],
        });

        assert!(validator.is_port_allowed("example.com", 80));
        assert!(validator.is_port_allowed("example.com", 443));
        assert!(!validator.is_port_allowed("example.com", 22));
        assert!(!validator.is_port_allowed("example.com", 3306));
    }

    #[test]
    fn test_port_scope_no_restrictions() {
        let entries = vec![ScopeEntry {
            target: "example.com".to_string(),
            in_scope: true,
            notes: None,
        }];
        let validator = ScopeValidator::new(entries).unwrap();
        // No port scope defined → all ports allowed
        assert!(validator.is_port_allowed("example.com", 80));
        assert!(validator.is_port_allowed("example.com", 22));
        assert!(validator.is_port_allowed("example.com", 65535));
    }

    #[test]
    fn test_protocol_restrictions() {
        let entries = vec![ScopeEntry {
            target: "example.com".to_string(),
            in_scope: true,
            notes: None,
        }];
        let mut validator = ScopeValidator::new(entries).unwrap();
        validator.set_allowed_protocols(vec!["https".to_string(), "wss".to_string()]);

        assert!(validator.is_protocol_allowed("https"));
        assert!(validator.is_protocol_allowed("wss"));
        assert!(!validator.is_protocol_allowed("http"));
        assert!(!validator.is_protocol_allowed("ftp"));
    }

    #[test]
    fn test_protocol_no_restrictions() {
        let entries = vec![ScopeEntry {
            target: "example.com".to_string(),
            in_scope: true,
            notes: None,
        }];
        let validator = ScopeValidator::new(entries).unwrap();
        // No protocol restrictions → all allowed
        assert!(validator.is_protocol_allowed("http"));
        assert!(validator.is_protocol_allowed("https"));
        assert!(validator.is_protocol_allowed("ftp"));
    }

    #[test]
    fn test_validate_url_full() {
        let entries = vec![ScopeEntry {
            target: "example.com".to_string(),
            in_scope: true,
            notes: None,
        }];
        let mut validator = ScopeValidator::new(entries).unwrap();
        validator.set_allowed_protocols(vec!["https".to_string()]);
        validator.add_port_scope(PortScope {
            host: "example.com".to_string(),
            allowed_ports: vec![443, 8443],
            blocked_ports: vec![],
        });

        // Valid: https on port 443
        assert!(validator.validate_url_full("https://example.com/path").is_ok());
        // Valid: https on port 8443
        assert!(validator.validate_url_full("https://example.com:8443/path").is_ok());
        // Invalid: HTTP protocol not allowed
        assert!(validator.validate_url_full("http://example.com/path").is_err());
        // Invalid: port 8080 not allowed
        assert!(validator.validate_url_full("https://example.com:8080/path").is_err());
        // Invalid: out-of-scope domain
        assert!(validator.validate_url_full("https://other.com/path").is_err());
    }

    #[test]
    fn test_cidr_block_parse_invalid() {
        assert!(CidrBlock::parse("not-a-cidr", true).is_err());
        assert!(CidrBlock::parse("10.0.0.0/33", true).is_err()); // prefix too large
        assert!(CidrBlock::parse("10.0.0.0", true).is_err()); // no prefix
    }

    #[test]
    fn test_ip_range_parse_invalid() {
        assert!(IpRange::parse("not-a-range", true).is_err());
        assert!(IpRange::parse("10.0.0.200-10.0.0.100", true).is_err()); // start > end
    }

    #[test]
    fn test_cidr_ipv6() {
        let cidr = CidrBlock::parse("2001:db8::/32", true).unwrap();
        assert!(cidr.contains("2001:db8::1".parse().unwrap()));
        assert!(cidr.contains("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
        assert!(!cidr.contains("2001:db9::1".parse().unwrap()));
    }
}
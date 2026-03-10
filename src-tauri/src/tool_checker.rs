//! Tool Availability Checker
//!
//! Verifies which security tools are installed on the system at startup.
//! Presents missing tools to the user with install instructions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

/// Information about a security tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    /// Tool name (binary name)
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// Whether the tool is installed
    pub installed: bool,
    /// Version string if installed
    pub version: Option<String>,
    /// Install command for this tool
    pub install_command: String,
    /// Tool category
    pub category: String,
    /// Whether this tool is required (vs optional)
    pub required: bool,
}

/// Check if a single tool is installed by looking for it in PATH
fn check_tool_installed(name: &str) -> Option<String> {
    Command::new("which")
        .arg(name)
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(
                    String::from_utf8_lossy(&output.stdout)
                        .trim()
                        .to_string(),
                )
            } else {
                None
            }
        })
}

/// Get version string for a tool
fn get_tool_version(name: &str) -> Option<String> {
    // Try common version flags
    for flag in &["--version", "-version", "-V", "version"] {
        if let Ok(output) = Command::new(name).arg(flag).output() {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let first_line = combined.lines().next().unwrap_or("").trim().to_string();
            if !first_line.is_empty() && first_line.len() < 200 {
                return Some(first_line);
            }
        }
    }
    None
}

/// Get the full tool inventory with install commands
fn get_tool_inventory() -> Vec<(&'static str, &'static str, &'static str, &'static str, bool)> {
    // (name, description, install_command, category, required)
    vec![
        // Passive Recon
        ("subfinder", "Subdomain enumeration", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "recon", true),
        ("assetfinder", "Find related domains", "go install github.com/tomnomnom/assetfinder@latest", "recon", false),
        ("dnsx", "DNS toolkit", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "recon", true),
        ("findomain", "Subdomain enumerator", "curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip && unzip findomain-linux.zip", "recon", false),
        ("httpx", "HTTP probe", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", "recon", true),
        ("wafw00f", "WAF detection", "pip3 install wafw00f", "recon", true),
        ("gau", "Get All URLs", "go install github.com/lc/gau/v2/cmd/gau@latest", "recon", true),
        ("waybackurls", "Wayback Machine URLs", "go install github.com/tomnomnom/waybackurls@latest", "recon", true),
        ("katana", "Web crawler", "go install github.com/projectdiscovery/katana/cmd/katana@latest", "recon", true),
        ("gospider", "Fast web spider", "go install github.com/jaeles-project/gospider@latest", "recon", false),
        ("paramspider", "Parameter discovery", "pip3 install paramspider", "recon", false),
        ("whatweb", "Tech fingerprinting", "apt install whatweb", "recon", false),
        ("gowitness", "Screenshot tool", "go install github.com/sensepost/gowitness@latest", "recon", false),

        // Scanning
        ("nuclei", "Vulnerability scanner", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "scanning", true),
        ("naabu", "Port scanner", "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "scanning", true),
        ("nmap", "Network scanner", "apt install nmap", "scanning", true),
        ("nikto", "Web server scanner", "apt install nikto", "scanning", false),
        ("wpscan", "WordPress scanner", "gem install wpscan", "scanning", false),

        // Fuzzing
        ("ffuf", "Web fuzzer", "go install github.com/ffuf/ffuf/v2@latest", "fuzzing", true),
        ("feroxbuster", "Content discovery", "apt install feroxbuster", "fuzzing", false),
        ("gobuster", "Directory scanner", "go install github.com/OJ/gobuster/v3@latest", "fuzzing", false),
        ("arjun", "Parameter discovery", "pip3 install arjun", "fuzzing", false),

        // Active Testing
        ("dalfox", "XSS scanner", "go install github.com/hahwul/dalfox/v2@latest", "active-testing", true),
        ("sqlmap", "SQL injection", "apt install sqlmap", "active-testing", true),
        ("kxss", "Reflected param detection", "go install github.com/Emoe/kxss@latest", "active-testing", false),
        ("corsy", "CORS scanner", "pip3 install corsy", "active-testing", false),
        ("interactsh-client", "OOB detection", "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest", "active-testing", true),

        // Utilities
        ("jq", "JSON processor", "apt install jq", "utility", true),
        ("anew", "Line deduplication", "go install github.com/tomnomnom/anew@latest", "utility", false),
        ("qsreplace", "URL param replacement", "go install github.com/tomnomnom/qsreplace@latest", "utility", false),
        ("unfurl", "URL parser", "go install github.com/tomnomnom/unfurl@latest", "utility", false),

        // SSL/TLS
        ("testssl.sh", "SSL/TLS testing", "apt install testssl.sh", "ssl", false),
        ("sslyze", "SSL scanner", "pip3 install sslyze", "ssl", false),

        // Other
        ("searchsploit", "Exploit DB search", "apt install exploitdb", "utility", false),
        ("python3", "Python interpreter", "apt install python3", "runtime", true),
        ("go", "Go compiler", "apt install golang-go", "runtime", false),
        ("node", "Node.js runtime", "apt install nodejs", "runtime", true),
        ("docker", "Container runtime", "apt install docker.io", "runtime", false),
    ]
}

/// Check all tools and return their status
#[tauri::command]
pub fn check_installed_tools() -> Vec<ToolInfo> {
    let inventory = get_tool_inventory();
    let mut results = Vec::new();

    for (name, description, install_cmd, category, required) in inventory {
        let path = check_tool_installed(name);
        let installed = path.is_some();
        let version = if installed {
            get_tool_version(name)
        } else {
            None
        };

        results.push(ToolInfo {
            name: name.to_string(),
            description: description.to_string(),
            installed,
            version,
            install_command: install_cmd.to_string(),
            category: category.to_string(),
            required,
        });
    }

    results
}

/// Get only missing required tools
#[tauri::command]
pub fn get_missing_required_tools() -> Vec<ToolInfo> {
    check_installed_tools()
        .into_iter()
        .filter(|t| t.required && !t.installed)
        .collect()
}

/// Get tool installation summary
#[tauri::command]
pub fn get_tool_summary() -> HashMap<String, serde_json::Value> {
    let tools = check_installed_tools();
    let total = tools.len();
    let installed = tools.iter().filter(|t| t.installed).count();
    let missing_required = tools.iter().filter(|t| t.required && !t.installed).count();

    let mut summary = HashMap::new();
    summary.insert(
        "total".to_string(),
        serde_json::Value::Number(total.into()),
    );
    summary.insert(
        "installed".to_string(),
        serde_json::Value::Number(installed.into()),
    );
    summary.insert(
        "missing".to_string(),
        serde_json::Value::Number((total - installed).into()),
    );
    summary.insert(
        "missing_required".to_string(),
        serde_json::Value::Number(missing_required.into()),
    );
    summary.insert(
        "ready".to_string(),
        serde_json::Value::Bool(missing_required == 0),
    );
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_installed_tools_returns_results() {
        let tools = check_installed_tools();
        assert!(!tools.is_empty());
    }

    #[test]
    fn test_common_tools_in_inventory() {
        let tools = check_installed_tools();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(tool_names.contains(&"python3"));
        assert!(tool_names.contains(&"jq"));
        assert!(tool_names.contains(&"nmap"));
    }
}

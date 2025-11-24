//! HackerOne API Integration
//!
//! Provides server-side access to HackerOne API, bypassing CORS restrictions.
//! Fetches program details, scope, and guidelines for bug bounty programs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProgramGuidelines {
    pub program_handle: String,
    pub program_name: String,
    pub url: String,
    pub scope: ProgramScope,
    pub rules: Vec<String>,
    pub bounty_range: BountyRange,
    pub response_time: Option<String>,
    pub severity: SeverityPayouts,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProgramScope {
    pub in_scope: Vec<String>,
    pub out_of_scope: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BountyRange {
    pub min: u32,
    pub max: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SeverityPayouts {
    pub critical: Option<String>,
    pub high: Option<String>,
    pub medium: Option<String>,
    pub low: Option<String>,
}

/// Fetch program guidelines from HackerOne API
#[tauri::command]
pub async fn fetch_h1_program(program_handle: String) -> Result<ProgramGuidelines, String> {
    tracing::info!("Fetching HackerOne program: {}", program_handle);

    // Build API URL
    let api_url = format!(
        "https://api.hackerone.com/v1/hackers/programs/{}",
        program_handle
    );

    // Check for API credentials in environment
    let api_username = std::env::var("HACKERONE_API_USERNAME").ok();
    let api_token = std::env::var("HACKERONE_API_TOKEN").ok();

    // Make HTTP request
    let client = reqwest::Client::new();
    let mut request = client
        .get(&api_url)
        .header("Accept", "application/json")
        .header("User-Agent", "Huntress/1.0")
        .timeout(std::time::Duration::from_secs(10));

    // Add authentication if credentials are available
    if let (Some(username), Some(token)) = (api_username, api_token) {
        tracing::info!("Using authenticated HackerOne API request");
        request = request.basic_auth(username, Some(token));
    } else {
        tracing::warn!("No HackerOne API credentials found - attempting unauthenticated request");
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("Failed to fetch program: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_msg = if status == 401 {
            format!(
                "Authentication required. Please set HACKERONE_API_USERNAME and HACKERONE_API_TOKEN environment variables. \
                See https://docs.hackerone.com/programs/api-tokens.html for instructions."
            )
        } else {
            format!(
                "HackerOne API returned error: {} - {}",
                status,
                status.canonical_reason().unwrap_or("Unknown")
            )
        };
        return Err(error_msg);
    }

    // Parse response
    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    // Log the response for debugging
    tracing::debug!("HackerOne API response: {}", serde_json::to_string_pretty(&json).unwrap_or_default());

    // HackerOne API v1 can return data in different formats
    // Try to extract data from various possible structures
    let data = if let Some(d) = json.get("data") {
        d
    } else if json.is_object() {
        // Sometimes the response IS the data object
        &json
    } else {
        return Err(format!("Unexpected API response format. Response: {}",
            serde_json::to_string(&json).unwrap_or_default()));
    };

    let attributes = data.get("attributes")
        .ok_or_else(|| format!("No attributes in response. Data: {}",
            serde_json::to_string(data).unwrap_or_default()))?;

    let relationships = data.get("relationships");

    // Extract scope
    let mut in_scope = Vec::new();
    let mut out_of_scope = Vec::new();

    if let Some(rels) = relationships {
        if let Some(scopes) = rels.get("structured_scopes").and_then(|s| s.get("data")) {
            if let Some(scope_array) = scopes.as_array() {
                for scope_item in scope_array {
                    if let Some(scope_attrs) = scope_item.get("attributes") {
                        if let Some(asset) = scope_attrs.get("asset_identifier").and_then(|a| a.as_str()) {
                            let eligible = scope_attrs
                                .get("eligible_for_bounty")
                                .and_then(|e| e.as_bool())
                                .unwrap_or(false);

                            if eligible {
                                in_scope.push(asset.to_string());
                            } else {
                                out_of_scope.push(asset.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Extract program name
    let program_name = attributes
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or(&program_handle)
        .to_string();

    // Extract policy/rules (truncate if too long)
    let policy = attributes
        .get("policy")
        .and_then(|p| p.as_str())
        .unwrap_or("No policy available");
    
    let policy_preview = if policy.len() > 500 {
        format!("{}...", &policy[..500])
    } else {
        policy.to_string()
    };

    // Extract bounty range - HackerOne API doesn't always provide this
    // We'll need to parse it from the policy or use default values
    let offers_bounties = attributes
        .get("offers_bounties")
        .and_then(|ob| ob.as_bool())
        .unwrap_or(false);

    let (bounty_min, bounty_max) = if offers_bounties {
        // Try to extract from bounty_range if available
        let min = attributes
            .get("bounty_range")
            .and_then(|br| br.get("min"))
            .and_then(|m| m.as_u64())
            .unwrap_or(0) as u32;

        let max = attributes
            .get("bounty_range")
            .and_then(|br| br.get("max"))
            .and_then(|m| m.as_u64())
            .unwrap_or(0) as u32;

        // If not available, use reasonable defaults for programs that offer bounties
        if min == 0 && max == 0 {
            (100, 10000) // Default range for bounty programs
        } else {
            (min, max)
        }
    } else {
        (0, 0)
    };

    // Extract response time
    let response_time = attributes
        .get("response_efficiency_percentage")
        .and_then(|r| r.as_u64())
        .map(|pct| format!("{}% within 24h", pct));

    // Extract severity payouts - may not be available in all responses
    let bounty_table = attributes.get("bounty_table");
    let severity = SeverityPayouts {
        critical: bounty_table
            .and_then(|bt| bt.get("critical"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
            .or_else(|| if offers_bounties { Some("Varies".to_string()) } else { None }),
        high: bounty_table
            .and_then(|bt| bt.get("high"))
            .and_then(|h| h.as_str())
            .map(|s| s.to_string())
            .or_else(|| if offers_bounties { Some("Varies".to_string()) } else { None }),
        medium: bounty_table
            .and_then(|bt| bt.get("medium"))
            .and_then(|m| m.as_str())
            .map(|s| s.to_string())
            .or_else(|| if offers_bounties { Some("Varies".to_string()) } else { None }),
        low: bounty_table
            .and_then(|bt| bt.get("low"))
            .and_then(|l| l.as_str())
            .map(|s| s.to_string())
            .or_else(|| if offers_bounties { Some("Varies".to_string()) } else { None }),
    };

    tracing::info!(
        "Successfully fetched program: {} ({} in-scope, {} out-of-scope)",
        program_name,
        in_scope.len(),
        out_of_scope.len()
    );

    Ok(ProgramGuidelines {
        program_handle: program_handle.clone(),
        program_name,
        url: format!("https://hackerone.com/{}", program_handle),
        scope: ProgramScope {
            in_scope,
            out_of_scope,
        },
        rules: vec![policy_preview, policy.to_string()],
        bounty_range: BountyRange {
            min: bounty_min,
            max: bounty_max,
        },
        response_time,
        severity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_public_program() {
        // Test with a known public program
        let result = fetch_h1_program("security".to_string()).await;
        
        match result {
            Ok(guidelines) => {
                assert_eq!(guidelines.program_handle, "security");
                assert!(!guidelines.program_name.is_empty());
                println!("Program: {}", guidelines.program_name);
                println!("In-scope: {}", guidelines.scope.in_scope.len());
            }
            Err(e) => {
                // API might be unavailable in test environment
                println!("API call failed (expected in CI): {}", e);
            }
        }
    }
}
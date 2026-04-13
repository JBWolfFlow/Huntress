//! Agent Browser — Persistent Node.js subprocess manager (I2)
//!
//! Manages long-lived Node.js child processes that host Playwright browsers
//! on behalf of ReAct loops. Each agent hunt can open its own session; the
//! subprocess stays alive for the duration of the hunt and handles many
//! browser tool calls over a newline-delimited JSON stdio protocol.
//!
//! Rationale: Tauri's WebView cannot resolve `playwright-core` imports
//! (static imports of Node-native modules fail with a binding error). The
//! fix is to keep browser code out of the WebView entirely and call into
//! it through stdio IPC with a proper Node.js subprocess.
//!
//! Protocol (per `scripts/agent_browser.mjs`):
//!   stdin:  `{"id":"r1","action":"navigate","url":"..."}` + newline
//!   stdout: `{"id":"r1","ok":true,"data":{...}}`          + newline
//!
//! Each session is addressed by an opaque string key picked by the caller.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

/// Timeout for a single browser request (navigate/evaluate/click).
/// The Node script itself caps per-operation timeouts lower than this.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// One live Node subprocess.
struct BrowserSession {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
}

/// Global manager keyed by caller-provided session key.
pub struct AgentBrowserManager {
    sessions: Mutex<HashMap<String, Arc<Mutex<BrowserSession>>>>,
}

impl Default for AgentBrowserManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentBrowserManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Spawn a new Node subprocess under `key`. If a session already exists
    /// for the key, the existing one is returned (idempotent).
    pub async fn spawn(&self, key: &str, script_path: &str) -> Result<(), String> {
        let mut sessions = self.sessions.lock().await;
        if sessions.contains_key(key) {
            return Ok(());
        }

        let mut child = Command::new("node")
            .arg(script_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("Failed to spawn agent_browser subprocess: {}", e))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "Subprocess stdin missing".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "Subprocess stdout missing".to_string())?;

        info!(session = key, "agent_browser subprocess spawned");

        let session = BrowserSession {
            child,
            stdin,
            reader: BufReader::new(stdout),
        };
        sessions.insert(key.to_string(), Arc::new(Mutex::new(session)));
        Ok(())
    }

    /// Send a JSON request and read the JSON response. The caller is
    /// responsible for the protocol — we just framing-by-newline.
    pub async fn call(&self, key: &str, request_json: &str) -> Result<String, String> {
        let session_arc = {
            let sessions = self.sessions.lock().await;
            sessions
                .get(key)
                .cloned()
                .ok_or_else(|| format!("No agent_browser session for key: {}", key))?
        };

        // Hold the per-session lock for the full request-response cycle so
        // two concurrent callers don't interleave JSON lines.
        let mut session = session_arc.lock().await;

        // Write request + newline
        let mut payload = request_json.as_bytes().to_vec();
        if !payload.ends_with(b"\n") {
            payload.push(b'\n');
        }
        session
            .stdin
            .write_all(&payload)
            .await
            .map_err(|e| format!("agent_browser stdin write failed: {}", e))?;
        session
            .stdin
            .flush()
            .await
            .map_err(|e| format!("agent_browser stdin flush failed: {}", e))?;

        // Read one response line with an overall timeout
        let mut line = String::new();
        let read_result = timeout(REQUEST_TIMEOUT, session.reader.read_line(&mut line)).await;

        match read_result {
            Err(_) => Err("agent_browser request timed out".to_string()),
            Ok(Err(e)) => Err(format!("agent_browser stdout read failed: {}", e)),
            Ok(Ok(0)) => Err("agent_browser subprocess closed stdout".to_string()),
            Ok(Ok(_)) => Ok(line.trim_end_matches('\n').to_string()),
        }
    }

    /// Kill the subprocess for `key` and drop it from the map.
    pub async fn kill(&self, key: &str) -> Result<(), String> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session_arc) = sessions.remove(key) {
            let mut session = session_arc.lock().await;
            // Best-effort graceful close via `close` command first
            let _ = session.stdin.write_all(b"{\"action\":\"close\"}\n").await;
            let _ = session.stdin.flush().await;
            // Then force-kill if it hasn't exited
            if let Err(e) = session.child.start_kill() {
                warn!(session = key, error = %e, "agent_browser kill failed");
            }
            let _ = session.child.wait().await;
            info!(session = key, "agent_browser subprocess killed");
        }
        Ok(())
    }

    /// Kill every live session. Used on app shutdown to avoid orphaning
    /// Playwright Node subprocesses (Issue #7 caught in Hunt #11 monitoring).
    /// Returns the number of sessions killed.
    pub async fn kill_all(&self) -> usize {
        let keys: Vec<String> = {
            let sessions = self.sessions.lock().await;
            sessions.keys().cloned().collect()
        };
        let count = keys.len();
        for key in keys {
            if let Err(e) = self.kill(&key).await {
                warn!(session = %key, error = %e, "agent_browser kill_all: session kill failed");
            }
        }
        count
    }
}

// ─── Tauri commands ─────────────────────────────────────────────────────────

use std::sync::LazyLock;

static GLOBAL_AGENT_BROWSER: LazyLock<AgentBrowserManager> = LazyLock::new(AgentBrowserManager::new);

/// Resolve the agent_browser.mjs script path. We look for it relative to the
/// current working directory (dev) and next to the app executable (prod).
fn resolve_script_path() -> Result<String, String> {
    let candidates = [
        "scripts/agent_browser.mjs",
        "../scripts/agent_browser.mjs",
        "../../scripts/agent_browser.mjs",
    ];
    for path in candidates.iter() {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    Err("agent_browser.mjs not found in any expected location".to_string())
}

#[tauri::command]
pub async fn agent_browser_spawn(session_key: String) -> Result<(), String> {
    let script_path = resolve_script_path()?;
    GLOBAL_AGENT_BROWSER.spawn(&session_key, &script_path).await
}

#[tauri::command]
pub async fn agent_browser_send(session_key: String, request_json: String) -> Result<String, String> {
    GLOBAL_AGENT_BROWSER.call(&session_key, &request_json).await
}

#[tauri::command]
pub async fn agent_browser_kill(session_key: String) -> Result<(), String> {
    GLOBAL_AGENT_BROWSER.kill(&session_key).await
}

/// Called from Tauri shutdown hook (Issue #7): kill every live browser
/// subprocess so we don't leak Playwright Node processes across dev restarts.
pub async fn shutdown_cleanup() -> usize {
    GLOBAL_AGENT_BROWSER.kill_all().await
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn call_returns_error_for_missing_session() {
        let mgr = AgentBrowserManager::new();
        let result = mgr.call("no-such-session", "{}").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No agent_browser session"));
    }

    #[tokio::test]
    async fn kill_missing_session_is_noop() {
        let mgr = AgentBrowserManager::new();
        let result = mgr.kill("no-such-session").await;
        assert!(result.is_ok());
    }

    /// End-to-end round-trip: spawn a trivial `cat`-like echo subprocess and
    /// verify write+read framing works. We use `node -e` with a tiny line
    /// echo to stay simple.
    #[tokio::test]
    async fn round_trip_over_node_echo() {
        // Skip if node isn't on PATH (e.g. minimal CI image)
        if Command::new("node").arg("--version").output().await.is_err() {
            return;
        }

        let mgr = AgentBrowserManager::new();
        // Spawn directly via the internal helper — bypass script resolution
        let mut child = Command::new("node")
            .arg("-e")
            .arg(
                "process.stdin.setEncoding('utf8');\
                 let buf='';\
                 process.stdin.on('data',c=>{\
                   buf+=c;\
                   let i;\
                   while((i=buf.indexOf('\\n'))>=0){\
                     const line=buf.slice(0,i);buf=buf.slice(i+1);\
                     process.stdout.write('ECHO:'+line+'\\n');\
                   }\
                 });"
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn node");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();

        {
            let mut sessions = mgr.sessions.lock().await;
            sessions.insert(
                "echo".to_string(),
                Arc::new(Mutex::new(BrowserSession {
                    child,
                    stdin,
                    reader: BufReader::new(stdout),
                })),
            );
        }

        let response = mgr.call("echo", "hello-world").await.expect("call");
        assert_eq!(response, "ECHO:hello-world");

        let _ = mgr.kill("echo").await;
    }
}

//! MCP Resource implementations for Garden AI sandbox.
//!
//! Exposes three read-only resources to MCP clients (Claude Desktop, Cursor, etc.):
//!
//! | URI                            | Contents                                         |
//! |--------------------------------|--------------------------------------------------|
//! | `garden://sandbox/status`      | Current VM running state and uptime              |
//! | `garden://security/events`     | Last 50 security events from the session log     |
//! | `garden://security/violations` | Only events that triggered a policy violation    |
//!
//! All resources are read from the host-side log files or daemon gRPC — they
//! cannot be spoofed by a compromised guest VM.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// URI constants
// ---------------------------------------------------------------------------

pub const URI_SANDBOX_STATUS: &str = "garden://sandbox/status";
pub const URI_SECURITY_EVENTS: &str = "garden://security/events";
pub const URI_SECURITY_VIOLATIONS: &str = "garden://security/violations";

/// Number of recent events to surface for the `events` resource.
const RECENT_EVENTS_COUNT: usize = 50;

// ---------------------------------------------------------------------------
// Log file helpers
// ---------------------------------------------------------------------------

/// Find the most recently modified `events.ndjson` across all Garden sessions.
///
/// Sessions live at `~/.garden/sessions/{session_id}/events.ndjson`.
/// Returns `None` if no daemon session has been created yet.
pub fn find_latest_session_log() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let sessions_dir = PathBuf::from(home).join(".garden").join("sessions");

    let mut candidates: Vec<(std::time::SystemTime, PathBuf)> =
        std::fs::read_dir(&sessions_dir)
            .ok()?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let log_path = entry.path().join("events.ndjson");
                let modified = std::fs::metadata(&log_path).ok()?.modified().ok()?;
                Some((modified, log_path))
            })
            .collect();

    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    candidates.into_iter().next().map(|(_, path)| path)
}

/// Return the last `n` lines of a file.
fn tail_lines(path: &PathBuf, n: usize) -> Vec<String> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let lines: Vec<String> = BufReader::new(file)
        .lines()
        .filter_map(|l| l.ok())
        .collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].to_vec()
}

// ---------------------------------------------------------------------------
// Event formatting
// ---------------------------------------------------------------------------

/// Render a list of raw NDJSON log lines as human-readable text.
///
/// Each line is a JSON object produced by `EventLogger::log()`. We extract
/// the key fields rather than dumping raw JSON, so the output is useful
/// as an MCP resource that an AI can reason about directly.
fn format_log_lines(lines: &[String]) -> String {
    if lines.is_empty() {
        return "No events recorded yet.".to_string();
    }

    let mut out = format!("Security events ({} shown):\n\n", lines.len());
    for line in lines {
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(v) => {
                let ts = v["ts"].as_str().unwrap_or("?");
                let seq = v["seq"].as_u64().unwrap_or(0);
                let pid = v["pid"].as_u64().unwrap_or(0);
                let comm = v["comm"].as_str().unwrap_or("?");
                let kind_desc = describe_event_kind(&v["event"]["kind"]);

                if let Some(viol) = v["violation"].as_object() {
                    let rule = viol
                        .get("rule")
                        .and_then(|r| r.as_str())
                        .unwrap_or("?");
                    let severity = viol
                        .get("severity")
                        .and_then(|s| s.as_str())
                        .unwrap_or("?");
                    let msg = viol
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("");
                    out.push_str(&format!(
                        "[{}] #{} pid={} ({}) {} -- VIOLATION [{severity}] {rule}: {msg}\n",
                        ts, seq, pid, comm, kind_desc
                    ));
                } else {
                    out.push_str(&format!(
                        "[{}] #{} pid={} ({}) {}\n",
                        ts, seq, pid, comm, kind_desc
                    ));
                }
            }
            // Raw line if JSON fails to parse (e.g. partial write during crash)
            Err(_) => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

/// Produce a short one-line description of a `SecurityEventKind` JSON value.
///
/// The kind is serialised with `#[serde(tag = "type", rename_all = "snake_case")]`,
/// so the `"type"` field is the snake_case variant name.
fn describe_event_kind(kind: &serde_json::Value) -> String {
    let t = kind["type"].as_str().unwrap_or("unknown");
    match t {
        "file_access" => {
            let path = kind["path"].as_str().unwrap_or("?");
            let allowed = kind["allowed"].as_bool().unwrap_or(true);
            let verdict = if allowed { "allowed" } else { "denied" };
            format!("file_access {path} [{verdict}]")
        }
        "network_connect" => {
            let ip = kind["dest_ip"].as_str().unwrap_or("?");
            let port = kind["dest_port"].as_u64().unwrap_or(0);
            let proto = kind["protocol"].as_str().unwrap_or("?");
            let allowed = kind["allowed"].as_bool().unwrap_or(true);
            let verdict = if allowed { "allowed" } else { "denied" };
            format!("connect {ip}:{port} ({proto}) [{verdict}]")
        }
        "process_exec" => {
            let binary = kind["binary"].as_str().unwrap_or("?");
            let allowed = kind["allowed"].as_bool().unwrap_or(true);
            let verdict = if allowed { "allowed" } else { "denied" };
            format!("exec {binary} [{verdict}]")
        }
        "process_fork" => {
            let child_pid = kind["child_pid"].as_u64().unwrap_or(0);
            let child_comm = kind["child_comm"].as_str().unwrap_or("?");
            format!("fork -> pid={child_pid} ({child_comm})")
        }
        "process_exit" => {
            let sig = kind["exit_signal"].as_u64().unwrap_or(0);
            let status = kind["exit_status"].as_u64().unwrap_or(0);
            if sig > 0 {
                format!("exit signal={sig}")
            } else {
                format!("exit status={status}")
            }
        }
        "dns_query" => {
            let domain = kind["domain"].as_str().unwrap_or("?");
            let server = kind["server_ip"].as_str().unwrap_or("?");
            format!("dns_query {domain} via {server}")
        }
        "mount_attempt" => {
            let target = kind["target"].as_str().unwrap_or("?");
            let source = kind["source"].as_str().unwrap_or("?");
            format!("mount {source} -> {target}")
        }
        "bpf_syscall" => {
            let cmd = kind["cmd"].as_u64().unwrap_or(0);
            format!("bpf_syscall cmd={cmd}")
        }
        "module_load" => {
            let size = kind["size"].as_u64().unwrap_or(0);
            format!("module_load size={size}")
        }
        "syscall_trace" => {
            let name = kind["syscall_name"].as_str().unwrap_or("?");
            format!("syscall {name}")
        }
        "creds_changed" => {
            let old = kind["old_uid"].as_u64().unwrap_or(0);
            let new = kind["new_uid"].as_u64().unwrap_or(0);
            format!("creds_changed uid {old} -> {new}")
        }
        "tcp_send" => {
            let bytes = kind["bytes"].as_u64().unwrap_or(0);
            format!("tcp_send {bytes} bytes")
        }
        "tcp_recv" => {
            let bytes = kind["bytes"].as_u64().unwrap_or(0);
            format!("tcp_recv {bytes} bytes")
        }
        "oom_kill" => {
            let vpid = kind["victim_pid"].as_u64().unwrap_or(0);
            let vcomm = kind["victim_comm"].as_str().unwrap_or("?");
            format!("oom_kill victim pid={vpid} ({vcomm})")
        }
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Public resource readers
// ---------------------------------------------------------------------------

/// Read the last [`RECENT_EVENTS_COUNT`] events from the most recent session log.
pub fn read_recent_events() -> String {
    match find_latest_session_log() {
        Some(path) => {
            let lines = tail_lines(&path, RECENT_EVENTS_COUNT);
            format_log_lines(&lines)
        }
        None => concat!(
            "No session logs found. The Garden daemon may not have been started yet.\n",
            "Expected location: ~/.garden/sessions/<session_id>/events.ndjson"
        )
        .to_string(),
    }
}

/// Read only the violation events from the most recent session log.
pub fn read_violations() -> String {
    match find_latest_session_log() {
        Some(path) => {
            let file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => return format!("Could not open log file: {e}"),
            };
            // Filter lines that contain a non-null violation object.
            // The log serialises violations as `"violation":{...}` (never `null`).
            let violation_lines: Vec<String> = BufReader::new(file)
                .lines()
                .filter_map(|l| l.ok())
                .filter(|l| l.contains(r#""violation":{"#))
                .collect();

            if violation_lines.is_empty() {
                "No policy violations detected in the current session.".to_string()
            } else {
                format!("Policy violations ({} total):\n\n", violation_lines.len())
                    + &format_log_lines(&violation_lines)
            }
        }
        None => {
            "No session logs found. The Garden daemon may not have been started yet.".to_string()
        }
    }
}

/// Query the VM running state from the DaemonService gRPC endpoint.
///
/// Connects to 127.0.0.1:9000 on each call (the status resource is read
/// infrequently, so we don't keep a persistent connection here).
/// Degrades gracefully if the daemon is not reachable.
pub async fn read_sandbox_status() -> String {
    use garden_common::daemon::daemon_service_client::DaemonServiceClient;
    use garden_common::daemon::VmStatusRequest;

    match DaemonServiceClient::connect("http://127.0.0.1:9000").await {
        Ok(mut client) => {
            match client
                .get_vm_status(tonic::Request::new(VmStatusRequest {}))
                .await
            {
                Ok(response) => {
                    let r = response.into_inner();
                    if r.running {
                        let h = r.uptime_seconds / 3600;
                        let m = (r.uptime_seconds % 3600) / 60;
                        let s = r.uptime_seconds % 60;
                        format!(
                            "status: running\nuptime: {h}h {m}m {s}s\nkernel: {}",
                            r.kernel_path
                        )
                    } else {
                        "status: stopped".to_string()
                    }
                }
                Err(e) => format!("status: unknown\nerror: {}", e.message()),
            }
        }
        Err(_) => {
            "status: unknown\nerror: daemon not reachable at 127.0.0.1:9000\n\
             Start the Garden daemon with `garden-daemon` before querying VM status."
                .to_string()
        }
    }
}

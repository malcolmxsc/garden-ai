//! Persistent per-session event log for Garden AI security telemetry.
//!
//! Every security event received from the guest is written to an NDJSON
//! file at `~/.garden/sessions/{session_id}/events.ndjson`. Each line
//! includes a wall-clock timestamp, sequential event number, the parsed
//! event, and an optional violation if host-side policy was triggered.
//!
//! Violation detection runs on the host daemon — it cannot be tampered
//! with by the guest agent.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use garden_ebpf::events::{SecurityEvent, SecurityEventKind};
use serde::Serialize;

// ---------------------------------------------------------------------------
// Violation types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    pub severity: &'static str,
    pub rule: &'static str,
    pub message: String,
}

fn detect_violation(event: &SecurityEvent) -> Option<Violation> {
    match &event.kind {
        SecurityEventKind::CredsChanged { new_uid, .. } if *new_uid == 0 => {
            Some(Violation {
                severity: "critical",
                rule: "privilege_escalation",
                message: format!(
                    "process '{}' (pid {}) escalated to root (uid 0)",
                    event.comm, event.pid
                ),
            })
        }
        SecurityEventKind::TcpSend { bytes } if *bytes > 10_000_000 => {
            Some(Violation {
                severity: "high",
                rule: "data_exfiltration",
                message: format!(
                    "process '{}' (pid {}) sent {} bytes over TCP (>10MB threshold)",
                    event.comm,
                    event.pid,
                    bytes
                ),
            })
        }
        SecurityEventKind::TcpRecv { bytes } if *bytes > 50_000_000 => {
            Some(Violation {
                severity: "medium",
                rule: "large_download",
                message: format!(
                    "process '{}' (pid {}) received {} bytes over TCP (>50MB threshold)",
                    event.comm,
                    event.pid,
                    bytes
                ),
            })
        }
        SecurityEventKind::ModuleLoad { .. } => Some(Violation {
            severity: "high",
            rule: "module_load",
            message: format!(
                "process '{}' (pid {}) attempted to load a kernel module (CONFIG_MODULES=n)",
                event.comm, event.pid
            ),
        }),
        SecurityEventKind::BpfSyscall { cmd } if *cmd == 5 => Some(Violation {
            severity: "high",
            rule: "bpf_prog_load",
            message: format!(
                "process '{}' (pid {}) called BPF_PROG_LOAD — guest should not load BPF programs",
                event.comm, event.pid
            ),
        }),
        SecurityEventKind::MountAttempt { target, .. } if event.pid != 1 => Some(Violation {
            severity: "high",
            rule: "mount_attempt",
            message: format!(
                "process '{}' (pid {}) attempted to mount '{}' (only pid 1 should mount)",
                event.comm, event.pid, target
            ),
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Log line format
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct LogLine<'a> {
    ts: String,
    session_id: &'a str,
    seq: u64,
    pid: u32,
    comm: &'a str,
    event: &'a SecurityEvent,
    violation: Option<Violation>,
}

/// Format a Unix timestamp (seconds + millis) as a compact ISO 8601 string.
/// Output: `2026-03-31T12:34:56.789Z`
fn format_iso8601(secs: u64, millis: u32) -> String {
    // Days since Unix epoch → calendar date (Gregorian proleptic)
    let mut days = (secs / 86400) as u32;
    let time_secs = (secs % 86400) as u32;
    let hh = time_secs / 3600;
    let mm = (time_secs % 3600) / 60;
    let ss = time_secs % 60;

    // Compute year, month, day from days since 1970-01-01
    // Using the algorithm from https://howardhinnant.github.io/date_algorithms.html
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        yr, m, d, hh, mm, ss, millis
    )
}

// ---------------------------------------------------------------------------
// EventLogger
// ---------------------------------------------------------------------------

pub struct EventLogger {
    session_id: String,
    session_dir: PathBuf,
    file: Mutex<std::fs::File>,
    seq: AtomicU64,
}

impl EventLogger {
    /// Create a new session log under `~/.garden/sessions/{timestamp_ms}/`.
    pub fn new() -> anyhow::Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch");
        let session_id = format!("{}", now.as_millis());

        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let session_dir = PathBuf::from(home)
            .join(".garden")
            .join("sessions")
            .join(&session_id);

        std::fs::create_dir_all(&session_dir)?;

        let log_path = session_dir.join("events.ndjson");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        Ok(Self {
            session_id,
            session_dir,
            file: Mutex::new(file),
            seq: AtomicU64::new(0),
        })
    }

    /// Path to the session directory (contains `events.ndjson`).
    pub fn session_dir(&self) -> &Path {
        &self.session_dir
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Write one event to the log, with violation detection.
    pub fn log(&self, event: &SecurityEvent) -> anyhow::Result<()> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let violation = detect_violation(event);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch");
        let ts = format_iso8601(now.as_secs(), (now.subsec_millis()) as u32);

        let line = LogLine {
            ts,
            session_id: &self.session_id,
            seq,
            pid: event.pid,
            comm: &event.comm,
            event,
            violation,
        };

        let mut json = serde_json::to_string(&line)?;
        json.push('\n');

        let mut file = self.file.lock().unwrap();
        file.write_all(json.as_bytes())?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use garden_ebpf::events::{SecurityEvent, SecurityEventKind};

    fn make_event(pid: u32, comm: &str, kind: SecurityEventKind) -> SecurityEvent {
        SecurityEvent {
            timestamp_ns: 0,
            pid,
            comm: comm.into(),
            kind,
        }
    }

    #[test]
    fn test_no_violation_for_normal_exec() {
        let ev = make_event(
            42,
            "ls",
            SecurityEventKind::ProcessExec {
                binary: "/bin/ls".into(),
                args: vec![],
                allowed: true,
            },
        );
        assert!(detect_violation(&ev).is_none());
    }

    #[test]
    fn test_privilege_escalation_detected() {
        let ev = make_event(
            100,
            "evil",
            SecurityEventKind::CredsChanged {
                old_uid: 1000,
                new_uid: 0,
            },
        );
        let v = detect_violation(&ev).unwrap();
        assert_eq!(v.severity, "critical");
        assert_eq!(v.rule, "privilege_escalation");
    }

    #[test]
    fn test_no_violation_for_uid_change_non_root() {
        let ev = make_event(
            100,
            "su",
            SecurityEventKind::CredsChanged {
                old_uid: 0,
                new_uid: 1000,
            },
        );
        assert!(detect_violation(&ev).is_none());
    }

    #[test]
    fn test_data_exfiltration_detected() {
        let ev = make_event(
            200,
            "curl",
            SecurityEventKind::TcpSend { bytes: 15_000_000 },
        );
        let v = detect_violation(&ev).unwrap();
        assert_eq!(v.severity, "high");
        assert_eq!(v.rule, "data_exfiltration");
    }

    #[test]
    fn test_no_violation_for_small_tcp_send() {
        let ev = make_event(
            200,
            "curl",
            SecurityEventKind::TcpSend { bytes: 1024 },
        );
        assert!(detect_violation(&ev).is_none());
    }

    #[test]
    fn test_large_download_detected() {
        let ev = make_event(
            300,
            "wget",
            SecurityEventKind::TcpRecv { bytes: 60_000_000 },
        );
        let v = detect_violation(&ev).unwrap();
        assert_eq!(v.severity, "medium");
        assert_eq!(v.rule, "large_download");
    }

    #[test]
    fn test_module_load_violation() {
        let ev = make_event(
            400,
            "insmod",
            SecurityEventKind::ModuleLoad {
                size: 4096,
                args: "".into(),
            },
        );
        let v = detect_violation(&ev).unwrap();
        assert_eq!(v.severity, "high");
        assert_eq!(v.rule, "module_load");
    }

    #[test]
    fn test_bpf_prog_load_violation() {
        let ev = make_event(500, "agent", SecurityEventKind::BpfSyscall { cmd: 5 });
        let v = detect_violation(&ev).unwrap();
        assert_eq!(v.severity, "high");
        assert_eq!(v.rule, "bpf_prog_load");
    }

    #[test]
    fn test_mount_from_non_init_violation() {
        let ev = make_event(
            999,
            "sh",
            SecurityEventKind::MountAttempt {
                target: "/mnt/host".into(),
                source: "/dev/vda".into(),
                flags: 0,
            },
        );
        let v = detect_violation(&ev).unwrap();
        assert_eq!(v.severity, "high");
        assert_eq!(v.rule, "mount_attempt");
    }

    #[test]
    fn test_mount_from_init_no_violation() {
        let ev = make_event(
            1,
            "init",
            SecurityEventKind::MountAttempt {
                target: "/proc".into(),
                source: "proc".into(),
                flags: 0,
            },
        );
        assert!(detect_violation(&ev).is_none());
    }

    #[test]
    fn test_format_iso8601() {
        // 2024-03-31 00:00:00.000 UTC = 1711843200 seconds since epoch
        let s = format_iso8601(1711843200, 0);
        assert_eq!(s, "2024-03-31T00:00:00.000Z");
    }

    #[test]
    fn test_format_iso8601_with_millis() {
        let s = format_iso8601(1711843200, 123);
        assert_eq!(s, "2024-03-31T00:00:00.123Z");
    }
}

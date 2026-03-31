//! Persistent per-session event log for Garden AI security telemetry.
//!
//! Every security event received from the guest is written to an NDJSON
//! file at `~/.garden/sessions/{session_id}/events.ndjson`. Each line
//! includes a wall-clock timestamp, sequential event number, the parsed
//! event, and an optional violation if host-side policy was triggered.
//!
//! ## Log Rotation
//!
//! When `events.ndjson` reaches `max_file_bytes` (default 10 MB), it is
//! rotated: the current file becomes `events.1.ndjson`, older files are
//! shifted up (`events.1` → `events.2`, etc.), and files beyond
//! `max_files` (default 5) are deleted. This bounds total disk usage to
//! approximately `max_file_bytes × max_files` = 50 MB by default.
//!
//! ## Violation Detection
//!
//! Runs host-side inside `log()` — it cannot be tampered with by the guest.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use garden_ebpf::events::{SecurityEvent, SecurityEventKind};
use serde::Serialize;

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB
const DEFAULT_MAX_FILES: usize = 5;

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
                    event.comm, event.pid, bytes
                ),
            })
        }
        SecurityEventKind::TcpRecv { bytes } if *bytes > 50_000_000 => {
            Some(Violation {
                severity: "medium",
                rule: "large_download",
                message: format!(
                    "process '{}' (pid {}) received {} bytes over TCP (>50MB threshold)",
                    event.comm, event.pid, bytes
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
    let time_secs = (secs % 86400) as u32;
    let hh = time_secs / 3600;
    let mm = (time_secs % 3600) / 60;
    let ss = time_secs % 60;

    // Compute year, month, day from days since 1970-01-01
    // Algorithm: https://howardhinnant.github.io/date_algorithms.html
    let days = secs / 86400;
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
// Rotating file wrapper
// ---------------------------------------------------------------------------

struct RotatingFile {
    file: std::fs::File,
    /// Bytes written to the current file so far.
    current_bytes: u64,
}

// ---------------------------------------------------------------------------
// EventLogger
// ---------------------------------------------------------------------------

pub struct EventLogger {
    session_id: String,
    session_dir: PathBuf,
    rotating: Mutex<RotatingFile>,
    seq: AtomicU64,
    /// Rotate when the active file reaches this size.
    max_file_bytes: u64,
    /// Keep at most this many rotated files (plus the active one).
    max_files: usize,
}

impl EventLogger {
    /// Create a new session log under `~/.garden/sessions/{timestamp_ms}/`.
    pub fn new() -> anyhow::Result<Self> {
        Self::with_limits(DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_FILES)
    }

    /// Create with custom rotation limits (exposed for testing).
    pub fn with_limits(max_file_bytes: u64, max_files: usize) -> anyhow::Result<Self> {
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

        let rotating = open_log_file(&session_dir)?;

        Ok(Self {
            session_id,
            session_dir,
            rotating: Mutex::new(rotating),
            seq: AtomicU64::new(0),
            max_file_bytes,
            max_files,
        })
    }

    /// Path to the session directory (contains `events.ndjson` and rotated files).
    pub fn session_dir(&self) -> &Path {
        &self.session_dir
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Write one event to the log, rotating if the file has reached `max_file_bytes`.
    pub fn log(&self, event: &SecurityEvent) -> anyhow::Result<()> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let violation = detect_violation(event);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch");
        let ts = format_iso8601(now.as_secs(), now.subsec_millis());

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

        let mut rotating = self.rotating.lock().unwrap();

        // Rotate before writing if this line would push us over the limit
        if rotating.current_bytes + json.len() as u64 > self.max_file_bytes {
            self.rotate(&mut rotating)?;
        }

        rotating.file.write_all(json.as_bytes())?;
        rotating.current_bytes += json.len() as u64;

        Ok(())
    }

    /// Rotate log files:
    ///   events.{max_files-1}.ndjson → deleted
    ///   events.{n}.ndjson → events.{n+1}.ndjson  (for n = max_files-2 down to 1)
    ///   events.1.ndjson → events.2.ndjson (if exists)
    ///   events.ndjson   → events.1.ndjson
    ///   (fresh file)    → events.ndjson
    fn rotate(&self, rotating: &mut RotatingFile) -> anyhow::Result<()> {
        // Flush and drop the current file handle before renaming
        rotating.file.flush()?;
        // Drop the file by replacing with a placeholder; we'll reopen below
        drop(std::mem::replace(
            &mut rotating.file,
            // Temporarily open /dev/null as a stand-in so the field is valid
            // while we do the renames. We'll replace it again at the end.
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/null")
                .unwrap_or_else(|_| {
                    // Absolute fallback: re-open the existing log file
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(self.session_dir.join("events.ndjson"))
                        .expect("failed to open events.ndjson as fallback")
                }),
        ));

        let base = &self.session_dir;

        // Delete the oldest file if it exists (events.{max_files}.ndjson)
        let oldest = base.join(format!("events.{}.ndjson", self.max_files));
        if oldest.exists() {
            std::fs::remove_file(&oldest)?;
        }

        // Shift existing rotated files: events.{n} → events.{n+1}
        for n in (1..self.max_files).rev() {
            let src = base.join(format!("events.{}.ndjson", n));
            let dst = base.join(format!("events.{}.ndjson", n + 1));
            if src.exists() {
                std::fs::rename(&src, &dst)?;
            }
        }

        // Rotate active log: events.ndjson → events.1.ndjson
        let active = base.join("events.ndjson");
        if active.exists() {
            std::fs::rename(&active, base.join("events.1.ndjson"))?;
        }

        // Open the fresh active log file
        let fresh = open_log_file(base)?;
        *rotating = fresh;

        Ok(())
    }
}

/// Open (or create) `events.ndjson` in `dir` and return a `RotatingFile`.
fn open_log_file(dir: &Path) -> anyhow::Result<RotatingFile> {
    let path = dir.join("events.ndjson");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let current_bytes = file.metadata()?.len();
    Ok(RotatingFile { file, current_bytes })
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

    // ---- violation detection ----

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
        let ev = make_event(200, "curl", SecurityEventKind::TcpSend { bytes: 15_000_000 });
        let v = detect_violation(&ev).unwrap();
        assert_eq!(v.severity, "high");
        assert_eq!(v.rule, "data_exfiltration");
    }

    #[test]
    fn test_no_violation_for_small_tcp_send() {
        let ev = make_event(200, "curl", SecurityEventKind::TcpSend { bytes: 1024 });
        assert!(detect_violation(&ev).is_none());
    }

    #[test]
    fn test_large_download_detected() {
        let ev = make_event(300, "wget", SecurityEventKind::TcpRecv { bytes: 60_000_000 });
        let v = detect_violation(&ev).unwrap();
        assert_eq!(v.severity, "medium");
        assert_eq!(v.rule, "large_download");
    }

    #[test]
    fn test_module_load_violation() {
        let ev = make_event(
            400,
            "insmod",
            SecurityEventKind::ModuleLoad { size: 4096, args: "".into() },
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

    // ---- ISO 8601 formatting ----

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

    // ---- log rotation ----

    #[test]
    fn test_rotation_creates_rotated_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Tiny limit: 100 bytes per file, keep 3
        let logger = EventLogger::with_limits(100, 3).unwrap();
        // Override session_dir isn't exposed, so we test via a fresh logger
        // pointed at a temp dir using the internal helper directly.
        let _ = dir; // kept alive

        // Instead: test the rotate() mechanic in isolation using open_log_file
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path();

        // Write initial content to events.ndjson
        std::fs::write(base.join("events.ndjson"), b"initial line\n").unwrap();

        // Build a RotatingFile and exercise rotate()
        let mut rf = open_log_file(base).unwrap();
        rf.current_bytes = 9999; // pretend it's full

        let logger = EventLogger {
            session_id: "test".into(),
            session_dir: base.to_path_buf(),
            rotating: Mutex::new(open_log_file(base).unwrap()),
            seq: AtomicU64::new(0),
            max_file_bytes: 100,
            max_files: 3,
        };

        // Trigger rotation by writing to a full logger
        let mut rotating = logger.rotating.lock().unwrap();
        rotating.current_bytes = 9999;
        drop(rotating);
        logger
            .log(&make_event(1, "test", SecurityEventKind::ProcessExit { exit_code: 0 }))
            .unwrap();

        // events.1.ndjson should now exist (the original events.ndjson was rotated)
        assert!(base.join("events.1.ndjson").exists(), "events.1.ndjson should exist after rotation");
        // events.ndjson should be fresh (only contains the new event)
        let fresh = std::fs::read_to_string(base.join("events.ndjson")).unwrap();
        assert!(fresh.contains("\"seq\":1"), "fresh log should contain the new event");
    }

    #[test]
    fn test_rotation_deletes_oldest_beyond_max_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path();

        // Pre-populate rotated files 1..=3 (max_files = 3)
        for i in 1..=3usize {
            std::fs::write(
                base.join(format!("events.{}.ndjson", i)),
                format!("old {}\n", i),
            )
            .unwrap();
        }
        std::fs::write(base.join("events.ndjson"), b"current\n").unwrap();

        let logger = EventLogger {
            session_id: "test".into(),
            session_dir: base.to_path_buf(),
            rotating: Mutex::new(open_log_file(base).unwrap()),
            seq: AtomicU64::new(0),
            max_file_bytes: 1, // force immediate rotation
            max_files: 3,
        };

        logger
            .log(&make_event(1, "test", SecurityEventKind::ProcessExit { exit_code: 0 }))
            .unwrap();

        // events.3.ndjson should have been deleted (was the oldest beyond max_files=3)
        // After rotation: old 1→2, old 2→3, current→1, fresh→events.ndjson
        // events.4.ndjson should NOT exist
        assert!(!base.join("events.4.ndjson").exists(), "events.4.ndjson must not exist");
        assert!(base.join("events.1.ndjson").exists());
        assert!(base.join("events.2.ndjson").exists());
        assert!(base.join("events.3.ndjson").exists());
    }
}

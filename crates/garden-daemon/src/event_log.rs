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

use std::collections::HashMap;
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

/// Lexically normalize a path by collapsing `.` and `..` segments without
/// touching the filesystem. Prevents traversal bypass of prefix-based checks
/// (e.g. `/workspace/../../etc/shadow` → `/etc/shadow`).
pub(crate) fn normalize_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                if absolute || stack.last().is_some_and(|s| *s != "..") {
                    stack.pop();
                } else {
                    stack.push("..");
                }
            }
            _ => stack.push(part),
        }
    }
    let joined = stack.join("/");
    if absolute {
        if joined.is_empty() { "/".to_string() } else { format!("/{}", joined) }
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// Whether an access to `/proc/<target>/...` is self-introspection or
/// cross-process. Returned only if the path matches a known-sensitive leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcTarget { Self_, Other }

/// Classify a proc path against the sensitive-leaf list, after normalization.
/// Returns `None` if the path is not under `/proc/<pid_or_self>/<sensitive>`.
fn classify_proc_memory_path(path: &str) -> Option<ProcTarget> {
    let norm = normalize_path(path);
    let rest = norm.strip_prefix("/proc/")?;
    let (pid_part, after_pid) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => return None,
    };
    let target = if pid_part == "self" {
        ProcTarget::Self_
    } else if !pid_part.is_empty() && pid_part.chars().all(|c| c.is_ascii_digit()) {
        ProcTarget::Other
    } else {
        return None;
    };
    let is_sensitive = matches!(after_pid, "mem" | "maps" | "pagemap" | "smaps"
        | "status" | "cmdline" | "wchan" | "stack" | "syscall" | "environ")
        || after_pid.starts_with("ns/");
    if is_sensitive { Some(target) } else { None }
}

/// Returns true if the open flags indicate write intent (O_WRONLY or O_RDWR).
fn is_write_intent(flags: u32) -> bool {
    let mode = flags & 3;
    mode == 1 || mode == 2
}

/// Standard device nodes that are safe to write to from any process.
/// Takes the already-normalized path so `..` traversal cannot smuggle
/// `/workspace/../../etc/shadow` past this check.
fn is_allowed_device_write(norm: &str) -> bool {
    if matches!(
        norm,
        "/dev/null" | "/dev/zero" | "/dev/urandom" | "/dev/random"
            | "/dev/tty" | "/dev/stdin" | "/dev/stdout" | "/dev/stderr"
            | "/dev/fd/1" | "/dev/fd/2"
    ) {
        return true;
    }
    if norm.starts_with("/proc/self/fd/") {
        return true;
    }
    if norm.starts_with("/tmp/") || norm.starts_with("/run/") {
        return true;
    }
    false
}

/// Returns true if the binary basename is on the privileged-tool blocklist.
fn is_privileged_binary(binary: &str) -> bool {
    const BLOCKLIST: &[&str] = &[
        "su", "sudo", "modprobe", "insmod", "rmmod",
        "newuidmap", "newgidmap", "pkexec", "dbus-daemon",
        "nsenter", "unshare",
    ];
    let basename = binary.rsplit('/').next().unwrap_or(binary);
    BLOCKLIST.contains(&basename)
}

fn detect_violation(event: &SecurityEvent) -> Option<Violation> {
    match &event.kind {
        // Namespace escape: /proc/<pid>/ns/ path opened. Checked before the
        // proc_memory arms because the ns/ path also matches sensitive_leaf.
        SecurityEventKind::FileAccess { path, .. }
            if event.pid != 1 && {
                let norm = normalize_path(path);
                if let Some(rest) = norm.strip_prefix("/proc/") {
                    if let Some(slash) = rest.find('/') {
                        let pid_part = &rest[..slash];
                        let after = &rest[slash + 1..];
                        (pid_part == "self"
                            || (!pid_part.is_empty()
                                && pid_part.chars().all(|c| c.is_ascii_digit())))
                            && after.starts_with("ns/")
                    } else { false }
                } else { false }
            } =>
        {
            Some(Violation {
                severity: "high",
                rule: "namespace_escape_attempt",
                message: format!(
                    "process '{}' (pid {}) accessed namespace entry '{}'",
                    event.comm, event.pid, path
                ),
            })
        }

        // Self-introspection: /proc/self/{mem,maps,status,environ,...}.
        // Still a sandbox leak (ASLR, capset, env vars, ...) — different
        // rule name so it's not conflated with cross-process memory reads.
        SecurityEventKind::FileAccess { path, .. }
            if event.pid != 1
                && classify_proc_memory_path(path) == Some(ProcTarget::Self_) =>
        {
            Some(Violation {
                severity: "high",
                rule: "self_process_introspection",
                message: format!(
                    "process '{}' (pid {}) inspected own process state via '{}'",
                    event.comm, event.pid, path
                ),
            })
        }

        // Cross-process memory access via /proc/<other-pid>/mem et al.
        SecurityEventKind::FileAccess { path, .. }
            if event.pid != 1
                && classify_proc_memory_path(path) == Some(ProcTarget::Other) =>
        {
            Some(Violation {
                severity: "high",
                rule: "cross_process_memory",
                message: format!(
                    "process '{}' (pid {}) accessed cross-process memory path '{}'",
                    event.comm, event.pid, path
                ),
            })
        }

        // Sensitive kernel interfaces: raw memory devices, kernel log,
        // symbol table, sysrq trigger. Kernel blocks the common ones via
        // lsm_file_open; this arm catches any that slipped past (e.g.
        // new targets not yet in the in-kernel block list) and classifies
        // sysrq-trigger correctly rather than as a generic write.
        SecurityEventKind::FileAccess { path, .. }
            if event.pid != 1
                && matches!(normalize_path(path).as_str(),
                    "/dev/mem" | "/dev/kmem" | "/dev/port"
                    | "/dev/kmsg" | "/proc/kallsyms" | "/proc/kcore"
                    | "/proc/sysrq-trigger") =>
        {
            Some(Violation {
                severity: "critical",
                rule: "sensitive_kernel_access",
                message: format!(
                    "process '{}' (pid {}) attempted to open sensitive kernel interface '{}'",
                    event.comm, event.pid, path
                ),
            })
        }

        // Path traversal: raw path contains `..` segments that resolve
        // outside /workspace. The eBPF probe emits the pre-lookup string
        // from the openat syscall, so traversal attempts sneak past any
        // prefix check on the raw path. Canonicalize here and flag when
        // the resolved target escapes the workspace. In-kernel d_path
        // would be stricter (catches symlink traversal too) but is a
        // separate probe rework.
        SecurityEventKind::FileAccess { path, .. }
            if event.pid != 1 && {
                let has_dotdot = path.split('/').any(|seg| seg == "..");
                if !has_dotdot {
                    false
                } else {
                    let norm = normalize_path(path);
                    !(norm == "/workspace" || norm.starts_with("/workspace/"))
                }
            } =>
        {
            Some(Violation {
                severity: "high",
                rule: "path_traversal_attempt",
                message: format!(
                    "process '{}' (pid {}) used path traversal at '{}' (resolves to '{}')",
                    event.comm, event.pid, path, normalize_path(path)
                ),
            })
        }

        // Gap 2: write-intent open outside /workspace.
        // Only fires on absolute paths — relative paths cannot be resolved
        // from the string alone (the actual target depends on the process's
        // cwd, which the tracepoint doesn't capture), and the in-kernel
        // LSM hook now enforces the true canonical target via bpf_d_path.
        // So for relative paths we trust the kernel: if it made it past the
        // LSM hook, the resolved target was inside an allowlisted directory.
        // Normalize before prefix-check so `/workspace/../etc/shadow` is
        // not accidentally allowlisted by the literal `/workspace` prefix.
        SecurityEventKind::FileAccess { path, flags, .. }
            if event.pid != 1 && is_write_intent(*flags) && path.starts_with('/') && {
                let norm = normalize_path(path);
                !(norm == "/workspace"
                    || norm.starts_with("/workspace/")
                    || is_allowed_device_write(&norm))
            } =>
        {
            Some(Violation {
                severity: "medium",
                rule: "write_outside_workspace",
                message: format!(
                    "process '{}' (pid {}) attempted to write to '{}' (outside /workspace)",
                    event.comm, event.pid, path
                ),
            })
        }

        // Gap 3: exec of a known privilege-escalation binary.
        // Checks both the exec path (symlink case: /bin/nsenter) and argv[0]
        // (direct busybox invocation: /bin/busybox with argv[0] = nsenter).
        SecurityEventKind::ProcessExec { binary, args, .. }
            if is_privileged_binary(binary)
                || args.first().map(|a| is_privileged_binary(a)).unwrap_or(false) =>
        {
            let name = if is_privileged_binary(binary) {
                binary.rsplit('/').next().unwrap_or(binary).to_string()
            } else {
                args.first()
                    .map(|a| a.rsplit('/').next().unwrap_or(a).to_string())
                    .unwrap_or_else(|| binary.clone())
            };
            Some(Violation {
                severity: "high",
                rule: "privileged_binary_exec",
                message: format!(
                    "process '{}' (pid {}) attempted to exec privileged binary '{}'",
                    event.comm, event.pid, name
                ),
            })
        }

        SecurityEventKind::CredsChanged { old_uid, new_uid } if *old_uid != 0 && *new_uid == 0 => {
            Some(Violation {
                severity: "critical",
                rule: "privilege_escalation",
                message: format!(
                    "process '{}' (pid {}) escalated to root (uid {} → 0)",
                    event.comm, event.pid, old_uid
                ),
            })
        }

        // Note: TcpSend/TcpRecv per-event checks are removed — cumulative
        // tracking in EventLogger.check_cumulative_bytes() handles this now.

        SecurityEventKind::ModuleLoad { .. } => Some(Violation {
            severity: "high",
            rule: "module_load",
            message: format!(
                "process '{}' (pid {}) attempted to load a kernel module (CONFIG_MODULES=n)",
                event.comm, event.pid
            ),
        }),
        SecurityEventKind::FinitModuleLoad { .. } => Some(Violation {
            severity: "high",
            rule: "finit_module_load",
            message: format!(
                "process '{}' (pid {}) attempted finit_module — kernel module load via fd",
                event.comm, event.pid
            ),
        }),
        SecurityEventKind::PtraceAttempt { request, target_pid } => Some(Violation {
            severity: "high",
            rule: "ptrace_attempt",
            message: format!(
                "process '{}' (pid {}) called ptrace(request={}, target_pid={}) — process injection attempt",
                event.comm, event.pid, request, target_pid
            ),
        }),
        SecurityEventKind::BpfSyscall { cmd } if *cmd == 5 && event.pid != 1 => Some(Violation {
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

        // Destructive file ops on critical system paths
        SecurityEventKind::FileDelete { path, .. }
            if event.pid != 1
                && (path.starts_with("/etc/") || path.starts_with("/usr/") || path.starts_with("/bin/") || path.starts_with("/sbin/")) =>
        {
            Some(Violation {
                severity: "high",
                rule: "critical_file_delete",
                message: format!(
                    "process '{}' (pid {}) deleted critical system file '{}'",
                    event.comm, event.pid, path
                ),
            })
        }
        SecurityEventKind::FileRename { old_path, new_path, .. }
            if event.pid != 1
                && (old_path.starts_with("/etc/") || old_path.starts_with("/usr/")) =>
        {
            Some(Violation {
                severity: "high",
                rule: "critical_file_rename",
                message: format!(
                    "process '{}' (pid {}) renamed critical system file '{}' → '{}'",
                    event.comm, event.pid, old_path, new_path
                ),
            })
        }

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
    /// Cumulative per-PID byte counters for data exfiltration detection (#11).
    /// Key: pid, Value: (total_sent, total_received)
    byte_counters: Mutex<HashMap<u32, (u64, u64)>>,
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
            byte_counters: Mutex::new(HashMap::new()),
        })
    }

    /// Path to the session directory (contains `events.ndjson` and rotated files).
    pub fn session_dir(&self) -> &Path {
        &self.session_dir
    }

    #[allow(dead_code)]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Write one event to the log, rotating if the file has reached `max_file_bytes`.
    /// Log the event and return any violation detected, so callers can enforce.
    pub fn log(&self, event: &SecurityEvent) -> anyhow::Result<Option<Violation>> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;

        // Check for static violations first
        let mut violation = detect_violation(event);

        // Issue #11: Cumulative per-PID byte tracking for data exfiltration.
        // Individual TcpSend/TcpRecv events carry per-call byte counts, but
        // we need to accumulate over the process lifetime to detect exfil.
        if violation.is_none() {
            violation = self.check_cumulative_bytes(event);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch");
        let ts = format_iso8601(now.as_secs(), now.subsec_millis());

        // If there's a violation, override "allowed" to false in the event —
        // the tracepoint fires before the LSM and doesn't know the LSM will
        // block. This makes the log accurately reflect enforcement.
        let corrected_event;
        let event_ref = if violation.is_some() {
            corrected_event = event.with_allowed_false();
            &corrected_event
        } else {
            event
        };

        let line = LogLine {
            ts,
            session_id: &self.session_id,
            seq,
            pid: event_ref.pid,
            comm: &event_ref.comm,
            event: event_ref,
            violation: violation.clone(),
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

        Ok(violation)
    }

    /// Accumulate TCP bytes per PID and check against exfiltration thresholds.
    ///
    /// Returns a violation if the cumulative bytes cross the threshold.
    /// This replaces the old per-event threshold checks — a process sending
    /// 1000 × 10KB writes should still trigger at 10MB total.
    fn check_cumulative_bytes(&self, event: &SecurityEvent) -> Option<Violation> {
        const SEND_THRESHOLD: u64 = 10_000_000;  // 10 MB
        const RECV_THRESHOLD: u64 = 50_000_000;  // 50 MB

        let (send_delta, recv_delta) = match &event.kind {
            SecurityEventKind::TcpSend { bytes } => (*bytes, 0u64),
            SecurityEventKind::TcpRecv { bytes } => (0u64, *bytes),
            _ => return None,
        };

        let mut counters = self.byte_counters.lock().unwrap();
        let entry = counters.entry(event.pid).or_insert((0, 0));

        let was_below_send = entry.0 < SEND_THRESHOLD;
        let was_below_recv = entry.1 < RECV_THRESHOLD;

        entry.0 = entry.0.saturating_add(send_delta);
        entry.1 = entry.1.saturating_add(recv_delta);

        // Only fire the violation once — when crossing the threshold
        if was_below_send && entry.0 >= SEND_THRESHOLD {
            return Some(Violation {
                severity: "high",
                rule: "data_exfiltration",
                message: format!(
                    "process '{}' (pid {}) cumulative TCP send reached {} bytes (>{}B threshold)",
                    event.comm, event.pid, entry.0, SEND_THRESHOLD
                ),
            });
        }
        if was_below_recv && entry.1 >= RECV_THRESHOLD {
            return Some(Violation {
                severity: "medium",
                rule: "large_download",
                message: format!(
                    "process '{}' (pid {}) cumulative TCP recv reached {} bytes (>{}B threshold)",
                    event.comm, event.pid, entry.1, RECV_THRESHOLD
                ),
            });
        }

        None
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
            uid: 1000,
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
    fn test_cumulative_data_exfiltration_detected() {
        // Cumulative tracking is in EventLogger, not detect_violation
        let logger = EventLogger::with_limits(10 * 1024 * 1024, 5).unwrap();

        // Send 9 events of 1.5MB each — total = 13.5MB, should trigger at 10MB
        for i in 0..9 {
            let ev = make_event(200, "curl", SecurityEventKind::TcpSend { bytes: 1_500_000 });
            let result = logger.log(&ev).unwrap();
            if i < 6 {
                // Below 10MB threshold
                assert!(result.is_none(), "Event {} should not trigger violation", i);
            } else if i == 6 {
                // 7 × 1.5MB = 10.5MB — crosses threshold
                assert!(result.is_some(), "Event {} should trigger violation", i);
                let v = result.unwrap();
                assert_eq!(v.rule, "data_exfiltration");
            }
            // After first trigger, no more violations (one-shot)
        }
    }

    #[test]
    fn test_no_violation_for_small_tcp_send() {
        let ev = make_event(200, "curl", SecurityEventKind::TcpSend { bytes: 1024 });
        assert!(detect_violation(&ev).is_none());
    }

    #[test]
    fn test_large_download_cumulative() {
        let logger = EventLogger::with_limits(10 * 1024 * 1024, 5).unwrap();
        // Send 10 events of 6MB each — total crosses 50MB at event index 8
        for i in 0..10 {
            let ev = make_event(300, "wget", SecurityEventKind::TcpRecv { bytes: 6_000_000 });
            let result = logger.log(&ev).unwrap();
            if i < 8 {
                assert!(result.is_none(), "Event {} should not trigger", i);
            } else if i == 8 {
                assert!(result.is_some(), "Event {} should trigger large_download", i);
                assert_eq!(result.unwrap().rule, "large_download");
            }
        }
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

    #[test]
    fn test_finit_module_violation() {
        let ev = make_event(
            700,
            "modprobe",
            SecurityEventKind::FinitModuleLoad { flags: 0, args: "".into() },
        );
        let v = detect_violation(&ev).unwrap();
        assert_eq!(v.rule, "finit_module_load");
    }

    #[test]
    fn test_ptrace_violation() {
        let ev = make_event(
            800,
            "gdb",
            SecurityEventKind::PtraceAttempt { request: 16, target_pid: 42 },
        );
        let v = detect_violation(&ev).unwrap();
        assert_eq!(v.rule, "ptrace_attempt");
    }

    #[test]
    fn test_critical_file_delete_violation() {
        let ev = make_event(
            900,
            "rm",
            SecurityEventKind::FileDelete { path: "/etc/passwd".into(), flags: 0 },
        );
        let v = detect_violation(&ev).unwrap();
        assert_eq!(v.rule, "critical_file_delete");
    }

    #[test]
    fn test_workspace_file_delete_no_violation() {
        let ev = make_event(
            900,
            "rm",
            SecurityEventKind::FileDelete { path: "/workspace/test.txt".into(), flags: 0 },
        );
        assert!(detect_violation(&ev).is_none());
    }

    #[test]
    fn test_critical_file_rename_violation() {
        let ev = make_event(
            1000,
            "mv",
            SecurityEventKind::FileRename {
                old_path: "/etc/shadow".into(),
                new_path: "/etc/shadow.bak".into(),
                flags: 0,
            },
        );
        let v = detect_violation(&ev).unwrap();
        assert_eq!(v.rule, "critical_file_rename");
    }

    #[test]
    fn test_proc_self_fd_write_allowed() {
        let ev = make_event(
            50,
            "dhcp",
            SecurityEventKind::FileAccess {
                path: "/proc/self/fd/3".into(),
                flags: 1, // O_WRONLY
                allowed: true,
            },
        );
        // Should NOT trigger write_outside_workspace because /proc/self/fd is allowed
        assert!(detect_violation(&ev).is_none());
    }

    #[test]
    fn test_relative_path_write_not_flagged() {
        // Relative paths cannot be resolved from the string alone — the true
        // target depends on cwd, which the tracepoint doesn't capture. The
        // in-kernel LSM hook now enforces canonical-path policy, so if a
        // write event with a relative path made it out of the kernel, the
        // resolved target was inside an allowlist. Don't false-flag here.
        let ev = make_event(
            119,
            "sh",
            SecurityEventKind::FileAccess {
                path: "write_test.txt".into(),
                flags: 1, // O_WRONLY
                allowed: true,
            },
        );
        assert!(detect_violation(&ev).is_none());
    }

    #[test]
    fn test_tmp_write_allowed() {
        let ev = make_event(
            50,
            "python",
            SecurityEventKind::FileAccess {
                path: "/tmp/scratch.txt".into(),
                flags: 1,
                allowed: true,
            },
        );
        assert!(detect_violation(&ev).is_none());
    }

    // ---- path normalization + policy hardening fixes ----

    #[test]
    fn test_normalize_path_collapses_dotdot() {
        assert_eq!(normalize_path("/workspace/../etc/shadow"), "/etc/shadow");
        assert_eq!(normalize_path("/workspace/../../etc/shadow"), "/etc/shadow");
        assert_eq!(normalize_path("/workspace/./a//b/"), "/workspace/a/b");
        assert_eq!(normalize_path("/a/b/../../c"), "/c");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("/workspace"), "/workspace");
    }

    #[test]
    fn test_path_traversal_not_allowlisted_as_workspace() {
        // Write-mode traversal escapes workspace — the traversal rule
        // fires first (more specific signal than a plain write_outside).
        let ev = make_event(
            50,
            "sh",
            SecurityEventKind::FileAccess {
                path: "/workspace/../../etc/shadow".into(),
                flags: 1, // O_WRONLY
                allowed: true,
            },
        );
        let v = detect_violation(&ev).expect("traversal should be flagged");
        assert_eq!(v.rule, "path_traversal_attempt");
    }

    #[test]
    fn test_read_traversal_fires_when_escaping_workspace() {
        let ev = make_event(
            50,
            "sh",
            SecurityEventKind::FileAccess {
                path: "/workspace/../init".into(),
                flags: 0, // O_RDONLY
                allowed: true,
            },
        );
        let v = detect_violation(&ev).expect("read traversal escaping workspace should fire");
        assert_eq!(v.rule, "path_traversal_attempt");
        assert_eq!(v.severity, "high");
    }

    #[test]
    fn test_dotdot_staying_within_workspace_is_not_flagged() {
        // `/workspace/a/../b` normalizes to `/workspace/b` — legitimate
        // relative lookup, not an escape attempt.
        let ev = make_event(
            50,
            "sh",
            SecurityEventKind::FileAccess {
                path: "/workspace/a/../b".into(),
                flags: 0,
                allowed: true,
            },
        );
        assert!(detect_violation(&ev).is_none());
    }

    #[test]
    fn test_proc_self_environ_is_self_introspection() {
        let ev = make_event(
            50,
            "sh",
            SecurityEventKind::FileAccess {
                path: "/proc/self/environ".into(),
                flags: 0,
                allowed: true,
            },
        );
        let v = detect_violation(&ev).expect("environ should be flagged");
        assert_eq!(v.rule, "self_process_introspection");
    }

    #[test]
    fn test_proc_other_pid_mem_is_cross_process() {
        let ev = make_event(
            50,
            "sh",
            SecurityEventKind::FileAccess {
                path: "/proc/1234/mem".into(),
                flags: 0,
                allowed: true,
            },
        );
        let v = detect_violation(&ev).expect("cross-pid mem should be flagged");
        assert_eq!(v.rule, "cross_process_memory");
    }

    #[test]
    fn test_sysrq_trigger_is_sensitive_kernel_access() {
        let ev = make_event(
            50,
            "sh",
            SecurityEventKind::FileAccess {
                path: "/proc/sysrq-trigger".into(),
                flags: 1,
                allowed: true,
            },
        );
        let v = detect_violation(&ev).expect("sysrq-trigger should be flagged");
        assert_eq!(v.rule, "sensitive_kernel_access");
    }

    #[test]
    fn test_workspace_subdir_still_allowed() {
        let ev = make_event(
            50,
            "sh",
            SecurityEventKind::FileAccess {
                path: "/workspace/data/out.txt".into(),
                flags: 1,
                allowed: true,
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
        let _logger = EventLogger::with_limits(100, 3).unwrap();
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
            byte_counters: Mutex::new(HashMap::new()),
        };

        // Trigger rotation by writing to a full logger
        let mut rotating = logger.rotating.lock().unwrap();
        rotating.current_bytes = 9999;
        drop(rotating);
        logger
            .log(&make_event(1, "test", SecurityEventKind::ProcessExit { exit_status: 0, exit_signal: 0 }))
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
            byte_counters: Mutex::new(HashMap::new()),
        };

        logger
            .log(&make_event(1, "test", SecurityEventKind::ProcessExit { exit_status: 0, exit_signal: 0 }))
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

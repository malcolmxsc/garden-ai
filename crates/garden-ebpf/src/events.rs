//! Security event types emitted by eBPF probes.

use serde::{Deserialize, Serialize};

/// A security event captured by the eBPF probes in the guest kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Timestamp in nanoseconds since boot.
    pub timestamp_ns: u64,
    /// Process ID that triggered the event.
    pub pid: u32,
    /// Process name.
    pub comm: String,
    /// The specific event type.
    pub kind: SecurityEventKind,
}

/// Categories of security events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecurityEventKind {
    /// A file was opened or accessed.
    FileAccess {
        path: String,
        flags: u32,
        allowed: bool,
    },
    /// A network connection was attempted.
    NetworkConnect {
        dest_ip: String,
        dest_port: u16,
        protocol: String,
        allowed: bool,
    },
    /// A process was executed.
    ProcessExec {
        binary: String,
        args: Vec<String>,
        allowed: bool,
    },
    /// A syscall was invoked that matches a security policy.
    SyscallTrace {
        syscall_nr: u64,
        syscall_name: String,
        allowed: bool,
    },
}

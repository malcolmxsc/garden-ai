//! Shared types between eBPF kernel probes and userspace loader.
//!
//! This crate is `no_std`-compatible so it can be used from BPF programs
//! (which have no access to the standard library). The `user` feature
//! enables serde support for the host-side deserializer.

#![cfg_attr(not(feature = "user"), no_std)]

/// Maximum length for the process name (comm) field.
/// Matches the kernel's TASK_COMM_LEN.
pub const MAX_COMM_LEN: usize = 16;

/// Maximum length for file paths captured by probes.
pub const MAX_PATH_LEN: usize = 256;

/// Maximum length for execve argument capture.
pub const MAX_ARGS_LEN: usize = 256;

/// Discriminant for the event kind, matching `SecurityEventKind` variants.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// Process execution (sys_enter_execve).
    Execve = 1,
    /// File open/access (sys_enter_openat).
    Openat = 2,
    /// Network connection attempt (sys_enter_connect).
    Connect = 3,
    /// DNS query (sys_enter_sendto, UDP port 53) — Tier 2.
    DnsQuery = 4,
    /// Mount attempt (sys_enter_mount) — Tier 2.
    Mount = 5,
    /// BPF program load attempt (sys_enter_bpf) — Tier 2.
    BpfLoad = 6,
    /// Kernel module load attempt (sys_enter_init_module) — Tier 2.
    ModuleLoad = 7,
}

impl EventKind {
    /// Convert from raw u32 discriminant.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Execve),
            2 => Some(Self::Openat),
            3 => Some(Self::Connect),
            4 => Some(Self::DnsQuery),
            5 => Some(Self::Mount),
            6 => Some(Self::BpfLoad),
            7 => Some(Self::ModuleLoad),
            _ => None,
        }
    }
}

/// Raw security event written by BPF programs into `PerfEventArray`.
///
/// This struct uses a flat layout with all fields always present.
/// The `kind` field determines which fields are meaningful:
///
/// - `Execve`: `comm`, `path` (binary), `args` (first arg)
/// - `Openat`: `comm`, `path` (file), `flags` (open flags)
/// - `Connect`: `comm`, `dest_ip`, `dest_port`, `protocol`
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawSecurityEvent {
    /// Event type discriminant (see `EventKind`).
    pub kind: u32,
    /// Process ID (tgid from `bpf_get_current_pid_tgid() >> 32`).
    pub pid: u32,
    /// Timestamp in nanoseconds from `bpf_ktime_get_ns()`.
    pub timestamp_ns: u64,
    /// Process name from `bpf_get_current_comm()`.
    pub comm: [u8; MAX_COMM_LEN],
    /// File path or binary path (null-terminated).
    pub path: [u8; MAX_PATH_LEN],
    /// Execve first argument (null-terminated).
    pub args: [u8; MAX_ARGS_LEN],
    /// Open flags for `openat`, unused for other event types.
    pub flags: u32,
    /// Destination IPv4 address in network byte order (for `connect`).
    pub dest_ip: u32,
    /// Destination port in host byte order (for `connect`).
    pub dest_port: u16,
    /// IP protocol number: 6=TCP, 17=UDP (for `connect`).
    pub protocol: u16,
}

impl RawSecurityEvent {
    /// Create a zeroed event. Used by BPF programs to initialize on the stack.
    pub fn zeroed() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// Extract a null-terminated string from a fixed-size byte array.
pub fn bytes_to_str(bytes: &[u8]) -> &str {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..len]).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_event_size_stable() {
        // Ensure the struct fits in a single perf event buffer slot
        assert!(
            core::mem::size_of::<RawSecurityEvent>() <= 1024,
            "RawSecurityEvent is {} bytes, must be <= 1024",
            core::mem::size_of::<RawSecurityEvent>()
        );
    }

    #[test]
    fn test_raw_event_repr_c_alignment() {
        assert_eq!(core::mem::align_of::<RawSecurityEvent>(), 8);
    }

    #[test]
    fn test_event_kind_roundtrip() {
        assert_eq!(EventKind::from_u32(1), Some(EventKind::Execve));
        assert_eq!(EventKind::from_u32(2), Some(EventKind::Openat));
        assert_eq!(EventKind::from_u32(3), Some(EventKind::Connect));
        assert_eq!(EventKind::from_u32(99), None);
    }

    #[test]
    fn test_bytes_to_str() {
        let mut buf = [0u8; 16];
        buf[..5].copy_from_slice(b"hello");
        assert_eq!(bytes_to_str(&buf), "hello");
    }

    #[test]
    fn test_bytes_to_str_full() {
        let buf = *b"exactly16chars!!";
        assert_eq!(bytes_to_str(&buf), "exactly16chars!!");
    }

    #[test]
    fn test_zeroed_event() {
        let event = RawSecurityEvent::zeroed();
        assert_eq!(event.kind, 0);
        assert_eq!(event.pid, 0);
        assert_eq!(event.timestamp_ns, 0);
    }
}

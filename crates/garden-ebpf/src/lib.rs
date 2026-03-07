//! Garden AI — eBPF Security Daemon (Userspace Loader).
//!
//! This crate runs **inside the guest Linux VM** and uses the `aya` eBPF
//! library to load and manage kernel probes that trace:
//! - Syscalls (file open, exec, socket, etc.)
//! - Network connections (outbound IP filtering)
//! - File access patterns
//!
//! On macOS (the host), this crate compiles as a stub with only the
//! type definitions — the actual eBPF functionality requires a Linux kernel.

pub mod events;
pub mod policy;
pub mod tracer;

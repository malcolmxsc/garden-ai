//! Garden AI — Shared types, errors, and IPC protocol.
//!
//! This crate contains the common data structures used across all Garden AI
//! components: the FFI bridge, MCP server, CLI, and eBPF daemon.

pub mod error;
pub mod ipc;
pub mod types;

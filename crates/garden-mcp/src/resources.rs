//! MCP Resource definitions.
//!
//! Resources expose sandbox state & data to AI clients for context
//! (e.g., security logs, filesystem tree, sandbox status).

/// Resource: sandbox status as a JSON document.
pub struct SandboxStatusResource;

/// Resource: security event log from the eBPF daemon.
pub struct SecurityLogResource;

//! Security policy engine.
//!
//! Defines rules for what the eBPF probes should allow or block
//! (e.g., "block all outbound network to non-local IPs").

use serde::{Deserialize, Serialize};

/// A security policy that governs sandbox behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Human-readable policy name.
    pub name: String,
    /// Rules in this policy.
    pub rules: Vec<PolicyRule>,
}

/// A single rule within a security policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyRule {
    /// Block or allow access to specific file paths.
    FileAccess {
        /// Glob pattern for file paths.
        pattern: String,
        /// Whether to allow or deny.
        action: PolicyAction,
    },
    /// Block or allow network connections.
    Network {
        /// CIDR range or IP address (e.g., "0.0.0.0/0" for all).
        dest: String,
        /// Optional port filter.
        port: Option<u16>,
        /// Whether to allow or deny.
        action: PolicyAction,
    },
    /// Block or allow specific syscalls.
    Syscall {
        /// Syscall name or number.
        name: String,
        /// Whether to allow or deny.
        action: PolicyAction,
    },
}

/// The action to take when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Deny,
    Log,
}

//! IPC message protocol between the Swift UI / CLI and the Rust engine.
//!
//! These messages are serialized as JSON and passed over the FFI boundary
//! or via Unix domain sockets for CLI ↔ daemon communication.

use serde::{Deserialize, Serialize};

use crate::types::{SandboxConfig, SandboxId, SandboxStatus};

/// Request from the host (Swift UI or CLI) to the Rust engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostRequest {
    /// Boot a new sandbox VM with the given configuration.
    Boot { config: SandboxConfig },
    /// Execute a command inside a running sandbox.
    Execute {
        sandbox_id: SandboxId,
        command: String,
        args: Vec<String>,
    },
    /// Query the status of a sandbox.
    Status { sandbox_id: SandboxId },
    /// Stop a running sandbox.
    Stop { sandbox_id: SandboxId },
    /// List all known sandboxes.
    List,
}

/// Response from the Rust engine back to the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EngineResponse {
    /// Sandbox was successfully booted.
    Booted { sandbox_id: SandboxId },
    /// Command execution result.
    ExecutionResult {
        sandbox_id: SandboxId,
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    /// Status of a sandbox.
    StatusResult { status: SandboxStatus },
    /// List of all sandbox statuses.
    ListResult { sandboxes: Vec<SandboxStatus> },
    /// Sandbox was stopped.
    Stopped { sandbox_id: SandboxId },
    /// An error occurred.
    Error { message: String },
}

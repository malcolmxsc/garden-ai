//! Core types shared across Garden AI components.

use serde::{Deserialize, Serialize};

/// Unique identifier for a sandbox VM instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SandboxId(pub String);

/// Current state of a sandbox VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxState {
    /// VM is booting up.
    Booting,
    /// VM is running and ready to accept commands.
    Running,
    /// VM is in the process of shutting down.
    Stopping,
    /// VM has stopped.
    Stopped,
    /// VM encountered an error.
    Error,
}

/// Configuration for a new sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Human-readable name for the sandbox.
    pub name: String,
    /// Path to the Linux kernel image (bzImage).
    pub kernel_path: String,
    /// Path to the root filesystem image.
    pub rootfs_path: String,
    /// Host directories to share via VirtioFS.
    pub shared_dirs: Vec<SharedDirectory>,
    /// Memory allocation in megabytes.
    pub memory_mb: u64,
    /// Number of CPU cores.
    pub cpu_count: u32,
}

/// A host directory shared with the guest VM via VirtioFS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedDirectory {
    /// Path on the host filesystem.
    pub host_path: String,
    /// Mount tag used inside the guest VM.
    pub mount_tag: String,
    /// Whether the guest has read-only access.
    pub read_only: bool,
}

/// Status information about a running sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxStatus {
    pub id: SandboxId,
    pub state: SandboxState,
    pub config: SandboxConfig,
    /// Uptime in seconds (None if not running).
    pub uptime_secs: Option<u64>,
}

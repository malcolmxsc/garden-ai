//! Error types for Garden AI.

use thiserror::Error;

/// Top-level error type for all Garden AI operations.
#[derive(Debug, Error)]
pub enum GardenError {
    #[error("VM error: {0}")]
    Vm(String),

    #[error("MCP protocol error: {0}")]
    Mcp(String),

    #[error("FFI bridge error: {0}")]
    Ffi(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Convenience Result type for Garden AI.
pub type GardenResult<T> = Result<T, GardenError>;

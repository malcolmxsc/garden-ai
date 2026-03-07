//! MCP Server lifecycle management.
//!
//! Handles server initialization, transport setup (stdio / SSE),
//! and routing of JSON-RPC requests to tool handlers.

use anyhow::Result;

/// Configuration for the MCP server.
pub struct McpServerConfig {
    /// Port for the SSE transport (None = stdio only).
    pub sse_port: Option<u16>,
    /// Server name advertised to MCP clients.
    pub server_name: String,
    /// Server version.
    pub server_version: String,
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            sse_port: None,
            server_name: "garden-ai".to_string(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Start the MCP server with the given configuration.
///
/// This is the main entry point called from the FFI bridge or CLI.
pub async fn start_server(_config: McpServerConfig) -> Result<()> {
    tracing::info!("Starting Garden AI MCP server...");
    // TODO: Initialize rmcp server, register tools, start transport
    Ok(())
}

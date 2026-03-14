//! Garden AI MCP Server.
//!
//! Bridges MCP tool calls from AI clients (Claude Desktop, Cursor) to the
//! Garden sandbox guest VM via the existing gRPC-over-vSock transport.
//!
//! Architecture:
//!   AI Client --[MCP/stdio]--> GardenMcpServer --[gRPC/TCP]--> daemon proxy --[vSock]--> guest agent

use std::sync::Arc;

use anyhow::Result;
use garden_common::ipc::{agent_service_client::AgentServiceClient, CommandRequest};
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt};
use tokio::sync::Mutex;
use tonic::transport::Channel;

use crate::tools::*;

/// Configuration for the MCP server.
pub struct McpServerConfig {
    /// Server name advertised to MCP clients.
    pub server_name: String,
    /// Server version.
    pub server_version: String,
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            server_name: "garden-ai".to_string(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// The MCP server that bridges AI client tool calls to the Garden sandbox.
///
/// Holds a gRPC client connection to the daemon's TCP proxy (127.0.0.1:10000),
/// which forwards requests to the guest agent via vSock.
#[derive(Clone)]
pub struct GardenMcpServer {
    grpc_client: Arc<Mutex<AgentServiceClient<Channel>>>,
    tool_router: ToolRouter<Self>,
}

impl GardenMcpServer {
    pub fn new(grpc_client: AgentServiceClient<Channel>) -> Self {
        Self {
            grpc_client: Arc::new(Mutex::new(grpc_client)),
            tool_router: Self::tool_router(),
        }
    }

    /// Execute a command in the guest VM via gRPC.
    async fn exec(
        &self,
        command: &str,
        args: &[&str],
        cwd: &str,
    ) -> std::result::Result<(i32, String, String), String> {
        let mut client = self.grpc_client.lock().await;
        let request = tonic::Request::new(CommandRequest {
            command: command.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: cwd.to_string(),
        });
        match client.execute_command(request).await {
            Ok(response) => {
                let resp = response.into_inner();
                Ok((
                    resp.exit_code,
                    String::from_utf8_lossy(&resp.stdout).to_string(),
                    String::from_utf8_lossy(&resp.stderr).to_string(),
                ))
            }
            Err(status) => Err(format!("gRPC error: {}", status.message())),
        }
    }
}

#[tool_router]
impl GardenMcpServer {
    #[tool(
        description = "Execute a command inside the Garden sandbox VM. Returns stdout, stderr, and exit code."
    )]
    async fn run_command(&self, Parameters(params): Parameters<RunCommandParams>) -> String {
        let arg_refs: Vec<&str> = params.args.iter().map(|s| s.as_str()).collect();
        match self.exec(&params.command, &arg_refs, &params.cwd).await {
            Ok((exit_code, stdout, stderr)) => {
                let mut output = String::new();
                if !stdout.is_empty() {
                    output.push_str(&stdout);
                }
                if !stderr.is_empty() {
                    if !output.is_empty() {
                        output.push('\n');
                    }
                    output.push_str("[stderr]\n");
                    output.push_str(&stderr);
                }
                if exit_code != 0 {
                    if !output.is_empty() {
                        output.push('\n');
                    }
                    output.push_str(&format!("[exit code: {}]", exit_code));
                }
                if output.is_empty() {
                    "(no output)".to_string()
                } else {
                    output
                }
            }
            Err(e) => format!("Error: {}", e),
        }
    }

    #[tool(description = "Read the contents of a file from the sandbox workspace.")]
    async fn read_file(&self, Parameters(params): Parameters<ReadFileParams>) -> String {
        match self.exec("cat", &[&params.path], ".").await {
            Ok((exit_code, stdout, stderr)) => {
                if exit_code != 0 {
                    format!("Error reading file: {}", stderr.trim())
                } else {
                    stdout
                }
            }
            Err(e) => format!("Error: {}", e),
        }
    }

    #[tool(
        description = "Write content to a file in the sandbox workspace. Creates the file if it doesn't exist, overwrites if it does."
    )]
    async fn write_file(&self, Parameters(params): Parameters<WriteFileParams>) -> String {
        // Use sh -c with a heredoc to write arbitrary content safely.
        let script = format!(
            "cat > '{}' << 'GARDEN_WRITE_EOF'\n{}\nGARDEN_WRITE_EOF",
            params.path.replace('\'', "'\\''"),
            params.content
        );
        match self.exec("sh", &["-c", &script], ".").await {
            Ok((exit_code, _stdout, stderr)) => {
                if exit_code != 0 {
                    format!("Error writing file: {}", stderr.trim())
                } else {
                    format!("Successfully wrote to {}", params.path)
                }
            }
            Err(e) => format!("Error: {}", e),
        }
    }

    #[tool(description = "List the contents of a directory in the sandbox workspace.")]
    async fn list_directory(
        &self,
        Parameters(params): Parameters<ListDirectoryParams>,
    ) -> String {
        match self.exec("ls", &["-la", &params.path], ".").await {
            Ok((exit_code, stdout, stderr)) => {
                if exit_code != 0 {
                    format!("Error listing directory: {}", stderr.trim())
                } else {
                    stdout
                }
            }
            Err(e) => format!("Error: {}", e),
        }
    }
}

#[tool_handler]
impl ServerHandler for GardenMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::LATEST,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "garden-ai".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                ..Default::default()
            },
            instructions: Some(
                "Garden AI sandbox server. Execute commands, read/write files, \
                 and list directories inside a hardware-isolated Linux micro-VM."
                    .to_string(),
            ),
        }
    }
}

/// Start the MCP server using stdio transport.
///
/// Connects to the daemon's gRPC proxy at 127.0.0.1:10000, then listens
/// for MCP JSON-RPC messages on stdin/stdout (standard for Claude Desktop).
pub async fn start_server(_config: McpServerConfig) -> Result<()> {
    tracing::info!("Connecting to Garden daemon gRPC proxy...");
    let grpc_client = AgentServiceClient::connect("http://127.0.0.1:10000").await?;
    tracing::info!("Connected. Starting MCP server on stdio...");

    let server = GardenMcpServer::new(grpc_client);
    let transport = rmcp::transport::stdio();
    let service = server.serve(transport).await?;
    service.waiting().await?;

    Ok(())
}

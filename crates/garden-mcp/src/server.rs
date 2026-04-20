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

use crate::prompts::{build_list_prompts_result, dispatch_get_prompt};
use crate::resources::{
    read_recent_events, read_sandbox_status, read_violations, URI_SANDBOX_STATUS,
    URI_SECURITY_EVENTS, URI_SECURITY_VIOLATIONS,
};
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
/// The gRPC connection to the daemon proxy (127.0.0.1:10000) is established
/// lazily on the first tool call, so the MCP server starts successfully even
/// when the daemon is not yet running (prompts and resources work offline).
#[derive(Clone)]
pub struct GardenMcpServer {
    /// Lazily-established gRPC client. None until first tool call.
    grpc_client: Arc<Mutex<Option<AgentServiceClient<Channel>>>>,
    tool_router: ToolRouter<Self>,
}

impl GardenMcpServer {
    pub fn new() -> Self {
        Self {
            grpc_client: Arc::new(Mutex::new(None)),
            tool_router: Self::tool_router(),
        }
    }

    /// Return a connected gRPC client, connecting now if not yet connected.
    async fn client(&self) -> std::result::Result<tokio::sync::MutexGuard<'_, Option<AgentServiceClient<Channel>>>, String> {
        let mut guard = self.grpc_client.lock().await;
        if guard.is_none() {
            match AgentServiceClient::connect("http://127.0.0.1:10000").await {
                Ok(c) => {
                    tracing::info!("Connected to Garden daemon gRPC proxy.");
                    *guard = Some(c);
                }
                Err(e) => {
                    return Err(format!(
                        "Garden sandbox is not running. Start garden-daemon first. ({})",
                        e
                    ));
                }
            }
        }
        Ok(guard)
    }

    /// Execute a command in the guest VM via gRPC.
    async fn exec(
        &self,
        command: &str,
        args: &[&str],
        cwd: &str,
    ) -> std::result::Result<(i32, String, String), String> {
        let mut guard = self.client().await?;
        let client = guard.as_mut().unwrap();
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
            Err(e) => {
                // Connection may have dropped — clear it so next call reconnects
                *guard = None;
                Err(format!("gRPC error: {}", e.message()))
            }
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

    #[tool(
        description = "Analyse recent eBPF security events and policy violations from the Garden \
                       sandbox. Summarises what the AI workload has been doing, flags suspicious \
                       patterns, rates overall risk (LOW/MEDIUM/HIGH), and recommends policy changes."
    )]
    async fn analyze_security(&self) -> String {
        let events = read_recent_events();
        let violations = read_violations();
        format!(
            "## Recent Security Events\n\n{events}\n\n## Policy Violations\n\n{violations}"
        )
    }

    #[tool(
        description = "Full sandbox health report: VM running state, uptime, kernel version, \
                       recent security events, and any policy violations."
    )]
    async fn sandbox_report(&self) -> String {
        let status = read_sandbox_status().await;
        let events = read_recent_events();
        let violations = read_violations();
        format!(
            "## Sandbox Status\n\n{status}\n\n\
             ## Recent Security Events (last 50)\n\n{events}\n\n\
             ## Policy Violations\n\n{violations}"
        )
    }

    #[tool(
        description = "Retrieve all eBPF security events for a specific guest process ID. \
                       Useful for investigating what a particular process was doing."
    )]
    async fn investigate_process(
        &self,
        Parameters(params): Parameters<InvestigateProcessParams>,
    ) -> String {
        use crate::resources::{find_latest_session_log, format_events_for_pid};

        let pid: u64 = match params.pid.parse() {
            Ok(n) => n,
            Err(_) => return format!("Invalid PID '{}': must be a non-negative integer.", params.pid),
        };

        match find_latest_session_log() {
            None => "No session log found. The Garden daemon may not have been started yet.".to_string(),
            Some(path) => match format_events_for_pid(&path, pid) {
                Ok(text) => text,
                Err(e) => format!("Could not open session log: {e}"),
            },
        }
    }
}

#[tool_handler]
impl ServerHandler for GardenMcpServer {
    fn get_info(&self) -> ServerInfo {
        // Advertise 2025-11-25 so Claude Desktop shows MCP prompts in the `/` menu.
        // rmcp 1.3's LATEST constant is 2025-06-18; we deserialize the newer version string
        // since ProtocolVersion accepts unknown versions via its Deserialize impl.
        let protocol_version: rmcp::model::ProtocolVersion =
            serde_json::from_value(serde_json::json!("2025-11-25")).unwrap();
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
        .with_server_info(Implementation::new("garden-ai", env!("CARGO_PKG_VERSION")))
        .with_instructions(
            "Garden AI sandbox server — a hardware-isolated Linux micro-VM for AI workloads.\n\n\
             TOOLS: run_command, read_file, write_file, list_directory — execute and manage \
             files inside the sandbox VM.\n\n\
             RESOURCES (read with read_resource):\n\
             - garden://sandbox/status — VM running state and uptime\n\
             - garden://security/events — last 50 eBPF security events\n\
             - garden://security/violations — policy violations detected by host\n\n\
             PROMPTS (invoke with get_prompt or tell the user to select from the / menu):\n\
             - analyze-security — analyse recent events and flag suspicious activity\n\
             - sandbox-report — full health report: VM state + security summary\n\
             - investigate-process (arg: pid) — all events for a specific guest PID",
        )
        .with_protocol_version(protocol_version)
    }

    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListResourcesResult, rmcp::model::ErrorData> {
        use rmcp::model::{Annotated, ListResourcesResult, RawResource};

        let make = |uri: &str, name: &str, title: &str, desc: &str| -> Annotated<RawResource> {
            Annotated::new(
                RawResource {
                    uri: uri.to_string(),
                    name: name.to_string(),
                    title: Some(title.to_string()),
                    description: Some(desc.to_string()),
                    mime_type: Some("text/plain".to_string()),
                    size: None,
                    icons: None,
                    meta: None,
                },
                None,
            )
        };

        let resources = vec![
            make(
                URI_SANDBOX_STATUS,
                "Sandbox Status",
                "VM running state and uptime",
                "Current status of the Garden micro-VM: whether it is running, \
                 how long it has been up, and which kernel it booted.",
            ),
            make(
                URI_SECURITY_EVENTS,
                "Security Events",
                "Recent eBPF security telemetry",
                "The last 50 security events captured by eBPF probes inside the VM: \
                 file opens, network connections, process executions, credential changes, \
                 and more.",
            ),
            make(
                URI_SECURITY_VIOLATIONS,
                "Security Violations",
                "Policy violations detected by the host",
                "Events that triggered a host-side policy violation: privilege escalation, \
                 data exfiltration, large downloads, kernel module loads, and mount attempts.",
            ),
        ];

        Ok(ListResourcesResult::with_all_items(resources))
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResult, rmcp::model::ErrorData> {
        use rmcp::model::{ErrorData, ReadResourceResult, ResourceContents};

        let text = match request.uri.as_str() {
            URI_SANDBOX_STATUS => read_sandbox_status().await,
            URI_SECURITY_EVENTS => read_recent_events(),
            URI_SECURITY_VIOLATIONS => read_violations(),
            other => {
                return Err(ErrorData::resource_not_found(
                    format!("unknown resource URI: {other}"),
                    None,
                ));
            }
        };

        Ok(ReadResourceResult::new(vec![
            ResourceContents::TextResourceContents {
                uri: request.uri,
                mime_type: Some("text/plain".to_string()),
                text,
                meta: None,
            },
        ]))
    }

    async fn list_prompts(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListPromptsResult, rmcp::model::ErrorData> {
        Ok(build_list_prompts_result())
    }

    async fn get_prompt(
        &self,
        request: rmcp::model::GetPromptRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::GetPromptResult, rmcp::model::ErrorData> {
        dispatch_get_prompt(request).await
    }
}

/// Start the MCP server using stdio transport.
///
/// The gRPC connection to the daemon is established lazily on first tool use,
/// so this returns immediately and Claude Desktop can use prompts/resources
/// even when the Garden daemon is not yet running.
pub async fn start_server(_config: McpServerConfig) -> Result<()> {
    tracing::info!("Starting Garden AI MCP server on stdio (lazy daemon connection)...");

    let server = GardenMcpServer::new();
    let transport = rmcp::transport::stdio();
    let service = server.serve(transport).await?;
    service.waiting().await?;

    Ok(())
}

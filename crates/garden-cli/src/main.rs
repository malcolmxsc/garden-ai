//! Garden AI CLI — The open-source command-line interface.
//!
//! Usage:
//!   garden boot [--kernel <path>] [--rootfs <path>]
//!   garden run <command> [args...]
//!   garden status
//!   garden stop

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "garden",
    about = "🌿 Garden AI — The un-hackable room for your AI",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Boot a new sandbox VM
    Boot {
        /// Path to the Linux kernel image
        #[arg(long, default_value = "guest/kernel/bzImage")]
        kernel: String,

        /// Path to the root filesystem
        #[arg(long, default_value = "guest/rootfs/rootfs.img")]
        rootfs: String,

        /// Memory allocation in MB
        #[arg(long, default_value = "512")]
        memory: u64,

        /// Number of CPU cores
        #[arg(long, default_value = "2")]
        cpus: u32,

        /// Host directories to share (format: host_path:mount_tag)
        #[arg(long)]
        share: Vec<String>,
    },

    /// Execute a command inside the running sandbox
    Run {
        /// The command to execute
        command: String,

        /// Arguments to the command
        args: Vec<String>,
    },

    /// Show the status of running sandboxes
    Status,

    /// Stop a running sandbox
    Stop {
        /// Sandbox ID to stop (defaults to the most recent)
        #[arg(short, long)]
        id: Option<String>,
    },

    /// Start the MCP server for AI client connections
    Serve {
        /// Port for the SSE transport
        #[arg(long, default_value = "3000")]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    match cli.command {
        Commands::Boot {
            kernel,
            rootfs,
            memory,
            cpus,
            share,
        } => {
            tracing::info!(
                kernel = %kernel,
                rootfs = %rootfs,
                memory_mb = memory,
                cpus = cpus,
                shared_dirs = ?share,
                "Booting sandbox VM..."
            );
            // TODO: Send Boot request via IPC
            println!("🌿 Sandbox booted successfully.");
        }
        Commands::Run { command, args } => {
            tracing::info!(command = %command, args = ?args, "Executing command in sandbox...");
            // TODO: Send Execute request via IPC
            println!("🌿 Command executed.");
        }
        Commands::Status => {
            tracing::info!("Querying sandbox status...");
            // TODO: Send Status request via IPC
            println!("🌿 No sandboxes running.");
        }
        Commands::Stop { id } => {
            tracing::info!(id = ?id, "Stopping sandbox...");
            // TODO: Send Stop request via IPC
            println!("🌿 Sandbox stopped.");
        }
        Commands::Serve { port } => {
            tracing::info!(port = port, "Starting MCP server...");
            garden_mcp::server::start_server(garden_mcp::server::McpServerConfig {
                sse_port: Some(port),
                ..Default::default()
            })
            .await?;
        }
    }

    Ok(())
}

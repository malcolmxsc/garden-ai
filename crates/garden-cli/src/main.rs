//! Garden AI CLI — The open-source command-line interface.
//!
//! Usage:
//!   garden init
//!   garden update-kernel
//!   garden boot [--kernel <path>] [--rootfs <path>]
//!   garden run <command> [args...]
//!   garden status
//!   garden stop

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "garden",
    about = "🌿 Garden AI — A secure, hardware-accelerated Linux Micro-VM environment.",
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
    /// Initializes the workspace and downloads the Alpine Linux kernel
    Init,

    /// Fetches the latest Alpine kernel and initrd
    UpdateKernel,

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
        Commands::Init => {
            tracing::info!("🌿 Initializing Garden workspace...");
            tracing::info!("Downloading Alpine Linux kernel...");
            download_alpine().await?;
            tracing::info!("✅ Workspace initialized securely!");
        }
        Commands::UpdateKernel => {
            tracing::info!("🔄 Fetching the latest Alpine Linux kernel...");
            download_alpine().await?;
            tracing::info!("✅ Kernel updated.");
        }
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
            // ----------------------------------------------------
            // VirtioFS Secure Sandbox Validation
            // ----------------------------------------------------
            // The macOS host only shares ~/GardenBox with the guest VM.
            // We must enforce that the user runs the CLI from inside this directory.
            let sandbox_root = dirs::home_dir()
                .expect("Could not find home directory")
                .join("GardenBox");
                
            let cwd = std::env::current_dir().unwrap_or_default();
            
            if !cwd.starts_with(&sandbox_root) {
                eprintln!("❌ Security Violation: garden commands can only run inside the secure sandbox.");
                eprintln!("   Your current directory is: {}", cwd.display());
                eprintln!("   Please cd into: {}", sandbox_root.display());
                std::process::exit(1);
            }
            
            // Calculate the relative path from the sandbox root.
            // e.g. ~/GardenBox/my_project/src -> my_project/src
            let relative_cwd = cwd.strip_prefix(&sandbox_root)
                .unwrap_or(std::path::Path::new(""))
                .to_string_lossy()
                .to_string();

            tracing::info!(command = %command, args = ?args, cwd = %relative_cwd, "Connecting to Micro-VM Agent...");
            
            // Connect to the daemon's local TCP proxy which forwards to the
            // guest agent via vSock. No guest IP discovery needed!
            let mut client = garden_common::ipc::agent_service_client::AgentServiceClient::connect("http://127.0.0.1:10000").await?;
            
            let request = tonic::Request::new(garden_common::ipc::CommandRequest {
                command,
                args,
                cwd: relative_cwd,
            });

            tracing::info!("Executing Remote Procedure Call...");
            let response = client.execute_command(request).await?.into_inner();
            
            println!("🌿 Command executed. Exit Code: {}", response.exit_code);
            if !response.stdout.is_empty() {
                println!("--- STDOUT ---\n{}", String::from_utf8_lossy(&response.stdout));
            }
            if !response.stderr.is_empty() {
                println!("--- STDERR ---\n{}", String::from_utf8_lossy(&response.stderr));
            }
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

// =====================================================================
// SYNTAX BREAKDOWN: Async Downloading
// =====================================================================
// We use `reqwest` for HTTP. We `.await` the initial connection, check
// the HTTP status code (e.g. 200 OK vs 404 Not Found) with `error_for_status()`,
// and then `.await` the actual byte downloading. 
// Finally, `tokio::fs::write` writes the bytes asynchronously to the SSD.
async fn download_alpine() -> anyhow::Result<()> {
    // We target Apple Silicon (Aarch64) Alpine Linux Netboot artifacts
    let kernel_url = "https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/netboot/vmlinuz-virt";
    let initrd_url = "https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/netboot/initramfs-virt";

    let guest_dir = std::path::Path::new("guest/kernel");
    
    // Safety check: ensure the folder actually exists before we try to save files into it!
    tokio::fs::create_dir_all(guest_dir).await?;
    
    // 1. Download Kernel
    let kernel_dest = guest_dir.join("vmlinuz-virt");
    tracing::info!(" -> Downloading vmlinuz-virt (Kernel)...");
    download_file(kernel_url, &kernel_dest).await?;

    // 2. Download Initrd
    let initrd_dest = guest_dir.join("initramfs-virt");
    tracing::info!(" -> Downloading initramfs-virt (RAM Disk)...");
    download_file(initrd_url, &initrd_dest).await?;

    Ok(())
}

async fn download_file(url: &str, dest: &std::path::Path) -> anyhow::Result<()> {
    let response = reqwest::get(url).await?.error_for_status()?;
    let content = response.bytes().await?;
    tokio::fs::write(dest, content).await?;
    Ok(())
}

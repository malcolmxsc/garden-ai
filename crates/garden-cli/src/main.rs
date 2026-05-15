//! Garden AI CLI — The open-source command-line interface.
//!
//! Usage:
//!   garden init
//!   garden update-kernel
//!   garden start [--policy <file>] [--network=allow|deny]    one-step daemon+VM
//!   garden boot  [--policy <file>] [--network=allow|deny]    requires daemon up
//!   garden run <command> [args...]
//!   garden status
//!   garden stop    stop VM only (daemon stays running)
//!   garden down    stop VM and kill the daemon (full teardown)

use clap::{Parser, Subcommand, ValueEnum};

/// Ad-hoc-signing entitlements for the daemon binary. Embedded at compile
/// time so `garden start` can codesign without needing the project tree on
/// disk. Source of truth: crates/garden-daemon/entitlements.plist.
const DAEMON_ENTITLEMENTS_PLIST: &str =
    include_str!("../../garden-daemon/entitlements.plist");

/// Network egress posture at boot time.
///
/// `Allow` (default) leaves all outbound connections allowed unless an
/// explicit `--policy` rule denies them. `Deny` injects catch-all
/// deny-everything rules for IPv4 (0.0.0.0/0) and IPv6 (::/0) into the
/// policy that gets shipped to the guest, so the guest agent's BPF-LSM
/// hook rejects every `socket_connect()` from a non-PID-1 process unless
/// the user has also passed `--policy <file>` with explicit allow rules
/// that punch holes through the catch-all (per-CIDR allow lookups win
/// over the catch-all deny via LPM longest-prefix-match).
#[derive(Clone, Copy, Debug, ValueEnum)]
enum NetworkMode {
    /// Outbound network allowed by default (current observe-only behaviour).
    Allow,
    /// All outbound network denied; pair with --policy for an allowlist.
    Deny,
}

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
        /// Path to the Linux kernel image (leave empty to use daemon default)
        #[arg(long, default_value = "")]
        kernel: String,

        /// Path to the initramfs image (leave empty to use daemon default)
        #[arg(long, default_value = "")]
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

        /// Path to a JSON security policy file
        #[arg(long)]
        policy: Option<String>,

        /// Network egress posture: `allow` (default, current behaviour) or
        /// `deny` (block all outbound; combine with --policy to whitelist).
        #[arg(long, value_enum, default_value_t = NetworkMode::Allow)]
        network: NetworkMode,
    },

    /// One-step: launch the daemon (if not already running), then boot a VM.
    ///
    /// Replaces the manual flow of "run ./target/debug/garden-daemon in one
    /// terminal, then `garden boot` in another." Accepts the same flags as
    /// `boot` and passes them through. If the daemon is already up, just
    /// boots the VM with whatever you pass.
    Start {
        /// Path to the Linux kernel image (leave empty to use daemon default)
        #[arg(long, default_value = "")]
        kernel: String,

        /// Path to the initramfs image (leave empty to use daemon default)
        #[arg(long, default_value = "")]
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

        /// Path to a JSON security policy file
        #[arg(long)]
        policy: Option<String>,

        /// Network egress posture: `allow` (default) or `deny`.
        #[arg(long, value_enum, default_value_t = NetworkMode::Allow)]
        network: NetworkMode,

        /// Start the daemon but don't boot a VM. Useful for running an MCP
        /// session and explicitly booting later.
        #[arg(long)]
        no_boot: bool,
    },

    /// Execute a command inside the running sandbox
    Run {
        /// The command to execute
        command: String,

        /// Arguments to the command. Hyphen-prefixed args (e.g. `-la`) are
        /// passed through verbatim instead of being parsed as flags.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Debug-only: execute a command through the agent privileged-exec endpoint.
    #[command(name = "debug-run-privileged", hide = true)]
    DebugRunPrivileged {
        /// The command to execute
        command: String,

        /// Arguments to the command. Hyphen-prefixed args pass through.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
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

    /// Full teardown: stop the VM, then kill the garden-daemon process.
    ///
    /// Mirrors the `docker compose down` pattern. Use this when you want to
    /// reclaim the host port (9000/9001/10000/10001) bindings and start
    /// from a clean slate. `garden stop` only stops the VM and leaves the
    /// daemon running so subsequent `garden boot` calls are instant.
    Down,

    /// Start the MCP server for AI client connections (stdio transport)
    Serve,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing — MCP stdio transport owns stdout, so always log to stderr
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
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
            policy,
            network,
        } => {
            do_boot(kernel, rootfs, memory, cpus, share, policy, network).await?;
        }
        Commands::Start {
            kernel,
            rootfs,
            memory,
            cpus,
            share,
            policy,
            network,
            no_boot,
        } => {
            ensure_daemon_running().await?;
            if !no_boot {
                do_boot(kernel, rootfs, memory, cpus, share, policy, network).await?;
            } else {
                println!("🌱 Daemon ready on :9000 (no VM booted — pass `garden boot ...` or omit --no-boot)");
            }
        }
        Commands::Run { command, args } => {
            run_agent_command(command, args, false).await?;
        }
        Commands::DebugRunPrivileged { command, args } => {
            run_agent_command(command, args, true).await?;
        }
        Commands::Status => {
            tracing::info!("Querying sandbox status...");

            // First try the DaemonService for VM-level status
            match garden_common::daemon::daemon_service_client::DaemonServiceClient::connect("http://127.0.0.1:9000").await {
                Ok(mut daemon_client) => {
                    let vm_status = daemon_client
                        .get_vm_status(tonic::Request::new(garden_common::daemon::VmStatusRequest {}))
                        .await?
                        .into_inner();

                    println!("🌿 Sandbox Status");
                    println!("  VM running:     {}", if vm_status.running { "yes" } else { "no" });

                    if vm_status.running {
                        let uptime = vm_status.uptime_seconds;
                        let hours = uptime / 3600;
                        let minutes = (uptime % 3600) / 60;
                        let seconds = uptime % 60;
                        println!("  Uptime:         {}h {}m {}s", hours, minutes, seconds);
                    }

                    if !vm_status.kernel_path.is_empty() {
                        println!("  Kernel:         {}", vm_status.kernel_path);
                    }

                    // Also try the agent for guest-side info
                    if vm_status.running {
                        match garden_common::ipc::agent_service_client::AgentServiceClient::connect("http://127.0.0.1:10000").await {
                            Ok(mut agent_client) => {
                                let agent_status = agent_client
                                    .get_status(tonic::Request::new(garden_common::ipc::StatusRequest {}))
                                    .await?
                                    .into_inner();
                                println!("  Agent version:  {}", agent_status.version);
                            }
                            Err(_) => {
                                println!("  Agent:          not reachable (still booting?)");
                            }
                        }
                    }

                    println!("  Daemon gRPC:    127.0.0.1:9000");
                    println!("  Agent proxy:    127.0.0.1:10000");
                    println!("  Telemetry:      127.0.0.1:10001");
                }
                Err(_) => {
                    println!("🌿 No sandbox running (daemon not reachable on :9000).");
                }
            }
        }
        Commands::Stop { id } => {
            tracing::info!(id = ?id, "Stopping sandbox...");

            let mut client = garden_common::daemon::daemon_service_client::DaemonServiceClient::connect("http://127.0.0.1:9000")
                .await
                .map_err(|e| anyhow::anyhow!("Failed to connect to daemon on :9000: {}", e))?;

            let response = client
                .stop_vm(tonic::Request::new(garden_common::daemon::StopVmRequest {}))
                .await?
                .into_inner();

            if response.success {
                println!("🌿 {}", response.message);
            } else {
                eprintln!("❌ {}", response.message);
                std::process::exit(1);
            }
        }
        Commands::Down => {
            // Step 1: ask the daemon to stop the VM cleanly if it's reachable.
            // We don't bail on failure here — the daemon might already be
            // half-dead and we still want to send SIGTERM in step 2.
            match garden_common::daemon::daemon_service_client::DaemonServiceClient::connect("http://127.0.0.1:9000").await {
                Ok(mut client) => {
                    match client
                        .stop_vm(tonic::Request::new(garden_common::daemon::StopVmRequest {}))
                        .await
                    {
                        Ok(resp) => {
                            let r = resp.into_inner();
                            if r.success {
                                println!("🌿 VM: {}", r.message);
                            } else {
                                eprintln!("⚠️  VM stop reported failure: {}", r.message);
                            }
                        }
                        Err(e) => {
                            eprintln!("⚠️  VM stop RPC failed: {} (continuing with daemon kill)", e);
                        }
                    }
                }
                Err(_) => {
                    println!("🌿 Daemon not reachable on :9000 — skipping VM stop.");
                }
            }

            // Step 2: SIGTERM the garden-daemon process(es).
            shutdown_garden_daemon()?;
        }
        Commands::Serve => {
            garden_mcp::server::start_server(garden_mcp::server::McpServerConfig::default())
                .await?;
        }
    }

    Ok(())
}

/// Shared boot path used by both `garden boot` and `garden start`. Reads
/// the policy file if given, applies the --network deny catch-all if
/// requested, calls the daemon's BootVm gRPC. Exits the process on
/// fatal errors.
async fn do_boot(
    kernel: String,
    rootfs: String,
    memory: u64,
    cpus: u32,
    share: Vec<String>,
    policy: Option<String>,
    network: NetworkMode,
) -> anyhow::Result<()> {
    tracing::info!(
        kernel = %kernel,
        rootfs = %rootfs,
        memory_mb = memory,
        cpus = cpus,
        shared_dirs = ?share,
        network = ?network,
        "Booting sandbox VM..."
    );

    let mut policy_json = match policy {
        Some(path) => {
            let json = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                eprintln!("Cannot read policy file {}: {}", path, e);
                std::process::exit(1);
            });
            if serde_json::from_str::<serde_json::Value>(&json).is_err() {
                eprintln!("Invalid JSON in policy file: {}", path);
                std::process::exit(1);
            }
            json
        }
        None => String::new(),
    };

    // --network=deny: append catch-all deny rules for IPv4 + IPv6 to
    // whatever policy was loaded (or synthesize a deny-only policy if
    // none was given). User-supplied per-CIDR allow rules win at lookup
    // time via the LPM trie's longest-prefix-match.
    if matches!(network, NetworkMode::Deny) {
        eprintln!("🚫 Network egress: DENY ALL (combine with --policy to allowlist exceptions)");
        let deny_rules = serde_json::json!([
            {"type": "network", "dest": "0.0.0.0/0", "action": "deny"},
            {"type": "network", "dest": "::/0",      "action": "deny"}
        ]);
        if policy_json.is_empty() {
            let synthesised = serde_json::json!({
                "name": "network-deny",
                "rules": deny_rules
            });
            policy_json = serde_json::to_string(&synthesised)
                .expect("synthesised policy serialises");
        } else {
            let mut existing: serde_json::Value = serde_json::from_str(&policy_json)
                .expect("policy file already validated as JSON");
            if let Some(rules) = existing["rules"].as_array_mut() {
                for rule in deny_rules.as_array().expect("deny_rules is an array") {
                    rules.push(rule.clone());
                }
            } else {
                eprintln!("⚠️  --policy file has no `rules` array — --network=deny rules not appended");
            }
            policy_json = serde_json::to_string(&existing)
                .expect("policy with appended rules serialises");
        }
    }

    let mut client = garden_common::daemon::daemon_service_client::DaemonServiceClient::connect("http://127.0.0.1:9000")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to daemon on :9000: {}", e))?;

    let request = tonic::Request::new(garden_common::daemon::BootVmRequest {
        kernel_path: kernel,
        initrd_path: rootfs,
        cpus,
        memory_mb: memory,
        policy_json,
    });

    let response = client.boot_vm(request).await?.into_inner();
    if response.success {
        println!("🌿 {}", response.message);
    } else {
        eprintln!("❌ {}", response.message);
        std::process::exit(1);
    }
    Ok(())
}

/// Make sure a garden-daemon is running on 127.0.0.1:9000.
///
/// Sequence:
///   1. If we can already connect to :9000, return immediately.
///   2. Find the daemon binary in the same directory as this CLI binary
///      (the cargo/install convention).
///   3. Codesign it ad-hoc with the embedded entitlements — Apple's
///      Virtualization.framework rejects unsigned binaries.
///   4. Spawn it as a detached background process with stdout/stderr
///      redirected to /tmp/garden-daemon.log (so the parent shell stays
///      clean; the user can `tail -f /tmp/garden-daemon.log` to watch).
///   5. Poll :9000 for up to ~5 seconds. Bail if it never binds.
async fn ensure_daemon_running() -> anyhow::Result<()> {
    use std::io::Write;

    // Already up?
    if tokio::net::TcpStream::connect("127.0.0.1:9000").await.is_ok() {
        return Ok(());
    }

    // Find the daemon binary alongside the CLI binary.
    let cli_exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("can't locate cli executable: {}", e))?;
    let daemon_bin = cli_exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cli executable has no parent directory"))?
        .join("garden-daemon");
    if !daemon_bin.exists() {
        anyhow::bail!(
            "daemon binary not found at {}. Build it first: cargo build -p garden-daemon",
            daemon_bin.display()
        );
    }

    // Write entitlements to a temp file and ad-hoc sign. Overwriting an
    // existing /tmp/garden-entitlements.plist is intentional — we always
    // want the version embedded in this CLI build to be authoritative.
    let entitlements_path = std::env::temp_dir().join("garden-entitlements.plist");
    {
        let mut f = std::fs::File::create(&entitlements_path)
            .map_err(|e| anyhow::anyhow!("can't write entitlements: {}", e))?;
        f.write_all(DAEMON_ENTITLEMENTS_PLIST.as_bytes())?;
    }
    let sign = std::process::Command::new("codesign")
        .arg("-s")
        .arg("-")
        .arg("--entitlements")
        .arg(&entitlements_path)
        .arg("--force")
        .arg(&daemon_bin)
        .output()?;
    if !sign.status.success() {
        anyhow::bail!(
            "codesign failed:\n{}",
            String::from_utf8_lossy(&sign.stderr)
        );
    }

    // Detached background launch. Log file at a known path so users (and
    // future debugging sessions) can find it.
    let log_path = "/tmp/garden-daemon.log";
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| anyhow::anyhow!("can't open daemon log {}: {}", log_path, e))?;
    let log_err = log.try_clone()?;

    std::process::Command::new(&daemon_bin)
        .stdin(std::process::Stdio::null())
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn daemon: {}", e))?;

    // Wait for the gRPC port to bind. The daemon needs to init Apple's
    // Hypervisor framework, sign-check itself, start a tokio runtime, and
    // bind two TCP sockets — usually under 1 second, but allow 5.
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if tokio::net::TcpStream::connect("127.0.0.1:9000").await.is_ok() {
            eprintln!("🌱 Daemon started (log: {})", log_path);
            return Ok(());
        }
    }
    anyhow::bail!(
        "daemon failed to bind :9000 within 5s. Check {} for errors.",
        log_path
    )
}

/// SIGTERM every process whose command line contains "garden-daemon".
///
/// We deliberately don't trust `lsof -i :9000` alone — another process
/// could be squatting on that port. Instead we list every garden-daemon
/// pid via `pgrep -f garden-daemon`, verify the command via `ps -p <pid>
/// -o command=`, and only then send SIGTERM. SIGKILL is a last resort
/// after a 2-second grace period.
fn shutdown_garden_daemon() -> anyhow::Result<()> {
    let pgrep = std::process::Command::new("pgrep")
        .arg("-f")
        .arg("garden-daemon")
        .output()?;

    if !pgrep.status.success() {
        // pgrep exits 1 when nothing matches — that's fine.
        println!("🌿 No garden-daemon process found.");
        return Ok(());
    }

    let pids: Vec<i32> = String::from_utf8_lossy(&pgrep.stdout)
        .lines()
        .filter_map(|l| l.trim().parse::<i32>().ok())
        // Skip our own pid in case the user ever runs this from inside the
        // daemon process (e.g. via `garden serve` self-call).
        .filter(|pid| *pid != std::process::id() as i32)
        .collect();

    if pids.is_empty() {
        println!("🌿 No garden-daemon process found.");
        return Ok(());
    }

    for pid in &pids {
        // Defence in depth: confirm this pid's command really is the
        // daemon binary before we signal it.
        let ps = std::process::Command::new("ps")
            .arg("-p")
            .arg(pid.to_string())
            .arg("-o")
            .arg("command=")
            .output()?;
        let cmdline = String::from_utf8_lossy(&ps.stdout);
        if !cmdline.contains("garden-daemon") {
            eprintln!("⚠️  Skipping pid {}: command line does not contain 'garden-daemon' ({})", pid, cmdline.trim());
            continue;
        }

        let kill = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status()?;
        if kill.success() {
            println!("🌿 Sent SIGTERM to garden-daemon (pid {}).", pid);
        } else {
            eprintln!("⚠️  Failed to SIGTERM pid {}", pid);
        }
    }

    // Wait for the daemon to release :9000. If it hasn't dropped the
    // socket within 2 seconds, escalate to SIGKILL.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let still_bound = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:9000".parse().unwrap(),
        std::time::Duration::from_millis(200),
    )
    .is_ok();
    if still_bound {
        eprintln!("⚠️  Daemon still bound to :9000 after 2s — escalating to SIGKILL.");
        for pid in &pids {
            let _ = std::process::Command::new("kill")
                .arg("-KILL")
                .arg(pid.to_string())
                .status();
        }
    }

    Ok(())
}

async fn run_agent_command(command: String, args: Vec<String>, privileged: bool) -> anyhow::Result<()> {
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
    let relative_cwd = cwd
        .strip_prefix(&sandbox_root)
        .unwrap_or(std::path::Path::new(""))
        .to_string_lossy()
        .to_string();

    tracing::info!(
        command = %command,
        args = ?args,
        cwd = %relative_cwd,
        privileged = privileged,
        "Connecting to Micro-VM Agent..."
    );

    // Connect to the daemon's local TCP proxy which forwards to the
    // guest agent via vSock. No guest IP discovery needed.
    let mut client =
        garden_common::ipc::agent_service_client::AgentServiceClient::connect("http://127.0.0.1:10000").await?;

    let request = tonic::Request::new(garden_common::ipc::CommandRequest {
        command,
        args,
        cwd: relative_cwd,
    });

    tracing::info!("Executing Remote Procedure Call...");
    let response = if privileged {
        client.execute_privileged_command(request).await?.into_inner()
    } else {
        client.execute_command(request).await?.into_inner()
    };

    println!("🌿 Command executed. Exit Code: {}", response.exit_code);
    if !response.stdout.is_empty() {
        println!("--- STDOUT ---\n{}", String::from_utf8_lossy(&response.stdout));
    }
    if !response.stderr.is_empty() {
        println!("--- STDERR ---\n{}", String::from_utf8_lossy(&response.stderr));
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

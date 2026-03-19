//! Garden Agent — The micro-VM Guest Agent
//! 
//! This binary is compiled statically and injected directly into the Apple Hypervisor
//! via a custom `cpio` ramdisk. The Linux Kernel executes this file as Process 1 (`/init`).
//!
//! As PID 1, this process MUST NEVER EXIT — if it does, the kernel panics immediately.
//! All errors are caught and logged, and the process enters an emergency loop if
//! the main logic fails.

use garden_common::ipc::agent_service_server::{AgentService, AgentServiceServer};
use garden_common::ipc::{CommandRequest, CommandResponse, StatusRequest, StatusResponse};
use tonic::{transport::Server, Request, Response, Status};

use tokio_stream::StreamExt;

// =====================================================================
// PID 1 Signal Safety
// =====================================================================
// PID 1 is special in Linux:
//   - If PID 1 exits for ANY reason, the kernel panics.
//   - If PID 1 receives an unhandled fatal signal, the kernel panics.
//   - When any process's parent exits, orphaned children are reparented to PID 1.
//   - PID 1 must reap these orphan zombies via waitpid().
//
// We handle this by:
//   1. Setting SIGCHLD to SIG_IGN — tells the kernel to auto-reap all children.
//      This means we never accumulate zombie processes.
//   2. Ignoring SIGHUP, SIGPIPE, SIGINT — prevents accidental PID 1 death.
//   3. Wrapping main() in catch_unwind + never-exit loop.

fn install_signal_handlers() {
    unsafe {
        // SIGCHLD: keep default behavior (SIG_DFL = ignore on Linux).
        // We do NOT use SIG_IGN because that tells the kernel to auto-reap
        // children, which races with waitpid() in std::process::Command and
        // tokio::process::Command, causing ECHILD errors.
        // Instead, we run a periodic reaper task to clean up orphan zombies.

        // Ignore signals that would kill PID 1
        libc::signal(libc::SIGHUP, libc::SIG_IGN);    // No controlling terminal
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);    // Broken vSock connections
        libc::signal(libc::SIGINT, libc::SIG_IGN);     // Console interrupt
        libc::signal(libc::SIGTERM, libc::SIG_IGN);    // VM will be killed externally
    }
}

fn main() {
    // Install signal handlers FIRST — before anything can panic or spawn children
    install_signal_handlers();

    // Catch any panic in the rest of the program
    let result = std::panic::catch_unwind(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");

        if let Err(e) = rt.block_on(async_main()) {
            eprintln!("[init] async_main returned error: {:?}", e);
        } else {
            eprintln!("[init] async_main returned cleanly — this should not happen");
        }
    });

    if let Err(panic_info) = result {
        eprintln!("[init] PANIC caught: {:?}", panic_info);
    }

    // PID 1 must NEVER exit. If we get here, loop forever.
    // The host can still kill the VM externally via Virtualizer.stop().
    eprintln!("[init] Entering emergency hold loop — VM must be killed externally");
    loop {
        unsafe { libc::pause(); }
    }
}

#[derive(Default)]
pub struct GardenAgentImpl {}

#[tonic::async_trait]
impl AgentService for GardenAgentImpl {
    async fn execute_command(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        let req = request.into_inner();
        
        // Ensure cwd is relative to the sandbox and prevents traversal
        let relative_cwd = req.cwd.trim_start_matches('/');
        if relative_cwd.contains("..") {
            tracing::error!("Path traversal attempt blocked: cwd={}", req.cwd);
            return Err(Status::invalid_argument("Path traversal ('..') is not allowed inside the sandbox"));
        }
        
        let target_cwd = std::path::Path::new("/workspace").join(relative_cwd);
        let cwd_str = target_cwd.to_string_lossy();
        
        tracing::info!("Executing command: {} {:?} (cwd={})", req.command, req.args, cwd_str);

        // Use tokio::process::Command for non-blocking child process management.
        // This integrates with tokio's reactor and handles waitpid internally.
        let output = tokio::process::Command::new(&req.command)
            .args(&req.args)
            .current_dir(&target_cwd)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                tracing::error!("Failed to execute '{}': {:?}", req.command, e);
                Status::internal(format!("Failed to execute process: {}", e))
            })?;

        let response = CommandResponse {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        };

        tracing::info!("Command '{}' exited with code {}", req.command, response.exit_code);
        Ok(Response::new(response))
    }

    async fn get_status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        tracing::debug!("Host requested Agent Status");
        
        let response = StatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: 42, 
        };

        Ok(Response::new(response))
    }
}

async fn async_main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    // 0. Mount essential pseudo-filesystems for Linux operation
    // =========================================================
    let _ = std::fs::create_dir_all("/proc");
    let _ = std::fs::create_dir_all("/sys");
    let _ = std::fs::create_dir_all("/dev");
    let _ = std::process::Command::new("/bin/busybox").args(["mount", "-t", "proc", "proc", "/proc"]).status();
    let _ = std::process::Command::new("/bin/busybox").args(["mount", "-t", "sysfs", "sys", "/sys"]).status();
    let _ = std::process::Command::new("/bin/busybox").args(["mount", "-t", "devtmpfs", "dev", "/dev"]).status();
    tracing::info!("Mounted /proc, /sys, /dev");

    // 0.2. Mount the VirtioFS Workspace
    // =========================================================
    // The macOS host shares ~/GardenBox via VirtioFS with the tag "garden_workspace".
    // FUSE and VirtioFS are compiled directly into the custom Linux kernel,
    // so no modprobe or external modules are required!
    let _ = std::fs::create_dir_all("/workspace");
    let workspace_mount = std::process::Command::new("/bin/busybox")
        .args(["mount", "-t", "virtiofs", "garden_workspace", "/workspace"])
        .output();
    match workspace_mount {
        Ok(out) if out.status.success() => {
            tracing::info!("✅ Mounted VirtioFS workspace at /workspace");
        }
        Ok(out) => {
            tracing::error!("❌ Failed to mount VirtioFS workspace: {}", String::from_utf8_lossy(&out.stderr));
        }
        Err(e) => {
            tracing::error!("❌ Failed to execute mount for VirtioFS: {}", e);
        }
    }

    // 0.5. Create BusyBox symlinks so commands like "echo", "ls" work
    // =========================================================
    // BusyBox is a single binary that acts as many commands depending
    // on the name it's invoked as. We create symlinks so standard
    // command names resolve to busybox.
    setup_busybox_symlinks();

    // 1. Initialize Network Interfaces using Netlink
    // =========================================================
    tracing::info!("Configuring network interfaces via Netlink...");
    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(connection);

    // Bring up loopback interface
    let mut links = handle.link().get().match_name("lo".to_string()).execute();
    if let Some(Ok(link)) = links.next().await {
        let mut msg = netlink_packet_route::link::LinkMessage::default();
        msg.header.index = link.header.index;
        msg.header.flags = netlink_packet_route::link::LinkFlags::Up;
        msg.header.change_mask = netlink_packet_route::link::LinkFlags::Up;
        handle.link().set(msg).execute().await.unwrap();
        tracing::info!("Loopback (lo) interface is UP");
    }

    // Bring up NAT Ethernet interface for internet egress
    let mut eth0_idx = 0;
    for _ in 0..20 {
        let mut links = handle.link().get().match_name("eth0".to_string()).execute();
        if let Some(Ok(link)) = links.next().await {
            eth0_idx = link.header.index;
            let mut msg = netlink_packet_route::link::LinkMessage::default();
            msg.header.index = eth0_idx;
            msg.header.flags = netlink_packet_route::link::LinkFlags::Up;
            msg.header.change_mask = netlink_packet_route::link::LinkFlags::Up;
            handle.link().set(msg).execute().await.unwrap();
            tracing::info!("Ethernet (eth0) interface is UP");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    if eth0_idx == 0 {
        tracing::warn!("Failed to find eth0 network device. Virtio PCI probe timed out.");
    }

    // 2. Acquire IP via DHCP for internet egress
    // =========================================================
    if eth0_idx > 0 {
        let dhcp = std::process::Command::new("/bin/busybox")
            .args(["udhcpc", "-i", "eth0", "-n", "-q", "-f", "-s", "/usr/share/udhcpc/default.script"])
            .output();
        match &dhcp {
            Ok(out) => {
                tracing::info!("DHCP result: exit={}, stderr={}", 
                    out.status, 
                    String::from_utf8_lossy(&out.stderr));
            }
            Err(e) => tracing::error!("DHCP failed to run: {}", e),
        }
    }

    // 3. Start zombie reaper for orphaned processes
    // =========================================================
    // As PID 1, orphaned child processes (grandchildren) get reparented to us.
    // We must periodically reap them to prevent zombie accumulation.
    // Our OWN children are reaped by std::process::Command / tokio::process::Command.
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            // Reap all available zombies (non-blocking)
            loop {
                let pid = unsafe {
                    libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG)
                };
                if pid <= 0 { break; } // 0 = no zombies, -1 = error/ECHILD
                tracing::debug!("Reaped orphan zombie pid={}", pid);
            }
        }
    });

    // 3.5. Mount debugfs and bpffs for eBPF tracepoint attachment
    // =========================================================
    let _ = std::fs::create_dir_all("/sys/kernel/debug");
    let _ = std::process::Command::new("/bin/busybox")
        .args(["mount", "-t", "debugfs", "debugfs", "/sys/kernel/debug"])
        .status();
    let _ = std::fs::create_dir_all("/sys/fs/bpf");
    let _ = std::process::Command::new("/bin/busybox")
        .args(["mount", "-t", "bpf", "bpf", "/sys/fs/bpf"])
        .status();
    tracing::info!("Mounted debugfs and bpffs for eBPF");

    // 3.6. Start eBPF security tracer
    // =========================================================
    let default_policy = garden_ebpf::policy::SecurityPolicy::default_observe();

    match garden_ebpf::tracer::start_tracer(&default_policy).await {
        Ok((handle, mut rx)) => {
            tracing::info!("eBPF tracer started successfully");
            // Leak the handle so programs stay attached for VM lifetime
            std::mem::forget(handle);

            // 3.7. Spawn telemetry vSock sender on port 6001
            // =============================================================
            // Streams SecurityEvents as NDJSON to the host daemon.
            // Supports reconnection — if the host disconnects, we go back
            // to the accept loop.
            tokio::spawn(async move {
                let listener_fd = match create_vsock_listener(6001) {
                    Ok(fd) => fd,
                    Err(e) => {
                        tracing::error!("Failed to create telemetry vSock listener on port 6001: {}", e);
                        return;
                    }
                };
                tracing::info!("Telemetry vSock listener ready on port 6001");

                loop {
                    // Accept a telemetry consumer (the host daemon)
                    let conn_fd = unsafe {
                        libc::accept(listener_fd, std::ptr::null_mut(), std::ptr::null_mut())
                    };
                    if conn_fd < 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        continue;
                    }
                    tracing::info!("Telemetry consumer connected, fd={}", conn_fd);

                    // Set non-blocking for async writes
                    unsafe {
                        let flags = libc::fcntl(conn_fd, libc::F_GETFL);
                        libc::fcntl(conn_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                    }

                    // Stream events to this consumer until it disconnects
                    loop {
                        match rx.recv().await {
                            Some(event) => {
                                let mut json = match serde_json::to_string(&event) {
                                    Ok(j) => j,
                                    Err(_) => continue,
                                };
                                json.push('\n');

                                let written = unsafe {
                                    libc::write(
                                        conn_fd,
                                        json.as_ptr() as *const libc::c_void,
                                        json.len(),
                                    )
                                };
                                if written < 0 {
                                    tracing::warn!("Telemetry consumer disconnected");
                                    unsafe { libc::close(conn_fd); }
                                    break;
                                }
                            }
                            None => {
                                tracing::warn!("Telemetry event channel closed");
                                unsafe { libc::close(conn_fd); }
                                return;
                            }
                        }
                    }
                }
            });
        }
        Err(e) => {
            tracing::error!("Failed to start eBPF tracer (non-fatal): {}", e);
            tracing::warn!("Continuing without security telemetry");
        }
    }

    // 4. Start gRPC AgentService
    // =========================================================
    let agent = GardenAgentImpl::default();

    if std::path::Path::new("/dev/vsock").exists() {
        tracing::info!("🔌 /dev/vsock detected! Starting vSock listener on port 6000...");
        
        let vsock_listener_fd = create_vsock_listener(6000)?;
        tracing::info!("AgentService listening on vSock port 6000");
        
        let incoming = VsockIncoming::new(vsock_listener_fd)?;
        
        Server::builder()
            .add_service(AgentServiceServer::new(agent))
            .serve_with_incoming(incoming)
            .await?;
    } else {
        tracing::warn!("/dev/vsock not found — falling back to TCP listener");
        let addr = "0.0.0.0:10000".parse().unwrap();
        tracing::info!("AgentService listening on TCP {}", addr);

        Server::builder()
            .add_service(AgentServiceServer::new(agent))
            .serve(addr)
            .await?;
    }

    Ok(())
}

// =====================================================================
// BusyBox Symlink Setup
// =====================================================================
// Creates /usr/bin symlinks for common BusyBox applets so that
// commands like "echo", "ls", "cat" can be found by name.
fn setup_busybox_symlinks() {
    let applets = [
        "cat", "cp", "echo", "env", "grep", "head", "hostname",
        "id", "kill", "ln", "ls", "mkdir", "mv", "ps", "pwd",
        "rm", "rmdir", "sed", "sh", "sleep", "sort", "tail",
        "touch", "uname", "wc", "which", "whoami",
    ];

    let _ = std::fs::create_dir_all("/usr/bin");
    
    for applet in &applets {
        let target = format!("/usr/bin/{}", applet);
        // Ignore errors — symlink may already exist
        let _ = std::os::unix::fs::symlink("/bin/busybox", &target);
    }

    // Also ensure /bin has the common ones
    let bin_applets = ["sh", "echo", "ls", "cat", "ps", "kill", "hostname"];
    for applet in &bin_applets {
        let target = format!("/bin/{}", applet);
        let _ = std::os::unix::fs::symlink("/bin/busybox", &target);
    }

    tracing::info!("Created BusyBox symlinks for {} applets", applets.len());
}

// =====================================================================
// vSock Listener (raw libc)
// =====================================================================
fn create_vsock_listener(port: u32) -> anyhow::Result<i32> {
    use std::mem;
    
    const AF_VSOCK: i32 = 40;
    const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
    
    #[repr(C)]
    struct SockaddrVm {
        family: u16,
        reserved1: u16,
        port: u32,
        cid: u32,
        flags: u8,
        zero: [u8; 3],
    }
    
    unsafe {
        let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            anyhow::bail!("socket(AF_VSOCK) failed: {}", std::io::Error::last_os_error());
        }
        
        let addr = SockaddrVm {
            family: AF_VSOCK as u16,
            reserved1: 0,
            port,
            cid: VMADDR_CID_ANY,
            flags: 0,
            zero: [0; 3],
        };
        
        let ret = libc::bind(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            mem::size_of::<SockaddrVm>() as u32,
        );
        if ret < 0 {
            libc::close(fd);
            anyhow::bail!("bind(AF_VSOCK, port={}) failed: {}", port, std::io::Error::last_os_error());
        }
        
        let ret = libc::listen(fd, 5);
        if ret < 0 {
            libc::close(fd);
            anyhow::bail!("listen(AF_VSOCK) failed: {}", std::io::Error::last_os_error());
        }
        
        Ok(fd)
    }
}

// =====================================================================
// VsockStream: AsyncRead + AsyncWrite wrapper for AF_VSOCK fds
// =====================================================================
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

struct VsockStream {
    inner: tokio::io::unix::AsyncFd<RawFdWrapper>,
}

struct RawFdWrapper(RawFd);

impl AsRawFd for RawFdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl VsockStream {
    fn new(fd: RawFd) -> std::io::Result<Self> {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let inner = tokio::io::unix::AsyncFd::new(RawFdWrapper(fd))?;
        Ok(Self { inner })
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        unsafe { libc::close(self.inner.as_raw_fd()); }
    }
}

impl tonic::transport::server::Connected for VsockStream {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl tokio::io::AsyncRead for VsockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            let mut guard = match self.inner.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            
            let fd = self.inner.as_raw_fd();
            let unfilled = buf.initialize_unfilled();
            let n = unsafe {
                libc::read(fd, unfilled.as_mut_ptr() as *mut libc::c_void, unfilled.len())
            };
            
            if n >= 0 {
                buf.advance(n as usize);
                return Poll::Ready(Ok(()));
            } else {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Poll::Ready(Err(err));
            }
        }
    }
}

impl tokio::io::AsyncWrite for VsockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            let mut guard = match self.inner.poll_write_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            
            let fd = self.inner.as_raw_fd();
            let n = unsafe {
                libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len())
            };
            
            if n >= 0 {
                return Poll::Ready(Ok(n as usize));
            } else {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Poll::Ready(Err(err));
            }
        }
    }
    
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let fd = self.inner.as_raw_fd();
        unsafe { libc::shutdown(fd, libc::SHUT_WR); }
        Poll::Ready(Ok(()))
    }
}

impl Unpin for VsockStream {}

// =====================================================================
// VsockIncoming: Stream of accepted vSock connections for tonic
// =====================================================================
struct VsockIncoming {
    listener: tokio::io::unix::AsyncFd<RawFdWrapper>,
}

impl VsockIncoming {
    fn new(listener_fd: i32) -> std::io::Result<Self> {
        unsafe {
            let flags = libc::fcntl(listener_fd, libc::F_GETFL);
            libc::fcntl(listener_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let listener = tokio::io::unix::AsyncFd::new(RawFdWrapper(listener_fd))?;
        Ok(Self { listener })
    }
}

impl futures_core::Stream for VsockIncoming {
    type Item = Result<VsockStream, std::io::Error>;
    
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let mut guard = match self.listener.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => return Poll::Pending,
            };
            
            let conn_fd = unsafe {
                libc::accept(self.listener.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut())
            };
            
            if conn_fd >= 0 {
                tracing::info!("📥 Accepted vSock connection, fd={}", conn_fd);
                match VsockStream::new(conn_fd) {
                    Ok(stream) => return Poll::Ready(Some(Ok(stream))),
                    Err(e) => {
                        unsafe { libc::close(conn_fd); }
                        return Poll::Ready(Some(Err(e)));
                    }
                }
            } else {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Poll::Ready(Some(Err(err)));
            }
        }
    }
}

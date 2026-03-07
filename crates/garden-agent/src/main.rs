//! Garden Agent — The micro-VM Guest Agent
//! 
//! This binary is compiled statically and injected directly into the Apple Hypervisor
//! via a custom `cpio` ramdisk. The Linux Kernel executes this file as Process 1 (`/init`).

use garden_common::ipc::agent_service_server::{AgentService, AgentServiceServer};
use garden_common::ipc::{CommandRequest, CommandResponse, StatusRequest, StatusResponse};
use std::process::Command;
use tonic::{transport::Server, Request, Response, Status};

use tokio_stream::StreamExt;

#[derive(Default)]
pub struct GardenAgentImpl {}

#[tonic::async_trait]
impl AgentService for GardenAgentImpl {
    async fn execute_command(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        let req = request.into_inner();
        tracing::info!("Executing command: {} {:?} (cwd={})", req.command, req.args, req.cwd);

        // Define our execution directory 
        let cwd = if req.cwd.is_empty() { "/" } else { &req.cwd };

        // Execute the command inside the Linux Guest!
        let output = Command::new(&req.command)
            .args(&req.args)
            .current_dir(cwd)
            .output()
            .map_err(|e| {
                tracing::error!("Command::new failed: {:?}", e);
                Status::internal(format!("Failed to execute process: {}", e))
            })?;

        let response = CommandResponse {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        };

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    // 0. Mount essential pseudo-filesystems for Linux operation
    // =========================================================
    // As PID 1, we are the first userspace process. The kernel
    // does NOT mount these automatically — we must do it ourselves.
    let _ = std::fs::create_dir_all("/proc");
    let _ = std::fs::create_dir_all("/sys");
    let _ = std::fs::create_dir_all("/dev");
    let _ = std::process::Command::new("/bin/busybox").args(["mount", "-t", "proc", "proc", "/proc"]).status();
    let _ = std::process::Command::new("/bin/busybox").args(["mount", "-t", "sysfs", "sys", "/sys"]).status();
    let _ = std::process::Command::new("/bin/busybox").args(["mount", "-t", "devtmpfs", "dev", "/dev"]).status();
    tracing::info!("Mounted /proc, /sys, /dev");

    // 1. Initialize Network Interfaces using Netlink
    // =========================================================
    // With our custom kernel (CONFIG_MODULES=n), all drivers are
    // built-in — no modprobe needed! Just bring up interfaces.
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

    // 3. Start gRPC AgentService
    // =========================================================
    // Check if /dev/vsock exists to decide transport:
    //   - vSock present: listen on vSock port 6000 (host connects directly)
    //   - vSock absent:  fallback to TCP 0.0.0.0:10000 (legacy NAT path)
    let agent = GardenAgentImpl::default();

    if std::path::Path::new("/dev/vsock").exists() {
        // vSock transport: bind with AF_VSOCK using raw libc
        tracing::info!("🔌 /dev/vsock detected! Starting vSock listener on port 6000...");
        
        let vsock_listener_fd = create_vsock_listener(6000)?;
        tracing::info!("AgentService listening on vSock port 6000");
        
        // We can NOT use TcpListener::from_raw_fd because vSock fds
        // are AF_VSOCK, not AF_INET. Instead, we manually accept()
        // and convert each connection into a UnixStream (which works
        // for any SOCK_STREAM file descriptor).
        let incoming = VsockIncoming::new(vsock_listener_fd);
        
        Server::builder()
            .add_service(AgentServiceServer::new(agent))
            .serve_with_incoming(incoming)
            .await?;
    } else {
        // TCP fallback: no vSock available (legacy Alpine kernel path)
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
// SYNTAX BREAKDOWN: Creating a vSock Listener with Raw libc
// =====================================================================
// Linux's AF_VSOCK socket family uses the same socket/bind/listen
// syscalls as TCP, but with `sockaddr_vm` instead of `sockaddr_in`.
//
// We use raw libc calls because:
//   1. The `vsock` crate pulls in dependencies that may not cross-compile
//      cleanly under `aarch64-unknown-linux-musl`.
//   2. It's only ~20 lines of code — not worth a dependency.
//
// `VMADDR_CID_ANY` (0xFFFFFFFF) tells the kernel: "Accept connections
// from any CID" — meaning we don't need to know our own CID.
fn create_vsock_listener(port: u32) -> anyhow::Result<i32> {
    use std::mem;
    
    // AF_VSOCK = 40 on Linux
    const AF_VSOCK: i32 = 40;
    // VMADDR_CID_ANY = -1 (0xFFFFFFFF) — accept from any CID
    const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
    
    // struct sockaddr_vm layout (from Linux kernel headers):
    //   sa_family: u16   (AF_VSOCK = 40)
    //   reserved1: u16   (must be 0)
    //   port:      u32   (the vSock port number)
    //   cid:       u32   (VMADDR_CID_ANY to accept from any CID)
    //   ...padding to 16 bytes total
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
        // 1. Create the socket
        let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            anyhow::bail!("socket(AF_VSOCK) failed: {}", std::io::Error::last_os_error());
        }
        
        // 2. Bind to our port
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
        
        // 3. Listen for incoming connections
        let ret = libc::listen(fd, 5);
        if ret < 0 {
            libc::close(fd);
            anyhow::bail!("listen(AF_VSOCK) failed: {}", std::io::Error::last_os_error());
        }
        
        Ok(fd)
    }
}

// =====================================================================
// SYNTAX BREAKDOWN: VsockIncoming — Custom Stream for tonic
// =====================================================================
// tonic's `serve_with_incoming` requires a `Stream` that yields
// items implementing `AsyncRead + AsyncWrite + Connected + Unpin`.
// `tokio::net::UnixStream` satisfies all of these and works with
// any SOCK_STREAM file descriptor (not just AF_UNIX — AF_VSOCK too).
//
// This struct wraps a raw AF_VSOCK listener fd and yields accepted
// connections as `UnixStream`s.
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::UnixStream;

struct VsockIncoming {
    listener_fd: i32,
}

impl VsockIncoming {
    fn new(listener_fd: i32) -> Self {
        // Set the listener to non-blocking so tokio can poll it
        unsafe {
            let flags = libc::fcntl(listener_fd, libc::F_GETFL);
            libc::fcntl(listener_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        Self { listener_fd }
    }
}

impl futures_core::Stream for VsockIncoming {
    type Item = Result<UnixStream, std::io::Error>;
    
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Try to accept a connection
        let conn_fd = unsafe {
            libc::accept(self.listener_fd, std::ptr::null_mut(), std::ptr::null_mut())
        };
        
        if conn_fd >= 0 {
            // Successfully accepted — wrap as a UnixStream
            let std_stream = unsafe {
                use std::os::unix::io::FromRawFd;
                std::os::unix::net::UnixStream::from_raw_fd(conn_fd)
            };
            std_stream.set_nonblocking(true)?;
            let tokio_stream = UnixStream::from_std(std_stream)?;
            Poll::Ready(Some(Ok(tokio_stream)))
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                // No connection pending — register for wake-up.
                // We use a simple timer-based poll since we can't easily
                // register vSock fds with epoll via tokio's reactor.
                let waker = cx.waker().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    waker.wake();
                });
                Poll::Pending
            } else {
                Poll::Ready(Some(Err(err)))
            }
        }
    }
}

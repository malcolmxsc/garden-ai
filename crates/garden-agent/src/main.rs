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
        let incoming = VsockIncoming::new(vsock_listener_fd)?;
        
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
// VsockStream: AsyncRead + AsyncWrite wrapper for AF_VSOCK fds
// =====================================================================
// Uses `tokio::io::unix::AsyncFd` which registers the fd with the tokio
// reactor (epoll on Linux). This works for ANY pollable fd, including
// AF_VSOCK accepted connections.
//
// We can NOT use `tokio::net::UnixStream` because it expects AF_UNIX
// sockets and rejects AF_VSOCK fds.
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
        // Set non-blocking
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

// Required by tonic's serve_with_incoming
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
        // Set the listener to non-blocking for epoll
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

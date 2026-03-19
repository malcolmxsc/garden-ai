mod virtualizer;

use virtualizer::Virtualizer;

fn main() {
    println!("🌱 Starting Garden Engine Daemon...");

    // 1. Initialize the FFI Bridge 
    println!("Checking Apple Silicon Virtualization support...");
    
    let mut engine = match Virtualizer::new() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("❌ Failed to initialize Garden Engine: {}", e);
            std::process::exit(1);
        }
    };

    // 2. Check hardware support
    match engine.check_hardware() {
        Ok(_) => println!("✅ Virtualization hardware is supported and ready!"),
        Err(e) => {
            eprintln!("❌ Virtualization checks failed: {}", e);
            std::process::exit(1);
        }
    }
    
    // 3. Configure the VM
    println!("⚙️ Configuring Virtual Machine (2 CPUs, 512MB RAM)...");
    
    let kernel_path = "/Users/malcolmgriffin/.gemini/antigravity/scratch/garden-ai/guest/kernel/kernel"; 
    let initrd_path = "/Users/malcolmgriffin/.gemini/antigravity/scratch/garden-ai/guest/kernel/garden-initrd.cpio.gz";

    match engine.configure(kernel_path, initrd_path, 2, 512) {
        Ok(_) => println!("✅ VM successfully configured by Apple Hypervisor!"),
        Err(e) => {
            eprintln!("❌ VM configuration failed: {}", e);
            std::process::exit(1);
        }
    }

    // 4. Boot the VM
    println!("🚀 Booting the Alpine Linux VM...");
    match engine.start() {
        Ok(_) => println!("✅ VM Boot sequence initiated!"),
        Err(e) => {
            eprintln!("❌ VM failed to boot: {}", e);
            std::process::exit(1);
        }
    }

    // 5. Wait for agent to be ready, then start TCP proxy
    // =================================================================
    // For each incoming CLI TCP connection, we open a FRESH vSock connection
    // to the guest agent. The agent's VsockIncoming listener will accept()
    // each one independently, giving each CLI connection its own HTTP/2 stream.
    println!("🔌 Starting TCP→vSock proxy (background thread)...");
    
    let engine: &'static Virtualizer = Box::leak(Box::new(engine));
    
    std::thread::spawn(move || {
        // Wait for the VM kernel to boot and the agent to start listening
        std::thread::sleep(std::time::Duration::from_secs(3));
        
        // Start the TCP proxy — vSock connections are made on-demand per CLI session
        let vsock_port: u32 = 6000;
        run_tcp_vsock_proxy(engine, vsock_port);
    });

    // 6. Start telemetry receiver (connects to guest eBPF vSock port 6001)
    // =================================================================
    // Also starts a TCP proxy on 127.0.0.1:10001 so external tools can
    // tap the raw telemetry NDJSON stream.
    println!("📊 Starting telemetry receiver (background thread)...");

    std::thread::spawn(move || {
        // Wait longer than gRPC proxy — eBPF probes load after gRPC server starts
        std::thread::sleep(std::time::Duration::from_secs(5));
        run_telemetry_receiver(engine);
    });

    println!("🔄 Daemon handing control to macOS CFRunLoop. Press Ctrl+C to stop.");
    Virtualizer::run_loop();
}

// =====================================================================
// TCP-to-vSock Async Proxy (per-connection vSock)
// =====================================================================
// For each CLI TCP connection to 127.0.0.1:10000, we open a NEW vSock
// connection to the guest agent. This gives each CLI connection its own
// isolated gRPC/HTTP/2 channel. The agent's VsockIncoming listener will
// accept() each connection independently.
fn run_tcp_vsock_proxy(engine: &'static Virtualizer, vsock_port: u32) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime for proxy");
    
    rt.block_on(async move {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:10000").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("❌ Failed to bind proxy: {}", e);
                return;
            }
        };
        println!("✅ TCP→vSock proxy listening on 127.0.0.1:10000");
        
        loop {
            let (tcp_stream, addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("❌ Accept error: {}", e);
                    continue;
                }
            };
            
            println!("📥 CLI connected from {}", addr);
            
            // Open a FRESH vSock connection for this CLI session.
            // connect_vsock dispatches to the main thread via GCD.
            let vsock_fd = match engine.connect_vsock(vsock_port) {
                Ok(fd) => {
                    println!("   🔗 New vSock connection fd={}", fd);
                    fd
                }
                Err(e) => {
                    eprintln!("   ❌ vSock connect failed: {}", e);
                    continue;
                }
            };
            
            // Set non-blocking for async I/O
            unsafe {
                let flags = libc::fcntl(vsock_fd, libc::F_GETFL);
                libc::fcntl(vsock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
            
            // Wrap in our async VsockStream
            let vsock_stream = match VsockStream::new(vsock_fd) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("   ❌ VsockStream error: {}", e);
                    unsafe { libc::close(vsock_fd); }
                    continue;
                }
            };
            
            // Spawn a task to bidirectionally copy bytes: TCP ↔ vSock
            tokio::spawn(async move {
                let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_stream);
                let (mut vsock_read, mut vsock_write) = tokio::io::split(vsock_stream);
                
                let t1 = tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut tcp_read, &mut vsock_write).await;
                });
                let t2 = tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut vsock_read, &mut tcp_write).await;
                });
                
                let _ = tokio::try_join!(t1, t2);
                println!("📤 CLI disconnected from {}", addr);
            });
        }
    });
}

// =====================================================================
// Telemetry Receiver (connects to guest eBPF vSock port 6001)
// =====================================================================
// Reads NDJSON SecurityEvent stream from the guest agent's eBPF tracer.
// Also starts a TCP proxy on 127.0.0.1:10001 for external tools to tap
// the raw telemetry stream.
fn run_telemetry_receiver(engine: &'static Virtualizer) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime for telemetry");

    let policy = garden_ebpf::policy::SecurityPolicy::default_observe();

    rt.block_on(async move {
        // Also start a TCP proxy for telemetry on port 10001
        // so external tools (socat, test scripts) can tap the stream
        tokio::spawn(run_telemetry_tcp_proxy(engine));

        loop {
            println!("📊 Connecting to guest telemetry vSock port 6001...");

            let vsock_fd = match engine.connect_vsock(6001) {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("📊 Telemetry connect failed: {}, retrying in 2s...", e);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
            };

            println!("📊 Telemetry connected to guest, fd={}", vsock_fd);

            // Set non-blocking for async I/O
            unsafe {
                let flags = libc::fcntl(vsock_fd, libc::F_GETFL);
                libc::fcntl(vsock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }

            let stream = match VsockStream::new(vsock_fd) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("📊 VsockStream error: {}, retrying...", e);
                    unsafe { libc::close(vsock_fd); }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
            };

            // Read NDJSON lines and evaluate policy
            process_telemetry_stream(stream, &policy).await;

            println!("📊 Telemetry connection lost, reconnecting in 2s...");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
}

async fn process_telemetry_stream(stream: VsockStream, policy: &garden_ebpf::policy::SecurityPolicy) {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        match serde_json::from_str::<garden_ebpf::events::SecurityEvent>(&line) {
            Ok(event) => {
                let action = policy.evaluate(&event);
                match action {
                    garden_ebpf::policy::PolicyAction::Deny => {
                        eprintln!(
                            "🚨 DENIED: pid={} comm={} {:?}",
                            event.pid, event.comm, event.kind
                        );
                    }
                    garden_ebpf::policy::PolicyAction::Log => {
                        println!(
                            "📊 [telemetry] pid={} comm={} {:?}",
                            event.pid, event.comm, event.kind
                        );
                    }
                    garden_ebpf::policy::PolicyAction::Allow => {
                        // Silent pass — allowed events are not printed
                    }
                }
            }
            Err(e) => {
                eprintln!("📊 Failed to parse telemetry event: {} (line: {})", e, line);
            }
        }
    }
}

/// TCP proxy for telemetry on 127.0.0.1:10001.
/// External tools (socat, test scripts) can connect here to receive
/// the raw NDJSON telemetry stream from the guest.
async fn run_telemetry_tcp_proxy(engine: &'static Virtualizer) {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:10001").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("📊 Failed to bind telemetry proxy on 10001: {}", e);
            return;
        }
    };
    println!("✅ Telemetry TCP proxy listening on 127.0.0.1:10001");

    loop {
        let (tcp_stream, addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("📊 Telemetry proxy accept error: {}", e);
                continue;
            }
        };

        println!("📊 Telemetry consumer connected from {}", addr);

        let vsock_fd = match engine.connect_vsock(6001) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("📊 Telemetry vSock connect failed: {}", e);
                continue;
            }
        };

        unsafe {
            let flags = libc::fcntl(vsock_fd, libc::F_GETFL);
            libc::fcntl(vsock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let vsock_stream = match VsockStream::new(vsock_fd) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("📊 VsockStream error: {}", e);
                unsafe { libc::close(vsock_fd); }
                continue;
            }
        };

        // One-directional copy: vSock → TCP (telemetry flows guest → host → consumer)
        tokio::spawn(async move {
            let (mut vsock_read, _) = tokio::io::split(vsock_stream);
            let (_, mut tcp_write) = tokio::io::split(tcp_stream);
            let _ = tokio::io::copy(&mut vsock_read, &mut tcp_write).await;
            println!("📊 Telemetry consumer disconnected from {}", addr);
        });
    }
}

// =====================================================================
// VsockStream: AsyncRead + AsyncWrite wrapper for any raw fd
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
        let inner = tokio::io::unix::AsyncFd::new(RawFdWrapper(fd))?;
        Ok(Self { inner })
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        unsafe { libc::close(self.inner.as_raw_fd()); }
    }
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

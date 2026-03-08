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

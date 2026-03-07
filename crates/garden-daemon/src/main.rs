mod virtualizer;

use virtualizer::Virtualizer;

fn main() {
    println!("🌱 Starting Garden Engine Daemon...");

    // 1. Initialize the FFI Bridge
    println!("Checking Apple Silicon Virtualization support...");
    
    // We use Rust's `match` statement to handle the Result enum returned by our `Virtualizer::new()` wrapper.
    let mut engine = match Virtualizer::new() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("❌ Failed to initialize Garden Engine: {}", e);
            std::process::exit(1);
        }
    };

    // 2. Test the Swift Method
    // Now we call our safe Rust method, which passes the raw pointer across the C-bridge into Swift.
    match engine.check_hardware() {
        Ok(_) => println!("✅ Virtualization hardware is supported and ready!"),
        Err(e) => {
            eprintln!("❌ Virtualization checks failed: {}", e);
            std::process::exit(1);
        }
    }
    
    // 3. Test Configuring the Virtual Machine
    // We pass our downloaded Alpine Linux paths across the bridge into Swift, requesting 2 CPUs and 512MB of RAM.
    println!("⚙️ Configuring Virtual Machine (2 CPUs, 512MB RAM)...");
    
    // In a real app we'd get these paths dynamically from the CLI
    let kernel_path = "/Users/malcolmgriffin/.gemini/antigravity/scratch/garden-ai/guest/kernel/kernel"; 
    let initrd_path = "/Users/malcolmgriffin/.gemini/antigravity/scratch/garden-ai/guest/kernel/garden-initrd.cpio.gz";

    match engine.configure(kernel_path, initrd_path, 2, 512) {
        Ok(_) => println!("✅ VM successfully configured by Apple Hypervisor!"),
        Err(e) => {
            eprintln!("❌ VM configuration failed: {}", e);
            std::process::exit(1);
        }
    }

    // 4. Test Booting the Virtual Machine
    println!("🚀 Booting the Alpine Linux VM...");
    match engine.start() {
        Ok(_) => println!("✅ VM Boot sequence initiated!"),
        Err(e) => {
            eprintln!("❌ VM failed to boot: {}", e);
            std::process::exit(1);
        }
    }

    // 5. Connect to guest agent via vSock (from a background thread)
    // =================================================================
    // CRITICAL: VZVirtioSocketDevice.connect(toPort:) dispatches its
    // completion callback on the main thread's CFRunLoop. We must start
    // the RunLoop FIRST, then connect from a background thread.
    println!("🔌 Will connect to guest agent via vSock (background thread)...");
    
    // Leak the engine into a &'static reference — it lives for the entire
    // process lifetime anyway (until Ctrl+C kills the daemon).
    let engine: &'static Virtualizer = Box::leak(Box::new(engine));
    
    std::thread::spawn(move || {
        // Wait for the VM kernel to boot and the agent to start listening
        std::thread::sleep(std::time::Duration::from_secs(3));
        
        let vsock_port: u32 = 6000;
        let mut vsock_fd: Option<i32> = None;
        
        for attempt in 1..=30 {
            match engine.connect_vsock(vsock_port) {
                Ok(fd) => {
                    println!("✅ vSock connected! fd={} (attempt {})", fd, attempt);
                    vsock_fd = Some(fd);
                    break;
                }
                Err(e) => {
                    if attempt % 5 == 0 {
                        println!("   ⏳ vSock attempt {}/30: {}", attempt, e);
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        
        match vsock_fd {
            Some(fd) => {
                println!("🌿 Garden Agent connected on vSock fd={}", fd);
                println!("   Starting local TCP proxy on 127.0.0.1:10000...");
                if let Err(e) = run_tcp_vsock_proxy(fd) {
                    eprintln!("❌ TCP-vSock proxy error: {}", e);
                }
            }
            None => {
                eprintln!("⚠️  vSock connection failed after 30 attempts.");
                eprintln!("   Falling back to NAT TCP (guest must have a DHCP IP).");
            }
        }
    });

    println!("🔄 Daemon handing control to macOS CFRunLoop. Press Ctrl+C to stop.");
    Virtualizer::run_loop();
}

// =====================================================================
// SYNTAX BREAKDOWN: TCP-to-vSock Proxy
// =====================================================================
// The CLI connects to 127.0.0.1:10000 (localhost). We accept the
// connection and bidirectionally copy bytes between the CLI's TCP
// socket and the vSock file descriptor that points into the Linux VM.
//
// This is a simple single-connection proxy — good enough for the
// current 1:1 CLI-to-agent model. For connection pooling or multiplexing,
// this would need to be expanded into an async acceptor loop.
fn run_tcp_vsock_proxy(vsock_fd: i32) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::io::FromRawFd;
    
    let listener = TcpListener::bind("127.0.0.1:10000")?;
    // Allow rapid restart of the daemon without "Address already in use"
    listener.set_nonblocking(false)?;
    println!("✅ Local proxy listening on 127.0.0.1:10000");
    
    for stream in listener.incoming() {
        let mut tcp_stream = stream?;
        
        // Wrap the vSock fd into a Rust File for read/write.
        // SAFETY: The fd was returned by VZVirtioSocketConnection and is
        // valid for the lifetime of the VM. We use `dup()` to avoid
        // closing the original fd when this File is dropped.
        let dup_fd = unsafe { libc::dup(vsock_fd) };
        if dup_fd < 0 {
            eprintln!("❌ Failed to dup vSock fd");
            continue;
        }
        let mut vsock_stream = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        
        // Bidirectional copy: TCP ↔ vSock
        let mut tcp_clone = tcp_stream.try_clone()?;
        let mut vsock_clone = vsock_stream.try_clone()?;
        
        // Forward TCP → vSock in a thread
        let t1 = std::thread::spawn(move || {
            let _ = std::io::copy(&mut tcp_stream, &mut vsock_stream);
        });
        
        // Forward vSock → TCP in this thread
        let _ = std::io::copy(&mut vsock_clone, &mut tcp_clone);
        let _ = t1.join();
    }
    
    Ok(())
}

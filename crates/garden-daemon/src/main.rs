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

    println!("🔄 Daemon handing control to macOS CFRunLoop. Press Ctrl+C to stop.");
    // 5. The Execution Loop
    // The Swift Virtualizer runs on background threads managed by macOS.
    // Apple's Virtualization.framework requires an active RunLoop on the main thread
    // to process asynchronous block callbacks and I/O streams.
    Virtualizer::run_loop();
}

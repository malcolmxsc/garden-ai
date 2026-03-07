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
    let kernel_path = "../guest/kernel/vmlinuz-virt"; 
    let initrd_path = "../guest/kernel/initramfs-virt";

    match engine.configure(kernel_path, initrd_path, 2, 512) {
        Ok(_) => println!("✅ VM successfully configured by Apple Hypervisor!"),
        Err(e) => {
            eprintln!("❌ VM configuration failed: {}", e);
            std::process::exit(1);
        }
    }

    // As `engine` goes out of scope at the end of `main`, Rust will automatically 
    // call our `Drop` trait and release the Swift object!
}

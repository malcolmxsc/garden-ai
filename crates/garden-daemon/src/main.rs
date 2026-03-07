mod virtualizer;

use virtualizer::Virtualizer;

fn main() {
    println!("🌱 Starting Garden Engine Daemon...");

    // 1. Initialize the FFI Bridge
    println!("Checking Apple Silicon Virtualization support...");
    
    // We use Rust's `match` statement to handle the Result enum returned by our `Virtualizer::new()` wrapper.
    let engine = match Virtualizer::new() {
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
    
    // As `engine` goes out of scope at the end of `main`, Rust will automatically 
    // call our `Drop` trait and release the Swift object!
}

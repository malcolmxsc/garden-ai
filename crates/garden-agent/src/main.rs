#[cfg(target_os = "linux")]
mod agent_core;

#[cfg(target_os = "linux")]
fn main() {
    agent_core::run();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("garden-agent is a Linux-only executable.");
}

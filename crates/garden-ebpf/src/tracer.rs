//! eBPF probe loader and tracer.
//!
//! On Linux, this module uses `aya` to load eBPF programs into the kernel
//! and attach them to tracepoints/kprobes. On macOS, it compiles as a
//! no-op stub.

/// Start the eBPF tracer with the given policy.
///
/// This function loads eBPF probes, attaches them to kernel hooks,
/// and begins streaming security events.
#[cfg(target_os = "linux")]
pub async fn start_tracer(
    _policy: &super::policy::SecurityPolicy,
) -> anyhow::Result<()> {
    tracing::info!("Loading eBPF probes...");
    // TODO: Use aya to load BPF programs from garden-ebpf-probes
    // TODO: Attach to tracepoints (sys_enter_openat, sys_enter_connect, etc.)
    // TODO: Start perf event polling loop
    Ok(())
}

/// Stub tracer for non-Linux platforms (macOS host).
#[cfg(not(target_os = "linux"))]
pub async fn start_tracer(
    _policy: &super::policy::SecurityPolicy,
) -> anyhow::Result<()> {
    tracing::warn!("eBPF tracer is only available on Linux (inside the guest VM)");
    Ok(())
}

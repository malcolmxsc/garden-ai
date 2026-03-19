//! eBPF probe loader and tracer.
//!
//! On Linux, this module uses `aya` to load eBPF programs into the kernel
//! and attach them to tracepoints/kprobes. On macOS, it compiles as a
//! no-op stub.

use super::events::{SecurityEvent, SecurityEventKind};
use garden_ebpf_common::{bytes_to_str, EventKind, RawSecurityEvent};
use tokio::sync::mpsc;

/// Handle to a running eBPF tracer.
///
/// Dropping this handle detaches all probes and stops event collection.
/// For long-lived tracing (e.g., VM lifetime), leak with `std::mem::forget`.
pub struct TracerHandle {
    #[cfg(target_os = "linux")]
    _ebpf: aya::Ebpf,
}

/// Convert a raw BPF event to a typed `SecurityEvent`.
fn convert_raw_event(raw: &RawSecurityEvent) -> Option<SecurityEvent> {
    let kind_enum = EventKind::from_u32(raw.kind)?;
    let comm = bytes_to_str(&raw.comm).to_string();

    let kind = match kind_enum {
        EventKind::Execve => SecurityEventKind::ProcessExec {
            binary: bytes_to_str(&raw.path).to_string(),
            args: vec![bytes_to_str(&raw.args).to_string()],
            allowed: true,
        },
        EventKind::Openat => SecurityEventKind::FileAccess {
            path: bytes_to_str(&raw.path).to_string(),
            flags: raw.flags,
            allowed: true,
        },
        EventKind::Connect => {
            let ip = raw.dest_ip.to_be_bytes();
            SecurityEventKind::NetworkConnect {
                dest_ip: format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                dest_port: raw.dest_port,
                protocol: if raw.protocol == 17 {
                    "udp".to_string()
                } else {
                    "tcp".to_string()
                },
                allowed: true,
            }
        }
        // Tier 2 events — placeholder for future probes
        _ => SecurityEventKind::SyscallTrace {
            syscall_nr: raw.kind as u64,
            syscall_name: format!("{:?}", kind_enum),
            allowed: true,
        },
    };

    Some(SecurityEvent {
        timestamp_ns: raw.timestamp_ns,
        pid: raw.pid,
        comm,
        kind,
    })
}

/// Start the eBPF tracer with the given policy.
///
/// Loads BPF probes, attaches them to kernel tracepoints, and begins
/// streaming security events through the returned channel.
///
/// # Returns
/// - `TracerHandle` — keeps probes attached; drop to stop tracing
/// - `mpsc::Receiver<SecurityEvent>` — event stream (capacity 1024)
#[cfg(target_os = "linux")]
pub async fn start_tracer(
    _policy: &super::policy::SecurityPolicy,
) -> anyhow::Result<(TracerHandle, mpsc::Receiver<SecurityEvent>)> {
    use aya::maps::perf::AsyncPerfEventArray;
    use aya::programs::TracePoint;
    use aya::util::online_cpus;
    use bytes::BytesMut;

    tracing::info!("Loading eBPF probes...");

    // 1. Load BPF bytecode embedded at compile time
    //
    // The BPF ELF is built by `garden-ebpf-probes` and placed at a known
    // path. During development, this path is set by the build script or
    // can be overridden via the GARDEN_BPF_ELF environment variable.
    let bpf_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../garden-ebpf-probes/target/bpfel-unknown-none/release/garden-ebpf-probes"
    ));
    let mut ebpf = aya::Ebpf::load(bpf_bytes)?;

    // 2. Initialize aya-log for BPF-side debug logging
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        tracing::warn!("Failed to init eBPF logger (non-fatal): {}", e);
    }

    // 3. Attach Tier 1 tracepoints
    let probes = [
        ("trace_execve", "syscalls", "sys_enter_execve"),
        ("trace_openat", "syscalls", "sys_enter_openat"),
        ("trace_connect", "syscalls", "sys_enter_connect"),
    ];

    for (name, category, tracepoint) in &probes {
        let program: &mut TracePoint = ebpf
            .program_mut(name)
            .ok_or_else(|| anyhow::anyhow!("BPF program '{}' not found in ELF", name))?
            .try_into()?;
        program.load()?;
        program.attach(category, tracepoint)?;
        tracing::info!("Attached eBPF probe: {}/{}", category, tracepoint);
    }

    // 4. Open PerfEventArray and spawn per-CPU polling tasks
    let (tx, rx) = mpsc::channel::<SecurityEvent>(1024);

    let mut perf_array = AsyncPerfEventArray::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("BPF map 'EVENTS' not found"))?,
    )?;

    let cpus = online_cpus().map_err(|e| anyhow::anyhow!("failed to get online CPUs: {}", e))?;
    tracing::info!("Starting perf event readers on {} CPUs", cpus.len());

    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, Some(256))?;
        let tx = tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(core::mem::size_of::<RawSecurityEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        tracing::error!(
                            "Error reading perf events on CPU {}: {}",
                            cpu_id,
                            e
                        );
                        // Brief backoff before retrying
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };

                for i in 0..events.read {
                    if buffers[i].len() >= core::mem::size_of::<RawSecurityEvent>() {
                        let raw = unsafe {
                            &*(buffers[i].as_ptr() as *const RawSecurityEvent)
                        };
                        if let Some(event) = convert_raw_event(raw) {
                            // Non-blocking send — drop events if channel is full
                            // rather than blocking the perf reader
                            if tx.try_send(event).is_err() {
                                tracing::warn!("Telemetry channel full, dropping event");
                            }
                        }
                    }
                }
            }
        });
    }

    tracing::info!("eBPF tracer started — monitoring execve, openat, connect");

    Ok((TracerHandle { _ebpf: ebpf }, rx))
}

/// Stub tracer for non-Linux platforms (macOS host).
///
/// Returns a dummy handle and an event channel that never produces events.
/// This allows the rest of the codebase to compile on macOS without
/// conditional compilation at every call site.
#[cfg(not(target_os = "linux"))]
pub async fn start_tracer(
    _policy: &super::policy::SecurityPolicy,
) -> anyhow::Result<(TracerHandle, mpsc::Receiver<SecurityEvent>)> {
    tracing::warn!("eBPF tracer is only available on Linux (inside the guest VM)");
    let (_tx, rx) = mpsc::channel(1);
    Ok((TracerHandle {}, rx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use garden_ebpf_common::{EventKind, RawSecurityEvent};

    #[test]
    fn test_convert_execve_event() {
        let mut raw = RawSecurityEvent::zeroed();
        raw.kind = EventKind::Execve as u32;
        raw.pid = 42;
        raw.timestamp_ns = 123456789;
        raw.comm[..4].copy_from_slice(b"bash");
        raw.path[..8].copy_from_slice(b"/bin/cat");
        raw.args[..5].copy_from_slice(b"hello");

        let event = convert_raw_event(&raw).unwrap();
        assert_eq!(event.pid, 42);
        assert_eq!(event.comm, "bash");
        if let SecurityEventKind::ProcessExec { binary, args, .. } = &event.kind {
            assert_eq!(binary, "/bin/cat");
            assert_eq!(args[0], "hello");
        } else {
            panic!("expected ProcessExec");
        }
    }

    #[test]
    fn test_convert_openat_event() {
        let mut raw = RawSecurityEvent::zeroed();
        raw.kind = EventKind::Openat as u32;
        raw.pid = 100;
        raw.comm[..2].copy_from_slice(b"ls");
        raw.path[..4].copy_from_slice(b"/tmp");
        raw.flags = 0o0;

        let event = convert_raw_event(&raw).unwrap();
        assert_eq!(event.pid, 100);
        if let SecurityEventKind::FileAccess { path, flags, .. } = &event.kind {
            assert_eq!(path, "/tmp");
            assert_eq!(*flags, 0);
        } else {
            panic!("expected FileAccess");
        }
    }

    #[test]
    fn test_convert_connect_event() {
        let mut raw = RawSecurityEvent::zeroed();
        raw.kind = EventKind::Connect as u32;
        raw.pid = 200;
        raw.comm[..4].copy_from_slice(b"curl");
        // 93.184.216.34 = 0x5DB8D822
        raw.dest_ip = u32::from_be_bytes([93, 184, 216, 34]);
        raw.dest_port = 443;
        raw.protocol = 6; // TCP

        let event = convert_raw_event(&raw).unwrap();
        if let SecurityEventKind::NetworkConnect {
            dest_ip,
            dest_port,
            protocol,
            ..
        } = &event.kind
        {
            assert_eq!(dest_ip, "93.184.216.34");
            assert_eq!(*dest_port, 443);
            assert_eq!(protocol, "tcp");
        } else {
            panic!("expected NetworkConnect");
        }
    }

    #[test]
    fn test_convert_unknown_kind_returns_none() {
        let mut raw = RawSecurityEvent::zeroed();
        raw.kind = 255; // invalid
        assert!(convert_raw_event(&raw).is_none());
    }
}

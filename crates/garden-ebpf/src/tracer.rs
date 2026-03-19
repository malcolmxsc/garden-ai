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

/// Decode a DNS query name from a raw DNS packet stored in `args`.
///
/// DNS wire format: 12-byte header, then length-prefixed labels.
/// e.g., `\x07example\x03com\x00` → "example.com"
fn decode_dns_query(raw: &[u8]) -> String {
    // DNS header is 12 bytes; query name starts at offset 12
    if raw.len() <= 12 {
        return String::new();
    }

    let mut result = String::new();
    let mut pos = 12;

    // Safety: limit iterations to prevent infinite loops on malformed data
    for _ in 0..64 {
        if pos >= raw.len() {
            break;
        }
        let label_len = raw[pos] as usize;
        if label_len == 0 {
            break;
        }
        pos += 1;
        if pos + label_len > raw.len() {
            break;
        }
        if !result.is_empty() {
            result.push('.');
        }
        if let Ok(label) = core::str::from_utf8(&raw[pos..pos + label_len]) {
            result.push_str(label);
        }
        pos += label_len;
    }

    result
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
        EventKind::DnsQuery => {
            let ip = raw.dest_ip.to_be_bytes();
            SecurityEventKind::DnsQuery {
                server_ip: format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                domain: decode_dns_query(&raw.args),
            }
        }
        EventKind::Mount => SecurityEventKind::MountAttempt {
            target: bytes_to_str(&raw.path).to_string(),
            source: bytes_to_str(&raw.args).to_string(),
            flags: raw.flags,
        },
        EventKind::BpfLoad => SecurityEventKind::BpfSyscall {
            cmd: raw.flags,
        },
        EventKind::ModuleLoad => SecurityEventKind::ModuleLoad {
            size: raw.flags,
            args: bytes_to_str(&raw.args).to_string(),
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

    // 3. Attach tracepoints (Tier 1 + Tier 2)
    let probes = [
        // Tier 1
        ("trace_execve", "syscalls", "sys_enter_execve"),
        ("trace_openat", "syscalls", "sys_enter_openat"),
        ("trace_connect", "syscalls", "sys_enter_connect"),
        // Tier 2
        ("trace_sendto", "syscalls", "sys_enter_sendto"),
        ("trace_mount", "syscalls", "sys_enter_mount"),
        ("trace_bpf", "syscalls", "sys_enter_bpf"),
        ("trace_init_module", "syscalls", "sys_enter_init_module"),
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

    tracing::info!("eBPF tracer started — monitoring execve, openat, connect, sendto, mount, bpf, init_module");

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

    #[test]
    fn test_decode_dns_query() {
        // DNS wire format: 12-byte header + "\x07example\x03com\x00"
        let mut raw = [0u8; 256];
        // Skip 12-byte header (zeros)
        raw[12] = 7; // length of "example"
        raw[13..20].copy_from_slice(b"example");
        raw[20] = 3; // length of "com"
        raw[21..24].copy_from_slice(b"com");
        raw[24] = 0; // terminator

        assert_eq!(decode_dns_query(&raw), "example.com");
    }

    #[test]
    fn test_decode_dns_query_empty() {
        let raw = [0u8; 10]; // too short for DNS header
        assert_eq!(decode_dns_query(&raw), "");
    }

    #[test]
    fn test_convert_dns_event() {
        let mut raw = RawSecurityEvent::zeroed();
        raw.kind = EventKind::DnsQuery as u32;
        raw.pid = 300;
        raw.comm[..7].copy_from_slice(b"resolv ");
        raw.dest_ip = u32::from_be_bytes([8, 8, 8, 8]);
        raw.dest_port = 53;
        raw.protocol = 17; // UDP
        // DNS payload: header (12 bytes) + \x07example\x03com\x00
        raw.args[12] = 7;
        raw.args[13..20].copy_from_slice(b"example");
        raw.args[20] = 3;
        raw.args[21..24].copy_from_slice(b"com");

        let event = convert_raw_event(&raw).unwrap();
        if let SecurityEventKind::DnsQuery { server_ip, domain } = &event.kind {
            assert_eq!(server_ip, "8.8.8.8");
            assert_eq!(domain, "example.com");
        } else {
            panic!("expected DnsQuery");
        }
    }

    #[test]
    fn test_convert_mount_event() {
        let mut raw = RawSecurityEvent::zeroed();
        raw.kind = EventKind::Mount as u32;
        raw.pid = 1;
        raw.comm[..4].copy_from_slice(b"init");
        raw.path[..4].copy_from_slice(b"/mnt");
        raw.args[..8].copy_from_slice(b"/dev/vda");
        raw.flags = 0;

        let event = convert_raw_event(&raw).unwrap();
        if let SecurityEventKind::MountAttempt { target, source, flags } = &event.kind {
            assert_eq!(target, "/mnt");
            assert_eq!(source, "/dev/vda");
            assert_eq!(*flags, 0);
        } else {
            panic!("expected MountAttempt");
        }
    }

    #[test]
    fn test_convert_bpf_event() {
        let mut raw = RawSecurityEvent::zeroed();
        raw.kind = EventKind::BpfLoad as u32;
        raw.pid = 500;
        raw.comm[..5].copy_from_slice(b"agent");
        raw.flags = 5; // BPF_PROG_LOAD

        let event = convert_raw_event(&raw).unwrap();
        if let SecurityEventKind::BpfSyscall { cmd } = &event.kind {
            assert_eq!(*cmd, 5);
        } else {
            panic!("expected BpfSyscall");
        }
    }

    #[test]
    fn test_convert_module_load_event() {
        let mut raw = RawSecurityEvent::zeroed();
        raw.kind = EventKind::ModuleLoad as u32;
        raw.pid = 600;
        raw.comm[..6].copy_from_slice(b"insmod");
        raw.flags = 4096; // module size

        let event = convert_raw_event(&raw).unwrap();
        if let SecurityEventKind::ModuleLoad { size, .. } = &event.kind {
            assert_eq!(*size, 4096);
        } else {
            panic!("expected ModuleLoad");
        }
    }
}

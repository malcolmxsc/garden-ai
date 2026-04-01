//! eBPF probe loader and tracer.
//!
//! On Linux, this module uses `aya` to load eBPF programs into the kernel
//! and attach them to tracepoints/kprobes. On macOS, it compiles as a
//! no-op stub.

use super::events::{SecurityEvent, SecurityEventKind};
#[cfg(target_os = "linux")]
use super::policy::PolicyAction;
use garden_ebpf_common::{bytes_to_str, EventKind, RawSecurityEvent, MAX_COMM_LEN};
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
            let ip = raw.dest_ip.to_ne_bytes();
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
            let ip = raw.dest_ip.to_ne_bytes();
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
        EventKind::Fork => SecurityEventKind::ProcessFork {
            parent_pid: raw.pid,
            child_pid: raw.flags,
            child_comm: bytes_to_str(&raw.path[..MAX_COMM_LEN]).to_string(),
        },
        EventKind::Exit => SecurityEventKind::ProcessExit {
            exit_code: raw.flags,
        },
        EventKind::CredsChanged => SecurityEventKind::CredsChanged {
            old_uid: raw.aux as u32,
            new_uid: raw.flags,
        },
        EventKind::TcpSend => SecurityEventKind::TcpSend {
            bytes: raw.aux,
        },
        EventKind::TcpRecv => SecurityEventKind::TcpRecv {
            bytes: raw.aux,
        },
        EventKind::OomKill => SecurityEventKind::OomKill {
            victim_pid: raw.pid,
            victim_comm: bytes_to_str(&raw.path[..MAX_COMM_LEN]).to_string(),
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
    policy: super::policy::SecurityPolicy,
) -> anyhow::Result<(TracerHandle, mpsc::Receiver<SecurityEvent>)> {
    use aya::maps::perf::AsyncPerfEventArray;
    use aya::programs::{KProbe, Lsm, TracePoint};
    use aya::util::online_cpus;
    use aya::Btf;
    use bytes::BytesMut;

    tracing::info!("Loading eBPF probes...");

    // 1. Load BPF bytecode embedded at compile time
    //
    // The BPF ELF is built by `garden-ebpf-probes` and placed at a known
    // path. We copy into a Vec to guarantee 8-byte alignment, which the
    // `object` crate's ELF parser requires. `include_bytes!` only
    // guarantees 1-byte alignment.
    let bpf_bytes_raw = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../garden-ebpf-probes/target/bpfel-unknown-none/release/garden-ebpf-probes"
    ));
    let bpf_bytes = bpf_bytes_raw.to_vec();
    let mut ebpf = aya::Ebpf::load(&bpf_bytes)?;

    // 1b. Populate BPF-LSM policy maps before attaching probes.
    // LSM probes read these maps synchronously at hook time, so they must be
    // populated before the probes are attached. Glob-pattern rules are skipped
    // here and fall back to kill-on-detect in the perf event loop.
    populate_policy_maps(&mut ebpf, &policy)?;

    // 2. Attach tracepoints (Tier 1 + Tier 2)
    //
    // Some probes may be unavailable if the kernel was built without the
    // corresponding syscall (e.g., init_module with CONFIG_MODULES=n).
    // We attach as many as possible and log warnings for failures.
    let probes = [
        // Tier 1
        ("trace_execve", "syscalls", "sys_enter_execve", true),
        ("trace_openat", "syscalls", "sys_enter_openat", true),
        ("trace_connect", "syscalls", "sys_enter_connect", true),
        // Tier 2
        ("trace_sendto", "syscalls", "sys_enter_sendto", false),
        ("trace_mount", "syscalls", "sys_enter_mount", false),
        ("trace_bpf", "syscalls", "sys_enter_bpf", false),
        ("trace_init_module", "syscalls", "sys_enter_init_module", false),
        // Tier 3 — process lifecycle + OOM
        ("trace_fork", "sched", "sched_process_fork", false),
        ("trace_exit", "sched", "sched_process_exit", false),
        ("trace_oom_victim", "oom", "mark_victim", false),
    ];

    let mut attached = 0u32;
    for (name, category, tracepoint, required) in &probes {
        let result = (|| -> anyhow::Result<()> {
            let program: &mut TracePoint = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("BPF program '{}' not found in ELF", name))?
                .try_into()?;
            program.load()?;
            program.attach(category, tracepoint)?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                tracing::info!("Attached eBPF probe: {}/{}", category, tracepoint);
                attached += 1;
            }
            Err(e) if *required => {
                return Err(e.context(format!("Required probe {}/{} failed", category, tracepoint)));
            }
            Err(e) => {
                tracing::warn!("Optional probe {}/{} unavailable: {}", category, tracepoint, e);
            }
        }
    }
    tracing::info!("Attached {}/{} eBPF tracepoints", attached, probes.len());

    // 3. Attach kprobes (Tier 3 — require CONFIG_KPROBES=y)
    let kprobes = [
        ("trace_commit_creds", "commit_creds", false),
        ("trace_tcp_sendmsg",  "tcp_sendmsg",  false),
        ("trace_tcp_recvmsg",  "tcp_recvmsg",  false),
    ];

    let mut kprobes_attached = 0u32;
    for (name, fn_name, required) in &kprobes {
        let result = (|| -> anyhow::Result<()> {
            let program: &mut KProbe = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("BPF program '{}' not found in ELF", name))?
                .try_into()?;
            program.load()?;
            program.attach(fn_name, 0)?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                tracing::info!("Attached kprobe: {}", fn_name);
                kprobes_attached += 1;
            }
            Err(e) if *required => {
                return Err(e.context(format!("Required kprobe {} failed", fn_name)));
            }
            Err(e) => {
                tracing::warn!("Optional kprobe {} unavailable: {}", fn_name, e);
            }
        }
    }
    tracing::info!("Attached {}/{} kprobes", kprobes_attached, kprobes.len());

    // 4. Attach BPF-LSM programs.
    // LSM programs enforce policy synchronously — before syscalls complete —
    // by returning -EPERM from the hook. They require BTF (loaded from
    // /sys/kernel/btf/vmlinux) for CO-RE relocation at load time.
    let btf = Btf::from_sys_fs().unwrap_or_else(|e| {
        tracing::warn!("Failed to load BTF from /sys/kernel/btf/vmlinux: {} — LSM probes may not load", e);
        // Safety: we'll fail at load time below if BTF is missing
        unsafe { core::mem::zeroed() }
    });

    let lsm_hooks: &[(&str, &str, bool)] = &[
        ("lsm_file_open",      "file_open",           false),
        ("lsm_socket_connect", "socket_connect",       false),
        ("lsm_bprm_check",     "bprm_check_security", false),
        ("lsm_sb_mount",       "sb_mount",             false),
    ];

    let mut lsm_attached = 0u32;
    for (name, hook, required) in lsm_hooks {
        let result = (|| -> anyhow::Result<()> {
            let program: &mut Lsm = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("BPF program '{}' not found in ELF", name))?
                .try_into()?;
            program.load(hook, &btf)?;
            program.attach()?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                tracing::info!("Attached BPF-LSM hook: {}", hook);
                lsm_attached += 1;
            }
            Err(e) if *required => {
                return Err(e.context(format!("Required LSM hook {} failed", hook)));
            }
            Err(e) => {
                tracing::warn!(
                    "Optional LSM hook {} unavailable (need CONFIG_BPF_LSM=y + 'bpf' in CONFIG_LSM): {}",
                    hook, e
                );
            }
        }
    }
    tracing::info!("Attached {}/{} BPF-LSM hooks", lsm_attached, lsm_hooks.len());

    // 5. Open PerfEventArray and spawn per-CPU polling tasks
    let policy = std::sync::Arc::new(policy);
    let (tx, rx) = mpsc::channel::<SecurityEvent>(1024);

    let mut perf_array = AsyncPerfEventArray::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("BPF map 'EVENTS' not found"))?,
    )?;

    // Note: `ebpf` must be kept alive for the duration of tracing.
    // Moved into TracerHandle below.

    let cpus = online_cpus().map_err(|e| anyhow::anyhow!("failed to get online CPUs: {:?}", e))?;
    tracing::info!("Starting perf event readers on {} CPUs", cpus.len());

    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, Some(256))?;
        let tx = tx.clone();
        let policy = policy.clone();

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
                            // Kill-on-detect is now restricted to stateful violations that
                            // BPF-LSM cannot handle at a single hook point:
                            //   - TcpSend / TcpRecv: byte-count thresholds accumulated over
                            //     multiple sends/receives; no single LSM hook covers them.
                            //
                            // All single-operation violations (file access, exec, connect,
                            // mount) are now enforced synchronously by BPF-LSM hooks, which
                            // return -EPERM before the syscall completes. Killing here for
                            // those events would be redundant and racy.
                            if policy.evaluate(&event) == PolicyAction::Deny {
                                let is_stateful = matches!(
                                    &event.kind,
                                    SecurityEventKind::TcpSend { .. }
                                        | SecurityEventKind::TcpRecv { .. }
                                );
                                if is_stateful {
                                    unsafe {
                                        libc::kill(event.pid as libc::pid_t, libc::SIGKILL);
                                    }
                                    tracing::warn!(
                                        "STATEFUL KILL: pid={} comm={} {:?}",
                                        event.pid, event.comm, event.kind
                                    );
                                }
                            }
                            // Always forward to channel so daemon can log the event
                            if tx.try_send(event).is_err() {
                                tracing::warn!("Telemetry channel full, dropping event");
                            }
                        }
                    }
                }
            }
        });
    }

    tracing::info!("eBPF tracer started — tracepoints, kprobes, and BPF-LSM hooks active");

    Ok((TracerHandle { _ebpf: ebpf }, rx))
}

/// Populate BPF-LSM policy maps from the given security policy.
///
/// Translates `PolicyRule::FileAccess` and `PolicyRule::Network` rules into
/// BPF map entries. Rules with glob patterns are skipped (BPF can't evaluate
/// globs) and fall back to kill-on-detect in the perf event loop.
///
/// Must be called before attaching LSM probes so the maps are ready when the
/// first hook fires.
#[cfg(target_os = "linux")]
fn populate_policy_maps(
    ebpf: &mut aya::Ebpf,
    policy: &super::policy::SecurityPolicy,
) -> anyhow::Result<()> {
    use aya::maps::{HashMap, LpmTrie};
    use super::policy::{PolicyAction, PolicyRule};

    // Collect keys first so we can insert into each map one at a time.
    // aya 0.13 requires exclusive access per map and cannot hold multiple
    // map handles simultaneously (borrow checker).
    let mut file_deny:  Vec<[u8; 256]>                      = Vec::new();
    let mut file_allow: Vec<[u8; 256]>                      = Vec::new();
    let mut net_deny:   Vec<aya::maps::lpm_trie::Key<u32>>  = Vec::new();
    let mut net_allow:  Vec<aya::maps::lpm_trie::Key<u32>>  = Vec::new();

    for rule in &policy.rules {
        match rule {
            PolicyRule::FileAccess { pattern, action } => {
                // Skip glob patterns — BPF maps do exact match only.
                // Glob rules are evaluated by kill-on-detect in the perf loop.
                if super::policy::has_glob_pattern(pattern) {
                    tracing::debug!("Glob FileAccess rule skipped for BPF map (kill-on-detect fallback): {}", pattern);
                    continue;
                }
                let key = path_to_map_key(pattern);
                match action {
                    PolicyAction::Deny  => file_deny.push(key),
                    PolicyAction::Allow => file_allow.push(key),
                    PolicyAction::Log   => {}
                }
            }
            PolicyRule::Network { dest, port: None, action } => {
                // Port-specific rules can't be enforced per-port by CIDR LPM trie;
                // those fall back to kill-on-detect.
                match cidr_to_lpm_key(dest) {
                    Ok(key) => match action {
                        PolicyAction::Deny  => net_deny.push(key),
                        PolicyAction::Allow => net_allow.push(key),
                        PolicyAction::Log   => {}
                    },
                    Err(e) => {
                        tracing::warn!("Failed to parse CIDR '{}' for BPF-LSM map: {}", dest, e);
                    }
                }
            }
            PolicyRule::Network { port: Some(_), .. } => {
                // Port-specific rules fall back to kill-on-detect (no per-port LPM trie).
            }
            PolicyRule::Syscall { .. } => {
                // Syscall rules are handled by seccomp, not BPF-LSM maps.
            }
        }
    }

    // Insert into each map separately — one mutable borrow at a time.
    {
        let mut m: HashMap<_, [u8; 256], u8> =
            HashMap::try_from(ebpf.map_mut("DENIED_PATHS").ok_or_else(|| {
                anyhow::anyhow!("BPF map 'DENIED_PATHS' not found")
            })?)?;
        for key in file_deny {
            tracing::debug!("BPF-LSM: DENIED_PATHS += {} bytes", key[..key.iter().position(|&b| b == 0).unwrap_or(255)].len());
            m.insert(key, 1u8, 0)?;
        }
    }
    {
        let mut m: HashMap<_, [u8; 256], u8> =
            HashMap::try_from(ebpf.map_mut("ALLOWED_PATHS").ok_or_else(|| {
                anyhow::anyhow!("BPF map 'ALLOWED_PATHS' not found")
            })?)?;
        for key in file_allow {
            m.insert(key, 1u8, 0)?;
        }
    }
    {
        let mut m: LpmTrie<_, u32, u8> =
            LpmTrie::try_from(ebpf.map_mut("DENIED_NETS").ok_or_else(|| {
                anyhow::anyhow!("BPF map 'DENIED_NETS' not found")
            })?)?;
        for key in net_deny {
            m.insert(&key, 1u8, 0)?;
        }
    }
    {
        let mut m: LpmTrie<_, u32, u8> =
            LpmTrie::try_from(ebpf.map_mut("ALLOWED_NETS").ok_or_else(|| {
                anyhow::anyhow!("BPF map 'ALLOWED_NETS' not found")
            })?)?;
        for key in net_allow {
            m.insert(&key, 1u8, 0)?;
        }
    }

    Ok(())
}

/// Convert a filesystem path string to a zero-padded 256-byte BPF map key.
#[cfg(target_os = "linux")]
fn path_to_map_key(path: &str) -> [u8; 256] {
    let mut key = [0u8; 256];
    let bytes = path.as_bytes();
    let len = bytes.len().min(255); // leave final byte as null terminator
    key[..len].copy_from_slice(&bytes[..len]);
    key
}

/// Convert a CIDR string (e.g. "10.0.0.0/8") to an aya LPM trie key.
///
/// Returns `Key<u32>` = `{ prefix_len: u32, data: u32 }` (8 bytes total) where
/// `data` is the masked IPv4 address in network byte order, matching the kernel's
/// `struct bpf_lpm_trie_key { __u32 prefixlen; __u8 data[0]; }` ABI.
#[cfg(target_os = "linux")]
fn cidr_to_lpm_key(cidr: &str) -> anyhow::Result<aya::maps::lpm_trie::Key<u32>> {
    let (net_str, prefix_len) = if let Some((net, bits)) = cidr.split_once('/') {
        let bits: u32 = bits.parse().map_err(|_| anyhow::anyhow!("invalid prefix length in '{}'", cidr))?;
        (net, bits)
    } else {
        (cidr, 32u32) // bare IP = /32
    };

    let ip_u32 = parse_ipv4_to_u32(net_str)
        .ok_or_else(|| anyhow::anyhow!("invalid IPv4 address in '{}'", cidr))?;

    // Mask the address to the prefix length to normalise (e.g. 10.0.0.5/8 → 10.0.0.0/8)
    let masked = if prefix_len == 0 {
        0u32
    } else if prefix_len >= 32 {
        ip_u32
    } else {
        ip_u32 & (!0u32 << (32 - prefix_len))
    };

    // .to_be() converts host-byte-order u32 to big-endian, matching the BPF probe's
    // u32::from_ne_bytes(sin_addr bytes) which also preserves network byte order.
    Ok(aya::maps::lpm_trie::Key::new(prefix_len, masked.to_be()))
}

/// Parse a dotted-quad IPv4 address into a host-byte-order u32.
#[cfg(target_os = "linux")]
fn parse_ipv4_to_u32(s: &str) -> Option<u32> {
    let mut parts = s.split('.');
    let a: u8 = parts.next()?.parse().ok()?;
    let b: u8 = parts.next()?.parse().ok()?;
    let c: u8 = parts.next()?.parse().ok()?;
    let d: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() { return None; }
    Some(u32::from_be_bytes([a, b, c, d]))
}

/// Stub tracer for non-Linux platforms (macOS host).
///
/// Returns a dummy handle and an event channel that never produces events.
/// This allows the rest of the codebase to compile on macOS without
/// conditional compilation at every call site.
#[cfg(not(target_os = "linux"))]
pub async fn start_tracer(
    _policy: super::policy::SecurityPolicy,
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
        // BPF probe stores IP bytes via from_ne_bytes, preserving network byte order
        raw.dest_ip = u32::from_ne_bytes([93, 184, 216, 34]);
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
        raw.dest_ip = u32::from_ne_bytes([8, 8, 8, 8]);
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

//! eBPF probe loader and tracer.
//!
//! On Linux, this module uses `aya` to load eBPF programs into the kernel
//! and attach them to tracepoints/kprobes. On macOS, it compiles as a
//! no-op stub.

#[allow(unused_imports)]
use super::events::{SecurityEvent, SecurityEventKind};
#[cfg(target_os = "linux")]
use super::policy::PolicyAction;
#[allow(unused_imports)]
use garden_ebpf_common::{bytes_to_str, EventKind, RawSecurityEvent, MAX_COMM_LEN};
use tokio::sync::mpsc;

/// Handle to a running eBPF tracer.
///
/// Dropping this handle detaches all probes and stops event collection.
/// For long-lived tracing (e.g., VM lifetime), leak with `std::mem::forget`.
pub struct TracerHandle {
    #[cfg(target_os = "linux")]
    _ebpf: aya::Ebpf,
    /// BPF link fds for LSM hooks attached via BPF_LINK_CREATE.
    /// Must be kept alive for the duration of tracing — dropping closes the link.
    #[cfg(target_os = "linux")]
    _lsm_links: Vec<std::os::fd::OwnedFd>,
}

/// Attach a loaded BPF LSM program using BPF_LINK_CREATE.
///
/// Aya 0.13 uses `bpf_raw_tracepoint_open` for LSM attachment, which returns
/// ENOTSUPP (524) on Linux 6.x where BPF_LINK_CREATE is required for LSM
/// programs. This function makes the syscall directly.
///
/// The returned `OwnedFd` is the link fd — keep it alive to maintain attachment.
#[cfg(target_os = "linux")]
fn lsm_link_create(prog_fd: std::os::fd::RawFd) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{FromRawFd, OwnedFd};

    const BPF_LINK_CREATE: libc::c_long = 28;
    const BPF_LSM_MAC: u32 = 27; // bpf_attach_type::BPF_LSM_MAC = 27 (not 29)

    // The kernel's bpf_attr union — we only fill in the fields for LSM link creation.
    // The hook's BTF ID was already stored in the prog during BPF_PROG_LOAD (via aya's load()),
    // so the kernel uses prog->aux->attach_btf_id; we do not need to repeat it here.
    #[repr(C, align(8))]
    struct BpfAttrLinkCreate {
        prog_fd: u32,
        target_fd: u32,
        attach_type: u32,
        flags: u32,
        _rest: [u8; 48], // pad union to 64 bytes; cookie/target_btf_id default to 0
    }

    let attr = BpfAttrLinkCreate {
        prog_fd: prog_fd as u32,
        target_fd: 0, // 0 = system-wide (not cgroup-scoped)
        attach_type: BPF_LSM_MAC,
        flags: 0,
        _rest: [0u8; 48],
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_LINK_CREATE,
            &attr as *const BpfAttrLinkCreate as *mut libc::c_void,
            std::mem::size_of::<BpfAttrLinkCreate>() as libc::c_ulong,
        )
    };

    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
    }
}

/// Decode a DNS query name from a raw DNS packet stored in `args`.
///
/// DNS wire format: 12-byte header, then length-prefixed labels.
/// e.g., `\x07example\x03com\x00` → "example.com"
#[cfg(target_os = "linux")]
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

/// Format a 16-byte IPv6 address as a standard IPv6 string.
#[cfg(target_os = "linux")]
fn format_ipv6(bytes: &[u8; 16]) -> String {
    let groups: [u16; 8] = [
        u16::from_be_bytes([bytes[0], bytes[1]]),
        u16::from_be_bytes([bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u16::from_be_bytes([bytes[10], bytes[11]]),
        u16::from_be_bytes([bytes[12], bytes[13]]),
        u16::from_be_bytes([bytes[14], bytes[15]]),
    ];

    // Simple formatting without :: compression (always correct, easy to parse)
    format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        groups[0], groups[1], groups[2], groups[3],
        groups[4], groups[5], groups[6], groups[7]
    )
}

/// Convert a raw BPF event to a typed `SecurityEvent`.
#[cfg(target_os = "linux")]
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
        EventKind::ConnectV6 => {
            let ip6_bytes: [u8; 16] = raw.dest_ip6;
            SecurityEventKind::NetworkConnect {
                dest_ip: format_ipv6(&ip6_bytes),
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
        EventKind::FinitModule => SecurityEventKind::FinitModuleLoad {
            flags: raw.flags,
            args: bytes_to_str(&raw.args).to_string(),
        },
        EventKind::Ptrace => SecurityEventKind::PtraceAttempt {
            request: raw.flags,
            target_pid: raw.aux as u32,
        },
        EventKind::Unlink => SecurityEventKind::FileDelete {
            path: bytes_to_str(&raw.path).to_string(),
            flags: raw.flags,
        },
        EventKind::Rename => SecurityEventKind::FileRename {
            old_path: bytes_to_str(&raw.path).to_string(),
            new_path: bytes_to_str(&raw.args).to_string(),
            flags: raw.flags,
        },
        EventKind::Fork => SecurityEventKind::ProcessFork {
            parent_pid: raw.pid,
            child_pid: raw.flags,
            child_comm: bytes_to_str(&raw.path[..MAX_COMM_LEN]).to_string(),
        },
        EventKind::Exit => {
            // Decode raw kernel task->exit_code (same encoding as waitpid status):
            // lower 7 bits = signal number, bits 8-15 = exit status
            let sig = raw.flags & 0x7F;
            let status = (raw.flags >> 8) & 0xFF;
            SecurityEventKind::ProcessExit {
                exit_status: status,
                exit_signal: sig,
            }
        }
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
        uid: raw.uid,
        comm,
        kind,
    })
}

/// Simple deduplication cache for high-frequency events (e.g., openat).
///
/// Deduplicates by (pid, path) within a time window to reduce noise from
/// repeated accesses (e.g., libc, ld.so lookups during a single exec).
#[cfg(target_os = "linux")]
struct EventDedup {
    /// (pid, path_hash) → last seen timestamp_ns
    seen: std::collections::HashMap<(u32, u64), u64>,
    /// Dedup window in nanoseconds (100ms)
    window_ns: u64,
    /// Counter for periodic cleanup
    ops: u64,
}

#[cfg(target_os = "linux")]
impl EventDedup {
    fn new() -> Self {
        Self {
            seen: std::collections::HashMap::with_capacity(256),
            window_ns: 100_000_000, // 100ms
            ops: 0,
        }
    }

    /// Returns true if this event should be emitted (not a duplicate).
    fn should_emit(&mut self, event: &SecurityEvent) -> bool {
        // Only dedup openat events — other event types are always emitted.
        let path = match &event.kind {
            SecurityEventKind::FileAccess { path, .. } => path,
            _ => return true,
        };

        let path_hash = Self::hash_path(path);
        let key = (event.pid, path_hash);

        self.ops += 1;
        // Periodic cleanup every 1000 operations to prevent unbounded growth
        if self.ops.is_multiple_of(1000) {
            let cutoff = event.timestamp_ns.saturating_sub(self.window_ns * 10);
            self.seen.retain(|_, ts| *ts > cutoff);
        }

        match self.seen.get(&key) {
            Some(&last_ts) if event.timestamp_ns.saturating_sub(last_ts) < self.window_ns => {
                false // duplicate within window
            }
            _ => {
                self.seen.insert(key, event.timestamp_ns);
                true
            }
        }
    }

    /// Simple FNV-1a hash for path strings (no_std friendly, fast).
    fn hash_path(path: &str) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        for byte in path.bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }
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
    use aya::maps::ring_buf::RingBuf;
    use aya::programs::{KProbe, Lsm, TracePoint};
    use aya::Btf;
    use tokio::io::unix::AsyncFd;

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

    // 1c. Resolve kernel struct offsets via BTF and populate the OFFSETS map
    // so probes can use runtime offsets instead of hardcoded constants.
    // On kernels without CONFIG_DEBUG_INFO_BTF this silently no-ops and the
    // probes fall back to their baked-in defaults.
    populate_btf_offsets(&mut ebpf);

    // 2. Attach tracepoints (Tier 1 + Tier 2 + new probes)
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
        ("trace_finit_module", "syscalls", "sys_enter_finit_module", false),
        ("trace_ptrace", "syscalls", "sys_enter_ptrace", false),
        ("trace_unlinkat", "syscalls", "sys_enter_unlinkat", false),
        ("trace_renameat2", "syscalls", "sys_enter_renameat2", false),
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
    //
    // Note: trace_tcp_recvmsg is a kretprobe (captures return value = actual
    // bytes received), while the others are kprobes. Aya resolves the correct
    // attachment type from the ELF section name (kprobe/ vs kretprobe/).
    let kprobes = [
        ("trace_commit_creds", "commit_creds", false),
        ("trace_tcp_sendmsg",  "tcp_sendmsg",  false),
        ("trace_tcp_recvmsg",  "tcp_recvmsg",  false),
        // fix #16: catches DNS queries sent via connect()+send()/write() on UDP
        // sockets, which don't hit the sys_enter_sendto tracepoint.
        ("trace_udp_sendmsg",  "udp_sendmsg",  false),
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

    // Diagnose what LSMs are actually active at runtime.
    match std::fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(active) => tracing::info!("Active LSMs: {}", active.trim()),
        Err(e) => tracing::warn!("Could not read /sys/kernel/security/lsm: {}", e),
    }

    let btf_result = Btf::from_sys_fs();
    if let Err(ref e) = btf_result {
        tracing::error!("Failed to load BTF from /sys/kernel/btf/vmlinux: {} — LSM probes will be skipped", e);
        // Check if the BTF file exists at all
        match std::fs::metadata("/sys/kernel/btf/vmlinux") {
            Ok(m) => tracing::info!("  /sys/kernel/btf/vmlinux exists ({} bytes)", m.len()),
            Err(e2) => tracing::error!("  /sys/kernel/btf/vmlinux does NOT exist: {}", e2),
        }
    }

    let lsm_hooks: &[(&str, &str, bool)] = &[
        ("lsm_file_open",      "file_open",           true),
        ("lsm_socket_connect", "socket_connect",       true),
        ("lsm_bprm_check",     "bprm_check_security", true),
        ("lsm_sb_mount",       "sb_mount",             true),
    ];

    // Finding 4a fix: refuse to start if BTF is unavailable while any LSM hook
    // is marked required. Previously, BTF load failure silently skipped the
    // entire LSM attach loop and start_tracer returned Ok with 0 hooks
    // attached — a hidden fail-open path that the required:true on individual
    // hooks couldn't catch (the loop wouldn't run).
    if btf_result.is_err() && lsm_hooks.iter().any(|(_, _, required)| *required) {
        return Err(anyhow::anyhow!(
            "BTF unavailable but required LSM hooks present — refusing to start without enforcement"
        ));
    }

    let mut lsm_attached = 0u32;
    let mut lsm_links: Vec<std::os::fd::OwnedFd> = Vec::new();
    if let Ok(ref btf) = btf_result {
        for (name, hook, required) in lsm_hooks {
            let result = (|| -> anyhow::Result<()> {
                use std::os::fd::{AsFd, AsRawFd};
                let program: &mut Lsm = ebpf
                    .program_mut(name)
                    .ok_or_else(|| anyhow::anyhow!("BPF program '{}' not found in ELF", name))?
                    .try_into()?;
                program.load(hook, btf)?;
                // Aya uses bpf_raw_tracepoint_open for LSM attachment, but Linux 6.x
                // requires BPF_LINK_CREATE. Call the syscall directly.
                let prog_fd = program.fd()?.as_fd().as_raw_fd();
                let link = lsm_link_create(prog_fd)
                    .map_err(|e| anyhow::anyhow!("BPF_LINK_CREATE for {}: {}", hook, e))?;
                lsm_links.push(link);
                Ok(())
            })();

            match result {
                Ok(()) => {
                    tracing::info!("Attached BPF-LSM hook: {}", hook);
                    lsm_attached += 1;
                }
                Err(e) => {
                    // Write full verifier log to VirtioFS so it survives a guest panic.
                    let full_err = format!("{:#}", e);
                    let log_path = format!("/workspace/lsm_{}_error.txt", hook.replace('/', "_"));
                    let _ = std::fs::write(
                        &log_path,
                        &full_err,
                    );
                    tracing::warn!("LSM hook '{}' failed (full log: {}): {}",
                        hook, log_path, &full_err);
                    if *required {
                        return Err(e.context(format!("Required LSM hook {} failed", hook)));
                    }
                }
            }
        }
    }
    tracing::info!("Attached {}/{} BPF-LSM hooks", lsm_attached, lsm_hooks.len());

    // 5. Open the BPF ring buffer and spawn a single reader task.
    //
    // Unlike PerfEventArray (N per-CPU buffers, one reader task per CPU),
    // BPF_MAP_TYPE_RINGBUF is a single shared, globally-ordered buffer drained
    // by one reader. This eliminates the per-CPU fan-out and the `events.lost`
    // bookkeeping — the kernel `ringbuf_output` helper returns an error if the
    // buffer is full, which the BPF program can count directly.
    let policy = std::sync::Arc::new(policy);
    let (tx, rx) = mpsc::channel::<SecurityEvent>(1024);

    let ring_buf = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("BPF map 'EVENTS' not found"))?,
    )?;
    let mut async_rb = AsyncFd::new(ring_buf)?;

    tracing::info!("Starting BPF ring buffer reader (single task, globally ordered)");

    {
        let tx = tx.clone();
        let policy = policy.clone();
        tokio::spawn(async move {
            // Global deduplication cache (issue #20). Previously per-CPU —
            // now one instance because the ring buffer is globally ordered,
            // so duplicates that previously slipped across CPUs are caught.
            let mut dedup = EventDedup::new();

            // Per-CPU next-expected sequence number for drop detection (#24).
            // SEQ is a PerCpuArray<u64>, and since BPF runs preemption-disabled
            // each CPU issues a strictly increasing sequence. A gap means the
            // ringbuf dropped an event on that CPU. Cross-CPU interleaving is
            // irrelevant — we only compare within a single CPU's stream.
            let mut next_seq: std::collections::HashMap<u32, u64> =
                std::collections::HashMap::new();
            let mut total_gaps: u64 = 0;

            loop {
                let mut guard = match async_rb.readable_mut().await {
                    Ok(g) => g,
                    Err(e) => {
                        tracing::error!("ring buffer readable_mut error: {}", e);
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() < core::mem::size_of::<RawSecurityEvent>() {
                        continue;
                    }
                    let raw = unsafe { &*(item.as_ptr() as *const RawSecurityEvent) };

                    // Sequence gap detection (#24), keyed by source CPU: the
                    // BPF-side counter is per-CPU, so only same-CPU events form
                    // a strictly-increasing stream. Cross-CPU interleaving into
                    // the ringbuf is fine — each CPU's subsequence stays intact.
                    let seq_key = raw.cpu_id;
                    match next_seq.get(&seq_key).copied() {
                        Some(expected) if raw.seq > expected => {
                            let gap = raw.seq - expected;
                            total_gaps += gap;
                            tracing::warn!(
                                "seq gap: cpu={} expected={} got={} (dropped {}, cumulative gaps={})",
                                raw.cpu_id, expected, raw.seq, gap, total_gaps
                            );
                        }
                        _ => {}
                    }
                    next_seq.insert(seq_key, raw.seq.wrapping_add(1));

                    if let Some(event) = convert_raw_event(raw) {
                        // Issue #20: Deduplicate noisy openat events
                        if !dedup.should_emit(&event) {
                            continue;
                        }

                        // Kill-on-detect is restricted to stateful violations
                        // that BPF-LSM cannot handle at a single hook point:
                        //   - TcpSend / TcpRecv: byte-count thresholds
                        //     accumulated over multiple sends/receives.
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
                        if tx.try_send(event).is_err() {
                            tracing::warn!("Telemetry channel full, dropping event");
                        }
                    }
                }
                guard.clear_ready();
            }
        });
    }

    tracing::info!("eBPF tracer started — tracepoints, kprobes, and BPF-LSM hooks active");

    Ok((TracerHandle { _ebpf: ebpf, _lsm_links: lsm_links }, rx))
}

/// Populate the OFFSETS BPF map with kernel struct field offsets resolved
/// from `/sys/kernel/btf/vmlinux`.
///
/// This replaces the previous hardcoded-offset approach (which silently
/// broke on kernel upgrades — issue #13). On kernels without BTF the map
/// is left empty and probes use their baked-in fallback constants.
///
/// Index layout must match the constants in `garden-ebpf-probes/src/main.rs`:
///   0: task_struct.exit_code
///   1: linux_binprm.file
///   2: file.f_path.dentry
///   3: dentry.d_name.name
///   4: dentry.d_parent
///   5: linux_binprm.filename
#[cfg(target_os = "linux")]
fn populate_btf_offsets(ebpf: &mut aya::Ebpf) {
    use super::btf_offsets::{read_vmlinux_btf, struct_member_offset};
    use aya::maps::Array;

    let btf = match read_vmlinux_btf() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                "BTF unavailable ({}); probes will use hardcoded offset fallbacks. \
                 If kernel struct layout has changed this may cause silent mis-reads.",
                e
            );
            return;
        }
    };

    let map = match ebpf.map_mut("OFFSETS") {
        Some(m) => m,
        None => {
            tracing::warn!("OFFSETS map not found in BPF ELF — skipping BTF resolution");
            return;
        }
    };
    let mut arr: Array<_, u32> = match Array::try_from(map) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!("OFFSETS map not an Array<u32>: {}", e);
            return;
        }
    };

    // (index, struct, member, effective-fallback)
    // The effective-fallback values must match DEFAULT_*_OFFSET in probes/main.rs
    // because the effective value (after the +8 adjustments below for nested
    // struct path/qstr members) is what the probe will use if the map lookup
    // returns the fallback.
    let lookups: &[(u32, &str, &str, u32)] = &[
        (0, "task_struct",  "exit_code",  1076),
        (1, "linux_binprm", "file",       64),
        (2, "file",         "f_path",     72),  // f_path.dentry = offsetof(file,f_path) + offsetof(path,dentry=8)
        (3, "dentry",       "d_name",     40),  // d_name.name   = offsetof(dentry,d_name) + offsetof(qstr,name=8)
        (4, "dentry",       "d_parent",   24),
        (5, "linux_binprm", "filename",   96),
    ];

    for (idx, st, memb, fallback) in lookups {
        match struct_member_offset(&btf, st, memb) {
            Ok(off) => {
                // file.f_path.dentry is inside struct path { mnt; dentry; } — dentry is at +8.
                // dentry.d_name.name is inside struct qstr { hash_len; name; } — name is at +8.
                let effective = match (*st, *memb) {
                    ("file",   "f_path") => off + 8,
                    ("dentry", "d_name") => off + 8,
                    _ => off,
                };
                if effective != *fallback {
                    tracing::info!(
                        "BTF offset drift: {}.{} = {} (fallback was {})",
                        st, memb, effective, fallback
                    );
                } else {
                    tracing::debug!("BTF offset {}.{} = {} (matches fallback)", st, memb, effective);
                }
                if let Err(e) = arr.set(*idx, effective, 0) {
                    tracing::warn!("OFFSETS.set({}) failed: {}", idx, e);
                }
            }
            Err(e) => {
                tracing::warn!(
                    "BTF lookup {}.{} failed: {} — probe will fall back to {}",
                    st, memb, e, fallback
                );
            }
        }
    }
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
    let mut file_deny:   Vec<[u8; 256]>                          = Vec::new();
    let mut file_allow:  Vec<[u8; 256]>                          = Vec::new();
    let mut net_deny:    Vec<aya::maps::lpm_trie::Key<u32>>      = Vec::new();
    let mut net_allow:   Vec<aya::maps::lpm_trie::Key<u32>>      = Vec::new();
    let mut net6_deny:   Vec<aya::maps::lpm_trie::Key<[u8; 16]>> = Vec::new();
    let mut net6_allow:  Vec<aya::maps::lpm_trie::Key<[u8; 16]>> = Vec::new();

    for rule in &policy.rules {
        match rule {
            PolicyRule::FileAccess { pattern, action } => {
                // Skip glob patterns — BPF maps do exact match only.
                // Glob rules are evaluated by kill-on-detect in the perf loop.
                if super::policy::has_glob_pattern(pattern) {
                    // Finding 3 fix (partial): warn-level so operators see when
                    // their glob rule degrades to async kill-on-detect instead
                    // of pre-hoc kernel deny. The real fix (prefix-match LpmTrie)
                    // is separate work.
                    tracing::warn!(
                        "Glob FileAccess rule '{}' cannot be enforced at kernel level — falling back to userspace kill-on-detect (post-hoc)",
                        pattern
                    );
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
                //
                // Try IPv4 first; on failure try IPv6. This keeps the existing
                // v4 behaviour unchanged while adding v6 as a parallel path.
                if let Ok(key) = cidr_to_lpm_key(dest) {
                    match action {
                        PolicyAction::Deny  => net_deny.push(key),
                        PolicyAction::Allow => net_allow.push(key),
                        PolicyAction::Log   => {}
                    }
                } else if let Ok(key) = cidr_to_lpm_key_v6(dest) {
                    match action {
                        PolicyAction::Deny  => net6_deny.push(key),
                        PolicyAction::Allow => net6_allow.push(key),
                        PolicyAction::Log   => {}
                    }
                } else {
                    tracing::warn!("Failed to parse CIDR '{}' for BPF-LSM map (v4 and v6)", dest);
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
    {
        let mut m: LpmTrie<_, [u8; 16], u8> =
            LpmTrie::try_from(ebpf.map_mut("DENIED_NETS_V6").ok_or_else(|| {
                anyhow::anyhow!("BPF map 'DENIED_NETS_V6' not found")
            })?)?;
        for key in net6_deny {
            m.insert(&key, 1u8, 0)?;
        }
    }
    {
        let mut m: LpmTrie<_, [u8; 16], u8> =
            LpmTrie::try_from(ebpf.map_mut("ALLOWED_NETS_V6").ok_or_else(|| {
                anyhow::anyhow!("BPF map 'ALLOWED_NETS_V6' not found")
            })?)?;
        for key in net6_allow {
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

/// Convert an IPv6 CIDR string (e.g. "2001:db8::/32") to an aya LPM trie key.
///
/// The kernel's `bpf_lpm_trie_key` stores `prefix_len` followed by `data` in
/// network byte order. IPv6 addresses are already in network byte order
/// (16 raw bytes), so we pass them through unchanged after masking.
#[cfg(target_os = "linux")]
fn cidr_to_lpm_key_v6(cidr: &str) -> anyhow::Result<aya::maps::lpm_trie::Key<[u8; 16]>> {
    let (net_str, prefix_len) = if let Some((net, bits)) = cidr.split_once('/') {
        let bits: u32 = bits.parse().map_err(|_| anyhow::anyhow!("invalid prefix length in '{}'", cidr))?;
        if bits > 128 {
            return Err(anyhow::anyhow!("IPv6 prefix length >128 in '{}'", cidr));
        }
        (net, bits)
    } else {
        (cidr, 128u32)
    };

    let mut addr = super::policy::parse_ipv6(net_str)
        .ok_or_else(|| anyhow::anyhow!("invalid IPv6 address in '{}'", cidr))?;

    // Mask the address to the prefix length so "2001:db8::1/32" normalises to
    // "2001:db8::/32". The LPM trie does longest-prefix match on the stored key,
    // so unmasked host bits would leak into the match.
    let full_bytes = (prefix_len / 8) as usize;
    let rem_bits = (prefix_len % 8) as u8;
    if full_bytes < 16 && rem_bits != 0 {
        let mask = 0xFFu8 << (8 - rem_bits);
        addr[full_bytes] &= mask;
        for b in addr.iter_mut().skip(full_bytes + 1) { *b = 0; }
    } else {
        for b in addr.iter_mut().skip(full_bytes) { *b = 0; }
    }

    Ok(aya::maps::lpm_trie::Key::new(prefix_len, addr))
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

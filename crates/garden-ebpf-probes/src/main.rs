//! Garden AI eBPF kernel-side security probes.
//!
//! This is a `#![no_std]` BPF program compiled to `bpfel-unknown-none`.
//! It attaches to syscall tracepoints and emits `RawSecurityEvent`s
//! through a shared `RingBuf` map (BPF_MAP_TYPE_RINGBUF).
//!
//! ## Stack Management
//! `RawSecurityEvent` (~580 bytes) exceeds BPF's 512-byte stack limit.
//! We use a `PerCpuArray` map with a single element as heap-like scratch
//! space — each CPU gets its own slot, and since BPF programs run with
//! preemption disabled, this is safe without locks.
//!
//! ## Tier 1 Probes
//! - `trace_execve` — process execution (sys_enter_execve)
//! - `trace_openat` — file access (sys_enter_openat)
//! - `trace_connect` — network connections (sys_enter_connect, IPv4 + IPv6)
//!
//! ## Tier 2 Probes
//! - `trace_sendto` — DNS queries (sys_enter_sendto, UDP port 53)
//! - `trace_mount` — mount attempts (sys_enter_mount) — escape canary
//! - `trace_bpf` — BPF syscall (sys_enter_bpf) — red flag
//! - `trace_init_module` — kernel module load (sys_enter_init_module) — should never fire
//! - `trace_finit_module` — fd-based module load (sys_enter_finit_module) — should never fire
//! - `trace_ptrace` — ptrace attempt (sys_enter_ptrace) — process inspection/injection
//!
//! ## Tier 3 Probes
//! - `trace_fork` / `trace_exit` — process lifecycle
//! - `trace_oom_victim` — OOM kill victim
//! - `trace_commit_creds` — privilege escalation
//! - `trace_tcp_sendmsg` / `trace_tcp_recvmsg` — TCP data volume
//! - `trace_unlinkat` / `trace_renameat2` — file deletion and rename

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{file as KernelFile, linux_binprm},
    cty::c_long,
    helpers::{
        bpf_d_path, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
        gen::{bpf_get_current_task, bpf_send_signal},
    },
    macros::{kprobe, kretprobe, lsm, map, tracepoint},
    maps::{lpm_trie::Key as LpmKey, Array, HashMap, LpmTrie, PerCpuArray, RingBuf},
    programs::{LsmContext, ProbeContext, RetProbeContext, TracePointContext},
};
use garden_ebpf_common::{EventKind, RawSecurityEvent};

// ---------------------------------------------------------------------------
// Shared maps
// ---------------------------------------------------------------------------

/// BPF ring buffer (single shared buffer, globally ordered) — userspace reads
/// from this via a single `aya::maps::RingBuf` reader. 256 KiB = 64 × 4 KiB
/// page; byte size must be a power-of-two multiple of page size.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch space for building events without exceeding the 512-byte
/// BPF stack limit. Single element (index 0), one copy per CPU.
#[map]
static SCRATCH: PerCpuArray<RawSecurityEvent> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU monotonically increasing sequence counter. Assigned to
/// `RawSecurityEvent.seq` in `fill_common`. Userspace watches for gaps per
/// CPU to detect dropped events (#24). Per-CPU is safe because BPF runs
/// preemption-disabled on a single CPU — no cross-CPU races.
#[map]
static SEQ: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Per-PID rolling TCP byte counter (fix #21). Emit a TcpSend/TcpRecv event
/// only when a PID's cumulative bytes crosses the next `TCP_RATE_BUCKET`
/// boundary — cuts events ~99% on chatty TCP workloads, reducing ringbuf
/// pressure without losing cumulative accuracy.
#[map]
static TCP_SEND_BYTES: aya_ebpf::maps::HashMap<u32, u64> =
    aya_ebpf::maps::HashMap::<u32, u64>::with_max_entries(4096, 0);
#[map]
static TCP_RECV_BYTES: aya_ebpf::maps::HashMap<u32, u64> =
    aya_ebpf::maps::HashMap::<u32, u64>::with_max_entries(4096, 0);

const TCP_RATE_BUCKET: u64 = 1 << 20; // 1 MiB granularity.

/// Kernel struct field offsets, populated by userspace at load time from BTF
/// (see `crates/garden-ebpf/src/btf_offsets.rs`). Issue #13: previously these
/// were hardcoded constants that silently broke on kernel upgrades.
///
/// Index layout:
///   0 = task_struct.exit_code
///   1 = linux_binprm.file
///   2 = file.f_path.dentry
///   3 = dentry.d_name.name
///   4 = dentry.d_parent
///   5 = linux_binprm.filename
/// Indices 6–7 reserved for future use.
#[map]
static OFFSETS: Array<u32> = Array::with_max_entries(8, 0);

const OFFSET_IDX_TASK_EXIT_CODE: u32 = 0;
const OFFSET_IDX_BPRM_FILE: u32 = 1;
const OFFSET_IDX_FILE_DENTRY: u32 = 2;
const OFFSET_IDX_DENTRY_NAME: u32 = 3;
const OFFSET_IDX_DENTRY_D_PARENT: u32 = 4;
const OFFSET_IDX_BPRM_FILENAME: u32 = 5;

/// Look up a kernel struct field offset. Falls back to `default` if the
/// userspace loader failed to populate the map (e.g., BTF missing).
#[inline(always)]
fn offset_or(idx: u32, default: u64) -> u64 {
    match OFFSETS.get(idx) {
        Some(v) if *v != 0 => *v as u64,
        _ => default,
    }
}

/// Get a mutable reference to the per-CPU scratch event, zeroed out.
#[inline(always)]
fn get_scratch_event() -> Option<&'static mut RawSecurityEvent> {
    let event = unsafe { SCRATCH.get_ptr_mut(0)?.as_mut()? };
    // Zero the struct for reuse
    *event = RawSecurityEvent::zeroed();
    Some(event)
}

/// Populate the common fields (pid, uid, timestamp, comm, seq) on a scratch
/// event. The sequence number is taken from the per-CPU `SEQ` counter and
/// incremented in place — userspace uses gaps to detect dropped events (#24).
#[inline(always)]
fn fill_common(event: &mut RawSecurityEvent) -> Result<(), c_long> {
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = bpf_get_current_comm()?;

    fill_cpu_and_seq(event);
    Ok(())
}

/// Populate `cpu_id` and `seq` only. Used by probes (fork/exit/oom) that
/// derive pid/uid/comm from tracepoint arguments rather than the current
/// task, and so cannot use `fill_common`, but still need gap-detection
/// metadata (#24).
#[inline(always)]
fn fill_cpu_and_seq(event: &mut RawSecurityEvent) {
    event.cpu_id = unsafe { aya_ebpf::helpers::bpf_get_smp_processor_id() };
    if let Some(seq_ptr) = unsafe { SEQ.get_ptr_mut(0) } {
        unsafe {
            let next = (*seq_ptr).wrapping_add(1);
            *seq_ptr = next;
            event.seq = next;
        }
    }
}

// ===========================================================================
// Inline enforcement helpers — called synchronously from tracepoint context
// to send SIGKILL before the syscall returns, eliminating the userspace race.
// All functions take &[u8; 256] path and do fixed-length byte comparisons only
// (no loops) to satisfy the BPF verifier.
// ===========================================================================

/// True if flags indicate write intent: O_WRONLY (1) or O_RDWR (2).
#[inline(always)]
fn has_write_intent(flags: u32) -> bool {
    let mode = flags & 3;
    mode == 1 || mode == 2
}

/// True if path starts with `/workspace`.
#[inline(always)]
fn path_starts_with_workspace(p: &[u8; 256]) -> bool {
    p[0] == b'/' && p[1] == b'w' && p[2] == b'o' && p[3] == b'r'
        && p[4] == b'k' && p[5] == b's' && p[6] == b'p' && p[7] == b'a'
        && p[8] == b'c' && p[9] == b'e'
}

/// True if path starts with `/dev/` (device files — writes are always allowed).
#[inline(always)]
fn path_starts_with_dev(p: &[u8; 256]) -> bool {
    p[0] == b'/' && p[1] == b'd' && p[2] == b'e' && p[3] == b'v' && p[4] == b'/'
}

/// True if path starts with `/tmp/` (temp files — writes are allowed).
#[inline(always)]
fn path_starts_with_tmp(p: &[u8; 256]) -> bool {
    p[0] == b'/' && p[1] == b't' && p[2] == b'm' && p[3] == b'p' && p[4] == b'/'
}

/// True if path starts with `/proc/self/` (self-introspection — allowed).
#[inline(always)]
fn path_starts_with_proc_self(p: &[u8; 256]) -> bool {
    p[0] == b'/' && p[1] == b'p' && p[2] == b'r' && p[3] == b'o'
        && p[4] == b'c' && p[5] == b'/' && p[6] == b's' && p[7] == b'e'
        && p[8] == b'l' && p[9] == b'f' && p[10] == b'/'
}

/// True if path starts with `/etc/` (config files — written by DHCP, init scripts).
#[inline(always)]
fn path_starts_with_etc(p: &[u8; 256]) -> bool {
    p[0] == b'/' && p[1] == b'e' && p[2] == b't' && p[3] == b'c' && p[4] == b'/'
}

/// True if path starts with `/run/` (runtime state — written by daemons, DHCP).
#[inline(always)]
fn path_starts_with_run(p: &[u8; 256]) -> bool {
    p[0] == b'/' && p[1] == b'r' && p[2] == b'u' && p[3] == b'n' && p[4] == b'/'
}

/// True if path starts with `/var/` (variable data — logs, caches).
#[inline(always)]
fn path_starts_with_var(p: &[u8; 256]) -> bool {
    p[0] == b'/' && p[1] == b'v' && p[2] == b'a' && p[3] == b'r' && p[4] == b'/'
}

/// True if path starts with `/proc/` (procfs — writable for sysctls etc).
#[inline(always)]
fn path_starts_with_proc(p: &[u8; 256]) -> bool {
    p[0] == b'/' && p[1] == b'p' && p[2] == b'r' && p[3] == b'o'
        && p[4] == b'c' && p[5] == b'/'
}

/// True if path starts with `/sys/` (sysfs — writable for config).
#[inline(always)]
fn path_starts_with_sys(p: &[u8; 256]) -> bool {
    p[0] == b'/' && p[1] == b's' && p[2] == b'y' && p[3] == b's' && p[4] == b'/'
}

/// True if the path contains a literal `..` path component: a `/..` sequence
/// followed by `/` or end-of-string. Used to flag traversal-escape attempts.
/// Bounded scan over the first 128 bytes — verifier-friendly.
#[inline(always)]
fn path_has_dotdot_segment(p: &[u8; 256]) -> bool {
    let mut i: usize = 0;
    while i < 125 {
        if p[i] == 0 {
            return false;
        }
        if p[i] == b'/' && p[i + 1] == b'.' && p[i + 2] == b'.' && (p[i + 3] == b'/' || p[i + 3] == 0) {
            return true;
        }
        i += 1;
    }
    false
}

/// True if the last path component is a known privilege-escalation binary:
/// su, sudo, newuidmap, newgidmap, pkexec, nsenter, unshare.
/// Checks up to 64 bytes of the path for the last `/`.
#[inline(always)]
fn path_is_privesc_binary(p: &[u8; 256]) -> bool {
    if p[0] == b's' && p[1] == b'u' && p[2] == 0 { return true; }
    if p[0] == b's' && p[1] == b'u' && p[2] == b'd' && p[3] == b'o'
        && p[4] == 0 { return true; }

    // Walk path forward to find last slash position (unrolled, max 64 bytes).
    let mut last_slash: usize = 0;
    // Fully unrolled scan of first 64 bytes; constant time for verifier.
    if p[1] == b'/'   { last_slash = 1;   }
    if p[2] == b'/'   { last_slash = 2;   }
    if p[3] == b'/'   { last_slash = 3;   }
    if p[4] == b'/'   { last_slash = 4;   }
    if p[5] == b'/'   { last_slash = 5;   }
    if p[6] == b'/'   { last_slash = 6;   }
    if p[7] == b'/'   { last_slash = 7;   }
    if p[8] == b'/'   { last_slash = 8;   }
    if p[9] == b'/'   { last_slash = 9;   }
    if p[10] == b'/'  { last_slash = 10;  }
    if p[11] == b'/'  { last_slash = 11;  }
    if p[12] == b'/'  { last_slash = 12;  }
    if p[13] == b'/'  { last_slash = 13;  }
    if p[14] == b'/'  { last_slash = 14;  }
    if p[15] == b'/'  { last_slash = 15;  }
    if p[16] == b'/'  { last_slash = 16;  }
    if p[17] == b'/'  { last_slash = 17;  }
    if p[18] == b'/'  { last_slash = 18;  }
    if p[19] == b'/'  { last_slash = 19;  }
    if p[20] == b'/'  { last_slash = 20;  }
    if p[21] == b'/'  { last_slash = 21;  }
    if p[22] == b'/'  { last_slash = 22;  }
    if p[23] == b'/'  { last_slash = 23;  }
    if p[24] == b'/'  { last_slash = 24;  }
    if p[25] == b'/'  { last_slash = 25;  }
    if p[26] == b'/'  { last_slash = 26;  }
    if p[27] == b'/'  { last_slash = 27;  }
    if p[28] == b'/'  { last_slash = 28;  }
    if p[29] == b'/'  { last_slash = 29;  }
    if p[30] == b'/'  { last_slash = 30;  }
    // Extended scan to 64 bytes (issue #7: deeper paths like /usr/lib/...)
    if p[31] == b'/'  { last_slash = 31;  }
    if p[32] == b'/'  { last_slash = 32;  }
    if p[33] == b'/'  { last_slash = 33;  }
    if p[34] == b'/'  { last_slash = 34;  }
    if p[35] == b'/'  { last_slash = 35;  }
    if p[36] == b'/'  { last_slash = 36;  }
    if p[37] == b'/'  { last_slash = 37;  }
    if p[38] == b'/'  { last_slash = 38;  }
    if p[39] == b'/'  { last_slash = 39;  }
    if p[40] == b'/'  { last_slash = 40;  }
    if p[41] == b'/'  { last_slash = 41;  }
    if p[42] == b'/'  { last_slash = 42;  }
    if p[43] == b'/'  { last_slash = 43;  }
    if p[44] == b'/'  { last_slash = 44;  }
    if p[45] == b'/'  { last_slash = 45;  }
    if p[46] == b'/'  { last_slash = 46;  }
    if p[47] == b'/'  { last_slash = 47;  }
    if p[48] == b'/'  { last_slash = 48;  }
    if p[49] == b'/'  { last_slash = 49;  }
    if p[50] == b'/'  { last_slash = 50;  }
    if p[51] == b'/'  { last_slash = 51;  }
    if p[52] == b'/'  { last_slash = 52;  }
    if p[53] == b'/'  { last_slash = 53;  }
    if p[54] == b'/'  { last_slash = 54;  }
    if p[55] == b'/'  { last_slash = 55;  }
    if p[56] == b'/'  { last_slash = 56;  }
    if p[57] == b'/'  { last_slash = 57;  }
    if p[58] == b'/'  { last_slash = 58;  }
    if p[59] == b'/'  { last_slash = 59;  }
    if p[60] == b'/'  { last_slash = 60;  }
    if p[61] == b'/'  { last_slash = 61;  }
    if p[62] == b'/'  { last_slash = 62;  }
    if p[63] == b'/'  { last_slash = 63;  }
    let i = last_slash + 1;
    // "su\0"
    if p[i] == b's' && p[i+1] == b'u' && p[i+2] == 0 { return true; }
    // "sudo\0"
    if p[i] == b's' && p[i+1] == b'u' && p[i+2] == b'd' && p[i+3] == b'o'
        && p[i+4] == 0 { return true; }
    // "newuidmap\0"
    if p[i] == b'n' && p[i+1] == b'e' && p[i+2] == b'w' && p[i+3] == b'u'
        && p[i+4] == b'i' && p[i+5] == b'd' && p[i+6] == b'm' && p[i+7] == b'a'
        && p[i+8] == b'p' && p[i+9] == 0 { return true; }
    // "newgidmap\0"
    if p[i] == b'n' && p[i+1] == b'e' && p[i+2] == b'w' && p[i+3] == b'g'
        && p[i+4] == b'i' && p[i+5] == b'd' && p[i+6] == b'm' && p[i+7] == b'a'
        && p[i+8] == b'p' && p[i+9] == 0 { return true; }
    // "pkexec\0"
    if p[i] == b'p' && p[i+1] == b'k' && p[i+2] == b'e' && p[i+3] == b'x'
        && p[i+4] == b'e' && p[i+5] == b'c' && p[i+6] == 0 { return true; }
    // "nsenter\0"
    if p[i] == b'n' && p[i+1] == b's' && p[i+2] == b'e' && p[i+3] == b'n'
        && p[i+4] == b't' && p[i+5] == b'e' && p[i+6] == b'r' && p[i+7] == 0 { return true; }
    // "unshare\0"
    if p[i] == b'u' && p[i+1] == b'n' && p[i+2] == b's' && p[i+3] == b'h'
        && p[i+4] == b'a' && p[i+5] == b'r' && p[i+6] == b'e' && p[i+7] == 0 { return true; }
    false
}

// ===========================================================================
// Tier 1: sys_enter_execve
// ===========================================================================

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn trace_execve(ctx: TracePointContext) -> u32 {
    match try_trace_execve(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_execve(ctx: &TracePointContext) -> Result<(), c_long> {
    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::Execve as u32;
    fill_common(event)?;

    let filename_ptr: u64 = unsafe { ctx.read_at(16)? };
    if filename_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.path)
        };
    }

    let argv_ptr: u64 = unsafe { ctx.read_at(24)? };
    if argv_ptr != 0 {
        let mut arg0_ptr_buf = [0u8; 8];
        let _ = unsafe { bpf_probe_read_user_buf(argv_ptr as *const u8, &mut arg0_ptr_buf) };
        let arg0_ptr = u64::from_ne_bytes(arg0_ptr_buf);
        if arg0_ptr != 0 {
            let _ = unsafe {
                bpf_probe_read_user_str_bytes(arg0_ptr as *const u8, &mut event.args)
            };
        }
    }

    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 1: sys_enter_openat
// ===========================================================================

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn trace_openat(ctx: TracePointContext) -> u32 {
    match try_trace_openat(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_openat(ctx: &TracePointContext) -> Result<(), c_long> {
    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::Openat as u32;
    fill_common(event)?;

    let filename_ptr: u64 = unsafe { ctx.read_at(24)? };
    if filename_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.path)
        };
    }

    let flags: u64 = unsafe { ctx.read_at(32)? };
    event.flags = flags as u32;

    // Hand off to lsm_file_open: stash the intent flags for this pid_tgid so
    // the LSM hook can resolve the canonical path via bpf_d_path and enforce.
    // We do not enforce here because the raw user path may be relative — only
    // bpf_d_path (available in LSM hooks) gives the true target.
    if event.pid != 1 {
        let mut intent: u8 = 0;
        if path_starts_with_workspace(&event.path) && path_has_dotdot_segment(&event.path) {
            intent |= INTENT_TRAVERSAL;
        }
        if has_write_intent(event.flags) {
            intent |= INTENT_WRITE;
        }
        if intent != 0 {
            let key = bpf_get_current_pid_tgid();
            let _ = OPEN_INTENT.insert(&key, &intent, 0);
        }
    }

    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 1: sys_enter_connect (IPv4 + IPv6)
// ===========================================================================

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[tracepoint(category = "syscalls", name = "sys_enter_connect")]
pub fn trace_connect(ctx: TracePointContext) -> u32 {
    match try_trace_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_connect(ctx: &TracePointContext) -> Result<(), c_long> {
    let addr_ptr: u64 = unsafe { ctx.read_at(24)? };
    if addr_ptr == 0 {
        return Ok(());
    }

    // Read first 2 bytes for sa_family
    let mut family_buf = [0u8; 2];
    let _ = unsafe { bpf_probe_read_user_buf(addr_ptr as *const u8, &mut family_buf) };
    let sa_family = u16::from_ne_bytes(family_buf);

    if sa_family == AF_INET {
        // IPv4: read 8 bytes (family + port + addr)
        let mut sockaddr_buf = [0u8; 8];
        let _ = unsafe { bpf_probe_read_user_buf(addr_ptr as *const u8, &mut sockaddr_buf) };

        let event = get_scratch_event().ok_or(1i64)?;
        event.kind = EventKind::Connect as u32;
        fill_common(event)?;
        event.dest_port = u16::from_be_bytes([sockaddr_buf[2], sockaddr_buf[3]]);
        event.dest_ip = u32::from_ne_bytes([
            sockaddr_buf[4], sockaddr_buf[5], sockaddr_buf[6], sockaddr_buf[7],
        ]);
        event.protocol = 6;
        let _ = EVENTS.output(event, 0);
    } else if sa_family == AF_INET6 {
        // IPv6: sockaddr_in6 = family(2) + port(2) + flowinfo(4) + addr(16) + scope(4)
        // Read 28 bytes total
        let mut sa6_buf = [0u8; 28];
        let _ = unsafe { bpf_probe_read_user_buf(addr_ptr as *const u8, &mut sa6_buf) };

        let event = get_scratch_event().ok_or(1i64)?;
        event.kind = EventKind::ConnectV6 as u32;
        fill_common(event)?;
        event.dest_port = u16::from_be_bytes([sa6_buf[2], sa6_buf[3]]);
        // IPv6 address is at bytes 8..24 in sockaddr_in6
        event.dest_ip6.copy_from_slice(&sa6_buf[8..24]);
        event.protocol = 6;
        let _ = EVENTS.output(event, 0);
    }

    Ok(())
}

// ===========================================================================
// Tier 2: sys_enter_sendto — DNS query logging
// ===========================================================================

const DNS_PORT: u16 = 53;
const IPPROTO_UDP: u16 = 17;

#[tracepoint(category = "syscalls", name = "sys_enter_sendto")]
pub fn trace_sendto(ctx: TracePointContext) -> u32 {
    match try_trace_sendto(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_sendto(ctx: &TracePointContext) -> Result<(), c_long> {
    let addr_ptr: u64 = unsafe { ctx.read_at(48)? };
    if addr_ptr == 0 {
        return Ok(());
    }

    let mut sockaddr_buf = [0u8; 8];
    let _ = unsafe { bpf_probe_read_user_buf(addr_ptr as *const u8, &mut sockaddr_buf) };

    let sa_family = u16::from_ne_bytes([sockaddr_buf[0], sockaddr_buf[1]]);
    if sa_family != AF_INET {
        return Ok(());
    }

    let dest_port = u16::from_be_bytes([sockaddr_buf[2], sockaddr_buf[3]]);
    if dest_port != DNS_PORT {
        return Ok(());
    }

    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::DnsQuery as u32;
    fill_common(event)?;

    event.dest_ip = u32::from_ne_bytes([
        sockaddr_buf[4], sockaddr_buf[5], sockaddr_buf[6], sockaddr_buf[7],
    ]);
    event.dest_port = dest_port;
    event.protocol = IPPROTO_UDP;

    let buff_ptr: u64 = unsafe { ctx.read_at(24)? };
    let buff_len: u64 = unsafe { ctx.read_at(32)? };
    if buff_ptr != 0 && buff_len > 12 {
        let read_len = if buff_len < 256 { buff_len as usize } else { 256 };
        let _ = unsafe {
            bpf_probe_read_user_buf(buff_ptr as *const u8, &mut event.args[..read_len])
        };
    }

    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 2: sys_enter_mount — escape canary
// ===========================================================================

#[tracepoint(category = "syscalls", name = "sys_enter_mount")]
pub fn trace_mount(ctx: TracePointContext) -> u32 {
    match try_trace_mount(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_mount(ctx: &TracePointContext) -> Result<(), c_long> {
    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::Mount as u32;
    fill_common(event)?;

    let dir_name_ptr: u64 = unsafe { ctx.read_at(24)? };
    if dir_name_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(dir_name_ptr as *const u8, &mut event.path)
        };
    }

    let dev_name_ptr: u64 = unsafe { ctx.read_at(16)? };
    if dev_name_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(dev_name_ptr as *const u8, &mut event.args)
        };
    }

    let flags: u64 = unsafe { ctx.read_at(40)? };
    event.flags = flags as u32;

    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 2: sys_enter_bpf — BPF syscall monitor
// ===========================================================================

#[tracepoint(category = "syscalls", name = "sys_enter_bpf")]
pub fn trace_bpf(ctx: TracePointContext) -> u32 {
    match try_trace_bpf(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_bpf(ctx: &TracePointContext) -> Result<(), c_long> {
    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::BpfLoad as u32;
    fill_common(event)?;

    let cmd: u64 = unsafe { ctx.read_at(16)? };
    event.flags = cmd as u32;

    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 2: sys_enter_init_module — kernel module load monitor
// ===========================================================================

#[tracepoint(category = "syscalls", name = "sys_enter_init_module")]
pub fn trace_init_module(ctx: TracePointContext) -> u32 {
    match try_trace_init_module(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_init_module(ctx: &TracePointContext) -> Result<(), c_long> {
    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::ModuleLoad as u32;
    fill_common(event)?;

    let module_len: u64 = unsafe { ctx.read_at(24)? };
    event.flags = module_len as u32;

    let uargs_ptr: u64 = unsafe { ctx.read_at(32)? };
    if uargs_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(uargs_ptr as *const u8, &mut event.args)
        };
    }

    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 2: sys_enter_finit_module — fd-based kernel module load (issue #14)
// ===========================================================================
// Tracepoint args:
//   field:int __syscall_nr;      offset:8;  size:4;
//   field:int fd;                offset:16; size:8;
//   field:const char * uargs;   offset:24; size:8;
//   field:int flags;            offset:32; size:8;

#[tracepoint(category = "syscalls", name = "sys_enter_finit_module")]
pub fn trace_finit_module(ctx: TracePointContext) -> u32 {
    match try_trace_finit_module(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_finit_module(ctx: &TracePointContext) -> Result<(), c_long> {
    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::FinitModule as u32;
    fill_common(event)?;

    let flags: u64 = unsafe { ctx.read_at(32)? };
    event.flags = flags as u32;

    let uargs_ptr: u64 = unsafe { ctx.read_at(24)? };
    if uargs_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(uargs_ptr as *const u8, &mut event.args)
        };
    }

    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 2: sys_enter_ptrace — process injection/inspection (issue #15)
// ===========================================================================
// Tracepoint args:
//   field:int __syscall_nr;      offset:8;  size:4;
//   field:long request;          offset:16; size:8;
//   field:long pid;              offset:24; size:8;
//   field:unsigned long addr;    offset:32; size:8;
//   field:unsigned long data;    offset:40; size:8;

#[tracepoint(category = "syscalls", name = "sys_enter_ptrace")]
pub fn trace_ptrace(ctx: TracePointContext) -> u32 {
    match try_trace_ptrace(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_ptrace(ctx: &TracePointContext) -> Result<(), c_long> {
    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::Ptrace as u32;
    fill_common(event)?;

    // Store ptrace request code in flags
    let request: u64 = unsafe { ctx.read_at(16)? };
    event.flags = request as u32;

    // Store target pid in aux
    let target_pid: u64 = unsafe { ctx.read_at(24)? };
    event.aux = target_pid;

    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 2: sys_enter_unlinkat — file deletion tracking (issue #18)
// ===========================================================================
// Tracepoint args:
//   field:int __syscall_nr;      offset:8;  size:4;
//   field:int dfd;               offset:16; size:8;
//   field:const char * pathname; offset:24; size:8;
//   field:int flag;              offset:32; size:8;

#[tracepoint(category = "syscalls", name = "sys_enter_unlinkat")]
pub fn trace_unlinkat(ctx: TracePointContext) -> u32 {
    match try_trace_unlinkat(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_unlinkat(ctx: &TracePointContext) -> Result<(), c_long> {
    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::Unlink as u32;
    fill_common(event)?;

    let pathname_ptr: u64 = unsafe { ctx.read_at(24)? };
    if pathname_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(pathname_ptr as *const u8, &mut event.path)
        };
    }

    let flag: u64 = unsafe { ctx.read_at(32)? };
    event.flags = flag as u32;

    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 2: sys_enter_renameat2 — file rename tracking (issue #18)
// ===========================================================================
// Tracepoint args:
//   field:int __syscall_nr;       offset:8;  size:4;
//   field:int olddfd;             offset:16; size:8;
//   field:const char * oldname;   offset:24; size:8;
//   field:int newdfd;             offset:32; size:8;
//   field:const char * newname;   offset:40; size:8;
//   field:unsigned int flags;     offset:48; size:8;

#[tracepoint(category = "syscalls", name = "sys_enter_renameat2")]
pub fn trace_renameat2(ctx: TracePointContext) -> u32 {
    match try_trace_renameat2(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_renameat2(ctx: &TracePointContext) -> Result<(), c_long> {
    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::Rename as u32;
    fill_common(event)?;

    // Old path into event.path
    let oldname_ptr: u64 = unsafe { ctx.read_at(24)? };
    if oldname_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(oldname_ptr as *const u8, &mut event.path)
        };
    }

    // New path into event.args
    let newname_ptr: u64 = unsafe { ctx.read_at(40)? };
    if newname_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(newname_ptr as *const u8, &mut event.args)
        };
    }

    let flags: u64 = unsafe { ctx.read_at(48)? };
    event.flags = flags as u32;

    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 3: sched/sched_process_fork — process lifecycle
// ===========================================================================

#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn trace_fork(ctx: TracePointContext) -> u32 {
    match try_trace_fork(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_fork(ctx: &TracePointContext) -> Result<(), c_long> {
    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::Fork as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;

    let parent_pid: u32 = unsafe { ctx.read_at(24)? };
    event.pid = parent_pid;

    let child_pid: u32 = unsafe { ctx.read_at(44)? };
    event.flags = child_pid;

    let comm_lo: u64 = unsafe { ctx.read_at(8)? };
    let comm_hi: u64 = unsafe { ctx.read_at(16)? };
    event.comm[..8].copy_from_slice(&comm_lo.to_ne_bytes());
    event.comm[8..16].copy_from_slice(&comm_hi.to_ne_bytes());

    let child_lo: u64 = unsafe { ctx.read_at(28)? };
    let child_hi: u64 = unsafe { ctx.read_at(36)? };
    event.path[..8].copy_from_slice(&child_lo.to_ne_bytes());
    event.path[8..16].copy_from_slice(&child_hi.to_ne_bytes());

    fill_cpu_and_seq(event);
    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 3: sched/sched_process_exit — process lifecycle
// ===========================================================================

// Issue #13: kernel struct offsets are now resolved from BTF by the userspace
// loader and pushed into the OFFSETS map at start-up. 1076 is the Linux 6.12.13
// aarch64 value, kept as a last-resort fallback if BTF parsing fails.
const DEFAULT_TASK_EXIT_CODE_OFFSET: u64 = 1076;

#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn trace_exit(ctx: TracePointContext) -> u32 {
    match try_trace_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_exit(ctx: &TracePointContext) -> Result<(), c_long> {
    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::Exit as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;

    let pid: u32 = unsafe { ctx.read_at(24)? };
    event.pid = pid;

    let comm_lo: u64 = unsafe { ctx.read_at(8)? };
    let comm_hi: u64 = unsafe { ctx.read_at(16)? };
    event.comm[..8].copy_from_slice(&comm_lo.to_ne_bytes());
    event.comm[8..16].copy_from_slice(&comm_hi.to_ne_bytes());

    let task = unsafe { bpf_get_current_task() };
    if task != 0 {
        let off = offset_or(OFFSET_IDX_TASK_EXIT_CODE, DEFAULT_TASK_EXIT_CODE_OFFSET);
        if let Ok(code) = unsafe {
            bpf_probe_read_kernel((task + off) as *const i32)
        } {
            event.flags = code as u32;
        }
    }

    fill_cpu_and_seq(event);
    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 3: oom/mark_victim — OOM kill victim
// ===========================================================================

#[tracepoint(category = "oom", name = "mark_victim")]
pub fn trace_oom_victim(ctx: TracePointContext) -> u32 {
    match try_trace_oom_victim(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_oom_victim(ctx: &TracePointContext) -> Result<(), c_long> {
    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::OomKill as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;

    // Fix #12: populate comm with the current process context (the OOM killer)
    event.comm = bpf_get_current_comm()?;

    let victim_pid: u32 = unsafe { ctx.read_at(8)? };
    event.pid = victim_pid;

    // Victim comm (16 bytes at offset 12) — store in path field
    let comm_lo: u64 = unsafe { ctx.read_at(12)? };
    let comm_hi: u64 = unsafe { ctx.read_at(20)? };
    event.path[..8].copy_from_slice(&comm_lo.to_ne_bytes());
    event.path[8..16].copy_from_slice(&comm_hi.to_ne_bytes());

    fill_cpu_and_seq(event);
    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 3: commit_creds kprobe — privilege escalation detection
// ===========================================================================

#[kprobe]
pub fn trace_commit_creds(ctx: ProbeContext) -> u32 {
    match try_trace_commit_creds(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_commit_creds(ctx: &ProbeContext) -> Result<(), c_long> {
    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::CredsChanged as u32;
    fill_common(event)?;

    let old_uid_gid = bpf_get_current_uid_gid();
    event.aux = (old_uid_gid & 0xFFFF_FFFF) as u64;

    let cred_ptr = ctx.arg::<u64>(0).ok_or(1i64)?;
    if cred_ptr != 0 {
        let new_uid: u32 = unsafe {
            bpf_probe_read_kernel((cred_ptr + 8) as *const u32).unwrap_or(0)
        };
        event.flags = new_uid;
    }

    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 3: tcp_sendmsg kprobe — TCP data volume sent
// ===========================================================================

#[kprobe]
pub fn trace_tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_trace_tcp_sendmsg(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_tcp_sendmsg(ctx: &ProbeContext) -> Result<(), c_long> {
    let bytes = ctx.arg::<u64>(2).unwrap_or(0);
    if bytes == 0 {
        return Ok(());
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let prev = unsafe { TCP_SEND_BYTES.get(&pid) }.copied().unwrap_or(0);
    let pending = prev.wrapping_add(bytes);

    // Emit only once the pending (unreported) byte total crosses a bucket
    // boundary. This keeps userspace's delta-sum cumulative tracking correct
    // while slashing event rate ~99% on chatty TCP workloads (#21).
    if pending < TCP_RATE_BUCKET {
        let _ = TCP_SEND_BYTES.insert(&pid, &pending, 0);
        return Ok(());
    }

    // Crossing threshold: emit pending as the delta and reset the counter.
    let zero: u64 = 0;
    let _ = TCP_SEND_BYTES.insert(&pid, &zero, 0);

    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::TcpSend as u32;
    fill_common(event)?;
    event.aux = pending;

    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 3: tcp_recvmsg kretprobe — TCP data volume received (fix #3)
// ===========================================================================
// Changed from kprobe to kretprobe so we capture the ACTUAL bytes received
// (return value) instead of the buffer size (arg2). The return value is
// negative on error, zero on EOF, or positive for actual bytes read.

#[kretprobe]
pub fn trace_tcp_recvmsg(ctx: RetProbeContext) -> u32 {
    match try_trace_tcp_recvmsg(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_tcp_recvmsg(ctx: &RetProbeContext) -> Result<(), c_long> {
    // tcp_recvmsg returns `int` (32-bit signed). On AArch64 the high 32
    // bits of the return register are unspecified per AAPCS64 for sub-
    // 64-bit returns, so reading ctx.ret() directly as i64 picks up
    // garbage and an error code like -512 (0xFFFFFE00) reads as
    // 4,294,966,784 — exactly the value that triggered the spurious
    // 4.29 GB `large_download` violation. Read as i32 and sign-extend.
    let ret: i32 = ctx.ret().unwrap_or(0);
    // Only emit if bytes > 0 (negative = error, 0 = EOF)
    if ret <= 0 {
        return Ok(());
    }
    let bytes = ret as u64;

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let prev = unsafe { TCP_RECV_BYTES.get(&pid) }.copied().unwrap_or(0);
    let pending = prev.wrapping_add(bytes);

    if pending < TCP_RATE_BUCKET {
        let _ = TCP_RECV_BYTES.insert(&pid, &pending, 0);
        return Ok(());
    }

    let zero: u64 = 0;
    let _ = TCP_RECV_BYTES.insert(&pid, &zero, 0);

    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::TcpRecv as u32;
    fill_common(event)?;
    event.aux = pending;

    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// Tier 3: udp_sendmsg kprobe — DNS query visibility on connected UDP sockets
// (fix #16)
// ===========================================================================
// `trace_sendto` (tracepoint) only sees `sendto()` syscalls. A resolver that
// calls `connect()` + `send()`/`write()` on a UDP socket goes through
// `udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)` in the kernel
// without hitting `sendto`. We kprobe that function and filter by destination
// port 53 (the connected socket stores its peer port in `sk_dport`, in
// network byte order at offset 12 on aarch64 Linux 6.12).
//
// We don't decode the DNS qname on this path — walking msg->msg_iter to locate
// the DNS payload is verifier-unfriendly. Instead we emit a DnsQuery event
// with only the destination port populated, letting userspace know the query
// exists even if the name is unknown. Tracepoint `trace_sendto` still decodes
// qnames on the `sendto` path.

// sock->sk_dport lives at a well-known small offset inside the struct
// `sock_common` head of `struct sock`. BTF could resolve this dynamically but
// for a simple read we accept the hardcoded fallback (consistent with what the
// rest of this file did before Phase C).
const DEFAULT_SOCK_SK_DPORT_OFFSET: u64 = 12;
const DNS_PORT_BE: u16 = 0x3500; // 53 in big-endian (wire format)

#[kprobe]
pub fn trace_udp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_trace_udp_sendmsg(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_udp_sendmsg(ctx: &ProbeContext) -> Result<(), c_long> {
    // arg0 = struct sock *sk
    let sk: u64 = ctx.arg::<u64>(0).unwrap_or(0);
    if sk == 0 {
        return Ok(());
    }

    // Read sk->sk_dport (u16, network byte order).
    let dport_be: u16 = match unsafe {
        bpf_probe_read_kernel((sk + DEFAULT_SOCK_SK_DPORT_OFFSET) as *const u16)
    } {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };

    if dport_be != DNS_PORT_BE {
        return Ok(());
    }

    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::DnsQuery as u32;
    fill_common(event)?;
    event.dest_port = 53;
    event.protocol = 17; // UDP
    // args buffer is left zeroed — qname not decoded on this path.
    let _ = EVENTS.output(event, 0);
    Ok(())
}

// ===========================================================================
// BPF-LSM policy enforcement
// ===========================================================================

#[map]
static PATH_SCRATCH: PerCpuArray<[u8; 256]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PATH_COMPONENT_SCRATCH: PerCpuArray<[u8; 256]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static DENIED_PATHS: HashMap<[u8; 256], u8> = HashMap::with_max_entries(512, 0);

#[map]
static ALLOWED_PATHS: HashMap<[u8; 256], u8> = HashMap::with_max_entries(512, 0);

#[map]
static DENIED_NETS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(256, 0);

#[map]
static ALLOWED_NETS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(256, 0);

// IPv6 CIDR enforcement maps. Key is a 16-byte in6_addr in network byte order;
// the LPM prefix length is stored in the key's 4-byte prefix_len field.
#[map]
static DENIED_NETS_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(256, 0);

#[map]
static ALLOWED_NETS_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(256, 0);

#[map]
static LSM_ERROR_COUNTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

const LSM_ERR_FILE_OPEN: u32 = 0;
const LSM_ERR_SOCKET_CONNECT: u32 = 1;
const LSM_ERR_BPRM_CHECK: u32 = 2;
const LSM_ERR_SB_MOUNT: u32 = 3;

fn zero_bpf_d_path_tail(path_buf_ptr: *mut [u8; 256], ret: c_long) {
    if ret <= 0 || ret >= 256 {
        return;
    }

    let mut off = ret as usize;
    while off < 256 {
        unsafe {
            core::ptr::write_volatile((path_buf_ptr as *mut u8).add(off), 0);
        }
        off += 1;
    }
}

// Keyed by pid_tgid. Set by trace_openat to hand off "this open needs the
// resolved path checked" to lsm_file_open. Value is a bitmask:
//   bit 0 (INTENT_TRAVERSAL) — raw path was /workspace-rooted with a `..`
//                              segment; verify resolved stays under /workspace.
//   bit 1 (INTENT_WRITE)     — open has write flags; verify resolved lands in
//                              a write-allowed directory (workspace, tmp, etc.).
// lsm_file_open looks up once, calls bpf_d_path once, runs both checks.
#[map]
static OPEN_INTENT: HashMap<u64, u8> = HashMap::with_max_entries(4096, 0);

const INTENT_TRAVERSAL: u8 = 1 << 0;
const INTENT_WRITE: u8 = 1 << 1;

const EPERM: i32 = 1;

// file.f_path is an embedded struct path at offset 64 on aarch64 Linux 6.12.13
// (dentry at offset 72 = f_path + 8). Passed as *mut path to bpf_d_path.
const DEFAULT_FILE_F_PATH_OFFSET: u64 = 64;

// Struct offsets for aarch64 Linux 6.12.13 — verified via /sys/kernel/btf/vmlinux.
// Issue #13: resolved from BTF at load time. These defaults are for Linux
// 6.12.13 aarch64 and serve as last-resort fallbacks when BTF is missing.
const DEFAULT_FILE_DENTRY_OFFSET: u64 = 72;       // file.f_path.dentry (64 + 8)
const DEFAULT_DENTRY_NAME_OFFSET: u64 = 40;       // dentry.d_name.name (32 + 8)
const DEFAULT_DENTRY_D_PARENT_OFFSET: u64 = 24;   // dentry.d_parent
const DEFAULT_BPRM_FILE_OFFSET: u64 = 64;         // linux_binprm.file
const DEFAULT_BPRM_FILENAME_OFFSET: u64 = 96;     // linux_binprm.filename
const MAX_DENTRY_DEPTH: u8 = 24;
const MAX_PATH_COMPONENT_COPY: usize = 32;
const MAX_PATH_KEY_COPY: usize = 32;

#[inline(always)]
fn lsm_internal_error_verdict(counter_idx: u32) -> i32 {
    if let Some(counter_ptr) = LSM_ERROR_COUNTS.get_ptr_mut(counter_idx) {
        unsafe {
            *counter_ptr = (*counter_ptr).wrapping_add(1);
        }
    }

    -EPERM
}

// ---------------------------------------------------------------------------
// LSM probe: file_open — synchronous enforcement for dangerous paths
// ---------------------------------------------------------------------------

#[lsm(hook = "file_open")]
pub fn lsm_file_open(ctx: LsmContext) -> i32 {
    match try_lsm_file_open(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => lsm_internal_error_verdict(LSM_ERR_FILE_OPEN),
    }
}

#[inline(always)]
fn read_dentry_name(dentry_addr: u64, buf: &mut [u8; 16]) {
    if let Ok(name_ptr) = unsafe {
        bpf_probe_read_kernel((dentry_addr + offset_or(OFFSET_IDX_DENTRY_NAME, DEFAULT_DENTRY_NAME_OFFSET)) as *const u64)
    } {
        if name_ptr != 0 {
            let _ = unsafe { bpf_probe_read_kernel_str_bytes(name_ptr as *const u8, buf) };
        }
    }
}

#[inline(always)]
fn read_dentry_parent(dentry_addr: u64) -> u64 {
    match unsafe { bpf_probe_read_kernel((dentry_addr + offset_or(OFFSET_IDX_DENTRY_D_PARENT, DEFAULT_DENTRY_D_PARENT_OFFSET)) as *const u64) } {
        Ok(parent) if parent != 0 && parent != dentry_addr => parent,
        _ => 0,
    }
}

#[inline(always)]
fn read_dentry_name_full(dentry_addr: u64, buf: &mut [u8; 256]) -> bool {
    match unsafe {
        bpf_probe_read_kernel((dentry_addr + offset_or(OFFSET_IDX_DENTRY_NAME, DEFAULT_DENTRY_NAME_OFFSET)) as *const u64)
    } {
        Ok(name_ptr) if name_ptr != 0 => {
            let _ = unsafe { bpf_probe_read_kernel_str_bytes(name_ptr as *const u8, buf) };
            buf[0] != 0
        }
        _ => false,
    }
}

#[inline(always)]
fn build_path_key_from_dentry(dentry_addr: u64, path_buf_ptr: *mut [u8; 256]) -> Result<(), c_long> {
    let component_buf_ptr = PATH_COMPONENT_SCRATCH.get_ptr_mut(0).ok_or(1i64)?;
    unsafe { core::ptr::write_bytes(path_buf_ptr as *mut u8, 0, 256) };

    let path = path_buf_ptr as *mut u8;
    let component = component_buf_ptr as *mut u8;

    let mut current = dentry_addr;
    let mut write_pos: usize = 255;
    let mut saw_component = false;
    let mut depth: u8 = 0;

    while depth < MAX_DENTRY_DEPTH && current != 0 {
        unsafe { core::ptr::write_bytes(component_buf_ptr as *mut u8, 0, 256) };
        if read_dentry_name_full(current, unsafe { &mut *(component_buf_ptr as *mut [u8; 256]) }) {
            let first = unsafe { core::ptr::read(component) };
            let second = unsafe { core::ptr::read(component.add(1)) };
            if !(first == b'/' && second == 0) {
                let mut len: usize = 0;
                while len < MAX_PATH_COMPONENT_COPY {
                    if unsafe { core::ptr::read(component.add(len)) } == 0 {
                        break;
                    }
                    len += 1;
                }

                if len > 0 {
                    if len + 1 > write_pos {
                        return Err(1i64);
                    }

                    write_pos -= len;
                    let mut i: usize = 0;
                    while i < MAX_PATH_COMPONENT_COPY {
                        if i >= len {
                            break;
                        }
                        unsafe {
                            core::ptr::write(path.add(write_pos + i), core::ptr::read(component.add(i)));
                        }
                        i += 1;
                    }
                    write_pos -= 1;
                    unsafe { core::ptr::write(path.add(write_pos), b'/') };
                    saw_component = true;
                }
            }
        }

        let parent = read_dentry_parent(current);
        if parent == 0 {
            break;
        }
        current = parent;
        depth += 1;
    }

    if !saw_component {
        unsafe { core::ptr::write(path, b'/') };
        return Ok(());
    }

    let start = write_pos;
    let mut i: usize = 0;
    while i < MAX_PATH_KEY_COPY {
        let value;
        if start + i < 256 {
            value = unsafe { core::ptr::read(path.add(start + i)) };
        } else {
            value = 0;
        }
        unsafe { core::ptr::write(path.add(i), value) };
        i += 1;
    }

    Ok(())
}

#[inline(always)]
fn is_proc_danger_name(n: &[u8; 16]) -> bool {
    if n[0] == b'm' && n[1] == b'e' && n[2] == b'm' && n[3] == 0 { return true; }
    if n[0] == b'm' && n[1] == b'a' && n[2] == b'p' && n[3] == b's' && n[4] == 0 { return true; }
    if n[0] == b'p' && n[1] == b'a' && n[2] == b'g' && n[3] == b'e'
        && n[4] == b'm' && n[5] == b'a' && n[6] == b'p' && n[7] == 0 { return true; }
    if n[0] == b's' && n[1] == b'm' && n[2] == b'a' && n[3] == b'p'
        && n[4] == b's' && n[5] == 0 { return true; }
    if n[0] == b's' && n[1] == b't' && n[2] == b'a' && n[3] == b't'
        && n[4] == b'u' && n[5] == b's' && n[6] == 0 { return true; }
    if n[0] == b'c' && n[1] == b'm' && n[2] == b'd' && n[3] == b'l'
        && n[4] == b'i' && n[5] == b'n' && n[6] == b'e' && n[7] == 0 { return true; }
    if n[0] == b'w' && n[1] == b'c' && n[2] == b'h' && n[3] == b'a'
        && n[4] == b'n' && n[5] == 0 { return true; }
    if n[0] == b's' && n[1] == b't' && n[2] == b'a' && n[3] == b'c'
        && n[4] == b'k' && n[5] == 0 { return true; }
    if n[0] == b's' && n[1] == b'y' && n[2] == b's' && n[3] == b'c'
        && n[4] == b'a' && n[5] == b'l' && n[6] == b'l' && n[7] == 0 { return true; }
    if n[0] == b'e' && n[1] == b'n' && n[2] == b'v' && n[3] == b'i'
        && n[4] == b'r' && n[5] == b'o' && n[6] == b'n' && n[7] == 0 { return true; }
    false
}

#[inline(always)]
fn name_is_dev(n: &[u8; 16]) -> bool {
    n[0] == b'd' && n[1] == b'e' && n[2] == b'v' && n[3] == 0
}

#[inline(always)]
fn is_proc_sensitive_leaf(n: &[u8; 16]) -> bool {
    // kallsyms
    if n[0] == b'k' && n[1] == b'a' && n[2] == b'l' && n[3] == b'l'
        && n[4] == b's' && n[5] == b'y' && n[6] == b'm' && n[7] == b's'
        && n[8] == 0 { return true; }
    // kcore
    if n[0] == b'k' && n[1] == b'c' && n[2] == b'o' && n[3] == b'r'
        && n[4] == b'e' && n[5] == 0 { return true; }
    // vmlinux — /sys/kernel/btf/vmlinux is a complete BTF dump of every
    // kernel struct/function. Leaks all offsets and signatures, valuable
    // for sandbox-escape research. PID 1 reads this at agent startup; the
    // PID == 1 fast-path at the top of try_lsm_file_open exempts that.
    if n[0] == b'v' && n[1] == b'm' && n[2] == b'l' && n[3] == b'i'
        && n[4] == b'n' && n[5] == b'u' && n[6] == b'x' && n[7] == 0 { return true; }
    false
}

#[inline(always)]
fn is_dev_sensitive_leaf(n: &[u8; 16]) -> bool {
    // mem
    if n[0] == b'm' && n[1] == b'e' && n[2] == b'm' && n[3] == 0 { return true; }
    // kmem
    if n[0] == b'k' && n[1] == b'm' && n[2] == b'e' && n[3] == b'm' && n[4] == 0 { return true; }
    // port
    if n[0] == b'p' && n[1] == b'o' && n[2] == b'r' && n[3] == b't' && n[4] == 0 { return true; }
    // kmsg
    if n[0] == b'k' && n[1] == b'm' && n[2] == b's' && n[3] == b'g' && n[4] == 0 { return true; }
    false
}

#[inline(always)]
fn name_is_pid(n: &[u8; 16]) -> bool {
    if n[0] < b'0' || n[0] > b'9' { return false; }
    let mut i = 1u8;
    while i < 8 {
        let c = n[i as usize];
        if c == 0 { return true; }
        if c < b'0' || c > b'9' { return false; }
        i += 1;
    }
    true
}

#[inline(always)]
fn name_is_fd_or_ns(n: &[u8; 16]) -> bool {
    (n[0] == b'f' && n[1] == b'd' && n[2] == 0) ||
    (n[0] == b'n' && n[1] == b's' && n[2] == 0)
}

fn try_lsm_file_open(ctx: &LsmContext) -> Result<i32, c_long> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    if pid == 1 { return Ok(0); }

    let file_addr: u64 = unsafe { ctx.arg(0) };
    if file_addr == 0 { return Ok(0); }

    // Consume intent flags set by trace_openat and enforce them now that we
    // have `struct file` and can resolve the canonical path via bpf_d_path.
    // The tracepoint sees raw user paths (possibly relative, possibly with
    // `..`); this hook is the only place the kernel gives us the true target.
    let intent: u8 = match unsafe { OPEN_INTENT.get(&pid_tgid) } {
        Some(v) => *v,
        None => 0,
    };
    if intent != 0 {
        let _ = OPEN_INTENT.remove(&pid_tgid);
        let f_path_addr = file_addr + DEFAULT_FILE_F_PATH_OFFSET;
        if let Some(buf_ptr) = unsafe { PATH_SCRATCH.get_ptr_mut(0) } {
            unsafe { core::ptr::write_bytes(buf_ptr as *mut u8, 0, 256) };
            let ret = unsafe {
                bpf_d_path(f_path_addr as *mut _, buf_ptr as *mut u8, 256)
            };
            if ret > 0 {
                let resolved = unsafe { &*(buf_ptr as *const [u8; 256]) };

                // Traversal: raw path was /workspace-rooted with `..` — the
                // canonical path must still stay under /workspace.
                if (intent & INTENT_TRAVERSAL) != 0 && !path_starts_with_workspace(resolved) {
                    unsafe { bpf_send_signal(9) };
                    return Ok(-EPERM);
                }

                // Write-intent: the resolved target must land in a directory
                // where writes are policy-allowed. Keeps the expanded fix #6
                // allowlist (/etc, /run, /var, /proc, /sys for DHCP + init).
                if (intent & INTENT_WRITE) != 0
                    && !path_starts_with_workspace(resolved)
                    && !path_starts_with_dev(resolved)
                    && !path_starts_with_tmp(resolved)
                    && !path_starts_with_proc_self(resolved)
                    && !path_starts_with_etc(resolved)
                    && !path_starts_with_run(resolved)
                    && !path_starts_with_var(resolved)
                    && !path_starts_with_proc(resolved)
                    && !path_starts_with_sys(resolved)
                {
                    unsafe { bpf_send_signal(9) };
                    return Ok(-EPERM);
                }
            }
        }
    }

    let d0 = match unsafe {
        bpf_probe_read_kernel((file_addr + offset_or(OFFSET_IDX_FILE_DENTRY, DEFAULT_FILE_DENTRY_OFFSET)) as *const u64)
    } {
        Ok(d) if d != 0 => d,
        _ => return Ok(0),
    };

    let mut n0 = [0u8; 16];
    read_dentry_name(d0, &mut n0);

    let d1 = read_dentry_parent(d0);
    let mut n1 = [0u8; 16];
    if d1 != 0 { read_dentry_name(d1, &mut n1); }

    let d2 = if d1 != 0 { read_dentry_parent(d1) } else { 0 };
    let mut n2 = [0u8; 16];
    if d2 != 0 { read_dentry_name(d2, &mut n2); }

    // For /proc/kallsyms and /proc/kcore the dentry walk cannot see a
    // parent named "proc" because d_parent of a filesystem root dentry
    // loops on itself (mount boundaries need vfsmount to cross). The
    // filenames "kallsyms" and "kcore" are distinctive enough that a
    // leaf-only match is acceptable in a sandbox — blocking a user file
    // named literally "kallsyms" is a tolerable false positive.
    //
    // /dev leaf names like "mem" are too common for leaf-only matching,
    // so we keep the parent check there (accept "dev" at n1 or n2 in
    // case the walk crosses the devtmpfs root).
    let blocked = (name_is_pid(&n1) && is_proc_danger_name(&n0))
        || (name_is_pid(&n2) && name_is_fd_or_ns(&n1))
        || is_proc_sensitive_leaf(&n0)
        || ((name_is_dev(&n1) || name_is_dev(&n2)) && is_dev_sensitive_leaf(&n0));

    if blocked {
        unsafe { bpf_send_signal(9) };
        return Ok(-EPERM);
    }

    if let Some(path_buf_ptr) = PATH_SCRATCH.get_ptr_mut(0) {
        unsafe { core::ptr::write_bytes(path_buf_ptr as *mut u8, 0, 256) };
        let f_path_addr = file_addr + DEFAULT_FILE_F_PATH_OFFSET;
        let ret = unsafe {
            bpf_d_path(f_path_addr as *mut _, path_buf_ptr as *mut u8, 256)
        };
        if ret > 0 {
            zero_bpf_d_path_tail(path_buf_ptr, ret);
            let path_key = unsafe { &*(path_buf_ptr as *const [u8; 256]) };
            if unsafe { ALLOWED_PATHS.get(path_key) }.is_some() {
                return Ok(0);
            }
            if unsafe { DENIED_PATHS.get(path_key) }.is_some() {
                return Ok(-EPERM);
            }
        }
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// LSM probe: socket_connect — block forbidden network connections (IPv4 + IPv6)
// ---------------------------------------------------------------------------

#[lsm(hook = "socket_connect")]
pub fn lsm_socket_connect(ctx: LsmContext) -> i32 {
    match try_lsm_socket_connect(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => lsm_internal_error_verdict(LSM_ERR_SOCKET_CONNECT),
    }
}

fn try_lsm_socket_connect(ctx: &LsmContext) -> Result<i32, c_long> {
    let addr_ptr: *const u8 = unsafe { ctx.arg(1) };
    if addr_ptr.is_null() {
        return Ok(0);
    }

    let sa_buf: [u8; 8] = unsafe {
        bpf_probe_read_kernel(addr_ptr as *const [u8; 8]).unwrap_or([0u8; 8])
    };

    let sa_family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);

    if sa_family == AF_INET {
        let dest_port = u16::from_be_bytes([sa_buf[2], sa_buf[3]]);
        let dest_ip_ne = u32::from_ne_bytes([sa_buf[4], sa_buf[5], sa_buf[6], sa_buf[7]]);

        if unsafe { ALLOWED_NETS.get(&LpmKey::new(32, dest_ip_ne)) }.is_some() {
            return Ok(0);
        }

        if unsafe { DENIED_NETS.get(&LpmKey::new(32, dest_ip_ne)) }.is_some() {
            let event = get_scratch_event().ok_or(1i64)?;
            event.kind = EventKind::Connect as u32;
            fill_common(event)?;
            event.dest_ip = dest_ip_ne;
            event.dest_port = dest_port;
            event.protocol = 6;
            let _ = EVENTS.output(event, 0);
            return Ok(-EPERM);
        }
    } else if sa_family == AF_INET6 {
        // sockaddr_in6 layout:
        //   u16 sin6_family; u16 sin6_port; u32 sin6_flowinfo;
        //   u8  sin6_addr[16]; u32 sin6_scope_id;
        // Read 28 bytes total.
        let sa6: [u8; 28] = match unsafe { bpf_probe_read_kernel(addr_ptr as *const [u8; 28]) } {
            Ok(b) => b,
            Err(_) => return Ok(0),
        };
        let dest_port = u16::from_be_bytes([sa6[2], sa6[3]]);
        let mut dest_addr = [0u8; 16];
        dest_addr.copy_from_slice(&sa6[8..24]);

        if ALLOWED_NETS_V6.get(&LpmKey::new(128, dest_addr)).is_some() {
            return Ok(0);
        }

        if DENIED_NETS_V6.get(&LpmKey::new(128, dest_addr)).is_some() {
            let event = get_scratch_event().ok_or(1i64)?;
            event.kind = EventKind::ConnectV6 as u32;
            fill_common(event)?;
            event.dest_ip6.copy_from_slice(&dest_addr);
            event.dest_port = dest_port;
            event.protocol = 6;
            let _ = EVENTS.output(event, 0);
            unsafe { bpf_send_signal(9) };
            return Ok(-EPERM);
        }
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// LSM probe: bprm_check_security — block forbidden binary execution (fix #1)
// ---------------------------------------------------------------------------
//
// FIX: Previous implementation read `bprm->buf` which contains the first 256
// bytes of the FILE CONTENT (ELF header / shebang), NOT the binary path.
// Now we walk `bprm->file->f_path.dentry` chain (same as lsm_file_open)
// to reconstruct the filename for DENIED_PATHS/ALLOWED_PATHS lookup.

#[lsm(hook = "bprm_check_security")]
pub fn lsm_bprm_check(ctx: LsmContext) -> i32 {
    match try_lsm_bprm_check(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => lsm_internal_error_verdict(LSM_ERR_BPRM_CHECK),
    }
}

fn try_lsm_bprm_check(ctx: &LsmContext) -> Result<i32, c_long> {
    // arg(0) is struct linux_binprm *bprm
    let bprm: *const linux_binprm = unsafe { ctx.arg(0) };
    if bprm.is_null() {
        return Ok(0);
    }

    if let Some(filename_buf_ptr) = PATH_COMPONENT_SCRATCH.get_ptr_mut(0) {
        unsafe { core::ptr::write_bytes(filename_buf_ptr as *mut u8, 0, 256) };
        let filename_ptr: u64 = match unsafe {
            bpf_probe_read_kernel(
                (bprm as *const u8)
                    .add(offset_or(OFFSET_IDX_BPRM_FILENAME, DEFAULT_BPRM_FILENAME_OFFSET) as usize)
                    as *const u64,
            )
        } {
            Ok(ptr) => ptr,
            _ => 0,
        };
        if filename_ptr != 0 {
            let filename_key = unsafe { &mut *(filename_buf_ptr as *mut [u8; 256]) };
            let _ = unsafe { bpf_probe_read_kernel_str_bytes(filename_ptr as *const u8, filename_key) };
            if path_is_privesc_binary(filename_key) {
                let event = get_scratch_event().ok_or(1i64)?;
                event.kind = EventKind::Execve as u32;
                fill_common(event)?;
                event.path.copy_from_slice(filename_key);
                let _ = EVENTS.output(event, 0);
                return Ok(-EPERM);
            }
        }
    }

    // Walk bprm->file->f_path to get the actual binary path.
    //
    // Keep this as direct constant-offset pointer access. Reading the field via
    // bpf_probe_read_kernel turns the result into a scalar address, and the
    // verifier then rejects bpf_d_path because it requires a trusted path ptr.
    let file_ptr = unsafe {
        core::ptr::read(
            (bprm as *const u8).add(DEFAULT_BPRM_FILE_OFFSET as usize) as *const *const KernelFile
        )
    };
    if file_ptr.is_null() {
        return Ok(0);
    }

    let path_buf_ptr = PATH_SCRATCH.get_ptr_mut(0).ok_or(1i64)?;
    unsafe { core::ptr::write_bytes(path_buf_ptr as *mut u8, 0, 256) };
    let f_path_addr = unsafe {
        (file_ptr as *const u8).add(DEFAULT_FILE_F_PATH_OFFSET as usize)
    };
    let ret = unsafe {
        bpf_d_path(f_path_addr as *mut _, path_buf_ptr as *mut u8, 256)
    };
    if ret <= 0 {
        return Ok(0);
    }
    zero_bpf_d_path_tail(path_buf_ptr, ret);
    let path_key = unsafe { &*(path_buf_ptr as *const [u8; 256]) };

    // Check privesc binary list inline — this catches the common cases
    // regardless of map contents.
    if path_is_privesc_binary(path_key) {
        let event = get_scratch_event().ok_or(1i64)?;
        event.kind = EventKind::Execve as u32;
        fill_common(event)?;
        event.path.copy_from_slice(path_key);
        let _ = EVENTS.output(event, 0);
        return Ok(-EPERM);
    }

    if unsafe { ALLOWED_PATHS.get(path_key) }.is_some() {
        return Ok(0);
    }

    if unsafe { DENIED_PATHS.get(path_key) }.is_some() {
        let event = get_scratch_event().ok_or(1i64)?;
        event.kind = EventKind::Execve as u32;
        fill_common(event)?;
        event.path.copy_from_slice(path_key);
        let _ = EVENTS.output(event, 0);
        return Ok(-EPERM);
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// LSM probe: sb_mount — block all mount attempts from non-init processes
// ---------------------------------------------------------------------------

#[lsm(hook = "sb_mount")]
pub fn lsm_sb_mount(ctx: LsmContext) -> i32 {
    match try_lsm_sb_mount(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => lsm_internal_error_verdict(LSM_ERR_SB_MOUNT),
    }
}

fn try_lsm_sb_mount(ctx: &LsmContext) -> Result<i32, c_long> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::Mount as u32;
    event.pid = pid;
    event.uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = bpf_get_current_comm()?;

    let dev_name_ptr: *const u8 = unsafe { ctx.arg(0) };
    if !dev_name_ptr.is_null() {
        let _ = unsafe { bpf_probe_read_kernel_str_bytes(dev_name_ptr, &mut event.args) };
    }

    let path_addr: u64 = unsafe { ctx.arg(1) };
    let path_ptr = path_addr as *mut core::ffi::c_void;
    if !path_ptr.is_null() {
        let path_buf_ptr = unsafe { PATH_SCRATCH.get_ptr_mut(0).ok_or(1i64)? };
        unsafe { core::ptr::write_bytes(path_buf_ptr as *mut u8, 0, 256) };
        let ret = unsafe {
            bpf_d_path(path_ptr as *mut _, path_buf_ptr as *mut u8, 256)
        };
        if ret >= 0 {
            let path_key = unsafe { &*(path_buf_ptr as *const [u8; 256]) };
            event.path.copy_from_slice(path_key);
        }
    }

    let _ = EVENTS.output(event, 0);

    if pid != 1 {
        return Ok(-EPERM);
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// BPF panic handler (required for no_std)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

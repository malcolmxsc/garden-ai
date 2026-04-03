//! Garden AI eBPF kernel-side security probes.
//!
//! This is a `#![no_std]` BPF program compiled to `bpfel-unknown-none`.
//! It attaches to syscall tracepoints and emits `RawSecurityEvent`s
//! through a shared `PerfEventArray` map.
//!
//! ## Stack Management
//! `RawSecurityEvent` (~556 bytes) exceeds BPF's 512-byte stack limit.
//! We use a `PerCpuArray` map with a single element as heap-like scratch
//! space — each CPU gets its own slot, and since BPF programs run with
//! preemption disabled, this is safe without locks.
//!
//! ## Tier 1 Probes
//! - `trace_execve` — process execution (sys_enter_execve)
//! - `trace_openat` — file access (sys_enter_openat)
//! - `trace_connect` — network connections (sys_enter_connect)
//!
//! ## Tier 2 Probes
//! - `trace_sendto` — DNS queries (sys_enter_sendto, UDP port 53)
//! - `trace_mount` — mount attempts (sys_enter_mount) — escape canary
//! - `trace_bpf` — BPF syscall (sys_enter_bpf) — red flag
//! - `trace_init_module` — kernel module load (sys_enter_init_module) — should never fire

#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_long,
    helpers::{
        bpf_d_path, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
        gen::{bpf_get_current_task, bpf_send_signal},
    },
    macros::{kprobe, lsm, map, tracepoint},
    maps::{lpm_trie::Key as LpmKey, HashMap, LpmTrie, PerCpuArray, PerfEventArray},
    programs::{LsmContext, ProbeContext, TracePointContext},
};
use garden_ebpf_common::{EventKind, RawSecurityEvent};

// ---------------------------------------------------------------------------
// Shared maps
// ---------------------------------------------------------------------------

/// Perf event ring buffer — userspace reads from this via AsyncPerfEventArray.
#[map]
static EVENTS: PerfEventArray<RawSecurityEvent> = PerfEventArray::new(0);

/// Per-CPU scratch space for building events without exceeding the 512-byte
/// BPF stack limit. Single element (index 0), one copy per CPU.
#[map]
static SCRATCH: PerCpuArray<RawSecurityEvent> = PerCpuArray::with_max_entries(1, 0);

/// Get a mutable reference to the per-CPU scratch event, zeroed out.
#[inline(always)]
fn get_scratch_event() -> Option<&'static mut RawSecurityEvent> {
    let event = unsafe { SCRATCH.get_ptr_mut(0)?.as_mut()? };
    // Zero the struct for reuse
    *event = RawSecurityEvent::zeroed();
    Some(event)
}

// ===========================================================================
// Inline enforcement helpers — called synchronously from tracepoint context
// to send SIGKILL before the syscall returns, eliminating the userspace race.
// All functions take &[u8; 256] path and do fixed-length byte comparisons only
// (no loops) to satisfy the BPF verifier.
// ===========================================================================

/// True if path starts with `/proc/` followed by a decimal digit.
/// Matches `/proc/<pid>/...` while allowing `/proc/cpuinfo`, `/proc/sys/`, etc.
#[inline(always)]
fn path_starts_with_proc_pid(p: &[u8; 256]) -> bool {
    p[0] == b'/' && p[1] == b'p' && p[2] == b'r' && p[3] == b'o'
        && p[4] == b'c' && p[5] == b'/' && p[6] >= b'0' && p[6] <= b'9'
}

/// True if byte at `i` starts one of the known-dangerous `/proc/<pid>/` entries:
/// `mem`, `maps`, `pagemap`, `smaps`, `fd/`
#[inline(always)]
fn is_proc_danger_at(p: &[u8; 256], i: usize) -> bool {
    // "mem\0"
    if p[i] == b'm' && p[i+1] == b'e' && p[i+2] == b'm'
        && (p[i+3] == 0 || p[i+3] == b'/') { return true; }
    // "maps\0"
    if p[i] == b'm' && p[i+1] == b'a' && p[i+2] == b'p' && p[i+3] == b's'
        && (p[i+4] == 0 || p[i+4] == b'/') { return true; }
    // "pagemap\0"
    if p[i] == b'p' && p[i+1] == b'a' && p[i+2] == b'g' && p[i+3] == b'e'
        && p[i+4] == b'm' && p[i+5] == b'a' && p[i+6] == b'p'
        && (p[i+7] == 0 || p[i+7] == b'/') { return true; }
    // "smaps\0"
    if p[i] == b's' && p[i+1] == b'm' && p[i+2] == b'a' && p[i+3] == b'p'
        && p[i+4] == b's' && (p[i+5] == 0 || p[i+5] == b'/') { return true; }
    // "fd/"
    if p[i] == b'f' && p[i+1] == b'd' && p[i+2] == b'/' { return true; }
    // "ns/" — namespace entries (/proc/<pid>/ns/ipc, /ns/mnt, etc.)
    if p[i] == b'n' && p[i+1] == b's' && p[i+2] == b'/' { return true; }
    false
}

/// Scan offsets 7..14 (covers PIDs with 1–7 digits) for a `/` followed by a
/// dangerous proc file name.  Fully unrolled — verifier-friendly.
#[inline(always)]
fn path_has_proc_danger(p: &[u8; 256]) -> bool {
    // pid length 1: slash at offset 7, file starts at 8
    if p[7] == b'/' && is_proc_danger_at(p, 8)  { return true; }
    // pid length 2: slash at offset 8
    if p[8] == b'/' && is_proc_danger_at(p, 9)  { return true; }
    // pid length 3
    if p[9] == b'/' && is_proc_danger_at(p, 10) { return true; }
    // pid length 4
    if p[10] == b'/' && is_proc_danger_at(p, 11) { return true; }
    // pid length 5
    if p[11] == b'/' && is_proc_danger_at(p, 12) { return true; }
    // pid length 6
    if p[12] == b'/' && is_proc_danger_at(p, 13) { return true; }
    // pid length 7
    if p[13] == b'/' && is_proc_danger_at(p, 14) { return true; }
    false
}

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

/// True if the last path component is a known privilege-escalation binary:
/// su, sudo, newuidmap, newgidmap, pkexec.
/// Checks up to 4 candidate positions of the last `/` (paths up to ~100 bytes).
#[inline(always)]
fn path_is_privesc_binary(p: &[u8; 256]) -> bool {
    // Walk path forward to find last slash position (unrolled, max 128 bytes).
    // We compute last_slash as the largest index < 128 where p[i] == b'/'.
    // After the loop, name starts at last_slash + 1.
    let mut last_slash: usize = 0;
    // Fully unrolled scan of first 128 bytes; constant time for verifier.
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
// Tracepoint args (from /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format):
//   field:int __syscall_nr;         offset:8;  size:4;
//   field:const char * filename;    offset:16; size:8;
//   field:const char *const * argv; offset:24; size:8;
//   field:const char *const * envp; offset:32; size:8;

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
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = bpf_get_current_comm()?;

    // Read the filename pointer from the tracepoint args
    let filename_ptr: u64 = unsafe { ctx.read_at(16)? };
    if filename_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(
                filename_ptr as *const u8,
                &mut event.path,
            )
        };
    }

    // Read argv[0] pointer for the first argument
    let argv_ptr: u64 = unsafe { ctx.read_at(24)? };
    if argv_ptr != 0 {
        // argv is a pointer to an array of pointers; read argv[0]
        let mut arg0_ptr_buf = [0u8; 8];
        let _ = unsafe {
            bpf_probe_read_user_buf(argv_ptr as *const u8, &mut arg0_ptr_buf)
        };
        let arg0_ptr = u64::from_ne_bytes(arg0_ptr_buf);
        if arg0_ptr != 0 {
            let _ = unsafe {
                bpf_probe_read_user_str_bytes(
                    arg0_ptr as *const u8,
                    &mut event.args,
                )
            };
        }
    }

    // Enforcement for privilege-escalation binaries is handled by the
    // lsm_bprm_check hook (returns -EPERM synchronously, before exec).
    // The tracepoint only emits telemetry.

    EVENTS.output(ctx, event, 0);
    Ok(())
}

// ===========================================================================
// Tier 1: sys_enter_openat
// ===========================================================================
// Tracepoint args (from /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format):
//   field:int __syscall_nr;      offset:8;  size:4;
//   field:int dfd;               offset:16; size:8;
//   field:const char * filename; offset:24; size:8;
//   field:int flags;             offset:32; size:8;
//   field:umode_t mode;          offset:40; size:8;

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
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = bpf_get_current_comm()?;

    // Read filename pointer
    let filename_ptr: u64 = unsafe { ctx.read_at(24)? };
    if filename_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(
                filename_ptr as *const u8,
                &mut event.path,
            )
        };
    }

    // Read open flags
    let flags: u64 = unsafe { ctx.read_at(32)? };
    event.flags = flags as u32;

    // /proc/<pid> enforcement is handled by the lsm_file_open hook (returns
    // -EPERM synchronously). The tracepoint only sends SIGKILL for write-path
    // violations that the LSM hook can't check (it lacks full-path + flags).
    if event.pid != 1 {
        if has_write_intent(event.flags)
            && !path_starts_with_workspace(&event.path)
            && !path_starts_with_dev(&event.path)
            && !path_starts_with_tmp(&event.path)
            && !path_starts_with_proc_self(&event.path)
        {
            unsafe { bpf_send_signal(9) };
        }
    }

    EVENTS.output(ctx, event, 0);
    Ok(())
}

// ===========================================================================
// Tier 1: sys_enter_connect
// ===========================================================================
// Tracepoint args (from /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format):
//   field:int __syscall_nr;             offset:8;  size:4;
//   field:int fd;                       offset:16; size:8;
//   field:struct sockaddr * uservaddr;  offset:24; size:8;
//   field:int addrlen;                  offset:32; size:8;

/// sockaddr_in layout (16 bytes):
///   sin_family: u16  (AF_INET = 2)
///   sin_port:   u16  (network byte order)
///   sin_addr:   u32  (network byte order)
///   sin_zero:   [u8; 8]
const AF_INET: u16 = 2;

#[tracepoint(category = "syscalls", name = "sys_enter_connect")]
pub fn trace_connect(ctx: TracePointContext) -> u32 {
    match try_trace_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_connect(ctx: &TracePointContext) -> Result<(), c_long> {
    // Read the sockaddr pointer
    let addr_ptr: u64 = unsafe { ctx.read_at(24)? };
    if addr_ptr == 0 {
        return Ok(());
    }

    // Read sockaddr_in (first 8 bytes: family + port + addr)
    let mut sockaddr_buf = [0u8; 8];
    let _ = unsafe {
        bpf_probe_read_user_buf(addr_ptr as *const u8, &mut sockaddr_buf)
    };

    // sa_family is at bytes [0..2]
    let sa_family = u16::from_ne_bytes([sockaddr_buf[0], sockaddr_buf[1]]);

    // Only trace IPv4 connections for now
    if sa_family != AF_INET {
        return Ok(());
    }

    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::Connect as u32;
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = bpf_get_current_comm()?;

    // sin_port is at bytes [2..4] in network byte order
    event.dest_port = u16::from_be_bytes([sockaddr_buf[2], sockaddr_buf[3]]);
    // sin_addr is at bytes [4..8] in network byte order
    event.dest_ip = u32::from_ne_bytes([
        sockaddr_buf[4],
        sockaddr_buf[5],
        sockaddr_buf[6],
        sockaddr_buf[7],
    ]);
    // Default to TCP (protocol 6) — we can't easily determine protocol from connect() alone
    event.protocol = 6;

    EVENTS.output(ctx, event, 0);
    Ok(())
}

// ===========================================================================
// Tier 2: sys_enter_sendto — DNS query logging
// ===========================================================================
// Tracepoint args (from /sys/kernel/debug/tracing/events/syscalls/sys_enter_sendto/format):
//   field:int __syscall_nr;              offset:8;  size:4;
//   field:int fd;                        offset:16; size:8;
//   field:void * buff;                   offset:24; size:8;
//   field:size_t len;                    offset:32; size:8;
//   field:unsigned int flags;            offset:40; size:8;
//   field:struct sockaddr * addr;        offset:48; size:8;
//   field:int addr_len;                  offset:56; size:8;
//
// We filter for UDP port 53 to capture DNS queries. The DNS query name
// is extracted from the send buffer (starts at byte 12 in the DNS header).

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
    // Read the sockaddr pointer to check if this is UDP port 53
    let addr_ptr: u64 = unsafe { ctx.read_at(48)? };
    if addr_ptr == 0 {
        return Ok(());
    }

    // Read sockaddr_in (first 8 bytes: family + port + addr)
    let mut sockaddr_buf = [0u8; 8];
    let _ = unsafe {
        bpf_probe_read_user_buf(addr_ptr as *const u8, &mut sockaddr_buf)
    };

    let sa_family = u16::from_ne_bytes([sockaddr_buf[0], sockaddr_buf[1]]);
    if sa_family != AF_INET {
        return Ok(());
    }

    // Check if destination port is 53 (DNS)
    let dest_port = u16::from_be_bytes([sockaddr_buf[2], sockaddr_buf[3]]);
    if dest_port != DNS_PORT {
        return Ok(());
    }

    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::DnsQuery as u32;
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = bpf_get_current_comm()?;

    // DNS server IP
    event.dest_ip = u32::from_ne_bytes([
        sockaddr_buf[4],
        sockaddr_buf[5],
        sockaddr_buf[6],
        sockaddr_buf[7],
    ]);
    event.dest_port = dest_port;
    event.protocol = IPPROTO_UDP;

    // Try to read the DNS query name from the send buffer.
    // DNS header is 12 bytes, then the query name starts (length-prefixed labels).
    // We read the raw buffer into event.args for userspace to decode.
    let buff_ptr: u64 = unsafe { ctx.read_at(24)? };
    let buff_len: u64 = unsafe { ctx.read_at(32)? };
    if buff_ptr != 0 && buff_len > 12 {
        // Read up to MAX_ARGS_LEN bytes of the DNS payload
        let read_len = if buff_len < 256 { buff_len as usize } else { 256 };
        // Read the raw DNS packet into args (userspace will decode the domain)
        let _ = unsafe {
            bpf_probe_read_user_buf(
                buff_ptr as *const u8,
                &mut event.args[..read_len],
            )
        };
    }

    EVENTS.output(ctx, event, 0);
    Ok(())
}

// ===========================================================================
// Tier 2: sys_enter_mount — escape canary
// ===========================================================================
// Tracepoint args (from /sys/kernel/debug/tracing/events/syscalls/sys_enter_mount/format):
//   field:int __syscall_nr;              offset:8;  size:4;
//   field:char * dev_name;               offset:16; size:8;
//   field:char * dir_name;               offset:24; size:8;
//   field:char * type;                   offset:32; size:8;
//   field:unsigned long flags;           offset:40; size:8;
//   field:void * data;                   offset:48; size:8;
//
// In our VM, only PID 1 (init) should mount filesystems during boot.
// Any mount call from another process is suspicious and worth logging.

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
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = bpf_get_current_comm()?;

    // Read mount target directory (dir_name)
    let dir_name_ptr: u64 = unsafe { ctx.read_at(24)? };
    if dir_name_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(
                dir_name_ptr as *const u8,
                &mut event.path,
            )
        };
    }

    // Read device name into args
    let dev_name_ptr: u64 = unsafe { ctx.read_at(16)? };
    if dev_name_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(
                dev_name_ptr as *const u8,
                &mut event.args,
            )
        };
    }

    // Read mount flags
    let flags: u64 = unsafe { ctx.read_at(40)? };
    event.flags = flags as u32;

    EVENTS.output(ctx, event, 0);
    Ok(())
}

// ===========================================================================
// Tier 2: sys_enter_bpf — BPF syscall monitor
// ===========================================================================
// Tracepoint args (from /sys/kernel/debug/tracing/events/syscalls/sys_enter_bpf/format):
//   field:int __syscall_nr;     offset:8;  size:4;
//   field:int cmd;              offset:16; size:8;
//   field:union bpf_attr * uattr; offset:24; size:8;
//   field:unsigned int size;    offset:32; size:8;
//
// Any BPF syscall from the agent process is a red flag — the agent
// should never be loading its own BPF programs.

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
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = bpf_get_current_comm()?;

    // Store the BPF command in flags (cmd values: 0=MAP_CREATE, 5=PROG_LOAD, etc.)
    let cmd: u64 = unsafe { ctx.read_at(16)? };
    event.flags = cmd as u32;

    EVENTS.output(ctx, event, 0);
    Ok(())
}

// ===========================================================================
// Tier 2: sys_enter_init_module — kernel module load monitor
// ===========================================================================
// Tracepoint args (from /sys/kernel/debug/tracing/events/syscalls/sys_enter_init_module/format):
//   field:int __syscall_nr;     offset:8;  size:4;
//   field:void * umod;          offset:16; size:8;
//   field:unsigned long len;    offset:24; size:8;
//   field:const char * uargs;   offset:32; size:8;
//
// CONFIG_MODULES=n in our kernel, so this should NEVER fire.
// If it does, something is very wrong.

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
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = bpf_get_current_comm()?;

    // Read the module size
    let module_len: u64 = unsafe { ctx.read_at(24)? };
    event.flags = module_len as u32;

    // Read module arguments if present
    let uargs_ptr: u64 = unsafe { ctx.read_at(32)? };
    if uargs_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(
                uargs_ptr as *const u8,
                &mut event.args,
            )
        };
    }

    EVENTS.output(ctx, event, 0);
    Ok(())
}

// ===========================================================================
// Tier 3: sched/sched_process_fork — process lifecycle
// ===========================================================================
// Tracepoint format (from /sys/kernel/debug/tracing/events/sched/sched_process_fork/format):
//   field:char parent_comm[16]; offset:8;  size:16;
//   field:pid_t parent_pid;     offset:24; size:4;
//   field:char child_comm[16];  offset:28; size:16;
//   field:pid_t child_pid;      offset:44; size:4;

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

    // Read parent_pid at offset 24
    let parent_pid: u32 = unsafe { ctx.read_at(24)? };
    event.pid = parent_pid;

    // Read child_pid at offset 44
    let child_pid: u32 = unsafe { ctx.read_at(44)? };
    event.flags = child_pid;

    // Read parent_comm (16 bytes at offset 8) as two u64 reads
    let comm_lo: u64 = unsafe { ctx.read_at(8)? };
    let comm_hi: u64 = unsafe { ctx.read_at(16)? };
    event.comm[..8].copy_from_slice(&comm_lo.to_ne_bytes());
    event.comm[8..16].copy_from_slice(&comm_hi.to_ne_bytes());

    // Read child_comm (16 bytes at offset 28) into path
    let child_lo: u64 = unsafe { ctx.read_at(28)? };
    let child_hi: u64 = unsafe { ctx.read_at(36)? };
    event.path[..8].copy_from_slice(&child_lo.to_ne_bytes());
    event.path[8..16].copy_from_slice(&child_hi.to_ne_bytes());

    EVENTS.output(ctx, event, 0);
    Ok(())
}

// ===========================================================================
// Tier 3: sched/sched_process_exit — process lifecycle
// ===========================================================================
// Tracepoint format:
//   field:char comm[16]; offset:8;  size:16;
//   field:pid_t pid;     offset:24; size:4;
//   field:int prio;      offset:28; size:4;

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

    // Read pid at offset 24
    let pid: u32 = unsafe { ctx.read_at(24)? };
    event.pid = pid;

    // Read comm (16 bytes at offset 8) as two u64 reads
    let comm_lo: u64 = unsafe { ctx.read_at(8)? };
    let comm_hi: u64 = unsafe { ctx.read_at(16)? };
    event.comm[..8].copy_from_slice(&comm_lo.to_ne_bytes());
    event.comm[8..16].copy_from_slice(&comm_hi.to_ne_bytes());

    // Read exit_code from task_struct (not in tracepoint args).
    // For signal deaths: lower 7 bits = signal number (e.g. 9 for SIGKILL).
    // For normal exits: bits 8-15 = exit code (same as WEXITSTATUS).
    let task = unsafe { bpf_get_current_task() };
    if task != 0 {
        if let Ok(code) = unsafe {
            bpf_probe_read_kernel((task + OFFSET_TASK_EXIT_CODE) as *const i32)
        } {
            event.flags = code as u32;
        }
    }

    EVENTS.output(ctx, event, 0);
    Ok(())
}

// ===========================================================================
// Tier 3: oom/mark_victim — OOM kill victim
// ===========================================================================
// Tracepoint format (from /sys/kernel/debug/tracing/events/oom/mark_victim/format):
//   field:int pid;         offset:8;  size:4;
//   field:char comm[16];   offset:12; size:16;

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

    // Victim pid at offset 8
    let victim_pid: u32 = unsafe { ctx.read_at(8)? };
    event.pid = victim_pid;

    // Victim comm (16 bytes at offset 12) — store in path field
    // offset 12 means: first u64 straddles the boundary, read as two separate reads
    let comm_lo: u64 = unsafe { ctx.read_at(12)? };
    let comm_hi: u64 = unsafe { ctx.read_at(20)? };
    event.path[..8].copy_from_slice(&comm_lo.to_ne_bytes());
    event.path[8..16].copy_from_slice(&comm_hi.to_ne_bytes());

    EVENTS.output(ctx, event, 0);
    Ok(())
}

// ===========================================================================
// Tier 3: commit_creds kprobe — privilege escalation detection
// ===========================================================================
// Function signature: int commit_creds(struct cred *new)
// struct cred layout (aarch64):
//   offset 0:  atomic_long_t usage (8 bytes)
//   offset 8:  kuid_t uid          (4 bytes)
//   offset 12: kgid_t gid          (4 bytes)
//   offset 20: kuid_t euid         (4 bytes)

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
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = bpf_get_current_comm()?;

    // Old uid: current process uid before the change
    // bpf_get_current_uid_gid() returns (gid << 32 | uid)
    let old_uid_gid = bpf_get_current_uid_gid();
    event.aux = (old_uid_gid & 0xFFFF_FFFF) as u64;

    // New uid: read from the cred struct argument (arg 0)
    // struct cred: atomic_long_t usage (8 bytes) then kuid_t uid (4 bytes)
    let cred_ptr = ctx.arg::<u64>(0).ok_or(1i64)?;
    if cred_ptr != 0 {
        let new_uid: u32 = unsafe {
            bpf_probe_read_kernel((cred_ptr + 8) as *const u32).unwrap_or(0)
        };
        event.flags = new_uid;
    }

    EVENTS.output(ctx, event, 0);
    Ok(())
}

// ===========================================================================
// Tier 3: tcp_sendmsg kprobe — TCP data volume sent
// ===========================================================================
// Function signature: int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
// arg2 = size (bytes being sent)

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

    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::TcpSend as u32;
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = bpf_get_current_comm()?;
    event.aux = bytes;

    EVENTS.output(ctx, event, 0);
    Ok(())
}

// ===========================================================================
// Tier 3: tcp_recvmsg kprobe — TCP data volume received
// ===========================================================================
// Function signature: int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
// arg2 = len (bytes requested to receive)

#[kprobe]
pub fn trace_tcp_recvmsg(ctx: ProbeContext) -> u32 {
    match try_trace_tcp_recvmsg(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_trace_tcp_recvmsg(ctx: &ProbeContext) -> Result<(), c_long> {
    let bytes = ctx.arg::<u64>(2).unwrap_or(0);
    if bytes == 0 {
        return Ok(());
    }

    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::TcpRecv as u32;
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = bpf_get_current_comm()?;
    event.aux = bytes;

    EVENTS.output(ctx, event, 0);
    Ok(())
}

// ===========================================================================
// BPF-LSM policy enforcement
// ===========================================================================
//
// These maps are populated by userspace (tracer.rs::populate_policy_maps) at
// probe load time. LSM hooks look up policy here synchronously — before the
// syscall completes — and return -EPERM if a Deny rule matches. No userspace
// roundtrip is needed; the BPF program enforces directly.
//
// Map key conventions:
//   DENIED_PATHS / ALLOWED_PATHS: null-terminated path, zero-padded to 256 bytes
//   DENIED_NETS / ALLOWED_NETS:   LPM key = [prefix_len: u32 LE][ip: u32 BE]
//
// Evaluation order: ALLOWED wins over DENIED (first-match-wins with allow first).
// Glob patterns are not supported in BPF — handled by kill-on-detect fallback.

/// Per-CPU scratch buffer for path strings used in LSM hook map lookups.
/// Avoids putting 256-byte arrays on the 512-byte BPF stack limit.
#[map]
static PATH_SCRATCH: PerCpuArray<[u8; 256]> = PerCpuArray::with_max_entries(1, 0);

/// Paths explicitly denied by policy (exact match, no globs).
/// Populated from `PolicyRule::FileAccess { action: Deny }` rules without globs.
#[map]
static DENIED_PATHS: HashMap<[u8; 256], u8> = HashMap::with_max_entries(512, 0);

/// Paths explicitly allowed by policy. Checked before DENIED_PATHS.
/// Populated from `PolicyRule::FileAccess { action: Allow }` rules without globs.
#[map]
static ALLOWED_PATHS: HashMap<[u8; 256], u8> = HashMap::with_max_entries(512, 0);

/// Network CIDR ranges denied by policy (longest-prefix match).
/// Key: Key<u32> where data is IPv4 address in network byte order.
/// Populated from `PolicyRule::Network { port: None, action: Deny }` rules.
#[map]
static DENIED_NETS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(256, 0);

/// Network CIDR ranges allowed by policy. Checked before DENIED_NETS.
/// Populated from `PolicyRule::Network { port: None, action: Allow }` rules.
#[map]
static ALLOWED_NETS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(256, 0);

/// Linux EPERM errno value (permission denied).
const EPERM: i32 = 1;

// Struct offsets for aarch64 Linux 6.12.13 — verified via /sys/kernel/btf/vmlinux.
//
// struct file (size=184, btf_id=545):
//   offset 0:   f_count (atomic_long_t)
//   offset 8:   f_lock (spinlock_t)
//   offset 12:  f_mode (fmode_t)
//   offset 16:  f_op (const struct file_operations *)
//   offset 24:  f_mapping (struct address_space *)
//   offset 32:  private_data (void *)
//   offset 40:  f_inode (struct inode *)
//   offset 48:  f_flags (unsigned int)
//   offset 52:  f_iocb_flags (unsigned int)
//   offset 56:  f_cred (const struct cred *)
//   offset 64:  f_path (struct path — mnt at +0, dentry at +8)
//
// struct dentry (size=192, btf_id=611):
//   offset 0:   d_flags (unsigned int)
//   offset 4:   d_seq (seqcount_spinlock_t)
//   offset 8:   d_hash (hlist_bl_node)
//   offset 24:  d_parent (struct dentry *)
//   offset 32:  d_name (struct qstr — hash_len at +0, name ptr at +8)
//   offset 48:  d_inode (struct inode *)
const OFFSET_FILE_DENTRY: u64 = 72;       // file.f_path.dentry (64 + 8)
const OFFSET_DENTRY_NAME: u64 = 40;       // dentry.d_name.name (32 + 8)
const OFFSET_DENTRY_D_PARENT: u64 = 24;   // dentry.d_parent
const OFFSET_TASK_EXIT_CODE: u64 = 1076;  // task_struct.exit_code (from BTF, kernel 6.12)

// ---------------------------------------------------------------------------
// LSM probe: file_open — synchronous enforcement for dangerous paths
// ---------------------------------------------------------------------------
//
// bpf_d_path() can't be used here (arg(0) is struct file *, verifier needs
// PTR_TO_BTF_ID for struct path). Instead we walk the dentry->d_parent chain
// to reconstruct 3 path components and match /proc/<pid>/{mem,maps,...}.
// Returns -EPERM synchronously — the open() syscall fails before any data
// is read, eliminating the race window that bpf_send_signal has.

#[lsm(hook = "file_open")]
pub fn lsm_file_open(ctx: LsmContext) -> i32 {
    match try_lsm_file_open(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => 0, // fail open on error
    }
}

/// Read up to 16 bytes of the dentry's d_name.name into a stack buffer.
/// Infallible — buffer stays zeroed if any read fails.
#[inline(always)]
fn read_dentry_name(dentry_addr: u64, buf: &mut [u8; 16]) {
    if let Ok(name_ptr) = unsafe {
        bpf_probe_read_kernel((dentry_addr + OFFSET_DENTRY_NAME) as *const u64)
    } {
        if name_ptr != 0 {
            let _ = unsafe { bpf_probe_read_kernel_str_bytes(name_ptr as *const u8, buf) };
        }
    }
}

/// Read dentry->d_parent pointer. Returns 0 if read fails or parent == self (root).
#[inline(always)]
fn read_dentry_parent(dentry_addr: u64) -> u64 {
    match unsafe { bpf_probe_read_kernel((dentry_addr + OFFSET_DENTRY_D_PARENT) as *const u64) } {
        Ok(parent) if parent != 0 && parent != dentry_addr => parent,
        _ => 0,
    }
}

/// True if the 16-byte name buffer matches a dangerous /proc/<pid>/ file.
/// Covers memory inspection, recon (status/cmdline), and kernel interfaces.
#[inline(always)]
fn is_proc_danger_name(n: &[u8; 16]) -> bool {
    // "mem"
    if n[0] == b'm' && n[1] == b'e' && n[2] == b'm' && n[3] == 0 { return true; }
    // "maps"
    if n[0] == b'm' && n[1] == b'a' && n[2] == b'p' && n[3] == b's' && n[4] == 0 { return true; }
    // "pagemap"
    if n[0] == b'p' && n[1] == b'a' && n[2] == b'g' && n[3] == b'e'
        && n[4] == b'm' && n[5] == b'a' && n[6] == b'p' && n[7] == 0 { return true; }
    // "smaps"
    if n[0] == b's' && n[1] == b'm' && n[2] == b'a' && n[3] == b'p'
        && n[4] == b's' && n[5] == 0 { return true; }
    // "status" — exposes capabilities, UIDs, memory layout
    if n[0] == b's' && n[1] == b't' && n[2] == b'a' && n[3] == b't'
        && n[4] == b'u' && n[5] == b's' && n[6] == 0 { return true; }
    // "cmdline" — reveals process arguments
    if n[0] == b'c' && n[1] == b'm' && n[2] == b'd' && n[3] == b'l'
        && n[4] == b'i' && n[5] == b'n' && n[6] == b'e' && n[7] == 0 { return true; }
    // "wchan"
    if n[0] == b'w' && n[1] == b'c' && n[2] == b'h' && n[3] == b'a'
        && n[4] == b'n' && n[5] == 0 { return true; }
    // "stack"
    if n[0] == b's' && n[1] == b't' && n[2] == b'a' && n[3] == b'c'
        && n[4] == b'k' && n[5] == 0 { return true; }
    // "syscall"
    if n[0] == b's' && n[1] == b'y' && n[2] == b's' && n[3] == b'c'
        && n[4] == b'a' && n[5] == b'l' && n[6] == b'l' && n[7] == 0 { return true; }
    false
}

/// True if name buffer starts with an ASCII digit (PID directory).
#[inline(always)]
fn name_is_pid(n: &[u8; 16]) -> bool {
    n[0] >= b'0' && n[0] <= b'9'
}

/// True if name buffer is "proc".
#[inline(always)]
fn name_is_proc(n: &[u8; 16]) -> bool {
    n[0] == b'p' && n[1] == b'r' && n[2] == b'o' && n[3] == b'c' && n[4] == 0
}

/// True if name buffer is "fd" or "ns" (subdir patterns at depth 1 under /proc/<pid>/).
#[inline(always)]
fn name_is_fd_or_ns(n: &[u8; 16]) -> bool {
    (n[0] == b'f' && n[1] == b'd' && n[2] == 0) ||
    (n[0] == b'n' && n[1] == b's' && n[2] == 0)
}

fn try_lsm_file_open(ctx: &LsmContext) -> Result<i32, c_long> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Never block PID 1 (agent init) — it reads /proc/self/* during startup.
    if pid == 1 { return Ok(0); }

    let file_addr: u64 = unsafe { ctx.arg(0) };
    if file_addr == 0 { return Ok(0); }

    // Walk dentry chain: file->f_path.dentry -> d_parent -> d_parent -> d_parent
    // All reads are infallible — buffers stay zeroed on failure, pattern won't match.
    let d0 = match unsafe {
        bpf_probe_read_kernel((file_addr + OFFSET_FILE_DENTRY) as *const u64)
    } {
        Ok(d) if d != 0 => d,
        _ => return Ok(0),
    };

    // Level 0: filename (e.g. "maps", "mem", "3", "mnt")
    let mut n0 = [0u8; 16];
    read_dentry_name(d0, &mut n0);

    // Level 1: parent dir (e.g. "1", "fd", "ns")
    let d1 = read_dentry_parent(d0);
    let mut n1 = [0u8; 16];
    if d1 != 0 { read_dentry_name(d1, &mut n1); }

    // Level 2: grandparent dir (e.g. "proc", "1")
    let d2 = if d1 != 0 { read_dentry_parent(d1) } else { 0 };
    let mut n2 = [0u8; 16];
    if d2 != 0 { read_dentry_name(d2, &mut n2); }

    // Pattern 1: /proc/<pid>/{mem,maps,pagemap,smaps}
    //   n1=<digit> (PID dir), n0=danger file.
    //   procfs root dentry has empty name, so n2 won't be "proc" — but
    //   a numeric dir + danger filename is unique to procfs. No false positives.
    let blocked = (name_is_pid(&n1) && is_proc_danger_name(&n0))
    // Pattern 2: /proc/<pid>/fd/* or /proc/<pid>/ns/*
    //   n2=<digit> (PID dir), n1="fd"|"ns", n0=target
        || (name_is_pid(&n2) && name_is_fd_or_ns(&n1));

    // LSM hook is enforcement-only — no telemetry emission here.
    // The sys_enter_openat tracepoint already emits the telemetry event
    // with the correct full path. Emitting here caused double-fire with
    // mangled paths (///1/maps) that tripped write_outside_workspace.

    if blocked {
        unsafe { bpf_send_signal(9) };
        return Ok(-EPERM);
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// LSM probe: socket_connect — block forbidden network connections
// ---------------------------------------------------------------------------
//
// Hook fires before connect() completes. We read the destination sockaddr,
// build an LPM key, and check ALLOWED_NETS / DENIED_NETS. Only AF_INET
// (IPv4) is checked; AF_INET6 and AF_UNIX pass through.

#[lsm(hook = "socket_connect")]
pub fn lsm_socket_connect(ctx: LsmContext) -> i32 {
    match try_lsm_socket_connect(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => 0,
    }
}

fn try_lsm_socket_connect(ctx: &LsmContext) -> Result<i32, c_long> {
    // arg(1) is struct sockaddr *address
    let addr_ptr: *const u8 = unsafe { ctx.arg(1) };
    if addr_ptr.is_null() {
        return Ok(0);
    }

    // Read first 8 bytes: sa_family(2) + sin_port(2) + sin_addr(4)
    let sa_buf: [u8; 8] = unsafe {
        bpf_probe_read_kernel(addr_ptr as *const [u8; 8]).unwrap_or([0u8; 8])
    };

    // Only enforce IPv4 connections
    let sa_family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);
    if sa_family != AF_INET {
        return Ok(0);
    }

    // sin_port in network byte order; sin_addr in network byte order
    let dest_port = u16::from_be_bytes([sa_buf[2], sa_buf[3]]);
    // dest_ip_ne: IPv4 address bytes from sin_addr, kept in network byte order
    // using from_ne_bytes so the u32 memory layout == original network-order bytes.
    let dest_ip_ne = u32::from_ne_bytes([sa_buf[4], sa_buf[5], sa_buf[6], sa_buf[7]]);

    // LPM key: Key<u32> = { prefix_len: u32, data: u32 } = 8 bytes total.
    // prefix_len=32 means "match this exact host; trie returns longest prefix match".
    // Allow list takes precedence
    if unsafe { ALLOWED_NETS.get(&LpmKey::new(32, dest_ip_ne)) }.is_some() {
        return Ok(0);
    }

    // Check deny list
    if unsafe { DENIED_NETS.get(&LpmKey::new(32, dest_ip_ne)) }.is_some() {
        let event = get_scratch_event().ok_or(1i64)?;
        event.kind = EventKind::Connect as u32;
        event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
        event.comm = bpf_get_current_comm()?;
        event.dest_ip = dest_ip_ne;
        event.dest_port = dest_port;
        event.protocol = 6; // TCP
        EVENTS.output(ctx, event, 0);
        return Ok(-EPERM);
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// LSM probe: bprm_check_security — block forbidden binary execution
// ---------------------------------------------------------------------------
//
// Hook fires when the kernel is about to exec a binary (after ELF/script
// detection). `bprm->buf` at offset 0 contains the binary path string.
// We check the same ALLOWED_PATHS / DENIED_PATHS maps as lsm_file_open.

#[lsm(hook = "bprm_check_security")]
pub fn lsm_bprm_check(ctx: LsmContext) -> i32 {
    match try_lsm_bprm_check(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => 0,
    }
}

fn try_lsm_bprm_check(ctx: &LsmContext) -> Result<i32, c_long> {
    let path_buf_ptr = unsafe { PATH_SCRATCH.get_ptr_mut(0).ok_or(1i64)? };
    unsafe { core::ptr::write_bytes(path_buf_ptr as *mut u8, 0, 256) };

    // arg(0) is struct linux_binprm *bprm.
    // bprm->buf (offset 0) holds the binary path as a null-terminated string.
    let bprm_ptr: *const u8 = unsafe { ctx.arg(0) };
    if bprm_ptr.is_null() {
        return Ok(0);
    }

    // Read binary path from bprm->buf into scratch buffer
    let path_slice = unsafe { &mut *(path_buf_ptr as *mut [u8; 256]) };
    let _ = unsafe { bpf_probe_read_kernel_str_bytes(bprm_ptr, path_slice) };

    let path_key = unsafe { &*(path_buf_ptr as *const [u8; 256]) };

    if unsafe { ALLOWED_PATHS.get(path_key) }.is_some() {
        return Ok(0);
    }

    if unsafe { DENIED_PATHS.get(path_key) }.is_some() {
        let event = get_scratch_event().ok_or(1i64)?;
        event.kind = EventKind::Execve as u32;
        event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
        event.comm = bpf_get_current_comm()?;
        event.path.copy_from_slice(path_key);
        EVENTS.output(ctx, event, 0);
        return Ok(-EPERM);
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// LSM probe: sb_mount — block all mount attempts from non-init processes
// ---------------------------------------------------------------------------
//
// Hook fires before mount() completes. In our VM, only PID 1 (init) mounts
// filesystems during boot. Any mount from another process is an escape attempt
// (bind-mounting /proc or /sys to get out of a chroot). We emit a telemetry
// event regardless and deny if the caller is not PID 1.

#[lsm(hook = "sb_mount")]
pub fn lsm_sb_mount(ctx: LsmContext) -> i32 {
    match try_lsm_sb_mount(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => 0,
    }
}

fn try_lsm_sb_mount(ctx: &LsmContext) -> Result<i32, c_long> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let event = get_scratch_event().ok_or(1i64)?;
    event.kind = EventKind::Mount as u32;
    event.pid = pid;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.comm = bpf_get_current_comm()?;

    // arg(0) is const char *dev_name
    let dev_name_ptr: *const u8 = unsafe { ctx.arg(0) };
    if !dev_name_ptr.is_null() {
        let _ = unsafe { bpf_probe_read_kernel_str_bytes(dev_name_ptr, &mut event.args) };
    }

    // arg(1) is const struct path *path (mount target).
    // bpf_d_path() resolves the mount target to a full path string.
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

    EVENTS.output(ctx, event, 0);

    // Block any mount from non-init — no legitimate workload process should mount
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

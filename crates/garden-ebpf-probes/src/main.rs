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
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns,
        bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{PerCpuArray, PerfEventArray},
    programs::TracePointContext,
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

// ---------------------------------------------------------------------------
// BPF panic handler (required for no_std)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

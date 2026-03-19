//! Garden AI eBPF kernel-side security probes.
//!
//! This is a `#![no_std]` BPF program compiled to `bpfel-unknown-none`.
//! It attaches to syscall tracepoints and emits `RawSecurityEvent`s
//! through a shared `PerfEventArray` map.
//!
//! ## Tier 1 Probes
//! - `trace_execve` — process execution (sys_enter_execve)
//! - `trace_openat` — file access (sys_enter_openat)
//! - `trace_connect` — network connections (sys_enter_connect)

#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_long,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns,
        bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use garden_ebpf_common::{EventKind, RawSecurityEvent, MAX_PATH_LEN};

// ---------------------------------------------------------------------------
// Shared perf event map — userspace reads from this via AsyncPerfEventArray
// ---------------------------------------------------------------------------

#[map]
static EVENTS: PerfEventArray<RawSecurityEvent> = PerfEventArray::new(0);

// ---------------------------------------------------------------------------
// Tier 1: sys_enter_execve
// ---------------------------------------------------------------------------
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
    let mut event = RawSecurityEvent::zeroed();
    event.kind = EventKind::Execve as u32;
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    bpf_get_current_comm(&mut event.comm)?;

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

    EVENTS.output(ctx, &event, 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tier 1: sys_enter_openat
// ---------------------------------------------------------------------------
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
    let mut event = RawSecurityEvent::zeroed();
    event.kind = EventKind::Openat as u32;
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    bpf_get_current_comm(&mut event.comm)?;

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

    EVENTS.output(ctx, &event, 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tier 1: sys_enter_connect
// ---------------------------------------------------------------------------
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

    let mut event = RawSecurityEvent::zeroed();
    event.kind = EventKind::Connect as u32;
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    bpf_get_current_comm(&mut event.comm)?;

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

    EVENTS.output(ctx, &event, 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// BPF panic handler (required for no_std)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

# eBPF Security Design — Garden AI Sandbox

## Overview

Garden AI uses eBPF as the observability and enforcement backbone for a hardware-isolated micro-VM sandbox running on Apple Silicon. The system runs AI agent workloads inside an aarch64 Linux VM (managed by Apple's Virtualization.framework) and monitors them for security policy violations. This document explains the eBPF architecture, probe selection rationale, and the two-layer enforcement model.

---

## Why eBPF for a VM Sandbox?

The standard approach for sandboxing is seccomp-BPF — attach a syscall filter to a process before exec and let the kernel enforce it. That works well for single-process sandboxes with a known syscall surface. It has two limitations in this context:

1. **AI agent workloads are opaque.** The workload is a general-purpose agent that may run Python, Node, shell scripts, compilers, or anything else. A static seccomp allowlist that doesn't break arbitrary toolchains is difficult to construct upfront.

2. **We need rich telemetry, not just block/allow.** The host (macOS daemon) needs a structured event stream — which process connected where, what files were opened, whether credentials changed — for audit logging, policy tuning, and UI display. Seccomp alone returns EPERM silently; it produces no structured events.

eBPF solves both problems. Tracepoints and kprobes attach to the kernel non-intrusively, capture rich context (pid, comm, arguments, timestamps), and emit structured events to userspace via a `PerfEventArray`. This gives full observability across all processes in the VM regardless of how they were spawned, without requiring any modification to the workloads.

Tracepoints fire *after* the syscall completes — they are async and read-only with respect to the syscall result. This is why single-operation policy violations are enforced by **BPF-LSM hooks** (synchronous, return `-EPERM` before the syscall completes) while tracepoints remain the observability layer. Kill-on-detect is retained only for stateful violations (byte-count thresholds) that span multiple syscalls and have no single LSM hook.

---

## Kernel Configuration

The guest kernel (Linux 6.12.13, cross-compiled for aarch64) requires specific configuration for the eBPF stack to work:

| Config | Value | Purpose |
|--------|-------|---------|
| `CONFIG_BPF_SYSCALL` | y | Enable the `bpf()` syscall for loading programs |
| `CONFIG_BPF_JIT` | y | JIT-compile BPF bytecode to native aarch64 instructions |
| `CONFIG_DEBUG_INFO_BTF` | y | Emit BPF Type Format data — required for CO-RE (Compile Once, Run Everywhere) and for aya to correctly resolve kernel struct layouts |
| `CONFIG_KPROBES` | y | Enable kprobe attachment points on arbitrary kernel functions |
| `CONFIG_KPROBE_EVENTS` | y | Expose kprobes as trace events |
| `CONFIG_FTRACE_SYSCALLS` | y | Generate `sys_enter_*` / `sys_exit_*` tracepoints for all syscalls |
| `CONFIG_PERF_EVENTS` | y | Enable the perf subsystem — required for `PerfEventArray` ring buffer |
| `CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT` | y | Use the toolchain's DWARF version (avoids pahole version conflicts) |
| `CONFIG_DEBUG_INFO_REDUCED` | n | Must be off — reduced debug info breaks BTF generation |
| `CONFIG_BPF_LSM` | y | Enable BPF programs as Linux Security Module hooks — required for synchronous pre-syscall enforcement |
| `CONFIG_LSM` | `"...,bpf"` | Must include `bpf` at the end or LSM hooks exist but are never invoked |

`CONFIG_DEBUG_INFO_BTF` is the most critical and fragile setting. `olddefconfig` silently drops it if `CONFIG_DEBUG_INFO_REDUCED=y` is present (which the arm64 defconfig sets). The build script explicitly sets `CONFIG_DEBUG_INFO_REDUCED=n` and verifies all critical configs survived after the dependency resolution pass.

---

## Probe Architecture

Probes are organized into three tiers by criticality.

### Tier 1 — Required (process exec, file access, network)

These three probes must attach or the agent aborts startup. They cover the highest-value security signals for an AI agent workload.

| Probe | Type | Kernel hook | What it captures |
|-------|------|------------|-----------------|
| `trace_execve` | tracepoint | `syscalls/sys_enter_execve` | Every process execution: binary path, argv[0], PID |
| `trace_openat` | tracepoint | `syscalls/sys_enter_openat` | Every file open: path, open flags (O_RDONLY, O_WRONLY, etc.) |
| `trace_connect` | tracepoint | `syscalls/sys_enter_connect` | Every outbound TCP/UDP connection: dest IP, dest port |

**Why `execve` and not `execveat`?** `execveat` is the modern variant that takes a dirfd, but in practice virtually all userspace code — including `sh`, Python, Node — calls the `execve` syscall. Monitoring `execve` captures the full workload.

**Why `openat` and not `open`?** `open(2)` is a legacy wrapper. On aarch64 Linux, `open` is not a native syscall — glibc maps it to `openat(AT_FDCWD, ...)`. All file opens go through `openat`.

**Why `connect` for network?** `connect` is the chokepoint for all client-initiated TCP and UDP connections. DNS lookups, HTTP requests, database connections — they all call `connect`. Monitoring here gives complete outbound network visibility.

### Tier 2 — Optional (escape canaries)

These probes attach if available and log warnings if they can't. They are "should never fire" monitors for a well-behaved AI agent.

| Probe | Type | Kernel hook | What it captures | Why it matters |
|-------|------|------------|-----------------|---------------|
| `trace_sendto` | tracepoint | `syscalls/sys_enter_sendto` | UDP sends filtered to port 53 | DNS query visibility — the domain name is decoded from the DNS wire format in the payload |
| `trace_mount` | tracepoint | `syscalls/sys_enter_mount` | Any mount syscall | Escape canary: an AI agent should never mount filesystems. If this fires from a non-init process it's a red flag |
| `trace_bpf` | tracepoint | `syscalls/sys_enter_bpf` | BPF syscall with command code | The agent itself loads eBPF programs; if the workload tries to load BPF programs, that's suspicious |
| `trace_init_module` | tracepoint | `syscalls/sys_enter_init_module` | Kernel module load | The kernel is built with `CONFIG_MODULES=n` so this should truly never fire. If it does, something is deeply wrong |

**`CONFIG_MODULES=n`** means `sys_enter_init_module` tracepoint doesn't exist in the kernel. The probe attachment fails with a warning — that's expected and fine. It would only matter if modules were re-enabled.

### Tier 3 — Optional (process lifecycle + privilege + data volume)

These probes require the kernel config additions (`CONFIG_KPROBES`, `CONFIG_DEBUG_INFO_BTF`) made in the most recent kernel rebuild. They provide richer forensic context.

| Probe | Type | Kernel hook | What it captures |
|-------|------|------------|-----------------|
| `trace_fork` | tracepoint | `sched/sched_process_fork` | Process fork: parent PID/comm and child PID/comm |
| `trace_exit` | tracepoint | `sched/sched_process_exit` | Process exit with exit code |
| `trace_oom_victim` | tracepoint | `oom/mark_victim` | OOM killer selection: victim PID and comm |
| `trace_commit_creds` | kprobe | `commit_creds()` | Credential change: old UID → new UID (privilege escalation detection) |
| `trace_tcp_sendmsg` | kprobe | `tcp_sendmsg()` | TCP bytes sent per call (data exfiltration volume) |
| `trace_tcp_recvmsg` | kprobe | `tcp_recvmsg()` | TCP bytes received per call (large download detection) |

**Why kprobes for commit_creds and tcp_sendmsg?** These are not syscalls — they're internal kernel functions with no corresponding tracepoint. Kprobes let us attach to arbitrary kernel function entry points. `commit_creds` is called whenever a process changes its credentials (setuid, sudo, privilege escalation). `tcp_sendmsg`/`tcp_recvmsg` are called for every TCP data transfer — the byte count in arg2 lets us detect large data exfiltration without inspecting packet contents.

**Why fork tracepoint matters:** AI workloads often spawn many child processes (shell commands, subinterpreters, parallel jobs). Tracking the fork tree lets the host daemon correlate events to their root spawner — an exec inside a deeply nested fork chain can be traced back to the original `execute_command` call.

---

## The Stack Limit Problem

BPF programs run on the kernel stack, which is limited to **512 bytes**. `RawSecurityEvent` is 564 bytes — it exceeds the limit and cannot be allocated on the BPF stack.

The solution is a `PerCpuArray` map with a single entry:

```rust
#[map]
static SCRATCH: PerCpuArray<RawSecurityEvent> = PerCpuArray::with_max_entries(1, 0);
```

Each CPU gets its own independent copy of the map entry. BPF programs run with preemption disabled on a single CPU, so there are no concurrent accesses to the same slot — no locking needed. The program fetches the per-CPU pointer, zeroes it, fills in the event fields, and outputs it to the perf ring buffer.

---

## Event Flow

```
Guest kernel
  │
  │  BPF-LSM hooks (synchronous, pre-syscall)
  │  → look up DENIED_PATHS / DENIED_NETS / ALLOWED_* maps
  │  → return -EPERM if denied (syscall never completes)
  │  → emit event to EVENTS ring buffer for telemetry
  │
  │  eBPF tracepoints + kprobes (async, post-syscall)
  │  → fill RawSecurityEvent in PerCpuArray scratch
  │  → EVENTS.output() → PerfEventArray ring buffer
  │
Garden agent (guest userspace, PID 1)
  │
  │  Per-CPU async tasks drain PerfEventArray
  │  → convert_raw_event() → SecurityEvent (typed)
  │  → policy.evaluate() → PolicyAction
  │  → if Deny AND stateful (TcpSend/TcpRecv):
  │      libc::kill(pid, SIGKILL)   ← stateful-only kill-on-detect
  │  → mpsc channel → NDJSON serializer
  │
  │  vSock port 6001 → host daemon
  │
Garden daemon (host, macOS)
  │
  │  Receives NDJSON stream
  │  → parse SecurityEvent
  │  → detect_violation() → Option<Violation>
  │  → write to ~/.garden/sessions/{id}/events.ndjson
  │  → broadcast to :10001 TCP (UI / external tools)
```

---

## Three-Layer Enforcement

### Layer 1 — BPF-LSM (synchronous, single-operation policy violations)

BPF-LSM programs run as Linux Security Module hooks. They execute *synchronously inside the kernel*, before the syscall completes, and can return `-EPERM` to deny the operation. The process never sees a successful result — the syscall fails immediately.

Four LSM hooks are attached:

| Hook | Protects against |
|------|-----------------|
| `file_open` | Unauthorized file reads/writes (e.g. `/etc/shadow`) |
| `socket_connect` | Unauthorized outbound network connections (CIDR-based) |
| `bprm_check_security` | Unauthorized binary execution |
| `sb_mount` | Filesystem escape via mount (blocked for all non-init PIDs) |

Policy is encoded into BPF maps at probe load time:
- `DENIED_PATHS` / `ALLOWED_PATHS`: exact-path `HashMap<[u8;256], u8>` lookups
- `DENIED_NETS` / `ALLOWED_NETS`: CIDR `LpmTrie<[u8;8], u8>` lookups (longest prefix match)

**Limitation:** BPF cannot evaluate glob patterns. `FileAccess` rules with wildcards (e.g. `/workspace/**`) are not encoded into LSM maps and fall back to kill-on-detect.

### Layer 2 — Kill-on-detect (stateful violations only)

Kill-on-detect (`SIGKILL` from the perf event loop) is now restricted to violations that span multiple syscalls and have no single LSM hook:
- `TcpSend` byte threshold — accumulated over multiple `tcp_sendmsg` calls
- `TcpRecv` byte threshold — accumulated over multiple `tcp_recvmsg` calls

For all other event types, the BPF-LSM hook fires first. Killing in the perf loop would be redundant and racy; it's suppressed for non-stateful events.

### Layer 3 — Seccomp baseline (pre-emptive, for spawned commands)

Every command spawned via `execute_command` applies a seccomp-BPF filter in the child process after `fork()` but before `exec()` (via `pre_exec` hook). The filter uses a default-allow policy with a blocklist of syscalls that a legitimate AI agent workload should never need.

The `seccompiler` crate builds the BPF filter at agent startup and stores it in `GardenAgentImpl`. The filter is applied in the child process, so it cannot affect the agent itself.

### Layer comparison

| Scenario | BPF-LSM | Kill-on-detect | Seccomp |
|----------|---------|---------------|---------|
| Workload opens `/etc/shadow` | `-EPERM` before open returns | — | — |
| Workload connects to denied IP | `-EPERM` before connect returns | — | — |
| Workload calls `mount()` | `-EPERM` (non-PID-1) | — | `-EPERM` |
| Workload forks and child calls `ptrace` | — | — | `-EPERM` |
| Workload sends > N bytes over TCP | — | SIGKILL (stateful) | — |
| Glob-pattern file deny (`/workspace/**`) | — (no BPF glob) | SIGKILL | — |
| Agent itself is compromised | hooks cover all processes | covers all processes | N/A |

---

## Seccomp Baseline — Blocked Syscalls

The baseline blocks syscalls that are never needed by AI agent workloads and represent significant escalation or escape vectors. Default action is Allow; blocked syscalls return `EPERM`.

| Syscall | aarch64 nr | Why blocked |
|---------|-----------|-------------|
| `mount` | 40 | Filesystem escape — allows mounting host paths or creating new namespaces |
| `umount2` | 39 | Filesystem escape — unmounting could expose underlying host paths |
| `init_module` | 105 | Kernel module load — would give kernel-level code execution |
| `finit_module` | 273 | Kernel module load via file descriptor — same risk as init_module |
| `delete_module` | 106 | Kernel module removal — could remove security modules |
| `ptrace` | 117 | Process inspection/injection — allows reading/writing arbitrary process memory, bypassing all sandbox controls |
| `kexec_load` | 104 | Kernel replacement — replaces the running kernel, destroying all isolation |
| `kexec_file_load` | 294 | Kernel replacement via file — same risk as kexec_load |
| `reboot` | 142 | VM shutdown/restart — allows the workload to kill the VM |
| `swapon` | 224 | Swap activation — could be used to write sensitive data to a block device |
| `swapoff` | 225 | Swap deactivation — paired with swapon for storage manipulation |
| `sethostname` | 161 | Identity change — could be used to confuse logging/monitoring |
| `setdomainname` | 162 | Identity change — same class of risk as sethostname |
| `perf_event_open` | 241 | Performance monitoring — can be used to observe kernel internals and time side-channel attacks |

**Not blocked (intentionally):**
- `clone` / `unshare` with namespace flags: blocking these breaks Python's subprocess module and many tools. Namespace isolation is enforced at the VM boundary instead.
- `socket` / `connect` / `bind`: network access is controlled by eBPF policy (kill-on-detect for IP/port rules) rather than seccomp. Blocking `connect` via seccomp would be a blunt instrument that can't distinguish between allowed and denied destinations.
- `openat`: file access control is policy-based (glob patterns), not syscall-based. Blocking `openat` breaks everything.

---

## BTF and CO-RE

`CONFIG_DEBUG_INFO_BTF=y` embeds BPF Type Format data into the kernel's `vmlinux` binary. This is what allows the `aya` runtime to verify and load BPF programs correctly on the target kernel without recompiling.

The BTF generation step is the most resource-intensive part of the kernel build. `pahole` (from the `dwarves` package) processes the full DWARF debug information in `vmlinux` and converts it to BTF. This step requires approximately 5GB of RAM. To make it feasible in Docker:

- Disabled heavyweight subsystems: `CONFIG_SOUND=n`, `CONFIG_USB_SUPPORT=n`, `CONFIG_DRM=n`, `CONFIG_BLUETOOTH=n`, `CONFIG_WLAN=n`, `CONFIG_KVM=n`, `CONFIG_INFINIBAND=n`, and all vendor ethernet drivers except VirtIO
- Set Docker memory limit to 6GB (`--memory 6g`)
- Used `CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y` to let the toolchain choose the DWARF format (pahole 1.24+ can handle DWARF5; older pahole requires DWARF4 via `CONFIG_DEBUG_INFO_DWARF4=y`)

The build script verifies all critical configs survived `olddefconfig` before starting the 5-10 minute compilation.

---

## Apple Virtualization.framework Integration

The eBPF stack runs entirely inside the guest VM. From the host (macOS) perspective, the VM is an opaque aarch64 Linux process managed via `Virtualization.framework`. The host daemon communicates with the guest only through two vSock channels:

- **Port 6000** — gRPC for command execution (`execute_command`, `get_status`)
- **Port 6001** — NDJSON telemetry stream from the eBPF tracer

This means:
- The host never touches the guest kernel or BPF programs
- The guest cannot tamper with the host-side policy evaluator or session log
- The VM hardware boundary (Apple Hypervisor) is the primary isolation layer; eBPF + seccomp are defense-in-depth within the VM

This architecture allows the host policy engine to be the source of truth. Even if the AI workload inside the VM fully compromises the guest Linux userspace (including the agent binary), the host still receives the eBPF event stream, writes the session log, and can stop the VM via `DaemonService.StopVm`.

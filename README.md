# Garden AI

<!--
  Note to self (Malcolm Griffin):
  This project was inspired by seeing a role for a sandbox systems developer
  at Anthropic on 08/04/2025.
-->

**Hardware-isolated micro-VM sandbox for AI agents on Apple Silicon, with eBPF-based security enforcement.**

Garden AI boots Linux micro-VMs in under 200ms using Apple's `Virtualization.framework`, giving autonomous AI agents a secure, ephemeral environment to execute code. A custom aarch64 Linux kernel runs inside the VM with a Rust PID 1 init process, an eBPF security tracer with BPF-LSM enforcement, and a three-layer defense model (LSM hooks, kill-on-detect, seccomp). The host daemon evaluates policy, logs telemetry, and exposes everything through an MCP server for AI clients and a SwiftUI dashboard for humans.

## Why

AI coding agents need to run arbitrary code -- shell commands, Python scripts, compilers, package managers. Giving them direct access to the host is dangerous. Containers share the host kernel and have a long history of escapes. Garden AI uses **hardware-level VM isolation** (Apple Hypervisor) as the primary boundary, with eBPF observability and enforcement as defense-in-depth inside the guest.

## Architecture

```
                        macOS Host (Apple Silicon)
 ┌──────────────────────────────────────────────────────────────────────┐
 │                                                                      │
 │  garden-cli                    garden-daemon (Rust + Swift FFI)      │
 │    $ garden boot --policy p.json    ├─ Swift VZVirtualMachine        │
 │    $ garden run "echo hello"        ├─ VM lifecycle + vSock proxy    │
 │    $ garden serve (MCP stdio)       ├─ Telemetry receiver (vSock)    │
 │         │                           ├─ Policy evaluator              │
 │         │ gRPC/TCP :10000           ├─ Session logger (NDJSON)       │
 │         ▼                           └─ TCP broadcast :10001          │
 │    ┌────────────┐                         │                          │
 │    │ TCP→vSock  │◄────────────────────────┘                          │
 │    │   Proxy    │                                                    │
 │    └─────┬──────┘               garden-ui (SwiftUI)                  │
 │          │                        ├─ Live telemetry feed             │
 │          │ AF_VSOCK               ├─ Session log viewer              │
 │          │ (hypervisor            └─ Violation filter + alerts       │
 │          │  transport)                                               │
 ├──────────┼───────────────────────────────────────────────────────────┤
 │          ▼       Guest Linux Micro-VM (aarch64, custom kernel)       │
 │                                                                      │
 │   garden-agent (Rust, PID 1)                                        │
 │     ├─ Mount /proc /sys /dev, VirtioFS → /workspace                 │
 │     ├─ Kernel hardening (kptr_restrict, dmesg_restrict)             │
 │     ├─ Network config via rtnetlink + DHCP                          │
 │     ├─ eBPF tracer: 13 probes + 4 BPF-LSM hooks                    │
 │     ├─ Seccomp baseline on spawned commands                         │
 │     ├─ Telemetry stream → vSock :6001                               │
 │     └─ gRPC AgentService → vSock :6000                              │
 │                                                                      │
 │   Custom Kernel 6.12.13                                             │
 │     CONFIG_BPF_LSM=y  CONFIG_KPROBES=y  CONFIG_DEBUG_INFO_BTF=y     │
 │     CONFIG_MODULES=n  All VirtIO drivers built-in (=y)              │
 │                                                                      │
 └──────────────────────────────────────────────────────────────────────┘
```

## Key Features

### Three-Layer Security Enforcement

| Layer | Mechanism | When it fires | Example |
|-------|-----------|---------------|---------|
| **BPF-LSM** | Synchronous kernel hooks return `-EPERM` + `bpf_send_signal(9)` | Before syscall completes | Agent opens `/etc/shadow` -- denied, process killed |
| **Kill-on-detect** | `SIGKILL` from perf event loop | After stateful threshold exceeded | Agent sends > N bytes over TCP -- exfiltration kill |
| **Seccomp** | BPF filter on spawned child processes | On blocked syscall | Spawned command calls `ptrace` -- EPERM |

### eBPF Probe Coverage

**13 probes** across three tiers, plus **4 BPF-LSM hooks**:

| Tier | Probes | Purpose |
|------|--------|---------|
| Tier 1 (required) | `execve`, `openat`, `connect` | Process execution, file access, network connections |
| Tier 2 (canary) | `sendto` (DNS), `mount`, `bpf`, `init_module` | Escape detection -- should never fire from workloads |
| Tier 3 (forensic) | `fork`, `exit`, `oom`, `commit_creds`, `tcp_sendmsg`, `tcp_recvmsg` | Process lifecycle, privilege changes, data volume |
| BPF-LSM | `file_open`, `socket_connect`, `bprm_check_security`, `sb_mount` | Synchronous enforcement (block before syscall completes) |

### Host-Side Violation Detection

The daemon evaluates telemetry from the trusted host side (can't be tampered by compromised guest):

- **proc_memory_access** -- `/proc/<pid>/mem`, `/proc/<pid>/maps`, status, cmdline, syscall
- **sensitive_kernel_access** -- `/dev/mem`, `/dev/kmem`, `/dev/port`, `/dev/kmsg`, `/proc/kallsyms`, `/proc/kcore`
- **write_outside_workspace** -- any write to paths outside `/workspace`
- **namespace_escape_attempt** -- `mount` or `bpf` syscall from non-init process
- **privileged_binary_exec** -- `sudo`, `su`, `chroot`, `nsenter`, `unshare`, etc.
- **data_exfiltration** / **large_download** -- TCP byte thresholds

### MCP Server (Model Context Protocol)

AI clients (Claude Desktop, Cursor) connect via `garden serve` (stdio transport):

**Tools:** `run_command`, `read_file`, `write_file`, `list_directory`, `analyze_security`, `sandbox_report`, `investigate_process`

**Resources:** `garden://sandbox/status`, `garden://security/events`, `garden://security/violations`

**Prompts:** `analyze-security`, `sandbox-report`, `investigate-process`

### Configurable Security Policy

```bash
# Create a deny policy
cat > policy.json << 'EOF'
{
  "name": "strict",
  "rules": [
    { "type": "file_access", "pattern": "/etc/shadow", "action": "deny" },
    { "type": "network_connect", "pattern": "0.0.0.0/0", "action": "deny" }
  ]
}
EOF

# Boot with policy -- flows through CLI → daemon → VirtioFS → agent → BPF maps
garden boot --policy policy.json
```

## Crate Breakdown

| Crate | Lines | Description |
|-------|-------|-------------|
| `garden-agent` | 786 | Guest VM PID 1 -- mounts, networking, eBPF tracer, seccomp, gRPC server |
| `garden-daemon` | 1,867 | macOS daemon -- VM lifecycle (Swift FFI), vSock proxy, policy engine, session logging, TCP broadcast |
| `garden-cli` | 326 | CLI -- `boot`, `run`, `status`, `stop`, `serve` with `--policy` support |
| `garden-mcp` | 1,011 | MCP server -- tools, resources, prompts for AI client integration |
| `garden-ebpf` | 1,513 | eBPF event types, policy evaluation, tracer lifecycle (host-side library) |
| `garden-ebpf-probes` | 1,279 | BPF bytecode -- all 13 probes + 4 LSM hooks (targets `bpfel-unknown-none`) |
| `garden-common` | -- | Shared protobuf definitions (`AgentService`, `DaemonService`) |
| `garden-ui` (Swift) | ~970 | SwiftUI menu bar app -- live telemetry, session viewer, violation alerts |

**~9,750 lines** of Rust + Swift across the workspace.

## Technical Highlights

- **Sub-200ms VM boot** via Apple Virtualization.framework on Apple Silicon
- **Custom aarch64 Linux kernel** (6.12.13) with `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_MODULES=n`
- **Rust PID 1** with signal safety, zombie reaping, panic catch, emergency halt loop
- **AF_VSOCK IPC** -- hypervisor-accelerated transport, no TCP ports exposed between host and guest
- **Swift/Rust FFI bridge** -- `Unmanaged` ARC bridging, NSError marshalling, `build.rs` swiftc integration
- **BPF 512-byte stack workaround** -- `PerCpuArray` scratch map for 564-byte event structs
- **BTF offset extraction** -- reads `task_struct->exit_code` at offset 1076 via `bpf_get_current_task()`
- **Wall-clock telemetry** -- daemon enriches CLOCK_MONOTONIC timestamps with Unix epoch `wall_time`
- **Kernel hardening** -- `kptr_restrict=2`, `dmesg_restrict=1`, `/dev/kmsg` removal inside guest
- **Dentry chain walking** in LSM context for path reconstruction
- **VirtioFS** with host-side, CLI-side, and guest-side path traversal prevention

## Event Flow

```
Guest kernel
  │
  ├─ BPF-LSM hooks (synchronous, pre-syscall)
  │    → check DENIED_PATHS / DENIED_NETS / ALLOWED_* maps
  │    → return -EPERM if denied (syscall never completes)
  │    → bpf_send_signal(9) to kill violating process
  │
  ├─ eBPF tracepoints + kprobes (async, post-syscall)
  │    → fill RawSecurityEvent in PerCpuArray scratch
  │    → EVENTS.output() → PerfEventArray ring buffer
  │
  ▼
Garden agent (guest, PID 1)
  │  Drains PerfEventArray → SecurityEvent → NDJSON
  │  vSock port 6001 → host daemon
  ▼
Garden daemon (host, macOS)
  │  Receives NDJSON stream
  │  → detect_violation() → Option<Violation>
  │  → Enrich with wall_time + violation + allowed override
  │  → Write to ~/.garden/sessions/{id}/events.ndjson
  │  → Broadcast to TCP :10001 (SwiftUI + external tools)
  ▼
Garden UI (SwiftUI) + MCP Server
  │  Live feed, violation filter, session history
  │  AI clients query via prompts/resources/tools
```

## Quick Start

```bash
# Build the workspace
cargo build --workspace

# Build BPF probes (requires nightly + LLVM)
cd crates/garden-ebpf-probes
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
cd ../..

# Cross-compile guest agent
cargo zigbuild -p garden-agent --target aarch64-unknown-linux-musl --release

# Repack initramfs
cp target/aarch64-unknown-linux-musl/release/garden-agent guest/initramfs/init
chmod 755 guest/initramfs/init
cd guest/initramfs && find . | cpio --create --format=newc | gzip -9 > ../kernel/garden-initrd.cpio.gz && cd ../..

# Sign the daemon (required for Virtualization.framework entitlement)
codesign --sign - --entitlements crates/garden-daemon/entitlements.plist --force target/debug/garden-daemon

# Start the daemon
./target/debug/garden-daemon

# Boot a sandbox (in another terminal)
cd ~/GardenBox && garden boot

# Run commands inside the sandbox
cd ~/GardenBox && garden run echo "hello from the sandbox"
cd ~/GardenBox && garden run ls -la /

# Start MCP server for AI clients (stdio transport)
garden serve
```

## Build Requirements

- macOS with Apple Silicon (M1/M2/M3/M4)
- Rust stable + nightly toolchain
- Xcode (for Virtualization.framework and `swiftc`)
- LLVM 21 (Homebrew: `brew install llvm`)
- `cargo-zigbuild` for aarch64-linux cross-compilation
- Docker (for kernel cross-compilation only)

## Project Structure

```
garden-ai/
├── crates/
│   ├── garden-agent/           # Guest VM PID 1 (Rust, static binary)
│   ├── garden-cli/             # CLI interface
│   ├── garden-daemon/          # macOS daemon + Swift FFI + policy engine
│   │   └── src/swift/          # Virtualization.framework Swift bridge
│   ├── garden-common/          # Shared protobuf definitions
│   │   └── proto/              # agent.proto, daemon.proto
│   ├── garden-mcp/             # MCP server (tools, resources, prompts)
│   ├── garden-ebpf/            # eBPF event types, policy, tracer (host lib)
│   └── garden-ebpf-probes/     # BPF bytecode (targets bpfel-unknown-none)
├── garden-ui/                  # SwiftUI menu bar app
│   └── Sources/GardenUI/
├── kernel/
│   ├── build.sh                # Docker cross-compile script
│   └── garden.config           # Kernel config overrides
├── guest/
│   ├── kernel/                 # Compiled kernel + initramfs
│   └── initramfs/              # Initramfs staging (init + busybox)
└── docs/
    └── ebpf-security-design.md # eBPF architecture documentation
```

## Technology Stack

| Component | Technology |
|-----------|-----------|
| VM hypervisor | Apple Virtualization.framework |
| Guest kernel | Linux 6.12.13 (custom aarch64, BTF-enabled) |
| Host daemon | Rust + Swift FFI |
| Guest agent | Rust (static musl binary, PID 1) |
| eBPF framework | Aya (Rust eBPF library) |
| IPC transport | gRPC over AF_VSOCK (tonic + prost) |
| Security policy | BPF-LSM maps + configurable JSON rules |
| AI integration | MCP server (rmcp, stdio transport) |
| UI | SwiftUI (macOS menu bar app) |
| CLI | Clap 4 (derive) |
| Async runtime | Tokio |
| Cross-compilation | cargo-zigbuild (aarch64-linux-musl) |

## License

MIT OR Apache-2.0

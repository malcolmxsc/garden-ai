# Garden AI

**Hardware-isolated micro-VM sandbox for AI coding agents on Apple Silicon.**

Garden AI boots Linux micro-VMs in under 200ms using Apple's `Virtualization.framework`, giving autonomous AI agents (Claude, Cursor, LangChain) a secure, ephemeral environment to execute code without risking the host machine. The guest VM runs a custom aarch64 Linux kernel with a Rust-based PID 1 init process that accepts commands over gRPC via a hypervisor-accelerated vSock transport — no TCP ports exposed, no network attack surface.

## Key Technical Highlights

- **Sub-200ms VM boot** via Apple Virtualization.framework on Apple Silicon
- **Custom aarch64 Linux kernel** (6.12.13) built with all VirtIO drivers compiled in (`=y`, not modules), `CONFIG_MODULES=n`
- **Rust PID 1 init process** (`garden-agent`) that mounts filesystems, configures networking via netlink, runs DHCP, reaps zombies, and serves gRPC — all as a single static binary
- **AF_VSOCK IPC** — hypervisor-accelerated socket transport between host and guest (no IP addresses, no TCP stack)
- **Swift/Rust FFI bridge** — `Unmanaged` ARC bridging, NSError marshalling, `build.rs` swiftc integration
- **gRPC-over-vSock** command execution with Tokio async runtime and tonic
- **TCP-to-vSock proxy** in the daemon for transparent CLI connectivity
- **VirtioFS filesystem sharing** with path traversal prevention (commands restricted to `/workspace`)
- **PID 1 resilience** — signal handler installation, zombie reaper task, panic catch with emergency halt loop

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    macOS Host (Apple Silicon)                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  garden-cli (Rust)                                          │
│    $ garden run "echo hello"                                │
│    Parses args, validates CWD inside ~/GardenBox            │
│    Connects via TCP to 127.0.0.1:10000                      │
│         │                                                   │
│         ▼                                                   │
│  garden-daemon (Rust + Swift FFI)                           │
│    ├─ Swift VZVirtualMachine (Virtualization.framework)      │
│    ├─ VM lifecycle: configure, boot, connect                │
│    └─ TCP→vSock Proxy                                       │
│         Accepts TCP on 127.0.0.1:10000                      │
│         Opens fresh AF_VSOCK conn to guest port 6000        │
│         Spawns bidirectional byte-copy (tokio::io::copy)    │
│         │                                                   │
│         ▼  AF_VSOCK (hypervisor transport, no TCP)          │
├─────────────────────────────────────────────────────────────┤
│              Guest Linux Micro-VM (aarch64)                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Custom Kernel 6.12.13                                      │
│    VirtIO drivers built-in: vsock, net, console, fs         │
│    CONFIG_MODULES=n (no module loading)                     │
│         │                                                   │
│         ▼                                                   │
│  garden-agent (Rust) — PID 1 (/init)                        │
│    1. Mount /proc, /sys, /dev                               │
│    2. Mount VirtioFS → /workspace (shared with host)        │
│    3. Install signal handlers (SIGHUP, SIGPIPE, SIGINT)     │
│    4. Bring up lo + eth0 via netlink                        │
│    5. DHCP via BusyBox udhcpc                               │
│    6. Spawn zombie reaper (waitpid loop)                    │
│    7. Listen on AF_VSOCK port 6000                          │
│    8. Serve gRPC AgentService                               │
│         │                                                   │
│         ▼                                                   │
│    AgentService RPCs:                                       │
│      ExecuteCommand(cmd, args, cwd) → stdout, stderr, exit  │
│      GetStatus() → version, uptime                          │
│                                                             │
│  [planned] garden-ebpf — eBPF syscall/network/file tracing  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Crate Breakdown

| Crate | Type | Status | Description |
|-------|------|--------|-------------|
| `garden-cli` | `bin` | Working | CLI interface (`garden init`, `boot`, `run`, `status`, `stop`, `serve`) |
| `garden-daemon` | `bin` | Working | macOS daemon — boots VM via Virtualization.framework, runs TCP→vSock proxy |
| `garden-agent` | `bin` | Working | Guest VM PID 1 init process — mounts, networking, gRPC server on vSock |
| `garden-common` | `lib` | Working | Shared protobuf/gRPC service definitions (`AgentService`) |
| `garden-mcp` | `lib` | Stub | MCP server skeleton for AI client integration (Claude Desktop, etc.) |
| `garden-ebpf` | `lib` | Stub | eBPF security daemon — syscall/network/file tracing inside guest |

### garden-cli

Command-line interface built with `clap`. Validates that the working directory is inside `~/GardenBox` (the VirtioFS security boundary), then sends gRPC `ExecuteCommand` requests to the daemon's TCP proxy at `127.0.0.1:10000`. Also handles `garden init` (downloads Alpine kernel) and `garden boot` (starts the VM).

**Source:** `crates/garden-cli/src/main.rs` (235 lines)

### garden-daemon

The host-side orchestrator. Uses Swift FFI to call Apple's `Virtualization.framework` for VM creation and lifecycle. After booting the VM, it runs an async TCP-to-vSock proxy: for each incoming CLI connection on `127.0.0.1:10000`, it opens a fresh `AF_VSOCK` connection to the guest on port 6000 and spawns a bidirectional byte-copy task using `tokio::io::copy`. The Swift integration is compiled via `build.rs` which invokes `swiftc` to produce a static library linked into the Rust binary.

**Source:** `crates/garden-daemon/src/main.rs` (265 lines), `src/virtualizer.rs` (228 lines), `src/swift/Virtualizer.swift` (234 lines), `src/swift/bridging_impl.swift` (180 lines)

### garden-agent

Runs inside the guest VM as PID 1 (`/init`). This is a fully static Rust binary injected into the initramfs. On boot it:

1. Installs signal handlers (`SIGHUP`, `SIGPIPE`, `SIGINT`, `SIGTERM` → `SIG_IGN`) to prevent PID 1 from being killed
2. Mounts pseudo-filesystems (`/proc`, `/sys`, `/dev`) and VirtioFS (`/workspace`)
3. Creates BusyBox symlinks for shell commands
4. Configures networking via `rtnetlink` (bring up `lo` and `eth0`), then runs DHCP via BusyBox `udhcpc`
5. Spawns a background zombie reaper task (non-blocking `waitpid(-1, WNOHANG)` loop every 1s)
6. Creates a raw `AF_VSOCK` listener on port 6000 (custom `libc` socket calls, wrapped in `tokio::io::unix::AsyncFd` and implementing `futures_core::Stream` for tonic)
7. Starts a tonic gRPC server with `ExecuteCommand` and `GetStatus` RPCs
8. Wraps everything in `std::panic::catch_unwind` with an emergency `libc::pause()` loop — PID 1 must never exit

**Source:** `crates/garden-agent/src/main.rs` (542 lines)

### garden-common

Defines the gRPC protocol shared between host and guest:

```protobuf
service AgentService {
  rpc ExecuteCommand(CommandRequest) returns (CommandResponse);
  rpc GetStatus(StatusRequest) returns (StatusResponse);
}
```

`CommandRequest` carries `command`, `args[]`, and `cwd`. `CommandResponse` returns `exit_code`, `stdout` (bytes), and `stderr` (bytes). Built at compile time via `tonic-build`.

**Source:** `crates/garden-common/proto/agent.proto` (55 lines)

### garden-mcp

Skeleton for an MCP (Model Context Protocol) server that would expose Garden sandboxes as tools to AI clients like Claude Desktop and Cursor. Defines tool types (`RunCommandTool`, `ReadFileTool`, `WriteFileTool`, `ListDirectoryTool`) and resource types (`SandboxStatusResource`, `SecurityLogResource`). No server loop implemented yet.

**Source:** `crates/garden-mcp/src/` (server.rs, tools.rs, resources.rs)

### garden-ebpf

Skeleton for an eBPF-based security daemon that would run inside the guest VM to trace syscalls, network connections, process execs, and file access. Defines event types (`SecurityEvent`, `SecurityEventKind`) and policy types (`SecurityPolicy`, `PolicyRule`, `PolicyAction`). Uses the `aya` eBPF library (Linux-only, conditional compilation). No probes loaded yet.

**Source:** `crates/garden-ebpf/src/` (tracer.rs, policy.rs, events.rs)

## End-to-End Command Execution Flow

```
1. User runs:  garden run ls /
2. garden-cli:
   - Parses args via clap
   - Validates CWD is inside ~/GardenBox
   - Connects TCP to 127.0.0.1:10000
   - Sends gRPC ExecuteCommand { command: "ls", args: ["/"], cwd: "." }
3. garden-daemon TCP proxy:
   - Accepts TCP connection
   - Calls Swift FFI → VZVirtioSocketDevice.connect(port: 6000) → fd
   - Wraps fd in async VsockStream
   - Spawns bidirectional copy: TCP ↔ vSock
4. garden-agent (guest PID 1):
   - Accepts vSock connection on port 6000
   - Receives gRPC ExecuteCommand request
   - Validates cwd (rejects ".." path traversal)
   - Spawns: tokio::process::Command::new("ls").args(["/"]).current_dir("/workspace/.")
   - Collects stdout, stderr, exit_code
   - Returns CommandResponse over gRPC
5. Response flows back: vSock → TCP proxy → CLI
6. garden-cli prints stdout/stderr, exits with the command's exit code
```

## Technical Deep Dives

### Custom aarch64 Linux Kernel

A minimal kernel is cross-compiled in Docker targeting `arm64` (Apple Silicon). Key design decisions:

- **All VirtIO drivers built-in** (`=y`, not `=m`): `CONFIG_VIRTIO_VSOCKETS=y`, `CONFIG_VIRTIO_NET=y`, `CONFIG_VIRTIO_CONSOLE=y`, `CONFIG_VIRTIO_FS=y`
- **No module loading** (`CONFIG_MODULES=n`): eliminates attack surface and simplifies the initramfs (no `/lib/modules/`)
- **FUSE + VirtioFS**: `CONFIG_FUSE_FS=y` for host-guest filesystem sharing
- **Minimal size**: ~5-10MB uncompressed image
- **Boot params**: `console=hvc0 console=ttyAMA0,115200 earlycon`

Build script: `kernel/build.sh` — downloads Linux 6.12.13 source, applies `kernel/garden.config` overrides, cross-compiles with `gcc-aarch64-linux-gnu`, outputs to `guest/kernel/kernel`.

### AF_VSOCK IPC Implementation

vSock is a hypervisor-accelerated socket family (`AF_VSOCK = 40`) that enables host-guest communication without any IP networking. The implementation uses raw `libc` calls:

**Guest side (garden-agent):** Creates a raw socket with `libc::socket(AF_VSOCK, SOCK_STREAM, 0)`, binds to `VMADDR_CID_ANY:6000`, and listens. Incoming connections are wrapped in a custom `VsockStream` struct that implements `AsyncRead`/`AsyncWrite` via `tokio::io::unix::AsyncFd<RawFdWrapper>`. A `VsockIncoming` struct implements `futures_core::Stream` to feed connections to tonic's gRPC server.

**Host side (garden-daemon):** Calls Swift FFI into `VZVirtioSocketDevice.connect(toPort:)` which returns a file descriptor. This fd is wrapped in the same `VsockStream` async adapter for the TCP proxy.

### Swift/Rust FFI Bridge

The daemon uses a three-layer FFI architecture:

1. **Swift layer** (`Virtualizer.swift`): `GardenVirtualizer` class wrapping `VZVirtualMachine` — configures boot loader, CPU, memory, VirtIO devices (console, network, entropy, vSock, filesystem)
2. **C bridge** (`bridging.h`): Declares `@_cdecl` exported functions like `garden_virtualizer_create()`, `garden_virtualizer_configure()`, `garden_virtualizer_start()`, `garden_virtualizer_connect_vsock()`
3. **Rust FFI** (`virtualizer.rs`): `extern "C"` declarations matching the C header, wrapped in safe Rust `Virtualizer` struct methods

Memory management crosses ARC and Rust ownership boundaries using `Unmanaged.passRetained()` (Swift → opaque pointer → Rust) and `takeUnretainedValue()` (Rust → Swift method calls). Errors are bridged by passing `NSError**` out-params through FFI, then extracting `localizedDescription` via Objective-C runtime message sends on the Rust side.

The build integration (`build.rs`) invokes `swiftc -emit-library -static` to compile Swift sources and links the resulting static library with `cargo:rustc-link-lib=static=garden_swift`.

### PID 1 Resilience

Running as PID 1 inside a Linux VM requires special handling because:
- If PID 1 exits, the kernel panics
- PID 1 is the default parent for orphaned processes and must reap zombies
- Signals that normally terminate a process must be ignored

The implementation:
- **Signal handlers**: `libc::signal(SIG*, SIG_IGN)` for `SIGHUP`, `SIGPIPE`, `SIGINT`, `SIGTERM` — installed before any async work begins
- **Zombie reaper**: Background tokio task calling `waitpid(-1, WNOHANG)` in a loop every second, logging each reaped PID
- **Panic safety**: `std::panic::catch_unwind` wrapping the entire async runtime; if anything panics, falls through to an infinite `libc::pause()` loop so PID 1 never exits

### VirtioFS Secure Sandbox

The host exposes `~/GardenBox` as a VirtioFS share (tag: `garden_workspace`), mounted inside the guest at `/workspace`. Security boundaries:

- **Host side**: The Swift `VZVirtioFileSystemDeviceConfiguration` only exposes a single directory
- **CLI side**: `garden-cli` validates that the current working directory is inside `~/GardenBox` before sending any commands
- **Guest side**: `garden-agent` strips leading `/` from the requested `cwd`, rejects any path containing `..`, and joins with `/workspace` to produce the final working directory

### Networking

- **Host**: `VZNATNetworkDeviceAttachment` provides automatic NAT for guest internet access
- **Guest**: `garden-agent` uses `rtnetlink` (Rust netlink library) to bring up `lo` and `eth0` interfaces, then runs BusyBox `udhcpc` for DHCP. Eth0 discovery polls up to 20 times with 100ms delays waiting for the VirtIO NIC driver to initialize.

## Security Model

| Layer | Mechanism | Description |
|-------|-----------|-------------|
| **Hardware isolation** | Apple Virtualization.framework | Full hypervisor-level VM isolation — separate kernel, memory space, and process tree |
| **IPC isolation** | AF_VSOCK | No TCP ports opened; communication is hypervisor-mediated socket transport |
| **Filesystem isolation** | VirtioFS | Only `~/GardenBox` is exposed; guest sees it as `/workspace` |
| **Path traversal prevention** | CLI + agent validation | CLI checks CWD is inside GardenBox; agent rejects `..` in paths |
| **Network isolation** | NAT-only egress | Guest can reach the internet; no inbound connections possible |
| **PID 1 safety** | Signal handlers + reaper | PID 1 cannot be killed; orphan zombies are automatically reaped |
| **Observability** (planned) | eBPF probes | Trace all syscalls, network connections, file access, and process execs |

## Technology Stack

**Languages:** Rust, Swift, Protobuf, Shell, C (FFI headers)

**Core Dependencies:**

| Dependency | Version | Purpose |
|------------|---------|---------|
| `tokio` | 1.x | Async runtime (full features) |
| `tonic` | 0.11 | gRPC server and client |
| `prost` | 0.12 | Protocol buffer code generation |
| `clap` | 4.x | CLI argument parsing (derive) |
| `rtnetlink` | 0.20 | Linux netlink for network interface configuration |
| `nix` | 0.31 | POSIX system call wrappers |
| `objc` | 0.2 | Objective-C runtime (for Swift/Rust FFI) |
| `rmcp` | 0.15 | Model Context Protocol library |
| `aya` | 0.12 | eBPF program loader (Linux-only) |
| `reqwest` | 0.12 | HTTP client (kernel download) |
| `tracing` | 0.1 | Structured logging |

**Build Requirements:** Rust 1.75+, macOS with Apple Silicon, Xcode (for Virtualization.framework and swiftc), Docker (for kernel cross-compilation)

## Implementation Status

**Working end-to-end:**
- VM boot via Virtualization.framework (< 200ms)
- Custom aarch64 kernel 6.12.13 with built-in VirtIO + vSock
- garden-agent as PID 1 with full init duties and gRPC server
- gRPC `ExecuteCommand` over AF_VSOCK
- TCP→vSock proxy for CLI connectivity
- `garden init` (kernel download), `garden boot`, `garden run` CLI commands
- Guest networking via netlink + DHCP + macOS NAT
- VirtioFS workspace mounting with path traversal prevention
- PID 1 signal safety, zombie reaping, panic catch

**Stub (compiles, architecture defined, no runtime logic):**
- `garden-mcp` — MCP server for AI client integration
- `garden-ebpf` — eBPF security tracing daemon
- `garden-ui` — SwiftUI menu bar app
- `garden status`, `garden stop` CLI commands

**Planned:**
- eBPF syscall/network/file probes with policy engine
- MCP tool/resource serving (RunCommand, ReadFile, WriteFile, ListDirectory)
- UI ↔ daemon IPC bridge
- Multi-sandbox lifecycle management

## Project Structure

```
garden-ai/
├── crates/
│   ├── garden-agent/          # Guest VM PID 1 (542 lines)
│   │   └── src/main.rs
│   ├── garden-cli/            # CLI interface (235 lines)
│   │   └── src/main.rs
│   ├── garden-daemon/         # macOS daemon + Swift FFI
│   │   └── src/
│   │       ├── main.rs        # VM boot, TCP proxy (265 lines)
│   │       ├── virtualizer.rs # Rust FFI wrapper (228 lines)
│   │       └── swift/
│   │           ├── Virtualizer.swift       # VZ wrapper (234 lines)
│   │           ├── bridging_impl.swift     # @_cdecl exports (180 lines)
│   │           └── bridging.h              # C header (48 lines)
│   ├── garden-common/         # Shared gRPC protocol
│   │   └── proto/agent.proto
│   ├── garden-mcp/            # MCP server (stub)
│   │   └── src/{server,tools,resources}.rs
│   └── garden-ebpf/           # eBPF daemon (stub)
│       └── src/{tracer,policy,events}.rs
├── kernel/
│   ├── build.sh               # Docker cross-compile script
│   └── garden.config          # Kernel config overrides
├── guest/
│   ├── kernel/                # Compiled kernel + initramfs
│   ├── initramfs/             # Initramfs staging
│   └── rootfs/                # Root filesystem (placeholder)
├── Cargo.toml                 # Workspace manifest (6 members)
├── architecture_diagram.md    # Original v1 architecture plan
├── architecture_diagram_v2.md # Current as-built architecture
├── architecture_comparison.md # Design vs. implementation comparison
├── garden-ai-vsock-implementation-prompt.md  # vSock phase spec
└── garden-ai-pid1-reaper-prompt.md           # PID 1 resilience spec
```

## Quick Start

```bash
# Build the Rust workspace
cargo build --workspace

# Initialize (downloads Alpine kernel)
cargo run -p garden-cli -- init

# Boot a sandbox VM
cargo run -p garden-cli -- boot

# Execute a command inside the sandbox
cargo run -p garden-cli -- run echo "hello from the sandbox"

# Run a more complex command
cargo run -p garden-cli -- run ls -la /workspace
```

## License

MIT OR Apache-2.0

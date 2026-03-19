# Garden AI: Project Execution Roadmap

This document breaks the project down into distinct, actionable phases based on the IPC Subprocess Architecture. Tracking progress through these checkpoints will prevent scope creep and maintain security context.

> **Last updated:** March 2026 — reflects actual as-built state against original plan.

## Phase 1: The Engine Baseline (Host & Guest Separation) — ~95% COMPLETE
**Goal:** Successfully spin up a hardware-isolated Linux Micro-VM from a standalone daemon process.

### Checkpoints
- [x] **Project Scaffolding**: Create Rust workspace (`garden-daemon`, `garden-cli`, etc.) and basic SwiftUI project.
- [ ] **Daemon↔UI IPC**: Establish IPC (Unix socket/XPC) between `garden-daemon` and SwiftUI. *(Deprioritized — CLI provides full control; daemon works standalone.)*
- [x] **VM Configuration**: Built out Apple Virtualization constraints via Swift FFI — configures CPU, memory, VirtIO devices (console, network, entropy, vSock, filesystem), and boot loader. Custom aarch64 Linux kernel 6.12.13 cross-compiled with all VirtIO drivers built-in.
- [x] **Networking**: `VZNATNetworkDeviceAttachment` on host; guest-side `rtnetlink` brings up `lo` + `eth0`, BusyBox `udhcpc` for DHCP.
- [x] **Hello World**: Boots custom aarch64 kernel with `garden-agent` as PID 1 (`/init`). Full init sequence: mounts `/proc`, `/sys`, `/dev`, sets up BusyBox symlinks, configures networking, starts gRPC server.

---

## Phase 2: The Agent Interface (MCP & Orchestration) — COMPLETE
**Goal:** Allow an external AI agent (like Claude Desktop) to connect to `garden-daemon` and execute commands *inside* the Sandbox.

### Checkpoints
- [x] **MCP Server**: Full MCP server implemented in `garden-mcp` using rmcp 0.15. `GardenMcpServer` bridges MCP JSON-RPC (stdio transport) to gRPC via `#[tool_router]`/`#[tool_handler]` macros. 4 tools: `run_command`, `read_file`, `write_file`, `list_directory`. Setup guide in `MCP_SETUP.md`.
- [x] **Daemon-to-VM Comms**: Implemented gRPC-over-AF_VSOCK — hypervisor-accelerated socket transport with no TCP exposure. Custom `VsockStream` wrapping raw `libc` sockets in `tokio::io::unix::AsyncFd`, implementing `AsyncRead`/`AsyncWrite` and `futures_core::Stream` for tonic. TCP→vSock proxy in daemon for CLI connectivity.
- [x] **Command Execution**: `garden run` executes commands inside the VM via gRPC `ExecuteCommand`. Full round-trip: CLI → TCP → daemon proxy → vSock → guest agent → `tokio::process::Command` → response. Path traversal prevention enforced.
- [x] **MCP Execution Tool**: All 4 MCP tools wired to gRPC `ExecuteCommand`. `run_command` forwards directly; `read_file` uses `cat`; `write_file` uses `sh -c` heredoc; `list_directory` uses `ls -la`. Parameter schemas auto-generated via `schemars::JsonSchema`.
- [x] **Agent Test**: End-to-end MCP integration verified via `scripts/test_mcp_agent.sh`. Test script acts as an MCP client over stdio (JSONL framing), sends JSON-RPC messages through the full pipeline: MCP server → gRPC → daemon proxy → vSock → guest agent. All 4 tools tested: `whoami` returns `root`, `uname -a` confirms `Linux aarch64`, write/read roundtrip in `/workspace`, directory listing, and error handling for missing files. 18/18 assertions pass.

---

## Phase 3: The Walled Garden (Filesystem & Security Telemetry) — ~95% COMPLETE
**Goal:** Securely share a specific host directory with the guest and monitor its activity without trusting the guest OS.

### Checkpoints
- [x] **Swift Bindings**: `Virtualizer.swift` wraps `VZVirtualMachine` with full hardware config (CPU, memory, VirtIO devices).
- [x] **Build Script**: `build.rs` invokes `swiftc -emit-library -static` and links via `cargo:rustc-link-lib=static=garden_swift`.
- [x] **FFI Validation**: `Virtualizer::new()` tested — `Unmanaged` ARC bridging, NSError marshalling, and Objective-C runtime interop all working.
- [x] **Jailed Workspace**: VirtioFS shares `~/GardenBox` (tag: `garden_workspace`), mounted at `/workspace` in guest. CLI validates CWD is inside `~/GardenBox`; agent rejects `..` in paths.
- [x] **eBPF Tracing (Tier 1)**: Full eBPF security telemetry pipeline implemented across 3 new crates:
  - `garden-ebpf-common` — `#![no_std]` shared `#[repr(C)]` types (`RawSecurityEvent`, `EventKind`) between BPF kernel probes and userspace loader.
  - `garden-ebpf-probes` — Pure Rust BPF programs using `aya-ebpf`, compiled to `bpfel-unknown-none`. Three Tier 1 tracepoints: `sys_enter_execve` (process execution), `sys_enter_openat` (file access), `sys_enter_connect` (network connections). All write to shared `PerfEventArray` map.
  - `garden-ebpf` — Userspace loader using `aya` 0.12. `start_tracer()` loads BPF ELF, attaches all 3 tracepoints, spawns per-CPU `AsyncPerfEventArray` readers, converts `RawSecurityEvent` to `SecurityEvent`, streams via `mpsc::channel`. Policy engine (`SecurityPolicy::evaluate()`) with glob-based file path matching, CIDR-based network matching, first-match-wins semantics.
  - Guest agent mounts `debugfs`/`bpffs`, loads probes before gRPC server starts, streams NDJSON events over dedicated vSock port 6001.
  - Host daemon receives telemetry via vSock 6001, evaluates policy (Allow/Deny/Log), TCP proxy on `127.0.0.1:10001` for external telemetry consumers.
  - 25 unit/integration tests: policy evaluation (glob, CIDR, first-match), event serialization roundtrips, raw event conversion, macOS stub tracer.
- [x] **eBPF Tracing (Tier 2)**: DNS query logging (`sys_enter_sendto` UDP port 53 with wire-format domain decoding), mount attempt canary (`sys_enter_mount` — only PID 1 should mount), BPF syscall monitor (`sys_enter_bpf` — agent loading BPF is a red flag), kernel module load (`sys_enter_init_module` — should never fire with `CONFIG_MODULES=n`). All 4 probes use `PerCpuArray` scratch to avoid 512-byte BPF stack limit. BPF ELF compiles to 10.9 KB with all 7 tracepoints. 31 unit tests passing.
- [x] **Telemetry Pipeline**: NDJSON-over-vSock streaming from guest to host. Dedicated vSock port 6001 (separate from gRPC command channel on 6000). Reconnection support on both sides. E2E test script at `scripts/test_ebpf_telemetry.sh`.
- [ ] **Kernel BPF Verification**: Verify guest kernel 6.12.13 has `CONFIG_BPF=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_FTRACE_SYSCALLS=y`. Rebuild if needed via `kernel/build.sh`.

---

## Phase 4: The Developer Experience (Native macOS UI) — NOT STARTED
**Goal:** Build the sleek, user-facing native application that monitors and controls the daemon.

### Checkpoints
- [ ] **IPC Bridge**: Establish the local IPC connection (Unix Domain Socket / XPC) between `garden-ui` and the background `garden-daemon`.
- [ ] **Menu Bar App**: Build the SwiftUI app to display VM lifecycle status (Cold, Warming Up, Active).
- [ ] **Security Dashboard**: Develop the UI to display the real-time eBPF logs received via IPC.
- [ ] **Visual Diff**: Implement a visual representation of the modified files in the host workspace.

---

## Priority Path

The fastest route to a fully working AI sandbox product:

1. ~~**Implement `garden-mcp` server**~~ — **DONE.**
2. ~~**Agent Test**~~ — **DONE.** End-to-end MCP integration verified via stdio test harness.
3. ~~**Load eBPF probes**~~ — **DONE.** Tier 1 probes (execve, openat, connect) implemented with `aya-ebpf`. Userspace loader, policy engine, and NDJSON telemetry pipeline complete.
4. ~~**eBPF telemetry over vSock**~~ — **DONE.** Dedicated vSock port 6001 streams SecurityEvents as NDJSON. Host daemon evaluates policy and logs. TCP proxy on :10001 for external consumers.
5. **Verify kernel BPF support** — boot VM, check `/proc/config.gz` for BTF/tracepoint config, rebuild kernel if needed.
6. ~~**Tier 2 eBPF probes**~~ — **DONE.** DNS logging, mount/BPF/module load canaries. All 7 tracepoints compiled into 10.9 KB BPF ELF.
7. **E2E telemetry validation** — boot VM with BPF kernel, verify all 7 probes load, run `scripts/test_ebpf_telemetry.sh`.
8. **SwiftUI menu bar app** — display VM status and security logs.

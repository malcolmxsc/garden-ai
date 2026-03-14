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

## Phase 2: The Agent Interface (MCP & Orchestration) — ~90% COMPLETE
**Goal:** Allow an external AI agent (like Claude Desktop) to connect to `garden-daemon` and execute commands *inside* the Sandbox.

### Checkpoints
- [x] **MCP Server**: Full MCP server implemented in `garden-mcp` using rmcp 0.15. `GardenMcpServer` bridges MCP JSON-RPC (stdio transport) to gRPC via `#[tool_router]`/`#[tool_handler]` macros. 4 tools: `run_command`, `read_file`, `write_file`, `list_directory`. Setup guide in `MCP_SETUP.md`.
- [x] **Daemon-to-VM Comms**: Implemented gRPC-over-AF_VSOCK — hypervisor-accelerated socket transport with no TCP exposure. Custom `VsockStream` wrapping raw `libc` sockets in `tokio::io::unix::AsyncFd`, implementing `AsyncRead`/`AsyncWrite` and `futures_core::Stream` for tonic. TCP→vSock proxy in daemon for CLI connectivity.
- [x] **Command Execution**: `garden run` executes commands inside the VM via gRPC `ExecuteCommand`. Full round-trip: CLI → TCP → daemon proxy → vSock → guest agent → `tokio::process::Command` → response. Path traversal prevention enforced.
- [x] **MCP Execution Tool**: All 4 MCP tools wired to gRPC `ExecuteCommand`. `run_command` forwards directly; `read_file` uses `cat`; `write_file` uses `sh -c` heredoc; `list_directory` uses `ls -la`. Parameter schemas auto-generated via `schemars::JsonSchema`.
- [ ] **Agent Test**: MCP server is implemented — ready for end-to-end verification. Need to confirm Claude Desktop can connect via MCP stdio and successfully run `whoami` and `uname -a` inside the Garden VM.

---

## Phase 3: The Walled Garden (Filesystem & Security Telemetry) — ~50% COMPLETE
**Goal:** Securely share a specific host directory with the guest and monitor its activity without trusting the guest OS.

### Checkpoints
- [x] **Swift Bindings**: `Virtualizer.swift` wraps `VZVirtualMachine` with full hardware config (CPU, memory, VirtIO devices).
- [x] **Build Script**: `build.rs` invokes `swiftc -emit-library -static` and links via `cargo:rustc-link-lib=static=garden_swift`.
- [x] **FFI Validation**: `Virtualizer::new()` tested — `Unmanaged` ARC bridging, NSError marshalling, and Objective-C runtime interop all working.
- [x] **Jailed Workspace**: VirtioFS shares `~/GardenBox` (tag: `garden_workspace`), mounted at `/workspace` in guest. CLI validates CWD is inside `~/GardenBox`; agent rejects `..` in paths.
- [ ] **eBPF Tracing**: `garden-ebpf` crate defines event types (`SecurityEvent`, `SecurityEventKind`), policy engine (`SecurityPolicy`, `PolicyRule`, `PolicyAction`), and tracer skeleton. Uses `aya` eBPF library (Linux-only, conditional compilation). **No probes loaded yet.**
- [ ] **Telemetry Pipeline**: Stream eBPF logs from guest back to `garden-daemon` via vSock. Not started — depends on eBPF probes.

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

1. ~~**Implement `garden-mcp` server**~~ — **DONE.** MCP tools wired to gRPC `ExecuteCommand`. Claude Desktop / Cursor / Claude Code can connect via stdio.
2. **Agent Test** — verify end-to-end MCP flow: boot VM → start MCP server → Claude Desktop executes `whoami` and `uname -a` in sandbox.
3. **Load eBPF probes** — attach to syscall/network/file tracepoints inside the guest for observability.
4. **eBPF telemetry over vSock** — stream security events from guest to host daemon.
5. **SwiftUI menu bar app** — display VM status and security logs.

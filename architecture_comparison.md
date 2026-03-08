# Architecture Comparison: Original Plan vs Current Implementation

## What Changed

| Component | Original Plan (v1) | Current Reality (v2) |
|-----------|-------------------|---------------------|
| **CLI → VM Transport** | Unspecified (implied MCP → VM) | CLI → TCP (127.0.0.1:10000) → daemon vSock proxy → guest gRPC |
| **Daemon Role** | MCP Server + VM Manager + Firewall + VirtioFS | **TCP→vSock byte proxy** + VM Manager |
| **Guest Agent** | "Agent Shell / Runtime" (vague) | **PID 1 /init** with tonic gRPC, signal handlers, zombie reaper, BusyBox symlinks |
| **IPC Mechanism** | "Unix Socket / XPC" between UI and daemon | gRPC/HTTP2 over vSock (AF_VSOCK, port 6000) |
| **Networking** | "Host Network Rules (NAT / Gateway config)" | DHCP via `udhcpc` on virtio-net `eth0`, macOS NAT |
| **eBPF** | Rust eBPF Daemon inside guest | ❌ Not yet implemented |
| **VirtioFS** | Host VirtioFS Server ↔ Guest Client | ❌ Not yet implemented |
| **garden-ui** | SwiftUI app with Menu Bar, Diff View, Security Dashboard | ❌ Not yet implemented |
| **MCP Server** | Receives intents from Claude/LangChain | ❌ Not yet implemented (daemon boots VM but doesn't serve MCP) |

## Key Architectural Shifts

### 1. Daemon became a byte proxy, not a gRPC proxy
The original plan had the daemon as a heavyweight orchestrator. In practice, the daemon is a **thin TCP↔vSock pipe**. All gRPC logic lives in the guest agent. This is simpler and more robust — HTTP/2 frames pass through transparently.

### 2. Agent is PID 1 with real init responsibilities
The original diagram treated the guest as a black box. In reality, the agent IS the init system — it mounts `/proc`, `/sys`, `/dev`, runs DHCP, handles signals, and reaps zombie processes. This was a hard-won lesson after kernel panics.

### 3. vSock replaced the implied network path
The original plan showed a generic firewall between host and guest. We now use Apple's `VZVirtioSocketDevice` for a direct, zero-config host↔guest channel that bypasses networking entirely.

## Overall Progress

```
✅ Completed          🔲 Not Started
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ VM boot (Virtualization.framework, custom aarch64 kernel)
✅ Guest networking (DHCP, NAT egress)
✅ vSock transport (AsyncFd, per-connection proxy)
✅ gRPC command execution (CLI → daemon → agent → child process → response)
✅ PID 1 resilience (signals, catch_unwind, zombie reaper)
🔲 VirtioFS workspace sharing
🔲 MCP Server integration (Claude/LangChain → daemon)
🔲 garden-ui (SwiftUI menu bar app)
🔲 eBPF observability daemon
🔲 Security dashboard
```

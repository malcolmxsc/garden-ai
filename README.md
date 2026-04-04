# Garden AI

<!--
  Note to self (Malcolm Griffin):
  This project was inspired by seeing a role for a sandbox systems developer
  at Anthropic on 08/04/2025.
-->

**Hardware-isolated micro-VM sandbox for AI agents on Apple Silicon.**

Garden AI boots ephemeral Linux micro-VMs using Apple's Virtualization.framework, giving AI coding agents (Claude, Cursor, LangChain) a secure environment to execute arbitrary code without risking the host. A custom aarch64 kernel runs eBPF-based security enforcement inside the VM, while the host daemon evaluates policy and streams telemetry to an MCP server and SwiftUI dashboard.

## What is Garden AI?

Garden AI is a sandbox runtime that combines **hardware VM isolation** with **kernel-level observability**. It solves the problem that AI agents need to run untrusted code (shell commands, scripts, compilers) but containers share the host kernel and have a history of escapes.

- **Hypervisor boundary** -- Apple Virtualization.framework provides full VM isolation (separate kernel, memory, process tree)
- **eBPF enforcement** -- 13 probes + 4 BPF-LSM hooks monitor and block malicious syscalls inside the guest
- **Three-layer defense** -- BPF-LSM (synchronous block), kill-on-detect (stateful thresholds), seccomp (spawned processes)
- **Host-side policy** -- the daemon evaluates telemetry from outside the VM, so a compromised guest can't tamper with it
- **MCP integration** -- AI clients connect via `garden serve` to run commands, read files, and query security telemetry

## Architecture

```
  macOS Host                          Guest Linux Micro-VM
 ┌──────────────────────┐            ┌──────────────────────────┐
 │  garden-cli           │            │  garden-agent (PID 1)    │
 │  garden-daemon        │  AF_VSOCK  │    ├─ gRPC server        │
 │    ├─ Swift FFI (VZ)  │◄──────────►│    ├─ eBPF tracer        │
 │    ├─ vSock proxy     │  :6000     │    ├─ BPF-LSM hooks      │
 │    ├─ Policy engine   │◄───────────│    ├─ Seccomp baseline   │
 │    └─ Session logger  │  :6001     │    └─ VirtioFS /workspace│
 │                       │ telemetry  │                          │
 │  garden-mcp (MCP)     │            │  Kernel 6.12.13          │
 │  garden-ui (SwiftUI)  │            │    BPF-LSM, BTF, kprobes │
 └──────────────────────┘            └──────────────────────────┘
```

## Security Model

| Layer | Mechanism | Scope |
|-------|-----------|-------|
| Hardware isolation | Apple Hypervisor (Virtualization.framework) | VM boundary |
| BPF-LSM | Synchronous `-EPERM` + `SIGKILL` before syscall completes | File access, network, exec, mount |
| Kill-on-detect | `SIGKILL` from perf event loop | TCP byte thresholds (exfiltration) |
| Seccomp | BPF filter on child processes | `ptrace`, `mount`, `kexec`, `reboot`, etc. |
| Host policy engine | Violation detection on daemon side | Proc recon, kernel device access, privilege escalation |
| Filesystem | VirtioFS with path traversal prevention | Only `~/GardenBox` exposed |

## Getting Started

```bash
# Build
cargo build --workspace

# Sign daemon (required for Virtualization.framework entitlement)
codesign --sign - --entitlements crates/garden-daemon/entitlements.plist \
  --force target/debug/garden-daemon

# Start daemon, then in another terminal:
./target/debug/garden-daemon

# Boot and run
cd ~/GardenBox
garden boot
garden run echo "hello from the sandbox"

# Boot with a security policy
garden boot --policy policy.json

# Start MCP server for AI clients
garden serve
```

See [docs/ebpf-security-design.md](docs/ebpf-security-design.md) for the full eBPF architecture and probe documentation.

## Crates

| Crate | Description |
|-------|-------------|
| `garden-daemon` | macOS daemon -- VM lifecycle (Swift FFI), vSock proxy, policy engine, telemetry |
| `garden-agent` | Guest PID 1 -- init, networking, eBPF tracer, seccomp, gRPC server |
| `garden-ebpf-probes` | BPF bytecode -- 13 probes + 4 LSM hooks (targets `bpfel-unknown-none`) |
| `garden-ebpf` | Host-side eBPF library -- event types, policy evaluation, tracer lifecycle |
| `garden-mcp` | MCP server -- tools, resources, prompts for AI client integration |
| `garden-cli` | CLI -- `boot`, `run`, `status`, `stop`, `serve` |
| `garden-common` | Shared protobuf definitions |

## Platform Support

| Platform | Status |
|----------|--------|
| macOS Apple Silicon (M1/M2/M3/M4) | Supported |
| macOS Intel | Not supported (requires Virtualization.framework + ARM guest) |
| Linux / Windows | Not supported |

**Build requirements:** Rust stable + nightly, Xcode, LLVM 21, `cargo-zigbuild`

## UI

`garden-ui` is a SwiftUI menu bar app that connects to the daemon's TCP telemetry broadcast on port 10001. It provides a live security event feed, session log viewer, and violation filter.

## Contributing

Contributions are welcome. Please open an issue before submitting large changes.

## License

MIT OR Apache-2.0

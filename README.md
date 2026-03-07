# 🌿 Garden AI

**The un-hackable room for your AI.**

Garden AI is a hyper-fast, hardware-isolated, local sandbox for AI coding agents. It uses Apple's `Virtualization.framework` to boot Linux micro-VMs in <200ms, giving autonomous AI agents (Claude, Cursor, LangChain) a safe place to run code — without risking your machine.

## Architecture

```
┌──────────────────────────────────────────┐
│          Swift (macOS App)               │
│  ┌──────────┐  ┌──────────────────────┐  │
│  │ SwiftUI  │  │ VMManager            │  │
│  │ Menu Bar │  │ Virtualization.fwk   │  │
│  └────┬─────┘  └──────────┬───────────┘  │
│       │    FFI (cdylib)    │              │
├───────┼────────────────────┼──────────────┤
│       ▼                    ▼              │
│  ┌──────────┐  ┌──────────────────────┐  │
│  │ garden-  │  │ garden-mcp           │  │
│  │ ffi      │  │ MCP JSON-RPC Server  │  │
│  └──────────┘  └──────────────────────┘  │
│          Rust Workspace                  │
└──────────────────────────────────────────┘
         │
         ▼  (Hypervisor)
┌──────────────────────────────────────────┐
│  Guest Linux Micro-VM                    │
│  ┌──────────────────────────────────┐    │
│  │ garden-ebpf (eBPF Security)     │    │
│  │ Syscall / Network / File Tracing │    │
│  └──────────────────────────────────┘    │
└──────────────────────────────────────────┘
```

## Crates

| Crate | Type | Description |
|-------|------|-------------|
| `garden-ffi` | `cdylib` | C-ABI bridge between Swift and Rust |
| `garden-mcp` | `lib` | MCP server for AI client connectivity |
| `garden-cli` | `bin` | Open-source CLI (`garden boot`, `garden run`) |
| `garden-ebpf` | `lib` | eBPF security daemon (runs inside guest VM) |
| `garden-common` | `lib` | Shared types, errors, IPC protocol |

## Quick Start

```bash
# Build the Rust workspace
cargo build --workspace

# Boot a sandbox (CLI)
cargo run -p garden-cli -- boot

# Connect Claude Desktop via MCP
# (Configure claude_desktop_config.json to point at garden's MCP server)
```

## License

MIT OR Apache-2.0

# Garden AI Architecture — As-Built (v2)

> **Legend:**
> - **Solid lines** = implemented and working
> - **Dashed lines** = planned / not yet implemented
> - **Yellow nodes** = stub (compiles but no logic)
> - **Red/dark nodes** = planned (not yet started)
>
> Compare with [`architecture_diagram.md`](./architecture_diagram.md) for the original planning-phase design.

```mermaid
flowchart TD
    classDef external fill:#1e1e1e,stroke:#4a4a4a,stroke-width:2px,color:#dcdcdc
    classDef macos fill:#1a2332,stroke:#3b5278,stroke-width:2px,color:#e0e0e0
    classDef guest fill:#1a2f23,stroke:#306b44,stroke-width:2px,color:#e0e0e0
    classDef stub fill:#2a2a1a,stroke:#8b7525,stroke-width:2px,color:#e0e0e0,stroke-dasharray: 5 5
    classDef planned fill:#2a1a1a,stroke:#8b2525,stroke-width:2px,color:#9e9e9e,stroke-dasharray: 8 4

    %% External AI Clients
    subgraph External["AI Ecosystem (Planned)"]
        Claude["Claude Desktop / Cursor"]
        LangChain["LangChain / Dev Scripts"]
    end

    %% macOS Host
    subgraph HostOS["Host System (Apple macOS / Apple Silicon)"]

        subgraph CLIProcess["Process: garden-cli (Rust, open-source)"]
            CLI["CLI Commands\ninit · boot · run · status · stop"]
            MCPServe["serve --port 3000\n[stub — not implemented]"]
        end

        subgraph DaemonProcess["Process: garden-daemon (Rust + Swift FFI)"]
            SwiftVZ["Swift VZVirtualMachine\n(Virtualization.framework)"]
            TCPProxy["TCP→vSock Proxy\n127.0.0.1:10000 → vsock:6000"]
            VirtFSHost["Virtio-FS Host Server\n[planned]"]
        end

        subgraph UIProcess["Process: garden-ui (SwiftUI) [not wired]"]
            MenuBar["Menu Bar Controls [stub]"]
            SecDash["Security Dashboard [planned]"]
        end

        MCPCrate["garden-mcp crate\n[stub — no server loop]"]
        Workspace[("📁 Isolated Workspace\n[planned — Virtio-FS]")]
        KernelBuild["kernel/build.sh\n→ guest/kernel/kernel\n(aarch64 Alpine Linux 6.12.13)"]
    end

    %% Guest VM
    subgraph MicroVM["Guest Environment (Linux Micro-VM, aarch64)"]
        direction TB

        subgraph GuestInit["PID 1: garden-agent (Rust)"]
            InitDuties["Init Duties\nmount /proc /sys /dev\nDHCP via BusyBox udhcpc\nzombie reaper (waitpid loop)"]
            GRPCServer["gRPC Server\nvSock port 6000\nExecuteCommand · GetStatus"]
        end

        subgraph GuestKernel["Guest Kernel (custom build, CONFIG_MODULES=n)"]
            vSockDrv["AF_VSOCK driver\n(CONFIG_VIRTIO_VSOCKETS=y)"]
            vNIC["VirtIO NIC\n(NAT via macOS — automatic)"]
            GuestFS["Virtio-FS Client\n[planned]"]
            eBPFKern["eBPF hooks\n[planned]"]
        end

        Shell["Agent Shell / Runtime\n(spawned by gRPC ExecuteCommand)"]
    end

    %% --- Connections ---

    %% CLI → Daemon → Guest (working path)
    CLI -- "gRPC over TCP\nhttp://127.0.0.1:10000" --> TCPProxy
    TCPProxy -- "AF_VSOCK CID:3 port 6000" --> GRPCServer

    %% Daemon boots VM
    SwiftVZ -- "Boots with kernel + initrd\n(Virtualization.framework)" --> MicroVM
    KernelBuild -. "Provides kernel binary" .-> SwiftVZ

    %% MCP (planned path)
    Claude & LangChain -. "JSON-RPC MCP [planned]" .-> MCPServe
    MCPServe -. "delegates to" .-> MCPCrate

    %% UI (not wired)
    UIProcess -. "Unix Socket / XPC\n[not implemented]" .-> DaemonProcess

    %% Filesystem (planned)
    VirtFSHost -. "[planned] mounts" .-> Workspace
    GuestFS -. "[planned] shared folders" .-> VirtFSHost
    Shell -. "[planned] reads/writes" .-> GuestFS

    %% Networking
    vNIC -- "egress TCP/UDP" --> Internet((Internet))

    %% eBPF telemetry (planned)
    eBPFKern -. "[planned] telemetry via vSock" .-> MCPCrate

    %% Guest internals
    InitDuties --> GRPCServer
    GRPCServer --> Shell

    %% Apply styles
    class Claude,LangChain,Internet external
    class HostOS,CLIProcess,DaemonProcess macos
    class MicroVM,GuestInit,GuestKernel guest
    class MCPCrate,MCPServe stub
    class VirtFSHost,GuestFS,eBPFKern,UIProcess,MenuBar,SecDash planned
```

---

## What Changed from the Original Plan

| Area | Original `architecture_diagram.md` | This Diagram (as-built) |
|---|---|---|
| **MCP Server** | Inside `garden-daemon`, the entry point | Separate `garden-mcp` stub crate; `garden-cli serve` would host it |
| **CLI tool** | Not shown | `garden-cli` is the primary user interface |
| **Guest agent** | Vague "Agent Shell / Runtime" | `garden-agent` is a Rust **PID 1 gRPC server** with full init duties |
| **Host↔Guest protocol** | Not specified | **gRPC-over-vSock** on port 6000, with TCP→vSock proxy in daemon |
| **Virtio-FS** | Core filesystem sharing mechanism | Not implemented — `guest/rootfs/` is an empty placeholder |
| **eBPF daemon** | Running, sending telemetry via vSock | Stub only — no probes loaded, no events emitted |
| **UI↔Daemon IPC** | Unix Socket / XPC shown as working | `garden-ui` exists but is not wired to the daemon |
| **Host Firewall** | Explicit NAT/gateway component | Apple's built-in NAT handles it — no custom rules needed |
| **Kernel build** | Not shown | `kernel/build.sh` produces custom aarch64 kernel (Alpine 6.12.13) |

## Current Status

**Working end-to-end:**
- VM boot via Apple Virtualization.framework (Swift + Rust FFI)
- Custom aarch64 Linux kernel with vSock support
- `garden-agent` as PID 1: mounts pseudo-fs, DHCP, gRPC server
- gRPC `ExecuteCommand` over AF_VSOCK (CID 3, port 6000)
- TCP→vSock proxy for CLI connectivity
- `garden-cli`: `init`, `boot`, `run` commands

**Stubs (compiles, no logic):**
- `garden-mcp` — MCP server crate skeleton
- `garden-ui` — SwiftUI app (not wired to daemon)

**Planned (not started):**
- Virtio-FS filesystem sharing
- eBPF security probing and telemetry
- UI↔Daemon IPC bridge
- Sandbox lifecycle management (`status`, `stop`, `list`)
- MCP tool/resource implementation for AI client connectivity

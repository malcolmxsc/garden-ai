# Garden AI

🌿 **Garden AI** is an ultra-fast, secure, hardware-accelerated Linux Micro-VM environment designed specifically to give AI orchestrators (like Claude Desktop and Cursor) a completely jailed execution context on Apple Silicon (macOS) hardware.

This project solves the "AI Breakout" problem: instead of allowing AI coding agents full native access to a user's machine, Garden AI spins up an isolated Alpine Linux instance with strict filesystem scoping (`~/GardenBox`) and executes all generated commands securely over `vSock` connections.

## Technical Architecture

Under the hood, Garden AI leverages a deep integration of macOS Virtualization and Linux kernel primitives, bridging Swift, Rust, and embedded systems programming to achieve boot times under a second.

### 1. `garden-daemon` (The Hypervisor Bindings)
- **Swift / Rust FFI**: Uses Apple's modern `Virtualization.framework` written in Swift, exposed to a central Rust daemon via a C-ABI static library.
- **Hardware Acceleration**: Leverages the native Apple Silicon hypervisor to directly accelerate virtual CPU and Memory.
- **Device Emulation**: Configures VirtIO devices for networking, serial communication, and storage mapping directly to the host OS.
- **vSock Proxy**: Creates a transparent TCP-to-vSock asynchronous proxy using a low-level `tokio` event loop. This allows standard TCP-based CLI clients to connect to a raw VirtIO socket boundary without native macOS socket support blocking the transaction.

### 2. `garden-agent` (The PID 1 Micro-VM Manager)
- **Direct Init Injection**: Rather than extracting a full bloated Linux OS, Garden AI injects a statically-compiled Rust binary into a minimal `cpio` ramdisk. The custom Linux kernel runs this binary as `init` (PID 1).
- **Process Robustness**: Because Linux panics if PID 1 exits, the agent implements advanced signal handling techniques (muting `SIGCHLD`, `SIGINT`, `SIGPIPE`), zombie process reaping, and panic unwinding (`catch_unwind`) to guarantee eternal uptime.
- **gRPC Server**: Uses `tonic` to expose a stable, strictly-typed protocol via protobuf. Commands sent from the host execute instantly and return `stdout`, `stderr`, and `exit_code` inside the protobuf response.
- **vSock Transport**: Implements a custom raw file descriptor wrapper for `AF_VSOCK`, mapping hardware memory sockets straight into Rust's asynchronous `tokio::io::AsyncFd`.

### 3. `garden-cli` & `garden-mcp` (The Agent Interface)
- **Path Traversal Protection**: Enforces strict validation that all shell execution happens *only* inside the `~/GardenBox` directory, dropping any attempts to use `../` or absolute host paths to escape the environment.
- **Model Context Protocol (MCP)**: Implements an `rmcp` SSE gateway on `localhost:3000` to expose the sandboxed VM to standard AI orchestrators. AI bots make calls to the `run_command` tool which proxies via gRPC over vSock down to the Alpine agent.

### 4. Custom Alpine Linux Kernel
- **`CONFIG_VIRTIO_FS=y`**: Bypasses the need for `.ko` kernel modules and `modprobe` completely. VirtioFS and FUSE are compiled directly into the `vmlinux` `aarch64` kernel image to shave off boot dependencies.
- **Zero-Copy VirtioFS Sharing**: Secures the host boundary by relying on Apple's `VZVirtioFileSystemDeviceConfiguration` mapped inside the guest as `/workspace`. Host changes reflect to the guest instantaneously, and guest writes reflect to the host seamlessly, without any network share (NFS/SMB) networking overhead.

## Engineering Challenges Overcome

* **macOS vs. Linux Socket API Mismatches**: Apple handles Virtual Sockets (vSock) differently than Linux. We resolved this by mapping `connect_vsock()` via GCD (Grand Central Dispatch) in Swift, `dup()`-ing the resulting file descriptors, and importing them into Rust `tokio` raw File Descriptor loops.
* **Kernel Module Nightmares**: Re-packing kernel `initramfs` structures and handling runtime loading of `virtiofs.ko` via busybox `modprobe` was unstable. We moved to building custom mainline Linux kernels (v6.12) overriding `.config` parameters through Docker to embed necessary security and virtio components entirely statically.
* **Orphan Processes**: A naive remote execution agent accumulates zombie child processes that it never reaps. We designed the PID 1 agent to automatically handle the `waitpid` syscalls either synchronously per executed command, or periodically inside a background Toko task.

## Repository Layout
* **`crates/garden-daemon/`**: Main host background task (Rust + Swift `build.rs`).
* **`crates/garden-agent/`**: The Linux PID 1 environment (Cross-compiled to `aarch64-unknown-linux-musl`).
* **`crates/garden-cli/`**: Desktop binary to manually control VMs.
* **`crates/garden-mcp/`**: (WIP) The Model Context Protocol Gateway.
* **`crates/garden-common/`**: Protobuf files.
* **`kernel/`**: Docker build scripts and kernel config tweaks for the secure Alpine Linux OS.

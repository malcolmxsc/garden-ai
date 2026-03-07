# Garden AI — Phase 2: Implement VirtIO-VSock IPC Layer

## Context

Garden AI is a secure macOS sandbox for AI coding agents. The architecture is:

- **Host (Swift)**: SwiftUI app using Apple's `Virtualization.framework` to boot Linux micro-VMs on Apple Silicon.
- **Brain (Rust Core)**: Linked into the Swift app, handles MCP server and business logic.
- **Guest (Linux VM)**: Minimal Linux micro-VM running a statically-compiled Rust agent (`garden-agent`) as PID 1 via a custom `cpio.gz` initramfs.

**Current state**: The VM boots successfully with a custom-extracted raw ARM64 kernel image (Alpine's `linux-virt` 6.12.13-0-virt). The guest agent runs as PID 1, mounts `/proc`, `/sys`, `/dev`, loads `af_packet` + `virtio_net` + `virtio_rng` modules, acquires an IP via `udhcpc`, and serves a gRPC `AgentService` on `0.0.0.0:10000` over TCP/virtio-net. Command execution works end-to-end (`garden run /bin/busybox -- ls /`).

**Problem**: Alpine's `linux-virt` kernel for aarch64 does **not** ship the `vmw_vsock_virtio_transport` module. It's either not compiled at all or not included in the module tree. We need vsock for host↔guest IPC to eliminate IP address discovery, remove the dependency on the network stack for control-plane communication, and tighten the security boundary.

**Solution**: Build a custom minimal Linux kernel for aarch64 with vsock compiled built-in (`=y`, not `=m`), and update both the Swift host and Rust guest agent to communicate over vsock instead of TCP/gRPC.

---

## Task 1: Build a Custom aarch64 Linux Kernel with VSock Built-In

### Goal
Cross-compile a minimal Linux kernel for `aarch64` that boots under Apple's `Virtualization.framework` with vsock support baked in. The output is a raw uncompressed `Image` file (not `vmlinuz`, not `zboot` — Virtualization.framework cannot boot compressed PE32+ stubs on Apple Silicon).

### Steps

1. **Clone the Linux kernel source** — use a stable release matching or close to what we had (6.12.x LTS). For example:
   ```bash
   git clone --depth 1 --branch v6.12.13 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
   ```

2. **Generate a minimal aarch64 defconfig**, then customize it. Start from:
   ```bash
   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig
   ```
   Then apply the following config changes (use `scripts/config` or edit `.config` directly):

   **Required — built-in (`=y`, NOT `=m`):**
   ```
   # Core virtio (needed for Virtualization.framework)
   CONFIG_VIRTIO=y
   CONFIG_VIRTIO_PCI=y
   CONFIG_VIRTIO_MMIO=y
   CONFIG_VIRTIO_BLK=y
   CONFIG_VIRTIO_NET=y
   CONFIG_VIRTIO_CONSOLE=y
   CONFIG_VIRTIO_RNG=y
   CONFIG_VIRTIO_BALLOON=y

   # VSock — THE WHOLE POINT
   CONFIG_VSOCKETS=y
   CONFIG_VIRTIO_VSOCKETS=y
   CONFIG_VIRTIO_VSOCKETS_COMMON=y

   # Networking basics (needed for DHCP fallback / outbound internet)
   CONFIG_NET=y
   CONFIG_INET=y
   CONFIG_PACKET=y          # AF_PACKET for udhcpc

   # Filesystem basics
   CONFIG_PROC_FS=y
   CONFIG_SYSFS=y
   CONFIG_DEVTMPFS=y
   CONFIG_DEVTMPFS_MOUNT=y
   CONFIG_TMPFS=y

   # Console
   CONFIG_SERIAL_AMBA_PL011=y
   CONFIG_SERIAL_AMBA_PL011_CONSOLE=y

   # initramfs support
   CONFIG_BLK_DEV_INITRD=y

   # PCI (Virtualization.framework presents virtio devices over PCI)
   CONFIG_PCI=y
   CONFIG_PCI_HOST_GENERIC=y
   ```

   **Disable to keep it small:**
   ```
   CONFIG_MODULES=n          # Everything built-in, no module loading needed
   CONFIG_SOUND=n
   CONFIG_USB=n
   CONFIG_WLAN=n
   CONFIG_BLUETOOTH=n
   CONFIG_GPU_DRIVERS=n      # or CONFIG_DRM=n
   CONFIG_INPUT_MOUSE=n
   CONFIG_INPUT_KEYBOARD=n   # (keep if you want console input)
   CONFIG_WIRELESS=n
   CONFIG_HAMRADIO=n
   CONFIG_CAN=n
   CONFIG_NFC=n
   CONFIG_MEDIA_SUPPORT=n
   CONFIG_STAGING=n
   ```

   Setting `CONFIG_MODULES=n` means we don't need to ship any `.ko` files in the initramfs — everything the kernel needs is compiled in. This eliminates the modprobe dance for `af_packet`, `virtio_net`, `virtio_rng`, etc.

3. **Cross-compile:**
   ```bash
   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc) Image
   ```
   The output is at `arch/arm64/boot/Image` — this is the raw, uncompressed ARM64 kernel binary that Virtualization.framework needs. Do NOT use `vmlinuz` or `bzImage`.

4. **Verify the config is baked in:**
   ```bash
   grep -E "VSOCK|VIRTIO_VSOCK" .config
   # Should show:
   # CONFIG_VSOCKETS=y
   # CONFIG_VIRTIO_VSOCKETS=y
   # CONFIG_VIRTIO_VSOCKETS_COMMON=y
   ```

5. **Replace the old kernel Image** in the Garden AI build with this new one. Update whatever path `garden-daemon` or the Swift host uses for `kernelURL` to point to this new `Image`.

### Important Notes
- On macOS, you'll need an aarch64 cross-compiler. Install via Homebrew: `brew install aarch64-elf-gcc` or use a Docker container with `gcc-aarch64-linux-gnu` installed (e.g., `docker run --rm -v $(pwd):/build ubuntu:24.04` then `apt install gcc-aarch64-linux-gnu make flex bison libssl-dev bc`).
- The Docker approach is more reliable for kernel builds. The full cross-compile toolchain prefix is `aarch64-linux-gnu-`.
- Build time is ~5-10 minutes with a minimal config on Apple Silicon.

---

## Task 2: Update the Initramfs (cpio.gz)

Since we set `CONFIG_MODULES=n`, the initramfs no longer needs `/lib/modules/` or BusyBox for `modprobe`. Update the cpio packing script:

1. **Remove** the `/lib/modules/` directory from the initramfs entirely.
2. **Remove** any `modprobe` calls from the init sequence in the Rust agent (the kernel already has virtio_net, af_packet, vsock, etc. built in).
3. **Keep** BusyBox static binary — it's still needed for `udhcpc` (DHCP client) and for the `garden run` command execution sandbox.
4. **Verify** `/dev/vsock` appears automatically at boot (it should, since `DEVTMPFS_MOUNT=y` and `CONFIG_VIRTIO_VSOCKETS=y`).

---

## Task 3: Update the Rust Guest Agent to Listen on VSock

### Goal
The `garden-agent` (PID 1 in the VM) should listen on a vsock port for connections from the macOS host, replacing or supplementing the TCP gRPC listener.

### Implementation

1. **Add the `vsock` crate** to the guest agent's `Cargo.toml`:
   ```toml
   [dependencies]
   vsock = "0.4"     # or latest — provides AF_VSOCK socket wrapper
   tokio-vsock = "0.5"  # if using async/tokio
   ```
   Alternatively, use raw libc bindings since we're statically linking against musl:
   ```rust
   use libc::{socket, bind, listen, accept, AF_VSOCK, SOCK_STREAM, sockaddr_vm};
   ```

2. **Listen on a well-known vsock port.** Use port `1024` or higher (ports below 1024 are privileged). Recommended: **port 6000** for the Garden AI agent service.

   ```rust
   // Using the vsock crate:
   use vsock::VsockListener;
   
   const VSOCK_PORT: u32 = 6000;

   // VMADDR_CID_ANY (-1 / 0xFFFFFFFF) binds to any CID,
   // meaning "accept connections regardless of what CID the host assigned us"
   let listener = VsockListener::bind_with_cid_port(libc::VMADDR_CID_ANY, VSOCK_PORT)?;
   
   for stream in listener.incoming() {
       let stream = stream?;
       // Handle connection — this replaces the TCP gRPC accept loop
   }
   ```

3. **Protocol options on top of vsock:**
   - **Option A (simpler):** Run your existing gRPC/tonic service over the vsock stream by implementing a custom `tonic` connector/listener that wraps vsock file descriptors. Tonic supports custom transports via `tower::Service`.
   - **Option B (lighter):** Use a simple length-prefixed JSON or protobuf protocol directly over the vsock stream, since there's only one client (the host). This avoids the HTTP/2 overhead of gRPC for a local IPC channel.
   - **Recommendation:** Start with Option A if your gRPC service definitions are already working. Migrate to Option B later if you want to minimize overhead.

4. **Verify `/dev/vsock` exists** at agent startup before attempting to bind. If it doesn't exist, fall back to TCP (graceful degradation):
   ```rust
   if std::path::Path::new("/dev/vsock").exists() {
       // Start vsock listener
   } else {
       eprintln!("[garden-agent] WARNING: /dev/vsock not found, falling back to TCP");
       // Start TCP listener on 0.0.0.0:10000 as before
   }
   ```

5. **Remove the modprobe calls** for `virtio_net`, `af_packet`, `virtio_rng`, and `vmw_vsock_virtio_transport` from the agent's init sequence. With `CONFIG_MODULES=n`, these are all built into the kernel.

6. **Keep the network init path** (bringing up `eth0`, running `udhcpc`) — the VM still needs outbound internet access for the AI agent to fetch packages, clone repos, etc. VSock replaces only the **control plane** (host↔agent commands), not the **data plane** (internet access).

---

## Task 4: Update the Swift Host to Connect via VSock

### Goal
The Swift host app should connect to the guest agent over vsock instead of TCP, eliminating the need for IP address discovery.

### Implementation

1. **Add `VZVirtioSocketDeviceConfiguration` to the VM config:**
   ```swift
   let vsockDevice = VZVirtioSocketDeviceConfiguration()
   config.socketDevices = [vsockDevice]
   ```
   This must be added alongside the existing network, storage, and other device configurations.

2. **After the VM starts, get the socket device and connect:**
   ```swift
   // Get the vsock device from the running VM
   guard let socketDevice = vm.socketDevices.first as? VZVirtioSocketDevice else {
       fatalError("No vsock device found")
   }
   
   // Connect to the guest agent on port 6000
   let port: UInt32 = 6000
   socketDevice.connect(toPort: port) { result in
       switch result {
       case .success(let connection):
           // connection is a VZVirtioSocketConnection
           // connection.fileDescriptor gives you a raw fd for read/write
           let fd = connection.fileDescriptor
           // Use this fd to send/receive data (protobuf, gRPC, etc.)
       case .failure(let error):
           print("VSock connection failed: \(error)")
       }
   }
   ```

   **Important**: On macOS, you cannot create raw `AF_VSOCK` sockets from userspace. All vsock connections MUST go through `VZVirtioSocketDevice`. This is by design — Apple routes everything through Virtualization.framework.

3. **Connection timing:** The guest agent needs a moment to boot and start listening on the vsock port. Implement a retry loop with backoff:
   ```swift
   func connectToAgent(socketDevice: VZVirtioSocketDevice, port: UInt32, retries: Int = 10) {
       var attempt = 0
       func tryConnect() {
           socketDevice.connect(toPort: port) { result in
               switch result {
               case .success(let connection):
                   self.handleConnection(connection)
               case .failure(let error):
                   attempt += 1
                   if attempt < retries {
                       DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                           tryConnect()
                       }
                   } else {
                       print("Failed to connect after \(retries) attempts: \(error)")
                   }
               }
           }
       }
       tryConnect()
   }
   ```

4. **Bridge to the Rust core via FFI:** The `VZVirtioSocketConnection` gives you a file descriptor. Pass this fd across the Swift→Rust FFI boundary so the Rust MCP server can read/write to it:
   ```swift
   @_cdecl("get_vsock_fd")
   func getVsockFd() -> Int32 {
       // Return the stored file descriptor from the vsock connection
       return Int32(activeConnection.fileDescriptor)
   }
   ```
   On the Rust side:
   ```rust
   extern "C" {
       fn get_vsock_fd() -> i32;
   }
   
   // Wrap the fd in a safe Rust type
   let fd = unsafe { get_vsock_fd() };
   let stream = unsafe { std::net::TcpStream::from_raw_fd(fd as RawFd) };
   // Or use tokio::net::TcpStream::from_std() for async
   ```

5. **Remove the hardcoded IP address** (`192.168.64.6`) from the CLI and host code. VSock uses CID + port, no IP needed. The guest CID is automatically assigned by Virtualization.framework (usually CID 3 for the first VM).

---

## Task 5: Update the `garden` CLI

Update the CLI to connect via vsock when available:
- Remove the `--host` / `--ip` flag or make it optional with a vsock default.
- The connection flow becomes: CLI → Rust Core → Swift Host (VZVirtioSocketDevice) → VSock → Guest Agent.
- No IP resolution needed. The CLI just says "run this command" and the Rust core handles routing it through the vsock connection.

---

## Architecture After This Change

```
┌──────────────┐       ┌───────────────────────────┐       ┌──────────────────┐
│  garden CLI  │──────▶│   Rust Core (MCP Server)  │──────▶│  Swift Host App  │
│              │       │                           │  FFI  │                  │
└──────────────┘       └───────────────────────────┘       └────────┬─────────┘
                                                                    │
                                                    VZVirtioSocketDevice
                                                      .connect(port: 6000)
                                                                    │
                                                              ┌─────▼─────┐
                                                              │  VSock    │
                                                              │  (no IP)  │
                                                              └─────┬─────┘
                                                                    │
                                                         ┌──────────▼──────────┐
                                                         │   Linux Guest VM    │
                                                         │   garden-agent      │
                                                         │   (PID 1)          │
                                                         │                    │
                                                         │   VSock listener   │
                                                         │   port 6000       │
                                                         │                    │
                                                         │   eth0 (DHCP) for │
                                                         │   internet only    │
                                                         └────────────────────┘
```

**Control plane**: Host ↔ Guest via vsock (no IP, no DHCP dependency, no address discovery)
**Data plane**: Guest → Internet via virtio-net + DHCP (unchanged)

---

## Verification Checklist

- [ ] Custom kernel boots under Virtualization.framework (raw `Image`, not compressed)
- [ ] `dmesg | grep vsock` in guest shows vsock transport registered
- [ ] `/dev/vsock` exists in the guest at boot
- [ ] `garden-agent` successfully binds to vsock port 6000
- [ ] Swift host connects to guest via `VZVirtioSocketDevice.connect(toPort: 6000)`
- [ ] End-to-end command execution works: `garden run /bin/busybox -- ls /` over vsock
- [ ] Outbound internet still works from the guest (DHCP + virtio-net)
- [ ] No `modprobe` calls in the init sequence (everything built-in)
- [ ] Initramfs no longer contains `/lib/modules/`
- [ ] Fallback to TCP works if `/dev/vsock` is missing

---

## Files to Modify

1. **Kernel build** — new directory: `kernel/` with build script and `.config`
2. **Initramfs packing script** — remove `/lib/modules/`, remove modprobe logic
3. **`garden-agent/src/main.rs`** (or equivalent) — add vsock listener, remove modprobe calls
4. **`garden-agent/Cargo.toml`** — add `vsock` or `tokio-vsock` dependency
5. **Swift host VM configuration** — add `VZVirtioSocketDeviceConfiguration`
6. **Swift host connection logic** — replace TCP connect with `VZVirtioSocketDevice.connect()`
7. **Rust FFI bridge** — pass vsock fd from Swift to Rust
8. **`garden` CLI** — remove hardcoded IP, use vsock path
9. **`implementation_plan.md`** — update to reflect vsock architecture

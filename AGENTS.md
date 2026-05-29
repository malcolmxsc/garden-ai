# Garden AI - Agent Instructions

## Cursor Cloud specific instructions

### Platform constraints

Garden AI is a macOS Apple Silicon-only product. The full end-to-end flow (daemon → VM → agent) **cannot run on Linux**. In a Linux Cloud Agent environment, development is limited to:

- **Compilable crates** (all except `garden-daemon`): `garden-common`, `garden-ebpf-common`, `garden-ebpf`, `garden-mcp`, `garden-cli`, `garden-agent`
- **Unit tests** for the above crates (30 tests across `garden-ebpf` and `garden-ebpf-common`)
- **Clippy and formatting checks**
- **CLI smoke tests** (`garden --help`, `garden status`, etc.)

`garden-daemon` requires macOS-only Swift FFI (`Virtualization.framework`, `objc` crate) and will not link on Linux.

### Build commands

```bash
# Build everything that compiles on Linux
cargo build --workspace --exclude garden-daemon

# Run all unit tests
cargo test --workspace --exclude garden-daemon

# Lint
cargo clippy --workspace --exclude garden-daemon

# Format check
cargo fmt --check
```

### eBPF probe stub

The `garden-ebpf` crate uses `include_bytes!` to embed the compiled eBPF probe binary at compile time. The probes are built separately (target `bpfel-unknown-none`, requires Rust nightly + LLVM 21) and are excluded from the workspace. A stub file must exist at `crates/garden-ebpf-probes/target/bpfel-unknown-none/release/garden-ebpf-probes` for `garden-ebpf` to compile on Linux. The update script creates this stub automatically. The eBPF integration tests (`probe_loading`, `bpf_load_diag`) are all `#[ignore]` and require root + a BPF-capable kernel.

### System dependencies

- `protobuf-compiler` (protoc) — required by `garden-common` build.rs for `tonic-build` gRPC codegen
- `libssl-dev` — required by `openssl-sys` (transitive dependency via `reqwest`)
- Rust stable toolchain (1.85+) — the `Cargo.lock` pins dependencies requiring Rust 1.85+

### Key gotchas

- The `garden-daemon` tests (30+ tests in `event_log.rs`) cannot be run on Linux because the daemon binary fails to link (missing `libgarden_swift.a` and ObjC runtime).
- `cargo fmt --check` may report formatting diffs in existing code — these are pre-existing and not lint-blocking (exit code 0 when informational).
- The `.cargo/config.toml` sets a cross-compilation linker for `aarch64-unknown-linux-musl` using a zig-based script. This only affects cross-compilation and is harmless on x86_64.

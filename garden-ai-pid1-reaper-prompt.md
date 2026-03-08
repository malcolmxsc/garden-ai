# Garden AI — Fix Kernel Panic: Implement PID 1 Child Process Reaping

## Context

The `garden-agent` runs as PID 1 (`/init`) inside a Linux micro-VM booted via Apple's Virtualization.framework. The VM uses a custom aarch64 kernel with `CONFIG_MODULES=n` and a minimal initramfs containing the statically-compiled Rust agent + BusyBox.

The gRPC-over-vSock transport layer is fully working. The agent receives `ExecuteCommand` RPCs from the host via vsock, spawns child processes (e.g., `/bin/busybox ls /`), and returns stdout/stderr/exit code.

**The bug:** When a spawned child process exits, the kernel panics. This happens because:

1. PID 1 is special in Linux — if PID 1 dies or receives an unhandled fatal signal, the kernel panics immediately. There is no recovery.
2. When a child process exits, the kernel sends `SIGCHLD` to its parent (PID 1). If PID 1 doesn't handle `SIGCHLD`, the default disposition may cause issues. More critically, if PID 1 doesn't call `waitpid()` on exited children, they become zombies.
3. In a normal Linux system, `systemd` or `init` handles all of this. We have neither — our Rust binary IS init.

## Requirements

Implement robust PID 1 process management in the `garden-agent` so that:

1. Child processes can be spawned and reaped without kernel panics
2. Exit codes are captured and returned to the caller (the `ExecuteCommand` RPC handler needs them)
3. Orphaned processes (children of children) are properly reaped as zombies get reparented to PID 1
4. The agent never exits or panics — any unhandled error must be caught and logged, not propagated

## Implementation Plan

### Step 1: Install Signal Handlers at Agent Startup

Before doing ANYTHING else (before mounting filesystems, before starting the vsock listener), set up signal handling. This is the very first code that runs in `main()`:

```rust
use std::sync::atomic::{AtomicBool, Ordering};

static SIGCHLD_RECEIVED: AtomicBool = AtomicBool::new(false);

fn install_signal_handlers() {
    unsafe {
        // SIGCHLD — set a flag so we can reap in the main loop
        libc::signal(libc::SIGCHLD, sigchld_handler as libc::sighandler_t);

        // Ignore signals that would kill PID 1
        // SIGTERM — host may send this on VM shutdown, handle gracefully
        libc::signal(libc::SIGTERM, sigterm_handler as libc::sighandler_t);
        // SIGHUP — ignore, no controlling terminal
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        // SIGPIPE — ignore, broken vsock connections shouldn't kill init
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        // SIGINT — could come from console, ignore or handle
        libc::signal(libc::SIGINT, libc::SIG_IGN);
    }
}

extern "C" fn sigchld_handler(_sig: libc::c_int) {
    // Signal handlers must be async-signal-safe.
    // Only set an atomic flag — do NOT call waitpid() here.
    SIGCHLD_RECEIVED.store(true, Ordering::SeqCst);
}

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn sigterm_handler(_sig: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}
```

**Critical:** Call `install_signal_handlers()` as the absolute first line of `main()`, before any other initialization.

### Step 2: Implement the Zombie Reaper

Create a reaper function that collects all exited children. This must be called:
- Periodically in the background (catches orphaned zombies reparented to PID 1)
- After every command execution (captures the exit code we need)

```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Maps child PID → exit status for processes we care about
type ExitMap = Arc<Mutex<HashMap<i32, i32>>>;

/// Reap all zombie children. Returns the number of processes reaped.
/// This is safe to call at any time — it won't block.
fn reap_zombies(exit_map: &ExitMap) -> usize {
    let mut reaped = 0;
    loop {
        let mut status: libc::c_int = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };

        match pid {
            // No more children to reap
            0 => break,
            // Error — either no children exist (ECHILD) or interrupted
            -1 => break,
            // Successfully reaped a child
            pid => {
                reaped += 1;
                let exit_code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else if libc::WIFSIGNALED(status) {
                    // Killed by signal — convention is 128 + signal number
                    128 + libc::WTERMSIG(status)
                } else {
                    -1
                };

                // Store the exit code so the RPC handler can retrieve it
                if let Ok(mut map) = exit_map.lock() {
                    map.insert(pid, exit_code);
                }

                eprintln!("[init] reaped child pid={} exit_code={}", pid, exit_code);
            }
        }
    }

    // Reset the flag
    SIGCHLD_RECEIVED.store(false, Ordering::SeqCst);
    reaped
}
```

### Step 3: Background Reaper Task

Spawn a tokio task that periodically reaps zombies. This catches orphaned processes (grandchildren that get reparented to PID 1 when their parent exits) that we wouldn't otherwise know about:

```rust
fn spawn_reaper_task(exit_map: ExitMap) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            interval.tick().await;

            // Only call waitpid if we got a SIGCHLD (avoids unnecessary syscalls)
            if SIGCHLD_RECEIVED.load(Ordering::SeqCst) {
                reap_zombies(&exit_map);
            }

            // Check for shutdown
            if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                eprintln!("[init] SIGTERM received, shutting down...");
                // Optionally: kill all children, reap them, then:
                unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) };
            }
        }
    });
}
```

### Step 4: Update the `ExecuteCommand` RPC Handler

The current handler likely uses `std::process::Command` or `tokio::process::Command`. Update it to:

1. Spawn the child process
2. Wait for it using tokio's built-in child management (NOT raw `waitpid` — let tokio handle its own children)
3. Return stdout, stderr, and the exit code

```rust
use tokio::process::Command;

async fn execute_command(
    program: &str,
    args: &[String],
    exit_map: &ExitMap,
) -> Result<(String, String, i32), String> {
    let result = Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let child = match result {
        Ok(child) => child,
        Err(e) => return Err(format!("Failed to spawn process: {}", e)),
    };

    // tokio::process::Command internally handles SIGCHLD and waitpid
    // for children it spawns. Our background reaper handles everything else.
    match child.wait_with_output().await {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let exit_code = output.status.code().unwrap_or(-1);
            Ok((stdout, stderr, exit_code))
        }
        Err(e) => Err(format!("Failed to wait for process: {}", e)),
    }
}
```

**Important interaction between tokio and our reaper:** `tokio::process::Command` registers its own `SIGCHLD` handler internally to manage children it spawns. This can conflict with our manual `libc::signal(SIGCHLD, ...)` handler. There are two ways to handle this:

**Option A (Recommended): Use `tokio::signal::unix::signal(SignalKind::child())` instead of raw `libc::signal`.** This integrates with tokio's signal handling infrastructure and avoids conflicts:

```rust
use tokio::signal::unix::{signal, SignalKind};

fn spawn_reaper_task(exit_map: ExitMap) {
    tokio::spawn(async move {
        let mut sigchld = signal(SignalKind::child()).expect("failed to register SIGCHLD");

        loop {
            sigchld.recv().await;
            reap_zombies(&exit_map);

            if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                eprintln!("[init] SIGTERM received, shutting down...");
                unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) };
            }
        }
    });
}
```

**Option B: Use `SIG_IGN` for SIGCHLD and let the kernel auto-reap.** Simpler but you lose exit code tracking for orphaned processes:

```rust
unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN); }
```

With this approach, `tokio::process::Command` still works because it uses `pidfd` or `waitpid` on specific PIDs before the kernel auto-reaps. But orphaned grandchildren just vanish silently. This is fine if you don't care about their exit codes (and you probably don't — they're orphans).

**Recommendation:** Use Option A (`tokio::signal`) for the background reaper. Use `tokio::process::Command` for your own children. They coexist fine because the reaper only calls `waitpid(-1, WNOHANG)` which reaps whatever's available, and tokio's Command uses `waitpid(specific_pid, ...)` for its own children.

### Step 5: Wrap All of `main()` in a Panic Catch

PID 1 must never panic. Wrap the entire agent in a catch:

```rust
fn main() {
    // Install signal handlers FIRST — before anything can panic
    install_signal_handlers();

    // Catch any panic in the rest of the program
    let result = std::panic::catch_unwind(|| {
        // Build and run the tokio runtime
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");

        rt.block_on(async_main());
    });

    match result {
        Ok(()) => {
            eprintln!("[init] async_main returned cleanly, halting");
        }
        Err(e) => {
            eprintln!("[init] PANIC caught: {:?}", e);
            eprintln!("[init] PID 1 cannot exit — entering emergency loop");
        }
    }

    // PID 1 must NEVER exit. If we get here, loop forever.
    // The host can still kill the VM externally.
    loop {
        unsafe { libc::pause() };
        // Reap any remaining zombies while we're stuck here
        let exit_map: ExitMap = Arc::new(Mutex::new(HashMap::new()));
        reap_zombies(&exit_map);
    }
}

async fn async_main() {
    // Mount /proc, /sys, /dev
    // Start network
    // Start vsock listener
    // Start gRPC server
    // ... everything that's currently in main()
}
```

### Step 6: Mount /proc Before Signal Handling (if not already)

`tokio::signal` on Linux uses signalfd or a self-pipe trick that may need `/proc`. Make sure the mount order is:

1. `install_signal_handlers()` — raw libc signals (works without /proc)
2. `mount /proc`, `mount /sys`, `mount /dev`
3. Start tokio runtime
4. Inside tokio: set up `tokio::signal::unix::signal(SignalKind::child())` for the reaper
5. Start vsock listener + gRPC server

## Verification

- [ ] `garden run /bin/busybox -- ls /` completes without kernel panic
- [ ] `garden run /bin/busybox -- echo hello` returns stdout "hello" and exit code 0
- [ ] Running 10 commands in sequence doesn't leak zombies (check with `busybox ps` if available)
- [ ] Killing a long-running child (`sleep 999` then Ctrl+C on the CLI) doesn't panic the agent
- [ ] Agent survives a panic in a request handler (test by sending a malformed request)
- [ ] `SIGTERM` triggers clean VM shutdown (send from host via `vm.stop()`)
- [ ] No zombie processes accumulate over time

## Files to Modify

1. **`garden-agent/src/main.rs`** — restructure main() with panic catch, signal handlers, and emergency loop
2. **`garden-agent/src/reaper.rs`** (new file) — zombie reaper logic, exit code map, background task
3. **`garden-agent/src/rpc.rs`** (or wherever ExecuteCommand lives) — use tokio::process::Command, integrate with exit map
4. **`garden-agent/Cargo.toml`** — ensure `tokio` has the `process` and `signal` features enabled:
   ```toml
   tokio = { version = "1", features = ["full"] }
   # or at minimum: ["rt-multi-thread", "macros", "signal", "process", "time", "io-util"]
   ```

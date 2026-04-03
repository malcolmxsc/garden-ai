mod event_log;
mod virtualizer;

use virtualizer::Virtualizer;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use garden_common::daemon::daemon_service_server::{DaemonService, DaemonServiceServer};
use garden_common::daemon::{
    BootVmRequest, BootVmResponse, StopVmRequest, StopVmResponse,
    VmStatusRequest, VmStatusResponse,
};

// =====================================================================
// Shared VM State
// =====================================================================
// The DaemonService gRPC handlers and the main boot logic both need
// access to the VM's running state. We use atomics and mutexes wrapped
// in Arc so the gRPC service (running on a background tokio runtime)
// can safely read and update state.
struct VmState {
    running: AtomicBool,
    boot_time: Mutex<Option<Instant>>,
    kernel_path: Mutex<String>,
}

// =====================================================================
// DaemonService gRPC Implementation
// =====================================================================
struct DaemonServiceImpl {
    engine: &'static Virtualizer,
    state: Arc<VmState>,
}

#[tonic::async_trait]
impl DaemonService for DaemonServiceImpl {
    async fn boot_vm(
        &self,
        request: tonic::Request<BootVmRequest>,
    ) -> Result<tonic::Response<BootVmResponse>, tonic::Status> {
        if self.state.running.load(Ordering::SeqCst) {
            return Ok(tonic::Response::new(BootVmResponse {
                success: false,
                message: "VM is already running".into(),
            }));
        }

        let req = request.into_inner();

        let kernel = if req.kernel_path.is_empty() {
            "/Users/malcolmgriffin/.gemini/antigravity/scratch/garden-ai/guest/kernel/kernel".to_string()
        } else {
            req.kernel_path
        };
        let initrd = if req.initrd_path.is_empty() {
            "/Users/malcolmgriffin/.gemini/antigravity/scratch/garden-ai/guest/kernel/garden-initrd.cpio.gz".to_string()
        } else {
            req.initrd_path
        };
        let cpus = if req.cpus == 0 { 2 } else { req.cpus };
        let memory_mb = if req.memory_mb == 0 { 512 } else { req.memory_mb };

        // Write policy JSON to VirtioFS so the guest agent can read it at startup.
        // ~/GardenBox is mounted at /workspace inside the guest.
        let home = std::env::var("HOME").unwrap_or_default();
        let policy_file = std::path::Path::new(&home)
            .join("GardenBox")
            .join(".garden-policy.json");
        if !req.policy_json.is_empty() {
            if let Err(e) = std::fs::write(&policy_file, req.policy_json.as_bytes()) {
                eprintln!("⚠️  Failed to write policy to VirtioFS: {} — guest will use default-observe", e);
            } else {
                println!("📋 Policy written to {}", policy_file.display());
            }
        } else {
            let _ = std::fs::remove_file(&policy_file); // clear stale policy from prior boot
        }

        if let Err(e) = self.engine.configure(&kernel, &initrd, cpus, memory_mb) {
            return Ok(tonic::Response::new(BootVmResponse {
                success: false,
                message: format!("Configure failed: {}", e),
            }));
        }

        if let Err(e) = self.engine.start() {
            return Ok(tonic::Response::new(BootVmResponse {
                success: false,
                message: format!("Start failed: {}", e),
            }));
        }

        self.state.running.store(true, Ordering::SeqCst);
        *self.state.boot_time.lock().unwrap() = Some(Instant::now());
        *self.state.kernel_path.lock().unwrap() = kernel;

        // Start proxies after a brief delay for the guest to initialize
        let engine = self.engine;
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(3));
            run_tcp_vsock_proxy(engine, 6000);
        });
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(5));
            run_telemetry_receiver(engine);
        });

        Ok(tonic::Response::new(BootVmResponse {
            success: true,
            message: "VM booted successfully".into(),
        }))
    }

    async fn stop_vm(
        &self,
        _request: tonic::Request<StopVmRequest>,
    ) -> Result<tonic::Response<StopVmResponse>, tonic::Status> {
        if !self.state.running.load(Ordering::SeqCst) {
            return Ok(tonic::Response::new(StopVmResponse {
                success: false,
                message: "No VM is running".into(),
            }));
        }

        match self.engine.stop() {
            Ok(_) => {
                self.state.running.store(false, Ordering::SeqCst);
                *self.state.boot_time.lock().unwrap() = None;
                Ok(tonic::Response::new(StopVmResponse {
                    success: true,
                    message: "VM stopped successfully".into(),
                }))
            }
            Err(e) => Ok(tonic::Response::new(StopVmResponse {
                success: false,
                message: format!("Stop failed: {}", e),
            })),
        }
    }

    async fn get_vm_status(
        &self,
        _request: tonic::Request<VmStatusRequest>,
    ) -> Result<tonic::Response<VmStatusResponse>, tonic::Status> {
        let running = self.state.running.load(Ordering::SeqCst);
        let uptime = self.state.boot_time.lock().unwrap()
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);
        let kernel_path = self.state.kernel_path.lock().unwrap().clone();

        Ok(tonic::Response::new(VmStatusResponse {
            running,
            uptime_seconds: uptime,
            kernel_path,
        }))
    }
}

fn main() {
    println!("🌱 Starting Garden Engine Daemon...");

    // 1. Initialize the FFI Bridge
    println!("Checking Apple Silicon Virtualization support...");

    let engine = match Virtualizer::new() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("❌ Failed to initialize Garden Engine: {}", e);
            std::process::exit(1);
        }
    };

    // 2. Check hardware support
    match engine.check_hardware() {
        Ok(_) => println!("✅ Virtualization hardware is supported and ready!"),
        Err(e) => {
            eprintln!("❌ Virtualization checks failed: {}", e);
            std::process::exit(1);
        }
    }

    // 3. Configure the VM
    println!("⚙️ Configuring Virtual Machine (2 CPUs, 512MB RAM)...");

    let kernel_path = "/Users/malcolmgriffin/.gemini/antigravity/scratch/garden-ai/guest/kernel/kernel";
    let initrd_path = "/Users/malcolmgriffin/.gemini/antigravity/scratch/garden-ai/guest/kernel/garden-initrd.cpio.gz";

    match engine.configure(kernel_path, initrd_path, 2, 512) {
        Ok(_) => println!("✅ VM successfully configured by Apple Hypervisor!"),
        Err(e) => {
            eprintln!("❌ VM configuration failed: {}", e);
            std::process::exit(1);
        }
    }

    // 4. Boot the VM
    println!("🚀 Booting the Alpine Linux VM...");
    match engine.start() {
        Ok(_) => println!("✅ VM Boot sequence initiated!"),
        Err(e) => {
            eprintln!("❌ VM failed to boot: {}", e);
            std::process::exit(1);
        }
    }

    // Shared VM state for the DaemonService
    let vm_state = Arc::new(VmState {
        running: AtomicBool::new(true),
        boot_time: Mutex::new(Some(Instant::now())),
        kernel_path: Mutex::new(kernel_path.to_string()),
    });

    // 5. Wait for agent to be ready, then start TCP proxy
    // =================================================================
    // For each incoming CLI TCP connection, we open a FRESH vSock connection
    // to the guest agent. The agent's VsockIncoming listener will accept()
    // each one independently, giving each CLI connection its own HTTP/2 stream.
    println!("🔌 Starting TCP→vSock proxy (background thread)...");

    let engine: &'static Virtualizer = Box::leak(Box::new(engine));

    std::thread::spawn(move || {
        // Wait for the VM kernel to boot and the agent to start listening
        std::thread::sleep(std::time::Duration::from_secs(3));

        // Start the TCP proxy — vSock connections are made on-demand per CLI session
        let vsock_port: u32 = 6000;
        run_tcp_vsock_proxy(engine, vsock_port);
    });

    // 6. Start telemetry receiver (connects to guest eBPF vSock port 6001)
    // =================================================================
    // Also starts a TCP proxy on 127.0.0.1:10001 so external tools can
    // tap the raw telemetry NDJSON stream.
    println!("📊 Starting telemetry receiver (background thread)...");

    std::thread::spawn(move || {
        // Wait longer than gRPC proxy — eBPF probes load after gRPC server starts
        std::thread::sleep(std::time::Duration::from_secs(5));
        run_telemetry_receiver(engine);
    });

    // 7. Start DaemonService gRPC server on port 9000 (background thread)
    // =================================================================
    // This allows the CLI to send boot/stop/status commands to the daemon.
    println!("🔧 Starting DaemonService gRPC on 127.0.0.1:9000...");

    let daemon_state = vm_state.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to build tokio runtime for DaemonService");

        rt.block_on(async move {
            let service = DaemonServiceImpl {
                engine,
                state: daemon_state,
            };

            let addr = "127.0.0.1:9000".parse().unwrap();
            match tonic::transport::Server::builder()
                .add_service(DaemonServiceServer::new(service))
                .serve(addr)
                .await
            {
                Ok(_) => {}
                Err(e) => eprintln!("❌ DaemonService gRPC server error: {}", e),
            }
        });
    });

    // 8. Start HTTP REST API on port 9001 for Swift UI thin client
    // =================================================================
    // Exposes: GET /api/status, POST /api/boot, POST /api/stop
    println!("🌐 Starting HTTP API on 127.0.0.1:9001...");
    let http_state = vm_state.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to build tokio runtime for HTTP API");
        rt.block_on(run_http_api(engine, http_state));
    });

    println!("🔄 Daemon handing control to macOS CFRunLoop. Press Ctrl+C to stop.");
    // run_loop() returns when the VM stops. Keep looping so the daemon stays
    // alive and the gRPC/HTTP servers can accept a subsequent `garden boot`.
    loop {
        Virtualizer::run_loop();
        println!("🔄 VM stopped — daemon staying alive, waiting for next boot command.");
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

// =====================================================================
// TCP-to-vSock Async Proxy (per-connection vSock)
// =====================================================================
// For each CLI TCP connection to 127.0.0.1:10000, we open a NEW vSock
// connection to the guest agent. This gives each CLI connection its own
// isolated gRPC/HTTP/2 channel. The agent's VsockIncoming listener will
// accept() each connection independently.
fn run_tcp_vsock_proxy(engine: &'static Virtualizer, vsock_port: u32) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime for proxy");
    
    rt.block_on(async move {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:10000").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("❌ Failed to bind proxy: {}", e);
                return;
            }
        };
        println!("✅ TCP→vSock proxy listening on 127.0.0.1:10000");
        
        loop {
            let (tcp_stream, addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("❌ Accept error: {}", e);
                    continue;
                }
            };
            
            println!("📥 CLI connected from {}", addr);
            
            // Open a FRESH vSock connection for this CLI session.
            // connect_vsock dispatches to the main thread via GCD.
            let vsock_fd = match engine.connect_vsock(vsock_port) {
                Ok(fd) => {
                    println!("   🔗 New vSock connection fd={}", fd);
                    fd
                }
                Err(e) => {
                    eprintln!("   ❌ vSock connect failed: {}", e);
                    continue;
                }
            };
            
            // Set non-blocking for async I/O
            unsafe {
                let flags = libc::fcntl(vsock_fd, libc::F_GETFL);
                libc::fcntl(vsock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
            
            // Wrap in our async VsockStream
            let vsock_stream = match VsockStream::new(vsock_fd) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("   ❌ VsockStream error: {}", e);
                    unsafe { libc::close(vsock_fd); }
                    continue;
                }
            };
            
            // Spawn a task to bidirectionally copy bytes: TCP ↔ vSock
            tokio::spawn(async move {
                let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_stream);
                let (mut vsock_read, mut vsock_write) = tokio::io::split(vsock_stream);
                
                let t1 = tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut tcp_read, &mut vsock_write).await;
                });
                let t2 = tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut vsock_read, &mut tcp_write).await;
                });
                
                let _ = tokio::try_join!(t1, t2);
                println!("📤 CLI disconnected from {}", addr);
            });
        }
    });
}

// =====================================================================
// Telemetry Receiver (connects to guest eBPF vSock port 6001)
// =====================================================================
// Reads NDJSON SecurityEvent stream from the guest agent's eBPF tracer.
// Also starts a TCP proxy on 127.0.0.1:10001 for external tools to tap
// the raw telemetry stream.
fn run_telemetry_receiver(engine: &'static Virtualizer) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime for telemetry");

    // Load host-side policy from ~/.garden/policy.json if present.
    // Falls back to default-observe (log everything, deny nothing).
    let policy = {
        let home = std::env::var("HOME").unwrap_or_default();
        let p = std::path::Path::new(&home).join(".garden").join("policy.json");
        std::fs::read_to_string(&p)
            .ok()
            .and_then(|json| {
                serde_json::from_str(&json)
                    .map_err(|e| { eprintln!("⚠️  Bad host policy at {}: {}", p.display(), e); e })
                    .ok()
            })
            .unwrap_or_else(garden_ebpf::policy::SecurityPolicy::default_observe)
    };
    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<String>(256);

    let logger = std::sync::Arc::new(
        event_log::EventLogger::new().expect("Failed to create session event log"),
    );
    println!("📋 Session log: {}", logger.session_dir().display());

    rt.block_on(async move {
        // Also start a TCP proxy for telemetry on port 10001
        // so external tools (socat, test scripts) can tap the stream
        tokio::spawn(run_telemetry_tcp_proxy(broadcast_tx.clone()));

        loop {
            println!("📊 Connecting to guest telemetry vSock port 6001...");

            let vsock_fd = match engine.connect_vsock(6001) {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("📊 Telemetry connect failed: {}, retrying in 2s...", e);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
            };

            println!("📊 Telemetry connected to guest, fd={}", vsock_fd);

            // Set non-blocking for async I/O
            unsafe {
                let flags = libc::fcntl(vsock_fd, libc::F_GETFL);
                libc::fcntl(vsock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }

            let stream = match VsockStream::new(vsock_fd) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("📊 VsockStream error: {}, retrying...", e);
                    unsafe { libc::close(vsock_fd); }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
            };

            // Read NDJSON lines, evaluate policy, log to session file, and broadcast
            process_telemetry_stream(stream, &policy, &broadcast_tx, logger.clone()).await;

            println!("📊 Telemetry connection lost, reconnecting in 2s...");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
}

async fn process_telemetry_stream(
    stream: VsockStream,
    policy: &garden_ebpf::policy::SecurityPolicy,
    broadcast_tx: &tokio::sync::broadcast::Sender<String>,
    logger: std::sync::Arc<event_log::EventLogger>,
) {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();


    while let Ok(Some(line)) = lines.next_line().await {
        match serde_json::from_str::<garden_ebpf::events::SecurityEvent>(&line) {
            Ok(event) => {
                // Persist to session log; get back any violation for enforcement.
                let violation = match logger.log(&event) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("📋 Failed to write session log: {}", e);
                        None
                    }
                };

                // Broadcast enriched event (with violation info) to TCP proxy
                // clients so the SwiftUI app can filter violations.
                // Override "allowed" to false when there's a violation — the
                // tracepoint fires before the LSM hook and doesn't know the
                // LSM will return -EPERM, so it reports allowed=true.
                let mut kind_json = serde_json::to_value(&event.kind)
                    .unwrap_or(serde_json::Value::Null);
                if violation.is_some() {
                    if let Some(obj) = kind_json.as_object_mut() {
                        if obj.contains_key("allowed") {
                            obj.insert("allowed".into(), serde_json::Value::Bool(false));
                        }
                    }
                }
                let enriched = serde_json::json!({
                    "timestamp_ns": event.timestamp_ns,
                    "pid": event.pid,
                    "comm": event.comm,
                    "kind": kind_json,
                    "violation": violation,
                });
                let _ = broadcast_tx.send(format!("{}\n", enriched));

                // Enforce hardcoded violations: SIGKILL the offending process.
                // Rules with in-kernel enforcement (LSM -EPERM + bpf_send_signal)
                // don't need a redundant reactive kill — the process is already dead
                // by the time this event reaches the daemon.
                if let Some(ref v) = violation {
                    let kernel_enforced = matches!(
                        v.rule,
                        "proc_memory_access"
                        | "namespace_escape_attempt"
                        | "write_outside_workspace"
                        | "privileged_binary_exec"
                    );
                    let should_kill = matches!(v.severity, "critical" | "high") && !kernel_enforced;
                    if should_kill && event.pid != 1 {
                        eprintln!(
                            "🚨 ENFORCING [{}] rule={} pid={} comm={} — sending SIGKILL",
                            v.severity, v.rule, event.pid, event.comm
                        );
                        let pid = event.pid;
                        tokio::spawn(async move {
                            if let Ok(mut client) =
                                garden_common::ipc::agent_service_client::AgentServiceClient::connect(
                                    "http://127.0.0.1:10000",
                                )
                                .await
                            {
                                let req = tonic::Request::new(garden_common::ipc::CommandRequest {
                                    command: "kill".to_string(),
                                    args: vec!["-9".to_string(), pid.to_string()],
                                    cwd: ".".to_string(),
                                });
                                let _ = client.execute_command(req).await;
                            }
                        });
                    }
                }

                // Enforce configurable policy (JSON policy file).
                let action = policy.evaluate(&event);
                match action {
                    garden_ebpf::policy::PolicyAction::Deny => {
                        eprintln!(
                            "🚨 POLICY DENY: pid={} comm={} {:?}",
                            event.pid, event.comm, event.kind
                        );
                        if event.pid != 1 {
                            let pid = event.pid;
                            tokio::spawn(async move {
                                if let Ok(mut client) =
                                    garden_common::ipc::agent_service_client::AgentServiceClient::connect(
                                        "http://127.0.0.1:10000",
                                    )
                                    .await
                                {
                                    let req = tonic::Request::new(garden_common::ipc::CommandRequest {
                                        command: "kill".to_string(),
                                        args: vec!["-9".to_string(), pid.to_string()],
                                        cwd: ".".to_string(),
                                    });
                                    let _ = client.execute_command(req).await;
                                }
                            });
                        }
                    }
                    garden_ebpf::policy::PolicyAction::Log => {
                        if violation.is_none() {
                            println!(
                                "📊 [telemetry] pid={} comm={} {:?}",
                                event.pid, event.comm, event.kind
                            );
                        }
                    }
                    #[allow(unreachable_patterns)]
                    garden_ebpf::policy::PolicyAction::Allow => {}
                }
            }
            Err(e) => {
                eprintln!("📊 Failed to parse telemetry event: {} (line: {})", e, line);
            }
        }
    }
}

/// TCP proxy for telemetry on 127.0.0.1:10001.
/// External tools (socat, test scripts) can connect here to receive
/// the raw NDJSON telemetry stream from the guest.
///
/// Uses a broadcast channel: the main telemetry receiver reads from the
/// single vSock connection and broadcasts each line to all TCP clients.
async fn run_telemetry_tcp_proxy(broadcast_tx: tokio::sync::broadcast::Sender<String>) {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:10001").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("📊 Failed to bind telemetry proxy on 10001: {}", e);
            return;
        }
    };
    println!("✅ Telemetry TCP proxy listening on 127.0.0.1:10001");

    loop {
        let (tcp_stream, addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("📊 Telemetry proxy accept error: {}", e);
                continue;
            }
        };

        println!("📊 Telemetry consumer connected from {}", addr);

        let mut rx = broadcast_tx.subscribe();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let (_, mut tcp_write) = tokio::io::split(tcp_stream);
            while let Ok(line) = rx.recv().await {
                if tcp_write.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
            }
            println!("📊 Telemetry consumer disconnected from {}", addr);
        });
    }
}

// =====================================================================
// HTTP REST API (port 9001) — for the Swift UI thin client
// =====================================================================
// Three endpoints:
//   GET  /api/status  → {"running":bool,"uptime_seconds":u64,"kernel_path":str}
//   POST /api/boot    → {"success":bool,"message":str}
//   POST /api/stop    → {"success":bool,"message":str}
//
// The engine pointer is `&'static Virtualizer` (Box::leaked in main) so it
// is safe to move into the axum handler closures.

#[derive(serde::Serialize)]
struct ApiStatusResponse {
    running: bool,
    uptime_seconds: u64,
    kernel_path: String,
}

#[derive(serde::Serialize)]
struct ApiActionResponse {
    success: bool,
    message: String,
}

// ---------------------------------------------------------------------------
// Session log endpoints
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct SessionInfo {
    id: String,
    start_ts: String,
    event_count: u64,
}

async fn api_list_sessions() -> axum::Json<Vec<SessionInfo>> {
    let home = std::env::var("HOME").unwrap_or_default();
    let sessions_dir = std::path::Path::new(&home).join(".garden").join("sessions");
    let mut sessions = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&sessions_dir) {
        for entry in entries.flatten() {
            let id = entry.file_name().to_string_lossy().to_string();
            // Only allow numeric session IDs (Unix ms timestamps) — prevent path traversal
            if !id.chars().all(|c| c.is_ascii_digit()) { continue; }
            let events_path = entry.path().join("events.ndjson");
            let event_count = std::fs::read_to_string(&events_path)
                .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count() as u64)
                .unwrap_or(0);
            sessions.push(SessionInfo { id: id.clone(), start_ts: id, event_count });
        }
    }
    sessions.sort_by(|a, b| b.id.cmp(&a.id)); // newest first
    axum::Json(sessions)
}

async fn api_get_session_events(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> axum::Json<Vec<serde_json::Value>> {
    // Validate: only numeric IDs (Unix ms timestamps)
    if !id.chars().all(|c| c.is_ascii_digit()) {
        return axum::Json(vec![]);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let events_path = std::path::Path::new(&home)
        .join(".garden").join("sessions").join(&id).join("events.ndjson");
    let mut events = Vec::new();
    if let Ok(content) = std::fs::read_to_string(&events_path) {
        for line in content.lines() {
            if line.trim().is_empty() { continue; }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                events.push(v);
            }
        }
    }
    axum::Json(events)
}

async fn run_http_api(engine: &'static Virtualizer, state: Arc<VmState>) {
    use axum::{routing, Router};

    let st = state.clone();
    let status_handler = move || {
        let running = st.running.load(Ordering::SeqCst);
        let uptime = st.boot_time.lock().unwrap()
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);
        let kernel_path = st.kernel_path.lock().unwrap().clone();
        async move {
            axum::Json(ApiStatusResponse { running, uptime_seconds: uptime, kernel_path })
        }
    };

    let st_boot = state.clone();
    let boot_handler = move || {
        let st = st_boot.clone();
        async move {
            if st.running.load(Ordering::SeqCst) {
                return axum::Json(ApiActionResponse {
                    success: false,
                    message: "VM is already running".into(),
                });
            }
            let kernel = "/Users/malcolmgriffin/.gemini/antigravity/scratch/garden-ai/guest/kernel/kernel".to_string();
            let initrd  = "/Users/malcolmgriffin/.gemini/antigravity/scratch/garden-ai/guest/kernel/garden-initrd.cpio.gz".to_string();
            if let Err(e) = engine.configure(&kernel, &initrd, 2, 512) {
                return axum::Json(ApiActionResponse { success: false, message: format!("Configure failed: {}", e) });
            }
            if let Err(e) = engine.start() {
                return axum::Json(ApiActionResponse { success: false, message: format!("Start failed: {}", e) });
            }
            st.running.store(true, Ordering::SeqCst);
            *st.boot_time.lock().unwrap() = Some(Instant::now());
            *st.kernel_path.lock().unwrap() = kernel;
            // Start proxies
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(3));
                run_tcp_vsock_proxy(engine, 6000);
            });
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(5));
                run_telemetry_receiver(engine);
            });
            axum::Json(ApiActionResponse { success: true, message: "VM booted".into() })
        }
    };

    let st_stop = state.clone();
    let stop_handler = move || {
        let st = st_stop.clone();
        async move {
            if !st.running.load(Ordering::SeqCst) {
                return axum::Json(ApiActionResponse { success: false, message: "No VM running".into() });
            }
            match engine.stop() {
                Ok(_) => {
                    st.running.store(false, Ordering::SeqCst);
                    *st.boot_time.lock().unwrap() = None;
                    axum::Json(ApiActionResponse { success: true, message: "VM stopped".into() })
                }
                Err(e) => axum::Json(ApiActionResponse { success: false, message: format!("Stop failed: {}", e) }),
            }
        }
    };

    let app = Router::new()
        .route("/api/status",                   routing::get(status_handler))
        .route("/api/boot",                     routing::post(boot_handler))
        .route("/api/stop",                     routing::post(stop_handler))
        .route("/api/sessions",                 routing::get(api_list_sessions))
        .route("/api/sessions/{id}/events",     routing::get(api_get_session_events));

    let listener = match tokio::net::TcpListener::bind("127.0.0.1:9001").await {
        Ok(l) => l,
        Err(e) => { eprintln!("❌ HTTP API bind failed: {}", e); return; }
    };
    println!("✅ HTTP API listening on 127.0.0.1:9001");
    axum::serve(listener, app).await.unwrap_or_else(|e| eprintln!("❌ HTTP API error: {}", e));
}

// =====================================================================
// VsockStream: AsyncRead + AsyncWrite wrapper for any raw fd
// =====================================================================
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

struct VsockStream {
    inner: tokio::io::unix::AsyncFd<RawFdWrapper>,
}

struct RawFdWrapper(RawFd);

impl AsRawFd for RawFdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl VsockStream {
    fn new(fd: RawFd) -> std::io::Result<Self> {
        let inner = tokio::io::unix::AsyncFd::new(RawFdWrapper(fd))?;
        Ok(Self { inner })
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        unsafe { libc::close(self.inner.as_raw_fd()); }
    }
}

impl tokio::io::AsyncRead for VsockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            let mut guard = match self.inner.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            
            let fd = self.inner.as_raw_fd();
            let unfilled = buf.initialize_unfilled();
            let n = unsafe {
                libc::read(fd, unfilled.as_mut_ptr() as *mut libc::c_void, unfilled.len())
            };
            
            if n >= 0 {
                buf.advance(n as usize);
                return Poll::Ready(Ok(()));
            } else {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Poll::Ready(Err(err));
            }
        }
    }
}

impl tokio::io::AsyncWrite for VsockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            let mut guard = match self.inner.poll_write_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            
            let fd = self.inner.as_raw_fd();
            let n = unsafe {
                libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len())
            };
            
            if n >= 0 {
                return Poll::Ready(Ok(n as usize));
            } else {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Poll::Ready(Err(err));
            }
        }
    }
    
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let fd = self.inner.as_raw_fd();
        unsafe { libc::shutdown(fd, libc::SHUT_WR); }
        Poll::Ready(Ok(()))
    }
}

impl Unpin for VsockStream {}

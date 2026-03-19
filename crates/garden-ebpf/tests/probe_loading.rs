//! Integration tests for eBPF probe loading.
//!
//! These tests require:
//! - Linux with BPF-capable kernel (CONFIG_BPF=y, CONFIG_TRACEPOINTS=y)
//! - Root privileges (CAP_BPF / CAP_SYS_ADMIN)
//! - The compiled BPF ELF at the expected path
//!
//! Run with: `cargo test -p garden-ebpf --test probe_loading -- --ignored`
//! (inside the guest VM or a BPF-capable Linux host)

#[cfg(target_os = "linux")]
mod linux_tests {
    use garden_ebpf::events::{SecurityEvent, SecurityEventKind};
    use garden_ebpf::policy::SecurityPolicy;

    #[tokio::test]
    #[ignore] // Requires root + BPF-capable kernel
    async fn test_probes_load_and_attach() {
        let policy = SecurityPolicy::default_observe();
        let (handle, _rx) = garden_ebpf::tracer::start_tracer(&policy)
            .await
            .expect("tracer should start — check kernel BPF config and root privileges");

        // If we get here, all 3 probes (execve, openat, connect) loaded successfully
        drop(handle);
    }

    #[tokio::test]
    #[ignore]
    async fn test_execve_event_received() {
        let policy = SecurityPolicy::default_observe();
        let (_handle, mut rx) = garden_ebpf::tracer::start_tracer(&policy)
            .await
            .expect("tracer should start");

        // Trigger an execve by running a command
        tokio::process::Command::new("/bin/true")
            .output()
            .await
            .expect("should be able to run /bin/true");

        // Should receive at least one execve event within 1 second
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("should receive event within 1s")
            .expect("channel should not be closed");

        assert!(event.pid > 0, "event pid should be > 0");
        assert!(!event.comm.is_empty(), "event comm should not be empty");
    }

    #[tokio::test]
    #[ignore]
    async fn test_openat_event_received() {
        let policy = SecurityPolicy::default_observe();
        let (_handle, mut rx) = garden_ebpf::tracer::start_tracer(&policy)
            .await
            .expect("tracer should start");

        // Trigger an openat by reading a file
        let _ = tokio::fs::read_to_string("/etc/hostname").await;

        // Collect events for up to 1 second, look for an openat
        let mut found_openat = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await {
                Ok(Some(event)) => {
                    if let SecurityEventKind::FileAccess { path, .. } = &event.kind {
                        if path.contains("hostname") {
                            found_openat = true;
                            break;
                        }
                    }
                }
                _ => continue,
            }
        }
        assert!(found_openat, "should have received openat event for /etc/hostname");
    }

    #[tokio::test]
    #[ignore]
    async fn test_connect_event_received() {
        let policy = SecurityPolicy::default_observe();
        let (_handle, mut rx) = garden_ebpf::tracer::start_tracer(&policy)
            .await
            .expect("tracer should start");

        // Trigger a connect by attempting a TCP connection to localhost
        // (will likely fail, but the connect syscall still fires)
        let _ = tokio::net::TcpStream::connect("127.0.0.1:1").await;

        let mut found_connect = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await {
                Ok(Some(event)) => {
                    if let SecurityEventKind::NetworkConnect { dest_ip, .. } = &event.kind {
                        if dest_ip == "127.0.0.1" {
                            found_connect = true;
                            break;
                        }
                    }
                }
                _ => continue,
            }
        }
        assert!(
            found_connect,
            "should have received connect event for 127.0.0.1"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn test_event_fields_correct() {
        let policy = SecurityPolicy::default_observe();
        let (_handle, mut rx) = garden_ebpf::tracer::start_tracer(&policy)
            .await
            .expect("tracer should start");

        // Run a known command
        tokio::process::Command::new("/bin/echo")
            .arg("hello")
            .output()
            .await
            .expect("should run echo");

        // Find the execve event for echo
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await {
                Ok(Some(event)) => {
                    if let SecurityEventKind::ProcessExec { binary, .. } = &event.kind {
                        if binary.contains("echo") {
                            assert!(event.pid > 0);
                            assert!(event.timestamp_ns > 0);
                            assert!(!event.comm.is_empty());
                            return; // Test passed
                        }
                    }
                }
                _ => continue,
            }
        }
        panic!("did not find execve event for /bin/echo within 2s");
    }
}

/// Stub tests for macOS — verify the stub tracer returns successfully.
#[cfg(not(target_os = "linux"))]
mod macos_tests {
    use garden_ebpf::policy::SecurityPolicy;

    #[tokio::test]
    async fn test_stub_tracer_returns_ok() {
        let policy = SecurityPolicy::default_observe();
        let (handle, mut rx) = garden_ebpf::tracer::start_tracer(&policy)
            .await
            .expect("stub tracer should return Ok");

        // Channel should exist but never produce events
        assert!(
            rx.try_recv().is_err(),
            "stub tracer should not produce events"
        );
        drop(handle);
    }
}

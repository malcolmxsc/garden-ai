//! Garden Agent — The micro-VM Guest Agent
//! 
//! This binary is compiled statically and injected directly into the Apple Hypervisor
//! via a custom `cpio` ramdisk. The Linux Kernel executes this file as Process 1 (`/init`).

use garden_common::ipc::agent_service_server::{AgentService, AgentServiceServer};
use garden_common::ipc::{CommandRequest, CommandResponse, StatusRequest, StatusResponse};
use std::process::Command;
use tonic::{transport::Server, Request, Response, Status};

use tokio_stream::StreamExt;

#[derive(Default)]
pub struct GardenAgentImpl {}

#[tonic::async_trait]
impl AgentService for GardenAgentImpl {
    async fn execute_command(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        let req = request.into_inner();
        tracing::info!("Executing command: {} {:?} (cwd={}) [bytes={:?}]", req.command, req.args, req.cwd, req.command.as_bytes());
        tracing::info!("File exists check: {:?}", std::fs::metadata(&req.command));

        // Define our execution directory 
        let cwd = if req.cwd.is_empty() { "/" } else { &req.cwd };

        // Execute the command inside the Linux Guest!
        let output = Command::new(&req.command)
            .args(&req.args)
            .current_dir(cwd)
            .output()
            .map_err(|e| {
                tracing::error!("Command::new failed: {:?}", e);
                Status::internal(format!("Failed to execute process: {}", e))
            })?;

        let response = CommandResponse {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        };

        Ok(Response::new(response))
    }

    async fn get_status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        tracing::debug!("Host requested Agent Status");
        
        // Return a mock response. In a real app we'd query /proc/uptime
        let response = StatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: 42, 
        };

        Ok(Response::new(response))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .init();

    // 0. Mount essential pseudo-filesystems for Linux operation
    let _ = std::fs::create_dir_all("/proc");
    let _ = std::fs::create_dir_all("/sys");
    let _ = std::fs::create_dir_all("/dev");
    let _ = std::process::Command::new("/bin/busybox").args(["mount", "-t", "proc", "proc", "/proc"]).status();
    let _ = std::process::Command::new("/bin/busybox").args(["mount", "-t", "sysfs", "sys", "/sys"]).status();
    let _ = std::process::Command::new("/bin/busybox").args(["mount", "-t", "devtmpfs", "dev", "/dev"]).status();
    tracing::info!("Mounted /proc, /sys, /dev");

    // Load Virtio Kernel Modules required for Apple Virtualization
    let modules = ["af_packet", "virtio_net", "virtio_rng", "vmw_vsock_virtio_transport"];
    for mod_name in modules {
        let status = std::process::Command::new("/bin/busybox")
            .args(["modprobe", mod_name])
            .status();
        tracing::info!("modprobe {}: {:?}", mod_name, status);
    }

    // Initialize Network Interfaces using Netlink (no `ip` binary needed!)
    tracing::info!("Configuring network interfaces via Netlink...");
    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(connection);

    // 1. Bring up loopback interface (`ip link set lo up`)
    let mut links = handle.link().get().match_name("lo".to_string()).execute();
    if let Some(Ok(link)) = links.next().await {
        let mut msg = netlink_packet_route::link::LinkMessage::default();
        msg.header.index = link.header.index;
        msg.header.flags = netlink_packet_route::link::LinkFlags::Up;
        msg.header.change_mask = netlink_packet_route::link::LinkFlags::Up;
        handle.link().set(msg).execute().await.unwrap();
        tracing::info!("Loopback (lo) interface is UP");
    }

    // 2. Bring up NAT Ethernet interface (`ip link set eth0 up`)
    let mut eth0_idx = 0;
    for _ in 0..20 {
        let mut links = handle.link().get().match_name("eth0".to_string()).execute();
        if let Some(Ok(link)) = links.next().await {
            eth0_idx = link.header.index;
            let mut msg = netlink_packet_route::link::LinkMessage::default();
            msg.header.index = eth0_idx;
            msg.header.flags = netlink_packet_route::link::LinkFlags::Up;
            msg.header.change_mask = netlink_packet_route::link::LinkFlags::Up;
            handle.link().set(msg).execute().await.unwrap();
            tracing::info!("Ethernet (eth0) interface is UP");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    if eth0_idx == 0 {
        tracing::warn!("Failed to find eth0 network device. Virtio PCI probe timed out.");
    }

    // 3. Acquire IP via DHCP from Apple's NAT router
    if eth0_idx > 0 {
        let dhcp = std::process::Command::new("/bin/busybox")
            .args(["udhcpc", "-i", "eth0", "-n", "-q", "-f", "-s", "/usr/share/udhcpc/default.script"])
            .output();
        match &dhcp {
            Ok(out) => {
                tracing::info!("DHCP result: exit={}, stdout={}, stderr={}", 
                    out.status, 
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr));
            }
            Err(e) => tracing::error!("DHCP failed to run: {}", e),
        }
    }

    // Log the assigned IP for debugging
    let ifconfig = std::process::Command::new("/bin/busybox")
        .args(["ifconfig", "eth0"])
        .output();
    if let Ok(out) = ifconfig {
        tracing::info!("eth0 config: {}", String::from_utf8_lossy(&out.stdout));
    }

    let addr = "0.0.0.0:10000".parse().unwrap();
    let agent = GardenAgentImpl::default();

    tracing::info!("AgentService listening on {}", addr);

    Server::builder()
        .add_service(AgentServiceServer::new(agent))
        .serve(addr)
        .await?;

    Ok(())
}

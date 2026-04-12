//! Security event types emitted by eBPF probes.

use serde::{Deserialize, Serialize};

/// A security event captured by the eBPF probes in the guest kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Timestamp in nanoseconds since boot.
    pub timestamp_ns: u64,
    /// Process ID that triggered the event.
    pub pid: u32,
    /// User ID that triggered the event.
    pub uid: u32,
    /// Process name.
    pub comm: String,
    /// The specific event type.
    pub kind: SecurityEventKind,
}

impl SecurityEvent {
    /// Return a copy with `allowed` set to false on applicable event kinds.
    pub fn with_allowed_false(&self) -> SecurityEvent {
        let mut e = self.clone();
        match &mut e.kind {
            SecurityEventKind::FileAccess { allowed, .. }
            | SecurityEventKind::NetworkConnect { allowed, .. }
            | SecurityEventKind::ProcessExec { allowed, .. } => *allowed = false,
            _ => {}
        }
        e
    }
}

/// Categories of security events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecurityEventKind {
    /// A file was opened or accessed.
    FileAccess {
        path: String,
        flags: u32,
        allowed: bool,
    },
    /// A network connection was attempted (IPv4 or IPv6).
    NetworkConnect {
        dest_ip: String,
        dest_port: u16,
        protocol: String,
        allowed: bool,
    },
    /// A process was executed.
    ProcessExec {
        binary: String,
        args: Vec<String>,
        allowed: bool,
    },
    /// A DNS query was sent (UDP port 53).
    DnsQuery {
        /// DNS server IP address.
        server_ip: String,
        /// Raw DNS query domain (decoded from wire format).
        domain: String,
    },
    /// A mount syscall was invoked — escape canary.
    MountAttempt {
        /// Mount target directory.
        target: String,
        /// Device or source being mounted.
        source: String,
        /// Mount flags.
        flags: u32,
    },
    /// A BPF syscall was invoked — red flag if from agent.
    BpfSyscall {
        /// BPF command (0=MAP_CREATE, 5=PROG_LOAD, etc.).
        cmd: u32,
    },
    /// A kernel module load was attempted — should never fire.
    ModuleLoad {
        /// Module size in bytes.
        size: u32,
        /// Module arguments if any.
        args: String,
    },
    /// A kernel module load via fd was attempted — should never fire.
    FinitModuleLoad {
        /// Module flags.
        flags: u32,
        /// Module arguments if any.
        args: String,
    },
    /// A ptrace syscall was invoked — process inspection/injection attempt.
    PtraceAttempt {
        /// Ptrace request code (0=TRACEME, 16=ATTACH, etc.).
        request: u32,
        /// Target PID of the ptrace call.
        target_pid: u32,
    },
    /// A file was deleted (unlinkat).
    FileDelete {
        /// Path of the deleted file.
        path: String,
        /// Unlinkat flags (AT_REMOVEDIR = 0x200 means rmdir).
        flags: u32,
    },
    /// A file was renamed (renameat2).
    FileRename {
        /// Original file path.
        old_path: String,
        /// New file path.
        new_path: String,
        /// Rename flags (RENAME_NOREPLACE, RENAME_EXCHANGE, etc.).
        flags: u32,
    },
    /// A syscall was invoked that matches a security policy.
    SyscallTrace {
        syscall_nr: u64,
        syscall_name: String,
        allowed: bool,
    },
    /// A process was forked.
    ProcessFork {
        /// Parent process PID.
        parent_pid: u32,
        /// Newly spawned child PID.
        child_pid: u32,
        /// Child process name.
        child_comm: String,
    },
    /// A process exited.
    ProcessExit {
        /// Exit status (0-255) from exit(). Only meaningful when exit_signal is 0.
        exit_status: u32,
        /// Signal number that killed the process (e.g. 9 = SIGKILL). 0 = normal exit.
        exit_signal: u32,
    },
    /// Process credentials changed (commit_creds kprobe).
    CredsChanged {
        /// UID before the change.
        old_uid: u32,
        /// UID after the change (0 = root — escalation).
        new_uid: u32,
    },
    /// TCP data was sent.
    TcpSend {
        /// Bytes sent in this call.
        bytes: u64,
    },
    /// TCP data was received.
    TcpRecv {
        /// Bytes actually received in this call (from kretprobe return value).
        bytes: u64,
    },
    /// The OOM killer selected a victim process.
    OomKill {
        /// PID of the process being killed.
        victim_pid: u32,
        /// Name of the process being killed.
        victim_comm: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_event_json_roundtrip() {
        let event = SecurityEvent {
            timestamp_ns: 123456789,
            pid: 42,
            uid: 1000,
            comm: "curl".into(),
            kind: SecurityEventKind::NetworkConnect {
                dest_ip: "93.184.216.34".into(),
                dest_port: 443,
                protocol: "tcp".into(),
                allowed: true,
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: SecurityEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pid, 42);
        assert_eq!(parsed.uid, 1000);
        assert_eq!(parsed.comm, "curl");
        assert_eq!(parsed.timestamp_ns, 123456789);
        if let SecurityEventKind::NetworkConnect {
            dest_ip, dest_port, ..
        } = &parsed.kind
        {
            assert_eq!(dest_ip, "93.184.216.34");
            assert_eq!(*dest_port, 443);
        } else {
            panic!("wrong event kind");
        }
    }

    #[test]
    fn test_ndjson_multiline_parsing() {
        let lines = concat!(
            r#"{"timestamp_ns":1,"pid":1,"uid":0,"comm":"ls","kind":{"type":"file_access","path":"/tmp","flags":0,"allowed":true}}"#,
            "\n",
            r#"{"timestamp_ns":2,"pid":2,"uid":1000,"comm":"curl","kind":{"type":"network_connect","dest_ip":"1.2.3.4","dest_port":80,"protocol":"tcp","allowed":true}}"#,
            "\n",
            r#"{"timestamp_ns":3,"pid":3,"uid":1000,"comm":"sh","kind":{"type":"process_exec","binary":"/bin/sh","args":["-c","echo"],"allowed":true}}"#,
        );
        let events: Vec<SecurityEvent> = lines
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].pid, 1);
        assert_eq!(events[1].pid, 2);
        assert_eq!(events[2].pid, 3);
    }

    #[test]
    fn test_all_event_kinds_serialize() {
        let kinds = vec![
            SecurityEventKind::FileAccess {
                path: "/test".into(),
                flags: 0,
                allowed: true,
            },
            SecurityEventKind::NetworkConnect {
                dest_ip: "1.2.3.4".into(),
                dest_port: 80,
                protocol: "tcp".into(),
                allowed: false,
            },
            SecurityEventKind::ProcessExec {
                binary: "/bin/ls".into(),
                args: vec!["-la".into()],
                allowed: true,
            },
            SecurityEventKind::DnsQuery {
                server_ip: "8.8.8.8".into(),
                domain: "example.com".into(),
            },
            SecurityEventKind::MountAttempt {
                target: "/mnt".into(),
                source: "/dev/vda".into(),
                flags: 0,
            },
            SecurityEventKind::BpfSyscall { cmd: 5 },
            SecurityEventKind::ModuleLoad {
                size: 4096,
                args: "".into(),
            },
            SecurityEventKind::FinitModuleLoad {
                flags: 0,
                args: "".into(),
            },
            SecurityEventKind::PtraceAttempt {
                request: 16,
                target_pid: 42,
            },
            SecurityEventKind::FileDelete {
                path: "/workspace/test.txt".into(),
                flags: 0,
            },
            SecurityEventKind::FileRename {
                old_path: "/workspace/old.txt".into(),
                new_path: "/workspace/new.txt".into(),
                flags: 0,
            },
            SecurityEventKind::SyscallTrace {
                syscall_nr: 59,
                syscall_name: "execve".into(),
                allowed: true,
            },
            SecurityEventKind::ProcessFork {
                parent_pid: 100,
                child_pid: 101,
                child_comm: "bash".into(),
            },
            SecurityEventKind::ProcessExit { exit_status: 0, exit_signal: 0 },
            SecurityEventKind::CredsChanged {
                old_uid: 1000,
                new_uid: 0,
            },
            SecurityEventKind::TcpSend { bytes: 4096 },
            SecurityEventKind::TcpRecv { bytes: 8192 },
            SecurityEventKind::OomKill {
                victim_pid: 500,
                victim_comm: "oom-test".into(),
            },
        ];
        for kind in kinds {
            let event = SecurityEvent {
                timestamp_ns: 0,
                pid: 1,
                uid: 0,
                comm: "test".into(),
                kind,
            };
            let json = serde_json::to_string(&event).unwrap();
            let _: SecurityEvent = serde_json::from_str(&json).unwrap();
        }
    }
}

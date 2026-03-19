//! Security event types emitted by eBPF probes.

use serde::{Deserialize, Serialize};

/// A security event captured by the eBPF probes in the guest kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Timestamp in nanoseconds since boot.
    pub timestamp_ns: u64,
    /// Process ID that triggered the event.
    pub pid: u32,
    /// Process name.
    pub comm: String,
    /// The specific event type.
    pub kind: SecurityEventKind,
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
    /// A network connection was attempted.
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
    /// A syscall was invoked that matches a security policy.
    SyscallTrace {
        syscall_nr: u64,
        syscall_name: String,
        allowed: bool,
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
            r#"{"timestamp_ns":1,"pid":1,"comm":"ls","kind":{"type":"file_access","path":"/tmp","flags":0,"allowed":true}}"#,
            "\n",
            r#"{"timestamp_ns":2,"pid":2,"comm":"curl","kind":{"type":"network_connect","dest_ip":"1.2.3.4","dest_port":80,"protocol":"tcp","allowed":true}}"#,
            "\n",
            r#"{"timestamp_ns":3,"pid":3,"comm":"sh","kind":{"type":"process_exec","binary":"/bin/sh","args":["-c","echo"],"allowed":true}}"#,
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
            SecurityEventKind::SyscallTrace {
                syscall_nr: 59,
                syscall_name: "execve".into(),
                allowed: true,
            },
        ];
        for kind in kinds {
            let event = SecurityEvent {
                timestamp_ns: 0,
                pid: 1,
                comm: "test".into(),
                kind,
            };
            let json = serde_json::to_string(&event).unwrap();
            let _: SecurityEvent = serde_json::from_str(&json).unwrap();
        }
    }
}

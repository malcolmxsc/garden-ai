//! Security policy engine.
//!
//! Defines rules for evaluating eBPF security events. The policy engine
//! runs on the **host** side (garden-daemon) where it can't be tampered
//! with by the guest VM.

use serde::{Deserialize, Serialize};

use super::events::{SecurityEvent, SecurityEventKind};

/// A security policy that governs sandbox behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Human-readable policy name.
    pub name: String,
    /// Rules in this policy, evaluated in order (first match wins).
    pub rules: Vec<PolicyRule>,
}

/// A single rule within a security policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyRule {
    /// Block or allow access to specific file paths.
    FileAccess {
        /// Glob pattern for file paths (e.g., "/workspace/**", "/etc/shadow").
        pattern: String,
        /// Whether to allow or deny.
        action: PolicyAction,
    },
    /// Block or allow network connections.
    Network {
        /// CIDR range or IP address (e.g., "0.0.0.0/0" for all, "127.0.0.0/8" for localhost).
        dest: String,
        /// Optional port filter.
        port: Option<u16>,
        /// Whether to allow or deny.
        action: PolicyAction,
    },
    /// Block or allow specific syscalls.
    Syscall {
        /// Syscall name or number.
        name: String,
        /// Whether to allow or deny.
        action: PolicyAction,
    },
}

/// The action to take when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Deny,
    Log,
}

impl SecurityPolicy {
    /// Evaluate an event against all rules. Returns the action for the first
    /// matching rule, or `PolicyAction::Log` if no rules match (default:
    /// observe everything).
    pub fn evaluate(&self, event: &SecurityEvent) -> PolicyAction {
        for rule in &self.rules {
            if let Some(action) = rule.matches(event) {
                return action;
            }
        }
        PolicyAction::Log
    }

    /// Create a default policy that logs everything.
    pub fn default_observe() -> Self {
        Self {
            name: "default-observe".to_string(),
            rules: vec![],
        }
    }
}

impl PolicyRule {
    /// Check if this rule matches the given event.
    /// Returns `Some(action)` if matched, `None` otherwise.
    fn matches(&self, event: &SecurityEvent) -> Option<PolicyAction> {
        match (self, &event.kind) {
            (
                PolicyRule::FileAccess { pattern, action },
                SecurityEventKind::FileAccess { path, .. },
            ) => {
                if glob_match(pattern, path) {
                    Some(*action)
                } else {
                    None
                }
            }
            (
                PolicyRule::Network { dest, port, action },
                SecurityEventKind::NetworkConnect {
                    dest_ip, dest_port, ..
                },
            ) => {
                if cidr_match(dest, dest_ip) && port.map_or(true, |p| p == *dest_port) {
                    Some(*action)
                } else {
                    None
                }
            }
            (
                PolicyRule::Syscall { name, action },
                SecurityEventKind::SyscallTrace { syscall_name, .. },
            ) => {
                if name == syscall_name {
                    Some(*action)
                } else {
                    None
                }
            }
            // A FileAccess rule can also match ProcessExec (binary path)
            (
                PolicyRule::FileAccess { pattern, action },
                SecurityEventKind::ProcessExec { binary, .. },
            ) => {
                if glob_match(pattern, binary) {
                    Some(*action)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Match a file path against a glob pattern.
fn glob_match(pattern: &str, path: &str) -> bool {
    glob::Pattern::new(pattern)
        .map(|p| p.matches(path))
        .unwrap_or(false)
}

/// Match an IP address against a CIDR range.
///
/// Supports formats:
/// - `"0.0.0.0/0"` — matches everything
/// - `"127.0.0.0/8"` — matches localhost
/// - `"192.168.1.0/24"` — matches a /24 subnet
/// - `"10.0.0.1"` — exact match (equivalent to /32)
fn cidr_match(cidr: &str, ip_str: &str) -> bool {
    let (net_str, prefix_len) = if let Some((net, bits)) = cidr.split_once('/') {
        let bits: u32 = bits.parse().unwrap_or(32);
        (net, bits)
    } else {
        (cidr, 32)
    };

    let net_ip = match parse_ipv4(net_str) {
        Some(ip) => ip,
        None => return false,
    };
    let target_ip = match parse_ipv4(ip_str) {
        Some(ip) => ip,
        None => return false,
    };

    if prefix_len == 0 {
        return true; // 0.0.0.0/0 matches everything
    }
    if prefix_len >= 32 {
        return net_ip == target_ip;
    }

    let mask = !0u32 << (32 - prefix_len);
    (net_ip & mask) == (target_ip & mask)
}

/// Parse a dotted-quad IPv4 address into a u32.
fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let a: u8 = parts[0].parse().ok()?;
    let b: u8 = parts[1].parse().ok()?;
    let c: u8 = parts[2].parse().ok()?;
    let d: u8 = parts[3].parse().ok()?;
    Some(u32::from_be_bytes([a, b, c, d]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::*;

    fn make_file_event(path: &str) -> SecurityEvent {
        SecurityEvent {
            timestamp_ns: 0,
            pid: 1,
            comm: "test".into(),
            kind: SecurityEventKind::FileAccess {
                path: path.into(),
                flags: 0,
                allowed: true,
            },
        }
    }

    fn make_net_event(ip: &str, port: u16) -> SecurityEvent {
        SecurityEvent {
            timestamp_ns: 0,
            pid: 1,
            comm: "curl".into(),
            kind: SecurityEventKind::NetworkConnect {
                dest_ip: ip.into(),
                dest_port: port,
                protocol: "tcp".into(),
                allowed: true,
            },
        }
    }

    fn make_exec_event(binary: &str) -> SecurityEvent {
        SecurityEvent {
            timestamp_ns: 0,
            pid: 1,
            comm: "sh".into(),
            kind: SecurityEventKind::ProcessExec {
                binary: binary.into(),
                args: vec![],
                allowed: true,
            },
        }
    }

    #[test]
    fn test_file_deny_exact_path() {
        let policy = SecurityPolicy {
            name: "test".into(),
            rules: vec![PolicyRule::FileAccess {
                pattern: "/etc/shadow".into(),
                action: PolicyAction::Deny,
            }],
        };
        assert_eq!(
            policy.evaluate(&make_file_event("/etc/shadow")),
            PolicyAction::Deny
        );
        // Non-matching path should get default Log
        assert_eq!(
            policy.evaluate(&make_file_event("/tmp/safe")),
            PolicyAction::Log
        );
    }

    #[test]
    fn test_file_allow_workspace_glob() {
        let policy = SecurityPolicy {
            name: "test".into(),
            rules: vec![PolicyRule::FileAccess {
                pattern: "/workspace/**".into(),
                action: PolicyAction::Allow,
            }],
        };
        assert_eq!(
            policy.evaluate(&make_file_event("/workspace/src/main.rs")),
            PolicyAction::Allow
        );
        assert_eq!(
            policy.evaluate(&make_file_event("/etc/passwd")),
            PolicyAction::Log
        );
    }

    #[test]
    fn test_network_deny_all() {
        let policy = SecurityPolicy {
            name: "test".into(),
            rules: vec![PolicyRule::Network {
                dest: "0.0.0.0/0".into(),
                port: None,
                action: PolicyAction::Deny,
            }],
        };
        assert_eq!(
            policy.evaluate(&make_net_event("93.184.216.34", 80)),
            PolicyAction::Deny
        );
        assert_eq!(
            policy.evaluate(&make_net_event("127.0.0.1", 8080)),
            PolicyAction::Deny
        );
    }

    #[test]
    fn test_network_allow_localhost() {
        let policy = SecurityPolicy {
            name: "test".into(),
            rules: vec![
                PolicyRule::Network {
                    dest: "127.0.0.0/8".into(),
                    port: None,
                    action: PolicyAction::Allow,
                },
                PolicyRule::Network {
                    dest: "0.0.0.0/0".into(),
                    port: None,
                    action: PolicyAction::Deny,
                },
            ],
        };
        assert_eq!(
            policy.evaluate(&make_net_event("127.0.0.1", 8080)),
            PolicyAction::Allow
        );
        assert_eq!(
            policy.evaluate(&make_net_event("10.0.0.1", 80)),
            PolicyAction::Deny
        );
    }

    #[test]
    fn test_network_port_filter() {
        let policy = SecurityPolicy {
            name: "test".into(),
            rules: vec![PolicyRule::Network {
                dest: "0.0.0.0/0".into(),
                port: Some(443),
                action: PolicyAction::Allow,
            }],
        };
        assert_eq!(
            policy.evaluate(&make_net_event("1.2.3.4", 443)),
            PolicyAction::Allow
        );
        // Port 80 doesn't match the rule, falls through to default
        assert_eq!(
            policy.evaluate(&make_net_event("1.2.3.4", 80)),
            PolicyAction::Log
        );
    }

    #[test]
    fn test_default_action_is_log() {
        let policy = SecurityPolicy::default_observe();
        assert_eq!(
            policy.evaluate(&make_file_event("/anything")),
            PolicyAction::Log
        );
    }

    #[test]
    fn test_first_match_wins() {
        let policy = SecurityPolicy {
            name: "test".into(),
            rules: vec![
                PolicyRule::FileAccess {
                    pattern: "/etc/shadow".into(),
                    action: PolicyAction::Deny,
                },
                PolicyRule::FileAccess {
                    pattern: "/etc/*".into(),
                    action: PolicyAction::Allow,
                },
            ],
        };
        // /etc/shadow matches the Deny rule first
        assert_eq!(
            policy.evaluate(&make_file_event("/etc/shadow")),
            PolicyAction::Deny
        );
        // /etc/hostname only matches the Allow rule
        assert_eq!(
            policy.evaluate(&make_file_event("/etc/hostname")),
            PolicyAction::Allow
        );
    }

    #[test]
    fn test_exec_matches_file_access_rule() {
        let policy = SecurityPolicy {
            name: "test".into(),
            rules: vec![PolicyRule::FileAccess {
                pattern: "/usr/bin/curl".into(),
                action: PolicyAction::Deny,
            }],
        };
        assert_eq!(
            policy.evaluate(&make_exec_event("/usr/bin/curl")),
            PolicyAction::Deny
        );
        assert_eq!(
            policy.evaluate(&make_exec_event("/bin/ls")),
            PolicyAction::Log
        );
    }

    #[test]
    fn test_cidr_match_subnet() {
        assert!(cidr_match("192.168.1.0/24", "192.168.1.100"));
        assert!(!cidr_match("192.168.1.0/24", "192.168.2.1"));
        assert!(cidr_match("10.0.0.0/8", "10.255.255.255"));
        assert!(!cidr_match("10.0.0.0/8", "11.0.0.1"));
    }

    #[test]
    fn test_cidr_match_exact() {
        assert!(cidr_match("1.2.3.4", "1.2.3.4"));
        assert!(!cidr_match("1.2.3.4", "1.2.3.5"));
    }

    #[test]
    fn test_policy_json_roundtrip() {
        let policy = SecurityPolicy {
            name: "test-policy".into(),
            rules: vec![
                PolicyRule::FileAccess {
                    pattern: "/etc/shadow".into(),
                    action: PolicyAction::Deny,
                },
                PolicyRule::Network {
                    dest: "0.0.0.0/0".into(),
                    port: Some(80),
                    action: PolicyAction::Log,
                },
            ],
        };
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: SecurityPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test-policy");
        assert_eq!(parsed.rules.len(), 2);
    }
}

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

/// Returns `true` if `pattern` contains glob metacharacters (`*` or `?`).
///
/// Used by `tracer.rs` to decide whether a `FileAccess` rule can be encoded
/// into a BPF map (exact match only) or must fall back to kill-on-detect.
pub fn has_glob_pattern(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
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
                if cidr_match(dest, dest_ip) && port.is_none_or(|p| p == *dest_port) {
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
/// Supports both IPv4 and IPv6 formats:
/// - `"0.0.0.0/0"` — matches all IPv4
/// - `"127.0.0.0/8"` — matches IPv4 localhost
/// - `"192.168.1.0/24"` — matches a /24 IPv4 subnet
/// - `"10.0.0.1"` — exact IPv4 match (equivalent to /32)
/// - `"::/0"` — matches all IPv6
/// - `"::1"` — exact IPv6 loopback match
/// - `"2001:db8::/32"` — matches an IPv6 /32 prefix
fn cidr_match(cidr: &str, ip_str: &str) -> bool {
    let (net_str, prefix_len_str) = if let Some((net, bits)) = cidr.split_once('/') {
        (net, Some(bits))
    } else {
        (cidr, None)
    };

    // Try IPv4 first
    if let Some(net_ip) = parse_ipv4(net_str) {
        let prefix_len: u32 = prefix_len_str.and_then(|b| b.parse().ok()).unwrap_or(32);
        let target_ip = match parse_ipv4(ip_str) {
            Some(ip) => ip,
            None => return false,
        };
        return cidr_match_v4(net_ip, prefix_len, target_ip);
    }

    // Try IPv6
    if let Some(net_ip) = parse_ipv6(net_str) {
        let prefix_len: u32 = prefix_len_str.and_then(|b| b.parse().ok()).unwrap_or(128);
        let target_ip = match parse_ipv6(ip_str) {
            Some(ip) => ip,
            None => return false,
        };
        return cidr_match_v6(&net_ip, prefix_len, &target_ip);
    }

    false
}

/// IPv4 CIDR matching.
fn cidr_match_v4(net_ip: u32, prefix_len: u32, target_ip: u32) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len >= 32 {
        return net_ip == target_ip;
    }
    let mask = !0u32 << (32 - prefix_len);
    (net_ip & mask) == (target_ip & mask)
}

/// IPv6 CIDR matching on 128-bit addresses.
fn cidr_match_v6(net: &[u8; 16], prefix_len: u32, target: &[u8; 16]) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len >= 128 {
        return net == target;
    }

    let full_bytes = (prefix_len / 8) as usize;
    let remaining_bits = prefix_len % 8;

    // Compare full bytes
    if net[..full_bytes] != target[..full_bytes] {
        return false;
    }

    // Compare remaining bits in the partial byte
    if remaining_bits > 0 && full_bytes < 16 {
        let mask = !0u8 << (8 - remaining_bits);
        if (net[full_bytes] & mask) != (target[full_bytes] & mask) {
            return false;
        }
    }

    true
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

/// Parse an IPv6 address string into a 16-byte array.
///
/// Supports standard notation (e.g., `2001:db8::1`) including `::` compression.
pub(crate) fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    // Handle :: expansion
    let (left, right) = if let Some((l, r)) = s.split_once("::") {
        (l, Some(r))
    } else {
        (s, None)
    };

    let mut groups = Vec::new();

    // Parse left side
    if !left.is_empty() {
        for part in left.split(':') {
            let val = u16::from_str_radix(part, 16).ok()?;
            groups.push(val);
        }
    }

    let left_count = groups.len();

    // Parse right side (after ::)
    let right_count = if let Some(r) = right {
        if !r.is_empty() {
            for part in r.split(':') {
                let val = u16::from_str_radix(part, 16).ok()?;
                groups.push(val);
            }
            groups.len() - left_count
        } else {
            0
        }
    } else {
        0
    };

    // With ::, pad with zeros to fill 8 groups
    if right.is_some() {
        let zeros_needed = 8 - left_count - right_count;
        let mut expanded = Vec::with_capacity(8);
        expanded.extend_from_slice(&groups[..left_count]);
        expanded.extend(std::iter::repeat_n(0u16, zeros_needed));
        expanded.extend_from_slice(&groups[left_count..]);
        groups = expanded;
    }

    if groups.len() != 8 {
        return None;
    }

    let mut result = [0u8; 16];
    for (i, g) in groups.iter().enumerate() {
        let bytes = g.to_be_bytes();
        result[i * 2] = bytes[0];
        result[i * 2 + 1] = bytes[1];
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::*;

    fn make_file_event(path: &str) -> SecurityEvent {
        SecurityEvent {
            timestamp_ns: 0,
            pid: 1,
            uid: 1000,
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
            uid: 1000,
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
            uid: 1000,
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
    fn test_cidr_match_ipv6_loopback() {
        assert!(cidr_match("::1", "0:0:0:0:0:0:0:1"));
        assert!(!cidr_match("::1", "0:0:0:0:0:0:0:2"));
    }

    #[test]
    fn test_cidr_match_ipv6_prefix() {
        assert!(cidr_match("2001:db8::/32", "2001:db8:0:0:0:0:0:1"));
        assert!(cidr_match("2001:db8::/32", "2001:db8:ffff:ffff:0:0:0:0"));
        assert!(!cidr_match("2001:db8::/32", "2001:db9:0:0:0:0:0:1"));
    }

    #[test]
    fn test_cidr_match_ipv6_all() {
        assert!(cidr_match("::/0", "2001:db8:0:0:0:0:0:1"));
        assert!(cidr_match("::/0", "0:0:0:0:0:0:0:1"));
    }

    #[test]
    fn test_parse_ipv6_loopback() {
        let result = parse_ipv6("::1").unwrap();
        let mut expected = [0u8; 16];
        expected[15] = 1;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_ipv6_full() {
        let result = parse_ipv6("2001:db8:0:0:0:0:0:1").unwrap();
        assert_eq!(result[0], 0x20);
        assert_eq!(result[1], 0x01);
        assert_eq!(result[2], 0x0d);
        assert_eq!(result[3], 0xb8);
        assert_eq!(result[15], 1);
    }

    #[test]
    fn test_parse_ipv6_compressed() {
        let result = parse_ipv6("2001:db8::1").unwrap();
        assert_eq!(result[0], 0x20);
        assert_eq!(result[1], 0x01);
        assert_eq!(result[15], 1);
        // Middle should be zeros
        assert_eq!(result[4], 0);
        assert_eq!(result[5], 0);
    }

    #[test]
    fn test_ipv6_network_rule_matches() {
        let policy = SecurityPolicy {
            name: "test".into(),
            rules: vec![PolicyRule::Network {
                dest: "2001:db8::/32".into(),
                port: None,
                action: PolicyAction::Deny,
            }],
        };
        assert_eq!(
            policy.evaluate(&make_net_event("2001:db8:0:0:0:0:0:1", 80)),
            PolicyAction::Deny
        );
        // IPv4 should not match an IPv6 rule
        assert_eq!(
            policy.evaluate(&make_net_event("1.2.3.4", 80)),
            PolicyAction::Log
        );
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

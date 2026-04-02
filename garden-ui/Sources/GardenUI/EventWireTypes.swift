import Foundation

// ---------------------------------------------------------------------------
// EventWireTypes — Decodable mirror of Rust SecurityEvent / SecurityEventKind
// ---------------------------------------------------------------------------
// Shared by TelemetryStream (live feed) and SessionsView (log file parsing).

struct WireEvent: Decodable {
    let timestamp_ns: UInt64
    let pid: UInt32
    let comm: String
    let kind: WireKind
    let violation: WireViolation?
}

struct WireViolation: Decodable {
    let severity: String
    let rule: String
    let message: String
}

struct WireKind: Decodable {
    let type: String
    // file_access
    let path: String?
    let flags: UInt32?
    let allowed: Bool?
    // network_connect
    let dest_ip: String?
    let dest_port: UInt16?
    let networkProtocol: String?
    // process_exec
    let binary: String?
    let args: [String]?
    // dns_query
    let server_ip: String?
    let domain: String?
    // process_fork
    let parent_pid: UInt32?
    let child_pid: UInt32?
    let child_comm: String?
    // process_exit
    let exit_status: UInt32?
    let exit_signal: UInt32?
    // creds_changed
    let old_uid: UInt32?
    let new_uid: UInt32?
    // tcp_send / tcp_recv
    let bytes: UInt64?
    // mount_attempt
    let target: String?
    let source: String?
    // bpf_syscall
    let cmd: UInt32?
    // oom_kill
    let victim_pid: UInt32?
    let victim_comm: String?
    // module_load
    let size: UInt32?
    // syscall_trace
    let syscall_nr: UInt64?
    let syscall_name: String?

    private enum CodingKeys: String, CodingKey {
        case type, path, flags, allowed
        case dest_ip, dest_port
        case networkProtocol = "protocol"
        case binary, args
        case server_ip, domain
        case parent_pid, child_pid, child_comm
        case exit_status, exit_signal
        case old_uid, new_uid
        case bytes
        case target, source
        case cmd
        case victim_pid, victim_comm
        case size
        case syscall_nr, syscall_name
    }
}

extension WireEvent {
    func toSecurityEvent() -> SecurityEvent? {
        let k = kind
        let eventKind: SecurityEvent.Kind
        switch k.type {
        case "file_access":
            eventKind = .fileAccess(path: k.path ?? "?", allowed: k.allowed ?? true)
        case "network_connect":
            eventKind = .networkConnect(ip: k.dest_ip ?? "?", port: Int(k.dest_port ?? 0), allowed: k.allowed ?? true)
        case "process_exec":
            eventKind = .processExec(binary: k.binary ?? "?", allowed: k.allowed ?? true)
        case "process_fork":
            eventKind = .processFork(childPid: Int(k.child_pid ?? 0), childComm: k.child_comm ?? "?")
        case "process_exit":
            eventKind = .processExit(exitStatus: Int(k.exit_status ?? 0), exitSignal: Int(k.exit_signal ?? 0))
        case "dns_query":
            eventKind = .dnsQuery(domain: k.domain ?? "?")
        case "creds_changed":
            eventKind = .credsChanged(oldUID: Int(k.old_uid ?? 0), newUID: Int(k.new_uid ?? 0))
        case "tcp_send":
            eventKind = .tcpSend(bytes: Int(k.bytes ?? 0))
        case "tcp_recv":
            eventKind = .tcpRecv(bytes: Int(k.bytes ?? 0))
        case "mount_attempt":
            eventKind = .mountAttempt(source: k.source ?? "?", target: k.target ?? "?")
        case "bpf_syscall":
            eventKind = .bpfSyscall(cmd: Int(k.cmd ?? 0))
        default:
            return nil
        }

        // Use daemon's host-side violation detection (same rules as session log).
        let isViolation = violation != nil
        let violationMessage = violation.map { "[\($0.severity)] \($0.rule): \($0.message)" }

        return SecurityEvent(
            id: UUID(),
            timestamp: Date(timeIntervalSince1970: Double(timestamp_ns) / 1_000_000_000),
            pid: Int(pid),
            comm: comm,
            kind: eventKind,
            isViolation: isViolation,
            violationMessage: violationMessage
        )
    }
}

import Foundation
import Network

// ---------------------------------------------------------------------------
// TelemetryStream — reads NDJSON SecurityEvent lines from daemon TCP :10001
// ---------------------------------------------------------------------------
// The daemon broadcasts one JSON line per event (newline-terminated).
// We reconnect automatically on drop.

// MARK: - Wire types (mirror Rust SecurityEventKind JSON shape)
// kind.type is snake_case (serde rename_all = "snake_case")

private struct WireEvent: Decodable {
    let timestamp_ns: UInt64
    let pid: UInt32
    let comm: String
    let kind: WireKind
}

private struct WireKind: Decodable {
    let type: String
    // file_access
    let path: String?
    let flags: UInt32?
    let allowed: Bool?
    // network_connect
    let dest_ip: String?
    let dest_port: UInt16?
    let protocol: String?
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
    let exit_code: UInt32?
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
}

private extension WireEvent {
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
            eventKind = .processExit(code: Int(k.exit_code ?? 0))
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

        // A violation is any denied (allowed == false) or mount/module/creds escalation
        let isViolation: Bool
        let violationMessage: String?
        switch eventKind {
        case .fileAccess(_, let allowed) where !allowed:
            isViolation = true; violationMessage = "File access denied by policy"
        case .networkConnect(_, _, let allowed) where !allowed:
            isViolation = true; violationMessage = "Network connection blocked by policy"
        case .processExec(_, let allowed) where !allowed:
            isViolation = true; violationMessage = "Process exec blocked by policy"
        case .mountAttempt:
            isViolation = true; violationMessage = "Mount attempt detected"
        case .bpfSyscall:
            isViolation = true; violationMessage = "BPF syscall from agent process"
        case .credsChanged(let old, let new) where new == 0 && old != 0:
            isViolation = true; violationMessage = "Privilege escalation to root"
        default:
            isViolation = false; violationMessage = nil
        }

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

// MARK: - Stream actor

@MainActor
final class TelemetryStream {
    private var connection: NWConnection?
    private var buffer = Data()
    private var reconnectTask: Task<Void, Never>?
    var onEvent: ((SecurityEvent) -> Void)?

    func start() {
        connect()
    }

    func stop() {
        reconnectTask?.cancel()
        connection?.cancel()
        connection = nil
        buffer = Data()
    }

    private func connect() {
        let host: NWEndpoint.Host = "127.0.0.1"
        let port: NWEndpoint.Port = 10001
        let conn = NWConnection(host: host, port: port, using: .tcp)
        connection = conn
        conn.stateUpdateHandler = { [weak self] state in
            Task { @MainActor [weak self] in
                guard let self else { return }
                switch state {
                case .ready:
                    self.receive(on: conn)
                case .failed, .cancelled:
                    self.scheduleReconnect()
                default:
                    break
                }
            }
        }
        conn.start(queue: .global(qos: .utility))
    }

    private func receive(on conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            Task { @MainActor [weak self] in
                guard let self else { return }
                if let data { self.processChunk(data) }
                if let _ = error { self.scheduleReconnect(); return }
                if isComplete { self.scheduleReconnect(); return }
                self.receive(on: conn)
            }
        }
    }

    private func processChunk(_ data: Data) {
        buffer.append(data)
        while let newlineRange = buffer.firstRange(of: Data("\n".utf8)) {
            let lineData = buffer[..<newlineRange.lowerBound]
            buffer = Data(buffer[newlineRange.upperBound...])
            if lineData.isEmpty { continue }
            if let wire = try? JSONDecoder().decode(WireEvent.self, from: lineData),
               let event = wire.toSecurityEvent() {
                onEvent?(event)
            }
        }
    }

    private func scheduleReconnect() {
        connection?.cancel()
        connection = nil
        buffer = Data()
        reconnectTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(3))
            guard !Task.isCancelled else { return }
            await self?.connect()
        }
    }
}

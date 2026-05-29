import SwiftUI

public struct SecurityEvent: Identifiable, Equatable {
    public let id: UUID
    public let timestamp: Date
    public let pid: Int
    public let comm: String
    public let kind: Kind
    public let isViolation: Bool
    public let violationMessage: String?

    // MARK: - Initializer

    public init(id: UUID = UUID(), timestamp: Date = Date(), pid: Int, comm: String, kind: Kind, isViolation: Bool, violationMessage: String? = nil) {
        self.id = id
        self.timestamp = timestamp
        self.pid = pid
        self.comm = comm
        self.kind = kind
        self.isViolation = isViolation
        self.violationMessage = violationMessage
    }

    // MARK: - Kind

    public enum Kind: Equatable {
        case fileAccess(path: String, allowed: Bool)
        case networkConnect(ip: String, port: Int, allowed: Bool)
        case processExec(binary: String, allowed: Bool)
        case processFork(childPid: Int, childComm: String)
        case processExit(exitStatus: Int, exitSignal: Int)
        case dnsQuery(domain: String)
        case credsChanged(oldUID: Int, newUID: Int)
        case tcpSend(bytes: Int)
        case tcpRecv(bytes: Int)
        case mountAttempt(source: String, target: String)
        case bpfSyscall(cmd: Int)

        public var icon: String {
            switch self {
            case .fileAccess:      return "doc.fill"
            case .networkConnect:  return "network"
            case .processExec:     return "terminal.fill"
            case .processFork:     return "arrow.branch"
            case .processExit:     return "xmark.circle"
            case .dnsQuery:        return "globe"
            case .credsChanged:    return "person.badge.key.fill"
            case .tcpSend:         return "arrow.up.circle.fill"
            case .tcpRecv:         return "arrow.down.circle.fill"
            case .mountAttempt:    return "externaldrive.fill"
            case .bpfSyscall:      return "cpu"
            }
        }

        public var color: Color {
            switch self {
            case .fileAccess(_, let allowed):        return allowed ? .blue   : .red
            case .networkConnect(_, _, let allowed): return allowed ? .purple : .red
            case .processExec(_, let allowed):       return allowed ? .green  : .red
            case .processFork:                          return .secondary
            case .processExit(_, let signal):           return signal > 0 ? .red : .secondary
            case .dnsQuery:                          return .purple
            case .credsChanged:                      return .orange
            case .tcpSend, .tcpRecv:                 return .cyan
            case .mountAttempt:                      return .red
            case .bpfSyscall:                        return .secondary
            }
        }

        public var description: String {
            switch self {
            case .fileAccess(let path, let allowed):
                return "\(allowed ? "open" : "BLOCKED") \(path)"
            case .networkConnect(let ip, let port, let allowed):
                return "\(allowed ? "connect" : "BLOCKED") \(ip):\(port)"
            case .processExec(let binary, let allowed):
                return "\(allowed ? "exec" : "BLOCKED") \(binary)"
            case .processFork(let pid, let comm):
                return "fork → pid=\(pid) (\(comm))"
            case .processExit(let status, let signal):
                return signal > 0 ? "exit signal=\(signal)" : "exit status=\(status)"
            case .dnsQuery(let domain):
                return "dns \(domain)"
            case .credsChanged(let old, let new):
                return "uid \(old) → \(new)"
            case .tcpSend(let bytes):
                return "send \(formatBytes(bytes))"
            case .tcpRecv(let bytes):
                return "recv \(formatBytes(bytes))"
            case .mountAttempt(let src, let tgt):
                return "mount \(src) → \(tgt)"
            case .bpfSyscall(let cmd):
                return "bpf cmd=\(cmd)"
            }
        }
    }

    // MARK: - Formatting

    public var timeString: String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f.string(from: timestamp)
    }
}

private func formatBytes(_ n: Int) -> String {
    if n >= 1_048_576 { return String(format: "%.1fMB", Double(n) / 1_048_576) }
    if n >= 1_024    { return String(format: "%.1fKB", Double(n) / 1_024) }
    return "\(n)B"
}

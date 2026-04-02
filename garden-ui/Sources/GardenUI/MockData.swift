import Foundation

enum MockData {

    private static let processes = ["python3", "node", "sh", "curl", "git", "cargo", "bash", "npm", "uvicorn", "ruff"]
    private static let paths = [
        "/workspace/app.py", "/workspace/server.js", "/workspace/.env",
        "/workspace/node_modules/.bin/tsc", "/etc/resolv.conf",
        "/tmp/scratch_4a2b.tmp", "/workspace/Cargo.toml",
        "/etc/shadow",               // violation bait
        "/proc/self/mem",            // violation bait
    ]
    private static let domains = [
        "api.openai.com", "github.com", "pypi.org",
        "registry.npmjs.org", "storage.googleapis.com", "huggingface.co"
    ]
    private static let ips = [
        "142.250.80.46", "140.82.121.4", "151.101.1.63",
        "104.18.8.148",  "8.8.8.8",
        "10.0.0.1",      // violation bait (internal)
    ]

    static func randomEvent() -> SecurityEvent {
        let comm = processes.randomElement()!
        let pid  = Int.random(in: 100...9999)

        // ~10% violation rate; violations always use red-flag content
        let isViolation = Double.random(in: 0...1) < 0.10
        let kind: SecurityEvent.Kind

        if isViolation {
            switch Int.random(in: 0...3) {
            case 0:  kind = .fileAccess(path: "/etc/shadow", allowed: false)
            case 1:  kind = .networkConnect(ip: "10.0.0.1", port: 4444, allowed: false)
            case 2:  kind = .credsChanged(oldUID: 1000, newUID: 0)
            default: kind = .mountAttempt(source: "/dev/sda1", target: "/mnt/host")
            }
        } else {
            let roll = Double.random(in: 0...1)
            switch roll {
            case ..<0.30: kind = .fileAccess(path: paths.filter { !$0.contains("shadow") && !$0.contains("mem") }.randomElement()!, allowed: true)
            case ..<0.48: kind = .networkConnect(ip: ips.filter { !$0.hasPrefix("10.") }.randomElement()!, port: [80, 443, 8080].randomElement()!, allowed: true)
            case ..<0.58: kind = .processExec(binary: "/usr/bin/\(comm)", allowed: true)
            case ..<0.66: kind = .dnsQuery(domain: domains.randomElement()!)
            case ..<0.74: kind = .tcpSend(bytes: Int.random(in: 200...16_384))
            case ..<0.82: kind = .tcpRecv(bytes: Int.random(in: 1_024...131_072))
            case ..<0.90: kind = .processFork(childPid: pid + Int.random(in: 1...5), childComm: processes.randomElement()!)
            default:      kind = .processExit(exitStatus: [0, 0, 0, 1].randomElement()!, exitSignal: 0)
            }
        }

        return SecurityEvent(
            id: UUID(),
            timestamp: Date(),
            pid: pid,
            comm: comm,
            kind: kind,
            isViolation: isViolation,
            violationMessage: isViolation ? violationMessage(for: kind) : nil
        )
    }

    private static func violationMessage(for kind: SecurityEvent.Kind) -> String {
        switch kind {
        case .fileAccess(let path, _):
            return "Denied access to \(path) — matches DENIED_PATHS policy"
        case .networkConnect(let ip, let port, _):
            return "Blocked connection to \(ip):\(port) — matches DENIED_NETS policy"
        case .credsChanged(_, let new) where new == 0:
            return "Privilege escalation: UID changed to root (0)"
        case .mountAttempt:
            return "Mount attempt blocked — BPF-LSM sb_mount hook"
        default:
            return "Policy violation"
        }
    }
}

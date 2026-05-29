import Foundation
import GardenTelemetry

// ---------------------------------------------------------------------------
// DaemonClient — thin URLSession wrapper for the daemon HTTP API at :9001
// ---------------------------------------------------------------------------
// GET  /api/status  → DaemonStatus
// POST /api/boot    → ActionResult
// POST /api/stop    → ActionResult

struct DaemonStatus: Decodable {
    let running: Bool
    let uptime_seconds: UInt64
    let kernel_path: String
}

struct ActionResult: Decodable {
    let success: Bool
    let message: String
}

struct SessionInfo: Decodable, Identifiable {
    let id: String
    let start_ts: String
    let event_count: UInt64

    // Human-readable date from Unix ms timestamp string
    var displayDate: String {
        guard let ms = Double(start_ts) else { return start_ts }
        let date = Date(timeIntervalSince1970: ms / 1000)
        let f = DateFormatter()
        f.dateFormat = "MMM d, HH:mm:ss"
        return f.string(from: date)
    }
}

struct LogEntry: Decodable, Identifiable {
    let id = UUID()
    let ts: String
    let seq: UInt64
    let pid: UInt32
    let comm: String
    let event: WireEvent
    let violation: LogViolation?

    private enum CodingKeys: String, CodingKey {
        case ts, seq, pid, comm, event, violation
    }

    func toSecurityEvent() -> SecurityEvent? {
        guard let base = event.toSecurityEvent() else { return nil }

        // Parse the daemon's wall-clock ts (ISO 8601 UTC) for correct display time.
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let wallTime = formatter.date(from: ts) ?? base.timestamp

        // Override isViolation from the authoritative host-side violation field
        let isViolation = violation != nil
        let violationMsg = violation.map { $0.message }

        return SecurityEvent(
            id: base.id,
            timestamp: wallTime,
            pid: base.pid,
            comm: base.comm,
            kind: base.kind,
            isViolation: isViolation,
            violationMessage: violationMsg
        )
    }
}

struct LogViolation: Decodable {
    let severity: String
    let rule: String
    let message: String
}

enum DaemonClientError: Error {
    case unreachable(Error)
    case badStatus(Int)
    case decodeFailed(Error)
}

struct DaemonClient {
    static let base = URL(string: "http://127.0.0.1:9001")!

    private static let session: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 5
        cfg.timeoutIntervalForResource = 10
        return URLSession(configuration: cfg)
    }()

    // MARK: - Public API

    static func status() async throws -> DaemonStatus {
        try await get("/api/status")
    }

    static func boot() async throws -> ActionResult {
        try await post("/api/boot")
    }

    static func stop() async throws -> ActionResult {
        try await post("/api/stop")
    }

    static func sessions() async throws -> [SessionInfo] {
        try await get("/api/sessions")
    }

    static func sessionEvents(id: String) async throws -> [LogEntry] {
        try await get("/api/sessions/\(id)/events")
    }

    // MARK: - Helpers

    private static func get<T: Decodable>(_ path: String) async throws -> T {
        let req = URLRequest(url: base.appendingPathComponent(path))
        return try await fetch(req)
    }

    private static func post<T: Decodable>(_ path: String) async throws -> T {
        var req = URLRequest(url: base.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = Data("{}".utf8)
        return try await fetch(req)
    }

    private static func fetch<T: Decodable>(_ req: URLRequest) async throws -> T {
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: req)
        } catch {
            throw DaemonClientError.unreachable(error)
        }
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw DaemonClientError.badStatus(http.statusCode)
        }
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw DaemonClientError.decodeFailed(error)
        }
    }
}

import Foundation
import Network

// ---------------------------------------------------------------------------
// TelemetryStream — reads NDJSON SecurityEvent lines from daemon TCP :10001
// ---------------------------------------------------------------------------
// The daemon broadcasts one JSON line per event (newline-terminated).
// Wire types (WireEvent/WireKind) are in EventWireTypes.swift.

@MainActor
public final class TelemetryStream {
    private var connection: NWConnection?
    private var buffer = Data()
    private var reconnectTask: Task<Void, Never>?
    public var onEvent: ((SecurityEvent) -> Void)?

    public init() {}

    public func start() {
        connect()
    }

    public func stop() {
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
                case .waiting, .failed, .cancelled:
                    // .waiting fires when the OS couldn't establish the
                    // connection (e.g. daemon binds :9001 a hair before
                    // :10001 at startup, so the first connect attempt
                    // gets ECONNREFUSED). NWConnection's built-in retry
                    // sits in .waiting indefinitely — we cancel and
                    // schedule our own 3s reconnect instead.
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
                if error != nil { self.scheduleReconnect(); return }
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
        // Cancelling the existing reconnect task ensures multiple state
        // transitions during one teardown (e.g. .waiting → cancel → .cancelled)
        // collapse into a single pending reconnect rather than scheduling
        // a duplicate 3s task that races the first one.
        reconnectTask?.cancel()
        reconnectTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(3))
            guard !Task.isCancelled else { return }
            self?.connect()
        }
    }
}

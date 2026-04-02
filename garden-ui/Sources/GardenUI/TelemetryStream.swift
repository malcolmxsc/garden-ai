import Foundation
import Network

// ---------------------------------------------------------------------------
// TelemetryStream — reads NDJSON SecurityEvent lines from daemon TCP :10001
// ---------------------------------------------------------------------------
// The daemon broadcasts one JSON line per event (newline-terminated).
// Wire types (WireEvent/WireKind) are in EventWireTypes.swift.

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
        reconnectTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(3))
            guard !Task.isCancelled else { return }
            await self?.connect()
        }
    }
}

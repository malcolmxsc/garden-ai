import SwiftUI

// ---------------------------------------------------------------------------
// VM State
// ---------------------------------------------------------------------------

enum VMState: String, Equatable {
    case stopped  = "Stopped"
    case booting  = "Booting"
    case running  = "Running"
    case stopping = "Stopping"
    case error    = "Error"

    var color: Color {
        switch self {
        case .stopped, .stopping: return .secondary
        case .booting, .running:  return Color(hue: 0.36, saturation: 0.7, brightness: 0.75)
        case .error:              return .red
        }
    }
}

// ---------------------------------------------------------------------------
// AppState — single source of truth, wired to daemon HTTP + telemetry stream
// ---------------------------------------------------------------------------

@MainActor
final class AppState: ObservableObject {

    // VM
    @Published var vmState: VMState = .stopped
    @Published var errorMessage: String?

    // Uptime
    @Published var uptimeSeconds: Int = 0

    // Events (newest first)
    @Published var events: [SecurityEvent] = []
    @Published var showViolationsOnly: Bool = false

    // Resource metrics
    @Published var cpuHistory: [Double] = Array(repeating: 0.0, count: 30)
    @Published var memoryMB: Double = 0

    // Flare — triggers the "wake" flash on transition to running
    @Published var wakeFlash: Bool = false

    // Whether we successfully reached the daemon. @Published so the
    // ContentView "Daemon offline" banner re-renders on change.
    @Published private(set) var daemonReachable: Bool = false

    // Consecutive failed daemon polls. Once this hits the threshold below
    // we treat the daemon as truly offline and roll vmState back to
    // .stopped so the UI doesn't keep displaying stale uptime/cpu.
    private var consecutiveFailedPolls: Int = 0
    private let failedPollsBeforeOffline = 2  // ~10s at the 5s poll cadence

    private var didHandleLaunchAutoBoot: Bool = false

    var filteredEvents: [SecurityEvent] {
        showViolationsOnly ? events.filter(\.isViolation) : events
    }

    var formattedUptime: String {
        let h = uptimeSeconds / 3600
        let m = (uptimeSeconds % 3600) / 60
        let s = uptimeSeconds % 60
        return h > 0
            ? String(format: "%d:%02d:%02d", h, m, s)
            : String(format: "%02d:%02d", m, s)
    }

    // MARK: - Lifecycle

    init() {
        // Poll daemon for current status on launch so UI reflects real VM state
        Task { await syncStatusFromDaemon() }
        startStatusPolling()
    }

    func boot(allowMockFallback: Bool = true) async {
        guard vmState == .stopped || vmState == .error else { return }
        vmState = .booting
        errorMessage = nil

        if daemonReachable {
            do {
                let result = try await DaemonClient.boot()
                if result.success {
                    vmState = .running
                    wakeFlash = true
                    startUptimeTimer()
                    startTelemetryStream()
                } else {
                    vmState = .error
                    errorMessage = result.message
                }
            } catch {
                if allowMockFallback {
                    // Daemon was reachable at init but is now gone — fall back to mock
                    vmState = .running
                    wakeFlash = true
                    startUptimeTimer()
                    startMockEventStream()
                } else {
                    vmState = .error
                    errorMessage = error.localizedDescription
                }
            }
        } else {
            // No daemon: demo mode with mock events
            try? await Task.sleep(for: .seconds(2.5))
            vmState = .running
            wakeFlash = true
            startUptimeTimer()
            startMockEventStream()
        }
    }

    func stop() async {
        guard vmState == .running else { return }
        vmState = .stopping
        stopAll()

        if daemonReachable {
            do {
                let result = try await DaemonClient.stop()
                if !result.success {
                    // Log but still transition to stopped in the UI
                    errorMessage = result.message
                }
            } catch {
                // Network error — still reflect stopped state locally
            }
        } else {
            try? await Task.sleep(for: .milliseconds(800))
        }

        vmState = .stopped
        uptimeSeconds = 0
        memoryMB = 0
        cpuHistory = Array(repeating: 0.0, count: 30)
        withAnimation(.easeOut(duration: 0.4)) {
            events = []
        }
    }

    // MARK: - Daemon status sync

    private func syncStatusFromDaemon() async {
        do {
            let status = try await DaemonClient.status()
            daemonReachable = true
            let shouldAutoBoot = !status.running && !didHandleLaunchAutoBoot
            didHandleLaunchAutoBoot = true

            if status.running {
                vmState = .running
                uptimeSeconds = Int(status.uptime_seconds)
                startUptimeTimer()
                startTelemetryStream()
            } else if shouldAutoBoot {
                await boot(allowMockFallback: false)
            }
        } catch {
            daemonReachable = false
            didHandleLaunchAutoBoot = true
            // Daemon not running — stay in stopped state, demo mode available
        }
    }

    // MARK: - Persistent status polling

    /// Fires every 5 s — detects terminal-initiated VM boots/stops and keeps telemetry live.
    private func startStatusPolling() {
        pollTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                await self?.pollDaemonStatus()
            }
        }
    }

    private func pollDaemonStatus() async {
        do {
            let status = try await DaemonClient.status()
            daemonReachable = true
            consecutiveFailedPolls = 0

            if status.running {
                // Always snap to daemon truth so the counter survives daemon
                // restarts, VM reboots, and clock drift. Local timer ticks
                // between polls for smooth animation.
                uptimeSeconds = Int(status.uptime_seconds)
                if vmState == .stopped || vmState == .error {
                    // Terminal did `garden boot` while UI wasn't watching — reattach
                    vmState = .running
                    startUptimeTimer()
                    startTelemetryStream()
                    withAnimation(.easeIn) { wakeFlash = true }
                } else if vmState == .running {
                    // VM still running but we may have torn things down
                    // during a transient daemon hiccup. Reconnect telemetry
                    // and resume the uptime timer if either was paused.
                    if telemetry == nil { startTelemetryStream() }
                    if uptimeTimer == nil { startUptimeTimer() }
                }
            } else if vmState == .running || vmState == .booting {
                // Terminal did `garden stop` — reflect in UI
                stopAll()
                vmState = .stopped
                uptimeSeconds = 0
                memoryMB = 0
                cpuHistory = Array(repeating: 0.0, count: 30)
                withAnimation(.easeOut(duration: 0.4)) { events = [] }
            }
        } catch {
            // Daemon went away (typical cause: `garden down` from the terminal
            // followed by `garden start`). Tear down the telemetry stream so
            // the next successful poll's `telemetry == nil` branch kicks in
            // and reconnects against the *new* daemon process. Without this,
            // the dead NWConnection from the previous daemon's lifetime stays
            // resident, never recovers, and events silently stop appearing
            // even though vmState is still .running.
            daemonReachable = false
            if telemetry != nil {
                telemetry?.stop()
                telemetry = nil
            }

            // Freeze the uptime/cpu animation on the FIRST failure. The
            // offline banner is already visible at this point (gated on
            // daemonReachable), so a still-ticking clock makes the UI
            // inconsistent with what the banner is saying. The displayed
            // uptimeSeconds value is preserved verbatim — if the daemon
            // comes back inside the threshold window, the success branch
            // will resume the timer and snap to daemon truth.
            uptimeTimer?.invalidate(); uptimeTimer = nil

            // After a couple of consecutive failures, assume the daemon is
            // genuinely offline (not just a transient blip) and roll the UI
            // back to .stopped so we don't keep showing stale uptime/cpu.
            // The next successful poll's reattach branch will pick the new
            // daemon up automatically — no manual relaunch needed.
            consecutiveFailedPolls += 1
            if consecutiveFailedPolls >= failedPollsBeforeOffline,
               vmState == .running || vmState == .booting {
                stopAll()
                vmState = .stopped
                uptimeSeconds = 0
                memoryMB = 0
                cpuHistory = Array(repeating: 0.0, count: 30)
                withAnimation(.easeOut(duration: 0.4)) { events = [] }
            }
        }
    }

    // MARK: - Timers

    private var uptimeTimer: Timer?
    private var mockTimer: Timer?
    private var telemetry: TelemetryStream?
    private var statusPollTask: Task<Void, Never>?
    private var pollTimer: Timer?  // persistent — NOT stopped by stopAll()

    private func startUptimeTimer() {
        uptimeTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, self.vmState == .running else { return }
                self.uptimeSeconds += 1

                // Simulate CPU fluctuation (real metrics not yet exposed by daemon)
                let last = self.cpuHistory.last ?? 0.25
                let next = max(0.05, min(0.95, last + Double.random(in: -0.08...0.08)))
                self.cpuHistory.removeFirst()
                self.cpuHistory.append(next)

                self.memoryMB = 196 + Double.random(in: -12...12)
            }
        }
    }

    private func startTelemetryStream() {
        let stream = TelemetryStream()
        stream.onEvent = { [weak self] event in
            Task { @MainActor [weak self] in
                guard let self, self.vmState == .running else { return }
                withAnimation(.spring(duration: 0.4, bounce: 0.3)) {
                    self.events.insert(event, at: 0)
                    if self.events.count > 150 { self.events.removeLast() }
                }
            }
        }
        stream.start()
        telemetry = stream
    }

    private func startMockEventStream() {
        injectMockEvent()
        mockTimer = Timer.scheduledTimer(withTimeInterval: 1.4, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, self.vmState == .running else { return }
                self.injectMockEvent()
            }
        }
    }

    private func injectMockEvent() {
        let event = MockData.randomEvent()
        withAnimation(.spring(duration: 0.4, bounce: 0.3)) {
            events.insert(event, at: 0)
            if events.count > 150 { events.removeLast() }
        }
    }

    private func stopAll() {
        uptimeTimer?.invalidate(); uptimeTimer = nil
        mockTimer?.invalidate();   mockTimer = nil
        telemetry?.stop();         telemetry = nil
        statusPollTask?.cancel();  statusPollTask = nil
    }
}

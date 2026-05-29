import GardenTelemetry
import SwiftUI

// ---------------------------------------------------------------------------
// SessionsView — browse past session log files from ~/.garden/sessions/
// ---------------------------------------------------------------------------

struct SessionsView: View {
    @State private var sessions: [SessionInfo] = []
    @State private var selectedSession: SessionInfo?
    @State private var sessionEvents: [SecurityEvent] = []
    @State private var showViolationsOnly = false
    @State private var isLoading = false
    @State private var errorMsg: String?

    private var displayedEvents: [SecurityEvent] {
        showViolationsOnly ? sessionEvents.filter(\.isViolation) : sessionEvents
    }

    var body: some View {
        VStack(spacing: 0) {
            sessionHeader
            Divider().opacity(0.2)
            if selectedSession != nil {
                sessionDetail
            } else {
                sessionList
            }
        }
        .task { await loadSessions() }
    }

    // MARK: - Header

    private var sessionHeader: some View {
        HStack(spacing: 8) {
            if selectedSession != nil {
                Button {
                    withAnimation(.spring(duration: 0.3)) {
                        selectedSession = nil
                        sessionEvents = []
                        showViolationsOnly = false
                    }
                } label: {
                    Image(systemName: "chevron.left")
                        .font(.system(size: 11, weight: .semibold))
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.secondary)
            }

            Image(systemName: "clock.arrow.trianglehead.counterclockwise.rotate.90")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)

            Text(selectedSession.map { "Session \($0.displayDate)" } ?? "Session History")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)
                .lineLimit(1)

            Spacer()

            if selectedSession == nil {
                Button { Task { await loadSessions() } } label: {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
            } else {
                let violationCount = sessionEvents.filter(\.isViolation).count
                Button {
                    withAnimation(.spring(duration: 0.3)) {
                        showViolationsOnly.toggle()
                    }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 9, weight: .semibold))
                        if violationCount > 0 {
                            Text("\(violationCount)")
                                .font(.system(size: 10, weight: .bold).monospacedDigit())
                        } else {
                            Text("Violations")
                                .font(.system(size: 10, weight: .medium))
                        }
                    }
                    .foregroundStyle(showViolationsOnly ? .white : (violationCount > 0 ? .red : .secondary))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background {
                        Capsule()
                            .fill(showViolationsOnly ? Color.red : Color.red.opacity(violationCount > 0 ? 0.12 : 0.0))
                            .overlay {
                                Capsule()
                                    .strokeBorder(Color.red.opacity(showViolationsOnly ? 0 : (violationCount > 0 ? 0.35 : 0.2)), lineWidth: 0.5)
                            }
                    }
                }
                .buttonStyle(.borderless)
                .animation(.spring(duration: 0.25), value: showViolationsOnly)
                .animation(.spring(duration: 0.25), value: violationCount)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
    }

    // MARK: - Session List

    @ViewBuilder
    private var sessionList: some View {
        if isLoading {
            centerState { ProgressView().scaleEffect(0.7) }
        } else if let err = errorMsg {
            centerState {
                VStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.system(size: 24)).foregroundStyle(.tertiary)
                    Text(err).font(.callout).foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center)
                }
            }
        } else if sessions.isEmpty {
            centerState {
                VStack(spacing: 8) {
                    Image(systemName: "clock")
                        .font(.system(size: 24)).foregroundStyle(.tertiary)
                    Text("No sessions yet.\nBoot the sandbox to start recording.")
                        .font(.callout).foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center)
                }
            }
        } else {
            ScrollView(.vertical, showsIndicators: false) {
                LazyVStack(spacing: 3) {
                    ForEach(sessions) { session in
                        SessionRowView(session: session)
                            .onTapGesture { Task { await selectSession(session) } }
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
            }
        }
    }

    // MARK: - Session Detail

    @ViewBuilder
    private var sessionDetail: some View {
        if isLoading {
            centerState { ProgressView().scaleEffect(0.7) }
        } else if displayedEvents.isEmpty {
            centerState {
                VStack(spacing: 8) {
                    Image(systemName: showViolationsOnly ? "exclamationmark.triangle" : "tray")
                        .font(.system(size: 24)).foregroundStyle(.tertiary)
                    Text(showViolationsOnly ? "No violations in this session." : "No events in this session.")
                        .font(.callout).foregroundStyle(.tertiary)
                }
            }
        } else {
            ScrollView(.vertical, showsIndicators: false) {
                LazyVStack(spacing: 3) {
                    ForEach(displayedEvents) { event in
                        EventRowView(event: event)
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .animation(.spring(duration: 0.4, bounce: 0.25), value: displayedEvents.map(\.id))
            }
        }
    }

    private func centerState<C: View>(@ViewBuilder content: () -> C) -> some View {
        content()
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Data Loading

    private func loadSessions() async {
        isLoading = true
        errorMsg = nil
        do {
            sessions = try await DaemonClient.sessions()
        } catch DaemonClientError.unreachable {
            sessions = loadLocalSessions()
            if sessions.isEmpty {
                errorMsg = "Daemon not running.\nStart the daemon to view sessions."
            }
        } catch {
            errorMsg = error.localizedDescription
        }
        isLoading = false
    }

    private func selectSession(_ session: SessionInfo) async {
        withAnimation(.spring(duration: 0.3)) { selectedSession = session }
        isLoading = true
        do {
            let entries = try await DaemonClient.sessionEvents(id: session.id)
            sessionEvents = entries.compactMap { $0.toSecurityEvent() }
        } catch DaemonClientError.unreachable {
            sessionEvents = loadLocalEvents(sessionId: session.id)
        } catch {
            sessionEvents = []
        }
        isLoading = false
    }

    // MARK: - Local disk fallback (daemon offline)

    private func loadLocalSessions() -> [SessionInfo] {
        let url = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".garden/sessions")
        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: url, includingPropertiesForKeys: nil
        ) else { return [] }

        return entries
            .filter { $0.hasDirectoryPath }
            .compactMap { dir -> SessionInfo? in
                let id = dir.lastPathComponent
                guard id.allSatisfy(\.isNumber) else { return nil }
                let eventsURL = dir.appendingPathComponent("events.ndjson")
                let count = (try? String(contentsOf: eventsURL, encoding: .utf8))?
                    .components(separatedBy: "\n")
                    .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
                    .count ?? 0
                return SessionInfo(id: id, start_ts: id, event_count: UInt64(count))
            }
            .sorted { $0.id > $1.id }
    }

    private func loadLocalEvents(sessionId: String) -> [SecurityEvent] {
        let url = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".garden/sessions/\(sessionId)/events.ndjson")
        guard let content = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        let decoder = JSONDecoder()
        return content.components(separatedBy: "\n")
            .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            .compactMap { line -> SecurityEvent? in
                guard let data = line.data(using: .utf8),
                      let entry = try? decoder.decode(LogEntry.self, from: data)
                else { return nil }
                return entry.toSecurityEvent()
            }
    }
}

// ---------------------------------------------------------------------------
// SessionRowView — a single row in the session list
// ---------------------------------------------------------------------------

struct SessionRowView: View {
    let session: SessionInfo
    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "doc.text.fill")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .frame(width: 20)

            VStack(alignment: .leading, spacing: 2) {
                Text(session.displayDate)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.primary)
                Text("\(session.event_count) events")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Image(systemName: "chevron.right")
                .font(.system(size: 10))
                .foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(isHovered ? Color.white.opacity(0.08) : Color.white.opacity(0.04))
                .overlay {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .strokeBorder(.white.opacity(0.07), lineWidth: 0.5)
                }
        }
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .onHover { isHovered = $0 }
        .animation(.easeOut(duration: 0.15), value: isHovered)
    }
}

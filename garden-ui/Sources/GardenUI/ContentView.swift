import SwiftUI

struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @State private var contentOpacity: Double = 1.0
    @State private var activeTab: Tab = .live

    enum Tab { case live, sessions }

    var body: some View {
        VStack(spacing: 0) {

            // Zone 1 — Status Island
            VStack {
                StatusIslandView()
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .background(.regularMaterial)

            thinDivider

            // Tab picker
            tabPicker

            thinDivider

            // Zone 2 — Live Feed or Sessions (takes all remaining space)
            Group {
                if activeTab == .live {
                    SecurityFeedView()
                } else {
                    SessionsView()
                }
            }
            .frame(maxHeight: .infinity)

            thinDivider

            // Zone 3 — Action Rail
            ActionRailView()
                .background(.regularMaterial)
        }
        .opacity(contentOpacity)
        .onChange(of: appState.wakeFlash) { fired in
            guard fired else { return }
            appState.wakeFlash = false
            contentOpacity = 0.82
            withAnimation(.easeIn(duration: 0.45)) {
                contentOpacity = 1.0
            }
        }
        .onChange(of: appState.vmState) { state in
            withAnimation(.easeInOut(duration: 0.4)) {
                contentOpacity = state == .stopped ? 0.85 : 1.0
            }
        }
    }

    // MARK: - Tab Picker

    private var tabPicker: some View {
        HStack(spacing: 0) {
            tabButton("Live", tab: .live, icon: "waveform")
            tabButton("Sessions", tab: .sessions, icon: "clock")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 6)
        .background(.regularMaterial)
    }

    private func tabButton(_ label: String, tab: Tab, icon: String) -> some View {
        let isActive = activeTab == tab
        return Button {
            withAnimation(.spring(duration: 0.3, bounce: 0.2)) {
                activeTab = tab
            }
        } label: {
            HStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.system(size: 10, weight: .medium))
                Text(label)
                    .font(.system(size: 11, weight: .medium))
            }
            .foregroundStyle(isActive ? .primary : .secondary)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background {
                if isActive {
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .fill(.ultraThinMaterial)
                        .overlay {
                            RoundedRectangle(cornerRadius: 7, style: .continuous)
                                .strokeBorder(.white.opacity(0.15), lineWidth: 0.5)
                        }
                }
            }
        }
        .buttonStyle(.borderless)
    }

    private var thinDivider: some View {
        Divider().opacity(0.25)
    }
}

// ---------------------------------------------------------------------------
// Settings window (stub)
// ---------------------------------------------------------------------------

struct SettingsView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Garden AI Settings")
                .font(.title2.bold())

            Divider()

            Label("Daemon gRPC:  127.0.0.1:9000", systemImage: "bolt.fill")
            Label("HTTP API:     127.0.0.1:9001", systemImage: "network")
            Label("Agent proxy:  127.0.0.1:10000", systemImage: "cpu")
            Label("Telemetry:    127.0.0.1:10001", systemImage: "chart.xyaxis.line")

            Spacer()
        }
        .padding(20)
        .frame(width: 320, height: 200)
    }
}

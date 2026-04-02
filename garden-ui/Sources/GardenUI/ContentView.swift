import SwiftUI

struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @State private var contentOpacity: Double = 1.0

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

            // Zone 2 — Security Feed (takes all remaining space)
            SecurityFeedView()
                .frame(maxHeight: .infinity)

            thinDivider

            // Zone 3 — Action Rail
            ActionRailView()
                .background(.regularMaterial)
        }
        .opacity(contentOpacity)
        // Wake flash: briefly dims and returns to full brightness on .running
        .onChange(of: appState.wakeFlash) { fired in
            guard fired else { return }
            appState.wakeFlash = false
            contentOpacity = 0.82
            withAnimation(.easeIn(duration: 0.45)) {
                contentOpacity = 1.0
            }
        }
        // Dim content when stopped
        .onChange(of: appState.vmState) { state in
            withAnimation(.easeInOut(duration: 0.4)) {
                contentOpacity = state == .stopped ? 0.85 : 1.0
            }
        }
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
            Label("Agent proxy:  127.0.0.1:10000", systemImage: "cpu")
            Label("Telemetry:   127.0.0.1:10001", systemImage: "chart.xyaxis.line")

            Spacer()
        }
        .padding(20)
        .frame(width: 320, height: 200)
    }
}

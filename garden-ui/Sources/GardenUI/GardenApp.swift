import SwiftUI

@main
struct GardenApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        Window("Garden AI", id: "main") {
            ContentView()
                .environmentObject(appState)
        }
        .defaultSize(width: 420, height: 600)
        .windowResizability(.contentMinSize)

        MenuBarExtra {
            MenuBarStatusView()
                .environmentObject(appState)
        } label: {
            menuBarLabel
        }
        .menuBarExtraStyle(.menu)

        Settings {
            SettingsView()
                .environmentObject(appState)
        }
    }

    @ViewBuilder
    private var menuBarLabel: some View {
        switch appState.vmState {
        case .booting:
            Image(systemName: "leaf.fill")
                .symbolEffect(.variableColor.iterative.dimInactiveLayers, isActive: true)
        case .running:
            Image(systemName: "leaf.fill")
                .foregroundStyle(Color(hue: 0.36, saturation: 0.7, brightness: 0.75))
        case .error:
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
        case .stopped, .stopping:
            Image(systemName: "leaf")
                .foregroundStyle(.secondary)
        }
    }
}

struct MenuBarStatusView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("Open Garden AI") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Divider()
        Text(statusLine)
            .foregroundStyle(.secondary)
        Divider()
        Button("Quit Garden AI") {
            NSApplication.shared.terminate(nil)
        }
    }

    private var statusLine: String {
        switch appState.vmState {
        case .booting:  return "Sandbox: booting..."
        case .running:  return "Sandbox: running"
        case .stopping: return "Sandbox: stopping..."
        case .stopped:  return "Sandbox: stopped"
        case .error:    return "Sandbox: error"
        }
    }
}

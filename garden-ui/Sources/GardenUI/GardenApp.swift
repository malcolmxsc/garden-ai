import SwiftUI

@main
struct GardenApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        MenuBarExtra {
            ContentView()
                .environmentObject(appState)
                .frame(width: 420, height: 540)
        } label: {
            menuBarLabel
        }
        .menuBarExtraStyle(.window)

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
        default:
            Image(systemName: "leaf")
                .foregroundStyle(.secondary)
        }
    }
}

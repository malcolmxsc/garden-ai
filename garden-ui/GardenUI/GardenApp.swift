import SwiftUI

/// Garden AI — Menu Bar App
///
/// This is the main entry point for the GardenUI macOS application.
/// It runs as a menu bar extra (no dock icon) and provides:
/// - VM lifecycle controls (boot/stop)
/// - Visual diff/merge for AI file changes
/// - Security dashboard (eBPF event feed)
@main
struct GardenApp: App {
    @StateObject private var vmManager = VMManager()

    var body: some Scene {
        // Menu bar popover
        MenuBarExtra("Garden AI", systemImage: "leaf.fill") {
            ContentView(vmManager: vmManager)
                .frame(width: 420, height: 520)
        }
        .menuBarExtraStyle(.window)

        // Settings window (accessible via ⌘,)
        Settings {
            Text("Garden AI Settings")
                .padding()
        }
    }
}

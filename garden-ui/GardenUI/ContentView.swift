import SwiftUI

/// Main content view displayed in the menu bar popover.
///
/// Shows sandbox status, quick actions, and a summary of security events.
struct ContentView: View {
    @ObservedObject var vmManager: VMManager

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // --- Header ---
            HStack {
                Image(systemName: "leaf.fill")
                    .foregroundColor(.green)
                    .font(.title2)
                Text("Garden AI")
                    .font(.title2)
                    .fontWeight(.bold)
                Spacer()
                StatusBadge(state: vmManager.state)
            }

            Divider()

            // --- Status ---
            VStack(alignment: .leading, spacing: 8) {
                Label(vmManager.statusMessage, systemImage: "info.circle")
                    .foregroundColor(.secondary)
                    .font(.callout)
            }

            Divider()

            // --- Quick Actions ---
            VStack(spacing: 8) {
                if vmManager.state == .stopped {
                    Button(action: {
                        Task {
                            try? await vmManager.boot(
                                kernelPath: "guest/kernel/bzImage",
                                rootfsPath: "guest/rootfs/rootfs.img"
                            )
                        }
                    }) {
                        Label("Boot Sandbox", systemImage: "play.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .controlSize(.large)
                    .buttonStyle(.borderedProminent)
                    .tint(.green)
                } else if vmManager.state == .running {
                    Button(action: {
                        Task { try? await vmManager.stop() }
                    }) {
                        Label("Stop Sandbox", systemImage: "stop.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .controlSize(.large)
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                }
            }

            Divider()

            // --- Placeholder sections ---
            Group {
                Label("File Changes", systemImage: "doc.badge.plus")
                    .font(.headline)
                Text("No pending changes")
                    .foregroundColor(.secondary)
                    .font(.callout)
            }

            Group {
                Label("Security Events", systemImage: "shield.lefthalf.filled")
                    .font(.headline)
                Text("No events recorded")
                    .foregroundColor(.secondary)
                    .font(.callout)
            }

            Spacer()

            // --- Footer ---
            HStack {
                Button("Settings") {
                    NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
                }
                .buttonStyle(.borderless)
                Spacer()
                Button("Quit") {
                    NSApplication.shared.terminate(nil)
                }
                .buttonStyle(.borderless)
                .foregroundColor(.red)
            }
            .font(.callout)
        }
        .padding()
    }
}

/// Small badge showing the VM state.
struct StatusBadge: View {
    let state: VMManager.VMState

    var color: Color {
        switch state {
        case .running: return .green
        case .booting, .stopping: return .orange
        case .stopped: return .secondary
        case .error: return .red
        }
    }

    var body: some View {
        Text(state.rawValue)
            .font(.caption)
            .fontWeight(.medium)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.15))
            .foregroundColor(color)
            .clipShape(Capsule())
    }
}

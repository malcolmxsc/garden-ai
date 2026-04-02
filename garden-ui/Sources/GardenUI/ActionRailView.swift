import SwiftUI
import AppKit

// ---------------------------------------------------------------------------
// Action Rail — boot/stop + workspace + footer
// ---------------------------------------------------------------------------

struct ActionRailView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        HStack(spacing: 8) {
            primaryButton
            workspaceButton
            Spacer()
            footerButtons
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
    }

    // MARK: - Primary button (Boot / Stop / disabled)

    @ViewBuilder
    private var primaryButton: some View {
        switch appState.vmState {
        case .stopped, .error:
            GlassButton(label: "Boot", icon: "play.fill", tint: Color(hue: 0.36, saturation: 0.7, brightness: 0.75)) {
                Task { await appState.boot() }
            }
        case .running:
            GlassButton(label: "Stop", icon: "stop.fill", tint: .red) {
                Task { await appState.stop() }
            }
        case .booting:
            GlassButton(label: "Starting…", icon: "ellipsis", tint: .secondary) { }
                .disabled(true)
                .opacity(0.6)
        case .stopping:
            GlassButton(label: "Stopping…", icon: "ellipsis", tint: .secondary) { }
                .disabled(true)
                .opacity(0.6)
        }
    }

    // MARK: - Workspace button

    private var workspaceButton: some View {
        GlassButton(label: "Workspace", icon: "folder.fill", tint: .blue) {
            let url = URL(fileURLWithPath: NSHomeDirectory() + "/GardenBox")
            NSWorkspace.shared.open(url)
        }
    }

    // MARK: - Footer (Settings + Quit)

    private var footerButtons: some View {
        HStack(spacing: 12) {
            Button("Settings") {
                NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
            }
            .buttonStyle(.borderless)
            .font(.callout)
            .foregroundStyle(.secondary)

            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
            .buttonStyle(.borderless)
            .font(.callout)
            .foregroundStyle(.red)
        }
    }
}

// ---------------------------------------------------------------------------
// GlassButton — reusable glass-style button with spring press feedback
// ---------------------------------------------------------------------------

struct GlassButton: View {
    let label: String
    let icon: String
    var tint: Color = .primary
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Image(systemName: icon)
                    .font(.system(size: 11, weight: .semibold))
                Text(label)
                    .font(.system(size: 12, weight: .medium))
            }
            .foregroundStyle(tint)
        }
        .buttonStyle(GlassButtonStyle(tint: tint))
    }
}

struct GlassButtonStyle: ButtonStyle {
    let tint: Color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(.ultraThinMaterial)
                    .overlay {
                        // Tint fill — stronger when pressed
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .fill(tint.opacity(configuration.isPressed ? 0.18 : 0.08))
                    }
                    .overlay {
                        // Glass rim
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .strokeBorder(
                                LinearGradient(
                                    colors: [Color.white.opacity(0.24), Color.white.opacity(0.06)],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                ),
                                lineWidth: 0.5
                            )
                    }
            }
            // Press scale — small but physically convincing
            .scaleEffect(configuration.isPressed ? 0.96 : 1.0)
            // Spring back overshoots to 1.01 before settling — feels real
            .animation(
                configuration.isPressed
                    ? .easeOut(duration: 0.08)
                    : .spring(duration: 0.3, bounce: 0.45),
                value: configuration.isPressed
            )
    }
}

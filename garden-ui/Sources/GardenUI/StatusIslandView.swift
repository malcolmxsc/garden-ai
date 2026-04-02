import SwiftUI

// ---------------------------------------------------------------------------
// Status Island — the animated pill at the top of the popover
// ---------------------------------------------------------------------------

struct StatusIslandView: View {
    @EnvironmentObject var appState: AppState

    // Arc animation state
    @State private var arcRotation: Double = 0
    @State private var arcTrim: Double = 0.68

    // Glow animation state
    @State private var glowOpacity: Double = 0

    var body: some View {
        HStack(spacing: 10) {

            // --- Icon + booting arc ---
            ZStack {
                if appState.vmState == .booting {
                    bootingArc
                        .transition(
                            .asymmetric(
                                insertion: .opacity,
                                removal: .opacity.combined(with: .scale(scale: 1.5))
                            )
                        )
                }
                Image(systemName: appState.vmState == .stopped ? "leaf" : "leaf.fill")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(appState.vmState.color)
                    .symbolEffect(.bounce, value: appState.vmState == .running)
            }
            .frame(width: 20, height: 20)

            // --- State label / uptime ---
            stateLabel

            // --- Resource meters (running only) ---
            if appState.vmState == .running {
                HStack(spacing: 8) {
                    MiniSparkline(values: appState.cpuHistory, color: appState.vmState.color)
                        .frame(width: 38, height: 18)

                    Text("\(Int(appState.memoryMB))M")
                        .font(.system(size: 10, weight: .medium).monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                .transition(
                    .asymmetric(
                        insertion: .opacity.combined(with: .scale(scale: 0.7, anchor: .leading)),
                        removal: .opacity
                    )
                )
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 9)
        .background { islandBackground }
        // The spring drives the width change as content appears/disappears
        .animation(.spring(duration: 0.5, bounce: 0.25), value: appState.vmState)
        .onAppear    { startArcAnimation()  }
        .onChange(of: appState.vmState) { startGlowAnimation() }
    }

    // MARK: - Sub-views

    @ViewBuilder
    private var stateLabel: some View {
        switch appState.vmState {
        case .stopped:
            Text("Garden AI")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.secondary)

        case .booting:
            Text("Starting…")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(appState.vmState.color)

        case .running:
            Text(appState.formattedUptime)
                .font(.system(size: 13, weight: .semibold).monospacedDigit())
                .foregroundStyle(appState.vmState.color)
                .contentTransition(.numericText(countsDown: false))
                .animation(.spring(duration: 0.3, bounce: 0.1), value: appState.formattedUptime)

        case .stopping:
            Text("Stopping…")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.orange)

        case .error:
            Text(appState.errorMessage ?? "Error")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.red)
                .lineLimit(1)
        }
    }

    @ViewBuilder
    private var islandBackground: some View {
        Capsule(style: .continuous)
            .fill(.ultraThinMaterial)
            .overlay {
                // State tint layer
                Capsule(style: .continuous)
                    .fill(appState.vmState.color.opacity(0.09))
            }
            .overlay {
                // Glass rim
                Capsule(style: .continuous)
                    .strokeBorder(
                        LinearGradient(
                            colors: [Color.white.opacity(0.28), Color.white.opacity(0.06)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: 0.6
                    )
            }
            .shadow(
                color: appState.vmState.color.opacity(glowOpacity),
                radius: 10, x: 0, y: 0
            )
    }

    @ViewBuilder
    private var bootingArc: some View {
        Circle()
            .trim(from: 0, to: arcTrim)
            .stroke(
                AngularGradient(
                    colors: [appState.vmState.color.opacity(0), appState.vmState.color],
                    center: .center
                ),
                style: StrokeStyle(lineWidth: 2, lineCap: .round)
            )
            .rotationEffect(.degrees(arcRotation - 90))
    }

    // MARK: - Animations

    private func startArcAnimation() {
        withAnimation(.linear(duration: 0.9).repeatForever(autoreverses: false)) {
            arcRotation = 360
        }
        withAnimation(.easeInOut(duration: 1.4).repeatForever(autoreverses: true)) {
            arcTrim = 0.84
        }
    }

    private func startGlowAnimation() {
        // Cancel previous glow
        glowOpacity = 0
        guard appState.vmState == .running else { return }

        withAnimation(.easeInOut(duration: 2.6).repeatForever(autoreverses: true)) {
            glowOpacity = 0.45
        }
    }
}

// ---------------------------------------------------------------------------
// MiniSparkline — tiny animated waveform for CPU history
// ---------------------------------------------------------------------------

struct MiniSparkline: View {
    let values: [Double]   // each value 0.0–1.0
    let color: Color

    var body: some View {
        GeometryReader { geo in
            let pts = points(in: geo.size)
            ZStack(alignment: .bottom) {
                fillPath(pts: pts, height: geo.size.height)
                    .fill(
                        LinearGradient(
                            colors: [color.opacity(0.35), color.opacity(0.04)],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                strokePath(pts: pts)
                    .stroke(
                        color.opacity(0.75),
                        style: StrokeStyle(lineWidth: 1.5, lineCap: .round, lineJoin: .round)
                    )
            }
        }
    }

    private func points(in size: CGSize) -> [CGPoint] {
        guard values.count > 1 else { return [] }
        let step = size.width / CGFloat(values.count - 1)
        return values.enumerated().map { i, v in
            CGPoint(x: CGFloat(i) * step, y: size.height * (1 - CGFloat(v)))
        }
    }

    private func fillPath(pts: [CGPoint], height: CGFloat) -> Path {
        Path { p in
            guard let first = pts.first, let last = pts.last else { return }
            p.move(to: CGPoint(x: first.x, y: height))
            pts.forEach { p.addLine(to: $0) }
            p.addLine(to: CGPoint(x: last.x, y: height))
            p.closeSubpath()
        }
    }

    private func strokePath(pts: [CGPoint]) -> Path {
        Path { p in
            guard let first = pts.first else { return }
            p.move(to: first)
            pts.dropFirst().forEach { p.addLine(to: $0) }
        }
    }
}

import SwiftUI

// ---------------------------------------------------------------------------
// EventRowView — a single row in the security feed
// ---------------------------------------------------------------------------

struct EventRowView: View {
    let event: SecurityEvent

    // Arrival pulse for violations
    @State private var pulseScale: CGFloat = 1.0
    @State private var pulseOpacity: Double = 0.0

    // Breathing glow for violation rows
    @State private var glowOpacity: Double = 0.25

    var body: some View {
        HStack(spacing: 0) {

            // --- Left colour bar ---
            RoundedRectangle(cornerRadius: 1.5)
                .fill(event.kind.color)
                .frame(width: 2.5)
                .padding(.vertical, 6)
                .padding(.leading, 8)

            // --- Icon ---
            Image(systemName: event.kind.icon)
                .font(.system(size: 10, weight: .medium))
                .foregroundStyle(event.kind.color)
                .frame(width: 20)
                .padding(.leading, 6)

            // --- Content ---
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(event.comm)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(.primary)
                    Text("·")
                        .foregroundStyle(.tertiary)
                    Text("pid \(event.pid)")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                }

                Text(event.kind.description)
                    .font(.system(size: 10).monospaced())
                    .foregroundStyle(event.isViolation ? event.kind.color.opacity(0.9) : .secondary)
                    .lineLimit(1)
            }
            .padding(.leading, 7)

            Spacer(minLength: 4)

            // --- Right: timestamp + violation badge ---
            VStack(alignment: .trailing, spacing: 3) {
                Text(event.timeString)
                    .font(.system(size: 9).monospacedDigit())
                    .foregroundStyle(.tertiary)

                if event.isViolation {
                    Text("VIOLATION")
                        .font(.system(size: 7, weight: .bold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(.red))
                }
            }
            .padding(.trailing, 10)
        }
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background { rowBackground }
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .onAppear {
            if event.isViolation { fireArrivalPulse() }
            startViolationGlow()
        }
    }

    // MARK: - Background

    @ViewBuilder
    private var rowBackground: some View {
        if event.isViolation {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(.red.opacity(0.07))
                .overlay {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .strokeBorder(.red.opacity(glowOpacity), lineWidth: 0.6)
                }
                // Arrival pulse radiates outward from the left
                .overlay(alignment: .leading) {
                    Circle()
                        .fill(.red.opacity(pulseOpacity))
                        .frame(width: 24, height: 24)
                        .scaleEffect(pulseScale)
                        .offset(x: 6)
                        .allowsHitTesting(false)
                }
        } else {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(.white.opacity(0.04))
                .overlay {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .strokeBorder(.white.opacity(0.07), lineWidth: 0.5)
                }
        }
    }

    // MARK: - Animations

    private func fireArrivalPulse() {
        // Reset to initial state
        pulseScale   = 1.0
        pulseOpacity = 0.55
        // Delay slightly so the row entrance spring settles first,
        // then the pulse expands and fades
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            withAnimation(.easeOut(duration: 0.65)) {
                pulseScale   = 2.8
                pulseOpacity = 0
            }
        }
    }

    private func startViolationGlow() {
        guard event.isViolation else { return }
        withAnimation(.easeInOut(duration: 2.8).repeatForever(autoreverses: true)) {
            glowOpacity = 0.55
        }
    }
}

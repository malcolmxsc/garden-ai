import SwiftUI

// ---------------------------------------------------------------------------
// Security Feed — scrolling list of eBPF events
// ---------------------------------------------------------------------------

struct SecurityFeedView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        VStack(spacing: 0) {
            feedHeader
            Divider().opacity(0.2)
            eventList
        }
    }

    // MARK: - Header

    private var feedHeader: some View {
        HStack(spacing: 8) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)

            Text("Security Events")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)

            if !appState.events.isEmpty {
                let count = appState.showViolationsOnly
                    ? appState.events.filter(\.isViolation).count
                    : appState.events.count
                Text("\(count)")
                    .font(.system(size: 10, weight: .medium).monospacedDigit())
                    .foregroundStyle(.tertiary)
                    .contentTransition(.numericText())
                    .animation(.spring(duration: 0.3), value: count)
            }

            Spacer()

            // Violations toggle
            Toggle(isOn: $appState.showViolationsOnly.animation(.spring(duration: 0.3))) {
                Label("Violations only", systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 10, weight: .medium))
                    .labelStyle(.iconOnly)
                    .foregroundStyle(appState.showViolationsOnly ? .red : .secondary)
            }
            .toggleStyle(.button)
            .buttonStyle(.borderless)
            .help("Show violations only")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
    }

    // MARK: - Event list

    @ViewBuilder
    private var eventList: some View {
        let displayed = appState.filteredEvents

        if displayed.isEmpty {
            emptyState
        } else {
            ScrollView(.vertical, showsIndicators: false) {
                LazyVStack(spacing: 3) {
                    ForEach(displayed) { event in
                        EventRowView(event: event)
                            .transition(
                                .asymmetric(
                                    insertion: .opacity
                                        .combined(with: .offset(y: -16))
                                        .combined(with: .scale(scale: 0.96, anchor: .top)),
                                    removal: .opacity
                                )
                            )
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                // Drives insertion/removal animations for the whole list
                .animation(.spring(duration: 0.4, bounce: 0.25), value: displayed.map(\.id))
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Image(systemName: appState.vmState == .stopped ? "leaf" : "waveform")
                .font(.system(size: 24))
                .foregroundStyle(.tertiary)
            Text(appState.vmState == .stopped ? "Boot the sandbox to start monitoring" : "Waiting for events…")
                .font(.callout)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

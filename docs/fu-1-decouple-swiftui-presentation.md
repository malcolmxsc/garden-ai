# FU-1 Plan: Decouple SwiftUI Presentation From GardenTelemetry

## Goal

Keep `GardenTelemetry` focused on telemetry data and decoding by removing its dependency on SwiftUI. Presentation details should live in `GardenUI`, where SwiftUI is already required.

## Current Problem

`Sources/GardenTelemetry/SecurityEvent.swift` imports SwiftUI only for `SecurityEvent.Kind.color: Color` and `SecurityEvent.Kind.icon: String`. This forces future non-UI consumers, such as CLIs, tests, or headless telemetry sinks, to resolve SwiftUI for data-only types.

## Proposed Changes

1. Update `Sources/GardenTelemetry/SecurityEvent.swift`.
   - Remove `import SwiftUI`.
   - Remove `SecurityEvent.Kind.color`.
   - Remove `SecurityEvent.Kind.icon`.
   - Keep `SecurityEvent.Kind.description` and `SecurityEvent.timeString`.

2. Add `garden-ui/Sources/GardenUI/SecurityEvent+Presentation.swift`.
   - Import `GardenTelemetry` and `SwiftUI`.
   - Add a UI-side extension on `SecurityEvent.Kind`.
   - Move the existing `icon` and `color` switch implementations into that extension.

3. Rebuild consumers.
   - Run `cd garden-ui && swift build`.
   - Run `make run-agent`.
   - Add imports only if the compiler reports a missing UI-side presentation extension.

## Acceptance Criteria

- `Sources/GardenTelemetry` has no SwiftUI imports.
- `GardenTelemetry` still builds as a data-only module.
- `GardenUI` renders the same event icons and colors.
- `garden-ui` and `GardenAgent` both build successfully.

## Notes

This should be done after the modular migration because the UI now imports the canonical `GardenTelemetry` module instead of local duplicate telemetry files.

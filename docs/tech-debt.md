# Garden AI Tech Debt

This document tracks follow-up work intentionally left outside the modular migration that removed duplicate Swift sources and wired consumers to the root Swift package.

## FU-1: Decouple SwiftUI Presentation From GardenTelemetry

Status: Planned. See `docs/fu-1-decouple-swiftui-presentation.md` for the review plan.

`Sources/GardenTelemetry/SecurityEvent.swift` currently imports SwiftUI only to expose presentation helpers on `SecurityEvent.Kind`. Move `icon` and `color` into a UI-side extension so `GardenTelemetry` remains a pure telemetry/data module.

## FU-2: Extract an MLX-free GardenKit Package

Move `GardenCore` and `GardenTelemetry` into their own package so `garden-ui` can depend on shared Swift code without resolving `mlx-swift` and `swift-numerics`.

## FU-3: Resolve the Orphaned Root Test Target

`Tests/garden-aiTests/garden_aiTests.swift` imports a nonexistent `garden_ai` module and has no test target in the root manifest. Either declare the intended `.testTarget` or delete the stale test file.

## FU-4: Wire the Real Quantized Model

`GardenAgent` currently runs only an MLX smoke test. Loading `mlx-community/Qwen2.5-7B-Instruct-4bit` requires adding the `MLXLLM` and `Hub` products from `mlx-swift-examples`, plus a model download/cache path.

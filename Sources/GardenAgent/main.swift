import Foundation
import MLX
import GardenCore
import GardenTelemetry

@MainActor
func run() async {
    print("🌱 Starting GardenAgent MLX Orchestration Engine...")

    // 1. Core Virtualization check using GardenCore
    let virtualizer = GardenVirtualizer()
    do {
        let isSupported = try virtualizer.checkHardwareSupport()
        print("💻 Apple Silicon Virtualization Support: \(isSupported ? "Supported" : "Unsupported")")
    } catch {
        print("⚠️ Apple Silicon Virtualization Check Error: \(error.localizedDescription)")
    }

    // 2. Telemetry Stream setup using GardenTelemetry
    let telemetry = TelemetryStream()
    telemetry.onEvent = { event in
        print("📡 Received Event: \(event.kind.description)")
    }
    print("📡 Initialized Telemetry stream (listener configured on TCP :10001)")

    // 3. MLX Array initialization to verify MLX library integration
    print("🧠 Initializing MLX backend...")
    let array = MLXArray([1.0, 2.0, 3.0, 4.0])
    let sum = array.sum()
    print("🧠 MLX Test Array: \(array)")
    print("🧠 MLX Test Sum: \(sum.item(Float.self))")

    print("🚀 GardenAgent is ready!")
}

await run()

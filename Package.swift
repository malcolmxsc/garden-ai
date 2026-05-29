// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "garden-ai",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "GardenCore",
            targets: ["GardenCore"]
        ),
        .library(
            name: "GardenTelemetry",
            targets: ["GardenTelemetry"]
        ),
        .executable(
            name: "GardenAgent",
            targets: ["GardenAgent"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/ml-explore/mlx-swift.git", from: "0.10.0")
    ],
    targets: [
        .target(
            name: "GardenCore",
            dependencies: [],
            path: "Sources/GardenCore"
        ),
        .target(
            name: "GardenTelemetry",
            dependencies: [],
            path: "Sources/GardenTelemetry"
        ),
        .executableTarget(
            name: "GardenAgent",
            dependencies: [
                "GardenCore",
                "GardenTelemetry",
                .product(name: "MLX", package: "mlx-swift")
            ],
            path: "Sources/GardenAgent"
        )
    ]
)

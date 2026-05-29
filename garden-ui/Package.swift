// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "GardenUI",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(path: "..")
    ],
    targets: [
        .executableTarget(
            name: "GardenUI",
            dependencies: [
                .product(name: "GardenTelemetry", package: "garden-ai")
            ],
            path: "Sources/GardenUI"
        )
    ]
)

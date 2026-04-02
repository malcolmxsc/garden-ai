// swift-tools-version: 5.9
import PackageDescription

// Garden AI — macOS menu bar app.
// Open this file directly in Xcode: `open Package.swift`
// Then press Cmd+R to run.

let package = Package(
    name: "GardenUI",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "GardenUI",
            path: "Sources/GardenUI"
        )
    ]
)

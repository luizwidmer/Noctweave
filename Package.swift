// swift-tools-version: 5.9
import PackageDescription

/// Repository-root package entry point for downstream Swift integrations.
///
/// The component packages remain independently buildable from
/// `NoctweaveCore/` and `NoctweaveRelayServer/`. This manifest lets another
/// repository depend on the public Core product through the repository URL
/// without copying protocol sources.
let package = Package(
    name: "Noctweave",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "NoctweaveCore",
            targets: ["NoctweaveCore"]
        ),
        .executable(
            name: "NoctweaveCLI",
            targets: ["NoctweaveCLI"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "liboqs",
            path: "NoctweaveCore/Vendor/liboqs.xcframework"
        ),
        .target(
            name: "NoctweaveCore",
            dependencies: ["liboqs"],
            path: "NoctweaveCore/Sources/NoctweaveCore"
        ),
        .executableTarget(
            name: "NoctweaveCLI",
            dependencies: ["NoctweaveCore"],
            path: "NoctweaveCore/Sources/NoctweaveCLI",
            exclude: ["LICENSE"]
        ),
        .testTarget(
            name: "NoctweaveCoreTests",
            dependencies: ["NoctweaveCore"],
            path: "NoctweaveCore/Tests/NoctweaveCoreTests"
        )
    ]
)

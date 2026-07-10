// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "NoctweaveCore",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(name: "NoctweaveCore", targets: ["NoctweaveCore"]),
        .executable(name: "NoctyraCLI", targets: ["NoctyraCLI"]),
        .executable(name: "NoctweaveCoreTestHarness", targets: ["NoctweaveCoreTestHarness"])
    ],
    targets: [
        .binaryTarget(name: "liboqs", path: "Vendor/liboqs.xcframework"),
        .target(name: "NoctweaveCore", dependencies: ["liboqs"]),
        .executableTarget(
            name: "NoctyraCLI",
            dependencies: ["NoctweaveCore"],
            exclude: ["LICENSE"]
        ),
        .executableTarget(name: "NoctweaveCoreTestHarness", dependencies: ["NoctweaveCore"]),
        .testTarget(name: "NoctweaveCoreTests", dependencies: ["NoctweaveCore"])
    ]
)

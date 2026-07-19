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
        .executable(name: "NoctweaveCLI", targets: ["NoctweaveCLI"])
    ],
    targets: [
        .binaryTarget(name: "liboqs", path: "Vendor/liboqs.xcframework"),
        .target(name: "NoctweaveCore", dependencies: ["liboqs"]),
        .executableTarget(
            name: "NoctweaveCLI",
            dependencies: ["NoctweaveCore"],
            exclude: ["LICENSE"]
        ),
        .testTarget(name: "NoctweaveCoreTests", dependencies: ["NoctweaveCore"])
    ]
)

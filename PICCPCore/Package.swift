// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PICCPCore",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(name: "PICCPCore", targets: ["PICCPCore"]),
        .executable(name: "PICCPCoreTestHarness", targets: ["PICCPCoreTestHarness"])
    ],
    targets: [
        .binaryTarget(name: "liboqs", path: "Vendor/liboqs.xcframework"),
        .target(name: "PICCPCore", dependencies: ["liboqs"]),
        .executableTarget(name: "PICCPCoreTestHarness", dependencies: ["PICCPCore"]),
        .testTarget(name: "PICCPCoreTests", dependencies: ["PICCPCore"])
    ]
)

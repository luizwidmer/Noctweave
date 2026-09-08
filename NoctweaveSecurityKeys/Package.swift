// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "NoctweaveSecurityKeys",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "NoctweaveSecurityKeys", targets: ["NoctweaveSecurityKeys"]),
        .executable(name: "NoctweaveSecurityKeyBridge", targets: ["NoctweaveSecurityKeyBridge"])
    ],
    dependencies: [
        .package(path: "Vendor/YubiKit")
    ],
    targets: [
        .target(name: "NoctweaveSecurityKeys", dependencies: [
            .product(name: "YubiKit", package: "YubiKit")
        ]),
        .executableTarget(name: "NoctweaveSecurityKeyBridge", dependencies: ["NoctweaveSecurityKeys"]),
        .testTarget(name: "NoctweaveSecurityKeysTests", dependencies: ["NoctweaveSecurityKeys"])
    ]
)

// swift-tools-version: 6.1
// YubiKit Swift 1.4.0 source snapshot; see UPSTREAM.md for provenance and changes.
import PackageDescription
let package = Package(name: "YubiKit", platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "YubiKit", targets: ["YubiKit"])],
    dependencies: [.package(url: "https://github.com/apple/swift-log.git", exact: "1.15.1")],
    targets: [.target(name: "YubiKit", dependencies: [.product(name: "Logging", package: "swift-log")])])

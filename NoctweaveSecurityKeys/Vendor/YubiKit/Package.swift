// swift-tools-version: 6.1
// YubiKit Swift 1.3.0 source snapshot; see UPSTREAM.md for provenance and changes.
import PackageDescription
let package = Package(name: "YubiKit", platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "YubiKit", targets: ["YubiKit"])],
    targets: [.target(name: "YubiKit")])

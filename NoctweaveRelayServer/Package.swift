// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "NoctweaveRelayServer",
    platforms: [
        .macOS(.v13)
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", exact: "2.92.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.15.1")
    ],
    targets: [
        .systemLibrary(
            name: "CSQLite",
            pkgConfig: "sqlite3",
            providers: [
                .apt(["libsqlite3-dev"]),
                .brew(["sqlite3"])
            ]
        ),
        .executableTarget(
            name: "NoctweaveRelayServer",
            dependencies: [
                "CSQLite",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOFoundationCompat", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOWebSocket", package: "swift-nio"),
                .product(name: "Crypto", package: "swift-crypto")
            ]
        ),
        .testTarget(
            name: "NoctweaveRelayServerTests",
            dependencies: [
                "NoctweaveRelayServer",
                "CSQLite",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOFoundationCompat", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio")
            ]
        )
    ]
)

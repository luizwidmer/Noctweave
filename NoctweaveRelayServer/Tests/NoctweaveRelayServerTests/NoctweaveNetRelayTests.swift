import Crypto
import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class NoctweaveNetRelayTests: XCTestCase {
    func testCurrentRelayTopologyContainsExactlyThreeRoles() {
        XCTAssertEqual(RelayKind.allCases, [.standard, .passthrough, .host])
        XCTAssertFalse(RelayKind.coordinator.isCurrentTopologyRole)
    }

    func testRoleCapabilitiesAdvertiseOnlyTheirSurface() {
        let standard = RelayCapabilityManifestV2.advertised(
            relayKind: .standard,
            attachmentsEnabled: false,
            hiddenRetrievalEnabled: false,
            onionEnabled: false,
            mixnetEnabled: false,
            opaqueRouteRuntimeEnabled: true,
            openDiscoveryEnabled: false,
            rendezvousTransportEnabled: false
        )
        XCTAssertFalse(standard.supports(module: "nw.net-passthrough", version: 1))
        XCTAssertFalse(standard.supports(module: "nw.net-host", version: 1))

        let standardHost = RelayCapabilityManifestV2.advertised(
            relayKind: .standard,
            netHostEnabled: true,
            attachmentsEnabled: false,
            hiddenRetrievalEnabled: false,
            onionEnabled: false,
            mixnetEnabled: false,
            opaqueRouteRuntimeEnabled: true,
            openDiscoveryEnabled: false,
            rendezvousTransportEnabled: false
        )
        XCTAssertTrue(standardHost.supports(module: "nw.opaque-route", version: 2))
        XCTAssertTrue(standardHost.supports(module: "nw.net-host", version: 1))
        XCTAssertFalse(standardHost.supports(module: "nw.net-passthrough", version: 1))

        let passthrough = RelayCapabilityManifestV2.advertised(
            relayKind: .passthrough,
            attachmentsEnabled: true,
            hiddenRetrievalEnabled: true,
            onionEnabled: true,
            mixnetEnabled: true,
            opaqueRouteRuntimeEnabled: true,
            openDiscoveryEnabled: true,
            rendezvousTransportEnabled: true
        )
        XCTAssertEqual(
            passthrough.modules.map(\.module),
            ["nw.core", "nw.net-passthrough"]
        )

        let host = RelayCapabilityManifestV2.advertised(
            relayKind: .host,
            attachmentsEnabled: true,
            hiddenRetrievalEnabled: true,
            onionEnabled: true,
            mixnetEnabled: true,
            opaqueRouteRuntimeEnabled: true,
            openDiscoveryEnabled: true,
            rendezvousTransportEnabled: true
        )
        XCTAssertEqual(host.modules.map(\.module), ["nw.core", "nw.net-host"])
    }

    func testRelayInfoAdvertisesCoLocatedAndDedicatedHostCapability() throws {
        let standard = RelayConfiguration(
            kind: .standard,
            netHostEnabled: true
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))
        XCTAssertTrue(
            try XCTUnwrap(standard.protocolCapabilities)
                .supports(module: "nw.net-host", version: 1)
        )

        let host = RelayConfiguration(kind: .host)
            .makeInfo(now: Date(timeIntervalSince1970: 1_000))
        XCTAssertTrue(
            try XCTUnwrap(host.protocolCapabilities)
                .supports(module: "nw.net-host", version: 1)
        )
    }

    func testServerConfigEnablesHostingForStandardAndDedicatedHostRelays() {
        let standard = ServerConfig.parse(
            arguments: [
                "--relay-kind", "standard",
                "--net-host-enabled", "true",
                "--noctweb-relay-suffix", ".atelier"
            ],
            environment: [:]
        )
        XCTAssertTrue(standard.netHostEnabled)
        XCTAssertEqual(standard.noctwebRelaySuffix, ".atelier")
        XCTAssertGreaterThanOrEqual(standard.maxMessageBytes ?? 0, 2 * 1_024 * 1_024)

        let host = ServerConfig.parse(
            arguments: ["--relay-kind", "host"],
            environment: [:]
        )
        XCTAssertTrue(host.netHostEnabled)
    }

    func testHostStorePersistsVerifiesAndCapabilityReleases() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            UUID().uuidString,
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let key = Curve25519.Signing.PrivateKey()
        let payload = Data("hosted capsule bytes".utf8)
        let releaseCapability = Data(repeating: 0x29, count: 32)
        let request = NoctweaveNetHostPutRequest(
            objectID: NoctweaveNetHostPutRequest.objectID(for: payload),
            payload: payload,
            ttlSeconds: 3_600,
            releaseCapabilityDigest: NoctweaveNetHostReleaseRequest.capabilityDigest(
                releaseCapability
            ),
            idempotencyKey: Data(repeating: 0x42, count: 32)
        )
        let now = Date(
            timeIntervalSince1970: floor(Date().timeIntervalSince1970)
        )
        let store = NoctweaveNetHostStore(
            directoryURL: root,
            signingPrivateKey: key,
            maximumObjects: 2,
            maximumTotalBytes: 4_096
        )
        try store.load()
        let receipt = try store.put(request, now: now)
        XCTAssertTrue(receipt.isSignatureValid)
        XCTAssertEqual(try store.fetch(.init(objectID: request.objectID), now: now)?.payload, payload)

        let restored = NoctweaveNetHostStore(
            directoryURL: root,
            signingPrivateKey: key,
            maximumObjects: 2,
            maximumTotalBytes: 4_096
        )
        try restored.load()
        XCTAssertTrue(
            try restored.presence(.init(objectID: request.objectID), now: now).present
        )
        XCTAssertThrowsError(
            try restored.release(
                .init(
                    objectID: request.objectID,
                    releaseCapability: Data(repeating: 0x30, count: 32)
                ),
                now: now
            )
        ) {
            XCTAssertEqual(
                $0 as? NoctweaveNetHostStoreError,
                .unauthorizedRelease
            )
        }
        XCTAssertTrue(
            try restored.release(
                .init(objectID: request.objectID, releaseCapability: releaseCapability),
                now: now
            ).released
        )
        XCTAssertFalse(
            try restored.presence(.init(objectID: request.objectID), now: now).present
        )
    }

    func testHostAndPassthroughWireBindingsRoundTripExactly() throws {
        let payload = Data("capsule".utf8)
        let host = RelayRequest.putNetHostObject(
            NoctweaveNetHostPutRequest(
                objectID: NoctweaveNetHostPutRequest.objectID(for: payload),
                payload: payload,
                ttlSeconds: nil,
                releaseCapabilityDigest: Data(repeating: 0x51, count: 32),
                idempotencyKey: Data(repeating: 0x52, count: 32)
            )
        )
        let encodedHost = try RelayCodec.encoder().encode(host)
        XCTAssertEqual(
            try RelayCodec.decodeWire(RelayRequest.self, from: encodedHost),
            host
        )
        XCTAssertTrue(requestRequiresConfidentialHTTPBridge(host))
        XCTAssertFalse(requestRequiresConfidentialHTTPBridge(
            .getNetHostObject(.init(objectID: NoctweaveNetHostPutRequest.objectID(for: payload)))
        ))

        let passthrough = RelayRequest.netPassthrough(
            NoctweaveNetPassthroughRequest(
                destination: RelayEndpoint(
                    host: "relay.example",
                    port: 443,
                    useTLS: true,
                    transport: .http
                ),
                payload: Data("{}".utf8)
            )
        )
        let encodedPassthrough = try RelayCodec.encoder().encode(passthrough)
        XCTAssertEqual(
            try RelayCodec.decodeWire(
                RelayRequest.self,
                from: encodedPassthrough
            ),
            passthrough
        )
        XCTAssertTrue(requestRequiresConfidentialHTTPBridge(passthrough))
    }
}

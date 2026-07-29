import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class NoctweaveNetRelayTests: XCTestCase {
    func testCurrentRelayTopologyContainsExactlyThreeRoles() {
        XCTAssertEqual(RelayKind.allCases, [.standard, .passthrough, .host])
        XCTAssertTrue(RelayKind.standard.isCurrentTopologyRole)
        XCTAssertTrue(RelayKind.passthrough.isCurrentTopologyRole)
        XCTAssertTrue(RelayKind.host.isCurrentTopologyRole)
        XCTAssertFalse(RelayKind.coordinator.isCurrentTopologyRole)
    }

    func testPrivateEndpointPolicyAcceptsLANAndInternalHostsOnly() {
        XCTAssertTrue(
            PublicRelayEndpointPolicy.permitsPrivate(
                RelayEndpoint(host: "192.168.1.20", port: 9339)
            )
        )
        XCTAssertTrue(
            PublicRelayEndpointPolicy.permitsPrivate(
                RelayEndpoint(
                    host: "host.docker.internal",
                    port: 9339
                )
            )
        )
        XCTAssertFalse(
            PublicRelayEndpointPolicy.permitsPrivate(
                RelayEndpoint(host: "8.8.8.8", port: 9339)
            )
        )
    }

    func testEmbeddedRelayRefusesOperationalNetRoles() {
        for kind in [RelayKind.passthrough, .host] {
            let relay = RelayServer(
                store: RelayStore(storeURL: nil),
                configuration: RelayConfiguration(kind: kind)
            )
            XCTAssertThrowsError(try relay.start(host: "127.0.0.1", port: 0))
        }
    }

    func testRoleCapabilitiesAreMutuallyExclusive() {
        let standard = RelayCapabilityManifestV2.advertised(
            relayKind: .standard,
            attachmentsEnabled: false,
            wakeEnabled: false,
            hiddenRetrievalEnabled: false,
            onionEnabled: false,
            mixnetEnabled: false
        )
        XCTAssertFalse(standard.supports(module: "nw.net-passthrough", version: 1))
        XCTAssertFalse(standard.supports(module: "nw.net-host", version: 1))

        let passthrough = RelayCapabilityManifestV2.advertised(
            relayKind: .passthrough,
            attachmentsEnabled: true,
            wakeEnabled: true,
            hiddenRetrievalEnabled: true,
            onionEnabled: true,
            mixnetEnabled: true
        )
        XCTAssertEqual(
            passthrough.modules.map(\.module),
            ["nw.core", "nw.net-passthrough"]
        )

        let host = RelayCapabilityManifestV2.advertised(
            relayKind: .host,
            attachmentsEnabled: true,
            wakeEnabled: true,
            hiddenRetrievalEnabled: true,
            onionEnabled: true,
            mixnetEnabled: true
        )
        XCTAssertEqual(host.modules.map(\.module), ["nw.core", "nw.net-host"])
    }

    func testStandardRelayAdvertisesHostingOnlyWhenEnabled() {
        let disabled = RelayConfiguration(
            kind: .standard,
            netHostEnabled: false
        )
        XCTAssertFalse(disabled.isNetHostEnabled)
        XCTAssertFalse(
            disabled.makeInfo().protocolCapabilities?.supports(
                module: "nw.net-host",
                version: 1
            ) ?? true
        )

        let enabled = RelayConfiguration(
            kind: .standard,
            netHostEnabled: true
        )
        XCTAssertTrue(enabled.isNetHostEnabled)
        XCTAssertTrue(
            enabled.makeInfo().protocolCapabilities?.supports(
                module: "nw.net-host",
                version: 1
            ) ?? false
        )
    }

    func testNativeHostStorePersistsAndReleasesBoundedObject() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "noctweave-native-host-\(UUID().uuidString)",
                isDirectory: true
            )
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let signingKey =
            RelayNoctwebHostStore.generateSigningPrivateKey()
        let payload = Data("native hosted capsule".utf8)
        let releaseCapability = Data(repeating: 0x7A, count: 32)
        let objectID =
            NoctweaveNetHostPutRequest.objectID(for: payload)
        let put = NoctweaveNetHostPutRequest(
            objectID: objectID,
            payload: payload,
            ttlSeconds: 3_600,
            releaseCapabilityDigest:
                NoctweaveNetHostReleaseRequest.capabilityDigest(
                    releaseCapability
                ),
            idempotencyKey: Data(repeating: 0x4D, count: 32)
        )

        let first = try RelayNoctwebHostStore(
            directoryURL: directory,
            signingPrivateKeyData: signingKey
        )
        try first.load()
        let receipt = try first.put(
            put,
            now: Date(timeIntervalSince1970: 1_800_000_000)
        )
        XCTAssertTrue(receipt.isSignatureValid)
        let suffix = NoctwebRelaySuffixV1(rawValue: ".native")!
        let binding = NoctweaveNetHostNameBindingRequestV1(
            relaySuffix: suffix,
            siteLabel: "capsule",
            objectID: objectID,
            publisherID:
                "nwpub1_\(String(repeating: "b", count: 64))",
            headID:
                "sha256:\(String(repeating: "c", count: 64))",
            revision: 1,
            previousObjectID: nil,
            idempotencyKey: Data(repeating: 0x2A, count: 32)
        )
        _ = try first.bindName(
            binding,
            now: Date(timeIntervalSince1970: 1_800_000_000)
        )
        XCTAssertEqual(
            try first.fetch(
                NoctweaveNetHostObjectRequest(objectID: objectID),
                now: Date(timeIntervalSince1970: 1_800_000_001)
            )?.payload,
            payload
        )

        let reloaded = try RelayNoctwebHostStore(
            directoryURL: directory,
            signingPrivateKeyData: signingKey
        )
        try reloaded.load()
        XCTAssertEqual(
            try reloaded.fetch(
                NoctweaveNetHostObjectRequest(objectID: objectID),
                now: Date(timeIntervalSince1970: 1_800_000_002)
            )?.payload,
            payload
        )
        let release = try reloaded.release(
            NoctweaveNetHostReleaseRequest(
                objectID: objectID,
                releaseCapability: releaseCapability
            ),
            now: Date(timeIntervalSince1970: 1_800_000_003)
        )
        XCTAssertTrue(release.released)
        XCTAssertNil(
            try reloaded.resolveName(
                NoctweaveNetHostNameRequestV1(
                    relaySuffix: suffix,
                    siteLabel: "capsule"
                ),
                now: Date(timeIntervalSince1970: 1_800_000_004)
            )
        )
        XCTAssertNil(
            try reloaded.fetch(
                NoctweaveNetHostObjectRequest(objectID: objectID),
                now: Date(timeIntervalSince1970: 1_800_000_004)
            )
        )
    }

    func testNativeHostStorePrunesExpiredNameBindings() throws {
        let store = try RelayNoctwebHostStore(
            directoryURL: nil,
            signingPrivateKeyData:
                RelayNoctwebHostStore.generateSigningPrivateKey()
        )
        try store.load()
        let payload = Data("short-lived capsule".utf8)
        let objectID =
            NoctweaveNetHostPutRequest.objectID(for: payload)
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        _ = try store.put(
            NoctweaveNetHostPutRequest(
                objectID: objectID,
                payload: payload,
                ttlSeconds:
                    NoctweaveNetLimits.minimumHostRetentionSeconds,
                releaseCapabilityDigest: Data(repeating: 0x1A, count: 32),
                idempotencyKey: Data(repeating: 0x1B, count: 32)
            ),
            now: start
        )
        let suffix = NoctwebRelaySuffixV1(rawValue: ".expiry")!
        _ = try store.bindName(
            NoctweaveNetHostNameBindingRequestV1(
                relaySuffix: suffix,
                siteLabel: "brief",
                objectID: objectID,
                publisherID:
                    "nwpub1_\(String(repeating: "d", count: 64))",
                headID:
                    "sha256:\(String(repeating: "e", count: 64))",
                revision: 1,
                previousObjectID: nil,
                idempotencyKey: Data(repeating: 0x1C, count: 32)
            ),
            now: start
        )

        XCTAssertNil(
            try store.resolveName(
                NoctweaveNetHostNameRequestV1(
                    relaySuffix: suffix,
                    siteLabel: "brief"
                ),
                now: start.addingTimeInterval(
                    TimeInterval(
                        NoctweaveNetLimits.minimumHostRetentionSeconds + 1
                    )
                )
            )
        )
    }

    func testHostRequestIsContentAddressedAndExactOnWire() throws {
        let payload = Data("hello noctweave net".utf8)
        let releaseCapability = Data(repeating: 0x31, count: 32)
        let request = NoctweaveNetHostPutRequest(
            objectID: NoctweaveNetHostPutRequest.objectID(for: payload),
            payload: payload,
            ttlSeconds: 3_600,
            releaseCapabilityDigest: NoctweaveNetHostReleaseRequest.capabilityDigest(
                releaseCapability
            ),
            idempotencyKey: Data(repeating: 0x44, count: 32)
        )
        XCTAssertTrue(request.isStructurallyValid)

        let relayRequest = RelayRequest.putNetHostObject(request)
        let encoded = try NoctweaveCoder.encode(relayRequest)
        XCTAssertEqual(try NoctweaveCoder.decode(RelayRequest.self, from: encoded), relayRequest)

        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertEqual(object["module"] as? String, "nw.net-host")
        XCTAssertEqual(object["method"] as? String, "put")
        var body = try XCTUnwrap(object["body"] as? [String: Any])
        body["legacy"] = true
        object["body"] = body
        let malformed = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try NoctweaveCoder.decode(RelayRequest.self, from: malformed))
    }

    func testHostingReceiptSignatureAndFetchBindingVerify() throws {
        let payload = Data("signed capsule".utf8)
        let key = Curve25519.Signing.PrivateKey()
        let storedAt = Date(timeIntervalSince1970: 1_700_000_000)
        let expiresAt = storedAt.addingTimeInterval(3_600)
        let unsigned = NoctweaveNetHostingReceipt(
            objectID: NoctweaveNetHostPutRequest.objectID(for: payload),
            byteCount: UInt64(payload.count),
            storedAt: storedAt,
            expiresAt: expiresAt,
            signingPublicKey: key.publicKey.rawRepresentation,
            signature: Data(repeating: 0, count: 64)
        )
        let receipt = NoctweaveNetHostingReceipt(
            objectID: unsigned.objectID,
            byteCount: unsigned.byteCount,
            storedAt: storedAt,
            expiresAt: expiresAt,
            signingPublicKey: key.publicKey.rawRepresentation,
            signature: try key.signature(for: unsigned.signingPayload)
        )
        XCTAssertTrue(receipt.isSignatureValid)
        XCTAssertTrue(
            NoctweaveNetHostFetchResponse(receipt: receipt, payload: payload)
                .isStructurallyValid
        )
    }

    func testPassthroughRequiresBoundedHTTPDestination() {
        let valid = NoctweaveNetPassthroughRequest(
            destination: RelayEndpoint(
                host: "relay.example",
                port: 443,
                useTLS: true,
                transport: .http
            ),
            payload: Data("{}".utf8)
        )
        XCTAssertTrue(valid.isStructurallyValid)

        let websocket = NoctweaveNetPassthroughRequest(
            destination: RelayEndpoint(
                host: "relay.example",
                port: 443,
                useTLS: true,
                transport: .websocket
            ),
            payload: Data("{}".utf8)
        )
        XCTAssertFalse(websocket.isStructurallyValid)
    }
}

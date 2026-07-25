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

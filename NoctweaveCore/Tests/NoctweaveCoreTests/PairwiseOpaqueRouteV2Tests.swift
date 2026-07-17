import Foundation
import XCTest
@testable import NoctweaveCore

final class PairwiseOpaqueRouteV2Tests: XCTestCase {
    private let origin = Date(timeIntervalSince1970: 1_800_000_000)

    func testPeerProjectionContainsOnlySendAndPayloadAuthority() throws {
        let fixture = try makeRouteFixture()
        let peerRoute = try fixture.local.peerSendRoute()
        let encoded = try NoctweaveCoder.encode(peerRoute, sortedKeys: true)
        let text = try XCTUnwrap(String(data: encoded, encoding: .utf8))

        XCTAssertTrue(text.contains("sendCapability"))
        XCTAssertTrue(text.contains("payloadKey"))
        for secret in [
            fixture.capabilities.readCredential.rawValue,
            fixture.capabilities.renewCapability.rawValue,
            fixture.capabilities.teardownCapability.rawValue,
        ] {
            XCTAssertFalse(text.contains(secret.base64EncodedString()))
        }
        XCTAssertEqual(String(describing: peerRoute), "PairwiseSendRouteV2(<redacted>)")
        XCTAssertTrue(Mirror(reflecting: peerRoute).children.isEmpty)
        XCTAssertEqual(String(describing: fixture.local), "LocalOpaqueReceiveRouteV2(<redacted>)")
        XCTAssertTrue(Mirror(reflecting: fixture.local).children.isEmpty)
    }

    func testIntroductionIsRendezvousBoundCurrentAndStrict() throws {
        let routeFixture = try makeRouteFixture()
        let identityFixture = try makeIdentityFixture()
        let rendezvousDigest = Data(repeating: 0xA7, count: 32)
        let introduction = try ContactIntroductionV2.create(
            identity: identityFixture.identity,
            identityGenerationID: identityFixture.generationID,
            endpointSetManifest: identityFixture.manifest,
            preferredEndpoint: identityFixture.certificate,
            receiveRoute: routeFixture.local.peerSendRoute(),
            rendezvousTranscriptDigest: rendezvousDigest,
            issuedAt: origin,
            expiresAt: origin.addingTimeInterval(300)
        )

        XCTAssertEqual(
            try introduction.verified(
                for: rendezvousDigest,
                at: origin.addingTimeInterval(1)
            ),
            introduction
        )
        XCTAssertThrowsError(try introduction.verified(
            for: Data(repeating: 0xA8, count: 32),
            at: origin.addingTimeInterval(1)
        )) { XCTAssertEqual($0 as? PairwiseOpaqueRouteV2Error, .wrongRendezvous) }
        XCTAssertThrowsError(try introduction.verified(
            for: rendezvousDigest,
            at: origin.addingTimeInterval(300)
        )) { XCTAssertEqual($0 as? PairwiseOpaqueRouteV2Error, .expiredIntroduction) }

        let encoded = try NoctweaveCoder.encode(introduction, sortedKeys: true)
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        var route = try XCTUnwrap(object["receiveRoute"] as? [String: Any])
        route["unknownAuthority"] = "forbidden"
        object["receiveRoute"] = route
        let unknownNestedField = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            ContactIntroductionV2.self,
            from: unknownNestedField
        ))
    }

    func testEveryIntroductionCanUseFreshUnlinkableRouteMaterial() throws {
        let first = try makeRouteFixture(marker: 0x31)
        let second = try makeRouteFixture(marker: 0x32)
        let firstProjection = try first.local.peerSendRoute()
        let secondProjection = try second.local.peerSendRoute()

        XCTAssertNotEqual(firstProjection.routeID, secondProjection.routeID)
        XCTAssertNotEqual(firstProjection.sendCapability, secondProjection.sendCapability)
        XCTAssertNotEqual(firstProjection.payloadKey, secondProjection.payloadKey)
    }

    private func makeRouteFixture(
        marker: UInt8 = 0x21
    ) throws -> (
        local: LocalOpaqueReceiveRouteV2,
        capabilities: OpaqueRouteClientCapabilityMaterialV2
    ) {
        let capabilities = try OpaqueRouteClientCapabilityMaterialV2()
        let lease = try OpaqueRouteLeaseV2(
            issuedAt: origin,
            expiresAt: origin.addingTimeInterval(3_600),
            policy: OpaqueRoutePolicyV2(
                paddingBucket: .bytes4096,
                retentionBucket: .sixHours,
                quotaBucket: .packets256
            )
        )
        let create = try capabilities.makeCreateRequest(
            lease: lease,
            idempotencyKey: .generate()
        )
        let route = try OpaqueReceiveRouteV2.creating(
            from: create,
            presentedRenewCapability: capabilities.renewCapability,
            existing: nil,
            confidentialTransport: true,
            receivedAt: origin
        )
        let payloadKey = OpaqueRoutePayloadKeyV2(
            rawValue: Data(repeating: marker, count: 32)
        )
        let local = try LocalOpaqueReceiveRouteV2(
            relay: RelayEndpoint(
                host: "relay.example",
                port: 443,
                useTLS: true,
                transport: .websocket
            ),
            route: route,
            clientCapabilities: capabilities,
            payloadKey: payloadKey
        )
        return (local, capabilities)
    }

    private func makeIdentityFixture() throws -> (
        identity: Identity,
        generationID: UUID,
        manifest: EndpointSetManifest,
        certificate: CertifiedGenerationEndpoint
    ) {
        let identity = try Identity.generate(displayName: "Ephemeral Alice")
        let generationID = UUID()
        let endpoint = try LocalEndpointState.generate(
            identityGenerationId: generationID,
            createdAt: origin
        )
        let manifest = try EndpointSetManifest.create(
            identityGenerationId: generationID,
            epoch: 0,
            endpoints: [endpoint.publicRecord(addedEpoch: 0)],
            identity: identity,
            issuedAt: origin
        )
        let certificate = try CertifiedGenerationEndpoint.create(
            identity: identity,
            endpoint: endpoint,
            manifest: manifest,
            issuedAt: origin
        )
        return (identity, generationID, manifest, certificate)
    }
}

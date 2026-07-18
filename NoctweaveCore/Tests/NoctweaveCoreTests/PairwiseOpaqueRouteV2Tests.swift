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
        XCTAssertEqual(String(describing: peerRoute), "OpaqueSendRouteV2(<redacted>)")
        XCTAssertTrue(Mirror(reflecting: peerRoute).children.isEmpty)
        XCTAssertEqual(String(describing: fixture.local), "LocalOpaqueReceiveRouteV2(<redacted>)")
        XCTAssertTrue(Mirror(reflecting: fixture.local).children.isEmpty)
    }

    func testLocalRoutePersistsBoundedRouteReassemblyState() throws {
        let fixture = try makeRouteFixture()
        var local = fixture.local
        XCTAssertEqual(local.reassembler, .empty)
        XCTAssertEqual(
            OpaqueRoutePacketReassemblerV2.defaultMaximumBufferedBytes,
            LocalOpaqueReceiveRouteV2.maximumPersistedReassemblerBufferedBytes
        )
        XCTAssertLessThanOrEqual(
            LocalOpaqueReceiveRouteV2.maximumPersistedReassemblerBufferedBytes
                * PairwiseRelationshipV2.maximumReceiveRoutes * 2,
            ClientStateStore.maximumPlaintextBytes
        )

        let sendRoute = try local.peerSendRoute()
        let capacity = NoctweaveOpaqueRoutePacketsV2.maximumFragmentPayloadBytes(
            for: sendRoute.policy.paddingBucket
        )
        let payload = Data(repeating: 0x91, count: capacity + 23)
        let bundle = try OpaqueRouteSealedBundleV2.seal(
            payload,
            to: sendRoute,
            authorizedAt: origin.addingTimeInterval(1)
        )
        let payloadKey = local.payloadKey
        let firstResult = try local.updateReassembler {
            try $0.consume(
                bundle.packets[0],
                payloadKey: payloadKey,
                routeRevision: sendRoute.routeRevision
            )
        }
        XCTAssertEqual(firstResult, .accepted)
        XCTAssertEqual(local.reassembler.pendingBundleCount, 1)
        XCTAssertTrue(local.isStructurallyValid)

        let encoded = try NoctweaveCoder.encode(local, sortedKeys: true)
        var restored = try NoctweaveCoder.decode(LocalOpaqueReceiveRouteV2.self, from: encoded)
        XCTAssertEqual(restored, local)
        XCTAssertEqual(restored.reassembler, local.reassembler)
        let resumed = try restored.updateReassembler {
            try $0.consume(
                bundle.packets[1],
                payloadKey: payloadKey,
                routeRevision: sendRoute.routeRevision
            )
        }
        guard case .complete(let completed) = resumed else {
            return XCTFail("Expected local route state to resume its persisted bundle")
        }
        XCTAssertEqual(completed.payload, payload)

        var missingState = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        missingState.removeValue(forKey: "reassembler")
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            LocalOpaqueReceiveRouteV2.self,
            from: JSONSerialization.data(withJSONObject: missingState)
        ))

        let oversized = try OpaqueRoutePacketReassemblerV2(
            maximumBufferedBytes:
                LocalOpaqueReceiveRouteV2.maximumPersistedReassemblerBufferedBytes + 1
        )
        XCTAssertThrowsError(try local.replaceReassembler(with: oversized)) {
            XCTAssertEqual($0 as? PairwiseOpaqueRouteV2Error, .invalidRoute)
        }

        let otherFixture = try makeRouteFixture(marker: 0x92)
        let otherSendRoute = try otherFixture.local.peerSendRoute()
        let otherBundle = try OpaqueRouteSealedBundleV2.seal(
            Data(repeating: 0x92, count: capacity + 1),
            to: otherSendRoute,
            authorizedAt: origin.addingTimeInterval(1)
        )
        var otherReassembler = OpaqueRoutePacketReassemblerV2.empty
        _ = try otherReassembler.consume(
            otherBundle.packets[0],
            payloadKey: otherFixture.local.payloadKey,
            routeRevision: otherSendRoute.routeRevision
        )
        XCTAssertThrowsError(try local.replaceReassembler(with: otherReassembler)) {
            XCTAssertEqual($0 as? PairwiseOpaqueRouteV2Error, .invalidRoute)
        }
    }

    func testIntroductionIsRendezvousBoundCurrentAndStrict() throws {
        let routeFixture = try makeRouteFixture()
        let pairwiseIdentity = try LocalPairwiseIdentityV2.generate(
            relationshipPseudonym: "Ephemeral Alice",
            createdAt: origin
        )
        let rendezvousDigest = Data(repeating: 0xA7, count: 32)
        let relationshipID = try PairwiseRelationshipIDV2.derive(from: rendezvousDigest)
        let endpointHandle = RelationshipEndpointHandle.generate(
            relationshipId: relationshipID
        )
        let routeSet = try pairwiseIdentity.makeInitialRouteSet(
            relationshipID: relationshipID,
            ownerEndpointHandle: endpointHandle,
            receiveRoute: routeFixture.local.peerSendRoute(),
            issuedAt: origin
        )
        let introduction = try pairwiseIdentity.makeIntroduction(
            receiveRoutes: routeSet,
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

        let peer = try PeerPairwiseIdentityV2(
            introduction: introduction,
            rendezvousTranscriptDigest: rendezvousDigest,
            acceptedAt: origin.addingTimeInterval(1)
        )
        XCTAssertEqual(peer.relationshipID, relationshipID)
        XCTAssertEqual(peer.sendRoutes, routeSet)
        XCTAssertTrue(peer.isStructurallyValid)

        var peerObject = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: NoctweaveCoder.encode(peer, sortedKeys: true)
            ) as? [String: Any]
        )
        peerObject["legacyFingerprint"] = "forbidden"
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            PeerPairwiseIdentityV2.self,
            from: JSONSerialization.data(withJSONObject: peerObject)
        ))

        let encoded = try NoctweaveCoder.encode(introduction, sortedKeys: true)
        let encodedText = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        XCTAssertTrue(encodedText.contains("Ephemeral Alice"))
        XCTAssertFalse(encodedText.contains("Private local persona name that must never leave"))
        for forbiddenField in [
            "displayName",
            "relationshipGenerationID",
            "endpointSetCheckpoint",
            "preferredEndpoint",
            "manifestEpoch",
            "allowContinuity",
        ] {
            XCTAssertFalse(encodedText.contains(forbiddenField))
        }
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        var routes = try XCTUnwrap(object["receiveRoutes"] as? [String: Any])
        var routeList = try XCTUnwrap(routes["routes"] as? [[String: Any]])
        var route = try XCTUnwrap(routeList.first)
        route["unknownAuthority"] = "forbidden"
        routeList[0] = route
        routes["routes"] = routeList
        object["receiveRoutes"] = routes
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

    func testPairwiseIdentityKeysAreNeverReusedAcrossContacts() throws {
        let first = try LocalPairwiseIdentityV2.generate(
            relationshipPseudonym: "Same local alias",
            createdAt: origin
        )
        let second = try LocalPairwiseIdentityV2.generate(
            relationshipPseudonym: "Same local alias",
            createdAt: origin
        )

        XCTAssertNotEqual(
            first.relationshipAuthority.signingKey.publicKeyData,
            second.relationshipAuthority.signingKey.publicKeyData
        )
        XCTAssertNotEqual(
            first.localEndpoint.signingKey.publicKeyData,
            second.localEndpoint.signingKey.publicKeyData
        )
        XCTAssertEqual(String(describing: first), "LocalPairwiseIdentityV2(<redacted>)")
        XCTAssertTrue(Mirror(reflecting: first).children.isEmpty)
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

}

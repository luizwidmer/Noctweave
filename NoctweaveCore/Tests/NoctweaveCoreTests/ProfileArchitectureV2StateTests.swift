import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class ProfileArchitectureV2StateTests: XCTestCase {
    func testUnsignedLegacySelfSyncStateIsRejectedByCleanBaseline() throws {
        let generationId = UUID()
        let legacy = Data("""
        {
          "version": 2,
          "identityGenerationId": "\(generationId.uuidString)",
          "stream": {"rawValue": "\(Data(repeating: 1, count: 32).base64EncodedString())"},
          "encryptionKeyData": "\(Data(repeating: 2, count: 32).base64EncodedString())",
          "nextSourceSequence": 7,
          "appliedCursors": []
        }
        """.utf8)

        XCTAssertThrowsError(try NoctweaveCoder.decode(SelfSyncLocalStateV2.self, from: legacy))
    }

    func testInboundReplayReceiptWithoutSourceScopeIsRejected() throws {
        let receipt = InboundEnvelopeReceiptV2(
            sourceScopeId: UUID(),
            logicalEventId: UUID(),
            envelopeId: UUID(),
            envelopeDigest: Data(repeating: 0x11, count: 32)
        )
        let encoded = try NoctweaveCoder.encode(receipt, sortedKeys: true)
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        object.removeValue(forKey: "sourceScopeId")
        let incomplete = try JSONSerialization.data(withJSONObject: object)

        XCTAssertThrowsError(
            try NoctweaveCoder.decode(InboundEnvelopeReceiptV2.self, from: incomplete)
        )
    }

    func testInboundReplayReceiptsScopeLogicalIdentifiersToRelationships() throws {
        let identity = try Identity.generate(displayName: "Local")
        var profile = try makeCurrentIdentityProfile(
            identity: identity,
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity)
        )
        let sharedLogicalId = UUID()
        let sharedEnvelopeId = UUID()
        let firstScope = UUID()
        let secondScope = UUID()
        let firstReceipt = InboundEnvelopeReceiptV2(
            sourceScopeId: firstScope,
            logicalEventId: sharedLogicalId,
            envelopeId: sharedEnvelopeId,
            envelopeDigest: Data(repeating: 0x11, count: 32)
        )
        profile.inboundEnvelopeReceiptsV2 = [firstReceipt]
        XCTAssertTrue(profile.isArchitectureV2Ready)
        XCTAssertFalse(firstReceipt.isReplayCandidate(
            sourceScopeId: secondScope,
            logicalEventId: sharedLogicalId,
            envelopeId: UUID()
        ))
        XCTAssertTrue(firstReceipt.isExactReplay(
            sourceScopeId: firstScope,
            logicalEventId: sharedLogicalId,
            envelopeId: sharedEnvelopeId,
            envelopeDigest: firstReceipt.envelopeDigest
        ))
        XCTAssertFalse(firstReceipt.isExactReplay(
            sourceScopeId: secondScope,
            logicalEventId: sharedLogicalId,
            envelopeId: sharedEnvelopeId,
            envelopeDigest: firstReceipt.envelopeDigest
        ))

        profile.inboundEnvelopeReceiptsV2.append(
            InboundEnvelopeReceiptV2(
                sourceScopeId: secondScope,
                logicalEventId: sharedLogicalId,
                envelopeId: UUID(),
                envelopeDigest: Data(repeating: 0x22, count: 32)
            )
        )
        XCTAssertTrue(profile.isArchitectureV2Ready)

        profile.inboundEnvelopeReceiptsV2.append(
            InboundEnvelopeReceiptV2(
                sourceScopeId: UUID(),
                logicalEventId: UUID(),
                envelopeId: sharedEnvelopeId,
                envelopeDigest: Data(repeating: 0x33, count: 32)
            )
        )
        XCTAssertFalse(profile.isArchitectureV2Ready)
    }

    func testVerifiedRouteEventAndSelfSyncProgressRoundTripInProfile() throws {
        let identity = try Identity.generate(displayName: "Local")
        let peer = try Identity.generate(displayName: "Peer")
        let contact = Contact(
            displayName: peer.displayName,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "relay.example", port: 443, useTLS: true),
            signingPublicKey: peer.signingKey.publicKeyData,
            agreementPublicKey: peer.agreementKey.publicKeyData
        )
        var profile = try makeCurrentIdentityProfile(
            identity: identity,
            relay: RelayEndpoint(host: "relay.example", port: 443, useTLS: true),
            contacts: [contact],
            prekeys: try PrekeyState.generate(identity: identity)
        )
        var endpoint = try XCTUnwrap(profile.localEndpoint)
        let relationshipId = UUID()
        let endpointHandle = RelationshipEndpointHandle.generate(
            identityGenerationId: try XCTUnwrap(profile.identityGenerationId),
            endpointId: endpoint.id,
            relationshipId: relationshipId
        )
        endpoint.relationshipHandles[relationshipId] = endpointHandle
        profile.localEndpoint = endpoint
        var relationship = RelationshipStateV2(
            id: relationshipId,
            contactId: contact.id,
            localEndpointHandle: endpointHandle
        )
        XCTAssertTrue(relationship.includeConversationIds(["conversation-v2"]))
        let now = Date(timeIntervalSince1970: 2_000)

        let content = try XCTUnwrap(EncodedContent.text("hello"))
        let event = ConversationEvent(
            conversationId: "conversation-v2",
            authorEndpointHandle: relationship.localEndpointHandle,
            createdAt: now,
            kind: .application,
            content: content
        )
        XCTAssertTrue(relationship.appendEvent(event))

        let routeCapabilities = try OpaqueRouteClientCapabilityMaterialV2()
        let routeLease = try OpaqueRouteLeaseV2(
            issuedAt: now,
            expiresAt: now.addingTimeInterval(3_600),
            policy: OpaqueRoutePolicyV2(
                paddingBucket: .bytes4096,
                retentionBucket: .sixHours,
                quotaBucket: .packets256
            )
        )
        let routeCreate = try routeCapabilities.makeCreateRequest(
            lease: routeLease,
            idempotencyKey: .generate()
        )
        let relayRoute = try OpaqueReceiveRouteV2.creating(
            from: routeCreate,
            presentedRenewCapability: routeCapabilities.renewCapability,
            existing: nil,
            confidentialTransport: true,
            receivedAt: now
        )
        let localRoute = try LocalOpaqueReceiveRouteV2(
            relay: RelayEndpoint(
                host: "relay.example",
                port: 443,
                useTLS: true,
                transport: .websocket
            ),
            route: relayRoute,
            clientCapabilities: routeCapabilities,
            payloadKey: .generate()
        )
        let routeSet = try PairwiseRouteSetV2.create(
            relationshipID: relationship.id,
            ownerEndpointHandle: relationship.localEndpointHandle,
            activeRoutes: [try localRoute.peerSendRoute()],
            issuedAt: now,
            signingKey: endpoint.signingKey,
        )
        XCTAssertTrue(
            relationship.upsertVerifiedRouteSet(
                routeSet,
                ownerSigningPublicKey: endpoint.signingKey.publicKeyData
            )
        )
        profile.relationshipsV2 = [relationship]

        var selfSync = try XCTUnwrap(profile.selfSyncV2)
        let manifest = try XCTUnwrap(profile.endpointSetManifest)
        let selfSyncCreatedAt = manifest.issuedAt.addingTimeInterval(1)
        let record = try selfSync.sealEvent(
            sourceEndpointId: endpoint.id,
            manifestEpoch: manifest.epoch,
            payload: .conversationEvent(event),
            sourceSigningKey: endpoint.signingKey,
            createdAt: selfSyncCreatedAt
        )
        let opened = try selfSync.openAndAdvance(
            record,
            manifest: manifest,
            identityPublicKey: profile.identity.signingKey.publicKeyData
        )
        guard case .conversationEvent(let openedEvent) = opened.payload else {
            return XCTFail("Expected a self-sync event")
        }
        XCTAssertEqual(openedEvent, event)
        XCTAssertEqual(opened.sourceResult, .applied)
        XCTAssertEqual(selfSync.nextSourceSequence, 2)
        XCTAssertEqual(selfSync.appliedSourceChains.first?.throughSequence, 1)
        profile.selfSyncV2 = selfSync

        let decoded = try NoctweaveCoder.decode(
            IdentityProfile.self,
            from: NoctweaveCoder.encode(profile)
        )
        XCTAssertTrue(decoded.isArchitectureV2Ready)
        XCTAssertEqual(decoded.relationshipsV2.first?.events, [event])
        XCTAssertEqual(decoded.relationshipsV2.first?.routeSets, [routeSet])
        XCTAssertEqual(decoded.selfSyncV2?.nextSourceSequence, 2)
    }
}

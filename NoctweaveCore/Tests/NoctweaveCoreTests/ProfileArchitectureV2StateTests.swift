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

    func testLegacyInboundReplayReceiptDecodesAsEnvelopeOnlyScope() throws {
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
        let legacy = try JSONSerialization.data(withJSONObject: object)
        let decoded = try NoctweaveCoder.decode(
            InboundEnvelopeReceiptV2.self,
            from: legacy
        )

        XCTAssertEqual(
            decoded.sourceScopeId,
            InboundEnvelopeReceiptV2.legacyUnscopedSourceId
        )
        XCTAssertTrue(decoded.isStructurallyValid)
    }

    func testInboundReplayReceiptsScopeLogicalIdentifiersToRelationships() throws {
        let identity = try Identity.generate(displayName: "Local")
        var profile = IdentityProfile(
            identity: identity,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            prekeys: try PrekeyState.generate(identity: identity)
        )
        _ = try profile.migrateToArchitectureV2()
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

    func testLegacyContactBackfillPersistsRelationshipWithoutFabricatingRoute() throws {
        let identity = try Identity.generate(displayName: "Local")
        let peer = try Identity.generate(displayName: "Peer")
        let contact = Contact(
            displayName: peer.displayName,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            signingPublicKey: peer.signingKey.publicKeyData,
            agreementPublicKey: peer.agreementKey.publicKeyData
        )
        var profile = IdentityProfile(
            identity: identity,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            contacts: [contact],
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: Date(timeIntervalSince1970: 1_000)
        )

        XCTAssertTrue(try profile.migrateToArchitectureV2())
        XCTAssertTrue(profile.isArchitectureV2Ready)
        let relationship = try XCTUnwrap(profile.relationshipsV2.first)
        let installation = try XCTUnwrap(profile.localInstallation)
        XCTAssertEqual(relationship.contactId, contact.id)
        XCTAssertEqual(
            installation.relationshipHandles[relationship.id],
            relationship.localInstallationHandle
        )
        XCTAssertTrue(relationship.routeSets.isEmpty)
        XCTAssertTrue(relationship.events.isEmpty)
        XCTAssertTrue(try XCTUnwrap(profile.selfSyncV2).isStructurallyValid)

        let decoded = try NoctweaveCoder.decode(
            IdentityProfile.self,
            from: NoctweaveCoder.encode(profile)
        )
        XCTAssertTrue(decoded.isArchitectureV2Ready)
        XCTAssertEqual(decoded.relationshipsV2.first?.id, relationship.id)
        var idempotent = decoded
        XCTAssertFalse(try idempotent.migrateToArchitectureV2())
        XCTAssertEqual(idempotent.relationshipsV2.first?.id, relationship.id)
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
        var profile = IdentityProfile(
            identity: identity,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "relay.example", port: 443, useTLS: true),
            contacts: [contact],
            prekeys: try PrekeyState.generate(identity: identity)
        )
        _ = try profile.migrateToArchitectureV2()
        let installation = try XCTUnwrap(profile.localInstallation)
        var relationship = try XCTUnwrap(profile.relationshipsV2.first)
        XCTAssertTrue(relationship.includeConversationIds(["conversation-v2"]))
        let now = Date(timeIntervalSince1970: 2_000)

        let content = try XCTUnwrap(EncodedContent.text("hello"))
        let event = ConversationEvent(
            conversationId: "conversation-v2",
            authorInstallationHandle: relationship.localInstallationHandle,
            createdAt: now,
            kind: .application,
            content: content
        )
        XCTAssertTrue(relationship.appendEvent(event))

        let route = RelationshipRouteV2.active(
            id: .generate(
                relationshipId: relationship.id,
                installationHandle: relationship.localInstallationHandle
            ),
            installationHandle: relationship.localInstallationHandle,
            relay: profile.relay,
            inboxCapability: .generate(),
            at: now
        )
        let routeSet = try RelationshipRouteSetV2.createInitial(
            relationshipId: relationship.id,
            ownerInstallationHandle: relationship.localInstallationHandle,
            route: route,
            signingKey: installation.signingKey,
            issuedAt: now
        )
        XCTAssertTrue(
            relationship.upsertVerifiedRouteSet(
                routeSet,
                ownerSigningPublicKey: installation.signingKey.publicKeyData
            )
        )
        profile.relationshipsV2 = [relationship]

        var selfSync = try XCTUnwrap(profile.selfSyncV2)
        let manifest = try XCTUnwrap(profile.installationManifest)
        let selfSyncCreatedAt = manifest.issuedAt.addingTimeInterval(1)
        let record = try selfSync.sealEvent(
            sourceEndpointId: installation.id,
            manifestEpoch: manifest.epoch,
            payload: .conversationEvent(event),
            sourceSigningKey: installation.signingKey,
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

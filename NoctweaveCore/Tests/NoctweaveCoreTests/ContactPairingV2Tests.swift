import Foundation
import XCTest
@testable import NoctweaveCore

final class ContactPairingV2Tests: XCTestCase {
    private let origin = Date(timeIntervalSince1970: 1_900_000_000)

    func testInvitationContainsOnlyOneUseRendezvousMaterial() throws {
        let offer = try ContactPairingHandshakeV2.makeOffer(
            createdAt: origin,
            expiresAt: origin.addingTimeInterval(300)
        )
        let encoded = try NoctweaveCoder.encode(offer.invitation, sortedKeys: true)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )

        XCTAssertEqual(Set(object.keys), Set(["version", "offer", "redemptionSecret"]))
        XCTAssertEqual(offer.invitation.offer.purpose, .contactPairing)
        let text = try XCTUnwrap(String(data: encoded, encoding: .utf8)).lowercased()
        for forbidden in [
            "displayname",
            "relationshipid",
            "generationid",
            "endpointid",
            "routeid",
            "relayendpoint",
            "inbox",
            "account",
            "profile",
            "signingpublickey",
        ] {
            XCTAssertFalse(text.contains(forbidden), "Invitation leaked forbidden field: \(forbidden)")
        }

        XCTAssertEqual(
            try ContactPairingInvitationV2.decode(offer.invitation.encoded()),
            offer.invitation
        )
    }

    func testHandshakeCreatesMutuallyBoundFreshPairwiseRelationships() throws {
        var fixture = try makeHandshakeFixture()
        let result = try ContactPairingHandshakeV2.establish(
            pendingOffer: &fixture.pending,
            invitation: fixture.invitation,
            offerer: fixture.offerer,
            responder: fixture.responder,
            ledger: &fixture.ledger,
            at: origin.addingTimeInterval(1)
        )

        XCTAssertEqual(result.offererRelationship.id, result.relationshipID)
        XCTAssertEqual(result.responderRelationship.id, result.relationshipID)
        XCTAssertEqual(
            result.offererRelationship.peerIdentity.signingPublicKey,
            fixture.responder.localIdentity.relationshipAuthority.signingKey.publicKeyData
        )
        XCTAssertEqual(
            result.responderRelationship.peerIdentity.signingPublicKey,
            fixture.offerer.localIdentity.relationshipAuthority.signingKey.publicKeyData
        )
        XCTAssertNotEqual(
            result.offererRelationship.localIdentity.relationshipAuthority.signingKey.publicKeyData,
            result.responderRelationship.localIdentity.relationshipAuthority.signingKey.publicKeyData
        )
        XCTAssertNotEqual(
            result.offererRelationship.localReceiveRoutes[0].route.routeID,
            result.responderRelationship.localReceiveRoutes[0].route.routeID
        )
        XCTAssertEqual(result.offererRelationship.continuityPolicy, .disabled)
        XCTAssertEqual(result.offererRelationship.localPolicy.consent, .accepted)
        XCTAssertFalse(result.offererRelationship.continuityPolicy.allowsSending)
        XCTAssertFalse(result.offererRelationship.continuityPolicy.allowsReceiving)
        XCTAssertTrue(fixture.pending.isRedeemed)
        XCTAssertEqual(fixture.ledger.redemptionCount, 1)
    }

    func testContinuityConsentIsLocalAndRelationshipScoped() throws {
        var fixture = try makeHandshakeFixture()
        let established = try ContactPairingHandshakeV2.establish(
            pendingOffer: &fixture.pending,
            invitation: fixture.invitation,
            offerer: fixture.offerer,
            responder: fixture.responder,
            ledger: &fixture.ledger,
            at: origin.addingTimeInterval(1)
        )
        var relationship = established.offererRelationship
        relationship.continuityPolicy = .sendOnly

        XCTAssertTrue(relationship.continuityPolicy.allowsSending)
        XCTAssertFalse(relationship.continuityPolicy.allowsReceiving)
        let encoded = try NoctweaveCoder.encode(relationship, sortedKeys: true)
        let text = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        XCTAssertTrue(text.contains("continuityPolicy\":\"sendOnly\""))
        XCTAssertEqual(
            try NoctweaveCoder.decode(PairwiseRelationshipV2.self, from: encoded),
            relationship
        )
    }

    func testMessageRequestMuteReceiptAndBlockPolicyIsStrictlyLocal() throws {
        var fixture = try makeHandshakeFixture()
        let established = try ContactPairingHandshakeV2.establish(
            pendingOffer: &fixture.pending,
            invitation: fixture.invitation,
            offerer: fixture.offerer,
            responder: fixture.responder,
            ledger: &fixture.ledger,
            at: origin.addingTimeInterval(1)
        )
        var relationship = established.offererRelationship
        relationship.localPolicy = RelationshipLocalPolicyV2(
            consent: .pendingRequest,
            mutedUntil: origin.addingTimeInterval(600),
            deliveryReceiptsEnabled: false,
            readReceiptsEnabled: false
        )

        XCTAssertFalse(relationship.localPolicy.allowsUserSending)
        XCTAssertTrue(relationship.localPolicy.acceptsInboundEvents)
        XCTAssertTrue(relationship.localPolicy.isMuted(at: origin))

        let encoded = try NoctweaveCoder.encode(relationship, sortedKeys: true)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertNotNil(object["localPolicy"])
        XCTAssertNil(object["blockList"])
        XCTAssertNil(object["accountID"])
        XCTAssertEqual(
            try NoctweaveCoder.decode(PairwiseRelationshipV2.self, from: encoded),
            relationship
        )

        var policyObject = try XCTUnwrap(object["localPolicy"] as? [String: Any])
        policyObject["legacyConsent"] = true
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            RelationshipLocalPolicyV2.self,
            from: JSONSerialization.data(withJSONObject: policyObject)
        ))

        relationship.localPolicy.consent = .blocked
        relationship.localReceiveRoutes.removeAll()
        XCTAssertFalse(relationship.localPolicy.acceptsInboundEvents)
        XCTAssertTrue(relationship.isStructurallyValid)
    }

    func testPeerStateNeverReceivesLocalReadRenewOrTeardownAuthority() throws {
        var fixture = try makeHandshakeFixture()
        let result = try ContactPairingHandshakeV2.establish(
            pendingOffer: &fixture.pending,
            invitation: fixture.invitation,
            offerer: fixture.offerer,
            responder: fixture.responder,
            ledger: &fixture.ledger,
            at: origin.addingTimeInterval(1)
        )
        let encodedForPeer = try NoctweaveCoder.encode(
            result.offererRelationship.peerIdentity,
            sortedKeys: true
        )
        let text = try XCTUnwrap(String(data: encodedForPeer, encoding: .utf8))
        let responderSecrets = fixture.responder.localReceiveRoute.clientCapabilities

        XCTAssertFalse(text.contains(
            fixture.responder.localIdentity.relationshipAuthority.signingKey.privateKeyData
                .base64EncodedString()
        ))
        XCTAssertFalse(text.contains(
            fixture.responder.localIdentity.relationshipAuthority.agreementKey.privateKeyData
                .base64EncodedString()
        ))
        XCTAssertFalse(text.contains(responderSecrets.readCredential.rawValue.base64EncodedString()))
        XCTAssertFalse(text.contains(responderSecrets.renewCapability.rawValue.base64EncodedString()))
        XCTAssertFalse(text.contains(responderSecrets.teardownCapability.rawValue.base64EncodedString()))
        XCTAssertEqual(
            result.offererRelationship.peerIdentity.sendRoutes.routes.first?.sendCapability,
            responderSecrets.sendCapability
        )
    }

    func testInvitationCanBeRedeemedOnlyOnce() throws {
        var fixture = try makeHandshakeFixture()
        _ = try ContactPairingHandshakeV2.establish(
            pendingOffer: &fixture.pending,
            invitation: fixture.invitation,
            offerer: fixture.offerer,
            responder: fixture.responder,
            ledger: &fixture.ledger,
            at: origin.addingTimeInterval(1)
        )

        XCTAssertThrowsError(try ContactPairingHandshakeV2.establish(
            pendingOffer: &fixture.pending,
            invitation: fixture.invitation,
            offerer: fixture.offerer,
            responder: fixture.responder,
            ledger: &fixture.ledger,
            at: origin.addingTimeInterval(2)
        )) { error in
            XCTAssertEqual(error as? RendezvousV2Error, .alreadyRedeemed)
        }
        XCTAssertEqual(fixture.ledger.redemptionCount, 1)
    }

    func testRelationshipFanoutPersistsExactRetryArtifacts() throws {
        var fixture = try makeHandshakeFixture()
        let established = try ContactPairingHandshakeV2.establish(
            pendingOffer: &fixture.pending,
            invitation: fixture.invitation,
            offerer: fixture.offerer,
            responder: fixture.responder,
            ledger: &fixture.ledger,
            at: origin.addingTimeInterval(1)
        )
        var relationship = established.offererRelationship
        let logicalEventID = UUID()
        let event = ConversationEvent(
            id: logicalEventID,
            clientTransactionId: UUID(),
            conversationId: relationship.conversationID,
            authorEndpointHandle: relationship.localEndpointHandle,
            createdAt: origin.addingTimeInterval(2),
            kind: .application,
            content: try XCTUnwrap(EncodedContent.text(String(repeating: "z", count: 1_000)))
        )
        XCTAssertTrue(try relationship.appendEvent(event))
        XCTAssertFalse(try relationship.appendEvent(event))
        XCTAssertEqual(relationship.events, [event])
        let payload = try NoctweaveCoder.encode(event, sortedKeys: true)
        let queued = try relationship.enqueue(
            logicalEventID: logicalEventID,
            payload: payload,
            at: origin.addingTimeInterval(2)
        )

        XCTAssertEqual(queued.count, 1)
        XCTAssertEqual(queued[0].logicalEventID, logicalEventID)
        XCTAssertEqual(relationship.pendingDeliveries, queued)
        let originalPackets = relationship.pendingDeliveries[0].packets
        relationship.pendingDeliveries[0].attemptCount += 1
        relationship.pendingDeliveries[0].lastAttemptAt = origin.addingTimeInterval(3)
        XCTAssertEqual(relationship.pendingDeliveries[0].packets, originalPackets)

        let roundTrip = try NoctweaveCoder.decode(
            PairwiseRelationshipV2.self,
            from: NoctweaveCoder.encode(relationship, sortedKeys: true)
        )
        XCTAssertEqual(roundTrip, relationship)
    }

    func testCurrentPairingStateRejectsUnknownFields() throws {
        var fixture = try makeHandshakeFixture()
        let established = try ContactPairingHandshakeV2.establish(
            pendingOffer: &fixture.pending,
            invitation: fixture.invitation,
            offerer: fixture.offerer,
            responder: fixture.responder,
            ledger: &fixture.ledger,
            at: origin.addingTimeInterval(1)
        )

        try assertUnknownFieldRejected(offer: fixture.invitation)
        try assertUnknownFieldRejected(participant: fixture.offerer)
        try assertUnknownFieldRejected(relationship: established.offererRelationship)
    }

    func testSeparatePairingsNeverReuseIdentityOrRouteMaterial() throws {
        var first = try makeHandshakeFixture()
        let firstResult = try ContactPairingHandshakeV2.establish(
            pendingOffer: &first.pending,
            invitation: first.invitation,
            offerer: first.offerer,
            responder: first.responder,
            ledger: &first.ledger,
            at: origin.addingTimeInterval(1)
        )
        var second = try makeHandshakeFixture(offset: 20)
        let secondResult = try ContactPairingHandshakeV2.establish(
            pendingOffer: &second.pending,
            invitation: second.invitation,
            offerer: second.offerer,
            responder: second.responder,
            ledger: &second.ledger,
            at: origin.addingTimeInterval(21)
        )

        XCTAssertNotEqual(firstResult.relationshipID, secondResult.relationshipID)
        XCTAssertNotEqual(
            firstResult.offererRelationship.localIdentity.relationshipAuthority.signingKey.publicKeyData,
            secondResult.offererRelationship.localIdentity.relationshipAuthority.signingKey.publicKeyData
        )
        XCTAssertNotEqual(
            firstResult.offererRelationship.localReceiveRoutes[0].route.routeID,
            secondResult.offererRelationship.localReceiveRoutes[0].route.routeID
        )
    }

    func testPersistedPersonasRejectReusedRelationshipAuthorityEndpointAndRoute() throws {
        var first = try makeHandshakeFixture()
        let firstResult = try ContactPairingHandshakeV2.establish(
            pendingOffer: &first.pending,
            invitation: first.invitation,
            offerer: first.offerer,
            responder: first.responder,
            ledger: &first.ledger,
            at: origin.addingTimeInterval(1)
        )
        var second = try makeHandshakeFixture(offset: 20)
        let reusedResult = try ContactPairingHandshakeV2.establish(
            pendingOffer: &second.pending,
            invitation: second.invitation,
            offerer: first.offerer,
            responder: second.responder,
            ledger: &second.ledger,
            at: origin.addingTimeInterval(21)
        )
        XCTAssertNotEqual(firstResult.relationshipID, reusedResult.relationshipID)
        XCTAssertEqual(
            firstResult.offererRelationship.localIdentity.relationshipAuthority.signingKey.publicKeyData,
            reusedResult.offererRelationship.localIdentity.relationshipAuthority.signingKey.publicKeyData
        )

        var persona = try PersonaProfileV1(displayName: "Local", createdAt: origin)
        try persona.upsert(relationship: firstResult.offererRelationship)
        XCTAssertThrowsError(
            try persona.upsert(relationship: reusedResult.offererRelationship)
        ) { error in
            XCTAssertEqual(error as? PersonaProfileV1Error, .invalidState)
        }

        var state = try ClientState(displayName: "First", createdAt: origin)
        try state.updateActivePersona {
            try $0.upsert(relationship: firstResult.offererRelationship)
        }
        _ = try state.addPersona(displayName: "Second", createdAt: origin)
        XCTAssertThrowsError(
            try state.updateActivePersona {
                try $0.upsert(relationship: reusedResult.offererRelationship)
            }
        ) { error in
            XCTAssertEqual(error as? ClientStateError, .invalidState)
        }
    }

    private func makeHandshakeFixture(
        offset: TimeInterval = 0
    ) throws -> (
        pending: PendingRendezvousOfferV2,
        invitation: ContactPairingInvitationV2,
        offerer: PreparedContactParticipantV2,
        responder: PreparedContactParticipantV2,
        ledger: RendezvousRedemptionLedgerV2
    ) {
        let createdAt = origin.addingTimeInterval(offset)
        let offer = try ContactPairingHandshakeV2.makeOffer(
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(300)
        )
        return (
            pending: offer.pending,
            invitation: offer.invitation,
            offerer: try makeParticipant(
                relationshipPseudonym: "Alice",
                relay: relay(host: "alice-relay.example"),
                createdAt: createdAt
            ),
            responder: try makeParticipant(
                relationshipPseudonym: "Bob",
                relay: relay(host: "bob-relay.example"),
                createdAt: createdAt
            ),
            ledger: RendezvousRedemptionLedgerV2()
        )
    }

    private func makeParticipant(
        relationshipPseudonym: String,
        relay: RelayEndpoint,
        createdAt: Date
    ) throws -> PreparedContactParticipantV2 {
        let pending = try PendingContactParticipantV2.prepare(
            relationshipPseudonym: relationshipPseudonym,
            relay: relay,
            createdAt: createdAt
        )
        XCTAssertEqual(String(describing: pending), "PendingContactParticipantV2(<redacted>)")
        XCTAssertTrue(Mirror(reflecting: pending).children.isEmpty)
        let createdRoute = try OpaqueReceiveRouteV2.creating(
            from: pending.routeCreateRequest,
            presentedRenewCapability: pending.clientCapabilities.renewCapability,
            existing: nil,
            confidentialTransport: true,
            receivedAt: createdAt
        )
        let participant = try pending.activate(createdRoute: createdRoute)
        XCTAssertEqual(
            String(describing: participant),
            "PreparedContactParticipantV2(<redacted>)"
        )
        XCTAssertTrue(Mirror(reflecting: participant).children.isEmpty)
        return participant
    }

    private func relay(host: String) -> RelayEndpoint {
        RelayEndpoint(host: host, port: 443, useTLS: true, transport: .websocket)
    }

    private func assertUnknownFieldRejected(offer: ContactPairingInvitationV2) throws {
        var object = try jsonObject(offer)
        object["legacyIdentity"] = "forbidden"
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            ContactPairingInvitationV2.self,
            from: JSONSerialization.data(withJSONObject: object)
        ))
    }

    private func assertUnknownFieldRejected(participant: PreparedContactParticipantV2) throws {
        var object = try jsonObject(participant)
        object["accountID"] = "forbidden"
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            PreparedContactParticipantV2.self,
            from: JSONSerialization.data(withJSONObject: object)
        ))
    }

    private func assertUnknownFieldRejected(relationship: PairwiseRelationshipV2) throws {
        var object = try jsonObject(relationship)
        object["deviceID"] = "forbidden"
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            PairwiseRelationshipV2.self,
            from: JSONSerialization.data(withJSONObject: object)
        ))
    }

    private func jsonObject<T: Encodable>(_ value: T) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: NoctweaveCoder.encode(value, sortedKeys: true)
            ) as? [String: Any]
        )
    }
}

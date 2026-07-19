import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class ConversationEventStrictTests: XCTestCase {
    private let origin = Date(timeIntervalSince1970: 1_910_000_000)

    func testUnknownApplicationTypeRoundTripsWithoutGainingControlAuthority() throws {
        let type = ContentTypeId(
            authority: "example.extension",
            name: "poll",
            major: 1
        )
        let content = EncodedContent(
            type: type,
            parameters: ["mode": "single"],
            payload: Data("opaque-poll".utf8),
            fallbackText: "Unsupported poll",
            disposition: .visible
        )
        let event = ConversationEvent(
            conversationId: "relationship-conversation",
            authorEndpointHandle: handle(),
            createdAt: origin,
            kind: .application,
            content: content
        )

        XCTAssertTrue(event.isStructurallyValid)
        XCTAssertFalse(event.mayMutateControlState(supportedControlTypes: Set([type])))
        let encoded = try NoctweaveCoder.encode(event, sortedKeys: true)
        XCTAssertEqual(
            try NoctweaveCoder.decode(ConversationEvent.self, from: encoded),
            event
        )
    }

    func testCurrentEventAndNestedContentRejectUnknownOrMissingFields() throws {
        let event = try textEvent()
        var object = try jsonObject(event)
        object["unknownTopLevel"] = true
        XCTAssertThrowsError(try decodeEvent(object))

        object = try jsonObject(event)
        var content = try XCTUnwrap(object["content"] as? [String: Any])
        content["unknownNested"] = true
        object["content"] = content
        XCTAssertThrowsError(try decodeEvent(object))

        object = try jsonObject(event)
        object.removeValue(forKey: "clientTransactionId")
        XCTAssertThrowsError(try decodeEvent(object))
    }

    func testOptionalFieldsEncodeAsExplicitNull() throws {
        let event = try textEvent()
        let object = try jsonObject(event)
        XCTAssertTrue(object["relation"] is NSNull)
        let content = try XCTUnwrap(object["content"] as? [String: Any])
        XCTAssertEqual(content["fallbackText"] as? String, "hello")

        let retraction = RetractionContentV1()
        let retractionObject = try jsonObject(retraction)
        XCTAssertTrue(retractionObject["reason"] is NSNull)
    }

    func testImmutableEventReplayIsIdempotentButConflictingIDFails() throws {
        var fixture = try makeRelationship()
        let first = try textEvent(
            id: UUID(),
            conversationID: fixture.conversationID,
            author: fixture.localEndpointHandle
        )
        XCTAssertTrue(try fixture.appendEvent(first))
        XCTAssertFalse(try fixture.appendEvent(first))

        let conflict = ConversationEvent(
            id: first.id,
            clientTransactionId: first.clientTransactionId,
            conversationId: first.conversationId,
            authorEndpointHandle: first.authorEndpointHandle,
            createdAt: first.createdAt,
            kind: .application,
            content: try XCTUnwrap(EncodedContent.text("changed"))
        )
        XCTAssertThrowsError(try fixture.appendEvent(conflict)) { error in
            XCTAssertEqual(error as? PairwiseRelationshipV2Error, .conflictingEvent)
        }
    }

    func testDeliveryStateCanAdvanceButNeverRegress() {
        var state = DeliveryStateRecord(
            eventId: UUID(),
            destinationEndpoint: handle(),
            state: .locallyPersisted,
            updatedAt: origin
        )
        XCTAssertTrue(state.advance(to: .relayAccepted, at: origin.addingTimeInterval(1)))
        XCTAssertTrue(state.advance(to: .peerStored, at: origin.addingTimeInterval(2)))
        XCTAssertFalse(state.advance(to: .relayAccepted, at: origin.addingTimeInterval(3)))
        XCTAssertEqual(state.state, .peerStored)
    }

    func testDurableStateCompactionPreservesActiveAndDependentRecords() throws {
        var relationship = try makeRelationship()
        let content = try XCTUnwrap(EncodedContent.text("bounded"))
        let peerEndpoint = relationship.peerIdentity.sendRoutes.ownerEndpointHandle
        let events = (0..<NoctweaveArchitectureV2.maximumRelationshipEvents).map { index in
            ConversationEvent(
                conversationId: relationship.conversationID,
                authorEndpointHandle: relationship.localEndpointHandle,
                createdAt: origin.addingTimeInterval(TimeInterval(index)),
                kind: .application,
                content: content
            )
        }
        relationship.events = events
        relationship.deliveryStates = events.enumerated().map { index, event in
            DeliveryStateRecord(
                eventId: event.id,
                destinationEndpoint: peerEndpoint,
                state: index == 0 ? .relayAccepted : (index == 2 ? .locallyPersisted : .peerRead),
                updatedAt: event.createdAt
            )
        }
        relationship.inboundReceipts = events.map { event in
            InboundEnvelopeReceiptV2(
                sourceScopeId: relationship.id,
                logicalEventId: event.id,
                envelopeId: UUID(),
                envelopeDigest: Data(SHA256.hash(data: Data(event.id.uuidString.utf8))),
                processedAt: event.createdAt
            )
        }

        var terminalIntents: [ProtocolIntentV2] = []
        terminalIntents.reserveCapacity(NoctweaveArchitectureV2.maximumProtocolIntents - 1)
        for index in 0..<(NoctweaveArchitectureV2.maximumProtocolIntents - 1) {
            let id = UUID()
            let date = origin.addingTimeInterval(TimeInterval(index))
            terminalIntents.append(ProtocolIntentV2(
                id: id,
                kind: .sendEvent,
                targetIdentifier: Data(UUID().uuidString.lowercased().utf8),
                idempotencyKey: .generate(intentId: id),
                payloadDigest: Data(SHA256.hash(data: Data("intent-\(index)".utf8))),
                state: .finalized,
                attemptCount: 1,
                lastAttemptId: UUID(),
                lastAttemptAt: date,
                createdAt: date,
                updatedAt: date
            ))
        }
        let requiredDependency = try XCTUnwrap(terminalIntents.first)
        relationship.protocolIntents = terminalIntents

        let unfinishedEvent = events[2]
        let createdSession = try MessageEngine.createOutboundEndpointSession(
            relationship: relationship,
            now: unfinishedEvent.createdAt
        )
        var conversation = createdSession.conversation
        let envelope = try MessageEngine.encryptDirectV4(
            wirePayload: .application(unfinishedEvent),
            eventID: unfinishedEvent.id,
            relationship: relationship,
            conversation: &conversation,
            bootstrap: .signedPrekey(
                kemCiphertext: createdSession.kemCiphertext,
                prekey: createdSession.prekey
            ),
            sentAt: unfinishedEvent.createdAt
        )
        try relationship.upsertDirectSession(conversation)
        let queued = try relationship.enqueue(
            logicalEventID: unfinishedEvent.id,
            payload: NoctweaveCoder.encode(envelope, sortedKeys: true),
            at: unfinishedEvent.createdAt
        )
        let delivery = try XCTUnwrap(queued.first)
        let unfinishedIndex = try XCTUnwrap(relationship.protocolIntents.firstIndex {
            $0.id == delivery.intentID
        })
        let prepared = relationship.protocolIntents[unfinishedIndex]
        let unfinished = ProtocolIntentV2(
            id: prepared.id,
            kind: prepared.kind,
            targetIdentifier: prepared.targetIdentifier,
            expectedEpoch: prepared.expectedEpoch,
            idempotencyKey: prepared.idempotencyKey,
            payloadDigest: prepared.payloadDigest,
            dependencies: [requiredDependency.id],
            state: prepared.state,
            attemptCount: prepared.attemptCount,
            lastAttemptId: prepared.lastAttemptId,
            lastAttemptAt: prepared.lastAttemptAt,
            lastErrorClass: prepared.lastErrorClass,
            nextAttemptNotBefore: prepared.nextAttemptNotBefore,
            createdAt: prepared.createdAt,
            updatedAt: prepared.updatedAt,
            expiresAt: prepared.expiresAt
        )
        relationship.protocolIntents[unfinishedIndex] = unfinished
        XCTAssertTrue(relationship.isStructurallyValid)
        let newestEventID = try XCTUnwrap(events.last?.id)

        try relationship.compactDurableState()

        XCTAssertTrue(relationship.isStructurallyValid)
        XCTAssertEqual(
            relationship.events.count,
            NoctweaveArchitectureV2.relationshipEventRecentWindow + 1
        )
        XCTAssertFalse(relationship.events.contains { $0.id == events[0].id })
        XCTAssertFalse(relationship.events.contains { $0.id == events[1].id })
        XCTAssertTrue(relationship.events.contains { $0.id == unfinishedEvent.id })
        XCTAssertTrue(relationship.events.contains { $0.id == newestEventID })
        XCTAssertEqual(
            relationship.deliveryStates.count,
            NoctweaveArchitectureV2.deliveryStateRecentWindow + 1
        )
        XCTAssertFalse(relationship.deliveryStates.contains { $0.eventId == events[0].id })
        XCTAssertFalse(relationship.deliveryStates.contains { $0.eventId == events[1].id })
        XCTAssertTrue(relationship.deliveryStates.contains {
            $0.eventId == unfinishedEvent.id
        })
        XCTAssertEqual(
            relationship.inboundReceipts.count,
            NoctweaveArchitectureV2.inboundEnvelopeReceiptRecentWindow
        )
        XCTAssertFalse(relationship.inboundReceipts.contains {
            $0.logicalEventId == events[0].id
        })
        XCTAssertTrue(relationship.inboundReceipts.contains {
            $0.logicalEventId == newestEventID
        })
        XCTAssertEqual(
            relationship.protocolIntents.count,
            NoctweaveArchitectureV2.protocolIntentRecentWindow + 2
        )
        XCTAssertTrue(relationship.protocolIntents.contains {
            $0.id == requiredDependency.id
        })
        XCTAssertTrue(relationship.protocolIntents.contains { $0.id == unfinished.id })
        XCTAssertFalse(relationship.protocolIntents.contains {
            $0.id == terminalIntents[1].id
        })
    }

    func testIntentCapacityNeverDiscardsUnfinishedRecoveryState() throws {
        var relationship = try makeRelationship()
        relationship.protocolIntents = (0..<NoctweaveArchitectureV2.maximumProtocolIntents).map {
            index in
            ProtocolIntentV2.prepare(
                kind: .sendEvent,
                payloadDigest: Data(SHA256.hash(data: Data("pending-\(index)".utf8))),
                createdAt: origin.addingTimeInterval(TimeInterval(index))
            )
        }
        let additional = ProtocolIntentV2.prepare(
            kind: .sendEvent,
            payloadDigest: Data(SHA256.hash(data: Data("additional".utf8))),
            createdAt: origin.addingTimeInterval(10_000)
        )

        XCTAssertThrowsError(try relationship.appendProtocolIntent(additional)) { error in
            XCTAssertEqual(error as? PairwiseRelationshipV2Error, .capacityReached)
        }
        XCTAssertEqual(
            relationship.protocolIntents.count,
            NoctweaveArchitectureV2.maximumProtocolIntents
        )
        XCTAssertTrue(relationship.protocolIntents.allSatisfy { !$0.state.isTerminal })
    }

    private func textEvent(
        id: UUID = UUID(),
        conversationID: String = "relationship-conversation",
        author: RelationshipEndpointHandle? = nil
    ) throws -> ConversationEvent {
        ConversationEvent(
            id: id,
            clientTransactionId: UUID(),
            conversationId: conversationID,
            authorEndpointHandle: author ?? handle(),
            createdAt: origin,
            kind: .application,
            content: try XCTUnwrap(EncodedContent.text("hello"))
        )
    }

    private func handle() -> RelationshipEndpointHandle {
        RelationshipEndpointHandle.generate(
            relationshipId: UUID()
        )
    }

    private func makeRelationship() throws -> PairwiseRelationshipV2 {
        let createdAt = origin
        var offer = try ContactPairingHandshakeV2.makeOffer(
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(300)
        )
        let first = try activateParticipant(name: "A", host: "a.example", at: createdAt)
        let second = try activateParticipant(name: "B", host: "b.example", at: createdAt)
        var ledger = RendezvousRedemptionLedgerV2()
        return try ContactPairingHandshakeV2.establish(
            pendingOffer: &offer.pending,
            invitation: offer.invitation,
            offerer: first,
            responder: second,
            ledger: &ledger,
            at: createdAt.addingTimeInterval(1)
        ).offererRelationship
    }

    private func activateParticipant(
        name: String,
        host: String,
        at date: Date
    ) throws -> PreparedContactParticipantV2 {
        let pending = try PendingContactParticipantV2.prepare(
            relationshipPseudonym: name,
            relay: RelayEndpoint(
                host: host,
                port: 443,
                useTLS: true,
                transport: .websocket
            ),
            createdAt: date
        )
        let route = try OpaqueReceiveRouteV2.creating(
            from: pending.routeCreateRequest,
            presentedRenewCapability: pending.clientCapabilities.renewCapability,
            existing: nil,
            confidentialTransport: true,
            receivedAt: date
        )
        return try pending.activate(createdRoute: route)
    }

    private func jsonObject<T: Encodable>(_ value: T) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: NoctweaveCoder.encode(value, sortedKeys: true)
            ) as? [String: Any]
        )
    }

    private func decodeEvent(_ object: [String: Any]) throws -> ConversationEvent {
        try NoctweaveCoder.decode(
            ConversationEvent.self,
            from: JSONSerialization.data(withJSONObject: object)
        )
    }
}

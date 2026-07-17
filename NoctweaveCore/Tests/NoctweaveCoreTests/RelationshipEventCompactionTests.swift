import XCTest
@testable import NoctweaveCore

final class RelationshipEventCompactionTests: XCTestCase {
    func testCheckpointCompactionIsDeterministicBoundedAndAppendableAfterRoundTrip() throws {
        let relationshipId = UUID()
        let handle = RelationshipEndpointHandle.generate(
            identityGenerationId: UUID(),
            endpointId: UUID(),
            relationshipId: relationshipId,
            nonce: UUID()
        )
        let conversationId = "checkpointed-conversation"
        let createdAt = Date(timeIntervalSince1970: 1_700_000_000)
        let eventCount = NoctweaveArchitectureV2.maximumRelationshipEvents + 1
        let sourceEvents = try (0..<eventCount).map { index in
            try relationshipEvent(
                index: index,
                conversationId: conversationId,
                handle: handle,
                createdAt: createdAt
            )
        }
        var first = RelationshipStateV2(
            id: relationshipId,
            contactId: UUID(),
            localEndpointHandle: handle,
            conversationIds: [conversationId],
            createdAt: createdAt
        )
        var replay = RelationshipStateV2(
            id: relationshipId,
            contactId: first.contactId,
            localEndpointHandle: handle,
            conversationIds: [conversationId],
            createdAt: createdAt
        )

        for event in sourceEvents {
            XCTAssertTrue(first.appendEvent(event))
            XCTAssertTrue(replay.appendEvent(event))
        }

        let removalCount = NoctweaveArchitectureV2.maximumRelationshipEvents
            - NoctweaveArchitectureV2.relationshipEventRecentWindow
        let checkpoint = try XCTUnwrap(first.eventCheckpoint)
        XCTAssertEqual(checkpoint, replay.eventCheckpoint)
        XCTAssertTrue(checkpoint.isStructurallyValid(for: relationshipId))
        XCTAssertEqual(checkpoint.compactedEventCount, UInt64(removalCount))
        XCTAssertEqual(checkpoint.lastCompactedEventId, sourceEvents[removalCount - 1].id)
        XCTAssertEqual(
            first.events.count,
            NoctweaveArchitectureV2.relationshipEventRecentWindow + 1
        )
        XCTAssertEqual(first.events.first?.id, sourceEvents[removalCount].id)
        XCTAssertEqual(first.events.last?.id, sourceEvents.last?.id)
        XCTAssertEqual(first.totalEventCount, UInt64(eventCount))
        XCTAssertTrue(first.isStructurallyValid)

        var decoded = try NoctweaveCoder.decode(
            RelationshipStateV2.self,
            from: NoctweaveCoder.encode(first, sortedKeys: true)
        )
        XCTAssertEqual(decoded, first)
        XCTAssertTrue(decoded.isStructurallyValid)

        let next = try relationshipEvent(
            index: eventCount,
            conversationId: conversationId,
            handle: handle,
            createdAt: createdAt
        )
        XCTAssertTrue(decoded.appendEvent(next))
        XCTAssertEqual(decoded.eventCheckpoint, checkpoint)
        XCTAssertEqual(decoded.events.last?.id, next.id)
        XCTAssertEqual(decoded.totalEventCount, UInt64(eventCount + 1))
        XCTAssertTrue(decoded.isStructurallyValid)

        let additionalToFillWindow = NoctweaveArchitectureV2.maximumRelationshipEvents
            - decoded.events.count
        for offset in 0..<additionalToFillWindow {
            let additionalEvent = try relationshipEvent(
                index: eventCount + 1 + offset,
                conversationId: conversationId,
                handle: handle,
                createdAt: createdAt
            )
            XCTAssertTrue(decoded.appendEvent(additionalEvent))
        }
        XCTAssertEqual(
            decoded.events.count,
            NoctweaveArchitectureV2.maximumRelationshipEvents
        )
        let secondRoundEvent = try relationshipEvent(
            index: eventCount + 1 + additionalToFillWindow,
            conversationId: conversationId,
            handle: handle,
            createdAt: createdAt
        )
        XCTAssertTrue(decoded.appendEvent(secondRoundEvent))
        let secondCheckpoint = try XCTUnwrap(decoded.eventCheckpoint)
        XCTAssertEqual(
            secondCheckpoint.compactedEventCount,
            UInt64(removalCount * 2)
        )
        XCTAssertNotEqual(secondCheckpoint.digest, checkpoint.digest)
        XCTAssertEqual(
            decoded.totalEventCount,
            UInt64(eventCount + 2 + additionalToFillWindow)
        )
        XCTAssertTrue(decoded.isStructurallyValid)
    }

    func testCheckpointIsRelationshipBoundAndMalformedCheckpointFailsClosed() throws {
        let relationshipId = UUID()
        let otherRelationshipId = UUID()
        let handle = RelationshipEndpointHandle.generate(
            identityGenerationId: UUID(),
            endpointId: UUID(),
            relationshipId: relationshipId,
            nonce: UUID()
        )
        let event = try relationshipEvent(
            index: 1,
            conversationId: "binding",
            handle: handle,
            createdAt: Date(timeIntervalSince1970: 1_700_100_000)
        )
        let first = try RelationshipEventCheckpointV2.advancing(
            previous: nil,
            relationshipId: relationshipId,
            removedEvents: [event]
        )
        let other = try RelationshipEventCheckpointV2.advancing(
            previous: nil,
            relationshipId: otherRelationshipId,
            removedEvents: [event]
        )
        XCTAssertNotEqual(first.digest, other.digest)
        XCTAssertFalse(first.isStructurallyValid(for: otherRelationshipId))

        let malformed = RelationshipEventCheckpointV2(
            relationshipId: relationshipId,
            compactedEventCount: 1,
            lastCompactedEventId: event.id,
            digest: Data(repeating: 0, count: 31)
        )
        let invalid = RelationshipStateV2(
            id: relationshipId,
            contactId: UUID(),
            localEndpointHandle: handle,
            conversationIds: [event.conversationId],
            events: [event],
            eventCheckpoint: malformed
        )
        XCTAssertFalse(invalid.isStructurallyValid)
    }
}

private func relationshipEvent(
    index: Int,
    conversationId: String,
    handle: RelationshipEndpointHandle,
    createdAt: Date
) throws -> ConversationEvent {
    ConversationEvent(
        id: UUID(),
        clientTransactionId: UUID(),
        conversationId: conversationId,
        authorEndpointHandle: handle,
        createdAt: createdAt.addingTimeInterval(TimeInterval(index)),
        kind: .application,
        content: try XCTUnwrap(EncodedContent.text("event-\(index)"))
    )
}

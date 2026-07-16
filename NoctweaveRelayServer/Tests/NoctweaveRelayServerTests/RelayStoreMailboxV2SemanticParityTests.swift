import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class RelayStoreMailboxV2SemanticParityTests: XCTestCase {
    func testAuthenticatedCursorPaginatesWithoutCommitAndIsConsumerBound() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        let firstConsumer = MailboxConsumerId.generate()
        let secondConsumer = MailboxConsumerId.generate()
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA1]))
        _ = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: firstConsumer,
            consumerSigningPublicKey: linuxParityMailboxPublicKey(0xD1),
            startingSequence: 0
        )
        _ = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: secondConsumer,
            consumerSigningPublicKey: linuxParityMailboxPublicKey(0xD2),
            sponsorConsumerId: firstConsumer,
            startingSequence: 0
        )
        for counter in 1...3 {
            _ = try store.deliver(makeEnvelope(counter: UInt64(counter)), to: inboxId)
        }

        let firstPage = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: firstConsumer,
            cursor: nil,
            maxCount: 0
        )
        XCTAssertEqual(firstPage.events.map(\.sequence), [1])
        XCTAssertTrue(firstPage.hasMore)
        let secondPage = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: firstConsumer,
            cursor: firstPage.nextCursor,
            maxCount: 1
        )
        XCTAssertEqual(secondPage.events.map(\.sequence), [2])

        XCTAssertThrowsError(
            try store.syncMailbox(
                inboxId: inboxId,
                consumerId: secondConsumer,
                cursor: firstPage.nextCursor,
                maxCount: nil
            )
        ) { error in
            XCTAssertEqual(error as? MailboxSyncError, .invalidCursor)
        }
        _ = try store.commitMailboxCursor(
            inboxId: inboxId,
            consumerId: firstConsumer,
            cursor: secondPage.nextCursor,
            sequence: secondPage.nextSequence
        )
        XCTAssertThrowsError(
            try store.syncMailbox(
                inboxId: inboxId,
                consumerId: firstConsumer,
                cursor: firstPage.nextCursor,
                maxCount: nil
            )
        ) { error in
            XCTAssertEqual(error as? MailboxSyncError, .cursorRollback)
        }
        let remaining = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: firstConsumer,
            cursor: nil,
            maxCount: nil
        )
        XCTAssertEqual(remaining.events.map(\.sequence), [3])
    }

    func testLegacyAckCannotCrossEnvelopeKindsOrDeleteAheadOfConsumer() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        let consumer = MailboxConsumerId.generate()
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA2]))
        _ = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumer,
            consumerSigningPublicKey: linuxParityMailboxPublicKey(0xD3),
            startingSequence: 0
        )
        let direct = makeEnvelope(counter: 1)
        let group = makeEnvelope(counter: 2)
        _ = try store.deliver(direct, to: inboxId)
        _ = try store.deliverGroupEnvelope(
            group,
            to: inboxId,
            recipientFingerprints: ["member-a"]
        )

        XCTAssertEqual(try store.acknowledge(inboxId: inboxId, messageIds: [direct.id]), 0)
        XCTAssertEqual(try store.acknowledge(inboxId: inboxId, messageIds: [group.id]), 0)
        let batch = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: consumer,
            cursor: nil,
            maxCount: nil
        )
        XCTAssertEqual(batch.events.map(\.id), [direct.id, group.id])
        _ = try store.commitMailboxCursor(
            inboxId: inboxId,
            consumerId: consumer,
            cursor: batch.nextCursor,
            sequence: batch.nextSequence
        )
        XCTAssertEqual(store.fetch(inboxId: inboxId, maxCount: nil).map(\.id), [group.id])
        XCTAssertEqual(try store.acknowledge(inboxId: inboxId, messageIds: [group.id]), 0)
        XCTAssertEqual(
            try store.acknowledgeGroupEnvelopes(
                inboxId: inboxId,
                messageIds: [group.id],
                recipientFingerprint: "member-a"
            ),
            1
        )
        XCTAssertTrue(store.fetch(inboxId: inboxId, maxCount: nil).isEmpty)
    }

    func testFirstV2ConsumerNormalizesRetainedLegacySequenceGaps() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        let consumer = MailboxConsumerId.generate()
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA5]))

        let first = makeEnvelope(counter: 1)
        let removed = makeEnvelope(counter: 2)
        let third = makeEnvelope(counter: 3)
        _ = try store.deliver(first, to: inboxId)
        _ = try store.deliver(removed, to: inboxId)
        _ = try store.deliver(third, to: inboxId)
        XCTAssertEqual(try store.acknowledge(inboxId: inboxId, messageIds: [removed.id]), 1)

        _ = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumer,
            consumerSigningPublicKey: linuxParityMailboxPublicKey(0xD7),
            startingSequence: 0
        )
        let batch = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: consumer,
            cursor: nil,
            maxCount: nil
        )

        XCTAssertEqual(batch.events.map(\.id), [first.id, third.id])
        XCTAssertEqual(batch.events.map(\.sequence), [1, 2])
        XCTAssertEqual(batch.highWatermark, 2)
        XCTAssertEqual(batch.retentionFloor, 0)
    }

    func testFirstV2ConsumerNormalizesFullyAcknowledgedLegacyMailboxToZero() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        let consumer = MailboxConsumerId.generate()
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA6]))

        let envelope = makeEnvelope(counter: 4)
        _ = try store.deliver(envelope, to: inboxId)
        XCTAssertEqual(try store.acknowledge(inboxId: inboxId, messageIds: [envelope.id]), 1)

        _ = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumer,
            consumerSigningPublicKey: linuxParityMailboxPublicKey(0xD8),
            startingSequence: 0
        )
        let batch = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: consumer,
            cursor: nil,
            maxCount: nil
        )

        XCTAssertTrue(batch.events.isEmpty)
        XCTAssertEqual(batch.nextSequence, 0)
        XCTAssertEqual(batch.highWatermark, 0)
        XCTAssertEqual(batch.retentionFloor, 0)
    }

    func testConflictingEnvelopeIdReplayIsRejected() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        let id = UUID()
        let original = makeEnvelope(id: id, counter: 1)
        let conflicting = makeEnvelope(id: id, counter: 2)
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA7]))
        _ = try store.deliver(original, to: inboxId)
        XCTAssertThrowsError(try store.deliver(conflicting, to: inboxId)) { error in
            XCTAssertEqual(error as? RelayStoreError, .invalidEnvelopePayload)
        }

        let groupInbox = InboxAddress.generate()
        try store.registerInbox(inboxId: groupInbox, accessPublicKey: Data([0xA8]))
        _ = try store.deliverGroupEnvelope(
            original,
            to: groupInbox,
            recipientFingerprints: ["member-a"]
        )
        XCTAssertThrowsError(
            try store.deliverGroupEnvelope(
                original,
                to: groupInbox,
                recipientFingerprints: ["member-b"]
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .invalidEnvelopePayload)
        }
    }

    func testSequenceDoesNotReuseAfterRetentionGarbageCollection() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        let first = makeEnvelope(counter: 1)
        let second = makeEnvelope(counter: 2)
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA3]))
        _ = try store.deliver(first, to: inboxId)
        _ = try store.deliver(second, to: inboxId)
        let current = MailboxConsumerId.generate()
        let recovering = MailboxConsumerId.generate()
        let currentRegistration = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: current,
            consumerSigningPublicKey: linuxParityMailboxPublicKey(0xD4)
        )
        _ = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: recovering,
            consumerSigningPublicKey: linuxParityMailboxPublicKey(0xD5),
            sponsorConsumerId: current,
            startingSequence: 0
        )
        XCTAssertEqual(currentRegistration.committedSequence, 2)
        let recoveryBatch = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: recovering,
            cursor: nil,
            maxCount: nil
        )
        XCTAssertEqual(recoveryBatch.events.map(\.sequence), [1, 2])
        _ = try store.commitMailboxCursor(
            inboxId: inboxId,
            consumerId: recovering,
            cursor: recoveryBatch.nextCursor,
            sequence: recoveryBatch.nextSequence
        )
        XCTAssertTrue(store.fetch(inboxId: inboxId, maxCount: nil).isEmpty)

        let third = makeEnvelope(counter: 3)
        _ = try store.deliver(third, to: inboxId)
        let currentBatch = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: current,
            cursor: nil,
            maxCount: nil
        )
        XCTAssertEqual(currentBatch.events.map(\.sequence), [3])
        XCTAssertEqual(currentBatch.events.map(\.id), [third.id])
    }

    func testPageSizeUsesSharedDefaultAndMaximumBounds() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        let consumer = MailboxConsumerId.generate()
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA4]))
        _ = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumer,
            consumerSigningPublicKey: linuxParityMailboxPublicKey(0xD6),
            startingSequence: 0
        )
        for counter in 1...257 {
            _ = try store.deliver(makeEnvelope(counter: UInt64(counter)), to: inboxId)
        }
        let defaultPage = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: consumer,
            cursor: nil,
            maxCount: nil
        )
        let maximumPage = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: consumer,
            cursor: nil,
            maxCount: 10_000
        )
        XCTAssertEqual(defaultPage.events.count, 100)
        XCTAssertTrue(defaultPage.hasMore)
        XCTAssertEqual(maximumPage.events.count, 256)
        XCTAssertTrue(maximumPage.hasMore)
    }

    private func makeEnvelope(id: UUID = UUID(), counter: UInt64) -> Envelope {
        Envelope(
            id: id,
            conversationId: "mailbox-v2-parity",
            sessionId: "session-v2",
            senderFingerprint: Data(repeating: 0x44, count: 32).base64EncodedString(),
            sentAt: Date(timeIntervalSince1970: TimeInterval(2_000 + counter)),
            messageCounter: counter,
            kemCiphertext: nil,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: 12),
                ciphertext: Data(repeating: UInt8(truncatingIfNeeded: counter), count: 512),
                tag: Data(repeating: 0x22, count: 16)
            ),
            signature: Data(
                repeating: 0x33,
                count: OQSSignatureVerifier.mlDSA65SignatureBytes
            )
        )
    }
}

private func linuxParityMailboxPublicKey(_ marker: UInt8) -> Data {
    Data(repeating: marker, count: OQSSignatureVerifier.mlDSA65PublicKeyBytes)
}

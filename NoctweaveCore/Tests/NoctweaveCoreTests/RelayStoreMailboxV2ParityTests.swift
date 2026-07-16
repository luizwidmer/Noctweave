import XCTest
@testable import NoctweaveCore

final class RelayStoreMailboxV2ParityTests: XCTestCase {
    func testAuthenticatedCursorPaginatesWithoutCommitAndIsConsumerBound() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        let firstConsumer = MailboxConsumerId.generate()
        let secondConsumer = MailboxConsumerId.generate()
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA1]))
        _ = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: firstConsumer,
            consumerSigningPublicKey: parityMailboxPublicKey(0xB1),
            startingSequence: 0
        )
        _ = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: secondConsumer,
            consumerSigningPublicKey: parityMailboxPublicKey(0xB2),
            sponsorConsumerId: firstConsumer,
            startingSequence: 0
        )
        for counter in 1...3 {
            _ = try await store.deliver(makeEnvelope(counter: UInt64(counter)), to: inboxId)
        }

        let firstPage = try await store.syncMailbox(
            inboxId: inboxId,
            consumerId: firstConsumer,
            maxCount: 0
        )
        XCTAssertEqual(firstPage.events.map(\.sequence), [1])
        XCTAssertTrue(firstPage.hasMore)
        let secondPage = try await store.syncMailbox(
            inboxId: inboxId,
            consumerId: firstConsumer,
            cursor: firstPage.nextCursor,
            maxCount: 1
        )
        XCTAssertEqual(secondPage.events.map(\.sequence), [2])

        await XCTAssertThrowsMailboxErrorAsync(
            try await store.syncMailbox(
                inboxId: inboxId,
                consumerId: secondConsumer,
                cursor: firstPage.nextCursor
            )
        ) { error in
            XCTAssertEqual(error as? MailboxSyncError, .invalidCursor)
        }
        _ = try await store.commitMailboxCursor(
            inboxId: inboxId,
            consumerId: firstConsumer,
            cursor: secondPage.nextCursor,
            sequence: secondPage.nextSequence
        )
        await XCTAssertThrowsMailboxErrorAsync(
            try await store.syncMailbox(
                inboxId: inboxId,
                consumerId: firstConsumer,
                cursor: firstPage.nextCursor
            )
        ) { error in
            XCTAssertEqual(error as? MailboxSyncError, .cursorRollback)
        }
        let remaining = try await store.syncMailbox(
            inboxId: inboxId,
            consumerId: firstConsumer
        )
        XCTAssertEqual(remaining.events.map(\.sequence), [3])
    }

    func testConflictingEnvelopeIdReplayIsRejected() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        let id = UUID()
        let original = makeEnvelope(id: id, counter: 1)
        let conflicting = makeEnvelope(id: id, counter: 2)
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA7]))
        _ = try await store.deliver(original, to: inboxId)
        await XCTAssertThrowsMailboxErrorAsync(try await store.deliver(conflicting, to: inboxId)) { error in
            XCTAssertEqual(error as? RelayStoreError, .invalidEnvelopePayload)
        }

    }

    func testSequenceDoesNotReuseAfterRetentionGarbageCollection() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        let first = makeEnvelope(counter: 1)
        let second = makeEnvelope(counter: 2)
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA3]))
        _ = try await store.deliver(first, to: inboxId)
        _ = try await store.deliver(second, to: inboxId)
        let current = MailboxConsumerId.generate()
        let recovering = MailboxConsumerId.generate()
        let currentRegistration = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: current,
            consumerSigningPublicKey: parityMailboxPublicKey(0xB4)
        )
        _ = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: recovering,
            consumerSigningPublicKey: parityMailboxPublicKey(0xB5),
            sponsorConsumerId: current,
            startingSequence: 0
        )
        XCTAssertEqual(currentRegistration.committedSequence, 2)
        let recoveryBatch = try await store.syncMailbox(
            inboxId: inboxId,
            consumerId: recovering
        )
        XCTAssertEqual(recoveryBatch.events.map(\.sequence), [1, 2])
        _ = try await store.commitMailboxCursor(
            inboxId: inboxId,
            consumerId: recovering,
            cursor: recoveryBatch.nextCursor,
            sequence: recoveryBatch.nextSequence
        )
        let afterGarbageCollection = try await store.fetch(inboxId: inboxId)
        XCTAssertTrue(afterGarbageCollection.isEmpty)

        let third = makeEnvelope(counter: 3)
        _ = try await store.deliver(third, to: inboxId)
        let currentBatch = try await store.syncMailbox(inboxId: inboxId, consumerId: current)
        XCTAssertEqual(currentBatch.events.map(\.sequence), [3])
        XCTAssertEqual(currentBatch.events.map(\.id), [third.id])
    }

    func testPageSizeUsesSharedDefaultAndMaximumBounds() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        let consumer = MailboxConsumerId.generate()
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA4]))
        _ = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumer,
            consumerSigningPublicKey: parityMailboxPublicKey(0xB6),
            startingSequence: 0
        )
        for counter in 1...257 {
            _ = try await store.deliver(makeEnvelope(counter: UInt64(counter)), to: inboxId)
        }
        let defaultPage = try await store.syncMailbox(inboxId: inboxId, consumerId: consumer)
        let maximumPage = try await store.syncMailbox(
            inboxId: inboxId,
            consumerId: consumer,
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
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: 12),
                ciphertext: Data(repeating: UInt8(truncatingIfNeeded: counter), count: 512),
                tag: Data(repeating: 0x22, count: 16)
            ),
            signature: Data(repeating: 0x33, count: 3_309)
        )
    }
}

private func parityMailboxPublicKey(_ marker: UInt8) -> Data {
    Data(repeating: marker, count: 1_952)
}

private func XCTAssertThrowsMailboxErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ errorHandler: (Error) -> Void = { _ in },
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected expression to throw", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}

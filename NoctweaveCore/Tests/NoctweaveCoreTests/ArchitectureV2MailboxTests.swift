import XCTest
@testable import NoctweaveCore

final class ArchitectureV2MailboxTests: XCTestCase {
    func testIdempotentRegistrationCannotReplaceBoundConsumerSigningKey() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        let consumer = MailboxConsumerId.generate()
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x0A]))

        let first = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumer,
            consumerSigningPublicKey: architectureMailboxPublicKey(0xA1),
            startingSequence: 0
        )
        let replay = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumer,
            consumerSigningPublicKey: architectureMailboxPublicKey(0xA1),
            startingSequence: 0
        )
        XCTAssertEqual(first, replay)
        XCTAssertEqual(first.consumerSigningPublicKey, architectureMailboxPublicKey(0xA1))
        await XCTAssertThrowsErrorAsync(
            try await store.registerMailboxConsumer(
                inboxId: inboxId,
                consumerId: consumer,
                consumerSigningPublicKey: architectureMailboxPublicKey(0xA2),
                startingSequence: 0
            )
        ) { error in
            XCTAssertEqual(error as? MailboxSyncError, .consumerSigningKeyMismatch)
        }
    }

    func testRevokedConsumerHistoryIsBoundedWithoutExhaustingDeviceChurn() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x0B]))

        var current = MailboxConsumerId.generate()
        _ = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: current,
            consumerSigningPublicKey: architectureMailboxPublicKey(1),
            startingSequence: 0
        )
        for index in 1..<80 {
            let replacement = MailboxConsumerId.generate()
            _ = try await store.registerMailboxConsumer(
                inboxId: inboxId,
                consumerId: replacement,
                consumerSigningPublicKey: architectureMailboxPublicKey(UInt8(index + 1)),
                sponsorConsumerId: current,
                startingSequence: 0
            )
            _ = try await store.revokeMailboxConsumer(inboxId: inboxId, consumerId: current)
            current = replacement
        }

        let retainedConsumers = await store.mailboxConsumers(inboxId: inboxId)
        let remainsEndpointManaged = await store.hasMailboxConsumerBindings(inboxId: inboxId)
        XCTAssertEqual(
            retainedConsumers.count,
            NoctweaveArchitectureV2.maximumMailboxConsumerHistory
        )
        XCTAssertTrue(remainsEndpointManaged)
        let replacement = MailboxConsumerId.generate()
        let registered = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: replacement,
            consumerSigningPublicKey: architectureMailboxPublicKey(0xFE),
            sponsorConsumerId: current,
            startingSequence: 0
        )
        XCTAssertEqual(registered.state, .active)
    }

    func testMailboxConsumersAdvanceIndependentlyBeforeGarbageCollection() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data(repeating: 0xA1, count: 32))
        let phone = MailboxConsumerId.generate()
        let desktop = MailboxConsumerId.generate()
        _ = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: phone,
            consumerSigningPublicKey: architectureMailboxPublicKey(0xF1),
            startingSequence: 0
        )
        _ = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: desktop,
            consumerSigningPublicKey: architectureMailboxPublicKey(0xF2),
            sponsorConsumerId: phone,
            startingSequence: 0
        )

        let first = makeEnvelope(counter: 1)
        let second = makeEnvelope(counter: 2)
        try await store.deliver(first, to: inboxId)
        try await store.deliver(second, to: inboxId)

        let phoneBatch = try await store.syncMailbox(inboxId: inboxId, consumerId: phone)
        XCTAssertEqual(phoneBatch.events.map(\.sequence), [1, 2])
        XCTAssertTrue(phoneBatch.isStructurallyValid)
        try await store.commitMailboxCursor(
            inboxId: inboxId,
            consumerId: phone,
            cursor: phoneBatch.nextCursor,
            sequence: phoneBatch.nextSequence
        )
        let afterPhoneCommit = try await store.fetch(inboxId: inboxId)
        XCTAssertEqual(afterPhoneCommit.map(\.id), [first.id, second.id])

        let desktopFirstPage = try await store.syncMailbox(
            inboxId: inboxId,
            consumerId: desktop,
            maxCount: 1
        )
        XCTAssertEqual(desktopFirstPage.events.map(\.sequence), [1])
        XCTAssertTrue(desktopFirstPage.hasMore)
        try await store.commitMailboxCursor(
            inboxId: inboxId,
            consumerId: desktop,
            cursor: desktopFirstPage.nextCursor,
            sequence: desktopFirstPage.nextSequence
        )
        let afterDesktopFirstCommit = try await store.fetch(inboxId: inboxId)
        XCTAssertEqual(afterDesktopFirstCommit.map(\.id), [second.id])

        let desktopSecondPage = try await store.syncMailbox(inboxId: inboxId, consumerId: desktop)
        XCTAssertEqual(desktopSecondPage.events.map(\.sequence), [2])
        try await store.commitMailboxCursor(
            inboxId: inboxId,
            consumerId: desktop,
            cursor: desktopSecondPage.nextCursor,
            sequence: desktopSecondPage.nextSequence
        )
        let afterDesktopSecondCommit = try await store.fetch(inboxId: inboxId)
        XCTAssertTrue(afterDesktopSecondCommit.isEmpty)
    }

    func testMailboxRejectsForgedAndRollbackCursors() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        let consumer = MailboxConsumerId.generate()
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x01]))
        _ = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumer,
            consumerSigningPublicKey: architectureMailboxPublicKey(0xF3),
            startingSequence: 0
        )
        try await store.deliver(makeEnvelope(counter: 1), to: inboxId)
        let batch = try await store.syncMailbox(inboxId: inboxId, consumerId: consumer)

        await XCTAssertThrowsErrorAsync(
            try await store.commitMailboxCursor(
                inboxId: inboxId,
                consumerId: consumer,
                cursor: MailboxCursor(rawValue: Data(repeating: 0xBC, count: 32).base64EncodedString()),
                sequence: batch.nextSequence
            )
        ) { error in
            XCTAssertEqual(error as? MailboxSyncError, .invalidCursor)
        }
        try await store.commitMailboxCursor(
            inboxId: inboxId,
            consumerId: consumer,
            cursor: batch.nextCursor,
            sequence: batch.nextSequence
        )
        await XCTAssertThrowsErrorAsync(
            try await store.commitMailboxCursor(
                inboxId: inboxId,
                consumerId: consumer,
                cursor: batch.nextCursor,
                sequence: 0
            )
        ) { error in
            XCTAssertEqual(error as? MailboxSyncError, .cursorRollback)
        }
    }

    func testMailboxConsumerAndCursorSurviveSQLiteReload() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let storeURL = directory.appendingPathComponent("relay.sqlite")
        defer { try? FileManager.default.removeItem(at: directory) }
        let inboxId = InboxAddress.generate()
        let consumer = MailboxConsumerId.generate()
        let original = RelayStore(storeURL: storeURL)
        try await original.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x02]))
        _ = try await original.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumer,
            consumerSigningPublicKey: architectureMailboxPublicKey(0xF4),
            startingSequence: 0
        )
        try await original.deliver(makeEnvelope(counter: 1), to: inboxId)

        let reloaded = RelayStore(storeURL: storeURL)
        try await reloaded.loadFromDisk()
        let batch = try await reloaded.syncMailbox(inboxId: inboxId, consumerId: consumer)
        XCTAssertEqual(batch.events.map(\.sequence), [1])
        try await reloaded.commitMailboxCursor(
            inboxId: inboxId,
            consumerId: consumer,
            cursor: batch.nextCursor,
            sequence: 1
        )
        let remaining = try await reloaded.fetch(inboxId: inboxId)
        XCTAssertTrue(remaining.isEmpty)
    }

    private func makeEnvelope(counter: UInt64) -> ProtocolEnvelopeV1 {
        makeTestProtocolEnvelope(
            conversationId: "architecture-v2-mailbox",
            counter: counter,
            sentAt: Date(timeIntervalSince1970: TimeInterval(1_000 + counter)),
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: 12),
                ciphertext: Data(repeating: UInt8(counter), count: PaddedMessagePlaintext.minimumPaddedBytes),
                tag: Data(repeating: 0x22, count: 16)
            ),
            signature: Data(repeating: 0x33, count: 3_309)
        )
    }
}

private func architectureMailboxPublicKey(_ marker: UInt8) -> Data {
    Data(repeating: marker, count: 1_952)
}

private func XCTAssertThrowsErrorAsync<T>(
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

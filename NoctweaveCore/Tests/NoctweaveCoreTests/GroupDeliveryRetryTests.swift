import Foundation
import SQLite3
import XCTest
@testable import NoctweaveCore

final class GroupDeliveryRetryTests: XCTestCase {
    func testRetryUsesImmutableOriginalRecipientsAcrossPartialAckAndLegacySQLiteReload() async throws {
        let sqliteURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-core-group-retry-\(UUID().uuidString)")
            .appendingPathExtension("sqlite")
        defer { try? FileManager.default.removeItem(at: sqliteURL) }

        let inboxId = InboxAddress.generate()
        let envelope = makeEnvelope(counter: 1)
        let originalRecipients = ["member-a", "member-b"]
        let initialStore = RelayStore(storeURL: sqliteURL, temporalBucketSeconds: 0)
        try await initialStore.registerInbox(
            inboxId: inboxId,
            accessPublicKey: Data([0x50])
        )

        let initialDeliveryCount = try await initialStore.deliverGroupEnvelope(
            envelope,
            to: inboxId,
            recipientFingerprints: originalRecipients
        )
        XCTAssertEqual(initialDeliveryCount, 1)
        let preAckRetryCount = try await initialStore.deliverGroupEnvelope(
            envelope,
            to: inboxId,
            recipientFingerprints: [" member-b ", "member-a"]
        )
        XCTAssertEqual(preAckRetryCount, 1)

        // Simulate the normalized SQLite record written by the previous build,
        // which had only the mutable pending recipient set.
        try stripOriginalRecipientsFromMailboxRecord(at: sqliteURL)

        let migratedStore = RelayStore(storeURL: sqliteURL, temporalBucketSeconds: 0)
        try await migratedStore.loadFromDisk()
        let acknowledged = try await migratedStore.acknowledgeGroupEnvelopes(
            inboxId: inboxId,
            messageIds: [envelope.id],
            recipientFingerprint: "member-a"
        )
        XCTAssertEqual(acknowledged, 1)
        let postAckRetryCount = try await migratedStore.deliverGroupEnvelope(
            envelope,
            to: inboxId,
            recipientFingerprints: originalRecipients
        )
        XCTAssertEqual(postAckRetryCount, 1)
        let acknowledgedRecipientEvents = try await migratedStore.fetchGroupEnvelopes(
            inboxId: inboxId,
            recipientFingerprint: "member-a"
        )
        let pendingRecipientEvents = try await migratedStore.fetchGroupEnvelopes(
            inboxId: inboxId,
            recipientFingerprint: "member-b"
        )
        XCTAssertTrue(acknowledgedRecipientEvents.isEmpty)
        XCTAssertEqual(pendingRecipientEvents.map(\.id), [envelope.id])

        let reloadedStore = RelayStore(storeURL: sqliteURL, temporalBucketSeconds: 0)
        try await reloadedStore.loadFromDisk()
        let postReloadRetryCount = try await reloadedStore.deliverGroupEnvelope(
            envelope,
            to: inboxId,
            recipientFingerprints: originalRecipients
        )
        XCTAssertEqual(postReloadRetryCount, 1)

        await XCTAssertThrowsGroupRetryErrorAsync(
            try await reloadedStore.deliverGroupEnvelope(
                envelope,
                to: inboxId,
                recipientFingerprints: ["member-a", "member-c"]
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .invalidEnvelopePayload)
        }
        await XCTAssertThrowsGroupRetryErrorAsync(
            try await reloadedStore.deliverGroupEnvelope(
                makeEnvelope(id: envelope.id, counter: 2),
                to: inboxId,
                recipientFingerprints: originalRecipients
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .invalidEnvelopePayload)
        }
        await XCTAssertThrowsGroupRetryErrorAsync(
            try await reloadedStore.deliverGroupEnvelope(
                makeEnvelope(counter: 3),
                to: inboxId,
                recipientFingerprints: (0...256).map { "member-\($0)" }
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .invalidEnvelopePayload)
        }
        await XCTAssertThrowsGroupRetryErrorAsync(
            try await reloadedStore.deliverGroupEnvelope(
                makeEnvelope(counter: 4),
                to: inboxId,
                recipientFingerprints: [String(repeating: "x", count: 129)]
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .invalidEnvelopePayload)
        }
    }

    func testRetryAfterAllLegacyAcksDoesNotReopenDeliveryAheadOfV2Cursor() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        let consumerId = MailboxConsumerId.generate()
        let envelope = makeEnvelope(counter: 10)
        let recipients = ["member-a", "member-b"]

        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x51]))
        _ = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: Data(repeating: 0x52, count: 1_952),
            startingSequence: 0
        )
        _ = try await store.deliverGroupEnvelope(
            envelope,
            to: inboxId,
            recipientFingerprints: recipients
        )
        let firstAcknowledgement = try await store.acknowledgeGroupEnvelopes(
            inboxId: inboxId,
            messageIds: [envelope.id],
            recipientFingerprint: "member-a"
        )
        let secondAcknowledgement = try await store.acknowledgeGroupEnvelopes(
            inboxId: inboxId,
            messageIds: [envelope.id],
            recipientFingerprint: "member-b"
        )
        XCTAssertEqual(firstAcknowledgement, 1)
        XCTAssertEqual(secondAcknowledgement, 1)

        let retryCount = try await store.deliverGroupEnvelope(
            envelope,
            to: inboxId,
            recipientFingerprints: recipients
        )
        let legacyEvents = try await store.fetchGroupEnvelopes(
            inboxId: inboxId,
            recipientFingerprint: "member-a"
        )
        let batch = try await store.syncMailbox(inboxId: inboxId, consumerId: consumerId)
        XCTAssertEqual(retryCount, 1)
        XCTAssertTrue(legacyEvents.isEmpty)
        XCTAssertEqual(batch.events.map(\.id), [envelope.id])

        _ = try await store.commitMailboxCursor(
            inboxId: inboxId,
            consumerId: consumerId,
            cursor: batch.nextCursor,
            sequence: batch.nextSequence
        )
        let afterCommit = try await store.fetch(inboxId: inboxId)
        XCTAssertTrue(afterCommit.isEmpty)
    }

    private func makeEnvelope(id: UUID = UUID(), counter: UInt64) -> Envelope {
        Envelope(
            id: id,
            conversationId: "stable-group-retry",
            sessionId: "session-v2",
            senderFingerprint: Data(repeating: 0x44, count: 32).base64EncodedString(),
            sentAt: Date(timeIntervalSince1970: TimeInterval(4_000 + counter)),
            messageCounter: counter,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x41, count: 12),
                ciphertext: Data(repeating: UInt8(truncatingIfNeeded: counter), count: 512),
                tag: Data(repeating: 0x42, count: 16)
            ),
            signature: Data(repeating: 0x43, count: 3_309)
        )
    }
}

private enum GroupRetrySQLiteTestError: Error {
    case operation(String)
}

private let groupRetrySQLiteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

private func stripOriginalRecipientsFromMailboxRecord(at sqliteURL: URL) throws {
    var database: OpaquePointer?
    guard sqlite3_open(sqliteURL.path, &database) == SQLITE_OK, let database else {
        throw GroupRetrySQLiteTestError.operation("open")
    }
    defer { sqlite3_close(database) }

    var rowID: Int64 = 0
    var value = Data()
    var select: OpaquePointer?
    guard sqlite3_prepare_v2(
        database,
        "SELECT rowid, value FROM relay_mailbox_envelopes ORDER BY rowid LIMIT 1;",
        -1,
        &select,
        nil
    ) == SQLITE_OK, let select else {
        throw GroupRetrySQLiteTestError.operation("prepare select")
    }
    defer { sqlite3_finalize(select) }
    guard sqlite3_step(select) == SQLITE_ROW,
          let bytes = sqlite3_column_blob(select, 1) else {
        throw GroupRetrySQLiteTestError.operation("read record")
    }
    rowID = sqlite3_column_int64(select, 0)
    value = Data(bytes: bytes, count: Int(sqlite3_column_bytes(select, 1)))

    guard var object = try JSONSerialization.jsonObject(with: value) as? [String: Any],
          object.removeValue(forKey: "originalGroupRecipientFingerprints") != nil else {
        throw GroupRetrySQLiteTestError.operation("missing new recipient field")
    }
    let legacyValue = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    var update: OpaquePointer?
    guard sqlite3_prepare_v2(
        database,
        "UPDATE relay_mailbox_envelopes SET value = ? WHERE rowid = ?;",
        -1,
        &update,
        nil
    ) == SQLITE_OK, let update else {
        throw GroupRetrySQLiteTestError.operation("prepare update")
    }
    defer { sqlite3_finalize(update) }
    let bindResult = legacyValue.withUnsafeBytes { buffer in
        sqlite3_bind_blob(
            update,
            1,
            buffer.baseAddress,
            Int32(buffer.count),
            groupRetrySQLiteTransient
        )
    }
    guard bindResult == SQLITE_OK,
          sqlite3_bind_int64(update, 2, rowID) == SQLITE_OK,
          sqlite3_step(update) == SQLITE_DONE,
          sqlite3_changes(database) == 1 else {
        throw GroupRetrySQLiteTestError.operation("update record")
    }
}

private func XCTAssertThrowsGroupRetryErrorAsync<T>(
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

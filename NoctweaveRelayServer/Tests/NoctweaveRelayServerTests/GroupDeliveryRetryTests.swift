import Foundation
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite
#endif
import XCTest
@testable import NoctweaveRelayServer

final class GroupDeliveryRetryTests: XCTestCase {
    func testRetryUsesImmutableOriginalRecipientsAcrossPartialAckAndLegacySQLiteReload() throws {
        let sqliteURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-linux-group-retry-\(UUID().uuidString)")
            .appendingPathExtension("sqlite")
        defer { try? FileManager.default.removeItem(at: sqliteURL) }

        let inboxId = InboxAddress.generate()
        let envelope = makeEnvelope(counter: 1)
        let originalRecipients = ["member-a", "member-b"]
        let initialStore = RelayStore(
            fileURL: sqliteURL,
            maxInboxMessages: nil,
            temporalBucketSeconds: 0
        )
        try initialStore.registerInbox(
            inboxId: inboxId,
            accessPublicKey: Data([0x50])
        )

        XCTAssertEqual(
            try initialStore.deliverGroupEnvelope(
                envelope,
                to: inboxId,
                recipientFingerprints: originalRecipients
            ),
            1
        )
        XCTAssertEqual(
            try initialStore.deliverGroupEnvelope(
                envelope,
                to: inboxId,
                recipientFingerprints: [" member-b ", "member-a"]
            ),
            1
        )

        try stripLinuxOriginalRecipientsFromMailboxRecord(at: sqliteURL)

        let migratedStore = RelayStore(
            fileURL: sqliteURL,
            maxInboxMessages: nil,
            temporalBucketSeconds: 0
        )
        try migratedStore.load()
        XCTAssertEqual(
            try migratedStore.acknowledgeGroupEnvelopes(
                inboxId: inboxId,
                messageIds: [envelope.id],
                recipientFingerprint: "member-a"
            ),
            1
        )
        XCTAssertEqual(
            try migratedStore.deliverGroupEnvelope(
                envelope,
                to: inboxId,
                recipientFingerprints: originalRecipients
            ),
            1
        )
        XCTAssertTrue(
            migratedStore.fetchGroupEnvelopes(
                inboxId: inboxId,
                recipientFingerprint: "member-a",
                maxCount: nil
            ).isEmpty
        )
        XCTAssertEqual(
            migratedStore.fetchGroupEnvelopes(
                inboxId: inboxId,
                recipientFingerprint: "member-b",
                maxCount: nil
            ).map(\.id),
            [envelope.id]
        )

        let reloadedStore = RelayStore(
            fileURL: sqliteURL,
            maxInboxMessages: nil,
            temporalBucketSeconds: 0
        )
        try reloadedStore.load()
        XCTAssertEqual(
            try reloadedStore.deliverGroupEnvelope(
                envelope,
                to: inboxId,
                recipientFingerprints: originalRecipients
            ),
            1
        )
        XCTAssertThrowsError(
            try reloadedStore.deliverGroupEnvelope(
                envelope,
                to: inboxId,
                recipientFingerprints: ["member-a", "member-c"]
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .invalidEnvelopePayload)
        }
        XCTAssertThrowsError(
            try reloadedStore.deliverGroupEnvelope(
                makeEnvelope(id: envelope.id, counter: 2),
                to: inboxId,
                recipientFingerprints: originalRecipients
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .invalidEnvelopePayload)
        }
        XCTAssertThrowsError(
            try reloadedStore.deliverGroupEnvelope(
                makeEnvelope(counter: 3),
                to: inboxId,
                recipientFingerprints: (0...256).map { "member-\($0)" }
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .invalidEnvelopePayload)
        }
        XCTAssertThrowsError(
            try reloadedStore.deliverGroupEnvelope(
                makeEnvelope(counter: 4),
                to: inboxId,
                recipientFingerprints: [String(repeating: "x", count: 129)]
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .invalidEnvelopePayload)
        }
    }

    func testRetryAfterAllLegacyAcksDoesNotReopenDeliveryAheadOfV2Cursor() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        let consumerId = MailboxConsumerId.generate()
        let envelope = makeEnvelope(counter: 10)
        let recipients = ["member-a", "member-b"]

        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x51]))
        _ = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: Data(
                repeating: 0x52,
                count: OQSSignatureVerifier.mlDSA65PublicKeyBytes
            ),
            startingSequence: 0
        )
        _ = try store.deliverGroupEnvelope(
            envelope,
            to: inboxId,
            recipientFingerprints: recipients
        )
        XCTAssertEqual(
            try store.acknowledgeGroupEnvelopes(
                inboxId: inboxId,
                messageIds: [envelope.id],
                recipientFingerprint: "member-a"
            ),
            1
        )
        XCTAssertEqual(
            try store.acknowledgeGroupEnvelopes(
                inboxId: inboxId,
                messageIds: [envelope.id],
                recipientFingerprint: "member-b"
            ),
            1
        )

        XCTAssertEqual(
            try store.deliverGroupEnvelope(
                envelope,
                to: inboxId,
                recipientFingerprints: recipients
            ),
            1
        )
        XCTAssertTrue(
            store.fetchGroupEnvelopes(
                inboxId: inboxId,
                recipientFingerprint: "member-a",
                maxCount: nil
            ).isEmpty
        )
        let batch = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: consumerId,
            cursor: nil,
            maxCount: nil
        )
        XCTAssertEqual(batch.events.map(\.id), [envelope.id])
        _ = try store.commitMailboxCursor(
            inboxId: inboxId,
            consumerId: consumerId,
            cursor: batch.nextCursor,
            sequence: batch.nextSequence
        )
        XCTAssertTrue(store.fetch(inboxId: inboxId, maxCount: nil).isEmpty)
    }

    private func makeEnvelope(id: UUID = UUID(), counter: UInt64) -> Envelope {
        Envelope(
            id: id,
            conversationId: "stable-group-retry",
            sessionId: "session-v2",
            senderFingerprint: Data(repeating: 0x44, count: 32).base64EncodedString(),
            sentAt: Date(timeIntervalSince1970: TimeInterval(4_000 + counter)),
            messageCounter: counter,
            kemCiphertext: nil,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x41, count: 12),
                ciphertext: Data(repeating: UInt8(truncatingIfNeeded: counter), count: 512),
                tag: Data(repeating: 0x42, count: 16)
            ),
            signature: Data(
                repeating: 0x43,
                count: OQSSignatureVerifier.mlDSA65SignatureBytes
            )
        )
    }
}

private enum LinuxGroupRetrySQLiteTestError: Error {
    case operation(String)
}

private let linuxGroupRetrySQLiteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

private func stripLinuxOriginalRecipientsFromMailboxRecord(at sqliteURL: URL) throws {
    var database: OpaquePointer?
    guard sqlite3_open(sqliteURL.path, &database) == SQLITE_OK, let database else {
        throw LinuxGroupRetrySQLiteTestError.operation("open")
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
        throw LinuxGroupRetrySQLiteTestError.operation("prepare select")
    }
    defer { sqlite3_finalize(select) }
    guard sqlite3_step(select) == SQLITE_ROW,
          let bytes = sqlite3_column_blob(select, 1) else {
        throw LinuxGroupRetrySQLiteTestError.operation("read record")
    }
    rowID = sqlite3_column_int64(select, 0)
    value = Data(bytes: bytes, count: Int(sqlite3_column_bytes(select, 1)))

    guard var object = try JSONSerialization.jsonObject(with: value) as? [String: Any],
          object.removeValue(forKey: "originalGroupRecipientFingerprints") != nil else {
        throw LinuxGroupRetrySQLiteTestError.operation("missing new recipient field")
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
        throw LinuxGroupRetrySQLiteTestError.operation("prepare update")
    }
    defer { sqlite3_finalize(update) }
    let bindResult = legacyValue.withUnsafeBytes { buffer in
        sqlite3_bind_blob(
            update,
            1,
            buffer.baseAddress,
            Int32(buffer.count),
            linuxGroupRetrySQLiteTransient
        )
    }
    guard bindResult == SQLITE_OK,
          sqlite3_bind_int64(update, 2, rowID) == SQLITE_OK,
          sqlite3_step(update) == SQLITE_DONE,
          sqlite3_changes(database) == 1 else {
        throw LinuxGroupRetrySQLiteTestError.operation("update record")
    }
}

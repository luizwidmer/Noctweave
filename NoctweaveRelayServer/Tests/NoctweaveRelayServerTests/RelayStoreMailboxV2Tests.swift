import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class RelayStoreMailboxV2Tests: XCTestCase {
    func testIdempotentRegistrationCannotReplaceBoundConsumerSigningKey() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        let consumer = MailboxConsumerId.generate()
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x0A]))

        let first = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumer,
            consumerSigningPublicKey: linuxMailboxPublicKey(0xA1),
            startingSequence: 0
        )
        let replay = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumer,
            consumerSigningPublicKey: linuxMailboxPublicKey(0xA1),
            startingSequence: 0
        )
        XCTAssertEqual(first, replay)
        XCTAssertEqual(first.consumerSigningPublicKey, linuxMailboxPublicKey(0xA1))
        XCTAssertThrowsError(
            try store.registerMailboxConsumer(
                inboxId: inboxId,
                consumerId: consumer,
                consumerSigningPublicKey: linuxMailboxPublicKey(0xA2),
                startingSequence: 0
            )
        ) { error in
            XCTAssertEqual(error as? MailboxSyncError, .consumerSigningKeyMismatch)
        }
    }

    func testLegacyConsumerRegistrationDecodesWithoutCredentialAndFailsValidation() throws {
        let consumer = MailboxConsumerId.generate()
        let legacy = LegacyMailboxConsumerRegistration(
            consumerId: consumer,
            state: .active,
            committedSequence: 0,
            registeredAt: Date(timeIntervalSince1970: 100),
            revokedAt: nil
        )
        let decoded = try JSONDecoder().decode(
            MailboxConsumerRegistration.self,
            from: JSONEncoder().encode(legacy)
        )
        XCTAssertNil(decoded.consumerSigningPublicKey)
        XCTAssertFalse(decoded.isStructurallyValid)
    }

    func testRevokedConsumerHistoryIsBoundedWithoutExhaustingDeviceChurn() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x0B]))

        var current = MailboxConsumerId.generate()
        _ = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: current,
            consumerSigningPublicKey: linuxMailboxPublicKey(1),
            startingSequence: 0
        )
        for index in 1..<80 {
            let replacement = MailboxConsumerId.generate()
            _ = try store.registerMailboxConsumer(
                inboxId: inboxId,
                consumerId: replacement,
                consumerSigningPublicKey: linuxMailboxPublicKey(UInt8(index + 1)),
                sponsorConsumerId: current,
                startingSequence: 0
            )
            _ = try store.revokeMailboxConsumer(inboxId: inboxId, consumerId: current)
            current = replacement
        }

        XCTAssertEqual(store.mailboxConsumers(inboxId: inboxId).count, 64)
        XCTAssertTrue(store.hasMailboxConsumerBindings(inboxId: inboxId))
        let replacement = MailboxConsumerId.generate()
        let registered = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: replacement,
            consumerSigningPublicKey: linuxMailboxPublicKey(0xFE),
            sponsorConsumerId: current,
            startingSequence: 0
        )
        XCTAssertEqual(registered.state, .active)
    }

    func testRegistrationDefaultsToHighWatermarkAndAllowsAuthorizedRetainedStart() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x00]))
        let envelope = makeEnvelope()
        _ = try store.deliver(envelope, to: inboxId)
        let currentOnly = MailboxConsumerId.generate()
        let recovering = MailboxConsumerId.generate()

        let currentRegistration = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: currentOnly,
            consumerSigningPublicKey: linuxMailboxPublicKey(0xC1)
        )
        XCTAssertEqual(currentRegistration.committedSequence, 1)
        XCTAssertTrue(
            try store.syncMailbox(
                inboxId: inboxId,
                consumerId: currentOnly,
                cursor: nil,
                maxCount: nil
            ).events.isEmpty
        )

        let recoveryRegistration = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: recovering,
            consumerSigningPublicKey: linuxMailboxPublicKey(0xC2),
            sponsorConsumerId: currentOnly,
            startingSequence: 0
        )
        XCTAssertEqual(recoveryRegistration.committedSequence, 0)
        XCTAssertEqual(
            try store.syncMailbox(
                inboxId: inboxId,
                consumerId: recovering,
                cursor: nil,
                maxCount: nil
            ).events.map(\.id),
            [envelope.id]
        )
    }

    func testDirectAndGroupDeliveryAreIdempotentAndShareOneOrderedStream() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x01]))
        let consumer = MailboxConsumerId.generate(
            nonce: UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!
        )
        try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumer,
            consumerSigningPublicKey: linuxMailboxPublicKey(0xC3)
        )
        let direct = makeEnvelope(id: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!)
        let group = makeEnvelope(id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!)

        XCTAssertEqual(try store.deliver(direct, to: inboxId), 1)
        XCTAssertEqual(try store.deliver(direct, to: inboxId), 1)
        XCTAssertEqual(
            try store.deliverGroupEnvelope(group, to: inboxId, recipientFingerprints: ["member-a"]),
            2
        )
        XCTAssertEqual(
            try store.deliverGroupEnvelope(group, to: inboxId, recipientFingerprints: ["member-a"]),
            2
        )

        let batch = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: consumer,
            cursor: nil,
            maxCount: nil
        )
        XCTAssertEqual(batch.events.map(\.sequence), [1, 2])
        XCTAssertEqual(batch.events.map(\.id), [direct.id, group.id])
        XCTAssertEqual(batch.highWatermark, 2)
        XCTAssertFalse(batch.hasMore)
        XCTAssertTrue(batch.isStructurallyValid)
    }

    func testConsumersCommitIndependentlyAndLegacyAckCannotDeleteTheirData() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x02]))
        let phone = MailboxConsumerId.generate(
            nonce: UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!
        )
        let desktop = MailboxConsumerId.generate(
            nonce: UUID(uuidString: "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC")!
        )
        try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: phone,
            consumerSigningPublicKey: linuxMailboxPublicKey(0xC4)
        )
        try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: desktop,
            consumerSigningPublicKey: linuxMailboxPublicKey(0xC5),
            sponsorConsumerId: phone
        )
        let first = makeEnvelope()
        let second = makeEnvelope()
        _ = try store.deliver(first, to: inboxId)
        _ = try store.deliver(second, to: inboxId)

        let phoneBatch = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: phone,
            cursor: nil,
            maxCount: nil
        )
        let desktopBatch = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: desktop,
            cursor: nil,
            maxCount: nil
        )
        XCTAssertEqual(try store.acknowledge(inboxId: inboxId, messageIds: [first.id, second.id]), 0)
        XCTAssertEqual(store.fetch(inboxId: inboxId, maxCount: nil).count, 2)

        XCTAssertEqual(
            try store.commitMailboxCursor(
                inboxId: inboxId,
                consumerId: phone,
                cursor: phoneBatch.nextCursor,
                sequence: phoneBatch.nextSequence
            ).committedSequence,
            2
        )
        XCTAssertEqual(store.fetch(inboxId: inboxId, maxCount: nil).count, 2)
        XCTAssertEqual(
            try store.commitMailboxCursor(
                inboxId: inboxId,
                consumerId: desktop,
                cursor: desktopBatch.nextCursor,
                sequence: desktopBatch.nextSequence
            ).committedSequence,
            2
        )
        XCTAssertTrue(store.fetch(inboxId: inboxId, maxCount: nil).isEmpty)

        let caughtUp = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: phone,
            cursor: phoneBatch.nextCursor,
            maxCount: nil
        )
        XCTAssertTrue(caughtUp.events.isEmpty)
        XCTAssertEqual(caughtUp.retentionFloor, 2)
        XCTAssertTrue(caughtUp.isStructurallyValid)
    }

    func testLegacyGroupAckLeavesEnvelopeForActiveV2ConsumerUntilCommit() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x03]))
        let consumer = MailboxConsumerId.generate(
            nonce: UUID(uuidString: "DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD")!
        )
        try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumer,
            consumerSigningPublicKey: linuxMailboxPublicKey(0xC6)
        )
        let envelope = makeEnvelope()
        _ = try store.deliverGroupEnvelope(
            envelope,
            to: inboxId,
            recipientFingerprints: ["member-a"]
        )
        let batch = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: consumer,
            cursor: nil,
            maxCount: nil
        )

        XCTAssertEqual(
            try store.acknowledgeGroupEnvelopes(
                inboxId: inboxId,
                messageIds: [envelope.id],
                recipientFingerprint: "member-a"
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
        XCTAssertEqual(
            try store.syncMailbox(
                inboxId: inboxId,
                consumerId: consumer,
                cursor: nil,
                maxCount: nil
            ).events.map(\.id),
            [envelope.id]
        )
        _ = try store.commitMailboxCursor(
            inboxId: inboxId,
            consumerId: consumer,
            cursor: batch.nextCursor,
            sequence: batch.nextSequence
        )
        XCTAssertTrue(store.fetch(inboxId: inboxId, maxCount: nil).isEmpty)
    }

    func testRevocationRemovesConsumerFromRetentionAndRejectsFutureSync() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x04]))
        let active = MailboxConsumerId.generate(
            nonce: UUID(uuidString: "EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE")!
        )
        let lost = MailboxConsumerId.generate(
            nonce: UUID(uuidString: "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")!
        )
        try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: active,
            consumerSigningPublicKey: linuxMailboxPublicKey(0xC7)
        )
        try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: lost,
            consumerSigningPublicKey: linuxMailboxPublicKey(0xC8),
            sponsorConsumerId: active
        )
        _ = try store.deliver(makeEnvelope(), to: inboxId)
        let activeBatch = try store.syncMailbox(
            inboxId: inboxId,
            consumerId: active,
            cursor: nil,
            maxCount: nil
        )
        _ = try store.commitMailboxCursor(
            inboxId: inboxId,
            consumerId: active,
            cursor: activeBatch.nextCursor,
            sequence: activeBatch.nextSequence
        )
        XCTAssertEqual(store.fetch(inboxId: inboxId, maxCount: nil).count, 1)

        let revoked = try store.revokeMailboxConsumer(inboxId: inboxId, consumerId: lost)
        XCTAssertEqual(revoked.state, .revoked)
        XCTAssertTrue(store.fetch(inboxId: inboxId, maxCount: nil).isEmpty)
        XCTAssertThrowsError(
            try store.syncMailbox(inboxId: inboxId, consumerId: lost, cursor: nil, maxCount: nil)
        ) { error in
            XCTAssertEqual(error as? MailboxSyncError, .consumerRevoked)
        }
    }

    func testCursorAuthenticationAndConsumerStateSurviveSQLiteReload() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-mailbox-v2-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("relay.json")
        let inboxId = InboxAddress.generate()
        let consumer = MailboxConsumerId.generate(
            nonce: UUID(uuidString: "12345678-1234-1234-1234-123456789ABC")!
        )

        let writer = RelayStore(fileURL: storeURL, maxInboxMessages: nil, temporalBucketSeconds: 0)
        try writer.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x05]))
        try writer.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumer,
            consumerSigningPublicKey: linuxMailboxPublicKey(0xC9)
        )
        _ = try writer.deliver(makeEnvelope(), to: inboxId)
        let batch = try writer.syncMailbox(
            inboxId: inboxId,
            consumerId: consumer,
            cursor: nil,
            maxCount: nil
        )

        let reader = RelayStore(fileURL: storeURL, maxInboxMessages: nil, temporalBucketSeconds: 0)
        try reader.load()
        XCTAssertEqual(
            try reader.commitMailboxCursor(
                inboxId: inboxId,
                consumerId: consumer,
                cursor: batch.nextCursor,
                sequence: batch.nextSequence
            ).committedSequence,
            1
        )

        let tampered = MailboxCursor(rawValue: String(batch.nextCursor.rawValue.dropLast()) + "A")
        XCTAssertThrowsError(
            try reader.commitMailboxCursor(
                inboxId: inboxId,
                consumerId: consumer,
                cursor: tampered,
                sequence: batch.nextSequence
            )
        ) { error in
            XCTAssertEqual(error as? MailboxSyncError, .invalidCursor)
        }
    }

    private func makeEnvelope(id: UUID = UUID()) -> Envelope {
        Envelope(
            id: id,
            conversationId: "mailbox-v2-conversation",
            sessionId: UUID().uuidString,
            senderFingerprint: Data(repeating: 0x44, count: 32).base64EncodedString(),
            sentAt: Date(timeIntervalSince1970: 1_800_000_000),
            messageCounter: 1,
            kemCiphertext: nil,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0xA1, count: 12),
                ciphertext: Data(repeating: 0x01, count: 512),
                tag: Data(repeating: 0xB2, count: 16)
            ),
            signature: Data(
                repeating: 0x99,
                count: OQSSignatureVerifier.mlDSA65SignatureBytes
            )
        )
    }
}

private struct LegacyMailboxConsumerRegistration: Codable {
    let consumerId: MailboxConsumerId
    let state: MailboxConsumerState
    let committedSequence: UInt64
    let registeredAt: Date
    let revokedAt: Date?
}

private func linuxMailboxPublicKey(_ marker: UInt8) -> Data {
    Data(repeating: marker, count: OQSSignatureVerifier.mlDSA65PublicKeyBytes)
}

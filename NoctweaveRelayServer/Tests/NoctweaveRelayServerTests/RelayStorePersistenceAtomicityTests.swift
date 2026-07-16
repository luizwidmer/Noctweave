import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class RelayStorePersistenceAtomicityTests: XCTestCase {
    func testFailedDirectAndGroupDeliveryRollBackThenExactRetryPersistsWithoutSequenceGap() throws {
        let fixture = try makeLinuxPersistentRelayFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let store = RelayStore(
            fileURL: fixture.storeURL,
            maxInboxMessages: nil,
            temporalBucketSeconds: 0
        )
        let inboxId = InboxAddress.generate()
        let recipient = canonicalLinuxRelayFingerprint(0x31)
        let direct = structurallyValidLinuxEnvelope(marker: 0x11)
        let group = structurallyValidLinuxEnvelope(marker: 0x12)
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x01]))

        store.failNextPersistenceForTesting()
        XCTAssertThrowsError(try store.deliver(direct, to: inboxId))
        XCTAssertTrue(store.fetch(inboxId: inboxId, maxCount: nil).isEmpty)
        XCTAssertEqual(try store.deliver(direct, to: inboxId), 1)

        store.failNextPersistenceForTesting()
        XCTAssertThrowsError(
            try store.deliverGroupEnvelope(
                group,
                to: inboxId,
                recipientFingerprints: [recipient]
            )
        )
        XCTAssertTrue(
            store.fetchGroupEnvelopes(
                inboxId: inboxId,
                recipientFingerprint: recipient,
                maxCount: nil
            ).isEmpty
        )
        XCTAssertEqual(
            try store.deliverGroupEnvelope(
                group,
                to: inboxId,
                recipientFingerprints: [recipient]
            ),
            2
        )

        let reloaded = RelayStore(
            fileURL: fixture.storeURL,
            maxInboxMessages: nil,
            temporalBucketSeconds: 0
        )
        try reloaded.load()
        try reloaded.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x01]))
        let consumerId = MailboxConsumerId.generate()
        _ = try reloaded.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: Data(
                repeating: 0xA1,
                count: OQSSignatureVerifier.mlDSA65PublicKeyBytes
            ),
            startingSequence: 0
        )
        let batch = try reloaded.syncMailbox(
            inboxId: inboxId,
            consumerId: consumerId,
            cursor: nil,
            maxCount: 10
        )
        XCTAssertEqual(batch.events.map(\.sequence), [1, 2])
        XCTAssertEqual(batch.events.map(\.envelope.id), [direct.id, group.id])
    }

    func testFailedDestructiveAcknowledgementsRollBackThenExactRetryPersists() throws {
        let fixture = try makeLinuxPersistentRelayFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let store = RelayStore(
            fileURL: fixture.storeURL,
            maxInboxMessages: nil,
            temporalBucketSeconds: 0
        )
        let inboxId = InboxAddress.generate()
        let recipient = canonicalLinuxRelayFingerprint(0x32)
        let direct = structurallyValidLinuxEnvelope(marker: 0x21)
        let group = structurallyValidLinuxEnvelope(marker: 0x22)
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x01]))
        _ = try store.deliver(direct, to: inboxId)
        _ = try store.deliverGroupEnvelope(
            group,
            to: inboxId,
            recipientFingerprints: [recipient]
        )

        store.failNextPersistenceForTesting()
        XCTAssertThrowsError(
            try store.acknowledge(inboxId: inboxId, messageIds: [direct.id])
        )
        XCTAssertTrue(
            store.fetch(inboxId: inboxId, maxCount: nil).contains { $0.id == direct.id }
        )
        XCTAssertEqual(
            try store.acknowledge(inboxId: inboxId, messageIds: [direct.id]),
            1
        )

        store.failNextPersistenceForTesting()
        XCTAssertThrowsError(
            try store.acknowledgeGroupEnvelopes(
                inboxId: inboxId,
                messageIds: [group.id],
                recipientFingerprint: recipient
            )
        )
        XCTAssertEqual(
            store.fetchGroupEnvelopes(
                inboxId: inboxId,
                recipientFingerprint: recipient,
                maxCount: nil
            ).map(\.id),
            [group.id]
        )
        XCTAssertEqual(
            try store.acknowledgeGroupEnvelopes(
                inboxId: inboxId,
                messageIds: [group.id],
                recipientFingerprint: recipient
            ),
            1
        )

        let reloaded = RelayStore(
            fileURL: fixture.storeURL,
            maxInboxMessages: nil,
            temporalBucketSeconds: 0
        )
        try reloaded.load()
        XCTAssertTrue(reloaded.fetch(inboxId: inboxId, maxCount: nil).isEmpty)
    }

    func testMalformedEnvelopeIsRejectedBeforeMailboxSequenceAllocation() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        let malformed = structurallyValidLinuxEnvelope(marker: 0x41, signatureBytes: 100_000)
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x01]))
        XCTAssertThrowsError(try store.deliver(malformed, to: inboxId))
        XCTAssertThrowsError(
            try store.deliverGroupEnvelope(
                malformed,
                to: inboxId,
                recipientFingerprints: [canonicalLinuxRelayFingerprint(0x42)]
            )
        )
        XCTAssertTrue(store.fetch(inboxId: inboxId, maxCount: nil).isEmpty)
    }

    func testFailedConsumerRegistrationAndRevocationRollBackBeforeIdempotentRetry() throws {
        let fixture = try makeLinuxPersistentRelayFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let store = RelayStore(
            fileURL: fixture.storeURL,
            maxInboxMessages: nil,
            temporalBucketSeconds: 0
        )
        let inboxId = InboxAddress.generate()
        let consumerId = MailboxConsumerId.generate()
        let publicKey = Data(
            repeating: 0xA2,
            count: OQSSignatureVerifier.mlDSA65PublicKeyBytes
        )
        try store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x01]))

        store.failNextPersistenceForTesting()
        XCTAssertThrowsError(
            try store.registerMailboxConsumer(
                inboxId: inboxId,
                consumerId: consumerId,
                consumerSigningPublicKey: publicKey
            )
        )
        XCTAssertTrue(store.mailboxConsumers(inboxId: inboxId).isEmpty)
        _ = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: publicKey
        )

        store.failNextPersistenceForTesting()
        XCTAssertThrowsError(
            try store.revokeMailboxConsumer(inboxId: inboxId, consumerId: consumerId)
        )
        XCTAssertEqual(
            store.mailboxConsumer(inboxId: inboxId, consumerId: consumerId)?.state,
            .active
        )
        _ = try store.revokeMailboxConsumer(inboxId: inboxId, consumerId: consumerId)

        let reloaded = RelayStore(
            fileURL: fixture.storeURL,
            maxInboxMessages: nil,
            temporalBucketSeconds: 0
        )
        try reloaded.load()
        XCTAssertEqual(
            reloaded.mailboxConsumer(inboxId: inboxId, consumerId: consumerId)?.state,
            .revoked
        )
    }

    func testFailedExternalAttachmentReplacementPreservesDurableBlobAndCleansOrphan() throws {
        let fixture = try makeLinuxPersistentRelayFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let blobStore = LinuxAtomicityBlobStore()
        let store = RelayStore(
            fileURL: fixture.storeURL,
            maxInboxMessages: nil,
            attachmentBlobStore: blobStore,
            temporalBucketSeconds: 0
        )
        let attachmentId = UUID()
        let first = linuxAtomicityAttachmentPayload(0x61)
        let replacement = linuxAtomicityAttachmentPayload(0x62)
        _ = try store.storeAttachment(
            attachmentId: attachmentId,
            chunkIndex: 0,
            payload: first,
            ttlSeconds: 300
        )
        XCTAssertEqual(blobStore.activeBlobCount, 1)

        store.failNextPersistenceForTesting()
        XCTAssertThrowsError(
            try store.storeAttachment(
                attachmentId: attachmentId,
                chunkIndex: 0,
                payload: replacement,
                ttlSeconds: 300
            )
        )
        XCTAssertEqual(
            try store.fetchAttachment(attachmentId: attachmentId, chunkIndex: 0)?.payload,
            first
        )
        XCTAssertEqual(blobStore.activeBlobCount, 1)

        _ = try store.storeAttachment(
            attachmentId: attachmentId,
            chunkIndex: 0,
            payload: replacement,
            ttlSeconds: 300
        )
        let reloaded = RelayStore(
            fileURL: fixture.storeURL,
            maxInboxMessages: nil,
            attachmentBlobStore: blobStore,
            temporalBucketSeconds: 0
        )
        try reloaded.load()
        XCTAssertEqual(
            try reloaded.fetchAttachment(attachmentId: attachmentId, chunkIndex: 0)?.payload,
            replacement
        )
        XCTAssertEqual(blobStore.activeBlobCount, 1)
    }
}

private func makeLinuxPersistentRelayFixture() throws -> (directory: URL, storeURL: URL) {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("noctweave-linux-relay-atomicity-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return (directory, directory.appendingPathComponent("relay.sqlite"))
}

private func structurallyValidLinuxEnvelope(
    marker: UInt8,
    signatureBytes: Int = OQSSignatureVerifier.mlDSA65SignatureBytes
) -> Envelope {
    Envelope(
        conversationId: "atomicity-\(marker)",
        senderFingerprint: canonicalLinuxRelayFingerprint(marker),
        sentAt: Date(timeIntervalSince1970: 1_700_000_000),
        messageCounter: UInt64(marker),
        payload: EncryptedPayload(
            nonce: Data(repeating: marker, count: 12),
            ciphertext: Data(repeating: marker, count: 512),
            tag: Data(repeating: marker, count: 16)
        ),
        signature: Data(repeating: marker, count: signatureBytes)
    )
}

private func canonicalLinuxRelayFingerprint(_ marker: UInt8) -> String {
    Data(repeating: marker, count: 32).base64EncodedString()
}

private func linuxAtomicityAttachmentPayload(_ marker: UInt8) -> EncryptedPayload {
    EncryptedPayload(
        nonce: Data(repeating: marker, count: 12),
        ciphertext: Data(repeating: marker, count: 32),
        tag: Data(repeating: marker, count: 16)
    )
}

private final class LinuxAtomicityBlobStore: AttachmentBlobStore {
    let backendName = "atomicity-test"
    private var blobs: [String: Data] = [:]
    private var nextLocator = 0

    var activeBlobCount: Int { blobs.count }

    func put(
        _ data: Data,
        attachmentId: UUID,
        chunkIndex: Int,
        expiresAt: Date
    ) throws -> AttachmentExternalRecord {
        nextLocator += 1
        let locator = "\(attachmentId.uuidString)-\(chunkIndex)-\(nextLocator)"
        blobs[locator] = data
        return AttachmentExternalRecord(
            backend: backendName,
            locator: locator,
            byteCount: data.count,
            sha256Hex: AttachmentBlobDigest.sha256Hex(data),
            expiresAt: expiresAt
        )
    }

    func get(_ record: AttachmentExternalRecord) throws -> Data {
        guard let data = blobs[record.locator] else {
            throw AttachmentBlobStoreError.fetchFailed("missing atomicity blob")
        }
        return data
    }

    func delete(_ record: AttachmentExternalRecord) {
        blobs.removeValue(forKey: record.locator)
    }
}

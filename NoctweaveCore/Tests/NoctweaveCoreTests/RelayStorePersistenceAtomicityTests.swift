import Foundation
import XCTest
@testable import NoctweaveCore

final class RelayStorePersistenceAtomicityTests: XCTestCase {
    func testFailedDirectDeliveryRollsBackThenExactRetryPersistsWithoutSequenceGap() async throws {
        let fixture = try makeCorePersistentRelayFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let store = RelayStore(storeURL: fixture.storeURL, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        let direct = structurallyValidCoreEnvelope(marker: 0x11)
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x01]))

        await store.failNextPersistenceForTesting()
        await assertCoreFailure {
            _ = try await store.deliver(direct, to: inboxId)
        }
        let afterFailedDirect = try await store.fetch(inboxId: inboxId)
        XCTAssertTrue(afterFailedDirect.isEmpty)
        let directCount = try await store.deliver(direct, to: inboxId)
        XCTAssertEqual(directCount, 1)

        let reloaded = RelayStore(storeURL: fixture.storeURL, temporalBucketSeconds: 0)
        try await reloaded.loadFromDisk()
        try await reloaded.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x01]))
        let consumerId = MailboxConsumerId.generate()
        _ = try await reloaded.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: Data(repeating: 0xA1, count: 1_952),
            startingSequence: 0
        )
        let batch = try await reloaded.syncMailbox(
            inboxId: inboxId,
            consumerId: consumerId,
            maxCount: 10
        )
        XCTAssertEqual(batch.events.map(\.sequence), [1])
        XCTAssertEqual(batch.events.map(\.envelope.id), [direct.id])
    }

    func testMalformedEnvelopeIsRejectedBeforeMailboxSequenceAllocation() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        let malformed = structurallyValidCoreEnvelope(marker: 0x41, signatureBytes: 100_000)
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x01]))
        await assertCoreFailure {
            _ = try await store.deliver(malformed, to: inboxId)
        }
        let retained = try await store.fetch(inboxId: inboxId)
        XCTAssertTrue(retained.isEmpty)
    }

    func testFailedConsumerRegistrationAndRevocationRollBackBeforeIdempotentRetry() async throws {
        let fixture = try makeCorePersistentRelayFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let store = RelayStore(storeURL: fixture.storeURL, temporalBucketSeconds: 0)
        let inboxId = InboxAddress.generate()
        let consumerId = MailboxConsumerId.generate()
        let publicKey = Data(repeating: 0xA2, count: 1_952)
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x01]))

        await store.failNextPersistenceForTesting()
        await assertCoreFailure {
            _ = try await store.registerMailboxConsumer(
                inboxId: inboxId,
                consumerId: consumerId,
                consumerSigningPublicKey: publicKey
            )
        }
        let afterFailedRegistration = await store.mailboxConsumers(inboxId: inboxId)
        XCTAssertTrue(afterFailedRegistration.isEmpty)
        _ = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: publicKey
        )

        await store.failNextPersistenceForTesting()
        await assertCoreFailure {
            _ = try await store.revokeMailboxConsumer(
                inboxId: inboxId,
                consumerId: consumerId
            )
        }
        let afterFailedRevocation = await store.mailboxConsumer(
            inboxId: inboxId,
            consumerId: consumerId
        )
        XCTAssertEqual(afterFailedRevocation?.state, .active)
        _ = try await store.revokeMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumerId
        )

        let reloaded = RelayStore(storeURL: fixture.storeURL, temporalBucketSeconds: 0)
        try await reloaded.loadFromDisk()
        let persisted = await reloaded.mailboxConsumer(
            inboxId: inboxId,
            consumerId: consumerId
        )
        XCTAssertEqual(persisted?.state, .revoked)
    }

    func testFailedExternalAttachmentReplacementPreservesDurableBlobAndCleansOrphan() async throws {
        let fixture = try makeCorePersistentRelayFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let blobStore = CoreAtomicityBlobStore()
        let store = RelayStore(
            storeURL: fixture.storeURL,
            temporalBucketSeconds: 0,
            attachmentBlobStore: blobStore
        )
        let attachmentId = UUID()
        let first = atomicityAttachmentPayload(0x61)
        let replacement = atomicityAttachmentPayload(0x62)
        _ = try await store.storeAttachment(
            attachmentId: attachmentId,
            chunkIndex: 0,
            payload: first,
            ttlSeconds: 300
        )
        XCTAssertEqual(blobStore.activeBlobCount, 1)

        await store.failNextPersistenceForTesting()
        await assertCoreFailure {
            _ = try await store.storeAttachment(
                attachmentId: attachmentId,
                chunkIndex: 0,
                payload: replacement,
                ttlSeconds: 300
            )
        }
        let afterFailure = try await store.fetchAttachment(
            attachmentId: attachmentId,
            chunkIndex: 0
        )
        XCTAssertEqual(afterFailure?.payload, first)
        XCTAssertEqual(blobStore.activeBlobCount, 1)

        _ = try await store.storeAttachment(
            attachmentId: attachmentId,
            chunkIndex: 0,
            payload: replacement,
            ttlSeconds: 300
        )
        let reloaded = RelayStore(
            storeURL: fixture.storeURL,
            temporalBucketSeconds: 0,
            attachmentBlobStore: blobStore
        )
        try await reloaded.loadFromDisk()
        let persisted = try await reloaded.fetchAttachment(
            attachmentId: attachmentId,
            chunkIndex: 0
        )
        XCTAssertEqual(persisted?.payload, replacement)
        XCTAssertEqual(blobStore.activeBlobCount, 1)
    }
}

private func makeCorePersistentRelayFixture() throws -> (directory: URL, storeURL: URL) {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("noctweave-core-relay-atomicity-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return (directory, directory.appendingPathComponent("relay.sqlite"))
}

private func structurallyValidCoreEnvelope(
    marker: UInt8,
    signatureBytes: Int = 3_309
) -> Envelope {
    Envelope(
        conversationId: "atomicity-\(marker)",
        senderFingerprint: canonicalRelayFingerprint(marker),
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

private func canonicalRelayFingerprint(_ marker: UInt8) -> String {
    Data(repeating: marker, count: 32).base64EncodedString()
}

private func atomicityAttachmentPayload(_ marker: UInt8) -> EncryptedPayload {
    EncryptedPayload(
        nonce: Data(repeating: marker, count: 12),
        ciphertext: Data(repeating: marker, count: 32),
        tag: Data(repeating: marker, count: 16)
    )
}

private final class CoreAtomicityBlobStore: AttachmentBlobStore {
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

private func assertCoreFailure(
    _ operation: () async throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        try await operation()
        XCTFail("Expected operation to fail", file: file, line: line)
    } catch {
        // Expected.
    }
}

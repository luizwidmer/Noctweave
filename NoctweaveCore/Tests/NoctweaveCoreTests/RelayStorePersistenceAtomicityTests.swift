import Foundation
import SQLite3
import XCTest
@testable import NoctweaveCore

final class RelayStorePersistenceAtomicityTests: XCTestCase {
    func testAttachmentUploadCanonicalBodyDigestVector() {
        let digest = attachmentUploadBodyDigest(
            attachmentId: UUID(uuidString: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")!,
            chunkIndex: 7,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: 12),
                ciphertext: Data([0x22, 0x23]),
                tag: Data(repeating: 0x33, count: 16)
            ),
            ttlSeconds: 300
        )
        XCTAssertEqual(
            digest.map { String(format: "%02x", $0) }.joined(),
            "7dc148be3f5b80970024c6ea417d4c2eab2db423599f018c96c5431dce7c6895"
        )
    }

    func testExistingUnmarkedSQLiteStoreIsRejected() async throws {
        let fixture = try makeCorePersistentRelayFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        var database: OpaquePointer?
        XCTAssertEqual(sqlite3_open(fixture.storeURL.path, &database), SQLITE_OK)
        XCTAssertEqual(sqlite3_close(database), SQLITE_OK)

        let store = RelayStore(storeURL: fixture.storeURL, temporalBucketSeconds: 0)
        do {
            try await store.loadFromDisk()
            XCTFail("Expected the unmarked store to be rejected")
        } catch {
            XCTAssertEqual(error as? RelayStorePersistenceError, .invalidCurrentState)
        }
    }

    func testImmutableAttachmentReplayAndFailedNewChunkPreserveDurableBlobs() async throws {
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
        let second = atomicityAttachmentPayload(0x62)
        let firstKey = Data(repeating: 0x71, count: 32)
        let secondKey = Data(repeating: 0x72, count: 32)
        _ = try await store.storeAttachment(
            attachmentId: attachmentId,
            chunkIndex: 0,
            payload: first,
            ttlSeconds: 300,
            idempotencyKey: firstKey
        )
        XCTAssertEqual(blobStore.activeBlobCount, 1)

        await store.failNextPersistenceForTesting()
        let replay = try await store.storeAttachment(
            attachmentId: attachmentId,
            chunkIndex: 0,
            payload: first,
            ttlSeconds: 300,
            idempotencyKey: firstKey
        )
        XCTAssertEqual(replay.payload, first)
        XCTAssertEqual(blobStore.activeBlobCount, 1)

        do {
            _ = try await store.storeAttachment(
                attachmentId: attachmentId,
                chunkIndex: 0,
                payload: second,
                ttlSeconds: 300,
                idempotencyKey: firstKey
            )
            XCTFail("Expected immutable attachment conflict")
        } catch RelayStoreError.attachmentConflict {
            // Expected.
        }
        do {
            _ = try await store.storeAttachment(
                attachmentId: attachmentId,
                chunkIndex: 0,
                payload: first,
                ttlSeconds: 300,
                idempotencyKey: secondKey
            )
            XCTFail("Expected idempotency-key conflict")
        } catch RelayStoreError.attachmentConflict {
            // Expected.
        }
        XCTAssertEqual(blobStore.activeBlobCount, 1)

        await assertCoreFailure {
            _ = try await store.storeAttachment(
                attachmentId: attachmentId,
                chunkIndex: 1,
                payload: second,
                ttlSeconds: 300,
                idempotencyKey: secondKey
            )
        }
        let afterFailure = try await store.fetchAttachment(
            attachmentId: attachmentId,
            chunkIndex: 0
        )
        XCTAssertEqual(afterFailure?.payload, first)
        let missingSecondChunk = try await store.fetchAttachment(
            attachmentId: attachmentId,
            chunkIndex: 1
        )
        XCTAssertNil(missingSecondChunk)
        XCTAssertEqual(blobStore.activeBlobCount, 1)

        _ = try await store.storeAttachment(
            attachmentId: attachmentId,
            chunkIndex: 1,
            payload: second,
            ttlSeconds: 300,
            idempotencyKey: secondKey
        )
        let reloaded = RelayStore(
            storeURL: fixture.storeURL,
            temporalBucketSeconds: 0,
            attachmentBlobStore: blobStore
        )
        try await reloaded.loadFromDisk()
        let persisted = try await reloaded.fetchAttachment(
            attachmentId: attachmentId,
            chunkIndex: 1
        )
        XCTAssertEqual(persisted?.payload, second)
        _ = try await reloaded.storeAttachment(
            attachmentId: attachmentId,
            chunkIndex: 1,
            payload: second,
            ttlSeconds: 300,
            idempotencyKey: secondKey
        )
        do {
            _ = try await reloaded.storeAttachment(
                attachmentId: attachmentId,
                chunkIndex: 1,
                payload: second,
                ttlSeconds: 301,
                idempotencyKey: secondKey
            )
            XCTFail("Expected persisted TTL conflict")
        } catch RelayStoreError.attachmentConflict {
            // Expected.
        }
        XCTAssertEqual(blobStore.activeBlobCount, 2)
    }
}

private func makeCorePersistentRelayFixture() throws -> (directory: URL, storeURL: URL) {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("noctweave-core-relay-atomicity-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return (directory, directory.appendingPathComponent("relay.sqlite"))
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

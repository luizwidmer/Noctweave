import Foundation
import SQLite3
import XCTest
@testable import NoctweaveCore

final class RelayStorePersistenceAtomicityTests: XCTestCase {
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

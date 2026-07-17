import Foundation
import XCTest
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite
#endif
@testable import NoctweaveRelayServer

final class RelayStoreCurrentTests: XCTestCase {
    func testCurrentStatePersistsAttachmentsFederationAndPinsInOneSchema() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("relay.sqlite")
        let attachmentID = UUID()
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0x11, count: 12),
            ciphertext: Data(repeating: 0x22, count: 512),
            tag: Data(repeating: 0x33, count: 16)
        )
        let endpoint = RelayEndpoint(
            host: "relay.example.org",
            port: 443,
            useTLS: true,
            transport: .http
        )
        let pinnedKey = Data(repeating: 0x44, count: 32)

        let writer = RelayStore(fileURL: url, temporalBucketSeconds: 0)
        _ = try writer.storeAttachment(
            attachmentId: attachmentID,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: 300
        )
        _ = try writer.registerFederationNode(
            FederationNodeRegistrationRequest(
                endpoint: endpoint,
                relayInfo: RelayConfiguration(
                    federation: FederationDescriptor(mode: .open)
                ).makeInfo(),
                ttlSeconds: 300
            )
        )
        try writer.pinCoordinatorPublicKey(pinnedKey, for: endpoint)

        let reader = RelayStore(fileURL: url, temporalBucketSeconds: 0)
        try reader.load()
        XCTAssertEqual(
            try reader.fetchAttachment(attachmentId: attachmentID, chunkIndex: 0)?.payload,
            payload
        )
        XCTAssertEqual(reader.listFederationNodes(nil).map(\.endpoint), [endpoint])
        XCTAssertEqual(reader.pinnedCoordinatorPublicKey(for: endpoint), pinnedKey)
        XCTAssertEqual(try tableNames(in: url), ["relay_runtime_state_v1"])
    }

    func testPersistenceFailureRestoresLastDurableAttachmentState() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("relay.sqlite")
        let store = RelayStore(fileURL: url, temporalBucketSeconds: 0)
        let attachmentID = UUID()
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0xA1, count: 12),
            ciphertext: Data(repeating: 0xA2, count: 512),
            tag: Data(repeating: 0xA3, count: 16)
        )

        store.failNextPersistenceForTesting()
        XCTAssertThrowsError(try store.storeAttachment(
            attachmentId: attachmentID,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: 300
        ))
        XCTAssertNil(try store.fetchAttachment(attachmentId: attachmentID, chunkIndex: 0))

        _ = try store.storeAttachment(
            attachmentId: attachmentID,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: 300
        )
        let reader = RelayStore(fileURL: url, temporalBucketSeconds: 0)
        try reader.load()
        XCTAssertEqual(
            try reader.fetchAttachment(attachmentId: attachmentID, chunkIndex: 0)?.payload,
            payload
        )
    }

    func testExistingForeignDatabaseIsRejectedWithoutImportFallback() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("relay.sqlite")
        var database: OpaquePointer?
        XCTAssertEqual(sqlite3_open(url.path, &database), SQLITE_OK)
        XCTAssertEqual(
            sqlite3_exec(database, "CREATE TABLE foreign_state (value BLOB);", nil, nil, nil),
            SQLITE_OK
        )
        XCTAssertEqual(sqlite3_close(database), SQLITE_OK)

        let store = RelayStore(fileURL: url)
        XCTAssertThrowsError(try store.load())
    }

    private func tableNames(in url: URL) throws -> [String] {
        var database: OpaquePointer?
        guard sqlite3_open_v2(url.path, &database, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
              let database else {
            throw NSError(domain: "RelayStoreCurrentTests", code: 1)
        }
        defer { sqlite3_close(database) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            database,
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name;",
            -1,
            &statement,
            nil
        ) == SQLITE_OK,
              let statement else {
            throw NSError(domain: "RelayStoreCurrentTests", code: 2)
        }
        defer { sqlite3_finalize(statement) }
        var names: [String] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            names.append(String(cString: sqlite3_column_text(statement, 0)))
        }
        return names
    }
}

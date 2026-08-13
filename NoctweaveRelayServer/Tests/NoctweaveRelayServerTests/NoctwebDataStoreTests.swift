import Crypto
import CSQLite
import XCTest
@testable import NoctweaveRelayServer

final class NoctwebDataStoreTests: XCTestCase {
    func testPublisherCRUDPersistsInsideRelaySQLite() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let sqliteURL = directory.appendingPathComponent("relay_store.sqlite")
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }

        let publisher = Curve25519.Signing.PrivateKey()
        let origin = makeOrigin(publisher: publisher)
        let store = RelayNoctwebDataStore(fileURL: sqliteURL)
        try store.load()
        let create = try makeCreate(origin: origin, publisher: publisher)
        XCTAssertTrue(try store.createDatabase(create).created)

        let put = try makePut(origin: origin, publisher: publisher)
        let record = try store.putRecord(put, now: Date(timeIntervalSince1970: 10))
        XCTAssertEqual(record.revision, 1)
        XCTAssertEqual(try store.putRecord(put), record)
        XCTAssertEqual(try store.getRecord(.init(
            databaseID: origin.databaseID,
            collection: "products",
            recordID: "coffee"
        )), record)

        let restored = RelayNoctwebDataStore(fileURL: sqliteURL)
        try restored.load()
        XCTAssertEqual(try restored.listRecords(.init(
            databaseID: origin.databaseID,
            collection: "products",
            limit: 10
        )).records, [record])
        XCTAssertTrue(try tableExists("noctweb_data_service_v1", at: sqliteURL))

        let delete = try makeDelete(record: record, origin: origin, publisher: publisher)
        XCTAssertEqual(try restored.deleteRecord(delete).deletedRevision, 1)
        XCTAssertThrowsError(try restored.getRecord(.init(
            databaseID: origin.databaseID,
            collection: "products",
            recordID: "coffee"
        ))) { XCTAssertEqual($0 as? RelayNoctwebDataStoreError, .databaseUnavailable) }
    }

    func testWireRejectsUnknownFieldsAndInvalidSignature() throws {
        let publisher = Curve25519.Signing.PrivateKey()
        let origin = makeOrigin(publisher: publisher)
        let create = try makeCreate(origin: origin, publisher: publisher)
        let request = RelayRequest.createNoctwebDatabaseV1(create)
        let encoded = try RelayCodec.encoder(sortedKeys: true).encode(request)
        XCTAssertEqual(try RelayCodec.decoder().decode(RelayRequest.self, from: encoded), request)

        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        var body = try XCTUnwrap(object["body"] as? [String: Any])
        body["unexpected"] = true
        object["body"] = body
        XCTAssertThrowsError(try RelayCodec.decoder().decode(
            RelayRequest.self,
            from: JSONSerialization.data(withJSONObject: object)
        ))

        let put = try makePut(origin: origin, publisher: publisher)
        var putObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: RelayCodec.encoder().encode(put))
                as? [String: Any]
        )
        putObject["unexpected"] = true
        XCTAssertThrowsError(try RelayCodec.decoder().decode(
            NoctwebDataRecordPutRequestV1.self,
            from: JSONSerialization.data(withJSONObject: putObject)
        ))

        let invalid = NoctwebDataDatabaseCreateRequestV1(
            origin: create.origin,
            collections: create.collections,
            idempotencyKey: create.idempotencyKey,
            signature: Data(repeating: 9, count: NoctwebDataV1.publisherSignatureBytes)
        )
        XCTAssertThrowsError(try RelayNoctwebDataStore().createDatabase(invalid)) {
            XCTAssertEqual($0 as? RelayNoctwebDataStoreError, .authenticationRequired)
        }
    }

    private func makeOrigin(publisher: Curve25519.Signing.PrivateKey) -> NoctwebDataOriginV1 {
        let publicKey = publisher.publicKey.rawRepresentation
        return .init(
            relaySuffix: NoctwebRelaySuffixV1(rawValue: ".store")!,
            siteLabel: "market",
            publisherID: noctwebDataPublisherID(for: publicKey),
            publisherSigningPublicKey: publicKey
        )
    }

    private func makeCreate(
        origin: NoctwebDataOriginV1,
        publisher: Curve25519.Signing.PrivateKey
    ) throws -> NoctwebDataDatabaseCreateRequestV1 {
        let collections = [NoctwebDataCollectionV1(
            name: "products",
            readPolicy: .publicRead,
            writePolicy: .publisher
        )]
        let key = Data(repeating: 1, count: NoctwebDataV1.idempotencyKeyBytes)
        let draft = NoctwebDataDatabaseCreateRequestV1(
            origin: origin,
            collections: collections,
            idempotencyKey: key,
            signature: Data(repeating: 0, count: NoctwebDataV1.publisherSignatureBytes)
        )
        return .init(
            origin: origin,
            collections: collections,
            idempotencyKey: key,
            signature: try publisher.signature(for: NoctwebDataTranscriptV1.createDatabase(draft))
        )
    }

    private func makePut(
        origin: NoctwebDataOriginV1,
        publisher: Curve25519.Signing.PrivateKey
    ) throws -> NoctwebDataRecordPutRequestV1 {
        let payload = Data(#"{"name":"Coffee","price":8}"#.utf8)
        let nonce = Data(repeating: 2, count: NoctwebDataV1.nonceBytes)
        let idempotencyKey = Data(repeating: 3, count: NoctwebDataV1.idempotencyKeyBytes)
        let draftAuthorization = NoctwebDataAuthorizationV1(
            actorKind: .publisher,
            actorID: origin.publisherID,
            nonce: nonce,
            signature: Data(repeating: 0, count: NoctwebDataV1.publisherSignatureBytes)
        )
        let draft = NoctwebDataRecordPutRequestV1(
            databaseID: origin.databaseID,
            collection: "products",
            recordID: "coffee",
            ownerAccountID: nil,
            payload: payload,
            expectedRevision: 0,
            idempotencyKey: idempotencyKey,
            authorization: draftAuthorization
        )
        return .init(
            databaseID: draft.databaseID,
            collection: draft.collection,
            recordID: draft.recordID,
            ownerAccountID: nil,
            payload: payload,
            expectedRevision: 0,
            idempotencyKey: idempotencyKey,
            authorization: .init(
                actorKind: .publisher,
                actorID: origin.publisherID,
                nonce: nonce,
                signature: try publisher.signature(for: NoctwebDataTranscriptV1.putRecord(draft))
            )
        )
    }

    private func makeDelete(
        record: NoctwebDataRecordV1,
        origin: NoctwebDataOriginV1,
        publisher: Curve25519.Signing.PrivateKey
    ) throws -> NoctwebDataRecordDeleteRequestV1 {
        let nonce = Data(repeating: 4, count: NoctwebDataV1.nonceBytes)
        let key = Data(repeating: 5, count: NoctwebDataV1.idempotencyKeyBytes)
        let draftAuthorization = NoctwebDataAuthorizationV1(
            actorKind: .publisher,
            actorID: origin.publisherID,
            nonce: nonce,
            signature: Data(repeating: 0, count: NoctwebDataV1.publisherSignatureBytes)
        )
        let draft = NoctwebDataRecordDeleteRequestV1(
            databaseID: record.databaseID,
            collection: record.collection,
            recordID: record.recordID,
            expectedRevision: record.revision,
            idempotencyKey: key,
            authorization: draftAuthorization
        )
        return .init(
            databaseID: record.databaseID,
            collection: record.collection,
            recordID: record.recordID,
            expectedRevision: record.revision,
            idempotencyKey: key,
            authorization: .init(
                actorKind: .publisher,
                actorID: origin.publisherID,
                nonce: nonce,
                signature: try publisher.signature(for: NoctwebDataTranscriptV1.deleteRecord(draft))
            )
        )
    }

    private func tableExists(_ name: String, at url: URL) throws -> Bool {
        var database: OpaquePointer?
        guard sqlite3_open_v2(url.path, &database, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
              let database else { return false }
        defer { sqlite3_close(database) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            database,
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?;",
            -1,
            &statement,
            nil
        ) == SQLITE_OK, let statement else { return false }
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_text(statement, 1, name, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        return sqlite3_step(statement) == SQLITE_ROW
    }
}

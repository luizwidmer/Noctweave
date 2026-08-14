import Crypto
import CSQLite
import XCTest
@testable import NoctweaveRelayServer

final class NoctwebDataStoreTests: XCTestCase {
    func testRelayHandlerReadsLiveProvisioningConfiguration() throws {
        let initial = RelayConfiguration(
            netHostEnabled: true,
            noctwebDataEnabled: true,
            noctwebDataDatabaseCreationEnabled: false,
            publisherPassword: "old-password"
        )
        let configurationStore = RelayConfigurationStore(initial)
        let handler = RelayHandler(
            store: RelayStore(fileURL: nil, temporalBucketSeconds: 0),
            maxMessageBytes: 512 * 1_024,
            maxLineBytes: 640 * 1_024,
            localEndpoint: nil,
            relayConfiguration: initial,
            relayConfigurationStore: configurationStore,
            relayIdentityRuntime: RelayIdentityRuntime(
                keyMaterial: try RelayIdentityKeyMaterialV1.generate()
            ),
            forwardingRequestTimeoutSeconds: 2,
            noctwebDataStore: RelayNoctwebDataStore()
        )
        XCTAssertFalse(
            handler.currentRelayConfiguration
                .isNoctwebDataDatabaseCreationEnabled
        )
        XCTAssertEqual(
            handler.currentRelayConfiguration.publisherPassword,
            "old-password"
        )

        configurationStore.replace(with: RelayConfiguration(
            netHostEnabled: true,
            noctwebDataEnabled: true,
            noctwebDataDatabaseCreationEnabled: true,
            publisherPassword: "rotated-password"
        ))
        XCTAssertTrue(
            handler.currentRelayConfiguration
                .isNoctwebDataDatabaseCreationEnabled
        )
        XCTAssertEqual(
            handler.currentRelayConfiguration.publisherPassword,
            "rotated-password"
        )
    }

    func testNoctwebDataWorkLimiterBoundsDetachedJobs() {
        let limiter = NoctwebDataWorkLimiter(maximumInFlight: 2)
        XCTAssertTrue(limiter.tryAcquire())
        XCTAssertTrue(limiter.tryAcquire())
        XCTAssertFalse(limiter.tryAcquire())
        limiter.release()
        XCTAssertTrue(limiter.tryAcquire())
        limiter.release()
        limiter.release()
    }

    func testJavaScriptPublisherWriteFixtureDecodes() throws {
        let fixture = Data(#"""
        {"databaseID":"nwdb1_0addfd02b26e7678f5503ad95acf98b2b660435245dcc1129c0469b923295991","collection":"catalog","recordID":"tea","payload":"eyJhbGdvcml0aG0iOiJBRVMtMjU2LUdDTSIsImNpcGhlcnRleHQiOiJKTWkyRFNKMFovSlZwY1U1Q0lRMElNOTd1aXNDbmhKTkdvaGdqNGR0eDB1WnB3MTZ0UFJJS0c4PSIsImtleUlEIjoiMk9LemdvVXN0emUwZEZIazN6aVlvM2hGc0o2V2RoaW1SSk1YZkRyVXJzcz0iLCJub25jZSI6InhUWEpobUhUNUNZRzM3ejMiLCJ2ZXJzaW9uIjoxfQ==","expectedRevision":0,"idempotencyKey":"72XdilVz9FaP+jIcSFiCgoJxeIfC+zMw2e55VY2AVYE=","authorization":{"actorKind":"publisher","actorID":"nwpub1_0141db19e5bf1c573e8c13e27b452cb4788658c6860ad54bca34d7fcb3fb93da","nonce":"mnZ9CQW8JooaIY/EMWQvzSl2sTVKD4/w/Xq1FnC+9Rw=","expiresAt":"2026-08-14T00:03:05Z","signature":"vZ/MQsEelDXzTQSEhfRNP3M0AqmTX6kDcafqW1aDdJBwCcB1hRbUx5W/LF8aAqd84gFI+U13K3cW/QzTeN0ECg=="}}
        """#.utf8)
        let decoded = try RelayCodec.decoder().decode(
            NoctwebDataRecordPutRequestV1.self,
            from: fixture
        )
        XCTAssertEqual(decoded.collection, "catalog")
        XCTAssertEqual(decoded.recordID, "tea")
    }

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

        let account = try OQSSignatureVerifier.shared.generateKeyPairThrowing()
        let registration = try makeRegistration(
            databaseID: origin.databaseID,
            privateKey: account.privateKey,
            publicKey: account.publicKey
        )
        XCTAssertTrue(try store.registerAccount(registration).created)

        let notice = try makePut(
            origin: origin,
            publisher: publisher,
            collection: "notices",
            recordID: "welcome",
            ownerAccountID: registration.accountID
        )
        let noticeRecord = try store.putRecord(
            notice,
            now: Date(timeIntervalSince1970: 10)
        )
        XCTAssertEqual(try store.getRecord(.init(
            databaseID: origin.databaseID,
            collection: "notices",
            recordID: "welcome",
            ownerAccountID: registration.accountID
        )), noticeRecord)
        XCTAssertEqual(try store.deleteRecord(
            makeDelete(record: noticeRecord, origin: origin, publisher: publisher)
        ).ownerAccountID, registration.accountID)

        let mixed = try makePut(
            origin: origin,
            publisher: publisher,
            collection: "mixed",
            recordID: "global"
        )
        let mixedRecord = try store.putRecord(
            mixed,
            now: Date(timeIntervalSince1970: 10)
        )
        XCTAssertEqual(
            try store.getRecord(
                makePublisherGet(
                    origin: origin,
                    publisher: publisher,
                    collection: "mixed",
                    recordID: "global"
                ),
                now: Date(timeIntervalSince1970: 10)
            ),
            mixedRecord
        )

        let unownedPrivateNotice = try makePut(
            origin: origin,
            publisher: publisher,
            collection: "private-notices",
            recordID: "orphaned"
        )
        XCTAssertThrowsError(try store.putRecord(
            unownedPrivateNotice,
            now: Date(timeIntervalSince1970: 10)
        )) {
            XCTAssertEqual($0 as? RelayNoctwebDataStoreError, .unauthorized)
        }

        let put = try makePut(origin: origin, publisher: publisher)
        let record = try store.putRecord(put, now: Date(timeIntervalSince1970: 10))
        XCTAssertEqual(record.revision, 1)
        XCTAssertEqual(
            try store.putRecord(put, now: Date(timeIntervalSince1970: 20)),
            record
        )
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
            limit: 8
        )).records, [record])
        XCTAssertTrue(try tableExists("noctweb_data_databases_v2", at: sqliteURL))
        XCTAssertFalse(try tableExists("noctweb_data_service_v1", at: sqliteURL))

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

    func testLegacyPlaintextSnapshotFailsClosed() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let sqliteURL = directory.appendingPathComponent("relay_store.sqlite")
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }

        try RelayNoctwebDataStore(fileURL: sqliteURL).load()
        var database: OpaquePointer?
        XCTAssertEqual(
            sqlite3_open_v2(sqliteURL.path, &database, SQLITE_OPEN_READWRITE, nil),
            SQLITE_OK
        )
        let opened = try XCTUnwrap(database)
        defer { sqlite3_close(opened) }
        XCTAssertEqual(sqlite3_exec(opened, """
            CREATE TABLE noctweb_data_service_v1 (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                snapshot BLOB NOT NULL
            );
            INSERT INTO noctweb_data_service_v1 (singleton, snapshot)
            VALUES (1, X'7B7D');
            """, nil, nil, nil), SQLITE_OK)

        XCTAssertThrowsError(try RelayNoctwebDataStore(fileURL: sqliteURL).load()) {
            XCTAssertEqual($0 as? RelayNoctwebDataStoreError, .corruptPersistence)
        }
    }

    func testSQLiteSymlinkTargetIsRejected() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let target = directory.appendingPathComponent("attacker.sqlite")
        try Data().write(to: target)
        let link = directory.appendingPathComponent("relay_store.sqlite")
        try FileManager.default.createSymbolicLink(
            at: link,
            withDestinationURL: target
        )
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }

        XCTAssertThrowsError(try RelayNoctwebDataStore(fileURL: link).load()) {
            XCTAssertEqual($0 as? RelayNoctwebDataStoreError, .corruptPersistence)
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
        let collections = [
            NoctwebDataCollectionV1(
                name: "products",
                readPolicy: .publicRead,
                writePolicy: .publisher
            ),
            NoctwebDataCollectionV1(
                name: "mixed",
                readPolicy: .ownerOrPublisher,
                writePolicy: .ownerOrPublisher
            ),
            NoctwebDataCollectionV1(
                name: "notices",
                readPolicy: .publicRead,
                writePolicy: .publisher
            ),
            NoctwebDataCollectionV1(
                name: "private-notices",
                readPolicy: .owner,
                writePolicy: .publisher
            ),
        ]
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
        publisher: Curve25519.Signing.PrivateKey,
        collection: String = "products",
        recordID: String = "coffee",
        ownerAccountID: String? = nil
    ) throws -> NoctwebDataRecordPutRequestV1 {
        let payload = try makeEncryptedPayload(
            Data(#"{"name":"Coffee","price":8}"#.utf8),
            databaseID: origin.databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: ownerAccountID,
            revision: 1
        )
        let nonce = Data(repeating: 2, count: NoctwebDataV1.nonceBytes)
        let idempotencyKey = Data(SHA256.hash(data: Data(
            "put\u{0}\(collection)\u{0}\(ownerAccountID ?? "")\u{0}\(recordID)".utf8
        )))
        let expiresAt = Date(timeIntervalSince1970: 120)
        let draftAuthorization = NoctwebDataAuthorizationV1(
            actorKind: .publisher,
            actorID: origin.publisherID,
            nonce: nonce,
            expiresAt: expiresAt,
            signature: Data(repeating: 0, count: NoctwebDataV1.publisherSignatureBytes)
        )
        let draft = NoctwebDataRecordPutRequestV1(
            databaseID: origin.databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: ownerAccountID,
            payload: payload,
            expectedRevision: 0,
            idempotencyKey: idempotencyKey,
            authorization: draftAuthorization
        )
        return .init(
            databaseID: draft.databaseID,
            collection: draft.collection,
            recordID: draft.recordID,
            ownerAccountID: ownerAccountID,
            payload: payload,
            expectedRevision: 0,
            idempotencyKey: idempotencyKey,
            authorization: .init(
                actorKind: .publisher,
                actorID: origin.publisherID,
                nonce: nonce,
                expiresAt: expiresAt,
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
        let key = Data(SHA256.hash(data: Data(
            "\(record.collection)\u{0}\(record.ownerAccountID ?? "")\u{0}\(record.recordID)".utf8
        )))
        let expiresAt = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970) + 120)
        let draftAuthorization = NoctwebDataAuthorizationV1(
            actorKind: .publisher,
            actorID: origin.publisherID,
            nonce: nonce,
            expiresAt: expiresAt,
            signature: Data(repeating: 0, count: NoctwebDataV1.publisherSignatureBytes)
        )
        let draft = NoctwebDataRecordDeleteRequestV1(
            databaseID: record.databaseID,
            collection: record.collection,
            recordID: record.recordID,
            ownerAccountID: record.ownerAccountID,
            expectedRevision: record.revision,
            idempotencyKey: key,
            authorization: draftAuthorization
        )
        return .init(
            databaseID: record.databaseID,
            collection: record.collection,
            recordID: record.recordID,
            ownerAccountID: record.ownerAccountID,
            expectedRevision: record.revision,
            idempotencyKey: key,
            authorization: .init(
                actorKind: .publisher,
                actorID: origin.publisherID,
                nonce: nonce,
                expiresAt: expiresAt,
                signature: try publisher.signature(for: NoctwebDataTranscriptV1.deleteRecord(draft))
            )
        )
    }

    private func makePublisherGet(
        origin: NoctwebDataOriginV1,
        publisher: Curve25519.Signing.PrivateKey,
        collection: String,
        recordID: String,
        ownerAccountID: String? = nil
    ) throws -> NoctwebDataRecordGetRequestV1 {
        let nonce = Data(repeating: 6, count: NoctwebDataV1.nonceBytes)
        let expiresAt = Date(timeIntervalSince1970: 120)
        let draftAuthorization = NoctwebDataAuthorizationV1(
            actorKind: .publisher,
            actorID: origin.publisherID,
            nonce: nonce,
            expiresAt: expiresAt,
            signature: Data(repeating: 0, count: NoctwebDataV1.publisherSignatureBytes)
        )
        let draft = NoctwebDataRecordGetRequestV1(
            databaseID: origin.databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: ownerAccountID,
            authorization: draftAuthorization
        )
        return .init(
            databaseID: origin.databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: ownerAccountID,
            authorization: .init(
                actorKind: .publisher,
                actorID: origin.publisherID,
                nonce: nonce,
                expiresAt: expiresAt,
                signature: try publisher.signature(
                    for: NoctwebDataTranscriptV1.getRecord(draft)
                )
            )
        )
    }

    private func makeEncryptedPayload(
        _ plaintext: Data,
        databaseID: String,
        collection: String,
        recordID: String,
        ownerAccountID: String? = nil,
        revision: UInt64
    ) throws -> Data {
        let keyMaterial = Data(repeating: 0xA7, count: NoctwebDataV1.payloadKeyBytes)
        var keyIDMaterial = Data("org.noctweave.noctweb/payload-key-id/v1".utf8)
        keyIDMaterial.append(0)
        keyIDMaterial.append(keyMaterial)
        let keyID = Data(SHA256.hash(data: keyIDMaterial))
        var nonceMaterial = Data(databaseID.utf8)
        nonceMaterial.append(Data(collection.utf8))
        nonceMaterial.append(Data(recordID.utf8))
        nonceMaterial.append(plaintext)
        let nonce = Data(SHA256.hash(data: nonceMaterial).prefix(NoctwebDataV1.payloadNonceBytes))
        let aad = NoctwebDataTranscriptV1.encryptedPayloadAAD(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: ownerAccountID,
            revision: revision,
            keyID: keyID
        )
        let sealed = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: keyMaterial),
            nonce: AES.GCM.Nonce(data: nonce),
            authenticating: aad
        )
        let envelope = NoctwebDataEncryptedPayloadV1(
            keyID: keyID,
            nonce: nonce,
            ciphertext: sealed.ciphertext + sealed.tag
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(envelope)
    }

    private func makeRegistration(
        databaseID: String,
        privateKey: Data,
        publicKey: Data
    ) throws -> NoctwebDataAccountRegisterRequestV1 {
        let accountID = NoctwebDataAccountRegisterRequestV1.accountID(
            databaseID: databaseID,
            publicKey: publicKey
        )
        let key = Data(repeating: 7, count: NoctwebDataV1.idempotencyKeyBytes)
        let draft = NoctwebDataAccountRegisterRequestV1(
            databaseID: databaseID,
            accountID: accountID,
            accountSigningPublicKey: publicKey,
            idempotencyKey: key,
            signature: Data(repeating: 0, count: NoctwebDataV1.accountSignatureBytes)
        )
        return .init(
            databaseID: databaseID,
            accountID: accountID,
            accountSigningPublicKey: publicKey,
            idempotencyKey: key,
            signature: try OQSSignatureVerifier.shared.signThrowing(
                data: NoctwebDataTranscriptV1.registerAccount(draft),
                privateKey: privateKey,
                publicKey: publicKey
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

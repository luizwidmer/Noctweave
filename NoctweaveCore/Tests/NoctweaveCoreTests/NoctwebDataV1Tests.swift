import CryptoKit
import XCTest
@testable import NoctweaveCore

final class NoctwebDataV1Tests: XCTestCase {
    func testCrossLanguageOriginAndAccountIdentifiers() {
        XCTAssertEqual(
            String(data: try! JSONEncoder().encode(NoctwebRelaySuffixV1(rawValue: ".vector")!), encoding: .utf8),
            #"".vector""#
        )
        let publisherKey = Data((0..<32).map(UInt8.init))
        let publisherID = noctwebDataPublisherID(for: publisherKey)
        XCTAssertEqual(
            publisherID,
            "nwpub1_95a0e7e50deed5ca358e0f56637306094399af16c8d8c127a0f4dd742d372db5"
        )
        let origin = NoctwebDataOriginV1(
            relaySuffix: NoctwebRelaySuffixV1(rawValue: ".vector")!,
            siteLabel: "shop",
            publisherID: publisherID,
            publisherSigningPublicKey: publisherKey
        )
        XCTAssertEqual(
            origin.databaseID,
            "nwdb1_ffb36f4bf6d9b191831320522c1ccf8a0fc6d74d225bf847b638cf377f8cad4c"
        )
        let accountKey = Data((0..<NoctwebDataV1.accountPublicKeyBytes).map {
            UInt8(($0 * 17 + 3) % 256)
        })
        XCTAssertEqual(
            NoctwebDataAccountRegisterRequestV1.accountID(
                databaseID: origin.databaseID,
                publicKey: accountKey
            ),
            "nwa1_8910a1946435943581132c38d336d1de871f28e0e20b22fccb3eff58c38b8d6d"
        )
    }

    func testPublisherAndOriginScopedAccountPoliciesCASAndPersistence() throws {
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("relay_store.sqlite")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent())
        }
        let publisher = Curve25519.Signing.PrivateKey()
        let origin = makeOrigin(publisher: publisher, label: "shop")
        let store = RelayNoctwebDataStore(fileURL: fileURL)
        let create = try makeCreate(
            origin: origin,
            collections: [
                .init(name: "catalog", readPolicy: .publicRead, writePolicy: .publisher),
                .init(name: "carts", readPolicy: .owner, writePolicy: .owner),
            ],
            publisher: publisher
        )
        XCTAssertTrue(try store.createDatabase(create).created)
        XCTAssertFalse(try store.createDatabase(create).created)

        let account = try SigningKeyPair.generate()
        let registration = try makeRegistration(databaseID: origin.databaseID, account: account)
        XCTAssertTrue(try store.registerAccount(registration).created)

        let cart = try makeAccountPut(
            databaseID: origin.databaseID,
            collection: "carts",
            recordID: "active",
            payload: Data(#"{"sku":"tea","quantity":2}"#.utf8),
            expectedRevision: 0,
            account: account,
            accountID: registration.accountID
        )
        let inserted = try store.putRecord(cart)
        XCTAssertEqual(inserted.revision, 1)
        XCTAssertEqual(try store.putRecord(cart), inserted, "identical idempotent replay must be stable")
        XCTAssertThrowsError(try store.getRecord(.init(
            databaseID: origin.databaseID,
            collection: "carts",
            recordID: "active"
        ))) { XCTAssertEqual($0 as? RelayNoctwebDataStoreError, .unauthorized) }

        let authorizedGet = try makeAccountGet(
            databaseID: origin.databaseID,
            collection: "carts",
            recordID: "active",
            account: account,
            accountID: registration.accountID
        )
        XCTAssertEqual(try store.getRecord(authorizedGet), inserted)

        let stale = try makeAccountPut(
            databaseID: origin.databaseID,
            collection: "carts",
            recordID: "active",
            payload: Data(#"{"sku":"tea","quantity":3}"#.utf8),
            expectedRevision: 0,
            account: account,
            accountID: registration.accountID
        )
        XCTAssertThrowsError(try store.putRecord(stale)) {
            XCTAssertEqual($0 as? RelayNoctwebDataStoreError, .conflict)
        }

        let catalog = try makePublisherPut(
            databaseID: origin.databaseID,
            collection: "catalog",
            recordID: "tea",
            payload: Data(#"{"price":12,"stock":4}"#.utf8),
            publisher: publisher,
            publisherID: origin.publisherID
        )
        XCTAssertEqual(try store.putRecord(catalog).recordID, "tea")
        let publicList = try store.listRecords(.init(
            databaseID: origin.databaseID,
            collection: "catalog",
            limit: 10
        ))
        XCTAssertEqual(publicList.records.map(\.recordID), ["tea"])

        let restored = RelayNoctwebDataStore(fileURL: fileURL)
        try restored.load()
        XCTAssertEqual(try restored.getRecord(authorizedGet), inserted)

        let otherOrigin = makeOrigin(publisher: Curve25519.Signing.PrivateKey(), label: "shop")
        XCTAssertNotEqual(origin.databaseID, otherOrigin.databaseID)
        XCTAssertThrowsError(try restored.getRecord(.init(
            databaseID: otherOrigin.databaseID,
            collection: "catalog",
            recordID: "tea"
        ))) { XCTAssertEqual($0 as? RelayNoctwebDataStoreError, .databaseUnavailable) }
    }

    func testWireRoundTripAndTamperedSignatureRejection() throws {
        let publisher = Curve25519.Signing.PrivateKey()
        let origin = makeOrigin(publisher: publisher, label: "wire")
        let create = try makeCreate(
            origin: origin,
            collections: [.init(name: "items", readPolicy: .publicRead, writePolicy: .publisher)],
            publisher: publisher
        )
        let request = RelayRequest.createNoctwebDatabase(create)
        let encoded = try JSONEncoder().encode(request)
        XCTAssertEqual(try JSONDecoder().decode(RelayRequest.self, from: encoded), request)

        let store = RelayNoctwebDataStore()
        XCTAssertTrue(try store.createDatabase(create).created)
        let validPut = try makePublisherPut(
            databaseID: origin.databaseID,
            collection: "items",
            recordID: "one",
            payload: Data("valid".utf8),
            publisher: publisher,
            publisherID: origin.publisherID
        )
        let tampered = NoctwebDataRecordPutRequestV1(
            databaseID: validPut.databaseID,
            collection: validPut.collection,
            recordID: validPut.recordID,
            ownerAccountID: nil,
            payload: Data("tampered".utf8),
            expectedRevision: validPut.expectedRevision,
            idempotencyKey: validPut.idempotencyKey,
            authorization: validPut.authorization
        )
        XCTAssertThrowsError(try store.putRecord(tampered)) {
            XCTAssertEqual($0 as? RelayNoctwebDataStoreError, .authenticationRequired)
        }

        var putObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(validPut))
                as? [String: Any]
        )
        putObject["unexpected"] = true
        XCTAssertThrowsError(try JSONDecoder().decode(
            NoctwebDataRecordPutRequestV1.self,
            from: JSONSerialization.data(withJSONObject: putObject)
        ))
    }

    private func makeOrigin(
        publisher: Curve25519.Signing.PrivateKey,
        label: String
    ) -> NoctwebDataOriginV1 {
        let publicKey = publisher.publicKey.rawRepresentation
        return NoctwebDataOriginV1(
            relaySuffix: NoctwebRelaySuffixV1(rawValue: ".test")!,
            siteLabel: label,
            publisherID: noctwebDataPublisherID(for: publicKey),
            publisherSigningPublicKey: publicKey
        )
    }

    private func makeCreate(
        origin: NoctwebDataOriginV1,
        collections: [NoctwebDataCollectionV1],
        publisher: Curve25519.Signing.PrivateKey
    ) throws -> NoctwebDataDatabaseCreateRequestV1 {
        let key = Data(repeating: 1, count: NoctwebDataV1.idempotencyKeyBytes)
        let draft = NoctwebDataDatabaseCreateRequestV1(
            origin: origin,
            collections: collections,
            idempotencyKey: key,
            signature: Data(repeating: 0, count: NoctwebDataV1.publisherSignatureBytes)
        )
        return NoctwebDataDatabaseCreateRequestV1(
            origin: origin,
            collections: collections,
            idempotencyKey: key,
            signature: try publisher.signature(for: NoctwebDataTranscriptV1.createDatabase(draft))
        )
    }

    private func makeRegistration(
        databaseID: String,
        account: SigningKeyPair
    ) throws -> NoctwebDataAccountRegisterRequestV1 {
        let accountID = NoctwebDataAccountRegisterRequestV1.accountID(
            databaseID: databaseID,
            publicKey: account.publicKeyData
        )
        let key = Data(repeating: 2, count: NoctwebDataV1.idempotencyKeyBytes)
        let draft = NoctwebDataAccountRegisterRequestV1(
            databaseID: databaseID,
            accountID: accountID,
            accountSigningPublicKey: account.publicKeyData,
            idempotencyKey: key,
            signature: Data(repeating: 0, count: NoctwebDataV1.accountSignatureBytes)
        )
        return .init(
            databaseID: databaseID,
            accountID: accountID,
            accountSigningPublicKey: account.publicKeyData,
            idempotencyKey: key,
            signature: try account.sign(NoctwebDataTranscriptV1.registerAccount(draft))
        )
    }

    private func makeAccountPut(
        databaseID: String,
        collection: String,
        recordID: String,
        payload: Data,
        expectedRevision: UInt64,
        account: SigningKeyPair,
        accountID: String
    ) throws -> NoctwebDataRecordPutRequestV1 {
        let nonce = Data(repeating: 3, count: NoctwebDataV1.nonceBytes)
        let key = Data(SHA256.hash(data: payload + Data(recordID.utf8)))
        let draftAuthorization = NoctwebDataAuthorizationV1(
            actorKind: .account,
            actorID: accountID,
            nonce: nonce,
            signature: Data(repeating: 0, count: NoctwebDataV1.accountSignatureBytes)
        )
        let draft = NoctwebDataRecordPutRequestV1(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: accountID,
            payload: payload,
            expectedRevision: expectedRevision,
            idempotencyKey: key,
            authorization: draftAuthorization
        )
        let authorization = NoctwebDataAuthorizationV1(
            actorKind: .account,
            actorID: accountID,
            nonce: nonce,
            signature: try account.sign(NoctwebDataTranscriptV1.putRecord(draft))
        )
        return .init(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: accountID,
            payload: payload,
            expectedRevision: expectedRevision,
            idempotencyKey: key,
            authorization: authorization
        )
    }

    private func makeAccountGet(
        databaseID: String,
        collection: String,
        recordID: String,
        account: SigningKeyPair,
        accountID: String
    ) throws -> NoctwebDataRecordGetRequestV1 {
        let nonce = Data(repeating: 4, count: NoctwebDataV1.nonceBytes)
        let draftAuthorization = NoctwebDataAuthorizationV1(
            actorKind: .account,
            actorID: accountID,
            nonce: nonce,
            signature: Data(repeating: 0, count: NoctwebDataV1.accountSignatureBytes)
        )
        let draft = NoctwebDataRecordGetRequestV1(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            authorization: draftAuthorization
        )
        let authorization = NoctwebDataAuthorizationV1(
            actorKind: .account,
            actorID: accountID,
            nonce: nonce,
            signature: try account.sign(NoctwebDataTranscriptV1.getRecord(draft))
        )
        return .init(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            authorization: authorization
        )
    }

    private func makePublisherPut(
        databaseID: String,
        collection: String,
        recordID: String,
        payload: Data,
        publisher: Curve25519.Signing.PrivateKey,
        publisherID: String
    ) throws -> NoctwebDataRecordPutRequestV1 {
        let nonce = Data(repeating: 5, count: NoctwebDataV1.nonceBytes)
        let key = Data(SHA256.hash(data: payload + Data(recordID.utf8)))
        let draftAuthorization = NoctwebDataAuthorizationV1(
            actorKind: .publisher,
            actorID: publisherID,
            nonce: nonce,
            signature: Data(repeating: 0, count: NoctwebDataV1.publisherSignatureBytes)
        )
        let draft = NoctwebDataRecordPutRequestV1(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: nil,
            payload: payload,
            expectedRevision: 0,
            idempotencyKey: key,
            authorization: draftAuthorization
        )
        let authorization = NoctwebDataAuthorizationV1(
            actorKind: .publisher,
            actorID: publisherID,
            nonce: nonce,
            signature: try publisher.signature(for: NoctwebDataTranscriptV1.putRecord(draft))
        )
        return .init(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: nil,
            payload: payload,
            expectedRevision: 0,
            idempotencyKey: key,
            authorization: authorization
        )
    }
}

import CryptoKit
import XCTest
@testable import NoctweaveCore

final class NoctwebDataV1Tests: XCTestCase {
    func testDatabaseCreationIsSeparatelyDefaultOff() {
        let serving = RelayConfiguration(
            kind: .standard,
            netHostEnabled: true,
            noctwebDataEnabled: true
        )
        XCTAssertTrue(serving.isNoctwebDataEnabled)
        XCTAssertFalse(serving.isNoctwebDataDatabaseCreationEnabled)

        let provisioning = RelayConfiguration(
            kind: .standard,
            netHostEnabled: true,
            noctwebDataEnabled: true,
            noctwebDataDatabaseCreationEnabled: true
        )
        XCTAssertTrue(provisioning.isNoctwebDataDatabaseCreationEnabled)
        XCTAssertEqual(
            NoctwebDataV1.advertisedCapabilityLimits(
                databaseCreationEnabled: false
            )["databaseCreationEnabled"],
            0
        )
        XCTAssertEqual(
            NoctwebDataV1.advertisedCapabilityLimits(
                databaseCreationEnabled: true
            )["databaseCreationEnabled"],
            1
        )
    }

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

    func testMaximumRecordPageFitsDefaultRelayResponseBudget() throws {
        let databaseID = "nwdb1_" + String(repeating: "a", count: 64)
        let accountID = "nwa1_" + String(repeating: "b", count: 64)
        let collection = String(repeating: "c", count: 48)
        let payload = try noctwebDataEncodeEncryptedPayload(.init(
            keyID: Data(repeating: 1, count: NoctwebDataV1.payloadKeyIDBytes),
            nonce: Data(repeating: 2, count: NoctwebDataV1.payloadNonceBytes),
            ciphertext: Data(repeating: 3, count: 49_000)
        ))
        XCTAssertGreaterThan(payload.count, 65_000)
        XCTAssertLessThanOrEqual(payload.count, NoctwebDataV1.maximumRecordBytes)
        let records = (0..<NoctwebDataV1.maximumPage).map { index in
            let recordID = String(format: "%02d-", index)
                + String(repeating: "r", count: 90)
            return NoctwebDataRecordV1(
                databaseID: databaseID,
                collection: collection,
                recordID: recordID,
                ownerAccountID: accountID,
                payload: payload,
                revision: 1,
                createdAt: Date(timeIntervalSince1970: 1),
                updatedAt: Date(timeIntervalSince1970: 1),
                provenance: .init(
                    actorKind: .account,
                    actorID: accountID,
                    actorSigningPublicKey: Data(
                        repeating: 4,
                        count: NoctwebDataV1.accountPublicKeyBytes
                    ),
                    authorizationNonce: Data(
                        repeating: 5,
                        count: NoctwebDataV1.nonceBytes
                    ),
                    authorizationExpiresAt: Date(timeIntervalSince1970: 2),
                    idempotencyKey: Data(
                        repeating: 6,
                        count: NoctwebDataV1.idempotencyKeyBytes
                    ),
                    expectedRevision: 0,
                    signature: Data(
                        repeating: 7,
                        count: NoctwebDataV1.accountSignatureBytes
                    )
                )
            )
        }
        let list = NoctwebDataRecordListV1(records: records, nextCursor: nil)
        XCTAssertTrue(list.isStructurallyValid)
        let request = RelayRequest.listNoctwebRecords(.init(
            databaseID: databaseID,
            collection: collection,
            ownerAccountID: accountID,
            limit: NoctwebDataV1.maximumPage
        ))
        let response = RelayResponse.success(
            .noctwebRecords(list),
            respondingTo: request
        )
        XCTAssertLessThanOrEqual(
            try NoctweaveCoder.encode(response).count,
            RelayClientPolicy.defaultMaximumResponseBytes
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
                .init(name: "mixed", readPolicy: .ownerOrPublisher, writePolicy: .ownerOrPublisher),
                .init(name: "notices", readPolicy: .publicRead, writePolicy: .publisher),
                .init(name: "private-notices", readPolicy: .owner, writePolicy: .publisher),
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
        XCTAssertThrowsError(try store.getRecord(authorizedGet)) {
            XCTAssertEqual($0 as? RelayNoctwebDataStoreError, .authenticationRequired)
        }

        let expiredGet = try makeAccountGet(
            databaseID: origin.databaseID,
            collection: "carts",
            recordID: "active",
            account: account,
            accountID: registration.accountID,
            expiresAt: Date(timeIntervalSince1970: 1)
        )
        XCTAssertThrowsError(try store.getRecord(expiredGet)) {
            XCTAssertEqual($0 as? RelayNoctwebDataStoreError, .authenticationRequired)
        }

        let secondAccount = try SigningKeyPair.generate()
        let secondRegistration = try makeRegistration(
            databaseID: origin.databaseID,
            account: secondAccount
        )
        XCTAssertTrue(try store.registerAccount(secondRegistration).created)
        let secondCart = try makeAccountPut(
            databaseID: origin.databaseID,
            collection: "carts",
            recordID: "active",
            payload: Data(#"{"sku":"coffee","quantity":1}"#.utf8),
            expectedRevision: 0,
            account: secondAccount,
            accountID: secondRegistration.accountID
        )
        let secondInserted = try store.putRecord(secondCart)
        XCTAssertEqual(secondInserted.recordID, inserted.recordID)
        XCTAssertNotEqual(secondInserted.ownerAccountID, inserted.ownerAccountID)
        let secondGet = try makeAccountGet(
            databaseID: origin.databaseID,
            collection: "carts",
            recordID: "active",
            account: secondAccount,
            accountID: secondRegistration.accountID
        )
        XCTAssertEqual(try store.getRecord(secondGet), secondInserted)

        let ownerNotice = try makePublisherPut(
            databaseID: origin.databaseID,
            collection: "notices",
            recordID: "shared",
            payload: Data(#"{"message":"hello"}"#.utf8),
            publisher: publisher,
            publisherID: origin.publisherID,
            ownerAccountID: registration.accountID
        )
        let ownerNoticeRecord = try store.putRecord(ownerNotice)
        XCTAssertEqual(
            try store.getRecord(.init(
                databaseID: origin.databaseID,
                collection: "notices",
                recordID: "shared",
                ownerAccountID: registration.accountID
            )),
            ownerNoticeRecord
        )
        XCTAssertEqual(
            try store.listRecords(.init(
                databaseID: origin.databaseID,
                collection: "notices",
                ownerAccountID: registration.accountID,
                limit: 8
            )).records,
            [ownerNoticeRecord]
        )
        let ownerNoticeDelete = try makePublisherDelete(
            record: ownerNoticeRecord,
            publisher: publisher,
            publisherID: origin.publisherID
        )
        XCTAssertEqual(
            try store.deleteRecord(ownerNoticeDelete).ownerAccountID,
            registration.accountID
        )

        let unownedMixed = try makePublisherPut(
            databaseID: origin.databaseID,
            collection: "mixed",
            recordID: "global",
            payload: Data(#"{"message":"publisher"}"#.utf8),
            publisher: publisher,
            publisherID: origin.publisherID
        )
        let unownedMixedRecord = try store.putRecord(unownedMixed)
        XCTAssertEqual(
            try store.getRecord(makePublisherGet(
                databaseID: origin.databaseID,
                collection: "mixed",
                recordID: "global",
                publisher: publisher,
                publisherID: origin.publisherID
            )),
            unownedMixedRecord
        )

        let unownedPrivateNotice = try makePublisherPut(
            databaseID: origin.databaseID,
            collection: "private-notices",
            recordID: "orphaned",
            payload: Data(#"{"message":"unreachable"}"#.utf8),
            publisher: publisher,
            publisherID: origin.publisherID
        )
        XCTAssertThrowsError(try store.putRecord(unownedPrivateNotice)) {
            XCTAssertEqual($0 as? RelayNoctwebDataStoreError, .unauthorized)
        }

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
            limit: 8
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
        let substituted = RelayResponse.success(
            .noctwebDatabase(.init(
                databaseID: "nwdb1_" + String(repeating: "0", count: 64),
                created: true
            )),
            respondingTo: request
        )
        XCTAssertTrue(substituted.isResponse(to: request))
        XCTAssertFalse(substituted.isSemanticallyBound(to: request))

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
            payload: try makeEncryptedPayload(
                Data("tampered".utf8),
                databaseID: validPut.databaseID,
                collection: validPut.collection,
                recordID: validPut.recordID,
                ownerAccountID: nil,
                revision: validPut.expectedRevision + 1
            ),
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

        let envelope = NoctwebDataEncryptedPayloadV1(
            keyID: Data(repeating: 7, count: NoctwebDataV1.payloadKeyIDBytes),
            nonce: Data(repeating: 8, count: NoctwebDataV1.payloadNonceBytes),
            ciphertext: Data(repeating: 9, count: 17)
        )
        let canonical = try noctwebDataEncodeEncryptedPayload(envelope)
        let noncanonical = try JSONSerialization.data(
            withJSONObject: JSONSerialization.jsonObject(with: canonical),
            options: [.prettyPrinted]
        )
        XCTAssertNotEqual(canonical, noncanonical)
        XCTAssertNil(noctwebDataEncryptedPayload(from: noncanonical))

        let javascriptCanonical = Data(#"{"algorithm":"AES-256-GCM","ciphertext":"JMi2DSJ0Z/JVpcU5CIQ0IM97uisCnhJNGohgj4dtx0uZpw16tPRIKG8=","keyID":"2OKzgoUstze0dFHk3ziYo3hFsJ6WdhimRJMXfDrUrss=","nonce":"xTXJhmHT5CYG37z3","version":1}"#.utf8)
        XCTAssertNotNil(
            noctwebDataEncryptedPayload(from: javascriptCanonical),
            "Swift must accept the JavaScript canonical form without escaped base64 slashes"
        )
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
        let encryptedPayload = try makeEncryptedPayload(
            payload,
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: accountID,
            revision: expectedRevision + 1
        )
        let key = Data(SHA256.hash(data: encryptedPayload + Data(recordID.utf8)))
        let expiresAt = authorizationExpiry()
        let draftAuthorization = NoctwebDataAuthorizationV1(
            actorKind: .account,
            actorID: accountID,
            nonce: nonce,
            expiresAt: expiresAt,
            signature: Data(repeating: 0, count: NoctwebDataV1.accountSignatureBytes)
        )
        let draft = NoctwebDataRecordPutRequestV1(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: accountID,
            payload: encryptedPayload,
            expectedRevision: expectedRevision,
            idempotencyKey: key,
            authorization: draftAuthorization
        )
        let authorization = NoctwebDataAuthorizationV1(
            actorKind: .account,
            actorID: accountID,
            nonce: nonce,
            expiresAt: expiresAt,
            signature: try account.sign(NoctwebDataTranscriptV1.putRecord(draft))
        )
        return .init(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: accountID,
            payload: encryptedPayload,
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
        accountID: String,
        expiresAt suppliedExpiry: Date? = nil
    ) throws -> NoctwebDataRecordGetRequestV1 {
        let nonce = Data(repeating: 4, count: NoctwebDataV1.nonceBytes)
        let expiresAt = suppliedExpiry ?? authorizationExpiry()
        let draftAuthorization = NoctwebDataAuthorizationV1(
            actorKind: .account,
            actorID: accountID,
            nonce: nonce,
            expiresAt: expiresAt,
            signature: Data(repeating: 0, count: NoctwebDataV1.accountSignatureBytes)
        )
        let draft = NoctwebDataRecordGetRequestV1(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: accountID,
            authorization: draftAuthorization
        )
        let authorization = NoctwebDataAuthorizationV1(
            actorKind: .account,
            actorID: accountID,
            nonce: nonce,
            expiresAt: expiresAt,
            signature: try account.sign(NoctwebDataTranscriptV1.getRecord(draft))
        )
        return .init(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: accountID,
            authorization: authorization
        )
    }

    private func makePublisherPut(
        databaseID: String,
        collection: String,
        recordID: String,
        payload: Data,
        publisher: Curve25519.Signing.PrivateKey,
        publisherID: String,
        ownerAccountID: String? = nil
    ) throws -> NoctwebDataRecordPutRequestV1 {
        let nonce = Data(repeating: 5, count: NoctwebDataV1.nonceBytes)
        let encryptedPayload = try makeEncryptedPayload(
            payload,
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: ownerAccountID,
            revision: 1
        )
        let key = Data(SHA256.hash(data: encryptedPayload + Data(recordID.utf8)))
        let expiresAt = authorizationExpiry()
        let draftAuthorization = NoctwebDataAuthorizationV1(
            actorKind: .publisher,
            actorID: publisherID,
            nonce: nonce,
            expiresAt: expiresAt,
            signature: Data(repeating: 0, count: NoctwebDataV1.publisherSignatureBytes)
        )
        let draft = NoctwebDataRecordPutRequestV1(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: ownerAccountID,
            payload: encryptedPayload,
            expectedRevision: 0,
            idempotencyKey: key,
            authorization: draftAuthorization
        )
        let authorization = NoctwebDataAuthorizationV1(
            actorKind: .publisher,
            actorID: publisherID,
            nonce: nonce,
            expiresAt: expiresAt,
            signature: try publisher.signature(for: NoctwebDataTranscriptV1.putRecord(draft))
        )
        return .init(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: ownerAccountID,
            payload: encryptedPayload,
            expectedRevision: 0,
            idempotencyKey: key,
            authorization: authorization
        )
    }

    private func makePublisherGet(
        databaseID: String,
        collection: String,
        recordID: String,
        publisher: Curve25519.Signing.PrivateKey,
        publisherID: String,
        ownerAccountID: String? = nil
    ) throws -> NoctwebDataRecordGetRequestV1 {
        let nonce = Data(repeating: 6, count: NoctwebDataV1.nonceBytes)
        let expiresAt = authorizationExpiry()
        let draftAuthorization = NoctwebDataAuthorizationV1(
            actorKind: .publisher,
            actorID: publisherID,
            nonce: nonce,
            expiresAt: expiresAt,
            signature: Data(repeating: 0, count: NoctwebDataV1.publisherSignatureBytes)
        )
        let draft = NoctwebDataRecordGetRequestV1(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: ownerAccountID,
            authorization: draftAuthorization
        )
        return .init(
            databaseID: databaseID,
            collection: collection,
            recordID: recordID,
            ownerAccountID: ownerAccountID,
            authorization: .init(
                actorKind: .publisher,
                actorID: publisherID,
                nonce: nonce,
                expiresAt: expiresAt,
                signature: try publisher.signature(
                    for: NoctwebDataTranscriptV1.getRecord(draft)
                )
            )
        )
    }

    private func makePublisherDelete(
        record: NoctwebDataRecordV1,
        publisher: Curve25519.Signing.PrivateKey,
        publisherID: String
    ) throws -> NoctwebDataRecordDeleteRequestV1 {
        let nonce = Data(repeating: 6, count: NoctwebDataV1.nonceBytes)
        let key = Data(SHA256.hash(data: Data(
            "\(record.collection)\u{0}\(record.ownerAccountID ?? "")\u{0}\(record.recordID)".utf8
        )))
        let expiresAt = authorizationExpiry()
        let draftAuthorization = NoctwebDataAuthorizationV1(
            actorKind: .publisher,
            actorID: publisherID,
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
                actorID: publisherID,
                nonce: nonce,
                expiresAt: expiresAt,
                signature: try publisher.signature(
                    for: NoctwebDataTranscriptV1.deleteRecord(draft)
                )
            )
        )
    }

    private func authorizationExpiry() -> Date {
        Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970) + 120)
    }

    private func makeEncryptedPayload(
        _ plaintext: Data,
        databaseID: String,
        collection: String,
        recordID: String,
        ownerAccountID: String?,
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
        return try noctwebDataEncodeEncryptedPayload(.init(
            keyID: keyID,
            nonce: nonce,
            ciphertext: sealed.ciphertext + sealed.tag
        ))
    }
}

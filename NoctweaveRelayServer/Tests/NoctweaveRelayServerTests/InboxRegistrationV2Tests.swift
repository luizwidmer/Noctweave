import Crypto
import Foundation
import XCTest
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite
#endif
@testable import NoctweaveRelayServer

final class InboxRegistrationV2Tests: XCTestCase {
    func testCanonicalProofPayloadMatchesCoreParityVector() throws {
        let request = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: "inbox",
            accessPublicKey: Data([0x22])
        )
        let proof = RelayActorProof(
            fingerprint: "",
            publicSigningKey: Data(),
            signedAt: try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-07-16T12:34:56Z")),
            nonce: try XCTUnwrap(UUID(uuidString: "11111111-1111-4111-8111-111111111111")),
            signature: Data()
        )

        XCTAssertEqual(
            String(decoding: try request.signableData(for: proof), as: UTF8.self),
            #"{"accessPublicKey":"Ig==","inboxId":"inbox","nonce":"11111111-1111-4111-8111-111111111111","registrationVersion":2,"signedAt":"2026-07-16T12:34:56Z"}"#
        )
    }

    func testPrivacyMinimizedWireRequestContainsNoIdentityOrContactMaterial() throws {
        let signer = try makeSignerOrSkip()
        let inboxId = InboxAddress.derived(from: signer.publicKey)
        let request = try signedV2Request(inboxId: inboxId, signer: signer)
        let data = try RelayCodec.encoder().encode(RelayRequest.registerInbox(request))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let registration = try XCTUnwrap(object["registerInbox"] as? [String: Any])

        XCTAssertEqual(registration["registrationVersion"] as? Int, 2)
        XCTAssertNil(registration["contactOffer"])
        XCTAssertEqual(
            Set(registration.keys),
            ["accessProof", "accessPublicKey", "inboxId", "registrationVersion"]
        )
        let json = String(decoding: data, as: UTF8.self)
        for forbidden in [
            "contactOffer", "displayName", "signingPublicKey", "agreementPublicKey",
            "installationManifest", "endpointCertificate", "prekey"
        ] {
            XCTAssertFalse(json.contains(forbidden), forbidden)
        }
    }

    func testRelayAcceptsV2AndRejectsDowngradeWrongKeyTamperContactOfferAndReplay() throws {
        let harness = try RelayTCPHarness()
        defer { try? harness.shutdown() }
        let signer = try makeSignerOrSkip()
        let inboxId = InboxAddress.derived(from: signer.publicKey)
        let valid = try signedV2Request(inboxId: inboxId, signer: signer)

        let downgraded = RegisterInboxRequest(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey,
            accessProof: valid.accessProof
        )
        XCTAssertEqual(
            try harness.send(.registerInbox(downgraded)).error,
            "Inbox registration is not bound to a valid identity offer"
        )

        let forbiddenOffer = ContactOffer(
            version: 2,
            displayName: "Must stay off relay",
            inboxId: inboxId,
            relay: harness.endpoint,
            signingPublicKey: Data("IDENTITY-SIGNING-PUBLIC-KEY".utf8),
            agreementPublicKey: Data("IDENTITY-AGREEMENT-PUBLIC-KEY".utf8),
            inboxAccessPublicKey: signer.publicKey,
            fingerprint: "identity-fingerprint",
            signature: Data()
        )
        let v2WithContact = RegisterInboxRequest(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey,
            registrationVersion: 2,
            contactOffer: forbiddenOffer,
            accessProof: valid.accessProof
        )
        XCTAssertEqual(
            try harness.send(.registerInbox(v2WithContact)).error,
            "Privacy-minimized inbox registration must not include a contact offer"
        )

        let wrongSigner = try makeSignerOrSkip()
        let wrongDraft = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey
        )
        let wrongKeyRequest = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey,
            accessProof: try wrongSigner.proof { try wrongDraft.signableData(for: $0) }
        )
        XCTAssertEqual(
            try harness.send(.registerInbox(wrongKeyRequest)).error,
            "Actor proof fingerprint mismatch."
        )

        let proof = try XCTUnwrap(valid.accessProof)
        let tamperedProof = RelayActorProof(
            fingerprint: proof.fingerprint,
            publicSigningKey: proof.publicSigningKey,
            signedAt: proof.signedAt.addingTimeInterval(1),
            nonce: proof.nonce,
            signature: proof.signature
        )
        let tampered = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey,
            accessProof: tamperedProof
        )
        XCTAssertEqual(
            try harness.send(.registerInbox(tampered)).error,
            "Invalid actor proof signature."
        )

        let unsupported = RegisterInboxRequest(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey,
            registrationVersion: 3,
            accessProof: valid.accessProof
        )
        XCTAssertEqual(
            try harness.send(.registerInbox(unsupported)).error,
            "Unsupported inbox registration version"
        )

        XCTAssertEqual(try harness.send(.registerInbox(valid)).type, .ok)
        XCTAssertEqual(
            try harness.send(.registerInbox(valid)).error,
            "Actor proof replay detected."
        )
    }

    func testSQLiteInboxRegistrationPersistsOnlyAddressAccessKeyAndMailboxState() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("relay.sqlite")
        let accessPublicKey = Data("ACCESS-PUBLIC-KEY-ONLY".utf8)
        let inboxId = InboxAddress.derived(from: accessPublicKey)

        do {
            let store = RelayStore(fileURL: storeURL, maxInboxMessages: nil, temporalBucketSeconds: 300)
            try store.registerInbox(inboxId: inboxId, accessPublicKey: accessPublicKey)
            XCTAssertEqual(store.inboxAccessPublicKey(for: inboxId), accessPublicKey)
        }

        var database: OpaquePointer?
        XCTAssertEqual(sqlite3_open(storeURL.path, &database), SQLITE_OK)
        defer { sqlite3_close(database) }
        var columnsStatement: OpaquePointer?
        XCTAssertEqual(
            sqlite3_prepare_v2(
                database,
                "PRAGMA table_info(relay_inbox_registrations);",
                -1,
                &columnsStatement,
                nil
            ),
            SQLITE_OK
        )
        defer { sqlite3_finalize(columnsStatement) }
        var columns: Set<String> = []
        while sqlite3_step(columnsStatement) == SQLITE_ROW {
            columns.insert(String(cString: sqlite3_column_text(columnsStatement, 1)))
        }
        XCTAssertEqual(columns, ["inbox_id", "registered_at", "access_public_key", "value"])

        var valueStatement: OpaquePointer?
        XCTAssertEqual(
            sqlite3_prepare_v2(
                database,
                "SELECT inbox_id, access_public_key, value FROM relay_inbox_registrations LIMIT 1;",
                -1,
                &valueStatement,
                nil
            ),
            SQLITE_OK
        )
        defer { sqlite3_finalize(valueStatement) }
        XCTAssertEqual(sqlite3_step(valueStatement), SQLITE_ROW)
        XCTAssertEqual(String(cString: sqlite3_column_text(valueStatement, 0)), inboxId)
        let persistedAccessKey = Data(
            bytes: sqlite3_column_blob(valueStatement, 1),
            count: Int(sqlite3_column_bytes(valueStatement, 1))
        )
        XCTAssertEqual(persistedAccessKey, accessPublicKey)
        let persistedRecord = Data(
            bytes: sqlite3_column_blob(valueStatement, 2),
            count: Int(sqlite3_column_bytes(valueStatement, 2))
        )
        for forbidden in [
            "IDENTITY-SIGNING-PUBLIC-KEY", "IDENTITY-AGREEMENT-PUBLIC-KEY",
            "Must stay off relay", "ContactOffer", "InstallationManifest",
            "endpointCertificate", "prekey", "contact_offer", "display_name"
        ] {
            XCTAssertNil(persistedRecord.range(of: Data(forbidden.utf8)), forbidden)
        }
    }

    func testLegacyRegistrationDecodesWithoutV2Discriminator() throws {
        let data = Data(#"{"inboxId":"legacy","accessPublicKey":"Ig=="}"#.utf8)
        let decoded = try RelayCodec.decoder().decode(RegisterInboxRequest.self, from: data)
        XCTAssertNil(decoded.registrationVersion)
    }

    private func signedV2Request(
        inboxId: String,
        signer: InboxRegistrationV2Signer
    ) throws -> RegisterInboxRequest {
        let unsigned = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey
        )
        return RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: signer.publicKey,
            accessProof: try signer.proof { try unsigned.signableData(for: $0) }
        )
    }

    private func makeSignerOrSkip() throws -> InboxRegistrationV2Signer {
        guard let pair = OQSSignatureVerifier.shared.generateKeyPair() else {
            throw XCTSkip("ML-DSA runtime is unavailable")
        }
        return InboxRegistrationV2Signer(privateKey: pair.privateKey, publicKey: pair.publicKey)
    }
}

private struct InboxRegistrationV2Signer {
    let privateKey: Data
    let publicKey: Data

    func proof(signableData: (RelayActorProof) throws -> Data) throws -> RelayActorProof {
        let draft = RelayActorProof(
            fingerprint: Data(SHA256.hash(data: publicKey)).base64EncodedString(),
            publicSigningKey: publicKey,
            signedAt: Date(),
            nonce: UUID(),
            signature: Data()
        )
        guard let signature = OQSSignatureVerifier.shared.sign(
            data: try signableData(draft),
            privateKey: privateKey,
            publicKey: publicKey
        ) else {
            throw XCTSkip("ML-DSA signing is unavailable")
        }
        return RelayActorProof(
            fingerprint: draft.fingerprint,
            publicSigningKey: draft.publicSigningKey,
            signedAt: draft.signedAt,
            nonce: draft.nonce,
            signature: signature
        )
    }
}

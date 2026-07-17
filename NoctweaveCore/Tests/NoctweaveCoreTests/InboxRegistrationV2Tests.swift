import XCTest
@testable import NoctweaveCore

final class InboxRegistrationV2Tests: XCTestCase {
    func testCanonicalProofPayloadMatchesArchitectureV2ParityVector() throws {
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
        let accessKey = try SigningKeyPair.generate()
        let inboxId = InboxAddress.derived(from: accessKey.publicKeyData)
        let request = try signedV2Request(inboxId: inboxId, accessKey: accessKey)
        let data = try NoctweaveCoder.encode(RelayRequest.registerInbox(request), sortedKeys: true)
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
            "endpointSetManifest", "endpointCertificate", "prekey"
        ] {
            XCTAssertFalse(json.contains(forbidden), forbidden)
        }
    }

    func testRelayAcceptsV2AndRejectsWrongKeyTamperUnknownVersionAndReplay() async throws {
        let port = UInt16.random(in: 56_000...58_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(store: RelayStore())
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 200_000_000)
        let client = RelayClient(endpoint: endpoint)

        let accessKey = try SigningKeyPair.generate()
        let inboxId = InboxAddress.derived(from: accessKey.publicKeyData)
        let valid = try signedV2Request(inboxId: inboxId, accessKey: accessKey)

        let wrongKey = try SigningKeyPair.generate()
        let wrongKeyProof = try actorProof(signingKey: wrongKey) { proof in
            try RegisterInboxRequest.privacyMinimizedV2(
                inboxId: inboxId,
                accessPublicKey: accessKey.publicKeyData
            ).signableData(for: proof)
        }
        let wrongKeyRequest = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            accessProof: wrongKeyProof
        )
        let wrongKeyResponse = try await client.send(.registerInbox(wrongKeyRequest))
        XCTAssertEqual(wrongKeyResponse.error, "Actor proof fingerprint mismatch.")

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
            accessPublicKey: accessKey.publicKeyData,
            accessProof: tamperedProof
        )
        let tamperedResponse = try await client.send(.registerInbox(tampered))
        XCTAssertEqual(tamperedResponse.error, "Invalid actor proof signature.")

        let unknownVersion = RegisterInboxRequest(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            registrationVersion: 3,
            accessProof: valid.accessProof
        )
        let unknownVersionResponse = try await client.send(.registerInbox(unknownVersion))
        XCTAssertEqual(unknownVersionResponse.error, "Unsupported inbox registration version")

        let validResponse = try await client.send(.registerInbox(valid))
        XCTAssertEqual(validResponse.type, .ok)
        let replayResponse = try await client.send(.registerInbox(valid))
        XCTAssertEqual(replayResponse.error, "Actor proof replay detected.")
    }

    func testRegistrationVersionIsRequiredWhenDecoded() {
        let data = Data(#"{"inboxId":"inbox","accessPublicKey":"Ig=="}"#.utf8)
        XCTAssertThrowsError(try NoctweaveCoder.decode(RegisterInboxRequest.self, from: data))
    }

    private func signedV2Request(
        inboxId: String,
        accessKey: SigningKeyPair
    ) throws -> RegisterInboxRequest {
        let unsigned = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData
        )
        let proof = try actorProof(signingKey: accessKey) { proof in
            try unsigned.signableData(for: proof)
        }
        return RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            accessProof: proof
        )
    }

    private func actorProof(
        signingKey: SigningKeyPair,
        signableData: (RelayActorProof) throws -> Data
    ) throws -> RelayActorProof {
        let draft = RelayActorProof(
            fingerprint: CryptoBox.fingerprint(for: signingKey.publicKeyData),
            publicSigningKey: signingKey.publicKeyData,
            signedAt: Date(),
            nonce: UUID(),
            signature: Data()
        )
        return RelayActorProof(
            fingerprint: draft.fingerprint,
            publicSigningKey: draft.publicSigningKey,
            signedAt: draft.signedAt,
            nonce: draft.nonce,
            signature: try signingKey.sign(signableData(draft))
        )
    }
}

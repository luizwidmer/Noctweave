import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class EnvelopeWireFidelityTests: XCTestCase {
    func testCoreEnvelopeVectorSurvivesCodecAndPersistentRelayRoundTrip() throws {
        let vector = Data(
            """
            {
              "id":"11111111-1111-1111-1111-111111111111",
              "conversationId":"core-envelope-vector",
              "sessionId":"session-v2",
              "senderFingerprint":"REREREREREREREREREREREREREREREREREREREREREQ=",
              "sentAt":"2027-01-15T08:00:00Z",
              "messageCounter":42,
              "kemCiphertext":"AQID",
              "prekey":{"kind":"oneTime","id":"22222222-2222-2222-2222-222222222222"},
              "rootRatchet":{
                "counter":7,
                "kemCiphertext":"BAUG",
                "sentAt":"2027-01-15T08:01:00Z"
              },
              "authenticatedContext":{
                "purpose":"group",
                "group":{
                  "protocolVersion":"noctweave-pq-group-experimental-2",
                  "cipherSuite":"Noctweave-PQ-Group-Experimental-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-2",
                  "groupId":"33333333-3333-3333-3333-333333333333",
                  "epoch":9,
                  "senderFingerprint":"REREREREREREREREREREREREREREREREREREREREREQ=",
                  "transcriptHash":"VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU="
                }
              },
              "payload":{"nonce":"ERERERERERERERER","ciphertext":"ISIjJA==","tag":"MzMzMzMzMzMzMzMzMzMzMw=="},
              "signature":"QkNERQ=="
            }
            """.utf8
        )
        let envelope = try RelayCodec.decoder().decode(Envelope.self, from: vector)
        XCTAssertEqual(envelope.prekey?.kind, .oneTime)
        XCTAssertEqual(
            envelope.prekey?.id,
            UUID(uuidString: "22222222-2222-2222-2222-222222222222")
        )
        XCTAssertEqual(envelope.rootRatchet?.counter, 7)
        XCTAssertEqual(envelope.rootRatchet?.kemCiphertext, Data([0x04, 0x05, 0x06]))
        XCTAssertEqual(envelope.authenticatedContext?.purpose, .group)
        XCTAssertEqual(
            envelope.authenticatedContext?.group?.protocolVersion,
            MLSGroupEpochState.currentProtocolVersion
        )
        XCTAssertEqual(
            envelope.authenticatedContext?.group?.cipherSuite,
            MLSGroupEpochState.currentCipherSuite
        )
        XCTAssertEqual(envelope.authenticatedContext?.group?.epoch, 9)
        XCTAssertEqual(
            envelope.authenticatedContext?.group?.transcriptHash,
            Data(repeating: 0x55, count: 32)
        )
        let reencodedVector = try RelayCodec.encoder(sortedKeys: true).encode(envelope)
        XCTAssertEqual(try jsonObject(reencodedVector), try jsonObject(vector))

        let persistentEnvelope = Envelope(
            id: envelope.id,
            conversationId: envelope.conversationId,
            sessionId: envelope.sessionId,
            senderFingerprint: envelope.senderFingerprint,
            sentAt: envelope.sentAt,
            messageCounter: envelope.messageCounter,
            kemCiphertext: Data(repeating: 0x01, count: 1_088),
            prekey: envelope.prekey,
            rootRatchet: RootRatchet(
                counter: 7,
                kemCiphertext: Data(repeating: 0x04, count: 1_088),
                sentAt: Date(timeIntervalSince1970: 1_800_000_060)
            ),
            authenticatedContext: envelope.authenticatedContext,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: 12),
                ciphertext: Data(repeating: 0x21, count: 512),
                tag: Data(repeating: 0x33, count: 16)
            ),
            signature: Data(
                repeating: 0x42,
                count: OQSSignatureVerifier.mlDSA65SignatureBytes
            )
        )
        XCTAssertTrue(persistentEnvelope.isStructurallyValid)

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-envelope-vector-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("relay.sqlite")
        let inboxId = InboxAddress.generate()
        let writer = RelayStore(fileURL: storeURL, maxInboxMessages: nil, temporalBucketSeconds: 0)
        try writer.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA9]))
        _ = try writer.deliver(persistentEnvelope, to: inboxId)

        let reader = RelayStore(fileURL: storeURL, maxInboxMessages: nil, temporalBucketSeconds: 0)
        try reader.load()
        let persisted = try XCTUnwrap(reader.fetch(inboxId: inboxId, maxCount: nil).first)
        XCTAssertEqual(persisted, persistentEnvelope)
        let reencoded = try RelayCodec.encoder(sortedKeys: true).encode(persisted)
        XCTAssertEqual(
            try jsonObject(reencoded),
            try jsonObject(RelayCodec.encoder(sortedKeys: true).encode(persistentEnvelope))
        )
    }

    func testLegacyEnvelopeVectorWithoutOptionalV2FieldsStillDecodes() throws {
        let vector = Data(
            """
            {
              "id":"AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
              "conversationId":"legacy-envelope-vector",
              "sessionId":null,
              "senderFingerprint":"legacy",
              "sentAt":"2027-01-15T08:00:00Z",
              "messageCounter":1,
              "kemCiphertext":null,
              "payload":{"nonce":"ERERERERERERERER","ciphertext":"IQ==","tag":"MzMzMzMzMzMzMzMzMzMzMw=="},
              "signature":"Qg=="
            }
            """.utf8
        )
        let envelope = try RelayCodec.decoder().decode(Envelope.self, from: vector)
        XCTAssertNil(envelope.prekey)
        XCTAssertNil(envelope.rootRatchet)
        XCTAssertNil(envelope.authenticatedContext)
        let roundTripped = try RelayCodec.decoder().decode(
            Envelope.self,
            from: RelayCodec.encoder(sortedKeys: true).encode(envelope)
        )
        XCTAssertEqual(roundTripped, envelope)
    }

    func testDirectV4NegotiationContextSurvivesRelayCodecRoundTrip() throws {
        let vector = Data(
            """
            {
              "id":"44444444-4444-4444-4444-444444444444",
              "conversationId":"direct-v4-envelope-vector",
              "sessionId":"session-v4",
              "senderFingerprint":"REREREREREREREREREREREREREREREREREREREREREQ=",
              "sentAt":"2027-01-15T08:00:00Z",
              "messageCounter":3,
              "authenticatedContext":{
                "purpose":"directV4",
                "directV4":{
                  "version":4,
                  "payloadFormat":"nw.wire-payload.v2",
                  "cipherSuite":"nw.direct-v4.ml-kem-768.ml-dsa-65.hkdf-sha256.hmac-sha256.aes-256-gcm",
                  "negotiatedCapabilitiesDigest":"iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg=",
                  "eventId":"55555555-5555-5555-5555-555555555555",
                  "senderEndpointHandle":"REREREREREREREREREREREREREREREREREREREREREQ=",
                  "senderCertificateDigest":"VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU=",
                  "recipientEndpointHandle":"ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY=",
                  "senderManifestEpoch":4,
                  "recipientManifestEpoch":7,
                  "recipientCertificateDigest":"d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c="
                }
              },
              "payload":{"nonce":"ERERERERERERERER","ciphertext":"ISIjJA==","tag":"MzMzMzMzMzMzMzMzMzMzMw=="},
              "signature":"QkNERQ=="
            }
            """.utf8
        )

        let envelope = try RelayCodec.decoder().decode(Envelope.self, from: vector)
        XCTAssertEqual(envelope.authenticatedContext?.purpose, .directV4)
        XCTAssertEqual(
            envelope.authenticatedContext?.directV4?.payloadFormat,
            "nw.wire-payload.v2"
        )
        XCTAssertEqual(
            envelope.authenticatedContext?.directV4?.cipherSuite,
            "nw.direct-v4.ml-kem-768.ml-dsa-65.hkdf-sha256.hmac-sha256.aes-256-gcm"
        )
        XCTAssertEqual(
            envelope.authenticatedContext?.directV4?.negotiatedCapabilitiesDigest,
            Data(repeating: 0x88, count: 32)
        )
        let reencoded = try RelayCodec.encoder(sortedKeys: true).encode(envelope)
        XCTAssertEqual(try jsonObject(reencoded), try jsonObject(vector))
    }

    func testDirectV4StructuralValidationRejectsNegotiationTampering() {
        XCTAssertTrue(makeDirectV4Envelope().isStructurallyValid)
        XCTAssertFalse(
            makeDirectV4Envelope(cipherSuite: "nw.direct-v4.downgraded").isStructurallyValid
        )
        XCTAssertFalse(
            makeDirectV4Envelope(capabilitiesDigest: Data(repeating: 0x88, count: 31))
                .isStructurallyValid
        )
    }

    private func makeDirectV4Envelope(
        cipherSuite: String = "nw.direct-v4.ml-kem-768.ml-dsa-65.hkdf-sha256.hmac-sha256.aes-256-gcm",
        capabilitiesDigest: Data = Data(repeating: 0x88, count: 32)
    ) -> Envelope {
        let senderHandle = RelationshipEndpointHandle(
            rawValue: Data(repeating: 0x44, count: 32).base64EncodedString()
        )
        return Envelope(
            conversationId: "direct-v4-structural-validation",
            sessionId: "session-v4",
            senderFingerprint: senderHandle.rawValue,
            sentAt: Date(timeIntervalSince1970: 1_800_000_000),
            messageCounter: 3,
            authenticatedContext: MessageAuthenticatedContext(
                purpose: .directV4,
                group: nil,
                directV4: DirectMessageAuthenticatedContextV4(
                    version: 4,
                    payloadFormat: "nw.wire-payload.v2",
                    cipherSuite: cipherSuite,
                    negotiatedCapabilitiesDigest: capabilitiesDigest,
                    eventId: UUID(uuidString: "55555555-5555-5555-5555-555555555555")!,
                    senderEndpointHandle: senderHandle,
                    senderCertificateDigest: Data(repeating: 0x55, count: 32),
                    recipientEndpointHandle: RelationshipEndpointHandle(
                        rawValue: Data(repeating: 0x66, count: 32).base64EncodedString()
                    ),
                    senderManifestEpoch: 4,
                    recipientManifestEpoch: 7,
                    recipientCertificateDigest: Data(repeating: 0x77, count: 32)
                )
            ),
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: 12),
                ciphertext: Data(repeating: 0x21, count: 512),
                tag: Data(repeating: 0x33, count: 16)
            ),
            signature: Data(
                repeating: 0x42,
                count: OQSSignatureVerifier.mlDSA65SignatureBytes
            )
        )
    }

    private func jsonObject(_ data: Data) throws -> NSDictionary {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: data, options: []) as? NSDictionary
        )
    }
}

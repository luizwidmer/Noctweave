import Crypto
import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class GroupEnvelopeAuthenticationTests: XCTestCase {
    func testLinuxVerifierAcceptsOnlyCompleteExperimentalV2Transcript() throws {
        guard OQSSignatureVerifier.shared.isAvailable else {
            throw XCTSkip("liboqs runtime is unavailable")
        }
        let keys = try XCTUnwrap(OQSSignatureVerifier.shared.generateKeyPair())
        let fingerprint = Data(SHA256.hash(data: keys.publicKey)).base64EncodedString()
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0x11, count: 12),
            ciphertext: Data(repeating: 0x22, count: 512),
            tag: Data(repeating: 0x33, count: 16)
        )
        let unsigned = GroupRatchetEnvelope(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            groupId: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!,
            epoch: 7,
            transcriptHash: Data(repeating: 0x44, count: 32),
            senderFingerprint: fingerprint,
            sentAt: Date(timeIntervalSince1970: 1_800_000_000),
            messageCounter: 9,
            payload: payload,
            signature: Data(repeating: 0, count: OQSSignatureVerifier.mlDSA65SignatureBytes)
        )
        let signature = try XCTUnwrap(
            OQSSignatureVerifier.shared.sign(
                data: try signableData(for: unsigned),
                privateKey: keys.privateKey,
                publicKey: keys.publicKey
            )
        )
        let envelope = replacing(unsigned, signature: signature)

        XCTAssertTrue(envelope.verifySignature(publicSigningKey: keys.publicKey))
        XCTAssertFalse(
            replacing(envelope, id: UUID()).verifySignature(publicSigningKey: keys.publicKey)
        )
        XCTAssertFalse(
            replacing(
                envelope,
                protocolVersion: "noctweave-pq-group-experimental-1"
            ).verifySignature(publicSigningKey: keys.publicKey)
        )
        XCTAssertFalse(
            replacing(envelope, sentAt: envelope.sentAt.addingTimeInterval(1))
                .verifySignature(publicSigningKey: keys.publicKey)
        )
        XCTAssertFalse(
            replacing(envelope, payload: mutatingNonce(envelope.payload))
                .verifySignature(publicSigningKey: keys.publicKey)
        )
    }

    func testLinuxGroupCarrierContextPreservesProfileAndCipherSuite() throws {
        let context = MessageAuthenticatedContext(
            purpose: .group,
            group: GroupMessageAuthenticatedContext(
                protocolVersion: MLSGroupEpochState.currentProtocolVersion,
                cipherSuite: MLSGroupEpochState.currentCipherSuite,
                groupId: UUID(),
                epoch: 2,
                senderFingerprint: Data(repeating: 0x51, count: 32).base64EncodedString(),
                transcriptHash: Data(repeating: 0x61, count: 32)
            )
        )
        let decoded = try RelayCodec.decoder().decode(
            MessageAuthenticatedContext.self,
            from: RelayCodec.encoder(sortedKeys: true).encode(context)
        )

        XCTAssertEqual(decoded, context)
        XCTAssertEqual(decoded.group?.protocolVersion, MLSGroupEpochState.currentProtocolVersion)
        XCTAssertEqual(decoded.group?.cipherSuite, MLSGroupEpochState.currentCipherSuite)
    }

    func testLinuxDecoderDoesNotInventMissingGroupEnvelopeProfile() throws {
        let envelope = GroupRatchetEnvelope(
            groupId: UUID(),
            epoch: 0,
            transcriptHash: Data(repeating: 0x41, count: 32),
            senderFingerprint: Data(repeating: 0x42, count: 32).base64EncodedString(),
            sentAt: Date(timeIntervalSince1970: 1_800_000_000),
            messageCounter: 0,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x43, count: 12),
                ciphertext: Data(repeating: 0x44, count: 512),
                tag: Data(repeating: 0x45, count: 16)
            ),
            signature: Data(repeating: 0x46, count: OQSSignatureVerifier.mlDSA65SignatureBytes)
        )
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: RelayCodec.encoder(sortedKeys: true).encode(envelope)
            ) as? [String: Any]
        )
        object.removeValue(forKey: "protocolVersion")
        object.removeValue(forKey: "cipherSuite")
        let legacy = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])

        XCTAssertThrowsError(
            try RelayCodec.decoder().decode(GroupRatchetEnvelope.self, from: legacy)
        )
    }

    private func signableData(for envelope: GroupRatchetEnvelope) throws -> Data {
        try RelayCodec.encoder(sortedKeys: true).encode(
            SignaturePayload(
                version: 2,
                id: envelope.id,
                protocolVersion: envelope.protocolVersion,
                cipherSuite: envelope.cipherSuite,
                groupId: envelope.groupId,
                epoch: envelope.epoch,
                transcriptHash: envelope.transcriptHash,
                senderFingerprint: envelope.senderFingerprint,
                sentAt: envelope.sentAt,
                messageCounter: envelope.messageCounter,
                payload: envelope.payload
            )
        )
    }

    private func replacing(
        _ envelope: GroupRatchetEnvelope,
        id: UUID? = nil,
        protocolVersion: String? = nil,
        sentAt: Date? = nil,
        payload: EncryptedPayload? = nil,
        signature: Data? = nil
    ) -> GroupRatchetEnvelope {
        GroupRatchetEnvelope(
            id: id ?? envelope.id,
            protocolVersion: protocolVersion ?? envelope.protocolVersion,
            cipherSuite: envelope.cipherSuite,
            groupId: envelope.groupId,
            epoch: envelope.epoch,
            transcriptHash: envelope.transcriptHash,
            senderFingerprint: envelope.senderFingerprint,
            sentAt: sentAt ?? envelope.sentAt,
            messageCounter: envelope.messageCounter,
            payload: payload ?? envelope.payload,
            signature: signature ?? envelope.signature
        )
    }

    private func mutatingNonce(_ payload: EncryptedPayload) -> EncryptedPayload {
        var nonce = payload.nonce
        nonce[nonce.startIndex] ^= 0x01
        return EncryptedPayload(
            nonce: nonce,
            ciphertext: payload.ciphertext,
            tag: payload.tag
        )
    }
}

private struct SignaturePayload: Codable {
    let version: Int
    let id: UUID
    let protocolVersion: String
    let cipherSuite: String
    let groupId: UUID
    let epoch: UInt64
    let transcriptHash: Data
    let senderFingerprint: String
    let sentAt: Date
    let messageCounter: UInt64
    let payload: EncryptedPayload
}

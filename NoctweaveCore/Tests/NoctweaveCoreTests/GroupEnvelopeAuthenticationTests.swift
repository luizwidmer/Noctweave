import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class GroupEnvelopeAuthenticationTests: XCTestCase {
    func testEpochHistoryValidatorRejectsSupersededProfileAndSuite() {
        let transcript = Data(repeating: 0x31, count: 32)
        let commit = MLSGroupCommitSummary(
            operation: .create,
            actorFingerprint: Data(repeating: 0x32, count: 32).base64EncodedString(),
            epoch: 0,
            committedAt: Date(timeIntervalSince1970: 1_800_000_000),
            memberFingerprints: [],
            previousTranscriptHash: nil,
            transcriptHash: transcript
        )
        let oldProfile = MLSGroupEpochState(
            protocolVersion: "noctweave-pq-group-experimental-1",
            groupId: UUID(),
            epoch: 0,
            treeHash: Data(repeating: 0x33, count: 32),
            confirmedTranscriptHash: transcript,
            lastCommit: commit
        )
        let oldSuite = MLSGroupEpochState(
            cipherSuite: "Noctweave-PQ-Group-Experimental-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-1",
            groupId: UUID(),
            epoch: 0,
            treeHash: Data(repeating: 0x33, count: 32),
            confirmedTranscriptHash: transcript,
            lastCommit: commit
        )

        XCTAssertTrue(
            MLSGroupEpochHistoryValidator.issues(currentState: oldProfile, history: [commit])
                .contains(.unsupportedProtocolVersion)
        )
        XCTAssertTrue(
            MLSGroupEpochHistoryValidator.issues(currentState: oldSuite, history: [commit])
                .contains(.unsupportedCipherSuite)
        )
    }

    func testCurrentEnvelopeRoundTripsWithCompleteV2Context() throws {
        let fixture = try makeFixture()

        XCTAssertEqual(GroupRatchet.applicationEnvelopeVersion, 2)
        XCTAssertEqual(fixture.envelope.protocolVersion, MLSGroupEpochState.currentProtocolVersion)
        XCTAssertEqual(fixture.envelope.cipherSuite, MLSGroupEpochState.currentCipherSuite)
        XCTAssertTrue(
            fixture.envelope.verifySignature(
                publicSigningKey: fixture.sender.signingKey.publicKeyData
            )
        )

        var receiver = fixture.receiverState
        XCTAssertEqual(
            try GroupRatchet.decrypt(
                envelope: fixture.envelope,
                senderPublicSigningKey: fixture.sender.signingKey.publicKeyData,
                state: &receiver
            ),
            .text("authenticated group envelope")
        )
    }

    func testSignatureRejectsTamperingOfEveryVisibleEnvelopeField() throws {
        let fixture = try makeFixture()
        let envelope = fixture.envelope
        let alternateFingerprint = Data(repeating: 0xA5, count: 32).base64EncodedString()
        let alternateTranscript = Data(SHA256.hash(data: Data("other transcript".utf8)))

        let mutations: [GroupRatchetEnvelope] = [
            replacing(envelope, id: UUID()),
            replacing(envelope, protocolVersion: "noctweave-pq-group-experimental-1"),
            replacing(
                envelope,
                cipherSuite: "Noctweave-PQ-Group-Experimental-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-1"
            ),
            replacing(envelope, groupId: UUID()),
            replacing(envelope, epoch: envelope.epoch + 1),
            replacing(envelope, transcriptHash: alternateTranscript),
            replacing(envelope, senderFingerprint: alternateFingerprint),
            replacing(envelope, sentAt: envelope.sentAt.addingTimeInterval(1)),
            replacing(envelope, messageCounter: envelope.messageCounter + 1),
            replacing(envelope, payload: mutatingNonce(envelope.payload)),
            replacing(envelope, payload: doublingCiphertext(envelope.payload)),
            replacing(envelope, payload: mutatingCiphertext(envelope.payload)),
            replacing(envelope, payload: mutatingTag(envelope.payload))
        ]

        for mutation in mutations {
            XCTAssertFalse(
                mutation.verifySignature(
                    publicSigningKey: fixture.sender.signingKey.publicKeyData
                ),
                "Mutation unexpectedly retained a valid group-envelope signature: \(mutation)"
            )
        }
    }

    func testAEADRejectsResignedUUIDTimestampAndCiphertextMetadataTampering() throws {
        let fixture = try makeFixture()
        let envelope = fixture.envelope
        let mutations = [
            replacing(envelope, id: UUID()),
            replacing(envelope, sentAt: envelope.sentAt.addingTimeInterval(1)),
            replacing(envelope, payload: mutatingNonce(envelope.payload)),
            replacing(envelope, payload: doublingCiphertext(envelope.payload)),
            replacing(envelope, payload: mutatingCiphertext(envelope.payload)),
            replacing(envelope, payload: mutatingTag(envelope.payload))
        ]

        for mutation in mutations {
            let resigned = try resign(mutation, with: fixture.sender.signingKey)
            XCTAssertTrue(
                resigned.verifySignature(
                    publicSigningKey: fixture.sender.signingKey.publicKeyData
                )
            )
            var receiver = fixture.receiverState
            XCTAssertThrowsError(
                try GroupRatchet.decrypt(
                    envelope: resigned,
                    senderPublicSigningKey: fixture.sender.signingKey.publicKeyData,
                    state: &receiver
                )
            )
            XCTAssertEqual(receiver, fixture.receiverState)
        }
    }

    func testLegacyProfileHasNoVerifierFallback() throws {
        let fixture = try makeFixture()
        let legacy = try resign(
            replacing(
                fixture.envelope,
                protocolVersion: "noctweave-pq-group-experimental-1",
                cipherSuite: "Noctweave-PQ-Group-Experimental-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-1"
            ),
            with: fixture.sender.signingKey
        )

        XCTAssertFalse(legacy.isStructurallyValid)
        XCTAssertFalse(
            legacy.verifySignature(publicSigningKey: fixture.sender.signingKey.publicKeyData)
        )
        var receiver = fixture.receiverState
        XCTAssertThrowsError(
            try GroupRatchet.decrypt(
                envelope: legacy,
                senderPublicSigningKey: fixture.sender.signingKey.publicKeyData,
                state: &receiver
            )
        ) { error in
            XCTAssertEqual(error as? CryptoError, .invalidPayload)
        }
    }

    func testLegacyEnvelopeWithoutProfileAndCipherSuiteDoesNotDecode() throws {
        let fixture = try makeFixture()
        let encoded = try NoctweaveCoder.encode(fixture.envelope, sortedKeys: true)
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        object.removeValue(forKey: "protocolVersion")
        object.removeValue(forKey: "cipherSuite")
        let legacy = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])

        XCTAssertThrowsError(
            try NoctweaveCoder.decode(GroupRatchetEnvelope.self, from: legacy)
        )
    }

    func testV2EnvelopeRetainsReplayProtectionAndBoundedOutOfOrderDelivery() throws {
        let groupId = UUID()
        let transcriptHash = Data(SHA256.hash(data: Data("ordered epoch".utf8)))
        let groupSecret = Data(SHA256.hash(data: Data("ordered secret".utf8)))
        let sender = try Identity.generate(displayName: "Sender")
        var senderState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 5,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret,
            localSenderFingerprint: sender.fingerprint
        )
        var receiverState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 5,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret
        )
        let first = try encrypt("first", sender: sender, state: &senderState)
        let second = try encrypt("second", sender: sender, state: &senderState)
        let third = try encrypt("third", sender: sender, state: &senderState)

        XCTAssertEqual(try decrypt(third, sender: sender, state: &receiverState), .text("third"))
        XCTAssertEqual(try decrypt(first, sender: sender, state: &receiverState), .text("first"))
        XCTAssertEqual(try decrypt(second, sender: sender, state: &receiverState), .text("second"))
        XCTAssertThrowsError(try decrypt(third, sender: sender, state: &receiverState)) { error in
            XCTAssertEqual(error as? CryptoError, .counterReplay)
        }
    }

    private func makeFixture() throws -> (
        sender: Identity,
        receiverState: GroupRatchetState,
        envelope: GroupRatchetEnvelope
    ) {
        let groupId = UUID()
        let transcriptHash = Data(SHA256.hash(data: Data("authenticated epoch".utf8)))
        let groupSecret = Data(SHA256.hash(data: Data("authenticated secret".utf8)))
        let sender = try Identity.generate(displayName: "Sender")
        var senderState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 3,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret,
            localSenderFingerprint: sender.fingerprint
        )
        let receiverState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 3,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret
        )
        let envelope = try GroupRatchet.encrypt(
            body: .text("authenticated group envelope"),
            senderSigningKey: sender.signingKey,
            senderFingerprint: sender.fingerprint,
            state: &senderState,
            sentAt: Date(timeIntervalSince1970: 1_800_000_123),
            metadataBucketSeconds: 300
        )
        return (sender, receiverState, envelope)
    }

    private func encrypt(
        _ text: String,
        sender: Identity,
        state: inout GroupRatchetState
    ) throws -> GroupRatchetEnvelope {
        try GroupRatchet.encrypt(
            body: .text(text),
            senderSigningKey: sender.signingKey,
            senderFingerprint: sender.fingerprint,
            state: &state
        )
    }

    private func decrypt(
        _ envelope: GroupRatchetEnvelope,
        sender: Identity,
        state: inout GroupRatchetState
    ) throws -> MessageBody {
        try GroupRatchet.decrypt(
            envelope: envelope,
            senderPublicSigningKey: sender.signingKey.publicKeyData,
            state: &state
        )
    }

    private func resign(
        _ envelope: GroupRatchetEnvelope,
        with key: SigningKeyPair
    ) throws -> GroupRatchetEnvelope {
        let signature = try key.sign(
            GroupRatchet.signableData(
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
        return replacing(envelope, signature: signature)
    }

    private func replacing(
        _ envelope: GroupRatchetEnvelope,
        id: UUID? = nil,
        protocolVersion: String? = nil,
        cipherSuite: String? = nil,
        groupId: UUID? = nil,
        epoch: UInt64? = nil,
        transcriptHash: Data? = nil,
        senderFingerprint: String? = nil,
        sentAt: Date? = nil,
        messageCounter: UInt64? = nil,
        payload: EncryptedPayload? = nil,
        signature: Data? = nil
    ) -> GroupRatchetEnvelope {
        GroupRatchetEnvelope(
            id: id ?? envelope.id,
            protocolVersion: protocolVersion ?? envelope.protocolVersion,
            cipherSuite: cipherSuite ?? envelope.cipherSuite,
            groupId: groupId ?? envelope.groupId,
            epoch: epoch ?? envelope.epoch,
            transcriptHash: transcriptHash ?? envelope.transcriptHash,
            senderFingerprint: senderFingerprint ?? envelope.senderFingerprint,
            sentAt: sentAt ?? envelope.sentAt,
            messageCounter: messageCounter ?? envelope.messageCounter,
            payload: payload ?? envelope.payload,
            signature: signature ?? envelope.signature
        )
    }

    private func mutatingNonce(_ payload: EncryptedPayload) -> EncryptedPayload {
        EncryptedPayload(
            nonce: flippingFirstByte(payload.nonce),
            ciphertext: payload.ciphertext,
            tag: payload.tag
        )
    }

    private func mutatingCiphertext(_ payload: EncryptedPayload) -> EncryptedPayload {
        EncryptedPayload(
            nonce: payload.nonce,
            ciphertext: flippingFirstByte(payload.ciphertext),
            tag: payload.tag
        )
    }

    private func doublingCiphertext(_ payload: EncryptedPayload) -> EncryptedPayload {
        EncryptedPayload(
            nonce: payload.nonce,
            ciphertext: payload.ciphertext + payload.ciphertext,
            tag: payload.tag
        )
    }

    private func mutatingTag(_ payload: EncryptedPayload) -> EncryptedPayload {
        EncryptedPayload(
            nonce: payload.nonce,
            ciphertext: payload.ciphertext,
            tag: flippingFirstByte(payload.tag)
        )
    }

    private func flippingFirstByte(_ data: Data) -> Data {
        var result = data
        result[result.startIndex] ^= 0x01
        return result
    }
}

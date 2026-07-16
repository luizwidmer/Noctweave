import Crypto
import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class InboxRetirementTests: XCTestCase {
    func testRetirementPurgesMailboxConsumersAndBlocksReuseAndDelivery() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let access = try makeRetirementSignerOrSkip()
        let consumer = try makeRetirementSignerOrSkip()
        let inboxId = InboxAddress.derived(from: access.publicKey)
        let direct = linuxRetirementEnvelope(marker: 0x11)
        let group = linuxRetirementEnvelope(marker: 0x12)
        let consumerId = MailboxConsumerId.generate()

        try store.registerInbox(inboxId: inboxId, accessPublicKey: access.publicKey)
        _ = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: consumer.publicKey,
            startingSequence: 0
        )
        _ = try store.deliver(direct, to: inboxId)
        _ = try store.deliverGroupEnvelope(
            group,
            to: inboxId,
            recipientFingerprints: [linuxRetirementFingerprint(0x31)]
        )

        let digest = Data(repeating: 0xA1, count: SHA256.byteCount)
        try store.retireInbox(inboxId: inboxId, requestDigest: digest)

        XCTAssertTrue(store.fetch(inboxId: inboxId, maxCount: nil).isEmpty)
        XCTAssertNil(store.inboxAccessPublicKey(for: inboxId))
        XCTAssertTrue(store.mailboxConsumers(inboxId: inboxId).isEmpty)
        XCTAssertTrue(store.isInboxRetired(inboxId: inboxId))
        XCTAssertThrowsError(try store.deliver(direct, to: inboxId)) {
            XCTAssertEqual($0 as? RelayStoreError, .inboxRetired)
        }
        XCTAssertThrowsError(
            try store.deliverGroupEnvelope(
                group,
                to: inboxId,
                recipientFingerprints: [linuxRetirementFingerprint(0x31)]
            )
        ) { XCTAssertEqual($0 as? RelayStoreError, .inboxRetired) }
        XCTAssertThrowsError(try store.registerInbox(inboxId: inboxId, accessPublicKey: access.publicKey)) {
            XCTAssertEqual($0 as? RelayStoreError, .inboxRetired)
        }
        XCTAssertThrowsError(
            try store.registerMailboxConsumer(
                inboxId: inboxId,
                consumerId: MailboxConsumerId.generate(),
                consumerSigningPublicKey: consumer.publicKey
            )
        ) { XCTAssertEqual($0 as? RelayStoreError, .inboxRetired) }

        try store.retireInbox(inboxId: inboxId, requestDigest: digest)
        XCTAssertThrowsError(
            try store.retireInbox(
                inboxId: inboxId,
                requestDigest: Data(repeating: 0xA2, count: SHA256.byteCount)
            )
        ) { XCTAssertEqual($0 as? RelayStoreError, .invalidInboxRetirement) }
    }

    func testRetirementPersistenceFailureRollsBackThenExactRetryPersists() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("retirement.sqlite")
        let store = RelayStore(fileURL: storeURL, maxInboxMessages: nil, temporalBucketSeconds: 0)
        let access = try makeRetirementSignerOrSkip()
        let consumer = try makeRetirementSignerOrSkip()
        let inboxId = InboxAddress.derived(from: access.publicKey)
        let envelope = linuxRetirementEnvelope(marker: 0x21)
        let consumerId = MailboxConsumerId.generate()
        let digest = Data(repeating: 0xB1, count: SHA256.byteCount)

        try store.registerInbox(inboxId: inboxId, accessPublicKey: access.publicKey)
        _ = try store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: consumer.publicKey,
            startingSequence: 0
        )
        _ = try store.deliver(envelope, to: inboxId)

        store.failNextPersistenceForTesting()
        XCTAssertThrowsError(try store.retireInbox(inboxId: inboxId, requestDigest: digest))
        XCTAssertNotNil(store.inboxAccessPublicKey(for: inboxId))
        XCTAssertEqual(store.fetch(inboxId: inboxId, maxCount: nil).map(\.id), [envelope.id])
        XCTAssertEqual(store.mailboxConsumers(inboxId: inboxId).map(\.consumerId), [consumerId])
        XCTAssertFalse(store.isInboxRetired(inboxId: inboxId))

        try store.retireInbox(inboxId: inboxId, requestDigest: digest)
        let reloaded = RelayStore(fileURL: storeURL, maxInboxMessages: nil, temporalBucketSeconds: 0)
        try reloaded.load()
        XCTAssertTrue(reloaded.isMatchingInboxRetirement(inboxId: inboxId, requestDigest: digest))
        XCTAssertNil(reloaded.inboxAccessPublicKey(for: inboxId))
        XCTAssertTrue(reloaded.fetch(inboxId: inboxId, maxCount: nil).isEmpty)
        XCTAssertTrue(reloaded.mailboxConsumers(inboxId: inboxId).isEmpty)
    }

    func testLifetimeCapacityRejectsNewGenerationsButNeverBlocksAdmittedRetirement() throws {
        let store = RelayStore(
            fileURL: nil,
            maxInboxMessages: nil,
            maxLifetimeInboxGenerations: 2
        )
        let firstKey = Data("lifetime-cap-first".utf8)
        let secondKey = Data("lifetime-cap-second".utf8)
        let thirdKey = Data("lifetime-cap-third".utf8)
        let firstInbox = InboxAddress.derived(from: firstKey)
        let secondInbox = InboxAddress.derived(from: secondKey)
        let thirdInbox = InboxAddress.derived(from: thirdKey)
        try store.registerInbox(inboxId: firstInbox, accessPublicKey: firstKey)
        try store.registerInbox(inboxId: secondInbox, accessPublicKey: secondKey)

        XCTAssertThrowsError(
            try store.registerInbox(inboxId: thirdInbox, accessPublicKey: thirdKey)
        ) { XCTAssertEqual($0 as? RelayStoreError, .relayCapacityExceeded) }
        try store.retireInbox(
            inboxId: firstInbox,
            requestDigest: Data(repeating: 0xD1, count: SHA256.byteCount)
        )
        try store.retireInbox(
            inboxId: secondInbox,
            requestDigest: Data(repeating: 0xD2, count: SHA256.byteCount)
        )
        XCTAssertThrowsError(
            try store.registerInbox(inboxId: thirdInbox, accessPublicKey: thirdKey)
        ) { XCTAssertEqual($0 as? RelayStoreError, .relayCapacityExceeded) }
        XCTAssertThrowsError(
            try store.retireInbox(
                inboxId: thirdInbox,
                requestDigest: Data(repeating: 0xD3, count: SHA256.byteCount)
            )
        ) { XCTAssertEqual($0 as? RelayStoreError, .relayCapacityExceeded) }
    }

    func testRetirementMarkersNeverExpireOrEvictOlderBurns() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil)
        let now = Date()
        for index in 0..<10_000 {
            let key = withUnsafeBytes(of: UInt64(index).bigEndian) { Data($0) }
            let inboxId = InboxAddress.derived(from: key)
            try store.registerInbox(inboxId: inboxId, accessPublicKey: key)
            try store.retireInbox(
                inboxId: inboxId,
                requestDigest: Data(repeating: UInt8(truncatingIfNeeded: index), count: SHA256.byteCount),
                now: now
            )
        }
        XCTAssertEqual(store.inboxRetirementTombstoneCount(now: now), 10_000)

        let overflowKey = Data("retirement-overflow".utf8)
        let overflowInbox = InboxAddress.derived(from: overflowKey)
        try store.registerInbox(inboxId: overflowInbox, accessPublicKey: overflowKey)
        try store.retireInbox(
            inboxId: overflowInbox,
            requestDigest: Data(repeating: 0xCC, count: SHA256.byteCount),
            now: now
        )
        XCTAssertEqual(store.inboxRetirementTombstoneCount(now: now), 10_001)
        XCTAssertNil(store.inboxAccessPublicKey(for: overflowInbox))
        XCTAssertTrue(store.isInboxRetired(inboxId: overflowInbox, now: now))

        let afterRetention = now.addingTimeInterval(30 * 86400 + 1)
        XCTAssertEqual(store.inboxRetirementTombstoneCount(now: afterRetention), 10_001)
        let oldestKey = withUnsafeBytes(of: UInt64(0).bigEndian) { Data($0) }
        let oldestInbox = InboxAddress.derived(from: oldestKey)
        XCTAssertTrue(store.isInboxRetired(inboxId: oldestInbox, now: afterRetention))
        XCTAssertThrowsError(try store.registerInbox(inboxId: oldestInbox, accessPublicKey: oldestKey)) {
            XCTAssertEqual($0 as? RelayStoreError, .inboxRetired)
        }
    }

    func testWireRetirementIsNonExpiringExactReplayAndRejectsChangedOrMalformedRequest() throws {
        let harness = try RelayTCPHarness()
        defer { try? harness.shutdown() }
        let signer = try makeRetirementSignerOrSkip()
        let inboxId = InboxAddress.derived(from: signer.publicKey)
        XCTAssertEqual(
            try harness.send(.registerInbox(try signedRetirementRegistration(inboxId: inboxId, signer: signer))).type,
            .ok
        )

        let persistedRequest = try signedRetirementRequest(
            inboxId: inboxId,
            signer: signer,
            signedAt: Date(timeIntervalSince1970: 1),
            nonce: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
        )
        XCTAssertEqual(try harness.send(.retireInbox(persistedRequest)).type, .ok)
        XCTAssertEqual(try harness.send(.retireInbox(persistedRequest)).type, .ok)

        let changed = try signedRetirementRequest(
            inboxId: inboxId,
            signer: signer,
            signedAt: persistedRequest.accessProof!.signedAt,
            nonce: UUID(uuidString: "22222222-2222-4222-8222-222222222222")!
        )
        XCTAssertEqual(
            try harness.send(.retireInbox(changed)).error,
            "Inbox retirement request does not match tombstone"
        )

        let malformedSigner = try makeRetirementSignerOrSkip()
        let malformedInbox = InboxAddress.derived(from: malformedSigner.publicKey)
        XCTAssertEqual(
            try harness.send(
                .registerInbox(
                    try signedRetirementRegistration(
                        inboxId: malformedInbox,
                        signer: malformedSigner
                    )
                )
            ).type,
            .ok
        )
        let valid = try signedRetirementRequest(inboxId: malformedInbox, signer: malformedSigner)
        let proof = valid.accessProof!
        let malformed = RetireInboxRequest(
            inboxId: malformedInbox,
            accessProof: RelayActorProof(
                fingerprint: proof.fingerprint,
                publicSigningKey: proof.publicSigningKey,
                signedAt: proof.signedAt,
                nonce: proof.nonce,
                signature: Data(repeating: 0x00, count: proof.signature.count)
            )
        )
        XCTAssertEqual(
            try harness.send(.retireInbox(malformed)).error,
            "Invalid inbox retirement proof signature."
        )

        let alreadyAbsentSigner = try makeRetirementSignerOrSkip()
        let alreadyAbsentInbox = InboxAddress.derived(from: alreadyAbsentSigner.publicKey)
        let alreadyAbsent = try signedRetirementRequest(
            inboxId: alreadyAbsentInbox,
            signer: alreadyAbsentSigner,
            signedAt: Date(timeIntervalSince1970: 1)
        )
        XCTAssertEqual(try harness.send(.retireInbox(alreadyAbsent)).type, .ok)
        XCTAssertEqual(
            try harness.send(
                .registerInbox(
                    try signedRetirementRegistration(
                        inboxId: alreadyAbsentInbox,
                        signer: alreadyAbsentSigner
                    )
                )
            ).error,
            "Inbox is retired"
        )
    }

    func testCanonicalRetirementProofPayloadMatchesCore() throws {
        let proof = RelayActorProof(
            fingerprint: "",
            publicSigningKey: Data(),
            signedAt: ISO8601DateFormatter().date(from: "2026-07-16T12:34:56Z")!,
            nonce: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
            signature: Data()
        )
        let request = RetireInboxRequest(inboxId: "inbox")
        XCTAssertEqual(
            String(decoding: try request.signableData(for: proof), as: UTF8.self),
            #"{"domain":"org.noctweave.relay.retire-inbox","inboxId":"inbox","nonce":"11111111-1111-4111-8111-111111111111","signedAt":"2026-07-16T12:34:56Z","version":1}"#
        )
    }

    private func makeRetirementSignerOrSkip() throws -> InboxRetirementSigner {
        guard let pair = OQSSignatureVerifier.shared.generateKeyPair() else {
            throw XCTSkip("ML-DSA runtime is unavailable")
        }
        return InboxRetirementSigner(privateKey: pair.privateKey, publicKey: pair.publicKey)
    }
}

private struct InboxRetirementSigner {
    let privateKey: Data
    let publicKey: Data

    func proof(
        signedAt: Date = Date(),
        nonce: UUID = UUID(),
        signableData: (RelayActorProof) throws -> Data
    ) throws -> RelayActorProof {
        let draft = RelayActorProof(
            fingerprint: Data(SHA256.hash(data: publicKey)).base64EncodedString(),
            publicSigningKey: publicKey,
            signedAt: signedAt,
            nonce: nonce,
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
            signedAt: signedAt,
            nonce: nonce,
            signature: signature
        )
    }
}

private func signedRetirementRegistration(
    inboxId: String,
    signer: InboxRetirementSigner
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

private func signedRetirementRequest(
    inboxId: String,
    signer: InboxRetirementSigner,
    signedAt: Date = Date(),
    nonce: UUID = UUID()
) throws -> RetireInboxRequest {
    let unsigned = RetireInboxRequest(inboxId: inboxId)
    return RetireInboxRequest(
        inboxId: inboxId,
        accessProof: try signer.proof(signedAt: signedAt, nonce: nonce) {
            try unsigned.signableData(for: $0)
        }
    )
}

private func linuxRetirementEnvelope(marker: UInt8) -> Envelope {
    Envelope(
        conversationId: "inbox-retirement",
        sessionId: "retirement-session",
        senderFingerprint: linuxRetirementFingerprint(marker),
        sentAt: Date(),
        messageCounter: UInt64(marker),
        kemCiphertext: nil,
        payload: EncryptedPayload(
            nonce: Data(repeating: marker, count: 12),
            ciphertext: Data(repeating: marker, count: 512),
            tag: Data(repeating: marker, count: 16)
        ),
        signature: Data(
            repeating: marker,
            count: OQSSignatureVerifier.mlDSA65SignatureBytes
        )
    )
}

private func linuxRetirementFingerprint(_ marker: UInt8) -> String {
    Data(repeating: marker, count: 32).base64EncodedString()
}

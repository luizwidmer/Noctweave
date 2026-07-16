import Crypto
import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class RelayMailboxV2WireTests: XCTestCase {
    func testMailboxConsumerWireLifecycleRequiresAccessProofAndRedactsCursorFailures() throws {
        let signer = try makeSignerOrSkip()
        let consumerSigner = try makeSignerOrSkip()
        let otherConsumerSigner = try makeSignerOrSkip()
        let linkedSigner = try makeSignerOrSkip()
        let harness = try RelayTCPHarness()
        defer { try? harness.shutdown() }
        let inboxId = InboxAddress.derived(from: signer.publicKey)
        try harness.registerInboxDirect(inboxId: inboxId, accessPublicKey: signer.publicKey)
        let consumerId = MailboxConsumerId.generate(
            nonce: UUID(uuidString: "01234567-89AB-CDEF-8123-456789ABCDEF")!
        )

        let missingProof = try harness.send(
            .registerMailboxConsumer(
                RegisterMailboxConsumerRequest(
                    inboxId: inboxId,
                    consumerId: consumerId,
                    consumerSigningPublicKey: consumerSigner.publicKey
                )
            )
        )
        XCTAssertEqual(missingProof.type, .error)
        XCTAssertEqual(missingProof.error, "Missing actor proof.")

        let envelope = makeEnvelope()
        XCTAssertEqual(
            try harness.send(
                .deliver(
                    DeliverRequest(
                        inboxId: inboxId,
                        routingToken: inboxId,
                        envelope: envelope,
                        destinationRelay: nil
                    )
                )
            ).type,
            .delivered
        )

        let registrationDraft = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: consumerSigner.publicKey,
            startingSequence: 0
        )
        let registration = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: consumerSigner.publicKey,
            startingSequence: 0,
            authorityProof: try signer.proof { try registrationDraft.authoritySignableData(for: $0) },
            consumerProof: try consumerSigner.proof { try registrationDraft.consumerSignableData(for: $0) }
        )
        let registered = try harness.send(.registerMailboxConsumer(registration))
        XCTAssertEqual(registered.type, .mailboxConsumer)
        XCTAssertEqual(registered.mailboxConsumer?.consumerId, consumerId)
        XCTAssertEqual(registered.mailboxConsumer?.committedSequence, 0)
        XCTAssertEqual(registered.mailboxConsumer?.state, .active)

        let linkedConsumerId = MailboxConsumerId.generate()
        let unsponsoredDraft = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: linkedConsumerId,
            consumerSigningPublicKey: linkedSigner.publicKey,
            startingSequence: 0
        )
        let unsponsored = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: linkedConsumerId,
            consumerSigningPublicKey: linkedSigner.publicKey,
            startingSequence: 0,
            authorityProof: try signer.proof { try unsponsoredDraft.authoritySignableData(for: $0) },
            consumerProof: try linkedSigner.proof { try unsponsoredDraft.consumerSignableData(for: $0) }
        )
        XCTAssertEqual(try harness.send(.registerMailboxConsumer(unsponsored)).type, .error)

        let linkedDraft = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: linkedConsumerId,
            consumerSigningPublicKey: linkedSigner.publicKey,
            sponsorConsumerId: consumerId,
            startingSequence: 0
        )
        let wrongSponsor = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: linkedConsumerId,
            consumerSigningPublicKey: linkedSigner.publicKey,
            sponsorConsumerId: consumerId,
            startingSequence: 0,
            authorityProof: try signer.proof { try linkedDraft.authoritySignableData(for: $0) },
            consumerProof: try linkedSigner.proof { try linkedDraft.consumerSignableData(for: $0) },
            sponsorProof: try linkedSigner.proof { try linkedDraft.sponsorSignableData(for: $0) }
        )
        XCTAssertEqual(try harness.send(.registerMailboxConsumer(wrongSponsor)).type, .error)

        let tamperedSponsor = MailboxConsumerId.generate()
        let tampered = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: linkedConsumerId,
            consumerSigningPublicKey: linkedSigner.publicKey,
            sponsorConsumerId: tamperedSponsor,
            startingSequence: 0,
            authorityProof: try signer.proof { try linkedDraft.authoritySignableData(for: $0) },
            consumerProof: try linkedSigner.proof { try linkedDraft.consumerSignableData(for: $0) },
            sponsorProof: try consumerSigner.proof { try linkedDraft.sponsorSignableData(for: $0) }
        )
        XCTAssertEqual(try harness.send(.registerMailboxConsumer(tampered)).type, .error)

        let linkedRegistration = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: linkedConsumerId,
            consumerSigningPublicKey: linkedSigner.publicKey,
            sponsorConsumerId: consumerId,
            startingSequence: 0,
            authorityProof: try signer.proof { try linkedDraft.authoritySignableData(for: $0) },
            consumerProof: try linkedSigner.proof { try linkedDraft.consumerSignableData(for: $0) },
            sponsorProof: try consumerSigner.proof { try linkedDraft.sponsorSignableData(for: $0) }
        )
        XCTAssertEqual(
            try harness.send(.registerMailboxConsumer(linkedRegistration)).mailboxConsumer?.consumerId,
            linkedConsumerId
        )

        let replayConsumerId = MailboxConsumerId.generate()
        let replaySigner = try makeSignerOrSkip()
        let replayDraft = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: replayConsumerId,
            consumerSigningPublicKey: replaySigner.publicKey,
            sponsorConsumerId: consumerId,
            startingSequence: UInt64.max
        )
        let replayedSponsorProof = try consumerSigner.proof {
            try replayDraft.sponsorSignableData(for: $0)
        }
        func replayRequest() throws -> RegisterMailboxConsumerRequest {
            RegisterMailboxConsumerRequest(
                inboxId: inboxId,
                consumerId: replayConsumerId,
                consumerSigningPublicKey: replaySigner.publicKey,
                sponsorConsumerId: consumerId,
                startingSequence: UInt64.max,
                authorityProof: try signer.proof { try replayDraft.authoritySignableData(for: $0) },
                consumerProof: try replaySigner.proof { try replayDraft.consumerSignableData(for: $0) },
                sponsorProof: replayedSponsorProof
            )
        }
        XCTAssertEqual(
            try harness.send(.registerMailboxConsumer(replayRequest())).error,
            "Invalid mailbox cursor"
        )
        XCTAssertEqual(
            try harness.send(.registerMailboxConsumer(replayRequest())).error,
            "Actor proof replay detected."
        )

        let legacyFetchDraft = FetchRequest(inboxId: inboxId, maxCount: 10)
        let legacyFetch = FetchRequest(
            inboxId: inboxId,
            maxCount: 10,
            accessProof: try signer.proof { try legacyFetchDraft.signableData(for: $0) }
        )
        let legacyFetchResponse = try harness.send(.fetch(legacyFetch))
        XCTAssertEqual(legacyFetchResponse.type, .error)
        XCTAssertEqual(
            legacyFetchResponse.error,
            "Legacy mailbox fetch is disabled for endpoint-managed inboxes"
        )

        let legacyAckDraft = AcknowledgeMessagesRequest(
            inboxId: inboxId,
            messageIds: [envelope.id]
        )
        let legacyAck = AcknowledgeMessagesRequest(
            inboxId: inboxId,
            messageIds: [envelope.id],
            accessProof: try signer.proof { try legacyAckDraft.signableData(for: $0) }
        )
        let legacyAckResponse = try harness.send(.acknowledgeMessages(legacyAck))
        XCTAssertEqual(legacyAckResponse.type, .error)
        XCTAssertEqual(
            legacyAckResponse.error,
            "Legacy mailbox acknowledgement is disabled for endpoint-managed inboxes"
        )

        let syncDraft = SyncMailboxRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            maxCount: 10
        )
        let sync = SyncMailboxRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            maxCount: 10,
            consumerProof: try consumerSigner.proof { try syncDraft.signableData(for: $0) }
        )
        let synchronized = try harness.send(.syncMailbox(sync))
        XCTAssertEqual(synchronized.type, .mailboxSync)
        XCTAssertEqual(synchronized.mailboxSync?.events.map(\.id), [envelope.id])
        XCTAssertEqual(synchronized.mailboxSync?.nextSequence, 1)
        guard let cursor = synchronized.mailboxSync?.nextCursor else {
            return XCTFail("Mailbox sync did not return a cursor")
        }

        let wrongKeySyncDraft = SyncMailboxRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            maxCount: 10
        )
        let wrongKeySync = SyncMailboxRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            maxCount: 10,
            consumerProof: try otherConsumerSigner.proof {
                try wrongKeySyncDraft.signableData(for: $0)
            }
        )
        XCTAssertEqual(try harness.send(.syncMailbox(wrongKeySync)).type, .error)

        let mismatchedCommitDraft = CommitMailboxCursorRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            cursor: cursor,
            sequence: 2
        )
        let mismatchedCommit = CommitMailboxCursorRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            cursor: cursor,
            sequence: 2,
            consumerProof: try consumerSigner.proof { try mismatchedCommitDraft.signableData(for: $0) }
        )
        let rejected = try harness.send(.commitMailboxCursor(mismatchedCommit))
        XCTAssertEqual(rejected.type, .error)
        XCTAssertEqual(rejected.error, "Invalid mailbox cursor")

        let wrongKeyCommitDraft = CommitMailboxCursorRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            cursor: cursor,
            sequence: 1
        )
        let wrongKeyCommit = CommitMailboxCursorRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            cursor: cursor,
            sequence: 1,
            consumerProof: try otherConsumerSigner.proof {
                try wrongKeyCommitDraft.signableData(for: $0)
            }
        )
        XCTAssertEqual(try harness.send(.commitMailboxCursor(wrongKeyCommit)).type, .error)

        let commitDraft = CommitMailboxCursorRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            cursor: cursor,
            sequence: 1
        )
        let commit = CommitMailboxCursorRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            cursor: cursor,
            sequence: 1,
            consumerProof: try consumerSigner.proof { try commitDraft.signableData(for: $0) }
        )
        let committed = try harness.send(.commitMailboxCursor(commit))
        XCTAssertEqual(committed.type, .mailboxConsumer)
        XCTAssertEqual(committed.mailboxConsumer?.committedSequence, 1)

        let revocationDraft = RevokeMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: consumerId
        )
        let revocation = RevokeMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            authorityProof: try signer.proof { try revocationDraft.signableData(for: $0) }
        )
        let revoked = try harness.send(.revokeMailboxConsumer(revocation))
        XCTAssertEqual(revoked.type, .mailboxConsumer)
        XCTAssertEqual(revoked.mailboxConsumer?.state, .revoked)

        let revokedSyncDraft = SyncMailboxRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            maxCount: 10
        )
        let revokedSync = SyncMailboxRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            maxCount: 10,
            consumerProof: try consumerSigner.proof { try revokedSyncDraft.signableData(for: $0) }
        )
        let revokedResponse = try harness.send(.syncMailbox(revokedSync))
        XCTAssertEqual(revokedResponse.type, .error)
        XCTAssertEqual(revokedResponse.error, "Mailbox consumer revoked")

        let rejectedId = MailboxConsumerId.generate()
        let rejectedSigner = try makeSignerOrSkip()
        let revokedSponsorDraft = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: rejectedId,
            consumerSigningPublicKey: rejectedSigner.publicKey,
            sponsorConsumerId: consumerId
        )
        let revokedSponsor = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: rejectedId,
            consumerSigningPublicKey: rejectedSigner.publicKey,
            sponsorConsumerId: consumerId,
            authorityProof: try signer.proof { try revokedSponsorDraft.authoritySignableData(for: $0) },
            consumerProof: try rejectedSigner.proof { try revokedSponsorDraft.consumerSignableData(for: $0) },
            sponsorProof: try consumerSigner.proof { try revokedSponsorDraft.sponsorSignableData(for: $0) }
        )
        XCTAssertEqual(try harness.send(.registerMailboxConsumer(revokedSponsor)).type, .error)

        let linkedRevocationDraft = RevokeMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: linkedConsumerId
        )
        let linkedRevocation = RevokeMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: linkedConsumerId,
            authorityProof: try signer.proof { try linkedRevocationDraft.signableData(for: $0) }
        )
        XCTAssertEqual(
            try harness.send(.revokeMailboxConsumer(linkedRevocation)).mailboxConsumer?.state,
            .revoked
        )
        let lastDeviceDraft = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: rejectedId,
            consumerSigningPublicKey: rejectedSigner.publicKey
        )
        let lastDevice = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: rejectedId,
            consumerSigningPublicKey: rejectedSigner.publicKey,
            authorityProof: try signer.proof { try lastDeviceDraft.authoritySignableData(for: $0) },
            consumerProof: try rejectedSigner.proof { try lastDeviceDraft.consumerSignableData(for: $0) }
        )
        XCTAssertEqual(try harness.send(.registerMailboxConsumer(lastDevice)).type, .error)
    }

    func testMailboxSyncLongPollReturnsNewlyDeliveredEnvelope() throws {
        let signer = try makeSignerOrSkip()
        let consumerSigner = try makeSignerOrSkip()
        let harness = try RelayTCPHarness(
            wakeSupport: DecentralizedWakeSupport(
                mode: .longPoll,
                minPollIntervalSeconds: 2,
                maxPollIntervalSeconds: 2,
                jitterPermille: 0,
                longPollTimeoutSeconds: 2
            )
        )
        defer { try? harness.shutdown() }
        let inboxId = InboxAddress.derived(from: signer.publicKey)
        try harness.registerInboxDirect(inboxId: inboxId, accessPublicKey: signer.publicKey)
        let consumerId = MailboxConsumerId.generate()
        let registrationDraft = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: consumerSigner.publicKey
        )
        let registration = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: consumerSigner.publicKey,
            authorityProof: try signer.proof { try registrationDraft.authoritySignableData(for: $0) },
            consumerProof: try consumerSigner.proof { try registrationDraft.consumerSignableData(for: $0) }
        )
        XCTAssertEqual(
            try harness.send(.registerMailboxConsumer(registration)).type,
            .mailboxConsumer
        )

        let syncDraft = SyncMailboxRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            maxCount: 10,
            longPollTimeoutSeconds: 2
        )
        let sync = SyncMailboxRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            maxCount: 10,
            longPollTimeoutSeconds: 2,
            consumerProof: try consumerSigner.proof { try syncDraft.signableData(for: $0) }
        )
        let envelope = makeEnvelope()
        let completed = expectation(description: "mailbox-v2 long poll returned")
        var response: RelayResponse?
        var responseError: Error?
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                response = try harness.send(.syncMailbox(sync))
            } catch {
                responseError = error
            }
            completed.fulfill()
        }

        Thread.sleep(forTimeInterval: 0.25)
        _ = try harness.send(
            .deliver(
                DeliverRequest(
                    inboxId: inboxId,
                    routingToken: inboxId,
                    envelope: envelope,
                    destinationRelay: nil
                )
            )
        )
        wait(for: [completed], timeout: 4)
        XCTAssertNil(responseError)
        XCTAssertEqual(response?.type, .mailboxSync)
        XCTAssertEqual(response?.mailboxSync?.events.map(\.id), [envelope.id])
    }

    func testMailboxWireUsesCoreFieldNames() throws {
        let request = RelayRequest.registerMailboxConsumer(
            RegisterMailboxConsumerRequest(
                inboxId: "inbox",
                consumerId: MailboxConsumerId.generate(
                    nonce: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!
                ),
                consumerSigningPublicKey: Data([0x01]),
                startingSequence: 7
            )
        )
        let data = try RelayCodec.encoder().encode(request)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(object["type"] as? String, "registerMailboxConsumer")
        let payload = try XCTUnwrap(object["registerMailboxConsumer"] as? [String: Any])
        XCTAssertEqual(payload["inboxId"] as? String, "inbox")
        XCTAssertEqual(payload["startingSequence"] as? Int, 7)
        XCTAssertNotNil(payload["consumerId"])
        XCTAssertNotNil(payload["consumerSigningPublicKey"])
    }

    private func makeSignerOrSkip() throws -> MailboxWireSigner {
        guard let pair = OQSSignatureVerifier.shared.generateKeyPair() else {
            throw XCTSkip("ML-DSA runtime is unavailable")
        }
        return MailboxWireSigner(privateKey: pair.privateKey, publicKey: pair.publicKey)
    }

    private func makeEnvelope() -> Envelope {
        Envelope(
            conversationId: "mailbox-v2-wire",
            sessionId: UUID().uuidString,
            senderFingerprint: Data(repeating: 0x44, count: 32).base64EncodedString(),
            sentAt: Date(),
            messageCounter: 1,
            kemCiphertext: nil,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: 12),
                ciphertext: Data(repeating: 0x22, count: 512),
                tag: Data(repeating: 0x44, count: 16)
            ),
            signature: Data(
                repeating: 0x55,
                count: OQSSignatureVerifier.mlDSA65SignatureBytes
            )
        )
    }
}

private struct MailboxWireSigner {
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
        let data = try signableData(draft)
        guard let signature = OQSSignatureVerifier.shared.sign(
            data: data,
            privateKey: privateKey,
            publicKey: publicKey
        ) else {
            throw NSError(
                domain: "RelayMailboxV2WireTests",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "ML-DSA signing failed"]
            )
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

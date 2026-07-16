import CryptoKit
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2RelayWireTests: XCTestCase {
    func testMailboxConsumerAuthorityProofCanonicalBytesMatchJavaScriptVector() throws {
        let consumerId = MailboxConsumerId(
            rawValue: Data(repeating: 0x33, count: 32).base64EncodedString()
        )
        let request = RegisterMailboxConsumerRequest(
            inboxId: "noctweave1qvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpskx0f2v",
            consumerId: consumerId,
            consumerSigningPublicKey: Data(repeating: 0x22, count: 1_952),
            startingSequence: 7
        )
        let signedAt = try XCTUnwrap(
            ISO8601DateFormatter().date(from: "2026-07-16T12:34:56Z")
        )
        let proof = RelayActorProof(
            fingerprint: "",
            publicSigningKey: Data(),
            signedAt: signedAt,
            nonce: try XCTUnwrap(UUID(uuidString: "11111111-1111-4111-8111-111111111111")),
            signature: Data()
        )

        let digest = SHA256.hash(data: try request.authoritySignableData(for: proof))
        XCTAssertEqual(
            digest.map { String(format: "%02x", $0) }.joined(),
            "5298f3e02de00b173dab621c147252f3988d32d9ecbfe8b1592fda649cd90f2f"
        )
    }

    func testMailboxRawValueTypesUseCanonicalStringWireShape() throws {
        let consumerId = MailboxConsumerId(
            rawValue: Data(repeating: 0x33, count: 32).base64EncodedString()
        )
        let cursor = MailboxCursor(rawValue: "opaque:7")
        let request = CommitMailboxCursorRequest(
            inboxId: "noctweave1qvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpskx0f2v",
            consumerId: consumerId,
            cursor: cursor,
            sequence: 7
        )
        let encoded = try NoctweaveCoder.encode(request, sortedKeys: true)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertEqual(object["consumerId"] as? String, consumerId.rawValue)
        XCTAssertEqual(object["cursor"] as? String, cursor.rawValue)
        XCTAssertNoThrow(try NoctweaveCoder.decode(CommitMailboxCursorRequest.self, from: encoded))
    }

    func testRelayWireKeepsMailboxEventsUntilEveryConsumerCommits() async throws {
        let port = UInt16.random(in: 58_100...60_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(
            store: RelayStore(),
            configuration: RelayConfiguration(
                compatibilityProfiles: [RelayCompatibilityProfile.legacyFingerprint]
            )
        )
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 200_000_000)

        let client = RelayClient(endpoint: endpoint)
        let accessKey = try SigningKeyPair.generate()
        let inboxId = InboxAddress.derived(from: accessKey.publicKeyData)
        let identity = try Identity.generate(displayName: "Mailbox owner")
        let offer = try MessageEngine.makeContactOffer(
            identity: identity,
            inboxId: inboxId,
            relay: endpoint,
            inboxAccessPublicKey: accessKey.publicKeyData
        )
        var inboxRegistration = RegisterInboxRequest(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            contactOffer: offer
        )
        inboxRegistration = RegisterInboxRequest(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            contactOffer: offer,
            accessProof: try makeProof(key: accessKey) { try inboxRegistration.signableData(for: $0) }
        )
        let inboxResponse = try await client.send(.registerInbox(inboxRegistration))
        XCTAssertEqual(inboxResponse.type, .ok)

        let phone = MailboxConsumerId.generate()
        let desktop = MailboxConsumerId.generate()
        let phoneKey = try SigningKeyPair.generate()
        let desktopKey = try SigningKeyPair.generate()
        let phoneDraft = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: phone,
            consumerSigningPublicKey: phoneKey.publicKeyData,
            startingSequence: 0
        )
        let phoneRegistration = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: phone,
            consumerSigningPublicKey: phoneKey.publicKeyData,
            startingSequence: 0,
            authorityProof: try makeProof(key: accessKey) { try phoneDraft.authoritySignableData(for: $0) },
            consumerProof: try makeProof(key: phoneKey) { try phoneDraft.consumerSignableData(for: $0) }
        )
        let phoneResponse = try await client.send(.registerMailboxConsumer(phoneRegistration))
        XCTAssertEqual(phoneResponse.mailboxConsumer?.consumerId, phone)

        let unsponsoredDesktopDraft = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: desktop,
            consumerSigningPublicKey: desktopKey.publicKeyData,
            startingSequence: 0
        )
        let unsponsoredDesktop = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: desktop,
            consumerSigningPublicKey: desktopKey.publicKeyData,
            startingSequence: 0,
            authorityProof: try makeProof(key: accessKey) {
                try unsponsoredDesktopDraft.authoritySignableData(for: $0)
            },
            consumerProof: try makeProof(key: desktopKey) {
                try unsponsoredDesktopDraft.consumerSignableData(for: $0)
            }
        )
        let unsponsoredResponse = try await client.send(.registerMailboxConsumer(unsponsoredDesktop))
        XCTAssertEqual(unsponsoredResponse.type, .error)

        let desktopDraft = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: desktop,
            consumerSigningPublicKey: desktopKey.publicKeyData,
            sponsorConsumerId: phone,
            startingSequence: 0
        )
        let desktopAuthorityProof = try makeProof(key: accessKey) {
            try desktopDraft.authoritySignableData(for: $0)
        }
        let desktopConsumerProof = try makeProof(key: desktopKey) {
            try desktopDraft.consumerSignableData(for: $0)
        }
        let wrongSponsorRegistration = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: desktop,
            consumerSigningPublicKey: desktopKey.publicKeyData,
            sponsorConsumerId: phone,
            startingSequence: 0,
            authorityProof: desktopAuthorityProof,
            consumerProof: desktopConsumerProof,
            sponsorProof: try makeProof(key: desktopKey) {
                try desktopDraft.sponsorSignableData(for: $0)
            }
        )
        let wrongSponsorResponse = try await client.send(
            .registerMailboxConsumer(wrongSponsorRegistration)
        )
        XCTAssertEqual(wrongSponsorResponse.type, .error)

        let desktopRegistration = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: desktop,
            consumerSigningPublicKey: desktopKey.publicKeyData,
            sponsorConsumerId: phone,
            startingSequence: 0,
            authorityProof: try makeProof(key: accessKey) {
                try desktopDraft.authoritySignableData(for: $0)
            },
            consumerProof: try makeProof(key: desktopKey) {
                try desktopDraft.consumerSignableData(for: $0)
            },
            sponsorProof: try makeProof(key: phoneKey) {
                try desktopDraft.sponsorSignableData(for: $0)
            }
        )
        let desktopResponse = try await client.send(.registerMailboxConsumer(desktopRegistration))
        XCTAssertEqual(desktopResponse.mailboxConsumer?.consumerId, desktop)

        let envelope = makeEnvelope()
        let deliveryResponse = try await client.send(
            .deliver(DeliverRequest(inboxId: inboxId, envelope: envelope))
        )
        XCTAssertEqual(deliveryResponse.type, .delivered)
        let phoneBatch = try await sync(client: client, key: phoneKey, inboxId: inboxId, consumer: phone)
        XCTAssertEqual(phoneBatch.events.map(\.id), [envelope.id])

        var wrongKeySync = SyncMailboxRequest(inboxId: inboxId, consumerId: phone, maxCount: 10)
        wrongKeySync = SyncMailboxRequest(
            inboxId: inboxId,
            consumerId: phone,
            maxCount: 10,
            consumerProof: try makeProof(key: desktopKey) { try wrongKeySync.signableData(for: $0) }
        )
        let wrongKeySyncResponse = try await client.send(.syncMailbox(wrongKeySync))
        XCTAssertEqual(wrongKeySyncResponse.type, .error)

        var wrongKeyCommit = CommitMailboxCursorRequest(
            inboxId: inboxId,
            consumerId: phone,
            cursor: phoneBatch.nextCursor,
            sequence: phoneBatch.nextSequence
        )
        wrongKeyCommit = CommitMailboxCursorRequest(
            inboxId: inboxId,
            consumerId: phone,
            cursor: phoneBatch.nextCursor,
            sequence: phoneBatch.nextSequence,
            consumerProof: try makeProof(key: desktopKey) { try wrongKeyCommit.signableData(for: $0) }
        )
        let wrongKeyCommitResponse = try await client.send(.commitMailboxCursor(wrongKeyCommit))
        XCTAssertEqual(wrongKeyCommitResponse.type, .error)

        _ = try await commit(
            client: client,
            key: phoneKey,
            inboxId: inboxId,
            consumer: phone,
            batch: phoneBatch
        )
        let desktopBatch = try await sync(client: client, key: desktopKey, inboxId: inboxId, consumer: desktop)
        XCTAssertEqual(desktopBatch.events.map(\.id), [envelope.id])
        _ = try await commit(
            client: client,
            key: desktopKey,
            inboxId: inboxId,
            consumer: desktop,
            batch: desktopBatch
        )
        let empty = try await sync(client: client, key: phoneKey, inboxId: inboxId, consumer: phone)
        XCTAssertTrue(empty.events.isEmpty)
        XCTAssertEqual(empty.retentionFloor, 1)

        var legacyFetch = FetchRequest(inboxId: inboxId, maxCount: 10)
        legacyFetch = FetchRequest(
            inboxId: inboxId,
            maxCount: 10,
            accessProof: try makeProof(key: accessKey) { try legacyFetch.signableData(for: $0) }
        )
        let legacyFetchResponse = try await client.send(.fetch(legacyFetch))
        XCTAssertEqual(legacyFetchResponse.type, .error)

        var legacyAck = AcknowledgeMessagesRequest(
            inboxId: inboxId,
            messageIds: [envelope.id]
        )
        legacyAck = AcknowledgeMessagesRequest(
            inboxId: inboxId,
            messageIds: [envelope.id],
            accessProof: try makeProof(key: accessKey) { try legacyAck.signableData(for: $0) }
        )
        let legacyAckResponse = try await client.send(.acknowledgeMessages(legacyAck))
        XCTAssertEqual(legacyAckResponse.type, .error)

        var revocation = RevokeMailboxConsumerRequest(inboxId: inboxId, consumerId: phone)
        revocation = RevokeMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: phone,
            authorityProof: try makeProof(key: accessKey) { try revocation.signableData(for: $0) }
        )
        let revocationResponse = try await client.send(.revokeMailboxConsumer(revocation))
        XCTAssertEqual(revocationResponse.mailboxConsumer?.state, .revoked)
        var revokedSync = SyncMailboxRequest(inboxId: inboxId, consumerId: phone, maxCount: 10)
        revokedSync = SyncMailboxRequest(
            inboxId: inboxId,
            consumerId: phone,
            maxCount: 10,
            consumerProof: try makeProof(key: phoneKey) { try revokedSync.signableData(for: $0) }
        )
        let revokedSyncResponse = try await client.send(.syncMailbox(revokedSync))
        XCTAssertEqual(revokedSyncResponse.type, .error)

        let rejectedConsumer = MailboxConsumerId.generate()
        let rejectedKey = try SigningKeyPair.generate()
        let revokedSponsorDraft = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: rejectedConsumer,
            consumerSigningPublicKey: rejectedKey.publicKeyData,
            sponsorConsumerId: phone
        )
        let revokedSponsorRequest = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: rejectedConsumer,
            consumerSigningPublicKey: rejectedKey.publicKeyData,
            sponsorConsumerId: phone,
            authorityProof: try makeProof(key: accessKey) {
                try revokedSponsorDraft.authoritySignableData(for: $0)
            },
            consumerProof: try makeProof(key: rejectedKey) {
                try revokedSponsorDraft.consumerSignableData(for: $0)
            },
            sponsorProof: try makeProof(key: phoneKey) {
                try revokedSponsorDraft.sponsorSignableData(for: $0)
            }
        )
        let revokedSponsorResponse = try await client.send(
            .registerMailboxConsumer(revokedSponsorRequest)
        )
        XCTAssertEqual(revokedSponsorResponse.type, .error)

        var desktopRevocation = RevokeMailboxConsumerRequest(inboxId: inboxId, consumerId: desktop)
        desktopRevocation = RevokeMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: desktop,
            authorityProof: try makeProof(key: accessKey) {
                try desktopRevocation.signableData(for: $0)
            }
        )
        _ = try await client.send(.revokeMailboxConsumer(desktopRevocation))
        let lastDeviceDraft = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: rejectedConsumer,
            consumerSigningPublicKey: rejectedKey.publicKeyData
        )
        let lastDeviceRequest = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: rejectedConsumer,
            consumerSigningPublicKey: rejectedKey.publicKeyData,
            authorityProof: try makeProof(key: accessKey) {
                try lastDeviceDraft.authoritySignableData(for: $0)
            },
            consumerProof: try makeProof(key: rejectedKey) {
                try lastDeviceDraft.consumerSignableData(for: $0)
            }
        )
        let lastDeviceResponse = try await client.send(
            .registerMailboxConsumer(lastDeviceRequest)
        )
        XCTAssertEqual(lastDeviceResponse.type, .error)
    }

    private func sync(
        client: RelayClient,
        key: SigningKeyPair,
        inboxId: String,
        consumer: MailboxConsumerId
    ) async throws -> MailboxSyncBatch {
        var request = SyncMailboxRequest(inboxId: inboxId, consumerId: consumer, maxCount: 10)
        request = SyncMailboxRequest(
            inboxId: inboxId,
            consumerId: consumer,
            maxCount: 10,
            consumerProof: try makeProof(key: key) { try request.signableData(for: $0) }
        )
        let response = try await client.send(.syncMailbox(request))
        XCTAssertEqual(response.type, .mailboxSync)
        return try XCTUnwrap(response.mailboxSync)
    }

    private func commit(
        client: RelayClient,
        key: SigningKeyPair,
        inboxId: String,
        consumer: MailboxConsumerId,
        batch: MailboxSyncBatch
    ) async throws -> MailboxConsumerRegistration {
        var request = CommitMailboxCursorRequest(
            inboxId: inboxId,
            consumerId: consumer,
            cursor: batch.nextCursor,
            sequence: batch.nextSequence
        )
        request = CommitMailboxCursorRequest(
            inboxId: inboxId,
            consumerId: consumer,
            cursor: batch.nextCursor,
            sequence: batch.nextSequence,
            consumerProof: try makeProof(key: key) { try request.signableData(for: $0) }
        )
        let response = try await client.send(.commitMailboxCursor(request))
        return try XCTUnwrap(response.mailboxConsumer)
    }

    private func makeProof(
        key: SigningKeyPair,
        signable: (RelayActorProof) throws -> Data
    ) throws -> RelayActorProof {
        let signedAt = Date()
        let nonce = UUID()
        let placeholder = RelayActorProof(
            fingerprint: CryptoBox.fingerprint(for: key.publicKeyData),
            publicSigningKey: key.publicKeyData,
            signedAt: signedAt,
            nonce: nonce,
            signature: Data()
        )
        return try RelayActorProof.make(
            signingKey: key,
            signableData: signable(placeholder),
            signedAt: signedAt,
            nonce: nonce
        )
    }

    private func makeEnvelope() -> Envelope {
        Envelope(
            conversationId: "wire-mailbox-v2",
            senderFingerprint: Data(repeating: 0x31, count: 32).base64EncodedString(),
            sentAt: Date(timeIntervalSince1970: 2_000),
            messageCounter: 1,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x32, count: 12),
                ciphertext: Data(repeating: 0x33, count: PaddedMessagePlaintext.minimumPaddedBytes),
                tag: Data(repeating: 0x34, count: 16)
            ),
            signature: Data(repeating: 0x35, count: 3_309)
        )
    }
}

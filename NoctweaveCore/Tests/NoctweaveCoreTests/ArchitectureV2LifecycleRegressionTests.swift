import CryptoKit
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2LifecycleRegressionTests: XCTestCase {
    func testExpiredEndpointPrekeyRejectsOnlyNewBootstrap() throws {
        let alice = try lifecycleEndpointFixture("Alice")
        let bob = try lifecycleEndpointFixture("Bob")
        let aliceContact = try MessageEngine.contact(from: try lifecycleOffer(bob))
        let bobContact = try MessageEngine.contact(from: try lifecycleOffer(alice))
        let aliceBob = try lifecycleBinding(local: alice, peer: bob)
        let bobAlice = try lifecycleBinding(local: bob, peer: alice)
        let bootstrapAt = max(alice.endpoint.issuedAt, bob.endpoint.issuedAt)

        let outbound = try MessageEngine.createOutboundInstallationSession(
            localInstallation: alice.installation,
            localEndpoint: alice.endpoint,
            pairwiseBinding: aliceBob,
            contact: aliceContact,
            now: bootstrapAt
        )
        var inboundConversation = try MessageEngine.createInboundInstallationSession(
            localInstallation: bob.installation,
            localEndpoint: bob.endpoint,
            senderEndpoint: alice.endpoint,
            pairwiseBinding: bobAlice,
            contact: bobContact,
            kemCiphertext: outbound.kemCiphertext,
            prekey: outbound.prekey,
            now: bootstrapAt
        )

        let afterExpiry = bootstrapAt.addingTimeInterval(PrekeyBundle.maximumAge + 1)
        XCTAssertNoThrow(try aliceContact.certifiedInstallationEndpoint())
        XCTAssertThrowsError(try MessageEngine.createOutboundInstallationSession(
            localInstallation: alice.installation,
            localEndpoint: alice.endpoint,
            pairwiseBinding: aliceBob,
            contact: aliceContact,
            now: afterExpiry
        )) { error in
            XCTAssertEqual(error as? CryptoError, .invalidPayload)
        }
        XCTAssertThrowsError(try MessageEngine.createInboundInstallationSession(
            localInstallation: bob.installation,
            localEndpoint: bob.endpoint,
            senderEndpoint: alice.endpoint,
            pairwiseBinding: bobAlice,
            contact: bobContact,
            kemCiphertext: outbound.kemCiphertext,
            prekey: outbound.prekey,
            now: afterExpiry
        )) { error in
            XCTAssertEqual(error as? CryptoError, .invalidPayload)
        }

        // The already-created endpoint session remains usable. Neither
        // established encryption nor decryption re-applies bootstrap age.
        var outboundConversation = outbound.conversation
        let context = try MessageAuthenticatedContext.directV4(
            eventId: UUID(),
            senderEndpoint: alice.endpoint,
            recipientEndpoint: bob.endpoint,
            pairwiseBinding: aliceBob
        )
        let envelope = try MessageEngine.encrypt(
            body: .text("established session survives prekey age"),
            senderSigningKey: alice.installation.signingKey,
            senderFingerprint: aliceBob.localInstallationHandle.rawValue,
            conversation: &outboundConversation,
            kemCiphertext: outbound.kemCiphertext,
            prekey: outbound.prekey,
            authenticatedContext: context
        )
        let decrypted = try MessageEngine.decryptDirectV4(
            envelope: envelope,
            contact: bobContact,
            localIdentity: bob.identity,
            localInstallation: bob.installation,
            localManifest: bob.manifest,
            localEndpoint: bob.endpoint,
            pairwiseBinding: bobAlice,
            conversation: &inboundConversation
        )
        XCTAssertEqual(decrypted.body, .text("established session survives prekey age"))
    }

    func testEndpointRevocationUsesCurrentContinuityKeyAfterRotationAndReload() throws {
        let original = try lifecycleEndpointFixture("Alice")
        var contact = try MessageEngine.contact(from: try lifecycleOffer(original))
        var rotatedIdentity = original.identity
        let rotation = try rotatedIdentity.rotateKeys().rotation
        XCTAssertTrue(contact.apply(rotation: rotation))

        let rotatedAt = original.manifest.issuedAt.addingTimeInterval(1)
        let rotatedManifest = try InstallationManifest.create(
            identityGenerationId: original.generationId,
            epoch: original.manifest.epoch + 1,
            previousManifestDigest: try XCTUnwrap(original.manifest.digest),
            installations: original.manifest.installations,
            identity: rotatedIdentity,
            issuedAt: rotatedAt
        )
        let revokedManifest = try XCTUnwrap(try rotatedManifest.revoking(
            installationId: original.installation.id,
            identity: rotatedIdentity,
            at: rotatedAt.addingTimeInterval(1)
        ))
        let revocation = try InstallationEndpointRevocationV4.create(
            endpoint: original.endpoint,
            revokedManifest: revokedManifest,
            identity: rotatedIdentity
        )

        XCTAssertTrue(contact.apply(endpointRevocation: revocation))
        let reloaded = try NoctweaveCoder.decode(
            Contact.self,
            from: NoctweaveCoder.encode(contact, sortedKeys: true)
        )
        XCTAssertThrowsError(try reloaded.certifiedInstallationEndpoint()) { error in
            XCTAssertEqual(
                error as? CertifiedInstallationEndpointError,
                .installationNotAuthorized
            )
        }
    }

    func testMailboxBatchRejectsInternalAndCursorRelativeGaps() {
        let first = SequencedEnvelope(
            sequence: 1,
            envelope: lifecycleEnvelope(counter: 1),
            storedAt: Date(timeIntervalSince1970: 1_001)
        )
        let second = SequencedEnvelope(
            sequence: 2,
            envelope: lifecycleEnvelope(counter: 2),
            storedAt: Date(timeIntervalSince1970: 1_002)
        )
        let third = SequencedEnvelope(
            sequence: 3,
            envelope: lifecycleEnvelope(counter: 3),
            storedAt: Date(timeIntervalSince1970: 1_003)
        )
        let cursor = MailboxCursor(rawValue: "opaque-cursor")

        let internalGap = MailboxSyncBatch(
            events: [first, third],
            nextCursor: cursor,
            nextSequence: 3,
            highWatermark: 3,
            retentionFloor: 0,
            hasMore: false
        )
        XCTAssertFalse(internalGap.isStructurallyValid)

        let omittedPrefix = MailboxSyncBatch(
            events: [second, third],
            nextCursor: cursor,
            nextSequence: 3,
            highWatermark: 3,
            retentionFloor: 0,
            hasMore: false
        )
        XCTAssertTrue(omittedPrefix.isStructurallyValid)
        XCTAssertFalse(omittedPrefix.isContiguous(after: 0))

        let contiguous = MailboxSyncBatch(
            events: [first, second],
            nextCursor: cursor,
            nextSequence: 2,
            highWatermark: 3,
            retentionFloor: 0,
            hasMore: true
        )
        XCTAssertTrue(contiguous.isStructurallyValid)
        XCTAssertTrue(contiguous.isContiguous(after: 0))
    }

    func testV2DecodeRejectsIntentOverflowWithoutTruncatingClientStateSetter() throws {
        let identity = try Identity.generate(displayName: "Intent bounds")
        var state = ClientState(
            identity: identity,
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            inboxId: InboxAddress.generate()
        )
        _ = try state.migrateToArchitectureV2()
        let createdAt = Date(timeIntervalSince1970: 1_700_000_000)
        let intents = (0...NoctweaveArchitectureV2.maximumProtocolIntents).map { index in
            ProtocolIntentV2.prepare(
                kind: .rotateRoute,
                targetIdentifier: Data("route-\(index)".utf8),
                payloadDigest: Data(SHA256.hash(data: Data("payload-\(index)".utf8))),
                createdAt: createdAt
            )
        }

        state.protocolIntents = intents
        XCTAssertEqual(
            state.protocolIntents.count,
            NoctweaveArchitectureV2.maximumProtocolIntents + 1
        )
        let encoded = try NoctweaveCoder.encode(state, sortedKeys: true)
        XCTAssertThrowsError(try NoctweaveCoder.decode(ClientState.self, from: encoded))
    }

    func testLegacyMigrationPreservesExactPendingCiphertextAndNonterminalIntent() throws {
        let identity = try Identity.generate(displayName: "Legacy durable outbox")
        let queuedAt = Date(timeIntervalSince1970: 1_700_100_000)
        let existingPending = lifecyclePendingDelivery(counter: 10, queuedAt: queuedAt)
        let missingIntentPending = lifecyclePendingDelivery(counter: 11, queuedAt: queuedAt)
        let encodedEnvelope = try NoctweaveCoder.encode(
            existingPending.envelope,
            sortedKeys: true
        )
        let existingIntent = ProtocolIntentV2.prepare(
            id: existingPending.id,
            kind: .sendEvent,
            targetIdentifier: Data(existingPending.contactId.uuidString.lowercased().utf8),
            payloadDigest: Data(SHA256.hash(data: encodedEnvelope)),
            createdAt: existingPending.queuedAt
        )
        var profile = IdentityProfile(
            protocolIntents: [existingIntent],
            identity: identity,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "127.0.0.1", port: 9340),
            pendingDirectDeliveries: [existingPending, missingIntentPending],
            prekeys: try PrekeyState.generate(identity: identity),
            createdAt: queuedAt
        )

        XCTAssertTrue(try profile.migrateToArchitectureV2())
        XCTAssertEqual(profile.pendingDirectDeliveries, [existingPending, missingIntentPending])
        XCTAssertEqual(
            profile.protocolIntents.first(where: { $0.id == existingPending.id }),
            existingIntent
        )
        let repaired = try XCTUnwrap(
            profile.protocolIntents.first(where: { $0.id == missingIntentPending.id })
        )
        XCTAssertEqual(repaired.kind, .sendEvent)
        XCTAssertFalse(repaired.state.isTerminal)
        XCTAssertTrue(profile.isArchitectureV2Ready)

        let reloaded = try NoctweaveCoder.decode(
            IdentityProfile.self,
            from: NoctweaveCoder.encode(profile, sortedKeys: true)
        )
        XCTAssertEqual(reloaded.pendingDirectDeliveries, profile.pendingDirectDeliveries)
        XCTAssertEqual(reloaded.protocolIntents, profile.protocolIntents)
    }

    func testDirectSendBackpressurePreservesFullIntentJournal() async throws {
        let port = UInt16.random(in: 61_001...63_500)
        let relay = RelayEndpoint(host: "127.0.0.1", port: port)
        let relayStore = RelayStore()
        let server = RelayServer(store: relayStore)
        try server.start(host: "127.0.0.1", port: port)
        try await Task.sleep(nanoseconds: 200_000_000)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer {
            server.stop()
            try? FileManager.default.removeItem(at: directory)
        }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let alice = HeadlessMessagingClient(
            stateURL: directory.appendingPathComponent("alice.json"),
            useEncryptedStore: false
        )
        let bob = HeadlessMessagingClient(
            stateURL: directory.appendingPathComponent("bob.json"),
            useEncryptedStore: false
        )
        _ = try await alice.createState(displayName: "Alice", relay: relay)
        _ = try await bob.createState(displayName: "Bob", relay: relay)
        try await alice.registerInbox()
        try await bob.registerInbox()
        _ = try await alice.importContactCode(try await bob.exportContactCode())

        let maybeState = try await alice.store.load()
        var state = try XCTUnwrap(maybeState)
        let createdAt = Date(timeIntervalSince1970: 1_700_200_000)
        let fullJournal = (0..<NoctweaveArchitectureV2.maximumProtocolIntents).map { index in
            ProtocolIntentV2.prepare(
                kind: .rotateRoute,
                targetIdentifier: Data("route-\(index)".utf8),
                payloadDigest: Data(SHA256.hash(data: Data("payload-\(index)".utf8))),
                createdAt: createdAt
            )
        }
        state.protocolIntents = fullJournal
        try await alice.store.save(state)

        do {
            _ = try await alice.sendText(to: "Bob", text: "must not evict durable state")
            XCTFail("Expected direct outbox backpressure")
        } catch {
            XCTAssertEqual(
                error as? HeadlessMessagingClientError,
                .directOutboxFull(NoctweaveArchitectureV2.maximumProtocolIntents)
            )
        }

        let maybePersisted = try await alice.store.load()
        let persisted = try XCTUnwrap(maybePersisted)
        XCTAssertEqual(persisted.protocolIntents, fullJournal)
        XCTAssertTrue(persisted.pendingDirectDeliveries.isEmpty)
    }
}

private struct LifecycleEndpointFixture {
    let identity: Identity
    let generationId: UUID
    let installation: LocalInstallationState
    let manifest: InstallationManifest
    let endpoint: CertifiedInstallationEndpoint
    let relay: RelayEndpoint
}

private func lifecycleEndpointFixture(_ name: String) throws -> LifecycleEndpointFixture {
    let identity = try Identity.generate(displayName: name)
    let generationId = UUID()
    let installation = try LocalInstallationState.generate(identityGenerationId: generationId)
    let manifest = try InstallationManifest.create(
        identityGenerationId: generationId,
        epoch: 0,
        installations: [installation.publicRecord(addedEpoch: 0)],
        identity: identity,
        issuedAt: installation.createdAt
    )
    return LifecycleEndpointFixture(
        identity: identity,
        generationId: generationId,
        installation: installation,
        manifest: manifest,
        endpoint: try CertifiedInstallationEndpoint.create(
            identity: identity,
            installation: installation,
            manifest: manifest,
            issuedAt: installation.createdAt
        ),
        relay: RelayEndpoint(host: "127.0.0.1", port: 9340)
    )
}

private func lifecycleOffer(_ fixture: LifecycleEndpointFixture) throws -> ContactOffer {
    try ContactOffer.createCertified(
        displayName: fixture.identity.displayName,
        inboxId: InboxAddress.generate(),
        relay: fixture.relay,
        identity: fixture.identity,
        identityGenerationId: fixture.generationId,
        installationManifest: fixture.manifest,
        preferredInstallationEndpoint: fixture.endpoint
    )
}

private func lifecycleBinding(
    local: LifecycleEndpointFixture,
    peer: LifecycleEndpointFixture
) throws -> PairwiseInstallationBindingV4 {
    try PairwiseInstallationBindingV4.derive(
        localIdentityGenerationId: local.generationId,
        localIdentitySigningPublicKey: local.identity.signingKey.publicKeyData,
        localEndpoint: local.endpoint,
        peerIdentityGenerationId: peer.generationId,
        peerIdentitySigningPublicKey: peer.identity.signingKey.publicKeyData,
        peerEndpoint: peer.endpoint
    )
}

private func lifecycleEnvelope(counter: UInt64) -> Envelope {
    Envelope(
        conversationId: "architecture-v2-lifecycle",
        sessionId: "session-v2",
        senderFingerprint: Data(repeating: 0x44, count: 32).base64EncodedString(),
        sentAt: Date(timeIntervalSince1970: TimeInterval(1_000 + counter)),
        messageCounter: counter,
        payload: EncryptedPayload(
            nonce: Data(repeating: 0x11, count: 12),
            ciphertext: Data(
                repeating: UInt8(truncatingIfNeeded: counter),
                count: PaddedMessagePlaintext.minimumPaddedBytes
            ),
            tag: Data(repeating: 0x22, count: 16)
        ),
        signature: Data(repeating: 0x33, count: 3_309)
    )
}

private func lifecyclePendingDelivery(
    counter: UInt64,
    queuedAt: Date
) -> PendingDirectDelivery {
    PendingDirectDelivery(
        contactId: UUID(),
        inboxId: InboxAddress.generate(),
        preferredRelay: RelayEndpoint(host: "sender-relay.example", port: 443, useTLS: true),
        destinationRelay: RelayEndpoint(host: "peer-relay.example", port: 443, useTLS: true),
        envelope: lifecycleEnvelope(counter: counter),
        queuedAt: queuedAt
    )
}

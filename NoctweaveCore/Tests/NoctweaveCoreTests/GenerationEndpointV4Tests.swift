import CryptoKit
import XCTest
@testable import NoctweaveCore

final class GenerationEndpointV4Tests: XCTestCase {
    func testDirectV4ContactImportRejectsPreV4Offer() throws {
        let identity = try Identity.generate(displayName: "Pre-v4")
        let offer = try ContactOffer.create(
            displayName: identity.displayName,
            inboxId: "pre-v4-inbox",
            relay: RelayEndpoint(host: "127.0.0.1", port: 9339),
            signingKey: identity.signingKey,
            agreementPublicKey: identity.agreementKey.publicKeyData
        )

        XCTAssertThrowsError(try MessageEngine.contact(from: offer)) { error in
            XCTAssertEqual(error as? ContactOfferError, .invalidStructure)
        }
    }

    func testPairwiseBindingMatchesSharedSwiftAndJavaScriptVector() throws {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let vectorURL = repositoryRoot
            .appendingPathComponent("NoctweaveDocumentation/test_vectors/direct_v4_pairwise_binding.json")
        let vector = try JSONDecoder().decode(
            DirectV4PairwiseBindingVector.self,
            from: Data(contentsOf: vectorURL)
        )
        let issuedAt = try XCTUnwrap(ISO8601DateFormatter().date(from: vector.issuedAt))
        let localEndpoint = directV4VectorEndpoint(vector.local, issuedAt: issuedAt)
        let peerEndpoint = directV4VectorEndpoint(vector.peer, issuedAt: issuedAt)

        let binding = try PairwiseEndpointBindingV4.derive(
            localIdentityGenerationId: try XCTUnwrap(UUID(uuidString: vector.local.identityGenerationId)),
            localIdentitySigningPublicKey: Data(
                repeating: UInt8(vector.local.identitySigningByte),
                count: 1_952
            ),
            localEndpoint: localEndpoint,
            peerIdentityGenerationId: try XCTUnwrap(UUID(uuidString: vector.peer.identityGenerationId)),
            peerIdentitySigningPublicKey: Data(
                repeating: UInt8(vector.peer.identitySigningByte),
                count: 1_952
            ),
            peerEndpoint: peerEndpoint
        )

        XCTAssertEqual(binding.relationshipId.uuidString, vector.expected.relationshipId)
        XCTAssertEqual(binding.localEndpointHandle.rawValue, vector.expected.localEndpointHandle)
        XCTAssertEqual(binding.peerEndpointHandle.rawValue, vector.expected.peerEndpointHandle)
        XCTAssertEqual(
            binding.localCertificateReferenceDigest.base64EncodedString(),
            vector.expected.localCertificateReferenceDigest
        )
        XCTAssertEqual(
            binding.peerCertificateReferenceDigest.base64EncodedString(),
            vector.expected.peerCertificateReferenceDigest
        )
        XCTAssertEqual(binding.cipherSuite, vector.expected.cipherSuite)
        XCTAssertEqual(
            binding.negotiatedCapabilitiesDigest.base64EncodedString(),
            vector.expected.negotiatedCapabilitiesDigest
        )
        XCTAssertEqual(
            MessageEngine.conversationIdForEndpoints(
                localEndpoint,
                peerEndpoint,
                pairwiseBinding: binding
            ),
            vector.wire.conversationId
        )

        let context = try MessageAuthenticatedContext.directV4(
            eventId: try XCTUnwrap(UUID(uuidString: vector.wire.eventId)),
            senderEndpoint: localEndpoint,
            recipientEndpoint: peerEndpoint,
            pairwiseBinding: binding
        )
        let aad = try NoctweaveCoder.encode(
            DirectV4AADVectorPayload(
                version: CertifiedGenerationEndpoint.version,
                conversationId: vector.wire.conversationId,
                sessionId: vector.wire.sessionId,
                messageCounter: vector.wire.messageCounter,
                context: context
            ),
            sortedKeys: true
        )
        XCTAssertEqual(aad.base64EncodedString(), vector.wire.aadCanonicalBase64)

        let signable = try Envelope.signableData(
            id: try XCTUnwrap(UUID(uuidString: vector.wire.envelopeId)),
            conversationId: vector.wire.conversationId,
            sessionId: vector.wire.sessionId,
            senderFingerprint: binding.localEndpointHandle.rawValue,
            sentAt: try XCTUnwrap(ISO8601DateFormatter().date(from: vector.wire.sentAt)),
            messageCounter: vector.wire.messageCounter,
            kemCiphertext: nil,
            prekey: nil,
            rootRatchet: nil,
            authenticatedContext: context,
            payload: EncryptedPayload(
                nonce: Data(repeating: UInt8(vector.wire.nonceByte), count: 12),
                ciphertext: Data(
                    repeating: UInt8(vector.wire.ciphertextByte),
                    count: vector.wire.ciphertextCount
                ),
                tag: Data(repeating: UInt8(vector.wire.tagByte), count: 16)
            )
        )
        XCTAssertEqual(
            Data(SHA256.hash(data: signable)).base64EncodedString(),
            vector.wire.signatureCanonicalSHA256
        )
    }

    func testPairwiseBindingsAreSymmetricAndCrossRelationshipUnlinkable() throws {
        let alice = try fixture("Alice")
        let bob = try fixture("Bob")
        let carol = try fixture("Carol")

        let aliceBob = try binding(local: alice, peer: bob)
        let bobAlice = try binding(local: bob, peer: alice)
        let aliceCarol = try binding(local: alice, peer: carol)

        XCTAssertEqual(aliceBob.relationshipId, bobAlice.relationshipId)
        XCTAssertEqual(aliceBob.localEndpointHandle, bobAlice.peerEndpointHandle)
        XCTAssertEqual(aliceBob.peerEndpointHandle, bobAlice.localEndpointHandle)
        XCTAssertEqual(
            aliceBob.localCertificateReferenceDigest,
            bobAlice.peerCertificateReferenceDigest
        )
        XCTAssertNotEqual(aliceBob.relationshipId, aliceCarol.relationshipId)
        XCTAssertNotEqual(
            aliceBob.localEndpointHandle,
            aliceCarol.localEndpointHandle
        )
        XCTAssertNotEqual(
            aliceBob.localCertificateReferenceDigest,
            aliceCarol.localCertificateReferenceDigest
        )
    }

    func testDirectV4NegotiationFailsClosedOnMissingModulesVersionGapsAndDowngrade() throws {
        let issuedAt = Date(timeIntervalSince1970: 1_752_672_896)
        let base = ProtocolCapabilityManifest()
        let local = directV4VectorEndpoint(
            DirectV4PairwiseBindingVector.Endpoint.localFixture,
            issuedAt: issuedAt,
            capabilities: base
        )
        let missingEvents = ProtocolCapabilityManifest(
            modules: base.modules.filter { $0.module != "nw.events" }
        )
        let peerMissing = directV4VectorEndpoint(
            DirectV4PairwiseBindingVector.Endpoint.peerFixture,
            issuedAt: issuedAt,
            capabilities: missingEvents
        )
        XCTAssertThrowsError(
            try PairwiseEndpointBindingV4.derive(
                localIdentityGenerationId: local.identityGenerationId,
                localIdentitySigningPublicKey: local.identityAuthorityPublicKey,
                localEndpoint: local,
                peerIdentityGenerationId: peerMissing.identityGenerationId,
                peerIdentitySigningPublicKey: peerMissing.identityAuthorityPublicKey,
                peerEndpoint: peerMissing
            )
        ) { error in
            XCTAssertEqual(
                error as? DirectV4CapabilityNegotiationError,
                .missingRequiredModule("nw.events")
            )
        }

        let incompatibleEvents = replacingCapabilityModule(
            "nw.events",
            in: base,
            versions: [3]
        )
        let peerIncompatible = directV4VectorEndpoint(
            DirectV4PairwiseBindingVector.Endpoint.peerFixture,
            issuedAt: issuedAt,
            capabilities: incompatibleEvents
        )
        XCTAssertThrowsError(
            try PairwiseEndpointBindingV4.derive(
                localIdentityGenerationId: local.identityGenerationId,
                localIdentitySigningPublicKey: local.identityAuthorityPublicKey,
                localEndpoint: local,
                peerIdentityGenerationId: peerIncompatible.identityGenerationId,
                peerIdentitySigningPublicKey: peerIncompatible.identityAuthorityPublicKey,
                peerEndpoint: peerIncompatible
            )
        ) { error in
            XCTAssertEqual(
                error as? DirectV4CapabilityNegotiationError,
                .noSharedVersion("nw.events")
            )
        }

        let peer = directV4VectorEndpoint(
            DirectV4PairwiseBindingVector.Endpoint.peerFixture,
            issuedAt: issuedAt,
            capabilities: base
        )
        let binding = try PairwiseEndpointBindingV4.derive(
            localIdentityGenerationId: local.identityGenerationId,
            localIdentitySigningPublicKey: local.identityAuthorityPublicKey,
            localEndpoint: local,
            peerIdentityGenerationId: peer.identityGenerationId,
            peerIdentitySigningPublicKey: peer.identityAuthorityPublicKey,
            peerEndpoint: peer
        )
        let downgraded = try DirectMessageAuthenticatedContextV4(
            cipherSuite: "nw.direct-v4.downgraded",
            negotiatedCapabilitiesDigest: binding.negotiatedCapabilitiesDigest,
            eventId: UUID(),
            senderEndpointHandle: binding.localEndpointHandle,
            senderCertificateDigest: binding.localCertificateReferenceDigest,
            recipientEndpointHandle: binding.peerEndpointHandle,
            senderManifestEpoch: local.manifestEpoch,
            recipientManifestEpoch: peer.manifestEpoch,
            recipientCertificateDigest: binding.peerCertificateReferenceDigest
        )
        XCTAssertFalse(downgraded.isStructurallyValid)

    }

    func testDirectV4NegotiationIsSymmetricAndBindsAlteredLimits() throws {
        let base = ProtocolCapabilityManifest()
        let optionalGroup = try XCTUnwrap(
            ProtocolCapabilityManifest.knownModuleCatalog.first { $0.module == "nw.groups" }
        )
        let optionalPrivacy = try XCTUnwrap(
            ProtocolCapabilityManifest.knownModuleCatalog.first {
                $0.module == "nw.privacy.onion"
            }
        )
        let explicitlyExtended = ProtocolCapabilityManifest(
            modules: base.modules + [optionalGroup, optionalPrivacy]
        )
        XCTAssertEqual(
            try DirectV4NegotiatedCapabilityManifest.negotiate(
                local: base,
                peer: explicitlyExtended
            ),
            try DirectV4NegotiatedCapabilityManifest.negotiate(local: base, peer: base)
        )

        let overclaimedEndpoints = replacingCapabilityModule(
            "nw.endpoints",
            in: base,
            limits: ["maxActiveEndpoints": 16]
        )
        XCTAssertEqual(
            try DirectV4NegotiatedCapabilityManifest.negotiate(
                local: overclaimedEndpoints,
                peer: overclaimedEndpoints
            ).limit(module: "nw.endpoints", name: "maxActiveEndpoints"),
            1
        )
        let constrained = replacingCapabilityModule(
            "nw.events",
            in: base,
            limits: ["maxContentPayloadBytes": 1_024]
        )
        let forward = try DirectV4NegotiatedCapabilityManifest.negotiate(
            local: base,
            peer: constrained
        )
        let reverse = try DirectV4NegotiatedCapabilityManifest.negotiate(
            local: constrained,
            peer: base
        )
        XCTAssertEqual(forward, reverse)
        XCTAssertEqual(forward.cipherSuite, DirectV4CipherSuite.identifier)
        XCTAssertEqual(
            forward.limit(module: "nw.events", name: "maxContentPayloadBytes"),
            1_024
        )
        XCTAssertNotEqual(
            try forward.digest(),
            try DirectV4NegotiatedCapabilityManifest.negotiate(
                local: base,
                peer: base
            ).digest()
        )
    }

    func testDirectV4WireIsOpaqueAndSignedByEndpoint() throws {
        let alice = try fixture("Alice")
        let bob = try fixture("Bob")
        let aliceOffer = try offer(alice)
        let bobOffer = try offer(bob)
        let aliceContact = try MessageEngine.contact(from: bobOffer)
        let bobContact = try MessageEngine.contact(from: aliceOffer)
        let aliceBob = try binding(local: alice, peer: bob)
        let bobAlice = try binding(local: bob, peer: alice)

        let outbound = try MessageEngine.createOutboundEndpointSession(
            localEndpoint: alice.localEndpoint,
            localCertificate: alice.endpoint,
            pairwiseBinding: aliceBob,
            contact: aliceContact
        )
        var outboundConversation = outbound.conversation
        let eventId = UUID()
        let context = try MessageAuthenticatedContext.directV4(
            eventId: eventId,
            senderEndpoint: alice.endpoint,
            recipientEndpoint: bob.endpoint,
            pairwiseBinding: aliceBob
        )
        let sentAt = Date(timeIntervalSince1970: 1_752_680_100)
        let event = ConversationEvent(
            id: eventId,
            conversationId: outboundConversation.id,
            authorEndpointHandle: aliceBob.localEndpointHandle,
            createdAt: sentAt,
            kind: .application,
            content: try XCTUnwrap(EncodedContent.text("endpoint signed"))
        )
        let envelope = try MessageEngine.encryptDirectV4(
            wirePayload: .application(event),
            senderSigningKey: alice.localEndpoint.signingKey,
            senderFingerprint: aliceBob.localEndpointHandle.rawValue,
            conversation: &outboundConversation,
            kemCiphertext: outbound.kemCiphertext,
            prekey: outbound.prekey,
            authenticatedContext: context,
            sentAt: sentAt
        )

        XCTAssertEqual(envelope.senderFingerprint, aliceBob.localEndpointHandle.rawValue)
        XCTAssertEqual(context.directV4?.cipherSuite, DirectV4CipherSuite.identifier)
        XCTAssertEqual(
            context.directV4?.negotiatedCapabilitiesDigest,
            aliceBob.negotiatedCapabilitiesDigest
        )
        XCTAssertTrue(envelope.verifySignature(
            publicSigningKey: alice.localEndpoint.signingKey.publicKeyData
        ))
        XCTAssertFalse(envelope.verifySignature(
            publicSigningKey: alice.identity.signingKey.publicKeyData
        ))

        let relayVisible = try NoctweaveCoder.encode(try XCTUnwrap(context.directV4))
        let relayJSON = try XCTUnwrap(String(data: relayVisible, encoding: .utf8))
        for forbidden in [
            alice.identity.signingKey.publicKeyData.base64EncodedString(),
            alice.localEndpoint.signingKey.publicKeyData.base64EncodedString(),
            alice.localEndpoint.agreementKey.publicKeyData.base64EncodedString(),
            alice.endpoint.prekeyBundle.signedPrekey.publicKey.base64EncodedString(),
            alice.localEndpoint.id.uuidString,
            alice.localEndpoint.identityGenerationId.uuidString,
            alice.identity.fingerprint,
            "prekeyBundle",
            "endpointSetManifest",
            "identityAuthorityPublicKey",
            "signingPublicKey",
            "agreementPublicKey"
        ] {
            XCTAssertFalse(relayJSON.contains(forbidden), "relay context leaked \(forbidden)")
        }

        var inboundConversation = try MessageEngine.createInboundEndpointSession(
            localEndpoint: bob.localEndpoint,
            localCertificate: bob.endpoint,
            senderEndpoint: alice.endpoint,
            pairwiseBinding: bobAlice,
            contact: bobContact,
            kemCiphertext: outbound.kemCiphertext,
            prekey: outbound.prekey
        )
        let decrypted = try MessageEngine.decryptDirectV4(
            envelope: envelope,
            contact: bobContact,
            localIdentity: bob.identity,
            localEndpoint: bob.localEndpoint,
            localManifest: bob.manifest,
            localCertificate: bob.endpoint,
            pairwiseBinding: bobAlice,
            conversation: &inboundConversation
        )
        XCTAssertEqual(decrypted.body, .text("endpoint signed"))
        XCTAssertEqual(context.directV4?.eventId, eventId)
    }

    func testRevokedPreferredEndpointFailsClosed() throws {
        let alice = try fixture("Alice")
        let bob = try fixture("Bob")
        var bobContact = try MessageEngine.contact(from: try offer(alice))
        let revokedAt = alice.manifest.issuedAt.addingTimeInterval(1)
        let revokedManifest = try XCTUnwrap(
            try alice.manifest.revoking(
                endpointId: alice.localEndpoint.id,
                identity: alice.identity,
                at: revokedAt
            )
        )
        let revocation = try EndpointRemovalProofV4.create(
            endpoint: alice.endpoint,
            revokedManifest: revokedManifest,
            identity: alice.identity
        )
        XCTAssertTrue(bobContact.apply(endpointRevocation: revocation))
        XCTAssertThrowsError(try bobContact.certifiedGenerationEndpoint())

        let unrelated = try fixture("Mallory")
        let direct = try XCTUnwrap(
            try MessageAuthenticatedContext.directV4(
                eventId: UUID(),
                senderEndpoint: unrelated.endpoint,
                recipientEndpoint: bob.endpoint,
                pairwiseBinding: try binding(local: unrelated, peer: bob)
            ).directV4
        )
        var state = try makeCurrentClientState(
            identity: bob.identity,
            relay: bob.relay
        )
        state.contacts = [bobContact]
        XCTAssertNil(state.resolveCertifiedDirectContext(direct))
    }

    func testHeadlessMutualOffersPersistEndpointSessionAcrossRestart() async throws {
        let port = UInt16.random(in: 58_001...61_000)
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
        let aliceURL = directory.appendingPathComponent("alice.json")
        let bobURL = directory.appendingPathComponent("bob.json")
        let alice = HeadlessMessagingClient(stateURL: aliceURL, useEncryptedStore: false)
        let bob = HeadlessMessagingClient(stateURL: bobURL, useEncryptedStore: false)
        _ = try await alice.createState(displayName: "Alice", relay: relay)
        _ = try await bob.createState(displayName: "Bob", relay: relay)
        try await alice.registerInbox()
        try await bob.registerInbox()
        let aliceCode = try await alice.exportContactCode()
        let bobCode = try await bob.exportContactCode()
        _ = try await alice.importContactCode(bobCode)
        _ = try await bob.importContactCode(aliceCode)

        let sent = try await alice.sendText(to: "Bob", text: "pairwise v4")
        let maybeBobState = try await bob.store.load()
        let bobState = try XCTUnwrap(maybeBobState)
        let storedEnvelopes = try await relayStore.fetch(inboxId: bobState.inboxId)
        let stored = try XCTUnwrap(storedEnvelopes.first)
        let maybeAliceState = try await alice.store.load()
        let aliceState = try XCTUnwrap(maybeAliceState)
        let aliceEndpoint = try XCTUnwrap(aliceState.localEndpoint)
        XCTAssertEqual(stored.authenticatedContext?.purpose, .directV4)
        XCTAssertTrue(stored.verifySignature(publicSigningKey: aliceEndpoint.signingKey.publicKeyData))
        XCTAssertFalse(stored.verifySignature(publicSigningKey: aliceState.identity.signingKey.publicKeyData))
        XCTAssertEqual(stored.id, sent.envelopeId)

        let restartedBob = HeadlessMessagingClient(stateURL: bobURL, useEncryptedStore: false)
        let received = try await restartedBob.receive(maxCount: 10)
        XCTAssertEqual(received.map(\.body), [.text("pairwise v4")])
        let maybePersisted = try await restartedBob.store.load()
        let persisted = try XCTUnwrap(maybePersisted)
        let session = try XCTUnwrap(persisted.conversations.first?.endpointSession)
        XCTAssertEqual(session.localEndpointId, persisted.localEndpoint?.id)
        XCTAssertEqual(session.peerEndpointHandle.rawValue, stored.senderFingerprint)
    }
}

private struct DirectV4PairwiseBindingVector: Decodable {
    struct Endpoint: Decodable {
        let identityGenerationId: String
        let identitySigningByte: Int
        let endpointId: String
        let endpointSigningByte: Int
        let endpointAgreementByte: Int
        let manifestEpoch: UInt64
        let manifestDigestByte: Int
        let signedPrekeyId: String
        let signedPrekeyByte: Int
        let signatureByte: Int

        static let localFixture = Endpoint(
            identityGenerationId: "11111111-2222-4333-8444-555555555555",
            identitySigningByte: 17,
            endpointId: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
            endpointSigningByte: 49,
            endpointAgreementByte: 65,
            manifestEpoch: 3,
            manifestDigestByte: 81,
            signedPrekeyId: "10101010-2020-4030-8040-505050505050",
            signedPrekeyByte: 97,
            signatureByte: 113
        )

        static let peerFixture = Endpoint(
            identityGenerationId: "99999999-8888-4777-8666-555555555555",
            identitySigningByte: 34,
            endpointId: "BBBBBBBB-CCCC-4DDD-8EEE-FFFFFFFFFFFF",
            endpointSigningByte: 50,
            endpointAgreementByte: 66,
            manifestEpoch: 7,
            manifestDigestByte: 82,
            signedPrekeyId: "60606060-7070-4080-8090-A0A0A0A0A0A0",
            signedPrekeyByte: 98,
            signatureByte: 114
        )
    }

    struct Expected: Decodable {
        let relationshipId: String
        let localEndpointHandle: String
        let peerEndpointHandle: String
        let localCertificateReferenceDigest: String
        let peerCertificateReferenceDigest: String
        let cipherSuite: String
        let negotiatedCapabilitiesDigest: String
    }

    struct Wire: Decodable {
        let eventId: String
        let envelopeId: String
        let clientTransactionId: String
        let conversationId: String
        let sessionId: String
        let sentAt: String
        let messageCounter: UInt64
        let nonceByte: Int
        let ciphertextByte: Int
        let ciphertextCount: Int
        let tagByte: Int
        let aadCanonicalBase64: String
        let signatureCanonicalSHA256: String
    }

    let issuedAt: String
    let local: Endpoint
    let peer: Endpoint
    let wire: Wire
    let expected: Expected
}

private struct DirectV4AADVectorPayload: Codable {
    let version: Int
    let conversationId: String
    let sessionId: String
    let messageCounter: UInt64
    let context: MessageAuthenticatedContext?
}

private func directV4VectorEndpoint(
    _ value: DirectV4PairwiseBindingVector.Endpoint,
    issuedAt: Date,
    capabilities: ProtocolCapabilityManifest = ProtocolCapabilityManifest()
) -> CertifiedGenerationEndpoint {
    let signature = Data(repeating: UInt8(value.signatureByte), count: 3_309)
    return CertifiedGenerationEndpoint(
        identityGenerationId: UUID(uuidString: value.identityGenerationId)!,
        identityAuthorityPublicKey: Data(
            repeating: UInt8(value.identitySigningByte),
            count: 1_952
        ),
        manifestEpoch: value.manifestEpoch,
        manifestDigest: Data(repeating: UInt8(value.manifestDigestByte), count: 32),
        endpointId: UUID(uuidString: value.endpointId)!,
        signingPublicKey: Data(repeating: UInt8(value.endpointSigningByte), count: 1_952),
        agreementPublicKey: Data(repeating: UInt8(value.endpointAgreementByte), count: 1_184),
        capabilities: capabilities,
        prekeyBundle: PrekeyBundle(
            identityFingerprint: Data(
                repeating: UInt8(value.endpointSigningByte),
                count: 32
            ).base64EncodedString(),
            signedPrekey: SignedPrekey(
                id: UUID(uuidString: value.signedPrekeyId)!,
                publicKey: Data(repeating: UInt8(value.signedPrekeyByte), count: 1_184),
                issuedAt: issuedAt,
                signature: signature
            ),
            oneTimePrekeys: [],
            createdAt: issuedAt
        ),
        issuedAt: issuedAt,
        authoritySignature: signature,
        possessionSignature: signature
    )
}

private func replacingCapabilityModule(
    _ name: String,
    in manifest: ProtocolCapabilityManifest,
    versions: [UInt16]? = nil,
    limits: [String: UInt64]? = nil
) -> ProtocolCapabilityManifest {
    ProtocolCapabilityManifest(
        modules: manifest.modules.map { module in
            guard module.module == name else { return module }
            return ProtocolModuleCapability(
                module: module.module,
                versions: versions ?? module.versions,
                status: module.status,
                limits: limits ?? module.limits
            )
        }
    )
}

private struct EndpointFixture {
    let identity: Identity
    let generationId: UUID
    let localEndpoint: LocalEndpointState
    let manifest: EndpointSetManifest
    let endpoint: CertifiedGenerationEndpoint
    let relay: RelayEndpoint
}

private func fixture(_ name: String) throws -> EndpointFixture {
    let identity = try Identity.generate(displayName: name)
    let generationId = UUID()
    let localEndpoint = try LocalEndpointState.generate(identityGenerationId: generationId)
    let manifest = try EndpointSetManifest.create(
        identityGenerationId: generationId,
        epoch: 0,
        endpoints: [localEndpoint.publicRecord(addedEpoch: 0)],
        identity: identity,
        issuedAt: localEndpoint.createdAt
    )
    return EndpointFixture(
        identity: identity,
        generationId: generationId,
        localEndpoint: localEndpoint,
        manifest: manifest,
        endpoint: try CertifiedGenerationEndpoint.create(
            identity: identity,
            endpoint: localEndpoint,
            manifest: manifest,
            issuedAt: localEndpoint.createdAt
        ),
        relay: RelayEndpoint(host: "127.0.0.1", port: 9340)
    )
}

private func offer(_ fixture: EndpointFixture) throws -> ContactOffer {
    try ContactOffer.createCertified(
        displayName: fixture.identity.displayName,
        inboxId: "test-inbox-\(fixture.identity.fingerprint.prefix(12))",
        relay: fixture.relay,
        identity: fixture.identity,
        identityGenerationId: fixture.generationId,
        endpointSetManifest: fixture.manifest,
        preferredGenerationEndpoint: fixture.endpoint
    )
}

private func binding(
    local: EndpointFixture,
    peer: EndpointFixture
) throws -> PairwiseEndpointBindingV4 {
    try PairwiseEndpointBindingV4.derive(
        localIdentityGenerationId: local.generationId,
        localIdentitySigningPublicKey: local.identity.signingKey.publicKeyData,
        localEndpoint: local.endpoint,
        peerIdentityGenerationId: peer.generationId,
        peerIdentitySigningPublicKey: peer.identity.signingKey.publicKeyData,
        peerEndpoint: peer.endpoint
    )
}

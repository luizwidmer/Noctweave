import Foundation
import XCTest
@testable import NoctweaveCore

final class WirePayloadV2Tests: XCTestCase {
    func testDirectV4TypedApplicationRoundTripBindsDistinctIdentifiersAndFormat() throws {
        let pair = try makeWirePair()
        var outbound = pair.outbound.conversation
        var inbound = try pair.inboundConversation()
        let eventId = UUID()
        let transactionId = UUID()
        let sentAt = Date(timeIntervalSince1970: 20_000)
        let context = try MessageAuthenticatedContext.directV4(
            eventId: eventId,
            senderEndpoint: pair.alice.endpoint,
            recipientEndpoint: pair.bob.endpoint,
            pairwiseBinding: pair.aliceBob
        )
        let event = ConversationEvent(
            id: eventId,
            clientTransactionId: transactionId,
            conversationId: outbound.id,
            authorInstallationHandle: pair.aliceBob.localInstallationHandle,
            createdAt: sentAt,
            kind: .application,
            content: try XCTUnwrap(EncodedContent.text("typed direct-v4"))
        )
        let envelope = try MessageEngine.encryptDirectV4(
            wirePayload: .application(event),
            senderSigningKey: pair.alice.installation.signingKey,
            senderFingerprint: pair.aliceBob.localInstallationHandle.rawValue,
            conversation: &outbound,
            kemCiphertext: pair.outbound.kemCiphertext,
            prekey: pair.outbound.prekey,
            authenticatedContext: context,
            sentAt: sentAt
        )

        XCTAssertNotEqual(event.id, event.clientTransactionId)
        XCTAssertEqual(context.directV4?.payloadFormat, NoctweaveWirePayloadV2.directV4Format)
        let decrypted = try MessageEngine.decryptDirectV4Payload(
            envelope: envelope,
            contact: pair.bobContact,
            localIdentity: pair.bob.identity,
            localInstallation: pair.bob.installation,
            localManifest: pair.bob.manifest,
            localEndpoint: pair.bob.endpoint,
            pairwiseBinding: pair.bobAlice,
            conversation: &inbound
        )
        guard case .application(let decodedEvent, let projection) = decrypted.disposition else {
            return XCTFail("Expected typed application payload")
        }
        XCTAssertEqual(decodedEvent, event)
        XCTAssertEqual(projection.body, .text("typed direct-v4"))
        XCTAssertEqual(inbound.receiveChain.counter, 1)
    }

    func testKnownTextProfileMatchesJavaScriptDecoderExactly() throws {
        let handle = RelationshipInstallationHandle(
            rawValue: Data(repeating: 0x4f, count: 32).base64EncodedString()
        )
        let makeEvent: (EncodedContent, EventRelation?) -> ConversationEvent = { content, relation in
            ConversationEvent(
                conversationId: "conversation",
                authorInstallationHandle: handle,
                kind: .application,
                content: content,
                relation: relation
            )
        }
        let text = Data("canonical text".utf8)
        let valid = EncodedContent(
            type: .text,
            payload: text,
            fallbackText: "canonical text",
            disposition: .visible
        )
        XCTAssertEqual(
            try WirePayloadV2.application(makeEvent(valid, nil)).applicationProjection().body,
            .text("canonical text")
        )

        let invalidContents = [
            EncodedContent(
                type: .text,
                parameters: ["language": "en"],
                payload: text,
                fallbackText: "canonical text",
                disposition: .visible
            ),
            EncodedContent(
                type: .text,
                payload: text,
                fallbackText: "different",
                disposition: .visible
            ),
            EncodedContent(
                type: .text,
                payload: text,
                fallbackText: "canonical text",
                disposition: .silent
            )
        ]
        for content in invalidContents {
            XCTAssertThrowsError(
                try WirePayloadV2.application(makeEvent(content, nil)).applicationProjection()
            )
        }
        XCTAssertThrowsError(
            try WirePayloadV2.application(
                makeEvent(valid, EventRelation(kind: .reply, targetEventId: UUID()))
            ).applicationProjection()
        )
    }

    func testKnownAttachmentFallbackMatchesJavaScriptDecoderExactly() throws {
        let handle = RelationshipInstallationHandle(
            rawValue: Data(repeating: 0x50, count: 32).base64EncodedString()
        )
        let expectedFallbacks = [
            "image/png": "Image",
            "audio/ogg": "Voice message",
            "application/pdf": "Attachment"
        ]

        for (mimeType, expectedFallback) in expectedFallbacks {
            let descriptor = AttachmentDescriptor(
                fileName: nil,
                mimeType: mimeType,
                byteCount: 1,
                sha256: Data(repeating: 0x42, count: 32),
                chunkCount: 1,
                chunkSize: 1
            )
            let wire = try WirePayloadV2.projectingMessageBody(
                .attachment(descriptor),
                eventId: UUID(),
                clientTransactionId: UUID(),
                conversationId: "conversation",
                authorInstallationHandle: handle,
                createdAt: Date(timeIntervalSince1970: 20_001)
            )

            XCTAssertEqual(wire.application?.content.fallbackText, expectedFallback)
            XCTAssertEqual(try wire.applicationProjection().body, .attachment(descriptor))
        }
    }

    func testUnknownApplicationContentIsPreservedWithVisibleOrSilentProjection() throws {
        XCTAssertFalse(
            ContentTypeId(authority: "example/app", name: "poll", major: 1)
                .isStructurallyValid
        )
        XCTAssertFalse(
            ContentTypeId(authority: "example.app", name: "poll:spoof", major: 1)
                .isStructurallyValid
        )
        let handle = RelationshipInstallationHandle(
            rawValue: Data(repeating: 0x51, count: 32).base64EncodedString()
        )
        let unknownType = ContentTypeId(
            authority: "example.app",
            name: "poll",
            major: 7,
            minor: 2
        )
        let visibleEvent = ConversationEvent(
            conversationId: "conversation",
            authorInstallationHandle: handle,
            createdAt: Date(timeIntervalSince1970: 21_000),
            kind: .application,
            content: EncodedContent(
                type: unknownType,
                payload: Data("opaque-poll".utf8),
                fallbackText: "Unsupported poll",
                disposition: .visible
            )
        )
        let visibleWire = try WirePayloadV2.application(visibleEvent)
        let encoded = try PaddedMessagePlaintext.encodeWirePayloadV2(visibleWire)
        let decoded = try PaddedMessagePlaintext.decodeWirePayloadV2(encoded)
        let visibleProjection = try decoded.applicationProjection()

        XCTAssertEqual(decoded.application, visibleEvent)
        XCTAssertTrue(visibleProjection.isUnsupported)
        XCTAssertEqual(visibleProjection.body, .text("Unsupported poll"))

        let silentEvent = ConversationEvent(
            conversationId: "conversation",
            authorInstallationHandle: handle,
            createdAt: Date(timeIntervalSince1970: 21_001),
            kind: .receipt,
            content: EncodedContent(
                type: unknownType,
                payload: Data("opaque-receipt".utf8),
                fallbackText: "must not display",
                disposition: .silent
            )
        )
        let silentProjection = try WirePayloadV2.application(silentEvent).applicationProjection()
        XCTAssertTrue(silentProjection.isUnsupported)
        XCTAssertNil(silentProjection.body)
    }

    func testUnknownControlIsQuarantinedAndMalformedKnownControlFailsTransactionally() throws {
        let pair = try makeWirePair()
        var outbound = pair.outbound.conversation
        var inbound = try pair.inboundConversation()
        let sentAt = Date(timeIntervalSince1970: 22_000)
        let unknownContext = try MessageAuthenticatedContext.directV4(
            eventId: UUID(),
            senderEndpoint: pair.alice.endpoint,
            recipientEndpoint: pair.bob.endpoint,
            pairwiseBinding: pair.aliceBob
        )
        let unknown = AuthenticatedControlPayloadV2(
            type: ContentTypeId(
                authority: "org.noctweave.control",
                name: "future-policy",
                major: 1,
                minor: 0
            ),
            encodedPayload: Data("opaque-future-control".utf8)
        )
        let unknownEnvelope = try MessageEngine.encryptDirectV4(
            wirePayload: .control(unknown),
            senderSigningKey: pair.alice.installation.signingKey,
            senderFingerprint: pair.aliceBob.localInstallationHandle.rawValue,
            conversation: &outbound,
            kemCiphertext: pair.outbound.kemCiphertext,
            prekey: pair.outbound.prekey,
            authenticatedContext: unknownContext,
            sentAt: sentAt
        )
        let unknownResult = try MessageEngine.decryptDirectV4Payload(
            envelope: unknownEnvelope,
            contact: pair.bobContact,
            localIdentity: pair.bob.identity,
            localInstallation: pair.bob.installation,
            localManifest: pair.bob.manifest,
            localEndpoint: pair.bob.endpoint,
            pairwiseBinding: pair.bobAlice,
            conversation: &inbound
        )
        guard case .quarantinedControl(let quarantined) = unknownResult.disposition else {
            return XCTFail("Expected unknown control quarantine")
        }
        XCTAssertNil(unknownResult.disposition.body)
        XCTAssertEqual(quarantined.event.id, unknownContext.directV4?.eventId)
        XCTAssertEqual(quarantined.event.kind, .control)
        XCTAssertEqual(quarantined.event.content.payload, unknown.encodedPayload)
        XCTAssertEqual(inbound.receiveChain.counter, 1)

        let malformedContext = try MessageAuthenticatedContext.directV4(
            eventId: UUID(),
            senderEndpoint: pair.alice.endpoint,
            recipientEndpoint: pair.bob.endpoint,
            pairwiseBinding: pair.aliceBob
        )
        let malformed = AuthenticatedControlPayloadV2(
            type: AuthenticatedControlKindV2.identityRotation.contentType,
            encodedPayload: Data("not-a-rotation".utf8)
        )
        let malformedEnvelope = try MessageEngine.encryptDirectV4(
            wirePayload: .control(malformed),
            senderSigningKey: pair.alice.installation.signingKey,
            senderFingerprint: pair.aliceBob.localInstallationHandle.rawValue,
            conversation: &outbound,
            authenticatedContext: malformedContext,
            sentAt: sentAt.addingTimeInterval(1)
        )
        let counterBefore = inbound.receiveChain.counter
        XCTAssertThrowsError(
            try MessageEngine.decryptDirectV4Payload(
                envelope: malformedEnvelope,
                contact: pair.bobContact,
                localIdentity: pair.bob.identity,
                localInstallation: pair.bob.installation,
                localManifest: pair.bob.manifest,
                localEndpoint: pair.bob.endpoint,
                pairwiseBinding: pair.bobAlice,
                conversation: &inbound
            )
        ) { error in
            XCTAssertEqual(error as? WirePayloadV2Error, .invalidKnownControl)
        }
        XCTAssertEqual(inbound.receiveChain.counter, counterBefore)
    }

    func testLegacyAndTypedPaddingFramesAreMutuallyIsolated() throws {
        let legacy = try PaddedMessagePlaintext.encodeLegacyMessageBody(.text("legacy"))
        let handle = RelationshipInstallationHandle(
            rawValue: Data(repeating: 0x61, count: 32).base64EncodedString()
        )
        let event = ConversationEvent(
            conversationId: "conversation",
            authorInstallationHandle: handle,
            createdAt: Date(timeIntervalSince1970: 23_000),
            kind: .application,
            content: try XCTUnwrap(EncodedContent.text("typed"))
        )
        let typed = try PaddedMessagePlaintext.encodeWirePayloadV2(.application(event))

        XCTAssertThrowsError(try PaddedMessagePlaintext.decodeWirePayloadV2(legacy))
        XCTAssertThrowsError(try PaddedMessagePlaintext.decodeLegacyMessageBody(typed))
        XCTAssertEqual(try PaddedMessagePlaintext.decodeLegacyMessageBody(legacy), .text("legacy"))
        XCTAssertEqual(try PaddedMessagePlaintext.decodeWirePayloadV2(typed).application, event)
    }

    func testHeadlessPersistsUnknownApplicationAndQuarantinesUnknownControlWithoutBubble() async throws {
        let relayStore = RelayStore()
        let server = RelayServer(store: relayStore)
        let started = expectation(description: "typed payload relay started")
        var boundPort: UInt16?
        server.onEvent = { event in
            if case .started(let port) = event {
                boundPort = port
                started.fulfill()
            }
        }
        try server.start(host: "127.0.0.1", port: 0)
        await fulfillment(of: [started], timeout: 2)
        let relay = RelayEndpoint(host: "127.0.0.1", port: try XCTUnwrap(boundPort))
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
        let aliceCode = try await alice.exportContactCode()
        let bobCode = try await bob.exportContactCode()
        _ = try await alice.importContactCode(bobCode)
        _ = try await bob.importContactCode(aliceCode)

        let maybeAliceState = try await alice.store.load()
        let maybeBobState = try await bob.store.load()
        let aliceState = try XCTUnwrap(maybeAliceState)
        let bobState = try XCTUnwrap(maybeBobState)
        let aliceInstallation = try XCTUnwrap(aliceState.localInstallation)
        let aliceGeneration = try XCTUnwrap(aliceState.identityGenerationId)
        let aliceEndpoint = try XCTUnwrap(aliceState.issuedContactEndpointsV2.last)
        let bobContact = try XCTUnwrap(aliceState.contacts.first)
        let bobEndpoint = try bobContact.certifiedInstallationEndpoint()
        let bobGeneration = try XCTUnwrap(bobContact.identityGenerationId)
        let aliceBob = try PairwiseInstallationBindingV4.derive(
            localIdentityGenerationId: aliceGeneration,
            localIdentitySigningPublicKey: aliceState.identity.signingKey.publicKeyData,
            localEndpoint: aliceEndpoint,
            peerIdentityGenerationId: bobGeneration,
            peerIdentitySigningPublicKey: bobContact.signingPublicKey,
            peerEndpoint: bobEndpoint
        )
        let outboundSession = try MessageEngine.createOutboundInstallationSession(
            localInstallation: aliceInstallation,
            localEndpoint: aliceEndpoint,
            pairwiseBinding: aliceBob,
            contact: bobContact
        )
        var outbound = outboundSession.conversation

        let unknownControlId = UUID()
        let controlContext = try MessageAuthenticatedContext.directV4(
            eventId: unknownControlId,
            senderEndpoint: aliceEndpoint,
            recipientEndpoint: bobEndpoint,
            pairwiseBinding: aliceBob
        )
        let controlEnvelope = try MessageEngine.encryptDirectV4(
            wirePayload: .control(
                AuthenticatedControlPayloadV2(
                    type: ContentTypeId(
                        authority: "org.noctweave.control",
                        name: "future-policy",
                        major: 1
                    ),
                    encodedPayload: Data("future-control".utf8)
                )
            ),
            senderSigningKey: aliceInstallation.signingKey,
            senderFingerprint: aliceBob.localInstallationHandle.rawValue,
            conversation: &outbound,
            kemCiphertext: outboundSession.kemCiphertext,
            prekey: outboundSession.prekey,
            authenticatedContext: controlContext,
            sentAt: Date()
        )
        _ = try await relayStore.deliver(controlEnvelope, to: bobState.inboxId)
        let controlMessages = try await bob.receive(maxCount: 10)
        XCTAssertTrue(controlMessages.isEmpty)
        let maybeQuarantinedState = try await bob.store.load()
        let quarantinedState = try XCTUnwrap(maybeQuarantinedState)
        XCTAssertEqual(quarantinedState.quarantinedControlEvents.map(\.id), [unknownControlId])
        XCTAssertTrue(quarantinedState.conversations.flatMap(\.messages).isEmpty)

        let unknownEventId = UUID()
        let unknownTransactionId = UUID()
        let eventAt = Date()
        let applicationContext = try MessageAuthenticatedContext.directV4(
            eventId: unknownEventId,
            senderEndpoint: aliceEndpoint,
            recipientEndpoint: bobEndpoint,
            pairwiseBinding: aliceBob
        )
        let unknownEvent = ConversationEvent(
            id: unknownEventId,
            clientTransactionId: unknownTransactionId,
            conversationId: outbound.id,
            authorInstallationHandle: aliceBob.localInstallationHandle,
            createdAt: eventAt,
            kind: .application,
            content: EncodedContent(
                type: ContentTypeId(authority: "example.app", name: "poll", major: 1),
                payload: Data("opaque-poll".utf8),
                fallbackText: "Unsupported poll",
                disposition: .visible
            )
        )
        let applicationEnvelope = try MessageEngine.encryptDirectV4(
            wirePayload: .application(unknownEvent),
            senderSigningKey: aliceInstallation.signingKey,
            senderFingerprint: aliceBob.localInstallationHandle.rawValue,
            conversation: &outbound,
            authenticatedContext: applicationContext,
            sentAt: eventAt
        )
        _ = try await relayStore.deliver(applicationEnvelope, to: bobState.inboxId)
        let received = try await bob.receive(maxCount: 10)
        XCTAssertEqual(received.map(\.body), [.text("Unsupported poll")])
        let maybePersisted = try await bob.store.load()
        let persisted = try XCTUnwrap(maybePersisted)
        let canonicalUnknownEvent = try NoctweaveCoder.decode(
            ConversationEvent.self,
            from: NoctweaveCoder.encode(unknownEvent, sortedKeys: true)
        )
        XCTAssertEqual(
            persisted.relationshipsV2.flatMap(\.events).first { $0.id == unknownEventId },
            canonicalUnknownEvent
        )
        XCTAssertEqual(persisted.quarantinedControlEvents.map(\.id), [unknownControlId])
    }

    func testCertifiedHeadlessContactQuarantinesDowngradeWithoutBlockingLaterEvent() async throws {
        let relayStore = RelayStore()
        let server = RelayServer(store: relayStore)
        let started = expectation(description: "downgrade quarantine relay started")
        var boundPort: UInt16?
        server.onEvent = { event in
            if case .started(let port) = event {
                boundPort = port
                started.fulfill()
            }
        }
        try server.start(host: "127.0.0.1", port: 0)
        await fulfillment(of: [started], timeout: 2)
        let relay = RelayEndpoint(host: "127.0.0.1", port: try XCTUnwrap(boundPort))
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
        let aliceCode = try await alice.exportContactCode()
        let bobCode = try await bob.exportContactCode()
        _ = try await alice.importContactCode(bobCode)
        _ = try await bob.importContactCode(aliceCode)

        let maybeAliceState = try await alice.store.load()
        let maybeBobState = try await bob.store.load()
        let aliceState = try XCTUnwrap(maybeAliceState)
        let bobState = try XCTUnwrap(maybeBobState)
        let bobContact = try XCTUnwrap(aliceState.contacts.first)
        XCTAssertTrue(bobContact.usesCertifiedInstallationEndpoint)
        // Forge a legacy-only projection to model a hostile downgraded sender.
        // Production APIs now reject passing the certified contact itself to
        // legacy session creation, so the test must not rely on that fallback.
        let legacyProjection = Contact(
            id: bobContact.id,
            displayName: bobContact.displayName,
            inboxId: bobContact.inboxId,
            relay: bobContact.relay,
            signingPublicKey: bobContact.signingPublicKey,
            agreementPublicKey: bobContact.agreementPublicKey
        )
        let legacySession = try MessageEngine.createOutboundSession(
            identity: aliceState.identity,
            contact: legacyProjection
        )
        var legacyConversation = legacySession.conversation
        let downgradedEnvelope = try MessageEngine.encrypt(
            body: .text("legacy downgrade"),
            senderSigningKey: aliceState.identity.signingKey,
            senderFingerprint: aliceState.identity.fingerprint,
            conversation: &legacyConversation,
            kemCiphertext: legacySession.kemCiphertext
        )
        _ = try await relayStore.deliver(downgradedEnvelope, to: bobState.inboxId)
        _ = try await alice.sendText(to: "Bob", text: "valid after poison")

        let received = try await bob.receive(maxCount: 10)
        XCTAssertEqual(received.map(\.body), [.text("valid after poison")])
        let maybePersisted = try await bob.store.load()
        let persisted = try XCTUnwrap(maybePersisted)
        XCTAssertEqual(persisted.quarantinedTransportEnvelopesV2.count, 1)
        XCTAssertEqual(
            persisted.quarantinedTransportEnvelopesV2.first?.reason,
            .incompatibleProfile
        )
        XCTAssertFalse(persisted.relationshipsV2.flatMap(\.events).isEmpty)
    }
}

private struct WireEndpointFixture {
    let identity: Identity
    let generationId: UUID
    let installation: LocalInstallationState
    let manifest: InstallationManifest
    let endpoint: CertifiedInstallationEndpoint
    let relay: RelayEndpoint
}

private struct WirePairFixture {
    let alice: WireEndpointFixture
    let bob: WireEndpointFixture
    let aliceContact: Contact
    let bobContact: Contact
    let aliceBob: PairwiseInstallationBindingV4
    let bobAlice: PairwiseInstallationBindingV4
    let outbound: (conversation: Conversation, kemCiphertext: Data, prekey: PrekeyReference)

    func inboundConversation() throws -> Conversation {
        try MessageEngine.createInboundInstallationSession(
            localInstallation: bob.installation,
            localEndpoint: bob.endpoint,
            senderEndpoint: alice.endpoint,
            pairwiseBinding: bobAlice,
            contact: bobContact,
            kemCiphertext: outbound.kemCiphertext,
            prekey: outbound.prekey
        )
    }
}

private func makeWirePair() throws -> WirePairFixture {
    let alice = try makeWireEndpoint("Alice")
    let bob = try makeWireEndpoint("Bob")
    let aliceContact = try MessageEngine.contact(from: makeWireOffer(bob))
    let bobContact = try MessageEngine.contact(from: makeWireOffer(alice))
    let aliceBob = try makeWireBinding(local: alice, peer: bob)
    let bobAlice = try makeWireBinding(local: bob, peer: alice)
    let outbound = try MessageEngine.createOutboundInstallationSession(
        localInstallation: alice.installation,
        localEndpoint: alice.endpoint,
        pairwiseBinding: aliceBob,
        contact: aliceContact
    )
    return WirePairFixture(
        alice: alice,
        bob: bob,
        aliceContact: aliceContact,
        bobContact: bobContact,
        aliceBob: aliceBob,
        bobAlice: bobAlice,
        outbound: outbound
    )
}

private func makeWireEndpoint(_ name: String) throws -> WireEndpointFixture {
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
    return WireEndpointFixture(
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

private func makeWireOffer(_ fixture: WireEndpointFixture) throws -> ContactOffer {
    try ContactOffer.createCertified(
        displayName: fixture.identity.displayName,
        inboxId: "wire-test-\(fixture.identity.fingerprint.prefix(12))",
        relay: fixture.relay,
        identity: fixture.identity,
        identityGenerationId: fixture.generationId,
        installationManifest: fixture.manifest,
        preferredInstallationEndpoint: fixture.endpoint
    )
}

private func makeWireBinding(
    local: WireEndpointFixture,
    peer: WireEndpointFixture
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

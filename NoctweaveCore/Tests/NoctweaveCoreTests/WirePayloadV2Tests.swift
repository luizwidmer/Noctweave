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
        XCTAssertEqual(
            try WirePayloadV2.application(
                makeEvent(valid, EventRelation(kind: .reply, targetEventId: UUID()))
            ).applicationProjection().body,
            .text("canonical text")
        )
        XCTAssertThrowsError(
            try WirePayloadV2.application(
                makeEvent(valid, EventRelation(kind: .reaction, targetEventId: UUID()))
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
            let reply = ConversationEvent(
                conversationId: "conversation",
                authorInstallationHandle: handle,
                createdAt: Date(timeIntervalSince1970: 20_001),
                kind: .application,
                content: try XCTUnwrap(wire.application?.content),
                relation: EventRelation(kind: .reply, targetEventId: UUID())
            )
            XCTAssertEqual(
                try WirePayloadV2.application(reply).applicationProjection().body,
                .attachment(descriptor)
            )
        }
    }

    func testStandardRelationsReceiptsAndTombstonesMatchJavaScriptCanonicalPayloads() throws {
        let handle = RelationshipInstallationHandle(
            rawValue: Data(repeating: 0x52, count: 32).base64EncodedString()
        )
        let target = try XCTUnwrap(UUID(uuidString: "11111111-2222-4333-8444-555555555555"))

        let relationKinds: [EventRelationKind] = [.reply, .replacement, .reference]
        for kind in relationKinds {
            let event = ConversationEvent(
                conversationId: "conversation",
                authorInstallationHandle: handle,
                createdAt: Date(timeIntervalSince1970: 21_100),
                kind: .application,
                content: try XCTUnwrap(EncodedContent.text("revised text")),
                relation: EventRelation(kind: kind, targetEventId: target)
            )
            XCTAssertEqual(
                try WirePayloadV2.application(event).applicationProjection().body,
                .text("revised text")
            )
            XCTAssertNotEqual(event.id, target)
        }

        let reactionContent = try XCTUnwrap(EncodedContent.reaction("👍"))
        XCTAssertEqual(String(data: reactionContent.payload, encoding: .utf8), #"{"value":"👍"}"#)
        XCTAssertEqual(reactionContent.fallbackText, "Reacted 👍 to a message")
        let reactionEvent = ConversationEvent(
            conversationId: "conversation",
            authorInstallationHandle: handle,
            createdAt: Date(timeIntervalSince1970: 21_101),
            kind: .application,
            content: reactionContent,
            relation: EventRelation(kind: .reaction, targetEventId: target)
        )
        XCTAssertEqual(
            try WirePayloadV2.application(reactionEvent).applicationProjection(),
            .reaction(ReactionContentV1(value: "👍"), targetEventId: target)
        )

        let retractionContent = try XCTUnwrap(EncodedContent.retraction(reason: "duplicate"))
        XCTAssertEqual(
            String(data: retractionContent.payload, encoding: .utf8),
            #"{"reason":"duplicate","scope":"received-copies-may-remain"}"#
        )
        XCTAssertEqual(retractionContent.fallbackText, RetractionContentV1.fallbackText)
        let retractionEvent = ConversationEvent(
            conversationId: "conversation",
            authorInstallationHandle: handle,
            createdAt: Date(timeIntervalSince1970: 21_102),
            kind: .application,
            content: retractionContent,
            relation: EventRelation(kind: .retraction, targetEventId: target)
        )
        XCTAssertEqual(
            try WirePayloadV2.application(retractionEvent).applicationProjection(),
            .retraction(RetractionContentV1(reason: "duplicate"), targetEventId: target)
        )
        XCTAssertEqual(
            try WirePayloadV2.application(retractionEvent).applicationProjection().body,
            .text("Message retracted; received copies may remain")
        )

        for (content, isRead) in [
            (try XCTUnwrap(EncodedContent.deliveryReceipt(targetEventId: target)), false),
            (try XCTUnwrap(EncodedContent.readReceipt(targetEventId: target)), true)
        ] {
            XCTAssertEqual(
                String(data: content.payload, encoding: .utf8),
                #"{"targetEventId":"11111111-2222-4333-8444-555555555555"}"#
            )
            let receiptEvent = ConversationEvent(
                conversationId: "conversation",
                authorInstallationHandle: handle,
                createdAt: Date(timeIntervalSince1970: 21_103),
                kind: .receipt,
                content: content
            )
            let projection = try WirePayloadV2.application(receiptEvent).applicationProjection()
            XCTAssertNil(projection.body)
            if isRead {
                XCTAssertEqual(projection, .readReceipt(EventReceiptContentV1(targetEventId: target)))
            } else {
                XCTAssertEqual(projection, .deliveryReceipt(EventReceiptContentV1(targetEventId: target)))
            }
        }
    }

    func testKnownRelationsAndReceiptsFailClosedForNoncanonicalOrCrossFamilyContent() throws {
        let handle = RelationshipInstallationHandle(
            rawValue: Data(repeating: 0x53, count: 32).base64EncodedString()
        )
        let target = UUID()
        let malformedReaction = EncodedContent(
            type: .reaction,
            payload: Data(#"{ "value": "👍" }"#.utf8),
            fallbackText: "Reacted 👍 to a message"
        )
        let reactionEvent = ConversationEvent(
            conversationId: "conversation",
            authorInstallationHandle: handle,
            createdAt: Date(timeIntervalSince1970: 21_200),
            kind: .application,
            content: malformedReaction,
            relation: EventRelation(kind: .reaction, targetEventId: target)
        )
        XCTAssertThrowsError(
            try WirePayloadV2.application(reactionEvent).applicationProjection()
        ) { error in
            XCTAssertEqual(error as? WirePayloadV2Error, .invalidKnownApplicationContent)
        }

        let validReaction = try XCTUnwrap(EncodedContent.reaction("👍"))
        for relation in [
            Optional<EventRelation>.none,
            EventRelation(kind: .reply, targetEventId: target)
        ] {
            let mismatched = ConversationEvent(
                conversationId: "conversation",
                authorInstallationHandle: handle,
                createdAt: Date(timeIntervalSince1970: 21_200),
                kind: .application,
                content: validReaction,
                relation: relation
            )
            XCTAssertThrowsError(try WirePayloadV2.application(mismatched))
        }
        let spoofedReactionRelation = ConversationEvent(
            conversationId: "conversation",
            authorInstallationHandle: handle,
            createdAt: Date(timeIntervalSince1970: 21_200),
            kind: .application,
            content: try XCTUnwrap(EncodedContent.text("not a reaction")),
            relation: EventRelation(kind: .reaction, targetEventId: target)
        )
        XCTAssertThrowsError(try WirePayloadV2.application(spoofedReactionRelation))

        let validRetraction = try XCTUnwrap(EncodedContent.retraction())
        for relation in [
            Optional<EventRelation>.none,
            EventRelation(kind: .reference, targetEventId: target)
        ] {
            let mismatched = ConversationEvent(
                conversationId: "conversation",
                authorInstallationHandle: handle,
                createdAt: Date(timeIntervalSince1970: 21_200),
                kind: .application,
                content: validRetraction,
                relation: relation
            )
            XCTAssertThrowsError(try WirePayloadV2.application(mismatched))
        }
        let spoofedRetractionRelation = ConversationEvent(
            conversationId: "conversation",
            authorInstallationHandle: handle,
            createdAt: Date(timeIntervalSince1970: 21_200),
            kind: .application,
            content: try XCTUnwrap(EncodedContent.text("not a retraction")),
            relation: EventRelation(kind: .retraction, targetEventId: target)
        )
        XCTAssertThrowsError(try WirePayloadV2.application(spoofedRetractionRelation))

        let selfTargeting = ConversationEvent(
            id: target,
            conversationId: "conversation",
            authorInstallationHandle: handle,
            createdAt: Date(timeIntervalSince1970: 21_201),
            kind: .application,
            content: try XCTUnwrap(EncodedContent.text("invalid self edit")),
            relation: EventRelation(kind: .replacement, targetEventId: target)
        )
        XCTAssertThrowsError(try WirePayloadV2.application(selfTargeting))

        let visibleReceipt = EncodedContent(
            type: .readReceipt,
            payload: try NoctweaveCoder.encode(EventReceiptContentV1(targetEventId: target)),
            fallbackText: "Read",
            disposition: .visible
        )
        let invalidReceipt = ConversationEvent(
            conversationId: "conversation",
            authorInstallationHandle: handle,
            createdAt: Date(timeIntervalSince1970: 21_202),
            kind: .receipt,
            content: visibleReceipt
        )
        XCTAssertThrowsError(try WirePayloadV2.application(invalidReceipt))

        XCTAssertNil(EncodedContent.reaction("bad\u{0000}reaction"))
        XCTAssertNil(EncodedContent.retraction(reason: "bad\u{0000}reason"))
        let outOfRange = ConversationEvent(
            conversationId: "conversation",
            authorInstallationHandle: handle,
            createdAt: Date(timeIntervalSince1970: 4_102_444_801),
            kind: .application,
            content: try XCTUnwrap(EncodedContent.text("future"))
        )
        XCTAssertThrowsError(try WirePayloadV2.application(outOfRange))
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
            kind: .application,
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

    func testGroupAndDirectPaddingFramesAreMutuallyIsolated() throws {
        let group = try PaddedMessagePlaintext.encodeGroupMessageBody(.text("group"))
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

        XCTAssertThrowsError(try PaddedMessagePlaintext.decodeWirePayloadV2(group))
        XCTAssertThrowsError(try PaddedMessagePlaintext.decodeGroupMessageBody(typed))
        XCTAssertEqual(try PaddedMessagePlaintext.decodeGroupMessageBody(group), .text("group"))
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

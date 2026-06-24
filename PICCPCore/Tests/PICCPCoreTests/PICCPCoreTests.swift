import XCTest
@testable import PICCPCore

final class PICCPCoreTests: XCTestCase {
    func testPublicRelayEndpointPolicyRejectsIPv6TransitionPrivateTargets() {
        let endpoints = [
            RelayEndpoint(host: "64:ff9b::7f00:1", port: 443, useTLS: true),
            RelayEndpoint(host: "64:ff9b::0a00:1", port: 443, useTLS: true),
            RelayEndpoint(host: "2002:0a00:0001::1", port: 443, useTLS: true),
            RelayEndpoint(host: "2001:0000:4136:e378:8000:63bf:3fff:fdd2", port: 443, useTLS: true)
        ]

        for endpoint in endpoints {
            XCTAssertFalse(
                PublicRelayEndpointPolicy.permits(endpoint),
                "Expected public endpoint policy to reject \(endpoint.host)"
            )
        }
    }

    func testOpenFederationDHTRecordValidatesSignedRelayAdvertisement() throws {
        let signingKey = SigningKeyPair()
        let endpoint = RelayEndpoint(
            host: "relay.example.org",
            port: 443,
            useTLS: true,
            transport: .websocket
        )
        let record = try OpenFederationDHTRecord.signed(
            endpoint: endpoint,
            federationName: "Example Open Net",
            signingKey: signingKey
        )

        XCTAssertNoThrow(
            try record.validate(
                expectedFederationName: "example open net",
                requirePublicEndpoint: false
            )
        )
        XCTAssertEqual(record.signatureAlgorithm, OpenFederationDHTRecord.signatureAlgorithm)
        XCTAssertEqual(
            record.relayIdentityDigest,
            OpenFederationDHTRecord.relayIdentityDigest(publicKey: signingKey.publicKeyData)
        )
    }

    func testOpenFederationDHTRecordRejectsTamperedEndpoint() throws {
        let signingKey = SigningKeyPair()
        let record = try OpenFederationDHTRecord.signed(
            endpoint: RelayEndpoint(host: "relay.example.org", port: 443, useTLS: true, transport: .websocket),
            federationName: "poison-test",
            signingKey: signingKey
        )
        let tampered = OpenFederationDHTRecord(
            namespace: record.namespace,
            relayIdentityDigest: record.relayIdentityDigest,
            endpoint: RelayEndpoint(host: "evil.example.org", port: 443, useTLS: true, transport: .websocket),
            federationName: record.federationName,
            issuedAt: record.issuedAt,
            expiresAt: record.expiresAt,
            relaySigningPublicKey: record.relaySigningPublicKey,
            signature: record.signature
        )

        XCTAssertThrowsError(
            try tampered.validate(expectedFederationName: "poison-test", requirePublicEndpoint: false)
        ) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .invalidSignature)
        }
    }

    func testOpenFederationDHTRecordRejectsNamespaceMismatch() throws {
        let record = try OpenFederationDHTRecord.signed(
            endpoint: RelayEndpoint(host: "relay.example.org", port: 443, useTLS: true, transport: .websocket),
            federationName: "one-open-net",
            signingKey: SigningKeyPair()
        )

        XCTAssertThrowsError(
            try record.validate(expectedFederationName: "other-open-net", requirePublicEndpoint: false)
        ) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .namespaceMismatch)
        }
    }

    func testOpenFederationDHTRecordRejectsExpiredAndOverlongRecords() throws {
        let signingKey = SigningKeyPair()
        let endpoint = RelayEndpoint(host: "relay.example.org", port: 443, useTLS: true, transport: .websocket)
        let expired = try OpenFederationDHTRecord.signed(
            endpoint: endpoint,
            federationName: "expiry-test",
            signingKey: signingKey,
            issuedAt: Date(timeIntervalSince1970: 100),
            lifetimeSeconds: 60
        )
        XCTAssertThrowsError(
            try expired.validate(expectedFederationName: "expiry-test", now: Date(), requirePublicEndpoint: false)
        ) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .expired)
        }

        let overlong = OpenFederationDHTRecord(
            namespace: OpenFederationDHTRecord.namespace(federationName: "expiry-test"),
            relayIdentityDigest: OpenFederationDHTRecord.relayIdentityDigest(publicKey: signingKey.publicKeyData),
            endpoint: endpoint,
            federationName: "expiry-test",
            issuedAt: Date(timeIntervalSince1970: 100),
            expiresAt: Date(timeIntervalSince1970: 10_000),
            relaySigningPublicKey: signingKey.publicKeyData,
            signature: Data()
        )
        let signedOverlong = OpenFederationDHTRecord(
            namespace: overlong.namespace,
            relayIdentityDigest: overlong.relayIdentityDigest,
            endpoint: overlong.endpoint,
            federationName: overlong.federationName,
            issuedAt: overlong.issuedAt,
            expiresAt: overlong.expiresAt,
            relaySigningPublicKey: overlong.relaySigningPublicKey,
            signature: try signingKey.sign(PICCPCoder.encode(
                [
                    "endpoint": "force-invalid-signature-for-overlong-record"
                ],
                sortedKeys: true
            ))
        )
        XCTAssertThrowsError(
            try signedOverlong.validate(
                expectedFederationName: "expiry-test",
                now: Date(timeIntervalSince1970: 200),
                requirePublicEndpoint: false
            )
        ) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .invalidLifetime)
        }
    }

    func testOpenFederationDHTRecordRequiresSecureHttpOrWebSocketEndpoint() throws {
        let record = try OpenFederationDHTRecord.signed(
            endpoint: RelayEndpoint(host: "relay.example.org", port: 9339, useTLS: false, transport: .tcp),
            federationName: "secure-only",
            signingKey: SigningKeyPair()
        )

        XCTAssertThrowsError(
            try record.validate(expectedFederationName: "secure-only", requirePublicEndpoint: false)
        ) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .insecureEndpoint)
        }
    }

    func testContactOfferCodeRoundTrip() throws {
        let identity = Identity(displayName: "Alice")
        let relay = RelayEndpoint(host: "localhost", port: 9339)
        let offer = try MessageEngine.makeContactOffer(identity: identity, inboxId: "inbox-1", relay: relay)
        let code = try ContactOfferCode.encode(offer)
        let decoded = try ContactOfferCode.decode(code)
        XCTAssertEqual(decoded, offer)
    }

    func testContactOfferBindsInboxAccessKey() throws {
        let identity = Identity(displayName: "Alice")
        let accessKey = SigningKeyPair()
        let relay = RelayEndpoint(host: "localhost", port: 9339)
        let offer = try MessageEngine.makeContactOffer(
            identity: identity,
            inboxId: "inbox-1",
            relay: relay,
            inboxAccessPublicKey: accessKey.publicKeyData
        )

        XCTAssertEqual(offer.version, 3)
        XCTAssertEqual(offer.inboxAccessPublicKey, accessKey.publicKeyData)
        XCTAssertNoThrow(try offer.verified())
    }

    func testInboxAddressIsDerivedFromAccessKey() {
        let accessKey = SigningKeyPair()
        let address = InboxAddress.derived(from: accessKey.publicKeyData)

        XCTAssertTrue(InboxAddress.isValid(address))
        XCTAssertTrue(InboxAddress.isBound(address, to: accessKey.publicKeyData))
        XCTAssertFalse(InboxAddress.isBound(address, to: SigningKeyPair().publicKeyData))
    }

    func testContactShareRoundTrip() throws {
        let identity = Identity(displayName: "Alice")
        let relay = RelayEndpoint(host: "localhost", port: 9339)
        let offer = try MessageEngine.makeContactOffer(identity: identity, inboxId: "inbox-1", relay: relay)
        let data = try ContactShare.encode(offer, password: "correct horse")
        let decoded = try ContactShare.decode(data, password: "correct horse")
        XCTAssertEqual(decoded, offer)
    }

    func testContactShareWrongPasswordFails() throws {
        let identity = Identity(displayName: "Alice")
        let relay = RelayEndpoint(host: "localhost", port: 9339)
        let offer = try MessageEngine.makeContactOffer(identity: identity, inboxId: "inbox-1", relay: relay)
        let data = try ContactShare.encode(offer, password: "secret")
        XCTAssertThrowsError(try ContactShare.decode(data, password: "wrong password"))
    }

    func testContactOfferCodeRejectsTamperedPayload() throws {
        let identity = Identity(displayName: "Alice")
        let relay = RelayEndpoint(host: "localhost", port: 9339)
        let offer = try MessageEngine.makeContactOffer(identity: identity, inboxId: "inbox-1", relay: relay)
        let code = try ContactOfferCode.encode(offer)
        let data = try XCTUnwrap(Data(base64Encoded: code))
        var tampered = try PICCPCoder.decode(ContactOffer.self, from: data)
        tampered = ContactOffer(
            version: tampered.version,
            displayName: "Mallory",
            inboxId: tampered.inboxId,
            relay: tampered.relay,
            signingPublicKey: tampered.signingPublicKey,
            agreementPublicKey: tampered.agreementPublicKey,
            fingerprint: tampered.fingerprint,
            signature: tampered.signature
        )
        let tamperedCode = try PICCPCoder.encode(tampered).base64EncodedString()
        XCTAssertThrowsError(try ContactOfferCode.decode(tamperedCode))
    }

    func testContactSafetyNumberIsSymmetricAndIdentityBound() {
        let aliceToBob = ContactSafetyNumber.make(
            localFingerprint: "alice-fingerprint",
            remoteFingerprint: "bob-fingerprint"
        )
        let bobToAlice = ContactSafetyNumber.make(
            localFingerprint: "bob-fingerprint",
            remoteFingerprint: "alice-fingerprint"
        )
        let aliceToMallory = ContactSafetyNumber.make(
            localFingerprint: "alice-fingerprint",
            remoteFingerprint: "mallory-fingerprint"
        )

        XCTAssertEqual(aliceToBob, bobToAlice)
        XCTAssertNotEqual(aliceToBob, aliceToMallory)
        XCTAssertEqual(aliceToBob.split(separator: " ").count, 12)
    }

    func testOneTimePrekeySignatureRejectsRelaySubstitution() throws {
        let identity = Identity(displayName: "Alice")
        let prekeys = try PrekeyState.generate(identity: identity, oneTimeCount: 1)
        let bundle = try prekeys.bundle(identity: identity)
        let original = try XCTUnwrap(bundle.oneTimePrekeys.first)

        XCTAssertTrue(original.verify(using: identity.signingKey.publicKeyData))

        let substituted = OneTimePrekey(
            id: original.id,
            publicKey: AgreementKeyPair().publicKeyData,
            signature: original.signature
        )
        XCTAssertFalse(substituted.verify(using: identity.signingKey.publicKeyData))
    }

    func testLegacyUnsignedOneTimePrekeyLoadsButFailsClosed() throws {
        struct LegacyOneTimePrekey: Codable {
            let id: UUID
            let publicKey: Data
        }

        let legacy = LegacyOneTimePrekey(
            id: UUID(),
            publicKey: AgreementKeyPair().publicKeyData
        )
        let data = try PICCPCoder.encode(legacy)
        let decoded = try PICCPCoder.decode(OneTimePrekey.self, from: data)

        XCTAssertTrue(decoded.signature.isEmpty)
        XCTAssertFalse(decoded.verify(using: SigningKeyPair().publicKeyData))
    }

    func testConversationBootstrapKeysMatch() throws {
        let alice = Identity(displayName: "Alice")
        let bob = Identity(displayName: "Bob")
        let bobContact = Contact(
            displayName: bob.displayName,
            inboxId: "bob-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: bob.signingKey.publicKeyData,
            agreementPublicKey: bob.agreementKey.publicKeyData
        )
        let aliceContact = Contact(
            displayName: alice.displayName,
            inboxId: "alice-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: alice.signingKey.publicKeyData,
            agreementPublicKey: alice.agreementKey.publicKeyData
        )

        let session = try MessageEngine.createOutboundSession(identity: alice, contact: bobContact)
        var aliceConversation = session.conversation
        var bobConversation = try MessageEngine.createInboundSession(identity: bob, contact: aliceContact, kemCiphertext: session.kemCiphertext)

        let (aliceCounter, aliceKey) = try aliceConversation.sendChain.nextMessageKey()
        let bobKey = try bobConversation.receiveChain.messageKey(for: aliceCounter)

        XCTAssertEqual(aliceKey.dataRepresentation, bobKey.dataRepresentation)
    }

    func testRatchetStateTransitions() throws {
        let alice = Identity(displayName: "Alice")
        let bob = Identity(displayName: "Bob")
        let bobContact = Contact(
            displayName: bob.displayName,
            inboxId: "bob-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: bob.signingKey.publicKeyData,
            agreementPublicKey: bob.agreementKey.publicKeyData
        )
        let session = try MessageEngine.createOutboundSession(identity: alice, contact: bobContact)
        var conversation = session.conversation

        XCTAssertEqual(conversation.ratchetState, .initializing)
        conversation.markMessageProcessed()
        XCTAssertEqual(conversation.ratchetState, .active)
        XCTAssertTrue(conversation.transition(to: .reset))
        XCTAssertEqual(conversation.ratchetState, .reset)
        conversation.markMessageProcessed()
        XCTAssertEqual(conversation.ratchetState, .healed)
        XCTAssertFalse(conversation.transition(to: .active))
        XCTAssertEqual(conversation.ratchetState, .healed)
    }

    func testOutOfOrderMessagesWithinWindow() throws {
        let alice = Identity(displayName: "Alice")
        let bob = Identity(displayName: "Bob")
        let bobContact = Contact(
            displayName: "Bob",
            inboxId: "bob-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: bob.signingKey.publicKeyData,
            agreementPublicKey: bob.agreementKey.publicKeyData
        )
        let aliceContact = Contact(
            displayName: "Alice",
            inboxId: "alice-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: alice.signingKey.publicKeyData,
            agreementPublicKey: alice.agreementKey.publicKeyData
        )

        let session = try MessageEngine.createOutboundSession(identity: alice, contact: bobContact)
        var aliceConversation = session.conversation
        var bobConversation = try MessageEngine.createInboundSession(
            identity: bob,
            contact: aliceContact,
            kemCiphertext: session.kemCiphertext
        )

        let count = 20
        var envelopes: [Envelope] = []
        for index in 0..<count {
            let envelope = try MessageEngine.encrypt(
                body: .text("msg-\(index)"),
                senderSigningKey: alice.signingKey,
                senderFingerprint: alice.fingerprint,
                conversation: &aliceConversation,
                kemCiphertext: index == 0 ? session.kemCiphertext : nil
            )
            envelopes.append(envelope)
        }

        var order = Array(0..<count)
        order.swapAt(1, 2)
        order.swapAt(5, 7)
        order.shuffle()

        var received: [String] = []
        for index in order {
            let body = try MessageEngine.decrypt(
                envelope: envelopes[index],
                contact: aliceContact,
                conversation: &bobConversation
            )
            if case .text(let text) = body {
                received.append(text)
            }
        }
        XCTAssertEqual(received.count, count)
        XCTAssertEqual(Set(received), Set((0..<count).map { "msg-\($0)" }))
    }

    func testReplayIsRejected() throws {
        let alice = Identity(displayName: "Alice")
        let bob = Identity(displayName: "Bob")
        let bobContact = Contact(
            displayName: "Bob",
            inboxId: "bob-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: bob.signingKey.publicKeyData,
            agreementPublicKey: bob.agreementKey.publicKeyData
        )
        let aliceContact = Contact(
            displayName: "Alice",
            inboxId: "alice-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: alice.signingKey.publicKeyData,
            agreementPublicKey: alice.agreementKey.publicKeyData
        )
        let session = try MessageEngine.createOutboundSession(identity: alice, contact: bobContact)
        var aliceConversation = session.conversation
        var bobConversation = try MessageEngine.createInboundSession(
            identity: bob,
            contact: aliceContact,
            kemCiphertext: session.kemCiphertext
        )

        let envelope = try MessageEngine.encrypt(
            body: .text("once"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            conversation: &aliceConversation,
            kemCiphertext: session.kemCiphertext
        )
        _ = try MessageEngine.decrypt(
            envelope: envelope,
            contact: aliceContact,
            conversation: &bobConversation
        )

        XCTAssertThrowsError(
            try MessageEngine.decrypt(
                envelope: envelope,
                contact: aliceContact,
                conversation: &bobConversation
            )
        ) { error in
            XCTAssertEqual(error as? CryptoError, .counterReplay)
        }
    }

    func testCounterWindowExceeded() throws {
        let alice = Identity(displayName: "Alice")
        let bob = Identity(displayName: "Bob")
        let bobContact = Contact(
            displayName: "Bob",
            inboxId: "bob-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: bob.signingKey.publicKeyData,
            agreementPublicKey: bob.agreementKey.publicKeyData
        )
        let aliceContact = Contact(
            displayName: "Alice",
            inboxId: "alice-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: alice.signingKey.publicKeyData,
            agreementPublicKey: alice.agreementKey.publicKeyData
        )
        let session = try MessageEngine.createOutboundSession(identity: alice, contact: bobContact)
        var aliceConversation = session.conversation
        var bobConversation = try MessageEngine.createInboundSession(
            identity: bob,
            contact: aliceContact,
            kemCiphertext: session.kemCiphertext
        )

        let target = Int(ChainKeyState.defaultMaxSkip + 5)
        var envelopes: [Envelope] = []
        for index in 0..<target {
            let envelope = try MessageEngine.encrypt(
                body: .text("msg-\(index)"),
                senderSigningKey: alice.signingKey,
                senderFingerprint: alice.fingerprint,
                conversation: &aliceConversation,
                kemCiphertext: index == 0 ? session.kemCiphertext : nil
            )
            envelopes.append(envelope)
        }

        let farEnvelope = envelopes.last!
        XCTAssertThrowsError(
            try MessageEngine.decrypt(
                envelope: farEnvelope,
                contact: aliceContact,
                conversation: &bobConversation
            )
        ) { error in
            XCTAssertEqual(error as? CryptoError, .counterWindowExceeded)
        }
    }

    func testMessageEncryptDecryptRoundTrip() throws {
        let alice = Identity(displayName: "Alice")
        let bob = Identity(displayName: "Bob")
        let bobContact = Contact(
            displayName: "Bob",
            inboxId: "bob-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: bob.signingKey.publicKeyData,
            agreementPublicKey: bob.agreementKey.publicKeyData
        )
        let session = try MessageEngine.createOutboundSession(identity: alice, contact: bobContact)
        var aliceConversation = session.conversation

        let aliceContact = Contact(
            displayName: "Alice",
            inboxId: "alice-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: alice.signingKey.publicKeyData,
            agreementPublicKey: alice.agreementKey.publicKeyData
        )
        var bobConversation = try MessageEngine.createInboundSession(identity: bob, contact: aliceContact, kemCiphertext: session.kemCiphertext)

        let envelope = try MessageEngine.encrypt(
            body: .text("Hello"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            conversation: &aliceConversation,
            kemCiphertext: session.kemCiphertext
        )

        let body = try MessageEngine.decrypt(
            envelope: envelope,
            contact: aliceContact,
            conversation: &bobConversation
        )

        XCTAssertEqual(body, .text("Hello"))
    }

    func testPostQuantumOperationsRejectMalformedBufferLengths() throws {
        XCTAssertThrowsError(
            try SigningKeyPair(
                privateKeyData: Data([0x01]),
                publicKeyData: Data([0x02])
            )
        )
        XCTAssertFalse(
            SigningKeyPair.verify(
                signature: Data([0x01]),
                data: Data("message".utf8),
                publicKeyData: Data([0x02])
            )
        )
        XCTAssertThrowsError(
            try AgreementKeyPair.encapsulate(to: Data([0x01]))
        )

        let validAgreementKey = AgreementKeyPair()
        XCTAssertThrowsError(
            try validAgreementKey.decapsulate(ciphertext: Data([0x01]))
        )
    }

    func testIdentityRotationVerification() throws {
        var identity = Identity(displayName: "Alice")
        let oldSigningKey = identity.signingKey
        let rotation = try identity.rotateKeys().rotation
        XCTAssertTrue(rotation.verify(using: oldSigningKey.publicKeyData))
        XCTAssertFalse(rotation.verify(using: identity.signingKey.publicKeyData))
    }

    func testIdentityRotationBootstrapSessionAllowsPostRotationMessages() throws {
        var alice = Identity(displayName: "Alice")
        let bob = Identity(displayName: "Bob")

        let bobContact = Contact(
            displayName: "Bob",
            inboxId: "bob-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: bob.signingKey.publicKeyData,
            agreementPublicKey: bob.agreementKey.publicKeyData
        )
        var aliceContact = Contact(
            displayName: "Alice",
            inboxId: "alice-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: alice.signingKey.publicKeyData,
            agreementPublicKey: alice.agreementKey.publicKeyData
        )

        let initialSession = try MessageEngine.createOutboundSession(identity: alice, contact: bobContact)
        var aliceConversation = initialSession.conversation
        var bobConversation = try MessageEngine.createInboundSession(
            identity: bob,
            contact: aliceContact,
            kemCiphertext: initialSession.kemCiphertext
        )

        let beforeEnvelope = try MessageEngine.encrypt(
            body: .text("before-rotation"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            conversation: &aliceConversation
        )
        let beforeBody = try MessageEngine.decrypt(
            envelope: beforeEnvelope,
            contact: aliceContact,
            conversation: &bobConversation
        )
        XCTAssertEqual(beforeBody, .text("before-rotation"))

        var previousAlice = alice
        let rotationContext = try alice.rotateKeys()
        previousAlice.signingKey = rotationContext.oldSigningKey
        previousAlice.agreementKey = rotationContext.oldAgreementKey

        let bootstrapSession = try MessageEngine.createOutboundSession(identity: previousAlice, contact: bobContact)
        var bootstrapConversation = bootstrapSession.conversation
        let rotationEnvelope = try MessageEngine.encrypt(
            body: .identityRotation(rotationContext.rotation),
            senderSigningKey: rotationContext.oldSigningKey,
            senderFingerprint: rotationContext.oldFingerprint,
            conversation: &bootstrapConversation,
            kemCiphertext: bootstrapSession.kemCiphertext
        )
        bootstrapConversation.markMessageProcessed()

        XCTAssertThrowsError(
            try MessageEngine.decrypt(
                envelope: rotationEnvelope,
                contact: aliceContact,
                conversation: &bobConversation
            )
        ) { error in
            XCTAssertEqual(error as? CryptoError, .invalidPayload)
        }

        bobConversation = try MessageEngine.createInboundSession(
            identity: bob,
            contact: aliceContact,
            kemCiphertext: bootstrapSession.kemCiphertext
        )
        let rotationBody = try MessageEngine.decrypt(
            envelope: rotationEnvelope,
            contact: aliceContact,
            conversation: &bobConversation
        )
        guard case .identityRotation(let rotation) = rotationBody else {
            return XCTFail("Expected identity rotation payload")
        }
        XCTAssertTrue(aliceContact.apply(rotation: rotation))
        XCTAssertEqual(aliceContact.signingPublicKey, alice.signingKey.publicKeyData)

        bootstrapConversation.messages = aliceConversation.messages
        bootstrapConversation.unreadCount = aliceConversation.unreadCount
        aliceConversation = bootstrapConversation

        let afterEnvelope = try MessageEngine.encrypt(
            body: .text("after-rotation"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            conversation: &aliceConversation
        )
        let afterBody = try MessageEngine.decrypt(
            envelope: afterEnvelope,
            contact: aliceContact,
            conversation: &bobConversation
        )
        XCTAssertEqual(afterBody, .text("after-rotation"))
    }

    func testRootRatchetRoundTrip() throws {
        let alice = Identity(displayName: "Alice")
        let bob = Identity(displayName: "Bob")
        let bobContact = Contact(
            displayName: "Bob",
            inboxId: "bob",
            relay: RelayEndpoint(host: "localhost", port: 0),
            signingPublicKey: bob.signingKey.publicKeyData,
            agreementPublicKey: bob.agreementKey.publicKeyData
        )
        let aliceContact = Contact(
            displayName: "Alice",
            inboxId: "alice",
            relay: RelayEndpoint(host: "localhost", port: 0),
            signingPublicKey: alice.signingKey.publicKeyData,
            agreementPublicKey: alice.agreementKey.publicKeyData
        )

        let session = try MessageEngine.createOutboundSession(identity: alice, contact: bobContact)
        var aliceConversation = session.conversation
        var bobConversation = try MessageEngine.createInboundSession(
            identity: bob,
            contact: aliceContact,
            kemCiphertext: session.kemCiphertext
        )
        let originalSessionId = aliceConversation.sessionId

        let ratchetContext = try MessageEngine.createRootRatchet(contact: bobContact, conversation: aliceConversation)
        let envelope = try MessageEngine.encrypt(
            body: .text("Root ratchet"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            conversation: &aliceConversation,
            rootRatchet: ratchetContext.ratchet
        )
        MessageEngine.applyRootRatchet(
            sharedSecret: ratchetContext.sharedSecret,
            counter: ratchetContext.ratchet.counter,
            identity: alice,
            contact: bobContact,
            conversation: &aliceConversation
        )

        let body = try MessageEngine.decrypt(
            envelope: envelope,
            contact: aliceContact,
            conversation: &bobConversation
        )
        XCTAssertEqual(body, .text("Root ratchet"))

        let bobSecret = try bob.agreementKey.decapsulate(ciphertext: ratchetContext.ratchet.kemCiphertext)
        MessageEngine.applyRootRatchet(
            sharedSecret: bobSecret,
            counter: ratchetContext.ratchet.counter,
            identity: bob,
            contact: aliceContact,
            conversation: &bobConversation
        )

        XCTAssertEqual(aliceConversation.rootCounter, 1)
        XCTAssertEqual(bobConversation.rootCounter, 1)
        XCTAssertNotEqual(aliceConversation.sessionId, originalSessionId)

        let followUp = try MessageEngine.encrypt(
            body: .text("After ratchet"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            conversation: &aliceConversation
        )
        let followUpBody = try MessageEngine.decrypt(
            envelope: followUp,
            contact: aliceContact,
            conversation: &bobConversation
        )
        XCTAssertEqual(followUpBody, .text("After ratchet"))
    }

    func testRelayStoreDeliverFetch() async throws {
        let store = RelayStore()
        let envelope = Envelope(
            conversationId: "conv",
            senderFingerprint: "fingerprint",
            sentAt: Date(),
            messageCounter: 0,
            payload: EncryptedPayload(nonce: Data(), ciphertext: Data([1, 2, 3]), tag: Data()),
            signature: Data([4, 5, 6])
        )

        let count = try await store.deliver(envelope, to: "inbox")
        XCTAssertEqual(count, 1)

        let fetched = try await store.fetch(inboxId: "inbox")
        XCTAssertEqual(fetched, [envelope])
        _ = try await store.acknowledge(inboxId: "inbox", messageIds: [envelope.id])

        let empty = try await store.fetch(inboxId: "inbox")
        XCTAssertEqual(empty.count, 0)
    }

    func testRelayStoreInboxLimitIsEnforced() async throws {
        let store = RelayStore(maxInboxMessages: 1)
        let envelope = Envelope(
            conversationId: "bounded-inbox",
            senderFingerprint: "fingerprint",
            sentAt: Date(),
            messageCounter: 0,
            payload: EncryptedPayload(nonce: Data(), ciphertext: Data([1]), tag: Data()),
            signature: Data([2])
        )

        _ = try await store.deliver(envelope, to: "inbox")
        do {
            _ = try await store.deliver(envelope, to: "inbox")
            XCTFail("Expected inbox capacity to be enforced.")
        } catch RelayStoreError.inboxFull {
            // Expected.
        }
    }

    func testRelayRejectsPrekeyUploadWithoutIdentityProof() async throws {
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: 39488)
        let server = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: RelayConfiguration()
        )
        let started = expectation(description: "prekey proof relay started")
        server.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try server.start(host: "0.0.0.0", port: endpoint.port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let identity = Identity(displayName: "Prekey Owner")
        let prekeys = try PrekeyState.generate(identity: identity)
        let request = UploadPrekeyBundleRequest(
            fingerprint: identity.fingerprint,
            bundle: try prekeys.bundle(identity: identity)
        )
        let response = try await RelayClient(endpoint: endpoint).send(.uploadPrekeys(request))

        XCTAssertEqual(response.type, .error)
        XCTAssertTrue((response.error ?? "").localizedCaseInsensitiveContains("proof"))
    }

    func testRelayAcceptsPrekeyUploadWithValidIdentityProof() async throws {
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: 39489)
        let server = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: RelayConfiguration()
        )
        let started = expectation(description: "signed prekey relay started")
        server.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try server.start(host: "0.0.0.0", port: endpoint.port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let identity = Identity(displayName: "Prekey Owner")
        let prekeys = try PrekeyState.generate(identity: identity)
        let bundle = try prekeys.bundle(identity: identity)
        let unsigned = UploadPrekeyBundleRequest(
            fingerprint: identity.fingerprint,
            bundle: bundle
        )
        let signedAt = Date()
        let nonce = UUID()
        let placeholder = RelayActorProof(
            fingerprint: identity.fingerprint,
            publicSigningKey: identity.signingKey.publicKeyData,
            signedAt: signedAt,
            nonce: nonce,
            signature: Data()
        )
        let signature = try identity.signingKey.sign(unsigned.signableData(for: placeholder))
        let proof = RelayActorProof(
            fingerprint: identity.fingerprint,
            publicSigningKey: identity.signingKey.publicKeyData,
            signedAt: signedAt,
            nonce: nonce,
            signature: signature
        )
        let request = UploadPrekeyBundleRequest(
            fingerprint: identity.fingerprint,
            bundle: bundle,
            actorProof: proof
        )
        let client = RelayClient(endpoint: endpoint)
        let upload = try await client.send(.uploadPrekeys(request))
        XCTAssertEqual(upload.type, .ok)

        let fetched = try await client.send(
            .fetchPrekeyBundle(FetchPrekeyBundleRequest(fingerprint: identity.fingerprint))
        )
        XCTAssertEqual(fetched.type, .prekeyBundle)
        XCTAssertEqual(fetched.prekeyBundle?.identityFingerprint, identity.fingerprint)
    }

    func testRelayStoreAttachmentRoundTrip() async throws {
        let store = RelayStore()
        let attachmentId = UUID()
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0xA5, count: 12),
            ciphertext: Data([2, 3]),
            tag: Data(repeating: 0x5A, count: 16)
        )

        _ = try await store.storeAttachment(
            attachmentId: attachmentId,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: 60
        )

        let fetched = try await store.fetchAttachment(attachmentId: attachmentId, chunkIndex: 0)
        XCTAssertEqual(fetched?.payload, payload)
    }

    func testRelayStoreDiskPersistenceUsesSQLite() async throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        let requestedURL = tempDirectory.appendingPathComponent("relay_store.json")
        let sqliteURL = tempDirectory.appendingPathComponent("relay_store.sqlite")
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let store = RelayStore(storeURL: requestedURL)
        let envelope = Envelope(
            conversationId: "conv",
            senderFingerprint: "fingerprint",
            sentAt: Date(),
            messageCounter: 0,
            payload: EncryptedPayload(
                nonce: Data(),
                ciphertext: Data([0x11, 0x22]),
                tag: Data()
            ),
            signature: Data([0x33, 0x44])
        )

        _ = try await store.deliver(envelope, to: "sqlite-inbox")
        XCTAssertTrue(FileManager.default.fileExists(atPath: sqliteURL.path))
        let sqliteHeader = try Data(contentsOf: sqliteURL).prefix(16)
        XCTAssertEqual(Data("SQLite format 3\0".utf8), Data(sqliteHeader))

        let reloaded = RelayStore(storeURL: requestedURL)
        try await reloaded.loadFromDisk()
        let fetched = try await reloaded.fetch(inboxId: "sqlite-inbox")
        XCTAssertEqual(fetched.count, 1)
        XCTAssertEqual(fetched.first?.id, envelope.id)
        XCTAssertEqual(fetched.first?.conversationId, envelope.conversationId)
        XCTAssertEqual(fetched.first?.senderFingerprint, envelope.senderFingerprint)
        XCTAssertEqual(fetched.first?.messageCounter, envelope.messageCounter)
        XCTAssertEqual(fetched.first?.kemCiphertext, envelope.kemCiphertext)
        XCTAssertEqual(fetched.first?.payload, envelope.payload)
        XCTAssertEqual(fetched.first?.signature, envelope.signature)
    }

    func testRelayStoreRejectsInvalidAttachmentPayload() async throws {
        let store = RelayStore()
        let attachmentId = UUID()
        let payload = EncryptedPayload(
            nonce: Data([1]),
            ciphertext: Data([2, 3]),
            tag: Data([4])
        )

        do {
            _ = try await store.storeAttachment(
                attachmentId: attachmentId,
                chunkIndex: 0,
                payload: payload,
                ttlSeconds: 60
            )
            XCTFail("Expected invalid attachment payload to be rejected.")
        } catch RelayStoreError.invalidAttachmentPayload {
            // Expected.
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testClientStateStoreSaveLoad() async throws {
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let fileURL = temp.appendingPathComponent("state.json")
        let store = ClientStateStore(fileURL: fileURL, useEncryption: false)

        let state = ClientState(
            identity: Identity(displayName: "Alice"),
            relay: RelayEndpoint(host: "localhost", port: 9339),
            inboxId: "inbox"
        )

        try await store.save(state)
        let loaded = try await store.load()
        XCTAssertEqual(loaded?.inboxId, state.inboxId)
        XCTAssertEqual(loaded?.identity.displayName, state.identity.displayName)
    }

    func testClientStateStoreEncryptionProtectsPayload() async throws {
        #if canImport(Security)
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let fileURL = temp.appendingPathComponent("state.json")
        let store = ClientStateStore(fileURL: fileURL, useEncryption: true)

        let state = ClientState(
            identity: Identity(displayName: "Alice"),
            relay: RelayEndpoint(host: "localhost", port: 9339),
            inboxId: "inbox"
        )

        try await store.save(state)
        let rawData = try Data(contentsOf: fileURL)
        let rawString = String(data: rawData, encoding: .utf8) ?? ""
        XCTAssertFalse(rawString.contains("Alice"))
        XCTAssertFalse(rawString.contains("inbox"))
        XCTAssertFalse(rawString.contains("identity"))

        let loaded = try await store.load()
        XCTAssertEqual(loaded?.identity.displayName, "Alice")
        XCTAssertEqual(loaded?.inboxId, "inbox")
        #else
        throw XCTSkip("Keychain unavailable on this platform.")
        #endif
    }

    func testPrivacyDefaultsToSecureTyping() throws {
        let state = ClientState(
            identity: Identity(displayName: "Alice"),
            relay: RelayEndpoint(host: "localhost", port: 9339),
            inboxId: "inbox"
        )
        XCTAssertTrue(state.privacy.secureTypingEnabled)
        XCTAssertFalse(state.privacy.useSecureCameraCapture)
    }

    func testPrivacySettingsPersist() throws {
        var state = ClientState(
            identity: Identity(displayName: "Alice"),
            relay: RelayEndpoint(host: "localhost", port: 9339),
            inboxId: "inbox"
        )
        state.privacy.secureTypingEnabled = false
        state.privacy.useSecureCameraCapture = true
        let data = try PICCPCoder.encode(state)
        let decoded = try PICCPCoder.decode(ClientState.self, from: data)
        XCTAssertFalse(decoded.privacy.secureTypingEnabled)
        XCTAssertTrue(decoded.privacy.useSecureCameraCapture)
    }

    func testRelayRequestEncoding() throws {
        let relay = RelayRequest.fetch(FetchRequest(inboxId: "inbox", maxCount: 10))
        let data = try PICCPCoder.encode(relay)
        let decoded = try PICCPCoder.decode(RelayRequest.self, from: data)
        XCTAssertEqual(decoded, relay)
    }

    func testRelayRequestAuthTokenInjection() throws {
        let request = RelayRequest.fetch(FetchRequest(inboxId: "inbox", maxCount: 10))
        let authenticated = request.withAuthToken("relay-secret")
        XCTAssertEqual(authenticated.type, .fetch)
        XCTAssertEqual(authenticated.fetch?.inboxId, "inbox")
        XCTAssertEqual(authenticated.authToken, "relay-secret")
    }

    func testRelayInfoAdvertisesPasswordRequirement() throws {
        let openRelay = RelayConfiguration(accessPassword: nil)
        XCTAssertEqual(openRelay.makeInfo().requiresPassword, false)
        XCTAssertEqual(openRelay.makeInfo().attachmentDefaultTTLSeconds, 3600)
        XCTAssertEqual(openRelay.makeInfo().attachmentMaxTTLSeconds, 21600)

        let protectedRelay = RelayConfiguration(accessPassword: "  relay-secret  ")
        XCTAssertEqual(protectedRelay.makeInfo().requiresPassword, true)

        let curatedRelay = RelayConfiguration(
            federation: FederationDescriptor(mode: .curated, name: "mesh-test"),
            curatedStrictPolicyEnabled: true,
            curatedCoordinatorQuorum: 2,
            curatedRequireSignedDirectory: true
        )
        let curatedInfo = curatedRelay.makeInfo()
        XCTAssertEqual(curatedInfo.curatedStrictPolicyEnabled, true)
        XCTAssertEqual(curatedInfo.curatedCoordinatorQuorum, 2)
        XCTAssertEqual(curatedInfo.curatedRequireSignedDirectory, true)
    }

    func testRelayInfoAdvertisesTemporalBucketSchedule() throws {
        let relay = RelayConfiguration(
            temporalBucketSeconds: 300,
            temporalBucketScheduleSeconds: [60, 120, 300],
            attachmentDefaultTTLSeconds: 1200,
            attachmentMaxTTLSeconds: 7200
        )
        let info = relay.makeInfo()
        XCTAssertEqual(info.temporalBucketSeconds, 300)
        XCTAssertEqual(info.temporalBucketScheduleSeconds ?? [], [60, 120, 300])
        XCTAssertEqual(info.attachmentDefaultTTLSeconds, 1200)
        XCTAssertEqual(info.attachmentMaxTTLSeconds, 7200)

        let encoded = try PICCPCoder.encode(info)
        let decoded = try PICCPCoder.decode(RelayInfo.self, from: encoded)
        XCTAssertEqual(decoded.temporalBucketScheduleSeconds ?? [], [60, 120, 300])
        XCTAssertEqual(decoded.attachmentDefaultTTLSeconds, 1200)
        XCTAssertEqual(decoded.attachmentMaxTTLSeconds, 7200)
    }

    func testRelayConfigurationNormalizesAttachmentTTLPolicy() {
        let relay = RelayConfiguration(
            attachmentDefaultTTLSeconds: 30,
            attachmentMaxTTLSeconds: 45,
            attachmentsEnabled: false
        )
        XCTAssertEqual(relay.attachmentDefaultTTLSeconds, 60)
        XCTAssertEqual(relay.attachmentMaxTTLSeconds, 60)
        XCTAssertEqual(relay.makeInfo().attachmentsEnabled, false)
    }

    func testPasswordProtectedRelayEnforcesAuthentication() async throws {
        let relayPassword = "relay-secret"
        let serverEndpoint = RelayEndpoint(host: "0.0.0.0", port: 39439)
        let clientEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39439)
        let store = RelayStore(storeURL: nil, temporalBucketSeconds: 300)
        let server = RelayServer(
            store: store,
            configuration: RelayConfiguration(accessPassword: relayPassword)
        )
        let started = expectation(description: "relay started")
        server.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try server.start(host: serverEndpoint.host, port: serverEndpoint.port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let client = RelayClient(endpoint: clientEndpoint)
        let health = try await client.send(.health())
        XCTAssertEqual(health.type, .ok)

        let inbox = InboxAddress.generate()
        let request = RelayRequest.deliver(
            DeliverRequest(
                inboxId: inbox,
                routingToken: inbox,
                envelope: Envelope(
                    conversationId: "auth-test",
                    senderFingerprint: "sender",
                    sentAt: Date(),
                    messageCounter: 1,
                    payload: EncryptedPayload(nonce: Data(), ciphertext: Data([1]), tag: Data()),
                    signature: Data([1])
                )
            )
        )
        let unauthorized = try await client.send(request)
        XCTAssertEqual(unauthorized.type, .error)
        XCTAssertTrue((unauthorized.error ?? "").localizedCaseInsensitiveContains("unauthorized"))

        let authenticatedClient = RelayClient(endpoint: clientEndpoint, authToken: relayPassword)
        let authorized = try await authenticatedClient.send(request)
        XCTAssertEqual(authorized.type, .delivered)
    }

    func testPairRequestFetchRequiresIdentityProof() async throws {
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: 39488)
        let server = RelayServer(store: RelayStore())
        let started = expectation(description: "pair proof relay started")
        server.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try server.start(host: "0.0.0.0", port: endpoint.port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let recipient = Identity(displayName: "Recipient")
        let sender = Identity(displayName: "Sender")
        let senderOffer = try MessageEngine.makeContactOffer(
            identity: sender,
            inboxId: InboxAddress.generate(),
            relay: endpoint
        )
        let client = RelayClient(endpoint: endpoint)
        let unsignedSendResponse = try await client.send(
            .sendPairRequest(
                SendPairRequest(
                    targetFingerprint: recipient.fingerprint,
                    offer: senderOffer
                )
            )
        )
        XCTAssertEqual(unsignedSendResponse.type, .error)

        var sendRequest = SendPairRequest(
            targetFingerprint: recipient.fingerprint,
            offer: senderOffer
        )
        let sendProof = try makeActorProof(identity: sender) { actorProof in
            try sendRequest.signableData(for: actorProof)
        }
        let redirectedRequest = SendPairRequest(
            targetFingerprint: Identity(displayName: "Mallory").fingerprint,
            offer: senderOffer,
            actorProof: sendProof
        )
        let redirectedResponse = try await client.send(.sendPairRequest(redirectedRequest))
        XCTAssertEqual(redirectedResponse.type, .error)

        sendRequest = SendPairRequest(
            targetFingerprint: recipient.fingerprint,
            offer: senderOffer,
            actorProof: sendProof
        )
        let sendResponse = try await client.send(.sendPairRequest(sendRequest))
        XCTAssertEqual(sendResponse.type, .ok)

        let unsignedResponse = try await client.send(
            .fetchPairRequests(
                FetchPairRequestsRequest(
                    fingerprint: recipient.fingerprint,
                    maxCount: 10
                )
            )
        )
        XCTAssertEqual(unsignedResponse.type, .error)

        var signedRequest = FetchPairRequestsRequest(
            fingerprint: recipient.fingerprint,
            maxCount: 10
        )
        let proof = try makeActorProof(identity: recipient) { actorProof in
            try signedRequest.signableData(for: actorProof)
        }
        signedRequest = FetchPairRequestsRequest(
            fingerprint: recipient.fingerprint,
            maxCount: 10,
            actorProof: proof
        )
        let signedResponse = try await client.send(.fetchPairRequests(signedRequest))
        XCTAssertEqual(signedResponse.type, .pairRequests)
        XCTAssertEqual(signedResponse.pairRequests?.first?.from.fingerprint, sender.fingerprint)
    }

    func testInboxRegistrationRequiresIdentityBoundAccessKey() async throws {
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: 39489)
        let server = RelayServer(store: RelayStore())
        let started = expectation(description: "mailbox binding relay started")
        server.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try server.start(host: "0.0.0.0", port: endpoint.port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let accessKey = SigningKeyPair()
        let inboxId = InboxAddress.derived(from: accessKey.publicKeyData)
        let otherAccessKey = SigningKeyPair()
        let identity = Identity(displayName: "Mailbox owner")
        let mismatchedOffer = try MessageEngine.makeContactOffer(
            identity: identity,
            inboxId: inboxId,
            relay: endpoint,
            inboxAccessPublicKey: otherAccessKey.publicKeyData
        )
        let client = RelayClient(endpoint: endpoint)

        var missingOffer = RegisterInboxRequest(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData
        )
        let missingProof = try makeInboxProof(signingKey: accessKey) { proof in
            try missingOffer.signableData(for: proof)
        }
        missingOffer = RegisterInboxRequest(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            accessProof: missingProof
        )
        let missingResponse = try await client.send(.registerInbox(missingOffer))
        XCTAssertEqual(missingResponse.type, .error)

        var mismatched = RegisterInboxRequest(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            contactOffer: mismatchedOffer
        )
        let mismatchedProof = try makeInboxProof(signingKey: accessKey) { proof in
            try mismatched.signableData(for: proof)
        }
        mismatched = RegisterInboxRequest(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            contactOffer: mismatchedOffer,
            accessProof: mismatchedProof
        )
        let mismatchedResponse = try await client.send(.registerInbox(mismatched))
        XCTAssertEqual(mismatchedResponse.type, .error)
    }

    func testRelayStoreGroupLifecycle() async throws {
        let store = RelayStore()
        let creator = "creator-fingerprint"
        let memberA = "member-a"
        let memberB = "member-b"

        let created = try await store.createGroup(
            title: "Ops",
            creatorFingerprint: creator,
            memberFingerprints: [memberA]
        )
        XCTAssertEqual(created.title, "Ops")
        XCTAssertTrue(created.members.contains(where: { $0.fingerprint == creator }))
        XCTAssertTrue(created.members.contains(where: { $0.fingerprint == memberA }))

        let listedForCreator = await store.listGroups(memberFingerprint: creator)
        XCTAssertEqual(listedForCreator.count, 1)
        XCTAssertEqual(listedForCreator[0].id, created.id)

        let updated = try await store.updateGroup(
            UpdateGroupRequest(
                groupId: created.id,
                actorFingerprint: creator,
                title: "Ops Team",
                addMemberFingerprints: [memberB]
            )
        )
        XCTAssertEqual(updated.title, "Ops Team")
        XCTAssertTrue(updated.members.contains(where: { $0.fingerprint == memberB }))
        XCTAssertEqual(updated.epoch, 1)
    }

    func testRelayStoreGroupMemberCanLeaveButCannotMutateOthers() async throws {
        let store = RelayStore()
        let creator = "creator-fingerprint"
        let memberA = "member-a"
        let memberB = "member-b"

        let created = try await store.createGroup(
            title: "Ops",
            creatorFingerprint: creator,
            memberFingerprints: [memberA, memberB]
        )

        do {
            _ = try await store.updateGroup(
                UpdateGroupRequest(
                    groupId: created.id,
                    actorFingerprint: memberA,
                    title: "Changed by member"
                )
            )
            XCTFail("Expected unauthorized member mutation to fail.")
        } catch {
            XCTAssertTrue(error is RelayStoreError)
        }

        let left = try await store.updateGroup(
            UpdateGroupRequest(
                groupId: created.id,
                actorFingerprint: memberA,
                removeMemberFingerprints: [memberA]
            )
        )
        XCTAssertFalse(left.members.contains(where: { $0.fingerprint == memberA }))
        XCTAssertTrue(left.members.contains(where: { $0.fingerprint == creator }))
        XCTAssertTrue(left.members.contains(where: { $0.fingerprint == memberB }))
    }

    func testRelayStoreGroupCreatorCanDelete() async throws {
        let store = RelayStore()
        let creator = "creator-fingerprint"
        let member = "member-a"
        let created = try await store.createGroup(
            title: "Ops",
            creatorFingerprint: creator,
            memberFingerprints: [member]
        )

        do {
            try await store.deleteGroup(
                DeleteGroupRequest(
                    groupId: created.id,
                    actorFingerprint: member
                )
            )
            XCTFail("Expected non-creator delete to fail.")
        } catch {
            XCTAssertTrue(error is RelayStoreError)
        }

        try await store.deleteGroup(
            DeleteGroupRequest(
                groupId: created.id,
                actorFingerprint: creator
            )
        )
        let creatorGroups = await store.listGroups(memberFingerprint: creator)
        XCTAssertTrue(creatorGroups.isEmpty)
        let memberGroups = await store.listGroups(memberFingerprint: member)
        XCTAssertTrue(memberGroups.isEmpty)
    }

    func testRelayStoreGroupJoinRequestLifecycle() async throws {
        let store = RelayStore()
        let creator = Identity(displayName: "Creator")
        let member = Identity(displayName: "Member")
        let joiner = Identity(displayName: "Joiner")

        let created = try await store.createGroup(
            title: "Ops",
            creatorFingerprint: creator.fingerprint,
            memberFingerprints: [member.fingerprint]
        )

        let joinProfile = RelayGroupMemberProfile(
            fingerprint: joiner.fingerprint,
            displayName: joiner.displayName,
            inboxId: InboxAddress.generate(),
            relay: RelayEndpoint(host: "127.0.0.1", port: 9339),
            signingPublicKey: joiner.signingKey.publicKeyData,
            agreementPublicKey: joiner.agreementKey.publicKeyData
        )

        let requested = try await store.requestGroupJoin(
            RequestGroupJoinRequest(groupId: created.id, requesterProfile: joinProfile)
        )
        XCTAssertEqual(requested.groupId, created.id)
        XCTAssertEqual(requested.requester.fingerprint, joiner.fingerprint)

        let listed = try await store.listGroupJoinRequests(
            ListGroupJoinRequestsRequest(groupId: created.id, actorFingerprint: creator.fingerprint)
        )
        XCTAssertEqual(listed.count, 1)
        XCTAssertEqual(listed[0].id, requested.id)

        let approved = try await store.approveGroupJoin(
            ApproveGroupJoinRequest(
                groupId: created.id,
                actorFingerprint: creator.fingerprint,
                joinRequestId: requested.id
            )
        )
        XCTAssertTrue(approved.members.contains(where: { $0.fingerprint == joiner.fingerprint }))

        let postApprove = try await store.listGroupJoinRequests(
            ListGroupJoinRequestsRequest(groupId: created.id, actorFingerprint: creator.fingerprint)
        )
        XCTAssertTrue(postApprove.isEmpty)
    }

    func testRelayServerGroupJoinRoutes() async throws {
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: 39442)
        let server = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(groupCreationMode: .allowed)
        )
        let started = expectation(description: "join route relay started")
        server.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try server.start(host: "0.0.0.0", port: endpoint.port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let creator = Identity(displayName: "Creator")
        let member = Identity(displayName: "Member")
        let joiner = Identity(displayName: "Joiner")
        let client = RelayClient(endpoint: endpoint)
        let creatorProfile = relayGroupMemberProfile(identity: creator, relay: endpoint)

        let createRequest = try signedCreateGroupRequest(
            CreateGroupRequest(
                title: "Federated",
                creatorFingerprint: creator.fingerprint,
                memberFingerprints: [member.fingerprint],
                creatorProfile: creatorProfile
            ),
            signer: creator
        )
        let createResponse = try await client.send(
            .createGroup(createRequest)
        )
        XCTAssertEqual(createResponse.type, .group)
        guard let group = createResponse.group else {
            XCTFail("Expected group in create response.")
            return
        }

        let anonymousLookup = try await client.send(
            .getGroup(GetGroupRequest(groupId: group.id))
        )
        XCTAssertEqual(anonymousLookup.type, .error)

        let signedLookup = try signedGetGroupRequest(
            GetGroupRequest(groupId: group.id, memberFingerprint: creator.fingerprint),
            signer: creator
        )
        let lookupResponse = try await client.send(.getGroup(signedLookup))
        XCTAssertEqual(lookupResponse.type, .group)
        XCTAssertEqual(lookupResponse.group?.id, group.id)

        let joinProfile = relayGroupMemberProfile(identity: joiner, relay: endpoint)
        let requestJoin = try signedRequestGroupJoinRequest(
            RequestGroupJoinRequest(groupId: group.id, requesterProfile: joinProfile),
            signer: joiner
        )
        let requestJoinResponse = try await client.send(
            .requestGroupJoin(requestJoin)
        )
        XCTAssertEqual(requestJoinResponse.type, .groupJoinRequests)
        guard let joinRequest = requestJoinResponse.groupJoinRequests?.first else {
            XCTFail("Expected a join request payload.")
            return
        }

        let listJoin = try signedListGroupJoinRequestsRequest(
            ListGroupJoinRequestsRequest(groupId: group.id, actorFingerprint: creator.fingerprint),
            signer: creator
        )
        let listResponse = try await client.send(
            .listGroupJoinRequests(listJoin)
        )
        XCTAssertEqual(listResponse.type, .groupJoinRequests)
        XCTAssertEqual(listResponse.groupJoinRequests?.count, 1)

        let approveJoin = try signedApproveGroupJoinRequest(
            ApproveGroupJoinRequest(
                groupId: group.id,
                actorFingerprint: creator.fingerprint,
                joinRequestId: joinRequest.id
            ),
            signer: creator
        )
        let approveResponse = try await client.send(
            .approveGroupJoin(approveJoin)
        )
        XCTAssertEqual(approveResponse.type, .group)
        XCTAssertTrue(approveResponse.group?.members.contains(where: { $0.fingerprint == joiner.fingerprint }) ?? false)
    }

    func testRelayServerDeleteGroupRoute() async throws {
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: 39443)
        let server = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(groupCreationMode: .allowed)
        )
        let started = expectation(description: "delete route relay started")
        server.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try server.start(host: "0.0.0.0", port: endpoint.port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let creator = Identity(displayName: "Creator")
        let member = Identity(displayName: "Member")
        let client = RelayClient(endpoint: endpoint)
        let creatorProfile = relayGroupMemberProfile(identity: creator, relay: endpoint)
        let memberProfile = relayGroupMemberProfile(identity: member, relay: endpoint)

        let createRequest = try signedCreateGroupRequest(
            CreateGroupRequest(
                title: "Disposable",
                creatorFingerprint: creator.fingerprint,
                memberFingerprints: [member.fingerprint],
                creatorProfile: creatorProfile,
                memberProfiles: [memberProfile]
            ),
            signer: creator
        )
        let createResponse = try await client.send(
            .createGroup(createRequest)
        )
        XCTAssertEqual(createResponse.type, .group)
        guard let group = createResponse.group else {
            XCTFail("Expected group in create response.")
            return
        }

        let memberDelete = try signedDeleteGroupRequest(
            DeleteGroupRequest(
                groupId: group.id,
                actorFingerprint: member.fingerprint
            ),
            signer: member
        )
        let unauthorizedDelete = try await client.send(
            .deleteGroup(memberDelete)
        )
        XCTAssertEqual(unauthorizedDelete.type, .error)
        XCTAssertTrue((unauthorizedDelete.error ?? "").localizedCaseInsensitiveContains("unauthorized"))

        let creatorDelete = try signedDeleteGroupRequest(
            DeleteGroupRequest(
                groupId: group.id,
                actorFingerprint: creator.fingerprint
            ),
            signer: creator
        )
        let deleteResponse = try await client.send(
            .deleteGroup(creatorDelete)
        )
        XCTAssertEqual(deleteResponse.type, .ok)

        let creatorList = try signedListGroupsRequest(
            ListGroupsRequest(memberFingerprint: creator.fingerprint, limit: 32),
            signer: creator
        )
        let creatorGroups = try await client.send(
            .listGroups(creatorList)
        )
        XCTAssertEqual(creatorGroups.type, .groups)
        XCTAssertTrue((creatorGroups.groups ?? []).isEmpty)

        let memberList = try signedListGroupsRequest(
            ListGroupsRequest(memberFingerprint: member.fingerprint, limit: 32),
            signer: member
        )
        let memberGroups = try await client.send(
            .listGroups(memberList)
        )
        XCTAssertEqual(memberGroups.type, .groups)
        XCTAssertTrue((memberGroups.groups ?? []).isEmpty)
    }

    func testRelayServerRejectsReplayedActorProof() async throws {
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: 39479)
        let server = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(groupCreationMode: .allowed)
        )
        let started = expectation(description: "replay guard relay started")
        server.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try server.start(host: "0.0.0.0", port: endpoint.port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let creator = Identity(displayName: "Creator")
        let member = Identity(displayName: "Member")
        let client = RelayClient(endpoint: endpoint)
        let creatorProfile = relayGroupMemberProfile(identity: creator, relay: endpoint)

        let signedCreate = try signedCreateGroupRequest(
            CreateGroupRequest(
                title: "Replay Guard",
                creatorFingerprint: creator.fingerprint,
                memberFingerprints: [member.fingerprint],
                creatorProfile: creatorProfile
            ),
            signer: creator
        )

        let first = try await client.send(.createGroup(signedCreate))
        XCTAssertEqual(first.type, .group)

        let replay = try await client.send(.createGroup(signedCreate))
        XCTAssertEqual(replay.type, .error)
        XCTAssertTrue((replay.error ?? "").localizedCaseInsensitiveContains("replay"))
    }

    func testRelayServerGroupCreationPolicyIsEnforced() async throws {
        let disabledEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39440)
        let disabledServer = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(groupCreationMode: .disabled)
        )
        let startedDisabled = expectation(description: "disabled relay started")
        disabledServer.onEvent = { event in
            if case .started = event {
                startedDisabled.fulfill()
            }
        }
        try disabledServer.start(host: "0.0.0.0", port: disabledEndpoint.port)
        defer { disabledServer.stop() }
        await fulfillment(of: [startedDisabled], timeout: 2.0)

        let creator = Identity(displayName: "Creator")
        let member = Identity(displayName: "Member")
        let disabledClient = RelayClient(endpoint: disabledEndpoint)
        let unsignedRequest = CreateGroupRequest(
            title: "Team",
            creatorFingerprint: creator.fingerprint,
            memberFingerprints: [member.fingerprint],
            creatorProfile: relayGroupMemberProfile(identity: creator, relay: disabledEndpoint),
            memberProfiles: [relayGroupMemberProfile(identity: member, relay: disabledEndpoint)]
        )
        let createRequest = RelayRequest.createGroup(
            try signedCreateGroupRequest(unsignedRequest, signer: creator)
        )
        let disabledResponse = try await disabledClient.send(createRequest)
        XCTAssertEqual(disabledResponse.type, .error)
        XCTAssertTrue((disabledResponse.error ?? "").localizedCaseInsensitiveContains("disabled"))

        let enabledEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39441)
        let enabledServer = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(groupCreationMode: .allowed)
        )
        let startedEnabled = expectation(description: "enabled relay started")
        enabledServer.onEvent = { event in
            if case .started = event {
                startedEnabled.fulfill()
            }
        }
        try enabledServer.start(host: "0.0.0.0", port: enabledEndpoint.port)
        defer { enabledServer.stop() }
        await fulfillment(of: [startedEnabled], timeout: 2.0)

        let enabledClient = RelayClient(endpoint: enabledEndpoint)
        let enabledResponse = try await enabledClient.send(createRequest)
        XCTAssertEqual(enabledResponse.type, .group)
        XCTAssertEqual(enabledResponse.group?.title, "Team")
        XCTAssertNotNil(enabledResponse.group?.inboxId)
    }

    private func relayGroupMemberProfile(identity: Identity, relay: RelayEndpoint) -> RelayGroupMemberProfile {
        RelayGroupMemberProfile(
            fingerprint: identity.fingerprint,
            displayName: identity.displayName,
            inboxId: InboxAddress.generate(),
            relay: relay,
            signingPublicKey: identity.signingKey.publicKeyData,
            agreementPublicKey: identity.agreementKey.publicKeyData
        )
    }

    private func signedCreateGroupRequest(_ request: CreateGroupRequest, signer: Identity) throws -> CreateGroupRequest {
        let proof = try makeActorProof(identity: signer) { actorProof in
            try request.signableData(for: actorProof)
        }
        return CreateGroupRequest(
            title: request.title,
            creatorFingerprint: request.creatorFingerprint,
            memberFingerprints: request.memberFingerprints,
            creatorProfile: request.creatorProfile,
            memberProfiles: request.memberProfiles,
            creatorProof: proof
        )
    }

    private func signedRequestGroupJoinRequest(
        _ request: RequestGroupJoinRequest,
        signer: Identity
    ) throws -> RequestGroupJoinRequest {
        let proof = try makeActorProof(identity: signer) { actorProof in
            try request.signableData(for: actorProof)
        }
        return RequestGroupJoinRequest(
            groupId: request.groupId,
            requesterProfile: request.requesterProfile,
            requesterProof: proof
        )
    }

    private func signedListGroupJoinRequestsRequest(
        _ request: ListGroupJoinRequestsRequest,
        signer: Identity
    ) throws -> ListGroupJoinRequestsRequest {
        let proof = try makeActorProof(identity: signer) { actorProof in
            try request.signableData(for: actorProof)
        }
        return ListGroupJoinRequestsRequest(
            groupId: request.groupId,
            actorFingerprint: request.actorFingerprint,
            limit: request.limit,
            actorProof: proof
        )
    }

    private func signedApproveGroupJoinRequest(
        _ request: ApproveGroupJoinRequest,
        signer: Identity
    ) throws -> ApproveGroupJoinRequest {
        let proof = try makeActorProof(identity: signer) { actorProof in
            try request.signableData(for: actorProof)
        }
        return ApproveGroupJoinRequest(
            groupId: request.groupId,
            actorFingerprint: request.actorFingerprint,
            joinRequestId: request.joinRequestId,
            actorProof: proof
        )
    }

    private func signedDeleteGroupRequest(_ request: DeleteGroupRequest, signer: Identity) throws -> DeleteGroupRequest {
        let proof = try makeActorProof(identity: signer) { actorProof in
            try request.signableData(for: actorProof)
        }
        return DeleteGroupRequest(
            groupId: request.groupId,
            actorFingerprint: request.actorFingerprint,
            actorProof: proof
        )
    }

    private func signedListGroupsRequest(_ request: ListGroupsRequest, signer: Identity) throws -> ListGroupsRequest {
        let proof = try makeActorProof(identity: signer) { actorProof in
            try request.signableData(for: actorProof)
        }
        return ListGroupsRequest(
            memberFingerprint: request.memberFingerprint,
            limit: request.limit,
            memberProof: proof
        )
    }

    private func signedGetGroupRequest(_ request: GetGroupRequest, signer: Identity) throws -> GetGroupRequest {
        let proof = try makeActorProof(identity: signer) { actorProof in
            try request.signableData(for: actorProof)
        }
        return GetGroupRequest(
            groupId: request.groupId,
            memberFingerprint: request.memberFingerprint,
            memberProof: proof
        )
    }

    private func makeActorProof(
        identity: Identity,
        signableDataBuilder: (RelayActorProof) throws -> Data
    ) throws -> RelayActorProof {
        let signedAt = Date()
        let nonce = UUID()
        let placeholder = RelayActorProof(
            fingerprint: identity.fingerprint,
            publicSigningKey: identity.signingKey.publicKeyData,
            signedAt: signedAt,
            nonce: nonce,
            signature: Data()
        )
        let signableData = try signableDataBuilder(placeholder)
        let signature = try identity.signingKey.sign(signableData)
        return RelayActorProof(
            fingerprint: identity.fingerprint,
            publicSigningKey: identity.signingKey.publicKeyData,
            signedAt: signedAt,
            nonce: nonce,
            signature: signature
        )
    }

    func testCoordinatorRegistersAndListsFederationNodes() async throws {
        let coordinatorEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39464)
        let nodeEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39463)
        let federation = FederationDescriptor(mode: .curated, name: "mesh-a")
        let coordinator = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation
            )
        )
        let nodeRelay = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                temporalBucketSeconds: 120
            )
        )
        let started = expectation(description: "coordinator started")
        coordinator.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        let startedNode = expectation(description: "node relay started")
        nodeRelay.onEvent = { event in
            if case .started = event {
                startedNode.fulfill()
            }
        }
        try coordinator.start(host: "0.0.0.0", port: coordinatorEndpoint.port)
        try nodeRelay.start(host: "0.0.0.0", port: nodeEndpoint.port)
        defer { coordinator.stop() }
        defer { nodeRelay.stop() }
        await fulfillment(of: [started, startedNode], timeout: 5.0)

        let client = RelayClient(endpoint: coordinatorEndpoint)
        let nodeInfo = RelayConfiguration(
            kind: .standard,
            federation: federation,
            temporalBucketSeconds: 120
        ).makeInfo()

        let registerResponse = try await client.send(
            .registerFederationNode(
                FederationNodeRegistrationRequest(
                    endpoint: nodeEndpoint,
                    relayInfo: nodeInfo,
                    ttlSeconds: 120
                )
            )
        )
        XCTAssertEqual(registerResponse.type, .federationNodes)
        XCTAssertEqual(registerResponse.federationNodes?.first?.endpoint, nodeEndpoint)

        let listResponse = try await client.send(
            .listFederationNodes(
                ListFederationNodesRequest(
                    mode: .curated,
                    federationName: "mesh-a",
                    onlyHealthy: true,
                    requireSignedSnapshot: true
                )
            )
        )
        XCTAssertEqual(listResponse.type, .federationNodes)
        XCTAssertEqual(listResponse.federationNodes?.count, 1)
        XCTAssertEqual(listResponse.federationNodes?.first?.endpoint, nodeEndpoint)
        let snapshot = try XCTUnwrap(listResponse.federationSnapshot)
        XCTAssertGreaterThan(snapshot.validUntil, Date())

        let infoResponse = try await client.send(.info())
        XCTAssertEqual(infoResponse.type, .info)
        XCTAssertEqual(infoResponse.relayInfo?.kind, .coordinator)
        XCTAssertEqual(infoResponse.relayInfo?.coordinatorReportedRelayCount, 1)
        let publicKey = try XCTUnwrap(infoResponse.relayInfo?.federationDirectoryPublicKey)
        XCTAssertTrue(FederationDirectorySignature.verify(snapshot: snapshot, trustedPublicKey: publicKey))
    }

    func testCoordinatorRegistrationTokenIsEnforcedWhenConfigured() async throws {
        let coordinatorEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39486)
        let nodeEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39487)
        let token = "mesh-secret-token"
        let federation = FederationDescriptor(mode: .curated, name: "mesh-token")
        let coordinator = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorRegistrationToken: token
            )
        )
        let nodeRelay = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation
            )
        )
        let started = expectation(description: "coordinator token started")
        coordinator.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        let startedNode = expectation(description: "coordinator token node started")
        nodeRelay.onEvent = { event in
            if case .started = event {
                startedNode.fulfill()
            }
        }
        try coordinator.start(host: "0.0.0.0", port: coordinatorEndpoint.port)
        try nodeRelay.start(host: "0.0.0.0", port: nodeEndpoint.port)
        defer { coordinator.stop() }
        defer { nodeRelay.stop() }
        await fulfillment(of: [started, startedNode], timeout: 2.0)

        let client = RelayClient(endpoint: coordinatorEndpoint)
        let request = RelayRequest.registerFederationNode(
            FederationNodeRegistrationRequest(
                endpoint: nodeEndpoint,
                relayInfo: RelayConfiguration(
                    kind: .standard,
                    federation: federation
                ).makeInfo(),
                ttlSeconds: 120
            )
        )

        let unauthorized = try await client.send(request)
        XCTAssertEqual(unauthorized.type, .error)
        XCTAssertEqual(unauthorized.error, "Unauthorized: coordinator registration token is required.")

        let wrongToken = try await client.send(request.withAuthToken("wrong-token"))
        XCTAssertEqual(wrongToken.type, .error)
        XCTAssertEqual(wrongToken.error, "Unauthorized: coordinator registration token is required.")

        let authorized = try await client.send(request.withAuthToken(token))
        XCTAssertEqual(authorized.type, .federationNodes)
        XCTAssertEqual(authorized.federationNodes?.count, 1)
    }

    func testFederationNodeListingRespectsMaxStaleness() async throws {
        let store = RelayStore(storeURL: nil, temporalBucketSeconds: 300)
        let federation = FederationDescriptor(mode: .open, name: "mesh-stale")
        let endpoint = RelayEndpoint(host: "relay-stale.example", port: 9339)
        let info = RelayConfiguration(kind: .standard, federation: federation).makeInfo(now: Date())
        _ = try await store.registerFederationNode(
            FederationNodeRegistrationRequest(
                endpoint: endpoint,
                relayInfo: info,
                ttlSeconds: 120
            )
        )
        try await Task.sleep(nanoseconds: 2_100_000_000)
        let staleFiltered = await store.listFederationNodes(
            ListFederationNodesRequest(
                mode: .open,
                federationName: "mesh-stale",
                onlyHealthy: true,
                maxStalenessSeconds: 1
            )
        )
        XCTAssertTrue(staleFiltered.isEmpty)
    }

    func testCuratedRelayForwardsUsingCoordinatorDirectory() async throws {
        let federation = FederationDescriptor(mode: .curated, name: "mesh-b")
        let coordinatorPrivateKey = FederationDirectorySignature.privateKeyData(from: nil)
        let coordinatorPublicKey = try XCTUnwrap(FederationDirectorySignature.publicKeyData(from: coordinatorPrivateKey))
        let coordinatorEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: 39465,
            directorySigningPublicKey: coordinatorPublicKey
        )
        let relayXEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39466)
        let relayYEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39467)

        let coordinator = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorDirectorySigningPrivateKey: coordinatorPrivateKey
            )
        )
        let relayX = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .bridge,
                federation: federation,
                federationCoordinatorEndpoints: [coordinatorEndpoint],
                curatedStrictPolicyEnabled: true,
                curatedCoordinatorQuorum: 1,
                curatedRequireSignedDirectory: true,
                federationAllowList: [relayYEndpoint]
            )
        )
        let relayY = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation
            )
        )

        let startedCoordinator = expectation(description: "coordinator started")
        coordinator.onEvent = { event in
            if case .started = event {
                startedCoordinator.fulfill()
            }
        }
        let startedX = expectation(description: "relay x started")
        relayX.onEvent = { event in
            if case .started = event {
                startedX.fulfill()
            }
        }
        let startedY = expectation(description: "relay y started")
        relayY.onEvent = { event in
            if case .started = event {
                startedY.fulfill()
            }
        }

        try coordinator.start(host: "0.0.0.0", port: coordinatorEndpoint.port)
        try relayX.start(host: "0.0.0.0", port: relayXEndpoint.port)
        try relayY.start(host: "0.0.0.0", port: relayYEndpoint.port)
        defer {
            relayX.stop()
            relayY.stop()
            coordinator.stop()
        }
        await fulfillment(of: [startedCoordinator, startedX, startedY], timeout: 2.0)

        let coordinatorClient = RelayClient(endpoint: coordinatorEndpoint)
        _ = try await coordinatorClient.send(
            .registerFederationNode(
                FederationNodeRegistrationRequest(
                    endpoint: relayYEndpoint,
                    relayInfo: RelayConfiguration(
                        kind: .standard,
                        federation: federation
                    ).makeInfo(),
                    ttlSeconds: 120
                )
            )
        )

        let destinationAccessKey = SigningKeyPair()
        let destinationInbox = InboxAddress.derived(from: destinationAccessKey.publicKeyData)
        let envelope = Envelope(
            conversationId: "federated-test",
            senderFingerprint: "sender-fp",
            sentAt: Date(),
            messageCounter: 1,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x01, count: 12),
                ciphertext: Data([0xDE, 0xAD, 0xBE, 0xEF]),
                tag: Data(repeating: 0x02, count: 16)
            ),
            signature: Data([0xAA])
        )

        let xClient = RelayClient(endpoint: relayXEndpoint)
        let deliverResponse = try await xClient.send(
            .deliver(
                DeliverRequest(
                    inboxId: destinationInbox,
                    routingToken: destinationInbox,
                    envelope: envelope,
                    destinationRelay: relayYEndpoint
                )
            )
        )
        XCTAssertEqual(deliverResponse.type, .delivered)

        let yClient = RelayClient(endpoint: relayYEndpoint)
        let fetchResponse = try await registerAndFetch(
            client: yClient,
            inboxId: destinationInbox,
            accessKey: destinationAccessKey,
            maxCount: 10
        )
        XCTAssertEqual(fetchResponse.type, .messages)
        XCTAssertEqual(fetchResponse.messages?.count, 1)
        XCTAssertEqual(fetchResponse.messages?.first?.id, envelope.id)
    }

    func testCuratedStrictPolicyRejectsDestinationOutsideAllowList() async throws {
        let federation = FederationDescriptor(mode: .curated, name: "mesh-c")
        let coordinatorPrivateKey = FederationDirectorySignature.privateKeyData(from: nil)
        let coordinatorPublicKey = try XCTUnwrap(FederationDirectorySignature.publicKeyData(from: coordinatorPrivateKey))
        let coordinatorEndpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: 39468,
            directorySigningPublicKey: coordinatorPublicKey
        )
        let relayXEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39469)
        let relayYEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39470)
        let nonMatchingAllowListEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39999)

        let coordinator = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorDirectorySigningPrivateKey: coordinatorPrivateKey
            )
        )
        let relayX = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .bridge,
                federation: federation,
                federationCoordinatorEndpoints: [coordinatorEndpoint],
                curatedStrictPolicyEnabled: true,
                curatedCoordinatorQuorum: 1,
                curatedRequireSignedDirectory: true,
                federationAllowList: [nonMatchingAllowListEndpoint]
            )
        )
        let relayY = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation
            )
        )

        let startedCoordinator = expectation(description: "coordinator strict allowlist started")
        coordinator.onEvent = { event in
            if case .started = event {
                startedCoordinator.fulfill()
            }
        }
        let startedX = expectation(description: "relay x strict allowlist started")
        relayX.onEvent = { event in
            if case .started = event {
                startedX.fulfill()
            }
        }
        let startedY = expectation(description: "relay y strict allowlist started")
        relayY.onEvent = { event in
            if case .started = event {
                startedY.fulfill()
            }
        }

        try coordinator.start(host: "0.0.0.0", port: coordinatorEndpoint.port)
        try relayX.start(host: "0.0.0.0", port: relayXEndpoint.port)
        try relayY.start(host: "0.0.0.0", port: relayYEndpoint.port)
        defer {
            relayX.stop()
            relayY.stop()
            coordinator.stop()
        }
        await fulfillment(of: [startedCoordinator, startedX, startedY], timeout: 2.0)

        let coordinatorClient = RelayClient(endpoint: coordinatorEndpoint)
        _ = try await coordinatorClient.send(
            .registerFederationNode(
                FederationNodeRegistrationRequest(
                    endpoint: relayYEndpoint,
                    relayInfo: RelayConfiguration(
                        kind: .standard,
                        federation: federation
                    ).makeInfo(),
                    ttlSeconds: 120
                )
            )
        )

        let destinationInbox = InboxAddress.generate()
        let envelope = Envelope(
            conversationId: "strict-allowlist-test",
            senderFingerprint: "sender-fp",
            sentAt: Date(),
            messageCounter: 1,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x01, count: 12),
                ciphertext: Data([0x11, 0x22, 0x33]),
                tag: Data(repeating: 0x02, count: 16)
            ),
            signature: Data([0xAA])
        )

        let xClient = RelayClient(endpoint: relayXEndpoint)
        let deliverResponse = try await xClient.send(
            .deliver(
                DeliverRequest(
                    inboxId: destinationInbox,
                    routingToken: destinationInbox,
                    envelope: envelope,
                    destinationRelay: relayYEndpoint
                )
            )
        )
        XCTAssertEqual(deliverResponse.type, .error)
        XCTAssertTrue(
            (deliverResponse.error ?? "").localizedCaseInsensitiveContains("allow list"),
            "Expected strict curated allow-list failure, got: \(deliverResponse.error ?? "nil")"
        )
    }

    func testFederationForwardingDoesNotReuseInboundClientAuthToken() async throws {
        let federation = FederationDescriptor(mode: .open, name: "mesh-auth-isolation")
        let relayXEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39475)
        let relayYEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39476)

        let relayX = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .bridge,
                federation: federation,
                accessPassword: "client-token",
                allowPrivateFederationEndpoints: true
            )
        )
        let relayY = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                accessPassword: "client-token"
            )
        )

        let startedX = expectation(description: "relay x started (auth isolation)")
        relayX.onEvent = { event in
            if case .started = event {
                startedX.fulfill()
            }
        }
        let startedY = expectation(description: "relay y started (auth isolation)")
        relayY.onEvent = { event in
            if case .started = event {
                startedY.fulfill()
            }
        }

        try relayX.start(host: "0.0.0.0", port: relayXEndpoint.port)
        try relayY.start(host: "0.0.0.0", port: relayYEndpoint.port)
        defer {
            relayX.stop()
            relayY.stop()
        }
        await fulfillment(of: [startedX, startedY], timeout: 2.0)

        let destinationAccessKey = SigningKeyPair()
        let destinationInbox = InboxAddress.derived(from: destinationAccessKey.publicKeyData)
        let envelope = Envelope(
            conversationId: "forward-auth-isolation",
            senderFingerprint: "sender-fp",
            sentAt: Date(),
            messageCounter: 1,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x01, count: 12),
                ciphertext: Data([0x01, 0x02, 0x03]),
                tag: Data(repeating: 0x02, count: 16)
            ),
            signature: Data([0xAA])
        )

        let xClient = RelayClient(endpoint: relayXEndpoint, authToken: "client-token")
        let deliverResponse = try await xClient.send(
            .deliver(
                DeliverRequest(
                    inboxId: destinationInbox,
                    routingToken: destinationInbox,
                    envelope: envelope,
                    destinationRelay: relayYEndpoint
                )
            )
        )
        XCTAssertEqual(deliverResponse.type, .error)
        XCTAssertTrue((deliverResponse.error ?? "").localizedCaseInsensitiveContains("unauthorized"))

        let yClient = RelayClient(endpoint: relayYEndpoint, authToken: "client-token")
        let fetchResponse = try await registerAndFetch(
            client: yClient,
            inboxId: destinationInbox,
            accessKey: destinationAccessKey,
            maxCount: 10
        )
        XCTAssertEqual(fetchResponse.type, .messages)
        XCTAssertEqual(fetchResponse.messages?.count ?? 0, 0)
    }

    func testFederationForwardingUsesDedicatedInterRelayTokenWhenConfigured() async throws {
        let federation = FederationDescriptor(mode: .open, name: "mesh-auth-forward")
        let relayXEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39477)
        let relayYEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39478)

        let relayX = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .bridge,
                federation: federation,
                accessPassword: "client-token",
                federationForwardingAuthToken: "relay-token",
                allowPrivateFederationEndpoints: true
            )
        )
        let relayY = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                accessPassword: "relay-token"
            )
        )

        let startedX = expectation(description: "relay x started (forward auth)")
        relayX.onEvent = { event in
            if case .started = event {
                startedX.fulfill()
            }
        }
        let startedY = expectation(description: "relay y started (forward auth)")
        relayY.onEvent = { event in
            if case .started = event {
                startedY.fulfill()
            }
        }

        try relayX.start(host: "0.0.0.0", port: relayXEndpoint.port)
        try relayY.start(host: "0.0.0.0", port: relayYEndpoint.port)
        defer {
            relayX.stop()
            relayY.stop()
        }
        await fulfillment(of: [startedX, startedY], timeout: 2.0)

        let destinationAccessKey = SigningKeyPair()
        let destinationInbox = InboxAddress.derived(from: destinationAccessKey.publicKeyData)
        let envelope = Envelope(
            conversationId: "forward-auth-success",
            senderFingerprint: "sender-fp",
            sentAt: Date(),
            messageCounter: 1,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x01, count: 12),
                ciphertext: Data([0xAA, 0xBB, 0xCC]),
                tag: Data(repeating: 0x02, count: 16)
            ),
            signature: Data([0xAA])
        )

        let xClient = RelayClient(endpoint: relayXEndpoint, authToken: "client-token")
        let deliverResponse = try await xClient.send(
            .deliver(
                DeliverRequest(
                    inboxId: destinationInbox,
                    routingToken: destinationInbox,
                    envelope: envelope,
                    destinationRelay: relayYEndpoint
                )
            )
        )
        XCTAssertEqual(deliverResponse.type, .delivered)
        XCTAssertEqual(deliverResponse.delivered?.storedCount, 1)

        let yClient = RelayClient(endpoint: relayYEndpoint, authToken: "relay-token")
        let fetchResponse = try await registerAndFetch(
            client: yClient,
            inboxId: destinationInbox,
            accessKey: destinationAccessKey,
            maxCount: 10
        )
        XCTAssertEqual(fetchResponse.type, .messages)
        XCTAssertEqual(fetchResponse.messages?.count, 1)
        XCTAssertEqual(fetchResponse.messages?.first?.id, envelope.id)
    }

    func testFederatedRelaysSupportEncryptedRoundTripBetweenClients() async throws {
        let federation = FederationDescriptor(mode: .open, name: "mesh-client-roundtrip")
        let relayAEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39520)
        let relayBEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39521)

        let relayA = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .bridge,
                federation: federation,
                allowPrivateFederationEndpoints: true
            )
        )
        let relayB = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .bridge,
                federation: federation,
                allowPrivateFederationEndpoints: true
            )
        )

        let startedA = expectation(description: "relay A started (client roundtrip)")
        relayA.onEvent = { event in
            if case .started = event {
                startedA.fulfill()
            }
        }
        let startedB = expectation(description: "relay B started (client roundtrip)")
        relayB.onEvent = { event in
            if case .started = event {
                startedB.fulfill()
            }
        }

        try relayA.start(host: "0.0.0.0", port: relayAEndpoint.port)
        try relayB.start(host: "0.0.0.0", port: relayBEndpoint.port)
        defer {
            relayA.stop()
            relayB.stop()
        }
        await fulfillment(of: [startedA, startedB], timeout: 2.0)

        let alice = Identity(displayName: "Alice Federation")
        let bob = Identity(displayName: "Bob Federation")
        let aliceAccessKey = SigningKeyPair()
        let bobAccessKey = SigningKeyPair()
        let aliceInbox = InboxAddress.derived(from: aliceAccessKey.publicKeyData)
        let bobInbox = InboxAddress.derived(from: bobAccessKey.publicKeyData)

        let bobAsContactForAlice = Contact(
            displayName: bob.displayName,
            inboxId: bobInbox,
            relay: relayBEndpoint,
            signingPublicKey: bob.signingKey.publicKeyData,
            agreementPublicKey: bob.agreementKey.publicKeyData
        )
        let aliceAsContactForBob = Contact(
            displayName: alice.displayName,
            inboxId: aliceInbox,
            relay: relayAEndpoint,
            signingPublicKey: alice.signingKey.publicKeyData,
            agreementPublicKey: alice.agreementKey.publicKeyData
        )

        let session = try MessageEngine.createOutboundSession(identity: alice, contact: bobAsContactForAlice)
        var aliceConversation = session.conversation
        var bobConversation = try MessageEngine.createInboundSession(
            identity: bob,
            contact: aliceAsContactForBob,
            kemCiphertext: session.kemCiphertext
        )

        let outboundEnvelope = try MessageEngine.encrypt(
            body: .text("hello-over-federation"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            conversation: &aliceConversation,
            kemCiphertext: session.kemCiphertext
        )

        let relayAClient = RelayClient(endpoint: relayAEndpoint)
        let deliverToRelayB = try await relayAClient.send(
            .deliver(
                DeliverRequest(
                    inboxId: bobInbox,
                    routingToken: bobInbox,
                    envelope: outboundEnvelope,
                    destinationRelay: relayBEndpoint
                )
            )
        )
        XCTAssertEqual(deliverToRelayB.type, .delivered)

        let relayBClient = RelayClient(endpoint: relayBEndpoint)
        let fetchedAtRelayB = try await registerAndFetch(
            client: relayBClient,
            inboxId: bobInbox,
            accessKey: bobAccessKey,
            maxCount: 10
        )
        XCTAssertEqual(fetchedAtRelayB.type, .messages)
        let receivedAtBob = try XCTUnwrap(fetchedAtRelayB.messages?.first)
        let decryptedAtBob = try MessageEngine.decrypt(
            envelope: receivedAtBob,
            contact: aliceAsContactForBob,
            conversation: &bobConversation
        )
        if case .text(let text) = decryptedAtBob {
            XCTAssertEqual(text, "hello-over-federation")
        } else {
            XCTFail("Expected text message at Bob")
        }

        let replyEnvelope = try MessageEngine.encrypt(
            body: .text("ack-from-bob"),
            senderSigningKey: bob.signingKey,
            senderFingerprint: bob.fingerprint,
            conversation: &bobConversation,
            kemCiphertext: nil
        )

        let deliverToRelayA = try await relayBClient.send(
            .deliver(
                DeliverRequest(
                    inboxId: aliceInbox,
                    routingToken: aliceInbox,
                    envelope: replyEnvelope,
                    destinationRelay: relayAEndpoint
                )
            )
        )
        XCTAssertEqual(deliverToRelayA.type, .delivered)

        let fetchedAtRelayA = try await registerAndFetch(
            client: relayAClient,
            inboxId: aliceInbox,
            accessKey: aliceAccessKey,
            maxCount: 10
        )
        XCTAssertEqual(fetchedAtRelayA.type, .messages)
        let receivedAtAlice = try XCTUnwrap(fetchedAtRelayA.messages?.first)
        let decryptedAtAlice = try MessageEngine.decrypt(
            envelope: receivedAtAlice,
            contact: bobAsContactForAlice,
            conversation: &aliceConversation
        )
        if case .text(let text) = decryptedAtAlice {
            XCTAssertEqual(text, "ack-from-bob")
        } else {
            XCTFail("Expected text message at Alice")
        }
    }

    func testCuratedStrictPolicyRequiresCoordinatorQuorum() async throws {
        let federation = FederationDescriptor(mode: .curated, name: "mesh-d")
        let coordinatorAPrivateKey = FederationDirectorySignature.privateKeyData(from: nil)
        let coordinatorAPublicKey = try XCTUnwrap(FederationDirectorySignature.publicKeyData(from: coordinatorAPrivateKey))
        let coordinatorA = RelayEndpoint(
            host: "127.0.0.1",
            port: 39471,
            directorySigningPublicKey: coordinatorAPublicKey
        )
        let coordinatorBPrivateKey = FederationDirectorySignature.privateKeyData(from: nil)
        let coordinatorBPublicKey = try XCTUnwrap(FederationDirectorySignature.publicKeyData(from: coordinatorBPrivateKey))
        let coordinatorB = RelayEndpoint(
            host: "127.0.0.1",
            port: 39472,
            directorySigningPublicKey: coordinatorBPublicKey
        )
        let relayXEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39473)
        let relayYEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39474)

        let coordinatorNodeA = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorDirectorySigningPrivateKey: coordinatorAPrivateKey
            )
        )
        let coordinatorNodeB = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorDirectorySigningPrivateKey: coordinatorBPrivateKey
            )
        )
        let relayX = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .bridge,
                federation: federation,
                federationCoordinatorEndpoints: [coordinatorA, coordinatorB],
                curatedStrictPolicyEnabled: true,
                curatedCoordinatorQuorum: 2,
                curatedRequireSignedDirectory: true,
                federationAllowList: [relayYEndpoint]
            )
        )
        let relayY = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation
            )
        )

        let startedCoordinatorA = expectation(description: "coordinator A started")
        coordinatorNodeA.onEvent = { event in
            if case .started = event {
                startedCoordinatorA.fulfill()
            }
        }
        let startedCoordinatorB = expectation(description: "coordinator B started")
        coordinatorNodeB.onEvent = { event in
            if case .started = event {
                startedCoordinatorB.fulfill()
            }
        }
        let startedX = expectation(description: "relay x strict quorum started")
        relayX.onEvent = { event in
            if case .started = event {
                startedX.fulfill()
            }
        }
        let startedY = expectation(description: "relay y strict quorum started")
        relayY.onEvent = { event in
            if case .started = event {
                startedY.fulfill()
            }
        }

        try coordinatorNodeA.start(host: "0.0.0.0", port: coordinatorA.port)
        try coordinatorNodeB.start(host: "0.0.0.0", port: coordinatorB.port)
        try relayX.start(host: "0.0.0.0", port: relayXEndpoint.port)
        try relayY.start(host: "0.0.0.0", port: relayYEndpoint.port)
        defer {
            relayX.stop()
            relayY.stop()
            coordinatorNodeA.stop()
            coordinatorNodeB.stop()
        }
        await fulfillment(of: [startedCoordinatorA, startedCoordinatorB, startedX, startedY], timeout: 2.0)

        let coordinatorClient = RelayClient(endpoint: coordinatorA)
        _ = try await coordinatorClient.send(
            .registerFederationNode(
                FederationNodeRegistrationRequest(
                    endpoint: relayYEndpoint,
                    relayInfo: RelayConfiguration(
                        kind: .standard,
                        federation: federation
                    ).makeInfo(),
                    ttlSeconds: 120
                )
            )
        )

        let destinationInbox = InboxAddress.generate()
        let envelope = Envelope(
            conversationId: "strict-quorum-test",
            senderFingerprint: "sender-fp",
            sentAt: Date(),
            messageCounter: 1,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x01, count: 12),
                ciphertext: Data([0xAA, 0xBB, 0xCC]),
                tag: Data(repeating: 0x02, count: 16)
            ),
            signature: Data([0xAA])
        )

        let xClient = RelayClient(endpoint: relayXEndpoint)
        let deliverResponse = try await xClient.send(
            .deliver(
                DeliverRequest(
                    inboxId: destinationInbox,
                    routingToken: destinationInbox,
                    envelope: envelope,
                    destinationRelay: relayYEndpoint
                )
            )
        )
        XCTAssertEqual(deliverResponse.type, .error)
        XCTAssertTrue(
            (deliverResponse.error ?? "").localizedCaseInsensitiveContains("quorum"),
            "Expected strict curated quorum failure, got: \(deliverResponse.error ?? "nil")"
        )
    }

    func testAttachmentCryptoRoundTrip() throws {
        let alice = Identity(displayName: "Alice")
        let bob = Identity(displayName: "Bob")
        let bobContact = Contact(
            displayName: "Bob",
            inboxId: "bob-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: bob.signingKey.publicKeyData,
            agreementPublicKey: bob.agreementKey.publicKeyData
        )
        let aliceContact = Contact(
            displayName: "Alice",
            inboxId: "alice-inbox",
            relay: RelayEndpoint(host: "localhost", port: 9339),
            signingPublicKey: alice.signingKey.publicKeyData,
            agreementPublicKey: alice.agreementKey.publicKeyData
        )
        let session = try MessageEngine.createOutboundSession(identity: alice, contact: bobContact)
        var aliceConversation = session.conversation
        var bobConversation = try MessageEngine.createInboundSession(identity: bob, contact: aliceContact, kemCiphertext: session.kemCiphertext)

        let attachmentId = UUID()
        let plaintext = Data("image-bytes".utf8)
        let (counter, messageKey) = try MessageEngine.prepareMessageKey(conversation: &aliceConversation)
        let receiverKey = try bobConversation.receiveChain.messageKey(for: counter)
        let aad = AttachmentCrypto.authenticatedData(
            conversationId: aliceConversation.id,
            sessionId: aliceConversation.sessionId,
            messageCounter: counter,
            attachmentId: attachmentId,
            chunkIndex: 0,
            byteCount: plaintext.count
        )
        let encrypted = try AttachmentCrypto.encryptChunk(
            plaintext: plaintext,
            messageKey: messageKey,
            attachmentId: attachmentId,
            chunkIndex: 0,
            authenticatedData: aad
        )
        let decrypted = try AttachmentCrypto.decryptChunk(
            payload: encrypted,
            messageKey: receiverKey,
            attachmentId: attachmentId,
            chunkIndex: 0,
            authenticatedData: aad
        )
        XCTAssertEqual(decrypted, plaintext)
    }

    func testAttachmentMessageBodyRoundTrip() throws {
        let descriptor = AttachmentDescriptor(
            fileName: "photo.jpg",
            mimeType: "image/jpeg",
            byteCount: 123,
            sha256: Data([0x01, 0x02]),
            chunkCount: 1,
            chunkSize: 123
        )
        let body = MessageBody.attachment(descriptor)
        let data = try PICCPCoder.encode(body)
        let decoded = try PICCPCoder.decode(MessageBody.self, from: data)
        XCTAssertEqual(decoded, body)
    }

    func testFuzzedDeliveryOrderingAndReplays() throws {
        let iterations = 8
        let messageCount = 24

        for seed in 0..<iterations {
            var rng = SeededGenerator(seed: UInt64(seed + 1))
            let alice = Identity(displayName: "Alice")
            let bob = Identity(displayName: "Bob")
            let bobContact = Contact(
                displayName: "Bob",
                inboxId: "bob-inbox",
                relay: RelayEndpoint(host: "localhost", port: 9339),
                signingPublicKey: bob.signingKey.publicKeyData,
                agreementPublicKey: bob.agreementKey.publicKeyData
            )
            let aliceContact = Contact(
                displayName: "Alice",
                inboxId: "alice-inbox",
                relay: RelayEndpoint(host: "localhost", port: 9339),
                signingPublicKey: alice.signingKey.publicKeyData,
                agreementPublicKey: alice.agreementKey.publicKeyData
            )

            let session = try MessageEngine.createOutboundSession(identity: alice, contact: bobContact)
            var aliceConversation = session.conversation
            var bobConversation = try MessageEngine.createInboundSession(
                identity: bob,
                contact: aliceContact,
                kemCiphertext: session.kemCiphertext
            )

            var envelopes: [Envelope] = []
            for index in 0..<messageCount {
                let envelope = try MessageEngine.encrypt(
                    body: .text("msg-\(index)"),
                    senderSigningKey: alice.signingKey,
                    senderFingerprint: alice.fingerprint,
                    conversation: &aliceConversation,
                    kemCiphertext: index == 0 ? session.kemCiphertext : nil
                )
                envelopes.append(envelope)
            }

            var deliveries: [Int] = []
            for index in 0..<messageCount {
                if rng.nextInt(upperBound: 100) < 85 {
                    deliveries.append(index)
                }
                if rng.nextInt(upperBound: 100) < 25 {
                    deliveries.append(index)
                }
            }
            deliveries.shuffle(using: &rng)

            var seen: Set<Int> = []
            for index in deliveries {
                if seen.contains(index) {
                    XCTAssertThrowsError(
                        try MessageEngine.decrypt(
                            envelope: envelopes[index],
                            contact: aliceContact,
                            conversation: &bobConversation
                        )
                    ) { error in
                        XCTAssertEqual(error as? CryptoError, .counterReplay)
                    }
                } else {
                    let body = try MessageEngine.decrypt(
                        envelope: envelopes[index],
                        contact: aliceContact,
                        conversation: &bobConversation
                    )
                    XCTAssertEqual(body, .text("msg-\(index)"))
                    seen.insert(index)
                }
            }
        }
    }

    func testMessageDecodingBackwardsCompatibleWithoutSenderDisplayName() throws {
        let json = """
        {
          "id": "E5C22757-5D8E-4F67-A2C1-73092E5B5E8E",
          "direction": "received",
          "body": "hello",
          "timestamp": "2026-02-16T00:00:00Z",
          "counter": 1,
          "isMismatch": false
        }
        """
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let message = try decoder.decode(Message.self, from: Data(json.utf8))
        XCTAssertNil(message.senderDisplayName)
        XCTAssertEqual(message.body, "hello")
    }

    func testClientStateUpsertContactDeduplicatesAndRemapsReferences() {
        let identity = Identity(displayName: "Owner")
        let relay = RelayEndpoint(host: "relay.example", port: 443, useTLS: true, transport: .http)
        var state = ClientState(identity: identity, relay: relay, inboxId: "owner-inbox")

        let peerIdentity = Identity(displayName: "Peer")
        let sharedSigning = peerIdentity.signingKey.publicKeyData
        let sharedAgreement = peerIdentity.agreementKey.publicKeyData

        let primaryId = UUID()
        let duplicateId = UUID()
        let primary = Contact(
            id: primaryId,
            displayName: "Peer",
            inboxId: "peer-inbox",
            relay: relay,
            signingPublicKey: sharedSigning,
            agreementPublicKey: sharedAgreement,
            allowIdentityReset: true
        )
        let duplicate = Contact(
            id: duplicateId,
            displayName: "Peer Duplicate",
            inboxId: "peer-inbox",
            relay: relay,
            signingPublicKey: sharedSigning,
            agreementPublicKey: sharedAgreement
        )
        state.contacts = [primary, duplicate]

        state.conversations = [
            makeConversation(contactId: primaryId, body: "older", timestamp: Date(timeIntervalSince1970: 10)),
            makeConversation(contactId: duplicateId, body: "newer", timestamp: Date(timeIntervalSince1970: 20))
        ]
        state.groups = [
            GroupConversation(title: "Ops", memberContactIds: [primaryId, duplicateId])
        ]

        let updated = Contact(
            id: UUID(),
            displayName: "Peer Renamed",
            inboxId: "peer-inbox",
            relay: relay,
            signingPublicKey: sharedSigning,
            agreementPublicKey: sharedAgreement
        )
        state.upsert(contact: updated)

        XCTAssertEqual(state.contacts.count, 1)
        XCTAssertEqual(state.contacts[0].id, primaryId)
        XCTAssertEqual(state.contacts[0].displayName, "Peer Renamed")
        XCTAssertTrue(state.contacts[0].allowIdentityReset)

        XCTAssertEqual(state.conversations.count, 1)
        XCTAssertEqual(state.conversations[0].contactId, primaryId)
        XCTAssertEqual(state.conversations[0].messages.last?.body, "newer")

        XCTAssertEqual(state.groups.count, 1)
        XCTAssertEqual(state.groups[0].memberContactIds, [primaryId])
    }

    func testClientStateUpsertContactMatchesByAddressWhenFingerprintChanges() {
        let identity = Identity(displayName: "Owner")
        let relay = RelayEndpoint(host: "relay.example", port: 443, useTLS: true, transport: .http)
        var state = ClientState(identity: identity, relay: relay, inboxId: "owner-inbox")

        let oldIdentity = Identity(displayName: "Peer")
        let newIdentity = Identity(displayName: "Peer")
        let contactId = UUID()

        let existing = Contact(
            id: contactId,
            displayName: "Peer",
            inboxId: "peer-stable-inbox",
            relay: relay,
            signingPublicKey: oldIdentity.signingKey.publicKeyData,
            agreementPublicKey: oldIdentity.agreementKey.publicKeyData
        )
        state.contacts = [existing]
        state.conversations = [makeConversation(contactId: contactId, body: "session", timestamp: Date(timeIntervalSince1970: 30))]

        let incoming = Contact(
            id: UUID(),
            displayName: "Peer Rotated",
            inboxId: "peer-stable-inbox",
            relay: relay,
            signingPublicKey: newIdentity.signingKey.publicKeyData,
            agreementPublicKey: newIdentity.agreementKey.publicKeyData
        )
        state.upsert(contact: incoming)

        XCTAssertEqual(state.contacts.count, 1)
        XCTAssertEqual(state.contacts[0].id, contactId)
        XCTAssertEqual(state.contacts[0].displayName, "Peer Rotated")
        XCTAssertEqual(state.contacts[0].signingPublicKey, newIdentity.signingKey.publicKeyData)
        XCTAssertEqual(state.conversations.count, 1)
        XCTAssertEqual(state.conversations[0].contactId, contactId)
    }

    func testGroupConversationPersistsInClientState() throws {
        let identity = Identity(displayName: "Alice")
        let relay = RelayEndpoint(host: "localhost", port: 9339)
        let group = GroupConversation(
            title: "Team",
            memberContactIds: [UUID(), UUID()],
            messages: [
                Message(
                    direction: .received,
                    senderDisplayName: "Bob",
                    body: "hi",
                    timestamp: Date(timeIntervalSince1970: 100),
                    counter: 1
                )
            ],
            unreadCount: 1,
            createdAt: Date(timeIntervalSince1970: 50)
        )
        var state = ClientState(
            identity: identity,
            relay: relay,
            inboxId: "inbox"
        )
        state.groups = [group]

        let data = try PICCPCoder.encode(state)
        let decoded = try PICCPCoder.decode(ClientState.self, from: data)
        XCTAssertEqual(decoded.groups.count, 1)
        XCTAssertEqual(decoded.groups[0].title, "Team")
        XCTAssertEqual(decoded.groups[0].messages.first?.senderDisplayName, "Bob")
    }

    private func registerAndFetch(
        client: RelayClient,
        inboxId: String,
        accessKey: SigningKeyPair,
        maxCount: Int
    ) async throws -> RelayResponse {
        let identity = Identity(displayName: "Mailbox owner")
        let offer = try MessageEngine.makeContactOffer(
            identity: identity,
            inboxId: inboxId,
            relay: RelayEndpoint(host: "127.0.0.1", port: 9339),
            inboxAccessPublicKey: accessKey.publicKeyData
        )
        var registration = RegisterInboxRequest(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            contactOffer: offer
        )
        let registrationProof = try makeInboxProof(signingKey: accessKey) { proof in
            try registration.signableData(for: proof)
        }
        registration = RegisterInboxRequest(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            contactOffer: offer,
            accessProof: registrationProof
        )
        let registrationResponse = try await client.send(.registerInbox(registration))
        guard registrationResponse.type == .ok else {
            return registrationResponse
        }

        var fetch = FetchRequest(
            inboxId: inboxId,
            routingToken: inboxId,
            maxCount: maxCount
        )
        let fetchProof = try makeInboxProof(signingKey: accessKey) { proof in
            try fetch.signableData(for: proof)
        }
        fetch = FetchRequest(
            inboxId: inboxId,
            routingToken: inboxId,
            maxCount: maxCount,
            accessProof: fetchProof
        )
        return try await client.send(.fetch(fetch))
    }

    private func makeInboxProof(
        signingKey: SigningKeyPair,
        signableDataBuilder: (RelayActorProof) throws -> Data
    ) throws -> RelayActorProof {
        let signedAt = Date()
        let nonce = UUID()
        let fingerprint = CryptoBox.fingerprint(for: signingKey.publicKeyData)
        let placeholder = RelayActorProof(
            fingerprint: fingerprint,
            publicSigningKey: signingKey.publicKeyData,
            signedAt: signedAt,
            nonce: nonce,
            signature: Data()
        )
        return RelayActorProof(
            fingerprint: fingerprint,
            publicSigningKey: signingKey.publicKeyData,
            signedAt: signedAt,
            nonce: nonce,
            signature: try signingKey.sign(signableDataBuilder(placeholder))
        )
    }

    private func makeConversation(contactId: UUID, body: String, timestamp: Date) -> Conversation {
        Conversation(
            id: UUID().uuidString,
            contactId: contactId,
            sessionId: UUID().uuidString,
            rootKey: Data(repeating: 0x11, count: 32),
            rootCounter: 1,
            sendChain: ChainKeyState(keyData: Data(repeating: 0x22, count: 32), counter: 1),
            receiveChain: ChainKeyState(keyData: Data(repeating: 0x33, count: 32), counter: 2),
            messages: [
                Message(
                    direction: .received,
                    body: body,
                    timestamp: timestamp,
                    counter: 1
                )
            ],
            unreadCount: 1,
            ratchetState: .active
        )
    }
}

private struct SeededGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed == 0 ? 0x123456789ABCDEF : seed
    }

    mutating func next() -> UInt64 {
        state = state &* 6364136223846793005 &+ 1
        return state
    }

    mutating func nextInt(upperBound: Int) -> Int {
        guard upperBound > 0 else { return 0 }
        return Int(next() % UInt64(upperBound))
    }
}

private extension Array {
    mutating func shuffle(using generator: inout SeededGenerator) {
        guard count > 1 else { return }
        for index in stride(from: count - 1, through: 1, by: -1) {
            let swapIndex = generator.nextInt(upperBound: index + 1)
            if swapIndex != index {
                swapAt(index, swapIndex)
            }
        }
    }
}

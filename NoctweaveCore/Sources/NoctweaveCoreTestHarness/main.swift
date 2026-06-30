import CoreImage
import CoreImage.CIFilterBuiltins
import Foundation
import NoctweaveCore

@main
struct NoctweaveCoreTestHarness {
    static func main() async {
        var runner = TestRunner()
        await runner.run()
        runner.finish()
    }
}

private struct TestRunner {
    private var failures: [String] = []

    mutating func run() async {
        await testTwoClientRelayFlow()
        await testRelayServerHealthIfAvailable()
        await testRelayServerIntegrationIfAvailable()
        await testInsecurePairingIfAvailable()
        await testAutoHealSessionMismatchIfAvailable()
        testQRCodeGeneration()
        testInboxAddressGeneration()
        testIdentityResetFlow()
        testSessionResetFlow()
        testQRChunking()
        testSimultaneousInitiation()
    }

    mutating func finish() {
        if failures.isEmpty {
            print("All tests passed.")
            return
        }
        for failure in failures {
            fputs("FAIL: \(failure)\n", stderr)
        }
        exit(1)
    }

    private mutating func testTwoClientRelayFlow() async {
        do {
            let messageText = "Hello Bob"
            let alice = Identity(displayName: "Alice")
            let bob = Identity(displayName: "Bob")

            let bobContact = Contact(
                displayName: bob.displayName,
                inboxId: "bob-inbox",
                relay: RelayEndpoint(host: "relay.local", port: 9339),
                signingPublicKey: bob.signingKey.publicKeyData,
                agreementPublicKey: bob.agreementKey.publicKeyData
            )
            let aliceContact = Contact(
                displayName: alice.displayName,
                inboxId: "alice-inbox",
                relay: RelayEndpoint(host: "relay.local", port: 9339),
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
                body: .text(messageText),
                senderSigningKey: alice.signingKey,
                senderFingerprint: alice.fingerprint,
                conversation: &aliceConversation,
                kemCiphertext: session.kemCiphertext
            )

            check(envelope.kemCiphertext == session.kemCiphertext, "Envelope should include KEM ciphertext on first message.")
            check(envelope.sessionId == session.conversation.sessionId, "Envelope sessionId should match conversation session.")

            let deliverRequest = RelayRequest.deliver(DeliverRequest(inboxId: bobContact.inboxId, envelope: envelope))
            let requestData = try NoctweaveCoder.encode(deliverRequest)
            let requestString = String(data: requestData, encoding: .utf8) ?? ""

            check(!requestString.contains(messageText), "Plaintext must not appear in encoded relay request.")
            check(requestString.contains("\"ciphertext\""), "Relay request must contain encrypted payload.")

            let decodedRequest = try NoctweaveCoder.decode(RelayRequest.self, from: requestData)
            check(decodedRequest.type == .deliver, "Relay request should decode as deliver.")
            check(decodedRequest.deliver?.inboxId == bobContact.inboxId, "Relay request inbox should round trip.")
            let decodedEnvelope = decodedRequest.deliver?.envelope
            check(decodedEnvelope?.senderFingerprint == envelope.senderFingerprint, "Envelope sender should round trip.")
            check(decodedEnvelope?.messageCounter == envelope.messageCounter, "Envelope counter should round trip.")

            let store = RelayStore()
            let storedCount = try await store.deliver(envelope, to: bobContact.inboxId)
            check(storedCount == 1, "Relay store should contain one envelope after deliver.")

            let fetchRequest = RelayRequest.fetch(FetchRequest(inboxId: bobContact.inboxId))
            let fetchData = try NoctweaveCoder.encode(fetchRequest)
            _ = try NoctweaveCoder.decode(RelayRequest.self, from: fetchData)

            let fetched = try await store.fetch(inboxId: bobContact.inboxId)
            guard let fetchedEnvelope = fetched.first else {
                fail("Relay store returned no envelopes.")
                return
            }

            check(fetchedEnvelope.verifySignature(publicSigningKey: alice.signingKey.publicKeyData), "Envelope signature must verify.")

            let body = try MessageEngine.decrypt(
                envelope: fetchedEnvelope,
                contact: aliceContact,
                conversation: &bobConversation
            )
            check(body == .text(messageText), "Decrypted message should match original plaintext.")
        } catch {
            fail("Two-client relay flow failed: \(error.localizedDescription)")
        }
    }

    private mutating func testQRCodeGeneration() {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data("NOCTWEAVE-UI-QR-Test".utf8)
        let output = filter.outputImage
        check(output != nil, "QR code generator should produce an output image.")
    }

    private mutating func testInboxAddressGeneration() {
        let address = InboxAddress.generate()
        check(address.hasPrefix("\(InboxAddress.hrp)1"), "Inbox address should include bech32 HRP.")
        check(InboxAddress.isValid(address), "Generated inbox address should validate.")
        let decoded = InboxAddress.decode(address)
        check(decoded?.count == 32, "Inbox address should decode to 32 bytes.")
    }

    private mutating func testIdentityResetFlow() {
        do {
            let alice = Identity(displayName: "Alice")
            let bob = Identity(displayName: "Bob")
            let relay = RelayEndpoint(host: "relay.local", port: 9339)

            var aliceContact = Contact(
                displayName: alice.displayName,
                inboxId: "alice-inbox-old",
                relay: relay,
                signingPublicKey: alice.signingKey.publicKeyData,
                agreementPublicKey: alice.agreementKey.publicKeyData
            )

            let newIdentity = Identity(displayName: "Alice")
            let newInbox = InboxAddress.generate()
            let offer = try MessageEngine.makeContactOffer(identity: newIdentity, inboxId: newInbox, relay: relay)
            let reset = try IdentityReset.create(newOffer: offer, signingKey: alice.signingKey)
            check(reset.verify(using: alice.signingKey.publicKeyData), "Identity reset should verify with old signing key.")

            let applied = aliceContact.apply(reset: reset)
            check(applied, "Contact should accept identity reset.")
            check(aliceContact.inboxId == newInbox, "Contact inbox should update on reset.")
            check(aliceContact.signingPublicKey == newIdentity.signingKey.publicKeyData, "Contact signing key should update on reset.")

            let bobContact = Contact(
                displayName: bob.displayName,
                inboxId: "bob-inbox",
                relay: relay,
                signingPublicKey: bob.signingKey.publicKeyData,
                agreementPublicKey: bob.agreementKey.publicKeyData
            )
            let session = try MessageEngine.createOutboundSession(identity: bob, contact: aliceContact)
            var bobConversation = session.conversation
            var aliceConversation = try MessageEngine.createInboundSession(
                identity: newIdentity,
                contact: bobContact,
                kemCiphertext: session.kemCiphertext
            )

            let envelope = try MessageEngine.encrypt(
                body: .text("After reset"),
                senderSigningKey: bob.signingKey,
                senderFingerprint: bob.fingerprint,
                conversation: &bobConversation,
                kemCiphertext: session.kemCiphertext
            )

            let body = try MessageEngine.decrypt(
                envelope: envelope,
                contact: bobContact,
                conversation: &aliceConversation
            )
            check(body == .text("After reset"), "Post-reset session should decrypt messages.")
        } catch {
            fail("Identity reset flow failed: \(error.localizedDescription)")
        }
    }

    private mutating func testSessionResetFlow() {
        do {
            let alice = Identity(displayName: "Alice")
            let bob = Identity(displayName: "Bob")
            let relay = RelayEndpoint(host: "relay.local", port: 9339)

            let bobContact = Contact(
                displayName: bob.displayName,
                inboxId: "bob-inbox",
                relay: relay,
                signingPublicKey: bob.signingKey.publicKeyData,
                agreementPublicKey: bob.agreementKey.publicKeyData
            )
            let aliceContact = Contact(
                displayName: alice.displayName,
                inboxId: "alice-inbox",
                relay: relay,
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

            let hello = try MessageEngine.encrypt(
                body: .text("Hello"),
                senderSigningKey: alice.signingKey,
                senderFingerprint: alice.fingerprint,
                conversation: &aliceConversation,
                kemCiphertext: initialSession.kemCiphertext
            )
            _ = try MessageEngine.decrypt(envelope: hello, contact: aliceContact, conversation: &bobConversation)

            let resetSession = try MessageEngine.createOutboundSession(identity: alice, contact: bobContact)
            var aliceResetConversation = resetSession.conversation
            let resetEnvelope = try MessageEngine.encrypt(
                body: .sessionReset(SessionReset()),
                senderSigningKey: alice.signingKey,
                senderFingerprint: alice.fingerprint,
                conversation: &aliceResetConversation,
                kemCiphertext: resetSession.kemCiphertext
            )

            var bobResetConversation = try MessageEngine.createInboundSession(
                identity: bob,
                contact: aliceContact,
                kemCiphertext: resetSession.kemCiphertext
            )
            let resetBody = try MessageEngine.decrypt(envelope: resetEnvelope, contact: aliceContact, conversation: &bobResetConversation)
            if case .sessionReset = resetBody {
                // expected
            } else {
                fail("Session reset should decode as sessionReset.")
                return
            }

            bobConversation = bobResetConversation

            var aliceNewConversation = aliceResetConversation
            let followUp = try MessageEngine.encrypt(
                body: .text("After reset"),
                senderSigningKey: alice.signingKey,
                senderFingerprint: alice.fingerprint,
                conversation: &aliceNewConversation,
                kemCiphertext: resetSession.kemCiphertext
            )

            let followUpBody = try MessageEngine.decrypt(
                envelope: followUp,
                contact: aliceContact,
                conversation: &bobConversation
            )
            check(followUpBody == .text("After reset"), "Session reset should allow decrypting new session messages.")
        } catch {
            fail("Session reset flow failed: \(error.localizedDescription)")
        }
    }

    private mutating func testQRChunking() {
        let message = String(repeating: "Noctweave", count: 400)
        let frames = QRCodeTransfer.encodeFrames(message, maxChunkSize: 120)
        check(frames.count > 1, "QR chunking should split long messages.")

        var collector = QRChunkCollector()
        var result: QRChunkResult = .invalid
        for frame in frames {
            result = collector.consume(frame)
        }
        switch result {
        case .complete(let decoded):
            check(decoded == message, "QR chunking should reassemble the original message.")
        default:
            fail("QR chunking did not complete.")
        }
    }

    private mutating func testSimultaneousInitiation() {
        do {
            let alice = Identity(displayName: "Alice")
            let bob = Identity(displayName: "Bob")
            let relay = RelayEndpoint(host: "relay.local", port: 9339)

            let bobContact = Contact(
                displayName: bob.displayName,
                inboxId: "bob-inbox",
                relay: relay,
                signingPublicKey: bob.signingKey.publicKeyData,
                agreementPublicKey: bob.agreementKey.publicKeyData
            )
            let aliceContact = Contact(
                displayName: alice.displayName,
                inboxId: "alice-inbox",
                relay: relay,
                signingPublicKey: alice.signingKey.publicKeyData,
                agreementPublicKey: alice.agreementKey.publicKeyData
            )

            let aliceSession = try MessageEngine.createOutboundSession(identity: alice, contact: bobContact)
            let bobSession = try MessageEngine.createOutboundSession(identity: bob, contact: aliceContact)

            var aliceConversation = aliceSession.conversation
            var bobConversation = bobSession.conversation

            let aliceEnvelope = try MessageEngine.encrypt(
                body: .text("Hi Bob"),
                senderSigningKey: alice.signingKey,
                senderFingerprint: alice.fingerprint,
                conversation: &aliceConversation,
                kemCiphertext: aliceSession.kemCiphertext
            )
            let bobEnvelope = try MessageEngine.encrypt(
                body: .text("Hi Alice"),
                senderSigningKey: bob.signingKey,
                senderFingerprint: bob.fingerprint,
                conversation: &bobConversation,
                kemCiphertext: bobSession.kemCiphertext
            )

            let aliceInbound = try MessageEngine.createInboundSession(identity: alice, contact: bobContact, kemCiphertext: bobSession.kemCiphertext)
            let bobInbound = try MessageEngine.createInboundSession(identity: bob, contact: aliceContact, kemCiphertext: aliceSession.kemCiphertext)

            var aliceInboundConversation = aliceInbound
            var bobInboundConversation = bobInbound

            let aliceBody = try MessageEngine.decrypt(envelope: bobEnvelope, contact: bobContact, conversation: &aliceInboundConversation)
            let bobBody = try MessageEngine.decrypt(envelope: aliceEnvelope, contact: aliceContact, conversation: &bobInboundConversation)

            check(aliceBody == .text("Hi Alice"), "Alice should decrypt Bob's simultaneous message.")
            check(bobBody == .text("Hi Bob"), "Bob should decrypt Alice's simultaneous message.")
        } catch {
            fail("Simultaneous initiation failed: \(error.localizedDescription)")
        }
    }

    private mutating func testRelayServerIntegrationIfAvailable() async {
        guard
            let host = ProcessInfo.processInfo.environment["NOCTWEAVE_TEST_SERVER_HOST"],
            let portString = ProcessInfo.processInfo.environment["NOCTWEAVE_TEST_SERVER_PORT"],
            let port = UInt16(portString)
        else {
            print("Skipping relay server integration test (set NOCTWEAVE_TEST_SERVER_HOST/PORT).")
            return
        }

        do {
            let alice = Identity(displayName: "Alice")
            let bob = Identity(displayName: "Bob")

            let relay = RelayEndpoint(host: host, port: port)
            let bobContact = Contact(
                displayName: bob.displayName,
                inboxId: "bob-inbox-integration",
                relay: relay,
                signingPublicKey: bob.signingKey.publicKeyData,
                agreementPublicKey: bob.agreementKey.publicKeyData
            )
            let aliceContact = Contact(
                displayName: alice.displayName,
                inboxId: "alice-inbox-integration",
                relay: relay,
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
                body: .text("Hello from integration"),
                senderSigningKey: alice.signingKey,
                senderFingerprint: alice.fingerprint,
                conversation: &aliceConversation,
                kemCiphertext: session.kemCiphertext
            )

            let client = RelayClient(endpoint: relay)
            _ = try await client.send(.deliver(DeliverRequest(inboxId: bobContact.inboxId, envelope: envelope)))
            let response = try await client.send(.fetch(FetchRequest(inboxId: bobContact.inboxId)))

            guard response.type == .messages, let messages = response.messages, let received = messages.first else {
                fail("Relay server did not return messages.")
                return
            }

            let body = try MessageEngine.decrypt(
                envelope: received,
                contact: aliceContact,
                conversation: &bobConversation
            )
            check(body == .text("Hello from integration"), "Relay server should deliver decryptable message.")
        } catch {
            fail("Relay server integration failed: \(error.localizedDescription)")
        }
    }

    private mutating func testRelayServerHealthIfAvailable() async {
        guard
            let host = ProcessInfo.processInfo.environment["NOCTWEAVE_TEST_SERVER_HOST"],
            let portString = ProcessInfo.processInfo.environment["NOCTWEAVE_TEST_SERVER_PORT"],
            let port = UInt16(portString)
        else {
            print("Skipping relay health test (set NOCTWEAVE_TEST_SERVER_HOST/PORT).")
            return
        }

        do {
            let relay = RelayEndpoint(host: host, port: port)
            let client = RelayClient(endpoint: relay)
            let response = try await client.send(.health())
            check(response.type == .ok, "Relay health should return ok.")
        } catch {
            fail("Relay health failed: \(error.localizedDescription)")
        }
    }

    private mutating func testInsecurePairingIfAvailable() async {
        guard
            let host = ProcessInfo.processInfo.environment["NOCTWEAVE_TEST_SERVER_HOST"],
            let portString = ProcessInfo.processInfo.environment["NOCTWEAVE_TEST_SERVER_PORT"],
            let port = UInt16(portString)
        else {
            print("Skipping insecure pairing test (set NOCTWEAVE_TEST_SERVER_HOST/PORT).")
            return
        }

        do {
            let relay = RelayEndpoint(host: host, port: port)
            let alice = Identity(displayName: "Alice")
            let bob = Identity(displayName: "Bob")
            let aliceOffer = try MessageEngine.makeContactOffer(identity: alice, inboxId: "alice-pair", relay: relay)
            let bobOffer = try MessageEngine.makeContactOffer(identity: bob, inboxId: "bob-pair", relay: relay)
            let client = RelayClient(endpoint: relay)

            let announceAlice = try await client.send(.announce(AnnounceRequest(offer: aliceOffer, ttlSeconds: 120)))
            check(announceAlice.type == .announcements, "Announce should return announcements.")
            let announceBob = try await client.send(.announce(AnnounceRequest(offer: bobOffer, ttlSeconds: 120)))
            check(announceBob.type == .announcements, "Announce should return announcements.")

            let list = try await client.send(.listAnnouncements(ListAnnouncementsRequest(limit: 50)))
            guard list.type == .announcements, let announcements = list.announcements else {
                fail("Insecure pairing list should return announcements.")
                return
            }
            let fingerprints = Set(announcements.map { $0.offer.fingerprint })
            check(fingerprints.contains(alice.fingerprint), "Announcements should include Alice.")
            check(fingerprints.contains(bob.fingerprint), "Announcements should include Bob.")

            var sendPairRequest = SendPairRequest(
                targetFingerprint: bob.fingerprint,
                offer: aliceOffer
            )
            let signedAt = Date()
            let nonce = UUID()
            let placeholder = RelayActorProof(
                fingerprint: alice.fingerprint,
                publicSigningKey: alice.signingKey.publicKeyData,
                signedAt: signedAt,
                nonce: nonce,
                signature: Data()
            )
            let proof = RelayActorProof(
                fingerprint: alice.fingerprint,
                publicSigningKey: alice.signingKey.publicKeyData,
                signedAt: signedAt,
                nonce: nonce,
                signature: try alice.signingKey.sign(sendPairRequest.signableData(for: placeholder))
            )
            sendPairRequest = SendPairRequest(
                targetFingerprint: bob.fingerprint,
                offer: aliceOffer,
                actorProof: proof
            )
            let sendPair = try await client.send(.sendPairRequest(sendPairRequest))
            check(sendPair.type == .ok, "Send pair request should return ok.")

            var fetchRequest = FetchPairRequestsRequest(
                fingerprint: bob.fingerprint,
                maxCount: 10
            )
            let fetchSignedAt = Date()
            let fetchNonce = UUID()
            let fetchPlaceholder = RelayActorProof(
                fingerprint: bob.fingerprint,
                publicSigningKey: bob.signingKey.publicKeyData,
                signedAt: fetchSignedAt,
                nonce: fetchNonce,
                signature: Data()
            )
            let fetchProof = RelayActorProof(
                fingerprint: bob.fingerprint,
                publicSigningKey: bob.signingKey.publicKeyData,
                signedAt: fetchSignedAt,
                nonce: fetchNonce,
                signature: try bob.signingKey.sign(fetchRequest.signableData(for: fetchPlaceholder))
            )
            fetchRequest = FetchPairRequestsRequest(
                fingerprint: bob.fingerprint,
                maxCount: 10,
                actorProof: fetchProof
            )
            let fetch = try await client.send(.fetchPairRequests(fetchRequest))
            guard fetch.type == .pairRequests, let requests = fetch.pairRequests else {
                fail("Fetch pair requests should return pairRequests.")
                return
            }
            let requestFingerprints = Set(requests.map { $0.from.fingerprint })
            check(requestFingerprints.contains(alice.fingerprint), "Pair requests should include Alice offer.")
        } catch {
            fail("Insecure pairing test failed: \(error.localizedDescription)")
        }
    }

    private mutating func testAutoHealSessionMismatchIfAvailable() async {
        guard
            let host = ProcessInfo.processInfo.environment["NOCTWEAVE_TEST_SERVER_HOST"],
            let portString = ProcessInfo.processInfo.environment["NOCTWEAVE_TEST_SERVER_PORT"],
            let port = UInt16(portString)
        else {
            print("Skipping auto-heal test (set NOCTWEAVE_TEST_SERVER_HOST/PORT).")
            return
        }

        do {
            let relay = RelayEndpoint(host: host, port: port)
            let alice = Identity(displayName: "Alice")
            let bob = Identity(displayName: "Bob")

            let aliceContact = Contact(
                displayName: alice.displayName,
                inboxId: "alice-autoheal",
                relay: relay,
                signingPublicKey: alice.signingKey.publicKeyData,
                agreementPublicKey: alice.agreementKey.publicKeyData
            )
            let bobContact = Contact(
                displayName: bob.displayName,
                inboxId: "bob-autoheal",
                relay: relay,
                signingPublicKey: bob.signingKey.publicKeyData,
                agreementPublicKey: bob.agreementKey.publicKeyData
            )

            let session1 = try MessageEngine.createOutboundSession(identity: alice, contact: bobContact)
            var aliceConversation = session1.conversation
            var bobConversation = try MessageEngine.createInboundSession(
                identity: bob,
                contact: aliceContact,
                kemCiphertext: session1.kemCiphertext
            )

            let firstEnvelope = try MessageEngine.encrypt(
                body: .text("Init"),
                senderSigningKey: alice.signingKey,
                senderFingerprint: alice.fingerprint,
                conversation: &aliceConversation,
                kemCiphertext: session1.kemCiphertext
            )

            let client = RelayClient(endpoint: relay)
            _ = try await client.send(.deliver(DeliverRequest(inboxId: bobContact.inboxId, envelope: firstEnvelope)))

            let firstResponse = try await client.send(.fetch(FetchRequest(inboxId: bobContact.inboxId)))
            guard let receivedFirst = firstResponse.messages?.first else {
                fail("Auto-heal test: missing initial message.")
                return
            }
            _ = try MessageEngine.decrypt(envelope: receivedFirst, contact: aliceContact, conversation: &bobConversation)

            let oldEnvelope = try MessageEngine.encrypt(
                body: .text("Old session"),
                senderSigningKey: alice.signingKey,
                senderFingerprint: alice.fingerprint,
                conversation: &aliceConversation,
                kemCiphertext: nil
            )
            _ = try await client.send(.deliver(DeliverRequest(inboxId: bobContact.inboxId, envelope: oldEnvelope)))

            let bobNewSession = try MessageEngine.createOutboundSession(identity: bob, contact: aliceContact)
            bobConversation = bobNewSession.conversation

            let healedConversation = try await SessionRecovery.sendSessionResetAndResendRequest(
                identity: bob,
                contact: aliceContact,
                existingConversation: bobConversation,
                preferredRelay: relay,
                resendCount: 1
            )

            let resetResponse = try await client.send(.fetch(FetchRequest(inboxId: aliceContact.inboxId)))
            guard let resetEnvelopes = resetResponse.messages, resetEnvelopes.count >= 2 else {
                fail("Auto-heal test: missing reset/resend envelopes.")
                return
            }
            let resetEnvelope = resetEnvelopes[0]
            guard let resetKem = resetEnvelope.kemCiphertext else {
                fail("Auto-heal test: reset missing KEM ciphertext.")
                return
            }
            var aliceInbound = try MessageEngine.createInboundSession(
                identity: alice,
                contact: bobContact,
                kemCiphertext: resetKem
            )
            let resetBody = try MessageEngine.decrypt(
                envelope: resetEnvelope,
                contact: bobContact,
                conversation: &aliceInbound
            )
            guard case .sessionReset = resetBody else {
                fail("Auto-heal test: reset body did not decode.")
                return
            }
            let resendEnvelope = resetEnvelopes[1]
            let resendBody = try MessageEngine.decrypt(
                envelope: resendEnvelope,
                contact: bobContact,
                conversation: &aliceInbound
            )
            guard case .resendRequest = resendBody else {
                fail("Auto-heal test: resend request did not decode.")
                return
            }

            var bobHealedConversation = healedConversation
            let followUp = try MessageEngine.encrypt(
                body: .text("After heal"),
                senderSigningKey: bob.signingKey,
                senderFingerprint: bob.fingerprint,
                conversation: &bobHealedConversation,
                kemCiphertext: nil
            )
            _ = try await client.send(.deliver(DeliverRequest(inboxId: aliceContact.inboxId, envelope: followUp)))

            let followResponse = try await client.send(.fetch(FetchRequest(inboxId: aliceContact.inboxId)))
            guard let followEnvelope = followResponse.messages?.first else {
                fail("Auto-heal test: missing follow-up message.")
                return
            }
            let followBody = try MessageEngine.decrypt(
                envelope: followEnvelope,
                contact: bobContact,
                conversation: &aliceInbound
            )
            check(followBody == .text("After heal"), "Auto-heal follow-up should decrypt on new session.")
        } catch {
            fail("Auto-heal test failed: \(error.localizedDescription)")
        }
    }

    private mutating func check(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() {
            fail(message)
        }
    }

    private mutating func fail(_ message: String) {
        failures.append(message)
    }
}

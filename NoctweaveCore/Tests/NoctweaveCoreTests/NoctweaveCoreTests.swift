import Foundation
import CryptoKit
import SQLite3
import XCTest
@testable import NoctweaveCore

final class NoctweaveCoreTests: XCTestCase {
    func testAppendMessagePreservesEnvelopeIdentifier() {
        var conversation = Conversation(
            id: "conversation",
            contactId: UUID(),
            sessionId: "session",
            sendChain: ChainKeyState(keyData: Data(repeating: 1, count: 32)),
            receiveChain: ChainKeyState(keyData: Data(repeating: 2, count: 32))
        )
        let envelopeId = UUID()

        let message = MessageEngine.appendMessage(
            id: envelopeId,
            body: .text("deduplicated"),
            direction: .received,
            counter: 7,
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            conversation: &conversation
        )

        XCTAssertEqual(message?.id, envelopeId)
        XCTAssertEqual(conversation.messages.map(\.id), [envelopeId])
    }

    func testMetadataMinimizerBucketsVisibleTimestamps() {
        let precise = Date(timeIntervalSince1970: 1_765_400_123)

        XCTAssertEqual(
            MetadataMinimizer.bucketedTimestamp(precise, bucketSeconds: 300),
            Date(timeIntervalSince1970: 1_765_400_100)
        )
        XCTAssertEqual(MetadataMinimizer.bucketedTimestamp(precise, bucketSeconds: 1), precise)
        XCTAssertEqual(MetadataMinimizer.bucketedTimestamp(precise, bucketSeconds: nil), precise)
    }

    func testHiddenRetrievalPlannerBuildsDeterministicCoverQuery() throws {
        let records = ["msg-4", "msg-1", "msg-3", "msg-2", "msg-5"]
        let secret = Data("client-local-cover-secret".utf8)

        let first = try HiddenRetrievalPlanner.makeCoverQuery(
            bucketId: "bucket-2026-06-25T10:00",
            availableRecordIds: records,
            targetRecordId: "msg-3",
            coverSetSize: 3,
            secret: secret
        )
        let second = try HiddenRetrievalPlanner.makeCoverQuery(
            bucketId: "bucket-2026-06-25T10:00",
            availableRecordIds: records.reversed(),
            targetRecordId: "msg-3",
            coverSetSize: 3,
            secret: secret
        )

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.bucketId, "bucket-2026-06-25T10:00")
        XCTAssertEqual(first.requestedRecordIds.count, 3)
        XCTAssertTrue(first.requestedRecordIds.contains("msg-3"))
        XCTAssertNotNil(first.targetOffset)
        XCTAssertEqual(first.requestedRecordIds, first.requestedRecordIds.sorted())
    }

    func testHeadlessMessagingClientExchangesDirectMessagesThroughRelay() async throws {
        let port = UInt16.random(in: 45_000...49_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(store: RelayStore())
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 250_000_000)

        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-headless-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let aliceURL = root.appendingPathComponent("alice.json")
        let bobURL = root.appendingPathComponent("bob.json")
        let alice = HeadlessMessagingClient(stateURL: aliceURL, useEncryptedStore: false, timeout: 3)
        let bob = HeadlessMessagingClient(stateURL: bobURL, useEncryptedStore: false, timeout: 3)

        let aliceStatus = try await alice.createState(displayName: "Alice CLI", relay: endpoint)
        let bobStatus = try await bob.createState(displayName: "Bob CLI", relay: endpoint)
        XCTAssertEqual(aliceStatus.contactCount, 0)
        XCTAssertEqual(bobStatus.contactCount, 0)

        try await alice.registerInbox()
        try await bob.registerInbox()

        let aliceCode = try await alice.exportContactCode()
        let bobCode = try await bob.exportContactCode()
        let importedBob = try await alice.importContactCode(bobCode)
        let importedAlice = try await bob.importContactCode(aliceCode)
        XCTAssertEqual(importedBob.displayName, "Bob CLI")
        XCTAssertEqual(importedAlice.displayName, "Alice CLI")

        let sent = try await alice.sendText(to: "Bob CLI", text: "hello from headless")
        XCTAssertEqual(sent.messageCounter, 0)

        let received = try await bob.receive(maxCount: 10)
        XCTAssertEqual(received.count, 1)
        XCTAssertEqual(received[0].contact.displayName, "Alice CLI")
        XCTAssertEqual(received[0].body, .text("hello from headless"))

        let bobReloaded = HeadlessMessagingClient(stateURL: bobURL, useEncryptedStore: false, timeout: 3)
        let contacts = try await bobReloaded.contacts()
        let status = try await bobReloaded.status()
        XCTAssertEqual(contacts.count, 1)
        XCTAssertEqual(status.conversationCount, 1)
    }

    func testHeadlessMessagingClientSerializesConcurrentMultiContactBursts() async throws {
        let port = UInt16.random(in: 40_000...41_999)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(store: RelayStore())
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 250_000_000)

        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-headless-concurrent-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let alice = HeadlessMessagingClient(
            stateURL: root.appendingPathComponent("alice.json"),
            useEncryptedStore: false,
            timeout: 3
        )
        let bob = HeadlessMessagingClient(
            stateURL: root.appendingPathComponent("bob.json"),
            useEncryptedStore: false,
            timeout: 3
        )
        let carol = HeadlessMessagingClient(
            stateURL: root.appendingPathComponent("carol.json"),
            useEncryptedStore: false,
            timeout: 3
        )

        _ = try await alice.createState(displayName: "Alice Burst", relay: endpoint)
        _ = try await bob.createState(displayName: "Bob Burst", relay: endpoint)
        _ = try await carol.createState(displayName: "Carol Burst", relay: endpoint)
        try await alice.registerInbox()
        try await bob.registerInbox()
        try await carol.registerInbox()

        let aliceCode = try await alice.exportContactCode()
        let bobCode = try await bob.exportContactCode()
        let carolCode = try await carol.exportContactCode()
        _ = try await alice.importContactCode(bobCode)
        _ = try await alice.importContactCode(carolCode)
        _ = try await bob.importContactCode(aliceCode)
        _ = try await carol.importContactCode(aliceCode)

        _ = try await alice.sendText(to: "Bob Burst", text: "bootstrap bob")
        _ = try await bob.receive(maxCount: 10)
        _ = try await bob.sendText(to: "Alice Burst", text: "bootstrap alice from bob")
        _ = try await alice.receive(maxCount: 10)
        _ = try await alice.sendText(to: "Carol Burst", text: "bootstrap carol")
        _ = try await carol.receive(maxCount: 10)
        _ = try await carol.sendText(to: "Alice Burst", text: "bootstrap alice from carol")
        _ = try await alice.receive(maxCount: 10)

        @Sendable func burst(
            client: HeadlessMessagingClient,
            selector: String,
            prefix: String,
            count: Int
        ) async throws -> [HeadlessSentMessage] {
            try await withThrowingTaskGroup(of: HeadlessSentMessage.self) { group in
                for index in 0..<count {
                    group.addTask {
                        try await client.sendText(to: selector, text: "\(prefix)-\(index)")
                    }
                }
                var sent: [HeadlessSentMessage] = []
                for try await message in group {
                    sent.append(message)
                }
                return sent
            }
        }

        async let aliceToBob = burst(client: alice, selector: "Bob Burst", prefix: "a-b", count: 6)
        async let aliceToCarol = burst(client: alice, selector: "Carol Burst", prefix: "a-c", count: 6)
        async let bobToAlice = burst(client: bob, selector: "Alice Burst", prefix: "b-a", count: 6)
        async let carolToAlice = burst(client: carol, selector: "Alice Burst", prefix: "c-a", count: 6)
        let sent = try await (aliceToBob, aliceToCarol, bobToAlice, carolToAlice)

        for messages in [sent.0, sent.1, sent.2, sent.3] {
            XCTAssertEqual(messages.map(\.messageCounter).sorted(), Array(1...6).map(UInt64.init))
        }

        let bobReceived = try await bob.receive(maxCount: 100)
        let carolReceived = try await carol.receive(maxCount: 100)
        let aliceReceived = try await alice.receive(maxCount: 100)
        XCTAssertEqual(bobReceived.count, 6)
        XCTAssertEqual(carolReceived.count, 6)
        XCTAssertEqual(aliceReceived.count, 12)
        func textBodies(_ messages: [HeadlessReceivedMessage]) -> Set<String> {
            Set(messages.compactMap { message in
                guard case .text(let text) = message.body else { return nil }
                return text
            })
        }
        XCTAssertEqual(textBodies(bobReceived), Set((0..<6).map { "a-b-\($0)" }))
        XCTAssertEqual(textBodies(carolReceived), Set((0..<6).map { "a-c-\($0)" }))
        XCTAssertEqual(
            textBodies(aliceReceived),
            Set((0..<6).map { "b-a-\($0)" } + (0..<6).map { "c-a-\($0)" })
        )
    }


    func testRelayClientDoesNotFallbackAcrossConfiguredTransports() async throws {
        let port = UInt16.random(in: 42_000...44_999)
        let rawTCPEndpoint = RelayEndpoint(host: "127.0.0.1", port: port, transport: .tcp)
        let httpEndpoint = RelayEndpoint(host: "127.0.0.1", port: port, transport: .http)
        let server = RelayServer(store: RelayStore())
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 250_000_000)

        let tcpResponse = try await RelayClient(endpoint: rawTCPEndpoint).send(.health(), timeout: 2)
        XCTAssertEqual(tcpResponse.type, .ok)

        do {
            _ = try await RelayClient(endpoint: httpEndpoint).send(.health(), timeout: 2)
            XCTFail("HTTP-configured clients must not silently retry raw TCP.")
        } catch {
            // Expected: the server is raw TCP only, so the HTTP request must fail
            // instead of being retried over a different transport.
        }
    }

    func testRelayClientTLSObservationIsNilForPlaintextTransport() async throws {
        let port = UInt16.random(in: 42_000...44_999)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port, transport: .tcp)
        let server = RelayServer(store: RelayStore())
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 250_000_000)

        let observation = try await RelayClient(endpoint: endpoint).sendObservingTLS(.health(), timeout: 2)
        XCTAssertEqual(observation.response.type, .ok)
        XCTAssertNil(observation.leafCertificateSHA256)
    }

    func testLiveTLSObservationAndPinEnforcementWhenConfigured() async throws {
        guard let value = ProcessInfo.processInfo.environment["NOCTWEAVE_LIVE_TLS_RELAY"],
              !value.isEmpty else {
            throw XCTSkip("Set NOCTWEAVE_LIVE_TLS_RELAY to run the live TLS pin test.")
        }
        var endpoint = try RelayEndpointParser.parse(value)
        guard endpoint.useTLS else {
            XCTFail("NOCTWEAVE_LIVE_TLS_RELAY must use TLS.")
            return
        }

        let observation = try await RelayClient(endpoint: endpoint).sendObservingTLS(.info(), timeout: 8)
        XCTAssertEqual(observation.response.type, .info)
        let fingerprint = try XCTUnwrap(observation.leafCertificateSHA256)
        XCTAssertEqual(fingerprint.count, 32)

        endpoint.tlsCertificateFingerprintSHA256 = fingerprint
        let pinnedResponse = try await RelayClient(endpoint: endpoint).send(.info(), timeout: 8)
        XCTAssertEqual(pinnedResponse.type, .info)

        endpoint.tlsCertificateFingerprintSHA256 = Data(repeating: 0xFF, count: 32)
        do {
            _ = try await RelayClient(endpoint: endpoint).send(.info(), timeout: 8)
            XCTFail("A mismatched TLS certificate pin must fail closed.")
        } catch {
            // Expected.
        }
    }

    func testRelayClientRejectsUnsafeConfigurationBeforeNetworking() async throws {
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: 9)

        for timeout in [TimeInterval.nan, .infinity, 0, 301] {
            do {
                _ = try await RelayClient(endpoint: endpoint).send(.health(), timeout: timeout)
                XCTFail("Expected invalid timeout to be rejected")
            } catch RelayNetworkError.invalidTimeout {
                // Expected.
            } catch {
                XCTFail("Unexpected error: \(error)")
            }
        }

        do {
            _ = try await RelayClient(
                endpoint: endpoint,
                authToken: String(repeating: "x", count: RelayClient.maxAuthenticationBytes + 1)
            ).send(.health())
            XCTFail("Expected oversized authentication material to be rejected")
        } catch RelayNetworkError.invalidAuthentication {
            // Expected.
        }
    }

    func testRelayClientAcceptsBoundedDeploymentPolicy() throws {
        let policy = try RelayClientPolicy(
            maximumResponseBytes: 2 * 1_024 * 1_024,
            maximumRequestBytes: 1 * 1_024 * 1_024,
            timeout: 30
        )
        let client = RelayClient(
            endpoint: RelayEndpoint(host: "relay.example", port: 443, useTLS: true, transport: .http),
            policy: policy
        )

        XCTAssertEqual(client.policy.maximumResponseBytes, 2 * 1_024 * 1_024)
        XCTAssertEqual(client.policy.maximumRequestBytes, 1 * 1_024 * 1_024)
        XCTAssertEqual(client.policy.timeout, 30)
    }

    func testRelayClientPolicyRejectsValuesAboveSafetyCeilings() {
        XCTAssertThrowsError(
            try RelayClientPolicy(
                maximumResponseBytes: RelayClientPolicy.absoluteMaximumResponseBytes + 1
            )
        ) { error in
            XCTAssertEqual(error as? RelayClientPolicyError, .invalidMaximumResponseBytes)
        }
        XCTAssertThrowsError(
            try RelayClientPolicy(
                maximumRequestBytes: RelayClientPolicy.absoluteMaximumRequestBytes + 1
            )
        ) { error in
            XCTAssertEqual(error as? RelayClientPolicyError, .invalidMaximumRequestBytes)
        }
        XCTAssertThrowsError(
            try RelayClientPolicy(timeout: RelayClientPolicy.absoluteMaximumTimeout + 1)
        ) { error in
            XCTAssertEqual(error as? RelayClientPolicyError, .invalidTimeout)
        }
    }

    func testHeadlessMessagingClientRedactsRelayRejectionDetails() async throws {
        let port = UInt16.random(in: 42_000...44_999)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(store: RelayStore())
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 250_000_000)

        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-headless-redaction-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let client = HeadlessMessagingClient(
            stateURL: root.appendingPathComponent("client.json"),
            useEncryptedStore: false,
            timeout: 3
        )
        _ = try await client.createState(displayName: "Unregistered CLI", relay: endpoint)

        do {
            _ = try await client.receive(maxCount: 1)
            XCTFail("Unregistered headless fetch should be rejected by the relay.")
        } catch let error as HeadlessMessagingClientError {
            let description = error.localizedDescription
            // Mailbox-v2 deliberately collapses an unknown inbox into the
            // structurally-invalid registration response so the registration
            // endpoint cannot be used as an inbox-existence oracle.
            XCTAssertEqual(description, "Relay rejected the request: Relay rejected an invalid request.")
            XCTAssertFalse(description.localizedCaseInsensitiveContains("not registered"))
            XCTAssertFalse(description.localizedCaseInsensitiveContains("inbox"))
        }
    }


    func testRelayHTTPResponseSummaryDoesNotEchoBodyText() {
        let cloudflareLikeBody = Data("Cloudflare error code: 1010 token=secret-value".utf8)
        let regularBody = Data("upstream failure token=secret-value".utf8)

        XCTAssertEqual(
            RelayClient.responseSummary(cloudflareLikeBody),
            "<redacted Cloudflare error page, \(cloudflareLikeBody.count) bytes>"
        )
        XCTAssertEqual(
            RelayClient.responseSummary(regularBody),
            "<redacted \(regularBody.count) bytes>"
        )
        XCTAssertFalse(RelayClient.responseSummary(cloudflareLikeBody).contains("secret-value"))
        XCTAssertFalse(RelayClient.responseSummary(regularBody).contains("secret-value"))
    }

    func testHeadlessMessagingClientRotatesAndBurnsIdentityWithContactReset() async throws {
        let port = UInt16.random(in: 49_001...53_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(store: RelayStore())
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 250_000_000)

        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-headless-identity-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let alice = HeadlessMessagingClient(stateURL: root.appendingPathComponent("alice.json"), useEncryptedStore: false, timeout: 3)
        let bob = HeadlessMessagingClient(stateURL: root.appendingPathComponent("bob.json"), useEncryptedStore: false, timeout: 3)
        let initialAliceStatus = try await alice.createState(displayName: "Alice CLI", relay: endpoint)
        _ = try await bob.createState(displayName: "Bob CLI", relay: endpoint)
        try await alice.registerInbox()
        try await bob.registerInbox()

        let bobContact = try await alice.importContactCode(try await bob.exportContactCode())
        _ = try await bob.importContactCode(try await alice.exportContactCode())

        do {
            _ = try await alice.sendText(to: "Bob CLI", text: "before rotate")
        } catch {
            XCTFail("Initial direct send failed: \(error)")
            return
        }
        let beforeRotateBodies: [MessageBody]
        do {
            beforeRotateBodies = try await bob.receive(maxCount: 10).map(\.body)
        } catch {
            XCTFail("Initial direct receive failed: \(error)")
            return
        }
        XCTAssertEqual(beforeRotateBodies, [.text("before rotate")])

        let rotation: HeadlessIdentityChangeResult
        do {
            rotation = try await alice.rotateIdentity(
                preservingContinuityWith: [bobContact.id]
            )
        } catch {
            XCTFail("Identity rotation failed: \(error)")
            return
        }
        XCTAssertEqual(rotation.notifiedContacts, ["Bob CLI"])
        XCTAssertTrue(rotation.failedContacts.isEmpty)
        XCTAssertEqual(rotation.oldFingerprint, initialAliceStatus.fingerprint)
        XCTAssertNotEqual(rotation.newFingerprint, initialAliceStatus.fingerprint)

        let rotationMessages: [HeadlessReceivedMessage]
        do {
            rotationMessages = try await bob.receive(maxCount: 10)
        } catch {
            XCTFail("Rotation notification receive failed: \(error)")
            return
        }
        XCTAssertEqual(rotationMessages.count, 1)
        guard case .identityRotation = try XCTUnwrap(rotationMessages.first).body else {
            return XCTFail("Expected identity rotation control message")
        }
        let rotatedContactFingerprint = try await bob.contacts().first?.fingerprint
        XCTAssertEqual(rotatedContactFingerprint, rotation.newFingerprint)

        do {
            _ = try await alice.sendText(to: "Bob CLI", text: "after rotate")
        } catch {
            XCTFail("Post-rotation direct send failed: \(error)")
            return
        }
        let afterRotateBodies: [MessageBody]
        do {
            afterRotateBodies = try await bob.receive(maxCount: 10).map(\.body)
        } catch {
            XCTFail("Post-rotation direct receive failed: \(error)")
            return
        }
        XCTAssertEqual(afterRotateBodies, [.text("after rotate")])

        let allowedContact = try await alice.setContactIdentityReset(selector: "Bob CLI", allow: true)
        XCTAssertTrue(allowedContact.allowIdentityReset)

        let burn: HeadlessIdentityChangeResult
        do {
            burn = try await alice.burnIdentity()
        } catch {
            XCTFail("Identity burn failed: \(error)")
            return
        }
        XCTAssertEqual(burn.notifiedContacts, ["Bob CLI"])
        XCTAssertTrue(burn.failedContacts.isEmpty)
        XCTAssertEqual(burn.oldFingerprint, rotation.newFingerprint)
        XCTAssertNotEqual(burn.newFingerprint, rotation.newFingerprint)
        let alicePostBurnStatus = try await alice.status()
        XCTAssertEqual(alicePostBurnStatus.conversationCount, 0)

        let resetMessages: [HeadlessReceivedMessage]
        do {
            resetMessages = try await bob.receive(maxCount: 10)
        } catch {
            XCTFail("Reset notification receive failed: \(error)")
            return
        }
        XCTAssertEqual(resetMessages.count, 1)
        guard case .identityReset = try XCTUnwrap(resetMessages.first).body else {
            return XCTFail("Expected identity reset control message")
        }
        let resetContactFingerprint = try await bob.contacts().first?.fingerprint
        XCTAssertEqual(resetContactFingerprint, burn.newFingerprint)

        do {
            _ = try await alice.sendText(to: "Bob CLI", text: "after burn")
        } catch {
            XCTFail("Post-burn direct send failed: \(error)")
            return
        }
        let afterBurnBodies: [MessageBody]
        do {
            afterBurnBodies = try await bob.receive(maxCount: 10).map(\.body)
        } catch {
            XCTFail("Post-burn direct receive failed: \(error)")
            return
        }
        XCTAssertEqual(afterBurnBodies, [.text("after burn")])

        let aliceAudit = try await alice.continuityAudit()
        // Burn severs the local generation link too; selected peers retain
        // only the reset they explicitly received.
        XCTAssertTrue(aliceAudit.events.isEmpty)
        XCTAssertEqual(aliceAudit.fingerprint, burn.newFingerprint)

        let bobAudit = try await bob.continuityAudit()
        XCTAssertEqual(bobAudit.events.map(\.kind), [.contactRotationReceived, .contactResetReceived])
        XCTAssertEqual(bobAudit.events.map(\.contactDisplayName), ["Alice CLI", "Alice CLI"])

        let purge = try await bob.purgeContinuityAudit()
        XCTAssertEqual(purge.profileId, bobAudit.profileId)
        XCTAssertEqual(purge.purgedCount, 2)
        let purgedAudit = try await bob.continuityAudit()
        XCTAssertTrue(purgedAudit.events.isEmpty)
    }

    func testHeadlessMessagingClientExchangesAttachmentsThroughRelay() async throws {
        let port = UInt16.random(in: 57_001...60_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(store: RelayStore())
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 250_000_000)

        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-headless-attachment-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let alice = HeadlessMessagingClient(stateURL: root.appendingPathComponent("alice.json"), useEncryptedStore: false, timeout: 3)
        let bobURL = root.appendingPathComponent("bob.json")
        let bob = HeadlessMessagingClient(stateURL: bobURL, useEncryptedStore: false, timeout: 3)
        _ = try await alice.createState(displayName: "Alice CLI", relay: endpoint)
        _ = try await bob.createState(displayName: "Bob CLI", relay: endpoint)
        try await alice.registerInbox()
        try await bob.registerInbox()

        _ = try await alice.importContactCode(try await bob.exportContactCode())
        _ = try await bob.importContactCode(try await alice.exportContactCode())

        let payload = Data("headless encrypted image bytes".utf8)
        let sent = try await alice.sendAttachment(
            to: "Bob CLI",
            data: payload,
            fileName: "photo.bin",
            mimeType: "application/octet-stream",
            chunkSize: 8,
            ttlSeconds: 600
        )
        XCTAssertEqual(sent.uploadedChunkCount, 4)
        XCTAssertEqual(sent.descriptor.byteCount, payload.count)

        let rawChunk = try await RelayClient(endpoint: endpoint).send(
            .fetchAttachment(
                FetchAttachmentRequest(
                    attachmentId: sent.descriptor.id,
                    chunkIndex: 0
                )
            )
        )
        XCTAssertEqual(rawChunk.type, .attachment)
        XCTAssertNotEqual(rawChunk.attachment?.payload.ciphertext, payload.prefix(8))

        let received = try await bob.receive(maxCount: 10)
        XCTAssertEqual(received.count, 1)
        guard case .attachment(let descriptor) = received[0].body else {
            return XCTFail("Expected attachment descriptor")
        }
        XCTAssertEqual(descriptor.id, sent.descriptor.id)

        let bobReloaded = HeadlessMessagingClient(stateURL: bobURL, useEncryptedStore: false, timeout: 3)
        let fetched = try await bobReloaded.fetchAttachment(id: descriptor.id)
        XCTAssertNil(fetched.descriptor.fileName)
        XCTAssertEqual(fetched.data, payload)
    }

    func testHeadlessMessagingClientTreatsRedeliveryAsIdempotent() async throws {
        let port = UInt16.random(in: 49_001...52_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(store: RelayStore())
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 250_000_000)

        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-headless-redelivery-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let alice = HeadlessMessagingClient(stateURL: root.appendingPathComponent("alice.json"), useEncryptedStore: false, timeout: 3)
        let bob = HeadlessMessagingClient(stateURL: root.appendingPathComponent("bob.json"), useEncryptedStore: false, timeout: 3)
        _ = try await alice.createState(displayName: "Alice", relay: endpoint)
        _ = try await bob.createState(displayName: "Bob", relay: endpoint)
        try await alice.registerInbox()
        try await bob.registerInbox()
        _ = try await alice.importContactCode(try await bob.exportContactCode())
        _ = try await bob.importContactCode(try await alice.exportContactCode())

        _ = try await alice.sendText(to: "Bob", text: "once")
        let first = try await bob.receive(maxCount: 10, acknowledge: false)
        let replay = try await bob.receive(maxCount: 10, acknowledge: false)
        let acknowledgementPass = try await bob.receive(maxCount: 10, acknowledge: true)
        let drained = try await bob.receive(maxCount: 10)

        XCTAssertEqual(first.map(\.body), [.text("once")])
        XCTAssertTrue(replay.isEmpty)
        XCTAssertTrue(acknowledgementPass.isEmpty)
        XCTAssertTrue(drained.isEmpty)
    }

    func testHiddenRetrievalPlannerExtractsTargetFromCoverResponse() throws {
        let plan = try HiddenRetrievalPlanner.makeCoverQuery(
            bucketId: "bucket-a",
            availableRecordIds: ["a", "b", "c", "d"],
            targetRecordId: "c",
            coverSetSize: 4,
            secret: Data("secret".utf8)
        )
        let response = [
            "a": Data("decoy-a".utf8),
            "b": Data("decoy-b".utf8),
            "c": Data("target".utf8),
            "d": Data("decoy-d".utf8)
        ]

        XCTAssertEqual(
            try HiddenRetrievalPlanner.extractTarget(from: response, using: plan),
            Data("target".utf8)
        )
    }

    func testHiddenRetrievalPlannerRejectsIncompleteCoverResponse() throws {
        let plan = try HiddenRetrievalPlanner.makeCoverQuery(
            bucketId: "bucket-a",
            availableRecordIds: ["a", "b", "c", "d"],
            targetRecordId: "c",
            coverSetSize: 4,
            secret: Data("secret".utf8)
        )
        let response = [
            "c": Data("target".utf8)
        ]

        XCTAssertThrowsError(try HiddenRetrievalPlanner.extractTarget(from: response, using: plan)) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .incompleteCoverResponse)
        }
    }

    func testHiddenRetrievalPlannerRejectsMalformedPublicQueryPlans() throws {
        let response = [
            "a": Data("decoy-a".utf8),
            "b": Data("decoy-b".utf8),
            "c": Data("target".utf8)
        ]
        let missingTarget = HiddenRetrievalQueryPlan(
            bucketId: "bucket-a",
            requestedRecordIds: ["a", "b"],
            targetRecordId: "c"
        )
        let duplicateTarget = HiddenRetrievalQueryPlan(
            bucketId: "bucket-a",
            requestedRecordIds: ["a", "c", "c"],
            targetRecordId: "c"
        )
        let targetOnly = HiddenRetrievalQueryPlan(
            bucketId: "bucket-a",
            requestedRecordIds: ["c"],
            targetRecordId: "c"
        )
        let emptyBucket = HiddenRetrievalQueryPlan(
            bucketId: " ",
            requestedRecordIds: ["a", "c"],
            targetRecordId: "c"
        )
        let emptyTarget = HiddenRetrievalQueryPlan(
            bucketId: "bucket-a",
            requestedRecordIds: ["a", "b"],
            targetRecordId: " "
        )
        let emptyRequestedRecord = HiddenRetrievalQueryPlan(
            bucketId: "bucket-a",
            requestedRecordIds: ["a", " "],
            targetRecordId: "a"
        )
        let extraResponseRecords = HiddenRetrievalQueryPlan(
            bucketId: "bucket-a",
            requestedRecordIds: ["a", "c"],
            targetRecordId: "c"
        )

        for plan in [missingTarget, duplicateTarget, targetOnly, emptyBucket, emptyTarget, emptyRequestedRecord] {
            XCTAssertThrowsError(try HiddenRetrievalPlanner.extractTarget(from: response, using: plan)) { error in
                XCTAssertEqual(error as? HiddenRetrievalError, .malformedPublicPlan)
            }
            XCTAssertNil(HiddenRetrievalPlanner.targetIfValid(from: response, using: plan))
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.extractTarget(from: response, using: extraResponseRecords)
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .unexpectedResponseRecords)
        }
    }

    func testHiddenRetrievalPlannerRejectsInvalidQueries() throws {
        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: " ",
                availableRecordIds: ["a", "b"],
                targetRecordId: "a",
                coverSetSize: 2,
                secret: Data()
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidBucketId)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a", "b"],
                targetRecordId: " ",
                coverSetSize: 2,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidTargetRecordId)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a", " "],
                targetRecordId: "a",
                coverSetSize: 2,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidRecordId)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a", "b"],
                targetRecordId: "a",
                coverSetSize: 2,
                secret: Data()
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidSecret)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a"],
                targetRecordId: "a",
                coverSetSize: 0,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidCoverSetSize)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a", "b", "c"],
                targetRecordId: "a",
                coverSetSize: 3,
                secret: Data("secret".utf8),
                maximumCoverSetSize: 2
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .coverSetTooLarge)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a", "b"],
                targetRecordId: "a",
                coverSetSize: 1,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidCoverSetSize)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: [],
                targetRecordId: "a",
                coverSetSize: 2,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .emptyBucket)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a", "b"],
                targetRecordId: "c",
                coverSetSize: 2,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .targetMissing)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeCoverQuery(
                bucketId: "bucket",
                availableRecordIds: ["a", "b"],
                targetRecordId: "a",
                coverSetSize: 3,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .insufficientBucketRecords)
        }
    }

    func testHiddenRetrievalPlannerCanonicalizesBucketAndRecordIds() throws {
        let plan = try HiddenRetrievalPlanner.makeCoverQuery(
            bucketId: " bucket-a ",
            availableRecordIds: [" a ", "b", "c"],
            targetRecordId: " a ",
            coverSetSize: 2,
            secret: Data("secret".utf8)
        )

        XCTAssertEqual(plan.bucketId, "bucket-a")
        XCTAssertEqual(plan.targetRecordId, "a")
        XCTAssertTrue(plan.requestedRecordIds.contains("a"))
        XCTAssertFalse(plan.requestedRecordIds.contains(" a "))
    }

    func testHiddenRetrievalPlannerBuildsReplicatedXORPIRQuery() throws {
        let plan = try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
            bucketId: " bucket-pir ",
            orderedRecordIds: [" a ", "b", "c", "d"],
            targetRecordId: " c ",
            replicaCount: 3,
            secret: Data("client-local-pir-secret".utf8)
        )

        XCTAssertEqual(plan.bucketId, "bucket-pir")
        XCTAssertEqual(plan.orderedRecordIds, ["a", "b", "c", "d"])
        XCTAssertEqual(plan.targetRecordId, "c")
        XCTAssertEqual(plan.targetIndex, 2)
        XCTAssertEqual(plan.shares.map(\.replicaIndex), [0, 1, 2])
        XCTAssertTrue(plan.shares.allSatisfy { $0.recordCount == 4 })

        let records = [
            Data("record-a-16bytes".utf8),
            Data("record-b-16bytes".utf8),
            Data("record-c-16bytes".utf8),
            Data("record-d-16bytes".utf8)
        ]
        let responses = try plan.shares.map {
            try HiddenRetrievalPlanner.evaluateReplicatedXORPIRShare(records: records, share: $0)
        }

        XCTAssertEqual(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(from: responses, using: plan),
            records[2]
        )
    }

    func testHiddenRetrievalPlannerReplicatedXORPIRDoesNotSendTargetOnlyShares() throws {
        let plan = try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
            bucketId: "bucket-pir",
            orderedRecordIds: ["a", "b", "c", "d", "e"],
            targetRecordId: "d",
            replicaCount: 2,
            secret: Data("client-local-pir-secret".utf8)
        )

        let unitTarget = testBitset(recordCount: plan.orderedRecordIds.count, enabledIndex: plan.targetIndex)
        XCTAssertTrue(plan.shares.allSatisfy { $0.selectionBits != unitTarget })

        let combined = plan.shares
            .map(\.selectionBits)
            .reduce(Data(repeating: 0, count: unitTarget.count), xorTestData)
        XCTAssertEqual(combined, unitTarget)
    }

    func testHiddenRetrievalPlannerBuildsPaddedReplicatedXORPIRQuery() throws {
        let plan = try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
            bucketId: "bucket-pir",
            orderedRecordIds: ["a", "b", "c"],
            targetRecordId: "b",
            replicaCount: 3,
            secret: Data("client-local-padded-pir-secret".utf8),
            paddedRecordCount: 16
        )

        XCTAssertEqual(plan.orderedRecordIds.count, 3)
        XCTAssertEqual(plan.shares.map(\.recordCount), [16, 16, 16])
        XCTAssertTrue(plan.shares.allSatisfy { $0.selectionBits.count == 2 })

        let records = [
            Data("record-a-16bytes".utf8),
            Data("record-b-16bytes".utf8),
            Data("record-c-16bytes".utf8)
        ]
        let responses = try plan.shares.map {
            try HiddenRetrievalPlanner.evaluateReplicatedXORPIRShare(records: records, share: $0)
        }

        XCTAssertEqual(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(from: responses, using: plan),
            records[1]
        )

        let unitTarget = testBitset(recordCount: 16, enabledIndex: plan.targetIndex)
        let combined = plan.shares
            .map(\.selectionBits)
            .reduce(Data(repeating: 0, count: unitTarget.count), xorTestData)
        XCTAssertEqual(combined, unitTarget)
    }

    func testHiddenRetrievalPlannerBuildsFixedSizeReplicatedXORPIRResponses() throws {
        let plan = try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
            bucketId: "bucket-pir",
            orderedRecordIds: ["a", "b", "c"],
            targetRecordId: "c",
            replicaCount: 3,
            secret: Data("client-local-fixed-response-pir-secret".utf8),
            paddedRecordCount: 16
        )
        let records = [
            Data("record-a".utf8),
            Data("record-b".utf8),
            Data("record-c".utf8)
        ]
        let fixedResponseSize = 32

        let responses = try plan.shares.map {
            try HiddenRetrievalPlanner.evaluateReplicatedXORPIRShare(
                records: records,
                share: $0,
                fixedResponseSize: fixedResponseSize
            )
        }

        XCTAssertTrue(responses.allSatisfy { $0.payload.count == fixedResponseSize })
        var expected = records[2]
        expected.append(Data(repeating: 0, count: fixedResponseSize - expected.count))
        XCTAssertEqual(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(
                from: responses,
                using: plan,
                fixedResponseSize: fixedResponseSize
            ),
            expected
        )
    }

    func testHiddenRetrievalPlannerRejectsMalformedReplicatedXORPIRInputs() throws {
        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
                bucketId: "bucket-pir",
                orderedRecordIds: ["a", "b"],
                targetRecordId: "a",
                replicaCount: 1,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidReplicaCount)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
                bucketId: "bucket-pir",
                orderedRecordIds: ["a", "a"],
                targetRecordId: "a",
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidRecordCount)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
                bucketId: "bucket-pir",
                orderedRecordIds: ["a", "b", "c"],
                targetRecordId: "a",
                secret: Data("secret".utf8),
                paddedRecordCount: 2
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidRecordCount)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.evaluateReplicatedXORPIRShare(
                records: [Data("short".utf8), Data("longer".utf8)],
                share: HiddenRetrievalPIRQueryShare(
                    replicaIndex: 0,
                    recordCount: 2,
                    selectionBits: Data([0b0000_0011])
                )
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidRecordSize)
        }

        let plan = try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
            bucketId: "bucket-pir",
            orderedRecordIds: ["a", "b"],
            targetRecordId: "a",
            secret: Data("secret".utf8)
        )
        let response = HiddenRetrievalPIRResponseShare(replicaIndex: 0, payload: Data("target".utf8))
        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(from: [response], using: plan)
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .malformedPIRResponse)
        }

        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.evaluateReplicatedXORPIRShare(
                records: [Data("record-a".utf8), Data("record-b".utf8)],
                share: plan.shares[0],
                fixedResponseSize: 4
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidRecordSize)
        }

        let completeResponses = try plan.shares.map {
            try HiddenRetrievalPlanner.evaluateReplicatedXORPIRShare(
                records: [Data("record-a".utf8), Data("record-b".utf8)],
                share: $0,
                fixedResponseSize: 16
            )
        }
        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(
                from: completeResponses,
                using: plan,
                fixedResponseSize: 32
            )
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidRecordSize)
        }
    }

    func testHiddenRetrievalPlannerRejectsMalformedReplicatedXORPIRPlans() throws {
        let plan = try HiddenRetrievalPlanner.makeReplicatedXORPIRQuery(
            bucketId: "bucket-pir",
            orderedRecordIds: ["a", "b", "c"],
            targetRecordId: "b",
            replicaCount: 3,
            secret: Data("client-local-pir-plan-secret".utf8),
            paddedRecordCount: 8
        )
        let records = [
            Data("record-a".utf8),
            Data("record-b".utf8),
            Data("record-c".utf8)
        ]
        let responses = try plan.shares.map {
            try HiddenRetrievalPlanner.evaluateReplicatedXORPIRShare(records: records, share: $0)
        }

        let duplicateReplicaPlan = HiddenRetrievalPIRQueryPlan(
            bucketId: plan.bucketId,
            orderedRecordIds: plan.orderedRecordIds,
            targetRecordId: plan.targetRecordId,
            targetIndex: plan.targetIndex,
            shares: [
                plan.shares[0],
                HiddenRetrievalPIRQueryShare(
                    replicaIndex: 0,
                    recordCount: plan.shares[1].recordCount,
                    selectionBits: plan.shares[1].selectionBits
                ),
                plan.shares[2]
            ]
        )
        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(from: responses, using: duplicateReplicaPlan)
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .malformedPIRShare)
        }

        let wrongTargetPlan = HiddenRetrievalPIRQueryPlan(
            bucketId: plan.bucketId,
            orderedRecordIds: plan.orderedRecordIds,
            targetRecordId: "c",
            targetIndex: plan.targetIndex,
            shares: plan.shares
        )
        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(from: responses, using: wrongTargetPlan)
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .targetMissing)
        }

        let zeroedSharePlan = HiddenRetrievalPIRQueryPlan(
            bucketId: plan.bucketId,
            orderedRecordIds: plan.orderedRecordIds,
            targetRecordId: plan.targetRecordId,
            targetIndex: plan.targetIndex,
            shares: [
                HiddenRetrievalPIRQueryShare(
                    replicaIndex: 0,
                    recordCount: plan.shares[0].recordCount,
                    selectionBits: Data(repeating: 0, count: plan.shares[0].selectionBits.count)
                ),
                plan.shares[1],
                plan.shares[2]
            ]
        )
        XCTAssertThrowsError(
            try HiddenRetrievalPlanner.recoverReplicatedXORPIRTarget(from: responses, using: zeroedSharePlan)
        ) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .malformedPIRShare)
        }
    }

    func testRelayInfoAdvertisesOptionalHiddenRetrievalSupport() throws {
        let info = RelayConfiguration(
            hiddenRetrieval: HiddenRetrievalSupport(
                defaultCoverSetSize: 64,
                maxCoverSetSize: 16
            )
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))

        XCTAssertEqual(info.hiddenRetrieval?.mode, .coverQuery)
        XCTAssertEqual(info.hiddenRetrieval?.defaultCoverSetSize, 16)
        XCTAssertEqual(info.hiddenRetrieval?.maxCoverSetSize, 16)

        let encoded = try NoctweaveCoder.encode(info)
        let decoded = try NoctweaveCoder.decode(RelayInfo.self, from: encoded)

        XCTAssertEqual(decoded.hiddenRetrieval, info.hiddenRetrieval)
    }

    func testHiddenRetrievalSupportAdvertisesReplicatedXORPIRMode() throws {
        let info = RelayConfiguration(
            hiddenRetrieval: HiddenRetrievalSupport(
                mode: .replicatedXorPIR,
                defaultCoverSetSize: 8,
                maxCoverSetSize: 32,
                replicatedXorPIRReplicas: [
                    HiddenRetrievalPIRReplica(
                        replicaId: "replica-a",
                        operatorId: "operator-a",
                        endpoint: RelayEndpoint(host: "pir-a.example", port: 443, useTLS: true, transport: .http)
                    ),
                    HiddenRetrievalPIRReplica(
                        replicaId: "replica-b",
                        operatorId: "operator-b",
                        endpoint: RelayEndpoint(host: "pir-b.example", port: 443, useTLS: true, transport: .http)
                    )
                ]
            )
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))

        XCTAssertEqual(info.hiddenRetrieval?.mode, .replicatedXorPIR)
        XCTAssertTrue(HiddenRetrievalPIRReplicaSetValidator.isUsable(info.hiddenRetrieval))
        XCTAssertEqual(try HiddenRetrievalPIRReplicaSetValidator.validate(info.hiddenRetrieval).count, 2)

        let encoded = try NoctweaveCoder.encode(info)
        let decoded = try NoctweaveCoder.decode(RelayInfo.self, from: encoded)

        XCTAssertEqual(decoded.hiddenRetrieval?.mode, .replicatedXorPIR)
        XCTAssertEqual(decoded.hiddenRetrieval?.replicatedXorPIRReplicas, info.hiddenRetrieval?.replicatedXorPIRReplicas)
    }

    func testHiddenRetrievalSupportDoesNotAdvertiseTargetOnlyPlans() {
        let support = HiddenRetrievalSupport(defaultCoverSetSize: 1, maxCoverSetSize: 1)

        XCTAssertEqual(support.defaultCoverSetSize, 2)
        XCTAssertEqual(support.maxCoverSetSize, 2)
    }

    func testHiddenRetrievalReplicaSetValidatorRejectsMisleadingReplicatedPIRMetadata() {
        XCTAssertEqual(
            HiddenRetrievalPIRReplicaSetValidator.issues(for: nil),
            [.hiddenRetrievalUnavailable]
        )
        XCTAssertEqual(
            HiddenRetrievalPIRReplicaSetValidator.issues(for: HiddenRetrievalSupport()),
            [.unsupportedMode]
        )

        let duplicatedSingleOperator = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "same",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir.example", port: 443, useTLS: true, transport: .http)
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "same",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir.example", port: 443, useTLS: true, transport: .http)
                )
            ]
        )
        let issues = HiddenRetrievalPIRReplicaSetValidator.issues(for: duplicatedSingleOperator)

        XCTAssertTrue(issues.contains(.duplicateReplicaId))
        XCTAssertTrue(issues.contains(.duplicateOperatorId))
        XCTAssertTrue(issues.contains(.duplicateEndpoint))
        XCTAssertThrowsError(try HiddenRetrievalPIRReplicaSetValidator.validate(duplicatedSingleOperator)) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidReplicaSet)
        }

        let noTLS = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir-a.example", port: 80, useTLS: false, transport: .http)
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: RelayEndpoint(host: "pir-b.example", port: 443, useTLS: true, transport: .http)
                )
            ]
        )

        XCTAssertTrue(HiddenRetrievalPIRReplicaSetValidator.issues(for: noTLS).contains(.insecureEndpoint))
        XCTAssertTrue(HiddenRetrievalPIRReplicaSetValidator.isUsable(noTLS, requireTLS: false))

        let sameHostDifferentPorts = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir-shared.example", port: 443, useTLS: true, transport: .http)
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: RelayEndpoint(host: "PIR-SHARED.example", port: 8443, useTLS: true, transport: .http)
                )
            ]
        )
        let sameHostIssues = HiddenRetrievalPIRReplicaSetValidator.issues(for: sameHostDifferentPorts)
        XCTAssertTrue(sameHostIssues.contains(.duplicateHost))
        XCTAssertFalse(sameHostIssues.contains(.duplicateEndpoint))
    }

    func testRelayInfoSuppressesWeakReplicatedPIRAdvertisement() {
        let weakReplicas = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir-shared.example", port: 443, useTLS: true, transport: .http)
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: RelayEndpoint(host: "pir-shared.example", port: 8443, useTLS: true, transport: .http)
                )
            ]
        )
        let weakInfo = RelayConfiguration(hiddenRetrieval: weakReplicas).makeInfo()
        XCTAssertNil(weakInfo.hiddenRetrieval)

        let coverQueryInfo = RelayConfiguration(
            hiddenRetrieval: HiddenRetrievalSupport(mode: .coverQuery)
        ).makeInfo()
        XCTAssertEqual(coverQueryInfo.hiddenRetrieval?.mode, .coverQuery)
    }

    func testHiddenRetrievalPIROperationalValidatorRequiresPaddingAndFixedResponses() {
        let support = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir-a.example.org", port: 443, useTLS: true, transport: .http)
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: RelayEndpoint(host: "pir-b.example.org", port: 443, useTLS: true, transport: .http)
                )
            ]
        )

        let weak = HiddenRetrievalPIROperationalProfile(
            support: support,
            paddedRecordCount: 16,
            fixedResponseSize: nil
        )
        XCTAssertEqual(
            HiddenRetrievalPIROperationalValidator.issues(for: weak),
            [.missingFixedResponseSize, .paddedRecordCountTooSmall]
        )
        XCTAssertFalse(HiddenRetrievalPIROperationalValidator.isOperationallyUsable(weak))

        let operational = HiddenRetrievalPIROperationalProfile(
            support: support,
            paddedRecordCount: 256,
            fixedResponseSize: 2_048
        )
        XCTAssertTrue(HiddenRetrievalPIROperationalValidator.issues(for: operational).isEmpty)
        XCTAssertTrue(HiddenRetrievalPIROperationalValidator.isOperationallyUsable(operational))
        XCTAssertNoThrow(try HiddenRetrievalPIROperationalValidator.validate(operational))
    }

    func testHiddenRetrievalPIROperationalValidatorRejectsWeakReplicaSets() {
        let weakSupport = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir.example.org", port: 443, useTLS: true, transport: .http)
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir.example.org", port: 8443, useTLS: true, transport: .http)
                )
            ]
        )
        let profile = HiddenRetrievalPIROperationalProfile(
            support: weakSupport,
            paddedRecordCount: 256,
            fixedResponseSize: 2_048
        )

        XCTAssertEqual(
            HiddenRetrievalPIROperationalValidator.issues(for: profile),
            [.invalidReplicaSet]
        )
        XCTAssertThrowsError(try HiddenRetrievalPIROperationalValidator.validate(profile)) { error in
            XCTAssertEqual(error as? HiddenRetrievalError, .invalidReplicaSet)
        }
    }

    func testHiddenRetrievalPIRPromotionRequiresFreshDeploymentEvidence() {
        let now = Date(timeIntervalSince1970: 10_000)
        let replicaAEndpoint = RelayEndpoint(host: "pir-a.example.org", port: 443, useTLS: true, transport: .http)
        let replicaBEndpoint = RelayEndpoint(host: "pir-b.example.org", port: 443, useTLS: true, transport: .http)
        let support = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: replicaAEndpoint
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: replicaBEndpoint
                )
            ]
        )
        let profile = HiddenRetrievalPIROperationalProfile(
            support: support,
            paddedRecordCount: 256,
            fixedResponseSize: 2_048
        )

        XCTAssertEqual(
            HiddenRetrievalPIRPromotionValidator.issues(for: profile, evidence: nil, now: now),
            [.missingDeploymentEvidence]
        )

        let staleAndWeakEvidence = HiddenRetrievalPIRDeploymentEvidence(
            collectedAt: now,
            replicaEvidence: [
                HiddenRetrievalPIRReplicaDeploymentEvidence(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: replicaAEndpoint,
                    checkedAt: now.addingTimeInterval(-90_000),
                    isAvailable: true,
                    nonCollusionAttestationDigest: "same-attestation"
                ),
                HiddenRetrievalPIRReplicaDeploymentEvidence(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: replicaBEndpoint,
                    checkedAt: now,
                    isAvailable: false,
                    nonCollusionAttestationDigest: "same-attestation"
                )
            ]
        )
        XCTAssertEqual(
            HiddenRetrievalPIRPromotionValidator.issues(
                for: profile,
                evidence: staleAndWeakEvidence,
                now: now
            ),
            [
                .duplicateNonCollusionAttestation,
                .staleReplicaEvidence,
                .unavailableReplicaEvidence
            ]
        )

        let validEvidence = HiddenRetrievalPIRDeploymentEvidence(
            collectedAt: now,
            replicaEvidence: [
                HiddenRetrievalPIRReplicaDeploymentEvidence(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: replicaAEndpoint,
                    checkedAt: now.addingTimeInterval(-60),
                    isAvailable: true,
                    nonCollusionAttestationDigest: "operator-a-attestation-digest"
                ),
                HiddenRetrievalPIRReplicaDeploymentEvidence(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: replicaBEndpoint,
                    checkedAt: now.addingTimeInterval(-120),
                    isAvailable: true,
                    nonCollusionAttestationDigest: "operator-b-attestation-digest"
                )
            ]
        )
        XCTAssertTrue(
            HiddenRetrievalPIRPromotionValidator.issues(
                for: profile,
                evidence: validEvidence,
                now: now
            ).isEmpty
        )
        XCTAssertTrue(HiddenRetrievalPIRPromotionValidator.isPromotable(profile, evidence: validEvidence, now: now))
        XCTAssertNoThrow(try HiddenRetrievalPIRPromotionValidator.validate(profile, evidence: validEvidence, now: now))
    }

    func testHiddenRetrievalPIRPromotionRejectsMismatchedDeploymentEvidence() {
        let now = Date(timeIntervalSince1970: 12_000)
        let support = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: [
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir-a.example.org", port: 443, useTLS: true, transport: .http)
                ),
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: RelayEndpoint(host: "pir-b.example.org", port: 443, useTLS: true, transport: .http)
                )
            ]
        )
        let profile = HiddenRetrievalPIROperationalProfile(
            support: support,
            paddedRecordCount: 256,
            fixedResponseSize: 2_048
        )
        let evidence = HiddenRetrievalPIRDeploymentEvidence(
            collectedAt: now,
            replicaEvidence: [
                HiddenRetrievalPIRReplicaDeploymentEvidence(
                    replicaId: "replica-a",
                    operatorId: "operator-a",
                    endpoint: RelayEndpoint(host: "pir-a.example.org", port: 443, useTLS: true, transport: .http),
                    checkedAt: now,
                    isAvailable: true,
                    nonCollusionAttestationDigest: "attestation-a"
                ),
                HiddenRetrievalPIRReplicaDeploymentEvidence(
                    replicaId: "replica-a",
                    operatorId: "operator-b",
                    endpoint: RelayEndpoint(host: "pir-b.evil.example.org", port: 443, useTLS: true, transport: .http),
                    checkedAt: now,
                    isAvailable: true,
                    nonCollusionAttestationDigest: ""
                )
            ]
        )

        XCTAssertEqual(
            HiddenRetrievalPIRPromotionValidator.issues(for: profile, evidence: evidence, now: now),
            [
                .duplicateReplicaEvidence,
                .missingNonCollusionAttestation,
                .operatorEvidenceMismatch,
                .replicaEvidenceMismatch
            ]
        )
    }

    func testRelayInfoAdvertisesGroupSecurityModel() throws {
        let defaultInfo = RelayConfiguration().makeInfo(now: Date(timeIntervalSince1970: 1_000))
        XCTAssertEqual(defaultInfo.groupSecurityModel, .mlsDerivedTree)

        let mlsInfo = RelayConfiguration(
            groupSecurityModel: .mlsDerivedTree
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))

        XCTAssertEqual(mlsInfo.groupSecurityModel, .mlsDerivedTree)

        let encoded = try NoctweaveCoder.encode(mlsInfo)
        let decoded = try NoctweaveCoder.decode(RelayInfo.self, from: encoded)

        XCTAssertEqual(decoded.groupSecurityModel, .mlsDerivedTree)
    }

    func testRelayConfigurationBoundsOperatorControlledCollectionsAndCounts() {
        let endpoints = (0..<300).map { index in
            RelayEndpoint(host: "relay-\(index).example.org", port: 443, useTLS: true, transport: .http)
        }
        let configuration = RelayConfiguration(
            temporalBucketSeconds: Int.max,
            temporalBucketScheduleSeconds: Array(1...100),
            attachmentDefaultTTLSeconds: Int.max,
            attachmentMaxTTLSeconds: Int.max,
            federationCoordinatorEndpoints: endpoints,
            coordinatorHeartbeatSeconds: Int.max,
            coordinatorDirectoryMaxStalenessSeconds: Int.max,
            relayPeerExchangeLimit: Int.max,
            openFederationDHTMaxRecords: Int.max,
            openFederationDHTMaxRecordsPerHost: Int.max,
            openFederationDHTMaxQueryRecords: Int.max,
            coordinatorDirectorySigningPrivateKey: Data(repeating: 1, count: 16_385),
            curatedCoordinatorQuorum: Int.max,
            federationAllowList: endpoints
        )

        XCTAssertEqual(configuration.temporalBucketSeconds, 86_400)
        XCTAssertEqual(configuration.temporalBucketScheduleSeconds?.count, 16)
        XCTAssertEqual(configuration.attachmentDefaultTTLSeconds, 2_592_000)
        XCTAssertEqual(configuration.attachmentMaxTTLSeconds, 2_592_000)
        XCTAssertEqual(configuration.federationCoordinatorEndpoints?.count, 16)
        XCTAssertEqual(configuration.coordinatorHeartbeatSeconds, 3_600)
        XCTAssertEqual(configuration.coordinatorDirectoryMaxStalenessSeconds, 86_400)
        XCTAssertEqual(configuration.relayPeerExchangeLimit, 128)
        XCTAssertEqual(configuration.openFederationDHTMaxRecords, 256)
        XCTAssertEqual(configuration.openFederationDHTMaxRecordsPerHost, 16)
        XCTAssertEqual(configuration.openFederationDHTMaxQueryRecords, 512)
        XCTAssertNil(configuration.coordinatorDirectorySigningPrivateKey)
        XCTAssertEqual(configuration.curatedCoordinatorQuorum, 16)
        XCTAssertEqual(configuration.federationAllowList.count, 256)
    }

    func testDecentralizedWakeSupportNormalizesPolicy() {
        let pullOnly = DecentralizedWakeSupport(
            mode: .pullOnly,
            minPollIntervalSeconds: 1,
            maxPollIntervalSeconds: 2,
            jitterPermille: 2_000,
            longPollTimeoutSeconds: 60
        )

        XCTAssertEqual(pullOnly.minPollIntervalSeconds, 5)
        XCTAssertEqual(pullOnly.maxPollIntervalSeconds, 5)
        XCTAssertEqual(pullOnly.jitterPermille, 1_000)
        XCTAssertNil(pullOnly.longPollTimeoutSeconds)

        let longPoll = DecentralizedWakeSupport(
            mode: .longPoll,
            minPollIntervalSeconds: 10,
            maxPollIntervalSeconds: 30,
            jitterPermille: -1,
            longPollTimeoutSeconds: 120
        )

        XCTAssertEqual(longPoll.jitterPermille, 0)
        XCTAssertEqual(longPoll.longPollTimeoutSeconds, 30)
    }

    func testDecentralizedWakePlannerIsDeterministicAndBounded() {
        let support = DecentralizedWakeSupport(
            mode: .longPoll,
            minPollIntervalSeconds: 20,
            maxPollIntervalSeconds: 120,
            jitterPermille: 500,
            longPollTimeoutSeconds: 40
        )
        let now = Date(timeIntervalSince1970: 1_234)
        let seed = Data("identity-seed".utf8)

        let first = DecentralizedWakePlanner.makePlan(
            support: support,
            identitySeed: seed,
            relayIdentifier: "relay.example.org",
            failureCount: 2,
            now: now
        )
        let second = DecentralizedWakePlanner.makePlan(
            support: support,
            identitySeed: seed,
            relayIdentifier: "relay.example.org",
            failureCount: 2,
            now: now
        )

        XCTAssertEqual(first, second)
        XCTAssertGreaterThanOrEqual(first.nextPollDelaySeconds, 80)
        XCTAssertLessThanOrEqual(first.nextPollDelaySeconds, 120)
        XCTAssertEqual(first.longPollTimeoutSeconds, 40)
        XCTAssertEqual(first.failureBackoffStep, 2)

        let capped = DecentralizedWakePlanner.makePlan(
            support: support,
            identitySeed: seed,
            relayIdentifier: "relay.example.org",
            failureCount: 99,
            now: now
        )
        XCTAssertEqual(capped.failureBackoffStep, 6)
        XCTAssertLessThanOrEqual(capped.nextPollDelaySeconds, 120)
    }

    func testDecentralizedWakePlannerHandlesNonFiniteDatesWithoutTrapping() {
        let plan = DecentralizedWakePlanner.makePlan(
            support: DecentralizedWakeSupport(
                minPollIntervalSeconds: 10,
                maxPollIntervalSeconds: 30,
                jitterPermille: 500
            ),
            identitySeed: Data("identity-seed".utf8),
            relayIdentifier: "relay.example.org",
            now: Date(timeIntervalSince1970: .infinity)
        )

        XCTAssertGreaterThanOrEqual(plan.nextPollDelaySeconds, 10)
        XCTAssertLessThanOrEqual(plan.nextPollDelaySeconds, 30)
    }

    func testDecentralizedWakePlannerCapsLongPollTimeoutToNextDelay() {
        let support = DecentralizedWakeSupport(
            mode: .longPoll,
            minPollIntervalSeconds: 20,
            maxPollIntervalSeconds: 300,
            jitterPermille: 0,
            longPollTimeoutSeconds: 300
        )

        let plan = DecentralizedWakePlanner.makePlan(
            support: support,
            identitySeed: Data("wake-identity".utf8),
            relayIdentifier: "relay.example.org",
            failureCount: 0,
            now: Date(timeIntervalSince1970: 1_000)
        )

        XCTAssertEqual(plan.nextPollDelaySeconds, 20)
        XCTAssertEqual(plan.longPollTimeoutSeconds, 20)
    }

    func testDecentralizedWakePlannerUsesBoundedPullDefaultsWithoutRelayPolicy() {
        let now = Date(timeIntervalSince1970: 9_876)
        let plan = DecentralizedWakePlanner.makePlan(
            support: nil,
            identitySeed: Data("fallback-identity".utf8),
            relayIdentifier: "relay-without-policy",
            failureCount: 99,
            now: now
        )

        XCTAssertNil(plan.longPollTimeoutSeconds)
        XCTAssertEqual(plan.failureBackoffStep, 6)
        XCTAssertGreaterThanOrEqual(plan.nextPollDelaySeconds, 60)
        XCTAssertLessThanOrEqual(plan.nextPollDelaySeconds, 300)
    }

    func testDecentralizedWakePlannerSpreadsManyIdentitiesAcrossRelayWindow() {
        let support = DecentralizedWakeSupport(
            mode: .longPoll,
            minPollIntervalSeconds: 30,
            maxPollIntervalSeconds: 120,
            jitterPermille: 1_000,
            longPollTimeoutSeconds: 30
        )
        let relayIdentifier = "relay.example.org"
        let now = Date(timeIntervalSince1970: 123_456)
        let plans = (0..<128).map { index in
            DecentralizedWakePlanner.makePlan(
                support: support,
                identitySeed: Data("identity-\(index)".utf8),
                relayIdentifier: relayIdentifier,
                failureCount: 0,
                now: now
            )
        }
        let delayHistogram = Dictionary(
            grouping: plans,
            by: \.nextPollDelaySeconds
        ).mapValues(\.count)

        XCTAssertEqual(plans.map(\.longPollTimeoutSeconds).allSatisfy { $0 == 30 }, true)
        XCTAssertEqual(plans.map(\.failureBackoffStep).allSatisfy { $0 == 0 }, true)
        XCTAssertGreaterThanOrEqual(delayHistogram.count, 24)
        XCTAssertLessThanOrEqual(delayHistogram.values.max() ?? 0, 12)
        XCTAssertTrue(plans.allSatisfy { plan in
            plan.nextPollDelaySeconds >= 30 && plan.nextPollDelaySeconds <= 60
        })

        let backedOff = DecentralizedWakePlanner.makePlan(
            support: support,
            identitySeed: Data("identity-0".utf8),
            relayIdentifier: relayIdentifier,
            failureCount: 99,
            now: now
        )
        XCTAssertEqual(backedOff.failureBackoffStep, 6)
        XCTAssertLessThanOrEqual(backedOff.nextPollDelaySeconds, 120)
    }

    func testDecentralizedWakePlannerIncludesProfilesWithoutAdvertisedPolicy() {
        let slowAdvertised = DecentralizedWakeSupport(
            mode: .pullOnly,
            minPollIntervalSeconds: 120,
            maxPollIntervalSeconds: 240,
            jitterPermille: 0
        )
        let now = Date(timeIntervalSince1970: 10_000)
        let delay = DecentralizedWakePlanner.nextPollDelaySeconds(
            for: [
                DecentralizedWakeProfile(
                    support: slowAdvertised,
                    identitySeed: Data("slow-profile".utf8),
                    relayIdentifier: "slow-relay"
                ),
                DecentralizedWakeProfile(
                    support: nil,
                    identitySeed: Data("local-default-profile".utf8),
                    relayIdentifier: "relay-without-policy"
                )
            ],
            defaultDelaySeconds: 8,
            maxDelaySeconds: 300,
            now: now
        )

        XCTAssertEqual(delay, 8)
    }

    func testDecentralizedWakePlannerBuildsAuditableCyclePlan() {
        let longPoll = DecentralizedWakeSupport(
            mode: .longPoll,
            minPollIntervalSeconds: 30,
            maxPollIntervalSeconds: 120,
            jitterPermille: 0,
            longPollTimeoutSeconds: 90
        )
        let slow = DecentralizedWakeSupport(
            mode: .pullOnly,
            minPollIntervalSeconds: 120,
            maxPollIntervalSeconds: 240,
            jitterPermille: 0
        )

        let cycle = DecentralizedWakePlanner.makeCyclePlan(
            for: [
                DecentralizedWakeProfile(
                    support: slow,
                    identitySeed: Data("identity-b".utf8),
                    relayIdentifier: " relay-b ",
                    failureCount: 0
                ),
                DecentralizedWakeProfile(
                    support: longPoll,
                    identitySeed: Data("identity-a".utf8),
                    relayIdentifier: "relay-a",
                    failureCount: 0
                ),
                DecentralizedWakeProfile(
                    support: longPoll,
                    identitySeed: Data("identity-a".utf8),
                    relayIdentifier: "relay-a",
                    failureCount: 2
                ),
                DecentralizedWakeProfile(
                    support: nil,
                    identitySeed: Data("identity-c".utf8),
                    relayIdentifier: " ",
                    failureCount: 99
                )
            ],
            defaultDelaySeconds: 12,
            maxDelaySeconds: 300,
            now: Date(timeIntervalSince1970: 10_000)
        )

        XCTAssertEqual(cycle.profilePlans.map(\.relayIdentifier), ["default-relay", "relay-a", "relay-b"])
        XCTAssertEqual(cycle.profilePlans.count, 3)
        XCTAssertEqual(cycle.nextPollDelaySeconds, 12)
        XCTAssertNil(cycle.longPollTimeoutSeconds)
        XCTAssertEqual(cycle.profilePlans[0].plan.failureBackoffStep, 6)
        XCTAssertEqual(cycle.profilePlans[1].plan.nextPollDelaySeconds, 30)
        XCTAssertEqual(cycle.profilePlans[1].plan.longPollTimeoutSeconds, 30)
    }

    func testDecentralizedWakePlannerReturnsDefaultCycleForNoProfiles() {
        let cycle = DecentralizedWakePlanner.makeCyclePlan(
            for: [],
            defaultDelaySeconds: 3,
            maxDelaySeconds: 4,
            now: Date(timeIntervalSince1970: 10_000)
        )

        XCTAssertTrue(cycle.profilePlans.isEmpty)
        XCTAssertEqual(cycle.nextPollDelaySeconds, 5)
        XCTAssertNil(cycle.longPollTimeoutSeconds)
    }

    func testDecentralizedWakePlannerSelectsFastestAdvertisedProfile() {
        let slow = DecentralizedWakeSupport(
            mode: .pullOnly,
            minPollIntervalSeconds: 120,
            maxPollIntervalSeconds: 240,
            jitterPermille: 0
        )
        let fast = DecentralizedWakeSupport(
            mode: .pullOnly,
            minPollIntervalSeconds: 15,
            maxPollIntervalSeconds: 60,
            jitterPermille: 0
        )
        let now = Date(timeIntervalSince1970: 10_000)
        let delay = DecentralizedWakePlanner.nextPollDelaySeconds(
            for: [
                DecentralizedWakeProfile(
                    support: slow,
                    identitySeed: Data("slow-profile".utf8),
                    relayIdentifier: "slow-relay"
                ),
                DecentralizedWakeProfile(
                    support: fast,
                    identitySeed: Data("fast-profile".utf8),
                    relayIdentifier: "fast-relay"
                )
            ],
            defaultDelaySeconds: 8,
            maxDelaySeconds: 300,
            now: now
        )

        XCTAssertEqual(delay, 15)
    }

    func testDecentralizedWakePlannerDoesNotLetBackedOffProfileDelayHealthyProfile() {
        let support = DecentralizedWakeSupport(
            mode: .pullOnly,
            minPollIntervalSeconds: 30,
            maxPollIntervalSeconds: 300,
            jitterPermille: 0
        )
        let now = Date(timeIntervalSince1970: 10_000)
        let delay = DecentralizedWakePlanner.nextPollDelaySeconds(
            for: [
                DecentralizedWakeProfile(
                    support: support,
                    identitySeed: Data("failing-profile".utf8),
                    relayIdentifier: "relay-a",
                    failureCount: 4
                ),
                DecentralizedWakeProfile(
                    support: support,
                    identitySeed: Data("healthy-profile".utf8),
                    relayIdentifier: "relay-b",
                    failureCount: 0
                )
            ],
            defaultDelaySeconds: 8,
            maxDelaySeconds: 300,
            now: now
        )

        XCTAssertEqual(delay, 30)
    }

    func testDecentralizedPrefetchExecutionPlannerCapsProfilesAndEnvelopeBudgets() {
        let longPoll = DecentralizedWakeSupport(
            mode: .longPoll,
            minPollIntervalSeconds: 10,
            maxPollIntervalSeconds: 60,
            jitterPermille: 0,
            longPollTimeoutSeconds: 30
        )
        let pullOnly = DecentralizedWakeSupport(
            mode: .pullOnly,
            minPollIntervalSeconds: 20,
            maxPollIntervalSeconds: 120,
            jitterPermille: 0
        )
        let plan = DecentralizedPrefetchExecutionPlanner.makePlan(
            for: [
                DecentralizedWakeProfile(
                    support: pullOnly,
                    identitySeed: Data("identity-c".utf8),
                    relayIdentifier: "relay-c"
                ),
                DecentralizedWakeProfile(
                    support: longPoll,
                    identitySeed: Data("identity-a".utf8),
                    relayIdentifier: "relay-a"
                ),
                DecentralizedWakeProfile(
                    support: pullOnly,
                    identitySeed: Data("identity-b".utf8),
                    relayIdentifier: "relay-b"
                )
            ],
            defaultDelaySeconds: 60,
            maxDelaySeconds: 300,
            policy: DecentralizedPrefetchExecutionPolicy(
                maxProfilesPerCycle: 2,
                maxRecordsPerPullProfile: 3,
                maxRecordsPerLongPollProfile: 5,
                maxTotalRecordsPerCycle: 7
            ),
            now: Date(timeIntervalSince1970: 1_000)
        )

        XCTAssertEqual(plan.profileExecutions.map(\.relayIdentifier), ["relay-a", "relay-b"])
        XCTAssertEqual(plan.profileExecutions.map(\.maxEnvelopeCount), [5, 2])
        XCTAssertEqual(plan.maxTotalEnvelopeCount, 7)
        XCTAssertEqual(plan.nextCycleDelaySeconds, 10)
        XCTAssertEqual(plan.longPollTimeoutSeconds, 10)
        XCTAssertEqual(plan.profileExecutions.first?.longPollTimeoutSeconds, 10)
    }

    func testRelayInfoAdvertisesDecentralizedWakeSupport() throws {
        let info = RelayConfiguration(
            wakeSupport: DecentralizedWakeSupport(
                mode: .longPoll,
                minPollIntervalSeconds: 30,
                maxPollIntervalSeconds: 180,
                jitterPermille: 125,
                longPollTimeoutSeconds: 45
            )
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))

        XCTAssertEqual(info.wakeSupport?.mode, .longPoll)
        XCTAssertEqual(info.wakeSupport?.minPollIntervalSeconds, 30)
        XCTAssertEqual(info.wakeSupport?.maxPollIntervalSeconds, 180)
        XCTAssertEqual(info.wakeSupport?.jitterPermille, 125)
        XCTAssertEqual(info.wakeSupport?.longPollTimeoutSeconds, 45)

        let encoded = try NoctweaveCoder.encode(info)
        let decoded = try NoctweaveCoder.decode(RelayInfo.self, from: encoded)

        XCTAssertEqual(decoded.wakeSupport, info.wakeSupport)
    }

    func testDecentralizedPrefetchStagerStagesDirectCiphertextOnlyRecords() throws {
        let envelope = makeTestProtocolEnvelope(
            id: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
            conversationId: "conversation-a",
            sessionId: "session-a",
            counter: 7,
            sentAt: Date(timeIntervalSince1970: 1_000),
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x01, count: 12),
                ciphertext: Data(repeating: 0xAA, count: 512),
                tag: Data(repeating: 0x03, count: 16)
            ),
            signature: Data(repeating: 0x05, count: 3_309)
        )

        let batch = try DecentralizedPrefetchStager.stageDirectMessages(
            [envelope],
            inboxId: " inbox-a ",
            relayIdentifier: " relay-a ",
            stagedAt: Date(timeIntervalSince1970: 2_000)
        )

        XCTAssertTrue(batch.isCiphertextOnly)
        XCTAssertEqual(batch.messageIds, [envelope.id])
        XCTAssertEqual(batch.records.first?.kind, .directMessage)
        XCTAssertEqual(batch.records.first?.relayIdentifier, "relay-a")
        XCTAssertEqual(batch.records.first?.inboxId, "inbox-a")
        XCTAssertNil(batch.records.first?.groupId)
        XCTAssertEqual(batch.records.first?.acknowledgementDeferred, true)
        let decoded = try NoctweaveCoder.decode(
            ProtocolEnvelopeV1.self,
            from: try XCTUnwrap(batch.records.first?.sealedEnvelope)
        )
        XCTAssertEqual(decoded, envelope)
    }

    func testDecentralizedPrefetchStagerStagesGroupCiphertextOnlyRecords() throws {
        let groupId = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let envelope = GroupRatchetEnvelope(
            id: UUID(uuidString: "33333333-3333-3333-3333-333333333333")!,
            groupId: groupId,
            epoch: 4,
            transcriptHash: Data([0x10, 0x11]),
            senderFingerprint: "sender-b",
            sentAt: Date(timeIntervalSince1970: 3_000),
            messageCounter: 9,
            payload: EncryptedPayload(
                nonce: Data([0x12, 0x13]),
                ciphertext: Data([0xBA, 0xAD, 0xF0, 0x0D]),
                tag: Data([0x14, 0x15])
            ),
            signature: Data([0x16, 0x17])
        )

        let batch = try DecentralizedPrefetchStager.stageGroupMessages(
            [envelope],
            groupInboxId: " group-inbox ",
            relayIdentifier: " relay-b ",
            stagedAt: Date(timeIntervalSince1970: 4_000)
        )

        XCTAssertTrue(batch.isCiphertextOnly)
        XCTAssertEqual(batch.messageIds, [envelope.id])
        XCTAssertEqual(batch.records.first?.kind, .groupMessage)
        XCTAssertEqual(batch.records.first?.groupId, groupId)
        XCTAssertEqual(batch.records.first?.acknowledgementDeferred, true)
        let decoded = try NoctweaveCoder.decode(
            GroupRatchetEnvelope.self,
            from: try XCTUnwrap(batch.records.first?.sealedEnvelope)
        )
        XCTAssertEqual(decoded, envelope)
    }

    func testDecentralizedPrefetchStagerDoesNotAcknowledgeRelayMessages() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        let envelope = makeStructurallyValidRelayEnvelope(
            id: UUID(uuidString: "44444444-4444-4444-4444-444444444444")!,
            conversationId: "conversation-c",
            messageCounter: 11,
            marker: 0x51,
            sentAt: Date(timeIntervalSince1970: 5_000)
        )

        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x92]))
        try await store.deliver(envelope, to: inboxId)
        let fetched = try await store.fetch(inboxId: inboxId)
        let batch = try DecentralizedPrefetchStager.stageDirectMessages(
            fetched,
            inboxId: inboxId,
            relayIdentifier: "relay-c"
        )
        let fetchedAfterStaging = try await store.fetch(inboxId: inboxId)

        XCTAssertTrue(batch.isCiphertextOnly)
        XCTAssertEqual(batch.messageIds, [envelope.id])
        XCTAssertEqual(fetchedAfterStaging.map(\.id), [envelope.id])
    }

    func testDecentralizedPrefetchBatchStorePersistsEncryptedCiphertextOnlyBatch() async throws {
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("prefetch.batch")
        defer { try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent()) }

        let envelope = makeTestProtocolEnvelope(
            id: UUID(uuidString: "55555555-5555-5555-5555-555555555555")!,
            conversationId: "conversation-d",
            sessionId: "session-d",
            counter: 13,
            sentAt: Date(timeIntervalSince1970: 6_000),
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x61, count: 12),
                ciphertext: Data(repeating: 0x64, count: 512),
                tag: Data(repeating: 0x62, count: 16)
            ),
            signature: Data(repeating: 0x63, count: 3_309)
        )
        let batch = try DecentralizedPrefetchStager.stageDirectMessages(
            [envelope],
            inboxId: "inbox-d",
            relayIdentifier: "relay-d",
            stagedAt: Date(timeIntervalSince1970: 7_000)
        )
        let encodedBatch = try NoctweaveCoder.encode(batch)
        let store = try DecentralizedPrefetchBatchStore(
            fileURL: fileURL,
            protectionKey: Data(repeating: 0xA5, count: 32)
        )

        try await store.save(batch)
        let rawStored = try Data(contentsOf: fileURL)
        XCTAssertNotEqual(rawStored, encodedBatch)
        XCTAssertNil(rawStored.range(of: try XCTUnwrap(batch.records.first?.sealedEnvelope)))
        XCTAssertNil(rawStored.range(of: Data(repeating: 0x64, count: 512)))

        let maybeReloaded = try await store.load()
        let reloaded = try XCTUnwrap(maybeReloaded)
        XCTAssertEqual(reloaded, batch)
        XCTAssertTrue(reloaded.isCiphertextOnly)
        XCTAssertEqual(reloaded.records.first?.acknowledgementDeferred, true)
    }

    func testDecentralizedPrefetchBatchStoreRemoveDeletesPersistedBatch() async throws {
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("prefetch.batch")
        defer { try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent()) }

        let envelope = makeTestProtocolEnvelope(
            id: UUID(uuidString: "56565656-5656-5656-5656-565656565656")!,
            conversationId: "conversation-remove",
            sessionId: "session-remove",
            counter: 14,
            sentAt: Date(timeIntervalSince1970: 6_100),
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x65, count: 12),
                ciphertext: Data(repeating: 0x68, count: 512),
                tag: Data(repeating: 0x66, count: 16)
            ),
            signature: Data(repeating: 0x67, count: 3_309)
        )
        let batch = try DecentralizedPrefetchStager.stageDirectMessages(
            [envelope],
            inboxId: "inbox-remove",
            relayIdentifier: "relay-remove",
            stagedAt: Date(timeIntervalSince1970: 7_100)
        )
        let store = try DecentralizedPrefetchBatchStore(
            fileURL: fileURL,
            protectionKey: Data(repeating: 0xD8, count: 32)
        )

        try await store.save(batch)
        XCTAssertTrue(FileManager.default.fileExists(atPath: fileURL.path))

        try await store.remove()
        XCTAssertFalse(FileManager.default.fileExists(atPath: fileURL.path))
        let reloaded = try await store.load()
        XCTAssertNil(reloaded)

        try await store.remove()
    }

    func testDecentralizedPrefetchBatchStoreRejectsWrongKeyAndAcknowledgedRecords() async throws {
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("prefetch.batch")
        defer { try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent()) }

        let acknowledged = DecentralizedPrefetchBatch(
            records: [
                DecentralizedPrefetchRecord(
                    id: UUID(uuidString: "66666666-6666-6666-6666-666666666666")!,
                    kind: .directMessage,
                    relayIdentifier: "relay-e",
                    inboxId: "inbox-e",
                    groupId: nil,
                    stagedAt: Date(timeIntervalSince1970: 8_000),
                    sealedEnvelope: Data([0x70, 0x71]),
                    acknowledgementDeferred: false
                )
            ],
            stagedAt: Date(timeIntervalSince1970: 8_000)
        )
        let store = try DecentralizedPrefetchBatchStore(
            fileURL: fileURL,
            protectionKey: Data(repeating: 0xB6, count: 32)
        )

        do {
            try await store.save(acknowledged)
            XCTFail("Expected acknowledged prefetch records to be rejected.")
        } catch {
            XCTAssertEqual(error as? DecentralizedPrefetchError, .invalidBatch)
        }

        let valid = DecentralizedPrefetchBatch(
            records: [
                DecentralizedPrefetchRecord(
                    id: UUID(uuidString: "77777777-7777-7777-7777-777777777777")!,
                    kind: .groupMessage,
                    relayIdentifier: "relay-f",
                    inboxId: "group-inbox-f",
                    groupId: UUID(uuidString: "88888888-8888-8888-8888-888888888888")!,
                    stagedAt: Date(timeIntervalSince1970: 9_000),
                    sealedEnvelope: Data([0x80, 0x81, 0x82]),
                    acknowledgementDeferred: true
                )
            ],
            stagedAt: Date(timeIntervalSince1970: 9_000)
        )
        try await store.save(valid)

        let wrongKeyStore = try DecentralizedPrefetchBatchStore(
            fileURL: fileURL,
            protectionKey: Data(repeating: 0xC7, count: 32)
        )
        do {
            _ = try await wrongKeyStore.load()
            XCTFail("Expected wrong prefetch protection key to fail closed.")
        } catch {
            XCTAssertEqual(error as? DecentralizedPrefetchError, .invalidStoredBatch)
        }
    }

    func testDecentralizedPrefetchBatchStoreRejectsOversizedAndAmbiguousRecords() async throws {
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("prefetch.batch")
        defer { try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent()) }
        let store = try DecentralizedPrefetchBatchStore(
            fileURL: fileURL,
            protectionKey: Data(repeating: 0xA1, count: 32)
        )
        let record = DecentralizedPrefetchRecord(
            id: UUID(),
            kind: .directMessage,
            relayIdentifier: "relay",
            inboxId: "inbox",
            groupId: UUID(),
            stagedAt: Date(),
            sealedEnvelope: Data(repeating: 0x44, count: DecentralizedPrefetchStager.maximumSealedEnvelopeBytes + 1),
            acknowledgementDeferred: true
        )

        do {
            try await store.save(DecentralizedPrefetchBatch(records: [record], stagedAt: Date()))
            XCTFail("Expected an oversized, kind-ambiguous prefetch record to be rejected")
        } catch {
            XCTAssertEqual(error as? DecentralizedPrefetchError, .invalidBatch)
        }
    }

    func testRatchetRecoveryPolicyClassifiesRecoverableFailures() throws {
        XCTAssertEqual(RatchetRecoveryPolicy.decision(for: CryptoError.invalidPayload), .recover)
        XCTAssertEqual(RatchetRecoveryPolicy.decision(for: CryptoError.counterOutOfOrder), .recover)
        XCTAssertEqual(RatchetRecoveryPolicy.decision(for: CryptoError.counterWindowExceeded), .recover)
        XCTAssertEqual(RatchetRecoveryPolicy.decision(for: CryptoError.counterReplay), .acknowledge)
        XCTAssertEqual(RatchetRecoveryPolicy.decision(for: CryptoError.invalidSignature), .acknowledge)
        XCTAssertEqual(RatchetRecoveryPolicy.decision(for: CryptoError.operationFailed), .retryLater)

        let key = SymmetricKey(size: .bits256)
        let wrongKey = SymmetricKey(size: .bits256)
        let sealed = try AES.GCM.seal(Data("message".utf8), using: key)
        XCTAssertThrowsError(try AES.GCM.open(sealed, using: wrongKey)) { error in
            XCTAssertEqual(RatchetRecoveryPolicy.decision(for: error), .recover)
        }
    }

    func testPublicRelayEndpointPolicyRejectsIPv6TransitionPrivateTargets() {
        let endpoints = [
            RelayEndpoint(host: "64:ff9b::7f00:1", port: 443, useTLS: true),
            RelayEndpoint(host: "64:ff9b::0a00:1", port: 443, useTLS: true),
            RelayEndpoint(host: "2002:0a00:0001::1", port: 443, useTLS: true),
            RelayEndpoint(host: "2001:0000:4136:e378:8000:63bf:3fff:fdd2", port: 443, useTLS: true),
            RelayEndpoint(host: "::7f00:1", port: 443, useTLS: true),
            RelayEndpoint(host: "100::1", port: 443, useTLS: true),
            RelayEndpoint(host: "fec0::1", port: 443, useTLS: true),
            RelayEndpoint(host: "3fff::1", port: 443, useTLS: true)
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

        let wrongVersion = OpenFederationDHTRecord(
            version: 99,
            namespace: record.namespace,
            relayIdentityDigest: record.relayIdentityDigest,
            endpoint: record.endpoint,
            federationName: record.federationName,
            issuedAt: record.issuedAt,
            expiresAt: record.expiresAt,
            relaySigningPublicKey: record.relaySigningPublicKey,
            signature: record.signature
        )
        XCTAssertThrowsError(
            try wrongVersion.validate(expectedFederationName: "poison-test", requirePublicEndpoint: false)
        ) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .unsupportedVersion)
        }

        let mislabeled = OpenFederationDHTRecord(
            namespace: record.namespace,
            relayIdentityDigest: record.relayIdentityDigest,
            endpoint: record.endpoint,
            federationName: "other-federation",
            issuedAt: record.issuedAt,
            expiresAt: record.expiresAt,
            relaySigningPublicKey: record.relaySigningPublicKey,
            signature: record.signature
        )
        XCTAssertThrowsError(
            try mislabeled.validate(expectedFederationName: "poison-test", requirePublicEndpoint: false)
        ) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .federationNameMismatch)
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
            signature: try signingKey.sign(NoctweaveCoder.encode(
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

    func testOpenFederationDHTDiscoveryIsFeatureGated() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let record = try makeDHTRecord(host: "relay.example.org", federationName: "gated-net", issuedAt: now)
        var cache = OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: false,
                federationName: "gated-net",
                requirePublicEndpoint: false
            )
        )

        let result = cache.ingest([record], now: now)

        XCTAssertTrue(result.accepted.isEmpty)
        XCTAssertEqual(result.rejected.map(\.reason), [.discoveryDisabled])
        XCTAssertEqual(cache.count, 0)
    }

    func testOpenFederationDHTDiscoveryAcceptsValidatedSignedRecords() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let record = try makeDHTRecord(host: "relay-a.example.org", federationName: "open-net", issuedAt: now)
        var cache = OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "open-net",
                requirePublicEndpoint: false
            )
        )

        let result = cache.ingest([record], now: now)
        let nodes = cache.federationNodes(now: now)

        XCTAssertEqual(result.accepted, [record])
        XCTAssertTrue(result.rejected.isEmpty)
        XCTAssertEqual(nodes.count, 1)
        XCTAssertEqual(nodes[0].endpoint, record.endpoint)
        XCTAssertEqual(nodes[0].relayInfo.federation.mode, .open)
        XCTAssertEqual(nodes[0].relayInfo.federation.name, "open-net")
    }

    func testOpenFederationDHTDiscoveryRejectsPoisonedRecords() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let valid = try makeDHTRecord(host: "relay-a.example.org", federationName: "open-net", issuedAt: now)
        let wrongFederation = try makeDHTRecord(host: "relay-b.example.org", federationName: "other-net", issuedAt: now)
        let tampered = OpenFederationDHTRecord(
            namespace: valid.namespace,
            relayIdentityDigest: valid.relayIdentityDigest,
            endpoint: RelayEndpoint(host: "poison.example.org", port: 443, useTLS: true, transport: .websocket),
            federationName: valid.federationName,
            issuedAt: valid.issuedAt,
            expiresAt: valid.expiresAt,
            relaySigningPublicKey: valid.relaySigningPublicKey,
            signature: valid.signature
        )
        let insecure = try makeDHTRecord(
            endpoint: RelayEndpoint(host: "plain.example.org", port: 80, useTLS: false, transport: .http),
            federationName: "open-net",
            issuedAt: now
        )
        var cache = OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "open-net",
                requirePublicEndpoint: false
            )
        )

        let result = cache.ingest([valid, wrongFederation, tampered, insecure], now: now)

        XCTAssertEqual(result.accepted, [valid])
        XCTAssertEqual(
            result.rejected.map(\.reason),
            [
                .validationFailed(.namespaceMismatch),
                .validationFailed(.invalidSignature),
                .validationFailed(.insecureEndpoint)
            ]
        )
        XCTAssertEqual(cache.records(now: now), [valid])
    }

    func testOpenFederationDHTDiscoveryCapsHostFloods() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let records = try (0..<5).map { index in
            try makeDHTRecord(host: "crowded.example.org", federationName: "open-net", issuedAt: now.addingTimeInterval(Double(index)))
        }
        var cache = OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "open-net",
                requirePublicEndpoint: false,
                maxRecords: 10,
                maxRecordsPerHost: 2
            )
        )

        let result = cache.ingest(records, now: now)

        XCTAssertEqual(result.accepted.count, 2)
        XCTAssertEqual(result.rejected.map(\.reason), [.hostLimitExceeded, .hostLimitExceeded, .hostLimitExceeded])
        XCTAssertEqual(cache.records(now: now).count, 2)
    }

    func testOpenFederationDHTDiscoveryAppliesHostCapToRelayIdentityHostMoves() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let movingKey = SigningKeyPair()
        let original = try makeDHTRecord(
            host: "original.example.org",
            federationName: "open-net",
            signingKey: movingKey,
            issuedAt: now
        )
        let crowded = try makeDHTRecord(
            host: "crowded.example.org",
            federationName: "open-net",
            issuedAt: now.addingTimeInterval(1)
        )
        let movedIntoCrowdedHost = try makeDHTRecord(
            host: "crowded.example.org",
            federationName: "open-net",
            signingKey: movingKey,
            issuedAt: now.addingTimeInterval(2)
        )
        var cache = OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "open-net",
                requirePublicEndpoint: false,
                maxRecords: 10,
                maxRecordsPerHost: 1
            )
        )

        let initial = cache.ingest([original, crowded], now: now)
        XCTAssertEqual(initial.accepted.count, 2)

        let move = cache.ingest([movedIntoCrowdedHost], now: now.addingTimeInterval(2))

        XCTAssertTrue(move.accepted.isEmpty)
        XCTAssertEqual(move.rejected.map(\.reason), [.hostLimitExceeded])
        XCTAssertEqual(
            Set(cache.records(now: now).map(\.endpoint.host)),
            ["original.example.org", "crowded.example.org"]
        )
    }

    func testOpenFederationDHTDiscoveryCapsTotalRecords() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let records = try (0..<5).map { index in
            try makeDHTRecord(
                host: "relay-\(index).example.org",
                federationName: "open-net",
                issuedAt: now.addingTimeInterval(Double(index)),
                lifetimeSeconds: 300 + Double(index)
            )
        }
        var cache = OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "open-net",
                requirePublicEndpoint: false,
                maxRecords: 3,
                maxRecordsPerHost: 2
            )
        )

        _ = cache.ingest(records, now: now)
        let keptHosts = cache.records(now: now).map(\.endpoint.host)

        XCTAssertEqual(cache.count, 3)
        XCTAssertEqual(keptHosts, ["relay-4.example.org", "relay-3.example.org", "relay-2.example.org"])
    }

    func testOpenFederationDHTDiscoveryHandlesChurnAndStaleRecords() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let signingKey = SigningKeyPair()
        let older = try makeDHTRecord(
            host: "relay.example.org",
            federationName: "open-net",
            signingKey: signingKey,
            issuedAt: now,
            lifetimeSeconds: 120
        )
        let newer = try makeDHTRecord(
            host: "relay-new.example.org",
            federationName: "open-net",
            signingKey: signingKey,
            issuedAt: now.addingTimeInterval(60),
            lifetimeSeconds: 300
        )
        var cache = OpenFederationDHTCandidateCache(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "open-net",
                requirePublicEndpoint: false
            )
        )

        XCTAssertEqual(cache.ingest([newer, older], now: now.addingTimeInterval(60)).rejected.map(\.reason), [.staleDuplicate])
        XCTAssertEqual(cache.records(now: now.addingTimeInterval(60)), [newer])

        cache.evictExpired(now: newer.expiresAt.addingTimeInterval(1))
        XCTAssertTrue(cache.records(now: newer.expiresAt.addingTimeInterval(1)).isEmpty)
    }

    func testOpenFederationDHTDiscoveryEnginePublishesAndQueriesBehindFeatureFlag() async throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let federationName = "open-net"
        let namespace = OpenFederationDHTRecord.namespace(federationName: federationName)
        let localEndpoint = RelayEndpoint(host: "local-relay.example.org", port: 443, useTLS: true, transport: .websocket)
        let localKey = SigningKeyPair()
        let remoteRecord = try makeDHTRecord(host: "remote-relay.example.org", federationName: federationName, issuedAt: now)
        let transport = MockOpenFederationDHTTransport(recordsByNamespace: [namespace: [remoteRecord]])
        var engine = OpenFederationDHTDiscoveryEngine(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: federationName,
                requirePublicEndpoint: false,
                maxRecords: 8,
                maxRecordsPerHost: 2,
                maxQueryRecords: 16
            )
        )

        let result = try await engine.refresh(
            transport: transport,
            localEndpoint: localEndpoint,
            signingKey: localKey,
            now: now
        )

        let publishedRecords = await transport.publishedRecords()
        let lastQueryLimit = await transport.lastQueryLimit()
        XCTAssertEqual(result.publishedRecord?.endpoint, localEndpoint)
        XCTAssertEqual(publishedRecords.count, 1)
        XCTAssertEqual(lastQueryLimit, 16)
        XCTAssertEqual(Set(result.nodes.map(\.endpoint.host)), ["local-relay.example.org", "remote-relay.example.org"])
    }

    func testRelayCanServeOpenFederationDHTRecordsWhenEnabled() async throws {
        let federationName = "relay-dht-net"
        let port: UInt16 = 39489
        let serverEndpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                federation: FederationDescriptor(mode: .open, name: federationName),
                relayPeerExchangeLimit: 7,
                openFederationDHTEnabled: true,
                openFederationDHTMaxRecords: 8,
                openFederationDHTMaxRecordsPerHost: 2,
                openFederationDHTMaxQueryRecords: 4,
                allowPrivateFederationEndpoints: true
            )
        )
        let started = expectation(description: "dht relay started")
        server.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let client = RelayClient(endpoint: serverEndpoint)
        let infoResponse = try await client.send(.info())
        XCTAssertEqual(infoResponse.relayInfo?.openFederationDiscovery?.dhtNodeEnabled, true)
        XCTAssertEqual(infoResponse.relayInfo?.openFederationDiscovery?.peerExchangeLimit, 7)

        let record = try makeDHTRecord(
            host: "relay-a.dht.example.org",
            federationName: federationName,
            issuedAt: Date()
        )
        let namespace = OpenFederationDHTRecord.namespace(federationName: federationName)
        let publishResponse = try await client.send(
            .publishOpenFederationDHTRecord(
                PublishOpenFederationDHTRecordRequest(namespace: namespace, record: record)
            )
        )
        XCTAssertEqual(publishResponse.type, .ok)

        let listResponse = try await client.send(
            .listOpenFederationDHTRecords(
                ListOpenFederationDHTRecordsRequest(namespace: namespace, limit: 4)
            )
        )
        XCTAssertEqual(listResponse.type, .openFederationDHTRecords)
        XCTAssertEqual(listResponse.openFederationDHTRecords?.map(\.endpoint.host), ["relay-a.dht.example.org"])
    }

    func testRelayRejectsOpenFederationDHTRoutesWhenDisabled() async throws {
        let federationName = "relay-dht-disabled-net"
        let port: UInt16 = 39490
        let serverEndpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                federation: FederationDescriptor(mode: .open, name: federationName),
                openFederationDHTEnabled: false,
                allowPrivateFederationEndpoints: true
            )
        )
        let started = expectation(description: "disabled dht relay started")
        server.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let record = try makeDHTRecord(
            host: "relay-disabled.dht.example.org",
            federationName: federationName,
            issuedAt: Date()
        )
        let response = try await RelayClient(endpoint: serverEndpoint).send(
            .publishOpenFederationDHTRecord(
                PublishOpenFederationDHTRecordRequest(
                    namespace: OpenFederationDHTRecord.namespace(federationName: federationName),
                    record: record
                )
            )
        )
        XCTAssertEqual(response.type, .error)
        XCTAssertTrue((response.error ?? "").contains("DHT-enabled"))
    }

    func testOpenFederationDHTDiscoveryEngineDisabledDoesNotTouchTransport() async throws {
        let transport = MockOpenFederationDHTTransport()
        var engine = OpenFederationDHTDiscoveryEngine(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: false,
                federationName: "disabled-net",
                requirePublicEndpoint: false
            )
        )

        do {
            _ = try await engine.refresh(
                transport: transport,
                localEndpoint: RelayEndpoint(host: "relay.example.org", port: 443, useTLS: true, transport: .websocket),
                signingKey: SigningKeyPair(),
                now: Date(timeIntervalSince1970: 1_000)
            )
            XCTFail("Expected disabled DHT discovery to throw before transport access")
        } catch {
            XCTAssertEqual(error as? OpenFederationDHTDiscoveryError, .disabled)
        }

        let publishedRecords = await transport.publishedRecords()
        let queryCount = await transport.queryCount()
        XCTAssertTrue(publishedRecords.isEmpty)
        XCTAssertEqual(queryCount, 0)
    }

    func testOpenFederationDHTDiscoveryEngineRejectsInvalidLocalAdvertisementBeforePublish() async throws {
        let transport = MockOpenFederationDHTTransport()
        var engine = OpenFederationDHTDiscoveryEngine(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: "public-net",
                requirePublicEndpoint: true
            )
        )

        do {
            _ = try await engine.refresh(
                transport: transport,
                localEndpoint: RelayEndpoint(host: "127.0.0.1", port: 443, useTLS: true, transport: .websocket),
                signingKey: SigningKeyPair(),
                now: Date(timeIntervalSince1970: 1_000)
            )
            XCTFail("Expected non-public local advertisement to be rejected")
        } catch {
            XCTAssertEqual(
                error as? OpenFederationDHTDiscoveryError,
                .invalidLocalAdvertisement(.nonPublicEndpoint)
            )
        }

        let publishedRecords = await transport.publishedRecords()
        let queryCount = await transport.queryCount()
        XCTAssertTrue(publishedRecords.isEmpty)
        XCTAssertEqual(queryCount, 0)
    }

    func testOpenFederationDHTDiscoveryEngineHonorsTransportQueryLimit() async throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let federationName = "limited-net"
        let namespace = OpenFederationDHTRecord.namespace(federationName: federationName)
        let records = try (0..<5).map { index in
            try makeDHTRecord(host: "relay-\(index).example.org", federationName: federationName, issuedAt: now)
        }
        let transport = MockOpenFederationDHTTransport(recordsByNamespace: [namespace: records])
        var engine = OpenFederationDHTDiscoveryEngine(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: federationName,
                requirePublicEndpoint: false,
                maxRecords: 10,
                maxRecordsPerHost: 2,
                maxQueryRecords: 2
            )
        )

        let result = try await engine.refresh(
            transport: transport,
            localEndpoint: nil,
            signingKey: nil,
            now: now
        )

        let lastQueryLimit = await transport.lastQueryLimit()
        XCTAssertEqual(lastQueryLimit, 2)
        XCTAssertEqual(result.ingestResult.accepted.count, 2)
        XCTAssertEqual(Set(result.nodes.map(\.endpoint.host)), ["relay-0.example.org", "relay-1.example.org"])
    }

    func testOpenFederationDHTDiscoveryEngineFallsBackToCachedNodesWhenQueryFails() async throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let federationName = "resilient-net"
        let namespace = OpenFederationDHTRecord.namespace(federationName: federationName)
        let cachedRecord = try makeDHTRecord(
            host: "cached-relay.example.org",
            federationName: federationName,
            issuedAt: now
        )
        let transport = MockOpenFederationDHTTransport(recordsByNamespace: [namespace: [cachedRecord]])
        var engine = OpenFederationDHTDiscoveryEngine(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: federationName,
                requirePublicEndpoint: false,
                maxRecords: 8,
                maxRecordsPerHost: 2,
                maxQueryRecords: 16
            )
        )

        let warmResult = try await engine.refresh(
            transport: transport,
            localEndpoint: nil,
            signingKey: nil,
            now: now
        )
        XCTAssertEqual(warmResult.nodes.map(\.endpoint.host), ["cached-relay.example.org"])

        await transport.setQueryFailureEnabled(true)
        let fallbackResult = try await engine.refresh(
            transport: transport,
            localEndpoint: nil,
            signingKey: nil,
            now: now.addingTimeInterval(30)
        )

        XCTAssertTrue(fallbackResult.ingestResult.accepted.isEmpty)
        XCTAssertTrue(fallbackResult.ingestResult.rejected.isEmpty)
        XCTAssertEqual(fallbackResult.nodes.map(\.endpoint.host), ["cached-relay.example.org"])
        let queryCount = await transport.queryCount()
        XCTAssertEqual(queryCount, 2)
    }

    func testOpenFederationDHTDiscoveryEngineDropsExpiredCacheWhenQueryFails() async throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let federationName = "stale-cache-net"
        let namespace = OpenFederationDHTRecord.namespace(federationName: federationName)
        let cachedRecord = try makeDHTRecord(
            host: "short-lived-relay.example.org",
            federationName: federationName,
            issuedAt: now,
            lifetimeSeconds: 10
        )
        let transport = MockOpenFederationDHTTransport(recordsByNamespace: [namespace: [cachedRecord]])
        var engine = OpenFederationDHTDiscoveryEngine(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: federationName,
                requirePublicEndpoint: false,
                maxRecords: 8,
                maxRecordsPerHost: 2,
                maxQueryRecords: 16
            )
        )

        let warmResult = try await engine.refresh(
            transport: transport,
            localEndpoint: nil,
            signingKey: nil,
            now: now
        )
        XCTAssertEqual(warmResult.nodes.map(\.endpoint.host), ["short-lived-relay.example.org"])

        await transport.setQueryFailureEnabled(true)
        let fallbackResult = try await engine.refresh(
            transport: transport,
            localEndpoint: nil,
            signingKey: nil,
            now: cachedRecord.expiresAt.addingTimeInterval(OpenFederationDHTRecord.maxClockSkewSeconds + 1)
        )

        XCTAssertTrue(fallbackResult.ingestResult.accepted.isEmpty)
        XCTAssertTrue(fallbackResult.ingestResult.rejected.isEmpty)
        XCTAssertTrue(fallbackResult.nodes.isEmpty)
        let queryCount = await transport.queryCount()
        XCTAssertEqual(queryCount, 2)
    }

    func testOpenFederationDHTHTTPGatewayTransportPublishesWithAuthHeader() async throws {
        let namespace = OpenFederationDHTRecord.namespace(federationName: "gateway-net")
        let record = try makeDHTRecord(
            host: "relay.gateway.example.org",
            federationName: "gateway-net",
            issuedAt: Date(timeIntervalSince1970: 1_000)
        )
        let protocolHarness = DHTGatewayURLProtocolHarness()
        protocolHarness.handler = { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.url?.path, "/mesh/v1/open-federation/dht/records")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer gateway-token")
            let body = try XCTUnwrap(DHTGatewayURLProtocolHarness.bodyData(from: request))
            let decoded = try NoctweaveCoder.decode(DHTGatewayPublishRequestProbe.self, from: body)
            XCTAssertEqual(decoded.namespace, namespace)
            XCTAssertEqual(decoded.record, record)
            return (200, Data())
        }
        let transport = try OpenFederationDHTHTTPGatewayTransport(
            baseURL: try XCTUnwrap(URL(string: "https://gateway.example.org/mesh")),
            session: protocolHarness.makeSession(),
            authToken: " gateway-token "
        )

        try await transport.publish(record, namespace: namespace)
        XCTAssertEqual(protocolHarness.requestCount, 1)
    }

    func testOpenFederationDHTHTTPGatewayTransportQueriesRecords() async throws {
        let namespace = OpenFederationDHTRecord.namespace(federationName: "gateway-net")
        let records = try (0..<3).map { index in
            try makeDHTRecord(
                host: "relay-\(index).gateway.example.org",
                federationName: "gateway-net",
                issuedAt: Date(timeIntervalSince1970: 1_000 + Double(index))
            )
        }
        let response = try NoctweaveCoder.encode(
            DHTGatewayQueryResponseProbe(records: records),
            sortedKeys: true
        )
        let protocolHarness = DHTGatewayURLProtocolHarness()
        protocolHarness.handler = { request in
            XCTAssertEqual(request.httpMethod, "GET")
            XCTAssertEqual(request.url?.path, "/v1/open-federation/dht/records")
            let components = try XCTUnwrap(URLComponents(url: try XCTUnwrap(request.url), resolvingAgainstBaseURL: false))
            let query = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).map { ($0.name, $0.value ?? "") })
            XCTAssertEqual(query["namespace"], namespace)
            XCTAssertEqual(query["limit"], "2")
            return (200, response)
        }
        let transport = try OpenFederationDHTHTTPGatewayTransport(
            baseURL: try XCTUnwrap(URL(string: "https://gateway.example.org")),
            session: protocolHarness.makeSession()
        )

        let queried = try await transport.query(namespace: namespace, limit: 2)
        XCTAssertEqual(queried, Array(records.prefix(2)))
        XCTAssertEqual(protocolHarness.requestCount, 1)
    }

    func testOpenFederationDHTHTTPGatewayRefreshAppliesPoisoningAndFloodGuards() async throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let federationName = "gateway-net"
        let namespace = OpenFederationDHTRecord.namespace(federationName: federationName)
        let valid = try makeDHTRecord(host: "relay-a.gateway.example.org", federationName: federationName, issuedAt: now)
        let wrongFederation = try makeDHTRecord(host: "relay-b.gateway.example.org", federationName: "other-net", issuedAt: now)
        let tampered = OpenFederationDHTRecord(
            namespace: valid.namespace,
            relayIdentityDigest: valid.relayIdentityDigest,
            endpoint: RelayEndpoint(host: "poison.gateway.example.org", port: 443, useTLS: true, transport: .websocket),
            federationName: valid.federationName,
            issuedAt: valid.issuedAt,
            expiresAt: valid.expiresAt,
            relaySigningPublicKey: valid.relaySigningPublicKey,
            signature: valid.signature
        )
        let flooded = try (0..<3).map { index in
            try makeDHTRecord(
                host: "crowded.gateway.example.org",
                federationName: federationName,
                issuedAt: now.addingTimeInterval(Double(index + 1))
            )
        }
        let response = try NoctweaveCoder.encode(
            DHTGatewayQueryResponseProbe(records: [valid, wrongFederation, tampered] + flooded),
            sortedKeys: true
        )
        let protocolHarness = DHTGatewayURLProtocolHarness()
        protocolHarness.handler = { request in
            XCTAssertEqual(request.httpMethod, "GET")
            let components = try XCTUnwrap(URLComponents(url: try XCTUnwrap(request.url), resolvingAgainstBaseURL: false))
            let query = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).map { ($0.name, $0.value ?? "") })
            XCTAssertEqual(query["namespace"], namespace)
            XCTAssertEqual(query["limit"], "12")
            return (200, response)
        }
        let transport = try OpenFederationDHTHTTPGatewayTransport(
            baseURL: try XCTUnwrap(URL(string: "https://gateway.example.org")),
            session: protocolHarness.makeSession()
        )
        var engine = OpenFederationDHTDiscoveryEngine(
            configuration: OpenFederationDHTDiscoveryConfiguration(
                isEnabled: true,
                federationName: federationName,
                requirePublicEndpoint: false,
                maxRecords: 8,
                maxRecordsPerHost: 2,
                maxQueryRecords: 12
            )
        )

        let result = try await engine.refresh(
            transport: transport,
            localEndpoint: nil,
            signingKey: nil,
            now: now
        )

        XCTAssertEqual(result.ingestResult.accepted.count, 3)
        XCTAssertEqual(
            result.ingestResult.rejected.map(\.reason),
            [
                .validationFailed(.namespaceMismatch),
                .validationFailed(.invalidSignature),
                .hostLimitExceeded
            ]
        )
        XCTAssertEqual(result.nodes.count, 3)
        XCTAssertEqual(protocolHarness.requestCount, 1)
    }

    func testOpenFederationDHTHTTPGatewayTransportRejectsOversizedResponse() async throws {
        let protocolHarness = DHTGatewayURLProtocolHarness()
        protocolHarness.handler = { _ in
            (200, Data(repeating: 0x41, count: 2_048))
        }
        let transport = try OpenFederationDHTHTTPGatewayTransport(
            baseURL: try XCTUnwrap(URL(string: "https://gateway.example.org")),
            session: protocolHarness.makeSession(),
            maxResponseBytes: 1_024
        )

        do {
            _ = try await transport.query(namespace: "oversized", limit: 1)
            XCTFail("Expected oversized DHT gateway response to be rejected")
        } catch {
            XCTAssertEqual(error as? OpenFederationDHTGatewayTransportError, .responseTooLarge)
        }
    }

    func testOpenFederationDHTHTTPGatewayTransportRejectsURLCredentialsAndAmbientQuery() async throws {
        for rawURL in [
            "https://user:password@gateway.example.org",
            "https://gateway.example.org?redirect=https://attacker.example"
        ] {
            let transport = try OpenFederationDHTHTTPGatewayTransport(
                baseURL: try XCTUnwrap(URL(string: rawURL))
            )
            do {
                _ = try await transport.query(namespace: "bounded", limit: 1)
                XCTFail("Expected unsafe gateway URL to be rejected")
            } catch {
                XCTAssertEqual(error as? OpenFederationDHTGatewayTransportError, .invalidURL)
            }
        }
    }



    func testInboxAddressIsDerivedFromAccessKey() {
        let accessKey = SigningKeyPair()
        let address = InboxAddress.derived(from: accessKey.publicKeyData)

        XCTAssertTrue(InboxAddress.isValid(address))
        XCTAssertTrue(InboxAddress.isBound(address, to: accessKey.publicKeyData))
        XCTAssertFalse(InboxAddress.isBound(address, to: SigningKeyPair().publicKeyData))
    }




    func testContactShareRejectsMalformedPackageBeforeKDFWork() throws {
        let package = ContactSharePackage(
            version: ContactShare.currentVersion,
            salt: Data(repeating: 0, count: 1),
            kdfRounds: ContactShare.defaultKdfRounds,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0, count: 12),
                ciphertext: Data([1]),
                tag: Data(repeating: 0, count: 16)
            )
        )
        let encoded = try NoctweaveCoder.encode(package)

        XCTAssertThrowsError(try ContactShare.decode(encoded, password: "a strong passphrase")) { error in
            XCTAssertEqual(error as? ContactShareError, .invalidPackage)
        }
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

    func testUnsignedOneTimePrekeyDecodeFailsClosed() throws {
        struct UnsignedOneTimePrekey: Codable {
            let id: UUID
            let publicKey: Data
        }

        let unsigned = UnsignedOneTimePrekey(
            id: UUID(),
            publicKey: AgreementKeyPair().publicKeyData
        )
        let data = try NoctweaveCoder.encode(unsigned)

        XCTAssertThrowsError(try NoctweaveCoder.decode(OneTimePrekey.self, from: data))
    }










    func testGroupRatchetEncryptsOnceForSharedGroupState() throws {
        let groupId = UUID()
        let transcriptHash = Data(SHA256.hash(data: Data("epoch-0".utf8)))
        let groupSecret = Data(SHA256.hash(data: Data("shared group secret".utf8)))
        let alice = Identity(displayName: "Alice")
        let bob = Identity(displayName: "Bob")
        var aliceState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 0,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret,
            localSenderFingerprint: alice.fingerprint
        )
        var bobState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 0,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret,
            localSenderFingerprint: bob.fingerprint
        )

        let envelope = try GroupRatchet.encrypt(
            body: .text("hello group"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            state: &aliceState
        )
        XCTAssertEqual(envelope.groupId, groupId)
        XCTAssertEqual(envelope.epoch, 0)
        XCTAssertEqual(envelope.transcriptHash, transcriptHash)

        let body = try GroupRatchet.decrypt(
            envelope: envelope,
            senderPublicSigningKey: alice.signingKey.publicKeyData,
            state: &bobState
        )
        XCTAssertEqual(body, .text("hello group"))
        XCTAssertNotNil(bobState.receiveChains[alice.fingerprint])
    }

    func testGroupRatchetBucketsVisibleEnvelopeTimestamp() throws {
        let groupId = UUID()
        let transcriptHash = Data(SHA256.hash(data: Data("epoch-0".utf8)))
        let groupSecret = Data(SHA256.hash(data: Data("shared group secret".utf8)))
        let alice = Identity(displayName: "Alice")
        let bob = Identity(displayName: "Bob")
        var aliceState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 0,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret,
            localSenderFingerprint: alice.fingerprint
        )
        var bobState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 0,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret,
            localSenderFingerprint: bob.fingerprint
        )
        let preciseSentAt = Date(timeIntervalSince1970: 1_765_400_123)

        let envelope = try GroupRatchet.encrypt(
            body: .text("bucketed group"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            state: &aliceState,
            sentAt: preciseSentAt,
            metadataBucketSeconds: 300
        )

        XCTAssertEqual(envelope.sentAt, Date(timeIntervalSince1970: 1_765_400_100))
        let body = try GroupRatchet.decrypt(
            envelope: envelope,
            senderPublicSigningKey: alice.signingKey.publicKeyData,
            state: &bobState
        )
        XCTAssertEqual(body, .text("bucketed group"))
    }

    func testGroupRatchetPadsSmallPlaintextsToFixedCiphertextSize() throws {
        let groupId = UUID()
        let transcriptHash = Data(SHA256.hash(data: Data("epoch-padding".utf8)))
        let groupSecret = Data(SHA256.hash(data: Data("shared group padding secret".utf8)))
        let alice = Identity(displayName: "Alice")
        let bob = Identity(displayName: "Bob")
        var aliceState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 0,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret,
            localSenderFingerprint: alice.fingerprint
        )
        var bobState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 0,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret,
            localSenderFingerprint: bob.fingerprint
        )

        let short = try GroupRatchet.encrypt(
            body: .text("hi"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            state: &aliceState
        )
        let longer = try GroupRatchet.encrypt(
            body: .text("this group message is longer but remains in the same padding bucket"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            state: &aliceState
        )

        XCTAssertEqual(short.payload.ciphertext.count, PaddedMessagePlaintext.minimumPaddedBytes)
        XCTAssertEqual(longer.payload.ciphertext.count, PaddedMessagePlaintext.minimumPaddedBytes)
        XCTAssertEqual(
            try GroupRatchet.decrypt(
                envelope: short,
                senderPublicSigningKey: alice.signingKey.publicKeyData,
                state: &bobState
            ),
            .text("hi")
        )
        XCTAssertEqual(
            try GroupRatchet.decrypt(
                envelope: longer,
                senderPublicSigningKey: alice.signingKey.publicKeyData,
                state: &bobState
            ),
            .text("this group message is longer but remains in the same padding bucket")
        )
    }

    func testGroupRatchetAttachmentDescriptorAndChunkUseSameMessageKey() throws {
        let groupId = UUID()
        let transcriptHash = Data(SHA256.hash(data: Data("epoch-attachment".utf8)))
        let groupSecret = Data(SHA256.hash(data: Data("shared group attachment secret".utf8)))
        let alice = Identity(displayName: "Alice")
        let bob = Identity(displayName: "Bob")
        var aliceState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 1,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret,
            localSenderFingerprint: alice.fingerprint
        )
        var bobState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 1,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret,
            localSenderFingerprint: bob.fingerprint
        )
        let plaintext = Data("group image bytes".utf8)
        let attachmentId = UUID()
        let prepared = try GroupRatchet.prepareMessageKey(
            senderFingerprint: alice.fingerprint,
            state: &aliceState
        )
        let descriptor = AttachmentDescriptor(
            id: attachmentId,
            fileName: "image.jpg",
            mimeType: "image/jpeg",
            byteCount: plaintext.count,
            sha256: AttachmentCrypto.sha256(plaintext),
            chunkCount: 1,
            chunkSize: 64 * 1024
        )
        let chunkAAD = AttachmentCrypto.authenticatedData(
            conversationId: "group:\(groupId.uuidString)",
            sessionId: "epoch:1:\(transcriptHash.base64EncodedString())",
            messageCounter: prepared.counter,
            attachmentId: attachmentId,
            chunkIndex: 0,
            byteCount: plaintext.count
        )
        let encryptedChunk = try AttachmentCrypto.encryptChunk(
            plaintext: plaintext,
            messageKey: prepared.key,
            attachmentId: attachmentId,
            chunkIndex: 0,
            authenticatedData: chunkAAD
        )
        let envelope = try GroupRatchet.encrypt(
            body: .attachment(descriptor),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            messageCounter: prepared.counter,
            messageKey: prepared.key,
            state: aliceState
        )

        let decrypted = try GroupRatchet.decryptWithKey(
            envelope: envelope,
            senderPublicSigningKey: alice.signingKey.publicKeyData,
            state: &bobState
        )
        XCTAssertEqual(decrypted.body, .attachment(descriptor))
        let recoveredChunk = try AttachmentCrypto.decryptChunk(
            payload: encryptedChunk,
            messageKey: decrypted.messageKey,
            attachmentId: attachmentId,
            chunkIndex: 0,
            authenticatedData: chunkAAD
        )
        XCTAssertEqual(recoveredChunk, plaintext)
    }

    func testGroupRatchetRejectsReplayAndAllowsBoundedOutOfOrderDelivery() throws {
        let groupId = UUID()
        let transcriptHash = Data(SHA256.hash(data: Data("epoch-0".utf8)))
        let groupSecret = Data(SHA256.hash(data: Data("shared group secret".utf8)))
        let alice = Identity(displayName: "Alice")
        var aliceState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 0,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret,
            localSenderFingerprint: alice.fingerprint
        )
        var receiverState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 0,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret
        )

        let first = try GroupRatchet.encrypt(
            body: .text("first"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            state: &aliceState
        )
        let second = try GroupRatchet.encrypt(
            body: .text("second"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            state: &aliceState
        )

        let secondBody = try GroupRatchet.decrypt(
            envelope: second,
            senderPublicSigningKey: alice.signingKey.publicKeyData,
            state: &receiverState
        )
        XCTAssertEqual(secondBody, .text("second"))

        let firstBody = try GroupRatchet.decrypt(
            envelope: first,
            senderPublicSigningKey: alice.signingKey.publicKeyData,
            state: &receiverState
        )
        XCTAssertEqual(firstBody, .text("first"))

        XCTAssertThrowsError(
            try GroupRatchet.decrypt(
                envelope: second,
                senderPublicSigningKey: alice.signingKey.publicKeyData,
                state: &receiverState
            )
        ) { error in
            XCTAssertEqual(error as? CryptoError, .counterReplay)
        }
    }

    func testGroupRatchetBindsTranscriptAndSignature() throws {
        let groupId = UUID()
        let transcriptHash = Data(SHA256.hash(data: Data("epoch-0".utf8)))
        let wrongTranscriptHash = Data(SHA256.hash(data: Data("wrong epoch".utf8)))
        let groupSecret = Data(SHA256.hash(data: Data("shared group secret".utf8)))
        let alice = Identity(displayName: "Alice")
        let mallory = Identity(displayName: "Mallory")
        var aliceState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 0,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret,
            localSenderFingerprint: alice.fingerprint
        )
        var receiverState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 0,
            transcriptHash: wrongTranscriptHash,
            groupSecret: groupSecret
        )

        let envelope = try GroupRatchet.encrypt(
            body: .text("bound"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            state: &aliceState
        )

        XCTAssertThrowsError(
            try GroupRatchet.decrypt(
                envelope: envelope,
                senderPublicSigningKey: alice.signingKey.publicKeyData,
                state: &receiverState
            )
        ) { error in
            XCTAssertEqual(error as? CryptoError, .invalidPayload)
        }

        var validReceiverState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 0,
            transcriptHash: transcriptHash,
            groupSecret: groupSecret
        )
        XCTAssertThrowsError(
            try GroupRatchet.decrypt(
                envelope: envelope,
                senderPublicSigningKey: mallory.signingKey.publicKeyData,
                state: &validReceiverState
            )
        ) { error in
            XCTAssertEqual(error as? CryptoError, .invalidPayload)
        }
    }

    func testGroupRatchetAdvancesEpochAndRejectsOldEpochMessages() throws {
        let groupId = UUID()
        let transcript0 = Data(SHA256.hash(data: Data("epoch-0".utf8)))
        let transcript1 = Data(SHA256.hash(data: Data("epoch-1".utf8)))
        let groupSecret = Data(SHA256.hash(data: Data("shared group secret".utf8)))
        let commitSecret = Data(SHA256.hash(data: Data("commit secret".utf8)))
        let alice = Identity(displayName: "Alice")
        var aliceState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 0,
            transcriptHash: transcript0,
            groupSecret: groupSecret,
            localSenderFingerprint: alice.fingerprint
        )
        var receiverState = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 0,
            transcriptHash: transcript0,
            groupSecret: groupSecret
        )

        let oldEnvelope = try GroupRatchet.encrypt(
            body: .text("old"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            state: &aliceState
        )

        try aliceState.advanceEpoch(to: 1, transcriptHash: transcript1, commitSecret: commitSecret)
        try receiverState.advanceEpoch(to: 1, transcriptHash: transcript1, commitSecret: commitSecret)

        XCTAssertThrowsError(
            try GroupRatchet.decrypt(
                envelope: oldEnvelope,
                senderPublicSigningKey: alice.signingKey.publicKeyData,
                state: &receiverState
            )
        ) { error in
            XCTAssertEqual(error as? CryptoError, .invalidPayload)
        }

        let newEnvelope = try GroupRatchet.encrypt(
            body: .text("new"),
            senderSigningKey: alice.signingKey,
            senderFingerprint: alice.fingerprint,
            state: &aliceState
        )
        let body = try GroupRatchet.decrypt(
            envelope: newEnvelope,
            senderPublicSigningKey: alice.signingKey.publicKeyData,
            state: &receiverState
        )
        XCTAssertEqual(body, .text("new"))
        XCTAssertEqual(newEnvelope.epoch, 1)
        XCTAssertEqual(newEnvelope.transcriptHash, transcript1)
    }

    func testGroupRatchetRejectsSkippedEpochAdvance() throws {
        let groupId = UUID()
        let transcript0 = Data(SHA256.hash(data: Data("epoch-0".utf8)))
        let transcript1 = Data(SHA256.hash(data: Data("epoch-1".utf8)))
        let transcript2 = Data(SHA256.hash(data: Data("epoch-2".utf8)))
        let groupSecret = Data(SHA256.hash(data: Data("shared group secret".utf8)))
        let commitSecret1 = Data(SHA256.hash(data: Data("commit secret 1".utf8)))
        let commitSecret2 = Data(SHA256.hash(data: Data("commit secret 2".utf8)))
        let alice = Identity(displayName: "Alice")
        var state = GroupRatchetState.initialize(
            groupId: groupId,
            epoch: 0,
            transcriptHash: transcript0,
            groupSecret: groupSecret,
            localSenderFingerprint: alice.fingerprint
        )

        XCTAssertThrowsError(
            try state.advanceEpoch(to: 2, transcriptHash: transcript2, commitSecret: commitSecret2)
        ) { error in
            XCTAssertEqual(error as? CryptoError, .invalidPayload)
        }
        XCTAssertEqual(state.epoch, 0)
        XCTAssertEqual(state.transcriptHash, transcript0)

        try state.advanceEpoch(to: 1, transcriptHash: transcript1, commitSecret: commitSecret1)
        XCTAssertEqual(state.epoch, 1)
        XCTAssertEqual(state.transcriptHash, transcript1)
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

    func testPostQuantumKeyPairsRejectMismatchedAndMalformedDecodedKeys() throws {
        let signingA = try SigningKeyPair.generate()
        let signingB = try SigningKeyPair.generate()
        XCTAssertThrowsError(
            try SigningKeyPair(
                privateKeyData: signingA.privateKeyData,
                publicKeyData: signingB.publicKeyData
            )
        )

        let agreementA = try AgreementKeyPair.generate()
        let agreementB = try AgreementKeyPair.generate()
        XCTAssertThrowsError(
            try AgreementKeyPair(
                privateKeyData: agreementA.privateKeyData,
                publicKeyData: agreementB.publicKeyData
            )
        )

        let malformedSigning = try JSONSerialization.data(withJSONObject: [
            "privateKeyData": Data([0x01]).base64EncodedString(),
            "publicKeyData": signingA.publicKeyData.base64EncodedString()
        ])
        XCTAssertThrowsError(try NoctweaveCoder.decode(SigningKeyPair.self, from: malformedSigning))
    }

    func testPostQuantumSigningSupportsEmptyMessagesAndBoundsWork() throws {
        let signing = try SigningKeyPair.generate()
        let signature = try signing.sign(Data())
        XCTAssertTrue(
            SigningKeyPair.verify(
                signature: signature,
                data: Data(),
                publicKeyData: signing.publicKeyData
            )
        )
        XCTAssertThrowsError(try signing.sign(Data(repeating: 0x41, count: 512 * 1024 + 1))) { error in
            XCTAssertEqual(error as? CryptoError, .invalidPayload)
        }
    }

    func testIdentityRotationVerification() throws {
        var identity = Identity(displayName: "Alice")
        let oldSigningKey = identity.signingKey
        let rotation = try identity.rotateKeys().rotation
        XCTAssertTrue(rotation.verify(using: oldSigningKey.publicKeyData))
        XCTAssertFalse(rotation.verify(using: identity.signingKey.publicKeyData))
    }



    func testRelayStoreDeliverFetch() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        let envelope = makeStructurallyValidRelayEnvelope(
            conversationId: "conv",
            messageCounter: 0,
            marker: 0x11
        )

        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x93]))
        let count = try await store.deliver(envelope, to: inboxId)
        XCTAssertEqual(count, 1)

        let fetched = try await store.fetch(inboxId: inboxId)
        XCTAssertEqual(fetched, [envelope])
    }

    func testRelayStoreInboxLimitIsEnforced() async throws {
        let store = RelayStore(maxInboxMessages: 1)
        let inboxId = InboxAddress.generate()
        let envelope = makeStructurallyValidRelayEnvelope(
            conversationId: "bounded-inbox",
            messageCounter: 0,
            marker: 0x12
        )

        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x94]))
        _ = try await store.deliver(envelope, to: inboxId)
        let secondEnvelope = makeStructurallyValidRelayEnvelope(
            id: UUID(),
            conversationId: "inbox-capacity",
            messageCounter: 1,
            marker: 0x13,
            sentAt: Date(timeIntervalSince1970: 7_200)
        )
        do {
            _ = try await store.deliver(secondEnvelope, to: inboxId)
            XCTFail("Expected inbox capacity to be enforced.")
        } catch RelayStoreError.inboxFull {
            // Expected.
        }
    }

    func testRelayStoreRejectsOversizedEnvelopePayloads() async throws {
        let store = RelayStore()
        let oversizedPayload = EncryptedPayload(
            nonce: Data(repeating: 0x01, count: 12),
            ciphertext: Data(repeating: 0x02, count: 100 * 1024),
            tag: Data(repeating: 0x03, count: 16)
        )
        let envelope = makeTestProtocolEnvelope(
            conversationId: "oversized",
            counter: 0,
            sentAt: Date(),
            payload: oversizedPayload,
            signature: Data(repeating: 0x04, count: 3_309)
        )

        do {
            _ = try await store.deliver(envelope, to: "inbox")
            XCTFail("Expected oversized direct envelope payload to be rejected.")
        } catch RelayStoreError.invalidEnvelopePayload {
            // Expected.
        }

    }

    func testRelayLongPollFetchReturnsMessageDeliveredDuringWait() async throws {
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: 39491)
        let server = RelayServer(
            store: RelayStore(storeURL: nil),
            configuration: RelayConfiguration(
                wakeSupport: DecentralizedWakeSupport(
                    mode: .longPoll,
                    minPollIntervalSeconds: 5,
                    maxPollIntervalSeconds: 5,
                    jitterPermille: 0,
                    longPollTimeoutSeconds: 5
                )
            )
        )
        let started = expectation(description: "long-poll relay started")
        server.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try server.start(host: "0.0.0.0", port: endpoint.port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let client = RelayClient(endpoint: endpoint)
        let accessKey = SigningKeyPair()
        let inboxId = InboxAddress.derived(from: accessKey.publicKeyData)
        var registration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData
        )
        let registrationProof = try makeInboxProof(signingKey: accessKey) { proof in
            try registration.signableData(for: proof)
        }
        registration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            accessProof: registrationProof
        )
        let registrationResponse = try await client.send(.registerInbox(registration))
        XCTAssertEqual(registrationResponse.type, .ok)

        var fetch = FetchRequest(
            inboxId: inboxId,
            routingToken: inboxId,
            maxCount: 10,
            longPollTimeoutSeconds: 5
        )
        let fetchProof = try makeInboxProof(signingKey: accessKey) { proof in
            try fetch.signableData(for: proof)
        }
        fetch = FetchRequest(
            inboxId: inboxId,
            routingToken: inboxId,
            maxCount: 10,
            longPollTimeoutSeconds: 5,
            accessProof: fetchProof
        )
        let signedFetch = fetch

        async let fetchResponse = client.send(.fetch(signedFetch), timeout: 7)
        try await Task.sleep(nanoseconds: 250_000_000)
        let envelope = makeStructurallyValidRelayEnvelope(
            conversationId: "long-poll",
            messageCounter: 1,
            marker: 0x14
        )
        let deliveryResponse = try await client.send(
            .deliver(
                DeliverRequest(
                    inboxId: inboxId,
                    routingToken: inboxId,
                    envelope: envelope,
                    destinationRelay: nil
                )
            )
        )
        XCTAssertEqual(deliveryResponse.type, .delivered)

        let response = try await fetchResponse
        XCTAssertEqual(response.type, .messages)
        XCTAssertEqual(response.messages?.map(\.id), [envelope.id])
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

    func testRelayStoreBoundsAttachmentTTLAtStoreBoundary() async throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }
        let requestedURL = tempDirectory.appendingPathComponent("relay_store.json")
        let sqliteURL = tempDirectory.appendingPathComponent("relay_store.sqlite")
        let store = RelayStore(storeURL: requestedURL, temporalBucketSeconds: 0)
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0xA5, count: 12),
            ciphertext: Data([2, 3]),
            tag: Data(repeating: 0x5A, count: 16)
        )

        let longTTLAttachment = UUID()
        let longTTLStart = Date()
        _ = try await store.storeAttachment(
            attachmentId: longTTLAttachment,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: 10_000_000
        )
        let longTTLExpiry = try relayAttachmentExpiry(at: sqliteURL, attachmentId: longTTLAttachment)
        XCTAssertLessThanOrEqual(longTTLExpiry.timeIntervalSince(longTTLStart), 6 * 3600 + 5)

        let shortTTLAttachment = UUID()
        let shortTTLStart = Date()
        _ = try await store.storeAttachment(
            attachmentId: shortTTLAttachment,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: -1
        )
        let shortTTLExpiry = try relayAttachmentExpiry(at: sqliteURL, attachmentId: shortTTLAttachment)
        XCTAssertGreaterThanOrEqual(shortTTLExpiry.timeIntervalSince(shortTTLStart), 55)
    }

    func testRelayStoreCanOffloadAttachmentChunksToExternalBlobStore() async throws {
        let blobStore = TestAttachmentBlobStore()
        let store = RelayStore(attachmentBlobStore: blobStore)
        let attachmentId = UUID()
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0xA5, count: 12),
            ciphertext: Data([2, 3, 4]),
            tag: Data(repeating: 0x5A, count: 16)
        )

        _ = try await store.storeAttachment(
            attachmentId: attachmentId,
            chunkIndex: 1,
            payload: payload,
            ttlSeconds: 60
        )

        let fetched = try await store.fetchAttachment(attachmentId: attachmentId, chunkIndex: 1)
        XCTAssertEqual(fetched?.payload, payload)
        XCTAssertEqual(blobStore.putCount, 1)
        XCTAssertEqual(blobStore.records.values.first?.backend, "test-blob")
    }

    func testRelayStoreRejectsCorruptExternalAttachmentBlob() async throws {
        let blobStore = TestAttachmentBlobStore()
        let store = RelayStore(attachmentBlobStore: blobStore)
        let attachmentId = UUID()
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0xA5, count: 12),
            ciphertext: Data([2, 3, 4]),
            tag: Data(repeating: 0x5A, count: 16)
        )

        _ = try await store.storeAttachment(
            attachmentId: attachmentId,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: 60
        )
        blobStore.corruptAll()

        do {
            _ = try await store.fetchAttachment(attachmentId: attachmentId, chunkIndex: 0)
            XCTFail("Expected corrupt external attachment blob to be rejected")
        } catch {
            XCTAssertTrue(error is AttachmentBlobStoreError || error is RelayStoreError)
        }
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
        let inboxId = InboxAddress.generate()
        let envelope = makeStructurallyValidRelayEnvelope(
            conversationId: "conv",
            messageCounter: 0,
            marker: 0x15
        )

        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x95]))
        _ = try await store.deliver(envelope, to: inboxId)
        XCTAssertTrue(FileManager.default.fileExists(atPath: sqliteURL.path))
        let sqliteHeader = try Data(contentsOf: sqliteURL).prefix(16)
        XCTAssertEqual(Data("SQLite format 3\0".utf8), Data(sqliteHeader))

        let reloaded = RelayStore(storeURL: requestedURL)
        try await reloaded.loadFromDisk()
        let fetched = try await reloaded.fetch(inboxId: inboxId)
        XCTAssertEqual(fetched.count, 1)
        XCTAssertEqual(fetched.first, envelope)
    }

    func testRelayStoreDiskPersistenceRejectsCorruptNormalizedMessageRow() async throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }
        let requestedURL = tempDirectory.appendingPathComponent("relay_store.json")
        let sqliteURL = tempDirectory.appendingPathComponent("relay_store.sqlite")
        let first = makeStructurallyValidRelayEnvelope(
            conversationId: "conv",
            messageCounter: 1,
            marker: 0x16
        )
        let second = makeStructurallyValidRelayEnvelope(
            conversationId: "conv",
            messageCounter: 2,
            marker: 0x17
        )

        let writer = RelayStore(storeURL: requestedURL)
        let inboxId = InboxAddress.generate()
        try await writer.registerInbox(inboxId: inboxId, accessPublicKey: Data([0x96]))
        _ = try await writer.deliver(first, to: inboxId)
        _ = try await writer.deliver(second, to: inboxId)
        try overwriteMailboxEnvelope(at: sqliteURL, envelopeId: second.id, with: Data([0xDE, 0xAD, 0xBE, 0xEF]))

        let reloaded = RelayStore(storeURL: requestedURL)
        do {
            try await reloaded.loadFromDisk()
            XCTFail("Expected corrupt relay state to fail closed")
        } catch {
            XCTAssertFalse(String(describing: error).isEmpty)
        }
    }

    func testFederationDirectoryKeyLoaderDoesNotReplaceCorruptExistingKey() {
        XCTAssertTrue(FederationDirectorySignature.privateKeyData(from: Data([0xDE, 0xAD])).isEmpty)
        XCTAssertNil(FederationDirectorySignature.publicKeyData(from: Data([0xDE, 0xAD])))
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

    private func makeStructurallyValidRelayEnvelope(
        id: UUID = UUID(),
        conversationId: String,
        messageCounter: UInt64,
        marker: UInt8,
        sentAt: Date = Date()
    ) -> ProtocolEnvelopeV1 {
        let canonicalSentAt = Date(timeIntervalSince1970: floor(sentAt.timeIntervalSince1970))
        return makeTestProtocolEnvelope(
            id: id,
            conversationId: conversationId,
            sessionId: "relay-test-session",
            counter: messageCounter,
            sentAt: canonicalSentAt,
            payload: EncryptedPayload(
                nonce: Data(repeating: marker, count: 12),
                ciphertext: Data(repeating: marker, count: 512),
                tag: Data(repeating: marker, count: 16)
            ),
            signature: Data(repeating: marker, count: 3_309)
        )
    }

    private func overwriteMailboxEnvelope(at sqliteURL: URL, envelopeId: UUID, with data: Data) throws {
        var db: OpaquePointer?
        guard sqlite3_open(sqliteURL.path, &db) == SQLITE_OK, let db else {
            throw NSError(domain: "NoctweaveCoreTests.SQLite", code: 5)
        }
        defer { sqlite3_close(db) }

        let sql = "UPDATE relay_mailbox_envelopes SET value = ?1 WHERE envelope_id = ?2;"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            throw NSError(domain: "NoctweaveCoreTests.SQLite", code: 6)
        }
        defer { sqlite3_finalize(statement) }

        let bindBlobResult = data.withUnsafeBytes { buffer in
            sqlite3_bind_blob(statement, 1, buffer.baseAddress, Int32(buffer.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        }
        guard bindBlobResult == SQLITE_OK else {
            throw NSError(domain: "NoctweaveCoreTests.SQLite", code: 7)
        }
        guard sqlite3_bind_text(statement, 2, envelopeId.uuidString, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)) == SQLITE_OK else {
            throw NSError(domain: "NoctweaveCoreTests.SQLite", code: 8)
        }
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw NSError(domain: "NoctweaveCoreTests.SQLite", code: 9)
        }
        XCTAssertEqual(sqlite3_changes(db), 1)
    }

    private func relayAttachmentExpiry(at sqliteURL: URL, attachmentId: UUID) throws -> Date {
        var db: OpaquePointer?
        guard sqlite3_open(sqliteURL.path, &db) == SQLITE_OK, let db else {
            throw NSError(domain: "NoctweaveCoreTests.SQLite", code: 10)
        }
        defer { sqlite3_close(db) }

        let sql = "SELECT expires_at FROM relay_attachment_chunks WHERE attachment_id = ?1 LIMIT 1;"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            throw NSError(domain: "NoctweaveCoreTests.SQLite", code: 11)
        }
        defer { sqlite3_finalize(statement) }

        guard sqlite3_bind_text(statement, 1, attachmentId.uuidString, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)) == SQLITE_OK else {
            throw NSError(domain: "NoctweaveCoreTests.SQLite", code: 12)
        }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw NSError(domain: "NoctweaveCoreTests.SQLite", code: 13)
        }
        return Date(timeIntervalSince1970: sqlite3_column_double(statement, 0))
    }

    func testClientStateStoreSaveLoad() async throws {
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let fileURL = temp.appendingPathComponent("state.json")
        let store = ClientStateStore(fileURL: fileURL, useEncryption: false)

        let state = try makeCurrentClientState(
            identity: Identity(displayName: "Alice"),
            relay: RelayEndpoint(host: "localhost", port: 9339)
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

        let state = try makeCurrentClientState(
            identity: Identity(displayName: "Alice"),
            relay: RelayEndpoint(host: "localhost", port: 9339)
        )

        try await store.save(state)
        let rawData = try Data(contentsOf: fileURL)
        let rawString = String(data: rawData, encoding: .utf8) ?? ""
        XCTAssertFalse(rawString.contains("Alice"))
        XCTAssertFalse(rawString.contains("inbox"))
        XCTAssertFalse(rawString.contains("identity"))

        let loaded = try await store.load()
        XCTAssertEqual(loaded?.identity.displayName, "Alice")
        XCTAssertEqual(loaded?.inboxId, state.inboxId)
        #else
        throw XCTSkip("Keychain unavailable on this platform.")
        #endif
    }

    func testClientStateStoreSupportsPortableSuppliedEncryptionKey() async throws {
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: temp) }
        let fileURL = temp.appendingPathComponent("state.json")
        let key = SymmetricKey(data: Data(repeating: 0xA7, count: 32))
        let store = ClientStateStore(fileURL: fileURL, useEncryption: true, encryptionKey: key)
        let state = try makeCurrentClientState(
            identity: Identity(displayName: "Portable Key"),
            relay: RelayEndpoint(host: "localhost", port: 9339)
        )

        try await store.save(state)
        let raw = try Data(contentsOf: fileURL)
        XCTAssertNil(raw.range(of: Data("Portable Key".utf8)))
        let reloaded = try await store.load()
        XCTAssertEqual(reloaded?.inboxId, state.inboxId)

        let wrongKeyStore = ClientStateStore(
            fileURL: fileURL,
            useEncryption: true,
            encryptionKey: SymmetricKey(data: Data(repeating: 0xB8, count: 32))
        )
        do {
            _ = try await wrongKeyStore.load()
            XCTFail("Expected a mismatched portable state key to fail closed.")
        } catch {
            // Expected: encrypted state cannot be opened under a different key.
        }
    }

    func testClientStateStoreRejectsOversizedStateBeforeReadingIt() async throws {
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: temp) }
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
        let fileURL = temp.appendingPathComponent("oversized-state.json")
        XCTAssertTrue(FileManager.default.createFile(atPath: fileURL.path, contents: Data([0x00])))
        let handle = try FileHandle(forWritingTo: fileURL)
        try handle.truncate(atOffset: UInt64(ClientStateStore.maximumStoredBytes + 1))
        try handle.close()

        let store = ClientStateStore(fileURL: fileURL, useEncryption: false)
        do {
            _ = try await store.load()
            XCTFail("Expected oversized state to be rejected before decoding")
        } catch {
            // Expected: the sparse file exceeds the hard storage bound.
        }
    }

    func testPrivacyDefaultsToSecureTyping() throws {
        let state = try makeCurrentClientState(
            identity: Identity(displayName: "Alice"),
            relay: RelayEndpoint(host: "localhost", port: 9339)
        )
        XCTAssertTrue(state.privacy.secureTypingEnabled)
        XCTAssertTrue(state.privacy.useSecureCameraCapture)
    }

    func testPrivacySettingsPersist() throws {
        var state = try makeCurrentClientState(
            identity: Identity(displayName: "Alice"),
            relay: RelayEndpoint(host: "localhost", port: 9339)
        )
        state.privacy.secureTypingEnabled = false
        state.privacy.useSecureCameraCapture = true
        let data = try NoctweaveCoder.encode(state)
        let decoded = try NoctweaveCoder.decode(ClientState.self, from: data)
        XCTAssertFalse(decoded.privacy.secureTypingEnabled)
        XCTAssertTrue(decoded.privacy.useSecureCameraCapture)
    }

    func testRelayCertificatePinsPersistAndRejectMalformedRecords() throws {
        let valid = RelayCertificatePinRecord(
            host: "relay.example",
            port: 443,
            useTLS: true,
            transport: .http,
            fingerprintSHA256: Data(repeating: 0xA5, count: 32),
            pinnedAt: Date(timeIntervalSince1970: 1_800_000_000),
            origin: .automaticFirstUse
        )
        let invalid = RelayCertificatePinRecord(
            host: "relay.invalid",
            port: 443,
            useTLS: true,
            transport: .http,
            fingerprintSHA256: Data(repeating: 0xB6, count: 31),
            pinnedAt: Date(timeIntervalSince1970: 1_800_000_000),
            origin: .manual
        )
        let state = try ClientState(
            identity: Identity(displayName: "Alice"),
            relay: RelayEndpoint(host: "relay.example", port: 443, useTLS: true, transport: .http),
            inboxAccessKey: SigningKeyPair.generate(),
            relayCertificatePins: [invalid, valid]
        )

        XCTAssertEqual(state.relayCertificatePins, [valid])
        let decoded = try NoctweaveCoder.decode(
            ClientState.self,
            from: NoctweaveCoder.encode(state)
        )
        XCTAssertEqual(decoded.relayCertificatePins, [valid])
    }

    func testRelayRequestEncoding() throws {
        let relay = RelayRequest.fetch(FetchRequest(inboxId: "inbox", maxCount: 10))
        let data = try NoctweaveCoder.encode(relay)
        let decoded = try NoctweaveCoder.decode(RelayRequest.self, from: data)
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

        let encoded = try NoctweaveCoder.encode(info)
        let decoded = try NoctweaveCoder.decode(RelayInfo.self, from: encoded)
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

    func testRelayHTTPResponsesIncludeSecurityHeaders() {
        var headerLines: [String] = []
        RelayHTTPSecurityHeaders.append(to: &headerLines)
        let headers = Dictionary(
            uniqueKeysWithValues: headerLines.compactMap { line -> (String, String)? in
                guard let separator = line.firstIndex(of: ":") else {
                    return nil
                }
                let name = String(line[..<separator]).lowercased()
                let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
                return (name, value)
            }
        )

        XCTAssertEqual(headers["cache-control"], "no-store")
        XCTAssertEqual(headers["pragma"], "no-cache")
        XCTAssertEqual(headers["x-content-type-options"], "nosniff")
        XCTAssertEqual(headers["x-frame-options"], "DENY")
        XCTAssertEqual(headers["referrer-policy"], "no-referrer")
        XCTAssertEqual(headers["cross-origin-resource-policy"], "same-origin")
        XCTAssertEqual(headers["content-security-policy"], "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        XCTAssertEqual(headers["permissions-policy"], "camera=(), microphone=(), geolocation=(), interest-cohort=()")
    }

    func testRelayRequestRateLimiterCapsSourceWindow() async {
        let limiter = RelayRequestRateLimiter(maxRequests: 2, windowSeconds: 60)
        let now = Date(timeIntervalSince1970: 1_800_000_000)

        let first = await limiter.allow(sourceKey: "client-a", now: now)
        let second = await limiter.allow(sourceKey: "client-a", now: now.addingTimeInterval(1))
        let capped = await limiter.allow(sourceKey: "client-a", now: now.addingTimeInterval(2))
        let otherSource = await limiter.allow(sourceKey: "client-b", now: now.addingTimeInterval(2))
        let afterWindow = await limiter.allow(sourceKey: "client-a", now: now.addingTimeInterval(61))

        XCTAssertTrue(first)
        XCTAssertTrue(second)
        XCTAssertFalse(capped)
        XCTAssertTrue(otherSource)
        XCTAssertTrue(afterWindow)
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

        let accessKey = SigningKeyPair()
        let inbox = InboxAddress.derived(from: accessKey.publicKeyData)
        let request = RelayRequest.deliver(
            DeliverRequest(
                inboxId: inbox,
                routingToken: inbox,
                envelope: makeStructurallyValidRelayEnvelope(
                    conversationId: "auth-test",
                    messageCounter: 1,
                    marker: 0x18
                )
            )
        )
        let unauthorized = try await client.send(request)
        XCTAssertEqual(unauthorized.type, .error)
        XCTAssertTrue((unauthorized.error ?? "").localizedCaseInsensitiveContains("unauthorized"))

        let authenticatedClient = RelayClient(endpoint: clientEndpoint, authToken: relayPassword)
        let registration = try await registerInbox(
            client: authenticatedClient,
            inboxId: inbox,
            accessKey: accessKey
        )
        XCTAssertEqual(registration.type, .ok, registration.error ?? "Inbox registration failed")
        let authorized = try await authenticatedClient.send(request)
        XCTAssertEqual(authorized.type, .delivered)
    }

    func testInboxRegistrationRequiresValidAccessKeyProof() async throws {
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
        let client = RelayClient(endpoint: endpoint)

        let missingProof = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData
        )
        let missingResponse = try await client.send(.registerInbox(missingProof))
        XCTAssertEqual(missingResponse.type, .error)

        let unsigned = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData
        )
        let mismatchedProof = try makeInboxProof(signingKey: accessKey) { proof in
            try unsigned.signableData(for: proof)
        }
        let mismatched = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: otherAccessKey.publicKeyData,
            accessProof: mismatchedProof
        )
        let mismatchedResponse = try await client.send(.registerInbox(mismatched))
        XCTAssertEqual(mismatchedResponse.type, .error)
    }

    func testCoordinatorRegistersAndListsFederationNodes() async throws {
        let coordinatorEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39464)
        let nodeEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39463)
        let federation = FederationDescriptor(mode: .curated, name: "mesh-a")
        let coordinator = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorRegistrationToken: "test-coordinator-registration-token"
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

        let client = RelayClient(
            endpoint: coordinatorEndpoint,
            authToken: "test-coordinator-registration-token"
        )
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

    func testCuratedCoordinatorFailsClosedWithoutRegistrationToken() async throws {
        let coordinatorEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39488)
        let federation = FederationDescriptor(mode: .curated, name: "mesh-token-required")
        let coordinator = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(kind: .coordinator, federation: federation)
        )
        let started = expectation(description: "curated coordinator without token started")
        coordinator.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try coordinator.start(host: "127.0.0.1", port: coordinatorEndpoint.port)
        defer { coordinator.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let response = try await RelayClient(endpoint: coordinatorEndpoint).send(
            .registerFederationNode(
                FederationNodeRegistrationRequest(
                    endpoint: RelayEndpoint(host: "127.0.0.1", port: 39999),
                    relayInfo: RelayConfiguration(kind: .standard, federation: federation).makeInfo(),
                    ttlSeconds: 120
                )
            )
        )

        XCTAssertEqual(response.type, .error)
        XCTAssertEqual(
            response.error,
            "Coordinator configuration error: curated registration requires a token."
        )
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

    func testCoordinatorRegistrationTTLIsBounded() async throws {
        let store = RelayStore(storeURL: nil, temporalBucketSeconds: 300)
        let federation = FederationDescriptor(mode: .open, name: "bounded-ttl")
        let record = try await store.registerFederationNode(
            FederationNodeRegistrationRequest(
                endpoint: RelayEndpoint(host: "relay.example.org", port: 443, useTLS: true),
                relayInfo: RelayConfiguration(kind: .standard, federation: federation).makeInfo(),
                ttlSeconds: Int.max
            )
        )

        XCTAssertGreaterThanOrEqual(record.expiresAt.timeIntervalSince(record.lastHeartbeatAt), 899)
        XCTAssertLessThanOrEqual(record.expiresAt.timeIntervalSince(record.lastHeartbeatAt), 901)
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
                coordinatorRegistrationToken: "test-coordinator-registration-token",
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

        let coordinatorClient = RelayClient(
            endpoint: coordinatorEndpoint,
            authToken: "test-coordinator-registration-token"
        )
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
        let envelope = makeStructurallyValidRelayEnvelope(
            conversationId: "federated-test",
            messageCounter: 1,
            marker: 0x21
        )

        let xClient = RelayClient(endpoint: relayXEndpoint)
        let yClient = RelayClient(endpoint: relayYEndpoint)
        let yRegistration = try await registerInbox(
            client: yClient,
            inboxId: destinationInbox,
            accessKey: destinationAccessKey
        )
        XCTAssertEqual(yRegistration.type, .ok)
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

    func testManualFederationAllowListCanUpdateWhileRunning() async throws {
        let federation = FederationDescriptor(mode: .manual, name: "manual-live")
        let basePort = UInt16.random(in: 40_000...43_000)
        let relayXEndpoint = RelayEndpoint(host: "127.0.0.1", port: basePort)
        let relayYEndpoint = RelayEndpoint(host: "127.0.0.1", port: basePort + 1)

        let relayX = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                federationAllowList: []
            )
        )
        let relayY = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation
            )
        )

        let startedX = expectation(description: "manual relay x started")
        relayX.onEvent = { event in
            if case .started = event {
                startedX.fulfill()
            }
        }
        let startedY = expectation(description: "manual relay y started")
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
        let blockedEnvelope = makeStructurallyValidRelayEnvelope(
            conversationId: "manual-live-test",
            messageCounter: 1,
            marker: 0x22
        )

        let xClient = RelayClient(endpoint: relayXEndpoint)
        let yClient = RelayClient(endpoint: relayYEndpoint)
        let yRegistration = try await registerInbox(
            client: yClient,
            inboxId: destinationInbox,
            accessKey: destinationAccessKey
        )
        XCTAssertEqual(yRegistration.type, .ok)
        let blockedResponse = try await xClient.send(
            .deliver(
                DeliverRequest(
                    inboxId: destinationInbox,
                    routingToken: destinationInbox,
                    envelope: blockedEnvelope,
                    destinationRelay: relayYEndpoint
                )
            )
        )
        XCTAssertEqual(blockedResponse.type, .error)
        XCTAssertTrue((blockedResponse.error ?? "").contains("not in the node list"))

        relayX.updateFederationAllowList([relayYEndpoint])
        let deliveredEnvelope = makeStructurallyValidRelayEnvelope(
            conversationId: "manual-live-test",
            messageCounter: 2,
            marker: 0x23
        )
        let deliveredResponse = try await xClient.send(
            .deliver(
                DeliverRequest(
                    inboxId: destinationInbox,
                    routingToken: destinationInbox,
                    envelope: deliveredEnvelope,
                    destinationRelay: relayYEndpoint
                )
            )
        )
        XCTAssertEqual(deliveredResponse.type, .delivered)

        let fetchResponse = try await registerAndFetch(
            client: yClient,
            inboxId: destinationInbox,
            accessKey: destinationAccessKey,
            maxCount: 10
        )
        XCTAssertEqual(fetchResponse.type, .messages)
        XCTAssertEqual(fetchResponse.messages?.map(\.id), [deliveredEnvelope.id])
    }

    func testRelayConfigurationRuntimeUpdatesAreThreadSafe() {
        let server = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: FederationDescriptor(mode: .manual, name: "race-a")
            )
        )
        let queue = DispatchQueue(label: "NoctweaveTests.RelayConfigurationRace", attributes: .concurrent)
        let group = DispatchGroup()
        let iterations = 250

        for index in 0..<iterations {
            group.enter()
            queue.async {
                let endpoint = RelayEndpoint(
                    host: "relay-\(index).example.org",
                    port: UInt16(9_000 + index)
                )
                server.updateFederationRuntimeSettings(
                    from: RelayConfiguration(
                        kind: .standard,
                        federation: FederationDescriptor(
                            mode: index.isMultiple(of: 2) ? .manual : .curated,
                            name: "race-\(index)"
                        ),
                        federationCoordinatorEndpoints: [endpoint],
                        coordinatorHeartbeatSeconds: 15 + index,
                        coordinatorDirectoryMaxStalenessSeconds: 30 + index,
                        federationAllowList: [endpoint]
                    )
                )
                group.leave()
            }

            group.enter()
            queue.async {
                let snapshot = server.configuration
                _ = snapshot.makeInfo()
                _ = snapshot.federationAllowList
                _ = snapshot.federationCoordinatorEndpoints
                group.leave()
            }
        }

        XCTAssertEqual(group.wait(timeout: .now() + 5), .success)
        let final = server.configuration
        XCTAssertFalse(final.federation.name?.isEmpty ?? true)
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
                coordinatorRegistrationToken: "test-coordinator-registration-token",
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

        let coordinatorClient = RelayClient(
            endpoint: coordinatorEndpoint,
            authToken: "test-coordinator-registration-token"
        )
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
        let envelope = makeStructurallyValidRelayEnvelope(
            conversationId: "strict-allowlist-test",
            messageCounter: 1,
            marker: 0x24
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
        let envelope = makeStructurallyValidRelayEnvelope(
            conversationId: "forward-auth-isolation",
            messageCounter: 1,
            marker: 0x25
        )

        let xClient = RelayClient(endpoint: relayXEndpoint, authToken: "client-token")
        let yClient = RelayClient(endpoint: relayYEndpoint, authToken: "client-token")
        let yRegistration = try await registerInbox(
            client: yClient,
            inboxId: destinationInbox,
            accessKey: destinationAccessKey
        )
        XCTAssertEqual(yRegistration.type, .ok)
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
        let envelope = makeStructurallyValidRelayEnvelope(
            conversationId: "forward-auth-success",
            messageCounter: 1,
            marker: 0x26
        )

        let xClient = RelayClient(endpoint: relayXEndpoint, authToken: "client-token")
        let yClient = RelayClient(endpoint: relayYEndpoint, authToken: "relay-token")
        let yRegistration = try await registerInbox(
            client: yClient,
            inboxId: destinationInbox,
            accessKey: destinationAccessKey
        )
        XCTAssertEqual(yRegistration.type, .ok)
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


    func testManualFederationForwardsBetweenStandardListedRelays() async throws {
        let federation = FederationDescriptor(mode: .manual, name: "manual-mesh")
        let relayAEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39526)
        let relayBEndpoint = RelayEndpoint(host: "127.0.0.1", port: 39527)

        let relayA = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                federationAllowList: [relayBEndpoint]
            )
        )
        let relayB = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .standard,
                federation: federation,
                federationAllowList: [relayAEndpoint]
            )
        )

        let startedA = expectation(description: "relay A started (manual federation)")
        relayA.onEvent = { event in
            if case .started = event {
                startedA.fulfill()
            }
        }
        let startedB = expectation(description: "relay B started (manual federation)")
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

        let destinationAccessKey = SigningKeyPair()
        let destinationInbox = InboxAddress.derived(from: destinationAccessKey.publicKeyData)
        let envelope = makeStructurallyValidRelayEnvelope(
            conversationId: "manual-federation-test",
            messageCounter: 1,
            marker: 0x27
        )

        let relayAClient = RelayClient(endpoint: relayAEndpoint)
        let relayBClient = RelayClient(endpoint: relayBEndpoint)
        let relayBRegistration = try await registerInbox(
            client: relayBClient,
            inboxId: destinationInbox,
            accessKey: destinationAccessKey
        )
        XCTAssertEqual(relayBRegistration.type, .ok)
        let deliverResponse = try await relayAClient.send(
            .deliver(
                DeliverRequest(
                    inboxId: destinationInbox,
                    routingToken: destinationInbox,
                    envelope: envelope,
                    destinationRelay: relayBEndpoint
                )
            )
        )
        XCTAssertEqual(deliverResponse.type, .delivered)

        let fetchResponse = try await registerAndFetch(
            client: relayBClient,
            inboxId: destinationInbox,
            accessKey: destinationAccessKey,
            maxCount: 10
        )
        XCTAssertEqual(fetchResponse.type, .messages)
        XCTAssertEqual(fetchResponse.messages?.first?.id, envelope.id)
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
                coordinatorRegistrationToken: "test-coordinator-registration-token",
                coordinatorDirectorySigningPrivateKey: coordinatorAPrivateKey
            )
        )
        let coordinatorNodeB = RelayServer(
            store: RelayStore(storeURL: nil, temporalBucketSeconds: 300),
            configuration: RelayConfiguration(
                kind: .coordinator,
                federation: federation,
                coordinatorRegistrationToken: "test-coordinator-registration-token",
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

        let coordinatorClient = RelayClient(
            endpoint: coordinatorA,
            authToken: "test-coordinator-registration-token"
        )
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
        let envelope = makeStructurallyValidRelayEnvelope(
            conversationId: "strict-quorum-test",
            messageCounter: 1,
            marker: 0x28
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
        let attachmentId = UUID()
        let plaintext = Data("image-bytes".utf8)
        let counter: UInt64 = 7
        let messageKey = SymmetricKey(size: .bits256)
        let aad = AttachmentCrypto.authenticatedData(
            conversationId: "direct-v4-conversation",
            sessionId: "direct-v4-session",
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
            messageKey: messageKey,
            attachmentId: attachmentId,
            chunkIndex: 0,
            authenticatedData: aad
        )
        XCTAssertEqual(decrypted, plaintext)
    }

    func testAttachmentMessageBodyRoundTrip() throws {
        let descriptor = AttachmentDescriptor(
            fileName: nil,
            mimeType: "image/jpeg",
            byteCount: 123,
            sha256: Data([0x01, 0x02]),
            chunkCount: 1,
            chunkSize: 123
        )
        let body = MessageBody.attachment(descriptor)
        let data = try NoctweaveCoder.encode(body)
        let decoded = try NoctweaveCoder.decode(MessageBody.self, from: data)
        XCTAssertEqual(decoded, body)
    }

    func testAttachmentDescriptorStructuralValidationEnforcesPrivacyAndResourceBounds() {
        let valid = AttachmentDescriptor(
            fileName: nil,
            mimeType: "image/jpeg",
            byteCount: 65_537,
            sha256: Data(repeating: 0x42, count: 32),
            chunkCount: 2,
            chunkSize: 65_536,
            relayTTLSeconds: 1_800
        )
        XCTAssertTrue(valid.isStructurallyValid())

        let leakedName = AttachmentDescriptor(
            fileName: "../../private.jpg",
            mimeType: valid.mimeType,
            byteCount: valid.byteCount,
            sha256: valid.sha256,
            chunkCount: valid.chunkCount,
            chunkSize: valid.chunkSize
        )
        XCTAssertFalse(leakedName.isStructurallyValid())

        let excessiveChunks = AttachmentDescriptor(
            fileName: nil,
            mimeType: valid.mimeType,
            byteCount: 129 * 1_024,
            sha256: valid.sha256,
            chunkCount: 129,
            chunkSize: 1_024
        )
        XCTAssertFalse(excessiveChunks.isStructurallyValid())

        let injectedMIME = AttachmentDescriptor(
            fileName: nil,
            mimeType: "image/jpeg\r\nX-Injected: true",
            byteCount: 1,
            sha256: valid.sha256,
            chunkCount: 1,
            chunkSize: 1
        )
        XCTAssertFalse(injectedMIME.isStructurallyValid())
    }


    func testMessageDecodingAllowsMissingOptionalSenderDisplayName() throws {
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

    func testClientStateUpsertContactDeduplicatesAndRemapsReferences() throws {
        let identity = Identity(displayName: "Owner")
        let relay = RelayEndpoint(host: "relay.example", port: 443, useTLS: true, transport: .http)
        var state = try makeCurrentClientState(identity: identity, relay: relay)

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

    func testClientStateUpsertContactMatchesByAddressWhenFingerprintChanges() throws {
        let identity = Identity(displayName: "Owner")
        let relay = RelayEndpoint(host: "relay.example", port: 443, useTLS: true, transport: .http)
        var state = try makeCurrentClientState(identity: identity, relay: relay)

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

    func testClientStateMergeUpsertConversationPreservesConcurrentMessages() throws {
        let identity = Identity(displayName: "Owner")
        let relay = RelayEndpoint(host: "relay.example", port: 443, useTLS: true, transport: .http)
        let contactId = UUID()
        var state = try makeCurrentClientState(identity: identity, relay: relay)

        let received = Message(
            id: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!,
            direction: .received,
            body: "arrived while sending",
            timestamp: Date(timeIntervalSince1970: 10),
            counter: 1
        )
        var existing = makeConversation(contactId: contactId, body: "seed", timestamp: Date(timeIntervalSince1970: 1))
        existing.messages = [received]
        existing.unreadCount = 1
        state.conversations = [existing]

        let sent = Message(
            id: UUID(uuidString: "BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF")!,
            direction: .sent,
            body: "sent while receiving",
            timestamp: Date(timeIntervalSince1970: 11),
            counter: 2
        )
        var outboundSnapshot = existing
        outboundSnapshot.messages = [sent]
        outboundSnapshot.unreadCount = 0
        outboundSnapshot.sendChain = ChainKeyState(keyData: Data(repeating: 0x44, count: 32), counter: 3)

        state.mergeUpsert(conversation: outboundSnapshot)

        XCTAssertEqual(state.conversations.count, 1)
        XCTAssertEqual(state.conversations[0].messages.map(\.body), ["arrived while sending", "sent while receiving"])
        XCTAssertEqual(state.conversations[0].unreadCount, 1)
        XCTAssertEqual(state.conversations[0].sendChain.counter, 3)
    }

    func testClientStateMergeUpsertGroupPreservesConcurrentMessages() throws {
        let identity = Identity(displayName: "Owner")
        let relay = RelayEndpoint(host: "relay.example", port: 443, useTLS: true, transport: .http)
        let groupId = UUID()
        var state = try makeCurrentClientState(identity: identity, relay: relay)

        let received = Message(
            id: UUID(uuidString: "CCCCCCCC-DDDD-EEEE-FFFF-AAAAAAAAAAAA")!,
            direction: .received,
            senderDisplayName: "Peer",
            body: "group inbound",
            timestamp: Date(timeIntervalSince1970: 20),
            counter: 4
        )
        let existing = GroupConversation(
            id: groupId,
            title: "Team",
            memberContactIds: [],
            messages: [received],
            unreadCount: 1
        )
        state.groups = [existing]

        let sent = Message(
            id: UUID(uuidString: "DDDDDDDD-EEEE-FFFF-AAAA-BBBBBBBBBBBB")!,
            direction: .sent,
            senderDisplayName: "Owner",
            body: "group outbound",
            timestamp: Date(timeIntervalSince1970: 21),
            counter: 5
        )
        var outboundSnapshot = existing
        outboundSnapshot.messages = [sent]
        outboundSnapshot.unreadCount = 0
        outboundSnapshot.relayEpoch = 8

        state.mergeUpsert(group: outboundSnapshot)

        XCTAssertEqual(state.groups.count, 1)
        XCTAssertEqual(state.groups[0].messages.map(\.body), ["group inbound", "group outbound"])
        XCTAssertEqual(state.groups[0].unreadCount, 1)
        XCTAssertEqual(state.groups[0].relayEpoch, 8)
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
        var state = try makeCurrentClientState(
            identity: identity,
            relay: relay
        )
        state.groups = [group]

        let data = try NoctweaveCoder.encode(state)
        let decoded = try NoctweaveCoder.decode(ClientState.self, from: data)
        XCTAssertEqual(decoded.groups.count, 1)
        XCTAssertEqual(decoded.groups[0].title, "Team")
        XCTAssertEqual(decoded.groups[0].messages.first?.senderDisplayName, "Bob")
    }

    func testOnionTransportPeelsThreeHopsInOrder() throws {
        let hop1 = AgreementKeyPair()
        let hop2 = AgreementKeyPair()
        let hop3 = AgreementKeyPair()
        let finalPayload = Data("fixed-size-message-frame".utf8)
        let packet = try OnionTransport.seal(
            finalPayload: finalPayload,
            hops: [
                OnionHopDescriptor(
                    hopId: "relay-a",
                    publicKeyData: hop1.publicKeyData,
                    routingInstruction: "forward:relay-b",
                    delayBucketSeconds: 60
                ),
                OnionHopDescriptor(
                    hopId: "relay-b",
                    publicKeyData: hop2.publicKeyData,
                    routingInstruction: "forward:relay-c",
                    delayBucketSeconds: 120
                ),
                OnionHopDescriptor(
                    hopId: "relay-c",
                    publicKeyData: hop3.publicKeyData,
                    routingInstruction: "deliver:target-inbox",
                    delayBucketSeconds: 300
                )
            ]
        )

        XCTAssertEqual(packet.entryHopId, "relay-a")
        let first = try OnionTransport.peel(layer: packet.layer, using: hop1)
        XCTAssertEqual(first.routingInstruction, "forward:relay-b")
        XCTAssertEqual(first.nextHopId, "relay-b")
        XCTAssertNil(first.finalPayload)

        let secondLayer = try XCTUnwrap(first.nextLayer)
        let second = try OnionTransport.peel(layer: secondLayer, using: hop2)
        XCTAssertEqual(second.routingInstruction, "forward:relay-c")
        XCTAssertEqual(second.nextHopId, "relay-c")
        XCTAssertNil(second.finalPayload)

        let thirdLayer = try XCTUnwrap(second.nextLayer)
        let third = try OnionTransport.peel(layer: thirdLayer, using: hop3)
        XCTAssertEqual(third.routingInstruction, "deliver:target-inbox")
        XCTAssertNil(third.nextHopId)
        XCTAssertNil(third.nextLayer)
        XCTAssertEqual(third.finalPayload, finalPayload)
    }

    func testOnionTransportRejectsWrongHopKey() throws {
        let intendedHop = AgreementKeyPair()
        let wrongHop = AgreementKeyPair()
        let packet = try OnionTransport.seal(
            finalPayload: Data("payload".utf8),
            hops: [
                OnionHopDescriptor(
                    hopId: "relay-a",
                    publicKeyData: intendedHop.publicKeyData,
                    routingInstruction: "deliver"
                )
            ]
        )

        XCTAssertThrowsError(try OnionTransport.peel(layer: packet.layer, using: wrongHop))
    }

    func testOnionTransportRejectsTamperedLayer() throws {
        let hop = AgreementKeyPair()
        let packet = try OnionTransport.seal(
            finalPayload: Data("payload".utf8),
            hops: [
                OnionHopDescriptor(
                    hopId: "relay-a",
                    publicKeyData: hop.publicKeyData,
                    routingInstruction: "deliver"
                )
            ]
        )
        var tamperedTag = packet.layer.payload.tag
        tamperedTag.append(0x01)
        let tamperedLayer = OnionLayer(
            hopId: packet.layer.hopId,
            kemCiphertext: packet.layer.kemCiphertext,
            payload: EncryptedPayload(
                nonce: packet.layer.payload.nonce,
                ciphertext: packet.layer.payload.ciphertext,
                tag: tamperedTag
            )
        )

        XCTAssertThrowsError(try OnionTransport.peel(layer: tamperedLayer, using: hop))
    }

    func testRelayInfoAdvertisesOptionalOnionTransportSupport() throws {
        let info = RelayConfiguration(
            onionTransport: OnionTransportSupport(enabled: true, maxHops: 5, requiresFixedSizePackets: true)
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))

        XCTAssertEqual(info.onionTransport?.enabled, true)
        XCTAssertEqual(info.onionTransport?.maxHops, 5)
        XCTAssertEqual(info.onionTransport?.requiresFixedSizePackets, true)

        let decoded = try NoctweaveCoder.decode(RelayInfo.self, from: NoctweaveCoder.encode(info))
        XCTAssertEqual(decoded.onionTransport, info.onionTransport)
    }

    func testRelayInfoSuppressesUnusableOnionTransportSupport() {
        let disabledInfo = RelayConfiguration(
            onionTransport: OnionTransportSupport(enabled: false, maxHops: 5, requiresFixedSizePackets: true)
        ).makeInfo()
        XCTAssertNil(disabledInfo.onionTransport)

        let oneHopInfo = RelayConfiguration(
            onionTransport: OnionTransportSupport(enabled: true, maxHops: 1, requiresFixedSizePackets: true)
        ).makeInfo()
        XCTAssertNil(oneHopInfo.onionTransport)

        XCTAssertEqual(
            OnionTransportPolicyValidator.issues(for: OnionTransportSupport(enabled: true, maxHops: 1)),
            [.insufficientHops]
        )
    }

    func testMixnetSchedulerBuildsDeterministicBatchWithCoverTraffic() throws {
        let policy = MixnetTransportSupport(
            batchIntervalSeconds: 30,
            minBatchSize: 5,
            coverPacketsPerBatch: 1,
            maxDelaySeconds: 10
        )
        let now = Date(timeIntervalSince1970: 1_000)
        let secret = Data("mixnet-test-secret".utf8)
        let first = try MixnetScheduler.makeBatchPlan(
            pendingPacketIds: ["msg-c", "msg-a", "msg-b"],
            now: now,
            policy: policy,
            secret: secret
        )
        let second = try MixnetScheduler.makeBatchPlan(
            pendingPacketIds: ["msg-b", "msg-c", "msg-a"],
            now: now,
            policy: policy,
            secret: secret
        )

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.realPacketCount, 3)
        XCTAssertEqual(first.coverPacketCount, 2)
        XCTAssertEqual(first.packets.count, 5)
        XCTAssertTrue(first.packets.allSatisfy { $0.batchId == first.batchId })
        XCTAssertTrue(first.packets.allSatisfy { $0.releaseAt == first.releaseAt })
        XCTAssertLessThanOrEqual(first.packets.first?.delaySeconds ?? 0, 10)
    }

    func testMixnetSchedulerCanEmitPureCoverBatch() throws {
        let policy = MixnetTransportSupport(
            batchIntervalSeconds: 60,
            minBatchSize: 3,
            coverPacketsPerBatch: 3,
            maxDelaySeconds: 0
        )
        let plan = try MixnetScheduler.makeBatchPlan(
            pendingPacketIds: [],
            now: Date(timeIntervalSince1970: 1_001),
            policy: policy,
            secret: Data("cover-secret".utf8)
        )

        XCTAssertEqual(plan.realPacketCount, 0)
        XCTAssertEqual(plan.coverPacketCount, 3)
        XCTAssertEqual(plan.releaseAt, Date(timeIntervalSince1970: 1_020))
        XCTAssertTrue(plan.packets.allSatisfy { $0.packetId.hasPrefix("cover-") })
    }

    func testMixnetSchedulerBuildsContinuousCoverCycle() throws {
        let policy = MixnetTransportSupport(
            batchIntervalSeconds: 30,
            minBatchSize: 4,
            coverPacketsPerBatch: 2,
            maxDelaySeconds: 10
        )
        let now = Date(timeIntervalSince1970: 1_001)
        let secret = Data("cycle-secret".utf8)

        let first = try MixnetScheduler.makeCoverCyclePlan(
            pendingPacketIdsByBatch: [
                ["message-a", "message-b"],
                [],
                ["message-c"]
            ],
            now: now,
            policy: policy,
            secret: secret,
            horizonSeconds: 95
        )
        let second = try MixnetScheduler.makeCoverCyclePlan(
            pendingPacketIdsByBatch: [
                ["message-b", "message-a"],
                [],
                ["message-c"]
            ],
            now: now,
            policy: policy,
            secret: secret,
            horizonSeconds: 95
        )

        XCTAssertEqual(first, second)
        XCTAssertTrue(first.coversEveryInterval)
        XCTAssertEqual(first.cycleStart, Date(timeIntervalSince1970: 1_020))
        XCTAssertEqual(first.batchIntervalSeconds, 30)
        XCTAssertEqual(first.batches.count, 4)
        XCTAssertEqual(first.batches.map(\.realPacketCount), [2, 0, 1, 0])
        XCTAssertTrue(first.batches.allSatisfy { $0.coverPacketCount >= 2 })
        XCTAssertTrue(first.batches.allSatisfy { $0.packets.count >= policy.minBatchSize })
    }

    func testMixnetInterRelayCoverCoordinatorBuildsDeterministicLinkCoverPlan() throws {
        let policy = MixnetTransportSupport(
            batchIntervalSeconds: 30,
            minBatchSize: 4,
            coverPacketsPerBatch: 2,
            maxDelaySeconds: 10
        )
        let relays = [
            mixnetRelayPeer(id: "relay-a", operatorId: "operator-a", host: "relay-a.example"),
            mixnetRelayPeer(id: "relay-b", operatorId: "operator-b", host: "relay-b.example"),
            mixnetRelayPeer(id: "relay-c", operatorId: "operator-c", host: "relay-c.example")
        ]
        let secret = Data("inter-relay-cover-secret".utf8)

        let first = try MixnetInterRelayCoverCoordinator.makePlan(
            relays: relays,
            now: Date(timeIntervalSince1970: 1_001),
            policy: policy,
            secret: secret,
            horizonSeconds: 95,
            coverPacketsPerLink: 2
        )
        let second = try MixnetInterRelayCoverCoordinator.makePlan(
            relays: relays.reversed(),
            now: Date(timeIntervalSince1970: 1_001),
            policy: policy,
            secret: secret,
            horizonSeconds: 95,
            coverPacketsPerLink: 2
        )

        XCTAssertEqual(first, second)
        XCTAssertTrue(first.coversEveryRelayLinkEachInterval)
        XCTAssertEqual(first.cycleStart, Date(timeIntervalSince1970: 1_020))
        XCTAssertEqual(first.batches.count, 4)
        XCTAssertEqual(first.relayIds, ["relay-a", "relay-b", "relay-c"])
        XCTAssertTrue(first.batches.allSatisfy { $0.packets.count == 12 })
        XCTAssertTrue(first.batches.flatMap(\.packets).allSatisfy { $0.packetId.hasPrefix("relay-cover-") })
        XCTAssertTrue(first.batches.flatMap(\.packets).allSatisfy { $0.sourceRelayId != $0.destinationRelayId })
        XCTAssertLessThanOrEqual(first.batches.first?.packets.first?.delaySeconds ?? 0, 10)
    }

    func testMixnetInterRelayCoverCoordinatorRejectsWeakRelaySets() {
        let policy = MixnetTransportSupport(batchIntervalSeconds: 30, minBatchSize: 4, coverPacketsPerBatch: 2)
        let diverse = [
            mixnetRelayPeer(id: "relay-a", operatorId: "operator-a", host: "relay-a.example"),
            mixnetRelayPeer(id: "relay-b", operatorId: "operator-b", host: "relay-b.example")
        ]

        XCTAssertThrowsError(
            try MixnetInterRelayCoverCoordinator.makePlan(
                relays: diverse,
                now: Date(),
                policy: policy,
                secret: Data(),
                horizonSeconds: 60
            )
        ) { error in
            XCTAssertEqual(error as? MixnetInterRelayCoverError, .emptySecret)
        }
        XCTAssertThrowsError(
            try MixnetInterRelayCoverCoordinator.makePlan(
                relays: diverse,
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8),
                horizonSeconds: 0
            )
        ) { error in
            XCTAssertEqual(error as? MixnetInterRelayCoverError, .invalidHorizon)
        }
        XCTAssertThrowsError(
            try MixnetInterRelayCoverCoordinator.makePlan(
                relays: diverse,
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8),
                horizonSeconds: 60,
                coverPacketsPerLink: 0
            )
        ) { error in
            XCTAssertEqual(error as? MixnetInterRelayCoverError, .invalidCoverPacketCount)
        }

        let duplicateRelay = [
            mixnetRelayPeer(id: "relay-a", operatorId: "operator-a", host: "relay-a.example"),
            mixnetRelayPeer(id: " relay-a ", operatorId: "operator-b", host: "relay-b.example")
        ]
        XCTAssertThrowsError(
            try MixnetInterRelayCoverCoordinator.makePlan(
                relays: duplicateRelay,
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8),
                horizonSeconds: 60
            )
        ) { error in
            XCTAssertEqual(error as? MixnetInterRelayCoverError, .invalidRelaySet)
        }

        let sameOperator = [
            mixnetRelayPeer(id: "relay-a", operatorId: "operator-a", host: "relay-a.example"),
            mixnetRelayPeer(id: "relay-b", operatorId: "operator-a", host: "relay-b.example")
        ]
        XCTAssertThrowsError(
            try MixnetInterRelayCoverCoordinator.makePlan(
                relays: sameOperator,
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8),
                horizonSeconds: 60
            )
        ) { error in
            XCTAssertEqual(error as? MixnetInterRelayCoverError, .insufficientDiversity)
        }

        let sameHost = [
            mixnetRelayPeer(id: "relay-a", operatorId: "operator-a", host: "relay-shared.example"),
            mixnetRelayPeer(id: "relay-b", operatorId: "operator-b", host: "relay-shared.example")
        ]
        XCTAssertThrowsError(
            try MixnetInterRelayCoverCoordinator.makePlan(
                relays: sameHost,
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8),
                horizonSeconds: 60
            )
        ) { error in
            XCTAssertEqual(error as? MixnetInterRelayCoverError, .insufficientDiversity)
        }

        XCTAssertThrowsError(
            try MixnetInterRelayCoverCoordinator.makePlan(
                relays: [mixnetRelayPeer(id: "relay-a", operatorId: "operator-a", host: "relay-a.example", useTLS: false)],
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8),
                horizonSeconds: 60
            )
        ) { error in
            XCTAssertEqual(error as? MixnetInterRelayCoverError, .invalidEndpoint)
        }
    }

    func testMixnetSchedulerRejectsMalformedInputs() {
        let policy = MixnetTransportSupport(minBatchSize: 1, coverPacketsPerBatch: 0)
        XCTAssertThrowsError(
            try MixnetScheduler.makeBatchPlan(
                pendingPacketIds: ["msg-a"],
                now: Date(),
                policy: policy,
                secret: Data()
            )
        ) { error in
            XCTAssertEqual(error as? MixnetSchedulerError, .emptySecret)
        }
        XCTAssertThrowsError(
            try MixnetScheduler.makeBatchPlan(
                pendingPacketIds: ["msg-a", " "],
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? MixnetSchedulerError, .blankPacketId)
        }
        XCTAssertThrowsError(
            try MixnetScheduler.makeCoverCyclePlan(
                pendingPacketIds: [],
                now: Date(),
                policy: policy,
                secret: Data("secret".utf8),
                horizonSeconds: 0
            )
        ) { error in
            XCTAssertEqual(error as? MixnetSchedulerError, .invalidHorizon)
        }
    }

    func testMixnetPacketPadderProducesFixedSizePackets() throws {
        let shortPayload = Data("short".utf8)
        let longerPayload = Data("longer-payload".utf8)
        let fixedPayloadSize = 64

        let shortPacket = try MixnetPacketPadder.pad(
            packetId: " packet-a ",
            payload: shortPayload,
            fixedPayloadSize: fixedPayloadSize
        )
        let longerPacket = try MixnetPacketPadder.pad(
            packetId: "packet-b",
            payload: longerPayload,
            fixedPayloadSize: fixedPayloadSize
        )

        XCTAssertEqual(shortPacket.packetId, "packet-a")
        XCTAssertEqual(shortPacket.paddedPayload.count, fixedPayloadSize)
        XCTAssertEqual(longerPacket.paddedPayload.count, fixedPayloadSize)
        XCTAssertEqual(shortPacket.fixedPayloadSize, longerPacket.fixedPayloadSize)
        XCTAssertEqual(try MixnetPacketPadder.open(shortPacket), shortPayload)
        XCTAssertEqual(try MixnetPacketPadder.open(longerPacket), longerPayload)
    }

    func testMixnetPacketPadderRejectsMalformedPackets() throws {
        XCTAssertThrowsError(
            try MixnetPacketPadder.pad(packetId: " ", payload: Data("payload".utf8), fixedPayloadSize: 32)
        ) { error in
            XCTAssertEqual(error as? MixnetPacketPaddingError, .blankPacketId)
        }
        XCTAssertThrowsError(
            try MixnetPacketPadder.pad(packetId: "packet", payload: Data(), fixedPayloadSize: 32)
        ) { error in
            XCTAssertEqual(error as? MixnetPacketPaddingError, .invalidPayload)
        }
        XCTAssertThrowsError(
            try MixnetPacketPadder.pad(packetId: "packet", payload: Data("payload".utf8), fixedPayloadSize: 0)
        ) { error in
            XCTAssertEqual(error as? MixnetPacketPaddingError, .invalidFixedSize)
        }
        XCTAssertThrowsError(
            try MixnetPacketPadder.pad(packetId: "packet", payload: Data("payload".utf8), fixedPayloadSize: 3)
        ) { error in
            XCTAssertEqual(error as? MixnetPacketPaddingError, .payloadTooLarge)
        }

        let wrongSizePacket = MixnetFixedSizePacket(
            packetId: "packet",
            paddedPayload: Data(repeating: 1, count: 31),
            originalPayloadSize: 8,
            fixedPayloadSize: 32
        )
        XCTAssertThrowsError(try MixnetPacketPadder.open(wrongSizePacket)) { error in
            XCTAssertEqual(error as? MixnetPacketPaddingError, .malformedPacket)
        }

        let oversizedOriginalPacket = MixnetFixedSizePacket(
            packetId: "packet",
            paddedPayload: Data(repeating: 1, count: 32),
            originalPayloadSize: 33,
            fixedPayloadSize: 32
        )
        XCTAssertThrowsError(try MixnetPacketPadder.open(oversizedOriginalPacket)) { error in
            XCTAssertEqual(error as? MixnetPacketPaddingError, .malformedPacket)
        }
    }

    func testMixnetRouteSelectorBuildsDeterministicDiverseRoute() throws {
        let candidates = [
            mixnetRouteCandidate(id: "hop-a", operatorId: "operator-a", host: "relay-a.example"),
            mixnetRouteCandidate(id: "hop-b", operatorId: "operator-b", host: "relay-b.example"),
            mixnetRouteCandidate(id: "hop-c", operatorId: "operator-c", host: "relay-c.example"),
            mixnetRouteCandidate(id: "hop-d", operatorId: "operator-d", host: "relay-d.example")
        ]
        let secret = Data("route-secret".utf8)

        let first = try MixnetRouteSelector.makeRoutePlan(
            candidates: candidates,
            secret: secret,
            routeContext: "batch-1",
            hopCount: 3
        )
        let second = try MixnetRouteSelector.makeRoutePlan(
            candidates: candidates.reversed(),
            secret: secret,
            routeContext: "batch-1",
            hopCount: 3
        )

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.selectedCandidates.count, 3)
        XCTAssertEqual(Set(first.selectedCandidates.map(\.operatorId)).count, 3)
        XCTAssertEqual(Set(first.selectedCandidates.map { $0.endpoint.host }).count, 3)
        XCTAssertEqual(first.onionHops.map(\.hopId), first.selectedCandidates.map(\.hopId))
        XCTAssertFalse(first.routeId.isEmpty)
    }

    func testMixnetRouteSelectorRejectsWeakRoutes() {
        let diverse = [
            mixnetRouteCandidate(id: "hop-a", operatorId: "operator-a", host: "relay-a.example"),
            mixnetRouteCandidate(id: "hop-b", operatorId: "operator-b", host: "relay-b.example")
        ]

        XCTAssertThrowsError(
            try MixnetRouteSelector.makeRoutePlan(
                candidates: diverse,
                secret: Data(),
                routeContext: "batch-1",
                hopCount: 2
            )
        ) { error in
            XCTAssertEqual(error as? MixnetRouteSelectionError, .emptySecret)
        }
        XCTAssertThrowsError(
            try MixnetRouteSelector.makeRoutePlan(
                candidates: diverse,
                secret: Data("route-secret".utf8),
                routeContext: "batch-1",
                hopCount: 1
            )
        ) { error in
            XCTAssertEqual(error as? MixnetRouteSelectionError, .invalidRouteLength)
        }

        let sameOperator = [
            mixnetRouteCandidate(id: "hop-a", operatorId: "operator-a", host: "relay-a.example"),
            mixnetRouteCandidate(id: "hop-b", operatorId: "operator-a", host: "relay-b.example")
        ]
        XCTAssertThrowsError(
            try MixnetRouteSelector.makeRoutePlan(
                candidates: sameOperator,
                secret: Data("route-secret".utf8),
                routeContext: "batch-1",
                hopCount: 2
            )
        ) { error in
            XCTAssertEqual(error as? MixnetRouteSelectionError, .insufficientDiversity)
        }

        let sameHost = [
            mixnetRouteCandidate(id: "hop-a", operatorId: "operator-a", host: "relay-shared.example"),
            mixnetRouteCandidate(id: "hop-b", operatorId: "operator-b", host: "relay-shared.example")
        ]
        XCTAssertThrowsError(
            try MixnetRouteSelector.makeRoutePlan(
                candidates: sameHost,
                secret: Data("route-secret".utf8),
                routeContext: "batch-1",
                hopCount: 2
            )
        ) { error in
            XCTAssertEqual(error as? MixnetRouteSelectionError, .insufficientDiversity)
        }

        XCTAssertThrowsError(
            try MixnetRouteSelector.makeRoutePlan(
                candidates: [mixnetRouteCandidate(id: "hop-a", operatorId: "operator-a", host: "relay-a.example", useTLS: false)],
                secret: Data("route-secret".utf8),
                routeContext: "batch-1",
                hopCount: 2
            )
        ) { error in
            XCTAssertEqual(error as? MixnetRouteSelectionError, .invalidEndpoint)
        }
    }

    func testRelayInfoAdvertisesOptionalMixnetTransportSupport() throws {
        let support = MixnetTransportSupport(
            enabled: true,
            batchIntervalSeconds: 45,
            minBatchSize: 12,
            coverPacketsPerBatch: 4,
            maxDelaySeconds: 90
        )
        let onion = OnionTransportSupport(enabled: true, maxHops: 3, requiresFixedSizePackets: true)
        let info = RelayConfiguration(
            onionTransport: onion,
            mixnetTransport: support
        ).makeInfo(now: Date(timeIntervalSince1970: 1_000))

        XCTAssertEqual(info.onionTransport, onion)
        XCTAssertEqual(info.mixnetTransport, support)
        let decoded = try NoctweaveCoder.decode(RelayInfo.self, from: NoctweaveCoder.encode(info))
        XCTAssertEqual(decoded.mixnetTransport, support)
    }

    func testRelayInfoSuppressesMisleadingMixnetAdvertisement() {
        let mixnet = MixnetTransportSupport(
            enabled: true,
            batchIntervalSeconds: 45,
            minBatchSize: 12,
            coverPacketsPerBatch: 4,
            maxDelaySeconds: 90
        )
        let missingOnionInfo = RelayConfiguration(mixnetTransport: mixnet).makeInfo()
        XCTAssertNil(missingOnionInfo.mixnetTransport)

        let weakOnion = OnionTransportSupport(enabled: true, maxHops: 1, requiresFixedSizePackets: false)
        let weakOnionInfo = RelayConfiguration(
            onionTransport: weakOnion,
            mixnetTransport: mixnet
        ).makeInfo()
        XCTAssertNil(weakOnionInfo.onionTransport)
        XCTAssertNil(weakOnionInfo.mixnetTransport)
    }

    func testMixnetRoutePolicyValidatorAcceptsOnionBackedCoverBatches() {
        let mixnet = MixnetTransportSupport(
            enabled: true,
            batchIntervalSeconds: 45,
            minBatchSize: 12,
            coverPacketsPerBatch: 4,
            maxDelaySeconds: 90
        )
        let onion = OnionTransportSupport(enabled: true, maxHops: 3, requiresFixedSizePackets: true)

        XCTAssertTrue(MixnetRoutePolicyValidator.isUsable(mixnetSupport: mixnet, onionSupport: onion))
        XCTAssertEqual(
            MixnetRoutePolicyValidator.issues(for: mixnet, onionSupport: onion),
            []
        )
    }

    func testMixnetRoutePolicyValidatorRejectsMisleadingMixnetAdvertisements() {
        XCTAssertEqual(
            MixnetRoutePolicyValidator.issues(for: nil, onionSupport: nil),
            [.notAdvertised]
        )

        let weakMixnet = MixnetTransportSupport(
            enabled: false,
            batchIntervalSeconds: 5,
            minBatchSize: 1,
            coverPacketsPerBatch: 0,
            maxDelaySeconds: 0
        )
        let weakOnion = OnionTransportSupport(enabled: false, maxHops: 1, requiresFixedSizePackets: false)
        let issues = MixnetRoutePolicyValidator.issues(for: weakMixnet, onionSupport: weakOnion)

        XCTAssertTrue(issues.contains(.disabled))
        XCTAssertTrue(issues.contains(.insufficientBatchSize))
        XCTAssertTrue(issues.contains(.coverTrafficDisabled))
        XCTAssertTrue(issues.contains(.batchIntervalTooShort))
        XCTAssertTrue(issues.contains(.releaseDelayDisabled))
        XCTAssertTrue(issues.contains(.onionTransportDisabled))
        XCTAssertTrue(issues.contains(.insufficientOnionHops))
        XCTAssertTrue(issues.contains(.fixedSizePacketsNotRequired))

        let missingOnion = MixnetTransportSupport(
            enabled: true,
            batchIntervalSeconds: 30,
            minBatchSize: 8,
            coverPacketsPerBatch: 2,
            maxDelaySeconds: 120
        )
        XCTAssertTrue(
            MixnetRoutePolicyValidator.issues(for: missingOnion, onionSupport: nil).contains(.missingOnionTransport)
        )
    }

    func testMLSEpochAdvancementRejectsCounterExhaustion() {
        let groupId = UUID()
        let transcript = Data(repeating: 7, count: 32)
        let commit = MLSGroupCommitSummary(
            operation: .update,
            actorFingerprint: String(repeating: "a", count: 64),
            epoch: UInt64.max,
            committedAt: Date(),
            memberFingerprints: [String(repeating: "a", count: 64), String(repeating: "b", count: 64)],
            previousTranscriptHash: transcript,
            transcriptHash: transcript
        )
        let terminal = MLSGroupEpochState(
            groupId: groupId,
            epoch: UInt64.max,
            treeHash: transcript,
            confirmedTranscriptHash: transcript,
            lastCommit: commit
        )

        XCTAssertThrowsError(
            try terminal.advancing(
                title: "Terminal",
                inboxId: "nw1terminal",
                actorFingerprint: commit.actorFingerprint,
                members: [],
                operation: .update,
                committedAt: Date()
            )
        )
    }

    func testResendRequestRejectsUnboundedWireCounts() throws {
        XCTAssertEqual(ResendRequest(count: Int.max).count, ResendRequest.maximumCount)
        let oversized = Data("{\"count\":9223372036854775807}".utf8)
        XCTAssertThrowsError(try NoctweaveCoder.decode(ResendRequest.self, from: oversized))
        let valid = try NoctweaveCoder.decode(ResendRequest.self, from: Data("{\"count\":32}".utf8))
        XCTAssertEqual(valid.count, 32)
    }

    private func registerAndFetch(
        client: RelayClient,
        inboxId: String,
        accessKey: SigningKeyPair,
        maxCount: Int
    ) async throws -> RelayResponse {
        let registrationResponse = try await registerInbox(
            client: client,
            inboxId: inboxId,
            accessKey: accessKey
        )
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

    private func registerInbox(
        client: RelayClient,
        inboxId: String,
        accessKey: SigningKeyPair
    ) async throws -> RelayResponse {
        var registration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData
        )
        let registrationProof = try makeInboxProof(signingKey: accessKey) { proof in
            try registration.signableData(for: proof)
        }
        registration = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: inboxId,
            accessPublicKey: accessKey.publicKeyData,
            accessProof: registrationProof
        )
        return try await client.send(.registerInbox(registration))
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

    private func makeDHTRecord(
        host: String,
        federationName: String?,
        signingKey: SigningKeyPair = SigningKeyPair(),
        issuedAt: Date,
        lifetimeSeconds: TimeInterval = 300
    ) throws -> OpenFederationDHTRecord {
        try makeDHTRecord(
            endpoint: RelayEndpoint(host: host, port: 443, useTLS: true, transport: .websocket),
            federationName: federationName,
            signingKey: signingKey,
            issuedAt: issuedAt,
            lifetimeSeconds: lifetimeSeconds
        )
    }

    private func makeDHTRecord(
        endpoint: RelayEndpoint,
        federationName: String?,
        signingKey: SigningKeyPair = SigningKeyPair(),
        issuedAt: Date,
        lifetimeSeconds: TimeInterval = 300
    ) throws -> OpenFederationDHTRecord {
        try OpenFederationDHTRecord.signed(
            endpoint: endpoint,
            federationName: federationName,
            signingKey: signingKey,
            issuedAt: issuedAt,
            lifetimeSeconds: lifetimeSeconds
        )
    }
}

private func mixnetRouteCandidate(
    id: String,
    operatorId: String,
    host: String,
    useTLS: Bool = true
) -> MixnetRouteCandidate {
    MixnetRouteCandidate(
        hopId: id,
        operatorId: operatorId,
        endpoint: RelayEndpoint(host: host, port: 443, useTLS: useTLS, transport: .http),
        onionHop: OnionHopDescriptor(
            hopId: id,
            publicKeyData: Data("public-key-\(id)".utf8),
            routingInstruction: "route-to-\(host)",
            delayBucketSeconds: 30
        )
    )
}

private func mixnetRelayPeer(
    id: String,
    operatorId: String,
    host: String,
    useTLS: Bool = true
) -> MixnetRelayPeer {
    MixnetRelayPeer(
        relayId: id,
        operatorId: operatorId,
        endpoint: RelayEndpoint(host: host, port: 443, useTLS: useTLS, transport: .http)
    )
}

private func testBitset(recordCount: Int, enabledIndex: Int) -> Data {
    var bitset = Data(repeating: 0, count: (recordCount + 7) / 8)
    bitset[enabledIndex / 8] = UInt8(1) << UInt8(enabledIndex % 8)
    return bitset
}

private func xorTestData(_ lhs: Data, _ rhs: Data) -> Data {
    Data(zip(lhs, rhs).map { $0 ^ $1 })
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

private actor MockOpenFederationDHTTransport: OpenFederationDHTTransport {
    private var recordsByNamespace: [String: [OpenFederationDHTRecord]]
    private var published: [OpenFederationDHTRecord] = []
    private var queries = 0
    private var mostRecentLimit: Int?
    private var queryFailureEnabled = false

    init(recordsByNamespace: [String: [OpenFederationDHTRecord]] = [:]) {
        self.recordsByNamespace = recordsByNamespace
    }

    func publish(_ record: OpenFederationDHTRecord, namespace: String) async throws {
        published.append(record)
        recordsByNamespace[namespace, default: []].append(record)
    }

    func query(namespace: String, limit: Int) async throws -> [OpenFederationDHTRecord] {
        queries += 1
        mostRecentLimit = limit
        if queryFailureEnabled {
            throw MockOpenFederationDHTTransportError.queryFailed
        }
        return Array((recordsByNamespace[namespace] ?? []).prefix(limit))
    }

    func publishedRecords() -> [OpenFederationDHTRecord] {
        published
    }

    func queryCount() -> Int {
        queries
    }

    func lastQueryLimit() -> Int? {
        mostRecentLimit
    }

    func setQueryFailureEnabled(_ enabled: Bool) {
        queryFailureEnabled = enabled
    }
}

private enum MockOpenFederationDHTTransportError: Error {
    case queryFailed
}

private struct DHTGatewayPublishRequestProbe: Codable {
    let namespace: String
    let record: OpenFederationDHTRecord
}

private struct DHTGatewayQueryResponseProbe: Codable {
    let records: [OpenFederationDHTRecord]
}

private final class DHTGatewayURLProtocolHarness {
    typealias Handler = (URLRequest) throws -> (status: Int, body: Data)

    private let state = LockedState()

    var handler: Handler? {
        get { state.handler }
        set { state.handler = newValue }
    }

    var requestCount: Int {
        state.requests.count
    }

    func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [DHTGatewayURLProtocol.self]
        let token = UUID().uuidString
        configuration.httpAdditionalHeaders = ["X-Noctyra-Test-Token": token]
        DHTGatewayURLProtocol.register(harness: self, token: token)
        return URLSession(configuration: configuration)
    }

    fileprivate func handle(_ request: URLRequest) throws -> (status: Int, body: Data) {
        state.requests.append(request)
        guard let handler = state.handler else {
            return (500, Data())
        }
        return try handler(request)
    }

    static func bodyData(from request: URLRequest) -> Data? {
        if let body = request.httpBody {
            return body
        }
        guard let stream = request.httpBodyStream else {
            return nil
        }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count > 0 {
                data.append(buffer, count: count)
            } else {
                break
            }
        }
        return data
    }

    private final class LockedState {
        private let lock = NSLock()
        private var _handler: Handler?
        private var _requests: [URLRequest] = []

        var handler: Handler? {
            get {
                lock.lock()
                defer { lock.unlock() }
                return _handler
            }
            set {
                lock.lock()
                _handler = newValue
                lock.unlock()
            }
        }

        var requests: [URLRequest] {
            get {
                lock.lock()
                defer { lock.unlock() }
                return _requests
            }
            set {
                lock.lock()
                _requests = newValue
                lock.unlock()
            }
        }
    }
}

private final class TestAttachmentBlobStore: AttachmentBlobStore {
    let backendName = "test-blob"
    private(set) var records: [String: AttachmentExternalRecord] = [:]
    private var blobs: [String: Data] = [:]
    private(set) var putCount = 0

    func put(_ data: Data, attachmentId: UUID, chunkIndex: Int, expiresAt: Date) throws -> AttachmentExternalRecord {
        putCount += 1
        let locator = "\(attachmentId.uuidString)-\(chunkIndex)-\(putCount)"
        blobs[locator] = data
        let record = AttachmentExternalRecord(
            backend: backendName,
            locator: locator,
            byteCount: data.count,
            sha256Hex: AttachmentBlobDigest.sha256Hex(data),
            expiresAt: expiresAt
        )
        records[locator] = record
        return record
    }

    func get(_ record: AttachmentExternalRecord) throws -> Data {
        guard let data = blobs[record.locator] else {
            throw AttachmentBlobStoreError.fetchFailed("missing test blob")
        }
        guard data.count == record.byteCount,
              AttachmentBlobDigest.sha256Hex(data) == record.sha256Hex else {
            throw AttachmentBlobStoreError.digestMismatch
        }
        return data
    }

    func delete(_ record: AttachmentExternalRecord) {
        blobs.removeValue(forKey: record.locator)
        records.removeValue(forKey: record.locator)
    }

    func corruptAll() {
        blobs = blobs.mapValues { data in
            var corrupted = data
            corrupted.append(0x00)
            return corrupted
        }
    }
}

private final class DHTGatewayURLProtocol: URLProtocol {
    private static let lock = NSLock()
    private static var harnesses: [String: DHTGatewayURLProtocolHarness] = [:]

    static func register(harness: DHTGatewayURLProtocolHarness, token: String) {
        lock.lock()
        harnesses[token] = harness
        lock.unlock()
    }

    override class func canInit(with request: URLRequest) -> Bool {
        request.value(forHTTPHeaderField: "X-Noctyra-Test-Token") != nil
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let token = request.value(forHTTPHeaderField: "X-Noctyra-Test-Token"),
              let harness = Self.harness(for: token),
              let url = request.url else {
            client?.urlProtocol(self, didFailWithError: OpenFederationDHTGatewayTransportError.invalidURL)
            return
        }

        do {
            let result = try harness.handle(request)
            let response = HTTPURLResponse(
                url: url,
                statusCode: result.status,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if !result.body.isEmpty {
                client?.urlProtocol(self, didLoad: result.body)
            }
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}

    private static func harness(for token: String) -> DHTGatewayURLProtocolHarness? {
        lock.lock()
        defer { lock.unlock() }
        return harnesses[token]
    }
}

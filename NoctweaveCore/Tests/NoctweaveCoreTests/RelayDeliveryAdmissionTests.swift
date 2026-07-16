import XCTest
@testable import NoctweaveCore

final class RelayDeliveryAdmissionTests: XCTestCase {
    func testDirectDeliveryRequiresRegisteredDestinationBeforeAllocatingStorage() async throws {
        let store = RelayStore()
        let inboxId = InboxAddress.generate()
        let envelope = makeAdmissionEnvelope(counter: 1)

        await XCTAssertThrowsDeliveryAdmissionErrorAsync(
            try await store.deliver(envelope, to: inboxId)
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .destinationInboxNotRegistered)
        }
        let rejectedInbox = try await store.fetch(inboxId: inboxId)
        XCTAssertTrue(rejectedInbox.isEmpty)

        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA1]))
        let storedCount = try await store.deliver(envelope, to: inboxId)
        let acceptedInbox = try await store.fetch(inboxId: inboxId)
        XCTAssertEqual(storedCount, 1)
        XCTAssertEqual(acceptedInbox.map(\.id), [envelope.id])
    }

    func testGroupDeliveryRequiresRegisteredDestinationAndAcceptsGroupDescriptorInbox() async throws {
        let store = RelayStore()
        let syntheticInboxId = InboxAddress.generate()
        let envelope = makeAdmissionEnvelope(counter: 2)

        await XCTAssertThrowsDeliveryAdmissionErrorAsync(
            try await store.deliverGroupEnvelope(
                envelope,
                to: syntheticInboxId,
                recipientFingerprints: ["member-b"]
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .destinationInboxNotRegistered)
        }
        let rejectedInbox = try await store.fetch(inboxId: syntheticInboxId)
        XCTAssertTrue(rejectedInbox.isEmpty)

        let group = try await store.createGroup(
            title: "Registered group",
            creatorFingerprint: "member-a",
            memberFingerprints: ["member-a", "member-b"]
        )
        let storedCount = try await store.deliverGroupEnvelope(
            envelope,
            to: group.inboxId,
            recipientFingerprints: ["member-b"]
        )
        let acceptedInbox = try await store.fetch(inboxId: group.inboxId)
        XCTAssertEqual(storedCount, 1)
        XCTAssertEqual(acceptedInbox.map(\.id), [envelope.id])
    }

    func testCoreRelayHandlerReturnsExplicitAdmissionErrorAndAcceptsAfterRegistration() async throws {
        let store = RelayStore()
        let server = RelayServer(
            store: store,
            configuration: RelayConfiguration(
                compatibilityProfiles: [RelayCompatibilityProfile.legacyFingerprint]
            )
        )
        let endpoint = RelayEndpoint(
            host: "127.0.0.1",
            port: UInt16.random(in: 43_000...45_000)
        )
        let started = expectation(description: "delivery-admission relay started")
        server.onEvent = { event in
            if case .started = event {
                started.fulfill()
            }
        }
        try server.start(host: "0.0.0.0", port: endpoint.port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2)

        let inboxId = InboxAddress.generate()
        let envelope = makeAdmissionEnvelope(counter: 3)
        let request = RelayRequest.deliver(
            DeliverRequest(
                inboxId: inboxId,
                routingToken: inboxId,
                envelope: envelope
            )
        )
        let client = RelayClient(endpoint: endpoint)

        let rejected = try await client.send(request)
        XCTAssertEqual(rejected.type, .error)
        XCTAssertEqual(rejected.error, "Destination inbox is not registered")

        try await store.registerInbox(inboxId: inboxId, accessPublicKey: Data([0xA2]))
        let accepted = try await client.send(request)
        XCTAssertEqual(accepted.type, .delivered)
        XCTAssertEqual(accepted.delivered?.storedCount, 1)

        let groupId = UUID()
        let groupInboxId = InboxAddress.generate()
        let groupRejected = try await client.send(
            .deliverGroupMessage(
                DeliverGroupMessageRequest(
                    groupId: groupId,
                    groupInboxId: groupInboxId,
                    envelope: makeUnregisteredGroupEnvelope(groupId: groupId)
                )
            )
        )
        XCTAssertEqual(groupRejected.type, .error)
        XCTAssertEqual(groupRejected.error, "Destination group inbox is not registered")
    }

    private func makeAdmissionEnvelope(counter: UInt64) -> Envelope {
        Envelope(
            conversationId: "relay-delivery-admission",
            sessionId: "session-v2",
            senderFingerprint: Data(repeating: 0x44, count: 32).base64EncodedString(),
            sentAt: Date(timeIntervalSince1970: TimeInterval(9_000 + counter)),
            messageCounter: counter,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: 12),
                ciphertext: Data(repeating: UInt8(truncatingIfNeeded: counter), count: 512),
                tag: Data(repeating: 0x22, count: 16)
            ),
            signature: Data(repeating: 0x33, count: 3_309)
        )
    }

    private func makeUnregisteredGroupEnvelope(groupId: UUID) -> GroupRatchetEnvelope {
        GroupRatchetEnvelope(
            groupId: groupId,
            epoch: 0,
            transcriptHash: Data(repeating: 0x44, count: 32),
            senderFingerprint: Data(repeating: 0x55, count: 32).base64EncodedString(),
            sentAt: Date(timeIntervalSince1970: 9_100),
            messageCounter: 0,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: 12),
                ciphertext: Data(repeating: 0x22, count: 512),
                tag: Data(repeating: 0x33, count: 16)
            ),
            signature: Data(repeating: 0x66, count: 3_309)
        )
    }
}

private func XCTAssertThrowsDeliveryAdmissionErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ errorHandler: (Error) -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected expression to throw", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}

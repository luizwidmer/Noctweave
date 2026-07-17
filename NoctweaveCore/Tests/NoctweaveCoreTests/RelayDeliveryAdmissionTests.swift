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

    func testCoreRelayHandlerReturnsExplicitAdmissionErrorAndAcceptsAfterRegistration() async throws {
        let store = RelayStore()
        let server = RelayServer(store: store)
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

    }

    private func makeAdmissionEnvelope(counter: UInt64) -> ProtocolEnvelopeV1 {
        makeTestProtocolEnvelope(
            conversationId: "relay-delivery-admission",
            counter: counter,
            sentAt: Date(timeIntervalSince1970: TimeInterval(9_000 + counter)),
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: 12),
                ciphertext: Data(repeating: UInt8(truncatingIfNeeded: counter), count: 512),
                tag: Data(repeating: 0x22, count: 16)
            ),
            signature: Data(repeating: 0x33, count: 3_309)
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

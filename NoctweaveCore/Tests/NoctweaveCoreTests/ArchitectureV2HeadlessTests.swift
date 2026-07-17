import XCTest
@testable import NoctweaveCore

final class ArchitectureV2HeadlessTests: XCTestCase {
    func testPermanentIntentDoesNotBlockOtherCiphertextAndCanBeRearmed() async throws {
        let port = UInt16.random(in: 54_000...58_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let relayStore = RelayStore()
        var server: RelayServer? = RelayServer(store: relayStore)
        try server?.start(host: "127.0.0.1", port: port)
        try await Task.sleep(nanoseconds: 200_000_000)

        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer {
            server?.stop()
            try? FileManager.default.removeItem(at: directory)
        }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let alice = HeadlessMessagingClient(
            stateURL: directory.appendingPathComponent("alice.json"),
            useEncryptedStore: false,
            timeout: 0.5
        )
        let bob = HeadlessMessagingClient(
            stateURL: directory.appendingPathComponent("bob.json"),
            useEncryptedStore: false,
            timeout: 1
        )
        let carol = HeadlessMessagingClient(
            stateURL: directory.appendingPathComponent("carol.json"),
            useEncryptedStore: false,
            timeout: 1
        )
        _ = try await alice.createState(displayName: "Alice", relay: endpoint)
        _ = try await bob.createState(displayName: "Bob", relay: endpoint)
        _ = try await carol.createState(displayName: "Carol", relay: endpoint)
        try await alice.registerInbox()
        try await bob.registerInbox()
        try await carol.registerInbox()
        _ = try await alice.importContactCode(try await bob.exportContactCode())
        _ = try await bob.importContactCode(try await alice.exportContactCode())
        _ = try await alice.importContactCode(try await carol.exportContactCode())
        _ = try await carol.importContactCode(try await alice.exportContactCode())

        server?.stop()
        server = nil
        try await Task.sleep(nanoseconds: 200_000_000)
        await expectAsyncThrow { _ = try await alice.sendText(to: "Bob", text: "first") }
        await expectAsyncThrow { _ = try await alice.sendText(to: "Carol", text: "second") }

        let maybeFailed = try await alice.store.load()
        var failed = try XCTUnwrap(maybeFailed)
        XCTAssertEqual(failed.pendingDirectDeliveries.count, 2)
        let firstId = failed.pendingDirectDeliveries[0].id
        let firstIntentIndex = try XCTUnwrap(
            failed.protocolIntents.firstIndex(where: { $0.id == firstId })
        )
        let firstIntent = failed.protocolIntents[firstIntentIndex]
        failed.protocolIntents[firstIntentIndex] = ProtocolIntentV2(
            id: firstIntent.id,
            kind: firstIntent.kind,
            targetIdentifier: firstIntent.targetIdentifier,
            expectedEpoch: firstIntent.expectedEpoch,
            idempotencyKey: firstIntent.idempotencyKey,
            payloadDigest: firstIntent.payloadDigest,
            dependencies: firstIntent.dependencies,
            state: .permanentFailure,
            lastErrorClass: .relayRejected,
            createdAt: firstIntent.createdAt,
            updatedAt: Date()
        )
        try await alice.store.save(failed)

        server = RelayServer(store: relayStore)
        try server?.start(host: "127.0.0.1", port: port)
        try await Task.sleep(nanoseconds: 1_200_000_000)
        do {
            _ = try await alice.retryPendingDirectDeliveries()
            XCTFail("The preserved permanent failure must require an explicit action.")
        } catch let error as HeadlessMessagingClientError {
            XCTAssertEqual(error, .directDeliveryRequiresAction(firstId))
        }
        let secondOnly = try await carol.receive(maxCount: 10).map(\.body)
        XCTAssertEqual(secondOnly, [.text("second")])

        try await alice.rearmPendingDirectDelivery(envelopeId: firstId)
        let retried = try await alice.retryPendingDirectDeliveries()
        XCTAssertEqual(retried, 1)
        let firstAfterRearm = try await bob.receive(maxCount: 10).map(\.body)
        XCTAssertEqual(firstAfterRearm, [.text("first")])
    }

    func testFailedSendPersistsLocalEchoAndRetriesExactEnvelope() async throws {
        let port = UInt16.random(in: 54_000...58_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let relayStore = RelayStore()
        var server: RelayServer? = RelayServer(store: relayStore)
        try server?.start(host: "127.0.0.1", port: port)
        try await Task.sleep(nanoseconds: 200_000_000)

        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer {
            server?.stop()
            try? FileManager.default.removeItem(at: directory)
        }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let alice = HeadlessMessagingClient(
            stateURL: directory.appendingPathComponent("alice.json"),
            useEncryptedStore: false,
            timeout: 0.5
        )
        let bob = HeadlessMessagingClient(
            stateURL: directory.appendingPathComponent("bob.json"),
            useEncryptedStore: false,
            timeout: 1
        )
        _ = try await alice.createState(displayName: "Alice", relay: endpoint)
        _ = try await bob.createState(displayName: "Bob", relay: endpoint)
        try await alice.registerInbox()
        try await bob.registerInbox()
        _ = try await alice.importContactCode(try await bob.exportContactCode())
        _ = try await bob.importContactCode(try await alice.exportContactCode())

        server?.stop()
        server = nil
        try await Task.sleep(nanoseconds: 200_000_000)
        await expectAsyncThrow {
            _ = try await alice.sendText(to: "Bob", text: "durable retry")
        }

        let maybeFailedState = try await alice.store.load()
        var failedState = try XCTUnwrap(maybeFailedState)
        XCTAssertEqual(failedState.pendingDirectDeliveries.count, 1)
        let pendingId = try XCTUnwrap(failedState.pendingDirectDeliveries.first?.id)
        let pendingEnvelope = try XCTUnwrap(failedState.pendingDirectDeliveries.first?.envelope)
        let pendingEventId = pendingEnvelope.eventId
        XCTAssertEqual(pendingEnvelope.payloadFormat, NoctweaveWirePayloadV2.directV4Format)
        let persistedOutboundEvent = try XCTUnwrap(
            failedState.relationshipsV2.flatMap(\.events).first { $0.id == pendingEventId }
        )
        XCTAssertNotEqual(persistedOutboundEvent.id, persistedOutboundEvent.clientTransactionId)
        XCTAssertEqual(failedState.conversations.first?.messages.last?.body, "durable retry")
        XCTAssertEqual(failedState.protocolIntents.first { $0.id == pendingId }?.state, .prepared)

        // A registration attempt that cannot reach the relay must still durably
        // reserve its route-scoped credential so restart replays the same ID.
        await expectAsyncThrow {
            _ = try await bob.receive(maxCount: 10)
        }
        let maybePreparedBobState = try await bob.store.load()
        let preparedBobState = try XCTUnwrap(maybePreparedBobState)
        let preparedConsumerId = try XCTUnwrap(
            preparedBobState.localEndpoint?.mailboxCredentialsByRoute.values.first?.consumerId
        )

        // A saturated outbox attempt counter cannot overflow during retry; the
        // protocol intent remains the authoritative retry bound.
        failedState.pendingDirectDeliveries[0].attemptCount = Int.max
        try await alice.store.save(failedState)

        server = RelayServer(store: relayStore)
        try server?.start(host: "127.0.0.1", port: port)
        try await Task.sleep(nanoseconds: 1_200_000_000)
        let retried = try await alice.retryPendingDirectDeliveries()
        XCTAssertEqual(retried, 1)

        let maybeRecoveredState = try await alice.store.load()
        let recoveredState = try XCTUnwrap(maybeRecoveredState)
        XCTAssertTrue(recoveredState.pendingDirectDeliveries.isEmpty)
        XCTAssertEqual(recoveredState.protocolIntents.first { $0.id == pendingId }?.state, .finalized)
        let received = try await bob.receive(maxCount: 10)
        XCTAssertEqual(received.map(\.body), [.text("durable retry")])
        XCTAssertEqual(received.first?.envelopeId, pendingId)
        let maybeRecoveredBobState = try await bob.store.load()
        let recoveredBobState = try XCTUnwrap(maybeRecoveredBobState)
        let persistedInboundEvent = try XCTUnwrap(
            recoveredBobState.relationshipsV2.flatMap(\.events).first { $0.id == pendingEventId }
        )
        XCTAssertEqual(persistedInboundEvent, persistedOutboundEvent)
        XCTAssertEqual(
            recoveredBobState.localEndpoint?.mailboxCredentialsByRoute.values.first?.consumerId,
            preparedConsumerId
        )
        let emptyReplay = try await bob.receive(maxCount: 10)
        XCTAssertTrue(emptyReplay.isEmpty)
        let consumerRegistrations = await relayStore.mailboxConsumers(inboxId: preparedBobState.inboxId)
        XCTAssertEqual(consumerRegistrations.map(\.consumerId), [preparedConsumerId])
    }
}

private func expectAsyncThrow(
    _ operation: () async throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        try await operation()
        XCTFail("Expected operation to throw", file: file, line: line)
    } catch {
        // Expected.
    }
}

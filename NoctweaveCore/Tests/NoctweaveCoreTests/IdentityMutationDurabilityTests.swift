import XCTest
@testable import NoctweaveCore

final class IdentityMutationDurabilityTests: XCTestCase {
    func testRotationPersistsNewIdentityAndExactOldKeyNotificationBeforeDelivery() async throws {
        let port = UInt16.random(in: 38_000...41_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let relayStore = RelayStore()
        var server: RelayServer? = RelayServer(store: relayStore)
        try server?.start(host: "127.0.0.1", port: port)
        try await Task.sleep(nanoseconds: 200_000_000)

        let root = try makeTemporaryDirectory()
        defer {
            server?.stop()
            try? FileManager.default.removeItem(at: root)
        }
        let aliceURL = root.appendingPathComponent("alice.json")
        let alice = HeadlessMessagingClient(stateURL: aliceURL, useEncryptedStore: false, timeout: 0.5)
        let bob = HeadlessMessagingClient(
            stateURL: root.appendingPathComponent("bob.json"),
            useEncryptedStore: false,
            timeout: 1
        )
        let charlie = HeadlessMessagingClient(
            stateURL: root.appendingPathComponent("charlie.json"),
            useEncryptedStore: false,
            timeout: 1
        )
        _ = try await alice.createState(displayName: "Alice", relay: endpoint)
        _ = try await bob.createState(displayName: "Bob", relay: endpoint)
        _ = try await charlie.createState(displayName: "Charlie", relay: endpoint)
        try await alice.registerInbox()
        try await bob.registerInbox()
        try await charlie.registerInbox()
        let bobContact = try await alice.importContactCode(try await bob.exportContactCode())
        let charlieContact = try await alice.importContactCode(try await charlie.exportContactCode())
        _ = try await bob.importContactCode(try await alice.exportContactCode())
        _ = try await charlie.importContactCode(try await alice.exportContactCode())

        let beforeState = try await awaitState(alice)
        let before = try XCTUnwrap(beforeState.identityProfiles.first)
        let oldPrivateKey = before.identity.signingKey.privateKeyData
        let oldPublicKey = before.identity.signingKey.publicKeyData
        let oldFingerprint = before.identity.fingerprint

        server?.stop()
        server = nil
        try await Task.sleep(nanoseconds: 150_000_000)
        let offlineResult = try await alice.rotateIdentity(
            preservingContinuityWith: [bobContact.id]
        )
        XCTAssertEqual(offlineResult.oldFingerprint, oldFingerprint)
        XCTAssertEqual(offlineResult.failedContacts, ["Bob"])

        let durable = try await awaitState(alice)
        XCTAssertNotEqual(durable.identity.fingerprint, oldFingerprint)
        XCTAssertNotEqual(durable.identity.signingKey.privateKeyData, oldPrivateKey)
        let journal = try XCTUnwrap(durable.identityMutationV2)
        XCTAssertEqual(journal.kind, .rotation)
        XCTAssertEqual(journal.phase, .cleanupComplete)
        XCTAssertEqual(journal.oldSigningPublicKey, oldPublicKey)
        XCTAssertEqual(journal.notifications.map(\.contactId), [bobContact.id])
        XCTAssertFalse(journal.notifications.contains { $0.contactId == charlieContact.id })
        XCTAssertNil(journal.stagedBurn)
        XCTAssertTrue(journal.pendingInboxRetirements.isEmpty)
        let encodedJournal = try NoctweaveCoder.encode(journal, sortedKeys: true)
        XCTAssertNil(encodedJournal.range(of: Data(oldPrivateKey.base64EncodedString().utf8)))
        let pending = try XCTUnwrap(durable.pendingDirectDeliveries.first)
        let notificationSigner = try XCTUnwrap(journal.notifications.first?.signerPublicKey)
        XCTAssertNotEqual(notificationSigner, oldPublicKey)
        XCTAssertTrue(pending.envelope.verifySignature(publicSigningKey: notificationSigner))
        XCTAssertEqual(journal.notificationIds, Set([pending.id]))
        await expectIdentityMutationInProgress {
            _ = try await alice.sendText(to: "Bob", text: "must wait for rotation notice")
        }
        var missingExactOutbox = durable
        missingExactOutbox.pendingDirectDeliveries.removeAll()
        XCTAssertFalse(missingExactOutbox.identityProfiles.first?.isArchitectureV2Ready == true)
        do {
            _ = try await alice.rotateIdentity(preservingContinuityWith: [])
            XCTFail("A durable rotation must not resume with a wider or narrower recipient set.")
        } catch let error as HeadlessMessagingClientError {
            XCTAssertEqual(error, .identityRotationSelectionMismatch)
        }

        server = RelayServer(store: relayStore)
        try server?.start(host: "127.0.0.1", port: port)
        try await Task.sleep(nanoseconds: 1_200_000_000)
        let restartedAlice = HeadlessMessagingClient(
            stateURL: aliceURL,
            useEncryptedStore: false,
            timeout: 1
        )
        let retriedRotation = try await restartedAlice.retryPendingDirectDeliveries()
        XCTAssertEqual(retriedRotation, 1)
        let received = try await bob.receive(maxCount: 10)
        XCTAssertEqual(received.map(\.envelopeId), [pending.id])
        guard case .identityRotation = try XCTUnwrap(received.first).body else {
            return XCTFail("Expected the durable rotation notification")
        }
        let unselectedMessages = try await charlie.receive(maxCount: 10)
        XCTAssertTrue(unselectedMessages.isEmpty)
        let after = try await awaitState(restartedAlice)
        XCTAssertEqual(after.identity.fingerprint, offlineResult.newFingerprint)
        XCTAssertNil(after.identityMutationV2)
    }

    func testRotationRequiresKnownExplicitSelectionAndEmptySetNotifiesNobody() async throws {
        let root = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let client = HeadlessMessagingClient(
            stateURL: root.appendingPathComponent("client.json"),
            useEncryptedStore: false,
            timeout: 0.1
        )
        let initial = try await client.createState(
            displayName: "Unlinked",
            relay: RelayEndpoint(host: "127.0.0.1", port: 49_997)
        )

        let unknownId = UUID()
        do {
            _ = try await client.rotateIdentity(preservingContinuityWith: [unknownId])
            XCTFail("Unknown continuity recipients must fail closed.")
        } catch let error as HeadlessMessagingClientError {
            XCTAssertEqual(error, .contactNotFound(unknownId.uuidString))
        }
        let unchangedStatus = try await client.status()
        XCTAssertEqual(unchangedStatus.fingerprint, initial.fingerprint)

        let result = try await client.rotateIdentity(preservingContinuityWith: [])
        XCTAssertEqual(result.oldFingerprint, initial.fingerprint)
        XCTAssertNotEqual(result.newFingerprint, initial.fingerprint)
        XCTAssertTrue(result.notifiedContacts.isEmpty)
        XCTAssertTrue(result.failedContacts.isEmpty)
        let state = try await awaitState(client)
        XCTAssertTrue(state.pendingDirectDeliveries.isEmpty)
        XCTAssertNil(state.identityMutationV2)
    }

    func testBurnRegistrationFailureLeavesOldIdentityAndConsumerUsableThenResumesSameStage() async throws {
        let port = UInt16.random(in: 41_001...44_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let relayStore = RelayStore()
        var server: RelayServer? = RelayServer(store: relayStore)
        try server?.start(host: "127.0.0.1", port: port)
        try await Task.sleep(nanoseconds: 200_000_000)

        let root = try makeTemporaryDirectory()
        defer {
            server?.stop()
            try? FileManager.default.removeItem(at: root)
        }
        let aliceURL = root.appendingPathComponent("alice.json")
        let alice = HeadlessMessagingClient(stateURL: aliceURL, useEncryptedStore: false, timeout: 0.5)
        let bob = HeadlessMessagingClient(
            stateURL: root.appendingPathComponent("bob.json"),
            useEncryptedStore: false,
            timeout: 1
        )
        _ = try await alice.createState(displayName: "Alice", relay: endpoint)
        _ = try await bob.createState(displayName: "Bob", relay: endpoint)
        try await alice.registerInbox()
        try await bob.registerInbox()
        _ = try await alice.importContactCode(try await bob.exportContactCode())
        _ = try await bob.importContactCode(try await alice.exportContactCode())
        _ = try await alice.setContactIdentityReset(selector: "Bob", allow: true)

        let oldState = try await awaitState(alice)
        let oldFingerprint = oldState.identity.fingerprint
        let oldInboxId = oldState.inboxId
        let oldConsumerId = try XCTUnwrap(oldState.localInstallation?.mailboxConsumerIdsByRoute.values.first)

        server?.stop()
        server = nil
        try await Task.sleep(nanoseconds: 150_000_000)
        await expectIdentityMutationThrow {
            _ = try await alice.burnIdentity()
        }

        let prepared = try await awaitState(alice)
        XCTAssertEqual(prepared.identity.fingerprint, oldFingerprint)
        XCTAssertEqual(prepared.inboxId, oldInboxId)
        let preparedJournal = try XCTUnwrap(prepared.identityMutationV2)
        XCTAssertEqual(preparedJournal.phase, .prepared)
        await expectIdentityMutationInProgress {
            _ = try await alice.sendText(to: "Bob", text: "must not race staged burn")
        }
        let stagedFingerprint = try XCTUnwrap(preparedJournal.stagedBurn).identity.fingerprint
        let stagedInboxId = try XCTUnwrap(preparedJournal.stagedBurn).inboxId

        server = RelayServer(store: relayStore)
        try server?.start(host: "127.0.0.1", port: port)
        try await Task.sleep(nanoseconds: 250_000_000)
        let beforeResumeConsumers = await relayStore.mailboxConsumers(inboxId: oldInboxId)
        XCTAssertEqual(beforeResumeConsumers.first { $0.consumerId == oldConsumerId }?.state, .active)

        _ = try await bob.sendText(to: "Alice", text: "old route still works")
        let oldRouteMessage = try await alice.receive(maxCount: 10)
        XCTAssertEqual(oldRouteMessage.map(\.body), [.text("old route still works")])

        let restartedAlice = HeadlessMessagingClient(
            stateURL: aliceURL,
            useEncryptedStore: false,
            timeout: 1
        )
        let burn = try await restartedAlice.burnIdentity()
        XCTAssertEqual(burn.newFingerprint, stagedFingerprint)
        XCTAssertEqual(burn.notifiedContacts, ["Bob"])
        let final = try await awaitState(restartedAlice)
        XCTAssertEqual(final.identity.fingerprint, stagedFingerprint)
        XCTAssertEqual(final.inboxId, stagedInboxId)
        XCTAssertTrue(
            final.identityProfile(id: final.activeIdentityId)?.continuityEvents.isEmpty == true
        )
        XCTAssertNil(final.identityMutationV2)
        let oldConsumers = await relayStore.mailboxConsumers(inboxId: oldInboxId)
        XCTAssertTrue(oldConsumers.isEmpty)
        let oldInboxRetired = await relayStore.isInboxRetired(inboxId: oldInboxId)
        XCTAssertTrue(oldInboxRetired)
    }

    func testBurnCutoverRetriesExactResetWithoutRetainingOldIdentityPrivateKey() async throws {
        let alicePort = UInt16.random(in: 44_001...47_000)
        let bobPort = UInt16.random(in: 47_001...50_000)
        let aliceEndpoint = RelayEndpoint(host: "127.0.0.1", port: alicePort)
        let bobEndpoint = RelayEndpoint(host: "127.0.0.1", port: bobPort)
        let aliceRelayStore = RelayStore()
        let bobRelayStore = RelayStore()
        let aliceServer = RelayServer(store: aliceRelayStore)
        var bobServer: RelayServer? = RelayServer(store: bobRelayStore)
        try aliceServer.start(host: "127.0.0.1", port: alicePort)
        try bobServer?.start(host: "127.0.0.1", port: bobPort)
        try await Task.sleep(nanoseconds: 200_000_000)

        let root = try makeTemporaryDirectory()
        defer {
            aliceServer.stop()
            bobServer?.stop()
            try? FileManager.default.removeItem(at: root)
        }
        let aliceURL = root.appendingPathComponent("alice.json")
        let alice = HeadlessMessagingClient(stateURL: aliceURL, useEncryptedStore: false, timeout: 0.5)
        let bob = HeadlessMessagingClient(
            stateURL: root.appendingPathComponent("bob.json"),
            useEncryptedStore: false,
            timeout: 1
        )
        _ = try await alice.createState(displayName: "Alice", relay: aliceEndpoint)
        _ = try await bob.createState(displayName: "Bob", relay: bobEndpoint)
        try await alice.registerInbox()
        try await bob.registerInbox()
        _ = try await alice.importContactCode(try await bob.exportContactCode())
        _ = try await bob.importContactCode(try await alice.exportContactCode())
        _ = try await alice.setContactIdentityReset(selector: "Bob", allow: true)

        let before = try await awaitState(alice)
        let oldPrivateKey = before.identity.signingKey.privateKeyData
        let oldInboxPrivateKey = try XCTUnwrap(before.inboxAccessKey?.privateKeyData)
        let oldPublicKey = before.identity.signingKey.publicKeyData
        let oldInboxId = before.inboxId

        bobServer?.stop()
        bobServer = nil
        try await Task.sleep(nanoseconds: 150_000_000)
        let offlineReset = try await alice.burnIdentity()
        XCTAssertEqual(offlineReset.failedContacts, ["Bob"])

        let cutover = try await awaitState(alice)
        XCTAssertEqual(cutover.identity.fingerprint, offlineReset.newFingerprint)
        XCTAssertNotEqual(cutover.identity.signingKey.privateKeyData, oldPrivateKey)
        let journal = try XCTUnwrap(cutover.identityMutationV2)
        XCTAssertEqual(journal.phase, .cleanupComplete)
        XCTAssertNil(journal.stagedBurn)
        XCTAssertTrue(journal.pendingInboxRetirements.isEmpty)
        let encodedJournal = try NoctweaveCoder.encode(journal, sortedKeys: true)
        XCTAssertNil(encodedJournal.range(of: Data(oldInboxPrivateKey.base64EncodedString().utf8)))
        let pendingReset = try XCTUnwrap(cutover.pendingDirectDeliveries.first)
        let notificationSigner = try XCTUnwrap(journal.notifications.first?.signerPublicKey)
        XCTAssertNotEqual(notificationSigner, oldPublicKey)
        XCTAssertTrue(pendingReset.envelope.verifySignature(publicSigningKey: notificationSigner))
        await expectIdentityMutationInProgress {
            _ = try await alice.sendText(to: "Bob", text: "must wait for reset")
        }
        await expectIdentityMutationInProgress {
            _ = try await alice.sendAttachment(
                to: "Bob",
                data: Data("blocked attachment".utf8),
                fileName: "blocked.txt",
                mimeType: "text/plain"
            )
        }
        let oldConsumers = await aliceRelayStore.mailboxConsumers(inboxId: oldInboxId)
        XCTAssertTrue(oldConsumers.isEmpty)
        let oldInboxRetired = await aliceRelayStore.isInboxRetired(inboxId: oldInboxId)
        XCTAssertTrue(oldInboxRetired)

        bobServer = RelayServer(store: bobRelayStore)
        try bobServer?.start(host: "127.0.0.1", port: bobPort)
        try await Task.sleep(nanoseconds: 1_200_000_000)
        let restartedAlice = HeadlessMessagingClient(
            stateURL: aliceURL,
            useEncryptedStore: false,
            timeout: 1
        )
        let retriedReset = try await restartedAlice.retryPendingDirectDeliveries()
        XCTAssertEqual(retriedReset, 1)
        let received = try await bob.receive(maxCount: 10)
        XCTAssertEqual(received.map(\.envelopeId), [pendingReset.id])
        guard case .identityReset = try XCTUnwrap(received.first).body else {
            return XCTFail("Expected the durable reset notification")
        }
        let final = try await awaitState(restartedAlice)
        XCTAssertEqual(final.identity.fingerprint, offlineReset.newFingerprint)
        XCTAssertTrue(
            final.identityProfile(id: final.activeIdentityId)?.continuityEvents.isEmpty == true
        )
        XCTAssertNil(final.identityMutationV2)
        let retainedContactId = try XCTUnwrap(final.contacts.first?.id)
        let backfilledShell = try XCTUnwrap(final.relationshipsV2.first(where: {
            $0.contactId == retainedContactId
        }))
        XCTAssertTrue(backfilledShell.events.isEmpty)
        XCTAssertTrue(backfilledShell.routeSets.isEmpty)

        let postBurn = try await restartedAlice.sendText(
            to: "Bob",
            text: "fresh generation send"
        )
        let storedAfterBurn = try await bobRelayStore.fetch(inboxId: (try await awaitState(bob)).inboxId)
        let storedPostBurn = try XCTUnwrap(storedAfterBurn.first { $0.id == postBurn.envelopeId })
        let postBurnEventId = try XCTUnwrap(storedPostBurn.authenticatedContext?.directV4?.eventId)
        let reboundState = try await awaitState(restartedAlice)
        let rebound = try XCTUnwrap(reboundState.relationshipsV2.first(where: {
            $0.contactId == backfilledShell.contactId
        }))
        XCTAssertNotEqual(rebound.id, backfilledShell.id)
        XCTAssertEqual(rebound.events.last?.id, postBurnEventId)
        XCTAssertEqual(
            reboundState.localInstallation?.relationshipHandles[rebound.id],
            rebound.localInstallationHandle
        )
        XCTAssertNil(reboundState.localInstallation?.relationshipHandles[backfilledShell.id])
        XCTAssertTrue(reboundState.identityProfiles.first?.isArchitectureV2Ready == true)
    }

    func testBurnRetiresEveryScopedOldInboxRouteWithoutRetainingAuthority() async throws {
        let primaryPort = UInt16.random(in: 50_001...53_000)
        let secondaryPort = UInt16.random(in: 53_001...56_000)
        let primaryEndpoint = RelayEndpoint(host: "127.0.0.1", port: primaryPort)
        let secondaryEndpoint = RelayEndpoint(host: "127.0.0.1", port: secondaryPort)
        let primaryStore = RelayStore()
        let secondaryStore = RelayStore()
        let primaryServer = RelayServer(store: primaryStore)
        let secondaryServer = RelayServer(store: secondaryStore)
        try primaryServer.start(host: "127.0.0.1", port: primaryPort)
        try secondaryServer.start(host: "127.0.0.1", port: secondaryPort)
        try await Task.sleep(nanoseconds: 200_000_000)

        let root = try makeTemporaryDirectory()
        defer {
            primaryServer.stop()
            secondaryServer.stop()
            try? FileManager.default.removeItem(at: root)
        }
        let client = HeadlessMessagingClient(
            stateURL: root.appendingPathComponent("multi-route.json"),
            useEncryptedStore: false,
            timeout: 1
        )
        _ = try await client.createState(displayName: "Route Burn", relay: primaryEndpoint)
        try await client.registerInbox()

        var oldState = try await awaitState(client)
        let oldInboxId = oldState.inboxId
        let oldInboxPrivateKey = try XCTUnwrap(oldState.inboxAccessKey?.privateKeyData)
        var endpointState = try XCTUnwrap(oldState.localInstallation)
        let secondaryRouteKey = "\(secondaryEndpoint.transport.rawValue):0:\(secondaryEndpoint.host):\(secondaryEndpoint.port):\(oldInboxId.lowercased())"
        let secondaryCredential = try endpointState.ensureMailboxCredential(
            for: secondaryRouteKey,
            relay: secondaryEndpoint,
            inboxId: oldInboxId
        )
        oldState.localInstallation = endpointState
        try await client.store.save(oldState)
        let accessKey = try XCTUnwrap(oldState.inboxAccessKey)
        try await secondaryStore.registerInbox(
            inboxId: oldInboxId,
            accessPublicKey: accessKey.publicKeyData
        )
        _ = try await secondaryStore.registerMailboxConsumer(
            inboxId: oldInboxId,
            consumerId: secondaryCredential.consumerId,
            consumerSigningPublicKey: secondaryCredential.signingKey.publicKeyData,
            startingSequence: 0
        )

        _ = try await client.burnIdentity()
        let final = try await awaitState(client)
        XCTAssertNotEqual(final.inboxId, oldInboxId)
        let encoded = try NoctweaveCoder.encode(final, sortedKeys: true)
        XCTAssertNil(encoded.range(of: Data(oldInboxPrivateKey.base64EncodedString().utf8)))
        let primaryRetired = await primaryStore.isInboxRetired(inboxId: oldInboxId)
        let secondaryRetired = await secondaryStore.isInboxRetired(inboxId: oldInboxId)
        XCTAssertTrue(primaryRetired)
        XCTAssertTrue(secondaryRetired)
        let primaryConsumers = await primaryStore.mailboxConsumers(inboxId: oldInboxId)
        let secondaryConsumers = await secondaryStore.mailboxConsumers(inboxId: oldInboxId)
        XCTAssertTrue(primaryConsumers.isEmpty)
        XCTAssertTrue(secondaryConsumers.isEmpty)
    }

    private func makeTemporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private func awaitState(_ client: HeadlessMessagingClient) async throws -> ClientState {
        let maybeState = try await client.store.load()
        return try XCTUnwrap(maybeState)
    }
}

private func expectIdentityMutationThrow(
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

private func expectIdentityMutationInProgress<T>(
    _ operation: () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await operation()
        XCTFail("Expected identity mutation send gate", file: file, line: line)
    } catch {
        guard case .identityMutationInProgress = error as? HeadlessMessagingClientError else {
            return XCTFail("Expected identityMutationInProgress, got \(error)", file: file, line: line)
        }
    }
}

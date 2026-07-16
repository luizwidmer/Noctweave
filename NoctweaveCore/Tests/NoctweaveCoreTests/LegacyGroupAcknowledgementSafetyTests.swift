import CryptoKit
import Foundation
import XCTest
@testable import NoctweaveCore

final class LegacyGroupAcknowledgementSafetyTests: XCTestCase {
    func testLegacyGroupDecodeMigratesMissingPendingAcknowledgements() throws {
        let group = GroupConversation(
            title: "Migrated group",
            memberContactIds: [],
            relayInboxId: "legacy-group-inbox"
        )
        let encoded = try NoctweaveCoder.encode(group)
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertNotNil(object.removeValue(forKey: "pendingAcknowledgements"))

        let legacyData = try JSONSerialization.data(withJSONObject: object)
        let decoded = try NoctweaveCoder.decode(GroupConversation.self, from: legacyData)

        XCTAssertTrue(decoded.pendingAcknowledgements.isEmpty)
    }

    func testPendingLegacyGroupAcknowledgementsAreBoundedWithoutEviction() throws {
        var group = GroupConversation(title: "Bounded group", memberContactIds: [])
        var firstEnvelopeId: UUID?

        for index in 0..<GroupConversation.maximumPendingAcknowledgements {
            let envelopeId = UUID()
            firstEnvelopeId = firstEnvelopeId ?? envelopeId
            let digest = Data(SHA256.hash(data: Data("pending-\(index)".utf8)))
            XCTAssertEqual(
                group.recordPendingAcknowledgement(
                    envelopeId: envelopeId,
                    envelopeDigest: digest,
                    storedAt: Date(timeIntervalSince1970: TimeInterval(index + 1))
                ),
                .inserted
            )
        }

        let overflowId = UUID()
        XCTAssertEqual(
            group.recordPendingAcknowledgement(
                envelopeId: overflowId,
                envelopeDigest: Data(SHA256.hash(data: Data("overflow".utf8)))
            ),
            .capacityExceeded
        )
        XCTAssertEqual(
            group.pendingAcknowledgements.count,
            GroupConversation.maximumPendingAcknowledgements
        )
        XCTAssertNotNil(group.pendingAcknowledgement(for: try XCTUnwrap(firstEnvelopeId)))
        XCTAssertNil(group.pendingAcknowledgement(for: overflowId))

        var corrupt = group
        corrupt.pendingAcknowledgements.append(
            PendingGroupAcknowledgement(
                envelopeId: overflowId,
                envelopeDigest: Data(SHA256.hash(data: Data("corrupt".utf8))),
                storedAt: Date()
            )
        )
        let corruptData = try NoctweaveCoder.encode(corrupt)
        XCTAssertThrowsError(try NoctweaveCoder.decode(GroupConversation.self, from: corruptData))
    }

    func testPendingLegacyGroupAcknowledgementRejectsEnvelopeIdConflict() {
        var group = GroupConversation(title: "Conflict group", memberContactIds: [])
        let envelopeId = UUID()
        let original = Data(SHA256.hash(data: Data("original".utf8)))
        let conflicting = Data(SHA256.hash(data: Data("conflicting".utf8)))

        XCTAssertEqual(
            group.recordPendingAcknowledgement(envelopeId: envelopeId, envelopeDigest: original),
            .inserted
        )
        XCTAssertEqual(
            group.recordPendingAcknowledgement(envelopeId: envelopeId, envelopeDigest: original),
            .alreadyPending
        )
        XCTAssertEqual(
            group.recordPendingAcknowledgement(envelopeId: envelopeId, envelopeDigest: conflicting),
            .conflictingEnvelope
        )
        XCTAssertEqual(group.pendingAcknowledgements.map(\.envelopeDigest), [original])
    }

    func testGroupAckLossAndRestartDoNotReplayRatchetOrDuplicateMessage() async throws {
        let port = UInt16.random(in: 46_000...49_999)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let relayStore = RelayStore()
        let server = RelayServer(
            store: relayStore,
            configuration: RelayConfiguration(
                compatibilityProfiles: [RelayCompatibilityProfile.legacyFingerprint]
            )
        )
        let started = expectation(description: "legacy group safety relay started")
        server.onEvent = { event in
            if case .started = event { started.fulfill() }
        }
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2.0)

        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-legacy-group-ack-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let aliceURL = root.appendingPathComponent("alice.json")
        let bobURL = root.appendingPathComponent("bob.json")
        let alice = HeadlessMessagingClient(stateURL: aliceURL, useEncryptedStore: false, timeout: 1)
        let bob = HeadlessMessagingClient(stateURL: bobURL, useEncryptedStore: false, timeout: 1)
        _ = try await alice.createState(displayName: "Alice", relay: endpoint)
        _ = try await bob.createState(displayName: "Bob", relay: endpoint)
        try await alice.registerInbox()
        try await bob.registerInbox()
        _ = try await alice.importContactCode(try await bob.exportContactCode())
        _ = try await bob.importContactCode(try await alice.exportContactCode())

        let created = try await alice.createGroup(title: "Ack safety", memberSelectors: ["Bob"])
        _ = try await bob.groups()
        _ = try await alice.sendGroupText(to: created.id.uuidString, text: "persist exactly once")

        let fetchStoppedServer = expectation(description: "relay stopped after group fetch")
        var stoppedForFetch = false
        server.onEvent = { event in
            guard !stoppedForFetch,
                  case .fetched(let inboxId, let count) = event,
                  inboxId == created.inboxId,
                  count == 1 else { return }
            stoppedForFetch = true
            server.stop()
            fetchStoppedServer.fulfill()
        }

        do {
            _ = try await bob.receiveGroupMessages(
                group: created.id.uuidString,
                maxCount: 10,
                acknowledge: true
            )
            XCTFail("The destructive acknowledgement should fail after the relay stops.")
        } catch {
            // Expected: decryption and durable receipt completed before the lost acknowledgement.
        }
        await fulfillment(of: [fetchStoppedServer], timeout: 2.0)

        let afterAckLossValue = try await bob.store.load()
        let afterAckLoss = try XCTUnwrap(afterAckLossValue)
        let afterAckLossGroup = try XCTUnwrap(afterAckLoss.group(for: created.id))
        XCTAssertEqual(afterAckLossGroup.messages.filter { $0.body == "persist exactly once" }.count, 1)
        XCTAssertEqual(afterAckLossGroup.pendingAcknowledgements.count, 1)

        let restarted = expectation(description: "legacy group safety relay restarted")
        server.onEvent = { event in
            if case .started = event { restarted.fulfill() }
        }
        try server.start(host: "127.0.0.1", port: port)
        await fulfillment(of: [restarted], timeout: 2.0)

        let restartedBob = HeadlessMessagingClient(stateURL: bobURL, useEncryptedStore: false, timeout: 2)
        let duplicateFetch = try await restartedBob.receiveGroupMessages(
            group: created.id.uuidString,
            maxCount: 10,
            acknowledge: false
        )
        XCTAssertTrue(duplicateFetch.isEmpty)

        let stillPendingValue = try await restartedBob.store.load()
        let stillPending = try XCTUnwrap(stillPendingValue)
        let stillPendingGroup = try XCTUnwrap(stillPending.group(for: created.id))
        XCTAssertEqual(stillPendingGroup.messages.filter { $0.body == "persist exactly once" }.count, 1)
        XCTAssertEqual(stillPendingGroup.pendingAcknowledgements.count, 1)

        let afterRetry = try await restartedBob.receiveGroupMessages(
            group: created.id.uuidString,
            maxCount: 10,
            acknowledge: true
        )
        XCTAssertTrue(afterRetry.isEmpty)

        let finalizedValue = try await restartedBob.store.load()
        let finalized = try XCTUnwrap(finalizedValue)
        let finalizedGroup = try XCTUnwrap(finalized.group(for: created.id))
        XCTAssertEqual(finalizedGroup.messages.filter { $0.body == "persist exactly once" }.count, 1)
        XCTAssertTrue(finalizedGroup.pendingAcknowledgements.isEmpty)

        _ = try await alice.sendGroupText(to: created.id.uuidString, text: "blocked by backpressure")
        var saturated = finalized
        var saturatedGroup = finalizedGroup
        for index in 0..<GroupConversation.maximumPendingAcknowledgements {
            XCTAssertEqual(
                saturatedGroup.recordPendingAcknowledgement(
                    envelopeId: UUID(),
                    envelopeDigest: Data(SHA256.hash(data: Data("saturated-\(index)".utf8)))
                ),
                .inserted
            )
        }
        saturated.upsert(group: saturatedGroup)
        try await restartedBob.store.save(saturated)

        do {
            _ = try await restartedBob.receiveGroupMessages(
                group: created.id.uuidString,
                maxCount: 10,
                acknowledge: false
            )
            XCTFail("A full pending-acknowledgement window must apply backpressure.")
        } catch let error as HeadlessMessagingClientError {
            XCTAssertEqual(
                error,
                .legacyGroupAcknowledgementBackpressure(
                    "Ack safety",
                    GroupConversation.maximumPendingAcknowledgements
                )
            )
        }

        let afterBackpressureValue = try await restartedBob.store.load()
        let afterBackpressure = try XCTUnwrap(afterBackpressureValue)
        let afterBackpressureGroup = try XCTUnwrap(afterBackpressure.group(for: created.id))
        XCTAssertEqual(
            afterBackpressureGroup.pendingAcknowledgements.count,
            GroupConversation.maximumPendingAcknowledgements
        )
        XCTAssertFalse(afterBackpressureGroup.messages.contains { $0.body == "blocked by backpressure" })
    }

    func testIdentityRotationFailsClosedWithActiveFingerprintScopedGroup() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-group-rotation-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let stateURL = root.appendingPathComponent("client.json")
        let client = HeadlessMessagingClient(stateURL: stateURL, useEncryptedStore: false)
        _ = try await client.createState(
            displayName: "Owner",
            relay: RelayEndpoint(host: "127.0.0.1", port: 49_998)
        )
        let initialValue = try await client.store.load()
        var state = try XCTUnwrap(initialValue)
        let originalFingerprint = state.identity.fingerprint
        state.groups = [
            GroupConversation(
                title: "Fingerprint scoped",
                memberContactIds: [],
                relayInboxId: "legacy-group-inbox"
            )
        ]
        try await client.store.save(state)

        do {
            _ = try await client.rotateIdentity(preservingContinuityWith: [])
            XCTFail("Identity rotation should fail closed while a legacy group is active.")
        } catch let error as HeadlessMessagingClientError {
            XCTAssertEqual(error, .identityRotationBlockedByLegacyGroups(1))
        }

        let persistedValue = try await client.store.load()
        let persisted = try XCTUnwrap(persistedValue)
        XCTAssertEqual(persisted.identity.fingerprint, originalFingerprint)
        XCTAssertNil(persisted.identityMutationV2)
    }
}

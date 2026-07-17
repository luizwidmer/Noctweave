import Foundation
import CryptoKit
import XCTest
@testable import NoctweaveCore

final class InboxRetirementTests: XCTestCase {
    func testRetirementPurgesMailboxConsumersAndBlocksReuseAndDelivery() async throws {
        let store = RelayStore(temporalBucketSeconds: 0)
        let accessKey = try SigningKeyPair.generate()
        let consumerKey = try SigningKeyPair.generate()
        let inboxId = InboxAddress.derived(from: accessKey.publicKeyData)
        let direct = retirementEnvelope(marker: 0x11)
        let consumerId = MailboxConsumerId.generate()

        try await store.registerInbox(inboxId: inboxId, accessPublicKey: accessKey.publicKeyData)
        _ = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: consumerKey.publicKeyData,
            startingSequence: 0
        )
        _ = try await store.deliver(direct, to: inboxId)

        let digest = Data(repeating: 0xA1, count: SHA256.byteCount)
        try await store.retireInbox(inboxId: inboxId, requestDigest: digest)

        let purgedMessages = try await store.fetch(inboxId: inboxId)
        let purgedAccessKey = await store.inboxAccessPublicKey(for: inboxId)
        let purgedConsumers = await store.mailboxConsumers(inboxId: inboxId)
        let isRetired = await store.isInboxRetired(inboxId: inboxId)
        XCTAssertTrue(purgedMessages.isEmpty)
        XCTAssertNil(purgedAccessKey)
        XCTAssertTrue(purgedConsumers.isEmpty)
        XCTAssertTrue(isRetired)

        await XCTAssertThrowsInboxRetirementErrorAsync(
            try await store.deliver(direct, to: inboxId),
            expected: .inboxRetired
        )
        await XCTAssertThrowsInboxRetirementErrorAsync(
            try await store.registerInbox(inboxId: inboxId, accessPublicKey: accessKey.publicKeyData),
            expected: .inboxRetired
        )
        await XCTAssertThrowsInboxRetirementErrorAsync(
            try await store.registerMailboxConsumer(
                inboxId: inboxId,
                consumerId: MailboxConsumerId.generate(),
                consumerSigningPublicKey: consumerKey.publicKeyData
            ),
            expected: .inboxRetired
        )

        try await store.retireInbox(inboxId: inboxId, requestDigest: digest)
        await XCTAssertThrowsInboxRetirementErrorAsync(
            try await store.retireInbox(
                inboxId: inboxId,
                requestDigest: Data(repeating: 0xA2, count: SHA256.byteCount)
            ),
            expected: .invalidInboxRetirement
        )
    }

    func testRetirementPersistenceFailureRollsBackThenExactRetryPersists() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("retirement.sqlite")
        let store = RelayStore(storeURL: storeURL, temporalBucketSeconds: 0)
        let accessKey = try SigningKeyPair.generate()
        let consumerKey = try SigningKeyPair.generate()
        let inboxId = InboxAddress.derived(from: accessKey.publicKeyData)
        let envelope = retirementEnvelope(marker: 0x21)
        let consumerId = MailboxConsumerId.generate()
        let digest = Data(repeating: 0xB1, count: SHA256.byteCount)

        try await store.registerInbox(inboxId: inboxId, accessPublicKey: accessKey.publicKeyData)
        _ = try await store.registerMailboxConsumer(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: consumerKey.publicKeyData,
            startingSequence: 0
        )
        _ = try await store.deliver(envelope, to: inboxId)

        await store.failNextPersistenceForTesting()
        await XCTAssertThrowsInboxRetirementErrorAsync(
            try await store.retireInbox(inboxId: inboxId, requestDigest: digest)
        )
        let rolledBackKey = await store.inboxAccessPublicKey(for: inboxId)
        let rolledBackMessages = try await store.fetch(inboxId: inboxId)
        let rolledBackConsumers = await store.mailboxConsumers(inboxId: inboxId)
        let rolledBackRetirement = await store.isInboxRetired(inboxId: inboxId)
        XCTAssertNotNil(rolledBackKey)
        XCTAssertEqual(rolledBackMessages.map(\.id), [envelope.id])
        XCTAssertEqual(rolledBackConsumers.map(\.consumerId), [consumerId])
        XCTAssertFalse(rolledBackRetirement)

        try await store.retireInbox(inboxId: inboxId, requestDigest: digest)
        let reloaded = RelayStore(storeURL: storeURL, temporalBucketSeconds: 0)
        try await reloaded.loadFromDisk()
        let persistedRetirement = await reloaded.isMatchingInboxRetirement(
            inboxId: inboxId,
            requestDigest: digest
        )
        let persistedKey = await reloaded.inboxAccessPublicKey(for: inboxId)
        let persistedMessages = try await reloaded.fetch(inboxId: inboxId)
        let persistedConsumers = await reloaded.mailboxConsumers(inboxId: inboxId)
        XCTAssertTrue(persistedRetirement)
        XCTAssertNil(persistedKey)
        XCTAssertTrue(persistedMessages.isEmpty)
        XCTAssertTrue(persistedConsumers.isEmpty)
    }

    func testLifetimeCapacityRejectsNewGenerationsButNeverBlocksAdmittedRetirement() async throws {
        let store = RelayStore(maxLifetimeInboxGenerations: 2)
        let firstKey = Data("lifetime-cap-first".utf8)
        let secondKey = Data("lifetime-cap-second".utf8)
        let thirdKey = Data("lifetime-cap-third".utf8)
        let firstInbox = InboxAddress.derived(from: firstKey)
        let secondInbox = InboxAddress.derived(from: secondKey)
        let thirdInbox = InboxAddress.derived(from: thirdKey)
        try await store.registerInbox(inboxId: firstInbox, accessPublicKey: firstKey)
        try await store.registerInbox(inboxId: secondInbox, accessPublicKey: secondKey)

        await XCTAssertThrowsInboxRetirementErrorAsync(
            try await store.registerInbox(inboxId: thirdInbox, accessPublicKey: thirdKey),
            expected: .relayCapacityExceeded
        )
        try await store.retireInbox(
            inboxId: firstInbox,
            requestDigest: Data(repeating: 0xD1, count: SHA256.byteCount)
        )
        try await store.retireInbox(
            inboxId: secondInbox,
            requestDigest: Data(repeating: 0xD2, count: SHA256.byteCount)
        )
        await XCTAssertThrowsInboxRetirementErrorAsync(
            try await store.registerInbox(inboxId: thirdInbox, accessPublicKey: thirdKey),
            expected: .relayCapacityExceeded
        )
        await XCTAssertThrowsInboxRetirementErrorAsync(
            try await store.retireInbox(
                inboxId: thirdInbox,
                requestDigest: Data(repeating: 0xD3, count: SHA256.byteCount)
            ),
            expected: .relayCapacityExceeded
        )
    }

    func testRetirementMarkersNeverExpireOrEvictOlderBurns() async throws {
        let store = RelayStore()
        let now = Date()
        for index in 0..<10_000 {
            let key = withUnsafeBytes(of: UInt64(index).bigEndian) { Data($0) }
            let inboxId = InboxAddress.derived(from: key)
            try await store.registerInbox(inboxId: inboxId, accessPublicKey: key)
            try await store.retireInbox(
                inboxId: inboxId,
                requestDigest: Data(repeating: UInt8(truncatingIfNeeded: index), count: SHA256.byteCount),
                now: now
            )
        }
        let fullCount = await store.inboxRetirementTombstoneCount(now: now)
        XCTAssertEqual(fullCount, 10_000)

        let overflowKey = Data("retirement-overflow".utf8)
        let overflowInbox = InboxAddress.derived(from: overflowKey)
        try await store.registerInbox(inboxId: overflowInbox, accessPublicKey: overflowKey)
        try await store.retireInbox(
            inboxId: overflowInbox,
            requestDigest: Data(repeating: 0xCC, count: SHA256.byteCount),
            now: now
        )
        let retainedCount = await store.inboxRetirementTombstoneCount(now: now)
        let overflowRegistration = await store.inboxAccessPublicKey(for: overflowInbox)
        let overflowRetired = await store.isInboxRetired(inboxId: overflowInbox, now: now)
        XCTAssertEqual(retainedCount, 10_001)
        XCTAssertNil(overflowRegistration)
        XCTAssertTrue(overflowRetired)

        let afterRetention = now.addingTimeInterval(30 * 86400 + 1)
        let retainedAfterThirtyDays = await store.inboxRetirementTombstoneCount(now: afterRetention)
        XCTAssertEqual(retainedAfterThirtyDays, 10_001)
        let oldestKey = withUnsafeBytes(of: UInt64(0).bigEndian) { Data($0) }
        let oldestInbox = InboxAddress.derived(from: oldestKey)
        let oldestStillRetired = await store.isInboxRetired(inboxId: oldestInbox, now: afterRetention)
        XCTAssertTrue(oldestStillRetired)
        await XCTAssertThrowsInboxRetirementErrorAsync(
            try await store.registerInbox(inboxId: oldestInbox, accessPublicKey: oldestKey),
            expected: .inboxRetired
        )
    }

    func testWireRetirementIsNonExpiringExactReplayAndRejectsChangedOrMalformedRequest() async throws {
        let store = RelayStore()
        let server = RelayServer(store: store)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: UInt16.random(in: 45_100...47_000))
        let started = expectation(description: "retirement relay started")
        server.onEvent = { event in
            if case .started = event { started.fulfill() }
        }
        try server.start(host: "0.0.0.0", port: endpoint.port)
        defer { server.stop() }
        await fulfillment(of: [started], timeout: 2)
        let client = RelayClient(endpoint: endpoint)

        let accessKey = try SigningKeyPair.generate()
        let inboxId = InboxAddress.derived(from: accessKey.publicKeyData)
        try await store.registerInbox(inboxId: inboxId, accessPublicKey: accessKey.publicKeyData)
        let persistedRequest = try RetireInboxRequest.make(
            inboxId: inboxId,
            accessSigningKey: accessKey,
            signedAt: Date(timeIntervalSince1970: 1),
            nonce: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
        )

        let firstResponse = try await client.send(.retireInbox(persistedRequest))
        let replayResponse = try await client.send(.retireInbox(persistedRequest))
        XCTAssertEqual(firstResponse.type, .ok)
        XCTAssertEqual(replayResponse.type, .ok)

        let changed = try RetireInboxRequest.make(
            inboxId: inboxId,
            accessSigningKey: accessKey,
            signedAt: persistedRequest.accessProof!.signedAt,
            nonce: UUID(uuidString: "22222222-2222-4222-8222-222222222222")!
        )
        let changedResponse = try await client.send(.retireInbox(changed))
        XCTAssertEqual(changedResponse.error, "Inbox retirement request does not match tombstone")

        let remainsRetired = await store.isInboxRetired(
            inboxId: inboxId,
            now: Date().addingTimeInterval(30 * 86400 + 1)
        )
        XCTAssertTrue(remainsRetired)
        let replayAfterTombstoneExpiry = try await client.send(.retireInbox(persistedRequest))
        XCTAssertEqual(replayAfterTombstoneExpiry.type, .ok)

        let absentKey = try SigningKeyPair.generate()
        let absentInbox = InboxAddress.derived(from: absentKey.publicKeyData)
        let absentRequest = try RetireInboxRequest.make(
            inboxId: absentInbox,
            accessSigningKey: absentKey
        )
        let absentResponse = try await client.send(.retireInbox(absentRequest))
        XCTAssertEqual(absentResponse.type, .ok)
        let absentRetired = await store.isInboxRetired(inboxId: absentInbox)
        XCTAssertTrue(absentRetired)
        await XCTAssertThrowsInboxRetirementErrorAsync(
            try await store.registerInbox(inboxId: absentInbox, accessPublicKey: absentKey.publicKeyData),
            expected: .inboxRetired
        )

        let malformedKey = try SigningKeyPair.generate()
        let malformedInbox = InboxAddress.derived(from: malformedKey.publicKeyData)
        try await store.registerInbox(
            inboxId: malformedInbox,
            accessPublicKey: malformedKey.publicKeyData
        )
        let valid = try RetireInboxRequest.make(
            inboxId: malformedInbox,
            accessSigningKey: malformedKey
        )
        let proof = valid.accessProof!
        let malformed = RetireInboxRequest(
            inboxId: malformedInbox,
            accessProof: RelayActorProof(
                fingerprint: proof.fingerprint,
                publicSigningKey: proof.publicSigningKey,
                signedAt: proof.signedAt,
                nonce: proof.nonce,
                signature: Data(repeating: 0x00, count: proof.signature.count)
            )
        )
        let malformedResponse = try await client.send(.retireInbox(malformed))
        XCTAssertEqual(malformedResponse.error, "Invalid inbox retirement proof signature.")
        let retainedMalformedRegistration = await store.inboxAccessPublicKey(for: malformedInbox)
        XCTAssertNotNil(retainedMalformedRegistration)
    }

    func testCanonicalRetirementProofPayload() throws {
        let proof = RelayActorProof(
            fingerprint: "",
            publicSigningKey: Data(),
            signedAt: ISO8601DateFormatter().date(from: "2026-07-16T12:34:56Z")!,
            nonce: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
            signature: Data()
        )
        let request = RetireInboxRequest(inboxId: "inbox")
        XCTAssertEqual(
            String(decoding: try request.signableData(for: proof), as: UTF8.self),
            #"{"domain":"org.noctweave.relay.retire-inbox","inboxId":"inbox","nonce":"11111111-1111-4111-8111-111111111111","signedAt":"2026-07-16T12:34:56Z","version":1}"#
        )
    }
}

private func retirementEnvelope(marker: UInt8) -> ProtocolEnvelopeV1 {
    makeTestProtocolEnvelope(
        conversationId: "inbox-retirement",
        sessionId: "retirement-session",
        counter: UInt64(marker),
        sentAt: Date(),
        payload: EncryptedPayload(
            nonce: Data(repeating: marker, count: 12),
            ciphertext: Data(repeating: marker, count: 512),
            tag: Data(repeating: marker, count: 16)
        ),
        signature: Data(repeating: marker, count: 3_309)
    )
}

private func retirementFingerprint(_ marker: UInt8) -> String {
    Data(repeating: marker, count: 32).base64EncodedString()
}

private func XCTAssertThrowsInboxRetirementErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    expected: RelayStoreError? = nil,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected expression to throw", file: file, line: line)
    } catch {
        if let expected {
            XCTAssertEqual(error as? RelayStoreError, expected, file: file, line: line)
        }
    }
}

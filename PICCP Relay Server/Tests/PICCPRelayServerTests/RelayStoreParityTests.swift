import Foundation
import XCTest
@testable import PICCPRelayServer

final class RelayStoreParityTests: XCTestCase {
    func testStoreRejectsInvalidAttachmentPayload() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 300)
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0x01, count: 11),
            ciphertext: Data([0xAA, 0xBB]),
            tag: Data(repeating: 0x02, count: 16)
        )

        XCTAssertThrowsError(
            try store.storeAttachment(
                attachmentId: UUID(),
                chunkIndex: 0,
                payload: payload,
                ttlSeconds: nil
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .invalidAttachmentPayload)
        }
    }

    func testInboxLimitIsEnforced() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: 1, temporalBucketSeconds: 300)
        let inboxId = InboxAddress.generate()
        let envelope = makeEnvelope()

        _ = try store.deliver(envelope, to: inboxId)
        XCTAssertThrowsError(try store.deliver(envelope, to: inboxId)) { error in
            XCTAssertEqual(error as? RelayStoreError, .inboxFull)
        }
    }

    func testStoreRejectsOversizedPrekeyBundle() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: 1, temporalBucketSeconds: 300)
        let fingerprint = "prekey-owner"
        let bundle = PrekeyBundle(
            identityFingerprint: fingerprint,
            signedPrekey: SignedPrekey(
                id: UUID(),
                publicKey: Data([0x01]),
                issuedAt: Date(),
                signature: Data([0x02])
            ),
            oneTimePrekeys: (0..<65).map { _ in
                OneTimePrekey(publicKey: Data([0x03]), signature: Data([0x04]))
            }
        )

        XCTAssertThrowsError(
            try store.uploadPrekeyBundle(fingerprint: fingerprint, bundle: bundle, ttlSeconds: nil)
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .invalidPrekeyBundle)
        }
    }

    func testDeleteGroupAuthorizationMatchesCoreBehavior() throws {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 300)
        let creator = "creator-fingerprint"
        let peer = "peer-fingerprint"
        let group = try store.createGroup(
            title: "Parity Group",
            creatorFingerprint: creator,
            memberFingerprints: [peer],
            creatorProfile: nil,
            memberProfiles: nil
        )

        XCTAssertThrowsError(
            try store.deleteGroup(
                DeleteGroupRequest(groupId: group.id, actorFingerprint: peer)
            )
        ) { error in
            XCTAssertEqual(error as? RelayStoreError, .unauthorizedGroupMutation)
        }

        try store.deleteGroup(DeleteGroupRequest(groupId: group.id, actorFingerprint: creator))
        XCTAssertNil(store.fetchGroup(groupId: group.id))
    }

    func testCoordinatorDirectoryCacheRoundTrip() {
        let store = RelayStore(fileURL: nil, maxInboxMessages: nil, temporalBucketSeconds: 300)
        let node = FederationNodeRecord(
            endpoint: RelayEndpoint(host: "relay.example.org", port: 9339, useTLS: true, transport: .websocket),
            relayInfo: RelayInfo(
                kind: .standard,
                federation: FederationDescriptor(mode: .open, name: "open-mesh", description: nil),
                tlsEnabled: true,
                temporalBucketSeconds: 60,
                relayName: "Edge 1",
                operatorNote: nil,
                softwareVersion: "test",
                groupCreationMode: .allowed,
                requiresPassword: false,
                federationCoordinatorEndpoints: nil,
                coordinatorReportedRelayCount: nil,
                curatedStrictPolicyEnabled: nil,
                curatedCoordinatorQuorum: nil,
                curatedRequireSignedDirectory: nil,
                federationDirectoryPublicKey: nil,
                knownOpenPeers: nil,
                advertisedAt: Date()
            ),
            lastHeartbeatAt: Date(),
            expiresAt: Date().addingTimeInterval(120)
        )

        store.setCoordinatorDirectoryCache([node])
        XCTAssertEqual(store.coordinatorDirectoryCacheSnapshot(), [node])
    }

    func testFederationDirectorySignatureUsesMLDSAAndRejectsTampering() throws {
        guard OQSSignatureVerifier.shared.isAvailable else {
            throw XCTSkip("liboqs runtime is unavailable")
        }

        let privateKey = FederationDirectorySignature.privateKeyData(from: nil)
        let publicKey = try XCTUnwrap(FederationDirectorySignature.publicKeyData(from: privateKey))
        let node = FederationNodeRecord(
            endpoint: RelayEndpoint(host: "relay.example.org", port: 9339, useTLS: true, transport: .websocket),
            relayInfo: RelayInfo(
                kind: .standard,
                federation: FederationDescriptor(mode: .open, name: "open-mesh", description: nil),
                tlsEnabled: true,
                temporalBucketSeconds: 60,
                relayName: "Edge 1",
                operatorNote: nil,
                softwareVersion: "test",
                groupCreationMode: .allowed,
                requiresPassword: false,
                federationCoordinatorEndpoints: nil,
                coordinatorReportedRelayCount: nil,
                curatedStrictPolicyEnabled: nil,
                curatedCoordinatorQuorum: nil,
                curatedRequireSignedDirectory: nil,
                federationDirectoryPublicKey: nil,
                knownOpenPeers: nil,
                advertisedAt: Date()
            ),
            lastHeartbeatAt: Date(),
            expiresAt: Date().addingTimeInterval(120)
        )
        let unsigned = FederationDirectorySnapshot(
            version: 1,
            mode: .open,
            federationName: "open-mesh",
            issuedAt: Date(),
            validUntil: Date().addingTimeInterval(120),
            maxStalenessSeconds: 60,
            nodes: [node],
            signatureAlgorithm: nil,
            signature: nil
        )

        let signed = try FederationDirectorySignature.signedSnapshot(from: unsigned, privateKeyData: privateKey)
        XCTAssertEqual(signed.signatureAlgorithm, FederationDirectorySignature.algorithm)
        XCTAssertTrue(FederationDirectorySignature.verify(snapshot: signed, trustedPublicKey: publicKey))

        let tampered = FederationDirectorySnapshot(
            version: signed.version,
            mode: signed.mode,
            federationName: "different-mesh",
            issuedAt: signed.issuedAt,
            validUntil: signed.validUntil,
            maxStalenessSeconds: signed.maxStalenessSeconds,
            nodes: signed.nodes,
            signatureAlgorithm: signed.signatureAlgorithm,
            signature: signed.signature
        )
        XCTAssertFalse(FederationDirectorySignature.verify(snapshot: tampered, trustedPublicKey: publicKey))
    }

    func testRelayInfoCarriesTemporalBucketSchedule() {
        let configuration = RelayConfiguration(
            temporalBucketSeconds: 300,
            temporalBucketScheduleSeconds: [60, 120, 300],
            attachmentDefaultTTLSeconds: 1800,
            attachmentMaxTTLSeconds: 7200
        )
        let info = configuration.makeInfo()
        XCTAssertEqual(info.temporalBucketSeconds, 300)
        XCTAssertEqual(info.temporalBucketScheduleSeconds ?? [], [60, 120, 300])
        XCTAssertEqual(info.attachmentDefaultTTLSeconds, 1800)
        XCTAssertEqual(info.attachmentMaxTTLSeconds, 7200)
    }

    func testRelayConfigurationNormalizesAttachmentTTLPolicy() {
        let configuration = RelayConfiguration(
            attachmentDefaultTTLSeconds: 30,
            attachmentMaxTTLSeconds: 45,
            attachmentsEnabled: false
        )
        XCTAssertEqual(configuration.attachmentDefaultTTLSeconds, 60)
        XCTAssertEqual(configuration.attachmentMaxTTLSeconds, 60)
        XCTAssertEqual(configuration.makeInfo().attachmentsEnabled, false)
    }

    func testDiskPersistenceUsesSQLiteStore() throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }
        let requestedURL = tempDirectory.appendingPathComponent("relay_store.json")
        let sqliteURL = tempDirectory.appendingPathComponent("relay_store.sqlite")
        let inboxId = InboxAddress.generate()
        let envelope = makeEnvelope()

        let writer = RelayStore(fileURL: requestedURL, maxInboxMessages: nil, temporalBucketSeconds: 300)
        _ = try writer.deliver(envelope, to: inboxId)
        XCTAssertTrue(FileManager.default.fileExists(atPath: sqliteURL.path))
        let sqliteHeader = try Data(contentsOf: sqliteURL).prefix(16)
        XCTAssertEqual(Data("SQLite format 3\0".utf8), Data(sqliteHeader))

        let reader = RelayStore(fileURL: requestedURL, maxInboxMessages: nil, temporalBucketSeconds: 300)
        reader.load()
        let fetched = reader.fetch(inboxId: inboxId, maxCount: nil)
        XCTAssertEqual(fetched.count, 1)
        XCTAssertEqual(fetched.first?.id, envelope.id)
        XCTAssertEqual(fetched.first?.conversationId, envelope.conversationId)
        XCTAssertEqual(fetched.first?.sessionId, envelope.sessionId)
        XCTAssertEqual(fetched.first?.senderFingerprint, envelope.senderFingerprint)
        XCTAssertEqual(fetched.first?.messageCounter, envelope.messageCounter)
        XCTAssertEqual(fetched.first?.kemCiphertext, envelope.kemCiphertext)
        XCTAssertEqual(fetched.first?.payload, envelope.payload)
        XCTAssertEqual(fetched.first?.signature, envelope.signature)
    }

    private func makeEnvelope() -> Envelope {
        Envelope(
            conversationId: "parity-conversation",
            sessionId: UUID().uuidString,
            senderFingerprint: "sender-fingerprint",
            sentAt: Date(),
            messageCounter: 1,
            kemCiphertext: Data([0x10, 0x20]),
            payload: EncryptedPayload(
                nonce: Data(repeating: 0xA1, count: 12),
                ciphertext: Data([0x01, 0x02, 0x03]),
                tag: Data(repeating: 0xB2, count: 16)
            ),
            signature: Data([0x99, 0x98, 0x97])
        )
    }
}

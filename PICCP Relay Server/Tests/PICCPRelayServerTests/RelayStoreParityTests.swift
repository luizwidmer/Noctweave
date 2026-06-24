import Foundation
import SQLite3
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

    func testOpenFederationDHTRecordUsesMLDSAAndRejectsTampering() throws {
        guard OQSSignatureVerifier.shared.isAvailable,
              let keyPair = OQSSignatureVerifier.shared.generateKeyPair() else {
            throw XCTSkip("liboqs runtime is unavailable")
        }

        let now = Date(timeIntervalSince1970: 1_000)
        let record = try OpenFederationDHTRecord.signed(
            endpoint: RelayEndpoint(host: "relay.example.org", port: 443, useTLS: true, transport: .websocket),
            federationName: "open-mesh",
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey,
            issuedAt: now
        )

        XCTAssertNoThrow(try record.validate(expectedFederationName: "open-mesh", now: now, requirePublicEndpoint: false))
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
        XCTAssertThrowsError(try tampered.validate(expectedFederationName: "open-mesh", now: now, requirePublicEndpoint: false)) { error in
            XCTAssertEqual(error as? OpenFederationDHTRecordError, .invalidSignature)
        }
    }

    func testOpenFederationDHTHTTPGatewayTransportPublishesWithAuthHeader() async throws {
        let namespace = OpenFederationDHTRecord.namespace(federationName: "gateway-net")
        let record = makeUnsignedDHTRecord(host: "relay.gateway.example.org", federationName: "gateway-net")
        let protocolHarness = DHTGatewayURLProtocolHarness()
        protocolHarness.handler = { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.url?.path, "/mesh/v1/open-federation/dht/records")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer gateway-token")
            let body = try XCTUnwrap(DHTGatewayURLProtocolHarness.bodyData(from: request))
            let decoded = try RelayCodec.decoder().decode(DHTGatewayPublishRequestProbe.self, from: body)
            XCTAssertEqual(decoded.namespace, namespace)
            XCTAssertEqual(decoded.record, record)
            return (200, Data())
        }
        let transport = OpenFederationDHTHTTPGatewayTransport(
            baseURL: try XCTUnwrap(URL(string: "https://gateway.example.org/mesh")),
            session: protocolHarness.makeSession(),
            authToken: " gateway-token "
        )

        try await transport.publish(record, namespace: namespace)
        XCTAssertEqual(protocolHarness.requestCount, 1)
    }

    func testOpenFederationDHTHTTPGatewayTransportQueriesRecords() async throws {
        let namespace = OpenFederationDHTRecord.namespace(federationName: "gateway-net")
        let records = (0..<3).map {
            makeUnsignedDHTRecord(host: "relay-\($0).gateway.example.org", federationName: "gateway-net")
        }
        let response = try RelayCodec.encoder(sortedKeys: true).encode(
            DHTGatewayQueryResponseProbe(records: records)
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
        let transport = OpenFederationDHTHTTPGatewayTransport(
            baseURL: try XCTUnwrap(URL(string: "https://gateway.example.org")),
            session: protocolHarness.makeSession()
        )

        let queried = try await transport.query(namespace: namespace, limit: 2)
        XCTAssertEqual(queried, Array(records.prefix(2)))
        XCTAssertEqual(protocolHarness.requestCount, 1)
    }

    func testOpenFederationDHTHTTPGatewayRefreshAppliesPoisoningAndFloodGuards() async throws {
        guard OQSSignatureVerifier.shared.isAvailable,
              let keyPair = OQSSignatureVerifier.shared.generateKeyPair() else {
            throw XCTSkip("liboqs runtime is unavailable")
        }

        let now = Date(timeIntervalSince1970: 1_000)
        let federationName = "gateway-net"
        let namespace = OpenFederationDHTRecord.namespace(federationName: federationName)
        let valid = try makeSignedDHTRecord(host: "relay-a.gateway.example.org", federationName: federationName, keyPair: keyPair, issuedAt: now)
        let wrongFederation = try makeSignedDHTRecord(host: "relay-b.gateway.example.org", federationName: "other-net", keyPair: keyPair, issuedAt: now)
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
            try makeSignedDHTRecord(
                host: "crowded.gateway.example.org",
                federationName: federationName,
                keyPair: keyPair,
                issuedAt: now.addingTimeInterval(Double(index + 1))
            )
        }
        let response = try RelayCodec.encoder(sortedKeys: true).encode(
            DHTGatewayQueryResponseProbe(records: [valid, wrongFederation, tampered] + flooded)
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
        let transport = OpenFederationDHTHTTPGatewayTransport(
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
            privateKey: nil,
            publicKey: nil,
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

    func testOpenFederationDHTNativeOverlayTransportWalksPeerHintsWithBounds() async throws {
        let namespace = OpenFederationDHTRecord.namespace(federationName: "native-net")
        let seed = RelayEndpoint(host: "seed.example.org", port: 443, useTLS: true, transport: .http)
        let peerA = RelayEndpoint(host: "peer-a.example.org", port: 443, useTLS: true, transport: .http)
        let peerB = RelayEndpoint(host: "peer-b.example.org", port: 443, useTLS: true, transport: .http)
        let client = MockOpenFederationDHTRelayQueryClient(
            infoByEndpoint: [
                seed: relayInfo(name: "native-net", knownOpenPeers: [peerA, peerB]),
                peerA: relayInfo(name: "native-net", knownOpenPeers: [seed]),
                peerB: relayInfo(name: "native-net")
            ],
            recordsByEndpoint: [
                seed: [makeUnsignedDHTRecord(host: "seed-record.example.org", federationName: "native-net")],
                peerA: [makeUnsignedDHTRecord(host: "peer-record.example.org", federationName: "native-net")],
                peerB: [makeUnsignedDHTRecord(host: "ignored-record.example.org", federationName: "native-net")]
            ]
        )
        let transport = OpenFederationDHTNativeOverlayTransport(
            seedEndpoints: [seed],
            client: client,
            maxVisitedEndpoints: 2,
            maxPeerHintsPerEndpoint: 2
        )

        let records = try await transport.query(namespace: namespace, limit: 8)
        let visited = await client.visitedHosts()

        XCTAssertEqual(records.map(\.endpoint.host), ["seed-record.example.org", "peer-record.example.org"])
        XCTAssertEqual(visited, ["seed.example.org", "peer-a.example.org"])
    }

    func testOpenFederationDHTNativeOverlayRefreshAppliesPoisoningAndFloodGuards() async throws {
        guard OQSSignatureVerifier.shared.isAvailable,
              let keyPair = OQSSignatureVerifier.shared.generateKeyPair() else {
            throw XCTSkip("liboqs runtime is unavailable")
        }

        let now = Date(timeIntervalSince1970: 1_000)
        let federationName = "native-net"
        let namespace = OpenFederationDHTRecord.namespace(federationName: federationName)
        let seed = RelayEndpoint(host: "seed.example.org", port: 443, useTLS: true, transport: .http)
        let valid = try makeSignedDHTRecord(host: "relay-a.native.example.org", federationName: federationName, keyPair: keyPair, issuedAt: now)
        let wrongFederation = try makeSignedDHTRecord(host: "relay-b.native.example.org", federationName: "other-net", keyPair: keyPair, issuedAt: now)
        let tampered = OpenFederationDHTRecord(
            namespace: valid.namespace,
            relayIdentityDigest: valid.relayIdentityDigest,
            endpoint: RelayEndpoint(host: "poison.native.example.org", port: 443, useTLS: true, transport: .websocket),
            federationName: valid.federationName,
            issuedAt: valid.issuedAt,
            expiresAt: valid.expiresAt,
            relaySigningPublicKey: valid.relaySigningPublicKey,
            signature: valid.signature
        )
        let flooded = try (0..<3).map { index in
            try makeSignedDHTRecord(
                host: "crowded.native.example.org",
                federationName: federationName,
                keyPair: keyPair,
                issuedAt: now.addingTimeInterval(Double(index + 1))
            )
        }
        let client = MockOpenFederationDHTRelayQueryClient(
            infoByEndpoint: [seed: relayInfo(name: federationName)],
            recordsByEndpoint: [seed: [valid, wrongFederation, tampered] + flooded]
        )
        let transport = OpenFederationDHTNativeOverlayTransport(
            seedEndpoints: [seed],
            client: client,
            maxVisitedEndpoints: 4,
            maxPeerHintsPerEndpoint: 2
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
            privateKey: nil,
            publicKey: nil,
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
        let publishCount = await client.publishCount()
        let queryNamespaces = await client.queryNamespaces()
        XCTAssertEqual(result.nodes.count, 3)
        XCTAssertEqual(publishCount, 0)
        XCTAssertEqual(queryNamespaces, [namespace])
    }

    func testOpenFederationDHTHTTPGatewayTransportRejectsOversizedResponse() async throws {
        let protocolHarness = DHTGatewayURLProtocolHarness()
        protocolHarness.handler = { _ in
            (200, Data(repeating: 0x41, count: 2_048))
        }
        let transport = OpenFederationDHTHTTPGatewayTransport(
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

    func testDiskPersistenceSkipsCorruptNormalizedMessageRow() throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }
        let requestedURL = tempDirectory.appendingPathComponent("relay_store.json")
        let sqliteURL = tempDirectory.appendingPathComponent("relay_store.sqlite")
        let inboxId = InboxAddress.generate()
        let first = makeEnvelope()
        let second = makeEnvelope()

        let writer = RelayStore(fileURL: requestedURL, maxInboxMessages: nil, temporalBucketSeconds: 300)
        _ = try writer.deliver(first, to: inboxId)
        _ = try writer.deliver(second, to: inboxId)
        try overwriteMailboxEnvelope(at: sqliteURL, envelopeId: second.id, with: Data([0xDE, 0xAD, 0xBE, 0xEF]))

        let reader = RelayStore(fileURL: requestedURL, maxInboxMessages: nil, temporalBucketSeconds: 300)
        reader.load()
        let fetched = reader.fetch(inboxId: inboxId, maxCount: nil)
        XCTAssertEqual(fetched.map(\.id), [first.id])
    }

    func testDiskPersistenceMigratesLegacySnapshotIntoNormalizedTables() throws {
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDirectory)
        }
        let requestedURL = tempDirectory.appendingPathComponent("relay_store.json")
        let sqliteURL = tempDirectory.appendingPathComponent("relay_store.sqlite")
        let inboxId = InboxAddress.generate()
        let envelope = makeEnvelope()
        let legacySnapshot = LegacyRelayStoreSnapshot(
            mailboxes: [
                inboxId: [
                    LegacyStoredEnvelope(envelope: envelope, storedAt: Date())
                ]
            ]
        )
        try insertRelayStateValue(
            at: sqliteURL,
            key: "relay_snapshot_v1",
            value: RelayCodec.encoder().encode(legacySnapshot)
        )

        let reader = RelayStore(fileURL: requestedURL, maxInboxMessages: nil, temporalBucketSeconds: 300)
        reader.load()
        let fetched = reader.fetch(inboxId: inboxId, maxCount: nil)

        XCTAssertEqual(fetched.map(\.id), [envelope.id])
        XCTAssertTrue(try relayStateMetaExists(at: sqliteURL, key: "normalized_schema_v1"))
        XCTAssertEqual(try sqliteRowCount(at: sqliteURL, table: "relay_mailbox_envelopes"), 1)
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

    private struct LegacyRelayStoreSnapshot: Codable {
        let mailboxes: [String: [LegacyStoredEnvelope]]
    }

    private struct LegacyStoredEnvelope: Codable {
        let envelope: Envelope
        let storedAt: Date
    }

    private func overwriteMailboxEnvelope(at sqliteURL: URL, envelopeId: UUID, with data: Data) throws {
        var db: OpaquePointer?
        guard sqlite3_open(sqliteURL.path, &db) == SQLITE_OK, let db else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 5)
        }
        defer { sqlite3_close(db) }

        let sql = "UPDATE relay_mailbox_envelopes SET value = ?1 WHERE envelope_id = ?2;"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 6)
        }
        defer { sqlite3_finalize(statement) }

        let bindBlobResult = data.withUnsafeBytes { buffer in
            sqlite3_bind_blob(statement, 1, buffer.baseAddress, Int32(buffer.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        }
        guard bindBlobResult == SQLITE_OK else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 7)
        }
        guard sqlite3_bind_text(statement, 2, envelopeId.uuidString, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)) == SQLITE_OK else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 8)
        }
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 9)
        }
        XCTAssertEqual(sqlite3_changes(db), 1)
    }

    private func insertRelayStateValue(at sqliteURL: URL, key: String, value: Data) throws {
        var db: OpaquePointer?
        guard sqlite3_open(sqliteURL.path, &db) == SQLITE_OK, let db else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 10)
        }
        defer { sqlite3_close(db) }
        guard sqlite3_exec(
            db,
            "CREATE TABLE IF NOT EXISTS relay_state (key TEXT PRIMARY KEY, value BLOB NOT NULL);",
            nil,
            nil,
            nil
        ) == SQLITE_OK else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 11)
        }
        let sql = "INSERT INTO relay_state (key, value) VALUES (?1, ?2);"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 12)
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_bind_text(statement, 1, key, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)) == SQLITE_OK else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 13)
        }
        let bindBlobResult = value.withUnsafeBytes { buffer in
            sqlite3_bind_blob(statement, 2, buffer.baseAddress, Int32(buffer.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        }
        guard bindBlobResult == SQLITE_OK else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 14)
        }
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 15)
        }
    }

    private func relayStateMetaExists(at sqliteURL: URL, key: String) throws -> Bool {
        var db: OpaquePointer?
        guard sqlite3_open(sqliteURL.path, &db) == SQLITE_OK, let db else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 16)
        }
        defer { sqlite3_close(db) }
        let sql = "SELECT 1 FROM relay_state_meta WHERE key = ?1 LIMIT 1;"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 17)
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_bind_text(statement, 1, key, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)) == SQLITE_OK else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 18)
        }
        return sqlite3_step(statement) == SQLITE_ROW
    }

    private func sqliteRowCount(at sqliteURL: URL, table: String) throws -> Int {
        var db: OpaquePointer?
        guard sqlite3_open(sqliteURL.path, &db) == SQLITE_OK, let db else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 19)
        }
        defer { sqlite3_close(db) }
        let sql = "SELECT COUNT(*) FROM \(table);"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 20)
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw NSError(domain: "PICCPRelayServerTests.SQLite", code: 21)
        }
        return Int(sqlite3_column_int64(statement, 0))
    }

    private func makeUnsignedDHTRecord(host: String, federationName: String) -> OpenFederationDHTRecord {
        let publicKey = Data("test-public-key-\(host)".utf8)
        let issuedAt = Date(timeIntervalSince1970: 1_000)
        return OpenFederationDHTRecord(
            namespace: OpenFederationDHTRecord.namespace(federationName: federationName),
            relayIdentityDigest: OpenFederationDHTRecord.relayIdentityDigest(publicKey: publicKey),
            endpoint: RelayEndpoint(host: host, port: 443, useTLS: true, transport: .websocket),
            federationName: federationName,
            issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(300),
            relaySigningPublicKey: publicKey,
            signature: Data("test-signature-\(host)".utf8)
        )
    }

    private func makeSignedDHTRecord(
        host: String,
        federationName: String,
        keyPair: (privateKey: Data, publicKey: Data),
        issuedAt: Date
    ) throws -> OpenFederationDHTRecord {
        try OpenFederationDHTRecord.signed(
            endpoint: RelayEndpoint(host: host, port: 443, useTLS: true, transport: .websocket),
            federationName: federationName,
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey,
            issuedAt: issuedAt
        )
    }

    private func relayInfo(name: String, knownOpenPeers: [RelayEndpoint]? = nil) -> RelayInfo {
        RelayInfo(
            kind: .standard,
            federation: FederationDescriptor(mode: .open, name: name),
            tlsEnabled: true,
            transport: .http,
            temporalBucketSeconds: 300,
            groupCreationMode: .allowed,
            knownOpenPeers: knownOpenPeers,
            advertisedAt: Date(timeIntervalSince1970: 1_000)
        )
    }
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

private actor MockOpenFederationDHTRelayQueryClient: OpenFederationDHTRelayQueryClient {
    private let infoByEndpoint: [RelayEndpoint: RelayInfo]
    private let recordsByEndpoint: [RelayEndpoint: [OpenFederationDHTRecord]]
    private var visited: [String] = []
    private var published: [OpenFederationDHTRecord] = []
    private var namespaces: [String] = []

    init(
        infoByEndpoint: [RelayEndpoint: RelayInfo],
        recordsByEndpoint: [RelayEndpoint: [OpenFederationDHTRecord]]
    ) {
        self.infoByEndpoint = infoByEndpoint
        self.recordsByEndpoint = recordsByEndpoint
    }

    func send(_ request: RelayRequest, to endpoint: RelayEndpoint) async throws -> RelayResponse {
        switch request.type {
        case .info:
            visited.append(endpoint.host)
            guard let info = infoByEndpoint[endpoint] else {
                return .error("No relay info")
            }
            return .info(info)
        case .publishOpenFederationDHTRecord:
            if let record = request.publishOpenFederationDHTRecord?.record {
                published.append(record)
            }
            return .ok()
        case .listOpenFederationDHTRecords:
            if let namespace = request.listOpenFederationDHTRecords?.namespace {
                namespaces.append(namespace)
            }
            return .openFederationDHTRecords(recordsByEndpoint[endpoint] ?? [])
        default:
            return .error("Unsupported request")
        }
    }

    func visitedHosts() -> [String] {
        visited
    }

    func publishCount() -> Int {
        published.count
    }

    func queryNamespaces() -> [String] {
        namespaces
    }
}

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

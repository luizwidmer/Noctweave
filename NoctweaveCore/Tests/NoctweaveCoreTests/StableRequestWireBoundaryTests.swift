import Foundation
import XCTest
@testable import NoctweaveCore

final class StableRequestWireBoundaryTests: XCTestCase {
    func testRelayEndpointRequiresExactFieldsAndStructuralValidity() throws {
        let endpoint = makeEndpoint()
        let encoded = try NoctweaveCoder.encode(endpoint)
        let base = try object(encoded)

        XCTAssertEqual(
            Set(base.keys),
            [
                "host", "port", "useTLS", "transport",
                "tlsCertificateFingerprintSHA256", "directorySigningPublicKey"
            ]
        )
        XCTAssertTrue(base["tlsCertificateFingerprintSHA256"] is NSNull)
        XCTAssertTrue(base["directorySigningPublicKey"] is NSNull)
        XCTAssertEqual(try NoctweaveCoder.decode(RelayEndpoint.self, from: encoded), endpoint)

        var unknown = base
        unknown["legacy"] = true
        XCTAssertThrowsError(try decode(RelayEndpoint.self, from: unknown))

        var missing = base
        missing.removeValue(forKey: "directorySigningPublicKey")
        XCTAssertThrowsError(try decode(RelayEndpoint.self, from: missing))

        for invalidHost in ["", " relay.example", "relay\u{0}example", String(repeating: "é", count: 128)] {
            var invalid = base
            invalid["host"] = invalidHost
            XCTAssertThrowsError(try decode(RelayEndpoint.self, from: invalid))
        }

        var zeroPort = base
        zeroPort["port"] = 0
        XCTAssertThrowsError(try decode(RelayEndpoint.self, from: zeroPort))

        var shortFingerprint = base
        shortFingerprint["tlsCertificateFingerprintSHA256"] = Data(repeating: 0x11, count: 31)
            .base64EncodedString()
        XCTAssertThrowsError(try decode(RelayEndpoint.self, from: shortFingerprint))

        let invalidEndpoints = [
            RelayEndpoint(host: "", port: 443),
            RelayEndpoint(host: "relay.example", port: 0),
            RelayEndpoint(
                host: "relay.example",
                port: 443,
                tlsCertificateFingerprintSHA256: Data(repeating: 0x11, count: 31)
            ),
            RelayEndpoint(
                host: "relay.example",
                port: 443,
                directorySigningPublicKey: Data([0x11])
            )
        ]
        for invalid in invalidEndpoints {
            XCTAssertFalse(invalid.isStructurallyValid)
            XCTAssertThrowsError(try NoctweaveCoder.encode(invalid))
        }
    }

    func testAttachmentRequestsRequireExactFieldsBoundsAndExplicitNulls() throws {
        let upload = UploadAttachmentRequest(
            attachmentId: UUID(),
            chunkIndex: 0,
            payload: makePayload()
        )
        let uploadData = try NoctweaveCoder.encode(upload)
        let uploadObject = try object(uploadData)
        XCTAssertEqual(Set(uploadObject.keys), ["attachmentId", "chunkIndex", "payload", "ttlSeconds"])
        XCTAssertTrue(uploadObject["ttlSeconds"] is NSNull)
        XCTAssertEqual(try NoctweaveCoder.decode(UploadAttachmentRequest.self, from: uploadData), upload)

        var uploadUnknown = uploadObject
        uploadUnknown["legacy"] = true
        XCTAssertThrowsError(try decode(UploadAttachmentRequest.self, from: uploadUnknown))

        var uploadMissing = uploadObject
        uploadMissing.removeValue(forKey: "ttlSeconds")
        XCTAssertThrowsError(try decode(UploadAttachmentRequest.self, from: uploadMissing))

        for (field, value) in [
            ("chunkIndex", -1),
            ("chunkIndex", AttachmentChunk.maximumChunkCount),
            ("ttlSeconds", 59),
            ("ttlSeconds", 2_592_001)
        ] {
            var invalid = uploadObject
            invalid[field] = value
            XCTAssertThrowsError(try decode(UploadAttachmentRequest.self, from: invalid))
        }

        let oversizedPayload = EncryptedPayload(
            nonce: Data(repeating: 0x11, count: EncryptedPayload.nonceByteCount),
            ciphertext: Data(
                repeating: 0x22,
                count: AttachmentChunk.maximumPayloadBytes
                    - EncryptedPayload.nonceByteCount
                    - EncryptedPayload.tagByteCount
                    + 1
            ),
            tag: Data(repeating: 0x33, count: EncryptedPayload.tagByteCount)
        )
        XCTAssertTrue(oversizedPayload.isStructurallyValid)

        let invalidUploads = [
            UploadAttachmentRequest(
                attachmentId: UUID(),
                chunkIndex: -1,
                payload: makePayload()
            ),
            UploadAttachmentRequest(
                attachmentId: UUID(),
                chunkIndex: 0,
                payload: makePayload(),
                ttlSeconds: 59
            ),
            UploadAttachmentRequest(
                attachmentId: UUID(),
                chunkIndex: 0,
                payload: oversizedPayload
            )
        ]
        for invalid in invalidUploads {
            XCTAssertFalse(invalid.isStructurallyValid)
            XCTAssertThrowsError(try NoctweaveCoder.encode(invalid))
            XCTAssertThrowsError(try NoctweaveCoder.encode(RelayRequest.uploadAttachment(invalid)))
        }

        let fetch = FetchAttachmentRequest(attachmentId: UUID(), chunkIndex: 511)
        let fetchData = try NoctweaveCoder.encode(fetch)
        let fetchObject = try object(fetchData)
        XCTAssertEqual(Set(fetchObject.keys), ["attachmentId", "chunkIndex"])
        XCTAssertEqual(try NoctweaveCoder.decode(FetchAttachmentRequest.self, from: fetchData), fetch)

        var fetchUnknown = fetchObject
        fetchUnknown["legacy"] = true
        XCTAssertThrowsError(try decode(FetchAttachmentRequest.self, from: fetchUnknown))

        var fetchMissing = fetchObject
        fetchMissing.removeValue(forKey: "chunkIndex")
        XCTAssertThrowsError(try decode(FetchAttachmentRequest.self, from: fetchMissing))

        for chunkIndex in [-1, AttachmentChunk.maximumChunkCount] {
            let invalid = FetchAttachmentRequest(attachmentId: UUID(), chunkIndex: chunkIndex)
            XCTAssertFalse(invalid.isStructurallyValid)
            XCTAssertThrowsError(try NoctweaveCoder.encode(invalid))
            XCTAssertThrowsError(try NoctweaveCoder.encode(RelayRequest.fetchAttachment(invalid)))
        }
    }

    func testFederationRegistrationRequiresExactNestedValidityAndTTLBounds() throws {
        let registration = FederationNodeRegistrationRequest(
            endpoint: makeEndpoint(),
            relayInfo: makeRelayInfo()
        )
        let encoded = try NoctweaveCoder.encode(registration)
        let base = try object(encoded)
        XCTAssertEqual(Set(base.keys), ["endpoint", "relayInfo", "ttlSeconds"])
        XCTAssertTrue(base["ttlSeconds"] is NSNull)
        XCTAssertEqual(
            try NoctweaveCoder.decode(FederationNodeRegistrationRequest.self, from: encoded),
            registration
        )

        var unknown = base
        unknown["legacy"] = true
        XCTAssertThrowsError(try decode(FederationNodeRegistrationRequest.self, from: unknown))

        var missing = base
        missing.removeValue(forKey: "ttlSeconds")
        XCTAssertThrowsError(try decode(FederationNodeRegistrationRequest.self, from: missing))

        for ttl in [0, 901] {
            var invalid = base
            invalid["ttlSeconds"] = ttl
            XCTAssertThrowsError(try decode(FederationNodeRegistrationRequest.self, from: invalid))
        }

        var invalidInfo = makeRelayInfo()
        invalidInfo.temporalBucketSeconds = 86_401
        let invalidRequests = [
            FederationNodeRegistrationRequest(
                endpoint: RelayEndpoint(host: "", port: 443),
                relayInfo: makeRelayInfo()
            ),
            FederationNodeRegistrationRequest(
                endpoint: makeEndpoint(),
                relayInfo: invalidInfo
            ),
            FederationNodeRegistrationRequest(
                endpoint: makeEndpoint(),
                relayInfo: makeRelayInfo(),
                ttlSeconds: 901
            )
        ]
        for invalid in invalidRequests {
            XCTAssertFalse(invalid.isStructurallyValid)
            XCTAssertThrowsError(try NoctweaveCoder.encode(invalid))
            XCTAssertThrowsError(try NoctweaveCoder.encode(RelayRequest.registerFederationNode(invalid)))
        }
    }

    func testFederationListRequiresExactFieldsBoundsAndExplicitNulls() throws {
        let request = ListFederationNodesRequest()
        let encoded = try NoctweaveCoder.encode(request)
        let base = try object(encoded)
        XCTAssertEqual(
            Set(base.keys),
            ["mode", "federationName", "onlyHealthy", "maxStalenessSeconds", "requireSignedSnapshot"]
        )
        XCTAssertTrue(base.values.allSatisfy { $0 is NSNull })
        XCTAssertEqual(try NoctweaveCoder.decode(ListFederationNodesRequest.self, from: encoded), request)

        var unknown = base
        unknown["legacy"] = true
        XCTAssertThrowsError(try decode(ListFederationNodesRequest.self, from: unknown))

        var missing = base
        missing.removeValue(forKey: "mode")
        XCTAssertThrowsError(try decode(ListFederationNodesRequest.self, from: missing))

        for invalidName in ["", " federation", "federation\n", String(repeating: "é", count: 513)] {
            var invalid = base
            invalid["federationName"] = invalidName
            XCTAssertThrowsError(try decode(ListFederationNodesRequest.self, from: invalid))
        }
        for staleness in [0, 86_401] {
            var invalid = base
            invalid["maxStalenessSeconds"] = staleness
            XCTAssertThrowsError(try decode(ListFederationNodesRequest.self, from: invalid))
        }

        let invalidRequests = [
            ListFederationNodesRequest(federationName: ""),
            ListFederationNodesRequest(federationName: String(repeating: "é", count: 513)),
            ListFederationNodesRequest(maxStalenessSeconds: 0),
            ListFederationNodesRequest(maxStalenessSeconds: 86_401)
        ]
        for invalid in invalidRequests {
            XCTAssertFalse(invalid.isStructurallyValid)
            XCTAssertThrowsError(try NoctweaveCoder.encode(invalid))
            XCTAssertThrowsError(try NoctweaveCoder.encode(RelayRequest.listFederationNodes(invalid)))
        }
    }

    func testRelayRequestRejectsInvalidAuthenticationWhenDecodingAndEncoding() throws {
        let request = RelayRequest.health()
        XCTAssertNoThrow(
            try NoctweaveCoder.encode(
                request.withAuthToken(String(repeating: "x", count: RelayClient.maxAuthenticationBytes))
            )
        )

        let base = try object(NoctweaveCoder.encode(request))
        for token in ["", String(repeating: "x", count: RelayClient.maxAuthenticationBytes + 1)] {
            XCTAssertThrowsError(try NoctweaveCoder.encode(request.withAuthToken(token)))

            var invalid = base
            invalid["authToken"] = token
            XCTAssertThrowsError(try decode(RelayRequest.self, from: invalid))
        }
    }

    private func makeEndpoint(host: String = "relay.example") -> RelayEndpoint {
        RelayEndpoint(host: host, port: 443, useTLS: true, transport: .websocket)
    }

    private func makePayload() -> EncryptedPayload {
        EncryptedPayload(
            nonce: Data(repeating: 0x11, count: EncryptedPayload.nonceByteCount),
            ciphertext: Data([0x22]),
            tag: Data(repeating: 0x33, count: EncryptedPayload.tagByteCount)
        )
    }

    private func makeRelayInfo() -> RelayInfo {
        RelayInfo(
            kind: .standard,
            federation: FederationDescriptor(mode: .manual, name: "example"),
            temporalBucketSeconds: 0,
            advertisedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
    }

    private func object(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func decode<T: Decodable>(_ type: T.Type, from value: [String: Any]) throws -> T {
        try NoctweaveCoder.decode(
            type,
            from: JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        )
    }
}

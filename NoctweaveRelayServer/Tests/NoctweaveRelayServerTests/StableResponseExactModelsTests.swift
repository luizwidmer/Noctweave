import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class StableResponseExactModelsTests: XCTestCase {
    func testRelayInfoAndEveryNestedStableValueRequireExactObjects() throws {
        let endpointA = relayEndpoint(host: "relay-a.example.org")
        let endpointB = relayEndpoint(host: "relay-b.example.org")
        let descriptor = FederationDescriptor(
            mode: .open,
            name: "example-federation",
            description: "Independent relay federation"
        )
        let replicaA = HiddenRetrievalPIRReplica(
            replicaId: "replica-a",
            operatorId: "operator-a",
            endpoint: endpointA
        )
        let replicaB = HiddenRetrievalPIRReplica(
            replicaId: "replica-b",
            operatorId: "operator-b",
            endpoint: endpointB
        )
        let hiddenRetrieval = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            defaultCoverSetSize: 8,
            maxCoverSetSize: 32,
            replicatedXorPIRReplicas: [replicaA, replicaB]
        )
        let openDiscovery = OpenFederationDiscoverySupport(
            dhtNodeEnabled: true,
            peerExchangeEnabled: true,
            peerExchangeLimit: 16,
            requirePublicEndpoint: true,
            maxDHTRecords: 128,
            maxDHTRecordsPerHost: 4,
            maxDHTQueryRecords: 128
        )
        let onion = OnionTransportSupport(
            enabled: true,
            maxHops: 3,
            requiresFixedSizePackets: true
        )
        let mixnet = MixnetTransportSupport(
            enabled: true,
            batchIntervalSeconds: 30,
            minBatchSize: 8,
            coverPacketsPerBatch: 2,
            maxDelaySeconds: 120
        )
        let wake = DecentralizedWakeSupport(
            mode: .longPoll,
            minPollIntervalSeconds: 30,
            maxPollIntervalSeconds: 300,
            jitterPermille: 250,
            longPollTimeoutSeconds: 60
        )
        let module = RelayModuleCapabilityV2(
            module: "nw.core",
            versions: [2],
            status: .stable,
            limits: ["maxPage": 256]
        )
        let manifest = RelayCapabilityManifestV2(modules: [module])

        try assertExactObject(
            descriptor,
            keys: ["mode", "name", "description"],
            missingKey: "description"
        )
        try assertExactObject(
            endpointA,
            keys: [
                "host", "port", "useTLS", "transport",
                "tlsCertificateFingerprintSHA256", "directorySigningPublicKey"
            ],
            missingKey: "directorySigningPublicKey"
        )
        try assertExactObject(
            replicaA,
            keys: ["replicaId", "operatorId", "endpoint"],
            missingKey: "operatorId"
        )
        try assertExactObject(
            hiddenRetrieval,
            keys: [
                "mode", "defaultCoverSetSize", "maxCoverSetSize",
                "replicatedXorPIRReplicas"
            ],
            missingKey: "replicatedXorPIRReplicas"
        )
        try assertExactObject(
            openDiscovery,
            keys: [
                "dhtNodeEnabled", "peerExchangeEnabled", "peerExchangeLimit",
                "requirePublicEndpoint", "maxDHTRecords", "maxDHTRecordsPerHost",
                "maxDHTQueryRecords"
            ],
            missingKey: "peerExchangeLimit"
        )
        try assertExactObject(
            onion,
            keys: ["enabled", "maxHops", "requiresFixedSizePackets"],
            missingKey: "maxHops"
        )
        try assertExactObject(
            mixnet,
            keys: [
                "enabled", "batchIntervalSeconds", "minBatchSize",
                "coverPacketsPerBatch", "maxDelaySeconds"
            ],
            missingKey: "coverPacketsPerBatch"
        )
        try assertExactObject(
            wake,
            keys: [
                "mode", "minPollIntervalSeconds", "maxPollIntervalSeconds",
                "jitterPermille", "longPollTimeoutSeconds"
            ],
            missingKey: "longPollTimeoutSeconds"
        )
        try assertExactObject(
            module,
            keys: ["module", "versions", "status", "limits"],
            missingKey: "limits"
        )
        try assertExactObject(
            manifest,
            keys: ["architectureVersion", "modules"],
            missingKey: "modules"
        )

        let info = RelayInfo(
            kind: .standard,
            federation: descriptor,
            tlsEnabled: true,
            transport: .http,
            temporalBucketSeconds: 300,
            temporalBucketScheduleSeconds: [60, 300],
            attachmentDefaultTTLSeconds: 3_600,
            attachmentMaxTTLSeconds: 21_600,
            attachmentsEnabled: true,
            attachmentStorageBackend: "inline",
            hiddenRetrieval: hiddenRetrieval,
            onionTransport: onion,
            mixnetTransport: mixnet,
            wakeSupport: wake,
            relayName: "Relay A",
            operatorNote: "Self-hosted",
            softwareVersion: "1.0.0",
            protocolCapabilities: manifest,
            requiresPassword: false,
            federationCoordinatorEndpoints: [endpointA],
            coordinatorReportedRelayCount: 2,
            coordinatorRegistrationAuthRequired: false,
            curatedStrictPolicyEnabled: true,
            curatedCoordinatorQuorum: 2,
            curatedRequireSignedDirectory: true,
            federationDirectoryPublicKey: Data(
                repeating: 0x44,
                count: OQSSignatureVerifier.mlDSA65PublicKeyBytes
            ),
            knownOpenPeers: [endpointB],
            openFederationDiscovery: openDiscovery,
            advertisedAt: Date(timeIntervalSince1970: 1_000)
        )
        try assertExactObject(
            info,
            keys: Self.relayInfoKeys,
            missingKey: "wakeSupport"
        )
        try assertNestedRelayInfoRejectsUnknownFields(info)
    }

    func testDefaultRelayInfoWritesEveryOptionalAsExplicitNull() throws {
        let info = RelayConfiguration().makeInfo(
            now: Date(timeIntervalSince1970: 2_000)
        )
        let encoded = try RelayCodec.encoder().encode(info)
        let object = try jsonObject(encoded)

        XCTAssertEqual(Set(object.keys), Self.relayInfoKeys)
        for key in [
            "temporalBucketScheduleSeconds", "attachmentStorageBackend",
            "hiddenRetrieval", "onionTransport", "mixnetTransport", "wakeSupport",
            "relayName", "operatorNote", "softwareVersion",
            "federationCoordinatorEndpoints", "coordinatorReportedRelayCount",
            "coordinatorRegistrationAuthRequired", "curatedStrictPolicyEnabled",
            "curatedCoordinatorQuorum", "curatedRequireSignedDirectory",
            "federationDirectoryPublicKey", "knownOpenPeers", "openFederationDiscovery"
        ] {
            XCTAssertTrue(object[key] is NSNull, "Expected explicit null for \(key)")
        }
        XCTAssertEqual(try RelayCodec.decoder().decode(RelayInfo.self, from: encoded), info)
    }

    func testAttachmentChunkAndFederationDirectoryRequireExactRecursiveObjects() throws {
        let attachment = AttachmentChunk(
            attachmentId: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            chunkIndex: 0,
            payload: EncryptedPayload(
                nonce: Data(repeating: 0x11, count: EncryptedPayload.nonceByteCount),
                ciphertext: Data([0x22]),
                tag: Data(repeating: 0x33, count: EncryptedPayload.tagByteCount)
            )
        )
        try assertExactObject(
            attachment,
            keys: ["attachmentId", "chunkIndex", "payload"],
            missingKey: "chunkIndex"
        )

        let endpoint = relayEndpoint(host: "directory.example.org")
        let relayInfo = RelayConfiguration(
            federation: FederationDescriptor(mode: .curated, name: "curated")
        ).makeInfo(now: Date(timeIntervalSince1970: 3_000))
        let node = FederationNodeRecord(
            endpoint: endpoint,
            relayInfo: relayInfo,
            lastHeartbeatAt: Date(timeIntervalSince1970: 3_000),
            expiresAt: Date(timeIntervalSince1970: 3_300)
        )
        let snapshot = FederationDirectorySnapshot(
            mode: .curated,
            federationName: "curated",
            issuedAt: Date(timeIntervalSince1970: 3_000),
            validUntil: Date(timeIntervalSince1970: 3_300),
            maxStalenessSeconds: 300,
            nodes: [node],
            signatureAlgorithm: FederationDirectorySignature.algorithm,
            signature: Data(
                repeating: 0x55,
                count: OQSSignatureVerifier.mlDSA65SignatureBytes
            )
        )
        try assertExactObject(
            node,
            keys: ["endpoint", "relayInfo", "lastHeartbeatAt", "expiresAt"],
            missingKey: "relayInfo"
        )
        try assertExactObject(
            snapshot,
            keys: [
                "version", "mode", "federationName", "issuedAt", "validUntil",
                "maxStalenessSeconds", "nodes", "signatureAlgorithm", "signature"
            ],
            missingKey: "signature"
        )

        var nestedAttachment = try jsonObject(RelayCodec.encoder().encode(attachment))
        var payload = try XCTUnwrap(nestedAttachment["payload"] as? [String: Any])
        payload["legacy"] = true
        nestedAttachment["payload"] = payload
        XCTAssertThrowsError(try decode(AttachmentChunk.self, object: nestedAttachment))

        var nestedDirectory = try jsonObject(RelayCodec.encoder().encode(snapshot))
        var nodes = try XCTUnwrap(nestedDirectory["nodes"] as? [[String: Any]])
        nodes[0]["legacy"] = true
        nestedDirectory["nodes"] = nodes
        XCTAssertThrowsError(
            try decode(FederationDirectorySnapshot.self, object: nestedDirectory)
        )
    }

    private static let relayInfoKeys: Set<String> = [
        "kind", "federation", "temporalBucketSeconds", "temporalBucketScheduleSeconds",
        "attachmentDefaultTTLSeconds", "attachmentMaxTTLSeconds", "attachmentsEnabled",
        "attachmentStorageBackend", "hiddenRetrieval", "onionTransport", "mixnetTransport",
        "wakeSupport", "relayName", "operatorNote", "softwareVersion",
        "protocolCapabilities", "requiresPassword", "tlsEnabled", "transport",
        "federationCoordinatorEndpoints", "coordinatorReportedRelayCount",
        "coordinatorRegistrationAuthRequired", "curatedStrictPolicyEnabled",
        "curatedCoordinatorQuorum", "curatedRequireSignedDirectory",
        "federationDirectoryPublicKey", "knownOpenPeers", "openFederationDiscovery",
        "advertisedAt"
    ]

    private func relayEndpoint(host: String) -> RelayEndpoint {
        RelayEndpoint(
            host: host,
            port: 443,
            useTLS: true,
            transport: .http,
            tlsCertificateFingerprintSHA256: nil,
            directorySigningPublicKey: nil
        )
    }

    private func assertExactObject<Value: Codable & Equatable>(
        _ value: Value,
        keys: Set<String>,
        missingKey: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let data = try RelayCodec.encoder().encode(value)
        let object = try jsonObject(data)
        XCTAssertEqual(Set(object.keys), keys, file: file, line: line)
        XCTAssertEqual(
            try RelayCodec.decoder().decode(Value.self, from: data),
            value,
            file: file,
            line: line
        )

        var unknown = object
        unknown["legacy"] = true
        XCTAssertThrowsError(
            try decode(Value.self, object: unknown),
            file: file,
            line: line
        )

        var missing = object
        missing.removeValue(forKey: missingKey)
        XCTAssertThrowsError(
            try decode(Value.self, object: missing),
            file: file,
            line: line
        )
    }

    private func assertNestedRelayInfoRejectsUnknownFields(_ value: RelayInfo) throws {
        let data = try RelayCodec.encoder().encode(value)
        let base = try jsonObject(data)

        for nestedKey in [
            "federation", "hiddenRetrieval", "onionTransport", "mixnetTransport",
            "wakeSupport", "protocolCapabilities", "openFederationDiscovery"
        ] {
            var mutated = base
            var nested = try XCTUnwrap(mutated[nestedKey] as? [String: Any])
            nested["legacy"] = true
            mutated[nestedKey] = nested
            XCTAssertThrowsError(try decode(RelayInfo.self, object: mutated))
        }

        var endpointMutation = base
        var peers = try XCTUnwrap(endpointMutation["knownOpenPeers"] as? [[String: Any]])
        peers[0]["legacy"] = true
        endpointMutation["knownOpenPeers"] = peers
        XCTAssertThrowsError(try decode(RelayInfo.self, object: endpointMutation))

        var replicaMutation = base
        var hidden = try XCTUnwrap(replicaMutation["hiddenRetrieval"] as? [String: Any])
        var replicas = try XCTUnwrap(hidden["replicatedXorPIRReplicas"] as? [[String: Any]])
        replicas[0]["legacy"] = true
        hidden["replicatedXorPIRReplicas"] = replicas
        replicaMutation["hiddenRetrieval"] = hidden
        XCTAssertThrowsError(try decode(RelayInfo.self, object: replicaMutation))

        var moduleMutation = base
        var manifest = try XCTUnwrap(moduleMutation["protocolCapabilities"] as? [String: Any])
        var modules = try XCTUnwrap(manifest["modules"] as? [[String: Any]])
        modules[0]["legacy"] = true
        manifest["modules"] = modules
        moduleMutation["protocolCapabilities"] = manifest
        XCTAssertThrowsError(try decode(RelayInfo.self, object: moduleMutation))
    }

    private func jsonObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
    }

    private func decode<Value: Decodable>(
        _ type: Value.Type,
        object: [String: Any]
    ) throws -> Value {
        try RelayCodec.decoder().decode(
            type,
            from: JSONSerialization.data(withJSONObject: object)
        )
    }
}

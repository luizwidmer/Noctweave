import Foundation
import XCTest
@testable import NoctweaveCore

final class RelaySuccessObjectExactnessTests: XCTestCase {
    func testRelayInfoRequiresEveryCurrentFieldAndExplicitNullOptionals() throws {
        let info = makeRelayInfo()
        let object = try encodedObject(info)
        XCTAssertEqual(Set(object.keys), relayInfoKeys)
        for key in relayInfoNullableKeys {
            XCTAssertTrue(object[key] is NSNull, "Expected explicit null for \(key)")
        }
        let federation = try XCTUnwrap(object["federation"] as? [String: Any])
        XCTAssertEqual(Set(federation.keys), ["mode", "name", "description"])
        XCTAssertTrue(federation["name"] is NSNull)
        XCTAssertTrue(federation["description"] is NSNull)
        XCTAssertEqual(try NoctweaveCoder.decode(RelayInfo.self, from: encodedData(object)), info)

        var missing = object
        missing.removeValue(forKey: "wakeSupport")
        assertRejects(RelayInfo.self, object: missing)

        var unknown = object
        unknown["legacy"] = true
        assertRejects(RelayInfo.self, object: unknown)

        var nestedUnknown = object
        var changedFederation = federation
        changedFederation["legacy"] = true
        nestedUnknown["federation"] = changedFederation
        assertRejects(RelayInfo.self, object: nestedUnknown)

        var unboundedText = object
        unboundedText["relayName"] = String(repeating: "x", count: 1_025)
        assertRejects(RelayInfo.self, object: unboundedText)

        var unboundedSchedule = object
        unboundedSchedule["temporalBucketScheduleSeconds"] = Array(1...17)
        assertRejects(RelayInfo.self, object: unboundedSchedule)
    }

    func testRelayInfoNestedSupportAndCapabilitiesAreExactAndBounded() throws {
        let endpoint = makeEndpoint()
        let support = HiddenRetrievalSupport(mode: .coverQuery)
        let supportObject = try encodedObject(support)
        XCTAssertEqual(
            Set(supportObject.keys),
            ["mode", "defaultCoverSetSize", "maxCoverSetSize", "replicatedXorPIRReplicas"]
        )
        XCTAssertTrue(supportObject["replicatedXorPIRReplicas"] is NSNull)

        var hiddenUnknown = supportObject
        hiddenUnknown["legacy"] = true
        assertRejects(HiddenRetrievalSupport.self, object: hiddenUnknown)
        var hiddenMissing = supportObject
        hiddenMissing.removeValue(forKey: "replicatedXorPIRReplicas")
        assertRejects(HiddenRetrievalSupport.self, object: hiddenMissing)
        var hiddenUnbounded = supportObject
        hiddenUnbounded["maxCoverSetSize"] = 4_097
        assertRejects(HiddenRetrievalSupport.self, object: hiddenUnbounded)

        let replica = HiddenRetrievalPIRReplica(
            replicaId: "replica-a",
            operatorId: "operator-a",
            endpoint: endpoint
        )
        var replicaObject = try encodedObject(replica)
        replicaObject["legacy"] = true
        assertRejects(HiddenRetrievalPIRReplica.self, object: replicaObject)

        let openSupport = OpenFederationDiscoverySupport()
        var openObject = try encodedObject(openSupport)
        openObject["maxDHTQueryRecords"] = 513
        assertRejects(OpenFederationDiscoverySupport.self, object: openObject)

        var onionObject = try encodedObject(OnionTransportSupport())
        onionObject["legacy"] = true
        assertRejects(OnionTransportSupport.self, object: onionObject)
        onionObject.removeValue(forKey: "legacy")
        onionObject["maxHops"] = 9
        assertRejects(OnionTransportSupport.self, object: onionObject)

        var mixnetObject = try encodedObject(MixnetTransportSupport())
        mixnetObject.removeValue(forKey: "coverPacketsPerBatch")
        assertRejects(MixnetTransportSupport.self, object: mixnetObject)
        mixnetObject = try encodedObject(MixnetTransportSupport())
        mixnetObject["batchIntervalSeconds"] = 3_601
        assertRejects(MixnetTransportSupport.self, object: mixnetObject)

        let capability = RelayCapabilityManifestV2(modules: [
            RelayModuleCapabilityV2(module: "nw.core", versions: [2], status: .stable)
        ])
        var capabilityObject = try encodedObject(capability)
        var modules = try XCTUnwrap(capabilityObject["modules"] as? [[String: Any]])
        modules[0]["legacy"] = true
        capabilityObject["modules"] = modules
        assertRejects(RelayCapabilityManifestV2.self, object: capabilityObject)

        capabilityObject = try encodedObject(capability)
        capabilityObject["modules"] = (0..<65).map { index in
            [
                "module": index == 0 ? "nw.core" : String(format: "nw.module-%02d", index),
                "versions": index == 0 ? [2] : [1],
                "status": "stable",
                "limits": [:]
            ] as [String: Any]
        }
        assertRejects(RelayCapabilityManifestV2.self, object: capabilityObject)
    }

    func testAttachmentAndFederationSuccessObjectsRejectNestedDrift() throws {
        let payload = EncryptedPayload(
            nonce: Data(repeating: 0x11, count: 12),
            ciphertext: Data([0x22]),
            tag: Data(repeating: 0x33, count: 16)
        )
        let chunk = AttachmentChunk(
            attachmentId: UUID(uuidString: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")!,
            chunkIndex: 7,
            payload: payload
        )
        var chunkObject = try encodedObject(chunk)
        chunkObject["legacy"] = true
        assertRejects(AttachmentChunk.self, object: chunkObject)
        chunkObject = try encodedObject(chunk)
        chunkObject.removeValue(forKey: "payload")
        assertRejects(AttachmentChunk.self, object: chunkObject)
        chunkObject = try encodedObject(chunk)
        chunkObject["chunkIndex"] = AttachmentChunk.maximumChunkCount
        assertRejects(AttachmentChunk.self, object: chunkObject)

        let issuedAt = Date(timeIntervalSince1970: 1_752_840_000)
        let node = FederationNodeRecord(
            endpoint: makeEndpoint(),
            relayInfo: makeRelayInfo(advertisedAt: issuedAt),
            lastHeartbeatAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(60)
        )
        var nodeObject = try encodedObject(node)
        var nestedInfo = try XCTUnwrap(nodeObject["relayInfo"] as? [String: Any])
        nestedInfo["legacy"] = true
        nodeObject["relayInfo"] = nestedInfo
        assertRejects(FederationNodeRecord.self, object: nodeObject)

        let snapshot = FederationDirectorySnapshot(
            mode: .curated,
            federationName: nil,
            issuedAt: issuedAt,
            validUntil: issuedAt.addingTimeInterval(60),
            maxStalenessSeconds: 300,
            nodes: [node]
        )
        let snapshotObject = try encodedObject(snapshot)
        XCTAssertEqual(
            Set(snapshotObject.keys),
            [
                "version", "mode", "federationName", "issuedAt", "validUntil",
                "maxStalenessSeconds", "nodes", "signatureAlgorithm", "signature"
            ]
        )
        XCTAssertTrue(snapshotObject["federationName"] is NSNull)
        XCTAssertTrue(snapshotObject["signatureAlgorithm"] is NSNull)
        XCTAssertTrue(snapshotObject["signature"] is NSNull)

        var snapshotMissing = snapshotObject
        snapshotMissing.removeValue(forKey: "signature")
        assertRejects(FederationDirectorySnapshot.self, object: snapshotMissing)
        var snapshotUnbounded = snapshotObject
        snapshotUnbounded["maxStalenessSeconds"] = 86_401
        assertRejects(FederationDirectorySnapshot.self, object: snapshotUnbounded)

        XCTAssertFalse(
            FederationNodesResponseBody(
                nodes: Array(repeating: node, count: FederationNodesResponseBody.maximumNodes + 1)
            ).isStructurallyValid
        )
    }

    private var relayInfoKeys: Set<String> {
        [
            "kind", "federation", "temporalBucketSeconds", "temporalBucketScheduleSeconds",
            "attachmentDefaultTTLSeconds", "attachmentMaxTTLSeconds", "attachmentsEnabled",
            "attachmentStorageBackend", "hiddenRetrieval", "onionTransport", "mixnetTransport",
            "wakeSupport", "relayName", "operatorNote", "softwareVersion", "protocolCapabilities",
            "requiresPassword", "tlsEnabled", "transport", "federationCoordinatorEndpoints",
            "coordinatorReportedRelayCount", "coordinatorRegistrationAuthRequired",
            "curatedStrictPolicyEnabled", "curatedCoordinatorQuorum", "curatedRequireSignedDirectory",
            "federationDirectoryPublicKey", "knownOpenPeers", "openFederationDiscovery", "advertisedAt"
        ]
    }

    private var relayInfoNullableKeys: Set<String> {
        relayInfoKeys.subtracting(["kind", "federation", "temporalBucketSeconds", "advertisedAt"])
    }

    private func makeRelayInfo(
        advertisedAt: Date = Date(timeIntervalSince1970: 1_752_840_000)
    ) -> RelayInfo {
        RelayInfo(
            kind: .standard,
            federation: FederationDescriptor(mode: .solo),
            temporalBucketSeconds: 300,
            advertisedAt: advertisedAt
        )
    }

    private func makeEndpoint() -> RelayEndpoint {
        RelayEndpoint(host: "relay.example", port: 443, useTLS: true, transport: .http)
    }

    private func encodedObject<T: Encodable>(_ value: T) throws -> [String: Any] {
        let encoded = try NoctweaveCoder.encode(value, sortedKeys: true)
        return try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
    }

    private func encodedData(_ object: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private func assertRejects<T: Decodable>(
        _ type: T.Type,
        object: Any,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try NoctweaveCoder.decode(type, from: encodedData(object)),
            file: file,
            line: line
        )
    }
}

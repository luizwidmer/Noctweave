import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class StableModelBoundsTests: XCTestCase {
    func testAttachmentRequestsRequireExactBoundedCurrentObjects() throws {
        let payload = validPayload()
        let attachmentID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
        let upload = UploadAttachmentRequest(
            attachmentId: attachmentID,
            chunkIndex: 0,
            payload: payload,
            ttlSeconds: nil
        )
        let fetch = FetchAttachmentRequest(attachmentId: attachmentID, chunkIndex: 511)

        try assertExactObject(
            upload,
            keys: ["attachmentId", "chunkIndex", "payload", "ttlSeconds"],
            missingKey: "ttlSeconds"
        )
        let uploadObject = try jsonObject(RelayCodec.encoder().encode(upload))
        XCTAssertTrue(uploadObject["ttlSeconds"] is NSNull)
        try assertExactObject(
            fetch,
            keys: ["attachmentId", "chunkIndex"],
            missingKey: "chunkIndex"
        )

        XCTAssertEqual(AttachmentChunk.maximumChunkCount, 512)
        for invalidIndex in [-1, AttachmentChunk.maximumChunkCount] {
            let invalidUpload = UploadAttachmentRequest(
                attachmentId: attachmentID,
                chunkIndex: invalidIndex,
                payload: payload,
                ttlSeconds: 60
            )
            let invalidFetch = FetchAttachmentRequest(
                attachmentId: attachmentID,
                chunkIndex: invalidIndex
            )
            let invalidChunk = AttachmentChunk(
                attachmentId: attachmentID,
                chunkIndex: invalidIndex,
                payload: payload
            )
            XCTAssertThrowsError(try RelayCodec.encoder().encode(invalidUpload))
            XCTAssertThrowsError(try RelayCodec.encoder().encode(invalidFetch))
            XCTAssertThrowsError(try RelayCodec.encoder().encode(invalidChunk))

            var uploadJSON = uploadObject
            uploadJSON["chunkIndex"] = invalidIndex
            XCTAssertThrowsError(try decode(UploadAttachmentRequest.self, object: uploadJSON))

            var chunkJSON = try jsonObject(
                RelayCodec.encoder().encode(
                    AttachmentChunk(attachmentId: attachmentID, chunkIndex: 0, payload: payload)
                )
            )
            chunkJSON["chunkIndex"] = invalidIndex
            XCTAssertThrowsError(try decode(AttachmentChunk.self, object: chunkJSON))
        }

        for invalidTTL in [59, 2_592_001] {
            let invalid = UploadAttachmentRequest(
                attachmentId: attachmentID,
                chunkIndex: 0,
                payload: payload,
                ttlSeconds: invalidTTL
            )
            XCTAssertThrowsError(try RelayCodec.encoder().encode(invalid))
            var object = uploadObject
            object["ttlSeconds"] = invalidTTL
            XCTAssertThrowsError(try decode(UploadAttachmentRequest.self, object: object))
        }
        let maximumTTL = UploadAttachmentRequest(
            attachmentId: attachmentID,
            chunkIndex: 511,
            payload: payload,
            ttlSeconds: 2_592_000
        )
        XCTAssertEqual(
            try RelayCodec.decoder().decode(
                UploadAttachmentRequest.self,
                from: RelayCodec.encoder().encode(maximumTTL)
            ),
            maximumTTL
        )
    }

    func testFederationAndHiddenRetrievalBoundsMatchCoreAndJS() throws {
        let maximumText = String(repeating: "x", count: 1_024)
        let descriptor = FederationDescriptor(
            mode: .open,
            name: maximumText,
            description: maximumText
        )
        XCTAssertEqual(
            try RelayCodec.decoder().decode(
                FederationDescriptor.self,
                from: RelayCodec.encoder().encode(descriptor)
            ),
            descriptor
        )

        let endpointA = endpoint(host: "replica-a.example.org")
        let endpointB = endpoint(host: "replica-b.example.org")
        let maximumReplica = HiddenRetrievalPIRReplica(
            replicaId: maximumText,
            operatorId: maximumText,
            endpoint: endpointA
        )
        XCTAssertEqual(
            try RelayCodec.decoder().decode(
                HiddenRetrievalPIRReplica.self,
                from: RelayCodec.encoder().encode(maximumReplica)
            ),
            maximumReplica
        )

        let oversizedText = String(repeating: "y", count: 1_025)
        XCTAssertThrowsError(
            try RelayCodec.encoder().encode(
                FederationDescriptor(mode: .open, name: oversizedText)
            )
        )
        XCTAssertThrowsError(
            try RelayCodec.encoder().encode(
                HiddenRetrievalPIRReplica(
                    replicaId: oversizedText,
                    operatorId: "operator",
                    endpoint: endpointA
                )
            )
        )

        let replicaA = HiddenRetrievalPIRReplica(
            replicaId: "replica-a",
            operatorId: "operator-a",
            endpoint: endpointA
        )
        let coverWithoutReplicas = HiddenRetrievalSupport(
            mode: .coverQuery,
            replicatedXorPIRReplicas: nil
        )
        let coverWithOneReplica = HiddenRetrievalSupport(
            mode: .coverQuery,
            replicatedXorPIRReplicas: [replicaA]
        )
        XCTAssertTrue(coverWithoutReplicas.isStructurallyValid)
        XCTAssertTrue(coverWithOneReplica.isStructurallyValid)
        XCTAssertThrowsError(
            try RelayCodec.encoder().encode(
                HiddenRetrievalSupport(
                    mode: .coverQuery,
                    replicatedXorPIRReplicas: []
                )
            )
        )
        XCTAssertThrowsError(
            try RelayCodec.encoder().encode(
                HiddenRetrievalSupport(
                    mode: .replicatedXorPIR,
                    replicatedXorPIRReplicas: [replicaA]
                )
            )
        )

        for duplicates in [
            [
                replicaA,
                HiddenRetrievalPIRReplica(
                    replicaId: "REPLICA-A",
                    operatorId: "operator-b",
                    endpoint: endpointB
                )
            ],
            [
                replicaA,
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "OPERATOR-A",
                    endpoint: endpointB
                )
            ],
            [
                replicaA,
                HiddenRetrievalPIRReplica(
                    replicaId: "replica-b",
                    operatorId: "operator-b",
                    endpoint: endpointA
                )
            ]
        ] {
            XCTAssertThrowsError(
                try RelayCodec.encoder().encode(
                    HiddenRetrievalSupport(
                        mode: .replicatedXorPIR,
                        replicatedXorPIRReplicas: duplicates
                    )
                )
            )
        }

        let maximumReplicas = (0..<256).map { index in
            HiddenRetrievalPIRReplica(
                replicaId: "replica-\(index)",
                operatorId: "operator-\(index)",
                endpoint: endpoint(host: "replica-\(index).example.org")
            )
        }
        let maximumSupport = HiddenRetrievalSupport(
            mode: .replicatedXorPIR,
            replicatedXorPIRReplicas: maximumReplicas
        )
        XCTAssertTrue(maximumSupport.isStructurallyValid)
        let maximumData = try RelayCodec.encoder().encode(maximumSupport)
        XCTAssertEqual(
            try RelayCodec.decoder().decode(HiddenRetrievalSupport.self, from: maximumData),
            maximumSupport
        )

        var oversizedReplicaSet = try jsonObject(maximumData)
        var replicas = try XCTUnwrap(
            oversizedReplicaSet["replicatedXorPIRReplicas"] as? [[String: Any]]
        )
        replicas.append(try XCTUnwrap(replicas.first))
        oversizedReplicaSet["replicatedXorPIRReplicas"] = replicas
        XCTAssertThrowsError(
            try decode(HiddenRetrievalSupport.self, object: oversizedReplicaSet)
        )
    }

    private func validPayload() -> EncryptedPayload {
        EncryptedPayload(
            nonce: Data(repeating: 0x11, count: EncryptedPayload.nonceByteCount),
            ciphertext: Data([0x22]),
            tag: Data(repeating: 0x33, count: EncryptedPayload.tagByteCount)
        )
    }

    private func endpoint(host: String) -> RelayEndpoint {
        RelayEndpoint(host: host, port: 443, useTLS: true, transport: .http)
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

    private func jsonObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
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

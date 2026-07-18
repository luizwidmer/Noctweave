import Foundation
import XCTest
@testable import NoctweaveRelayServer

final class RelayWireStructuralBoundaryTests: XCTestCase {
    func testRelayRequestRejectsInvalidAuthenticationWhenDecodingAndEncoding() throws {
        let request = RelayRequest.health()
        XCTAssertNoThrow(
            try RelayCodec.encoder().encode(
                request.withAuthToken(String(repeating: "x", count: 4_096))
            )
        )

        let base = try object(RelayCodec.encoder().encode(request))
        for token in ["", String(repeating: "x", count: 4_097)] {
            XCTAssertThrowsError(try RelayCodec.encoder().encode(request.withAuthToken(token)))

            var invalid = base
            invalid["authToken"] = token
            XCTAssertThrowsError(try decode(RelayRequest.self, from: invalid))
        }
    }

    func testFederationNodesResponseRejectsRecursiveInvalidityDuplicatesAndExcessCountOnEncode() throws {
        let node = makeNode(host: "relay.example")
        let caseEquivalentNode = makeNode(host: "RELAY.EXAMPLE")
        let duplicateBody = FederationNodesResponseBody(nodes: [node, caseEquivalentNode])
        XCTAssertFalse(duplicateBody.isStructurallyValid)
        XCTAssertThrowsError(try encodeResponse(duplicateBody))

        let oversizedBody = FederationNodesResponseBody(nodes: Array(repeating: node, count: 10_001))
        XCTAssertFalse(oversizedBody.isStructurallyValid)
        XCTAssertThrowsError(try encodeResponse(oversizedBody))

        let invalidNode = FederationNodeRecord(
            endpoint: RelayEndpoint(host: "", port: 443),
            relayInfo: makeRelayInfo(),
            lastHeartbeatAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_700_000_060)
        )
        let recursivelyInvalid = FederationNodesResponseBody(nodes: [invalidNode])
        XCTAssertFalse(recursivelyInvalid.isStructurallyValid)
        XCTAssertThrowsError(try encodeResponse(recursivelyInvalid))
    }

    func testFederationNodesResponseRejectsDuplicateCanonicalEndpointsOnDecode() throws {
        let node = makeNode(host: "relay.example")
        var response = try object(encodeResponse(.init(nodes: [node])))
        var body = try XCTUnwrap(response["body"] as? [String: Any])
        body["nodes"] = [
            try object(RelayCodec.encoder().encode(node)),
            try object(RelayCodec.encoder().encode(makeNode(host: "RELAY.EXAMPLE")))
        ]
        response["body"] = body

        XCTAssertThrowsError(try decode(RelayResponse.self, from: response))
    }

    func testFederationNodesResponseRequiresSnapshotNodesToExactlyMatch() throws {
        let node = makeNode(host: "relay.example")
        let matchingSnapshot = makeSnapshot(nodes: [node])
        let matchingBody = FederationNodesResponseBody(nodes: [node], snapshot: matchingSnapshot)
        XCTAssertTrue(matchingBody.isStructurallyValid)

        let encoded = try encodeResponse(matchingBody)
        XCTAssertNoThrow(try RelayCodec.decodeWire(RelayResponse.self, from: encoded))

        let mismatchedBody = FederationNodesResponseBody(
            nodes: [node],
            snapshot: makeSnapshot(nodes: [])
        )
        XCTAssertFalse(mismatchedBody.isStructurallyValid)
        XCTAssertThrowsError(try encodeResponse(mismatchedBody))

        var response = try object(encoded)
        var body = try XCTUnwrap(response["body"] as? [String: Any])
        var snapshot = try XCTUnwrap(body["snapshot"] as? [String: Any])
        snapshot["nodes"] = [Any]()
        body["snapshot"] = snapshot
        response["body"] = body
        XCTAssertThrowsError(try decode(RelayResponse.self, from: response))
    }

    private func encodeResponse(_ body: FederationNodesResponseBody) throws -> Data {
        try RelayCodec.encoder().encode(
            RelayResponse.success(
                .federationNodes(body),
                respondingTo: .listFederationNodes(ListFederationNodesRequest())
            )
        )
    }

    private func makeNode(host: String) -> FederationNodeRecord {
        FederationNodeRecord(
            endpoint: RelayEndpoint(host: host, port: 443, useTLS: true, transport: .websocket),
            relayInfo: makeRelayInfo(),
            lastHeartbeatAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_700_000_060)
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

    private func makeSnapshot(nodes: [FederationNodeRecord]) -> FederationDirectorySnapshot {
        FederationDirectorySnapshot(
            mode: .manual,
            federationName: "example",
            issuedAt: Date(timeIntervalSince1970: 1_700_000_000),
            validUntil: Date(timeIntervalSince1970: 1_700_000_060),
            maxStalenessSeconds: 60,
            nodes: nodes
        )
    }

    private func object(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func decode<T: Decodable>(_ type: T.Type, from value: [String: Any]) throws -> T {
        try RelayCodec.decodeWire(
            type,
            from: JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        )
    }
}

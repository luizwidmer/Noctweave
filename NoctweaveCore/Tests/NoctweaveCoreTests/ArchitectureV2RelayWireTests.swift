import Foundation
import XCTest
@testable import NoctweaveCore

final class ArchitectureV2RelayWireTests: XCTestCase {
    func testOpaqueRouteLifecycleAcrossRelayWire() async throws {
        let port = UInt16.random(in: 58_100...60_000)
        let endpoint = RelayEndpoint(host: "127.0.0.1", port: port)
        let server = RelayServer(
            store: RelayStore(),
            opaqueRouteStore: OpaqueRouteRelayStoreV2()
        )
        try server.start(host: "127.0.0.1", port: port)
        defer { server.stop() }
        try await Task.sleep(nanoseconds: 200_000_000)

        let client = RelayClient(endpoint: endpoint)
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let payloadKey = OpaqueRoutePayloadKeyV2.generate()
        let issuedAt = Date()
        let policy = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .oneHour,
            quotaBucket: .packets64
        )
        let lease = try OpaqueRouteLeaseV2(
            issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(3_600),
            policy: policy
        )
        let create = try material.makeCreateRequest(
            lease: lease,
            idempotencyKey: .generate()
        )

        let createResponse = try await client.send(.createOpaqueRouteV2(
            CreateOpaqueRouteRelayRequestV2(
                request: create,
                renewCapability: material.renewCapability
            )
        ))
        guard case .opaqueRoute(let created)? = createResponse.successBody else {
            return XCTFail("Expected opaque route create response")
        }
        XCTAssertEqual(created.routeID, material.routeID)

        let sendRoute = try OpaqueSendRouteV2(
            routeID: material.routeID,
            relay: endpoint,
            sendCapability: material.sendCapability,
            payloadKey: payloadKey,
            routeRevision: created.lease.renewalSequence,
            policy: created.lease.policy,
            validFrom: created.lease.issuedAt,
            expiresAt: created.lease.expiresAt,
            state: .active,
            testedAt: created.lease.issuedAt
        )
        let packet = try XCTUnwrap(
            OpaqueRouteSealedBundleV2.seal(
                Data("opaque relay wire".utf8),
                to: sendRoute
            ).packets.first
        )
        let appendResponse = try await client.send(.appendOpaqueRouteV2(
            AppendOpaqueRouteRelayRequestV2(
                packet: packet,
                sendCapability: material.sendCapability
            )
        ))
        guard case .opaqueRouteAppend(let receipt)? = appendResponse.successBody else {
            return XCTFail("Expected opaque route append response")
        }
        XCTAssertEqual(receipt.packetID, packet.packetID)

        let sync = try material.makeSyncRequest(after: nil, limit: 8)
        let syncResponse = try await client.send(.syncOpaqueRouteV2(
            SyncOpaqueRouteRelayRequestV2(
                request: sync,
                readCredential: material.readCredential
            )
        ))
        guard case .opaqueRouteSync(let batch)? = syncResponse.successBody else {
            return XCTFail("Expected opaque route sync response")
        }
        XCTAssertEqual(batch.packets.map(\.packet.packetID), [packet.packetID])

        let commit = try material.makeCommitRequest(cursor: batch.nextCursor)
        let commitResponse = try await client.send(.commitOpaqueRouteV2(
            CommitOpaqueRouteRelayRequestV2(
                request: commit,
                readCredential: material.readCredential
            )
        ))
        guard case .opaqueRouteCommit(let committed)? = commitResponse.successBody else {
            return XCTFail("Expected opaque route commit response")
        }
        XCTAssertTrue(committed.committedCursor.isStructurallyValid)

        let afterCommit = try material.makeSyncRequest(
            after: committed.committedCursor,
            limit: 8
        )
        let afterCommitResponse = try await client.send(.syncOpaqueRouteV2(
            SyncOpaqueRouteRelayRequestV2(
                request: afterCommit,
                readCredential: material.readCredential
            )
        ))
        guard case .opaqueRouteSync(let afterCommitBatch)? = afterCommitResponse.successBody else {
            return XCTFail("Expected post-commit opaque route sync response")
        }
        XCTAssertTrue(afterCommitBatch.packets.isEmpty)

        let renewal = try material.makeRenewRequest(
            current: created,
            newExpiry: created.lease.expiresAt.addingTimeInterval(3_600),
            authorizedAt: Date(),
            idempotencyKey: .generate()
        )
        let renewalResponse = try await client.send(.renewOpaqueRouteV2(
            RenewOpaqueRouteRelayRequestV2(
                request: renewal,
                renewCapability: material.renewCapability
            )
        ))
        guard case .opaqueRoute(let renewed)? = renewalResponse.successBody else {
            return XCTFail("Expected opaque route renewal response")
        }
        XCTAssertEqual(renewed.lease.renewalSequence, 1)

        let teardown = try material.makeTeardownRequest(
            current: renewed,
            authorizedAt: Date(),
            idempotencyKey: .generate()
        )
        let teardownResponse = try await client.send(.teardownOpaqueRouteV2(
            TeardownOpaqueRouteRelayRequestV2(
                request: teardown,
                teardownCapability: material.teardownCapability
            )
        ))
        guard case .opaqueRoute(let tornDown)? = teardownResponse.successBody else {
            return XCTFail("Expected opaque route teardown response")
        }
        XCTAssertEqual(tornDown.status, .tornDown)
    }
}

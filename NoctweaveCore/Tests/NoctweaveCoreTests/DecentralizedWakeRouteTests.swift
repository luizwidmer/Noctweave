import Foundation
import XCTest
@testable import NoctweaveCore

final class DecentralizedWakeRouteTests: XCTestCase {
    private let origin = Date(timeIntervalSince1970: 300_000)

    func testWakeSupportNormalizesAtConstructionAndRejectsNoncanonicalWireValues() throws {
        let support = DecentralizedWakeSupport(
            mode: .longPoll,
            minPollIntervalSeconds: 1,
            maxPollIntervalSeconds: 10,
            jitterPermille: 2_000,
            longPollTimeoutSeconds: 100
        )
        XCTAssertEqual(support.minPollIntervalSeconds, 5)
        XCTAssertEqual(support.maxPollIntervalSeconds, 10)
        XCTAssertEqual(support.jitterPermille, 1_000)
        XCTAssertEqual(support.longPollTimeoutSeconds, 10)

        let encoded = try NoctweaveCoder.encode(support, sortedKeys: true)
        XCTAssertEqual(try NoctweaveCoder.decode(DecentralizedWakeSupport.self, from: encoded), support)

        var unknown = try jsonObject(encoded)
        unknown["futureAuthority"] = true
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            DecentralizedWakeSupport.self,
            from: try jsonData(unknown)
        ))

        var noncanonical = try jsonObject(encoded)
        noncanonical["minPollIntervalSeconds"] = 1
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            DecentralizedWakeSupport.self,
            from: try jsonData(noncanonical)
        ))
    }

    func testWakeJitterIsDeterministicAndRouteScoped() {
        let support = DecentralizedWakeSupport(
            mode: .pullOnly,
            minPollIntervalSeconds: 60,
            maxPollIntervalSeconds: 120,
            jitterPermille: 1_000
        )
        let now = Date(timeIntervalSince1970: 360_000)
        let plans = (1...16).map { value in
            DecentralizedWakePlanner.makePlan(
                support: support,
                routeID: routeID(value),
                routeJitterSeed: Data(repeating: UInt8(32 + value), count: 32),
                relayIdentifier: "wss://relay.example/opaque",
                now: now
            )
        }
        XCTAssertGreaterThan(Set(plans.map(\.nextPollDelaySeconds)).count, 1)
        XCTAssertTrue(plans.allSatisfy { (60...120).contains($0.nextPollDelaySeconds) })

        let repeated = DecentralizedWakePlanner.makePlan(
            support: support,
            routeID: routeID(1),
            routeJitterSeed: Data(repeating: 33, count: 32),
            relayIdentifier: "wss://relay.example/opaque",
            now: now
        )
        XCTAssertEqual(repeated, plans[0])

        let nonfinite = DecentralizedWakePlanner.makePlan(
            support: support,
            routeID: routeID(1),
            routeJitterSeed: Data(repeating: 33, count: 32),
            relayIdentifier: "wss://relay.example/opaque",
            now: Date(timeIntervalSince1970: .infinity)
        )
        XCTAssertTrue(nonfinite.isStructurallyValid)
    }

    func testCycleDeduplicatesRoutesAndHealthyRouteIsNotDelayedByBackoff() throws {
        let healthySupport = DecentralizedWakeSupport(
            minPollIntervalSeconds: 30,
            maxPollIntervalSeconds: 600,
            jitterPermille: 0
        )
        let healthy = DecentralizedWakeRoute(
            support: healthySupport,
            routeID: routeID(1),
            routeJitterSeed: Data(repeating: 1, count: 32),
            relayIdentifier: "relay-a",
            failureCount: 0
        )
        let duplicateBackedOff = DecentralizedWakeRoute(
            support: healthySupport,
            routeID: routeID(1),
            routeJitterSeed: Data(repeating: 2, count: 32),
            relayIdentifier: "relay-a",
            failureCount: 5
        )
        let backedOff = DecentralizedWakeRoute(
            support: healthySupport,
            routeID: routeID(2),
            routeJitterSeed: Data(repeating: 3, count: 32),
            relayIdentifier: "relay-b",
            failureCount: 4
        )
        let localDefault = DecentralizedWakeRoute(
            support: nil,
            routeID: routeID(3),
            routeJitterSeed: Data(repeating: 4, count: 32),
            relayIdentifier: "relay-c"
        )

        let cycle = DecentralizedWakePlanner.makeCyclePlan(
            for: [duplicateBackedOff, backedOff, localDefault, healthy],
            defaultDelaySeconds: 45,
            maxDelaySeconds: 600,
            now: origin
        )
        XCTAssertEqual(cycle.routePlans.count, 3)
        XCTAssertEqual(cycle.nextPollDelaySeconds, 30)
        XCTAssertEqual(
            try XCTUnwrap(cycle.routePlans.first { $0.routeID == healthy.routeID })
                .plan.failureBackoffStep,
            0
        )
        XCTAssertEqual(
            try XCTUnwrap(cycle.routePlans.first { $0.routeID == localDefault.routeID })
                .plan.nextPollDelaySeconds,
            45
        )
    }

    func testExecutionPlannerBoundsRoutesAndPackets() {
        let plans = [
            DecentralizedWakeRoutePlan(
                routeID: routeID(1),
                relayIdentifier: "relay-a",
                plan: DecentralizedWakePlan(
                    nextPollDelaySeconds: 5,
                    longPollTimeoutSeconds: 5,
                    failureBackoffStep: 0
                )
            ),
            DecentralizedWakeRoutePlan(
                routeID: routeID(2),
                relayIdentifier: "relay-b",
                plan: DecentralizedWakePlan(
                    nextPollDelaySeconds: 10,
                    longPollTimeoutSeconds: nil,
                    failureBackoffStep: 0
                )
            ),
            DecentralizedWakeRoutePlan(
                routeID: routeID(3),
                relayIdentifier: "relay-c",
                plan: DecentralizedWakePlan(
                    nextPollDelaySeconds: 20,
                    longPollTimeoutSeconds: nil,
                    failureBackoffStep: 0
                )
            ),
        ]
        let cycle = DecentralizedWakeCyclePlan(
            routePlans: plans,
            nextPollDelaySeconds: 5,
            longPollTimeoutSeconds: 5
        )
        let execution = DecentralizedPrefetchExecutionPlanner.makePlan(
            from: cycle,
            policy: DecentralizedPrefetchExecutionPolicy(
                maxRoutesPerCycle: 2,
                maxPacketsPerPullRoute: 3,
                maxPacketsPerLongPollRoute: 4,
                maxTotalPacketsPerCycle: 5
            )
        )
        XCTAssertEqual(execution.routeExecutions.count, 2)
        XCTAssertEqual(execution.routeExecutions.map(\.maxPacketCount), [4, 1])
        XCTAssertEqual(execution.maxTotalPacketCount, 5)
    }

    func testOpaqueRouteSyncStagesCiphertextAndDefersCursorCommit() async throws {
        let fixture = try await makeSyncFixture(payload: Data("staged secret".utf8))
        let stagedAt = origin.addingTimeInterval(20)
        let batch = try DecentralizedPrefetchStager.stageOpaqueRouteBatch(
            fixture.sync,
            routeID: fixture.material.routeID,
            relayIdentifier: "wss://relay.example/opaque",
            fetchedAfter: nil,
            stagedAt: stagedAt
        )

        XCTAssertEqual(batch.routeID, fixture.material.routeID)
        XCTAssertEqual(batch.deferredCommitCursor, fixture.sync.nextCursor)
        XCTAssertEqual(batch.highWatermark, fixture.sync.highWatermark)
        XCTAssertEqual(batch.startsAfterSequence, fixture.sync.startsAfterSequence)
        XCTAssertEqual(batch.startsAfterRecordDigest, fixture.sync.startsAfterRecordDigest)
        XCTAssertEqual(batch.nextSequence, fixture.sync.nextSequence)
        XCTAssertEqual(batch.nextRecordDigest, fixture.sync.nextRecordDigest)
        XCTAssertEqual(batch.highWatermarkSequence, fixture.sync.highWatermarkSequence)
        XCTAssertEqual(batch.retentionFloorSequence, fixture.sync.retentionFloorSequence)
        XCTAssertEqual(batch.records.map(\.envelopeID), fixture.sync.packets.map(\.packet.packetID))
        XCTAssertTrue(batch.records.allSatisfy(\.isStructurallyValid))
        XCTAssertFalse(batch.records[0].sealedPacketEnvelope.containsBytes(Data("staged secret".utf8)))

        let encoded = try NoctweaveCoder.encode(batch, sortedKeys: true)
        XCTAssertEqual(
            Set(try jsonObject(encoded).keys),
            [
                "version", "routeID", "relayIdentifier", "records", "fetchedAfter",
                "startsAfterSequence", "startsAfterRecordDigest", "nextSequence",
                "nextRecordDigest", "highWatermarkSequence", "retentionFloorSequence",
                "deferredCommitCursor", "highWatermark", "retentionFloor", "hasMore",
                "stagedAt",
            ]
        )
    }

    func testStagerRejectsPacketsForAnotherRoute() async throws {
        let fixture = try await makeSyncFixture(payload: Data("opaque".utf8))
        XCTAssertThrowsError(try DecentralizedPrefetchStager.stageOpaqueRouteBatch(
            fixture.sync,
            routeID: routeID(99),
            relayIdentifier: "relay.example",
            fetchedAfter: nil,
            stagedAt: origin.addingTimeInterval(20)
        )) { error in
            XCTAssertEqual(error as? DecentralizedPrefetchError, .invalidRouteBatch)
        }
    }

    func testPrefetchBatchWireIsExactAndRejectsCorruptSealedPacket() async throws {
        let fixture = try await makeSyncFixture(payload: Data("opaque".utf8))
        let batch = try DecentralizedPrefetchStager.stageOpaqueRouteBatch(
            fixture.sync,
            routeID: fixture.material.routeID,
            relayIdentifier: "relay.example",
            fetchedAfter: nil,
            stagedAt: origin.addingTimeInterval(20)
        )
        let encoded = try NoctweaveCoder.encode(batch, sortedKeys: true)
        var unknown = try jsonObject(encoded)
        unknown["legacyState"] = true
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            DecentralizedPrefetchBatch.self,
            from: try jsonData(unknown)
        ))

        var corrupt = try jsonObject(encoded)
        var records = try XCTUnwrap(corrupt["records"] as? [[String: Any]])
        records[0]["sealedPacketEnvelope"] = Data("not an opaque packet".utf8).base64EncodedString()
        corrupt["records"] = records
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            DecentralizedPrefetchBatch.self,
            from: try jsonData(corrupt)
        ))

        var brokenChain = try jsonObject(encoded)
        brokenChain["nextRecordDigest"] = Data(repeating: 0xA5, count: 32)
            .base64EncodedString()
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            DecentralizedPrefetchBatch.self,
            from: try jsonData(brokenChain)
        ))
    }

    func testEncryptedBatchStoreHidesMetadataAndRejectsWrongKey() async throws {
        let fixture = try await makeSyncFixture(payload: Data("locally protected secret".utf8))
        let batch = try DecentralizedPrefetchStager.stageOpaqueRouteBatch(
            fixture.sync,
            routeID: fixture.material.routeID,
            relayIdentifier: "private-relay-label",
            fetchedAfter: nil,
            stagedAt: origin.addingTimeInterval(20)
        )
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-route-prefetch-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("batch.json")
        let store = try DecentralizedPrefetchBatchStore(
            fileURL: file,
            protectionKey: Data(repeating: 7, count: 32)
        )
        try await store.save(batch)

        let raw = try Data(contentsOf: file)
        XCTAssertFalse(raw.containsBytes(Data("private-relay-label".utf8)))
        XCTAssertFalse(raw.containsBytes(Data("locally protected secret".utf8)))
        let loaded = try await store.load()
        XCTAssertEqual(loaded, batch)

        let wrongKeyStore = try DecentralizedPrefetchBatchStore(
            fileURL: file,
            protectionKey: Data(repeating: 8, count: 32)
        )
        do {
            _ = try await wrongKeyStore.load()
            XCTFail("A different local protection key must not open the staged batch")
        } catch {
            XCTAssertEqual(error as? DecentralizedPrefetchError, .invalidStoredBatch)
        }

        try await store.remove()
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }

    func testRelayInfoRoundTripPreservesWakeSupport() throws {
        let support = DecentralizedWakeSupport(
            mode: .longPoll,
            minPollIntervalSeconds: 30,
            maxPollIntervalSeconds: 180,
            jitterPermille: 300,
            longPollTimeoutSeconds: 45
        )
        let info = RelayInfo(
            kind: .standard,
            federation: FederationDescriptor(mode: .solo),
            temporalBucketSeconds: 60,
            wakeSupport: support,
            advertisedAt: origin
        )
        XCTAssertEqual(
            try NoctweaveCoder.decode(
                RelayInfo.self,
                from: NoctweaveCoder.encode(info, sortedKeys: true)
            ).wakeSupport,
            support
        )
    }

    private struct SyncFixture {
        let material: OpaqueRouteClientCapabilityMaterialV2
        let sync: OpaqueRouteSyncResponseV2
    }

    private func makeSyncFixture(payload: Data) async throws -> SyncFixture {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        let policy = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .oneHour,
            quotaBucket: .packets64
        )
        let lease = try OpaqueRouteLeaseV2(
            issuedAt: origin,
            expiresAt: origin.addingTimeInterval(7_200),
            policy: policy
        )
        let create = try material.makeCreateRequest(
            lease: lease,
            idempotencyKey: .generate()
        )
        let store = OpaqueRouteRelayStoreV2()
        let receiveRoute = try await store.create(
            create,
            presentedCapability: material.renewCapability,
            confidentialTransport: true,
            receivedAt: origin
        )
        let sendRoute = try OpaqueSendRouteV2(
            routeID: material.routeID,
            relay: RelayEndpoint(
                host: "relay.example",
                port: 443,
                useTLS: true,
                transport: .websocket
            ),
            sendCapability: material.sendCapability,
            payloadKey: .generate(),
            routeRevision: receiveRoute.lease.renewalSequence,
            policy: receiveRoute.lease.policy,
            validFrom: receiveRoute.lease.issuedAt,
            expiresAt: receiveRoute.lease.expiresAt,
            state: .active,
            testedAt: receiveRoute.lease.issuedAt
        )
        let bundle = try OpaqueRouteSealedBundleV2.seal(
            payload,
            to: sendRoute,
            authorizedAt: origin.addingTimeInterval(10)
        )
        for packet in bundle.packets {
            _ = try await store.append(
                packet,
                presentedCapability: material.sendCapability,
                confidentialTransport: true,
                receivedAt: origin.addingTimeInterval(10)
            )
        }
        let request = try material.makeSyncRequest(
            after: nil,
            limit: UInt16(bundle.packets.count),
            authorizedAt: origin.addingTimeInterval(11)
        )
        return SyncFixture(
            material: material,
            sync: try await store.sync(
                request,
                presentedCredential: material.readCredential,
                confidentialTransport: true,
                receivedAt: origin.addingTimeInterval(11)
            )
        )
    }

    private func routeID(_ byte: Int) -> OpaqueReceiveRouteIDV2 {
        OpaqueReceiveRouteIDV2(rawValue: Data(repeating: UInt8(byte), count: 32))
    }

    private func jsonObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func jsonData(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
}

private extension Data {
    func containsBytes(_ candidate: Data) -> Bool {
        guard !candidate.isEmpty, candidate.count <= count else { return false }
        for start in 0...(count - candidate.count) {
            if self[start..<(start + candidate.count)] == candidate[...] {
                return true
            }
        }
        return false
    }
}

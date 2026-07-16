import Foundation
import XCTest
@testable import NoctweaveCore

final class RendezvousRelayTransportTests: XCTestCase {
    func testHandlerIsDefaultOffAndAllowsExplicitLoopbackDevelopment() async throws {
        let now = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
        let fixture = makeFixture(now: now)
        let disabledStore = RelayStore()
        let disabledServer = RelayServer(store: disabledStore)
        let disabledPort = UInt16.random(in: 48_100...49_000)
        let disabledStarted = expectation(description: "disabled rendezvous relay started")
        disabledServer.onEvent = { event in
            if case .started = event { disabledStarted.fulfill() }
        }
        try disabledServer.start(host: "127.0.0.1", port: disabledPort)
        defer { disabledServer.stop() }
        await fulfillment(of: [disabledStarted], timeout: 2)
        let disabledResponse = try await RelayClient(
            endpoint: RelayEndpoint(host: "127.0.0.1", port: disabledPort)
        ).send(.registerRendezvousTransportV2(fixture.registration))
        XCTAssertEqual(disabledResponse.error, "Rendezvous transport is disabled")

        let enabledStore = RelayStore()
        let enabledServer = RelayServer(
            store: enabledStore,
            configuration: RelayConfiguration(rendezvousTransportEnabled: true)
        )
        var enabledPort = UInt16.random(in: 49_100...50_000)
        while enabledPort == disabledPort {
            enabledPort = UInt16.random(in: 49_100...50_000)
        }
        let enabledStarted = expectation(description: "enabled rendezvous relay started")
        enabledServer.onEvent = { event in
            if case .started = event { enabledStarted.fulfill() }
        }
        try enabledServer.start(host: "127.0.0.1", port: enabledPort)
        defer { enabledServer.stop() }
        await fulfillment(of: [enabledStarted], timeout: 2)
        let enabledResponse = try await RelayClient(
            endpoint: RelayEndpoint(host: "127.0.0.1", port: enabledPort)
        ).send(.registerRendezvousTransportV2(fixture.registration))
        XCTAssertEqual(enabledResponse.type, .ok)
    }

    func testWireShapeIsIdentityBlindBoundedAndDefaultOff() throws {
        let now = canonical(2_000_000_000)
        let fixture = makeFixture(now: now)
        let encoded = try NoctweaveCoder.encode(fixture.registration, sortedKeys: true)
        let json = try XCTUnwrap(String(data: encoded, encoding: .utf8)?.lowercased())

        for forbidden in ["purpose", "generation", "identity", "endpoint", "inbox", "provider", "contact"] {
            XCTAssertFalse(json.contains(forbidden), "relay registration leaked \(forbidden)")
        }
        XCTAssertFalse(RelayConfiguration().isRendezvousTransportEnabled)
        XCTAssertFalse(
            try XCTUnwrap(RelayConfiguration().makeInfo().protocolCapabilities)
                .supports(module: "nw.rendezvous-transport", version: 2)
        )
        XCTAssertTrue(
            try XCTUnwrap(
                RelayConfiguration(rendezvousTransportEnabled: true)
                    .makeInfo()
                    .protocolCapabilities
            ).supports(module: "nw.rendezvous-transport", version: 2)
        )

        let reusedAuthority = RendezvousRelayPublishCapabilityV2(
            rawValue: fixture.route.rawValue
        )
        let invalid = RegisterRendezvousTransportV2Request(
            routeCapability: fixture.route,
            expiresAt: now.addingTimeInterval(60),
            lanes: [
                RendezvousRelayLaneRegistrationV2(
                    laneId: fixture.lanes[0].laneId,
                    publishCapability: reusedAuthority,
                    readCapability: fixture.lanes[0].readCapability,
                    deleteCapability: fixture.lanes[0].deleteCapability
                ),
                fixture.lanes[1]
            ]
        )
        XCTAssertFalse(invalid.isStructurallyValid(at: now))
        XCTAssertFalse(
            RegisterRendezvousTransportV2Request(
                routeCapability: fixture.route,
                expiresAt: now.addingTimeInterval(601),
                lanes: fixture.lanes
            ).isStructurallyValid(at: now)
        )
    }

    func testAppendSyncAuthoritySeparationAndExactIdempotence() async throws {
        let now = canonical(2_000_000_000)
        let fixture = makeFixture(now: now)
        let store = RelayStore(temporalBucketSeconds: 0)
        try await store.registerRendezvousTransportV2(fixture.registration, now: now)

        let first = frame(marker: 0x41, sequence: 1)
        let append = AppendRendezvousTransportV2Request(
            routeCapability: fixture.route,
            laneId: fixture.lanes[0].laneId,
            publishCapability: fixture.lanes[0].publishCapability,
            frame: first
        )
        let firstAppendSequence = try await store.appendRendezvousTransportV2(append, now: now)
        let replayAppendSequence = try await store.appendRendezvousTransportV2(append, now: now)
        XCTAssertEqual(firstAppendSequence, 1)
        XCTAssertEqual(replayAppendSequence, 1)

        let batch = try await store.syncRendezvousTransportV2(
            SyncRendezvousTransportV2Request(
                routeCapability: fixture.route,
                laneId: fixture.lanes[0].laneId,
                readCapability: fixture.lanes[0].readCapability
            ),
            now: now
        )
        XCTAssertEqual(batch.frames, [first])
        XCTAssertEqual(batch.highWatermark, 1)
        XCTAssertFalse(batch.hasMore)

        await assertStoreError(.rendezvousRouteUnavailable) {
            _ = try await store.syncRendezvousTransportV2(
                SyncRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    laneId: fixture.lanes[0].laneId,
                    readCapability: fixture.lanes[1].readCapability
                ),
                now: now
            )
        }
        await assertStoreError(.rendezvousSequenceGap) {
            _ = try await store.appendRendezvousTransportV2(
                AppendRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    laneId: fixture.lanes[0].laneId,
                    publishCapability: fixture.lanes[0].publishCapability,
                    frame: self.frame(marker: 0x42, sequence: 3)
                ),
                now: now
            )
        }
        await assertStoreError(.rendezvousFrameConflict) {
            _ = try await store.appendRendezvousTransportV2(
                AppendRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    laneId: fixture.lanes[0].laneId,
                    publishCapability: fixture.lanes[0].publishCapability,
                    frame: RendezvousRelayCiphertextFrameV2(
                        frameId: first.frameId,
                        sequence: 1,
                        ciphertext: Data(repeating: 0x43, count: 4_096)
                    )
                ),
                now: now
            )
        }

        XCTAssertFalse(
            RendezvousRelayCiphertextFrameV2(
                frameId: .generate(),
                sequence: 2,
                ciphertext: Data(repeating: 0x44, count: 8_192)
            ).isStructurallyValid
        )
    }

    func testReplayAndNonResurrectionSurviveRestartWithoutPersistingBearers() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-rendezvous-core-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("relay.sqlite")
        let now = canonical(2_000_000_000)
        let fixture = makeFixture(now: now)
        let first = frame(marker: 0x51, sequence: 1)
        let append = AppendRendezvousTransportV2Request(
            routeCapability: fixture.route,
            laneId: fixture.lanes[1].laneId,
            publishCapability: fixture.lanes[1].publishCapability,
            frame: first
        )

        let store = RelayStore(storeURL: storeURL, temporalBucketSeconds: 0)
        try await store.registerRendezvousTransportV2(fixture.registration, now: now)
        _ = try await store.appendRendezvousTransportV2(append, now: now)
        try await store.deleteRendezvousTransportV2(
            DeleteRendezvousTransportV2Request(
                routeCapability: fixture.route,
                laneId: fixture.lanes[0].laneId,
                deleteCapability: fixture.lanes[0].deleteCapability
            ),
            now: now
        )

        let sqlite = try Data(contentsOf: storeURL)
        let rawBearers = [fixture.route.rawValue] + fixture.lanes.flatMap {
            [
                $0.publishCapability.rawValue,
                $0.readCapability.rawValue,
                $0.deleteCapability.rawValue
            ]
        }
        for bearer in rawBearers {
            XCTAssertNil(sqlite.range(of: bearer), "raw rendezvous bearer was persisted")
        }

        let reloaded = RelayStore(storeURL: storeURL, temporalBucketSeconds: 0)
        try await reloaded.loadFromDisk()
        // A lost successful registration response can be retried exactly,
        // including after restart, without allocating or mutating state.
        try await reloaded.registerRendezvousTransportV2(fixture.registration, now: now)
        await assertStoreError(.rendezvousRegistrationConflict) {
            try await reloaded.registerRendezvousTransportV2(
                RegisterRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    expiresAt: fixture.registration.expiresAt.addingTimeInterval(1),
                    lanes: fixture.lanes
                ),
                now: now
            )
        }
        let replaySequence = try await reloaded.appendRendezvousTransportV2(append, now: now)
        XCTAssertEqual(replaySequence, 1)
        await assertStoreError(.rendezvousRouteUnavailable) {
            _ = try await reloaded.syncRendezvousTransportV2(
                SyncRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    laneId: fixture.lanes[0].laneId,
                    readCapability: fixture.lanes[0].readCapability
                ),
                now: now
            )
        }
        try await reloaded.deleteRendezvousTransportV2(
            DeleteRendezvousTransportV2Request(
                routeCapability: fixture.route,
                laneId: fixture.lanes[1].laneId,
                deleteCapability: fixture.lanes[1].deleteCapability
            ),
            now: now
        )
        // An exact delete retry is idempotent even after the route is retired.
        try await reloaded.deleteRendezvousTransportV2(
            DeleteRendezvousTransportV2Request(
                routeCapability: fixture.route,
                laneId: fixture.lanes[1].laneId,
                deleteCapability: fixture.lanes[1].deleteCapability
            ),
            now: now
        )
        await assertStoreError(.rendezvousRouteUnavailable) {
            try await reloaded.registerRendezvousTransportV2(
                RegisterRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    expiresAt: now.addingTimeInterval(500),
                    lanes: fixture.lanes
                ),
                now: now
            )
        }

        let tombstoneReload = RelayStore(storeURL: storeURL, temporalBucketSeconds: 0)
        try await tombstoneReload.loadFromDisk()
        await assertStoreError(.rendezvousRouteUnavailable) {
            try await tombstoneReload.registerRendezvousTransportV2(
                RegisterRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    expiresAt: now.addingTimeInterval(500),
                    lanes: fixture.lanes
                ),
                now: now
            )
        }
    }

    func testExpiryCreatesPersistentNonResurrectionTombstone() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("noctweave-rendezvous-expiry-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeURL = directory.appendingPathComponent("relay.sqlite")
        let now = canonical(2_000_000_000)
        let fixture = makeFixture(now: now, lifetime: 10)
        let store = RelayStore(storeURL: storeURL, temporalBucketSeconds: 0)
        try await store.registerRendezvousTransportV2(fixture.registration, now: now)
        await assertStoreError(.rendezvousRouteUnavailable) {
            _ = try await store.syncRendezvousTransportV2(
                SyncRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    laneId: fixture.lanes[0].laneId,
                    readCapability: fixture.lanes[0].readCapability
                ),
                now: now.addingTimeInterval(10)
            )
        }
        let reloaded = RelayStore(storeURL: storeURL, temporalBucketSeconds: 0)
        try await reloaded.loadFromDisk()
        await assertStoreError(.rendezvousRouteUnavailable) {
            try await reloaded.registerRendezvousTransportV2(
                RegisterRendezvousTransportV2Request(
                    routeCapability: fixture.route,
                    expiresAt: now.addingTimeInterval(300),
                    lanes: fixture.lanes
                ),
                now: now.addingTimeInterval(20)
            )
        }
    }

    private func canonical(_ seconds: TimeInterval) -> Date {
        Date(timeIntervalSince1970: floor(seconds))
    }

    private func makeFixture(
        now: Date,
        lifetime: TimeInterval = 300
    ) -> (
        route: RendezvousRelayRouteCapabilityV2,
        lanes: [RendezvousRelayLaneRegistrationV2],
        registration: RegisterRendezvousTransportV2Request
    ) {
        let route = RendezvousRelayRouteCapabilityV2.generate()
        let lanes = (0..<2).map { _ in
            RendezvousRelayLaneRegistrationV2(
                laneId: .generate(),
                publishCapability: .generate(),
                readCapability: .generate(),
                deleteCapability: .generate()
            )
        }
        return (
            route,
            lanes,
            RegisterRendezvousTransportV2Request(
                routeCapability: route,
                expiresAt: now.addingTimeInterval(lifetime),
                lanes: lanes
            )
        )
    }

    private func frame(marker: UInt8, sequence: UInt64) -> RendezvousRelayCiphertextFrameV2 {
        RendezvousRelayCiphertextFrameV2(
            frameId: .generate(),
            sequence: sequence,
            ciphertext: Data(repeating: marker, count: 4_096)
        )
    }

    private func assertStoreError(
        _ expected: RelayStoreError,
        operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            XCTFail("Expected \(expected)")
        } catch let error as RelayStoreError {
            XCTAssertEqual(error, expected)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}

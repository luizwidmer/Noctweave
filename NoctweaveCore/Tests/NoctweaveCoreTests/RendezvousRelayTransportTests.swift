import Foundation
import XCTest
@testable import NoctweaveCore

final class RendezvousRelayTransportTests: XCTestCase {
    func testInvitationCapabilityDerivesEncryptedDirectionalRelayTransport() throws {
        let now = canonical(2_000_000_000)
        let expiresAt = now.addingTimeInterval(300)
        let transportCapability = try RendezvousTransportCapabilityV2.generate(
            expiresAt: expiresAt
        )
        var pending = try PendingRendezvousOfferV2.create(
            transportCapability: transportCapability,
            createdAt: now
        )
        let opened = try RendezvousResponderV2.createOpen(
            for: pending.offer,
            redemptionSecret: pending.redemptionSecret(),
            at: now
        )
        var responderSession = opened.session
        var ledger = RendezvousRedemptionLedgerV2()
        var offererSession = try pending.accept(opened.request, ledger: &ledger, at: now)

        let offererAdapter = try RendezvousRelayAdapterV2(offer: pending.offer)
        let responderAdapter = try RendezvousRelayAdapterV2(offer: pending.offer)
        XCTAssertEqual(offererAdapter, responderAdapter)
        XCTAssertTrue(offererAdapter.registrationRequest.isStructurallyValid(at: now))
        XCTAssertEqual(
            offererAdapter.syncRequest(receivingAs: .offerer).laneId,
            responderAdapter.responderToOfferer.registration.laneId
        )

        let sealedOpen = try responderAdapter.sealOpen(opened.request)
        XCTAssertEqual(sealedOpen.frame.sequence, 1)
        XCTAssertEqual(sealedOpen.frame.ciphertext.count, 4_096)
        guard case .open(let decodedOpen) = try offererAdapter.open(
            sealedOpen.frame,
            direction: .responderToOfferer
        ) else {
            return XCTFail("Expected rendezvous open")
        }
        XCTAssertEqual(decodedOpen, opened.request)

        let acceptance = try responderSession.seal(
            Data("relationship-scoped introduction".utf8),
            kind: .contactAcceptance,
            at: now
        )
        let sealedAcceptance = try responderAdapter.sealSessionFrame(
            acceptance,
            transportSequence: 2
        )
        guard case .sessionFrame(let decodedFrame) = try offererAdapter.open(
            sealedAcceptance.frame,
            direction: .responderToOfferer
        ) else {
            return XCTFail("Expected encrypted rendezvous session frame")
        }
        XCTAssertEqual(
            try offererSession.open(decodedFrame, at: now),
            Data("relationship-scoped introduction".utf8)
        )

        let offer = try offererSession.seal(
            Data("independent relationship introduction".utf8),
            kind: .contactOffer,
            at: now
        )
        let sealedOffer = try offererAdapter.sealSessionFrame(
            offer,
            transportSequence: 1
        )
        guard case .sessionFrame(let decodedOffer) = try responderAdapter.open(
            sealedOffer.frame,
            direction: .offererToResponder
        ) else {
            return XCTFail("Expected offerer rendezvous session frame")
        }
        XCTAssertEqual(
            try responderSession.open(decodedOffer, at: now),
            Data("independent relationship introduction".utf8)
        )
    }

    func testOuterTransportHasRoomForLargestInnerRendezvousBucket() throws {
        let now = canonical(2_000_000_000)
        let expiresAt = now.addingTimeInterval(300)
        var pending = try PendingRendezvousOfferV2.create(
            transportCapability: .generate(expiresAt: expiresAt),
            createdAt: now
        )
        let opened = try RendezvousResponderV2.createOpen(
            for: pending.offer,
            redemptionSecret: pending.redemptionSecret(),
            at: now
        )
        var ledger = RendezvousRedemptionLedgerV2()
        _ = try pending.accept(opened.request, ledger: &ledger, at: now)
        var responderSession = opened.session
        let inner = try responderSession.seal(
            Data(repeating: 0x5a, count: 60 * 1_024),
            kind: .contactAcceptance,
            at: now
        )
        XCTAssertEqual(inner.payload.ciphertext.count, 65_536)
        let adapter = try RendezvousRelayAdapterV2(offer: pending.offer)
        let outer = try adapter.sealSessionFrame(inner, transportSequence: 2)
        XCTAssertEqual(outer.frame.ciphertext.count, 131_072)

        var tampered = outer.frame.ciphertext
        tampered[tampered.startIndex] ^= 0x01
        XCTAssertThrowsError(try adapter.open(
            RendezvousRelayCiphertextFrameV2(
                frameId: outer.frame.frameId,
                sequence: outer.frame.sequence,
                ciphertext: tampered
            ),
            direction: .responderToOfferer
        )) { error in
            XCTAssertEqual(error as? RendezvousRelayAdapterV2Error, .decryptionFailed)
        }
    }

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
        XCTAssertEqual(disabledResponse.status, .error)
        XCTAssertEqual(disabledResponse.error?.message, "Rendezvous transport is disabled")

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
        XCTAssertEqual(enabledResponse.status, .success)
        guard case .empty? = enabledResponse.successBody else {
            return XCTFail("Expected empty rendezvous registration success")
        }
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

import XCTest
@testable import NoctweaveRelayServer

final class PairingLobbyRelayV1Tests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 2_000_000_000)

    func testModuleIsDefaultOffAndDependsOnRealtimeRoutes() throws {
        let defaultManifest = try XCTUnwrap(
            RelayConfiguration().makeInfo().protocolCapabilities
        )
        XCTAssertFalse(defaultManifest.supports(module: "nw.pairing-lobby", version: 1))
        let enabled = try XCTUnwrap(
            RelayConfiguration(pairingLobbyEnabled: true)
                .makeInfo().protocolCapabilities
        )
        XCTAssertTrue(enabled.supports(module: "nw.pairing-lobby", version: 1))
        let missingDependency = try XCTUnwrap(
            RelayConfiguration(
                realtimeRoutesEnabled: false,
                pairingLobbyEnabled: true
            ).makeInfo().protocolCapabilities
        )
        XCTAssertFalse(missingDependency.supports(module: "nw.pairing-lobby", version: 1))
    }

    func testWireRoundTripUsesDedicatedPairingModule() throws {
        let acquire = PairingLobbyAcquireRequestV1(
            leaseID: Data(repeating: 1, count: 16),
            leaseCapability: Data(repeating: 2, count: 32),
            announcement: Data("opaque".utf8),
            ttlSeconds: 30
        )
        let request = RelayRequest.acquirePairingLobbyV1(acquire)
        let encoded = try RelayCodec.encoder(sortedKeys: true).encode(request)
        XCTAssertEqual(try RelayCodec.decoder().decode(RelayRequest.self, from: encoded), request)
        XCTAssertTrue(encoded.contains(Data("nw.pairing-lobby".utf8)))
    }

    func testRuntimeDoesNotPersistAndRequiresLeaseAuthority() throws {
        var runtime = PairingLobbyRelayRuntimeV1()
        let leaseID = Data(repeating: 3, count: 16)
        let capability = Data(repeating: 4, count: 32)
        let acquire = PairingLobbyAcquireRequestV1(
            leaseID: leaseID,
            leaseCapability: capability,
            announcement: Data("opaque-signed-listing".utf8),
            ttlSeconds: 30
        )
        let lease = try runtime.acquire(acquire, now: now)
        XCTAssertEqual(try runtime.acquire(acquire, now: now), lease)
        XCTAssertThrowsError(try runtime.release(
            PairingLobbyReleaseRequestV1(
                leaseID: leaseID,
                leaseCapability: Data(repeating: 5, count: 32)
            ),
            now: now
        )) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .unauthorized) }
        XCTAssertEqual(runtime.list(PairingLobbyListRequestV1(), now: now), [lease])
        XCTAssertTrue(runtime.list(
            PairingLobbyListRequestV1(),
            now: now.addingTimeInterval(31)
        ).isEmpty)

        var restarted = PairingLobbyRelayRuntimeV1()
        XCTAssertTrue(restarted.list(PairingLobbyListRequestV1(), now: now).isEmpty)
    }

    func testRuntimeRejectsConflictingIdempotencyAndCapacityOverflow() throws {
        var runtime = PairingLobbyRelayRuntimeV1()
        let first = PairingLobbyAcquireRequestV1(
            leaseID: Data(repeating: 1, count: 16),
            leaseCapability: Data(repeating: 2, count: 32),
            announcement: Data("first".utf8),
            ttlSeconds: 120
        )
        _ = try runtime.acquire(first, now: now)
        XCTAssertThrowsError(try runtime.acquire(
            PairingLobbyAcquireRequestV1(
                leaseID: first.leaseID,
                leaseCapability: first.leaseCapability,
                announcement: Data("changed".utf8),
                ttlSeconds: 120
            ),
            now: now
        )) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .conflict) }

        for index in 1..<PairingLobbyRelayLimitsV1.maximumListings {
            var leaseID = Data(repeating: 0, count: 16)
            leaseID[0] = UInt8(index / 256)
            leaseID[1] = UInt8(index % 256)
            leaseID[15] = 9
            _ = try runtime.acquire(
                PairingLobbyAcquireRequestV1(
                    leaseID: leaseID,
                    leaseCapability: Data(repeating: UInt8((index % 254) + 1), count: 32),
                    announcement: Data("opaque-\(index)".utf8),
                    ttlSeconds: 120
                ),
                now: now
            )
        }
        XCTAssertThrowsError(try runtime.acquire(
            PairingLobbyAcquireRequestV1(
                leaseID: Data(repeating: 255, count: 16),
                leaseCapability: Data(repeating: 254, count: 32),
                announcement: Data("overflow".utf8),
                ttlSeconds: 120
            ),
            now: now
        )) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .capacity) }
    }
}

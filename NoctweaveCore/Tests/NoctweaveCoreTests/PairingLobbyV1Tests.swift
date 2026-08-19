import XCTest
@testable import NoctweaveCore

final class PairingLobbyV1Tests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 2_000_000_000)

    func testBadgeMatchesJavaScriptCrossLanguageVector() {
        let badge = PairingLobbyBadgeV1.make(
            signingPublicKey: Data(repeating: 0x41, count: PairingLobbyV1.mlDSA65PublicKeyBytes)
        )
        XCTAssertEqual(badge.words, "Acorn Harbor")
        XCTAssertEqual(badge.comparisonCode, "788982")
    }

    func testCapabilityIsDefaultOffAndRequiresRealtimeRoutes() throws {
        let defaultManifest = try XCTUnwrap(
            RelayConfiguration().makeInfo().protocolCapabilities
        )
        XCTAssertFalse(defaultManifest.supports(module: "nw.pairing-lobby", version: 1))

        let enabledManifest = try XCTUnwrap(
            RelayConfiguration(pairingLobbyEnabled: true)
                .makeInfo().protocolCapabilities
        )
        XCTAssertTrue(enabledManifest.supports(module: "nw.pairing-lobby", version: 1))

        let missingDependency = try XCTUnwrap(
            RelayConfiguration(
                realtimeRoutesEnabled: false,
                pairingLobbyEnabled: true
            ).makeInfo().protocolCapabilities
        )
        XCTAssertFalse(missingDependency.supports(module: "nw.pairing-lobby", version: 1))
    }

    func testAcceptedRequestDeliversOnlyEncryptedOneUseLink() throws {
        var host = try PairingLobbyHostSessionV1.create(at: now)
        let lease = PairingLobbyLeaseV1(
            leaseID: host.leaseAcquireRequest.leaseID,
            announcement: host.leaseAcquireRequest.announcement,
            expiresAt: now.addingTimeInterval(120)
        )
        let listing = try PairingLobbyListingV1.verified(lease, at: now)
        var requester = try PairingLobbyRequesterSessionV1.create(for: listing, at: now)

        let pending = try host.openRequest(requester.requestAppendRequest.payload, at: now)
        XCTAssertEqual(pending.requesterBadge, requester.requesterBadge)
        XCTAssertEqual(requester.hostBadge, host.badge)

        let oneUseLink = "noctweave://pair?payload=opaque-one-use-invitation"
        let append = try host.decisionAppendRequest(
            for: pending,
            decision: .accepted,
            pairingLink: oneUseLink,
            at: now
        )
        XCTAssertFalse(append.payload.contains(Data(oneUseLink.utf8)))

        let response = try requester.openResponse(append.payload, at: now)
        XCTAssertEqual(response.decision, .accepted)
        XCTAssertEqual(response.pairingLink, oneUseLink)
        XCTAssertThrowsError(try requester.openResponse(append.payload, at: now)) {
            XCTAssertEqual($0 as? PairingLobbyV1Error, .replay)
        }
        XCTAssertThrowsError(try host.openRequest(requester.requestAppendRequest.payload, at: now)) {
            XCTAssertEqual($0 as? PairingLobbyV1Error, .replay)
        }
    }

    func testRejectionContainsNoPairingLink() throws {
        var host = try PairingLobbyHostSessionV1.create(at: now)
        let lease = PairingLobbyLeaseV1(
            leaseID: host.leaseAcquireRequest.leaseID,
            announcement: host.leaseAcquireRequest.announcement,
            expiresAt: now.addingTimeInterval(120)
        )
        let listing = try PairingLobbyListingV1.verified(lease, at: now)
        var requester = try PairingLobbyRequesterSessionV1.create(for: listing, at: now)
        let pending = try host.openRequest(requester.requestAppendRequest.payload, at: now)
        let append = try host.decisionAppendRequest(
            for: pending,
            decision: .rejected,
            at: now
        )
        let response = try requester.openResponse(append.payload, at: now)
        XCTAssertEqual(response.decision, .rejected)
        XCTAssertEqual(response.pairingLink, "")
    }

    func testTamperingAndExpiryFailClosed() throws {
        var host = try PairingLobbyHostSessionV1.create(at: now)
        let lease = PairingLobbyLeaseV1(
            leaseID: host.leaseAcquireRequest.leaseID,
            announcement: host.leaseAcquireRequest.announcement,
            expiresAt: now.addingTimeInterval(120)
        )
        let listing = try PairingLobbyListingV1.verified(lease, at: now)
        let requester = try PairingLobbyRequesterSessionV1.create(for: listing, at: now)
        var tampered = requester.requestAppendRequest.payload
        tampered[tampered.index(before: tampered.endIndex)] ^= 1
        XCTAssertThrowsError(try host.openRequest(tampered, at: now))
        XCTAssertThrowsError(
            try PairingLobbyListingV1.verified(
                lease,
                at: now.addingTimeInterval(121)
            )
        ) { XCTAssertEqual($0 as? PairingLobbyV1Error, .expired) }
    }

    func testRelayRuntimeIsBoundedEphemeralAndCapabilityScoped() throws {
        var runtime = PairingLobbyRelayRuntimeV1()
        let leaseID = Data(repeating: 1, count: PairingLobbyRelayLimitsV1.leaseIDBytes)
        let capability = Data(repeating: 2, count: PairingLobbyRelayLimitsV1.leaseCapabilityBytes)
        let acquire = PairingLobbyAcquireRequestV1(
            leaseID: leaseID,
            leaseCapability: capability,
            announcement: Data("opaque-signed-announcement".utf8),
            ttlSeconds: 30
        )
        let first = try runtime.acquire(acquire, now: now)
        XCTAssertEqual(try runtime.acquire(acquire, now: now), first)
        XCTAssertEqual(runtime.list(PairingLobbyListRequestV1(), now: now), [first])
        XCTAssertThrowsError(try runtime.release(
            PairingLobbyReleaseRequestV1(
                leaseID: leaseID,
                leaseCapability: Data(repeating: 9, count: 32)
            ),
            now: now
        )) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .unauthorized) }
        XCTAssertTrue(runtime.list(
            PairingLobbyListRequestV1(),
            now: now.addingTimeInterval(31)
        ).isEmpty)
    }

    func testRelayRuntimeEnforcesGlobalListingCapacity() throws {
        var runtime = PairingLobbyRelayRuntimeV1()
        for index in 0..<PairingLobbyRelayLimitsV1.maximumListings {
            var leaseID = Data(repeating: 0, count: PairingLobbyRelayLimitsV1.leaseIDBytes)
            leaseID[0] = UInt8(index / 256)
            leaseID[1] = UInt8(index % 256)
            leaseID[15] = 1
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
                announcement: Data("one-too-many".utf8),
                ttlSeconds: 120
            ),
            now: now
        )) { XCTAssertEqual($0 as? RealtimeRelayRuntimeError, .capacity) }
    }
}

import Foundation
import XCTest
@testable import NoctweaveCore

final class PairwiseRouteSetV2Tests: XCTestCase {
    private let origin = Date(timeIntervalSince1970: 1_800_100_000)

    func testRouteRolloverIsMakeBeforeBreak() throws {
        let signingKey = try SigningKeyPair.generate()
        let relationshipID = UUID()
        let handle = RelationshipEndpointHandle(rawValue: Data(repeating: 0x42, count: 32).base64EncodedString())
        let current = try route(marker: 0x11, state: .active, validFrom: origin)
        var routeSet = try PairwiseRouteSetV2.create(
            relationshipID: relationshipID,
            ownerEndpointHandle: handle,
            activeRoutes: [current],
            issuedAt: origin,
            signingKey: signingKey
        )

        let candidateAt = origin.addingTimeInterval(60)
        let candidate = try route(marker: 0x22, state: .testing, validFrom: candidateAt)
        routeSet = try routeSet.addingTestingRoute(
            candidate,
            signingKey: signingKey,
            issuedAt: candidateAt
        )
        XCTAssertEqual(routeSet.usableRoutes(at: candidateAt).map(\.routeID), [current.routeID])

        let testedAt = candidateAt.addingTimeInterval(1)
        routeSet = try routeSet.markingRouteTested(
            candidate.routeID,
            signingKey: signingKey,
            testedAt: testedAt
        )
        XCTAssertEqual(routeSet.usableRoutes(at: testedAt).map(\.routeID), [current.routeID])

        let activatedAt = testedAt.addingTimeInterval(1)
        let overlapUntil = activatedAt.addingTimeInterval(120)
        routeSet = try routeSet.promotingTestedRoute(
            candidate.routeID,
            replacing: [current.routeID],
            overlapUntil: overlapUntil,
            signingKey: signingKey,
            issuedAt: activatedAt
        )
        XCTAssertEqual(Set(routeSet.usableRoutes(at: activatedAt).map(\.routeID)), Set([current.routeID, candidate.routeID]))

        routeSet = try routeSet.revokingDrainedRoute(
            current.routeID,
            signingKey: signingKey,
            issuedAt: overlapUntil
        )
        XCTAssertEqual(routeSet.usableRoutes(at: overlapUntil).map(\.routeID), [candidate.routeID])
        XCTAssertTrue(routeSet.verify(ownerSigningPublicKey: signingKey.publicKeyData))
        XCTAssertEqual(routeSet.revision, 4)
    }

    func testRouteSetRejectsUnknownFieldsAndTampering() throws {
        let signingKey = try SigningKeyPair.generate()
        let routeSet = try PairwiseRouteSetV2.create(
            relationshipID: UUID(),
            ownerEndpointHandle: RelationshipEndpointHandle(
                rawValue: Data(repeating: 0x43, count: 32).base64EncodedString()
            ),
            activeRoutes: [try route(marker: 0x33, state: .active, validFrom: origin)],
            issuedAt: origin,
            signingKey: signingKey
        )
        let encoded = try NoctweaveCoder.encode(routeSet, sortedKeys: true)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        object["legacyInbox"] = "forbidden"
        XCTAssertThrowsError(try NoctweaveCoder.decode(
            PairwiseRouteSetV2.self,
            from: JSONSerialization.data(withJSONObject: object)
        ))

        object.removeValue(forKey: "legacyInbox")
        var routes = try XCTUnwrap(object["routes"] as? [[String: Any]])
        routes[0]["priority"] = 101
        object["routes"] = routes
        let tampered = try NoctweaveCoder.decode(
            PairwiseRouteSetV2.self,
            from: JSONSerialization.data(withJSONObject: object)
        )
        XCTAssertFalse(tampered.verify(ownerSigningPublicKey: signingKey.publicKeyData))
    }

    private func route(
        marker: UInt8,
        state: RelationshipRouteStateV2,
        validFrom: Date
    ) throws -> PairwiseSendRouteV2 {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        return try PairwiseSendRouteV2(
            routeID: material.routeID,
            relay: RelayEndpoint(
                host: "relay-\(marker).example",
                port: 443,
                useTLS: true,
                transport: .websocket
            ),
            sendCapability: material.sendCapability,
            payloadKey: OpaqueRoutePayloadKeyV2(
                rawValue: Data(repeating: marker, count: 32)
            ),
            routeRevision: 0,
            policy: OpaqueRoutePolicyV2(
                paddingBucket: .bytes4096,
                retentionBucket: .sixHours,
                quotaBucket: .packets256
            ),
            validFrom: validFrom,
            expiresAt: validFrom.addingTimeInterval(3_600),
            state: state,
            testedAt: state == .active ? validFrom : nil
        )
    }
}

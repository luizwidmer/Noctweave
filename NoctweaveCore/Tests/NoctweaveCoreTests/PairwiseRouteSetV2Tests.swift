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
        XCTAssertTrue(try routeSet.verifyThrowing(
            ownerSigningPublicKey: signingKey.publicKeyData
        ))
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
        XCTAssertFalse(try tampered.verifyThrowing(
            ownerSigningPublicKey: signingKey.publicKeyData
        ))
    }

    func testTargetedProbePromotesInOneVerifiableSuccessor() throws {
        let signingKey = try SigningKeyPair.generate()
        let relationshipID = UUID()
        let handle = RelationshipEndpointHandle(
            rawValue: Data(repeating: 0x44, count: 32).base64EncodedString()
        )
        let current = try route(marker: 0x41, state: .active, validFrom: origin)
        let initial = try PairwiseRouteSetV2.create(
            relationshipID: relationshipID,
            ownerEndpointHandle: handle,
            activeRoutes: [current],
            issuedAt: origin,
            signingKey: signingKey
        )
        let candidateAt = origin.addingTimeInterval(30)
        let candidate = try route(marker: 0x42, state: .testing, validFrom: candidateAt)
        let testing = try initial.addingTestingRoute(
            candidate,
            signingKey: signingKey,
            issuedAt: candidateAt
        )
        let probedAt = candidateAt.addingTimeInterval(1)
        let promoted = try testing.promotingProbedRoute(
            candidate.routeID,
            replacing: [current.routeID],
            testedAt: probedAt,
            overlapUntil: probedAt.addingTimeInterval(300),
            signingKey: signingKey,
            issuedAt: probedAt
        )

        XCTAssertTrue(promoted.isValidSuccessor(
            of: testing,
            ownerSigningPublicKey: signingKey.publicKeyData
        ))
        XCTAssertTrue(try promoted.isValidSuccessorThrowing(
            of: testing,
            ownerSigningPublicKey: signingKey.publicKeyData
        ))
        XCTAssertEqual(promoted.revision, testing.revision + 1)
        XCTAssertEqual(
            Set(promoted.usableRoutes(at: probedAt).map(\.routeID)),
            Set([current.routeID, candidate.routeID])
        )
    }

    func testObservedSuccessorRejectsFarFutureAndUnusableRouteSnapshots() throws {
        let signingKey = try SigningKeyPair.generate()
        let relationshipID = UUID()
        let handle = RelationshipEndpointHandle(
            rawValue: Data(repeating: 0x45, count: 32).base64EncodedString()
        )
        let initial = try PairwiseRouteSetV2.create(
            relationshipID: relationshipID,
            ownerEndpointHandle: handle,
            activeRoutes: [try route(marker: 0x51, state: .active, validFrom: origin)],
            issuedAt: origin,
            signingKey: signingKey
        )
        let candidateAt = origin.addingTimeInterval(60)
        let currentSuccessor = try initial.addingTestingRoute(
            try route(marker: 0x52, state: .testing, validFrom: candidateAt),
            signingKey: signingKey,
            issuedAt: candidateAt
        )

        XCTAssertTrue(currentSuccessor.isAcceptableSuccessor(
            of: initial,
            ownerSigningPublicKey: signingKey.publicKeyData,
            observedAt: candidateAt
        ))
        XCTAssertTrue(try currentSuccessor.isAcceptableSuccessorThrowing(
            of: initial,
            ownerSigningPublicKey: signingKey.publicKeyData,
            observedAt: candidateAt
        ))
        XCTAssertFalse(currentSuccessor.isAcceptableSuccessor(
            of: initial,
            ownerSigningPublicKey: signingKey.publicKeyData,
            observedAt: origin.addingTimeInterval(4_000)
        ))

        let farFuture = origin.addingTimeInterval(
            NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew + 1_000
        )
        let futureSuccessor = try initial.addingTestingRoute(
            try route(marker: 0x53, state: .testing, validFrom: farFuture),
            signingKey: signingKey,
            issuedAt: farFuture
        )
        XCTAssertTrue(futureSuccessor.isValidSuccessor(
            of: initial,
            ownerSigningPublicKey: signingKey.publicKeyData
        ))
        XCTAssertFalse(futureSuccessor.isAcceptableSuccessor(
            of: initial,
            ownerSigningPublicKey: signingKey.publicKeyData,
            observedAt: origin
        ))
    }

    private func route(
        marker: UInt8,
        state: RelationshipRouteStateV2,
        validFrom: Date
    ) throws -> OpaqueSendRouteV2 {
        let material = try OpaqueRouteClientCapabilityMaterialV2()
        return try OpaqueSendRouteV2(
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

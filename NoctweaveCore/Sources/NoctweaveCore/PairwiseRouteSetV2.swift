import CryptoKit
import Foundation

public enum PairwiseRouteSetV2Error: Error, Equatable {
    case invalidState
    case invalidTransition
}

/// A relationship-encrypted, endpoint-signed snapshot of the opaque routes a
/// peer may use. Route replacement is make-before-break: a fresh route is
/// tested, activated with an overlap window, and only then is the old route
/// revoked. No read, renewal, or teardown authority is ever present here.
public struct PairwiseRouteSetV2: Codable, Equatable {
    public static let version = 2

    public let version: Int
    public let relationshipID: UUID
    public let ownerEndpointHandle: RelationshipEndpointHandle
    public let revision: UInt64
    public let previousDigest: Data?
    public let routes: [OpaqueSendRouteV2]
    public let issuedAt: Date
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case relationshipID
        case ownerEndpointHandle
        case revision
        case previousDigest
        case routes
        case issuedAt
        case signature
    }

    private init(
        version: Int = Self.version,
        relationshipID: UUID,
        ownerEndpointHandle: RelationshipEndpointHandle,
        revision: UInt64,
        previousDigest: Data?,
        routes: [OpaqueSendRouteV2],
        issuedAt: Date,
        signature: Data
    ) {
        self.version = version
        self.relationshipID = relationshipID
        self.ownerEndpointHandle = ownerEndpointHandle
        self.revision = revision
        self.previousDigest = previousDigest
        self.routes = routes.sorted(by: Self.routeOrdering)
        self.issuedAt = issuedAt
        self.signature = signature
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PairwiseRouteSetCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Pairwise route-set fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try container.decode(Int.self, forKey: .version),
            relationshipID: try container.decode(UUID.self, forKey: .relationshipID),
            ownerEndpointHandle: try container.decode(
                RelationshipEndpointHandle.self,
                forKey: .ownerEndpointHandle
            ),
            revision: try container.decode(UInt64.self, forKey: .revision),
            previousDigest: try container.decodeIfPresent(Data.self, forKey: .previousDigest),
            routes: try container.decode([OpaqueSendRouteV2].self, forKey: .routes),
            issuedAt: try container.decode(Date.self, forKey: .issuedAt),
            signature: try container.decode(Data.self, forKey: .signature)
        )
        guard try isStructurallyValidThrowing else {
            throw DecodingError.dataCorruptedError(
                forKey: .signature,
                in: container,
                debugDescription: "Pairwise route set is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Pairwise route set is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(relationshipID, forKey: .relationshipID)
        try container.encode(ownerEndpointHandle, forKey: .ownerEndpointHandle)
        try container.encode(revision, forKey: .revision)
        if let previousDigest {
            try container.encode(previousDigest, forKey: .previousDigest)
        } else {
            try container.encodeNil(forKey: .previousDigest)
        }
        try container.encode(routes, forKey: .routes)
        try container.encode(issuedAt, forKey: .issuedAt)
        try container.encode(signature, forKey: .signature)
    }

    public static func create(
        relationshipID: UUID,
        ownerEndpointHandle: RelationshipEndpointHandle,
        activeRoutes: [OpaqueSendRouteV2],
        issuedAt: Date,
        signingKey: SigningKeyPair
    ) throws -> PairwiseRouteSetV2 {
        guard !activeRoutes.isEmpty,
              activeRoutes.allSatisfy({ $0.state == .active && $0.isUsable(at: issuedAt) }) else {
            throw PairwiseRouteSetV2Error.invalidState
        }
        return try signed(
            relationshipID: relationshipID,
            ownerEndpointHandle: ownerEndpointHandle,
            revision: 0,
            previousDigest: nil,
            routes: activeRoutes,
            issuedAt: issuedAt,
            signingKey: signingKey
        )
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard version == Self.version,
                  ownerEndpointHandle.isStructurallyValid,
                  previousDigest?.count != 0,
                  previousDigest.map({ $0.count == SHA256.byteCount }) ?? true,
                  (revision == 0) == (previousDigest == nil),
                  !routes.isEmpty,
                  routes.count <= NoctweaveArchitectureV2.maximumRoutes,
                  routes == routes.sorted(by: Self.routeOrdering),
                  Set(routes.map(\.routeID)).count == routes.count,
                  routes.contains(where: { $0.state == .active || $0.state == .draining }),
                  issuedAt.timeIntervalSince1970.isFinite,
                  routes.allSatisfy({ $0.validFrom <= issuedAt }),
                  !signature.isEmpty,
                  signature.count <= 8 * 1_024 else {
                return false
            }
            for route in routes {
                guard try route.isStructurallyValidThrowing else { return false }
            }
            return true
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    public func verifyThrowing(ownerSigningPublicKey: Data) throws -> Bool {
        guard try isStructurallyValidThrowing else { return false }
        return try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: signaturePayloadData(),
            publicKeyData: ownerSigningPublicKey
        )
    }

    public func verify(ownerSigningPublicKey: Data) -> Bool {
        (try? verifyThrowing(ownerSigningPublicKey: ownerSigningPublicKey)) == true
    }

    /// Verifies one exact monotonic successor. Route sets are snapshots, so a
    /// receiver never resolves forks or merges competing histories.
    public func isValidSuccessor(
        of previous: PairwiseRouteSetV2,
        ownerSigningPublicKey: Data
    ) -> Bool {
        (try? isValidSuccessorThrowing(
            of: previous,
            ownerSigningPublicKey: ownerSigningPublicKey
        )) == true
    }

    public func isValidSuccessorThrowing(
        of previous: PairwiseRouteSetV2,
        ownerSigningPublicKey: Data
    ) throws -> Bool {
        guard previous.revision < UInt64.max,
              relationshipID == previous.relationshipID,
              ownerEndpointHandle == previous.ownerEndpointHandle,
              revision == previous.revision + 1,
              previousDigest == previous.digest,
              issuedAt >= previous.issuedAt else {
            return false
        }
        return try verifyThrowing(ownerSigningPublicKey: ownerSigningPublicKey)
    }

    /// Applies the receiver's observation time to a signed successor. The
    /// peer timestamp remains authenticated metadata, but cannot install a
    /// route snapshot that is far in the future or has no currently usable
    /// delivery path.
    func isAcceptableSuccessor(
        of previous: PairwiseRouteSetV2,
        ownerSigningPublicKey: Data,
        observedAt: Date
    ) -> Bool {
        (try? isAcceptableSuccessorThrowing(
            of: previous,
            ownerSigningPublicKey: ownerSigningPublicKey,
            observedAt: observedAt
        )) == true
    }

    func isAcceptableSuccessorThrowing(
        of previous: PairwiseRouteSetV2,
        ownerSigningPublicKey: Data,
        observedAt: Date
    ) throws -> Bool {
        guard observedAt.timeIntervalSince1970.isFinite,
              issuedAt <= observedAt.addingTimeInterval(
                NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew
              ),
              !usableRoutes(at: observedAt).isEmpty else {
            return false
        }
        return try isValidSuccessorThrowing(
            of: previous,
            ownerSigningPublicKey: ownerSigningPublicKey
        )
    }

    public var digest: Data? {
        guard isStructurallyValid,
              let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else {
            return nil
        }
        return Data(SHA256.hash(data: encoded))
    }

    public func usableRoutes(at date: Date) -> [OpaqueSendRouteV2] {
        routes.filter { $0.isUsable(at: date) }.sorted {
            if $0.priority != $1.priority { return $0.priority < $1.priority }
            return Self.routeOrdering($0, $1)
        }
    }

    public func addingTestingRoute(
        _ route: OpaqueSendRouteV2,
        signingKey: SigningKeyPair,
        issuedAt: Date
    ) throws -> PairwiseRouteSetV2 {
        if let existing = routes.first(where: { $0.routeID == route.routeID }) {
            guard existing == route else { throw PairwiseRouteSetV2Error.invalidTransition }
            return self
        }
        guard route.state == .testing,
              route.testedAt == nil,
              route.validFrom >= self.issuedAt,
              route.validFrom <= issuedAt else {
            throw PairwiseRouteSetV2Error.invalidTransition
        }
        let retained = routes.filter { $0.state != .revoked }
        guard retained.count < NoctweaveArchitectureV2.maximumRoutes else {
            throw PairwiseRouteSetV2Error.invalidTransition
        }
        return try transitioning(
            routes: retained + [route],
            signingKey: signingKey,
            issuedAt: issuedAt
        )
    }

    public func markingRouteTested(
        _ routeID: OpaqueReceiveRouteIDV2,
        signingKey: SigningKeyPair,
        testedAt: Date
    ) throws -> PairwiseRouteSetV2 {
        guard let index = routes.firstIndex(where: { $0.routeID == routeID }) else {
            throw PairwiseRouteSetV2Error.invalidTransition
        }
        let route = routes[index]
        guard route.state == .testing else {
            throw PairwiseRouteSetV2Error.invalidTransition
        }
        if route.testedAt == testedAt { return self }
        guard route.testedAt == nil, testedAt >= route.validFrom else {
            throw PairwiseRouteSetV2Error.invalidTransition
        }
        var updated = routes
        updated[index] = try route.replacingLifecycle(
            state: .testing,
            testedAt: testedAt,
            drainAfter: nil,
            revokedAt: nil
        )
        return try transitioning(routes: updated, signingKey: signingKey, issuedAt: testedAt)
    }

    public func promotingTestedRoute(
        _ routeID: OpaqueReceiveRouteIDV2,
        replacing replacedRouteIDs: [OpaqueReceiveRouteIDV2],
        overlapUntil: Date,
        signingKey: SigningKeyPair,
        issuedAt: Date
    ) throws -> PairwiseRouteSetV2 {
        let replacementIDs = Set(replacedRouteIDs)
        guard !replacementIDs.isEmpty,
              replacementIDs.count == replacedRouteIDs.count,
              !replacementIDs.contains(routeID),
              overlapUntil > issuedAt,
              let targetIndex = routes.firstIndex(where: { $0.routeID == routeID }) else {
            throw PairwiseRouteSetV2Error.invalidTransition
        }
        let target = routes[targetIndex]
        guard target.state == .testing,
              let testedAt = target.testedAt,
              testedAt <= issuedAt,
              replacementIDs.allSatisfy({ id in
                  routes.contains { $0.routeID == id && $0.state == .active }
              }) else {
            throw PairwiseRouteSetV2Error.invalidTransition
        }
        var updated = routes
        updated[targetIndex] = try target.replacingLifecycle(
            state: .active,
            testedAt: testedAt,
            drainAfter: nil,
            revokedAt: nil
        )
        for index in updated.indices where replacementIDs.contains(updated[index].routeID) {
            let route = updated[index]
            updated[index] = try route.replacingLifecycle(
                state: .draining,
                testedAt: route.testedAt,
                drainAfter: overlapUntil,
                revokedAt: nil
            )
        }
        return try transitioning(routes: updated, signingKey: signingKey, issuedAt: issuedAt)
    }

    /// Records a successful targeted probe and promotes the route in one
    /// signed successor so the peer never needs an unpublished intermediate
    /// testing snapshot to validate the hash chain.
    public func promotingProbedRoute(
        _ routeID: OpaqueReceiveRouteIDV2,
        replacing replacedRouteIDs: [OpaqueReceiveRouteIDV2],
        testedAt: Date,
        overlapUntil: Date,
        signingKey: SigningKeyPair,
        issuedAt: Date
    ) throws -> PairwiseRouteSetV2 {
        let replacementIDs = Set(replacedRouteIDs)
        guard !replacementIDs.isEmpty,
              replacementIDs.count == replacedRouteIDs.count,
              !replacementIDs.contains(routeID),
              testedAt <= issuedAt,
              overlapUntil > issuedAt,
              let targetIndex = routes.firstIndex(where: { $0.routeID == routeID }) else {
            throw PairwiseRouteSetV2Error.invalidTransition
        }
        let target = routes[targetIndex]
        guard target.state == .testing,
              target.testedAt == nil,
              testedAt >= target.validFrom,
              replacementIDs.allSatisfy({ id in
                  routes.contains { $0.routeID == id && $0.state == .active }
              }) else {
            throw PairwiseRouteSetV2Error.invalidTransition
        }
        var updated = routes
        updated[targetIndex] = try target.replacingLifecycle(
            state: .active,
            testedAt: testedAt,
            drainAfter: nil,
            revokedAt: nil
        )
        for index in updated.indices where replacementIDs.contains(updated[index].routeID) {
            let route = updated[index]
            updated[index] = try route.replacingLifecycle(
                state: .draining,
                testedAt: route.testedAt,
                drainAfter: overlapUntil,
                revokedAt: nil
            )
        }
        return try transitioning(routes: updated, signingKey: signingKey, issuedAt: issuedAt)
    }

    public func revokingDrainedRoute(
        _ routeID: OpaqueReceiveRouteIDV2,
        signingKey: SigningKeyPair,
        issuedAt: Date
    ) throws -> PairwiseRouteSetV2 {
        guard let index = routes.firstIndex(where: { $0.routeID == routeID }) else {
            throw PairwiseRouteSetV2Error.invalidTransition
        }
        let route = routes[index]
        if route.state == .revoked { return self }
        guard route.state == .draining,
              let drainAfter = route.drainAfter,
              issuedAt >= drainAfter else {
            throw PairwiseRouteSetV2Error.invalidTransition
        }
        var updated = routes
        updated[index] = try route.replacingLifecycle(
            state: .revoked,
            testedAt: route.testedAt,
            drainAfter: drainAfter,
            revokedAt: issuedAt
        )
        return try transitioning(routes: updated, signingKey: signingKey, issuedAt: issuedAt)
    }

    public func abandoningTestingRoute(
        _ routeID: OpaqueReceiveRouteIDV2,
        signingKey: SigningKeyPair,
        issuedAt: Date
    ) throws -> PairwiseRouteSetV2 {
        guard let index = routes.firstIndex(where: { $0.routeID == routeID }) else {
            throw PairwiseRouteSetV2Error.invalidTransition
        }
        let route = routes[index]
        if route.state == .revoked { return self }
        guard route.state == .testing, issuedAt >= route.validFrom else {
            throw PairwiseRouteSetV2Error.invalidTransition
        }
        var updated = routes
        updated[index] = try route.replacingLifecycle(
            state: .revoked,
            testedAt: route.testedAt,
            drainAfter: nil,
            revokedAt: issuedAt
        )
        return try transitioning(routes: updated, signingKey: signingKey, issuedAt: issuedAt)
    }

    private func transitioning(
        routes: [OpaqueSendRouteV2],
        signingKey: SigningKeyPair,
        issuedAt: Date
    ) throws -> PairwiseRouteSetV2 {
        guard try verifyThrowing(ownerSigningPublicKey: signingKey.publicKeyData),
              let digest,
              revision < UInt64.max,
              issuedAt.timeIntervalSince1970.isFinite,
              issuedAt >= self.issuedAt else {
            throw PairwiseRouteSetV2Error.invalidTransition
        }
        return try Self.signed(
            relationshipID: relationshipID,
            ownerEndpointHandle: ownerEndpointHandle,
            revision: revision + 1,
            previousDigest: digest,
            routes: routes,
            issuedAt: issuedAt,
            signingKey: signingKey
        )
    }

    private static func signed(
        relationshipID: UUID,
        ownerEndpointHandle: RelationshipEndpointHandle,
        revision: UInt64,
        previousDigest: Data?,
        routes: [OpaqueSendRouteV2],
        issuedAt: Date,
        signingKey: SigningKeyPair
    ) throws -> PairwiseRouteSetV2 {
        let ordered = routes.sorted(by: routeOrdering)
        let unsigned = PairwiseRouteSetSignaturePayloadV2(
            version: Self.version,
            relationshipID: relationshipID,
            ownerEndpointHandle: ownerEndpointHandle,
            revision: revision,
            previousDigest: previousDigest,
            routes: ordered,
            issuedAt: issuedAt
        )
        let signature = try signingKey.sign(NoctweaveCoder.encode(unsigned, sortedKeys: true))
        let result = PairwiseRouteSetV2(
            relationshipID: relationshipID,
            ownerEndpointHandle: ownerEndpointHandle,
            revision: revision,
            previousDigest: previousDigest,
            routes: ordered,
            issuedAt: issuedAt,
            signature: signature
        )
        guard try result.isStructurallyValidThrowing else {
            throw PairwiseRouteSetV2Error.invalidState
        }
        return result
    }

    private func signaturePayloadData() throws -> Data {
        try NoctweaveCoder.encode(
            PairwiseRouteSetSignaturePayloadV2(
                version: version,
                relationshipID: relationshipID,
                ownerEndpointHandle: ownerEndpointHandle,
                revision: revision,
                previousDigest: previousDigest,
                routes: routes,
                issuedAt: issuedAt
            ),
            sortedKeys: true
        )
    }

    private static func routeOrdering(
        _ lhs: OpaqueSendRouteV2,
        _ rhs: OpaqueSendRouteV2
    ) -> Bool {
        lhs.routeID.rawValue.lexicographicallyPrecedes(rhs.routeID.rawValue)
    }
}

private struct PairwiseRouteSetSignaturePayloadV2: Codable {
    let version: Int
    let relationshipID: UUID
    let ownerEndpointHandle: RelationshipEndpointHandle
    let revision: UInt64
    let previousDigest: Data?
    let routes: [OpaqueSendRouteV2]
    let issuedAt: Date
}

private struct PairwiseRouteSetCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

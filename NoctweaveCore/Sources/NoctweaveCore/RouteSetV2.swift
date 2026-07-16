import CryptoKit
import Foundation

public enum RouteSetV2Error: Error, Equatable {
    case invalidInitialState
}

/// A route identifier that is unique to one relationship. It is not a global
/// endpoint or account identifier and is safe to replace during rotation.
public struct RelationshipRouteID: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: Data

    public init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public static func generate(
        relationshipId: UUID,
        installationHandle: RelationshipInstallationHandle,
        nonce: UUID = UUID()
    ) -> RelationshipRouteID {
        var material = Data("Noctweave/relationship-route-id/v2".utf8)
        material.append(Data(relationshipId.uuidString.lowercased().utf8))
        material.append(Data(installationHandle.rawValue.utf8))
        material.append(Data(nonce.uuidString.lowercased().utf8))
        return RelationshipRouteID(rawValue: Data(SHA256.hash(data: material)))
    }

    public var isStructurallyValid: Bool {
        rawValue.count == 32
    }
}

/// An opaque bearer capability understood by a relay. It intentionally carries
/// no user, contact, conversation, or endpoint label.
public enum InboxRouteCapabilityV2Error: Error, Equatable {
    case invalidAuthenticatedBearer
}

public struct InboxRouteCapabilityV2: Codable, Equatable, Hashable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let relayRegistryDigestDomain = "org.noctweave.relay.inbox-route-capability/v2"

    let rawValue: Data

    private enum CodingKeys: String, CodingKey {
        case rawValue
    }

    /// Internal construction exists for wire decoding and deterministic test
    /// fixtures. New bearer capabilities must be minted with `generate()`.
    init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decoded = try container.decode(Data.self, forKey: .rawValue)
        let capability = InboxRouteCapabilityV2(rawValue: decoded)
        guard capability.isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawValue,
                in: container,
                debugDescription: "Inbox route capability must be a nonzero 32-byte bearer"
            )
        }
        self = capability
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rawValue, forKey: .rawValue)
    }

    public static func generate() -> InboxRouteCapabilityV2 {
        var generator = SystemRandomNumberGenerator()
        while true {
            let bytes = (0..<32).map { _ in
                UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
            }
            let capability = InboxRouteCapabilityV2(rawValue: Data(bytes))
            if capability.isStructurallyValid {
                return capability
            }
        }
    }

    /// Imports a bearer received inside an already authenticated relationship
    /// transcript. This is not a minting API: callers creating a new route must
    /// use `generate()` so the value comes from the operating-system CSPRNG.
    public static func importAuthenticatedBearer(
        _ rawValue: Data
    ) throws -> InboxRouteCapabilityV2 {
        let capability = InboxRouteCapabilityV2(rawValue: rawValue)
        guard capability.isStructurallyValid else {
            throw InboxRouteCapabilityV2Error.invalidAuthenticatedBearer
        }
        return capability
    }

    public var isStructurallyValid: Bool {
        rawValue.count == 32 && rawValue.contains(where: { $0 != 0 })
    }

    public var description: String {
        "InboxRouteCapabilityV2(<redacted>)"
    }

    public var debugDescription: String {
        description
    }

    public var customMirror: Mirror {
        Mirror(self, children: [:], displayStyle: .struct)
    }

    /// The relay persists only this domain-separated digest, never the bearer
    /// capability itself. The digest is an opaque lookup key and carries no
    /// endpoint, relationship, conversation, or identity label.
    var relayRegistryDigest: Data {
        var material = Data(Self.relayRegistryDigestDomain.utf8)
        material.append(0)
        material.append(rawValue)
        return Data(SHA256.hash(data: material))
    }
}

public enum RelationshipRouteStateV2: String, Codable, Equatable, CaseIterable {
    case testing
    case active
    case draining
    case revoked
}

public struct RelationshipRouteV2: Codable, Equatable, Identifiable {
    public let id: RelationshipRouteID
    public let installationHandle: RelationshipInstallationHandle
    public let relay: RelayEndpoint
    public let inboxCapability: InboxRouteCapabilityV2
    public let priority: UInt16
    public let state: RelationshipRouteStateV2
    public let validFrom: Date
    public let testedAt: Date?
    public let drainAfter: Date?
    public let revokedAt: Date?

    public init(
        id: RelationshipRouteID,
        installationHandle: RelationshipInstallationHandle,
        relay: RelayEndpoint,
        inboxCapability: InboxRouteCapabilityV2,
        priority: UInt16 = 100,
        state: RelationshipRouteStateV2,
        validFrom: Date,
        testedAt: Date? = nil,
        drainAfter: Date? = nil,
        revokedAt: Date? = nil
    ) {
        self.id = id
        self.installationHandle = installationHandle
        self.relay = relay
        self.inboxCapability = inboxCapability
        self.priority = priority
        self.state = state
        self.validFrom = validFrom
        self.testedAt = testedAt
        self.drainAfter = drainAfter
        self.revokedAt = revokedAt
    }

    public static func active(
        id: RelationshipRouteID,
        installationHandle: RelationshipInstallationHandle,
        relay: RelayEndpoint,
        inboxCapability: InboxRouteCapabilityV2,
        priority: UInt16 = 100,
        at date: Date
    ) -> RelationshipRouteV2 {
        RelationshipRouteV2(
            id: id,
            installationHandle: installationHandle,
            relay: relay,
            inboxCapability: inboxCapability,
            priority: priority,
            state: .active,
            validFrom: date,
            testedAt: date
        )
    }

    public static func testing(
        id: RelationshipRouteID,
        installationHandle: RelationshipInstallationHandle,
        relay: RelayEndpoint,
        inboxCapability: InboxRouteCapabilityV2,
        priority: UInt16 = 100,
        at date: Date
    ) -> RelationshipRouteV2 {
        RelationshipRouteV2(
            id: id,
            installationHandle: installationHandle,
            relay: relay,
            inboxCapability: inboxCapability,
            priority: priority,
            state: .testing,
            validFrom: date
        )
    }

    public var isStructurallyValid: Bool {
        guard id.isStructurallyValid,
              installationHandle.isStructurallyValid,
              relay.isStructurallyValidRelationshipRouteEndpointV2,
              relay.isConfidentialCapabilityTransportV2,
              inboxCapability.isStructurallyValid,
              validFrom.timeIntervalSince1970.isFinite,
              testedAt?.timeIntervalSince1970.isFinite ?? true,
              drainAfter?.timeIntervalSince1970.isFinite ?? true,
              revokedAt?.timeIntervalSince1970.isFinite ?? true,
              testedAt.map({ $0 >= validFrom }) ?? true else {
            return false
        }

        switch state {
        case .testing:
            return drainAfter == nil && revokedAt == nil
        case .active:
            return testedAt != nil && drainAfter == nil && revokedAt == nil
        case .draining:
            return testedAt != nil
                && drainAfter.map { $0 > validFrom } == true
                && revokedAt == nil
        case .revoked:
            guard let revokedAt, revokedAt >= validFrom else { return false }
            return drainAfter.map { revokedAt >= $0 } ?? true
        }
    }

    fileprivate func replacing(
        state: RelationshipRouteStateV2,
        testedAt: Date? = nil,
        drainAfter: Date? = nil,
        revokedAt: Date? = nil
    ) -> RelationshipRouteV2 {
        RelationshipRouteV2(
            id: id,
            installationHandle: installationHandle,
            relay: relay,
            inboxCapability: inboxCapability,
            priority: priority,
            state: state,
            validFrom: validFrom,
            testedAt: testedAt,
            drainAfter: drainAfter,
            revokedAt: revokedAt
        )
    }
}

/// A signed, relationship-encrypted route snapshot. Revisions form a hash
/// chain, while old revoked entries may be compacted from the current snapshot
/// to keep ordinary endpoint and relay churn bounded.
public struct RelationshipRouteSetV2: Codable, Equatable {
    public let version: Int
    public let relationshipId: UUID
    public let ownerInstallationHandle: RelationshipInstallationHandle
    public let revision: UInt64
    public let previousDigest: Data?
    public let routes: [RelationshipRouteV2]
    public let issuedAt: Date
    public let signature: Data

    public init(
        version: Int = NoctweaveArchitectureV2.version,
        relationshipId: UUID,
        ownerInstallationHandle: RelationshipInstallationHandle,
        revision: UInt64,
        previousDigest: Data?,
        routes: [RelationshipRouteV2],
        issuedAt: Date,
        signature: Data
    ) {
        self.version = version
        self.relationshipId = relationshipId
        self.ownerInstallationHandle = ownerInstallationHandle
        self.revision = revision
        self.previousDigest = previousDigest
        self.routes = routes.sorted(by: Self.routeOrdering)
        self.issuedAt = issuedAt
        self.signature = signature
    }

    public static func createInitial(
        relationshipId: UUID,
        ownerInstallationHandle: RelationshipInstallationHandle,
        route: RelationshipRouteV2,
        signingKey: SigningKeyPair,
        issuedAt: Date
    ) throws -> RelationshipRouteSetV2 {
        guard route.state == .active,
              route.installationHandle == ownerInstallationHandle,
              route.isStructurallyValid,
              issuedAt.timeIntervalSince1970.isFinite,
              issuedAt >= route.validFrom else {
            throw RouteSetV2Error.invalidInitialState
        }
        return try signed(
            relationshipId: relationshipId,
            ownerInstallationHandle: ownerInstallationHandle,
            revision: 1,
            previousDigest: nil,
            routes: [route],
            issuedAt: issuedAt,
            signingKey: signingKey
        )
    }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveArchitectureV2.version,
              ownerInstallationHandle.isStructurallyValid,
              revision > 0,
              !routes.isEmpty,
              routes.count <= NoctweaveArchitectureV2.maximumRoutes,
              Set(routes.map(\.id)).count == routes.count,
              routes.allSatisfy({
                  $0.installationHandle == ownerInstallationHandle
                      && $0.isStructurallyValid
                      && $0.validFrom <= issuedAt
                      && ($0.testedAt.map { $0 <= issuedAt } ?? true)
                      && ($0.revokedAt.map { $0 <= issuedAt } ?? true)
              }),
              routes.contains(where: { $0.state == .active }),
              issuedAt.timeIntervalSince1970.isFinite,
              signature.count == 3_309 else {
            return false
        }
        if revision == 1 {
            return previousDigest == nil
        }
        return previousDigest?.count == 32
    }

    public var digest: Data? {
        guard isStructurallyValid,
              let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else {
            return nil
        }
        return Data(SHA256.hash(data: encoded))
    }

    public func verify(ownerSigningPublicKey: Data) -> Bool {
        guard isStructurallyValid,
              let encoded = try? NoctweaveCoder.encode(signaturePayload, sortedKeys: true) else {
            return false
        }
        return SigningKeyPair.verify(
            signature: signature,
            data: encoded,
            publicKeyData: ownerSigningPublicKey
        )
    }

    /// Active routes and not-yet-expired draining routes are both returned
    /// during an overlap window. Callers can fan out over this bounded list.
    public func usableRoutes(at date: Date) -> [RelationshipRouteV2] {
        routes.filter { route in
            guard route.validFrom <= date else { return false }
            switch route.state {
            case .active:
                return true
            case .draining:
                return route.drainAfter.map { date < $0 } ?? false
            case .testing, .revoked:
                return false
            }
        }.sorted {
            if $0.priority != $1.priority { return $0.priority < $1.priority }
            return Self.routeOrdering($0, $1)
        }
    }

    /// Adds a new route without disturbing any working route. Replaying the
    /// same operation is a no-op; reusing an ID for different material fails.
    public func addingTestingRoute(
        _ route: RelationshipRouteV2,
        signingKey: SigningKeyPair,
        issuedAt: Date
    ) throws -> RelationshipRouteSetV2? {
        if let existing = routes.first(where: { $0.id == route.id }) {
            return existing == route ? self : nil
        }
        guard route.state == .testing,
              route.testedAt == nil,
              route.installationHandle == ownerInstallationHandle,
              route.isStructurallyValid,
              route.validFrom >= self.issuedAt,
              route.validFrom <= issuedAt else {
            return nil
        }

        // A signed previous digest preserves the removed history, allowing
        // already-revoked entries to be compacted before enforcing the bound.
        let retained = routes.filter { $0.state != .revoked }
        guard retained.count < NoctweaveArchitectureV2.maximumRoutes else { return nil }
        return try transitioning(
            routes: retained + [route],
            signingKey: signingKey,
            issuedAt: issuedAt
        )
    }

    public func markingRouteTested(
        _ routeId: RelationshipRouteID,
        signingKey: SigningKeyPair,
        testedAt: Date
    ) throws -> RelationshipRouteSetV2? {
        guard let index = routes.firstIndex(where: { $0.id == routeId }) else { return nil }
        let route = routes[index]
        guard route.state == .testing else { return nil }
        if route.testedAt != nil { return self }
        guard testedAt >= route.validFrom else { return nil }

        var updated = routes
        updated[index] = route.replacing(state: .testing, testedAt: testedAt)
        return try transitioning(routes: updated, signingKey: signingKey, issuedAt: testedAt)
    }

    /// Activates a tested route and starts draining only the explicitly
    /// replaced active routes. Other active routes remain available for users
    /// who intentionally configure redundant delivery.
    public func promotingTestedRoute(
        _ routeId: RelationshipRouteID,
        replacing replacedRouteIds: [RelationshipRouteID],
        overlapUntil: Date,
        signingKey: SigningKeyPair,
        issuedAt: Date
    ) throws -> RelationshipRouteSetV2? {
        guard let targetIndex = routes.firstIndex(where: { $0.id == routeId }) else { return nil }
        if routes[targetIndex].state == .active { return self }

        let replacementIds = Set(replacedRouteIds)
        guard !replacementIds.isEmpty,
              replacementIds.count == replacedRouteIds.count,
              !replacementIds.contains(routeId),
              overlapUntil > issuedAt else {
            return nil
        }
        let target = routes[targetIndex]
        guard target.state == .testing,
              let testedAt = target.testedAt,
              testedAt <= issuedAt,
              replacementIds.allSatisfy({ id in
                  routes.contains { $0.id == id && $0.state == .active }
              }) else {
            return nil
        }

        var updated = routes
        updated[targetIndex] = target.replacing(state: .active, testedAt: testedAt)
        for index in updated.indices where replacementIds.contains(updated[index].id) {
            let route = updated[index]
            updated[index] = route.replacing(
                state: .draining,
                testedAt: route.testedAt,
                drainAfter: overlapUntil
            )
        }
        return try transitioning(routes: updated, signingKey: signingKey, issuedAt: issuedAt)
    }

    public func revokingDrainedRoute(
        _ routeId: RelationshipRouteID,
        signingKey: SigningKeyPair,
        issuedAt: Date
    ) throws -> RelationshipRouteSetV2? {
        guard let index = routes.firstIndex(where: { $0.id == routeId }) else { return nil }
        let route = routes[index]
        if route.state == .revoked { return self }
        guard route.state == .draining,
              let drainAfter = route.drainAfter,
              issuedAt >= drainAfter else {
            return nil
        }

        var updated = routes
        updated[index] = route.replacing(
            state: .revoked,
            testedAt: route.testedAt,
            drainAfter: drainAfter,
            revokedAt: issuedAt
        )
        return try transitioning(routes: updated, signingKey: signingKey, issuedAt: issuedAt)
    }

    public func abandoningTestingRoute(
        _ routeId: RelationshipRouteID,
        signingKey: SigningKeyPair,
        issuedAt: Date
    ) throws -> RelationshipRouteSetV2? {
        guard let index = routes.firstIndex(where: { $0.id == routeId }) else { return nil }
        let route = routes[index]
        if route.state == .revoked { return self }
        guard route.state == .testing, issuedAt >= route.validFrom else { return nil }

        var updated = routes
        updated[index] = route.replacing(
            state: .revoked,
            testedAt: route.testedAt,
            revokedAt: issuedAt
        )
        return try transitioning(routes: updated, signingKey: signingKey, issuedAt: issuedAt)
    }

    private func transitioning(
        routes: [RelationshipRouteV2],
        signingKey: SigningKeyPair,
        issuedAt: Date
    ) throws -> RelationshipRouteSetV2? {
        guard verify(ownerSigningPublicKey: signingKey.publicKeyData),
              let digest,
              revision < UInt64.max,
              issuedAt.timeIntervalSince1970.isFinite,
              issuedAt >= self.issuedAt else {
            return nil
        }
        let result = try Self.signed(
            relationshipId: relationshipId,
            ownerInstallationHandle: ownerInstallationHandle,
            revision: revision + 1,
            previousDigest: digest,
            routes: routes,
            issuedAt: issuedAt,
            signingKey: signingKey
        )
        return result.isStructurallyValid ? result : nil
    }

    private static func signed(
        relationshipId: UUID,
        ownerInstallationHandle: RelationshipInstallationHandle,
        revision: UInt64,
        previousDigest: Data?,
        routes: [RelationshipRouteV2],
        issuedAt: Date,
        signingKey: SigningKeyPair
    ) throws -> RelationshipRouteSetV2 {
        let ordered = routes.sorted(by: routeOrdering)
        let payload = RelationshipRouteSetSignaturePayloadV2(
            version: NoctweaveArchitectureV2.version,
            relationshipId: relationshipId,
            ownerInstallationHandle: ownerInstallationHandle,
            revision: revision,
            previousDigest: previousDigest,
            routes: ordered,
            issuedAt: issuedAt
        )
        let encoded = try NoctweaveCoder.encode(payload, sortedKeys: true)
        return RelationshipRouteSetV2(
            relationshipId: relationshipId,
            ownerInstallationHandle: ownerInstallationHandle,
            revision: revision,
            previousDigest: previousDigest,
            routes: ordered,
            issuedAt: issuedAt,
            signature: try signingKey.sign(encoded)
        )
    }

    private var signaturePayload: RelationshipRouteSetSignaturePayloadV2 {
        RelationshipRouteSetSignaturePayloadV2(
            version: version,
            relationshipId: relationshipId,
            ownerInstallationHandle: ownerInstallationHandle,
            revision: revision,
            previousDigest: previousDigest,
            routes: routes,
            issuedAt: issuedAt
        )
    }

    private static func routeOrdering(_ lhs: RelationshipRouteV2, _ rhs: RelationshipRouteV2) -> Bool {
        lhs.id.rawValue.lexicographicallyPrecedes(rhs.id.rawValue)
    }
}

private struct RelationshipRouteSetSignaturePayloadV2: Codable {
    let version: Int
    let relationshipId: UUID
    let ownerInstallationHandle: RelationshipInstallationHandle
    let revision: UInt64
    let previousDigest: Data?
    let routes: [RelationshipRouteV2]
    let issuedAt: Date
}

private extension RelayEndpoint {
    var isStructurallyValidRelationshipRouteEndpointV2: Bool {
        let normalizedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedHost.isEmpty,
              normalizedHost == host,
              normalizedHost.utf8.count <= 255,
              normalizedHost.unicodeScalars.allSatisfy({
                  !CharacterSet.controlCharacters.contains($0)
              }),
              port > 0,
              tlsCertificateFingerprintSHA256.map({ $0.count == 32 }) ?? true,
              directorySigningPublicKey.map({ SigningKeyPair.isValidPublicKey($0) }) ?? true else {
            return false
        }
        return true
    }

    /// A route capability is write authority, not merely metadata. Active
    /// relationship routes therefore require authenticated transport encryption.
    /// Literal loopback is the only exception for same-host development and
    /// operator-local relay access; private-LAN cleartext is intentionally not
    /// inferred from an address range.
    var isConfidentialCapabilityTransportV2: Bool {
        if useTLS { return true }
        let normalizedHost = host.lowercased()
        if normalizedHost == "localhost"
            || normalizedHost == "::1"
            || normalizedHost == "[::1]" {
            return true
        }
        let octets = normalizedHost.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4,
              octets.allSatisfy({ UInt8($0) != nil }) else {
            return false
        }
        return octets.first == "127"
    }
}

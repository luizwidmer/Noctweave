import CryptoKit
import Foundation

/// Protocol models for an independent, lease-bounded relay route. This module
/// is deliberately not advertised by any relay capability manifest yet.
///
/// An opaque route is not an alias for an inbox. It has no account, identity,
/// generation, endpoint, relationship, provider, or owner field. Relays see a
/// random route identifier and domain-separated credential digests only.
public enum NoctweaveOpaqueRoutesV2 {
    public static let version = 2
    public static let advertisedByDefault = false

    public static let credentialBytes = 32
    public static let digestBytes = 32
    public static let minimumLeaseDuration: TimeInterval = 5 * 60
    public static let maximumLeaseDuration: TimeInterval = 30 * 24 * 60 * 60
    public static let maximumAuthorizationClockSkew: TimeInterval = 5 * 60
}

public enum OpaqueRouteV2Error: Error, Equatable {
    case invalidRouteIdentifier
    case invalidCredential
    case invalidIdempotencyKey
    case invalidPolicy
    case invalidLease
    case invalidRequest
    case confidentialTransportRequired
    case invalidAuthorization
    case authorizationExpired
    case authorizationReplay
    case authorizationLedgerExhausted
    case routeAlreadyExists
    case routeMismatch
    case routeExpired
    case routeTornDown
    case idempotencyConflict
    case staleTransition
    case transitionOutOfOrder
    case transitionFork
    case renewalSequenceExhausted
}

// MARK: - Opaque fixed-size values

public struct OpaqueReceiveRouteIDV2: Codable, Equatable, Hashable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let rawValue: Data

    private enum CodingKeys: String, CodingKey { case rawValue }

    init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public static func generate() -> OpaqueReceiveRouteIDV2 {
        OpaqueReceiveRouteIDV2(rawValue: opaqueRouteRandomValue())
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawValue = try container.decode(Data.self, forKey: .rawValue)
        guard opaqueRouteIsValidFixedValue(rawValue) else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawValue,
                in: container,
                debugDescription: "Opaque route identifier must be a nonzero 32-byte value"
            )
        }
        self.rawValue = rawValue
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rawValue, forKey: .rawValue)
    }

    public var isStructurallyValid: Bool {
        opaqueRouteIsValidFixedValue(rawValue)
    }

    public var description: String { "OpaqueReceiveRouteIDV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

public struct OpaqueRouteIdempotencyKeyV2: Codable, Equatable, Hashable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let rawValue: Data

    private enum CodingKeys: String, CodingKey { case rawValue }

    init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public static func generate() -> OpaqueRouteIdempotencyKeyV2 {
        OpaqueRouteIdempotencyKeyV2(rawValue: opaqueRouteRandomValue())
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawValue = try container.decode(Data.self, forKey: .rawValue)
        guard opaqueRouteIsValidFixedValue(rawValue) else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawValue,
                in: container,
                debugDescription: "Opaque route idempotency key must be a nonzero 32-byte value"
            )
        }
        self.rawValue = rawValue
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rawValue, forKey: .rawValue)
    }

    public var isStructurallyValid: Bool {
        opaqueRouteIsValidFixedValue(rawValue)
    }

    public var description: String { "OpaqueRouteIdempotencyKeyV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

public struct OpaqueRouteProofNonceV2: Codable, Equatable, Hashable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let rawValue: Data

    private enum CodingKeys: String, CodingKey { case rawValue }

    init(rawValue: Data) {
        self.rawValue = rawValue
    }

    public static func generate() -> OpaqueRouteProofNonceV2 {
        OpaqueRouteProofNonceV2(rawValue: opaqueRouteRandomValue())
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawValue = try container.decode(Data.self, forKey: .rawValue)
        guard opaqueRouteIsValidFixedValue(rawValue) else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawValue,
                in: container,
                debugDescription: "Opaque route proof nonce must be a nonzero 32-byte value"
            )
        }
        self.rawValue = rawValue
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rawValue, forKey: .rawValue)
    }

    public var isStructurallyValid: Bool {
        opaqueRouteIsValidFixedValue(rawValue)
    }

    public var description: String { "OpaqueRouteProofNonceV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

// Separate nominal types keep one authority from being accidentally supplied
// to an API for another authority. Their raw bytes are client-only material.
public struct RouteSendCapabilityV2: Codable, Equatable, Hashable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let rawValue: Data

    init(rawValue: Data) { self.rawValue = rawValue }

    public static func generate() -> RouteSendCapabilityV2 {
        RouteSendCapabilityV2(rawValue: opaqueRouteRandomValue())
    }

    public init(from decoder: Decoder) throws {
        let value = try opaqueRouteDecodeCredential(from: decoder)
        self.init(rawValue: value)
    }

    public func encode(to encoder: Encoder) throws {
        try opaqueRouteEncodeCredential(rawValue, to: encoder)
    }

    public var isStructurallyValid: Bool { opaqueRouteIsValidFixedValue(rawValue) }
    public var description: String { "RouteSendCapabilityV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

public struct RouteReadCredentialV2: Codable, Equatable, Hashable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let rawValue: Data

    init(rawValue: Data) { self.rawValue = rawValue }

    public static func generate() -> RouteReadCredentialV2 {
        RouteReadCredentialV2(rawValue: opaqueRouteRandomValue())
    }

    public init(from decoder: Decoder) throws {
        let value = try opaqueRouteDecodeCredential(from: decoder)
        self.init(rawValue: value)
    }

    public func encode(to encoder: Encoder) throws {
        try opaqueRouteEncodeCredential(rawValue, to: encoder)
    }

    public var isStructurallyValid: Bool { opaqueRouteIsValidFixedValue(rawValue) }
    public var description: String { "RouteReadCredentialV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

public struct RouteRenewCapabilityV2: Codable, Equatable, Hashable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let rawValue: Data

    init(rawValue: Data) { self.rawValue = rawValue }

    public static func generate() -> RouteRenewCapabilityV2 {
        RouteRenewCapabilityV2(rawValue: opaqueRouteRandomValue())
    }

    public init(from decoder: Decoder) throws {
        let value = try opaqueRouteDecodeCredential(from: decoder)
        self.init(rawValue: value)
    }

    public func encode(to encoder: Encoder) throws {
        try opaqueRouteEncodeCredential(rawValue, to: encoder)
    }

    public var isStructurallyValid: Bool { opaqueRouteIsValidFixedValue(rawValue) }
    public var description: String { "RouteRenewCapabilityV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

public struct RouteTeardownCapabilityV2: Codable, Equatable, Hashable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let rawValue: Data

    init(rawValue: Data) { self.rawValue = rawValue }

    public static func generate() -> RouteTeardownCapabilityV2 {
        RouteTeardownCapabilityV2(rawValue: opaqueRouteRandomValue())
    }

    public init(from decoder: Decoder) throws {
        let value = try opaqueRouteDecodeCredential(from: decoder)
        self.init(rawValue: value)
    }

    public func encode(to encoder: Encoder) throws {
        try opaqueRouteEncodeCredential(rawValue, to: encoder)
    }

    public var isStructurallyValid: Bool { opaqueRouteIsValidFixedValue(rawValue) }
    public var description: String { "RouteTeardownCapabilityV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

// MARK: - Fixed policy buckets and bounded leases

public enum OpaqueRoutePaddingBucketV2: UInt32, Codable, CaseIterable {
    case bytes4096 = 4_096
    case bytes16384 = 16_384
    case bytes65536 = 65_536
}

public enum OpaqueRouteRetentionBucketV2: UInt32, Codable, CaseIterable {
    case oneHour = 3_600
    case sixHours = 21_600
    case oneDay = 86_400
    case sevenDays = 604_800
}

public enum OpaqueRouteQuotaBucketV2: UInt32, Codable, CaseIterable {
    case packets64 = 64
    case packets256 = 256
    case packets1024 = 1_024
}

public enum OpaqueRouteTransportRequirementV2: String, Codable, Equatable {
    case confidentialAuthenticated
}

public struct OpaqueRoutePolicyV2: Codable, Equatable {
    public let paddingBucket: OpaqueRoutePaddingBucketV2
    public let retentionBucket: OpaqueRouteRetentionBucketV2
    public let quotaBucket: OpaqueRouteQuotaBucketV2
    public let transportRequirement: OpaqueRouteTransportRequirementV2

    public init(
        paddingBucket: OpaqueRoutePaddingBucketV2,
        retentionBucket: OpaqueRouteRetentionBucketV2,
        quotaBucket: OpaqueRouteQuotaBucketV2
    ) {
        self.paddingBucket = paddingBucket
        self.retentionBucket = retentionBucket
        self.quotaBucket = quotaBucket
        self.transportRequirement = .confidentialAuthenticated
    }

    public var maximumStoredBytes: UInt64 {
        UInt64(paddingBucket.rawValue) * UInt64(quotaBucket.rawValue)
    }

    public var isStructurallyValid: Bool {
        transportRequirement == .confidentialAuthenticated
            && maximumStoredBytes <= 64 * 1_024 * 1_024
    }
}

public struct OpaqueRouteLeaseV2: Codable, Equatable {
    public let issuedAt: Date
    public let lastRenewedAt: Date
    public let expiresAt: Date
    public let renewalSequence: UInt64
    public let policy: OpaqueRoutePolicyV2

    public init(
        issuedAt: Date,
        expiresAt: Date,
        renewalSequence: UInt64 = 0,
        policy: OpaqueRoutePolicyV2
    ) throws {
        self.issuedAt = issuedAt
        self.lastRenewedAt = issuedAt
        self.expiresAt = expiresAt
        self.renewalSequence = renewalSequence
        self.policy = policy
        guard isStructurallyValid else { throw OpaqueRouteV2Error.invalidLease }
    }

    private init(
        issuedAt: Date,
        lastRenewedAt: Date,
        expiresAt: Date,
        renewalSequence: UInt64,
        policy: OpaqueRoutePolicyV2
    ) {
        self.issuedAt = issuedAt
        self.lastRenewedAt = lastRenewedAt
        self.expiresAt = expiresAt
        self.renewalSequence = renewalSequence
        self.policy = policy
    }

    public var isStructurallyValid: Bool {
        guard issuedAt.timeIntervalSince1970.isFinite,
              lastRenewedAt.timeIntervalSince1970.isFinite,
              expiresAt.timeIntervalSince1970.isFinite,
              issuedAt <= lastRenewedAt,
              lastRenewedAt < expiresAt,
              policy.isStructurallyValid,
              renewalSequence < UInt64.max else {
            return false
        }
        let remaining = expiresAt.timeIntervalSince(lastRenewedAt)
        return remaining >= NoctweaveOpaqueRoutesV2.minimumLeaseDuration
            && remaining <= NoctweaveOpaqueRoutesV2.maximumLeaseDuration
    }

    public func isActive(at date: Date) -> Bool {
        date.timeIntervalSince1970.isFinite && date >= issuedAt && date < expiresAt
    }

    fileprivate func renewing(at renewedAt: Date, through newExpiry: Date) throws -> OpaqueRouteLeaseV2 {
        guard renewalSequence < UInt64.max - 1 else {
            throw OpaqueRouteV2Error.renewalSequenceExhausted
        }
        guard renewedAt.timeIntervalSince1970.isFinite,
              newExpiry.timeIntervalSince1970.isFinite,
              renewedAt >= lastRenewedAt,
              renewedAt < expiresAt,
              newExpiry > expiresAt else {
            throw OpaqueRouteV2Error.invalidLease
        }
        let renewed = OpaqueRouteLeaseV2(
            issuedAt: issuedAt,
            lastRenewedAt: renewedAt,
            expiresAt: newExpiry,
            renewalSequence: renewalSequence + 1,
            policy: policy
        )
        guard renewed.isStructurallyValid else { throw OpaqueRouteV2Error.invalidLease }
        return renewed
    }
}

// MARK: - Authorization proofs

public enum OpaqueRouteAuthorityV2: String, Codable, Equatable, CaseIterable {
    case send
    case read
    case renew
    case teardown
}

public struct OpaqueRouteAuthorizationProofV2: Codable, Equatable {
    public let authority: OpaqueRouteAuthorityV2
    public let nonce: OpaqueRouteProofNonceV2
    public let operationDigest: Data
    public let authorizedAt: Date
    public let mac: Data

    public var isStructurallyValid: Bool {
        nonce.isStructurallyValid
            && opaqueRouteIsValidDigest(operationDigest)
            && authorizedAt.timeIntervalSince1970.isFinite
            && mac.count == NoctweaveOpaqueRoutesV2.digestBytes
    }

    fileprivate static func make(
        authority: OpaqueRouteAuthorityV2,
        routeID: OpaqueReceiveRouteIDV2,
        operationDigest: Data,
        authorizedAt: Date,
        nonce: OpaqueRouteProofNonceV2,
        secret: Data
    ) throws -> OpaqueRouteAuthorizationProofV2 {
        guard routeID.isStructurallyValid,
              opaqueRouteIsValidDigest(operationDigest),
              authorizedAt.timeIntervalSince1970.isFinite,
              nonce.isStructurallyValid,
              opaqueRouteIsValidFixedValue(secret) else {
            throw OpaqueRouteV2Error.invalidRequest
        }
        let material = try opaqueRouteAuthorizationMaterial(
            authority: authority,
            routeID: routeID,
            operationDigest: operationDigest,
            authorizedAt: authorizedAt,
            nonce: nonce
        )
        let mac = Data(HMAC<SHA256>.authenticationCode(
            for: material,
            using: SymmetricKey(data: secret)
        ))
        return OpaqueRouteAuthorizationProofV2(
            authority: authority,
            nonce: nonce,
            operationDigest: operationDigest,
            authorizedAt: authorizedAt,
            mac: mac
        )
    }

    fileprivate func verify(
        expectedAuthority: OpaqueRouteAuthorityV2,
        routeID: OpaqueReceiveRouteIDV2,
        operationDigest: Data,
        secret: Data
    ) -> Bool {
        guard isStructurallyValid,
              authority == expectedAuthority,
              self.operationDigest == operationDigest,
              opaqueRouteIsValidFixedValue(secret),
              let material = try? opaqueRouteAuthorizationMaterial(
                  authority: expectedAuthority,
                  routeID: routeID,
                  operationDigest: operationDigest,
                  authorizedAt: authorizedAt,
                  nonce: nonce
              ) else {
            return false
        }
        return HMAC<SHA256>.isValidAuthenticationCode(
            mac,
            authenticating: material,
            using: SymmetricKey(data: secret)
        )
    }

    fileprivate var replayDigest: Data? {
        guard isStructurallyValid,
              let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else {
            return nil
        }
        return opaqueRouteDigest(
            domain: "org.noctweave.opaque-route.authorization-replay/v2",
            components: [encoded]
        )
    }
}

/// A fail-closed, bounded nonce ledger for send/read authorization proofs.
///
/// Proofs are retained through the complete authorization freshness window.
/// After that point the proof can no longer pass freshness validation, so its
/// replay digest can be pruned without making it usable again. The persisted
/// high-water mark prevents a local wall-clock rollback from reopening a
/// freshness window that this relay has already passed.
public struct OpaqueRouteAuthorizationReplayLedgerV2: Codable, Equatable {
    public static let maximumEntries = 4_096

    private struct Entry: Codable, Equatable {
        let digest: Data
        let expiresAt: Date
    }

    private var entriesByDigest: [Data: Date] = [:]
    private var observedAtHighWatermark: Date?

    private enum CodingKeys: String, CodingKey {
        case entries
        case observedAtHighWatermark
    }

    public init() {}

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let entries = try container.decode([Entry].self, forKey: .entries)
        let highWatermark = try container.decodeIfPresent(
            Date.self,
            forKey: .observedAtHighWatermark
        )
        guard entries.count <= Self.maximumEntries,
              entries.allSatisfy({
                  $0.digest.count == NoctweaveOpaqueRoutesV2.digestBytes
                      && $0.expiresAt.timeIntervalSince1970.isFinite
              }),
              Set(entries.map(\.digest)).count == entries.count,
              highWatermark?.timeIntervalSince1970.isFinite != false else {
            throw DecodingError.dataCorruptedError(
                forKey: .entries,
                in: container,
                debugDescription: "Opaque route replay ledger must contain unique, bounded, finite entries"
            )
        }
        if let highWatermark,
           entries.contains(where: { $0.expiresAt < highWatermark }) {
            throw DecodingError.dataCorruptedError(
                forKey: .entries,
                in: container,
                debugDescription: "Opaque route replay ledger contains entries older than its persisted time high-water mark"
            )
        }
        entriesByDigest = Dictionary(
            uniqueKeysWithValues: entries.map { ($0.digest, $0.expiresAt) }
        )
        observedAtHighWatermark = highWatermark
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        let deterministicEntries = entriesByDigest.map {
            Entry(digest: $0.key, expiresAt: $0.value)
        }.sorted {
            $0.digest.lexicographicallyPrecedes($1.digest)
        }
        try container.encode(deterministicEntries, forKey: .entries)
        try container.encodeIfPresent(
            observedAtHighWatermark,
            forKey: .observedAtHighWatermark
        )
    }

    public var count: Int { entriesByDigest.count }

    fileprivate mutating func monotonicTime(_ receivedAt: Date) throws -> Date {
        guard receivedAt.timeIntervalSince1970.isFinite else {
            throw OpaqueRouteV2Error.invalidRequest
        }
        let effectiveTime = max(receivedAt, observedAtHighWatermark ?? receivedAt)
        observedAtHighWatermark = effectiveTime
        entriesByDigest = entriesByDigest.filter { $0.value >= effectiveTime }
        return effectiveTime
    }

    fileprivate mutating func consume(
        _ proof: OpaqueRouteAuthorizationProofV2,
        receivedAt: Date
    ) throws {
        guard let digest = proof.replayDigest else {
            throw OpaqueRouteV2Error.invalidAuthorization
        }
        guard entriesByDigest[digest] == nil else {
            throw OpaqueRouteV2Error.authorizationReplay
        }
        guard entriesByDigest.count < Self.maximumEntries else {
            throw OpaqueRouteV2Error.authorizationLedgerExhausted
        }
        let expiresAt = proof.authorizedAt.addingTimeInterval(
            NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew
        )
        guard expiresAt.timeIntervalSince1970.isFinite, expiresAt >= receivedAt else {
            throw OpaqueRouteV2Error.authorizationExpired
        }
        entriesByDigest[digest] = expiresAt
    }
}

// MARK: - Client-only capability material

public struct OpaqueRouteClientCapabilityMaterialV2: Codable, Equatable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let routeID: OpaqueReceiveRouteIDV2
    public let sendCapability: RouteSendCapabilityV2
    public let readCredential: RouteReadCredentialV2
    public let renewCapability: RouteRenewCapabilityV2
    public let teardownCapability: RouteTeardownCapabilityV2

    public init(
        routeID: OpaqueReceiveRouteIDV2 = .generate(),
        sendCapability: RouteSendCapabilityV2 = .generate(),
        readCredential: RouteReadCredentialV2 = .generate(),
        renewCapability: RouteRenewCapabilityV2 = .generate(),
        teardownCapability: RouteTeardownCapabilityV2 = .generate()
    ) throws {
        self.routeID = routeID
        self.sendCapability = sendCapability
        self.readCredential = readCredential
        self.renewCapability = renewCapability
        self.teardownCapability = teardownCapability
        guard isStructurallyValid else { throw OpaqueRouteV2Error.invalidCredential }
    }

    public var isStructurallyValid: Bool {
        routeID.isStructurallyValid
            && sendCapability.isStructurallyValid
            && readCredential.isStructurallyValid
            && renewCapability.isStructurallyValid
            && teardownCapability.isStructurallyValid
            && Set([
                sendCapability.rawValue,
                readCredential.rawValue,
                renewCapability.rawValue,
                teardownCapability.rawValue,
            ]).count == 4
    }

    public func makeCreateRequest(
        lease: OpaqueRouteLeaseV2,
        idempotencyKey: OpaqueRouteIdempotencyKeyV2,
        nonce: OpaqueRouteProofNonceV2 = .generate()
    ) throws -> OpaqueRouteCreateRequestV2 {
        guard isStructurallyValid, lease.isStructurallyValid else {
            throw OpaqueRouteV2Error.invalidRequest
        }
        let unsigned = OpaqueRouteCreateRequestV2.Unsigned(
            version: NoctweaveOpaqueRoutesV2.version,
            routeID: routeID,
            sendCapabilityDigest: opaqueRouteCredentialDigest(.send, sendCapability.rawValue),
            readCredentialDigest: opaqueRouteCredentialDigest(.read, readCredential.rawValue),
            renewCapabilityDigest: opaqueRouteCredentialDigest(.renew, renewCapability.rawValue),
            teardownCapabilityDigest: opaqueRouteCredentialDigest(.teardown, teardownCapability.rawValue),
            lease: lease,
            idempotencyKey: idempotencyKey
        )
        let digest = try unsigned.digest()
        let proof = try OpaqueRouteAuthorizationProofV2.make(
            authority: .renew,
            routeID: routeID,
            operationDigest: digest,
            authorizedAt: lease.issuedAt,
            nonce: nonce,
            secret: renewCapability.rawValue
        )
        return OpaqueRouteCreateRequestV2(unsigned: unsigned, authorization: proof)
    }

    public func makeRenewRequest(
        current: OpaqueReceiveRouteV2,
        newExpiry: Date,
        authorizedAt: Date,
        idempotencyKey: OpaqueRouteIdempotencyKeyV2,
        nonce: OpaqueRouteProofNonceV2 = .generate()
    ) throws -> OpaqueRouteRenewRequestV2 {
        guard current.routeID == routeID,
              current.status == .active,
              current.lease.renewalSequence < UInt64.max - 1 else {
            throw OpaqueRouteV2Error.invalidRequest
        }
        let unsigned = OpaqueRouteRenewRequestV2.Unsigned(
            version: NoctweaveOpaqueRoutesV2.version,
            routeID: routeID,
            renewalSequence: current.lease.renewalSequence + 1,
            previousTransitionDigest: current.lastTransitionDigest,
            newExpiry: newExpiry,
            authorizedAt: authorizedAt,
            idempotencyKey: idempotencyKey
        )
        let digest = try unsigned.digest()
        let proof = try OpaqueRouteAuthorizationProofV2.make(
            authority: .renew,
            routeID: routeID,
            operationDigest: digest,
            authorizedAt: authorizedAt,
            nonce: nonce,
            secret: renewCapability.rawValue
        )
        return OpaqueRouteRenewRequestV2(unsigned: unsigned, authorization: proof)
    }

    public func makeTeardownRequest(
        current: OpaqueReceiveRouteV2,
        authorizedAt: Date,
        idempotencyKey: OpaqueRouteIdempotencyKeyV2,
        nonce: OpaqueRouteProofNonceV2 = .generate()
    ) throws -> OpaqueRouteTeardownRequestV2 {
        guard current.routeID == routeID else { throw OpaqueRouteV2Error.routeMismatch }
        let unsigned = OpaqueRouteTeardownRequestV2.Unsigned(
            version: NoctweaveOpaqueRoutesV2.version,
            routeID: routeID,
            renewalSequence: current.lease.renewalSequence,
            previousTransitionDigest: current.lastTransitionDigest,
            authorizedAt: authorizedAt,
            idempotencyKey: idempotencyKey
        )
        let digest = try unsigned.digest()
        let proof = try OpaqueRouteAuthorizationProofV2.make(
            authority: .teardown,
            routeID: routeID,
            operationDigest: digest,
            authorizedAt: authorizedAt,
            nonce: nonce,
            secret: teardownCapability.rawValue
        )
        return OpaqueRouteTeardownRequestV2(unsigned: unsigned, authorization: proof)
    }

    public func makeSendAuthorization(
        operationDigest: Data,
        authorizedAt: Date,
        nonce: OpaqueRouteProofNonceV2 = .generate()
    ) throws -> OpaqueRouteAuthorizationProofV2 {
        try OpaqueRouteAuthorizationProofV2.make(
            authority: .send,
            routeID: routeID,
            operationDigest: operationDigest,
            authorizedAt: authorizedAt,
            nonce: nonce,
            secret: sendCapability.rawValue
        )
    }

    public func makeReadAuthorization(
        operationDigest: Data,
        authorizedAt: Date,
        nonce: OpaqueRouteProofNonceV2 = .generate()
    ) throws -> OpaqueRouteAuthorizationProofV2 {
        try OpaqueRouteAuthorizationProofV2.make(
            authority: .read,
            routeID: routeID,
            operationDigest: operationDigest,
            authorizedAt: authorizedAt,
            nonce: nonce,
            secret: readCredential.rawValue
        )
    }

    public var description: String { "OpaqueRouteClientCapabilityMaterialV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

// MARK: - Transition requests

public struct OpaqueRouteCreateRequestV2: Codable, Equatable {
    fileprivate struct Unsigned: Codable, Equatable {
        let version: Int
        let routeID: OpaqueReceiveRouteIDV2
        let sendCapabilityDigest: Data
        let readCredentialDigest: Data
        let renewCapabilityDigest: Data
        let teardownCapabilityDigest: Data
        let lease: OpaqueRouteLeaseV2
        let idempotencyKey: OpaqueRouteIdempotencyKeyV2

        func digest() throws -> Data {
            opaqueRouteDigest(
                domain: "org.noctweave.opaque-route.create/v2",
                components: [try NoctweaveCoder.encode(self, sortedKeys: true)]
            )
        }
    }

    public let version: Int
    public let routeID: OpaqueReceiveRouteIDV2
    public let sendCapabilityDigest: Data
    public let readCredentialDigest: Data
    public let renewCapabilityDigest: Data
    public let teardownCapabilityDigest: Data
    public let lease: OpaqueRouteLeaseV2
    public let idempotencyKey: OpaqueRouteIdempotencyKeyV2
    public let authorization: OpaqueRouteAuthorizationProofV2

    fileprivate init(unsigned: Unsigned, authorization: OpaqueRouteAuthorizationProofV2) {
        version = unsigned.version
        routeID = unsigned.routeID
        sendCapabilityDigest = unsigned.sendCapabilityDigest
        readCredentialDigest = unsigned.readCredentialDigest
        renewCapabilityDigest = unsigned.renewCapabilityDigest
        teardownCapabilityDigest = unsigned.teardownCapabilityDigest
        lease = unsigned.lease
        idempotencyKey = unsigned.idempotencyKey
        self.authorization = authorization
    }

    fileprivate var unsigned: Unsigned {
        Unsigned(
            version: version,
            routeID: routeID,
            sendCapabilityDigest: sendCapabilityDigest,
            readCredentialDigest: readCredentialDigest,
            renewCapabilityDigest: renewCapabilityDigest,
            teardownCapabilityDigest: teardownCapabilityDigest,
            lease: lease,
            idempotencyKey: idempotencyKey
        )
    }

    public var transitionDigest: Data? { try? unsigned.digest() }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveOpaqueRoutesV2.version,
              routeID.isStructurallyValid,
              lease.isStructurallyValid,
              lease.renewalSequence == 0,
              idempotencyKey.isStructurallyValid,
              [sendCapabilityDigest, readCredentialDigest, renewCapabilityDigest, teardownCapabilityDigest]
                .allSatisfy(opaqueRouteIsValidDigest),
              Set([sendCapabilityDigest, readCredentialDigest, renewCapabilityDigest, teardownCapabilityDigest]).count == 4,
              let transitionDigest else {
            return false
        }
        return authorization.isStructurallyValid
            && authorization.authority == .renew
            && authorization.authorizedAt == lease.issuedAt
            && authorization.operationDigest == transitionDigest
    }
}

public struct OpaqueRouteRenewRequestV2: Codable, Equatable {
    fileprivate struct Unsigned: Codable, Equatable {
        let version: Int
        let routeID: OpaqueReceiveRouteIDV2
        let renewalSequence: UInt64
        let previousTransitionDigest: Data
        let newExpiry: Date
        let authorizedAt: Date
        let idempotencyKey: OpaqueRouteIdempotencyKeyV2

        func digest() throws -> Data {
            opaqueRouteDigest(
                domain: "org.noctweave.opaque-route.renew/v2",
                components: [try NoctweaveCoder.encode(self, sortedKeys: true)]
            )
        }
    }

    public let version: Int
    public let routeID: OpaqueReceiveRouteIDV2
    public let renewalSequence: UInt64
    public let previousTransitionDigest: Data
    public let newExpiry: Date
    public let authorizedAt: Date
    public let idempotencyKey: OpaqueRouteIdempotencyKeyV2
    public let authorization: OpaqueRouteAuthorizationProofV2

    fileprivate init(unsigned: Unsigned, authorization: OpaqueRouteAuthorizationProofV2) {
        version = unsigned.version
        routeID = unsigned.routeID
        renewalSequence = unsigned.renewalSequence
        previousTransitionDigest = unsigned.previousTransitionDigest
        newExpiry = unsigned.newExpiry
        authorizedAt = unsigned.authorizedAt
        idempotencyKey = unsigned.idempotencyKey
        self.authorization = authorization
    }

    fileprivate var unsigned: Unsigned {
        Unsigned(
            version: version,
            routeID: routeID,
            renewalSequence: renewalSequence,
            previousTransitionDigest: previousTransitionDigest,
            newExpiry: newExpiry,
            authorizedAt: authorizedAt,
            idempotencyKey: idempotencyKey
        )
    }

    public var transitionDigest: Data? { try? unsigned.digest() }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveOpaqueRoutesV2.version,
              routeID.isStructurallyValid,
              renewalSequence > 0,
              opaqueRouteIsValidDigest(previousTransitionDigest),
              newExpiry.timeIntervalSince1970.isFinite,
              authorizedAt.timeIntervalSince1970.isFinite,
              idempotencyKey.isStructurallyValid,
              let transitionDigest else {
            return false
        }
        return authorization.isStructurallyValid
            && authorization.authority == .renew
            && authorization.authorizedAt == authorizedAt
            && authorization.operationDigest == transitionDigest
    }
}

public struct OpaqueRouteTeardownRequestV2: Codable, Equatable {
    fileprivate struct Unsigned: Codable, Equatable {
        let version: Int
        let routeID: OpaqueReceiveRouteIDV2
        let renewalSequence: UInt64
        let previousTransitionDigest: Data
        let authorizedAt: Date
        let idempotencyKey: OpaqueRouteIdempotencyKeyV2

        func digest() throws -> Data {
            opaqueRouteDigest(
                domain: "org.noctweave.opaque-route.teardown/v2",
                components: [try NoctweaveCoder.encode(self, sortedKeys: true)]
            )
        }
    }

    public let version: Int
    public let routeID: OpaqueReceiveRouteIDV2
    public let renewalSequence: UInt64
    public let previousTransitionDigest: Data
    public let authorizedAt: Date
    public let idempotencyKey: OpaqueRouteIdempotencyKeyV2
    public let authorization: OpaqueRouteAuthorizationProofV2

    fileprivate init(unsigned: Unsigned, authorization: OpaqueRouteAuthorizationProofV2) {
        version = unsigned.version
        routeID = unsigned.routeID
        renewalSequence = unsigned.renewalSequence
        previousTransitionDigest = unsigned.previousTransitionDigest
        authorizedAt = unsigned.authorizedAt
        idempotencyKey = unsigned.idempotencyKey
        self.authorization = authorization
    }

    fileprivate var unsigned: Unsigned {
        Unsigned(
            version: version,
            routeID: routeID,
            renewalSequence: renewalSequence,
            previousTransitionDigest: previousTransitionDigest,
            authorizedAt: authorizedAt,
            idempotencyKey: idempotencyKey
        )
    }

    public var transitionDigest: Data? { try? unsigned.digest() }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveOpaqueRoutesV2.version,
              routeID.isStructurallyValid,
              opaqueRouteIsValidDigest(previousTransitionDigest),
              authorizedAt.timeIntervalSince1970.isFinite,
              idempotencyKey.isStructurallyValid,
              let transitionDigest else {
            return false
        }
        return authorization.isStructurallyValid
            && authorization.authority == .teardown
            && authorization.authorizedAt == authorizedAt
            && authorization.operationDigest == transitionDigest
    }
}

// MARK: - Relay-safe route projection and state machine

public enum OpaqueReceiveRouteStatusV2: String, Codable, Equatable {
    case active
    case tornDown
}

/// Relay-safe state. This is the only route object intended for relay storage.
/// It deliberately contains credential digests instead of bearer secrets.
public struct OpaqueReceiveRouteV2: Codable, Equatable {
    public let version: Int
    public let routeID: OpaqueReceiveRouteIDV2
    public let sendCapabilityDigest: Data
    public let readCredentialDigest: Data
    public let renewCapabilityDigest: Data
    public let teardownCapabilityDigest: Data
    public let lease: OpaqueRouteLeaseV2
    public let status: OpaqueReceiveRouteStatusV2
    public let createdAt: Date
    public let tornDownAt: Date?
    public let creationIdempotencyKey: OpaqueRouteIdempotencyKeyV2
    public let creationDigest: Data
    public let lastIdempotencyKey: OpaqueRouteIdempotencyKeyV2
    public let lastTransitionDigest: Data

    private init(
        version: Int = NoctweaveOpaqueRoutesV2.version,
        routeID: OpaqueReceiveRouteIDV2,
        sendCapabilityDigest: Data,
        readCredentialDigest: Data,
        renewCapabilityDigest: Data,
        teardownCapabilityDigest: Data,
        lease: OpaqueRouteLeaseV2,
        status: OpaqueReceiveRouteStatusV2,
        createdAt: Date,
        tornDownAt: Date?,
        creationIdempotencyKey: OpaqueRouteIdempotencyKeyV2,
        creationDigest: Data,
        lastIdempotencyKey: OpaqueRouteIdempotencyKeyV2,
        lastTransitionDigest: Data
    ) {
        self.version = version
        self.routeID = routeID
        self.sendCapabilityDigest = sendCapabilityDigest
        self.readCredentialDigest = readCredentialDigest
        self.renewCapabilityDigest = renewCapabilityDigest
        self.teardownCapabilityDigest = teardownCapabilityDigest
        self.lease = lease
        self.status = status
        self.createdAt = createdAt
        self.tornDownAt = tornDownAt
        self.creationIdempotencyKey = creationIdempotencyKey
        self.creationDigest = creationDigest
        self.lastIdempotencyKey = lastIdempotencyKey
        self.lastTransitionDigest = lastTransitionDigest
    }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveOpaqueRoutesV2.version,
              routeID.isStructurallyValid,
              [sendCapabilityDigest, readCredentialDigest, renewCapabilityDigest, teardownCapabilityDigest]
                .allSatisfy(opaqueRouteIsValidDigest),
              Set([sendCapabilityDigest, readCredentialDigest, renewCapabilityDigest, teardownCapabilityDigest]).count == 4,
              lease.isStructurallyValid,
              createdAt == lease.issuedAt,
              createdAt.timeIntervalSince1970.isFinite,
              creationIdempotencyKey.isStructurallyValid,
              lastIdempotencyKey.isStructurallyValid,
              opaqueRouteIsValidDigest(creationDigest),
              opaqueRouteIsValidDigest(lastTransitionDigest) else {
            return false
        }
        switch status {
        case .active:
            return tornDownAt == nil
        case .tornDown:
            return tornDownAt.map({
                $0.timeIntervalSince1970.isFinite && $0 >= createdAt
            }) == true
        }
    }

    /// Confirms that client-held bearer material belongs to this relay-safe
    /// route projection without exposing any bearer bytes.
    public func matches(
        clientCapabilities: OpaqueRouteClientCapabilityMaterialV2
    ) -> Bool {
        isStructurallyValid
            && clientCapabilities.isStructurallyValid
            && clientCapabilities.routeID == routeID
            && opaqueRouteCredentialDigest(.send, clientCapabilities.sendCapability.rawValue)
                == sendCapabilityDigest
            && opaqueRouteCredentialDigest(.read, clientCapabilities.readCredential.rawValue)
                == readCredentialDigest
            && opaqueRouteCredentialDigest(.renew, clientCapabilities.renewCapability.rawValue)
                == renewCapabilityDigest
            && opaqueRouteCredentialDigest(.teardown, clientCapabilities.teardownCapability.rawValue)
                == teardownCapabilityDigest
    }

    /// Creates or idempotently reconciles a route. A retained torn-down state
    /// is a tombstone: even the original create request cannot resurrect it.
    public static func creating(
        from request: OpaqueRouteCreateRequestV2,
        presentedRenewCapability: RouteRenewCapabilityV2,
        existing: OpaqueReceiveRouteV2?,
        confidentialTransport: Bool,
        receivedAt: Date
    ) throws -> OpaqueReceiveRouteV2 {
        guard confidentialTransport else {
            throw OpaqueRouteV2Error.confidentialTransportRequired
        }
        guard request.isStructurallyValid,
              let transitionDigest = request.transitionDigest,
              receivedAt.timeIntervalSince1970.isFinite else {
            throw OpaqueRouteV2Error.invalidRequest
        }
        guard opaqueRouteCredentialDigest(.renew, presentedRenewCapability.rawValue)
                == request.renewCapabilityDigest,
              request.authorization.verify(
                  expectedAuthority: .renew,
                  routeID: request.routeID,
                  operationDigest: transitionDigest,
                  secret: presentedRenewCapability.rawValue
              ) else {
            throw OpaqueRouteV2Error.invalidAuthorization
        }

        if let existing {
            guard existing.routeID == request.routeID else {
                throw OpaqueRouteV2Error.routeMismatch
            }
            guard existing.status != .tornDown else {
                throw OpaqueRouteV2Error.routeTornDown
            }
            if existing.creationIdempotencyKey == request.idempotencyKey {
                guard existing.creationDigest == transitionDigest else {
                    throw OpaqueRouteV2Error.idempotencyConflict
                }
                return existing
            }
            throw OpaqueRouteV2Error.routeAlreadyExists
        }

        try opaqueRouteValidateAuthorizationTime(
            request.authorization.authorizedAt,
            at: receivedAt
        )
        guard request.lease.isActive(at: receivedAt) else {
            throw OpaqueRouteV2Error.routeExpired
        }
        let state = OpaqueReceiveRouteV2(
            routeID: request.routeID,
            sendCapabilityDigest: request.sendCapabilityDigest,
            readCredentialDigest: request.readCredentialDigest,
            renewCapabilityDigest: request.renewCapabilityDigest,
            teardownCapabilityDigest: request.teardownCapabilityDigest,
            lease: request.lease,
            status: .active,
            createdAt: request.lease.issuedAt,
            tornDownAt: nil,
            creationIdempotencyKey: request.idempotencyKey,
            creationDigest: transitionDigest,
            lastIdempotencyKey: request.idempotencyKey,
            lastTransitionDigest: transitionDigest
        )
        guard state.isStructurallyValid else { throw OpaqueRouteV2Error.invalidRequest }
        return state
    }

    public func applyingRenewal(
        _ request: OpaqueRouteRenewRequestV2,
        presentedCapability: RouteRenewCapabilityV2,
        confidentialTransport: Bool,
        receivedAt: Date
    ) throws -> OpaqueReceiveRouteV2 {
        guard confidentialTransport else {
            throw OpaqueRouteV2Error.confidentialTransportRequired
        }
        guard isStructurallyValid,
              request.isStructurallyValid,
              let transitionDigest = request.transitionDigest,
              receivedAt.timeIntervalSince1970.isFinite else {
            throw OpaqueRouteV2Error.invalidRequest
        }
        guard request.routeID == routeID else { throw OpaqueRouteV2Error.routeMismatch }

        if request.idempotencyKey == lastIdempotencyKey {
            guard transitionDigest == lastTransitionDigest else {
                throw OpaqueRouteV2Error.idempotencyConflict
            }
            guard opaqueRouteCredentialDigest(.renew, presentedCapability.rawValue)
                    == renewCapabilityDigest,
                  request.authorization.verify(
                      expectedAuthority: .renew,
                      routeID: routeID,
                      operationDigest: transitionDigest,
                      secret: presentedCapability.rawValue
                  ) else {
                throw OpaqueRouteV2Error.invalidAuthorization
            }
            return self
        }
        guard status == .active else { throw OpaqueRouteV2Error.routeTornDown }
        guard lease.isActive(at: receivedAt) else { throw OpaqueRouteV2Error.routeExpired }

        let expectedSequence = lease.renewalSequence + 1
        if request.renewalSequence < expectedSequence {
            throw request.renewalSequence == lease.renewalSequence
                ? OpaqueRouteV2Error.transitionFork
                : OpaqueRouteV2Error.staleTransition
        }
        guard request.renewalSequence == expectedSequence else {
            throw OpaqueRouteV2Error.transitionOutOfOrder
        }
        guard request.previousTransitionDigest == lastTransitionDigest else {
            throw OpaqueRouteV2Error.transitionFork
        }
        try opaqueRouteValidateAuthorizationTime(request.authorization.authorizedAt, at: receivedAt)
        guard request.authorizedAt >= lease.lastRenewedAt,
              opaqueRouteCredentialDigest(.renew, presentedCapability.rawValue)
                == renewCapabilityDigest,
              request.authorization.verify(
                  expectedAuthority: .renew,
                  routeID: routeID,
                  operationDigest: transitionDigest,
                  secret: presentedCapability.rawValue
              ) else {
            throw OpaqueRouteV2Error.invalidAuthorization
        }

        let renewedLease = try lease.renewing(
            at: request.authorizedAt,
            through: request.newExpiry
        )
        let result = OpaqueReceiveRouteV2(
            routeID: routeID,
            sendCapabilityDigest: sendCapabilityDigest,
            readCredentialDigest: readCredentialDigest,
            renewCapabilityDigest: renewCapabilityDigest,
            teardownCapabilityDigest: teardownCapabilityDigest,
            lease: renewedLease,
            status: .active,
            createdAt: createdAt,
            tornDownAt: nil,
            creationIdempotencyKey: creationIdempotencyKey,
            creationDigest: creationDigest,
            lastIdempotencyKey: request.idempotencyKey,
            lastTransitionDigest: transitionDigest
        )
        guard result.isStructurallyValid else { throw OpaqueRouteV2Error.invalidRequest }
        return result
    }

    public func applyingTeardown(
        _ request: OpaqueRouteTeardownRequestV2,
        presentedCapability: RouteTeardownCapabilityV2,
        confidentialTransport: Bool,
        receivedAt: Date
    ) throws -> OpaqueReceiveRouteV2 {
        guard confidentialTransport else {
            throw OpaqueRouteV2Error.confidentialTransportRequired
        }
        guard isStructurallyValid,
              request.isStructurallyValid,
              let transitionDigest = request.transitionDigest,
              receivedAt.timeIntervalSince1970.isFinite else {
            throw OpaqueRouteV2Error.invalidRequest
        }
        guard request.routeID == routeID else { throw OpaqueRouteV2Error.routeMismatch }

        if request.idempotencyKey == lastIdempotencyKey {
            guard transitionDigest == lastTransitionDigest else {
                throw OpaqueRouteV2Error.idempotencyConflict
            }
            guard opaqueRouteCredentialDigest(.teardown, presentedCapability.rawValue)
                    == teardownCapabilityDigest,
                  request.authorization.verify(
                      expectedAuthority: .teardown,
                      routeID: routeID,
                      operationDigest: transitionDigest,
                      secret: presentedCapability.rawValue
                  ) else {
                throw OpaqueRouteV2Error.invalidAuthorization
            }
            return self
        }
        guard status == .active else { throw OpaqueRouteV2Error.routeTornDown }
        if request.renewalSequence < lease.renewalSequence {
            throw OpaqueRouteV2Error.staleTransition
        }
        guard request.renewalSequence == lease.renewalSequence else {
            throw OpaqueRouteV2Error.transitionOutOfOrder
        }
        guard request.previousTransitionDigest == lastTransitionDigest else {
            throw OpaqueRouteV2Error.transitionFork
        }
        try opaqueRouteValidateAuthorizationTime(request.authorization.authorizedAt, at: receivedAt)
        guard opaqueRouteCredentialDigest(.teardown, presentedCapability.rawValue)
                == teardownCapabilityDigest,
              request.authorization.verify(
                  expectedAuthority: .teardown,
                  routeID: routeID,
                  operationDigest: transitionDigest,
                  secret: presentedCapability.rawValue
              ) else {
            throw OpaqueRouteV2Error.invalidAuthorization
        }

        let result = OpaqueReceiveRouteV2(
            routeID: routeID,
            sendCapabilityDigest: sendCapabilityDigest,
            readCredentialDigest: readCredentialDigest,
            renewCapabilityDigest: renewCapabilityDigest,
            teardownCapabilityDigest: teardownCapabilityDigest,
            lease: lease,
            status: .tornDown,
            createdAt: createdAt,
            tornDownAt: receivedAt,
            creationIdempotencyKey: creationIdempotencyKey,
            creationDigest: creationDigest,
            lastIdempotencyKey: request.idempotencyKey,
            lastTransitionDigest: transitionDigest
        )
        guard result.isStructurallyValid else { throw OpaqueRouteV2Error.invalidRequest }
        return result
    }

    public func authorizeSend(
        _ proof: OpaqueRouteAuthorizationProofV2,
        operationDigest: Data,
        presentedCapability: RouteSendCapabilityV2,
        confidentialTransport: Bool,
        receivedAt: Date,
        replayLedger: inout OpaqueRouteAuthorizationReplayLedgerV2
    ) throws {
        try authorizeUse(
            proof,
            expectedAuthority: .send,
            expectedCredentialDigest: sendCapabilityDigest,
            presentedSecret: presentedCapability.rawValue,
            operationDigest: operationDigest,
            confidentialTransport: confidentialTransport,
            receivedAt: receivedAt,
            replayLedger: &replayLedger
        )
    }

    public func authorizeRead(
        _ proof: OpaqueRouteAuthorizationProofV2,
        operationDigest: Data,
        presentedCredential: RouteReadCredentialV2,
        confidentialTransport: Bool,
        receivedAt: Date,
        replayLedger: inout OpaqueRouteAuthorizationReplayLedgerV2
    ) throws {
        try authorizeUse(
            proof,
            expectedAuthority: .read,
            expectedCredentialDigest: readCredentialDigest,
            presentedSecret: presentedCredential.rawValue,
            operationDigest: operationDigest,
            confidentialTransport: confidentialTransport,
            receivedAt: receivedAt,
            replayLedger: &replayLedger
        )
    }

    /// Authenticates an exact append retry that the relay has already
    /// durably accepted. Freshness and replay consumption are intentionally
    /// omitted: the caller must first prove that the packet identifier and
    /// complete operation digest match the retained accepted record.
    public func authenticateAcceptedSendRetry(
        _ proof: OpaqueRouteAuthorizationProofV2,
        operationDigest: Data,
        presentedCapability: RouteSendCapabilityV2,
        confidentialTransport: Bool
    ) throws {
        try authenticateAcceptedRetry(
            proof,
            expectedAuthority: .send,
            expectedCredentialDigest: sendCapabilityDigest,
            presentedSecret: presentedCapability.rawValue,
            operationDigest: operationDigest,
            confidentialTransport: confidentialTransport
        )
    }

    /// Authenticates an exact read/commit retry that the relay has already
    /// durably answered. The retained request identifier and digest are the
    /// idempotency boundary; this method cannot authorize a new operation.
    public func authenticateAcceptedReadRetry(
        _ proof: OpaqueRouteAuthorizationProofV2,
        operationDigest: Data,
        presentedCredential: RouteReadCredentialV2,
        confidentialTransport: Bool
    ) throws {
        try authenticateAcceptedRetry(
            proof,
            expectedAuthority: .read,
            expectedCredentialDigest: readCredentialDigest,
            presentedSecret: presentedCredential.rawValue,
            operationDigest: operationDigest,
            confidentialTransport: confidentialTransport
        )
    }

    private func authenticateAcceptedRetry(
        _ proof: OpaqueRouteAuthorizationProofV2,
        expectedAuthority: OpaqueRouteAuthorityV2,
        expectedCredentialDigest: Data,
        presentedSecret: Data,
        operationDigest: Data,
        confidentialTransport: Bool
    ) throws {
        guard confidentialTransport else {
            throw OpaqueRouteV2Error.confidentialTransportRequired
        }
        guard isStructurallyValid, opaqueRouteIsValidDigest(operationDigest) else {
            throw OpaqueRouteV2Error.invalidRequest
        }
        guard status == .active else { throw OpaqueRouteV2Error.routeTornDown }
        guard opaqueRouteCredentialDigest(expectedAuthority, presentedSecret)
                == expectedCredentialDigest,
              proof.verify(
                  expectedAuthority: expectedAuthority,
                  routeID: routeID,
                  operationDigest: operationDigest,
                  secret: presentedSecret
              ) else {
            throw OpaqueRouteV2Error.invalidAuthorization
        }
    }

    private func authorizeUse(
        _ proof: OpaqueRouteAuthorizationProofV2,
        expectedAuthority: OpaqueRouteAuthorityV2,
        expectedCredentialDigest: Data,
        presentedSecret: Data,
        operationDigest: Data,
        confidentialTransport: Bool,
        receivedAt: Date,
        replayLedger: inout OpaqueRouteAuthorizationReplayLedgerV2
    ) throws {
        guard confidentialTransport else {
            throw OpaqueRouteV2Error.confidentialTransportRequired
        }
        guard isStructurallyValid, opaqueRouteIsValidDigest(operationDigest) else {
            throw OpaqueRouteV2Error.invalidRequest
        }
        guard status == .active else { throw OpaqueRouteV2Error.routeTornDown }
        guard lease.isActive(at: receivedAt) else { throw OpaqueRouteV2Error.routeExpired }
        let effectiveReceivedAt = try replayLedger.monotonicTime(receivedAt)
        try opaqueRouteValidateAuthorizationTime(
            proof.authorizedAt,
            at: effectiveReceivedAt
        )
        guard opaqueRouteCredentialDigest(expectedAuthority, presentedSecret)
                == expectedCredentialDigest,
              proof.verify(
                  expectedAuthority: expectedAuthority,
                  routeID: routeID,
                  operationDigest: operationDigest,
                  secret: presentedSecret
              ) else {
            throw OpaqueRouteV2Error.invalidAuthorization
        }
        try replayLedger.consume(proof, receivedAt: effectiveReceivedAt)
    }
}

// MARK: - Private helpers

private struct OpaqueRouteCredentialCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil

    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

private func opaqueRouteDecodeCredential(from decoder: Decoder) throws -> Data {
    let key = OpaqueRouteCredentialCodingKey(stringValue: "rawValue")!
    let container = try decoder.container(keyedBy: OpaqueRouteCredentialCodingKey.self)
    let value = try container.decode(Data.self, forKey: key)
    guard opaqueRouteIsValidFixedValue(value) else {
        throw DecodingError.dataCorruptedError(
            forKey: key,
            in: container,
            debugDescription: "Opaque route credential must be a nonzero 32-byte value"
        )
    }
    return value
}

private func opaqueRouteEncodeCredential(_ value: Data, to encoder: Encoder) throws {
    guard opaqueRouteIsValidFixedValue(value) else {
        throw EncodingError.invalidValue(
            value,
            EncodingError.Context(
                codingPath: encoder.codingPath,
                debugDescription: "Opaque route credential must be a nonzero 32-byte value"
            )
        )
    }
    let key = OpaqueRouteCredentialCodingKey(stringValue: "rawValue")!
    var container = encoder.container(keyedBy: OpaqueRouteCredentialCodingKey.self)
    try container.encode(value, forKey: key)
}

private func opaqueRouteRandomValue() -> Data {
    var generator = SystemRandomNumberGenerator()
    while true {
        let value = Data((0..<NoctweaveOpaqueRoutesV2.credentialBytes).map { _ in
            UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
        })
        if opaqueRouteIsValidFixedValue(value) { return value }
    }
}

private func opaqueRouteIsValidFixedValue(_ value: Data) -> Bool {
    value.count == NoctweaveOpaqueRoutesV2.credentialBytes
        && value.contains(where: { $0 != 0 })
}

private func opaqueRouteIsValidDigest(_ value: Data) -> Bool {
    value.count == NoctweaveOpaqueRoutesV2.digestBytes
}

private func opaqueRouteCredentialDigest(
    _ authority: OpaqueRouteAuthorityV2,
    _ secret: Data
) -> Data {
    opaqueRouteDigest(
        domain: "org.noctweave.opaque-route.credential.\(authority.rawValue)/v2",
        components: [secret]
    )
}

private func opaqueRouteDigest(domain: String, components: [Data]) -> Data {
    var material = Data(domain.utf8)
    for component in components {
        var length = UInt64(component.count).bigEndian
        withUnsafeBytes(of: &length) { material.append(contentsOf: $0) }
        material.append(component)
    }
    return Data(SHA256.hash(data: material))
}

private struct OpaqueRouteAuthorizationMACPayloadV2: Codable {
    let version: Int
    let authority: OpaqueRouteAuthorityV2
    let routeID: OpaqueReceiveRouteIDV2
    let operationDigest: Data
    let authorizedAt: Date
    let nonce: OpaqueRouteProofNonceV2
}

private func opaqueRouteAuthorizationMaterial(
    authority: OpaqueRouteAuthorityV2,
    routeID: OpaqueReceiveRouteIDV2,
    operationDigest: Data,
    authorizedAt: Date,
    nonce: OpaqueRouteProofNonceV2
) throws -> Data {
    let payload = OpaqueRouteAuthorizationMACPayloadV2(
        version: NoctweaveOpaqueRoutesV2.version,
        authority: authority,
        routeID: routeID,
        operationDigest: operationDigest,
        authorizedAt: authorizedAt,
        nonce: nonce
    )
    return try NoctweaveCoder.encode(payload, sortedKeys: true)
}

private func opaqueRouteValidateAuthorizationTime(_ authorizedAt: Date, at receivedAt: Date) throws {
    guard authorizedAt.timeIntervalSince1970.isFinite,
          receivedAt.timeIntervalSince1970.isFinite,
          abs(receivedAt.timeIntervalSince(authorizedAt))
            <= NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew else {
        throw OpaqueRouteV2Error.authorizationExpired
    }
}

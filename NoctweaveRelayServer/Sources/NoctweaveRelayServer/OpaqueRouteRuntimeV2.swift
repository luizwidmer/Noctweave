import Crypto
import Foundation

enum NoctweaveOpaqueRoutesV2 {
    static let version = 2
    static let credentialBytes = 32
    static let digestBytes = 32
    static let minimumLeaseDuration: TimeInterval = 5 * 60
    static let maximumLeaseDuration: TimeInterval = 30 * 24 * 60 * 60
    static let maximumAuthorizationClockSkew: TimeInterval = 5 * 60
}

enum NoctweaveOpaqueRouteRelayStoreV2 {
    static let maximumSyncPage = 256
    static let maximumAcceptedPacketIdentifiers = 65_536
    static let maximumReadRequestReceipts = 65_536
    static let maximumRoutes = 100_000
    static let cursorBytes = 68
}

enum OpaqueRouteV2Error: Error, Equatable {
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

enum OpaqueRouteRelayStoreV2Error: Error, Equatable {
    case routeNotFound
    case invalidRequest
    case invalidCursor
    case cursorExpired
    case cursorAheadOfRoute
    case packetIdentifierConflict
    case requestIdentifierConflict
    case routeQuotaExceeded
    case packetIdentifierLedgerExhausted
    case requestReceiptLedgerExhausted
    case sequenceExhausted
    case routeCapacityExceeded
}

private protocol OpaqueRouteFixedValueV2 {
    var rawValue: Data { get }
}

struct OpaqueReceiveRouteIDV2: Codable, Equatable, Hashable, OpaqueRouteFixedValueV2 {
    let rawValue: Data
    var isStructurallyValid: Bool { opaqueRouteIsValidFixedValue(rawValue) }
}

struct OpaqueRouteIdempotencyKeyV2: Codable, Equatable, Hashable, OpaqueRouteFixedValueV2 {
    let rawValue: Data
    var isStructurallyValid: Bool { opaqueRouteIsValidFixedValue(rawValue) }
}

struct OpaqueRouteProofNonceV2: Codable, Equatable, Hashable, OpaqueRouteFixedValueV2 {
    let rawValue: Data
    var isStructurallyValid: Bool { opaqueRouteIsValidFixedValue(rawValue) }
}

struct OpaqueRoutePacketIDV2: Codable, Equatable, Hashable, OpaqueRouteFixedValueV2 {
    let rawValue: Data
    var isStructurallyValid: Bool { opaqueRouteIsValidFixedValue(rawValue) }
}

struct RouteSendCapabilityV2: Codable, Equatable, Hashable, OpaqueRouteFixedValueV2 {
    let rawValue: Data
    var isStructurallyValid: Bool { opaqueRouteIsValidFixedValue(rawValue) }
}

struct RouteReadCredentialV2: Codable, Equatable, Hashable, OpaqueRouteFixedValueV2 {
    let rawValue: Data
    var isStructurallyValid: Bool { opaqueRouteIsValidFixedValue(rawValue) }
}

struct RouteRenewCapabilityV2: Codable, Equatable, Hashable, OpaqueRouteFixedValueV2 {
    let rawValue: Data
    var isStructurallyValid: Bool { opaqueRouteIsValidFixedValue(rawValue) }
}

struct RouteTeardownCapabilityV2: Codable, Equatable, Hashable, OpaqueRouteFixedValueV2 {
    let rawValue: Data
    var isStructurallyValid: Bool { opaqueRouteIsValidFixedValue(rawValue) }
}

enum OpaqueRoutePaddingBucketV2: UInt32, Codable, CaseIterable {
    case bytes4096 = 4_096
    case bytes16384 = 16_384
    case bytes65536 = 65_536
}

enum OpaqueRouteRetentionBucketV2: UInt32, Codable, CaseIterable {
    case oneHour = 3_600
    case sixHours = 21_600
    case oneDay = 86_400
    case sevenDays = 604_800
}

enum OpaqueRouteQuotaBucketV2: UInt32, Codable, CaseIterable {
    case packets64 = 64
    case packets256 = 256
    case packets1024 = 1_024
}

enum OpaqueRouteTransportRequirementV2: String, Codable, Equatable {
    case confidentialAuthenticated
}

struct OpaqueRoutePolicyV2: Codable, Equatable {
    let paddingBucket: OpaqueRoutePaddingBucketV2
    let retentionBucket: OpaqueRouteRetentionBucketV2
    let quotaBucket: OpaqueRouteQuotaBucketV2
    let transportRequirement: OpaqueRouteTransportRequirementV2

    init(
        paddingBucket: OpaqueRoutePaddingBucketV2,
        retentionBucket: OpaqueRouteRetentionBucketV2,
        quotaBucket: OpaqueRouteQuotaBucketV2
    ) {
        self.paddingBucket = paddingBucket
        self.retentionBucket = retentionBucket
        self.quotaBucket = quotaBucket
        transportRequirement = .confidentialAuthenticated
    }

    var maximumStoredBytes: UInt64 {
        UInt64(paddingBucket.rawValue) * UInt64(quotaBucket.rawValue)
    }

    var isStructurallyValid: Bool {
        transportRequirement == .confidentialAuthenticated
            && maximumStoredBytes <= 64 * 1_024 * 1_024
    }
}

struct OpaqueRouteLeaseV2: Codable, Equatable {
    let issuedAt: Date
    let lastRenewedAt: Date
    let expiresAt: Date
    let renewalSequence: UInt64
    let policy: OpaqueRoutePolicyV2

    init(
        issuedAt: Date,
        lastRenewedAt: Date? = nil,
        expiresAt: Date,
        renewalSequence: UInt64 = 0,
        policy: OpaqueRoutePolicyV2
    ) {
        self.issuedAt = issuedAt
        self.lastRenewedAt = lastRenewedAt ?? issuedAt
        self.expiresAt = expiresAt
        self.renewalSequence = renewalSequence
        self.policy = policy
    }

    var isStructurallyValid: Bool {
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

    func isActive(at date: Date) -> Bool {
        date.timeIntervalSince1970.isFinite && date >= issuedAt && date < expiresAt
    }

    func renewing(at renewedAt: Date, through newExpiry: Date) throws -> OpaqueRouteLeaseV2 {
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
        let result = OpaqueRouteLeaseV2(
            issuedAt: issuedAt,
            lastRenewedAt: renewedAt,
            expiresAt: newExpiry,
            renewalSequence: renewalSequence + 1,
            policy: policy
        )
        guard result.isStructurallyValid else { throw OpaqueRouteV2Error.invalidLease }
        return result
    }
}

enum OpaqueRouteAuthorityV2: String, Codable, Equatable, CaseIterable {
    case send
    case read
    case renew
    case teardown
}

struct OpaqueRouteAuthorizationProofV2: Codable, Equatable {
    let authority: OpaqueRouteAuthorityV2
    let nonce: OpaqueRouteProofNonceV2
    let operationDigest: Data
    let authorizedAt: Date
    let mac: Data

    var isStructurallyValid: Bool {
        nonce.isStructurallyValid
            && opaqueRouteIsValidDigest(operationDigest)
            && authorizedAt.timeIntervalSince1970.isFinite
            && mac.count == NoctweaveOpaqueRoutesV2.digestBytes
    }

    static func make(
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
        return OpaqueRouteAuthorizationProofV2(
            authority: authority,
            nonce: nonce,
            operationDigest: operationDigest,
            authorizedAt: authorizedAt,
            mac: Data(HMAC<SHA256>.authenticationCode(
                for: material,
                using: SymmetricKey(data: secret)
            ))
        )
    }

    func verify(
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

    var replayDigest: Data? {
        guard isStructurallyValid,
              let encoded = try? RelayCodec.encoder(sortedKeys: true).encode(self) else {
            return nil
        }
        return opaqueRouteDigest(
            domain: "org.noctweave.opaque-route.authorization-replay/v2",
            components: [encoded]
        )
    }
}

struct OpaqueRouteAuthorizationReplayLedgerV2: Codable, Equatable {
    static let maximumEntries = 4_096

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

    init() {}

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let entries = try container.decode([Entry].self, forKey: .entries)
        let high = try container.decodeIfPresent(Date.self, forKey: .observedAtHighWatermark)
        guard entries.count <= Self.maximumEntries,
              entries.allSatisfy({ opaqueRouteIsValidDigest($0.digest) && $0.expiresAt.timeIntervalSince1970.isFinite }),
              Set(entries.map(\.digest)).count == entries.count,
              high?.timeIntervalSince1970.isFinite != false,
              high.map({ point in entries.allSatisfy { $0.expiresAt >= point } }) ?? true else {
            throw OpaqueRouteRelayStoreV2Error.invalidRequest
        }
        entriesByDigest = Dictionary(uniqueKeysWithValues: entries.map { ($0.digest, $0.expiresAt) })
        observedAtHighWatermark = high
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        let entries = entriesByDigest.map { Entry(digest: $0.key, expiresAt: $0.value) }
            .sorted { $0.digest.lexicographicallyPrecedes($1.digest) }
        try container.encode(entries, forKey: .entries)
        try container.encodeIfPresent(observedAtHighWatermark, forKey: .observedAtHighWatermark)
    }

    var isStructurallyValid: Bool {
        entriesByDigest.count <= Self.maximumEntries
            && entriesByDigest.allSatisfy { opaqueRouteIsValidDigest($0.key) && $0.value.timeIntervalSince1970.isFinite }
            && observedAtHighWatermark?.timeIntervalSince1970.isFinite != false
    }

    mutating func monotonicTime(_ receivedAt: Date) throws -> Date {
        guard receivedAt.timeIntervalSince1970.isFinite else {
            throw OpaqueRouteV2Error.invalidRequest
        }
        let effective = max(receivedAt, observedAtHighWatermark ?? receivedAt)
        observedAtHighWatermark = effective
        entriesByDigest = entriesByDigest.filter { $0.value >= effective }
        return effective
    }

    mutating func consume(_ proof: OpaqueRouteAuthorizationProofV2, receivedAt: Date) throws {
        guard let digest = proof.replayDigest else { throw OpaqueRouteV2Error.invalidAuthorization }
        guard entriesByDigest[digest] == nil else { throw OpaqueRouteV2Error.authorizationReplay }
        guard entriesByDigest.count < Self.maximumEntries else {
            throw OpaqueRouteV2Error.authorizationLedgerExhausted
        }
        let expiry = proof.authorizedAt.addingTimeInterval(
            NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew
        )
        guard expiry.timeIntervalSince1970.isFinite, expiry >= receivedAt else {
            throw OpaqueRouteV2Error.authorizationExpired
        }
        entriesByDigest[digest] = expiry
    }
}

struct OpaqueRouteCreateRequestV2: Codable, Equatable {
    private struct Unsigned: Codable, Equatable {
        let version: Int
        let routeID: OpaqueReceiveRouteIDV2
        let sendCapabilityDigest: Data
        let readCredentialDigest: Data
        let renewCapabilityDigest: Data
        let teardownCapabilityDigest: Data
        let lease: OpaqueRouteLeaseV2
        let idempotencyKey: OpaqueRouteIdempotencyKeyV2
    }

    let version: Int
    let routeID: OpaqueReceiveRouteIDV2
    let sendCapabilityDigest: Data
    let readCredentialDigest: Data
    let renewCapabilityDigest: Data
    let teardownCapabilityDigest: Data
    let lease: OpaqueRouteLeaseV2
    let idempotencyKey: OpaqueRouteIdempotencyKeyV2
    let authorization: OpaqueRouteAuthorizationProofV2

    var transitionDigest: Data? {
        let value = Unsigned(
            version: version,
            routeID: routeID,
            sendCapabilityDigest: sendCapabilityDigest,
            readCredentialDigest: readCredentialDigest,
            renewCapabilityDigest: renewCapabilityDigest,
            teardownCapabilityDigest: teardownCapabilityDigest,
            lease: lease,
            idempotencyKey: idempotencyKey
        )
        return try? opaqueRouteDigest(
            domain: "org.noctweave.opaque-route.create/v2",
            components: [RelayCodec.encoder(sortedKeys: true).encode(value)]
        )
    }

    var isStructurallyValid: Bool {
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

struct OpaqueRouteRenewRequestV2: Codable, Equatable {
    private struct Unsigned: Codable, Equatable {
        let version: Int
        let routeID: OpaqueReceiveRouteIDV2
        let renewalSequence: UInt64
        let previousTransitionDigest: Data
        let newExpiry: Date
        let authorizedAt: Date
        let idempotencyKey: OpaqueRouteIdempotencyKeyV2
    }

    let version: Int
    let routeID: OpaqueReceiveRouteIDV2
    let renewalSequence: UInt64
    let previousTransitionDigest: Data
    let newExpiry: Date
    let authorizedAt: Date
    let idempotencyKey: OpaqueRouteIdempotencyKeyV2
    let authorization: OpaqueRouteAuthorizationProofV2

    var transitionDigest: Data? {
        let value = Unsigned(
            version: version,
            routeID: routeID,
            renewalSequence: renewalSequence,
            previousTransitionDigest: previousTransitionDigest,
            newExpiry: newExpiry,
            authorizedAt: authorizedAt,
            idempotencyKey: idempotencyKey
        )
        return try? opaqueRouteDigest(
            domain: "org.noctweave.opaque-route.renew/v2",
            components: [RelayCodec.encoder(sortedKeys: true).encode(value)]
        )
    }

    var isStructurallyValid: Bool {
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

struct OpaqueRouteTeardownRequestV2: Codable, Equatable {
    private struct Unsigned: Codable, Equatable {
        let version: Int
        let routeID: OpaqueReceiveRouteIDV2
        let renewalSequence: UInt64
        let previousTransitionDigest: Data
        let authorizedAt: Date
        let idempotencyKey: OpaqueRouteIdempotencyKeyV2
    }

    let version: Int
    let routeID: OpaqueReceiveRouteIDV2
    let renewalSequence: UInt64
    let previousTransitionDigest: Data
    let authorizedAt: Date
    let idempotencyKey: OpaqueRouteIdempotencyKeyV2
    let authorization: OpaqueRouteAuthorizationProofV2

    var transitionDigest: Data? {
        let value = Unsigned(
            version: version,
            routeID: routeID,
            renewalSequence: renewalSequence,
            previousTransitionDigest: previousTransitionDigest,
            authorizedAt: authorizedAt,
            idempotencyKey: idempotencyKey
        )
        return try? opaqueRouteDigest(
            domain: "org.noctweave.opaque-route.teardown/v2",
            components: [RelayCodec.encoder(sortedKeys: true).encode(value)]
        )
    }

    var isStructurallyValid: Bool {
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

enum OpaqueReceiveRouteStatusV2: String, Codable, Equatable {
    case active
    case tornDown
}

struct OpaqueReceiveRouteV2: Codable, Equatable {
    let version: Int
    let routeID: OpaqueReceiveRouteIDV2
    let sendCapabilityDigest: Data
    let readCredentialDigest: Data
    let renewCapabilityDigest: Data
    let teardownCapabilityDigest: Data
    let lease: OpaqueRouteLeaseV2
    let status: OpaqueReceiveRouteStatusV2
    let createdAt: Date
    let tornDownAt: Date?
    let creationIdempotencyKey: OpaqueRouteIdempotencyKeyV2
    let creationDigest: Data
    let lastIdempotencyKey: OpaqueRouteIdempotencyKeyV2
    let lastTransitionDigest: Data

    var isStructurallyValid: Bool {
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
            return tornDownAt.map { $0.timeIntervalSince1970.isFinite && $0 >= createdAt } == true
        }
    }

    static func creating(
        from request: OpaqueRouteCreateRequestV2,
        presentedRenewCapability: RouteRenewCapabilityV2,
        existing: OpaqueReceiveRouteV2?,
        confidentialTransport: Bool,
        receivedAt: Date
    ) throws -> OpaqueReceiveRouteV2 {
        guard confidentialTransport else { throw OpaqueRouteV2Error.confidentialTransportRequired }
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
            guard existing.routeID == request.routeID else { throw OpaqueRouteV2Error.routeMismatch }
            guard existing.status != .tornDown else { throw OpaqueRouteV2Error.routeTornDown }
            if existing.creationIdempotencyKey == request.idempotencyKey {
                guard existing.creationDigest == transitionDigest else {
                    throw OpaqueRouteV2Error.idempotencyConflict
                }
                return existing
            }
            throw OpaqueRouteV2Error.routeAlreadyExists
        }
        try opaqueRouteValidateAuthorizationTime(request.authorization.authorizedAt, at: receivedAt)
        guard request.lease.isActive(at: receivedAt) else { throw OpaqueRouteV2Error.routeExpired }
        let result = OpaqueReceiveRouteV2(
            version: NoctweaveOpaqueRoutesV2.version,
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
        guard result.isStructurallyValid else { throw OpaqueRouteV2Error.invalidRequest }
        return result
    }

    func applyingRenewal(
        _ request: OpaqueRouteRenewRequestV2,
        presentedCapability: RouteRenewCapabilityV2,
        confidentialTransport: Bool,
        receivedAt: Date
    ) throws -> OpaqueReceiveRouteV2 {
        guard confidentialTransport else { throw OpaqueRouteV2Error.confidentialTransportRequired }
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
            try authenticateTransition(
                request.authorization,
                authority: .renew,
                digest: transitionDigest,
                presentedSecret: presentedCapability.rawValue,
                expectedDigest: renewCapabilityDigest
            )
            return self
        }
        guard status == .active else { throw OpaqueRouteV2Error.routeTornDown }
        guard lease.isActive(at: receivedAt) else { throw OpaqueRouteV2Error.routeExpired }
        let expected = lease.renewalSequence + 1
        if request.renewalSequence < expected {
            throw request.renewalSequence == lease.renewalSequence
                ? OpaqueRouteV2Error.transitionFork : OpaqueRouteV2Error.staleTransition
        }
        guard request.renewalSequence == expected else {
            throw OpaqueRouteV2Error.transitionOutOfOrder
        }
        guard request.previousTransitionDigest == lastTransitionDigest else {
            throw OpaqueRouteV2Error.transitionFork
        }
        try opaqueRouteValidateAuthorizationTime(request.authorization.authorizedAt, at: receivedAt)
        guard request.authorizedAt >= lease.lastRenewedAt else {
            throw OpaqueRouteV2Error.invalidAuthorization
        }
        try authenticateTransition(
            request.authorization,
            authority: .renew,
            digest: transitionDigest,
            presentedSecret: presentedCapability.rawValue,
            expectedDigest: renewCapabilityDigest
        )
        let result = OpaqueReceiveRouteV2(
            version: version,
            routeID: routeID,
            sendCapabilityDigest: sendCapabilityDigest,
            readCredentialDigest: readCredentialDigest,
            renewCapabilityDigest: renewCapabilityDigest,
            teardownCapabilityDigest: teardownCapabilityDigest,
            lease: try lease.renewing(at: request.authorizedAt, through: request.newExpiry),
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

    func applyingTeardown(
        _ request: OpaqueRouteTeardownRequestV2,
        presentedCapability: RouteTeardownCapabilityV2,
        confidentialTransport: Bool,
        receivedAt: Date
    ) throws -> OpaqueReceiveRouteV2 {
        guard confidentialTransport else { throw OpaqueRouteV2Error.confidentialTransportRequired }
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
            try authenticateTransition(
                request.authorization,
                authority: .teardown,
                digest: transitionDigest,
                presentedSecret: presentedCapability.rawValue,
                expectedDigest: teardownCapabilityDigest
            )
            return self
        }
        guard status == .active else { throw OpaqueRouteV2Error.routeTornDown }
        if request.renewalSequence < lease.renewalSequence { throw OpaqueRouteV2Error.staleTransition }
        guard request.renewalSequence == lease.renewalSequence else {
            throw OpaqueRouteV2Error.transitionOutOfOrder
        }
        guard request.previousTransitionDigest == lastTransitionDigest else {
            throw OpaqueRouteV2Error.transitionFork
        }
        try opaqueRouteValidateAuthorizationTime(request.authorization.authorizedAt, at: receivedAt)
        try authenticateTransition(
            request.authorization,
            authority: .teardown,
            digest: transitionDigest,
            presentedSecret: presentedCapability.rawValue,
            expectedDigest: teardownCapabilityDigest
        )
        let result = OpaqueReceiveRouteV2(
            version: version,
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

    func authorizeSend(
        _ proof: OpaqueRouteAuthorizationProofV2,
        operationDigest: Data,
        presentedCapability: RouteSendCapabilityV2,
        confidentialTransport: Bool,
        receivedAt: Date,
        replayLedger: inout OpaqueRouteAuthorizationReplayLedgerV2
    ) throws {
        try authorizeUse(
            proof,
            authority: .send,
            expectedDigest: sendCapabilityDigest,
            secret: presentedCapability.rawValue,
            operationDigest: operationDigest,
            confidentialTransport: confidentialTransport,
            receivedAt: receivedAt,
            replayLedger: &replayLedger
        )
    }

    func authorizeRead(
        _ proof: OpaqueRouteAuthorizationProofV2,
        operationDigest: Data,
        presentedCredential: RouteReadCredentialV2,
        confidentialTransport: Bool,
        receivedAt: Date,
        replayLedger: inout OpaqueRouteAuthorizationReplayLedgerV2
    ) throws {
        try authorizeUse(
            proof,
            authority: .read,
            expectedDigest: readCredentialDigest,
            secret: presentedCredential.rawValue,
            operationDigest: operationDigest,
            confidentialTransport: confidentialTransport,
            receivedAt: receivedAt,
            replayLedger: &replayLedger
        )
    }

    func authenticateAcceptedRetry(
        _ proof: OpaqueRouteAuthorizationProofV2,
        authority: OpaqueRouteAuthorityV2,
        expectedDigest: Data,
        secret: Data,
        operationDigest: Data,
        confidentialTransport: Bool
    ) throws {
        guard confidentialTransport else { throw OpaqueRouteV2Error.confidentialTransportRequired }
        guard isStructurallyValid, status == .active else { throw OpaqueRouteV2Error.routeTornDown }
        guard opaqueRouteCredentialDigest(authority, secret) == expectedDigest,
              proof.verify(
                  expectedAuthority: authority,
                  routeID: routeID,
                  operationDigest: operationDigest,
                  secret: secret
              ) else {
            throw OpaqueRouteV2Error.invalidAuthorization
        }
    }

    private func authorizeUse(
        _ proof: OpaqueRouteAuthorizationProofV2,
        authority: OpaqueRouteAuthorityV2,
        expectedDigest: Data,
        secret: Data,
        operationDigest: Data,
        confidentialTransport: Bool,
        receivedAt: Date,
        replayLedger: inout OpaqueRouteAuthorizationReplayLedgerV2
    ) throws {
        guard confidentialTransport else { throw OpaqueRouteV2Error.confidentialTransportRequired }
        guard isStructurallyValid, opaqueRouteIsValidDigest(operationDigest) else {
            throw OpaqueRouteV2Error.invalidRequest
        }
        guard status == .active else { throw OpaqueRouteV2Error.routeTornDown }
        guard lease.isActive(at: receivedAt) else { throw OpaqueRouteV2Error.routeExpired }
        let effective = try replayLedger.monotonicTime(receivedAt)
        try opaqueRouteValidateAuthorizationTime(proof.authorizedAt, at: effective)
        guard opaqueRouteCredentialDigest(authority, secret) == expectedDigest,
              proof.verify(
                  expectedAuthority: authority,
                  routeID: routeID,
                  operationDigest: operationDigest,
                  secret: secret
              ) else {
            throw OpaqueRouteV2Error.invalidAuthorization
        }
        try replayLedger.consume(proof, receivedAt: effective)
    }

    private func authenticateTransition(
        _ proof: OpaqueRouteAuthorizationProofV2,
        authority: OpaqueRouteAuthorityV2,
        digest: Data,
        presentedSecret: Data,
        expectedDigest: Data
    ) throws {
        guard opaqueRouteCredentialDigest(authority, presentedSecret) == expectedDigest,
              proof.verify(
                  expectedAuthority: authority,
                  routeID: routeID,
                  operationDigest: digest,
                  secret: presentedSecret
              ) else {
            throw OpaqueRouteV2Error.invalidAuthorization
        }
    }
}

struct OpaqueRoutePacketV2: Codable, Equatable {
    let routeID: OpaqueReceiveRouteIDV2
    let packetID: OpaqueRoutePacketIDV2
    let sealedFrame: Data
    let authorization: OpaqueRouteAuthorizationProofV2

    var paddingBucket: OpaqueRoutePaddingBucketV2? {
        UInt32(exactly: sealedFrame.count).flatMap(OpaqueRoutePaddingBucketV2.init(rawValue:))
    }

    var operationDigest: Data {
        opaqueRouteStoreDigest(
            domain: "org.noctweave.opaque-route.packet-operation/v2",
            components: [routeID.rawValue, packetID.rawValue, sealedFrame]
        )
    }

    var isStructurallyValid: Bool {
        routeID.isStructurallyValid
            && packetID.isStructurallyValid
            && paddingBucket != nil
            && authorization.isStructurallyValid
            && authorization.authority == .send
            && authorization.operationDigest == operationDigest
    }
}

struct OpaqueRouteCursorV2: Codable, Equatable, Hashable {
    let rawValue: Data
    var isStructurallyValid: Bool {
        rawValue.count == NoctweaveOpaqueRouteRelayStoreV2.cursorBytes
    }
}

struct OpaqueRouteSyncRequestV2: Codable, Equatable {
    let routeID: OpaqueReceiveRouteIDV2
    let requestID: OpaqueRouteIdempotencyKeyV2
    let after: OpaqueRouteCursorV2?
    let limit: UInt16
    let authorization: OpaqueRouteAuthorizationProofV2

    var operationDigest: Data {
        opaqueRouteStoreDigest(
            domain: "org.noctweave.opaque-route.sync/v2",
            components: [
                routeID.rawValue,
                requestID.rawValue,
                after?.rawValue ?? Data([0]),
                opaqueRouteStoreIntegerBytes(limit),
            ]
        )
    }

    var isStructurallyValid: Bool {
        routeID.isStructurallyValid
            && requestID.isStructurallyValid
            && after?.isStructurallyValid != false
            && limit > 0
            && limit <= UInt16(NoctweaveOpaqueRouteRelayStoreV2.maximumSyncPage)
            && authorization.isStructurallyValid
            && authorization.authority == .read
            && authorization.operationDigest == operationDigest
    }
}

struct OpaqueRouteCommitRequestV2: Codable, Equatable {
    let routeID: OpaqueReceiveRouteIDV2
    let requestID: OpaqueRouteIdempotencyKeyV2
    let cursor: OpaqueRouteCursorV2
    let authorization: OpaqueRouteAuthorizationProofV2

    var operationDigest: Data {
        opaqueRouteStoreDigest(
            domain: "org.noctweave.opaque-route.commit/v2",
            components: [routeID.rawValue, requestID.rawValue, cursor.rawValue]
        )
    }

    var isStructurallyValid: Bool {
        routeID.isStructurallyValid
            && requestID.isStructurallyValid
            && cursor.isStructurallyValid
            && authorization.isStructurallyValid
            && authorization.authority == .read
            && authorization.operationDigest == operationDigest
    }
}

struct OpaqueRouteAppendReceiptV2: Codable, Equatable {
    let packetID: OpaqueRoutePacketIDV2
    let acceptedCursor: OpaqueRouteCursorV2
    let highWatermark: OpaqueRouteCursorV2
}

struct OpaqueRouteReceivedPacketV2: Codable, Equatable {
    let sequence: UInt64
    let previousRecordDigest: Data
    let recordDigest: Data
    let routeRevision: UInt64
    let packet: OpaqueRoutePacketV2

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case sequence
        case previousRecordDigest
        case recordDigest
        case routeRevision
        case packet
    }

    init(
        sequence: UInt64,
        previousRecordDigest: Data,
        recordDigest: Data,
        routeRevision: UInt64,
        packet: OpaqueRoutePacketV2
    ) {
        self.sequence = sequence
        self.previousRecordDigest = previousRecordDigest
        self.recordDigest = recordDigest
        self.routeRevision = routeRevision
        self.packet = packet
    }

    init(from decoder: Decoder) throws {
        try opaqueRouteRelayRequireExactObject(
            decoder,
            keys: CodingKeys.allCases.map(\.rawValue)
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sequence = try container.decode(UInt64.self, forKey: .sequence)
        previousRecordDigest = try container.decode(Data.self, forKey: .previousRecordDigest)
        recordDigest = try container.decode(Data.self, forKey: .recordDigest)
        routeRevision = try container.decode(UInt64.self, forKey: .routeRevision)
        packet = try container.decode(OpaqueRoutePacketV2.self, forKey: .packet)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .recordDigest,
                in: container,
                debugDescription: "Opaque route record chain is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Opaque route record chain is invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(sequence, forKey: .sequence)
        try container.encode(previousRecordDigest, forKey: .previousRecordDigest)
        try container.encode(recordDigest, forKey: .recordDigest)
        try container.encode(routeRevision, forKey: .routeRevision)
        try container.encode(packet, forKey: .packet)
    }

    var isStructurallyValid: Bool {
        sequence > 0
            && opaqueRouteIsValidDigest(previousRecordDigest)
            && opaqueRouteIsValidDigest(recordDigest)
            && packet.isStructurallyValid
            && recordDigest == opaqueRouteRecordDigest(
                previousRecordDigest: previousRecordDigest,
                sequence: sequence,
                routeRevision: routeRevision,
                packet: packet
            )
    }
}

struct OpaqueRouteSyncResponseV2: Codable, Equatable {
    let packets: [OpaqueRouteReceivedPacketV2]
    let startsAfterSequence: UInt64
    let startsAfterRecordDigest: Data
    let nextSequence: UInt64
    let nextRecordDigest: Data
    let highWatermarkSequence: UInt64
    let retentionFloorSequence: UInt64
    let nextCursor: OpaqueRouteCursorV2
    let highWatermark: OpaqueRouteCursorV2
    let retentionFloor: OpaqueRouteCursorV2
    let hasMore: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case packets
        case startsAfterSequence
        case startsAfterRecordDigest
        case nextSequence
        case nextRecordDigest
        case highWatermarkSequence
        case retentionFloorSequence
        case nextCursor
        case highWatermark
        case retentionFloor
        case hasMore
    }

    init(
        packets: [OpaqueRouteReceivedPacketV2],
        startsAfterSequence: UInt64,
        startsAfterRecordDigest: Data,
        nextSequence: UInt64,
        nextRecordDigest: Data,
        highWatermarkSequence: UInt64,
        retentionFloorSequence: UInt64,
        nextCursor: OpaqueRouteCursorV2,
        highWatermark: OpaqueRouteCursorV2,
        retentionFloor: OpaqueRouteCursorV2,
        hasMore: Bool
    ) {
        self.packets = packets
        self.startsAfterSequence = startsAfterSequence
        self.startsAfterRecordDigest = startsAfterRecordDigest
        self.nextSequence = nextSequence
        self.nextRecordDigest = nextRecordDigest
        self.highWatermarkSequence = highWatermarkSequence
        self.retentionFloorSequence = retentionFloorSequence
        self.nextCursor = nextCursor
        self.highWatermark = highWatermark
        self.retentionFloor = retentionFloor
        self.hasMore = hasMore
    }

    init(from decoder: Decoder) throws {
        try opaqueRouteRelayRequireExactObject(
            decoder,
            keys: CodingKeys.allCases.map(\.rawValue)
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        packets = try container.decode([OpaqueRouteReceivedPacketV2].self, forKey: .packets)
        startsAfterSequence = try container.decode(UInt64.self, forKey: .startsAfterSequence)
        startsAfterRecordDigest = try container.decode(Data.self, forKey: .startsAfterRecordDigest)
        nextSequence = try container.decode(UInt64.self, forKey: .nextSequence)
        nextRecordDigest = try container.decode(Data.self, forKey: .nextRecordDigest)
        highWatermarkSequence = try container.decode(UInt64.self, forKey: .highWatermarkSequence)
        retentionFloorSequence = try container.decode(UInt64.self, forKey: .retentionFloorSequence)
        nextCursor = try container.decode(OpaqueRouteCursorV2.self, forKey: .nextCursor)
        highWatermark = try container.decode(OpaqueRouteCursorV2.self, forKey: .highWatermark)
        retentionFloor = try container.decode(OpaqueRouteCursorV2.self, forKey: .retentionFloor)
        hasMore = try container.decode(Bool.self, forKey: .hasMore)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .packets,
                in: container,
                debugDescription: "Opaque route sync chain is invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Opaque route sync chain is invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(packets, forKey: .packets)
        try container.encode(startsAfterSequence, forKey: .startsAfterSequence)
        try container.encode(startsAfterRecordDigest, forKey: .startsAfterRecordDigest)
        try container.encode(nextSequence, forKey: .nextSequence)
        try container.encode(nextRecordDigest, forKey: .nextRecordDigest)
        try container.encode(highWatermarkSequence, forKey: .highWatermarkSequence)
        try container.encode(retentionFloorSequence, forKey: .retentionFloorSequence)
        try container.encode(nextCursor, forKey: .nextCursor)
        try container.encode(highWatermark, forKey: .highWatermark)
        try container.encode(retentionFloor, forKey: .retentionFloor)
        try container.encode(hasMore, forKey: .hasMore)
    }

    var isStructurallyValid: Bool {
        guard packets.count <= NoctweaveOpaqueRouteRelayStoreV2.maximumSyncPage,
              retentionFloorSequence <= startsAfterSequence,
              startsAfterSequence <= nextSequence,
              nextSequence <= highWatermarkSequence,
              opaqueRouteIsValidDigest(startsAfterRecordDigest),
              opaqueRouteIsValidDigest(nextRecordDigest),
              nextCursor.isStructurallyValid,
              highWatermark.isStructurallyValid,
              retentionFloor.isStructurallyValid,
              hasMore == (nextSequence < highWatermarkSequence) else {
            return false
        }
        var expectedSequence = startsAfterSequence
        var expectedPreviousDigest = startsAfterRecordDigest
        for received in packets {
            guard expectedSequence < UInt64.max,
                  received.sequence == expectedSequence + 1,
                  received.previousRecordDigest == expectedPreviousDigest,
                  received.isStructurallyValid else {
                return false
            }
            expectedSequence = received.sequence
            expectedPreviousDigest = received.recordDigest
        }
        return expectedSequence == nextSequence
            && expectedPreviousDigest == nextRecordDigest
    }
}

struct OpaqueRouteCommitResponseV2: Codable, Equatable {
    let committedCursor: OpaqueRouteCursorV2
    let highWatermark: OpaqueRouteCursorV2
    let retentionFloor: OpaqueRouteCursorV2
}

struct OpaqueRouteCreateSubmissionV2: Codable, Equatable {
    let request: OpaqueRouteCreateRequestV2
    let renewCapability: RouteRenewCapabilityV2
    var isStructurallyValid: Bool { request.isStructurallyValid && renewCapability.isStructurallyValid }
}

struct OpaqueRouteRenewSubmissionV2: Codable, Equatable {
    let request: OpaqueRouteRenewRequestV2
    let renewCapability: RouteRenewCapabilityV2
    var isStructurallyValid: Bool { request.isStructurallyValid && renewCapability.isStructurallyValid }
}

struct OpaqueRouteTeardownSubmissionV2: Codable, Equatable {
    let request: OpaqueRouteTeardownRequestV2
    let teardownCapability: RouteTeardownCapabilityV2
    var isStructurallyValid: Bool { request.isStructurallyValid && teardownCapability.isStructurallyValid }
}

struct OpaqueRouteAppendSubmissionV2: Codable, Equatable {
    let packet: OpaqueRoutePacketV2
    let sendCapability: RouteSendCapabilityV2
    var isStructurallyValid: Bool { packet.isStructurallyValid && sendCapability.isStructurallyValid }
}

struct OpaqueRouteSyncSubmissionV2: Codable, Equatable {
    let request: OpaqueRouteSyncRequestV2
    let readCredential: RouteReadCredentialV2
    var isStructurallyValid: Bool { request.isStructurallyValid && readCredential.isStructurallyValid }
}

struct OpaqueRouteCommitSubmissionV2: Codable, Equatable {
    let request: OpaqueRouteCommitRequestV2
    let readCredential: RouteReadCredentialV2
    var isStructurallyValid: Bool { request.isStructurallyValid && readCredential.isStructurallyValid }
}

struct OpaqueRouteRuntimeStateV2: Codable, Equatable {
    private struct StoredPacket: Codable, Equatable {
        let sequence: UInt64
        let previousRecordDigest: Data
        let recordDigest: Data
        let routeRevision: UInt64
        let packet: OpaqueRoutePacketV2
        let expiresAt: Date
    }

    private struct AcceptedPacket: Codable, Equatable {
        let operationDigest: Data
        let receipt: OpaqueRouteAppendReceiptV2
        let authorizationExpiresAt: Date
    }

    private struct CachedSync: Codable, Equatable {
        let packetSequences: [UInt64]
        let response: OpaqueRouteSyncResponseV2
        let authorizationExpiresAt: Date
        let bodyExpiresAt: Date?
    }

    private enum CachedReadResult: Codable, Equatable {
        case sync(CachedSync)
        case commit(OpaqueRouteCommitResponseV2)
    }

    private struct AcceptedReadRequest: Codable, Equatable {
        let operationDigest: Data
        let result: CachedReadResult
        let authorizationExpiresAt: Date
    }

    private struct RouteState: Codable, Equatable {
        var route: OpaqueReceiveRouteV2
        var replayLedger: OpaqueRouteAuthorizationReplayLedgerV2
        var packets: [StoredPacket]
        var nextSequence: UInt64
        var retentionFloor: UInt64
        var retentionFloorDigest: Data
        var committedSequence: UInt64
        var acceptedPackets: [OpaqueRoutePacketIDV2: AcceptedPacket]
        var acceptedReads: [OpaqueRouteIdempotencyKeyV2: AcceptedReadRequest]
        var observedAtHighWatermark: Date

        init(route: OpaqueReceiveRouteV2, observedAtHighWatermark: Date) {
            self.route = route
            replayLedger = OpaqueRouteAuthorizationReplayLedgerV2()
            packets = []
            nextSequence = 1
            retentionFloor = 0
            retentionFloorDigest = Data(
                repeating: 0,
                count: NoctweaveOpaqueRoutesV2.digestBytes
            )
            committedSequence = 0
            acceptedPackets = [:]
            acceptedReads = [:]
            self.observedAtHighWatermark = observedAtHighWatermark
        }

        var isStructurallyValid: Bool {
            guard route.isStructurallyValid,
                  replayLedger.isStructurallyValid,
                  nextSequence > 0,
                  retentionFloor <= nextSequence - 1,
                  opaqueRouteIsValidDigest(retentionFloorDigest),
                  committedSequence <= nextSequence - 1,
                  acceptedPackets.count <= NoctweaveOpaqueRouteRelayStoreV2.maximumAcceptedPacketIdentifiers,
                  acceptedReads.count <= NoctweaveOpaqueRouteRelayStoreV2.maximumReadRequestReceipts,
                  observedAtHighWatermark.timeIntervalSince1970.isFinite else {
                return false
            }
            var previousSequence = retentionFloor
            var previousDigest = retentionFloorDigest
            for stored in packets {
                guard previousSequence < UInt64.max,
                      stored.sequence == previousSequence + 1,
                      stored.sequence < nextSequence,
                      stored.previousRecordDigest == previousDigest,
                      stored.recordDigest == opaqueRouteRecordDigest(
                          previousRecordDigest: stored.previousRecordDigest,
                          sequence: stored.sequence,
                          routeRevision: stored.routeRevision,
                          packet: stored.packet
                      ),
                      stored.routeRevision <= route.lease.renewalSequence,
                      stored.packet.routeID == route.routeID,
                      stored.packet.isStructurallyValid,
                      stored.packet.paddingBucket == route.lease.policy.paddingBucket,
                      stored.expiresAt.timeIntervalSince1970.isFinite else {
                    return false
                }
                previousSequence = stored.sequence
                previousDigest = stored.recordDigest
            }
            return packets.count <= Int(route.lease.policy.quotaBucket.rawValue)
                && acceptedPackets.allSatisfy { packetID, accepted in
                    packetID.isStructurallyValid
                        && opaqueRouteIsValidDigest(accepted.operationDigest)
                        && accepted.receipt.packetID == packetID
                        && accepted.receipt.acceptedCursor.isStructurallyValid
                        && accepted.receipt.highWatermark.isStructurallyValid
                        && accepted.authorizationExpiresAt.timeIntervalSince1970.isFinite
                }
                && acceptedReads.allSatisfy { requestID, accepted in
                    requestID.isStructurallyValid
                        && opaqueRouteIsValidDigest(accepted.operationDigest)
                        && accepted.authorizationExpiresAt.timeIntervalSince1970.isFinite
                }
        }
    }

    private var cursorKey: Data
    private var routes: [String: RouteState]

    init() {
        cursorKey = opaqueRouteRandomNonzeroValue()
        routes = [:]
    }

    var routeCount: Int { routes.count }

    var isStructurallyValid: Bool {
        cursorKey.count == 32
            && cursorKey.contains(where: { $0 != 0 })
            && routes.count <= NoctweaveOpaqueRouteRelayStoreV2.maximumRoutes
            && routes.allSatisfy { key, state in
                key == opaqueRouteStorageKey(state.route.routeID) && state.isStructurallyValid
            }
    }

    mutating func create(
        _ submission: OpaqueRouteCreateSubmissionV2,
        confidentialTransport: Bool,
        receivedAt: Date
    ) throws -> OpaqueReceiveRouteV2 {
        guard submission.isStructurallyValid else { throw OpaqueRouteRelayStoreV2Error.invalidRequest }
        let key = opaqueRouteStorageKey(submission.request.routeID)
        if routes[key] == nil, routes.count >= NoctweaveOpaqueRouteRelayStoreV2.maximumRoutes {
            throw OpaqueRouteRelayStoreV2Error.routeCapacityExceeded
        }
        let route = try OpaqueReceiveRouteV2.creating(
            from: submission.request,
            presentedRenewCapability: submission.renewCapability,
            existing: routes[key]?.route,
            confidentialTransport: confidentialTransport,
            receivedAt: receivedAt
        )
        if var state = routes[key] {
            state.observedAtHighWatermark = max(state.observedAtHighWatermark, receivedAt)
            routes[key] = state
        } else {
            routes[key] = RouteState(route: route, observedAtHighWatermark: receivedAt)
        }
        return route
    }

    mutating func renew(
        _ submission: OpaqueRouteRenewSubmissionV2,
        confidentialTransport: Bool,
        receivedAt: Date
    ) throws -> OpaqueReceiveRouteV2 {
        guard submission.isStructurallyValid else { throw OpaqueRouteRelayStoreV2Error.invalidRequest }
        let key = opaqueRouteStorageKey(submission.request.routeID)
        guard var state = routes[key] else { throw OpaqueRouteRelayStoreV2Error.routeNotFound }
        let effective = try monotonicTime(&state, receivedAt: receivedAt)
        state.route = try state.route.applyingRenewal(
            submission.request,
            presentedCapability: submission.renewCapability,
            confidentialTransport: confidentialTransport,
            receivedAt: effective
        )
        routes[key] = state
        return state.route
    }

    mutating func teardown(
        _ submission: OpaqueRouteTeardownSubmissionV2,
        confidentialTransport: Bool,
        receivedAt: Date
    ) throws -> OpaqueReceiveRouteV2 {
        guard submission.isStructurallyValid else { throw OpaqueRouteRelayStoreV2Error.invalidRequest }
        let key = opaqueRouteStorageKey(submission.request.routeID)
        guard var state = routes[key] else { throw OpaqueRouteRelayStoreV2Error.routeNotFound }
        let effective = try monotonicTime(&state, receivedAt: receivedAt)
        let wasActive = state.route.status == .active
        state.route = try state.route.applyingTeardown(
            submission.request,
            presentedCapability: submission.teardownCapability,
            confidentialTransport: confidentialTransport,
            receivedAt: effective
        )
        if wasActive, state.route.status == .tornDown {
            state.retentionFloor = state.nextSequence - 1
            state.packets.removeAll(keepingCapacity: false)
            state.acceptedPackets.removeAll(keepingCapacity: false)
            state.acceptedReads.removeAll(keepingCapacity: false)
            state.replayLedger = OpaqueRouteAuthorizationReplayLedgerV2()
        }
        routes[key] = state
        return state.route
    }

    mutating func append(
        _ submission: OpaqueRouteAppendSubmissionV2,
        confidentialTransport: Bool,
        receivedAt: Date
    ) throws -> OpaqueRouteAppendReceiptV2 {
        guard submission.isStructurallyValid else { throw OpaqueRouteRelayStoreV2Error.invalidRequest }
        let packet = submission.packet
        let key = opaqueRouteStorageKey(packet.routeID)
        guard var state = routes[key] else { throw OpaqueRouteRelayStoreV2Error.routeNotFound }
        if let accepted = state.acceptedPackets[packet.packetID] {
            if accepted.operationDigest == packet.operationDigest {
                try state.route.authenticateAcceptedRetry(
                    packet.authorization,
                    authority: .send,
                    expectedDigest: state.route.sendCapabilityDigest,
                    secret: submission.sendCapability.rawValue,
                    operationDigest: packet.operationDigest,
                    confidentialTransport: confidentialTransport
                )
                try advanceTimeAndCollect(&state, receivedAt: receivedAt)
                if state.acceptedPackets[packet.packetID] != nil {
                    routes[key] = state
                    return accepted.receipt
                }
            } else {
                var ledger = state.replayLedger
                try state.route.authorizeSend(
                    packet.authorization,
                    operationDigest: packet.operationDigest,
                    presentedCapability: submission.sendCapability,
                    confidentialTransport: confidentialTransport,
                    receivedAt: try monotonicTime(&state, receivedAt: receivedAt),
                    replayLedger: &ledger
                )
                routes[key] = state
                throw OpaqueRouteRelayStoreV2Error.packetIdentifierConflict
            }
        }
        let effective = try monotonicTime(&state, receivedAt: receivedAt)
        garbageCollect(&state, at: effective)
        var ledger = state.replayLedger
        try state.route.authorizeSend(
            packet.authorization,
            operationDigest: packet.operationDigest,
            presentedCapability: submission.sendCapability,
            confidentialTransport: confidentialTransport,
            receivedAt: effective,
            replayLedger: &ledger
        )
        guard packet.paddingBucket == state.route.lease.policy.paddingBucket else {
            throw OpaqueRouteRelayStoreV2Error.invalidRequest
        }
        guard state.packets.count < Int(state.route.lease.policy.quotaBucket.rawValue),
              UInt64(state.packets.count + 1) * UInt64(packet.sealedFrame.count)
                <= state.route.lease.policy.maximumStoredBytes else {
            throw OpaqueRouteRelayStoreV2Error.routeQuotaExceeded
        }
        guard state.acceptedPackets.count
                < NoctweaveOpaqueRouteRelayStoreV2.maximumAcceptedPacketIdentifiers else {
            throw OpaqueRouteRelayStoreV2Error.packetIdentifierLedgerExhausted
        }
        guard state.nextSequence < UInt64.max else { throw OpaqueRouteRelayStoreV2Error.sequenceExhausted }
        let expiry = effective.addingTimeInterval(
            TimeInterval(state.route.lease.policy.retentionBucket.rawValue)
        )
        guard expiry.timeIntervalSince1970.isFinite else {
            throw OpaqueRouteRelayStoreV2Error.invalidRequest
        }
        let sequence = state.nextSequence
        state.nextSequence += 1
        let previousRecordDigest = state.packets.last?.recordDigest
            ?? state.retentionFloorDigest
        let recordDigest = opaqueRouteRecordDigest(
            previousRecordDigest: previousRecordDigest,
            sequence: sequence,
            routeRevision: state.route.lease.renewalSequence,
            packet: packet
        )
        let cursor = try sealCursor(routeID: packet.routeID, position: sequence)
        let receipt = OpaqueRouteAppendReceiptV2(
            packetID: packet.packetID,
            acceptedCursor: cursor,
            highWatermark: cursor
        )
        state.packets.append(StoredPacket(
            sequence: sequence,
            previousRecordDigest: previousRecordDigest,
            recordDigest: recordDigest,
            routeRevision: state.route.lease.renewalSequence,
            packet: packet,
            expiresAt: expiry
        ))
        state.acceptedPackets[packet.packetID] = AcceptedPacket(
            operationDigest: packet.operationDigest,
            receipt: receipt,
            authorizationExpiresAt: packet.authorization.authorizedAt.addingTimeInterval(
                NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew
            )
        )
        state.replayLedger = ledger
        routes[key] = state
        return receipt
    }

    mutating func sync(
        _ submission: OpaqueRouteSyncSubmissionV2,
        confidentialTransport: Bool,
        receivedAt: Date
    ) throws -> OpaqueRouteSyncResponseV2 {
        guard submission.isStructurallyValid else { throw OpaqueRouteRelayStoreV2Error.invalidRequest }
        let request = submission.request
        let key = opaqueRouteStorageKey(request.routeID)
        guard var state = routes[key] else { throw OpaqueRouteRelayStoreV2Error.routeNotFound }
        if let accepted = state.acceptedReads[request.requestID] {
            if accepted.operationDigest == request.operationDigest,
               case let .sync(cached) = accepted.result {
                try state.route.authenticateAcceptedRetry(
                    request.authorization,
                    authority: .read,
                    expectedDigest: state.route.readCredentialDigest,
                    secret: submission.readCredential.rawValue,
                    operationDigest: request.operationDigest,
                    confidentialTransport: confidentialTransport
                )
                try advanceTimeAndCollect(&state, receivedAt: receivedAt)
                if state.acceptedReads[request.requestID] != nil {
                    routes[key] = state
                    return cached.response
                }
            } else {
                try authenticateConflictingRead(
                    request.authorization,
                    operationDigest: request.operationDigest,
                    presentedCredential: submission.readCredential,
                    confidentialTransport: confidentialTransport,
                    receivedAt: receivedAt,
                    state: &state
                )
                routes[key] = state
                throw OpaqueRouteRelayStoreV2Error.requestIdentifierConflict
            }
        }
        let effective = try monotonicTime(&state, receivedAt: receivedAt)
        garbageCollect(&state, at: effective)
        var ledger = state.replayLedger
        try state.route.authorizeRead(
            request.authorization,
            operationDigest: request.operationDigest,
            presentedCredential: submission.readCredential,
            confidentialTransport: confidentialTransport,
            receivedAt: effective,
            replayLedger: &ledger
        )
        guard state.acceptedReads.count
                < NoctweaveOpaqueRouteRelayStoreV2.maximumReadRequestReceipts else {
            throw OpaqueRouteRelayStoreV2Error.requestReceiptLedgerExhausted
        }
        let start: UInt64
        if let cursor = request.after {
            start = try openCursor(cursor, expectedRouteID: request.routeID)
            guard start >= state.retentionFloor else { throw OpaqueRouteRelayStoreV2Error.cursorExpired }
            guard start <= state.nextSequence - 1 else {
                throw OpaqueRouteRelayStoreV2Error.cursorAheadOfRoute
            }
        } else {
            start = state.retentionFloor
        }
        let page = state.packets.filter { $0.sequence > start }.prefix(Int(request.limit))
        let packetSequences = page.map(\.sequence)
        let nextPosition = packetSequences.last ?? start
        let highPosition = state.nextSequence - 1
        let startDigest = try recordDigest(at: start, in: state)
        let nextDigest = page.last?.recordDigest ?? startDigest
        let response = OpaqueRouteSyncResponseV2(
            packets: page.map {
                OpaqueRouteReceivedPacketV2(
                    sequence: $0.sequence,
                    previousRecordDigest: $0.previousRecordDigest,
                    recordDigest: $0.recordDigest,
                    routeRevision: $0.routeRevision,
                    packet: $0.packet
                )
            },
            startsAfterSequence: start,
            startsAfterRecordDigest: startDigest,
            nextSequence: nextPosition,
            nextRecordDigest: nextDigest,
            highWatermarkSequence: highPosition,
            retentionFloorSequence: state.retentionFloor,
            nextCursor: try sealCursor(routeID: request.routeID, position: nextPosition),
            highWatermark: try sealCursor(routeID: request.routeID, position: highPosition),
            retentionFloor: try sealCursor(routeID: request.routeID, position: state.retentionFloor),
            hasMore: state.packets.contains(where: { $0.sequence > nextPosition })
        )
        let cached = CachedSync(
            packetSequences: packetSequences,
            response: response,
            authorizationExpiresAt: request.authorization.authorizedAt.addingTimeInterval(
                NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew
            ),
            bodyExpiresAt: page.map(\.expiresAt).min()
        )
        state.acceptedReads[request.requestID] = AcceptedReadRequest(
            operationDigest: request.operationDigest,
            result: .sync(cached),
            authorizationExpiresAt: cached.authorizationExpiresAt
        )
        state.replayLedger = ledger
        routes[key] = state
        return response
    }

    mutating func commit(
        _ submission: OpaqueRouteCommitSubmissionV2,
        confidentialTransport: Bool,
        receivedAt: Date
    ) throws -> OpaqueRouteCommitResponseV2 {
        guard submission.isStructurallyValid else { throw OpaqueRouteRelayStoreV2Error.invalidRequest }
        let request = submission.request
        let key = opaqueRouteStorageKey(request.routeID)
        guard var state = routes[key] else { throw OpaqueRouteRelayStoreV2Error.routeNotFound }
        if let accepted = state.acceptedReads[request.requestID] {
            if accepted.operationDigest == request.operationDigest,
               case let .commit(response) = accepted.result {
                try state.route.authenticateAcceptedRetry(
                    request.authorization,
                    authority: .read,
                    expectedDigest: state.route.readCredentialDigest,
                    secret: submission.readCredential.rawValue,
                    operationDigest: request.operationDigest,
                    confidentialTransport: confidentialTransport
                )
                try advanceTimeAndCollect(&state, receivedAt: receivedAt)
                if state.acceptedReads[request.requestID] != nil {
                    routes[key] = state
                    return response
                }
            } else {
                try authenticateConflictingRead(
                    request.authorization,
                    operationDigest: request.operationDigest,
                    presentedCredential: submission.readCredential,
                    confidentialTransport: confidentialTransport,
                    receivedAt: receivedAt,
                    state: &state
                )
                routes[key] = state
                throw OpaqueRouteRelayStoreV2Error.requestIdentifierConflict
            }
        }
        let effective = try monotonicTime(&state, receivedAt: receivedAt)
        garbageCollect(&state, at: effective)
        var ledger = state.replayLedger
        try state.route.authorizeRead(
            request.authorization,
            operationDigest: request.operationDigest,
            presentedCredential: submission.readCredential,
            confidentialTransport: confidentialTransport,
            receivedAt: effective,
            replayLedger: &ledger
        )
        guard state.acceptedReads.count
                < NoctweaveOpaqueRouteRelayStoreV2.maximumReadRequestReceipts else {
            throw OpaqueRouteRelayStoreV2Error.requestReceiptLedgerExhausted
        }
        let position = try openCursor(request.cursor, expectedRouteID: request.routeID)
        let highPosition = state.nextSequence - 1
        guard position <= highPosition else { throw OpaqueRouteRelayStoreV2Error.cursorAheadOfRoute }
        if position > state.committedSequence, position < state.retentionFloor {
            throw OpaqueRouteRelayStoreV2Error.cursorExpired
        }
        state.committedSequence = max(state.committedSequence, position)
        garbageCollect(&state, at: effective)
        let response = OpaqueRouteCommitResponseV2(
            committedCursor: try sealCursor(routeID: request.routeID, position: state.committedSequence),
            highWatermark: try sealCursor(routeID: request.routeID, position: highPosition),
            retentionFloor: try sealCursor(routeID: request.routeID, position: state.retentionFloor)
        )
        state.acceptedReads[request.requestID] = AcceptedReadRequest(
            operationDigest: request.operationDigest,
            result: .commit(response),
            authorizationExpiresAt: request.authorization.authorizedAt.addingTimeInterval(
                NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew
            )
        )
        state.replayLedger = ledger
        routes[key] = state
        return response
    }

    private mutating func authenticateConflictingRead(
        _ proof: OpaqueRouteAuthorizationProofV2,
        operationDigest: Data,
        presentedCredential: RouteReadCredentialV2,
        confidentialTransport: Bool,
        receivedAt: Date,
        state: inout RouteState
    ) throws {
        let effective = try monotonicTime(&state, receivedAt: receivedAt)
        var ledger = state.replayLedger
        try state.route.authorizeRead(
            proof,
            operationDigest: operationDigest,
            presentedCredential: presentedCredential,
            confidentialTransport: confidentialTransport,
            receivedAt: effective,
            replayLedger: &ledger
        )
    }

    private func monotonicTime(_ state: inout RouteState, receivedAt: Date) throws -> Date {
        guard receivedAt.timeIntervalSince1970.isFinite else {
            throw OpaqueRouteRelayStoreV2Error.invalidRequest
        }
        let effective = max(state.observedAtHighWatermark, receivedAt)
        state.observedAtHighWatermark = effective
        return effective
    }

    private func advanceTimeAndCollect(_ state: inout RouteState, receivedAt: Date) throws {
        garbageCollect(&state, at: try monotonicTime(&state, receivedAt: receivedAt))
    }

    private func garbageCollect(_ state: inout RouteState, at receivedAt: Date) {
        let high = state.nextSequence - 1
        if state.route.status != .active || !state.route.lease.isActive(at: receivedAt) {
            state.retentionFloorDigest = state.packets.last?.recordDigest
                ?? state.retentionFloorDigest
            state.packets.removeAll(keepingCapacity: false)
            state.retentionFloor = high
            pruneReceipts(&state, at: receivedAt)
            return
        }
        var removedThrough = state.retentionFloor
        while let first = state.packets.first,
              first.sequence <= state.committedSequence || first.expiresAt <= receivedAt {
            removedThrough = first.sequence
            state.retentionFloorDigest = first.recordDigest
            state.packets.removeFirst()
        }
        state.retentionFloor = max(state.retentionFloor, removedThrough)
        pruneReceipts(&state, at: receivedAt)
    }

    private func pruneReceipts(_ state: inout RouteState, at receivedAt: Date) {
        let retainedSequences = Set(state.packets.map(\.sequence))
        let retainedPacketIDs = Set(state.packets.map { $0.packet.packetID })
        state.acceptedPackets = state.acceptedPackets.filter { packetID, receipt in
            retainedPacketIDs.contains(packetID) || receipt.authorizationExpiresAt >= receivedAt
        }
        state.acceptedReads = state.acceptedReads.filter { _, receipt in
            switch receipt.result {
            case let .sync(sync):
                let bodiesRetained = !sync.packetSequences.isEmpty
                    && sync.packetSequences.allSatisfy(retainedSequences.contains)
                let responseWithinTTL = sync.bodyExpiresAt.map { $0 > receivedAt } ?? true
                return responseWithinTTL && (bodiesRetained || sync.authorizationExpiresAt >= receivedAt)
            case .commit:
                return receipt.authorizationExpiresAt >= receivedAt
            }
        }
    }

    private func recordDigest(at sequence: UInt64, in state: RouteState) throws -> Data {
        if sequence == state.retentionFloor {
            return state.retentionFloorDigest
        }
        guard let packet = state.packets.first(where: { $0.sequence == sequence }) else {
            throw OpaqueRouteRelayStoreV2Error.invalidCursor
        }
        return packet.recordDigest
    }

    private func sealCursor(
        routeID: OpaqueReceiveRouteIDV2,
        position: UInt64
    ) throws -> OpaqueRouteCursorV2 {
        var claims = Data(routeID.rawValue)
        opaqueRouteStoreAppend(position, to: &claims)
        let box = try AES.GCM.seal(
            claims,
            using: SymmetricKey(data: cursorKey),
            nonce: AES.GCM.Nonce(),
            authenticating: Data("org.noctweave.opaque-route.cursor/v2".utf8)
        )
        var token = Data(box.nonce)
        token.append(box.ciphertext)
        token.append(box.tag)
        guard token.count == NoctweaveOpaqueRouteRelayStoreV2.cursorBytes else {
            throw OpaqueRouteRelayStoreV2Error.invalidCursor
        }
        return OpaqueRouteCursorV2(rawValue: token)
    }

    private func openCursor(
        _ cursor: OpaqueRouteCursorV2,
        expectedRouteID: OpaqueReceiveRouteIDV2
    ) throws -> UInt64 {
        guard cursor.isStructurallyValid else { throw OpaqueRouteRelayStoreV2Error.invalidCursor }
        let nonceEnd = 12
        let tagStart = cursor.rawValue.count - 16
        let claims: Data
        do {
            let nonce = try AES.GCM.Nonce(data: cursor.rawValue.prefix(nonceEnd))
            let box = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: cursor.rawValue[nonceEnd..<tagStart],
                tag: cursor.rawValue[tagStart...]
            )
            claims = try AES.GCM.open(
                box,
                using: SymmetricKey(data: cursorKey),
                authenticating: Data("org.noctweave.opaque-route.cursor/v2".utf8)
            )
        } catch {
            throw OpaqueRouteRelayStoreV2Error.invalidCursor
        }
        guard claims.count == 40, Data(claims.prefix(32)) == expectedRouteID.rawValue else {
            throw OpaqueRouteRelayStoreV2Error.invalidCursor
        }
        return claims.suffix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }
}

func opaqueRouteCredentialDigest(_ authority: OpaqueRouteAuthorityV2, _ secret: Data) -> Data {
    opaqueRouteDigest(
        domain: "org.noctweave.opaque-route.credential.\(authority.rawValue)/v2",
        components: [secret]
    )
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
    try RelayCodec.encoder(sortedKeys: true).encode(OpaqueRouteAuthorizationMACPayloadV2(
        version: NoctweaveOpaqueRoutesV2.version,
        authority: authority,
        routeID: routeID,
        operationDigest: operationDigest,
        authorizedAt: authorizedAt,
        nonce: nonce
    ))
}

private func opaqueRouteValidateAuthorizationTime(_ authorizedAt: Date, at receivedAt: Date) throws {
    guard authorizedAt.timeIntervalSince1970.isFinite,
          receivedAt.timeIntervalSince1970.isFinite,
          abs(receivedAt.timeIntervalSince(authorizedAt))
            <= NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew else {
        throw OpaqueRouteV2Error.authorizationExpired
    }
}

private func opaqueRouteStorageKey(_ routeID: OpaqueReceiveRouteIDV2) -> String {
    routeID.rawValue.base64EncodedString()
}

private func opaqueRouteIsValidFixedValue(_ value: Data) -> Bool {
    value.count == NoctweaveOpaqueRoutesV2.credentialBytes && value.contains(where: { $0 != 0 })
}

private func opaqueRouteIsValidDigest(_ value: Data) -> Bool {
    value.count == NoctweaveOpaqueRoutesV2.digestBytes
}

private func opaqueRouteRandomNonzeroValue() -> Data {
    var generator = SystemRandomNumberGenerator()
    while true {
        let value = Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
        if value.contains(where: { $0 != 0 }) { return value }
    }
}

private func opaqueRouteDigest(domain: String, components: [Data]) -> Data {
    var material = Data(domain.utf8)
    for component in components {
        opaqueRouteStoreAppend(UInt64(component.count), to: &material)
        material.append(component)
    }
    return Data(SHA256.hash(data: material))
}

private func opaqueRouteStoreDigest(domain: String, components: [Data]) -> Data {
    var material = Data(domain.utf8)
    material.append(0)
    for component in components {
        opaqueRouteStoreAppend(UInt64(component.count), to: &material)
        material.append(component)
    }
    return Data(SHA256.hash(data: material))
}

private func opaqueRouteRecordDigest(
    previousRecordDigest: Data,
    sequence: UInt64,
    routeRevision: UInt64,
    packet: OpaqueRoutePacketV2
) -> Data {
    opaqueRouteStoreDigest(
        domain: "org.noctweave.opaque-route.record/v2",
        components: [
            previousRecordDigest,
            opaqueRouteStoreIntegerBytes(sequence),
            opaqueRouteStoreIntegerBytes(routeRevision),
            packet.routeID.rawValue,
            packet.packetID.rawValue,
            packet.operationDigest,
            packet.authorization.nonce.rawValue,
            packet.authorization.mac,
        ]
    )
}

private func opaqueRouteStoreIntegerBytes<T: FixedWidthInteger>(_ value: T) -> Data {
    var data = Data()
    opaqueRouteStoreAppend(value, to: &data)
    return data
}

private func opaqueRouteStoreAppend<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
    var bigEndian = value.bigEndian
    Swift.withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
}

private struct OpaqueRouteRelayCodingKey: CodingKey {
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

private func opaqueRouteRelayRequireExactObject(
    _ decoder: Decoder,
    keys: [String]
) throws {
    let container = try decoder.container(keyedBy: OpaqueRouteRelayCodingKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == Set(keys) else {
        throw DecodingError.dataCorrupted(
            DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: "Opaque route relay fields must match the current protocol exactly"
            )
        )
    }
}

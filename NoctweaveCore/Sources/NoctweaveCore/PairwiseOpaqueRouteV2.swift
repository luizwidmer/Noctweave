import Foundation

public enum RelationshipRouteStateV2: String, Codable, Equatable, CaseIterable {
    case testing
    case active
    case draining
    case revoked
}

extension RelayEndpoint {
    var isStructurallyValidRelationshipRouteEndpointV2Throwing: Bool {
        get throws {
            let normalizedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !normalizedHost.isEmpty,
                  normalizedHost == host,
                  normalizedHost.utf8.count <= 255,
                  normalizedHost.unicodeScalars.allSatisfy({
                      !CharacterSet.controlCharacters.contains($0)
                  }),
                  port > 0,
                  tlsCertificateFingerprintSHA256.map({ $0.count == 32 }) ?? true else {
                return false
            }
            if let directorySigningPublicKey {
                return try SigningKeyPair.isValidPublicKeyThrowing(
                    directorySigningPublicKey
                )
            }
            return true
        }
    }

    var isStructurallyValidRelationshipRouteEndpointV2: Bool {
        (try? isStructurallyValidRelationshipRouteEndpointV2Throwing) == true
    }

    /// Route capabilities are write authority. They require TLS except for
    /// literal loopback development and same-host operator access.
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

public enum PairwiseOpaqueRouteV2Error: Error, Equatable {
    case invalidRoute
    case invalidIntroduction
    case wrongRendezvous
    case expiredIntroduction
    case invalidSignature
}

/// The only route material disclosed to a peer. It is carried inside an
/// authenticated pairwise or rendezvous ciphertext. Read, renewal, and
/// teardown authority never leave the receiving endpoint that owns the route.
public struct OpaqueSendRouteV2: Codable, Equatable, Identifiable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var id: OpaqueReceiveRouteIDV2 { routeID }
    public let routeID: OpaqueReceiveRouteIDV2
    public let relay: RelayEndpoint
    public let sendCapability: RouteSendCapabilityV2
    public let payloadKey: OpaqueRoutePayloadKeyV2
    public let routeRevision: UInt64
    public let policy: OpaqueRoutePolicyV2
    public let validFrom: Date
    public let expiresAt: Date
    public let priority: UInt16
    public let state: RelationshipRouteStateV2
    public let testedAt: Date?
    public let drainAfter: Date?
    public let revokedAt: Date?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case routeID
        case relay
        case sendCapability
        case payloadKey
        case routeRevision
        case policy
        case validFrom
        case expiresAt
        case priority
        case state
        case testedAt
        case drainAfter
        case revokedAt
    }

    public init(
        routeID: OpaqueReceiveRouteIDV2,
        relay: RelayEndpoint,
        sendCapability: RouteSendCapabilityV2,
        payloadKey: OpaqueRoutePayloadKeyV2,
        routeRevision: UInt64,
        policy: OpaqueRoutePolicyV2,
        validFrom: Date,
        expiresAt: Date,
        priority: UInt16 = 100,
        state: RelationshipRouteStateV2,
        testedAt: Date? = nil,
        drainAfter: Date? = nil,
        revokedAt: Date? = nil
    ) throws {
        self.routeID = routeID
        self.relay = relay
        self.sendCapability = sendCapability
        self.payloadKey = payloadKey
        self.routeRevision = routeRevision
        self.policy = policy
        self.validFrom = validFrom
        self.expiresAt = expiresAt
        self.priority = priority
        self.state = state
        self.testedAt = testedAt
        self.drainAfter = drainAfter
        self.revokedAt = revokedAt
        guard try isStructurallyValidThrowing else {
            throw PairwiseOpaqueRouteV2Error.invalidRoute
        }
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PairwiseOpaqueRouteCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Pairwise send route fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            routeID: container.decode(OpaqueReceiveRouteIDV2.self, forKey: .routeID),
            relay: container.decode(RelayEndpoint.self, forKey: .relay),
            sendCapability: container.decode(RouteSendCapabilityV2.self, forKey: .sendCapability),
            payloadKey: container.decode(OpaqueRoutePayloadKeyV2.self, forKey: .payloadKey),
            routeRevision: container.decode(UInt64.self, forKey: .routeRevision),
            policy: container.decode(OpaqueRoutePolicyV2.self, forKey: .policy),
            validFrom: container.decode(Date.self, forKey: .validFrom),
            expiresAt: container.decode(Date.self, forKey: .expiresAt),
            priority: container.decode(UInt16.self, forKey: .priority),
            state: container.decode(RelationshipRouteStateV2.self, forKey: .state),
            testedAt: container.decodeIfPresent(Date.self, forKey: .testedAt),
            drainAfter: container.decodeIfPresent(Date.self, forKey: .drainAfter),
            revokedAt: container.decodeIfPresent(Date.self, forKey: .revokedAt)
        )
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Pairwise send route is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(routeID, forKey: .routeID)
        try container.encode(relay, forKey: .relay)
        try container.encode(sendCapability, forKey: .sendCapability)
        try container.encode(payloadKey, forKey: .payloadKey)
        try container.encode(routeRevision, forKey: .routeRevision)
        try container.encode(policy, forKey: .policy)
        try container.encode(validFrom, forKey: .validFrom)
        try container.encode(expiresAt, forKey: .expiresAt)
        try container.encode(priority, forKey: .priority)
        try container.encode(state, forKey: .state)
        if let testedAt {
            try container.encode(testedAt, forKey: .testedAt)
        } else {
            try container.encodeNil(forKey: .testedAt)
        }
        if let drainAfter {
            try container.encode(drainAfter, forKey: .drainAfter)
        } else {
            try container.encodeNil(forKey: .drainAfter)
        }
        if let revokedAt {
            try container.encode(revokedAt, forKey: .revokedAt)
        } else {
            try container.encodeNil(forKey: .revokedAt)
        }
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard try relay.isStructurallyValidRelationshipRouteEndpointV2Throwing else {
                return false
            }
            return routeID.isStructurallyValid
                && relay.isConfidentialCapabilityTransportV2
                && sendCapability.isStructurallyValid
                && payloadKey.isStructurallyValid
                && policy.isStructurallyValid
                && validFrom.timeIntervalSince1970.isFinite
                && expiresAt.timeIntervalSince1970.isFinite
                && expiresAt > validFrom
                && testedAt?.timeIntervalSince1970.isFinite != false
                && drainAfter?.timeIntervalSince1970.isFinite != false
                && revokedAt?.timeIntervalSince1970.isFinite != false
                && lifecycleIsStructurallyValid
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    public func isUsable(at date: Date) -> Bool {
        guard isStructurallyValid,
              date.timeIntervalSince1970.isFinite,
              date >= validFrom,
              date < expiresAt else {
            return false
        }
        switch state {
        case .active:
            return true
        case .draining:
            return drainAfter.map { date < $0 } ?? false
        case .testing, .revoked:
            return false
        }
    }

    func replacingLifecycle(
        state: RelationshipRouteStateV2,
        testedAt: Date?,
        drainAfter: Date?,
        revokedAt: Date?
    ) throws -> OpaqueSendRouteV2 {
        try OpaqueSendRouteV2(
            routeID: routeID,
            relay: relay,
            sendCapability: sendCapability,
            payloadKey: payloadKey,
            routeRevision: routeRevision,
            policy: policy,
            validFrom: validFrom,
            expiresAt: expiresAt,
            priority: priority,
            state: state,
            testedAt: testedAt,
            drainAfter: drainAfter,
            revokedAt: revokedAt
        )
    }

    private var lifecycleIsStructurallyValid: Bool {
        guard testedAt.map({ $0 >= validFrom && $0 < expiresAt }) ?? true,
              drainAfter.map({ $0 > validFrom && $0 <= expiresAt }) ?? true,
              revokedAt.map({ $0 >= validFrom }) ?? true else {
            return false
        }
        switch state {
        case .testing:
            return drainAfter == nil && revokedAt == nil
        case .active:
            return testedAt != nil && drainAfter == nil && revokedAt == nil
        case .draining:
            return testedAt != nil && drainAfter != nil && revokedAt == nil
        case .revoked:
            guard let revokedAt else { return false }
            return drainAfter.map { revokedAt >= $0 } ?? true
        }
    }

    public var description: String { "OpaqueSendRouteV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

/// Endpoint-local receive authority. This record may be persisted only in the
/// endpoint's encrypted state. It is never placed in a contact introduction,
/// pairwise route set, group state, history projection, or relay response.
public enum OpaqueRouteGapReasonV2: String, Codable, Equatable, CaseIterable {
    case retentionExpired
    case sequenceDiscontinuity
    case digestChainBreak
    case cursorRegression
}

public struct OpaqueRouteGapStateV2: Codable, Equatable {
    public let reason: OpaqueRouteGapReasonV2
    public let expectedSequence: UInt64
    public let observedSequence: UInt64
    public let retentionFloorSequence: UInt64
    public let detectedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case reason
        case expectedSequence
        case observedSequence
        case retentionFloorSequence
        case detectedAt
    }

    public init(
        reason: OpaqueRouteGapReasonV2,
        expectedSequence: UInt64,
        observedSequence: UInt64,
        retentionFloorSequence: UInt64,
        detectedAt: Date
    ) {
        self.reason = reason
        self.expectedSequence = expectedSequence
        self.observedSequence = observedSequence
        self.retentionFloorSequence = retentionFloorSequence
        self.detectedAt = detectedAt
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PairwiseOpaqueRouteCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Opaque route gap fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            reason: try container.decode(OpaqueRouteGapReasonV2.self, forKey: .reason),
            expectedSequence: try container.decode(UInt64.self, forKey: .expectedSequence),
            observedSequence: try container.decode(UInt64.self, forKey: .observedSequence),
            retentionFloorSequence: try container.decode(
                UInt64.self,
                forKey: .retentionFloorSequence
            ),
            detectedAt: try container.decode(Date.self, forKey: .detectedAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .detectedAt,
                in: container,
                debugDescription: "Opaque route gap state is invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Opaque route gap state is invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(reason, forKey: .reason)
        try container.encode(expectedSequence, forKey: .expectedSequence)
        try container.encode(observedSequence, forKey: .observedSequence)
        try container.encode(retentionFloorSequence, forKey: .retentionFloorSequence)
        try container.encode(detectedAt, forKey: .detectedAt)
    }

    public var isStructurallyValid: Bool {
        detectedAt.timeIntervalSince1970.isFinite
    }
}

/// Local capability material for a replacement receive route before the relay
/// confirms creation. It contains no relationship or persona identifier.
public struct PendingLocalOpaqueReceiveRouteV2: Codable, Equatable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let version = 2

    public let version: Int
    public let relay: RelayEndpoint
    public let clientCapabilities: OpaqueRouteClientCapabilityMaterialV2
    public let payloadKey: OpaqueRoutePayloadKeyV2
    public let createRequest: OpaqueRouteCreateRequestV2
    public let createdAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case relay
        case clientCapabilities
        case payloadKey
        case createRequest
        case createdAt
    }

    private init(
        relay: RelayEndpoint,
        clientCapabilities: OpaqueRouteClientCapabilityMaterialV2,
        payloadKey: OpaqueRoutePayloadKeyV2,
        createRequest: OpaqueRouteCreateRequestV2,
        createdAt: Date
    ) {
        self.version = Self.version
        self.relay = relay
        self.clientCapabilities = clientCapabilities
        self.payloadKey = payloadKey
        self.createRequest = createRequest
        self.createdAt = createdAt
    }

    public static func prepare(
        relay: RelayEndpoint,
        policy: OpaqueRoutePolicyV2 = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .sixHours,
            quotaBucket: .packets256
        ),
        createdAt: Date = Date()
    ) throws -> PendingLocalOpaqueReceiveRouteV2 {
        let capabilities = try OpaqueRouteClientCapabilityMaterialV2()
        let lease = try OpaqueRouteLeaseV2(
            issuedAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(6 * 60 * 60),
            policy: policy
        )
        let result = PendingLocalOpaqueReceiveRouteV2(
            relay: relay,
            clientCapabilities: capabilities,
            payloadKey: .generate(),
            createRequest: try capabilities.makeCreateRequest(
                lease: lease,
                idempotencyKey: .generate()
            ),
            createdAt: createdAt
        )
        guard try result.isStructurallyValidThrowing else {
            throw PairwiseOpaqueRouteV2Error.invalidRoute
        }
        return result
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PairwiseOpaqueRouteCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Pending local route fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedVersion = try container.decode(Int.self, forKey: .version)
        guard decodedVersion == Self.version else {
            throw DecodingError.dataCorruptedError(
                forKey: .version,
                in: container,
                debugDescription: "Pending local route version is invalid"
            )
        }
        self.init(
            relay: try container.decode(RelayEndpoint.self, forKey: .relay),
            clientCapabilities: try container.decode(
                OpaqueRouteClientCapabilityMaterialV2.self,
                forKey: .clientCapabilities
            ),
            payloadKey: try container.decode(OpaqueRoutePayloadKeyV2.self, forKey: .payloadKey),
            createRequest: try container.decode(OpaqueRouteCreateRequestV2.self, forKey: .createRequest),
            createdAt: try container.decode(Date.self, forKey: .createdAt)
        )
        guard try isStructurallyValidThrowing else {
            throw DecodingError.dataCorruptedError(
                forKey: .createRequest,
                in: container,
                debugDescription: "Pending local route is invalid"
            )
        }
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard try relay.isStructurallyValidRelationshipRouteEndpointV2Throwing else {
                return false
            }
            return version == Self.version
                && relay.isConfidentialCapabilityTransportV2
                && clientCapabilities.isStructurallyValid
                && payloadKey.isStructurallyValid
                && createRequest.isStructurallyValid
                && createRequest.routeID == clientCapabilities.routeID
                && createRequest.lease.issuedAt == createdAt
                && createdAt.timeIntervalSince1970.isFinite
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    public func activate(
        createdRoute: OpaqueReceiveRouteV2
    ) throws -> LocalOpaqueReceiveRouteV2 {
        guard try isStructurallyValidThrowing,
              let transitionDigest = createRequest.transitionDigest,
              createdRoute.status == .active,
              createdRoute.routeID == createRequest.routeID,
              createdRoute.creationIdempotencyKey == createRequest.idempotencyKey,
              createdRoute.creationDigest == transitionDigest,
              createdRoute.matches(clientCapabilities: clientCapabilities) else {
            throw PairwiseOpaqueRouteV2Error.invalidRoute
        }
        return try LocalOpaqueReceiveRouteV2(
            relay: relay,
            route: createdRoute,
            clientCapabilities: clientCapabilities,
            payloadKey: payloadKey
        )
    }

    public var description: String { "PendingLocalOpaqueReceiveRouteV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

public struct LocalOpaqueReceiveRouteV2: Codable, Equatable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Per-route plaintext-fragment budget reserved inside the bounded,
    /// encrypted client-state document. Eight maximum-sized route states plus
    /// base64 expansion remain well below `ClientStateStore`'s plaintext cap.
    public static let maximumPersistedReassemblerBufferedBytes = 1 * 1_024 * 1_024

    public let relay: RelayEndpoint
    public let route: OpaqueReceiveRouteV2
    public let clientCapabilities: OpaqueRouteClientCapabilityMaterialV2
    public let payloadKey: OpaqueRoutePayloadKeyV2
    public var committedCursor: OpaqueRouteCursorV2?
    public var committedSequence: UInt64
    public var committedRecordDigest: Data
    public var gapState: OpaqueRouteGapStateV2?
    public private(set) var reassembler: OpaqueRoutePacketReassemblerV2

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case relay
        case route
        case clientCapabilities
        case payloadKey
        case committedCursor
        case committedSequence
        case committedRecordDigest
        case gapState
        case reassembler
    }

    public init(
        relay: RelayEndpoint,
        route: OpaqueReceiveRouteV2,
        clientCapabilities: OpaqueRouteClientCapabilityMaterialV2,
        payloadKey: OpaqueRoutePayloadKeyV2,
        committedCursor: OpaqueRouteCursorV2? = nil,
        committedSequence: UInt64 = 0,
        committedRecordDigest: Data = Data(
            repeating: 0,
            count: NoctweaveOpaqueRoutesV2.digestBytes
        ),
        gapState: OpaqueRouteGapStateV2? = nil,
        reassembler: OpaqueRoutePacketReassemblerV2 = .empty
    ) throws {
        self.relay = relay
        self.route = route
        self.clientCapabilities = clientCapabilities
        self.payloadKey = payloadKey
        self.committedCursor = committedCursor
        self.committedSequence = committedSequence
        self.committedRecordDigest = committedRecordDigest
        self.gapState = gapState
        self.reassembler = reassembler
        guard try isStructurallyValidThrowing else {
            throw PairwiseOpaqueRouteV2Error.invalidRoute
        }
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PairwiseOpaqueRouteCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Local opaque route fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            relay: container.decode(RelayEndpoint.self, forKey: .relay),
            route: container.decode(OpaqueReceiveRouteV2.self, forKey: .route),
            clientCapabilities: container.decode(
                OpaqueRouteClientCapabilityMaterialV2.self,
                forKey: .clientCapabilities
            ),
            payloadKey: container.decode(OpaqueRoutePayloadKeyV2.self, forKey: .payloadKey),
            committedCursor: container.decodeIfPresent(
                OpaqueRouteCursorV2.self,
                forKey: .committedCursor
            ),
            committedSequence: container.decode(UInt64.self, forKey: .committedSequence),
            committedRecordDigest: container.decode(Data.self, forKey: .committedRecordDigest),
            gapState: container.decodeIfPresent(OpaqueRouteGapStateV2.self, forKey: .gapState),
            reassembler: container.decode(
                OpaqueRoutePacketReassemblerV2.self,
                forKey: .reassembler
            )
        )
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Local opaque route is invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(relay, forKey: .relay)
        try container.encode(route, forKey: .route)
        try container.encode(clientCapabilities, forKey: .clientCapabilities)
        try container.encode(payloadKey, forKey: .payloadKey)
        try container.encode(committedCursor, forKey: .committedCursor)
        try container.encode(committedSequence, forKey: .committedSequence)
        try container.encode(committedRecordDigest, forKey: .committedRecordDigest)
        try container.encode(gapState, forKey: .gapState)
        try container.encode(reassembler, forKey: .reassembler)
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard try relay.isStructurallyValidRelationshipRouteEndpointV2Throwing else {
                return false
            }
            return relay.isConfidentialCapabilityTransportV2
                && route.status == .active
                && route.matches(clientCapabilities: clientCapabilities)
                && payloadKey.isStructurallyValid
                && committedCursor?.isStructurallyValid != false
                && committedRecordDigest.count == NoctweaveOpaqueRoutesV2.digestBytes
                && (committedCursor != nil
                    || (committedSequence == 0
                        && committedRecordDigest == Data(
                            repeating: 0,
                            count: NoctweaveOpaqueRoutesV2.digestBytes
                        )))
                && gapState?.isStructurallyValid != false
                && reassembler.maximumBufferedBytes
                    <= Self.maximumPersistedReassemblerBufferedBytes
                && reassembler.isStructurallyValid(for: route.routeID)
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    public mutating func replaceReassembler(
        with replacement: OpaqueRoutePacketReassemblerV2
    ) throws {
        guard replacement.maximumBufferedBytes
                <= Self.maximumPersistedReassemblerBufferedBytes,
              replacement.isStructurallyValid(for: route.routeID) else {
            throw PairwiseOpaqueRouteV2Error.invalidRoute
        }
        reassembler = replacement
    }

    /// Applies an update transactionally: a throwing or structurally invalid
    /// mutation leaves the persisted reassembler unchanged.
    @discardableResult
    public mutating func updateReassembler<Result>(
        _ update: (inout OpaqueRoutePacketReassemblerV2) throws -> Result
    ) throws -> Result {
        var replacement = reassembler
        let result = try update(&replacement)
        try replaceReassembler(with: replacement)
        return result
    }

    public func peerSendRoute(
        priority: UInt16 = 100,
        state: RelationshipRouteStateV2 = .active
    ) throws -> OpaqueSendRouteV2 {
        try OpaqueSendRouteV2(
            routeID: route.routeID,
            relay: relay,
            sendCapability: clientCapabilities.sendCapability,
            payloadKey: payloadKey,
            routeRevision: route.lease.renewalSequence,
            policy: route.lease.policy,
            validFrom: route.lease.issuedAt,
            expiresAt: route.lease.expiresAt,
            priority: priority,
            state: state,
            testedAt: state == .active ? route.lease.issuedAt : nil
        )
    }

    public var description: String { "LocalOpaqueReceiveRouteV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

/// One-use pairwise identity and route disclosure exchanged only after a PQ
/// rendezvous session is authenticated. Both the relationship identity and
/// receive routes are freshly scoped to this relationship, preventing reuse of
/// a public contact package as either identity or reachability metadata.
public struct ContactIntroductionV2: Codable, Equatable {
    public static let version = 2

    public let version: Int
    public let relationshipPseudonym: String
    public let relationshipSigningPublicKey: Data
    public let relationshipAgreementPublicKey: Data
    public let endpointBinding: RelationshipEndpointBindingV4
    public let receiveRoutes: PairwiseRouteSetV2
    public let rendezvousTranscriptDigest: Data
    public let issuedAt: Date
    public let expiresAt: Date
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case relationshipPseudonym
        case relationshipSigningPublicKey
        case relationshipAgreementPublicKey
        case endpointBinding
        case receiveRoutes
        case rendezvousTranscriptDigest
        case issuedAt
        case expiresAt
        case signature
    }

    public init(
        version: Int = Self.version,
        relationshipPseudonym: String,
        relationshipSigningPublicKey: Data,
        relationshipAgreementPublicKey: Data,
        endpointBinding: RelationshipEndpointBindingV4,
        receiveRoutes: PairwiseRouteSetV2,
        rendezvousTranscriptDigest: Data,
        issuedAt: Date,
        expiresAt: Date,
        signature: Data
    ) {
        self.version = version
        self.relationshipPseudonym = relationshipPseudonym
        self.relationshipSigningPublicKey = relationshipSigningPublicKey
        self.relationshipAgreementPublicKey = relationshipAgreementPublicKey
        self.endpointBinding = endpointBinding
        self.receiveRoutes = receiveRoutes
        self.rendezvousTranscriptDigest = rendezvousTranscriptDigest
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.signature = signature
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PairwiseOpaqueRouteCodingKey.self)
        let expected = Set(CodingKeys.allCases.map(\.rawValue))
        guard Set(strict.allKeys.map(\.stringValue)) == expected else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Contact introduction fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try container.decode(Int.self, forKey: .version),
            relationshipPseudonym: try container.decode(String.self, forKey: .relationshipPseudonym),
            relationshipSigningPublicKey: try container.decode(Data.self, forKey: .relationshipSigningPublicKey),
            relationshipAgreementPublicKey: try container.decode(Data.self, forKey: .relationshipAgreementPublicKey),
            endpointBinding: try container.decode(RelationshipEndpointBindingV4.self, forKey: .endpointBinding),
            receiveRoutes: try container.decode(PairwiseRouteSetV2.self, forKey: .receiveRoutes),
            rendezvousTranscriptDigest: try container.decode(Data.self, forKey: .rendezvousTranscriptDigest),
            issuedAt: try container.decode(Date.self, forKey: .issuedAt),
            expiresAt: try container.decode(Date.self, forKey: .expiresAt),
            signature: try container.decode(Data.self, forKey: .signature)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .signature,
                in: container,
                debugDescription: "Contact introduction is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Contact introduction is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(relationshipPseudonym, forKey: .relationshipPseudonym)
        try container.encode(relationshipSigningPublicKey, forKey: .relationshipSigningPublicKey)
        try container.encode(relationshipAgreementPublicKey, forKey: .relationshipAgreementPublicKey)
        try container.encode(endpointBinding, forKey: .endpointBinding)
        try container.encode(receiveRoutes, forKey: .receiveRoutes)
        try container.encode(rendezvousTranscriptDigest, forKey: .rendezvousTranscriptDigest)
        try container.encode(issuedAt, forKey: .issuedAt)
        try container.encode(expiresAt, forKey: .expiresAt)
        try container.encode(signature, forKey: .signature)
    }

    public static func create(
        relationshipPseudonym: String,
        relationshipAuthority: RelationshipAuthorityV2,
        endpointBinding: RelationshipEndpointBindingV4,
        receiveRoutes: PairwiseRouteSetV2,
        rendezvousTranscriptDigest: Data,
        issuedAt: Date,
        expiresAt: Date
    ) throws -> ContactIntroductionV2 {
        guard relationshipPseudonym == relationshipAuthority.relationshipPseudonym else {
            throw PairwiseOpaqueRouteV2Error.invalidIntroduction
        }
        do {
            _ = try endpointBinding.verified(
                authoritySigningPublicKey: relationshipAuthority.signingKey.publicKeyData,
                now: endpointBinding.prekeyBundle.createdAt
            )
        } catch let error as CryptoError {
            throw error
        } catch {
            throw PairwiseOpaqueRouteV2Error.invalidIntroduction
        }
        var introduction = ContactIntroductionV2(
            relationshipPseudonym: relationshipPseudonym,
            relationshipSigningPublicKey: relationshipAuthority.signingKey.publicKeyData,
            relationshipAgreementPublicKey: relationshipAuthority.agreementKey.publicKeyData,
            endpointBinding: endpointBinding,
            receiveRoutes: receiveRoutes,
            rendezvousTranscriptDigest: rendezvousTranscriptDigest,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            signature: Data(repeating: 0, count: 3_309)
        )
        guard try introduction.hasValidUnsignedStructureThrowing else {
            throw PairwiseOpaqueRouteV2Error.invalidIntroduction
        }
        introduction = ContactIntroductionV2(
            relationshipPseudonym: introduction.relationshipPseudonym,
            relationshipSigningPublicKey: introduction.relationshipSigningPublicKey,
            relationshipAgreementPublicKey: introduction.relationshipAgreementPublicKey,
            endpointBinding: introduction.endpointBinding,
            receiveRoutes: introduction.receiveRoutes,
            rendezvousTranscriptDigest: introduction.rendezvousTranscriptDigest,
            issuedAt: introduction.issuedAt,
            expiresAt: introduction.expiresAt,
            signature: try relationshipAuthority.signingKey.sign(introduction.signableData())
        )
        guard try introduction.isStructurallyValidThrowing else {
            throw PairwiseOpaqueRouteV2Error.invalidIntroduction
        }
        return introduction
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard try hasValidUnsignedStructureThrowing else { return false }
            return signature.count == 3_309
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    public func verified(
        for rendezvousTranscriptDigest: Data,
        at date: Date = Date()
    ) throws -> ContactIntroductionV2 {
        guard self.rendezvousTranscriptDigest == rendezvousTranscriptDigest else {
            throw PairwiseOpaqueRouteV2Error.wrongRendezvous
        }
        guard date.timeIntervalSince1970.isFinite, date >= issuedAt, date < expiresAt else {
            throw PairwiseOpaqueRouteV2Error.expiredIntroduction
        }
        // Probe the required PQ primitives before aggregate Bool validation
        // so a missing local algorithm/runtime is never reported as hostile
        // peer material.
        guard try SigningKeyPair.isValidPublicKeyThrowing(
                  relationshipSigningPublicKey
              ),
              try AgreementKeyPair.isValidPublicKeyThrowing(
                  relationshipAgreementPublicKey
              ),
              try receiveRoutes.verifyThrowing(
                  ownerSigningPublicKey: endpointBinding.signingPublicKey
              ),
              try isStructurallyValidThrowing else {
            throw PairwiseOpaqueRouteV2Error.invalidIntroduction
        }
        let signable = try signableData()
        guard try SigningKeyPair.verifyThrowing(
                  signature: signature,
                  data: signable,
                  publicKeyData: relationshipSigningPublicKey
              ) else {
            throw PairwiseOpaqueRouteV2Error.invalidSignature
        }
        do {
            _ = try endpointBinding.verified(
                authoritySigningPublicKey: relationshipSigningPublicKey,
                now: endpointBinding.prekeyBundle.createdAt
            )
        } catch let error as CryptoError {
            throw error
        } catch {
            throw PairwiseOpaqueRouteV2Error.invalidIntroduction
        }
        return self
    }

    private var hasValidUnsignedStructure: Bool {
        (try? hasValidUnsignedStructureThrowing) == true
    }

    private var hasValidUnsignedStructureThrowing: Bool {
        get throws {
        let pseudonym = relationshipPseudonym.trimmingCharacters(in: .whitespacesAndNewlines)
        let introductionLifetime = expiresAt.timeIntervalSince(issuedAt)
        guard version == Self.version,
              !pseudonym.isEmpty,
              pseudonym == relationshipPseudonym,
              pseudonym.utf8.count <= 512,
              try SigningKeyPair.isValidPublicKeyThrowing(relationshipSigningPublicKey),
              try AgreementKeyPair.isValidPublicKeyThrowing(relationshipAgreementPublicKey),
              try receiveRoutes.isStructurallyValidThrowing,
              try receiveRoutes.verifyThrowing(
                  ownerSigningPublicKey: endpointBinding.signingPublicKey
              ) else {
            return false
        }
        return !receiveRoutes.usableRoutes(at: issuedAt).isEmpty
            && rendezvousTranscriptDigest.count == 32
            && issuedAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && introductionLifetime > 0
            && introductionLifetime <= NoctweaveRendezvousV2.maximumLifetime
            && receiveRoutes.usableRoutes(at: issuedAt).allSatisfy { $0.expiresAt > expiresAt }
        }
    }

    private func signableData() throws -> Data {
        try NoctweaveCoder.encode(
            ContactIntroductionSignaturePayloadV2(
                version: version,
                relationshipPseudonym: relationshipPseudonym,
                relationshipSigningPublicKey: relationshipSigningPublicKey,
                relationshipAgreementPublicKey: relationshipAgreementPublicKey,
                endpointBinding: endpointBinding,
                receiveRoutes: receiveRoutes,
                rendezvousTranscriptDigest: rendezvousTranscriptDigest,
                issuedAt: issuedAt,
                expiresAt: expiresAt
            ),
            sortedKeys: true
        )
    }
}

private struct ContactIntroductionSignaturePayloadV2: Codable {
    let version: Int
    let relationshipPseudonym: String
    let relationshipSigningPublicKey: Data
    let relationshipAgreementPublicKey: Data
    let endpointBinding: RelationshipEndpointBindingV4
    let receiveRoutes: PairwiseRouteSetV2
    let rendezvousTranscriptDigest: Data
    let issuedAt: Date
    let expiresAt: Date
}

private struct PairwiseOpaqueRouteCodingKey: CodingKey, Hashable {
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

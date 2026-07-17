import Foundation

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
public struct PairwiseSendRouteV2: Codable, Equatable, Identifiable,
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
        guard isStructurallyValid else { throw PairwiseOpaqueRouteV2Error.invalidRoute }
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
        guard isStructurallyValid else {
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

    public var isStructurallyValid: Bool {
        routeID.isStructurallyValid
            && relay.isStructurallyValidRelationshipRouteEndpointV2
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
    ) throws -> PairwiseSendRouteV2 {
        try PairwiseSendRouteV2(
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

    public var description: String { "PairwiseSendRouteV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

/// Endpoint-local receive authority. This record may be persisted only in the
/// endpoint's encrypted state. It is never placed in a contact introduction,
/// pairwise route set, group state, history projection, or relay response.
public struct LocalOpaqueReceiveRouteV2: Codable, Equatable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let relay: RelayEndpoint
    public let route: OpaqueReceiveRouteV2
    public let clientCapabilities: OpaqueRouteClientCapabilityMaterialV2
    public let payloadKey: OpaqueRoutePayloadKeyV2
    public var committedCursor: OpaqueRouteCursorV2?

    public init(
        relay: RelayEndpoint,
        route: OpaqueReceiveRouteV2,
        clientCapabilities: OpaqueRouteClientCapabilityMaterialV2,
        payloadKey: OpaqueRoutePayloadKeyV2,
        committedCursor: OpaqueRouteCursorV2? = nil
    ) throws {
        self.relay = relay
        self.route = route
        self.clientCapabilities = clientCapabilities
        self.payloadKey = payloadKey
        self.committedCursor = committedCursor
        guard isStructurallyValid else { throw PairwiseOpaqueRouteV2Error.invalidRoute }
    }

    public var isStructurallyValid: Bool {
        relay.isStructurallyValidRelationshipRouteEndpointV2
            && relay.isConfidentialCapabilityTransportV2
            && route.status == .active
            && route.matches(clientCapabilities: clientCapabilities)
            && payloadKey.isStructurallyValid
            && committedCursor?.isStructurallyValid != false
    }

    public func peerSendRoute(
        priority: UInt16 = 100,
        state: RelationshipRouteStateV2 = .active
    ) throws -> PairwiseSendRouteV2 {
        try PairwiseSendRouteV2(
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
    public let displayName: String
    public let relationshipGenerationID: UUID
    public let relationshipSigningPublicKey: Data
    public let relationshipAgreementPublicKey: Data
    public let endpointSetCheckpoint: EndpointSetCheckpointV4
    public let preferredEndpoint: CertifiedGenerationEndpoint
    public let receiveRoutes: PairwiseRouteSetV2
    public let rendezvousTranscriptDigest: Data
    public let issuedAt: Date
    public let expiresAt: Date
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case displayName
        case relationshipGenerationID
        case relationshipSigningPublicKey
        case relationshipAgreementPublicKey
        case endpointSetCheckpoint
        case preferredEndpoint
        case receiveRoutes
        case rendezvousTranscriptDigest
        case issuedAt
        case expiresAt
        case signature
    }

    public init(
        version: Int = Self.version,
        displayName: String,
        relationshipGenerationID: UUID,
        relationshipSigningPublicKey: Data,
        relationshipAgreementPublicKey: Data,
        endpointSetCheckpoint: EndpointSetCheckpointV4,
        preferredEndpoint: CertifiedGenerationEndpoint,
        receiveRoutes: PairwiseRouteSetV2,
        rendezvousTranscriptDigest: Data,
        issuedAt: Date,
        expiresAt: Date,
        signature: Data
    ) {
        self.version = version
        self.displayName = displayName
        self.relationshipGenerationID = relationshipGenerationID
        self.relationshipSigningPublicKey = relationshipSigningPublicKey
        self.relationshipAgreementPublicKey = relationshipAgreementPublicKey
        self.endpointSetCheckpoint = endpointSetCheckpoint
        self.preferredEndpoint = preferredEndpoint
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
            displayName: try container.decode(String.self, forKey: .displayName),
            relationshipGenerationID: try container.decode(UUID.self, forKey: .relationshipGenerationID),
            relationshipSigningPublicKey: try container.decode(Data.self, forKey: .relationshipSigningPublicKey),
            relationshipAgreementPublicKey: try container.decode(Data.self, forKey: .relationshipAgreementPublicKey),
            endpointSetCheckpoint: try container.decode(EndpointSetCheckpointV4.self, forKey: .endpointSetCheckpoint),
            preferredEndpoint: try container.decode(CertifiedGenerationEndpoint.self, forKey: .preferredEndpoint),
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
        try container.encode(displayName, forKey: .displayName)
        try container.encode(relationshipGenerationID, forKey: .relationshipGenerationID)
        try container.encode(relationshipSigningPublicKey, forKey: .relationshipSigningPublicKey)
        try container.encode(relationshipAgreementPublicKey, forKey: .relationshipAgreementPublicKey)
        try container.encode(endpointSetCheckpoint, forKey: .endpointSetCheckpoint)
        try container.encode(preferredEndpoint, forKey: .preferredEndpoint)
        try container.encode(receiveRoutes, forKey: .receiveRoutes)
        try container.encode(rendezvousTranscriptDigest, forKey: .rendezvousTranscriptDigest)
        try container.encode(issuedAt, forKey: .issuedAt)
        try container.encode(expiresAt, forKey: .expiresAt)
        try container.encode(signature, forKey: .signature)
    }

    public static func create(
        relationshipIdentity: Identity,
        relationshipGenerationID: UUID,
        endpointSetManifest: EndpointSetManifest,
        preferredEndpoint: CertifiedGenerationEndpoint,
        receiveRoutes: PairwiseRouteSetV2,
        rendezvousTranscriptDigest: Data,
        issuedAt: Date,
        expiresAt: Date
    ) throws -> ContactIntroductionV2 {
        guard endpointSetManifest.identityGenerationId == relationshipGenerationID,
              preferredEndpoint.identityGenerationId == relationshipGenerationID,
              (try? preferredEndpoint.verified(
                  identityPublicKey: relationshipIdentity.signingKey.publicKeyData,
                  manifest: endpointSetManifest
              )) != nil else {
            throw PairwiseOpaqueRouteV2Error.invalidIntroduction
        }
        let checkpoint = try EndpointSetCheckpointV4.create(
            manifest: endpointSetManifest,
            identity: relationshipIdentity
        )
        var introduction = ContactIntroductionV2(
            displayName: relationshipIdentity.displayName,
            relationshipGenerationID: relationshipGenerationID,
            relationshipSigningPublicKey: relationshipIdentity.signingKey.publicKeyData,
            relationshipAgreementPublicKey: relationshipIdentity.agreementKey.publicKeyData,
            endpointSetCheckpoint: checkpoint,
            preferredEndpoint: preferredEndpoint,
            receiveRoutes: receiveRoutes,
            rendezvousTranscriptDigest: rendezvousTranscriptDigest,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            signature: Data(repeating: 0, count: 3_309)
        )
        guard introduction.hasValidUnsignedStructure else {
            throw PairwiseOpaqueRouteV2Error.invalidIntroduction
        }
        introduction = ContactIntroductionV2(
            displayName: introduction.displayName,
            relationshipGenerationID: introduction.relationshipGenerationID,
            relationshipSigningPublicKey: introduction.relationshipSigningPublicKey,
            relationshipAgreementPublicKey: introduction.relationshipAgreementPublicKey,
            endpointSetCheckpoint: introduction.endpointSetCheckpoint,
            preferredEndpoint: introduction.preferredEndpoint,
            receiveRoutes: introduction.receiveRoutes,
            rendezvousTranscriptDigest: introduction.rendezvousTranscriptDigest,
            issuedAt: introduction.issuedAt,
            expiresAt: introduction.expiresAt,
            signature: try relationshipIdentity.signingKey.sign(introduction.signableData())
        )
        guard introduction.isStructurallyValid else {
            throw PairwiseOpaqueRouteV2Error.invalidIntroduction
        }
        return introduction
    }

    public var isStructurallyValid: Bool {
        hasValidUnsignedStructure && signature.count == 3_309
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
        guard isStructurallyValid,
              let signable = try? signableData(),
              SigningKeyPair.verify(
                  signature: signature,
                  data: signable,
                  publicKeyData: relationshipSigningPublicKey
              ) else {
            throw PairwiseOpaqueRouteV2Error.invalidSignature
        }
        guard (try? preferredEndpoint.verified(
            identityPublicKey: relationshipSigningPublicKey,
            checkpoint: endpointSetCheckpoint,
            now: preferredEndpoint.prekeyBundle.createdAt
        )) != nil else {
            throw PairwiseOpaqueRouteV2Error.invalidIntroduction
        }
        return self
    }

    private var hasValidUnsignedStructure: Bool {
        let name = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        let introductionLifetime = expiresAt.timeIntervalSince(issuedAt)
        return version == Self.version
            && !name.isEmpty
            && name == displayName
            && name.utf8.count <= 512
            && SigningKeyPair.isValidPublicKey(relationshipSigningPublicKey)
            && AgreementKeyPair.isValidPublicKey(relationshipAgreementPublicKey)
            && endpointSetCheckpoint.identityGenerationId == relationshipGenerationID
            && preferredEndpoint.identityGenerationId == relationshipGenerationID
            && preferredEndpoint.manifestEpoch == endpointSetCheckpoint.epoch
            && receiveRoutes.isStructurallyValid
            && receiveRoutes.verify(
                ownerSigningPublicKey: preferredEndpoint.signingPublicKey
            )
            && !receiveRoutes.usableRoutes(at: issuedAt).isEmpty
            && rendezvousTranscriptDigest.count == 32
            && issuedAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && introductionLifetime > 0
            && introductionLifetime <= NoctweaveRendezvousV2.maximumLifetime
            && receiveRoutes.usableRoutes(at: issuedAt).allSatisfy { $0.expiresAt > expiresAt }
    }

    private func signableData() throws -> Data {
        try NoctweaveCoder.encode(
            ContactIntroductionSignaturePayloadV2(
                version: version,
                displayName: displayName,
                relationshipGenerationID: relationshipGenerationID,
                relationshipSigningPublicKey: relationshipSigningPublicKey,
                relationshipAgreementPublicKey: relationshipAgreementPublicKey,
                endpointSetCheckpoint: endpointSetCheckpoint,
                preferredEndpoint: preferredEndpoint,
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
    let displayName: String
    let relationshipGenerationID: UUID
    let relationshipSigningPublicKey: Data
    let relationshipAgreementPublicKey: Data
    let endpointSetCheckpoint: EndpointSetCheckpointV4
    let preferredEndpoint: CertifiedGenerationEndpoint
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

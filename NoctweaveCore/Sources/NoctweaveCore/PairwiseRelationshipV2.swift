import Foundation

public enum PairwiseRelationshipV2Error: Error, Equatable {
    case invalidState
    case wrongRelationship
    case conflictingEvent
    case capacityReached
}

/// Local-only consent for selectively disclosing continuity to this one peer.
/// It is never advertised and never grants authority outside the relationship.
public enum RelationshipContinuityPolicyV2: String, Codable, Equatable, CaseIterable {
    case disabled
    case sendOnly
    case receiveOnly
    case bidirectional

    public var allowsSending: Bool {
        self == .sendOnly || self == .bidirectional
    }

    public var allowsReceiving: Bool {
        self == .receiveOnly || self == .bidirectional
    }
}

/// Local consent state for one already-unlinkable relationship. A pending
/// relationship may collect message-request events without emitting receipts;
/// a blocked relationship never processes or sends user traffic. This state is
/// never disclosed to the peer or promoted into a global deny list.
public enum RelationshipConsentStateV2: String, Codable, Equatable, CaseIterable {
    case pendingRequest
    case accepted
    case blocked
}

public struct RelationshipLocalPolicyV2: Codable, Equatable {
    public static let version = 2

    public let version: Int
    public var consent: RelationshipConsentStateV2
    public var mutedUntil: Date?
    public var deliveryReceiptsEnabled: Bool
    public var readReceiptsEnabled: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case consent
        case mutedUntil
        case deliveryReceiptsEnabled
        case readReceiptsEnabled
    }

    public init(
        consent: RelationshipConsentStateV2 = .accepted,
        mutedUntil: Date? = nil,
        deliveryReceiptsEnabled: Bool = true,
        readReceiptsEnabled: Bool = true
    ) {
        version = Self.version
        self.consent = consent
        self.mutedUntil = mutedUntil
        self.deliveryReceiptsEnabled = deliveryReceiptsEnabled
        self.readReceiptsEnabled = readReceiptsEnabled
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PairwiseRelationshipCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Relationship local-policy fields must match exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        consent = try container.decode(RelationshipConsentStateV2.self, forKey: .consent)
        mutedUntil = try container.decodeIfPresent(Date.self, forKey: .mutedUntil)
        deliveryReceiptsEnabled = try container.decode(
            Bool.self,
            forKey: .deliveryReceiptsEnabled
        )
        readReceiptsEnabled = try container.decode(Bool.self, forKey: .readReceiptsEnabled)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .consent,
                in: container,
                debugDescription: "Relationship local policy is invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Relationship local policy is invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(consent, forKey: .consent)
        try container.encode(mutedUntil, forKey: .mutedUntil)
        try container.encode(deliveryReceiptsEnabled, forKey: .deliveryReceiptsEnabled)
        try container.encode(readReceiptsEnabled, forKey: .readReceiptsEnabled)
    }

    public var isStructurallyValid: Bool {
        version == Self.version
            && mutedUntil?.timeIntervalSince1970.isFinite != false
    }

    public var allowsUserSending: Bool { consent == .accepted }

    public var acceptsInboundEvents: Bool { consent != .blocked }

    public func isMuted(at date: Date = Date()) -> Bool {
        mutedUntil.map { date < $0 } ?? false
    }
}

/// Exact ciphertext artifacts for one logical event fanout to one opaque send
/// route. Retrying this record republishes identical packets; it never advances
/// a ratchet or creates a second logical event.
public struct PendingOpaqueRouteDeliveryV2: Codable, Equatable, Identifiable {
    public static let version = 2

    public let version: Int
    public let id: UUID
    public let logicalEventID: UUID
    public let relationshipID: UUID
    public let destinationRouteID: OpaqueReceiveRouteIDV2
    public let destinationRelay: RelayEndpoint
    public let bundleID: OpaqueRouteBundleIDV2
    public let packets: [OpaqueRoutePacketV2]
    public let queuedAt: Date
    public var attemptCount: UInt32
    public var lastAttemptAt: Date?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case logicalEventID
        case relationshipID
        case destinationRouteID
        case destinationRelay
        case bundleID
        case packets
        case queuedAt
        case attemptCount
        case lastAttemptAt
    }

    public init(
        id: UUID = UUID(),
        logicalEventID: UUID,
        relationshipID: UUID,
        destinationRelay: RelayEndpoint,
        sealedBundle: OpaqueRouteSealedBundleV2,
        queuedAt: Date,
        attemptCount: UInt32 = 0,
        lastAttemptAt: Date? = nil
    ) throws {
        guard let destinationRouteID = sealedBundle.packets.first?.routeID else {
            throw PairwiseRelationshipV2Error.invalidState
        }
        self.version = Self.version
        self.id = id
        self.logicalEventID = logicalEventID
        self.relationshipID = relationshipID
        self.destinationRouteID = destinationRouteID
        self.destinationRelay = destinationRelay
        self.bundleID = sealedBundle.bundleID
        self.packets = sealedBundle.packets
        self.queuedAt = queuedAt
        self.attemptCount = attemptCount
        self.lastAttemptAt = lastAttemptAt
        guard isStructurallyValid else { throw PairwiseRelationshipV2Error.invalidState }
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PairwiseRelationshipCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Pending opaque delivery fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        id = try container.decode(UUID.self, forKey: .id)
        logicalEventID = try container.decode(UUID.self, forKey: .logicalEventID)
        relationshipID = try container.decode(UUID.self, forKey: .relationshipID)
        destinationRouteID = try container.decode(
            OpaqueReceiveRouteIDV2.self,
            forKey: .destinationRouteID
        )
        destinationRelay = try container.decode(RelayEndpoint.self, forKey: .destinationRelay)
        bundleID = try container.decode(OpaqueRouteBundleIDV2.self, forKey: .bundleID)
        packets = try container.decode([OpaqueRoutePacketV2].self, forKey: .packets)
        queuedAt = try container.decode(Date.self, forKey: .queuedAt)
        attemptCount = try container.decode(UInt32.self, forKey: .attemptCount)
        lastAttemptAt = try container.decodeIfPresent(Date.self, forKey: .lastAttemptAt)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .packets,
                in: container,
                debugDescription: "Pending opaque delivery is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Pending opaque delivery is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(id, forKey: .id)
        try container.encode(logicalEventID, forKey: .logicalEventID)
        try container.encode(relationshipID, forKey: .relationshipID)
        try container.encode(destinationRouteID, forKey: .destinationRouteID)
        try container.encode(destinationRelay, forKey: .destinationRelay)
        try container.encode(bundleID, forKey: .bundleID)
        try container.encode(packets, forKey: .packets)
        try container.encode(queuedAt, forKey: .queuedAt)
        try container.encode(attemptCount, forKey: .attemptCount)
        if let lastAttemptAt {
            try container.encode(lastAttemptAt, forKey: .lastAttemptAt)
        } else {
            try container.encodeNil(forKey: .lastAttemptAt)
        }
    }

    public var isStructurallyValid: Bool {
        version == Self.version
            && destinationRouteID.isStructurallyValid
            && destinationRelay.isStructurallyValidRelationshipRouteEndpointV2
            && destinationRelay.isConfidentialCapabilityTransportV2
            && bundleID.isStructurallyValid
            && !packets.isEmpty
            && packets.count <= NoctweaveOpaqueRoutePacketsV2.maximumFragmentCount
            && Set(packets.map(\.packetID)).count == packets.count
            && packets.allSatisfy {
                $0.routeID == destinationRouteID && $0.isStructurallyValid
            }
            && queuedAt.timeIntervalSince1970.isFinite
            && lastAttemptAt?.timeIntervalSince1970.isFinite != false
            && lastAttemptAt.map { $0 >= queuedAt } ?? true
    }
}

/// Complete local state for one independently keyed pairwise relationship.
/// Nothing in this object is shared with another contact unless an explicit,
/// old-key-signed continuity event is sent to that contact.
public struct PairwiseRelationshipV2: Codable, Equatable, Identifiable {
    public static let version = 2
    public static let maximumReceiveRoutes = NoctweaveArchitectureV2.maximumRoutes
    public static let maximumEvents = NoctweaveArchitectureV2.maximumRelationshipEvents
    public static let maximumPendingDeliveries =
        NoctweaveArchitectureV2.maximumPendingDirectDeliveries
    public static let maximumIntents = NoctweaveArchitectureV2.maximumProtocolIntents

    public let version: Int
    public let id: UUID
    public var localIdentity: LocalPairwiseIdentityV2
    public let localEndpointHandle: RelationshipEndpointHandle
    public var localReceiveRoutes: [LocalOpaqueReceiveRouteV2]
    public var localAdvertisedRoutes: PairwiseRouteSetV2
    public var peerIdentity: PeerPairwiseIdentityV2
    public let conversationID: String
    public var events: [ConversationEvent]
    public var pendingDeliveries: [PendingOpaqueRouteDeliveryV2]
    public var deliveryStates: [DeliveryStateRecord]
    public var inboundReceipts: [InboundEnvelopeReceiptV2]
    public var protocolIntents: [ProtocolIntentV2]
    public var continuityPolicy: RelationshipContinuityPolicyV2
    public var localPolicy: RelationshipLocalPolicyV2
    public let createdAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case localIdentity
        case localEndpointHandle
        case localReceiveRoutes
        case localAdvertisedRoutes
        case peerIdentity
        case conversationID
        case events
        case pendingDeliveries
        case deliveryStates
        case inboundReceipts
        case protocolIntents
        case continuityPolicy
        case localPolicy
        case createdAt
    }

    init(
        localIdentity: LocalPairwiseIdentityV2,
        localEndpointHandle: RelationshipEndpointHandle,
        localReceiveRoutes: [LocalOpaqueReceiveRouteV2],
        localAdvertisedRoutes: PairwiseRouteSetV2,
        peerIntroduction: ContactIntroductionV2,
        rendezvousTranscriptDigest: Data,
        acceptedAt: Date
    ) throws {
        let relationshipID = try PairwiseRelationshipIDV2.derive(
            from: rendezvousTranscriptDigest
        )
        self.version = Self.version
        self.id = relationshipID
        self.localIdentity = localIdentity
        self.localEndpointHandle = localEndpointHandle
        self.localReceiveRoutes = localReceiveRoutes
        self.localAdvertisedRoutes = localAdvertisedRoutes
        self.peerIdentity = try PeerPairwiseIdentityV2(
            introduction: peerIntroduction,
            rendezvousTranscriptDigest: rendezvousTranscriptDigest,
            acceptedAt: acceptedAt
        )
        self.conversationID = relationshipID.uuidString.lowercased()
        self.events = []
        self.pendingDeliveries = []
        self.deliveryStates = []
        self.inboundReceipts = []
        self.protocolIntents = []
        self.continuityPolicy = .disabled
        self.localPolicy = RelationshipLocalPolicyV2()
        self.createdAt = acceptedAt
        guard isStructurallyValid else { throw PairwiseRelationshipV2Error.invalidState }
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PairwiseRelationshipCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Pairwise relationship fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        id = try container.decode(UUID.self, forKey: .id)
        localIdentity = try container.decode(LocalPairwiseIdentityV2.self, forKey: .localIdentity)
        localEndpointHandle = try container.decode(
            RelationshipEndpointHandle.self,
            forKey: .localEndpointHandle
        )
        localReceiveRoutes = try container.decode(
            [LocalOpaqueReceiveRouteV2].self,
            forKey: .localReceiveRoutes
        )
        localAdvertisedRoutes = try container.decode(
            PairwiseRouteSetV2.self,
            forKey: .localAdvertisedRoutes
        )
        peerIdentity = try container.decode(PeerPairwiseIdentityV2.self, forKey: .peerIdentity)
        conversationID = try container.decode(String.self, forKey: .conversationID)
        events = try container.decode([ConversationEvent].self, forKey: .events)
        pendingDeliveries = try container.decode(
            [PendingOpaqueRouteDeliveryV2].self,
            forKey: .pendingDeliveries
        )
        deliveryStates = try container.decode(
            [DeliveryStateRecord].self,
            forKey: .deliveryStates
        )
        inboundReceipts = try container.decode(
            [InboundEnvelopeReceiptV2].self,
            forKey: .inboundReceipts
        )
        protocolIntents = try container.decode(
            [ProtocolIntentV2].self,
            forKey: .protocolIntents
        )
        continuityPolicy = try container.decode(
            RelationshipContinuityPolicyV2.self,
            forKey: .continuityPolicy
        )
        localPolicy = try container.decode(
            RelationshipLocalPolicyV2.self,
            forKey: .localPolicy
        )
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .localIdentity,
                in: container,
                debugDescription: "Pairwise relationship is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Pairwise relationship is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(id, forKey: .id)
        try container.encode(localIdentity, forKey: .localIdentity)
        try container.encode(localEndpointHandle, forKey: .localEndpointHandle)
        try container.encode(localReceiveRoutes, forKey: .localReceiveRoutes)
        try container.encode(localAdvertisedRoutes, forKey: .localAdvertisedRoutes)
        try container.encode(peerIdentity, forKey: .peerIdentity)
        try container.encode(conversationID, forKey: .conversationID)
        try container.encode(events, forKey: .events)
        try container.encode(pendingDeliveries, forKey: .pendingDeliveries)
        try container.encode(deliveryStates, forKey: .deliveryStates)
        try container.encode(inboundReceipts, forKey: .inboundReceipts)
        try container.encode(protocolIntents, forKey: .protocolIntents)
        try container.encode(continuityPolicy, forKey: .continuityPolicy)
        try container.encode(localPolicy, forKey: .localPolicy)
        try container.encode(createdAt, forKey: .createdAt)
    }

    public var isStructurallyValid: Bool {
        let localRouteIDs = Set(localReceiveRoutes.map { $0.route.routeID })
        let activeRouteStateIsValid = !localReceiveRoutes.isEmpty
            && Set(localAdvertisedRoutes.routes
                .filter { $0.state != .revoked }
                .map(\.routeID)).isSubset(of: localRouteIDs)
        let blockedRouteStateIsValid = localPolicy.consent == .blocked
            && localRouteIDs.isSubset(of: Set(localAdvertisedRoutes.routes.map(\.routeID)))
        return version == Self.version
            && localIdentity.isStructurallyValid
            && localEndpointHandle.isStructurallyValid
            && localReceiveRoutes.count <= Self.maximumReceiveRoutes
            && localRouteIDs.count == localReceiveRoutes.count
            && localReceiveRoutes.allSatisfy(\.isStructurallyValid)
            && localAdvertisedRoutes.relationshipID == id
            && localAdvertisedRoutes.ownerEndpointHandle == localEndpointHandle
            && localAdvertisedRoutes.verify(
                ownerSigningPublicKey: localIdentity.localEndpoint.signingKey.publicKeyData
            )
            && (activeRouteStateIsValid || blockedRouteStateIsValid)
            && localRouteIDs.isSubset(of: Set(localAdvertisedRoutes.routes.map(\.routeID)))
            && peerIdentity.relationshipID == id
            && peerIdentity.isStructurallyValid
            && conversationID == id.uuidString.lowercased()
            && events.count <= Self.maximumEvents
            && Set(events.map(\.id)).count == events.count
            && events.allSatisfy {
                $0.isStructurallyValid
                    && $0.conversationId == conversationID
                    && ($0.authorEndpointHandle == localEndpointHandle
                        || $0.authorEndpointHandle == peerIdentity.sendRoutes.ownerEndpointHandle)
            }
            && pendingDeliveries.count <= Self.maximumPendingDeliveries
            && Set(pendingDeliveries.map(\.id)).count == pendingDeliveries.count
            && pendingDeliveries.allSatisfy {
                $0.relationshipID == id && $0.isStructurallyValid
            }
            && deliveryStates.count <= NoctweaveArchitectureV2.maximumDeliveryStates
            && Set(deliveryStates.map(DeliveryStateKey.init)).count == deliveryStates.count
            && deliveryStates.allSatisfy(\.isStructurallyValid)
            && deliveryStates.allSatisfy {
                $0.destinationEndpoint == peerIdentity.sendRoutes.ownerEndpointHandle
            }
            && inboundReceipts.count
                <= NoctweaveArchitectureV2.maximumInboundEnvelopeReceipts
            && Set(inboundReceipts.map(\.envelopeId)).count == inboundReceipts.count
            && Set(inboundReceipts.map(\.logicalEventId)).count == inboundReceipts.count
            && inboundReceipts.allSatisfy {
                $0.sourceScopeId == id && $0.isStructurallyValid
            }
            && protocolIntents.count <= Self.maximumIntents
            && Set(protocolIntents.map(\.id)).count == protocolIntents.count
            && Set(protocolIntents.map(\.idempotencyKey)).count == protocolIntents.count
            && protocolIntents.allSatisfy(\.isStructurallyValid)
            && localPolicy.isStructurallyValid
            && createdAt.timeIntervalSince1970.isFinite
    }

    /// Adds one immutable event to this relationship log. Replaying identical
    /// event bytes is idempotent; an ID reused for different bytes is rejected.
    @discardableResult
    public mutating func appendEvent(_ event: ConversationEvent) throws -> Bool {
        guard event.isStructurallyValid,
              event.conversationId == conversationID,
              event.authorEndpointHandle == localEndpointHandle
                || event.authorEndpointHandle == peerIdentity.sendRoutes.ownerEndpointHandle else {
            throw PairwiseRelationshipV2Error.wrongRelationship
        }
        if let existing = events.first(where: { $0.id == event.id }) {
            guard existing == event else {
                throw PairwiseRelationshipV2Error.conflictingEvent
            }
            return false
        }
        if events.count >= Self.maximumEvents {
            try compactDurableState(
                retainingEventIDs: Set(Self.referencedEventIDs(in: event)),
                retainingIntentIDs: [],
                reservedEventSlots: 1,
                reservedDeliveryStateSlots: 0,
                reservedInboundReceiptSlots: 0,
                reservedIntentSlots: 0
            )
        }
        guard events.count < Self.maximumEvents else {
            throw PairwiseRelationshipV2Error.capacityReached
        }
        events.append(event)
        return true
    }

    public mutating func enqueue(
        logicalEventID: UUID,
        payload: Data,
        at date: Date
    ) throws -> [PendingOpaqueRouteDeliveryV2] {
        try enqueue(
            logicalEventID: logicalEventID,
            payload: payload,
            destinationRouteIDs: nil,
            at: date
        )
    }

    /// Queues an exact targeted copy. Testing routes are accepted only through
    /// this path so a route probe cannot accidentally become ordinary fan-out.
    public mutating func enqueue(
        logicalEventID: UUID,
        payload: Data,
        destinationRouteIDs: Set<OpaqueReceiveRouteIDV2>?,
        at date: Date
    ) throws -> [PendingOpaqueRouteDeliveryV2] {
        let routes: [OpaqueSendRouteV2]
        if let destinationRouteIDs {
            let selected = peerIdentity.sendRoutes.routes.filter {
                destinationRouteIDs.contains($0.routeID)
                    && $0.state != .revoked
                    && date >= $0.validFrom
                    && date < $0.expiresAt
            }
            guard !destinationRouteIDs.isEmpty,
                  Set(selected.map(\.routeID)) == destinationRouteIDs else {
                throw PairwiseRelationshipV2Error.wrongRelationship
            }
            routes = selected
        } else {
            routes = peerIdentity.sendRoutes.usableRoutes(at: date)
        }
        guard !routes.isEmpty,
              pendingDeliveries.count + routes.count <= Self.maximumPendingDeliveries else {
            throw PairwiseRelationshipV2Error.capacityReached
        }
        var created: [PendingOpaqueRouteDeliveryV2] = []
        created.reserveCapacity(routes.count)
        for route in routes {
            let bundle = try OpaqueRouteSealedBundleV2.seal(
                payload,
                to: route,
                authorizedAt: date
            )
            created.append(try PendingOpaqueRouteDeliveryV2(
                logicalEventID: logicalEventID,
                relationshipID: id,
                destinationRelay: route.relay,
                sealedBundle: bundle,
                queuedAt: date
            ))
        }
        pendingDeliveries.append(contentsOf: created)
        return created
    }

    /// Compacts bounded operational state without discarding anything still
    /// needed by an unfinished send or intent. Event history retains the newest
    /// window plus active references; replay receipts remain a recent cache.
    public mutating func compactDurableState() throws {
        try compactDurableState(
            retainingEventIDs: [],
            retainingIntentIDs: [],
            reservedEventSlots: 0,
            reservedDeliveryStateSlots: 0,
            reservedInboundReceiptSlots: 0,
            reservedIntentSlots: 0
        )
    }

    /// Inserts or advances one destination delivery record while preserving a
    /// single monotonic record for each logical event and destination.
    @discardableResult
    public mutating func recordDeliveryState(_ state: DeliveryStateRecord) throws -> Bool {
        guard state.isStructurallyValid,
              state.destinationEndpoint == peerIdentity.sendRoutes.ownerEndpointHandle else {
            throw PairwiseRelationshipV2Error.wrongRelationship
        }
        let key = DeliveryStateKey(state)
        if let index = deliveryStates.firstIndex(where: { DeliveryStateKey($0) == key }) {
            if deliveryStates[index] == state { return false }
            var advanced = deliveryStates[index]
            guard advanced.advance(to: state.state, at: state.updatedAt) else {
                throw PairwiseRelationshipV2Error.conflictingEvent
            }
            deliveryStates[index] = advanced
            return true
        }
        if deliveryStates.count >= NoctweaveArchitectureV2.maximumDeliveryStates {
            try compactDurableState(
                retainingEventIDs: Self.requiresDurableEventContext(state)
                    ? Set([state.eventId])
                    : Set(),
                retainingIntentIDs: [],
                reservedEventSlots: 0,
                reservedDeliveryStateSlots: 1,
                reservedInboundReceiptSlots: 0,
                reservedIntentSlots: 0
            )
        }
        guard deliveryStates.count < NoctweaveArchitectureV2.maximumDeliveryStates else {
            throw PairwiseRelationshipV2Error.capacityReached
        }
        deliveryStates.append(state)
        return true
    }

    /// Records successful inbound processing. Exact replay is idempotent;
    /// mutation under either the envelope or logical event identity is rejected.
    @discardableResult
    public mutating func recordInboundReceipt(_ receipt: InboundEnvelopeReceiptV2) throws -> Bool {
        guard receipt.sourceScopeId == id, receipt.isStructurallyValid else {
            throw PairwiseRelationshipV2Error.wrongRelationship
        }
        if let existing = inboundReceipts.first(where: {
            $0.isReplayCandidate(
                sourceScopeId: receipt.sourceScopeId,
                logicalEventId: receipt.logicalEventId,
                envelopeId: receipt.envelopeId
            )
        }) {
            guard existing.isExactReplay(
                sourceScopeId: receipt.sourceScopeId,
                logicalEventId: receipt.logicalEventId,
                envelopeId: receipt.envelopeId,
                envelopeDigest: receipt.envelopeDigest
            ) else {
                throw PairwiseRelationshipV2Error.conflictingEvent
            }
            return false
        }
        if inboundReceipts.count
            >= NoctweaveArchitectureV2.maximumInboundEnvelopeReceipts {
            try compactDurableState(
                retainingEventIDs: [],
                retainingIntentIDs: [],
                reservedEventSlots: 0,
                reservedDeliveryStateSlots: 0,
                reservedInboundReceiptSlots: 1,
                reservedIntentSlots: 0
            )
        }
        guard inboundReceipts.count
            < NoctweaveArchitectureV2.maximumInboundEnvelopeReceipts else {
            throw PairwiseRelationshipV2Error.capacityReached
        }
        inboundReceipts.append(receipt)
        return true
    }

    /// Adds one mutation intent while retaining terminal dependency records for
    /// every unfinished intent. Duplicate exact intents are idempotent.
    @discardableResult
    public mutating func appendProtocolIntent(_ intent: ProtocolIntentV2) throws -> Bool {
        guard intent.isStructurallyValid else {
            throw PairwiseRelationshipV2Error.invalidState
        }
        if let existing = protocolIntents.first(where: {
            $0.id == intent.id || $0.idempotencyKey == intent.idempotencyKey
        }) {
            guard existing == intent else {
                throw PairwiseRelationshipV2Error.conflictingEvent
            }
            return false
        }
        if protocolIntents.count >= Self.maximumIntents {
            try compactDurableState(
                retainingEventIDs: [],
                retainingIntentIDs: Set(intent.dependencies),
                reservedEventSlots: 0,
                reservedDeliveryStateSlots: 0,
                reservedInboundReceiptSlots: 0,
                reservedIntentSlots: 1
            )
        }
        guard protocolIntents.count < Self.maximumIntents else {
            throw PairwiseRelationshipV2Error.capacityReached
        }
        protocolIntents.append(intent)
        return true
    }

    private mutating func compactDurableState(
        retainingEventIDs additionalEventIDs: Set<UUID>,
        retainingIntentIDs additionalIntentIDs: Set<UUID>,
        reservedEventSlots: Int,
        reservedDeliveryStateSlots: Int,
        reservedInboundReceiptSlots: Int,
        reservedIntentSlots: Int
    ) throws {
        guard reservedEventSlots >= 0,
              reservedEventSlots <= Self.maximumEvents,
              reservedDeliveryStateSlots >= 0,
              reservedDeliveryStateSlots <= NoctweaveArchitectureV2.maximumDeliveryStates,
              reservedInboundReceiptSlots >= 0,
              reservedInboundReceiptSlots
                <= NoctweaveArchitectureV2.maximumInboundEnvelopeReceipts,
              reservedIntentSlots >= 0,
              reservedIntentSlots <= Self.maximumIntents else {
            throw PairwiseRelationshipV2Error.invalidState
        }

        var candidate = self
        candidate.protocolIntents = try Self.compactedIntents(
            protocolIntents,
            retaining: additionalIntentIDs,
            maximumRetained: Self.maximumIntents - reservedIntentSlots
        )

        var protectedEventIDs = additionalEventIDs
        protectedEventIDs.formUnion(pendingDeliveries.map(\.logicalEventID))
        protectedEventIDs.formUnion(
            deliveryStates.lazy
                .filter(Self.requiresDurableEventContext)
                .map(\.eventId)
        )
        protectedEventIDs.formUnion(
            candidate.protocolIntents.lazy
                .filter { !$0.state.isTerminal }
                .compactMap(Self.targetEventID)
        )
        candidate.events = try Self.compactedEvents(
            events,
            retaining: protectedEventIDs,
            maximumRetained: Self.maximumEvents - reservedEventSlots
        )
        candidate.deliveryStates = try Self.compactedDeliveryStates(
            deliveryStates,
            retainingEventIDs: Set(candidate.events.map(\.id)),
            expectedDestination: peerIdentity.sendRoutes.ownerEndpointHandle,
            maximumRetained: NoctweaveArchitectureV2.maximumDeliveryStates
                - reservedDeliveryStateSlots
        )
        candidate.inboundReceipts = try Self.compactedInboundReceipts(
            inboundReceipts,
            relationshipID: id,
            maximumRetained: NoctweaveArchitectureV2.maximumInboundEnvelopeReceipts
                - reservedInboundReceiptSlots
        )
        guard candidate.isStructurallyValid else {
            throw PairwiseRelationshipV2Error.invalidState
        }
        self = candidate
    }

    private static func compactedEvents(
        _ source: [ConversationEvent],
        retaining protectedIDs: Set<UUID>,
        maximumRetained: Int
    ) throws -> [ConversationEvent] {
        guard maximumRetained >= 0,
              Set(source.map(\.id)).count == source.count,
              source.allSatisfy(\.isStructurallyValid) else {
            throw PairwiseRelationshipV2Error.invalidState
        }
        let availableIDs = Set(source.map(\.id))
        let mandatory = protectedIDs.intersection(availableIDs)
        guard mandatory.count <= maximumRetained else {
            throw PairwiseRelationshipV2Error.capacityReached
        }
        let recentTarget = min(
            NoctweaveArchitectureV2.relationshipEventRecentWindow,
            maximumRetained
        )
        if source.count <= recentTarget { return source }

        var selected = mandatory
        for event in source.suffix(recentTarget).reversed()
        where selected.count < maximumRetained {
            selected.insert(event.id)
        }

        // Retain referenced targets when space remains. Missing targets are
        // legal after compaction and render as historical placeholders.
        var queue = source.reversed().filter { selected.contains($0.id) }
        var queueIndex = 0
        let eventByID = Dictionary(uniqueKeysWithValues: source.map { ($0.id, $0) })
        while queueIndex < queue.count, selected.count < maximumRetained {
            let event = queue[queueIndex]
            queueIndex += 1
            for targetID in referencedEventIDs(in: event)
            where eventByID[targetID] != nil && !selected.contains(targetID) {
                selected.insert(targetID)
                if let target = eventByID[targetID] { queue.append(target) }
                if selected.count == maximumRetained { break }
            }
        }
        return source.filter { selected.contains($0.id) }
    }

    private static func compactedDeliveryStates(
        _ source: [DeliveryStateRecord],
        retainingEventIDs: Set<UUID>,
        expectedDestination: RelationshipEndpointHandle,
        maximumRetained: Int
    ) throws -> [DeliveryStateRecord] {
        let keys = source.map(DeliveryStateKey.init)
        guard maximumRetained >= 0,
              Set(keys).count == keys.count,
              source.allSatisfy(\.isStructurallyValid),
              source.allSatisfy({ $0.destinationEndpoint == expectedDestination }) else {
            throw PairwiseRelationshipV2Error.invalidState
        }
        let activeKeys = Set(source.lazy.filter(requiresDurableEventContext).map(DeliveryStateKey.init))
        guard activeKeys.count <= maximumRetained else {
            throw PairwiseRelationshipV2Error.capacityReached
        }
        let recentTarget = min(
            NoctweaveArchitectureV2.deliveryStateRecentWindow,
            maximumRetained
        )
        if source.count <= recentTarget { return source }

        var selected = activeKeys
        for state in source.reversed()
        where retainingEventIDs.contains(state.eventId) && selected.count < maximumRetained {
            selected.insert(DeliveryStateKey(state))
        }
        for state in source.suffix(recentTarget).reversed()
        where selected.count < maximumRetained {
            selected.insert(DeliveryStateKey(state))
        }
        return source.filter { selected.contains(DeliveryStateKey($0)) }
    }

    private static func compactedInboundReceipts(
        _ source: [InboundEnvelopeReceiptV2],
        relationshipID: UUID,
        maximumRetained: Int
    ) throws -> [InboundEnvelopeReceiptV2] {
        guard maximumRetained >= 0,
              Set(source.map(\.envelopeId)).count == source.count,
              Set(source.map(\.logicalEventId)).count == source.count,
              source.allSatisfy({
                  $0.sourceScopeId == relationshipID && $0.isStructurallyValid
              }) else {
            throw PairwiseRelationshipV2Error.invalidState
        }
        let targetCount = min(
            NoctweaveArchitectureV2.inboundEnvelopeReceiptRecentWindow,
            maximumRetained
        )
        if source.count <= targetCount { return source }
        let retainedIDs = Set(
            source.sorted {
                if $0.processedAt != $1.processedAt { return $0.processedAt < $1.processedAt }
                return $0.envelopeId.uuidString < $1.envelopeId.uuidString
            }.suffix(targetCount).map(\.envelopeId)
        )
        return source.filter { retainedIDs.contains($0.envelopeId) }
    }

    private static func compactedIntents(
        _ source: [ProtocolIntentV2],
        retaining additionalIDs: Set<UUID>,
        maximumRetained: Int
    ) throws -> [ProtocolIntentV2] {
        guard maximumRetained >= 0,
              Set(source.map(\.id)).count == source.count,
              Set(source.map(\.idempotencyKey)).count == source.count,
              source.allSatisfy(\.isStructurallyValid) else {
            throw PairwiseRelationshipV2Error.invalidState
        }
        let byID = Dictionary(uniqueKeysWithValues: source.map { ($0.id, $0) })
        var protected = Set(source.lazy.filter { !$0.state.isTerminal }.map(\.id))
        protected.formUnion(additionalIDs.intersection(Set(byID.keys)))
        var dependencyQueue = Array(protected)
        var queueIndex = 0
        while queueIndex < dependencyQueue.count {
            let intentID = dependencyQueue[queueIndex]
            queueIndex += 1
            guard let intent = byID[intentID] else { continue }
            for dependency in intent.dependencies
            where byID[dependency] != nil && !protected.contains(dependency) {
                protected.insert(dependency)
                dependencyQueue.append(dependency)
            }
        }
        guard protected.count <= maximumRetained else {
            throw PairwiseRelationshipV2Error.capacityReached
        }
        let recentTarget = min(
            NoctweaveArchitectureV2.protocolIntentRecentWindow,
            maximumRetained
        )
        if source.count <= recentTarget { return source }

        var selected = protected
        let recentTerminal = source.filter { $0.state.isTerminal }
            .sorted(by: intentIsOlder)
            .suffix(recentTarget)
        for intent in recentTerminal.reversed() where selected.count < maximumRetained {
            selected.insert(intent.id)
        }
        return source.filter { selected.contains($0.id) }
    }

    private static func intentIsOlder(_ lhs: ProtocolIntentV2, _ rhs: ProtocolIntentV2) -> Bool {
        if lhs.updatedAt != rhs.updatedAt { return lhs.updatedAt < rhs.updatedAt }
        if lhs.createdAt != rhs.createdAt { return lhs.createdAt < rhs.createdAt }
        return lhs.id.uuidString < rhs.id.uuidString
    }

    private static func referencedEventIDs(in event: ConversationEvent) -> [UUID] {
        var result: [UUID] = []
        if let relation = event.relation { result.append(relation.targetEventId) }
        if event.kind == .receipt,
           let receipt = try? NoctweaveCoder.decode(
               EventReceiptContentV1.self,
               from: event.content.payload
           ) {
            result.append(receipt.targetEventId)
        }
        return result
    }

    private static func targetEventID(_ intent: ProtocolIntentV2) -> UUID? {
        guard intent.kind == .sendEvent,
              let target = intent.targetIdentifier,
              let text = String(data: target, encoding: .utf8) else {
            return nil
        }
        return UUID(uuidString: text)
    }

    private static func requiresDurableEventContext(_ state: DeliveryStateRecord) -> Bool {
        state.state == .locallyPersisted || state.state == .relayAccepted
    }
}

private struct DeliveryStateKey: Hashable {
    let eventID: UUID
    let destination: RelationshipEndpointHandle

    init(_ state: DeliveryStateRecord) {
        eventID = state.eventId
        destination = state.destinationEndpoint
    }
}

private struct PairwiseRelationshipCodingKey: CodingKey {
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

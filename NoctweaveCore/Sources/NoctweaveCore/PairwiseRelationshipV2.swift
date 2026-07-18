import CryptoKit
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
    public let intentID: UUID
    public let logicalEventID: UUID
    public let relationshipID: UUID
    public let directSessionID: String
    public let messageCounter: UInt64
    public let destinationRouteID: OpaqueReceiveRouteIDV2
    public let destinationRelay: RelayEndpoint
    public let bundleID: OpaqueRouteBundleIDV2
    public let payloadDigest: Data
    public let packets: [OpaqueRoutePacketV2]
    public let queuedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case intentID
        case logicalEventID
        case relationshipID
        case directSessionID
        case messageCounter
        case destinationRouteID
        case destinationRelay
        case bundleID
        case payloadDigest
        case packets
        case queuedAt
    }

    public init(
        id: UUID = UUID(),
        intentID: UUID,
        logicalEventID: UUID,
        relationshipID: UUID,
        directSessionID: String,
        messageCounter: UInt64,
        destinationRelay: RelayEndpoint,
        payloadDigest: Data,
        sealedBundle: OpaqueRouteSealedBundleV2,
        queuedAt: Date
    ) throws {
        guard let destinationRouteID = sealedBundle.packets.first?.routeID else {
            throw PairwiseRelationshipV2Error.invalidState
        }
        self.version = Self.version
        self.id = id
        self.intentID = intentID
        self.logicalEventID = logicalEventID
        self.relationshipID = relationshipID
        self.directSessionID = directSessionID
        self.messageCounter = messageCounter
        self.destinationRouteID = destinationRouteID
        self.destinationRelay = destinationRelay
        self.bundleID = sealedBundle.bundleID
        self.payloadDigest = payloadDigest
        self.packets = sealedBundle.packets
        self.queuedAt = queuedAt
        guard try isStructurallyValidThrowing else {
            throw PairwiseRelationshipV2Error.invalidState
        }
    }

    private init(
        version: Int,
        id: UUID,
        intentID: UUID,
        logicalEventID: UUID,
        relationshipID: UUID,
        directSessionID: String,
        messageCounter: UInt64,
        destinationRouteID: OpaqueReceiveRouteIDV2,
        destinationRelay: RelayEndpoint,
        bundleID: OpaqueRouteBundleIDV2,
        payloadDigest: Data,
        packets: [OpaqueRoutePacketV2],
        queuedAt: Date
    ) {
        self.version = version
        self.id = id
        self.intentID = intentID
        self.logicalEventID = logicalEventID
        self.relationshipID = relationshipID
        self.directSessionID = directSessionID
        self.messageCounter = messageCounter
        self.destinationRouteID = destinationRouteID
        self.destinationRelay = destinationRelay
        self.bundleID = bundleID
        self.payloadDigest = payloadDigest
        self.packets = packets
        self.queuedAt = queuedAt
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
        intentID = try container.decode(UUID.self, forKey: .intentID)
        logicalEventID = try container.decode(UUID.self, forKey: .logicalEventID)
        relationshipID = try container.decode(UUID.self, forKey: .relationshipID)
        directSessionID = try container.decode(String.self, forKey: .directSessionID)
        messageCounter = try container.decode(UInt64.self, forKey: .messageCounter)
        destinationRouteID = try container.decode(
            OpaqueReceiveRouteIDV2.self,
            forKey: .destinationRouteID
        )
        destinationRelay = try container.decode(RelayEndpoint.self, forKey: .destinationRelay)
        bundleID = try container.decode(OpaqueRouteBundleIDV2.self, forKey: .bundleID)
        payloadDigest = try container.decode(Data.self, forKey: .payloadDigest)
        packets = try container.decode([OpaqueRoutePacketV2].self, forKey: .packets)
        queuedAt = try container.decode(Date.self, forKey: .queuedAt)
        guard try isStructurallyValidThrowing else {
            throw DecodingError.dataCorruptedError(
                forKey: .packets,
                in: container,
                debugDescription: "Pending opaque delivery is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
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
        try container.encode(intentID, forKey: .intentID)
        try container.encode(logicalEventID, forKey: .logicalEventID)
        try container.encode(relationshipID, forKey: .relationshipID)
        try container.encode(directSessionID, forKey: .directSessionID)
        try container.encode(messageCounter, forKey: .messageCounter)
        try container.encode(destinationRouteID, forKey: .destinationRouteID)
        try container.encode(destinationRelay, forKey: .destinationRelay)
        try container.encode(bundleID, forKey: .bundleID)
        try container.encode(payloadDigest, forKey: .payloadDigest)
        try container.encode(packets, forKey: .packets)
        try container.encode(queuedAt, forKey: .queuedAt)
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard try destinationRelay.isStructurallyValidRelationshipRouteEndpointV2Throwing else {
                return false
            }
            return version == Self.version
                && id == intentID
                && !directSessionID.isEmpty
                && directSessionID.utf8.count <= 128
                && destinationRouteID.isStructurallyValid
                && destinationRelay.isConfidentialCapabilityTransportV2
                && bundleID.isStructurallyValid
                && payloadDigest.count == 32
                && !packets.isEmpty
                && packets.count <= NoctweaveOpaqueRoutePacketsV2.maximumFragmentCount
                && Set(packets.map(\.packetID)).count == packets.count
                && packets.allSatisfy {
                    $0.routeID == destinationRouteID && $0.isStructurallyValid
                }
                && queuedAt.timeIntervalSince1970.isFinite
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    func refreshingExpiredAuthorizations(
        sendCapability: RouteSendCapabilityV2,
        at date: Date
    ) throws -> PendingOpaqueRouteDeliveryV2 {
        let expiryWindow = NoctweaveOpaqueRoutesV2.maximumAuthorizationClockSkew
        guard packets.contains(where: {
            $0.authorization.authorizedAt.addingTimeInterval(expiryWindow) < date
        }) else { return self }
        let refreshed = PendingOpaqueRouteDeliveryV2(
            version: version,
            id: id,
            intentID: intentID,
            logicalEventID: logicalEventID,
            relationshipID: relationshipID,
            directSessionID: directSessionID,
            messageCounter: messageCounter,
            destinationRouteID: destinationRouteID,
            destinationRelay: destinationRelay,
            bundleID: bundleID,
            payloadDigest: payloadDigest,
            packets: try packets.map {
                try $0.refreshingAuthorization(
                    sendCapability: sendCapability,
                    authorizedAt: date
                )
            },
            queuedAt: queuedAt
        )
        guard try refreshed.isStructurallyValidThrowing,
              zip(packets, refreshed.packets).allSatisfy({
                  $0.packetID == $1.packetID
                      && $0.sealedFrame == $1.sealedFrame
                      && $0.operationDigest == $1.operationDigest
              }) else {
            throw PairwiseRelationshipV2Error.invalidState
        }
        return refreshed
    }
}

/// Exact encrypted blob-upload request retained until one relay accepts it.
/// The record deliberately contains no attachment plaintext or encryption key.
public struct PendingAttachmentUploadV2: Codable, Equatable, Identifiable {
    public static let version = 2

    public let version: Int
    public let id: UUID
    public let relationshipID: UUID
    public let relay: RelayEndpoint
    public let request: UploadAttachmentRequest
    public let queuedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case relationshipID
        case relay
        case request
        case queuedAt
    }

    public init(
        id: UUID = UUID(),
        relationshipID: UUID,
        relay: RelayEndpoint,
        request: UploadAttachmentRequest,
        queuedAt: Date
    ) throws {
        self.version = Self.version
        self.id = id
        self.relationshipID = relationshipID
        self.relay = relay
        self.request = request
        self.queuedAt = queuedAt
        guard try isStructurallyValidThrowing else {
            throw PairwiseRelationshipV2Error.invalidState
        }
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PairwiseRelationshipCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Pending attachment upload fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        id = try container.decode(UUID.self, forKey: .id)
        relationshipID = try container.decode(UUID.self, forKey: .relationshipID)
        relay = try container.decode(RelayEndpoint.self, forKey: .relay)
        request = try container.decode(UploadAttachmentRequest.self, forKey: .request)
        queuedAt = try container.decode(Date.self, forKey: .queuedAt)
        guard try isStructurallyValidThrowing else {
            throw DecodingError.dataCorruptedError(
                forKey: .request,
                in: container,
                debugDescription: "Pending attachment upload is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Pending attachment upload is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(id, forKey: .id)
        try container.encode(relationshipID, forKey: .relationshipID)
        try container.encode(relay, forKey: .relay)
        try container.encode(request, forKey: .request)
        try container.encode(queuedAt, forKey: .queuedAt)
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard try relay.isStructurallyValidThrowing else { return false }
            return version == Self.version
                && request.isStructurallyValid
                && queuedAt.timeIntervalSince1970.isFinite
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
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
    public static let maximumPendingAttachmentUploads =
        NoctweaveArchitectureV2.maximumPendingAttachmentUploads
    public static let maximumIntents = NoctweaveArchitectureV2.maximumProtocolIntents
    public static let maximumTransportQuarantine =
        NoctweaveArchitectureV2.maximumQuarantinedTransportEnvelopes
    public static let maximumControlQuarantine =
        NoctweaveArchitectureV2.maximumQuarantinedControlEvents

    public let version: Int
    public let id: UUID
    public var localIdentity: LocalPairwiseIdentityV2
    public let localEndpointHandle: RelationshipEndpointHandle
    public var localReceiveRoutes: [LocalOpaqueReceiveRouteV2]
    public var localAdvertisedRoutes: PairwiseRouteSetV2
    public var peerIdentity: PeerPairwiseIdentityV2
    public let conversationID: String
    public var directSessions: [Conversation]
    public var events: [ConversationEvent]
    public var pendingDeliveries: [PendingOpaqueRouteDeliveryV2]
    public var pendingRouteRollovers: [PendingLocalOpaqueReceiveRouteV2]
    public var pendingAttachmentUploads: [PendingAttachmentUploadV2]
    public var deliveryStates: [DeliveryStateRecord]
    public var inboundReceipts: [InboundEnvelopeReceiptV2]
    public var transportQuarantine: [QuarantinedTransportEnvelopeV2]
    public var controlQuarantine: [QuarantinedControlEvent]
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
        case directSessions
        case events
        case pendingDeliveries
        case pendingRouteRollovers
        case pendingAttachmentUploads
        case deliveryStates
        case inboundReceipts
        case transportQuarantine
        case controlQuarantine
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
        self.directSessions = []
        self.events = []
        self.pendingDeliveries = []
        self.pendingRouteRollovers = []
        self.pendingAttachmentUploads = []
        self.deliveryStates = []
        self.inboundReceipts = []
        self.transportQuarantine = []
        self.controlQuarantine = []
        self.protocolIntents = []
        self.continuityPolicy = .disabled
        self.localPolicy = RelationshipLocalPolicyV2()
        self.createdAt = acceptedAt
        guard try isStructurallyValidThrowing else {
            throw PairwiseRelationshipV2Error.invalidState
        }
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
        directSessions = try container.decode([Conversation].self, forKey: .directSessions)
        events = try container.decode([ConversationEvent].self, forKey: .events)
        pendingDeliveries = try container.decode(
            [PendingOpaqueRouteDeliveryV2].self,
            forKey: .pendingDeliveries
        )
        pendingRouteRollovers = try container.decode(
            [PendingLocalOpaqueReceiveRouteV2].self,
            forKey: .pendingRouteRollovers
        )
        pendingAttachmentUploads = try container.decode(
            [PendingAttachmentUploadV2].self,
            forKey: .pendingAttachmentUploads
        )
        deliveryStates = try container.decode(
            [DeliveryStateRecord].self,
            forKey: .deliveryStates
        )
        inboundReceipts = try container.decode(
            [InboundEnvelopeReceiptV2].self,
            forKey: .inboundReceipts
        )
        transportQuarantine = try container.decode(
            [QuarantinedTransportEnvelopeV2].self,
            forKey: .transportQuarantine
        )
        controlQuarantine = try container.decode(
            [QuarantinedControlEvent].self,
            forKey: .controlQuarantine
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
        guard try isStructurallyValidThrowing else {
            throw DecodingError.dataCorruptedError(
                forKey: .localIdentity,
                in: container,
                debugDescription: "Pairwise relationship is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
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
        try container.encode(directSessions, forKey: .directSessions)
        try container.encode(events, forKey: .events)
        try container.encode(pendingDeliveries, forKey: .pendingDeliveries)
        try container.encode(pendingRouteRollovers, forKey: .pendingRouteRollovers)
        try container.encode(pendingAttachmentUploads, forKey: .pendingAttachmentUploads)
        try container.encode(deliveryStates, forKey: .deliveryStates)
        try container.encode(inboundReceipts, forKey: .inboundReceipts)
        try container.encode(transportQuarantine, forKey: .transportQuarantine)
        try container.encode(controlQuarantine, forKey: .controlQuarantine)
        try container.encode(protocolIntents, forKey: .protocolIntents)
        try container.encode(continuityPolicy, forKey: .continuityPolicy)
        try container.encode(localPolicy, forKey: .localPolicy)
        try container.encode(createdAt, forKey: .createdAt)
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            guard try localIdentity.isStructurallyValidThrowing,
                  try localAdvertisedRoutes.isStructurallyValidThrowing,
                  try localAdvertisedRoutes.verifyThrowing(
                    ownerSigningPublicKey: localIdentity.localEndpoint.signingKey.publicKeyData
                  ),
                  try peerIdentity.isStructurallyValidThrowing else {
                return false
            }
            for route in localReceiveRoutes {
                guard try route.isStructurallyValidThrowing else { return false }
            }
            for delivery in pendingDeliveries {
                guard try delivery.isStructurallyValidThrowing else { return false }
            }
            for rollover in pendingRouteRollovers {
                guard try rollover.isStructurallyValidThrowing else { return false }
            }
            for upload in pendingAttachmentUploads {
                guard try upload.isStructurallyValidThrowing else { return false }
            }
            return hasValidAggregateStructureAfterCryptoPreflight
        }
    }

    private var hasValidAggregateStructureAfterCryptoPreflight: Bool {
        let localRouteIDs = Set(localReceiveRoutes.map { $0.route.routeID })
        let intentIDs = Set(protocolIntents.map(\.id))
        let intentDependenciesAreValid = protocolIntents.allSatisfy { intent in
            intent.dependencies.allSatisfy(intentIDs.contains)
                && (intent.state.isTerminal || intent.dependencies.allSatisfy { dependencyID in
                    protocolIntents.first(where: { $0.id == dependencyID })?.state
                        != .permanentFailure
                })
        } && !Self.intentDependenciesContainCycle(protocolIntents)
        let intentKindsAreValid = protocolIntents.allSatisfy { intent in
            switch intent.kind {
            case .sendEvent, .renewRelationshipPrekey:
                guard intent.expectedEpoch == nil,
                      let eventID = Self.uuidTarget(intent.targetIdentifier) else {
                    return false
                }
                let matching = pendingDeliveries.filter { $0.intentID == intent.id }
                if intent.state == .finalized { return matching.isEmpty }
                if intent.state == .permanentFailure && matching.isEmpty { return true }
                guard matching.count == 1, let delivery = matching.first else { return false }
                return delivery.logicalEventID == eventID
                    && delivery.payloadDigest == intent.payloadDigest
                    && events.contains(where: { $0.id == eventID })
            case .uploadBlob:
                guard intent.expectedEpoch == nil,
                      let uploadID = Self.uuidTarget(intent.targetIdentifier) else {
                    return false
                }
                let matching = pendingAttachmentUploads.filter { $0.id == uploadID }
                if intent.state == .finalized { return matching.isEmpty }
                if intent.state == .permanentFailure && matching.isEmpty { return true }
                guard matching.count == 1, let pending = matching.first,
                      let digest = Self.canonicalDigest(pending.request) else { return false }
                let ttl = TimeInterval(pending.request.ttlSeconds ?? 3_600)
                return pending.relationshipID == id
                    && digest == intent.payloadDigest
                    && intent.createdAt == pending.queuedAt
                    && intent.expiresAt == pending.queuedAt.addingTimeInterval(ttl)
                    && intent.idempotencyKey.rawValue == pending.request.idempotencyKey
            case .rolloverRoute:
                guard let target = intent.targetIdentifier,
                      OpaqueReceiveRouteIDV2(rawValue: target).isStructurallyValid,
                      intent.expectedEpoch != nil else { return false }
                let pending = pendingRouteRollovers.filter {
                    $0.clientCapabilities.routeID.rawValue == target
                }
                let local = localReceiveRoutes.filter { $0.route.routeID.rawValue == target }
                let advertised = localAdvertisedRoutes.routes.filter {
                    $0.routeID.rawValue == target
                }
                switch intent.state {
                case .prepared:
                    guard pending.count == 1, local.isEmpty, advertised.isEmpty,
                          let artifact = pending.first,
                          let digest = Self.canonicalDigest(artifact.createRequest),
                          localAdvertisedRoutes.revision < UInt64.max else {
                        return false
                    }
                    return digest == intent.payloadDigest
                        && intent.createdAt == artifact.createdAt
                        && intent.expectedEpoch == localAdvertisedRoutes.revision + 1
                        && intent.expiresAt == artifact.createRequest.lease.expiresAt
                        && intent.idempotencyKey.rawValue
                            == artifact.createRequest.idempotencyKey.rawValue
                case .published, .committed:
                    return pending.isEmpty
                        && local.count == 1
                        && advertised.count == 1
                        && advertised.first?.state == .testing
                        && intent.expectedEpoch == localAdvertisedRoutes.revision
                        && intent.expiresAt == local.first?.route.lease.expiresAt
                        && intent.idempotencyKey.rawValue
                            == local.first?.route.creationIdempotencyKey.rawValue
                case .finalized:
                    return pending.isEmpty
                case .permanentFailure:
                    if let artifact = pending.first {
                        guard pending.count == 1, local.isEmpty, advertised.isEmpty,
                              localAdvertisedRoutes.revision < UInt64.max,
                              let digest = Self.canonicalDigest(artifact.createRequest) else {
                            return false
                        }
                        return digest == intent.payloadDigest
                            && intent.createdAt == artifact.createdAt
                            && intent.expectedEpoch == localAdvertisedRoutes.revision + 1
                            && intent.expiresAt == artifact.createRequest.lease.expiresAt
                            && intent.idempotencyKey.rawValue
                                == artifact.createRequest.idempotencyKey.rawValue
                    }
                    if !local.isEmpty || !advertised.isEmpty {
                        if local.isEmpty,
                           advertised.count == 1,
                           (advertised.first?.state == .revoked
                            || (localPolicy.consent == .blocked
                                && advertised.first?.state == .testing)) {
                            return intent.expectedEpoch != nil
                        }
                        return local.count == 1
                            && advertised.count == 1
                            && (advertised.first?.state == .testing
                                || advertised.first?.state == .revoked)
                            && intent.expectedEpoch != nil
                            && intent.expiresAt == local.first?.route.lease.expiresAt
                            && intent.idempotencyKey.rawValue
                                == local.first?.route.creationIdempotencyKey.rawValue
                    }
                    return true
                }
            }
        }
        let activeRouteStateIsValid = !localReceiveRoutes.isEmpty
            && Set(localAdvertisedRoutes.routes
                .filter { $0.state != .revoked }
                .map(\.routeID)).isSubset(of: localRouteIDs)
        let blockedRouteStateIsValid = localPolicy.consent == .blocked
            && localRouteIDs.isSubset(of: Set(localAdvertisedRoutes.routes.map(\.routeID)))
        return version == Self.version
            && localEndpointHandle.isStructurallyValid
            && localReceiveRoutes.count <= Self.maximumReceiveRoutes
            && localReceiveRoutes.count + pendingRouteRollovers.count
                <= Self.maximumReceiveRoutes
            && localRouteIDs.count == localReceiveRoutes.count
            && localAdvertisedRoutes.relationshipID == id
            && localAdvertisedRoutes.ownerEndpointHandle == localEndpointHandle
            && (activeRouteStateIsValid || blockedRouteStateIsValid)
            && localRouteIDs.isSubset(of: Set(localAdvertisedRoutes.routes.map(\.routeID)))
            && peerIdentity.relationshipID == id
            && conversationID == id.uuidString.lowercased()
            && directSessions.count
                <= NoctweaveArchitectureV2.maximumDirectSessionsPerRelationship
            && Set(directSessions.map(\.sessionId)).count == directSessions.count
            && directSessions.allSatisfy { session in
                session.relationshipID == id
                    && session.endpointSession.localEndpointHandle == localEndpointHandle
                    && session.endpointSession.peerEndpointHandle
                        == peerIdentity.sendRoutes.ownerEndpointHandle
                    && session.isStructurallyValid
            }
            && events.count <= Self.maximumEvents
            && Set(events.map(\.id)).count == events.count
            && Set(events.map {
                ConversationTransactionKey(
                    author: $0.authorEndpointHandle,
                    transactionID: $0.clientTransactionId
                )
            }).count == events.count
            && events.allSatisfy {
                $0.isStructurallyValid
                    && $0.conversationId == conversationID
                    && ($0.authorEndpointHandle == localEndpointHandle
                        || $0.authorEndpointHandle == peerIdentity.sendRoutes.ownerEndpointHandle)
            }
            && pendingDeliveries.count <= Self.maximumPendingDeliveries
            && Set(pendingDeliveries.map(\.id)).count == pendingDeliveries.count
            && Set(pendingDeliveries.map(\.intentID)).count == pendingDeliveries.count
            && Set(pendingDeliveries.map(DirectDeliveryOrderKey.init)).count
                == pendingDeliveries.count
            && pendingDeliveries.allSatisfy {
                $0.relationshipID == id
            }
            && pendingRouteRollovers.count <= Self.maximumReceiveRoutes
            && Set(pendingRouteRollovers.map {
                $0.clientCapabilities.routeID
            }).count == pendingRouteRollovers.count
            && pendingRouteRollovers.allSatisfy { pending in
                !localRouteIDs.contains(pending.clientCapabilities.routeID)
            }
            && pendingAttachmentUploads.count <= Self.maximumPendingAttachmentUploads
            && Set(pendingAttachmentUploads.map(\.id)).count
                == pendingAttachmentUploads.count
            && Set(pendingAttachmentUploads.map {
                AttachmentUploadCoordinate(
                    attachmentID: $0.request.attachmentId,
                    chunkIndex: $0.request.chunkIndex
                )
            }).count == pendingAttachmentUploads.count
            && Set(pendingAttachmentUploads.map {
                $0.request.idempotencyKey
            }).count == pendingAttachmentUploads.count
            && pendingAttachmentUploads.allSatisfy {
                $0.relationshipID == id
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
            && Self.isValidTransportQuarantineCollection(transportQuarantine)
            && Self.isValidControlQuarantineCollection(
                controlQuarantine,
                conversationID: conversationID,
                peerEndpoint: peerIdentity.sendRoutes.ownerEndpointHandle
            )
            && protocolIntents.count <= Self.maximumIntents
            && Set(protocolIntents.map(\.id)).count == protocolIntents.count
            && Set(protocolIntents.map(\.idempotencyKey)).count == protocolIntents.count
            && protocolIntents.allSatisfy(\.isStructurallyValid)
            && intentDependenciesAreValid
            && intentKindsAreValid
            && protocolIntents.filter {
                $0.kind == .rolloverRoute && !$0.state.isTerminal
            }.count <= 1
            && pendingRouteRollovers.count <= 1
            && localAdvertisedRoutes.routes.filter { $0.state == .testing }.count <= 1
            && pendingDeliveries.allSatisfy { delivery in
                guard let intent = protocolIntents.first(where: {
                    $0.id == delivery.intentID
                }) else { return false }
                return (intent.kind == .sendEvent
                        || intent.kind == .renewRelationshipPrekey)
                    && intent.state != .finalized
                    && intent.targetIdentifier
                        == Data(delivery.logicalEventID.uuidString.lowercased().utf8)
                    && intent.payloadDigest == delivery.payloadDigest
            }
            && pendingRouteRollovers.allSatisfy { pending in
                protocolIntents.filter { intent in
                    intent.kind == .rolloverRoute
                        && intent.state != .finalized
                        && intent.targetIdentifier
                            == pending.clientCapabilities.routeID.rawValue
                }.count == 1
            }
            && pendingAttachmentUploads.allSatisfy { pending in
                protocolIntents.filter { intent in
                    intent.kind == .uploadBlob
                        && intent.state != .finalized
                        && intent.targetIdentifier
                            == Data(pending.id.uuidString.lowercased().utf8)
                }.count == 1
            }
            && localPolicy.isStructurallyValid
            && createdAt.timeIntervalSince1970.isFinite
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
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
        guard !events.contains(where: {
            $0.authorEndpointHandle == event.authorEndpointHandle
                && $0.clientTransactionId == event.clientTransactionId
        }) else {
            throw PairwiseRelationshipV2Error.conflictingEvent
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

    /// Persists one relationship-scoped ratchet. Older sessions remain
    /// available for delayed envelopes, but the bounded set cannot grow
    /// without an explicit reset/retirement decision.
    public mutating func upsertDirectSession(_ session: Conversation) throws {
        guard session.relationshipID == id,
              session.endpointSession.localEndpointHandle == localEndpointHandle,
              session.endpointSession.peerEndpointHandle
                == peerIdentity.sendRoutes.ownerEndpointHandle,
              session.isStructurallyValid else {
            throw PairwiseRelationshipV2Error.wrongRelationship
        }
        if let index = directSessions.firstIndex(where: {
            $0.sessionId == session.sessionId
        }) {
            directSessions[index] = session
            return
        }
        if directSessions.count
            >= NoctweaveArchitectureV2.maximumDirectSessionsPerRelationship {
            // The array is insertion ordered. Retire the oldest reset session
            // first, otherwise the oldest session. Exact outbound ciphertexts
            // are retained separately and never depend on live ratchet state.
            let retirementIndex = directSessions.firstIndex {
                $0.ratchetState == .reset
            } ?? directSessions.startIndex
            directSessions.remove(at: retirementIndex)
        }
        directSessions.append(session)
    }

    public mutating func enqueue(
        logicalEventID: UUID,
        payload: Data,
        intentKind: ProtocolIntentKindV2 = .sendEvent,
        expiresAt: Date? = nil,
        at date: Date
    ) throws -> [PendingOpaqueRouteDeliveryV2] {
        try enqueue(
            logicalEventID: logicalEventID,
            payload: payload,
            destinationRouteIDs: nil,
            intentKind: intentKind,
            expiresAt: expiresAt,
            at: date
        )
    }

    /// Queues an exact targeted copy. Testing routes are accepted only through
    /// this path so a route probe cannot accidentally become ordinary fan-out.
    public mutating func enqueue(
        logicalEventID: UUID,
        payload: Data,
        destinationRouteIDs: Set<OpaqueReceiveRouteIDV2>?,
        intentKind: ProtocolIntentKindV2 = .sendEvent,
        expiresAt: Date? = nil,
        at date: Date
    ) throws -> [PendingOpaqueRouteDeliveryV2] {
        guard intentKind == .sendEvent || intentKind == .renewRelationshipPrekey,
              expiresAt.map({ $0 > date }) ?? true else {
            throw PairwiseRelationshipV2Error.invalidState
        }
        let envelope = try NoctweaveCoder.decode(DirectEnvelopeV4.self, from: payload)
        guard envelope.eventId == logicalEventID,
              envelope.conversationId == conversationID else {
            throw PairwiseRelationshipV2Error.invalidState
        }
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
        if protocolIntents.count + routes.count > Self.maximumIntents {
            try compactDurableState(
                retainingEventIDs: Set([logicalEventID]),
                retainingIntentIDs: [],
                reservedEventSlots: 0,
                reservedDeliveryStateSlots: 0,
                reservedInboundReceiptSlots: 0,
                reservedIntentSlots: routes.count
            )
        }
        guard protocolIntents.count + routes.count <= Self.maximumIntents else {
            throw PairwiseRelationshipV2Error.capacityReached
        }
        let payloadDigest = Data(SHA256.hash(data: payload))
        var created: [PendingOpaqueRouteDeliveryV2] = []
        var intents: [ProtocolIntentV2] = []
        created.reserveCapacity(routes.count)
        intents.reserveCapacity(routes.count)
        for route in routes {
            let intent = ProtocolIntentV2.prepare(
                kind: intentKind,
                targetIdentifier: Data(logicalEventID.uuidString.lowercased().utf8),
                payloadDigest: payloadDigest,
                createdAt: date,
                expiresAt: expiresAt
            )
            let bundle = try OpaqueRouteSealedBundleV2.seal(
                payload,
                to: route,
                authorizedAt: date
            )
            created.append(try PendingOpaqueRouteDeliveryV2(
                id: intent.id,
                intentID: intent.id,
                logicalEventID: logicalEventID,
                relationshipID: id,
                directSessionID: envelope.sessionId,
                messageCounter: envelope.messageCounter,
                destinationRelay: route.relay,
                payloadDigest: payloadDigest,
                sealedBundle: bundle,
                queuedAt: date
            ))
            intents.append(intent)
        }
        protocolIntents.append(contentsOf: intents)
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

    /// Records a permanently invalid opaque-route packet by transport
    /// coordinates that are available before the inner direct envelope can be
    /// decoded. Exact retries are idempotent. A coordinate reused for different
    /// bytes or a different terminal classification is rejected as a conflict.
    /// When the bounded dead-letter window is full, its deterministic oldest
    /// member is evicted instead of turning capacity into a stream wedge.
    @discardableResult
    public mutating func recordTransportQuarantine(
        _ quarantine: QuarantinedTransportEnvelopeV2
    ) throws -> Bool {
        guard quarantine.isStructurallyValid else {
            throw PairwiseRelationshipV2Error.invalidState
        }
        if let existing = transportQuarantine.first(where: {
            $0.streamDigest == quarantine.streamDigest
                && ($0.relaySequence == quarantine.relaySequence
                    || $0.packetID == quarantine.packetID)
        }) {
            guard Self.isSameTransportQuarantine(existing, quarantine) else {
                throw PairwiseRelationshipV2Error.conflictingEvent
            }
            return false
        }

        var candidate = self
        candidate.transportQuarantine.append(quarantine)
        candidate.transportQuarantine = Self.compactedTransportQuarantine(
            candidate.transportQuarantine
        )
        guard Self.isValidTransportQuarantineCollection(
            candidate.transportQuarantine
        ) else {
            throw PairwiseRelationshipV2Error.invalidState
        }
        let retained = candidate.transportQuarantine.contains(where: {
            TransportQuarantineCoordinate($0) == TransportQuarantineCoordinate(quarantine)
        })
        self = candidate
        return retained
    }

    /// Retains an authenticated but unsupported relationship control for a
    /// future client version without allowing it to mutate protocol state.
    /// The quarantine is relationship-local and bounded independently from the
    /// visible event projection.
    @discardableResult
    public mutating func recordControlQuarantine(
        _ quarantine: QuarantinedControlEvent
    ) throws -> Bool {
        guard quarantine.isStructurallyValid,
              quarantine.event.conversationId == conversationID,
              quarantine.event.authorEndpointHandle
                == peerIdentity.sendRoutes.ownerEndpointHandle else {
            throw PairwiseRelationshipV2Error.wrongRelationship
        }
        if let existing = controlQuarantine.first(where: {
            $0.event.id == quarantine.event.id
        }) {
            guard existing.event == quarantine.event,
                  existing.reason == quarantine.reason else {
                throw PairwiseRelationshipV2Error.conflictingEvent
            }
            return false
        }

        var candidate = self
        candidate.controlQuarantine.append(quarantine)
        candidate.controlQuarantine = Self.compactedControlQuarantine(
            candidate.controlQuarantine
        )
        guard Self.isValidControlQuarantineCollection(
            candidate.controlQuarantine,
            conversationID: conversationID,
            peerEndpoint: peerIdentity.sendRoutes.ownerEndpointHandle
        ) else {
            throw PairwiseRelationshipV2Error.invalidState
        }
        let retained = candidate.controlQuarantine.contains {
            $0.event.id == quarantine.event.id
        }
        self = candidate
        return retained
    }

    /// Re-applies deterministic quarantine ordering and bounds after importing
    /// or directly assembling local relationship state.
    public mutating func compactQuarantineState() throws {
        var candidate = self
        candidate.transportQuarantine = Self.compactedTransportQuarantine(
            candidate.transportQuarantine
        )
        candidate.controlQuarantine = Self.compactedControlQuarantine(
            candidate.controlQuarantine
        )
        guard try candidate.isStructurallyValidThrowing else {
            throw PairwiseRelationshipV2Error.invalidState
        }
        self = candidate
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

        var retainedIntentIDs = additionalIntentIDs
        retainedIntentIDs.formUnion(pendingDeliveries.map(\.intentID))
        retainedIntentIDs.formUnion(protocolIntents.compactMap { intent in
            guard intent.kind == .rolloverRoute,
                  pendingRouteRollovers.contains(where: {
                      intent.targetIdentifier == $0.clientCapabilities.routeID.rawValue
                  }) else { return nil }
            return intent.id
        })
        retainedIntentIDs.formUnion(protocolIntents.compactMap { intent in
            guard intent.kind == .uploadBlob,
                  pendingAttachmentUploads.contains(where: {
                      intent.targetIdentifier
                        == Data($0.id.uuidString.lowercased().utf8)
                  }) else { return nil }
            return intent.id
        })

        var candidate = self
        candidate.protocolIntents = try Self.compactedIntents(
            protocolIntents,
            retaining: retainedIntentIDs,
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
        candidate.transportQuarantine = Self.compactedTransportQuarantine(
            transportQuarantine
        )
        candidate.controlQuarantine = Self.compactedControlQuarantine(
            controlQuarantine
        )
        guard try candidate.isStructurallyValidThrowing else {
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

    private static func compactedTransportQuarantine(
        _ source: [QuarantinedTransportEnvelopeV2]
    ) -> [QuarantinedTransportEnvelopeV2] {
        Array(sortedTransportQuarantine(source).suffix(maximumTransportQuarantine))
    }

    private static func isValidTransportQuarantineCollection(
        _ source: [QuarantinedTransportEnvelopeV2]
    ) -> Bool {
        source.count <= maximumTransportQuarantine
            && Set(source.map(TransportQuarantineCoordinate.init)).count == source.count
            && Set(source.map(TransportQuarantinePacketCoordinate.init)).count == source.count
            && source.allSatisfy(\.isStructurallyValid)
            && source == sortedTransportQuarantine(source)
    }

    private static func sortedTransportQuarantine(
        _ source: [QuarantinedTransportEnvelopeV2]
    ) -> [QuarantinedTransportEnvelopeV2] {
        source.sorted(by: transportQuarantineIsOlder)
    }

    private static func transportQuarantineIsOlder(
        _ lhs: QuarantinedTransportEnvelopeV2,
        _ rhs: QuarantinedTransportEnvelopeV2
    ) -> Bool {
        if lhs.observedAt != rhs.observedAt { return lhs.observedAt < rhs.observedAt }
        if lhs.streamDigest != rhs.streamDigest {
            return lhs.streamDigest.lexicographicallyPrecedes(rhs.streamDigest)
        }
        if lhs.relaySequence != rhs.relaySequence {
            return lhs.relaySequence < rhs.relaySequence
        }
        if lhs.packetID.rawValue != rhs.packetID.rawValue {
            return lhs.packetID.rawValue.lexicographicallyPrecedes(rhs.packetID.rawValue)
        }
        if lhs.recordDigest != rhs.recordDigest {
            return lhs.recordDigest.lexicographicallyPrecedes(rhs.recordDigest)
        }
        if lhs.reason != rhs.reason { return lhs.reason.rawValue < rhs.reason.rawValue }
        return (lhs.innerEnvelopeID?.uuidString ?? "")
            < (rhs.innerEnvelopeID?.uuidString ?? "")
    }

    private static func isSameTransportQuarantine(
        _ lhs: QuarantinedTransportEnvelopeV2,
        _ rhs: QuarantinedTransportEnvelopeV2
    ) -> Bool {
        lhs.streamDigest == rhs.streamDigest
            && lhs.relaySequence == rhs.relaySequence
            && lhs.packetID == rhs.packetID
            && lhs.recordDigest == rhs.recordDigest
            && lhs.reason == rhs.reason
            && lhs.innerEnvelopeID == rhs.innerEnvelopeID
    }

    private static func compactedControlQuarantine(
        _ source: [QuarantinedControlEvent]
    ) -> [QuarantinedControlEvent] {
        Array(sortedControlQuarantine(source).suffix(maximumControlQuarantine))
    }

    private static func isValidControlQuarantineCollection(
        _ source: [QuarantinedControlEvent],
        conversationID: String,
        peerEndpoint: RelationshipEndpointHandle
    ) -> Bool {
        source.count <= maximumControlQuarantine
            && Set(source.map { $0.event.id }).count == source.count
            && source.allSatisfy {
                $0.isStructurallyValid
                    && $0.event.conversationId == conversationID
                    && $0.event.authorEndpointHandle == peerEndpoint
            }
            && source == sortedControlQuarantine(source)
    }

    private static func sortedControlQuarantine(
        _ source: [QuarantinedControlEvent]
    ) -> [QuarantinedControlEvent] {
        source.sorted {
            if $0.receivedAt != $1.receivedAt { return $0.receivedAt < $1.receivedAt }
            if $0.event.id != $1.event.id {
                return $0.event.id.uuidString < $1.event.id.uuidString
            }
            return $0.reason < $1.reason
        }
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
        guard intent.kind == .sendEvent || intent.kind == .renewRelationshipPrekey,
              let target = intent.targetIdentifier,
              let text = String(data: target, encoding: .utf8) else {
            return nil
        }
        return UUID(uuidString: text)
    }

    private static func uuidTarget(_ target: Data?) -> UUID? {
        guard let target,
              let text = String(data: target, encoding: .utf8),
              let value = UUID(uuidString: text),
              text == value.uuidString.lowercased() else {
            return nil
        }
        return value
    }

    private static func canonicalDigest<Value: Encodable>(_ value: Value) -> Data? {
        guard let encoded = try? NoctweaveCoder.encode(value, sortedKeys: true) else {
            return nil
        }
        return Data(SHA256.hash(data: encoded))
    }

    private static func intentDependenciesContainCycle(
        _ intents: [ProtocolIntentV2]
    ) -> Bool {
        let byID = Dictionary(uniqueKeysWithValues: intents.map { ($0.id, $0) })
        var visiting = Set<UUID>()
        var visited = Set<UUID>()

        func visit(_ id: UUID) -> Bool {
            if visiting.contains(id) { return true }
            if visited.contains(id) { return false }
            visiting.insert(id)
            for dependency in byID[id]?.dependencies ?? [] where visit(dependency) {
                return true
            }
            visiting.remove(id)
            visited.insert(id)
            return false
        }

        return intents.contains { visit($0.id) }
    }

    private static func requiresDurableEventContext(_ state: DeliveryStateRecord) -> Bool {
        // Only an unfinished local outbox entry requires its complete event
        // context forever. Relay acceptance is a durable terminal transport
        // fact and may age out through the bounded recent-history window when
        // the peer does not emit optional delivery/read receipts.
        state.state == .locallyPersisted
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

private struct TransportQuarantineCoordinate: Hashable {
    let streamDigest: Data
    let relaySequence: UInt64

    init(_ quarantine: QuarantinedTransportEnvelopeV2) {
        streamDigest = quarantine.streamDigest
        relaySequence = quarantine.relaySequence
    }
}

private struct TransportQuarantinePacketCoordinate: Hashable {
    let streamDigest: Data
    let packetID: OpaqueRoutePacketIDV2

    init(_ quarantine: QuarantinedTransportEnvelopeV2) {
        streamDigest = quarantine.streamDigest
        packetID = quarantine.packetID
    }
}

private struct DirectDeliveryOrderKey: Hashable {
    let routeID: OpaqueReceiveRouteIDV2
    let sessionID: String
    let messageCounter: UInt64

    init(_ delivery: PendingOpaqueRouteDeliveryV2) {
        routeID = delivery.destinationRouteID
        sessionID = delivery.directSessionID
        messageCounter = delivery.messageCounter
    }
}

private struct AttachmentUploadCoordinate: Hashable {
    let attachmentID: UUID
    let chunkIndex: Int
}

private struct ConversationTransactionKey: Hashable {
    let author: RelationshipEndpointHandle
    let transactionID: UUID
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

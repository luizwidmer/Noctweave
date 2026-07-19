import CryptoKit
import Foundation

public enum GroupOpaqueRouteInboundV2Error: Error, Equatable {
    case invalidState
    case routeNotFound
    case routeAlreadyPending
    case routeCapacityReached
    case routeGapDetected
    case incompletePage
    case unsupportedEnvelope
}

private struct StrictGroupOpaqueInboundCodingKey: CodingKey {
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

private func requireExactGroupOpaqueInboundKeys<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ keyType: Key.Type
) throws where Key.AllCases: Collection {
    let strict = try decoder.container(keyedBy: StrictGroupOpaqueInboundCodingKey.self)
    guard Set(strict.allKeys.map(\.stringValue))
            == Set(keyType.allCases.map(\.stringValue)) else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "Group inbound transport fields must match exactly"
            )
        )
    }
}

/// Local-only route material for one group-scoped credential. The nested
/// capability secrets never leave encrypted client state; peers receive only
/// the corresponding `OpaqueSendRouteV2` inside a signed group route set.
public struct GroupLocalOpaqueReceiveRouteV2: Codable, Equatable, Identifiable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var id: OpaqueReceiveRouteIDV2 { localRoute.route.routeID }
    public let localRoute: LocalOpaqueReceiveRouteV2
    public let advertisedState: RelationshipRouteStateV2
    public let activatedAt: Date
    public let drainAfter: Date?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case localRoute
        case advertisedState
        case activatedAt
        case drainAfter
    }

    public init(
        localRoute: LocalOpaqueReceiveRouteV2,
        advertisedState: RelationshipRouteStateV2,
        activatedAt: Date,
        drainAfter: Date? = nil
    ) throws {
        self.localRoute = localRoute
        self.advertisedState = advertisedState
        self.activatedAt = activatedAt
        self.drainAfter = drainAfter
        guard try isStructurallyValidThrowing else {
            throw GroupOpaqueRouteInboundV2Error.invalidState
        }
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupOpaqueInboundKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            localRoute: values.decode(LocalOpaqueReceiveRouteV2.self, forKey: .localRoute),
            advertisedState: values.decode(
                RelationshipRouteStateV2.self,
                forKey: .advertisedState
            ),
            activatedAt: values.decode(Date.self, forKey: .activatedAt),
            drainAfter: values.decodeIfPresent(Date.self, forKey: .drainAfter)
        )
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid group route")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(localRoute, forKey: .localRoute)
        try values.encode(advertisedState, forKey: .advertisedState)
        try values.encode(activatedAt, forKey: .activatedAt)
        try values.encode(drainAfter, forKey: .drainAfter)
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            try localRoute.isStructurallyValidThrowing
                && (advertisedState == .active || advertisedState == .draining)
                && activatedAt.timeIntervalSince1970.isFinite
                && activatedAt >= localRoute.route.createdAt
                && ((advertisedState == .draining) == (drainAfter != nil))
                && (drainAfter.map {
                    $0 > localRoute.route.lease.issuedAt
                        && $0 <= localRoute.route.lease.expiresAt
                } ?? true)
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    func replacing(
        localRoute: LocalOpaqueReceiveRouteV2? = nil,
        advertisedState: RelationshipRouteStateV2? = nil,
        drainAfter: Date?? = nil
    ) throws -> Self {
        try Self(
            localRoute: localRoute ?? self.localRoute,
            advertisedState: advertisedState ?? self.advertisedState,
            activatedAt: activatedAt,
            drainAfter: drainAfter ?? self.drainAfter
        )
    }

    func advertisedSendRoute() throws -> OpaqueSendRouteV2 {
        try OpaqueSendRouteV2(
            routeID: localRoute.route.routeID,
            relay: localRoute.relay,
            sendCapability: localRoute.clientCapabilities.sendCapability,
            payloadKey: localRoute.payloadKey,
            routeRevision: localRoute.route.lease.renewalSequence,
            policy: localRoute.route.lease.policy,
            validFrom: localRoute.route.lease.issuedAt,
            expiresAt: localRoute.route.lease.expiresAt,
            priority: 100,
            state: advertisedState,
            testedAt: advertisedState == .active || advertisedState == .draining
                ? localRoute.route.lease.issuedAt
                : nil,
            drainAfter: advertisedState == .draining ? drainAfter : nil,
            revokedAt: nil
        )
    }

    public var description: String { "GroupLocalOpaqueReceiveRouteV2(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:], displayStyle: .struct) }
}

public struct GroupInboundPacketSourceV2: Codable, Equatable {
    public let relaySequence: UInt64
    public let packetID: OpaqueRoutePacketIDV2
    public let recordDigest: Data

    public init(receivedPacket: OpaqueRouteReceivedPacketV2) {
        relaySequence = receivedPacket.sequence
        packetID = receivedPacket.packet.packetID
        recordDigest = receivedPacket.recordDigest
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case relaySequence
        case packetID
        case recordDigest
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupOpaqueInboundKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        relaySequence = try values.decode(UInt64.self, forKey: .relaySequence)
        packetID = try values.decode(OpaqueRoutePacketIDV2.self, forKey: .packetID)
        recordDigest = try values.decode(Data.self, forKey: .recordDigest)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .recordDigest,
                in: values,
                debugDescription: "Invalid group packet source"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid packet source")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(relaySequence, forKey: .relaySequence)
        try values.encode(packetID, forKey: .packetID)
        try values.encode(recordDigest, forKey: .recordDigest)
    }

    public var isStructurallyValid: Bool {
        relaySequence > 0
            && packetID.isStructurallyValid
            && recordDigest.count == NoctweaveOpaqueRoutesV2.digestBytes
    }
}

/// A complete plaintext protocol envelope retained after fragment reassembly
/// and before its authenticated group effect is applied. This closes the crash
/// window between writing a completed-bundle tombstone and processing payload.
public struct PendingGroupInboundBundleV2: Codable, Equatable, Identifiable {
    public var id: OpaqueRouteBundleIDV2 { bundleID }
    public let bundleID: OpaqueRouteBundleIDV2
    public let routeID: OpaqueReceiveRouteIDV2
    public let payload: Data
    public let source: GroupInboundPacketSourceV2
    public let receivedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case bundleID
        case routeID
        case payload
        case source
        case receivedAt
    }

    public init(
        bundle: OpaqueRouteReassembledBundleV2,
        source: GroupInboundPacketSourceV2,
        receivedAt: Date
    ) throws {
        bundleID = bundle.bundleID
        routeID = bundle.routeID
        payload = bundle.payload
        self.source = source
        self.receivedAt = receivedAt
        guard isStructurallyValid else {
            throw GroupOpaqueRouteInboundV2Error.invalidState
        }
    }

    private init(
        bundleID: OpaqueRouteBundleIDV2,
        routeID: OpaqueReceiveRouteIDV2,
        payload: Data,
        source: GroupInboundPacketSourceV2,
        receivedAt: Date
    ) {
        self.bundleID = bundleID
        self.routeID = routeID
        self.payload = payload
        self.source = source
        self.receivedAt = receivedAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupOpaqueInboundKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            bundleID: try values.decode(OpaqueRouteBundleIDV2.self, forKey: .bundleID),
            routeID: try values.decode(OpaqueReceiveRouteIDV2.self, forKey: .routeID),
            payload: try values.decode(Data.self, forKey: .payload),
            source: try values.decode(
                GroupInboundPacketSourceV2.self,
                forKey: .source
            ),
            receivedAt: try values.decode(Date.self, forKey: .receivedAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .payload,
                in: values,
                debugDescription: "Invalid pending group inbound bundle"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid inbound bundle")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(bundleID, forKey: .bundleID)
        try values.encode(routeID, forKey: .routeID)
        try values.encode(payload, forKey: .payload)
        try values.encode(source, forKey: .source)
        try values.encode(receivedAt, forKey: .receivedAt)
    }

    public var isStructurallyValid: Bool {
        bundleID.isStructurallyValid
            && routeID.isStructurallyValid
            && !payload.isEmpty
            && payload.count <= LocalOpaqueReceiveRouteV2.maximumPersistedReassemblerBufferedBytes
            && source.isStructurallyValid
            && receivedAt.timeIntervalSince1970.isFinite
    }
}

/// Separately delivered epoch artifacts are staged until the exact transition
/// and this credential's Welcome are both available. Each array is append
/// ordered and bounded; conflicting artifacts are handled by group verification.
public struct GroupInboundEpochStagingV2: Codable, Equatable {
    public static let maximumArtifacts = 32
    public let transitions: [GroupEpochTransitionEnvelopeV2]
    public let welcomes: [SignedGroupWelcomeV2]

    public static let empty = GroupInboundEpochStagingV2(
        uncheckedTransitions: [],
        welcomes: []
    )

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case transitions
        case welcomes
    }

    public init(
        transitions: [GroupEpochTransitionEnvelopeV2] = [],
        welcomes: [SignedGroupWelcomeV2] = []
    ) throws {
        self.transitions = transitions
        self.welcomes = welcomes
        guard isStructurallyValid else {
            throw GroupOpaqueRouteInboundV2Error.invalidState
        }
    }

    private init(
        uncheckedTransitions: [GroupEpochTransitionEnvelopeV2],
        welcomes: [SignedGroupWelcomeV2]
    ) {
        transitions = uncheckedTransitions
        self.welcomes = welcomes
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupOpaqueInboundKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            transitions: values.decode(
                [GroupEpochTransitionEnvelopeV2].self,
                forKey: .transitions
            ),
            welcomes: values.decode([SignedGroupWelcomeV2].self, forKey: .welcomes)
        )
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid epoch staging")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(transitions, forKey: .transitions)
        try values.encode(welcomes, forKey: .welcomes)
    }

    public var isStructurallyValid: Bool {
        transitions.count <= Self.maximumArtifacts
            && welcomes.count <= Self.maximumArtifacts
            && Set(transitions.map(\.id)).count == transitions.count
            && Set(welcomes.map(\.id)).count == welcomes.count
            && transitions.allSatisfy(\.isStructurallyValid)
            && welcomes.allSatisfy(\.isStructurallyValid)
    }
}

/// Complete durable inbound transport state for one group. It is local state,
/// not a protocol identity, and every signing authority referenced here is the
/// runtime's group-only credential.
public struct GroupOpaqueRouteInboundStateV2: Codable, Equatable {
    public static let version = 2
    public static let maximumPendingBundles = 64

    public let version: Int
    public let pendingRoute: PendingLocalOpaqueReceiveRouteV2?
    public let localRoutes: [GroupLocalOpaqueReceiveRouteV2]
    public let advertisedRouteSet: SignedGroupOpaqueRouteSetV2?
    public let advertisedRouteAnnouncement: SignedGroupRouteSetAnnouncementV2?
    public let pendingRouteAnnouncementID: UUID?
    public let routeSetOwnerSigningPublicKey: Data?
    public let pendingBundles: [PendingGroupInboundBundleV2]
    public let epochStaging: GroupInboundEpochStagingV2
    public let quarantines: [QuarantinedTransportEnvelopeV2]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case pendingRoute
        case localRoutes
        case advertisedRouteSet
        case advertisedRouteAnnouncement
        case pendingRouteAnnouncementID
        case routeSetOwnerSigningPublicKey
        case pendingBundles
        case epochStaging
        case quarantines
    }

    public init(
        version: Int = Self.version,
        pendingRoute: PendingLocalOpaqueReceiveRouteV2? = nil,
        localRoutes: [GroupLocalOpaqueReceiveRouteV2] = [],
        advertisedRouteSet: SignedGroupOpaqueRouteSetV2? = nil,
        advertisedRouteAnnouncement: SignedGroupRouteSetAnnouncementV2? = nil,
        pendingRouteAnnouncementID: UUID? = nil,
        routeSetOwnerSigningPublicKey: Data? = nil,
        pendingBundles: [PendingGroupInboundBundleV2] = [],
        epochStaging: GroupInboundEpochStagingV2 = .empty,
        quarantines: [QuarantinedTransportEnvelopeV2] = []
    ) {
        self.version = version
        self.pendingRoute = pendingRoute
        self.localRoutes = localRoutes
        self.advertisedRouteSet = advertisedRouteSet
        self.advertisedRouteAnnouncement = advertisedRouteAnnouncement
        self.pendingRouteAnnouncementID = pendingRouteAnnouncementID
        self.routeSetOwnerSigningPublicKey = routeSetOwnerSigningPublicKey
        self.pendingBundles = pendingBundles
        self.epochStaging = epochStaging
        self.quarantines = quarantines
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupOpaqueInboundKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            pendingRoute: try values.decodeIfPresent(
                PendingLocalOpaqueReceiveRouteV2.self,
                forKey: .pendingRoute
            ),
            localRoutes: try values.decode(
                [GroupLocalOpaqueReceiveRouteV2].self,
                forKey: .localRoutes
            ),
            advertisedRouteSet: try values.decodeIfPresent(
                SignedGroupOpaqueRouteSetV2.self,
                forKey: .advertisedRouteSet
            ),
            advertisedRouteAnnouncement: try values.decodeIfPresent(
                SignedGroupRouteSetAnnouncementV2.self,
                forKey: .advertisedRouteAnnouncement
            ),
            pendingRouteAnnouncementID: try values.decodeIfPresent(
                UUID.self,
                forKey: .pendingRouteAnnouncementID
            ),
            routeSetOwnerSigningPublicKey: try values.decodeIfPresent(
                Data.self,
                forKey: .routeSetOwnerSigningPublicKey
            ),
            pendingBundles: try values.decode(
                [PendingGroupInboundBundleV2].self,
                forKey: .pendingBundles
            ),
            epochStaging: try values.decode(
                GroupInboundEpochStagingV2.self,
                forKey: .epochStaging
            ),
            quarantines: try values.decode(
                [QuarantinedTransportEnvelopeV2].self,
                forKey: .quarantines
            )
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .localRoutes,
                in: values,
                debugDescription: "Invalid group inbound state"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid inbound state")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(pendingRoute, forKey: .pendingRoute)
        try values.encode(localRoutes, forKey: .localRoutes)
        try values.encode(advertisedRouteSet, forKey: .advertisedRouteSet)
        try values.encode(advertisedRouteAnnouncement, forKey: .advertisedRouteAnnouncement)
        try values.encode(pendingRouteAnnouncementID, forKey: .pendingRouteAnnouncementID)
        try values.encode(routeSetOwnerSigningPublicKey, forKey: .routeSetOwnerSigningPublicKey)
        try values.encode(pendingBundles, forKey: .pendingBundles)
        try values.encode(epochStaging, forKey: .epochStaging)
        try values.encode(quarantines, forKey: .quarantines)
    }

    public var isStructurallyValid: Bool {
        version == Self.version
            && pendingRoute?.isStructurallyValid != false
            && localRoutes.count <= NoctweaveArchitectureV2.maximumRoutes
            && Set(localRoutes.map(\.id)).count == localRoutes.count
            && localRoutes.allSatisfy(\.isStructurallyValid)
            && (localRoutes.filter {
                $0.advertisedState == .active || $0.advertisedState == .draining
            }.isEmpty == (advertisedRouteSet == nil))
            && ((advertisedRouteSet == nil) == (advertisedRouteAnnouncement == nil))
            && (pendingRouteAnnouncementID.map {
                $0 == advertisedRouteAnnouncement?.id
            } ?? true)
            && ((advertisedRouteSet == nil) == (routeSetOwnerSigningPublicKey == nil))
            && (routeSetOwnerSigningPublicKey.map { !$0.isEmpty && $0.count <= 8 * 1_024 }
                ?? true)
            && advertisedRoutesMatchLocalState
            && advertisedAnnouncementMatchesRouteSet
            && pendingBundles.count <= Self.maximumPendingBundles
            && Set(pendingBundles.map(\.id)).count == pendingBundles.count
            && pendingBundles.allSatisfy(\.isStructurallyValid)
            && Set(pendingBundles.map(\.routeID)).isSubset(of: Set(localRoutes.map(\.id)))
            && pendingBundles.reduce(0) { $0 + $1.payload.count }
                <= 2 * LocalOpaqueReceiveRouteV2.maximumPersistedReassemblerBufferedBytes
            && epochStaging.isStructurallyValid
            && quarantines.count <= NoctweaveArchitectureV2.maximumQuarantinedTransportEnvelopes
            && quarantines.allSatisfy(\.isStructurallyValid)
    }

    private var advertisedRoutesMatchLocalState: Bool {
        guard let advertisedRouteSet else { return localRoutes.isEmpty }
        let projections = try? localRoutes.filter {
            $0.advertisedState == .active || $0.advertisedState == .draining
        }.map {
            try $0.advertisedSendRoute()
        }.sorted { $0.routeID.rawValue.lexicographicallyPrecedes($1.routeID.rawValue) }
        guard let routeSetOwnerSigningPublicKey else { return false }
        return advertisedRouteSet.verify(
                ownerSigningPublicKey: routeSetOwnerSigningPublicKey
            )
            && projections == advertisedRouteSet.routes
    }

    private var advertisedAnnouncementMatchesRouteSet: Bool {
        guard let advertisedRouteSet,
              let advertisedRouteAnnouncement,
              let routeSetOwnerSigningPublicKey else {
            return advertisedRouteSet == nil
                && advertisedRouteAnnouncement == nil
                && pendingRouteAnnouncementID == nil
        }
        return advertisedRouteAnnouncement.routeSet == advertisedRouteSet
            && (try? advertisedRouteAnnouncement.verified(
                ownerSigningPublicKey: routeSetOwnerSigningPublicKey,
                observedAt: advertisedRouteAnnouncement.announcedAt
            )) != nil
    }

    func replacing(
        pendingRoute: PendingLocalOpaqueReceiveRouteV2?? = nil,
        localRoutes: [GroupLocalOpaqueReceiveRouteV2]? = nil,
        advertisedRouteSet: SignedGroupOpaqueRouteSetV2?? = nil,
        advertisedRouteAnnouncement: SignedGroupRouteSetAnnouncementV2?? = nil,
        pendingRouteAnnouncementID: UUID?? = nil,
        routeSetOwnerSigningPublicKey: Data?? = nil,
        pendingBundles: [PendingGroupInboundBundleV2]? = nil,
        epochStaging: GroupInboundEpochStagingV2? = nil,
        quarantines: [QuarantinedTransportEnvelopeV2]? = nil
    ) -> Self {
        Self(
            version: version,
            pendingRoute: pendingRoute ?? self.pendingRoute,
            localRoutes: localRoutes ?? self.localRoutes,
            advertisedRouteSet: advertisedRouteSet ?? self.advertisedRouteSet,
            advertisedRouteAnnouncement: advertisedRouteAnnouncement
                ?? self.advertisedRouteAnnouncement,
            pendingRouteAnnouncementID: pendingRouteAnnouncementID
                ?? self.pendingRouteAnnouncementID,
            routeSetOwnerSigningPublicKey: routeSetOwnerSigningPublicKey
                ?? self.routeSetOwnerSigningPublicKey,
            pendingBundles: pendingBundles ?? self.pendingBundles,
            epochStaging: epochStaging ?? self.epochStaging,
            quarantines: quarantines ?? self.quarantines
        )
    }
}

public struct GroupInboundSyncResultV2: Codable, Equatable {
    public let groupID: UUID
    public let routeID: OpaqueReceiveRouteIDV2
    public let receivedEvents: [GroupConversationEventV2]
    public let committedCursor: OpaqueRouteCursorV2
    public let hasMore: Bool
}

public struct HeadlessGroupReceiveRouteResultV2: Codable, Equatable {
    public let groupID: UUID
    public let routeID: OpaqueReceiveRouteIDV2
    public let routeSet: SignedGroupOpaqueRouteSetV2
    public let announcement: SignedGroupRouteSetAnnouncementV2
    public let announcementOperationID: UUID?
    public let announcementComplete: Bool
}

extension NoctweavePQGroupRuntimeV2 {
    public func inboundTransportSnapshot() -> GroupOpaqueRouteInboundStateV2 {
        record.inboundTransport
    }

    /// Saves fresh group-only receive capability material before route-create
    /// I/O. A crash resumes the same idempotent create request.
    public func prepareInboundReceiveRoute(
        relay: RelayEndpoint,
        policy: OpaqueRoutePolicyV2 = OpaqueRoutePolicyV2(
            paddingBucket: .bytes4096,
            retentionBucket: .sixHours,
            quotaBucket: .packets256
        ),
        createdAt: Date = Date()
    ) async throws -> PendingLocalOpaqueReceiveRouteV2 {
        try requireActiveRuntime()
        let inbound = record.inboundTransport
        guard inbound.pendingRoute == nil else {
            throw GroupOpaqueRouteInboundV2Error.routeAlreadyPending
        }
        guard inbound.localRoutes.filter({ createdAt < $0.localRoute.route.lease.expiresAt })
                .count < NoctweaveArchitectureV2.maximumRoutes else {
            throw GroupOpaqueRouteInboundV2Error.routeCapacityReached
        }
        let pending = try PendingLocalOpaqueReceiveRouteV2.prepare(
            relay: relay,
            policy: policy,
            createdAt: createdAt
        )
        try await persist(record.replacing(
            inboundTransport: inbound.replacing(pendingRoute: .some(pending))
        ))
        return pending
    }

    /// Installs a relay-confirmed route and signs the next group-credential
    /// route set. Existing active paths become draining but remain readable,
    /// so rotation is make-before-break.
    public func activateInboundReceiveRoute(
        createdRoute: OpaqueReceiveRouteV2,
        activatedAt: Date = Date()
    ) async throws -> SignedGroupOpaqueRouteSetV2 {
        try requireActiveRuntime()
        let inbound = record.inboundTransport
        guard let pending = inbound.pendingRoute,
              activatedAt.timeIntervalSince1970.isFinite else {
            throw GroupOpaqueRouteInboundV2Error.routeNotFound
        }
        let activated = try pending.activate(createdRoute: createdRoute)
        var localRoutes = try inbound.localRoutes.filter {
            activatedAt < $0.localRoute.route.lease.expiresAt
        }.map {
            let proposedDrainAfter = min(
                $0.localRoute.route.lease.expiresAt,
                activatedAt.addingTimeInterval(15 * 60)
            )
            let drainAfter = min($0.drainAfter ?? proposedDrainAfter, proposedDrainAfter)
            guard drainAfter > $0.localRoute.route.lease.issuedAt else {
                throw GroupOpaqueRouteInboundV2Error.invalidState
            }
            return try $0.replacing(
                advertisedState: .draining,
                drainAfter: .some(drainAfter)
            )
        }
        localRoutes.append(try GroupLocalOpaqueReceiveRouteV2(
            localRoute: activated,
            advertisedState: .active,
            activatedAt: activatedAt,
            drainAfter: nil
        ))
        let routeSet = try signInboundRouteSet(
            localRoutes: localRoutes,
            previous: inbound.advertisedRouteSet,
            issuedAt: activatedAt
        )
        let staged = try stageLocalRouteAnnouncement(
            inbound: inbound,
            localRoutes: localRoutes,
            routeSet: routeSet,
            pendingRoute: .some(nil),
            announcedAt: activatedAt
        )
        guard staged.inbound.isStructurallyValid else {
            throw GroupOpaqueRouteInboundV2Error.invalidState
        }
        try await persist(record.replacing(
            outboundTransportOperations: staged.operation.map {
                record.outboundTransportOperations + [$0]
            } ?? record.outboundTransportOperations,
            inboundTransport: staged.inbound
        ))
        return routeSet
    }

    /// Re-signs current paths after a group-only credential replacement. The
    /// new credential starts its own revision chain; no global continuity is
    /// inferred from the predecessor credential.
    public func refreshInboundRouteSet(
        at date: Date = Date()
    ) async throws -> SignedGroupOpaqueRouteSetV2 {
        try requireActiveRuntime()
        let inbound = record.inboundTransport
        guard !inbound.localRoutes.isEmpty else {
            throw GroupOpaqueRouteInboundV2Error.routeNotFound
        }
        let sameOwner = inbound.advertisedRouteSet?.ownerCredentialHandle
            == record.localCredential.credentialHandle
        let routeSet = try signInboundRouteSet(
            localRoutes: inbound.localRoutes,
            previous: sameOwner ? inbound.advertisedRouteSet : nil,
            issuedAt: date
        )
        let staged = try stageLocalRouteAnnouncement(
            inbound: inbound,
            localRoutes: inbound.localRoutes,
            routeSet: routeSet,
            announcedAt: date
        )
        try await persist(record.replacing(
            outboundTransportOperations: staged.operation.map {
                record.outboundTransportOperations + [$0]
            } ?? record.outboundTransportOperations,
            inboundTransport: staged.inbound
        ))
        return routeSet
    }

    /// Removes expired draining paths only after a newer active path exists,
    /// then signs the successor before returning capability material for
    /// best-effort relay teardown.
    public func finalizeExpiredInboundRoutes(
        at date: Date = Date()
    ) async throws -> (
        routeSet: SignedGroupOpaqueRouteSetV2,
        removedRoutes: [LocalOpaqueReceiveRouteV2]
    )? {
        let inbound = record.inboundTransport
        guard date.timeIntervalSince1970.isFinite,
              inbound.localRoutes.contains(where: {
                  $0.advertisedState == .active && date < $0.localRoute.route.lease.expiresAt
              }) else {
            return nil
        }
        let removed = inbound.localRoutes.filter {
            $0.advertisedState == .draining && $0.localRoute.route.lease.expiresAt <= date
        }
        guard !removed.isEmpty else { return nil }
        let retained = inbound.localRoutes.filter {
            !removed.contains($0)
        }
        let routeSet = try signInboundRouteSet(
            localRoutes: retained,
            previous: inbound.advertisedRouteSet,
            issuedAt: date
        )
        let staged = try stageLocalRouteAnnouncement(
            inbound: inbound,
            localRoutes: retained,
            routeSet: routeSet,
            announcedAt: date
        )
        try await persist(record.replacing(
            outboundTransportOperations: staged.operation.map {
                record.outboundTransportOperations + [$0]
            } ?? record.outboundTransportOperations,
            inboundTransport: staged.inbound
        ))
        return (routeSet, removed.map(\.localRoute))
    }

    public func currentRouteSetAnnouncement() -> SignedGroupRouteSetAnnouncementV2? {
        record.inboundTransport.advertisedRouteAnnouncement
    }

    public func pendingRouteSetAnnouncementTransport()
        -> GroupOpaqueRouteOutboundOperationV2? {
        guard let id = record.inboundTransport.pendingRouteAnnouncementID else {
            return nil
        }
        return record.outboundTransportOperations.first {
            $0.kind == .routeAnnouncement && $0.logicalID == id
        }
    }

    internal func markRouteSetAnnouncementPublished(
        announcementID: UUID
    ) async throws {
        let inbound = record.inboundTransport
        guard inbound.pendingRouteAnnouncementID == announcementID,
              record.outboundTransportOperations.contains(where: {
                  $0.kind == .routeAnnouncement
                      && $0.logicalID == announcementID
                      && $0.isComplete
              }) else {
            throw GroupOpaqueRouteInboundV2Error.invalidState
        }
        try await persist(record.replacing(
            inboundTransport: inbound.replacing(
                pendingRouteAnnouncementID: .some(nil)
            )
        ))
    }

    private func stageLocalRouteAnnouncement(
        inbound: GroupOpaqueRouteInboundStateV2,
        localRoutes: [GroupLocalOpaqueReceiveRouteV2],
        routeSet: SignedGroupOpaqueRouteSetV2,
        pendingRoute: PendingLocalOpaqueReceiveRouteV2?? = nil,
        announcedAt: Date
    ) throws -> (
        inbound: GroupOpaqueRouteInboundStateV2,
        operation: GroupOpaqueRouteOutboundOperationV2?
    ) {
        guard inbound.pendingRouteAnnouncementID == nil else {
            throw GroupOpaqueRouteInboundV2Error.invalidState
        }
        let announcement = try SignedGroupRouteSetAnnouncementV2.create(
            state: record.signedState,
            routeSet: routeSet,
            localCredential: record.localCredential,
            announcedAt: announcedAt
        )
        let recipients = record.signedState.activeCredentials.filter {
            $0.memberHandle != record.localCredential.memberHandle
        }
        let operation: GroupOpaqueRouteOutboundOperationV2?
        if recipients.isEmpty {
            operation = nil
        } else {
            guard record.outboundTransportOperations.count
                    < GroupOpaqueRouteOutboundOperationV2.maximumJournalEntries else {
                throw GroupOpaqueRouteTransportV2Error.capacityReached
            }
            do {
                let routeSets = try record.peerRouteCache.routeSets(
                    for: recipients,
                    at: announcedAt
                )
                let snapshots = try zip(recipients, routeSets).map {
                    try GroupOpaqueRouteDestinationSnapshotV2(
                        credential: $0.0,
                        routeSet: $0.1,
                        capturedAt: announcedAt
                    )
                }
                operation = try GroupOpaqueRouteOutboundOperationV2.routeAnnouncement(
                    announcement,
                    snapshots: snapshots,
                    at: announcedAt
                )
            } catch GroupRouteSetAnnouncementV2Error.routeSetMissing
                where inbound.advertisedRouteSet == nil {
                // A first receive route is invitation/bootstrap material. Once
                // a route has been advertised, every successor must fan out
                // through the complete authenticated peer cache.
                operation = nil
            }
        }
        let candidate = inbound.replacing(
            pendingRoute: pendingRoute,
            localRoutes: localRoutes,
            advertisedRouteSet: .some(routeSet),
            advertisedRouteAnnouncement: .some(announcement),
            pendingRouteAnnouncementID: .some(operation?.logicalID),
            routeSetOwnerSigningPublicKey: .some(
                record.localCredential.signingKey.publicKeyData
            )
        )
        guard candidate.isStructurallyValid else {
            throw GroupOpaqueRouteInboundV2Error.invalidState
        }
        return (candidate, operation)
    }

    /// Reassembles one relay-authenticated packet and persists either partial
    /// fragments, a terminal quarantine, or a complete pending bundle before
    /// returning. Complete payload processing happens in a separate idempotent
    /// drain so a process kill cannot lose the bundle.
    public func ingestInboundPacket(
        routeID: OpaqueReceiveRouteIDV2,
        receivedPacket: OpaqueRouteReceivedPacketV2,
        observedAt: Date = Date()
    ) async throws {
        guard observedAt.timeIntervalSince1970.isFinite else {
            throw GroupOpaqueRouteInboundV2Error.invalidState
        }
        var inbound = record.inboundTransport
        guard let index = inbound.localRoutes.firstIndex(where: { $0.id == routeID }) else {
            throw GroupOpaqueRouteInboundV2Error.routeNotFound
        }
        var wrapper = inbound.localRoutes[index]
        guard wrapper.localRoute.gapState == nil else {
            throw GroupOpaqueRouteInboundV2Error.routeGapDetected
        }
        var local = wrapper.localRoute
        let payloadKey = local.payloadKey
        var completed: OpaqueRouteReassembledBundleV2?
        var terminalReason: TransportQuarantineReasonV2?

        while completed == nil && terminalReason == nil {
            do {
                let result = try local.updateReassembler { reassembler in
                    try reassembler.consume(
                        receivedPacket.packet,
                        payloadKey: payloadKey,
                        routeRevision: receivedPacket.routeRevision
                    )
                }
                if case .complete(let bundle) = result { completed = bundle }
                if case .accepted = result { break }
                if case .duplicate = result { break }
            } catch OpaqueRoutePacketV2Error.reassemblyCapacityExceeded {
                let currentBundleID = try? receivedPacket.packet.open(
                    payloadKey: payloadKey,
                    routeRevision: receivedPacket.routeRevision
                ).bundleID
                let evicted = try local.updateReassembler { reassembler in
                    reassembler.discardOldestPendingBundle()
                }
                guard let evicted else { throw GroupOpaqueRouteInboundV2Error.invalidState }
                if evicted == currentBundleID { terminalReason = .reassemblyPressure }
            } catch {
                guard let reason = inboundQuarantineReason(for: error) else { throw error }
                terminalReason = reason
            }
        }

        wrapper = try wrapper.replacing(localRoute: local)
        var routes = inbound.localRoutes
        routes[index] = wrapper
        var bundles = inbound.pendingBundles
        var quarantines = inbound.quarantines
        if let completed,
           !bundles.contains(where: { $0.bundleID == completed.bundleID }) {
            guard bundles.count < GroupOpaqueRouteInboundStateV2.maximumPendingBundles else {
                throw GroupOpaqueRouteInboundV2Error.routeCapacityReached
            }
            bundles.append(try PendingGroupInboundBundleV2(
                bundle: completed,
                source: GroupInboundPacketSourceV2(receivedPacket: receivedPacket),
                receivedAt: observedAt
            ))
        }
        if let terminalReason {
            quarantines = appendInboundQuarantine(
                reason: terminalReason,
                receivedPacket: receivedPacket,
                routeID: routeID,
                innerEnvelopeID: nil,
                observedAt: observedAt,
                to: quarantines
            )
        }
        inbound = inbound.replacing(
            localRoutes: routes,
            pendingBundles: bundles,
            quarantines: quarantines
        )
        try await persist(record.replacing(inboundTransport: inbound))
    }

    /// Applies every complete pending bundle in append order. Each effect is
    /// saved before its pending-bundle record is removed; exact restart replays
    /// therefore converge through the runtime's replay journals.
    public func drainPendingInboundBundles(
        at date: Date = Date()
    ) async throws -> [GroupConversationEventV2] {
        guard date.timeIntervalSince1970.isFinite else {
            throw GroupOpaqueRouteInboundV2Error.invalidState
        }
        var receivedEvents: [GroupConversationEventV2] = []
        while let pending = record.inboundTransport.pendingBundles.first {
            do {
                let protocolEnvelope = try NoctweaveCoder.decode(
                    ProtocolEnvelopeV1.self,
                    from: pending.payload
                )
                switch protocolEnvelope {
                case .groupApplicationV2(let envelope):
                    guard envelope.groupId == record.groupId else {
                        throw GroupOpaqueRouteInboundV2Error.unsupportedEnvelope
                    }
                    let wasProcessed = record.processedApplicationEnvelopes.contains {
                        $0.eventID == envelope.eventId
                    }
                    let event = try await processApplicationEnvelope(envelope, at: date)
                    if !wasProcessed { receivedEvents.append(event) }
                case .groupCommitV2(let transition):
                    guard transition.commit.groupId == record.groupId else {
                        throw GroupOpaqueRouteInboundV2Error.unsupportedEnvelope
                    }
                    try await stageInboundTransition(transition)
                    try await convergeInboundEpochStaging(observedAt: date)
                case .groupWelcomeV2(let welcome):
                    guard welcome.groupId == record.groupId,
                          welcome.destinationCredentialHandle
                            == record.localCredential.credentialHandle
                            || record.pendingLocalCredentials.contains(where: {
                                $0.credentialHandle == welcome.destinationCredentialHandle
                            }) else {
                        throw GroupOpaqueRouteInboundV2Error.unsupportedEnvelope
                    }
                    try await stageInboundWelcome(welcome)
                    try await convergeInboundEpochStaging(observedAt: date)
                case .groupDeletionV2(let tombstone):
                    guard tombstone.groupId == record.groupId else {
                        throw GroupOpaqueRouteInboundV2Error.unsupportedEnvelope
                    }
                    _ = try await processDeletionTombstone(tombstone, observedAt: date)
                case .groupRouteSetV2(let announcement):
                    guard announcement.groupID == record.groupId else {
                        throw GroupOpaqueRouteInboundV2Error.unsupportedEnvelope
                    }
                    try await acceptPeerRouteSetAnnouncement(
                        announcement,
                        observedAt: date
                    )
                case .directV4:
                    throw GroupOpaqueRouteInboundV2Error.unsupportedEnvelope
                }
                try await removePendingInboundBundle(pending.bundleID)
            } catch {
                guard let reason = inboundEnvelopeQuarantineReason(for: error) else {
                    throw error
                }
                try await quarantinePendingInboundBundle(pending, reason: reason, at: date)
            }
        }
        return receivedEvents
    }

    public func markInboundRouteGap(
        routeID: OpaqueReceiveRouteIDV2,
        gap: OpaqueRouteGapStateV2
    ) async throws {
        var inbound = record.inboundTransport
        guard let index = inbound.localRoutes.firstIndex(where: { $0.id == routeID }) else {
            throw GroupOpaqueRouteInboundV2Error.routeNotFound
        }
        var local = inbound.localRoutes[index].localRoute
        local.gapState = gap
        _ = try local.updateReassembler { $0.discardPendingBundles() }
        var routes = inbound.localRoutes
        routes[index] = try inbound.localRoutes[index].replacing(localRoute: local)
        inbound = inbound.replacing(localRoutes: routes)
        try await persist(record.replacing(inboundTransport: inbound))
    }

    public func commitInboundPage(
        routeID: OpaqueReceiveRouteIDV2,
        batch: OpaqueRouteSyncResponseV2
    ) async throws {
        var inbound = record.inboundTransport
        guard inbound.pendingBundles.isEmpty,
              let index = inbound.localRoutes.firstIndex(where: { $0.id == routeID }) else {
            throw GroupOpaqueRouteInboundV2Error.incompletePage
        }
        var local = inbound.localRoutes[index].localRoute
        guard local.gapState == nil,
              batch.isStructurallyValid,
              batch.startsAfterSequence == local.committedSequence,
              batch.startsAfterRecordDigest == local.committedRecordDigest,
              batch.retentionFloorSequence <= local.committedSequence,
              batch.nextSequence >= local.committedSequence else {
            throw GroupOpaqueRouteInboundV2Error.routeGapDetected
        }
        local.committedCursor = batch.nextCursor
        local.committedSequence = batch.nextSequence
        local.committedRecordDigest = batch.nextRecordDigest
        var routes = inbound.localRoutes
        routes[index] = try inbound.localRoutes[index].replacing(localRoute: local)
        inbound = inbound.replacing(localRoutes: routes)
        try await persist(record.replacing(inboundTransport: inbound))
    }

    private func signInboundRouteSet(
        localRoutes: [GroupLocalOpaqueReceiveRouteV2],
        previous: SignedGroupOpaqueRouteSetV2?,
        issuedAt: Date
    ) throws -> SignedGroupOpaqueRouteSetV2 {
        guard issuedAt.timeIntervalSince1970.isFinite else {
            throw GroupOpaqueRouteInboundV2Error.invalidState
        }
        let advertised = localRoutes.filter {
            $0.advertisedState == .active || $0.advertisedState == .draining
        }
        let routes = try advertised.map {
            try $0.advertisedSendRoute()
        }
        guard let expiration = routes.map(\.expiresAt).min(), issuedAt < expiration else {
            throw GroupOpaqueRouteInboundV2Error.invalidState
        }
        if let previous,
           previous.ownerCredentialHandle == record.localCredential.credentialHandle,
           previous.ownerAdmissionDigest == record.localCredential.admissionDigest {
            return try previous.successor(
                routes: routes,
                issuedAt: issuedAt,
                expiresAt: expiration,
                signingKey: record.localCredential.signingKey
            )
        }
        return try SignedGroupOpaqueRouteSetV2.create(
            groupID: record.groupId,
            ownerCredentialHandle: record.localCredential.credentialHandle,
            ownerAdmissionDigest: record.localCredential.admissionDigest,
            routes: routes,
            issuedAt: issuedAt,
            expiresAt: expiration,
            signingKey: record.localCredential.signingKey
        )
    }

    private func stageInboundTransition(
        _ transition: GroupEpochTransitionEnvelopeV2
    ) async throws {
        var inbound = record.inboundTransport
        if inbound.epochStaging.transitions.contains(transition) { return }
        guard !inbound.epochStaging.transitions.contains(where: {
            $0.id == transition.id && $0 != transition
        }), inbound.epochStaging.transitions.count < GroupInboundEpochStagingV2.maximumArtifacts else {
            throw GroupRuntimeError.conflictingCommitQuarantined
        }
        let staging = try GroupInboundEpochStagingV2(
            transitions: inbound.epochStaging.transitions + [transition],
            welcomes: inbound.epochStaging.welcomes
        )
        inbound = inbound.replacing(epochStaging: staging)
        try await persist(record.replacing(inboundTransport: inbound))
    }

    private func stageInboundWelcome(_ welcome: SignedGroupWelcomeV2) async throws {
        var inbound = record.inboundTransport
        if inbound.epochStaging.welcomes.contains(welcome) { return }
        var retainedWelcomes = inbound.epochStaging.welcomes.filter {
            $0.epoch > record.signedState.epoch
        }
        if retainedWelcomes.count >= GroupInboundEpochStagingV2.maximumArtifacts,
           inbound.epochStaging.transitions.contains(where: {
               $0.nextState.epoch == welcome.epoch
                   && $0.nextState.commitDigest == welcome.commitDigest
           }),
           let eviction = retainedWelcomes.firstIndex(where: { candidate in
               !inbound.epochStaging.transitions.contains(where: {
                   $0.nextState.epoch == candidate.epoch
                       && $0.nextState.commitDigest == candidate.commitDigest
               })
           }) {
            retainedWelcomes.remove(at: eviction)
        }
        guard !inbound.epochStaging.welcomes.contains(where: {
            $0.id == welcome.id && $0 != welcome
        }), retainedWelcomes.count < GroupInboundEpochStagingV2.maximumArtifacts else {
            throw GroupRuntimeError.conflictingCommitQuarantined
        }
        let staging = try GroupInboundEpochStagingV2(
            transitions: inbound.epochStaging.transitions,
            welcomes: retainedWelcomes + [welcome]
        )
        inbound = inbound.replacing(epochStaging: staging)
        try await persist(record.replacing(inboundTransport: inbound))
    }

    private func convergeInboundEpochStaging(observedAt: Date) async throws {
        while !record.inboundTransport.epochStaging.transitions.isEmpty {
            let localHandles = Set(
                [record.localCredential.credentialHandle]
                    + record.pendingLocalCredentials.map(\.credentialHandle)
            )
            let staging = record.inboundTransport.epochStaging
            let ready = staging.transitions.lazy.compactMap { transition -> (
                GroupEpochTransitionEnvelopeV2,
                SignedGroupWelcomeV2?
            )? in
                let destination = transition.nextState.activeCredentials.first {
                    localHandles.contains($0.credentialHandle)
                }
                guard let destination else { return (transition, nil) }
                guard let welcome = staging.welcomes.first(where: {
                    $0.epoch == transition.nextState.epoch
                        && $0.commitDigest == transition.nextState.commitDigest
                        && $0.destinationCredentialHandle == destination.credentialHandle
                }) else { return nil }
                return (transition, welcome)
            }.first
            guard let (transition, welcome) = ready else {
                return
            }
            do {
                _ = try await processPeerEpoch(
                    transition,
                    welcome: welcome,
                    observedAt: observedAt
                )
            } catch {
                // Deterministically invalid staged artifacts must not pin the
                // head of this bounded queue forever. The caller retains and
                // quarantines the triggering relay bundle; retryable local
                // failures leave staging intact for restart recovery.
                if inboundEnvelopeQuarantineReason(for: error) != nil {
                    try await discardInboundEpochCandidate(
                        transition: transition,
                        matchingWelcome: welcome
                    )
                }
                throw error
            }
            var inbound = record.inboundTransport
            let updatedStaging = try GroupInboundEpochStagingV2(
                transitions: inbound.epochStaging.transitions.filter {
                    $0 != transition && $0.nextState.epoch > record.signedState.epoch
                },
                welcomes: inbound.epochStaging.welcomes.filter { candidate in
                    candidate != welcome
                        && candidate.epoch > record.signedState.epoch
                }
            )
            inbound = inbound.replacing(epochStaging: updatedStaging)
            try await persist(record.replacing(inboundTransport: inbound))
        }
    }

    private func discardInboundEpochCandidate(
        transition: GroupEpochTransitionEnvelopeV2,
        matchingWelcome: SignedGroupWelcomeV2?
    ) async throws {
        let inbound = record.inboundTransport
        let staging = try GroupInboundEpochStagingV2(
            transitions: inbound.epochStaging.transitions.filter { $0 != transition },
            welcomes: inbound.epochStaging.welcomes.filter { candidate in
                candidate != matchingWelcome
                    && !(candidate.epoch == transition.nextState.epoch
                        && candidate.commitDigest == transition.nextState.commitDigest)
            }
        )
        try await persist(record.replacing(
            inboundTransport: inbound.replacing(epochStaging: staging)
        ))
    }

    private func removePendingInboundBundle(_ bundleID: OpaqueRouteBundleIDV2) async throws {
        let inbound = record.inboundTransport
        try await persist(record.replacing(
            inboundTransport: inbound.replacing(
                pendingBundles: inbound.pendingBundles.filter { $0.bundleID != bundleID }
            )
        ))
    }

    private func quarantinePendingInboundBundle(
        _ pending: PendingGroupInboundBundleV2,
        reason: TransportQuarantineReasonV2,
        at date: Date
    ) async throws {
        var inbound = record.inboundTransport
        var streamMaterial = Data("org.noctweave.group.opaque-route.stream/v2".utf8)
        streamMaterial.append(0)
        streamMaterial.append(pending.routeID.rawValue)
        let envelopeID = try? NoctweaveCoder.decode(
            ProtocolEnvelopeV1.self,
            from: pending.payload
        ).id
        let receipt = QuarantinedTransportEnvelopeV2(
            streamDigest: Data(SHA256.hash(data: streamMaterial)),
            relaySequence: pending.source.relaySequence,
            packetID: pending.source.packetID,
            recordDigest: pending.source.recordDigest,
            reason: reason,
            observedAt: date,
            innerEnvelopeID: envelopeID
        )
        var quarantines = inbound.quarantines
        if !quarantines.contains(where: { $0.packetID == receipt.packetID }) {
            quarantines.append(receipt)
            quarantines = Array(quarantines.suffix(
                NoctweaveArchitectureV2.maximumQuarantinedTransportEnvelopes
            ))
        }
        inbound = inbound.replacing(
            pendingBundles: inbound.pendingBundles.filter { $0.id != pending.id },
            quarantines: quarantines
        )
        try await persist(record.replacing(inboundTransport: inbound))
    }

    private func appendInboundQuarantine(
        reason: TransportQuarantineReasonV2,
        receivedPacket: OpaqueRouteReceivedPacketV2,
        routeID: OpaqueReceiveRouteIDV2,
        innerEnvelopeID: UUID?,
        observedAt: Date,
        to existing: [QuarantinedTransportEnvelopeV2]
    ) -> [QuarantinedTransportEnvelopeV2] {
        var streamMaterial = Data("org.noctweave.group.opaque-route.stream/v2".utf8)
        streamMaterial.append(0)
        streamMaterial.append(routeID.rawValue)
        let receipt = QuarantinedTransportEnvelopeV2(
            streamDigest: Data(SHA256.hash(data: streamMaterial)),
            relaySequence: receivedPacket.sequence,
            packetID: receivedPacket.packet.packetID,
            recordDigest: receivedPacket.recordDigest,
            reason: reason,
            observedAt: observedAt,
            innerEnvelopeID: innerEnvelopeID
        )
        guard !existing.contains(where: { $0.packetID == receipt.packetID }) else {
            return existing
        }
        return Array((existing + [receipt]).suffix(
            NoctweaveArchitectureV2.maximumQuarantinedTransportEnvelopes
        ))
    }

    private func inboundQuarantineReason(for error: Error) -> TransportQuarantineReasonV2? {
        guard let error = error as? OpaqueRoutePacketV2Error else { return nil }
        switch error {
        case .malformedFrame, .invalidPacket, .invalidBundle, .invalidIdentifier:
            return .malformedPacket
        case .decryptionFailed, .bundleDigestMismatch:
            return .invalidCiphertext
        case .packetIdentifierConflict, .bundleConflict, .fragmentConflict:
            return .replayConflict
        case .emptyPayload, .payloadTooLarge, .fragmentCountExceeded:
            return .unsupportedPayload
        case .invalidPayloadKey, .reassemblyCapacityExceeded:
            return nil
        }
    }

    private func inboundEnvelopeQuarantineReason(
        for error: Error
    ) -> TransportQuarantineReasonV2? {
        if error is DecodingError { return .invalidEnvelope }
        if let error = error as? GroupOpaqueRouteInboundV2Error,
           error == .unsupportedEnvelope {
            return .incompatibleProtocol
        }
        if let error = error as? GroupRouteSetAnnouncementV2Error {
            return error == .invalidSignature ? .invalidAttribution : .invalidEnvelope
        }
        if let error = error as? GroupRuntimeError {
            switch error {
            case .conflictingCommitQuarantined,
                    .conflictingApplicationEnvelope,
                    .conflictingClientTransaction,
                    .invalidPeerEpoch,
                    .staleEpoch,
                    .missingWelcome,
                    .invalidDeletion,
                    .groupDeleted,
                    .conflictingDeletionQuarantined,
                    .localCredentialRemoved:
                return .invalidEnvelope
            case .invalidRecord, .missingRecord, .invalidIntent, .unknownIntent,
                    .pendingEpoch, .incompleteFanout, .unsupportedContentType,
                    .publicationNotFound, .capacityReached, .unsolicitedJoin:
                return nil
            }
        }
        if let error = error as? CryptoError {
            switch error {
            case .invalidSignature: return .invalidAttribution
            case .invalidPayload, .counterOutOfOrder, .counterReplay,
                    .counterWindowExceeded: return .invalidEnvelope
            case .invalidPublicKey, .invalidPrivateKey, .algorithmUnavailable,
                    .operationFailed: return nil
            }
        }
        return nil
    }
}

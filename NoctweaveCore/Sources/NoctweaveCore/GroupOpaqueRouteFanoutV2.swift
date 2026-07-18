import Foundation

public enum GroupOpaqueRouteFanoutV2Error: Error, Equatable {
    case invalidEnvelope
    case invalidDestination
    case noUsableRoute
    case invalidPlan
}

/// Local transport mapping for one group-scoped credential. The route must be
/// obtained through a group-authorized exchange; this object never maps the
/// credential back to a persona, account, device, or pairwise relationship.
public struct GroupOpaqueRouteDestinationV2: Equatable {
    public let credentialHandle: GroupScopedCredentialHandleV2
    public let routes: [OpaqueSendRouteV2]

    public init(
        credentialHandle: GroupScopedCredentialHandleV2,
        routes: [OpaqueSendRouteV2]
    ) {
        self.credentialHandle = credentialHandle
        self.routes = routes
    }
}

/// Exact packet artifacts for one group envelope copy to one opaque route.
/// Persisting this value makes transport retries byte-for-byte idempotent.
public struct GroupOpaqueRoutePublicationV2: Codable, Equatable, Identifiable {
    public static let version = 2

    public let version: Int
    public let id: UUID
    public let groupID: UUID
    public let protocolEnvelopeID: UUID
    public let destinationCredentialHandle: GroupScopedCredentialHandleV2
    public let destinationRouteID: OpaqueReceiveRouteIDV2
    public let destinationRelay: RelayEndpoint
    public let sendCapability: RouteSendCapabilityV2
    public let bundleID: OpaqueRouteBundleIDV2
    public let packets: [OpaqueRoutePacketV2]
    public let createdAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case groupID
        case protocolEnvelopeID
        case destinationCredentialHandle
        case destinationRouteID
        case destinationRelay
        case sendCapability
        case bundleID
        case packets
        case createdAt
    }

    public init(
        id: UUID = UUID(),
        groupID: UUID,
        protocolEnvelopeID: UUID,
        destinationCredentialHandle: GroupScopedCredentialHandleV2,
        destinationRelay: RelayEndpoint,
        sendCapability: RouteSendCapabilityV2,
        sealedBundle: OpaqueRouteSealedBundleV2,
        createdAt: Date
    ) throws {
        guard let routeID = sealedBundle.packets.first?.routeID else {
            throw GroupOpaqueRouteFanoutV2Error.invalidPlan
        }
        version = Self.version
        self.id = id
        self.groupID = groupID
        self.protocolEnvelopeID = protocolEnvelopeID
        self.destinationCredentialHandle = destinationCredentialHandle
        destinationRouteID = routeID
        self.destinationRelay = destinationRelay
        self.sendCapability = sendCapability
        bundleID = sealedBundle.bundleID
        packets = sealedBundle.packets
        self.createdAt = createdAt
        guard isStructurallyValid else {
            throw GroupOpaqueRouteFanoutV2Error.invalidPlan
        }
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: GroupOpaqueRouteFanoutCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Group opaque publication fields must match exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        version = try values.decode(Int.self, forKey: .version)
        id = try values.decode(UUID.self, forKey: .id)
        groupID = try values.decode(UUID.self, forKey: .groupID)
        protocolEnvelopeID = try values.decode(UUID.self, forKey: .protocolEnvelopeID)
        destinationCredentialHandle = try values.decode(
            GroupScopedCredentialHandleV2.self,
            forKey: .destinationCredentialHandle
        )
        destinationRouteID = try values.decode(
            OpaqueReceiveRouteIDV2.self,
            forKey: .destinationRouteID
        )
        destinationRelay = try values.decode(RelayEndpoint.self, forKey: .destinationRelay)
        sendCapability = try values.decode(
            RouteSendCapabilityV2.self,
            forKey: .sendCapability
        )
        bundleID = try values.decode(OpaqueRouteBundleIDV2.self, forKey: .bundleID)
        packets = try values.decode([OpaqueRoutePacketV2].self, forKey: .packets)
        createdAt = try values.decode(Date.self, forKey: .createdAt)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .packets,
                in: values,
                debugDescription: "Invalid group opaque publication"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid group opaque publication"
                )
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(id, forKey: .id)
        try values.encode(groupID, forKey: .groupID)
        try values.encode(protocolEnvelopeID, forKey: .protocolEnvelopeID)
        try values.encode(destinationCredentialHandle, forKey: .destinationCredentialHandle)
        try values.encode(destinationRouteID, forKey: .destinationRouteID)
        try values.encode(destinationRelay, forKey: .destinationRelay)
        try values.encode(sendCapability, forKey: .sendCapability)
        try values.encode(bundleID, forKey: .bundleID)
        try values.encode(packets, forKey: .packets)
        try values.encode(createdAt, forKey: .createdAt)
    }

    public var isStructurallyValid: Bool {
        version == Self.version
            && destinationCredentialHandle.isStructurallyValid
            && destinationRouteID.isStructurallyValid
            && destinationRelay.isStructurallyValidRelationshipRouteEndpointV2
            && destinationRelay.isConfidentialCapabilityTransportV2
            && sendCapability.isStructurallyValid
            && bundleID.isStructurallyValid
            && !packets.isEmpty
            && packets.count <= NoctweaveOpaqueRoutePacketsV2.maximumFragmentCount
            && Set(packets.map(\.packetID)).count == packets.count
            && packets.allSatisfy {
                $0.routeID == destinationRouteID && $0.isStructurallyValid
            }
            && createdAt.timeIntervalSince1970.isFinite
    }
}

public struct GroupOpaqueRouteFanoutPlanV2: Codable, Equatable {
    public static let version = 2

    public let version: Int
    public let groupID: UUID
    public let protocolEnvelopeID: UUID
    public let publications: [GroupOpaqueRoutePublicationV2]
    public let createdAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case groupID
        case protocolEnvelopeID
        case publications
        case createdAt
    }

    private init(
        version: Int = Self.version,
        groupID: UUID,
        protocolEnvelopeID: UUID,
        publications: [GroupOpaqueRoutePublicationV2],
        createdAt: Date
    ) {
        self.version = version
        self.groupID = groupID
        self.protocolEnvelopeID = protocolEnvelopeID
        self.publications = publications.sorted(by: Self.publicationOrdering)
        self.createdAt = createdAt
    }

    public static func create(
        envelope: ProtocolEnvelopeV1,
        groupID: UUID,
        destinations: [GroupOpaqueRouteDestinationV2],
        at date: Date = Date()
    ) throws -> GroupOpaqueRouteFanoutPlanV2 {
        guard envelope.isStructurallyValid,
              envelope.groupIDForOpaqueFanout == groupID,
              date.timeIntervalSince1970.isFinite,
              !destinations.isEmpty,
              Set(destinations.map(\.credentialHandle)).count == destinations.count,
              destinations.count
                <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials else {
            throw GroupOpaqueRouteFanoutV2Error.invalidDestination
        }
        let encoded = try NoctweaveCoder.encode(envelope, sortedKeys: true)
        var publications: [GroupOpaqueRoutePublicationV2] = []
        for destination in destinations {
            guard destination.credentialHandle.isStructurallyValid else {
                throw GroupOpaqueRouteFanoutV2Error.invalidDestination
            }
            let usable = destination.routes.filter { $0.isUsable(at: date) }
            guard !usable.isEmpty,
                  usable.count <= NoctweaveArchitectureV2.maximumRoutes,
                  Set(usable.map(\.routeID)).count == usable.count else {
                throw GroupOpaqueRouteFanoutV2Error.noUsableRoute
            }
            for route in usable {
                let sealed = try OpaqueRouteSealedBundleV2.seal(
                    encoded,
                    to: route,
                    authorizedAt: date
                )
                publications.append(try GroupOpaqueRoutePublicationV2(
                    groupID: groupID,
                    protocolEnvelopeID: envelope.id,
                    destinationCredentialHandle: destination.credentialHandle,
                    destinationRelay: route.relay,
                    sendCapability: route.sendCapability,
                    sealedBundle: sealed,
                    createdAt: date
                ))
            }
        }
        let plan = GroupOpaqueRouteFanoutPlanV2(
            groupID: groupID,
            protocolEnvelopeID: envelope.id,
            publications: publications,
            createdAt: date
        )
        guard plan.isStructurallyValid else {
            throw GroupOpaqueRouteFanoutV2Error.invalidPlan
        }
        return plan
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: GroupOpaqueRouteFanoutCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Group fanout plan fields must match exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let decodedPublications = try values.decode(
            [GroupOpaqueRoutePublicationV2].self,
            forKey: .publications
        )
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            groupID: try values.decode(UUID.self, forKey: .groupID),
            protocolEnvelopeID: try values.decode(UUID.self, forKey: .protocolEnvelopeID),
            publications: decodedPublications,
            createdAt: try values.decode(Date.self, forKey: .createdAt)
        )
        guard publications == decodedPublications, isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .publications,
                in: values,
                debugDescription: "Invalid group fanout plan"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid group fanout plan")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(groupID, forKey: .groupID)
        try values.encode(protocolEnvelopeID, forKey: .protocolEnvelopeID)
        try values.encode(publications, forKey: .publications)
        try values.encode(createdAt, forKey: .createdAt)
    }

    public var isStructurallyValid: Bool {
        let destinations = Set(publications.map(\.destinationCredentialHandle))
        return version == Self.version
            && !publications.isEmpty
            && destinations.count
                <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials
            && publications == publications.sorted(by: Self.publicationOrdering)
            && Set(publications.map(\.id)).count == publications.count
            && Set(publications.map(\.bundleID)).count == publications.count
            && publications.allSatisfy {
                $0.groupID == groupID
                    && $0.protocolEnvelopeID == protocolEnvelopeID
                    && $0.createdAt == createdAt
                    && $0.isStructurallyValid
            }
            && createdAt.timeIntervalSince1970.isFinite
    }

    private static func publicationOrdering(
        _ lhs: GroupOpaqueRoutePublicationV2,
        _ rhs: GroupOpaqueRoutePublicationV2
    ) -> Bool {
        if lhs.destinationCredentialHandle.rawValue
            != rhs.destinationCredentialHandle.rawValue {
            return lhs.destinationCredentialHandle.rawValue
                < rhs.destinationCredentialHandle.rawValue
        }
        return lhs.destinationRouteID.rawValue.lexicographicallyPrecedes(
            rhs.destinationRouteID.rawValue
        )
    }
}

private extension ProtocolEnvelopeV1 {
    var groupIDForOpaqueFanout: UUID? {
        switch self {
        case .groupApplicationV2(let envelope): return envelope.groupId
        case .groupCommitV2(let commit): return commit.groupId
        case .groupWelcomeV2(let welcome): return welcome.groupId
        case .groupDeletionV2(let deletion): return deletion.groupId
        case .directV4: return nil
        }
    }
}

private struct GroupOpaqueRouteFanoutCodingKey: CodingKey {
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

import Foundation

public enum PersonaProfileV1Error: Error, Equatable {
    case invalidState
    case relationshipCapacityReached
    case groupCapacityReached
    case groupAdmissionCapacityReached
}

/// A persona is local presentation and storage organization only. It has no
/// public key, inbox, relay, recovery authority, provider account, or network
/// identifier. Every relationship and group underneath it owns independent
/// cryptographic material.
public struct PersonaProfileV1: Codable, Equatable, Identifiable {
    public static let version = 1
    public static let maximumRelationships = 4_096
    public static let maximumGroupRuntimes = 256
    public static let maximumPendingGroupAdmissions = 32

    public let version: Int
    public let id: UUID
    public var displayName: String
    public internal(set) var relationships: [PairwiseRelationshipV2]
    public internal(set) var groupRuntimes: [GroupRuntimeRecord]
    public internal(set) var pendingGroupAdmissions: [PendingGroupAdmissionV2]
    public let createdAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case displayName
        case relationships
        case groupRuntimes
        case pendingGroupAdmissions
        case createdAt
    }

    public init(
        id: UUID = UUID(),
        displayName: String,
        createdAt: Date = Date()
    ) throws {
        self.version = Self.version
        self.id = id
        self.displayName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        self.relationships = []
        self.groupRuntimes = []
        self.pendingGroupAdmissions = []
        self.createdAt = createdAt
        guard try isStructurallyValidThrowing else {
            throw PersonaProfileV1Error.invalidState
        }
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: PersonaProfileCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Persona fields must match the current protocol exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        id = try container.decode(UUID.self, forKey: .id)
        displayName = try container.decode(String.self, forKey: .displayName)
        relationships = try container.decode(
            [PairwiseRelationshipV2].self,
            forKey: .relationships
        )
        groupRuntimes = try container.decode([GroupRuntimeRecord].self, forKey: .groupRuntimes)
        pendingGroupAdmissions = try container.decode(
            [PendingGroupAdmissionV2].self,
            forKey: .pendingGroupAdmissions
        )
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        guard try isStructurallyValidThrowing else {
            throw DecodingError.dataCorruptedError(
                forKey: .relationships,
                in: container,
                debugDescription: "Persona is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Persona is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(id, forKey: .id)
        try container.encode(displayName, forKey: .displayName)
        try container.encode(relationships, forKey: .relationships)
        try container.encode(groupRuntimes, forKey: .groupRuntimes)
        try container.encode(pendingGroupAdmissions, forKey: .pendingGroupAdmissions)
        try container.encode(createdAt, forKey: .createdAt)
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            for relationship in relationships {
                guard try relationship.isStructurallyValidThrowing else { return false }
            }
            for groupRuntime in groupRuntimes {
                guard try groupRuntime.isStructurallyValidThrowing else { return false }
            }
            for admission in pendingGroupAdmissions {
                guard try admission.isStructurallyValidThrowing else { return false }
            }
            return hasValidAggregateStructureAfterRelationshipPreflight
        }
    }

    private var hasValidAggregateStructureAfterRelationshipPreflight: Bool {
        let normalizedName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard version == Self.version,
              !normalizedName.isEmpty,
              normalizedName == displayName,
              normalizedName.utf8.count <= 512,
              relationships.count <= Self.maximumRelationships,
              Set(relationships.map(\.id)).count == relationships.count,
              groupRuntimes.count <= Self.maximumGroupRuntimes,
              Set(groupRuntimes.map(\.groupId)).count == groupRuntimes.count,
              pendingGroupAdmissions.count <= Self.maximumPendingGroupAdmissions,
              Set(pendingGroupAdmissions.map(\.id)).count == pendingGroupAdmissions.count,
              Set(pendingGroupAdmissions.map(\.groupID)).count
                == pendingGroupAdmissions.count,
              Set(groupRuntimes.map(\.groupId)).isDisjoint(
                with: Set(pendingGroupAdmissions.map(\.groupID))
              ),
              protocolScopesAreUnique(
                  relationships: relationships,
                  groupRuntimes: groupRuntimes,
                  pendingGroupAdmissions: pendingGroupAdmissions
              ),
              createdAt.timeIntervalSince1970.isFinite else {
            return false
        }
        return true
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    public mutating func upsert(
        relationship: PairwiseRelationshipV2
    ) throws {
        guard try relationship.isStructurallyValidThrowing else {
            throw PersonaProfileV1Error.invalidState
        }
        var updated = relationships
        if let index = updated.firstIndex(where: { $0.id == relationship.id }) {
            updated[index] = relationship
        } else {
            guard updated.count < Self.maximumRelationships else {
                throw PersonaProfileV1Error.relationshipCapacityReached
            }
            updated.append(relationship)
        }
        guard protocolScopesAreUnique(
            relationships: updated,
            groupRuntimes: groupRuntimes,
            pendingGroupAdmissions: pendingGroupAdmissions
        ) else {
            throw PersonaProfileV1Error.invalidState
        }
        relationships = updated
    }

    public mutating func upsert(groupRuntime: GroupRuntimeRecord) throws {
        guard try groupRuntime.isStructurallyValidThrowing else {
            throw PersonaProfileV1Error.invalidState
        }
        var updated = groupRuntimes
        if let index = updated.firstIndex(where: { $0.groupId == groupRuntime.groupId }) {
            updated[index] = groupRuntime
        } else {
            guard updated.count < Self.maximumGroupRuntimes else {
                throw PersonaProfileV1Error.groupCapacityReached
            }
            updated.append(groupRuntime)
        }
        guard protocolScopesAreUnique(
            relationships: relationships,
            groupRuntimes: updated,
            pendingGroupAdmissions: pendingGroupAdmissions
        ) else {
            throw PersonaProfileV1Error.invalidState
        }
        groupRuntimes = updated
    }

    public mutating func insert(
        pendingGroupAdmission admission: PendingGroupAdmissionV2
    ) throws {
        guard try admission.isStructurallyValidThrowing,
              !pendingGroupAdmissions.contains(where: {
                  $0.id == admission.id || $0.groupID == admission.groupID
              }),
              !groupRuntimes.contains(where: { $0.groupId == admission.groupID }) else {
            throw PersonaProfileV1Error.invalidState
        }
        guard pendingGroupAdmissions.count < Self.maximumPendingGroupAdmissions else {
            throw PersonaProfileV1Error.groupAdmissionCapacityReached
        }
        let updated = pendingGroupAdmissions + [admission]
        guard protocolScopesAreUnique(
            relationships: relationships,
            groupRuntimes: groupRuntimes,
            pendingGroupAdmissions: updated
        ) else {
            throw PersonaProfileV1Error.invalidState
        }
        pendingGroupAdmissions = updated
    }

    public mutating func replace(
        pendingGroupAdmission admission: PendingGroupAdmissionV2
    ) throws {
        guard try admission.isStructurallyValidThrowing,
              let index = pendingGroupAdmissions.firstIndex(where: {
                  $0.id == admission.id && $0.groupID == admission.groupID
              }) else {
            throw PersonaProfileV1Error.invalidState
        }
        var updated = pendingGroupAdmissions
        updated[index] = admission
        guard protocolScopesAreUnique(
            relationships: relationships,
            groupRuntimes: groupRuntimes,
            pendingGroupAdmissions: updated
        ) else {
            throw PersonaProfileV1Error.invalidState
        }
        pendingGroupAdmissions = updated
    }

    @discardableResult
    public mutating func removePendingGroupAdmission(id: UUID) -> PendingGroupAdmissionV2? {
        guard let index = pendingGroupAdmissions.firstIndex(where: { $0.id == id }) else {
            return nil
        }
        return pendingGroupAdmissions.remove(at: index)
    }

}

/// Enforces the core privacy invariant at the persisted aggregate boundary:
/// relationship and group authorities, credentials, endpoints, handles, and
/// routes are never reused, including between separate local personas.
func protocolScopesAreUnique(
    relationships: [PairwiseRelationshipV2],
    groupRuntimes: [GroupRuntimeRecord],
    pendingGroupAdmissions: [PendingGroupAdmissionV2] = []
) -> Bool {
    var scopeIDs = Set<UUID>()
    var signingKeys = Set<Data>()
    var agreementKeys = Set<Data>()
    var opaqueHandles = Set<String>()
    var routeIDs = Set<OpaqueReceiveRouteIDV2>()
    var routePayloadKeys = Set<OpaqueRoutePayloadKeyV2>()
    var admissionDigests = Set<Data>()

    for relationship in relationships {
        let local = relationship.localIdentity
        let peer = relationship.peerIdentity
        guard scopeIDs.insert(relationship.id).inserted,
              scopeIDs.insert(local.id).inserted,
              scopeIDs.insert(peer.id).inserted,
              signingKeys.insert(local.relationshipAuthority.signingKey.publicKeyData).inserted,
              signingKeys.insert(local.localEndpoint.signingKey.publicKeyData).inserted,
              signingKeys.insert(peer.signingPublicKey).inserted,
              signingKeys.insert(peer.endpointBinding.signingPublicKey).inserted,
              agreementKeys.insert(local.relationshipAuthority.agreementKey.publicKeyData).inserted,
              agreementKeys.insert(local.localEndpoint.agreementKey.publicKeyData).inserted,
              agreementKeys.insert(peer.agreementPublicKey).inserted,
              agreementKeys.insert(peer.endpointBinding.agreementPublicKey).inserted,
              opaqueHandles.insert(relationship.localEndpointHandle.rawValue).inserted,
              opaqueHandles.insert(peer.sendRoutes.ownerEndpointHandle.rawValue).inserted else {
            return false
        }

        for route in relationship.localAdvertisedRoutes.routes + peer.sendRoutes.routes {
            guard routeIDs.insert(route.routeID).inserted,
                  routePayloadKeys.insert(route.payloadKey).inserted else {
                return false
            }
        }
    }

    for runtime in groupRuntimes {
        guard scopeIDs.insert(runtime.groupId).inserted else { return false }

        // A runtime may retain the same credential in its accepted state and
        // in one or more recovery intents. Collapse repetitions within this
        // group, then require the resulting scope to be disjoint from every
        // relationship and every other group.
        var memberHandles = Set<String>()
        var credentialHandles = Set<String>()
        var groupSigningKeys = Set<Data>()
        var groupAgreementKeys = Set<Data>()
        var groupAdmissionDigests = Set<Data>()

        func collect(_ state: SignedGroupStateV2) {
            memberHandles.formUnion(state.members.map { $0.id.rawValue })
            credentialHandles.formUnion(
                state.memberCredentials.map { $0.credentialHandle.rawValue }
            )
            groupSigningKeys.formUnion(state.memberCredentials.map(\.signingPublicKey))
            groupAgreementKeys.formUnion(state.memberCredentials.map(\.agreementPublicKey))
            groupAdmissionDigests.formUnion(state.memberCredentials.map(\.admissionDigest))
        }

        collect(runtime.signedState)
        for intent in runtime.epochIntents {
            collect(intent.nextSignedState)
        }
        memberHandles.insert(runtime.localCredential.memberHandle.rawValue)
        credentialHandles.insert(runtime.localCredential.credentialHandle.rawValue)
        groupSigningKeys.insert(runtime.localCredential.signingKey.publicKeyData)
        groupAgreementKeys.insert(runtime.localCredential.agreementKey.publicKeyData)
        groupAdmissionDigests.insert(runtime.localCredential.admissionDigest)

        guard memberHandles.isDisjoint(with: credentialHandles),
              opaqueHandles.isDisjoint(with: memberHandles),
              opaqueHandles.isDisjoint(with: credentialHandles),
              signingKeys.isDisjoint(with: groupSigningKeys),
              agreementKeys.isDisjoint(with: groupAgreementKeys),
              admissionDigests.isDisjoint(with: groupAdmissionDigests) else {
            return false
        }
        opaqueHandles.formUnion(memberHandles)
        opaqueHandles.formUnion(credentialHandles)
        signingKeys.formUnion(groupSigningKeys)
        agreementKeys.formUnion(groupAgreementKeys)
        admissionDigests.formUnion(groupAdmissionDigests)
    }

    for admission in pendingGroupAdmissions {
        guard scopeIDs.insert(admission.groupID).inserted,
              opaqueHandles.insert(admission.localCredential.memberHandle.rawValue).inserted,
              opaqueHandles.insert(admission.localCredential.credentialHandle.rawValue).inserted,
              signingKeys.insert(
                  admission.localCredential.signingKey.publicKeyData
              ).inserted,
              agreementKeys.insert(
                  admission.localCredential.agreementKey.publicKeyData
              ).inserted,
              admissionDigests.insert(admission.localCredential.admissionDigest).inserted else {
            return false
        }
        let routes = [admission.pendingRoute?.clientCapabilities.routeID]
            .compactMap { $0 }
            + [admission.activeRoute?.id].compactMap { $0 }
        let payloadKeys = [admission.pendingRoute?.payloadKey]
            .compactMap { $0 }
            + [admission.activeRoute?.localRoute.payloadKey].compactMap { $0 }
        guard Set(routes).count == routes.count,
              Set(payloadKeys).count == payloadKeys.count,
              routeIDs.isDisjoint(with: Set(routes)),
              routePayloadKeys.isDisjoint(with: Set(payloadKeys)) else {
            return false
        }
        routeIDs.formUnion(routes)
        routePayloadKeys.formUnion(payloadKeys)
    }
    return true
}

private struct PersonaProfileCodingKey: CodingKey {
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

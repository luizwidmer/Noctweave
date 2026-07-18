import Foundation

public enum PersonaProfileV1Error: Error, Equatable {
    case invalidState
    case relationshipCapacityReached
    case groupCapacityReached
}

/// A persona is local presentation and storage organization only. It has no
/// public key, inbox, relay, recovery authority, provider account, or network
/// identifier. Every relationship and group underneath it owns independent
/// cryptographic material.
public struct PersonaProfileV1: Codable, Equatable, Identifiable {
    public static let version = 1
    public static let maximumRelationships = 4_096
    public static let maximumGroupRuntimes = 256

    public let version: Int
    public let id: UUID
    public var displayName: String
    public var relationships: [PairwiseRelationshipV2]
    public var groupRuntimes: [GroupRuntimeRecord]
    public let createdAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case displayName
        case relationships
        case groupRuntimes
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
        self.createdAt = createdAt
        guard isStructurallyValid else { throw PersonaProfileV1Error.invalidState }
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
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .relationships,
                in: container,
                debugDescription: "Persona is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
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
        try container.encode(createdAt, forKey: .createdAt)
    }

    public var isStructurallyValid: Bool {
        let normalizedName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard version == Self.version,
              !normalizedName.isEmpty,
              normalizedName == displayName,
              normalizedName.utf8.count <= 512,
              relationships.count <= Self.maximumRelationships,
              Set(relationships.map(\.id)).count == relationships.count,
              relationships.allSatisfy(\.isStructurallyValid),
              groupRuntimes.count <= Self.maximumGroupRuntimes,
              Set(groupRuntimes.map(\.groupId)).count == groupRuntimes.count,
              groupRuntimes.allSatisfy(\.isStructurallyValid),
              createdAt.timeIntervalSince1970.isFinite else {
            return false
        }
        return true
    }

    public mutating func upsert(
        relationship: PairwiseRelationshipV2
    ) throws {
        guard relationship.isStructurallyValid else {
            throw PersonaProfileV1Error.invalidState
        }
        if let index = relationships.firstIndex(where: { $0.id == relationship.id }) {
            relationships[index] = relationship
            return
        }
        guard relationships.count < Self.maximumRelationships else {
            throw PersonaProfileV1Error.relationshipCapacityReached
        }
        relationships.append(relationship)
    }

    public mutating func upsert(groupRuntime: GroupRuntimeRecord) throws {
        guard groupRuntime.isStructurallyValid else {
            throw PersonaProfileV1Error.invalidState
        }
        if let index = groupRuntimes.firstIndex(where: { $0.groupId == groupRuntime.groupId }) {
            groupRuntimes[index] = groupRuntime
            return
        }
        guard groupRuntimes.count < Self.maximumGroupRuntimes else {
            throw PersonaProfileV1Error.groupCapacityReached
        }
        groupRuntimes.append(groupRuntime)
    }

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

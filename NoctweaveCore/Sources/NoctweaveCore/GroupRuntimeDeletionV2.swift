import CryptoKit
import Foundation

private struct StrictGroupRuntimeDeletionCodingKey: CodingKey {
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

private func requireExactGroupRuntimeDeletionKeys<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ keyType: Key.Type
) throws where Key.AllCases: Collection {
    let strict = try decoder.container(keyedBy: StrictGroupRuntimeDeletionCodingKey.self)
    guard Set(strict.allKeys.map(\.stringValue))
            == Set(keyType.allCases.map(\.stringValue)) else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "Group deletion fields must match the current schema exactly"
            )
        )
    }
}

private func exactGroupDeletionArtifactDigest<T: Encodable>(_ value: T) -> Data? {
    guard let bytes = try? NoctweaveCoder.encode(value, sortedKeys: true) else {
        return nil
    }
    return Data(SHA256.hash(data: bytes))
}

public enum GroupDeletionOriginV2: String, Codable, Equatable {
    case local
    case peer
}

public enum GroupDeletionPublicationStateV2: String, Codable, Equatable {
    case pending
    case published
    case notApplicable
}

public enum GroupDeletionConflictKindV2: String, Codable, Equatable {
    case conflictingDeletion
    case resurrectionTransition
    case resurrectionCommit
}

/// Digest-only terminal conflict evidence. Full resurrection or conflicting
/// deletion artifacts are never retained in durable state.
public struct GroupDeletionConflictEvidenceV2: Codable, Equatable {
    public let groupId: UUID
    public let terminalEpoch: UInt64
    public let kind: GroupDeletionConflictKindV2
    public let artifactDigest: Data
    public let observedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case groupId
        case terminalEpoch
        case kind
        case artifactDigest
        case observedAt
    }

    public init(
        groupId: UUID,
        terminalEpoch: UInt64,
        kind: GroupDeletionConflictKindV2,
        artifactDigest: Data,
        observedAt: Date
    ) {
        self.groupId = groupId
        self.terminalEpoch = terminalEpoch
        self.kind = kind
        self.artifactDigest = artifactDigest
        self.observedAt = observedAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupRuntimeDeletionKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            groupId: try values.decode(UUID.self, forKey: .groupId),
            terminalEpoch: try values.decode(UInt64.self, forKey: .terminalEpoch),
            kind: try values.decode(GroupDeletionConflictKindV2.self, forKey: .kind),
            artifactDigest: try values.decode(Data.self, forKey: .artifactDigest),
            observedAt: try values.decode(Date.self, forKey: .observedAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group deletion conflict evidence")
            )
        }
    }

    public var isStructurallyValid: Bool {
        terminalEpoch > 1
            && artifactDigest.count == SHA256.byteCount
            && observedAt.timeIntervalSince1970.isFinite
    }
}

/// Durable terminal runtime state. The accepted signed deleted state retains
/// the exact tombstone. For a local deletion that same artifact is the outbox
/// until publication is explicitly completed.
public struct GroupRuntimeDeletionStateV2: Codable, Equatable {
    public static let version = 2
    public static let maximumConflictEvidence = 64

    public let version: Int
    public let deletedState: SignedDeletedGroupStateV2
    public let tombstoneArtifactDigest: Data
    public let origin: GroupDeletionOriginV2
    public let publicationState: GroupDeletionPublicationStateV2
    public let conflictEvidence: [GroupDeletionConflictEvidenceV2]
    public let updatedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case deletedState
        case tombstoneArtifactDigest
        case origin
        case publicationState
        case conflictEvidence
        case updatedAt
    }

    public init(
        version: Int = Self.version,
        deletedState: SignedDeletedGroupStateV2,
        origin: GroupDeletionOriginV2,
        publicationState: GroupDeletionPublicationStateV2,
        conflictEvidence: [GroupDeletionConflictEvidenceV2] = [],
        updatedAt: Date
    ) throws {
        guard let artifactDigest = exactGroupDeletionArtifactDigest(
            deletedState.tombstone
        ) else {
            throw GroupRuntimeError.invalidDeletion
        }
        self.init(
            version: version,
            deletedState: deletedState,
            tombstoneArtifactDigest: artifactDigest,
            origin: origin,
            publicationState: publicationState,
            conflictEvidence: conflictEvidence,
            updatedAt: updatedAt
        )
        guard isStructurallyValid else { throw GroupRuntimeError.invalidDeletion }
    }

    private init(
        version: Int,
        deletedState: SignedDeletedGroupStateV2,
        tombstoneArtifactDigest: Data,
        origin: GroupDeletionOriginV2,
        publicationState: GroupDeletionPublicationStateV2,
        conflictEvidence: [GroupDeletionConflictEvidenceV2],
        updatedAt: Date
    ) {
        self.version = version
        self.deletedState = deletedState
        self.tombstoneArtifactDigest = tombstoneArtifactDigest
        self.origin = origin
        self.publicationState = publicationState
        self.conflictEvidence = conflictEvidence
        self.updatedAt = updatedAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupRuntimeDeletionKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            deletedState: try values.decode(SignedDeletedGroupStateV2.self, forKey: .deletedState),
            tombstoneArtifactDigest: try values.decode(Data.self, forKey: .tombstoneArtifactDigest),
            origin: try values.decode(GroupDeletionOriginV2.self, forKey: .origin),
            publicationState: try values.decode(
                GroupDeletionPublicationStateV2.self,
                forKey: .publicationState
            ),
            conflictEvidence: try values.decode(
                [GroupDeletionConflictEvidenceV2].self,
                forKey: .conflictEvidence
            ),
            updatedAt: try values.decode(Date.self, forKey: .updatedAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid terminal group deletion state")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid terminal group deletion state")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(deletedState, forKey: .deletedState)
        try values.encode(tombstoneArtifactDigest, forKey: .tombstoneArtifactDigest)
        try values.encode(origin, forKey: .origin)
        try values.encode(publicationState, forKey: .publicationState)
        try values.encode(conflictEvidence, forKey: .conflictEvidence)
        try values.encode(updatedAt, forKey: .updatedAt)
    }

    public var isStructurallyValid: Bool {
        guard version == Self.version,
              deletedState.isStructurallyValid,
              tombstoneArtifactDigest.count == SHA256.byteCount,
              tombstoneArtifactDigest == exactGroupDeletionArtifactDigest(
                  deletedState.tombstone
              ),
              conflictEvidence.count <= Self.maximumConflictEvidence,
              Set(conflictEvidence.map {
                  "\($0.kind.rawValue):\($0.artifactDigest.base64EncodedString())"
              }).count == conflictEvidence.count,
              conflictEvidence.allSatisfy({
                  $0.isStructurallyValid
                      && $0.groupId == deletedState.tombstone.groupId
                      && $0.terminalEpoch == deletedState.tombstone.deletedEpoch
              }),
              updatedAt.timeIntervalSince1970.isFinite,
              updatedAt >= deletedState.observedAt else {
            return false
        }
        switch (origin, publicationState) {
        case (.local, .pending), (.local, .published), (.peer, .notApplicable):
            return true
        default:
            return false
        }
    }

    public func markingPublished(at date: Date) throws -> GroupRuntimeDeletionStateV2 {
        guard origin == .local,
              publicationState == .pending || publicationState == .published,
              date.timeIntervalSince1970.isFinite,
              date >= updatedAt else {
            throw GroupRuntimeError.invalidDeletion
        }
        if publicationState == .published { return self }
        return try GroupRuntimeDeletionStateV2(
            deletedState: deletedState,
            origin: origin,
            publicationState: .published,
            conflictEvidence: conflictEvidence,
            updatedAt: date
        )
    }

    public func retainingConflict(
        kind: GroupDeletionConflictKindV2,
        artifactDigest: Data,
        observedAt: Date
    ) throws -> GroupRuntimeDeletionStateV2 {
        guard artifactDigest.count == SHA256.byteCount,
              observedAt.timeIntervalSince1970.isFinite else {
            throw GroupRuntimeError.invalidDeletion
        }
        if conflictEvidence.contains(where: {
            $0.kind == kind && $0.artifactDigest == artifactDigest
        }) {
            return self
        }
        let evidence = GroupDeletionConflictEvidenceV2(
            groupId: deletedState.tombstone.groupId,
            terminalEpoch: deletedState.tombstone.deletedEpoch,
            kind: kind,
            artifactDigest: artifactDigest,
            observedAt: observedAt
        )
        let retained = Array(
            (conflictEvidence + [evidence]).suffix(Self.maximumConflictEvidence)
        )
        return try GroupRuntimeDeletionStateV2(
            deletedState: deletedState,
            origin: origin,
            publicationState: publicationState,
            conflictEvidence: retained,
            updatedAt: max(updatedAt, observedAt)
        )
    }
}

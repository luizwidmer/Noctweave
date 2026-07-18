import CryptoKit
import Foundation

private struct StrictGroupPeerEpochCodingKey: CodingKey {
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

private func requireExactGroupPeerEpochKeys<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ keyType: Key.Type
) throws where Key.AllCases: Collection {
    let strict = try decoder.container(keyedBy: StrictGroupPeerEpochCodingKey.self)
    guard Set(strict.allKeys.map(\.stringValue))
            == Set(keyType.allCases.map(\.stringValue)) else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "Peer epoch fields must match the current schema exactly"
            )
        )
    }
}

private func exactGroupArtifactDigest<T: Encodable>(_ artifact: T) -> Data? {
    guard let bytes = try? NoctweaveCoder.encode(artifact, sortedKeys: true) else {
        return nil
    }
    return Data(SHA256.hash(data: bytes))
}

private func peerEpochArtifactDigest(
    transitionDigest: Data,
    welcomeDigest: Data?
) -> Data {
    var bytes = Data("noctweave/group-peer-epoch-artifact/v2".utf8)
    bytes.append(transitionDigest)
    bytes.append(welcomeDigest == nil ? 0 : 1)
    if let welcomeDigest { bytes.append(welcomeDigest) }
    return Data(SHA256.hash(data: bytes))
}

public enum GroupPeerEpochOutcomeV2: String, Codable, Equatable {
    case active
    case localRemoved
}

/// Durable receiver observation. Digests cover the exact signed wire
/// artifacts, including signatures, rather than only their signable bodies.
public struct GroupPeerEpochJournalEntryV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let groupId: UUID
    public let baseEpoch: UInt64
    public let nextEpoch: UInt64
    public let transitionDigest: Data
    public let commitArtifactDigest: Data
    public let stateArtifactDigest: Data
    public let providerCommitDigest: Data
    public let welcomeArtifactDigest: Data?
    public let outcome: GroupPeerEpochOutcomeV2
    public let observedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case groupId
        case baseEpoch
        case nextEpoch
        case transitionDigest
        case commitArtifactDigest
        case stateArtifactDigest
        case providerCommitDigest
        case welcomeArtifactDigest
        case outcome
        case observedAt
    }

    public init(
        id: UUID = UUID(),
        transition: GroupEpochTransitionEnvelopeV2,
        welcome: SignedGroupWelcomeV2?,
        outcome: GroupPeerEpochOutcomeV2,
        observedAt: Date
    ) throws {
        guard let transitionDigest = transition.digest,
              let commitDigest = exactGroupArtifactDigest(transition.commit),
              let stateDigest = exactGroupArtifactDigest(transition.nextState) else {
            throw GroupRuntimeError.invalidPeerEpoch
        }
        let welcomeDigest: Data?
        if let welcome {
            guard let digest = exactGroupArtifactDigest(welcome) else {
                throw GroupRuntimeError.invalidPeerEpoch
            }
            welcomeDigest = digest
        } else {
            welcomeDigest = nil
        }
        self.init(
            id: id,
            groupId: transition.commit.groupId,
            baseEpoch: transition.commit.baseEpoch,
            nextEpoch: transition.commit.nextEpoch,
            transitionDigest: transitionDigest,
            commitArtifactDigest: commitDigest,
            stateArtifactDigest: stateDigest,
            providerCommitDigest: transition.commit.providerCommitDigest,
            welcomeArtifactDigest: welcomeDigest,
            outcome: outcome,
            observedAt: observedAt
        )
        guard isStructurallyValid else { throw GroupRuntimeError.invalidPeerEpoch }
    }

    private init(
        id: UUID,
        groupId: UUID,
        baseEpoch: UInt64,
        nextEpoch: UInt64,
        transitionDigest: Data,
        commitArtifactDigest: Data,
        stateArtifactDigest: Data,
        providerCommitDigest: Data,
        welcomeArtifactDigest: Data?,
        outcome: GroupPeerEpochOutcomeV2,
        observedAt: Date
    ) {
        self.id = id
        self.groupId = groupId
        self.baseEpoch = baseEpoch
        self.nextEpoch = nextEpoch
        self.transitionDigest = transitionDigest
        self.commitArtifactDigest = commitArtifactDigest
        self.stateArtifactDigest = stateArtifactDigest
        self.providerCommitDigest = providerCommitDigest
        self.welcomeArtifactDigest = welcomeArtifactDigest
        self.outcome = outcome
        self.observedAt = observedAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupPeerEpochKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try values.decode(UUID.self, forKey: .id),
            groupId: try values.decode(UUID.self, forKey: .groupId),
            baseEpoch: try values.decode(UInt64.self, forKey: .baseEpoch),
            nextEpoch: try values.decode(UInt64.self, forKey: .nextEpoch),
            transitionDigest: try values.decode(Data.self, forKey: .transitionDigest),
            commitArtifactDigest: try values.decode(Data.self, forKey: .commitArtifactDigest),
            stateArtifactDigest: try values.decode(Data.self, forKey: .stateArtifactDigest),
            providerCommitDigest: try values.decode(Data.self, forKey: .providerCommitDigest),
            welcomeArtifactDigest: try values.decodeIfPresent(
                Data.self,
                forKey: .welcomeArtifactDigest
            ),
            outcome: try values.decode(GroupPeerEpochOutcomeV2.self, forKey: .outcome),
            observedAt: try values.decode(Date.self, forKey: .observedAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid peer epoch journal entry")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid peer epoch journal entry")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(id, forKey: .id)
        try values.encode(groupId, forKey: .groupId)
        try values.encode(baseEpoch, forKey: .baseEpoch)
        try values.encode(nextEpoch, forKey: .nextEpoch)
        try values.encode(transitionDigest, forKey: .transitionDigest)
        try values.encode(commitArtifactDigest, forKey: .commitArtifactDigest)
        try values.encode(stateArtifactDigest, forKey: .stateArtifactDigest)
        try values.encode(providerCommitDigest, forKey: .providerCommitDigest)
        try values.encode(welcomeArtifactDigest, forKey: .welcomeArtifactDigest)
        try values.encode(outcome, forKey: .outcome)
        try values.encode(observedAt, forKey: .observedAt)
    }

    public var isStructurallyValid: Bool {
        baseEpoch < UInt64.max
            && nextEpoch == baseEpoch + 1
            && transitionDigest.count == SHA256.byteCount
            && commitArtifactDigest.count == SHA256.byteCount
            && stateArtifactDigest.count == SHA256.byteCount
            && providerCommitDigest.count == SHA256.byteCount
            && (welcomeArtifactDigest == nil
                || welcomeArtifactDigest?.count == SHA256.byteCount)
            && observedAt.timeIntervalSince1970.isFinite
    }

    public var artifactDigest: Data {
        peerEpochArtifactDigest(
            transitionDigest: transitionDigest,
            welcomeDigest: welcomeArtifactDigest
        )
    }

    public func exactlyMatches(
        transition: GroupEpochTransitionEnvelopeV2,
        welcome: SignedGroupWelcomeV2?
    ) -> Bool {
        let suppliedWelcomeDigest = welcome.flatMap(exactGroupArtifactDigest)
        guard welcome == nil || suppliedWelcomeDigest != nil else { return false }
        return groupId == transition.commit.groupId
            && baseEpoch == transition.commit.baseEpoch
            && nextEpoch == transition.commit.nextEpoch
            && transitionDigest == transition.digest
            && commitArtifactDigest == exactGroupArtifactDigest(transition.commit)
            && stateArtifactDigest == exactGroupArtifactDigest(transition.nextState)
            && providerCommitDigest == transition.commit.providerCommitDigest
            && welcomeArtifactDigest == suppliedWelcomeDigest
    }
}

public struct GroupPeerEpochForkQuarantineV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let groupId: UUID
    public let baseEpoch: UInt64
    public let acceptedArtifactDigest: Data
    public let conflictingArtifactDigest: Data
    public let transitionDigest: Data
    public let conflictingWelcomeDigest: Data?
    public let quarantinedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case groupId
        case baseEpoch
        case acceptedArtifactDigest
        case conflictingArtifactDigest
        case transitionDigest
        case conflictingWelcomeDigest
        case quarantinedAt
    }

    public init(
        id: UUID = UUID(),
        acceptedArtifactDigest: Data,
        transition: GroupEpochTransitionEnvelopeV2,
        welcome: SignedGroupWelcomeV2?,
        quarantinedAt: Date
    ) throws {
        guard let transitionDigest = transition.digest else {
            throw GroupRuntimeError.invalidPeerEpoch
        }
        let welcomeDigest: Data?
        if let welcome {
            guard let digest = exactGroupArtifactDigest(welcome) else {
                throw GroupRuntimeError.invalidPeerEpoch
            }
            welcomeDigest = digest
        } else {
            welcomeDigest = nil
        }
        self.init(
            id: id,
            groupId: transition.commit.groupId,
            baseEpoch: transition.commit.baseEpoch,
            acceptedArtifactDigest: acceptedArtifactDigest,
            conflictingArtifactDigest: peerEpochArtifactDigest(
                transitionDigest: transitionDigest,
                welcomeDigest: welcomeDigest
            ),
            transitionDigest: transitionDigest,
            conflictingWelcomeDigest: welcomeDigest,
            quarantinedAt: quarantinedAt
        )
        guard isStructurallyValid else { throw GroupRuntimeError.invalidPeerEpoch }
    }

    private init(
        id: UUID,
        groupId: UUID,
        baseEpoch: UInt64,
        acceptedArtifactDigest: Data,
        conflictingArtifactDigest: Data,
        transitionDigest: Data,
        conflictingWelcomeDigest: Data?,
        quarantinedAt: Date
    ) {
        self.id = id
        self.groupId = groupId
        self.baseEpoch = baseEpoch
        self.acceptedArtifactDigest = acceptedArtifactDigest
        self.conflictingArtifactDigest = conflictingArtifactDigest
        self.transitionDigest = transitionDigest
        self.conflictingWelcomeDigest = conflictingWelcomeDigest
        self.quarantinedAt = quarantinedAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupPeerEpochKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try values.decode(UUID.self, forKey: .id),
            groupId: try values.decode(UUID.self, forKey: .groupId),
            baseEpoch: try values.decode(UInt64.self, forKey: .baseEpoch),
            acceptedArtifactDigest: try values.decode(Data.self, forKey: .acceptedArtifactDigest),
            conflictingArtifactDigest: try values.decode(Data.self, forKey: .conflictingArtifactDigest),
            transitionDigest: try values.decode(Data.self, forKey: .transitionDigest),
            conflictingWelcomeDigest: try values.decodeIfPresent(Data.self, forKey: .conflictingWelcomeDigest),
            quarantinedAt: try values.decode(Date.self, forKey: .quarantinedAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid peer epoch fork quarantine")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid peer epoch fork quarantine")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(id, forKey: .id)
        try values.encode(groupId, forKey: .groupId)
        try values.encode(baseEpoch, forKey: .baseEpoch)
        try values.encode(acceptedArtifactDigest, forKey: .acceptedArtifactDigest)
        try values.encode(conflictingArtifactDigest, forKey: .conflictingArtifactDigest)
        try values.encode(transitionDigest, forKey: .transitionDigest)
        try values.encode(conflictingWelcomeDigest, forKey: .conflictingWelcomeDigest)
        try values.encode(quarantinedAt, forKey: .quarantinedAt)
    }

    public var isStructurallyValid: Bool {
        baseEpoch > 0
            && acceptedArtifactDigest.count == SHA256.byteCount
            && conflictingArtifactDigest.count == SHA256.byteCount
            && transitionDigest.count == SHA256.byteCount
            && (conflictingWelcomeDigest == nil
                || conflictingWelcomeDigest?.count == SHA256.byteCount)
            && conflictingArtifactDigest == peerEpochArtifactDigest(
                transitionDigest: transitionDigest,
                welcomeDigest: conflictingWelcomeDigest
            )
            && acceptedArtifactDigest != conflictingArtifactDigest
            && quarantinedAt.timeIntervalSince1970.isFinite
    }
}

/// Terminal local state after the group's accepted state no longer contains a
/// locally owned credential. It is group-scoped and grants no future access.
public struct GroupLocalRemovalStateV2: Codable, Equatable {
    public let groupId: UUID
    public let memberHandle: GroupScopedMemberHandleV2
    public let removedCredentialHandle: GroupScopedCredentialHandleV2
    public let acceptedEpoch: UInt64
    public let transitionDigest: Data
    public let observedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case groupId
        case memberHandle
        case removedCredentialHandle
        case acceptedEpoch
        case transitionDigest
        case observedAt
    }

    public init(
        groupId: UUID,
        memberHandle: GroupScopedMemberHandleV2,
        removedCredentialHandle: GroupScopedCredentialHandleV2,
        acceptedEpoch: UInt64,
        transitionDigest: Data,
        observedAt: Date
    ) {
        self.groupId = groupId
        self.memberHandle = memberHandle
        self.removedCredentialHandle = removedCredentialHandle
        self.acceptedEpoch = acceptedEpoch
        self.transitionDigest = transitionDigest
        self.observedAt = observedAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupPeerEpochKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            groupId: try values.decode(UUID.self, forKey: .groupId),
            memberHandle: try values.decode(GroupScopedMemberHandleV2.self, forKey: .memberHandle),
            removedCredentialHandle: try values.decode(GroupScopedCredentialHandleV2.self, forKey: .removedCredentialHandle),
            acceptedEpoch: try values.decode(UInt64.self, forKey: .acceptedEpoch),
            transitionDigest: try values.decode(Data.self, forKey: .transitionDigest),
            observedAt: try values.decode(Date.self, forKey: .observedAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid local group removal state")
            )
        }
    }

    public var isStructurallyValid: Bool {
        memberHandle.isStructurallyValid
            && removedCredentialHandle.isStructurallyValid
            && acceptedEpoch > 0
            && transitionDigest.count == SHA256.byteCount
            && observedAt.timeIntervalSince1970.isFinite
    }
}

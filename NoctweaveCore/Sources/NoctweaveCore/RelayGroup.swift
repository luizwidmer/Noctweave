import CryptoKit
import Foundation

public enum GroupCreationMode: String, Codable, CaseIterable {
    case disabled
    case allowed
}

public enum GroupSecurityModel: String, Codable, CaseIterable {
    case relayBackedPairwise
    case mlsDerivedTree
}

public enum MLSGroupCommitOperation: String, Codable, CaseIterable {
    case create
    case update
    case addMembers
    case removeMembers
    case selfLeave
    case joinApprove
}

public struct MLSGroupCommitSummary: Codable, Equatable {
    public let operation: MLSGroupCommitOperation
    public let actorFingerprint: String
    public let epoch: UInt64
    public let committedAt: Date
    public let memberFingerprints: [String]
    public let previousTranscriptHash: Data?
    public let transcriptHash: Data
    public let ratchetSecretDistribution: GroupRatchetEpochSecretDistribution?

    public init(
        operation: MLSGroupCommitOperation,
        actorFingerprint: String,
        epoch: UInt64,
        committedAt: Date,
        memberFingerprints: [String],
        previousTranscriptHash: Data?,
        transcriptHash: Data,
        ratchetSecretDistribution: GroupRatchetEpochSecretDistribution? = nil
    ) {
        self.operation = operation
        self.actorFingerprint = actorFingerprint
        self.epoch = epoch
        self.committedAt = committedAt
        self.memberFingerprints = memberFingerprints
        self.previousTranscriptHash = previousTranscriptHash
        self.transcriptHash = transcriptHash
        self.ratchetSecretDistribution = ratchetSecretDistribution
    }
}

public enum MLSGroupEpochHistoryIssue: String, Codable, Equatable, Hashable {
    case emptyHistory
    case duplicateEpoch
    case invalidInitialEpoch
    case nonContiguousEpoch
    case brokenTranscriptLink
    case currentStateMismatch
    case currentCommitMissing
}

public enum MLSGroupEpochHistoryValidator {
    public static func issues(
        currentState: MLSGroupEpochState,
        history: [MLSGroupCommitSummary],
        allowTruncatedHistory: Bool = true
    ) -> [MLSGroupEpochHistoryIssue] {
        guard !history.isEmpty else {
            return [.emptyHistory, .currentCommitMissing]
        }

        var issues = Set<MLSGroupEpochHistoryIssue>()
        let sorted = history.sorted { $0.epoch < $1.epoch }
        if Set(sorted.map(\.epoch)).count != sorted.count {
            issues.insert(.duplicateEpoch)
        }

        if let first = sorted.first {
            if first.epoch == 0 {
                if first.operation != .create || first.previousTranscriptHash != nil {
                    issues.insert(.invalidInitialEpoch)
                }
            } else if !allowTruncatedHistory {
                issues.insert(.invalidInitialEpoch)
            }
        }

        for (previous, current) in zip(sorted, sorted.dropFirst()) {
            if current.epoch != previous.epoch + 1 {
                issues.insert(.nonContiguousEpoch)
            }
            if current.previousTranscriptHash != previous.transcriptHash {
                issues.insert(.brokenTranscriptLink)
            }
        }

        guard let last = sorted.last else {
            return Array(issues).sortedByRawValue()
        }
        if last != currentState.lastCommit {
            issues.insert(.currentCommitMissing)
        }
        if currentState.epoch != currentState.lastCommit.epoch ||
            currentState.confirmedTranscriptHash != currentState.lastCommit.transcriptHash ||
            last.epoch != currentState.epoch ||
            last.transcriptHash != currentState.confirmedTranscriptHash {
            issues.insert(.currentStateMismatch)
        }

        return Array(issues).sortedByRawValue()
    }

    public static func isValid(
        currentState: MLSGroupEpochState,
        history: [MLSGroupCommitSummary],
        allowTruncatedHistory: Bool = true
    ) -> Bool {
        issues(
            currentState: currentState,
            history: history,
            allowTruncatedHistory: allowTruncatedHistory
        ).isEmpty
    }
}

private extension Array where Element == MLSGroupEpochHistoryIssue {
    func sortedByRawValue() -> [MLSGroupEpochHistoryIssue] {
        sorted { $0.rawValue < $1.rawValue }
    }
}

public struct MLSGroupEpochState: Codable, Equatable {
    public static let currentProtocolVersion = "noctyra-mls-v1"
    public static let currentCipherSuite = "Noctyra-MLS-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-v1"

    public let protocolVersion: String
    public let cipherSuite: String
    public let groupId: UUID
    public let epoch: UInt64
    public let treeHash: Data
    public let confirmedTranscriptHash: Data
    public let lastCommit: MLSGroupCommitSummary

    public init(
        protocolVersion: String = MLSGroupEpochState.currentProtocolVersion,
        cipherSuite: String = MLSGroupEpochState.currentCipherSuite,
        groupId: UUID,
        epoch: UInt64,
        treeHash: Data,
        confirmedTranscriptHash: Data,
        lastCommit: MLSGroupCommitSummary
    ) {
        self.protocolVersion = protocolVersion
        self.cipherSuite = cipherSuite
        self.groupId = groupId
        self.epoch = epoch
        self.treeHash = treeHash
        self.confirmedTranscriptHash = confirmedTranscriptHash
        self.lastCommit = lastCommit
    }

    public static func initial(
        groupId: UUID,
        title: String,
        inboxId: String,
        createdByFingerprint: String,
        members: [RelayGroupMember],
        createdAt: Date,
        ratchetSecretDistribution: GroupRatchetEpochSecretDistribution? = nil
    ) -> MLSGroupEpochState {
        make(
            groupId: groupId,
            title: title,
            inboxId: inboxId,
            actorFingerprint: createdByFingerprint,
            members: members,
            epoch: 0,
            previousTranscriptHash: nil,
            operation: .create,
            committedAt: createdAt,
            ratchetSecretDistribution: ratchetSecretDistribution
        )
    }

    public func advancing(
        title: String,
        inboxId: String,
        actorFingerprint: String,
        members: [RelayGroupMember],
        operation: MLSGroupCommitOperation,
        committedAt: Date,
        ratchetSecretDistribution: GroupRatchetEpochSecretDistribution? = nil
    ) -> MLSGroupEpochState {
        MLSGroupEpochState.make(
            groupId: groupId,
            title: title,
            inboxId: inboxId,
            actorFingerprint: actorFingerprint,
            members: members,
            epoch: epoch + 1,
            previousTranscriptHash: confirmedTranscriptHash,
            operation: operation,
            committedAt: committedAt,
            ratchetSecretDistribution: ratchetSecretDistribution
        )
    }

    private static func make(
        groupId: UUID,
        title: String,
        inboxId: String,
        actorFingerprint: String,
        members: [RelayGroupMember],
        epoch: UInt64,
        previousTranscriptHash: Data?,
        operation: MLSGroupCommitOperation,
        committedAt: Date,
        ratchetSecretDistribution: GroupRatchetEpochSecretDistribution?
    ) -> MLSGroupEpochState {
        let memberFingerprints = members.map(\.fingerprint).sorted()
        let treeHash = digest(
            MLSGroupTreeHashPayload(
                groupId: groupId,
                inboxId: inboxId,
                epoch: epoch,
                memberFingerprints: memberFingerprints
            )
        )
        let transcriptHash = digest(
            MLSGroupTranscriptHashPayload(
                protocolVersion: currentProtocolVersion,
                cipherSuite: currentCipherSuite,
                groupId: groupId,
                inboxId: inboxId,
                title: title,
                epoch: epoch,
                operation: operation,
                actorFingerprint: actorFingerprint,
                memberFingerprints: memberFingerprints,
                previousTranscriptHash: previousTranscriptHash,
                treeHash: treeHash,
                committedAt: committedAt
            )
        )
        let commit = MLSGroupCommitSummary(
            operation: operation,
            actorFingerprint: actorFingerprint,
            epoch: epoch,
            committedAt: committedAt,
            memberFingerprints: memberFingerprints,
            previousTranscriptHash: previousTranscriptHash,
            transcriptHash: transcriptHash,
            ratchetSecretDistribution: ratchetSecretDistribution
        )
        return MLSGroupEpochState(
            groupId: groupId,
            epoch: epoch,
            treeHash: treeHash,
            confirmedTranscriptHash: transcriptHash,
            lastCommit: commit
        )
    }

    private static func digest<T: Encodable>(_ value: T) -> Data {
        guard let data = try? NoctweaveCoder.encode(value, sortedKeys: true) else {
            return Data(SHA256.hash(data: Data()))
        }
        return Data(SHA256.hash(data: data))
    }
}

private struct MLSGroupTreeHashPayload: Codable {
    let groupId: UUID
    let inboxId: String
    let epoch: UInt64
    let memberFingerprints: [String]
}

private struct MLSGroupTranscriptHashPayload: Codable {
    let protocolVersion: String
    let cipherSuite: String
    let groupId: UUID
    let inboxId: String
    let title: String
    let epoch: UInt64
    let operation: MLSGroupCommitOperation
    let actorFingerprint: String
    let memberFingerprints: [String]
    let previousTranscriptHash: Data?
    let treeHash: Data
    let committedAt: Date
}

public struct RelayGroupMemberProfile: Codable, Equatable {
    public let fingerprint: String
    public let displayName: String?
    public let inboxId: String?
    public let relay: RelayEndpoint?
    public let signingPublicKey: Data?
    public let agreementPublicKey: Data?

    public init(
        fingerprint: String,
        displayName: String? = nil,
        inboxId: String? = nil,
        relay: RelayEndpoint? = nil,
        signingPublicKey: Data? = nil,
        agreementPublicKey: Data? = nil
    ) {
        self.fingerprint = fingerprint
        self.displayName = displayName
        self.inboxId = inboxId
        self.relay = relay
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
    }
}

public struct RelayGroupMember: Codable, Equatable {
    public let fingerprint: String
    public let joinedAt: Date
    public var displayName: String?
    public var inboxId: String?
    public var relay: RelayEndpoint?
    public var signingPublicKey: Data?
    public var agreementPublicKey: Data?

    public init(
        fingerprint: String,
        joinedAt: Date = Date(),
        displayName: String? = nil,
        inboxId: String? = nil,
        relay: RelayEndpoint? = nil,
        signingPublicKey: Data? = nil,
        agreementPublicKey: Data? = nil
    ) {
        self.fingerprint = fingerprint
        self.joinedAt = joinedAt
        self.displayName = displayName
        self.inboxId = inboxId
        self.relay = relay
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
    }
}

public struct RelayGroupDescriptor: Codable, Equatable, Identifiable {
    public let id: UUID
    public var title: String
    public let inboxId: String
    public let createdByFingerprint: String
    public var epoch: UInt64
    public var members: [RelayGroupMember]
    public var mlsEpochState: MLSGroupEpochState
    public var mlsEpochHistory: [MLSGroupCommitSummary]
    public let createdAt: Date
    public var updatedAt: Date

    public init(
        id: UUID = UUID(),
        title: String,
        inboxId: String = InboxAddress.generate(),
        createdByFingerprint: String,
        epoch: UInt64 = 0,
        members: [RelayGroupMember],
        mlsEpochState: MLSGroupEpochState? = nil,
        mlsEpochHistory: [MLSGroupCommitSummary]? = nil,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.title = title
        self.inboxId = inboxId
        self.createdByFingerprint = createdByFingerprint
        self.epoch = epoch
        self.members = members
        let resolvedEpochState = mlsEpochState ?? MLSGroupEpochState.initial(
            groupId: id,
            title: title,
            inboxId: inboxId,
            createdByFingerprint: createdByFingerprint,
            members: members,
            createdAt: createdAt
        )
        self.mlsEpochState = resolvedEpochState
        self.mlsEpochHistory = mlsEpochHistory ?? [resolvedEpochState.lastCommit]
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case title
        case inboxId
        case createdByFingerprint
        case epoch
        case members
        case mlsEpochState
        case mlsEpochHistory
        case createdAt
        case updatedAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        inboxId = try container.decode(String.self, forKey: .inboxId)
        createdByFingerprint = try container.decode(String.self, forKey: .createdByFingerprint)
        epoch = try container.decode(UInt64.self, forKey: .epoch)
        members = try container.decode([RelayGroupMember].self, forKey: .members)
        mlsEpochState = try container.decode(MLSGroupEpochState.self, forKey: .mlsEpochState)
        mlsEpochHistory = try container.decodeIfPresent([MLSGroupCommitSummary].self, forKey: .mlsEpochHistory)
            ?? [mlsEpochState.lastCommit]
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        updatedAt = try container.decode(Date.self, forKey: .updatedAt)
    }
}

public struct RelayGroupJoinRequest: Codable, Equatable, Identifiable {
    public let id: UUID
    public let groupId: UUID
    public let requester: RelayGroupMemberProfile
    public let invitedFingerprint: String?
    public let requestedAt: Date

    public init(
        id: UUID = UUID(),
        groupId: UUID,
        requester: RelayGroupMemberProfile,
        invitedFingerprint: String? = nil,
        requestedAt: Date = Date()
    ) {
        self.id = id
        self.groupId = groupId
        self.requester = requester
        self.invitedFingerprint = invitedFingerprint
        self.requestedAt = requestedAt
    }
}

public struct RelayGroupInvitation: Codable, Equatable, Identifiable {
    public let id: UUID
    public let groupId: UUID
    public let title: String
    public let createdByFingerprint: String
    public let invitedFingerprint: String
    public let inboxId: String
    public let epoch: UInt64
    public let createdAt: Date
    public let updatedAt: Date
    public let invitedAt: Date

    public init(
        id: UUID = UUID(),
        groupId: UUID,
        title: String,
        createdByFingerprint: String,
        invitedFingerprint: String,
        inboxId: String,
        epoch: UInt64,
        createdAt: Date,
        updatedAt: Date,
        invitedAt: Date = Date()
    ) {
        self.id = id
        self.groupId = groupId
        self.title = title
        self.createdByFingerprint = createdByFingerprint
        self.invitedFingerprint = invitedFingerprint
        self.inboxId = inboxId
        self.epoch = epoch
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.invitedAt = invitedAt
    }
}

public struct RelayActorProof: Codable, Equatable {
    public let fingerprint: String
    public let publicSigningKey: Data
    public let signedAt: Date
    public let nonce: UUID
    public let signature: Data

    public init(
        fingerprint: String,
        publicSigningKey: Data,
        signedAt: Date = Date(),
        nonce: UUID = UUID(),
        signature: Data
    ) {
        self.fingerprint = fingerprint
        self.publicSigningKey = publicSigningKey
        self.signedAt = signedAt
        self.nonce = nonce
        self.signature = signature
    }

    public static func make(
        identity: Identity,
        signableData: Data,
        signedAt: Date = Date(),
        nonce: UUID = UUID()
    ) throws -> RelayActorProof {
        try make(
            signingKey: identity.signingKey,
            signableData: signableData,
            signedAt: signedAt,
            nonce: nonce
        )
    }

    public static func make(
        signingKey: SigningKeyPair,
        signableData: Data,
        signedAt: Date = Date(),
        nonce: UUID = UUID()
    ) throws -> RelayActorProof {
        let signature = try signingKey.sign(signableData)
        return RelayActorProof(
            fingerprint: CryptoBox.fingerprint(for: signingKey.publicKeyData),
            publicSigningKey: signingKey.publicKeyData,
            signedAt: signedAt,
            nonce: nonce,
            signature: signature
        )
    }

    public func isConsistentFingerprint() -> Bool {
        !publicSigningKey.isEmpty
            && fingerprint == CryptoBox.fingerprint(for: publicSigningKey)
    }

    public func verify(signableData: Data) -> Bool {
        guard isConsistentFingerprint() else {
            return false
        }
        return SigningKeyPair.verify(
            signature: signature,
            data: signableData,
            publicKeyData: publicSigningKey
        )
    }
}

public struct CreateGroupRequest: Codable, Equatable {
    public let groupId: UUID?
    public let title: String
    public let creatorFingerprint: String
    public let memberFingerprints: [String]
    public let invitedFingerprints: [String]
    public let creatorProfile: RelayGroupMemberProfile?
    public let memberProfiles: [RelayGroupMemberProfile]?
    public let initialRatchetSecretDistribution: GroupRatchetEpochSecretDistribution?
    public let creatorProof: RelayActorProof?

    public init(
        groupId: UUID? = nil,
        title: String,
        creatorFingerprint: String,
        memberFingerprints: [String],
        invitedFingerprints: [String] = [],
        creatorProfile: RelayGroupMemberProfile? = nil,
        memberProfiles: [RelayGroupMemberProfile]? = nil,
        initialRatchetSecretDistribution: GroupRatchetEpochSecretDistribution? = nil,
        creatorProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.title = title
        self.creatorFingerprint = creatorFingerprint
        self.memberFingerprints = memberFingerprints
        self.invitedFingerprints = invitedFingerprints
        self.creatorProfile = creatorProfile
        self.memberProfiles = memberProfiles
        self.initialRatchetSecretDistribution = initialRatchetSecretDistribution
        self.creatorProof = creatorProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofEncoder.encode(
            CreateGroupProofPayload(
                groupId: groupId,
                title: title,
                creatorFingerprint: creatorFingerprint,
                memberFingerprints: memberFingerprints,
                invitedFingerprints: invitedFingerprints,
                creatorProfile: creatorProfile,
                memberProfiles: memberProfiles,
                initialRatchetSecretDistribution: initialRatchetSecretDistribution,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

public struct RequestGroupJoinRequest: Codable, Equatable {
    public let groupId: UUID
    public let requesterProfile: RelayGroupMemberProfile
    public let invitedFingerprint: String?
    public let groupCommit: SignedGroupCommit?
    public let requesterProof: RelayActorProof?

    public init(
        groupId: UUID,
        requesterProfile: RelayGroupMemberProfile,
        invitedFingerprint: String? = nil,
        groupCommit: SignedGroupCommit? = nil,
        requesterProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.requesterProfile = requesterProfile
        self.invitedFingerprint = invitedFingerprint
        self.groupCommit = groupCommit
        self.requesterProof = requesterProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofEncoder.encode(
            RequestGroupJoinProofPayload(
                groupId: groupId,
                requesterProfile: requesterProfile,
                invitedFingerprint: invitedFingerprint,
                groupCommit: groupCommit,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

public struct ListGroupInvitationsRequest: Codable, Equatable {
    public let invitedFingerprint: String
    public let limit: Int?
    public let invitedProof: RelayActorProof?

    public init(
        invitedFingerprint: String,
        limit: Int? = nil,
        invitedProof: RelayActorProof? = nil
    ) {
        self.invitedFingerprint = invitedFingerprint
        self.limit = limit
        self.invitedProof = invitedProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofEncoder.encode(
            ListGroupInvitationsProofPayload(
                invitedFingerprint: invitedFingerprint,
                limit: limit,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

public struct InviteGroupMembersRequest: Codable, Equatable {
    public let groupId: UUID
    public let actorFingerprint: String
    public let invitedFingerprints: [String]
    public let actorProof: RelayActorProof?

    public init(
        groupId: UUID,
        actorFingerprint: String,
        invitedFingerprints: [String],
        actorProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.actorFingerprint = actorFingerprint
        self.invitedFingerprints = invitedFingerprints
        self.actorProof = actorProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofEncoder.encode(
            InviteGroupMembersProofPayload(
                groupId: groupId,
                actorFingerprint: actorFingerprint,
                invitedFingerprints: invitedFingerprints,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }

    public var normalizedInvitedFingerprints: [String] {
        Array(Set(invitedFingerprints.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty })).sorted()
    }
}

public struct ListGroupJoinRequestsRequest: Codable, Equatable {
    public let groupId: UUID
    public let actorFingerprint: String
    public let limit: Int?
    public let actorProof: RelayActorProof?

    public init(
        groupId: UUID,
        actorFingerprint: String,
        limit: Int? = nil,
        actorProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.actorFingerprint = actorFingerprint
        self.limit = limit
        self.actorProof = actorProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofEncoder.encode(
            ListGroupJoinProofPayload(
                groupId: groupId,
                actorFingerprint: actorFingerprint,
                limit: limit,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

public struct ApproveGroupJoinRequest: Codable, Equatable {
    public let groupId: UUID
    public let actorFingerprint: String
    public let joinRequestId: UUID
    public let groupCommit: SignedGroupCommit
    public let actorProof: RelayActorProof?

    public init(
        groupId: UUID,
        actorFingerprint: String,
        joinRequestId: UUID,
        groupCommit: SignedGroupCommit,
        actorProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.actorFingerprint = actorFingerprint
        self.joinRequestId = joinRequestId
        self.groupCommit = groupCommit
        self.actorProof = actorProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofEncoder.encode(
            ApproveGroupJoinProofPayload(
                groupId: groupId,
                actorFingerprint: actorFingerprint,
                joinRequestId: joinRequestId,
                groupCommit: groupCommit,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

public struct RejectGroupJoinRequest: Codable, Equatable {
    public let groupId: UUID
    public let actorFingerprint: String
    public let joinRequestId: UUID
    public let actorProof: RelayActorProof?

    public init(
        groupId: UUID,
        actorFingerprint: String,
        joinRequestId: UUID,
        actorProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.actorFingerprint = actorFingerprint
        self.joinRequestId = joinRequestId
        self.actorProof = actorProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofEncoder.encode(
            RejectGroupJoinProofPayload(
                groupId: groupId,
                actorFingerprint: actorFingerprint,
                joinRequestId: joinRequestId,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

public struct GetGroupRequest: Codable, Equatable {
    public let groupId: UUID
    public let memberFingerprint: String?
    public let memberProof: RelayActorProof?

    public init(
        groupId: UUID,
        memberFingerprint: String? = nil,
        memberProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.memberFingerprint = memberFingerprint
        self.memberProof = memberProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofEncoder.encode(
            GetGroupProofPayload(
                groupId: groupId,
                memberFingerprint: memberFingerprint,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

public struct ListGroupsRequest: Codable, Equatable {
    public let memberFingerprint: String
    public let limit: Int?
    public let memberProof: RelayActorProof?

    public init(
        memberFingerprint: String,
        limit: Int? = nil,
        memberProof: RelayActorProof? = nil
    ) {
        self.memberFingerprint = memberFingerprint
        self.limit = limit
        self.memberProof = memberProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofEncoder.encode(
            ListGroupsProofPayload(
                memberFingerprint: memberFingerprint,
                limit: limit,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

public struct UpdateGroupRequest: Codable, Equatable {
    public let groupId: UUID
    public let actorFingerprint: String
    public let title: String?
    public let addMemberFingerprints: [String]
    public let addMemberProfiles: [RelayGroupMemberProfile]?
    public let removeMemberFingerprints: [String]
    public let actorProof: RelayActorProof?
    public let groupCommit: SignedGroupCommit?

    public init(
        groupId: UUID,
        actorFingerprint: String,
        title: String? = nil,
        addMemberFingerprints: [String] = [],
        addMemberProfiles: [RelayGroupMemberProfile]? = nil,
        removeMemberFingerprints: [String] = [],
        actorProof: RelayActorProof? = nil,
        groupCommit: SignedGroupCommit? = nil
    ) {
        self.groupId = groupId
        self.actorFingerprint = actorFingerprint
        self.title = title
        self.addMemberFingerprints = addMemberFingerprints
        self.addMemberProfiles = addMemberProfiles
        self.removeMemberFingerprints = removeMemberFingerprints
        self.actorProof = actorProof
        self.groupCommit = groupCommit
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofEncoder.encode(
            UpdateGroupProofPayload(
                groupId: groupId,
                actorFingerprint: actorFingerprint,
                title: title,
                addMemberFingerprints: addMemberFingerprints,
                addMemberProfiles: addMemberProfiles,
                removeMemberFingerprints: removeMemberFingerprints,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }

    public var normalizedTitle: String? {
        guard let title = title?.trimmingCharacters(in: .whitespacesAndNewlines),
              !title.isEmpty else {
            return nil
        }
        return title
    }

    public var normalizedAddMemberFingerprints: [String] {
        Array(Set(addMemberFingerprints.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty })).sorted()
    }

    public var normalizedAddMemberProfiles: [RelayGroupMemberProfile] {
        (addMemberProfiles ?? [])
            .filter { !$0.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            .sorted { $0.fingerprint < $1.fingerprint }
    }

    public var normalizedRemoveMemberFingerprints: [String] {
        Array(Set(removeMemberFingerprints.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty })).sorted()
    }
}

public struct SignedGroupCommit: Codable, Equatable {
    public let operation: MLSGroupCommitOperation
    public let groupId: UUID
    public let actorFingerprint: String
    public let baseEpoch: UInt64
    public let previousTranscriptHash: Data
    public let title: String?
    public let addMemberFingerprints: [String]
    public let addMemberProfiles: [RelayGroupMemberProfile]?
    public let removeMemberFingerprints: [String]
    public let ratchetSecretDistribution: GroupRatchetEpochSecretDistribution?
    public let actorProof: RelayActorProof?

    public init(
        operation: MLSGroupCommitOperation,
        groupId: UUID,
        actorFingerprint: String,
        baseEpoch: UInt64,
        previousTranscriptHash: Data,
        title: String? = nil,
        addMemberFingerprints: [String] = [],
        addMemberProfiles: [RelayGroupMemberProfile]? = nil,
        removeMemberFingerprints: [String] = [],
        ratchetSecretDistribution: GroupRatchetEpochSecretDistribution? = nil,
        actorProof: RelayActorProof? = nil
    ) {
        self.operation = operation
        self.groupId = groupId
        self.actorFingerprint = actorFingerprint
        self.baseEpoch = baseEpoch
        self.previousTranscriptHash = previousTranscriptHash
        self.title = title
        self.addMemberFingerprints = addMemberFingerprints
        self.addMemberProfiles = addMemberProfiles
        self.removeMemberFingerprints = removeMemberFingerprints
        self.ratchetSecretDistribution = ratchetSecretDistribution
        self.actorProof = actorProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofEncoder.encode(
            SignedGroupCommitProofPayload(
                operation: operation,
                groupId: groupId,
                actorFingerprint: actorFingerprint,
                baseEpoch: baseEpoch,
                previousTranscriptHash: previousTranscriptHash,
                title: title,
                addMemberFingerprints: addMemberFingerprints,
                addMemberProfiles: addMemberProfiles,
                removeMemberFingerprints: removeMemberFingerprints,
                ratchetSecretDistribution: ratchetSecretDistribution,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

public struct DeleteGroupRequest: Codable, Equatable {
    public let groupId: UUID
    public let actorFingerprint: String
    public let actorProof: RelayActorProof?

    public init(
        groupId: UUID,
        actorFingerprint: String,
        actorProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.actorFingerprint = actorFingerprint
        self.actorProof = actorProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofEncoder.encode(
            DeleteGroupProofPayload(
                groupId: groupId,
                actorFingerprint: actorFingerprint,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

private enum GroupProofEncoder {
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        try NoctweaveCoder.encode(value, sortedKeys: true)
    }
}

private struct CreateGroupProofPayload: Codable {
    let groupId: UUID?
    let title: String
    let creatorFingerprint: String
    let memberFingerprints: [String]
    let invitedFingerprints: [String]
    let creatorProfile: RelayGroupMemberProfile?
    let memberProfiles: [RelayGroupMemberProfile]?
    let initialRatchetSecretDistribution: GroupRatchetEpochSecretDistribution?
    let signedAt: Date
    let nonce: UUID
}

private struct RequestGroupJoinProofPayload: Codable {
    let groupId: UUID
    let requesterProfile: RelayGroupMemberProfile
    let invitedFingerprint: String?
    let groupCommit: SignedGroupCommit?
    let signedAt: Date
    let nonce: UUID
}

private struct ListGroupInvitationsProofPayload: Codable {
    let invitedFingerprint: String
    let limit: Int?
    let signedAt: Date
    let nonce: UUID
}

private struct InviteGroupMembersProofPayload: Codable {
    let groupId: UUID
    let actorFingerprint: String
    let invitedFingerprints: [String]
    let signedAt: Date
    let nonce: UUID
}

private struct ListGroupJoinProofPayload: Codable {
    let groupId: UUID
    let actorFingerprint: String
    let limit: Int?
    let signedAt: Date
    let nonce: UUID
}

private struct ApproveGroupJoinProofPayload: Codable {
    let groupId: UUID
    let actorFingerprint: String
    let joinRequestId: UUID
    let groupCommit: SignedGroupCommit
    let signedAt: Date
    let nonce: UUID
}

private struct RejectGroupJoinProofPayload: Codable {
    let groupId: UUID
    let actorFingerprint: String
    let joinRequestId: UUID
    let signedAt: Date
    let nonce: UUID
}

private struct UpdateGroupProofPayload: Codable {
    let groupId: UUID
    let actorFingerprint: String
    let title: String?
    let addMemberFingerprints: [String]
    let addMemberProfiles: [RelayGroupMemberProfile]?
    let removeMemberFingerprints: [String]
    let signedAt: Date
    let nonce: UUID
}

private struct SignedGroupCommitProofPayload: Codable {
    let operation: MLSGroupCommitOperation
    let groupId: UUID
    let actorFingerprint: String
    let baseEpoch: UInt64
    let previousTranscriptHash: Data
    let title: String?
    let addMemberFingerprints: [String]
    let addMemberProfiles: [RelayGroupMemberProfile]?
    let removeMemberFingerprints: [String]
    let ratchetSecretDistribution: GroupRatchetEpochSecretDistribution?
    let signedAt: Date
    let nonce: UUID
}

private struct DeleteGroupProofPayload: Codable {
    let groupId: UUID
    let actorFingerprint: String
    let signedAt: Date
    let nonce: UUID
}

private struct ListGroupsProofPayload: Codable {
    let memberFingerprint: String
    let limit: Int?
    let signedAt: Date
    let nonce: UUID
}

private struct GetGroupProofPayload: Codable {
    let groupId: UUID
    let memberFingerprint: String?
    let signedAt: Date
    let nonce: UUID
}

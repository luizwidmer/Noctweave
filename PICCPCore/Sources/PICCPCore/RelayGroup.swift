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

    public init(
        operation: MLSGroupCommitOperation,
        actorFingerprint: String,
        epoch: UInt64,
        committedAt: Date,
        memberFingerprints: [String],
        previousTranscriptHash: Data?,
        transcriptHash: Data
    ) {
        self.operation = operation
        self.actorFingerprint = actorFingerprint
        self.epoch = epoch
        self.committedAt = committedAt
        self.memberFingerprints = memberFingerprints
        self.previousTranscriptHash = previousTranscriptHash
        self.transcriptHash = transcriptHash
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
        createdAt: Date
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
            committedAt: createdAt
        )
    }

    public func advancing(
        title: String,
        inboxId: String,
        actorFingerprint: String,
        members: [RelayGroupMember],
        operation: MLSGroupCommitOperation,
        committedAt: Date
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
            committedAt: committedAt
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
        committedAt: Date
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
            transcriptHash: transcriptHash
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
        guard let data = try? PICCPCoder.encode(value, sortedKeys: true) else {
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
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.title = title
        self.inboxId = inboxId
        self.createdByFingerprint = createdByFingerprint
        self.epoch = epoch
        self.members = members
        self.mlsEpochState = mlsEpochState ?? MLSGroupEpochState.initial(
            groupId: id,
            title: title,
            inboxId: inboxId,
            createdByFingerprint: createdByFingerprint,
            members: members,
            createdAt: createdAt
        )
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

public struct RelayGroupJoinRequest: Codable, Equatable, Identifiable {
    public let id: UUID
    public let groupId: UUID
    public let requester: RelayGroupMemberProfile
    public let requestedAt: Date

    public init(
        id: UUID = UUID(),
        groupId: UUID,
        requester: RelayGroupMemberProfile,
        requestedAt: Date = Date()
    ) {
        self.id = id
        self.groupId = groupId
        self.requester = requester
        self.requestedAt = requestedAt
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
    public let title: String
    public let creatorFingerprint: String
    public let memberFingerprints: [String]
    public let creatorProfile: RelayGroupMemberProfile?
    public let memberProfiles: [RelayGroupMemberProfile]?
    public let creatorProof: RelayActorProof?

    public init(
        title: String,
        creatorFingerprint: String,
        memberFingerprints: [String],
        creatorProfile: RelayGroupMemberProfile? = nil,
        memberProfiles: [RelayGroupMemberProfile]? = nil,
        creatorProof: RelayActorProof? = nil
    ) {
        self.title = title
        self.creatorFingerprint = creatorFingerprint
        self.memberFingerprints = memberFingerprints
        self.creatorProfile = creatorProfile
        self.memberProfiles = memberProfiles
        self.creatorProof = creatorProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofEncoder.encode(
            CreateGroupProofPayload(
                title: title,
                creatorFingerprint: creatorFingerprint,
                memberFingerprints: memberFingerprints,
                creatorProfile: creatorProfile,
                memberProfiles: memberProfiles,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
    }
}

public struct RequestGroupJoinRequest: Codable, Equatable {
    public let groupId: UUID
    public let requesterProfile: RelayGroupMemberProfile
    public let requesterProof: RelayActorProof?

    public init(
        groupId: UUID,
        requesterProfile: RelayGroupMemberProfile,
        requesterProof: RelayActorProof? = nil
    ) {
        self.groupId = groupId
        self.requesterProfile = requesterProfile
        self.requesterProof = requesterProof
    }

    public func signableData(for proof: RelayActorProof) throws -> Data {
        try GroupProofEncoder.encode(
            RequestGroupJoinProofPayload(
                groupId: groupId,
                requesterProfile: requesterProfile,
                signedAt: proof.signedAt,
                nonce: proof.nonce
            )
        )
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
            ApproveGroupJoinProofPayload(
                groupId: groupId,
                actorFingerprint: actorFingerprint,
                joinRequestId: joinRequestId,
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
        try PICCPCoder.encode(value, sortedKeys: true)
    }
}

private struct CreateGroupProofPayload: Codable {
    let title: String
    let creatorFingerprint: String
    let memberFingerprints: [String]
    let creatorProfile: RelayGroupMemberProfile?
    let memberProfiles: [RelayGroupMemberProfile]?
    let signedAt: Date
    let nonce: UUID
}

private struct RequestGroupJoinProofPayload: Codable {
    let groupId: UUID
    let requesterProfile: RelayGroupMemberProfile
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

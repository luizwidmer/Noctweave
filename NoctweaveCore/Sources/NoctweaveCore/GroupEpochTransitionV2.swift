import CryptoKit
import Foundation

private struct StrictGroupEpochTransitionCodingKey: CodingKey {
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

private func requireExactGroupEpochTransitionKeys<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ keyType: Key.Type
) throws where Key.AllCases: Collection {
    let strict = try decoder.container(keyedBy: StrictGroupEpochTransitionCodingKey.self)
    guard Set(strict.allKeys.map(\.stringValue))
            == Set(keyType.allCases.map(\.stringValue)) else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "Group epoch artifact fields must match the current schema exactly"
            )
        )
    }
}

/// Complete author-produced epoch artifact. Relays route it opaquely; clients
/// verify the signed policy transition, the separately signed next state, and
/// the experimental provider commit before changing local state.
public struct GroupEpochTransitionEnvelopeV2: Codable, Equatable, Identifiable {
    public static let version = 2

    public var id: UUID { commit.id }
    public let version: Int
    public let commit: SignedGroupCommitV2
    public let nextState: SignedGroupStateV2
    public let providerCommitBytes: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case commit
        case nextState
        case providerCommitBytes
    }

    public init(
        version: Int = Self.version,
        commit: SignedGroupCommitV2,
        nextState: SignedGroupStateV2,
        providerCommitBytes: Data
    ) {
        self.version = version
        self.commit = commit
        self.nextState = nextState
        self.providerCommitBytes = providerCommitBytes
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupEpochTransitionKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            commit: try values.decode(SignedGroupCommitV2.self, forKey: .commit),
            nextState: try values.decode(SignedGroupStateV2.self, forKey: .nextState),
            providerCommitBytes: try values.decode(Data.self, forKey: .providerCommitBytes)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group epoch transition")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid group epoch transition")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(commit, forKey: .commit)
        try values.encode(nextState, forKey: .nextState)
        try values.encode(providerCommitBytes, forKey: .providerCommitBytes)
    }

    public var isStructurallyValid: Bool {
        guard version == Self.version,
              commit.isStructurallyValid,
              nextState.isStructurallyValid,
              !providerCommitBytes.isEmpty,
              providerCommitBytes.count <= NoctweaveGroupArchitectureV2.maximumCommitBytes,
              Data(SHA256.hash(data: providerCommitBytes)) == commit.providerCommitDigest,
              let commitDigest = commit.digest else {
            return false
        }
        return nextState.profile == commit.profile
            && nextState.cipherSuite == commit.cipherSuite
            && nextState.groupId == commit.groupId
            && nextState.epoch == commit.nextEpoch
            && nextState.previousTranscriptHash == commit.previousTranscriptHash
            && nextState.members == commit.proposedMembers
            && nextState.memberCredentials == commit.proposedCredentials
            && nextState.permissions == commit.proposedPermissions
            && nextState.metadataDigest == commit.proposedMetadataDigest
            && nextState.authorCredentialHandle == commit.authorCredentialHandle
            && nextState.commitDigest == commitDigest
            && nextState.signedAt == commit.createdAt
    }

    public var digest: Data? {
        guard isStructurallyValid,
              let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else {
            return nil
        }
        return Data(SHA256.hash(data: encoded))
    }
}

/// Explicit one-use group-only trust input delivered inside an already
/// encrypted invitation channel. A self-consistent Welcome is not sufficient:
/// callers must pin this base state and destination credential before join.
public struct GroupJoinAnchorV2: Codable, Equatable, Identifiable {
    public static let version = 2

    public let id: UUID
    public let version: Int
    public let baseState: SignedGroupStateV2
    public let baseStateDigest: Data
    public let destinationMemberHandle: GroupScopedMemberHandleV2
    public let destinationCredentialHandle: GroupScopedCredentialHandleV2
    public let destinationAdmissionDigest: Data
    public let issuedAt: Date
    public let expiresAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case version
        case baseState
        case baseStateDigest
        case destinationMemberHandle
        case destinationCredentialHandle
        case destinationAdmissionDigest
        case issuedAt
        case expiresAt
    }

    public init(
        id: UUID = UUID(),
        version: Int = Self.version,
        baseState: SignedGroupStateV2,
        destinationMemberHandle: GroupScopedMemberHandleV2,
        destinationCredentialHandle: GroupScopedCredentialHandleV2,
        destinationAdmissionDigest: Data,
        issuedAt: Date,
        expiresAt: Date
    ) throws {
        self.id = id
        self.version = version
        self.baseState = baseState
        self.baseStateDigest = Data(SHA256.hash(
            data: try NoctweaveCoder.encode(baseState, sortedKeys: true)
        ))
        self.destinationMemberHandle = destinationMemberHandle
        self.destinationCredentialHandle = destinationCredentialHandle
        self.destinationAdmissionDigest = destinationAdmissionDigest
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        guard isStructurallyValid else { throw SignedGroupV2Error.invalidStructure }
    }

    private init(
        id: UUID,
        version: Int,
        baseState: SignedGroupStateV2,
        baseStateDigest: Data,
        destinationMemberHandle: GroupScopedMemberHandleV2,
        destinationCredentialHandle: GroupScopedCredentialHandleV2,
        destinationAdmissionDigest: Data,
        issuedAt: Date,
        expiresAt: Date
    ) {
        self.id = id
        self.version = version
        self.baseState = baseState
        self.baseStateDigest = baseStateDigest
        self.destinationMemberHandle = destinationMemberHandle
        self.destinationCredentialHandle = destinationCredentialHandle
        self.destinationAdmissionDigest = destinationAdmissionDigest
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupEpochTransitionKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try values.decode(UUID.self, forKey: .id),
            version: try values.decode(Int.self, forKey: .version),
            baseState: try values.decode(SignedGroupStateV2.self, forKey: .baseState),
            baseStateDigest: try values.decode(Data.self, forKey: .baseStateDigest),
            destinationMemberHandle: try values.decode(
                GroupScopedMemberHandleV2.self,
                forKey: .destinationMemberHandle
            ),
            destinationCredentialHandle: try values.decode(
                GroupScopedCredentialHandleV2.self,
                forKey: .destinationCredentialHandle
            ),
            destinationAdmissionDigest: try values.decode(
                Data.self,
                forKey: .destinationAdmissionDigest
            ),
            issuedAt: try values.decode(Date.self, forKey: .issuedAt),
            expiresAt: try values.decode(Date.self, forKey: .expiresAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group join anchor")
            )
        }
    }

    public var isStructurallyValid: Bool {
        guard version == Self.version,
              baseState.isStructurallyValid,
              baseStateDigest.count == SHA256.byteCount,
              destinationMemberHandle.isStructurallyValid,
              destinationCredentialHandle.isStructurallyValid,
              destinationAdmissionDigest.count == SHA256.byteCount,
              issuedAt.timeIntervalSince1970.isFinite,
              expiresAt.timeIntervalSince1970.isFinite,
              expiresAt > issuedAt,
              expiresAt.timeIntervalSince(issuedAt)
                <= NoctweaveSignedGroupV2.maximumWelcomeLifetimeSeconds,
              let encoded = try? NoctweaveCoder.encode(baseState, sortedKeys: true) else {
            return false
        }
        return Data(SHA256.hash(data: encoded)) == baseStateDigest
    }
}

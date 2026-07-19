import CryptoKit
import Foundation

private struct StrictSignedGroupCodingKey: CodingKey, Hashable {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}

private func requireExactSignedGroupKeys(
    _ decoder: Decoder,
    required: Set<String>,
    optional: Set<String> = []
) throws {
    let strict = try decoder.container(keyedBy: StrictSignedGroupCodingKey.self)
    let actual = Set(strict.allKeys.map(\.stringValue))
    guard required.isSubset(of: actual), actual.isSubset(of: required.union(optional)) else {
        throw DecodingError.dataCorrupted(
            .init(codingPath: decoder.codingPath, debugDescription: "Unexpected group control schema")
        )
    }
}

/// Signed-state foundations for group-scoped membership and credentials.
public enum NoctweaveSignedGroupV2 {
    public static let version = 2
    public static let experimentalProfile = GroupProtocolProfile.noctweavePQExperimentalV2
    public static let experimentalCipherSuite =
        "Noctweave-PQ-Group-Experimental-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-2"
    public static let maximumAdmissionBytes = 64 * 1_024
    public static let maximumStateBytes = 8 * 1_024 * 1_024
    public static let maximumWelcomeLifetimeSeconds: TimeInterval = 7 * 24 * 60 * 60
    public static let maximumAdmissionLifetimeSeconds: TimeInterval = 30 * 24 * 60 * 60
    public static let maximumClockSkewSeconds: TimeInterval = 5 * 60
    public static let signatureBytes = 3_309
}

public enum SignedGroupV2Error: Error, Equatable {
    case invalidStructure
    case unsupportedProfile
    case invalidContext
    case invalidCredentialSignature
    case invalidStateSignature
    case invalidCommitSignature
    case staleEpoch
    case transcriptMismatch
    case unknownAuthor
    case unauthorized
    case invalidTransition
    case wouldRemoveLastOwner
    case activeLeafLimitExceeded
    case admissionMismatch
    case invalidWelcomeSignature
    case invalidTimestamp
    case genesisAdmissionRequired
    case groupDeleted
}

private func requireGroupCredentialAlgorithms(
    signingPublicKey: Data,
    agreementPublicKey: Data
) throws {
    try GroupCryptographicRuntimeProbeV2.requireAlgorithms(
        signingPublicKey: signingPublicKey,
        agreementPublicKey: agreementPublicKey
    )
}

private func requireGroupCredentialAlgorithms(
    _ credentials: [GroupMemberCredentialV2]
) throws {
    try GroupCryptographicRuntimeProbeV2.requireAlgorithms(
        signingPublicKey: credentials.first?.signingPublicKey ?? Data(),
        agreementPublicKey: credentials.first?.agreementPublicKey ?? Data()
    )
}

private func requireGroupCredentialAlgorithms(
    _ admission: GroupCredentialAdmissionV2
) throws {
    try requireGroupCredentialAlgorithms(
        signingPublicKey: admission.groupSigningPublicKey,
        agreementPublicKey: admission.groupAgreementPublicKey
    )
}

/// An opaque credential handle generated independently for exactly one group.
public struct GroupScopedCredentialHandleV2: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case rawValue
    }

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    /// Generates a handle without any external identifier as input.
    public static func generate() -> GroupScopedCredentialHandleV2 {
        var generator = SystemRandomNumberGenerator()
        while true {
            let bytes = Data((0..<32).map { _ in
                UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
            })
            if bytes.contains(where: { $0 != 0 }) {
                return GroupScopedCredentialHandleV2(rawValue: bytes.base64EncodedString())
            }
        }
    }

    public var isStructurallyValid: Bool {
        guard let decoded = Data(base64Encoded: rawValue), decoded.count == 32 else {
            return false
        }
        return decoded.base64EncodedString() == rawValue
    }

    public init(from decoder: Decoder) throws {
        try requireExactSignedGroupKeys(
            decoder,
            required: Set(CodingKeys.allCases.map(\.rawValue))
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(rawValue: try values.decode(String.self, forKey: .rawValue))
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawValue,
                in: values,
                debugDescription: "Invalid group-scoped credential handle"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid group-scoped credential handle"
                )
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(rawValue, forKey: .rawValue)
    }
}

/// Self-authenticating, group-only admission material for one fresh credential.
public struct GroupCredentialAdmissionV2: Codable, Equatable, Identifiable {
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case version
        case groupId
        case memberHandle
        case credentialHandle
        case selection
        case groupSigningPublicKey
        case groupAgreementPublicKey
        case contentTypes
        case issuedAt
        case expiresAt
        case credentialPossessionSignature
    }

    public let id: UUID
    public let version: Int
    public let groupId: UUID
    public let memberHandle: GroupScopedMemberHandleV2
    public let credentialHandle: GroupScopedCredentialHandleV2
    public let selection: GroupProtocolSelectionV2
    public let groupSigningPublicKey: Data
    public let groupAgreementPublicKey: Data
    public let contentTypes: [ContentTypeCapabilityV2]
    public let issuedAt: Date
    public let expiresAt: Date
    public let credentialPossessionSignature: Data

    public init(
        id: UUID,
        version: Int = NoctweaveSignedGroupV2.version,
        groupId: UUID,
        memberHandle: GroupScopedMemberHandleV2,
        credentialHandle: GroupScopedCredentialHandleV2,
        selection: GroupProtocolSelectionV2,
        groupSigningPublicKey: Data,
        groupAgreementPublicKey: Data,
        contentTypes: [ContentTypeCapabilityV2] = ProtocolCapabilityManifest.defaultContentTypes,
        issuedAt: Date,
        expiresAt: Date,
        credentialPossessionSignature: Data
    ) {
        self.id = id
        self.version = version
        self.groupId = groupId
        self.memberHandle = memberHandle
        self.credentialHandle = credentialHandle
        self.selection = selection
        self.groupSigningPublicKey = groupSigningPublicKey
        self.groupAgreementPublicKey = groupAgreementPublicKey
        self.contentTypes = contentTypes.sorted {
            ($0.authority, $0.name) < ($1.authority, $1.name)
        }
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.credentialPossessionSignature = credentialPossessionSignature
    }

    public init(from decoder: Decoder) throws {
        try requireExactSignedGroupKeys(
            decoder,
            required: Set(CodingKeys.allCases.map(\.rawValue))
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let decodedContentTypes = try values.decode(
            [ContentTypeCapabilityV2].self,
            forKey: .contentTypes
        )
        self.init(
            id: try values.decode(UUID.self, forKey: .id),
            version: try values.decode(Int.self, forKey: .version),
            groupId: try values.decode(UUID.self, forKey: .groupId),
            memberHandle: try values.decode(GroupScopedMemberHandleV2.self, forKey: .memberHandle),
            credentialHandle: try values.decode(GroupScopedCredentialHandleV2.self, forKey: .credentialHandle),
            selection: try values.decode(GroupProtocolSelectionV2.self, forKey: .selection),
            groupSigningPublicKey: try values.decode(Data.self, forKey: .groupSigningPublicKey),
            groupAgreementPublicKey: try values.decode(Data.self, forKey: .groupAgreementPublicKey),
            contentTypes: decodedContentTypes,
            issuedAt: try values.decode(Date.self, forKey: .issuedAt),
            expiresAt: try values.decode(Date.self, forKey: .expiresAt),
            credentialPossessionSignature: try values.decode(Data.self, forKey: .credentialPossessionSignature)
        )
        try requireGroupCredentialAlgorithms(self)
        guard contentTypes == decodedContentTypes, isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group admission")
            )
        }
    }

    public static func create(
        id: UUID = UUID(),
        groupId: UUID,
        memberHandle: GroupScopedMemberHandleV2,
        credentialHandle: GroupScopedCredentialHandleV2 = .generate(),
        selection: GroupProtocolSelectionV2 = .currentExperimental,
        groupSigningKey: SigningKeyPair,
        groupAgreementKey: AgreementKeyPair,
        contentTypes: [ContentTypeCapabilityV2] = ProtocolCapabilityManifest.defaultContentTypes,
        issuedAt: Date = Date(),
        expiresAt: Date
    ) throws -> GroupCredentialAdmissionV2 {
        try requireGroupCredentialAlgorithms(
            signingPublicKey: groupSigningKey.publicKeyData,
            agreementPublicKey: groupAgreementKey.publicKeyData
        )
        var projection = GroupCredentialAdmissionV2(
            id: id,
            groupId: groupId,
            memberHandle: memberHandle,
            credentialHandle: credentialHandle,
            selection: selection,
            groupSigningPublicKey: groupSigningKey.publicKeyData,
            groupAgreementPublicKey: groupAgreementKey.publicKeyData,
            contentTypes: contentTypes,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            credentialPossessionSignature: Data()
        )
        guard projection.isStructurallyValid(excludingSignature: true),
              let digest = projection.payloadDigest else {
            throw SignedGroupV2Error.invalidStructure
        }
        projection = GroupCredentialAdmissionV2(
            id: projection.id,
            groupId: projection.groupId,
            memberHandle: projection.memberHandle,
            credentialHandle: projection.credentialHandle,
            selection: projection.selection,
            groupSigningPublicKey: projection.groupSigningPublicKey,
            groupAgreementPublicKey: projection.groupAgreementPublicKey,
            contentTypes: projection.contentTypes,
            issuedAt: projection.issuedAt,
            expiresAt: projection.expiresAt,
            credentialPossessionSignature: try groupSigningKey.sign(
                try GroupAdmissionProjectionSignatureContextV2(
                    groupId: groupId,
                    memberHandle: memberHandle,
                    credentialHandle: credentialHandle,
                    payloadDigest: digest
                ).signableData()
            )
        )
        return try projection.verified(
            forGroupId: groupId,
            memberHandle: memberHandle,
            selection: selection,
            now: issuedAt
        )
    }

    public var digest: Data? {
        guard isStructurallyValid,
              let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else {
            return nil
        }
        return Data(SHA256.hash(data: encoded))
    }

    public var isStructurallyValid: Bool {
        isStructurallyValid(excludingSignature: false)
    }

    public func verified(
        forGroupId expectedGroupId: UUID,
        memberHandle expectedMemberHandle: GroupScopedMemberHandleV2,
        selection expectedSelection: GroupProtocolSelectionV2,
        now: Date = Date()
    ) throws -> GroupCredentialAdmissionV2 {
        try requireGroupCredentialAlgorithms(self)
        guard isStructurallyValid else { throw SignedGroupV2Error.invalidStructure }
        guard groupId == expectedGroupId,
              memberHandle == expectedMemberHandle,
              selection == expectedSelection else {
            throw SignedGroupV2Error.invalidContext
        }
        guard now.timeIntervalSince1970.isFinite,
              issuedAt <= now.addingTimeInterval(NoctweaveSignedGroupV2.maximumClockSkewSeconds),
              now < expiresAt,
              let digest = payloadDigest,
              try SigningKeyPair.verifyThrowing(
                  signature: credentialPossessionSignature,
                  data: try GroupAdmissionProjectionSignatureContextV2(
                      groupId: groupId,
                      memberHandle: memberHandle,
                      credentialHandle: credentialHandle,
                      payloadDigest: digest
                  ).signableData(),
                  publicKeyData: groupSigningPublicKey
              ) else {
            throw SignedGroupV2Error.invalidCredentialSignature
        }
        return self
    }

    fileprivate var payloadDigest: Data? {
        try? SignedGroupV2Hash.digest(payload)
    }

    fileprivate var payload: GroupCredentialAdmissionPayloadV2 {
        GroupCredentialAdmissionPayloadV2(
            version: version,
            id: id,
            groupId: groupId,
            memberHandle: memberHandle,
            credentialHandle: credentialHandle,
            selection: selection,
            groupSigningPublicKey: groupSigningPublicKey,
            groupAgreementPublicKey: groupAgreementPublicKey,
            contentTypes: contentTypes,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
    }

    private func isStructurallyValid(excludingSignature: Bool) -> Bool {
        version == NoctweaveSignedGroupV2.version
            && memberHandle.isStructurallyValid
            && credentialHandle.isStructurallyValid
            && selection.isStructurallyValid
            && selection == .currentExperimental
            && SigningKeyPair.isValidPublicKey(groupSigningPublicKey)
            && AgreementKeyPair.isValidPublicKey(groupAgreementPublicKey)
            && !contentTypes.isEmpty
            && contentTypes.count
                <= NoctweaveArchitectureV2.maximumContentTypeCapabilities
            && Set(contentTypes.map { "\($0.authority)\u{0}\($0.name)" }).count
                == contentTypes.count
            && contentTypes.allSatisfy(\.isStructurallyValid)
            && contentTypes.contains {
                $0.authority == ContentTypeId.text.authority
                    && $0.name == ContentTypeId.text.name
            }
            && issuedAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && expiresAt > issuedAt
            && expiresAt.timeIntervalSince(issuedAt)
                <= NoctweaveSignedGroupV2.maximumAdmissionLifetimeSeconds
            && (excludingSignature
                || credentialPossessionSignature.count == NoctweaveSignedGroupV2.signatureBytes)
    }
}

public struct GroupMemberCredentialV2: Codable, Equatable, Identifiable {
    public var id: GroupScopedCredentialHandleV2 { credentialHandle }
    public let memberHandle: GroupScopedMemberHandleV2
    public let credentialHandle: GroupScopedCredentialHandleV2
    public let admissionDigest: Data
    public let signingPublicKey: Data
    public let agreementPublicKey: Data
    public let contentTypes: [ContentTypeCapabilityV2]
    public let addedEpoch: UInt64
    public let removedEpoch: UInt64?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case memberHandle
        case credentialHandle
        case admissionDigest
        case signingPublicKey
        case agreementPublicKey
        case contentTypes
        case addedEpoch
        case removedEpoch
    }

    public init(
        memberHandle: GroupScopedMemberHandleV2,
        credentialHandle: GroupScopedCredentialHandleV2,
        admissionDigest: Data,
        signingPublicKey: Data,
        agreementPublicKey: Data,
        contentTypes: [ContentTypeCapabilityV2] = ProtocolCapabilityManifest.defaultContentTypes,
        addedEpoch: UInt64,
        removedEpoch: UInt64? = nil
    ) {
        self.memberHandle = memberHandle
        self.credentialHandle = credentialHandle
        self.admissionDigest = admissionDigest
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
        self.contentTypes = contentTypes.sorted {
            ($0.authority, $0.name) < ($1.authority, $1.name)
        }
        self.addedEpoch = addedEpoch
        self.removedEpoch = removedEpoch
    }

    public init(from decoder: Decoder) throws {
        try requireExactSignedGroupKeys(
            decoder,
            required: Set(CodingKeys.allCases.map(\.rawValue)).subtracting([
                CodingKeys.removedEpoch.rawValue
            ]),
            optional: [CodingKeys.removedEpoch.rawValue]
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let decodedContentTypes = try values.decode(
            [ContentTypeCapabilityV2].self,
            forKey: .contentTypes
        )
        self.init(
            memberHandle: try values.decode(GroupScopedMemberHandleV2.self, forKey: .memberHandle),
            credentialHandle: try values.decode(GroupScopedCredentialHandleV2.self, forKey: .credentialHandle),
            admissionDigest: try values.decode(Data.self, forKey: .admissionDigest),
            signingPublicKey: try values.decode(Data.self, forKey: .signingPublicKey),
            agreementPublicKey: try values.decode(Data.self, forKey: .agreementPublicKey),
            contentTypes: decodedContentTypes,
            addedEpoch: try values.decode(UInt64.self, forKey: .addedEpoch),
            removedEpoch: try values.decodeIfPresent(UInt64.self, forKey: .removedEpoch)
        )
        try requireGroupCredentialAlgorithms(
            signingPublicKey: signingPublicKey,
            agreementPublicKey: agreementPublicKey
        )
        guard contentTypes == decodedContentTypes, isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group credential")
            )
        }
    }

    public static func fromVerifiedProjection(
        _ projection: GroupCredentialAdmissionV2,
        addedEpoch: UInt64
    ) throws -> GroupMemberCredentialV2 {
        try requireGroupCredentialAlgorithms(projection)
        guard projection.isStructurallyValid, let digest = projection.digest else {
            throw SignedGroupV2Error.invalidStructure
        }
        return GroupMemberCredentialV2(
            memberHandle: projection.memberHandle,
            credentialHandle: projection.credentialHandle,
            admissionDigest: digest,
            signingPublicKey: projection.groupSigningPublicKey,
            agreementPublicKey: projection.groupAgreementPublicKey,
            contentTypes: projection.contentTypes,
            addedEpoch: addedEpoch
        )
    }

    public var isStructurallyValid: Bool {
        memberHandle.isStructurallyValid
            && credentialHandle.isStructurallyValid
            && admissionDigest.count == 32
            && SigningKeyPair.isValidPublicKey(signingPublicKey)
            && AgreementKeyPair.isValidPublicKey(agreementPublicKey)
            && !contentTypes.isEmpty
            && contentTypes.count
                <= NoctweaveArchitectureV2.maximumContentTypeCapabilities
            && Set(contentTypes.map { "\($0.authority)\u{0}\($0.name)" }).count
                == contentTypes.count
            && contentTypes.allSatisfy(\.isStructurallyValid)
            && contentTypes.contains {
                $0.authority == ContentTypeId.text.authority
                    && $0.name == ContentTypeId.text.name
            }
            && addedEpoch > 0
            && (removedEpoch.map { $0 > addedEpoch } ?? true)
    }

    public func isActive(at epoch: UInt64) -> Bool {
        isStructurallyValid
            && addedEpoch <= epoch
            && (removedEpoch.map { $0 > epoch } ?? true)
    }
}

public enum SignedGroupCommitOperationV2: String, Codable, Equatable, CaseIterable {
    case addMember
    case replaceCredential
    case removeMember
    case changeRole
    case changePolicy
    case updateMetadata
    case deleteGroup
}

/// A complete proposed next state. Carrying the full members, leaves, policy, and
/// metadata digest makes omission and mixed-operation attacks fail closed.
public struct SignedGroupCommitV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let version: Int
    public let profile: GroupProtocolProfile
    public let cipherSuite: String
    public let groupId: UUID
    public let operation: SignedGroupCommitOperationV2
    public let baseEpoch: UInt64
    public let nextEpoch: UInt64
    public let previousTranscriptHash: Data
    public let proposedMembers: [GroupMemberV2]
    public let proposedCredentials: [GroupMemberCredentialV2]
    public let admissionProjection: GroupCredentialAdmissionV2?
    public let proposedPermissions: GroupPermissionPolicy
    public let proposedMetadataDigest: Data?
    public let authorCredentialHandle: GroupScopedCredentialHandleV2
    public let providerCommitDigest: Data
    public let idempotencyKey: Data
    public let createdAt: Date
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case version
        case profile
        case cipherSuite
        case groupId
        case operation
        case baseEpoch
        case nextEpoch
        case previousTranscriptHash
        case proposedMembers
        case proposedCredentials
        case admissionProjection
        case proposedPermissions
        case proposedMetadataDigest
        case authorCredentialHandle
        case providerCommitDigest
        case idempotencyKey
        case createdAt
        case signature
    }

    public init(
        id: UUID,
        version: Int = NoctweaveSignedGroupV2.version,
        profile: GroupProtocolProfile,
        cipherSuite: String,
        groupId: UUID,
        operation: SignedGroupCommitOperationV2,
        baseEpoch: UInt64,
        nextEpoch: UInt64,
        previousTranscriptHash: Data,
        proposedMembers: [GroupMemberV2],
        proposedCredentials: [GroupMemberCredentialV2],
        admissionProjection: GroupCredentialAdmissionV2? = nil,
        proposedPermissions: GroupPermissionPolicy,
        proposedMetadataDigest: Data?,
        authorCredentialHandle: GroupScopedCredentialHandleV2,
        providerCommitDigest: Data,
        idempotencyKey: Data,
        createdAt: Date,
        signature: Data
    ) {
        self.id = id
        self.version = version
        self.profile = profile
        self.cipherSuite = cipherSuite
        self.groupId = groupId
        self.operation = operation
        self.baseEpoch = baseEpoch
        self.nextEpoch = nextEpoch
        self.previousTranscriptHash = previousTranscriptHash
        self.proposedMembers = proposedMembers.sorted { $0.id.rawValue < $1.id.rawValue }
        self.proposedCredentials = proposedCredentials.sorted {
            $0.credentialHandle.rawValue < $1.credentialHandle.rawValue
        }
        self.admissionProjection = admissionProjection
        self.proposedPermissions = proposedPermissions
        self.proposedMetadataDigest = proposedMetadataDigest
        self.authorCredentialHandle = authorCredentialHandle
        self.providerCommitDigest = providerCommitDigest
        self.idempotencyKey = idempotencyKey
        self.createdAt = createdAt
        self.signature = signature
    }

    public init(from decoder: Decoder) throws {
        try requireExactSignedGroupKeys(
            decoder,
            required: Set(CodingKeys.allCases.map(\.rawValue)).subtracting([
                CodingKeys.admissionProjection.rawValue,
                CodingKeys.proposedMetadataDigest.rawValue,
            ]),
            optional: [
                CodingKeys.admissionProjection.rawValue,
                CodingKeys.proposedMetadataDigest.rawValue,
            ]
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let members = try values.decode([GroupMemberV2].self, forKey: .proposedMembers)
        let credentials = try values.decode(
            [GroupMemberCredentialV2].self,
            forKey: .proposedCredentials
        )
        self.init(
            id: try values.decode(UUID.self, forKey: .id),
            version: try values.decode(Int.self, forKey: .version),
            profile: try values.decode(GroupProtocolProfile.self, forKey: .profile),
            cipherSuite: try values.decode(String.self, forKey: .cipherSuite),
            groupId: try values.decode(UUID.self, forKey: .groupId),
            operation: try values.decode(SignedGroupCommitOperationV2.self, forKey: .operation),
            baseEpoch: try values.decode(UInt64.self, forKey: .baseEpoch),
            nextEpoch: try values.decode(UInt64.self, forKey: .nextEpoch),
            previousTranscriptHash: try values.decode(Data.self, forKey: .previousTranscriptHash),
            proposedMembers: members,
            proposedCredentials: credentials,
            admissionProjection: try values.decodeIfPresent(
                GroupCredentialAdmissionV2.self,
                forKey: .admissionProjection
            ),
            proposedPermissions: try values.decode(
                GroupPermissionPolicy.self,
                forKey: .proposedPermissions
            ),
            proposedMetadataDigest: try values.decodeIfPresent(
                Data.self,
                forKey: .proposedMetadataDigest
            ),
            authorCredentialHandle: try values.decode(
                GroupScopedCredentialHandleV2.self,
                forKey: .authorCredentialHandle
            ),
            providerCommitDigest: try values.decode(Data.self, forKey: .providerCommitDigest),
            idempotencyKey: try values.decode(Data.self, forKey: .idempotencyKey),
            createdAt: try values.decode(Date.self, forKey: .createdAt),
            signature: try values.decode(Data.self, forKey: .signature)
        )
        guard proposedMembers == members,
              proposedCredentials == credentials,
              isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group commit")
            )
        }
    }

    /// Creates a group-only commit. Credential replacement is signed by the
    /// member's current credential and carries possession proof for the fresh
    /// replacement credential.
    public static func create(
        id: UUID = UUID(),
        operation: SignedGroupCommitOperationV2,
        currentState: SignedGroupStateV2,
        proposedMembers: [GroupMemberV2],
        proposedCredentials: [GroupMemberCredentialV2],
        admissionProjection: GroupCredentialAdmissionV2? = nil,
        proposedPermissions: GroupPermissionPolicy,
        proposedMetadataDigest: Data?,
        authorCredentialHandle: GroupScopedCredentialHandleV2,
        providerCommitDigest: Data,
        idempotencyKey: Data,
        signingKey: SigningKeyPair,
        createdAt: Date = Date()
    ) throws -> SignedGroupCommitV2 {
        guard currentState.epoch < UInt64.max else { throw SignedGroupV2Error.staleEpoch }
        var commit = SignedGroupCommitV2(
            id: id,
            profile: currentState.profile,
            cipherSuite: currentState.cipherSuite,
            groupId: currentState.groupId,
            operation: operation,
            baseEpoch: currentState.epoch,
            nextEpoch: currentState.epoch + 1,
            previousTranscriptHash: currentState.confirmedTranscriptHash,
            proposedMembers: proposedMembers,
            proposedCredentials: proposedCredentials,
            admissionProjection: admissionProjection,
            proposedPermissions: proposedPermissions,
            proposedMetadataDigest: proposedMetadataDigest,
            authorCredentialHandle: authorCredentialHandle,
            providerCommitDigest: providerCommitDigest,
            idempotencyKey: idempotencyKey,
            createdAt: createdAt,
            signature: Data()
        )
        try commit.validateTransition(
            from: currentState,
            verifySignature: false,
            observedAt: createdAt
        )
        guard let author = currentState.activeCredentials.first(where: {
            $0.credentialHandle == authorCredentialHandle
        }), author.signingPublicKey == signingKey.publicKeyData else {
            throw SignedGroupV2Error.unknownAuthor
        }
        let digest = try commit.commitDigest()
        commit = SignedGroupCommitV2(
            id: commit.id,
            profile: commit.profile,
            cipherSuite: commit.cipherSuite,
            groupId: commit.groupId,
            operation: commit.operation,
            baseEpoch: commit.baseEpoch,
            nextEpoch: commit.nextEpoch,
            previousTranscriptHash: commit.previousTranscriptHash,
            proposedMembers: commit.proposedMembers,
            proposedCredentials: commit.proposedCredentials,
            admissionProjection: commit.admissionProjection,
            proposedPermissions: commit.proposedPermissions,
            proposedMetadataDigest: commit.proposedMetadataDigest,
            authorCredentialHandle: commit.authorCredentialHandle,
            providerCommitDigest: commit.providerCommitDigest,
            idempotencyKey: commit.idempotencyKey,
            createdAt: commit.createdAt,
            signature: try signingKey.sign(
                try GroupCommitSignatureContextV2(
                    groupId: commit.groupId,
                    profile: commit.profile,
                    nextEpoch: commit.nextEpoch,
                    commitDigest: digest
                ).signableData()
            )
        )
        return try commit.verifiedTransition(
            from: currentState,
            observedAt: createdAt
        )
    }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveSignedGroupV2.version,
              profile == NoctweaveSignedGroupV2.experimentalProfile,
              cipherSuite == NoctweaveSignedGroupV2.experimentalCipherSuite,
              baseEpoch > 0,
              baseEpoch < UInt64.max,
              nextEpoch == baseEpoch + 1,
              previousTranscriptHash.count == 32,
              authorCredentialHandle.isStructurallyValid,
              providerCommitDigest.count == 32,
              idempotencyKey.count == 32,
              createdAt.timeIntervalSince1970.isFinite,
              admissionProjection?.isStructurallyValid ?? true,
              signature.count == NoctweaveSignedGroupV2.signatureBytes,
              let encoded = try? NoctweaveCoder.encode(payload, sortedKeys: true),
              encoded.count <= NoctweaveGroupArchitectureV2.maximumCommitBytes else {
            return false
        }
        let admissionFieldsAreValid: Bool
        switch operation {
        case .addMember, .replaceCredential:
            admissionFieldsAreValid = admissionProjection != nil
        case .removeMember, .changeRole, .changePolicy, .updateMetadata:
            admissionFieldsAreValid = admissionProjection == nil
        case .deleteGroup:
            admissionFieldsAreValid = false
        }
        guard admissionFieldsAreValid else { return false }
        return (try? SignedGroupStateValidatorV2.validate(
            profile: profile,
            cipherSuite: cipherSuite,
            epoch: nextEpoch,
            members: proposedMembers,
            memberCredentials: proposedCredentials,
            permissions: proposedPermissions,
            metadataDigest: proposedMetadataDigest
        )) != nil
    }

    public var digest: Data? {
        try? commitDigest()
    }

    public func verifiedTransition(
        from currentState: SignedGroupStateV2,
        observedAt: Date
    ) throws -> SignedGroupCommitV2 {
        try validateTransition(
            from: currentState,
            verifySignature: true,
            observedAt: observedAt
        )
        return self
    }

    fileprivate var payload: GroupCommitPayloadV2 {
        GroupCommitPayloadV2(
            version: version,
            id: id,
            profile: profile,
            cipherSuite: cipherSuite,
            groupId: groupId,
            operation: operation,
            baseEpoch: baseEpoch,
            nextEpoch: nextEpoch,
            previousTranscriptHash: previousTranscriptHash,
            proposedMembers: proposedMembers,
            proposedCredentials: proposedCredentials,
            admissionProjection: admissionProjection,
            proposedPermissions: proposedPermissions,
            proposedMetadataDigest: proposedMetadataDigest,
            authorCredentialHandle: authorCredentialHandle,
            providerCommitDigest: providerCommitDigest,
            idempotencyKey: idempotencyKey,
            createdAt: createdAt
        )
    }

    private func commitDigest() throws -> Data {
        try SignedGroupV2Hash.digest(payload)
    }

    private func validateTransition(
        from currentState: SignedGroupStateV2,
        verifySignature: Bool,
        observedAt: Date
    ) throws {
        try requireGroupCredentialAlgorithms(currentState.memberCredentials)
        try requireGroupCredentialAlgorithms(proposedCredentials)
        if let admissionProjection {
            try requireGroupCredentialAlgorithms(admissionProjection)
        }
        guard currentState.isStructurallyValid else { throw SignedGroupV2Error.invalidStructure }
        guard profile == currentState.profile,
              cipherSuite == currentState.cipherSuite,
              groupId == currentState.groupId else {
            throw SignedGroupV2Error.invalidContext
        }
        guard baseEpoch == currentState.epoch, nextEpoch == currentState.epoch + 1 else {
            throw SignedGroupV2Error.staleEpoch
        }
        guard previousTranscriptHash == currentState.confirmedTranscriptHash else {
            throw SignedGroupV2Error.transcriptMismatch
        }
        guard providerCommitDigest.count == 32,
              idempotencyKey.count == 32 else {
            throw SignedGroupV2Error.invalidStructure
        }
        guard observedAt.timeIntervalSince1970.isFinite,
              createdAt >= currentState.signedAt,
              createdAt <= observedAt.addingTimeInterval(
                  NoctweaveSignedGroupV2.maximumClockSkewSeconds
              ) else {
            throw SignedGroupV2Error.invalidTimestamp
        }
        try SignedGroupStateValidatorV2.validate(
            profile: profile,
            cipherSuite: cipherSuite,
            epoch: nextEpoch,
            members: proposedMembers,
            memberCredentials: proposedCredentials,
            permissions: proposedPermissions,
            metadataDigest: proposedMetadataDigest
        )
        guard let actorLeaf = currentState.activeCredentials.first(where: {
            $0.credentialHandle == authorCredentialHandle
        }), let actorMember = currentState.activeMembers.first(where: {
            $0.id == actorLeaf.memberHandle
        }) else {
            throw SignedGroupV2Error.unknownAuthor
        }
        if verifySignature {
            guard isStructurallyValid,
                  let digest else {
                throw SignedGroupV2Error.invalidCommitSignature
            }
            let signatureData = try GroupCommitSignatureContextV2(
                      groupId: groupId,
                      profile: profile,
                      nextEpoch: nextEpoch,
                      commitDigest: digest
                  ).signableData()
            guard try SigningKeyPair.verifyThrowing(
                signature: signature,
                data: signatureData,
                publicKeyData: actorLeaf.signingPublicKey
            ) else {
                throw SignedGroupV2Error.invalidCommitSignature
            }
        }
        let verifiedAddedLeaf: GroupMemberCredentialV2?
        switch operation {
        case .addMember, .replaceCredential:
            guard let admissionProjection else {
                throw SignedGroupV2Error.admissionMismatch
            }
            let selection = GroupProtocolSelectionV2(
                profile: currentState.profile,
                cipherSuite: currentState.cipherSuite
            )
            let verifiedProjection = try admissionProjection.verified(
                forGroupId: groupId,
                memberHandle: admissionProjection.memberHandle,
                selection: selection,
                now: createdAt
            )
            verifiedAddedLeaf = try GroupMemberCredentialV2.fromVerifiedProjection(
                verifiedProjection,
                addedEpoch: nextEpoch
            )
        case .removeMember, .changeRole, .changePolicy, .updateMetadata:
            guard admissionProjection == nil else {
                throw SignedGroupV2Error.invalidTransition
            }
            verifiedAddedLeaf = nil
        case .deleteGroup:
            throw SignedGroupV2Error.invalidTransition
        }
        try SignedGroupTransitionValidatorV2.validate(
            operation: operation,
            currentState: currentState,
            proposedMembers: proposedMembers,
            proposedCredentials: proposedCredentials,
            proposedPermissions: proposedPermissions,
            proposedMetadataDigest: proposedMetadataDigest,
            actorMember: actorMember,
            actorLeaf: actorLeaf,
            verifiedAddedLeaf: verifiedAddedLeaf,
            nextEpoch: nextEpoch
        )
    }
}

/// A deletion is represented by a separately signed terminal operation. It is
/// not encoded as another live membership state, so an implementation cannot
/// accidentally advance from it using an ordinary group commit.
public struct SignedGroupDeletionTombstoneV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let version: Int
    public let operation: SignedGroupCommitOperationV2
    public let selection: GroupProtocolSelectionV2
    public let groupId: UUID
    public let baseEpoch: UInt64
    public let deletedEpoch: UInt64
    public let previousTranscriptHash: Data
    public let authorCredentialHandle: GroupScopedCredentialHandleV2
    public let reasonDigest: Data?
    public let idempotencyKey: Data
    public let createdAt: Date
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case version
        case operation
        case selection
        case groupId
        case baseEpoch
        case deletedEpoch
        case previousTranscriptHash
        case authorCredentialHandle
        case reasonDigest
        case idempotencyKey
        case createdAt
        case signature
    }

    public init(
        id: UUID,
        version: Int = NoctweaveSignedGroupV2.version,
        operation: SignedGroupCommitOperationV2 = .deleteGroup,
        selection: GroupProtocolSelectionV2,
        groupId: UUID,
        baseEpoch: UInt64,
        deletedEpoch: UInt64,
        previousTranscriptHash: Data,
        authorCredentialHandle: GroupScopedCredentialHandleV2,
        reasonDigest: Data?,
        idempotencyKey: Data,
        createdAt: Date,
        signature: Data
    ) {
        self.id = id
        self.version = version
        self.operation = operation
        self.selection = selection
        self.groupId = groupId
        self.baseEpoch = baseEpoch
        self.deletedEpoch = deletedEpoch
        self.previousTranscriptHash = previousTranscriptHash
        self.authorCredentialHandle = authorCredentialHandle
        self.reasonDigest = reasonDigest
        self.idempotencyKey = idempotencyKey
        self.createdAt = createdAt
        self.signature = signature
    }

    public init(from decoder: Decoder) throws {
        try requireExactSignedGroupKeys(
            decoder,
            required: Set(CodingKeys.allCases.map(\.rawValue)).subtracting([
                CodingKeys.reasonDigest.rawValue
            ]),
            optional: [CodingKeys.reasonDigest.rawValue]
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try values.decode(UUID.self, forKey: .id),
            version: try values.decode(Int.self, forKey: .version),
            operation: try values.decode(SignedGroupCommitOperationV2.self, forKey: .operation),
            selection: try values.decode(GroupProtocolSelectionV2.self, forKey: .selection),
            groupId: try values.decode(UUID.self, forKey: .groupId),
            baseEpoch: try values.decode(UInt64.self, forKey: .baseEpoch),
            deletedEpoch: try values.decode(UInt64.self, forKey: .deletedEpoch),
            previousTranscriptHash: try values.decode(Data.self, forKey: .previousTranscriptHash),
            authorCredentialHandle: try values.decode(
                GroupScopedCredentialHandleV2.self,
                forKey: .authorCredentialHandle
            ),
            reasonDigest: try values.decodeIfPresent(Data.self, forKey: .reasonDigest),
            idempotencyKey: try values.decode(Data.self, forKey: .idempotencyKey),
            createdAt: try values.decode(Date.self, forKey: .createdAt),
            signature: try values.decode(Data.self, forKey: .signature)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group deletion")
            )
        }
    }

    public static func create(
        id: UUID = UUID(),
        currentState: SignedGroupStateV2,
        authorCredentialHandle: GroupScopedCredentialHandleV2,
        reasonDigest: Data? = nil,
        idempotencyKey: Data,
        signingKey: SigningKeyPair,
        createdAt: Date = Date()
    ) throws -> SignedGroupDeletionTombstoneV2 {
        try requireGroupCredentialAlgorithms(currentState.memberCredentials)
        guard currentState.isStructurallyValid,
              currentState.epoch < UInt64.max,
              idempotencyKey.count == 32,
              reasonDigest?.count ?? 32 == 32,
              createdAt >= currentState.signedAt,
              let authorLeaf = currentState.activeCredentials.first(where: {
                  $0.credentialHandle == authorCredentialHandle
              }),
              let authorUser = currentState.activeMembers.first(where: {
                  $0.id == authorLeaf.memberHandle
              }),
              currentState.permissions.allows(.deleteGroup, for: authorUser.role),
              authorLeaf.signingPublicKey == signingKey.publicKeyData else {
            throw SignedGroupV2Error.unauthorized
        }
        let selection = GroupProtocolSelectionV2(
            profile: currentState.profile,
            cipherSuite: currentState.cipherSuite
        )
        guard selection.isStructurallyValid else {
            throw SignedGroupV2Error.unsupportedProfile
        }
        var tombstone = SignedGroupDeletionTombstoneV2(
            id: id,
            selection: selection,
            groupId: currentState.groupId,
            baseEpoch: currentState.epoch,
            deletedEpoch: currentState.epoch + 1,
            previousTranscriptHash: currentState.confirmedTranscriptHash,
            authorCredentialHandle: authorCredentialHandle,
            reasonDigest: reasonDigest,
            idempotencyKey: idempotencyKey,
            createdAt: createdAt,
            signature: Data()
        )
        let digest = try tombstone.tombstoneDigest()
        tombstone = SignedGroupDeletionTombstoneV2(
            id: tombstone.id,
            selection: tombstone.selection,
            groupId: tombstone.groupId,
            baseEpoch: tombstone.baseEpoch,
            deletedEpoch: tombstone.deletedEpoch,
            previousTranscriptHash: tombstone.previousTranscriptHash,
            authorCredentialHandle: tombstone.authorCredentialHandle,
            reasonDigest: tombstone.reasonDigest,
            idempotencyKey: tombstone.idempotencyKey,
            createdAt: tombstone.createdAt,
            signature: try signingKey.sign(
                try GroupDeletionSignatureContextV2(
                    groupId: tombstone.groupId,
                    deletedEpoch: tombstone.deletedEpoch,
                    tombstoneDigest: digest
                ).signableData()
            )
        )
        return try tombstone.verified(
            against: currentState,
            observedAt: createdAt
        )
    }

    public var isStructurallyValid: Bool {
        version == NoctweaveSignedGroupV2.version
            && operation == .deleteGroup
            && selection.isStructurallyValid
            && baseEpoch > 0
            && baseEpoch < UInt64.max
            && deletedEpoch == baseEpoch + 1
            && previousTranscriptHash.count == 32
            && authorCredentialHandle.isStructurallyValid
            && reasonDigest?.count ?? 32 == 32
            && idempotencyKey.count == 32
            && createdAt.timeIntervalSince1970.isFinite
            && signature.count == NoctweaveSignedGroupV2.signatureBytes
    }

    public var digest: Data? {
        try? tombstoneDigest()
    }

    public func verified(
        against currentState: SignedGroupStateV2,
        observedAt: Date
    ) throws -> SignedGroupDeletionTombstoneV2 {
        try requireGroupCredentialAlgorithms(currentState.memberCredentials)
        guard isStructurallyValid,
              currentState.isStructurallyValid else {
            throw SignedGroupV2Error.invalidStructure
        }
        guard selection == GroupProtocolSelectionV2(
            profile: currentState.profile,
            cipherSuite: currentState.cipherSuite
        ),
              groupId == currentState.groupId,
              baseEpoch == currentState.epoch,
              deletedEpoch == currentState.epoch + 1,
              previousTranscriptHash == currentState.confirmedTranscriptHash,
              createdAt >= currentState.signedAt else {
            throw SignedGroupV2Error.invalidContext
        }
        guard observedAt.timeIntervalSince1970.isFinite,
              createdAt <= observedAt.addingTimeInterval(
                  NoctweaveSignedGroupV2.maximumClockSkewSeconds
              ) else {
            throw SignedGroupV2Error.invalidTimestamp
        }
        guard let authorLeaf = currentState.activeCredentials.first(where: {
            $0.credentialHandle == authorCredentialHandle
        }),
              let authorUser = currentState.activeMembers.first(where: {
                  $0.id == authorLeaf.memberHandle
              }),
              currentState.permissions.allows(.deleteGroup, for: authorUser.role),
              let digest,
              try SigningKeyPair.verifyThrowing(
                  signature: signature,
                  data: try GroupDeletionSignatureContextV2(
                      groupId: groupId,
                      deletedEpoch: deletedEpoch,
                      tombstoneDigest: digest
                  ).signableData(),
                  publicKeyData: authorLeaf.signingPublicKey
              ) else {
            throw SignedGroupV2Error.invalidCommitSignature
        }
        return self
    }

    fileprivate var payload: GroupDeletionTombstonePayloadV2 {
        GroupDeletionTombstonePayloadV2(
            version: version,
            id: id,
            operation: operation,
            selection: selection,
            groupId: groupId,
            baseEpoch: baseEpoch,
            deletedEpoch: deletedEpoch,
            previousTranscriptHash: previousTranscriptHash,
            authorCredentialHandle: authorCredentialHandle,
            reasonDigest: reasonDigest,
            idempotencyKey: idempotencyKey,
            createdAt: createdAt
        )
    }

    private func tombstoneDigest() throws -> Data {
        try SignedGroupV2Hash.digest(payload)
    }
}

/// Terminal local state retained after a valid deletion. Its transcript binds
/// the prior accepted group transcript and the signed tombstone. There is no
/// conversion back to `SignedGroupStateV2`.
public struct SignedDeletedGroupStateV2: Codable, Equatable, Identifiable {
    public var id: UUID { tombstone.groupId }
    public let version: Int
    public let tombstone: SignedGroupDeletionTombstoneV2
    public let tombstoneDigest: Data
    public let terminalTranscriptHash: Data
    /// Receiver-observed acceptance time retained for historical verification.
    /// The signed peer timestamp remains transcript metadata, not freshness authority.
    public let observedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case tombstone
        case tombstoneDigest
        case terminalTranscriptHash
        case observedAt
    }

    public init(
        version: Int = NoctweaveSignedGroupV2.version,
        tombstone: SignedGroupDeletionTombstoneV2,
        tombstoneDigest: Data,
        terminalTranscriptHash: Data,
        observedAt: Date
    ) {
        self.version = version
        self.tombstone = tombstone
        self.tombstoneDigest = tombstoneDigest
        self.terminalTranscriptHash = terminalTranscriptHash
        self.observedAt = observedAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactSignedGroupKeys(
            decoder,
            required: Set(CodingKeys.allCases.map(\.rawValue))
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            tombstone: try values.decode(SignedGroupDeletionTombstoneV2.self, forKey: .tombstone),
            tombstoneDigest: try values.decode(Data.self, forKey: .tombstoneDigest),
            terminalTranscriptHash: try values.decode(Data.self, forKey: .terminalTranscriptHash),
            observedAt: try values.decode(Date.self, forKey: .observedAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid deleted group state")
            )
        }
    }

    public static func create(
        tombstone: SignedGroupDeletionTombstoneV2,
        from currentState: SignedGroupStateV2,
        observedAt: Date
    ) throws -> SignedDeletedGroupStateV2 {
        _ = try tombstone.verified(
            against: currentState,
            observedAt: observedAt
        )
        guard let digest = tombstone.digest else {
            throw SignedGroupV2Error.invalidStructure
        }
        let state = SignedDeletedGroupStateV2(
            tombstone: tombstone,
            tombstoneDigest: digest,
            terminalTranscriptHash: try terminalHash(
                tombstone: tombstone,
                tombstoneDigest: digest
            ),
            observedAt: observedAt
        )
        return try state.verified(previousState: currentState)
    }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveSignedGroupV2.version,
              tombstone.isStructurallyValid,
              tombstone.digest == tombstoneDigest,
              tombstoneDigest.count == 32,
              terminalTranscriptHash.count == 32,
              observedAt.timeIntervalSince1970.isFinite,
              tombstone.createdAt <= observedAt.addingTimeInterval(
                  NoctweaveSignedGroupV2.maximumClockSkewSeconds
              ),
              let expected = try? Self.terminalHash(
                  tombstone: tombstone,
                  tombstoneDigest: tombstoneDigest
              ) else {
            return false
        }
        return expected == terminalTranscriptHash
    }

    public func verified(
        previousState: SignedGroupStateV2
    ) throws -> SignedDeletedGroupStateV2 {
        guard isStructurallyValid else { throw SignedGroupV2Error.invalidStructure }
        _ = try tombstone.verified(
            against: previousState,
            observedAt: observedAt
        )
        return self
    }

    /// Any later live state for this group is a resurrection attempt, even if
    /// it carries a numerically higher epoch or a newly generated key set.
    public func rejectResurrection(
        _ candidate: SignedGroupStateV2
    ) throws {
        guard candidate.groupId == tombstone.groupId else {
            throw SignedGroupV2Error.invalidContext
        }
        throw SignedGroupV2Error.groupDeleted
    }

    /// A terminal state cannot consume ordinary live commits.
    public func applying(
        _ commit: SignedGroupCommitV2
    ) throws -> SignedDeletedGroupStateV2 {
        guard commit.groupId == tombstone.groupId else {
            throw SignedGroupV2Error.invalidContext
        }
        throw SignedGroupV2Error.groupDeleted
    }

    private static func terminalHash(
        tombstone: SignedGroupDeletionTombstoneV2,
        tombstoneDigest: Data
    ) throws -> Data {
        try SignedGroupV2Hash.digest(
            GroupDeletionTerminalTranscriptV2(
                selection: tombstone.selection,
                groupId: tombstone.groupId,
                deletedEpoch: tombstone.deletedEpoch,
                previousTranscriptHash: tombstone.previousTranscriptHash,
                tombstoneDigest: tombstoneDigest
            )
        )
    }
}

public struct SignedGroupStateV2: Codable, Equatable, Identifiable {
    public var id: UUID { groupId }
    public let version: Int
    public let profile: GroupProtocolProfile
    public let cipherSuite: String
    public let groupId: UUID
    public let epoch: UInt64
    public let previousTranscriptHash: Data?
    public let members: [GroupMemberV2]
    public let memberCredentials: [GroupMemberCredentialV2]
    public let permissions: GroupPermissionPolicy
    public let metadataDigest: Data?
    public let authorCredentialHandle: GroupScopedCredentialHandleV2
    public let commitDigest: Data
    public let confirmedTranscriptHash: Data
    public let signedAt: Date
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case profile
        case cipherSuite
        case groupId
        case epoch
        case previousTranscriptHash
        case members
        case memberCredentials
        case permissions
        case metadataDigest
        case authorCredentialHandle
        case commitDigest
        case confirmedTranscriptHash
        case signedAt
        case signature
    }

    public init(
        version: Int = NoctweaveSignedGroupV2.version,
        profile: GroupProtocolProfile,
        cipherSuite: String,
        groupId: UUID,
        epoch: UInt64,
        previousTranscriptHash: Data?,
        members: [GroupMemberV2],
        memberCredentials: [GroupMemberCredentialV2],
        permissions: GroupPermissionPolicy,
        metadataDigest: Data?,
        authorCredentialHandle: GroupScopedCredentialHandleV2,
        commitDigest: Data,
        confirmedTranscriptHash: Data,
        signedAt: Date,
        signature: Data
    ) {
        self.version = version
        self.profile = profile
        self.cipherSuite = cipherSuite
        self.groupId = groupId
        self.epoch = epoch
        self.previousTranscriptHash = previousTranscriptHash
        self.members = members.sorted { $0.id.rawValue < $1.id.rawValue }
        self.memberCredentials = memberCredentials.sorted {
            $0.credentialHandle.rawValue < $1.credentialHandle.rawValue
        }
        self.permissions = permissions
        self.metadataDigest = metadataDigest
        self.authorCredentialHandle = authorCredentialHandle
        self.commitDigest = commitDigest
        self.confirmedTranscriptHash = confirmedTranscriptHash
        self.signedAt = signedAt
        self.signature = signature
    }

    public init(from decoder: Decoder) throws {
        try requireExactSignedGroupKeys(
            decoder,
            required: Set(CodingKeys.allCases.map(\.rawValue)).subtracting([
                CodingKeys.previousTranscriptHash.rawValue,
                CodingKeys.metadataDigest.rawValue,
            ]),
            optional: [
                CodingKeys.previousTranscriptHash.rawValue,
                CodingKeys.metadataDigest.rawValue,
            ]
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let decodedMembers = try values.decode([GroupMemberV2].self, forKey: .members)
        let decodedCredentials = try values.decode(
            [GroupMemberCredentialV2].self,
            forKey: .memberCredentials
        )
        self.init(
            version: try values.decode(Int.self, forKey: .version),
            profile: try values.decode(GroupProtocolProfile.self, forKey: .profile),
            cipherSuite: try values.decode(String.self, forKey: .cipherSuite),
            groupId: try values.decode(UUID.self, forKey: .groupId),
            epoch: try values.decode(UInt64.self, forKey: .epoch),
            previousTranscriptHash: try values.decodeIfPresent(
                Data.self,
                forKey: .previousTranscriptHash
            ),
            members: decodedMembers,
            memberCredentials: decodedCredentials,
            permissions: try values.decode(GroupPermissionPolicy.self, forKey: .permissions),
            metadataDigest: try values.decodeIfPresent(Data.self, forKey: .metadataDigest),
            authorCredentialHandle: try values.decode(
                GroupScopedCredentialHandleV2.self,
                forKey: .authorCredentialHandle
            ),
            commitDigest: try values.decode(Data.self, forKey: .commitDigest),
            confirmedTranscriptHash: try values.decode(
                Data.self,
                forKey: .confirmedTranscriptHash
            ),
            signedAt: try values.decode(Date.self, forKey: .signedAt),
            signature: try values.decode(Data.self, forKey: .signature)
        )
        try requireGroupCredentialAlgorithms(memberCredentials)
        guard members == decodedMembers,
              memberCredentials == decodedCredentials,
              isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid signed group state")
            )
        }
    }

    public static func initial(
        groupId: UUID,
        creator: GroupMemberV2,
        creatorAdmission: GroupCredentialAdmissionV2,
        permissions: GroupPermissionPolicy = .default,
        metadataDigest: Data? = nil,
        providerGenesisDigest: Data,
        signingKey: SigningKeyPair,
        signedAt: Date = Date()
    ) throws -> SignedGroupStateV2 {
        let profile = NoctweaveSignedGroupV2.experimentalProfile
        let cipherSuite = NoctweaveSignedGroupV2.experimentalCipherSuite
        guard creator.id == creatorAdmission.memberHandle,
              creator.role == .owner,
              creator.addedEpoch == 1,
              creator.removedEpoch == nil,
              providerGenesisDigest.count == 32,
              signedAt.timeIntervalSince1970.isFinite else {
            throw SignedGroupV2Error.invalidTransition
        }
        let verifiedAdmission = try creatorAdmission.verified(
            forGroupId: groupId,
            memberHandle: creator.id,
            selection: .currentExperimental,
            now: signedAt
        )
        guard verifiedAdmission.groupSigningPublicKey == signingKey.publicKeyData else {
            throw SignedGroupV2Error.unknownAuthor
        }
        let creatorLeaf = try GroupMemberCredentialV2.fromVerifiedProjection(
            verifiedAdmission,
            addedEpoch: 1
        )
        let members = [creator]
        let memberCredentials = [creatorLeaf]
        try SignedGroupStateValidatorV2.validate(
            profile: profile,
            cipherSuite: cipherSuite,
            epoch: 1,
            members: members,
            memberCredentials: memberCredentials,
            permissions: permissions,
            metadataDigest: metadataDigest
        )
        let state = try signedState(
            profile: profile,
            cipherSuite: cipherSuite,
            groupId: groupId,
            epoch: 1,
            previousTranscriptHash: nil,
            members: members,
            memberCredentials: memberCredentials,
            permissions: permissions,
            metadataDigest: metadataDigest,
            authorCredentialHandle: creatorLeaf.credentialHandle,
            commitDigest: providerGenesisDigest,
            signingKey: signingKey,
            signedAt: signedAt
        )
        return try state.verified(
            genesisAdmission: verifiedAdmission,
            observedAt: signedAt
        )
    }

    public static func applying(
        _ commit: SignedGroupCommitV2,
        to currentState: SignedGroupStateV2,
        observedAt: Date,
        signingKey: SigningKeyPair
    ) throws -> SignedGroupStateV2 {
        _ = try commit.verifiedTransition(
            from: currentState,
            observedAt: observedAt
        )
        guard let author = currentState.activeCredentials.first(where: {
            $0.credentialHandle == commit.authorCredentialHandle
        }), author.signingPublicKey == signingKey.publicKeyData,
              let digest = commit.digest else {
            throw SignedGroupV2Error.unknownAuthor
        }
        let state = try signedState(
            profile: commit.profile,
            cipherSuite: commit.cipherSuite,
            groupId: commit.groupId,
            epoch: commit.nextEpoch,
            previousTranscriptHash: commit.previousTranscriptHash,
            members: commit.proposedMembers,
            memberCredentials: commit.proposedCredentials,
            permissions: commit.proposedPermissions,
            metadataDigest: commit.proposedMetadataDigest,
            authorCredentialHandle: commit.authorCredentialHandle,
            commitDigest: digest,
            signingKey: signingKey,
            signedAt: commit.createdAt
        )
        return try state.verified(
            previousState: currentState,
            commit: commit,
            observedAt: observedAt
        )
    }

    public var activeMembers: [GroupMemberV2] {
        members.filter { $0.isActive(at: epoch) }
    }

    public var activeCredentials: [GroupMemberCredentialV2] {
        let activeMemberHandles = Set(activeMembers.map(\.id))
        return memberCredentials.filter { $0.isActive(at: epoch) && activeMemberHandles.contains($0.memberHandle) }
    }

    /// The accepted state is signed by the credential that authorized its
    /// transition. During credential replacement that key is retired at this
    /// epoch, so it is intentionally distinct from `activeCredentials`.
    fileprivate var transitionAuthorCredential: GroupMemberCredentialV2? {
        memberCredentials.first {
            $0.credentialHandle == authorCredentialHandle
                && $0.addedEpoch <= epoch
                && ($0.removedEpoch == nil || $0.removedEpoch == epoch)
        }
    }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveSignedGroupV2.version,
              epoch > 0,
              previousTranscriptHash?.count ?? 32 == 32,
              (epoch == 1 ? previousTranscriptHash == nil : previousTranscriptHash != nil),
              authorCredentialHandle.isStructurallyValid,
              commitDigest.count == 32,
              confirmedTranscriptHash.count == 32,
              signedAt.timeIntervalSince1970.isFinite,
              signature.count == NoctweaveSignedGroupV2.signatureBytes,
              let expectedHash = try? SignedGroupV2Hash.digest(transcriptPayload),
              expectedHash == confirmedTranscriptHash,
              let encoded = try? NoctweaveCoder.encode(transcriptPayload, sortedKeys: true),
              encoded.count <= NoctweaveSignedGroupV2.maximumStateBytes else {
            return false
        }
        return (try? SignedGroupStateValidatorV2.validate(
            profile: profile,
            cipherSuite: cipherSuite,
            epoch: epoch,
            members: members,
            memberCredentials: memberCredentials,
            permissions: permissions,
            metadataDigest: metadataDigest
        )) != nil
    }

    public var digest: Data? {
        guard let data = try? NoctweaveCoder.encode(self, sortedKeys: true) else { return nil }
        return Data(SHA256.hash(data: data))
    }

    public func verified(
        previousState: SignedGroupStateV2? = nil,
        commit: SignedGroupCommitV2? = nil,
        genesisAdmission: GroupCredentialAdmissionV2? = nil,
        observedAt: Date
    ) throws -> SignedGroupStateV2 {
        try requireGroupCredentialAlgorithms(memberCredentials)
        if let previousState {
            try requireGroupCredentialAlgorithms(previousState.memberCredentials)
        }
        if let genesisAdmission {
            try requireGroupCredentialAlgorithms(genesisAdmission)
        }
        guard observedAt.timeIntervalSince1970.isFinite,
              signedAt <= observedAt.addingTimeInterval(
                  NoctweaveSignedGroupV2.maximumClockSkewSeconds
              ) else {
            throw SignedGroupV2Error.invalidTimestamp
        }
        guard isStructurallyValid else { throw SignedGroupV2Error.invalidStructure }
        let authorKey: Data
        if let previousState {
            guard previousState.epoch < UInt64.max,
                  epoch == previousState.epoch + 1,
                  groupId == previousState.groupId,
                  profile == previousState.profile,
                  cipherSuite == previousState.cipherSuite else {
                throw SignedGroupV2Error.staleEpoch
            }
            guard previousTranscriptHash == previousState.confirmedTranscriptHash else {
                throw SignedGroupV2Error.transcriptMismatch
            }
            guard let commit else { throw SignedGroupV2Error.invalidTransition }
            _ = try commit.verifiedTransition(
                from: previousState,
                observedAt: observedAt
            )
            guard commit.groupId == groupId,
                  commit.nextEpoch == epoch,
                  commit.proposedMembers == members,
                  commit.proposedCredentials == memberCredentials,
                  commit.proposedPermissions == permissions,
                  commit.proposedMetadataDigest == metadataDigest,
                  commit.authorCredentialHandle == authorCredentialHandle,
                  commit.digest == commitDigest,
                  commit.createdAt == signedAt else {
                throw SignedGroupV2Error.invalidTransition
            }
            guard let author = previousState.activeCredentials.first(where: {
                $0.credentialHandle == authorCredentialHandle
            }) else {
                throw SignedGroupV2Error.unknownAuthor
            }
            authorKey = author.signingPublicKey
        } else {
            guard let genesisAdmission else {
                throw SignedGroupV2Error.genesisAdmissionRequired
            }
            guard epoch == 1,
                  previousTranscriptHash == nil,
                  commit == nil,
                  members.count == 1,
                  memberCredentials.count == 1,
                  let creator = members.first,
                  creator.id == genesisAdmission.memberHandle,
                  creator.role == .owner,
                  creator.addedEpoch == 1,
                  creator.removedEpoch == nil else {
                throw SignedGroupV2Error.invalidTransition
            }
            let verifiedAdmission = try genesisAdmission.verified(
                forGroupId: groupId,
                memberHandle: creator.id,
                selection: GroupProtocolSelectionV2(
                    profile: profile,
                    cipherSuite: cipherSuite
                ),
                // Admission validity is evaluated at the authenticated state
                // signing time. Freshness of that peer time is separately
                // bounded by the receiver-observed `observedAt` above.
                now: signedAt
            )
            let expectedLeaf = try GroupMemberCredentialV2.fromVerifiedProjection(
                verifiedAdmission,
                addedEpoch: 1
            )
            guard memberCredentials[0] == expectedLeaf,
                  authorCredentialHandle == expectedLeaf.credentialHandle else {
                throw SignedGroupV2Error.admissionMismatch
            }
            authorKey = verifiedAdmission.groupSigningPublicKey
        }
        let signatureData = try GroupStateSignatureContextV2(
            groupId: groupId,
            profile: profile,
            epoch: epoch,
            transcriptHash: confirmedTranscriptHash,
            commitDigest: commitDigest
        ).signableData()
        guard try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: signatureData,
            publicKeyData: authorKey
        ) else {
            throw SignedGroupV2Error.invalidStateSignature
        }
        return self
    }

    fileprivate var transcriptPayload: GroupStateTranscriptPayloadV2 {
        GroupStateTranscriptPayloadV2(
            version: version,
            profile: profile,
            cipherSuite: cipherSuite,
            groupId: groupId,
            epoch: epoch,
            previousTranscriptHash: previousTranscriptHash,
            members: members,
            memberCredentials: memberCredentials,
            permissions: permissions,
            metadataDigest: metadataDigest,
            authorCredentialHandle: authorCredentialHandle,
            commitDigest: commitDigest,
            signedAt: signedAt
        )
    }

    private static func signedState(
        profile: GroupProtocolProfile,
        cipherSuite: String,
        groupId: UUID,
        epoch: UInt64,
        previousTranscriptHash: Data?,
        members: [GroupMemberV2],
        memberCredentials: [GroupMemberCredentialV2],
        permissions: GroupPermissionPolicy,
        metadataDigest: Data?,
        authorCredentialHandle: GroupScopedCredentialHandleV2,
        commitDigest: Data,
        signingKey: SigningKeyPair,
        signedAt: Date
    ) throws -> SignedGroupStateV2 {
        let orderedMembers = members.sorted { $0.id.rawValue < $1.id.rawValue }
        let orderedLeaves = memberCredentials.sorted { $0.credentialHandle.rawValue < $1.credentialHandle.rawValue }
        try SignedGroupStateValidatorV2.validate(
            profile: profile,
            cipherSuite: cipherSuite,
            epoch: epoch,
            members: orderedMembers,
            memberCredentials: orderedLeaves,
            permissions: permissions,
            metadataDigest: metadataDigest
        )
        let payload = GroupStateTranscriptPayloadV2(
            version: NoctweaveSignedGroupV2.version,
            profile: profile,
            cipherSuite: cipherSuite,
            groupId: groupId,
            epoch: epoch,
            previousTranscriptHash: previousTranscriptHash,
            members: orderedMembers,
            memberCredentials: orderedLeaves,
            permissions: permissions,
            metadataDigest: metadataDigest,
            authorCredentialHandle: authorCredentialHandle,
            commitDigest: commitDigest,
            signedAt: signedAt
        )
        let transcriptHash = try SignedGroupV2Hash.digest(payload)
        let signatureData = try GroupStateSignatureContextV2(
            groupId: groupId,
            profile: profile,
            epoch: epoch,
            transcriptHash: transcriptHash,
            commitDigest: commitDigest
        ).signableData()
        return SignedGroupStateV2(
            profile: profile,
            cipherSuite: cipherSuite,
            groupId: groupId,
            epoch: epoch,
            previousTranscriptHash: previousTranscriptHash,
            members: orderedMembers,
            memberCredentials: orderedLeaves,
            permissions: permissions,
            metadataDigest: metadataDigest,
            authorCredentialHandle: authorCredentialHandle,
            commitDigest: commitDigest,
            confirmedTranscriptHash: transcriptHash,
            signedAt: signedAt,
            signature: try signingKey.sign(signatureData)
        )
    }
}

public struct SignedGroupWelcomeV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let version: Int
    public let profile: GroupProtocolProfile
    public let cipherSuite: String
    public let groupId: UUID
    public let epoch: UInt64
    public let stateTranscriptHash: Data
    public let commitDigest: Data
    public let authorCredentialHandle: GroupScopedCredentialHandleV2
    public let destinationCredentialHandle: GroupScopedCredentialHandleV2
    public let destinationAdmissionDigest: Data
    public let encryptedWelcome: Data
    public let createdAt: Date
    public let expiresAt: Date
    public let signature: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case version
        case profile
        case cipherSuite
        case groupId
        case epoch
        case stateTranscriptHash
        case commitDigest
        case authorCredentialHandle
        case destinationCredentialHandle
        case destinationAdmissionDigest
        case encryptedWelcome
        case createdAt
        case expiresAt
        case signature
    }

    public init(
        id: UUID,
        version: Int = NoctweaveSignedGroupV2.version,
        profile: GroupProtocolProfile,
        cipherSuite: String,
        groupId: UUID,
        epoch: UInt64,
        stateTranscriptHash: Data,
        commitDigest: Data,
        authorCredentialHandle: GroupScopedCredentialHandleV2,
        destinationCredentialHandle: GroupScopedCredentialHandleV2,
        destinationAdmissionDigest: Data,
        encryptedWelcome: Data,
        createdAt: Date,
        expiresAt: Date,
        signature: Data
    ) {
        self.id = id
        self.version = version
        self.profile = profile
        self.cipherSuite = cipherSuite
        self.groupId = groupId
        self.epoch = epoch
        self.stateTranscriptHash = stateTranscriptHash
        self.commitDigest = commitDigest
        self.authorCredentialHandle = authorCredentialHandle
        self.destinationCredentialHandle = destinationCredentialHandle
        self.destinationAdmissionDigest = destinationAdmissionDigest
        self.encryptedWelcome = encryptedWelcome
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.signature = signature
    }

    public init(from decoder: Decoder) throws {
        try requireExactSignedGroupKeys(
            decoder,
            required: Set(CodingKeys.allCases.map(\.rawValue))
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try values.decode(UUID.self, forKey: .id),
            version: try values.decode(Int.self, forKey: .version),
            profile: try values.decode(GroupProtocolProfile.self, forKey: .profile),
            cipherSuite: try values.decode(String.self, forKey: .cipherSuite),
            groupId: try values.decode(UUID.self, forKey: .groupId),
            epoch: try values.decode(UInt64.self, forKey: .epoch),
            stateTranscriptHash: try values.decode(Data.self, forKey: .stateTranscriptHash),
            commitDigest: try values.decode(Data.self, forKey: .commitDigest),
            authorCredentialHandle: try values.decode(
                GroupScopedCredentialHandleV2.self,
                forKey: .authorCredentialHandle
            ),
            destinationCredentialHandle: try values.decode(
                GroupScopedCredentialHandleV2.self,
                forKey: .destinationCredentialHandle
            ),
            destinationAdmissionDigest: try values.decode(
                Data.self,
                forKey: .destinationAdmissionDigest
            ),
            encryptedWelcome: try values.decode(Data.self, forKey: .encryptedWelcome),
            createdAt: try values.decode(Date.self, forKey: .createdAt),
            expiresAt: try values.decode(Date.self, forKey: .expiresAt),
            signature: try values.decode(Data.self, forKey: .signature)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group welcome")
            )
        }
    }

    public static func create(
        id: UUID = UUID(),
        state: SignedGroupStateV2,
        destinationCredentialHandle: GroupScopedCredentialHandleV2,
        encryptedWelcome: Data,
        signingKey: SigningKeyPair,
        createdAt: Date = Date(),
        expiresAt: Date
    ) throws -> SignedGroupWelcomeV2 {
        try requireGroupCredentialAlgorithms(state.memberCredentials)
        guard state.isStructurallyValid,
              let author = state.transitionAuthorCredential,
              author.signingPublicKey == signingKey.publicKeyData,
              let destination = state.activeCredentials.first(where: {
                  $0.credentialHandle == destinationCredentialHandle
              }) else {
            throw SignedGroupV2Error.unknownAuthor
        }
        var welcome = SignedGroupWelcomeV2(
            id: id,
            profile: state.profile,
            cipherSuite: state.cipherSuite,
            groupId: state.groupId,
            epoch: state.epoch,
            stateTranscriptHash: state.confirmedTranscriptHash,
            commitDigest: state.commitDigest,
            authorCredentialHandle: state.authorCredentialHandle,
            destinationCredentialHandle: destinationCredentialHandle,
            destinationAdmissionDigest: destination.admissionDigest,
            encryptedWelcome: encryptedWelcome,
            createdAt: createdAt,
            expiresAt: expiresAt,
            signature: Data()
        )
        guard welcome.isStructurallyValid(excludingSignature: true) else {
            throw SignedGroupV2Error.invalidStructure
        }
        welcome = SignedGroupWelcomeV2(
            id: welcome.id,
            profile: welcome.profile,
            cipherSuite: welcome.cipherSuite,
            groupId: welcome.groupId,
            epoch: welcome.epoch,
            stateTranscriptHash: welcome.stateTranscriptHash,
            commitDigest: welcome.commitDigest,
            authorCredentialHandle: welcome.authorCredentialHandle,
            destinationCredentialHandle: welcome.destinationCredentialHandle,
            destinationAdmissionDigest: welcome.destinationAdmissionDigest,
            encryptedWelcome: welcome.encryptedWelcome,
            createdAt: welcome.createdAt,
            expiresAt: welcome.expiresAt,
            signature: try signingKey.sign(try welcome.signatureContext().signableData())
        )
        return try welcome.verified(against: state, now: createdAt)
    }

    public var isStructurallyValid: Bool {
        isStructurallyValid(excludingSignature: false)
    }

    public func verified(
        against state: SignedGroupStateV2,
        now: Date = Date()
    ) throws -> SignedGroupWelcomeV2 {
        try requireGroupCredentialAlgorithms(state.memberCredentials)
        guard isStructurallyValid else { throw SignedGroupV2Error.invalidStructure }
        guard now.timeIntervalSince1970.isFinite,
              createdAt <= now.addingTimeInterval(NoctweaveSignedGroupV2.maximumClockSkewSeconds),
              now < expiresAt else {
            throw SignedGroupV2Error.invalidStructure
        }
        guard profile == state.profile,
              cipherSuite == state.cipherSuite,
              groupId == state.groupId,
              epoch == state.epoch,
              stateTranscriptHash == state.confirmedTranscriptHash,
              commitDigest == state.commitDigest else {
            throw SignedGroupV2Error.invalidContext
        }
        guard let destination = state.activeCredentials.first(where: {
            $0.credentialHandle == destinationCredentialHandle
        }), destination.admissionDigest == destinationAdmissionDigest else {
            throw SignedGroupV2Error.admissionMismatch
        }
        guard state.isStructurallyValid,
              let author = state.transitionAuthorCredential,
              author.credentialHandle == authorCredentialHandle else {
            throw SignedGroupV2Error.unknownAuthor
        }
        guard try SigningKeyPair.verifyThrowing(
            signature: signature,
            data: try signatureContext().signableData(),
            publicKeyData: author.signingPublicKey
        ) else {
            throw SignedGroupV2Error.invalidWelcomeSignature
        }
        return self
    }

    private func isStructurallyValid(excludingSignature: Bool) -> Bool {
        version == NoctweaveSignedGroupV2.version
            && profile == NoctweaveSignedGroupV2.experimentalProfile
            && cipherSuite == NoctweaveSignedGroupV2.experimentalCipherSuite
            && epoch > 0
            && stateTranscriptHash.count == 32
            && commitDigest.count == 32
            && authorCredentialHandle.isStructurallyValid
            && destinationCredentialHandle.isStructurallyValid
            && destinationAdmissionDigest.count == 32
            && !encryptedWelcome.isEmpty
            && encryptedWelcome.count <= NoctweaveGroupArchitectureV2.maximumWelcomeBytes
            && createdAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && expiresAt > createdAt
            && expiresAt.timeIntervalSince(createdAt)
                <= NoctweaveSignedGroupV2.maximumWelcomeLifetimeSeconds
            && (excludingSignature || signature.count == NoctweaveSignedGroupV2.signatureBytes)
    }

    private func signatureContext() throws -> GroupWelcomeSignatureContextV2 {
        GroupWelcomeSignatureContextV2(
            id: id,
            profile: profile,
            cipherSuite: cipherSuite,
            groupId: groupId,
            epoch: epoch,
            stateTranscriptHash: stateTranscriptHash,
            commitDigest: commitDigest,
            authorCredentialHandle: authorCredentialHandle,
            destinationCredentialHandle: destinationCredentialHandle,
            destinationAdmissionDigest: destinationAdmissionDigest,
            encryptedWelcomeDigest: SignedGroupV2Hash.digest(encryptedWelcome),
            createdAt: createdAt,
            expiresAt: expiresAt
        )
    }
}

private enum SignedGroupStateValidatorV2 {
    static func validate(
        profile: GroupProtocolProfile,
        cipherSuite: String,
        epoch: UInt64,
        members: [GroupMemberV2],
        memberCredentials: [GroupMemberCredentialV2],
        permissions: GroupPermissionPolicy,
        metadataDigest: Data?
    ) throws {
        try requireGroupCredentialAlgorithms(memberCredentials)
        guard profile == NoctweaveSignedGroupV2.experimentalProfile,
              cipherSuite == NoctweaveSignedGroupV2.experimentalCipherSuite else {
            throw SignedGroupV2Error.unsupportedProfile
        }
        guard epoch > 0,
              !members.isEmpty,
              members.count <= NoctweaveGroupArchitectureV2.maximumMembers,
              !memberCredentials.isEmpty,
              memberCredentials.count <= NoctweaveGroupArchitectureV2.maximumGroupCredentials,
              Set(members.map(\.id)).count == members.count,
              Set(memberCredentials.map(\.credentialHandle)).count == memberCredentials.count,
              Set(memberCredentials.map(\.admissionDigest)).count == memberCredentials.count,
              Set(memberCredentials.map(\.signingPublicKey)).count == memberCredentials.count,
              Set(memberCredentials.map(\.agreementPublicKey)).count == memberCredentials.count,
              permissions.isStructurallyValid,
              metadataDigest?.count ?? 32 == 32,
              members.allSatisfy({
                  $0.isStructurallyValid
                      && $0.addedEpoch <= epoch
                      && ($0.removedEpoch.map { $0 <= epoch } ?? true)
              }),
              memberCredentials.allSatisfy({
                  $0.isStructurallyValid
                      && $0.addedEpoch <= epoch
                      && ($0.removedEpoch.map { $0 <= epoch } ?? true)
              }) else {
            throw SignedGroupV2Error.invalidStructure
        }
        let membersById = Dictionary(uniqueKeysWithValues: members.map { ($0.id, $0) })
        guard memberCredentials.allSatisfy({ leaf in
            guard let member = membersById[leaf.memberHandle] else { return false }
            return leaf.addedEpoch >= member.addedEpoch
                && (member.removedEpoch.map { removal in
                    leaf.removedEpoch.map { $0 <= removal } ?? false
                } ?? true)
        }) else {
            throw SignedGroupV2Error.invalidStructure
        }
        for member in members {
            try validateCredentialTimeline(
                for: member,
                credentials: memberCredentials.filter { $0.memberHandle == member.id }
            )
        }
        let activeMembers = members.filter { $0.isActive(at: epoch) }
        let activeMemberHandles = Set(activeMembers.map(\.id))
        let activeLeaves = memberCredentials.filter {
            $0.isActive(at: epoch) && activeMemberHandles.contains($0.memberHandle)
        }
        guard activeLeaves.count <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials else {
            throw SignedGroupV2Error.activeLeafLimitExceeded
        }
        guard activeMembers.allSatisfy({ member in
            activeLeaves.contains { $0.memberHandle == member.id }
        }), activeLeaves.count == activeMembers.count,
            Set(activeLeaves.map(\.memberHandle)).count == activeLeaves.count,
            memberCredentials.filter({ $0.isActive(at: epoch) }).allSatisfy({
            activeMemberHandles.contains($0.memberHandle)
        }) else {
            throw SignedGroupV2Error.invalidTransition
        }
        let activeOwnerIds = Set(activeMembers.filter { $0.role == .owner }.map(\.id))
        guard !activeOwnerIds.isEmpty,
              activeLeaves.contains(where: { activeOwnerIds.contains($0.memberHandle) }) else {
            throw SignedGroupV2Error.wouldRemoveLastOwner
        }
    }

    private static func validateCredentialTimeline(
        for member: GroupMemberV2,
        credentials: [GroupMemberCredentialV2]
    ) throws {
        let ordered = credentials.sorted {
            if $0.addedEpoch != $1.addedEpoch { return $0.addedEpoch < $1.addedEpoch }
            return $0.credentialHandle.rawValue < $1.credentialHandle.rawValue
        }
        guard let first = ordered.first,
              first.addedEpoch == member.addedEpoch else {
            throw SignedGroupV2Error.invalidStructure
        }
        for index in ordered.indices {
            let credential = ordered[index]
            if index < ordered.index(before: ordered.endIndex) {
                let next = ordered[ordered.index(after: index)]
                guard credential.removedEpoch == next.addedEpoch else {
                    throw SignedGroupV2Error.invalidStructure
                }
            } else if credential.removedEpoch != member.removedEpoch {
                throw SignedGroupV2Error.invalidStructure
            }
        }
    }
}

private enum SignedGroupTransitionValidatorV2 {
    static func validate(
        operation: SignedGroupCommitOperationV2,
        currentState: SignedGroupStateV2,
        proposedMembers: [GroupMemberV2],
        proposedCredentials: [GroupMemberCredentialV2],
        proposedPermissions: GroupPermissionPolicy,
        proposedMetadataDigest: Data?,
        actorMember: GroupMemberV2,
        actorLeaf: GroupMemberCredentialV2,
        verifiedAddedLeaf: GroupMemberCredentialV2?,
        nextEpoch: UInt64
    ) throws {
        let oldMembers = dictionary(currentState.members, by: { $0.id })
        let newMembers = dictionary(proposedMembers, by: { $0.id })
        let oldLeaves = dictionary(currentState.memberCredentials, by: { $0.credentialHandle })
        let newLeaves = dictionary(proposedCredentials, by: { $0.credentialHandle })
        guard oldMembers.count == currentState.members.count,
              newMembers.count == proposedMembers.count,
              oldLeaves.count == currentState.memberCredentials.count,
              newLeaves.count == proposedCredentials.count else {
            throw SignedGroupV2Error.invalidTransition
        }

        switch operation {
        case .replaceCredential:
            guard proposedMembers == currentState.members,
                  proposedPermissions == currentState.permissions,
                  proposedMetadataDigest == currentState.metadataDigest,
                  Set(oldLeaves.keys).isSubset(of: Set(newLeaves.keys)),
                  newLeaves.count == oldLeaves.count + 1,
                  let added = newLeaves.first(where: { oldLeaves[$0.key] == nil })?.value,
                  added == verifiedAddedLeaf,
                  added.memberHandle == actorMember.id,
                  added.credentialHandle != actorLeaf.credentialHandle,
                  added.addedEpoch == nextEpoch,
                  added.removedEpoch == nil else {
                throw SignedGroupV2Error.invalidTransition
            }
            let changed = oldLeaves.compactMap { handle, old -> (GroupMemberCredentialV2, GroupMemberCredentialV2)? in
                guard let new = newLeaves[handle], new != old else { return nil }
                return (old, new)
            }
            guard changed.count == 1,
                  changed[0].0 == actorLeaf,
                  isRemoval(from: actorLeaf, to: changed[0].1, at: nextEpoch),
                  oldLeaves.allSatisfy({ handle, old in
                      handle == actorLeaf.credentialHandle
                          ? newLeaves[handle] == changed[0].1
                          : newLeaves[handle] == old
                  }) else {
                throw SignedGroupV2Error.invalidTransition
            }

        case .addMember:
            try requirePermission(.addMember, state: currentState, actor: actorMember)
            guard proposedPermissions == currentState.permissions,
                  proposedMetadataDigest == currentState.metadataDigest,
                  Set(oldMembers.keys).isSubset(of: Set(newMembers.keys)),
                  newMembers.count == oldMembers.count + 1,
                  oldMembers.allSatisfy({ newMembers[$0.key] == $0.value }),
                  Set(oldLeaves.keys).isSubset(of: Set(newLeaves.keys)),
                  newLeaves.count == oldLeaves.count + 1,
                  oldLeaves.allSatisfy({ newLeaves[$0.key] == $0.value }),
                  let addedMember = newMembers.first(where: { oldMembers[$0.key] == nil })?.value,
                  let addedLeaf = newLeaves.first(where: { oldLeaves[$0.key] == nil })?.value,
                  addedLeaf == verifiedAddedLeaf,
                  addedMember.addedEpoch == nextEpoch,
                  addedMember.removedEpoch == nil,
                  addedLeaf.memberHandle == addedMember.id,
                  addedLeaf.addedEpoch == nextEpoch,
                  addedLeaf.removedEpoch == nil,
                  roleRank(addedMember.role) <= roleRank(actorMember.role) else {
                throw SignedGroupV2Error.invalidTransition
            }

        case .removeMember:
            guard proposedPermissions == currentState.permissions,
                  proposedMetadataDigest == currentState.metadataDigest,
                  Set(oldMembers.keys) == Set(newMembers.keys),
                  Set(oldLeaves.keys) == Set(newLeaves.keys) else {
                throw SignedGroupV2Error.invalidTransition
            }
            let changedMembers = oldMembers.compactMap { key, old -> (GroupMemberV2, GroupMemberV2)? in
                guard let new = newMembers[key], new != old else { return nil }
                return (old, new)
            }
            guard changedMembers.count == 1,
                  isRemoval(from: changedMembers[0].0, to: changedMembers[0].1, at: nextEpoch),
                  changedMembers[0].0.isActive(at: currentState.epoch) else {
                throw SignedGroupV2Error.invalidTransition
            }
            let target = changedMembers[0].0
            for (handle, oldLeaf) in oldLeaves {
                guard let newLeaf = newLeaves[handle] else {
                    throw SignedGroupV2Error.invalidTransition
                }
                if oldLeaf.memberHandle == target.id && oldLeaf.isActive(at: currentState.epoch) {
                    guard isRemoval(from: oldLeaf, to: newLeaf, at: nextEpoch) else {
                        throw SignedGroupV2Error.invalidTransition
                    }
                } else if oldLeaf != newLeaf {
                    throw SignedGroupV2Error.invalidTransition
                }
            }
            if target.id != actorMember.id {
                try requirePermission(.removeMember, state: currentState, actor: actorMember)
                try requireMayModerate(actor: actorMember, target: target)
            }

        case .changeRole:
            try requirePermission(.updatePolicy, state: currentState, actor: actorMember)
            guard proposedPermissions == currentState.permissions,
                  proposedMetadataDigest == currentState.metadataDigest,
                  proposedCredentials == currentState.memberCredentials,
                  Set(oldMembers.keys) == Set(newMembers.keys) else {
                throw SignedGroupV2Error.invalidTransition
            }
            let changed = oldMembers.compactMap { key, old -> (GroupMemberV2, GroupMemberV2)? in
                guard let new = newMembers[key], new != old else { return nil }
                return (old, new)
            }
            guard changed.count == 1,
                  changed[0].0.id == changed[0].1.id,
                  changed[0].0.addedEpoch == changed[0].1.addedEpoch,
                  changed[0].0.removedEpoch == changed[0].1.removedEpoch,
                  changed[0].0.role != changed[0].1.role,
                  changed[0].0.isActive(at: currentState.epoch) else {
                throw SignedGroupV2Error.invalidTransition
            }
            try requireMayChangeRole(
                actor: actorMember,
                target: changed[0].0,
                newRole: changed[0].1.role
            )

        case .changePolicy:
            try requirePermission(.updatePolicy, state: currentState, actor: actorMember)
            guard proposedMembers == currentState.members,
                  proposedCredentials == currentState.memberCredentials,
                  proposedMetadataDigest == currentState.metadataDigest,
                  proposedPermissions != currentState.permissions,
                  proposedPermissions.isStructurallyValid else {
                throw SignedGroupV2Error.invalidTransition
            }

        case .updateMetadata:
            try requirePermission(.updateMetadata, state: currentState, actor: actorMember)
            guard proposedMembers == currentState.members,
                  proposedCredentials == currentState.memberCredentials,
                  proposedPermissions == currentState.permissions,
                  proposedMetadataDigest != currentState.metadataDigest,
                  proposedMetadataDigest?.count ?? 32 == 32 else {
                throw SignedGroupV2Error.invalidTransition
            }

        case .deleteGroup:
            // Deletion is a terminal tombstone, never another live state.
            throw SignedGroupV2Error.invalidTransition
        }
    }

    private static func requirePermission(
        _ permission: GroupPermission,
        state: SignedGroupStateV2,
        actor: GroupMemberV2
    ) throws {
        guard state.permissions.allows(permission, for: actor.role) else {
            throw SignedGroupV2Error.unauthorized
        }
    }

    private static func requireMayModerate(actor: GroupMemberV2, target: GroupMemberV2) throws {
        guard actor.role == .owner || roleRank(actor.role) > roleRank(target.role) else {
            throw SignedGroupV2Error.unauthorized
        }
    }

    /// Self-service role changes are strict demotions only. Changing another
    /// member requires the actor to outrank the target before the change, and the
    /// actor cannot grant a role above their own. The state validator separately
    /// preserves the invariant that at least one active owner remains.
    private static func requireMayChangeRole(
        actor: GroupMemberV2,
        target: GroupMemberV2,
        newRole: GroupRole
    ) throws {
        let actorRank = roleRank(actor.role)
        let targetRank = roleRank(target.role)
        let newRank = roleRank(newRole)
        if actor.id == target.id {
            guard newRank < actorRank else {
                throw SignedGroupV2Error.unauthorized
            }
            return
        }
        guard actorRank > targetRank, newRank <= actorRank else {
            throw SignedGroupV2Error.unauthorized
        }
    }

    private static func roleRank(_ role: GroupRole) -> Int {
        switch role {
        case .member: return 0
        case .admin: return 1
        case .owner: return 2
        }
    }

    private static func isRemoval(
        from old: GroupMemberV2,
        to new: GroupMemberV2,
        at epoch: UInt64
    ) -> Bool {
        old.id == new.id
            && old.role == new.role
            && old.addedEpoch == new.addedEpoch
            && old.removedEpoch == nil
            && new.removedEpoch == epoch
    }

    private static func isRemoval(
        from old: GroupMemberCredentialV2,
        to new: GroupMemberCredentialV2,
        at epoch: UInt64
    ) -> Bool {
        old.memberHandle == new.memberHandle
            && old.credentialHandle == new.credentialHandle
            && old.admissionDigest == new.admissionDigest
            && old.signingPublicKey == new.signingPublicKey
            && old.agreementPublicKey == new.agreementPublicKey
            && old.addedEpoch == new.addedEpoch
            && old.removedEpoch == nil
            && new.removedEpoch == epoch
    }

    private static func dictionary<Element, Key: Hashable>(
        _ elements: [Element],
        by key: (Element) -> Key
    ) -> [Key: Element] {
        var result: [Key: Element] = [:]
        for element in elements { result[key(element)] = element }
        return result
    }
}

fileprivate struct GroupCredentialAdmissionPayloadV2: Encodable {
    let version: Int
    let id: UUID
    let groupId: UUID
    let memberHandle: GroupScopedMemberHandleV2
    let credentialHandle: GroupScopedCredentialHandleV2
    let selection: GroupProtocolSelectionV2
    let groupSigningPublicKey: Data
    let groupAgreementPublicKey: Data
    let contentTypes: [ContentTypeCapabilityV2]
    let issuedAt: Date
    let expiresAt: Date
}

private struct GroupAdmissionProjectionSignatureContextV2: Encodable {
    let purpose = "Noctweave/group-credential-admission-projection/v2"
    let groupId: UUID
    let memberHandle: GroupScopedMemberHandleV2
    let credentialHandle: GroupScopedCredentialHandleV2
    let payloadDigest: Data

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

fileprivate struct GroupDeletionTombstonePayloadV2: Encodable {
    let version: Int
    let id: UUID
    let operation: SignedGroupCommitOperationV2
    let selection: GroupProtocolSelectionV2
    let groupId: UUID
    let baseEpoch: UInt64
    let deletedEpoch: UInt64
    let previousTranscriptHash: Data
    let authorCredentialHandle: GroupScopedCredentialHandleV2
    let reasonDigest: Data?
    let idempotencyKey: Data
    let createdAt: Date
}

private struct GroupDeletionSignatureContextV2: Encodable {
    let purpose = "Noctweave/group-deletion-tombstone/v2"
    let groupId: UUID
    let deletedEpoch: UInt64
    let tombstoneDigest: Data

    func signableData() throws -> Data {
        try NoctweaveCoder.encode(self, sortedKeys: true)
    }
}

private struct GroupDeletionTerminalTranscriptV2: Encodable {
    let purpose = "Noctweave/group-deleted-terminal-state/v2"
    let selection: GroupProtocolSelectionV2
    let groupId: UUID
    let deletedEpoch: UInt64
    let previousTranscriptHash: Data
    let tombstoneDigest: Data
}

fileprivate struct GroupCommitPayloadV2: Encodable {
    let version: Int
    let id: UUID
    let profile: GroupProtocolProfile
    let cipherSuite: String
    let groupId: UUID
    let operation: SignedGroupCommitOperationV2
    let baseEpoch: UInt64
    let nextEpoch: UInt64
    let previousTranscriptHash: Data
    let proposedMembers: [GroupMemberV2]
    let proposedCredentials: [GroupMemberCredentialV2]
    let admissionProjection: GroupCredentialAdmissionV2?
    let proposedPermissions: GroupPermissionPolicy
    let proposedMetadataDigest: Data?
    let authorCredentialHandle: GroupScopedCredentialHandleV2
    let providerCommitDigest: Data
    let idempotencyKey: Data
    let createdAt: Date
}

private struct GroupCommitSignatureContextV2: Encodable {
    let purpose = "Noctweave/signed-group-commit/v2"
    let groupId: UUID
    let profile: GroupProtocolProfile
    let nextEpoch: UInt64
    let commitDigest: Data
    func signableData() throws -> Data { try NoctweaveCoder.encode(self, sortedKeys: true) }
}

fileprivate struct GroupStateTranscriptPayloadV2: Encodable {
    let version: Int
    let profile: GroupProtocolProfile
    let cipherSuite: String
    let groupId: UUID
    let epoch: UInt64
    let previousTranscriptHash: Data?
    let members: [GroupMemberV2]
    let memberCredentials: [GroupMemberCredentialV2]
    let permissions: GroupPermissionPolicy
    let metadataDigest: Data?
    let authorCredentialHandle: GroupScopedCredentialHandleV2
    let commitDigest: Data
    let signedAt: Date
}

private struct GroupStateSignatureContextV2: Encodable {
    let purpose = "Noctweave/signed-group-state/v2"
    let groupId: UUID
    let profile: GroupProtocolProfile
    let epoch: UInt64
    let transcriptHash: Data
    let commitDigest: Data
    func signableData() throws -> Data { try NoctweaveCoder.encode(self, sortedKeys: true) }
}

private struct GroupWelcomeSignatureContextV2: Encodable {
    let purpose = "Noctweave/signed-group-welcome/v2"
    let id: UUID
    let profile: GroupProtocolProfile
    let cipherSuite: String
    let groupId: UUID
    let epoch: UInt64
    let stateTranscriptHash: Data
    let commitDigest: Data
    let authorCredentialHandle: GroupScopedCredentialHandleV2
    let destinationCredentialHandle: GroupScopedCredentialHandleV2
    let destinationAdmissionDigest: Data
    let encryptedWelcomeDigest: Data
    let createdAt: Date
    let expiresAt: Date
    func signableData() throws -> Data { try NoctweaveCoder.encode(self, sortedKeys: true) }
}

private enum SignedGroupV2Hash {
    static func digest<T: Encodable>(_ value: T) throws -> Data {
        Data(SHA256.hash(data: try NoctweaveCoder.encode(value, sortedKeys: true)))
    }

    static func digest(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}

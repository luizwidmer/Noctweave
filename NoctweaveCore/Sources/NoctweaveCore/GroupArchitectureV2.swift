import CryptoKit
import Foundation

private struct StrictGroupArchitectureCodingKey: CodingKey {
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

private func requireExactGroupArchitectureKeys<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ keyType: Key.Type,
    optional: Set<String> = []
) throws where Key.AllCases: Collection {
    let strict = try decoder.container(keyedBy: StrictGroupArchitectureCodingKey.self)
    let expected = Set(keyType.allCases.map(\.stringValue))
    let required = expected.subtracting(optional)
    let actual = Set(strict.allKeys.map(\.stringValue))
    guard required.isSubset(of: actual), actual.isSubset(of: expected) else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "Group fields must match the current schema exactly"
            )
        )
    }
}

public enum NoctweaveGroupArchitectureV2 {
    public static let version = 2
    public static let moduleVersion: UInt16 = 2
    public static let maximumMembers = 1_024
    /// The current O(n) experimental PQ provider seals one epoch secret per
    /// active credential. Keep its operational bound below the larger abstract
    /// state-model ceiling reserved for future providers.
    public static let maximumActiveExperimentalCredentials = 128
    public static let maximumGroupCredentials = 4_096
    public static let maximumCryptoStateBytes = 16 * 1_024 * 1_024
    public static let maximumCommitBytes = 8 * 1_024 * 1_024
    public static let maximumWelcomeBytes = 4 * 1_024 * 1_024
}

/// Aggregate structural predicates intentionally remain nonthrowing for UI and
/// persistence inspection. Throwing protocol paths call this probe first so a
/// missing local ML-DSA/ML-KEM runtime is never misclassified as peer-invalid
/// key material.
enum GroupCryptographicRuntimeProbeV2 {
    static func requireAlgorithms(
        signingPublicKey: Data = Data(),
        agreementPublicKey: Data = Data()
    ) throws {
        _ = try SigningKeyPair.isValidPublicKeyThrowing(signingPublicKey)
        _ = try AgreementKeyPair.isValidPublicKeyThrowing(agreementPublicKey)
    }
}

/// Names are deliberately explicit about interoperability and review status.
public enum GroupProtocolProfile: String, Codable, Equatable, Hashable, CaseIterable {
    /// The existing Noctweave post-quantum construction. It is not RFC 9420 MLS.
    case noctweavePQExperimentalV2 = "nw.pq-group.experimental-2"

    /// Reserved for a provider that independently demonstrates RFC 9420 conformance.
    case mlsRFC9420V1 = "mls.rfc9420-1"

    /// Reserved for a separately negotiated and reviewed post-quantum MLS profile.
    case mlsPQHybridExperimentalV1 = "mls.pq-hybrid.experimental-1"

    public var isExperimental: Bool {
        switch self {
        case .mlsRFC9420V1:
            return false
        case .noctweavePQExperimentalV2, .mlsPQHybridExperimentalV1:
            return true
        }
    }

    /// A profile identifier being present in the source registry is not an
    /// implementation claim. Only exact profile/ciphersuite pairs returned
    /// here may be selected by the current provider boundary.
    public var implementedCipherSuite: String? {
        switch self {
        case .noctweavePQExperimentalV2:
            return NoctweaveSignedGroupV2.experimentalCipherSuite
        case .mlsRFC9420V1, .mlsPQHybridExperimentalV1:
            return nil
        }
    }
}

public enum GroupProtocolNegotiationErrorV2: Error, Equatable {
    case invalidOffer
    case noSharedProfile
    case unsupportedSelection
    case downgradeRejected
}

public struct GroupProtocolSuiteOfferV2: Codable, Equatable, Hashable {
    public let profile: GroupProtocolProfile
    public let cipherSuite: String

    public init(profile: GroupProtocolProfile, cipherSuite: String) {
        self.profile = profile
        self.cipherSuite = cipherSuite
    }

    public var isStructurallyValid: Bool {
        !cipherSuite.isEmpty
            && cipherSuite.utf8.count <= 192
            && cipherSuite.unicodeScalars.allSatisfy {
                !CharacterSet.controlCharacters.contains($0)
            }
    }
}

/// Group-protocol support advertised for one group join. It is intentionally
/// independent of any pairwise relationship or transport capability state.
public struct GroupProtocolOfferV2: Codable, Equatable {
    public let moduleVersion: UInt16
    public let suites: [GroupProtocolSuiteOfferV2]

    public init(
        moduleVersion: UInt16 = NoctweaveGroupArchitectureV2.moduleVersion,
        suites: [GroupProtocolSuiteOfferV2]
    ) {
        self.moduleVersion = moduleVersion
        self.suites = Array(Set(suites)).sorted {
            if $0.profile.rawValue != $1.profile.rawValue {
                return $0.profile.rawValue < $1.profile.rawValue
            }
            return $0.cipherSuite < $1.cipherSuite
        }
    }

    public static let currentExperimental = GroupProtocolOfferV2(suites: [
        GroupProtocolSuiteOfferV2(
            profile: .noctweavePQExperimentalV2,
            cipherSuite: NoctweaveSignedGroupV2.experimentalCipherSuite
        )
    ])

    public var isStructurallyValid: Bool {
        moduleVersion == NoctweaveGroupArchitectureV2.moduleVersion
            && !suites.isEmpty
            && suites.count <= GroupProtocolProfile.allCases.count
            && Set(suites).count == suites.count
            && suites.allSatisfy(\.isStructurallyValid)
    }
}

public struct GroupProtocolSelectionV2: Codable, Equatable, Hashable {
    public let moduleVersion: UInt16
    public let profile: GroupProtocolProfile
    public let cipherSuite: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case moduleVersion
        case profile
        case cipherSuite
    }

    public init(
        moduleVersion: UInt16 = NoctweaveGroupArchitectureV2.moduleVersion,
        profile: GroupProtocolProfile,
        cipherSuite: String
    ) {
        self.moduleVersion = moduleVersion
        self.profile = profile
        self.cipherSuite = cipherSuite
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupArchitectureKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            moduleVersion: try values.decode(UInt16.self, forKey: .moduleVersion),
            profile: try values.decode(GroupProtocolProfile.self, forKey: .profile),
            cipherSuite: try values.decode(String.self, forKey: .cipherSuite)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group selection")
            )
        }
    }

    public static let currentExperimental = GroupProtocolSelectionV2(
        profile: .noctweavePQExperimentalV2,
        cipherSuite: NoctweaveSignedGroupV2.experimentalCipherSuite
    )

    public var isStructurallyValid: Bool {
        moduleVersion == NoctweaveGroupArchitectureV2.moduleVersion
            && profile.implementedCipherSuite == cipherSuite
    }

    public var digest: Data? {
        guard isStructurallyValid,
              let encoded = try? NoctweaveCoder.encode(self, sortedKeys: true) else {
            return nil
        }
        return Data(SHA256.hash(data: encoded))
    }
}

public enum GroupProtocolNegotiationV2 {
    /// Negotiates one exact implemented pair. A caller resuming persisted
    /// state supplies `required`; any different result is a downgrade rather
    /// than a new negotiation.
    public static func negotiate(
        local: GroupProtocolOfferV2,
        peer: GroupProtocolOfferV2,
        required: GroupProtocolSelectionV2? = nil
    ) throws -> GroupProtocolSelectionV2 {
        guard local.isStructurallyValid, peer.isStructurallyValid else {
            throw GroupProtocolNegotiationErrorV2.invalidOffer
        }
        if let required {
            guard required.isStructurallyValid else {
                throw GroupProtocolNegotiationErrorV2.unsupportedSelection
            }
            let requiredOffer = GroupProtocolSuiteOfferV2(
                profile: required.profile,
                cipherSuite: required.cipherSuite
            )
            guard local.suites.contains(requiredOffer),
                  peer.suites.contains(requiredOffer) else {
                throw GroupProtocolNegotiationErrorV2.downgradeRejected
            }
            return required
        }
        let shared = Set(local.suites).intersection(peer.suites)
            .compactMap { offered -> GroupProtocolSelectionV2? in
                let selection = GroupProtocolSelectionV2(
                    profile: offered.profile,
                    cipherSuite: offered.cipherSuite
                )
                return selection.isStructurallyValid ? selection : nil
            }
            .sorted { $0.profile.rawValue < $1.profile.rawValue }
        guard let selection = shared.first else {
            throw GroupProtocolNegotiationErrorV2.noSharedProfile
        }
        return selection
    }
}

public enum GroupRole: String, Codable, Equatable, Hashable, CaseIterable {
    case member
    case admin
    case owner

    fileprivate var authorityLevel: Int {
        switch self {
        case .member: return 0
        case .admin: return 1
        case .owner: return 2
        }
    }
}

public enum GroupPermission: String, Codable, Equatable, Hashable, CaseIterable {
    case addMember
    case removeMember
    case manageInvitations
    case updateMetadata
    case updatePolicy
    case deleteGroup
}

public enum GroupPermissionRule: String, Codable, Equatable, Hashable, CaseIterable {
    case everyone
    case admin
    case owner
    case nobody

    fileprivate func allows(role: GroupRole) -> Bool {
        switch self {
        case .everyone:
            return true
        case .admin:
            return role.authorityLevel >= GroupRole.admin.authorityLevel
        case .owner:
            return role == .owner
        case .nobody:
            return false
        }
    }
}

public struct GroupPermissionEntry: Codable, Equatable {
    public let permission: GroupPermission
    public let rule: GroupPermissionRule

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case permission
        case rule
    }

    public init(permission: GroupPermission, rule: GroupPermissionRule) {
        self.permission = permission
        self.rule = rule
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupArchitectureKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            permission: try values.decode(GroupPermission.self, forKey: .permission),
            rule: try values.decode(GroupPermissionRule.self, forKey: .rule)
        )
    }
}

/// A complete policy is carried in every signed group state rather than inferred by a relay.
public struct GroupPermissionPolicy: Codable, Equatable {
    public let entries: [GroupPermissionEntry]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case entries
    }

    public init(entries: [GroupPermissionEntry]) {
        self.entries = entries.sorted { $0.permission.rawValue < $1.permission.rawValue }
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupArchitectureKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let decoded = try values.decode([GroupPermissionEntry].self, forKey: .entries)
        self.init(entries: decoded)
        guard entries == decoded, isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group policy")
            )
        }
    }

    public static let `default` = GroupPermissionPolicy(entries: [
        GroupPermissionEntry(permission: .addMember, rule: .admin),
        GroupPermissionEntry(permission: .removeMember, rule: .admin),
        GroupPermissionEntry(permission: .manageInvitations, rule: .admin),
        GroupPermissionEntry(permission: .updateMetadata, rule: .admin),
        GroupPermissionEntry(permission: .updatePolicy, rule: .owner),
        GroupPermissionEntry(permission: .deleteGroup, rule: .owner)
    ])

    public var isStructurallyValid: Bool {
        entries.count == GroupPermission.allCases.count
            && Set(entries.map(\.permission)).count == entries.count
            && Set(entries.map(\.permission)) == Set(GroupPermission.allCases)
    }

    public func rule(for permission: GroupPermission) -> GroupPermissionRule? {
        entries.first { $0.permission == permission }?.rule
    }

    public func allows(_ permission: GroupPermission, for role: GroupRole) -> Bool {
        guard isStructurallyValid, let rule = rule(for: permission) else { return false }
        return rule.allows(role: role)
    }
}

/// An opaque member handle generated independently for exactly one group.
/// A local application may privately associate it with a pairwise
/// relationship, but that association is never group protocol state.
public struct GroupScopedMemberHandleV2: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case rawValue
    }

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public static func generate() -> GroupScopedMemberHandleV2 {
        var generator = SystemRandomNumberGenerator()
        while true {
            let bytes = Data((0..<32).map { _ in
                UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
            })
            if bytes.contains(where: { $0 != 0 }) {
                return GroupScopedMemberHandleV2(rawValue: bytes.base64EncodedString())
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
        try requireExactGroupArchitectureKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(rawValue: try values.decode(String.self, forKey: .rawValue))
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawValue,
                in: values,
                debugDescription: "Invalid group-scoped member handle"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid group-scoped member handle"
                )
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(rawValue, forKey: .rawValue)
    }
}

public struct GroupMemberV2: Codable, Equatable, Identifiable {
    public let id: GroupScopedMemberHandleV2
    public let role: GroupRole
    public let addedEpoch: UInt64
    public let removedEpoch: UInt64?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case role
        case addedEpoch
        case removedEpoch
    }

    public init(
        id: GroupScopedMemberHandleV2,
        role: GroupRole,
        addedEpoch: UInt64,
        removedEpoch: UInt64? = nil
    ) {
        self.id = id
        self.role = role
        self.addedEpoch = addedEpoch
        self.removedEpoch = removedEpoch
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupArchitectureKeys(
            decoder,
            CodingKeys.self,
            optional: [CodingKeys.removedEpoch.rawValue]
        )
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try values.decode(GroupScopedMemberHandleV2.self, forKey: .id),
            role: try values.decode(GroupRole.self, forKey: .role),
            addedEpoch: try values.decode(UInt64.self, forKey: .addedEpoch),
            removedEpoch: try values.decodeIfPresent(UInt64.self, forKey: .removedEpoch)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group member")
            )
        }
    }

    public var isStructurallyValid: Bool {
        id.isStructurallyValid
            && addedEpoch > 0
            && (removedEpoch.map { $0 > addedEpoch } ?? true)
    }

    public func isActive(at epoch: UInt64) -> Bool {
        isStructurallyValid
            && addedEpoch <= epoch
            && (removedEpoch.map { $0 > epoch } ?? true)
    }
}

/// One active group member has exactly one active group credential.

public struct GroupCryptoState: Codable, Equatable {
    public let selection: GroupProtocolSelectionV2
    public let groupId: UUID
    public let epoch: UInt64
    public let opaqueState: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case selection
        case groupId
        case epoch
        case opaqueState
    }

    public init(
        selection: GroupProtocolSelectionV2,
        groupId: UUID,
        epoch: UInt64,
        opaqueState: Data
    ) {
        self.selection = selection
        self.groupId = groupId
        self.epoch = epoch
        self.opaqueState = opaqueState
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupArchitectureKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            selection: try values.decode(GroupProtocolSelectionV2.self, forKey: .selection),
            groupId: try values.decode(UUID.self, forKey: .groupId),
            epoch: try values.decode(UInt64.self, forKey: .epoch),
            opaqueState: try values.decode(Data.self, forKey: .opaqueState)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group crypto state")
            )
        }
    }

    public var profile: GroupProtocolProfile { selection.profile }
    public var cipherSuite: String { selection.cipherSuite }

    public var isStructurallyValid: Bool {
        epoch > 0
            && !opaqueState.isEmpty
            && opaqueState.count <= NoctweaveGroupArchitectureV2.maximumCryptoStateBytes
            && selection.isStructurallyValid
    }
}

/// The cryptographic provider sees only fresh group-scoped handles and keys.
/// Any local association with a persona, relationship, route, or transport is
/// intentionally outside this boundary.
public struct GroupProviderCredentialV2: Codable, Equatable, Identifiable {
    public var id: GroupScopedCredentialHandleV2 { credentialHandle }
    public let memberHandle: GroupScopedMemberHandleV2
    public let credentialHandle: GroupScopedCredentialHandleV2
    public let admissionDigest: Data
    public let signingPublicKey: Data
    public let agreementPublicKey: Data

    public init(
        memberHandle: GroupScopedMemberHandleV2,
        credentialHandle: GroupScopedCredentialHandleV2,
        admissionDigest: Data,
        signingPublicKey: Data,
        agreementPublicKey: Data
    ) {
        self.memberHandle = memberHandle
        self.credentialHandle = credentialHandle
        self.admissionDigest = admissionDigest
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
    }

    public var isStructurallyValid: Bool {
        memberHandle.isStructurallyValid
            && credentialHandle.isStructurallyValid
            && admissionDigest.count == 32
            && SigningKeyPair.isValidPublicKey(signingPublicKey)
            && AgreementKeyPair.isValidPublicKey(agreementPublicKey)
    }
}

public struct GroupProviderMembershipV2: Codable, Equatable {
    public let groupId: UUID
    public let epoch: UInt64
    public let selection: GroupProtocolSelectionV2
    public let credentials: [GroupProviderCredentialV2]
    /// Digest of the policy-level proposed membership, before a provider
    /// commit or accepted transcript exists.
    public let membershipDigest: Data

    public init(
        groupId: UUID,
        epoch: UInt64,
        selection: GroupProtocolSelectionV2,
        credentials: [GroupProviderCredentialV2],
        membershipDigest: Data
    ) {
        self.groupId = groupId
        self.epoch = epoch
        self.selection = selection
        self.credentials = credentials.sorted { $0.credentialHandle.rawValue < $1.credentialHandle.rawValue }
        self.membershipDigest = membershipDigest
    }

    public var isStructurallyValid: Bool {
        epoch > 0
            && selection.isStructurallyValid
            && !credentials.isEmpty
            && credentials.count <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials
            && Set(credentials.map(\.credentialHandle)).count == credentials.count
            && Set(credentials.map(\.memberHandle)).count == credentials.count
            && Set(credentials.map(\.signingPublicKey)).count == credentials.count
            && Set(credentials.map(\.agreementPublicKey)).count == credentials.count
            && credentials.allSatisfy(\.isStructurallyValid)
            && membershipDigest.count == 32
    }
}

/// Provider preparation deliberately stops before the accepted signed
/// transcript. This removes the old circular dependency where provider bytes
/// needed a transcript whose state first needed the provider-byte digest.
public struct GroupCryptoEpochProposalV2: Codable, Equatable {
    public let groupId: UUID
    public let baseEpoch: UInt64
    public let nextEpoch: UInt64
    public let selection: GroupProtocolSelectionV2
    public let currentMembershipDigest: Data?
    public let proposedMembershipDigest: Data
    public let authorCredentialHandle: GroupScopedCredentialHandleV2

    public init(
        groupId: UUID,
        baseEpoch: UInt64,
        nextEpoch: UInt64,
        selection: GroupProtocolSelectionV2,
        currentMembershipDigest: Data?,
        proposedMembershipDigest: Data,
        authorCredentialHandle: GroupScopedCredentialHandleV2
    ) {
        self.groupId = groupId
        self.baseEpoch = baseEpoch
        self.nextEpoch = nextEpoch
        self.selection = selection
        self.currentMembershipDigest = currentMembershipDigest
        self.proposedMembershipDigest = proposedMembershipDigest
        self.authorCredentialHandle = authorCredentialHandle
    }

    public var isStructurallyValid: Bool {
        baseEpoch < UInt64.max
            && nextEpoch == baseEpoch + 1
            && selection.isStructurallyValid
            && currentMembershipDigest.map { $0.count == 32 } ?? (baseEpoch == 0)
            && (baseEpoch == 0 ? currentMembershipDigest == nil : currentMembershipDigest != nil)
            && proposedMembershipDigest.count == 32
            && authorCredentialHandle.isStructurallyValid
    }
}

public struct GroupWelcomePackage: Codable, Equatable {
    public let destination: GroupScopedCredentialHandleV2
    public let bytes: Data

    public init(destination: GroupScopedCredentialHandleV2, bytes: Data) {
        self.destination = destination
        self.bytes = bytes
    }

    public var isStructurallyValid: Bool {
        destination.isStructurallyValid
            && !bytes.isEmpty
            && bytes.count <= NoctweaveGroupArchitectureV2.maximumWelcomeBytes
    }
}

public struct GroupCryptoPreparedEpochV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let proposal: GroupCryptoEpochProposalV2
    /// Provisional state is not usable for application messages until
    /// `finalizePreparedEpoch` binds the accepted signed transcript.
    public let provisionalState: GroupCryptoState
    public let commitBytes: Data
    public let welcomes: [GroupWelcomePackage]

    public init(
        id: UUID = UUID(),
        proposal: GroupCryptoEpochProposalV2,
        provisionalState: GroupCryptoState,
        commitBytes: Data,
        welcomes: [GroupWelcomePackage]
    ) {
        self.id = id
        self.proposal = proposal
        self.provisionalState = provisionalState
        self.commitBytes = commitBytes
        self.welcomes = welcomes.sorted { $0.destination.rawValue < $1.destination.rawValue }
    }

    public var providerCommitDigest: Data? {
        guard !commitBytes.isEmpty else { return nil }
        return Data(SHA256.hash(data: commitBytes))
    }

    public var isStructurallyValid: Bool {
        proposal.isStructurallyValid
            && provisionalState.isStructurallyValid
            && provisionalState.groupId == proposal.groupId
            && provisionalState.epoch == proposal.nextEpoch
            && provisionalState.selection == proposal.selection
            && !commitBytes.isEmpty
            && commitBytes.count <= NoctweaveGroupArchitectureV2.maximumCommitBytes
            && welcomes.count <= NoctweaveGroupArchitectureV2.maximumGroupCredentials
            && Set(welcomes.map(\.destination)).count == welcomes.count
            && welcomes.allSatisfy(\.isStructurallyValid)
    }
}

public struct GroupCryptoAcceptedEpochV2: Codable, Equatable {
    public let proposal: GroupCryptoEpochProposalV2
    public let providerCommitDigest: Data
    public let signedCommitDigest: Data
    public let acceptedTranscriptHash: Data

    public init(
        proposal: GroupCryptoEpochProposalV2,
        providerCommitDigest: Data,
        signedCommitDigest: Data,
        acceptedTranscriptHash: Data
    ) {
        self.proposal = proposal
        self.providerCommitDigest = providerCommitDigest
        self.signedCommitDigest = signedCommitDigest
        self.acceptedTranscriptHash = acceptedTranscriptHash
    }

    public var isStructurallyValid: Bool {
        proposal.isStructurallyValid
            && providerCommitDigest.count == 32
            && signedCommitDigest.count == 32
            && acceptedTranscriptHash.count == 32
    }
}

public struct GroupCryptoSealResultV2: Codable, Equatable {
    public let state: GroupCryptoState
    public let ciphertext: Data

    public init(state: GroupCryptoState, ciphertext: Data) {
        self.state = state
        self.ciphertext = ciphertext
    }

    public var isStructurallyValid: Bool {
        state.isStructurallyValid
            && !ciphertext.isEmpty
            && ciphertext.count <= NoctweaveGroupArchitectureV2.maximumCommitBytes
    }
}

public struct GroupCryptoOpenResultV2: Codable, Equatable {
    public let state: GroupCryptoState
    public let plaintext: Data

    public init(state: GroupCryptoState, plaintext: Data) {
        self.state = state
        self.plaintext = plaintext
    }

    public var isStructurallyValid: Bool {
        state.isStructurallyValid
            && plaintext.count <= NoctweaveArchitectureV2.maximumContentPayloadBytes
    }
}

/// Cryptographic providers own epoch secrets and wire encoding;
/// membership policy stays above them. Every stateful operation returns the
/// replacement state, making persistence-before-publication enforceable.

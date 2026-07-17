import CryptoKit
import Foundation

public enum NoctweaveGroupArchitectureV2 {
    public static let version = 2
    public static let moduleVersion: UInt16 = 2
    public static let maximumUsers = 1_024
    /// The current O(n) experimental PQ provider seals one epoch secret per
    /// active client. Keep its operational bound below the larger abstract
    /// state-model ceiling reserved for future providers.
    public static let maximumActiveExperimentalClientLeaves = 128
    public static let maximumClientLeaves = 4_096
    public static let maximumCryptoStateBytes = 16 * 1_024 * 1_024
    public static let maximumCommitBytes = 8 * 1_024 * 1_024
    public static let maximumWelcomeBytes = 4 * 1_024 * 1_024
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

/// Endpoint-advertised group support. This contains only group protocol
/// information; it deliberately does not copy the endpoint's complete
/// capability manifest into group membership state.
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

    public init(
        moduleVersion: UInt16 = NoctweaveGroupArchitectureV2.moduleVersion,
        profile: GroupProtocolProfile,
        cipherSuite: String
    ) {
        self.moduleVersion = moduleVersion
        self.profile = profile
        self.cipherSuite = cipherSuite
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
    case addClient
    case removeClient
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

    public init(permission: GroupPermission, rule: GroupPermissionRule) {
        self.permission = permission
        self.rule = rule
    }
}

/// A complete policy is carried in every signed group state rather than inferred by a relay.
public struct GroupPermissionPolicy: Codable, Equatable {
    public let entries: [GroupPermissionEntry]

    public init(entries: [GroupPermissionEntry]) {
        self.entries = entries.sorted { $0.permission.rawValue < $1.permission.rawValue }
    }

    public static let `default` = GroupPermissionPolicy(entries: [
        GroupPermissionEntry(permission: .addClient, rule: .admin),
        GroupPermissionEntry(permission: .removeClient, rule: .admin),
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

public struct GroupUser: Codable, Equatable, Identifiable {
    public let id: UUID
    public let role: GroupRole
    public let addedEpoch: UInt64
    public let removedEpoch: UInt64?

    public init(id: UUID, role: GroupRole, addedEpoch: UInt64, removedEpoch: UInt64? = nil) {
        self.id = id
        self.role = role
        self.addedEpoch = addedEpoch
        self.removedEpoch = removedEpoch
    }

    public var isStructurallyValid: Bool {
        addedEpoch > 0 && (removedEpoch.map { $0 > addedEpoch } ?? true)
    }

    public func isActive(at epoch: UInt64) -> Bool {
        isStructurallyValid
            && addedEpoch <= epoch
            && (removedEpoch.map { $0 > epoch } ?? true)
    }
}

/// One group leaf is one independently revocable endpoint.
public struct GroupClientLeaf: Codable, Equatable, Identifiable {
    public let id: UUID
    public let userId: UUID
    public let endpointHandle: RelationshipEndpointHandle
    public let keyPackageDigest: Data
    public let addedEpoch: UInt64
    public let removedEpoch: UInt64?

    public init(
        id: UUID,
        userId: UUID,
        endpointHandle: RelationshipEndpointHandle,
        keyPackageDigest: Data,
        addedEpoch: UInt64,
        removedEpoch: UInt64? = nil
    ) {
        self.id = id
        self.userId = userId
        self.endpointHandle = endpointHandle
        self.keyPackageDigest = keyPackageDigest
        self.addedEpoch = addedEpoch
        self.removedEpoch = removedEpoch
    }

    public var isStructurallyValid: Bool {
        endpointHandle.isStructurallyValid
            && keyPackageDigest.count == 32
            && addedEpoch > 0
            && (removedEpoch.map { $0 > addedEpoch } ?? true)
    }

    public func isActive(at epoch: UInt64) -> Bool {
        isStructurallyValid
            && addedEpoch <= epoch
            && (removedEpoch.map { $0 > epoch } ?? true)
    }

    public func revoked(at epoch: UInt64) -> GroupClientLeaf? {
        guard removedEpoch == nil, epoch > addedEpoch else { return nil }
        return GroupClientLeaf(
            id: id,
            userId: userId,
            endpointHandle: endpointHandle,
            keyPackageDigest: keyPackageDigest,
            addedEpoch: addedEpoch,
            removedEpoch: epoch
        )
    }
}

public enum GroupArchitectureError: Error, Equatable {
    case invalidState
    case staleEpoch
    case unknownActor
    case unauthorized
    case unknownClient
    case alreadyRemoved
    case wouldRemoveLastOwnerClient
}

public struct GroupMembershipState: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let profile: GroupProtocolProfile
    public let epoch: UInt64
    public let users: [GroupUser]
    public let clientLeaves: [GroupClientLeaf]
    public let permissions: GroupPermissionPolicy
    public let metadataDigest: Data?
    public let confirmedTranscriptHash: Data

    public init(
        version: Int = NoctweaveGroupArchitectureV2.version,
        id: UUID,
        profile: GroupProtocolProfile,
        epoch: UInt64,
        users: [GroupUser],
        clientLeaves: [GroupClientLeaf],
        permissions: GroupPermissionPolicy = .default,
        metadataDigest: Data? = nil,
        confirmedTranscriptHash: Data
    ) {
        self.version = version
        self.id = id
        self.profile = profile
        self.epoch = epoch
        self.users = users.sorted { $0.id.uuidString < $1.id.uuidString }
        self.clientLeaves = clientLeaves.sorted { $0.id.uuidString < $1.id.uuidString }
        self.permissions = permissions
        self.metadataDigest = metadataDigest
        self.confirmedTranscriptHash = confirmedTranscriptHash
    }

    public var activeUsers: [GroupUser] {
        users.filter { $0.isActive(at: epoch) }
    }

    public var activeClientLeaves: [GroupClientLeaf] {
        clientLeaves.filter { leaf in
            leaf.isActive(at: epoch)
                && users.first(where: { $0.id == leaf.userId })?.isActive(at: epoch) == true
        }
    }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveGroupArchitectureV2.version,
              epoch > 0,
              !users.isEmpty,
              users.count <= NoctweaveGroupArchitectureV2.maximumUsers,
              !clientLeaves.isEmpty,
              clientLeaves.count <= NoctweaveGroupArchitectureV2.maximumClientLeaves,
              Set(users.map(\.id)).count == users.count,
              Set(clientLeaves.map(\.id)).count == clientLeaves.count,
              Set(clientLeaves.map(\.endpointHandle)).count == clientLeaves.count,
              users.allSatisfy(\.isStructurallyValid),
              clientLeaves.allSatisfy(\.isStructurallyValid),
              permissions.isStructurallyValid,
              metadataDigest?.count ?? 32 == 32,
              confirmedTranscriptHash.count == 32 else {
            return false
        }

        let usersById = Dictionary(uniqueKeysWithValues: users.map { ($0.id, $0) })
        guard clientLeaves.allSatisfy({ leaf in
            guard let user = usersById[leaf.userId] else { return false }
            return leaf.addedEpoch >= user.addedEpoch
                && (user.removedEpoch.map { removal in
                    leaf.removedEpoch.map { $0 <= removal } ?? false
                } ?? true)
        }) else {
            return false
        }

        let activeOwnerIds = Set(activeUsers.filter { $0.role == .owner }.map(\.id))
        return !activeOwnerIds.isEmpty
            && activeClientLeaves.contains { activeOwnerIds.contains($0.userId) }
    }

    /// Applies a cryptographically committed client-leaf removal without
    /// removing sibling endpoints in the same generation.
    public func revokingClient(
        _ clientLeafId: UUID,
        authorizedBy actorClientLeafId: UUID,
        nextEpoch: UInt64,
        confirmedTranscriptHash nextTranscriptHash: Data
    ) throws -> GroupMembershipState {
        guard isStructurallyValid else { throw GroupArchitectureError.invalidState }
        guard epoch < UInt64.max, nextEpoch == epoch + 1 else {
            throw GroupArchitectureError.staleEpoch
        }
        guard let actorLeaf = activeClientLeaves.first(where: { $0.id == actorClientLeafId }),
              let actorUser = activeUsers.first(where: { $0.id == actorLeaf.userId }) else {
            throw GroupArchitectureError.unknownActor
        }
        guard permissions.allows(.removeClient, for: actorUser.role) else {
            throw GroupArchitectureError.unauthorized
        }
        guard let targetIndex = clientLeaves.firstIndex(where: { $0.id == clientLeafId }) else {
            throw GroupArchitectureError.unknownClient
        }
        guard clientLeaves[targetIndex].isActive(at: epoch) else {
            throw GroupArchitectureError.alreadyRemoved
        }

        let target = clientLeaves[targetIndex]
        if activeUsers.first(where: { $0.id == target.userId })?.role == .owner {
            let activeOwnerLeaves = activeClientLeaves.filter { leaf in
                activeUsers.first(where: { $0.id == leaf.userId })?.role == .owner
            }
            if activeOwnerLeaves.count == 1 {
                throw GroupArchitectureError.wouldRemoveLastOwnerClient
            }
        }

        guard nextTranscriptHash.count == 32, let revoked = target.revoked(at: nextEpoch) else {
            throw GroupArchitectureError.invalidState
        }
        var nextLeaves = clientLeaves
        nextLeaves[targetIndex] = revoked
        let next = GroupMembershipState(
            id: id,
            profile: profile,
            epoch: nextEpoch,
            users: users,
            clientLeaves: nextLeaves,
            permissions: permissions,
            metadataDigest: metadataDigest,
            confirmedTranscriptHash: nextTranscriptHash
        )
        guard next.isStructurallyValid else { throw GroupArchitectureError.invalidState }
        return next
    }
}

public struct GroupCryptoState: Codable, Equatable {
    public let selection: GroupProtocolSelectionV2
    public let groupId: UUID
    public let epoch: UInt64
    public let opaqueState: Data

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

    public var profile: GroupProtocolProfile { selection.profile }
    public var cipherSuite: String { selection.cipherSuite }

    public var isStructurallyValid: Bool {
        epoch > 0
            && !opaqueState.isEmpty
            && opaqueState.count <= NoctweaveGroupArchitectureV2.maximumCryptoStateBytes
            && selection.isStructurallyValid
    }
}

/// The cryptographic provider sees only group-scoped clients. Generation,
/// endpoint, relationship, inbox, and relay identifiers are intentionally not
/// part of this boundary.
public struct GroupProviderClientV2: Codable, Equatable, Identifiable {
    public var id: GroupScopedClientHandleV2 { clientHandle }
    public let userId: UUID
    public let clientHandle: GroupScopedClientHandleV2
    public let keyPackageDigest: Data
    public let signingPublicKey: Data
    public let agreementPublicKey: Data

    public init(
        userId: UUID,
        clientHandle: GroupScopedClientHandleV2,
        keyPackageDigest: Data,
        signingPublicKey: Data,
        agreementPublicKey: Data
    ) {
        self.userId = userId
        self.clientHandle = clientHandle
        self.keyPackageDigest = keyPackageDigest
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
    }

    public var isStructurallyValid: Bool {
        clientHandle.isStructurallyValid
            && keyPackageDigest.count == 32
            && SigningKeyPair.isValidPublicKey(signingPublicKey)
            && AgreementKeyPair.isValidPublicKey(agreementPublicKey)
    }
}

public struct GroupProviderMembershipV2: Codable, Equatable {
    public let groupId: UUID
    public let epoch: UInt64
    public let selection: GroupProtocolSelectionV2
    public let clients: [GroupProviderClientV2]
    /// Digest of the policy-level proposed membership, before a provider
    /// commit or accepted transcript exists.
    public let membershipDigest: Data

    public init(
        groupId: UUID,
        epoch: UInt64,
        selection: GroupProtocolSelectionV2,
        clients: [GroupProviderClientV2],
        membershipDigest: Data
    ) {
        self.groupId = groupId
        self.epoch = epoch
        self.selection = selection
        self.clients = clients.sorted { $0.clientHandle.rawValue < $1.clientHandle.rawValue }
        self.membershipDigest = membershipDigest
    }

    public var isStructurallyValid: Bool {
        epoch > 0
            && selection.isStructurallyValid
            && !clients.isEmpty
            && clients.count <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalClientLeaves
            && Set(clients.map(\.clientHandle)).count == clients.count
            && Set(clients.map(\.signingPublicKey)).count == clients.count
            && Set(clients.map(\.agreementPublicKey)).count == clients.count
            && clients.allSatisfy(\.isStructurallyValid)
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
    public let authorClientHandle: GroupScopedClientHandleV2

    public init(
        groupId: UUID,
        baseEpoch: UInt64,
        nextEpoch: UInt64,
        selection: GroupProtocolSelectionV2,
        currentMembershipDigest: Data?,
        proposedMembershipDigest: Data,
        authorClientHandle: GroupScopedClientHandleV2
    ) {
        self.groupId = groupId
        self.baseEpoch = baseEpoch
        self.nextEpoch = nextEpoch
        self.selection = selection
        self.currentMembershipDigest = currentMembershipDigest
        self.proposedMembershipDigest = proposedMembershipDigest
        self.authorClientHandle = authorClientHandle
    }

    public var isStructurallyValid: Bool {
        baseEpoch < UInt64.max
            && nextEpoch == baseEpoch + 1
            && selection.isStructurallyValid
            && currentMembershipDigest.map { $0.count == 32 } ?? (baseEpoch == 0)
            && (baseEpoch == 0 ? currentMembershipDigest == nil : currentMembershipDigest != nil)
            && proposedMembershipDigest.count == 32
            && authorClientHandle.isStructurallyValid
    }
}

public struct GroupWelcomePackage: Codable, Equatable {
    public let destination: GroupScopedClientHandleV2
    public let bytes: Data

    public init(destination: GroupScopedClientHandleV2, bytes: Data) {
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
            && welcomes.count <= NoctweaveGroupArchitectureV2.maximumClientLeaves
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
public protocol GroupCryptoProvider {
    var selection: GroupProtocolSelectionV2 { get }

    func prepareGenesis(
        membership: GroupProviderMembershipV2,
        localClientHandle: GroupScopedClientHandleV2
    ) throws -> GroupCryptoPreparedEpochV2

    func prepareCommit(
        state: GroupCryptoState,
        currentMembership: GroupProviderMembershipV2,
        proposedMembership: GroupProviderMembershipV2,
        authorClientHandle: GroupScopedClientHandleV2
    ) throws -> GroupCryptoPreparedEpochV2

    func finalizePreparedEpoch(
        _ prepared: GroupCryptoPreparedEpochV2,
        acceptance: GroupCryptoAcceptedEpochV2
    ) throws -> GroupCryptoState

    func processCommit(
        state: GroupCryptoState,
        currentMembership: GroupProviderMembershipV2,
        proposedMembership: GroupProviderMembershipV2,
        acceptance: GroupCryptoAcceptedEpochV2,
        commitBytes: Data
    ) throws -> GroupCryptoState

    func processWelcome(
        _ welcome: GroupWelcomePackage,
        membership: GroupProviderMembershipV2,
        acceptance: GroupCryptoAcceptedEpochV2,
        localClientHandle: GroupScopedClientHandleV2
    ) throws -> GroupCryptoState

    func encryptApplicationEvent(
        _ event: Data,
        authenticatedContext: Data,
        state: GroupCryptoState
    ) throws -> GroupCryptoSealResultV2

    func decryptApplicationEvent(
        _ ciphertext: Data,
        authenticatedContext: Data,
        state: GroupCryptoState
    ) throws -> GroupCryptoOpenResultV2
}

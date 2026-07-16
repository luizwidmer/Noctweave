import Foundation

public enum NoctweaveGroupArchitectureV2 {
    public static let version = 2
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

/// One group leaf is one independently revocable installation endpoint.
public struct GroupClientLeaf: Codable, Equatable, Identifiable {
    public let id: UUID
    public let userId: UUID
    public let installationHandle: RelationshipInstallationHandle
    public let keyPackageDigest: Data
    public let addedEpoch: UInt64
    public let removedEpoch: UInt64?

    public init(
        id: UUID,
        userId: UUID,
        installationHandle: RelationshipInstallationHandle,
        keyPackageDigest: Data,
        addedEpoch: UInt64,
        removedEpoch: UInt64? = nil
    ) {
        self.id = id
        self.userId = userId
        self.installationHandle = installationHandle
        self.keyPackageDigest = keyPackageDigest
        self.addedEpoch = addedEpoch
        self.removedEpoch = removedEpoch
    }

    public var isStructurallyValid: Bool {
        installationHandle.isStructurallyValid
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
            installationHandle: installationHandle,
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
              Set(clientLeaves.map(\.installationHandle)).count == clientLeaves.count,
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
    public let profile: GroupProtocolProfile
    public let groupId: UUID
    public let epoch: UInt64
    public let opaqueState: Data

    public init(profile: GroupProtocolProfile, groupId: UUID, epoch: UInt64, opaqueState: Data) {
        self.profile = profile
        self.groupId = groupId
        self.epoch = epoch
        self.opaqueState = opaqueState
    }

    public var isStructurallyValid: Bool {
        epoch > 0
            && !opaqueState.isEmpty
            && opaqueState.count <= NoctweaveGroupArchitectureV2.maximumCryptoStateBytes
    }
}

public struct GroupWelcomePackage: Codable, Equatable {
    public let destination: RelationshipInstallationHandle
    public let bytes: Data

    public init(destination: RelationshipInstallationHandle, bytes: Data) {
        self.destination = destination
        self.bytes = bytes
    }

    public var isStructurallyValid: Bool {
        destination.isStructurallyValid
            && !bytes.isEmpty
            && bytes.count <= NoctweaveGroupArchitectureV2.maximumWelcomeBytes
    }
}

public struct GroupCryptoCommitOutput: Codable, Equatable {
    public let state: GroupCryptoState
    public let commitBytes: Data
    public let welcomes: [GroupWelcomePackage]

    public init(state: GroupCryptoState, commitBytes: Data, welcomes: [GroupWelcomePackage]) {
        self.state = state
        self.commitBytes = commitBytes
        self.welcomes = welcomes.sorted { $0.destination.rawValue < $1.destination.rawValue }
    }

    public var isStructurallyValid: Bool {
        state.isStructurallyValid
            && !commitBytes.isEmpty
            && commitBytes.count <= NoctweaveGroupArchitectureV2.maximumCommitBytes
            && welcomes.count <= NoctweaveGroupArchitectureV2.maximumClientLeaves
            && Set(welcomes.map(\.destination)).count == welcomes.count
            && welcomes.allSatisfy(\.isStructurallyValid)
    }
}

/// Cryptographic providers own epoch secrets and wire compatibility; membership policy stays above them.
public protocol GroupCryptoProvider {
    var profile: GroupProtocolProfile { get }

    func createGroup(
        membership: GroupMembershipState,
        localClientLeafId: UUID
    ) throws -> GroupCryptoState

    func prepareCommit(
        state: GroupCryptoState,
        currentMembership: GroupMembershipState,
        proposedMembership: GroupMembershipState,
        authorClientLeafId: UUID
    ) throws -> GroupCryptoCommitOutput

    func processCommit(
        state: GroupCryptoState,
        currentMembership: GroupMembershipState,
        commitBytes: Data
    ) throws -> GroupCryptoCommitOutput

    func encryptApplicationEvent(
        _ event: Data,
        authenticatedContext: Data,
        state: GroupCryptoState
    ) throws -> Data

    func decryptApplicationEvent(
        _ ciphertext: Data,
        authenticatedContext: Data,
        state: GroupCryptoState
    ) throws -> Data
}

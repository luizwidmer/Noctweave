import CryptoKit
import Foundation

private struct StrictGroupRuntimeCodingKey: CodingKey {
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

private func requireExactGroupRuntimeKeys<Key: CodingKey & CaseIterable>(
    _ decoder: Decoder,
    _ keyType: Key.Type
) throws where Key.AllCases: Collection {
    let strict = try decoder.container(keyedBy: StrictGroupRuntimeCodingKey.self)
    guard Set(strict.allKeys.map(\.stringValue))
            == Set(keyType.allCases.map(\.stringValue)) else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "Group runtime fields must match the current schema exactly"
            )
        )
    }
}

public enum GroupRuntimeError: Error, Equatable {
    case invalidRecord
    case missingRecord
    case invalidIntent
    case unknownIntent
    case pendingEpoch
    case staleEpoch
    case conflictingCommitQuarantined
    case incompleteFanout
    case unsupportedContentType
    case conflictingApplicationEnvelope
    case conflictingClientTransaction
    case publicationNotFound
    case capacityReached
    case invalidPeerEpoch
    case missingWelcome
    case unsolicitedJoin
    case localCredentialRemoved
    case invalidDeletion
    case groupDeleted
    case conflictingDeletionQuarantined
}

private struct GroupAuthorTransactionKeyV2: Hashable {
    let memberHandle: GroupScopedMemberHandleV2
    let clientTransactionID: UUID
}

/// Exact encrypted artifact retained after advancing a group sender chain and
/// before transport confirms publication. Retrying publishes this same envelope
/// and never consumes the sender chain twice.
public struct PendingGroupApplicationPublicationV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let event: GroupConversationEventV2
    public let envelope: GroupApplicationEnvelopeV2
    /// Exact Headless recipient routes selected before consuming a sender
    /// counter. Nil marks caller-managed legacy or low-level publication.
    public let transportRouteSets: [SignedGroupOpaqueRouteSetV2]?
    public let preparedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case event
        case envelope
        case transportRouteSets
        case preparedAt
    }

    public init(
        id: UUID = UUID(),
        event: GroupConversationEventV2,
        envelope: GroupApplicationEnvelopeV2,
        transportRouteSets: [SignedGroupOpaqueRouteSetV2]? = nil,
        preparedAt: Date
    ) {
        self.id = id
        self.event = event
        self.envelope = envelope
        self.transportRouteSets = transportRouteSets?.sorted {
            $0.ownerCredentialHandle.rawValue < $1.ownerCredentialHandle.rawValue
        }
        self.preparedAt = preparedAt
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: StrictGroupRuntimeCodingKey.self)
        let actualKeys = Set(strict.allKeys.map(\.stringValue))
        let currentKeys = Set(CodingKeys.allCases.map(\.stringValue))
        guard actualKeys == currentKeys
                || actualKeys == currentKeys.subtracting([CodingKeys.transportRouteSets.rawValue]) else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath,
                      debugDescription: "Invalid pending group publication fields")
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let routes = actualKeys == currentKeys
            ? try values.decode([SignedGroupOpaqueRouteSetV2].self, forKey: .transportRouteSets)
            : nil
        self.init(
            id: try values.decode(UUID.self, forKey: .id),
            event: try values.decode(GroupConversationEventV2.self, forKey: .event),
            envelope: try values.decode(GroupApplicationEnvelopeV2.self, forKey: .envelope),
            transportRouteSets: routes,
            preparedAt: try values.decode(Date.self, forKey: .preparedAt)
        )
        guard transportRouteSets == routes, isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Invalid pending group publication"
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid pending group publication"
                )
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(id, forKey: .id)
        try values.encode(event, forKey: .event)
        try values.encode(envelope, forKey: .envelope)
        try values.encodeIfPresent(transportRouteSets, forKey: .transportRouteSets)
        try values.encode(preparedAt, forKey: .preparedAt)
    }

    public var isStructurallyValid: Bool {
        event.isStructurallyValid
            && envelope.isStructurallyValid
            && event.groupID == envelope.groupId
            && event.id == envelope.eventId
            && (transportRouteSets == nil || transportRouteSetsAreValid)
            && preparedAt.timeIntervalSince1970.isFinite
            && preparedAt >= event.createdAt
    }

    private var transportRouteSetsAreValid: Bool {
        guard let transportRouteSets else { return true }
        return transportRouteSets.count
                <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials
            && transportRouteSets == transportRouteSets.sorted(by: {
                $0.ownerCredentialHandle.rawValue < $1.ownerCredentialHandle.rawValue
            })
            && Set(transportRouteSets.map(\.ownerCredentialHandle)).count
                == transportRouteSets.count
            && transportRouteSets.allSatisfy {
                $0.groupID == event.groupID
                    && $0.isStructurallyValid
                    && !$0.usableRoutes(at: preparedAt).isEmpty
            }
    }
}

/// Bounded replay receipt for an authenticated group application envelope.
public enum GroupApplicationProcessingOutcomeV2: String, Codable, Equatable, Sendable {
    case accepted
    case rejectedConflictingEnvelope
    case rejectedClientTransaction
}

public struct ProcessedGroupApplicationEnvelopeV2: Codable, Equatable, Identifiable {
    public var id: UUID { eventID }
    public let eventID: UUID
    public let envelopeDigest: Data
    public let outcome: GroupApplicationProcessingOutcomeV2
    public let processedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case eventID
        case envelopeDigest
        case outcome
        case processedAt
    }

    public init(
        eventID: UUID,
        envelopeDigest: Data,
        outcome: GroupApplicationProcessingOutcomeV2,
        processedAt: Date
    ) {
        self.eventID = eventID
        self.envelopeDigest = envelopeDigest
        self.outcome = outcome
        self.processedAt = processedAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupRuntimeKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            eventID: try values.decode(UUID.self, forKey: .eventID),
            envelopeDigest: try values.decode(Data.self, forKey: .envelopeDigest),
            outcome: try values.decode(
                GroupApplicationProcessingOutcomeV2.self,
                forKey: .outcome
            ),
            processedAt: try values.decode(Date.self, forKey: .processedAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Invalid processed group envelope receipt"
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid processed group envelope receipt"
                )
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(eventID, forKey: .eventID)
        try values.encode(envelopeDigest, forKey: .envelopeDigest)
        try values.encode(outcome, forKey: .outcome)
        try values.encode(processedAt, forKey: .processedAt)
    }

    public var isStructurallyValid: Bool {
        envelopeDigest.count == SHA256.byteCount
            && processedAt.timeIntervalSince1970.isFinite
    }
}

public enum GroupEpochIntentPhase: String, Codable, Equatable, CaseIterable {
    case prepared
    case stateCommitted
    case fanoutInProgress
    case finalized
}

public struct GroupEpochPublication: Codable, Equatable {
    public let intentId: UUID
    public let transition: GroupEpochTransitionEnvelopeV2
    public let signedWelcomes: [SignedGroupWelcomeV2]

    public var signedCommit: SignedGroupCommitV2 { transition.commit }
    public var signedState: SignedGroupStateV2 { transition.nextState }
    public var providerCommitBytes: Data { transition.providerCommitBytes }

    public init(
        intentId: UUID,
        transition: GroupEpochTransitionEnvelopeV2,
        signedWelcomes: [SignedGroupWelcomeV2]
    ) {
        self.intentId = intentId
        self.transition = transition
        self.signedWelcomes = signedWelcomes.sorted {
            $0.destinationCredentialHandle.rawValue < $1.destinationCredentialHandle.rawValue
        }
    }
}

public struct GroupEpochIntent: Codable, Equatable, Identifiable {
    public static let maximumJournalEntries =
        NoctweaveArchitectureV2.maximumGroupEpochIntents
    public static let recentJournalWindow =
        NoctweaveArchitectureV2.groupEpochIntentRecentWindow

    public let id: UUID
    public let idempotencyKey: Data
    public let groupId: UUID
    public let baseEpoch: UInt64
    public let nextEpoch: UInt64
    public let signedCommitDigest: Data
    public let phase: GroupEpochIntentPhase
    public let signedCommit: SignedGroupCommitV2
    public let nextSignedState: SignedGroupStateV2
    public let nextCryptoState: GroupCryptoState
    public let localCredentialAfterCommit: LocalGroupCredentialV2
    /// Group-only credential snapshot used to address the epoch transition.
    /// It is the union of credentials active before and after the commit, so
    /// removed credentials can receive the transition that removes them.
    public let transportRecipientCredentials: [GroupMemberCredentialV2]
    /// Exact authenticated routes selected before a Headless epoch commit.
    /// Nil marks a legacy or low-level intent with caller-managed transport.
    public let transportRouteSets: [SignedGroupOpaqueRouteSetV2]?
    public let providerCommitBytes: Data
    public let signedWelcomes: [SignedGroupWelcomeV2]
    public let deliveredCredentialHandles: [GroupScopedCredentialHandleV2]
    public let createdAt: Date
    public let updatedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case idempotencyKey
        case groupId
        case baseEpoch
        case nextEpoch
        case signedCommitDigest
        case phase
        case signedCommit
        case nextSignedState
        case nextCryptoState
        case localCredentialAfterCommit
        case transportRecipientCredentials
        case transportRouteSets
        case providerCommitBytes
        case signedWelcomes
        case deliveredCredentialHandles
        case createdAt
        case updatedAt
    }

    public init(
        id: UUID = UUID(),
        idempotencyKey: Data,
        groupId: UUID,
        baseEpoch: UInt64,
        nextEpoch: UInt64,
        signedCommitDigest: Data,
        phase: GroupEpochIntentPhase,
        signedCommit: SignedGroupCommitV2,
        nextSignedState: SignedGroupStateV2,
        nextCryptoState: GroupCryptoState,
        localCredentialAfterCommit: LocalGroupCredentialV2,
        transportRecipientCredentials: [GroupMemberCredentialV2]? = nil,
        transportRouteSets: [SignedGroupOpaqueRouteSetV2]? = nil,
        providerCommitBytes: Data,
        signedWelcomes: [SignedGroupWelcomeV2],
        deliveredCredentialHandles: [GroupScopedCredentialHandleV2] = [],
        createdAt: Date,
        updatedAt: Date
    ) {
        self.id = id
        self.idempotencyKey = idempotencyKey
        self.groupId = groupId
        self.baseEpoch = baseEpoch
        self.nextEpoch = nextEpoch
        self.signedCommitDigest = signedCommitDigest
        self.phase = phase
        self.signedCommit = signedCommit
        self.nextSignedState = nextSignedState
        self.nextCryptoState = nextCryptoState
        self.localCredentialAfterCommit = localCredentialAfterCommit
        self.transportRecipientCredentials = (
            transportRecipientCredentials ?? nextSignedState.memberCredentials.filter {
                $0.isActive(at: baseEpoch) || $0.isActive(at: nextEpoch)
            }
        ).sorted {
            $0.credentialHandle.rawValue < $1.credentialHandle.rawValue
        }
        self.transportRouteSets = transportRouteSets?.sorted {
            $0.ownerCredentialHandle.rawValue < $1.ownerCredentialHandle.rawValue
        }
        self.providerCommitBytes = providerCommitBytes
        self.signedWelcomes = signedWelcomes.sorted {
            $0.destinationCredentialHandle.rawValue < $1.destinationCredentialHandle.rawValue
        }
        self.deliveredCredentialHandles = deliveredCredentialHandles.sorted {
            $0.rawValue < $1.rawValue
        }
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: StrictGroupRuntimeCodingKey.self)
        let actualKeys = Set(strict.allKeys.map(\.stringValue))
        let currentKeys = Set(CodingKeys.allCases.map(\.stringValue))
        // Accept only the exact old intent shape or the current one.
        guard actualKeys == currentKeys
                || actualKeys == currentKeys.subtracting([CodingKeys.transportRouteSets.rawValue]) else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group epoch intent fields")
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let welcomes = try values.decode([SignedGroupWelcomeV2].self, forKey: .signedWelcomes)
        let delivered = try values.decode(
            [GroupScopedCredentialHandleV2].self,
            forKey: .deliveredCredentialHandles
        )
        let transportRecipients = try values.decode(
            [GroupMemberCredentialV2].self,
            forKey: .transportRecipientCredentials
        )
        let transportRoutes = actualKeys == currentKeys
            ? try values.decode(
                [SignedGroupOpaqueRouteSetV2].self,
                forKey: .transportRouteSets
            )
            : nil
        self.init(
            id: try values.decode(UUID.self, forKey: .id),
            idempotencyKey: try values.decode(Data.self, forKey: .idempotencyKey),
            groupId: try values.decode(UUID.self, forKey: .groupId),
            baseEpoch: try values.decode(UInt64.self, forKey: .baseEpoch),
            nextEpoch: try values.decode(UInt64.self, forKey: .nextEpoch),
            signedCommitDigest: try values.decode(Data.self, forKey: .signedCommitDigest),
            phase: try values.decode(GroupEpochIntentPhase.self, forKey: .phase),
            signedCommit: try values.decode(SignedGroupCommitV2.self, forKey: .signedCommit),
            nextSignedState: try values.decode(SignedGroupStateV2.self, forKey: .nextSignedState),
            nextCryptoState: try values.decode(GroupCryptoState.self, forKey: .nextCryptoState),
            localCredentialAfterCommit: try values.decode(
                LocalGroupCredentialV2.self,
                forKey: .localCredentialAfterCommit
            ),
            transportRecipientCredentials: transportRecipients,
            transportRouteSets: transportRoutes,
            providerCommitBytes: try values.decode(Data.self, forKey: .providerCommitBytes),
            signedWelcomes: welcomes,
            deliveredCredentialHandles: delivered,
            createdAt: try values.decode(Date.self, forKey: .createdAt),
            updatedAt: try values.decode(Date.self, forKey: .updatedAt)
        )
        guard signedWelcomes == welcomes,
              deliveredCredentialHandles == delivered,
              transportRecipientCredentials == transportRecipients,
              transportRouteSets == transportRoutes,
              isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group epoch intent")
            )
        }
    }

    public var publication: GroupEpochPublication {
        GroupEpochPublication(
            intentId: id,
            transition: GroupEpochTransitionEnvelopeV2(
                commit: signedCommit,
                nextState: nextSignedState,
                providerCommitBytes: providerCommitBytes
            ),
            signedWelcomes: signedWelcomes
        )
    }

    /// True only for a member-authored transition that removes the local
    /// group-scoped credential. The retained next-epoch crypto state exists
    /// solely to make the removal fanout crash-resumable; it cannot authorize
    /// further application traffic.
    public var isLocalSelfRemoval: Bool {
        guard signedCommit.operation == .removeMember,
              let removedLeaf = nextSignedState.memberCredentials.first(where: {
                  $0.credentialHandle == localCredentialAfterCommit.credentialHandle
              }),
              removedLeaf.memberHandle == localCredentialAfterCommit.memberHandle,
              removedLeaf.removedEpoch == nextEpoch,
              !nextSignedState.activeCredentials.contains(where: {
                  $0.memberHandle == localCredentialAfterCommit.memberHandle
              }) else {
            return false
        }
        return true
    }

    public var isStructurallyValid: Bool {
        guard idempotencyKey.count == 32,
              baseEpoch < UInt64.max,
              nextEpoch == baseEpoch + 1,
              signedCommitDigest.count == 32,
              signedCommit.groupId == groupId,
              signedCommit.baseEpoch == baseEpoch,
              signedCommit.nextEpoch == nextEpoch,
              signedCommit.digest == signedCommitDigest,
              nextSignedState.groupId == groupId,
              nextSignedState.epoch == nextEpoch,
              nextSignedState.commitDigest == signedCommitDigest,
              nextCryptoState.groupId == groupId,
              nextCryptoState.epoch == nextEpoch,
              localCredentialAfterCommit.groupId == groupId,
              !transportRecipientCredentials.isEmpty,
              transportRecipientCredentials.count
                <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials,
              transportRecipientCredentials == transportRecipientCredentials.sorted(by: {
                  $0.credentialHandle.rawValue < $1.credentialHandle.rawValue
              }),
              Set(transportRecipientCredentials.map(\.credentialHandle)).count
                == transportRecipientCredentials.count,
              transportRecipientCredentials.allSatisfy(\.isStructurallyValid),
              transportRecipientCredentials == nextSignedState.memberCredentials.filter({
                  $0.isActive(at: baseEpoch) || $0.isActive(at: nextEpoch)
              }),
              transportRouteSetsAreValid,
              GroupEpochTransitionEnvelopeV2(
                  commit: signedCommit,
                  nextState: nextSignedState,
                  providerCommitBytes: providerCommitBytes
              ).isStructurallyValid,
              Data(SHA256.hash(data: providerCommitBytes)) == signedCommit.providerCommitDigest,
              !providerCommitBytes.isEmpty,
              providerCommitBytes.count <= NoctweaveGroupArchitectureV2.maximumCommitBytes,
              !signedWelcomes.isEmpty,
              signedWelcomes.count
                  <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials,
              Set(signedWelcomes.map(\.destinationCredentialHandle)).count == signedWelcomes.count,
              Set(signedWelcomes.map(\.destinationCredentialHandle))
                == Set(nextSignedState.activeCredentials.map(\.credentialHandle)),
              signedWelcomes.allSatisfy({
                  $0.isStructurallyValid
                      && $0.groupId == groupId
                      && $0.epoch == nextEpoch
                      && $0.commitDigest == signedCommitDigest
                      && $0.stateTranscriptHash == nextSignedState.confirmedTranscriptHash
              }),
              Set(deliveredCredentialHandles).count == deliveredCredentialHandles.count,
              Set(deliveredCredentialHandles).isSubset(
                  of: Set(signedWelcomes.map(\.destinationCredentialHandle))
              ),
              createdAt.timeIntervalSince1970.isFinite,
              updatedAt.timeIntervalSince1970.isFinite,
              updatedAt >= createdAt else {
            return false
        }
        do {
            let provider = NoctweavePQGroupExperimentalProviderV2()
            if isLocalSelfRemoval {
                try provider.validateSelfRemovalState(
                    nextCryptoState,
                    signedState: nextSignedState,
                    removedLocalCredential: localCredentialAfterCommit
                )
            } else {
                try provider.validateActiveState(
                    nextCryptoState,
                    signedState: nextSignedState,
                    localCredential: localCredentialAfterCommit
                )
            }
        } catch {
            return false
        }
        switch phase {
        case .prepared, .stateCommitted:
            return deliveredCredentialHandles.isEmpty
        case .fanoutInProgress:
            return !deliveredCredentialHandles.isEmpty
        case .finalized:
            return true
        }
    }

    private var transportRouteSetsAreValid: Bool {
        guard let transportRouteSets else { return true }
        let remote = transportRecipientCredentials.filter {
            $0.memberHandle != localCredentialAfterCommit.memberHandle
        }
        guard transportRouteSets.count == remote.count,
              transportRouteSets == transportRouteSets.sorted(by: {
                  $0.ownerCredentialHandle.rawValue < $1.ownerCredentialHandle.rawValue
              }),
              Set(transportRouteSets.map(\.ownerCredentialHandle))
                == Set(remote.map(\.credentialHandle)) else { return false }
        let byHandle = Dictionary(uniqueKeysWithValues: remote.map {
            ($0.credentialHandle, $0)
        })
        return transportRouteSets.allSatisfy { routeSet in
            guard let credential = byHandle[routeSet.ownerCredentialHandle] else { return false }
            return routeSet.groupID == groupId
                && routeSet.ownerAdmissionDigest == credential.admissionDigest
                && !routeSet.usableRoutes(at: createdAt).isEmpty
                && (try? routeSet.verifyThrowing(
                    ownerSigningPublicKey: credential.signingPublicKey
                )) == true
        }
    }

    public var requiresRecoveryState: Bool {
        phase != .finalized
    }

    public func advancing(
        to phase: GroupEpochIntentPhase,
        deliveredCredentialHandles: [GroupScopedCredentialHandleV2]? = nil,
        at date: Date
    ) throws -> GroupEpochIntent {
        let allowed: Bool
        switch (self.phase, phase) {
        case (.prepared, .stateCommitted),
             (.stateCommitted, .fanoutInProgress),
             (.stateCommitted, .finalized),
             (.fanoutInProgress, .fanoutInProgress),
             (.fanoutInProgress, .finalized):
            allowed = true
        default:
            allowed = self.phase == phase
        }
        guard allowed, date >= updatedAt else { throw GroupRuntimeError.invalidIntent }
        let next = GroupEpochIntent(
            id: id,
            idempotencyKey: idempotencyKey,
            groupId: groupId,
            baseEpoch: baseEpoch,
            nextEpoch: nextEpoch,
            signedCommitDigest: signedCommitDigest,
            phase: phase,
            signedCommit: signedCommit,
            nextSignedState: nextSignedState,
            nextCryptoState: nextCryptoState,
            localCredentialAfterCommit: localCredentialAfterCommit,
            transportRecipientCredentials: transportRecipientCredentials,
            transportRouteSets: phase == .finalized ? nil : transportRouteSets,
            providerCommitBytes: providerCommitBytes,
            signedWelcomes: signedWelcomes,
            deliveredCredentialHandles: deliveredCredentialHandles ?? self.deliveredCredentialHandles,
            createdAt: createdAt,
            updatedAt: date
        )
        guard next.isStructurallyValid else { throw GroupRuntimeError.invalidIntent }
        return next
    }
}

public struct GroupEpochForkQuarantine: Codable, Equatable, Identifiable {
    public let id: UUID
    public let groupId: UUID
    public let baseEpoch: UInt64
    public let acceptedCommitDigest: Data
    public let conflictingCommitDigest: Data
    public let quarantinedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case groupId
        case baseEpoch
        case acceptedCommitDigest
        case conflictingCommitDigest
        case quarantinedAt
    }

    public init(
        id: UUID = UUID(),
        groupId: UUID,
        baseEpoch: UInt64,
        acceptedCommitDigest: Data,
        conflictingCommitDigest: Data,
        quarantinedAt: Date
    ) {
        self.id = id
        self.groupId = groupId
        self.baseEpoch = baseEpoch
        self.acceptedCommitDigest = acceptedCommitDigest
        self.conflictingCommitDigest = conflictingCommitDigest
        self.quarantinedAt = quarantinedAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupRuntimeKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try values.decode(UUID.self, forKey: .id),
            groupId: try values.decode(UUID.self, forKey: .groupId),
            baseEpoch: try values.decode(UInt64.self, forKey: .baseEpoch),
            acceptedCommitDigest: try values.decode(Data.self, forKey: .acceptedCommitDigest),
            conflictingCommitDigest: try values.decode(Data.self, forKey: .conflictingCommitDigest),
            quarantinedAt: try values.decode(Date.self, forKey: .quarantinedAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group fork quarantine")
            )
        }
    }

    public var isStructurallyValid: Bool {
        baseEpoch > 0
            && acceptedCommitDigest.count == 32
            && conflictingCommitDigest.count == 32
            && acceptedCommitDigest != conflictingCommitDigest
            && quarantinedAt.timeIntervalSince1970.isFinite
    }
}

public struct GroupRuntimeRecord: Codable, Equatable, Identifiable {
    public static let version = 6
    public static let maximumProtectedApplicationEvents = 256
    public static let maximumApplicationVerificationReceipts = 8_192
    public static let applicationVerificationRecentWindow = 4_096
    // No independent lifetime cap may reject a group while every historical
    // chain head is still required by a retained receipt or protected binding.
    // The 32 MiB aggregate limit remains the practical storage bound.
    public static let maximumApplicationVerificationFrontiers =
        maximumApplicationVerificationReceipts
            + maximumProtectedApplicationEvents * 256
            + NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials
    public static let maximumQuarantinedForks = 64
    public static let maximumPeerEpochJournalEntries = 256
    public static let peerEpochRecentWindow = 192
    public static let maximumPeerForkQuarantines = 64
    /// Leaves headroom inside the 64 MiB outer client-state envelope for
    /// persona, relationship, routing, and encoding overhead.
    public static let maximumDurableEncodedBytes = 32 * 1_024 * 1_024

    public var id: UUID { groupId }
    public let formatVersion: Int
    public let groupId: UUID
    public let localCredential: LocalGroupCredentialV2
    public let signedState: SignedGroupStateV2
    public let cryptoState: GroupCryptoState
    public let epochIntents: [GroupEpochIntent]
    public let quarantinedForks: [GroupEpochForkQuarantine]
    public let peerEpochJournal: [GroupPeerEpochJournalEntryV2]
    public let peerForkQuarantines: [GroupPeerEpochForkQuarantineV2]
    public let pendingLocalCredentials: [LocalGroupCredentialV2]
    public let localRemoval: GroupLocalRemovalStateV2?
    public let deletionState: GroupRuntimeDeletionStateV2?
    public let originJoinAnchorID: UUID?
    public let events: [GroupConversationEventV2]
    /// Application-selected, Core-verified events retained across normal
    /// recent-history compaction. Retention grants no application authority.
    public let protectedApplicationEventIDs: [UUID]
    /// Previously Core-bound application pins deliberately retired by an
    /// atomic series replacement while their events remain in local history.
    public let retiredProtectedApplicationEventIDs: [UUID]
    /// Epochs at or before this value predate authenticated local receipt
    /// tracking. Migrated v5 history must never be used for v2 policy proofs.
    public let applicationVerificationLegacyThroughEpoch: UInt64
    public let applicationVerificationReceipts: [GroupApplicationVerificationReceiptV2]
    public let applicationVerificationFrontiers: [GroupApplicationVerificationFrontierV2]
    public let protectedApplicationVerificationBindings:
        [GroupProtectedApplicationVerificationBindingV2]
    public let pendingApplicationPublications: [PendingGroupApplicationPublicationV2]
    public let processedApplicationEnvelopes: [ProcessedGroupApplicationEnvelopeV2]
    public let outboundTransportOperations: [GroupOpaqueRouteOutboundOperationV2]
    public let inboundTransport: GroupOpaqueRouteInboundStateV2
    public let peerRouteCache: GroupPeerRouteSetCacheV2

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case formatVersion
        case groupId
        case localCredential
        case signedState
        case cryptoState
        case epochIntents
        case quarantinedForks
        case peerEpochJournal
        case peerForkQuarantines
        case pendingLocalCredentials
        case localRemoval
        case deletionState
        case originJoinAnchorID
        case events
        case protectedApplicationEventIDs
        case retiredProtectedApplicationEventIDs
        case applicationVerificationLegacyThroughEpoch
        case applicationVerificationReceipts
        case applicationVerificationFrontiers
        case protectedApplicationVerificationBindings
        case pendingApplicationPublications
        case processedApplicationEnvelopes
        case outboundTransportOperations
        case inboundTransport
        case peerRouteCache
    }

    /// Encodes the same durable fields as `GroupRuntimeRecord` without
    /// re-entering its validation while measuring the record's byte budget.
    private struct UncheckedDurableEncoding: Encodable {
        let record: GroupRuntimeRecord

        func encode(to encoder: Encoder) throws {
            try record.encodeUnchecked(to: encoder)
        }
    }

    public init(
        formatVersion: Int = GroupRuntimeRecord.version,
        groupId: UUID,
        localCredential: LocalGroupCredentialV2,
        signedState: SignedGroupStateV2,
        cryptoState: GroupCryptoState,
        epochIntents: [GroupEpochIntent] = [],
        quarantinedForks: [GroupEpochForkQuarantine] = [],
        peerEpochJournal: [GroupPeerEpochJournalEntryV2] = [],
        peerForkQuarantines: [GroupPeerEpochForkQuarantineV2] = [],
        pendingLocalCredentials: [LocalGroupCredentialV2] = [],
        localRemoval: GroupLocalRemovalStateV2? = nil,
        deletionState: GroupRuntimeDeletionStateV2? = nil,
        originJoinAnchorID: UUID? = nil,
        events: [GroupConversationEventV2] = [],
        protectedApplicationEventIDs: [UUID] = [],
        retiredProtectedApplicationEventIDs: [UUID] = [],
        applicationVerificationLegacyThroughEpoch: UInt64 = 0,
        applicationVerificationReceipts: [GroupApplicationVerificationReceiptV2] = [],
        applicationVerificationFrontiers: [GroupApplicationVerificationFrontierV2] = [],
        protectedApplicationVerificationBindings:
            [GroupProtectedApplicationVerificationBindingV2] = [],
        pendingApplicationPublications: [PendingGroupApplicationPublicationV2] = [],
        processedApplicationEnvelopes: [ProcessedGroupApplicationEnvelopeV2] = [],
        outboundTransportOperations: [GroupOpaqueRouteOutboundOperationV2] = [],
        inboundTransport: GroupOpaqueRouteInboundStateV2 = .init(),
        peerRouteCache: GroupPeerRouteSetCacheV2 = .empty
    ) {
        self.formatVersion = formatVersion
        self.groupId = groupId
        self.localCredential = localCredential
        self.signedState = signedState
        self.cryptoState = cryptoState
        self.epochIntents = epochIntents.sorted {
            if $0.baseEpoch != $1.baseEpoch { return $0.baseEpoch < $1.baseEpoch }
            if $0.createdAt != $1.createdAt { return $0.createdAt < $1.createdAt }
            return $0.id.uuidString < $1.id.uuidString
        }
        self.quarantinedForks = quarantinedForks.sorted {
            if $0.quarantinedAt != $1.quarantinedAt {
                return $0.quarantinedAt < $1.quarantinedAt
            }
            return $0.id.uuidString < $1.id.uuidString
        }
        // Receiver observations retain authenticated append order. Peer dates
        // never choose which fork evidence survives bounded compaction.
        self.peerEpochJournal = peerEpochJournal
        self.peerForkQuarantines = peerForkQuarantines
        self.pendingLocalCredentials = pendingLocalCredentials.sorted {
            $0.credentialHandle.rawValue < $1.credentialHandle.rawValue
        }
        self.localRemoval = localRemoval
        self.deletionState = deletionState
        self.originJoinAnchorID = originJoinAnchorID
        // This array is the durable authenticated append order. Never sort it
        // by peer-authored timestamps: a sender could otherwise influence which
        // replay/transaction records survive bounded compaction.
        self.events = events
        self.protectedApplicationEventIDs = protectedApplicationEventIDs.sorted {
            $0.uuidString < $1.uuidString
        }
        self.retiredProtectedApplicationEventIDs = retiredProtectedApplicationEventIDs.sorted {
            $0.uuidString < $1.uuidString
        }
        self.applicationVerificationLegacyThroughEpoch =
            applicationVerificationLegacyThroughEpoch
        self.applicationVerificationReceipts = applicationVerificationReceipts
        self.applicationVerificationFrontiers = applicationVerificationFrontiers.sorted(
            by: GroupApplicationVerificationFrontierV2.precedes
        )
        self.protectedApplicationVerificationBindings =
            protectedApplicationVerificationBindings.sorted {
                $0.eventID.uuidString < $1.eventID.uuidString
            }
        self.pendingApplicationPublications = pendingApplicationPublications.sorted {
            if $0.preparedAt != $1.preparedAt { return $0.preparedAt < $1.preparedAt }
            return $0.id.uuidString < $1.id.uuidString
        }
        self.processedApplicationEnvelopes = processedApplicationEnvelopes.sorted {
            if $0.processedAt != $1.processedAt { return $0.processedAt < $1.processedAt }
            return $0.eventID.uuidString < $1.eventID.uuidString
        }
        self.outboundTransportOperations = outboundTransportOperations.sorted {
            if $0.createdAt != $1.createdAt { return $0.createdAt < $1.createdAt }
            return $0.id.uuidString < $1.id.uuidString
        }
        self.inboundTransport = inboundTransport
        self.peerRouteCache = peerRouteCache
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: StrictGroupRuntimeCodingKey.self)
        let keys = Set(strict.allKeys.map(\.stringValue))
        let currentKeys = Set(CodingKeys.allCases.map(\.rawValue))
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let decodedVersion = try values.decode(Int.self, forKey: .formatVersion)
        let isLegacy = decodedVersion == 5 && keys == currentKeys.subtracting([
            CodingKeys.protectedApplicationEventIDs.rawValue,
            CodingKeys.retiredProtectedApplicationEventIDs.rawValue,
            CodingKeys.applicationVerificationLegacyThroughEpoch.rawValue,
            CodingKeys.applicationVerificationReceipts.rawValue,
            CodingKeys.applicationVerificationFrontiers.rawValue,
            CodingKeys.protectedApplicationVerificationBindings.rawValue,
        ])
        let isPreRetirementV6 = decodedVersion == Self.version
            && keys == currentKeys.subtracting([
                CodingKeys.retiredProtectedApplicationEventIDs.rawValue
            ])
        guard isLegacy || isPreRetirementV6
                || (decodedVersion == Self.version && keys == currentKeys) else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath,
                      debugDescription: "Group runtime fields must match the versioned schema exactly")
            )
        }
        let decodedProtected = isLegacy ? []
            : try values.decode([UUID].self, forKey: .protectedApplicationEventIDs)
        let decodedRetired = isLegacy || isPreRetirementV6 ? []
            : try values.decode([UUID].self, forKey: .retiredProtectedApplicationEventIDs)
        let decodedLegacyThrough = isLegacy
            ? try values.decode(SignedGroupStateV2.self, forKey: .signedState).epoch
            : try values.decode(UInt64.self, forKey: .applicationVerificationLegacyThroughEpoch)
        let decodedVerificationReceipts = isLegacy ? []
            : try values.decode(
                [GroupApplicationVerificationReceiptV2].self,
                forKey: .applicationVerificationReceipts
            )
        let decodedVerificationFrontiers = isLegacy ? []
            : try values.decode(
                [GroupApplicationVerificationFrontierV2].self,
                forKey: .applicationVerificationFrontiers
            )
        let decodedVerificationBindings = isLegacy ? []
            : try values.decode(
                [GroupProtectedApplicationVerificationBindingV2].self,
                forKey: .protectedApplicationVerificationBindings
            )
        let intents = try values.decode([GroupEpochIntent].self, forKey: .epochIntents)
        let forks = try values.decode(
            [GroupEpochForkQuarantine].self,
            forKey: .quarantinedForks
        )
        let peerJournal = try values.decode(
            [GroupPeerEpochJournalEntryV2].self,
            forKey: .peerEpochJournal
        )
        let peerForks = try values.decode(
            [GroupPeerEpochForkQuarantineV2].self,
            forKey: .peerForkQuarantines
        )
        let pendingCredentials = try values.decode(
            [LocalGroupCredentialV2].self,
            forKey: .pendingLocalCredentials
        )
        let decodedEvents = try values.decode(
            [GroupConversationEventV2].self,
            forKey: .events
        )
        let decodedPending = try values.decode(
            [PendingGroupApplicationPublicationV2].self,
            forKey: .pendingApplicationPublications
        )
        let decodedProcessed = try values.decode(
            [ProcessedGroupApplicationEnvelopeV2].self,
            forKey: .processedApplicationEnvelopes
        )
        let decodedOutboundTransport = try values.decode(
            [GroupOpaqueRouteOutboundOperationV2].self,
            forKey: .outboundTransportOperations
        )
        let decodedInboundTransport = try values.decode(
            GroupOpaqueRouteInboundStateV2.self,
            forKey: .inboundTransport
        )
        let decodedPeerRouteCache = try values.decode(
            GroupPeerRouteSetCacheV2.self,
            forKey: .peerRouteCache
        )
        self.init(
            formatVersion: Self.version,
            groupId: try values.decode(UUID.self, forKey: .groupId),
            localCredential: try values.decode(
                LocalGroupCredentialV2.self,
                forKey: .localCredential
            ),
            signedState: try values.decode(SignedGroupStateV2.self, forKey: .signedState),
            cryptoState: try values.decode(GroupCryptoState.self, forKey: .cryptoState),
            epochIntents: intents,
            quarantinedForks: forks,
            peerEpochJournal: peerJournal,
            peerForkQuarantines: peerForks,
            pendingLocalCredentials: pendingCredentials,
            localRemoval: try values.decodeIfPresent(
                GroupLocalRemovalStateV2.self,
                forKey: .localRemoval
            ),
            deletionState: try values.decodeIfPresent(
                GroupRuntimeDeletionStateV2.self,
                forKey: .deletionState
            ),
            originJoinAnchorID: try values.decodeIfPresent(UUID.self, forKey: .originJoinAnchorID),
            events: decodedEvents,
            protectedApplicationEventIDs: decodedProtected,
            retiredProtectedApplicationEventIDs: decodedRetired,
            applicationVerificationLegacyThroughEpoch: decodedLegacyThrough,
            applicationVerificationReceipts: decodedVerificationReceipts,
            applicationVerificationFrontiers: decodedVerificationFrontiers,
            protectedApplicationVerificationBindings: decodedVerificationBindings,
            pendingApplicationPublications: decodedPending,
            processedApplicationEnvelopes: decodedProcessed,
            outboundTransportOperations: decodedOutboundTransport,
            inboundTransport: decodedInboundTransport,
            peerRouteCache: decodedPeerRouteCache
        )
        guard epochIntents == intents,
              quarantinedForks == forks,
              peerEpochJournal == peerJournal,
              peerForkQuarantines == peerForks,
              pendingLocalCredentials == pendingCredentials,
              events == decodedEvents,
              protectedApplicationEventIDs == decodedProtected,
              retiredProtectedApplicationEventIDs == decodedRetired,
              applicationVerificationLegacyThroughEpoch == decodedLegacyThrough,
              applicationVerificationReceipts == decodedVerificationReceipts,
              applicationVerificationFrontiers == decodedVerificationFrontiers,
              protectedApplicationVerificationBindings == decodedVerificationBindings,
              pendingApplicationPublications == decodedPending,
              processedApplicationEnvelopes == decodedProcessed,
              outboundTransportOperations == decodedOutboundTransport,
              inboundTransport == decodedInboundTransport,
              peerRouteCache == decodedPeerRouteCache,
              try isStructurallyValidThrowing else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group runtime record")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard try isStructurallyValidThrowing else {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid group runtime record"
                )
            )
        }
        try encodeUnchecked(to: encoder)
    }

    private func encodeUnchecked(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(formatVersion, forKey: .formatVersion)
        try values.encode(groupId, forKey: .groupId)
        try values.encode(localCredential, forKey: .localCredential)
        try values.encode(signedState, forKey: .signedState)
        try values.encode(cryptoState, forKey: .cryptoState)
        try values.encode(epochIntents, forKey: .epochIntents)
        try values.encode(quarantinedForks, forKey: .quarantinedForks)
        try values.encode(peerEpochJournal, forKey: .peerEpochJournal)
        try values.encode(peerForkQuarantines, forKey: .peerForkQuarantines)
        try values.encode(pendingLocalCredentials, forKey: .pendingLocalCredentials)
        try values.encode(localRemoval, forKey: .localRemoval)
        try values.encode(deletionState, forKey: .deletionState)
        try values.encode(originJoinAnchorID, forKey: .originJoinAnchorID)
        try values.encode(events, forKey: .events)
        try values.encode(protectedApplicationEventIDs, forKey: .protectedApplicationEventIDs)
        try values.encode(
            retiredProtectedApplicationEventIDs,
            forKey: .retiredProtectedApplicationEventIDs
        )
        try values.encode(
            applicationVerificationLegacyThroughEpoch,
            forKey: .applicationVerificationLegacyThroughEpoch
        )
        try values.encode(applicationVerificationReceipts, forKey: .applicationVerificationReceipts)
        try values.encode(applicationVerificationFrontiers, forKey: .applicationVerificationFrontiers)
        try values.encode(
            protectedApplicationVerificationBindings,
            forKey: .protectedApplicationVerificationBindings
        )
        try values.encode(
            pendingApplicationPublications,
            forKey: .pendingApplicationPublications
        )
        try values.encode(
            processedApplicationEnvelopes,
            forKey: .processedApplicationEnvelopes
        )
        try values.encode(
            outboundTransportOperations,
            forKey: .outboundTransportOperations
        )
        try values.encode(inboundTransport, forKey: .inboundTransport)
        try values.encode(peerRouteCache, forKey: .peerRouteCache)
    }

    public var isStructurallyValidThrowing: Bool {
        get throws {
            try requireCryptographicRuntime()
            // Bound work before indexing attacker-supplied durable arrays.
            guard events.count <= NoctweaveArchitectureV2.maximumGroupEvents,
                  pendingApplicationPublications.count
                    <= NoctweaveArchitectureV2.maximumPendingGroupPublications,
                  protectedApplicationEventIDs.count
                    <= Self.maximumProtectedApplicationEvents,
                  retiredProtectedApplicationEventIDs.count
                    <= NoctweaveArchitectureV2.maximumGroupEvents,
                  applicationVerificationReceipts.count
                    <= Self.maximumApplicationVerificationReceipts,
                  applicationVerificationFrontiers.count
                    <= Self.maximumApplicationVerificationFrontiers else {
                return false
            }
            var eventsByID: [UUID: GroupConversationEventV2] = [:]
            eventsByID.reserveCapacity(events.count)
            for event in events {
                guard eventsByID.updateValue(event, forKey: event.id) == nil else {
                    return false
                }
            }
            let eventIDs = Set(eventsByID.keys)
            let pendingEventIDs = Set(pendingApplicationPublications.map { $0.event.id })
            let protectedIDs = Set(protectedApplicationEventIDs)
            let retiredIDs = Set(retiredProtectedApplicationEventIDs)
            let activeCredentialHandles = Set(
                signedState.activeCredentials.map(\.credentialHandle)
            )
            let pendingRouteAnnouncementIDs = Set(
                inboundTransport.pendingRouteAnnouncementID.map { [$0] } ?? []
            )
            let incompleteRouteAnnouncementIDs = Set(
                outboundTransportOperations.filter {
                    $0.kind == .routeAnnouncement && !$0.isComplete
                }.map(\.logicalID)
            )
            guard formatVersion == Self.version,
              try localCredential.isStructurallyValidThrowing,
              localCredential.groupId == groupId,
              signedState.groupId == groupId,
              cryptoState.groupId == groupId,
              epochIntents.count <= GroupEpochIntent.maximumJournalEntries,
              Set(epochIntents.map(\.id)).count == epochIntents.count,
              Set(epochIntents.map(\.idempotencyKey)).count == epochIntents.count,
              epochIntents.allSatisfy({ $0.groupId == groupId && $0.isStructurallyValid }),
              quarantinedForks.count <= Self.maximumQuarantinedForks,
              Set(quarantinedForks.map(\.id)).count == quarantinedForks.count,
              Set(quarantinedForks.map(\.conflictingCommitDigest)).count
                == quarantinedForks.count,
              quarantinedForks.allSatisfy({
                  $0.groupId == groupId && $0.isStructurallyValid
              }),
              peerEpochJournal.count <= Self.maximumPeerEpochJournalEntries,
              Set(peerEpochJournal.map(\.id)).count == peerEpochJournal.count,
              Set(peerEpochJournal.map(\.baseEpoch)).count == peerEpochJournal.count,
              peerEpochJournal.allSatisfy({
                  $0.groupId == groupId && $0.isStructurallyValid
              }),
              zip(peerEpochJournal, peerEpochJournal.dropFirst()).allSatisfy({
                  $0.baseEpoch < $1.baseEpoch
              }),
              peerEpochJournal.last.map({ $0.nextEpoch <= signedState.epoch }) ?? true,
              peerForkQuarantines.count <= Self.maximumPeerForkQuarantines,
              Set(peerForkQuarantines.map(\.id)).count == peerForkQuarantines.count,
              Set(peerForkQuarantines.map(\.conflictingArtifactDigest)).count
                == peerForkQuarantines.count,
              peerForkQuarantines.allSatisfy({
                  $0.groupId == groupId && $0.isStructurallyValid
              }),
              pendingLocalCredentials.count
                <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials,
              Set(pendingLocalCredentials.map(\.credentialHandle)).count
                == pendingLocalCredentials.count,
              try pendingLocalCredentials.allSatisfy({
                  let structurallyValid = try $0.isStructurallyValidThrowing
                  return $0.groupId == groupId
                      && $0.memberHandle == localCredential.memberHandle
                      && $0.credentialHandle != localCredential.credentialHandle
                      && structurallyValid
              }),
              Set(events.map {
                  GroupAuthorTransactionKeyV2(
                      memberHandle: $0.authorMemberHandle,
                      clientTransactionID: $0.clientTransactionID
                  )
              }).count == events.count,
              events.allSatisfy({ $0.groupID == groupId && $0.isStructurallyValid }),
              protectedApplicationEventIDs == protectedApplicationEventIDs.sorted(by: {
                  $0.uuidString < $1.uuidString
              }),
              protectedIDs.count == protectedApplicationEventIDs.count,
              protectedApplicationEventIDs.allSatisfy({ protectedID in
                  eventsByID[protectedID]?.kind == .application
                      && !pendingEventIDs.contains(protectedID)
              }),
              retiredProtectedApplicationEventIDs
                == retiredProtectedApplicationEventIDs.sorted(by: {
                    $0.uuidString < $1.uuidString
                }),
              retiredIDs.count == retiredProtectedApplicationEventIDs.count,
              retiredIDs.isDisjoint(with: protectedIDs),
              retiredProtectedApplicationEventIDs.allSatisfy({ retiredID in
                  eventsByID[retiredID]?.kind == .application
                      && !pendingEventIDs.contains(retiredID)
              }),
              applicationVerificationLegacyThroughEpoch <= signedState.epoch,
              Set(applicationVerificationReceipts.map(\.eventID)).count
                == applicationVerificationReceipts.count,
              Set(applicationVerificationReceipts.map {
                  "\($0.epoch)\u{0}\($0.credentialHandle.rawValue)\u{0}\($0.messageCounter)"
              }).count == applicationVerificationReceipts.count,
              applicationVerificationReceipts.allSatisfy({ receipt in
                  receipt.isStructurallyValid
                      && receipt.groupID == groupId
                      && receipt.epoch > applicationVerificationLegacyThroughEpoch
                      && (receipt.outcome != .accepted || (
                          eventsByID[receipt.eventID].map { event in
                              event.digest == receipt.eventDigest
                                  && event.authorCredentialHandle == receipt.credentialHandle
                          } ?? false
                      ))
              }),
              applicationVerificationFrontiers == applicationVerificationFrontiers.sorted(
                  by: GroupApplicationVerificationFrontierV2.precedes
              ),
              Set(applicationVerificationFrontiers.map {
                  "\($0.epoch)\u{0}\($0.credentialHandle.rawValue)"
              }).count == applicationVerificationFrontiers.count,
              applicationVerificationFrontiers.allSatisfy({ frontier in
                  frontier.isStructurallyValid
                      && frontier.groupID == groupId
                      && frontier.epoch > applicationVerificationLegacyThroughEpoch
                      && frontier.epoch <= signedState.epoch
                      && (frontier.epoch != signedState.epoch || (
                          frontier.transcriptHash == signedState.confirmedTranscriptHash
                              && activeCredentialHandles.contains(frontier.credentialHandle)
                      ))
              }),
              protectedApplicationVerificationBindings.count
                <= Self.maximumProtectedApplicationEvents,
              protectedApplicationVerificationBindings
                == protectedApplicationVerificationBindings.sorted(by: {
                    $0.eventID.uuidString < $1.eventID.uuidString
                }),
              Set(protectedApplicationVerificationBindings.map(\.eventID)).count
                == protectedApplicationVerificationBindings.count,
              protectedApplicationVerificationBindings.allSatisfy({ binding in
                  binding.isStructurallyValid
                      && protectedIDs.contains(binding.eventID)
                      && binding.frontiers.allSatisfy { $0.groupID == groupId }
              }),
              applicationVerificationSequenceIsValid,
              Set(pendingApplicationPublications.map(\.id)).count
                == pendingApplicationPublications.count,
              pendingEventIDs.count == pendingApplicationPublications.count,
              pendingApplicationPublications.allSatisfy({ pending in
                  guard pending.event.groupID == groupId,
                        pending.isStructurallyValid,
                        eventsByID[pending.event.id] == pending.event else { return false }
                  guard let routes = pending.transportRouteSets else { return true }
                  let remote = signedState.activeCredentials.filter {
                      $0.memberHandle != localCredential.memberHandle
                  }
                  guard Set(routes.map(\.ownerCredentialHandle))
                            == Set(remote.map(\.credentialHandle)) else { return false }
                  let credentials = Dictionary(uniqueKeysWithValues: remote.map {
                      ($0.credentialHandle, $0)
                  })
                  return routes.allSatisfy { route in
                      guard let credential = credentials[route.ownerCredentialHandle] else {
                          return false
                      }
                      return route.ownerAdmissionDigest == credential.admissionDigest
                          && (try? route.verifyThrowing(
                              ownerSigningPublicKey: credential.signingPublicKey
                          )) == true
                  }
              }),
              processedApplicationEnvelopes.count
                <= NoctweaveArchitectureV2.maximumProcessedGroupEnvelopes,
              Set(processedApplicationEnvelopes.map(\.eventID)).count
                == processedApplicationEnvelopes.count,
              processedApplicationEnvelopes.allSatisfy(\.isStructurallyValid),
              outboundTransportOperations.count
                <= GroupOpaqueRouteOutboundOperationV2.maximumJournalEntries,
              Set(outboundTransportOperations.map(\.id)).count
                == outboundTransportOperations.count,
              Set(outboundTransportOperations.map {
                  "\($0.kind.rawValue)\u{0}\($0.logicalID.uuidString)"
              }).count == outboundTransportOperations.count,
              outboundTransportOperations.allSatisfy({
                  $0.groupID == groupId && $0.isStructurallyValid
              }),
              inboundTransport.isStructurallyValid,
              inboundTransport.advertisedRouteSet.map({ $0.groupID == groupId }) ?? true,
              inboundTransport.advertisedRouteAnnouncement.map({
                  $0.groupID == groupId
                      && $0.routeSet == inboundTransport.advertisedRouteSet
              }) ?? true,
              incompleteRouteAnnouncementIDs.isSubset(of: pendingRouteAnnouncementIDs),
              pendingRouteAnnouncementIDs.allSatisfy({ id in
                  outboundTransportOperations.contains {
                      $0.kind == .routeAnnouncement && $0.logicalID == id
                  }
              }),
              inboundTransport.epochStaging.transitions.allSatisfy({
                  $0.commit.groupId == groupId
              }),
              try peerRouteCache.validated(
                  against: signedState,
                  localCredential: localCredential
              ),
              outboundTransportOperations.allSatisfy({ operation in
                  guard operation.kind == .epoch,
                        let intent = epochIntents.first(where: {
                            $0.id == operation.logicalID
                        }) else {
                      return true
                  }
                  guard let transition = operation.deliveries.first(where: {
                      $0.artifactKind == .epochTransition
                  }),
                        transition.plan.protocolEnvelopeID
                            == intent.publication.transition.id else {
                      return false
                  }
                  let expectedTransition = Set(intent.transportRecipientCredentials.filter {
                      $0.memberHandle != intent.localCredentialAfterCommit.memberHandle
                  }.map(\.credentialHandle))
                  let expectedWelcomes = Set(intent.nextSignedState.activeCredentials.filter {
                      $0.memberHandle != intent.localCredentialAfterCommit.memberHandle
                  }.map(\.credentialHandle))
                  let actualWelcomes = Set(operation.deliveries.filter {
                      $0.artifactKind == .epochWelcome
                  }.flatMap(\.requiredCredentialHandles))
                  guard Set(transition.requiredCredentialHandles) == expectedTransition,
                        actualWelcomes == expectedWelcomes else {
                      return false
                  }
                  return operation.deliveries.filter {
                      $0.artifactKind == .epochWelcome
                  }.allSatisfy { delivery in
                      guard let handle = delivery.requiredCredentialHandles.first,
                            let welcome = intent.signedWelcomes.first(where: {
                                $0.destinationCredentialHandle == handle
                            }) else {
                          return false
                      }
                      return delivery.plan.protocolEnvelopeID == welcome.id
                  }
              }),
              outboundTransportOperations.filter({ !$0.isComplete }).allSatisfy({ operation in
                  switch operation.kind {
                  case .application:
                      return pendingApplicationPublications.contains {
                          $0.event.id == operation.logicalID
                      }
                  case .epoch:
                      return epochIntents.contains {
                          $0.id == operation.logicalID && $0.requiresRecoveryState
                      }
                  case .deletion:
                      return deletionState.map {
                          $0.origin == .local
                              && $0.publicationState == .pending
                              && $0.deletedState.tombstone.id == operation.logicalID
                      } ?? false
                  case .routeAnnouncement:
                      return inboundTransport.pendingRouteAnnouncementID
                          == operation.logicalID
                          && inboundTransport.advertisedRouteAnnouncement?.id
                          == operation.logicalID
                  }
              }),
              Set(processedApplicationEnvelopes.lazy.filter {
                  $0.outcome == .accepted
              }.map(\.eventID)).isSubset(of: eventIDs),
              Set(processedApplicationEnvelopes.lazy.filter {
                  $0.outcome != .accepted
              }.map(\.eventID)).isDisjoint(with: eventIDs),
              try durableAggregateEncodedByteCountThrowing()
                <= Self.maximumDurableEncodedBytes else {
                return false
            }
            if let deletionState {
                guard localRemoval == nil,
                      deletionState.isStructurallyValid,
                      deletionState.deletedState.tombstone.groupId == groupId,
                      deletionState.deletedState.tombstone.baseEpoch == signedState.epoch,
                      signedState.epoch == cryptoState.epoch,
                      pendingLocalCredentials.isEmpty,
                      pendingApplicationPublications.isEmpty,
                      epochIntents.isEmpty,
                      outboundTransportOperations.count <= 1,
                      outboundTransportOperations.allSatisfy({
                          $0.kind == .deletion
                              && $0.logicalID == deletionState.deletedState.tombstone.id
                      }) else {
                    return false
                }
            _ = try deletionState.deletedState.verified(previousState: signedState)
            try NoctweavePQGroupExperimentalProviderV2().validateActiveState(
                cryptoState,
                signedState: signedState,
                localCredential: localCredential
            )
        } else if let localRemoval {
                guard localRemoval.isStructurallyValid,
                      localRemoval.groupId == groupId,
                      localRemoval.memberHandle == localCredential.memberHandle,
                      localRemoval.removedCredentialHandle == localCredential.credentialHandle,
                      localRemoval.acceptedEpoch == signedState.epoch,
                      cryptoState.epoch < UInt64.max,
                      cryptoState.epoch + 1 == signedState.epoch,
                      !signedState.activeCredentials.contains(where: {
                          $0.credentialHandle == localCredential.credentialHandle
                      }),
                      pendingLocalCredentials.isEmpty,
                      pendingApplicationPublications.isEmpty,
                      outboundTransportOperations.allSatisfy(\.isComplete),
                      epochIntents.allSatisfy({ !$0.requiresRecoveryState }),
                      peerEpochJournal.last?.outcome == .localRemoved,
                      peerEpochJournal.last?.transitionDigest == localRemoval.transitionDigest else {
                    return false
                }
        } else {
            guard signedState.epoch == cryptoState.epoch else { return false }
            try NoctweavePQGroupExperimentalProviderV2().validateActiveState(
                cryptoState,
                signedState: signedState,
                localCredential: localCredential
            )
            guard try verificationFrontiersMatchCryptoState() else { return false }
        }
            return true
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
    }

    private var applicationVerificationSequenceIsValid: Bool {
        var lastByChain: [String: GroupApplicationVerificationReceiptV2] = [:]
        for receipt in applicationVerificationReceipts {
            let key = "\(receipt.epoch)\u{0}\(receipt.credentialHandle.rawValue)"
            if let prior = lastByChain[key] {
                guard prior.messageCounter < receipt.messageCounter else { return false }
                guard prior.transcriptHash == receipt.transcriptHash else { return false }
                if prior.messageCounter + 1 == receipt.messageCounter {
                    guard prior.prefixDigest == receipt.previousPrefixDigest else { return false }
                }
            } else if receipt.messageCounter == 0 {
                guard receipt.previousPrefixDigest
                        == GroupApplicationVerificationFrontierV2.initialDigest(
                            groupID: groupId, epoch: receipt.epoch,
                            transcriptHash: receipt.transcriptHash,
                            credentialHandle: receipt.credentialHandle
                        ) else { return false }
            }
            lastByChain[key] = receipt
        }
        for frontier in applicationVerificationFrontiers {
            let key = "\(frontier.epoch)\u{0}\(frontier.credentialHandle.rawValue)"
            if let last = lastByChain[key] {
                guard last.messageCounter < frontier.nextCounter,
                      last.transcriptHash == frontier.transcriptHash else {
                    return false
                }
                if last.messageCounter + 1 == frontier.nextCounter {
                    guard last.prefixDigest == frontier.prefixDigest else { return false }
                }
                lastByChain.removeValue(forKey: key)
            }
        }
        // An implicit zero-counter frontier is valid only for a sender chain
        // with no receipt. Every retained receipt needs its durable chain head.
        return lastByChain.isEmpty
    }

    private func verificationFrontiersMatchCryptoState() throws -> Bool {
        guard signedState.epoch > applicationVerificationLegacyThroughEpoch else {
            return !applicationVerificationFrontiers.contains { $0.epoch == signedState.epoch }
        }
        let positions = try NoctweavePQGroupExperimentalProviderV2()
            .applicationCounterPositions(state: cryptoState, signedState: signedState)
        var currentFrontiers: [GroupScopedCredentialHandleV2:
            GroupApplicationVerificationFrontierV2] = [:]
        for frontier in applicationVerificationFrontiers
        where frontier.epoch == signedState.epoch {
            currentFrontiers[frontier.credentialHandle] = frontier
        }
        return positions.allSatisfy { position in
            (currentFrontiers[position.credential]?.nextCounter ?? 0)
                == position.nextCounter
        }
    }

    public func applicationVerificationReceipt(
        for eventID: UUID
    ) -> GroupApplicationVerificationReceiptV2? {
        applicationVerificationReceipts.first { $0.eventID == eventID }
    }

    /// Returns a verified current or historical sender head. A fresh active
    /// credential has the domain-separated zero-counter head. Migrated legacy
    /// epochs deliberately return nil.
    public func verificationFrontier(
        epoch: UInt64,
        credential: GroupScopedCredentialHandleV2
    ) -> GroupApplicationVerificationFrontierV2? {
        guard epoch > applicationVerificationLegacyThroughEpoch else { return nil }
        if let frontier = applicationVerificationFrontiers.first(where: {
            $0.epoch == epoch && $0.credentialHandle == credential
        }) {
            return frontier
        }
        guard epoch == signedState.epoch,
              let member = signedState.activeCredentials.first(where: {
                  $0.credentialHandle == credential
              }) else { return nil }
        return .initial(
            groupID: groupId, epoch: epoch,
            transcriptHash: signedState.confirmedTranscriptHash,
            credentialHandle: member.credentialHandle
        )
    }

    public func currentVerificationFrontiers()
        -> [GroupApplicationVerificationFrontierV2]? {
        guard signedState.epoch > applicationVerificationLegacyThroughEpoch else {
            return nil
        }
        let frontiers = signedState.activeCredentials.compactMap {
            verificationFrontier(epoch: signedState.epoch,
                                 credential: $0.credentialHandle)
        }
        guard frontiers.count == signedState.activeCredentials.count else { return nil }
        return frontiers.sorted(by: GroupApplicationVerificationFrontierV2.precedes)
    }

    /// Nil means no Core-verified binding exists. Empty bindings are invalid.
    public func protectedVerificationFrontiers(
        for eventID: UUID
    ) -> [GroupApplicationVerificationFrontierV2]? {
        protectedApplicationVerificationBindings.first { $0.eventID == eventID }?.frontiers
    }

    /// Retains every unfinished epoch mutation and the newest finalized
    /// publications. Finalized artifacts are a bounded duplicate/fork window,
    /// not an unbounded group archive.
    public func compactedDurableState() throws -> GroupRuntimeRecord {
        try requireCryptographicRuntime()
        guard Set(epochIntents.map(\.id)).count == epochIntents.count,
              Set(epochIntents.map(\.idempotencyKey)).count == epochIntents.count,
              epochIntents.allSatisfy({
                  $0.groupId == groupId && $0.isStructurallyValid
              }) else {
            throw GroupRuntimeError.invalidRecord
        }

        let unfinishedIDs = Set(
            epochIntents.lazy.filter { $0.requiresRecoveryState }.map(\.id)
        )
        guard unfinishedIDs.count <= GroupEpochIntent.maximumJournalEntries else {
            throw GroupRuntimeError.invalidRecord
        }
        let recentFinalizedLimit = min(
            GroupEpochIntent.recentJournalWindow,
            GroupEpochIntent.maximumJournalEntries
        )
        var retainedIDs = unfinishedIDs
        let recentFinalized = epochIntents.filter { !$0.requiresRecoveryState }
            .sorted(by: Self.intentIsOlder)
            .suffix(recentFinalizedLimit)
        for intent in recentFinalized.reversed()
        where retainedIDs.count < GroupEpochIntent.maximumJournalEntries {
            retainedIDs.insert(intent.id)
        }
        let retainedEvents = compactedEvents()
        let retainedEventIDs = Set(retainedEvents.map(\.id))
        let recentVerificationIDs = Set(
            applicationVerificationReceipts.suffix(Self.applicationVerificationRecentWindow)
                .map(\.eventID)
        )
        let retainedVerificationReceipts = applicationVerificationReceipts.filter { receipt in
            if receipt.outcome == .accepted {
                return retainedEventIDs.contains(receipt.eventID)
            }
            return recentVerificationIDs.contains(receipt.eventID)
        }
        func frontierKey(_ epoch: UInt64,
                         _ credential: GroupScopedCredentialHandleV2) -> String {
            "\(epoch)\u{0}\(credential.rawValue)"
        }
        let currentKeys = Set(signedState.activeCredentials.map {
            frontierKey(signedState.epoch, $0.credentialHandle)
        })
        let receiptKeys = Set(retainedVerificationReceipts.map {
            frontierKey($0.epoch, $0.credentialHandle)
        })
        let boundKeys = Set(protectedApplicationVerificationBindings.flatMap {
            $0.frontiers.map { frontierKey($0.epoch, $0.credentialHandle) }
        })
        let relevantFrontierKeys = currentKeys.union(receiptKeys).union(boundKeys)
        let retainedVerificationFrontiers = applicationVerificationFrontiers.filter {
            relevantFrontierKeys.contains(frontierKey($0.epoch, $0.credentialHandle))
        }
        let retainedProcessed = Array(
            processedApplicationEnvelopes.filter {
                $0.outcome != .accepted || retainedEventIDs.contains($0.eventID)
            }.suffix(NoctweaveArchitectureV2.processedGroupEnvelopeRecentWindow)
        )
        let recoveryTransport = outboundTransportOperations.filter { operation in
            if !operation.isComplete { return true }
            switch operation.kind {
            case .application:
                return pendingApplicationPublications.contains {
                    $0.event.id == operation.logicalID
                }
            case .epoch:
                return epochIntents.contains {
                    $0.id == operation.logicalID && $0.requiresRecoveryState
                }
            case .deletion:
                return deletionState?.publicationState == .pending
                    && deletionState?.deletedState.tombstone.id == operation.logicalID
            case .routeAnnouncement:
                return inboundTransport.pendingRouteAnnouncementID == operation.logicalID
            }
        }
        guard recoveryTransport.count
                <= GroupOpaqueRouteOutboundOperationV2.maximumJournalEntries else {
            throw GroupRuntimeError.invalidRecord
        }
        let completedCapacity = max(
            0,
            GroupOpaqueRouteOutboundOperationV2.maximumJournalEntries
                - recoveryTransport.count
        )
        let recoveryTransportIDs = Set(recoveryTransport.map(\.id))
        let retainedCompletedTransport = Array(
            outboundTransportOperations.filter {
                $0.isComplete && !recoveryTransportIDs.contains($0.id)
            }.suffix(min(
                GroupOpaqueRouteOutboundOperationV2.recentCompletedWindow,
                completedCapacity
            ))
        )
        let retainedTransportIDs = Set(
            recoveryTransport.map(\.id) + retainedCompletedTransport.map(\.id)
        )
        let candidate = replacing(
            epochIntents: epochIntents.filter { retainedIDs.contains($0.id) },
            peerEpochJournal: Array(peerEpochJournal.suffix(Self.peerEpochRecentWindow)),
            peerForkQuarantines: Array(
                peerForkQuarantines.suffix(Self.maximumPeerForkQuarantines)
            ),
            events: retainedEvents,
            retiredProtectedApplicationEventIDs:
                retiredProtectedApplicationEventIDs.filter {
                    retainedEventIDs.contains($0)
                },
            applicationVerificationReceipts: retainedVerificationReceipts,
            applicationVerificationFrontiers: retainedVerificationFrontiers,
            processedApplicationEnvelopes: retainedProcessed,
            outboundTransportOperations: outboundTransportOperations.filter {
                retainedTransportIDs.contains($0.id)
            }
        )
        guard try candidate.isStructurallyValidThrowing else {
            throw GroupRuntimeError.invalidRecord
        }
        return candidate
    }

    private static func intentIsOlder(_ lhs: GroupEpochIntent, _ rhs: GroupEpochIntent) -> Bool {
        if lhs.updatedAt != rhs.updatedAt { return lhs.updatedAt < rhs.updatedAt }
        if lhs.createdAt != rhs.createdAt { return lhs.createdAt < rhs.createdAt }
        if lhs.baseEpoch != rhs.baseEpoch { return lhs.baseEpoch < rhs.baseEpoch }
        return lhs.id.uuidString < rhs.id.uuidString
    }

    func replacing(
        localCredential: LocalGroupCredentialV2? = nil,
        signedState: SignedGroupStateV2? = nil,
        cryptoState: GroupCryptoState? = nil,
        epochIntents: [GroupEpochIntent]? = nil,
        quarantinedForks: [GroupEpochForkQuarantine]? = nil,
        peerEpochJournal: [GroupPeerEpochJournalEntryV2]? = nil,
        peerForkQuarantines: [GroupPeerEpochForkQuarantineV2]? = nil,
        pendingLocalCredentials: [LocalGroupCredentialV2]? = nil,
        localRemoval: GroupLocalRemovalStateV2? = nil,
        deletionState: GroupRuntimeDeletionStateV2? = nil,
        originJoinAnchorID: UUID? = nil,
        events: [GroupConversationEventV2]? = nil,
        protectedApplicationEventIDs: [UUID]? = nil,
        retiredProtectedApplicationEventIDs: [UUID]? = nil,
        applicationVerificationReceipts: [GroupApplicationVerificationReceiptV2]? = nil,
        applicationVerificationFrontiers: [GroupApplicationVerificationFrontierV2]? = nil,
        protectedApplicationVerificationBindings:
            [GroupProtectedApplicationVerificationBindingV2]? = nil,
        pendingApplicationPublications: [PendingGroupApplicationPublicationV2]? = nil,
        processedApplicationEnvelopes: [ProcessedGroupApplicationEnvelopeV2]? = nil,
        outboundTransportOperations: [GroupOpaqueRouteOutboundOperationV2]? = nil,
        inboundTransport: GroupOpaqueRouteInboundStateV2? = nil,
        peerRouteCache: GroupPeerRouteSetCacheV2? = nil
    ) -> GroupRuntimeRecord {
        GroupRuntimeRecord(
            formatVersion: formatVersion,
            groupId: groupId,
            localCredential: localCredential ?? self.localCredential,
            signedState: signedState ?? self.signedState,
            cryptoState: cryptoState ?? self.cryptoState,
            epochIntents: epochIntents ?? self.epochIntents,
            quarantinedForks: quarantinedForks ?? self.quarantinedForks,
            peerEpochJournal: peerEpochJournal ?? self.peerEpochJournal,
            peerForkQuarantines: peerForkQuarantines ?? self.peerForkQuarantines,
            pendingLocalCredentials: pendingLocalCredentials ?? self.pendingLocalCredentials,
            localRemoval: localRemoval ?? self.localRemoval,
            deletionState: deletionState ?? self.deletionState,
            originJoinAnchorID: originJoinAnchorID ?? self.originJoinAnchorID,
            events: events ?? self.events,
            protectedApplicationEventIDs: protectedApplicationEventIDs
                ?? self.protectedApplicationEventIDs,
            retiredProtectedApplicationEventIDs: retiredProtectedApplicationEventIDs
                ?? self.retiredProtectedApplicationEventIDs,
            applicationVerificationLegacyThroughEpoch:
                applicationVerificationLegacyThroughEpoch,
            applicationVerificationReceipts: applicationVerificationReceipts
                ?? self.applicationVerificationReceipts,
            applicationVerificationFrontiers: applicationVerificationFrontiers
                ?? self.applicationVerificationFrontiers,
            protectedApplicationVerificationBindings: protectedApplicationVerificationBindings
                ?? self.protectedApplicationVerificationBindings,
            pendingApplicationPublications: pendingApplicationPublications
                ?? self.pendingApplicationPublications,
            processedApplicationEnvelopes: processedApplicationEnvelopes
                ?? self.processedApplicationEnvelopes,
            outboundTransportOperations: outboundTransportOperations
                ?? self.outboundTransportOperations,
            inboundTransport: inboundTransport ?? self.inboundTransport,
            peerRouteCache: peerRouteCache ?? self.peerRouteCache
        )
    }

    private func compactedEvents() -> [GroupConversationEventV2] {
        guard events.count > NoctweaveArchitectureV2.groupEventRecentWindow else {
            return events
        }
        let protected = Set(pendingApplicationPublications.map { $0.event.id })
            .union(protectedApplicationEventIDs)
        let recentIDs = Set(
            events.suffix(NoctweaveArchitectureV2.groupEventRecentWindow).map(\.id)
        )
        let retainedIDs = recentIDs.union(protected)
        return events.filter { retainedIDs.contains($0.id) }
    }

    /// Exact canonical size of every durable field, including record framing.
    /// The wrapper avoids recursively validating this record while preserving
    /// canonical encoding checks and the 32 MiB outer-envelope headroom.
    private func durableAggregateEncodedByteCountThrowing() throws -> Int {
        try NoctweaveCoder.encode(
            UncheckedDurableEncoding(record: self),
            sortedKeys: true
        ).count
    }

    fileprivate func requireCryptographicRuntime() throws {
        try GroupCryptographicRuntimeProbeV2.requireAlgorithms(
            signingPublicKey: signedState.memberCredentials.first?.signingPublicKey
                ?? localCredential.signingKey.publicKeyData,
            agreementPublicKey: signedState.memberCredentials.first?.agreementPublicKey
                ?? localCredential.agreementKey.publicKeyData
        )
    }
}

/// Implementations must replace the whole record atomically.
public protocol GroupRuntimeRecordPersistence: Sendable {
    func load() async throws -> GroupRuntimeRecord?
    func save(_ record: GroupRuntimeRecord) async throws
}

public actor NoctweavePQGroupRuntimeV2 {
    private let provider: NoctweavePQGroupExperimentalProviderV2
    private let persistence: any GroupRuntimeRecordPersistence
    var record: GroupRuntimeRecord

    public init(
        record: GroupRuntimeRecord,
        persistence: any GroupRuntimeRecordPersistence,
        provider: NoctweavePQGroupExperimentalProviderV2 = .init()
    ) throws {
        guard try record.isStructurallyValidThrowing else {
            throw GroupRuntimeError.invalidRecord
        }
        self.record = record
        self.persistence = persistence
        self.provider = provider
    }

    public static func create(
        record: GroupRuntimeRecord,
        persistence: any GroupRuntimeRecordPersistence
    ) async throws -> NoctweavePQGroupRuntimeV2 {
        guard try record.isStructurallyValidThrowing else {
            throw GroupRuntimeError.invalidRecord
        }
        try await persistence.save(record)
        return try NoctweavePQGroupRuntimeV2(record: record, persistence: persistence)
    }

    public static func open(
        persistence: any GroupRuntimeRecordPersistence
    ) async throws -> NoctweavePQGroupRuntimeV2 {
        guard let record = try await persistence.load() else {
            throw GroupRuntimeError.missingRecord
        }
        return try NoctweavePQGroupRuntimeV2(record: record, persistence: persistence)
    }

    /// Creates a runtime only from a caller-pinned, group-scoped invitation
    /// anchor. The encrypted Welcome supplies epoch secrets but never acts as
    /// its own trust root.
    public static func join(
        anchor: GroupJoinAnchorV2,
        transition: GroupEpochTransitionEnvelopeV2,
        welcome: SignedGroupWelcomeV2,
        localCredential: LocalGroupCredentialV2,
        observedAt: Date,
        persistence: any GroupRuntimeRecordPersistence
    ) async throws -> NoctweavePQGroupRuntimeV2 {
        guard try await persistence.load() == nil else {
            throw GroupRuntimeError.unsolicitedJoin
        }
        try GroupCryptographicRuntimeProbeV2.requireAlgorithms(
            signingPublicKey: anchor.baseState.memberCredentials.first?.signingPublicKey
                ?? localCredential.signingKey.publicKeyData,
            agreementPublicKey: anchor.baseState.memberCredentials.first?.agreementPublicKey
                ?? localCredential.agreementKey.publicKeyData
        )
        try GroupCryptographicRuntimeProbeV2.requireAlgorithms(
            signingPublicKey: transition.nextState.memberCredentials.first?.signingPublicKey
                ?? localCredential.signingKey.publicKeyData,
            agreementPublicKey: transition.nextState.memberCredentials.first?.agreementPublicKey
                ?? localCredential.agreementKey.publicKeyData
        )
        try GroupCryptographicRuntimeProbeV2.requireAlgorithms(
            signingPublicKey: localCredential.signingKey.publicKeyData,
            agreementPublicKey: localCredential.agreementKey.publicKeyData
        )
        guard try localCredential.isStructurallyValidThrowing,
              anchor.isStructurallyValid,
              transition.isStructurallyValid,
              observedAt.timeIntervalSince1970.isFinite,
              anchor.issuedAt <= observedAt.addingTimeInterval(
                  NoctweaveSignedGroupV2.maximumClockSkewSeconds
              ),
              observedAt < anchor.expiresAt,
              anchor.baseState.groupId == transition.commit.groupId,
              anchor.baseState.epoch == transition.commit.baseEpoch,
              localCredential.groupId == anchor.baseState.groupId,
              localCredential.memberHandle == anchor.destinationMemberHandle,
              localCredential.credentialHandle == anchor.destinationCredentialHandle,
              localCredential.admissionDigest == anchor.destinationAdmissionDigest else {
            throw GroupRuntimeError.unsolicitedJoin
        }
        _ = try transition.commit.verifiedTransition(
            from: anchor.baseState,
            observedAt: observedAt
        )
        _ = try transition.nextState.verified(
            previousState: anchor.baseState,
            commit: transition.commit,
            observedAt: observedAt
        )
        guard let localLeaf = transition.nextState.activeCredentials.first(where: {
            $0.memberHandle == localCredential.memberHandle
                && $0.credentialHandle == localCredential.credentialHandle
        }),
              localLeaf.admissionDigest == localCredential.admissionDigest,
              localLeaf.signingPublicKey == localCredential.signingKey.publicKeyData,
              localLeaf.agreementPublicKey == localCredential.agreementKey.publicKeyData,
              welcome.destinationCredentialHandle == localCredential.credentialHandle,
              welcome.destinationAdmissionDigest == localCredential.admissionDigest else {
            throw GroupRuntimeError.unsolicitedJoin
        }
        _ = try welcome.verified(against: transition.nextState, now: observedAt)

        let provider = NoctweavePQGroupExperimentalProviderV2()
        let currentMembership = try provider.membership(from: anchor.baseState)
        let proposedMembership = try provider.membership(from: transition.nextState)
        let acceptance = try acceptedPeerEpoch(
            transition: transition,
            currentMembership: currentMembership,
            proposedMembership: proposedMembership
        )
        let cryptoState = try provider.processWelcome(
            GroupWelcomePackage(
                destination: welcome.destinationCredentialHandle,
                bytes: welcome.encryptedWelcome
            ),
            membership: proposedMembership,
            acceptance: acceptance,
            commitBytes: transition.providerCommitBytes,
            localCredential: localCredential
        )
        let journal = try GroupPeerEpochJournalEntryV2(
            transition: transition,
            welcome: welcome,
            outcome: .active,
            observedAt: observedAt
        )
        let newRecord = GroupRuntimeRecord(
            groupId: transition.commit.groupId,
            localCredential: localCredential,
            signedState: transition.nextState,
            cryptoState: cryptoState,
            peerEpochJournal: [journal],
            originJoinAnchorID: anchor.id
        )
        guard try newRecord.isStructurallyValidThrowing else {
            throw GroupRuntimeError.invalidPeerEpoch
        }
        try await persistence.save(newRecord)
        return try NoctweavePQGroupRuntimeV2(
            record: newRecord,
            persistence: persistence,
            provider: provider
        )
    }

    public func snapshot() -> GroupRuntimeRecord { record }

    /// Retains one already-accepted application event while replacing a prior
    /// retained event in the same content family. Core does not interpret the
    /// event as a policy checkpoint or grant it any authorization semantics.
    /// Pending local publications cannot be protected until fanout completes.
    /// A deliberately retired ID cannot be re-protected by later replay.
    public func replaceProtectedApplicationEvent(
        previousEventID: UUID?,
        with newEventID: UUID,
        verificationFrontiers: [GroupApplicationVerificationFrontierV2] = []
    ) async throws {
        try requireActiveRuntime()
        guard let next = record.events.first(where: {
            $0.id == newEventID && $0.kind == .application
        }), !record.pendingApplicationPublications.contains(where: {
            $0.event.id == newEventID
        }), !record.retiredProtectedApplicationEventIDs.contains(newEventID) else {
            throw GroupRuntimeError.invalidRecord
        }
        var protected = Set(record.protectedApplicationEventIDs)
        if let previousEventID {
            guard protected.contains(previousEventID),
                  let previous = record.events.first(where: {
                      $0.id == previousEventID && $0.kind == .application
                  }), previous.content.type == next.content.type else {
                throw GroupRuntimeError.invalidRecord
            }
            protected.remove(previousEventID)
        }
        protected.insert(newEventID)
        guard protected.count <= GroupRuntimeRecord.maximumProtectedApplicationEvents else {
            throw GroupRuntimeError.capacityReached
        }
        let ordered = protected.sorted { $0.uuidString < $1.uuidString }
        var bindings = record.protectedApplicationVerificationBindings.filter {
            $0.eventID != previousEventID && $0.eventID != newEventID
        }
        if !verificationFrontiers.isEmpty {
            let binding = GroupProtectedApplicationVerificationBindingV2(
                eventID: newEventID, frontiers: verificationFrontiers
            )
            guard binding.isStructurallyValid,
                  let checkpointReceipt = record.applicationVerificationReceipt(
                      for: newEventID
                  ), checkpointReceipt.outcome == .accepted,
                  checkpointReceipt.eventDigest == next.digest,
                  binding.frontiers.contains(where: {
                      $0.epoch == checkpointReceipt.epoch
                          && $0.credentialHandle == checkpointReceipt.credentialHandle
                          && $0.nextCounter == checkpointReceipt.messageCounter
                          && $0.prefixDigest == checkpointReceipt.previousPrefixDigest
                  }),
                  binding.frontiers.allSatisfy({ verifiedFrontierMatches($0) }) else {
                throw GroupRuntimeError.invalidRecord
            }
            bindings.append(binding)
        } else if let existing = record.protectedApplicationVerificationBindings.first(where: {
            $0.eventID == newEventID
        }) {
            bindings.append(existing)
        }
        if ordered == record.protectedApplicationEventIDs
            && bindings == record.protectedApplicationVerificationBindings { return }
        try await persist(record.replacing(
            protectedApplicationEventIDs: ordered,
            protectedApplicationVerificationBindings: bindings
        ))
    }

    /// Removes an application-selected retention pin and its locally verified
    /// frontier binding. Callers must determine whether historical replay still
    /// needs the event before retiring it.
    public func removeProtectedApplicationEvent(eventID: UUID) async throws {
        try requireActiveRuntime()
        guard record.protectedApplicationEventIDs.contains(eventID) else {
            throw GroupRuntimeError.invalidRecord
        }
        try await persist(record.replacing(
            protectedApplicationEventIDs: record.protectedApplicationEventIDs.filter {
                $0 != eventID
            },
            protectedApplicationVerificationBindings:
                record.protectedApplicationVerificationBindings.filter {
                    $0.eventID != eventID
                }
        ))
    }

    /// Atomically binds a complete application-selected successor series and
    /// retires previously bound pins. Core verifies receipt/frontier evidence,
    /// but the caller must verify owner signatures, series completeness, and
    /// that no retained application history still needs the retired policy.
    public func replaceProtectedApplicationEventSeries(
        retiring oldEventIDs: [UUID],
        with newBindings: [GroupProtectedApplicationVerificationBindingV2]
    ) async throws {
        try requireActiveRuntime()
        let oldIDs = Set(oldEventIDs)
        let newIDs = Set(newBindings.map(\.eventID))
        guard !oldIDs.isEmpty, oldIDs.count == oldEventIDs.count,
              !newIDs.isEmpty, newIDs.count == newBindings.count,
              oldIDs.isSubset(of: Set(record.protectedApplicationEventIDs)),
              oldIDs.allSatisfy({ id in
                  record.protectedApplicationVerificationBindings.contains {
                      $0.eventID == id
                  }
              }),
              oldIDs.isDisjoint(with: newIDs),
              newIDs.isDisjoint(with: Set(record.retiredProtectedApplicationEventIDs)) else {
            throw GroupRuntimeError.invalidRecord
        }
        let eventPositions = Dictionary(uniqueKeysWithValues: record.events.enumerated().map {
            ($0.element.id, $0.offset)
        })
        guard let latestOld = oldIDs.compactMap({ eventPositions[$0] }).max(),
              let earliestNew = newIDs.compactMap({ eventPositions[$0] }).min(),
              earliestNew > latestOld,
              newBindings.allSatisfy({ verifiedAcceptedApplicationBinding($0) }) else {
            throw GroupRuntimeError.invalidRecord
        }
        let protected = Set(record.protectedApplicationEventIDs)
            .subtracting(oldIDs).union(newIDs)
        guard protected.count <= GroupRuntimeRecord.maximumProtectedApplicationEvents else {
            throw GroupRuntimeError.capacityReached
        }
        let bindings = record.protectedApplicationVerificationBindings.filter {
            !oldIDs.contains($0.eventID) && !newIDs.contains($0.eventID)
        } + newBindings
        let retired = Set(record.retiredProtectedApplicationEventIDs)
            .union(oldIDs)
        try await persist(record.replacing(
            protectedApplicationEventIDs: protected.sorted {
                $0.uuidString < $1.uuidString
            },
            retiredProtectedApplicationEventIDs: retired.sorted {
                $0.uuidString < $1.uuidString
            },
            protectedApplicationVerificationBindings: bindings
        ))
    }

    private func verifiedAcceptedApplicationBinding(
        _ binding: GroupProtectedApplicationVerificationBindingV2
    ) -> Bool {
        guard binding.isStructurallyValid,
              let event = record.events.first(where: {
                  $0.id == binding.eventID && $0.kind == .application
              }),
              !record.pendingApplicationPublications.contains(where: {
                  $0.event.id == binding.eventID
              }),
              let receipt = record.applicationVerificationReceipt(for: binding.eventID),
              receipt.outcome == .accepted,
              receipt.eventDigest == event.digest,
              binding.frontiers.contains(where: {
                  $0.epoch == receipt.epoch
                      && $0.credentialHandle == receipt.credentialHandle
                      && $0.nextCounter == receipt.messageCounter
                      && $0.prefixDigest == receipt.previousPrefixDigest
              }),
              binding.frontiers.allSatisfy({ verifiedFrontierMatches($0) }) else {
            return false
        }
        return true
    }

    private func verifiedFrontierMatches(
        _ expected: GroupApplicationVerificationFrontierV2
    ) -> Bool {
        guard expected.groupID == record.groupId,
              expected.isStructurallyValid else { return false }
        if let current = record.verificationFrontier(
            epoch: expected.epoch, credential: expected.credentialHandle
        ), current == expected { return true }
        if record.applicationVerificationReceipts.contains(where: { receipt in
            receipt.epoch == expected.epoch
                && receipt.transcriptHash == expected.transcriptHash
                && receipt.credentialHandle == expected.credentialHandle
                && receipt.messageCounter == expected.nextCounter
                && receipt.previousPrefixDigest == expected.prefixDigest
        }) { return true }
        if expected.nextCounter > 0,
           record.applicationVerificationReceipts.contains(where: { receipt in
               receipt.epoch == expected.epoch
                   && receipt.transcriptHash == expected.transcriptHash
                   && receipt.credentialHandle == expected.credentialHandle
                   && receipt.messageCounter + 1 == expected.nextCounter
                   && receipt.prefixDigest == expected.prefixDigest
           }) { return true }
        return record.protectedApplicationVerificationBindings.contains { binding in
            binding.frontiers.contains(expected)
        }
    }

    public func pendingApplicationPublications() -> [PendingGroupApplicationPublicationV2] {
        record.pendingApplicationPublications
    }

    /// Exact terminal tombstone awaiting transport acceptance. The tombstone
    /// remains in the terminal state after completion for replay rejection.
    public func pendingDeletionPublication() -> SignedGroupDeletionTombstoneV2? {
        guard let deletion = record.deletionState,
              deletion.origin == .local,
              deletion.publicationState == .pending else {
            return nil
        }
        return deletion.deletedState.tombstone
    }

    /// Creates and durably stores one exact deletion tombstone before it can be
    /// handed to transport. The same atomic replacement clears every sendable
    /// application, epoch, and replacement-credential artifact.
    public func prepareDeletion(
        reasonDigest: Data? = nil,
        idempotencyKey: Data,
        createdAt: Date = Date()
    ) async throws -> SignedGroupDeletionTombstoneV2 {
        if let deletion = record.deletionState {
            let retained = deletion.deletedState.tombstone
            guard deletion.origin == .local,
                  retained.idempotencyKey == idempotencyKey,
                  retained.reasonDigest == reasonDigest else {
                throw GroupRuntimeError.groupDeleted
            }
            return retained
        }
        try requireActiveRuntime()
        guard idempotencyKey.count == SHA256.byteCount,
              reasonDigest?.count ?? SHA256.byteCount == SHA256.byteCount,
              createdAt.timeIntervalSince1970.isFinite else {
            throw GroupRuntimeError.invalidDeletion
        }
        let tombstone = try SignedGroupDeletionTombstoneV2.create(
            currentState: record.signedState,
            authorCredentialHandle: record.localCredential.credentialHandle,
            reasonDigest: reasonDigest,
            idempotencyKey: idempotencyKey,
            signingKey: record.localCredential.signingKey,
            createdAt: createdAt
        )
        let deletedState = try SignedDeletedGroupStateV2.create(
            tombstone: tombstone,
            from: record.signedState,
            observedAt: createdAt
        )
        let deletion = try GroupRuntimeDeletionStateV2(
            deletedState: deletedState,
            origin: .local,
            publicationState: .pending,
            updatedAt: createdAt
        )
        try await persist(record.replacing(
            epochIntents: [],
            pendingLocalCredentials: [],
            deletionState: deletion,
            pendingApplicationPublications: [],
            outboundTransportOperations: []
        ))
        return tombstone
    }

    /// Completes the deletion outbox only after transport has accepted the
    /// exact retained tombstone. This operation is exactly idempotent.
    public func markDeletionPublished(
        tombstoneID: UUID,
        at date: Date = Date()
    ) async throws {
        guard let deletion = record.deletionState,
              deletion.origin == .local,
              deletion.deletedState.tombstone.id == tombstoneID,
              hasCompletedDeletionTransport(tombstoneID: tombstoneID) else {
            throw GroupRuntimeError.publicationNotFound
        }
        let completed = try deletion.markingPublished(at: date)
        if completed == deletion { return }
        try await persist(record.replacing(deletionState: completed))
    }

    /// Accepts a peer deletion against the current signed group state. A save
    /// failure leaves the active state untouched and the same artifact can be
    /// retried safely.
    public func processDeletionTombstone(
        _ tombstone: SignedGroupDeletionTombstoneV2,
        observedAt: Date = Date()
    ) async throws -> SignedDeletedGroupStateV2 {
        guard tombstone.isStructurallyValid,
              tombstone.groupId == record.groupId,
              observedAt.timeIntervalSince1970.isFinite,
              let artifactDigest = Self.exactArtifactDigest(tombstone) else {
            throw GroupRuntimeError.invalidDeletion
        }
        if let deletion = record.deletionState {
            if deletion.tombstoneArtifactDigest == artifactDigest,
               deletion.deletedState.tombstone == tombstone {
                return deletion.deletedState
            }
            _ = try tombstone.verified(
                against: record.signedState,
                observedAt: observedAt
            )
            try await retainDeletionConflict(
                kind: .conflictingDeletion,
                artifactDigest: artifactDigest,
                observedAt: observedAt
            )
            throw GroupRuntimeError.conflictingDeletionQuarantined
        }
        try requireActiveRuntime()
        let deletedState = try SignedDeletedGroupStateV2.create(
            tombstone: tombstone,
            from: record.signedState,
            observedAt: observedAt
        )
        let deletion = try GroupRuntimeDeletionStateV2(
            deletedState: deletedState,
            origin: .peer,
            publicationState: .notApplicable,
            updatedAt: observedAt
        )
        try await persist(record.replacing(
            epochIntents: [],
            pendingLocalCredentials: [],
            deletionState: deletion,
            pendingApplicationPublications: [],
            outboundTransportOperations: []
        ))
        return deletedState
    }

    /// Retains a freshly generated, group-only replacement credential until a
    /// valid accepted epoch installs it. No account or device identifier is
    /// introduced by this local ownership proof.
    public func registerPendingLocalCredential(
        _ credential: LocalGroupCredentialV2
    ) async throws {
        try requireActiveRuntime()
        guard try credential.isStructurallyValidThrowing,
              credential.groupId == record.groupId,
              credential.memberHandle == record.localCredential.memberHandle,
              credential.credentialHandle != record.localCredential.credentialHandle,
              !record.pendingLocalCredentials.contains(where: {
                  $0.credentialHandle == credential.credentialHandle
              }),
              record.pendingLocalCredentials.count
                < NoctweaveGroupArchitectureV2.maximumActiveExperimentalCredentials else {
            throw GroupRuntimeError.invalidIntent
        }
        try await persist(record.replacing(
            pendingLocalCredentials: record.pendingLocalCredentials + [credential]
        ))
    }

    /// Atomically advances the sender chain and stores the exact encrypted
    /// envelope in a durable outbox before returning it to a transport adapter.
    public func prepareApplicationEvent(
        _ event: GroupConversationEventV2,
        transportRouteSets: [SignedGroupOpaqueRouteSetV2]? = nil,
        at date: Date = Date()
    ) async throws -> GroupApplicationEnvelopeV2 {
        try requireActiveRuntime()
        guard event.isStructurallyValid,
              event.groupID == record.groupId,
              event.authorMemberHandle == record.localCredential.memberHandle,
              event.authorCredentialHandle == record.localCredential.credentialHandle,
              record.signedState.activeCredentials.contains(where: {
                  $0.memberHandle == event.authorMemberHandle
                      && $0.credentialHandle == event.authorCredentialHandle
              }),
              date.timeIntervalSince1970.isFinite,
              date >= event.createdAt else {
            throw GroupRuntimeError.invalidRecord
        }
        guard record.epochIntents.allSatisfy({ !$0.requiresRecoveryState }),
              record.outboundTransportOperations.allSatisfy({
                  $0.kind != .epoch || $0.isComplete
              }) else {
            throw GroupRuntimeError.pendingEpoch
        }
        if let existing = record.pendingApplicationPublications.first(where: {
            $0.event.id == event.id
        }) {
            guard existing.event == event else {
                throw GroupRuntimeError.conflictingApplicationEnvelope
            }
            if let transportRouteSets,
               let bound = existing.transportRouteSets,
               bound != transportRouteSets.sorted(by: {
                   $0.ownerCredentialHandle.rawValue < $1.ownerCredentialHandle.rawValue
               }) {
                throw GroupRuntimeError.conflictingApplicationEnvelope
            }
            return existing.envelope
        }
        guard !record.events.contains(where: { $0.id == event.id }) else {
            throw GroupRuntimeError.conflictingApplicationEnvelope
        }
        guard !record.events.contains(where: {
            $0.authorMemberHandle == event.authorMemberHandle
                && $0.clientTransactionID == event.clientTransactionID
        }) else {
            throw GroupRuntimeError.conflictingClientTransaction
        }
        guard record.pendingApplicationPublications.count
                < NoctweaveArchitectureV2.maximumPendingGroupPublications else {
            throw GroupRuntimeError.capacityReached
        }
        guard record.signedState.activeCredentials.allSatisfy({ credential in
            credential.contentTypes.contains { $0.supports(event.content.type) }
        }) else {
            throw GroupRuntimeError.unsupportedContentType
        }
        let eventBytes = try NoctweaveCoder.encode(event, sortedKeys: true)
        let sealed = try provider.encryptApplicationEvent(
            eventBytes,
            state: record.cryptoState,
            signedState: record.signedState,
            localCredential: record.localCredential,
            eventId: event.id,
            sentAt: date
        )
        let pending = PendingGroupApplicationPublicationV2(
            event: event,
            envelope: sealed.envelope,
            transportRouteSets: transportRouteSets,
            preparedAt: date
        )
        guard pending.isStructurallyValid else {
            throw GroupRuntimeError.invalidRecord
        }
        let envelopeDigest = Data(SHA256.hash(
            data: try NoctweaveCoder.encode(sealed.envelope, sortedKeys: true)
        ))
        let verification = try advancedApplicationVerification(
            envelope: sealed.envelope, envelopeDigest: envelopeDigest,
            eventDigest: event.digest, outcome: .accepted
        )
        try await persist(record.replacing(
            cryptoState: sealed.state,
            events: record.events + [event],
            applicationVerificationReceipts: verification.receipts,
            applicationVerificationFrontiers: verification.frontiers,
            pendingApplicationPublications: record.pendingApplicationPublications + [pending]
        ))
        return sealed.envelope
    }

    /// Removes a durable outbox artifact only after the selected transport has
    /// accepted responsibility for all intended group recipients.
    public func markApplicationPublished(
        eventID: UUID
    ) async throws {
        try requireActiveRuntime()
        guard record.pendingApplicationPublications.contains(where: {
            $0.event.id == eventID
        }) else {
            throw GroupRuntimeError.publicationNotFound
        }
        guard hasCompletedApplicationTransport(eventID: eventID) else {
            throw GroupRuntimeError.incompleteFanout
        }
        try await persist(record.replacing(
            pendingApplicationPublications: record.pendingApplicationPublications.filter {
                $0.event.id != eventID
            }
        ))
    }

    /// Verifies, decrypts, and durably records one group event. Exact transport
    /// replays return the already-persisted event without advancing a sender
    /// chain; mutation under a reused event ID fails closed.
    public func processApplicationEnvelope(
        _ envelope: GroupApplicationEnvelopeV2,
        at date: Date = Date()
    ) async throws -> GroupConversationEventV2 {
        try requireActiveRuntime()
        guard envelope.isStructurallyValid,
              envelope.groupId == record.groupId,
              date.timeIntervalSince1970.isFinite,
              let encodedEnvelope = try? NoctweaveCoder.encode(envelope, sortedKeys: true) else {
            throw GroupRuntimeError.invalidRecord
        }
        let envelopeDigest = Data(SHA256.hash(data: encodedEnvelope))
        if let processed = record.processedApplicationEnvelopes.first(where: {
            $0.eventID == envelope.eventId
        }) {
            guard processed.envelopeDigest == envelopeDigest else {
                throw GroupRuntimeError.conflictingApplicationEnvelope
            }
            switch processed.outcome {
            case .accepted:
                guard let existing = record.events.first(where: {
                    $0.id == envelope.eventId
                }) else {
                    throw GroupRuntimeError.invalidRecord
                }
                return existing
            case .rejectedConflictingEnvelope:
                throw GroupRuntimeError.conflictingApplicationEnvelope
            case .rejectedClientTransaction:
                throw GroupRuntimeError.conflictingClientTransaction
            }
        }
        guard !record.events.contains(where: { $0.id == envelope.eventId }) else {
            throw GroupRuntimeError.conflictingApplicationEnvelope
        }
        let opened = try provider.decryptApplicationEvent(
            envelope,
            state: record.cryptoState,
            signedState: record.signedState
        )
        let event: GroupConversationEventV2
        do {
            event = try NoctweaveCoder.decode(
                GroupConversationEventV2.self,
                from: opened.plaintext
            )
        } catch {
            try await persistRejectedApplication(
                envelope: envelope,
                envelopeDigest: envelopeDigest,
                cryptoState: opened.state,
                outcome: .rejectedConflictingEnvelope,
                at: date
            )
            throw GroupRuntimeError.conflictingApplicationEnvelope
        }
        guard event.groupID == record.groupId,
              event.id == envelope.eventId,
              event.authorCredentialHandle == envelope.senderCredentialHandle,
              let author = record.signedState.activeCredentials.first(where: {
                  $0.credentialHandle == envelope.senderCredentialHandle
              }),
              event.authorMemberHandle == author.memberHandle else {
            try await persistRejectedApplication(
                envelope: envelope,
                envelopeDigest: envelopeDigest,
                cryptoState: opened.state,
                outcome: .rejectedConflictingEnvelope,
                at: date
            )
            throw GroupRuntimeError.conflictingApplicationEnvelope
        }
        guard !record.events.contains(where: {
            $0.authorMemberHandle == event.authorMemberHandle
                && $0.clientTransactionID == event.clientTransactionID
        }) else {
            try await persistRejectedApplication(
                envelope: envelope,
                envelopeDigest: envelopeDigest,
                cryptoState: opened.state,
                outcome: .rejectedClientTransaction,
                at: date
            )
            throw GroupRuntimeError.conflictingClientTransaction
        }
        let processed = ProcessedGroupApplicationEnvelopeV2(
            eventID: event.id,
            envelopeDigest: envelopeDigest,
            outcome: .accepted,
            processedAt: date
        )
        let verification = try advancedApplicationVerification(
            envelope: envelope, envelopeDigest: envelopeDigest,
            eventDigest: event.digest, outcome: .accepted
        )
        try await persist(record.replacing(
            cryptoState: opened.state,
            events: record.events + [event],
            applicationVerificationReceipts: verification.receipts,
            applicationVerificationFrontiers: verification.frontiers,
            processedApplicationEnvelopes: record.processedApplicationEnvelopes
                + [processed]
        ))
        return event
    }

    public func prepareEpoch(
        operation: SignedGroupCommitOperationV2,
        proposedMembers: [GroupMemberV2],
        proposedCredentials: [GroupMemberCredentialV2],
        admissionProjection: GroupCredentialAdmissionV2? = nil,
        replacementLocalCredential: LocalGroupCredentialV2? = nil,
        proposedPermissions: GroupPermissionPolicy,
        proposedMetadataDigest: Data?,
        idempotencyKey: Data,
        transportRouteSets: [SignedGroupOpaqueRouteSetV2]? = nil,
        createdAt: Date = Date()
    ) async throws -> GroupEpochPublication {
        try requireActiveRuntime()
        guard idempotencyKey.count == 32,
              createdAt.timeIntervalSince1970.isFinite else {
            throw GroupRuntimeError.invalidIntent
        }
        switch operation {
        case .replaceCredential:
            guard let replacementLocalCredential,
                  let admissionProjection,
                  let projectionDigest = admissionProjection.digest,
                  replacementLocalCredential.groupId == record.groupId,
                  replacementLocalCredential.memberHandle == record.localCredential.memberHandle,
                  replacementLocalCredential.credentialHandle == admissionProjection.credentialHandle,
                  replacementLocalCredential.admissionDigest == projectionDigest,
                  replacementLocalCredential.signingKey.publicKeyData
                    == admissionProjection.groupSigningPublicKey,
                  replacementLocalCredential.agreementKey.publicKeyData
                    == admissionProjection.groupAgreementPublicKey else {
                throw GroupRuntimeError.invalidIntent
            }
        case .addMember, .removeMember, .changeRole, .changePolicy, .updateMetadata:
            guard replacementLocalCredential == nil else {
                throw GroupRuntimeError.invalidIntent
            }
        case .deleteGroup:
            throw GroupRuntimeError.invalidIntent
        }
        if let existing = record.epochIntents.first(where: {
            $0.idempotencyKey == idempotencyKey
        }) {
            return try await resumeOrReturn(existing.id, at: createdAt)
        }
        guard record.pendingApplicationPublications.isEmpty,
              record.epochIntents.allSatisfy({ !$0.requiresRecoveryState }),
              record.outboundTransportOperations.allSatisfy(\.isComplete) else {
            throw GroupRuntimeError.pendingEpoch
        }
        guard record.signedState.epoch < UInt64.max else {
            throw GroupRuntimeError.staleEpoch
        }
        let currentMembership = try provider.membership(from: record.signedState)
        let proposedMembership = try provider.membership(
            groupId: record.groupId,
            epoch: record.signedState.epoch + 1,
            members: proposedMembers,
            leaves: proposedCredentials
        )
        let isLocalSelfRemoval = operation == .removeMember
            && !proposedMembership.credentials.contains(where: {
                $0.memberHandle == record.localCredential.memberHandle
            })
        let prepared = try provider.prepareCommit(
            state: record.cryptoState,
            currentMembership: currentMembership,
            proposedMembership: proposedMembership,
            localCredential: record.localCredential,
            nextLocalCredential: replacementLocalCredential,
            allowLocalSelfRemoval: isLocalSelfRemoval
        )
        guard let providerCommitDigest = prepared.providerCommitDigest else {
            throw GroupRuntimeError.invalidIntent
        }
        let signedCommit = try SignedGroupCommitV2.create(
            operation: operation,
            currentState: record.signedState,
            proposedMembers: proposedMembers,
            proposedCredentials: proposedCredentials,
            admissionProjection: admissionProjection,
            proposedPermissions: proposedPermissions,
            proposedMetadataDigest: proposedMetadataDigest,
            authorCredentialHandle: record.localCredential.credentialHandle,
            providerCommitDigest: providerCommitDigest,
            idempotencyKey: idempotencyKey,
            signingKey: record.localCredential.signingKey,
            createdAt: createdAt
        )
        guard let signedCommitDigest = signedCommit.digest else {
            throw GroupRuntimeError.invalidIntent
        }
        let nextSignedState = try SignedGroupStateV2.applying(
            signedCommit,
            to: record.signedState,
            observedAt: createdAt,
            signingKey: record.localCredential.signingKey
        )
        let acceptance = GroupCryptoAcceptedEpochV2(
            proposal: prepared.proposal,
            providerCommitDigest: providerCommitDigest,
            signedCommitDigest: signedCommitDigest,
            acceptedTranscriptHash: nextSignedState.confirmedTranscriptHash
        )
        let nextCryptoState = try provider.finalizePreparedEpoch(
            prepared,
            acceptance: acceptance
        )
        let transportRecipients = nextSignedState.memberCredentials.filter {
            $0.isActive(at: record.signedState.epoch)
                || $0.isActive(at: nextSignedState.epoch)
        }
        let welcomeExpiry = createdAt.addingTimeInterval(
            min(NoctweaveSignedGroupV2.maximumWelcomeLifetimeSeconds, 24 * 60 * 60)
        )
        let signedWelcomes = try prepared.welcomes.map { welcome in
            try SignedGroupWelcomeV2.create(
                state: nextSignedState,
                destinationCredentialHandle: welcome.destination,
                encryptedWelcome: welcome.bytes,
                signingKey: record.localCredential.signingKey,
                createdAt: createdAt,
                expiresAt: welcomeExpiry
            )
        }
        let intent = GroupEpochIntent(
            idempotencyKey: idempotencyKey,
            groupId: record.groupId,
            baseEpoch: record.signedState.epoch,
            nextEpoch: nextSignedState.epoch,
            signedCommitDigest: signedCommitDigest,
            phase: .prepared,
            signedCommit: signedCommit,
            nextSignedState: nextSignedState,
            nextCryptoState: nextCryptoState,
            localCredentialAfterCommit: replacementLocalCredential ?? record.localCredential,
            transportRecipientCredentials: transportRecipients,
            transportRouteSets: transportRouteSets,
            providerCommitBytes: prepared.commitBytes,
            signedWelcomes: signedWelcomes,
            createdAt: createdAt,
            updatedAt: createdAt
        )
        guard intent.isStructurallyValid else { throw GroupRuntimeError.invalidIntent }
        try await persist(record.replacing(epochIntents: record.epochIntents + [intent]))
        return try await resumeOrReturn(intent.id, at: createdAt)
    }

    public func resumePreparedEpoch(
        intentId: UUID,
        at date: Date = Date()
    ) async throws -> GroupEpochPublication {
        try requireActiveRuntime()
        return try await resumeOrReturn(intentId, at: date)
    }

    public func markFanoutStored(
        intentId: UUID,
        destinationCredentialHandle: GroupScopedCredentialHandleV2,
        at date: Date = Date()
    ) async throws {
        try requireActiveRuntime()
        guard let index = record.epochIntents.firstIndex(where: { $0.id == intentId }) else {
            throw GroupRuntimeError.unknownIntent
        }
        let intent = record.epochIntents[index]
        guard intent.phase == .stateCommitted || intent.phase == .fanoutInProgress,
              intent.signedWelcomes.contains(where: {
                  $0.destinationCredentialHandle == destinationCredentialHandle
              }) else {
            throw GroupRuntimeError.invalidIntent
        }
        if intent.deliveredCredentialHandles.contains(destinationCredentialHandle) { return }
        guard hasAcceptedEpochWelcome(
            intentID: intentId,
            credentialHandle: destinationCredentialHandle
        ) else {
            throw GroupRuntimeError.incompleteFanout
        }
        let delivered = intent.deliveredCredentialHandles + [destinationCredentialHandle]
        let updated = try intent.advancing(
            to: .fanoutInProgress,
            deliveredCredentialHandles: delivered,
            at: date
        )
        var intents = record.epochIntents
        intents[index] = updated
        try await persist(record.replacing(epochIntents: intents))
    }

    public func finalizeEpoch(
        intentId: UUID,
        at date: Date = Date()
    ) async throws {
        try requireActiveRuntime()
        guard let index = record.epochIntents.firstIndex(where: { $0.id == intentId }) else {
            throw GroupRuntimeError.unknownIntent
        }
        let intent = record.epochIntents[index]
        if intent.phase == .finalized { return }
        guard intent.phase == .stateCommitted || intent.phase == .fanoutInProgress else {
            throw GroupRuntimeError.invalidIntent
        }
        let required = Set(intent.nextSignedState.activeCredentials.filter {
            $0.memberHandle != intent.localCredentialAfterCommit.memberHandle
        }.map(\.credentialHandle))
        guard Set(intent.deliveredCredentialHandles).isSuperset(of: required),
              hasCompletedEpochTransport(intent: intent) else {
            throw GroupRuntimeError.incompleteFanout
        }
        let updated = try intent.advancing(to: .finalized, at: date)
        var intents = record.epochIntents
        intents[index] = updated
        if intent.isLocalSelfRemoval {
            let transition = intent.publication.transition
            guard let transitionDigest = transition.digest,
                  record.peerEpochJournal.count
                    < GroupRuntimeRecord.maximumPeerEpochJournalEntries else {
                throw GroupRuntimeError.invalidRecord
            }
            let journal = try GroupPeerEpochJournalEntryV2(
                transition: transition,
                welcome: nil,
                outcome: .localRemoved,
                observedAt: date
            )
            let removal = GroupLocalRemovalStateV2(
                groupId: record.groupId,
                memberHandle: record.localCredential.memberHandle,
                removedCredentialHandle: record.localCredential.credentialHandle,
                acceptedEpoch: intent.nextSignedState.epoch,
                transitionDigest: transitionDigest,
                observedAt: date
            )
            let candidate = record.replacing(
                signedState: intent.nextSignedState,
                epochIntents: intents,
                peerEpochJournal: record.peerEpochJournal + [journal],
                pendingLocalCredentials: [],
                localRemoval: removal,
                pendingApplicationPublications: [],
                peerRouteCache: try record.peerRouteCache.pruning(
                    to: intent.nextSignedState,
                    localCredential: record.localCredential
                )
            )
            try await persist(candidate)
            return
        }
        try await persist(record.replacing(epochIntents: intents))
    }

    /// Applies one complete peer-authored epoch transition. Verification,
    /// provider processing, the accepted signed state, and the replay journal
    /// are saved as one record replacement.
    public func processPeerEpoch(
        _ transition: GroupEpochTransitionEnvelopeV2,
        welcome: SignedGroupWelcomeV2?,
        observedAt: Date = Date()
    ) async throws -> GroupPeerEpochOutcomeV2 {
        if record.deletionState != nil {
            throw GroupRuntimeError.groupDeleted
        }
        try GroupCryptographicRuntimeProbeV2.requireAlgorithms(
            signingPublicKey: transition.nextState.memberCredentials.first?.signingPublicKey
                ?? record.localCredential.signingKey.publicKeyData,
            agreementPublicKey: transition.nextState.memberCredentials.first?.agreementPublicKey
                ?? record.localCredential.agreementKey.publicKeyData
        )
        guard transition.isStructurallyValid,
              transition.commit.groupId == record.groupId,
              observedAt.timeIntervalSince1970.isFinite else {
            throw GroupRuntimeError.invalidPeerEpoch
        }

        if let accepted = record.peerEpochJournal.first(where: {
            $0.baseEpoch == transition.commit.baseEpoch
        }) {
            if accepted.exactlyMatches(transition: transition, welcome: welcome) {
                return accepted.outcome
            }
            try await quarantinePeerFork(
                accepted: accepted,
                transition: transition,
                welcome: welcome,
                at: observedAt
            )
            throw GroupRuntimeError.conflictingCommitQuarantined
        }

        if let localIntent = record.epochIntents.first(where: {
            $0.baseEpoch == transition.commit.baseEpoch
        }) {
            let localTransition = localIntent.publication.transition
            let localWelcome = localIntent.signedWelcomes.first(where: {
                $0.destinationCredentialHandle
                    == localIntent.localCredentialAfterCommit.credentialHandle
            })
            let baseline = try GroupPeerEpochJournalEntryV2(
                transition: localTransition,
                welcome: localWelcome,
                outcome: .active,
                observedAt: localIntent.createdAt
            )
            guard localTransition == transition, localWelcome == welcome else {
                try await quarantinePeerFork(
                    accepted: baseline,
                    transition: transition,
                    welcome: welcome,
                    at: observedAt
                )
                throw GroupRuntimeError.conflictingCommitQuarantined
            }
            if localIntent.phase != .prepared {
                if localIntent.isLocalSelfRemoval {
                    // A self-removal intentionally keeps the previous epoch
                    // active until the exact removal fanout is relay-backed.
                    // Seeing our own transition during that window is an
                    // idempotent replay, not evidence of a corrupt record.
                    guard record.localRemoval == nil,
                          record.signedState.epoch == localIntent.baseEpoch else {
                        throw GroupRuntimeError.invalidRecord
                    }
                    return .active
                }
                guard record.signedState.epoch >= localIntent.nextEpoch else {
                    throw GroupRuntimeError.invalidRecord
                }
                return .active
            }
            _ = try transition.commit.verifiedTransition(
                from: record.signedState,
                observedAt: observedAt
            )
            _ = try transition.nextState.verified(
                previousState: record.signedState,
                commit: transition.commit,
                observedAt: observedAt
            )
            guard let welcome else { throw GroupRuntimeError.missingWelcome }
            _ = try welcome.verified(against: transition.nextState, now: observedAt)
            try provider.validateActiveState(
                localIntent.nextCryptoState,
                signedState: localIntent.nextSignedState,
                localCredential: localIntent.localCredentialAfterCommit
            )
            let journal = try GroupPeerEpochJournalEntryV2(
                transition: transition,
                welcome: welcome,
                outcome: .active,
                observedAt: observedAt
            )
            let committed = try localIntent.advancing(
                to: .stateCommitted,
                at: max(observedAt, localIntent.updatedAt)
            )
            var intents = record.epochIntents
            guard let index = intents.firstIndex(where: { $0.id == localIntent.id }) else {
                throw GroupRuntimeError.invalidRecord
            }
            intents[index] = committed
            let peerRouteCache = try record.peerRouteCache.pruning(
                to: localIntent.nextSignedState,
                localCredential: localIntent.localCredentialAfterCommit
            )
            try await persist(record.replacing(
                localCredential: localIntent.localCredentialAfterCommit,
                signedState: localIntent.nextSignedState,
                cryptoState: localIntent.nextCryptoState,
                epochIntents: intents,
                peerEpochJournal: record.peerEpochJournal + [journal],
                pendingLocalCredentials: record.pendingLocalCredentials.filter {
                    $0.credentialHandle
                        != localIntent.localCredentialAfterCommit.credentialHandle
                },
                peerRouteCache: peerRouteCache
            ))
            return .active
        }

        try requireActiveRuntime()
        guard transition.commit.baseEpoch == record.signedState.epoch else {
            throw GroupRuntimeError.staleEpoch
        }
        _ = try transition.commit.verifiedTransition(
            from: record.signedState,
            observedAt: observedAt
        )
        _ = try transition.nextState.verified(
            previousState: record.signedState,
            commit: transition.commit,
            observedAt: observedAt
        )

        let currentMembership = try provider.membership(from: record.signedState)
        let proposedMembership = try provider.membership(from: transition.nextState)
        let acceptance = try Self.acceptedPeerEpoch(
            transition: transition,
            currentMembership: currentMembership,
            proposedMembership: proposedMembership
        )

        let currentCredentialStillActive = transition.nextState.activeCredentials.contains {
            $0.memberHandle == record.localCredential.memberHandle
                && $0.credentialHandle == record.localCredential.credentialHandle
                && $0.admissionDigest == record.localCredential.admissionDigest
                && $0.signingPublicKey == record.localCredential.signingKey.publicKeyData
                && $0.agreementPublicKey == record.localCredential.agreementKey.publicKeyData
        }

        let nextCredential: LocalGroupCredentialV2?
        let nextCryptoState: GroupCryptoState?
        let outcome: GroupPeerEpochOutcomeV2
        if currentCredentialStillActive {
            guard let welcome,
                  welcome.destinationCredentialHandle
                    == record.localCredential.credentialHandle,
                  welcome.destinationAdmissionDigest
                    == record.localCredential.admissionDigest else {
                throw GroupRuntimeError.missingWelcome
            }
            _ = try welcome.verified(against: transition.nextState, now: observedAt)
            nextCryptoState = try provider.processCommit(
                state: record.cryptoState,
                currentMembership: currentMembership,
                proposedMembership: proposedMembership,
                acceptance: acceptance,
                commitBytes: transition.providerCommitBytes,
                localPackage: GroupWelcomePackage(
                    destination: welcome.destinationCredentialHandle,
                    bytes: welcome.encryptedWelcome
                ),
                localCredential: record.localCredential
            )
            nextCredential = record.localCredential
            outcome = .active
        } else if let replacement = record.pendingLocalCredentials.first(where: { candidate in
            transition.nextState.activeCredentials.contains(where: { leaf in
                leaf.memberHandle == candidate.memberHandle
                    && leaf.credentialHandle == candidate.credentialHandle
                    && leaf.admissionDigest == candidate.admissionDigest
                    && leaf.signingPublicKey == candidate.signingKey.publicKeyData
                    && leaf.agreementPublicKey == candidate.agreementKey.publicKeyData
            })
        }) {
            guard let welcome,
                  welcome.destinationCredentialHandle == replacement.credentialHandle,
                  welcome.destinationAdmissionDigest == replacement.admissionDigest else {
                throw GroupRuntimeError.missingWelcome
            }
            _ = try welcome.verified(against: transition.nextState, now: observedAt)
            nextCryptoState = try provider.processWelcome(
                GroupWelcomePackage(
                    destination: welcome.destinationCredentialHandle,
                    bytes: welcome.encryptedWelcome
                ),
                membership: proposedMembership,
                acceptance: acceptance,
                commitBytes: transition.providerCommitBytes,
                localCredential: replacement
            )
            nextCredential = replacement
            outcome = .active
        } else {
            guard welcome == nil else { throw GroupRuntimeError.invalidPeerEpoch }
            nextCryptoState = nil
            nextCredential = nil
            outcome = .localRemoved
        }

        let journal = try GroupPeerEpochJournalEntryV2(
            transition: transition,
            welcome: welcome,
            outcome: outcome,
            observedAt: observedAt
        )
        let nextJournal = record.peerEpochJournal + [journal]
        let candidate: GroupRuntimeRecord
        if let nextCredential, let nextCryptoState {
            let peerRouteCache = try record.peerRouteCache.pruning(
                to: transition.nextState,
                localCredential: nextCredential
            )
            candidate = record.replacing(
                localCredential: nextCredential,
                signedState: transition.nextState,
                cryptoState: nextCryptoState,
                peerEpochJournal: nextJournal,
                pendingLocalCredentials: record.pendingLocalCredentials.filter {
                    $0.credentialHandle != nextCredential.credentialHandle
                },
                peerRouteCache: peerRouteCache
            )
        } else {
            guard let transitionDigest = transition.digest else {
                throw GroupRuntimeError.invalidPeerEpoch
            }
            let removal = GroupLocalRemovalStateV2(
                groupId: record.groupId,
                memberHandle: record.localCredential.memberHandle,
                removedCredentialHandle: record.localCredential.credentialHandle,
                acceptedEpoch: transition.nextState.epoch,
                transitionDigest: transitionDigest,
                observedAt: observedAt
            )
            candidate = record.replacing(
                signedState: transition.nextState,
                epochIntents: [],
                peerEpochJournal: nextJournal,
                pendingLocalCredentials: [],
                localRemoval: removal,
                pendingApplicationPublications: [],
                outboundTransportOperations: [],
                peerRouteCache: try record.peerRouteCache.pruning(
                    to: transition.nextState,
                    localCredential: record.localCredential
                )
            )
        }
        try await persist(candidate)
        return outcome
    }

    /// Returns the exact retained artifacts for a duplicate commit and
    /// quarantines a different digest that claims the same base epoch.
    public func observeCommit(
        _ commit: SignedGroupCommitV2,
        at date: Date = Date()
    ) async throws -> GroupEpochPublication? {
        if record.deletionState != nil {
            throw GroupRuntimeError.groupDeleted
        }
        guard commit.groupId == record.groupId,
              let digest = commit.digest,
              date.timeIntervalSince1970.isFinite else {
            throw GroupRuntimeError.invalidIntent
        }
        guard let accepted = record.epochIntents.first(where: {
            $0.baseEpoch == commit.baseEpoch
        }) else {
            if commit.baseEpoch < record.signedState.epoch {
                throw GroupRuntimeError.staleEpoch
            }
            return nil
        }
        if accepted.signedCommitDigest == digest {
            return accepted.publication
        }
        if !record.quarantinedForks.contains(where: {
            $0.baseEpoch == commit.baseEpoch && $0.conflictingCommitDigest == digest
        }) {
            let quarantine = GroupEpochForkQuarantine(
                groupId: record.groupId,
                baseEpoch: commit.baseEpoch,
                acceptedCommitDigest: accepted.signedCommitDigest,
                conflictingCommitDigest: digest,
                quarantinedAt: date
            )
            guard quarantine.isStructurallyValid else {
                throw GroupRuntimeError.invalidIntent
            }
            let retained = Array(
                (record.quarantinedForks + [quarantine])
                    .suffix(GroupRuntimeRecord.maximumQuarantinedForks)
            )
            try await persist(record.replacing(quarantinedForks: retained))
        }
        throw GroupRuntimeError.conflictingCommitQuarantined
    }

    private func resumeOrReturn(
        _ intentId: UUID,
        at date: Date
    ) async throws -> GroupEpochPublication {
        guard let index = record.epochIntents.firstIndex(where: { $0.id == intentId }) else {
            throw GroupRuntimeError.unknownIntent
        }
        let intent = record.epochIntents[index]
        guard intent.isStructurallyValid else { throw GroupRuntimeError.invalidIntent }
        guard intent.phase == .prepared else { return intent.publication }
        guard record.signedState.epoch == intent.baseEpoch else {
            throw GroupRuntimeError.staleEpoch
        }
        _ = try intent.nextSignedState.verified(
            previousState: record.signedState,
            commit: intent.signedCommit,
            // Reuse the original locally observed preparation time. Rechecking
            // against wall-clock time after a restart would eventually accept a
            // commit that was too far in the future when first observed.
            observedAt: intent.createdAt
        )
        if intent.isLocalSelfRemoval {
            try provider.validateSelfRemovalState(
                intent.nextCryptoState,
                signedState: intent.nextSignedState,
                removedLocalCredential: intent.localCredentialAfterCommit
            )
        } else {
            try provider.validateActiveState(
                intent.nextCryptoState,
                signedState: intent.nextSignedState,
                localCredential: intent.localCredentialAfterCommit
            )
        }
        let committedIntent = try intent.advancing(to: .stateCommitted, at: date)
        var intents = record.epochIntents
        intents[index] = committedIntent
        if intent.isLocalSelfRemoval {
            // Keep the current active epoch until every remaining member has
            // durable relay evidence for the removal. A crash can therefore
            // resume the exact fanout without either restoring local sending
            // authority after departure or stranding a terminal record.
            try await persist(record.replacing(epochIntents: intents))
            return committedIntent.publication
        }
        let peerRouteCache = try record.peerRouteCache.pruning(
            to: intent.nextSignedState,
            localCredential: intent.localCredentialAfterCommit
        )
        let candidate = record.replacing(
            localCredential: intent.localCredentialAfterCommit,
            signedState: intent.nextSignedState,
            cryptoState: intent.nextCryptoState,
            epochIntents: intents,
            peerRouteCache: peerRouteCache
        )
        try await persist(candidate)
        return committedIntent.publication
    }

    func persist(_ candidate: GroupRuntimeRecord) async throws {
        let compacted = try candidate.compactedDurableState()
        guard try compacted.isStructurallyValidThrowing else {
            throw GroupRuntimeError.invalidRecord
        }
        try await persistence.save(compacted)
        record = compacted
    }

    func requireActiveRuntime() throws {
        guard record.deletionState == nil else {
            throw GroupRuntimeError.groupDeleted
        }
        guard record.localRemoval == nil else {
            throw GroupRuntimeError.localCredentialRemoved
        }
    }

    private static func exactArtifactDigest<T: Encodable>(_ artifact: T) -> Data? {
        guard let bytes = try? NoctweaveCoder.encode(artifact, sortedKeys: true) else {
            return nil
        }
        return Data(SHA256.hash(data: bytes))
    }

    private func retainDeletionConflict(
        kind: GroupDeletionConflictKindV2,
        artifactDigest: Data,
        observedAt: Date
    ) async throws {
        guard let deletion = record.deletionState else {
            throw GroupRuntimeError.invalidRecord
        }
        let updated = try deletion.retainingConflict(
            kind: kind,
            artifactDigest: artifactDigest,
            observedAt: observedAt
        )
        if updated == deletion { return }
        try await persist(record.replacing(deletionState: updated))
    }

    private static func acceptedPeerEpoch(
        transition: GroupEpochTransitionEnvelopeV2,
        currentMembership: GroupProviderMembershipV2,
        proposedMembership: GroupProviderMembershipV2
    ) throws -> GroupCryptoAcceptedEpochV2 {
        guard transition.isStructurallyValid,
              let signedCommitDigest = transition.commit.digest,
              currentMembership.groupId == transition.commit.groupId,
              currentMembership.epoch == transition.commit.baseEpoch,
              proposedMembership.groupId == transition.commit.groupId,
              proposedMembership.epoch == transition.commit.nextEpoch,
              currentMembership.selection == .currentExperimental,
              proposedMembership.selection == .currentExperimental else {
            throw GroupRuntimeError.invalidPeerEpoch
        }
        let proposal = GroupCryptoEpochProposalV2(
            groupId: transition.commit.groupId,
            baseEpoch: transition.commit.baseEpoch,
            nextEpoch: transition.commit.nextEpoch,
            selection: .currentExperimental,
            currentMembershipDigest: currentMembership.membershipDigest,
            proposedMembershipDigest: proposedMembership.membershipDigest,
            authorCredentialHandle: transition.commit.authorCredentialHandle
        )
        let acceptance = GroupCryptoAcceptedEpochV2(
            proposal: proposal,
            providerCommitDigest: transition.commit.providerCommitDigest,
            signedCommitDigest: signedCommitDigest,
            acceptedTranscriptHash: transition.nextState.confirmedTranscriptHash
        )
        guard acceptance.isStructurallyValid else {
            throw GroupRuntimeError.invalidPeerEpoch
        }
        return acceptance
    }

    private func quarantinePeerFork(
        accepted: GroupPeerEpochJournalEntryV2,
        transition: GroupEpochTransitionEnvelopeV2,
        welcome: SignedGroupWelcomeV2?,
        at date: Date
    ) async throws {
        let quarantine = try GroupPeerEpochForkQuarantineV2(
            acceptedArtifactDigest: accepted.artifactDigest,
            transition: transition,
            welcome: welcome,
            quarantinedAt: date
        )
        if record.peerForkQuarantines.contains(where: {
            $0.conflictingArtifactDigest == quarantine.conflictingArtifactDigest
        }) {
            return
        }
        let retained = Array(
            (record.peerForkQuarantines + [quarantine])
                .suffix(GroupRuntimeRecord.maximumPeerForkQuarantines)
        )
        try await persist(record.replacing(peerForkQuarantines: retained))
    }

    /// Authenticated semantic poison consumes the sender-chain position before
    /// returning a deterministic peer-invalid result. Persisting the rejection
    /// atomically prevents one bad event from pinning all later events from that
    /// group-scoped credential; a save failure leaves the old chain retryable.
    private func persistRejectedApplication(
        envelope: GroupApplicationEnvelopeV2,
        envelopeDigest: Data,
        cryptoState: GroupCryptoState,
        outcome: GroupApplicationProcessingOutcomeV2,
        at date: Date
    ) async throws {
        guard outcome != .accepted else { throw GroupRuntimeError.invalidRecord }
        let processed = ProcessedGroupApplicationEnvelopeV2(
            eventID: envelope.eventId,
            envelopeDigest: envelopeDigest,
            outcome: outcome,
            processedAt: date
        )
        let verification = try advancedApplicationVerification(
            envelope: envelope, envelopeDigest: envelopeDigest,
            eventDigest: nil, outcome: outcome
        )
        try await persist(record.replacing(
            cryptoState: cryptoState,
            applicationVerificationReceipts: verification.receipts,
            applicationVerificationFrontiers: verification.frontiers,
            processedApplicationEnvelopes: record.processedApplicationEnvelopes
                + [processed]
        ))
    }

    private func advancedApplicationVerification(
        envelope: GroupApplicationEnvelopeV2,
        envelopeDigest: Data,
        eventDigest: Data?,
        outcome: GroupApplicationProcessingOutcomeV2
    ) throws -> (
        receipts: [GroupApplicationVerificationReceiptV2],
        frontiers: [GroupApplicationVerificationFrontierV2]
    ) {
        // Legacy v5 epochs have already consumed counters without a durable
        // prefix transcript. They remain usable for Core messaging, but cannot
        // provide v2 application-policy proof until a fresh epoch starts.
        guard envelope.epoch > record.applicationVerificationLegacyThroughEpoch else {
            return (record.applicationVerificationReceipts,
                    record.applicationVerificationFrontiers)
        }
        guard let previous = record.verificationFrontier(
            epoch: envelope.epoch, credential: envelope.senderCredentialHandle
        ), previous.nextCounter == envelope.messageCounter,
        previous.transcriptHash == envelope.transcriptHash,
        envelopeDigest.count == SHA256.byteCount else {
            throw GroupRuntimeError.invalidRecord
        }
        let digest = GroupApplicationVerificationReceiptV2.nextDigest(
            previous: previous.prefixDigest,
            eventID: envelope.eventId, groupID: envelope.groupId,
            epoch: envelope.epoch, transcriptHash: envelope.transcriptHash,
            credentialHandle: envelope.senderCredentialHandle,
            messageCounter: envelope.messageCounter,
            envelopeDigest: envelopeDigest,
            eventDigest: eventDigest,
            outcome: outcome
        )
        let receipt = GroupApplicationVerificationReceiptV2(
            eventID: envelope.eventId, groupID: envelope.groupId,
            eventDigest: eventDigest,
            epoch: envelope.epoch, transcriptHash: envelope.transcriptHash,
            credentialHandle: envelope.senderCredentialHandle,
            messageCounter: envelope.messageCounter,
            envelopeDigest: envelopeDigest,
            previousPrefixDigest: previous.prefixDigest,
            prefixDigest: digest, outcome: outcome
        )
        guard receipt.isStructurallyValid else { throw GroupRuntimeError.invalidRecord }
        let next = GroupApplicationVerificationFrontierV2(
            groupID: envelope.groupId, epoch: envelope.epoch,
            transcriptHash: envelope.transcriptHash,
            credentialHandle: envelope.senderCredentialHandle,
            nextCounter: envelope.messageCounter + 1,
            prefixDigest: digest
        )
        let frontiers = record.applicationVerificationFrontiers.filter {
            !($0.epoch == next.epoch && $0.credentialHandle == next.credentialHandle)
        } + [next]
        return (record.applicationVerificationReceipts + [receipt], frontiers)
    }
}

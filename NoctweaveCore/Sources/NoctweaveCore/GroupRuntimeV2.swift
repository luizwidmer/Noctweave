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
    public let preparedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case event
        case envelope
        case preparedAt
    }

    public init(
        id: UUID = UUID(),
        event: GroupConversationEventV2,
        envelope: GroupApplicationEnvelopeV2,
        preparedAt: Date
    ) {
        self.id = id
        self.event = event
        self.envelope = envelope
        self.preparedAt = preparedAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupRuntimeKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try values.decode(UUID.self, forKey: .id),
            event: try values.decode(GroupConversationEventV2.self, forKey: .event),
            envelope: try values.decode(GroupApplicationEnvelopeV2.self, forKey: .envelope),
            preparedAt: try values.decode(Date.self, forKey: .preparedAt)
        )
        guard isStructurallyValid else {
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
        try values.encode(preparedAt, forKey: .preparedAt)
    }

    public var isStructurallyValid: Bool {
        event.isStructurallyValid
            && envelope.isStructurallyValid
            && event.groupID == envelope.groupId
            && event.id == envelope.eventId
            && preparedAt.timeIntervalSince1970.isFinite
            && preparedAt >= event.createdAt
    }
}

/// Bounded replay receipt for an authenticated group application envelope.
public enum GroupApplicationProcessingOutcomeV2: String, Codable, Equatable {
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
        try requireExactGroupRuntimeKeys(decoder, CodingKeys.self)
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
            providerCommitBytes: try values.decode(Data.self, forKey: .providerCommitBytes),
            signedWelcomes: welcomes,
            deliveredCredentialHandles: delivered,
            createdAt: try values.decode(Date.self, forKey: .createdAt),
            updatedAt: try values.decode(Date.self, forKey: .updatedAt)
        )
        guard signedWelcomes == welcomes,
              deliveredCredentialHandles == delivered,
              transportRecipientCredentials == transportRecipients,
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
    public static let version = 5
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
        case pendingApplicationPublications
        case processedApplicationEnvelopes
        case outboundTransportOperations
        case inboundTransport
        case peerRouteCache
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
        try requireExactGroupRuntimeKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
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
            formatVersion: try values.decode(Int.self, forKey: .formatVersion),
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
              events.count <= NoctweaveArchitectureV2.maximumGroupEvents,
              Set(events.map(\.id)).count == events.count,
              Set(events.map {
                  GroupAuthorTransactionKeyV2(
                      memberHandle: $0.authorMemberHandle,
                      clientTransactionID: $0.clientTransactionID
                  )
              }).count == events.count,
              events.allSatisfy({ $0.groupID == groupId && $0.isStructurallyValid }),
              pendingApplicationPublications.count
                <= NoctweaveArchitectureV2.maximumPendingGroupPublications,
              Set(pendingApplicationPublications.map(\.id)).count
                == pendingApplicationPublications.count,
              Set(pendingApplicationPublications.map { $0.event.id }).count
                == pendingApplicationPublications.count,
              pendingApplicationPublications.allSatisfy({
                  $0.event.groupID == groupId
                      && $0.isStructurallyValid
                      && events.contains($0.event)
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
              }.map(\.eventID)).isSubset(of: Set(events.map(\.id))),
              Set(processedApplicationEnvelopes.lazy.filter {
                  $0.outcome != .accepted
              }.map(\.eventID)).isDisjoint(with: Set(events.map(\.id))),
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
        }
            return true
        }
    }

    public var isStructurallyValid: Bool {
        (try? isStructurallyValidThrowing) == true
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
        let recentIDs = Set(
            events.suffix(NoctweaveArchitectureV2.groupEventRecentWindow).map(\.id)
        )
        let retainedIDs = recentIDs.union(protected)
        return events.filter { retainedIDs.contains($0.id) }
    }

    /// Conservative sum of canonical field encodings plus fixed record
    /// framing. Array encodings include every duplicated artifact, so nominal
    /// entry-count bounds cannot bypass the durable byte budget.
    private func durableAggregateEncodedByteCountThrowing() throws -> Int {
        var total = 4_096
        func add<T: Encodable>(_ value: T) throws {
            let bytes = try NoctweaveCoder.encode(value, sortedKeys: true).count
            let (next, overflow) = total.addingReportingOverflow(bytes)
            guard !overflow else { throw GroupRuntimeError.capacityReached }
            total = next
        }
        try add(localCredential)
        try add(signedState)
        try add(cryptoState)
        try add(epochIntents)
        try add(quarantinedForks)
        try add(peerEpochJournal)
        try add(peerForkQuarantines)
        try add(pendingLocalCredentials)
        try add(localRemoval)
        try add(deletionState)
        try add(originJoinAnchorID)
        try add(events)
        try add(pendingApplicationPublications)
        try add(processedApplicationEnvelopes)
        try add(outboundTransportOperations)
        try add(inboundTransport)
        try add(peerRouteCache)
        return total
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
            preparedAt: date
        )
        guard pending.isStructurallyValid else {
            throw GroupRuntimeError.invalidRecord
        }
        try await persist(record.replacing(
            cryptoState: sealed.state,
            events: record.events + [event],
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
        try await persist(record.replacing(
            cryptoState: opened.state,
            events: record.events + [event],
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
        try await persist(record.replacing(
            cryptoState: cryptoState,
            processedApplicationEnvelopes: record.processedApplicationEnvelopes
                + [processed]
        ))
    }
}

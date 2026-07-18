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
    case publicationNotFound
    case capacityReached
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
public struct ProcessedGroupApplicationEnvelopeV2: Codable, Equatable, Identifiable {
    public var id: UUID { eventID }
    public let eventID: UUID
    public let envelopeDigest: Data
    public let processedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case eventID
        case envelopeDigest
        case processedAt
    }

    public init(eventID: UUID, envelopeDigest: Data, processedAt: Date) {
        self.eventID = eventID
        self.envelopeDigest = envelopeDigest
        self.processedAt = processedAt
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupRuntimeKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            eventID: try values.decode(UUID.self, forKey: .eventID),
            envelopeDigest: try values.decode(Data.self, forKey: .envelopeDigest),
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
    public let signedCommit: SignedGroupCommitV2
    public let signedState: SignedGroupStateV2
    public let providerCommitBytes: Data
    public let signedWelcomes: [SignedGroupWelcomeV2]

    public init(
        intentId: UUID,
        signedCommit: SignedGroupCommitV2,
        signedState: SignedGroupStateV2,
        providerCommitBytes: Data,
        signedWelcomes: [SignedGroupWelcomeV2]
    ) {
        self.intentId = intentId
        self.signedCommit = signedCommit
        self.signedState = signedState
        self.providerCommitBytes = providerCommitBytes
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
            providerCommitBytes: try values.decode(Data.self, forKey: .providerCommitBytes),
            signedWelcomes: welcomes,
            deliveredCredentialHandles: delivered,
            createdAt: try values.decode(Date.self, forKey: .createdAt),
            updatedAt: try values.decode(Date.self, forKey: .updatedAt)
        )
        guard signedWelcomes == welcomes,
              deliveredCredentialHandles == delivered,
              isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group epoch intent")
            )
        }
    }

    public var publication: GroupEpochPublication {
        GroupEpochPublication(
            intentId: id,
            signedCommit: signedCommit,
            signedState: nextSignedState,
            providerCommitBytes: providerCommitBytes,
            signedWelcomes: signedWelcomes
        )
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
            try NoctweavePQGroupExperimentalProviderV2().validateActiveState(
                nextCryptoState,
                signedState: nextSignedState,
                localCredential: localCredentialAfterCommit
            )
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
    public let conflictingCommit: SignedGroupCommitV2
    public let quarantinedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case groupId
        case baseEpoch
        case acceptedCommitDigest
        case conflictingCommitDigest
        case conflictingCommit
        case quarantinedAt
    }

    public init(
        id: UUID = UUID(),
        groupId: UUID,
        baseEpoch: UInt64,
        acceptedCommitDigest: Data,
        conflictingCommitDigest: Data,
        conflictingCommit: SignedGroupCommitV2,
        quarantinedAt: Date
    ) {
        self.id = id
        self.groupId = groupId
        self.baseEpoch = baseEpoch
        self.acceptedCommitDigest = acceptedCommitDigest
        self.conflictingCommitDigest = conflictingCommitDigest
        self.conflictingCommit = conflictingCommit
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
            conflictingCommit: try values.decode(
                SignedGroupCommitV2.self,
                forKey: .conflictingCommit
            ),
            quarantinedAt: try values.decode(Date.self, forKey: .quarantinedAt)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group fork quarantine")
            )
        }
    }

    public var isStructurallyValid: Bool {
        conflictingCommit.groupId == groupId
            && conflictingCommit.baseEpoch == baseEpoch
            && acceptedCommitDigest.count == 32
            && conflictingCommitDigest.count == 32
            && conflictingCommit.digest == conflictingCommitDigest
            && acceptedCommitDigest != conflictingCommitDigest
            && quarantinedAt.timeIntervalSince1970.isFinite
    }
}

public struct GroupRuntimeRecord: Codable, Equatable, Identifiable {
    public static let version = 1
    public static let maximumQuarantinedForks = 64

    public var id: UUID { groupId }
    public let formatVersion: Int
    public let groupId: UUID
    public let localCredential: LocalGroupCredentialV2
    public let signedState: SignedGroupStateV2
    public let cryptoState: GroupCryptoState
    public let epochIntents: [GroupEpochIntent]
    public let quarantinedForks: [GroupEpochForkQuarantine]
    public let events: [GroupConversationEventV2]
    public let pendingApplicationPublications: [PendingGroupApplicationPublicationV2]
    public let processedApplicationEnvelopes: [ProcessedGroupApplicationEnvelopeV2]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case formatVersion
        case groupId
        case localCredential
        case signedState
        case cryptoState
        case epochIntents
        case quarantinedForks
        case events
        case pendingApplicationPublications
        case processedApplicationEnvelopes
    }

    public init(
        formatVersion: Int = GroupRuntimeRecord.version,
        groupId: UUID,
        localCredential: LocalGroupCredentialV2,
        signedState: SignedGroupStateV2,
        cryptoState: GroupCryptoState,
        epochIntents: [GroupEpochIntent] = [],
        quarantinedForks: [GroupEpochForkQuarantine] = [],
        events: [GroupConversationEventV2] = [],
        pendingApplicationPublications: [PendingGroupApplicationPublicationV2] = [],
        processedApplicationEnvelopes: [ProcessedGroupApplicationEnvelopeV2] = []
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
        self.events = events.sorted {
            if $0.createdAt != $1.createdAt { return $0.createdAt < $1.createdAt }
            return $0.id.uuidString < $1.id.uuidString
        }
        self.pendingApplicationPublications = pendingApplicationPublications.sorted {
            if $0.preparedAt != $1.preparedAt { return $0.preparedAt < $1.preparedAt }
            return $0.id.uuidString < $1.id.uuidString
        }
        self.processedApplicationEnvelopes = processedApplicationEnvelopes.sorted {
            if $0.processedAt != $1.processedAt { return $0.processedAt < $1.processedAt }
            return $0.eventID.uuidString < $1.eventID.uuidString
        }
    }

    public init(from decoder: Decoder) throws {
        try requireExactGroupRuntimeKeys(decoder, CodingKeys.self)
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let intents = try values.decode([GroupEpochIntent].self, forKey: .epochIntents)
        let forks = try values.decode(
            [GroupEpochForkQuarantine].self,
            forKey: .quarantinedForks
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
            events: decodedEvents,
            pendingApplicationPublications: decodedPending,
            processedApplicationEnvelopes: decodedProcessed
        )
        guard epochIntents == intents,
              quarantinedForks == forks,
              events == decodedEvents,
              pendingApplicationPublications == decodedPending,
              processedApplicationEnvelopes == decodedProcessed,
              isStructurallyValid else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Invalid group runtime record")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
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
        try values.encode(events, forKey: .events)
        try values.encode(
            pendingApplicationPublications,
            forKey: .pendingApplicationPublications
        )
        try values.encode(
            processedApplicationEnvelopes,
            forKey: .processedApplicationEnvelopes
        )
    }

    public var isStructurallyValid: Bool {
        guard formatVersion == Self.version,
              localCredential.groupId == groupId,
              signedState.groupId == groupId,
              cryptoState.groupId == groupId,
              signedState.epoch == cryptoState.epoch,
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
              events.count <= NoctweaveArchitectureV2.maximumGroupEvents,
              Set(events.map(\.id)).count == events.count,
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
              Set(processedApplicationEnvelopes.map(\.eventID))
                .isSubset(of: Set(events.map(\.id))) else {
            return false
        }
        do {
            try NoctweavePQGroupExperimentalProviderV2().validateActiveState(
                cryptoState,
                signedState: signedState,
                localCredential: localCredential
            )
            return true
        } catch {
            return false
        }
    }

    /// Retains every unfinished epoch mutation and the newest finalized
    /// publications. Finalized artifacts are a bounded duplicate/fork window,
    /// not an unbounded group archive.
    public func compactedDurableState() throws -> GroupRuntimeRecord {
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
                retainedEventIDs.contains($0.eventID)
            }.suffix(NoctweaveArchitectureV2.processedGroupEnvelopeRecentWindow)
        )
        let candidate = replacing(
            epochIntents: epochIntents.filter { retainedIDs.contains($0.id) },
            events: retainedEvents,
            processedApplicationEnvelopes: retainedProcessed
        )
        guard candidate.isStructurallyValid else {
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

    fileprivate func replacing(
        localCredential: LocalGroupCredentialV2? = nil,
        signedState: SignedGroupStateV2? = nil,
        cryptoState: GroupCryptoState? = nil,
        epochIntents: [GroupEpochIntent]? = nil,
        quarantinedForks: [GroupEpochForkQuarantine]? = nil,
        events: [GroupConversationEventV2]? = nil,
        pendingApplicationPublications: [PendingGroupApplicationPublicationV2]? = nil,
        processedApplicationEnvelopes: [ProcessedGroupApplicationEnvelopeV2]? = nil
    ) -> GroupRuntimeRecord {
        GroupRuntimeRecord(
            formatVersion: formatVersion,
            groupId: groupId,
            localCredential: localCredential ?? self.localCredential,
            signedState: signedState ?? self.signedState,
            cryptoState: cryptoState ?? self.cryptoState,
            epochIntents: epochIntents ?? self.epochIntents,
            quarantinedForks: quarantinedForks ?? self.quarantinedForks,
            events: events ?? self.events,
            pendingApplicationPublications: pendingApplicationPublications
                ?? self.pendingApplicationPublications,
            processedApplicationEnvelopes: processedApplicationEnvelopes
                ?? self.processedApplicationEnvelopes
        )
    }

    private func compactedEvents() -> [GroupConversationEventV2] {
        guard events.count > NoctweaveArchitectureV2.groupEventRecentWindow else {
            return events
        }
        let protected = Set(pendingApplicationPublications.map { $0.event.id })
        var retained = Array(
            events.suffix(NoctweaveArchitectureV2.groupEventRecentWindow)
        )
        let retainedIDs = Set(retained.map(\.id))
        retained.append(contentsOf: events.filter {
            protected.contains($0.id) && !retainedIDs.contains($0.id)
        })
        return retained.sorted {
            if $0.createdAt != $1.createdAt { return $0.createdAt < $1.createdAt }
            return $0.id.uuidString < $1.id.uuidString
        }
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
    private var record: GroupRuntimeRecord

    public init(
        record: GroupRuntimeRecord,
        persistence: any GroupRuntimeRecordPersistence,
        provider: NoctweavePQGroupExperimentalProviderV2 = .init()
    ) throws {
        guard record.isStructurallyValid else { throw GroupRuntimeError.invalidRecord }
        self.record = record
        self.persistence = persistence
        self.provider = provider
    }

    public static func create(
        record: GroupRuntimeRecord,
        persistence: any GroupRuntimeRecordPersistence
    ) async throws -> NoctweavePQGroupRuntimeV2 {
        guard record.isStructurallyValid else { throw GroupRuntimeError.invalidRecord }
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

    public func snapshot() -> GroupRuntimeRecord { record }

    public func pendingApplicationPublications() -> [PendingGroupApplicationPublicationV2] {
        record.pendingApplicationPublications
    }

    /// Atomically advances the sender chain and stores the exact encrypted
    /// envelope in a durable outbox before returning it to a transport adapter.
    public func prepareApplicationEvent(
        _ event: GroupConversationEventV2,
        at date: Date = Date()
    ) async throws -> GroupApplicationEnvelopeV2 {
        guard event.isStructurallyValid,
              event.groupID == record.groupId,
              date.timeIntervalSince1970.isFinite,
              date >= event.createdAt else {
            throw GroupRuntimeError.invalidRecord
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
        guard record.pendingApplicationPublications.count
                < NoctweaveArchitectureV2.maximumPendingGroupPublications,
              record.events.count < NoctweaveArchitectureV2.maximumGroupEvents else {
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
        guard record.pendingApplicationPublications.contains(where: {
            $0.event.id == eventID
        }) else {
            throw GroupRuntimeError.publicationNotFound
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
            guard processed.envelopeDigest == envelopeDigest,
                  let existing = record.events.first(where: {
                      $0.id == envelope.eventId
                  }) else {
                throw GroupRuntimeError.conflictingApplicationEnvelope
            }
            return existing
        }
        guard !record.events.contains(where: { $0.id == envelope.eventId }),
              record.events.count < NoctweaveArchitectureV2.maximumGroupEvents,
              record.processedApplicationEnvelopes.count
                < NoctweaveArchitectureV2.maximumProcessedGroupEnvelopes else {
            throw GroupRuntimeError.capacityReached
        }
        let opened = try provider.decryptApplicationEvent(
            envelope,
            state: record.cryptoState,
            signedState: record.signedState
        )
        let event = try NoctweaveCoder.decode(
            GroupConversationEventV2.self,
            from: opened.plaintext
        )
        guard event.groupID == record.groupId,
              event.id == envelope.eventId else {
            throw GroupRuntimeError.conflictingApplicationEnvelope
        }
        let processed = ProcessedGroupApplicationEnvelopeV2(
            eventID: event.id,
            envelopeDigest: envelopeDigest,
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
        guard !record.epochIntents.contains(where: {
            $0.baseEpoch == record.signedState.epoch && $0.phase == .prepared
        }) else {
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
        let prepared = try provider.prepareCommit(
            state: record.cryptoState,
            currentMembership: currentMembership,
            proposedMembership: proposedMembership,
            localCredential: record.localCredential,
            nextLocalCredential: replacementLocalCredential
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
        try await resumeOrReturn(intentId, at: date)
    }

    public func markFanoutStored(
        intentId: UUID,
        destinationCredentialHandle: GroupScopedCredentialHandleV2,
        at date: Date = Date()
    ) async throws {
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
        guard let index = record.epochIntents.firstIndex(where: { $0.id == intentId }) else {
            throw GroupRuntimeError.unknownIntent
        }
        let intent = record.epochIntents[index]
        if intent.phase == .finalized { return }
        guard intent.phase == .stateCommitted || intent.phase == .fanoutInProgress else {
            throw GroupRuntimeError.invalidIntent
        }
        let required = Set(intent.signedWelcomes.map(\.destinationCredentialHandle)).subtracting([
            record.localCredential.credentialHandle
        ])
        guard Set(intent.deliveredCredentialHandles).isSuperset(of: required) else {
            throw GroupRuntimeError.incompleteFanout
        }
        let updated = try intent.advancing(to: .finalized, at: date)
        var intents = record.epochIntents
        intents[index] = updated
        try await persist(record.replacing(epochIntents: intents))
    }

    /// Returns the exact retained artifacts for a duplicate commit and
    /// quarantines a different digest that claims the same base epoch.
    public func observeCommit(
        _ commit: SignedGroupCommitV2,
        at date: Date = Date()
    ) async throws -> GroupEpochPublication? {
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
                conflictingCommit: commit,
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
            commit: intent.signedCommit
        )
        try provider.validateActiveState(
            intent.nextCryptoState,
            signedState: intent.nextSignedState,
            localCredential: intent.localCredentialAfterCommit
        )
        let committedIntent = try intent.advancing(to: .stateCommitted, at: date)
        var intents = record.epochIntents
        intents[index] = committedIntent
        let candidate = record.replacing(
            localCredential: intent.localCredentialAfterCommit,
            signedState: intent.nextSignedState,
            cryptoState: intent.nextCryptoState,
            epochIntents: intents
        )
        try await persist(candidate)
        return committedIntent.publication
    }

    private func persist(_ candidate: GroupRuntimeRecord) async throws {
        let compacted = try candidate.compactedDurableState()
        guard compacted.isStructurallyValid else { throw GroupRuntimeError.invalidRecord }
        try await persistence.save(compacted)
        record = compacted
    }
}

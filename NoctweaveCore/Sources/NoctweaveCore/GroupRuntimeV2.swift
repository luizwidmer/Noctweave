import CryptoKit
import Foundation

public enum GroupRuntimeError: Error, Equatable {
    case invalidRecord
    case missingRecord
    case invalidIntent
    case unknownIntent
    case pendingEpoch
    case staleEpoch
    case conflictingCommitQuarantined
    case incompleteFanout
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
            $0.destinationClientHandle.rawValue < $1.destinationClientHandle.rawValue
        }
    }
}

public struct GroupEpochIntent: Codable, Equatable, Identifiable {
    public static let maximumJournalEntries = 256

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
    public let providerCommitBytes: Data
    public let signedWelcomes: [SignedGroupWelcomeV2]
    public let deliveredClientHandles: [GroupScopedClientHandleV2]
    public let createdAt: Date
    public let updatedAt: Date

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
        providerCommitBytes: Data,
        signedWelcomes: [SignedGroupWelcomeV2],
        deliveredClientHandles: [GroupScopedClientHandleV2] = [],
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
        self.providerCommitBytes = providerCommitBytes
        self.signedWelcomes = signedWelcomes.sorted {
            $0.destinationClientHandle.rawValue < $1.destinationClientHandle.rawValue
        }
        self.deliveredClientHandles = deliveredClientHandles.sorted {
            $0.rawValue < $1.rawValue
        }
        self.createdAt = createdAt
        self.updatedAt = updatedAt
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
              Data(SHA256.hash(data: providerCommitBytes)) == signedCommit.providerCommitDigest,
              !providerCommitBytes.isEmpty,
              providerCommitBytes.count <= NoctweaveGroupArchitectureV2.maximumCommitBytes,
              !signedWelcomes.isEmpty,
              signedWelcomes.count
                  <= NoctweaveGroupArchitectureV2.maximumActiveExperimentalClientLeaves,
              Set(signedWelcomes.map(\.destinationClientHandle)).count == signedWelcomes.count,
              signedWelcomes.allSatisfy({
                  $0.isStructurallyValid
                      && $0.groupId == groupId
                      && $0.epoch == nextEpoch
                      && $0.commitDigest == signedCommitDigest
                      && $0.stateTranscriptHash == nextSignedState.confirmedTranscriptHash
              }),
              Set(deliveredClientHandles).count == deliveredClientHandles.count,
              Set(deliveredClientHandles).isSubset(
                  of: Set(signedWelcomes.map(\.destinationClientHandle))
              ),
              createdAt.timeIntervalSince1970.isFinite,
              updatedAt.timeIntervalSince1970.isFinite,
              updatedAt >= createdAt else {
            return false
        }
        switch phase {
        case .prepared, .stateCommitted:
            return deliveredClientHandles.isEmpty
        case .fanoutInProgress:
            return !deliveredClientHandles.isEmpty
        case .finalized:
            return true
        }
    }

    public func advancing(
        to phase: GroupEpochIntentPhase,
        deliveredClientHandles: [GroupScopedClientHandleV2]? = nil,
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
            providerCommitBytes: providerCommitBytes,
            signedWelcomes: signedWelcomes,
            deliveredClientHandles: deliveredClientHandles ?? self.deliveredClientHandles,
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
    public let localCredential: LocalGroupClientCredential
    public let signedState: SignedGroupStateV2
    public let cryptoState: GroupCryptoState
    public let epochIntents: [GroupEpochIntent]
    public let quarantinedForks: [GroupEpochForkQuarantine]

    public init(
        formatVersion: Int = GroupRuntimeRecord.version,
        groupId: UUID,
        localCredential: LocalGroupClientCredential,
        signedState: SignedGroupStateV2,
        cryptoState: GroupCryptoState,
        epochIntents: [GroupEpochIntent] = [],
        quarantinedForks: [GroupEpochForkQuarantine] = []
    ) {
        self.formatVersion = formatVersion
        self.groupId = groupId
        self.localCredential = localCredential
        self.signedState = signedState
        self.cryptoState = cryptoState
        self.epochIntents = epochIntents.sorted {
            if $0.baseEpoch != $1.baseEpoch { return $0.baseEpoch < $1.baseEpoch }
            return $0.createdAt < $1.createdAt
        }
        self.quarantinedForks = quarantinedForks.sorted {
            $0.quarantinedAt < $1.quarantinedAt
        }
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
              epochIntents.allSatisfy(\.isStructurallyValid),
              quarantinedForks.count <= Self.maximumQuarantinedForks,
              quarantinedForks.allSatisfy(\.isStructurallyValid) else {
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

    fileprivate func replacing(
        signedState: SignedGroupStateV2? = nil,
        cryptoState: GroupCryptoState? = nil,
        epochIntents: [GroupEpochIntent]? = nil,
        quarantinedForks: [GroupEpochForkQuarantine]? = nil
    ) -> GroupRuntimeRecord {
        GroupRuntimeRecord(
            formatVersion: formatVersion,
            groupId: groupId,
            localCredential: localCredential,
            signedState: signedState ?? self.signedState,
            cryptoState: cryptoState ?? self.cryptoState,
            epochIntents: epochIntents ?? self.epochIntents,
            quarantinedForks: quarantinedForks ?? self.quarantinedForks
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

    public func prepareEpoch(
        operation: SignedGroupCommitOperationV2,
        proposedUsers: [GroupUser],
        proposedClientLeaves: [GroupClientLeafV2],
        admissionProjection: GroupClientAdmissionProjectionV2? = nil,
        siblingClientConsent: GroupSiblingClientConsentV2? = nil,
        proposedPermissions: GroupPermissionPolicy,
        proposedMetadataDigest: Data?,
        idempotencyKey: Data,
        createdAt: Date = Date()
    ) async throws -> GroupEpochPublication {
        guard idempotencyKey.count == 32,
              createdAt.timeIntervalSince1970.isFinite else {
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
            users: proposedUsers,
            leaves: proposedClientLeaves
        )
        let prepared = try provider.prepareCommit(
            state: record.cryptoState,
            currentMembership: currentMembership,
            proposedMembership: proposedMembership,
            localCredential: record.localCredential
        )
        guard let providerCommitDigest = prepared.providerCommitDigest else {
            throw GroupRuntimeError.invalidIntent
        }
        let signedCommit = try SignedGroupCommitV2.create(
            operation: operation,
            currentState: record.signedState,
            proposedUsers: proposedUsers,
            proposedClientLeaves: proposedClientLeaves,
            admissionProjection: admissionProjection,
            siblingClientConsent: siblingClientConsent,
            proposedPermissions: proposedPermissions,
            proposedMetadataDigest: proposedMetadataDigest,
            authorClientHandle: record.localCredential.clientHandle,
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
                destinationClientHandle: welcome.destination,
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
        destinationClientHandle: GroupScopedClientHandleV2,
        at date: Date = Date()
    ) async throws {
        guard let index = record.epochIntents.firstIndex(where: { $0.id == intentId }) else {
            throw GroupRuntimeError.unknownIntent
        }
        let intent = record.epochIntents[index]
        guard intent.phase == .stateCommitted || intent.phase == .fanoutInProgress,
              intent.signedWelcomes.contains(where: {
                  $0.destinationClientHandle == destinationClientHandle
              }) else {
            throw GroupRuntimeError.invalidIntent
        }
        if intent.deliveredClientHandles.contains(destinationClientHandle) { return }
        let delivered = intent.deliveredClientHandles + [destinationClientHandle]
        let updated = try intent.advancing(
            to: .fanoutInProgress,
            deliveredClientHandles: delivered,
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
        let required = Set(intent.signedWelcomes.map(\.destinationClientHandle)).subtracting([
            record.localCredential.clientHandle
        ])
        guard Set(intent.deliveredClientHandles).isSuperset(of: required) else {
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
            localCredential: record.localCredential
        )
        let committedIntent = try intent.advancing(to: .stateCommitted, at: date)
        var intents = record.epochIntents
        intents[index] = committedIntent
        let candidate = record.replacing(
            signedState: intent.nextSignedState,
            cryptoState: intent.nextCryptoState,
            epochIntents: intents
        )
        try await persist(candidate)
        return committedIntent.publication
    }

    private func persist(_ candidate: GroupRuntimeRecord) async throws {
        guard candidate.isStructurallyValid else { throw GroupRuntimeError.invalidRecord }
        try await persistence.save(candidate)
        record = candidate
    }
}

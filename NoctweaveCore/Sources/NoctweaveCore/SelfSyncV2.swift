import Foundation

/// Shared limits retained by the signed self-sync and inert history-transfer
/// profiles. The former unsigned/generic self-sync record, raw-token
/// rendezvous, and authority-shaped history-grant models were removed before
/// 1.0; their existence encouraged callers to bypass source authentication and
/// purpose-specific state machines.
public enum NoctweaveSelfSyncV2 {
    public static let version = 2
    public static let maximumArchiveBytes: UInt64 = 16 * 1_024 * 1_024 * 1_024
}

/// External work that must complete after one endpoint is removed. Advancing
/// the endpoint set and rekeying local self-sync are not presented as complete
/// remote revocation until every obligation has been durably handled.
public enum EndpointRemovalCleanupKindV2: String, Codable, Equatable, Hashable, CaseIterable {
    case publishEndpointSet
    case redistributeSelfSyncKey
    case revokeMailboxAccess
    case removeRelationshipRoutes
    case removeGroupClients
}

public struct EndpointRemovalCleanupObligationV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let identityGenerationId: UUID
    public let removedEndpointId: UUID
    public let endpointSetEpoch: UInt64
    public let endpointSetDigest: Data
    public let replacementSelfSyncStreamDigest: Data
    public let remainingEndpointIds: [UUID]
    public let kind: EndpointRemovalCleanupKindV2
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        identityGenerationId: UUID,
        removedEndpointId: UUID,
        endpointSetEpoch: UInt64,
        endpointSetDigest: Data,
        replacementSelfSyncStreamDigest: Data,
        remainingEndpointIds: [UUID],
        kind: EndpointRemovalCleanupKindV2,
        createdAt: Date
    ) {
        self.id = id
        self.identityGenerationId = identityGenerationId
        self.removedEndpointId = removedEndpointId
        self.endpointSetEpoch = endpointSetEpoch
        self.endpointSetDigest = endpointSetDigest
        self.replacementSelfSyncStreamDigest = replacementSelfSyncStreamDigest
        self.remainingEndpointIds = Array(Set(remainingEndpointIds)).sorted {
            $0.uuidString < $1.uuidString
        }
        self.kind = kind
        self.createdAt = createdAt
    }

    public var isStructurallyValid: Bool {
        endpointSetDigest.count == 32
            && replacementSelfSyncStreamDigest.count == 32
            && remainingEndpointIds.count <= NoctweaveArchitectureV2.maximumInstallations
            && Set(remainingEndpointIds).count == remainingEndpointIds.count
            && !remainingEndpointIds.contains(removedEndpointId)
            && createdAt.timeIntervalSince1970.isFinite
    }
}

/// Atomic local result of endpoint removal. The replacement self-sync key is
/// retained only in `IdentityProfile.selfSyncV2`; this result carries digests
/// and a bounded explicit cleanup plan, never the new secret.
public struct EndpointRemovalResultV2: Codable, Equatable {
    public let identityGenerationId: UUID
    public let removedEndpointId: UUID
    public let endpointSetEpoch: UInt64
    public let endpointSetDigest: Data
    public let replacementSelfSyncStreamDigest: Data
    public let cleanupObligations: [EndpointRemovalCleanupObligationV2]

    public init(
        identityGenerationId: UUID,
        removedEndpointId: UUID,
        endpointSetEpoch: UInt64,
        endpointSetDigest: Data,
        replacementSelfSyncStreamDigest: Data,
        cleanupObligations: [EndpointRemovalCleanupObligationV2]
    ) {
        self.identityGenerationId = identityGenerationId
        self.removedEndpointId = removedEndpointId
        self.endpointSetEpoch = endpointSetEpoch
        self.endpointSetDigest = endpointSetDigest
        self.replacementSelfSyncStreamDigest = replacementSelfSyncStreamDigest
        self.cleanupObligations = cleanupObligations.sorted { $0.kind.rawValue < $1.kind.rawValue }
    }

    public var isStructurallyValid: Bool {
        let expectedKinds = Set(EndpointRemovalCleanupKindV2.allCases)
        return endpointSetDigest.count == 32
            && replacementSelfSyncStreamDigest.count == 32
            && !cleanupObligations.isEmpty
            && cleanupObligations.count
                <= NoctweaveArchitectureV2.maximumEndpointCleanupObligations
            && Set(cleanupObligations.map(\.id)).count == cleanupObligations.count
            && Set(cleanupObligations.map(\.kind)) == expectedKinds
            && cleanupObligations.allSatisfy {
                $0.isStructurallyValid
                    && $0.identityGenerationId == identityGenerationId
                    && $0.removedEndpointId == removedEndpointId
                    && $0.endpointSetEpoch == endpointSetEpoch
                    && $0.endpointSetDigest == endpointSetDigest
                    && $0.replacementSelfSyncStreamDigest == replacementSelfSyncStreamDigest
            }
    }

    public var requiresExternalCleanup: Bool { true }
    public var authorizesFutureParticipation: Bool { false }
}

/// Durable local record for the remote work left by an endpoint-set removal.
/// The exact obligations live with the profile until each one is acknowledged;
/// ignoring the immediate removal return value cannot lose cleanup state.
public struct EndpointRemovalJournalV2: Codable, Equatable, Identifiable {
    public let id: UUID
    public let result: EndpointRemovalResultV2
    public let completedObligationIds: [UUID]
    public let createdAt: Date
    public let updatedAt: Date

    public init(
        id: UUID = UUID(),
        result: EndpointRemovalResultV2,
        completedObligationIds: [UUID] = [],
        createdAt: Date,
        updatedAt: Date? = nil
    ) {
        self.id = id
        self.result = result
        self.completedObligationIds = Array(Set(completedObligationIds)).sorted {
            $0.uuidString < $1.uuidString
        }
        self.createdAt = createdAt
        self.updatedAt = updatedAt ?? createdAt
    }

    public var pendingObligations: [EndpointRemovalCleanupObligationV2] {
        let completed = Set(completedObligationIds)
        return result.cleanupObligations.filter { !completed.contains($0.id) }
    }

    public var isStructurallyValid: Bool {
        let obligationIds = Set(result.cleanupObligations.map(\.id))
        let completed = Set(completedObligationIds)
        return result.isStructurallyValid
            && completedObligationIds.count == completed.count
            && completed.isSubset(of: obligationIds)
            && completed.count < obligationIds.count
            && createdAt.timeIntervalSince1970.isFinite
            && updatedAt.timeIntervalSince1970.isFinite
            && updatedAt >= createdAt
    }

    /// Replays are idempotent. Completing the final obligation returns `nil`,
    /// which tells the profile to remove the fully settled journal.
    public func completing(
        obligationId: UUID,
        at date: Date
    ) -> EndpointRemovalJournalV2? {
        guard date.timeIntervalSince1970.isFinite,
              date >= updatedAt,
              result.cleanupObligations.contains(where: { $0.id == obligationId }) else {
            return self
        }
        if completedObligationIds.contains(obligationId) { return self }
        let completed = completedObligationIds + [obligationId]
        if completed.count == result.cleanupObligations.count { return nil }
        return EndpointRemovalJournalV2(
            id: id,
            result: result,
            completedObligationIds: completed,
            createdAt: createdAt,
            updatedAt: date
        )
    }
}

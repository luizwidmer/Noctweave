import CryptoKit
import Foundation

public enum HiddenRetrievalError: Error, Equatable {
    case invalidCoverSetSize
    case invalidBucketId
    case invalidTargetRecordId
    case invalidRecordId
    case invalidSecret
    case coverSetTooLarge
    case emptyBucket
    case targetMissing
    case insufficientBucketRecords
    case malformedPublicPlan
    case incompleteCoverResponse
    case unexpectedResponseRecords
}

public struct HiddenRetrievalQueryPlan: Codable, Equatable {
    public let bucketId: String
    public let requestedRecordIds: [String]
    public let targetRecordId: String

    public init(bucketId: String, requestedRecordIds: [String], targetRecordId: String) {
        self.bucketId = bucketId
        self.requestedRecordIds = requestedRecordIds
        self.targetRecordId = targetRecordId
    }

    public var targetOffset: Int? {
        requestedRecordIds.firstIndex(of: targetRecordId)
    }
}

public enum HiddenRetrievalPlanner {
    public static func makeCoverQuery(
        bucketId: String,
        availableRecordIds: [String],
        targetRecordId: String,
        coverSetSize: Int,
        secret: Data,
        maximumCoverSetSize: Int = 512
    ) throws -> HiddenRetrievalQueryPlan {
        let canonicalBucketId = bucketId.trimmingCharacters(in: .whitespacesAndNewlines)
        let canonicalTargetId = targetRecordId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !canonicalBucketId.isEmpty else {
            throw HiddenRetrievalError.invalidBucketId
        }
        guard !canonicalTargetId.isEmpty else {
            throw HiddenRetrievalError.invalidTargetRecordId
        }
        guard !secret.isEmpty else {
            throw HiddenRetrievalError.invalidSecret
        }
        guard coverSetSize >= 2 else {
            throw HiddenRetrievalError.invalidCoverSetSize
        }
        guard coverSetSize <= max(2, maximumCoverSetSize) else {
            throw HiddenRetrievalError.coverSetTooLarge
        }

        let normalizedIds = availableRecordIds.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        guard !normalizedIds.contains(where: { $0.isEmpty }) else {
            throw HiddenRetrievalError.invalidRecordId
        }
        let canonicalIds = Array(Set(normalizedIds)).sorted()
        guard !canonicalIds.isEmpty else {
            throw HiddenRetrievalError.emptyBucket
        }
        guard canonicalIds.contains(canonicalTargetId) else {
            throw HiddenRetrievalError.targetMissing
        }
        guard canonicalIds.count >= coverSetSize else {
            throw HiddenRetrievalError.insufficientBucketRecords
        }

        let decoys = canonicalIds.filter { $0 != canonicalTargetId }
            .map { id in
                (id: id, rank: rank(bucketId: canonicalBucketId, recordId: id, targetRecordId: canonicalTargetId, secret: secret))
            }
            .sorted { lhs, rhs in
                if lhs.rank == rhs.rank {
                    return lhs.id < rhs.id
                }
                return lhs.rank.lexicographicallyPrecedes(rhs.rank)
            }
            .prefix(max(0, coverSetSize - 1))
            .map(\.id)

        let selected = ([canonicalTargetId] + decoys).sorted()
        return HiddenRetrievalQueryPlan(
            bucketId: canonicalBucketId,
            requestedRecordIds: selected,
            targetRecordId: canonicalTargetId
        )
    }

    public static func extractTarget<T>(
        from records: [String: T],
        using plan: HiddenRetrievalQueryPlan
    ) throws -> T {
        try validateResponse(records: records, using: plan)
        return records[plan.targetRecordId]!
    }

    public static func targetIfValid<T>(
        from records: [String: T],
        using plan: HiddenRetrievalQueryPlan
    ) -> T? {
        try? extractTarget(from: records, using: plan)
    }

    public static func validateResponse<T>(
        records: [String: T],
        using plan: HiddenRetrievalQueryPlan
    ) throws {
        guard !plan.bucketId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !plan.targetRecordId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              plan.requestedRecordIds.count >= 2,
              Set(plan.requestedRecordIds).count == plan.requestedRecordIds.count,
              !plan.requestedRecordIds.contains(where: { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }),
              plan.requestedRecordIds.filter({ $0 == plan.targetRecordId }).count == 1 else {
            throw HiddenRetrievalError.malformedPublicPlan
        }
        guard plan.requestedRecordIds.allSatisfy({ records[$0] != nil }) else {
            throw HiddenRetrievalError.incompleteCoverResponse
        }
        guard Set(records.keys).isSubset(of: Set(plan.requestedRecordIds)) else {
            throw HiddenRetrievalError.unexpectedResponseRecords
        }
    }

    private static func rank(
        bucketId: String,
        recordId: String,
        targetRecordId: String,
        secret: Data
    ) -> [UInt8] {
        var data = Data("noctyra-hidden-retrieval-v1".utf8)
        data.append(Data(bucketId.utf8))
        data.append(0)
        data.append(Data(targetRecordId.utf8))
        data.append(0)
        data.append(Data(recordId.utf8))
        data.append(0)
        data.append(secret)
        return Array(SHA256.hash(data: data))
    }
}

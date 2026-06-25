import CryptoKit
import Foundation

public enum HiddenRetrievalError: Error, Equatable {
    case invalidCoverSetSize
    case emptyBucket
    case targetMissing
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
        secret: Data
    ) throws -> HiddenRetrievalQueryPlan {
        guard coverSetSize > 0 else {
            throw HiddenRetrievalError.invalidCoverSetSize
        }

        let canonicalIds = Array(Set(availableRecordIds)).sorted()
        guard !canonicalIds.isEmpty else {
            throw HiddenRetrievalError.emptyBucket
        }
        guard canonicalIds.contains(targetRecordId) else {
            throw HiddenRetrievalError.targetMissing
        }

        let decoys = canonicalIds.filter { $0 != targetRecordId }
            .map { id in
                (id: id, rank: rank(bucketId: bucketId, recordId: id, targetRecordId: targetRecordId, secret: secret))
            }
            .sorted { lhs, rhs in
                if lhs.rank == rhs.rank {
                    return lhs.id < rhs.id
                }
                return lhs.rank.lexicographicallyPrecedes(rhs.rank)
            }
            .prefix(max(0, coverSetSize - 1))
            .map(\.id)

        let selected = ([targetRecordId] + decoys).sorted()
        return HiddenRetrievalQueryPlan(
            bucketId: bucketId,
            requestedRecordIds: selected,
            targetRecordId: targetRecordId
        )
    }

    public static func extractTarget<T>(
        from records: [String: T],
        using plan: HiddenRetrievalQueryPlan
    ) -> T? {
        records[plan.targetRecordId]
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

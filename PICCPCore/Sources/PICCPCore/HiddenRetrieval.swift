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
    case invalidReplicaCount
    case invalidRecordCount
    case invalidRecordSize
    case malformedPIRShare
    case malformedPIRResponse
    case invalidReplicaSet
}

public enum HiddenRetrievalPIRReplicaSetIssue: String, Codable, Equatable, Hashable {
    case hiddenRetrievalUnavailable
    case unsupportedMode
    case insufficientReplicas
    case blankReplicaId
    case blankOperatorId
    case duplicateReplicaId
    case duplicateOperatorId
    case duplicateHost
    case duplicateEndpoint
    case insecureEndpoint
}

public enum HiddenRetrievalPIRReplicaSetValidator {
    public static func issues(
        for support: HiddenRetrievalSupport?,
        minimumReplicaCount: Int = 2,
        requireTLS: Bool = true
    ) -> [HiddenRetrievalPIRReplicaSetIssue] {
        guard let support else {
            return [.hiddenRetrievalUnavailable]
        }
        guard support.mode == .replicatedXorPIR else {
            return [.unsupportedMode]
        }

        let replicas = support.replicatedXorPIRReplicas ?? []
        var issues: [HiddenRetrievalPIRReplicaSetIssue] = []
        if replicas.count < max(2, minimumReplicaCount) {
            issues.append(.insufficientReplicas)
        }

        let replicaIds = replicas.map { $0.replicaId.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        let operatorIds = replicas.map { $0.operatorId.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        let hosts = replicas.map { $0.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        let endpoints = replicas.map { normalizedEndpointKey($0.endpoint) }

        if replicaIds.contains(where: \.isEmpty) {
            issues.append(.blankReplicaId)
        }
        if operatorIds.contains(where: \.isEmpty) {
            issues.append(.blankOperatorId)
        }
        if Set(replicaIds).count != replicaIds.count {
            issues.append(.duplicateReplicaId)
        }
        if Set(operatorIds).count != operatorIds.count {
            issues.append(.duplicateOperatorId)
        }
        if Set(hosts).count != hosts.count {
            issues.append(.duplicateHost)
        }
        if Set(endpoints).count != endpoints.count {
            issues.append(.duplicateEndpoint)
        }
        if requireTLS, replicas.contains(where: { !$0.endpoint.useTLS }) {
            issues.append(.insecureEndpoint)
        }

        return Array(Set(issues)).sorted { $0.rawValue < $1.rawValue }
    }

    public static func validate(
        _ support: HiddenRetrievalSupport?,
        minimumReplicaCount: Int = 2,
        requireTLS: Bool = true
    ) throws -> [HiddenRetrievalPIRReplica] {
        let problems = issues(
            for: support,
            minimumReplicaCount: minimumReplicaCount,
            requireTLS: requireTLS
        )
        guard problems.isEmpty else {
            throw HiddenRetrievalError.invalidReplicaSet
        }
        return support?.replicatedXorPIRReplicas ?? []
    }

    public static func isUsable(
        _ support: HiddenRetrievalSupport?,
        minimumReplicaCount: Int = 2,
        requireTLS: Bool = true
    ) -> Bool {
        issues(
            for: support,
            minimumReplicaCount: minimumReplicaCount,
            requireTLS: requireTLS
        ).isEmpty
    }

    private static func normalizedEndpointKey(_ endpoint: RelayEndpoint) -> String {
        [
            endpoint.transport.rawValue,
            endpoint.useTLS ? "tls" : "plain",
            endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
            String(endpoint.port)
        ].joined(separator: "://")
    }
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

public struct HiddenRetrievalPIRQueryShare: Codable, Equatable {
    public let replicaIndex: Int
    public let recordCount: Int
    public let selectionBits: Data

    public init(replicaIndex: Int, recordCount: Int, selectionBits: Data) {
        self.replicaIndex = replicaIndex
        self.recordCount = recordCount
        self.selectionBits = selectionBits
    }
}

public struct HiddenRetrievalPIRQueryPlan: Codable, Equatable {
    public let bucketId: String
    public let orderedRecordIds: [String]
    public let targetRecordId: String
    public let targetIndex: Int
    public let shares: [HiddenRetrievalPIRQueryShare]

    public init(
        bucketId: String,
        orderedRecordIds: [String],
        targetRecordId: String,
        targetIndex: Int,
        shares: [HiddenRetrievalPIRQueryShare]
    ) {
        self.bucketId = bucketId
        self.orderedRecordIds = orderedRecordIds
        self.targetRecordId = targetRecordId
        self.targetIndex = targetIndex
        self.shares = shares
    }
}

public struct HiddenRetrievalPIRResponseShare: Codable, Equatable {
    public let replicaIndex: Int
    public let payload: Data

    public init(replicaIndex: Int, payload: Data) {
        self.replicaIndex = replicaIndex
        self.payload = payload
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

    public static func makeReplicatedXORPIRQuery(
        bucketId: String,
        orderedRecordIds: [String],
        targetRecordId: String,
        replicaCount: Int = 2,
        secret: Data,
        paddedRecordCount: Int? = nil,
        maximumRecordCount: Int = 4096
    ) throws -> HiddenRetrievalPIRQueryPlan {
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
        guard replicaCount >= 2 else {
            throw HiddenRetrievalError.invalidReplicaCount
        }
        let normalizedIds = orderedRecordIds.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        guard !normalizedIds.contains(where: { $0.isEmpty }) else {
            throw HiddenRetrievalError.invalidRecordId
        }
        guard !normalizedIds.isEmpty,
              normalizedIds.count <= maximumRecordCount,
              Set(normalizedIds).count == normalizedIds.count else {
            throw HiddenRetrievalError.invalidRecordCount
        }
        guard let targetIndex = normalizedIds.firstIndex(of: canonicalTargetId) else {
            throw HiddenRetrievalError.targetMissing
        }
        let queryRecordCount = paddedRecordCount ?? normalizedIds.count
        guard queryRecordCount >= normalizedIds.count,
              queryRecordCount <= maximumRecordCount else {
            throw HiddenRetrievalError.invalidRecordCount
        }

        var shares: [Data] = []
        var combined = Data(repeating: 0, count: bitsetByteCount(for: queryRecordCount))
        for replicaIndex in 0..<(replicaCount - 1) {
            let share = deterministicMask(
                bucketId: canonicalBucketId,
                targetRecordId: canonicalTargetId,
                recordCount: queryRecordCount,
                replicaIndex: replicaIndex,
                secret: secret
            )
            combined = xorBitsets(combined, share)
            shares.append(share)
        }
        setBit(at: targetIndex, in: &combined)
        shares.append(combined)

        return HiddenRetrievalPIRQueryPlan(
            bucketId: canonicalBucketId,
            orderedRecordIds: normalizedIds,
            targetRecordId: canonicalTargetId,
            targetIndex: targetIndex,
            shares: shares.enumerated().map { index, selectionBits in
                HiddenRetrievalPIRQueryShare(
                    replicaIndex: index,
                    recordCount: queryRecordCount,
                    selectionBits: selectionBits
                )
            }
        )
    }

    public static func evaluateReplicatedXORPIRShare(
        records: [Data],
        share: HiddenRetrievalPIRQueryShare,
        fixedResponseSize: Int? = nil,
        maximumResponseSize: Int = 1_048_576
    ) throws -> HiddenRetrievalPIRResponseShare {
        guard share.replicaIndex >= 0,
              share.recordCount >= records.count,
              share.selectionBits.count == bitsetByteCount(for: share.recordCount) else {
            throw HiddenRetrievalError.malformedPIRShare
        }
        guard !records.isEmpty else {
            throw HiddenRetrievalError.invalidRecordCount
        }
        let recordSize = records[0].count
        guard recordSize > 0,
              records.allSatisfy({ $0.count == recordSize }) else {
            throw HiddenRetrievalError.invalidRecordSize
        }
        let responseSize = fixedResponseSize ?? recordSize
        guard responseSize >= recordSize,
              responseSize > 0,
              responseSize <= maximumResponseSize else {
            throw HiddenRetrievalError.invalidRecordSize
        }
        var accumulator = Data(repeating: 0, count: responseSize)
        for index in records.indices where bit(at: index, in: share.selectionBits) {
            accumulator = xorData(accumulator, paddedRecord(records[index], count: responseSize))
        }
        return HiddenRetrievalPIRResponseShare(
            replicaIndex: share.replicaIndex,
            payload: accumulator
        )
    }

    public static func recoverReplicatedXORPIRTarget(
        from responses: [HiddenRetrievalPIRResponseShare],
        using plan: HiddenRetrievalPIRQueryPlan,
        fixedResponseSize: Int? = nil
    ) throws -> Data {
        guard plan.shares.count >= 2,
              responses.count == plan.shares.count,
              Set(responses.map(\.replicaIndex)) == Set(plan.shares.map(\.replicaIndex)),
              !responses.isEmpty else {
            throw HiddenRetrievalError.malformedPIRResponse
        }
        let payloadSize = responses[0].payload.count
        guard payloadSize > 0,
              responses.allSatisfy({ $0.payload.count == payloadSize }) else {
            throw HiddenRetrievalError.invalidRecordSize
        }
        if let fixedResponseSize {
            guard payloadSize == fixedResponseSize else {
                throw HiddenRetrievalError.invalidRecordSize
            }
        }
        return responses
            .sorted { $0.replicaIndex < $1.replicaIndex }
            .reduce(Data(repeating: 0, count: payloadSize)) { partial, response in
                xorData(partial, response.payload)
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

    private static func deterministicMask(
        bucketId: String,
        targetRecordId: String,
        recordCount: Int,
        replicaIndex: Int,
        secret: Data
    ) -> Data {
        let byteCount = bitsetByteCount(for: recordCount)
        var output = Data()
        var blockCounter: UInt64 = 0
        while output.count < byteCount {
            var data = Data("noctyra-hidden-retrieval-xor-pir-v1".utf8)
            data.append(Data(bucketId.utf8))
            data.append(0)
            data.append(Data(targetRecordId.utf8))
            data.append(0)
            var recordCountBytes = UInt64(recordCount).bigEndian
            data.append(Data(bytes: &recordCountBytes, count: MemoryLayout<UInt64>.size))
            var replicaIndexBytes = UInt64(replicaIndex).bigEndian
            data.append(Data(bytes: &replicaIndexBytes, count: MemoryLayout<UInt64>.size))
            var blockCounterBytes = blockCounter.bigEndian
            data.append(Data(bytes: &blockCounterBytes, count: MemoryLayout<UInt64>.size))
            data.append(secret)
            output.append(Data(SHA256.hash(data: data)))
            blockCounter += 1
        }
        output = output.prefix(byteCount)
        clearUnusedBits(recordCount: recordCount, in: &output)
        return output
    }

    private static func bitsetByteCount(for bitCount: Int) -> Int {
        max(0, (bitCount + 7) / 8)
    }

    private static func bit(at index: Int, in bitset: Data) -> Bool {
        let byteIndex = index / 8
        let bitIndex = index % 8
        guard byteIndex < bitset.count else { return false }
        return (bitset[byteIndex] & (1 << UInt8(bitIndex))) != 0
    }

    private static func setBit(at index: Int, in bitset: inout Data) {
        let byteIndex = index / 8
        let bitIndex = index % 8
        guard byteIndex < bitset.count else { return }
        bitset[byteIndex] ^= (1 << UInt8(bitIndex))
    }

    private static func clearUnusedBits(recordCount: Int, in bitset: inout Data) {
        let usedBitsInLastByte = recordCount % 8
        guard usedBitsInLastByte != 0,
              let last = bitset.indices.last else {
            return
        }
        let mask = UInt8((1 << UInt8(usedBitsInLastByte)) - 1)
        bitset[last] &= mask
    }

    private static func xorBitsets(_ lhs: Data, _ rhs: Data) -> Data {
        xorData(lhs, rhs)
    }

    private static func xorData(_ lhs: Data, _ rhs: Data) -> Data {
        Data(zip(lhs, rhs).map { $0 ^ $1 })
    }

    private static func paddedRecord(_ record: Data, count: Int) -> Data {
        guard record.count < count else {
            return record
        }
        var padded = record
        padded.append(Data(repeating: 0, count: count - record.count))
        return padded
    }
}

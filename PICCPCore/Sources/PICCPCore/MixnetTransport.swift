import CryptoKit
import Foundation

public enum MixnetSchedulerError: Error, Equatable {
    case emptySecret
    case blankPacketId
    case emptyBatch
    case invalidHorizon
}

public enum MixnetRoutePolicyIssue: String, Codable, Equatable, CaseIterable {
    case notAdvertised
    case disabled
    case missingOnionTransport
    case onionTransportDisabled
    case insufficientOnionHops
    case fixedSizePacketsNotRequired
    case insufficientBatchSize
    case coverTrafficDisabled
    case batchIntervalTooShort
    case releaseDelayDisabled
}

public enum MixnetPacketKind: String, Codable, Equatable {
    case real
    case cover
}

public struct MixnetTransportSupport: Codable, Equatable {
    public var enabled: Bool
    public var batchIntervalSeconds: Int
    public var minBatchSize: Int
    public var coverPacketsPerBatch: Int
    public var maxDelaySeconds: Int

    public init(
        enabled: Bool = true,
        batchIntervalSeconds: Int = 30,
        minBatchSize: Int = 8,
        coverPacketsPerBatch: Int = 2,
        maxDelaySeconds: Int = 120
    ) {
        self.enabled = enabled
        self.batchIntervalSeconds = min(max(5, batchIntervalSeconds), 3_600)
        self.minBatchSize = min(max(1, minBatchSize), 256)
        self.coverPacketsPerBatch = min(max(0, coverPacketsPerBatch), 256)
        self.maxDelaySeconds = min(max(0, maxDelaySeconds), 3_600)
    }
}

public struct MixnetScheduledPacket: Codable, Equatable {
    public let packetId: String
    public let kind: MixnetPacketKind
    public let batchId: String
    public let releaseAt: Date
    public let delaySeconds: Int

    public init(
        packetId: String,
        kind: MixnetPacketKind,
        batchId: String,
        releaseAt: Date,
        delaySeconds: Int
    ) {
        self.packetId = packetId
        self.kind = kind
        self.batchId = batchId
        self.releaseAt = releaseAt
        self.delaySeconds = delaySeconds
    }
}

public struct MixnetBatchPlan: Codable, Equatable {
    public let batchId: String
    public let releaseAt: Date
    public let packets: [MixnetScheduledPacket]

    public var realPacketCount: Int {
        packets.filter { $0.kind == .real }.count
    }

    public var coverPacketCount: Int {
        packets.filter { $0.kind == .cover }.count
    }

    public init(batchId: String, releaseAt: Date, packets: [MixnetScheduledPacket]) {
        self.batchId = batchId
        self.releaseAt = releaseAt
        self.packets = packets
    }
}

public struct MixnetCoverCyclePlan: Codable, Equatable {
    public let cycleStart: Date
    public let cycleEnd: Date
    public let batchIntervalSeconds: Int
    public let batches: [MixnetBatchPlan]

    public var coversEveryInterval: Bool {
        guard !batches.isEmpty else {
            return false
        }

        let interval = TimeInterval(max(1, batchIntervalSeconds))
        let expectedCount = max(1, Int(ceil(cycleEnd.timeIntervalSince(cycleStart) / interval)))
        return batches.count == expectedCount && batches.allSatisfy { !$0.packets.isEmpty }
    }

    public init(cycleStart: Date, cycleEnd: Date, batchIntervalSeconds: Int, batches: [MixnetBatchPlan]) {
        self.cycleStart = cycleStart
        self.cycleEnd = cycleEnd
        self.batchIntervalSeconds = max(1, batchIntervalSeconds)
        self.batches = batches
    }
}

public enum MixnetRoutePolicyValidator {
    public static func issues(
        for mixnetSupport: MixnetTransportSupport?,
        onionSupport: OnionTransportSupport?,
        minimumBatchSize: Int = 4,
        minimumCoverPackets: Int = 1,
        minimumOnionHops: Int = 2,
        minimumBatchIntervalSeconds: Int = 10
    ) -> [MixnetRoutePolicyIssue] {
        guard let mixnetSupport else {
            return [.notAdvertised]
        }

        var issues: [MixnetRoutePolicyIssue] = []
        if !mixnetSupport.enabled {
            issues.append(.disabled)
        }
        if mixnetSupport.minBatchSize < max(2, minimumBatchSize) {
            issues.append(.insufficientBatchSize)
        }
        if mixnetSupport.coverPacketsPerBatch < max(1, minimumCoverPackets) {
            issues.append(.coverTrafficDisabled)
        }
        if mixnetSupport.batchIntervalSeconds < max(5, minimumBatchIntervalSeconds) {
            issues.append(.batchIntervalTooShort)
        }
        if mixnetSupport.maxDelaySeconds <= 0 {
            issues.append(.releaseDelayDisabled)
        }

        guard let onionSupport else {
            issues.append(.missingOnionTransport)
            return issues
        }
        if !onionSupport.enabled {
            issues.append(.onionTransportDisabled)
        }
        if onionSupport.maxHops < max(2, minimumOnionHops) {
            issues.append(.insufficientOnionHops)
        }
        if !onionSupport.requiresFixedSizePackets {
            issues.append(.fixedSizePacketsNotRequired)
        }
        return issues
    }

    public static func isUsable(
        mixnetSupport: MixnetTransportSupport?,
        onionSupport: OnionTransportSupport?,
        minimumBatchSize: Int = 4,
        minimumCoverPackets: Int = 1,
        minimumOnionHops: Int = 2,
        minimumBatchIntervalSeconds: Int = 10
    ) -> Bool {
        issues(
            for: mixnetSupport,
            onionSupport: onionSupport,
            minimumBatchSize: minimumBatchSize,
            minimumCoverPackets: minimumCoverPackets,
            minimumOnionHops: minimumOnionHops,
            minimumBatchIntervalSeconds: minimumBatchIntervalSeconds
        ).isEmpty
    }
}

public enum MixnetScheduler {
    public static func makeCoverCyclePlan(
        pendingPacketIdsByBatch: [[String]],
        now: Date,
        policy: MixnetTransportSupport,
        secret: Data,
        horizonSeconds: Int
    ) throws -> MixnetCoverCyclePlan {
        guard horizonSeconds > 0 else {
            throw MixnetSchedulerError.invalidHorizon
        }

        let interval = max(1, policy.batchIntervalSeconds)
        let batchCount = max(1, Int(ceil(Double(horizonSeconds) / Double(interval))))
        let cycleStart = batchBoundary(after: now, intervalSeconds: interval)
        var batches: [MixnetBatchPlan] = []
        batches.reserveCapacity(batchCount)

        for index in 0..<batchCount {
            let batchBase = cycleStart.addingTimeInterval(TimeInterval(index * interval))
            let realPacketIds = index < pendingPacketIdsByBatch.count ? pendingPacketIdsByBatch[index] : []
            let batch = try makeBatchPlan(
                pendingPacketIds: realPacketIds,
                now: batchBase,
                policy: policy,
                secret: secret
            )
            batches.append(batch)
        }

        let cycleEnd = cycleStart.addingTimeInterval(TimeInterval(batchCount * interval))
        return MixnetCoverCyclePlan(
            cycleStart: cycleStart,
            cycleEnd: cycleEnd,
            batchIntervalSeconds: interval,
            batches: batches
        )
    }

    public static func makeCoverCyclePlan(
        pendingPacketIds: [String],
        now: Date,
        policy: MixnetTransportSupport,
        secret: Data,
        horizonSeconds: Int
    ) throws -> MixnetCoverCyclePlan {
        try makeCoverCyclePlan(
            pendingPacketIdsByBatch: [pendingPacketIds],
            now: now,
            policy: policy,
            secret: secret,
            horizonSeconds: horizonSeconds
        )
    }

    public static func makeBatchPlan(
        pendingPacketIds: [String],
        now: Date,
        policy: MixnetTransportSupport,
        secret: Data
    ) throws -> MixnetBatchPlan {
        guard !secret.isEmpty else {
            throw MixnetSchedulerError.emptySecret
        }
        let realIds = try canonicalPacketIds(pendingPacketIds)
        let batchBase = batchBoundary(after: now, intervalSeconds: policy.batchIntervalSeconds)
        let batchId = makeBatchId(batchBase: batchBase, policy: policy, secret: secret)
        let coverCount = max(policy.coverPacketsPerBatch, policy.minBatchSize - realIds.count)
        let coverIds = (0..<coverCount).map { makeCoverPacketId(index: $0, batchId: batchId, secret: secret) }
        let delay = boundedDelaySeconds(batchId: batchId, secret: secret, maxDelaySeconds: policy.maxDelaySeconds)
        let releaseAt = batchBase.addingTimeInterval(TimeInterval(delay))

        var packets = realIds.map { id in
            MixnetScheduledPacket(
                packetId: id,
                kind: .real,
                batchId: batchId,
                releaseAt: releaseAt,
                delaySeconds: delay
            )
        }
        packets += coverIds.map { id in
            MixnetScheduledPacket(
                packetId: id,
                kind: .cover,
                batchId: batchId,
                releaseAt: releaseAt,
                delaySeconds: delay
            )
        }
        guard !packets.isEmpty else {
            throw MixnetSchedulerError.emptyBatch
        }
        packets.sort { lhs, rhs in
            let lhsRank = rank(packetId: lhs.packetId, batchId: batchId, secret: secret)
            let rhsRank = rank(packetId: rhs.packetId, batchId: batchId, secret: secret)
            if lhsRank == rhsRank {
                return lhs.packetId < rhs.packetId
            }
            return lhsRank.lexicographicallyPrecedes(rhsRank)
        }
        return MixnetBatchPlan(batchId: batchId, releaseAt: releaseAt, packets: packets)
    }

    private static func canonicalPacketIds(_ packetIds: [String]) throws -> [String] {
        var seen = Set<String>()
        var result: [String] = []
        for packetId in packetIds {
            let trimmed = packetId.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                throw MixnetSchedulerError.blankPacketId
            }
            if seen.insert(trimmed).inserted {
                result.append(trimmed)
            }
        }
        return result.sorted()
    }

    private static func batchBoundary(after date: Date, intervalSeconds: Int) -> Date {
        let interval = max(1, intervalSeconds)
        let timestamp = Int(date.timeIntervalSince1970)
        let remainder = timestamp % interval
        let boundary = remainder == 0 ? timestamp : timestamp + (interval - remainder)
        return Date(timeIntervalSince1970: TimeInterval(boundary))
    }

    private static func makeBatchId(
        batchBase: Date,
        policy: MixnetTransportSupport,
        secret: Data
    ) -> String {
        let material = Data("batch:\(Int(batchBase.timeIntervalSince1970)):\(policy.batchIntervalSeconds):\(policy.minBatchSize):\(policy.coverPacketsPerBatch)".utf8)
        return Data(SHA256.hash(data: secret + material)).prefix(12).map { String(format: "%02x", $0) }.joined()
    }

    private static func makeCoverPacketId(index: Int, batchId: String, secret: Data) -> String {
        let material = Data("cover:\(batchId):\(index)".utf8)
        let digest = Data(SHA256.hash(data: secret + material)).prefix(12).map { String(format: "%02x", $0) }.joined()
        return "cover-\(digest)"
    }

    private static func boundedDelaySeconds(batchId: String, secret: Data, maxDelaySeconds: Int) -> Int {
        guard maxDelaySeconds > 0 else {
            return 0
        }
        let material = Data("delay:\(batchId)".utf8)
        let digest = Data(SHA256.hash(data: secret + material))
        let value = digest.prefix(8).reduce(UInt64(0)) { partial, byte in
            (partial << 8) | UInt64(byte)
        }
        return Int(value % UInt64(maxDelaySeconds + 1))
    }

    private static func rank(packetId: String, batchId: String, secret: Data) -> Data {
        Data(SHA256.hash(data: secret + Data("rank:\(batchId):\(packetId)".utf8)))
    }
}

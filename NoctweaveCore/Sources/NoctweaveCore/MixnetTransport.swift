import CryptoKit
import Foundation

public enum MixnetSchedulerError: Error, Equatable {
    case emptySecret
    case blankPacketId
    case emptyBatch
    case invalidHorizon
}

public enum MixnetPacketPaddingError: Error, Equatable {
    case blankPacketId
    case invalidPayload
    case invalidFixedSize
    case payloadTooLarge
    case malformedPacket
}

public enum MixnetInterRelayCoverError: Error, Equatable {
    case emptySecret
    case invalidHorizon
    case invalidRelaySet
    case invalidCoverPacketCount
    case invalidEndpoint
    case insufficientDiversity
}

public enum MixnetRouteSelectionError: Error, Equatable {
    case emptySecret
    case invalidRouteLength
    case insufficientCandidates
    case blankHopId
    case blankOperatorId
    case invalidEndpoint
    case invalidOnionHop
    case insufficientDiversity
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

public struct MixnetFixedSizePacket: Codable, Equatable {
    public let packetId: String
    public let paddedPayload: Data
    public let originalPayloadSize: Int
    public let fixedPayloadSize: Int

    public init(packetId: String, paddedPayload: Data, originalPayloadSize: Int, fixedPayloadSize: Int) {
        self.packetId = packetId
        self.paddedPayload = paddedPayload
        self.originalPayloadSize = originalPayloadSize
        self.fixedPayloadSize = fixedPayloadSize
    }
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

public enum MixnetPacketPadder {
    public static func pad(
        packetId: String,
        payload: Data,
        fixedPayloadSize: Int
    ) throws -> MixnetFixedSizePacket {
        let trimmedPacketId = packetId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedPacketId.isEmpty else {
            throw MixnetPacketPaddingError.blankPacketId
        }
        guard !payload.isEmpty else {
            throw MixnetPacketPaddingError.invalidPayload
        }
        guard fixedPayloadSize > 0 else {
            throw MixnetPacketPaddingError.invalidFixedSize
        }
        guard payload.count <= fixedPayloadSize else {
            throw MixnetPacketPaddingError.payloadTooLarge
        }

        var paddedPayload = payload
        let paddingCount = fixedPayloadSize - payload.count
        if paddingCount > 0 {
            paddedPayload.append(contentsOf: (0..<paddingCount).map { _ in UInt8.random(in: UInt8.min...UInt8.max) })
        }

        return MixnetFixedSizePacket(
            packetId: trimmedPacketId,
            paddedPayload: paddedPayload,
            originalPayloadSize: payload.count,
            fixedPayloadSize: fixedPayloadSize
        )
    }

    public static func open(_ packet: MixnetFixedSizePacket) throws -> Data {
        let trimmedPacketId = packet.packetId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedPacketId.isEmpty else {
            throw MixnetPacketPaddingError.blankPacketId
        }
        guard packet.fixedPayloadSize > 0 else {
            throw MixnetPacketPaddingError.invalidFixedSize
        }
        guard packet.originalPayloadSize > 0,
              packet.originalPayloadSize <= packet.fixedPayloadSize,
              packet.paddedPayload.count == packet.fixedPayloadSize else {
            throw MixnetPacketPaddingError.malformedPacket
        }

        return Data(packet.paddedPayload.prefix(packet.originalPayloadSize))
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

public struct MixnetRouteCandidate: Codable, Equatable {
    public let hopId: String
    public let operatorId: String
    public let endpoint: RelayEndpoint
    public let onionHop: OnionHopDescriptor

    public init(
        hopId: String,
        operatorId: String,
        endpoint: RelayEndpoint,
        onionHop: OnionHopDescriptor
    ) {
        self.hopId = hopId.trimmingCharacters(in: .whitespacesAndNewlines)
        self.operatorId = operatorId.trimmingCharacters(in: .whitespacesAndNewlines)
        self.endpoint = endpoint
        self.onionHop = onionHop
    }
}

public struct MixnetRoutePlan: Codable, Equatable {
    public let routeId: String
    public let selectedCandidates: [MixnetRouteCandidate]

    public var onionHops: [OnionHopDescriptor] {
        selectedCandidates.map(\.onionHop)
    }

    public init(routeId: String, selectedCandidates: [MixnetRouteCandidate]) {
        self.routeId = routeId
        self.selectedCandidates = selectedCandidates
    }
}

public struct MixnetRelayPeer: Codable, Equatable {
    public let relayId: String
    public let operatorId: String
    public let endpoint: RelayEndpoint

    public init(relayId: String, operatorId: String, endpoint: RelayEndpoint) {
        self.relayId = relayId.trimmingCharacters(in: .whitespacesAndNewlines)
        self.operatorId = operatorId.trimmingCharacters(in: .whitespacesAndNewlines)
        self.endpoint = endpoint
    }
}

public struct MixnetInterRelayCoverPacket: Codable, Equatable {
    public let packetId: String
    public let sourceRelayId: String
    public let destinationRelayId: String
    public let batchId: String
    public let releaseAt: Date
    public let delaySeconds: Int

    public init(
        packetId: String,
        sourceRelayId: String,
        destinationRelayId: String,
        batchId: String,
        releaseAt: Date,
        delaySeconds: Int
    ) {
        self.packetId = packetId
        self.sourceRelayId = sourceRelayId
        self.destinationRelayId = destinationRelayId
        self.batchId = batchId
        self.releaseAt = releaseAt
        self.delaySeconds = delaySeconds
    }
}

public struct MixnetInterRelayCoverBatchPlan: Codable, Equatable {
    public let batchId: String
    public let releaseAt: Date
    public let packets: [MixnetInterRelayCoverPacket]

    public init(batchId: String, releaseAt: Date, packets: [MixnetInterRelayCoverPacket]) {
        self.batchId = batchId
        self.releaseAt = releaseAt
        self.packets = packets
    }
}

public struct MixnetInterRelayCoverPlan: Codable, Equatable {
    public let cycleStart: Date
    public let cycleEnd: Date
    public let batchIntervalSeconds: Int
    public let relayIds: [String]
    public let coverPacketsPerLink: Int
    public let batches: [MixnetInterRelayCoverBatchPlan]

    public var coversEveryRelayLinkEachInterval: Bool {
        guard relayIds.count >= 2, coverPacketsPerLink > 0, !batches.isEmpty else {
            return false
        }
        let interval = TimeInterval(max(1, batchIntervalSeconds))
        let expectedBatchCount = max(1, Int(ceil(cycleEnd.timeIntervalSince(cycleStart) / interval)))
        let expectedLinkCount = relayIds.count * (relayIds.count - 1)
        return batches.count == expectedBatchCount && batches.allSatisfy { batch in
            batch.packets.count == expectedLinkCount * coverPacketsPerLink &&
            Set(batch.packets.map { "\($0.sourceRelayId)->\($0.destinationRelayId)" }).count == expectedLinkCount
        }
    }

    public init(
        cycleStart: Date,
        cycleEnd: Date,
        batchIntervalSeconds: Int,
        relayIds: [String],
        coverPacketsPerLink: Int,
        batches: [MixnetInterRelayCoverBatchPlan]
    ) {
        self.cycleStart = cycleStart
        self.cycleEnd = cycleEnd
        self.batchIntervalSeconds = max(1, batchIntervalSeconds)
        self.relayIds = relayIds
        self.coverPacketsPerLink = max(0, coverPacketsPerLink)
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

public enum MixnetRouteSelector {
    public static func makeRoutePlan(
        candidates: [MixnetRouteCandidate],
        secret: Data,
        routeContext: String,
        hopCount: Int,
        requireTLS: Bool = true
    ) throws -> MixnetRoutePlan {
        guard !secret.isEmpty else {
            throw MixnetRouteSelectionError.emptySecret
        }
        guard hopCount >= 2 else {
            throw MixnetRouteSelectionError.invalidRouteLength
        }

        let normalized = try normalizedCandidates(candidates, requireTLS: requireTLS)
        guard normalized.count >= hopCount else {
            throw MixnetRouteSelectionError.insufficientCandidates
        }

        var selected: [MixnetRouteCandidate] = []
        var usedOperators = Set<String>()
        var usedHosts = Set<String>()

        for candidate in rankedCandidates(normalized, secret: secret, routeContext: routeContext) {
            let operatorKey = candidate.operatorId.lowercased()
            let hostKey = candidate.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !usedOperators.contains(operatorKey), !usedHosts.contains(hostKey) else {
                continue
            }
            selected.append(candidate)
            usedOperators.insert(operatorKey)
            usedHosts.insert(hostKey)
            if selected.count == hopCount {
                break
            }
        }

        guard selected.count == hopCount else {
            throw MixnetRouteSelectionError.insufficientDiversity
        }

        return MixnetRoutePlan(
            routeId: makeRouteId(selected: selected, secret: secret, routeContext: routeContext),
            selectedCandidates: selected
        )
    }

    private static func normalizedCandidates(
        _ candidates: [MixnetRouteCandidate],
        requireTLS: Bool
    ) throws -> [MixnetRouteCandidate] {
        var seenHopIds = Set<String>()
        var result: [MixnetRouteCandidate] = []
        for candidate in candidates {
            let hopId = candidate.hopId.trimmingCharacters(in: .whitespacesAndNewlines)
            let onionHopId = candidate.onionHop.hopId.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !hopId.isEmpty, !onionHopId.isEmpty else {
                throw MixnetRouteSelectionError.blankHopId
            }
            guard hopId.caseInsensitiveCompare(onionHopId) == .orderedSame,
                  !candidate.onionHop.publicKeyData.isEmpty,
                  !candidate.onionHop.routingInstruction.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw MixnetRouteSelectionError.invalidOnionHop
            }
            guard !candidate.operatorId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw MixnetRouteSelectionError.blankOperatorId
            }
            guard !candidate.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  !requireTLS || candidate.endpoint.useTLS else {
                throw MixnetRouteSelectionError.invalidEndpoint
            }
            guard seenHopIds.insert(hopId.lowercased()).inserted else {
                continue
            }
            result.append(candidate)
        }
        return result
    }

    private static func rankedCandidates(
        _ candidates: [MixnetRouteCandidate],
        secret: Data,
        routeContext: String
    ) -> [MixnetRouteCandidate] {
        candidates.sorted { lhs, rhs in
            let lhsRank = rank(candidate: lhs, secret: secret, routeContext: routeContext)
            let rhsRank = rank(candidate: rhs, secret: secret, routeContext: routeContext)
            if lhsRank == rhsRank {
                return lhs.hopId < rhs.hopId
            }
            return lhsRank.lexicographicallyPrecedes(rhsRank)
        }
    }

    private static func makeRouteId(
        selected: [MixnetRouteCandidate],
        secret: Data,
        routeContext: String
    ) -> String {
        let material = selected
            .map { "\($0.hopId):\($0.operatorId):\($0.endpoint.host):\($0.endpoint.port)" }
            .joined(separator: "|")
        return Data(SHA256.hash(data: secret + Data("route:\(routeContext):\(material)".utf8)))
            .prefix(12)
            .map { String(format: "%02x", $0) }
            .joined()
    }

    private static func rank(candidate: MixnetRouteCandidate, secret: Data, routeContext: String) -> Data {
        Data(SHA256.hash(data: secret + Data("route-rank:\(routeContext):\(candidate.hopId):\(candidate.operatorId)".utf8)))
    }
}

public enum MixnetInterRelayCoverCoordinator {
    public static func makePlan(
        relays: [MixnetRelayPeer],
        now: Date,
        policy: MixnetTransportSupport,
        secret: Data,
        horizonSeconds: Int,
        coverPacketsPerLink: Int = 1,
        requireTLS: Bool = true
    ) throws -> MixnetInterRelayCoverPlan {
        guard !secret.isEmpty else {
            throw MixnetInterRelayCoverError.emptySecret
        }
        guard horizonSeconds > 0 else {
            throw MixnetInterRelayCoverError.invalidHorizon
        }
        guard coverPacketsPerLink > 0, coverPacketsPerLink <= 32 else {
            throw MixnetInterRelayCoverError.invalidCoverPacketCount
        }

        let peers = try normalizedRelays(relays, requireTLS: requireTLS)
        let interval = max(1, policy.batchIntervalSeconds)
        let batchCount = max(1, Int(ceil(Double(horizonSeconds) / Double(interval))))
        let cycleStart = batchBoundary(after: now, intervalSeconds: interval)
        var batches: [MixnetInterRelayCoverBatchPlan] = []
        batches.reserveCapacity(batchCount)

        for batchIndex in 0..<batchCount {
            let batchBase = cycleStart.addingTimeInterval(TimeInterval(batchIndex * interval))
            let batchId = makeBatchId(batchBase: batchBase, relays: peers, policy: policy, secret: secret)
            let delay = boundedDelaySeconds(batchId: batchId, secret: secret, maxDelaySeconds: policy.maxDelaySeconds)
            let releaseAt = batchBase.addingTimeInterval(TimeInterval(delay))
            var packets: [MixnetInterRelayCoverPacket] = []
            for source in peers {
                for destination in peers where destination.relayId != source.relayId {
                    for coverIndex in 0..<coverPacketsPerLink {
                        packets.append(
                            MixnetInterRelayCoverPacket(
                                packetId: makeCoverPacketId(
                                    batchId: batchId,
                                    sourceRelayId: source.relayId,
                                    destinationRelayId: destination.relayId,
                                    coverIndex: coverIndex,
                                    secret: secret
                                ),
                                sourceRelayId: source.relayId,
                                destinationRelayId: destination.relayId,
                                batchId: batchId,
                                releaseAt: releaseAt,
                                delaySeconds: delay
                            )
                        )
                    }
                }
            }
            packets.sort { lhs, rhs in
                let lhsRank = rank(packet: lhs, secret: secret)
                let rhsRank = rank(packet: rhs, secret: secret)
                if lhsRank == rhsRank {
                    return lhs.packetId < rhs.packetId
                }
                return lhsRank.lexicographicallyPrecedes(rhsRank)
            }
            batches.append(MixnetInterRelayCoverBatchPlan(batchId: batchId, releaseAt: releaseAt, packets: packets))
        }

        return MixnetInterRelayCoverPlan(
            cycleStart: cycleStart,
            cycleEnd: cycleStart.addingTimeInterval(TimeInterval(batchCount * interval)),
            batchIntervalSeconds: interval,
            relayIds: peers.map(\.relayId),
            coverPacketsPerLink: coverPacketsPerLink,
            batches: batches
        )
    }

    private static func normalizedRelays(
        _ relays: [MixnetRelayPeer],
        requireTLS: Bool
    ) throws -> [MixnetRelayPeer] {
        var seenRelayIds = Set<String>()
        var peers: [MixnetRelayPeer] = []
        for relay in relays {
            let relayId = relay.relayId.trimmingCharacters(in: .whitespacesAndNewlines)
            let operatorId = relay.operatorId.trimmingCharacters(in: .whitespacesAndNewlines)
            let host = relay.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !relayId.isEmpty, !operatorId.isEmpty else {
                throw MixnetInterRelayCoverError.invalidRelaySet
            }
            guard !host.isEmpty, !requireTLS || relay.endpoint.useTLS else {
                throw MixnetInterRelayCoverError.invalidEndpoint
            }
            guard seenRelayIds.insert(relayId.lowercased()).inserted else {
                throw MixnetInterRelayCoverError.invalidRelaySet
            }
            peers.append(MixnetRelayPeer(relayId: relayId, operatorId: operatorId, endpoint: relay.endpoint))
        }
        guard peers.count >= 2 else {
            throw MixnetInterRelayCoverError.invalidRelaySet
        }
        let operators = Set(peers.map { $0.operatorId.lowercased() })
        let hosts = Set(peers.map { $0.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() })
        guard operators.count == peers.count, hosts.count == peers.count else {
            throw MixnetInterRelayCoverError.insufficientDiversity
        }
        return peers.sorted { $0.relayId < $1.relayId }
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
        relays: [MixnetRelayPeer],
        policy: MixnetTransportSupport,
        secret: Data
    ) -> String {
        let relayMaterial = relays
            .map { "\($0.relayId):\($0.operatorId):\($0.endpoint.host):\($0.endpoint.port)" }
            .joined(separator: "|")
        let material = Data("inter-relay-batch:\(Int(batchBase.timeIntervalSince1970)):\(policy.batchIntervalSeconds):\(relayMaterial)".utf8)
        return hexDigest(secret + material, prefix: 12)
    }

    private static func makeCoverPacketId(
        batchId: String,
        sourceRelayId: String,
        destinationRelayId: String,
        coverIndex: Int,
        secret: Data
    ) -> String {
        let material = Data("inter-relay-cover:\(batchId):\(sourceRelayId):\(destinationRelayId):\(coverIndex)".utf8)
        return "relay-cover-\(hexDigest(secret + material, prefix: 12))"
    }

    private static func boundedDelaySeconds(batchId: String, secret: Data, maxDelaySeconds: Int) -> Int {
        guard maxDelaySeconds > 0 else {
            return 0
        }
        let digest = Data(SHA256.hash(data: secret + Data("inter-relay-delay:\(batchId)".utf8)))
        let value = digest.prefix(8).reduce(UInt64(0)) { partial, byte in
            (partial << 8) | UInt64(byte)
        }
        return Int(value % UInt64(maxDelaySeconds + 1))
    }

    private static func rank(packet: MixnetInterRelayCoverPacket, secret: Data) -> Data {
        Data(SHA256.hash(data: secret + Data("inter-relay-rank:\(packet.batchId):\(packet.packetId)".utf8)))
    }

    private static func hexDigest(_ data: Data, prefix: Int) -> String {
        Data(SHA256.hash(data: data)).prefix(prefix).map { String(format: "%02x", $0) }.joined()
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

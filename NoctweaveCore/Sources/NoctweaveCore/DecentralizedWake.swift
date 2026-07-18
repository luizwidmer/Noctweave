import CryptoKit
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public enum DecentralizedWakeMode: String, Codable, CaseIterable {
    case pullOnly
    case longPoll
}

/// Relay-advertised bounds for optional opaque-route synchronization. This is
/// transport policy only; it grants no route, relationship, identity, account,
/// persona, or device authority.
public struct DecentralizedWakeSupport: Codable, Equatable {
    public static let absoluteMaximumPollIntervalSeconds = 86_400

    public var mode: DecentralizedWakeMode
    public var minPollIntervalSeconds: Int
    public var maxPollIntervalSeconds: Int
    public var jitterPermille: Int
    public var longPollTimeoutSeconds: Int?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case mode
        case minPollIntervalSeconds
        case maxPollIntervalSeconds
        case jitterPermille
        case longPollTimeoutSeconds
    }

    public init(
        mode: DecentralizedWakeMode = .pullOnly,
        minPollIntervalSeconds: Int = 60,
        maxPollIntervalSeconds: Int = 300,
        jitterPermille: Int = 250,
        longPollTimeoutSeconds: Int? = nil
    ) {
        let normalizedMin = min(
            Self.absoluteMaximumPollIntervalSeconds,
            max(5, minPollIntervalSeconds)
        )
        let normalizedMax = min(
            Self.absoluteMaximumPollIntervalSeconds,
            max(normalizedMin, maxPollIntervalSeconds)
        )
        self.mode = mode
        self.minPollIntervalSeconds = normalizedMin
        self.maxPollIntervalSeconds = normalizedMax
        self.jitterPermille = min(max(0, jitterPermille), 1_000)
        if mode == .longPoll {
            self.longPollTimeoutSeconds = longPollTimeoutSeconds.map {
                min(max(5, $0), normalizedMax)
            } ?? normalizedMin
        } else {
            self.longPollTimeoutSeconds = nil
        }
    }

    public init(from decoder: Decoder) throws {
        try decentralizedWakeRequireExactObject(
            decoder,
            keys: CodingKeys.allCases.map(\.rawValue)
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let mode = try container.decode(DecentralizedWakeMode.self, forKey: .mode)
        let minimum = try container.decode(Int.self, forKey: .minPollIntervalSeconds)
        let maximum = try container.decode(Int.self, forKey: .maxPollIntervalSeconds)
        let jitter = try container.decode(Int.self, forKey: .jitterPermille)
        let timeout = try container.decodeIfPresent(Int.self, forKey: .longPollTimeoutSeconds)
        self.init(
            mode: mode,
            minPollIntervalSeconds: minimum,
            maxPollIntervalSeconds: maximum,
            jitterPermille: jitter,
            longPollTimeoutSeconds: timeout
        )
        guard minPollIntervalSeconds == minimum,
              maxPollIntervalSeconds == maximum,
              jitterPermille == jitter,
              longPollTimeoutSeconds == timeout else {
            throw decentralizedWakeDecodingError(
                decoder,
                "Wake support must already use normalized current values"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(mode, forKey: .mode)
        try container.encode(minPollIntervalSeconds, forKey: .minPollIntervalSeconds)
        try container.encode(maxPollIntervalSeconds, forKey: .maxPollIntervalSeconds)
        try container.encode(jitterPermille, forKey: .jitterPermille)
        try container.encode(longPollTimeoutSeconds, forKey: .longPollTimeoutSeconds)
    }
}

public struct DecentralizedWakePlan: Codable, Equatable {
    public let nextPollDelaySeconds: Int
    public let longPollTimeoutSeconds: Int?
    public let failureBackoffStep: Int

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case nextPollDelaySeconds
        case longPollTimeoutSeconds
        case failureBackoffStep
    }

    public init(
        nextPollDelaySeconds: Int,
        longPollTimeoutSeconds: Int?,
        failureBackoffStep: Int
    ) {
        self.nextPollDelaySeconds = nextPollDelaySeconds
        self.longPollTimeoutSeconds = longPollTimeoutSeconds
        self.failureBackoffStep = failureBackoffStep
    }

    public init(from decoder: Decoder) throws {
        try decentralizedWakeRequireExactObject(
            decoder,
            keys: CodingKeys.allCases.map(\.rawValue)
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            nextPollDelaySeconds: try container.decode(
                Int.self,
                forKey: .nextPollDelaySeconds
            ),
            longPollTimeoutSeconds: try container.decodeIfPresent(
                Int.self,
                forKey: .longPollTimeoutSeconds
            ),
            failureBackoffStep: try container.decode(Int.self, forKey: .failureBackoffStep)
        )
        guard isStructurallyValid else {
            throw decentralizedWakeDecodingError(decoder, "Wake plan is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Wake plan is invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(nextPollDelaySeconds, forKey: .nextPollDelaySeconds)
        try container.encode(longPollTimeoutSeconds, forKey: .longPollTimeoutSeconds)
        try container.encode(failureBackoffStep, forKey: .failureBackoffStep)
    }

    public var isStructurallyValid: Bool {
        nextPollDelaySeconds >= 5
            && nextPollDelaySeconds <= DecentralizedWakeSupport.absoluteMaximumPollIntervalSeconds
            && (0...6).contains(failureBackoffStep)
            && longPollTimeoutSeconds.map {
                $0 >= 5 && $0 <= nextPollDelaySeconds
            } ?? true
    }
}

public struct DecentralizedWakeRoutePlan: Equatable {
    public let routeID: OpaqueReceiveRouteIDV2
    public let relayIdentifier: String
    public let plan: DecentralizedWakePlan

    public init(
        routeID: OpaqueReceiveRouteIDV2,
        relayIdentifier: String,
        plan: DecentralizedWakePlan
    ) {
        self.routeID = routeID
        self.relayIdentifier = relayIdentifier
        self.plan = plan
    }
}

public struct DecentralizedWakeCyclePlan: Equatable {
    public let routePlans: [DecentralizedWakeRoutePlan]
    public let nextPollDelaySeconds: Int
    public let longPollTimeoutSeconds: Int?

    public init(
        routePlans: [DecentralizedWakeRoutePlan],
        nextPollDelaySeconds: Int,
        longPollTimeoutSeconds: Int?
    ) {
        self.routePlans = routePlans
        self.nextPollDelaySeconds = nextPollDelaySeconds
        self.longPollTimeoutSeconds = longPollTimeoutSeconds
    }
}

/// Local scheduling input for one independently authorized opaque receive
/// route. `routeJitterSeed` must be freshly random per route and stays local.
public struct DecentralizedWakeRoute: Equatable {
    public let support: DecentralizedWakeSupport?
    public let routeID: OpaqueReceiveRouteIDV2
    public let routeJitterSeed: Data
    public let relayIdentifier: String
    public let failureCount: Int

    public init(
        support: DecentralizedWakeSupport?,
        routeID: OpaqueReceiveRouteIDV2,
        routeJitterSeed: Data,
        relayIdentifier: String,
        failureCount: Int = 0
    ) {
        self.support = support
        self.routeID = routeID
        self.routeJitterSeed = routeJitterSeed
        self.relayIdentifier = relayIdentifier
        self.failureCount = failureCount
    }

    public var isStructurallyValid: Bool {
        let relay = relayIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        return routeID.isStructurallyValid
            && routeJitterSeed.count == 32
            && routeJitterSeed.contains(where: { $0 != 0 })
            && relay == relayIdentifier
            && !relay.isEmpty
            && relay.utf8.count <= 512
    }
}

public enum DecentralizedPrefetchError: Error, Equatable {
    case invalidRelayIdentifier
    case invalidRouteBatch
    case invalidEnvelope
    case emptyBatch
    case invalidBatch
    case invalidProtectionKey
    case invalidStoredBatch
    case batchTooLarge
}

/// One relay-visible opaque packet staged without its route payload key. The
/// record cannot reveal whether the packet contains direct, group, control, or
/// cover traffic.
public struct DecentralizedPrefetchRecord: Codable, Equatable, Identifiable {
    public static let version = 2

    public let version: Int
    public let envelopeID: OpaqueRoutePacketIDV2
    public let routeID: OpaqueReceiveRouteIDV2
    public let routeRevision: UInt64
    public let stagedAt: Date
    public let sealedPacketEnvelope: Data

    public var id: OpaqueRoutePacketIDV2 { envelopeID }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case envelopeID
        case routeID
        case routeRevision
        case stagedAt
        case sealedPacketEnvelope
    }

    public init(
        envelopeID: OpaqueRoutePacketIDV2,
        routeID: OpaqueReceiveRouteIDV2,
        routeRevision: UInt64,
        stagedAt: Date,
        sealedPacketEnvelope: Data
    ) throws {
        self.version = Self.version
        self.envelopeID = envelopeID
        self.routeID = routeID
        self.routeRevision = routeRevision
        self.stagedAt = stagedAt
        self.sealedPacketEnvelope = sealedPacketEnvelope
        guard isStructurallyValid else { throw DecentralizedPrefetchError.invalidEnvelope }
    }

    public init(from decoder: Decoder) throws {
        try decentralizedWakeRequireExactObject(
            decoder,
            keys: CodingKeys.allCases.map(\.rawValue)
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        envelopeID = try container.decode(OpaqueRoutePacketIDV2.self, forKey: .envelopeID)
        routeID = try container.decode(OpaqueReceiveRouteIDV2.self, forKey: .routeID)
        routeRevision = try container.decode(UInt64.self, forKey: .routeRevision)
        stagedAt = try container.decode(Date.self, forKey: .stagedAt)
        sealedPacketEnvelope = try container.decode(Data.self, forKey: .sealedPacketEnvelope)
        guard isStructurallyValid else {
            throw decentralizedWakeDecodingError(decoder, "Prefetch record is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Prefetch record is invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(envelopeID, forKey: .envelopeID)
        try container.encode(routeID, forKey: .routeID)
        try container.encode(routeRevision, forKey: .routeRevision)
        try container.encode(stagedAt, forKey: .stagedAt)
        try container.encode(sealedPacketEnvelope, forKey: .sealedPacketEnvelope)
    }

    public var isStructurallyValid: Bool {
        guard version == Self.version,
              envelopeID.isStructurallyValid,
              routeID.isStructurallyValid,
              stagedAt.timeIntervalSince1970.isFinite,
              !sealedPacketEnvelope.isEmpty,
              sealedPacketEnvelope.count
                <= DecentralizedPrefetchStager.maximumSealedEnvelopeBytes,
              let received = try? NoctweaveCoder.decode(
                  OpaqueRouteReceivedPacketV2.self,
                  from: sealedPacketEnvelope
              ),
              let canonical = try? NoctweaveCoder.encode(received, sortedKeys: true) else {
            return false
        }
        return canonical == sealedPacketEnvelope
            && received.routeRevision == routeRevision
            && received.packet.routeID == routeID
            && received.packet.packetID == envelopeID
            && received.isStructurallyValid
    }
}

/// One durable opaque-route sync page. The relay cursor is intentionally not
/// committed until every staged packet has been verified, reassembled,
/// decrypted, and durably applied by the foreground client.
public struct DecentralizedPrefetchBatch: Codable, Equatable {
    public static let version = 2

    public let version: Int
    public let routeID: OpaqueReceiveRouteIDV2
    public let relayIdentifier: String
    public let records: [DecentralizedPrefetchRecord]
    public let fetchedAfter: OpaqueRouteCursorV2?
    public let startsAfterSequence: UInt64
    public let startsAfterRecordDigest: Data
    public let nextSequence: UInt64
    public let nextRecordDigest: Data
    public let highWatermarkSequence: UInt64
    public let retentionFloorSequence: UInt64
    public let deferredCommitCursor: OpaqueRouteCursorV2
    public let highWatermark: OpaqueRouteCursorV2
    public let retentionFloor: OpaqueRouteCursorV2
    public let hasMore: Bool
    public let stagedAt: Date

    public var envelopeIDs: [OpaqueRoutePacketIDV2] { records.map(\.envelopeID) }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case routeID
        case relayIdentifier
        case records
        case fetchedAfter
        case startsAfterSequence
        case startsAfterRecordDigest
        case nextSequence
        case nextRecordDigest
        case highWatermarkSequence
        case retentionFloorSequence
        case deferredCommitCursor
        case highWatermark
        case retentionFloor
        case hasMore
        case stagedAt
    }

    public init(
        routeID: OpaqueReceiveRouteIDV2,
        relayIdentifier: String,
        records: [DecentralizedPrefetchRecord],
        fetchedAfter: OpaqueRouteCursorV2?,
        startsAfterSequence: UInt64,
        startsAfterRecordDigest: Data,
        nextSequence: UInt64,
        nextRecordDigest: Data,
        highWatermarkSequence: UInt64,
        retentionFloorSequence: UInt64,
        deferredCommitCursor: OpaqueRouteCursorV2,
        highWatermark: OpaqueRouteCursorV2,
        retentionFloor: OpaqueRouteCursorV2,
        hasMore: Bool,
        stagedAt: Date
    ) throws {
        self.version = Self.version
        self.routeID = routeID
        self.relayIdentifier = relayIdentifier
        self.records = records
        self.fetchedAfter = fetchedAfter
        self.startsAfterSequence = startsAfterSequence
        self.startsAfterRecordDigest = startsAfterRecordDigest
        self.nextSequence = nextSequence
        self.nextRecordDigest = nextRecordDigest
        self.highWatermarkSequence = highWatermarkSequence
        self.retentionFloorSequence = retentionFloorSequence
        self.deferredCommitCursor = deferredCommitCursor
        self.highWatermark = highWatermark
        self.retentionFloor = retentionFloor
        self.hasMore = hasMore
        self.stagedAt = stagedAt
        guard isStructurallyValid else { throw DecentralizedPrefetchError.invalidBatch }
    }

    public init(from decoder: Decoder) throws {
        try decentralizedWakeRequireExactObject(
            decoder,
            keys: CodingKeys.allCases.map(\.rawValue)
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        routeID = try container.decode(OpaqueReceiveRouteIDV2.self, forKey: .routeID)
        relayIdentifier = try container.decode(String.self, forKey: .relayIdentifier)
        records = try container.decode([DecentralizedPrefetchRecord].self, forKey: .records)
        fetchedAfter = try container.decodeIfPresent(OpaqueRouteCursorV2.self, forKey: .fetchedAfter)
        startsAfterSequence = try container.decode(UInt64.self, forKey: .startsAfterSequence)
        startsAfterRecordDigest = try container.decode(Data.self, forKey: .startsAfterRecordDigest)
        nextSequence = try container.decode(UInt64.self, forKey: .nextSequence)
        nextRecordDigest = try container.decode(Data.self, forKey: .nextRecordDigest)
        highWatermarkSequence = try container.decode(UInt64.self, forKey: .highWatermarkSequence)
        retentionFloorSequence = try container.decode(UInt64.self, forKey: .retentionFloorSequence)
        deferredCommitCursor = try container.decode(
            OpaqueRouteCursorV2.self,
            forKey: .deferredCommitCursor
        )
        highWatermark = try container.decode(OpaqueRouteCursorV2.self, forKey: .highWatermark)
        retentionFloor = try container.decode(OpaqueRouteCursorV2.self, forKey: .retentionFloor)
        hasMore = try container.decode(Bool.self, forKey: .hasMore)
        stagedAt = try container.decode(Date.self, forKey: .stagedAt)
        guard isStructurallyValid else {
            throw decentralizedWakeDecodingError(decoder, "Prefetch batch is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Prefetch batch is invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(routeID, forKey: .routeID)
        try container.encode(relayIdentifier, forKey: .relayIdentifier)
        try container.encode(records, forKey: .records)
        try container.encode(fetchedAfter, forKey: .fetchedAfter)
        try container.encode(startsAfterSequence, forKey: .startsAfterSequence)
        try container.encode(startsAfterRecordDigest, forKey: .startsAfterRecordDigest)
        try container.encode(nextSequence, forKey: .nextSequence)
        try container.encode(nextRecordDigest, forKey: .nextRecordDigest)
        try container.encode(highWatermarkSequence, forKey: .highWatermarkSequence)
        try container.encode(retentionFloorSequence, forKey: .retentionFloorSequence)
        try container.encode(deferredCommitCursor, forKey: .deferredCommitCursor)
        try container.encode(highWatermark, forKey: .highWatermark)
        try container.encode(retentionFloor, forKey: .retentionFloor)
        try container.encode(hasMore, forKey: .hasMore)
        try container.encode(stagedAt, forKey: .stagedAt)
    }

    public var isStructurallyValid: Bool {
        let relay = relayIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard version == Self.version
            && routeID.isStructurallyValid
            && relay == relayIdentifier
            && !relay.isEmpty
            && relay.utf8.count <= 512
            && !records.isEmpty
            && records.count <= DecentralizedPrefetchStager.maximumRecordsPerBatch
            && Set(records.map(\.envelopeID)).count == records.count
            && records.allSatisfy({
                $0.routeID == routeID && $0.stagedAt == stagedAt && $0.isStructurallyValid
            })
            && fetchedAfter?.isStructurallyValid != false
            && deferredCommitCursor.isStructurallyValid
            && highWatermark.isStructurallyValid
            && retentionFloor.isStructurallyValid
            && retentionFloorSequence <= startsAfterSequence
            && startsAfterSequence <= nextSequence
            && nextSequence <= highWatermarkSequence
            && startsAfterRecordDigest.count == NoctweaveOpaqueRoutesV2.digestBytes
            && nextRecordDigest.count == NoctweaveOpaqueRoutesV2.digestBytes
            && hasMore == (nextSequence < highWatermarkSequence)
            && stagedAt.timeIntervalSince1970.isFinite else {
            return false
        }
        let received = records.compactMap {
            try? NoctweaveCoder.decode(
                OpaqueRouteReceivedPacketV2.self,
                from: $0.sealedPacketEnvelope
            )
        }
        guard received.count == records.count else { return false }
        var expectedSequence = startsAfterSequence
        var expectedDigest = startsAfterRecordDigest
        for packet in received {
            guard expectedSequence < UInt64.max,
                  packet.sequence == expectedSequence + 1,
                  packet.previousRecordDigest == expectedDigest else {
                return false
            }
            expectedSequence = packet.sequence
            expectedDigest = packet.recordDigest
        }
        return expectedSequence == nextSequence && expectedDigest == nextRecordDigest
    }
}

public struct DecentralizedPrefetchExecutionPolicy: Equatable {
    public var maxRoutesPerCycle: Int
    public var maxPacketsPerPullRoute: Int
    public var maxPacketsPerLongPollRoute: Int
    public var maxTotalPacketsPerCycle: Int

    public init(
        maxRoutesPerCycle: Int = 8,
        maxPacketsPerPullRoute: Int = 8,
        maxPacketsPerLongPollRoute: Int = 16,
        maxTotalPacketsPerCycle: Int = 64
    ) {
        self.maxRoutesPerCycle = max(1, maxRoutesPerCycle)
        self.maxPacketsPerPullRoute = max(1, maxPacketsPerPullRoute)
        self.maxPacketsPerLongPollRoute = max(
            self.maxPacketsPerPullRoute,
            maxPacketsPerLongPollRoute
        )
        self.maxTotalPacketsPerCycle = max(1, maxTotalPacketsPerCycle)
    }
}

public struct DecentralizedPrefetchRouteExecution: Equatable {
    public let routeID: OpaqueReceiveRouteIDV2
    public let relayIdentifier: String
    public let nextPollDelaySeconds: Int
    public let longPollTimeoutSeconds: Int?
    public let maxPacketCount: Int

    public init(
        routeID: OpaqueReceiveRouteIDV2,
        relayIdentifier: String,
        nextPollDelaySeconds: Int,
        longPollTimeoutSeconds: Int?,
        maxPacketCount: Int
    ) {
        self.routeID = routeID
        self.relayIdentifier = relayIdentifier
        self.nextPollDelaySeconds = nextPollDelaySeconds
        self.longPollTimeoutSeconds = longPollTimeoutSeconds
        self.maxPacketCount = max(1, maxPacketCount)
    }
}

public struct DecentralizedPrefetchExecutionPlan: Equatable {
    public let routeExecutions: [DecentralizedPrefetchRouteExecution]
    public let nextCycleDelaySeconds: Int
    public let longPollTimeoutSeconds: Int?
    public let maxTotalPacketCount: Int

    public init(
        routeExecutions: [DecentralizedPrefetchRouteExecution],
        nextCycleDelaySeconds: Int,
        longPollTimeoutSeconds: Int?,
        maxTotalPacketCount: Int
    ) {
        self.routeExecutions = routeExecutions
        self.nextCycleDelaySeconds = nextCycleDelaySeconds
        self.longPollTimeoutSeconds = longPollTimeoutSeconds
        self.maxTotalPacketCount = max(0, maxTotalPacketCount)
    }
}

public enum DecentralizedPrefetchStager {
    public static let maximumRecordsPerBatch = 128
    public static let maximumSealedEnvelopeBytes = 512 * 1_024

    public static func stageOpaqueRouteBatch(
        _ sync: OpaqueRouteSyncResponseV2,
        routeID: OpaqueReceiveRouteIDV2,
        relayIdentifier: String,
        fetchedAfter: OpaqueRouteCursorV2?,
        stagedAt: Date = Date()
    ) throws -> DecentralizedPrefetchBatch {
        guard !sync.packets.isEmpty else { throw DecentralizedPrefetchError.emptyBatch }
        guard sync.packets.count <= maximumRecordsPerBatch else {
            throw DecentralizedPrefetchError.batchTooLarge
        }
        let relay = try normalizedRelayIdentifier(relayIdentifier)
        guard routeID.isStructurallyValid,
              sync.isStructurallyValid,
              sync.nextCursor.isStructurallyValid,
              sync.highWatermark.isStructurallyValid,
              sync.retentionFloor.isStructurallyValid,
              fetchedAfter?.isStructurallyValid != false else {
            throw DecentralizedPrefetchError.invalidRouteBatch
        }
        let records = try sync.packets.map { received -> DecentralizedPrefetchRecord in
            guard received.packet.routeID == routeID,
                  received.packet.isStructurallyValid else {
                throw DecentralizedPrefetchError.invalidRouteBatch
            }
            let sealed = try NoctweaveCoder.encode(received, sortedKeys: true)
            guard sealed.count <= maximumSealedEnvelopeBytes else {
                throw DecentralizedPrefetchError.invalidEnvelope
            }
            return try DecentralizedPrefetchRecord(
                envelopeID: received.packet.packetID,
                routeID: routeID,
                routeRevision: received.routeRevision,
                stagedAt: stagedAt,
                sealedPacketEnvelope: sealed
            )
        }
        return try DecentralizedPrefetchBatch(
            routeID: routeID,
            relayIdentifier: relay,
            records: records,
            fetchedAfter: fetchedAfter,
            startsAfterSequence: sync.startsAfterSequence,
            startsAfterRecordDigest: sync.startsAfterRecordDigest,
            nextSequence: sync.nextSequence,
            nextRecordDigest: sync.nextRecordDigest,
            highWatermarkSequence: sync.highWatermarkSequence,
            retentionFloorSequence: sync.retentionFloorSequence,
            deferredCommitCursor: sync.nextCursor,
            highWatermark: sync.highWatermark,
            retentionFloor: sync.retentionFloor,
            hasMore: sync.hasMore,
            stagedAt: stagedAt
        )
    }

    private static func normalizedRelayIdentifier(_ value: String) throws -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed == value, !trimmed.isEmpty, trimmed.utf8.count <= 512 else {
            throw DecentralizedPrefetchError.invalidRelayIdentifier
        }
        return trimmed
    }
}

public actor DecentralizedPrefetchBatchStore {
    public static let maximumStoredBytes = 96 * 1_024 * 1_024
    private static let storedVersion = 2
    private static let authenticatedData = Data(
        "NOCTWEAVE/OPAQUE-ROUTE-PREFETCH-BATCH/V2".utf8
    )

    private let fileURL: URL
    private let protectionKey: SymmetricKey

    public init(fileURL: URL, protectionKey: Data) throws {
        guard protectionKey.count == 32 else {
            throw DecentralizedPrefetchError.invalidProtectionKey
        }
        self.fileURL = fileURL
        self.protectionKey = SymmetricKey(data: protectionKey)
    }

    public func save(_ batch: DecentralizedPrefetchBatch) throws {
        guard Self.isValid(batch) else { throw DecentralizedPrefetchError.invalidBatch }
        var encodedBatch = try NoctweaveCoder.encode(batch, sortedKeys: true)
        defer { encodedBatch.secureWipe() }
        let payload = try CryptoBox.encrypt(
            encodedBatch,
            key: protectionKey,
            authenticatedData: Self.authenticatedData
        )
        let stored = DecentralizedPrefetchStoredBatch(
            version: Self.storedVersion,
            payload: payload
        )
        var encodedStored = try NoctweaveCoder.encode(stored, sortedKeys: true)
        defer { encodedStored.secureWipe() }
        guard encodedStored.count <= Self.maximumStoredBytes else {
            throw DecentralizedPrefetchError.batchTooLarge
        }

        let directory = fileURL.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: directory.path
        )
        #if os(iOS)
        try encodedStored.write(to: fileURL, options: [.atomic, .completeFileProtection])
        #else
        try encodedStored.write(to: fileURL, options: [.atomic])
        #endif
        do {
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: fileURL.path
            )
        } catch {
            try? FileManager.default.removeItem(at: fileURL)
            throw error
        }
    }

    public func load() throws -> DecentralizedPrefetchBatch? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
        let values = try fileURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard values.isRegularFile == true,
              let fileSize = values.fileSize,
              fileSize >= 0,
              fileSize <= Self.maximumStoredBytes else {
            throw DecentralizedPrefetchError.invalidStoredBatch
        }
        var encodedStored = try Data(contentsOf: fileURL)
        defer { encodedStored.secureWipe() }
        guard encodedStored.count <= Self.maximumStoredBytes,
              let stored = try? NoctweaveCoder.decode(
                  DecentralizedPrefetchStoredBatch.self,
                  from: encodedStored
              ),
              stored.version == Self.storedVersion,
              var encodedBatch = try? CryptoBox.decrypt(
                  stored.payload,
                  key: protectionKey,
                  authenticatedData: Self.authenticatedData
              ) else {
            throw DecentralizedPrefetchError.invalidStoredBatch
        }
        defer { encodedBatch.secureWipe() }
        guard let batch = try? NoctweaveCoder.decode(
            DecentralizedPrefetchBatch.self,
            from: encodedBatch
        ), Self.isValid(batch) else {
            throw DecentralizedPrefetchError.invalidStoredBatch
        }
        return batch
    }

    public func remove() throws {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return }
        Self.bestEffortOverwriteFile(at: fileURL)
        try FileManager.default.removeItem(at: fileURL)
    }

    private static func isValid(_ batch: DecentralizedPrefetchBatch) -> Bool {
        batch.isStructurallyValid
    }

    private static func bestEffortOverwriteFile(at url: URL) {
        guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]),
              values.isRegularFile == true,
              let fileSize = values.fileSize,
              fileSize > 0,
              let handle = try? FileHandle(forWritingTo: url) else {
            return
        }
        defer { try? handle.close() }
        handle.seek(toFileOffset: 0)
        let chunkSize = 64 * 1_024
        let zeros = Data(repeating: 0, count: min(chunkSize, fileSize))
        var remaining = fileSize
        while remaining > 0 {
            let writeCount = min(chunkSize, remaining)
            handle.write(Data(zeros.prefix(writeCount)))
            remaining -= writeCount
        }
        handle.synchronizeFile()
    }
}

private struct DecentralizedPrefetchStoredBatch: Codable, Equatable {
    let version: Int
    let payload: EncryptedPayload

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case payload
    }

    init(version: Int, payload: EncryptedPayload) {
        self.version = version
        self.payload = payload
    }

    init(from decoder: Decoder) throws {
        try decentralizedWakeRequireExactObject(
            decoder,
            keys: CodingKeys.allCases.map(\.rawValue)
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        payload = try container.decode(EncryptedPayload.self, forKey: .payload)
    }
}

public enum DecentralizedPrefetchExecutionPlanner {
    public static func makePlan(
        for routes: [DecentralizedWakeRoute],
        defaultDelaySeconds: Int,
        maxDelaySeconds: Int,
        policy: DecentralizedPrefetchExecutionPolicy = DecentralizedPrefetchExecutionPolicy(),
        now: Date = Date()
    ) -> DecentralizedPrefetchExecutionPlan {
        makePlan(
            from: DecentralizedWakePlanner.makeCyclePlan(
                for: routes,
                defaultDelaySeconds: defaultDelaySeconds,
                maxDelaySeconds: maxDelaySeconds,
                now: now
            ),
            policy: policy
        )
    }

    public static func makePlan(
        from cycle: DecentralizedWakeCyclePlan,
        policy: DecentralizedPrefetchExecutionPolicy = DecentralizedPrefetchExecutionPolicy()
    ) -> DecentralizedPrefetchExecutionPlan {
        var remainingPackets = policy.maxTotalPacketsPerCycle
        let selectedRoutes = cycle.routePlans
            .sorted { lhs, rhs in
                if lhs.plan.nextPollDelaySeconds != rhs.plan.nextPollDelaySeconds {
                    return lhs.plan.nextPollDelaySeconds < rhs.plan.nextPollDelaySeconds
                }
                if lhs.relayIdentifier != rhs.relayIdentifier {
                    return lhs.relayIdentifier < rhs.relayIdentifier
                }
                return lhs.routeID.rawValue.lexicographicallyPrecedes(rhs.routeID.rawValue)
            }
            .prefix(policy.maxRoutesPerCycle)

        let executions = selectedRoutes.compactMap { route -> DecentralizedPrefetchRouteExecution? in
            guard remainingPackets > 0 else { return nil }
            let routeCap = route.plan.longPollTimeoutSeconds == nil
                ? policy.maxPacketsPerPullRoute
                : policy.maxPacketsPerLongPollRoute
            let packetCount = min(routeCap, remainingPackets)
            remainingPackets -= packetCount
            return DecentralizedPrefetchRouteExecution(
                routeID: route.routeID,
                relayIdentifier: route.relayIdentifier,
                nextPollDelaySeconds: route.plan.nextPollDelaySeconds,
                longPollTimeoutSeconds: route.plan.longPollTimeoutSeconds,
                maxPacketCount: packetCount
            )
        }
        return DecentralizedPrefetchExecutionPlan(
            routeExecutions: executions,
            nextCycleDelaySeconds: cycle.nextPollDelaySeconds,
            longPollTimeoutSeconds: cycle.longPollTimeoutSeconds,
            maxTotalPacketCount: policy.maxTotalPacketsPerCycle - remainingPackets
        )
    }
}

public enum DecentralizedWakePlanner {
    public static func makePlan(
        support: DecentralizedWakeSupport?,
        routeID: OpaqueReceiveRouteIDV2,
        routeJitterSeed: Data,
        relayIdentifier: String,
        failureCount: Int = 0,
        now: Date = Date()
    ) -> DecentralizedWakePlan {
        let policy = support ?? DecentralizedWakeSupport()
        let boundedFailures = min(max(0, failureCount), 6)
        let base = min(
            policy.maxPollIntervalSeconds,
            policy.minPollIntervalSeconds * (1 << boundedFailures)
        )
        let jitterWindow = max(0, base * policy.jitterPermille / 1_000)
        let jitter = jitterWindow == 0 || !routeID.isStructurallyValid
            || routeJitterSeed.count != 32
            ? 0
            : deterministicJitter(
                upperBound: jitterWindow,
                routeID: routeID,
                routeJitterSeed: routeJitterSeed,
                relayIdentifier: normalizedRelayIdentifier(relayIdentifier),
                now: now,
                failureCount: boundedFailures
            )
        let delay = min(policy.maxPollIntervalSeconds, base + jitter)
        return DecentralizedWakePlan(
            nextPollDelaySeconds: delay,
            longPollTimeoutSeconds: policy.longPollTimeoutSeconds.map { min($0, delay) },
            failureBackoffStep: boundedFailures
        )
    }

    public static func nextPollDelaySeconds(
        for routes: [DecentralizedWakeRoute],
        defaultDelaySeconds: Int,
        maxDelaySeconds: Int,
        now: Date = Date()
    ) -> Int {
        makeCyclePlan(
            for: routes,
            defaultDelaySeconds: defaultDelaySeconds,
            maxDelaySeconds: maxDelaySeconds,
            now: now
        ).nextPollDelaySeconds
    }

    public static func makeCyclePlan(
        for routes: [DecentralizedWakeRoute],
        defaultDelaySeconds: Int,
        maxDelaySeconds: Int,
        now: Date = Date()
    ) -> DecentralizedWakeCyclePlan {
        let defaultDelay = min(
            DecentralizedWakeSupport.absoluteMaximumPollIntervalSeconds,
            max(5, defaultDelaySeconds)
        )
        let upperBound = min(
            DecentralizedWakeSupport.absoluteMaximumPollIntervalSeconds,
            max(defaultDelay, maxDelaySeconds)
        )
        let validRoutes = routes.filter(\.isStructurallyValid)
        guard !validRoutes.isEmpty else {
            return DecentralizedWakeCyclePlan(
                routePlans: [],
                nextPollDelaySeconds: min(defaultDelay, upperBound),
                longPollTimeoutSeconds: nil
            )
        }

        let routePlans = Dictionary(grouping: validRoutes, by: routeKey)
            .values
            .compactMap { duplicates -> DecentralizedWakeRoutePlan? in
                guard let selected = duplicates.min(by: { lhs, rhs in
                    if lhs.failureCount != rhs.failureCount {
                        return lhs.failureCount < rhs.failureCount
                    }
                    if lhs.relayIdentifier != rhs.relayIdentifier {
                        return lhs.relayIdentifier < rhs.relayIdentifier
                    }
                    return lhs.routeJitterSeed.lexicographicallyPrecedes(rhs.routeJitterSeed)
                }) else { return nil }
                let rawPlan: DecentralizedWakePlan
                if let support = selected.support {
                    rawPlan = makePlan(
                        support: support,
                        routeID: selected.routeID,
                        routeJitterSeed: selected.routeJitterSeed,
                        relayIdentifier: selected.relayIdentifier,
                        failureCount: selected.failureCount,
                        now: now
                    )
                } else {
                    rawPlan = DecentralizedWakePlan(
                        nextPollDelaySeconds: defaultDelay,
                        longPollTimeoutSeconds: nil,
                        failureBackoffStep: min(max(0, selected.failureCount), 6)
                    )
                }
                let boundedDelay = min(max(rawPlan.nextPollDelaySeconds, 5), upperBound)
                return DecentralizedWakeRoutePlan(
                    routeID: selected.routeID,
                    relayIdentifier: selected.relayIdentifier,
                    plan: DecentralizedWakePlan(
                        nextPollDelaySeconds: boundedDelay,
                        longPollTimeoutSeconds: rawPlan.longPollTimeoutSeconds.map {
                            min($0, boundedDelay)
                        },
                        failureBackoffStep: rawPlan.failureBackoffStep
                    )
                )
            }
            .sorted {
                $0.routeID.rawValue.lexicographicallyPrecedes($1.routeID.rawValue)
            }
        let selectedDelay = routePlans.map(\.plan.nextPollDelaySeconds).min() ?? defaultDelay
        let selectedLongPoll = routePlans
            .filter { $0.plan.nextPollDelaySeconds == selectedDelay }
            .compactMap(\.plan.longPollTimeoutSeconds)
            .min()
        return DecentralizedWakeCyclePlan(
            routePlans: routePlans,
            nextPollDelaySeconds: selectedDelay,
            longPollTimeoutSeconds: selectedLongPoll
        )
    }

    private static func deterministicJitter(
        upperBound: Int,
        routeID: OpaqueReceiveRouteIDV2,
        routeJitterSeed: Data,
        relayIdentifier: String,
        now: Date,
        failureCount: Int
    ) -> Int {
        let minuteValue = now.timeIntervalSince1970 / 60
        let epochMinute: Int64
        if minuteValue.isFinite,
           minuteValue >= Double(Int64.min),
           minuteValue <= Double(Int64.max) {
            epochMinute = Int64(minuteValue.rounded(.towardZero))
        } else {
            epochMinute = 0
        }
        var data = Data("noctweave/opaque-route-wake/v2".utf8)
        data.append(routeJitterSeed)
        data.append(routeID.rawValue)
        data.append(0)
        data.append(Data(relayIdentifier.utf8))
        data.append(0)
        data.append(Data("\(epochMinute):\(failureCount)".utf8))
        let value = SHA256.hash(data: data).prefix(8).reduce(UInt64(0)) {
            ($0 << 8) | UInt64($1)
        }
        return Int(value % UInt64(upperBound + 1))
    }

    private static func routeKey(_ route: DecentralizedWakeRoute) -> Data {
        route.routeID.rawValue
    }

    private static func normalizedRelayIdentifier(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "local-relay-route" : trimmed
    }
}

private struct DecentralizedWakeCodingKey: CodingKey {
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

private func decentralizedWakeRequireExactObject(
    _ decoder: Decoder,
    keys: [String]
) throws {
    let container = try decoder.container(keyedBy: DecentralizedWakeCodingKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == Set(keys) else {
        throw decentralizedWakeDecodingError(
            decoder,
            "Persisted wake fields must match the current schema exactly"
        )
    }
}

private func decentralizedWakeDecodingError(
    _ decoder: Decoder,
    _ description: String
) -> DecodingError {
    .dataCorrupted(
        DecodingError.Context(
            codingPath: decoder.codingPath,
            debugDescription: description
        )
    )
}

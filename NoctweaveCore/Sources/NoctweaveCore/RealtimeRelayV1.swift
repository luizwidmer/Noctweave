import CryptoKit
import Foundation

/// Application-neutral relay modules for realtime collaboration. Every
/// payload in this file is opaque to the relay; the relay only validates
/// capability proofs, bounds, cursors, and lease lifetimes.
public enum RealtimeRelayLimitsV1 {
    public static let capabilityBytes = 32
    public static let maximumRecordBytes = 512 * 1024
    public static let maximumRecordsPerPage = 256
    public static let maximumRealtimeRecords = 4_096
    public static let maximumRealtimeRoutes = 4_096
    public static let maximumRealtimeSubscriptionsPerRoute = 256
    public static let maximumRealtimeLifetime: TimeInterval = 24 * 60 * 60
    public static let maximumSharedLogRecords = 100_000
    public static let maximumSharedLogs = 4_096
    public static let maximumSharedLogLifetime: TimeInterval = 30 * 24 * 60 * 60
    public static let maximumPresencePayloadBytes = 16 * 1024
    public static let minimumPresenceLeaseSeconds = 5
    public static let maximumPresenceLeaseSeconds = 120
    public static let maximumPresenceLeases = 4_096
    public static let maximumMediaBlobChunkBytes = 512 * 1024
    public static let maximumMediaBlobChunks = 256
    public static let maximumMediaBlobBytes = 32 * 1024 * 1024
    public static let maximumMediaBlobs = 4_096
    public static let minimumMediaRetentionSeconds = 60
    public static let maximumMediaRetentionSeconds = 7 * 24 * 60 * 60
}

public enum RealtimeRelayRuntimeError: Error, Equatable {
    case invalidRequest
    case unauthorized
    case unavailable
    case conflict
    case capacity
    case invalidCursor
    case expired
}

public enum OpaqueCapabilityV1 {
    public static func generate() -> Data {
        SymmetricKey(size: .bits256).dataRepresentation
    }

    public static func isValid(_ value: Data) -> Bool {
        value.count == RealtimeRelayLimitsV1.capabilityBytes && value.contains { $0 != 0 }
    }
}

private struct RealtimeCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?
    init?(stringValue: String) { self.stringValue = stringValue; intValue = nil }
    init?(intValue: Int) { stringValue = String(intValue); self.intValue = intValue }
}

private func realtimeRequireExact(_ decoder: Decoder, _ keys: Set<String>) throws {
    let container = try decoder.container(keyedBy: RealtimeCodingKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == keys else {
        throw DecodingError.dataCorrupted(.init(
            codingPath: decoder.codingPath,
            debugDescription: "Realtime relay object fields are not current"
        ))
    }
}

private func realtimeRequireAllowed(
    _ decoder: Decoder,
    allowed: Set<String>,
    required: Set<String>
) throws {
    let container = try decoder.container(keyedBy: RealtimeCodingKey.self)
    let actual = Set(container.allKeys.map(\.stringValue))
    guard actual.isSubset(of: allowed), required.isSubset(of: actual) else {
        throw DecodingError.dataCorrupted(.init(
            codingPath: decoder.codingPath,
            debugDescription: "Realtime relay object fields are not current"
        ))
    }
}

private func realtimeDate(_ date: Date) -> Date {
    Date(timeIntervalSince1970: floor(date.timeIntervalSince1970))
}

private func realtimeTimestampIsValid(_ date: Date) -> Bool {
    let seconds = date.timeIntervalSince1970
    return seconds.isFinite
        && seconds >= 0
        && seconds <= 9_007_199_254_740_991
        && floor(seconds) == seconds
}

private func realtimeValidPayload(_ payload: Data) -> Bool {
    !payload.isEmpty && payload.count <= RealtimeRelayLimitsV1.maximumRecordBytes
}

public struct OpaqueRelayRecordV1: Codable, Equatable {
    public let sequence: UInt64
    public let recordID: UUID
    public let payload: Data

    public init(sequence: UInt64, recordID: UUID, payload: Data) {
        self.sequence = sequence
        self.recordID = recordID
        self.payload = payload
    }

    public var isStructurallyValid: Bool {
        sequence > 0 && realtimeValidPayload(payload)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case sequence, recordID, payload
    }

    public init(from decoder: Decoder) throws {
        try realtimeRequireExact(decoder, Set(CodingKeys.allCases.map(\.rawValue)))
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            sequence: try values.decode(UInt64.self, forKey: .sequence),
            recordID: try values.decode(UUID.self, forKey: .recordID),
            payload: try values.decode(Data.self, forKey: .payload)
        )
        guard isStructurallyValid else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Opaque relay record is invalid")) }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw EncodingError.invalidValue(self, .init(codingPath: encoder.codingPath, debugDescription: "Opaque relay record is invalid")) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(sequence, forKey: .sequence)
        try values.encode(recordID, forKey: .recordID)
        try values.encode(payload, forKey: .payload)
    }
}

public struct OpaqueRelaySyncBatchV1: Codable, Equatable {
    public let records: [OpaqueRelayRecordV1]
    public let nextSequence: UInt64
    public let highWatermark: UInt64
    public let retentionFloor: UInt64
    public let hasMore: Bool

    public init(records: [OpaqueRelayRecordV1], nextSequence: UInt64, highWatermark: UInt64, retentionFloor: UInt64, hasMore: Bool) {
        self.records = records
        self.nextSequence = nextSequence
        self.highWatermark = highWatermark
        self.retentionFloor = retentionFloor
        self.hasMore = hasMore
    }

    public var isStructurallyValid: Bool {
        let sequences = records.map(\.sequence)
        let recordsAreContiguous = zip(sequences, sequences.dropFirst()).allSatisfy {
            $0 < UInt64.max && $1 == $0 + 1
        }
        return records.count <= RealtimeRelayLimitsV1.maximumRecordsPerPage
            && records.allSatisfy(\.isStructurallyValid)
            && recordsAreContiguous
            && nextSequence <= highWatermark
            && retentionFloor > 0
            && retentionFloor - 1 <= highWatermark
            && nextSequence >= retentionFloor - 1
            && (records.first?.sequence ?? retentionFloor) >= retentionFloor
            && (records.last?.sequence ?? nextSequence) == nextSequence
            && hasMore == (nextSequence < highWatermark)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable { case records, nextSequence, highWatermark, retentionFloor, hasMore }
    public init(from decoder: Decoder) throws {
        try realtimeRequireExact(decoder, Set(CodingKeys.allCases.map(\.rawValue)))
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(records: try values.decode([OpaqueRelayRecordV1].self, forKey: .records), nextSequence: try values.decode(UInt64.self, forKey: .nextSequence), highWatermark: try values.decode(UInt64.self, forKey: .highWatermark), retentionFloor: try values.decode(UInt64.self, forKey: .retentionFloor), hasMore: try values.decode(Bool.self, forKey: .hasMore))
        guard isStructurallyValid else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Opaque relay sync batch is invalid")) }
    }
    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw EncodingError.invalidValue(self, .init(codingPath: encoder.codingPath, debugDescription: "Opaque relay sync batch is invalid")) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(records, forKey: .records); try values.encode(nextSequence, forKey: .nextSequence); try values.encode(highWatermark, forKey: .highWatermark); try values.encode(retentionFloor, forKey: .retentionFloor); try values.encode(hasMore, forKey: .hasMore)
    }
}

public struct RealtimeRouteCreateRequestV1: Codable, Equatable {
    public let routeCapability: Data; public let appendCapability: Data; public let readCapability: Data; public let expiresAt: Date
    public init(routeCapability: Data, appendCapability: Data, readCapability: Data, expiresAt: Date) { self.routeCapability = routeCapability; self.appendCapability = appendCapability; self.readCapability = readCapability; self.expiresAt = realtimeDate(expiresAt) }
    public var isStructurallyValid: Bool { OpaqueCapabilityV1.isValid(routeCapability) && OpaqueCapabilityV1.isValid(appendCapability) && OpaqueCapabilityV1.isValid(readCapability) && Set([routeCapability, appendCapability, readCapability]).count == 3 && realtimeTimestampIsValid(expiresAt) }
    private enum CodingKeys: String, CodingKey, CaseIterable { case routeCapability, appendCapability, readCapability, expiresAt }
    public init(from decoder: Decoder) throws { try realtimeRequireExact(decoder, Set(CodingKeys.allCases.map(\.rawValue))); let v = try decoder.container(keyedBy: CodingKeys.self); self.init(routeCapability: try v.decode(Data.self, forKey: .routeCapability), appendCapability: try v.decode(Data.self, forKey: .appendCapability), readCapability: try v.decode(Data.self, forKey: .readCapability), expiresAt: try v.decode(Date.self, forKey: .expiresAt)); guard isStructurallyValid else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Realtime route create request is invalid")) } }
    public func encode(to encoder: Encoder) throws { guard isStructurallyValid else { throw EncodingError.invalidValue(self, .init(codingPath: encoder.codingPath, debugDescription: "Realtime route create request is invalid")) }; var v = encoder.container(keyedBy: CodingKeys.self); try v.encode(routeCapability, forKey: .routeCapability); try v.encode(appendCapability, forKey: .appendCapability); try v.encode(readCapability, forKey: .readCapability); try v.encode(expiresAt, forKey: .expiresAt) }
}

public struct RealtimeRouteCreatedV1: Codable, Equatable {
    public let routeCapability: Data; public let appendCapability: Data; public let readCapability: Data; public let expiresAt: Date
    public init(routeCapability: Data, appendCapability: Data, readCapability: Data, expiresAt: Date) { self.routeCapability = routeCapability; self.appendCapability = appendCapability; self.readCapability = readCapability; self.expiresAt = realtimeDate(expiresAt) }
    public var isStructurallyValid: Bool { RealtimeRouteCreateRequestV1(routeCapability: routeCapability, appendCapability: appendCapability, readCapability: readCapability, expiresAt: expiresAt).isStructurallyValid }
    private enum CodingKeys: String, CodingKey, CaseIterable { case routeCapability, appendCapability, readCapability, expiresAt }
    public init(from decoder: Decoder) throws { try realtimeRequireExact(decoder, Set(CodingKeys.allCases.map(\.rawValue))); let v = try decoder.container(keyedBy: CodingKeys.self); self.init(routeCapability: try v.decode(Data.self, forKey: .routeCapability), appendCapability: try v.decode(Data.self, forKey: .appendCapability), readCapability: try v.decode(Data.self, forKey: .readCapability), expiresAt: try v.decode(Date.self, forKey: .expiresAt)); guard isStructurallyValid else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Realtime route response is invalid")) } }
    public func encode(to encoder: Encoder) throws { guard isStructurallyValid else { throw EncodingError.invalidValue(self, .init(codingPath: encoder.codingPath, debugDescription: "Realtime route response is invalid")) }; var v = encoder.container(keyedBy: CodingKeys.self); try v.encode(routeCapability, forKey: .routeCapability); try v.encode(appendCapability, forKey: .appendCapability); try v.encode(readCapability, forKey: .readCapability); try v.encode(expiresAt, forKey: .expiresAt) }
}

public struct RealtimeRouteAppendRequestV1: Codable, Equatable {
    public let routeCapability: Data; public let appendCapability: Data; public let recordID: UUID; public let payload: Data
    public init(routeCapability: Data, appendCapability: Data, recordID: UUID, payload: Data) { self.routeCapability = routeCapability; self.appendCapability = appendCapability; self.recordID = recordID; self.payload = payload }
    public var isStructurallyValid: Bool { OpaqueCapabilityV1.isValid(routeCapability) && OpaqueCapabilityV1.isValid(appendCapability) && realtimeValidPayload(payload) }
    private enum CodingKeys: String, CodingKey, CaseIterable { case routeCapability, appendCapability, recordID, payload }
    public init(from decoder: Decoder) throws { try realtimeRequireExact(decoder, Set(CodingKeys.allCases.map(\.rawValue))); let v = try decoder.container(keyedBy: CodingKeys.self); self.init(routeCapability: try v.decode(Data.self, forKey: .routeCapability), appendCapability: try v.decode(Data.self, forKey: .appendCapability), recordID: try v.decode(UUID.self, forKey: .recordID), payload: try v.decode(Data.self, forKey: .payload)); guard isStructurallyValid else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Realtime route append request is invalid")) } }
    public func encode(to encoder: Encoder) throws { guard isStructurallyValid else { throw EncodingError.invalidValue(self, .init(codingPath: encoder.codingPath, debugDescription: "Realtime route append request is invalid")) }; var v = encoder.container(keyedBy: CodingKeys.self); try v.encode(routeCapability, forKey: .routeCapability); try v.encode(appendCapability, forKey: .appendCapability); try v.encode(recordID, forKey: .recordID); try v.encode(payload, forKey: .payload) }
}

public struct RealtimeRouteAppendReceiptV1: Codable, Equatable { public let sequence: UInt64; public let recordID: UUID; public init(sequence: UInt64, recordID: UUID) { self.sequence = sequence; self.recordID = recordID } }
public struct RealtimeRouteSubscribeRequestV1: Codable, Equatable { public let routeCapability: Data; public let readCapability: Data; public let afterSequence: UInt64; public init(routeCapability: Data, readCapability: Data, afterSequence: UInt64 = 0) { self.routeCapability = routeCapability; self.readCapability = readCapability; self.afterSequence = afterSequence } }
public struct RealtimeRouteSubscriptionV1: Codable, Equatable { public let subscriptionCapability: Data; public let routeCapability: Data; public let nextSequence: UInt64; public let expiresAt: Date; public init(subscriptionCapability: Data, routeCapability: Data, nextSequence: UInt64, expiresAt: Date) { self.subscriptionCapability = subscriptionCapability; self.routeCapability = routeCapability; self.nextSequence = nextSequence; self.expiresAt = realtimeDate(expiresAt) } }
public struct RealtimeRouteSyncRequestV1: Codable, Equatable { public let routeCapability: Data; public let subscriptionCapability: Data; public let afterSequence: UInt64; public let maxRecords: Int; public init(routeCapability: Data, subscriptionCapability: Data, afterSequence: UInt64 = 0, maxRecords: Int = 256) { self.routeCapability = routeCapability; self.subscriptionCapability = subscriptionCapability; self.afterSequence = afterSequence; self.maxRecords = maxRecords } }
public struct RealtimeRouteUnsubscribeRequestV1: Codable, Equatable { public let routeCapability: Data; public let subscriptionCapability: Data; public init(routeCapability: Data, subscriptionCapability: Data) { self.routeCapability = routeCapability; self.subscriptionCapability = subscriptionCapability } }

public struct SharedLogCreateRequestV1: Codable, Equatable { public let logCapability: Data; public let appendCapability: Data; public let readCapability: Data; public let retentionSeconds: Int; public let maxRecords: Int; public init(logCapability: Data, appendCapability: Data, readCapability: Data, retentionSeconds: Int = 2_592_000, maxRecords: Int = 100_000) { self.logCapability = logCapability; self.appendCapability = appendCapability; self.readCapability = readCapability; self.retentionSeconds = retentionSeconds; self.maxRecords = maxRecords } }
public struct SharedLogCreatedV1: Codable, Equatable { public let logCapability: Data; public let appendCapability: Data; public let readCapability: Data; public let retentionSeconds: Int; public init(logCapability: Data, appendCapability: Data, readCapability: Data, retentionSeconds: Int) { self.logCapability = logCapability; self.appendCapability = appendCapability; self.readCapability = readCapability; self.retentionSeconds = retentionSeconds } }
public struct SharedLogAppendRequestV1: Codable, Equatable { public let logCapability: Data; public let appendCapability: Data; public let recordID: UUID; public let payload: Data; public init(logCapability: Data, appendCapability: Data, recordID: UUID, payload: Data) { self.logCapability = logCapability; self.appendCapability = appendCapability; self.recordID = recordID; self.payload = payload } }
public struct SharedLogAppendReceiptV1: Codable, Equatable { public let sequence: UInt64; public let recordID: UUID; public init(sequence: UInt64, recordID: UUID) { self.sequence = sequence; self.recordID = recordID } }
public struct SharedLogSyncRequestV1: Codable, Equatable { public let logCapability: Data; public let readCapability: Data; public let afterSequence: UInt64; public let maxRecords: Int; public init(logCapability: Data, readCapability: Data, afterSequence: UInt64 = 0, maxRecords: Int = 256) { self.logCapability = logCapability; self.readCapability = readCapability; self.afterSequence = afterSequence; self.maxRecords = maxRecords } }

public struct PresenceLeaseAcquireRequestV1: Codable, Equatable { public let scope: Data; public let scopeCapability: Data; public let leaseID: Data; public let leaseCapability: Data; public let payload: Data; public let ttlSeconds: Int; public init(scope: Data, scopeCapability: Data, leaseID: Data, leaseCapability: Data, payload: Data, ttlSeconds: Int = 30) { self.scope = scope; self.scopeCapability = scopeCapability; self.leaseID = leaseID; self.leaseCapability = leaseCapability; self.payload = payload; self.ttlSeconds = ttlSeconds } }
public struct PresenceLeaseRenewRequestV1: Codable, Equatable { public let scope: Data; public let scopeCapability: Data; public let leaseID: Data; public let leaseCapability: Data; public let payload: Data; public let ttlSeconds: Int; public init(scope: Data, scopeCapability: Data, leaseID: Data, leaseCapability: Data, payload: Data, ttlSeconds: Int = 30) { self.scope = scope; self.scopeCapability = scopeCapability; self.leaseID = leaseID; self.leaseCapability = leaseCapability; self.payload = payload; self.ttlSeconds = ttlSeconds } }
public struct PresenceLeaseReleaseRequestV1: Codable, Equatable { public let scope: Data; public let scopeCapability: Data; public let leaseID: Data; public let leaseCapability: Data; public init(scope: Data, scopeCapability: Data, leaseID: Data, leaseCapability: Data) { self.scope = scope; self.scopeCapability = scopeCapability; self.leaseID = leaseID; self.leaseCapability = leaseCapability } }
public struct PresenceLeaseListRequestV1: Codable, Equatable { public let scope: Data; public let scopeCapability: Data; public init(scope: Data, scopeCapability: Data) { self.scope = scope; self.scopeCapability = scopeCapability } }
public struct PresenceLeaseV1: Codable, Equatable {
    public let leaseID: Data; public let payload: Data; public let expiresAt: Date
    public init(leaseID: Data, payload: Data, expiresAt: Date) { self.leaseID = leaseID; self.payload = payload; self.expiresAt = realtimeDate(expiresAt) }
    public var isStructurallyValid: Bool { leaseID.count == 16 && leaseID.contains { $0 != 0 } && payload.count <= RealtimeRelayLimitsV1.maximumPresencePayloadBytes && realtimeTimestampIsValid(expiresAt) }
    private enum CodingKeys: String, CodingKey, CaseIterable { case leaseID, payload, expiresAt }
    public init(from decoder: Decoder) throws {
        try realtimeRequireExact(decoder, Set(CodingKeys.allCases.map(\.rawValue)))
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(leaseID: try values.decode(Data.self, forKey: .leaseID), payload: try values.decode(Data.self, forKey: .payload), expiresAt: try values.decode(Date.self, forKey: .expiresAt))
        guard isStructurallyValid else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Presence lease is invalid")) }
    }
    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw EncodingError.invalidValue(self, .init(codingPath: encoder.codingPath, debugDescription: "Presence lease is invalid")) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(leaseID, forKey: .leaseID); try values.encode(payload, forKey: .payload); try values.encode(expiresAt, forKey: .expiresAt)
    }
}

public struct MediaBlobCreateRequestV1: Codable, Equatable { public let blobID: UUID; public let blobCapability: Data; public let chunkCount: Int; public let ttlSeconds: Int; public init(blobID: UUID, blobCapability: Data, chunkCount: Int, ttlSeconds: Int = 86_400) { self.blobID = blobID; self.blobCapability = blobCapability; self.chunkCount = chunkCount; self.ttlSeconds = ttlSeconds } }
public struct MediaBlobCreatedV1: Codable, Equatable { public let blobID: UUID; public let blobCapability: Data; public let chunkCount: Int; public let expiresAt: Date; public init(blobID: UUID, blobCapability: Data, chunkCount: Int, expiresAt: Date) { self.blobID = blobID; self.blobCapability = blobCapability; self.chunkCount = chunkCount; self.expiresAt = realtimeDate(expiresAt) } }
public struct MediaBlobUploadRequestV1: Codable, Equatable { public let blobID: UUID; public let blobCapability: Data; public let chunkIndex: Int; public let payload: Data; public let idempotencyKey: Data; public init(blobID: UUID, blobCapability: Data, chunkIndex: Int, payload: Data, idempotencyKey: Data) { self.blobID = blobID; self.blobCapability = blobCapability; self.chunkIndex = chunkIndex; self.payload = payload; self.idempotencyKey = idempotencyKey } }
public struct MediaBlobFetchRequestV1: Codable, Equatable { public let blobID: UUID; public let blobCapability: Data; public let chunkIndex: Int; public init(blobID: UUID, blobCapability: Data, chunkIndex: Int) { self.blobID = blobID; self.blobCapability = blobCapability; self.chunkIndex = chunkIndex } }
public struct MediaBlobReleaseRequestV1: Codable, Equatable { public let blobID: UUID; public let blobCapability: Data; public init(blobID: UUID, blobCapability: Data) { self.blobID = blobID; self.blobCapability = blobCapability } }
public struct MediaBlobChunkV1: Codable, Equatable { public let blobID: UUID; public let chunkIndex: Int; public let payload: Data; public init(blobID: UUID, chunkIndex: Int, payload: Data) { self.blobID = blobID; self.chunkIndex = chunkIndex; self.payload = payload } }

struct StoredOpaqueRecordV1: Codable, Equatable {
    let record: OpaqueRelayRecordV1
    let storedAt: Date
    private enum CodingKeys: String, CodingKey, CaseIterable { case record, storedAt }
    init(record: OpaqueRelayRecordV1, storedAt: Date) { self.record = record; self.storedAt = realtimeDate(storedAt) }
    var isStructurallyValid: Bool { record.isStructurallyValid && realtimeTimestampIsValid(storedAt) }
    init(from decoder: Decoder) throws {
        try realtimeRequireExact(decoder, Set(CodingKeys.allCases.map(\.rawValue)))
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(record: try values.decode(OpaqueRelayRecordV1.self, forKey: .record), storedAt: try values.decode(Date.self, forKey: .storedAt))
        guard isStructurallyValid else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Stored opaque record is invalid")) }
    }
    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw EncodingError.invalidValue(self, .init(codingPath: encoder.codingPath, debugDescription: "Stored opaque record is invalid")) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(record, forKey: .record); try values.encode(storedAt, forKey: .storedAt)
    }
}

struct RealtimeRouteStateV1: Codable, Equatable {
    let appendDigest: Data; let readDigest: Data; let expiresAt: Date
    var nextSequence: UInt64; var retentionFloor: UInt64
    var records: [StoredOpaqueRecordV1]; var subscriptions: [String: Date]
    private enum CodingKeys: String, CodingKey, CaseIterable { case appendDigest, readDigest, expiresAt, nextSequence, retentionFloor, records, subscriptions }
    init(appendDigest: Data, readDigest: Data, expiresAt: Date, nextSequence: UInt64, retentionFloor: UInt64, records: [StoredOpaqueRecordV1], subscriptions: [String: Date]) { self.appendDigest = appendDigest; self.readDigest = readDigest; self.expiresAt = realtimeDate(expiresAt); self.nextSequence = nextSequence; self.retentionFloor = retentionFloor; self.records = records; self.subscriptions = subscriptions }
    init(from decoder: Decoder) throws {
        try realtimeRequireExact(decoder, Set(CodingKeys.allCases.map(\.rawValue)))
        let values = try decoder.container(keyedBy: CodingKeys.self)
        guard try values.nestedUnkeyedContainer(forKey: .records).count.map({ $0 <= RealtimeRelayLimitsV1.maximumRealtimeRecords }) == true,
              try values.nestedContainer(keyedBy: RealtimeCodingKey.self, forKey: .subscriptions).allKeys.count <= RealtimeRelayLimitsV1.maximumRealtimeSubscriptionsPerRoute else {
            throw DecodingError.dataCorruptedError(forKey: .records, in: values, debugDescription: "Realtime route state exceeds its current bounds")
        }
        self.init(appendDigest: try values.decode(Data.self, forKey: .appendDigest), readDigest: try values.decode(Data.self, forKey: .readDigest), expiresAt: try values.decode(Date.self, forKey: .expiresAt), nextSequence: try values.decode(UInt64.self, forKey: .nextSequence), retentionFloor: try values.decode(UInt64.self, forKey: .retentionFloor), records: try values.decode([StoredOpaqueRecordV1].self, forKey: .records), subscriptions: try values.decode([String: Date].self, forKey: .subscriptions))
        guard isStructurallyValid else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Realtime route state is invalid")) }
    }
    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw EncodingError.invalidValue(self, .init(codingPath: encoder.codingPath, debugDescription: "Realtime route state is invalid")) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(appendDigest, forKey: .appendDigest); try values.encode(readDigest, forKey: .readDigest); try values.encode(expiresAt, forKey: .expiresAt); try values.encode(nextSequence, forKey: .nextSequence); try values.encode(retentionFloor, forKey: .retentionFloor); try values.encode(records, forKey: .records); try values.encode(subscriptions, forKey: .subscriptions)
    }
}

struct SharedLogStateV1: Codable, Equatable {
    let appendDigest: Data; let readDigest: Data; let retentionSeconds: Int; let maxRecords: Int
    var nextSequence: UInt64; var retentionFloor: UInt64; var records: [StoredOpaqueRecordV1]
    private enum CodingKeys: String, CodingKey, CaseIterable { case appendDigest, readDigest, retentionSeconds, maxRecords, nextSequence, retentionFloor, records }
    init(appendDigest: Data, readDigest: Data, retentionSeconds: Int, maxRecords: Int, nextSequence: UInt64, retentionFloor: UInt64, records: [StoredOpaqueRecordV1]) { self.appendDigest = appendDigest; self.readDigest = readDigest; self.retentionSeconds = retentionSeconds; self.maxRecords = maxRecords; self.nextSequence = nextSequence; self.retentionFloor = retentionFloor; self.records = records }
    init(from decoder: Decoder) throws {
        try realtimeRequireExact(decoder, Set(CodingKeys.allCases.map(\.rawValue)))
        let values = try decoder.container(keyedBy: CodingKeys.self)
        guard try values.nestedUnkeyedContainer(forKey: .records).count.map({ $0 <= RealtimeRelayLimitsV1.maximumSharedLogRecords }) == true else { throw DecodingError.dataCorruptedError(forKey: .records, in: values, debugDescription: "Shared log state exceeds its current bound") }
        self.init(appendDigest: try values.decode(Data.self, forKey: .appendDigest), readDigest: try values.decode(Data.self, forKey: .readDigest), retentionSeconds: try values.decode(Int.self, forKey: .retentionSeconds), maxRecords: try values.decode(Int.self, forKey: .maxRecords), nextSequence: try values.decode(UInt64.self, forKey: .nextSequence), retentionFloor: try values.decode(UInt64.self, forKey: .retentionFloor), records: try values.decode([StoredOpaqueRecordV1].self, forKey: .records))
        guard isStructurallyValid else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Shared log state is invalid")) }
    }
    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw EncodingError.invalidValue(self, .init(codingPath: encoder.codingPath, debugDescription: "Shared log state is invalid")) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(appendDigest, forKey: .appendDigest); try values.encode(readDigest, forKey: .readDigest); try values.encode(retentionSeconds, forKey: .retentionSeconds); try values.encode(maxRecords, forKey: .maxRecords); try values.encode(nextSequence, forKey: .nextSequence); try values.encode(retentionFloor, forKey: .retentionFloor); try values.encode(records, forKey: .records)
    }
}

struct MediaBlobStateV1: Codable, Equatable {
    let capabilityDigest: Data; let chunkCount: Int; let ttlSeconds: Int?; let expiresAt: Date
    var chunks: [Int: Data]; var idempotency: [String: Data]
    private enum CodingKeys: String, CodingKey, CaseIterable { case capabilityDigest, chunkCount, ttlSeconds, expiresAt, chunks, idempotency }
    init(capabilityDigest: Data, chunkCount: Int, ttlSeconds: Int?, expiresAt: Date, chunks: [Int: Data], idempotency: [String: Data]) { self.capabilityDigest = capabilityDigest; self.chunkCount = chunkCount; self.ttlSeconds = ttlSeconds; self.expiresAt = realtimeDate(expiresAt); self.chunks = chunks; self.idempotency = idempotency }
    init(from decoder: Decoder) throws {
        let allowed = Set(CodingKeys.allCases.map(\.rawValue))
        try realtimeRequireAllowed(decoder, allowed: allowed, required: allowed.subtracting([CodingKeys.ttlSeconds.rawValue]))
        let values = try decoder.container(keyedBy: CodingKeys.self)
        guard try values.nestedContainer(keyedBy: RealtimeCodingKey.self, forKey: .chunks).allKeys.count <= RealtimeRelayLimitsV1.maximumMediaBlobChunks,
              try values.nestedContainer(keyedBy: RealtimeCodingKey.self, forKey: .idempotency).allKeys.count <= RealtimeRelayLimitsV1.maximumMediaBlobChunks else {
            throw DecodingError.dataCorruptedError(forKey: .chunks, in: values, debugDescription: "Media blob state exceeds its current bounds")
        }
        self.init(capabilityDigest: try values.decode(Data.self, forKey: .capabilityDigest), chunkCount: try values.decode(Int.self, forKey: .chunkCount), ttlSeconds: try values.decodeIfPresent(Int.self, forKey: .ttlSeconds), expiresAt: try values.decode(Date.self, forKey: .expiresAt), chunks: try values.decode([Int: Data].self, forKey: .chunks), idempotency: try values.decode([String: Data].self, forKey: .idempotency))
        guard isStructurallyValid else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Media blob state is invalid")) }
    }
    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw EncodingError.invalidValue(self, .init(codingPath: encoder.codingPath, debugDescription: "Media blob state is invalid")) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(capabilityDigest, forKey: .capabilityDigest); try values.encode(chunkCount, forKey: .chunkCount); try values.encodeIfPresent(ttlSeconds, forKey: .ttlSeconds); try values.encode(expiresAt, forKey: .expiresAt); try values.encode(chunks, forKey: .chunks); try values.encode(idempotency, forKey: .idempotency)
    }
}
public struct RealtimeRelayRuntimeStateV1: Codable, Equatable {
    var routes: [String: RealtimeRouteStateV1]
    var sharedLogs: [String: SharedLogStateV1]
    var mediaBlobs: [String: MediaBlobStateV1]
    public init() { routes = [:]; sharedLogs = [:]; mediaBlobs = [:] }

    private enum CodingKeys: String, CodingKey, CaseIterable { case routes, sharedLogs, mediaBlobs }

    public init(from decoder: Decoder) throws {
        try realtimeRequireExact(decoder, Set(CodingKeys.allCases.map(\.rawValue)))
        let values = try decoder.container(keyedBy: CodingKeys.self)
        guard try values.nestedContainer(keyedBy: RealtimeCodingKey.self, forKey: .routes).allKeys.count <= RealtimeRelayLimitsV1.maximumRealtimeRoutes,
              try values.nestedContainer(keyedBy: RealtimeCodingKey.self, forKey: .sharedLogs).allKeys.count <= RealtimeRelayLimitsV1.maximumSharedLogs,
              try values.nestedContainer(keyedBy: RealtimeCodingKey.self, forKey: .mediaBlobs).allKeys.count <= RealtimeRelayLimitsV1.maximumMediaBlobs else {
            throw DecodingError.dataCorruptedError(forKey: .routes, in: values, debugDescription: "Realtime runtime state exceeds its current bounds")
        }
        routes = try values.decode([String: RealtimeRouteStateV1].self, forKey: .routes)
        sharedLogs = try values.decode([String: SharedLogStateV1].self, forKey: .sharedLogs)
        mediaBlobs = try values.decode([String: MediaBlobStateV1].self, forKey: .mediaBlobs)
        guard isStructurallyValid else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Realtime runtime state is invalid")) }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else { throw EncodingError.invalidValue(self, .init(codingPath: encoder.codingPath, debugDescription: "Realtime runtime state is invalid")) }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(routes, forKey: .routes); try values.encode(sharedLogs, forKey: .sharedLogs); try values.encode(mediaBlobs, forKey: .mediaBlobs)
    }

    var isStructurallyValid: Bool {
        routes.count <= RealtimeRelayLimitsV1.maximumRealtimeRoutes
            && sharedLogs.count <= RealtimeRelayLimitsV1.maximumSharedLogs
            && mediaBlobs.count <= RealtimeRelayLimitsV1.maximumMediaBlobs
            && routes.allSatisfy { realtimeDigestKeyIsCanonical($0.key) && $0.value.isStructurallyValid }
            && sharedLogs.allSatisfy { realtimeDigestKeyIsCanonical($0.key) && $0.value.isStructurallyValid }
            && mediaBlobs.allSatisfy { key, blob in
                UUID(uuidString: key)?.uuidString.lowercased() == key && blob.isStructurallyValid
            }
    }
}

private func realtimeDigestKeyIsCanonical(_ key: String) -> Bool {
    guard let digest = Data(base64Encoded: key) else { return false }
    return digest.count == SHA256.byteCount && digest.base64EncodedString() == key
}

private func realtimeStoredRecordsAreValid(
    _ records: [StoredOpaqueRecordV1],
    nextSequence: UInt64,
    retentionFloor: UInt64,
    maximumCount: Int
) -> Bool {
    guard nextSequence > 0,
          retentionFloor > 0,
          retentionFloor <= nextSequence,
          records.count <= maximumCount,
          UInt64(records.count) == nextSequence - retentionFloor else {
        return false
    }
    var expected = retentionFloor
    var recordIDs = Set<UUID>()
    for stored in records {
        guard stored.record.isStructurallyValid,
              stored.record.sequence == expected,
              realtimeTimestampIsValid(stored.storedAt),
              recordIDs.insert(stored.record.recordID).inserted else {
            return false
        }
        expected += 1
    }
    return expected == nextSequence
}

private extension RealtimeRouteStateV1 {
    var isStructurallyValid: Bool {
        appendDigest.count == SHA256.byteCount
            && readDigest.count == SHA256.byteCount
            && realtimeTimestampIsValid(expiresAt)
            && realtimeStoredRecordsAreValid(
                records,
                nextSequence: nextSequence,
                retentionFloor: retentionFloor,
                maximumCount: RealtimeRelayLimitsV1.maximumRealtimeRecords
            )
            && subscriptions.count <= RealtimeRelayLimitsV1.maximumRealtimeSubscriptionsPerRoute
            && subscriptions.allSatisfy { key, expiry in
                realtimeDigestKeyIsCanonical(key)
                    && realtimeTimestampIsValid(expiry)
                    && expiry == expiresAt
            }
    }
}

private extension SharedLogStateV1 {
    var isStructurallyValid: Bool {
        appendDigest.count == SHA256.byteCount
            && readDigest.count == SHA256.byteCount
            && (60...Int(RealtimeRelayLimitsV1.maximumSharedLogLifetime)).contains(retentionSeconds)
            && (1...RealtimeRelayLimitsV1.maximumSharedLogRecords).contains(maxRecords)
            && realtimeStoredRecordsAreValid(
                records,
                nextSequence: nextSequence,
                retentionFloor: retentionFloor,
                maximumCount: maxRecords
            )
    }
}

private extension MediaBlobStateV1 {
    var isStructurallyValid: Bool {
        guard capabilityDigest.count == SHA256.byteCount,
              (1...RealtimeRelayLimitsV1.maximumMediaBlobChunks).contains(chunkCount),
              ttlSeconds.map({
                  (RealtimeRelayLimitsV1.minimumMediaRetentionSeconds
                    ... RealtimeRelayLimitsV1.maximumMediaRetentionSeconds).contains($0)
              }) ?? true,
              realtimeTimestampIsValid(expiresAt),
              chunks.count <= chunkCount,
              idempotency.count <= RealtimeRelayLimitsV1.maximumMediaBlobChunks,
              chunks.allSatisfy({ index, payload in
                  (0..<chunkCount).contains(index)
                      && !payload.isEmpty
                      && payload.count <= RealtimeRelayLimitsV1.maximumMediaBlobChunkBytes
              }),
              idempotency.allSatisfy({ key, value in
                  realtimeDigestKeyIsCanonical(key) && value.count == SHA256.byteCount
              }) else {
            return false
        }
        return chunks.values.reduce(0) { $0 + $1.count }
            <= RealtimeRelayLimitsV1.maximumMediaBlobBytes
    }
}

struct RealtimeRelayRuntimeV1 {
    var state = RealtimeRelayRuntimeStateV1()
    private var presence: [String: (scopeDigest: Data, scopeCapabilityDigest: Data, leaseDigest: Data, payload: Data, expiresAt: Date)] = [:]

    mutating func createRoute(_ request: RealtimeRouteCreateRequestV1, now: Date = Date()) throws -> RealtimeRouteCreatedV1 {
        guard request.isStructurallyValid, request.expiresAt > now, request.expiresAt.timeIntervalSince(now) <= RealtimeRelayLimitsV1.maximumRealtimeLifetime else { throw RealtimeRelayRuntimeError.invalidRequest }
        let key = digest(request.routeCapability, domain: "realtime-route").base64EncodedString()
        if let existing = state.routes[key] {
            guard existing.appendDigest == digest(request.appendCapability, domain: "append"), existing.readDigest == digest(request.readCapability, domain: "read"), existing.expiresAt == request.expiresAt else { throw RealtimeRelayRuntimeError.conflict }
        } else {
            guard state.routes.count < 4_096 else { throw RealtimeRelayRuntimeError.capacity }
            state.routes[key] = RealtimeRouteStateV1(appendDigest: digest(request.appendCapability, domain: "append"), readDigest: digest(request.readCapability, domain: "read"), expiresAt: request.expiresAt, nextSequence: 1, retentionFloor: 1, records: [], subscriptions: [:])
        }
        return RealtimeRouteCreatedV1(routeCapability: request.routeCapability, appendCapability: request.appendCapability, readCapability: request.readCapability, expiresAt: request.expiresAt)
    }

    mutating func appendRoute(_ request: RealtimeRouteAppendRequestV1, now: Date = Date()) throws -> RealtimeRouteAppendReceiptV1 {
        guard request.isStructurallyValid else { throw RealtimeRelayRuntimeError.invalidRequest }
        let key = digest(request.routeCapability, domain: "realtime-route").base64EncodedString()
        guard var route = state.routes[key], route.expiresAt > now else { throw RealtimeRelayRuntimeError.expired }
        guard route.appendDigest == digest(request.appendCapability, domain: "append") else { throw RealtimeRelayRuntimeError.unauthorized }
        if let existing = route.records.first(where: { $0.record.recordID == request.recordID }) { guard existing.record.payload == request.payload else { throw RealtimeRelayRuntimeError.conflict }; return RealtimeRouteAppendReceiptV1(sequence: existing.record.sequence, recordID: request.recordID) }
        guard route.records.count < RealtimeRelayLimitsV1.maximumRealtimeRecords,
              route.nextSequence < UInt64.max else {
            throw RealtimeRelayRuntimeError.capacity
        }
        let record = OpaqueRelayRecordV1(sequence: route.nextSequence, recordID: request.recordID, payload: request.payload)
        route.nextSequence += 1; route.records.append(StoredOpaqueRecordV1(record: record, storedAt: realtimeDate(now))); state.routes[key] = route
        return RealtimeRouteAppendReceiptV1(sequence: record.sequence, recordID: record.recordID)
    }

    mutating func subscribe(_ request: RealtimeRouteSubscribeRequestV1, now: Date = Date()) throws -> RealtimeRouteSubscriptionV1 {
        let key = digest(request.routeCapability, domain: "realtime-route").base64EncodedString()
        guard var route = state.routes[key], route.expiresAt > now, OpaqueCapabilityV1.isValid(request.readCapability), route.readDigest == digest(request.readCapability, domain: "read") else { throw RealtimeRelayRuntimeError.unauthorized }
        guard request.afterSequence <= route.nextSequence - 1 else { throw RealtimeRelayRuntimeError.invalidCursor }
        guard route.subscriptions.count < RealtimeRelayLimitsV1.maximumRealtimeSubscriptionsPerRoute else { throw RealtimeRelayRuntimeError.capacity }
        let cap = OpaqueCapabilityV1.generate()
        let subscriptionKey = digest(cap, domain: "realtime-subscription").base64EncodedString()
        route.subscriptions[subscriptionKey] = route.expiresAt
        state.routes[key] = route
        return RealtimeRouteSubscriptionV1(subscriptionCapability: cap, routeCapability: request.routeCapability, nextSequence: request.afterSequence, expiresAt: route.expiresAt)
    }

    mutating func syncRoute(_ request: RealtimeRouteSyncRequestV1, now: Date = Date()) throws -> OpaqueRelaySyncBatchV1 {
        let key = digest(request.routeCapability, domain: "realtime-route").base64EncodedString()
        let subscriptionKey = digest(request.subscriptionCapability, domain: "realtime-subscription").base64EncodedString()
        guard OpaqueCapabilityV1.isValid(request.routeCapability),
              OpaqueCapabilityV1.isValid(request.subscriptionCapability),
              let route = state.routes[key],
              route.expiresAt > now,
              request.maxRecords > 0,
              request.maxRecords <= RealtimeRelayLimitsV1.maximumRecordsPerPage,
              let subscriptionExpiry = route.subscriptions[subscriptionKey],
              subscriptionExpiry > now else {
            throw RealtimeRelayRuntimeError.unauthorized
        }
        let high = route.nextSequence - 1
        guard request.afterSequence <= high,
              request.afterSequence >= route.retentionFloor - 1 else {
            throw RealtimeRelayRuntimeError.invalidCursor
        }
        let selected = route.records.filter { $0.record.sequence > request.afterSequence }.prefix(request.maxRecords).map { $0.record }
        let next = selected.last?.sequence ?? request.afterSequence
        return OpaqueRelaySyncBatchV1(records: selected, nextSequence: next, highWatermark: high, retentionFloor: route.retentionFloor, hasMore: next < high)
    }

    mutating func unsubscribe(_ request: RealtimeRouteUnsubscribeRequestV1, now: Date = Date()) throws {
        let key = digest(request.routeCapability, domain: "realtime-route").base64EncodedString()
        let subscriptionKey = digest(request.subscriptionCapability, domain: "realtime-subscription").base64EncodedString()
        guard OpaqueCapabilityV1.isValid(request.routeCapability),
              OpaqueCapabilityV1.isValid(request.subscriptionCapability),
              var route = state.routes[key],
              route.expiresAt > now,
              route.subscriptions.removeValue(forKey: subscriptionKey) != nil else {
            throw RealtimeRelayRuntimeError.unauthorized
        }
        state.routes[key] = route
    }

    mutating func createSharedLog(_ request: SharedLogCreateRequestV1, now: Date = Date()) throws -> SharedLogCreatedV1 {
        guard OpaqueCapabilityV1.isValid(request.logCapability), OpaqueCapabilityV1.isValid(request.appendCapability), OpaqueCapabilityV1.isValid(request.readCapability), Set([request.logCapability, request.appendCapability, request.readCapability]).count == 3, (60...Int(RealtimeRelayLimitsV1.maximumSharedLogLifetime)).contains(request.retentionSeconds), (1...RealtimeRelayLimitsV1.maximumSharedLogRecords).contains(request.maxRecords) else { throw RealtimeRelayRuntimeError.invalidRequest }
        let key = digest(request.logCapability, domain: "shared-log").base64EncodedString()
        if let existing = state.sharedLogs[key] {
            guard existing.appendDigest == digest(request.appendCapability, domain: "append"),
                  existing.readDigest == digest(request.readCapability, domain: "read"),
                  existing.retentionSeconds == request.retentionSeconds,
                  existing.maxRecords == request.maxRecords else {
                throw RealtimeRelayRuntimeError.conflict
            }
        } else {
            guard state.sharedLogs.count < RealtimeRelayLimitsV1.maximumSharedLogs else { throw RealtimeRelayRuntimeError.capacity }
            state.sharedLogs[key] = SharedLogStateV1(appendDigest: digest(request.appendCapability, domain: "append"), readDigest: digest(request.readCapability, domain: "read"), retentionSeconds: request.retentionSeconds, maxRecords: request.maxRecords, nextSequence: 1, retentionFloor: 1, records: [])
        }
        return SharedLogCreatedV1(logCapability: request.logCapability, appendCapability: request.appendCapability, readCapability: request.readCapability, retentionSeconds: request.retentionSeconds)
    }

    mutating func appendSharedLog(_ request: SharedLogAppendRequestV1, now: Date = Date()) throws -> SharedLogAppendReceiptV1 {
        guard realtimeValidPayload(request.payload) else { throw RealtimeRelayRuntimeError.invalidRequest }; let key = digest(request.logCapability, domain: "shared-log").base64EncodedString(); guard var log = state.sharedLogs[key] else { throw RealtimeRelayRuntimeError.expired }; guard log.appendDigest == digest(request.appendCapability, domain: "append") else { throw RealtimeRelayRuntimeError.unauthorized }; pruneSharedLog(&log, now: now); if let existing = log.records.first(where: { $0.record.recordID == request.recordID }) { guard existing.record.payload == request.payload else { throw RealtimeRelayRuntimeError.conflict }; return SharedLogAppendReceiptV1(sequence: existing.record.sequence, recordID: request.recordID) }; guard log.records.count < log.maxRecords, log.nextSequence < UInt64.max else { throw RealtimeRelayRuntimeError.capacity }; let record = OpaqueRelayRecordV1(sequence: log.nextSequence, recordID: request.recordID, payload: request.payload); log.nextSequence += 1; log.records.append(StoredOpaqueRecordV1(record: record, storedAt: realtimeDate(now))); state.sharedLogs[key] = log; return SharedLogAppendReceiptV1(sequence: record.sequence, recordID: record.recordID)
    }

    mutating func syncSharedLog(_ request: SharedLogSyncRequestV1, now: Date = Date()) throws -> OpaqueRelaySyncBatchV1 {
        let key = digest(request.logCapability, domain: "shared-log").base64EncodedString(); guard var log = state.sharedLogs[key], request.maxRecords > 0, request.maxRecords <= RealtimeRelayLimitsV1.maximumRecordsPerPage, log.readDigest == digest(request.readCapability, domain: "read") else { throw RealtimeRelayRuntimeError.unauthorized }; pruneSharedLog(&log, now: now); let high = log.nextSequence - 1; guard request.afterSequence <= high, request.afterSequence >= log.retentionFloor - 1 else { throw RealtimeRelayRuntimeError.invalidCursor }; let selected = log.records.filter { $0.record.sequence > request.afterSequence }.prefix(request.maxRecords).map { $0.record }; let next = selected.last?.sequence ?? request.afterSequence; state.sharedLogs[key] = log; return OpaqueRelaySyncBatchV1(records: selected, nextSequence: next, highWatermark: high, retentionFloor: log.retentionFloor, hasMore: next < high)
    }

    mutating func acquirePresence(_ request: PresenceLeaseAcquireRequestV1, now: Date = Date()) throws -> PresenceLeaseV1 { try validatePresence(request.scope, request.scopeCapability, request.leaseID, request.leaseCapability, request.payload, request.ttlSeconds); prunePresence(now: now); let key = request.leaseID.base64EncodedString(); guard presence[key] == nil else { throw RealtimeRelayRuntimeError.conflict }; guard presence.count < RealtimeRelayLimitsV1.maximumPresenceLeases else { throw RealtimeRelayRuntimeError.capacity }; let expiry = realtimeDate(now.addingTimeInterval(TimeInterval(request.ttlSeconds))); presence[key] = (digest(request.scope, domain: "scope"), digest(request.scopeCapability, domain: "scope-capability"), digest(request.leaseCapability, domain: "lease"), request.payload, expiry); return PresenceLeaseV1(leaseID: request.leaseID, payload: request.payload, expiresAt: expiry) }
    mutating func renewPresence(_ request: PresenceLeaseRenewRequestV1, now: Date = Date()) throws -> PresenceLeaseV1 { try validatePresence(request.scope, request.scopeCapability, request.leaseID, request.leaseCapability, request.payload, request.ttlSeconds); prunePresence(now: now); let key = request.leaseID.base64EncodedString(); guard let current = presence[key], current.scopeDigest == digest(request.scope, domain: "scope"), current.scopeCapabilityDigest == digest(request.scopeCapability, domain: "scope-capability"), current.leaseDigest == digest(request.leaseCapability, domain: "lease") else { throw RealtimeRelayRuntimeError.unauthorized }; let expiry = realtimeDate(now.addingTimeInterval(TimeInterval(request.ttlSeconds))); presence[key] = (current.scopeDigest, current.scopeCapabilityDigest, current.leaseDigest, request.payload, expiry); return PresenceLeaseV1(leaseID: request.leaseID, payload: request.payload, expiresAt: expiry) }
    mutating func releasePresence(_ request: PresenceLeaseReleaseRequestV1, now: Date = Date()) throws { guard OpaqueCapabilityV1.isValid(request.scopeCapability) else { throw RealtimeRelayRuntimeError.invalidRequest }; prunePresence(now: now); let key = request.leaseID.base64EncodedString(); guard let current = presence[key], current.scopeDigest == digest(request.scope, domain: "scope"), current.scopeCapabilityDigest == digest(request.scopeCapability, domain: "scope-capability"), current.leaseDigest == digest(request.leaseCapability, domain: "lease") else { throw RealtimeRelayRuntimeError.unauthorized }; presence.removeValue(forKey: key) }
    mutating func listPresence(_ request: PresenceLeaseListRequestV1, now: Date = Date()) throws -> [PresenceLeaseV1] { guard OpaqueCapabilityV1.isValid(request.scopeCapability) else { throw RealtimeRelayRuntimeError.invalidRequest }; prunePresence(now: now); let scope = digest(request.scope, domain: "scope"); let scopeCapability = digest(request.scopeCapability, domain: "scope-capability"); return presence.compactMap { key, value in value.scopeDigest == scope && value.scopeCapabilityDigest == scopeCapability ? PresenceLeaseV1(leaseID: Data(base64Encoded: key) ?? Data(), payload: value.payload, expiresAt: value.expiresAt) : nil }.filter { $0.expiresAt > now } }

    mutating func createMediaBlob(_ request: MediaBlobCreateRequestV1, now: Date = Date()) throws -> MediaBlobCreatedV1 { guard OpaqueCapabilityV1.isValid(request.blobCapability), (1...RealtimeRelayLimitsV1.maximumMediaBlobChunks).contains(request.chunkCount), (RealtimeRelayLimitsV1.minimumMediaRetentionSeconds...RealtimeRelayLimitsV1.maximumMediaRetentionSeconds).contains(request.ttlSeconds) else { throw RealtimeRelayRuntimeError.invalidRequest }; let key = request.blobID.uuidString.lowercased(); let expiry: Date; if let existing = state.mediaBlobs[key] { guard existing.capabilityDigest == digest(request.blobCapability, domain: "media-blob"), existing.chunkCount == request.chunkCount, existing.ttlSeconds == request.ttlSeconds else { throw RealtimeRelayRuntimeError.conflict }; expiry = existing.expiresAt } else { guard state.mediaBlobs.count < RealtimeRelayLimitsV1.maximumMediaBlobs else { throw RealtimeRelayRuntimeError.capacity }; expiry = realtimeDate(now.addingTimeInterval(TimeInterval(request.ttlSeconds))); state.mediaBlobs[key] = MediaBlobStateV1(capabilityDigest: digest(request.blobCapability, domain: "media-blob"), chunkCount: request.chunkCount, ttlSeconds: request.ttlSeconds, expiresAt: expiry, chunks: [:], idempotency: [:]) }; return MediaBlobCreatedV1(blobID: request.blobID, blobCapability: request.blobCapability, chunkCount: request.chunkCount, expiresAt: expiry) }
    mutating func uploadMediaBlob(_ request: MediaBlobUploadRequestV1, now: Date = Date()) throws -> MediaBlobChunkV1 { guard request.payload.count > 0, request.payload.count <= RealtimeRelayLimitsV1.maximumMediaBlobChunkBytes, request.idempotencyKey.count == 32, (0..<RealtimeRelayLimitsV1.maximumMediaBlobChunks).contains(request.chunkIndex) else { throw RealtimeRelayRuntimeError.invalidRequest }; let key = request.blobID.uuidString.lowercased(); guard var blob = state.mediaBlobs[key], blob.expiresAt > now, blob.capabilityDigest == digest(request.blobCapability, domain: "media-blob"), request.chunkIndex < blob.chunkCount else { throw RealtimeRelayRuntimeError.unauthorized }; let id = request.idempotencyKey.base64EncodedString(); let body = mediaUploadDigest(chunkIndex: request.chunkIndex, payload: request.payload); if let existing = blob.idempotency[id] { let legacyBody = Data(SHA256.hash(data: request.payload)); guard (existing == body || existing == legacyBody), blob.chunks[request.chunkIndex] == request.payload else { throw RealtimeRelayRuntimeError.conflict }; if existing != body { blob.idempotency[id] = body; state.mediaBlobs[key] = blob }; return MediaBlobChunkV1(blobID: request.blobID, chunkIndex: request.chunkIndex, payload: request.payload) }; guard blob.chunks[request.chunkIndex] == nil else { throw RealtimeRelayRuntimeError.conflict }; let total = blob.chunks.values.reduce(0) { $0 + $1.count }; guard total + request.payload.count <= RealtimeRelayLimitsV1.maximumMediaBlobBytes else { throw RealtimeRelayRuntimeError.capacity }; blob.chunks[request.chunkIndex] = request.payload; blob.idempotency[id] = body; state.mediaBlobs[key] = blob; return MediaBlobChunkV1(blobID: request.blobID, chunkIndex: request.chunkIndex, payload: request.payload) }
    mutating func fetchMediaBlob(_ request: MediaBlobFetchRequestV1, now: Date = Date()) throws -> MediaBlobChunkV1 { let key = request.blobID.uuidString.lowercased(); guard let blob = state.mediaBlobs[key], blob.expiresAt > now, blob.capabilityDigest == digest(request.blobCapability, domain: "media-blob"), (0..<blob.chunkCount).contains(request.chunkIndex), let payload = blob.chunks[request.chunkIndex] else { throw RealtimeRelayRuntimeError.unavailable }; return MediaBlobChunkV1(blobID: request.blobID, chunkIndex: request.chunkIndex, payload: payload) }
    mutating func releaseMediaBlob(_ request: MediaBlobReleaseRequestV1) throws { let key = request.blobID.uuidString.lowercased(); guard let blob = state.mediaBlobs[key], blob.capabilityDigest == digest(request.blobCapability, domain: "media-blob") else { throw RealtimeRelayRuntimeError.unauthorized }; state.mediaBlobs.removeValue(forKey: key) }

    mutating func prune(now: Date = Date()) { state.routes = state.routes.filter { $0.value.expiresAt > now }; state.mediaBlobs = state.mediaBlobs.filter { $0.value.expiresAt > now }; for key in state.sharedLogs.keys { if var log = state.sharedLogs[key] { pruneSharedLog(&log, now: now); state.sharedLogs[key] = log } }; prunePresence(now: now) }
    private mutating func prunePresence(now: Date) { presence = presence.filter { $0.value.expiresAt > now } }
    private func validatePresence(_ scope: Data, _ scopeCapability: Data, _ leaseID: Data, _ leaseCapability: Data, _ payload: Data, _ ttl: Int) throws { guard !scope.isEmpty && scope.count <= 64, OpaqueCapabilityV1.isValid(scopeCapability), leaseID.count == 16 && leaseID.contains(where: { $0 != 0 }), OpaqueCapabilityV1.isValid(leaseCapability), payload.count <= RealtimeRelayLimitsV1.maximumPresencePayloadBytes, (RealtimeRelayLimitsV1.minimumPresenceLeaseSeconds...RealtimeRelayLimitsV1.maximumPresenceLeaseSeconds).contains(ttl) else { throw RealtimeRelayRuntimeError.invalidRequest } }
    private func pruneSharedLog(_ log: inout SharedLogStateV1, now: Date) { let cutoff = now.addingTimeInterval(-TimeInterval(log.retentionSeconds)); let retained = Array(log.records.filter { $0.storedAt >= cutoff }.suffix(log.maxRecords)); log.retentionFloor = retained.first?.record.sequence ?? log.nextSequence; log.records = retained }
    private func mediaUploadDigest(chunkIndex: Int, payload: Data) -> Data {
        var index = UInt32(chunkIndex).bigEndian
        let indexData = withUnsafeBytes(of: &index) { Data($0) }
        return Data(SHA256.hash(data: Data("org.noctweave.media-upload.v1".utf8) + indexData + payload))
    }
    private func digest(_ value: Data, domain: String) -> Data { Data(SHA256.hash(data: Data("org.noctweave.\(domain).v1".utf8) + value)) }
}

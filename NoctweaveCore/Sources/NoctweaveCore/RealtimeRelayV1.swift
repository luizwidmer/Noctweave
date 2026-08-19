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

private func realtimeDate(_ date: Date) -> Date {
    Date(timeIntervalSince1970: floor(date.timeIntervalSince1970))
}

private func realtimeTimestampIsValid(_ date: Date) -> Bool {
    let seconds = date.timeIntervalSince1970
    return seconds.isFinite && seconds >= 0 && floor(seconds) == seconds
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
        records.count <= RealtimeRelayLimitsV1.maximumRecordsPerPage
            && records.allSatisfy(\.isStructurallyValid)
            && records.map(\.sequence) == records.map(\.sequence).sorted()
            && Set(records.map(\.sequence)).count == records.count
            && nextSequence <= highWatermark
            && retentionFloor <= highWatermark + 1
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
public struct PresenceLeaseV1: Codable, Equatable { public let leaseID: Data; public let payload: Data; public let expiresAt: Date; public init(leaseID: Data, payload: Data, expiresAt: Date) { self.leaseID = leaseID; self.payload = payload; self.expiresAt = realtimeDate(expiresAt) } }

public struct MediaBlobCreateRequestV1: Codable, Equatable { public let blobID: UUID; public let blobCapability: Data; public let chunkCount: Int; public let ttlSeconds: Int; public init(blobID: UUID, blobCapability: Data, chunkCount: Int, ttlSeconds: Int = 86_400) { self.blobID = blobID; self.blobCapability = blobCapability; self.chunkCount = chunkCount; self.ttlSeconds = ttlSeconds } }
public struct MediaBlobCreatedV1: Codable, Equatable { public let blobID: UUID; public let blobCapability: Data; public let chunkCount: Int; public let expiresAt: Date; public init(blobID: UUID, blobCapability: Data, chunkCount: Int, expiresAt: Date) { self.blobID = blobID; self.blobCapability = blobCapability; self.chunkCount = chunkCount; self.expiresAt = realtimeDate(expiresAt) } }
public struct MediaBlobUploadRequestV1: Codable, Equatable { public let blobID: UUID; public let blobCapability: Data; public let chunkIndex: Int; public let payload: Data; public let idempotencyKey: Data; public init(blobID: UUID, blobCapability: Data, chunkIndex: Int, payload: Data, idempotencyKey: Data) { self.blobID = blobID; self.blobCapability = blobCapability; self.chunkIndex = chunkIndex; self.payload = payload; self.idempotencyKey = idempotencyKey } }
public struct MediaBlobFetchRequestV1: Codable, Equatable { public let blobID: UUID; public let blobCapability: Data; public let chunkIndex: Int; public init(blobID: UUID, blobCapability: Data, chunkIndex: Int) { self.blobID = blobID; self.blobCapability = blobCapability; self.chunkIndex = chunkIndex } }
public struct MediaBlobReleaseRequestV1: Codable, Equatable { public let blobID: UUID; public let blobCapability: Data; public init(blobID: UUID, blobCapability: Data) { self.blobID = blobID; self.blobCapability = blobCapability } }
public struct MediaBlobChunkV1: Codable, Equatable { public let blobID: UUID; public let chunkIndex: Int; public let payload: Data; public init(blobID: UUID, chunkIndex: Int, payload: Data) { self.blobID = blobID; self.chunkIndex = chunkIndex; self.payload = payload } }

struct StoredOpaqueRecordV1: Codable, Equatable { let record: OpaqueRelayRecordV1; let storedAt: Date }
struct RealtimeRouteStateV1: Codable, Equatable { let appendDigest: Data; let readDigest: Data; let expiresAt: Date; var nextSequence: UInt64; var retentionFloor: UInt64; var records: [StoredOpaqueRecordV1]; var subscriptions: [String: Date] }
struct SharedLogStateV1: Codable, Equatable { let appendDigest: Data; let readDigest: Data; let retentionSeconds: Int; let maxRecords: Int; var nextSequence: UInt64; var retentionFloor: UInt64; var records: [StoredOpaqueRecordV1] }
struct MediaBlobStateV1: Codable, Equatable { let capabilityDigest: Data; let chunkCount: Int; let expiresAt: Date; var chunks: [Int: Data]; var idempotency: [String: Data] }
public struct RealtimeRelayRuntimeStateV1: Codable, Equatable {
    var routes: [String: RealtimeRouteStateV1]
    var sharedLogs: [String: SharedLogStateV1]
    var mediaBlobs: [String: MediaBlobStateV1]
    public init() { routes = [:]; sharedLogs = [:]; mediaBlobs = [:] }
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
        guard route.records.count < RealtimeRelayLimitsV1.maximumRealtimeRecords else { throw RealtimeRelayRuntimeError.capacity }
        let record = OpaqueRelayRecordV1(sequence: route.nextSequence, recordID: request.recordID, payload: request.payload)
        route.nextSequence += 1; route.records.append(StoredOpaqueRecordV1(record: record, storedAt: realtimeDate(now))); state.routes[key] = route
        return RealtimeRouteAppendReceiptV1(sequence: record.sequence, recordID: record.recordID)
    }

    mutating func subscribe(_ request: RealtimeRouteSubscribeRequestV1, now: Date = Date()) throws -> RealtimeRouteSubscriptionV1 {
        let key = digest(request.routeCapability, domain: "realtime-route").base64EncodedString()
        guard var route = state.routes[key], route.expiresAt > now, OpaqueCapabilityV1.isValid(request.readCapability), route.readDigest == digest(request.readCapability, domain: "read") else { throw RealtimeRelayRuntimeError.unauthorized }
        guard request.afterSequence <= route.nextSequence - 1 else { throw RealtimeRelayRuntimeError.invalidCursor }
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
        guard request.afterSequence + 1 >= route.retentionFloor else { throw RealtimeRelayRuntimeError.invalidCursor }
        let selected = route.records.filter { $0.record.sequence > request.afterSequence }.prefix(request.maxRecords).map { $0.record }
        let next = selected.last?.sequence ?? request.afterSequence; let high = route.nextSequence - 1
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
        if let existing = state.sharedLogs[key] { guard existing.appendDigest == digest(request.appendCapability, domain: "append"), existing.readDigest == digest(request.readCapability, domain: "read") else { throw RealtimeRelayRuntimeError.conflict } } else { state.sharedLogs[key] = SharedLogStateV1(appendDigest: digest(request.appendCapability, domain: "append"), readDigest: digest(request.readCapability, domain: "read"), retentionSeconds: request.retentionSeconds, maxRecords: request.maxRecords, nextSequence: 1, retentionFloor: 1, records: []) }
        return SharedLogCreatedV1(logCapability: request.logCapability, appendCapability: request.appendCapability, readCapability: request.readCapability, retentionSeconds: request.retentionSeconds)
    }

    mutating func appendSharedLog(_ request: SharedLogAppendRequestV1, now: Date = Date()) throws -> SharedLogAppendReceiptV1 {
        guard realtimeValidPayload(request.payload) else { throw RealtimeRelayRuntimeError.invalidRequest }; let key = digest(request.logCapability, domain: "shared-log").base64EncodedString(); guard var log = state.sharedLogs[key] else { throw RealtimeRelayRuntimeError.expired }; guard log.appendDigest == digest(request.appendCapability, domain: "append") else { throw RealtimeRelayRuntimeError.unauthorized }; if let existing = log.records.first(where: { $0.record.recordID == request.recordID }) { guard existing.record.payload == request.payload else { throw RealtimeRelayRuntimeError.conflict }; return SharedLogAppendReceiptV1(sequence: existing.record.sequence, recordID: request.recordID) }; pruneSharedLog(&log, now: now); guard log.records.count < log.maxRecords else { throw RealtimeRelayRuntimeError.capacity }; let record = OpaqueRelayRecordV1(sequence: log.nextSequence, recordID: request.recordID, payload: request.payload); log.nextSequence += 1; log.records.append(StoredOpaqueRecordV1(record: record, storedAt: realtimeDate(now))); state.sharedLogs[key] = log; return SharedLogAppendReceiptV1(sequence: record.sequence, recordID: record.recordID)
    }

    mutating func syncSharedLog(_ request: SharedLogSyncRequestV1, now: Date = Date()) throws -> OpaqueRelaySyncBatchV1 {
        let key = digest(request.logCapability, domain: "shared-log").base64EncodedString(); guard var log = state.sharedLogs[key], request.maxRecords > 0, request.maxRecords <= RealtimeRelayLimitsV1.maximumRecordsPerPage, log.readDigest == digest(request.readCapability, domain: "read") else { throw RealtimeRelayRuntimeError.unauthorized }; pruneSharedLog(&log, now: now); guard request.afterSequence + 1 >= log.retentionFloor else { throw RealtimeRelayRuntimeError.invalidCursor }; let selected = log.records.filter { $0.record.sequence > request.afterSequence }.prefix(request.maxRecords).map { $0.record }; let next = selected.last?.sequence ?? request.afterSequence; let high = log.nextSequence - 1; state.sharedLogs[key] = log; return OpaqueRelaySyncBatchV1(records: selected, nextSequence: next, highWatermark: high, retentionFloor: log.retentionFloor, hasMore: next < high)
    }

    mutating func acquirePresence(_ request: PresenceLeaseAcquireRequestV1, now: Date = Date()) throws -> PresenceLeaseV1 { try validatePresence(request.scope, request.scopeCapability, request.leaseID, request.leaseCapability, request.payload, request.ttlSeconds); prunePresence(now: now); let key = request.leaseID.base64EncodedString(); guard presence[key] == nil else { throw RealtimeRelayRuntimeError.conflict }; guard presence.count < RealtimeRelayLimitsV1.maximumPresenceLeases else { throw RealtimeRelayRuntimeError.capacity }; let expiry = realtimeDate(now.addingTimeInterval(TimeInterval(request.ttlSeconds))); presence[key] = (digest(request.scope, domain: "scope"), digest(request.scopeCapability, domain: "scope-capability"), digest(request.leaseCapability, domain: "lease"), request.payload, expiry); return PresenceLeaseV1(leaseID: request.leaseID, payload: request.payload, expiresAt: expiry) }
    mutating func renewPresence(_ request: PresenceLeaseRenewRequestV1, now: Date = Date()) throws -> PresenceLeaseV1 { try validatePresence(request.scope, request.scopeCapability, request.leaseID, request.leaseCapability, request.payload, request.ttlSeconds); prunePresence(now: now); let key = request.leaseID.base64EncodedString(); guard let current = presence[key], current.scopeDigest == digest(request.scope, domain: "scope"), current.scopeCapabilityDigest == digest(request.scopeCapability, domain: "scope-capability"), current.leaseDigest == digest(request.leaseCapability, domain: "lease") else { throw RealtimeRelayRuntimeError.unauthorized }; let expiry = realtimeDate(now.addingTimeInterval(TimeInterval(request.ttlSeconds))); presence[key] = (current.scopeDigest, current.scopeCapabilityDigest, current.leaseDigest, request.payload, expiry); return PresenceLeaseV1(leaseID: request.leaseID, payload: request.payload, expiresAt: expiry) }
    mutating func releasePresence(_ request: PresenceLeaseReleaseRequestV1, now: Date = Date()) throws { guard OpaqueCapabilityV1.isValid(request.scopeCapability) else { throw RealtimeRelayRuntimeError.invalidRequest }; prunePresence(now: now); let key = request.leaseID.base64EncodedString(); guard let current = presence[key], current.scopeDigest == digest(request.scope, domain: "scope"), current.scopeCapabilityDigest == digest(request.scopeCapability, domain: "scope-capability"), current.leaseDigest == digest(request.leaseCapability, domain: "lease") else { throw RealtimeRelayRuntimeError.unauthorized }; presence.removeValue(forKey: key) }
    mutating func listPresence(_ request: PresenceLeaseListRequestV1, now: Date = Date()) throws -> [PresenceLeaseV1] { guard OpaqueCapabilityV1.isValid(request.scopeCapability) else { throw RealtimeRelayRuntimeError.invalidRequest }; prunePresence(now: now); let scope = digest(request.scope, domain: "scope"); let scopeCapability = digest(request.scopeCapability, domain: "scope-capability"); return presence.compactMap { key, value in value.scopeDigest == scope && value.scopeCapabilityDigest == scopeCapability ? PresenceLeaseV1(leaseID: Data(base64Encoded: key) ?? Data(), payload: value.payload, expiresAt: value.expiresAt) : nil }.filter { $0.expiresAt > now } }

    mutating func createMediaBlob(_ request: MediaBlobCreateRequestV1, now: Date = Date()) throws -> MediaBlobCreatedV1 { guard OpaqueCapabilityV1.isValid(request.blobCapability), (1...RealtimeRelayLimitsV1.maximumMediaBlobChunks).contains(request.chunkCount), (RealtimeRelayLimitsV1.minimumMediaRetentionSeconds...RealtimeRelayLimitsV1.maximumMediaRetentionSeconds).contains(request.ttlSeconds) else { throw RealtimeRelayRuntimeError.invalidRequest }; let key = request.blobID.uuidString.lowercased(); let expiry = realtimeDate(now.addingTimeInterval(TimeInterval(request.ttlSeconds))); if let existing = state.mediaBlobs[key] { guard existing.capabilityDigest == digest(request.blobCapability, domain: "media-blob"), existing.chunkCount == request.chunkCount else { throw RealtimeRelayRuntimeError.conflict } } else { state.mediaBlobs[key] = MediaBlobStateV1(capabilityDigest: digest(request.blobCapability, domain: "media-blob"), chunkCount: request.chunkCount, expiresAt: expiry, chunks: [:], idempotency: [:]) }; return MediaBlobCreatedV1(blobID: request.blobID, blobCapability: request.blobCapability, chunkCount: request.chunkCount, expiresAt: expiry) }
    mutating func uploadMediaBlob(_ request: MediaBlobUploadRequestV1, now: Date = Date()) throws -> MediaBlobChunkV1 { guard request.payload.count > 0, request.payload.count <= RealtimeRelayLimitsV1.maximumMediaBlobChunkBytes, request.idempotencyKey.count == 32, (0..<RealtimeRelayLimitsV1.maximumMediaBlobChunks).contains(request.chunkIndex) else { throw RealtimeRelayRuntimeError.invalidRequest }; let key = request.blobID.uuidString.lowercased(); guard var blob = state.mediaBlobs[key], blob.expiresAt > now, blob.capabilityDigest == digest(request.blobCapability, domain: "media-blob"), request.chunkIndex < blob.chunkCount else { throw RealtimeRelayRuntimeError.unauthorized }; let id = request.idempotencyKey.base64EncodedString(); let body = Data(SHA256.hash(data: request.payload)); if let existing = blob.idempotency[id] { guard existing == body else { throw RealtimeRelayRuntimeError.conflict }; return MediaBlobChunkV1(blobID: request.blobID, chunkIndex: request.chunkIndex, payload: blob.chunks[request.chunkIndex] ?? request.payload) }; let total = blob.chunks.values.reduce(0) { $0 + $1.count }; guard total + request.payload.count <= RealtimeRelayLimitsV1.maximumMediaBlobBytes else { throw RealtimeRelayRuntimeError.capacity }; blob.chunks[request.chunkIndex] = request.payload; blob.idempotency[id] = body; state.mediaBlobs[key] = blob; return MediaBlobChunkV1(blobID: request.blobID, chunkIndex: request.chunkIndex, payload: request.payload) }
    mutating func fetchMediaBlob(_ request: MediaBlobFetchRequestV1, now: Date = Date()) throws -> MediaBlobChunkV1 { let key = request.blobID.uuidString.lowercased(); guard let blob = state.mediaBlobs[key], blob.expiresAt > now, blob.capabilityDigest == digest(request.blobCapability, domain: "media-blob"), (0..<blob.chunkCount).contains(request.chunkIndex), let payload = blob.chunks[request.chunkIndex] else { throw RealtimeRelayRuntimeError.unavailable }; return MediaBlobChunkV1(blobID: request.blobID, chunkIndex: request.chunkIndex, payload: payload) }
    mutating func releaseMediaBlob(_ request: MediaBlobReleaseRequestV1) throws { let key = request.blobID.uuidString.lowercased(); guard let blob = state.mediaBlobs[key], blob.capabilityDigest == digest(request.blobCapability, domain: "media-blob") else { throw RealtimeRelayRuntimeError.unauthorized }; state.mediaBlobs.removeValue(forKey: key) }

    mutating func prune(now: Date = Date()) { state.routes = state.routes.filter { $0.value.expiresAt > now }; state.mediaBlobs = state.mediaBlobs.filter { $0.value.expiresAt > now }; for key in state.sharedLogs.keys { if var log = state.sharedLogs[key] { pruneSharedLog(&log, now: now); state.sharedLogs[key] = log } }; prunePresence(now: now) }
    private mutating func prunePresence(now: Date) { presence = presence.filter { $0.value.expiresAt > now } }
    private func validatePresence(_ scope: Data, _ scopeCapability: Data, _ leaseID: Data, _ leaseCapability: Data, _ payload: Data, _ ttl: Int) throws { guard !scope.isEmpty && scope.count <= 64, OpaqueCapabilityV1.isValid(scopeCapability), leaseID.count == 16 && leaseID.contains(where: { $0 != 0 }), OpaqueCapabilityV1.isValid(leaseCapability), payload.count <= RealtimeRelayLimitsV1.maximumPresencePayloadBytes, (RealtimeRelayLimitsV1.minimumPresenceLeaseSeconds...RealtimeRelayLimitsV1.maximumPresenceLeaseSeconds).contains(ttl) else { throw RealtimeRelayRuntimeError.invalidRequest } }
    private func pruneSharedLog(_ log: inout SharedLogStateV1, now: Date) { let cutoff = now.addingTimeInterval(-TimeInterval(log.retentionSeconds)); let retained = Array(log.records.filter { $0.storedAt >= cutoff }.suffix(log.maxRecords)); log.retentionFloor = retained.first?.record.sequence ?? log.nextSequence; log.records = retained }
    private func digest(_ value: Data, domain: String) -> Data { Data(SHA256.hash(data: Data("org.noctweave.\(domain).v1".utf8) + value)) }
}

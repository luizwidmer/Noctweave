import Crypto
import Foundation

/// Application-neutral opaque collaboration primitives. This mirror is kept
/// wire-compatible with NoctweaveCore; it never interprets application data.
enum RealtimeRelayLimitsV1 {
    static let capabilityBytes = 32
    static let maximumRecordBytes = 512 * 1024
    static let maximumRecordsPerPage = 256
    static let maximumRealtimeRecords = 4_096
    static let maximumRealtimeRoutes = 4_096
    static let maximumRealtimeLifetime: TimeInterval = 24 * 60 * 60
    static let maximumSharedLogRecords = 100_000
    static let maximumSharedLogs = 4_096
    static let maximumSharedLogLifetime: TimeInterval = 30 * 24 * 60 * 60
    static let maximumPresencePayloadBytes = 16 * 1024
    static let minimumPresenceLeaseSeconds = 5
    static let maximumPresenceLeaseSeconds = 120
    static let maximumMediaBlobChunkBytes = 512 * 1024
    static let maximumMediaBlobChunks = 256
    static let maximumMediaBlobBytes = 32 * 1024 * 1024
    static let maximumMediaBlobs = 4_096
    static let minimumMediaRetentionSeconds = 60
    static let maximumMediaRetentionSeconds = 7 * 24 * 60 * 60
}

enum RealtimeRelayRuntimeError: Error, Equatable {
    case invalidRequest, unauthorized, unavailable, conflict, capacity, invalidCursor, expired
}

enum OpaqueCapabilityV1 {
    static func generate() -> Data { SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) } }
    static func isValid(_ value: Data) -> Bool { value.count == RealtimeRelayLimitsV1.capabilityBytes && value.contains { $0 != 0 } }
}

private func realtimeDate(_ date: Date) -> Date { Date(timeIntervalSince1970: floor(date.timeIntervalSince1970)) }
private func validTimestamp(_ date: Date) -> Bool { date.timeIntervalSince1970.isFinite && date.timeIntervalSince1970 >= 0 && floor(date.timeIntervalSince1970) == date.timeIntervalSince1970 }
private func validPayload(_ payload: Data) -> Bool { !payload.isEmpty && payload.count <= RealtimeRelayLimitsV1.maximumRecordBytes }
private func digest(_ value: Data, domain: String) -> Data { Data(SHA256.hash(data: Data("org.noctweave.\(domain).v1".utf8) + value)) }

struct OpaqueRelayRecordV1: Codable, Equatable {
    let sequence: UInt64; let recordID: UUID; let payload: Data
    var isStructurallyValid: Bool { sequence > 0 && validPayload(payload) }
}

struct OpaqueRelaySyncBatchV1: Codable, Equatable {
    let records: [OpaqueRelayRecordV1]; let nextSequence: UInt64; let highWatermark: UInt64; let retentionFloor: UInt64; let hasMore: Bool
    var isStructurallyValid: Bool {
        records.count <= RealtimeRelayLimitsV1.maximumRecordsPerPage && records.allSatisfy(\.isStructurallyValid)
            && records.map(\.sequence) == records.map(\.sequence).sorted() && Set(records.map(\.sequence)).count == records.count
            && nextSequence <= highWatermark && retentionFloor <= highWatermark + 1
            && (records.last?.sequence ?? nextSequence) == nextSequence && hasMore == (nextSequence < highWatermark)
    }
}

struct RealtimeRouteCreateRequestV1: Codable, Equatable { let routeCapability: Data; let appendCapability: Data; let readCapability: Data; let expiresAt: Date }
struct RealtimeRouteCreatedV1: Codable, Equatable { let routeCapability: Data; let appendCapability: Data; let readCapability: Data; let expiresAt: Date }
struct RealtimeRouteAppendRequestV1: Codable, Equatable { let routeCapability: Data; let appendCapability: Data; let recordID: UUID; let payload: Data }
struct RealtimeRouteAppendReceiptV1: Codable, Equatable { let sequence: UInt64; let recordID: UUID }
struct RealtimeRouteSubscribeRequestV1: Codable, Equatable { let routeCapability: Data; let readCapability: Data; let afterSequence: UInt64 }
struct RealtimeRouteSubscriptionV1: Codable, Equatable { let subscriptionCapability: Data; let routeCapability: Data; let nextSequence: UInt64; let expiresAt: Date }
struct RealtimeRouteSyncRequestV1: Codable, Equatable { let routeCapability: Data; let subscriptionCapability: Data; let afterSequence: UInt64; let maxRecords: Int }
struct RealtimeRouteUnsubscribeRequestV1: Codable, Equatable { let routeCapability: Data; let subscriptionCapability: Data }

struct SharedLogCreateRequestV1: Codable, Equatable { let logCapability: Data; let appendCapability: Data; let readCapability: Data; let retentionSeconds: Int; let maxRecords: Int }
struct SharedLogCreatedV1: Codable, Equatable { let logCapability: Data; let appendCapability: Data; let readCapability: Data; let retentionSeconds: Int }
struct SharedLogAppendRequestV1: Codable, Equatable { let logCapability: Data; let appendCapability: Data; let recordID: UUID; let payload: Data }
struct SharedLogAppendReceiptV1: Codable, Equatable { let sequence: UInt64; let recordID: UUID }
struct SharedLogSyncRequestV1: Codable, Equatable { let logCapability: Data; let readCapability: Data; let afterSequence: UInt64; let maxRecords: Int }

struct PresenceLeaseAcquireRequestV1: Codable, Equatable { let scope: Data; let scopeCapability: Data; let leaseID: Data; let leaseCapability: Data; let payload: Data; let ttlSeconds: Int }
struct PresenceLeaseRenewRequestV1: Codable, Equatable { let scope: Data; let scopeCapability: Data; let leaseID: Data; let leaseCapability: Data; let payload: Data; let ttlSeconds: Int }
struct PresenceLeaseReleaseRequestV1: Codable, Equatable { let scope: Data; let scopeCapability: Data; let leaseID: Data; let leaseCapability: Data }
struct PresenceLeaseListRequestV1: Codable, Equatable { let scope: Data; let scopeCapability: Data }
struct PresenceLeaseV1: Codable, Equatable { let leaseID: Data; let payload: Data; let expiresAt: Date }

struct MediaBlobCreateRequestV1: Codable, Equatable { let blobID: UUID; let blobCapability: Data; let chunkCount: Int; let ttlSeconds: Int }
struct MediaBlobCreatedV1: Codable, Equatable { let blobID: UUID; let blobCapability: Data; let chunkCount: Int; let expiresAt: Date }
struct MediaBlobUploadRequestV1: Codable, Equatable { let blobID: UUID; let blobCapability: Data; let chunkIndex: Int; let payload: Data; let idempotencyKey: Data }
struct MediaBlobFetchRequestV1: Codable, Equatable { let blobID: UUID; let blobCapability: Data; let chunkIndex: Int }
struct MediaBlobReleaseRequestV1: Codable, Equatable { let blobID: UUID; let blobCapability: Data }
struct MediaBlobChunkV1: Codable, Equatable { let blobID: UUID; let chunkIndex: Int; let payload: Data }

struct StoredOpaqueRecordV1: Codable, Equatable { let record: OpaqueRelayRecordV1; let storedAt: Date }
struct RealtimeRouteStateV1: Codable, Equatable { let appendDigest: Data; let readDigest: Data; let expiresAt: Date; var nextSequence: UInt64; var retentionFloor: UInt64; var records: [StoredOpaqueRecordV1]; var subscriptions: [String: Date] }
struct SharedLogStateV1: Codable, Equatable { let appendDigest: Data; let readDigest: Data; let retentionSeconds: Int; let maxRecords: Int; var nextSequence: UInt64; var retentionFloor: UInt64; var records: [StoredOpaqueRecordV1] }
struct MediaBlobStateV1: Codable, Equatable { let capabilityDigest: Data; let chunkCount: Int; let expiresAt: Date; var chunks: [Int: Data]; var idempotency: [String: Data] }
struct RealtimeRelayRuntimeStateV1: Codable, Equatable { var routes: [String: RealtimeRouteStateV1]; var sharedLogs: [String: SharedLogStateV1]; var mediaBlobs: [String: MediaBlobStateV1]; init() { routes = [:]; sharedLogs = [:]; mediaBlobs = [:] } }

struct RealtimeRelayRuntimeV1 {
    var state = RealtimeRelayRuntimeStateV1()
    private var presence: [String: (scopeDigest: Data, scopeCapabilityDigest: Data, leaseDigest: Data, payload: Data, expiresAt: Date)] = [:]

    mutating func createRoute(_ r: RealtimeRouteCreateRequestV1, now: Date = Date()) throws -> RealtimeRouteCreatedV1 {
        guard OpaqueCapabilityV1.isValid(r.routeCapability), OpaqueCapabilityV1.isValid(r.appendCapability), OpaqueCapabilityV1.isValid(r.readCapability), Set([r.routeCapability, r.appendCapability, r.readCapability]).count == 3, validTimestamp(r.expiresAt), r.expiresAt > now, r.expiresAt.timeIntervalSince(now) <= RealtimeRelayLimitsV1.maximumRealtimeLifetime else { throw RealtimeRelayRuntimeError.invalidRequest }
        let key = digest(r.routeCapability, domain: "realtime-route")
        if let e = state.routes[key.base64EncodedString()] { guard e.appendDigest == digest(r.appendCapability, domain: "append"), e.readDigest == digest(r.readCapability, domain: "read"), e.expiresAt == r.expiresAt else { throw RealtimeRelayRuntimeError.conflict } } else { guard state.routes.count < RealtimeRelayLimitsV1.maximumRealtimeRoutes else { throw RealtimeRelayRuntimeError.capacity }; state.routes[key.base64EncodedString()] = RealtimeRouteStateV1(appendDigest: digest(r.appendCapability, domain: "append"), readDigest: digest(r.readCapability, domain: "read"), expiresAt: r.expiresAt, nextSequence: 1, retentionFloor: 1, records: [], subscriptions: [:]) }
        return RealtimeRouteCreatedV1(routeCapability: r.routeCapability, appendCapability: r.appendCapability, readCapability: r.readCapability, expiresAt: r.expiresAt)
    }
    mutating func appendRoute(_ r: RealtimeRouteAppendRequestV1, now: Date = Date()) throws -> RealtimeRouteAppendReceiptV1 {
        guard OpaqueCapabilityV1.isValid(r.routeCapability), OpaqueCapabilityV1.isValid(r.appendCapability), validPayload(r.payload) else { throw RealtimeRelayRuntimeError.invalidRequest }; let key = digest(r.routeCapability, domain: "realtime-route").base64EncodedString(); guard var route = state.routes[key], route.expiresAt > now else { throw RealtimeRelayRuntimeError.expired }; guard route.appendDigest == digest(r.appendCapability, domain: "append") else { throw RealtimeRelayRuntimeError.unauthorized }; if let e = route.records.first(where: { $0.record.recordID == r.recordID }) { guard e.record.payload == r.payload else { throw RealtimeRelayRuntimeError.conflict }; return RealtimeRouteAppendReceiptV1(sequence: e.record.sequence, recordID: r.recordID) }; guard route.records.count < RealtimeRelayLimitsV1.maximumRealtimeRecords else { throw RealtimeRelayRuntimeError.capacity }; let record = OpaqueRelayRecordV1(sequence: route.nextSequence, recordID: r.recordID, payload: r.payload); route.nextSequence += 1; route.records.append(StoredOpaqueRecordV1(record: record, storedAt: realtimeDate(now))); state.routes[key] = route; return RealtimeRouteAppendReceiptV1(sequence: record.sequence, recordID: record.recordID)
    }
    mutating func subscribe(_ r: RealtimeRouteSubscribeRequestV1, now: Date = Date()) throws -> RealtimeRouteSubscriptionV1 { let key = digest(r.routeCapability, domain: "realtime-route").base64EncodedString(); guard var route = state.routes[key], route.expiresAt > now, OpaqueCapabilityV1.isValid(r.readCapability), route.readDigest == digest(r.readCapability, domain: "read"), r.afterSequence <= route.nextSequence - 1 else { throw RealtimeRelayRuntimeError.unauthorized }; let cap = OpaqueCapabilityV1.generate(); route.subscriptions[digest(cap, domain: "realtime-subscription").base64EncodedString()] = route.expiresAt; state.routes[key] = route; return RealtimeRouteSubscriptionV1(subscriptionCapability: cap, routeCapability: r.routeCapability, nextSequence: r.afterSequence, expiresAt: route.expiresAt) }
    mutating func syncRoute(_ r: RealtimeRouteSyncRequestV1, now: Date = Date()) throws -> OpaqueRelaySyncBatchV1 { let key = digest(r.routeCapability, domain: "realtime-route").base64EncodedString(); let subscriptionKey = digest(r.subscriptionCapability, domain: "realtime-subscription").base64EncodedString(); guard OpaqueCapabilityV1.isValid(r.routeCapability), OpaqueCapabilityV1.isValid(r.subscriptionCapability), let route = state.routes[key], route.expiresAt > now, r.maxRecords > 0, r.maxRecords <= RealtimeRelayLimitsV1.maximumRecordsPerPage, let expiry = route.subscriptions[subscriptionKey], expiry > now else { throw RealtimeRelayRuntimeError.unauthorized }; guard r.afterSequence + 1 >= route.retentionFloor else { throw RealtimeRelayRuntimeError.invalidCursor }; let selected = route.records.filter { $0.record.sequence > r.afterSequence }.prefix(r.maxRecords).map { $0.record }; let next = selected.last?.sequence ?? r.afterSequence; let high = route.nextSequence - 1; return OpaqueRelaySyncBatchV1(records: selected, nextSequence: next, highWatermark: high, retentionFloor: route.retentionFloor, hasMore: next < high) }
    mutating func unsubscribe(_ r: RealtimeRouteUnsubscribeRequestV1, now: Date = Date()) throws { let key = digest(r.routeCapability, domain: "realtime-route").base64EncodedString(); let subscriptionKey = digest(r.subscriptionCapability, domain: "realtime-subscription").base64EncodedString(); guard OpaqueCapabilityV1.isValid(r.routeCapability), OpaqueCapabilityV1.isValid(r.subscriptionCapability), var route = state.routes[key], route.expiresAt > now, route.subscriptions.removeValue(forKey: subscriptionKey) != nil else { throw RealtimeRelayRuntimeError.unauthorized }; state.routes[key] = route }

    mutating func createSharedLog(_ r: SharedLogCreateRequestV1, now: Date = Date()) throws -> SharedLogCreatedV1 { guard OpaqueCapabilityV1.isValid(r.logCapability), OpaqueCapabilityV1.isValid(r.appendCapability), OpaqueCapabilityV1.isValid(r.readCapability), Set([r.logCapability, r.appendCapability, r.readCapability]).count == 3, (60...Int(RealtimeRelayLimitsV1.maximumSharedLogLifetime)).contains(r.retentionSeconds), (1...RealtimeRelayLimitsV1.maximumSharedLogRecords).contains(r.maxRecords) else { throw RealtimeRelayRuntimeError.invalidRequest }; let key = digest(r.logCapability, domain: "shared-log").base64EncodedString(); if let e = state.sharedLogs[key] { guard e.appendDigest == digest(r.appendCapability, domain: "append"), e.readDigest == digest(r.readCapability, domain: "read") else { throw RealtimeRelayRuntimeError.conflict } } else { guard state.sharedLogs.count < RealtimeRelayLimitsV1.maximumSharedLogs else { throw RealtimeRelayRuntimeError.capacity }; state.sharedLogs[key] = SharedLogStateV1(appendDigest: digest(r.appendCapability, domain: "append"), readDigest: digest(r.readCapability, domain: "read"), retentionSeconds: r.retentionSeconds, maxRecords: r.maxRecords, nextSequence: 1, retentionFloor: 1, records: []) }; return SharedLogCreatedV1(logCapability: r.logCapability, appendCapability: r.appendCapability, readCapability: r.readCapability, retentionSeconds: r.retentionSeconds) }
    mutating func appendSharedLog(_ r: SharedLogAppendRequestV1, now: Date = Date()) throws -> SharedLogAppendReceiptV1 { guard validPayload(r.payload) else { throw RealtimeRelayRuntimeError.invalidRequest }; let key = digest(r.logCapability, domain: "shared-log").base64EncodedString(); guard var log = state.sharedLogs[key], log.appendDigest == digest(r.appendCapability, domain: "append") else { throw RealtimeRelayRuntimeError.unauthorized }; prune(&log, now: now); if let e = log.records.first(where: { $0.record.recordID == r.recordID }) { guard e.record.payload == r.payload else { throw RealtimeRelayRuntimeError.conflict }; return SharedLogAppendReceiptV1(sequence: e.record.sequence, recordID: r.recordID) }; guard log.records.count < log.maxRecords else { throw RealtimeRelayRuntimeError.capacity }; let record = OpaqueRelayRecordV1(sequence: log.nextSequence, recordID: r.recordID, payload: r.payload); log.nextSequence += 1; log.records.append(StoredOpaqueRecordV1(record: record, storedAt: realtimeDate(now))); state.sharedLogs[key] = log; return SharedLogAppendReceiptV1(sequence: record.sequence, recordID: record.recordID) }
    mutating func syncSharedLog(_ r: SharedLogSyncRequestV1, now: Date = Date()) throws -> OpaqueRelaySyncBatchV1 { let key = digest(r.logCapability, domain: "shared-log").base64EncodedString(); guard var log = state.sharedLogs[key], r.maxRecords > 0, r.maxRecords <= RealtimeRelayLimitsV1.maximumRecordsPerPage, log.readDigest == digest(r.readCapability, domain: "read") else { throw RealtimeRelayRuntimeError.unauthorized }; prune(&log, now: now); guard r.afterSequence + 1 >= log.retentionFloor else { throw RealtimeRelayRuntimeError.invalidCursor }; let selected = log.records.filter { $0.record.sequence > r.afterSequence }.prefix(r.maxRecords).map { $0.record }; let next = selected.last?.sequence ?? r.afterSequence; let high = log.nextSequence - 1; state.sharedLogs[key] = log; return OpaqueRelaySyncBatchV1(records: selected, nextSequence: next, highWatermark: high, retentionFloor: log.retentionFloor, hasMore: next < high) }

    mutating func acquirePresence(_ r: PresenceLeaseAcquireRequestV1, now: Date = Date()) throws -> PresenceLeaseV1 { try validatePresence(r.scope, r.scopeCapability, r.leaseID, r.leaseCapability, r.payload, r.ttlSeconds); prunePresence(now); let key = r.leaseID.base64EncodedString(); guard presence[key] == nil else { throw RealtimeRelayRuntimeError.conflict }; let expiry = realtimeDate(now.addingTimeInterval(TimeInterval(r.ttlSeconds))); presence[key] = (digest(r.scope, domain: "scope"), digest(r.scopeCapability, domain: "scope-capability"), digest(r.leaseCapability, domain: "lease"), r.payload, expiry); return PresenceLeaseV1(leaseID: r.leaseID, payload: r.payload, expiresAt: expiry) }
    mutating func renewPresence(_ r: PresenceLeaseRenewRequestV1, now: Date = Date()) throws -> PresenceLeaseV1 { try validatePresence(r.scope, r.scopeCapability, r.leaseID, r.leaseCapability, r.payload, r.ttlSeconds); prunePresence(now); let key = r.leaseID.base64EncodedString(); guard let current = presence[key], current.scopeDigest == digest(r.scope, domain: "scope"), current.scopeCapabilityDigest == digest(r.scopeCapability, domain: "scope-capability"), current.leaseDigest == digest(r.leaseCapability, domain: "lease") else { throw RealtimeRelayRuntimeError.unauthorized }; let expiry = realtimeDate(now.addingTimeInterval(TimeInterval(r.ttlSeconds))); presence[key] = (current.scopeDigest, current.scopeCapabilityDigest, current.leaseDigest, r.payload, expiry); return PresenceLeaseV1(leaseID: r.leaseID, payload: r.payload, expiresAt: expiry) }
    mutating func releasePresence(_ r: PresenceLeaseReleaseRequestV1, now: Date = Date()) throws { guard OpaqueCapabilityV1.isValid(r.scopeCapability) else { throw RealtimeRelayRuntimeError.invalidRequest }; prunePresence(now); let key = r.leaseID.base64EncodedString(); guard let current = presence[key], current.scopeDigest == digest(r.scope, domain: "scope"), current.scopeCapabilityDigest == digest(r.scopeCapability, domain: "scope-capability"), current.leaseDigest == digest(r.leaseCapability, domain: "lease") else { throw RealtimeRelayRuntimeError.unauthorized }; presence.removeValue(forKey: key) }
    mutating func listPresence(_ r: PresenceLeaseListRequestV1, now: Date = Date()) throws -> [PresenceLeaseV1] { guard OpaqueCapabilityV1.isValid(r.scopeCapability) else { throw RealtimeRelayRuntimeError.invalidRequest }; prunePresence(now); let scope = digest(r.scope, domain: "scope"); let capability = digest(r.scopeCapability, domain: "scope-capability"); return presence.compactMap { key, value in value.scopeDigest == scope && value.scopeCapabilityDigest == capability ? PresenceLeaseV1(leaseID: Data(base64Encoded: key) ?? Data(), payload: value.payload, expiresAt: value.expiresAt) : nil } }

    mutating func createMediaBlob(_ r: MediaBlobCreateRequestV1, now: Date = Date()) throws -> MediaBlobCreatedV1 { guard OpaqueCapabilityV1.isValid(r.blobCapability), (1...RealtimeRelayLimitsV1.maximumMediaBlobChunks).contains(r.chunkCount), (RealtimeRelayLimitsV1.minimumMediaRetentionSeconds...RealtimeRelayLimitsV1.maximumMediaRetentionSeconds).contains(r.ttlSeconds) else { throw RealtimeRelayRuntimeError.invalidRequest }; let key = r.blobID.uuidString.lowercased(); let expiry = realtimeDate(now.addingTimeInterval(TimeInterval(r.ttlSeconds))); if let e = state.mediaBlobs[key] { guard e.capabilityDigest == digest(r.blobCapability, domain: "media-blob"), e.chunkCount == r.chunkCount else { throw RealtimeRelayRuntimeError.conflict } } else { guard state.mediaBlobs.count < RealtimeRelayLimitsV1.maximumMediaBlobs else { throw RealtimeRelayRuntimeError.capacity }; state.mediaBlobs[key] = MediaBlobStateV1(capabilityDigest: digest(r.blobCapability, domain: "media-blob"), chunkCount: r.chunkCount, expiresAt: expiry, chunks: [:], idempotency: [:]) }; return MediaBlobCreatedV1(blobID: r.blobID, blobCapability: r.blobCapability, chunkCount: r.chunkCount, expiresAt: expiry) }
    mutating func uploadMediaBlob(_ r: MediaBlobUploadRequestV1, now: Date = Date()) throws -> MediaBlobChunkV1 { guard r.payload.count > 0, r.payload.count <= RealtimeRelayLimitsV1.maximumMediaBlobChunkBytes, r.idempotencyKey.count == 32 else { throw RealtimeRelayRuntimeError.invalidRequest }; let key = r.blobID.uuidString.lowercased(); guard var blob = state.mediaBlobs[key], blob.expiresAt > now, blob.capabilityDigest == digest(r.blobCapability, domain: "media-blob"), (0..<blob.chunkCount).contains(r.chunkIndex) else { throw RealtimeRelayRuntimeError.unauthorized }; let id = r.idempotencyKey.base64EncodedString(); let body = Data(SHA256.hash(data: r.payload)); if let existing = blob.idempotency[id] { guard existing == body else { throw RealtimeRelayRuntimeError.conflict }; return MediaBlobChunkV1(blobID: r.blobID, chunkIndex: r.chunkIndex, payload: blob.chunks[r.chunkIndex] ?? r.payload) }; let total = blob.chunks.values.reduce(0) { $0 + $1.count }; guard total + r.payload.count <= RealtimeRelayLimitsV1.maximumMediaBlobBytes else { throw RealtimeRelayRuntimeError.capacity }; blob.chunks[r.chunkIndex] = r.payload; blob.idempotency[id] = body; state.mediaBlobs[key] = blob; return MediaBlobChunkV1(blobID: r.blobID, chunkIndex: r.chunkIndex, payload: r.payload) }
    mutating func fetchMediaBlob(_ r: MediaBlobFetchRequestV1, now: Date = Date()) throws -> MediaBlobChunkV1 { let key = r.blobID.uuidString.lowercased(); guard let blob = state.mediaBlobs[key], blob.expiresAt > now, blob.capabilityDigest == digest(r.blobCapability, domain: "media-blob"), (0..<blob.chunkCount).contains(r.chunkIndex), let payload = blob.chunks[r.chunkIndex] else { throw RealtimeRelayRuntimeError.unavailable }; return MediaBlobChunkV1(blobID: r.blobID, chunkIndex: r.chunkIndex, payload: payload) }
    mutating func releaseMediaBlob(_ r: MediaBlobReleaseRequestV1) throws { let key = r.blobID.uuidString.lowercased(); guard let blob = state.mediaBlobs[key], blob.capabilityDigest == digest(r.blobCapability, domain: "media-blob") else { throw RealtimeRelayRuntimeError.unauthorized }; state.mediaBlobs.removeValue(forKey: key) }
    mutating func prune(_ now: Date = Date()) { state.routes = state.routes.filter { $0.value.expiresAt > now }; state.mediaBlobs = state.mediaBlobs.filter { $0.value.expiresAt > now }; for key in state.sharedLogs.keys { if var log = state.sharedLogs[key] { prune(&log, now: now); state.sharedLogs[key] = log } }; prunePresence(now) }
    private mutating func prunePresence(_ now: Date) { presence = presence.filter { $0.value.expiresAt > now } }
    private func prune(_ log: inout SharedLogStateV1, now: Date) { let cutoff = now.addingTimeInterval(-TimeInterval(log.retentionSeconds)); let records = Array(log.records.filter { $0.storedAt >= cutoff }.suffix(log.maxRecords)); log.retentionFloor = records.first?.record.sequence ?? log.nextSequence; log.records = records }
    private func validatePresence(_ scope: Data, _ scopeCapability: Data, _ leaseID: Data, _ leaseCapability: Data, _ payload: Data, _ ttl: Int) throws { guard !scope.isEmpty && scope.count <= 64, OpaqueCapabilityV1.isValid(scopeCapability), leaseID.count == 16 && leaseID.contains(where: { $0 != 0 }), OpaqueCapabilityV1.isValid(leaseCapability), payload.count <= RealtimeRelayLimitsV1.maximumPresencePayloadBytes, (RealtimeRelayLimitsV1.minimumPresenceLeaseSeconds...RealtimeRelayLimitsV1.maximumPresenceLeaseSeconds).contains(ttl) else { throw RealtimeRelayRuntimeError.invalidRequest } }
}

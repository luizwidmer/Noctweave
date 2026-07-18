import CryptoKit
import Foundation
import SQLite3

private enum RelayAttachmentRetentionLimits {
    static let defaultSeconds: TimeInterval = 3_600
    static let minimumSeconds: TimeInterval = 60
    static let maximumSeconds: TimeInterval = 2_592_000
}

public actor RelayStore {
    /// Keyed by a domain-separated route-capability digest. Values contain
    /// only digests of lane authorities; raw bearer material is never stored.
    private var rendezvousRoutesV2: [String: RendezvousRelayRouteRecordV2] = [:]
    private var attachments: [String: [AttachmentRecord]] = [:]
    private var federationNodes: [String: FederationNodeRecord] = [:]
    private var coordinatorPinnedPublicKeys: [String: Data] = [:]
    private var openFederationDHTCache = OpenFederationDHTCandidateCache(
        configuration: OpenFederationDHTDiscoveryConfiguration(isEnabled: false)
    )
    private var federationRegistrationAttemptsBySource: [String: [Date]] = [:]
    private var federationListAttemptsBySource: [String: [Date]] = [:]
    private var lastFederationRegistrationByEndpoint: [String: Date] = [:]
    private var lastDurableSnapshot = RelayStoreSnapshot.empty
    private var persistenceFailuresRemainingForTesting = 0
    private let maxAttachmentChunks = 512
    private let maxAttachmentChunkPayloadBytes = 128 * 1024
    private let maxAttachmentIds = 4_096
    private let coordinatorDefaultNodeTTL: TimeInterval = 180
    private let coordinatorMaximumNodeTTL: TimeInterval = 900
    private let maxFederationNodes = 10_000
    private let federationRateWindowSeconds: TimeInterval = 60
    private let federationRegistrationMaxPerWindow = 24
    private let federationListMaxPerWindow = 120
    private let federationRegistrationMinEndpointIntervalSeconds: TimeInterval = 15
    private let storeURL: URL?
    private let temporalBuckets: [TimeInterval]
    private let attachmentBlobStore: AttachmentBlobStore?
    private let maxActiveRendezvousRoutesV2 = 2_048
    private let maxLifetimeRendezvousRoutesV2 = 100_000

    public init(
        storeURL: URL? = nil,
        temporalBucketSeconds: Int = 300,
        temporalBucketScheduleSeconds: [Int]? = nil,
        attachmentBlobStore: AttachmentBlobStore? = nil
    ) {
        self.storeURL = storeURL
        self.attachmentBlobStore = attachmentBlobStore
        self.temporalBuckets = RelayStore.normalizeBuckets(
            primarySeconds: temporalBucketSeconds,
            scheduleSeconds: temporalBucketScheduleSeconds
        )
    }

    public func loadFromDisk() throws {
        guard let storeURL else {
            return
        }
        let sqliteURL = sqliteStoreURL(for: storeURL)
        if let snapshot = try SQLiteRelayStateStore.loadState(at: sqliteURL) {
            try validateCurrentSnapshot(snapshot)
            applySnapshot(snapshot)
            lastDurableSnapshot = currentSnapshot()
        }
    }

    public func saveToDisk() throws {
        guard let storeURL else {
            return
        }
        do {
            if persistenceFailuresRemainingForTesting > 0 {
                persistenceFailuresRemainingForTesting -= 1
                throw RelayStorePersistenceError.injectedFailure
            }
            pruneAttachments(now: Date())
            pruneFederationNodes(now: Date())
            let snapshot = currentSnapshot()
            try validateCurrentSnapshot(snapshot)
            try SQLiteRelayStateStore.saveState(snapshot, at: sqliteStoreURL(for: storeURL))
            lastDurableSnapshot = snapshot
        } catch {
            restoreSnapshot(lastDurableSnapshot)
            throw error
        }
    }

    /// Deterministic persistence fault injection used by `@testable` regression
    /// tests. The counter is deliberately outside the durable snapshot so one
    /// failed attempt is consumed before an exact retry.
    func failNextPersistenceForTesting(_ count: Int = 1) {
        persistenceFailuresRemainingForTesting = max(0, count)
    }

    public func ingestOpenFederationDHTRecords(
        _ records: [OpenFederationDHTRecord],
        configuration: OpenFederationDHTDiscoveryConfiguration,
        now: Date = Date()
    ) throws -> OpenFederationDHTDiscoveryIngestResult {
        openFederationDHTCache.configuration = configuration
        return try openFederationDHTCache.ingest(records, now: now)
    }

    public func listOpenFederationDHTRecords(
        configuration: OpenFederationDHTDiscoveryConfiguration,
        now: Date = Date(),
        limit: Int?
    ) -> [OpenFederationDHTRecord] {
        openFederationDHTCache.configuration = configuration
        openFederationDHTCache.evictExpired(now: now)
        let boundedLimit = max(0, min(limit ?? configuration.maxQueryRecords, configuration.maxQueryRecords))
        guard boundedLimit > 0 else {
            return []
        }
        return Array(openFederationDHTCache.records(now: now).prefix(boundedLimit))
    }

    /// Atomically creates two opaque directional lanes. The raw route and lane
    /// bearers are authenticated at this boundary and immediately reduced to
    /// domain-separated digests before durable state is assembled.
    func registerRendezvousTransportV2(
        _ request: RegisterRendezvousTransportV2Request,
        now: Date = Date()
    ) throws {
        guard request.isStructurallyValid(at: now) else {
            throw RelayStoreError.invalidRendezvousRoute
        }
        if retireExpiredRendezvousRoutesV2(now: now) {
            try saveToDisk()
        }
        let routeKey = rendezvousRouteKeyV2(request.routeCapability)
        let registrationDigest = rendezvousRegistrationDigestV2(request)
        if let existing = rendezvousRoutesV2[routeKey] {
            guard existing.retiredAt == nil else {
                throw RelayStoreError.rendezvousRouteUnavailable
            }
            guard rendezvousDigestEqualV2(existing.registrationDigest, registrationDigest) else {
                throw RelayStoreError.rendezvousRegistrationConflict
            }
            return
        }
        guard rendezvousRoutesV2.count < maxLifetimeRendezvousRoutesV2,
              rendezvousRoutesV2.values.lazy.filter({ $0.retiredAt == nil }).count
                < maxActiveRendezvousRoutesV2 else {
            throw RelayStoreError.rendezvousCapacityReached
        }
        let registeredAt = Date(timeIntervalSince1970: floor(now.timeIntervalSince1970))
        var lanes: [String: RendezvousRelayLaneRecordV2] = [:]
        for lane in request.lanes {
            lanes[rendezvousLaneKeyV2(lane.laneId)] = RendezvousRelayLaneRecordV2(
                publishCapabilityDigest: rendezvousBearerDigestV2(
                    lane.publishCapability.rawValue,
                    authority: "publish"
                ),
                readCapabilityDigest: rendezvousBearerDigestV2(
                    lane.readCapability.rawValue,
                    authority: "read"
                ),
                deleteCapabilityDigest: rendezvousBearerDigestV2(
                    lane.deleteCapability.rawValue,
                    authority: "delete"
                ),
                deletedAt: nil,
                frames: []
            )
        }
        let record = RendezvousRelayRouteRecordV2(
            registrationDigest: registrationDigest,
            registeredAt: registeredAt,
            expiresAt: request.expiresAt,
            retiredAt: nil,
            lanes: lanes
        )
        guard record.isStructurallyValid else {
            throw RelayStoreError.invalidRendezvousRoute
        }
        rendezvousRoutesV2[routeKey] = record
        try saveToDisk()
    }

    /// Appends exactly one fixed-size ciphertext at the next lane sequence.
    /// An exact frame-ID/digest retry is idempotent; every conflicting replay
    /// and every sequence gap fails closed.
    @discardableResult
    func appendRendezvousTransportV2(
        _ request: AppendRendezvousTransportV2Request,
        now: Date = Date()
    ) throws -> UInt64 {
        guard request.isStructurallyValid else {
            throw RelayStoreError.invalidRendezvousRoute
        }
        if retireExpiredRendezvousRoutesV2(now: now) {
            try saveToDisk()
        }
        let routeKey = rendezvousRouteKeyV2(request.routeCapability)
        guard var route = rendezvousRoutesV2[routeKey],
              route.retiredAt == nil,
              route.expiresAt > now else {
            throw RelayStoreError.rendezvousRouteUnavailable
        }
        let laneKey = rendezvousLaneKeyV2(request.laneId)
        guard var lane = route.lanes[laneKey],
              lane.deletedAt == nil,
              rendezvousDigestEqualV2(
                lane.publishCapabilityDigest,
                rendezvousBearerDigestV2(
                    request.publishCapability.rawValue,
                    authority: "publish"
                )
              ) else {
            throw RelayStoreError.rendezvousRouteUnavailable
        }

        let frameDigest = request.frame.ciphertextDigest
        if let existing = lane.frames.first(where: { $0.frame.frameId == request.frame.frameId }) {
            guard existing.frame.sequence == request.frame.sequence,
                  rendezvousDigestEqualV2(existing.ciphertextDigest, frameDigest) else {
                throw RelayStoreError.rendezvousFrameConflict
            }
            return existing.frame.sequence
        }
        let expectedSequence = UInt64(lane.frames.count) + 1
        guard request.frame.sequence == expectedSequence else {
            if request.frame.sequence < expectedSequence {
                throw RelayStoreError.rendezvousFrameConflict
            }
            throw RelayStoreError.rendezvousSequenceGap
        }
        guard lane.frames.count < Int(RendezvousRelayTransportV2.maximumFramesPerLane),
              lane.frames.reduce(0, { $0 + $1.frame.ciphertext.count })
                + request.frame.ciphertext.count
                <= RendezvousRelayTransportV2.maximumCiphertextBytesPerLane else {
            throw RelayStoreError.rendezvousQuotaReached
        }
        lane.frames.append(
            RendezvousRelayStoredFrameV2(
                frame: request.frame,
                ciphertextDigest: frameDigest
            )
        )
        route.lanes[laneKey] = lane
        rendezvousRoutesV2[routeKey] = route
        try saveToDisk()
        return request.frame.sequence
    }

    func syncRendezvousTransportV2(
        _ request: SyncRendezvousTransportV2Request,
        now: Date = Date()
    ) throws -> RendezvousRelaySyncBatchV2 {
        guard request.isStructurallyValid else {
            throw RelayStoreError.invalidRendezvousRoute
        }
        if retireExpiredRendezvousRoutesV2(now: now) {
            try saveToDisk()
        }
        let routeKey = rendezvousRouteKeyV2(request.routeCapability)
        guard let route = rendezvousRoutesV2[routeKey],
              route.retiredAt == nil,
              route.expiresAt > now,
              let lane = route.lanes[rendezvousLaneKeyV2(request.laneId)],
              lane.deletedAt == nil,
              rendezvousDigestEqualV2(
                lane.readCapabilityDigest,
                rendezvousBearerDigestV2(
                    request.readCapability.rawValue,
                    authority: "read"
                )
              ) else {
            throw RelayStoreError.rendezvousRouteUnavailable
        }
        let highWatermark = lane.frames.last?.frame.sequence ?? 0
        guard request.afterSequence <= highWatermark else {
            throw RelayStoreError.invalidRendezvousRoute
        }
        let limit = request.maxCount ?? RendezvousRelayTransportV2.maximumSyncFrames
        let frames = lane.frames.lazy
            .map(\.frame)
            .filter { $0.sequence > request.afterSequence }
        let selected = Array(frames.prefix(limit))
        let nextSequence = selected.last?.sequence ?? request.afterSequence
        return RendezvousRelaySyncBatchV2(
            frames: selected,
            highWatermark: highWatermark,
            nextSequence: nextSequence,
            hasMore: nextSequence < highWatermark
        )
    }

    /// Erases one lane using its independent deletion authority. Once both
    /// lanes are deleted the route becomes a permanent non-resurrection
    /// tombstone. Exact deletion retries remain idempotent.
    func deleteRendezvousTransportV2(
        _ request: DeleteRendezvousTransportV2Request,
        now: Date = Date()
    ) throws {
        guard request.isStructurallyValid,
              now.timeIntervalSince1970.isFinite else {
            throw RelayStoreError.invalidRendezvousRoute
        }
        if retireExpiredRendezvousRoutesV2(now: now) {
            try saveToDisk()
        }
        let routeKey = rendezvousRouteKeyV2(request.routeCapability)
        guard var route = rendezvousRoutesV2[routeKey],
              let laneKey = route.lanes.keys.first(where: {
                $0 == rendezvousLaneKeyV2(request.laneId)
              }),
              var lane = route.lanes[laneKey],
              rendezvousDigestEqualV2(
                lane.deleteCapabilityDigest,
                rendezvousBearerDigestV2(
                    request.deleteCapability.rawValue,
                    authority: "delete"
                )
              ) else {
            throw RelayStoreError.rendezvousRouteUnavailable
        }
        if lane.deletedAt != nil {
            return
        }
        guard route.retiredAt == nil, route.expiresAt > now else {
            throw RelayStoreError.rendezvousRouteUnavailable
        }
        let deletedAt = Date(timeIntervalSince1970: floor(now.timeIntervalSince1970))
        lane.deletedAt = deletedAt
        lane.frames = []
        route.lanes[laneKey] = lane
        if route.lanes.values.allSatisfy({ $0.deletedAt != nil }) {
            route.retiredAt = deletedAt
        }
        rendezvousRoutesV2[routeKey] = route
        try saveToDisk()
    }

    func rendezvousRouteRecordCountV2() -> Int {
        rendezvousRoutesV2.count
    }

    public func storeAttachment(
        attachmentId: UUID,
        chunkIndex: Int,
        payload: EncryptedPayload,
        ttlSeconds: Int?,
        idempotencyKey: Data,
        effectiveTTLSeconds: Int? = nil
    ) throws -> AttachmentChunk {
        guard chunkIndex >= 0, chunkIndex < maxAttachmentChunks else {
            throw RelayStoreError.invalidChunkIndex
        }
        let payloadBytes = payload.nonce.count + payload.ciphertext.count + payload.tag.count
        guard payload.nonce.count == 12,
              payload.tag.count == 16,
              !payload.ciphertext.isEmpty,
              payloadBytes <= maxAttachmentChunkPayloadBytes else {
            throw RelayStoreError.invalidAttachmentPayload
        }
        guard idempotencyKey.count == UploadAttachmentRequest.idempotencyKeyBytes else {
            throw RelayStoreError.invalidAttachmentIdempotency
        }
        pruneAttachments(now: Date())
        let bodyDigest = attachmentUploadBodyDigest(
            attachmentId: attachmentId,
            chunkIndex: chunkIndex,
            payload: payload,
            ttlSeconds: ttlSeconds
        )
        let ttl = boundedAttachmentTTL(effectiveTTLSeconds ?? ttlSeconds)
        let now = Date()
        let bucketKey = "attachment:\(attachmentId.uuidString):\(chunkIndex)"
        let expiresAt = bucketedCeil(now.addingTimeInterval(ttl), discriminator: bucketKey)
        let key = attachmentId.uuidString
        var deferredExternalDeletions: [AttachmentExternalRecord] = []
        var newlyStoredExternal: AttachmentExternalRecord?
        var attachmentKeyToEvict: String?
        if attachments[key] == nil, attachments.count >= maxAttachmentIds {
            attachmentKeyToEvict = attachments.min(by: { lhs, rhs in
                let lhsDate = lhs.value.map(\.storedAt).min() ?? .distantFuture
                let rhsDate = rhs.value.map(\.storedAt).min() ?? .distantFuture
                return lhsDate < rhsDate
            })?.key
        }
        var records = attachments[key, default: []]
        if let existing = records.first(where: { $0.chunkIndex == chunkIndex }) {
            guard existing.idempotencyKey == idempotencyKey,
                  existing.bodyDigest == bodyDigest else {
                throw RelayStoreError.attachmentConflict
            }
            return AttachmentChunk(
                attachmentId: attachmentId,
                chunkIndex: chunkIndex,
                payload: payload
            )
        }
        let storedAt = bucketed(now, discriminator: bucketKey)
        let record: AttachmentRecord
        if let attachmentBlobStore {
            let encodedPayload = try NoctweaveCoder.encode(payload)
            let external = try attachmentBlobStore.put(
                encodedPayload,
                attachmentId: attachmentId,
                chunkIndex: chunkIndex,
                expiresAt: expiresAt
            )
            newlyStoredExternal = external
            record = AttachmentRecord(
                chunkIndex: chunkIndex,
                payload: nil,
                external: external,
                storedAt: storedAt,
                expiresAt: expiresAt,
                idempotencyKey: idempotencyKey,
                bodyDigest: bodyDigest
            )
        } else {
            record = AttachmentRecord(
                chunkIndex: chunkIndex,
                payload: payload,
                external: nil,
                storedAt: storedAt,
                expiresAt: expiresAt,
                idempotencyKey: idempotencyKey,
                bodyDigest: bodyDigest
            )
        }
        if let attachmentKeyToEvict,
           let evicted = attachments.removeValue(forKey: attachmentKeyToEvict) {
            deferredExternalDeletions.append(contentsOf: evicted.compactMap(\.external))
        }
        records.append(record)
        if records.count > maxAttachmentChunks {
            records.sort { $0.storedAt < $1.storedAt }
            for removed in records.dropLast(maxAttachmentChunks) {
                if let external = removed.external {
                    deferredExternalDeletions.append(external)
                }
            }
            records = Array(records.suffix(maxAttachmentChunks))
        }
        attachments[key] = records
        do {
            try saveToDisk()
        } catch {
            if let newlyStoredExternal {
                deleteExternalAttachmentIfUnreferenced(newlyStoredExternal)
            }
            throw error
        }
        for external in deferredExternalDeletions {
            deleteExternalAttachmentIfUnreferenced(external)
        }
        return AttachmentChunk(attachmentId: attachmentId, chunkIndex: chunkIndex, payload: payload)
    }

    public func fetchAttachment(attachmentId: UUID, chunkIndex: Int) throws -> AttachmentChunk? {
        guard chunkIndex >= 0 else {
            throw RelayStoreError.invalidChunkIndex
        }
        pruneAttachments(now: Date())
        let key = attachmentId.uuidString
        guard let records = attachments[key],
              let record = records.first(where: { $0.chunkIndex == chunkIndex }) else {
            return nil
        }
        let payload = try payload(for: record)
        return AttachmentChunk(attachmentId: attachmentId, chunkIndex: chunkIndex, payload: payload)
    }

    public func registerFederationNode(_ request: FederationNodeRegistrationRequest) throws -> FederationNodeRecord {
        let now = Date()
        pruneFederationNodes(now: now)
        let ttl = TimeInterval(request.ttlSeconds ?? Int(coordinatorDefaultNodeTTL))
        let expiresAt = now.addingTimeInterval(min(coordinatorMaximumNodeTTL, max(30, ttl)))
        let endpoint = request.endpoint
        let key = federationNodeKey(for: endpoint)
        guard federationNodes[key] != nil || federationNodes.count < maxFederationNodes else {
            throw RelayStoreError.relayCapacityExceeded
        }
        let record = FederationNodeRecord(
            endpoint: endpoint,
            relayInfo: request.relayInfo,
            lastHeartbeatAt: now,
            expiresAt: expiresAt
        )
        federationNodes[key] = record
        pruneFederationNodes(now: now)
        try saveToDisk()
        return record
    }

    public func allowFederationRegistration(
        sourceKey: String,
        endpoint: RelayEndpoint,
        now: Date = Date()
    ) -> Bool {
        pruneFederationRateLimits(now: now)
        let source = normalizedFederationSourceKey(sourceKey)
        let endpointKey = federationNodeKey(for: endpoint)
        if let last = lastFederationRegistrationByEndpoint[endpointKey],
           now.timeIntervalSince(last) < federationRegistrationMinEndpointIntervalSeconds {
            return false
        }
        var attempts = federationRegistrationAttemptsBySource[source, default: []]
        if attempts.count >= federationRegistrationMaxPerWindow {
            federationRegistrationAttemptsBySource[source] = attempts
            return false
        }
        attempts.append(now)
        federationRegistrationAttemptsBySource[source] = attempts
        lastFederationRegistrationByEndpoint[endpointKey] = now
        return true
    }

    public func allowFederationDirectoryList(
        sourceKey: String,
        now: Date = Date()
    ) -> Bool {
        pruneFederationRateLimits(now: now)
        let source = normalizedFederationSourceKey(sourceKey)
        var attempts = federationListAttemptsBySource[source, default: []]
        if attempts.count >= federationListMaxPerWindow {
            federationListAttemptsBySource[source] = attempts
            return false
        }
        attempts.append(now)
        federationListAttemptsBySource[source] = attempts
        return true
    }

    public func listFederationNodes(_ request: ListFederationNodesRequest? = nil) -> [FederationNodeRecord] {
        let now = Date()
        pruneFederationNodes(now: now)
        var nodes = Array(federationNodes.values)
        if let mode = request?.mode {
            nodes = nodes.filter { $0.relayInfo.federation.mode == mode }
        }
        if let rawName = request?.federationName?.trimmingCharacters(in: .whitespacesAndNewlines),
           !rawName.isEmpty {
            nodes = nodes.filter { $0.relayInfo.federation.name == rawName }
        }
        if request?.onlyHealthy == true {
            nodes = nodes.filter { $0.expiresAt > now }
        }
        if let maxStaleness = request?.maxStalenessSeconds, maxStaleness > 0 {
            let cutoff = now.addingTimeInterval(-TimeInterval(maxStaleness))
            nodes = nodes.filter { $0.lastHeartbeatAt >= cutoff }
        }
        return nodes.sorted { lhs, rhs in
            if lhs.lastHeartbeatAt != rhs.lastHeartbeatAt {
                return lhs.lastHeartbeatAt > rhs.lastHeartbeatAt
            }
            return federationNodeKey(for: lhs.endpoint) < federationNodeKey(for: rhs.endpoint)
        }
    }

    public func pinnedCoordinatorPublicKey(for endpoint: RelayEndpoint) -> Data? {
        coordinatorPinnedPublicKeys[federationNodeKey(for: endpoint)]
    }

    public func pinCoordinatorPublicKey(_ key: Data, for endpoint: RelayEndpoint) throws {
        coordinatorPinnedPublicKeys[federationNodeKey(for: endpoint)] = key
        try saveToDisk()
    }

    private func pruneAttachments(now: Date) {
        attachments = attachments.compactMapValues { records in
            var filtered: [AttachmentRecord] = []
            for record in records {
                if record.expiresAt > now {
                    filtered.append(record)
                } else if let external = record.external {
                    attachmentBlobStore?.delete(external)
                }
            }
            return filtered.isEmpty ? nil : filtered
        }
    }

    private func boundedAttachmentTTL(_ ttlSeconds: Int?) -> TimeInterval {
        let requested = TimeInterval(
            ttlSeconds ?? Int(RelayAttachmentRetentionLimits.defaultSeconds)
        )
        return min(
            RelayAttachmentRetentionLimits.maximumSeconds,
            max(RelayAttachmentRetentionLimits.minimumSeconds, requested)
        )
    }

    private func payload(for record: AttachmentRecord) throws -> EncryptedPayload {
        if let payload = record.payload {
            return payload
        }
        guard let external = record.external,
              let attachmentBlobStore,
              external.backend == attachmentBlobStore.backendName else {
            throw RelayStoreError.invalidAttachmentPayload
        }
        let data = try attachmentBlobStore.get(external)
        return try NoctweaveCoder.decode(EncryptedPayload.self, from: data)
    }

    private func deleteExternalAttachmentIfUnreferenced(_ external: AttachmentExternalRecord) {
        let isReferenced = attachments.values.contains { records in
            records.contains { $0.external == external }
        }
        if !isReferenced {
            attachmentBlobStore?.delete(external)
        }
    }

    private func pruneFederationNodes(now: Date) {
        federationNodes = federationNodes.filter { $0.value.expiresAt > now }
        if federationNodes.count > maxFederationNodes {
            let retained = federationNodes
                .sorted { lhs, rhs in lhs.value.lastHeartbeatAt > rhs.value.lastHeartbeatAt }
                .prefix(maxFederationNodes)
            federationNodes = Dictionary(uniqueKeysWithValues: retained.map { ($0.key, $0.value) })
        }
    }

    private func federationNodeKey(for endpoint: RelayEndpoint) -> String {
        "\(endpoint.host.lowercased()):\(endpoint.port):\(endpoint.useTLS ? 1 : 0):\(endpoint.transport.rawValue)"
    }

    private func normalizedFederationSourceKey(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return trimmed.isEmpty ? "unknown" : trimmed
    }

    private func pruneFederationRateLimits(now: Date) {
        let cutoff = now.addingTimeInterval(-federationRateWindowSeconds)
        federationRegistrationAttemptsBySource = federationRegistrationAttemptsBySource.compactMapValues { attempts in
            let filtered = attempts.filter { $0 >= cutoff }
            return filtered.isEmpty ? nil : filtered
        }
        federationListAttemptsBySource = federationListAttemptsBySource.compactMapValues { attempts in
            let filtered = attempts.filter { $0 >= cutoff }
            return filtered.isEmpty ? nil : filtered
        }
        let endpointCutoff = now.addingTimeInterval(-federationRegistrationMinEndpointIntervalSeconds * 2)
        lastFederationRegistrationByEndpoint = lastFederationRegistrationByEndpoint.filter { _, timestamp in
            timestamp >= endpointCutoff
        }
    }

    private static func normalizeBuckets(primarySeconds: Int, scheduleSeconds: [Int]?) -> [TimeInterval] {
        var normalized = Set<Int>()
        normalized.insert(max(0, primarySeconds))
        if let scheduleSeconds {
            for value in scheduleSeconds {
                normalized.insert(max(0, value))
            }
        }
        return normalized
            .filter { $0 > 0 }
            .sorted()
            .map(TimeInterval.init)
    }

    private func selectedBucketSeconds(for discriminator: String) -> TimeInterval? {
        guard !temporalBuckets.isEmpty else {
            return nil
        }
        guard temporalBuckets.count > 1 else {
            return temporalBuckets[0]
        }
        let hash = RelayStore.fnv1a64(discriminator.utf8)
        let index = Int(hash % UInt64(temporalBuckets.count))
        return temporalBuckets[index]
    }

    private static func fnv1a64<S: Sequence>(_ bytes: S) -> UInt64 where S.Element == UInt8 {
        var hash: UInt64 = 14695981039346656037
        for byte in bytes {
            hash ^= UInt64(byte)
            hash &*= 1099511628211
        }
        return hash
    }

    private func bucketed(_ date: Date, discriminator: String) -> Date {
        guard let selected = selectedBucketSeconds(for: discriminator) else {
            return date
        }
        let timestamp = date.timeIntervalSince1970
        let bucketed = floor(timestamp / selected) * selected
        return Date(timeIntervalSince1970: bucketed)
    }

    private func bucketedCeil(_ date: Date, discriminator: String) -> Date {
        guard let selected = selectedBucketSeconds(for: discriminator) else {
            return date
        }
        let timestamp = date.timeIntervalSince1970
        let bucketed = ceil(timestamp / selected) * selected
        return Date(timeIntervalSince1970: bucketed)
    }

    private func applySnapshot(_ snapshot: RelayStoreSnapshot) {
        rendezvousRoutesV2 = snapshot.rendezvousRoutesV2
        attachments = snapshot.attachments
        federationNodes = snapshot.federationNodes
        coordinatorPinnedPublicKeys = snapshot.coordinatorPinnedPublicKeys
        pruneAttachments(now: Date())
        pruneFederationNodes(now: Date())
        normalizeRendezvousRoutesV2AfterLoad()
    }

    private func restoreSnapshot(_ snapshot: RelayStoreSnapshot) {
        rendezvousRoutesV2 = snapshot.rendezvousRoutesV2
        attachments = snapshot.attachments
        federationNodes = snapshot.federationNodes
        coordinatorPinnedPublicKeys = snapshot.coordinatorPinnedPublicKeys
    }

    private func currentSnapshot() -> RelayStoreSnapshot {
        RelayStoreSnapshot(
            rendezvousRoutesV2: rendezvousRoutesV2,
            attachments: attachments,
            federationNodes: federationNodes,
            coordinatorPinnedPublicKeys: coordinatorPinnedPublicKeys
        )
    }

    private func sqliteStoreURL(for url: URL) -> URL {
        let ext = url.pathExtension.lowercased()
        if ext == "sqlite" || ext == "db" {
            return url
        }
        let base = url.pathExtension.isEmpty ? url : url.deletingPathExtension()
        return base.appendingPathExtension("sqlite")
    }

    private func validateCurrentSnapshot(_ snapshot: RelayStoreSnapshot) throws {
        guard snapshot.rendezvousRoutesV2.count <= maxLifetimeRendezvousRoutesV2,
              snapshot.rendezvousRoutesV2.allSatisfy({ key, record in
                  Data(base64Encoded: key)?.count == SHA256.byteCount
                      && record.isStructurallyValid
              }),
              snapshot.attachments.count <= maxAttachmentIds,
              snapshot.attachments.allSatisfy({ attachmentId, records in
                  UUID(uuidString: attachmentId) != nil
                      && records.count <= maxAttachmentChunks
                      && Set(records.map(\.chunkIndex)).count == records.count
                      && records.allSatisfy({ record in
                          record.isStructurallyValid
                      })
              }),
              snapshot.federationNodes.count <= maxFederationNodes,
              snapshot.federationNodes.values.allSatisfy({ record in
                  record.lastHeartbeatAt.timeIntervalSince1970.isFinite
                      && record.expiresAt.timeIntervalSince1970.isFinite
                      && record.expiresAt >= record.lastHeartbeatAt
              }),
              snapshot.coordinatorPinnedPublicKeys.values.allSatisfy(
                  SigningKeyPair.isValidPublicKey
              ) else {
            throw RelayStorePersistenceError.invalidCurrentState
        }
    }

    private func rendezvousRouteKeyV2(
        _ capability: RendezvousRelayRouteCapabilityV2
    ) -> String {
        rendezvousBearerDigestV2(capability.rawValue, authority: "route")
            .base64EncodedString()
    }

    private func rendezvousLaneKeyV2(_ laneId: RendezvousRelayLaneIDV2) -> String {
        laneId.rawValue.base64EncodedString()
    }

    private func rendezvousBearerDigestV2(_ value: Data, authority: String) -> Data {
        var input = Data("org.noctweave.relay.rendezvous-transport-v2/\(authority)".utf8)
        input.append(0)
        input.append(value)
        return Data(SHA256.hash(data: input))
    }

    private func rendezvousRegistrationDigestV2(
        _ request: RegisterRendezvousTransportV2Request
    ) -> Data {
        var input = Data("org.noctweave.relay.rendezvous-transport-v2/registration".utf8)
        input.append(0)
        var version = UInt64(request.version).bigEndian
        withUnsafeBytes(of: &version) { input.append(contentsOf: $0) }
        var expiry = UInt64(request.expiresAt.timeIntervalSince1970).bigEndian
        withUnsafeBytes(of: &expiry) { input.append(contentsOf: $0) }
        input.append(request.routeCapability.rawValue)
        for lane in request.lanes.sorted(by: {
            $0.laneId.rawValue.lexicographicallyPrecedes($1.laneId.rawValue)
        }) {
            input.append(lane.laneId.rawValue)
            input.append(lane.publishCapability.rawValue)
            input.append(lane.readCapability.rawValue)
            input.append(lane.deleteCapability.rawValue)
        }
        return Data(SHA256.hash(data: input))
    }

    private func rendezvousDigestEqualV2(_ lhs: Data, _ rhs: Data) -> Bool {
        var difference = lhs.count ^ rhs.count
        for index in 0..<max(lhs.count, rhs.count) {
            let left = index < lhs.count ? lhs[index] : 0
            let right = index < rhs.count ? rhs[index] : 0
            difference |= Int(left ^ right)
        }
        return difference == 0
    }

    @discardableResult
    private func retireExpiredRendezvousRoutesV2(now: Date) -> Bool {
        guard now.timeIntervalSince1970.isFinite else { return false }
        let retiredAt = Date(timeIntervalSince1970: floor(now.timeIntervalSince1970))
        var changed = false
        for key in Array(rendezvousRoutesV2.keys) {
            guard var record = rendezvousRoutesV2[key],
                  record.retiredAt == nil,
                  record.expiresAt <= now else {
                continue
            }
            record.retiredAt = retiredAt
            record.lanes = [:]
            rendezvousRoutesV2[key] = record
            changed = true
        }
        return changed
    }

    private func normalizeRendezvousRoutesV2AfterLoad(now: Date = Date()) {
        rendezvousRoutesV2 = rendezvousRoutesV2.filter { key, record in
            guard let digest = Data(base64Encoded: key),
                  digest.count == SHA256.byteCount,
                  record.isStructurallyValid else {
                return false
            }
            return true
        }
        _ = retireExpiredRendezvousRoutesV2(now: now)
    }

}

private struct RendezvousRelayStoredFrameV2: Codable {
    let frame: RendezvousRelayCiphertextFrameV2
    let ciphertextDigest: Data

    var isStructurallyValid: Bool {
        frame.isStructurallyValid
            && ciphertextDigest.count == SHA256.byteCount
            && ciphertextDigest == frame.ciphertextDigest
    }
}

private struct RendezvousRelayLaneRecordV2: Codable {
    let publishCapabilityDigest: Data
    let readCapabilityDigest: Data
    let deleteCapabilityDigest: Data
    var deletedAt: Date?
    var frames: [RendezvousRelayStoredFrameV2]

    var isStructurallyValid: Bool {
        let digests = [
            publishCapabilityDigest,
            readCapabilityDigest,
            deleteCapabilityDigest
        ]
        guard digests.allSatisfy({ $0.count == SHA256.byteCount }),
              Set(digests).count == digests.count,
              frames.count <= Int(RendezvousRelayTransportV2.maximumFramesPerLane),
              frames.reduce(0, { $0 + $1.frame.ciphertext.count })
                <= RendezvousRelayTransportV2.maximumCiphertextBytesPerLane,
              frames.allSatisfy(\.isStructurallyValid),
              Set(frames.map(\.frame.frameId)).count == frames.count,
              frames.enumerated().allSatisfy({ index, record in
                record.frame.sequence == UInt64(index + 1)
              }) else {
            return false
        }
        if let deletedAt {
            return RendezvousRelayTransportV2.isCanonicalTimestamp(deletedAt)
                && frames.isEmpty
        }
        return true
    }
}

private struct RendezvousRelayRouteRecordV2: Codable {
    let registrationDigest: Data
    let registeredAt: Date
    let expiresAt: Date
    var retiredAt: Date?
    var lanes: [String: RendezvousRelayLaneRecordV2]

    var isStructurallyValid: Bool {
        let lifetime = expiresAt.timeIntervalSince(registeredAt)
        guard registrationDigest.count == SHA256.byteCount,
              RendezvousRelayTransportV2.isCanonicalTimestamp(registeredAt),
              RendezvousRelayTransportV2.isCanonicalTimestamp(expiresAt),
              lifetime > 0,
              lifetime <= RendezvousRelayTransportV2.maximumLifetimeSeconds,
              retiredAt.map(RendezvousRelayTransportV2.isCanonicalTimestamp) ?? true,
              retiredAt.map({ $0 >= registeredAt }) ?? true,
              lanes.count <= RendezvousRelayTransportV2.laneCount,
              lanes.allSatisfy({ key, lane in
                Data(base64Encoded: key)?.count == RendezvousRelayTransportV2.laneIDBytes
                    && lane.isStructurallyValid
              }) else {
            return false
        }
        return retiredAt != nil || lanes.count == RendezvousRelayTransportV2.laneCount
    }
}

private struct RelayStoreSnapshot: Codable {
    let rendezvousRoutesV2: [String: RendezvousRelayRouteRecordV2]
    let attachments: [String: [AttachmentRecord]]
    let federationNodes: [String: FederationNodeRecord]
    let coordinatorPinnedPublicKeys: [String: Data]

    static let empty = RelayStoreSnapshot(
        rendezvousRoutesV2: [:],
        attachments: [:],
        federationNodes: [:],
        coordinatorPinnedPublicKeys: [:]
    )
}

private struct AttachmentRecord: Codable {
    let chunkIndex: Int
    let payload: EncryptedPayload?
    let external: AttachmentExternalRecord?
    let storedAt: Date
    let expiresAt: Date
    let idempotencyKey: Data
    let bodyDigest: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case chunkIndex
        case payload
        case external
        case storedAt
        case expiresAt
        case idempotencyKey
        case bodyDigest
    }

    init(
        chunkIndex: Int,
        payload: EncryptedPayload?,
        external: AttachmentExternalRecord?,
        storedAt: Date,
        expiresAt: Date,
        idempotencyKey: Data,
        bodyDigest: Data
    ) {
        self.chunkIndex = chunkIndex
        self.payload = payload
        self.external = external
        self.storedAt = storedAt
        self.expiresAt = expiresAt
        self.idempotencyKey = idempotencyKey
        self.bodyDigest = bodyDigest
    }

    init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: AttachmentRecordCodingKey.self)
        let expected = Set(CodingKeys.allCases.map(\.rawValue))
        guard Set(strict.allKeys.map(\.stringValue)) == expected else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Stored attachment fields are not exact"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            chunkIndex: try values.decode(Int.self, forKey: .chunkIndex),
            payload: try values.decodeIfPresent(EncryptedPayload.self, forKey: .payload),
            external: try values.decodeIfPresent(AttachmentExternalRecord.self, forKey: .external),
            storedAt: try values.decode(Date.self, forKey: .storedAt),
            expiresAt: try values.decode(Date.self, forKey: .expiresAt),
            idempotencyKey: try values.decode(Data.self, forKey: .idempotencyKey),
            bodyDigest: try values.decode(Data.self, forKey: .bodyDigest)
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .chunkIndex,
                in: values,
                debugDescription: "Stored attachment is structurally invalid"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "Stored attachment is structurally invalid"
                )
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(chunkIndex, forKey: .chunkIndex)
        try values.encode(payload, forKey: .payload)
        try values.encode(external, forKey: .external)
        try values.encode(storedAt, forKey: .storedAt)
        try values.encode(expiresAt, forKey: .expiresAt)
        try values.encode(idempotencyKey, forKey: .idempotencyKey)
        try values.encode(bodyDigest, forKey: .bodyDigest)
    }

    var isStructurallyValid: Bool {
        (0..<AttachmentChunk.maximumChunkCount).contains(chunkIndex)
            && payload?.isStructurallyValid != false
            && (payload != nil) != (external != nil)
            && storedAt.timeIntervalSince1970.isFinite
            && expiresAt.timeIntervalSince1970.isFinite
            && expiresAt >= storedAt
            && idempotencyKey.count == UploadAttachmentRequest.idempotencyKeyBytes
            && bodyDigest.count == SHA256.byteCount
    }
}

private struct AttachmentRecordCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}

func attachmentUploadBodyDigest(
    attachmentId: UUID,
    chunkIndex: Int,
    payload: EncryptedPayload,
    ttlSeconds: Int?
) -> Data {
    var material = Data("org.noctweave.blobs.upload-v1".utf8)
    appendAttachmentDigestField(Data(attachmentId.uuidString.lowercased().utf8), to: &material)
    appendAttachmentDigestInteger(UInt64(chunkIndex), to: &material)
    appendAttachmentDigestField(payload.nonce, to: &material)
    appendAttachmentDigestField(payload.ciphertext, to: &material)
    appendAttachmentDigestField(payload.tag, to: &material)
    if let ttlSeconds {
        material.append(1)
        appendAttachmentDigestInteger(UInt64(bitPattern: Int64(ttlSeconds)), to: &material)
    } else {
        material.append(0)
    }
    return Data(SHA256.hash(data: material))
}

private func appendAttachmentDigestField(_ value: Data, to material: inout Data) {
    appendAttachmentDigestInteger(UInt64(value.count), to: &material)
    material.append(value)
}

private func appendAttachmentDigestInteger(_ value: UInt64, to material: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) {
        material.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
    }
}

private enum SQLiteRelayStateStoreError: Error, CustomStringConvertible {
    case openDatabase(String)
    case execute(String)
    case prepare(String)
    case bind(String)
    case step(String)
    case corrupt(String)

    var description: String {
        switch self {
        case .openDatabase(let message):
            return "SQLite open failed: \(message)"
        case .execute(let message):
            return "SQLite exec failed: \(message)"
        case .prepare(let message):
            return "SQLite prepare failed: \(message)"
        case .bind(let message):
            return "SQLite bind failed: \(message)"
        case .step(let message):
            return "SQLite step failed: \(message)"
        case .corrupt(let message):
            return "SQLite state is corrupt: \(message)"
        }
    }
}

private enum SQLiteRelayStateStore {
    private static let metaTableName = "relay_state_meta"
    private static let currentSchemaKey = "noctweave_1_0_clean_relay_schema"
    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    static func loadState(at url: URL) throws -> RelayStoreSnapshot? {
        let existedBeforeOpen = FileManager.default.fileExists(atPath: url.path)
        var db: OpaquePointer?
        try openDatabase(at: url, handle: &db)
        defer { sqlite3_close(db) }
        guard let db else { return nil }

        try ensureSchema(in: db)
        guard try hasCurrentState(in: db) else {
            if existedBeforeOpen {
                throw RelayStorePersistenceError.invalidCurrentState
            }
            return nil
        }
        return RelayStoreSnapshot(
            rendezvousRoutesV2: try loadRendezvousRoutesV2(in: db),
            attachments: try loadAttachments(in: db),
            federationNodes: try loadFederationNodes(in: db),
            coordinatorPinnedPublicKeys: try loadCoordinatorPinnedPublicKeys(in: db)
        )
    }

    static func saveState(_ snapshot: RelayStoreSnapshot, at url: URL) throws {
        var db: OpaquePointer?
        try openDatabase(at: url, handle: &db)
        defer { sqlite3_close(db) }
        guard let db else { return }

        try ensureSchema(in: db)
        try execute("BEGIN IMMEDIATE TRANSACTION;", in: db)
        do {
            try clearNormalizedTables(in: db)
            for (routeDigest, record) in snapshot.rendezvousRoutesV2 {
                try insertRendezvousRouteV2(
                    routeDigest: routeDigest,
                    record: record,
                    in: db
                )
            }
            for (attachmentId, records) in snapshot.attachments {
                for record in records {
                    try insertAttachmentRecord(attachmentId: attachmentId, record: record, in: db)
                }
            }
            for (nodeKey, record) in snapshot.federationNodes {
                try insertFederationNode(nodeKey: nodeKey, record: record, in: db)
            }
            for (coordinatorKey, publicKey) in snapshot.coordinatorPinnedPublicKeys {
                try insertCoordinatorPinnedPublicKey(coordinatorKey: coordinatorKey, publicKey: publicKey, in: db)
            }
            try insertMeta(key: currentSchemaKey, value: Data("1".utf8), in: db)
            try execute("COMMIT;", in: db)
        } catch {
            _ = sqlite3_exec(db, "ROLLBACK;", nil, nil, nil)
            throw error
        }
    }

    private static func loadRendezvousRoutesV2(
        in db: OpaquePointer
    ) throws -> [String: RendezvousRelayRouteRecordV2] {
        var records: [String: RendezvousRelayRouteRecordV2] = [:]
        try queryRows(
            "SELECT route_digest, value FROM relay_rendezvous_routes_v2;",
            in: db
        ) { statement in
            let digest = try readText(statement, column: 0, in: db)
            records[digest] = try decode(
                RendezvousRelayRouteRecordV2.self,
                from: readBlob(statement, column: 1)
            )
        }
        guard records.count <= 100_000 else {
            throw SQLiteRelayStateStoreError.corrupt("too many rendezvous route records")
        }
        return records
    }

    private static func loadAttachments(in db: OpaquePointer) throws -> [String: [AttachmentRecord]] {
        var attachments: [String: [AttachmentRecord]] = [:]
        try queryRows("SELECT attachment_id, value FROM relay_attachment_chunks ORDER BY attachment_id, chunk_index;", in: db) { statement in
            let attachmentId = try readText(statement, column: 0, in: db)
            let record = try decode(AttachmentRecord.self, from: readBlob(statement, column: 1))
            attachments[attachmentId, default: []].append(record)
        }
        return attachments
    }

    private static func loadFederationNodes(in db: OpaquePointer) throws -> [String: FederationNodeRecord] {
        var nodes: [String: FederationNodeRecord] = [:]
        try queryRows("SELECT node_key, value FROM relay_federation_nodes;", in: db) { statement in
            let nodeKey = try readText(statement, column: 0, in: db)
            nodes[nodeKey] = try decode(FederationNodeRecord.self, from: readBlob(statement, column: 1))
        }
        return nodes
    }

    private static func loadCoordinatorPinnedPublicKeys(in db: OpaquePointer) throws -> [String: Data] {
        var keys: [String: Data] = [:]
        try queryRows("SELECT coordinator_key, public_key FROM relay_coordinator_pinned_keys;", in: db) { statement in
            let coordinatorKey = try readText(statement, column: 0, in: db)
            let publicKey = try readBlob(statement, column: 1)
            guard try SigningKeyPair.isValidPublicKeyThrowing(publicKey) else {
                throw SQLiteRelayStateStoreError.corrupt("invalid pinned coordinator public key")
            }
            keys[coordinatorKey] = publicKey
        }
        return keys
    }

    private static func insertRendezvousRouteV2(
        routeDigest: String,
        record: RendezvousRelayRouteRecordV2,
        in db: OpaquePointer
    ) throws {
        try executePrepared(
            "INSERT INTO relay_rendezvous_routes_v2 (route_digest, expires_at, retired_at, value) VALUES (?1, ?2, ?3, ?4);",
            in: db
        ) { statement in
            try bindText(routeDigest, to: 1, in: statement, db: db)
            try bindDouble(record.expiresAt.timeIntervalSince1970, to: 2, in: statement, db: db)
            if let retiredAt = record.retiredAt {
                try bindDouble(retiredAt.timeIntervalSince1970, to: 3, in: statement, db: db)
            } else {
                guard sqlite3_bind_null(statement, 3) == SQLITE_OK else {
                    throw SQLiteRelayStateStoreError.bind(lastError(in: db))
                }
            }
            try bindBlob(encode(record), to: 4, in: statement, db: db)
        }
    }

    private static func insertAttachmentRecord(attachmentId: String, record: AttachmentRecord, in db: OpaquePointer) throws {
        try executePrepared(
            "INSERT INTO relay_attachment_chunks (attachment_id, chunk_index, stored_at, expires_at, value) VALUES (?1, ?2, ?3, ?4, ?5);",
            in: db
        ) { statement in
            try bindText(attachmentId, to: 1, in: statement, db: db)
            try bindInt(record.chunkIndex, to: 2, in: statement, db: db)
            try bindDouble(record.storedAt.timeIntervalSince1970, to: 3, in: statement, db: db)
            try bindDouble(record.expiresAt.timeIntervalSince1970, to: 4, in: statement, db: db)
            try bindBlob(encode(record), to: 5, in: statement, db: db)
        }
    }

    private static func insertFederationNode(nodeKey: String, record: FederationNodeRecord, in db: OpaquePointer) throws {
        try executePrepared(
            "INSERT INTO relay_federation_nodes (node_key, expires_at, value) VALUES (?1, ?2, ?3);",
            in: db
        ) { statement in
            try bindText(nodeKey, to: 1, in: statement, db: db)
            try bindDouble(record.expiresAt.timeIntervalSince1970, to: 2, in: statement, db: db)
            try bindBlob(encode(record), to: 3, in: statement, db: db)
        }
    }

    private static func insertCoordinatorPinnedPublicKey(coordinatorKey: String, publicKey: Data, in db: OpaquePointer) throws {
        try executePrepared(
            "INSERT INTO relay_coordinator_pinned_keys (coordinator_key, public_key) VALUES (?1, ?2);",
            in: db
        ) { statement in
            try bindText(coordinatorKey, to: 1, in: statement, db: db)
            try bindBlob(publicKey, to: 2, in: statement, db: db)
        }
    }

    private static func insertMeta(key: String, value: Data, in db: OpaquePointer) throws {
        try executePrepared(
            "INSERT INTO \(metaTableName) (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            in: db
        ) { statement in
            try bindText(key, to: 1, in: statement, db: db)
            try bindBlob(value, to: 2, in: statement, db: db)
        }
    }

    private static func hasCurrentState(in db: OpaquePointer) throws -> Bool {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT value FROM \(metaTableName) WHERE key = ?1 LIMIT 1;", -1, &statement, nil) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.prepare(lastError(in: db))
        }
        defer { sqlite3_finalize(statement) }
        guard let statement else { return false }

        try bindText(currentSchemaKey, to: 1, in: statement, db: db)
        let step = sqlite3_step(statement)
        if step == SQLITE_ROW {
            return try readBlob(statement, column: 0) == Data("1".utf8)
        }
        if step == SQLITE_DONE {
            return false
        }
        throw SQLiteRelayStateStoreError.step(lastError(in: db))
    }

    private static func clearNormalizedTables(in db: OpaquePointer) throws {
        for table in [
            "relay_rendezvous_routes_v2",
            "relay_attachment_chunks",
            "relay_federation_nodes",
            "relay_coordinator_pinned_keys"
        ] {
            try execute("DELETE FROM \(table);", in: db)
        }
    }

    private static func openDatabase(at url: URL, handle: inout OpaquePointer?) throws {
        let directory = url.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        let result = sqlite3_open(url.path, &handle)
        guard result == SQLITE_OK else {
            let message = handle.flatMap(lastError(in:)) ?? "Unknown error"
            if handle != nil {
                sqlite3_close(handle)
            }
            throw SQLiteRelayStateStoreError.openDatabase(message)
        }
    }

    private static func ensureSchema(in db: OpaquePointer) throws {
        let sql = """
        CREATE TABLE IF NOT EXISTS \(metaTableName) (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS relay_rendezvous_routes_v2 (
            route_digest TEXT PRIMARY KEY,
            expires_at REAL NOT NULL,
            retired_at REAL,
            value BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS relay_rendezvous_routes_v2_expiry_idx ON relay_rendezvous_routes_v2(expires_at);
        CREATE TABLE IF NOT EXISTS relay_attachment_chunks (
            attachment_id TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            stored_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            value BLOB NOT NULL,
            PRIMARY KEY (attachment_id, chunk_index)
        );
        CREATE INDEX IF NOT EXISTS relay_attachment_chunks_expiry_idx ON relay_attachment_chunks(expires_at);
        CREATE TABLE IF NOT EXISTS relay_federation_nodes (
            node_key TEXT PRIMARY KEY,
            expires_at REAL NOT NULL,
            value BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS relay_coordinator_pinned_keys (
            coordinator_key TEXT PRIMARY KEY,
            public_key BLOB NOT NULL
        );
        """
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.execute(lastError(in: db))
        }
    }

    private static func queryRows(
        _ sql: String,
        in db: OpaquePointer,
        row: (OpaquePointer) throws -> Void
    ) throws {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.prepare(lastError(in: db))
        }
        defer { sqlite3_finalize(statement) }
        guard let statement else { return }

        while true {
            let step = sqlite3_step(statement)
            if step == SQLITE_ROW {
                try row(statement)
            } else if step == SQLITE_DONE {
                return
            } else {
                throw SQLiteRelayStateStoreError.step(lastError(in: db))
            }
        }
    }

    private static func executePrepared(
        _ sql: String,
        in db: OpaquePointer,
        bindAndStep: (OpaquePointer) throws -> Void
    ) throws {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.prepare(lastError(in: db))
        }
        defer { sqlite3_finalize(statement) }
        guard let statement else { return }

        try bindAndStep(statement)
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw SQLiteRelayStateStoreError.step(lastError(in: db))
        }
    }

    private static func bindText(_ value: String, to index: Int32, in statement: OpaquePointer, db: OpaquePointer) throws {
        guard sqlite3_bind_text(statement, index, value, -1, transient) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.bind(lastError(in: db))
        }
    }

    private static func bindInt(_ value: Int, to index: Int32, in statement: OpaquePointer, db: OpaquePointer) throws {
        guard sqlite3_bind_int64(statement, index, sqlite3_int64(value)) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.bind(lastError(in: db))
        }
    }

    private static func bindDouble(_ value: Double, to index: Int32, in statement: OpaquePointer, db: OpaquePointer) throws {
        guard sqlite3_bind_double(statement, index, value) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.bind(lastError(in: db))
        }
    }

    private static func bindBlob(_ value: Data, to index: Int32, in statement: OpaquePointer, db: OpaquePointer) throws {
        let bindResult = value.withUnsafeBytes { buffer in
            sqlite3_bind_blob(statement, index, buffer.baseAddress, Int32(buffer.count), transient)
        }
        guard bindResult == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.bind(lastError(in: db))
        }
    }

    private static func readText(_ statement: OpaquePointer, column: Int32, in db: OpaquePointer) throws -> String {
        guard let cString = sqlite3_column_text(statement, column) else {
            throw SQLiteRelayStateStoreError.step(lastError(in: db))
        }
        return String(cString: cString)
    }

    private static func readBlob(_ statement: OpaquePointer, column: Int32) throws -> Data {
        let byteCount = Int(sqlite3_column_bytes(statement, column))
        guard byteCount > 0,
              byteCount <= 32 * 1024 * 1024,
              let bytes = sqlite3_column_blob(statement, column) else {
            throw SQLiteRelayStateStoreError.corrupt("empty or oversized blob")
        }
        return Data(bytes: bytes, count: byteCount)
    }

    private static func encode<T: Encodable>(_ value: T) throws -> Data {
        try NoctweaveCoder.encode(value)
    }

    private static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try NoctweaveCoder.decode(type, from: data)
    }

    private static func execute(_ sql: String, in db: OpaquePointer) throws {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.execute(lastError(in: db))
        }
    }

    private static func lastError(in db: OpaquePointer) -> String {
        guard let cString = sqlite3_errmsg(db) else {
            return "Unknown sqlite error"
        }
        return String(cString: cString)
    }
}

enum RelayStoreError: Error, Equatable {
    case invalidRendezvousRoute
    case rendezvousRouteUnavailable
    case rendezvousRegistrationConflict
    case rendezvousCapacityReached
    case rendezvousFrameConflict
    case rendezvousSequenceGap
    case rendezvousQuotaReached
    case relayCapacityExceeded
    case invalidChunkIndex
    case invalidAttachmentPayload
    case invalidAttachmentIdempotency
    case attachmentConflict
}

enum RelayStorePersistenceError: Error {
    case injectedFailure
    case invalidCurrentState
}

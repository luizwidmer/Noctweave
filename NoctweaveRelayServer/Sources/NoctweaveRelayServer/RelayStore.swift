import Crypto
import Foundation
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite
#endif

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
    case attachmentBlobUnavailable
}

enum RelayStorePersistenceError: Error {
    case injectedFailure
    case invalidCurrentState
}

final class RelayStore {
    /// Keyed by a domain-separated route-capability digest. Values contain
    /// only digests of lane authorities; raw bearer material is never stored.
    private var rendezvousRoutesV2: [String: RendezvousRelayRouteRecordV2] = [:]
    private var opaqueRouteRuntimeV2 = OpaqueRouteRuntimeStateV2()
    private var attachments: [String: [AttachmentRecord]] = [:]
    private var federationNodes: [String: FederationNodeRecord] = [:]
    private var coordinatorPinnedPublicKeys: [String: Data] = [:]
    private var openFederationDHTCache = OpenFederationDHTCandidateCache(
        configuration: OpenFederationDHTDiscoveryConfiguration(isEnabled: false)
    )
    private let queue = DispatchQueue(label: "noctweave.relay.store")
    private let fileURL: URL?
    private let attachmentBlobStore: AttachmentBlobStore?
    private var temporalBuckets: [TimeInterval]
    private let queueKey = DispatchSpecificKey<Void>()
    private let attachmentTTL: TimeInterval = 3600
    private let minimumAttachmentTTL: TimeInterval = 60
    private let maximumAttachmentTTL: TimeInterval = 6 * 3600
    private let maxAttachmentChunks = 512
    private let maxAttachmentChunkPayloadBytes = 128 * 1024
    private let maxAttachmentIds = 4_096
    private let coordinatorDefaultNodeTTL: TimeInterval = 180
    private let coordinatorMaximumNodeTTL: TimeInterval = 900
    private let maxFederationNodes = 10_000
    private let maxActiveRendezvousRoutesV2 = 2_048
    private let maxLifetimeRendezvousRoutesV2 = 100_000
    private var coordinatorDirectoryCache: [FederationNodeRecord] = []
    private var generalRequestAttemptsBySource: [String: [Date]] = [:]
    private var federationRegistrationAttemptsBySource: [String: [Date]] = [:]
    private var federationListAttemptsBySource: [String: [Date]] = [:]
    private var lastFederationRegistrationByEndpoint: [String: Date] = [:]
    private var lastDurableSnapshot = RelayStoreSnapshot.empty
    private var persistenceFailuresRemainingForTesting = 0
    private let federationRateWindowSeconds: TimeInterval = 60
    private let generalRequestRateWindowSeconds: TimeInterval = 60
    private let generalRequestMaxPerWindow = 240
    private let generalRequestMaxSources = 10_000
    private let federationRegistrationMaxPerWindow = 24
    private let federationListMaxPerWindow = 120
    private let federationRegistrationMinEndpointIntervalSeconds: TimeInterval = 15

    init(
        fileURL: URL?,
        attachmentBlobStore: AttachmentBlobStore? = nil,
        temporalBucketSeconds: Int = 300,
        temporalBucketScheduleSeconds: [Int]? = nil
    ) {
        self.fileURL = fileURL
        self.attachmentBlobStore = attachmentBlobStore
        self.temporalBuckets = RelayStore.normalizeBuckets(
            primarySeconds: temporalBucketSeconds,
            scheduleSeconds: temporalBucketScheduleSeconds
        )
        queue.setSpecific(key: queueKey, value: ())
    }

    func load() throws {
        guard let fileURL else {
            return
        }
        try performSync {
            let sqliteURL = sqliteStoreURL(for: fileURL)
            if let snapshot = try SQLiteRelayStateStore.loadState(at: sqliteURL) {
                try validateCurrentSnapshot(snapshot)
                applySnapshot(snapshot)
                lastDurableSnapshot = currentSnapshot()
            }
        }
    }

    func updateTemporalBuckets(primarySeconds: Int, scheduleSeconds: [Int]?) {
        performSync {
            temporalBuckets = RelayStore.normalizeBuckets(
                primarySeconds: primarySeconds,
                scheduleSeconds: scheduleSeconds
            )
        }
    }

    func save() throws {
        guard fileURL != nil else {
            return
        }
        try performSync {
            try saveLocked()
        }
    }

    /// Deterministic persistence fault injection used by `@testable` regression
    /// tests. The counter is deliberately outside the durable snapshot so one
    /// failed attempt is consumed before an exact retry.
    func failNextPersistenceForTesting(_ count: Int = 1) {
        performSync {
            persistenceFailuresRemainingForTesting = max(0, count)
        }
    }

    func createOpaqueRouteV2(
        _ submission: OpaqueRouteCreateSubmissionV2,
        confidentialTransport: Bool,
        receivedAt: Date = Date()
    ) throws -> OpaqueReceiveRouteV2 {
        try performSync {
            let route = try opaqueRouteRuntimeV2.create(
                submission,
                confidentialTransport: confidentialTransport,
                receivedAt: receivedAt
            )
            try saveLocked()
            return route
        }
    }

    func renewOpaqueRouteV2(
        _ submission: OpaqueRouteRenewSubmissionV2,
        confidentialTransport: Bool,
        receivedAt: Date = Date()
    ) throws -> OpaqueReceiveRouteV2 {
        try performSync {
            let route = try opaqueRouteRuntimeV2.renew(
                submission,
                confidentialTransport: confidentialTransport,
                receivedAt: receivedAt
            )
            try saveLocked()
            return route
        }
    }

    func teardownOpaqueRouteV2(
        _ submission: OpaqueRouteTeardownSubmissionV2,
        confidentialTransport: Bool,
        receivedAt: Date = Date()
    ) throws -> OpaqueReceiveRouteV2 {
        try performSync {
            let route = try opaqueRouteRuntimeV2.teardown(
                submission,
                confidentialTransport: confidentialTransport,
                receivedAt: receivedAt
            )
            try saveLocked()
            return route
        }
    }

    func appendOpaqueRouteV2(
        _ submission: OpaqueRouteAppendSubmissionV2,
        confidentialTransport: Bool,
        receivedAt: Date = Date()
    ) throws -> OpaqueRouteAppendReceiptV2 {
        try performSync {
            let receipt = try opaqueRouteRuntimeV2.append(
                submission,
                confidentialTransport: confidentialTransport,
                receivedAt: receivedAt
            )
            try saveLocked()
            return receipt
        }
    }

    func syncOpaqueRouteV2(
        _ submission: OpaqueRouteSyncSubmissionV2,
        confidentialTransport: Bool,
        receivedAt: Date = Date()
    ) throws -> OpaqueRouteSyncResponseV2 {
        try performSync {
            let response = try opaqueRouteRuntimeV2.sync(
                submission,
                confidentialTransport: confidentialTransport,
                receivedAt: receivedAt
            )
            try saveLocked()
            return response
        }
    }

    func commitOpaqueRouteV2(
        _ submission: OpaqueRouteCommitSubmissionV2,
        confidentialTransport: Bool,
        receivedAt: Date = Date()
    ) throws -> OpaqueRouteCommitResponseV2 {
        try performSync {
            let response = try opaqueRouteRuntimeV2.commit(
                submission,
                confidentialTransport: confidentialTransport,
                receivedAt: receivedAt
            )
            try saveLocked()
            return response
        }
    }

    func ingestOpenFederationDHTRecords(
        _ records: [OpenFederationDHTRecord],
        configuration: OpenFederationDHTDiscoveryConfiguration,
        now: Date = Date()
    ) -> OpenFederationDHTDiscoveryIngestResult {
        performSync {
            openFederationDHTCache.configuration = configuration
            return openFederationDHTCache.ingest(records, now: now)
        }
    }

    func listOpenFederationDHTRecords(
        configuration: OpenFederationDHTDiscoveryConfiguration,
        now: Date = Date(),
        limit: Int?
    ) -> [OpenFederationDHTRecord] {
        performSync {
            openFederationDHTCache.configuration = configuration
            openFederationDHTCache.evictExpired(now: now)
            let boundedLimit = max(0, min(limit ?? configuration.maxQueryRecords, configuration.maxQueryRecords))
            guard boundedLimit > 0 else {
                return []
            }
            return Array(openFederationDHTCache.records(now: now).prefix(boundedLimit))
        }
    }

    func storeAttachment(
        attachmentId: UUID,
        chunkIndex: Int,
        payload: EncryptedPayload,
        ttlSeconds: Int?
    ) throws -> AttachmentChunk {
        try performSync {
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
            pruneAttachmentsLocked(now: Date())
            let ttl = boundedAttachmentTTL(ttlSeconds)
            let now = Date()
            let bucketKey = "attachment:\(attachmentId.uuidString):\(chunkIndex)"
            let storedAt = bucketed(now, discriminator: bucketKey)
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
            let record: AttachmentRecord
            if let attachmentBlobStore {
                let encodedPayload = try RelayCodec.encoder().encode(payload)
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
                    expiresAt: expiresAt
                )
            } else {
                record = AttachmentRecord(
                    chunkIndex: chunkIndex,
                    payload: payload,
                    external: nil,
                    storedAt: storedAt,
                    expiresAt: expiresAt
                )
            }
            if let attachmentKeyToEvict,
               let evicted = attachments.removeValue(forKey: attachmentKeyToEvict) {
                deferredExternalDeletions.append(contentsOf: evicted.compactMap(\.external))
            }
            if let existing = records.first(where: { $0.chunkIndex == chunkIndex }),
               let external = existing.external {
                deferredExternalDeletions.append(external)
            }
            if let index = records.firstIndex(where: { $0.chunkIndex == chunkIndex }) {
                records[index] = record
            } else {
                records.append(record)
            }
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
                try saveLocked()
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
    }

    func fetchAttachment(attachmentId: UUID, chunkIndex: Int) throws -> AttachmentChunk? {
        try performSync {
            guard chunkIndex >= 0 else {
                throw RelayStoreError.invalidChunkIndex
            }
            pruneAttachmentsLocked(now: Date())
            let key = attachmentId.uuidString
            guard let records = attachments[key],
                  let record = records.first(where: { $0.chunkIndex == chunkIndex }) else {
                return nil
            }
            let payload = try payload(for: record)
            return AttachmentChunk(attachmentId: attachmentId, chunkIndex: chunkIndex, payload: payload)
        }
    }


    func registerRendezvousTransportV2(
        _ request: RegisterRendezvousTransportV2Request,
        now: Date = Date()
    ) throws {
        try performSync {
            guard request.isStructurallyValid(at: now) else {
                throw RelayStoreError.invalidRendezvousRoute
            }
            if retireExpiredRendezvousRoutesV2Locked(now: now) {
                try saveLocked()
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
            try saveLocked()
        }
    }

    @discardableResult
    func appendRendezvousTransportV2(
        _ request: AppendRendezvousTransportV2Request,
        now: Date = Date()
    ) throws -> UInt64 {
        try performSync {
            guard request.isStructurallyValid else {
                throw RelayStoreError.invalidRendezvousRoute
            }
            if retireExpiredRendezvousRoutesV2Locked(now: now) {
                try saveLocked()
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
            try saveLocked()
            return request.frame.sequence
        }
    }

    func syncRendezvousTransportV2(
        _ request: SyncRendezvousTransportV2Request,
        now: Date = Date()
    ) throws -> RendezvousRelaySyncBatchV2 {
        try performSync {
            guard request.isStructurallyValid else {
                throw RelayStoreError.invalidRendezvousRoute
            }
            if retireExpiredRendezvousRoutesV2Locked(now: now) {
                try saveLocked()
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
    }

    func deleteRendezvousTransportV2(
        _ request: DeleteRendezvousTransportV2Request,
        now: Date = Date()
    ) throws {
        try performSync {
            guard request.isStructurallyValid,
                  now.timeIntervalSince1970.isFinite else {
                throw RelayStoreError.invalidRendezvousRoute
            }
            if retireExpiredRendezvousRoutesV2Locked(now: now) {
                try saveLocked()
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
            try saveLocked()
        }
    }

    func rendezvousRouteRecordCountV2() -> Int {
        performSync { rendezvousRoutesV2.count }
    }


    func registerFederationNode(_ request: FederationNodeRegistrationRequest) throws -> FederationNodeRecord {
        try performSync {
            let now = Date()
            pruneFederationNodesLocked(now: now)
            let ttl = TimeInterval(request.ttlSeconds ?? Int(coordinatorDefaultNodeTTL))
            let expiresAt = now.addingTimeInterval(min(coordinatorMaximumNodeTTL, max(30, ttl)))
            let key = federationNodeKey(request.endpoint)
            guard federationNodes[key] != nil || federationNodes.count < maxFederationNodes else {
                throw RelayStoreError.relayCapacityExceeded
            }
            let record = FederationNodeRecord(
                endpoint: request.endpoint,
                relayInfo: request.relayInfo,
                lastHeartbeatAt: now,
                expiresAt: expiresAt
            )
            federationNodes[key] = record
            pruneFederationNodesLocked(now: now)
            try saveLocked()
            return record
        }
    }

    func allowFederationRegistration(
        sourceKey: String,
        endpoint: RelayEndpoint,
        now: Date = Date()
    ) -> Bool {
        performSync {
            pruneFederationRateLimitsLocked(now: now)
            let source = normalizedFederationSourceKey(sourceKey)
            let endpointKey = federationNodeKey(endpoint)
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
    }

    func allowFederationDirectoryList(
        sourceKey: String,
        now: Date = Date()
    ) -> Bool {
        performSync {
            pruneFederationRateLimitsLocked(now: now)
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
    }

    func allowRelayRequest(sourceKey: String, now: Date = Date()) -> Bool {
        performSync {
            pruneGeneralRequestRateLimitsLocked(now: now)
            let source = normalizedFederationSourceKey(sourceKey)
            var attempts = generalRequestAttemptsBySource[source, default: []]
            guard attempts.count < generalRequestMaxPerWindow else {
                generalRequestAttemptsBySource[source] = attempts
                return false
            }
            if generalRequestAttemptsBySource[source] == nil,
               generalRequestAttemptsBySource.count >= generalRequestMaxSources,
               let oldestSource = generalRequestAttemptsBySource.min(by: {
                   ($0.value.first ?? now) < ($1.value.first ?? now)
               })?.key {
                generalRequestAttemptsBySource.removeValue(forKey: oldestSource)
            }
            attempts.append(now)
            generalRequestAttemptsBySource[source] = attempts
            return true
        }
    }

    func listFederationNodes(_ request: ListFederationNodesRequest?) -> [FederationNodeRecord] {
        performSync {
            let now = Date()
            pruneFederationNodesLocked(now: now)
            var nodes = Array(federationNodes.values)
            if let mode = request?.mode {
                nodes = nodes.filter { $0.relayInfo.federation.mode == mode }
            }
            if let name = request?.federationName?.trimmingCharacters(in: .whitespacesAndNewlines),
               !name.isEmpty {
                nodes = nodes.filter { $0.relayInfo.federation.name == name }
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
                return federationNodeKey(lhs.endpoint) < federationNodeKey(rhs.endpoint)
            }
        }
    }

    func pinnedCoordinatorPublicKey(for endpoint: RelayEndpoint) -> Data? {
        performSync {
            coordinatorPinnedPublicKeys[federationNodeKey(endpoint)]
        }
    }

    func pinCoordinatorPublicKey(_ key: Data, for endpoint: RelayEndpoint) throws {
        try performSync {
            coordinatorPinnedPublicKeys[federationNodeKey(endpoint)] = key
            try saveLocked()
        }
    }

    func setCoordinatorDirectoryCache(_ nodes: [FederationNodeRecord]) {
        performSync {
            coordinatorDirectoryCache = nodes
        }
    }

    func coordinatorDirectoryCacheSnapshot() -> [FederationNodeRecord] {
        performSync {
            coordinatorDirectoryCache
        }
    }


    private func validateCurrentSnapshot(_ snapshot: RelayStoreSnapshot) throws {
        guard snapshot.version == RelayStoreSnapshot.schemaVersion,
              snapshot.opaqueRouteRuntimeV2.isStructurallyValid,
              snapshot.rendezvousRoutesV2.allSatisfy({ key, record in
                  Data(base64Encoded: key)?.count == SHA256.byteCount
                      && record.isStructurallyValid
              }),
              snapshot.attachments.allSatisfy({ _, records in
                  records.allSatisfy {
                      $0.chunkIndex >= 0
                          && $0.storedAt.timeIntervalSince1970.isFinite
                          && $0.expiresAt.timeIntervalSince1970.isFinite
                          && $0.expiresAt >= $0.storedAt
                          && (($0.payload != nil) != ($0.external != nil))
                  }
              }),
              snapshot.federationNodes.allSatisfy({ _, record in
                  record.lastHeartbeatAt.timeIntervalSince1970.isFinite
                      && record.expiresAt.timeIntervalSince1970.isFinite
              }) else {
            throw RelayStorePersistenceError.invalidCurrentState
        }
    }

    private func performSync<T>(_ block: () throws -> T) rethrows -> T {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            return try block()
        }
        return try queue.sync {
            try block()
        }
    }

    private func saveLocked() throws {
        guard let fileURL else {
            return
        }
        do {
            if persistenceFailuresRemainingForTesting > 0 {
                persistenceFailuresRemainingForTesting -= 1
                throw RelayStorePersistenceError.injectedFailure
            }
            pruneAttachmentsLocked(now: Date())
            let snapshot = currentSnapshot()
            try validateCurrentSnapshot(snapshot)
            try SQLiteRelayStateStore.saveState(snapshot, at: sqliteStoreURL(for: fileURL))
            lastDurableSnapshot = snapshot
        } catch {
            restoreSnapshot(lastDurableSnapshot)
            throw error
        }
    }

    private func applySnapshot(_ snapshot: RelayStoreSnapshot) {
        rendezvousRoutesV2 = snapshot.rendezvousRoutesV2
        opaqueRouteRuntimeV2 = snapshot.opaqueRouteRuntimeV2
        attachments = snapshot.attachments
        federationNodes = snapshot.federationNodes
        coordinatorPinnedPublicKeys = snapshot.coordinatorPinnedPublicKeys
        pruneAttachmentsLocked(now: Date())
        pruneFederationNodesLocked(now: Date())
        normalizeRendezvousRoutesV2AfterLoadLocked()
    }

    private func restoreSnapshot(_ snapshot: RelayStoreSnapshot) {
        rendezvousRoutesV2 = snapshot.rendezvousRoutesV2
        opaqueRouteRuntimeV2 = snapshot.opaqueRouteRuntimeV2
        attachments = snapshot.attachments
        federationNodes = snapshot.federationNodes
        coordinatorPinnedPublicKeys = snapshot.coordinatorPinnedPublicKeys
    }

    private func currentSnapshot() -> RelayStoreSnapshot {
        RelayStoreSnapshot(
            rendezvousRoutesV2: rendezvousRoutesV2,
            opaqueRouteRuntimeV2: opaqueRouteRuntimeV2,
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

    private func pruneAttachmentsLocked(now: Date) {
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
        let requested = TimeInterval(ttlSeconds ?? Int(attachmentTTL))
        return min(maximumAttachmentTTL, max(minimumAttachmentTTL, requested))
    }

    private func payload(for record: AttachmentRecord) throws -> EncryptedPayload {
        if let payload = record.payload {
            return payload
        }
        guard let external = record.external,
              let attachmentBlobStore,
              external.backend == attachmentBlobStore.backendName else {
            throw RelayStoreError.attachmentBlobUnavailable
        }
        let data = try attachmentBlobStore.get(external)
        return try RelayCodec.decoder().decode(EncryptedPayload.self, from: data)
    }

    private func deleteExternalAttachmentIfUnreferenced(_ external: AttachmentExternalRecord) {
        let isReferenced = attachments.values.contains { records in
            records.contains { $0.external == external }
        }
        if !isReferenced {
            attachmentBlobStore?.delete(external)
        }
    }

    private func pruneFederationNodesLocked(now: Date) {
        federationNodes = federationNodes.filter { $0.value.expiresAt > now }
        if federationNodes.count > maxFederationNodes {
            let retained = federationNodes
                .sorted { lhs, rhs in lhs.value.lastHeartbeatAt > rhs.value.lastHeartbeatAt }
                .prefix(maxFederationNodes)
            federationNodes = Dictionary(uniqueKeysWithValues: retained.map { ($0.key, $0.value) })
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


    private static func fnv1a64<S: Sequence>(_ bytes: S) -> UInt64 where S.Element == UInt8 {
        var hash: UInt64 = 14695981039346656037
        for byte in bytes {
            hash ^= UInt64(byte)
            hash &*= 1099511628211
        }
        return hash
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

    private func federationNodeKey(_ endpoint: RelayEndpoint) -> String {
        "\(endpoint.host.lowercased()):\(endpoint.port):\(endpoint.useTLS ? 1 : 0):\(endpoint.transport.rawValue)"
    }

    private func normalizedFederationSourceKey(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return trimmed.isEmpty ? "unknown" : trimmed
    }

    private func pruneFederationRateLimitsLocked(now: Date) {
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

    private func pruneGeneralRequestRateLimitsLocked(now: Date) {
        let cutoff = now.addingTimeInterval(-generalRequestRateWindowSeconds)
        generalRequestAttemptsBySource = generalRequestAttemptsBySource.compactMapValues { attempts in
            let filtered = attempts.filter { $0 >= cutoff }
            return filtered.isEmpty ? nil : filtered
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
    private func retireExpiredRendezvousRoutesV2Locked(now: Date) -> Bool {
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

    private func normalizeRendezvousRoutesV2AfterLoadLocked(now: Date = Date()) {
        rendezvousRoutesV2 = rendezvousRoutesV2.filter { key, record in
            guard let digest = Data(base64Encoded: key),
                  digest.count == SHA256.byteCount,
                  record.isStructurallyValid else {
                return false
            }
            return true
        }
        _ = retireExpiredRendezvousRoutesV2Locked(now: now)
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
    static let schemaVersion = 1

    let version: Int
    let rendezvousRoutesV2: [String: RendezvousRelayRouteRecordV2]
    let opaqueRouteRuntimeV2: OpaqueRouteRuntimeStateV2
    let attachments: [String: [AttachmentRecord]]
    let federationNodes: [String: FederationNodeRecord]
    let coordinatorPinnedPublicKeys: [String: Data]

    static let empty = RelayStoreSnapshot(
        version: schemaVersion,
        rendezvousRoutesV2: [:],
        opaqueRouteRuntimeV2: OpaqueRouteRuntimeStateV2(),
        attachments: [:],
        federationNodes: [:],
        coordinatorPinnedPublicKeys: [:]
    )

    init(
        version: Int = schemaVersion,
        rendezvousRoutesV2: [String: RendezvousRelayRouteRecordV2],
        opaqueRouteRuntimeV2: OpaqueRouteRuntimeStateV2,
        attachments: [String: [AttachmentRecord]],
        federationNodes: [String: FederationNodeRecord],
        coordinatorPinnedPublicKeys: [String: Data]
    ) {
        self.version = version
        self.rendezvousRoutesV2 = rendezvousRoutesV2
        self.opaqueRouteRuntimeV2 = opaqueRouteRuntimeV2
        self.attachments = attachments
        self.federationNodes = federationNodes
        self.coordinatorPinnedPublicKeys = coordinatorPinnedPublicKeys
    }
}

private struct AttachmentRecord: Codable {
    let chunkIndex: Int
    let payload: EncryptedPayload?
    let external: AttachmentExternalRecord?
    let storedAt: Date
    let expiresAt: Date
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
    private static let tableName = "relay_runtime_state_v1"
    private static let schemaVersion = RelayStoreSnapshot.schemaVersion
    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    static func loadState(at url: URL) throws -> RelayStoreSnapshot? {
        let existedBeforeOpen = FileManager.default.fileExists(atPath: url.path)
        var database: OpaquePointer?
        try openDatabase(at: url, handle: &database)
        defer { sqlite3_close(database) }
        guard let database else { return nil }

        if existedBeforeOpen, try !tableExists(in: database) {
            throw RelayStorePersistenceError.invalidCurrentState
        }
        try ensureSchema(in: database)
        let sql = "SELECT schema_version, snapshot FROM \(tableName) WHERE singleton = 1;"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK,
              let statement else {
            throw SQLiteRelayStateStoreError.prepare(lastError(in: database))
        }
        defer { sqlite3_finalize(statement) }

        switch sqlite3_step(statement) {
        case SQLITE_DONE:
            if existedBeforeOpen {
                throw RelayStorePersistenceError.invalidCurrentState
            }
            return nil
        case SQLITE_ROW:
            guard sqlite3_column_int(statement, 0) == Int32(schemaVersion) else {
                throw RelayStorePersistenceError.invalidCurrentState
            }
            let count = Int(sqlite3_column_bytes(statement, 1))
            guard count > 0, let bytes = sqlite3_column_blob(statement, 1) else {
                throw SQLiteRelayStateStoreError.corrupt("Missing runtime snapshot")
            }
            let data = Data(bytes: bytes, count: count)
            let snapshot: RelayStoreSnapshot
            do {
                snapshot = try RelayCodec.decoder().decode(RelayStoreSnapshot.self, from: data)
            } catch {
                throw SQLiteRelayStateStoreError.corrupt("Runtime snapshot decoding failed")
            }
            guard snapshot.version == schemaVersion else {
                throw RelayStorePersistenceError.invalidCurrentState
            }
            return snapshot
        default:
            throw SQLiteRelayStateStoreError.step(lastError(in: database))
        }
    }

    static func saveState(_ snapshot: RelayStoreSnapshot, at url: URL) throws {
        guard snapshot.version == schemaVersion else {
            throw RelayStorePersistenceError.invalidCurrentState
        }
        var database: OpaquePointer?
        try openDatabase(at: url, handle: &database)
        defer { sqlite3_close(database) }
        guard let database else {
            throw SQLiteRelayStateStoreError.openDatabase("Database handle unavailable")
        }

        try ensureSchema(in: database)
        let data = try RelayCodec.encoder(sortedKeys: true).encode(snapshot)
        try execute("BEGIN IMMEDIATE TRANSACTION;", in: database)
        do {
            let sql = """
            INSERT INTO \(tableName) (singleton, schema_version, snapshot)
            VALUES (1, ?, ?)
            ON CONFLICT(singleton) DO UPDATE SET
                schema_version = excluded.schema_version,
                snapshot = excluded.snapshot;
            """
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK,
                  let statement else {
                throw SQLiteRelayStateStoreError.prepare(lastError(in: database))
            }
            defer { sqlite3_finalize(statement) }
            guard sqlite3_bind_int(statement, 1, Int32(schemaVersion)) == SQLITE_OK else {
                throw SQLiteRelayStateStoreError.bind(lastError(in: database))
            }
            let bindResult = data.withUnsafeBytes { bytes in
                sqlite3_bind_blob(
                    statement,
                    2,
                    bytes.baseAddress,
                    Int32(data.count),
                    transient
                )
            }
            guard bindResult == SQLITE_OK else {
                throw SQLiteRelayStateStoreError.bind(lastError(in: database))
            }
            guard sqlite3_step(statement) == SQLITE_DONE else {
                throw SQLiteRelayStateStoreError.step(lastError(in: database))
            }
            try execute("COMMIT;", in: database)
        } catch {
            try? execute("ROLLBACK;", in: database)
            throw error
        }
    }

    private static func openDatabase(at url: URL, handle: inout OpaquePointer?) throws {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let flags = SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(url.path, &handle, flags, nil) == SQLITE_OK,
              let database = handle else {
            let message = handle.flatMap { sqlite3_errmsg($0).map(String.init(cString:)) }
                ?? "Unknown sqlite error"
            if let opened = handle {
                sqlite3_close(opened)
                handle = nil
            }
            throw SQLiteRelayStateStoreError.openDatabase(message)
        }
        sqlite3_busy_timeout(database, 5_000)
    }

    private static func ensureSchema(in database: OpaquePointer) throws {
        try execute(
            """
            CREATE TABLE IF NOT EXISTS \(tableName) (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL CHECK (schema_version = \(schemaVersion)),
                snapshot BLOB NOT NULL
            );
            """,
            in: database
        )
    }

    private static func tableExists(in database: OpaquePointer) throws -> Bool {
        let sql = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1;"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK,
              let statement else {
            throw SQLiteRelayStateStoreError.prepare(lastError(in: database))
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_bind_text(statement, 1, tableName, -1, transient) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.bind(lastError(in: database))
        }
        switch sqlite3_step(statement) {
        case SQLITE_ROW:
            return true
        case SQLITE_DONE:
            return false
        default:
            throw SQLiteRelayStateStoreError.step(lastError(in: database))
        }
    }

    private static func execute(_ sql: String, in database: OpaquePointer) throws {
        guard sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.execute(lastError(in: database))
        }
    }

    private static func lastError(in database: OpaquePointer) -> String {
        guard let value = sqlite3_errmsg(database) else {
            return "Unknown sqlite error"
        }
        return String(cString: value)
    }
}

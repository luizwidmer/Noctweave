import CryptoKit
import Foundation
import SQLite3

public actor RelayStore {
    private var mailboxes: [String: [StoredEnvelope]] = [:]
    private var inboxRegistrations: [String: InboxRegistrationRecord] = [:]
    private var inboxRetirements: [String: InboxRetirementRecord] = [:]
    /// Keyed by the base64 form of the domain-separated capability digest.
    /// Raw bearer capabilities are never persisted.
    private var inboxRouteCapabilities: [String: InboxRouteCapabilityRecord] = [:]
    /// Keyed by a domain-separated route-capability digest. Values contain
    /// only digests of lane authorities; raw bearer material is never stored.
    private var rendezvousRoutesV2: [String: RendezvousRelayRouteRecordV2] = [:]
    private var attachments: [String: [AttachmentRecord]] = [:]
    private var federationNodes: [String: FederationNodeRecord] = [:]
    private var coordinatorPinnedPublicKeys: [String: Data] = [:]
    private var openFederationDHTCache = OpenFederationDHTCandidateCache(
        configuration: OpenFederationDHTDiscoveryConfiguration(isEnabled: false)
    )
    private var actorProofReplayCache: [String: Date] = [:]
    private var federationRegistrationAttemptsBySource: [String: [Date]] = [:]
    private var federationListAttemptsBySource: [String: [Date]] = [:]
    private var lastFederationRegistrationByEndpoint: [String: Date] = [:]
    private var lastDurableSnapshot = RelayStoreSnapshot.empty
    private var persistenceFailuresRemainingForTesting = 0
    private let attachmentTTL: TimeInterval = 3600
    private let minimumAttachmentTTL: TimeInterval = 60
    private let maximumAttachmentTTL: TimeInterval = 6 * 3600
    private let maxAttachmentChunks = 512
    private let maxAttachmentChunkPayloadBytes = 128 * 1024
    private let maxEnvelopePayloadBytes = 96 * 1024
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
    private let maxInboxMessages: Int
    private let maxMailboxes = 10_000
    private let maxStoredMessages = 100_000
    private let maxInboxRegistrations = 10_000
    /// Exact non-resurrection has a storage lower bound. New generations stop
    /// being admitted at this lifetime ceiling; retirement records are never
    /// evicted, and every admitted live generation has a reserved slot.
    private let maxLifetimeInboxGenerations: Int
    private let maxActorProofReplayEntries = 20_000
    private let maxActiveInboxRouteCapabilitiesPerInbox = 16
    private let maxRevokedInboxRouteCapabilitiesPerInbox = 64
    private let maxInboxRouteCapabilityRecords = 100_000
    private let maxActiveRendezvousRoutesV2 = 2_048
    private let maxLifetimeRendezvousRoutesV2 = 100_000

    public init(
        storeURL: URL? = nil,
        temporalBucketSeconds: Int = 300,
        temporalBucketScheduleSeconds: [Int]? = nil,
        attachmentBlobStore: AttachmentBlobStore? = nil,
        maxInboxMessages: Int = 1_000,
        maxLifetimeInboxGenerations: Int = 100_000
    ) {
        self.storeURL = storeURL
        self.attachmentBlobStore = attachmentBlobStore
        self.maxInboxMessages = max(1, maxInboxMessages)
        self.maxLifetimeInboxGenerations = max(1, maxLifetimeInboxGenerations)
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
    ) -> OpenFederationDHTDiscoveryIngestResult {
        openFederationDHTCache.configuration = configuration
        return openFederationDHTCache.ingest(records, now: now)
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

    public func consumeActorProofNonce(
        fingerprint: String,
        nonce: UUID,
        now: Date = Date(),
        maxAgeSeconds: TimeInterval = 300
    ) -> Bool {
        let normalizedFingerprint = fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedFingerprint.isEmpty else {
            return false
        }
        let retentionWindow = max(30, maxAgeSeconds)
        let expirationCutoff = now.addingTimeInterval(-retentionWindow)
        actorProofReplayCache = actorProofReplayCache.filter { $0.value > expirationCutoff }
        let key = "\(normalizedFingerprint):\(nonce.uuidString.lowercased())"
        guard actorProofReplayCache[key] == nil else {
            return false
        }
        // Never evict an unexpired nonce: doing so would reopen its proof for
        // replay. Saturation fails closed until an entry expires.
        guard actorProofReplayCache.count < maxActorProofReplayEntries else {
            return false
        }
        actorProofReplayCache[key] = now
        return true
    }

    @discardableResult
    public func deliver(_ envelope: ProtocolEnvelopeV1, to inboxId: String) throws -> Int {
        guard envelope.isStructurallyValid,
              envelopePayloadBytes(envelope) <= maxEnvelopePayloadBytes else {
            throw RelayStoreError.invalidEnvelopePayload
        }
        guard !isInboxRetired(inboxId: inboxId) else {
            throw RelayStoreError.inboxRetired
        }
        guard inboxRegistrations[inboxId] != nil else {
            throw RelayStoreError.destinationInboxNotRegistered
        }
        if mailboxes[inboxId] == nil, mailboxes.count >= maxMailboxes {
            throw RelayStoreError.relayCapacityExceeded
        }
        var inbox = mailboxes[inboxId, default: []]
        if let existing = inbox.first(where: { $0.envelope.id == envelope.id }) {
            guard existing.envelope == envelope else {
                throw RelayStoreError.invalidEnvelopePayload
            }
            return inbox.count
        }
        let totalMessages = mailboxes.values.reduce(into: 0) { $0 += $1.count }
        guard totalMessages < maxStoredMessages else {
            throw RelayStoreError.relayCapacityExceeded
        }
        guard inbox.count < maxInboxMessages else {
            throw RelayStoreError.inboxFull
        }
        let sequence = try allocateMailboxSequence(for: inboxId)
        let discriminator = "\(inboxId):\(envelope.id.uuidString)"
        inbox.append(
            StoredEnvelope(
                sequence: sequence,
                envelope: envelope,
                storedAt: bucketed(Date(), discriminator: discriminator)
            )
        )
        mailboxes[inboxId] = inbox
        try saveToDisk()
        return inbox.count
    }

    public func fetch(inboxId: String, maxCount: Int? = nil) throws -> [ProtocolEnvelopeV1] {
        let inbox = mailboxes[inboxId, default: []]
        let count = max(0, maxCount ?? inbox.count)
        return Array(inbox.prefix(count)).map { $0.envelope }
    }

    public func registerInbox(
        inboxId: String,
        accessPublicKey: Data
    ) throws -> InboxRegistrationReceiptV3 {
        guard InboxAddress.isValid(inboxId), !accessPublicKey.isEmpty else {
            throw RelayStoreError.invalidInboxRegistration
        }
        guard !isInboxRetired(inboxId: inboxId) else {
            throw RelayStoreError.inboxRetired
        }
        if let existing = inboxRegistrations[inboxId] {
            guard existing.accessPublicKey == accessPublicKey else {
                throw RelayStoreError.inboxAlreadyRegistered
            }
            return existing.routeMutationReceipt
        }
        guard inboxRegistrations.count + inboxRetirements.count < maxLifetimeInboxGenerations else {
            throw RelayStoreError.relayCapacityExceeded
        }
        guard inboxRegistrations.count < maxInboxRegistrations else {
            throw RelayStoreError.relayCapacityExceeded
        }
        let registration = InboxRegistrationRecord(
            accessPublicKey: accessPublicKey,
            registeredAt: Date(),
            streamState: MailboxStreamState(
                highWatermark: mailboxes[inboxId, default: []].map(\.sequence).max() ?? 0
            )
        )
        inboxRegistrations[inboxId] = registration
        try saveToDisk()
        return registration.routeMutationReceipt
    }

    /// Registers an opaque relationship-delivery capability for a live inbox.
    /// Authentication is performed by the relay handler before this mutation.
    /// Multiple active capabilities are intentional: they permit bounded
    /// make-before-break route rotation without exposing relationship labels.
    func seedInboxRouteCapabilityForTesting(
        inboxId: String,
        capability: InboxRouteCapabilityV2,
        now: Date = Date()
    ) throws {
        try createInboxRouteCapabilityInMemory(
            inboxId: inboxId,
            capability: capability,
            now: now
        )
        try saveToDisk()
    }

    private func createInboxRouteCapabilityInMemory(
        inboxId: String,
        capability: InboxRouteCapabilityV2,
        now: Date
    ) throws {
        guard InboxAddress.isValid(inboxId),
              capability.isStructurallyValid,
              now.timeIntervalSince1970.isFinite else {
            throw RelayStoreError.invalidInboxRouteCapability
        }
        guard !isInboxRetired(inboxId: inboxId) else {
            throw RelayStoreError.inboxRetired
        }
        guard inboxRegistrations[inboxId] != nil else {
            throw RelayStoreError.destinationInboxNotRegistered
        }
        let key = inboxRouteCapabilityKey(capability)
        if let existing = inboxRouteCapabilities[key] {
            guard existing.inboxId == inboxId else {
                throw RelayStoreError.invalidInboxRouteCapability
            }
            guard existing.revokedAt == nil else {
                throw RelayStoreError.inboxRouteCapabilityRevoked
            }
            return
        }
        let activeCount = inboxRouteCapabilities.values.reduce(into: 0) { count, record in
            if record.inboxId == inboxId, record.revokedAt == nil {
                count += 1
            }
        }
        guard activeCount < maxActiveInboxRouteCapabilitiesPerInbox else {
            throw RelayStoreError.inboxRouteCapabilityLimitReached
        }
        try makeRoomForInboxRouteCapabilityRecord(
            inboxId: inboxId,
            addingRevokedRecord: false
        )
        inboxRouteCapabilities[key] = InboxRouteCapabilityRecord(
            inboxId: inboxId,
            createdAt: now,
            revokedAt: nil
        )
    }

    /// Revocation is idempotent. An authenticated revoke of an unseen value
    /// creates a bounded tombstone so a racing create cannot activate it.
    func seedInboxRouteCapabilityRevocationForTesting(
        inboxId: String,
        capability: InboxRouteCapabilityV2,
        now: Date = Date()
    ) throws {
        try revokeInboxRouteCapabilityInMemory(
            inboxId: inboxId,
            capability: capability,
            now: now
        )
        try saveToDisk()
    }

    private func revokeInboxRouteCapabilityInMemory(
        inboxId: String,
        capability: InboxRouteCapabilityV2,
        now: Date
    ) throws {
        guard InboxAddress.isValid(inboxId),
              capability.isStructurallyValid,
              now.timeIntervalSince1970.isFinite else {
            throw RelayStoreError.invalidInboxRouteCapability
        }
        guard !isInboxRetired(inboxId: inboxId) else {
            throw RelayStoreError.inboxRetired
        }
        guard inboxRegistrations[inboxId] != nil else {
            throw RelayStoreError.destinationInboxNotRegistered
        }
        let key = inboxRouteCapabilityKey(capability)
        if let existing = inboxRouteCapabilities[key] {
            guard existing.inboxId == inboxId else {
                throw RelayStoreError.invalidInboxRouteCapability
            }
            guard existing.revokedAt == nil else {
                return
            }
            evictOldestRevokedInboxRouteCapabilityIfAtLimit(inboxId: inboxId)
            inboxRouteCapabilities[key] = InboxRouteCapabilityRecord(
                inboxId: existing.inboxId,
                createdAt: existing.createdAt,
                revokedAt: now
            )
            return
        }
        try makeRoomForInboxRouteCapabilityRecord(
            inboxId: inboxId,
            addingRevokedRecord: true
        )
        inboxRouteCapabilities[key] = InboxRouteCapabilityRecord(
            inboxId: inboxId,
            createdAt: now,
            revokedAt: now
        )
    }

    /// Applies one relay-scoped route mutation and advances its inbox-local
    /// cursor in the same durable transaction. The cursor, not the generic
    /// actor-proof nonce cache, is the replay and ordering boundary.
    func applyInboxRouteCapabilityMutation(
        operation: InboxRouteCapabilityMutationOperation,
        inboxId: String,
        capability: InboxRouteCapabilityV2,
        relayScope: Data,
        mutationSequence: UInt64,
        mutationDigest: Data,
        now: Date = Date()
    ) throws -> InboxRouteCapabilityMutationApplyResult {
        guard var registration = inboxRegistrations[inboxId] else {
            throw RelayStoreError.destinationInboxNotRegistered
        }
        guard registration.routeMutationScope == relayScope,
              relayScope.isValidRouteMutationScope,
              mutationDigest.count == SHA256.byteCount,
              mutationSequence > 0,
              mutationSequence <= CreateInboxRouteCapabilityRequest.maximumMutationSequence else {
            throw RelayStoreError.invalidInboxRouteCapabilityMutation
        }
        if mutationSequence == registration.lastRouteMutationSequence {
            guard registration.lastRouteMutationDigest == mutationDigest else {
                throw RelayStoreError.inboxRouteCapabilityMutationConflict
            }
            return .replayed
        }
        guard registration.lastRouteMutationSequence
                < CreateInboxRouteCapabilityRequest.maximumMutationSequence,
              mutationSequence == registration.lastRouteMutationSequence + 1 else {
            throw RelayStoreError.inboxRouteCapabilityMutationOutOfOrder
        }

        switch operation {
        case .create:
            try createInboxRouteCapabilityInMemory(
                inboxId: inboxId,
                capability: capability,
                now: now
            )
        case .revoke:
            try revokeInboxRouteCapabilityInMemory(
                inboxId: inboxId,
                capability: capability,
                now: now
            )
        }
        registration.lastRouteMutationSequence = mutationSequence
        registration.lastRouteMutationDigest = mutationDigest
        inboxRegistrations[inboxId] = registration
        try saveToDisk()
        return .applied
    }

    /// Returns true only when this logical mutation is already the durable
    /// cursor value. Handlers use this to permit a signed idempotent replay
    /// after the ordinary proof freshness window without weakening freshness
    /// for a first application or a conflicting mutation.
    func isCurrentInboxRouteCapabilityMutation(
        inboxId: String,
        relayScope: Data,
        mutationSequence: UInt64,
        mutationDigest: Data
    ) -> Bool {
        guard let registration = inboxRegistrations[inboxId],
              registration.routeMutationScope == relayScope,
              relayScope.isValidRouteMutationScope,
              mutationSequence == registration.lastRouteMutationSequence,
              mutationDigest.count == SHA256.byteCount else {
            return false
        }
        return registration.lastRouteMutationDigest == mutationDigest
    }

    /// Resolves only live capabilities for live registered inboxes. Missing,
    /// malformed, cross-inbox, and revoked values all collapse to `nil` so the
    /// delivery handler does not allocate a mailbox or expose an oracle.
    public func resolveInboxRouteCapability(
        _ capability: InboxRouteCapabilityV2
    ) -> String? {
        guard capability.isStructurallyValid,
              let record = inboxRouteCapabilities[inboxRouteCapabilityKey(capability)],
              record.revokedAt == nil,
              inboxRegistrations[record.inboxId] != nil,
              !isInboxRetired(inboxId: record.inboxId) else {
            return nil
        }
        return record.inboxId
    }

    func inboxRouteCapabilityRecordCount() -> Int {
        inboxRouteCapabilities.count
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

    /// Atomically removes a live inbox generation and records an irreversible,
    /// route-level non-resurrection marker. Authentication is intentionally
    /// performed by the relay request handler before this mutation is entered.
    func retireInbox(
        inboxId: String,
        requestDigest: Data,
        now: Date = Date()
    ) throws {
        guard InboxAddress.isValid(inboxId),
              requestDigest.count == SHA256.byteCount,
              now.timeIntervalSince1970.isFinite else {
            throw RelayStoreError.invalidInboxRetirement
        }
        if let existing = inboxRetirements[inboxId] {
            guard existing.requestDigest == requestDigest else {
                throw RelayStoreError.invalidInboxRetirement
            }
            return
        }

        let hasReservedRegistrationSlot = inboxRegistrations[inboxId] != nil
        if !hasReservedRegistrationSlot,
           inboxRegistrations.count + inboxRetirements.count >= maxLifetimeInboxGenerations {
            throw RelayStoreError.relayCapacityExceeded
        }
        mailboxes.removeValue(forKey: inboxId)
        inboxRegistrations.removeValue(forKey: inboxId)
        inboxRouteCapabilities = inboxRouteCapabilities.filter { $0.value.inboxId != inboxId }
        inboxRetirements[inboxId] = InboxRetirementRecord(
            retiredAt: now,
            requestDigest: requestDigest
        )
        try saveToDisk()
    }

    func isInboxRetired(inboxId: String, now: Date = Date()) -> Bool {
        _ = now
        return inboxRetirements[inboxId] != nil
    }

    func isMatchingInboxRetirement(
        inboxId: String,
        requestDigest: Data,
        now: Date = Date()
    ) -> Bool {
        _ = now
        return inboxRetirements[inboxId]?.requestDigest == requestDigest
    }

    func inboxRetirementTombstoneCount(now: Date = Date()) -> Int {
        _ = now
        return inboxRetirements.count
    }

    public func inboxAccessPublicKey(for inboxId: String) -> Data? {
        inboxRegistrations[inboxId]?.accessPublicKey
    }

    /// Adds one opaque, independently revocable consumer to a mailbox stream.
    ///
    /// New endpoints normally begin at the current high watermark and obtain
    /// older history from encrypted self-sync. Tests, recovery tooling, and an
    /// explicitly authorized linking flow may request a retained earlier position.
    public func registerMailboxConsumer(
        inboxId: String,
        consumerId: MailboxConsumerId,
        consumerSigningPublicKey: Data,
        sponsorConsumerId: MailboxConsumerId? = nil,
        startingSequence: UInt64? = nil,
        now: Date = Date()
    ) throws -> MailboxConsumerRegistration {
        guard consumerId.isStructurallyValid,
              SigningKeyPair.isValidPublicKey(consumerSigningPublicKey),
              now.timeIntervalSince1970.isFinite else {
            throw MailboxSyncError.invalidConsumer
        }
        guard !isInboxRetired(inboxId: inboxId, now: now) else {
            throw RelayStoreError.inboxRetired
        }
        guard var registration = inboxRegistrations[inboxId] else {
            throw MailboxSyncError.consumerNotFound
        }
        let hasActiveBoundConsumer = registration.streamState.consumers.values.contains {
            $0.state == .active
                && SigningKeyPair.isValidPublicKey($0.consumerSigningPublicKey)
        }
        let sponsorIsActiveAndBound: Bool = {
            guard let sponsorConsumerId,
                  sponsorConsumerId != consumerId,
                  let sponsor = registration.streamState.consumers[sponsorConsumerId.rawValue] else {
                return false
            }
            return sponsor.state == .active
                && SigningKeyPair.isValidPublicKey(sponsor.consumerSigningPublicKey)
        }()
        if let existing = registration.streamState.consumers[consumerId.rawValue] {
            guard existing.state == .active else { throw MailboxSyncError.consumerRevoked }
            guard existing.cursorKey.count == 32 else { throw MailboxSyncError.invalidCursor }
            guard existing.consumerSigningPublicKey == consumerSigningPublicKey else {
                throw MailboxSyncError.consumerSigningKeyMismatch
            }
            return existing.publicRegistration(consumerId: consumerId)
        }
        if registration.streamState.isEndpointManaged {
            guard hasActiveBoundConsumer else {
                throw MailboxSyncError.freshInboxRequired
            }
            guard sponsorConsumerId != nil else {
                throw MailboxSyncError.consumerSponsorRequired
            }
            guard sponsorIsActiveAndBound else {
                throw MailboxSyncError.invalidConsumerSponsor
            }
        } else if sponsorConsumerId != nil {
            throw MailboxSyncError.invalidConsumerSponsor
        }
        let activeConsumerCount = registration.streamState.consumers.values.reduce(into: 0) {
            if $1.state == .active { $0 += 1 }
        }
        guard activeConsumerCount < NoctweaveArchitectureV2.maximumEndpoints else {
            throw MailboxSyncError.invalidConsumer
        }
        Self.compactRevokedMailboxConsumers(
            &registration.streamState.consumers,
            reservingSlots: 1
        )
        let start = startingSequence ?? registration.streamState.highWatermark
        guard start >= registration.streamState.retentionFloor else {
            throw MailboxSyncError.cursorExpired(retentionFloor: registration.streamState.retentionFloor)
        }
        guard start <= registration.streamState.highWatermark else {
            throw MailboxSyncError.invalidCursor
        }
        let consumer = MailboxConsumerRecord(
            state: .active,
            committedSequence: start,
            cursorKey: Self.generateMailboxCursorKey(),
            consumerSigningPublicKey: consumerSigningPublicKey,
            registeredAt: now,
            revokedAt: nil
        )
        registration.streamState.consumers[consumerId.rawValue] = consumer
        registration.streamState.isEndpointManaged = true
        inboxRegistrations[inboxId] = registration
        try saveToDisk()
        return consumer.publicRegistration(consumerId: consumerId)
    }

    public func mailboxConsumers(inboxId: String) -> [MailboxConsumerRegistration] {
        guard let stream = inboxRegistrations[inboxId]?.streamState else { return [] }
        return stream.consumers.compactMap { rawValue, record in
            let id = MailboxConsumerId(rawValue: rawValue)
            return id.isStructurallyValid ? record.publicRegistration(consumerId: id) : nil
        }.sorted { $0.consumerId.rawValue < $1.consumerId.rawValue }
    }

    public func mailboxConsumer(
        inboxId: String,
        consumerId: MailboxConsumerId
    ) -> MailboxConsumerRegistration? {
        guard consumerId.isStructurallyValid,
              let record = inboxRegistrations[inboxId]?
                .streamState.consumers[consumerId.rawValue] else {
            return nil
        }
        return record.publicRegistration(consumerId: consumerId)
    }

    /// Once a mailbox has entered endpoint-scoped synchronization, the
    /// profile-wide legacy fetch/ack capability must never become a fallback.
    /// Revoking every consumer therefore does not reopen the legacy path.
    public func hasMailboxConsumerBindings(inboxId: String) -> Bool {
        inboxRegistrations[inboxId]?.streamState.isEndpointManaged ?? false
    }

    /// Returns the credential bound to a consumer, including a revoked one so
    /// a request can be authenticated before the state machine rejects it.
    public func mailboxConsumerSigningPublicKey(
        inboxId: String,
        consumerId: MailboxConsumerId
    ) -> Data? {
        guard consumerId.isStructurallyValid,
              let consumer = inboxRegistrations[inboxId]?
                .streamState.consumers[consumerId.rawValue],
              SigningKeyPair.isValidPublicKey(consumer.consumerSigningPublicKey) else {
            return nil
        }
        return consumer.consumerSigningPublicKey
    }

    public func activeMailboxConsumerSigningPublicKey(
        inboxId: String,
        consumerId: MailboxConsumerId
    ) -> Data? {
        guard consumerId.isStructurallyValid,
              let consumer = inboxRegistrations[inboxId]?
                .streamState.consumers[consumerId.rawValue],
              consumer.state == .active,
              SigningKeyPair.isValidPublicKey(consumer.consumerSigningPublicKey) else {
            return nil
        }
        return consumer.consumerSigningPublicKey
    }

    public func syncMailbox(
        inboxId: String,
        consumerId: MailboxConsumerId,
        cursor: MailboxCursor? = nil,
        maxCount: Int? = nil
    ) throws -> MailboxSyncBatch {
        guard consumerId.isStructurallyValid else {
            throw MailboxSyncError.invalidConsumer
        }
        guard let registration = inboxRegistrations[inboxId],
              let consumer = registration.streamState.consumers[consumerId.rawValue] else {
            throw MailboxSyncError.consumerNotFound
        }
        guard consumer.state == .active else { throw MailboxSyncError.consumerRevoked }
        guard SigningKeyPair.isValidPublicKey(consumer.consumerSigningPublicKey) else {
            throw MailboxSyncError.consumerCredentialMissing
        }
        let stream = registration.streamState
        guard consumer.cursorKey.count == 32 else { throw MailboxSyncError.invalidCursor }
        guard consumer.committedSequence >= stream.retentionFloor else {
            throw MailboxSyncError.cursorExpired(retentionFloor: stream.retentionFloor)
        }
        let startSequence: UInt64
        if let cursor {
            if let decoded = Self.mailboxCursorSequence(
                from: cursor,
                inboxId: inboxId,
                consumerId: consumerId,
                key: consumer.cursorKey
            ) {
                startSequence = decoded
            } else {
                throw MailboxSyncError.invalidCursor
            }
        } else {
            startSequence = consumer.committedSequence
        }
        guard startSequence >= stream.retentionFloor else {
            throw MailboxSyncError.cursorExpired(retentionFloor: stream.retentionFloor)
        }
        guard startSequence >= consumer.committedSequence else {
            throw MailboxSyncError.cursorRollback
        }
        guard startSequence <= stream.highWatermark else {
            throw MailboxSyncError.invalidCursor
        }
        let pageSize = max(1, min(maxCount ?? 100, 256))
        let available = mailboxes[inboxId, default: []].filter {
            $0.sequence > startSequence
        }.sorted { $0.sequence < $1.sequence }
        let selected = Array(available.prefix(pageSize))
        let nextSequence = selected.last?.sequence ?? startSequence
        let events = selected.map {
            SequencedEnvelope(sequence: $0.sequence, envelope: $0.envelope, storedAt: $0.storedAt)
        }
        return MailboxSyncBatch(
            events: events,
            nextCursor: Self.mailboxCursor(
                inboxId: inboxId,
                consumerId: consumerId,
                sequence: nextSequence,
                key: consumer.cursorKey
            ),
            nextSequence: nextSequence,
            highWatermark: stream.highWatermark,
            retentionFloor: stream.retentionFloor,
            hasMore: available.contains { $0.sequence > nextSequence }
        )
    }

    /// Commits only a cursor issued by this relay for this consumer. Advancing a
    /// consumer never deletes data still needed by another active consumer.
    @discardableResult
    public func commitMailboxCursor(
        inboxId: String,
        consumerId: MailboxConsumerId,
        cursor: MailboxCursor,
        sequence: UInt64
    ) throws -> MailboxConsumerRegistration {
        guard consumerId.isStructurallyValid else {
            throw MailboxSyncError.invalidConsumer
        }
        guard cursor.isStructurallyValid,
              var registration = inboxRegistrations[inboxId],
              var consumer = registration.streamState.consumers[consumerId.rawValue] else {
            throw MailboxSyncError.consumerNotFound
        }
        guard consumer.state == .active else { throw MailboxSyncError.consumerRevoked }
        guard SigningKeyPair.isValidPublicKey(consumer.consumerSigningPublicKey) else {
            throw MailboxSyncError.consumerCredentialMissing
        }
        guard consumer.cursorKey.count == 32 else { throw MailboxSyncError.invalidCursor }
        guard sequence >= consumer.committedSequence else { throw MailboxSyncError.cursorRollback }
        guard sequence >= registration.streamState.retentionFloor else {
            throw MailboxSyncError.cursorExpired(
                retentionFloor: registration.streamState.retentionFloor
            )
        }
        guard sequence <= registration.streamState.highWatermark else { throw MailboxSyncError.invalidCursor }
        let authenticatedSequence = Self.mailboxCursorSequence(
            from: cursor,
            inboxId: inboxId,
            consumerId: consumerId,
            key: consumer.cursorKey
        )
        guard authenticatedSequence == sequence else {
            throw MailboxSyncError.invalidCursor
        }
        consumer.committedSequence = sequence
        registration.streamState.consumers[consumerId.rawValue] = consumer
        inboxRegistrations[inboxId] = registration
        garbageCollectCommittedDirectEnvelopes(inboxId: inboxId)
        try saveToDisk()
        return consumer.publicRegistration(consumerId: consumerId)
    }

    @discardableResult
    public func revokeMailboxConsumer(
        inboxId: String,
        consumerId: MailboxConsumerId,
        now: Date = Date()
    ) throws -> MailboxConsumerRegistration {
        guard consumerId.isStructurallyValid,
              now.timeIntervalSince1970.isFinite else {
            throw MailboxSyncError.invalidConsumer
        }
        guard var registration = inboxRegistrations[inboxId],
              var consumer = registration.streamState.consumers[consumerId.rawValue] else {
            throw MailboxSyncError.consumerNotFound
        }
        if consumer.state == .revoked {
            return consumer.publicRegistration(consumerId: consumerId)
        }
        consumer.state = .revoked
        consumer.revokedAt = now
        registration.streamState.consumers[consumerId.rawValue] = consumer
        inboxRegistrations[inboxId] = registration
        garbageCollectCommittedDirectEnvelopes(inboxId: inboxId)
        try saveToDisk()
        return consumer.publicRegistration(consumerId: consumerId)
    }

    private func envelopePayloadBytes(_ envelope: ProtocolEnvelopeV1) -> Int {
        envelope.encodedPayloadByteCount
    }

    private func allocateMailboxSequence(for inboxId: String) throws -> UInt64 {
        let current = inboxRegistrations[inboxId]?.streamState.highWatermark
            ?? mailboxes[inboxId, default: []].map(\.sequence).max()
            ?? 0
        guard current < UInt64.max else { throw MailboxSyncError.sequenceOverflow }
        let next = current + 1
        if var registration = inboxRegistrations[inboxId] {
            registration.streamState.highWatermark = next
            inboxRegistrations[inboxId] = registration
        }
        return next
    }

    private func garbageCollectCommittedDirectEnvelopes(inboxId: String) {
        guard var registration = inboxRegistrations[inboxId] else { return }
        let activePositions = registration.streamState.consumers.values.compactMap {
            $0.state == .active ? $0.committedSequence : nil
        }
        guard let floor = activePositions.min() else { return }
        registration.streamState.retentionFloor = max(registration.streamState.retentionFloor, floor)
        inboxRegistrations[inboxId] = registration
        let remaining = mailboxes[inboxId, default: []].filter { $0.sequence > floor }
        if remaining.isEmpty {
            mailboxes.removeValue(forKey: inboxId)
        } else {
            mailboxes[inboxId] = remaining
        }
    }

    private static func generateMailboxCursorKey() -> Data {
        var material = Data("Noctweave/mailbox-cursor-key/v2".utf8)
        material.append(Data(UUID().uuidString.lowercased().utf8))
        material.append(Data(UUID().uuidString.lowercased().utf8))
        return Data(SHA256.hash(data: material))
    }

    private static func compactRevokedMailboxConsumers(
        _ consumers: inout [String: MailboxConsumerRecord],
        reservingSlots: Int
    ) {
        let maximum = NoctweaveArchitectureV2.maximumMailboxConsumerHistory
        while consumers.count + max(0, reservingSlots) > maximum {
            guard let oldestRevokedId = consumers
                .filter({ $0.value.state == .revoked })
                .min(by: {
                    ($0.value.revokedAt ?? $0.value.registeredAt)
                        < ($1.value.revokedAt ?? $1.value.registeredAt)
                })?.key else {
                return
            }
            consumers.removeValue(forKey: oldestRevokedId)
        }
    }

    private static func mailboxCursor(
        inboxId: String,
        consumerId: MailboxConsumerId,
        sequence: UInt64,
        key: Data
    ) -> MailboxCursor {
        let sequenceData = mailboxCursorSequenceData(sequence)
        let authenticationCode = mailboxCursorAuthenticationCode(
            inboxId: inboxId,
            consumerId: consumerId,
            sequenceData: sequenceData,
            key: key
        )
        var token = sequenceData
        token.append(contentsOf: authenticationCode)
        return MailboxCursor(rawValue: token.base64EncodedString())
    }

    private static func mailboxCursorSequence(
        from cursor: MailboxCursor,
        inboxId: String,
        consumerId: MailboxConsumerId,
        key: Data
    ) -> UInt64? {
        guard cursor.isStructurallyValid,
              let token = Data(base64Encoded: cursor.rawValue),
              token.base64EncodedString() == cursor.rawValue,
              token.count == 40 else {
            return nil
        }
        let sequenceData = Data(token.prefix(8))
        let receivedCode = Data(token.suffix(32))
        var material = Data("Noctweave/mailbox-cursor/v2".utf8)
        material.append(Data(inboxId.utf8))
        material.append(0)
        material.append(Data(consumerId.rawValue.utf8))
        material.append(0)
        material.append(sequenceData)
        guard HMAC<SHA256>.isValidAuthenticationCode(
            receivedCode,
            authenticating: material,
            using: SymmetricKey(data: key)
        ) else {
            return nil
        }
        return sequenceData.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    private static func mailboxCursorAuthenticationCode(
        inboxId: String,
        consumerId: MailboxConsumerId,
        sequenceData: Data,
        key: Data
    ) -> Data {
        var material = Data("Noctweave/mailbox-cursor/v2".utf8)
        material.append(Data(inboxId.utf8))
        material.append(0)
        material.append(Data(consumerId.rawValue.utf8))
        material.append(0)
        material.append(sequenceData)
        let authenticationCode = HMAC<SHA256>.authenticationCode(
            for: material,
            using: SymmetricKey(data: key)
        )
        return Data(authenticationCode)
    }

    private static func mailboxCursorSequenceData(_ sequence: UInt64) -> Data {
        var bigEndian = sequence.bigEndian
        return withUnsafeBytes(of: &bigEndian) { Data($0) }
    }

    public func storeAttachment(
        attachmentId: UUID,
        chunkIndex: Int,
        payload: EncryptedPayload,
        ttlSeconds: Int?
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
        pruneAttachments(now: Date())
        let ttl = boundedAttachmentTTL(ttlSeconds)
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

    public func stats() -> (mailboxes: Int, messages: Int) {
        let messageCount = mailboxes.values.reduce(0) { $0 + $1.count }
        return (mailboxes.count, messageCount)
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
        mailboxes = snapshot.mailboxes
        inboxRegistrations = snapshot.inboxRegistrations
        inboxRetirements = snapshot.inboxRetirements
        inboxRouteCapabilities = snapshot.inboxRouteCapabilities
        rendezvousRoutesV2 = snapshot.rendezvousRoutesV2
        attachments = snapshot.attachments
        federationNodes = snapshot.federationNodes
        coordinatorPinnedPublicKeys = snapshot.coordinatorPinnedPublicKeys
        actorProofReplayCache = snapshot.actorProofReplayCache.filter {
            $0.value > Date().addingTimeInterval(-RelayActorProof.maximumAgeSeconds)
        }
        pruneAttachments(now: Date())
        pruneFederationNodes(now: Date())
        enforceLoadedInboxRetirements()
        normalizeInboxRouteCapabilitiesAfterLoad()
        normalizeRendezvousRoutesV2AfterLoad()
    }

    private func restoreSnapshot(_ snapshot: RelayStoreSnapshot) {
        mailboxes = snapshot.mailboxes
        inboxRegistrations = snapshot.inboxRegistrations
        inboxRetirements = snapshot.inboxRetirements
        inboxRouteCapabilities = snapshot.inboxRouteCapabilities
        rendezvousRoutesV2 = snapshot.rendezvousRoutesV2
        attachments = snapshot.attachments
        federationNodes = snapshot.federationNodes
        coordinatorPinnedPublicKeys = snapshot.coordinatorPinnedPublicKeys
        actorProofReplayCache = snapshot.actorProofReplayCache
    }

    private func currentSnapshot() -> RelayStoreSnapshot {
        RelayStoreSnapshot(
            mailboxes: mailboxes,
            inboxRegistrations: inboxRegistrations,
            inboxRetirements: inboxRetirements,
            inboxRouteCapabilities: inboxRouteCapabilities,
            rendezvousRoutesV2: rendezvousRoutesV2,
            attachments: attachments,
            federationNodes: federationNodes,
            coordinatorPinnedPublicKeys: coordinatorPinnedPublicKeys,
            actorProofReplayCache: actorProofReplayCache
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
        guard snapshot.inboxRegistrations.allSatisfy({ inboxId, registration in
                  InboxAddress.isValid(inboxId)
                      && !registration.accessPublicKey.isEmpty
                      && registration.registeredAt.timeIntervalSince1970.isFinite
                      && registration.routeMutationScope.isValidRouteMutationScope
                      && registration.streamState.retentionFloor
                          <= registration.streamState.highWatermark
              }),
              snapshot.mailboxes.allSatisfy({ inboxId, records in
                  guard let registration = snapshot.inboxRegistrations[inboxId] else {
                      return false
                  }
                  var previous = registration.streamState.retentionFloor
                  var envelopeIds = Set<UUID>()
                  for record in records {
                      guard record.sequence > previous,
                            record.sequence <= registration.streamState.highWatermark,
                            record.envelope.isStructurallyValid,
                            record.storedAt.timeIntervalSince1970.isFinite,
                            envelopeIds.insert(record.envelope.id).inserted else {
                          return false
                      }
                      previous = record.sequence
                  }
                  return true
              }) else {
            throw RelayStorePersistenceError.invalidCurrentState
        }
    }

    private func enforceLoadedInboxRetirements() {
        for inboxId in Array(inboxRetirements.keys) {
            mailboxes.removeValue(forKey: inboxId)
            inboxRegistrations.removeValue(forKey: inboxId)
            inboxRouteCapabilities = inboxRouteCapabilities.filter { $0.value.inboxId != inboxId }
        }
    }

    private func inboxRouteCapabilityKey(_ capability: InboxRouteCapabilityV2) -> String {
        capability.relayRegistryDigest.base64EncodedString()
    }

    private func evictOldestRevokedInboxRouteCapabilityIfAtLimit(inboxId: String) {
        let revokedForInbox = inboxRouteCapabilities
            .filter { $0.value.inboxId == inboxId && $0.value.revokedAt != nil }
            .sorted { lhs, rhs in
                (lhs.value.revokedAt ?? lhs.value.createdAt) < (rhs.value.revokedAt ?? rhs.value.createdAt)
            }
        if revokedForInbox.count >= maxRevokedInboxRouteCapabilitiesPerInbox,
           let oldest = revokedForInbox.first?.key {
            inboxRouteCapabilities.removeValue(forKey: oldest)
        }
    }

    private func makeRoomForInboxRouteCapabilityRecord(
        inboxId: String,
        addingRevokedRecord: Bool
    ) throws {
        if addingRevokedRecord {
            evictOldestRevokedInboxRouteCapabilityIfAtLimit(inboxId: inboxId)
        }
        while inboxRouteCapabilities.count >= maxInboxRouteCapabilityRecords {
            guard let oldestRevoked = inboxRouteCapabilities
                .filter({ $0.value.revokedAt != nil })
                .min(by: {
                    ($0.value.revokedAt ?? $0.value.createdAt)
                        < ($1.value.revokedAt ?? $1.value.createdAt)
                })?.key else {
                throw RelayStoreError.relayCapacityExceeded
            }
            inboxRouteCapabilities.removeValue(forKey: oldestRevoked)
        }
    }

    private func normalizeInboxRouteCapabilitiesAfterLoad() {
        let valid = inboxRouteCapabilities.filter { key, record in
            guard let digest = Data(base64Encoded: key),
                  digest.count == SHA256.byteCount,
                  InboxAddress.isValid(record.inboxId),
                  inboxRegistrations[record.inboxId] != nil,
                  inboxRetirements[record.inboxId] == nil,
                  record.createdAt.timeIntervalSince1970.isFinite,
                  record.revokedAt?.timeIntervalSince1970.isFinite ?? true,
                  record.revokedAt.map({ $0 >= record.createdAt }) ?? true else {
                return false
            }
            return true
        }
        var perInboxBounded: [String: InboxRouteCapabilityRecord] = [:]
        for inboxId in Set(valid.values.map(\.inboxId)) {
            let active = valid
                .filter { $0.value.inboxId == inboxId && $0.value.revokedAt == nil }
                .sorted { $0.value.createdAt > $1.value.createdAt }
                .prefix(maxActiveInboxRouteCapabilitiesPerInbox)
            let revoked = valid
                .filter { $0.value.inboxId == inboxId && $0.value.revokedAt != nil }
                .sorted {
                    ($0.value.revokedAt ?? $0.value.createdAt)
                        > ($1.value.revokedAt ?? $1.value.createdAt)
                }
                .prefix(maxRevokedInboxRouteCapabilitiesPerInbox)
            for entry in active {
                perInboxBounded[entry.key] = entry.value
            }
            for entry in revoked {
                perInboxBounded[entry.key] = entry.value
            }
        }
        let active = perInboxBounded
            .filter { $0.value.revokedAt == nil }
            .sorted { $0.value.createdAt > $1.value.createdAt }
        let revoked = perInboxBounded
            .filter { $0.value.revokedAt != nil }
            .sorted {
                ($0.value.revokedAt ?? $0.value.createdAt)
                    > ($1.value.revokedAt ?? $1.value.createdAt)
            }
        inboxRouteCapabilities = [:]
        for entry in active.prefix(maxInboxRouteCapabilityRecords) {
            inboxRouteCapabilities[entry.key] = entry.value
        }
        for entry in revoked where inboxRouteCapabilities.count < maxInboxRouteCapabilityRecords {
            inboxRouteCapabilities[entry.key] = entry.value
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
    let mailboxes: [String: [StoredEnvelope]]
    let inboxRegistrations: [String: InboxRegistrationRecord]
    let inboxRetirements: [String: InboxRetirementRecord]
    let inboxRouteCapabilities: [String: InboxRouteCapabilityRecord]
    let rendezvousRoutesV2: [String: RendezvousRelayRouteRecordV2]
    let attachments: [String: [AttachmentRecord]]
    let federationNodes: [String: FederationNodeRecord]
    let coordinatorPinnedPublicKeys: [String: Data]
    let actorProofReplayCache: [String: Date]

    static let empty = RelayStoreSnapshot(
        mailboxes: [:],
        inboxRegistrations: [:],
        inboxRetirements: [:],
        inboxRouteCapabilities: [:],
        rendezvousRoutesV2: [:],
        attachments: [:],
        federationNodes: [:],
        coordinatorPinnedPublicKeys: [:],
        actorProofReplayCache: [:]
    )

    init(
        mailboxes: [String: [StoredEnvelope]],
        inboxRegistrations: [String: InboxRegistrationRecord] = [:],
        inboxRetirements: [String: InboxRetirementRecord] = [:],
        inboxRouteCapabilities: [String: InboxRouteCapabilityRecord] = [:],
        rendezvousRoutesV2: [String: RendezvousRelayRouteRecordV2] = [:],
        attachments: [String: [AttachmentRecord]],
        federationNodes: [String: FederationNodeRecord] = [:],
        coordinatorPinnedPublicKeys: [String: Data] = [:],
        actorProofReplayCache: [String: Date] = [:]
    ) {
        self.mailboxes = mailboxes
        self.inboxRegistrations = inboxRegistrations
        self.inboxRetirements = inboxRetirements
        self.inboxRouteCapabilities = inboxRouteCapabilities
        self.rendezvousRoutesV2 = rendezvousRoutesV2
        self.attachments = attachments
        self.federationNodes = federationNodes
        self.coordinatorPinnedPublicKeys = coordinatorPinnedPublicKeys
        self.actorProofReplayCache = actorProofReplayCache
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mailboxes = try container.decode([String: [StoredEnvelope]].self, forKey: .mailboxes)
        inboxRegistrations = try container.decode([String: InboxRegistrationRecord].self, forKey: .inboxRegistrations)
        inboxRetirements = try container.decode(
            [String: InboxRetirementRecord].self,
            forKey: .inboxRetirements
        )
        inboxRouteCapabilities = try container.decode(
            [String: InboxRouteCapabilityRecord].self,
            forKey: .inboxRouteCapabilities
        )
        rendezvousRoutesV2 = try container.decode(
            [String: RendezvousRelayRouteRecordV2].self,
            forKey: .rendezvousRoutesV2
        )
        attachments = try container.decode([String: [AttachmentRecord]].self, forKey: .attachments)
        federationNodes = try container.decode([String: FederationNodeRecord].self, forKey: .federationNodes)
        coordinatorPinnedPublicKeys = try container.decode([String: Data].self, forKey: .coordinatorPinnedPublicKeys)
        actorProofReplayCache = try container.decode(
            [String: Date].self,
            forKey: .actorProofReplayCache
        )
    }
}

private struct InboxRetirementRecord: Codable {
    let retiredAt: Date
    let requestDigest: Data
}

private struct InboxRouteCapabilityRecord: Codable {
    let inboxId: String
    let createdAt: Date
    let revokedAt: Date?
}

struct InboxRegistrationRecord: Codable {
    let accessPublicKey: Data
    let registeredAt: Date
    var streamState: MailboxStreamState
    let routeMutationScope: Data
    var lastRouteMutationSequence: UInt64
    var lastRouteMutationDigest: Data?

    init(
        accessPublicKey: Data,
        registeredAt: Date,
        streamState: MailboxStreamState = MailboxStreamState(),
        routeMutationScope: Data = InboxRegistrationRecord.generateRouteMutationScope(),
        lastRouteMutationSequence: UInt64 = 0,
        lastRouteMutationDigest: Data? = nil
    ) {
        self.accessPublicKey = accessPublicKey
        self.registeredAt = registeredAt
        self.streamState = streamState
        self.routeMutationScope = routeMutationScope
        self.lastRouteMutationSequence = lastRouteMutationSequence
        self.lastRouteMutationDigest = lastRouteMutationDigest
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        accessPublicKey = try container.decode(Data.self, forKey: .accessPublicKey)
        registeredAt = try container.decode(Date.self, forKey: .registeredAt)
        streamState = try container.decode(MailboxStreamState.self, forKey: .streamState)
        lastRouteMutationSequence = try container.decode(
            UInt64.self,
            forKey: .lastRouteMutationSequence
        )
        guard lastRouteMutationSequence
                <= CreateInboxRouteCapabilityRequest.maximumMutationSequence else {
            throw DecodingError.dataCorruptedError(
                forKey: .lastRouteMutationSequence,
                in: container,
                debugDescription: "Route mutation sequence exceeds the protocol bound"
            )
        }
        let decodedDigest = try container.decodeIfPresent(
            Data.self,
            forKey: .lastRouteMutationDigest
        )
        routeMutationScope = try container.decode(Data.self, forKey: .routeMutationScope)
        guard routeMutationScope.isValidRouteMutationScope else {
            throw DecodingError.dataCorruptedError(
                forKey: .routeMutationScope,
                in: container,
                debugDescription: "Invalid relay-local route mutation scope"
            )
        }
        if lastRouteMutationSequence == 0 {
            guard decodedDigest == nil else {
                throw DecodingError.dataCorruptedError(
                    forKey: .lastRouteMutationDigest,
                    in: container,
                    debugDescription: "Unexpected route mutation digest at sequence zero"
                )
            }
            lastRouteMutationDigest = nil
        } else {
            guard let decodedDigest, decodedDigest.count == SHA256.byteCount else {
                throw DecodingError.dataCorruptedError(
                    forKey: .lastRouteMutationDigest,
                    in: container,
                    debugDescription: "Missing or invalid route mutation cursor digest"
                )
            }
            lastRouteMutationDigest = decodedDigest
        }
    }

    var routeMutationReceipt: InboxRegistrationReceiptV3 {
        InboxRegistrationReceiptV3(
            routeMutationScope: routeMutationScope,
            nextRouteMutationSequence: CreateInboxRouteCapabilityRequest
                .nextMutationSequence(after: lastRouteMutationSequence)
        )
    }

    private static func generateRouteMutationScope() -> Data {
        var generator = SystemRandomNumberGenerator()
        while true {
            let value = Data((0..<32).map { _ in
                UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
            })
            if value.isValidRouteMutationScope {
                return value
            }
        }
    }
}

extension Data {
    var isValidRouteMutationScope: Bool {
        count == SHA256.byteCount && contains(where: { $0 != 0 })
    }
}

private struct StoredEnvelope: Codable {
    var sequence: UInt64
    let envelope: ProtocolEnvelopeV1
    let storedAt: Date

    init(sequence: UInt64, envelope: ProtocolEnvelopeV1, storedAt: Date) {
        self.sequence = sequence
        self.envelope = envelope
        self.storedAt = storedAt
    }
}

struct MailboxStreamState: Codable {
    var highWatermark: UInt64
    var retentionFloor: UInt64
    var consumers: [String: MailboxConsumerRecord]
    var isEndpointManaged: Bool

    init(
        highWatermark: UInt64 = 0,
        retentionFloor: UInt64 = 0,
        consumers: [String: MailboxConsumerRecord] = [:],
        isEndpointManaged: Bool = false
    ) {
        self.highWatermark = highWatermark
        self.retentionFloor = min(retentionFloor, highWatermark)
        self.consumers = consumers
        self.isEndpointManaged = isEndpointManaged || !consumers.isEmpty
    }

    private enum CodingKeys: String, CodingKey {
        case highWatermark
        case retentionFloor
        case consumers
        case isEndpointManaged
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        highWatermark = try container.decode(UInt64.self, forKey: .highWatermark)
        retentionFloor = try container.decode(UInt64.self, forKey: .retentionFloor)
        consumers = try container.decode(
            [String: MailboxConsumerRecord].self,
            forKey: .consumers
        )
        isEndpointManaged = try container.decode(
            Bool.self,
            forKey: .isEndpointManaged
        )
        guard retentionFloor <= highWatermark,
              isEndpointManaged || consumers.isEmpty,
              consumers.allSatisfy({ key, value in
                  MailboxConsumerId(rawValue: key).isStructurallyValid
                      && value.isStructurallyValid(highWatermark: highWatermark)
              }) else {
            throw DecodingError.dataCorruptedError(
                forKey: .consumers,
                in: container,
                debugDescription: "Invalid current mailbox stream state"
            )
        }
    }
}

struct MailboxConsumerRecord: Codable {
    var state: MailboxConsumerState
    var committedSequence: UInt64
    let cursorKey: Data
    let consumerSigningPublicKey: Data
    let registeredAt: Date
    var revokedAt: Date?

    func isStructurallyValid(highWatermark: UInt64) -> Bool {
        guard committedSequence <= highWatermark,
              cursorKey.count == SHA256.byteCount,
              SigningKeyPair.isValidPublicKey(consumerSigningPublicKey),
              registeredAt.timeIntervalSince1970.isFinite,
              revokedAt?.timeIntervalSince1970.isFinite ?? true else {
            return false
        }
        switch (state, revokedAt) {
        case (.active, nil):
            return true
        case let (.revoked, .some(revokedAt)):
            return revokedAt >= registeredAt
        default:
            return false
        }
    }

    func publicRegistration(consumerId: MailboxConsumerId) -> MailboxConsumerRegistration {
        MailboxConsumerRegistration(
            consumerId: consumerId,
            consumerSigningPublicKey: consumerSigningPublicKey,
            state: state,
            committedSequence: committedSequence,
            registeredAt: registeredAt,
            revokedAt: revokedAt
        )
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
    private static let metaTableName = "relay_state_meta"
    private static let currentSchemaKey = "noctweave_1_0_schema"
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
            mailboxes: try loadMailboxes(in: db),
            inboxRegistrations: try loadInboxRegistrations(in: db),
            inboxRetirements: try loadInboxRetirements(in: db),
            inboxRouteCapabilities: try loadInboxRouteCapabilities(in: db),
            rendezvousRoutesV2: try loadRendezvousRoutesV2(in: db),
            attachments: try loadAttachments(in: db),
            federationNodes: try loadFederationNodes(in: db),
            coordinatorPinnedPublicKeys: try loadCoordinatorPinnedPublicKeys(in: db),
            actorProofReplayCache: try loadActorProofReplayCache(in: db)
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
            for (inboxId, records) in snapshot.mailboxes {
                for (position, record) in records.enumerated() {
                    try insertMailboxRecord(inboxId: inboxId, position: position, record: record, in: db)
                }
            }
            for (inboxId, record) in snapshot.inboxRegistrations {
                try insertInboxRegistration(inboxId: inboxId, record: record, in: db)
            }
            for (inboxId, record) in snapshot.inboxRetirements {
                try insertInboxRetirement(inboxId: inboxId, record: record, in: db)
            }
            for (capabilityDigest, record) in snapshot.inboxRouteCapabilities {
                try insertInboxRouteCapability(
                    capabilityDigest: capabilityDigest,
                    record: record,
                    in: db
                )
            }
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
            for (cacheKey, consumedAt) in snapshot.actorProofReplayCache {
                try insertActorProofReplayCacheEntry(
                    cacheKey: cacheKey,
                    consumedAt: consumedAt,
                    in: db
                )
            }
            try insertMeta(key: currentSchemaKey, value: Data("1".utf8), in: db)
            try execute("COMMIT;", in: db)
        } catch {
            _ = sqlite3_exec(db, "ROLLBACK;", nil, nil, nil)
            throw error
        }
    }

    private static func loadMailboxes(in db: OpaquePointer) throws -> [String: [StoredEnvelope]] {
        var mailboxes: [String: [StoredEnvelope]] = [:]
        try queryRows("SELECT inbox_id, value FROM relay_mailbox_envelopes ORDER BY inbox_id, position;", in: db) { statement in
            let inboxId = try readText(statement, column: 0, in: db)
            let record = try decode(StoredEnvelope.self, from: readBlob(statement, column: 1))
            mailboxes[inboxId, default: []].append(record)
        }
        return mailboxes
    }

    private static func loadInboxRegistrations(in db: OpaquePointer) throws -> [String: InboxRegistrationRecord] {
        var registrations: [String: InboxRegistrationRecord] = [:]
        try queryRows("SELECT inbox_id, value FROM relay_inbox_registrations;", in: db) { statement in
            let inboxId = try readText(statement, column: 0, in: db)
            registrations[inboxId] = try decode(InboxRegistrationRecord.self, from: readBlob(statement, column: 1))
        }
        return registrations
    }

    private static func loadInboxRetirements(in db: OpaquePointer) throws -> [String: InboxRetirementRecord] {
        var retirements: [String: InboxRetirementRecord] = [:]
        try queryRows("SELECT inbox_id, value FROM relay_inbox_retirements;", in: db) { statement in
            let inboxId = try readText(statement, column: 0, in: db)
            retirements[inboxId] = try decode(
                InboxRetirementRecord.self,
                from: readBlob(statement, column: 1)
            )
        }
        return retirements
    }

    private static func loadInboxRouteCapabilities(
        in db: OpaquePointer
    ) throws -> [String: InboxRouteCapabilityRecord] {
        var records: [String: InboxRouteCapabilityRecord] = [:]
        try queryRows(
            "SELECT capability_digest, value FROM relay_inbox_route_capabilities;",
            in: db
        ) { statement in
            let digest = try readText(statement, column: 0, in: db)
            records[digest] = try decode(
                InboxRouteCapabilityRecord.self,
                from: readBlob(statement, column: 1)
            )
        }
        return records
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
            guard SigningKeyPair.isValidPublicKey(publicKey) else {
                throw SQLiteRelayStateStoreError.corrupt("invalid pinned coordinator public key")
            }
            keys[coordinatorKey] = publicKey
        }
        return keys
    }

    private static func loadActorProofReplayCache(
        in db: OpaquePointer
    ) throws -> [String: Date] {
        var cache: [String: Date] = [:]
        try queryRows(
            "SELECT cache_key, consumed_at FROM relay_actor_proof_replay_cache;",
            in: db
        ) { statement in
            let cacheKey = try readText(statement, column: 0, in: db)
            cache[cacheKey] = Date(
                timeIntervalSince1970: sqlite3_column_double(statement, 1)
            )
        }
        return cache
    }

    private static func insertMailboxRecord(inboxId: String, position: Int, record: StoredEnvelope, in db: OpaquePointer) throws {
        try executePrepared(
            "INSERT INTO relay_mailbox_envelopes (inbox_id, position, envelope_id, stored_at, value) VALUES (?1, ?2, ?3, ?4, ?5);",
            in: db
        ) { statement in
            try bindText(inboxId, to: 1, in: statement, db: db)
            try bindInt(position, to: 2, in: statement, db: db)
            try bindText(record.envelope.id.uuidString, to: 3, in: statement, db: db)
            try bindDouble(record.storedAt.timeIntervalSince1970, to: 4, in: statement, db: db)
            try bindBlob(encode(record), to: 5, in: statement, db: db)
        }
    }

    private static func insertInboxRegistration(inboxId: String, record: InboxRegistrationRecord, in db: OpaquePointer) throws {
        try executePrepared(
            "INSERT INTO relay_inbox_registrations (inbox_id, registered_at, access_public_key, value) VALUES (?1, ?2, ?3, ?4);",
            in: db
        ) { statement in
            try bindText(inboxId, to: 1, in: statement, db: db)
            try bindDouble(record.registeredAt.timeIntervalSince1970, to: 2, in: statement, db: db)
            try bindBlob(record.accessPublicKey, to: 3, in: statement, db: db)
            try bindBlob(encode(record), to: 4, in: statement, db: db)
        }
    }

    private static func insertInboxRetirement(
        inboxId: String,
        record: InboxRetirementRecord,
        in db: OpaquePointer
    ) throws {
        try executePrepared(
            "INSERT INTO relay_inbox_retirements (inbox_id, retired_at, request_digest, value) VALUES (?1, ?2, ?3, ?4);",
            in: db
        ) { statement in
            try bindText(inboxId, to: 1, in: statement, db: db)
            try bindDouble(record.retiredAt.timeIntervalSince1970, to: 2, in: statement, db: db)
            try bindBlob(record.requestDigest, to: 3, in: statement, db: db)
            try bindBlob(encode(record), to: 4, in: statement, db: db)
        }
    }

    private static func insertInboxRouteCapability(
        capabilityDigest: String,
        record: InboxRouteCapabilityRecord,
        in db: OpaquePointer
    ) throws {
        try executePrepared(
            "INSERT INTO relay_inbox_route_capabilities (capability_digest, inbox_id, created_at, revoked_at, value) VALUES (?1, ?2, ?3, ?4, ?5);",
            in: db
        ) { statement in
            try bindText(capabilityDigest, to: 1, in: statement, db: db)
            try bindText(record.inboxId, to: 2, in: statement, db: db)
            try bindDouble(record.createdAt.timeIntervalSince1970, to: 3, in: statement, db: db)
            if let revokedAt = record.revokedAt {
                try bindDouble(revokedAt.timeIntervalSince1970, to: 4, in: statement, db: db)
            } else {
                guard sqlite3_bind_null(statement, 4) == SQLITE_OK else {
                    throw SQLiteRelayStateStoreError.bind(lastError(in: db))
                }
            }
            try bindBlob(encode(record), to: 5, in: statement, db: db)
        }
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

    private static func insertActorProofReplayCacheEntry(
        cacheKey: String,
        consumedAt: Date,
        in db: OpaquePointer
    ) throws {
        try executePrepared(
            "INSERT INTO relay_actor_proof_replay_cache (cache_key, consumed_at) VALUES (?1, ?2);",
            in: db
        ) { statement in
            try bindText(cacheKey, to: 1, in: statement, db: db)
            try bindDouble(consumedAt.timeIntervalSince1970, to: 2, in: statement, db: db)
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
            "relay_mailbox_envelopes",
            "relay_inbox_registrations",
            "relay_inbox_retirements",
            "relay_inbox_route_capabilities",
            "relay_rendezvous_routes_v2",
            "relay_attachment_chunks",
            "relay_federation_nodes",
            "relay_coordinator_pinned_keys",
            "relay_actor_proof_replay_cache"
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
        CREATE TABLE IF NOT EXISTS relay_mailbox_envelopes (
            inbox_id TEXT NOT NULL,
            position INTEGER NOT NULL,
            envelope_id TEXT NOT NULL,
            stored_at REAL NOT NULL,
            value BLOB NOT NULL,
            PRIMARY KEY (inbox_id, position)
        );
        CREATE INDEX IF NOT EXISTS relay_mailbox_envelopes_inbox_idx ON relay_mailbox_envelopes(inbox_id);
        CREATE TABLE IF NOT EXISTS relay_inbox_registrations (
            inbox_id TEXT PRIMARY KEY,
            registered_at REAL NOT NULL,
            access_public_key BLOB NOT NULL,
            value BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS relay_inbox_retirements (
            inbox_id TEXT PRIMARY KEY,
            retired_at REAL NOT NULL,
            request_digest BLOB NOT NULL,
            value BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS relay_inbox_route_capabilities (
            capability_digest TEXT PRIMARY KEY,
            inbox_id TEXT NOT NULL,
            created_at REAL NOT NULL,
            revoked_at REAL,
            value BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS relay_inbox_route_capabilities_inbox_idx ON relay_inbox_route_capabilities(inbox_id);
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
        CREATE TABLE IF NOT EXISTS relay_actor_proof_replay_cache (
            cache_key TEXT PRIMARY KEY,
            consumed_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS relay_actor_proof_replay_cache_consumed_at_idx ON relay_actor_proof_replay_cache(consumed_at);
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
    case inboxFull
    case invalidInboxRegistration
    case invalidInboxRetirement
    case inboxAlreadyRegistered
    case inboxRetired
    case invalidInboxRouteCapability
    case inboxRouteCapabilityRevoked
    case inboxRouteCapabilityLimitReached
    case invalidInboxRouteCapabilityMutation
    case inboxRouteCapabilityMutationConflict
    case inboxRouteCapabilityMutationOutOfOrder
    case invalidRendezvousRoute
    case rendezvousRouteUnavailable
    case rendezvousRegistrationConflict
    case rendezvousCapacityReached
    case rendezvousFrameConflict
    case rendezvousSequenceGap
    case rendezvousQuotaReached
    case destinationInboxNotRegistered
    case relayCapacityExceeded
    case invalidEnvelopePayload
    case invalidChunkIndex
    case invalidAttachmentPayload
}

enum InboxRouteCapabilityMutationOperation {
    case create
    case revoke
}

enum InboxRouteCapabilityMutationApplyResult: Equatable {
    case applied
    case replayed
}

enum RelayStorePersistenceError: Error {
    case injectedFailure
    case invalidCurrentState
}

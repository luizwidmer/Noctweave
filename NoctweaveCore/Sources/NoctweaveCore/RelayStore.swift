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
    private var announcements: [String: PairingAnnouncement] = [:]
    private var pairRequests: [String: [PairingRequest]] = [:]
    private var attachments: [String: [AttachmentRecord]] = [:]
    private var prekeyBundles: [String: PrekeyBundleRecord] = [:]
    private var federationNodes: [String: FederationNodeRecord] = [:]
    private var coordinatorPinnedPublicKeys: [String: Data] = [:]
    private var groups: [UUID: RelayGroupDescriptor] = [:]
    private var groupJoinRequests: [UUID: [RelayGroupJoinRequest]] = [:]
    private var groupInvitations: [String: [RelayGroupInvitation]] = [:]
    private var groupInvitationFingerprintsByGroup: [UUID: Set<String>] = [:]
    private var openFederationDHTCache = OpenFederationDHTCandidateCache(
        configuration: OpenFederationDHTDiscoveryConfiguration(isEnabled: false)
    )
    private var actorProofReplayCache: [String: Date] = [:]
    private var federationRegistrationAttemptsBySource: [String: [Date]] = [:]
    private var federationListAttemptsBySource: [String: [Date]] = [:]
    private var lastFederationRegistrationByEndpoint: [String: Date] = [:]
    private var lastDurableSnapshot = RelayStoreSnapshot.empty
    private var persistenceFailuresRemainingForTesting = 0
    private let announcementTTL: TimeInterval = 300
    private let minimumAnnouncementTTL: TimeInterval = 30
    private let maximumAnnouncementTTL: TimeInterval = 900
    private let maxAnnouncements = 2_048
    private let maxPairRequests = 100
    private let maxPairRequestTargets = 2_048
    private let attachmentTTL: TimeInterval = 3600
    private let minimumAttachmentTTL: TimeInterval = 60
    private let maximumAttachmentTTL: TimeInterval = 6 * 3600
    private let maxAttachmentChunks = 512
    private let maxAttachmentChunkPayloadBytes = 128 * 1024
    private let maxEnvelopePayloadBytes = 96 * 1024
    private let maxAttachmentIds = 4_096
    private let prekeyTTL: TimeInterval = 86400
    private let minimumPrekeyTTL: TimeInterval = 300
    private let maximumPrekeyTTL: TimeInterval = 7 * 86400
    private let maxPrekeyBundles = 10_000
    private let maxOneTimePrekeysPerBundle = 64
    private let maxGroupJoinRequests = 256
    private let maxGroupInvitationsPerIdentity = 256
    private let maxGroups = 10_000
    private let maxGroupsPerCreator = 100
    private let maxGroupMembers = 256
    private let maxGroupTitleCharacters = 128
    private let maxGroupEpochHistory = 64
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
            prunePrekeys(now: Date())
            pruneFederationNodes(now: Date())
            let snapshot = currentSnapshot()
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
    public func deliver(_ envelope: Envelope, to inboxId: String) throws -> Int {
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
            guard existing.envelope == envelope,
                  existing.pendingGroupRecipientFingerprints == nil,
                  existing.originalGroupRecipientFingerprints == nil else {
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

    @discardableResult
    public func deliverGroupEnvelope(
        _ envelope: Envelope,
        to inboxId: String,
        recipientFingerprints: [String]
    ) throws -> Int {
        guard envelope.isStructurallyValid,
              envelopePayloadBytes(envelope) <= maxEnvelopePayloadBytes else {
            throw RelayStoreError.invalidEnvelopePayload
        }
        guard !isInboxRetired(inboxId: inboxId) else {
            throw RelayStoreError.inboxRetired
        }
        // A group descriptor is the relay-authenticated registration for its
        // generated group inbox. Allowing a normal registered inbox here keeps
        // the storage primitive usable by migration and retry tooling; the
        // network handler additionally requires the exact group descriptor.
        guard inboxRegistrations[inboxId] != nil
                || groups.values.contains(where: { $0.inboxId == inboxId }) else {
            throw RelayStoreError.destinationInboxNotRegistered
        }
        guard let recipients = StoredEnvelope.normalizedGroupRecipients(
            recipientFingerprints
        ) else {
            throw RelayStoreError.invalidEnvelopePayload
        }
        guard !recipients.isEmpty else {
            return mailboxes[inboxId, default: []].count
        }
        var inbox = mailboxes[inboxId, default: []]
        if let existing = inbox.first(where: { $0.envelope.id == envelope.id }) {
            guard existing.envelope == envelope,
                  existing.pendingGroupRecipientFingerprints != nil,
                  existing.originalGroupRecipientFingerprints == recipients else {
                throw RelayStoreError.invalidEnvelopePayload
            }
            return inbox.count
        }
        if mailboxes[inboxId] == nil, mailboxes.count >= maxMailboxes {
            throw RelayStoreError.relayCapacityExceeded
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
                storedAt: bucketed(Date(), discriminator: discriminator),
                pendingGroupRecipientFingerprints: recipients,
                originalGroupRecipientFingerprints: recipients
            )
        )
        mailboxes[inboxId] = inbox
        try saveToDisk()
        return inbox.count
    }

    public func fetch(inboxId: String, maxCount: Int? = nil) throws -> [Envelope] {
        let inbox = mailboxes[inboxId, default: []]
        let count = max(0, maxCount ?? inbox.count)
        return Array(inbox.prefix(count)).map { $0.envelope }
    }

    public func fetchGroupEnvelopes(
        inboxId: String,
        recipientFingerprint: String,
        maxCount: Int? = nil
    ) throws -> [Envelope] {
        let recipient = recipientFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !recipient.isEmpty else {
            return []
        }
        let inbox = mailboxes[inboxId, default: []].filter { record in
            record.pendingGroupRecipientFingerprints?.contains(recipient) ?? false
        }
        let count = max(0, maxCount ?? inbox.count)
        return Array(inbox.prefix(count)).map { $0.envelope }
    }

    @discardableResult
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
            // Persist a relay-local scope synthesized while decoding a legacy
            // registration before returning it to the caller.
            try saveToDisk()
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
    /// New installations normally begin at the current high watermark and obtain
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
                && $0.consumerSigningPublicKey.map(SigningKeyPair.isValidPublicKey) == true
        }
        let sponsorIsActiveAndBound: Bool = {
            guard let sponsorConsumerId,
                  sponsorConsumerId != consumerId,
                  let sponsor = registration.streamState.consumers[sponsorConsumerId.rawValue] else {
                return false
            }
            return sponsor.state == .active
                && sponsor.consumerSigningPublicKey.map(SigningKeyPair.isValidPublicKey) == true
        }()
        if var existing = registration.streamState.consumers[consumerId.rawValue] {
            guard existing.state == .active else { throw MailboxSyncError.consumerRevoked }
            guard existing.cursorKey.count == 32 else { throw MailboxSyncError.invalidCursor }
            if let boundKey = existing.consumerSigningPublicKey {
                guard boundKey == consumerSigningPublicKey else {
                    throw MailboxSyncError.consumerSigningKeyMismatch
                }
            } else {
                if hasActiveBoundConsumer {
                    guard sponsorConsumerId != nil else {
                        throw MailboxSyncError.consumerSponsorRequired
                    }
                    guard sponsorIsActiveAndBound else {
                        throw MailboxSyncError.invalidConsumerSponsor
                    }
                }
                // Secure migration for a legacy persisted consumer. The wire
                // handler reaches this path only after validating authority,
                // possession, and (when available) active-sponsor proofs.
                existing.consumerSigningPublicKey = consumerSigningPublicKey
                registration.streamState.consumers[consumerId.rawValue] = existing
                inboxRegistrations[inboxId] = registration
                try saveToDisk()
            }
            return existing.publicRegistration(consumerId: consumerId)
        }
        if registration.streamState.isInstallationManaged {
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
        guard activeConsumerCount < NoctweaveArchitectureV2.maximumInstallations else {
            throw MailboxSyncError.invalidConsumer
        }
        Self.compactRevokedMailboxConsumers(
            &registration.streamState.consumers,
            reservingSlots: 1
        )
        if !registration.streamState.isInstallationManaged,
           registration.streamState.consumers.isEmpty {
            // Legacy acknowledgements delete arbitrary envelopes, so their
            // original relay sequences may contain holes. Those positions
            // have never been exposed through a v2 cursor. Normalize the
            // retained backlog exactly once before the first consumer is
            // activated so a cursor starting at zero can traverse it without
            // fabricating a gap or discarding an unacknowledged envelope.
            var retainedLegacyEnvelopes = mailboxes[inboxId, default: []]
            for index in retainedLegacyEnvelopes.indices {
                retainedLegacyEnvelopes[index].sequence = UInt64(index) + 1
            }
            mailboxes[inboxId] = retainedLegacyEnvelopes
            registration.streamState.highWatermark = UInt64(retainedLegacyEnvelopes.count)
            registration.streamState.retentionFloor = 0
        }
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
        registration.streamState.isInstallationManaged = true
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

    /// Once a mailbox has entered installation-scoped synchronization, the
    /// profile-wide legacy fetch/ack capability must never become a fallback.
    /// Revoking every consumer therefore does not reopen the legacy path.
    public func hasMailboxConsumerBindings(inboxId: String) -> Bool {
        inboxRegistrations[inboxId]?.streamState.isInstallationManaged ?? false
    }

    /// Returns the credential bound to a consumer, including a revoked one so
    /// a request can be authenticated before the state machine rejects it.
    /// Legacy records without a bound key deliberately return `nil` and cannot
    /// sync or commit until jointly re-authorized through registration.
    public func mailboxConsumerSigningPublicKey(
        inboxId: String,
        consumerId: MailboxConsumerId
    ) -> Data? {
        guard consumerId.isStructurallyValid,
              let key = inboxRegistrations[inboxId]?
                .streamState.consumers[consumerId.rawValue]?
                .consumerSigningPublicKey,
              SigningKeyPair.isValidPublicKey(key) else {
            return nil
        }
        return key
    }

    public func activeMailboxConsumerSigningPublicKey(
        inboxId: String,
        consumerId: MailboxConsumerId
    ) -> Data? {
        guard consumerId.isStructurallyValid,
              let consumer = inboxRegistrations[inboxId]?
                .streamState.consumers[consumerId.rawValue],
              consumer.state == .active,
              let key = consumer.consumerSigningPublicKey,
              SigningKeyPair.isValidPublicKey(key) else {
            return nil
        }
        return key
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
        guard consumer.consumerSigningPublicKey.map(SigningKeyPair.isValidPublicKey) == true else {
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
            } else if cursor == Self.legacyMailboxCursor(
                inboxId: inboxId,
                consumerId: consumerId,
                sequence: consumer.committedSequence,
                key: consumer.cursorKey
            ) {
                startSequence = consumer.committedSequence
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
        guard consumer.consumerSigningPublicKey.map(SigningKeyPair.isValidPublicKey) == true else {
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
        let acceptsLegacyCursor = cursor == Self.legacyMailboxCursor(
            inboxId: inboxId,
            consumerId: consumerId,
            sequence: sequence,
            key: consumer.cursorKey
        )
        guard authenticatedSequence == sequence || acceptsLegacyCursor else {
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

    @discardableResult
    public func acknowledge(inboxId: String, messageIds: [UUID]) throws -> Int {
        let ids = Set(messageIds.prefix(1_000))
        guard !ids.isEmpty else {
            return 0
        }
        let inbox = mailboxes[inboxId, default: []]
        let protectedFloor = inboxRegistrations[inboxId]?.streamState.consumers.values.compactMap {
            $0.state == .active ? $0.committedSequence : nil
        }.min()
        let remaining = inbox.filter { record in
            guard ids.contains(record.envelope.id) else { return true }
            guard record.pendingGroupRecipientFingerprints == nil else { return true }
            guard let protectedFloor else { return false }
            return record.sequence > protectedFloor
        }
        let removed = inbox.count - remaining.count
        if remaining.isEmpty {
            mailboxes.removeValue(forKey: inboxId)
        } else {
            mailboxes[inboxId] = remaining
        }
        if removed > 0 {
            try saveToDisk()
        }
        return removed
    }

    @discardableResult
    public func acknowledgeGroupEnvelopes(
        inboxId: String,
        messageIds: [UUID],
        recipientFingerprint: String
    ) throws -> Int {
        let ids = Set(messageIds.prefix(1_000))
        let recipient = recipientFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !ids.isEmpty, !recipient.isEmpty else {
            return 0
        }
        var removedForRecipient = 0
        var updated = false
        var remaining: [StoredEnvelope] = []
        let protectsV2Consumers = inboxRegistrations[inboxId]?.streamState.consumers.values.contains {
            $0.state == .active
        } ?? false
        let retentionFloor = inboxRegistrations[inboxId]?.streamState.retentionFloor ?? 0
        for var record in mailboxes[inboxId, default: []] {
            guard ids.contains(record.envelope.id),
                  var pending = record.pendingGroupRecipientFingerprints else {
                remaining.append(record)
                continue
            }
            if pending.remove(recipient) != nil {
                removedForRecipient += 1
                updated = true
            }
            if !pending.isEmpty {
                record.pendingGroupRecipientFingerprints = pending
                remaining.append(record)
            } else if protectsV2Consumers, record.sequence > retentionFloor {
                record.pendingGroupRecipientFingerprints = []
                remaining.append(record)
            } else {
                updated = true
            }
        }
        if updated {
            if remaining.isEmpty {
                mailboxes.removeValue(forKey: inboxId)
            } else {
                mailboxes[inboxId] = remaining
            }
            try saveToDisk()
        }
        return removedForRecipient
    }

    private func envelopePayloadBytes(_ envelope: Envelope) -> Int {
        envelope.payload.nonce.count + envelope.payload.ciphertext.count + envelope.payload.tag.count
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
        let remaining = mailboxes[inboxId, default: []].filter {
            if $0.sequence > floor {
                return true
            }
            return !($0.pendingGroupRecipientFingerprints?.isEmpty ?? true)
        }
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

    /// Accepts cursor tokens issued by the first architecture-v2 preview so a
    /// persisted post-decryption commit can finish during the pre-1.0 upgrade.
    private static func legacyMailboxCursor(
        inboxId: String,
        consumerId: MailboxConsumerId,
        sequence: UInt64,
        key: Data
    ) -> MailboxCursor {
        MailboxCursor(
            rawValue: mailboxCursorAuthenticationCode(
                inboxId: inboxId,
                consumerId: consumerId,
                sequenceData: mailboxCursorSequenceData(sequence),
                key: key
            ).base64EncodedString()
        )
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

    public func announce(_ offer: ContactOffer, ttlSeconds: Int? = nil, now: Date = Date()) -> PairingAnnouncement {
        pruneAnnouncements(now: now)
        let requestedTTL = TimeInterval(ttlSeconds ?? Int(announcementTTL))
        let ttl = min(maximumAnnouncementTTL, max(minimumAnnouncementTTL, requestedTTL))
        let visibleNow = bucketed(now, discriminator: "announce:\(offer.fingerprint)")
        let announcement = PairingAnnouncement(
            offer: offer,
            announcedAt: visibleNow,
            expiresAt: visibleNow.addingTimeInterval(ttl)
        )
        announcements[offer.fingerprint] = announcement
        if announcements.count > maxAnnouncements,
           let oldest = announcements.min(by: { $0.value.announcedAt < $1.value.announcedAt })?.key {
            announcements.removeValue(forKey: oldest)
        }
        return announcement
    }

    public func listAnnouncements(limit: Int? = nil) -> [PairingAnnouncement] {
        pruneAnnouncements(now: Date())
        let list = announcements.values.sorted { $0.announcedAt > $1.announcedAt }
        let boundedLimit = min(500, max(0, limit ?? 500))
        return Array(list.prefix(boundedLimit))
    }

    public func sendPairRequest(targetFingerprint: String, offer: ContactOffer, now: Date = Date()) -> Int {
        if pairRequests[targetFingerprint] == nil,
           pairRequests.count >= maxPairRequestTargets,
           let oldestTarget = pairRequests.min(by: {
               ($0.value.first?.sentAt ?? .distantFuture) < ($1.value.first?.sentAt ?? .distantFuture)
           })?.key {
            pairRequests.removeValue(forKey: oldestTarget)
        }
        var requests = pairRequests[targetFingerprint, default: []]
        requests.append(PairingRequest(
            from: offer,
            sentAt: bucketed(now, discriminator: "pair:\(targetFingerprint):\(offer.fingerprint)")
        ))
        if requests.count > maxPairRequests {
            requests = Array(requests.suffix(maxPairRequests))
        }
        pairRequests[targetFingerprint] = requests
        return requests.count
    }

    public func fetchPairRequests(targetFingerprint: String, maxCount: Int? = nil) -> [PairingRequest] {
        let requests = pairRequests[targetFingerprint, default: []]
        let count = max(0, maxCount ?? requests.count)
        return Array(requests.prefix(count))
    }

    public func uploadPrekeyBundle(
        fingerprint: String,
        bundle: PrekeyBundle,
        ttlSeconds: Int?
    ) throws {
        guard !fingerprint.isEmpty,
              fingerprint == bundle.identityFingerprint,
              bundle.oneTimePrekeys.count <= maxOneTimePrekeysPerBundle,
              bundle.isStructurallyValid() else {
            throw RelayStoreError.invalidPrekeyBundle
        }
        let requestedTTL = TimeInterval(ttlSeconds ?? Int(prekeyTTL))
        let ttl = min(maximumPrekeyTTL, max(minimumPrekeyTTL, requestedTTL))
        let now = Date()
        prunePrekeys(now: now)
        if prekeyBundles[fingerprint] == nil,
           prekeyBundles.count >= maxPrekeyBundles,
           let oldest = prekeyBundles.min(by: { $0.value.expiresAt < $1.value.expiresAt })?.key {
            prekeyBundles.removeValue(forKey: oldest)
        }
        prekeyBundles[fingerprint] = PrekeyBundleRecord(
            bundle: bundle,
            expiresAt: now.addingTimeInterval(ttl)
        )
        try saveToDisk()
    }

    public func fetchPrekeyBundle(fingerprint: String) throws -> PrekeyBundle? {
        prunePrekeys(now: Date())
        guard var record = prekeyBundles[fingerprint] else {
            return nil
        }
        guard record.bundle.isStructurallyValid() else {
            prekeyBundles.removeValue(forKey: fingerprint)
            try saveToDisk()
            throw RelayStoreError.invalidPrekeyBundle
        }
        var bundle = record.bundle
        if !bundle.oneTimePrekeys.isEmpty {
            let prekey = bundle.oneTimePrekeys[0]
            bundle = PrekeyBundle(
                version: bundle.version,
                identityFingerprint: bundle.identityFingerprint,
                signedPrekey: bundle.signedPrekey,
                oneTimePrekeys: [prekey],
                createdAt: bundle.createdAt
            )
            record.bundle = PrekeyBundle(
                version: record.bundle.version,
                identityFingerprint: record.bundle.identityFingerprint,
                signedPrekey: record.bundle.signedPrekey,
                oneTimePrekeys: Array(record.bundle.oneTimePrekeys.dropFirst()),
                createdAt: record.bundle.createdAt
            )
            prekeyBundles[fingerprint] = record
            try saveToDisk()
            return bundle
        }
        return bundle
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

    public func createGroup(
        groupId: UUID? = nil,
        title: String,
        creatorFingerprint: String,
        memberFingerprints: [String],
        creatorProfile: RelayGroupMemberProfile? = nil,
        memberProfiles: [RelayGroupMemberProfile]? = nil,
        invitedFingerprints: [String] = [],
        initialRatchetSecretDistribution: GroupRatchetEpochSecretDistribution? = nil
    ) throws -> RelayGroupDescriptor {
        let trimmedTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedTitle.isEmpty, trimmedTitle.count <= maxGroupTitleCharacters else {
            throw RelayStoreError.invalidGroupTitle
        }
        let creator = creatorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !creator.isEmpty else {
            throw RelayStoreError.invalidFingerprint
        }
        var profileByFingerprint: [String: RelayGroupMemberProfile] = [:]
        if let normalizedCreatorProfile = normalizedMemberProfile(creatorProfile),
           normalizedCreatorProfile.fingerprint == creator {
            profileByFingerprint[creator] = normalizedCreatorProfile
        }
        for profile in memberProfiles ?? [] {
            guard let normalized = normalizedMemberProfile(profile) else { continue }
            profileByFingerprint[normalized.fingerprint] = normalized
        }

        var normalizedMembers = Set(memberFingerprints.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty })
        normalizedMembers.formUnion(profileByFingerprint.keys)
        normalizedMembers.insert(creator)
        let normalizedInvitedFingerprints = Set(invitedFingerprints.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty && $0 != creator && !normalizedMembers.contains($0) })
        guard normalizedMembers.count >= 2 || !normalizedInvitedFingerprints.isEmpty else {
            throw RelayStoreError.notEnoughGroupMembers
        }
        guard normalizedMembers.union(normalizedInvitedFingerprints).count <= maxGroupMembers else {
            throw RelayStoreError.groupCapacityExceeded
        }
        guard groups.count < maxGroups,
              groups.values.filter({ $0.createdByFingerprint == creator }).count < maxGroupsPerCreator else {
            throw RelayStoreError.groupCapacityExceeded
        }

        let now = Date()
        let descriptorId = groupId ?? UUID()
        guard groups[descriptorId] == nil else {
            throw RelayStoreError.groupCapacityExceeded
        }
        try validateInvitationBucketsCanAdd(
            groupId: descriptorId,
            fingerprints: normalizedInvitedFingerprints
        )
        let descriptorInboxId = InboxAddress.generate()
        let members = normalizedMembers.sorted().map { fingerprint in
            makeGroupMember(
                fingerprint: fingerprint,
                existing: nil,
                profile: profileByFingerprint[fingerprint],
                joinedAt: now
            )
        }
        try validateRatchetSecretDistribution(
            initialRatchetSecretDistribution,
            groupId: descriptorId,
            epoch: 0,
            operation: .create,
            memberFingerprints: members.map(\.fingerprint)
        )
        let group = RelayGroupDescriptor(
            id: descriptorId,
            title: trimmedTitle,
            inboxId: descriptorInboxId,
            createdByFingerprint: creator,
            members: members,
            mlsEpochState: MLSGroupEpochState.initial(
                groupId: descriptorId,
                title: trimmedTitle,
                inboxId: descriptorInboxId,
                createdByFingerprint: creator,
                members: members,
                createdAt: now,
                ratchetSecretDistribution: initialRatchetSecretDistribution
            ),
            createdAt: now,
            updatedAt: now
        )
        groups[group.id] = group
        for fingerprint in normalizedInvitedFingerprints.sorted() {
            insertGroupInvitation(
                RelayGroupInvitation(
                    groupId: group.id,
                    title: group.title,
                    createdByFingerprint: group.createdByFingerprint,
                    invitedFingerprint: fingerprint,
                    inboxId: group.inboxId,
                    epoch: group.epoch,
                    createdAt: group.createdAt,
                    updatedAt: group.updatedAt,
                    invitedAt: now
                )
            )
        }
        try saveToDisk()
        return group
    }

    public func fetchGroup(groupId: UUID) -> RelayGroupDescriptor? {
        groups[groupId]
    }

    public func listGroups(memberFingerprint: String, limit: Int? = nil) -> [RelayGroupDescriptor] {
        let fingerprint = memberFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !fingerprint.isEmpty else {
            return []
        }
        var list = groups.values.filter { group in
            group.members.contains { $0.fingerprint == fingerprint }
        }
        list.sort { lhs, rhs in
            if lhs.updatedAt != rhs.updatedAt {
                return lhs.updatedAt > rhs.updatedAt
            }
            return lhs.createdAt > rhs.createdAt
        }
        return Array(list.prefix(min(500, max(0, limit ?? 500))))
    }

    public func listGroupInvitations(_ request: ListGroupInvitationsRequest) -> [RelayGroupInvitation] {
        let fingerprint = request.invitedFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !fingerprint.isEmpty else {
            return []
        }
        var invitations = groupInvitations[fingerprint, default: []].filter { invitation in
            groups[invitation.groupId] != nil
        }
        invitations.sort { lhs, rhs in
            if lhs.invitedAt != rhs.invitedAt {
                return lhs.invitedAt > rhs.invitedAt
            }
            return lhs.updatedAt > rhs.updatedAt
        }
        return Array(invitations.prefix(min(500, max(0, request.limit ?? 500))))
    }

    public func hasGroupInvitation(groupId: UUID, invitedFingerprint: String) -> Bool {
        let fingerprint = invitedFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !fingerprint.isEmpty else {
            return false
        }
        return groupInvitations[fingerprint, default: []].contains { invitation in
            invitation.groupId == groupId && groups[groupId] != nil
        }
    }

    public func inviteGroupMembers(_ request: InviteGroupMembersRequest) throws -> RelayGroupDescriptor {
        guard var group = groups[request.groupId] else {
            throw RelayStoreError.groupNotFound
        }
        let actor = request.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !actor.isEmpty else {
            throw RelayStoreError.invalidFingerprint
        }
        guard actor == group.createdByFingerprint else {
            throw RelayStoreError.unauthorizedGroupMutation
        }

        let currentMembers = Set(group.members.map(\.fingerprint))
        let requestedInvitees = Set(request.normalizedInvitedFingerprints.filter { fingerprint in
            fingerprint != group.createdByFingerprint && !currentMembers.contains(fingerprint)
        })
        let existingInvitees = groupInvitationFingerprintsByGroup[group.id, default: []]
        let invitees = requestedInvitees.subtracting(existingInvitees)
        guard !invitees.isEmpty else {
            return group
        }
        try validateGroupParticipantCapacity(
            groupId: group.id,
            memberFingerprints: currentMembers,
            addingPendingInvitees: invitees
        )
        try validateInvitationBucketsCanAdd(groupId: group.id, fingerprints: invitees)

        let now = Date()
        group.updatedAt = now
        groups[group.id] = group
        for fingerprint in invitees.sorted() {
            insertGroupInvitation(
                RelayGroupInvitation(
                    groupId: group.id,
                    title: group.title,
                    createdByFingerprint: group.createdByFingerprint,
                    invitedFingerprint: fingerprint,
                    inboxId: group.inboxId,
                    epoch: group.epoch,
                    createdAt: group.createdAt,
                    updatedAt: group.updatedAt,
                    invitedAt: now
                )
            )
        }
        try saveToDisk()
        return group
    }

    public func updateGroup(_ request: UpdateGroupRequest) throws -> RelayGroupDescriptor {
        guard var group = groups[request.groupId] else {
            throw RelayStoreError.groupNotFound
        }
        let actor = request.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !actor.isEmpty else {
            throw RelayStoreError.invalidFingerprint
        }
        let isCreator = actor == group.createdByFingerprint
        let isMember = group.members.contains { $0.fingerprint == actor }
        guard isCreator || isMember else {
            throw RelayStoreError.unauthorizedGroupMutation
        }
        let operation = expectedGroupCommitOperation(
            request: request,
            actorFingerprint: actor,
            isCreator: isCreator
        )
        try validateGroupCommit(
            request: request,
            group: group,
            actorFingerprint: actor,
            operation: operation
        )

        if !isCreator {
            let hasTitleChange = !(request.title?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
            let hasMemberAdds = request.addMemberFingerprints.contains {
                !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            } || (request.addMemberProfiles?.contains { normalizedMemberProfile($0) != nil } ?? false)
            let removeSet = Set(request.removeMemberFingerprints.map {
                $0.trimmingCharacters(in: .whitespacesAndNewlines)
            }.filter { !$0.isEmpty })
            let isSelfRemovalOnly = !removeSet.isEmpty && removeSet.isSubset(of: [actor])
            guard !hasTitleChange, !hasMemberAdds, isSelfRemovalOnly else {
                throw RelayStoreError.unauthorizedGroupMutation
            }
        }

        var changed = false
        if let title = request.title?.trimmingCharacters(in: .whitespacesAndNewlines),
           !title.isEmpty,
           title != group.title {
            guard title.count <= maxGroupTitleCharacters else {
                throw RelayStoreError.invalidGroupTitle
            }
            group.title = title
            changed = true
        }

        var memberMap = Dictionary(uniqueKeysWithValues: group.members.map { ($0.fingerprint, $0) })
        for fingerprint in request.addMemberFingerprints {
            let normalized = fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !normalized.isEmpty else { continue }
            if memberMap[normalized] == nil {
                memberMap[normalized] = makeGroupMember(
                    fingerprint: normalized,
                    existing: nil,
                    profile: nil,
                    joinedAt: Date()
                )
                changed = true
            }
        }
        for profile in request.addMemberProfiles ?? [] {
            guard let normalized = normalizedMemberProfile(profile) else { continue }
            let existing = memberMap[normalized.fingerprint]
            let merged = makeGroupMember(
                fingerprint: normalized.fingerprint,
                existing: existing,
                profile: normalized,
                joinedAt: Date()
            )
            if existing != merged {
                memberMap[normalized.fingerprint] = merged
                changed = true
            }
        }
        for fingerprint in request.removeMemberFingerprints {
            let normalized = fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !normalized.isEmpty else { continue }
            guard normalized != group.createdByFingerprint else { continue }
            if memberMap.removeValue(forKey: normalized) != nil {
                changed = true
            }
        }
        let projectedMemberFingerprints = Set(memberMap.keys)
        var consumedInvitationFingerprints = groupInvitationFingerprintsByGroup[group.id, default: []]
            .intersection(projectedMemberFingerprints)
        for pendingRequest in groupJoinRequests[group.id, default: []]
        where projectedMemberFingerprints.contains(pendingRequest.requester.fingerprint) {
            if let invitedFingerprint = pendingRequest.invitedFingerprint?
                .trimmingCharacters(in: .whitespacesAndNewlines),
               !invitedFingerprint.isEmpty {
                consumedInvitationFingerprints.insert(invitedFingerprint)
            }
        }
        try validateGroupParticipantCapacity(
            groupId: group.id,
            memberFingerprints: projectedMemberFingerprints,
            removingPendingInvitees: consumedInvitationFingerprints
        )

        guard memberMap.count >= 2 || operation == .selfLeave else {
            throw RelayStoreError.notEnoughGroupMembers
        }

        if changed {
            let now = Date()
            guard group.epoch < UInt64.max else {
                throw RelayStoreError.invalidGroupCommit
            }
            let nextEpochState = try group.mlsEpochState.advancing(
                title: group.title,
                inboxId: group.inboxId,
                actorFingerprint: actor,
                members: memberMap.values.sorted { $0.fingerprint < $1.fingerprint },
                operation: operation,
                committedAt: now,
                ratchetSecretDistribution: request.groupCommit?.ratchetSecretDistribution
            )
            group.members = memberMap.values.sorted { $0.fingerprint < $1.fingerprint }
            group.epoch = nextEpochState.epoch
            group.updatedAt = now
            group.mlsEpochState = nextEpochState
            group.mlsEpochHistory = boundedGroupEpochHistory(
                group.mlsEpochHistory + [group.mlsEpochState.lastCommit]
            )
            groups[group.id] = group
            for invitedFingerprint in consumedInvitationFingerprints {
                removeGroupInvitation(groupId: group.id, invitedFingerprint: invitedFingerprint)
            }
            if var pending = groupJoinRequests[group.id] {
                pending.removeAll { pendingRequest in
                    group.members.contains { $0.fingerprint == pendingRequest.requester.fingerprint }
                }
                if pending.isEmpty {
                    groupJoinRequests.removeValue(forKey: group.id)
                } else {
                    groupJoinRequests[group.id] = pending
                }
            }
            try saveToDisk()
        }
        return group
    }

    private func expectedGroupCommitOperation(
        request: UpdateGroupRequest,
        actorFingerprint: String,
        isCreator: Bool
    ) -> MLSGroupCommitOperation {
        if request.groupCommit?.operation == .joinApprove,
           isCreator,
           request.normalizedTitle == nil,
           !request.normalizedAddMemberFingerprints.isEmpty,
           request.normalizedRemoveMemberFingerprints.isEmpty {
            return .joinApprove
        }
        return groupCommitOperation(
            request: request,
            actorFingerprint: actorFingerprint,
            isCreator: isCreator
        )
    }

    private func validateGroupCommit(
        request: UpdateGroupRequest,
        group: RelayGroupDescriptor,
        actorFingerprint: String,
        operation: MLSGroupCommitOperation
    ) throws {
        guard let commit = request.groupCommit else {
            throw RelayStoreError.invalidGroupCommit
        }
        guard commit.operation == operation,
              commit.groupId == request.groupId,
              commit.actorFingerprint == actorFingerprint,
              commit.baseEpoch == group.epoch,
              commit.previousTranscriptHash == group.mlsEpochState.confirmedTranscriptHash,
              commit.title == request.normalizedTitle,
              Set(commit.addMemberFingerprints) == Set(request.normalizedAddMemberFingerprints),
              (commit.addMemberProfiles ?? []).sorted(by: { $0.fingerprint < $1.fingerprint }) == request.normalizedAddMemberProfiles,
              Set(commit.removeMemberFingerprints) == Set(request.normalizedRemoveMemberFingerprints) else {
            throw RelayStoreError.invalidGroupCommit
        }
        guard group.epoch < UInt64.max else {
            throw RelayStoreError.invalidGroupCommit
        }
        try validateRatchetSecretDistribution(
            commit.ratchetSecretDistribution,
            groupId: group.id,
            epoch: group.epoch + 1,
            operation: operation,
            memberFingerprints: projectedMemberFingerprints(for: request, group: group)
        )
    }

    private func validateRatchetSecretDistribution(
        _ distribution: GroupRatchetEpochSecretDistribution?,
        groupId: UUID,
        epoch: UInt64,
        operation: MLSGroupCommitOperation,
        memberFingerprints: [String]
    ) throws {
        guard let distribution else {
            return
        }
        let members = Set(memberFingerprints.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty })
        guard distribution.groupId == groupId,
              distribution.epoch == epoch,
              distribution.operation == operation,
              distribution.isStructurallyValid,
              Set(distribution.memberFingerprints) == members,
              Set(distribution.shares.map(\.recipientFingerprint)) == members,
              distribution.shares.count == members.count else {
            throw RelayStoreError.invalidGroupCommit
        }
    }

    private func boundedGroupEpochHistory(_ history: [MLSGroupCommitSummary]) -> [MLSGroupCommitSummary] {
        Array(history.sorted { $0.epoch < $1.epoch }.suffix(maxGroupEpochHistory))
    }

    private func projectedMemberFingerprints(
        for request: UpdateGroupRequest,
        group: RelayGroupDescriptor
    ) -> [String] {
        var members = Set(group.members.map(\.fingerprint))
        members.formUnion(request.normalizedAddMemberFingerprints)
        members.formUnion(request.normalizedAddMemberProfiles.map(\.fingerprint))
        members.subtract(request.normalizedRemoveMemberFingerprints)
        members.insert(group.createdByFingerprint)
        return members.sorted()
    }

    private func groupCommitOperation(
        request: UpdateGroupRequest,
        actorFingerprint: String,
        isCreator: Bool
    ) -> MLSGroupCommitOperation {
        let hasTitleChange = !(request.title?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
        let addFingerprints = request.addMemberFingerprints.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty }
        let hasProfileAdds = request.addMemberProfiles?.contains { normalizedMemberProfile($0) != nil } ?? false
        let removeFingerprints = request.removeMemberFingerprints.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty }

        if !isCreator && !removeFingerprints.isEmpty && Set(removeFingerprints).isSubset(of: [actorFingerprint]) {
            return .selfLeave
        }
        if !addFingerprints.isEmpty || hasProfileAdds {
            return removeFingerprints.isEmpty && !hasTitleChange ? .addMembers : .update
        }
        if !removeFingerprints.isEmpty {
            return hasTitleChange ? .update : .removeMembers
        }
        return .update
    }

    public func deleteGroup(_ request: DeleteGroupRequest) throws {
        guard let group = groups[request.groupId] else {
            throw RelayStoreError.groupNotFound
        }
        let actor = request.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !actor.isEmpty else {
            throw RelayStoreError.invalidFingerprint
        }
        guard actor == group.createdByFingerprint else {
            throw RelayStoreError.unauthorizedGroupMutation
        }
        groups.removeValue(forKey: request.groupId)
        groupJoinRequests.removeValue(forKey: request.groupId)
        removeGroupInvitations(groupId: request.groupId)
        try saveToDisk()
    }

    public func requestGroupJoin(_ request: RequestGroupJoinRequest) throws -> RelayGroupJoinRequest {
        guard let group = groups[request.groupId] else {
            throw RelayStoreError.groupNotFound
        }
        guard let requester = normalizedMemberProfile(request.requesterProfile) else {
            throw RelayStoreError.invalidFingerprint
        }
        let invitedFingerprint = request.invitedFingerprint?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let invitedFingerprint, !invitedFingerprint.isEmpty {
            guard groupInvitations[invitedFingerprint, default: []].contains(where: { $0.groupId == group.id }) else {
                throw RelayStoreError.unauthorizedGroupMutation
            }
        }
        if group.members.contains(where: { $0.fingerprint == requester.fingerprint }) {
            throw RelayStoreError.alreadyGroupMember
        }

        var pending = groupJoinRequests[group.id, default: []]
        let now = Date()
        if let existingIndex = pending.firstIndex(where: { $0.requester.fingerprint == requester.fingerprint }) {
            let existing = pending[existingIndex]
            let refreshed = RelayGroupJoinRequest(
                id: existing.id,
                groupId: group.id,
                requester: requester,
                invitedFingerprint: invitedFingerprint?.isEmpty == false ? invitedFingerprint : existing.invitedFingerprint,
                requestedAt: now
            )
            pending[existingIndex] = refreshed
            pending.sort { lhs, rhs in lhs.requestedAt > rhs.requestedAt }
            groupJoinRequests[group.id] = pending
            try saveToDisk()
            return refreshed
        }

        let joinRequest = RelayGroupJoinRequest(
            groupId: group.id,
            requester: requester,
            invitedFingerprint: invitedFingerprint?.isEmpty == false ? invitedFingerprint : nil,
            requestedAt: now
        )
        pending.insert(joinRequest, at: 0)
        if pending.count > maxGroupJoinRequests {
            pending = Array(pending.prefix(maxGroupJoinRequests))
        }
        groupJoinRequests[group.id] = pending
        try saveToDisk()
        return joinRequest
    }

    public func acceptGroupInvitation(_ request: RequestGroupJoinRequest) throws -> RelayGroupDescriptor {
        guard var group = groups[request.groupId] else {
            throw RelayStoreError.groupNotFound
        }
        guard let requester = normalizedMemberProfile(request.requesterProfile) else {
            throw RelayStoreError.invalidFingerprint
        }
        let invitedFingerprint = request.invitedFingerprint?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !invitedFingerprint.isEmpty,
              groupInvitations[invitedFingerprint, default: []].contains(where: { $0.groupId == group.id }) else {
            throw RelayStoreError.unauthorizedGroupMutation
        }
        if group.members.contains(where: { $0.fingerprint == requester.fingerprint }) {
            removeGroupInvitation(groupId: group.id, invitedFingerprint: invitedFingerprint)
            try saveToDisk()
            return group
        }
        guard let commit = request.groupCommit,
              commit.operation == .joinApprove,
              commit.groupId == group.id,
              commit.actorFingerprint == requester.fingerprint,
              commit.baseEpoch == group.epoch,
              commit.previousTranscriptHash == group.mlsEpochState.confirmedTranscriptHash,
              commit.title == nil,
              Set(commit.addMemberFingerprints) == Set([requester.fingerprint]),
              commit.addMemberProfiles == [requester],
              commit.removeMemberFingerprints.isEmpty else {
            throw RelayStoreError.invalidGroupCommit
        }

        let memberProfiles = projectedGroupMemberProfiles(
            currentMembers: group.members,
            addProfiles: [requester]
        )
        guard group.epoch < UInt64.max else {
            throw RelayStoreError.invalidGroupCommit
        }
        try validateRatchetSecretDistribution(
            commit.ratchetSecretDistribution,
            groupId: group.id,
            epoch: group.epoch + 1,
            operation: .joinApprove,
            memberFingerprints: memberProfiles.map(\.fingerprint)
        )

        var memberMap = Dictionary(uniqueKeysWithValues: group.members.map { ($0.fingerprint, $0) })
        memberMap[requester.fingerprint] = makeGroupMember(
            fingerprint: requester.fingerprint,
            existing: nil,
            profile: requester,
            joinedAt: Date()
        )
        try validateGroupParticipantCapacity(
            groupId: group.id,
            memberFingerprints: Set(memberMap.keys),
            removingPendingInvitees: [invitedFingerprint]
        )

        let now = Date()
        let nextEpochState = try group.mlsEpochState.advancing(
            title: group.title,
            inboxId: group.inboxId,
            actorFingerprint: requester.fingerprint,
            members: memberMap.values.sorted { $0.fingerprint < $1.fingerprint },
            operation: .joinApprove,
            committedAt: now,
            ratchetSecretDistribution: commit.ratchetSecretDistribution
        )
        group.members = memberMap.values.sorted { $0.fingerprint < $1.fingerprint }
        group.epoch = nextEpochState.epoch
        group.updatedAt = now
        group.mlsEpochState = nextEpochState
        group.mlsEpochHistory = boundedGroupEpochHistory(
            group.mlsEpochHistory + [group.mlsEpochState.lastCommit]
        )
        groups[group.id] = group
        removeGroupInvitation(groupId: group.id, invitedFingerprint: invitedFingerprint)
        if var pending = groupJoinRequests[group.id] {
            pending.removeAll { $0.requester.fingerprint == requester.fingerprint }
            if pending.isEmpty {
                groupJoinRequests.removeValue(forKey: group.id)
            } else {
                groupJoinRequests[group.id] = pending
            }
        }
        try saveToDisk()
        return group
    }

    public func listGroupJoinRequests(_ request: ListGroupJoinRequestsRequest) throws -> [RelayGroupJoinRequest] {
        guard let group = groups[request.groupId] else {
            throw RelayStoreError.groupNotFound
        }
        let actor = request.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !actor.isEmpty else {
            throw RelayStoreError.invalidFingerprint
        }
        guard actor == group.createdByFingerprint else {
            throw RelayStoreError.unauthorizedGroupMutation
        }
        var pending = groupJoinRequests[group.id, default: []]
        pending.sort { lhs, rhs in lhs.requestedAt > rhs.requestedAt }
        if let limit = request.limit {
            return Array(pending.prefix(max(0, limit)))
        }
        return pending
    }

    public func approveGroupJoin(_ request: ApproveGroupJoinRequest) throws -> RelayGroupDescriptor {
        guard let group = groups[request.groupId] else {
            throw RelayStoreError.groupNotFound
        }
        let actor = request.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !actor.isEmpty else {
            throw RelayStoreError.invalidFingerprint
        }
        guard actor == group.createdByFingerprint else {
            throw RelayStoreError.unauthorizedGroupMutation
        }

        let pending = groupJoinRequests[group.id, default: []]
        guard pending.contains(where: { $0.id == request.joinRequestId }) else {
            throw RelayStoreError.groupJoinRequestNotFound
        }
        guard let joinRequest = pending.first(where: { $0.id == request.joinRequestId }) else {
            throw RelayStoreError.groupJoinRequestNotFound
        }

        let updated = try updateGroup(
            UpdateGroupRequest(
                groupId: group.id,
                actorFingerprint: actor,
                addMemberFingerprints: [joinRequest.requester.fingerprint],
                addMemberProfiles: [joinRequest.requester],
                groupCommit: request.groupCommit
            )
        )

        var refreshedPending = groupJoinRequests[group.id, default: []]
        refreshedPending.removeAll { $0.id == request.joinRequestId }
        if refreshedPending.isEmpty {
            groupJoinRequests.removeValue(forKey: group.id)
        } else {
            groupJoinRequests[group.id] = refreshedPending
        }
        if updated.members.contains(where: { $0.fingerprint == joinRequest.requester.fingerprint }) {
            if let invitedFingerprint = joinRequest.invitedFingerprint {
                removeGroupInvitation(groupId: group.id, invitedFingerprint: invitedFingerprint)
            }
            try saveToDisk()
            return updated
        }

        throw RelayStoreError.invalidGroupCommit
    }

    public func rejectGroupJoin(_ request: RejectGroupJoinRequest) throws {
        guard let group = groups[request.groupId] else {
            throw RelayStoreError.groupNotFound
        }
        let actor = request.actorFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !actor.isEmpty else {
            throw RelayStoreError.invalidFingerprint
        }
        guard actor == group.createdByFingerprint else {
            throw RelayStoreError.unauthorizedGroupMutation
        }

        var pending = groupJoinRequests[group.id, default: []]
        guard let index = pending.firstIndex(where: { $0.id == request.joinRequestId }) else {
            throw RelayStoreError.groupJoinRequestNotFound
        }
        pending.remove(at: index)
        if pending.isEmpty {
            groupJoinRequests.removeValue(forKey: group.id)
        } else {
            groupJoinRequests[group.id] = pending
        }
        try saveToDisk()
    }

    private func removeGroupInvitation(groupId: UUID, invitedFingerprint: String) {
        let fingerprint = invitedFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !fingerprint.isEmpty, var invitations = groupInvitations[fingerprint] else {
            return
        }
        invitations.removeAll { $0.groupId == groupId }
        if invitations.isEmpty {
            groupInvitations.removeValue(forKey: fingerprint)
        } else {
            groupInvitations[fingerprint] = invitations
        }
        groupInvitationFingerprintsByGroup[groupId]?.remove(fingerprint)
        if groupInvitationFingerprintsByGroup[groupId]?.isEmpty == true {
            groupInvitationFingerprintsByGroup.removeValue(forKey: groupId)
        }
    }

    private func removeGroupInvitations(groupId: UUID) {
        for fingerprint in groupInvitationFingerprintsByGroup[groupId, default: []] {
            removeGroupInvitation(groupId: groupId, invitedFingerprint: fingerprint)
        }
    }

    private func insertGroupInvitation(_ invitation: RelayGroupInvitation) {
        let fingerprint = invitation.invitedFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !fingerprint.isEmpty,
              !groupInvitations[fingerprint, default: []].contains(where: { $0.groupId == invitation.groupId }) else {
            return
        }
        groupInvitations[fingerprint, default: []].insert(invitation, at: 0)
        groupInvitationFingerprintsByGroup[invitation.groupId, default: []].insert(fingerprint)
    }

    private func validateInvitationBucketsCanAdd(
        groupId: UUID,
        fingerprints: Set<String>
    ) throws {
        for fingerprint in fingerprints {
            let existingGroupIds = Set(groupInvitations[fingerprint, default: []].map(\.groupId))
            guard existingGroupIds.contains(groupId)
                    || existingGroupIds.count < maxGroupInvitationsPerIdentity else {
                throw RelayStoreError.groupCapacityExceeded
            }
        }
    }

    private func validateGroupParticipantCapacity(
        groupId: UUID,
        memberFingerprints: Set<String>,
        addingPendingInvitees: Set<String> = [],
        removingPendingInvitees: Set<String> = []
    ) throws {
        var pendingInvitees = groupInvitationFingerprintsByGroup[groupId, default: []]
        pendingInvitees.formUnion(addingPendingInvitees)
        pendingInvitees.subtract(removingPendingInvitees)
        pendingInvitees.subtract(memberFingerprints)
        guard memberFingerprints.union(pendingInvitees).count <= maxGroupMembers else {
            throw RelayStoreError.groupCapacityExceeded
        }
    }

    private func normalizeGroupInvitationsAfterLoad() {
        let candidates = groupInvitations.values
            .flatMap { $0 }
            .sorted { lhs, rhs in
                if lhs.invitedAt != rhs.invitedAt {
                    return lhs.invitedAt > rhs.invitedAt
                }
                return lhs.id.uuidString < rhs.id.uuidString
            }
        groupInvitations = [:]
        groupInvitationFingerprintsByGroup = [:]
        for invitation in candidates {
            let fingerprint = invitation.invitedFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !fingerprint.isEmpty,
                  let group = groups[invitation.groupId],
                  !group.members.contains(where: { $0.fingerprint == fingerprint }),
                  !groupInvitations[fingerprint, default: []].contains(where: {
                      $0.groupId == invitation.groupId
                  }),
                  groupInvitations[fingerprint, default: []].count < maxGroupInvitationsPerIdentity else {
                continue
            }
            let activeFingerprints = Set(group.members.map(\.fingerprint))
            let pendingFingerprints = groupInvitationFingerprintsByGroup[group.id, default: []]
            guard activeFingerprints.union(pendingFingerprints).count < maxGroupMembers else {
                continue
            }
            insertGroupInvitation(invitation)
        }
    }

    private func normalizedMemberProfile(_ profile: RelayGroupMemberProfile?) -> RelayGroupMemberProfile? {
        guard let profile else { return nil }
        let fingerprint = profile.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !fingerprint.isEmpty else { return nil }
        let trimmedDisplayName: String?
        if let displayName = profile.displayName?.trimmingCharacters(in: .whitespacesAndNewlines),
           !displayName.isEmpty {
            trimmedDisplayName = displayName
        } else {
            trimmedDisplayName = nil
        }
        let trimmedInboxId: String?
        if let inboxId = profile.inboxId?.trimmingCharacters(in: .whitespacesAndNewlines),
           !inboxId.isEmpty {
            trimmedInboxId = inboxId
        } else {
            trimmedInboxId = nil
        }
        return RelayGroupMemberProfile(
            fingerprint: fingerprint,
            displayName: trimmedDisplayName,
            inboxId: trimmedInboxId,
            relay: profile.relay,
            signingPublicKey: profile.signingPublicKey,
            agreementPublicKey: profile.agreementPublicKey
        )
    }

    private func makeGroupMember(
        fingerprint: String,
        existing: RelayGroupMember?,
        profile: RelayGroupMemberProfile?,
        joinedAt: Date
    ) -> RelayGroupMember {
        RelayGroupMember(
            fingerprint: fingerprint,
            joinedAt: existing?.joinedAt ?? joinedAt,
            displayName: profile?.displayName ?? existing?.displayName,
            inboxId: profile?.inboxId ?? existing?.inboxId,
            relay: profile?.relay ?? existing?.relay,
            signingPublicKey: profile?.signingPublicKey ?? existing?.signingPublicKey,
            agreementPublicKey: profile?.agreementPublicKey ?? existing?.agreementPublicKey
        )
    }

    private func projectedGroupMemberProfiles(
        currentMembers: [RelayGroupMember],
        addProfiles: [RelayGroupMemberProfile]
    ) -> [RelayGroupMemberProfile] {
        var profiles = Dictionary(uniqueKeysWithValues: currentMembers.map { member in
            (
                member.fingerprint,
                RelayGroupMemberProfile(
                    fingerprint: member.fingerprint,
                    displayName: member.displayName,
                    inboxId: member.inboxId,
                    relay: member.relay,
                    signingPublicKey: member.signingPublicKey,
                    agreementPublicKey: member.agreementPublicKey
                )
            )
        })
        for profile in addProfiles {
            let fingerprint = profile.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !fingerprint.isEmpty else { continue }
            profiles[fingerprint] = RelayGroupMemberProfile(
                fingerprint: fingerprint,
                displayName: profile.displayName,
                inboxId: profile.inboxId,
                relay: profile.relay,
                signingPublicKey: profile.signingPublicKey,
                agreementPublicKey: profile.agreementPublicKey
            )
        }
        return profiles.values.sorted { $0.fingerprint < $1.fingerprint }
    }

    private func pruneAnnouncements(now: Date) {
        announcements = announcements.filter { $0.value.expiresAt > now }
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

    private func prunePrekeys(now: Date) {
        prekeyBundles = prekeyBundles.filter { $0.value.expiresAt > now }
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
        normalizeMailboxStreamsAfterLoad()
        attachments = snapshot.attachments
        prekeyBundles = snapshot.prekeyBundles
        federationNodes = snapshot.federationNodes
        coordinatorPinnedPublicKeys = snapshot.coordinatorPinnedPublicKeys
        groups = snapshot.groups
        groupJoinRequests = snapshot.groupJoinRequests
        groupInvitations = snapshot.groupInvitations
        actorProofReplayCache = snapshot.actorProofReplayCache.filter {
            $0.value > Date().addingTimeInterval(-RelayActorProof.maximumAgeSeconds)
        }
        normalizeGroupInvitationsAfterLoad()
        pruneAttachments(now: Date())
        prunePrekeys(now: Date())
        pruneFederationNodes(now: Date())
        enforceLoadedInboxRetirements()
        normalizeInboxRouteCapabilitiesAfterLoad()
    }

    private func restoreSnapshot(_ snapshot: RelayStoreSnapshot) {
        mailboxes = snapshot.mailboxes
        inboxRegistrations = snapshot.inboxRegistrations
        inboxRetirements = snapshot.inboxRetirements
        inboxRouteCapabilities = snapshot.inboxRouteCapabilities
        attachments = snapshot.attachments
        prekeyBundles = snapshot.prekeyBundles
        federationNodes = snapshot.federationNodes
        coordinatorPinnedPublicKeys = snapshot.coordinatorPinnedPublicKeys
        groups = snapshot.groups
        groupJoinRequests = snapshot.groupJoinRequests
        groupInvitations = snapshot.groupInvitations
        actorProofReplayCache = snapshot.actorProofReplayCache
        normalizeGroupInvitationsAfterLoad()
    }

    private func currentSnapshot() -> RelayStoreSnapshot {
        RelayStoreSnapshot(
            mailboxes: mailboxes,
            inboxRegistrations: inboxRegistrations,
            inboxRetirements: inboxRetirements,
            inboxRouteCapabilities: inboxRouteCapabilities,
            attachments: attachments,
            prekeyBundles: prekeyBundles,
            federationNodes: federationNodes,
            coordinatorPinnedPublicKeys: coordinatorPinnedPublicKeys,
            groups: groups,
            groupJoinRequests: groupJoinRequests,
            groupInvitations: groupInvitations,
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

    private func normalizeMailboxStreamsAfterLoad() {
        for inboxId in Array(mailboxes.keys) {
            var previous: UInt64 = 0
            var records = mailboxes[inboxId, default: []]
            for index in records.indices {
                if records[index].sequence <= previous {
                    guard previous < UInt64.max else { break }
                    records[index].sequence = previous + 1
                }
                previous = records[index].sequence
            }
            mailboxes[inboxId] = records
            if var registration = inboxRegistrations[inboxId] {
                registration.streamState.highWatermark = max(
                    registration.streamState.highWatermark,
                    previous
                )
                registration.streamState.retentionFloor = min(
                    registration.streamState.retentionFloor,
                    registration.streamState.highWatermark
                )
                inboxRegistrations[inboxId] = registration
            }
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

}

private struct RelayStoreSnapshot: Codable {
    let mailboxes: [String: [StoredEnvelope]]
    let inboxRegistrations: [String: InboxRegistrationRecord]
    let inboxRetirements: [String: InboxRetirementRecord]
    let inboxRouteCapabilities: [String: InboxRouteCapabilityRecord]
    let attachments: [String: [AttachmentRecord]]
    let prekeyBundles: [String: PrekeyBundleRecord]
    let federationNodes: [String: FederationNodeRecord]
    let coordinatorPinnedPublicKeys: [String: Data]
    let groups: [UUID: RelayGroupDescriptor]
    let groupJoinRequests: [UUID: [RelayGroupJoinRequest]]
    let groupInvitations: [String: [RelayGroupInvitation]]
    let actorProofReplayCache: [String: Date]

    static let empty = RelayStoreSnapshot(
        mailboxes: [:],
        inboxRegistrations: [:],
        inboxRetirements: [:],
        inboxRouteCapabilities: [:],
        attachments: [:],
        prekeyBundles: [:],
        federationNodes: [:],
        coordinatorPinnedPublicKeys: [:],
        groups: [:],
        groupJoinRequests: [:],
        groupInvitations: [:],
        actorProofReplayCache: [:]
    )

    init(
        mailboxes: [String: [StoredEnvelope]],
        inboxRegistrations: [String: InboxRegistrationRecord] = [:],
        inboxRetirements: [String: InboxRetirementRecord] = [:],
        inboxRouteCapabilities: [String: InboxRouteCapabilityRecord] = [:],
        attachments: [String: [AttachmentRecord]],
        prekeyBundles: [String: PrekeyBundleRecord] = [:],
        federationNodes: [String: FederationNodeRecord] = [:],
        coordinatorPinnedPublicKeys: [String: Data] = [:],
        groups: [UUID: RelayGroupDescriptor] = [:],
        groupJoinRequests: [UUID: [RelayGroupJoinRequest]] = [:],
        groupInvitations: [String: [RelayGroupInvitation]] = [:],
        actorProofReplayCache: [String: Date] = [:]
    ) {
        self.mailboxes = mailboxes
        self.inboxRegistrations = inboxRegistrations
        self.inboxRetirements = inboxRetirements
        self.inboxRouteCapabilities = inboxRouteCapabilities
        self.attachments = attachments
        self.prekeyBundles = prekeyBundles
        self.federationNodes = federationNodes
        self.coordinatorPinnedPublicKeys = coordinatorPinnedPublicKeys
        self.groups = groups
        self.groupJoinRequests = groupJoinRequests
        self.groupInvitations = groupInvitations
        self.actorProofReplayCache = actorProofReplayCache
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mailboxes = try container.decodeIfPresent([String: [StoredEnvelope]].self, forKey: .mailboxes) ?? [:]
        inboxRegistrations = try container.decodeIfPresent([String: InboxRegistrationRecord].self, forKey: .inboxRegistrations) ?? [:]
        inboxRetirements = try container.decodeIfPresent(
            [String: InboxRetirementRecord].self,
            forKey: .inboxRetirements
        ) ?? [:]
        inboxRouteCapabilities = try container.decodeIfPresent(
            [String: InboxRouteCapabilityRecord].self,
            forKey: .inboxRouteCapabilities
        ) ?? [:]
        attachments = try container.decodeIfPresent([String: [AttachmentRecord]].self, forKey: .attachments) ?? [:]
        prekeyBundles = try container.decodeIfPresent([String: PrekeyBundleRecord].self, forKey: .prekeyBundles) ?? [:]
        federationNodes = try container.decodeIfPresent([String: FederationNodeRecord].self, forKey: .federationNodes) ?? [:]
        coordinatorPinnedPublicKeys = try container.decodeIfPresent([String: Data].self, forKey: .coordinatorPinnedPublicKeys) ?? [:]
        groups = try container.decodeIfPresent([UUID: RelayGroupDescriptor].self, forKey: .groups) ?? [:]
        groupJoinRequests = try container.decodeIfPresent([UUID: [RelayGroupJoinRequest]].self, forKey: .groupJoinRequests) ?? [:]
        groupInvitations = try container.decodeIfPresent(
            [String: [RelayGroupInvitation]].self,
            forKey: .groupInvitations
        ) ?? [:]
        actorProofReplayCache = try container.decodeIfPresent(
            [String: Date].self,
            forKey: .actorProofReplayCache
        ) ?? [:]
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
        streamState = try container.decodeIfPresent(MailboxStreamState.self, forKey: .streamState)
            ?? MailboxStreamState()
        lastRouteMutationSequence = try container.decodeIfPresent(
            UInt64.self,
            forKey: .lastRouteMutationSequence
        ) ?? 0
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
        let hasEncodedScope = container.contains(.routeMutationScope)
        let decodedScope = try container.decodeIfPresent(Data.self, forKey: .routeMutationScope)
        if hasEncodedScope {
            guard let decodedScope else {
                throw DecodingError.dataCorruptedError(
                    forKey: .routeMutationScope,
                    in: container,
                    debugDescription: "Null relay-local route mutation scope"
                )
            }
            guard decodedScope.isValidRouteMutationScope else {
                throw DecodingError.dataCorruptedError(
                    forKey: .routeMutationScope,
                    in: container,
                    debugDescription: "Invalid relay-local route mutation scope"
                )
            }
            routeMutationScope = decodedScope
        } else {
            guard lastRouteMutationSequence == 0, decodedDigest == nil else {
                throw DecodingError.dataCorruptedError(
                    forKey: .routeMutationScope,
                    in: container,
                    debugDescription: "Missing route mutation scope for v3 cursor state"
                )
            }
            // A pre-v3 registration with no cursor state receives a fresh,
            // relay-local scope exactly once during migration.
            routeMutationScope = Self.generateRouteMutationScope()
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
    private static let maximumGroupRecipientCount = 256
    private static let maximumRecipientFingerprintBytes = 128

    var sequence: UInt64
    let envelope: Envelope
    let storedAt: Date
    var pendingGroupRecipientFingerprints: Set<String>?
    let originalGroupRecipientFingerprints: Set<String>?

    init(
        sequence: UInt64 = 0,
        envelope: Envelope,
        storedAt: Date,
        pendingGroupRecipientFingerprints: Set<String>? = nil,
        originalGroupRecipientFingerprints: Set<String>? = nil
    ) {
        self.sequence = sequence
        self.envelope = envelope
        self.storedAt = storedAt
        self.pendingGroupRecipientFingerprints = pendingGroupRecipientFingerprints
        self.originalGroupRecipientFingerprints = pendingGroupRecipientFingerprints.map {
            originalGroupRecipientFingerprints ?? $0
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sequence = try container.decodeIfPresent(UInt64.self, forKey: .sequence) ?? 0
        envelope = try container.decode(Envelope.self, forKey: .envelope)
        storedAt = try container.decode(Date.self, forKey: .storedAt)
        pendingGroupRecipientFingerprints = try container.decodeIfPresent(
            Set<String>.self,
            forKey: .pendingGroupRecipientFingerprints
        )
        // Pre-architecture-v2 records only persisted the mutable pending set.
        // Its current value is the only safe fail-closed migration baseline.
        originalGroupRecipientFingerprints = try container.decodeIfPresent(
            Set<String>.self,
            forKey: .originalGroupRecipientFingerprints
        ) ?? pendingGroupRecipientFingerprints
        guard Self.isValidPersistedRecipientState(
            pending: pendingGroupRecipientFingerprints,
            original: originalGroupRecipientFingerprints
        ) else {
            throw DecodingError.dataCorruptedError(
                forKey: .pendingGroupRecipientFingerprints,
                in: container,
                debugDescription: "Invalid persisted group recipient state"
            )
        }
    }

    static func normalizedGroupRecipients(_ values: [String]) -> Set<String>? {
        guard values.count <= maximumGroupRecipientCount else { return nil }
        let recipients = Set(values.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty })
        return isValidRecipientSet(recipients) ? recipients : nil
    }

    private static func isValidPersistedRecipientState(
        pending: Set<String>?,
        original: Set<String>?
    ) -> Bool {
        switch (pending, original) {
        case (nil, nil):
            return true
        case let (.some(pending), .some(original)):
            return isValidRecipientSet(pending)
                && isValidRecipientSet(original)
                && pending.isSubset(of: original)
        default:
            return false
        }
    }

    private static func isValidRecipientSet(_ recipients: Set<String>) -> Bool {
        recipients.count <= maximumGroupRecipientCount
            && recipients.allSatisfy {
                !$0.isEmpty && $0.utf8.count <= maximumRecipientFingerprintBytes
            }
    }
}

struct MailboxStreamState: Codable {
    var highWatermark: UInt64
    var retentionFloor: UInt64
    var consumers: [String: MailboxConsumerRecord]
    var isInstallationManaged: Bool

    init(
        highWatermark: UInt64 = 0,
        retentionFloor: UInt64 = 0,
        consumers: [String: MailboxConsumerRecord] = [:],
        isInstallationManaged: Bool = false
    ) {
        self.highWatermark = highWatermark
        self.retentionFloor = min(retentionFloor, highWatermark)
        self.consumers = consumers
        self.isInstallationManaged = isInstallationManaged || !consumers.isEmpty
    }

    private enum CodingKeys: String, CodingKey {
        case highWatermark
        case retentionFloor
        case consumers
        case isInstallationManaged
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        highWatermark = try container.decodeIfPresent(UInt64.self, forKey: .highWatermark) ?? 0
        retentionFloor = min(
            try container.decodeIfPresent(UInt64.self, forKey: .retentionFloor) ?? 0,
            highWatermark
        )
        consumers = try container.decodeIfPresent(
            [String: MailboxConsumerRecord].self,
            forKey: .consumers
        ) ?? [:]
        isInstallationManaged = (try container.decodeIfPresent(
            Bool.self,
            forKey: .isInstallationManaged
        ) ?? false) || !consumers.isEmpty
    }
}

struct MailboxConsumerRecord: Codable {
    var state: MailboxConsumerState
    var committedSequence: UInt64
    let cursorKey: Data
    var consumerSigningPublicKey: Data?
    let registeredAt: Date
    var revokedAt: Date?

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

private struct PrekeyBundleRecord: Codable {
    var bundle: PrekeyBundle
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
    private static let normalizedSchemaKey = "normalized_schema_v1"
    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    static func loadState(at url: URL) throws -> RelayStoreSnapshot? {
        var db: OpaquePointer?
        try openDatabase(at: url, handle: &db)
        defer { sqlite3_close(db) }
        guard let db else { return nil }

        try ensureSchema(in: db)
        guard try hasNormalizedState(in: db) else {
            return nil
        }
        return RelayStoreSnapshot(
            mailboxes: try loadMailboxes(in: db),
            inboxRegistrations: try loadInboxRegistrations(in: db),
            inboxRetirements: try loadInboxRetirements(in: db),
            inboxRouteCapabilities: try loadInboxRouteCapabilities(in: db),
            attachments: try loadAttachments(in: db),
            prekeyBundles: try loadPrekeyBundles(in: db),
            federationNodes: try loadFederationNodes(in: db),
            coordinatorPinnedPublicKeys: try loadCoordinatorPinnedPublicKeys(in: db),
            groups: try loadGroups(in: db),
            groupJoinRequests: try loadGroupJoinRequests(in: db),
            groupInvitations: try loadGroupInvitations(in: db),
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
            for (attachmentId, records) in snapshot.attachments {
                for record in records {
                    try insertAttachmentRecord(attachmentId: attachmentId, record: record, in: db)
                }
            }
            for (fingerprint, record) in snapshot.prekeyBundles {
                try insertPrekeyBundle(fingerprint: fingerprint, record: record, in: db)
            }
            for (nodeKey, record) in snapshot.federationNodes {
                try insertFederationNode(nodeKey: nodeKey, record: record, in: db)
            }
            for (coordinatorKey, publicKey) in snapshot.coordinatorPinnedPublicKeys {
                try insertCoordinatorPinnedPublicKey(coordinatorKey: coordinatorKey, publicKey: publicKey, in: db)
            }
            for (groupId, group) in snapshot.groups {
                try insertGroup(groupId: groupId, group: group, in: db)
            }
            for (groupId, requests) in snapshot.groupJoinRequests {
                for (position, request) in requests.enumerated() {
                    try insertGroupJoinRequest(groupId: groupId, position: position, request: request, in: db)
                }
            }
            for (fingerprint, invitations) in snapshot.groupInvitations {
                for (position, invitation) in invitations.enumerated() {
                    try insertGroupInvitation(
                        invitedFingerprint: fingerprint,
                        position: position,
                        invitation: invitation,
                        in: db
                    )
                }
            }
            for (cacheKey, consumedAt) in snapshot.actorProofReplayCache {
                try insertActorProofReplayCacheEntry(
                    cacheKey: cacheKey,
                    consumedAt: consumedAt,
                    in: db
                )
            }
            try insertMeta(key: normalizedSchemaKey, value: Data("1".utf8), in: db)
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

    private static func loadAttachments(in db: OpaquePointer) throws -> [String: [AttachmentRecord]] {
        var attachments: [String: [AttachmentRecord]] = [:]
        try queryRows("SELECT attachment_id, value FROM relay_attachment_chunks ORDER BY attachment_id, chunk_index;", in: db) { statement in
            let attachmentId = try readText(statement, column: 0, in: db)
            let record = try decode(AttachmentRecord.self, from: readBlob(statement, column: 1))
            attachments[attachmentId, default: []].append(record)
        }
        return attachments
    }

    private static func loadPrekeyBundles(in db: OpaquePointer) throws -> [String: PrekeyBundleRecord] {
        var bundles: [String: PrekeyBundleRecord] = [:]
        try queryRows("SELECT fingerprint, value FROM relay_prekey_bundles;", in: db) { statement in
            let fingerprint = try readText(statement, column: 0, in: db)
            bundles[fingerprint] = try decode(PrekeyBundleRecord.self, from: readBlob(statement, column: 1))
        }
        return bundles
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

    private static func loadGroups(in db: OpaquePointer) throws -> [UUID: RelayGroupDescriptor] {
        var groups: [UUID: RelayGroupDescriptor] = [:]
        try queryRows("SELECT group_id, value FROM relay_groups;", in: db) { statement in
            guard let groupId = try UUID(uuidString: readText(statement, column: 0, in: db)) else {
                throw SQLiteRelayStateStoreError.corrupt("invalid group identifier")
            }
            let group = try decode(RelayGroupDescriptor.self, from: readBlob(statement, column: 1))
            groups[groupId] = group
        }
        return groups
    }

    private static func loadGroupJoinRequests(in db: OpaquePointer) throws -> [UUID: [RelayGroupJoinRequest]] {
        var requests: [UUID: [RelayGroupJoinRequest]] = [:]
        try queryRows("SELECT group_id, value FROM relay_group_join_requests ORDER BY group_id, position;", in: db) { statement in
            guard let groupId = try UUID(uuidString: readText(statement, column: 0, in: db)) else {
                throw SQLiteRelayStateStoreError.corrupt("invalid group join-request identifier")
            }
            let request = try decode(RelayGroupJoinRequest.self, from: readBlob(statement, column: 1))
            requests[groupId, default: []].append(request)
        }
        return requests
    }

    private static func loadGroupInvitations(in db: OpaquePointer) throws -> [String: [RelayGroupInvitation]] {
        var invitations: [String: [RelayGroupInvitation]] = [:]
        try queryRows(
            "SELECT invited_fingerprint, value FROM relay_group_invitations ORDER BY invited_fingerprint, position;",
            in: db
        ) { statement in
            let fingerprint = try readText(statement, column: 0, in: db)
            let invitation = try decode(RelayGroupInvitation.self, from: readBlob(statement, column: 1))
            invitations[fingerprint, default: []].append(invitation)
        }
        return invitations
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
            "INSERT INTO relay_inbox_retirements (inbox_id, retired_at, expires_at, request_digest, value) VALUES (?1, ?2, ?3, ?4, ?5);",
            in: db
        ) { statement in
            try bindText(inboxId, to: 1, in: statement, db: db)
            try bindDouble(record.retiredAt.timeIntervalSince1970, to: 2, in: statement, db: db)
            // `expires_at` is retained only for pre-1.0 SQLite schema
            // compatibility. Retirement records never expire.
            try bindDouble(Date.distantFuture.timeIntervalSince1970, to: 3, in: statement, db: db)
            try bindBlob(record.requestDigest, to: 4, in: statement, db: db)
            try bindBlob(encode(record), to: 5, in: statement, db: db)
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

    private static func insertPrekeyBundle(fingerprint: String, record: PrekeyBundleRecord, in db: OpaquePointer) throws {
        try executePrepared(
            "INSERT INTO relay_prekey_bundles (fingerprint, expires_at, value) VALUES (?1, ?2, ?3);",
            in: db
        ) { statement in
            try bindText(fingerprint, to: 1, in: statement, db: db)
            try bindDouble(record.expiresAt.timeIntervalSince1970, to: 2, in: statement, db: db)
            try bindBlob(encode(record), to: 3, in: statement, db: db)
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

    private static func insertGroup(groupId: UUID, group: RelayGroupDescriptor, in db: OpaquePointer) throws {
        try executePrepared(
            "INSERT INTO relay_groups (group_id, value) VALUES (?1, ?2);",
            in: db
        ) { statement in
            try bindText(groupId.uuidString, to: 1, in: statement, db: db)
            try bindBlob(encode(group), to: 2, in: statement, db: db)
        }
    }

    private static func insertGroupJoinRequest(groupId: UUID, position: Int, request: RelayGroupJoinRequest, in db: OpaquePointer) throws {
        try executePrepared(
            "INSERT INTO relay_group_join_requests (group_id, position, request_id, value) VALUES (?1, ?2, ?3, ?4);",
            in: db
        ) { statement in
            try bindText(groupId.uuidString, to: 1, in: statement, db: db)
            try bindInt(position, to: 2, in: statement, db: db)
            try bindText(request.id.uuidString, to: 3, in: statement, db: db)
            try bindBlob(encode(request), to: 4, in: statement, db: db)
        }
    }

    private static func insertGroupInvitation(
        invitedFingerprint: String,
        position: Int,
        invitation: RelayGroupInvitation,
        in db: OpaquePointer
    ) throws {
        try executePrepared(
            "INSERT INTO relay_group_invitations (invited_fingerprint, position, invitation_id, group_id, value) VALUES (?1, ?2, ?3, ?4, ?5);",
            in: db
        ) { statement in
            try bindText(invitedFingerprint, to: 1, in: statement, db: db)
            try bindInt(position, to: 2, in: statement, db: db)
            try bindText(invitation.id.uuidString, to: 3, in: statement, db: db)
            try bindText(invitation.groupId.uuidString, to: 4, in: statement, db: db)
            try bindBlob(encode(invitation), to: 5, in: statement, db: db)
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

    private static func hasNormalizedState(in db: OpaquePointer) throws -> Bool {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT 1 FROM \(metaTableName) WHERE key = ?1 LIMIT 1;", -1, &statement, nil) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.prepare(lastError(in: db))
        }
        defer { sqlite3_finalize(statement) }
        guard let statement else { return false }

        try bindText(normalizedSchemaKey, to: 1, in: statement, db: db)
        let step = sqlite3_step(statement)
        if step == SQLITE_ROW {
            return true
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
            "relay_attachment_chunks",
            "relay_prekey_bundles",
            "relay_federation_nodes",
            "relay_coordinator_pinned_keys",
            "relay_groups",
            "relay_group_join_requests",
            "relay_group_invitations",
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
            expires_at REAL NOT NULL,
            request_digest BLOB NOT NULL,
            value BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS relay_inbox_retirements_expiry_idx ON relay_inbox_retirements(expires_at);
        CREATE TABLE IF NOT EXISTS relay_inbox_route_capabilities (
            capability_digest TEXT PRIMARY KEY,
            inbox_id TEXT NOT NULL,
            created_at REAL NOT NULL,
            revoked_at REAL,
            value BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS relay_inbox_route_capabilities_inbox_idx ON relay_inbox_route_capabilities(inbox_id);
        CREATE TABLE IF NOT EXISTS relay_attachment_chunks (
            attachment_id TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            stored_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            value BLOB NOT NULL,
            PRIMARY KEY (attachment_id, chunk_index)
        );
        CREATE INDEX IF NOT EXISTS relay_attachment_chunks_expiry_idx ON relay_attachment_chunks(expires_at);
        CREATE TABLE IF NOT EXISTS relay_prekey_bundles (
            fingerprint TEXT PRIMARY KEY,
            expires_at REAL NOT NULL,
            value BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS relay_federation_nodes (
            node_key TEXT PRIMARY KEY,
            expires_at REAL NOT NULL,
            value BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS relay_coordinator_pinned_keys (
            coordinator_key TEXT PRIMARY KEY,
            public_key BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS relay_groups (
            group_id TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS relay_group_join_requests (
            group_id TEXT NOT NULL,
            position INTEGER NOT NULL,
            request_id TEXT NOT NULL,
            value BLOB NOT NULL,
            PRIMARY KEY (group_id, position)
        );
        CREATE INDEX IF NOT EXISTS relay_group_join_requests_group_idx ON relay_group_join_requests(group_id);
        CREATE TABLE IF NOT EXISTS relay_group_invitations (
            invited_fingerprint TEXT NOT NULL,
            position INTEGER NOT NULL,
            invitation_id TEXT NOT NULL,
            group_id TEXT NOT NULL,
            value BLOB NOT NULL,
            PRIMARY KEY (invited_fingerprint, position)
        );
        CREATE INDEX IF NOT EXISTS relay_group_invitations_invited_idx ON relay_group_invitations(invited_fingerprint);
        CREATE INDEX IF NOT EXISTS relay_group_invitations_group_idx ON relay_group_invitations(group_id);
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
    case destinationInboxNotRegistered
    case relayCapacityExceeded
    case invalidEnvelopePayload
    case invalidChunkIndex
    case invalidAttachmentPayload
    case invalidPrekeyBundle
    case groupCapacityExceeded
    case invalidGroupTitle
    case invalidFingerprint
    case invalidGroupCommit
    case notEnoughGroupMembers
    case groupNotFound
    case unauthorizedGroupMutation
    case groupJoinRequestNotFound
    case alreadyGroupMember
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
}

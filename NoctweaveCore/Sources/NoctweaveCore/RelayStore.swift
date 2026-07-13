import Foundation
import SQLite3

public actor RelayStore {
    private var mailboxes: [String: [StoredEnvelope]] = [:]
    private var inboxRegistrations: [String: InboxRegistrationRecord] = [:]
    private var announcements: [String: PairingAnnouncement] = [:]
    private var pairRequests: [String: [PairingRequest]] = [:]
    private var attachments: [String: [AttachmentRecord]] = [:]
    private var prekeyBundles: [String: PrekeyBundleRecord] = [:]
    private var federationNodes: [String: FederationNodeRecord] = [:]
    private var coordinatorPinnedPublicKeys: [String: Data] = [:]
    private var groups: [UUID: RelayGroupDescriptor] = [:]
    private var groupJoinRequests: [UUID: [RelayGroupJoinRequest]] = [:]
    private var groupInvitations: [String: [RelayGroupInvitation]] = [:]
    private var openFederationDHTCache = OpenFederationDHTCandidateCache(
        configuration: OpenFederationDHTDiscoveryConfiguration(isEnabled: false)
    )
    private var actorProofReplayCache: [String: Date] = [:]
    private var federationRegistrationAttemptsBySource: [String: [Date]] = [:]
    private var federationListAttemptsBySource: [String: [Date]] = [:]
    private var lastFederationRegistrationByEndpoint: [String: Date] = [:]
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
    private let maxActorProofReplayEntries = 20_000

    public init(
        storeURL: URL? = nil,
        temporalBucketSeconds: Int = 300,
        temporalBucketScheduleSeconds: [Int]? = nil,
        attachmentBlobStore: AttachmentBlobStore? = nil,
        maxInboxMessages: Int = 1_000
    ) {
        self.storeURL = storeURL
        self.attachmentBlobStore = attachmentBlobStore
        self.maxInboxMessages = max(1, maxInboxMessages)
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
        }
    }

    public func saveToDisk() throws {
        guard let storeURL else {
            return
        }
        pruneAttachments(now: Date())
        prunePrekeys(now: Date())
        pruneFederationNodes(now: Date())
        try SQLiteRelayStateStore.saveState(currentSnapshot(), at: sqliteStoreURL(for: storeURL))
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
        if actorProofReplayCache.count >= maxActorProofReplayEntries,
           let oldest = actorProofReplayCache.min(by: { $0.value < $1.value })?.key {
            actorProofReplayCache.removeValue(forKey: oldest)
        }
        actorProofReplayCache[key] = now
        return true
    }

    @discardableResult
    public func deliver(_ envelope: Envelope, to inboxId: String) throws -> Int {
        guard envelopePayloadBytes(envelope) <= maxEnvelopePayloadBytes else {
            throw RelayStoreError.invalidEnvelopePayload
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
        let discriminator = "\(inboxId):\(envelope.id.uuidString)"
        inbox.append(StoredEnvelope(envelope: envelope, storedAt: bucketed(Date(), discriminator: discriminator)))
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
        guard envelopePayloadBytes(envelope) <= maxEnvelopePayloadBytes else {
            throw RelayStoreError.invalidEnvelopePayload
        }
        let recipients = Set(recipientFingerprints.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty })
        guard !recipients.isEmpty else {
            return mailboxes[inboxId, default: []].count
        }
        if mailboxes[inboxId] == nil, mailboxes.count >= maxMailboxes {
            throw RelayStoreError.relayCapacityExceeded
        }
        let totalMessages = mailboxes.values.reduce(into: 0) { $0 += $1.count }
        guard totalMessages < maxStoredMessages else {
            throw RelayStoreError.relayCapacityExceeded
        }
        var inbox = mailboxes[inboxId, default: []]
        guard inbox.count < maxInboxMessages else {
            throw RelayStoreError.inboxFull
        }
        let discriminator = "\(inboxId):\(envelope.id.uuidString)"
        inbox.append(
            StoredEnvelope(
                envelope: envelope,
                storedAt: bucketed(Date(), discriminator: discriminator),
                pendingGroupRecipientFingerprints: recipients
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

    public func registerInbox(inboxId: String, accessPublicKey: Data) throws {
        guard InboxAddress.isValid(inboxId), !accessPublicKey.isEmpty else {
            throw RelayStoreError.invalidInboxRegistration
        }
        if let existing = inboxRegistrations[inboxId] {
            guard existing.accessPublicKey == accessPublicKey else {
                throw RelayStoreError.inboxAlreadyRegistered
            }
            return
        }
        guard inboxRegistrations.count < maxInboxRegistrations else {
            throw RelayStoreError.relayCapacityExceeded
        }
        inboxRegistrations[inboxId] = InboxRegistrationRecord(
            accessPublicKey: accessPublicKey,
            registeredAt: Date()
        )
        try saveToDisk()
    }

    public func inboxAccessPublicKey(for inboxId: String) -> Data? {
        inboxRegistrations[inboxId]?.accessPublicKey
    }

    @discardableResult
    public func acknowledge(inboxId: String, messageIds: [UUID]) throws -> Int {
        let ids = Set(messageIds.prefix(1_000))
        guard !ids.isEmpty else {
            return 0
        }
        let inbox = mailboxes[inboxId, default: []]
        let remaining = inbox.filter { !ids.contains($0.envelope.id) }
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
        if attachments[key] == nil, attachments.count >= maxAttachmentIds {
            if let oldestKey = attachments.min(by: { lhs, rhs in
                let lhsDate = lhs.value.map(\.storedAt).min() ?? .distantFuture
                let rhsDate = rhs.value.map(\.storedAt).min() ?? .distantFuture
                return lhsDate < rhsDate
            })?.key {
                attachments.removeValue(forKey: oldestKey)
            }
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
        if let existing = records.first(where: { $0.chunkIndex == chunkIndex }),
           let external = existing.external {
            attachmentBlobStore?.delete(external)
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
                    attachmentBlobStore?.delete(external)
                }
            }
            records = Array(records.suffix(maxAttachmentChunks))
        }
        attachments[key] = records
        try saveToDisk()
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
        guard normalizedMembers.count <= maxGroupMembers else {
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
            var invitations = groupInvitations[fingerprint, default: []]
            invitations.removeAll { $0.groupId == group.id }
            invitations.insert(
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
                ),
                at: 0
            )
            groupInvitations[fingerprint] = Array(invitations.prefix(maxGroupInvitationsPerIdentity))
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
        let invitees = request.normalizedInvitedFingerprints.filter { fingerprint in
            fingerprint != group.createdByFingerprint && !currentMembers.contains(fingerprint)
        }
        guard !invitees.isEmpty else {
            return group
        }
        guard currentMembers.count + invitees.count <= maxGroupMembers else {
            throw RelayStoreError.groupCapacityExceeded
        }

        let now = Date()
        group.updatedAt = now
        groups[group.id] = group
        for fingerprint in invitees {
            var invitations = groupInvitations[fingerprint, default: []]
            invitations.removeAll { $0.groupId == group.id }
            invitations.insert(
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
                ),
                at: 0
            )
            groupInvitations[fingerprint] = Array(invitations.prefix(maxGroupInvitationsPerIdentity))
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
        guard memberMap.count <= maxGroupMembers else {
            throw RelayStoreError.groupCapacityExceeded
        }

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
        guard memberMap.count <= maxGroupMembers else {
            throw RelayStoreError.groupCapacityExceeded
        }

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
    }

    private func removeGroupInvitations(groupId: UUID) {
        for fingerprint in Array(groupInvitations.keys) {
            removeGroupInvitation(groupId: groupId, invitedFingerprint: fingerprint)
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
        attachments = snapshot.attachments
        prekeyBundles = snapshot.prekeyBundles
        federationNodes = snapshot.federationNodes
        coordinatorPinnedPublicKeys = snapshot.coordinatorPinnedPublicKeys
        groups = snapshot.groups
        groupJoinRequests = snapshot.groupJoinRequests
        groupInvitations = snapshot.groupInvitations
        pruneAttachments(now: Date())
        prunePrekeys(now: Date())
        pruneFederationNodes(now: Date())
    }

    private func currentSnapshot() -> RelayStoreSnapshot {
        RelayStoreSnapshot(
            mailboxes: mailboxes,
            inboxRegistrations: inboxRegistrations,
            attachments: attachments,
            prekeyBundles: prekeyBundles,
            federationNodes: federationNodes,
            coordinatorPinnedPublicKeys: coordinatorPinnedPublicKeys,
            groups: groups,
            groupJoinRequests: groupJoinRequests,
            groupInvitations: groupInvitations
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

}

private struct RelayStoreSnapshot: Codable {
    let mailboxes: [String: [StoredEnvelope]]
    let inboxRegistrations: [String: InboxRegistrationRecord]
    let attachments: [String: [AttachmentRecord]]
    let prekeyBundles: [String: PrekeyBundleRecord]
    let federationNodes: [String: FederationNodeRecord]
    let coordinatorPinnedPublicKeys: [String: Data]
    let groups: [UUID: RelayGroupDescriptor]
    let groupJoinRequests: [UUID: [RelayGroupJoinRequest]]
    let groupInvitations: [String: [RelayGroupInvitation]]

    init(
        mailboxes: [String: [StoredEnvelope]],
        inboxRegistrations: [String: InboxRegistrationRecord] = [:],
        attachments: [String: [AttachmentRecord]],
        prekeyBundles: [String: PrekeyBundleRecord] = [:],
        federationNodes: [String: FederationNodeRecord] = [:],
        coordinatorPinnedPublicKeys: [String: Data] = [:],
        groups: [UUID: RelayGroupDescriptor] = [:],
        groupJoinRequests: [UUID: [RelayGroupJoinRequest]] = [:],
        groupInvitations: [String: [RelayGroupInvitation]] = [:]
    ) {
        self.mailboxes = mailboxes
        self.inboxRegistrations = inboxRegistrations
        self.attachments = attachments
        self.prekeyBundles = prekeyBundles
        self.federationNodes = federationNodes
        self.coordinatorPinnedPublicKeys = coordinatorPinnedPublicKeys
        self.groups = groups
        self.groupJoinRequests = groupJoinRequests
        self.groupInvitations = groupInvitations
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mailboxes = try container.decodeIfPresent([String: [StoredEnvelope]].self, forKey: .mailboxes) ?? [:]
        inboxRegistrations = try container.decodeIfPresent([String: InboxRegistrationRecord].self, forKey: .inboxRegistrations) ?? [:]
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
    }
}

private struct InboxRegistrationRecord: Codable {
    let accessPublicKey: Data
    let registeredAt: Date
}

private struct StoredEnvelope: Codable {
    let envelope: Envelope
    let storedAt: Date
    var pendingGroupRecipientFingerprints: Set<String>?

    init(
        envelope: Envelope,
        storedAt: Date,
        pendingGroupRecipientFingerprints: Set<String>? = nil
    ) {
        self.envelope = envelope
        self.storedAt = storedAt
        self.pendingGroupRecipientFingerprints = pendingGroupRecipientFingerprints
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        envelope = try container.decode(Envelope.self, forKey: .envelope)
        storedAt = try container.decode(Date.self, forKey: .storedAt)
        pendingGroupRecipientFingerprints = try container.decodeIfPresent(
            Set<String>.self,
            forKey: .pendingGroupRecipientFingerprints
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
            attachments: try loadAttachments(in: db),
            prekeyBundles: try loadPrekeyBundles(in: db),
            federationNodes: try loadFederationNodes(in: db),
            coordinatorPinnedPublicKeys: try loadCoordinatorPinnedPublicKeys(in: db),
            groups: try loadGroups(in: db),
            groupJoinRequests: try loadGroupJoinRequests(in: db),
            groupInvitations: try loadGroupInvitations(in: db)
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
            "relay_attachment_chunks",
            "relay_prekey_bundles",
            "relay_federation_nodes",
            "relay_coordinator_pinned_keys",
            "relay_groups",
            "relay_group_join_requests",
            "relay_group_invitations"
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

enum RelayStoreError: Error {
    case inboxFull
    case invalidInboxRegistration
    case inboxAlreadyRegistered
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

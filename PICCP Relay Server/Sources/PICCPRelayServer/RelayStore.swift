import Foundation
import SQLite3

enum RelayStoreError: Error {
    case inboxFull
    case invalidInboxRegistration
    case inboxAlreadyRegistered
    case relayCapacityExceeded
    case invalidChunkIndex
    case invalidAttachmentPayload
    case invalidPrekeyBundle
    case groupCapacityExceeded
    case invalidGroupTitle
    case invalidFingerprint
    case notEnoughGroupMembers
    case groupNotFound
    case unauthorizedGroupMutation
    case groupJoinRequestNotFound
    case alreadyGroupMember
}

final class RelayStore {
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
    private let queue = DispatchQueue(label: "piccp.relay.store")
    private let fileURL: URL?
    private let maxInboxMessages: Int?
    private let temporalBuckets: [TimeInterval]
    private let queueKey = DispatchSpecificKey<Void>()
    private let announcementTTL: TimeInterval = 300
    private let minimumAnnouncementTTL: TimeInterval = 30
    private let maximumAnnouncementTTL: TimeInterval = 900
    private let maxAnnouncements = 2_048
    private let maxPairRequests = 100
    private let maxPairRequestTargets = 2_048
    private let attachmentTTL: TimeInterval = 3600
    private let maxAttachmentChunks = 512
    private let maxAttachmentChunkPayloadBytes = 128 * 1024
    private let maxAttachmentIds = 4_096
    private let prekeyTTL: TimeInterval = 86400
    private let minimumPrekeyTTL: TimeInterval = 300
    private let maximumPrekeyTTL: TimeInterval = 7 * 86400
    private let maxPrekeyBundles = 10_000
    private let maxOneTimePrekeysPerBundle = 64
    private let coordinatorDefaultNodeTTL: TimeInterval = 180
    private let maxGroupJoinRequests = 256
    private let maxGroups = 10_000
    private let maxGroupsPerCreator = 100
    private let maxGroupMembers = 256
    private let maxGroupTitleCharacters = 128
    private let maxMailboxes = 10_000
    private let maxStoredMessages = 100_000
    private let maxInboxRegistrations = 10_000
    private let maxActorProofReplayEntries = 20_000
    private var coordinatorDirectoryCache: [FederationNodeRecord] = []
    private var actorProofReplayCache: [String: Date] = [:]
    private var federationRegistrationAttemptsBySource: [String: [Date]] = [:]
    private var federationListAttemptsBySource: [String: [Date]] = [:]
    private var lastFederationRegistrationByEndpoint: [String: Date] = [:]
    private let federationRateWindowSeconds: TimeInterval = 60
    private let federationRegistrationMaxPerWindow = 24
    private let federationListMaxPerWindow = 120
    private let federationRegistrationMinEndpointIntervalSeconds: TimeInterval = 15

    init(
        fileURL: URL?,
        maxInboxMessages: Int?,
        temporalBucketSeconds: Int = 300,
        temporalBucketScheduleSeconds: [Int]? = nil
    ) {
        self.fileURL = fileURL
        self.maxInboxMessages = maxInboxMessages
        self.temporalBuckets = RelayStore.normalizeBuckets(
            primarySeconds: temporalBucketSeconds,
            scheduleSeconds: temporalBucketScheduleSeconds
        )
        queue.setSpecific(key: queueKey, value: ())
    }

    func load() {
        guard let fileURL else {
            return
        }
        performSync {
            do {
                let sqliteURL = sqliteStoreURL(for: fileURL)
                if let snapshotData = try SQLiteRelayStateStore.loadSnapshot(at: sqliteURL) {
                    try applySnapshotData(snapshotData)
                }
            } catch {
                print("[relay] Failed to load store: \(error)")
            }
        }
    }

    func save() {
        guard fileURL != nil else {
            return
        }
        performSync {
            saveLocked()
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
            let ttl = TimeInterval(ttlSeconds ?? Int(attachmentTTL))
            let now = Date()
            let bucketKey = "attachment:\(attachmentId.uuidString):\(chunkIndex)"
            let storedAt = bucketed(now, discriminator: bucketKey)
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
            let record = AttachmentRecord(
                chunkIndex: chunkIndex,
                payload: payload,
                storedAt: storedAt,
                expiresAt: expiresAt
            )
            if let index = records.firstIndex(where: { $0.chunkIndex == chunkIndex }) {
                records[index] = record
            } else {
                records.append(record)
            }
            if records.count > maxAttachmentChunks {
                records.sort { $0.storedAt < $1.storedAt }
                records = Array(records.suffix(maxAttachmentChunks))
            }
            attachments[key] = records
            saveLocked()
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
            return AttachmentChunk(attachmentId: attachmentId, chunkIndex: chunkIndex, payload: record.payload)
        }
    }

    func deliver(_ envelope: Envelope, to inboxId: String) throws -> Int {
        try performSync {
            if mailboxes[inboxId] == nil, mailboxes.count >= maxMailboxes {
                throw RelayStoreError.relayCapacityExceeded
            }
            let totalMessages = mailboxes.values.reduce(into: 0) { $0 += $1.count }
            guard totalMessages < maxStoredMessages else {
                throw RelayStoreError.relayCapacityExceeded
            }
            var inbox = mailboxes[inboxId, default: []]
            if let maxInboxMessages, inbox.count >= maxInboxMessages {
                throw RelayStoreError.inboxFull
            }
            let discriminator = "\(inboxId):\(envelope.id.uuidString)"
            inbox.append(StoredEnvelope(envelope: envelope, storedAt: bucketed(Date(), discriminator: discriminator)))
            mailboxes[inboxId] = inbox
            saveLocked()
            return inbox.count
        }
    }

    func fetch(inboxId: String, maxCount: Int?) -> [Envelope] {
        performSync {
            let inbox = mailboxes[inboxId, default: []]
            let count = max(0, maxCount ?? inbox.count)
            return Array(inbox.prefix(count)).map(\.envelope)
        }
    }

    func registerInbox(inboxId: String, accessPublicKey: Data) throws {
        try performSync {
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
            saveLocked()
        }
    }

    func inboxAccessPublicKey(for inboxId: String) -> Data? {
        performSync {
            inboxRegistrations[inboxId]?.accessPublicKey
        }
    }

    @discardableResult
    func acknowledge(inboxId: String, messageIds: [UUID]) -> Int {
        performSync {
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
                saveLocked()
            }
            return removed
        }
    }

    func stats() -> (mailboxes: Int, messages: Int) {
        performSync {
            let messageCount = mailboxes.values.reduce(0) { $0 + $1.count }
            return (mailboxes.count, messageCount)
        }
    }

    func announce(_ offer: ContactOffer, ttlSeconds: Int?) -> PairingAnnouncement {
        performSync {
            pruneAnnouncements(now: Date())
            let requestedTTL = TimeInterval(ttlSeconds ?? Int(announcementTTL))
            let ttl = min(maximumAnnouncementTTL, max(minimumAnnouncementTTL, requestedTTL))
            let now = Date()
            let announcement = PairingAnnouncement(
                id: UUID(),
                offer: offer,
                announcedAt: now,
                expiresAt: now.addingTimeInterval(ttl)
            )
            announcements[offer.fingerprint] = announcement
            if announcements.count > maxAnnouncements,
               let oldest = announcements.min(by: { $0.value.announcedAt < $1.value.announcedAt })?.key {
                announcements.removeValue(forKey: oldest)
            }
            return announcement
        }
    }

    func listAnnouncements(limit: Int?) -> [PairingAnnouncement] {
        performSync {
            pruneAnnouncements(now: Date())
            let list = announcements.values.sorted { $0.announcedAt > $1.announcedAt }
            let boundedLimit = min(500, max(0, limit ?? 500))
            return Array(list.prefix(boundedLimit))
        }
    }

    func sendPairRequest(targetFingerprint: String, offer: ContactOffer) -> Int {
        performSync {
            if pairRequests[targetFingerprint] == nil,
               pairRequests.count >= maxPairRequestTargets,
               let oldestTarget = pairRequests.min(by: {
                   ($0.value.first?.sentAt ?? .distantFuture) < ($1.value.first?.sentAt ?? .distantFuture)
               })?.key {
                pairRequests.removeValue(forKey: oldestTarget)
            }
            var requests = pairRequests[targetFingerprint, default: []]
            requests.append(PairingRequest(id: UUID(), from: offer, sentAt: Date()))
            if requests.count > maxPairRequests {
                requests = Array(requests.suffix(maxPairRequests))
            }
            pairRequests[targetFingerprint] = requests
            return requests.count
        }
    }

    func fetchPairRequests(targetFingerprint: String, maxCount: Int?) -> [PairingRequest] {
        performSync {
            let requests = pairRequests[targetFingerprint, default: []]
            let count = max(0, maxCount ?? requests.count)
            let fetched = Array(requests.prefix(count))
            let remaining = Array(requests.dropFirst(fetched.count))
            if remaining.isEmpty {
                pairRequests.removeValue(forKey: targetFingerprint)
            } else {
                pairRequests[targetFingerprint] = remaining
            }
            return fetched
        }
    }

    func uploadPrekeyBundle(fingerprint: String, bundle: PrekeyBundle, ttlSeconds: Int?) throws {
        try performSync {
            guard !fingerprint.isEmpty,
                  fingerprint == bundle.identityFingerprint,
                  bundle.oneTimePrekeys.count <= maxOneTimePrekeysPerBundle else {
                throw RelayStoreError.invalidPrekeyBundle
            }
            let requestedTTL = TimeInterval(ttlSeconds ?? Int(prekeyTTL))
            let ttl = min(maximumPrekeyTTL, max(minimumPrekeyTTL, requestedTTL))
            let now = Date()
            prunePrekeysLocked(now: now)
            if prekeyBundles[fingerprint] == nil,
               prekeyBundles.count >= maxPrekeyBundles,
               let oldest = prekeyBundles.min(by: { $0.value.expiresAt < $1.value.expiresAt })?.key {
                prekeyBundles.removeValue(forKey: oldest)
            }
            prekeyBundles[fingerprint] = PrekeyBundleRecord(
                bundle: bundle,
                expiresAt: now.addingTimeInterval(ttl)
            )
            saveLocked()
        }
    }

    func fetchPrekeyBundle(fingerprint: String) throws -> PrekeyBundle? {
        performSync {
            prunePrekeysLocked(now: Date())
            guard var record = prekeyBundles[fingerprint] else {
                return nil
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
                saveLocked()
                return bundle
            }
            return bundle
        }
    }

    func registerFederationNode(_ request: FederationNodeRegistrationRequest) throws -> FederationNodeRecord {
        performSync {
            let now = Date()
            let ttl = TimeInterval(request.ttlSeconds ?? Int(coordinatorDefaultNodeTTL))
            let expiresAt = now.addingTimeInterval(max(30, ttl))
            let record = FederationNodeRecord(
                endpoint: request.endpoint,
                relayInfo: request.relayInfo,
                lastHeartbeatAt: now,
                expiresAt: expiresAt
            )
            let key = federationNodeKey(request.endpoint)
            federationNodes[key] = record
            pruneFederationNodesLocked(now: now)
            saveLocked()
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

    func pinCoordinatorPublicKey(_ key: Data, for endpoint: RelayEndpoint) {
        performSync {
            coordinatorPinnedPublicKeys[federationNodeKey(endpoint)] = key
            saveLocked()
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

    func consumeActorProofNonce(
        fingerprint: String,
        nonce: UUID,
        now: Date = Date(),
        maxAgeSeconds: TimeInterval = 300
    ) -> Bool {
        performSync {
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
    }

    func createGroup(
        title: String,
        creatorFingerprint: String,
        memberFingerprints: [String],
        creatorProfile: RelayGroupMemberProfile? = nil,
        memberProfiles: [RelayGroupMemberProfile]? = nil
    ) throws -> RelayGroupDescriptor {
        try performSync {
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

            var members = Set(memberFingerprints.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty })
            members.formUnion(profileByFingerprint.keys)
            members.insert(creator)
            guard members.count >= 2 else {
                throw RelayStoreError.notEnoughGroupMembers
            }
            guard members.count <= maxGroupMembers else {
                throw RelayStoreError.groupCapacityExceeded
            }
            guard groups.count < maxGroups,
                  groups.values.filter({ $0.createdByFingerprint == creator }).count < maxGroupsPerCreator else {
                throw RelayStoreError.groupCapacityExceeded
            }
            let now = Date()
            let descriptor = RelayGroupDescriptor(
                id: UUID(),
                title: trimmedTitle,
                inboxId: InboxAddress.generate(),
                createdByFingerprint: creator,
                epoch: 0,
                members: members.sorted().map {
                    makeGroupMember(
                        fingerprint: $0,
                        existing: nil,
                        profile: profileByFingerprint[$0],
                        joinedAt: now
                    )
                },
                createdAt: now,
                updatedAt: now
            )
            groups[descriptor.id] = descriptor
            saveLocked()
            return descriptor
        }
    }

    func fetchGroup(groupId: UUID) -> RelayGroupDescriptor? {
        performSync {
            groups[groupId]
        }
    }

    func listGroups(memberFingerprint: String, limit: Int?) -> [RelayGroupDescriptor] {
        performSync {
            let fingerprint = memberFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !fingerprint.isEmpty else { return [] }
            var list = groups.values.filter { group in
                group.members.contains(where: { $0.fingerprint == fingerprint })
            }
            list.sort { lhs, rhs in
                if lhs.updatedAt != rhs.updatedAt {
                    return lhs.updatedAt > rhs.updatedAt
                }
                return lhs.createdAt > rhs.createdAt
            }
            return Array(list.prefix(min(500, max(0, limit ?? 500))))
        }
    }

    func updateGroup(_ request: UpdateGroupRequest) throws -> RelayGroupDescriptor {
        try performSync {
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

            var members = Dictionary(uniqueKeysWithValues: group.members.map { ($0.fingerprint, $0) })
            for fingerprint in request.addMemberFingerprints {
                let normalized = fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !normalized.isEmpty else { continue }
                if members[normalized] == nil {
                    members[normalized] = makeGroupMember(
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
                let existing = members[normalized.fingerprint]
                let merged = makeGroupMember(
                    fingerprint: normalized.fingerprint,
                    existing: existing,
                    profile: normalized,
                    joinedAt: Date()
                )
                if existing != merged {
                    members[normalized.fingerprint] = merged
                    changed = true
                }
            }
            for fingerprint in request.removeMemberFingerprints {
                let normalized = fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !normalized.isEmpty else { continue }
                guard normalized != group.createdByFingerprint else { continue }
                if members.removeValue(forKey: normalized) != nil {
                    changed = true
                }
            }
            guard members.count <= maxGroupMembers else {
                throw RelayStoreError.groupCapacityExceeded
            }
            guard members.count >= 2 else {
                throw RelayStoreError.notEnoughGroupMembers
            }

            if changed {
                group.members = members.values.sorted { $0.fingerprint < $1.fingerprint }
                group.epoch += 1
                group.updatedAt = Date()
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
                saveLocked()
            }
            return group
        }
    }

    func deleteGroup(_ request: DeleteGroupRequest) throws {
        try performSync {
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
            saveLocked()
        }
    }

    func requestGroupJoin(_ request: RequestGroupJoinRequest) throws -> RelayGroupJoinRequest {
        try performSync {
            guard let group = groups[request.groupId] else {
                throw RelayStoreError.groupNotFound
            }
            guard let requester = normalizedMemberProfile(request.requesterProfile) else {
                throw RelayStoreError.invalidFingerprint
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
                    requestedAt: now
                )
                pending[existingIndex] = refreshed
                pending.sort { lhs, rhs in lhs.requestedAt > rhs.requestedAt }
                groupJoinRequests[group.id] = pending
                saveLocked()
                return refreshed
            }

            let joinRequest = RelayGroupJoinRequest(
                id: UUID(),
                groupId: group.id,
                requester: requester,
                requestedAt: now
            )
            pending.insert(joinRequest, at: 0)
            if pending.count > maxGroupJoinRequests {
                pending = Array(pending.prefix(maxGroupJoinRequests))
            }
            groupJoinRequests[group.id] = pending
            saveLocked()
            return joinRequest
        }
    }

    func listGroupJoinRequests(_ request: ListGroupJoinRequestsRequest) throws -> [RelayGroupJoinRequest] {
        try performSync {
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
    }

    func approveGroupJoin(_ request: ApproveGroupJoinRequest) throws -> RelayGroupDescriptor {
        try performSync {
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
            let joinRequest = pending.remove(at: index)
            if pending.isEmpty {
                groupJoinRequests.removeValue(forKey: group.id)
            } else {
                groupJoinRequests[group.id] = pending
            }

            if group.members.contains(where: { $0.fingerprint == joinRequest.requester.fingerprint }) {
                saveLocked()
                return group
            }

            let updated = try updateGroup(
                UpdateGroupRequest(
                    groupId: group.id,
                    actorFingerprint: actor,
                    title: nil,
                    addMemberFingerprints: [joinRequest.requester.fingerprint],
                    addMemberProfiles: [joinRequest.requester],
                    removeMemberFingerprints: [],
                    actorProof: nil
                )
            )
            saveLocked()
            return updated
        }
    }

    func rejectGroupJoin(_ request: RejectGroupJoinRequest) throws {
        try performSync {
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
            saveLocked()
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

    private func performSync<T>(_ block: () throws -> T) rethrows -> T {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            return try block()
        }
        return try queue.sync {
            try block()
        }
    }

    private func saveLocked() {
        guard let fileURL else {
            return
        }
        do {
            enforceLimitsLocked()
            pruneAttachmentsLocked(now: Date())
            prunePrekeysLocked(now: Date())
            let snapshot = RelayStoreSnapshot(
                mailboxes: mailboxes,
                inboxRegistrations: inboxRegistrations,
                attachments: attachments,
                prekeyBundles: prekeyBundles,
                federationNodes: federationNodes,
                coordinatorPinnedPublicKeys: coordinatorPinnedPublicKeys,
                groups: groups,
                groupJoinRequests: groupJoinRequests
            )
            let data = try RelayCodec.encoder().encode(snapshot)
            try SQLiteRelayStateStore.saveSnapshot(data, at: sqliteStoreURL(for: fileURL))
        } catch {
            print("[relay] Failed to save store: \(error)")
        }
    }

    private func applySnapshotData(_ data: Data) throws {
        let snapshot = try RelayCodec.decoder().decode(RelayStoreSnapshot.self, from: data)
        mailboxes = snapshot.mailboxes
        inboxRegistrations = snapshot.inboxRegistrations
        attachments = snapshot.attachments
        prekeyBundles = snapshot.prekeyBundles
        federationNodes = snapshot.federationNodes
        coordinatorPinnedPublicKeys = snapshot.coordinatorPinnedPublicKeys
        groups = snapshot.groups
        groupJoinRequests = snapshot.groupJoinRequests
        enforceLimitsLocked()
        pruneAttachmentsLocked(now: Date())
        prunePrekeysLocked(now: Date())
        pruneFederationNodesLocked(now: Date())
    }

    private func sqliteStoreURL(for url: URL) -> URL {
        let ext = url.pathExtension.lowercased()
        if ext == "sqlite" || ext == "db" {
            return url
        }
        let base = url.pathExtension.isEmpty ? url : url.deletingPathExtension()
        return base.appendingPathExtension("sqlite")
    }

    private func pruneAnnouncements(now: Date) {
        announcements = announcements.filter { $0.value.expiresAt > now }
    }

    private func pruneAttachmentsLocked(now: Date) {
        attachments = attachments.compactMapValues { records in
            let filtered = records.filter { $0.expiresAt > now }
            return filtered.isEmpty ? nil : filtered
        }
    }

    private func prunePrekeysLocked(now: Date) {
        prekeyBundles = prekeyBundles.filter { $0.value.expiresAt > now }
    }

    private func pruneFederationNodesLocked(now: Date) {
        federationNodes = federationNodes.filter { $0.value.expiresAt > now }
    }

    private func enforceLimitsLocked() {
        guard let maxInboxMessages else { return }
        for (inboxId, messages) in mailboxes {
            if messages.count > maxInboxMessages {
                mailboxes[inboxId] = Array(messages.suffix(maxInboxMessages))
            }
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

    init(
        mailboxes: [String: [StoredEnvelope]],
        inboxRegistrations: [String: InboxRegistrationRecord] = [:],
        attachments: [String: [AttachmentRecord]],
        prekeyBundles: [String: PrekeyBundleRecord] = [:],
        federationNodes: [String: FederationNodeRecord] = [:],
        coordinatorPinnedPublicKeys: [String: Data] = [:],
        groups: [UUID: RelayGroupDescriptor] = [:],
        groupJoinRequests: [UUID: [RelayGroupJoinRequest]] = [:]
    ) {
        self.mailboxes = mailboxes
        self.inboxRegistrations = inboxRegistrations
        self.attachments = attachments
        self.prekeyBundles = prekeyBundles
        self.federationNodes = federationNodes
        self.coordinatorPinnedPublicKeys = coordinatorPinnedPublicKeys
        self.groups = groups
        self.groupJoinRequests = groupJoinRequests
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
    }
}

private struct InboxRegistrationRecord: Codable {
    let accessPublicKey: Data
    let registeredAt: Date
}

private struct StoredEnvelope: Codable {
    let envelope: Envelope
    let storedAt: Date
}

private struct AttachmentRecord: Codable {
    let chunkIndex: Int
    let payload: EncryptedPayload
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
        }
    }
}

private enum SQLiteRelayStateStore {
    private static let tableName = "relay_state"
    private static let snapshotKey = "relay_snapshot_v1"
    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    static func loadSnapshot(at url: URL) throws -> Data? {
        var db: OpaquePointer?
        try openDatabase(at: url, handle: &db)
        defer { sqlite3_close(db) }
        guard let db else { return nil }

        try ensureSchema(in: db)
        let sql = "SELECT value FROM \(tableName) WHERE key = ?1 LIMIT 1;"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.prepare(lastError(in: db))
        }
        defer { sqlite3_finalize(statement) }
        guard let statement else { return nil }

        guard sqlite3_bind_text(statement, 1, snapshotKey, -1, transient) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.bind(lastError(in: db))
        }
        let step = sqlite3_step(statement)
        if step == SQLITE_ROW {
            let byteCount = Int(sqlite3_column_bytes(statement, 0))
            guard byteCount > 0, let bytes = sqlite3_column_blob(statement, 0) else {
                return Data()
            }
            return Data(bytes: bytes, count: byteCount)
        }
        if step == SQLITE_DONE {
            return nil
        }
        throw SQLiteRelayStateStoreError.step(lastError(in: db))
    }

    static func saveSnapshot(_ snapshot: Data, at url: URL) throws {
        var db: OpaquePointer?
        try openDatabase(at: url, handle: &db)
        defer { sqlite3_close(db) }
        guard let db else { return }

        try ensureSchema(in: db)
        let sql = """
        INSERT INTO \(tableName) (key, value) VALUES (?1, ?2)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value;
        """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.prepare(lastError(in: db))
        }
        defer { sqlite3_finalize(statement) }
        guard let statement else { return }

        guard sqlite3_bind_text(statement, 1, snapshotKey, -1, transient) == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.bind(lastError(in: db))
        }
        let bindResult = snapshot.withUnsafeBytes { buffer in
            sqlite3_bind_blob(statement, 2, buffer.baseAddress, Int32(buffer.count), transient)
        }
        guard bindResult == SQLITE_OK else {
            throw SQLiteRelayStateStoreError.bind(lastError(in: db))
        }
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw SQLiteRelayStateStoreError.step(lastError(in: db))
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
        CREATE TABLE IF NOT EXISTS \(tableName) (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );
        """
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

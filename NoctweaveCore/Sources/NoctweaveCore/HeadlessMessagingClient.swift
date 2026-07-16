import CryptoKit
import Foundation
#if canImport(Security)
import Security
#endif

public struct HeadlessClientStatus: Codable, Equatable {
    public let displayName: String
    public let fingerprint: String
    public let inboxId: String
    public let relay: RelayEndpoint
    public let contactCount: Int
    public let conversationCount: Int

    public init(
        displayName: String,
        fingerprint: String,
        inboxId: String,
        relay: RelayEndpoint,
        contactCount: Int,
        conversationCount: Int
    ) {
        self.displayName = displayName
        self.fingerprint = fingerprint
        self.inboxId = inboxId
        self.relay = relay
        self.contactCount = contactCount
        self.conversationCount = conversationCount
    }
}

public struct HeadlessSentMessage: Codable, Equatable {
    public let contact: Contact
    public let envelopeId: UUID
    public let messageCounter: UInt64
    public let storedCount: Int

    public init(contact: Contact, envelopeId: UUID, messageCounter: UInt64, storedCount: Int) {
        self.contact = contact
        self.envelopeId = envelopeId
        self.messageCounter = messageCounter
        self.storedCount = storedCount
    }
}

public struct HeadlessSentAttachment: Codable, Equatable {
    public let contact: Contact?
    public let group: HeadlessGroupSummary?
    public let envelopeId: UUID
    public let messageCounter: UInt64
    public let descriptor: AttachmentDescriptor
    public let uploadedChunkCount: Int
    public let storedCount: Int

    public init(
        contact: Contact?,
        group: HeadlessGroupSummary?,
        envelopeId: UUID,
        messageCounter: UInt64,
        descriptor: AttachmentDescriptor,
        uploadedChunkCount: Int,
        storedCount: Int
    ) {
        self.contact = contact
        self.group = group
        self.envelopeId = envelopeId
        self.messageCounter = messageCounter
        self.descriptor = descriptor
        self.uploadedChunkCount = uploadedChunkCount
        self.storedCount = storedCount
    }
}

public struct HeadlessFetchedAttachment: Codable, Equatable {
    public let descriptor: AttachmentDescriptor
    public let data: Data

    public init(descriptor: AttachmentDescriptor, data: Data) {
        self.descriptor = descriptor
        self.data = data
    }
}

public struct HeadlessReceivedMessage: Codable, Equatable {
    public let contact: Contact
    public let envelopeId: UUID
    public let messageCounter: UInt64
    public let body: MessageBody
    public let sentAt: Date

    public init(
        contact: Contact,
        envelopeId: UUID,
        messageCounter: UInt64,
        body: MessageBody,
        sentAt: Date
    ) {
        self.contact = contact
        self.envelopeId = envelopeId
        self.messageCounter = messageCounter
        self.body = body
        self.sentAt = sentAt
    }
}

public struct HeadlessIdentityChangeResult: Codable, Equatable {
    public let oldFingerprint: String
    public let newFingerprint: String
    public let notifiedContacts: [String]
    public let failedContacts: [String]

    public init(
        oldFingerprint: String,
        newFingerprint: String,
        notifiedContacts: [String],
        failedContacts: [String]
    ) {
        self.oldFingerprint = oldFingerprint
        self.newFingerprint = newFingerprint
        self.notifiedContacts = notifiedContacts
        self.failedContacts = failedContacts
    }
}

public struct HeadlessContinuityAudit: Codable, Equatable {
    public let profileId: UUID
    public let fingerprint: String
    public let events: [ContinuityEvent]

    public init(profileId: UUID, fingerprint: String, events: [ContinuityEvent]) {
        self.profileId = profileId
        self.fingerprint = fingerprint
        self.events = events
    }
}

public struct HeadlessContinuityAuditPurgeResult: Codable, Equatable {
    public let profileId: UUID
    public let fingerprint: String
    public let purgedCount: Int

    public init(profileId: UUID, fingerprint: String, purgedCount: Int) {
        self.profileId = profileId
        self.fingerprint = fingerprint
        self.purgedCount = purgedCount
    }
}

public struct HeadlessGroupSummary: Codable, Equatable {
    public let id: UUID
    public let title: String
    public let inboxId: String?
    public let memberCount: Int
    public let relayEpoch: UInt64?
    public let unreadCount: Int
    public let createdByFingerprint: String?

    public init(
        id: UUID,
        title: String,
        inboxId: String?,
        memberCount: Int,
        relayEpoch: UInt64?,
        unreadCount: Int,
        createdByFingerprint: String?
    ) {
        self.id = id
        self.title = title
        self.inboxId = inboxId
        self.memberCount = memberCount
        self.relayEpoch = relayEpoch
        self.unreadCount = unreadCount
        self.createdByFingerprint = createdByFingerprint
    }
}

public struct HeadlessSentGroupMessage: Codable, Equatable {
    public let group: HeadlessGroupSummary
    public let envelopeId: UUID
    public let messageCounter: UInt64
    public let storedCount: Int

    public init(group: HeadlessGroupSummary, envelopeId: UUID, messageCounter: UInt64, storedCount: Int) {
        self.group = group
        self.envelopeId = envelopeId
        self.messageCounter = messageCounter
        self.storedCount = storedCount
    }
}

public struct HeadlessReceivedGroupMessage: Codable, Equatable {
    public let group: HeadlessGroupSummary
    public let envelopeId: UUID
    public let messageCounter: UInt64
    public let senderFingerprint: String
    public let senderDisplayName: String?
    public let body: MessageBody
    public let sentAt: Date

    public init(
        group: HeadlessGroupSummary,
        envelopeId: UUID,
        messageCounter: UInt64,
        senderFingerprint: String,
        senderDisplayName: String?,
        body: MessageBody,
        sentAt: Date
    ) {
        self.group = group
        self.envelopeId = envelopeId
        self.messageCounter = messageCounter
        self.senderFingerprint = senderFingerprint
        self.senderDisplayName = senderDisplayName
        self.body = body
        self.sentAt = sentAt
    }
}

public enum HeadlessMessagingClientError: Error, Equatable {
    case stateAlreadyExists
    case missingState
    case missingInboxAccessKey
    case missingInstallation
    case identityMutationInProgress(String)
    case directOutboxFull(Int)
    case directDeliveryRequiresAction(UUID)
    case contactNotFound(String)
    case ambiguousContact(String)
    case groupNotFound(String)
    case ambiguousGroup(String)
    case missingGroupRatchet(String)
    case missingGroupSenderKey(String)
    case legacyGroupAcknowledgementConflict(UUID)
    case legacyGroupAcknowledgementBackpressure(String, Int)
    case inboundEnvelopeConflict(UUID)
    case identityRotationBlockedByLegacyGroups(Int)
    case identityRotationSelectionMismatch
    case attachmentNotFound(String)
    case missingAttachmentKey(String)
    case invalidAttachmentDescriptor
    case attachmentDigestMismatch(String)
    case relayRejected(String)
    case unsupportedInboundSession
}

extension HeadlessMessagingClientError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .stateAlreadyExists:
            return "Headless client state already exists. Use a different --state path or --overwrite true."
        case .missingState:
            return "Headless client state was not found. Run `NoctweaveCLI init` first."
        case .missingInboxAccessKey:
            return "Headless client state is missing its inbox access key."
        case .missingInstallation:
            return "Headless client state is missing its architecture-v2 installation."
        case .identityMutationInProgress(let detail):
            return "An identity mutation is already in progress: \(detail)"
        case .directOutboxFull(let maximum):
            return "The durable direct-message outbox is full (maximum \(maximum)). Retry pending deliveries before sending another message."
        case .directDeliveryRequiresAction(let envelopeId):
            return "Direct delivery `\(envelopeId.uuidString)` reached a permanent rejection or the bounded retry limit. Inspect the relay configuration, then explicitly rearm the preserved ciphertext."
        case .contactNotFound(let selector):
            return "No contact matched `\(selector)`."
        case .ambiguousContact(let selector):
            return "More than one contact matched `\(selector)`. Use the contact UUID or fingerprint."
        case .groupNotFound(let selector):
            return "No group matched `\(selector)`."
        case .ambiguousGroup(let selector):
            return "More than one group matched `\(selector)`. Use the group UUID."
        case .missingGroupRatchet(let selector):
            return "Group `\(selector)` is missing recoverable ratchet state. Refresh groups or recreate the group."
        case .missingGroupSenderKey(let fingerprint):
            return "Group sender signing key is missing for `\(fingerprint)`."
        case .legacyGroupAcknowledgementConflict(let envelopeId):
            return "Legacy group envelope `\(envelopeId.uuidString)` conflicts with a durably processed envelope using the same identifier."
        case .legacyGroupAcknowledgementBackpressure(let group, let limit):
            return "Legacy group `\(group)` has \(limit) processed messages awaiting destructive relay acknowledgement. Acknowledge them before fetching more."
        case .inboundEnvelopeConflict(let eventId):
            return "Inbound event `\(eventId.uuidString)` conflicts with a previously processed signed envelope. The mailbox cursor was not advanced."
        case .identityRotationBlockedByLegacyGroups(let count):
            return "Identity rotation is blocked while \(count) active fingerprint-scoped legacy group(s) remain. Leave or migrate those groups to signed installation-aware group state first."
        case .identityRotationSelectionMismatch:
            return "The requested continuity recipients do not match the durably prepared identity rotation. Resume it with the same contact IDs."
        case .attachmentNotFound(let selector):
            return "No attachment matched `\(selector)` in local state."
        case .missingAttachmentKey(let selector):
            return "Attachment `\(selector)` is missing local recovery metadata."
        case .invalidAttachmentDescriptor:
            return "Attachment metadata is malformed or exceeds Noctweave transport limits."
        case .attachmentDigestMismatch(let selector):
            return "Attachment `\(selector)` failed digest verification."
        case .relayRejected(let message):
            return "Relay rejected the request: \(message)"
        case .unsupportedInboundSession:
            return "Received a message without an existing session or session-init KEM ciphertext."
        }
    }
}

public actor HeadlessMessagingClient {
    public let store: ClientStateStore
    public let authToken: String?
    public let timeout: TimeInterval
    private let stateMutationGate = AsyncOperationGate()

    public init(
        stateURL: URL,
        useEncryptedStore: Bool,
        stateEncryptionKey: SymmetricKey? = nil,
        authToken: String? = nil,
        timeout: TimeInterval = RelayClient.defaultTimeout
    ) {
        self.store = ClientStateStore(
            fileURL: stateURL,
            useEncryption: useEncryptedStore,
            encryptionKey: stateEncryptionKey
        )
        self.authToken = authToken
        self.timeout = timeout
    }

    public func createState(
        displayName: String,
        relay: RelayEndpoint,
        overwrite: Bool = false
    ) async throws -> HeadlessClientStatus {
        if !overwrite, try await store.load() != nil {
            throw HeadlessMessagingClientError.stateAlreadyExists
        }
        let identity = try Identity.generate(displayName: displayName)
        let inboxAccessKey = try SigningKeyPair.generate()
        let inboxId = InboxAddress.derived(from: inboxAccessKey.publicKeyData)
        var state = ClientState(identity: identity, relay: relay, inboxId: inboxId)
        state.inboxAccessKey = inboxAccessKey
        try state.migrateToArchitectureV2()
        state.relayServers = [
            RelayServerRecord(
                name: relay.host,
                endpoint: relay
            )
        ]
        try await store.save(state)
        return status(for: state)
    }

    public func status() async throws -> HeadlessClientStatus {
        try await status(for: loadState())
    }

    public func registerInbox() async throws {
        var state = try await loadState()
        let accessKey = try inboxAccessKey(from: state)
        var request = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: state.inboxId,
            accessPublicKey: accessKey.publicKeyData
        )
        let proof = try Self.makeActorProof(signingKey: accessKey) { actorProof in
            try request.signableData(for: actorProof)
        }
        request = .privacyMinimizedV2(
            inboxId: state.inboxId,
            accessPublicKey: accessKey.publicKeyData,
            accessProof: proof
        )
        let response = try await relayClient(for: state.relay).send(.registerInbox(request), timeout: timeout)
        try requireOK(response)
        _ = try await ensureMailboxConsumer(state: &state, accessKey: accessKey)
        try await store.save(state)
    }

    /// Returns the active route credential identifier that one already
    /// admitted endpoint can use to sponsor another route credential in the
    /// same identity generation. This does not admit an endpoint. No inbox
    /// authority or private key material leaves this client.
    public func mailboxRouteSponsorshipContext() async throws -> MailboxRouteSponsorshipContext {
        await stateMutationGate.acquire()
        defer { stateMutationGate.release() }
        var state = try await loadState()
        let accessKey = try inboxAccessKey(from: state)
        let mailbox = try await ensureMailboxConsumer(state: &state, accessKey: accessKey)
        return MailboxRouteSponsorshipContext(
            inboxId: state.inboxId,
            relay: state.relay,
            sponsorConsumerId: mailbox.consumerId
        )
    }

    /// Sponsors a fresh route credential for an endpoint that was admitted
    /// separately through the generation-scoped endpoint-admission protocol.
    /// The caller supplies a draft containing the route public key, sponsor
    /// ID, and route-possession proof; this client adds the inbox-authority and
    /// active-route sponsor proofs and publishes it.
    @discardableResult
    public func sponsorMailboxRouteCredential(
        _ proposed: RegisterMailboxConsumerRequest
    ) async throws -> MailboxConsumerRegistration {
        await stateMutationGate.acquire()
        defer { stateMutationGate.release() }
        var state = try await loadState()
        let accessKey = try inboxAccessKey(from: state)
        let sponsor = try await ensureMailboxConsumer(state: &state, accessKey: accessKey)
        guard proposed.inboxId == state.inboxId,
              proposed.sponsorConsumerId == sponsor.consumerId,
              proposed.consumerId != sponsor.consumerId,
              SigningKeyPair.isValidPublicKey(proposed.consumerSigningPublicKey),
              let consumerProof = proposed.consumerProof,
              consumerProof.publicSigningKey == proposed.consumerSigningPublicKey,
              consumerProof.isConsistentFingerprint() else {
            throw HeadlessMessagingClientError.relayRejected("Invalid sponsored mailbox registration")
        }
        let draft = RegisterMailboxConsumerRequest(
            inboxId: state.inboxId,
            consumerId: proposed.consumerId,
            consumerSigningPublicKey: proposed.consumerSigningPublicKey,
            sponsorConsumerId: sponsor.consumerId,
            startingSequence: proposed.startingSequence,
            consumerProof: consumerProof
        )
        let consumerSignableData = try draft.consumerSignableData(for: consumerProof)
        guard consumerProof.verify(signableData: consumerSignableData) else {
            throw HeadlessMessagingClientError.relayRejected("Invalid new-consumer possession proof")
        }
        let authorityProof = try Self.makeActorProof(signingKey: accessKey) { proof in
            try draft.authoritySignableData(for: proof)
        }
        let sponsorProof = try Self.makeActorProof(signingKey: sponsor.consumerKey) { proof in
            try draft.sponsorSignableData(for: proof)
        }
        let request = RegisterMailboxConsumerRequest(
            inboxId: state.inboxId,
            consumerId: proposed.consumerId,
            consumerSigningPublicKey: proposed.consumerSigningPublicKey,
            sponsorConsumerId: sponsor.consumerId,
            startingSequence: proposed.startingSequence,
            authorityProof: authorityProof,
            consumerProof: consumerProof,
            sponsorProof: sponsorProof
        )
        let response = try await relayClient(for: state.relay).send(
            .registerMailboxConsumer(request),
            timeout: timeout
        )
        guard response.type == .mailboxConsumer,
              let registration = response.mailboxConsumer,
              registration.consumerId == proposed.consumerId,
              registration.consumerSigningPublicKey == proposed.consumerSigningPublicKey,
              registration.state == .active else {
            throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
        }
        return registration
    }

    public func exportContactCode() async throws -> String {
        var state = try await loadState()
        let inboxAccessPublicKey = state.inboxAccessKey?.publicKeyData
        let offer = try issueCertifiedContactOffer(
            state: &state,
            inboxAccessPublicKey: inboxAccessPublicKey
        )
        try await store.save(state)
        return try ContactOfferCode.encode(offer)
    }

    public func exportContactPackage(password: String) async throws -> Data {
        var state = try await loadState()
        let inboxAccessPublicKey = state.inboxAccessKey?.publicKeyData
        let offer = try issueCertifiedContactOffer(
            state: &state,
            inboxAccessPublicKey: inboxAccessPublicKey
        )
        try await store.save(state)
        return try ContactShare.encode(offer, password: password)
    }

    public func importContactCode(_ code: String) async throws -> Contact {
        let offer = try ContactOfferCode.decode(code)
        return try await importContactOffer(offer)
    }

    public func importContactPackage(_ data: Data, password: String) async throws -> Contact {
        let offer = try ContactShare.decode(data, password: password)
        return try await importContactOffer(offer)
    }

    public func contacts() async throws -> [Contact] {
        try await loadState().contacts.sorted { lhs, rhs in
            lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName) == .orderedAscending
        }
    }

    public func createGroup(title: String, memberSelectors: [String]) async throws -> HeadlessGroupSummary {
        var state = try await loadState()
        let contacts = try memberSelectors.map { try resolveContact($0, in: state.contacts) }
        let groupId = UUID()
        let creatorProfile = groupMemberProfile(identity: state.identity, inboxId: state.inboxId, relay: state.relay)
        let memberProfiles = contacts.map(groupMemberProfile(contact:))
        let distribution = try GroupRatchetEpochSecretDistribution.seal(
            secret: Self.randomBytes(count: 32),
            groupId: groupId,
            epoch: 0,
            operation: .create,
            recipients: [creatorProfile] + memberProfiles
        )
        var request = CreateGroupRequest(
            groupId: groupId,
            title: title,
            creatorFingerprint: state.identity.fingerprint,
            memberFingerprints: contacts.map(\.fingerprint),
            creatorProfile: creatorProfile,
            memberProfiles: memberProfiles,
            initialRatchetSecretDistribution: distribution
        )
        let proof = try Self.makeActorProof(signingKey: state.identity.signingKey) { actorProof in
            try request.signableData(for: actorProof)
        }
        request = CreateGroupRequest(
            groupId: request.groupId,
            title: request.title,
            creatorFingerprint: request.creatorFingerprint,
            memberFingerprints: request.memberFingerprints,
            invitedFingerprints: request.invitedFingerprints,
            creatorProfile: request.creatorProfile,
            memberProfiles: request.memberProfiles,
            initialRatchetSecretDistribution: request.initialRatchetSecretDistribution,
            creatorProof: proof
        )
        let response = try await relayClient(for: state.relay).send(.createGroup(request), timeout: timeout)
        guard response.type == .group, let descriptor = response.group else {
            throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
        }
        let group = try groupConversation(from: descriptor, contacts: contacts, state: state, existing: nil)
        state.upsert(group: group)
        try await store.save(state)
        return summary(for: group)
    }

    public func groups(refreshFromRelay: Bool = true, limit: Int = 100) async throws -> [HeadlessGroupSummary] {
        var state = try await loadState()
        if refreshFromRelay {
            try await refreshGroups(into: &state, limit: limit)
            try await store.save(state)
        }
        return state.groups
            .sorted { lhs, rhs in
                lhs.title.localizedCaseInsensitiveCompare(rhs.title) == .orderedAscending
            }
            .map(summary(for:))
    }

    public func continuityAudit() async throws -> HeadlessContinuityAudit {
        let state = try await loadState()
        return continuityAudit(for: state)
    }

    public func purgeContinuityAudit() async throws -> HeadlessContinuityAuditPurgeResult {
        var state = try await loadState()
        let before = continuityAudit(for: state)
        state.purgeContinuityEvents()
        try await store.save(state)
        return HeadlessContinuityAuditPurgeResult(
            profileId: before.profileId,
            fingerprint: before.fingerprint,
            purgedCount: before.events.count
        )
    }

    public func setContactIdentityReset(selector: String, allow: Bool) async throws -> Contact {
        var state = try await loadState()
        var contact = try resolveContact(selector, in: state.contacts)
        contact.allowIdentityReset = allow
        state.updateContact(contact)
        try await store.save(state)
        return contact
    }

    /// Rotates the current generation's identity authority and discloses the
    /// old-key-authenticated continuity statement only to the explicitly
    /// selected contacts. Passing an empty set is the explicit choice to
    /// disclose continuity to nobody. This is an in-generation authority
    /// rotation, not an unlinkability boundary; callers that need severance
    /// must use identity burn.
    public func rotateIdentity(
        preservingContinuityWith contactIds: Set<UUID>
    ) async throws -> HeadlessIdentityChangeResult {
        await stateMutationGate.acquire()
        defer { stateMutationGate.release() }
        var state = try await loadState()
        if let existing = state.identityMutationV2 {
            guard existing.kind == .rotation else {
                throw HeadlessMessagingClientError.identityMutationInProgress(existing.kind.rawValue)
            }
            guard Set(existing.notifications.map(\.contactId)) == contactIds else {
                throw HeadlessMessagingClientError.identityRotationSelectionMismatch
            }
            _ = try await retryPendingDirectDeliveriesUnlocked(maxCount: 256)
            return identityMutationResult(existing, state: try await loadState())
        }
        let activeLegacyGroupCount = state.groups.reduce(into: 0) { count, group in
            if !group.isPendingInvitation, group.relayInboxId != nil {
                count += 1
            }
        }
        guard activeLegacyGroupCount == 0 else {
            throw HeadlessMessagingClientError.identityRotationBlockedByLegacyGroups(activeLegacyGroupCount)
        }
        let knownContactIds = Set(state.contacts.map(\.id))
        guard contactIds.isSubset(of: knownContactIds) else {
            let unknownId = contactIds
                .subtracting(knownContactIds)
                .map(\.uuidString)
                .sorted()
                .first ?? "unknown"
            throw HeadlessMessagingClientError.contactNotFound(unknownId)
        }
        let selectedContacts = state.contacts.filter { contactIds.contains($0.id) }
        let existingPendingIds = state.pendingDirectDeliveries.map(\.id)
        guard selectedContacts.count + existingPendingIds.count
                <= IdentityMutationJournalV2.maximumNotifications,
              existingPendingIds.count <= NoctweaveArchitectureV2.maximumIntentDependencies else {
            throw HeadlessMessagingClientError.identityMutationInProgress(
                "retry pending sends before rotating"
            )
        }
        for pending in state.pendingDirectDeliveries {
            try ensurePreparedIntent(for: pending, dependencies: [], state: &state)
        }

        var previousIdentity = state.identity
        let rotationContext = try state.identity.rotateKeys()
        previousIdentity.signingKey = rotationContext.oldSigningKey
        previousIdentity.agreementKey = rotationContext.oldAgreementKey

        let oldFingerprint = rotationContext.oldFingerprint
        let newFingerprint = state.identity.fingerprint
        let mutationAt = max(Date(), state.installationManifest?.issuedAt ?? .distantPast)
        state.appendContinuityEvent(
            ContinuityEvent(
                kind: .identityRotated,
                timestamp: mutationAt,
                oldFingerprint: oldFingerprint,
                newFingerprint: newFingerprint
            )
        )
        state.prekeys = try PrekeyState.generate(identity: state.identity)
        try state.resignInstallationManifestAfterIdentityRotation(at: mutationAt)

        var notifications: [IdentityMutationNotificationV2] = []
        for contact in selectedContacts {
            let envelope: Envelope
            let notificationSigner: Data?
            if contact.usesCertifiedInstallationEndpoint {
                guard let installation = state.localInstallation else {
                    throw HeadlessMessagingClientError.missingInstallation
                }
                let peerEndpoint = try contact.certifiedInstallationEndpoint()
                let selected = try directSendEndpointContext(
                    contact: contact,
                    peerEndpoint: peerEndpoint,
                    state: &state
                )
                var conversation: Conversation
                var kemCiphertext: Data?
                var prekey: PrekeyReference?
                if let existing = state.conversation(
                    for: contact.id,
                    endpointSession: selected.endpointSession
                ) {
                    conversation = existing
                } else {
                    let session = try MessageEngine.createOutboundInstallationSession(
                        localInstallation: installation,
                        localEndpoint: selected.localEndpoint,
                        pairwiseBinding: selected.binding,
                        contact: contact
                    )
                    conversation = session.conversation
                    kemCiphertext = session.kemCiphertext
                    prekey = session.prekey
                }
                let context = try MessageAuthenticatedContext.directV4(
                    eventId: UUID(),
                    senderEndpoint: selected.localEndpoint,
                    recipientEndpoint: peerEndpoint,
                    pairwiseBinding: selected.binding
                )
                envelope = try MessageEngine.encrypt(
                    body: .identityRotation(rotationContext.rotation),
                    senderSigningKey: installation.signingKey,
                    senderFingerprint: selected.binding.localInstallationHandle.rawValue,
                    conversation: &conversation,
                    kemCiphertext: kemCiphertext,
                    prekey: prekey,
                    authenticatedContext: context
                )
                conversation.markMessageProcessed()
                state.upsert(conversation: conversation)
                notificationSigner = installation.signingKey.publicKeyData
            } else {
                let existingConversation = state.conversation(for: contact.id)
                let bootstrapSession = try MessageEngine.createOutboundSession(
                    identity: previousIdentity,
                    contact: contact
                )
                var conversation = bootstrapSession.conversation
                envelope = try MessageEngine.encrypt(
                    body: .identityRotation(rotationContext.rotation),
                    senderSigningKey: rotationContext.oldSigningKey,
                    senderFingerprint: oldFingerprint,
                    conversation: &conversation,
                    kemCiphertext: bootstrapSession.kemCiphertext
                )
                conversation.markMessageProcessed()
                if let existingConversation {
                    conversation.messages = existingConversation.messages
                    conversation.unreadCount = existingConversation.unreadCount
                }
                state.upsert(conversation: conversation)
                notificationSigner = nil
            }
            let pending = PendingDirectDelivery(
                contactId: contact.id,
                inboxId: contact.inboxId,
                preferredRelay: state.relay,
                destinationRelay: contact.relay,
                envelope: envelope,
                queuedAt: mutationAt
            )
            state.pendingDirectDeliveries.append(pending)
            try ensurePreparedIntent(
                for: pending,
                dependencies: existingPendingIds,
                state: &state
            )
            notifications.append(
                IdentityMutationNotificationV2(
                    id: envelope.id,
                    contactId: contact.id,
                    contactDisplayName: contact.displayName,
                    signerPublicKey: notificationSigner
                )
            )
        }
        let journal = IdentityMutationJournalV2(
            kind: .rotation,
            phase: .cleanupComplete,
            oldFingerprint: oldFingerprint,
            oldSigningPublicKey: rotationContext.oldSigningKey.publicKeyData,
            newFingerprint: newFingerprint,
            notifications: notifications,
            createdAt: mutationAt
        )
        guard journal.isStructurallyValid else {
            throw IdentityProfileMigrationError.invalidV2State
        }
        state.identityMutationV2 = journal
        // This is the rollback boundary: the new identity, manifest, sessions,
        // exact old-key-signed ciphertexts, and intents become durable together.
        try await store.save(state)
        _ = try await retryPendingDirectDeliveriesUnlocked(maxCount: 256)
        return identityMutationResult(journal, state: try await loadState())
    }

    public func burnIdentity() async throws -> HeadlessIdentityChangeResult {
        await stateMutationGate.acquire()
        defer { stateMutationGate.release() }
        var state = try await loadState()
        if let existing = state.identityMutationV2 {
            guard existing.kind == .burn else {
                throw HeadlessMessagingClientError.identityMutationInProgress(existing.kind.rawValue)
            }
            return try await resumeIdentityBurnUnlocked(existing)
        }
        let oldIdentity = state.identity
        let oldFingerprint = oldIdentity.fingerprint
        let oldInboxAccessKey = try inboxAccessKey(from: state)
        let retainedContacts = state.contacts.filter(\.allowIdentityReset)
        guard retainedContacts.count <= IdentityMutationJournalV2.maximumNotifications else {
            throw HeadlessMessagingClientError.identityMutationInProgress("too many reset contacts")
        }
        let staged = try StagedIdentityGenerationV2.generate(
            displayName: oldIdentity.displayName,
            relay: state.relay
        )
        guard let stagedEndpoint = staged.issuedContactEndpointsV2.first else {
            throw IdentityProfileMigrationError.invalidV2State
        }
        let newOffer = try ContactOffer.createCertified(
            displayName: staged.identity.displayName,
            inboxId: staged.inboxId,
            relay: staged.relay,
            identity: staged.identity,
            identityGenerationId: staged.identityGenerationId,
            installationManifest: staged.installationManifest,
            preferredInstallationEndpoint: stagedEndpoint,
            inboxAccessPublicKey: staged.inboxAccessKey.publicKeyData
        )
        let reset = try IdentityReset.create(
            newOffer: newOffer,
            signingKey: oldIdentity.signingKey
        )
        var notifications: [IdentityMutationNotificationV2] = []
        for contact in retainedContacts {
            let envelope: Envelope
            let notificationSigner: Data?
            if contact.usesCertifiedInstallationEndpoint {
                guard let installation = state.localInstallation else {
                    throw HeadlessMessagingClientError.missingInstallation
                }
                let peerEndpoint = try contact.certifiedInstallationEndpoint()
                let selected = try directSendEndpointContext(
                    contact: contact,
                    peerEndpoint: peerEndpoint,
                    state: &state
                )
                var conversation: Conversation
                var kemCiphertext: Data?
                var prekey: PrekeyReference?
                if let existing = state.conversation(
                    for: contact.id,
                    endpointSession: selected.endpointSession
                ) {
                    conversation = existing
                } else {
                    let session = try MessageEngine.createOutboundInstallationSession(
                        localInstallation: installation,
                        localEndpoint: selected.localEndpoint,
                        pairwiseBinding: selected.binding,
                        contact: contact
                    )
                    conversation = session.conversation
                    kemCiphertext = session.kemCiphertext
                    prekey = session.prekey
                }
                let context = try MessageAuthenticatedContext.directV4(
                    eventId: UUID(),
                    senderEndpoint: selected.localEndpoint,
                    recipientEndpoint: peerEndpoint,
                    pairwiseBinding: selected.binding
                )
                envelope = try MessageEngine.encrypt(
                    body: .identityReset(reset),
                    senderSigningKey: installation.signingKey,
                    senderFingerprint: selected.binding.localInstallationHandle.rawValue,
                    conversation: &conversation,
                    kemCiphertext: kemCiphertext,
                    prekey: prekey,
                    authenticatedContext: context
                )
                notificationSigner = installation.signingKey.publicKeyData
            } else {
                let session = try MessageEngine.createOutboundSession(identity: oldIdentity, contact: contact)
                var conversation = session.conversation
                envelope = try MessageEngine.encrypt(
                    body: .identityReset(reset),
                    senderSigningKey: oldIdentity.signingKey,
                    senderFingerprint: oldFingerprint,
                    conversation: &conversation,
                    kemCiphertext: session.kemCiphertext
                )
                notificationSigner = nil
            }
            let pending = PendingDirectDelivery(
                contactId: contact.id,
                inboxId: contact.inboxId,
                preferredRelay: state.relay,
                destinationRelay: contact.relay,
                envelope: envelope,
                queuedAt: staged.createdAt
            )
            notifications.append(
                IdentityMutationNotificationV2(
                    id: envelope.id,
                    contactId: contact.id,
                    contactDisplayName: contact.displayName,
                    signerPublicKey: notificationSigner,
                    stagedDelivery: pending
                )
            )
        }
        // Persist exact retirement requests before cutover so every known old
        // route can be destroyed without retaining the old inbox private key.
        let retirementRequest = try RetireInboxRequest.make(
            inboxId: state.inboxId,
            accessSigningKey: oldInboxAccessKey,
            signedAt: staged.createdAt
        )
        var retirementRelaysByRoute = [
            Self.mailboxRouteKey(relay: state.relay, inboxId: state.inboxId): state.relay
        ]
        for (routeKey, credential) in state.localInstallation?.mailboxCredentialsByRoute ?? [:] {
            if credential.inboxId == state.inboxId.lowercased(),
               let relay = credential.relay {
                retirementRelaysByRoute[routeKey] = relay
            } else if let parsed = Self.parseMailboxRouteKey(routeKey),
                      parsed.inboxId == state.inboxId.lowercased() {
                // Pre-scope migration fallback. It preserves route teardown,
                // while newly written credentials retain the exact endpoint.
                retirementRelaysByRoute[routeKey] = parsed.relay
            }
        }
        let pendingRetirements = retirementRelaysByRoute
            .sorted(by: { $0.key < $1.key })
            .map { _, relay in
                PendingInboxRetirementV2(relay: relay, request: retirementRequest)
            }
        let journal = IdentityMutationJournalV2(
            kind: .burn,
            phase: .prepared,
            oldFingerprint: oldFingerprint,
            oldSigningPublicKey: oldIdentity.signingKey.publicKeyData,
            newFingerprint: staged.identity.fingerprint,
            notifications: notifications,
            stagedBurn: staged,
            pendingInboxRetirements: pendingRetirements,
            createdAt: staged.createdAt
        )
        guard journal.isStructurallyValid else {
            throw IdentityProfileMigrationError.invalidV2State
        }
        state.identityMutationV2 = journal
        // No external state has changed yet; a failed save leaves the old
        // identity completely untouched and usable.
        try await store.save(state)
        return try await resumeIdentityBurnUnlocked(journal)
    }

    public func sendText(to selector: String, text: String) async throws -> HeadlessSentMessage {
        await stateMutationGate.acquire()
        defer { stateMutationGate.release() }
        return try await sendTextUnlocked(to: selector, text: text)
    }

    @discardableResult
    public func retryPendingDirectDeliveries(maxCount: Int = 64) async throws -> Int {
        await stateMutationGate.acquire()
        defer { stateMutationGate.release() }
        return try await retryPendingDirectDeliveriesUnlocked(maxCount: maxCount)
    }

    /// Explicitly rearms the exact preserved ciphertext after retry exhaustion
    /// or a permanent relay rejection. No ratchet or envelope bytes change.
    public func rearmPendingDirectDelivery(envelopeId: UUID) async throws {
        await stateMutationGate.acquire()
        defer { stateMutationGate.release() }
        var state = try await loadState()
        guard let pendingIndex = state.pendingDirectDeliveries.firstIndex(where: {
            $0.id == envelopeId
        }), let intentIndex = state.protocolIntents.firstIndex(where: {
            $0.id == envelopeId
        }), let rearmed = state.protocolIntents[intentIndex].rearming(at: Date()) else {
            throw HeadlessMessagingClientError.directDeliveryRequiresAction(envelopeId)
        }
        state.protocolIntents[intentIndex] = rearmed
        state.pendingDirectDeliveries[pendingIndex].attemptCount = 0
        state.pendingDirectDeliveries[pendingIndex].lastAttemptAt = nil
        try await store.save(state)
    }

    private func retryPendingDirectDeliveriesUnlocked(maxCount: Int) async throws -> Int {
        var state = try await loadState()
        var deliveredCount = 0
        var firstActionRequired: UUID?
        var blockedConversationIds = Set<String>()
        let pendingIds = state.pendingDirectDeliveries.prefix(max(1, min(maxCount, 256))).map(\.id)
        for pendingId in pendingIds {
            guard let pendingIndex = state.pendingDirectDeliveries.firstIndex(where: { $0.id == pendingId }) else {
                continue
            }
            let pending = state.pendingDirectDeliveries[pendingIndex]
            if blockedConversationIds.contains(pending.envelope.conversationId) {
                continue
            }
            let attemptId = UUID()
            let now = Date()
            let intentIndex: Int
            if let existing = state.protocolIntents.firstIndex(where: { $0.id == pendingId }) {
                intentIndex = existing
            } else {
                let digest = Data(SHA256.hash(data: try NoctweaveCoder.encode(pending.envelope, sortedKeys: true)))
                state.protocolIntents.append(
                    .prepare(
                        id: pendingId,
                        kind: .sendEvent,
                        targetIdentifier: Data(pending.contactId.uuidString.lowercased().utf8),
                        payloadDigest: digest,
                        createdAt: pending.queuedAt
                    )
                )
                intentIndex = state.protocolIntents.count - 1
            }
            let currentIntent = state.protocolIntents[intentIndex]
            if currentIntent.state == .permanentFailure
                || currentIntent.attemptCount
                    >= UInt32(NoctweaveArchitectureV2.maximumIntentAttempts) {
                firstActionRequired = firstActionRequired ?? pendingId
                blockedConversationIds.insert(pending.envelope.conversationId)
                continue
            }
            guard let attempting = currentIntent.beginningAttempt(
                id: attemptId,
                completedIntentIds: Self.completedIntentIds(in: state),
                at: now
            ) else {
                continue
            }
            state.protocolIntents[intentIndex] = attempting
            let boundedAttemptCount = max(0, state.pendingDirectDeliveries[pendingIndex].attemptCount)
            state.pendingDirectDeliveries[pendingIndex].attemptCount = min(
                boundedAttemptCount,
                NoctweaveArchitectureV2.maximumIntentAttempts - 1
            ) + 1
            state.pendingDirectDeliveries[pendingIndex].lastAttemptAt = now
            try await store.save(state)
            do {
                _ = try await deliver(pending: pending)
                try await finalizeDirectDeliveryIntent(
                    envelopeId: pendingId,
                    attemptId: attemptId,
                    state: &state
                )
                deliveredCount += 1
            } catch {
                try await recordDirectDeliveryFailure(
                    envelopeId: pendingId,
                    attemptId: attemptId,
                    error: error,
                    state: &state
                )
                if state.protocolIntents.first(where: { $0.id == pendingId })?.state
                    == .permanentFailure {
                    firstActionRequired = firstActionRequired ?? pendingId
                    blockedConversationIds.insert(pending.envelope.conversationId)
                }
            }
        }
        if identityMutationCanBeCleared(in: state) {
            state.identityMutationV2 = nil
            try await store.save(state)
        }
        if let firstActionRequired {
            // Other conversations were still given a chance to make progress;
            // the caller now gets an explicit recovery handle for the first
            // preserved ciphertext that needs rearming or dismissal.
            throw HeadlessMessagingClientError.directDeliveryRequiresAction(firstActionRequired)
        }
        return deliveredCount
    }

    private func sendTextUnlocked(to selector: String, text: String) async throws -> HeadlessSentMessage {
        var state = try await loadState()
        let contact = try resolveContact(selector, in: state.contacts)
        try requireContinuityDeliveryReady(for: contact, state: state)
        var conversation: Conversation
        var kemCiphertext: Data?
        let eventId = UUID()
        let clientTransactionId = UUID()
        var directApplicationEvent: ConversationEvent?
        var directRelationshipBinding: PairwiseInstallationBindingV4?
        let envelope: Envelope
        if contact.usesCertifiedInstallationEndpoint {
            guard let installation = state.localInstallation else {
                throw HeadlessMessagingClientError.missingInstallation
            }
            let peerEndpoint = try contact.certifiedInstallationEndpoint()
            let selected = try directSendEndpointContext(
                contact: contact,
                peerEndpoint: peerEndpoint,
                state: &state
            )
            let senderEndpoint = selected.localEndpoint
            let binding = selected.binding
            let endpointSession = selected.endpointSession
            var prekey: PrekeyReference?
            if let existing = state.conversation(for: contact.id, endpointSession: endpointSession) {
                conversation = existing
            } else {
                let session = try MessageEngine.createOutboundInstallationSession(
                    localInstallation: installation,
                    localEndpoint: senderEndpoint,
                    pairwiseBinding: binding,
                    contact: contact
                )
                conversation = session.conversation
                kemCiphertext = session.kemCiphertext
                prekey = session.prekey
            }
            let context = try MessageAuthenticatedContext.directV4(
                eventId: eventId,
                senderEndpoint: senderEndpoint,
                recipientEndpoint: peerEndpoint,
                pairwiseBinding: binding
            )
            let eventTimestamp = Date()
            guard let content = EncodedContent.text(text) else {
                throw WirePayloadV2Error.invalidKnownApplicationContent
            }
            let event = ConversationEvent(
                id: eventId,
                clientTransactionId: clientTransactionId,
                conversationId: conversation.id,
                authorInstallationHandle: binding.localInstallationHandle,
                createdAt: eventTimestamp,
                kind: .application,
                content: content
            )
            envelope = try MessageEngine.encryptDirectV4(
                wirePayload: .application(event),
                senderSigningKey: installation.signingKey,
                senderFingerprint: binding.localInstallationHandle.rawValue,
                conversation: &conversation,
                kemCiphertext: kemCiphertext,
                prekey: prekey,
                authenticatedContext: context,
                sentAt: eventTimestamp
            )
            directApplicationEvent = event
            directRelationshipBinding = binding
        } else {
            if let existing = state.conversation(for: contact.id) {
                conversation = existing
            } else {
                let session = try MessageEngine.createOutboundSession(identity: state.identity, contact: contact)
                conversation = session.conversation
                kemCiphertext = session.kemCiphertext
            }
            envelope = try MessageEngine.encrypt(
                body: .text(text),
                senderSigningKey: state.identity.signingKey,
                senderFingerprint: state.identity.fingerprint,
                conversation: &conversation,
                kemCiphertext: kemCiphertext
            )
        }
        _ = MessageEngine.appendMessage(
            id: envelope.authenticatedContext?.directV4?.eventId ?? envelope.id,
            body: .text(text),
            direction: .sent,
            counter: envelope.messageCounter,
            timestamp: envelope.sentAt,
            conversation: &conversation
        )
        state.upsert(conversation: conversation)
        if let directApplicationEvent, let directRelationshipBinding {
            try persistDirectEvent(
                directApplicationEvent,
                contact: contact,
                binding: directRelationshipBinding,
                state: &state
            )
        }

        let attemptId = try await persistDirectDeliveryIntent(
            envelope: envelope,
            contact: contact,
            state: &state
        )
        let response: RelayResponse
        do {
            response = try await deliver(envelope: envelope, to: contact, from: state)
            try await finalizeDirectDeliveryIntent(
                envelopeId: envelope.id,
                attemptId: attemptId,
                state: &state
            )
        } catch {
            try await recordDirectDeliveryFailure(
                envelopeId: envelope.id,
                attemptId: attemptId,
                error: error,
                state: &state
            )
            throw error
        }
        return HeadlessSentMessage(
            contact: contact,
            envelopeId: envelope.id,
            messageCounter: envelope.messageCounter,
            storedCount: response.delivered?.storedCount ?? 0
        )
    }

    public func sendAttachment(
        to selector: String,
        data: Data,
        fileName: String?,
        mimeType: String = "application/octet-stream",
        chunkSize: Int = 64 * 1024,
        ttlSeconds: Int? = nil
    ) async throws -> HeadlessSentAttachment {
        await stateMutationGate.acquire()
        defer { stateMutationGate.release() }
        return try await sendAttachmentUnlocked(
            to: selector,
            data: data,
            fileName: fileName,
            mimeType: mimeType,
            chunkSize: chunkSize,
            ttlSeconds: ttlSeconds
        )
    }

    private func sendAttachmentUnlocked(
        to selector: String,
        data: Data,
        fileName: String?,
        mimeType: String,
        chunkSize: Int,
        ttlSeconds: Int?
    ) async throws -> HeadlessSentAttachment {
        var state = try await loadState()
        let contact = try resolveContact(selector, in: state.contacts)
        try requireContinuityDeliveryReady(for: contact, state: state)
        var conversation: Conversation
        var kemCiphertext: Data?
        var prekey: PrekeyReference?
        var authenticatedContext: MessageAuthenticatedContext?
        var directRelationshipBinding: PairwiseInstallationBindingV4?
        let senderSigningKey: SigningKeyPair
        let senderIdentifier: String
        let eventId = UUID()
        let clientTransactionId = UUID()
        if contact.usesCertifiedInstallationEndpoint {
            guard let installation = state.localInstallation else {
                throw HeadlessMessagingClientError.missingInstallation
            }
            let peerEndpoint = try contact.certifiedInstallationEndpoint()
            let selected = try directSendEndpointContext(
                contact: contact,
                peerEndpoint: peerEndpoint,
                state: &state
            )
            let senderEndpoint = selected.localEndpoint
            let binding = selected.binding
            let endpointSession = selected.endpointSession
            if let existing = state.conversation(for: contact.id, endpointSession: endpointSession) {
                conversation = existing
            } else {
                let session = try MessageEngine.createOutboundInstallationSession(
                    localInstallation: installation,
                    localEndpoint: senderEndpoint,
                    pairwiseBinding: binding,
                    contact: contact
                )
                conversation = session.conversation
                kemCiphertext = session.kemCiphertext
                prekey = session.prekey
            }
            authenticatedContext = try .directV4(
                eventId: eventId,
                senderEndpoint: senderEndpoint,
                recipientEndpoint: peerEndpoint,
                pairwiseBinding: binding
            )
            directRelationshipBinding = binding
            senderSigningKey = installation.signingKey
            senderIdentifier = binding.localInstallationHandle.rawValue
        } else {
            if let existing = state.conversation(for: contact.id) {
                conversation = existing
            } else {
                let session = try MessageEngine.createOutboundSession(identity: state.identity, contact: contact)
                conversation = session.conversation
                kemCiphertext = session.kemCiphertext
            }
            senderSigningKey = state.identity.signingKey
            senderIdentifier = state.identity.fingerprint
        }
        let prepared = try MessageEngine.prepareMessageKey(conversation: &conversation)
        let context = AttachmentCryptoContext(
            conversationId: conversation.id,
            sessionId: conversation.sessionId,
            messageCounter: prepared.counter
        )
        let (descriptor, chunks) = try Self.encryptAttachmentChunks(
            data: data,
            fileName: nil,
            mimeType: mimeType,
            chunkSize: chunkSize,
            messageKey: prepared.key,
            context: context,
            relayTTLSeconds: ttlSeconds
        )
        try await upload(chunks: chunks, to: contact.relay, ttlSeconds: ttlSeconds)
        let envelope: Envelope
        var directApplicationEvent: ConversationEvent?
        if let directRelationshipBinding,
           let authenticatedContext {
            let eventTimestamp = Date()
            let content = EncodedContent(
                type: .attachment,
                payload: try NoctweaveCoder.encode(descriptor, sortedKeys: true),
                fallbackText: Self.attachmentTitle(for: descriptor),
                disposition: .visible
            )
            let event = ConversationEvent(
                id: eventId,
                clientTransactionId: clientTransactionId,
                conversationId: conversation.id,
                authorInstallationHandle: directRelationshipBinding.localInstallationHandle,
                createdAt: eventTimestamp,
                kind: .application,
                content: content
            )
            envelope = try MessageEngine.encryptDirectV4(
                wirePayload: .application(event),
                senderSigningKey: senderSigningKey,
                senderFingerprint: senderIdentifier,
                conversation: conversation,
                messageCounter: prepared.counter,
                messageKey: prepared.key,
                kemCiphertext: kemCiphertext,
                prekey: prekey,
                authenticatedContext: authenticatedContext,
                sentAt: eventTimestamp
            )
            directApplicationEvent = event
        } else {
            envelope = try MessageEngine.encrypt(
                body: .attachment(descriptor),
                senderSigningKey: senderSigningKey,
                senderFingerprint: senderIdentifier,
                conversation: conversation,
                messageCounter: prepared.counter,
                messageKey: prepared.key,
                kemCiphertext: kemCiphertext,
                prekey: prekey,
                authenticatedContext: authenticatedContext
            )
        }
        _ = MessageEngine.appendMessage(
            id: envelope.authenticatedContext?.directV4?.eventId ?? envelope.id,
            body: .attachment(descriptor),
            direction: .sent,
            counter: envelope.messageCounter,
            timestamp: envelope.sentAt,
            conversation: &conversation,
            attachmentRelay: contact.relay,
            messageKey: prepared.key
        )
        state.upsert(conversation: conversation)
        if let directApplicationEvent, let directRelationshipBinding {
            try persistDirectEvent(
                directApplicationEvent,
                contact: contact,
                binding: directRelationshipBinding,
                state: &state
            )
        }
        let attemptId = try await persistDirectDeliveryIntent(
            envelope: envelope,
            contact: contact,
            state: &state
        )
        let response: RelayResponse
        do {
            response = try await deliver(envelope: envelope, to: contact, from: state)
            try await finalizeDirectDeliveryIntent(
                envelopeId: envelope.id,
                attemptId: attemptId,
                state: &state
            )
        } catch {
            try await recordDirectDeliveryFailure(
                envelopeId: envelope.id,
                attemptId: attemptId,
                error: error,
                state: &state
            )
            throw error
        }
        return HeadlessSentAttachment(
            contact: contact,
            group: nil,
            envelopeId: envelope.id,
            messageCounter: envelope.messageCounter,
            descriptor: descriptor,
            uploadedChunkCount: chunks.count,
            storedCount: response.delivered?.storedCount ?? 0
        )
    }

    public func sendVoice(
        to selector: String,
        data: Data,
        fileName: String?,
        mimeType: String = "audio/m4a",
        chunkSize: Int = 64 * 1024,
        ttlSeconds: Int? = nil
    ) async throws -> HeadlessSentAttachment {
        try await sendAttachment(
            to: selector,
            data: data,
            fileName: fileName,
            mimeType: mimeType,
            chunkSize: chunkSize,
            ttlSeconds: ttlSeconds
        )
    }

    public func sendGroupText(to selector: String, text: String) async throws -> HeadlessSentGroupMessage {
        await stateMutationGate.acquire()
        defer { stateMutationGate.release() }
        return try await sendGroupTextUnlocked(to: selector, text: text)
    }

    private func sendGroupTextUnlocked(to selector: String, text: String) async throws -> HeadlessSentGroupMessage {
        var state = try await loadState()
        try await refreshGroups(into: &state, limit: 100)
        var group = try resolveGroup(selector, in: state.groups)
        guard var ratchetState = group.groupRatchetState else {
            throw HeadlessMessagingClientError.missingGroupRatchet(group.title)
        }
        let envelope = try GroupRatchet.encrypt(
            body: .text(text),
            senderSigningKey: state.identity.signingKey,
            senderFingerprint: state.identity.fingerprint,
            state: &ratchetState
        )
        group.groupRatchetState = ratchetState
        group.messages.append(
            Message(
                direction: .sent,
                body: text,
                timestamp: envelope.sentAt,
                counter: envelope.messageCounter
            )
        )
        state.upsert(group: group)
        let response = try await relayClient(for: state.relay).send(
            .deliverGroupMessage(
                DeliverGroupMessageRequest(
                    groupId: group.id,
                    groupInboxId: try groupInboxId(for: group),
                    envelope: envelope
                )
            ),
            timeout: timeout
        )
        guard response.type == .delivered || response.type == .ok else {
            throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
        }
        try await store.save(state)
        return HeadlessSentGroupMessage(
            group: summary(for: group),
            envelopeId: envelope.id,
            messageCounter: envelope.messageCounter,
            storedCount: response.delivered?.storedCount ?? 0
        )
    }

    public func sendGroupAttachment(
        to selector: String,
        data: Data,
        fileName: String?,
        mimeType: String = "application/octet-stream",
        chunkSize: Int = 64 * 1024,
        ttlSeconds: Int? = nil
    ) async throws -> HeadlessSentAttachment {
        await stateMutationGate.acquire()
        defer { stateMutationGate.release() }
        return try await sendGroupAttachmentUnlocked(
            to: selector,
            data: data,
            fileName: fileName,
            mimeType: mimeType,
            chunkSize: chunkSize,
            ttlSeconds: ttlSeconds
        )
    }

    private func sendGroupAttachmentUnlocked(
        to selector: String,
        data: Data,
        fileName: String?,
        mimeType: String,
        chunkSize: Int,
        ttlSeconds: Int?
    ) async throws -> HeadlessSentAttachment {
        var state = try await loadState()
        try await refreshGroups(into: &state, limit: 100)
        var group = try resolveGroup(selector, in: state.groups)
        guard var ratchetState = group.groupRatchetState else {
            throw HeadlessMessagingClientError.missingGroupRatchet(group.title)
        }
        let prepared = try GroupRatchet.prepareMessageKey(
            senderFingerprint: state.identity.fingerprint,
            state: &ratchetState
        )
        let context = Self.groupAttachmentContext(
            groupId: group.id,
            epoch: ratchetState.epoch,
            transcriptHash: ratchetState.transcriptHash,
            messageCounter: prepared.counter
        )
        let (descriptor, chunks) = try Self.encryptAttachmentChunks(
            data: data,
            fileName: nil,
            mimeType: mimeType,
            chunkSize: chunkSize,
            messageKey: prepared.key,
            context: context,
            relayTTLSeconds: ttlSeconds
        )
        try await upload(chunks: chunks, to: state.relay, ttlSeconds: ttlSeconds)
        let envelope = try GroupRatchet.encrypt(
            body: .attachment(descriptor),
            senderSigningKey: state.identity.signingKey,
            senderFingerprint: state.identity.fingerprint,
            messageCounter: prepared.counter,
            messageKey: prepared.key,
            state: ratchetState
        )
        group.groupRatchetState = ratchetState
        appendGroupMessage(
            body: .attachment(descriptor),
            direction: .sent,
            senderDisplayName: nil,
            counter: envelope.messageCounter,
            timestamp: envelope.sentAt,
            group: &group,
            attachmentRelay: state.relay,
            attachmentCryptoContext: context,
            messageKey: prepared.key
        )
        state.upsert(group: group)
        let response = try await relayClient(for: state.relay).send(
            .deliverGroupMessage(
                DeliverGroupMessageRequest(
                    groupId: group.id,
                    groupInboxId: try groupInboxId(for: group),
                    envelope: envelope
                )
            ),
            timeout: timeout
        )
        guard response.type == .delivered || response.type == .ok else {
            throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
        }
        try await store.save(state)
        return HeadlessSentAttachment(
            contact: nil,
            group: summary(for: group),
            envelopeId: envelope.id,
            messageCounter: envelope.messageCounter,
            descriptor: descriptor,
            uploadedChunkCount: chunks.count,
            storedCount: response.delivered?.storedCount ?? 0
        )
    }

    public func sendGroupVoice(
        to selector: String,
        data: Data,
        fileName: String?,
        mimeType: String = "audio/m4a",
        chunkSize: Int = 64 * 1024,
        ttlSeconds: Int? = nil
    ) async throws -> HeadlessSentAttachment {
        try await sendGroupAttachment(
            to: selector,
            data: data,
            fileName: fileName,
            mimeType: mimeType,
            chunkSize: chunkSize,
            ttlSeconds: ttlSeconds
        )
    }

    public func fetchAttachment(id: UUID) async throws -> HeadlessFetchedAttachment {
        let state = try await loadState()
        let info = try attachmentInfo(id: id, in: state)
        guard let messageKeyData = info.messageKeyData,
              let context = info.cryptoContext else {
            throw HeadlessMessagingClientError.missingAttachmentKey(id.uuidString)
        }
        guard info.descriptor.isStructurallyValid() else {
            throw HeadlessMessagingClientError.invalidAttachmentDescriptor
        }
        let relay = info.relay ?? state.relay
        let messageKey = AttachmentCrypto.key(from: messageKeyData)
        var recovered = Data()
        recovered.reserveCapacity(info.descriptor.byteCount)
        do {
            for chunkIndex in 0..<info.descriptor.chunkCount {
                let response = try await relayClient(for: relay).send(
                    .fetchAttachment(FetchAttachmentRequest(attachmentId: id, chunkIndex: chunkIndex)),
                    timeout: timeout
                )
                guard response.type == .attachment, let chunk = response.attachment else {
                    throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
                }
                let byteCount = Self.attachmentChunkPlaintextSize(
                    descriptor: info.descriptor,
                    chunkIndex: chunkIndex
                )
                let aad = AttachmentCrypto.authenticatedData(
                    conversationId: context.conversationId,
                    sessionId: context.sessionId,
                    messageCounter: context.messageCounter,
                    attachmentId: id,
                    chunkIndex: chunkIndex,
                    byteCount: byteCount
                )
                var plaintext = try AttachmentCrypto.decryptChunk(
                    payload: chunk.payload,
                    messageKey: messageKey,
                    attachmentId: id,
                    chunkIndex: chunkIndex,
                    authenticatedData: aad
                )
                recovered.append(plaintext)
                plaintext.secureWipe()
            }
            guard recovered.count == info.descriptor.byteCount,
                  AttachmentCrypto.sha256(recovered) == info.descriptor.sha256 else {
                throw HeadlessMessagingClientError.attachmentDigestMismatch(id.uuidString)
            }
            return HeadlessFetchedAttachment(descriptor: info.descriptor, data: recovered)
        } catch {
            recovered.secureWipe()
            throw error
        }
    }

    public func receiveGroupMessages(
        group selector: String? = nil,
        maxCount: Int = 25,
        longPollTimeoutSeconds: Int? = nil,
        acknowledge: Bool = true
    ) async throws -> [HeadlessReceivedGroupMessage] {
        await stateMutationGate.acquire()
        defer { stateMutationGate.release() }
        return try await receiveGroupMessagesUnlocked(
            group: selector,
            maxCount: maxCount,
            longPollTimeoutSeconds: longPollTimeoutSeconds,
            acknowledge: acknowledge
        )
    }

    private func receiveGroupMessagesUnlocked(
        group selector: String?,
        maxCount: Int,
        longPollTimeoutSeconds: Int?,
        acknowledge: Bool
    ) async throws -> [HeadlessReceivedGroupMessage] {
        var state = try await loadState()
        try await refreshGroups(into: &state, limit: 100)
        let targetGroups: [GroupConversation]
        if let selector {
            targetGroups = [try resolveGroup(selector, in: state.groups)]
        } else {
            targetGroups = state.groups
        }

        var received: [HeadlessReceivedGroupMessage] = []
        for var group in targetGroups {
            if acknowledge, !group.pendingAcknowledgements.isEmpty {
                try await flushPendingGroupAcknowledgements(group: &group, state: &state)
            }
            let inboxId = try groupInboxId(for: group)
            var request = FetchGroupMessagesRequest(
                groupId: group.id,
                groupInboxId: inboxId,
                maxCount: max(1, maxCount),
                longPollTimeoutSeconds: longPollTimeoutSeconds,
                actorFingerprint: state.identity.fingerprint
            )
            let proof = try Self.makeActorProof(signingKey: state.identity.signingKey) { actorProof in
                try request.signableData(for: actorProof)
            }
            request = FetchGroupMessagesRequest(
                groupId: request.groupId,
                groupInboxId: request.groupInboxId,
                maxCount: request.maxCount,
                longPollTimeoutSeconds: request.longPollTimeoutSeconds,
                actorFingerprint: request.actorFingerprint,
                actorProof: proof
            )
            let response = try await relayClient(for: state.relay).send(
                .fetchGroupMessages(request),
                timeout: timeout + TimeInterval(longPollTimeoutSeconds ?? 0)
            )
            guard response.type == .groupMessages else {
                if response.type == .ok {
                    continue
                }
                throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
            }
            var stagedGroup = group
            var envelopesToProcess: [GroupRatchetEnvelope] = []
            for envelope in response.groupMessages ?? [] {
                let digest = try Self.groupEnvelopeDigest(envelope)
                switch stagedGroup.recordPendingAcknowledgement(
                    envelopeId: envelope.id,
                    envelopeDigest: digest
                ) {
                case .inserted:
                    envelopesToProcess.append(envelope)
                case .alreadyPending:
                    continue
                case .conflictingEnvelope:
                    throw HeadlessMessagingClientError.legacyGroupAcknowledgementConflict(envelope.id)
                case .capacityExceeded:
                    throw HeadlessMessagingClientError.legacyGroupAcknowledgementBackpressure(
                        group.title,
                        GroupConversation.maximumPendingAcknowledgements
                    )
                }
            }
            group.pendingAcknowledgements = stagedGroup.pendingAcknowledgements
            for envelope in envelopesToProcess {
                guard var ratchetState = group.groupRatchetState else {
                    throw HeadlessMessagingClientError.missingGroupRatchet(group.title)
                }
                let sender = senderContact(for: envelope.senderFingerprint, in: state.contacts)
                let senderProfile = group.memberProfiles.first { $0.fingerprint == envelope.senderFingerprint }
                guard let senderKey = sender?.signingPublicKey
                    ?? groupMemberSigningKey(for: envelope.senderFingerprint, group: group, state: state) else {
                    throw HeadlessMessagingClientError.missingGroupSenderKey(envelope.senderFingerprint)
                }
                let decrypted = try GroupRatchet.decryptWithKey(
                    envelope: envelope,
                    senderPublicSigningKey: senderKey,
                    state: &ratchetState
                )
                let body = decrypted.body
                group.groupRatchetState = ratchetState
                appendGroupMessage(
                    body: body,
                    direction: .received,
                    senderDisplayName: sender?.displayName ?? senderProfile?.displayName,
                    counter: envelope.messageCounter,
                    timestamp: envelope.sentAt,
                    group: &group,
                    attachmentRelay: state.relay,
                    attachmentCryptoContext: Self.groupAttachmentContext(
                        groupId: envelope.groupId,
                        epoch: envelope.epoch,
                        transcriptHash: envelope.transcriptHash,
                        messageCounter: envelope.messageCounter
                    ),
                    messageKey: decrypted.messageKey
                )
                received.append(
                    HeadlessReceivedGroupMessage(
                        group: summary(for: group),
                        envelopeId: envelope.id,
                        messageCounter: envelope.messageCounter,
                        senderFingerprint: envelope.senderFingerprint,
                        senderDisplayName: sender?.displayName ?? senderProfile?.displayName,
                        body: body,
                        sentAt: envelope.sentAt
                    )
                )
            }
            state.upsert(group: group)
            // A relay acknowledgement is destructive in the legacy group path.
            // Persist the advanced ratchet, message, and receipt before releasing it.
            try await store.save(state)
            if acknowledge, !group.pendingAcknowledgements.isEmpty {
                try await flushPendingGroupAcknowledgements(group: &group, state: &state)
            }
        }
        try await store.save(state)
        return received
    }

    public func receive(maxCount: Int = 25, longPollTimeoutSeconds: Int? = nil, acknowledge: Bool = true) async throws -> [HeadlessReceivedMessage] {
        await stateMutationGate.acquire()
        defer { stateMutationGate.release() }
        return try await receiveUnlocked(
            maxCount: maxCount,
            longPollTimeoutSeconds: longPollTimeoutSeconds,
            acknowledge: acknowledge
        )
    }

    private func receiveUnlocked(
        maxCount: Int,
        longPollTimeoutSeconds: Int?,
        acknowledge: Bool
    ) async throws -> [HeadlessReceivedMessage] {
        var state = try await loadState()
        let accessKey = try inboxAccessKey(from: state)
        let mailbox = try await ensureMailboxConsumer(state: &state, accessKey: accessKey)
        if let pending = state.localInstallation?.pendingMailboxCommitsByStream[mailbox.routeKey] {
            try await finalizeMailboxCursorCommit(
                pending,
                state: &state,
                consumerId: mailbox.consumerId,
                routeKey: mailbox.routeKey
            )
        }
        let committedCursor = state.localInstallation?.cursorsByStream[mailbox.routeKey]
        var sync = SyncMailboxRequest(
            inboxId: state.inboxId,
            consumerId: mailbox.consumerId,
            cursor: committedCursor,
            maxCount: max(1, maxCount),
            longPollTimeoutSeconds: longPollTimeoutSeconds
        )
        let proof = try Self.makeActorProof(signingKey: mailbox.consumerKey) { actorProof in
            try sync.signableData(for: actorProof)
        }
        sync = SyncMailboxRequest(
            inboxId: state.inboxId,
            consumerId: mailbox.consumerId,
            cursor: committedCursor,
            maxCount: max(1, maxCount),
            longPollTimeoutSeconds: longPollTimeoutSeconds,
            consumerProof: proof
        )
        let response = try await relayClient(for: state.relay).send(
            .syncMailbox(sync),
            timeout: timeout + TimeInterval(longPollTimeoutSeconds ?? 0)
        )
        guard response.type == .mailboxSync,
              let batch = response.mailboxSync,
              batch.isStructurallyValid else {
            throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
        }
        guard let committedSequence = state.localInstallation?
                .committedSequencesByStream[mailbox.routeKey],
              batch.isContiguous(after: committedSequence) else {
            throw HeadlessMessagingClientError.relayRejected(
                "Mailbox sync response contains a sequence gap"
            )
        }

        var received: [HeadlessReceivedMessage] = []
        for sequenced in batch.events {
            let envelope = sequenced.envelope
            do {
            if envelope.authenticatedContext?.purpose == .directV4 {
                if let message = try receiveCertifiedDirectEnvelope(envelope, state: &state) {
                    received.append(message)
                }
                continue
            }
            guard var contact = state.contact(for: envelope.senderFingerprint) else {
                throw HeadlessMessagingClientError.contactNotFound(envelope.senderFingerprint)
            }
            guard !contact.usesCertifiedInstallationEndpoint else {
                // A certified relationship is pinned to the direct-v4 typed
                // profile. Identity-fingerprint/NPAD-v1 delivery is not a
                // compatibility fallback for that same contact.
                throw HeadlessMessagingClientError.unsupportedInboundSession
            }
            var conversation: Conversation
            let previousConversation = state.conversation(for: contact.id)
            if let existing = state.conversation(for: contact.id) {
                conversation = existing
            } else if let kemCiphertext = envelope.kemCiphertext {
                conversation = try MessageEngine.createInboundSession(
                    identity: state.identity,
                    contact: contact,
                    kemCiphertext: kemCiphertext
                )
            } else {
                throw HeadlessMessagingClientError.unsupportedInboundSession
            }
            // Verify attribution before consulting the replay cache. A forged
            // envelope must not be able to claim a known logical ID and turn
            // the conflict detector into a cursor-stalling oracle.
            guard envelope.verifySignature(publicSigningKey: contact.signingPublicKey) else {
                throw CryptoError.invalidSignature
            }
            // Envelope IDs are signed in architecture v2 and are the sole
            // logical delivery idempotency key. Counters restart with a fresh
            // session, so counter+timestamp heuristics can discard valid
            // rotation/reset messages.
            guard let inboundDigest = try Self.unseenInboundEnvelopeDigest(
                envelope,
                sourceScopeId: contact.id,
                logicalEventId: envelope.id,
                state: state
            ) else {
                continue
            }
            if conversation.messages.contains(where: { $0.id == envelope.id }) {
                throw HeadlessMessagingClientError.inboundEnvelopeConflict(envelope.id)
            }
            let decrypted: (body: MessageBody, messageKey: SymmetricKey)
            do {
                decrypted = try MessageEngine.decryptWithKey(envelope: envelope, contact: contact, conversation: &conversation)
            } catch {
                guard let kemCiphertext = envelope.kemCiphertext else {
                    throw error
                }
                conversation = try MessageEngine.createInboundSession(
                    identity: state.identity,
                    contact: contact,
                    kemCiphertext: kemCiphertext
                )
                decrypted = try MessageEngine.decryptWithKey(envelope: envelope, contact: contact, conversation: &conversation)
                if let previousConversation {
                    conversation.messages = previousConversation.messages
                    conversation.unreadCount = previousConversation.unreadCount
                }
            }
            let body = decrypted.body
            Self.recordInboundEnvelopeReceipt(
                envelope,
                sourceScopeId: contact.id,
                logicalEventId: envelope.id,
                digest: inboundDigest,
                state: &state
            )
            _ = MessageEngine.appendMessage(
                id: envelope.id,
                body: body,
                direction: .received,
                counter: envelope.messageCounter,
                timestamp: envelope.sentAt,
                conversation: &conversation,
                attachmentRelay: state.relay,
                messageKey: decrypted.messageKey
            )
            conversation.markMessageProcessed()
            switch body {
            case .identityRotation(let rotation):
                let previousFingerprint = contact.fingerprint
                if contact.apply(rotation: rotation) {
                    state.updateContact(contact)
                    state.appendContinuityEvent(
                        ContinuityEvent(
                            kind: .contactRotationReceived,
                            contactId: contact.id,
                            contactDisplayName: contact.displayName,
                            oldFingerprint: previousFingerprint,
                            newFingerprint: contact.fingerprint
                        )
                    )
                }
            case .identityReset(let reset):
                let previousFingerprint = contact.fingerprint
                if contact.apply(reset: reset) {
                    state.updateContact(contact)
                    state.appendContinuityEvent(
                        ContinuityEvent(
                            kind: .contactResetReceived,
                            contactId: contact.id,
                            contactDisplayName: contact.displayName,
                            oldFingerprint: previousFingerprint,
                            newFingerprint: contact.fingerprint
                        )
                    )
                }
            case .text, .attachment, .sessionReset, .resendRequest:
                break
            }
            state.upsert(conversation: conversation)
            received.append(
                HeadlessReceivedMessage(
                    contact: contact,
                    envelopeId: envelope.id,
                    messageCounter: envelope.messageCounter,
                    body: body,
                    sentAt: envelope.sentAt
                )
            )
            } catch {
                guard let reason = Self.transportQuarantineReason(for: error) else {
                    // Local state corruption, storage/runtime failure, and
                    // unavailable cryptographic primitives remain retryable
                    // failures and must not advance the cursor.
                    throw error
                }
                try Self.recordTransportQuarantine(
                    sequenced,
                    routeKey: mailbox.routeKey,
                    reason: reason,
                    state: &state
                )
            }
        }

        if acknowledge, !batch.events.isEmpty {
            guard var installation = state.localInstallation else {
                throw HeadlessMessagingClientError.missingInstallation
            }
            let pending = PendingMailboxCursorCommit(
                cursor: batch.nextCursor,
                sequence: batch.nextSequence
            )
            installation.pendingMailboxCommitsByStream[mailbox.routeKey] = pending
            state.localInstallation = installation
            try await store.save(state)
            try await finalizeMailboxCursorCommit(
                pending,
                state: &state,
                consumerId: mailbox.consumerId,
                routeKey: mailbox.routeKey
            )
        } else {
            try await store.save(state)
        }
        return received
    }

    private func receiveCertifiedDirectEnvelope(
        _ envelope: Envelope,
        state: inout ClientState
    ) throws -> HeadlessReceivedMessage? {
        guard let direct = envelope.authenticatedContext?.directV4,
              let resolved = state.resolveCertifiedDirectContext(direct),
              let installation = state.localInstallation,
              let localManifest = state.installationManifest else {
            throw HeadlessMessagingClientError.unsupportedInboundSession
        }
        var contact = resolved.contact
        let peerEndpoint = try contact.certifiedInstallationEndpoint()
        let endpointSession = DirectEndpointSessionIdentity(
            contactId: contact.id,
            localInstallationId: installation.id,
            localInstallationHandle: resolved.binding.localInstallationHandle,
            localCertificateReferenceDigest: resolved.binding.localCertificateReferenceDigest,
            localManifestEpoch: resolved.localEndpoint.manifestEpoch,
            peerInstallationId: peerEndpoint.installationId,
            peerInstallationHandle: resolved.binding.peerInstallationHandle,
            peerCertificateReferenceDigest: resolved.binding.peerCertificateReferenceDigest,
            peerManifestEpoch: peerEndpoint.manifestEpoch
        )
        let previousConversation = state.conversation(
            for: contact.id,
            endpointSession: endpointSession
        )
        var conversation: Conversation
        if let previousConversation {
            conversation = previousConversation
        } else if let kemCiphertext = envelope.kemCiphertext {
            conversation = try MessageEngine.createInboundInstallationSession(
                localInstallation: installation,
                localEndpoint: resolved.localEndpoint,
                senderEndpoint: peerEndpoint,
                pairwiseBinding: resolved.binding,
                contact: contact,
                kemCiphertext: kemCiphertext,
                prekey: envelope.prekey
            )
        } else {
            throw HeadlessMessagingClientError.unsupportedInboundSession
        }
        // The direct-v4 context is useful for routing, but it is not trusted
        // until the certified installation signature has been verified.
        guard envelope.verifySignature(publicSigningKey: peerEndpoint.signingPublicKey) else {
            throw CryptoError.invalidSignature
        }
        guard let inboundDigest = try Self.unseenInboundEnvelopeDigest(
            envelope,
            sourceScopeId: contact.id,
            logicalEventId: direct.eventId,
            state: state
        ) else {
            return nil
        }
        if conversation.messages.contains(where: { $0.id == direct.eventId })
            || state.relationshipsV2.contains(where: { relationship in
                relationship.contactId == contact.id
                    && relationship.events.contains(where: { $0.id == direct.eventId })
            })
            || state.quarantinedControlEvents.contains(where: { $0.id == direct.eventId }) {
            throw HeadlessMessagingClientError.inboundEnvelopeConflict(direct.eventId)
        }
        let decrypted: DirectV4DecryptionResultV2
        do {
            decrypted = try MessageEngine.decryptDirectV4Payload(
                envelope: envelope,
                contact: contact,
                localIdentity: state.identity,
                localInstallation: installation,
                localManifest: localManifest,
                localEndpoint: resolved.localEndpoint,
                pairwiseBinding: resolved.binding,
                conversation: &conversation
            )
        } catch {
            guard let kemCiphertext = envelope.kemCiphertext else { throw error }
            conversation = try MessageEngine.createInboundInstallationSession(
                localInstallation: installation,
                localEndpoint: resolved.localEndpoint,
                senderEndpoint: peerEndpoint,
                pairwiseBinding: resolved.binding,
                contact: contact,
                kemCiphertext: kemCiphertext,
                prekey: envelope.prekey
            )
            decrypted = try MessageEngine.decryptDirectV4Payload(
                envelope: envelope,
                contact: contact,
                localIdentity: state.identity,
                localInstallation: installation,
                localManifest: localManifest,
                localEndpoint: resolved.localEndpoint,
                pairwiseBinding: resolved.binding,
                conversation: &conversation
            )
            if let previousConversation {
                conversation.messages = previousConversation.messages
                conversation.unreadCount = previousConversation.unreadCount
            }
        }
        Self.recordInboundEnvelopeReceipt(
            envelope,
            sourceScopeId: contact.id,
            logicalEventId: direct.eventId,
            digest: inboundDigest,
            state: &state
        )
        let body: MessageBody
        switch decrypted.disposition {
        case .application(let event, let projection):
            try persistDirectEvent(
                event,
                contact: contact,
                binding: resolved.binding,
                state: &state
            )
            guard let visibleBody = projection.body else {
                conversation.markMessageProcessed()
                state.upsert(conversation: conversation)
                return nil
            }
            body = visibleBody
        case .control(let control, let auditEvent):
            try persistDirectEvent(
                auditEvent,
                contact: contact,
                binding: resolved.binding,
                state: &state
            )
            body = control.body
        case .quarantinedControl(let quarantined):
            state.quarantinedControlEvents.append(quarantined)
            state.quarantinedControlEvents = Array(
                state.quarantinedControlEvents.suffix(
                    NoctweaveArchitectureV2.maximumQuarantinedControlEvents
                )
            )
            conversation.markMessageProcessed()
            state.upsert(conversation: conversation)
            return nil
        }
        _ = MessageEngine.appendMessage(
            id: direct.eventId,
            body: body,
            direction: .received,
            counter: envelope.messageCounter,
            timestamp: envelope.sentAt,
            conversation: &conversation,
            attachmentRelay: state.relay,
            messageKey: decrypted.messageKey
        )
        conversation.markMessageProcessed()
        switch body {
        case .identityRotation(let rotation):
            let previousFingerprint = contact.fingerprint
            if contact.apply(rotation: rotation) {
                state.updateContact(contact)
                state.appendContinuityEvent(
                    ContinuityEvent(
                        kind: .contactRotationReceived,
                        contactId: contact.id,
                        contactDisplayName: contact.displayName,
                        oldFingerprint: previousFingerprint,
                        newFingerprint: contact.fingerprint
                    )
                )
            }
        case .identityReset(let reset):
            let previousFingerprint = contact.fingerprint
            if contact.apply(reset: reset) {
                state.updateContact(contact)
                state.appendContinuityEvent(
                    ContinuityEvent(
                        kind: .contactResetReceived,
                        contactId: contact.id,
                        contactDisplayName: contact.displayName,
                        oldFingerprint: previousFingerprint,
                        newFingerprint: contact.fingerprint
                    )
                )
            }
        case .text, .attachment, .sessionReset, .resendRequest:
            break
        }
        state.upsert(conversation: conversation)
        return HeadlessReceivedMessage(
            contact: contact,
            envelopeId: envelope.id,
            messageCounter: envelope.messageCounter,
            body: body,
            sentAt: envelope.sentAt
        )
    }

    private func persistDirectEvent(
        _ event: ConversationEvent,
        contact: Contact,
        binding: PairwiseInstallationBindingV4,
        state: inout ClientState
    ) throws {
        guard event.isStructurallyValid else {
            throw WirePayloadV2Error.invalidApplicationEvent
        }
        if let index = state.relationshipsV2.firstIndex(where: {
            $0.id == binding.relationshipId && $0.contactId == contact.id
        }) {
            guard state.localInstallation?.relationshipHandles[binding.relationshipId]
                    == binding.localInstallationHandle else {
                throw IdentityProfileMigrationError.invalidV2State
            }
            _ = state.relationshipsV2[index].includeConversationIds([event.conversationId])
            guard state.relationshipsV2[index].appendEvent(event) else {
                throw IdentityProfileMigrationError.invalidV2State
            }
            return
        }

        // A local migration or burn may leave an empty backfill shell. Rebind
        // only such a shell; a peer burn starts a new generation-scoped
        // relationship beside the retained historical relationship below.
        if let shellIndex = state.relationshipsV2.firstIndex(where: {
            $0.contactId == contact.id
                && $0.events.isEmpty
                && $0.routeSets.isEmpty
                && $0.eventCheckpoint == nil
        }) {
            let shell = state.relationshipsV2[shellIndex]
            guard !state.relationshipsV2.contains(where: {
                      $0.id == binding.relationshipId && $0.contactId != contact.id
                  }),
                  var installation = state.localInstallation,
                  installation.relationshipHandles[shell.id]
                    == shell.localInstallationHandle else {
                throw IdentityProfileMigrationError.invalidV2State
            }
            let rebound = RelationshipStateV2(
                id: binding.relationshipId,
                contactId: contact.id,
                localInstallationHandle: binding.localInstallationHandle,
                conversationIds: shell.conversationIds + [event.conversationId],
                events: [event],
                createdAt: shell.createdAt
            )
            guard rebound.isStructurallyValid,
                  installation.relationshipHandles[binding.relationshipId]
                    .map({ $0 == binding.localInstallationHandle }) ?? true else {
                throw IdentityProfileMigrationError.invalidV2State
            }
            installation.relationshipHandles.removeValue(forKey: shell.id)
            installation.relationshipHandles[binding.relationshipId]
                = binding.localInstallationHandle
            state.relationshipsV2[shellIndex] = rebound
            state.relationshipsV2.sort { $0.id.uuidString < $1.id.uuidString }
            state.localInstallation = installation
            return
        }

        let relationship = RelationshipStateV2(
            id: binding.relationshipId,
            contactId: contact.id,
            localInstallationHandle: binding.localInstallationHandle,
            conversationIds: [event.conversationId],
            events: [event]
        )
        guard relationship.isStructurallyValid,
              state.relationshipsV2.count < 4_096,
              !state.relationshipsV2.contains(where: { $0.id == binding.relationshipId }) else {
            throw IdentityProfileMigrationError.invalidV2State
        }
        guard var installation = state.localInstallation,
              installation.relationshipHandles[binding.relationshipId]
                .map({ $0 == binding.localInstallationHandle }) ?? true else {
            throw IdentityProfileMigrationError.invalidV2State
        }
        installation.relationshipHandles[binding.relationshipId]
            = binding.localInstallationHandle
        state.relationshipsV2.append(relationship)
        state.relationshipsV2.sort { $0.id.uuidString < $1.id.uuidString }
        state.localInstallation = installation
    }

    private func refreshGroups(into state: inout ClientState, limit: Int) async throws {
        var request = ListGroupsRequest(
            memberFingerprint: state.identity.fingerprint,
            limit: max(1, limit)
        )
        let proof = try Self.makeActorProof(signingKey: state.identity.signingKey) { actorProof in
            try request.signableData(for: actorProof)
        }
        request = ListGroupsRequest(
            memberFingerprint: request.memberFingerprint,
            limit: request.limit,
            memberProof: proof
        )
        let response = try await relayClient(for: state.relay).send(.listGroups(request), timeout: timeout)
        guard response.type == .groups else {
            throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
        }
        for descriptor in response.groups ?? [] {
            let contacts = state.contacts.filter { contact in
                descriptor.members.contains { $0.fingerprint == contact.fingerprint }
            }
            let existing = state.group(for: descriptor.id)
            let group = try groupConversation(from: descriptor, contacts: contacts, state: state, existing: existing)
            state.upsert(group: group)
        }
    }

    private func groupConversation(
        from descriptor: RelayGroupDescriptor,
        contacts: [Contact],
        state: ClientState,
        existing: GroupConversation?
    ) throws -> GroupConversation {
        let ratchetState = GroupRatchetRecovery.state(
            from: descriptor,
            identity: state.identity,
            existing: existing?.groupRatchetState
        )
        var group = GroupConversation(
            id: descriptor.id,
            title: descriptor.title,
            memberContactIds: contacts.map(\.id),
            relayInboxId: descriptor.inboxId,
            relayEpoch: descriptor.epoch,
            relayTranscriptHash: descriptor.mlsEpochState.confirmedTranscriptHash,
            groupRatchetState: ratchetState,
            createdByFingerprint: descriptor.createdByFingerprint,
            memberProfiles: groupMemberProfiles(from: descriptor, preferredRelay: state.relay),
            scopedIdentity: existing?.scopedIdentity,
            isPendingInvitation: existing?.isPendingInvitation ?? false,
            messages: existing?.messages ?? [],
            unreadCount: existing?.unreadCount ?? 0,
            createdAt: existing?.createdAt ?? descriptor.createdAt
        )
        group.pendingAcknowledgements = existing?.pendingAcknowledgements ?? []
        return group
    }

    private static func groupEnvelopeDigest(_ envelope: GroupRatchetEnvelope) throws -> Data {
        Data(SHA256.hash(data: try NoctweaveCoder.encode(envelope, sortedKeys: true)))
    }

    private static func transportQuarantineReason(
        for error: Error
    ) -> TransportQuarantineReasonV2? {
        if let clientError = error as? HeadlessMessagingClientError {
            switch clientError {
            case .contactNotFound:
                return .unknownSender
            case .unsupportedInboundSession:
                return .incompatibleProfile
            case .inboundEnvelopeConflict:
                return .replayConflict
            default:
                return nil
            }
        }
        if let cryptoError = error as? CryptoError {
            switch cryptoError {
            case .invalidSignature, .invalidPublicKey:
                return .invalidAttribution
            case .invalidPayload, .counterOutOfOrder, .counterReplay, .counterWindowExceeded:
                return .invalidCiphertext
            case .invalidPrivateKey, .algorithmUnavailable, .operationFailed:
                return nil
            }
        }
        if error is WirePayloadV2Error || error is DecodingError {
            return .unsupportedPayload
        }
        return nil
    }

    private static func recordTransportQuarantine(
        _ sequenced: SequencedEnvelope,
        routeKey: String,
        reason: TransportQuarantineReasonV2,
        state: inout ClientState
    ) throws {
        let streamDigest = Data(SHA256.hash(data: Data(routeKey.utf8)))
        let envelopeDigest = Data(
            SHA256.hash(
                data: try NoctweaveCoder.encode(sequenced.envelope, sortedKeys: true)
            )
        )
        if let existing = state.quarantinedTransportEnvelopesV2.first(where: {
            $0.streamDigest == streamDigest && $0.sequence == sequenced.sequence
        }) {
            guard existing.envelopeId == sequenced.envelope.id,
                  existing.envelopeDigest == envelopeDigest,
                  existing.reason == reason else {
                throw HeadlessMessagingClientError.inboundEnvelopeConflict(
                    sequenced.envelope.id
                )
            }
            return
        }
        if state.quarantinedTransportEnvelopesV2.count
            >= NoctweaveArchitectureV2.maximumQuarantinedTransportEnvelopes {
            state.quarantinedTransportEnvelopesV2.removeFirst(
                NoctweaveArchitectureV2.maximumQuarantinedTransportEnvelopes / 8
            )
        }
        state.quarantinedTransportEnvelopesV2.append(
            QuarantinedTransportEnvelopeV2(
                streamDigest: streamDigest,
                sequence: sequenced.sequence,
                envelopeId: sequenced.envelope.id,
                envelopeDigest: envelopeDigest,
                reason: reason
            )
        )
    }

    /// Returns the canonical digest for a new envelope, `nil` for an exact
    /// already-verified replay, and fails closed for any logical-ID or
    /// envelope-ID reuse with different signed bytes.
    private static func unseenInboundEnvelopeDigest(
        _ envelope: Envelope,
        sourceScopeId: UUID,
        logicalEventId: UUID,
        state: ClientState
    ) throws -> Data? {
        let digest = Data(
            SHA256.hash(data: try NoctweaveCoder.encode(envelope, sortedKeys: true))
        )
        guard let existing = state.inboundEnvelopeReceiptsV2.first(where: {
            $0.isReplayCandidate(
                sourceScopeId: sourceScopeId,
                logicalEventId: logicalEventId,
                envelopeId: envelope.id
            )
        }) else {
            return digest
        }
        guard existing.isExactReplay(
            sourceScopeId: sourceScopeId,
            logicalEventId: logicalEventId,
            envelopeId: envelope.id,
            envelopeDigest: digest
        ) else {
            throw HeadlessMessagingClientError.inboundEnvelopeConflict(logicalEventId)
        }
        return nil
    }

    private static func recordInboundEnvelopeReceipt(
        _ envelope: Envelope,
        sourceScopeId: UUID,
        logicalEventId: UUID,
        digest: Data,
        state: inout ClientState
    ) {
        if state.inboundEnvelopeReceiptsV2.count
            >= NoctweaveArchitectureV2.maximumInboundEnvelopeReceipts {
            // This is a verification cache, not recoverable protocol state.
            // An evicted ancient replay is processed through the ratchet and
            // fails authentication instead of being skipped by ID alone.
            state.inboundEnvelopeReceiptsV2.removeFirst(
                NoctweaveArchitectureV2.maximumInboundEnvelopeReceipts / 8
            )
        }
        state.inboundEnvelopeReceiptsV2.append(
            InboundEnvelopeReceiptV2(
                sourceScopeId: sourceScopeId,
                logicalEventId: logicalEventId,
                envelopeId: envelope.id,
                envelopeDigest: digest
            )
        )
    }

    private func flushPendingGroupAcknowledgements(
        group: inout GroupConversation,
        state: inout ClientState
    ) async throws {
        let ids = group.pendingAcknowledgements.map(\.envelopeId)
        guard !ids.isEmpty else { return }
        try await acknowledgeGroupMessages(ids, group: group, state: state)
        group.clearPendingAcknowledgements(Set(ids))
        state.upsert(group: group)
        // If this save fails, the durable receipt remains and the idempotent relay
        // acknowledgement is retried after restart before any ratchet replay.
        try await store.save(state)
    }

    private func acknowledgeGroupMessages(_ ids: [UUID], group: GroupConversation, state: ClientState) async throws {
        var request = AcknowledgeGroupMessagesRequest(
            groupId: group.id,
            groupInboxId: try groupInboxId(for: group),
            messageIds: ids,
            actorFingerprint: state.identity.fingerprint
        )
        let proof = try Self.makeActorProof(signingKey: state.identity.signingKey) { actorProof in
            try request.signableData(for: actorProof)
        }
        request = AcknowledgeGroupMessagesRequest(
            groupId: request.groupId,
            groupInboxId: request.groupInboxId,
            messageIds: request.messageIds,
            actorFingerprint: request.actorFingerprint,
            actorProof: proof
        )
        let response = try await relayClient(for: state.relay).send(.acknowledgeGroupMessages(request), timeout: timeout)
        try requireOK(response)
    }

    private func importContactOffer(_ offer: ContactOffer) async throws -> Contact {
        var state = try await loadState()
        let contact = try MessageEngine.contact(from: offer)
        state.upsert(contact: contact)
        if let peerEndpoint = contact.preferredInstallationEndpoint {
            let localEndpoint = try localEndpoint(state: &state)
            let binding = try pairwiseBinding(
                localEndpoint: localEndpoint,
                contact: contact,
                peerEndpoint: peerEndpoint
            )
            if let existing = state.relationshipsV2.first(where: {
                $0.id == binding.relationshipId && $0.contactId == contact.id
            }) {
                guard existing.localInstallationHandle == binding.localInstallationHandle,
                      state.localInstallation?.relationshipHandles[binding.relationshipId]
                        == binding.localInstallationHandle else {
                    throw HeadlessMessagingClientError.relayRejected(
                        "Certified contact relationship does not match existing state"
                    )
                }
            } else {
                guard var installation = state.localInstallation,
                      !state.relationshipsV2.contains(where: {
                          $0.id == binding.relationshipId && $0.contactId != contact.id
                      }) else {
                    throw HeadlessMessagingClientError.missingInstallation
                }
                if let shellIndex = state.relationshipsV2.firstIndex(where: {
                    $0.contactId == contact.id
                        && $0.events.isEmpty
                        && $0.routeSets.isEmpty
                        && $0.eventCheckpoint == nil
                }) {
                    let shell = state.relationshipsV2[shellIndex]
                    guard installation.relationshipHandles[shell.id]
                            == shell.localInstallationHandle,
                          installation.relationshipHandles[binding.relationshipId]
                            .map({ $0 == binding.localInstallationHandle }) ?? true else {
                        throw HeadlessMessagingClientError.missingInstallation
                    }
                    let rebound = RelationshipStateV2(
                        id: binding.relationshipId,
                        contactId: contact.id,
                        localInstallationHandle: binding.localInstallationHandle,
                        conversationIds: shell.conversationIds,
                        createdAt: shell.createdAt
                    )
                    guard rebound.isStructurallyValid else {
                        throw HeadlessMessagingClientError.missingInstallation
                    }
                    installation.relationshipHandles.removeValue(forKey: shell.id)
                    installation.relationshipHandles[binding.relationshipId]
                        = binding.localInstallationHandle
                    state.relationshipsV2[shellIndex] = rebound
                } else {
                    guard state.relationshipsV2.count < 4_096,
                          installation.relationshipHandles[binding.relationshipId] == nil else {
                        throw HeadlessMessagingClientError.missingInstallation
                    }
                    installation.relationshipHandles[binding.relationshipId]
                        = binding.localInstallationHandle
                    state.relationshipsV2.append(
                        RelationshipStateV2(
                            id: binding.relationshipId,
                            contactId: contact.id,
                            localInstallationHandle: binding.localInstallationHandle
                        )
                    )
                }
                state.relationshipsV2.sort { $0.id.uuidString < $1.id.uuidString }
                state.localInstallation = installation
            }
        }
        try await store.save(state)
        return contact
    }

    private func ensureMailboxConsumer(
        state: inout ClientState,
        accessKey: SigningKeyPair
    ) async throws -> (
        consumerId: MailboxConsumerId,
        consumerKey: SigningKeyPair,
        routeKey: String
    ) {
        guard var installation = state.localInstallation else {
            throw HeadlessMessagingClientError.missingInstallation
        }
        let routeKey = Self.mailboxRouteKey(relay: state.relay, inboxId: state.inboxId)
        let hadCredential = installation.mailboxCredentialsByRoute[routeKey] != nil
        var credential = try installation.ensureMailboxCredential(
            for: routeKey,
            relay: state.relay,
            inboxId: state.inboxId
        )
        if !hadCredential {
            installation.cursorsByStream.removeValue(forKey: routeKey)
            installation.pendingMailboxCommitsByStream.removeValue(forKey: routeKey)
            state.localInstallation = installation
            // Persist the route-specific ID and key before registration. If a
            // response or process is lost, the retry reuses the same tracked
            // credential instead of leaking another active consumer.
            try await store.save(state)
        }

        let startingSequence = installation.committedSequencesByStream[routeKey] ?? 0
        var request = try Self.makeMailboxConsumerRegistrationRequest(
            inboxId: state.inboxId,
            consumerId: credential.consumerId,
            startingSequence: startingSequence,
            authorityKey: accessKey,
            consumerKey: credential.signingKey,
            sponsorConsumerId: credential.legacySponsorConsumerId,
            sponsorKey: credential.legacySponsorConsumerId == nil ? nil : installation.signingKey
        )
        var response = try await relayClient(for: state.relay).send(
            .registerMailboxConsumer(request),
            timeout: timeout
        )
        if response.type != .mailboxConsumer,
           let legacyConsumerId = credential.legacySponsorConsumerId {
            // Profiles written before route-scoped credentials used the
            // installation key directly. Bind/replay that legacy consumer,
            // then use it once as the authenticated sponsor for a fresh route
            // key. A lost response is safe: registration and revocation are
            // idempotent, and the migration marker remains durable.
            let legacyRequest = try Self.makeMailboxConsumerRegistrationRequest(
                inboxId: state.inboxId,
                consumerId: legacyConsumerId,
                startingSequence: startingSequence,
                authorityKey: accessKey,
                consumerKey: installation.signingKey
            )
            let legacyResponse = try await relayClient(for: state.relay).send(
                .registerMailboxConsumer(legacyRequest),
                timeout: timeout
            )
            guard legacyResponse.type == .mailboxConsumer,
                  legacyResponse.mailboxConsumer?.consumerId == legacyConsumerId,
                  legacyResponse.mailboxConsumer?.state == .active else {
                throw HeadlessMessagingClientError.relayRejected(
                    Self.redactedRelayRejection(legacyResponse)
                )
            }
            request = try Self.makeMailboxConsumerRegistrationRequest(
                inboxId: state.inboxId,
                consumerId: credential.consumerId,
                startingSequence: startingSequence,
                authorityKey: accessKey,
                consumerKey: credential.signingKey,
                sponsorConsumerId: legacyConsumerId,
                sponsorKey: installation.signingKey
            )
            response = try await relayClient(for: state.relay).send(
                .registerMailboxConsumer(request),
                timeout: timeout
            )
        }
        guard response.type == .mailboxConsumer,
              let registration = response.mailboxConsumer,
              registration.consumerId == credential.consumerId,
              registration.consumerSigningPublicKey == credential.signingKey.publicKeyData,
              registration.state == .active else {
            throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
        }
        if let legacyConsumerId = credential.legacySponsorConsumerId {
            try await revokeMailboxConsumer(
                inboxId: state.inboxId,
                relay: state.relay,
                accessKey: accessKey,
                consumerId: legacyConsumerId
            )
            try installation.completeMailboxCredentialMigration(for: routeKey)
            guard let completedCredential = installation.mailboxCredentialsByRoute[routeKey] else {
                throw HeadlessMessagingClientError.missingInstallation
            }
            credential = completedCredential
        }
        // The relay's idempotent registration response is also the recovery
        // source for profiles written before committed sequence tracking was
        // persisted locally.
        installation.committedSequencesByStream[routeKey] = registration.committedSequence
        state.localInstallation = installation
        try await store.save(state)
        return (credential.consumerId, credential.signingKey, routeKey)
    }

    private func revokeMailboxConsumer(
        inboxId: String,
        relay: RelayEndpoint,
        accessKey: SigningKeyPair,
        consumerId: MailboxConsumerId
    ) async throws {
        var request = RevokeMailboxConsumerRequest(inboxId: inboxId, consumerId: consumerId)
        let proof = try Self.makeActorProof(signingKey: accessKey) { actorProof in
            try request.signableData(for: actorProof)
        }
        request = RevokeMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            authorityProof: proof
        )
        let response = try await relayClient(for: relay).send(.revokeMailboxConsumer(request), timeout: timeout)
        guard response.type == .mailboxConsumer,
              response.mailboxConsumer?.state == .revoked else {
            throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
        }
    }

    private func retireInbox(_ retirement: PendingInboxRetirementV2) async throws {
        guard retirement.isStructurallyValid else {
            throw IdentityProfileMigrationError.invalidV2State
        }
        let response = try await relayClient(for: retirement.relay).send(
            .retireInbox(retirement.request),
            timeout: timeout
        )
        guard response.type == .ok else {
            throw HeadlessMessagingClientError.relayRejected(
                Self.redactedRelayRejection(response)
            )
        }
    }

    private func finalizeMailboxCursorCommit(
        _ pending: PendingMailboxCursorCommit,
        state: inout ClientState,
        consumerId: MailboxConsumerId,
        routeKey: String
    ) async throws {
        guard pending.isStructurallyValid else {
            throw HeadlessMessagingClientError.relayRejected("Invalid pending mailbox cursor")
        }
        var request = CommitMailboxCursorRequest(
            inboxId: state.inboxId,
            consumerId: consumerId,
            cursor: pending.cursor,
            sequence: pending.sequence
        )
        guard let consumerKey = state.localInstallation?
                .mailboxCredentialsByRoute[routeKey]?.signingKey else {
            throw HeadlessMessagingClientError.missingInstallation
        }
        let proof = try Self.makeActorProof(signingKey: consumerKey) { actorProof in
            try request.signableData(for: actorProof)
        }
        request = CommitMailboxCursorRequest(
            inboxId: state.inboxId,
            consumerId: consumerId,
            cursor: pending.cursor,
            sequence: pending.sequence,
            consumerProof: proof
        )
        let response = try await relayClient(for: state.relay).send(
            .commitMailboxCursor(request),
            timeout: timeout
        )
        guard response.type == .mailboxConsumer,
              let committed = response.mailboxConsumer,
              committed.consumerId == consumerId,
              committed.committedSequence == pending.sequence else {
            throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
        }
        guard var installation = state.localInstallation else {
            throw HeadlessMessagingClientError.missingInstallation
        }
        installation.cursorsByStream[routeKey] = pending.cursor
        installation.committedSequencesByStream[routeKey] = pending.sequence
        installation.pendingMailboxCommitsByStream.removeValue(forKey: routeKey)
        state.localInstallation = installation
        try await store.save(state)
    }

    private func acknowledgeMessages(_ ids: [UUID], state: ClientState, accessKey: SigningKeyPair) async throws {
        var request = AcknowledgeMessagesRequest(inboxId: state.inboxId, messageIds: ids)
        let proof = try Self.makeActorProof(signingKey: accessKey) { actorProof in
            try request.signableData(for: actorProof)
        }
        request = AcknowledgeMessagesRequest(inboxId: state.inboxId, messageIds: ids, accessProof: proof)
        let response = try await relayClient(for: state.relay).send(.acknowledgeMessages(request), timeout: timeout)
        try requireOK(response)
    }

    private func registerInbox(for state: ClientState) async throws {
        let accessKey = try inboxAccessKey(from: state)
        var request = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: state.inboxId,
            accessPublicKey: accessKey.publicKeyData
        )
        let proof = try Self.makeActorProof(signingKey: accessKey) { actorProof in
            try request.signableData(for: actorProof)
        }
        request = .privacyMinimizedV2(
            inboxId: state.inboxId,
            accessPublicKey: accessKey.publicKeyData,
            accessProof: proof
        )
        let response = try await relayClient(for: state.relay).send(.registerInbox(request), timeout: timeout)
        try requireOK(response)
    }

    private func deliver(envelope: Envelope, to contact: Contact, from state: ClientState) async throws -> RelayResponse {
        let response = try await relayClient(for: contact.relay).send(
            .deliver(
                DeliverRequest(
                    inboxId: contact.inboxId,
                    routingToken: contact.inboxId,
                    envelope: envelope,
                    destinationRelay: nil
                )
            ),
            timeout: timeout
        )
        guard response.type == .delivered || response.type == .ok else {
            throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
        }
        return response
    }

    private func deliver(pending: PendingDirectDelivery) async throws -> RelayResponse {
        let response = try await relayClient(for: pending.destinationRelay).send(
            .deliver(
                DeliverRequest(
                    inboxId: pending.inboxId,
                    routingToken: pending.inboxId,
                    envelope: pending.envelope,
                    destinationRelay: nil
                )
            ),
            timeout: timeout
        )
        guard response.type == .delivered || response.type == .ok else {
            throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
        }
        return response
    }

    private func persistDirectDeliveryIntent(
        envelope: Envelope,
        contact: Contact,
        state: inout ClientState
    ) async throws -> UUID {
        let now = Date()
        let attemptId = UUID()
        if !state.pendingDirectDeliveries.contains(where: { $0.id == envelope.id }) {
            guard state.pendingDirectDeliveries.count
                    < NoctweaveArchitectureV2.maximumPendingDirectDeliveries else {
                throw HeadlessMessagingClientError.directOutboxFull(
                    NoctweaveArchitectureV2.maximumPendingDirectDeliveries
                )
            }
            state.pendingDirectDeliveries.append(
                PendingDirectDelivery(
                    contactId: contact.id,
                    inboxId: contact.inboxId,
                    preferredRelay: state.relay,
                    destinationRelay: contact.relay,
                    envelope: envelope,
                    queuedAt: now,
                    attemptCount: 1,
                    lastAttemptAt: now
                )
            )
        }
        if !state.protocolIntents.contains(where: { $0.id == envelope.id }) {
            let protectedIntentIds = Set(state.pendingDirectDeliveries.map(\.id))
                .union(state.identityMutationV2?.notificationIds ?? [])
                .union(
                    state.protocolIntents
                        .filter { !$0.state.isTerminal }
                        .flatMap(\.dependencies)
                )
            let requiredPruneCount = max(
                0,
                state.protocolIntents.count + 1
                    - NoctweaveArchitectureV2.maximumProtocolIntents
            )
            let prunable = state.protocolIntents
                .filter { $0.state.isTerminal && !protectedIntentIds.contains($0.id) }
                .sorted {
                    if $0.updatedAt == $1.updatedAt {
                        return $0.id.uuidString < $1.id.uuidString
                    }
                    return $0.updatedAt < $1.updatedAt
                }
            guard prunable.count >= requiredPruneCount else {
                throw HeadlessMessagingClientError.directOutboxFull(
                    NoctweaveArchitectureV2.maximumProtocolIntents
                )
            }
            let prunedIds = Set(prunable.prefix(requiredPruneCount).map(\.id))
            state.protocolIntents.removeAll { prunedIds.contains($0.id) }
            guard state.protocolIntents.count
                    < NoctweaveArchitectureV2.maximumProtocolIntents else {
                throw HeadlessMessagingClientError.directOutboxFull(
                    NoctweaveArchitectureV2.maximumProtocolIntents
                )
            }
            let digest = Data(SHA256.hash(data: try NoctweaveCoder.encode(envelope, sortedKeys: true)))
            let prepared = ProtocolIntentV2.prepare(
                id: envelope.id,
                kind: .sendEvent,
                targetIdentifier: Data(contact.id.uuidString.lowercased().utf8),
                payloadDigest: digest,
                createdAt: now
            )
            guard let attempting = prepared.beginningAttempt(
                id: attemptId,
                completedIntentIds: Self.completedIntentIds(in: state),
                at: now
            ) else {
                throw HeadlessMessagingClientError.relayRejected("Unable to prepare durable send intent")
            }
            state.protocolIntents.append(attempting)
        }
        try await store.save(state)
        return attemptId
    }

    private func finalizeDirectDeliveryIntent(
        envelopeId: UUID,
        attemptId: UUID,
        state: inout ClientState
    ) async throws {
        if let index = state.protocolIntents.firstIndex(where: { $0.id == envelopeId }) {
            let transitionAt = max(Date(), state.protocolIntents[index].updatedAt)
            guard let published = state.protocolIntents[index].advancing(
                to: .published,
                attemptId: attemptId,
                at: transitionAt
            ), let committed = published.advancing(
                to: .committed,
                attemptId: attemptId,
                at: transitionAt
            ), let finalized = committed.advancing(
                to: .finalized,
                attemptId: attemptId,
                at: transitionAt
            ) else {
                throw HeadlessMessagingClientError.relayRejected("Unable to finalize durable send intent")
            }
            state.protocolIntents[index] = finalized
        }
        // Drop the recoverable ciphertext only after the journal transition is
        // known to be valid. A transition error must leave the exact envelope
        // available for idempotent replay.
        state.pendingDirectDeliveries.removeAll { $0.id == envelopeId }
        try await store.save(state)
    }

    private func recordDirectDeliveryFailure(
        envelopeId: UUID,
        attemptId: UUID,
        error: Error,
        state: inout ClientState
    ) async throws {
        let now = Date()
        if let pendingIndex = state.pendingDirectDeliveries.firstIndex(where: { $0.id == envelopeId }) {
            state.pendingDirectDeliveries[pendingIndex].lastAttemptAt = now
        }
        if let intentIndex = state.protocolIntents.firstIndex(where: { $0.id == envelopeId }) {
            let intent = state.protocolIntents[intentIndex]
            let explicitRejection: Bool
            if case .relayRejected = error as? HeadlessMessagingClientError {
                explicitRejection = true
            } else {
                explicitRejection = false
            }
            if explicitRejection,
               let failed = intent.failingPermanently(errorClass: .relayRejected, at: now) {
                state.protocolIntents[intentIndex] = failed
            } else if intent.attemptCount
                        >= UInt32(NoctweaveArchitectureV2.maximumIntentAttempts),
                      let failed = intent.failingPermanently(
                        errorClass: .attemptLimitExceeded,
                        at: now
                      ) {
                state.protocolIntents[intentIndex] = failed
            } else if let failed = intent.recordingTransientFailure(
                attemptId: attemptId,
                errorClass: .relayUnavailable,
                retryNotBefore: now.addingTimeInterval(1),
                at: now
            ) {
                state.protocolIntents[intentIndex] = failed
            }
        }
        try await store.save(state)
    }

    private static func completedIntentIds(in state: ClientState) -> Set<UUID> {
        Set(state.protocolIntents.filter { $0.state == .finalized }.map(\.id))
    }

    private func ensurePreparedIntent(
        for pending: PendingDirectDelivery,
        dependencies: [UUID],
        state: inout ClientState
    ) throws {
        guard dependencies.count <= NoctweaveArchitectureV2.maximumIntentDependencies,
              pending.envelope.isStructurallyValid else {
            throw IdentityProfileMigrationError.invalidV2State
        }
        let encoded = try NoctweaveCoder.encode(pending.envelope, sortedKeys: true)
        let digest = Data(SHA256.hash(data: encoded))
        let target = Data(pending.contactId.uuidString.lowercased().utf8)
        if let existing = state.protocolIntents.first(where: { $0.id == pending.id }) {
            guard existing.kind == .sendEvent,
                  !existing.state.isTerminal,
                  existing.targetIdentifier == target,
                  existing.payloadDigest == digest else {
                throw IdentityProfileMigrationError.invalidV2State
            }
            return
        }
        let protectedIntentIds = Set(state.pendingDirectDeliveries.map(\.id))
            .union(state.identityMutationV2?.notificationIds ?? [])
            .union(
                state.protocolIntents
                    .filter { !$0.state.isTerminal }
                    .flatMap(\.dependencies)
            )
        let requiredPruneCount = max(
            0,
            state.protocolIntents.count + 1
                - NoctweaveArchitectureV2.maximumProtocolIntents
        )
        let prunable = state.protocolIntents
            .filter { $0.state.isTerminal && !protectedIntentIds.contains($0.id) }
            .sorted {
                if $0.updatedAt == $1.updatedAt {
                    return $0.id.uuidString < $1.id.uuidString
                }
                return $0.updatedAt < $1.updatedAt
            }
        guard prunable.count >= requiredPruneCount else {
            throw IdentityProfileMigrationError.invalidV2State
        }
        let prunedIds = Set(prunable.prefix(requiredPruneCount).map(\.id))
        state.protocolIntents.removeAll { prunedIds.contains($0.id) }
        guard state.protocolIntents.count
                < NoctweaveArchitectureV2.maximumProtocolIntents else {
            throw IdentityProfileMigrationError.invalidV2State
        }
        let intent = ProtocolIntentV2.prepare(
            id: pending.id,
            kind: .sendEvent,
            targetIdentifier: target,
            payloadDigest: digest,
            dependencies: dependencies,
            createdAt: pending.queuedAt
        )
        guard intent.isStructurallyValid else {
            throw IdentityProfileMigrationError.invalidV2State
        }
        state.protocolIntents.append(intent)
    }

    private func identityMutationResult(
        _ journal: IdentityMutationJournalV2,
        state: ClientState
    ) -> HeadlessIdentityChangeResult {
        let finalizedIds = Set(state.protocolIntents.filter { $0.state == .finalized }.map(\.id))
        let notified = journal.notifications.filter { finalizedIds.contains($0.id) }
        let failed = journal.notifications.filter { !finalizedIds.contains($0.id) }
        return HeadlessIdentityChangeResult(
            oldFingerprint: journal.oldFingerprint,
            newFingerprint: journal.newFingerprint,
            notifiedContacts: notified.map(\.contactDisplayName),
            failedContacts: failed.map(\.contactDisplayName)
        )
    }

    /// A staged burn may be resumed after a crash without allowing unrelated
    /// application sends to race the cutover. After the immediate local
    /// cutover, each retained relationship remains blocked only until its exact
    /// continuity ciphertext has reached the relay and its intent is durable.
    /// Rotation uses the same per-contact rule so legacy peers cannot observe a
    /// new identity key before the signed continuity notice.
    private func requireContinuityDeliveryReady(
        for contact: Contact,
        state: ClientState
    ) throws {
        guard let journal = state.identityMutationV2 else { return }
        if journal.phase == .prepared || journal.phase == .newRouteReady {
            throw HeadlessMessagingClientError.identityMutationInProgress(
                "\(journal.kind.rawValue) cutover is pending; resume the identity operation first"
            )
        }
        guard let notification = journal.notifications.first(where: { $0.contactId == contact.id }) else {
            return
        }
        let intentIsFinalized = state.protocolIntents.contains {
            $0.id == notification.id && $0.state == .finalized
        }
        let ciphertextIsPending = state.pendingDirectDeliveries.contains { $0.id == notification.id }
        guard intentIsFinalized, !ciphertextIsPending else {
            throw HeadlessMessagingClientError.identityMutationInProgress(
                "\(journal.kind.rawValue) continuity delivery to \(contact.displayName) is pending; retry pending direct deliveries first"
            )
        }
    }

    private func identityMutationCanBeCleared(in state: ClientState) -> Bool {
        guard let journal = state.identityMutationV2,
              journal.phase == .cleanupComplete else { return false }
        let finalizedIds = Set(state.protocolIntents.filter { $0.state == .finalized }.map(\.id))
        let pendingIds = Set(state.pendingDirectDeliveries.map(\.id))
        return journal.notificationIds.isSubset(of: finalizedIds)
            && journal.notificationIds.isDisjoint(with: pendingIds)
    }

    private func resumeIdentityBurnUnlocked(
        _ originalJournal: IdentityMutationJournalV2
    ) async throws -> HeadlessIdentityChangeResult {
        var state = try await loadState()
        guard var journal = state.identityMutationV2,
              journal.id == originalJournal.id,
              journal.kind == .burn else {
            throw IdentityProfileMigrationError.invalidV2State
        }

        if journal.phase == .prepared {
            guard let staged = journal.stagedBurn else {
                throw IdentityProfileMigrationError.invalidV2State
            }
            try await registerStagedIdentityRoute(staged)
            let transitionAt = max(Date(), journal.updatedAt)
            guard journal.markNewRouteReady(at: transitionAt) else {
                throw IdentityProfileMigrationError.invalidV2State
            }
            state.identityMutationV2 = journal
            // Replaying a lost response reuses the staged inbox and consumer;
            // both relay registrations are idempotent.
            try await store.save(state)
        }

        if journal.phase == .newRouteReady {
            let transitionAt = max(Date(), journal.updatedAt)
            try state.cutOverStagedIdentityBurn(at: transitionAt)
            // The old identity remains active on disk until this atomic save.
            try await store.save(state)
            guard let updatedJournal = state.identityMutationV2 else {
                throw IdentityProfileMigrationError.invalidV2State
            }
            journal = updatedJournal
        }

        if journal.phase == .cutoverComplete {
            // Retire routes independently so one unavailable relay cannot keep
            // already reachable old routes alive. Each successful removal is
            // persisted before the next network attempt.
            for retirement in journal.pendingInboxRetirements {
                do {
                    try await retireInbox(retirement)
                    let transitionAt = max(Date(), journal.updatedAt)
                    guard journal.markInboxRetired(
                        routeIdentifier: retirement.routeIdentifier,
                        at: transitionAt
                    ) else {
                        throw IdentityProfileMigrationError.invalidV2State
                    }
                    state.identityMutationV2 = journal
                    try await store.save(state)
                } catch {
                    // The exact private-key-free request remains durable and
                    // can be retried after restart or relay recovery.
                    continue
                }
            }
        }

        _ = try await retryPendingDirectDeliveriesUnlocked(maxCount: 256)
        return identityMutationResult(originalJournal, state: try await loadState())
    }

    private func registerStagedIdentityRoute(
        _ staged: StagedIdentityGenerationV2
    ) async throws {
        guard staged.isStructurallyValid,
              let credential = staged.mailboxCredential else {
            throw IdentityProfileMigrationError.invalidV2State
        }
        var inboxRequest = RegisterInboxRequest.privacyMinimizedV2(
            inboxId: staged.inboxId,
            accessPublicKey: staged.inboxAccessKey.publicKeyData
        )
        let inboxProof = try Self.makeActorProof(signingKey: staged.inboxAccessKey) { proof in
            try inboxRequest.signableData(for: proof)
        }
        inboxRequest = .privacyMinimizedV2(
            inboxId: staged.inboxId,
            accessPublicKey: staged.inboxAccessKey.publicKeyData,
            accessProof: inboxProof
        )
        let inboxResponse = try await relayClient(for: staged.relay).send(
            .registerInbox(inboxRequest),
            timeout: timeout
        )
        try requireOK(inboxResponse)

        let consumerRequest = try Self.makeMailboxConsumerRegistrationRequest(
            inboxId: staged.inboxId,
            consumerId: credential.consumerId,
            startingSequence: 0,
            authorityKey: staged.inboxAccessKey,
            consumerKey: credential.signingKey
        )
        let consumerResponse = try await relayClient(for: staged.relay).send(
            .registerMailboxConsumer(consumerRequest),
            timeout: timeout
        )
        guard consumerResponse.type == .mailboxConsumer,
              consumerResponse.mailboxConsumer?.consumerId == credential.consumerId,
              consumerResponse.mailboxConsumer?.consumerSigningPublicKey
                == credential.signingKey.publicKeyData,
              consumerResponse.mailboxConsumer?.state == .active else {
            throw HeadlessMessagingClientError.relayRejected(
                Self.redactedRelayRejection(consumerResponse)
            )
        }
    }

    private func loadState() async throws -> ClientState {
        guard let state = try await store.load() else {
            throw HeadlessMessagingClientError.missingState
        }
        return state
    }

    private func inboxAccessKey(from state: ClientState) throws -> SigningKeyPair {
        guard let key = state.inboxAccessKey else {
            throw HeadlessMessagingClientError.missingInboxAccessKey
        }
        return key
    }

    private func contactOffer(for state: ClientState) throws -> ContactOffer {
        if let generationId = state.identityGenerationId,
           state.localInstallation != nil,
           let manifest = state.installationManifest,
           let endpoint = state.issuedContactEndpointsV2.last {
            return try ContactOffer.createCertified(
                displayName: state.identity.displayName,
                inboxId: state.inboxId,
                relay: state.relay,
                identity: state.identity,
                identityGenerationId: generationId,
                installationManifest: manifest,
                preferredInstallationEndpoint: endpoint,
                inboxAccessPublicKey: state.inboxAccessKey?.publicKeyData
            )
        }
        return try MessageEngine.makeContactOffer(
            identity: state.identity,
            inboxId: state.inboxId,
            relay: state.relay,
            inboxAccessPublicKey: state.inboxAccessKey?.publicKeyData
        )
    }

    private func issueCertifiedContactOffer(
        state: inout ClientState,
        inboxAccessPublicKey: Data?
    ) throws -> ContactOffer {
        guard let generationId = state.identityGenerationId,
              let manifest = state.installationManifest else {
            throw HeadlessMessagingClientError.missingInstallation
        }
        let endpoint = try currentCertifiedEndpoint(state: &state)
        return try ContactOffer.createCertified(
            displayName: state.identity.displayName,
            inboxId: state.inboxId,
            relay: state.relay,
            identity: state.identity,
            identityGenerationId: generationId,
            installationManifest: manifest,
            preferredInstallationEndpoint: endpoint,
            inboxAccessPublicKey: inboxAccessPublicKey
        )
    }

    private func localEndpoint(state: inout ClientState) throws -> CertifiedInstallationEndpoint {
        try currentCertifiedEndpoint(state: &state)
    }

    private func currentCertifiedEndpoint(
        state: inout ClientState,
        now: Date = Date()
    ) throws -> CertifiedInstallationEndpoint {
        guard var installation = state.localInstallation,
              let generationId = state.identityGenerationId,
              let manifest = state.installationManifest,
              installation.identityGenerationId == generationId else {
            throw HeadlessMessagingClientError.missingInstallation
        }
        _ = try installation.renewSignedPrekeyIfNeeded(at: now)
        state.localInstallation = installation

        if let index = state.issuedContactEndpointsV2.lastIndex(where: {
            $0.identityGenerationId == generationId
                && $0.identityAuthorityPublicKey == state.identity.signingKey.publicKeyData
                && $0.manifestEpoch == manifest.epoch
                && $0.manifestDigest == manifest.digest
                && $0.installationId == installation.id
                && $0.signingPublicKey == installation.signingKey.publicKeyData
                && $0.agreementPublicKey == installation.agreementKey.publicKeyData
        }) {
            let current = state.issuedContactEndpointsV2[index]
            let isAuthorized = (try? current.verified(
                identityPublicKey: state.identity.signingKey.publicKeyData,
                manifest: manifest,
                now: current.prekeyBundle.createdAt
            )) != nil
            if isAuthorized {
                if current.prekeyBundle.signedPrekey.id == installation.prekeys.signedPrekeyId,
                   current.isStructurallyValid(now: now) {
                    return current
                }
                let refreshed = try current.refreshingPrekeyPackage(
                    using: installation,
                    at: now
                )
                var endpoints = state.issuedContactEndpointsV2
                endpoints[index] = refreshed
                state.issuedContactEndpointsV2 = endpoints
                return refreshed
            }
        }

        guard state.issuedContactEndpointsV2.count
                < NoctweaveArchitectureV2.maximumIssuedContactEndpoints else {
            throw HeadlessMessagingClientError.missingInstallation
        }
        let endpoint = try CertifiedInstallationEndpoint.create(
            identity: state.identity,
            installation: installation,
            manifest: manifest,
            issuedAt: now
        )
        state.issuedContactEndpointsV2.append(endpoint)
        return endpoint
    }

    private func pairwiseBinding(
        localEndpoint: CertifiedInstallationEndpoint,
        contact: Contact,
        peerEndpoint: CertifiedInstallationEndpoint
    ) throws -> PairwiseInstallationBindingV4 {
        guard contact.identityGenerationId == peerEndpoint.identityGenerationId else {
            throw CryptoError.invalidPayload
        }
        return try PairwiseInstallationBindingV4.derive(
            localIdentityGenerationId: localEndpoint.identityGenerationId,
            localIdentitySigningPublicKey: localEndpoint.identityAuthorityPublicKey,
            localEndpoint: localEndpoint,
            peerIdentityGenerationId: peerEndpoint.identityGenerationId,
            peerIdentitySigningPublicKey: peerEndpoint.identityAuthorityPublicKey,
            peerEndpoint: peerEndpoint
        )
    }

    private func directSendEndpointContext(
        contact: Contact,
        peerEndpoint: CertifiedInstallationEndpoint,
        state: inout ClientState
    ) throws -> (
        localEndpoint: CertifiedInstallationEndpoint,
        binding: PairwiseInstallationBindingV4,
        endpointSession: DirectEndpointSessionIdentity
    ) {
        guard let installation = state.localInstallation else {
            throw HeadlessMessagingClientError.missingInstallation
        }
        if state.issuedContactEndpointsV2.isEmpty {
            _ = try localEndpoint(state: &state)
        }
        var fallback: (
            CertifiedInstallationEndpoint,
            PairwiseInstallationBindingV4,
            DirectEndpointSessionIdentity
        )?
        for endpoint in state.issuedContactEndpointsV2.reversed() where
            endpoint.identityGenerationId == installation.identityGenerationId
                && endpoint.installationId == installation.id
                && endpoint.signingPublicKey == installation.signingKey.publicKeyData
                && endpoint.agreementPublicKey == installation.agreementKey.publicKeyData {
            let binding = try pairwiseBinding(
                localEndpoint: endpoint,
                contact: contact,
                peerEndpoint: peerEndpoint
            )
            let session = DirectEndpointSessionIdentity(
                contactId: contact.id,
                localInstallationId: installation.id,
                localInstallationHandle: binding.localInstallationHandle,
                localCertificateReferenceDigest: binding.localCertificateReferenceDigest,
                localManifestEpoch: endpoint.manifestEpoch,
                peerInstallationId: peerEndpoint.installationId,
                peerInstallationHandle: binding.peerInstallationHandle,
                peerCertificateReferenceDigest: binding.peerCertificateReferenceDigest,
                peerManifestEpoch: peerEndpoint.manifestEpoch
            )
            if state.conversation(for: contact.id, endpointSession: session) != nil {
                return (endpoint, binding, session)
            }
            if fallback == nil {
                fallback = (endpoint, binding, session)
            }
        }
        guard let fallback else { throw HeadlessMessagingClientError.missingInstallation }
        return fallback
    }

    private func status(for state: ClientState) -> HeadlessClientStatus {
        HeadlessClientStatus(
            displayName: state.identity.displayName,
            fingerprint: state.identity.fingerprint,
            inboxId: state.inboxId,
            relay: state.relay,
            contactCount: state.contacts.count,
            conversationCount: state.conversations.count
        )
    }

    private func continuityAudit(for state: ClientState) -> HeadlessContinuityAudit {
        let profile = state.identityProfile(id: state.activeIdentityId)
        return HeadlessContinuityAudit(
            profileId: state.activeIdentityId,
            fingerprint: state.identity.fingerprint,
            events: profile?.continuityEvents ?? []
        )
    }

    private func summary(for group: GroupConversation) -> HeadlessGroupSummary {
        HeadlessGroupSummary(
            id: group.id,
            title: group.title,
            inboxId: group.relayInboxId,
            memberCount: group.resolvedMemberCount,
            relayEpoch: group.relayEpoch,
            unreadCount: group.unreadCount,
            createdByFingerprint: group.createdByFingerprint
        )
    }

    private func groupMemberProfile(identity: Identity, inboxId: String, relay: RelayEndpoint) -> RelayGroupMemberProfile {
        RelayGroupMemberProfile(
            fingerprint: identity.fingerprint,
            displayName: identity.displayName,
            inboxId: inboxId,
            relay: relay,
            signingPublicKey: identity.signingKey.publicKeyData,
            agreementPublicKey: identity.agreementKey.publicKeyData
        )
    }

    private func groupMemberProfile(contact: Contact) -> RelayGroupMemberProfile {
        RelayGroupMemberProfile(
            fingerprint: contact.fingerprint,
            displayName: contact.displayName,
            inboxId: contact.inboxId,
            relay: contact.relay,
            signingPublicKey: contact.signingPublicKey,
            agreementPublicKey: contact.agreementPublicKey
        )
    }

    private func groupMemberProfile(member: RelayGroupMember) -> RelayGroupMemberProfile {
        RelayGroupMemberProfile(
            fingerprint: member.fingerprint,
            displayName: member.displayName,
            inboxId: member.inboxId,
            relay: member.relay,
            signingPublicKey: member.signingPublicKey,
            agreementPublicKey: member.agreementPublicKey
        )
    }

    private func groupMemberProfiles(
        from descriptor: RelayGroupDescriptor,
        preferredRelay: RelayEndpoint
    ) -> [RelayGroupMemberProfile] {
        var byFingerprint: [String: RelayGroupMemberProfile] = [:]
        for member in descriptor.members {
            let fingerprint = member.fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !fingerprint.isEmpty else { continue }
            var profile = groupMemberProfile(member: member)
            if profile.relay == nil, profile.inboxId != nil {
                profile = RelayGroupMemberProfile(
                    fingerprint: profile.fingerprint,
                    displayName: profile.displayName,
                    inboxId: profile.inboxId,
                    relay: preferredRelay,
                    signingPublicKey: profile.signingPublicKey,
                    agreementPublicKey: profile.agreementPublicKey
                )
            }
            byFingerprint[fingerprint] = profile
        }
        return byFingerprint.values.sorted { $0.fingerprint < $1.fingerprint }
    }

    private func groupInboxId(for group: GroupConversation) throws -> String {
        guard let inboxId = group.relayInboxId?.trimmingCharacters(in: .whitespacesAndNewlines),
              !inboxId.isEmpty else {
            throw HeadlessMessagingClientError.missingGroupRatchet(group.title)
        }
        return inboxId
    }

    private func senderContact(for fingerprint: String, in contacts: [Contact]) -> Contact? {
        contacts.first { $0.fingerprint == fingerprint }
    }

    private func groupMemberSigningKey(for fingerprint: String, group: GroupConversation, state: ClientState) -> Data? {
        if fingerprint == state.identity.fingerprint {
            return state.identity.signingKey.publicKeyData
        }
        if let profile = group.memberProfiles.first(where: { $0.fingerprint == fingerprint }),
           let signingPublicKey = profile.signingPublicKey,
           !signingPublicKey.isEmpty {
            return signingPublicKey
        }
        return state.contacts.first { contact in
            group.memberContactIds.contains(contact.id) && contact.fingerprint == fingerprint
        }?.signingPublicKey
    }

    private func appendGroupMessage(
        body: MessageBody,
        direction: MessageDirection,
        senderDisplayName: String?,
        counter: UInt64,
        timestamp: Date,
        group: inout GroupConversation,
        attachmentRelay: RelayEndpoint? = nil,
        attachmentCryptoContext: AttachmentCryptoContext? = nil,
        messageKey: SymmetricKey? = nil
    ) {
        switch body {
        case .text(let text):
            group.messages.append(
                Message(
                    direction: direction,
                    senderDisplayName: senderDisplayName,
                    body: text,
                    timestamp: timestamp,
                    counter: counter
                )
            )
        case .attachment(let descriptor):
            let title = Self.attachmentTitle(for: descriptor)
            group.messages.append(
                Message(
                    direction: direction,
                    senderDisplayName: senderDisplayName,
                    body: title,
                    timestamp: timestamp,
                    counter: counter,
                    attachment: AttachmentInfo(
                        descriptor: descriptor,
                        relay: attachmentRelay,
                        cryptoContext: attachmentCryptoContext,
                        messageKeyData: messageKey.map(AttachmentCrypto.keyData)
                    )
                )
            )
        case .identityRotation, .identityReset, .sessionReset, .resendRequest:
            break
        }
    }

    private func upload(chunks: [AttachmentChunk], to relay: RelayEndpoint, ttlSeconds: Int?) async throws {
        let client = relayClient(for: relay)
        for chunk in chunks {
            let response = try await client.send(
                .uploadAttachment(
                    UploadAttachmentRequest(
                        attachmentId: chunk.attachmentId,
                        chunkIndex: chunk.chunkIndex,
                        payload: chunk.payload,
                        ttlSeconds: ttlSeconds
                    )
                ),
                timeout: timeout
            )
            guard response.type == .attachment || response.type == .ok else {
                throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
            }
        }
    }

    private func attachmentInfo(id: UUID, in state: ClientState) throws -> AttachmentInfo {
        for conversation in state.conversations {
            if let info = conversation.messages.compactMap(\.attachment).first(where: { $0.descriptor.id == id }) {
                return info
            }
        }
        for group in state.groups {
            if let info = group.messages.compactMap(\.attachment).first(where: { $0.descriptor.id == id }) {
                return info
            }
        }
        throw HeadlessMessagingClientError.attachmentNotFound(id.uuidString)
    }

    private func relayClient(for endpoint: RelayEndpoint) -> RelayClient {
        RelayClient(endpoint: endpoint, authToken: authToken)
    }

    private func requireOK(_ response: RelayResponse) throws {
        guard response.type == .ok || response.type == .delivered else {
            throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
        }
    }

    private static func redactedRelayRejection(_ response: RelayResponse) -> String {
        guard let error = response.error?.trimmingCharacters(in: .whitespacesAndNewlines),
              !error.isEmpty else {
            return response.type == .error
                ? "Relay rejected the request."
                : "Relay returned an unexpected response."
        }

        let lowercased = error.lowercased()
        if lowercased.contains("unauthorized") || lowercased.contains("forbidden") {
            return "Relay authorization failed."
        }
        if lowercased.contains("proof") || lowercased.contains("signature") {
            return "Relay proof verification failed."
        }
        if lowercased.contains("not found") || lowercased.contains("not registered") {
            return "Relay resource was not found."
        }
        if lowercased.contains("rate") || lowercased.contains("quota") || lowercased.contains("limit") {
            return "Relay rate limit was reached."
        }
        if lowercased.contains("disabled") || lowercased.contains("not allowed") {
            return "Relay policy rejected the request."
        }
        if lowercased.contains("invalid") || lowercased.contains("malformed") || lowercased.contains("missing") {
            return "Relay rejected an invalid request."
        }
        return "Relay rejected the request."
    }

    private func resolveContact(_ selector: String, in contacts: [Contact]) throws -> Contact {
        let needle = selector.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else {
            throw HeadlessMessagingClientError.contactNotFound(selector)
        }
        let matches = contacts.filter { contact in
            contact.id.uuidString.caseInsensitiveCompare(needle) == .orderedSame
                || contact.fingerprint.caseInsensitiveCompare(needle) == .orderedSame
                || contact.displayName.localizedCaseInsensitiveCompare(needle) == .orderedSame
        }
        guard !matches.isEmpty else {
            throw HeadlessMessagingClientError.contactNotFound(selector)
        }
        guard matches.count == 1 else {
            throw HeadlessMessagingClientError.ambiguousContact(selector)
        }
        return matches[0]
    }

    private func resolveGroup(_ selector: String, in groups: [GroupConversation]) throws -> GroupConversation {
        let needle = selector.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else {
            throw HeadlessMessagingClientError.groupNotFound(selector)
        }
        let matches = groups.filter { group in
            group.id.uuidString.caseInsensitiveCompare(needle) == .orderedSame
                || group.title.localizedCaseInsensitiveCompare(needle) == .orderedSame
        }
        guard !matches.isEmpty else {
            throw HeadlessMessagingClientError.groupNotFound(selector)
        }
        guard matches.count == 1 else {
            throw HeadlessMessagingClientError.ambiguousGroup(selector)
        }
        return matches[0]
    }

    private static func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        #if canImport(Security)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw CryptoError.operationFailed
        }
        #else
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: 0...255)
        }
        #endif
        return Data(bytes)
    }

    private static func encryptAttachmentChunks(
        data: Data,
        fileName: String?,
        mimeType: String,
        chunkSize: Int,
        messageKey: SymmetricKey,
        context: AttachmentCryptoContext,
        relayTTLSeconds: Int?
    ) throws -> (AttachmentDescriptor, [AttachmentChunk]) {
        guard !data.isEmpty, data.count <= AttachmentDescriptor.maximumTransportBytes else {
            throw HeadlessMessagingClientError.invalidAttachmentDescriptor
        }
        let safeChunkSize = max(1, min(chunkSize, AttachmentDescriptor.maximumTransportChunkBytes))
        let attachmentId = UUID()
        let chunkCount = (data.count / safeChunkSize) + (data.count % safeChunkSize == 0 ? 0 : 1)
        guard chunkCount <= AttachmentDescriptor.maximumTransportChunks else {
            throw HeadlessMessagingClientError.invalidAttachmentDescriptor
        }
        let normalizedMIME = mimeType.trimmingCharacters(in: .whitespacesAndNewlines)
        let descriptor = AttachmentDescriptor(
            id: attachmentId,
            fileName: nil,
            mimeType: normalizedMIME.isEmpty
                ? "application/octet-stream"
                : normalizedMIME,
            byteCount: data.count,
            sha256: AttachmentCrypto.sha256(data),
            chunkCount: chunkCount,
            chunkSize: safeChunkSize,
            relayTTLSeconds: relayTTLSeconds
        )
        guard descriptor.isStructurallyValid() else {
            throw HeadlessMessagingClientError.invalidAttachmentDescriptor
        }
        var chunks: [AttachmentChunk] = []
        chunks.reserveCapacity(chunkCount)
        for chunkIndex in 0..<chunkCount {
            let start = data.index(data.startIndex, offsetBy: chunkIndex * safeChunkSize)
            let endOffset = min(data.count, (chunkIndex + 1) * safeChunkSize)
            let end = data.index(data.startIndex, offsetBy: endOffset)
            let plaintext = data[start..<end]
            let aad = AttachmentCrypto.authenticatedData(
                conversationId: context.conversationId,
                sessionId: context.sessionId,
                messageCounter: context.messageCounter,
                attachmentId: attachmentId,
                chunkIndex: chunkIndex,
                byteCount: plaintext.count
            )
            var plaintextCopy = Data(plaintext)
            let payload: EncryptedPayload
            do {
                defer { plaintextCopy.secureWipe() }
                payload = try AttachmentCrypto.encryptChunk(
                    plaintext: plaintextCopy,
                    messageKey: messageKey,
                    attachmentId: attachmentId,
                    chunkIndex: chunkIndex,
                    authenticatedData: aad
                )
            }
            chunks.append(AttachmentChunk(attachmentId: attachmentId, chunkIndex: chunkIndex, payload: payload))
        }
        return (descriptor, chunks)
    }

    private static func attachmentTitle(for descriptor: AttachmentDescriptor) -> String {
        let mimeType = descriptor.mimeType
            .split(separator: ";", maxSplits: 1)
            .first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() ?? descriptor.mimeType.lowercased()
        if mimeType.hasPrefix("audio/") {
            return "Voice message"
        }
        if mimeType.hasPrefix("image/") {
            return "Image"
        }
        return "Attachment"
    }

    private static func attachmentChunkPlaintextSize(
        descriptor: AttachmentDescriptor,
        chunkIndex: Int
    ) -> Int {
        guard descriptor.chunkCount > 0 else { return 0 }
        if chunkIndex == descriptor.chunkCount - 1 {
            return descriptor.byteCount - (descriptor.chunkSize * chunkIndex)
        }
        return descriptor.chunkSize
    }

    private static func groupAttachmentContext(
        groupId: UUID,
        epoch: UInt64,
        transcriptHash: Data,
        messageCounter: UInt64
    ) -> AttachmentCryptoContext {
        AttachmentCryptoContext(
            conversationId: "group:\(groupId.uuidString)",
            sessionId: "epoch:\(epoch):\(transcriptHash.base64EncodedString())",
            messageCounter: messageCounter
        )
    }

    private static func mailboxRouteKey(relay: RelayEndpoint, inboxId: String) -> String {
        "\(relay.transport.rawValue):\(relay.useTLS ? 1 : 0):\(relay.host.lowercased()):\(relay.port):\(inboxId.lowercased())"
    }

    /// Migration parser for route keys written before credentials retained the
    /// exact relay endpoint. Hosts may be IPv6, so parse fixed fields from both
    /// ends and join the middle segments back into the host.
    private static func parseMailboxRouteKey(
        _ routeKey: String
    ) -> (relay: RelayEndpoint, inboxId: String)? {
        let fields = routeKey.split(separator: ":", omittingEmptySubsequences: false)
        guard fields.count >= 5,
              let transport = RelayEndpointTransport(rawValue: String(fields[0])),
              fields[1] == "0" || fields[1] == "1",
              let port = UInt16(fields[fields.count - 2]) else {
            return nil
        }
        let host = fields[2..<(fields.count - 2)].joined(separator: ":")
        let inboxId = String(fields[fields.count - 1])
        guard !host.isEmpty, InboxAddress.isValid(inboxId) else { return nil }
        return (
            RelayEndpoint(
                host: host,
                port: port,
                useTLS: fields[1] == "1",
                transport: transport
            ),
            inboxId.lowercased()
        )
    }

    private static func makeActorProof(
        signingKey: SigningKeyPair,
        signableDataBuilder: (RelayActorProof) throws -> Data
    ) throws -> RelayActorProof {
        let signedAt = Date()
        let nonce = UUID()
        let placeholder = RelayActorProof(
            fingerprint: CryptoBox.fingerprint(for: signingKey.publicKeyData),
            publicSigningKey: signingKey.publicKeyData,
            signedAt: signedAt,
            nonce: nonce,
            signature: Data()
        )
        let signableData = try signableDataBuilder(placeholder)
        return try RelayActorProof.make(
            signingKey: signingKey,
            signableData: signableData,
            signedAt: signedAt,
            nonce: nonce
        )
    }

    /// Creates the two independent proofs required to bind an opaque relay
    /// consumer to one route. The inbox key authorizes the binding; the fresh
    /// route key proves possession and becomes the only key accepted for
    /// subsequent sync and cursor commits.
    private static func makeMailboxConsumerRegistrationRequest(
        inboxId: String,
        consumerId: MailboxConsumerId,
        startingSequence: UInt64?,
        authorityKey: SigningKeyPair,
        consumerKey: SigningKeyPair,
        sponsorConsumerId: MailboxConsumerId? = nil,
        sponsorKey: SigningKeyPair? = nil
    ) throws -> RegisterMailboxConsumerRequest {
        guard (sponsorConsumerId == nil) == (sponsorKey == nil) else {
            throw CryptoError.invalidPayload
        }
        let draft = RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: consumerKey.publicKeyData,
            sponsorConsumerId: sponsorConsumerId,
            startingSequence: startingSequence
        )
        let authorityProof = try makeActorProof(signingKey: authorityKey) { proof in
            try draft.authoritySignableData(for: proof)
        }
        let consumerProof = try makeActorProof(signingKey: consumerKey) { proof in
            try draft.consumerSignableData(for: proof)
        }
        let sponsorProof = try sponsorKey.map { sponsorKey in
            try makeActorProof(signingKey: sponsorKey) { proof in
                try draft.sponsorSignableData(for: proof)
            }
        }
        return RegisterMailboxConsumerRequest(
            inboxId: inboxId,
            consumerId: consumerId,
            consumerSigningPublicKey: consumerKey.publicKeyData,
            sponsorConsumerId: sponsorConsumerId,
            startingSequence: startingSequence,
            authorityProof: authorityProof,
            consumerProof: consumerProof,
            sponsorProof: sponsorProof
        )
    }
}

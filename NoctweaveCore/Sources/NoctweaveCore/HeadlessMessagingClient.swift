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
    public let contact: Contact
    public let envelopeId: UUID
    public let messageCounter: UInt64
    public let descriptor: AttachmentDescriptor
    public let uploadedChunkCount: Int
    public let storedCount: Int

    public init(
        contact: Contact,
        envelopeId: UUID,
        messageCounter: UInt64,
        descriptor: AttachmentDescriptor,
        uploadedChunkCount: Int,
        storedCount: Int
    ) {
        self.contact = contact
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
    case inboundEnvelopeConflict(UUID)
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
        case .inboundEnvelopeConflict(let eventId):
            return "Inbound event `\(eventId.uuidString)` conflicts with a previously processed signed envelope. The mailbox cursor was not advanced."
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
        var state = try ClientState(
            identity: identity,
            relay: relay,
            inboxAccessKey: inboxAccessKey
        )
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

        let rotationContext = try state.identity.rotateKeys()

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
            guard contact.usesCertifiedInstallationEndpoint,
                  let installation = state.localInstallation else {
                throw HeadlessMessagingClientError.unsupportedInboundSession
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
            let eventId = UUID()
            let context = try MessageAuthenticatedContext.directV4(
                eventId: eventId,
                senderEndpoint: selected.localEndpoint,
                recipientEndpoint: peerEndpoint,
                pairwiseBinding: selected.binding
            )
            let envelope = try MessageEngine.encryptDirectV4(
                wirePayload: .control(.identityRotation(rotationContext.rotation)),
                senderSigningKey: installation.signingKey,
                senderFingerprint: selected.binding.localInstallationHandle.rawValue,
                conversation: &conversation,
                kemCiphertext: kemCiphertext,
                prekey: prekey,
                authenticatedContext: context,
                sentAt: mutationAt
            )
            conversation.markMessageProcessed()
            state.upsert(conversation: conversation)
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
                    signerPublicKey: installation.signingKey.publicKeyData
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
            throw IdentityProfileStateError.invalidCurrentState
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
            throw IdentityProfileStateError.invalidCurrentState
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
            guard contact.usesCertifiedInstallationEndpoint,
                  let installation = state.localInstallation else {
                throw HeadlessMessagingClientError.unsupportedInboundSession
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
            let envelope = try MessageEngine.encryptDirectV4(
                wirePayload: .control(.identityReset(reset)),
                senderSigningKey: installation.signingKey,
                senderFingerprint: selected.binding.localInstallationHandle.rawValue,
                conversation: &conversation,
                kemCiphertext: kemCiphertext,
                prekey: prekey,
                authenticatedContext: context,
                sentAt: staged.createdAt
            )
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
                    signerPublicKey: installation.signingKey.publicKeyData,
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
            throw IdentityProfileStateError.invalidCurrentState
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
        guard contact.usesCertifiedInstallationEndpoint,
              let installation = state.localInstallation else {
            throw HeadlessMessagingClientError.unsupportedInboundSession
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
        let envelope = try MessageEngine.encryptDirectV4(
            wirePayload: .application(event),
            senderSigningKey: installation.signingKey,
            senderFingerprint: binding.localInstallationHandle.rawValue,
            conversation: &conversation,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            authenticatedContext: context,
            sentAt: eventTimestamp
        )
        _ = MessageEngine.appendMessage(
            id: eventId,
            body: .text(text),
            direction: .sent,
            counter: envelope.messageCounter,
            timestamp: envelope.sentAt,
            conversation: &conversation
        )
        state.upsert(conversation: conversation)
        try persistDirectEvent(event, contact: contact, binding: binding, state: &state)

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
        let eventId = UUID()
        let clientTransactionId = UUID()
        guard contact.usesCertifiedInstallationEndpoint,
              let installation = state.localInstallation else {
            throw HeadlessMessagingClientError.unsupportedInboundSession
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
        let authenticatedContext = try MessageAuthenticatedContext.directV4(
            eventId: eventId,
            senderEndpoint: senderEndpoint,
            recipientEndpoint: peerEndpoint,
            pairwiseBinding: binding
        )
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
            authorInstallationHandle: binding.localInstallationHandle,
            createdAt: eventTimestamp,
            kind: .application,
            content: content
        )
        let envelope = try MessageEngine.encryptDirectV4(
            wirePayload: .application(event),
            senderSigningKey: installation.signingKey,
            senderFingerprint: binding.localInstallationHandle.rawValue,
            conversation: conversation,
            messageCounter: prepared.counter,
            messageKey: prepared.key,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            authenticatedContext: authenticatedContext,
            sentAt: eventTimestamp
        )
        _ = MessageEngine.appendMessage(
            id: eventId,
            body: .attachment(descriptor),
            direction: .sent,
            counter: envelope.messageCounter,
            timestamp: envelope.sentAt,
            conversation: &conversation,
            attachmentRelay: contact.relay,
            messageKey: prepared.key
        )
        state.upsert(conversation: conversation)
        try persistDirectEvent(event, contact: contact, binding: binding, state: &state)
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
                guard envelope.authenticatedContext?.purpose == .directV4 else {
                    throw HeadlessMessagingClientError.unsupportedInboundSession
                }
                if let message = try receiveCertifiedDirectEnvelope(envelope, state: &state) {
                    received.append(message)
                }
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
                throw IdentityProfileStateError.invalidCurrentState
            }
            _ = state.relationshipsV2[index].includeConversationIds([event.conversationId])
            guard state.relationshipsV2[index].appendEvent(event) else {
                throw IdentityProfileStateError.invalidCurrentState
            }
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
            throw IdentityProfileStateError.invalidCurrentState
        }
        guard var installation = state.localInstallation,
              installation.relationshipHandles[binding.relationshipId]
                .map({ $0 == binding.localInstallationHandle }) ?? true else {
            throw IdentityProfileStateError.invalidCurrentState
        }
        installation.relationshipHandles[binding.relationshipId]
            = binding.localInstallationHandle
        state.relationshipsV2.append(relationship)
        state.relationshipsV2.sort { $0.id.uuidString < $1.id.uuidString }
        state.localInstallation = installation
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
        let credential = try installation.ensureMailboxCredential(
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
        let request = try Self.makeMailboxConsumerRegistrationRequest(
            inboxId: state.inboxId,
            consumerId: credential.consumerId,
            startingSequence: startingSequence,
            authorityKey: accessKey,
            consumerKey: credential.signingKey
        )
        let response = try await relayClient(for: state.relay).send(
            .registerMailboxConsumer(request),
            timeout: timeout
        )
        guard response.type == .mailboxConsumer,
              let registration = response.mailboxConsumer,
              registration.consumerId == credential.consumerId,
              registration.consumerSigningPublicKey == credential.signingKey.publicKeyData,
              registration.state == .active else {
            throw HeadlessMessagingClientError.relayRejected(Self.redactedRelayRejection(response))
        }
        // The relay's idempotent registration response is the authoritative
        // recovery source after a lost response.
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
            throw IdentityProfileStateError.invalidCurrentState
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
            throw IdentityProfileStateError.invalidCurrentState
        }
        let encoded = try NoctweaveCoder.encode(pending.envelope, sortedKeys: true)
        let digest = Data(SHA256.hash(data: encoded))
        let target = Data(pending.contactId.uuidString.lowercased().utf8)
        if let existing = state.protocolIntents.first(where: { $0.id == pending.id }) {
            guard existing.kind == .sendEvent,
                  !existing.state.isTerminal,
                  existing.targetIdentifier == target,
                  existing.payloadDigest == digest else {
                throw IdentityProfileStateError.invalidCurrentState
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
            throw IdentityProfileStateError.invalidCurrentState
        }
        let prunedIds = Set(prunable.prefix(requiredPruneCount).map(\.id))
        state.protocolIntents.removeAll { prunedIds.contains($0.id) }
        guard state.protocolIntents.count
                < NoctweaveArchitectureV2.maximumProtocolIntents else {
            throw IdentityProfileStateError.invalidCurrentState
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
            throw IdentityProfileStateError.invalidCurrentState
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
    /// Rotation uses the same per-contact rule so peers cannot observe a
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
            throw IdentityProfileStateError.invalidCurrentState
        }

        if journal.phase == .prepared {
            guard let staged = journal.stagedBurn else {
                throw IdentityProfileStateError.invalidCurrentState
            }
            try await registerStagedIdentityRoute(staged)
            let transitionAt = max(Date(), journal.updatedAt)
            guard journal.markNewRouteReady(at: transitionAt) else {
                throw IdentityProfileStateError.invalidCurrentState
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
                throw IdentityProfileStateError.invalidCurrentState
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
                        throw IdentityProfileStateError.invalidCurrentState
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
            throw IdentityProfileStateError.invalidCurrentState
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
        guard let generationId = state.identityGenerationId,
              state.localInstallation != nil,
              let manifest = state.installationManifest,
              let endpoint = state.issuedContactEndpointsV2.last else {
            throw HeadlessMessagingClientError.missingInstallation
        }
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

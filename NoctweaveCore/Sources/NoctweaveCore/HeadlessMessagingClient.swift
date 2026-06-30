import Foundation

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
    case contactNotFound(String)
    case ambiguousContact(String)
    case relayRejected(String)
    case unsupportedInboundSession
}

extension HeadlessMessagingClientError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .stateAlreadyExists:
            return "Headless client state already exists. Use a different --state path or --overwrite true."
        case .missingState:
            return "Headless client state was not found. Run `NoctyraCLI init` first."
        case .missingInboxAccessKey:
            return "Headless client state is missing its inbox access key."
        case .contactNotFound(let selector):
            return "No contact matched `\(selector)`."
        case .ambiguousContact(let selector):
            return "More than one contact matched `\(selector)`. Use the contact UUID or fingerprint."
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

    public init(
        stateURL: URL,
        useEncryptedStore: Bool = false,
        authToken: String? = nil,
        timeout: TimeInterval = RelayClient.defaultTimeout
    ) {
        self.store = ClientStateStore(fileURL: stateURL, useEncryption: useEncryptedStore)
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
        let identity = Identity(displayName: displayName)
        let inboxAccessKey = SigningKeyPair()
        let inboxId = InboxAddress.derived(from: inboxAccessKey.publicKeyData)
        var state = ClientState(identity: identity, relay: relay, inboxId: inboxId)
        state.inboxAccessKey = inboxAccessKey
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
        let state = try await loadState()
        let accessKey = try inboxAccessKey(from: state)
        let offer = try MessageEngine.makeContactOffer(
            identity: state.identity,
            inboxId: state.inboxId,
            relay: state.relay,
            inboxAccessPublicKey: accessKey.publicKeyData
        )
        var request = RegisterInboxRequest(
            inboxId: state.inboxId,
            accessPublicKey: accessKey.publicKeyData,
            contactOffer: offer
        )
        let proof = try Self.makeActorProof(signingKey: accessKey) { actorProof in
            try request.signableData(for: actorProof)
        }
        request = RegisterInboxRequest(
            inboxId: state.inboxId,
            accessPublicKey: accessKey.publicKeyData,
            contactOffer: offer,
            accessProof: proof
        )
        let response = try await relayClient(for: state.relay).send(.registerInbox(request), timeout: timeout)
        try requireOK(response)
        try await store.save(state)
    }

    public func exportContactCode() async throws -> String {
        let state = try await loadState()
        let offer = try contactOffer(for: state)
        return try ContactOfferCode.encode(offer)
    }

    public func exportContactPackage(password: String) async throws -> Data {
        let state = try await loadState()
        return try ContactShare.encode(try contactOffer(for: state), password: password)
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

    public func rotateIdentity() async throws -> HeadlessIdentityChangeResult {
        var state = try await loadState()
        var previousIdentity = state.identity
        let rotationContext = try state.identity.rotateKeys()
        previousIdentity.signingKey = rotationContext.oldSigningKey
        previousIdentity.agreementKey = rotationContext.oldAgreementKey

        let oldFingerprint = rotationContext.oldFingerprint
        let newFingerprint = state.identity.fingerprint
        state.appendContinuityEvent(
            ContinuityEvent(
                kind: .identityRotated,
                oldFingerprint: oldFingerprint,
                newFingerprint: newFingerprint
            )
        )
        if let regenerated = try? PrekeyState.generate(identity: state.identity) {
            state.prekeys = regenerated
        }

        var rebuiltByContact: [UUID: Conversation] = [:]
        var notified: [String] = []
        var failed: [String] = []
        for contact in state.contacts {
            let existingConversation = state.conversation(for: contact.id)
            do {
                let bootstrapSession = try MessageEngine.createOutboundSession(
                    identity: previousIdentity,
                    contact: contact
                )
                var bootstrapConversation = bootstrapSession.conversation
                let envelope = try MessageEngine.encrypt(
                    body: .identityRotation(rotationContext.rotation),
                    senderSigningKey: rotationContext.oldSigningKey,
                    senderFingerprint: oldFingerprint,
                    conversation: &bootstrapConversation,
                    kemCiphertext: bootstrapSession.kemCiphertext
                )
                bootstrapConversation.markMessageProcessed()
                _ = try await deliver(envelope: envelope, to: contact, from: state)
                if let existingConversation {
                    bootstrapConversation.messages = existingConversation.messages
                    bootstrapConversation.unreadCount = existingConversation.unreadCount
                }
                rebuiltByContact[contact.id] = bootstrapConversation
                notified.append(contact.displayName)
            } catch {
                if let existingConversation {
                    rebuiltByContact[contact.id] = existingConversation
                }
                failed.append(contact.displayName)
            }
        }
        state.conversations = state.contacts.compactMap { rebuiltByContact[$0.id] }
        try await store.save(state)
        return HeadlessIdentityChangeResult(
            oldFingerprint: oldFingerprint,
            newFingerprint: newFingerprint,
            notifiedContacts: notified,
            failedContacts: failed
        )
    }

    public func burnIdentity() async throws -> HeadlessIdentityChangeResult {
        var state = try await loadState()
        let oldIdentity = state.identity
        let oldSigningKey = oldIdentity.signingKey
        let oldFingerprint = oldIdentity.fingerprint

        state.identity = Identity(displayName: oldIdentity.displayName)
        let newInboxAccessKey = SigningKeyPair()
        state.inboxAccessKey = newInboxAccessKey
        state.inboxId = InboxAddress.derived(from: newInboxAccessKey.publicKeyData)
        let newFingerprint = state.identity.fingerprint
        if let regenerated = try? PrekeyState.generate(identity: state.identity) {
            state.prekeys = regenerated
        }
        state.appendContinuityEvent(
            ContinuityEvent(
                kind: .identityBurned,
                oldFingerprint: oldFingerprint,
                newFingerprint: newFingerprint
            )
        )

        try await registerInbox(for: state)

        let retainedContacts = state.contacts.filter(\.allowIdentityReset)
        let newOffer = try contactOffer(for: state)
        var notified: [String] = []
        var failed: [String] = []
        for contact in retainedContacts {
            do {
                let reset = try IdentityReset.create(newOffer: newOffer, signingKey: oldSigningKey)
                let session = try MessageEngine.createOutboundSession(identity: oldIdentity, contact: contact)
                var conversation = session.conversation
                let envelope = try MessageEngine.encrypt(
                    body: .identityReset(reset),
                    senderSigningKey: oldSigningKey,
                    senderFingerprint: oldFingerprint,
                    conversation: &conversation,
                    kemCiphertext: session.kemCiphertext
                )
                conversation.markMessageProcessed()
                _ = try await deliver(envelope: envelope, to: contact, from: state)
                notified.append(contact.displayName)
            } catch {
                failed.append(contact.displayName)
            }
        }

        state.contacts = retainedContacts
        state.conversations = []
        state.groups = []
        try await store.save(state)
        return HeadlessIdentityChangeResult(
            oldFingerprint: oldFingerprint,
            newFingerprint: newFingerprint,
            notifiedContacts: notified,
            failedContacts: failed
        )
    }

    public func sendText(to selector: String, text: String) async throws -> HeadlessSentMessage {
        var state = try await loadState()
        let contact = try resolveContact(selector, in: state.contacts)
        var conversation: Conversation
        var kemCiphertext: Data?
        if let existing = state.conversation(for: contact.id) {
            conversation = existing
        } else {
            let session = try MessageEngine.createOutboundSession(identity: state.identity, contact: contact)
            conversation = session.conversation
            kemCiphertext = session.kemCiphertext
        }
        let envelope = try MessageEngine.encrypt(
            body: .text(text),
            senderSigningKey: state.identity.signingKey,
            senderFingerprint: state.identity.fingerprint,
            conversation: &conversation,
            kemCiphertext: kemCiphertext
        )
        _ = MessageEngine.appendMessage(
            body: .text(text),
            direction: .sent,
            counter: envelope.messageCounter,
            timestamp: envelope.sentAt,
            conversation: &conversation
        )
        state.upsert(conversation: conversation)

        let response = try await deliver(envelope: envelope, to: contact, from: state)
        try await store.save(state)
        return HeadlessSentMessage(
            contact: contact,
            envelopeId: envelope.id,
            messageCounter: envelope.messageCounter,
            storedCount: response.delivered?.storedCount ?? 0
        )
    }

    public func receive(maxCount: Int = 25, longPollTimeoutSeconds: Int? = nil, acknowledge: Bool = true) async throws -> [HeadlessReceivedMessage] {
        var state = try await loadState()
        let accessKey = try inboxAccessKey(from: state)
        var fetch = FetchRequest(
            inboxId: state.inboxId,
            routingToken: state.inboxId,
            maxCount: max(1, maxCount),
            longPollTimeoutSeconds: longPollTimeoutSeconds
        )
        let proof = try Self.makeActorProof(signingKey: accessKey) { actorProof in
            try fetch.signableData(for: actorProof)
        }
        fetch = FetchRequest(
            inboxId: state.inboxId,
            routingToken: state.inboxId,
            maxCount: max(1, maxCount),
            longPollTimeoutSeconds: longPollTimeoutSeconds,
            accessProof: proof
        )
        let response = try await relayClient(for: state.relay).send(.fetch(fetch), timeout: timeout + TimeInterval(longPollTimeoutSeconds ?? 0))
        guard response.type == .messages else {
            if response.type == .ok {
                return []
            }
            throw HeadlessMessagingClientError.relayRejected(response.error ?? response.type.rawValue)
        }

        var received: [HeadlessReceivedMessage] = []
        var acknowledgedIds: [UUID] = []
        for envelope in response.messages ?? [] {
            guard var contact = state.contact(for: envelope.senderFingerprint) else {
                continue
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
            let body: MessageBody
            do {
                body = try MessageEngine.decrypt(envelope: envelope, contact: contact, conversation: &conversation)
            } catch {
                guard let kemCiphertext = envelope.kemCiphertext else {
                    throw error
                }
                conversation = try MessageEngine.createInboundSession(
                    identity: state.identity,
                    contact: contact,
                    kemCiphertext: kemCiphertext
                )
                body = try MessageEngine.decrypt(envelope: envelope, contact: contact, conversation: &conversation)
                if let previousConversation {
                    conversation.messages = previousConversation.messages
                    conversation.unreadCount = previousConversation.unreadCount
                }
            }
            _ = MessageEngine.appendMessage(
                body: body,
                direction: .received,
                counter: envelope.messageCounter,
                timestamp: envelope.sentAt,
                conversation: &conversation
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
            acknowledgedIds.append(envelope.id)
            received.append(
                HeadlessReceivedMessage(
                    contact: contact,
                    envelopeId: envelope.id,
                    messageCounter: envelope.messageCounter,
                    body: body,
                    sentAt: envelope.sentAt
                )
            )
        }

        if acknowledge, !acknowledgedIds.isEmpty {
            try await acknowledgeMessages(acknowledgedIds, state: state, accessKey: accessKey)
        }
        try await store.save(state)
        return received
    }

    private func importContactOffer(_ offer: ContactOffer) async throws -> Contact {
        var state = try await loadState()
        let contact = try MessageEngine.contact(from: offer)
        state.upsert(contact: contact)
        try await store.save(state)
        return contact
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
        let offer = try MessageEngine.makeContactOffer(
            identity: state.identity,
            inboxId: state.inboxId,
            relay: state.relay,
            inboxAccessPublicKey: accessKey.publicKeyData
        )
        var request = RegisterInboxRequest(
            inboxId: state.inboxId,
            accessPublicKey: accessKey.publicKeyData,
            contactOffer: offer
        )
        let proof = try Self.makeActorProof(signingKey: accessKey) { actorProof in
            try request.signableData(for: actorProof)
        }
        request = RegisterInboxRequest(
            inboxId: state.inboxId,
            accessPublicKey: accessKey.publicKeyData,
            contactOffer: offer,
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
                    destinationRelay: contact.relay == state.relay ? nil : contact.relay
                )
            ),
            timeout: timeout
        )
        guard response.type == .delivered || response.type == .ok else {
            throw HeadlessMessagingClientError.relayRejected(response.error ?? response.type.rawValue)
        }
        return response
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
        try MessageEngine.makeContactOffer(
            identity: state.identity,
            inboxId: state.inboxId,
            relay: state.relay,
            inboxAccessPublicKey: state.inboxAccessKey?.publicKeyData
        )
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

    private func relayClient(for endpoint: RelayEndpoint) -> RelayClient {
        RelayClient(endpoint: endpoint, authToken: authToken)
    }

    private func requireOK(_ response: RelayResponse) throws {
        guard response.type == .ok || response.type == .delivered else {
            throw HeadlessMessagingClientError.relayRejected(response.error ?? response.type.rawValue)
        }
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
}

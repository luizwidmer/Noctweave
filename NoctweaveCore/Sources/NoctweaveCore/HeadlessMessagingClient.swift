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
    case contactNotFound(String)
    case ambiguousContact(String)
    case groupNotFound(String)
    case ambiguousGroup(String)
    case missingGroupRatchet(String)
    case missingGroupSenderKey(String)
    case attachmentNotFound(String)
    case missingAttachmentKey(String)
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
            return "Headless client state was not found. Run `NoctyraCLI init` first."
        case .missingInboxAccessKey:
            return "Headless client state is missing its inbox access key."
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
        case .attachmentNotFound(let selector):
            return "No attachment matched `\(selector)` in local state."
        case .missingAttachmentKey(let selector):
            return "Attachment `\(selector)` is missing local recovery metadata."
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
            throw HeadlessMessagingClientError.relayRejected(response.error ?? response.type.rawValue)
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

    public func sendAttachment(
        to selector: String,
        data: Data,
        fileName: String?,
        mimeType: String = "application/octet-stream",
        chunkSize: Int = 64 * 1024,
        ttlSeconds: Int? = nil
    ) async throws -> HeadlessSentAttachment {
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
        let envelope = try MessageEngine.encrypt(
            body: .attachment(descriptor),
            senderSigningKey: state.identity.signingKey,
            senderFingerprint: state.identity.fingerprint,
            conversation: conversation,
            messageCounter: prepared.counter,
            messageKey: prepared.key,
            kemCiphertext: kemCiphertext
        )
        _ = MessageEngine.appendMessage(
            body: .attachment(descriptor),
            direction: .sent,
            counter: envelope.messageCounter,
            timestamp: envelope.sentAt,
            conversation: &conversation,
            attachmentRelay: contact.relay,
            messageKey: prepared.key
        )
        state.upsert(conversation: conversation)
        let response = try await deliver(envelope: envelope, to: contact, from: state)
        try await store.save(state)
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
            throw HeadlessMessagingClientError.relayRejected(response.error ?? response.type.rawValue)
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
            throw HeadlessMessagingClientError.relayRejected(response.error ?? response.type.rawValue)
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
        let relay = info.relay ?? state.relay
        let messageKey = AttachmentCrypto.key(from: messageKeyData)
        var recovered = Data()
        for chunkIndex in 0..<info.descriptor.chunkCount {
            let response = try await relayClient(for: relay).send(
                .fetchAttachment(FetchAttachmentRequest(attachmentId: id, chunkIndex: chunkIndex)),
                timeout: timeout
            )
            guard response.type == .attachment, let chunk = response.attachment else {
                throw HeadlessMessagingClientError.relayRejected(response.error ?? response.type.rawValue)
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
            let plaintext = try AttachmentCrypto.decryptChunk(
                payload: chunk.payload,
                messageKey: messageKey,
                attachmentId: id,
                chunkIndex: chunkIndex,
                authenticatedData: aad
            )
            recovered.append(plaintext)
        }
        guard recovered.count == info.descriptor.byteCount,
              AttachmentCrypto.sha256(recovered) == info.descriptor.sha256 else {
            throw HeadlessMessagingClientError.attachmentDigestMismatch(id.uuidString)
        }
        return HeadlessFetchedAttachment(descriptor: info.descriptor, data: recovered)
    }

    public func receiveGroupMessages(
        group selector: String? = nil,
        maxCount: Int = 25,
        longPollTimeoutSeconds: Int? = nil,
        acknowledge: Bool = true
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
                throw HeadlessMessagingClientError.relayRejected(response.error ?? response.type.rawValue)
            }
            var acknowledgedIds: [UUID] = []
            for envelope in response.groupMessages ?? [] {
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
                acknowledgedIds.append(envelope.id)
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
            if acknowledge, !acknowledgedIds.isEmpty {
                try await acknowledgeGroupMessages(acknowledgedIds, group: group, state: state)
            }
        }
        try await store.save(state)
        return received
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
            _ = MessageEngine.appendMessage(
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
            throw HeadlessMessagingClientError.relayRejected(response.error ?? response.type.rawValue)
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
        return GroupConversation(
            id: descriptor.id,
            title: descriptor.title,
            memberContactIds: contacts.map(\.id),
            relayInboxId: descriptor.inboxId,
            relayEpoch: descriptor.epoch,
            relayTranscriptHash: descriptor.mlsEpochState.confirmedTranscriptHash,
            groupRatchetState: ratchetState,
            createdByFingerprint: descriptor.createdByFingerprint,
            memberProfiles: groupMemberProfiles(from: descriptor, preferredRelay: state.relay),
            messages: existing?.messages ?? [],
            unreadCount: existing?.unreadCount ?? 0,
            createdAt: existing?.createdAt ?? descriptor.createdAt
        )
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
                throw HeadlessMessagingClientError.relayRejected(response.error ?? response.type.rawValue)
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
        let safeChunkSize = max(1, min(chunkSize, 64 * 1024))
        let attachmentId = UUID()
        let chunkCount = data.isEmpty ? 0 : Int(ceil(Double(data.count) / Double(safeChunkSize)))
        let descriptor = AttachmentDescriptor(
            id: attachmentId,
            fileName: nil,
            mimeType: mimeType.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                ? "application/octet-stream"
                : mimeType,
            byteCount: data.count,
            sha256: AttachmentCrypto.sha256(data),
            chunkCount: chunkCount,
            chunkSize: safeChunkSize,
            relayTTLSeconds: relayTTLSeconds
        )
        var chunks: [AttachmentChunk] = []
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
            let payload = try AttachmentCrypto.encryptChunk(
                plaintext: Data(plaintext),
                messageKey: messageKey,
                attachmentId: attachmentId,
                chunkIndex: chunkIndex,
                authenticatedData: aad
            )
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

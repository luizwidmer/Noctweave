import CryptoKit
import Foundation

public enum RelayCertificatePinOrigin: String, Codable, Equatable {
    case automaticFirstUse
    case manual
}

public struct RelayCertificatePinRecord: Codable, Equatable, Identifiable {
    public var host: String
    public var port: UInt16
    public var useTLS: Bool
    public var transport: RelayEndpointTransport
    public var fingerprintSHA256: Data
    public var pinnedAt: Date
    public var origin: RelayCertificatePinOrigin

    public var id: String {
        "\(transport.rawValue):\(useTLS ? "tls" : "plain"):\(host.lowercased()):\(port)"
    }

    public init(
        host: String,
        port: UInt16,
        useTLS: Bool,
        transport: RelayEndpointTransport,
        fingerprintSHA256: Data,
        pinnedAt: Date = Date(),
        origin: RelayCertificatePinOrigin
    ) {
        self.host = host
        self.port = port
        self.useTLS = useTLS
        self.transport = transport
        self.fingerprintSHA256 = fingerprintSHA256
        self.pinnedAt = pinnedAt
        self.origin = origin
    }
}

public struct ClientState: Codable {
    public var schemaVersion: Int
    public var identityProfiles: [IdentityProfile]
    public var activeIdentityId: UUID
    public var relayServers: [RelayServerRecord]
    public var masterServerSources: [MasterServerSource]
    public var appearance: AppearanceSettings
    public var privacy: PrivacySettings
    public var appLock: AppLockSettings
    public var chatList: ChatListSettings
    public var relayCertificatePins: [RelayCertificatePinRecord]
    public var hasCompletedOnboarding: Bool
    public var hasAcceptedPrivacyPolicy: Bool
    public var hasAcceptedTermsOfUse: Bool
    public var prekeys: PrekeyState {
        get { activeProfile.prekeys }
        set { updateActiveProfile { $0.prekeys = newValue } }
    }

    public var localEndpoint: LocalEndpointState? {
        get { activeProfile.localEndpoint }
        set { updateActiveProfile { $0.localEndpoint = newValue } }
    }

    public var endpointSetManifest: EndpointSetManifest? {
        get { activeProfile.endpointSetManifest }
        set { updateActiveProfile { $0.endpointSetManifest = newValue } }
    }

    public var issuedContactEndpointsV2: [CertifiedGenerationEndpoint] {
        get { activeProfile.issuedContactEndpointsV2 }
        set {
            updateActiveProfile {
                $0.issuedContactEndpointsV2 = Array(
                    newValue.suffix(NoctweaveArchitectureV2.maximumIssuedContactEndpoints)
                )
            }
        }
    }

    public var identityGenerationId: UUID? {
        activeProfile.identityGenerationId
    }

    public var identity: Identity {
        get { activeProfile.identity }
        set { updateActiveProfile { $0.identity = newValue } }
    }

    public var relay: RelayEndpoint {
        get { activeProfile.relay }
        set { updateActiveProfile { $0.relay = newValue } }
    }

    public var inboxId: String {
        get { activeProfile.inboxId }
        set { updateActiveProfile { $0.inboxId = newValue } }
    }

    public var inboxAccessKey: SigningKeyPair? {
        get { activeProfile.inboxAccessKey }
        set { updateActiveProfile { $0.inboxAccessKey = newValue } }
    }

    public var contacts: [Contact] {
        get { activeProfile.contacts }
        set { updateActiveProfile { $0.contacts = newValue } }
    }

    public var conversations: [Conversation] {
        get { activeProfile.conversations }
        set { updateActiveProfile { $0.conversations = newValue } }
    }

    public var groupRuntimes: [GroupRuntimeRecord] {
        get { activeProfile.groupRuntimes }
        set { updateActiveProfile { $0.groupRuntimes = newValue } }
    }

    public var pendingDirectDeliveries: [PendingDirectDelivery] {
        get { activeProfile.pendingDirectDeliveries }
        set { updateActiveProfile { $0.pendingDirectDeliveries = newValue } }
    }

    public var protocolIntents: [ProtocolIntentV2] {
        get { activeProfile.protocolIntents }
        set { updateActiveProfile { $0.protocolIntents = newValue } }
    }

    public var inboundEnvelopeReceiptsV2: [InboundEnvelopeReceiptV2] {
        get { activeProfile.inboundEnvelopeReceiptsV2 }
        set { updateActiveProfile { $0.inboundEnvelopeReceiptsV2 = newValue } }
    }

    public var quarantinedTransportEnvelopesV2: [QuarantinedTransportEnvelopeV2] {
        get { activeProfile.quarantinedTransportEnvelopesV2 }
        set {
            updateActiveProfile {
                $0.quarantinedTransportEnvelopesV2 = Array(
                    newValue.suffix(
                        NoctweaveArchitectureV2.maximumQuarantinedTransportEnvelopes
                    )
                )
            }
        }
    }

    public var relationshipsV2: [RelationshipStateV2] {
        get { activeProfile.relationshipsV2 }
        set { updateActiveProfile { $0.relationshipsV2 = newValue } }
    }

    public var quarantinedControlEvents: [QuarantinedControlEvent] {
        get { activeProfile.quarantinedControlEvents }
        set {
            updateActiveProfile {
                $0.quarantinedControlEvents = Array(
                    newValue.suffix(NoctweaveArchitectureV2.maximumQuarantinedControlEvents)
                )
            }
        }
    }

    public var selfSyncV2: SelfSyncLocalStateV2? {
        get { activeProfile.selfSyncV2 }
        set { updateActiveProfile { $0.selfSyncV2 = newValue } }
    }

    public var identityMutationV2: IdentityMutationJournalV2? {
        get { activeProfile.identityMutationV2 }
        set { updateActiveProfile { $0.identityMutationV2 = newValue } }
    }

    public var federationPolicy: FederationDescriptor? {
        get { activeProfile.federationPolicy }
        set { updateActiveProfile { $0.federationPolicy = newValue } }
    }

    public var selectedRelayId: UUID? {
        get { activeProfile.selectedRelayId }
        set { updateActiveProfile { $0.selectedRelayId = newValue } }
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case identityProfiles
        case activeIdentityId
        case relayServers
        case masterServerSources
        case appearance
        case privacy
        case appLock
        case chatList
        case relayCertificatePins
        case hasCompletedOnboarding
        case hasAcceptedPrivacyPolicy
        case hasAcceptedTermsOfUse
    }

    public init(
        identity: Identity,
        relay: RelayEndpoint,
        inboxAccessKey: SigningKeyPair,
        relayServers: [RelayServerRecord] = [],
        selectedRelayId: UUID? = nil,
        masterServerSources: [MasterServerSource] = [],
        appearance: AppearanceSettings = AppearanceSettings(),
        privacy: PrivacySettings = PrivacySettings(),
        appLock: AppLockSettings = AppLockSettings(),
        chatList: ChatListSettings = ChatListSettings(),
        relayCertificatePins: [RelayCertificatePinRecord] = [],
        hasCompletedOnboarding: Bool = true,
        hasAcceptedPrivacyPolicy: Bool = true,
        hasAcceptedTermsOfUse: Bool = true,
        prekeys: PrekeyState? = nil
    ) throws {
        let profile = try IdentityProfile.create(
            identity: identity,
            relay: relay,
            inboxAccessKey: inboxAccessKey,
            selectedRelayId: selectedRelayId,
            prekeys: prekeys
        )
        self.schemaVersion = NoctweaveArchitectureV2.version
        self.identityProfiles = [profile]
        self.activeIdentityId = profile.id
        self.relayServers = relayServers
        self.masterServerSources = masterServerSources
        self.appearance = appearance
        self.privacy = privacy
        self.appLock = appLock
        self.chatList = chatList
        self.relayCertificatePins = Self.sanitizedRelayCertificatePins(relayCertificatePins)
        self.hasCompletedOnboarding = hasCompletedOnboarding
        self.hasAcceptedPrivacyPolicy = hasAcceptedPrivacyPolicy
        self.hasAcceptedTermsOfUse = hasAcceptedTermsOfUse
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        guard schemaVersion == NoctweaveArchitectureV2.version else {
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion,
                in: container,
                debugDescription: "Unsupported client state schema"
            )
        }
        relayServers = try container.decode([RelayServerRecord].self, forKey: .relayServers)
        masterServerSources = try container.decode([MasterServerSource].self, forKey: .masterServerSources)
        appearance = try container.decode(AppearanceSettings.self, forKey: .appearance)
        privacy = try container.decode(PrivacySettings.self, forKey: .privacy)
        appLock = try container.decode(AppLockSettings.self, forKey: .appLock)
        chatList = try container.decode(ChatListSettings.self, forKey: .chatList)
        relayCertificatePins = Self.sanitizedRelayCertificatePins(
            try container.decode([RelayCertificatePinRecord].self, forKey: .relayCertificatePins)
        )
        hasCompletedOnboarding = try container.decode(Bool.self, forKey: .hasCompletedOnboarding)
        hasAcceptedPrivacyPolicy = try container.decode(Bool.self, forKey: .hasAcceptedPrivacyPolicy)
        hasAcceptedTermsOfUse = try container.decode(Bool.self, forKey: .hasAcceptedTermsOfUse)
        let profiles = try container.decode([IdentityProfile].self, forKey: .identityProfiles)
        guard !profiles.isEmpty else {
            throw DecodingError.dataCorruptedError(
                forKey: .identityProfiles,
                in: container,
                debugDescription: "Client state must contain at least one identity profile."
            )
        }
        identityProfiles = profiles
        activeIdentityId = try container.decode(UUID.self, forKey: .activeIdentityId)
        guard isCurrentBaselineValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .identityProfiles,
                in: container,
                debugDescription: "Invalid current client state"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isCurrentBaselineValid else {
            throw ClientStateError.invalidCurrentState
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(identityProfiles, forKey: .identityProfiles)
        try container.encode(activeIdentityId, forKey: .activeIdentityId)
        try container.encode(relayServers, forKey: .relayServers)
        try container.encode(masterServerSources, forKey: .masterServerSources)
        try container.encode(appearance, forKey: .appearance)
        try container.encode(privacy, forKey: .privacy)
        try container.encode(appLock, forKey: .appLock)
        try container.encode(chatList, forKey: .chatList)
        try container.encode(relayCertificatePins, forKey: .relayCertificatePins)
        try container.encode(hasCompletedOnboarding, forKey: .hasCompletedOnboarding)
        try container.encode(hasAcceptedPrivacyPolicy, forKey: .hasAcceptedPrivacyPolicy)
        try container.encode(hasAcceptedTermsOfUse, forKey: .hasAcceptedTermsOfUse)
    }

    public var isCurrentBaselineValid: Bool {
        schemaVersion == NoctweaveArchitectureV2.version
            && !identityProfiles.isEmpty
            && Set(identityProfiles.map(\.id)).count == identityProfiles.count
            && identityProfiles.contains(where: { $0.id == activeIdentityId })
            && identityProfiles.allSatisfy(\.isArchitectureV2Ready)
    }

    private static func sanitizedRelayCertificatePins(
        _ records: [RelayCertificatePinRecord]
    ) -> [RelayCertificatePinRecord] {
        var byID: [String: RelayCertificatePinRecord] = [:]
        for record in records.prefix(256) where
            record.useTLS
                && record.port > 0
                && !record.host.isEmpty
                && record.host.utf8.count <= 253
                && record.fingerprintSHA256.count == 32
                && record.pinnedAt.timeIntervalSince1970.isFinite {
            byID[record.id] = record
        }
        return byID.values.sorted { $0.id < $1.id }
    }

    public mutating func upsert(contact: Contact) {
        let mergedAddressKey = contactAddressKey(relay: contact.relay, inboxId: contact.inboxId)
        let primaryIndex: Int?
        if let index = contacts.firstIndex(where: { $0.id == contact.id }) {
            primaryIndex = index
        } else if let index = contacts.firstIndex(where: { $0.fingerprint == contact.fingerprint }) {
            primaryIndex = index
        } else if let mergedAddressKey,
                  let index = contacts.firstIndex(where: { existing in
                      contactAddressKey(relay: existing.relay, inboxId: existing.inboxId) == mergedAddressKey
                  }) {
            primaryIndex = index
        } else {
            primaryIndex = nil
        }

        guard let primaryIndex else {
            contacts.append(contact)
            return
        }

        let merged = mergeContact(existing: contacts[primaryIndex], incoming: contact)
        contacts[primaryIndex] = merged

        var duplicateIndices: [Int] = []
        var duplicateIds: [UUID] = []
        for (index, existing) in contacts.enumerated() where index != primaryIndex {
            let sameFingerprint = existing.fingerprint == merged.fingerprint
            let sameAddress = {
                guard let canonicalAddress = contactAddressKey(relay: merged.relay, inboxId: merged.inboxId) else {
                    return false
                }
                return contactAddressKey(relay: existing.relay, inboxId: existing.inboxId) == canonicalAddress
            }()
            if sameFingerprint || sameAddress {
                duplicateIndices.append(index)
                duplicateIds.append(existing.id)
            }
        }

        if !duplicateIndices.isEmpty {
            for index in duplicateIndices.sorted(by: >) {
                contacts.remove(at: index)
            }
            remapContactReferences(from: duplicateIds, to: merged.id)
        }
    }

    public mutating func upsert(conversation: Conversation) {
        if let index = conversations.firstIndex(where: {
            $0.contactId == conversation.contactId
                && $0.endpointSession == conversation.endpointSession
        }) {
            conversations[index] = conversation
        } else {
            conversations.append(conversation)
        }
    }

    public mutating func upsert(groupRuntime: GroupRuntimeRecord) throws {
        guard groupRuntime.isStructurallyValid else {
            throw ClientStateError.invalidCurrentState
        }
        if let index = groupRuntimes.firstIndex(where: { $0.id == groupRuntime.id }) {
            groupRuntimes[index] = groupRuntime
        } else {
            guard groupRuntimes.count < IdentityProfile.maximumGroupRuntimes else {
                throw ClientStateError.invalidCurrentState
            }
            groupRuntimes.append(groupRuntime)
        }
    }

    public mutating func mergeUpsert(conversation incoming: Conversation) {
        if let index = conversations.firstIndex(where: {
            $0.contactId == incoming.contactId
                && $0.endpointSession == incoming.endpointSession
        }) {
            var merged = incoming
            merged.messages = mergedMessages(conversations[index].messages, incoming.messages)
            merged.unreadCount = max(conversations[index].unreadCount, incoming.unreadCount)
            conversations[index] = merged
        } else {
            conversations.append(incoming)
        }
    }

    public func contact(for fingerprint: String) -> Contact? {
        contacts.first { $0.fingerprint == fingerprint }
    }

    public func resolveCertifiedDirectContext(
        _ direct: DirectEnvelopeV4
    ) -> (
        contact: Contact,
        localEndpoint: CertifiedGenerationEndpoint,
        binding: PairwiseEndpointBindingV4
    )? {
        var matches: [(Contact, CertifiedGenerationEndpoint, PairwiseEndpointBindingV4)] = []
        for contact in contacts {
            guard let peerEndpoint = try? contact.certifiedGenerationEndpoint() else { continue }
            for localEndpoint in issuedContactEndpointsV2 {
                guard let binding = try? PairwiseEndpointBindingV4.derive(
                    localIdentityGenerationId: localEndpoint.identityGenerationId,
                    localIdentitySigningPublicKey: localEndpoint.identityAuthorityPublicKey,
                    localEndpoint: localEndpoint,
                    peerIdentityGenerationId: peerEndpoint.identityGenerationId,
                    peerIdentitySigningPublicKey: peerEndpoint.identityAuthorityPublicKey,
                    peerEndpoint: peerEndpoint
                ) else { continue }
                if binding.peerEndpointHandle == direct.senderEndpointHandle,
                   binding.peerCertificateReferenceDigest == direct.senderCertificateDigest,
                   peerEndpoint.manifestEpoch == direct.senderEndpointSetEpoch,
                   binding.localEndpointHandle == direct.recipientEndpointHandle,
                   binding.localCertificateReferenceDigest == direct.recipientCertificateDigest,
                   localEndpoint.manifestEpoch == direct.recipientEndpointSetEpoch {
                    matches.append((contact, localEndpoint, binding))
                }
            }
        }
        return matches.count == 1 ? matches[0] : nil
    }

    public func conversation(
        for contactId: UUID,
        endpointSession: DirectEndpointSessionIdentity
    ) -> Conversation? {
        conversations.first {
            $0.contactId == contactId && $0.endpointSession == endpointSession
        }
    }

    public func conversation(for contactId: UUID) -> Conversation? {
        let matches = conversations.filter { $0.contactId == contactId }
        if matches.count <= 1 {
            return matches.first
        }
        return matches.max(by: { lhs, rhs in
            let leftDate = lhs.messages.last?.timestamp ?? Date.distantPast
            let rightDate = rhs.messages.last?.timestamp ?? Date.distantPast
            if leftDate != rightDate {
                return leftDate < rightDate
            }
            return lhs.receiveChain.counter < rhs.receiveChain.counter
        })
    }

    public func groupRuntime(for groupId: UUID) -> GroupRuntimeRecord? {
        groupRuntimes.first(where: { $0.id == groupId })
    }

    public mutating func updateConversation(_ conversation: Conversation) {
        if let index = conversations.firstIndex(where: {
            $0.contactId == conversation.contactId
                && $0.endpointSession == conversation.endpointSession
        }) {
            conversations[index] = conversation
        }
    }

    public mutating func updateGroupRuntime(_ groupRuntime: GroupRuntimeRecord) throws {
        try upsert(groupRuntime: groupRuntime)
    }

    public mutating func updateContact(_ contact: Contact) {
        upsert(contact: contact)
    }

    public func identityProfile(id: UUID) -> IdentityProfile? {
        identityProfiles.first { $0.id == id }
    }

    public mutating func updateIdentityProfile(_ profile: IdentityProfile) {
        if let index = identityProfiles.firstIndex(where: { $0.id == profile.id }) {
            identityProfiles[index] = profile
        }
    }

    public mutating func appendContinuityEvent(_ event: ContinuityEvent, profileId: UUID? = nil) {
        let targetId = profileId ?? activeIdentityId
        guard let index = identityProfiles.firstIndex(where: { $0.id == targetId }) else {
            return
        }
        identityProfiles[index].continuityEvents.append(event)
    }

    public mutating func purgeContinuityEvents(profileId: UUID? = nil) {
        let targetId = profileId ?? activeIdentityId
        guard let index = identityProfiles.firstIndex(where: { $0.id == targetId }) else {
            return
        }
        identityProfiles[index].continuityEvents.removeAll()
    }

    /// Atomically promotes a previously registered burn generation. Until this
    /// mutation is durably saved, the old identity remains the active profile.
    public mutating func cutOverStagedIdentityBurn(at date: Date = Date()) throws {
        guard let index = identityProfiles.firstIndex(where: { $0.id == activeIdentityId }),
              var journal = identityProfiles[index].identityMutationV2,
              journal.kind == .burn,
              journal.phase == .newRouteReady,
              journal.isStructurallyValid,
              identityProfiles[index].identity.fingerprint == journal.oldFingerprint,
              let staged = journal.stagedBurn,
              staged.isStructurallyValid,
              date.timeIntervalSince1970.isFinite,
              date >= journal.updatedAt else {
            throw IdentityProfileStateError.invalidCurrentState
        }
        let stagedDeliveries = journal.notifications.compactMap(\.stagedDelivery)
        guard stagedDeliveries.count == journal.notifications.count,
              Set(stagedDeliveries.map(\.id)).count == stagedDeliveries.count else {
            throw IdentityProfileStateError.invalidCurrentState
        }

        let retainedContactIds = Set(journal.notifications.map(\.contactId))
        var profile = identityProfiles[index]
        profile.identity = staged.identity
        profile.prekeys = staged.prekeys
        profile.architectureVersion = NoctweaveArchitectureV2.version
        profile.identityGenerationId = staged.identityGenerationId
        profile.localEndpoint = staged.localEndpoint
        profile.endpointSetManifest = staged.endpointSetManifest
        profile.issuedContactEndpointsV2 = staged.issuedContactEndpointsV2
        profile.selfSyncV2 = staged.selfSync
        profile.inboxId = staged.inboxId
        profile.inboxAccessKey = staged.inboxAccessKey
        profile.relay = staged.relay
        profile.contacts = profile.contacts.filter { retainedContactIds.contains($0.id) }
        profile.conversations.removeAll()
        profile.groupRuntimes.removeAll()
        profile.pendingDirectDeliveries = stagedDeliveries
        profile.deliveryStates.removeAll()
        profile.inboundEnvelopeReceiptsV2.removeAll()
        profile.quarantinedTransportEnvelopesV2.removeAll()
        profile.quarantinedControlEvents.removeAll()
        profile.relationshipsV2.removeAll()
        profile.protocolIntents = try stagedDeliveries.map { delivery in
            let encodedEnvelope = try NoctweaveCoder.encode(delivery.envelope, sortedKeys: true)
            return ProtocolIntentV2.prepare(
                id: delivery.id,
                kind: .sendEvent,
                targetIdentifier: Data(delivery.contactId.uuidString.lowercased().utf8),
                payloadDigest: Data(SHA256.hash(data: encodedEnvelope)),
                createdAt: delivery.queuedAt
            )
        }
        // A burn is a severance boundary, including in local state. Selected
        // contacts receive exact old-authorized reset ciphertexts, but the new
        // generation must not retain a general old-to-new audit link.
        profile.continuityEvents.removeAll()
        guard journal.markCutoverComplete(at: date) else {
            throw IdentityProfileStateError.invalidCurrentState
        }
        profile.identityMutationV2 = journal
        identityProfiles[index] = profile
        guard identityProfiles[index].isArchitectureV2Ready else {
            throw IdentityProfileStateError.invalidCurrentState
        }
    }

    public mutating func resignEndpointSetManifestAfterIdentityRotation(
        at date: Date = Date()
    ) throws {
        guard let index = identityProfiles.firstIndex(where: { $0.id == activeIdentityId }),
              let generationId = identityProfiles[index].identityGenerationId,
              let localEndpoint = identityProfiles[index].localEndpoint,
              let current = identityProfiles[index].endpointSetManifest,
              let localRecord = current.endpoints.first(where: {
                  $0.id == localEndpoint.id
              }),
              current.isStructurallyValid,
              current.identityGenerationId == generationId,
              localEndpoint.identityGenerationId == generationId,
              localRecord.identityGenerationId == generationId,
              localRecord.signingPublicKey == localEndpoint.signingKey.publicKeyData,
              localRecord.agreementPublicKey == localEndpoint.agreementKey.publicKeyData,
              localRecord.isActive(at: date, manifestEpoch: current.epoch),
              date.timeIntervalSince1970.isFinite,
              date >= current.issuedAt,
              let previousDigest = current.digest,
              current.epoch < UInt64.max else {
            throw IdentityProfileStateError.invalidCurrentState
        }
        identityProfiles[index].endpointSetManifest = try EndpointSetManifest.create(
            identityGenerationId: generationId,
            epoch: current.epoch + 1,
            previousManifestDigest: previousDigest,
            endpoints: current.endpoints,
            identity: identityProfiles[index].identity,
            issuedAt: date
        )
    }
}

public enum ClientStateError: Error, Equatable {
    case invalidCurrentState
}

fileprivate extension ClientState {
    func activeProfileIndex() -> Int {
        guard let index = identityProfiles.firstIndex(where: { $0.id == activeIdentityId }) else {
            preconditionFailure("Client state has no active current-generation profile")
        }
        return index
    }

    var activeProfile: IdentityProfile {
        get {
            identityProfiles[activeProfileIndex()]
        }
        set {
            var profiles = identityProfiles
            let index = activeProfileIndex()
            if profiles.indices.contains(index) {
                profiles[index] = newValue
                identityProfiles = profiles
                activeIdentityId = newValue.id
            }
        }
    }

    mutating func updateActiveProfile(_ update: (inout IdentityProfile) -> Void) {
        let index = activeProfileIndex()
        guard identityProfiles.indices.contains(index) else {
            return
        }
        var profile = identityProfiles[index]
        update(&profile)
        identityProfiles[index] = profile
        activeIdentityId = profile.id
    }

    func contactAddressKey(relay: RelayEndpoint, inboxId: String) -> String? {
        let normalizedInbox = inboxId
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard !normalizedInbox.isEmpty else {
            return nil
        }
        let normalizedHost = relay.host
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            .lowercased()
        return "\(normalizedHost):\(relay.port):\(relay.useTLS ? 1 : 0):\(relay.transport.rawValue):\(normalizedInbox)"
    }

    func mergeContact(existing: Contact, incoming: Contact) -> Contact {
        let trimmedName = incoming.displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedName = trimmedName.isEmpty ? existing.displayName : trimmedName
        let keysChanged = incoming.signingPublicKey != existing.signingPublicKey
            || incoming.agreementPublicKey != existing.agreementPublicKey
        let mergedCounter = keysChanged
            ? incoming.rotationCounter
            : max(existing.rotationCounter, incoming.rotationCounter)

        var trustById: [UUID: ContactTrustAssertion] = [:]
        for assertion in existing.trustAssertions {
            trustById[assertion.id] = assertion
        }
        for assertion in incoming.trustAssertions {
            trustById[assertion.id] = assertion
        }
        let mergedTrust = trustById.values.sorted { lhs, rhs in
            if lhs.timestamp != rhs.timestamp {
                return lhs.timestamp < rhs.timestamp
            }
            return lhs.id.uuidString < rhs.id.uuidString
        }

        return Contact(
            id: existing.id,
            displayName: resolvedName,
            inboxId: incoming.inboxId,
            relay: incoming.relay,
            signingPublicKey: incoming.signingPublicKey,
            agreementPublicKey: incoming.agreementPublicKey,
            identityGenerationId: incoming.identityGenerationId,
            endpointSetCheckpoint: incoming.endpointSetCheckpoint,
            preferredGenerationEndpoint: incoming.preferredGenerationEndpoint,
            endpointAuthoritySigningPublicKey: incoming.endpointAuthoritySigningPublicKey,
            preferredEndpointRevocation: incoming.preferredEndpointRevocation
                ?? existing.preferredEndpointRevocation,
            rotationCounter: mergedCounter,
            allowIdentityReset: existing.allowIdentityReset || incoming.allowIdentityReset,
            trustAssertions: mergedTrust
        )
    }

    mutating func remapContactReferences(from oldIds: [UUID], to newId: UUID) {
        let staleIds = Set(oldIds.filter { $0 != newId })
        guard !staleIds.isEmpty else {
            return
        }

        var rebuiltConversations: [Conversation] = []
        for conversation in conversations {
            let resolvedContactId = staleIds.contains(conversation.contactId) ? newId : conversation.contactId
            let adjusted = conversation.withContactId(resolvedContactId)
            if let index = rebuiltConversations.firstIndex(where: { $0.contactId == resolvedContactId }) {
                rebuiltConversations[index] = preferredConversation(
                    existing: rebuiltConversations[index],
                    candidate: adjusted
                )
            } else {
                rebuiltConversations.append(adjusted)
            }
        }
        conversations = rebuiltConversations

    }

    func preferredConversation(existing: Conversation, candidate: Conversation) -> Conversation {
        let existingDate = existing.messages.last?.timestamp ?? Date.distantPast
        let candidateDate = candidate.messages.last?.timestamp ?? Date.distantPast
        if existingDate != candidateDate {
            return candidateDate > existingDate ? candidate : existing
        }
        if existing.receiveChain.counter != candidate.receiveChain.counter {
            return candidate.receiveChain.counter > existing.receiveChain.counter ? candidate : existing
        }
        return existing.id <= candidate.id ? existing : candidate
    }

    func mergedMessages(_ messageSets: [Message]...) -> [Message] {
        var byId: [UUID: Message] = [:]
        for messages in messageSets {
            for message in messages {
                byId[message.id] = message
            }
        }
        return byId.values.sorted { lhs, rhs in
            if lhs.timestamp != rhs.timestamp {
                return lhs.timestamp < rhs.timestamp
            }
            if lhs.counter != rhs.counter {
                return lhs.counter < rhs.counter
            }
            return lhs.id.uuidString < rhs.id.uuidString
        }
    }
}

private extension Conversation {
    func withContactId(_ contactId: UUID) -> Conversation {
        guard self.contactId != contactId else {
            return self
        }
        return Conversation(
            id: id,
            contactId: contactId,
            endpointSession: endpointSession.map {
                DirectEndpointSessionIdentity(
                    contactId: contactId,
                    localEndpointId: $0.localEndpointId,
                    localEndpointHandle: $0.localEndpointHandle,
                    localCertificateReferenceDigest: $0.localCertificateReferenceDigest,
                    localManifestEpoch: $0.localManifestEpoch,
                    peerEndpointId: $0.peerEndpointId,
                    peerEndpointHandle: $0.peerEndpointHandle,
                    peerCertificateReferenceDigest: $0.peerCertificateReferenceDigest,
                    peerManifestEpoch: $0.peerManifestEpoch
                )
            },
            sessionId: sessionId,
            rootKey: rootKey,
            rootCounter: rootCounter,
            sendChain: sendChain,
            receiveChain: receiveChain,
            messages: messages,
            unreadCount: unreadCount,
            ratchetState: ratchetState
        )
    }
}

public enum ThemePaletteFamily: Codable, Equatable {
    case glacier
    case sunset
    case forest
    case citrus
    case slate
    case aurora
    case ember
    case cobalt
    case orchid
    case dune
    case noir
    case prism
    case weave
    case abyss
    case pearl
}

public enum ThemePalette: String, Codable, CaseIterable, Identifiable {
    case glacier
    case glacierDark
    case sunset
    case sunsetDark
    case forest
    case forestDark
    case citrus
    case citrusDark
    case slate
    case slateDark
    case aurora
    case auroraDark
    case ember
    case emberDark
    case cobalt
    case cobaltDark
    case orchid
    case orchidDark
    case dune
    case duneDark
    case noir
    case noirBright
    case prism
    case prismDark
    case weave
    case weaveDark
    case abyss
    case abyssDark
    case pearl
    case pearlDark

    public var id: String { rawValue }

    public var family: ThemePaletteFamily {
        switch self {
        case .glacier, .glacierDark: return .glacier
        case .sunset, .sunsetDark: return .sunset
        case .forest, .forestDark: return .forest
        case .citrus, .citrusDark: return .citrus
        case .slate, .slateDark: return .slate
        case .aurora, .auroraDark: return .aurora
        case .ember, .emberDark: return .ember
        case .cobalt, .cobaltDark: return .cobalt
        case .orchid, .orchidDark: return .orchid
        case .dune, .duneDark: return .dune
        case .noir, .noirBright: return .noir
        case .prism, .prismDark: return .prism
        case .weave, .weaveDark: return .weave
        case .abyss, .abyssDark: return .abyss
        case .pearl, .pearlDark: return .pearl
        }
    }

    public var basePalette: ThemePalette {
        switch self {
        case .glacier, .glacierDark: return .glacier
        case .sunset, .sunsetDark: return .sunset
        case .forest, .forestDark: return .forest
        case .citrus, .citrusDark: return .citrus
        case .slate, .slateDark: return .slate
        case .aurora, .auroraDark: return .aurora
        case .ember, .emberDark: return .ember
        case .cobalt, .cobaltDark: return .cobalt
        case .orchid, .orchidDark: return .orchid
        case .dune, .duneDark: return .dune
        case .noir, .noirBright: return .noir
        case .prism, .prismDark: return .prism
        case .weave, .weaveDark: return .weave
        case .abyss, .abyssDark: return .abyss
        case .pearl, .pearlDark: return .pearl
        }
    }

    public var isDarkVariant: Bool {
        switch self {
        case .glacierDark, .sunsetDark, .forestDark, .citrusDark, .slateDark,
             .auroraDark, .emberDark, .cobaltDark, .orchidDark, .duneDark,
             .noir, .prismDark, .weaveDark, .abyssDark, .pearlDark:
            return true
        case .glacier, .sunset, .forest, .citrus, .slate, .aurora, .ember,
             .cobalt, .orchid, .dune, .noirBright, .prism, .weave, .abyss, .pearl:
            return false
        }
    }

    public var displayName: String {
        switch self {
        case .glacier:
            return "Glacier Bright"
        case .glacierDark:
            return "Glacier Dark"
        case .sunset:
            return "Sunset Bright"
        case .sunsetDark:
            return "Sunset Dark"
        case .forest:
            return "Forest Bright"
        case .forestDark:
            return "Forest Dark"
        case .citrus:
            return "Citrus Bright"
        case .citrusDark:
            return "Citrus Dark"
        case .slate:
            return "Slate Bright"
        case .slateDark:
            return "Slate Dark"
        case .aurora:
            return "Aurora Bright"
        case .auroraDark:
            return "Aurora Dark"
        case .ember:
            return "Ember Bright"
        case .emberDark:
            return "Ember Dark"
        case .cobalt:
            return "Cobalt Bright"
        case .cobaltDark:
            return "Cobalt Dark"
        case .orchid:
            return "Orchid Bright"
        case .orchidDark:
            return "Orchid Dark"
        case .dune:
            return "Dune Bright"
        case .duneDark:
            return "Dune Dark"
        case .noir:
            return "Noir"
        case .noirBright:
            return "Noir Bright"
        case .prism:
            return "Prism Bright"
        case .prismDark:
            return "Prism Dark"
        case .weave:
            return "Weave Bright"
        case .weaveDark:
            return "Weave Dark"
        case .abyss:
            return "Abyss Bright"
        case .abyssDark:
            return "Abyss Dark"
        case .pearl:
            return "Pearl Bright"
        case .pearlDark:
            return "Pearl Dark"
        }
    }
}

public struct AppearanceSettings: Codable, Equatable {
    public var theme: ThemePalette

    // Default to Noir for a more subdued, privacy-forward look.
    public init(theme: ThemePalette = .noir) {
        self.theme = theme
    }
}

public struct ChatListSettings: Codable, Equatable {
    public var sortModeRaw: String
    public var pinnedContactIds: [UUID]
    public var pinnedGroupIds: [UUID]

    public init(
        sortModeRaw: String = "unread",
        pinnedContactIds: [UUID] = [],
        pinnedGroupIds: [UUID] = []
    ) {
        self.sortModeRaw = sortModeRaw
        self.pinnedContactIds = pinnedContactIds
        self.pinnedGroupIds = pinnedGroupIds
    }
}

public struct PrivacySettings: Codable, Equatable {
    public var secureTypingEnabled: Bool
    public var secureTypingKeyboard: SecureTypingKeyboard
    public var useSecureCameraCapture: Bool
    public var autoDownloadAttachments: Bool
    // macOS-only behaviors (safe to store cross-platform; ignored on iOS).
    public var hideSensitiveWhenUnfocused: Bool
    public var macBlockWindowCapture: Bool

    public init(
        secureTypingEnabled: Bool = true,
        secureTypingKeyboard: SecureTypingKeyboard = .noctyra,
        useSecureCameraCapture: Bool = true,
        autoDownloadAttachments: Bool = true,
        hideSensitiveWhenUnfocused: Bool = true,
        macBlockWindowCapture: Bool = true
    ) {
        self.secureTypingEnabled = secureTypingEnabled
        self.secureTypingKeyboard = secureTypingKeyboard
        self.useSecureCameraCapture = useSecureCameraCapture
        self.autoDownloadAttachments = autoDownloadAttachments
        self.hideSensitiveWhenUnfocused = hideSensitiveWhenUnfocused
        self.macBlockWindowCapture = macBlockWindowCapture
    }

    private enum CodingKeys: String, CodingKey {
        case secureTypingEnabled
        case secureTypingKeyboard
        case useSecureCameraCapture
        case autoDownloadAttachments
        case hideSensitiveWhenUnfocused
        case macBlockWindowCapture
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        secureTypingEnabled = try container.decodeIfPresent(Bool.self, forKey: .secureTypingEnabled) ?? true
        secureTypingKeyboard = try container.decodeIfPresent(SecureTypingKeyboard.self, forKey: .secureTypingKeyboard) ?? .noctyra
        useSecureCameraCapture = try container.decodeIfPresent(Bool.self, forKey: .useSecureCameraCapture) ?? true
        autoDownloadAttachments = try container.decodeIfPresent(Bool.self, forKey: .autoDownloadAttachments) ?? true
        hideSensitiveWhenUnfocused = try container.decodeIfPresent(Bool.self, forKey: .hideSensitiveWhenUnfocused) ?? true
        macBlockWindowCapture = try container.decodeIfPresent(Bool.self, forKey: .macBlockWindowCapture) ?? true
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(secureTypingEnabled, forKey: .secureTypingEnabled)
        try container.encode(secureTypingKeyboard, forKey: .secureTypingKeyboard)
        try container.encode(useSecureCameraCapture, forKey: .useSecureCameraCapture)
        try container.encode(autoDownloadAttachments, forKey: .autoDownloadAttachments)
        try container.encode(hideSensitiveWhenUnfocused, forKey: .hideSensitiveWhenUnfocused)
        try container.encode(macBlockWindowCapture, forKey: .macBlockWindowCapture)
    }
}

public enum SecureTypingKeyboard: String, Codable, CaseIterable, Identifiable, Equatable {
    case noctyra
    case apple

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .noctyra:
            "Noctyra keyboard"
        case .apple:
            "Apple keyboard"
        }
    }

    public var shortName: String {
        switch self {
        case .noctyra:
            "Noctyra"
        case .apple:
            "Apple"
        }
    }
}

public enum AppLockMode: String, Codable, CaseIterable, Identifiable {
    case off
    case biometrics
    case pinOnly
    case biometricsAndPin

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .off:
            return "Off"
        case .biometrics:
            return "Biometrics"
        case .pinOnly:
            return "PIN Only"
        case .biometricsAndPin:
            return "Biometrics + PIN"
        }
    }
}

public enum AppLockPinAction: String, Codable, CaseIterable, Identifiable {
    case burnIdentity
    case clearChats

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .burnIdentity:
            return "Burn Identity"
        case .clearChats:
            return "Clear Chats"
        }
    }
}

public enum AppLockActionKind: String, Codable, CaseIterable, Identifiable {
    case appReset
    case burnIdentities
    case deleteGroups
    case deleteIdentities
    case appCorruption
    case throwAround
    case deleteChats
    case deleteContacts
    case wipePhotos
    case wipeDocuments

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .appReset:
            return "App Reset"
        case .burnIdentities:
            return "Burn Identities"
        case .deleteGroups:
            return "Delete Groups"
        case .deleteIdentities:
            return "Delete Identities"
        case .appCorruption:
            return "App Corruption"
        case .throwAround:
            return "Throw Around"
        case .deleteChats:
            return "Delete Chats"
        case .deleteContacts:
            return "Delete Contacts"
        case .wipePhotos:
            return "Wipe Photos"
        case .wipeDocuments:
            return "Wipe Documents"
        }
    }

    public var targetHint: String {
        switch self {
        case .burnIdentities:
            return "Select identities."
        case .deleteGroups:
            return "Select groups."
        case .deleteIdentities:
            return "Select identities."
        case .deleteChats:
            return "Select direct chats and/or groups."
        case .deleteContacts:
            return "Select contacts."
        default:
            return "No target list required."
        }
    }
}

public struct AppLockActionOperation: Codable, Equatable, Identifiable {
    public var id: UUID
    public var kind: AppLockActionKind
    public var identityIds: [UUID]
    public var groupIds: [UUID]
    public var contactIds: [UUID]
    public var chatContactIds: [UUID]

    public init(
        id: UUID = UUID(),
        kind: AppLockActionKind,
        identityIds: [UUID] = [],
        groupIds: [UUID] = [],
        contactIds: [UUID] = [],
        chatContactIds: [UUID] = []
    ) {
        self.id = id
        self.kind = kind
        self.identityIds = identityIds
        self.groupIds = groupIds
        self.contactIds = contactIds
        self.chatContactIds = chatContactIds
    }
}

public struct AppLockActionPlan: Codable, Equatable, Identifiable {
    public var id: UUID
    public var label: String
    public var pinSalt: Data
    public var pinHash: Data
    public var operations: [AppLockActionOperation]
    public var createdAt: Date

    public init(
        id: UUID = UUID(),
        label: String,
        pinSalt: Data,
        pinHash: Data,
        operations: [AppLockActionOperation],
        createdAt: Date = Date()
    ) {
        self.id = id
        self.label = label
        self.pinSalt = pinSalt
        self.pinHash = pinHash
        self.operations = operations
        self.createdAt = createdAt
    }
}

public struct AppLockSettings: Codable, Equatable {
    public var mode: AppLockMode
    public var sessionTimeoutMinutes: Int
    public var lockScreenMessage: String
    public var pinSalt: Data?
    public var pinHash: Data?
    public var actionPlans: [AppLockActionPlan]

    public init(
        mode: AppLockMode = .off,
        sessionTimeoutMinutes: Int = 5,
        lockScreenMessage: String = "",
        pinSalt: Data? = nil,
        pinHash: Data? = nil,
        actionPlans: [AppLockActionPlan] = []
    ) {
        self.mode = mode
        self.sessionTimeoutMinutes = sessionTimeoutMinutes
        self.lockScreenMessage = lockScreenMessage
        self.pinSalt = pinSalt
        self.pinHash = pinHash
        self.actionPlans = actionPlans
    }

    public var isPinConfigured: Bool {
        pinSalt != nil && pinHash != nil
    }

    private enum CodingKeys: String, CodingKey {
        case mode
        case sessionTimeoutMinutes
        case lockScreenMessage
        case pinSalt
        case pinHash
        case actionPlans
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mode = try container.decodeIfPresent(AppLockMode.self, forKey: .mode) ?? .off
        sessionTimeoutMinutes = try container.decodeIfPresent(Int.self, forKey: .sessionTimeoutMinutes) ?? 5
        lockScreenMessage = try container.decodeIfPresent(String.self, forKey: .lockScreenMessage) ?? ""
        pinSalt = try container.decodeIfPresent(Data.self, forKey: .pinSalt)
        pinHash = try container.decodeIfPresent(Data.self, forKey: .pinHash)
        actionPlans = try container.decodeIfPresent([AppLockActionPlan].self, forKey: .actionPlans) ?? []
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(mode, forKey: .mode)
        try container.encode(sessionTimeoutMinutes, forKey: .sessionTimeoutMinutes)
        try container.encode(lockScreenMessage, forKey: .lockScreenMessage)
        try container.encodeIfPresent(pinSalt, forKey: .pinSalt)
        try container.encodeIfPresent(pinHash, forKey: .pinHash)
        try container.encode(actionPlans, forKey: .actionPlans)
    }
}

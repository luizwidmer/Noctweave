import Foundation

public struct IdentityProfile: Codable, Identifiable {
    public let id: UUID
    public var identity: Identity
    public var inboxId: String
    public var inboxAccessKey: SigningKeyPair?
    public var relay: RelayEndpoint
    public var contacts: [Contact]
    public var conversations: [Conversation]
    public var groups: [GroupConversation]
    public var selectedRelayId: UUID?
    public var prekeys: PrekeyState
    public var continuityEvents: [ContinuityEvent]
    public var federationPolicy: FederationDescriptor?
    public var isArchived: Bool
    public var archivedAt: Date?
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        identity: Identity,
        inboxId: String,
        inboxAccessKey: SigningKeyPair? = nil,
        relay: RelayEndpoint,
        contacts: [Contact] = [],
        conversations: [Conversation] = [],
        groups: [GroupConversation] = [],
        selectedRelayId: UUID? = nil,
        prekeys: PrekeyState,
        continuityEvents: [ContinuityEvent] = [],
        federationPolicy: FederationDescriptor? = nil,
        isArchived: Bool = false,
        archivedAt: Date? = nil,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.identity = identity
        self.inboxId = inboxId
        self.inboxAccessKey = inboxAccessKey
        self.relay = relay
        self.contacts = contacts
        self.conversations = conversations
        self.groups = groups
        self.selectedRelayId = selectedRelayId
        self.prekeys = prekeys
        self.continuityEvents = continuityEvents
        self.federationPolicy = federationPolicy
        self.isArchived = isArchived
        self.archivedAt = archivedAt
        self.createdAt = createdAt
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case identity
        case inboxId
        case inboxAccessKey
        case relay
        case contacts
        case conversations
        case groups
        case selectedRelayId
        case prekeys
        case continuityEvents
        case federationPolicy
        case isArchived
        case archivedAt
        case createdAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        identity = try container.decode(Identity.self, forKey: .identity)
        inboxId = try container.decode(String.self, forKey: .inboxId)
        inboxAccessKey = try container.decodeIfPresent(SigningKeyPair.self, forKey: .inboxAccessKey)
        relay = try container.decode(RelayEndpoint.self, forKey: .relay)
        contacts = try container.decodeIfPresent([Contact].self, forKey: .contacts) ?? []
        conversations = try container.decodeIfPresent([Conversation].self, forKey: .conversations) ?? []
        groups = try container.decodeIfPresent([GroupConversation].self, forKey: .groups) ?? []
        selectedRelayId = try container.decodeIfPresent(UUID.self, forKey: .selectedRelayId)
        prekeys = try container.decode(PrekeyState.self, forKey: .prekeys)
        continuityEvents = try container.decodeIfPresent([ContinuityEvent].self, forKey: .continuityEvents) ?? []
        federationPolicy = try container.decodeIfPresent(FederationDescriptor.self, forKey: .federationPolicy)
        isArchived = try container.decodeIfPresent(Bool.self, forKey: .isArchived) ?? false
        archivedAt = try container.decodeIfPresent(Date.self, forKey: .archivedAt)
        createdAt = try container.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date()
    }
}

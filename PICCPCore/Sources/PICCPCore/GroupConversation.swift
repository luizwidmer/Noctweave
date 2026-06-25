import Foundation

public struct GroupConversation: Codable, Identifiable, Equatable {
    public let id: UUID
    public var title: String
    public var memberContactIds: [UUID]
    public var relayInboxId: String?
    public var relayEpoch: UInt64?
    public var relayTranscriptHash: Data?
    public var createdByFingerprint: String?
    public var messages: [Message]
    public var unreadCount: Int
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        title: String,
        memberContactIds: [UUID],
        relayInboxId: String? = nil,
        relayEpoch: UInt64? = nil,
        relayTranscriptHash: Data? = nil,
        createdByFingerprint: String? = nil,
        messages: [Message] = [],
        unreadCount: Int = 0,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.title = title
        self.memberContactIds = Array(Set(memberContactIds))
        self.relayInboxId = relayInboxId
        self.relayEpoch = relayEpoch
        self.relayTranscriptHash = relayTranscriptHash
        self.createdByFingerprint = createdByFingerprint
        self.messages = messages
        self.unreadCount = unreadCount
        self.createdAt = createdAt
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case title
        case memberContactIds
        case relayInboxId
        case relayEpoch
        case relayTranscriptHash
        case createdByFingerprint
        case messages
        case unreadCount
        case createdAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        memberContactIds = try container.decodeIfPresent([UUID].self, forKey: .memberContactIds) ?? []
        relayInboxId = try container.decodeIfPresent(String.self, forKey: .relayInboxId)
        relayEpoch = try container.decodeIfPresent(UInt64.self, forKey: .relayEpoch)
        relayTranscriptHash = try container.decodeIfPresent(Data.self, forKey: .relayTranscriptHash)
        createdByFingerprint = try container.decodeIfPresent(String.self, forKey: .createdByFingerprint)
        messages = try container.decodeIfPresent([Message].self, forKey: .messages) ?? []
        unreadCount = try container.decodeIfPresent(Int.self, forKey: .unreadCount) ?? 0
        createdAt = try container.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date()
    }
}

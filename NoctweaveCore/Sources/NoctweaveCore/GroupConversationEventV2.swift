import CryptoKit
import Foundation

public enum GroupConversationEventKindV2: String, Codable, Equatable {
    case application
    case receipt
}

/// An immutable group-scoped event. Both author handles are freshly scoped to
/// this group and are authenticated against the enclosing application envelope
/// and accepted epoch membership. They are not relationship, endpoint, persona,
/// account, installation, or device identifiers.
public struct GroupConversationEventV2: Codable, Equatable, Identifiable {
    public static let version = 2

    public let version: Int
    public let id: UUID
    public let clientTransactionID: UUID
    public let groupID: UUID
    public let authorMemberHandle: GroupScopedMemberHandleV2
    public let authorCredentialHandle: GroupScopedCredentialHandleV2
    public let createdAt: Date
    public let kind: GroupConversationEventKindV2
    public let content: EncodedContent
    public let relation: EventRelation?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case clientTransactionID
        case groupID
        case authorMemberHandle
        case authorCredentialHandle
        case createdAt
        case kind
        case content
        case relation
    }

    public init(
        version: Int = Self.version,
        id: UUID = UUID(),
        clientTransactionID: UUID = UUID(),
        groupID: UUID,
        authorMemberHandle: GroupScopedMemberHandleV2,
        authorCredentialHandle: GroupScopedCredentialHandleV2,
        createdAt: Date = Date(),
        kind: GroupConversationEventKindV2,
        content: EncodedContent,
        relation: EventRelation? = nil
    ) {
        self.version = version
        self.id = id
        self.clientTransactionID = clientTransactionID
        self.groupID = groupID
        self.authorMemberHandle = authorMemberHandle
        self.authorCredentialHandle = authorCredentialHandle
        self.createdAt = createdAt
        self.kind = kind
        self.content = content
        self.relation = relation
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: GroupConversationEventCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Group event fields must match the current protocol exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        version = try values.decode(Int.self, forKey: .version)
        id = try values.decode(UUID.self, forKey: .id)
        clientTransactionID = try values.decode(UUID.self, forKey: .clientTransactionID)
        groupID = try values.decode(UUID.self, forKey: .groupID)
        authorMemberHandle = try values.decode(
            GroupScopedMemberHandleV2.self,
            forKey: .authorMemberHandle
        )
        authorCredentialHandle = try values.decode(
            GroupScopedCredentialHandleV2.self,
            forKey: .authorCredentialHandle
        )
        createdAt = try values.decode(Date.self, forKey: .createdAt)
        kind = try values.decode(GroupConversationEventKindV2.self, forKey: .kind)
        content = try values.decode(EncodedContent.self, forKey: .content)
        relation = try values.decodeIfPresent(EventRelation.self, forKey: .relation)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .content,
                in: values,
                debugDescription: "Invalid group conversation event"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid group conversation event"
                )
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(id, forKey: .id)
        try values.encode(clientTransactionID, forKey: .clientTransactionID)
        try values.encode(groupID, forKey: .groupID)
        try values.encode(authorMemberHandle, forKey: .authorMemberHandle)
        try values.encode(authorCredentialHandle, forKey: .authorCredentialHandle)
        try values.encode(createdAt, forKey: .createdAt)
        try values.encode(kind, forKey: .kind)
        try values.encode(content, forKey: .content)
        if let relation {
            try values.encode(relation, forKey: .relation)
        } else {
            try values.encodeNil(forKey: .relation)
        }
    }

    public var isStructurallyValid: Bool {
        guard version == Self.version,
              authorMemberHandle.isStructurallyValid,
              authorCredentialHandle.isStructurallyValid,
              createdAt.timeIntervalSince1970.isFinite,
              createdAt >= ConversationEvent.earliestCreatedAt,
              createdAt <= ConversationEvent.latestCreatedAt,
              content.isStructurallyValid,
              relation?.targetEventId != id else {
            return false
        }
        switch kind {
        case .application:
            guard content.type.authority != "org.noctweave.control",
                  content.type.authority != "org.noctweave.receipt" else {
                return false
            }
            if content.type == .reaction { return relation?.kind == .reaction }
            if content.type == .retraction { return relation?.kind == .retraction }
            return relation?.kind != .reaction && relation?.kind != .retraction
        case .receipt:
            return relation == nil
                && content.disposition == .silent
                && (content.type == .deliveryReceipt || content.type == .readReceipt)
        }
    }

    public var digest: Data? {
        guard let bytes = try? NoctweaveCoder.encode(self, sortedKeys: true) else {
            return nil
        }
        return Data(SHA256.hash(data: bytes))
    }
}

private struct GroupConversationEventCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

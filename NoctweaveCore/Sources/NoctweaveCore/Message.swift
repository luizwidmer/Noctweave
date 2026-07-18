import Foundation

public enum MessageDirection: String, Codable, Equatable {
    case sent
    case received
}

/// Local presentation derived from an immutable `ConversationEvent`. It is
/// never encrypted directly and cannot encode protocol-control operations.
public enum MessageBody: Codable, Equatable {
    case text(String)
    case attachment(AttachmentDescriptor)

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case type
        case text
        case attachment
    }

    private enum BodyType: String, Codable {
        case text
        case attachment
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: MessageCodingKey.self)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(BodyType.self, forKey: .type)
        let expected: Set<String>
        switch type {
        case .text:
            expected = [CodingKeys.type.rawValue, CodingKeys.text.rawValue]
            self = .text(try container.decode(String.self, forKey: .text))
        case .attachment:
            expected = [CodingKeys.type.rawValue, CodingKeys.attachment.rawValue]
            self = .attachment(
                try container.decode(AttachmentDescriptor.self, forKey: .attachment)
            )
        }
        guard Set(strict.allKeys.map(\.stringValue)) == expected else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Message-body fields must match the current projection exactly"
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .text(let text):
            try container.encode(BodyType.text, forKey: .type)
            try container.encode(text, forKey: .text)
        case .attachment(let descriptor):
            try container.encode(BodyType.attachment, forKey: .type)
            try container.encode(descriptor, forKey: .attachment)
        }
    }
}

public struct Message: Codable, Identifiable, Equatable {
    public let id: UUID
    public let direction: MessageDirection
    public let senderDisplayName: String?
    public let body: String
    public let timestamp: Date
    public let counter: UInt64
    public let isMismatch: Bool
    public let attachment: AttachmentInfo?

    public init(
        id: UUID = UUID(),
        direction: MessageDirection,
        senderDisplayName: String? = nil,
        body: String,
        timestamp: Date,
        counter: UInt64,
        isMismatch: Bool = false,
        attachment: AttachmentInfo? = nil
    ) {
        self.id = id
        self.direction = direction
        self.senderDisplayName = senderDisplayName
        self.body = body
        self.timestamp = timestamp
        self.counter = counter
        self.isMismatch = isMismatch
        self.attachment = attachment
    }
}

private struct MessageCodingKey: CodingKey {
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

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
    public let body: String
    public let timestamp: Date
    public let counter: UInt64
    public let isMismatch: Bool
    public let attachment: AttachmentInfo?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case direction
        case body
        case timestamp
        case counter
        case isMismatch
        case attachment
    }

    public init(
        id: UUID = UUID(),
        direction: MessageDirection,
        body: String,
        timestamp: Date,
        counter: UInt64,
        isMismatch: Bool = false,
        attachment: AttachmentInfo? = nil
    ) {
        self.id = id
        self.direction = direction
        self.body = body
        self.timestamp = timestamp
        self.counter = counter
        self.isMismatch = isMismatch
        self.attachment = attachment
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: MessageCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Message fields must match the current projection exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        direction = try container.decode(MessageDirection.self, forKey: .direction)
        body = try container.decode(String.self, forKey: .body)
        timestamp = try container.decode(Date.self, forKey: .timestamp)
        counter = try container.decode(UInt64.self, forKey: .counter)
        isMismatch = try container.decode(Bool.self, forKey: .isMismatch)
        attachment = try container.decodeIfPresent(AttachmentInfo.self, forKey: .attachment)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .body,
                in: container,
                debugDescription: "Message projection is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Message projection is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(direction, forKey: .direction)
        try container.encode(body, forKey: .body)
        try container.encode(timestamp, forKey: .timestamp)
        try container.encode(counter, forKey: .counter)
        try container.encode(isMismatch, forKey: .isMismatch)
        if let attachment {
            try container.encode(attachment, forKey: .attachment)
        } else {
            try container.encodeNil(forKey: .attachment)
        }
    }

    public var isStructurallyValid: Bool {
        body.utf8.count <= NoctweaveArchitectureV2.maximumContentPayloadBytes
            && timestamp.timeIntervalSinceReferenceDate.isFinite
            && attachment?.isStructurallyValid != false
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

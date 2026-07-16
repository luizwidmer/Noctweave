import Foundation

public enum MessageDirection: String, Codable {
    case sent
    case received
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

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        direction = try container.decode(MessageDirection.self, forKey: .direction)
        senderDisplayName = try container.decodeIfPresent(String.self, forKey: .senderDisplayName)
        body = try container.decode(String.self, forKey: .body)
        timestamp = try container.decode(Date.self, forKey: .timestamp)
        counter = try container.decode(UInt64.self, forKey: .counter)
        isMismatch = try container.decodeIfPresent(Bool.self, forKey: .isMismatch) ?? false
        attachment = try container.decodeIfPresent(AttachmentInfo.self, forKey: .attachment)
    }
}

/// Local UI/control projection. Certified direct-v4 encrypts
/// `WirePayloadV2`, not this closed enum.
public enum MessageBody: Codable, Equatable {
    case text(String)
    case attachment(AttachmentDescriptor)
    case identityRotation(IdentityRotation)
    case identityReset(IdentityReset)
    case sessionReset(SessionReset)
    case resendRequest(ResendRequest)

    private enum CodingKeys: String, CodingKey {
        case type
        case text
        case attachment
        case rotation
        case reset
        case sessionReset
        case resendRequest
    }

    private enum BodyType: String, Codable {
        case text
        case attachment
        case identityRotation
        case identityReset
        case sessionReset
        case resendRequest
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(BodyType.self, forKey: .type)
        switch type {
        case .text:
            let text = try container.decode(String.self, forKey: .text)
            self = .text(text)
        case .attachment:
            let attachment = try container.decode(AttachmentDescriptor.self, forKey: .attachment)
            self = .attachment(attachment)
        case .identityRotation:
            let rotation = try container.decode(IdentityRotation.self, forKey: .rotation)
            self = .identityRotation(rotation)
        case .identityReset:
            let reset = try container.decode(IdentityReset.self, forKey: .reset)
            self = .identityReset(reset)
        case .sessionReset:
            let reset = try container.decode(SessionReset.self, forKey: .sessionReset)
            self = .sessionReset(reset)
        case .resendRequest:
            let request = try container.decode(ResendRequest.self, forKey: .resendRequest)
            self = .resendRequest(request)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .text(let text):
            try container.encode(BodyType.text, forKey: .type)
            try container.encode(text, forKey: .text)
        case .attachment(let attachment):
            try container.encode(BodyType.attachment, forKey: .type)
            try container.encode(attachment, forKey: .attachment)
        case .identityRotation(let rotation):
            try container.encode(BodyType.identityRotation, forKey: .type)
            try container.encode(rotation, forKey: .rotation)
        case .identityReset(let reset):
            try container.encode(BodyType.identityReset, forKey: .type)
            try container.encode(reset, forKey: .reset)
        case .sessionReset(let reset):
            try container.encode(BodyType.sessionReset, forKey: .type)
            try container.encode(reset, forKey: .sessionReset)
        case .resendRequest(let request):
            try container.encode(BodyType.resendRequest, forKey: .type)
            try container.encode(request, forKey: .resendRequest)
        }
    }
}

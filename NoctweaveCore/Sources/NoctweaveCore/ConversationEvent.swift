import CryptoKit
import Foundation

public struct ContentTypeId: Codable, Equatable, Hashable {
    public let authority: String
    public let name: String
    public let major: UInt16
    public let minor: UInt16

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case authority
        case name
        case major
        case minor
    }

    public init(authority: String, name: String, major: UInt16, minor: UInt16 = 0) {
        self.authority = authority
        self.name = name
        self.major = major
        self.minor = minor
    }

    public static let text = ContentTypeId(authority: "org.noctweave", name: "text", major: 1)
    public static let attachment = ContentTypeId(authority: "org.noctweave", name: "attachment", major: 1)
    public static let reaction = ContentTypeId(authority: "org.noctweave", name: "reaction", major: 1)
    public static let retraction = ContentTypeId(authority: "org.noctweave", name: "retraction", major: 1)
    public static let deliveryReceipt = ContentTypeId(
        authority: "org.noctweave.receipt",
        name: "delivery",
        major: 1
    )
    public static let readReceipt = ContentTypeId(
        authority: "org.noctweave.receipt",
        name: "read",
        major: 1
    )

    public var canonicalName: String {
        "\(authority)/\(name):\(major).\(minor)"
    }

    public var isStructurallyValid: Bool {
        let normalizedAuthority = authority.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let identifierCharacters = CharacterSet(
            charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        )
        return !normalizedAuthority.isEmpty
            && normalizedAuthority == authority
            && authority.utf8.count <= NoctweaveArchitectureV2.maximumContentTypeBytes
            && !normalizedName.isEmpty
            && normalizedName == name
            && name.utf8.count <= NoctweaveArchitectureV2.maximumContentTypeBytes
            && major > 0
            && authority.unicodeScalars.allSatisfy { scalar in
                identifierCharacters.contains(scalar)
            }
            && name.unicodeScalars.allSatisfy { scalar in
                identifierCharacters.contains(scalar)
            }
    }

    public init(from decoder: Decoder) throws {
        let container = try strictConversationEventContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Content type identifier"
        )
        authority = try container.decode(String.self, forKey: .authority)
        name = try container.decode(String.self, forKey: .name)
        major = try container.decode(UInt16.self, forKey: .major)
        minor = try container.decode(UInt16.self, forKey: .minor)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .authority,
                in: container,
                debugDescription: "Invalid content type identifier"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidConversationEventEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid content type identifier"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(authority, forKey: .authority)
        try container.encode(name, forKey: .name)
        try container.encode(major, forKey: .major)
        try container.encode(minor, forKey: .minor)
    }
}

public enum ContentDisposition: String, Codable, Equatable {
    case visible
    case silent
}

public struct ReactionContentV1: Codable, Equatable {
    public static let maximumValueBytes = 64

    public let value: String

    private enum CodingKeys: String, CodingKey, CaseIterable { case value }

    public init(value: String) {
        self.value = value
    }

    public var isStructurallyValid: Bool {
        !value.isEmpty
            && value == value.trimmingCharacters(in: .whitespacesAndNewlines)
            && value.utf8.count <= Self.maximumValueBytes
            && !value.containsUnsafeProtocolControl
    }

    public var fallbackText: String {
        "Reacted \(value) to a message"
    }

    public init(from decoder: Decoder) throws {
        let container = try strictConversationEventContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Reaction content"
        )
        value = try container.decode(String.self, forKey: .value)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .value,
                in: container,
                debugDescription: "Invalid reaction content"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidConversationEventEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid reaction content"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(value, forKey: .value)
    }
}

public struct RetractionContentV1: Codable, Equatable {
    public static let retainedCopyScope = "received-copies-may-remain"
    public static let maximumReasonBytes = 512
    public static let fallbackText = "Message retracted; received copies may remain"

    public let scope: String
    public let reason: String?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case scope
        case reason
    }

    public init(reason: String? = nil) {
        self.scope = Self.retainedCopyScope
        self.reason = reason
    }

    public var isStructurallyValid: Bool {
        guard scope == Self.retainedCopyScope else { return false }
        guard let reason else { return true }
        return !reason.isEmpty
            && reason == reason.trimmingCharacters(in: .whitespacesAndNewlines)
            && reason.utf8.count <= Self.maximumReasonBytes
            && !reason.containsUnsafeProtocolControl
    }

    public init(from decoder: Decoder) throws {
        let container = try strictConversationEventContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Retraction content"
        )
        scope = try container.decode(String.self, forKey: .scope)
        reason = try container.decodeIfPresent(String.self, forKey: .reason)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .scope,
                in: container,
                debugDescription: "Invalid retraction content"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidConversationEventEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid retraction content"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(scope, forKey: .scope)
        if let reason {
            try container.encode(reason, forKey: .reason)
        } else {
            try container.encodeNil(forKey: .reason)
        }
    }
}

public struct EventReceiptContentV1: Codable, Equatable {
    public let targetEventId: UUID

    private enum CodingKeys: String, CodingKey, CaseIterable { case targetEventId }

    public init(targetEventId: UUID) {
        self.targetEventId = targetEventId
    }

    public init(from decoder: Decoder) throws {
        let container = try strictConversationEventContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Event receipt content"
        )
        targetEventId = try container.decode(UUID.self, forKey: .targetEventId)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(targetEventId, forKey: .targetEventId)
    }
}

public struct EncodedContent: Codable, Equatable {
    public let type: ContentTypeId
    public let parameters: [String: String]
    public let payload: Data
    public let fallbackText: String?
    public let disposition: ContentDisposition

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case type
        case parameters
        case payload
        case fallbackText
        case disposition
    }

    public init(
        type: ContentTypeId,
        parameters: [String: String] = [:],
        payload: Data,
        fallbackText: String? = nil,
        disposition: ContentDisposition = .visible
    ) {
        self.type = type
        self.parameters = parameters
        self.payload = payload
        self.fallbackText = fallbackText
        self.disposition = disposition
    }

    public static func text(_ value: String) -> EncodedContent? {
        guard let data = value.data(using: .utf8) else { return nil }
        let content = EncodedContent(type: .text, payload: data, fallbackText: value)
        return content.isStructurallyValid ? content : nil
    }

    public static func reaction(_ value: String) -> EncodedContent? {
        let reaction = ReactionContentV1(value: value)
        guard reaction.isStructurallyValid,
              let payload = try? NoctweaveCoder.encode(reaction, sortedKeys: true) else {
            return nil
        }
        let content = EncodedContent(
            type: .reaction,
            payload: payload,
            fallbackText: reaction.fallbackText
        )
        return content.isStructurallyValid ? content : nil
    }

    public static func retraction(reason: String? = nil) -> EncodedContent? {
        let retraction = RetractionContentV1(reason: reason)
        guard retraction.isStructurallyValid,
              let payload = try? NoctweaveCoder.encode(retraction, sortedKeys: true) else {
            return nil
        }
        let content = EncodedContent(
            type: .retraction,
            payload: payload,
            fallbackText: RetractionContentV1.fallbackText
        )
        return content.isStructurallyValid ? content : nil
    }

    public static func deliveryReceipt(targetEventId: UUID) -> EncodedContent? {
        receipt(type: .deliveryReceipt, targetEventId: targetEventId)
    }

    public static func readReceipt(targetEventId: UUID) -> EncodedContent? {
        receipt(type: .readReceipt, targetEventId: targetEventId)
    }

    private static func receipt(type: ContentTypeId, targetEventId: UUID) -> EncodedContent? {
        guard let payload = try? NoctweaveCoder.encode(
            EventReceiptContentV1(targetEventId: targetEventId),
            sortedKeys: true
        ) else {
            return nil
        }
        let content = EncodedContent(
            type: type,
            payload: payload,
            fallbackText: nil,
            disposition: .silent
        )
        return content.isStructurallyValid ? content : nil
    }

    public var isStructurallyValid: Bool {
        guard type.isStructurallyValid,
              parameters.count <= NoctweaveArchitectureV2.maximumContentParameters,
              payload.count <= NoctweaveArchitectureV2.maximumContentPayloadBytes,
              fallbackText?.utf8.count ?? 0 <= NoctweaveArchitectureV2.maximumFallbackBytes,
              fallbackText?.containsUnsafeProtocolControl != true else {
            return false
        }
        return parameters.allSatisfy { key, value in
            !key.isEmpty
                && key == key.trimmingCharacters(in: .whitespacesAndNewlines)
                && key.utf8.count <= NoctweaveArchitectureV2.maximumContentParameterBytes
                && value.utf8.count <= NoctweaveArchitectureV2.maximumContentParameterBytes
                && key.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
                && value.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try strictConversationEventContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Encoded application content"
        )
        type = try container.decode(ContentTypeId.self, forKey: .type)
        parameters = try container.decode([String: String].self, forKey: .parameters)
        payload = try container.decode(Data.self, forKey: .payload)
        fallbackText = try container.decodeIfPresent(String.self, forKey: .fallbackText)
        disposition = try container.decode(ContentDisposition.self, forKey: .disposition)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: container,
                debugDescription: "Invalid encoded application content"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidConversationEventEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid encoded application content"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(parameters, forKey: .parameters)
        try container.encode(payload, forKey: .payload)
        if let fallbackText {
            try container.encode(fallbackText, forKey: .fallbackText)
        } else {
            try container.encodeNil(forKey: .fallbackText)
        }
        try container.encode(disposition, forKey: .disposition)
    }
}

public enum EventRelationKind: String, Codable, Equatable {
    case reply
    case replacement
    case reaction
    case retraction
    case reference
}

public struct EventRelation: Codable, Equatable {
    public let kind: EventRelationKind
    public let targetEventId: UUID

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case kind
        case targetEventId
    }

    public init(kind: EventRelationKind, targetEventId: UUID) {
        self.kind = kind
        self.targetEventId = targetEventId
    }

    public init(from decoder: Decoder) throws {
        let container = try strictConversationEventContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Event relation"
        )
        kind = try container.decode(EventRelationKind.self, forKey: .kind)
        targetEventId = try container.decode(UUID.self, forKey: .targetEventId)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(kind, forKey: .kind)
        try container.encode(targetEventId, forKey: .targetEventId)
    }
}

public enum ConversationEventKind: String, Codable, Equatable {
    case application
    case control
    case receipt
}

public struct ConversationEvent: Codable, Equatable, Identifiable {
    public static let earliestCreatedAt = Date(timeIntervalSince1970: 0)
    public static let latestCreatedAt = Date(timeIntervalSince1970: 4_102_444_800)

    public let version: Int
    public let id: UUID
    public let clientTransactionId: UUID
    public let conversationId: String
    public let authorEndpointHandle: RelationshipEndpointHandle
    public let createdAt: Date
    public let kind: ConversationEventKind
    public let content: EncodedContent
    public let relation: EventRelation?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case id
        case clientTransactionId
        case conversationId
        case authorEndpointHandle
        case createdAt
        case kind
        case content
        case relation
    }

    public init(
        version: Int = NoctweaveArchitectureV2.version,
        id: UUID = UUID(),
        clientTransactionId: UUID = UUID(),
        conversationId: String,
        authorEndpointHandle: RelationshipEndpointHandle,
        createdAt: Date = Date(),
        kind: ConversationEventKind,
        content: EncodedContent,
        relation: EventRelation? = nil
    ) {
        self.version = version
        self.id = id
        self.clientTransactionId = clientTransactionId
        self.conversationId = conversationId
        self.authorEndpointHandle = authorEndpointHandle
        self.createdAt = createdAt
        self.kind = kind
        self.content = content
        self.relation = relation
    }

    public var digest: Data? {
        guard let data = try? NoctweaveCoder.encode(self, sortedKeys: true) else { return nil }
        return Data(SHA256.hash(data: data))
    }

    public var isStructurallyValid: Bool {
        guard version == NoctweaveArchitectureV2.version
            && !conversationId.isEmpty
            && conversationId.utf8.count <= 256
            && !conversationId.containsUnsafeProtocolControl
            && authorEndpointHandle.isStructurallyValid
            && createdAt.timeIntervalSince1970.isFinite
            && content.isStructurallyValid
            && createdAt >= Self.earliestCreatedAt
            && createdAt <= Self.latestCreatedAt
            && relation?.targetEventId != id else {
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
        case .control:
            return relation == nil
                && content.disposition == .silent
                && content.type.authority == "org.noctweave.control"
        }
    }

    public func mayMutateControlState(supportedControlTypes: Set<ContentTypeId>) -> Bool {
        kind == .control && isStructurallyValid && supportedControlTypes.contains(content.type)
    }

    public init(from decoder: Decoder) throws {
        let container = try strictConversationEventContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Conversation event"
        )
        version = try container.decode(Int.self, forKey: .version)
        id = try container.decode(UUID.self, forKey: .id)
        clientTransactionId = try container.decode(UUID.self, forKey: .clientTransactionId)
        conversationId = try container.decode(String.self, forKey: .conversationId)
        authorEndpointHandle = try container.decode(
            RelationshipEndpointHandle.self,
            forKey: .authorEndpointHandle
        )
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        kind = try container.decode(ConversationEventKind.self, forKey: .kind)
        content = try container.decode(EncodedContent.self, forKey: .content)
        relation = try container.decodeIfPresent(EventRelation.self, forKey: .relation)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .content,
                in: container,
                debugDescription: "Invalid conversation event"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidConversationEventEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid conversation event"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(id, forKey: .id)
        try container.encode(clientTransactionId, forKey: .clientTransactionId)
        try container.encode(conversationId, forKey: .conversationId)
        try container.encode(authorEndpointHandle, forKey: .authorEndpointHandle)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(kind, forKey: .kind)
        try container.encode(content, forKey: .content)
        if let relation {
            try container.encode(relation, forKey: .relation)
        } else {
            try container.encodeNil(forKey: .relation)
        }
    }
}

private extension String {
    var containsUnsafeProtocolControl: Bool {
        unicodeScalars.contains { scalar in
            CharacterSet.controlCharacters.contains(scalar)
                && scalar.value != 0x09
                && scalar.value != 0x0A
                && scalar.value != 0x0D
        }
    }
}

public struct DeliveryStateRecord: Codable, Equatable {
    public let eventId: UUID
    public let destinationEndpoint: RelationshipEndpointHandle
    public var state: MessageDeliveryState
    public var updatedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case eventId
        case destinationEndpoint
        case state
        case updatedAt
    }

    public init(
        eventId: UUID,
        destinationEndpoint: RelationshipEndpointHandle,
        state: MessageDeliveryState,
        updatedAt: Date = Date()
    ) {
        self.eventId = eventId
        self.destinationEndpoint = destinationEndpoint
        self.state = state
        self.updatedAt = updatedAt
    }

    public mutating func advance(to newState: MessageDeliveryState, at date: Date = Date()) -> Bool {
        guard date.timeIntervalSince1970.isFinite,
              date >= updatedAt,
              Self.rank(newState) >= Self.rank(state) else {
            return false
        }
        state = newState
        updatedAt = date
        return true
    }

    public var isStructurallyValid: Bool {
        destinationEndpoint.isStructurallyValid
            && updatedAt.timeIntervalSince1970.isFinite
    }

    private static func rank(_ state: MessageDeliveryState) -> Int {
        switch state {
        case .locallyPersisted: return 0
        case .relayAccepted: return 1
        case .peerStored: return 2
        case .peerRead: return 3
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try strictConversationEventContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Delivery state"
        )
        eventId = try container.decode(UUID.self, forKey: .eventId)
        destinationEndpoint = try container.decode(
            RelationshipEndpointHandle.self,
            forKey: .destinationEndpoint
        )
        state = try container.decode(MessageDeliveryState.self, forKey: .state)
        updatedAt = try container.decode(Date.self, forKey: .updatedAt)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .destinationEndpoint,
                in: container,
                debugDescription: "Invalid delivery state"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidConversationEventEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid delivery state"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(eventId, forKey: .eventId)
        try container.encode(destinationEndpoint, forKey: .destinationEndpoint)
        try container.encode(state, forKey: .state)
        try container.encode(updatedAt, forKey: .updatedAt)
    }
}

public struct QuarantinedControlEvent: Codable, Equatable, Identifiable {
    public var id: UUID { event.id }
    public let event: ConversationEvent
    public let receivedAt: Date
    public let reason: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case event
        case receivedAt
        case reason
    }

    public init(event: ConversationEvent, receivedAt: Date = Date(), reason: String) {
        self.event = event
        self.receivedAt = receivedAt
        self.reason = boundedConversationEventString(reason, maximumUTF8Bytes: 256)
    }

    public var isStructurallyValid: Bool {
        event.isStructurallyValid
            && event.kind == .control
            && receivedAt.timeIntervalSince1970.isFinite
            && !reason.isEmpty
            && reason.utf8.count <= 256
            && !reason.containsUnsafeProtocolControl
    }

    public init(from decoder: Decoder) throws {
        let container = try strictConversationEventContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Quarantined control event"
        )
        event = try container.decode(ConversationEvent.self, forKey: .event)
        receivedAt = try container.decode(Date.self, forKey: .receivedAt)
        reason = try container.decode(String.self, forKey: .reason)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .event,
                in: container,
                debugDescription: "Invalid quarantined control event"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidConversationEventEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid quarantined control event"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(event, forKey: .event)
        try container.encode(receivedAt, forKey: .receivedAt)
        try container.encode(reason, forKey: .reason)
    }
}

private struct StrictConversationEventCodingKey: CodingKey, Hashable {
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

private func strictConversationEventContainer<Key>(
    _ decoder: Decoder,
    keyedBy keyType: Key.Type,
    description: String
) throws -> KeyedDecodingContainer<Key>
where Key: CodingKey & CaseIterable, Key.AllCases.Element == Key {
    let strict = try decoder.container(keyedBy: StrictConversationEventCodingKey.self)
    let actual = Set(strict.allKeys.map(\.stringValue))
    let expected = Set(Key.allCases.map(\.stringValue))
    guard actual == expected else {
        throw DecodingError.dataCorrupted(
            DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: "\(description) fields must match the current protocol exactly"
            )
        )
    }
    return try decoder.container(keyedBy: keyType)
}

private func requireValidConversationEventEncoding<Value>(
    _ isValid: Bool,
    value: Value,
    encoder: Encoder,
    description: String
) throws {
    guard isValid else {
        throw EncodingError.invalidValue(
            value,
            EncodingError.Context(
                codingPath: encoder.codingPath,
                debugDescription: description
            )
        )
    }
}

private func boundedConversationEventString(
    _ value: String,
    maximumUTF8Bytes: Int
) -> String {
    var result = ""
    result.reserveCapacity(min(value.count, maximumUTF8Bytes))
    for character in value {
        let candidate = result + String(character)
        guard candidate.utf8.count <= maximumUTF8Bytes else { break }
        result = candidate
    }
    return result
}

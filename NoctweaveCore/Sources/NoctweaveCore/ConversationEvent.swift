import CryptoKit
import Foundation

public struct ContentTypeId: Codable, Equatable, Hashable {
    public let authority: String
    public let name: String
    public let major: UInt16
    public let minor: UInt16

    public init(authority: String, name: String, major: UInt16, minor: UInt16 = 0) {
        self.authority = authority
        self.name = name
        self.major = major
        self.minor = minor
    }

    public static let text = ContentTypeId(authority: "org.noctweave", name: "text", major: 1)
    public static let attachment = ContentTypeId(authority: "org.noctweave", name: "attachment", major: 1)

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
}

public enum ContentDisposition: String, Codable, Equatable {
    case visible
    case silent
}

public struct EncodedContent: Codable, Equatable {
    public let type: ContentTypeId
    public let parameters: [String: String]
    public let payload: Data
    public let fallbackText: String?
    public let disposition: ContentDisposition

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

    public var isStructurallyValid: Bool {
        guard type.isStructurallyValid,
              parameters.count <= NoctweaveArchitectureV2.maximumContentParameters,
              payload.count <= NoctweaveArchitectureV2.maximumContentPayloadBytes,
              fallbackText?.utf8.count ?? 0 <= NoctweaveArchitectureV2.maximumFallbackBytes else {
            return false
        }
        return parameters.allSatisfy { key, value in
            !key.isEmpty
                && key.utf8.count <= NoctweaveArchitectureV2.maximumContentParameterBytes
                && value.utf8.count <= NoctweaveArchitectureV2.maximumContentParameterBytes
                && key.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
        }
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

    public init(kind: EventRelationKind, targetEventId: UUID) {
        self.kind = kind
        self.targetEventId = targetEventId
    }
}

public enum ConversationEventKind: String, Codable, Equatable {
    case application
    case control
    case receipt
}

public struct ConversationEvent: Codable, Equatable, Identifiable {
    public let version: Int
    public let id: UUID
    public let clientTransactionId: UUID
    public let conversationId: String
    public let authorInstallationHandle: RelationshipInstallationHandle
    public let createdAt: Date
    public let kind: ConversationEventKind
    public let content: EncodedContent
    public let relation: EventRelation?

    public init(
        version: Int = NoctweaveArchitectureV2.version,
        id: UUID = UUID(),
        clientTransactionId: UUID = UUID(),
        conversationId: String,
        authorInstallationHandle: RelationshipInstallationHandle,
        createdAt: Date = Date(),
        kind: ConversationEventKind,
        content: EncodedContent,
        relation: EventRelation? = nil
    ) {
        self.version = version
        self.id = id
        self.clientTransactionId = clientTransactionId
        self.conversationId = conversationId
        self.authorInstallationHandle = authorInstallationHandle
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
        version == NoctweaveArchitectureV2.version
            && !conversationId.isEmpty
            && conversationId.utf8.count <= 256
            && authorInstallationHandle.isStructurallyValid
            && createdAt.timeIntervalSince1970.isFinite
            && content.isStructurallyValid
            && !(kind != .application && relation != nil)
    }

    public func mayMutateControlState(supportedControlTypes: Set<ContentTypeId>) -> Bool {
        kind == .control && isStructurallyValid && supportedControlTypes.contains(content.type)
    }
}

public struct DeliveryStateRecord: Codable, Equatable {
    public let eventId: UUID
    public let destinationInstallation: RelationshipInstallationHandle
    public var state: MessageDeliveryState
    public var updatedAt: Date

    public init(
        eventId: UUID,
        destinationInstallation: RelationshipInstallationHandle,
        state: MessageDeliveryState,
        updatedAt: Date = Date()
    ) {
        self.eventId = eventId
        self.destinationInstallation = destinationInstallation
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
        destinationInstallation.isStructurallyValid
            && updatedAt.timeIntervalSince1970.isFinite
    }

    private static func rank(_ state: MessageDeliveryState) -> Int {
        switch state {
        case .locallyPersisted: return 0
        case .relayAccepted: return 1
        case .peerEndpointStored: return 2
        case .peerRead: return 3
        }
    }
}

public struct QuarantinedControlEvent: Codable, Equatable, Identifiable {
    public var id: UUID { event.id }
    public let event: ConversationEvent
    public let receivedAt: Date
    public let reason: String

    public init(event: ConversationEvent, receivedAt: Date = Date(), reason: String) {
        self.event = event
        self.receivedAt = receivedAt
        self.reason = String(reason.prefix(256))
    }
}

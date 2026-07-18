import Foundation

/// One live direct-v4 ratchet scoped to exactly one pairwise relationship.
/// The authoritative message history lives in `PairwiseRelationshipV2.events`;
/// `messages` is a disposable local display projection.
public struct Conversation: Codable, Identifiable, Equatable {
    public enum RatchetState: String, Codable, CaseIterable {
        case initializing
        case active
        case reset
        case healed
    }

    public let id: String
    public let relationshipID: UUID
    public let endpointSession: DirectEndpointSessionIdentity
    public var sessionId: String
    public var rootKey: Data
    public var rootCounter: UInt64
    public var sendChain: ChainKeyState
    public var receiveChain: ChainKeyState
    public var messages: [Message]
    public var unreadCount: Int
    public var ratchetState: RatchetState

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case relationshipID
        case endpointSession
        case sessionId
        case rootKey
        case rootCounter
        case sendChain
        case receiveChain
        case messages
        case unreadCount
        case ratchetState
    }

    public init(
        id: String,
        relationshipID: UUID,
        endpointSession: DirectEndpointSessionIdentity,
        sessionId: String,
        rootKey: Data,
        rootCounter: UInt64 = 0,
        sendChain: ChainKeyState,
        receiveChain: ChainKeyState,
        messages: [Message] = [],
        unreadCount: Int = 0,
        ratchetState: RatchetState = .initializing
    ) {
        self.id = id
        self.relationshipID = relationshipID
        self.endpointSession = endpointSession
        self.sessionId = sessionId
        self.rootKey = rootKey
        self.rootCounter = rootCounter
        self.sendChain = sendChain
        self.receiveChain = receiveChain
        self.messages = messages
        self.unreadCount = unreadCount
        self.ratchetState = ratchetState
    }

    public init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: ConversationCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Conversation fields must match the current schema exactly"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        relationshipID = try container.decode(UUID.self, forKey: .relationshipID)
        endpointSession = try container.decode(
            DirectEndpointSessionIdentity.self,
            forKey: .endpointSession
        )
        sessionId = try container.decode(String.self, forKey: .sessionId)
        rootKey = try container.decode(Data.self, forKey: .rootKey)
        rootCounter = try container.decode(UInt64.self, forKey: .rootCounter)
        sendChain = try container.decode(ChainKeyState.self, forKey: .sendChain)
        receiveChain = try container.decode(ChainKeyState.self, forKey: .receiveChain)
        messages = try container.decode([Message].self, forKey: .messages)
        unreadCount = try container.decode(Int.self, forKey: .unreadCount)
        ratchetState = try container.decode(RatchetState.self, forKey: .ratchetState)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .relationshipID,
                in: container,
                debugDescription: "Conversation is structurally invalid"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Conversation is structurally invalid"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(relationshipID, forKey: .relationshipID)
        try container.encode(endpointSession, forKey: .endpointSession)
        try container.encode(sessionId, forKey: .sessionId)
        try container.encode(rootKey, forKey: .rootKey)
        try container.encode(rootCounter, forKey: .rootCounter)
        try container.encode(sendChain, forKey: .sendChain)
        try container.encode(receiveChain, forKey: .receiveChain)
        try container.encode(messages, forKey: .messages)
        try container.encode(unreadCount, forKey: .unreadCount)
        try container.encode(ratchetState, forKey: .ratchetState)
    }

    public var isStructurallyValid: Bool {
        !id.isEmpty
            && id.utf8.count <= 256
            && id == relationshipID.uuidString.lowercased()
            && endpointSession.relationshipID == relationshipID
            && endpointSession.isStructurallyValid
            && !sessionId.isEmpty
            && sessionId.utf8.count <= 256
            && rootKey.count == 32
            && messages.count <= NoctweaveArchitectureV2.maximumRelationshipEvents
            && Set(messages.map(\.id)).count == messages.count
            && messages.allSatisfy(\.isStructurallyValid)
            && unreadCount >= 0
            && unreadCount <= messages.count
    }

    public mutating func transition(to newState: RatchetState) -> Bool {
        if newState == ratchetState { return true }
        switch (ratchetState, newState) {
        case (.initializing, .active), (.initializing, .reset),
             (.active, .reset), (.reset, .healed), (.healed, .reset):
            ratchetState = newState
            return true
        default:
            return false
        }
    }

    public mutating func markMessageProcessed() {
        switch ratchetState {
        case .initializing: _ = transition(to: .active)
        case .reset: _ = transition(to: .healed)
        case .active, .healed: break
        }
    }

    public mutating func markReset() {
        _ = transition(to: .reset)
    }
}

private struct ConversationCodingKey: CodingKey {
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

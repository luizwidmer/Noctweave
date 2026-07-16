import Foundation

public struct Conversation: Codable, Identifiable, Equatable {
    public let id: String
    public let contactId: UUID
    public let endpointSession: DirectEndpointSessionIdentity?
    public var sessionId: String
    public var rootKey: Data
    public var rootCounter: UInt64
    public var sendChain: ChainKeyState
    public var receiveChain: ChainKeyState
    public var messages: [Message]
    public var unreadCount: Int
    public var ratchetState: RatchetState

    public enum RatchetState: String, Codable, CaseIterable {
        case initializing
        case active
        case reset
        case healed
    }

    public init(
        id: String,
        contactId: UUID,
        endpointSession: DirectEndpointSessionIdentity? = nil,
        sessionId: String,
        rootKey: Data = Data(),
        rootCounter: UInt64 = 0,
        sendChain: ChainKeyState,
        receiveChain: ChainKeyState,
        messages: [Message] = [],
        unreadCount: Int = 0,
        ratchetState: RatchetState = .initializing
    ) {
        self.id = id
        self.contactId = contactId
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
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        contactId = try container.decode(UUID.self, forKey: .contactId)
        endpointSession = try container.decodeIfPresent(
            DirectEndpointSessionIdentity.self,
            forKey: .endpointSession
        )
        sessionId = try container.decodeIfPresent(String.self, forKey: .sessionId) ?? id
        rootKey = try container.decodeIfPresent(Data.self, forKey: .rootKey) ?? Data()
        rootCounter = try container.decodeIfPresent(UInt64.self, forKey: .rootCounter) ?? 0
        sendChain = try container.decode(ChainKeyState.self, forKey: .sendChain)
        receiveChain = try container.decode(ChainKeyState.self, forKey: .receiveChain)
        messages = try container.decodeIfPresent([Message].self, forKey: .messages) ?? []
        unreadCount = try container.decodeIfPresent(Int.self, forKey: .unreadCount) ?? 0
        ratchetState = try container.decodeIfPresent(RatchetState.self, forKey: .ratchetState) ?? .active
    }

    public mutating func transition(to newState: RatchetState) -> Bool {
        if newState == ratchetState {
            return true
        }
        switch (ratchetState, newState) {
        case (.initializing, .active),
             (.initializing, .reset),
             (.active, .reset),
             (.reset, .healed),
             (.healed, .reset):
            ratchetState = newState
            return true
        default:
            return false
        }
    }

    public mutating func markMessageProcessed() {
        switch ratchetState {
        case .initializing:
            _ = transition(to: .active)
        case .reset:
            _ = transition(to: .healed)
        case .active, .healed:
            break
        }
    }

    public mutating func markReset() {
        _ = transition(to: .reset)
    }
}

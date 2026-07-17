import CryptoKit
import Foundation

/// A relay-scoped, opaque handle for one authorized mailbox consumer.
///
/// The value deliberately does not expose the local endpoint identifier. A client
/// should create a different handle for every relay route so relays cannot use it
/// as a cross-relationship endpoint identifier.
public struct MailboxConsumerId: RawRepresentable, Codable, Equatable, Hashable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public static func generate(nonce: UUID = UUID()) -> MailboxConsumerId {
        var material = Data("Noctweave/mailbox-consumer/v2".utf8)
        material.append(Data(nonce.uuidString.lowercased().utf8))
        return MailboxConsumerId(rawValue: Data(SHA256.hash(data: material)).base64EncodedString())
    }

    public var isStructurallyValid: Bool {
        guard let bytes = Data(base64Encoded: rawValue), bytes.count == 32 else { return false }
        return bytes.base64EncodedString() == rawValue
    }
}

public struct SequencedEnvelope: Codable, Equatable, Identifiable {
    public var id: UUID { envelope.id }
    public let sequence: UInt64
    public let envelope: Envelope
    public let storedAt: Date

    public init(sequence: UInt64, envelope: Envelope, storedAt: Date) {
        self.sequence = sequence
        self.envelope = envelope
        self.storedAt = storedAt
    }

    public var isStructurallyValid: Bool {
        sequence > 0 && envelope.isStructurallyValid && storedAt.timeIntervalSince1970.isFinite
    }
}

public struct MailboxSyncBatch: Codable, Equatable {
    public let events: [SequencedEnvelope]
    public let nextCursor: MailboxCursor
    public let nextSequence: UInt64
    public let highWatermark: UInt64
    public let retentionFloor: UInt64
    public let hasMore: Bool

    public init(
        events: [SequencedEnvelope],
        nextCursor: MailboxCursor,
        nextSequence: UInt64,
        highWatermark: UInt64,
        retentionFloor: UInt64,
        hasMore: Bool
    ) {
        self.events = events
        self.nextCursor = nextCursor
        self.nextSequence = nextSequence
        self.highWatermark = highWatermark
        self.retentionFloor = retentionFloor
        self.hasMore = hasMore
    }

    public var isStructurallyValid: Bool {
        nextCursor.isStructurallyValid
            && nextSequence <= highWatermark
            && retentionFloor <= highWatermark
            && events.allSatisfy(\.isStructurallyValid)
            && zip(events, events.dropFirst()).allSatisfy {
                $0.sequence < UInt64.max && $1.sequence == $0.sequence + 1
            }
            && (events.last?.sequence ?? nextSequence) == nextSequence
            && events.allSatisfy { $0.sequence > retentionFloor && $0.sequence <= highWatermark }
    }

    /// Validates the relay batch against the endpoint's durable cursor
    /// position. Internal ordering alone is insufficient: a relay could omit
    /// the first event after the cursor and still return an increasing page.
    public func isContiguous(after committedSequence: UInt64) -> Bool {
        guard isStructurallyValid else { return false }
        guard let first = events.first else {
            return nextSequence == committedSequence
        }
        return committedSequence < UInt64.max
            && first.sequence == committedSequence + 1
    }
}

public enum MailboxConsumerState: String, Codable, Equatable {
    case active
    case revoked
}

public struct MailboxConsumerRegistration: Codable, Equatable {
    public let consumerId: MailboxConsumerId
    /// The relay/inbox-route signing key authorized to sync and commit this
    /// consumer. Current state never contains an unbound consumer.
    public let consumerSigningPublicKey: Data
    public let state: MailboxConsumerState
    public let committedSequence: UInt64
    public let registeredAt: Date
    public let revokedAt: Date?

    public init(
        consumerId: MailboxConsumerId,
        consumerSigningPublicKey: Data,
        state: MailboxConsumerState = .active,
        committedSequence: UInt64,
        registeredAt: Date = Date(),
        revokedAt: Date? = nil
    ) {
        self.consumerId = consumerId
        self.consumerSigningPublicKey = consumerSigningPublicKey
        self.state = state
        self.committedSequence = committedSequence
        self.registeredAt = registeredAt
        self.revokedAt = revokedAt
    }

    public var isStructurallyValid: Bool {
        guard consumerId.isStructurallyValid,
              SigningKeyPair.isValidPublicKey(consumerSigningPublicKey),
              registeredAt.timeIntervalSince1970.isFinite,
              revokedAt?.timeIntervalSince1970.isFinite ?? true else {
            return false
        }
        switch (state, revokedAt) {
        case (.active, nil), (.revoked, .some):
            return true
        default:
            return false
        }
    }
}

public struct PendingMailboxCursorCommit: Codable, Equatable {
    public let cursor: MailboxCursor
    public let sequence: UInt64
    public let preparedAt: Date

    public init(cursor: MailboxCursor, sequence: UInt64, preparedAt: Date = Date()) {
        self.cursor = cursor
        self.sequence = sequence
        self.preparedAt = preparedAt
    }

    public var isStructurallyValid: Bool {
        cursor.isStructurallyValid && preparedAt.timeIntervalSince1970.isFinite
    }
}

/// Route-binding information an already admitted endpoint may share with
/// another endpoint in the same identity generation. It only identifies the
/// active sponsor credential; it does not admit an endpoint and contains no
/// inbox authority or private key material.
public struct MailboxRouteSponsorshipContext: Codable, Equatable {
    public let inboxId: String
    public let relay: RelayEndpoint
    public let sponsorConsumerId: MailboxConsumerId

    public init(inboxId: String, relay: RelayEndpoint, sponsorConsumerId: MailboxConsumerId) {
        self.inboxId = inboxId
        self.relay = relay
        self.sponsorConsumerId = sponsorConsumerId
    }

    public var isStructurallyValid: Bool {
        InboxAddress.isValid(inboxId) && sponsorConsumerId.isStructurallyValid
    }
}

public enum MailboxSyncError: Error, Equatable {
    case invalidConsumer
    case consumerNotFound
    case consumerRevoked
    case consumerCredentialMissing
    case consumerSigningKeyMismatch
    case consumerSponsorRequired
    case invalidConsumerSponsor
    case freshInboxRequired
    case invalidCursor
    case cursorExpired(retentionFloor: UInt64)
    case cursorRollback
    case sequenceOverflow
}

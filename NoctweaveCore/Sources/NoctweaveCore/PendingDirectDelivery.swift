import Foundation

/// A ciphertext-only outbox record persisted with the encrypted client state.
///
/// The original envelope is retried unchanged so its ratchet counter and
/// signature remain stable. Relay storage treats the envelope identifier as an
/// idempotency key.
public struct PendingDirectDelivery: Codable, Equatable, Identifiable {
    public var id: UUID { envelope.id }
    public let contactId: UUID
    public let inboxId: String
    public let preferredRelay: RelayEndpoint
    public let destinationRelay: RelayEndpoint
    public let envelope: Envelope
    public let queuedAt: Date
    public var attemptCount: Int
    public var lastAttemptAt: Date?

    public init(
        contactId: UUID,
        inboxId: String,
        preferredRelay: RelayEndpoint,
        destinationRelay: RelayEndpoint,
        envelope: Envelope,
        queuedAt: Date = Date(),
        attemptCount: Int = 0,
        lastAttemptAt: Date? = nil
    ) {
        self.contactId = contactId
        self.inboxId = inboxId
        self.preferredRelay = preferredRelay
        self.destinationRelay = destinationRelay
        self.envelope = envelope
        self.queuedAt = queuedAt
        self.attemptCount = max(0, attemptCount)
        self.lastAttemptAt = lastAttemptAt
    }
}

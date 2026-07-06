import Foundation

public enum SessionRecovery {
    public enum SessionRecoveryError: Error {
        case relayError(String)
        case unexpectedResponse
    }

    public struct Cooldown {
        public let interval: TimeInterval
        private var lastAttempts: [UUID: Date]

        public init(interval: TimeInterval = 30, lastAttempts: [UUID: Date] = [:]) {
            self.interval = interval
            self.lastAttempts = lastAttempts
        }

        public mutating func shouldAttempt(contactId: UUID, now: Date = Date()) -> Bool {
            if let lastAttempt = lastAttempts[contactId],
               now.timeIntervalSince(lastAttempt) < interval {
                return false
            }
            lastAttempts[contactId] = now
            return true
        }
    }

    public static func deliver(
        envelope: Envelope,
        inboxId: String,
        preferredRelay: RelayEndpoint,
        destinationRelay: RelayEndpoint,
        preferredRelayAuthToken: String? = nil,
        destinationRelayAuthToken: String? = nil
    ) async throws {
        if preferredRelay != destinationRelay {
            do {
                try await deliver(
                    envelope: envelope,
                    inboxId: inboxId,
                    via: preferredRelay,
                    destination: destinationRelay,
                    authToken: preferredRelayAuthToken
                )
                return
            } catch {
                // Fall back to direct delivery.
            }
        }
        try await deliver(
            envelope: envelope,
            inboxId: inboxId,
            via: destinationRelay,
            destination: nil,
            authToken: destinationRelayAuthToken
        )
    }

    public static func sendSessionReset(
        identity: Identity,
        contact: Contact,
        existingConversation: Conversation,
        preferredRelay: RelayEndpoint,
        preferredRelayAuthToken: String? = nil,
        destinationRelayAuthToken: String? = nil
    ) async throws -> Conversation {
        let session = try MessageEngine.createOutboundSession(identity: identity, contact: contact)
        var conversationForEncrypt = session.conversation
        conversationForEncrypt.markReset()
        let envelope = try MessageEngine.encrypt(
            body: .sessionReset(SessionReset()),
            senderSigningKey: identity.signingKey,
            senderFingerprint: identity.fingerprint,
            conversation: &conversationForEncrypt,
            kemCiphertext: session.kemCiphertext
        )

        try await deliver(
            envelope: envelope,
            inboxId: contact.inboxId,
            preferredRelay: preferredRelay,
            destinationRelay: contact.relay,
            preferredRelayAuthToken: preferredRelayAuthToken,
            destinationRelayAuthToken: destinationRelayAuthToken
        )

        var rebuilt = conversationForEncrypt
        rebuilt.messages = existingConversation.messages
        rebuilt.unreadCount = existingConversation.unreadCount
        return rebuilt
    }

    public static func sendSessionResetAndResendRequest(
        identity: Identity,
        contact: Contact,
        existingConversation: Conversation,
        preferredRelay: RelayEndpoint,
        resendCount: Int,
        preferredRelayAuthToken: String? = nil,
        destinationRelayAuthToken: String? = nil
    ) async throws -> Conversation {
        var rebuilt = try await sendSessionReset(
            identity: identity,
            contact: contact,
            existingConversation: existingConversation,
            preferredRelay: preferredRelay,
            preferredRelayAuthToken: preferredRelayAuthToken,
            destinationRelayAuthToken: destinationRelayAuthToken
        )
        guard resendCount > 0 else { return rebuilt }
        let request = ResendRequest(count: resendCount)
        let envelope = try MessageEngine.encrypt(
            body: .resendRequest(request),
            senderSigningKey: identity.signingKey,
            senderFingerprint: identity.fingerprint,
            conversation: &rebuilt,
            kemCiphertext: nil
        )
        try await deliver(
            envelope: envelope,
            inboxId: contact.inboxId,
            preferredRelay: preferredRelay,
            destinationRelay: contact.relay,
            preferredRelayAuthToken: preferredRelayAuthToken,
            destinationRelayAuthToken: destinationRelayAuthToken
        )
        return rebuilt
    }

    private static func deliver(
        envelope: Envelope,
        inboxId: String,
        via relay: RelayEndpoint,
        destination: RelayEndpoint?,
        authToken: String?
    ) async throws {
        let client = RelayClient(endpoint: relay, authToken: authToken)
        let request = RelayRequest.deliver(
            DeliverRequest(
                inboxId: inboxId,
                routingToken: inboxId,
                envelope: envelope,
                destinationRelay: destination
            )
        )
        let response = try await client.send(request)
        guard response.type == .delivered else {
            if let error = response.error {
                throw SessionRecoveryError.relayError(redactedRelayError(error))
            }
            throw SessionRecoveryError.unexpectedResponse
        }
    }

    private static func redactedRelayError(_ error: String) -> String {
        let lowercased = error.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if lowercased.contains("unauthorized") || lowercased.contains("forbidden") {
            return "Relay authorization failed."
        }
        if lowercased.contains("proof") || lowercased.contains("signature") {
            return "Relay proof verification failed."
        }
        if lowercased.contains("not found") || lowercased.contains("not registered") {
            return "Relay resource was not found."
        }
        if lowercased.contains("rate") || lowercased.contains("quota") || lowercased.contains("limit") {
            return "Relay rate limit was reached."
        }
        if lowercased.contains("disabled") || lowercased.contains("not allowed") {
            return "Relay policy rejected the request."
        }
        if lowercased.contains("invalid") || lowercased.contains("malformed") || lowercased.contains("missing") {
            return "Relay rejected an invalid request."
        }
        return "Relay rejected the request."
    }
}

import Foundation

public enum MessageAuthenticatedContextPurpose: String, Codable, Equatable {
    case group
}

public struct GroupMessageAuthenticatedContext: Codable, Equatable {
    public let groupId: UUID
    public let epoch: UInt64
    public let senderFingerprint: String
    public let transcriptHash: Data

    public init(
        groupId: UUID,
        epoch: UInt64,
        senderFingerprint: String,
        transcriptHash: Data
    ) {
        self.groupId = groupId
        self.epoch = epoch
        self.senderFingerprint = senderFingerprint
        self.transcriptHash = transcriptHash
    }
}

public struct MessageAuthenticatedContext: Codable, Equatable {
    public let purpose: MessageAuthenticatedContextPurpose
    public let group: GroupMessageAuthenticatedContext?

    public init(
        purpose: MessageAuthenticatedContextPurpose,
        group: GroupMessageAuthenticatedContext?
    ) {
        self.purpose = purpose
        self.group = group
    }

    public static func group(
        groupId: UUID,
        epoch: UInt64,
        senderFingerprint: String,
        transcriptHash: Data
    ) -> MessageAuthenticatedContext {
        MessageAuthenticatedContext(
            purpose: .group,
            group: GroupMessageAuthenticatedContext(
                groupId: groupId,
                epoch: epoch,
                senderFingerprint: senderFingerprint,
                transcriptHash: transcriptHash
            )
        )
    }
}

public struct Envelope: Codable, Identifiable, Equatable {
    public let id: UUID
    public let conversationId: String
    public let sessionId: String?
    public let senderFingerprint: String
    public let sentAt: Date
    public let messageCounter: UInt64
    public let kemCiphertext: Data?
    public let prekey: PrekeyReference?
    public let rootRatchet: RootRatchet?
    public let authenticatedContext: MessageAuthenticatedContext?
    public let payload: EncryptedPayload
    public let signature: Data

    public init(
        id: UUID = UUID(),
        conversationId: String,
        sessionId: String? = nil,
        senderFingerprint: String,
        sentAt: Date,
        messageCounter: UInt64,
        kemCiphertext: Data? = nil,
        prekey: PrekeyReference? = nil,
        rootRatchet: RootRatchet? = nil,
        authenticatedContext: MessageAuthenticatedContext? = nil,
        payload: EncryptedPayload,
        signature: Data
    ) {
        self.id = id
        self.conversationId = conversationId
        self.sessionId = sessionId
        self.senderFingerprint = senderFingerprint
        self.sentAt = sentAt
        self.messageCounter = messageCounter
        self.kemCiphertext = kemCiphertext
        self.prekey = prekey
        self.rootRatchet = rootRatchet
        self.authenticatedContext = authenticatedContext
        self.payload = payload
        self.signature = signature
    }

    public func verifySignature(publicSigningKey: Data) -> Bool {
        guard let data = try? NoctweaveCoder.encode(signaturePayload, sortedKeys: true) else {
            return false
        }
        return SigningKeyPair.verify(signature: signature, data: data, publicKeyData: publicSigningKey)
    }

    public static func signableData(
        conversationId: String,
        sessionId: String?,
        senderFingerprint: String,
        sentAt: Date,
        messageCounter: UInt64,
        kemCiphertext: Data?,
        prekey: PrekeyReference?,
        rootRatchet: RootRatchet?,
        authenticatedContext: MessageAuthenticatedContext?,
        payload: EncryptedPayload
    ) throws -> Data {
        let payload = SignaturePayload(
            conversationId: conversationId,
            sessionId: sessionId,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: messageCounter,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            rootRatchet: rootRatchet,
            authenticatedContext: authenticatedContext,
            payload: payload
        )
        return try NoctweaveCoder.encode(payload, sortedKeys: true)
    }

    private var signaturePayload: SignaturePayload {
        SignaturePayload(
            conversationId: conversationId,
            sessionId: sessionId,
            senderFingerprint: senderFingerprint,
            sentAt: sentAt,
            messageCounter: messageCounter,
            kemCiphertext: kemCiphertext,
            prekey: prekey,
            rootRatchet: rootRatchet,
            authenticatedContext: authenticatedContext,
            payload: payload
        )
    }
}

private struct SignaturePayload: Codable {
    let conversationId: String
    let sessionId: String?
    let senderFingerprint: String
    let sentAt: Date
    let messageCounter: UInt64
    let kemCiphertext: Data?
    let prekey: PrekeyReference?
    let rootRatchet: RootRatchet?
    let authenticatedContext: MessageAuthenticatedContext?
    let payload: EncryptedPayload
}
